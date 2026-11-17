package zfs

import (
	"sort"
	"strings"
)

// ZFS attribute processors (ZAPs): the pools' and datasets' name→value maps.
//
// A ZAP is either micro — a 64-byte header followed by 64-byte fixed entries
// in one block, used while a map is small — or fat: a header block holding a
// pointer table, plus leaf blocks whose chunks hold names and values. The
// object directory, the dataset master node and every directory are ZAPs, so
// this is how names become objects.
//
// The fat reader enumerates leaves through the pointer table rather than
// scanning the object's blocks. A freed leaf block can still hold its old
// contents; walking the pointer table is what distinguishes the namespace
// that exists from bytes that merely survived.

const (
	zapMagic       uint64 = 0x2_F52AB2AB
	zapZBTLeaf     uint64 = 1 << 63
	zapZBTHeader   uint64 = (1 << 63) + 1
	zapZBTMicro    uint64 = (1 << 63) + 3
	zapLeafMagic   uint32 = 0x2AB1EAF
	leafChunkSize         = 24
	leafArrayBytes        = 21
	chunkEntry     byte   = 252
	chunkArray     byte   = 251
	chunkFree      byte   = 253
	chainEnd       uint16 = 0xffff
	maxZapEntries         = 1 << 20
	// maxZapBytes bounds decoded name and value bytes across one ZAP, so a
	// hostile table cannot force many megabytes of value copies per entry.
	maxZapBytes = 64 << 20
	// maxZapShift bounds the pointer table's slot count at maxZapEntries.
	// OpenZFS permits 24; a table that large cannot hold fewer than a million
	// entries, which this reader's entry cap already refuses.
	maxZapShift = 20
)

// ZapEntry is one name and its stored value bytes.
type ZapEntry struct {
	name  string
	value []byte
}

// Zap is a decoded ZAP.
type Zap struct {
	items []ZapEntry
	// truncated is true when the reader stopped at its entry bound.
	truncated bool
}

// readZap reads every entry of the ZAP object node describes.
func readZap(reader *BlockReader, node *Dnode) (*Zap, error) {
	return readZapUpTo(reader, node, maxZapEntries)
}

// readZapUpTo reads at most limit entries; the rest are counted as truncated.
func readZapUpTo(reader *BlockReader, node *Dnode, limit int) (*Zap, error) {
	if limit < 0 {
		limit = 0
	}
	if limit > maxZapEntries {
		limit = maxZapEntries
	}
	blockSize := node.dataBlockSize()
	if blockSize == 0 {
		return &Zap{}, nil
	}
	if blockSize > 1<<20 {
		return nil, corruptf("a ZAP with %d-byte blocks", blockSize)
	}
	header, err := readObject(reader, node, 0, int(blockSize))
	if err != nil {
		return nil, err
	}
	switch kind := leUint64(header[0:]); kind {
	case zapZBTMicro:
		entries, truncated, err := microEntries(header, limit)
		if err != nil {
			return nil, err
		}
		return &Zap{items: entries, truncated: truncated}, nil
	case zapZBTHeader:
		return readFatZap(reader, node, header, limit)
	default:
		return nil, corruptf("object %d holds neither a micro nor a fat ZAP (block type 0x%016x)", node.object, kind)
	}
}

func readFatZap(reader *BlockReader, node *Dnode, header []byte, limit int) (*Zap, error) {
	if leUint64(header[8:]) != zapMagic {
		return nil, corruptf("object %d's ZAP header magic is 0x%016x", node.object, leUint64(header[8:]))
	}
	blockSize := uint64(len(header))
	shift := leUint64(header[32:])
	if shift < 5 || shift > maxZapShift {
		return nil, corruptf("object %d's ZAP pointer table has shift %d", node.object, shift)
	}
	ptrs := uint64(1) << shift
	tableBlock := leUint64(header[16:])
	tableBlocks := leUint64(header[24:])
	leaves := map[uint64]struct{}{}
	if tableBlocks == 0 || tableBlock == 0 {
		if tableBlock != 0 || tableBlocks != 0 {
			return nil, corruptf("a ZAP pointer table names only half its location")
		}
		half := blockSize / 2
		if half+ptrs*8 > uint64(len(header)) {
			return nil, corruptf("object %d's %d embedded pointer table entries do not fit", node.object, ptrs)
		}
		for index := uint64(0); index < ptrs; index++ {
			leaf := leUint64(header[half+index*8:])
			if leaf != 0 {
				leaves[leaf] = struct{}{}
			}
		}
	} else {
		perBlock := blockSize / 8
		needed := (ptrs + perBlock - 1) / perBlock
		if needed != tableBlocks {
			return nil, corruptf("object %d's pointer table needs %d block(s), the header says %d",
				node.object, needed, tableBlocks)
		}
		index := uint64(0)
		for block := uint64(0); block < tableBlocks; block++ {
			if block > ^uint64(0)-tableBlock {
				return nil, corruptf("object %d's pointer table offset overflows", node.object)
			}
			tableIndex := tableBlock + block
			if blockSize == 0 || tableIndex > ^uint64(0)/blockSize {
				return nil, corruptf("object %d's pointer table offset overflows", node.object)
			}
			offset := tableIndex * blockSize
			table, err := readObject(reader, node, offset, int(blockSize))
			if err != nil {
				return nil, err
			}
			for within := uint64(0); within < perBlock && index < ptrs; within++ {
				leaf := leUint64(table[within*8:])
				if leaf != 0 {
					leaves[leaf] = struct{}{}
				}
				index++
			}
		}
	}
	if len(leaves) > maxZapEntries {
		return nil, corruptf("object %d's pointer table names %d leaf blocks, more than the %d-entry cap",
			node.object, len(leaves), maxZapEntries)
	}
	ordered := make([]uint64, 0, len(leaves))
	for leaf := range leaves {
		ordered = append(ordered, leaf)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	entries := make([]ZapEntry, 0, limit)
	totalBytes := 0
	truncated := false
	for _, leaf := range ordered {
		if len(entries) >= limit {
			truncated = true
			break
		}
		if leaf == 0 || leaf > node.maxBlkID {
			return nil, corruptf("object %d's pointer table names leaf block %d, past maxblkid %d",
				node.object, leaf, node.maxBlkID)
		}
		if blockSize == 0 || leaf > ^uint64(0)/blockSize {
			return nil, corruptf("object %d's leaf offset overflows", node.object)
		}
		offset := leaf * blockSize
		block, err := readObject(reader, node, offset, int(blockSize))
		if err != nil {
			return nil, err
		}
		found, cut, err := leafEntries(block, limit-len(entries))
		if err != nil {
			return nil, err
		}
		for _, entry := range found {
			totalBytes += len(entry.name) + len(entry.value)
			if totalBytes > maxZapBytes {
				return nil, corruptf("object %d's ZAP decodes more than %d name and value bytes",
					node.object, maxZapBytes)
			}
		}
		entries = append(entries, found...)
		truncated = truncated || cut
	}
	if len(entries) > maxZapEntries {
		return nil, corruptf("object %d's ZAP holds more than %d entries", node.object, maxZapEntries)
	}
	return &Zap{items: entries, truncated: truncated}, nil
}

func microEntries(block []byte, limit int) ([]ZapEntry, bool, error) {
	if len(block) < 128 || len(block)%64 != 0 {
		return nil, false, corruptf("a micro ZAP block of %d bytes", len(block))
	}
	entries := make([]ZapEntry, 0, limit)
	truncated := false
	chunks := len(block)/64 - 1
	for index := 0; index < chunks; index++ {
		if len(entries) >= limit {
			truncated = true
			break
		}
		chunk := block[64+index*64 : 64+index*64+64]
		if chunk[14] == 0 {
			continue
		}
		nameBytes := chunk[14:64]
		end := -1
		for i, b := range nameBytes {
			if b == 0 {
				end = i
				break
			}
		}
		if end < 0 {
			return nil, false, corruptf("a micro ZAP name is not terminated")
		}
		if end == 0 {
			continue
		}
		// A ZAP name is bytes, not UTF-8; an invalid sequence is carried with
		// replacement rather than refusing the whole map.
		entries = append(entries, ZapEntry{
			name:  lossyUTF8(nameBytes[:end]),
			value: append([]byte(nil), chunk[:8]...),
		})
		if len(entries) > maxZapEntries {
			return nil, false, corruptf("a micro ZAP holds too many entries")
		}
	}
	return entries, truncated, nil
}

func leafEntries(block []byte, limit int) ([]ZapEntry, bool, error) {
	if len(block) < 64 || len(block)&(len(block)-1) != 0 {
		return nil, false, corruptf("a ZAP leaf block of %d bytes", len(block))
	}
	if leUint64(block[0:]) != zapZBTLeaf {
		return nil, false, corruptf("a ZAP leaf block has block type 0x%016x", leUint64(block[0:]))
	}
	magic := uint32(block[24]) | uint32(block[25])<<8 | uint32(block[26])<<16 | uint32(block[27])<<24
	if magic != zapLeafMagic {
		return nil, false, corruptf("a ZAP leaf magic is 0x%08x", magic)
	}
	hashEntries := len(block) / 32
	chunksStart := 48 + 2*hashEntries
	chunks := (len(block)-2*hashEntries)/leafChunkSize - 2
	if chunks < 0 {
		return nil, false, corruptf("a ZAP leaf block of %d bytes holds no chunks", len(block))
	}
	entries := make([]ZapEntry, 0, limit)
	totalBytes := 0
	truncated := false
	for index := 0; index < chunks; index++ {
		if len(entries) >= limit {
			truncated = true
			break
		}
		start := chunksStart + index*leafChunkSize
		if start+leafChunkSize > len(block) {
			break
		}
		chunk := block[start : start+leafChunkSize]
		if chunk[0] != chunkEntry {
			continue
		}
		nameChunk := uint16(chunk[4]) | uint16(chunk[5])<<8
		nameLen := int(uint16(chunk[6]) | uint16(chunk[7])<<8)
		valueChunk := uint16(chunk[8]) | uint16(chunk[9])<<8
		// le_value_numints counts integers, and le_value_intlen is their
		// width in bytes (OpenZFS checks it is 1, 2, 4 or 8). The byte count
		// is the product; a value with no integers has no chunks at all.
		valueIntlen := int(chunk[1])
		valueInts := int(uint16(chunk[10]) | uint16(chunk[11])<<8)
		if valueInts != 0 && valueIntlen != 1 && valueIntlen != 2 && valueIntlen != 4 && valueIntlen != 8 {
			return nil, false, corruptf("a ZAP leaf entry holds %d value(s) of %d-byte integers",
				valueInts, valueIntlen)
		}
		valueLen := valueInts * valueIntlen
		if nameLen == 0 {
			return nil, false, corruptf("a ZAP leaf entry has an empty name")
		}
		if nameLen > 1024 || valueLen > 1<<20 {
			return nil, false, corruptf("a ZAP leaf entry has a %d-byte name and a %d-byte value", nameLen, valueLen)
		}
		name, err := zapChain(block, chunksStart, chunks, nameChunk, nameLen)
		if err != nil {
			return nil, false, err
		}
		if len(name) == 0 || name[len(name)-1] != 0 {
			return nil, false, corruptf("a ZAP leaf name does not end in NUL")
		}
		name = name[:len(name)-1]
		for _, b := range name {
			if b == 0 {
				return nil, false, corruptf("a ZAP leaf name holds an embedded NUL")
			}
		}
		value, err := zapChain(block, chunksStart, chunks, valueChunk, valueLen)
		if err != nil {
			return nil, false, err
		}
		// Leaf array integers are stored most-significant byte first, a
		// format independent of the host's byte order. Normalise each integer
		// to little-endian so the rest of the module reads values uniformly.
		if valueIntlen > 1 {
			for at := 0; at+valueIntlen <= len(value); at += valueIntlen {
				for i, j := at, at+valueIntlen-1; i < j; i, j = i+1, j-1 {
					value[i], value[j] = value[j], value[i]
				}
			}
		}
		totalBytes += len(name) + len(value)
		if totalBytes > maxZapBytes {
			return nil, false, corruptf("a ZAP leaf decodes more than %d name and value bytes", maxZapBytes)
		}
		entries = append(entries, ZapEntry{name: lossyUTF8(name), value: value})
		if len(entries) > maxZapEntries {
			return nil, false, corruptf("a ZAP leaf holds too many entries")
		}
	}
	return entries, truncated, nil
}

// zapChain follows a chain of 21-byte array chunks, refusing cycles.
func zapChain(block []byte, chunksStart, chunks int, first uint16, length int) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	out := make([]byte, 0, length)
	index := int(first)
	for iteration := 0; iteration <= chunks; iteration++ {
		if index == int(chainEnd) {
			break
		}
		if index < 0 || index >= chunks {
			return nil, corruptf("a ZAP array names chunk %d of %d", index, chunks)
		}
		start := chunksStart + index*leafChunkSize
		chunk := block[start : start+leafChunkSize]
		if chunk[0] != chunkArray {
			return nil, corruptf("a ZAP array chain runs into chunk type %d", chunk[0])
		}
		out = append(out, chunk[1:1+leafArrayBytes]...)
		if len(out) >= length {
			return out[:length], nil
		}
		index = int(uint16(chunk[22]) | uint16(chunk[23])<<8)
	}
	if len(out) < length {
		return nil, corruptf("a ZAP array chain ends after %d of %d bytes", len(out), length)
	}
	return out[:length], nil
}

// entries returns the decoded pairs.
func (z *Zap) entries() []ZapEntry { return z.items }

func (z *Zap) len() int { return len(z.items) }

func (z *Zap) isEmpty() bool { return len(z.items) == 0 }

func (z *Zap) get(name string) (ZapEntry, bool) {
	for _, entry := range z.items {
		if entry.name == name {
			return entry, true
		}
	}
	return ZapEntry{}, false
}

func (z *Zap) unsigned(name string) (uint64, bool) {
	entry, ok := z.get(name)
	if !ok || len(entry.value) != 8 {
		return 0, false
	}
	return leUint64(entry.value), true
}

func (z *Zap) stringValue(name string) (string, bool) {
	entry, ok := z.get(name)
	if !ok {
		return "", false
	}
	text := entry.value
	if len(text) > 0 && text[len(text)-1] == 0 {
		text = text[:len(text)-1]
	}
	if !validUTF8(text) {
		return "", false
	}
	return string(text), true
}

func lossyUTF8(bytes []byte) string {
	return strings.ToValidUTF8(string(bytes), "�")
}
