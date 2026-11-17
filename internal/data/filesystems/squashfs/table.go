package squashfs

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	idsPerBlock       = 2048
	fragmentsPerBlock = 512
)

// fragmentEntry is one fragment-table entry.
type fragmentEntry struct {
	startBlock uint64
	storedSize uint32
}

func (f fragmentEntry) isUncompressed() bool { return f.storedSize&uncompressedBlockBit != 0 }

func (f fragmentEntry) bytes() uint32 { return f.storedSize & blockSizeMask }

// tables holds the id and fragment lookup tables.
type tables struct {
	idIndex       []uint64
	fragmentIndex []uint64
	idCount       uint16
	fragments     uint32
}

func readU64s(src source.ByteSource, start uint64, count int, what string, bytesUsed uint64) ([]uint64, error) {
	length := uint64(count) * 8
	if start > bytesUsed || length > bytesUsed-start {
		return nil, corruptf("the %s index at %d does not fit in the %d bytes in use", what, start, bytesUsed)
	}
	raw := make([]byte, int(length))
	if err := source.ReadExactAt(src, start, raw); err != nil {
		return nil, err
	}
	out := make([]uint64, count)
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(raw[i*8:])
	}
	return out, nil
}

func readTables(src source.ByteSource, sb *superblock) (*tables, error) {
	idBlocks := int((uint64(sb.idCount)*4 + 8191) / 8192)
	if idBlocks < 1 {
		idBlocks = 1
	}
	idIndex, err := readU64s(src, sb.idTableStart, idBlocks, "id", sb.bytesUsed)
	if err != nil {
		return nil, err
	}
	if len(idIndex) == 0 {
		return nil, corruptf("the id index is empty")
	}
	if last := idIndex[len(idIndex)-1]; last >= sb.idTableStart {
		return nil, corruptf("the id index points at %d, not below its own start %d", last, sb.idTableStart)
	}

	var fragmentIndex []uint64
	if sb.fragments != 0 && sb.fragmentTableStart != invalidTable {
		blocks := int((uint64(sb.fragments)*16 + 8191) / 8192)
		if blocks < 1 {
			blocks = 1
		}
		fragmentIndex, err = readU64s(src, sb.fragmentTableStart, blocks, "fragment", sb.bytesUsed)
		if err != nil {
			return nil, err
		}
		if len(fragmentIndex) == 0 || fragmentIndex[0] >= sb.fragmentTableStart {
			return nil, corruptf("the fragment index does not point below its own start %d", sb.fragmentTableStart)
		}
	}
	return &tables{
		idIndex:       idIndex,
		fragmentIndex: fragmentIndex,
		idCount:       sb.idCount,
		fragments:     sb.fragments,
	}, nil
}

func (t *tables) id(cache *metadataCache, src source.ByteSource, index uint16) (uint32, error) {
	if index >= t.idCount {
		return 0, corruptf("uid/gid index %d is past the %d entries in the id table", index, t.idCount)
	}
	block := uint64(index) / idsPerBlock
	offset := int((uint64(index) % idsPerBlock) * 4)
	if block >= uint64(len(t.idIndex)) {
		return 0, corruptf("no id index entry for block %d", block)
	}
	bytes, err := cache.span(src, t.idIndex[block], offset, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(bytes), nil
}

func (t *tables) fragment(cache *metadataCache, src source.ByteSource, index uint32) (*fragmentEntry, error) {
	if t.fragments == 0 {
		return nil, corruptf("the image has no fragment table")
	}
	if index >= t.fragments {
		return nil, corruptf("fragment %d is past the %d fragments the superblock declares", index, t.fragments)
	}
	block := uint64(index) / fragmentsPerBlock
	offset := int((uint64(index) % fragmentsPerBlock) * 16)
	if block >= uint64(len(t.fragmentIndex)) {
		return nil, corruptf("no fragment index entry for block %d", block)
	}
	bytes, err := cache.span(src, t.fragmentIndex[block], offset, 16)
	if err != nil {
		return nil, err
	}
	stored := binary.LittleEndian.Uint32(bytes[8:])
	if stored>>25 != 0 {
		return nil, corruptf("fragment %d stores a size with reserved bits set: %#x", index, stored)
	}
	if stored&blockSizeMask == 0 {
		return nil, corruptf("fragment %d stores no bytes", index)
	}
	return &fragmentEntry{
		startBlock: binary.LittleEndian.Uint64(bytes[0:8]),
		storedSize: stored,
	}, nil
}
