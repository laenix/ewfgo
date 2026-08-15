package btrfs

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// Btrfs filesystem implementation — a real on-disk tree walk.
//
// Walk path: superblock -> sys_chunk_array bootstrap -> chunk tree ->
// root tree (ROOT_ITEM for the FS subvolume) -> fs tree leaves ->
// INODE_ITEM / DIR_ITEM / DIR_INDEX / EXTENT_DATA items.
//
// On-disk layout facts (verified against btrfs-progs v6.6.3 — the exact tool
// that created the committed fixtures — via `btrfs inspect-internal
// dump-tree`, which parses them perfectly):
//
//   - A node's item array starts at byte 101 = BTRFS_LEAF_DATA_OFFSET (0x65).
//     The parser tries 101 first and only falls back to a bounded scan for
//     layouts produced by other btrfs implementations.
//   - btrfs_dir_item = btrfs_disk_key location[17] + transid u64[8] +
//     data_len u16[2] + name_len u16[2] + type u8[1]: name_len @27,
//     type @29, name @30; the target inode is location.objectid @0.
//   - btrfs_root_item = btrfs_inode_item[160] + generation u64[8] +
//     root_dirid u64[8] + bytenr u64[8]: the tree-root bytenr is at 176
//     (offset 24 is inode.nbytes, not a tree root).
//   - file_extent_item = generation u64 @0 + ram_bytes u64 @8 + compression
//     u8 @16 + encryption u8 @17 + other_encoding u16 @18 + type u8 @20.
//     Inline data (type 0) follows the 21-byte header at @21; regular /
//     prealloc extents (type 1/2) carry disk_bytenr u64 @21, disk_num_bytes
//     u64 @29, offset u64 @37 and num_bytes u64 @45.
//   - The superblock's sys_chunk_array lives at a fixed struct offset (0x32b
//     on this btrfs-progs v6.6.3 image) whose size is the sys_chunk_array_size
//     field @0xa0. A bounded scan of the superblock is the fallback for other
//     btrfs-progs versions.
//   - The volume label is the 256-byte field at superblock+0x12b (after the
//     98-byte btrfs_dev_item @0xc9).
//
// Everything returned by ListDirectory/GetFile/GetFileByPath/SearchFiles is
// real data parsed from the on-disk trees or an explicit error — never a
// fabricated result (解析红线).

// Btrfs key object/type constants.
const (
	btrfsRootTreeObjectid  = 1
	btrfsChunkTreeObjectid = 3
	btrfsFsTreeObjectid    = 5
	btrfsFirstFreeObjectid = 256 // the FS tree's root directory inode
)

// On-disk item key types (btrfs_item_key.type).
const (
	btrfsInodeItemKey  = 1   // 0x01 INODE_ITEM
	btrfsInodeRefKey   = 12  // 0x0c INODE_REF
	btrfsDirItemKey    = 84  // 0x54 DIR_ITEM
	btrfsDirIndexKey   = 96  // 0x60 DIR_INDEX
	btrfsExtentDataKey = 108 // 0x6c EXTENT_DATA
	btrfsRootItemKey   = 132 // 0x84 ROOT_ITEM
	btrfsChunkItemKey  = 228 // 0xe4 CHUNK_ITEM
)

// btrfs file-type values (btrfs_dir_item type byte).
const (
	btrfsFileTypeRegular = 1
	btrfsFileTypeDir     = 2
)

// btrfsExtentItemBytes is the byte length of a node/leaf item slot: a 17-byte
// key plus either {off u32, size u32} (leaf) or an 8-byte block pointer
// (internal node).
const btrfsItemSlotBytes = 25

// maxSearchDepth bounds recursive directory traversal in SearchFiles and tree
// descent in walkTreeLevel; maxSearchCount bounds the number of results
// SearchFiles may return. They mirror the parent filesystem package's bounds,
// which are unexported there and so re-declared here.
const (
	maxSearchDepth = 32
	maxSearchCount = 100000
)

// btrfsDiskKey is the 17-byte on-disk btrfs key.
type btrfsDiskKey struct {
	objectid uint64
	typ      uint8
	offset   uint64
}

// btrfsItem is a decoded node item. For leaves, off/size locate data within the
// node and data holds the item's payload. For internal nodes, blockptr is the
// child node bytenr (items carry a key+blockptr instead of key+off+size).
type btrfsItem struct {
	key      btrfsDiskKey
	off      uint32
	size     uint32
	data     []byte
	blockptr uint64
}

// btrfsInode holds the fields of an INODE_ITEM needed for listing/info.
type btrfsInode struct {
	size uint64
	mode uint32
}

// btrfsChunk maps a logical address range [logical, logical+length) to a
// physical address (stripe 0's offset, partition-relative byte address).
type btrfsChunk struct {
	logical uint64
	phys    uint64
	length  uint64
}

type Btrfs struct {
	uuid          [16]byte
	fsid          [16]byte
	blocksize     uint32
	totalBytes    uint64
	usedBytes     uint64
	numDevices    uint32
	sysChunkSize  uint64
	chunkRootSize uint64
	label         string

	reader   filesystem.Reader
	startLBA uint64
	readFunc func(startLBA uint64, count uint64) ([]byte, error)

	sectorsize      int
	nodesize        int
	rootBytenr      uint64
	chunkRootBytenr uint64
	chunks          []btrfsChunk

	fsRoot   uint64
	fsItems  []btrfsItem
	fsInodes map[uint64]btrfsInode
}

// Btrfs Super Block (at offset 0x10000 = 64KB)
type BtrfsSuperblock struct {
	Magic           [8]byte   // "_BHRfS_M"
	Generation      uint64    // Transaction ID
	TreeRoot        uint64    // Object ID of tree root
	ChunkRoot       uint64    // Object ID of chunk root
	RootLevel       uint8     // Level of tree root
	ChunkRootLevel  uint8     // Level of chunk root
	_               [2]byte   // Reserved
	ChunkRootObject uint64    // Object ID of chunk root
	TotalBytes      uint64    // Total bytes
	BytesUsed       uint64    // Bytes used
	Length          uint64    // Length of this device
	DeviceID        uint64    // Device ID
	DeviceGroup     uint32    // Device group
	DeviceSize      uint64    // Total bytes on this device
	Type            uint32    // Type flags
	Generation2     uint64    // Generation
	UUID            [16]byte  // UUID of this device
	UUID2           [16]byte  // UUID of the filesystem
	Label           [256]byte // Label
}

const BtrfsMagic = uint64(0x4F5245425346425F) // "_BHRfS_M" as little-endian

// NewBtrfsHandler creates a new btrfs handler. reader is the absolute-LBA
// sector reader (see Reader); startLBA is the partition's first sector. The
// superblock is read and the chunk map is built immediately so every later
// read can translate logical node bytenrs.
func NewBtrfsHandler(reader filesystem.Reader, startLBA uint64) (*Btrfs, error) {
	if reader == nil {
		return nil, fmt.Errorf("btrfs handler requires a reader")
	}
	h := &Btrfs{
		reader:   reader,
		startLBA: startLBA,
	}
	h.readFunc = reader.ReadSectors
	if err := h.readSuperblock(); err != nil {
		return nil, err
	}
	if err := h.buildChunkMap(); err != nil {
		return nil, fmt.Errorf("btrfs: failed to build chunk map: %w", err)
	}
	return h, nil
}

func (btrfs *Btrfs) Type() filesystem.FileSystemType {
	return filesystem.FS_BTRFS
}

// Open parses the superblock from a raw sector window (used by the detection
// path; real reads require a reader via NewBtrfsHandler).
func (btrfs *Btrfs) Open(sectorData []byte) error {
	// Btrfs superblock is at offset 0x10000 (64KB).
	if len(sectorData) < 0x10048 {
		return fmt.Errorf("btrfs: sector data too small")
	}
	if string(sectorData[0x10040:0x10048]) != "_BHRfS_M" {
		return fmt.Errorf("btrfs: invalid magic")
	}
	sbEnd := 0x10000 + 0x1000
	if sbEnd > len(sectorData) {
		sbEnd = len(sectorData)
	}
	sb := sectorData[0x10000:sbEnd]
	btrfs.totalBytes = binary.LittleEndian.Uint64(sb[0x70:0x78])
	btrfs.usedBytes = binary.LittleEndian.Uint64(sb[0x78:0x80])
	btrfs.numDevices = binary.LittleEndian.Uint32(sb[0x88:0x8c])
	btrfs.label = detectBtrfsLabel(sb)
	btrfs.blocksize = 4096
	return nil
}

func (btrfs *Btrfs) Close() error { return nil }

// readBytes reads length bytes at partition-relative byte offset off via the
// handler's reader. Every read is bounds-checked and returns an explicit error
// on short reads (EWF 红线).
func (btrfs *Btrfs) readBytes(off uint64, length uint64) ([]byte, error) {
	if length == 0 {
		return []byte{}, nil
	}
	if btrfs.readFunc == nil {
		return nil, fmt.Errorf("btrfs: handler has no reader")
	}
	const sectorSize = 512
	if off > 1<<40 {
		return nil, fmt.Errorf("btrfs: read offset 0x%x out of range", off)
	}
	if length > 1<<30 {
		return nil, fmt.Errorf("btrfs: read length %d out of range", length)
	}
	byteOff := btrfs.startLBA*sectorSize + off
	lba := byteOff / sectorSize
	start := byteOff % sectorSize
	count := (start + length + sectorSize - 1) / sectorSize
	data, err := btrfs.readFunc(lba, count)
	if err != nil {
		return nil, err
	}
	if start+length > uint64(len(data)) {
		return nil, fmt.Errorf("btrfs: short read at byte 0x%x: got %d bytes, want %d", off, len(data), start+length)
	}
	return data[start : start+length], nil
}

// readSuperblock reads and validates the 4096-byte superblock at byte 0x10000
// and caches the fields the tree walk needs.
func (btrfs *Btrfs) readSuperblock() error {
	sb, err := btrfs.readBytes(0x10000, 0x1000)
	if err != nil {
		return fmt.Errorf("btrfs: failed to read superblock: %w", err)
	}
	if len(sb) < 0xa4 {
		return fmt.Errorf("btrfs: superblock too small")
	}
	if string(sb[0x40:0x48]) != "_BHRfS_M" {
		return fmt.Errorf("btrfs: invalid magic")
	}
	btrfs.rootBytenr = binary.LittleEndian.Uint64(sb[0x50:0x58])
	btrfs.chunkRootBytenr = binary.LittleEndian.Uint64(sb[0x58:0x60])
	btrfs.totalBytes = binary.LittleEndian.Uint64(sb[0x70:0x78])
	btrfs.usedBytes = binary.LittleEndian.Uint64(sb[0x78:0x80])
	btrfs.numDevices = binary.LittleEndian.Uint32(sb[0x88:0x8c])
	btrfs.sectorsize = int(binary.LittleEndian.Uint32(sb[0x90:0x94]))
	btrfs.nodesize = int(binary.LittleEndian.Uint32(sb[0x94:0x98]))
	btrfs.blocksize = uint32(btrfs.nodesize)
	if btrfs.sectorsize < 512 || btrfs.sectorsize > 0x10000 || (btrfs.sectorsize&(btrfs.sectorsize-1)) != 0 {
		return fmt.Errorf("btrfs: invalid sectorsize %d", btrfs.sectorsize)
	}
	if btrfs.nodesize < 0x1000 || btrfs.nodesize > 0x10000 || (btrfs.nodesize&(btrfs.nodesize-1)) != 0 {
		return fmt.Errorf("btrfs: invalid nodesize %d", btrfs.nodesize)
	}
	if btrfs.rootBytenr == 0 || btrfs.chunkRootBytenr == 0 {
		return fmt.Errorf("btrfs: superblock has zero root or chunk_root")
	}
	btrfs.label = detectBtrfsLabel(sb)
	return nil
}

// btrfsSuperDevItemOffset is the byte offset of the 98-byte btrfs_dev_item in
// the 4KiB superblock; the 256-byte label field follows it.
const (
	btrfsSuperDevItemOffset  = 0xc9
	btrfsSuperLabelOffset    = btrfsSuperDevItemOffset + 98 // 0x12b
	btrfsSuperLabelLen       = 256
	btrfsSuperSysChunkOff    = 0x32b // btrfs-progs v6.6.3 sys_chunk_array position
	btrfsSuperSysChunkSizeAt = 0xa0  // sys_chunk_array_size field
)

// detectBtrfsLabel extracts the volume label from its real superblock field:
// 256 bytes at offset 0x12b (after the 98-byte btrfs_dev_item at 0xc9),
// NUL-terminated. If the field reads empty (defensive, e.g. images made by a
// different btrfs-progs struct layout), it falls back to the longest printable
// ASCII run inside that region. Returns "" when nothing printable is found.
func detectBtrfsLabel(sb []byte) string {
	if len(sb) >= btrfsSuperLabelOffset+btrfsSuperLabelLen {
		raw := sb[btrfsSuperLabelOffset : btrfsSuperLabelOffset+btrfsSuperLabelLen]
		if i := indexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		if label := strings.Trim(string(raw), " \t"); label != "" {
			return label
		}
	}
	// Defensive fallback: no real label in the field — take the longest
	// printable run inside the same region.
	lo, hi := btrfsSuperLabelOffset, btrfsSuperLabelOffset+btrfsSuperLabelLen
	if lo > len(sb) {
		return ""
	}
	if hi > len(sb) {
		hi = len(sb)
	}
	best := ""
	cur := ""
	for i := lo; i < hi; i++ {
		c := sb[i]
		if c >= 0x20 && c < 0x7f {
			cur += string(c)
		} else {
			if len(cur) > len(best) {
				best = cur
			}
			cur = ""
		}
	}
	if len(cur) > len(best) {
		best = cur
	}
	return best
}

// indexByte returns the index of the first occurrence of c in b, or -1.
func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// parseBtrfsKey decodes a 17-byte on-disk key.
func parseBtrfsKey(b []byte) (btrfsDiskKey, error) {
	if len(b) < 17 {
		return btrfsDiskKey{}, fmt.Errorf("btrfs: key buffer too short")
	}
	return btrfsDiskKey{
		objectid: binary.LittleEndian.Uint64(b[0:8]),
		typ:      b[8],
		offset:   binary.LittleEndian.Uint64(b[9:17]),
	}, nil
}

// keyLess reports whether a < b in btrfs key order.
func keyLess(a, b btrfsDiskKey) bool {
	return a.objectid < b.objectid ||
		(a.objectid == b.objectid && (a.typ < b.typ ||
			(a.typ == b.typ && a.offset < b.offset)))
}

// buildChunkMap builds the logical->physical chunk map. It first bootstraps
// from chunk items embedded in the superblock (the sys_chunk_array), then reads
// the chunk tree to obtain the full map.
func (btrfs *Btrfs) buildChunkMap() error {
	sb, err := btrfs.readBytes(0x10000, 0x1000)
	if err != nil {
		return err
	}
	chunks, err := btrfs.scanSuperblockChunks(sb)
	if err != nil {
		return err
	}
	if len(chunks) == 0 {
		return fmt.Errorf("btrfs: no chunk items found in superblock")
	}
	btrfs.chunks = chunks

	// Read the chunk tree to get the complete chunk map. The same node walk
	// used for the root/fs trees descends internal nodes, so multi-level chunk
	// trees are handled without special casing (all chunk-tree nodes live in
	// the SYSTEM chunk covered by the bootstrap map).
	err = btrfs.walkTree(btrfs.chunkRootBytenr, func(items []btrfsItem) error {
		for _, it := range items {
			if it.key.typ != btrfsChunkItemKey {
				continue
			}
			length, phys, _, ok := parseBtrfsChunkItem(it.data)
			if !ok {
				continue
			}
			btrfs.chunks = append(btrfs.chunks, btrfsChunk{logical: it.key.offset, phys: phys, length: length})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("btrfs: chunk tree: %w", err)
	}
	sort.Slice(btrfs.chunks, func(i, j int) bool {
		return btrfs.chunks[i].logical < btrfs.chunks[j].logical
	})
	return nil
}

// scanSuperblockChunks reads the chunks embedded in the superblock
// (the sys_chunk_array content, used to bootstrap the chunk-map read). It
// tries the real struct offset of the sys_chunk_array first and only falls
// back to a bounded scan of the superblock when that fails validation.
func (btrfs *Btrfs) scanSuperblockChunks(sb []byte) ([]btrfsChunk, error) {
	chunks, ok := btrfs.sysChunkAt(btrfsSuperSysChunkOff, sb)
	if ok {
		return chunks, nil
	}
	for p := 0; p+17+48 <= len(sb); p++ {
		if sb[p+8] != btrfsChunkItemKey {
			continue
		}
		key, err := parseBtrfsKey(sb[p : p+17])
		if err != nil {
			continue
		}
		if key.offset < 0x100000 {
			continue
		}
		if btrfs.totalBytes > 0 && key.offset >= btrfs.totalBytes {
			continue
		}
		length, phys, _, ok := parseBtrfsChunkItem(sb[p+17:])
		if !ok {
			continue
		}
		chunks = append(chunks, btrfsChunk{logical: key.offset, phys: phys, length: length})
	}
	return chunks, nil
}

// sysChunkAt decodes the sys_chunk_array entries beginning at superblock
// offset off: consecutive key{_,0xe4,_}+chunk-item pairs, bounded by the
// sys_chunk_array_size field. Returns ok=false when no entry validates.
func (btrfs *Btrfs) sysChunkAt(off int, sb []byte) ([]btrfsChunk, bool) {
	var chunks []btrfsChunk
	sz := int(binary.LittleEndian.Uint32(sb[btrfsSuperSysChunkSizeAt : btrfsSuperSysChunkSizeAt+4]))
	if sz <= 0 || sz > 4096 {
		return nil, false
	}
	end := off + sz
	if end > len(sb) {
		end = len(sb)
	}
	for p := off; p+17+48 <= end; {
		if sb[p+8] != btrfsChunkItemKey {
			break
		}
		key, err := parseBtrfsKey(sb[p : p+17])
		if err != nil || key.typ != btrfsChunkItemKey {
			break
		}
		if key.offset < 0x100000 {
			break
		}
		if btrfs.totalBytes > 0 && key.offset >= btrfs.totalBytes {
			break
		}
		length, phys, numStripes, ok := parseBtrfsChunkItem(sb[p+17:])
		if !ok {
			break
		}
		chunks = append(chunks, btrfsChunk{logical: key.offset, phys: phys, length: length})
		p += 17 + 48 + int(numStripes)*32
	}
	if len(chunks) == 0 {
		return nil, false
	}
	return chunks, true
}

// parseBtrfsChunkItem validates a chunk item and returns its length, stripe 0
// physical offset and stripe count. The header is {length u64 @0, owner u64 @8,
// stripe_len u64 @16, type u64 @24, io_align u32 @32, io_width u32 @36,
// sector_size u32 @40, num_stripes u16 @44, sub_stripes u16 @46, stripes @48}
// with 32-byte stripes {devid u64, offset u64, dev_uuid 16}. Validation is
// structural only: no hard caps on length/phys that would reject legitimate
// large images; every field is bounds-checked so malformed data yields ok=false
// and never a panic.
func parseBtrfsChunkItem(b []byte) (uint64, uint64, uint16, bool) {
	if len(b) < 48 {
		return 0, 0, 0, false
	}
	length := binary.LittleEndian.Uint64(b[0:8])
	stripeLen := binary.LittleEndian.Uint64(b[16:24])
	typ := binary.LittleEndian.Uint64(b[24:32])
	ioAlign := binary.LittleEndian.Uint32(b[32:36])
	ioWidth := binary.LittleEndian.Uint32(b[36:40])
	sectorSize := binary.LittleEndian.Uint32(b[40:44])
	numStripes := binary.LittleEndian.Uint16(b[44:46])
	subStripes := binary.LittleEndian.Uint16(b[46:48])

	if length < 0x100000 || length > 1<<48 || length%0x100000 != 0 {
		return 0, 0, 0, false
	}
	if stripeLen != 0x10000 && stripeLen != 0x1000 {
		return 0, 0, 0, false
	}
	profile := typ & 0x7
	if profile != 1 && profile != 2 && profile != 4 {
		return 0, 0, 0, false
	}
	if ioAlign != ioWidth || (ioAlign != 0x10000 && ioAlign != 0x1000) {
		return 0, 0, 0, false
	}
	if sectorSize < 512 || sectorSize > 0x10000 || (sectorSize&(sectorSize-1)) != 0 {
		return 0, 0, 0, false
	}
	if numStripes < 1 || numStripes > 32 || subStripes > 32 {
		return 0, 0, 0, false
	}
	if len(b) < 48+int(numStripes)*32 {
		return 0, 0, 0, false
	}
	dev := binary.LittleEndian.Uint64(b[48:56])
	phys := binary.LittleEndian.Uint64(b[56:64])
	if dev == 0 || phys == 0 || phys > 1<<48 {
		return 0, 0, 0, false
	}
	return length, phys, numStripes, true
}

// translate maps a logical bytenr to its physical (partition-relative) address.
func (btrfs *Btrfs) translate(addr uint64) (uint64, error) {
	for _, c := range btrfs.chunks {
		if addr >= c.logical && addr < c.logical+c.length {
			return c.phys + (addr - c.logical), nil
		}
	}
	return 0, fmt.Errorf("btrfs: no chunk covers logical address 0x%x", addr)
}

// readNode reads a node at a logical bytenr, translates it and decodes it.
func (btrfs *Btrfs) readNode(bytenr uint64) (level uint8, owner uint64, items []btrfsItem, err error) {
	addr, err := btrfs.translate(bytenr)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("btrfs: translate node 0x%x: %w", bytenr, err)
	}
	data, err := btrfs.readBytes(addr, uint64(btrfs.nodesize))
	if err != nil {
		return 0, 0, nil, fmt.Errorf("btrfs: read node 0x%x: %w", bytenr, err)
	}
	return btrfs.decodeNode(data, bytenr)
}

// decodeNode parses a node/leaf header and item array. It is fully
// bounds-checked so malformed on-disk data yields an error, never a panic.
func (btrfs *Btrfs) decodeNode(data []byte, expectBytenr uint64) (level uint8, owner uint64, items []btrfsItem, err error) {
	if len(data) < 101 {
		return 0, 0, nil, fmt.Errorf("btrfs: node too small")
	}
	nodeBytenr := binary.LittleEndian.Uint64(data[48:56])
	if expectBytenr != 0 && nodeBytenr != expectBytenr {
		return 0, 0, nil, fmt.Errorf("btrfs: node bytenr 0x%x does not match expected 0x%x", nodeBytenr, expectBytenr)
	}
	nritems := binary.LittleEndian.Uint32(data[96:100])
	level = data[100]
	owner = binary.LittleEndian.Uint64(data[88:96])
	if nritems == 0 || nritems > 4096 {
		return 0, 0, nil, fmt.Errorf("btrfs: invalid item count %d", nritems)
	}
	if level > 2 {
		return 0, 0, nil, fmt.Errorf("btrfs: invalid node level %d", level)
	}

	P, shift := findBtrfsItemLayout(data, int(nritems), level)
	if P < 0 {
		return 0, 0, nil, fmt.Errorf("btrfs: cannot locate item array in node 0x%x", expectBytenr)
	}

	items = make([]btrfsItem, 0, nritems)
	for i := 0; i < int(nritems); i++ {
		o := P + i*btrfsItemSlotBytes
		if o+btrfsItemSlotBytes > len(data) {
			return 0, 0, nil, fmt.Errorf("btrfs: item %d out of bounds", i)
		}
		key, err := parseBtrfsKey(data[o : o+17])
		if err != nil {
			return 0, 0, nil, err
		}
		it := btrfsItem{key: key}
		if level == 0 {
			off := int(binary.LittleEndian.Uint32(data[o+17 : o+21]))
			size := int(binary.LittleEndian.Uint32(data[o+21 : o+25]))
			if off+shift < 0 || off+shift+size > len(data) {
				return 0, 0, nil, fmt.Errorf("btrfs: item %d data out of bounds (off %d size %d)", i, off, size)
			}
			it.off = uint32(off)
			it.size = uint32(size)
			it.data = data[off+shift : off+shift+size]
		} else {
			it.blockptr = binary.LittleEndian.Uint64(data[o+17 : o+25])
		}
		items = append(items, it)
	}
	return level, owner, items, nil
}

// btrfsLeafDataOffset is the byte at which a node's item array starts on
// genuine btrfs: BTRFS_LEAF_DATA_OFFSET = 0x65 = 101.
const btrfsLeafDataOffset = 101

// findBtrfsItemLayout locates the node's item-array start P and the data shift
// (for leaves; the on-disk item offsets are relative to P on the committed
// fixture, so shift = len(data)-(item[0].off+item[0].size)). It tries the spec
// position first (P=101 = BTRFS_LEAF_DATA_OFFSET) and only falls back to a
// bounded scan of candidate positions for layouts produced by other btrfs
// implementations. Returns P and shift, or (-1,-1) when no candidate validates.
func findBtrfsItemLayout(data []byte, nritems int, level uint8) (int, int) {
	if p, shift, ok := validateBtrfsItemLayout(data, nritems, level, btrfsLeafDataOffset); ok {
		return p, shift
	}
	for p := 0x40; p <= 0x100; p++ {
		if p == btrfsLeafDataOffset {
			continue
		}
		if p+nritems*btrfsItemSlotBytes > len(data) {
			break
		}
		if p, shift, ok := validateBtrfsItemLayout(data, nritems, level, p); ok {
			return p, shift
		}
	}
	return -1, -1
}

// validateBtrfsItemLayout checks that the item array at position p decodes as a
// well-formed btrfs node item array (sorted keys; for leaves, data offsets
// descending from the node end with a small shift; for internal nodes, plausible
// block pointers). Fully bounds-checked: malformed data returns ok=false.
func validateBtrfsItemLayout(data []byte, nritems int, level uint8, p int) (int, int, bool) {
	if p+nritems*btrfsItemSlotBytes > len(data) {
		return 0, 0, false
	}
	// Items must be sorted ascending by key.
	var prev btrfsDiskKey
	for i := 0; i < nritems; i++ {
		o := p + i*btrfsItemSlotBytes
		if o+17 > len(data) {
			return 0, 0, false
		}
		k, err := parseBtrfsKey(data[o : o+17])
		if err != nil {
			return 0, 0, false
		}
		if i > 0 && keyLess(k, prev) {
			return 0, 0, false
		}
		prev = k
	}

	if level > 0 {
		// Internal node: each slot is key+blockptr. Validate the block
		// pointers are plausible child addresses.
		for i := 0; i < nritems; i++ {
			o := p + i*btrfsItemSlotBytes
			bp := binary.LittleEndian.Uint64(data[o+17 : o+25])
			if bp < 0x10000 || bp%0x1000 != 0 {
				return 0, 0, false
			}
		}
		return p, 0, true
	}

	// Leaf: item data offsets must run strictly downward from the end of the
	// node, and the resulting shift must be small.
	var firstOff, firstSize uint32
	lastEnd := len(data) + 1
	for i := 0; i < nritems; i++ {
		o := p + i*btrfsItemSlotBytes
		off := int(binary.LittleEndian.Uint32(data[o+17 : o+21]))
		size := int(binary.LittleEndian.Uint32(data[o+21 : o+25]))
		if i == 0 {
			firstOff, firstSize = uint32(off), uint32(size)
		}
		if off < p || off+size > len(data) {
			return 0, 0, false
		}
		if i > 0 && off+size > lastEnd {
			return 0, 0, false
		}
		lastEnd = off
	}
	shift := len(data) - (int(firstOff) + int(firstSize))
	if shift < 0 || shift > 0x100 {
		return 0, 0, false
	}
	for i := 0; i < nritems; i++ {
		o := p + i*btrfsItemSlotBytes
		off := int(binary.LittleEndian.Uint32(data[o+17 : o+21]))
		size := int(binary.LittleEndian.Uint32(data[o+21 : o+25]))
		if off+shift+size > len(data) {
			return 0, 0, false
		}
	}
	return p, shift, true
}

// walkTree reads a tree rooted at bytenr, descending internal nodes, and calls
// collect for every leaf's items. Cycles and excessive depth are explicit
// errors, never hangs or panics.
func (btrfs *Btrfs) walkTree(bytenr uint64, collect func([]btrfsItem) error) error {
	visited := make(map[uint64]struct{})
	return btrfs.walkTreeLevel(bytenr, collect, visited, 0)
}

func (btrfs *Btrfs) walkTreeLevel(bytenr uint64, collect func([]btrfsItem) error, visited map[uint64]struct{}, depth int) error {
	if depth > maxSearchDepth {
		return fmt.Errorf("btrfs: tree exceeds depth %d", maxSearchDepth)
	}
	if _, seen := visited[bytenr]; seen {
		return fmt.Errorf("btrfs: tree cycle at bytenr 0x%x", bytenr)
	}
	visited[bytenr] = struct{}{}
	level, _, items, err := btrfs.readNode(bytenr)
	if err != nil {
		return err
	}
	if level == 0 {
		return collect(items)
	}
	for _, it := range items {
		if it.blockptr == 0 {
			continue
		}
		if err := btrfs.walkTreeLevel(it.blockptr, collect, visited, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// rootItemBytenr extracts a ROOT_ITEM's tree-root bytenr from the real spec
// position: btrfs_root_item = btrfs_inode_item[160] + generation u64 + root_dirid
// u64 + bytenr u64, so bytenr is at offset 176. (Offset 24 is inode.nbytes, not
// a tree root.) The candidate is validated by reading the node (must decode as
// the FS tree root leaf). Returns (0,false) when it does not validate.
func (btrfs *Btrfs) rootItemBytenr(data []byte) (uint64, bool) {
	const bytenrOff = 176
	if len(data) < bytenrOff+8 {
		return 0, false
	}
	c := binary.LittleEndian.Uint64(data[bytenrOff : bytenrOff+8])
	if c < 0x10000 {
		return 0, false
	}
	level, owner, _, err := btrfs.readNode(c)
	if err != nil {
		return 0, false
	}
	if level == 0 && owner == btrfsFsTreeObjectid {
		return c, true
	}
	return 0, false
}

// fsTreeRoot finds the FS subvolume (objectid 5) root bytenr by walking the
// root tree and reading its ROOT_ITEM.
func (btrfs *Btrfs) fsTreeRoot() (uint64, error) {
	var result uint64
	err := btrfs.walkTree(btrfs.rootBytenr, func(items []btrfsItem) error {
		for _, it := range items {
			if it.key.typ != btrfsRootItemKey || it.key.objectid != btrfsFsTreeObjectid {
				continue
			}
			if bytenr, ok := btrfs.rootItemBytenr(it.data); ok {
				result = bytenr
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if result == 0 {
		return 0, fmt.Errorf("btrfs: fs tree root not found in root tree")
	}
	return result, nil
}

// ensureFsTree lazily reads the FS tree into the handler cache. All later
// directory/file operations work off the cached items.
func (btrfs *Btrfs) ensureFsTree() error {
	if btrfs.fsItems != nil {
		return nil
	}
	fsRoot, err := btrfs.fsTreeRoot()
	if err != nil {
		return err
	}
	btrfs.fsRoot = fsRoot
	items := make([]btrfsItem, 0, 16)
	err = btrfs.walkTree(fsRoot, func(leaf []btrfsItem) error {
		items = append(items, leaf...)
		return nil
	})
	if err != nil {
		return err
	}
	btrfs.fsItems = items
	btrfs.fsInodes = make(map[uint64]btrfsInode)
	for _, it := range items {
		if it.key.typ != btrfsInodeItemKey {
			continue
		}
		if len(it.data) < 56 {
			continue
		}
		size := binary.LittleEndian.Uint64(it.data[16:24])
		mode := binary.LittleEndian.Uint32(it.data[52:56])
		btrfs.fsInodes[it.key.objectid] = btrfsInode{size: size, mode: mode}
	}
	return nil
}

// parseBtrfsDirItem decodes a DIR_ITEM/DIR_INDEX payload into
// (name, targetInode, fileType, ok). btrfs_dir_item = location btrfs_disk_key
// [17] + transid u64 + data_len u16 + name_len u16 + type u8, so name_len is at
// 27, type at 29 and name at 30; the target inode is location.objectid @0.
// Every read is bounds-checked and the name must be printable, so malformed
// data yields ok=false and never a panic.
func parseBtrfsDirItem(data []byte) (string, uint64, uint8, bool) {
	if len(data) < 30 {
		return "", 0, 0, false
	}
	nl := int(binary.LittleEndian.Uint16(data[27:29]))
	if nl < 1 || nl > 255 || 30+nl > len(data) {
		return "", 0, 0, false
	}
	name := data[30 : 30+nl]
	if !printableBtrfsName(name) {
		return "", 0, 0, false
	}
	return string(name), binary.LittleEndian.Uint64(data[0:8]), data[29], true
}

// printableBtrfsName reports whether name contains no control bytes, so a
// guessed name length can be trusted as real on-disk data.
func printableBtrfsName(name []byte) bool {
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// readExtent reads a file's EXTENT_DATA payload. Inline data (type 0) is
// returned directly from the item; regular/prealloc extents (type 1/2) are read
// through the chunk map. file_extent_item = generation u64 @0 + ram_bytes u64
// @8 + compression u8 @16 + encryption u8 @17 + other_encoding u16 @18 + type
// u8 @20, then for disk extents disk_bytenr u64 @21, disk_num_bytes u64 @29,
// offset u64 @37 and num_bytes u64 @45. The file bytes for this extent are the
// num_bytes bytes at logical disk_bytenr+offset. Unsupported
// compression/encryption is an explicit error, never fabricated content; every
// read is bounds-checked.
func (btrfs *Btrfs) readExtent(data []byte) ([]byte, error) {
	if len(data) < 21 {
		return nil, fmt.Errorf("btrfs: extent item too small (%d bytes)", len(data))
	}
	typ := data[20]
	if typ == 0 { // BTRFS_FILE_EXTENT_INLINE: the file bytes follow the header.
		return append([]byte(nil), data[21:]...), nil
	}
	if typ != 1 && typ != 2 { // BTRFS_FILE_EXTENT_REG / PREALLOC
		return nil, fmt.Errorf("btrfs: unsupported extent type %d", typ)
	}
	if len(data) < 53 {
		return nil, fmt.Errorf("btrfs: extent item too small for a disk extent (%d bytes)", len(data))
	}
	if data[16] != 0 || data[17] != 0 {
		return nil, fmt.Errorf("btrfs: compressed or encrypted extent unsupported")
	}
	diskBytenr := binary.LittleEndian.Uint64(data[21:29])
	diskNumBytes := binary.LittleEndian.Uint64(data[29:37])
	extentOff := binary.LittleEndian.Uint64(data[37:45])
	numBytes := binary.LittleEndian.Uint64(data[45:53])
	if diskBytenr == 0 {
		// Hole (or prealloc without backing data): the extent reads as zeros.
		if numBytes > 1<<30 {
			return nil, fmt.Errorf("btrfs: invalid hole extent length %d", numBytes)
		}
		return make([]byte, numBytes), nil
	}
	if diskNumBytes == 0 || numBytes == 0 || numBytes > 1<<30 || diskNumBytes > 1<<30 {
		return nil, fmt.Errorf("btrfs: invalid extent length disk=%d file=%d", diskNumBytes, numBytes)
	}
	if extentOff > 1<<40 || diskBytenr > 1<<40 || extentOff+numBytes > diskNumBytes {
		return nil, fmt.Errorf("btrfs: invalid extent disk_bytenr 0x%x offset 0x%x num %d disk %d", diskBytenr, extentOff, numBytes, diskNumBytes)
	}
	addr, err := btrfs.translate(diskBytenr + extentOff)
	if err != nil {
		return nil, fmt.Errorf("btrfs: extent disk_bytenr 0x%x: %w", diskBytenr, err)
	}
	return btrfs.readBytes(addr, numBytes)
}

// resolveInodeFromItems resolves a slash-separated path (no leading/trailing
// slash) to an inode by walking DIR_ITEM/DIR_INDEX entries of the FS tree.
func (btrfs *Btrfs) resolveInodeFromItems(items []btrfsItem, path string) (uint64, error) {
	parts := splitBtrfsPath(path)
	inode := uint64(btrfsFirstFreeObjectid)
	for _, part := range parts {
		found := false
		for _, it := range items {
			if it.key.typ != btrfsDirItemKey && it.key.typ != btrfsDirIndexKey {
				continue
			}
			if it.key.objectid != inode {
				continue
			}
			name, child, _, ok := parseBtrfsDirItem(it.data)
			if ok && name == part {
				inode = child
				found = true
				break
			}
		}
		if !found {
			// Classify the miss: a name missing under a real directory is a
			// not-found, while a path that tries to descend through a regular
			// file (or any non-directory inode) is a not-a-directory. Both are
			// exported sentinels so callers such as OpenFile can route them.
			if in, ok := btrfs.fsInodes[inode]; ok && (in.mode&0xF000) != 0x4000 {
				return 0, fmt.Errorf("btrfs: %q is not a directory: %w", part, filesystem.ErrNotDirectory)
			}
			return 0, fmt.Errorf("btrfs: path component not found: %q: %w", part, filesystem.ErrNotFound)
		}
	}
	return inode, nil
}

// splitBtrfsPath splits a cleaned path into non-empty components.
func splitBtrfsPath(path string) []string {
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// ListDirectory lists files in the specified directory path. An empty or "/"
// path lists the root directory.
func (btrfs *Btrfs) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	if btrfs.readFunc == nil {
		return nil, fmt.Errorf("btrfs: handler has no reader")
	}
	if err := btrfs.ensureFsTree(); err != nil {
		return nil, err
	}
	clean := strings.Trim(path, "/")
	inode := uint64(btrfsFirstFreeObjectid)
	if clean != "" {
		var err error
		inode, err = btrfs.resolveInodeFromItems(btrfs.fsItems, clean)
		if err != nil {
			return nil, err
		}
		in, ok := btrfs.fsInodes[inode]
		if ok && (in.mode&0xF000) != 0x4000 {
			return nil, fmt.Errorf("btrfs: %q is not a directory", path)
		}
	}
	return btrfs.listDirInode(inode, path)
}

// listDirInode returns the directory entries of the given directory inode.
// Sizes and directory flags come from each child's INODE_ITEM; the result is a
// non-nil empty slice for a genuinely empty directory (解析红线). Btrfs stores
// each entry twice (a DIR_ITEM keyed by name hash and a DIR_INDEX keyed by
// insertion index), so entries are deduplicated by name per directory.
func (btrfs *Btrfs) listDirInode(inode uint64, path string) ([]filesystem.DirectoryEntry, error) {
	entries := make([]filesystem.DirectoryEntry, 0, 4)
	seen := make(map[string]struct{})
	for _, it := range btrfs.fsItems {
		if it.key.typ != btrfsDirItemKey && it.key.typ != btrfsDirIndexKey {
			continue
		}
		if it.key.objectid != inode {
			continue
		}
		name, child, _, ok := parseBtrfsDirItem(it.data)
		if !ok {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		de := filesystem.DirectoryEntry{
			Name:  name,
			Path:  filesystem.JoinPath(path, name),
			Inode: child,
		}
		if in, ok := btrfs.fsInodes[child]; ok {
			de.Size = in.size
			de.IsDir = (in.mode & 0xF000) == 0x4000
		}
		entries = append(entries, de)
	}
	return entries, nil
}

// maxExtentEnd returns the greatest file byte offset reached by inode's
// EXTENT_DATA items (the end of its last usable extent), or 0 when the inode has
// no usable extents. Inline extents (type 0) span len(data)-21 bytes; regular
// and prealloc extents (type 1/2) span their num_bytes field, honored only when
// the item is structurally long enough and num_bytes <= 1<<30 — the same bound
// readExtent enforces. Malformed or oversized extent items contribute 0 (they
// surface as an explicit error from readExtent later). The result bounds what the
// INODE_ITEM's st_size is trusted up to: sizes beyond the extent coverage are not
// backed by real data and must never drive an allocation (EWF 红线).
func (btrfs *Btrfs) maxExtentEnd(inode uint64) uint64 {
	const (
		maxExtentLen = uint64(1) << 30
		maxUint64    = ^uint64(0)
	)
	var maxEnd uint64
	for _, it := range btrfs.fsItems {
		if it.key.typ != btrfsExtentDataKey || it.key.objectid != inode {
			continue
		}
		if len(it.data) < 21 {
			continue // malformed; readExtent will error on it
		}
		var span uint64
		switch it.data[20] {
		case 0: // BTRFS_FILE_EXTENT_INLINE: the file bytes follow the header.
			span = uint64(len(it.data) - 21)
		case 1, 2: // BTRFS_FILE_EXTENT_REG / PREALLOC
			if len(it.data) < 53 {
				continue
			}
			n := binary.LittleEndian.Uint64(it.data[45:53])
			if n > maxExtentLen {
				continue // absurd; readExtent will error on it
			}
			span = n
		default:
			continue
		}
		if span == 0 {
			continue
		}
		if it.key.offset > maxUint64-span {
			continue // overflow-safe: out of representable range
		}
		if end := it.key.offset + span; end > maxEnd {
			maxEnd = end
		}
	}
	return maxEnd
}

// GetFile reads a file's contents by resolving its path to an inode and
// assembling its EXTENT_DATA items.
func (btrfs *Btrfs) GetFile(path string) ([]byte, error) {
	if btrfs.readFunc == nil {
		return nil, fmt.Errorf("btrfs: handler has no reader")
	}
	if err := btrfs.ensureFsTree(); err != nil {
		return nil, err
	}
	clean := strings.Trim(path, "/")
	if clean == "" {
		return nil, fmt.Errorf("btrfs: root path has no file content")
	}
	inode, err := btrfs.resolveInodeFromItems(btrfs.fsItems, clean)
	if err != nil {
		return nil, err
	}
	if in, ok := btrfs.fsInodes[inode]; ok && (in.mode&0xF000) == 0x4000 {
		return nil, fmt.Errorf("btrfs: path is a directory: %s", path)
	}
	// Assemble the extents at their file offsets and truncate to the inode's
	// real size (from its INODE_ITEM), so the returned bytes are exactly the
	// on-disk file content. Gaps (holes) read as zeros, matching btrfs.
	if in, ok := btrfs.fsInodes[inode]; ok {
		// The INODE_ITEM's st_size is an untrusted on-disk field: a crafted value
		// (e.g. 2^48) must never drive a giant allocation. Bound it by the inode's
		// extent-backed coverage, then by a hard cap; anything beyond those limits
		// is an explicit error, not an OOM (EWF 红线). For genuine files maxEnd
		// equals in.size, so this is a no-op there.
		size := in.size
		if maxEnd := btrfs.maxExtentEnd(inode); size > maxEnd {
			size = maxEnd
		}
		const maxBtrfsFileBytes = uint64(1) << 40 // 1 TiB; no single-file read needs more
		if size > maxBtrfsFileBytes {
			return nil, fmt.Errorf("btrfs: file inode %d size %d exceeds the supported maximum", inode, size)
		}
		out := make([]byte, size)
		for _, it := range btrfs.fsItems {
			if it.key.typ != btrfsExtentDataKey || it.key.objectid != inode {
				continue
			}
			chunk, err := btrfs.readExtent(it.data)
			if err != nil {
				return nil, fmt.Errorf("btrfs: extent for inode %d: %w", inode, err)
			}
			pos := it.key.offset
			if pos >= size {
				continue
			}
			end := pos + uint64(len(chunk))
			if end > size {
				end = size
			}
			copy(out[pos:end], chunk[:end-pos])
		}
		return out, nil
	}
	var out []byte
	for _, it := range btrfs.fsItems {
		if it.key.typ != btrfsExtentDataKey || it.key.objectid != inode {
			continue
		}
		chunk, err := btrfs.readExtent(it.data)
		if err != nil {
			return nil, fmt.Errorf("btrfs: extent for inode %d: %w", inode, err)
		}
		out = append(out, chunk...)
	}
	if out == nil {
		out = []byte{}
	}
	return out, nil
}

// GetFileByPath gets file info by path.
func (btrfs *Btrfs) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	if btrfs.readFunc == nil {
		return nil, fmt.Errorf("btrfs: handler has no reader")
	}
	if err := btrfs.ensureFsTree(); err != nil {
		return nil, err
	}
	clean := strings.Trim(path, "/")
	if clean == "" {
		return nil, fmt.Errorf("btrfs: root has no file info")
	}
	inode, err := btrfs.resolveInodeFromItems(btrfs.fsItems, clean)
	if err != nil {
		return nil, err
	}
	in, ok := btrfs.fsInodes[inode]
	if !ok {
		return nil, fmt.Errorf("btrfs: inode %d has no inode item", inode)
	}
	isDir := (in.mode & 0xF000) == 0x4000
	mode := filesystem.FileMode(filesystem.ModeRegular)
	if isDir {
		mode = filesystem.ModeDir
	}
	parts := splitBtrfsPath(clean)
	name := parts[len(parts)-1]
	return &filesystem.FileInfo{
		Name:  name,
		Path:  "/" + clean,
		Size:  in.size,
		Mode:  mode,
		IsDir: isDir,
	}, nil
}

// SearchFiles searches for files matching a predicate, recursing through
// directories. Depth and result count are bounded.
func (btrfs *Btrfs) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	if btrfs.readFunc == nil {
		return nil, fmt.Errorf("btrfs: handler has no reader")
	}
	if err := btrfs.ensureFsTree(); err != nil {
		return nil, err
	}
	start := uint64(btrfsFirstFreeObjectid)
	base := ""
	cleanRoot := strings.Trim(rootPath, "/")
	if cleanRoot != "" {
		var err error
		start, err = btrfs.resolveInodeFromItems(btrfs.fsItems, cleanRoot)
		if err != nil {
			return nil, err
		}
		base = "/" + cleanRoot
	}

	results := make([]filesystem.FileInfo, 0)
	visited := make(map[uint64]struct{})

	var walk func(inode uint64, dirPath string, depth int) error
	walk = func(inode uint64, dirPath string, depth int) error {
		if depth > maxSearchDepth {
			return nil
		}
		if _, seen := visited[inode]; seen {
			return nil
		}
		visited[inode] = struct{}{}
		seenNames := make(map[string]struct{})
		for _, it := range btrfs.fsItems {
			if it.key.typ != btrfsDirItemKey && it.key.typ != btrfsDirIndexKey {
				continue
			}
			if it.key.objectid != inode {
				continue
			}
			name, child, _, ok := parseBtrfsDirItem(it.data)
			if !ok {
				continue
			}
			if _, dup := seenNames[name]; dup {
				continue
			}
			seenNames[name] = struct{}{}
			if len(results) >= maxSearchCount {
				return fmt.Errorf("btrfs: search exceeded %d results", maxSearchCount)
			}
			fi := filesystem.FileInfo{
				Name:  name,
				Path:  filesystem.JoinPath(dirPath, name),
				Mode:  filesystem.ModeRegular,
				IsDir: false,
			}
			if in, ok := btrfs.fsInodes[child]; ok {
				fi.Size = in.size
				if (in.mode & 0xF000) == 0x4000 {
					fi.IsDir = true
					fi.Mode = filesystem.ModeDir
				}
			}
			if predicate(fi) {
				results = append(results, fi)
			}
			if fi.IsDir && depth < maxSearchDepth {
				if err := walk(child, fi.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(start, base, 0); err != nil {
		return nil, err
	}
	return results, nil
}

func (btrfs *Btrfs) GetVolumeLabel() string {
	return btrfs.label
}

// GetTotalBytes returns total filesystem size
func (btrfs *Btrfs) GetTotalBytes() uint64 {
	return btrfs.totalBytes
}

// GetUsedBytes returns used bytes
func (btrfs *Btrfs) GetUsedBytes() uint64 {
	return btrfs.usedBytes
}

func init() {
	filesystem.RegisterFileSystem(filesystem.FS_BTRFS, func() filesystem.FileSystem {
		return &Btrfs{}
	})
	filesystem.RegisterHandler(filesystem.FS_BTRFS, func(r filesystem.Reader, startLBA, partitionSize uint64) (filesystem.FileSystem, error) {
		return NewBtrfsHandler(r, startLBA)
	})
}
