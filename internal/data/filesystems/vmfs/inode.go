package vmfs

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// A VMFS file descriptor ("inode") begins with a metadata header whose magic
// is 0x10c00001; the header is 512 bytes on VMFS5 and 4096 bytes on VMFS6.
// The fixed fields follow it:
//
//	+0x00 id          u32     the file descriptor's block id
//	+0x04 id2         u32     generation / record id
//	+0x08 nlink       u32
//	+0x0c type        u32     1 file, 2 directory, 3 symlink
//	+0x10 flags       u32
//	+0x14 size        u64     logical bytes
//	+0x1c blk_size    u64     file-block size
//	+0x24 blk_count   u64     allocated file blocks
//	+0x2c mtime       u32     Unix seconds
//	+0x30 ctime       u32
//	+0x34 atime       u32
//	+0x38 uid         u32
//	+0x3c gid         u32
//	+0x40 mode        u32
//	+0x44 zla         u32     zero-level address type: FB, SB, PB, FD
//
// The block-address array is the last 256 entries of the descriptor: 32-bit on
// VMFS5 (the last 1024 bytes of a 2048-byte descriptor) and 64-bit on VMFS6
// (the last 2048 bytes of an 8192-byte descriptor). A VMFS6 file descriptor has
// 4096 bytes of lock block, 4096 bytes of metadata and then the 64-bit array
// aligned to the descriptor's end.
const (
	inodeMagic uint32 = 0x10C0_0001

	blkTypeMask uint32 = 0x7
	blkTypeFB   uint32 = 1
	blkTypeSB   uint32 = 2
	blkTypePB   uint32 = 3
	blkTypeFD   uint32 = 4
	blkTypePB2  uint32 = 6

	fdEntryShift uint32 = 6
	fdEntryMask  uint32 = 0x7fff
	fdItemShift  uint32 = 22
	fdItemMask   uint32 = 0x3ff

	// rootBlockID is the root directory's file descriptor: FDC entry 0, item 0.
	rootBlockID uint32 = blkTypeFD

	// fileBlockEntries is the number of block addresses in one descriptor.
	fileBlockEntries = 256
)

func blockType(id uint32) uint32 { return id & blkTypeMask }

func fdEntry(id uint32) uint32 { return (id >> fdEntryShift) & fdEntryMask }

func fdItem(id uint32) uint32 { return (id >> fdItemShift) & fdItemMask }

// fdBuild builds a file-descriptor block id from its FDC entry and item.
func fdBuild(entry, item uint32) uint32 {
	return (entry&fdEntryMask)<<fdEntryShift | (item&fdItemMask)<<fdItemShift | blkTypeFD
}

// blockNumber is the physical 1 MiB block a file-block or pointer-block id
// names.
func blockNumber(id uint32) uint64 { return uint64(id >> 3) }

// inodeKind is what a descriptor's type field says an object is.
type inodeKind uint8

const (
	kindFile      inodeKind = 1
	kindDirectory inodeKind = 2
	kindSymlink   inodeKind = 3
)

func (k inodeKind) label() string {
	switch k {
	case kindFile:
		return "file"
	case kindDirectory:
		return "directory"
	case kindSymlink:
		return "symlink"
	default:
		return "unknown"
	}
}

func (k inodeKind) isDirectory() bool { return k == kindDirectory }
func (k inodeKind) isSymlink() bool   { return k == kindSymlink }
func (k inodeKind) isFile() bool      { return k == kindFile }

// inode is one parsed file descriptor.
type inode struct {
	// blockID is the block id this descriptor was read through.
	blockID uint32
	// id is the id field, which must equal blockID.
	id uint32
	// id2 is the generation field, which a directory entry's record id repeats.
	id2       uint32
	links     uint32
	inodeType uint32
	flags     uint32
	kind      inodeKind
	size      uint64
	// blockSize is the file-block size the descriptor declares.
	blockSize uint64
	// blockCount is the number of allocated file blocks.
	blockCount uint64
	// Times are Unix seconds; zero means unset.
	modified uint32
	changed  uint32
	accessed uint32
	uid      uint32
	gid      uint32
	// mode holds the permission and type bits as recorded (lower 16 bits).
	mode uint16
	// zla is the zero-level address type.
	zla uint32
	// blocks holds all 256 block addresses, widened to 64 bits.
	blocks [fileBlockEntries]uint64
	// at is the byte offset of the descriptor in the source.
	at uint64
}

func (in *inode) allocatedBytes() (uint64, error) {
	allocated, ok := mulChecked(in.blockCount, in.blockSize)
	if !ok {
		return 0, corruptf("file descriptor %d's allocation overflows", in.id)
	}
	return allocated, nil
}

// readInode reads one file descriptor through the FDC bitmap.
func readInode(src source.ByteSource, sb *superblock, bitmap *bitmapHeader, blockID uint32) (*inode, error) {
	if blockType(blockID) != blkTypeFD {
		return nil, corruptf("block id 0x%08x has type %d, not a file descriptor (%d)",
			blockID, blockType(blockID), blkTypeFD)
	}
	entry := fdEntry(blockID)
	item := fdItem(blockID)
	relative, ok := bitmap.itemPos(entry, item)
	if !ok {
		return nil, corruptf("file descriptor 0x%08x (FDC entry %d, item %d) is outside the %d items the bitmap header at byte %d declares",
			blockID, entry, item, bitmap.totalItems, bitmap.at)
	}
	base, ok := mulChecked(fdcBaseBlock, uint64(sb.blockSize))
	if !ok {
		return nil, corruptf("the FDC base block overflows")
	}
	at, ok := addChecked(base, relative)
	if !ok {
		return nil, corruptf("the file descriptor's byte offset overflows")
	}
	fdSize := uint64(sb.fdSize)
	end, ok := addChecked(at, fdSize)
	if !ok || end > src.Len() {
		return nil, corruptf("file descriptor 0x%08x at byte %d needs %d bytes, but the source is %d bytes",
			blockID, at, fdSize, src.Len())
	}
	bytes := make([]byte, sb.fdSize)
	if err := source.ReadExactAt(src, at, bytes); err != nil {
		return nil, err
	}
	return parseInode(bytes, blockID, at, sb)
}

// parseInode parses one descriptor's bytes.
func parseInode(bytes []byte, blockID uint32, at uint64, sb *superblock) (*inode, error) {
	fdSize := int(sb.fdSize)
	if len(bytes) != fdSize {
		return nil, corruptf("file descriptor 0x%08x at byte %d is %d bytes, expected %d",
			blockID, at, len(bytes), fdSize)
	}
	magic := le32(bytes, 0)
	if magic != inodeMagic {
		return nil, corruptf("file descriptor 0x%08x at byte %d has no VMFS inode metadata magic 0x%08x; found 0x%08x",
			blockID, at, inodeMagic, magic)
	}
	base := int(sb.metadataHeaderSize)
	entrySize := 4
	if sb.wideBlockAddresses {
		entrySize = 8
	}
	arrayOffset := fdSize - fileBlockEntries*entrySize
	if base+80 > arrayOffset {
		return nil, corruptf("file descriptor 0x%08x at byte %d: a %d-byte metadata header leaves no room for the fixed fields before the block array at offset %d",
			blockID, at, base, arrayOffset)
	}

	id := le32(bytes, base)
	if id != blockID {
		return nil, corruptf("file descriptor at byte %d was read as 0x%08x but names itself 0x%08x", at, blockID, id)
	}
	id2 := le32(bytes, base+4)
	links := le32(bytes, base+8)
	if links == 0 {
		return nil, corruptf("file descriptor 0x%08x at byte %d has a zero link count", blockID, at)
	}
	inodeType := le32(bytes, base+12)
	var kind inodeKind
	switch inodeType {
	case 0:
		return nil, corruptf("file descriptor 0x%08x at byte %d is an unused or deleted slot (type 0); deleted-file recovery is not read", blockID, at)
	case 1:
		kind = kindFile
	case 2:
		kind = kindDirectory
	case 3:
		kind = kindSymlink
	case 4, 5:
		return nil, unsupportedf("file descriptor 0x%08x at byte %d is an RDM/raw-device descriptor (type %d), which is not decoded", blockID, at, inodeType)
	default:
		return nil, unsupportedf("file descriptor 0x%08x at byte %d has inode type %d, which this reader does not decode", blockID, at, inodeType)
	}

	flags := le32(bytes, base+16)
	size := le64(bytes, base+20)
	blockSize := le64(bytes, base+28)
	blockCount := le64(bytes, base+36)
	modified := le32(bytes, base+44)
	changed := le32(bytes, base+48)
	accessed := le32(bytes, base+52)
	uid := le32(bytes, base+56)
	gid := le32(bytes, base+60)
	mode := uint16(le32(bytes, base+64))
	zla := le32(bytes, base+68)

	if size > sb.volumeBytes {
		return nil, corruptf("file descriptor 0x%08x at byte %d declares %d bytes, more than the %d-byte source",
			blockID, at, size, sb.volumeBytes)
	}
	if blockSize == 0 {
		return nil, corruptf("file descriptor 0x%08x at byte %d declares a zero file-block size", blockID, at)
	}
	if blockSize != uint64(sb.blockSize) {
		return nil, unsupportedf("file descriptor 0x%08x at byte %d uses %d-byte file blocks; this reader decodes %d-byte blocks only",
			blockID, at, blockSize, sb.blockSize)
	}
	allocation, ok := mulChecked(blockCount, blockSize)
	if !ok {
		return nil, corruptf("file descriptor 0x%08x at byte %d: the allocation overflows", blockID, at)
	}
	if size > allocation {
		return nil, corruptf("file descriptor 0x%08x at byte %d declares %d bytes but allocates only %d blocks (%d bytes)",
			blockID, at, size, blockCount, allocation)
	}
	if blockCount == 0 && size != 0 {
		return nil, corruptf("file descriptor 0x%08x at byte %d declares %d bytes but allocates no blocks",
			blockID, at, size)
	}
	if blockCount > 0 && zla == 0 {
		return nil, corruptf("file descriptor 0x%08x at byte %d allocates %d blocks but declares zero-level address type 0",
			blockID, at, blockCount)
	}

	var blocks [fileBlockEntries]uint64
	for i := 0; i < fileBlockEntries; i++ {
		offset := arrayOffset + i*entrySize
		if sb.wideBlockAddresses {
			blocks[i] = le64(bytes, offset)
		} else {
			blocks[i] = uint64(le32(bytes, offset))
		}
	}

	return &inode{
		blockID:    blockID,
		id:         id,
		id2:        id2,
		links:      links,
		inodeType:  inodeType,
		flags:      flags,
		kind:       kind,
		size:       size,
		blockSize:  blockSize,
		blockCount: blockCount,
		modified:   modified,
		changed:    changed,
		accessed:   accessed,
		uid:        uid,
		gid:        gid,
		mode:       mode,
		zla:        zla,
		blocks:     blocks,
		at:         at,
	}, nil
}
