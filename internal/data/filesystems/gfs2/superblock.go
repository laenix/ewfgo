package gfs2

import (
	"encoding/hex"

	"github.com/laenix/ewfgo/internal/data/source"
)

// On-disk constants, from Linux include/uapi/linux/gfs2_ondisk.h.
const (
	// BasicBlockSize is the unit GFS2_SB_ADDR is expressed in.
	BasicBlockSize uint64 = 512
	// SuperBlockAddr is GFS2_SB_ADDR, in basic blocks.
	SuperBlockAddr uint64 = 128
	// SuperBlockOffset is the fixed byte offset of the superblock: 128*512.
	SuperBlockOffset uint64 = SuperBlockAddr * BasicBlockSize

	// Magic is GFS2_MAGIC, stored big-endian.
	Magic uint32 = 0x01161970
	// SwappedMagic is the same word as a byte-swapped writer stores it.
	SwappedMagic uint32 = 0x70191601

	// MetaSB is the superblock metatype.
	MetaSB uint32 = 1
	// MetaDI is the dinode metatype.
	MetaDI uint32 = 4
	// MetaIN is the indirect pointer-block metatype.
	MetaIN uint32 = 5
	// MetaLF is the leaf metatype; this reader does not decode it.
	MetaLF uint32 = 6
	// MetaJD is the journaled-data metatype.
	MetaJD uint32 = 7

	// FormatSB is the superblock format.
	FormatSB uint32 = 100
	// FormatDI is the dinode format.
	FormatDI uint32 = 400
	// FormatIN is the indirect pointer-block format.
	FormatIN uint32 = 500
	// FormatLF is the leaf format; this reader does not decode it.
	FormatLF uint32 = 600
	// FormatJD is the journaled-data format.
	FormatJD uint32 = 700

	// FSFormatGFS2 is sb_fs_format for GFS2.
	FSFormatGFS2 uint32 = 1801
	// FSFormatGFS1 is sb_fs_format for the older GFS1.
	FSFormatGFS1 uint32 = 1309
	// MultihostFormatGFS2 is sb_multihost_format for GFS2.
	MultihostFormatGFS2 uint32 = 1900
	// MultihostFormatGFS1 is sb_multihost_format for GFS1.
	MultihostFormatGFS1 uint32 = 1401

	// MinBlockSize is the smallest filesystem block GFS2 permits.
	MinBlockSize uint32 = 512
	// MaxBlockSize is the largest filesystem block GFS2 permits.
	MaxBlockSize uint32 = 4096

	// MetaHeaderSize is sizeof(struct gfs2_meta_header).
	MetaHeaderSize = 24
	// DinodeSize is the fixed part of a dinode, before its data or pointers.
	DinodeSize = 232
	// SuperblockSize is sizeof(struct gfs2_sb).
	SuperblockSize = 0x110
)

// Superblock is a parsed GFS2 superblock.
type Superblock struct {
	// BlockSize is sb_bsize in bytes.
	BlockSize uint32
	// BlockShift is sb_bsize_shift.
	BlockShift uint32
	// TotalBlocks is the volume size in whole filesystem blocks: the source
	// length divided by BlockSize.
	TotalBlocks uint64
	// VolumeBytes is TotalBlocks * BlockSize.
	VolumeBytes uint64
	// SuperBlock is the block that holds the superblock.
	SuperBlock uint64
	// FSFormat is sb_fs_format.
	FSFormat uint32
	// MultihostFormat is sb_multihost_format.
	MultihostFormat uint32
	// RootFormal and RootAddr are sb_root_dir's formal inode and block
	// address. The block address is the inode number this reader reports.
	RootFormal uint64
	RootAddr   uint64
	// MasterFormal and MasterAddr are the master directory's inum.
	MasterFormal uint64
	MasterAddr   uint64
	// LockProto and LockTable are the lock protocol and table names.
	LockProto string
	LockTable string
	// UUID is sb_uuid.
	UUID [16]byte
}

// BlockOffset returns the byte offset of a validated block.
func (s *Superblock) BlockOffset(block uint64) (uint64, bool) {
	offset := block * uint64(s.BlockSize)
	if block != 0 && offset/block != uint64(s.BlockSize) {
		return 0, false
	}
	return offset, true
}

// ValidateBlock checks one block number against the volume's size.
func (s *Superblock) ValidateBlock(block uint64, what string) error {
	if block == 0 {
		return corruptf("%s names block 0, which GFS2 uses as the hole sentinel", what)
	}
	if block >= s.TotalBlocks {
		return corruptf("%s names block %d, out of range for the volume's %d blocks",
			what, block, s.TotalBlocks)
	}
	return nil
}

// JDataSize is the directory payload in one journaled-data block.
func (s *Superblock) JDataSize() uint64 {
	return uint64(s.BlockSize) - MetaHeaderSize
}

// StuffedCapacity is the bytes available for stuffed data in a dinode.
func (s *Superblock) StuffedCapacity() uint64 {
	return uint64(s.BlockSize) - DinodeSize
}

// DinodePointers is the number of top-level pointers in a dinode.
func (s *Superblock) DinodePointers() uint64 {
	return (uint64(s.BlockSize) - DinodeSize) / 8
}

// IndirectPointers is the number of pointers in an indirect IN block.
func (s *Superblock) IndirectPointers() uint64 {
	return (uint64(s.BlockSize) - MetaHeaderSize) / 8
}

// UUIDHex returns the UUID as 32 lowercase hexadecimal digits.
func (s *Superblock) UUIDHex() string { return hex.EncodeToString(s.UUID[:]) }

// detectSuperblock reports whether src carries a GFS2 superblock this reader
// understands. A recognisable but byte-swapped magic is an error by name.
func detectSuperblock(src source.ByteSource) (bool, error) {
	if src.Len() < SuperBlockOffset+4 {
		return false, nil
	}
	var magic [4]byte
	if err := source.ReadExactAt(src, SuperBlockOffset, magic[:]); err != nil {
		return false, err
	}
	switch be32(magic[:], 0) {
	case Magic:
		if _, err := ReadSuperblock(src); err != nil {
			return false, err
		}
		return true, nil
	case SwappedMagic:
		return false, unsupportedf("a byte-swapped GFS2 superblock (its magic is little-endian); this reader decodes big-endian images only")
	default:
		return false, nil
	}
}

// ReadSuperblock reads and validates the superblock at its fixed offset.
func ReadSuperblock(src source.ByteSource) (*Superblock, error) {
	if src.Len() < SuperBlockOffset+SuperblockSize {
		return nil, source.NewUnexpectedEOF(src.Len())
	}
	raw := make([]byte, SuperblockSize)
	if err := source.ReadExactAt(src, SuperBlockOffset, raw); err != nil {
		return nil, err
	}

	magic := be32(raw, 0x00)
	if magic != Magic {
		if magic == SwappedMagic {
			return nil, unsupportedf("a byte-swapped GFS2 superblock (its magic is little-endian); this reader decodes big-endian images only")
		}
		return nil, corruptf("no GFS2 magic at byte %d; found 0x%08x", SuperBlockOffset, magic)
	}
	if metaType := be32(raw, 0x04); metaType != MetaSB {
		return nil, corruptf("the superblock header names metatype %d, not the superblock type %d", metaType, MetaSB)
	}
	if format := be32(raw, 0x10); format != FormatSB {
		return nil, corruptf("the superblock header names format %d, not the superblock format %d", format, FormatSB)
	}

	fsFormat := be32(raw, 0x18)
	if fsFormat == FSFormatGFS1 {
		return nil, unsupportedf("a GFS1 (not GFS2) superblock; this reader decodes GFS2 only")
	}
	if fsFormat != FSFormatGFS2 {
		return nil, unsupportedf("filesystem format %d; this reader decodes GFS2 format %d", fsFormat, FSFormatGFS2)
	}
	multihostFormat := be32(raw, 0x1c)
	if multihostFormat == MultihostFormatGFS1 {
		return nil, unsupportedf("a GFS1 multihost format; this reader decodes GFS2 only")
	}
	if multihostFormat != MultihostFormatGFS2 {
		return nil, unsupportedf("multihost format %d; this reader decodes GFS2 format %d",
			multihostFormat, MultihostFormatGFS2)
	}

	blockSize := be32(raw, 0x24)
	if blockSize < MinBlockSize || blockSize > MaxBlockSize || blockSize&(blockSize-1) != 0 {
		return nil, unsupportedf("block size %d; this reader accepts powers of two from %d through %d",
			blockSize, MinBlockSize, MaxBlockSize)
	}
	blockShift := be32(raw, 0x28)
	if blockShift != trailingZeros(blockSize) {
		return nil, corruptf("block shift %d does not describe the %d-byte block size", blockShift, blockSize)
	}

	sbBlock := SuperBlockOffset / uint64(blockSize)
	if SuperBlockOffset%uint64(blockSize) != 0 {
		return nil, corruptf("the %d-byte block size does not divide the superblock offset %d",
			blockSize, SuperBlockOffset)
	}
	totalBlocks := src.Len() / uint64(blockSize)
	if totalBlocks == 0 {
		return nil, corruptf("the source holds no whole GFS2 block")
	}
	if sbBlock >= totalBlocks {
		return nil, corruptf("the source is %d bytes, too short to hold the superblock's block %d",
			src.Len(), sbBlock)
	}
	volumeBytes := totalBlocks * uint64(blockSize)
	if totalBlocks != 0 && volumeBytes/totalBlocks != uint64(blockSize) {
		return nil, corruptf("the volume size overflows the byte address space")
	}

	lockProto := fixedString(raw, 0x60, 64)
	if lockProto == "" {
		return nil, corruptf("the superblock names no lock protocol")
	}

	superblock := &Superblock{
		BlockSize:       blockSize,
		BlockShift:      blockShift,
		TotalBlocks:     totalBlocks,
		VolumeBytes:     volumeBytes,
		SuperBlock:      sbBlock,
		FSFormat:        fsFormat,
		MultihostFormat: multihostFormat,
		RootFormal:      be64(raw, 0x50),
		RootAddr:        be64(raw, 0x58),
		MasterFormal:    be64(raw, 0x30),
		MasterAddr:      be64(raw, 0x38),
		LockProto:       lockProto,
		LockTable:       fixedString(raw, 0xa0, 64),
	}
	copy(superblock.UUID[:], raw[0x100:0x110])

	if err := superblock.ValidateBlock(superblock.RootAddr, "the root directory inode"); err != nil {
		return nil, err
	}
	if err := superblock.ValidateBlock(superblock.MasterAddr, "the master directory inode"); err != nil {
		return nil, err
	}
	if superblock.RootAddr == superblock.MasterAddr {
		return nil, corruptf("the root and master directories share inode block %d", superblock.RootAddr)
	}
	if superblock.RootAddr == superblock.SuperBlock {
		return nil, corruptf("the superblock names its own block as the root directory inode")
	}
	if superblock.MasterAddr == superblock.SuperBlock {
		return nil, corruptf("the superblock names its own block as the master directory inode")
	}
	return superblock, nil
}

// validateMeta verifies a gfs2_meta_header at the start of raw.
func validateMeta(raw []byte, expectedType, expectedFormat uint32, what string) error {
	if len(raw) < MetaHeaderSize {
		return corruptf("%s is %d bytes, shorter than the %d-byte metadata header",
			what, len(raw), MetaHeaderSize)
	}
	if magic := be32(raw, 0x00); magic != Magic {
		return corruptf("%s has magic 0x%08x, not the GFS2 magic 0x%08x", what, magic, Magic)
	}
	if metaType := be32(raw, 0x04); metaType != expectedType {
		return corruptf("%s names metatype %d, expected %d", what, metaType, expectedType)
	}
	if format := be32(raw, 0x10); format != expectedFormat {
		return corruptf("%s names format %d, expected %d", what, format, expectedFormat)
	}
	return nil
}

func trailingZeros(value uint32) uint32 {
	var shift uint32
	for shift < 32 && value&(1<<shift) == 0 {
		shift++
	}
	return shift
}

// blockBytes reads one whole filesystem block.
func blockBytes(sb *Superblock, src source.ByteSource, block uint64, what string) ([]byte, error) {
	if err := sb.ValidateBlock(block, what); err != nil {
		return nil, err
	}
	offset, ok := sb.BlockOffset(block)
	if !ok {
		return nil, corruptf("%s: block %d overflows the byte address space", what, block)
	}
	size := uint64(sb.BlockSize)
	if offset > src.Len() || size > src.Len()-offset {
		return nil, source.NewUnexpectedEOF(offset)
	}
	raw := make([]byte, int(size))
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return nil, err
	}
	return raw, nil
}
