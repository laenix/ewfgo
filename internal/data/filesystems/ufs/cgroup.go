package ufs

import (
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Cylinder-group header offsets.
const (
	// GroupHeaderLen is the bytes of struct cg before its bitmaps.
	GroupHeaderLen = 168
	// CGIUsedOff is the offset of cg_iusedoff.
	CGIUsedOff = 92
	// CGCheckHashOffset is the offset of cg_ckhash, zeroed before hashing.
	CGCheckHashOffset = 132
	// CGNDBlk is the offset of cg_ndblk, the fragments in this group.
	CGNDBlk = 20
	// CGFreeOff is the offset of cg_freeoff, the fragment bitmap.
	CGFreeOff = 96
	// CGNBFree is the offset of cg_cs.cs_nbfree.
	CGNBFree = 28
	// CGNFFree is the offset of cg_cs.cs_nffree.
	CGNFFree = 36
)

// CylinderGroup is one decoded group header.
type CylinderGroup struct {
	Index uint64
	// Magic is cg_magic, which must be CGMagic.
	Magic uint32
	// NDblk is the fragments in the group.
	NDblk uint32
	// NIblk is the inodes in the group.
	NIblk uint32
	// InitedIblk is how many of those inodes the writer initialised.
	InitedIblk uint32
	// Time is cg_time, when the group was last written.
	Time int64

	// CheckHashKnown is true when the volume maintains a group hash.
	CheckHashKnown bool
	// CheckHashValid is the comparison result when CheckHashKnown is true.
	CheckHashValid bool
}

// ReadCylinderGroup reads one group's header.
func ReadCylinderGroup(src source.ByteSource, sb *Superblock, index uint64) (*CylinderGroup, error) {
	if index >= uint64(sb.NCG) {
		return nil, corruptf("cylinder group %d is past the %d declared", index, sb.NCG)
	}
	offset, err := sb.FragmentOffset(sb.CGTOD(index))
	if err != nil {
		return nil, err
	}
	length := int(sb.CGSize)
	raw := make([]byte, length)
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return nil, err
	}
	group := &CylinderGroup{
		Index:      index,
		Magic:      sb.Endian.U32(raw, 4),
		NDblk:      sb.Endian.U32(raw, CGNDBlk),
		NIblk:      sb.Endian.U32(raw, 116),
		InitedIblk: sb.Endian.U32(raw, 120),
		Time:       sb.Endian.I64(raw, 136),
	}
	if group.Magic != CGMagic {
		return nil, corruptf("cylinder group %d at byte %d has magic %#08x, expected %#08x",
			index, offset, group.Magic, CGMagic)
	}
	if !sb.Checks(CK_CYLGRP) {
		return group, nil
	}
	stored := sb.Endian.U32(raw, CGCheckHashOffset)
	clear(raw[CGCheckHashOffset : CGCheckHashOffset+4])
	group.CheckHashKnown = true
	group.CheckHashValid = foundation.CRC32C(raw) == stored
	return group, nil
}

// InodeBitmap is one group's inode allocation bitmap.
type InodeBitmap struct {
	// Group is the cylinder-group index.
	Group uint64
	// FirstInode is slot zero's inode number: group * fs_ipg.
	FirstInode uint32
	// Count is the inodes the bitmap covers, from cg_niblk.
	Count uint32
	raw   []byte
}

// IsUsed reports whether a slot is allocated. A set bit means allocated; bits
// past Count are not read as free.
func (b *InodeBitmap) IsUsed(slot uint32) bool {
	if slot >= b.Count || int(slot/8) >= len(b.raw) {
		return true
	}
	return b.raw[slot/8]&(1<<(slot%8)) != 0
}

// Bytes returns the raw bitmap, low bit first.
func (b *InodeBitmap) Bytes() []byte { return b.raw }

// ReadInodeBitmap reads one group's inode bitmap.
//
// cg_iusedoff must point past the fixed header, the bitmap must fit inside the
// group's header block and cover exactly cg_niblk inodes, and a group whose
// stored check hash does not match its bytes is refused: the hash covers the
// block the bitmap lives in, so neither the offset nor the bytes can be
// trusted.
func ReadInodeBitmap(src source.ByteSource, sb *Superblock, index uint64) (*InodeBitmap, error) {
	group, err := ReadCylinderGroup(src, sb, index)
	if err != nil {
		return nil, err
	}
	if group.CheckHashKnown && !group.CheckHashValid {
		return nil, unsupportedf("cylinder group %d stores a check hash its bytes do not match, so its inode bitmap is not trusted", index)
	}
	if group.NIblk == 0 || group.NIblk > sb.IPG {
		return nil, unsupportedf("cylinder group %d claims %d inodes; the geometry allows 1..=%d", index, group.NIblk, sb.IPG)
	}
	offset, err := sb.FragmentOffset(sb.CGTOD(index))
	if err != nil {
		return nil, err
	}
	cgSize := int(sb.CGSize)
	raw := make([]byte, cgSize)
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return nil, err
	}
	usedOff := int(sb.Endian.U32(raw, CGIUsedOff))
	needed := (int(group.NIblk) + 7) / 8
	if usedOff < GroupHeaderLen || usedOff > cgSize || needed > cgSize-usedOff {
		return nil, unsupportedf("cylinder group %d places its %d-byte inode bitmap at byte %d of a %d-byte header, outside the bitmap area after the %d-byte fixed fields",
			index, needed, usedOff, cgSize, GroupHeaderLen)
	}
	first, ok := mulCheck(index, uint64(sb.IPG))
	if !ok || first > uint64(^uint32(0)) {
		return nil, corruptf("cylinder group %d starts past the 32-bit inode number space", index)
	}
	return &InodeBitmap{
		Group:      index,
		FirstInode: uint32(first),
		Count:      group.NIblk,
		raw:        append([]byte(nil), raw[usedOff:usedOff+needed]...),
	}, nil
}
