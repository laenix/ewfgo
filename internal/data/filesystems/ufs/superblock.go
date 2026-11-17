package ufs

import (
	"math/bits"
	"strings"
	"unicode"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Magic words. UFS1 and UFS2 use different magics, and a writer that marked a
// superblock unusable leaves FS_BAD_MAGIC in its place.
const (
	// FS_UFS1_MAGIC is the little-endian UFS1 magic.
	FS_UFS1_MAGIC uint32 = 0x0001_1954
	// FS_UFS2_MAGIC is the little-endian UFS2 magic.
	FS_UFS2_MAGIC uint32 = 0x1954_0119
	// FS_BAD_MAGIC marks a superblock its writer abandoned.
	FS_BAD_MAGIC uint32 = 0x1996_0408
)

// The four byte offsets the kernel searches for a superblock.
const (
	// SBLOCK_UFS1 is the standard UFS1 superblock offset.
	SBLOCK_UFS1 uint64 = 8_192
	// SBLOCK_UFS2 is the standard UFS2 superblock offset.
	SBLOCK_UFS2 uint64 = 65_536
	// SBLOCK_FLOPPY is the offset a stripped floppy image uses.
	SBLOCK_FLOPPY uint64 = 0
	// SBLOCK_PIGGY is the alternate superblock newfs also writes.
	SBLOCK_PIGGY uint64 = 262_144
)

// SuperblockOffsets is the order the kernel looks in.
var SuperblockOffsets = [...]uint64{SBLOCK_UFS2, SBLOCK_UFS1, SBLOCK_FLOPPY, SBLOCK_PIGGY}

const (
	// SuperblockLen is sizeof(struct fs).
	SuperblockLen = 1_376
	// MaxSuperblockLen is the largest fs_sbsize this reader hashes.
	MaxSuperblockLen = 65_536
	// MaxBlockSize bounds fs_bsize so a hostile superblock cannot request a
	// gigabyte-sized read. Real UFS caps blocks at 64 KiB; one MiB is the
	// reader's own safety ceiling.
	MaxBlockSize = 1 << 20
)

// CGMagic is the cylinder-group magic.
const CGMagic uint32 = 0x0009_0255

// Inode-format values.
const (
	// FS_42INODEFMT is the pre-4.4BSD inode layout, which this reader refuses
	// by name.
	FS_42INODEFMT int32 = -1
	// FS_44INODEFMT is the modern inode layout.
	FS_44INODEFMT int32 = 2
)

// Superblock flags (fs_flags).
const (
	// FS_UNCLEAN means the filesystem was not unmounted cleanly.
	FS_UNCLEAN int32 = 0x0000_0001
	// FS_DOSOFTDEP means soft dependency ordering was in use.
	FS_DOSOFTDEP int32 = 0x0000_0002
	// FS_NEEDSFSCK means the filesystem needs fsck.
	FS_NEEDSFSCK int32 = 0x0000_0004
	// FS_SUJ means soft updates journaling was in use; the journal is not
	// replayed by this reader.
	FS_SUJ int32 = 0x0000_0008
	// FS_FLAGS_UPDATED means the 64-bit size fields are valid.
	FS_FLAGS_UPDATED int32 = 0x0000_0080
	// FS_METACKHASH means metadata check hashes are maintained.
	FS_METACKHASH int32 = 0x0000_0200
)

// Check-hash kinds (fs_metackhash).
const (
	// CK_SUPERBLOCK means fs_ckhash is maintained.
	CK_SUPERBLOCK uint32 = 0x0000_0001
	// CK_CYLGRP means each cylinder group's hash is maintained.
	CK_CYLGRP uint32 = 0x0000_0002
	// CK_INODE means each UFS2 inode's hash is maintained.
	CK_INODE uint32 = 0x0000_0004
	// CK_SUPPORTED is the set this reader understands.
	CK_SUPPORTED uint32 = 0x0000_0007
)

// Version names the format generation.
type Version uint8

const (
	// UFS1 is the 128-byte-inode, 32-bit-pointer generation.
	UFS1 Version = iota
	// UFS2 is the 256-byte-inode, 64-bit-pointer generation.
	UFS2
)

// ID returns the stable identifier used in reports.
func (v Version) ID() string {
	if v == UFS1 {
		return "ufs1"
	}
	return "ufs2"
}

// Label returns the display name.
func (v Version) Label() string {
	if v == UFS1 {
		return "UFS1"
	}
	return "UFS2"
}

// InodeSize returns the on-disk inode size.
func (v Version) InodeSize() int {
	if v == UFS1 {
		return InodeLenUFS1
	}
	return InodeLenUFS2
}

// PointerSize returns the width of a block pointer.
func (v Version) PointerSize() int {
	if v == UFS1 {
		return 4
	}
	return 8
}

// Magic returns the version's magic word.
func (v Version) Magic() uint32 {
	if v == UFS1 {
		return FS_UFS1_MAGIC
	}
	return FS_UFS2_MAGIC
}

// Superblock is a decoded struct fs. Every field the reader uses is exported so
// a report can state exactly what the volume claims.
type Superblock struct {
	Endian  Endian
	Version Version
	// Offset is the byte offset the superblock was found at.
	Offset uint64

	Sblkno          int32
	Cblkno          int32
	Iblkno          int32
	Dblkno          int32
	OldCGOFFSET     int32
	OldCGMask       int32
	NCG             uint32
	BSize           uint32
	FSize           uint32
	Frag            uint32
	FragShift       uint32
	FSBTODB         int32
	SBSize          uint32
	NIndir          uint32
	InoPB           uint32
	MinFree         int32
	Optim           int32
	IPG             uint32
	FPG             uint32
	CGSize          uint32
	SizeFrags       uint64
	DSizeFrags      uint64
	Time            int64
	MTime           int64
	Flags           int32
	OldFlags        int32
	Clean           int8
	Metackhash      uint32
	CKHash          uint32
	MaxSymlinkLen   int32
	OldInodeFmt     int32
	VolumeName      string
	MountPoint      string
	ID              [2]uint32
	SblockLoc       int64
	SblockActuAlloc int64
	ProviderSize    int64
}

// ReadSuperblock finds and decodes a superblock.
//
// A nil superblock with a nil error means none of the four places holds a UFS
// magic in either byte order. A magic whose geometry does not hang together is
// an error.
func ReadSuperblock(src source.ByteSource) (*Superblock, error) {
	for _, offset := range SuperblockOffsets {
		if offset+SuperblockLen > src.Len() {
			continue
		}
		var magic [4]byte
		if err := source.ReadExactAt(src, offset+1372, magic[:]); err != nil {
			return nil, err
		}
		little := uint32(magic[0]) | uint32(magic[1])<<8 | uint32(magic[2])<<16 | uint32(magic[3])<<24
		big := uint32(magic[0])<<24 | uint32(magic[1])<<16 | uint32(magic[2])<<8 | uint32(magic[3])
		if little == FS_BAD_MAGIC || big == FS_BAD_MAGIC {
			return nil, corruptf("the superblock at byte %d carries FS_BAD_MAGIC, so its writer marked the filesystem unusable", offset)
		}
		var version Version
		var endian Endian
		switch {
		case little == FS_UFS2_MAGIC:
			version, endian = UFS2, LittleEndian
		case little == FS_UFS1_MAGIC:
			version, endian = UFS1, LittleEndian
		case big == FS_UFS2_MAGIC:
			version, endian = UFS2, BigEndian
		case big == FS_UFS1_MAGIC:
			version, endian = UFS1, BigEndian
		default:
			continue
		}
		raw := make([]byte, SuperblockLen)
		if err := source.ReadExactAt(src, offset, raw); err != nil {
			return nil, err
		}
		return ParseSuperblock(raw, version, endian, offset)
	}
	return nil, nil
}

// ParseSuperblock decodes and validates one superblock. The slices in the
// fixture tests call this directly; production code goes through
// ReadSuperblock.
func ParseSuperblock(raw []byte, version Version, endian Endian, offset uint64) (*Superblock, error) {
	if len(raw) < SuperblockLen {
		return nil, corruptf("a %d-byte superblock is shorter than struct fs (%d bytes)", len(raw), SuperblockLen)
	}
	magic := endian.U32(raw, 1372)
	if magic == FS_BAD_MAGIC {
		return nil, corruptf("the superblock carries FS_BAD_MAGIC, so its writer marked the filesystem unusable")
	}
	if magic != version.Magic() {
		return nil, corruptf("superblock magic is %#010x, expected %#010x for %s", magic, version.Magic(), version.Label())
	}
	updated := endian.I32(raw, 1312)&FS_FLAGS_UPDATED != 0
	oldSize := endian.I32(raw, 36)
	oldDSize := endian.I32(raw, 40)
	var sizeFrags uint64
	if updated {
		if value := endian.I64(raw, 1080); value > 0 {
			sizeFrags = uint64(value)
		}
	} else {
		if oldSize < 0 {
			return nil, corruptf("fs_old_size is %d, which cannot be a fragment count", oldSize)
		}
		sizeFrags = uint64(oldSize)
	}
	dsizeFrags := uint64(0)
	if updated {
		if value := endian.I64(raw, 1088); value > 0 {
			dsizeFrags = uint64(value)
		}
	} else if oldDSize > 0 {
		dsizeFrags = uint64(oldDSize)
	}

	sb := &Superblock{
		Endian:          endian,
		Version:         version,
		Offset:          offset,
		Sblkno:          endian.I32(raw, 8),
		Cblkno:          endian.I32(raw, 12),
		Iblkno:          endian.I32(raw, 16),
		Dblkno:          endian.I32(raw, 20),
		OldCGOFFSET:     endian.I32(raw, 24),
		OldCGMask:       endian.I32(raw, 28),
		NCG:             endian.U32(raw, 44),
		BSize:           uint32(maxI32(endian.I32(raw, 48), 0)),
		FSize:           uint32(maxI32(endian.I32(raw, 52), 0)),
		Frag:            uint32(maxI32(endian.I32(raw, 56), 0)),
		FragShift:       uint32(maxI32(endian.I32(raw, 96), 0)),
		FSBTODB:         endian.I32(raw, 100),
		SBSize:          uint32(maxI32(endian.I32(raw, 104), 0)),
		NIndir:          uint32(maxI32(endian.I32(raw, 116), 0)),
		InoPB:           endian.U32(raw, 120),
		MinFree:         endian.I32(raw, 60),
		Optim:           endian.I32(raw, 128),
		IPG:             endian.U32(raw, 184),
		FPG:             uint32(maxI32(endian.I32(raw, 188), 0)),
		CGSize:          uint32(maxI32(endian.I32(raw, 160), 0)),
		SizeFrags:       sizeFrags,
		DSizeFrags:      dsizeFrags,
		Time:            endian.I64(raw, 1072),
		MTime:           endian.I64(raw, 1208),
		Flags:           endian.I32(raw, 1312),
		OldFlags:        int32(int8(raw[211])),
		Clean:           int8(raw[209]),
		Metackhash:      endian.U32(raw, 1308),
		CKHash:          endian.U32(raw, 1304),
		MaxSymlinkLen:   endian.I32(raw, 1320),
		OldInodeFmt:     endian.I32(raw, 1324),
		VolumeName:      fixedString(raw[680:712]),
		MountPoint:      fixedString(raw[212:680]),
		SblockLoc:       endian.I64(raw, 1000),
		SblockActuAlloc: endian.I64(raw, 992),
		ProviderSize:    endian.I64(raw, 872),
	}
	sb.ID = [2]uint32{endian.U32(raw, 144), endian.U32(raw, 148)}
	if err := sb.Validate(); err != nil {
		return nil, err
	}
	return sb, nil
}

func maxI32(value, floor int32) int32 {
	if value < floor {
		return floor
	}
	return value
}

// Validate cross-checks the fields against each other. These are the
// invariants newfs establishes and the kernel relies on: a field that
// disagrees with its neighbours makes every later read point somewhere
// plausible and wrong.
func (s *Superblock) Validate() error {
	bsize := s.BSize
	if bsize < 4096 || bsize&(bsize-1) != 0 {
		return corruptf("fs_bsize is %d, which is not a power of two of at least 4096", bsize)
	}
	if bsize > MaxBlockSize {
		return corruptf("fs_bsize is %d, above this reader's %d-byte safety ceiling", bsize, MaxBlockSize)
	}
	fsize := s.FSize
	if fsize < 512 || fsize&(fsize-1) != 0 || fsize > bsize {
		return corruptf("fs_fsize is %d, which is not a power of two between 512 and %d", fsize, bsize)
	}
	if s.Frag == 0 || s.Frag > 8 || bsize/fsize != s.Frag {
		return corruptf("fs_frag is %d but %d/%d is %d", s.Frag, bsize, fsize, bsize/fsize)
	}
	if s.FragShift != uint32(bits.TrailingZeros32(s.Frag)) {
		return corruptf("fs_fragshift is %d but fs_frag %d is 2^%d", s.FragShift, s.Frag, bits.TrailingZeros32(s.Frag))
	}
	expectedFSBTODB := int32(bits.TrailingZeros32(fsize)) - 9
	if s.FSBTODB != expectedFSBTODB {
		return corruptf("fs_fsbtodb is %d but a %d-byte fragment needs %d", s.FSBTODB, fsize, expectedFSBTODB)
	}
	if s.InoPB != bsize/uint32(s.Version.InodeSize()) {
		return corruptf("fs_inopb is %d but a %d-byte block holds %d %s inodes",
			s.InoPB, bsize, bsize/uint32(s.Version.InodeSize()), s.Version.Label())
	}
	if s.NIndir != bsize/uint32(s.Version.PointerSize()) {
		return corruptf("fs_nindir is %d but a %d-byte block holds %d %s pointers",
			s.NIndir, bsize, bsize/uint32(s.Version.PointerSize()), s.Version.Label())
	}
	if s.NCG == 0 || s.NCG > 1<<20 {
		return corruptf("fs_ncg is %d, which cannot be a cylinder-group count", s.NCG)
	}
	if s.IPG == 0 || s.IPG%s.InoPB != 0 {
		return corruptf("fs_ipg is %d but fs_inopb is %d", s.IPG, s.InoPB)
	}
	totalInodes := uint64(s.NCG) * uint64(s.IPG)
	if totalInodes > uint64(^uint32(0)) {
		return corruptf("%d inodes do not fit in 32-bit inode numbers", totalInodes)
	}
	if s.FPG == 0 {
		return corruptf("fs_fpg is zero")
	}
	if s.Sblkno < 0 || s.Cblkno < 0 || s.Iblkno < 0 || s.Dblkno < 0 {
		return corruptf("group offsets are negative: sblkno %d, cblkno %d, iblkno %d, dblkno %d",
			s.Sblkno, s.Cblkno, s.Iblkno, s.Dblkno)
	}
	if s.OldCGOFFSET < 0 {
		return corruptf("fs_old_cgoffset is %d, which cannot be a fragment offset", s.OldCGOFFSET)
	}
	inodeFrags := (uint64(s.IPG) / uint64(s.InoPB)) * uint64(s.Frag)
	if uint64(s.Iblkno)+inodeFrags > uint64(s.FPG) {
		return corruptf("the inode blocks at frag %d need %d frags, past the %d per group", s.Iblkno, inodeFrags, s.FPG)
	}
	if uint64(s.Cblkno)+uint64(s.CGSize)/uint64(s.FSize) > uint64(s.Iblkno) {
		return corruptf("the %d-byte cylinder-group block at frag %d overlaps the inode blocks at %d",
			s.CGSize, s.Cblkno, s.Iblkno)
	}
	if s.CGSize < 168 || s.CGSize > bsize {
		return corruptf("fs_cgsize is %d, outside the 168-byte header .. %d-byte block", s.CGSize, bsize)
	}
	if s.Dblkno < s.Iblkno {
		return corruptf("fs_dblkno %d is before fs_iblkno %d", s.Dblkno, s.Iblkno)
	}
	if s.SizeFrags == 0 {
		return corruptf("fs_size is zero")
	}
	groupFrags := uint64(s.FPG)
	groups := uint64(s.NCG)
	if s.SizeFrags <= groupFrags*(groups-1) || s.SizeFrags > groupFrags*groups {
		return corruptf("fs_size %d does not fill %d groups of %d frags", s.SizeFrags, s.NCG, groupFrags)
	}
	symlinkLimit := int32(0)
	if s.MaxSymlinkLen > 0 {
		symlinkLimit = s.MaxSymlinkLen
	}
	inlineCapacity := int32(UFS2InlineLen)
	if s.Version == UFS1 {
		inlineCapacity = UFS1InlineLen
	}
	if symlinkLimit > inlineCapacity {
		return corruptf("fs_maxsymlinklen is %d but an inode holds %d", symlinkLimit, inlineCapacity)
	}
	switch s.OldInodeFmt {
	case FS_44INODEFMT:
	case FS_42INODEFMT:
		return unsupportedf("4.2BSD inode format (FS_42INODEFMT): inode fields are laid out differently")
	default:
		return unsupportedf("unknown inode format %d (fs_old_inodefmt)", s.OldInodeFmt)
	}
	if s.Metackhash&^CK_SUPPORTED != 0 {
		return unsupportedf("metadata check-hash kinds %#x; this reader knows %#x", s.Metackhash&^CK_SUPPORTED, CK_SUPPORTED)
	}
	return nil
}

// Kind returns "ufs1" or "ufs2".
func (s *Superblock) Kind() string { return s.Version.ID() }

// Label returns the display name.
func (s *Superblock) Label() string { return s.Version.Label() }

// BlockSize returns fs_bsize.
func (s *Superblock) BlockSize() uint64 { return uint64(s.BSize) }

// FragSize returns fs_fsize.
func (s *Superblock) FragSize() uint64 { return uint64(s.FSize) }

// InodeSize returns the on-disk inode size.
func (s *Superblock) InodeSize() int { return s.Version.InodeSize() }

// InodesPerBlock returns fs_inopb.
func (s *Superblock) InodesPerBlock() uint64 { return uint64(s.InoPB) }

// PointersPerBlock returns fs_nindir.
func (s *Superblock) PointersPerBlock() uint64 { return uint64(s.NIndir) }

// VolumeLen returns the bytes the superblock says the filesystem occupies.
func (s *Superblock) VolumeLen() uint64 {
	return saturatingMul(s.SizeFrags, s.FragSize())
}

// IsClean reports whether the last unmount was clean, as far as the flags say.
func (s *Superblock) IsClean() bool { return s.Clean != 0 && s.Flags&FS_UNCLEAN == 0 }

// NeedsFsck reports whether the filesystem is flagged for repair.
func (s *Superblock) NeedsFsck() bool { return s.Flags&FS_NEEDSFSCK != 0 }

// HasSoftUpdatesJournal reports whether SU+J was in use. The journal is not
// replayed.
func (s *Superblock) HasSoftUpdatesJournal() bool { return s.Flags&FS_SUJ != 0 }

// Checks reports whether a check-hash kind is maintained.
func (s *Superblock) Checks(kind uint32) bool { return s.Metackhash&kind != 0 }

// FlagNames returns the names of the fs_flags bits this reader knows.
func (s *Superblock) FlagNames() []string {
	var names []string
	for _, flag := range []struct {
		bit  int32
		name string
	}{
		{FS_UNCLEAN, "unclean"},
		{FS_DOSOFTDEP, "soft-updates"},
		{FS_NEEDSFSCK, "needs-fsck"},
		{FS_SUJ, "suj"},
		{FS_FLAGS_UPDATED, "flags-updated"},
		{FS_METACKHASH, "metadata-check-hash"},
	} {
		if s.Flags&flag.bit != 0 {
			names = append(names, flag.name)
		}
	}
	return names
}

// CGBase returns the fragment a cylinder group begins at.
func (s *Superblock) CGBase(cg uint64) uint64 { return uint64(s.FPG) * cg }

// CGStart returns the first fragment of a group's header. UFS1 shifts it by
// the per-cylinder offset.
func (s *Superblock) CGStart(cg uint64) uint64 {
	base := s.CGBase(cg)
	if s.Version == UFS2 {
		return base
	}
	mask := uint64(uint32(s.OldCGMask))
	return base + uint64(s.OldCGOFFSET)*(cg&^mask)
}

// CGIMin returns the fragment where a group's inode blocks begin.
func (s *Superblock) CGIMin(cg uint64) uint64 { return s.CGStart(cg) + uint64(s.Iblkno) }

// CGTOD returns the fragment where a group's own header begins.
func (s *Superblock) CGTOD(cg uint64) uint64 { return s.CGStart(cg) + uint64(s.Cblkno) }

// CGSBlock returns the fragment where a group's backup superblock begins.
func (s *Superblock) CGSBlock(cg uint64) uint64 { return s.CGStart(cg) + uint64(s.Sblkno) }

// FragmentOffset converts a fragment number to a byte offset, refusing
// fragment zero and fragments outside the declared volume.
func (s *Superblock) FragmentOffset(fragment uint64) (uint64, error) {
	if fragment == 0 {
		return 0, corruptf("fragment 0 holds the boot area")
	}
	if fragment >= s.SizeFrags {
		return 0, corruptf("fragment %d lies past the %d the superblock declares", fragment, s.SizeFrags)
	}
	offset, ok := mulCheck(fragment, s.FragSize())
	if !ok {
		return 0, corruptf("fragment offset overflows")
	}
	return offset, nil
}

// InodeOffset returns the byte offset where an inode lives.
func (s *Superblock) InodeOffset(number uint32) (uint64, error) {
	if number == 0 {
		return 0, corruptf("inode 0 is the null inode")
	}
	perGroup := uint64(s.IPG)
	group := uint64(number) / perGroup
	index := uint64(number) % perGroup
	if group >= uint64(s.NCG) {
		return 0, corruptf("inode %d belongs to cylinder group %d, past the %d declared", number, group, s.NCG)
	}
	block := index / s.InodesPerBlock()
	slot := index % s.InodesPerBlock()
	fragment := s.CGIMin(group) + block*uint64(s.Frag)
	base, ok := mulCheck(fragment, s.FragSize())
	if !ok {
		return 0, corruptf("inode offset overflows")
	}
	offset, ok := addCheck(base, slot*uint64(s.InodeSize()))
	if !ok {
		return 0, corruptf("inode offset overflows")
	}
	end, ok := addCheck(offset, uint64(s.InodeSize()))
	if !ok || end > s.VolumeLen() {
		return 0, corruptf("inode %d at byte %d lies outside the %d declared", number, offset, s.VolumeLen())
	}
	return offset, nil
}

// CheckHash verifies fs_ckhash when the volume maintains it. maintained is
// false when the superblock stores no hash.
func (s *Superblock) CheckHash(src source.ByteSource) (maintained, valid bool, err error) {
	if !s.Checks(CK_SUPERBLOCK) {
		return false, false, nil
	}
	length := uint64(s.SBSize)
	if length < SuperblockLen || length > MaxSuperblockLen {
		return true, false, corruptf("fs_sbsize is %d, outside %d..=%d", length, SuperblockLen, MaxSuperblockLen)
	}
	if s.Offset > src.Len() || length > src.Len()-s.Offset {
		// A truncated image cannot hold the bytes the writer hashed.
		return true, false, nil
	}
	raw := make([]byte, int(length))
	if err := source.ReadExactAt(src, s.Offset, raw); err != nil {
		return true, false, err
	}
	clear(raw[1304:1308])
	return true, foundation.CRC32C(raw) == s.CKHash, nil
}

// fixedString decodes a fixed-width field up to its first NUL, trailing
// whitespace removed.
func fixedString(raw []byte) string {
	end := len(raw)
	for index, value := range raw {
		if value == 0 {
			end = index
			break
		}
	}
	return strings.TrimRightFunc(lossyUTF8(raw[:end]), unicode.IsSpace)
}

func saturatingMul(left, right uint64) uint64 {
	if left == 0 || right == 0 {
		return 0
	}
	if left > ^uint64(0)/right {
		return ^uint64(0)
	}
	return left * right
}

func mulCheck(left, right uint64) (uint64, bool) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, false
	}
	return left * right, true
}

func addCheck(left, right uint64) (uint64, bool) {
	if left > ^uint64(0)-right {
		return 0, false
	}
	return left + right, true
}
