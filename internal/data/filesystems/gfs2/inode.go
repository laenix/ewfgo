package gfs2

import (
	"math"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Dinode flag bits (di_flags).
const (
	// FlagJData marks journaled data. Directories require it when unstuffed.
	FlagJData uint32 = 0x0000_0001
	// FlagExhash marks a hash-indexed directory.
	FlagExhash uint32 = 0x0000_0002
	// FlagEAIndirect marks indirect extended attributes.
	FlagEAIndirect uint32 = 0x0000_0008
	// FlagDirectIO is a direct-I/O hint; it changes no on-disk layout.
	FlagDirectIO uint32 = 0x0000_0010
	// FlagImmutable, FlagAppendOnly, FlagNoAtime, FlagSync, FlagSystem,
	// FlagTruncInProg, FlagInheritJData and FlagInheritDirectIO are recorded
	// but do not change the layout this reader decodes.
	FlagImmutable       uint32 = 0x0000_0020
	FlagAppendOnly      uint32 = 0x0000_0040
	FlagNoAtime         uint32 = 0x0000_0080
	FlagSync            uint32 = 0x0000_0100
	FlagSystem          uint32 = 0x0000_0200
	FlagTruncInProg     uint32 = 0x0000_0400
	FlagInheritJData    uint32 = 0x0000_0800
	FlagInheritDirectIO uint32 = 0x0000_1000
)

// Mode type bits (S_IFMT).
const (
	modeFifo      uint32 = 0x1000
	modeChar      uint32 = 0x2000
	modeDirectory uint32 = 0x4000
	modeBlock     uint32 = 0x6000
	modeFile      uint32 = 0x8000
	modeSymlink   uint32 = 0xA000
	modeSocket    uint32 = 0xC000
)

// MaxHeight is the defensive cap on a pointer-tree's height.
const MaxHeight uint16 = 10

// InodeKind is what an inode's mode bits say it is.
type InodeKind uint8

// Inode kinds.
const (
	KindUnknown InodeKind = iota
	KindFile
	KindDirectory
	KindSymlink
	KindFifo
	KindSocket
	KindBlockDevice
	KindCharDevice
)

// InodeKindForMode classifies the S_IFMT bits of a mode.
func InodeKindForMode(mode uint32) InodeKind {
	switch mode & 0xF000 {
	case modeFile:
		return KindFile
	case modeDirectory:
		return KindDirectory
	case modeSymlink:
		return KindSymlink
	case modeFifo:
		return KindFifo
	case modeSocket:
		return KindSocket
	case modeBlock:
		return KindBlockDevice
	case modeChar:
		return KindCharDevice
	default:
		return KindUnknown
	}
}

// String returns the label the catalog reports.
func (k InodeKind) String() string {
	switch k {
	case KindFile:
		return "file"
	case KindDirectory:
		return "directory"
	case KindSymlink:
		return "symlink"
	case KindFifo:
		return "fifo"
	case KindSocket:
		return "socket"
	case KindBlockDevice:
		return "block device"
	case KindCharDevice:
		return "character device"
	default:
		return "unknown"
	}
}

// IsDirectory reports whether the inode is a directory.
func (k InodeKind) IsDirectory() bool { return k == KindDirectory }

// IsSymlink reports whether the inode is a symbolic link.
func (k InodeKind) IsSymlink() bool { return k == KindSymlink }

// IsFile reports whether the inode is a regular file.
func (k InodeKind) IsFile() bool { return k == KindFile }

// HasData reports whether the kind carries a data stream or a directory
// listing.
func (k InodeKind) HasData() bool {
	return k == KindFile || k == KindDirectory || k == KindSymlink
}

// Dinode is one parsed GFS2 inode. Its block is its inode number.
type Dinode struct {
	// Block is the block the dinode was read from, which is its inode number.
	Block uint64
	// Formal is di_num.no_formal_ino.
	Formal uint64
	// Mode is di_mode: permission and type bits as recorded.
	Mode uint32
	UID  uint32
	GID  uint32
	// Links is di_nlink.
	Links uint32
	// Size is the logical length in bytes; for a directory it is the dirent
	// byte count.
	Size uint64
	// Blocks is di_blocks, recorded but not used to validate the map.
	Blocks uint64
	// Flags is di_flags.
	Flags uint32
	// Height is di_height: zero means stuffed, one a dinode pointer array,
	// higher values add indirect IN blocks.
	Height uint16
	// Depth is di_depth, the hash depth of an EXHASH directory.
	Depth uint16
	// Entries is di_entries.
	Entries uint32
	// EAttr is di_eattr, recorded but not followed.
	EAttr uint64
	// Accessed, Modified and Changed are Unix seconds, nil when the stored
	// pair is zero.
	Accessed *int64
	Modified *int64
	Changed  *int64
	// Kind is the classification of Mode.
	Kind InodeKind
	// Stuffed holds the bytes stored in the dinode when Height is zero and
	// the kind has data.
	Stuffed []byte
}

// IsDirectory reports whether the inode is a directory.
func (d *Dinode) IsDirectory() bool { return d.Kind.IsDirectory() }

// IsFile reports whether the inode is a regular file.
func (d *Dinode) IsFile() bool { return d.Kind.IsFile() }

// IsSymlink reports whether the inode is a symbolic link.
func (d *Dinode) IsSymlink() bool { return d.Kind.IsSymlink() }

// IsExhash reports whether the inode carries GFS2_DIF_EXHASH.
func (d *Dinode) IsExhash() bool { return d.Flags&FlagExhash != 0 }

// IsJData reports whether the inode carries GFS2_DIF_JDATA.
func (d *Dinode) IsJData() bool { return d.Flags&FlagJData != 0 }

// StuffedText returns the stuffed bytes as text.
func (d *Dinode) StuffedText() string {
	if d.Stuffed == nil {
		return ""
	}
	return string(d.Stuffed)
}

// ParseDinode parses one block of dinode bytes.
func ParseDinode(raw []byte, block uint64, superblock *Superblock) (*Dinode, error) {
	blockSize := uint64(superblock.BlockSize)
	if uint64(len(raw)) < blockSize {
		return nil, corruptf("dinode block %d is %d bytes, shorter than the %d-byte block",
			block, len(raw), blockSize)
	}
	what := "dinode block " + u64(block)
	if err := validateMeta(raw, MetaDI, FormatDI, what); err != nil {
		return nil, err
	}

	formal := be64(raw, 0x18)
	addr := be64(raw, 0x20)
	if addr != block {
		return nil, corruptf("dinode read from block %d names itself as block %d", block, addr)
	}
	mode := be32(raw, 0x28)
	kind := InodeKindForMode(mode)
	if kind == KindUnknown {
		return nil, corruptf("dinode block %d has mode 0x%08x, which names no supported file type", block, mode)
	}
	links := be32(raw, 0x34)
	if links == 0 {
		return nil, corruptf("dinode block %d has a zero link count", block)
	}
	size := be64(raw, 0x38)
	if size > superblock.VolumeBytes {
		return nil, corruptf("dinode block %d declares %d bytes, more than the %d-byte volume",
			block, size, superblock.VolumeBytes)
	}
	flags := be32(raw, 0x80)
	height := be16(raw, 0x8a)
	depth := be16(raw, 0x92)
	entries := be32(raw, 0x94)
	if height > MaxHeight {
		return nil, unsupportedf("dinode block %d has pointer-tree height %d, more than the %d-level cap",
			block, height, MaxHeight)
	}
	jdata := flags&FlagJData != 0
	exhash := flags&FlagExhash != 0

	if kind.IsDirectory() && height > 0 && !jdata {
		return nil, unsupportedf("directory inode %d is not journaled data (GFS2_DIF_JDATA is clear); its block layout is not decoded", block)
	}
	if exhash && !kind.IsDirectory() {
		return nil, corruptf("dinode block %d carries GFS2_DIF_EXHASH but is a %s, not a directory", block, kind)
	}
	if !kind.HasData() && (height != 0 || size != 0) {
		return nil, corruptf("dinode block %d is a %s but declares %d bytes and height %d",
			block, kind, size, height)
	}
	if kind.IsFile() && jdata {
		return nil, unsupportedf("file inode %d uses journaled data (GFS2_DIF_JDATA); its per-block headers are not decoded", block)
	}
	if kind.IsSymlink() && jdata {
		return nil, unsupportedf("symbolic-link inode %d uses journaled data (GFS2_DIF_JDATA); its per-block headers are not decoded", block)
	}

	var stuffed []byte
	if height == 0 && kind.HasData() {
		capacity := superblock.StuffedCapacity()
		if size > capacity {
			return nil, corruptf("dinode block %d declares %d stuffed bytes, more than the %d that fit",
				block, size, capacity)
		}
		end := DinodeSize + int(size)
		stuffed = append([]byte(nil), raw[DinodeSize:end]...)
	}

	accessed, err := timestamp(be64(raw, 0x48), be32(raw, 0xb0))
	if err != nil {
		return nil, err
	}
	modified, err := timestamp(be64(raw, 0x50), be32(raw, 0xb4))
	if err != nil {
		return nil, err
	}
	changed, err := timestamp(be64(raw, 0x58), be32(raw, 0xb8))
	if err != nil {
		return nil, err
	}

	return &Dinode{
		Block:    block,
		Formal:   formal,
		Mode:     mode,
		UID:      be32(raw, 0x2c),
		GID:      be32(raw, 0x30),
		Links:    links,
		Size:     size,
		Blocks:   be64(raw, 0x40),
		Flags:    flags,
		Height:   height,
		Depth:    depth,
		Entries:  entries,
		EAttr:    be64(raw, 0xa8),
		Accessed: accessed,
		Modified: modified,
		Changed:  changed,
		Kind:     kind,
		Stuffed:  stuffed,
	}, nil
}

// ReadInode reads and parses one dinode block.
func ReadInode(src source.ByteSource, superblock *Superblock, block uint64) (*Dinode, error) {
	raw, err := blockBytes(superblock, src, block, "a dinode")
	if err != nil {
		return nil, err
	}
	return ParseDinode(raw, block, superblock)
}

// timestamp converts a stored second/nanosecond pair to Unix seconds. A zero
// pair is GFS2's "unset", never 1970.
func timestamp(seconds uint64, nanoseconds uint32) (*int64, error) {
	if nanoseconds >= 1_000_000_000 {
		return nil, corruptf("a timestamp has %d nanoseconds, outside 0..1,000,000,000", nanoseconds)
	}
	if seconds == 0 && nanoseconds == 0 {
		return nil, nil
	}
	if seconds > math.MaxInt64 {
		return nil, corruptf("timestamp %d does not fit a signed second count", seconds)
	}
	value := int64(seconds)
	return &value, nil
}

func u64(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
