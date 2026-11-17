package qnx6

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// InodeSize is the bytes in one on-disk inode entry.
const InodeSize uint64 = 128

// di_status values.
const (
	StatusDirectory uint8 = 1
	StatusDeleted   uint8 = 2
	StatusNormal    uint8 = 3
)

// InodeKind is what an inode's mode bits say it is.
type InodeKind uint8

const (
	// KindFile is a regular file.
	KindFile InodeKind = iota
	// KindDirectory is a directory.
	KindDirectory
	// KindSymlink is a symbolic link.
	KindSymlink
	// KindFifo is a FIFO.
	KindFifo
	// KindSocket is a socket.
	KindSocket
	// KindBlockDevice is a block device.
	KindBlockDevice
	// KindCharDevice is a character device.
	KindCharDevice
	// KindUnknown is a mode that names no supported file type.
	KindUnknown
)

// KindFromMode maps the POSIX S_IFMT bits to an InodeKind.
func KindFromMode(mode uint16) InodeKind {
	switch mode & 0xf000 {
	case 0x8000:
		return KindFile
	case 0x4000:
		return KindDirectory
	case 0xa000:
		return KindSymlink
	case 0x1000:
		return KindFifo
	case 0xc000:
		return KindSocket
	case 0x6000:
		return KindBlockDevice
	case 0x2000:
		return KindCharDevice
	default:
		return KindUnknown
	}
}

// Label returns the kind's report name.
func (k InodeKind) Label() string {
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

// IsDirectory reports whether the kind is a directory.
func (k InodeKind) IsDirectory() bool { return k == KindDirectory }

// IsSymlink reports whether the kind is a symbolic link.
func (k InodeKind) IsSymlink() bool { return k == KindSymlink }

// IsFile reports whether the kind is a regular file.
func (k InodeKind) IsFile() bool { return k == KindFile }

// HasData reports whether the kind has a block-mapped data stream.
func (k InodeKind) HasData() bool {
	return k == KindFile || k == KindDirectory || k == KindSymlink
}

// Inode is one parsed QNX6 inode.
type Inode struct {
	// Number is the 1-based inode number.
	Number uint64
	Size   uint64
	UID    uint32
	GID    uint32

	// Created is di_ftime in Unix seconds; nil means the stored value is
	// zero ("unset").
	Created  *int64
	Modified *int64
	Accessed *int64
	Changed  *int64

	Mode    uint16
	ExtMode uint16
	Ptrs    [16]uint32
	Levels  uint8
	Status  uint8
	Kind    InodeKind
}

// timestamp maps a stored second to an optional time: zero is "unset", never
// 1970.
func timestamp(seconds uint32) *int64 {
	if seconds == 0 {
		return nil
	}
	value := int64(seconds)
	return &value
}

// ParseInode parses one 128-byte inode record.
func ParseInode(bytes []byte, number uint64, superblock *Superblock) (*Inode, error) {
	if uint64(len(bytes)) < InodeSize {
		return nil, corruptf("inode %d is %d bytes, shorter than the %d-byte record",
			number, len(bytes), InodeSize)
	}
	order := superblock.Order
	size := order.u64(bytes, 0x00)
	if size > superblock.VolumeBytes() {
		return nil, corruptf("inode %d declares %d bytes, more than the %d-byte volume",
			number, size, superblock.VolumeBytes())
	}
	mode := order.u16(bytes, 0x20)
	kind := KindFromMode(mode)
	if kind == KindUnknown {
		return nil, corruptf("inode %d has mode 0x%04x, which names no supported file type", number, mode)
	}
	status := bytes[0x65]
	if status == StatusDeleted {
		return nil, unsupportedf("inode %d is marked deleted; deleted inodes and reclaimed data are not decoded", number)
	}
	if status != StatusDirectory && status != StatusNormal {
		return nil, corruptf("inode %d has status %d, outside the format's 1 (directory), 2 (deleted) and 3 (normal)",
			number, status)
	}
	if (status == StatusDirectory) != kind.IsDirectory() {
		return nil, corruptf("inode %d has status %d but mode 0x%04x names a %s",
			number, status, mode, kind.Label())
	}
	levels := bytes[0x64]
	if levels > MaxPtrLevels {
		return nil, unsupportedf("inode %d has pointer depth %d, more than the %d-level cap",
			number, levels, MaxPtrLevels)
	}
	if !kind.HasData() && (size != 0 || levels != 0) {
		return nil, corruptf("inode %d is a %s but declares %d bytes at depth %d",
			number, kind.Label(), size, levels)
	}

	inode := &Inode{
		Number:   number,
		Size:     size,
		UID:      order.u32(bytes, 0x08),
		GID:      order.u32(bytes, 0x0c),
		Created:  timestamp(order.u32(bytes, 0x10)),
		Modified: timestamp(order.u32(bytes, 0x14)),
		Accessed: timestamp(order.u32(bytes, 0x18)),
		Changed:  timestamp(order.u32(bytes, 0x1c)),
		Mode:     mode,
		ExtMode:  order.u16(bytes, 0x22),
		Levels:   levels,
		Status:   status,
		Kind:     kind,
	}
	for index := 0; index < 16; index++ {
		inode.Ptrs[index] = order.u32(bytes, 0x24+index*4)
	}
	return inode, nil
}

// ReadInode reads one inode by its 1-based number.
func ReadInode(src source.ByteSource, superblock *Superblock, number uint64) (*Inode, error) {
	if number == 0 || number > uint64(superblock.NumInodes) {
		return nil, corruptf("inode number %d is outside the superblock's 1..=%d range",
			number, superblock.NumInodes)
	}
	offset := (number - 1) * InodeSize
	if offset/InodeSize != number-1 {
		return nil, corruptf("inode %d's table offset overflows", number)
	}
	end := offset + InodeSize
	if end < offset {
		return nil, corruptf("inode %d's table offset overflows", number)
	}
	if end > superblock.Inode.Size {
		return nil, corruptf("inode %d ends at byte %d of the inode table, past its %d-byte size",
			number, end, superblock.Inode.Size)
	}

	blockSize := uint64(superblock.BlockSize)
	logical := offset / blockSize
	inside := offset % blockSize

	mapper := NewMapper(superblock, src)
	block, err := mapper.Map(superblock.Inode.Ptr, superblock.Inode.Levels, logical, "the inode table")
	if err != nil {
		return nil, err
	}
	physical, ok := superblock.BlockOffset(block)
	if !ok {
		return nil, corruptf("inode table block %d overflows", block)
	}
	bytes := make([]byte, int(superblock.BlockSize))
	if err := source.ReadExactAt(src, physical, bytes); err != nil {
		return nil, err
	}
	if inside+InodeSize > uint64(len(bytes)) {
		return nil, corruptf("inode %d starts at byte %d of a %d-byte block, past the record",
			number, inside, len(bytes))
	}
	return ParseInode(bytes[inside:inside+InodeSize], number, superblock)
}
