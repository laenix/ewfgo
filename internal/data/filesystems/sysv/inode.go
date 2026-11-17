package sysv

import "github.com/laenix/ewfgo/internal/data/source"

const (
	// inodeBytes is the on-disk inode record size.
	inodeBytes = 64
	// inodePointers is the number of three-byte data pointers in an inode.
	inodePointers = 13
	// directPointers are the direct data pointers; the rest name the three
	// indirect levels.
	directPointers = 10
)

// inodeKind is the file type in an inode's mode.
type inodeKind uint8

const (
	kindFile inodeKind = iota
	kindDirectory
	kindSymlink
	kindCharDevice
	kindBlockDevice
	kindFifo
	kindSocket
	kindUnknown
)

func kindFromMode(mode uint16) inodeKind {
	switch mode & 0o170000 {
	case 0o100000:
		return kindFile
	case 0o040000:
		return kindDirectory
	case 0o120000:
		return kindSymlink
	case 0o020000:
		return kindCharDevice
	case 0o060000:
		return kindBlockDevice
	case 0o010000:
		return kindFifo
	case 0o140000:
		return kindSocket
	default:
		return kindUnknown
	}
}

func (k inodeKind) label() string {
	switch k {
	case kindFile:
		return "regular file"
	case kindDirectory:
		return "directory"
	case kindSymlink:
		return "symbolic link"
	case kindCharDevice:
		return "character device"
	case kindBlockDevice:
		return "block device"
	case kindFifo:
		return "fifo"
	case kindSocket:
		return "socket"
	default:
		return "unknown type"
	}
}

func (k inodeKind) hasData() bool { return k == kindFile || k == kindSymlink }

// inode is one parsed inode.
type inode struct {
	number uint32
	mode   uint16
	kind   inodeKind
	links  uint16
	uid    uint16
	gid    uint16
	size   uint32
	// pointers holds the thirteen three-byte data pointers, decoded.
	pointers   []uint32
	generation uint8
	// Raw Unix seconds; zero is no time.
	atime uint32
	mtime uint32
	ctime uint32
}

func parseInode(bytes []byte, number uint32, order byteOrder) (*inode, error) {
	if len(bytes) < inodeBytes {
		return nil, corruptf("inode %d is %d bytes, shorter than the %d-byte record",
			number, len(bytes), inodeBytes)
	}
	pointers := make([]uint32, inodePointers)
	for index := range pointers {
		pointers[index] = order.ptr24(bytes, 12+index*3)
	}
	mode := order.u16(bytes, 0)
	return &inode{
		number:     number,
		mode:       mode,
		kind:       kindFromMode(mode),
		links:      order.u16(bytes, 2),
		uid:        order.u16(bytes, 4),
		gid:        order.u16(bytes, 6),
		size:       order.u32(bytes, 8),
		pointers:   pointers,
		generation: bytes[51],
		atime:      order.u32(bytes, 52),
		mtime:      order.u32(bytes, 56),
		ctime:      order.u32(bytes, 60),
	}, nil
}

func readInode(src source.ByteSource, sb *superblock, number uint32) (*inode, error) {
	offset, ok := sb.inodeOffset(number)
	if !ok {
		return nil, corruptf("inode %d is outside the %d the superblock declares", number, sb.inodeCount())
	}
	bytes := make([]byte, inodeBytes)
	if err := source.ReadExactAt(src, offset, bytes); err != nil {
		return nil, err
	}
	return parseInode(bytes, number, sb.byteOrder)
}
