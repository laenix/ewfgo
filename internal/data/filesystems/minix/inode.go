package minix

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Unix file-type bits in i_mode.
const (
	sIFMT   = 0xF000
	sIFIFO  = 0x1000
	sIFCHR  = 0x2000
	sIFDIR  = 0x4000
	sIFBLK  = 0x6000
	sIFREG  = 0x8000
	sIFLNK  = 0xA000
	sIFSOCK = 0xC000
)

// inodeKind is what an inode names.
type inodeKind uint8

const (
	kindFile inodeKind = iota
	kindDirectory
	kindSymlink
	kindBlockDevice
	kindCharDevice
	kindFifo
	kindSocket
	kindUnknown
)

func (k inodeKind) label() string {
	switch k {
	case kindFile:
		return "file"
	case kindDirectory:
		return "directory"
	case kindSymlink:
		return "symbolic link"
	case kindBlockDevice:
		return "block device"
	case kindCharDevice:
		return "character device"
	case kindFifo:
		return "fifo"
	case kindSocket:
		return "socket"
	default:
		return "unknown"
	}
}

func kindFromMode(mode uint16) inodeKind {
	switch mode & sIFMT {
	case sIFREG:
		return kindFile
	case sIFDIR:
		return kindDirectory
	case sIFLNK:
		return kindSymlink
	case sIFBLK:
		return kindBlockDevice
	case sIFCHR:
		return kindCharDevice
	case sIFIFO:
		return kindFifo
	case sIFSOCK:
		return kindSocket
	default:
		return kindUnknown
	}
}

// inode is one parsed inode.
type inode struct {
	number uint32
	mode   uint16
	kind   inodeKind
	uid    uint32
	gid    uint32
	size   uint64
	links  uint32
	// Zero means the writer recorded no time.
	atime uint32
	mtime uint32
	ctime uint32
	zones []uint32
}

func parseInode(bytes []byte, number uint32, v version) (*inode, error) {
	switch v {
	case versionV1:
		return parseInodeV1(bytes, number)
	default:
		return parseInodeV2(bytes, number)
	}
}

func parseInodeV1(bytes []byte, number uint32) (*inode, error) {
	if len(bytes) < inodeV1Bytes {
		return nil, corruptf("inode %d holds %d bytes, shorter than a V1 inode", number, len(bytes))
	}
	mode := binary.LittleEndian.Uint16(bytes[0:])
	zones := make([]uint32, 9)
	for index := range zones {
		zones[index] = uint32(binary.LittleEndian.Uint16(bytes[14+index*2:]))
	}
	return &inode{
		number: number,
		mode:   mode,
		kind:   kindFromMode(mode),
		uid:    uint32(binary.LittleEndian.Uint16(bytes[2:])),
		gid:    uint32(bytes[12]),
		size:   uint64(binary.LittleEndian.Uint32(bytes[4:])),
		links:  uint32(bytes[13]),
		mtime:  binary.LittleEndian.Uint32(bytes[8:]),
		zones:  zones,
	}, nil
}

func parseInodeV2(bytes []byte, number uint32) (*inode, error) {
	if len(bytes) < inodeV2Bytes {
		return nil, corruptf("inode %d holds %d bytes, shorter than a V2/V3 inode", number, len(bytes))
	}
	mode := binary.LittleEndian.Uint16(bytes[0:])
	zones := make([]uint32, 10)
	for index := range zones {
		zones[index] = binary.LittleEndian.Uint32(bytes[24+index*4:])
	}
	return &inode{
		number: number,
		mode:   mode,
		kind:   kindFromMode(mode),
		links:  uint32(binary.LittleEndian.Uint16(bytes[2:])),
		uid:    uint32(binary.LittleEndian.Uint16(bytes[4:])),
		gid:    uint32(binary.LittleEndian.Uint16(bytes[6:])),
		size:   uint64(binary.LittleEndian.Uint32(bytes[8:])),
		atime:  binary.LittleEndian.Uint32(bytes[12:]),
		mtime:  binary.LittleEndian.Uint32(bytes[16:]),
		ctime:  binary.LittleEndian.Uint32(bytes[20:]),
		zones:  zones,
	}, nil
}

// readInode reads and parses inode `number`.
func readInode(src source.ByteSource, sb *superblock, number uint32) (*inode, error) {
	offset, ok := sb.inodeOffset(number)
	if !ok {
		return nil, corruptf("inode %d is outside the %d the superblock declares", number, sb.ninodes)
	}
	bytes := make([]byte, sb.inodeSize)
	if err := source.ReadExactAt(src, offset, bytes); err != nil {
		return nil, err
	}
	return parseInode(bytes, number, sb.version)
}
