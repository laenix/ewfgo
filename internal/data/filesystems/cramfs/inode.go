package cramfs

// Inodes: twelve bytes of bit fields, and the type they name.
//
//	word 0   mode:16  uid:16
//	word 1   size:24  gid:8
//	word 2   namelen:6  offset:26
//
// "offset" is divided by four; its meaning depends on the type. For a
// directory it is where the listing starts, for a regular file and a symbolic
// link it is the block-pointer table, and for a device node "size" is the
// device number. "namelen" is the name's padded length divided by four. The
// format records no timestamps or inode numbers at all.

const (
	// inodeBytes is the on-disk size of one inode, in the superblock and in a
	// directory listing.
	inodeBytes = 12
	// maxNameBytes is the longest name the six-bit word count can describe.
	maxNameBytes = 63 * 4
	// typeMask is mode & S_IFMT as the format stores it.
	typeMask = 0o170000
)

type inodeKind uint8

const (
	inodeFile inodeKind = iota
	inodeDirectory
	inodeSymlink
	inodeCharDevice
	inodeBlockDevice
	inodeFifo
	inodeSocket
)

func (k inodeKind) label() string {
	switch k {
	case inodeFile:
		return "regular file"
	case inodeDirectory:
		return "directory"
	case inodeSymlink:
		return "symbolic link"
	case inodeCharDevice:
		return "character device"
	case inodeBlockDevice:
		return "block device"
	case inodeFifo:
		return "fifo"
	default:
		return "socket"
	}
}

// inode is one inode as recorded.
type inode struct {
	mode        uint16 // permission and type bits together, exactly as stored
	uid         uint16
	size        uint32 // file length, device number, or directory listing length
	gid         uint8
	nameWords   uint8  // padded name length divided by four
	offsetUnits uint32 // data offset divided by four
	kind        inodeKind
}

func parseInode(bytes []byte) (inode, error) {
	if len(bytes) < inodeBytes {
		return inode{}, corruptf("an inode needs %d bytes, got %d", inodeBytes, len(bytes))
	}
	word0 := uint32(bytes[0]) | uint32(bytes[1])<<8 | uint32(bytes[2])<<16 | uint32(bytes[3])<<24
	word1 := uint32(bytes[4]) | uint32(bytes[5])<<8 | uint32(bytes[6])<<16 | uint32(bytes[7])<<24
	word2 := uint32(bytes[8]) | uint32(bytes[9])<<8 | uint32(bytes[10])<<16 | uint32(bytes[11])<<24

	in := inode{
		mode:        uint16(word0 & 0xFFFF),
		uid:         uint16(word0 >> 16),
		size:        word1 & 0x00FF_FFFF,
		gid:         uint8(word1 >> 24),
		nameWords:   uint8(word2 & 0x3F),
		offsetUnits: word2 >> 6,
	}
	switch in.mode & typeMask {
	case 0o100000:
		in.kind = inodeFile
	case 0o040000:
		in.kind = inodeDirectory
	case 0o120000:
		in.kind = inodeSymlink
	case 0o020000:
		in.kind = inodeCharDevice
	case 0o060000:
		in.kind = inodeBlockDevice
	case 0o010000:
		in.kind = inodeFifo
	case 0o140000:
		in.kind = inodeSocket
	default:
		return inode{}, corruptf("inode mode %#o names an unknown file type %#o",
			in.mode, in.mode&typeMask)
	}
	return in, nil
}

// isPadding reports the all-zero word pattern a writer may pad a listing with.
func isPadding(bytes []byte) bool {
	if len(bytes) < inodeBytes {
		return false
	}
	for _, b := range bytes[:inodeBytes] {
		if b != 0 {
			return false
		}
	}
	return true
}

// dataOffset is the absolute image offset of this inode's data.
func (i inode) dataOffset() uint64 { return uint64(i.offsetUnits) << 2 }
