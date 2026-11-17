package erofs

// EROFS inodes: a 32-byte compact form or a 64-byte extended one.
//
//	compact (32 bytes)              extended (64 bytes)
//	  0  i_format    u16              0  i_format     u16
//	  2  xattr_count u16              2  xattr_count  u16
//	  4  i_mode      u16              4  i_mode       u16
//	  6  i_nlink     u16              6  reserved     u16
//	  8  i_size      u32              8  i_size       u64
//	 12  reserved    u32             16  i_u          u32
//	 16  i_u         u32             20  i_ino        u32
//	 20  i_ino       u32             24  i_uid        u32
//	 24  i_uid       u16             28  i_gid        u32
//	 26  i_gid       u16             32  i_mtime      u64
//	 28  reserved    u32             40  i_mtime_nsec u32
//	                                 44  i_nlink      u32
//	                                 48  reserved     16
//
// i_format bit 0 names the form (zero compact, one extended) and bits 1–3 the
// data layout. i_u is a block address for a flat inode and a device number for
// a device node. Only an extended inode has a time field, and it is meaningful
// only when the superblock's mtime feature is set; a zero second is "unset",
// not 1970.

const (
	inodeCompactBytes  uint16 = 32
	inodeExtendedBytes uint16 = 64
	// islotBits is log2 of the 32-byte inode slot.
	islotBits = 5

	formatVersionMask     uint16 = 0x0001
	formatDataLayoutMask  uint16 = 0x000e
	formatDataLayoutShift        = 1
	formatAll             uint16 = 0x000f
	typeMask              uint16 = 0o170000

	xattrHeaderBytes uint32 = 12
	xattrEntryBytes  uint32 = 4
)

type dataLayout uint8

const (
	layoutFlatPlain dataLayout = iota
	layoutCompressedFull
	layoutFlatInline
	layoutCompressedCompact
	layoutChunkBased
)

func (l dataLayout) label() string {
	switch l {
	case layoutFlatPlain:
		return "flat plain"
	case layoutCompressedFull:
		return "compressed full"
	case layoutFlatInline:
		return "flat inline"
	case layoutCompressedCompact:
		return "compressed compact"
	default:
		return "chunk based"
	}
}

func (l dataLayout) isStored() bool {
	return l == layoutFlatPlain || l == layoutFlatInline
}

func (l dataLayout) isCompressed() bool {
	return l == layoutCompressedFull || l == layoutCompressedCompact
}

type inodeKind uint8

const (
	kindFile inodeKind = iota
	kindDirectory
	kindSymlink
	kindCharDevice
	kindBlockDevice
	kindFifo
	kindSocket
)

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
	default:
		return "socket"
	}
}

type inode struct {
	format      uint16
	version     uint8
	layout      dataLayout
	xattrIcount uint16
	xattrBytes  uint32
	mode        uint16
	nlink       uint32
	size        uint64
	unit        uint32 // i_u: a block address or a device number
	ino         uint32
	uid         uint32
	gid         uint32
	mtimeValid  bool
	mtimeSec    uint64
	mtimeNsec   uint32
	kind        inodeKind
}

func (i inode) inodeBytes() uint16 {
	if i.version == 0 {
		return inodeCompactBytes
	}
	return inodeExtendedBytes
}

func (i inode) headerBytes() uint64 {
	return uint64(i.inodeBytes()) + uint64(i.xattrBytes)
}

// rawBlkaddr is the block address a flat inode's data starts at. Zero names a
// hole, since block zero holds the superblock and cannot hold file data.
func (i inode) rawBlkaddr() uint32 { return i.unit }

func parseInode(bytes []byte, hasMtime bool) (inode, error) {
	if len(bytes) < int(inodeCompactBytes) {
		return inode{}, corruptf("an inode needs %d bytes, got %d", inodeCompactBytes, len(bytes))
	}
	format := uint16(bytes[0]) | uint16(bytes[1])<<8
	if format&^formatAll != 0 {
		return inode{}, unsupportedf("i_format %#06x sets bits above the defined %#06x",
			format, formatAll)
	}
	version := uint8(format & formatVersionMask)
	layoutBits := (format & formatDataLayoutMask) >> formatDataLayoutShift
	var layout dataLayout
	switch layoutBits {
	case 0:
		layout = layoutFlatPlain
	case 1:
		layout = layoutCompressedFull
	case 2:
		layout = layoutFlatInline
	case 3:
		layout = layoutCompressedCompact
	case 4:
		layout = layoutChunkBased
	default:
		return inode{}, unsupportedf("data layout %d in i_format %#06x", layoutBits, format)
	}
	inodeBytes := inodeCompactBytes
	if version == 1 {
		inodeBytes = inodeExtendedBytes
	}
	if len(bytes) < int(inodeBytes) {
		return inode{}, corruptf("an extended inode needs %d bytes, got %d", inodeBytes, len(bytes))
	}

	xattrIcount := uint16(bytes[2]) | uint16(bytes[3])<<8
	xattrBytes := uint32(0)
	if xattrIcount != 0 {
		xattrBytes = xattrHeaderBytes + xattrEntryBytes*(uint32(xattrIcount)-1)
	}
	mode := uint16(bytes[4]) | uint16(bytes[5])<<8
	var kind inodeKind
	switch mode & typeMask {
	case 0o100000:
		kind = kindFile
	case 0o040000:
		kind = kindDirectory
	case 0o120000:
		kind = kindSymlink
	case 0o020000:
		kind = kindCharDevice
	case 0o060000:
		kind = kindBlockDevice
	case 0o010000:
		kind = kindFifo
	case 0o140000:
		kind = kindSocket
	default:
		return inode{}, corruptf("inode mode %#o names an unknown file type %#o",
			mode, mode&typeMask)
	}

	word := func(at int) uint32 {
		return uint32(bytes[at]) | uint32(bytes[at+1])<<8 |
			uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
	}
	in := inode{
		format:      format,
		version:     version,
		layout:      layout,
		xattrIcount: xattrIcount,
		xattrBytes:  xattrBytes,
		mode:        mode,
		kind:        kind,
	}
	if version == 0 {
		in.nlink = uint32(uint16(bytes[6]) | uint16(bytes[7])<<8)
		in.size = uint64(word(8))
		in.unit = word(16)
		in.ino = word(20)
		in.uid = uint32(uint16(bytes[24]) | uint16(bytes[25])<<8)
		in.gid = uint32(uint16(bytes[26]) | uint16(bytes[27])<<8)
	} else {
		in.size = uint64(bytes[8]) | uint64(bytes[9])<<8 | uint64(bytes[10])<<16 |
			uint64(bytes[11])<<24 | uint64(bytes[12])<<32 | uint64(bytes[13])<<40 |
			uint64(bytes[14])<<48 | uint64(bytes[15])<<56
		in.unit = word(16)
		in.ino = word(20)
		in.uid = word(24)
		in.gid = word(28)
		seconds := uint64(bytes[32]) | uint64(bytes[33])<<8 | uint64(bytes[34])<<16 |
			uint64(bytes[35])<<24 | uint64(bytes[36])<<32 | uint64(bytes[37])<<40 |
			uint64(bytes[38])<<48 | uint64(bytes[39])<<56
		in.mtimeNsec = word(40)
		in.nlink = word(44)
		if hasMtime && seconds != 0 {
			in.mtimeValid = true
			in.mtimeSec = seconds
		}
	}
	return in, nil
}
