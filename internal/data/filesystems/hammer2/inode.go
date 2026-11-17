package hammer2

import (
	"math"
	"unicode/utf8"
)

// InodeBytes is HAMMER2_INODE_BYTES: the size of every inode record.
const InodeBytes = 1024

// InodeVersion is HAMMER2_INODE_VERSION_ONE, the only version a writer emits.
const InodeVersion uint16 = 1

// InodeMaxName is HAMMER2_INODE_MAXNAME.
const InodeMaxName = 256

// EmbeddedBytes is HAMMER2_EMBEDDED_BYTES: the direct-data / blockset union.
const EmbeddedBytes = 512

// UnionOffset is the offset of the direct-data / blockset union.
const UnionOffset = 0x200

// FilenameOffset is the offset of the filename field.
const FilenameOffset = 0x100

// UIDAt and GIDAt are the Unix ids inside the 16-byte uid/gid UUIDs.
const (
	UIDAt = 0x3c
	GIDAt = 0x4c
)

// Inode operation flags.
const (
	OpflagDirectData uint8 = 0x01
	OpflagPFSRoot    uint8 = 0x02
)

// HAMMER2 object types.
const (
	ObjtypeUnknown   uint8 = 0
	ObjtypeDirectory uint8 = 1
	ObjtypeRegfile   uint8 = 2
	ObjtypeFifo      uint8 = 4
	ObjtypeCDEV      uint8 = 5
	ObjtypeBDEV      uint8 = 6
	ObjtypeSoftlink  uint8 = 7
	ObjtypeSocket    uint8 = 9
	ObjtypeWhiteout  uint8 = 10
)

// InodeKind is the classification of an inode's object type.
type InodeKind uint8

// Inode kinds.
const (
	KindDirectory InodeKind = iota
	KindRegular
	KindSymlink
	KindFifo
	KindCharDevice
	KindBlockDevice
	KindSocket
	KindWhiteout
)

// String returns the label the catalog reports.
func (k InodeKind) String() string {
	switch k {
	case KindDirectory:
		return "directory"
	case KindRegular:
		return "regular file"
	case KindSymlink:
		return "symbolic link"
	case KindFifo:
		return "FIFO"
	case KindCharDevice:
		return "character device"
	case KindBlockDevice:
		return "block device"
	case KindSocket:
		return "socket"
	case KindWhiteout:
		return "whiteout"
	default:
		return "unknown"
	}
}

// IsDirectory reports whether the inode is a directory.
func (k InodeKind) IsDirectory() bool { return k == KindDirectory }

// IsSymlink reports whether the inode is a symbolic link.
func (k InodeKind) IsSymlink() bool { return k == KindSymlink }

// IsRegular reports whether the inode is a regular file.
func (k InodeKind) IsRegular() bool { return k == KindRegular }

func kindFor(objectType uint8, what string) (InodeKind, error) {
	switch objectType {
	case ObjtypeDirectory:
		return KindDirectory, nil
	case ObjtypeRegfile:
		return KindRegular, nil
	case ObjtypeSoftlink:
		return KindSymlink, nil
	case ObjtypeFifo:
		return KindFifo, nil
	case ObjtypeCDEV:
		return KindCharDevice, nil
	case ObjtypeBDEV:
		return KindBlockDevice, nil
	case ObjtypeSocket:
		return KindSocket, nil
	case ObjtypeWhiteout:
		return KindWhiteout, nil
	case ObjtypeUnknown:
		return 0, corruptf("%s records object type 0 (unknown)", what)
	default:
		return 0, unsupportedf("%s records unsupported object type %d", what, objectType)
	}
}

// Inode is one parsed HAMMER2 inode.
type Inode struct {
	Version    uint16
	PFSSubtype uint8
	UFlags     uint32
	RMajor     uint32
	RMinor     uint32
	// Times in microseconds since the Unix epoch; nil when the field is zero.
	Ctime *int64
	Mtime *int64
	Atime *int64
	Btime *int64
	UID   uint32
	GID   uint32

	Kind        InodeKind
	OpFlags     uint8
	CapFlags    uint16
	Mode        uint32
	Inum        uint64
	Size        uint64
	NLinks      uint64
	IParent     uint64
	NameKey     uint64
	NameLen     uint16
	NCopies     uint8
	CompAlgo    uint8
	CheckAlgo   uint8
	PFSNMasters uint8
	PFSType     uint8
	PFSInum     uint64
	PFSClid     [16]byte
	PFSFsid     [16]byte

	// Filename is the raw, unterminated name bytes.
	Filename []byte
	// Blockset is set when the union holds a blockset (DIRECTDATA clear).
	Blockset *Blockset
	// DirectData is the embedded 512 bytes when DIRECTDATA is set.
	DirectData []byte
	// MediaOffset is the inode record's physical offset when it was read
	// through a block reference.
	MediaOffset *uint64
}

// ParseInode parses one 1024-byte inode record.
func ParseInode(raw []byte, what string) (*Inode, error) {
	if len(raw) < InodeBytes {
		return nil, corruptf("%s is %d bytes, shorter than the %d-byte inode",
			what, len(raw), InodeBytes)
	}
	version := le16(raw, 0x00)
	if version != InodeVersion {
		return nil, unsupportedf("%s records inode version %d; this reader decodes version %d",
			what, version, InodeVersion)
	}
	nameLen := le16(raw, 0x80)
	if int(nameLen) > InodeMaxName {
		return nil, corruptf("%s records a %d-byte filename, larger than HAMMER2's %d-byte limit",
			what, nameLen, InodeMaxName)
	}
	opFlags := raw[0x51]
	filename := append([]byte(nil), raw[FilenameOffset:FilenameOffset+int(nameLen)]...)
	kind, err := kindFor(raw[0x50], what)
	if err != nil {
		return nil, err
	}
	size := le64(raw, 0x60)

	union := raw[UnionOffset : UnionOffset+EmbeddedBytes]
	var blockset *Blockset
	var directData []byte
	if opFlags&OpflagDirectData != 0 {
		if kind.IsDirectory() {
			return nil, corruptf("%s is a directory that claims embedded data", what)
		}
		if size > EmbeddedBytes {
			return nil, corruptf("%s claims embedded data but records a size of %d bytes, more than the %d-byte union",
				what, size, EmbeddedBytes)
		}
		directData = append([]byte(nil), union...)
	} else {
		blockset, err = ParseBlockset(union[:BlocksetBytes], what+" blockset")
		if err != nil {
			return nil, err
		}
	}

	ctime, err := timestamp(le64(raw, 0x10), what)
	if err != nil {
		return nil, err
	}
	mtime, err := timestamp(le64(raw, 0x18), what)
	if err != nil {
		return nil, err
	}
	atime, err := timestamp(le64(raw, 0x20), what)
	if err != nil {
		return nil, err
	}
	btime, err := timestamp(le64(raw, 0x28), what)
	if err != nil {
		return nil, err
	}

	inode := &Inode{
		Version:     version,
		PFSSubtype:  raw[0x03],
		UFlags:      le32(raw, 0x04),
		RMajor:      le32(raw, 0x08),
		RMinor:      le32(raw, 0x0c),
		Ctime:       ctime,
		Mtime:       mtime,
		Atime:       atime,
		Btime:       btime,
		UID:         le32(raw, UIDAt),
		GID:         le32(raw, GIDAt),
		Kind:        kind,
		OpFlags:     opFlags,
		CapFlags:    le16(raw, 0x52),
		Mode:        le32(raw, 0x54),
		Inum:        le64(raw, 0x58),
		Size:        size,
		NLinks:      le64(raw, 0x68),
		IParent:     le64(raw, 0x70),
		NameKey:     le64(raw, 0x78),
		NameLen:     nameLen,
		NCopies:     raw[0x82],
		CompAlgo:    raw[0x83],
		CheckAlgo:   raw[0x85],
		PFSNMasters: raw[0x86],
		PFSType:     raw[0x87],
		PFSInum:     le64(raw, 0x88),
		Filename:    filename,
		Blockset:    blockset,
		DirectData:  directData,
	}
	copy(inode.PFSClid[:], raw[0x90:0xa0])
	copy(inode.PFSFsid[:], raw[0xa0:0xb0])
	return inode, nil
}

// IsDirectData reports whether the union holds embedded data.
func (i *Inode) IsDirectData() bool { return i.OpFlags&OpflagDirectData != 0 }

// IsPFSRoot reports whether the inode carries HAMMER2_OPFLAG_PFSROOT.
func (i *Inode) IsPFSRoot() bool { return i.OpFlags&OpflagPFSRoot != 0 }

// Name returns the filename as text. HAMMER2 does not enforce an encoding; a
// name that is not valid UTF-8 is refused rather than replaced.
func (i *Inode) Name() (string, error) {
	if !utf8.Valid(i.Filename) {
		return "", unsupportedf("inode %d has a filename that is not valid UTF-8", i.Inum)
	}
	return string(i.Filename), nil
}

// EmbeddedData returns the embedded data truncated to the inode's size.
func (i *Inode) EmbeddedData() []byte {
	if i.DirectData == nil {
		return nil
	}
	length := len(i.DirectData)
	if i.Size < uint64(length) {
		length = int(i.Size)
	}
	return i.DirectData[:length]
}

// timestamp converts a stored microsecond count; zero is "unset".
func timestamp(micros uint64, what string) (*int64, error) {
	if micros == 0 {
		return nil, nil
	}
	if micros > math.MaxInt64 {
		return nil, corruptf("%s timestamp %d microseconds does not fit a signed count", what, micros)
	}
	value := int64(micros)
	return &value, nil
}
