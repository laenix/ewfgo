package nilfs2

// The NILFS2 on-disk inode is 128 bytes. Its first field is the mode, so the
// inode file's index is the inode number. The block-map area at 0x40 holds a
// flags word and seven direct pointers; for user inodes those pointers are
// virtual block numbers translated through the DAT file, and for metadata
// inodes they are physical.

const (
	// InodeSize is the fixed on-disk inode size.
	InodeSize = 128
	// BmapOffset is the block-map flags word.
	BmapOffset = 0x40
	// BmapWords counts the flags word and seven direct pointers.
	BmapWords = 8
	// DirectPointers is the number of direct pointer slots.
	DirectPointers = BmapWords - 1
	// DirectPointerOffset is where the first direct pointer starts.
	DirectPointerOffset = BmapOffset + 8
	// FastSymlinkMax is the longest target a fast symbolic link can store.
	FastSymlinkMax = uint64(DirectPointers) * 8

	// BmapLarge marks a B-tree block map.
	BmapLarge uint64 = 0x0001
	// BmapDirty marks unflushed dirty state (not expected on disk).
	BmapDirty uint64 = 0x0002
	// BmapStale marks stale state.
	BmapStale uint64 = 0x0004

	bmapKnown = BmapLarge | BmapDirty | BmapStale
)

// Kind is what an inode's mode bits say it is.
type Kind uint8

// Inode kinds.
const (
	KindFile Kind = iota
	KindDirectory
	KindSymlink
	KindFifo
	KindSocket
	KindBlockDevice
	KindCharDevice
	KindUnknown
)

// KindFromMode classifies a mode word.
func KindFromMode(mode uint16) Kind {
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

// Label names a kind.
func (k Kind) Label() string {
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
func (k Kind) IsDirectory() bool { return k == KindDirectory }

// IsSymlink reports whether the kind is a symbolic link.
func (k Kind) IsSymlink() bool { return k == KindSymlink }

// IsFile reports whether the kind is a regular file.
func (k Kind) IsFile() bool { return k == KindFile }

// HasData reports whether the kind carries a data stream or directory listing.
func (k Kind) HasData() bool {
	return k == KindFile || k == KindDirectory || k == KindSymlink
}

// Inode is one parsed NILFS2 inode.
type Inode struct {
	// number is the inode file index; the on-disk record does not store it.
	number     uint64
	Mode       uint16
	Links      uint16
	UID        uint32
	GID        uint32
	Size       uint64
	Blocks     uint64
	Modified   *int64
	Changed    *int64
	Accessed   *int64
	Generation uint32
	BmapFlags  uint64
	Bmap       [DirectPointers]uint64
	// Inline is the target bytes of a fast symbolic link; nil otherwise.
	Inline []byte
	Kind   Kind
}

// Number returns the inode number: the inode file index it was read from.
func (i *Inode) Number() uint64 { return i.number }

// IsLargeBmap reports whether the inode uses the B-tree block map.
func (i *Inode) IsLargeBmap() bool { return i.BmapFlags&BmapLarge != 0 }

// InlineText is the fast symbolic link's target as text.
func (i *Inode) InlineText() string { return string(i.Inline) }

func parseInode(bytes []byte, what string, metadata bool, volumeBytes uint64) (*Inode, error) {
	if len(bytes) < InodeSize {
		return nil, corruptf("%s is %d bytes, shorter than the %d-byte inode", what, len(bytes), InodeSize)
	}
	mode := le16(bytes, 0x00)
	kind := KindFromMode(mode)
	links := le16(bytes, 0x02)
	size := le64(bytes, 0x0c)
	bmapFlags := le64(bytes, BmapOffset)
	if unknown := bmapFlags &^ bmapKnown; unknown != 0 {
		return nil, unsupportedf("%s sets unknown block-map flags 0x%016x", what, unknown)
	}
	if metadata {
		if kind != KindUnknown && kind != KindFile {
			return nil, corruptf("%s is a metadata inode with mode 0x%04x (%s)", what, mode, kind.Label())
		}
	} else {
		if kind == KindUnknown {
			return nil, corruptf("%s has mode 0x%04x, which names no supported file type", what, mode)
		}
		if links == 0 {
			return nil, corruptf("%s has a zero link count", what)
		}
		if size > volumeBytes {
			return nil, corruptf("%s declares %d bytes, more than the %d-byte volume", what, size, volumeBytes)
		}
	}
	if kind.HasData() && bmapFlags&BmapLarge != 0 && metadata {
		return nil, unsupportedf("%s uses a B-tree block map; this reader decodes direct block maps only", what)
	}

	var bmap [DirectPointers]uint64
	for index := range bmap {
		bmap[index] = le64(bytes, DirectPointerOffset+index*8)
	}

	var inline []byte
	if kind == KindSymlink && bmapFlags&BmapLarge == 0 && size <= FastSymlinkMax {
		length := int(size)
		inline = make([]byte, length)
		copy(inline, bytes[DirectPointerOffset:DirectPointerOffset+length])
	}

	modified, err := timestamp(le64(bytes, 0x1c))
	if err != nil {
		return nil, err
	}
	changed, err := timestamp(le64(bytes, 0x24))
	if err != nil {
		return nil, err
	}
	accessed, err := timestamp(le64(bytes, 0x2c))
	if err != nil {
		return nil, err
	}

	return &Inode{
		Mode:       mode,
		Links:      links,
		UID:        le32(bytes, 0x04),
		GID:        le32(bytes, 0x08),
		Size:       size,
		Blocks:     le64(bytes, 0x14),
		Modified:   modified,
		Changed:    changed,
		Accessed:   accessed,
		Generation: le32(bytes, 0x34),
		BmapFlags:  bmapFlags,
		Bmap:       bmap,
		Inline:     inline,
		Kind:       kind,
	}, nil
}

// ParseMetadataInode parses one of the four super-root metadata inodes.
func ParseMetadataInode(bytes []byte, what string) (*Inode, error) {
	return parseInode(bytes, what, true, ^uint64(0))
}

// ParseUserInode parses an inode from the inode file.
func ParseUserInode(bytes []byte, what string, volumeBytes uint64) (*Inode, error) {
	return parseInode(bytes, what, false, volumeBytes)
}
