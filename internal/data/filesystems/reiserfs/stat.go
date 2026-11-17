package reiserfs

// ReiserFS stat data: the inode metadata stored as an item body. ReiserFS has
// no inode table; everything a Unix inode holds lives in a stat data item whose
// key is (parent directory, object, 0).
const (
	// StatDataV1Len is the 3.5 record length.
	StatDataV1Len = 32
	// StatDataV2Len is the 3.6 record length.
	StatDataV2Len = 44
)

// File type bits of sd_mode.
const (
	S_IFMT   uint16 = 0o170_000
	S_IFIFO  uint16 = 0o010_000
	S_IFCHR  uint16 = 0o020_000
	S_IFDIR  uint16 = 0o040_000
	S_IFBLK  uint16 = 0o060_000
	S_IFREG  uint16 = 0o100_000
	S_IFLNK  uint16 = 0o120_000
	S_IFSOCK uint16 = 0o140_000
)

// StatVersion is which stat data layout an item uses.
type StatVersion int

const (
	// StatVersionV1 is the 32-byte 3.5 record.
	StatVersionV1 StatVersion = iota
	// StatVersionV2 is the 44-byte 3.6 record.
	StatVersionV2
)

// FromKeyVersion maps a key version to its stat data layout.
func statVersionFromKeyVersion(version KeyVersion) StatVersion {
	if version == KeyVersionV1 {
		return StatVersionV1
	}
	return StatVersionV2
}

// RecordLen returns the bytes the record needs.
func (v StatVersion) RecordLen() int {
	if v == StatVersionV1 {
		return StatDataV1Len
	}
	return StatDataV2Len
}

// FileType is the kind of object named by the mode word.
type FileType int

const (
	FileTypeDirectory FileType = iota
	FileTypeRegular
	FileTypeSymlink
	FileTypeCharDevice
	FileTypeBlockDevice
	FileTypeFifo
	FileTypeSocket
	FileTypeUnknown
)

// Name returns a lower-case name.
func (f FileType) Name() string {
	switch f {
	case FileTypeDirectory:
		return "directory"
	case FileTypeRegular:
		return "regular file"
	case FileTypeSymlink:
		return "symbolic link"
	case FileTypeCharDevice:
		return "character device"
	case FileTypeBlockDevice:
		return "block device"
	case FileTypeFifo:
		return "fifo"
	case FileTypeSocket:
		return "socket"
	default:
		return "unknown"
	}
}

// StatData is a decoded stat data item.
type StatData struct {
	Version StatVersion
	Mode    uint16
	// Attrs is the 3.6 sd_attrs word; zero on 3.5.
	Attrs uint16
	Nlink uint32
	Size  uint64
	UID   uint32
	GID   uint32
	// Atime, Mtime and Ctime are seconds since the Unix epoch, UTC.
	Atime uint32
	Mtime uint32
	Ctime uint32
	// Blocks is 3.6 sd_blocks; nil on 3.5.
	Blocks *uint32
	// UnionWord is sd_rdev/sd_generation on 3.6 and sd_rdev/sd_blocks on 3.5.
	UnionWord uint32
	// FirstDirectByte is 3.5 sd_first_direct_byte; nil on 3.6.
	FirstDirectByte *uint32
}

// ParseStatData decodes a stat data body.
func ParseStatData(body []byte, version StatVersion) (*StatData, error) {
	need := version.RecordLen()
	if len(body) < need {
		kind := "3.6"
		if version == StatVersionV1 {
			kind = "3.5"
		}
		return nil, corruptf("a %s stat data item is %d bytes; the record needs %d", kind, len(body), need)
	}
	mode := le16(body, 0)
	if version == StatVersionV1 {
		blocks := uint32(le32(body, 24))
		first := uint32(le32(body, 28))
		return &StatData{
			Version:         version,
			Mode:            mode,
			Nlink:           uint32(le16(body, 2)),
			Size:            uint64(le32(body, 8)),
			UID:             uint32(le16(body, 4)),
			GID:             uint32(le16(body, 6)),
			Atime:           le32(body, 12),
			Mtime:           le32(body, 16),
			Ctime:           le32(body, 20),
			UnionWord:       blocks,
			FirstDirectByte: &first,
		}, nil
	}
	blocks := uint32(le32(body, 36))
	return &StatData{
		Version:   version,
		Mode:      mode,
		Attrs:     le16(body, 2),
		Nlink:     le32(body, 4),
		Size:      le64(body, 8),
		UID:       le32(body, 16),
		GID:       le32(body, 20),
		Atime:     le32(body, 24),
		Mtime:     le32(body, 28),
		Ctime:     le32(body, 32),
		Blocks:    &blocks,
		UnionWord: le32(body, 40),
	}, nil
}

// FileType returns the object's kind.
func (s *StatData) FileType() FileType {
	switch s.Mode & S_IFMT {
	case S_IFDIR:
		return FileTypeDirectory
	case S_IFREG:
		return FileTypeRegular
	case S_IFLNK:
		return FileTypeSymlink
	case S_IFCHR:
		return FileTypeCharDevice
	case S_IFBLK:
		return FileTypeBlockDevice
	case S_IFIFO:
		return FileTypeFifo
	case S_IFSOCK:
		return FileTypeSocket
	default:
		return FileTypeUnknown
	}
}

// IsDirectory reports whether the object is a directory.
func (s *StatData) IsDirectory() bool { return s.FileType() == FileTypeDirectory }

// IsRegular reports whether the object is a regular file.
func (s *StatData) IsRegular() bool { return s.FileType() == FileTypeRegular }

// IsSymlink reports whether the object is a symbolic link.
func (s *StatData) IsSymlink() bool { return s.FileType() == FileTypeSymlink }

// IsDevice reports whether the mode names a device node.
func (s *StatData) IsDevice() bool {
	kind := s.FileType()
	return kind == FileTypeCharDevice || kind == FileTypeBlockDevice
}

// DeviceNumber returns a device node's number.
func (s *StatData) DeviceNumber() *uint32 {
	if !s.IsDevice() {
		return nil
	}
	value := s.UnionWord
	return &value
}

// Generation returns a non-device object's 3.6 generation word.
func (s *StatData) Generation() *uint32 {
	if s.Version != StatVersionV2 || s.IsDevice() {
		return nil
	}
	value := s.UnionWord
	return &value
}

// BlocksUsed returns the blocks the object uses.
func (s *StatData) BlocksUsed() *uint32 {
	if s.Version == StatVersionV2 {
		return s.Blocks
	}
	if s.IsDevice() {
		return nil
	}
	value := s.UnionWord
	return &value
}

// IsUnlinked reports a zero link count, the kernel's condition for reclaiming
// an object. It is evidence, not proof of deletion.
func (s *StatData) IsUnlinked() bool { return s.Nlink == 0 }

// FirstDirectByteValue returns the 3.5 first-direct-byte word.
func (s *StatData) FirstDirectByteValue() *uint32 { return s.FirstDirectByte }
