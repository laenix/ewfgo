package ufs

// Inode sizes and the fixed pointer counts both generations share.
const (
	// InodeLenUFS1 is sizeof(struct ufs1_dinode).
	InodeLenUFS1 = 128
	// InodeLenUFS2 is sizeof(struct ufs2_dinode).
	InodeLenUFS2 = 256
	// UFSNDirect is di_db[12].
	UFSNDirect = 12
	// UFSNIndirect is di_ib[3]: single, double, triple.
	UFSNIndirect = 3
	// UFSNExtAttr is di_extb[2].
	UFSNExtAttr = 2
	// RootInode is the root directory's fixed inode number.
	RootInode uint32 = 2
	// Wino is the whiteout inode: a name removed from a union mount.
	Wino uint32 = 1
	// MaxNameLen is the longest name a struct direct can hold.
	MaxNameLen = 255
	// UFS1InlineLen is the inline symbolic-link capacity of a UFS1 inode.
	UFS1InlineLen = 60
	// UFS2InlineLen is the inline symbolic-link capacity of a UFS2 inode.
	UFS2InlineLen = 120
)

// di_flags bits this reader reports.
const (
	// UFAppend is the user append-only flag.
	UFAppend uint32 = 0x0000_0004
	// UFImmutable is the user immutable flag.
	UFImmutable uint32 = 0x0000_0002
	// SFAppend is the system append-only flag.
	SFAppend uint32 = 0x0004_0000
	// SFImmutable is the system immutable flag.
	SFImmutable uint32 = 0x0002_0000
)

// POSIX type bits of di_mode.
const (
	SIFMT   uint16 = 0o170_000
	SIFIFO  uint16 = 0o010_000
	SIFCHR  uint16 = 0o020_000
	SIFDIR  uint16 = 0o040_000
	SIFBLK  uint16 = 0o060_000
	SIFREG  uint16 = 0o100_000
	SIFLNK  uint16 = 0o120_000
	SIFSOCK uint16 = 0o140_000
)

// UfsTime is a timestamp: seconds since the Unix epoch plus nanoseconds. UFS1
// stores both halves as signed 32-bit values; UFS2 widened the seconds.
type UfsTime struct {
	Seconds int64
	Nanos   uint32
}

// IsZero reports whether the timestamp records nothing.
func (t UfsTime) IsZero() bool { return t.Seconds == 0 && t.Nanos == 0 }

// UnixNanos returns nanoseconds since the Unix epoch.
func (t UfsTime) UnixNanos() int64 {
	if t.Seconds > (1<<63-1)/1_000_000_000 || t.Seconds < (-1<<63)/1_000_000_000 {
		if t.Seconds > 0 {
			return 1<<63 - 1
		}
		return -1 << 63
	}
	return t.Seconds*1_000_000_000 + int64(t.Nanos)
}

// UnixSeconds returns the seconds half.
func (t UfsTime) UnixSeconds() int64 { return t.Seconds }

// InodeType names the kind of object an inode describes.
type InodeType uint8

const (
	InodeRegular InodeType = iota
	InodeDirectory
	InodeSymlink
	InodeFifo
	InodeCharacter
	InodeBlock
	InodeSocket
	InodeUnknown
)

// Name returns a stable display name.
func (t InodeType) Name() string {
	switch t {
	case InodeRegular:
		return "regular file"
	case InodeDirectory:
		return "directory"
	case InodeSymlink:
		return "symbolic link"
	case InodeFifo:
		return "FIFO"
	case InodeCharacter:
		return "character device"
	case InodeBlock:
		return "block device"
	case InodeSocket:
		return "socket"
	default:
		return "unknown type"
	}
}

// Inode is one decoded UFS1 or UFS2 dinode.
type Inode struct {
	Number uint32
	// Mode is di_mode; zero means the inode is cleared.
	Mode   uint16
	Links  uint16
	UID    uint32
	GID    uint32
	Size   uint64
	Blocks uint64
	Flags  uint32
	// Generation is di_gen.
	Generation uint32

	AccessTime       UfsTime
	ModificationTime UfsTime
	ChangeTime       UfsTime
	// CreationTime is UFS2's di_birthtime; nil for UFS1 and for an unset
	// birth time.
	CreationTime *UfsTime

	// DB holds direct fragment pointers; zero is a hole.
	DB [UFSNDirect]int64
	// IB holds single, double and triple indirect fragment pointers.
	IB [UFSNIndirect]int64

	inline []byte

	// CheckHash is UFS2's stored di_ckhash; nil for UFS1.
	CheckHash *uint32
	// FreeLink is UFS2's di_freelink; nil for UFS1.
	FreeLink *uint32
}

// ParseInode decodes one inode from its on-disk bytes.
func ParseInode(number uint32, raw []byte, version Version, endian Endian) (*Inode, error) {
	needed := version.InodeSize()
	if len(raw) < needed {
		return nil, corruptf("inode %d is %d bytes, but a %s inode is %d", number, len(raw), version.Label(), needed)
	}
	if version == UFS1 {
		return parseInodeUFS1(number, raw, endian), nil
	}
	return parseInodeUFS2(number, raw, endian), nil
}

func parseInodeUFS1(number uint32, raw []byte, endian Endian) *Inode {
	inode := &Inode{
		Number:           number,
		Mode:             endian.U16(raw, 0),
		Links:            endian.U16(raw, 2),
		UID:              endian.U32(raw, 112),
		GID:              endian.U32(raw, 116),
		Size:             endian.U64(raw, 8),
		Blocks:           uint64(maxI32(endian.I32(raw, 104), 0)),
		Flags:            endian.U32(raw, 100),
		Generation:       uint32(endian.I32(raw, 108)),
		AccessTime:       makeUfsTime(int64(endian.I32(raw, 16)), endian.I32(raw, 20)),
		ModificationTime: makeUfsTime(int64(endian.I32(raw, 24)), endian.I32(raw, 28)),
		ChangeTime:       makeUfsTime(int64(endian.I32(raw, 32)), endian.I32(raw, 36)),
		inline:           append([]byte(nil), raw[40:100]...),
	}
	for index := 0; index < UFSNDirect; index++ {
		inode.DB[index] = int64(endian.I32(raw, 40+index*4))
	}
	for index := 0; index < UFSNIndirect; index++ {
		inode.IB[index] = int64(endian.I32(raw, 88+index*4))
	}
	return inode
}

func parseInodeUFS2(number uint32, raw []byte, endian Endian) *Inode {
	birthSeconds := endian.I64(raw, 56)
	birthNanos := endian.I32(raw, 76)
	var creation *UfsTime
	if birthSeconds != 0 || birthNanos != 0 {
		value := makeUfsTime(birthSeconds, birthNanos)
		creation = &value
	}
	checkHash := endian.U32(raw, 244)
	freeLink := endian.U32(raw, 240)
	inode := &Inode{
		Number:           number,
		Mode:             endian.U16(raw, 0),
		Links:            endian.U16(raw, 2),
		UID:              endian.U32(raw, 4),
		GID:              endian.U32(raw, 8),
		Size:             endian.U64(raw, 16),
		Blocks:           endian.U64(raw, 24),
		Flags:            endian.U32(raw, 88),
		Generation:       endian.U32(raw, 80),
		AccessTime:       makeUfsTime(endian.I64(raw, 32), endian.I32(raw, 68)),
		ModificationTime: makeUfsTime(endian.I64(raw, 40), endian.I32(raw, 64)),
		ChangeTime:       makeUfsTime(endian.I64(raw, 48), endian.I32(raw, 72)),
		CreationTime:     creation,
		inline:           append([]byte(nil), raw[112:232]...),
		CheckHash:        &checkHash,
		FreeLink:         &freeLink,
	}
	for index := 0; index < UFSNDirect; index++ {
		inode.DB[index] = endian.I64(raw, 112+index*8)
	}
	for index := 0; index < UFSNIndirect; index++ {
		inode.IB[index] = endian.I64(raw, 208+index*8)
	}
	return inode
}

// makeUfsTime clamps the nanosecond half to a value a clock can produce; a
// corrupt high half would otherwise make the time unprintable.
func makeUfsTime(seconds int64, nanos int32) UfsTime {
	value := uint32(0)
	if nanos >= 0 && nanos < 1_000_000_000 {
		value = uint32(nanos)
	}
	return UfsTime{Seconds: seconds, Nanos: value}
}

// FileType maps di_mode onto the object kind.
func (i *Inode) FileType() InodeType {
	switch i.Mode & SIFMT {
	case SIFREG:
		return InodeRegular
	case SIFDIR:
		return InodeDirectory
	case SIFLNK:
		return InodeSymlink
	case SIFIFO:
		return InodeFifo
	case SIFCHR:
		return InodeCharacter
	case SIFBLK:
		return InodeBlock
	case SIFSOCK:
		return InodeSocket
	default:
		return InodeUnknown
	}
}

// IsCleared reports whether the writer freed the inode and left no type.
func (i *Inode) IsCleared() bool { return i.Mode == 0 }

// IsRegular reports whether the inode names a regular file.
func (i *Inode) IsRegular() bool { return i.Mode&SIFMT == SIFREG }

// IsDirectory reports whether the inode names a directory.
func (i *Inode) IsDirectory() bool { return i.Mode&SIFMT == SIFDIR }

// IsSymlink reports whether the inode names a symbolic link.
func (i *Inode) IsSymlink() bool { return i.Mode&SIFMT == SIFLNK }

// InlineLink returns the bytes that hold a short symbolic link's target.
func (i *Inode) InlineLink() []byte { return i.inline }

// IsFastSymlink reports whether the target lives inside the inode.
//
// The format decides by size alone: fs_maxsymlinklen is the boundary the
// writer used, so a target shorter than it was stored in the block-pointer
// area and a longer one was stored in blocks. A volume with
// fs_maxsymlinklen <= 0 has no inline targets at all.
func (i *Inode) IsFastSymlink(maxSymlinkLen int32) bool {
	return i.IsSymlink() &&
		maxSymlinkLen > 0 &&
		i.Size < uint64(maxSymlinkLen) &&
		i.Size <= uint64(len(i.inline))
}

// AllocatedBytes returns the bytes held, in 512-byte units as the format
// stores them.
func (i *Inode) AllocatedBytes() uint64 { return saturatingMul(i.Blocks, 512) }

// IsImmutable reports whether the inode is marked immutable.
func (i *Inode) IsImmutable() bool { return i.Flags&(UFImmutable|SFImmutable) != 0 }

// IsAppendOnly reports whether the inode is marked append-only.
func (i *Inode) IsAppendOnly() bool { return i.Flags&(UFAppend|SFAppend) != 0 }
