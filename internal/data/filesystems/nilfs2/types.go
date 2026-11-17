package nilfs2

// Fixed NILFS2 geometry and reserved numbers. Every number on disk is
// little-endian.

const (
	// Magic is NILFS2_SUPER_MAGIC, read as a little-endian word.
	Magic uint16 = 0x3434
	// SuperBlockOffset is the byte offset of the primary superblock.
	SuperBlockOffset uint64 = 1024
	// DefaultSuperblockBytes is the usual s_bytes value.
	DefaultSuperblockBytes uint16 = 1024
	// MinSuperblockBytes is the smallest s_bytes a valid superblock can
	// declare: it must cover the UUID and feature words at 0xf8..0x100.
	MinSuperblockBytes uint16 = 0x100
	// MaxRevLevel is the newest superblock revision this reader decodes.
	MaxRevLevel uint32 = 2
	// MinLogBlockSize and MaxLogBlockSize bound 1024 << value.
	MinLogBlockSize uint32 = 0
	MaxLogBlockSize uint32 = 6

	// readWindow is how many superblock bytes are read at once.
	superblockReadWindow uint64 = 4096
)

// Reserved inode numbers.
const (
	RootRecord   uint64 = 0
	RootInode    uint64 = 1
	DatIno       uint64 = 2
	CpfileIno    uint64 = 3
	SufileIno    uint64 = 4
	IfileIno     uint64 = 6
	SketchIno    uint64 = 10
	FirstUserIno uint64 = 11
)

// KindLabel is the filesystem name as facts and listings report it.
const KindLabel = "NILFS2"

// Resource ceilings keep a hostile image from exhausting memory.
const (
	// MaxNodes is the largest number of names a walk will record.
	MaxNodes = 5_000_000
	// MaxSymlinkBytes is the longest symbolic-link target held inline in an
	// entry.
	MaxSymlinkBytes = 64 * 1024
	// WarningCap bounds the warnings a walk keeps.
	WarningCap = 32
)
