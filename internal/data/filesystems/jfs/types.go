package jfs

// On-disk primitives shared by the JFS structures. Every number is
// little-endian. A physical extent descriptor (pxd_t) is eight bytes: the low
// 24 bits of the first word are the length in filesystem blocks, the high
// eight bits are bits 32..39 of the address, and the second word holds the low
// 32 address bits.
const (
	// BlockSize is the only block size Linux JFS writes.
	BlockSize = 4096
	// InodeSize is the fixed on-disk inode size.
	InodeSize = 512
	// InodesPerPage is how many inodes fit in one 4 KiB page.
	InodesPerPage = 8
	// InodesPerExtent is how many inodes one 16 KiB inode extent holds.
	InodesPerExtent = 32
	// InodesPerGroup is one inode allocation group.
	InodesPerGroup = 4096
	// ExtentsPerGroup is the number of extents an allocation group lists.
	ExtentsPerGroup = 128
	// PagesPerInodeExtent is how many blocks one inode extent occupies.
	PagesPerInodeExtent = 4
	// MaxAllocationGroups is the format's ceiling for allocation groups.
	MaxAllocationGroups = 128
)

// Fixed byte offsets in an aggregate. The secondary superblock and the
// secondary aggregate inode table are reported, never used to mount.
const (
	// SuperblockOffset is the primary superblock's byte offset.
	SuperblockOffset uint64 = 0x8000
	// SecondarySuperblockOffset is the secondary copy's byte offset.
	SecondarySuperblockOffset uint64 = 0xF000
	// AIMapOffset is the aggregate inode map's conventional byte offset.
	AIMapOffset uint64 = 0x9000
	// AITableOffset is the fixed aggregate inode table's byte offset.
	AITableOffset uint64 = 0xB000
	// AggregateInodeCount is the number of slots in that fixed table.
	AggregateInodeCount = 32
)

// Magic is the only filesystem magic JFS writes.
var Magic = [4]byte{'J', 'F', 'S', '1'}

// Aggregate and fileset inode numbers.
const (
	AggregateInode   uint32 = 1
	BlockMapInode    uint32 = 2
	LogInode         uint32 = 3
	BadBlockInode    uint32 = 4
	FilesystemInode  uint32 = 16
	FilesetReserved  uint32 = 0
	FilesetExtent    uint32 = 1
	RootInode        uint32 = 2
	FilesetACLInode  uint32 = 3
	AggregateVersion uint32 = 2
)

// Mount states (s_state).
const (
	FMClean     uint32 = 0x0000_0000
	FMMount     uint32 = 0x0000_0001
	FMDirty     uint32 = 0x0000_0002
	FMLogRedo   uint32 = 0x0000_0004
	FMExtendFS  uint32 = 0x0000_0008
	FMStateMask uint32 = 0x0000_000f
)

// Aggregate flags (s_flag).
const (
	JFSUnicode   uint32 = 0x0000_0001
	JFSInlineLog uint32 = 0x0000_0800
	JFSBadSAIT   uint32 = 0x0001_0000
	JFSSparse    uint32 = 0x0002_0000
	JFSSwapBytes uint32 = 0x0010_0000
	JFSDirIndex  uint32 = 0x0020_0000
	JFSLinux     uint32 = 0x1000_0000
	JFSOS2       uint32 = 0x4000_0000
	JFSAIX       uint32 = 0x8000_0000
)

// Tree node flags shared by the extent and directory trees.
const (
	BTType     uint8 = 0x07
	BTRoot     uint8 = 0x01
	BTLeaf     uint8 = 0x02
	BTInternal uint8 = 0x04

	// Rust-style aliases kept for callers that prefer the on-disk names.
	BT_ROOT     = BTRoot
	BT_LEAF     = BTLeaf
	BT_INTERNAL = BTInternal
)

// Rust-style aliases for the aggregate flags and mount states. They name the
// same on-disk bits as the Go-spelled constants above.
const (
	JFS_UNICODE    = JFSUnicode
	JFS_INLINELOG  = JFSInlineLog
	JFS_BAD_SAIT   = JFSBadSAIT
	JFS_SPARSE     = JFSSparse
	JFS_SWAP_BYTES = JFSSwapBytes
	JFS_DIR_INDEX  = JFSDirIndex
	JFS_LINUX      = JFSLinux
	JFS_OS2        = JFSOS2
	JFS_AIX        = JFSAIX

	FM_CLEAN     = FMClean
	FM_MOUNT     = FMMount
	FM_DIRTY     = FMDirty
	FM_LOGREDO   = FMLogRedo
	FM_EXTENDFS  = FMExtendFS
	FM_STATE_MAX = FMStateMask
)

// Xad flags.
const (
	XadNew         uint8 = 0x01
	XadExtended    uint8 = 0x02
	XadCompressed  uint8 = 0x04
	XadNotRecorded uint8 = 0x08
	XadCoW         uint8 = 0x10
)

// Dmap bitmap locations inside one dmap page.
const (
	DBWord        = 32
	BlocksPerDMap = 8192
	WMapOffset    = 2048
	PMapOffset    = 3072
	DMapMapBytes  = 1024
)

// Dxd flags.
const (
	DxdIndex   uint8 = 0x80
	DxdInline  uint8 = 0x40
	DxdExtent  uint8 = 0x20
	DxdFile    uint8 = 0x10
	DxdCorrupt uint8 = 0x08
)

// Pxd is a physical extent descriptor: length and address, both in
// filesystem blocks.
type Pxd struct {
	Len     uint32
	Address uint64
}

// ParsePxd decodes the eight bytes at raw[at:at+8].
func ParsePxd(raw []byte, at int) (Pxd, error) {
	if at < 0 || at+8 > len(raw) || at+8 < at {
		return Pxd{}, corruptf("a physical extent descriptor at byte %d is past the %d-byte structure", at, len(raw))
	}
	word := le32(raw, at)
	return Pxd{
		Len:     word & 0x00ff_ffff,
		Address: uint64(word&0xff00_0000)<<8 | uint64(le32(raw, at+4)),
	}, nil
}

func encodePxd(raw []byte, at int, extent Pxd) {
	word := extent.Len&0x00ff_ffff | uint32(extent.Address>>32)<<24
	putLE32(raw, at, word)
	putLE32(raw, at+4, uint32(extent.Address))
}

// End returns the first block past the extent.
func (p Pxd) End() (uint64, error) {
	end := p.Address + uint64(p.Len)
	if end < p.Address {
		return 0, corruptf("a physical extent's end overflows the address space")
	}
	return end, nil
}

// IsEmpty reports whether the extent covers no blocks.
func (p Pxd) IsEmpty() bool { return p.Len == 0 }

// Dxd is a data extent descriptor (dxd_t): a flag byte, a byte size and a
// physical extent.
type Dxd struct {
	Flag uint8
	Size uint32
	Loc  Pxd
}

// ParseDxd decodes the sixteen bytes at raw[at:at+16].
func ParseDxd(raw []byte, at int) (Dxd, error) {
	if at < 0 || at+16 > len(raw) || at+16 < at {
		return Dxd{}, corruptf("a data extent descriptor at byte %d is past the %d-byte structure", at, len(raw))
	}
	loc, err := ParsePxd(raw, at+8)
	if err != nil {
		return Dxd{}, err
	}
	return Dxd{Flag: raw[at], Size: le32(raw, at+4), Loc: loc}, nil
}

// IsInline reports whether the descriptor holds its bytes inside the inode.
func (d Dxd) IsInline() bool { return d.Flag&DxdInline != 0 }

// IsExtent reports whether the descriptor names an extent.
func (d Dxd) IsExtent() bool { return d.Flag&DxdExtent != 0 }

// IsFile reports whether the descriptor names a file.
func (d Dxd) IsFile() bool { return d.Flag&DxdFile != 0 }

// Timestamp is a timestruc_t: seconds and a nanosecond remainder.
type Timestamp struct {
	Sec  uint32
	Nsec uint32
}

// ParseTimestamp decodes the eight bytes at raw[at:at+8].
func ParseTimestamp(raw []byte, at int) (Timestamp, error) {
	if at < 0 || at+8 > len(raw) || at+8 < at {
		return Timestamp{}, corruptf("a timestamp at byte %d is past the %d-byte structure", at, len(raw))
	}
	return Timestamp{Sec: le32(raw, at), Nsec: le32(raw, at+4)}, nil
}

// IsZero reports whether the timestamp records nothing.
func (t Timestamp) IsZero() bool { return t.Sec == 0 && t.Nsec == 0 }

// UnixNanos returns nanoseconds since the Unix epoch, saturating rather than
// overflowing.
func (t Timestamp) UnixNanos() int64 {
	const maxNanos = int64(^uint64(0) >> 1)
	if uint64(t.Sec) > uint64(maxNanos)/1_000_000_000 {
		return maxNanos
	}
	return int64(t.Sec)*1_000_000_000 + int64(t.Nsec)
}

// ---- little-endian readers -------------------------------------------------

func le16(raw []byte, at int) uint16 {
	return uint16(raw[at]) | uint16(raw[at+1])<<8
}

func le32(raw []byte, at int) uint32 {
	return uint32(raw[at]) |
		uint32(raw[at+1])<<8 |
		uint32(raw[at+2])<<16 |
		uint32(raw[at+3])<<24
}

func le64(raw []byte, at int) uint64 {
	return uint64(le32(raw, at)) | uint64(le32(raw, at+4))<<32
}

func putLE16(raw []byte, at int, value uint16) {
	raw[at] = byte(value)
	raw[at+1] = byte(value >> 8)
}

func putLE32(raw []byte, at int, value uint32) {
	raw[at] = byte(value)
	raw[at+1] = byte(value >> 8)
	raw[at+2] = byte(value >> 16)
	raw[at+3] = byte(value >> 24)
}

func putLE64(raw []byte, at int, value uint64) {
	putLE32(raw, at, uint32(value))
	putLE32(raw, at+4, uint32(value>>32))
}

// readLE16/32/64 are the bounds-checked variants used while parsing.
func readLE16(raw []byte, at int) (uint16, error) {
	if at < 0 || at+2 > len(raw) || at+2 < at {
		return 0, corruptf("a 16-bit field at byte %d is past the %d-byte structure", at, len(raw))
	}
	return le16(raw, at), nil
}

func readLE32(raw []byte, at int) (uint32, error) {
	if at < 0 || at+4 > len(raw) || at+4 < at {
		return 0, corruptf("a 32-bit field at byte %d is past the %d-byte structure", at, len(raw))
	}
	return le32(raw, at), nil
}

func readLE64(raw []byte, at int) (uint64, error) {
	if at < 0 || at+8 > len(raw) || at+8 < at {
		return 0, corruptf("a 64-bit field at byte %d is past the %d-byte structure", at, len(raw))
	}
	return le64(raw, at), nil
}
