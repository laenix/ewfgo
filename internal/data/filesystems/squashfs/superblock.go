package squashfs

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// magic is the four bytes at offset zero of a SquashFS image.
	magic = "hsqs"
	// superblockBytes is the size of the superblock structure.
	superblockBytes = 96
	minBlockSize    = 4096
	maxBlockSize    = 1024 * 1024
)

// invalidTable is the value SquashFS uses for an absent table.
const invalidTable = ^uint64(0)

// invalidFragment is the fragment index that means "no fragment tail".
const invalidFragment = uint32(0xFFFF_FFFF)

// Compressor identifiers as the superblock records them.
const (
	compressionZLIB = 1
	compressionLZMA = 2
	compressionLZO  = 3
	compressionXZ   = 4
	compressionLZ4  = 5
	compressionZSTD = 6
)

// Superblock flag bits this reader interprets.
const (
	flagUncompressedInodes    = 1 << 0
	flagUncompressedData      = 1 << 1
	flagUncompressedFragments = 1 << 3
	flagNoFragments           = 1 << 4
	flagAlwaysFragments       = 1 << 5
	flagDuplicates            = 1 << 6
	flagExport                = 1 << 7
	flagNoXattrs              = 1 << 8
	flagCompressionOptions    = 1 << 10
)

func compressionName(id uint16) string {
	switch id {
	case compressionZLIB:
		return "zlib"
	case compressionLZMA:
		return "lzma"
	case compressionLZO:
		return "lzo"
	case compressionXZ:
		return "xz"
	case compressionLZ4:
		return "lz4"
	case compressionZSTD:
		return "zstd"
	default:
		return "unknown"
	}
}

type superblock struct {
	inodeCount          uint32
	created             uint32
	blockSize           uint32
	fragments           uint32
	compression         uint16
	blockLog            uint16
	flags               uint16
	idCount             uint16
	versionMajor        uint16
	versionMinor        uint16
	rootInode           uint64
	bytesUsed           uint64
	idTableStart        uint64
	xattrIDTableStart   uint64
	inodeTableStart     uint64
	directoryTableStart uint64
	fragmentTableStart  uint64
	exportTableStart    uint64
}

func (sb *superblock) hasFlag(flag uint16) bool { return sb.flags&flag != 0 }

func parseSuperblock(bytes []byte) (*superblock, error) {
	if len(bytes) < superblockBytes {
		return nil, corruptf("the superblock needs %d bytes, only %d were read", superblockBytes, len(bytes))
	}
	if string(bytes[0:4]) != magic {
		return nil, corruptf("the magic is not %q", magic)
	}
	le16 := func(at int) uint16 { return binary.LittleEndian.Uint16(bytes[at:]) }
	le32 := func(at int) uint32 { return binary.LittleEndian.Uint32(bytes[at:]) }
	le64 := func(at int) uint64 { return binary.LittleEndian.Uint64(bytes[at:]) }
	sb := &superblock{
		inodeCount:          le32(4),
		created:             le32(8),
		blockSize:           le32(12),
		fragments:           le32(16),
		compression:         le16(20),
		blockLog:            le16(22),
		flags:               le16(24),
		idCount:             le16(26),
		versionMajor:        le16(28),
		versionMinor:        le16(30),
		rootInode:           le64(32),
		bytesUsed:           le64(40),
		idTableStart:        le64(48),
		xattrIDTableStart:   le64(56),
		inodeTableStart:     le64(64),
		directoryTableStart: le64(72),
		fragmentTableStart:  le64(80),
		exportTableStart:    le64(88),
	}
	if err := sb.validate(); err != nil {
		return nil, err
	}
	return sb, nil
}

func (sb *superblock) validate() error {
	if sb.versionMajor != 4 || sb.versionMinor != 0 {
		return unsupportedf("SquashFS %d.%d (this reader handles 4.0)", sb.versionMajor, sb.versionMinor)
	}
	if sb.blockSize < minBlockSize || sb.blockSize > maxBlockSize ||
		sb.blockSize&(sb.blockSize-1) != 0 {
		return corruptf("block size %d is not a power of two between %d and %d",
			sb.blockSize, minBlockSize, maxBlockSize)
	}
	if uint32(sb.blockLog) != trailingZeros(sb.blockSize) {
		return corruptf("block log %d does not describe a block size of %d", sb.blockLog, sb.blockSize)
	}
	if sb.bytesUsed < superblockBytes {
		return corruptf("the image claims %d bytes, fewer than its own superblock", sb.bytesUsed)
	}
	for _, table := range []struct {
		name  string
		start uint64
	}{
		{"inode table", sb.inodeTableStart},
		{"directory table", sb.directoryTableStart},
		{"id table", sb.idTableStart},
	} {
		if table.start >= sb.bytesUsed {
			return corruptf("the %s at %d lies outside the %d bytes in use", table.name, table.start, sb.bytesUsed)
		}
	}
	if sb.fragments > 0 && sb.fragmentTableStart >= sb.bytesUsed {
		return corruptf("the fragment table at %d lies outside the %d bytes in use",
			sb.fragmentTableStart, sb.bytesUsed)
	}
	if sb.idCount == 0 {
		return corruptf("the image has no uid/gid entries")
	}
	return nil
}

func trailingZeros(v uint32) uint32 {
	var count uint32
	for v > 1 {
		v >>= 1
		count++
	}
	return count
}

func readSuperblock(src source.ByteSource) (*superblock, error) {
	if src.Len() < superblockBytes {
		return nil, corruptf("the image is %d bytes, shorter than the %d-byte superblock",
			src.Len(), superblockBytes)
	}
	bytes := make([]byte, superblockBytes)
	if err := source.ReadExactAt(src, 0, bytes); err != nil {
		return nil, err
	}
	return parseSuperblock(bytes)
}

// Detect reports whether offset zero carries a SquashFS 4.0 superblock.
// An image whose compressor is unsupported is still SquashFS: detection
// returns true and Open reports the refusal by name.
func Detect(src source.ByteSource) (bool, error) {
	if src.Len() < superblockBytes {
		return false, nil
	}
	bytes := make([]byte, superblockBytes)
	if err := source.ReadExactAt(src, 0, bytes); err != nil {
		return false, err
	}
	if string(bytes[0:4]) != magic {
		return false, nil
	}
	if _, err := parseSuperblock(bytes); err != nil {
		if errIsUnsupported(err) {
			return true, nil
		}
		return false, err
	}
	return true, nil
}
