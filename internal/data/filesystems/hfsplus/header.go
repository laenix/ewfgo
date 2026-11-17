package hfsplus

// HFS+ volume header parsing and probing.
//
// The volume header lives at byte 1024, after the two boot blocks.  It
// describes the allocation geometry, the volume-wide counts and timestamps,
// and the five special forks (allocation, extents overflow, catalog,
// attributes, startup).  The signature separates the two dialects: "H+" is
// case-insensitive HFS+ and "HX" is case-sensitive HFSX, which mostly changes
// how the catalog compares names.

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// HeaderOffset is the byte offset of the volume header.
	HeaderOffset = 1024
	// HeaderLen is the size of the volume header structure.
	HeaderLen = 512

	// SignatureHFSPlus is the classic case-insensitive signature ("H+").
	SignatureHFSPlus Signature = 0x482B
	// SignatureHFSX is the case-sensitive signature ("HX").
	SignatureHFSX Signature = 0x4858

	// HFSUnixEpochOffset is the number of seconds from 1904-01-01 (the HFS
	// epoch) to 1970-01-01.
	HFSUnixEpochOffset int64 = 2_082_844_800

	maxBlockSize = 1024 * 1024
)

// Signature distinguishes the two HFS+ dialects.
type Signature uint16

// String returns the human label.
func (s Signature) String() string {
	if s == SignatureHFSX {
		return "HFSX"
	}
	return "HFS+"
}

// Label is an alias for String, kept for the Rust API's shape.
func (s Signature) Label() string { return s.String() }

// CaseSensitive reports whether the catalog compares names byte-wise.
func (s Signature) CaseSensitive() bool { return s == SignatureHFSX }

// Time is an HFS+ timestamp: seconds since 1904-01-01 UTC, stored unsigned.
// Zero is the HFS epoch itself, but Apple's tools write zero for a timestamp
// that was never set.
type Time uint32

// IsZero reports whether the timestamp was never set.
func (t Time) IsZero() bool { return t == 0 }

// Unix returns the timestamp in Unix seconds.
func (t Time) Unix() int64 { return int64(t) - HFSUnixEpochOffset }

func (t Time) String() string { return fmt.Sprintf("%d", t.Unix()) }

// Extent is one contiguous run of allocation blocks.
//
// A zero StartBlock is a hole in the ForkExtents vocabulary.  HFS+ has no
// sparse files, so a strict read refuses it rather than inventing bytes.
type Extent struct {
	StartBlock uint32
	BlockCount uint32
}

// IsEmpty reports whether the descriptor carries no blocks.
func (e Extent) IsEmpty() bool { return e.BlockCount == 0 }

// EndBlock returns the first block after the extent, saturated.
func (e Extent) EndBlock() uint32 {
	end := e.StartBlock + e.BlockCount
	if end < e.StartBlock {
		return ^uint32(0)
	}
	return end
}

// InlineExtents is the number of extent descriptors stored in every fork.
const InlineExtents = 8

// ForkLen is the size of an HFS+ fork descriptor.
const ForkLen = 80

// Fork is the descriptor embedded in a catalog record and in the volume
// header: a logical size, clump size, block count, and eight extents.
type Fork struct {
	LogicalSize uint64
	ClumpSize   uint32
	TotalBlocks uint32
	Extents     [InlineExtents]Extent
}

func parseFork(bytes []byte) (Fork, error) {
	if len(bytes) < ForkLen {
		return Fork{}, invalidf("fork descriptor is %d bytes, expected %d", len(bytes), ForkLen)
	}
	var fork Fork
	fork.LogicalSize = be64(bytes, 0)
	fork.ClumpSize = be32(bytes, 8)
	fork.TotalBlocks = be32(bytes, 12)
	for i := range fork.Extents {
		at := 16 + i*8
		fork.Extents[i] = Extent{StartBlock: be32(bytes, at), BlockCount: be32(bytes, at+4)}
	}
	return fork, nil
}

// InlineExtents returns the non-empty inline extent descriptors in fork order.
func (f Fork) InlineExtents() []Extent {
	out := make([]Extent, 0, InlineExtents)
	for _, extent := range f.Extents {
		if !extent.IsEmpty() {
			out = append(out, extent)
		}
	}
	return out
}

// IsEmpty reports whether the fork declares no content and no blocks.
func (f Fork) IsEmpty() bool { return f.LogicalSize == 0 && f.TotalBlocks == 0 }

// Header is the parsed HFS+ volume header.
type Header struct {
	Signature          Signature
	Version            uint16
	Attributes         uint32
	LastMountedVersion uint32
	JournalInfoBlock   uint32
	Created            Time
	Modified           Time
	BackedUp           Time
	Checked            Time
	FileCount          uint32
	FolderCount        uint32
	BlockSize          uint32
	TotalBlocks        uint32
	FreeBlocks         uint32
	NextAllocation     uint32
	ResourceClumpSize  uint32
	DataClumpSize      uint32
	NextCatalogID      uint32
	WriteCount         uint32
	EncodingsBitmap    uint64
	FinderInfo         [8]uint32
	AllocationFile     Fork
	ExtentsFile        Fork
	CatalogFile        Fork
	AttributesFile     Fork
	StartupFile        Fork
}

// ParseHeader parses the 512-byte volume header.
func ParseHeader(bytes []byte) (*Header, error) {
	if len(bytes) < HeaderLen {
		return nil, invalidf("volume header is %d bytes, expected %d", len(bytes), HeaderLen)
	}
	signature := Signature(be16(bytes, 0))
	if signature != SignatureHFSPlus && signature != SignatureHFSX {
		return nil, invalidf("signature 0x%04X is neither H+ nor HX", uint16(signature))
	}
	version := be16(bytes, 2)
	expected := uint16(4)
	if signature == SignatureHFSX {
		expected = 5
	}
	if version != expected {
		return nil, invalidf("%s volume header version %d, expected %d", signature, version, expected)
	}

	blockSize := be32(bytes, 40)
	if blockSize < 512 || blockSize > maxBlockSize || blockSize&(blockSize-1) != 0 {
		return nil, invalidf("block size %d is not a power of two in 512..=%d", blockSize, maxBlockSize)
	}
	totalBlocks := be32(bytes, 44)
	if totalBlocks == 0 {
		return nil, invalidf("total block count is zero")
	}
	freeBlocks := be32(bytes, 48)
	if freeBlocks > totalBlocks {
		return nil, invalidf("free block count %d exceeds %d total blocks", freeBlocks, totalBlocks)
	}

	var finderInfo [8]uint32
	for i := range finderInfo {
		finderInfo[i] = be32(bytes, 80+i*4)
	}
	allocation, err := parseFork(bytes[112:192])
	if err != nil {
		return nil, err
	}
	extents, err := parseFork(bytes[192:272])
	if err != nil {
		return nil, err
	}
	catalog, err := parseFork(bytes[272:352])
	if err != nil {
		return nil, err
	}
	attributes, err := parseFork(bytes[352:432])
	if err != nil {
		return nil, err
	}
	startup, err := parseFork(bytes[432:512])
	if err != nil {
		return nil, err
	}
	if catalog.TotalBlocks == 0 || catalog.LogicalSize == 0 {
		return nil, invalidf("catalog file is empty")
	}
	if extents.TotalBlocks == 0 {
		return nil, invalidf("extents overflow file is empty")
	}

	return &Header{
		Signature:          signature,
		Version:            version,
		Attributes:         be32(bytes, 4),
		LastMountedVersion: be32(bytes, 8),
		JournalInfoBlock:   be32(bytes, 12),
		Created:            Time(be32(bytes, 16)),
		Modified:           Time(be32(bytes, 20)),
		BackedUp:           Time(be32(bytes, 24)),
		Checked:            Time(be32(bytes, 28)),
		FileCount:          be32(bytes, 32),
		FolderCount:        be32(bytes, 36),
		BlockSize:          blockSize,
		TotalBlocks:        totalBlocks,
		FreeBlocks:         freeBlocks,
		NextAllocation:     be32(bytes, 52),
		ResourceClumpSize:  be32(bytes, 56),
		DataClumpSize:      be32(bytes, 60),
		NextCatalogID:      be32(bytes, 64),
		WriteCount:         be32(bytes, 68),
		EncodingsBitmap:    be64(bytes, 72),
		FinderInfo:         finderInfo,
		AllocationFile:     allocation,
		ExtentsFile:        extents,
		CatalogFile:        catalog,
		AttributesFile:     attributes,
		StartupFile:        startup,
	}, nil
}

// CaseSensitive reports whether the volume's catalog compares names byte-wise.
func (h *Header) CaseSensitive() bool { return h.Signature.CaseSensitive() }

// Journaled reports whether the volume header names a journal info block.
func (h *Header) Journaled() bool { return h.JournalInfoBlock != 0 }

// TotalBytes returns the allocation area's size in bytes.
func (h *Header) TotalBytes() uint64 { return uint64(h.TotalBlocks) * uint64(h.BlockSize) }

// Detect probes a source for an HFS+ volume header.  A matching signature
// with a malformed header is an error; a non-matching signature is nil, nil.
func Detect(src source.ByteSource) (*Header, error) {
	if src.Len() < HeaderOffset+HeaderLen {
		return nil, nil
	}
	bytes, err := source.ReadVecAt(src, HeaderOffset, HeaderLen)
	if err != nil {
		return nil, err
	}
	signature := Signature(be16(bytes, 0))
	if signature != SignatureHFSPlus && signature != SignatureHFSX {
		return nil, nil
	}
	return ParseHeader(bytes)
}
