package hfs

import "github.com/laenix/ewfgo/internal/data/source"

// MDBOffset is where the Master Directory Block starts in a volume.
const MDBOffset uint64 = 1024

// MDBBytes is the size of the Master Directory Block.
const MDBBytes = 162

// Signature is the classic-HFS signature word, `BD`.
const Signature uint16 = 0x4244

// SignatureSwapped is the same two bytes read little-endian.
const SignatureSwapped uint16 = 0x4442

// MaxVolumeName is the longest volume name, a Str27.
const MaxVolumeName = 27

// MasterDirectoryBlock is the parsed volume header. All dates are seconds
// since 1904-01-01 in the machine's local wall clock.
type MasterDirectoryBlock struct {
	Signature           uint16
	CreateDate          uint32
	ModifyDate          uint32
	Attributes          uint16
	RootFiles           uint16
	BitmapStart         uint16
	AllocationPtr       uint16
	AllocationBlocks    uint16
	AllocationBlockSize uint32
	ClumpSize           uint32
	AllocationStart     uint16
	NextCNID            uint32
	FreeBlocks          uint16
	Name                string
	BackupDate          uint32
	WriteCount          uint32
	ExtentsClumpSize    uint32
	CatalogClumpSize    uint32
	RootDirectories     uint16
	FileCount           uint32
	DirectoryCount      uint32
	ExtentsFileSize     uint32
	ExtentsExtents      ExtentRecord
	CatalogFileSize     uint32
	CatalogExtents      ExtentRecord
}

// AllocationBase is the absolute byte offset of allocation block 0.
func (m *MasterDirectoryBlock) AllocationBase() uint64 {
	return uint64(m.AllocationStart) * 512
}

// IsUnmounted reports whether the volume was left cleanly unmounted.
func (m *MasterDirectoryBlock) IsUnmounted() bool {
	return m.Attributes&0x0100 != 0
}

// detectMDB reports whether src carries a classic-HFS Master Directory Block.
// A byte-swapped signature is refused by name; a source too short for the MDB
// is simply not HFS.
func detectMDB(src source.ByteSource) (bool, error) {
	if src == nil {
		return false, corruptf("a nil byte source")
	}
	if src.Len() < MDBOffset+MDBBytes {
		return false, nil
	}
	raw := make([]byte, MDBBytes)
	if err := source.ReadExactAt(src, MDBOffset, raw); err != nil {
		return false, err
	}
	switch be16(raw, 0) {
	case SignatureSwapped:
		return false, unsupportedf("a byte-swapped (little-endian) MDB")
	case Signature:
		if _, err := parseMDB(raw); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, nil
	}
}

// ReadMDB reads the Master Directory Block from a source that must be classic
// HFS.
func ReadMDB(src source.ByteSource) (*MasterDirectoryBlock, error) {
	found, err := detectMDB(src)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, corruptf("the source has no classic-HFS Master Directory Block")
	}
	raw := make([]byte, MDBBytes)
	if err := source.ReadExactAt(src, MDBOffset, raw); err != nil {
		return nil, err
	}
	return parseMDB(raw)
}

// parseMDB decodes and validates the 162-byte structure.
func parseMDB(raw []byte) (*MasterDirectoryBlock, error) {
	if len(raw) < MDBBytes {
		return nil, corruptf("the Master Directory Block is truncated")
	}
	blockSize := be32(raw, 20)
	if blockSize == 0 || blockSize < 512 || blockSize&(blockSize-1) != 0 {
		return nil, corruptf("the allocation block size %d is not a power of two of at least 512", blockSize)
	}
	allocationBlocks := be16(raw, 18)
	if allocationBlocks == 0 {
		return nil, corruptf("the volume declares no allocation blocks")
	}
	allocationStart := be16(raw, 28)
	if allocationStart < 3 {
		return nil, corruptf("the allocation area starts at 512-byte block %d, inside the volume header", allocationStart)
	}
	nameLength := int(raw[36])
	if nameLength > MaxVolumeName {
		nameLength = MaxVolumeName
	}
	mdb := &MasterDirectoryBlock{
		Signature:           Signature,
		CreateDate:          be32(raw, 2),
		ModifyDate:          be32(raw, 6),
		Attributes:          be16(raw, 10),
		RootFiles:           be16(raw, 12),
		BitmapStart:         be16(raw, 14),
		AllocationPtr:       be16(raw, 16),
		AllocationBlocks:    allocationBlocks,
		AllocationBlockSize: blockSize,
		ClumpSize:           be32(raw, 24),
		AllocationStart:     allocationStart,
		NextCNID:            be32(raw, 30),
		FreeBlocks:          be16(raw, 34),
		Name:                decodeMacRoman(raw[37 : 37+nameLength]),
		BackupDate:          be32(raw, 64),
		WriteCount:          be32(raw, 70),
		ExtentsClumpSize:    be32(raw, 74),
		CatalogClumpSize:    be32(raw, 78),
		RootDirectories:     be16(raw, 82),
		FileCount:           be32(raw, 84),
		DirectoryCount:      be32(raw, 88),
		ExtentsFileSize:     be32(raw, 130),
		CatalogFileSize:     be32(raw, 146),
	}
	extents, err := readExtentRecord(raw, 134)
	if err != nil {
		return nil, err
	}
	catalog, err := readExtentRecord(raw, 150)
	if err != nil {
		return nil, err
	}
	mdb.ExtentsExtents = extents
	mdb.CatalogExtents = catalog
	return mdb, nil
}
