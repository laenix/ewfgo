package hpfs

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// HPFS sector and fixed-offset constants. HPFS is a 512-byte-sector
// filesystem: a boot block sits at byte 0, the main superblock at sector 16,
// and the spare block at sector 17.
const (
	// SectorBytes is the only sector size HPFS writes.
	SectorBytes uint64 = 512
	// BootOffset is the byte offset of the boot block.
	BootOffset uint64 = 0
	// SuperBlockOffset is the byte offset of the main superblock (sector 16).
	SuperBlockOffset uint64 = 0x2000
	// SpareBlockOffset is the byte offset of the spare block (sector 17).
	SpareBlockOffset uint64 = 0x2200
)

// Fixed magics and the boot signature.
const (
	mainMagic   uint32 = 0xf995e849
	mainMagic1  uint32 = 0xfa53e9c5
	spareMagic  uint32 = 0xf9911849
	spareMagic1 uint32 = 0xfa5229c5
	bootMagic   uint16 = 0xaa55
	bootSign    uint8  = 0x28
	minVersion  uint8  = 2
	maxVersion  uint8  = 3
)

// Exported aliases for callers that prefer the on-disk names.
const (
	MainMagic   = mainMagic
	MainMagic1  = mainMagic1
	SpareMagic  = spareMagic
	SpareMagic1 = spareMagic1
	BootMagic   = bootMagic
)

const (
	bytesPerSectorAt    = 0x0b
	sectorsPerClusterAt = 0x0d
	bootSignatureAt     = 0x26
	volumeSerialAt      = 0x27
	volumeLabelAt       = 0x2b
	volumeLabelLen      = 11
	fsTypeAt            = 0x36
	fsTypeLen           = 8
	bootMagicAt         = 0x1fe

	versionAt       = 0x08
	funcVersionAt   = 0x09
	rootAt          = 0x0c
	nSectorsAt      = 0x10
	nBadblocksAt    = 0x14
	bitmapsAt       = 0x18
	badblocksAt     = 0x20
	lastChkdskAt    = 0x28
	lastOptimizeAt  = 0x2c
	nDirBandAt      = 0x30
	dirBandStartAt  = 0x34
	dirBandEndAt    = 0x38
	dirBandBitmapAt = 0x3c
	volumeNameAt    = 0x40
	volumeNameLen   = 32
	userIDTableAt   = 0x60
)

// BootBlock is the FAT-shaped boot block at byte zero.
type BootBlock struct {
	BytesPerSector    uint16
	SectorsPerCluster uint8
	VolumeSerial      uint32
	// VolumeLabel is decoded only when the raw bytes are printable ASCII.
	VolumeLabel    string
	VolumeLabelRaw [volumeLabelLen]byte
	FSType         [fsTypeLen]byte
}

// Superblock is the main superblock at sector 16.
type Superblock struct {
	Version     uint8
	FuncVersion uint8
	// RootFnode is the sector holding the root directory's fnode.
	RootFnode uint32
	// NSectors is the volume size the superblock declares, in 512-byte sectors.
	NSectors   uint32
	NBadblocks uint32
	// Bitmaps is the sector of the bitmap directory, or zero when absent.
	Bitmaps uint32
	// Badblocks is the bad-block list sector, or zero when absent.
	Badblocks     uint32
	LastChkdsk    uint32
	LastOptimize  uint32
	NDirBand      uint32
	DirBandStart  uint32
	DirBandEnd    uint32
	DirBandBitmap uint32
	VolumeName    string
	VolumeNameRaw [volumeNameLen]byte
	UserIDTable   uint32
	DeclaredBytes uint64
	VolumeBytes   uint64
	SourceBytes   uint64
}

// SpareBlock is the block at sector 17. Only its magic pair is decoded: the
// block holds hotfix bookkeeping, not a second copy of the superblock.
type SpareBlock struct {
	Magic  uint32
	Magic1 uint32
}

// Superblocks is the boot block, main superblock and spare block as one set.
type Superblocks struct {
	Boot  BootBlock
	Main  Superblock
	Spare SpareBlock
}

func readSector(src source.ByteSource, offset uint64, what string) ([]byte, error) {
	if offset > src.Len() || src.Len()-offset < SectorBytes {
		return nil, corruptf("the source is %d bytes, too short for %s at byte %d",
			src.Len(), what, offset)
	}
	raw := make([]byte, SectorBytes)
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// ReadBoot reads and validates the boot block at byte zero.
func ReadBoot(src source.ByteSource) (*BootBlock, error) {
	raw, err := readSector(src, BootOffset, "the HPFS boot block")
	if err != nil {
		return nil, err
	}
	if got := le16(raw, bootMagicAt); got != bootMagic {
		return nil, corruptf("the boot block at byte 0 has signature 0x%04x, not 0x%04x", got, bootMagic)
	}
	if raw[bootSignatureAt] != bootSign {
		return nil, corruptf("the boot block at byte 0 has boot signature 0x%02x, not 0x%02x",
			raw[bootSignatureAt], bootSign)
	}
	var fsType [fsTypeLen]byte
	copy(fsType[:], raw[fsTypeAt:fsTypeAt+fsTypeLen])
	if string(fsType[:4]) != "HPFS" {
		return nil, corruptf("the boot block at byte 0 names filesystem %q, not HPFS", string(fsType[:]))
	}
	bytesPerSector := le16(raw, bytesPerSectorAt)
	if uint64(bytesPerSector) != SectorBytes {
		return nil, unsupportedf("the boot block declares %d-byte sectors; HPFS uses %d",
			bytesPerSector, SectorBytes)
	}
	var labelRaw [volumeLabelLen]byte
	copy(labelRaw[:], raw[volumeLabelAt:volumeLabelAt+volumeLabelLen])
	return &BootBlock{
		BytesPerSector:    bytesPerSector,
		SectorsPerCluster: raw[sectorsPerClusterAt],
		VolumeSerial:      le32(raw, volumeSerialAt),
		VolumeLabel:       decodeASCII(labelRaw[:]),
		VolumeLabelRaw:    labelRaw,
		FSType:            fsType,
	}, nil
}

// ReadMain reads and validates the main superblock at sector 16.
func ReadMain(src source.ByteSource) (*Superblock, error) {
	raw, err := readSector(src, SuperBlockOffset, "the HPFS main superblock")
	if err != nil {
		return nil, err
	}
	magic := le32(raw, 0)
	magic1 := le32(raw, 4)
	if magic != mainMagic || magic1 != mainMagic1 {
		return nil, corruptf("the main superblock at byte %#x has magic %#08x/%#08x, expected %#08x/%#08x",
			SuperBlockOffset, magic, magic1, mainMagic, mainMagic1)
	}
	version := raw[versionAt]
	funcVersion := raw[funcVersionAt]
	if version < minVersion || version > maxVersion {
		return nil, unsupportedf("HPFS version %d; this reader decodes versions %d through %d",
			version, minVersion, maxVersion)
	}
	if funcVersion < minVersion || funcVersion > maxVersion {
		return nil, unsupportedf("HPFS functional version %d; this reader decodes versions %d through %d",
			funcVersion, minVersion, maxVersion)
	}
	root := le32(raw, rootAt)
	nSectors := le32(raw, nSectorsAt)
	if nSectors == 0 {
		return nil, corruptf("the main superblock declares a zero-sector volume")
	}
	if root == 0 {
		return nil, corruptf("the main superblock declares no root fnode")
	}
	if root >= nSectors {
		return nil, corruptf("the root fnode sector %d is outside the volume's %d sectors", root, nSectors)
	}
	nBadblocks := le32(raw, nBadblocksAt)
	badblocks := le32(raw, badblocksAt)
	if nBadblocks > 0 && badblocks == 0 {
		return nil, corruptf("the main superblock records %d bad blocks but no bad-block list sector", nBadblocks)
	}
	declared := uint64(nSectors) * SectorBytes
	sourceBytes := src.Len()
	volumeBytes := declared
	if sourceBytes < volumeBytes {
		volumeBytes = sourceBytes
	}
	var nameRaw [volumeNameLen]byte
	copy(nameRaw[:], raw[volumeNameAt:volumeNameAt+volumeNameLen])
	sb := &Superblock{
		Version:       version,
		FuncVersion:   funcVersion,
		RootFnode:     root,
		NSectors:      nSectors,
		NBadblocks:    nBadblocks,
		Bitmaps:       le32(raw, bitmapsAt),
		Badblocks:     badblocks,
		LastChkdsk:    le32(raw, lastChkdskAt),
		LastOptimize:  le32(raw, lastOptimizeAt),
		NDirBand:      le32(raw, nDirBandAt),
		DirBandStart:  le32(raw, dirBandStartAt),
		DirBandEnd:    le32(raw, dirBandEndAt),
		DirBandBitmap: le32(raw, dirBandBitmapAt),
		VolumeName:    decodeASCII(nameRaw[:]),
		VolumeNameRaw: nameRaw,
		UserIDTable:   le32(raw, userIDTableAt),
		DeclaredBytes: declared,
		VolumeBytes:   volumeBytes,
		SourceBytes:   sourceBytes,
	}
	return sb, nil
}

// ReadSpare reads and validates the spare block at sector 17.
func ReadSpare(src source.ByteSource) (*SpareBlock, error) {
	raw, err := readSector(src, SpareBlockOffset, "the HPFS spare block")
	if err != nil {
		return nil, err
	}
	magic := le32(raw, 0)
	magic1 := le32(raw, 4)
	if magic != spareMagic || magic1 != spareMagic1 {
		return nil, corruptf("the spare block at byte %#x has magic %#08x/%#08x, expected %#08x/%#08x",
			SpareBlockOffset, magic, magic1, spareMagic, spareMagic1)
	}
	return &SpareBlock{Magic: magic, Magic1: magic1}, nil
}

// ReadSuperblocks reads the boot block, main superblock and spare block.
func ReadSuperblocks(src source.ByteSource) (*Superblocks, error) {
	boot, err := ReadBoot(src)
	if err != nil {
		return nil, err
	}
	main, err := ReadMain(src)
	if err != nil {
		return nil, err
	}
	spare, err := ReadSpare(src)
	if err != nil {
		return nil, err
	}
	return &Superblocks{Boot: *boot, Main: *main, Spare: *spare}, nil
}

// ValidateSectorRange validates a sector range and returns its byte offset.
// Sector zero holds the boot block, so no structure this reader follows may
// name it. Both the declared volume and the physical source bound the range.
func (s *Superblock) ValidateSectorRange(sector, sectors uint32, what string) (uint64, error) {
	if sector == 0 {
		return 0, corruptf("%s names sector 0, which holds the HPFS boot block", what)
	}
	if sectors == 0 {
		return 0, corruptf("%s names a zero-length sector range", what)
	}
	end := uint64(sector) + uint64(sectors)
	if end > uint64(s.NSectors) {
		return 0, corruptf("%s covers sectors %d..%d, past the volume's %d sectors",
			what, sector, end, s.NSectors)
	}
	start := uint64(sector) * SectorBytes
	endBytes := end * SectorBytes
	if endBytes > s.SourceBytes {
		return 0, corruptf("%s covers sectors %d..%d, ending at byte %d, past the %d bytes the source holds",
			what, sector, end, endBytes, s.SourceBytes)
	}
	return start, nil
}

// ValidateSector validates a one-sector range.
func (s *Superblock) ValidateSector(sector uint32, what string) (uint64, error) {
	return s.ValidateSectorRange(sector, 1, what)
}

// decodeASCII decodes a fixed field only when it is printable ASCII. The
// field ends at its first NUL; trailing spaces are removed.
func decodeASCII(raw []byte) string {
	end := len(raw)
	for index, value := range raw {
		if value == 0 {
			end = index
			break
		}
	}
	field := raw[:end]
	for len(field) > 0 && field[len(field)-1] == ' ' {
		field = field[:len(field)-1]
	}
	if len(field) == 0 {
		return ""
	}
	for _, value := range field {
		if value < 0x20 || value > 0x7e {
			return ""
		}
	}
	return string(field)
}

func bootClaims(src source.ByteSource) (bool, error) {
	if src.Len() < SectorBytes {
		return false, nil
	}
	raw, err := readSector(src, BootOffset, "the HPFS boot block")
	if err != nil {
		return false, err
	}
	return le16(raw, bootMagicAt) == bootMagic &&
		string(raw[fsTypeAt:fsTypeAt+4]) == "HPFS", nil
}

func mainMagicMatches(src source.ByteSource) (bool, error) {
	if src.Len() < SuperBlockOffset+8 {
		return false, nil
	}
	raw := make([]byte, 8)
	if err := source.ReadExactAt(src, SuperBlockOffset, raw); err != nil {
		return false, err
	}
	return le32(raw, 0) == mainMagic && le32(raw, 4) == mainMagic1, nil
}

// detectSuperblocks reports whether the fixed offsets carry an HPFS boot block
// or main superblock. A claim is parsed in full, so a matching boot block with
// a corrupt main superblock is an error rather than a silent non-match.
func detectSuperblocks(src source.ByteSource) (bool, error) {
	boot, err := bootClaims(src)
	if err != nil {
		return false, err
	}
	main, err := mainMagicMatches(src)
	if err != nil {
		return false, err
	}
	if !boot && !main {
		return false, nil
	}
	if _, err := ReadSuperblocks(src); err != nil {
		return false, err
	}
	return true, nil
}
