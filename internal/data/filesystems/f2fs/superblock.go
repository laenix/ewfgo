package f2fs

import (
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// F2FS's magic, used both as the superblock signature and as the CRC seed.
const Magic uint32 = 0xF2F52010

// Superblock layout constants.
const (
	SuperOffset     uint64 = 1024
	SuperSize              = 3072
	SuperCopyStride uint64 = 4096
	VolumeNameUnits        = 512
	MaxDevices             = 8
)

// Feature bits, in the order f2fs.h declares them.
const (
	FeatureEncrypt          uint32 = 0x00000001
	FeatureBlkZoned         uint32 = 0x00000002
	FeatureAtomicWrite      uint32 = 0x00000004
	FeatureExtraAttr        uint32 = 0x00000008
	FeaturePrjQuota         uint32 = 0x00000010
	FeatureInodeChecksum    uint32 = 0x00000020
	FeatureFlexibleInlineXA uint32 = 0x00000040
	FeatureQuotaIno         uint32 = 0x00000080
	FeatureInodeCrtime      uint32 = 0x00000100
	FeatureLostFound        uint32 = 0x00000200
	FeatureVerity           uint32 = 0x00000400
	FeatureSBChecksum       uint32 = 0x00000800
	FeatureCasefold         uint32 = 0x00001000
	FeatureCompression      uint32 = 0x00002000
	FeatureRO               uint32 = 0x00004000
	FeatureDeviceAlias      uint32 = 0x00008000
	FeaturePackedSSA        uint32 = 0x00010000
)

// KnownFeatures are the bits this reader understands well enough to keep
// reading.  Encryption and zoned storage change where data is stored and are
// not in this set.
const KnownFeatures uint32 = FeatureAtomicWrite |
	FeatureExtraAttr |
	FeaturePrjQuota |
	FeatureInodeChecksum |
	FeatureFlexibleInlineXA |
	FeatureQuotaIno |
	FeatureInodeCrtime |
	FeatureLostFound |
	FeatureVerity |
	FeatureSBChecksum |
	FeatureCasefold |
	FeatureCompression |
	FeatureRO |
	FeatureDeviceAlias |
	FeaturePackedSSA

// Superblock is a parsed F2FS superblock.
type Superblock struct {
	// Offset is the byte offset in the image this copy was read from.
	Offset uint64
	// ChecksumVerified records whether the seeded CRC verified.
	ChecksumVerified bool

	Major uint16
	Minor uint16

	BlockSize          uint32
	BlocksPerSegment   uint32
	SegmentsPerSection uint32
	SectionsPerZone    uint32
	BlockCount         uint64
	SectionCount       uint32
	SegmentCount       uint32
	SegmentCountCkpt   uint32
	SegmentCountSIT    uint32
	SegmentCountNAT    uint32
	SegmentCountSSA    uint32
	SegmentCountMain   uint32
	Segment0Blkaddr    uint32
	CPBlkaddr          uint32
	SITBlkaddr         uint32
	NATBlkaddr         uint32
	SSABlkaddr         uint32
	MainBlkaddr        uint32
	RootIno            uint32
	NodeIno            uint32
	MetaIno            uint32
	// CPPayload is the number of extra checkpoint payload blocks.
	CPPayload uint32

	UUID    [16]byte
	Label   string
	Feature uint32
}

// ParseSuperblock parses one superblock copy read from offset.
func ParseSuperblock(bytes []byte, offset uint64) (*Superblock, error) {
	if len(bytes) < SuperSize {
		return nil, invalidf("the superblock is shorter than %d bytes", SuperSize)
	}
	bytes = bytes[:SuperSize]
	magic, err := u32At(bytes, 0)
	if err != nil {
		return nil, err
	}
	if magic != Magic {
		return nil, invalidf("the superblock magic is missing")
	}
	feature, err := u32At(bytes, 2180)
	if err != nil {
		return nil, err
	}
	checksumVerified := false
	if feature&FeatureSBChecksum != 0 {
		rawAt, err := u32At(bytes, 32)
		if err != nil {
			return nil, err
		}
		at := int(rawAt)
		if at < 4 || at > SuperSize-4 {
			return nil, invalidf("the superblock checksum claims to live at byte %d", at)
		}
		stored, _ := u32At(bytes, at)
		computed := foundation.CRC32Seeded(Magic, bytes[:at])
		if stored != computed {
			return nil, invalidf("the superblock checksum is %#010x, computed %#010x", stored, computed)
		}
		checksumVerified = true
	}
	logSectors, err := u32At(bytes, 8)
	if err != nil {
		return nil, err
	}
	logSectorsPerBlock, err := u32At(bytes, 12)
	if err != nil {
		return nil, err
	}
	logBlockSize, err := u32At(bytes, 16)
	if err != nil {
		return nil, err
	}
	if logSectors < 9 || logSectors > 12 {
		return nil, invalidf("the sector-size log %d is outside 9..=12", logSectors)
	}
	if logBlockSize < 12 || logBlockSize > 16 {
		return nil, invalidf("the block-size log %d is outside 12..=16", logBlockSize)
	}
	if logSectorsPerBlock != logBlockSize-9 {
		return nil, invalidf("the sector log %d and block log %d disagree", logSectors, logBlockSize)
	}
	blockSize := uint32(1) << logBlockSize
	logBlocksPerSeg, err := u32At(bytes, 20)
	if err != nil {
		return nil, err
	}
	if logBlocksPerSeg < 8 || logBlocksPerSeg > 12 {
		return nil, invalidf("the segment-size log %d is outside 8..=12", logBlocksPerSeg)
	}
	blocksPerSegment := uint32(1) << logBlocksPerSeg
	segmentsPerSection, err := u32At(bytes, 24)
	if err != nil {
		return nil, err
	}
	sectionsPerZone, err := u32At(bytes, 28)
	if err != nil {
		return nil, err
	}
	if segmentsPerSection == 0 || sectionsPerZone == 0 {
		return nil, invalidf("the section or zone geometry is zero")
	}
	blockCount, err := u64At(bytes, 36)
	if err != nil {
		return nil, err
	}
	if blockCount == 0 {
		return nil, invalidf("the volume declares zero blocks")
	}
	segmentCount, err := u32At(bytes, 48)
	if err != nil {
		return nil, err
	}
	segmentCountCkpt, err := u32At(bytes, 52)
	if err != nil {
		return nil, err
	}
	segmentCountSIT, err := u32At(bytes, 56)
	if err != nil {
		return nil, err
	}
	segmentCountNAT, err := u32At(bytes, 60)
	if err != nil {
		return nil, err
	}
	segmentCountSSA, err := u32At(bytes, 64)
	if err != nil {
		return nil, err
	}
	segmentCountMain, err := u32At(bytes, 68)
	if err != nil {
		return nil, err
	}
	if segmentCountCkpt == 0 || segmentCountSIT == 0 || segmentCountNAT == 0 ||
		segmentCountSSA == 0 || segmentCountMain == 0 {
		return nil, invalidf("one of the five areas has no segments")
	}
	areas := uint64(segmentCountCkpt) + uint64(segmentCountSIT) + uint64(segmentCountNAT) +
		uint64(segmentCountSSA) + uint64(segmentCountMain)
	if areas > uint64(^uint32(0)) {
		return nil, invalidf("the segment counts overflow")
	}
	if uint32(areas) != segmentCount {
		return nil, invalidf("the areas hold %d segments but the volume declares %d", areas, segmentCount)
	}
	segment0Blkaddr, err := u32At(bytes, 72)
	if err != nil {
		return nil, err
	}
	if segment0Blkaddr%blocksPerSegment != 0 {
		return nil, invalidf("the first segment starts at block %d, not on a segment boundary", segment0Blkaddr)
	}
	cpBlkaddr, err := u32At(bytes, 76)
	if err != nil {
		return nil, err
	}
	sitBlkaddr, err := u32At(bytes, 80)
	if err != nil {
		return nil, err
	}
	natBlkaddr, err := u32At(bytes, 84)
	if err != nil {
		return nil, err
	}
	ssaBlkaddr, err := u32At(bytes, 88)
	if err != nil {
		return nil, err
	}
	mainBlkaddr, err := u32At(bytes, 92)
	if err != nil {
		return nil, err
	}
	expectSIT := uint64(segment0Blkaddr) + uint64(segmentCountCkpt)*uint64(blocksPerSegment)
	expectNAT := uint64(sitBlkaddr) + uint64(segmentCountSIT)*uint64(blocksPerSegment)
	expectSSA := uint64(natBlkaddr) + uint64(segmentCountNAT)*uint64(blocksPerSegment)
	expectMain := uint64(ssaBlkaddr) + uint64(segmentCountSSA)*uint64(blocksPerSegment)
	if uint64(cpBlkaddr) != uint64(segment0Blkaddr) {
		return nil, invalidf("the checkpoint area starts at %d, not at the first segment %d", cpBlkaddr, segment0Blkaddr)
	}
	if uint64(sitBlkaddr) != expectSIT || uint64(natBlkaddr) != expectNAT ||
		uint64(ssaBlkaddr) != expectSSA || uint64(mainBlkaddr) != expectMain {
		return nil, invalidf(
			"the area addresses do not follow the segment counts (%d, %d, %d, %d)",
			sitBlkaddr, natBlkaddr, ssaBlkaddr, mainBlkaddr)
	}
	end := uint64(segment0Blkaddr) + uint64(segmentCount)*uint64(blocksPerSegment)
	if end > blockCount {
		return nil, invalidf("the segments end at block %d, past the %d-block volume", end, blockCount)
	}
	rootIno, err := u32At(bytes, 96)
	if err != nil {
		return nil, err
	}
	nodeIno, err := u32At(bytes, 100)
	if err != nil {
		return nil, err
	}
	metaIno, err := u32At(bytes, 104)
	if err != nil {
		return nil, err
	}
	if rootIno < 3 || nodeIno < 3 || metaIno < 3 {
		return nil, invalidf("the root, node or metadata inode number is below the reserved range")
	}
	var uuid [16]byte
	copy(uuid[:], bytes[108:124])
	label := readLabel(bytes[124 : 124+VolumeNameUnits*2])
	sectionCount, err := u32At(bytes, 44)
	if err != nil {
		return nil, err
	}
	major, err := u16At(bytes, 4)
	if err != nil {
		return nil, err
	}
	minor, err := u16At(bytes, 6)
	if err != nil {
		return nil, err
	}
	cpPayload, err := u32At(bytes, 1664)
	if err != nil {
		return nil, err
	}
	return &Superblock{
		Offset:             offset,
		ChecksumVerified:   checksumVerified,
		Major:              major,
		Minor:              minor,
		BlockSize:          blockSize,
		BlocksPerSegment:   blocksPerSegment,
		SegmentsPerSection: segmentsPerSection,
		SectionsPerZone:    sectionsPerZone,
		BlockCount:         blockCount,
		SectionCount:       sectionCount,
		SegmentCount:       segmentCount,
		SegmentCountCkpt:   segmentCountCkpt,
		SegmentCountSIT:    segmentCountSIT,
		SegmentCountNAT:    segmentCountNAT,
		SegmentCountSSA:    segmentCountSSA,
		SegmentCountMain:   segmentCountMain,
		Segment0Blkaddr:    segment0Blkaddr,
		CPBlkaddr:          cpBlkaddr,
		SITBlkaddr:         sitBlkaddr,
		NATBlkaddr:         natBlkaddr,
		SSABlkaddr:         ssaBlkaddr,
		MainBlkaddr:        mainBlkaddr,
		RootIno:            rootIno,
		NodeIno:            nodeIno,
		MetaIno:            metaIno,
		CPPayload:          cpPayload,
		UUID:               uuid,
		Label:              label,
		Feature:            feature,
	}, nil
}

// ReadSuperblock reads the first superblock copy that parses.
func ReadSuperblock(src source.ByteSource) (*Superblock, error) {
	sb, err := DetectSuperblock(src)
	if err != nil {
		return nil, err
	}
	if sb == nil {
		return nil, invalidf("no F2FS superblock was found")
	}
	return sb, nil
}

// DetectSuperblock parses a superblock when the source carries one, without
// checking whether the volume's features are supported.
func DetectSuperblock(src source.ByteSource) (*Superblock, error) {
	var firstErr error
	for _, offset := range []uint64{SuperOffset, SuperOffset + SuperCopyStride} {
		if offset+SuperSize > src.Len() {
			continue
		}
		bytes, err := source.ReadVecAt(src, offset, SuperSize)
		if err != nil {
			continue
		}
		magic, err := u32At(bytes, 0)
		if err != nil || magic != Magic {
			continue
		}
		sb, err := ParseSuperblock(bytes, offset)
		if err == nil {
			return sb, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// ByteOffset returns the byte offset of a block address.
func (s *Superblock) ByteOffset(block uint32) uint64 {
	return uint64(block) * uint64(s.BlockSize)
}

// NATBlocks returns the blocks one active half of the node address table holds.
func (s *Superblock) NATBlocks() uint64 {
	return uint64(s.SegmentCountNAT) * uint64(s.BlocksPerSegment)
}

// UnknownFeatures returns the feature bits this build does not understand.
func (s *Superblock) UnknownFeatures() uint32 {
	return s.Feature &^ KnownFeatures
}

// CheckLength cross-checks the declared block count against the source.
func (s *Superblock) CheckLength(src source.ByteSource) error {
	declared := s.BlockCount * uint64(s.BlockSize)
	if declared > src.Len() {
		return invalidf("the volume declares %d bytes but the image holds %d", declared, src.Len())
	}
	return nil
}

// CheckSupported refuses volumes whose layout this reader cannot follow.
func (s *Superblock) CheckSupported() error {
	if s.Feature&FeatureEncrypt != 0 {
		return unsupportedf("an encrypted volume; file contents would be ciphertext")
	}
	if s.Feature&FeatureBlkZoned != 0 {
		return unsupportedf("a zoned (SMR) volume")
	}
	if unknown := s.UnknownFeatures(); unknown != 0 {
		return unsupportedf("feature bits %#x", unknown)
	}
	return nil
}

// FeatureNames returns the names of the feature bits this volume sets, in bit
// order.
func (s *Superblock) FeatureNames() []string {
	names := []struct {
		bit  uint32
		name string
	}{
		{FeatureEncrypt, "encrypt"},
		{FeatureBlkZoned, "blkzoned"},
		{FeatureAtomicWrite, "atomic-write"},
		{FeatureExtraAttr, "extra-attr"},
		{FeaturePrjQuota, "prjquota"},
		{FeatureInodeChecksum, "inode-checksum"},
		{FeatureFlexibleInlineXA, "flexible-inline-xattr"},
		{FeatureQuotaIno, "quota-ino"},
		{FeatureInodeCrtime, "inode-crtime"},
		{FeatureLostFound, "lost-found"},
		{FeatureVerity, "verity"},
		{FeatureSBChecksum, "sb-checksum"},
		{FeatureCasefold, "casefold"},
		{FeatureCompression, "compression"},
		{FeatureRO, "read-only"},
		{FeatureDeviceAlias, "device-alias"},
		{FeaturePackedSSA, "packed-ssa"},
	}
	out := make([]string, 0, len(names))
	for _, entry := range names {
		if s.Feature&entry.bit != 0 {
			out = append(out, entry.name)
		}
	}
	return out
}

func readLabel(bytes []byte) string {
	units := make([]uint16, 0, len(bytes)/2)
	for i := 0; i+2 <= len(bytes); i += 2 {
		unit := uint16(bytes[i]) | uint16(bytes[i+1])<<8
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units))
}
