package nilfs2

import (
	"fmt"
	"time"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Offsets inside a NILFS2 superblock.
const (
	revLevelAt          = 0x00
	minorRevLevelAt     = 0x04
	magicAt             = 0x06
	bytesAt             = 0x08
	flagsAt             = 0x0a
	crcSeedAt           = 0x0c
	sumAt               = 0x10
	logBlockSizeAt      = 0x14
	nsegmentsAt         = 0x18
	devSizeAt           = 0x20
	firstDataBlockAt    = 0x28
	blocksPerSegmentAt  = 0x30
	rSegmentsPercentAt  = 0x38
	lastCNOAt           = 0x3c
	lastPsegAt          = 0x44
	lastSeqAt           = 0x4c
	freeBlocksCountAt   = 0x54
	ctimeAt             = 0x5c
	mtimeAt             = 0x64
	wtimeAt             = 0x6c
	mntCountAt          = 0x74
	maxMntCountAt       = 0x7c
	lastcheckAt         = 0x84
	checkintervalAt     = 0x88
	errorsAt            = 0x8c
	firstInoAt          = 0x90
	volumeNameAt        = 0x98
	volumeNameLen       = 80
	uuidAt              = 0xe8
	uuidLen             = 16
	featureCompatAt     = 0xf8
	featureROCompatAt   = 0xfc
	superblockFixedSize = 0x100
)

// Superblock is a parsed NILFS2 superblock. Times are Unix seconds; nil means
// the stored field was zero ("unset", not 1970).
type Superblock struct {
	RevLevel        uint32
	MinorRevLevel   uint32
	Offset          uint64
	SuperblockBytes uint16
	Flags           uint16
	CRCSeed         uint32

	BlockSize    uint32
	LogBlockSize uint32

	NSegments        uint64
	DevSize          uint64
	TotalBlocks      uint64
	VolumeBytes      uint64
	FirstDataBlock   uint64
	BlocksPerSegment uint64
	RSegmentsPercent int32

	LastCNO         uint64
	LastPseg        uint64
	LastSeq         uint64
	FreeBlocksCount uint64
	Ctime           *int64
	Mtime           *int64
	Wtime           *int64
	MntCount        uint64
	MaxMntCount     int64
	Lastcheck       *int64
	Checkinterval   uint32
	Errors          int32
	FirstIno        uint64
	VolumeName      string
	UUID            [16]byte
	FeatureCompat   uint32
	FeatureROCompat uint32

	FromBackup   bool
	BackupStatus string
	SourceBytes  uint64
}

// BlockOffset returns the byte offset of a block.
func (s *Superblock) BlockOffset(block uint64) (uint64, bool) {
	offset := block * uint64(s.BlockSize)
	if block != 0 && offset/block == 0 {
		return 0, false
	}
	return offset, true
}

// ValidateBlock proves one filesystem block number is mapped inside the
// volume. Block zero is the hole sentinel and is never valid data.
func (s *Superblock) ValidateBlock(block uint64, what string) (uint64, error) {
	if block == 0 {
		return 0, corruptf("%s names block 0, which NILFS2 uses as the hole sentinel", what)
	}
	if block >= s.TotalBlocks {
		return 0, corruptf("%s names block %d, out of range for the volume's %d blocks", what, block, s.TotalBlocks)
	}
	offset, ok := s.BlockOffset(block)
	if !ok {
		return 0, corruptf("%s: block %d overflows the address space", what, block)
	}
	end := offset + uint64(s.BlockSize)
	if end < offset {
		return 0, corruptf("%s: block %d overflows the address space", what, block)
	}
	if end > s.SourceBytes {
		return 0, corruptf("%s: block %d ends at byte %d, past the %d bytes the source holds",
			what, block, end, s.SourceBytes)
	}
	return block, nil
}

// UUIDText is the 16-byte UUID as 32 lowercase hexadecimal digits.
func (s *Superblock) UUIDText() string {
	return fmt.Sprintf("%x", s.UUID[:])
}

func (s *Superblock) timeOf(seconds *int64) (time.Time, bool) {
	if seconds == nil {
		return time.Time{}, false
	}
	return time.Unix(*seconds, 0).UTC(), true
}

// timestamp converts a stored second count; zero is "unset".
func timestamp(seconds uint64) (*int64, error) {
	if seconds == 0 {
		return nil, nil
	}
	if seconds > uint64(^uint64(0)>>1) {
		return nil, corruptf("timestamp %d does not fit a signed second count", seconds)
	}
	value := int64(seconds)
	return &value, nil
}

// BackupOffset is the last 4 KiB page boundary strictly before the end of the
// source, when it can hold a second superblock.
func BackupOffset(sourceLen uint64) (uint64, bool) {
	if sourceLen < 2*4096 {
		return 0, false
	}
	pages := sourceLen >> 12
	offset := (pages - 1) << 12
	if offset < SuperBlockOffset+uint64(MinSuperblockBytes) {
		return 0, false
	}
	return offset, true
}

func readWindow(src source.ByteSource, offset uint64) ([]byte, error) {
	if offset >= src.Len() {
		return nil, corruptf("the source is %d bytes, too short for a superblock at byte %d", src.Len(), offset)
	}
	available := src.Len() - offset
	if available > superblockReadWindow {
		available = superblockReadWindow
	}
	bytes := make([]byte, int(available))
	if err := source.ReadExactAt(src, offset, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

func magicWordAt(src source.ByteSource, offset uint64) (*uint16, error) {
	if offset > ^uint64(0)-magicAt {
		return nil, corruptf("the superblock offset overflows")
	}
	at := offset + magicAt
	if at+2 > src.Len() || at+2 < at {
		return nil, nil
	}
	bytes := make([]byte, 2)
	if err := source.ReadExactAt(src, at, bytes); err != nil {
		return nil, err
	}
	value := le16(bytes, 0)
	return &value, nil
}

func readSuperblockAt(src source.ByteSource, offset uint64) (*Superblock, error) {
	bytes, err := readWindow(src, offset)
	if err != nil {
		return nil, err
	}
	if len(bytes) < int(MinSuperblockBytes) {
		return nil, corruptf("the superblock at byte %d has %d bytes, fewer than the %d needed for its fixed fields",
			offset, len(bytes), MinSuperblockBytes)
	}
	if magic := le16(bytes, magicAt); magic != Magic {
		return nil, corruptf("no NILFS2 magic at byte %d; found 0x%04x, expected 0x%04x", offset, magic, Magic)
	}
	revLevel := le32(bytes, revLevelAt)
	if revLevel > MaxRevLevel {
		return nil, unsupportedf("superblock revision %d; this reader decodes revisions through %d", revLevel, MaxRevLevel)
	}
	minorRevLevel := uint32(le16(bytes, minorRevLevelAt))
	if minorRevLevel != 0 {
		return nil, unsupportedf("minor superblock revision %d; this reader decodes revision 0", minorRevLevel)
	}
	declaredBytes := le16(bytes, bytesAt)
	if declaredBytes < MinSuperblockBytes {
		return nil, corruptf("the superblock declares %d bytes, fewer than the %d needed for its fixed fields",
			declaredBytes, MinSuperblockBytes)
	}
	covered := int(declaredBytes)
	if covered > len(bytes) {
		return nil, corruptf("the superblock declares %d checksum bytes but only %d are present", declaredBytes, len(bytes))
	}

	crcSeed := le32(bytes, crcSeedAt)
	storedSum := le32(bytes, sumAt)
	hashed := append([]byte(nil), bytes[:covered]...)
	clear(hashed[sumAt : sumAt+4])
	computedSum := foundation.CRC32Seeded(crcSeed, hashed)
	if computedSum != storedSum {
		return nil, corruptf("the superblock at byte %d checksum is 0x%08x but the %d covered bytes compute 0x%08x",
			offset, storedSum, covered, computedSum)
	}

	logBlockSize := le32(bytes, logBlockSizeAt)
	if logBlockSize < MinLogBlockSize || logBlockSize > MaxLogBlockSize {
		return nil, unsupportedf("log block size %d; this reader accepts %d through %d (1024 through 65536 bytes)",
			logBlockSize, MinLogBlockSize, MaxLogBlockSize)
	}
	blockSize := uint32(1024) << logBlockSize
	if blockSize == 0 {
		return nil, corruptf("the superblock names a zero block size")
	}

	nsegments := le64(bytes, nsegmentsAt)
	devSize := le64(bytes, devSizeAt)
	firstDataBlock := le64(bytes, firstDataBlockAt)
	blocksPerSegment := le64(bytes, blocksPerSegmentAt)
	if devSize == 0 {
		return nil, corruptf("the superblock declares a zero-length device")
	}
	if devSize%uint64(blockSize) != 0 {
		return nil, corruptf("the declared device size %d is not a whole number of %d-byte blocks", devSize, blockSize)
	}
	if blocksPerSegment == 0 || blocksPerSegment&(blocksPerSegment-1) != 0 {
		return nil, corruptf("the superblock declares %d blocks per segment, not a nonzero power of two", blocksPerSegment)
	}
	if nsegments == 0 {
		return nil, corruptf("the superblock declares zero segments")
	}
	segmentBytes := uint64(blockSize) * blocksPerSegment
	if segmentBytes == 0 {
		return nil, corruptf("the segment size overflows")
	}
	expectedNSegments := devSize / segmentBytes
	if nsegments != expectedNSegments {
		return nil, corruptf("the superblock declares %d segments, but %d bytes in %d-block segments make %d",
			nsegments, devSize, blocksPerSegment, expectedNSegments)
	}

	sourceBytes := src.Len()
	usableBytes := devSize
	if sourceBytes < usableBytes {
		usableBytes = sourceBytes
	}
	totalBlocks := usableBytes / uint64(blockSize)
	if totalBlocks == 0 {
		return nil, corruptf("the source holds no whole NILFS2 block")
	}
	volumeBytes := totalBlocks * uint64(blockSize)
	if volumeBytes/uint64(blockSize) != totalBlocks {
		return nil, corruptf("the volume size overflows the byte address space")
	}
	if firstDataBlock >= totalBlocks {
		return nil, corruptf("the first data block %d is outside the volume's %d blocks", firstDataBlock, totalBlocks)
	}

	featureCompat := le32(bytes, featureCompatAt)
	featureROCompat := le32(bytes, featureROCompatAt)
	if featureROCompat != 0 {
		return nil, unsupportedf("read-only feature flags 0x%08x change on-disk layout; this reader decodes none", featureROCompat)
	}

	ctime, err := timestamp(le64(bytes, ctimeAt))
	if err != nil {
		return nil, err
	}
	mtime, err := timestamp(le64(bytes, mtimeAt))
	if err != nil {
		return nil, err
	}
	wtime, err := timestamp(le64(bytes, wtimeAt))
	if err != nil {
		return nil, err
	}
	lastcheck, err := timestamp(le64(bytes, lastcheckAt))
	if err != nil {
		return nil, err
	}

	var uuid [16]byte
	copy(uuid[:], bytes[uuidAt:uuidAt+uuidLen])
	nameField := bytes[volumeNameAt : volumeNameAt+volumeNameLen]
	nameEnd := len(nameField)
	for index, value := range nameField {
		if value == 0 {
			nameEnd = index
			break
		}
	}

	superblock := &Superblock{
		RevLevel:         revLevel,
		MinorRevLevel:    minorRevLevel,
		Offset:           offset,
		SuperblockBytes:  declaredBytes,
		Flags:            le16(bytes, flagsAt),
		CRCSeed:          crcSeed,
		BlockSize:        blockSize,
		LogBlockSize:     logBlockSize,
		NSegments:        nsegments,
		DevSize:          devSize,
		TotalBlocks:      totalBlocks,
		VolumeBytes:      volumeBytes,
		FirstDataBlock:   firstDataBlock,
		BlocksPerSegment: blocksPerSegment,
		RSegmentsPercent: i32le(bytes, rSegmentsPercentAt),
		LastCNO:          le64(bytes, lastCNOAt),
		LastPseg:         le64(bytes, lastPsegAt),
		LastSeq:          le64(bytes, lastSeqAt),
		FreeBlocksCount:  le64(bytes, freeBlocksCountAt),
		Ctime:            ctime,
		Mtime:            mtime,
		Wtime:            wtime,
		MntCount:         le64(bytes, mntCountAt),
		MaxMntCount:      i64le(bytes, maxMntCountAt),
		Lastcheck:        lastcheck,
		Checkinterval:    le32(bytes, checkintervalAt),
		Errors:           i32le(bytes, errorsAt),
		FirstIno:         le64(bytes, firstInoAt),
		VolumeName:       string(nameField[:nameEnd]),
		UUID:             uuid,
		FeatureCompat:    featureCompat,
		FeatureROCompat:  featureROCompat,
		FromBackup:       false,
		BackupStatus:     "absent",
		SourceBytes:      sourceBytes,
	}
	return superblock, nil
}

// Detect reports whether the primary or backup offset carries a NILFS2 magic
// this reader recognises. A matching magic is parsed in full; a bad checksum
// is therefore an error by name rather than a silent non-match.
func Detect(src source.ByteSource) (bool, error) {
	primary, err := magicWordAt(src, SuperBlockOffset)
	if err != nil {
		return false, err
	}
	var backup *uint16
	if offset, ok := BackupOffset(src.Len()); ok {
		backup, err = magicWordAt(src, offset)
		if err != nil {
			return false, err
		}
	}
	primaryMatch := primary != nil && *primary == Magic
	backupMatch := backup != nil && *backup == Magic
	if !primaryMatch && !backupMatch {
		return false, nil
	}
	if _, err := ReadSuperblock(src); err != nil {
		return false, err
	}
	return true, nil
}

// ReadSuperblock reads the primary superblock, falling back to the backup copy
// when the primary is structurally invalid or fails its checksum.
func ReadSuperblock(src source.ByteSource) (*Superblock, error) {
	primaryOffset := SuperBlockOffset
	backup, hasBackup := BackupOffset(src.Len())
	primary, primaryErr := readSuperblockAt(src, primaryOffset)
	if primaryErr == nil {
		primary.FromBackup = false
		switch {
		case hasBackup && backup != primaryOffset:
			copySB, err := readSuperblockAt(src, backup)
			switch {
			case err == nil && copySB.UUID == primary.UUID &&
				copySB.BlockSize == primary.BlockSize &&
				copySB.DevSize == primary.DevSize:
				primary.BackupStatus = "valid"
			case err == nil:
				primary.BackupStatus = "mismatch"
			default:
				primary.BackupStatus = "invalid"
			}
		case hasBackup:
			primary.BackupStatus = "same-offset"
		default:
			primary.BackupStatus = "absent"
		}
		return primary, nil
	}
	if hasBackup && backup != primaryOffset {
		if copySB, err := readSuperblockAt(src, backup); err == nil {
			copySB.FromBackup = true
			copySB.BackupStatus = "valid"
			return copySB, nil
		}
	}
	return nil, primaryErr
}
