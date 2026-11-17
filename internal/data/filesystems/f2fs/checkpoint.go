package f2fs

import (
	"sort"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Checkpoint flags, in the order f2fs.h declares them.
const (
	CPUmountFlag         uint32 = 0x00000001
	CPOrphanPresentFlag  uint32 = 0x00000002
	CPCompactSumFlag     uint32 = 0x00000004
	CPErrorFlag          uint32 = 0x00000008
	CPFsckFlag           uint32 = 0x00000010
	CPFastbootFlag       uint32 = 0x00000020
	CPCRCRecoveryFlag    uint32 = 0x00000040
	CPNATBitsFlag        uint32 = 0x00000080
	CPTrimmedFlag        uint32 = 0x00000100
	CPNoCRCRecoveryFlag  uint32 = 0x00000200
	CPLargeNATBitmapFlag uint32 = 0x00000400
	CPQuotaNeedFsckFlag  uint32 = 0x00000800
	CPDisabledFlag       uint32 = 0x00001000
	CPDisabledQuickFlag  uint32 = 0x00002000
	CPResizeFSFlag       uint32 = 0x00004000
)

// Checkpoint layout constants.
const (
	MinChecksumOffset = 192
	BitmapOffset      = MinChecksumOffset
	MaxActiveLogs     = 16
)

// BitmapLayout says which bitmap comes first in the shared byte area.
type BitmapLayout int

const (
	// NatThenSit places the node-address bitmap first.
	NatThenSit BitmapLayout = iota
	// SitThenNat places the segment-info bitmap first.
	SitThenNat
)

// AllBitmapLayouts is every order this reader tries.
var AllBitmapLayouts = [...]BitmapLayout{NatThenSit, SitThenNat}

// Describe names the order for diagnostics.
func (l BitmapLayout) Describe() string {
	if l == SitThenNat {
		return "segment-info bitmap first"
	}
	return "node-address bitmap first"
}

// Checkpoint is a parsed F2FS checkpoint block.
type Checkpoint struct {
	Copy                      int
	Block                     uint32
	ChecksumVerified          bool
	Version                   uint64
	UserBlockCount            uint64
	ValidBlockCount           uint64
	ReservedSegmentCount      uint32
	OverprovisionSegmentCount uint32
	FreeSegmentCount          uint32
	Flags                     uint32
	PackBlockCount            uint32
	PackStartSum              uint32
	ValidNodeCount            uint32
	ValidInodeCount           uint32
	NextFreeNID               uint32
	CurNodeSegno              [8]uint32
	CurNodeBlkoff             [8]uint16
	CurDataSegno              [8]uint32
	CurDataBlkoff             [8]uint16
	AllocType                 [MaxActiveLogs]byte
	SITBitmapSize             uint32
	NATBitmapSize             uint32
	ElapsedTime               uint64

	bitmapArea []byte
}

// ReadCheckpoint reads the newest checkpoint copy that verifies.
func ReadCheckpoint(src source.ByteSource, sb *Superblock) (*Checkpoint, error) {
	copies := sb.SegmentCountCkpt
	if copies > 2 {
		copies = 2
	}
	var packs []*Checkpoint
	var failures []string
	for copyIndex := uint32(0); copyIndex < copies; copyIndex++ {
		block := sb.CPBlkaddr + copyIndex*sb.BlocksPerSegment
		cp, err := readCheckpointBlock(src, sb, block, int(copyIndex))
		if err != nil {
			failures = append(failures, "checkpoint copy "+itoa(int(copyIndex))+": "+err.Error())
			continue
		}
		packs = append(packs, cp)
	}
	if len(packs) == 0 {
		return nil, invalidf("neither checkpoint verified (%s)", joinStrings(failures, "; "))
	}
	sort.Slice(packs, func(i, j int) bool {
		if packs[i].Version != packs[j].Version {
			return packs[i].Version < packs[j].Version
		}
		return packs[i].Copy < packs[j].Copy
	})
	cp := packs[len(packs)-1]
	if err := cp.CheckSupported(sb); err != nil {
		return nil, err
	}
	return cp, nil
}

func readCheckpointBlock(src source.ByteSource, sb *Superblock, block uint32, copyIndex int) (*Checkpoint, error) {
	bytes, err := source.ReadVecAt(src, sb.ByteOffset(block), uint64(sb.BlockSize))
	if err != nil {
		return nil, err
	}
	return ParseCheckpoint(bytes, block, copyIndex, sb)
}

// ParseCheckpoint parses a checkpoint block whose bytes are bytes.
func ParseCheckpoint(bytes []byte, block uint32, copyIndex int, sb *Superblock) (*Checkpoint, error) {
	blockSize := int(sb.BlockSize)
	if len(bytes) < blockSize {
		return nil, invalidf("the checkpoint block is %d bytes, not %d", len(bytes), blockSize)
	}
	bytes = bytes[:blockSize]
	rawOffset, err := u32At(bytes, 164)
	if err != nil {
		return nil, err
	}
	checksumOffset := int(rawOffset)
	if checksumOffset < MinChecksumOffset || checksumOffset > blockSize-4 {
		return nil, invalidf("the checkpoint checksum offset %d is outside %d..=%d",
			checksumOffset, MinChecksumOffset, blockSize-4)
	}
	stored, _ := u32At(bytes, checksumOffset)
	computed := foundation.CRC32Seeded(Magic, bytes[:checksumOffset])
	if stored != computed {
		return nil, invalidf("the checkpoint checksum is %#010x, computed %#010x", stored, computed)
	}
	sitBitmapSize, err := u32At(bytes, 156)
	if err != nil {
		return nil, err
	}
	natBitmapSize, err := u32At(bytes, 160)
	if err != nil {
		return nil, err
	}
	needed := BitmapOffset + int(sitBitmapSize) + int(natBitmapSize)
	if needed > checksumOffset {
		return nil, invalidf("the version bitmaps need %d bytes but the checkpoint protects only %d",
			needed, checksumOffset)
	}
	packBlockCount, err := u32At(bytes, 136)
	if err != nil {
		return nil, err
	}
	if packBlockCount == 0 || packBlockCount > sb.BlocksPerSegment {
		return nil, invalidf("the checkpoint pack claims %d blocks of %d", packBlockCount, sb.BlocksPerSegment)
	}
	packStartSum, err := u32At(bytes, 140)
	if err != nil {
		return nil, err
	}
	if packStartSum == 0 || packStartSum >= packBlockCount {
		return nil, invalidf("the checkpoint's first summary block %d is outside its %d-block pack",
			packStartSum, packBlockCount)
	}
	sitBlocks := uint64(sb.SegmentCountSIT) * uint64(sb.BlocksPerSegment)
	natBlocks := sb.NATBlocks()
	if !bitmapCovers(sitBitmapSize, sitBlocks) {
		return nil, invalidf("the segment-info bitmap of %d bytes cannot describe %d blocks", sitBitmapSize, sitBlocks)
	}
	if !bitmapCovers(natBitmapSize, natBlocks) {
		return nil, invalidf("the node-address bitmap of %d bytes cannot describe %d blocks", natBitmapSize, natBlocks)
	}
	bitmapArea := make([]byte, int(sitBitmapSize)+int(natBitmapSize))
	copy(bitmapArea, bytes[BitmapOffset:BitmapOffset+len(bitmapArea)])
	var curNodeSegno [8]uint32
	var curNodeBlkoff [8]uint16
	var curDataSegno [8]uint32
	var curDataBlkoff [8]uint16
	for index := 0; index < 8; index++ {
		curNodeSegno[index], err = u32At(bytes, 36+index*4)
		if err != nil {
			return nil, err
		}
		curNodeBlkoff[index], err = u16At(bytes, 68+index*2)
		if err != nil {
			return nil, err
		}
		curDataSegno[index], err = u32At(bytes, 84+index*4)
		if err != nil {
			return nil, err
		}
		curDataBlkoff[index], err = u16At(bytes, 116+index*2)
		if err != nil {
			return nil, err
		}
	}
	var allocType [MaxActiveLogs]byte
	copy(allocType[:], bytes[176:176+MaxActiveLogs])
	version, err := u64At(bytes, 0)
	if err != nil {
		return nil, err
	}
	userBlockCount, err := u64At(bytes, 8)
	if err != nil {
		return nil, err
	}
	validBlockCount, err := u64At(bytes, 16)
	if err != nil {
		return nil, err
	}
	reservedSegmentCount, err := u32At(bytes, 24)
	if err != nil {
		return nil, err
	}
	overprovisionSegmentCount, err := u32At(bytes, 28)
	if err != nil {
		return nil, err
	}
	freeSegmentCount, err := u32At(bytes, 32)
	if err != nil {
		return nil, err
	}
	flags, err := u32At(bytes, 132)
	if err != nil {
		return nil, err
	}
	validNodeCount, err := u32At(bytes, 144)
	if err != nil {
		return nil, err
	}
	validInodeCount, err := u32At(bytes, 148)
	if err != nil {
		return nil, err
	}
	nextFreeNID, err := u32At(bytes, 152)
	if err != nil {
		return nil, err
	}
	elapsedTime, err := u64At(bytes, 168)
	if err != nil {
		return nil, err
	}
	return &Checkpoint{
		Copy:                      copyIndex,
		Block:                     block,
		ChecksumVerified:          true,
		Version:                   version,
		UserBlockCount:            userBlockCount,
		ValidBlockCount:           validBlockCount,
		ReservedSegmentCount:      reservedSegmentCount,
		OverprovisionSegmentCount: overprovisionSegmentCount,
		FreeSegmentCount:          freeSegmentCount,
		Flags:                     flags,
		PackBlockCount:            packBlockCount,
		PackStartSum:              packStartSum,
		ValidNodeCount:            validNodeCount,
		ValidInodeCount:           validInodeCount,
		NextFreeNID:               nextFreeNID,
		CurNodeSegno:              curNodeSegno,
		CurNodeBlkoff:             curNodeBlkoff,
		CurDataSegno:              curDataSegno,
		CurDataBlkoff:             curDataBlkoff,
		AllocType:                 allocType,
		SITBitmapSize:             sitBitmapSize,
		NATBitmapSize:             natBitmapSize,
		ElapsedTime:               elapsedTime,
		bitmapArea:                bitmapArea,
	}, nil
}

// CheckSupported refuses a checkpoint this reader cannot mount from.
func (c *Checkpoint) CheckSupported(sb *Superblock) error {
	if c.Flags&CPLargeNATBitmapFlag != 0 {
		return unsupportedf("a large node-address bitmap, whose bitmap sits outside the checkpoint block")
	}
	if c.Flags&(CPDisabledFlag|CPDisabledQuickFlag) != 0 {
		return unsupportedf("a checkpoint marked disabled; the volume was not checkpointed on write")
	}
	if sb.CPPayload != 0 {
		return unsupportedf("%d checkpoint payload block(s), which move the segment-info version bitmap out of the checkpoint block", sb.CPPayload)
	}
	mainBlocks := uint64(sb.SegmentCountMain) * uint64(sb.BlocksPerSegment)
	if c.UserBlockCount > mainBlocks {
		return invalidf("the checkpoint allows %d user blocks but the main area holds %d", c.UserBlockCount, mainBlocks)
	}
	if c.ValidBlockCount > c.UserBlockCount {
		return invalidf("%d valid blocks exceed the %d user blocks", c.ValidBlockCount, c.UserBlockCount)
	}
	if c.NextFreeNID < sb.RootIno {
		return invalidf("the next free node id %d is below the root inode %d", c.NextFreeNID, sb.RootIno)
	}
	return nil
}

// IsClean reports whether the checkpoint marks a clean unmount.
func (c *Checkpoint) IsClean() bool { return c.Flags&CPUmountFlag != 0 }

// HasNodeSummaries reports whether the pack carries node summaries.
func (c *Checkpoint) HasNodeSummaries() bool {
	return c.Flags&(CPUmountFlag|CPFastbootFlag) != 0
}

// HasCompactSummaries reports whether the data summaries use the compacted
// layout.
func (c *Checkpoint) HasCompactSummaries() bool { return c.Flags&CPCompactSumFlag != 0 }

// HadError reports whether the checkpoint recorded a write error.
func (c *Checkpoint) HadError() bool { return c.Flags&CPErrorFlag != 0 }

// SITBitmap returns the segment-info version bitmap as the given layout places
// it.
func (c *Checkpoint) SITBitmap(layout BitmapLayout) []byte {
	size := int(c.SITBitmapSize)
	nat := int(c.NATBitmapSize)
	if layout == SitThenNat {
		return c.bitmapArea[:size]
	}
	return c.bitmapArea[nat : nat+size]
}

// NATBitmap returns the node-address version bitmap as the given layout places
// it.
func (c *Checkpoint) NATBitmap(layout BitmapLayout) []byte {
	size := int(c.SITBitmapSize)
	nat := int(c.NATBitmapSize)
	if layout == NatThenSit {
		return c.bitmapArea[:nat]
	}
	return c.bitmapArea[size : size+nat]
}

func bitmapCovers(bytes uint32, blocks uint64) bool {
	half := blocks / 2
	return uint64(bytes)*8 >= half
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	at := len(buf)
	for value > 0 {
		at--
		buf[at] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[at:])
}

func joinStrings(values []string, sep string) string {
	out := ""
	for index, value := range values {
		if index > 0 {
			out += sep
		}
		out += value
	}
	return out
}
