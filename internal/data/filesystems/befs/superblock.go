package befs

import (
	"math/bits"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// SuperOffset is the byte offset of the superblock.
const SuperOffset uint64 = 512

// SuperBytes is the size of the superblock on disk.
const SuperBytes uint64 = 512

// Superblock magic values.
const (
	Magic1 uint32 = 0x4246_5331
	Magic2 uint32 = 0xdd12_1031
	Magic3 uint32 = 0x15b6_830e
)

// ByteOrderMarker is the `'BIGE'` byte-order constant as the format defines
// it, not as it appears on a little-endian disk.
const ByteOrderMarker uint32 = 0x4249_4745

// Flags values.
const (
	FlagClean uint32 = 0x434c_454e // 'CLEN'
	FlagDirty uint32 = 0x4449_5254 // 'DIRT'
)

// BlockSizes are the block sizes this reader accepts.
var BlockSizes = [4]uint32{1024, 2048, 4096, 8192}

// MinBlocks is the smallest block count Haiku accepts.
const MinBlocks int64 = 10

// NumDirectBlocks is the number of runs in a data stream's direct array.
const NumDirectBlocks = 12

// InodeFixedBytes is the fixed part of an inode, before its small-data area.
const InodeFixedBytes = 232

// blockRun is a BeFS block run: an allocation group and a range in it.
type blockRun struct {
	allocationGroup int32
	start           uint16
	length          uint16
}

func parseBlockRun(raw []byte) blockRun {
	return blockRun{
		allocationGroup: int32(le32(raw, 0)),
		start:           le16(raw, 4),
		length:          le16(raw, 6),
	}
}

// isZero reports the all-zero run, which means "none".
func (r blockRun) isZero() bool {
	return r.allocationGroup == 0 && r.start == 0 && r.length == 0
}

// toBlock returns the absolute block number `(group << ag_shift) | start`.
func (r blockRun) toBlock(agShift uint32) (uint64, bool) {
	if r.allocationGroup < 0 || agShift >= 64 {
		return 0, false
	}
	group := uint64(r.allocationGroup)
	if group > (^uint64(0))>>agShift {
		return 0, false
	}
	base := group << agShift
	if base > (^uint64(0))-uint64(r.start) {
		return 0, false
	}
	return base + uint64(r.start), true
}

// dataStream is a file's data-stream descriptor.
type dataStream struct {
	direct                 [NumDirectBlocks]blockRun
	maxDirectRange         int64
	indirect               blockRun
	maxIndirectRange       int64
	doubleIndirect         blockRun
	maxDoubleIndirectRange int64
	size                   int64
}

func parseDataStream(raw []byte) dataStream {
	var stream dataStream
	for index := range stream.direct {
		stream.direct[index] = parseBlockRun(raw[index*8 : index*8+8])
	}
	stream.maxDirectRange = int64(le64(raw, 96))
	stream.indirect = parseBlockRun(raw[104:112])
	stream.maxIndirectRange = int64(le64(raw, 112))
	stream.doubleIndirect = parseBlockRun(raw[120:128])
	stream.maxDoubleIndirectRange = int64(le64(raw, 128))
	stream.size = int64(le64(raw, 136))
	return stream
}

// superblock is a parsed BeFS superblock.
type superblock struct {
	name        string
	magic1      uint32
	byteOrder   uint32
	blockSize   uint32
	blockShift  uint32
	numBlocks   int64
	usedBlocks  int64
	inodeSize   uint32
	magic2      uint32
	blocksPerAG int32
	agShift     uint32
	numAGs      int32
	flags       uint32
	logBlocks   blockRun
	logStart    int64
	logEnd      int64
	magic3      uint32
	rootDir     blockRun
	indices     blockRun
}

// agBlocks is the number of blocks in one allocation group.
func (s *superblock) agBlocks() uint64 { return 1 << s.agShift }

// isClean reports whether the volume was cleanly unmounted and its journal is
// empty.
func (s *superblock) isClean() bool { return s.flags == FlagClean && s.logStart == s.logEnd }

// blockOffset is the byte offset of a block; an overflow saturates.
func (s *superblock) blockOffset(block uint64) uint64 {
	size := uint64(s.blockSize)
	if size != 0 && block > (^uint64(0))/size {
		return ^uint64(0)
	}
	return block * size
}

// inodeOffset is the byte offset of an inode block.
func (s *superblock) inodeOffset(block uint64) uint64 { return s.blockOffset(block) }

// isDataBlock reports whether a block number is a data block.
func (s *superblock) isDataBlock(block uint64) bool {
	return block >= 1 && block < uint64(s.numBlocks)
}

// validateRun validates one run and returns its absolute starting block. The
// zero run is (0, false, nil); every other run must lie inside the declared
// allocation groups and block count and must not name block 0.
func (s *superblock) validateRun(run blockRun, what string) (uint64, bool, error) {
	if run.isZero() {
		return 0, false, nil
	}
	if run.allocationGroup < 0 {
		return 0, false, corruptf("%s has negative allocation group %d", what, run.allocationGroup)
	}
	if run.allocationGroup >= s.numAGs {
		return 0, false, corruptf("%s names allocation group %d, but the volume has %d",
			what, run.allocationGroup, s.numAGs)
	}
	if run.length == 0 {
		return 0, false, corruptf("%s has zero length", what)
	}
	start := uint64(run.start)
	length := uint64(run.length)
	if start+length > s.agBlocks() {
		return 0, false, corruptf("%s starts at %d with length %d, past the %d blocks of its allocation group",
			what, start, length, s.agBlocks())
	}
	block, ok := run.toBlock(s.agShift)
	if !ok {
		return 0, false, corruptf("%s overflows the block address space", what)
	}
	if block == 0 {
		return 0, false, corruptf("%s names block 0, the boot block", what)
	}
	end := block + length
	if end < block || end > uint64(s.numBlocks) {
		return 0, false, corruptf("%s ends at block %d, past the %d the superblock declares",
			what, end, s.numBlocks)
	}
	return block, true, nil
}

// detectSuperblock reports whether byte 512 carries a BeFS superblock this
// reader understands. A recognisable but byte-swapped magic is an error by
// name.
func detectSuperblock(src source.ByteSource) (bool, error) {
	if src == nil {
		return false, corruptf("a nil byte source")
	}
	if src.Len() < SuperOffset+36 {
		return false, nil
	}
	raw := make([]byte, 4)
	if err := source.ReadExactAt(src, SuperOffset+32, raw); err != nil {
		return false, err
	}
	value := le32(raw, 0)
	if value == Magic1 {
		if _, err := readSuperblock(src); err != nil {
			return false, err
		}
		return true, nil
	}
	if bits.ReverseBytes32(value) == Magic1 {
		return false, unsupportedf("a byte-swapped (big-endian) BeFS superblock; this reader decodes little-endian images only")
	}
	return false, nil
}

// readSuperblock reads and validates the superblock.
func readSuperblock(src source.ByteSource) (*superblock, error) {
	if src == nil {
		return nil, corruptf("a nil byte source")
	}
	if src.Len() < SuperOffset+SuperBytes {
		return nil, corruptf("the source is %d bytes, too short for a superblock at byte %d", src.Len(), SuperOffset)
	}
	raw := make([]byte, SuperBytes)
	if err := source.ReadExactAt(src, SuperOffset, raw); err != nil {
		return nil, err
	}

	nameEnd := 32
	for index := 0; index < 32; index++ {
		if raw[index] == 0 {
			nameEnd = index
			break
		}
	}
	name := lossyUTF8(raw[:nameEnd])

	magic1 := le32(raw, 32)
	if magic1 != Magic1 {
		if bits.ReverseBytes32(magic1) == Magic1 {
			return nil, unsupportedf("a byte-swapped (big-endian) BeFS superblock; this reader decodes little-endian images only")
		}
		return nil, corruptf("no BeFS superblock magic at byte %d (found %#08x)", SuperOffset, magic1)
	}
	byteOrder := le32(raw, 36)
	if byteOrder != ByteOrderMarker {
		if bits.ReverseBytes32(byteOrder) == ByteOrderMarker {
			return nil, unsupportedf("a big-endian BeFS volume (its 'BIGE' byte-order marker is stored big endian); this reader decodes little-endian images only")
		}
		return nil, unsupportedf("unknown BeFS byte-order marker %#08x", byteOrder)
	}

	sb := &superblock{
		name:        name,
		magic1:      magic1,
		byteOrder:   byteOrder,
		blockSize:   le32(raw, 40),
		blockShift:  le32(raw, 44),
		numBlocks:   int64(le64(raw, 48)),
		usedBlocks:  int64(le64(raw, 56)),
		inodeSize:   le32(raw, 64),
		magic2:      le32(raw, 68),
		blocksPerAG: int32(le32(raw, 72)),
		agShift:     le32(raw, 76),
		numAGs:      int32(le32(raw, 80)),
		flags:       le32(raw, 84),
		logBlocks:   parseBlockRun(raw[88:96]),
		logStart:    int64(le64(raw, 96)),
		logEnd:      int64(le64(raw, 104)),
		magic3:      le32(raw, 112),
		rootDir:     parseBlockRun(raw[116:124]),
		indices:     parseBlockRun(raw[124:132]),
	}
	if sb.magic2 != Magic2 {
		return nil, corruptf("superblock magic 2 is %#08x, expected %#08x", sb.magic2, Magic2)
	}
	if sb.magic3 != Magic3 {
		return nil, corruptf("superblock magic 3 is %#08x, expected %#08x", sb.magic3, Magic3)
	}
	if !containsBlockSize(sb.blockSize) {
		return nil, unsupportedf("block size %d; this reader accepts %d, %d, %d, %d",
			sb.blockSize, BlockSizes[0], BlockSizes[1], BlockSizes[2], BlockSizes[3])
	}
	if sb.blockShift >= 32 || (uint64(1)<<sb.blockShift) != uint64(sb.blockSize) {
		return nil, corruptf("block shift %d does not describe block size %d", sb.blockShift, sb.blockSize)
	}
	if sb.inodeSize != sb.blockSize {
		return nil, corruptf("inode size %d differs from block size %d; BeFS stores one inode per block",
			sb.inodeSize, sb.blockSize)
	}
	if sb.numBlocks < MinBlocks {
		return nil, corruptf("the superblock declares %d blocks, fewer than the minimum %d", sb.numBlocks, MinBlocks)
	}
	if sb.usedBlocks < 0 || sb.usedBlocks > sb.numBlocks {
		return nil, corruptf("used block count %d is outside 0..=%d", sb.usedBlocks, sb.numBlocks)
	}
	if sb.agShift == 0 || sb.agShift > 16 {
		return nil, corruptf("allocation-group shift %d is outside 1..=16", sb.agShift)
	}
	if sb.blocksPerAG < 1 {
		return nil, corruptf("blocks per allocation group %d is not positive", sb.blocksPerAG)
	}
	if sb.numAGs < 1 {
		return nil, corruptf("allocation-group count %d is not positive", sb.numAGs)
	}
	expectedAGs := ceilDiv(uint64(sb.numBlocks), sb.agBlocks())
	if expectedAGs != uint64(sb.numAGs) {
		return nil, corruptf("%d blocks at %d blocks per allocation group need %d groups, but the superblock declares %d",
			sb.numBlocks, sb.agBlocks(), expectedAGs, sb.numAGs)
	}
	if uint64(sb.numBlocks) > (^uint64(0))/uint64(sb.blockSize) {
		return nil, corruptf("the declared block count overflows the byte address space")
	}
	end := uint64(sb.numBlocks) * uint64(sb.blockSize)
	if end > src.Len() {
		return nil, corruptf("the superblock declares %d blocks (%d bytes), but the source is %d bytes",
			sb.numBlocks, end, src.Len())
	}

	if _, ok, err := sb.validateRun(sb.rootDir, "the root directory inode"); err != nil {
		return nil, err
	} else if !ok {
		return nil, corruptf("the superblock names no root directory inode")
	}
	if sb.rootDir.length != 1 {
		return nil, corruptf("the root directory inode run has length %d, expected 1", sb.rootDir.length)
	}
	if !sb.indices.isZero() {
		if _, _, err := sb.validateRun(sb.indices, "the index inode"); err != nil {
			return nil, err
		}
		if sb.indices.length != 1 {
			return nil, corruptf("the index inode run has length %d, expected 1", sb.indices.length)
		}
	}
	return sb, nil
}

func containsBlockSize(size uint32) bool {
	for _, candidate := range BlockSizes {
		if candidate == size {
			return true
		}
	}
	return false
}

func lossyUTF8(raw []byte) string {
	return strings.ToValidUTF8(string(raw), "�")
}

// ---- little-endian readers -------------------------------------------------

func le16(raw []byte, at int) uint16 { return uint16(raw[at]) | uint16(raw[at+1])<<8 }

func le32(raw []byte, at int) uint32 {
	return uint32(raw[at]) |
		uint32(raw[at+1])<<8 |
		uint32(raw[at+2])<<16 |
		uint32(raw[at+3])<<24
}

func le64(raw []byte, at int) uint64 {
	return uint64(le32(raw, at)) | uint64(le32(raw, at+4))<<32
}

func ceilDiv(value, divisor uint64) uint64 {
	if divisor == 0 {
		return 0
	}
	if value%divisor == 0 {
		return value / divisor
	}
	return value/divisor + 1
}
