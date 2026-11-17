package minix

import (
	"encoding/binary"
	"math/bits"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// superOffset is byte 1024, immediately after the boot block, in every
	// Minix generation.
	superOffset = uint64(1024)
	// superBytes is the on-disk window this reader examines.
	superBytes = 44

	// Magic variants. The low magic selects the directory entry shape:
	// 0x137f/0x2468 are 16-byte entries with 14-byte names,
	// 0x138f/0x2478 are 32-byte entries with 30-byte names, and 0x4d5a is
	// the v3 magic at byte 24 with 64-byte entries and 60-byte names.
	magicV1_14 = 0x137F
	magicV1_30 = 0x138F
	magicV2_14 = 0x2468
	magicV2_30 = 0x2478
	magicV3    = 0x4D5A

	inodeV1Bytes = 32
	inodeV2Bytes = 64

	fixedBlockSize = 1024
	maxLogZoneSize = 8
)

// version is one of the three on-disk generations.
type version uint8

const (
	versionV1 version = iota
	versionV2
	versionV3
)

func (v version) label() string {
	switch v {
	case versionV1:
		return "V1"
	case versionV2:
		return "V2"
	default:
		return "V3"
	}
}

func (v version) inodeSize() int {
	if v == versionV1 {
		return inodeV1Bytes
	}
	return inodeV2Bytes
}

func (v version) pointerSize() int {
	if v == versionV1 {
		return 2
	}
	return 4
}

func (v version) hasTripleIndirect() bool { return v != versionV1 }

// entryShape returns the directory entry size and the name bytes inside one
// entry for a magic.
func (v version) entryShape(magic uint16) (entrySize, nameLen int) {
	switch magic {
	case magicV1_14, magicV2_14:
		return 16, 14
	case magicV1_30, magicV2_30:
		return 32, 30
	case magicV3:
		return 64, 60
	}
	if v == versionV3 {
		return 64, 60
	}
	return 16, 14
}

// superblock is one image's geometry.
type superblock struct {
	version   version
	magic     uint16
	ninodes   uint32
	zones     uint32
	imap      uint16
	zmap      uint16
	firstData uint32
	logZone   uint16
	maxSize   uint32
	state     uint16
	blockSize uint32

	nameLen      int
	dirEntrySize int
	inodeSize    int

	inodeTableBlock  uint32
	inodeTableBlocks uint32
}

func (sb *superblock) zoneSize() uint64 {
	return uint64(sb.blockSize) << sb.logZone
}

func (sb *superblock) pointersPerBlock() uint64 {
	return uint64(sb.blockSize) / uint64(sb.version.pointerSize())
}

// inodeOffset returns the byte offset of a 1-based inode number when it lies
// inside the declared inode table.
func (sb *superblock) inodeOffset(number uint32) (uint64, bool) {
	if number == 0 || number > sb.ninodes {
		return 0, false
	}
	index := uint64(number - 1)
	base := uint64(sb.inodeTableBlock) * uint64(sb.blockSize)
	// Both factors are 32-bit; their product fits in a uint64 comfortably.
	return base + index*uint64(sb.inodeSize), true
}

func (sb *superblock) isDataZone(zone uint32) bool {
	return zone >= sb.firstData && zone < sb.zones
}

func (sb *superblock) zoneOffset(zone uint32) (uint64, bool) {
	offset := uint64(zone) * sb.zoneSize()
	if zone != 0 && offset/sb.zoneSize() != uint64(zone) {
		return 0, false
	}
	return offset, true
}

func versionForMagic(magic uint16) (version, bool) {
	switch magic {
	case magicV1_14, magicV1_30:
		return versionV1, true
	case magicV2_14, magicV2_30:
		return versionV2, true
	case magicV3:
		return versionV3, true
	default:
		return 0, false
	}
}

func le16(bytes []byte, at int) uint16 { return binary.LittleEndian.Uint16(bytes[at:]) }
func le32(bytes []byte, at int) uint32 { return binary.LittleEndian.Uint32(bytes[at:]) }

// detectSuperblock reports whether byte 1024 carries a Minix superblock this
// reader understands. A byte-swapped magic is a Minix signature this reader
// refuses and returns ErrUnsupported. A recognised magic with impossible
// geometry returns true with the read error, because the source is still
// Minix rather than some other format that might claim it.
func detectSuperblock(src source.ByteSource) (bool, error) {
	if src.Len() < superOffset+32 {
		return false, nil
	}
	raw := make([]byte, superBytes)
	if err := source.ReadExactAt(src, superOffset, raw); err != nil {
		return false, err
	}
	magic16 := le16(raw, 16)
	_, known16 := versionForMagic(magic16)
	if known16 || le16(raw, 24) == magicV3 {
		if _, err := parseSuperblock(raw); err != nil {
			return true, err
		}
		return true, nil
	}
	for _, magic := range [2]uint16{magic16, le16(raw, 24)} {
		if _, swapped := versionForMagic(bits.ReverseBytes16(magic)); swapped {
			return false, unsupportedf(
				"a byte-swapped Minix magic %#06x at byte %d; this reader decodes little-endian images only",
				magic, superOffset)
		}
	}
	return false, nil
}

// readSuperblock reads and validates the superblock.
func readSuperblock(src source.ByteSource) (*superblock, error) {
	if src.Len() < superOffset+32 {
		return nil, corruptf("the source holds %d bytes, too short for a Minix superblock at byte %d",
			src.Len(), superOffset)
	}
	raw := make([]byte, superBytes)
	if err := source.ReadExactAt(src, superOffset, raw); err != nil {
		return nil, err
	}
	return parseSuperblock(raw)
}

func parseSuperblock(raw []byte) (*superblock, error) {
	if len(raw) < superBytes {
		return nil, corruptf("the superblock buffer holds %d bytes, shorter than %d", len(raw), superBytes)
	}
	magic16 := le16(raw, 16)
	if version, ok := versionForMagic(magic16); ok && version != versionV3 {
		zones32 := le32(raw, 20)
		nzones := uint32(le16(raw, 2))
		var zones uint32
		switch version {
		case versionV1:
			zones = nzones
			if zones == 0 {
				zones = zones32
			}
		default:
			zones = zones32
			if zones == 0 {
				zones = nzones
			}
		}
		return buildSuperblock(version, magic16,
			uint32(le16(raw, 0)), zones,
			le16(raw, 4), le16(raw, 6),
			uint32(le16(raw, 8)), le16(raw, 10),
			le32(raw, 12), le16(raw, 18), fixedBlockSize)
	}

	magic24 := le16(raw, 24)
	if magic24 == magicV3 {
		return buildSuperblock(versionV3, magic24,
			le32(raw, 0), le32(raw, 20),
			le16(raw, 6), le16(raw, 8),
			uint32(le16(raw, 10)), le16(raw, 12),
			le32(raw, 16), le16(raw, 31), uint32(le16(raw, 28)))
	}

	if _, swapped := versionForMagic(bits.ReverseBytes16(magic16)); swapped {
		return nil, unsupportedf(
			"a byte-swapped Minix magic %#06x at byte %d; this reader decodes little-endian images only",
			bits.ReverseBytes16(magic16), superOffset)
	}
	return nil, corruptf("no Minix magic at byte %d (found %#06x/%#06x)", superOffset, magic16, magic24)
}

func buildSuperblock(v version, magic uint16, ninodes, zones uint32, imap, zmap uint16,
	firstData uint32, logZone uint16, maxSize uint32, state uint16, blockSize uint32) (*superblock, error) {
	if ninodes == 0 {
		return nil, corruptf("the superblock declares zero inodes")
	}
	if zones == 0 {
		return nil, corruptf("the superblock declares zero zones")
	}
	if imap == 0 || zmap == 0 {
		return nil, corruptf("the superblock declares %d inode-bitmap and %d zone-bitmap blocks", imap, zmap)
	}
	if firstData < 3 {
		return nil, corruptf("the first data zone is %d, inside the boot block and superblock", firstData)
	}
	if firstData >= zones {
		return nil, corruptf("the first data zone %d is not below the %d declared zones", firstData, zones)
	}
	if logZone > maxLogZoneSize {
		return nil, unsupportedf("a zone of 2^%d blocks; this reader accepts at most 2^%d",
			logZone, maxLogZoneSize)
	}
	if blockSize == 0 {
		return nil, corruptf("a superblock whose block size is zero")
	}
	switch blockSize {
	case 1024, 2048, 4096:
	default:
		return nil, unsupportedf("a block size of %d; Minix defines 1024, 2048 and 4096", blockSize)
	}

	inodeSize := v.inodeSize()
	entrySize, nameLen := v.entryShape(magic)
	inodeTableBlock := uint32(2) + uint32(imap) + uint32(zmap)
	inodeBytes := uint64(ninodes) * uint64(inodeSize)
	inodeBlocks := (inodeBytes + uint64(blockSize) - 1) / uint64(blockSize)
	if inodeBlocks > 1<<32-1 {
		return nil, corruptf("the inode table block count overflows")
	}
	metadataBlocks := uint64(inodeTableBlock) + inodeBlocks
	firstDataBlock := uint64(firstData) << logZone
	if metadataBlocks > firstDataBlock {
		return nil, corruptf("the inode table ends at block %d, past the first data zone's block %d",
			metadataBlocks, firstDataBlock)
	}

	return &superblock{
		version:          v,
		magic:            magic,
		ninodes:          ninodes,
		zones:            zones,
		imap:             imap,
		zmap:             zmap,
		firstData:        firstData,
		logZone:          logZone,
		maxSize:          maxSize,
		state:            state,
		blockSize:        blockSize,
		nameLen:          nameLen,
		dirEntrySize:     entrySize,
		inodeSize:        inodeSize,
		inodeTableBlock:  inodeTableBlock,
		inodeTableBlocks: uint32(inodeBlocks),
	}, nil
}

// stateLabel renders the valid/error flag the writer recorded.
func stateLabel(state uint16) string {
	switch state {
	case 1:
		return "valid"
	case 2:
		return "marked with errors"
	default:
		return "unknown"
	}
}
