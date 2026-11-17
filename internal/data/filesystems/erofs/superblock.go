package erofs

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The EROFS superblock, and where in a source it starts.
//
//	   0  magic             u32   0xe0f5e1e2
//	   4  checksum          u32   recorded superblock checksum
//	   8  feature_compat    u32   optional features a reader may ignore
//	  12  blkszbits         u8    log2 of the block size
//	  13  sb_extslots       u8    extra 16-byte superblock slots
//	  14  root_nid          u16   the root directory's node id
//	  16  inos              u64   declared inode count
//	  24  build_time        u64   image build time, Unix seconds
//	  32  build_time_nsec   u32
//	  36  blocks            u32   total image blocks
//	  40  meta_blkaddr      u32   first block of the inode area
//	  44  xattr_blkaddr     u32   shared-xattr block, zero when none
//	  48  uuid              16
//	  64  volume_name       16    zero-padded
//	  80  feature_incompat  u32   features a reader must refuse or honour
//	  84  available_compr_algs u16 compression ids the image may name
//
// The superblock sits at byte 1024. Every block address in an inode is
// relative to the image start. Compatible bits are safe to ignore and only
// reported. An unknown incompatible bit can change what an offset means, so it
// is refused by name, as is the multi-device table.

const (
	magic       uint32 = 0xe0f5_e1e2
	superOffset uint64 = 1024
	superBytes         = 128

	minBlockBits uint8 = 9
	maxBlockBits uint8 = 16

	featureCompatSBChecksum  uint32 = 0x0000_0001
	featureCompatMtime       uint32 = 0x0000_0002
	featureCompatXattrFilter uint32 = 0x0000_0004

	featureIncompatZeroPadding   uint32 = 0x0000_0001
	featureIncompatComprCfgs     uint32 = 0x0000_0002
	featureIncompatBigPcluster   uint32 = 0x0000_0002
	featureIncompatChunkedFile   uint32 = 0x0000_0004
	featureIncompatDeviceTable   uint32 = 0x0000_0008
	featureIncompatZtailpacking  uint32 = 0x0000_0010
	featureIncompatFragments     uint32 = 0x0000_0020
	featureIncompatDedupe        uint32 = 0x0000_0020
	featureIncompatXattrPrefixes uint32 = 0x0000_0040
)

// supportedIncompat is every incompatible feature this reader can walk past.
// Compression and chunk bits do not change an uncompressed inode's layout;
// an inode that uses one is refused when it is read. The device table is
// deliberately absent: a file's data could live on a device this source does
// not hold.
const supportedIncompat uint32 = featureIncompatZeroPadding |
	featureIncompatComprCfgs |
	featureIncompatChunkedFile |
	featureIncompatZtailpacking |
	featureIncompatFragments |
	featureIncompatXattrPrefixes

type superblock struct {
	checksum           uint32
	featureCompat      uint32
	featureIncompat    uint32
	availableComprAlgs uint16
	blockBits          uint8
	extSlots           uint8
	rootNID            uint16
	inos               uint64
	buildTime          uint64
	buildTimeNsec      uint32
	blocks             uint32
	metaBlkaddr        uint32
	xattrBlkaddr       uint32
	uuid               [16]byte
	volumeName         string
}

func (sb superblock) hasCompat(feature uint32) bool   { return sb.featureCompat&feature != 0 }
func (sb superblock) hasIncompat(feature uint32) bool { return sb.featureIncompat&feature != 0 }
func (sb superblock) blockSize() uint64               { return uint64(1) << sb.blockBits }
func (sb superblock) limit() uint64                   { return uint64(sb.blocks) << sb.blockBits }
func (sb superblock) hasMtime() bool                  { return sb.hasCompat(featureCompatMtime) }

// iloc is the byte offset of node nid.
func (sb superblock) iloc(nid uint64) (uint64, error) {
	if nid > ^uint64(0)>>islotBits {
		return 0, corruptf("node id %d overflows the address space", nid)
	}
	base := uint64(sb.metaBlkaddr) << sb.blockBits
	offset := nid << islotBits
	if base > ^uint64(0)-offset {
		return 0, corruptf("node id %d overflows the address space", nid)
	}
	return base + offset, nil
}

func (sb superblock) hasUUID() bool {
	for _, b := range sb.uuid {
		if b != 0 {
			return true
		}
	}
	return false
}

func (sb superblock) uuidText() string {
	b := sb.uuid
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func compatNames(features uint32) []string {
	var names []string
	for _, pair := range []struct {
		feature uint32
		name    string
	}{
		{featureCompatSBChecksum, "sb_chksum"},
		{featureCompatMtime, "mtime"},
		{featureCompatXattrFilter, "xattr_filter"},
	} {
		if features&pair.feature != 0 {
			names = append(names, pair.name)
		}
	}
	return names
}

func incompatNames(features uint32) []string {
	var names []string
	for _, pair := range []struct {
		feature uint32
		name    string
	}{
		{featureIncompatZeroPadding, "zero_padding"},
		{featureIncompatComprCfgs, "compr_cfgs"},
		{featureIncompatChunkedFile, "chunked_file"},
		{featureIncompatDeviceTable, "device_table"},
		{featureIncompatZtailpacking, "ztailpacking"},
		{featureIncompatFragments, "fragments"},
		{featureIncompatXattrPrefixes, "xattr_prefixes"},
	} {
		if features&pair.feature != 0 {
			names = append(names, pair.name)
		}
	}
	return names
}

// detectSource reports whether byte 1024 carries an EROFS superblock.
func detectSource(src source.ByteSource) (bool, error) {
	if src.Len() < superOffset+4 {
		return false, nil
	}
	var bytes [4]byte
	if err := source.ReadExactAt(src, superOffset, bytes[:]); err != nil {
		return false, err
	}
	return binary.LittleEndian.Uint32(bytes[:]) == magic, nil
}

func readSuperblock(src source.ByteSource) (superblock, error) {
	sourceLen := src.Len()
	if sourceLen < superOffset+superBytes {
		return superblock{}, corruptf(
			"the source holds %d bytes, too short for a superblock at %d",
			sourceLen, superOffset)
	}
	var raw [superBytes]byte
	if err := source.ReadExactAt(src, superOffset, raw[:]); err != nil {
		return superblock{}, err
	}
	gotMagic := binary.LittleEndian.Uint32(raw[0:])
	if gotMagic != magic {
		return superblock{}, corruptf("the magic at %d is %#010x, not %#010x",
			superOffset, gotMagic, magic)
	}

	blockBits := raw[12]
	if blockBits < minBlockBits || blockBits > maxBlockBits {
		var named uint64
		if blockBits < 64 {
			named = uint64(1) << blockBits
		}
		return superblock{}, corruptf(
			"the block size exponent %d names a %d-byte block, outside %d..=%d",
			blockBits, named, minBlockBits, maxBlockBits)
	}
	blocks := binary.LittleEndian.Uint32(raw[36:])
	if blocks == 0 {
		return superblock{}, corruptf("the superblock declares no blocks")
	}
	limit := uint64(blocks) << blockBits
	if limit < superOffset+superBytes {
		return superblock{}, corruptf(
			"the image declares %d bytes, too short for its own superblock", limit)
	}
	if limit > sourceLen {
		return superblock{}, corruptf(
			"the image declares %d bytes but the source holds %d", limit, sourceLen)
	}

	metaBlkaddr := binary.LittleEndian.Uint32(raw[40:])
	if uint64(metaBlkaddr) >= uint64(blocks) {
		return superblock{}, corruptf(
			"the inode area starts at block %d, past the %d-block image",
			metaBlkaddr, blocks)
	}
	rootNID := binary.LittleEndian.Uint16(raw[14:])
	if rootNID == 0 {
		return superblock{}, corruptf("the superblock names no root node")
	}

	featureIncompat := binary.LittleEndian.Uint32(raw[80:])
	if featureIncompat&featureIncompatDeviceTable != 0 {
		return superblock{}, unsupportedf(
			"a multi-device image (feature_incompat bit 0x8): some files' data may " +
				"live on a device this source does not hold")
	}
	if unknown := featureIncompat &^ supportedIncompat; unknown != 0 {
		return superblock{}, unsupportedf(
			"feature_incompat %#010x sets bits %#010x this reader does not know",
			featureIncompat, unknown)
	}

	xattrBlkaddr := binary.LittleEndian.Uint32(raw[44:])
	if xattrBlkaddr != 0 && uint64(xattrBlkaddr) >= uint64(blocks) {
		return superblock{}, corruptf(
			"the shared xattr area starts at block %d, past the %d-block image",
			xattrBlkaddr, blocks)
	}

	var uuid [16]byte
	copy(uuid[:], raw[48:64])
	nameEnd := 16
	for i, b := range raw[64:80] {
		if b == 0 {
			nameEnd = i
			break
		}
	}

	return superblock{
		checksum:           binary.LittleEndian.Uint32(raw[4:]),
		featureCompat:      binary.LittleEndian.Uint32(raw[8:]),
		featureIncompat:    featureIncompat,
		availableComprAlgs: binary.LittleEndian.Uint16(raw[84:]),
		blockBits:          blockBits,
		extSlots:           raw[13],
		rootNID:            rootNID,
		inos:               binary.LittleEndian.Uint64(raw[16:]),
		buildTime:          binary.LittleEndian.Uint64(raw[24:]),
		buildTimeNsec:      binary.LittleEndian.Uint32(raw[32:]),
		blocks:             blocks,
		metaBlkaddr:        metaBlkaddr,
		xattrBlkaddr:       xattrBlkaddr,
		uuid:               uuid,
		volumeName:         strings.ToValidUTF8(string(raw[64:64+nameEnd]), "�"),
	}, nil
}
