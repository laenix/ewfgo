package vmfs

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The volume information sits at byte 0x100000 (1 MiB) and carries the volume
// name and UUID; the filesystem information sits at byte 0x200000 (2 MiB) and
// carries the version, label, UUID, device block size, file-block size,
// sub-block size and the FDC header/bitmap counts.
const (
	volumeInfoOffset uint64 = 0x10_0000
	fsInfoOffset     uint64 = 0x20_0000

	volumeMagic uint32 = 0xC001_D00D
	// reversedVolumeMagic is the magic after its bytes are reversed: a
	// byte-swapped writer.
	reversedVolumeMagic uint32 = 0x0DD0_01C0
	fsMagic             uint32 = 0x2FAB_F15E
	// reversedFSMagic is the filesystem magic after its bytes are reversed.
	reversedFSMagic uint32 = 0x5EF1_AB2F

	volumeInfoLen = 162
	fsInfoLen     = 221

	// fileBlockSize is the only file-block size this reader decodes.
	fileBlockSize uint32 = 1024 * 1024

	versionVMFS5 uint8 = 3
	versionVMFS6 uint8 = 4
)

// superblock is a validated VMFS5 or VMFS6 superblock.
type superblock struct {
	version           uint8
	versionLabel      string
	volumeInfoVersion uint32
	fsVolumeVersion   uint32

	blockSize       uint32
	subblockSize    uint32
	deviceBlockSize uint32
	volumeLabel     string
	volumeName      string
	uuid            [16]byte
	volumeUUID      [16]byte
	mode            uint32
	fdcHeaderSize   uint32
	fdcBitmapCount  uint32
	blocks          uint64
	volumeBytes     uint64

	fdSize             uint32
	metadataHeaderSize uint32
	fileBlockEntries   uint32
	wideBlockAddresses bool
}

func (sb *superblock) blockOffset(block uint64) (uint64, bool) {
	return mulChecked(block, uint64(sb.blockSize))
}

// validateBlock rejects a block number outside the source, and block zero.
func (sb *superblock) validateBlock(block uint64, what string) (uint64, error) {
	if block == 0 {
		return 0, corruptf("%s names block 0, which VMFS reserves", what)
	}
	if block >= sb.blocks {
		return 0, corruptf("%s names block %d, out of range for the source's %d whole %d-byte blocks",
			what, block, sb.blocks, sb.blockSize)
	}
	return block, nil
}

func (sb *superblock) uuidHex() string {
	return hex.EncodeToString(sb.uuid[:])
}

func (sb *superblock) volumeUUIDHex() string {
	return hex.EncodeToString(sb.volumeUUID[:])
}

func le32(b []byte, at int) uint32 { return binary.LittleEndian.Uint32(b[at:]) }
func le64(b []byte, at int) uint64 { return binary.LittleEndian.Uint64(b[at:]) }

// boundedText reads a fixed-width field, bounded at the first NUL. Invalid
// UTF-8 is preserved byte-for-byte rather than replaced.
func boundedText(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Detect reports whether byte 0x100000 carries a VMFS volume this reader
// understands.
//
// A recognisable but byte-swapped image is an error by name, not a silent
// non-match. When the volume magic matches, the filesystem information is read
// and validated before the image is claimed, so a malformed VMFS image is
// reported rather than ignored.
func Detect(src source.ByteSource) (bool, error) {
	if src.Len() < volumeInfoOffset+4 {
		return false, nil
	}
	raw := make([]byte, 4)
	if err := source.ReadExactAt(src, volumeInfoOffset, raw); err != nil {
		return false, err
	}
	magic := le32(raw, 0)
	if magic == reversedVolumeMagic {
		return false, unsupportedf("a byte-swapped VMFS volume information block (the magic bytes are reversed); this reader decodes little-endian images only")
	}
	if magic != volumeMagic {
		return false, nil
	}
	if _, err := readSuperblock(src); err != nil {
		return false, err
	}
	return true, nil
}

// readSuperblock reads and validates the volume and filesystem information.
func readSuperblock(src source.ByteSource) (*superblock, error) {
	if src.Len() < volumeInfoOffset+volumeInfoLen {
		return nil, corruptf("the source is %d bytes, too short for the %d-byte VMFS volume information at byte 0x%x",
			src.Len(), volumeInfoLen, volumeInfoOffset)
	}
	volume := make([]byte, volumeInfoLen)
	if err := source.ReadExactAt(src, volumeInfoOffset, volume); err != nil {
		return nil, err
	}
	magic := le32(volume, 0)
	if magic == reversedVolumeMagic {
		return nil, unsupportedf("a byte-swapped VMFS volume information block (the magic bytes are reversed); this reader decodes little-endian images only")
	}
	if magic != volumeMagic {
		return nil, corruptf("no VMFS volume information magic 0x%08x at byte 0x%x; found 0x%08x",
			volumeMagic, volumeInfoOffset, magic)
	}
	var uuid, volumeUUID [16]byte
	copy(volumeUUID[:], volume[130:146])
	volumeName := boundedText(volume[18:46])
	volumeVersion := le32(volume, 4)

	if src.Len() < fsInfoOffset+fsInfoLen {
		return nil, corruptf("the source is %d bytes, too short for the %d-byte VMFS filesystem information at byte 0x%x",
			src.Len(), fsInfoLen, fsInfoOffset)
	}
	fs := make([]byte, fsInfoLen)
	if err := source.ReadExactAt(src, fsInfoOffset, fs); err != nil {
		return nil, err
	}
	fsMagicRead := le32(fs, 0)
	if fsMagicRead == reversedFSMagic {
		return nil, unsupportedf("a byte-swapped VMFS filesystem information block (the magic bytes are reversed); this reader decodes little-endian images only")
	}
	if fsMagicRead != fsMagic {
		return nil, corruptf("no VMFS filesystem information magic 0x%08x at byte 0x%x; found 0x%08x",
			fsMagic, fsInfoOffset, fsMagicRead)
	}
	copy(uuid[:], fs[9:25])
	version := fs[8]
	fsVolumeVersion := le32(fs, 4)
	mode := le32(fs, 25)
	label := boundedText(fs[29:157])
	deviceBlockSize := le32(fs, 157)
	declaredBlockSize := le64(fs, 161)
	fdcHeaderSize := le32(fs, 209)
	fdcBitmapCount := le32(fs, 213)
	subblockSize := le32(fs, 217)

	var (
		versionLabel       string
		fdSize             uint32
		metadataHeaderSize uint32
		wide               bool
	)
	switch version {
	case 1:
		return nil, unsupportedf("a VMFS3 filesystem (version byte 1); the VMFS3 block and directory layout is not decoded, and this reader decodes VMFS5 and VMFS6 only")
	case 2:
		return nil, unsupportedf("a VMFS4 filesystem (version byte 2); this reader decodes VMFS5 and VMFS6 only")
	case versionVMFS5:
		versionLabel, fdSize, metadataHeaderSize, wide = "VMFS5", 2048, 512, false
	case versionVMFS6:
		versionLabel, fdSize, metadataHeaderSize, wide = "VMFS6", 8192, 4096, true
	default:
		return nil, unsupportedf("filesystem version byte %d; this reader decodes VMFS5 (3) and VMFS6 (4) only", version)
	}

	if declaredBlockSize == 0 {
		return nil, corruptf("the filesystem information declares a zero file-block size")
	}
	if declaredBlockSize > uint64(^uint32(0)) {
		return nil, corruptf("the filesystem information declares a %d-byte file block, which does not fit a 32-bit size", declaredBlockSize)
	}
	blockSize := uint32(declaredBlockSize)
	if blockSize&(blockSize-1) != 0 {
		return nil, corruptf("the filesystem information declares a %d-byte file block, not a power of two", blockSize)
	}
	if blockSize != fileBlockSize {
		return nil, unsupportedf("a %d-byte file block; this reader decodes the %d-byte VMFS5/VMFS6 file blocks only", blockSize, fileBlockSize)
	}
	if subblockSize == 0 || subblockSize&(subblockSize-1) != 0 {
		return nil, corruptf("the filesystem information declares a %d-byte sub-block, which is not a nonzero power of two", subblockSize)
	}
	if subblockSize > blockSize {
		return nil, corruptf("the filesystem information declares a %d-byte sub-block, larger than the %d-byte file block", subblockSize, blockSize)
	}
	if deviceBlockSize == 0 || deviceBlockSize&(deviceBlockSize-1) != 0 {
		return nil, corruptf("the filesystem information declares a %d-byte device block, which is not a nonzero power of two", deviceBlockSize)
	}
	if fdcHeaderSize == 0 {
		return nil, corruptf("the filesystem information declares a zero FDC header size")
	}
	if fdcBitmapCount == 0 {
		return nil, corruptf("the filesystem information declares zero FDC bitmap entries")
	}
	if fsVolumeVersion == 0 {
		return nil, corruptf("the filesystem information declares volume version zero")
	}

	blocks := src.Len() / uint64(blockSize)
	volumeBytes := blocks * uint64(blockSize)
	if blocks == 0 {
		return nil, corruptf("the source is %d bytes, shorter than one %d-byte file block", src.Len(), blockSize)
	}

	volumeLabel := label
	if volumeLabel == "" {
		volumeLabel = volumeName
	}

	return &superblock{
		version:            version,
		versionLabel:       versionLabel,
		volumeInfoVersion:  volumeVersion,
		fsVolumeVersion:    fsVolumeVersion,
		blockSize:          blockSize,
		subblockSize:       subblockSize,
		deviceBlockSize:    deviceBlockSize,
		volumeLabel:        volumeLabel,
		volumeName:         volumeName,
		uuid:               uuid,
		volumeUUID:         volumeUUID,
		mode:               mode,
		fdcHeaderSize:      fdcHeaderSize,
		fdcBitmapCount:     fdcBitmapCount,
		blocks:             blocks,
		volumeBytes:        volumeBytes,
		fdSize:             fdSize,
		metadataHeaderSize: metadataHeaderSize,
		fileBlockEntries:   256,
		wideBlockAddresses: wide,
	}, nil
}
