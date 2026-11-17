package ocfs2

import (
	"fmt"
	"math/bits"

	"github.com/laenix/ewfgo/internal/data/source"
)

// OCFS2's superblock is an ordinary dinode in filesystem block 2. Its first
// bytes are the OCFSV2 signature and the id2 union at 0xc0 holds the volume
// geometry. Because the block size is not known before the superblock is
// found, detection tries the four permitted block sizes and reads the
// signature at 2*size.

// Offsets inside the superblock's id2 union.
const (
	superMajorAt        = Id2Offset + 0x00
	superMinorAt        = Id2Offset + 0x02
	superStateAt        = Id2Offset + 0x08
	superCompatAt       = Id2Offset + 0x1c
	superIncompatAt     = Id2Offset + 0x20
	superROCompatAt     = Id2Offset + 0x24
	superRootBlknoAt    = Id2Offset + 0x28
	superSystemDirAt    = Id2Offset + 0x30
	superBlockShiftAt   = Id2Offset + 0x38
	superClusterShiftAt = Id2Offset + 0x3c
	superMaxSlotsAt     = Id2Offset + 0x40
	superFirstGroupAt   = Id2Offset + 0x48
	superLabelAt        = Id2Offset + 0x50
	superLabelLen       = 64
	superUUIDAt         = Id2Offset + 0x90
	superUUIDLen        = 16
)

// Superblock is a parsed OCFS2 superblock.
type Superblock struct {
	BlockSize         uint32
	BlockShift        uint32
	ClusterSize       uint32
	ClusterShift      uint32
	TotalClusters     uint32
	TotalBlocks       uint64
	VolumeBytes       uint64
	VolumeLabel       string
	UUID              [16]byte
	Major             uint16
	Minor             uint16
	MaxSlots          uint16
	State             uint16
	FeatureCompat     uint32
	FeatureIncompat   uint32
	FeatureROCompat   uint32
	RootBlkno         uint64
	SystemDirBlkno    uint64
	FirstClusterGroup uint64
	FsGeneration      uint32
}

// ClusterBlocks returns how many filesystem blocks one cluster holds.
func (s *Superblock) ClusterBlocks() uint64 {
	if s.BlockSize == 0 {
		return 0
	}
	return uint64(s.ClusterSize / s.BlockSize)
}

// MetaECC reports whether directory blocks carry a DIRTRL1 trailer.
func (s *Superblock) MetaECC() bool { return s.FeatureIncompat&FeatureIncompatMetaECC != 0 }

// SupportsInlineData reports whether the volume permits inline file data.
func (s *Superblock) SupportsInlineData() bool {
	return s.FeatureIncompat&FeatureIncompatInlineData != 0
}

// UUIDText is the 16-byte UUID as 32 lowercase hexadecimal digits.
func (s *Superblock) UUIDText() string { return fmt.Sprintf("%x", s.UUID[:]) }

// BlockOffset returns the byte offset of a block.
func (s *Superblock) BlockOffset(block uint64) (uint64, bool) {
	offset := block * uint64(s.BlockSize)
	if block != 0 && offset/block == 0 {
		return 0, false
	}
	return offset, true
}

// ValidateBlock proves a block number is inside the declared volume.
func (s *Superblock) ValidateBlock(block uint64, what string) (uint64, error) {
	if block == 0 {
		return 0, corruptf("%s names block 0, which OCFS2 reserves", what)
	}
	if block >= s.TotalBlocks {
		return 0, corruptf("%s names block %d, out of range for the volume's %d blocks", what, block, s.TotalBlocks)
	}
	return block, nil
}

func readSignature(src source.ByteSource, at uint64) ([]byte, error) {
	signature := make([]byte, 8)
	if err := source.ReadExactAt(src, at, signature); err != nil {
		return nil, err
	}
	return signature, nil
}

func hasSignature(signature, want []byte) bool {
	return len(signature) >= len(want) && string(signature[:len(want)]) == string(want)
}

// Detect reports whether block 2 carries an OCFS2 superblock this reader
// understands. A recognisable but byte-swapped image is an error by name.
func Detect(src source.ByteSource) (bool, error) {
	for _, blockSize := range BlockSizes {
		at := uint64(blockSize) * SuperBlockBlkno
		if src.Len() < at+8 || at+8 < at {
			continue
		}
		signature, err := readSignature(src, at)
		if err != nil {
			return false, err
		}
		if hasSignature(signature, Signature) {
			if _, err := readWithBlockSize(src, blockSize); err != nil {
				return false, err
			}
			return true, nil
		}
		if hasSignature(signature, ReversedSignature) {
			return false, unsupportedf("a byte-swapped OCFS2 superblock (its signature bytes are reversed); this reader decodes little-endian images only")
		}
	}
	return false, nil
}

// OpenSuperblock reads and validates the superblock, trying each permitted
// block size.
func OpenSuperblock(src source.ByteSource) (*Superblock, error) {
	for _, blockSize := range BlockSizes {
		at := uint64(blockSize) * SuperBlockBlkno
		if src.Len() < at+8 || at+8 < at {
			continue
		}
		signature, err := readSignature(src, at)
		if err != nil {
			return nil, err
		}
		if hasSignature(signature, Signature) {
			return readWithBlockSize(src, blockSize)
		}
		if hasSignature(signature, ReversedSignature) {
			return nil, unsupportedf("a byte-swapped OCFS2 superblock (its signature bytes are reversed); this reader decodes little-endian images only")
		}
	}
	return nil, corruptf("no OCFS2 superblock signature at block %d for block sizes 512, 1024, 2048, 4096",
		SuperBlockBlkno)
}

func readWithBlockSize(src source.ByteSource, blockSize uint32) (*Superblock, error) {
	at := uint64(blockSize) * SuperBlockBlkno
	if src.Len() < at+uint64(blockSize) || at+uint64(blockSize) < at {
		return nil, corruptf("the source is %d bytes, too short for a %d-byte superblock block at block %d",
			src.Len(), blockSize, SuperBlockBlkno)
	}
	bytes := make([]byte, int(blockSize))
	if err := source.ReadExactAt(src, at, bytes); err != nil {
		return nil, err
	}
	if !hasSignature(bytes, Signature) {
		if hasSignature(bytes, ReversedSignature) {
			return nil, unsupportedf("a byte-swapped OCFS2 superblock (its signature bytes are reversed); this reader decodes little-endian images only")
		}
		return nil, corruptf("no OCFS2 superblock signature at block %d (block size %d)", SuperBlockBlkno, blockSize)
	}

	flags := le32(bytes, 0x2c)
	if flags&SuperBlockFl == 0 {
		return nil, corruptf("the dinode at block %d does not carry OCFS2_SUPER_BLOCK_FL (i_flags 0x%08x)",
			SuperBlockBlkno, flags)
	}
	inodeBlock := le64(bytes, 0x50)
	if inodeBlock != SuperBlockBlkno {
		return nil, corruptf("the superblock dinode names itself as block %d, expected %d", inodeBlock, SuperBlockBlkno)
	}

	totalClusters := le32(bytes, 0x14)
	fsGeneration := le32(bytes, 0x60)
	blockShift := le32(bytes, superBlockShiftAt)
	clusterShift := le32(bytes, superClusterShiftAt)

	// A big-endian writer leaves the signature (a byte string) intact but
	// swaps every numeric field; the shifted block size then reads as a huge
	// value whose byte-swapped form is valid and describes the block size that
	// located this dinode.
	if blockShift < MinBlockBits || blockShift > MaxBlockBits {
		swapped := bits.ReverseBytes32(blockShift)
		swappedCluster := bits.ReverseBytes32(clusterShift)
		if swapped >= MinBlockBits && swapped <= MaxBlockBits &&
			uint32(1)<<swapped == blockSize &&
			swappedCluster >= MinClusterBits && swappedCluster <= MaxClusterBits {
			return nil, unsupportedf("a byte-swapped (big-endian) OCFS2 superblock; this reader decodes little-endian images only")
		}
	}
	if blockShift < MinBlockBits || blockShift > MaxBlockBits {
		return nil, unsupportedf("block size bits %d; this reader accepts %d through %d",
			blockShift, MinBlockBits, MaxBlockBits)
	}
	if uint32(1)<<blockShift != blockSize {
		return nil, corruptf("block size bits %d describe %d bytes, not the %d bytes where the superblock was found",
			blockShift, uint32(1)<<blockShift, blockSize)
	}
	if clusterShift < MinClusterBits || clusterShift > MaxClusterBits {
		return nil, unsupportedf("cluster size bits %d; this reader accepts %d through %d",
			clusterShift, MinClusterBits, MaxClusterBits)
	}
	if clusterShift < blockShift {
		return nil, corruptf("cluster size bits %d are smaller than block size bits %d", clusterShift, blockShift)
	}
	clusterSize := uint32(1) << clusterShift

	if totalClusters == 0 {
		return nil, corruptf("the superblock declares no clusters")
	}
	volumeBytes := uint64(totalClusters) * uint64(clusterSize)
	if volumeBytes/uint64(clusterSize) != uint64(totalClusters) {
		return nil, corruptf("the declared cluster count overflows the byte address space")
	}
	if volumeBytes%uint64(blockSize) != 0 {
		return nil, corruptf("the declared volume size %d is not a whole number of %d-byte blocks",
			volumeBytes, blockSize)
	}
	totalBlocks := volumeBytes / uint64(blockSize)
	if totalBlocks <= SuperBlockBlkno {
		return nil, corruptf("the superblock declares %d blocks, too few to hold block %d", totalBlocks, SuperBlockBlkno)
	}
	if volumeBytes > src.Len() {
		return nil, corruptf("the superblock declares %d clusters (%d bytes), but the source is %d bytes",
			totalClusters, volumeBytes, src.Len())
	}

	major := le16(bytes, superMajorAt)
	minor := le16(bytes, superMinorAt)
	state := le16(bytes, superStateAt)
	featureCompat := le32(bytes, superCompatAt)
	featureIncompat := le32(bytes, superIncompatAt)
	featureROCompat := le32(bytes, superROCompatAt)
	rootBlkno := le64(bytes, superRootBlknoAt)
	systemDirBlkno := le64(bytes, superSystemDirAt)
	maxSlots := le16(bytes, superMaxSlotsAt)
	firstClusterGroup := le64(bytes, superFirstGroupAt)

	if unknown := featureIncompat &^ SupportedIncompat; unknown != 0 {
		return nil, unsupportedf("incompat feature bits 0x%08x; this reader decodes only 0x%08x",
			unknown, SupportedIncompat)
	}
	if maxSlots == 0 || maxSlots > MaxSlots {
		return nil, corruptf("slot count %d is outside 1..=%d", maxSlots, MaxSlots)
	}

	labelBytes := bytes[superLabelAt : superLabelAt+superLabelLen]
	labelLen := len(labelBytes)
	for index, value := range labelBytes {
		if value == 0 {
			labelLen = index
			break
		}
	}
	var uuid [16]byte
	copy(uuid[:], bytes[superUUIDAt:superUUIDAt+superUUIDLen])

	superblock := &Superblock{
		BlockSize:         blockSize,
		BlockShift:        blockShift,
		ClusterSize:       clusterSize,
		ClusterShift:      clusterShift,
		TotalClusters:     totalClusters,
		TotalBlocks:       totalBlocks,
		VolumeBytes:       volumeBytes,
		VolumeLabel:       string(labelBytes[:labelLen]),
		UUID:              uuid,
		Major:             major,
		Minor:             minor,
		MaxSlots:          maxSlots,
		State:             state,
		FeatureCompat:     featureCompat,
		FeatureIncompat:   featureIncompat,
		FeatureROCompat:   featureROCompat,
		RootBlkno:         rootBlkno,
		SystemDirBlkno:    systemDirBlkno,
		FirstClusterGroup: firstClusterGroup,
		FsGeneration:      fsGeneration,
	}

	if _, err := superblock.ValidateBlock(rootBlkno, "the root directory inode"); err != nil {
		return nil, err
	}
	if _, err := superblock.ValidateBlock(systemDirBlkno, "the system directory inode"); err != nil {
		return nil, err
	}
	if rootBlkno == SuperBlockBlkno {
		return nil, corruptf("the superblock names itself as the root directory inode")
	}
	if systemDirBlkno == SuperBlockBlkno {
		return nil, corruptf("the superblock names itself as the system directory inode")
	}
	if rootBlkno == systemDirBlkno {
		return nil, corruptf("the root and system directory share inode block %d", rootBlkno)
	}
	if firstClusterGroup != 0 {
		if _, err := superblock.ValidateBlock(firstClusterGroup, "the first cluster group"); err != nil {
			return nil, err
		}
	}
	return superblock, nil
}
