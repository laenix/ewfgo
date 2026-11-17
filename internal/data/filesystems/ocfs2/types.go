package ocfs2

// Fixed OCFS2 geometry. Every numeric field is little-endian.

// SuperBlockBlkno is the filesystem block holding the superblock dinode.
const SuperBlockBlkno = 2

// Signature is the superblock dinode's byte string.
var Signature = []byte("OCFSV2")

// ReversedSignature is the signature with its bytes reversed; such an image
// was written by a byte-swapped (big-endian) host.
var ReversedSignature = []byte("2VSFCO")

// BlockSizes are the four block sizes OCFS2 permits.
var BlockSizes = [4]uint32{512, 1024, 2048, 4096}

const (
	// MinBlockBits and MaxBlockBits bound s_blocksize_bits.
	MinBlockBits uint32 = 9
	MaxBlockBits uint32 = 12
	// MinClusterBits and MaxClusterBits bound s_clustersize_bits.
	MinClusterBits uint32 = 12
	MaxClusterBits uint32 = 20
	// MaxSlots is the largest slot count OCFS2 defines.
	MaxSlots uint16 = 255
)

// Dinode flags.
const (
	// ValidFl marks a live inode.
	ValidFl uint32 = 0x0000_0001
	// OrphanedFl marks an inode with no directory entry.
	OrphanedFl uint32 = 0x0000_0004
	// SystemFl marks a system inode.
	SystemFl uint32 = 0x0000_0010
	// SuperBlockFl marks the superblock dinode.
	SuperBlockFl uint32 = 0x0000_0020
)

// Dynamic inode features (i_dyn_features).
const (
	// InlineDataFl puts the inode's bytes in id2.i_data.
	InlineDataFl uint16 = 0x0001
	// HasXattrFl marks extended attributes.
	HasXattrFl uint16 = 0x0002
	// InlineXattrFl marks inline extended attributes.
	InlineXattrFl uint16 = 0x0004
	// IndexedDirFl marks the indexed dx_root/dx_node/dx_leaf directory.
	IndexedDirFl uint16 = 0x0008
	// HasRefcountFl marks a refcount tree.
	HasRefcountFl uint16 = 0x0010

	KnownDynFeatures = InlineDataFl | HasXattrFl | InlineXattrFl | IndexedDirFl | HasRefcountFl
)

// Incompat feature bits this reader understands.
const (
	FeatureIncompatLocalMount  uint32 = 0x0000_0008
	FeatureIncompatSparseAlloc uint32 = 0x0000_0010
	FeatureIncompatInlineData  uint32 = 0x0000_0040
	FeatureIncompatIndexedDirs uint32 = 0x0000_0400
	FeatureIncompatMetaECC     uint32 = 0x0000_0800

	SupportedIncompat = FeatureIncompatLocalMount | FeatureIncompatSparseAlloc |
		FeatureIncompatInlineData | FeatureIncompatIndexedDirs | FeatureIncompatMetaECC
)

// Offsets inside an inode's id2 union.
const (
	Id2Offset = 0xc0
)

// KindLabel is the filesystem name as facts and listings report it.
const KindLabel = "OCFS2"

// Resource ceilings keep a hostile image from exhausting memory.
const (
	MaxNodes        = 5_000_000
	MaxSymlinkBytes = 64 * 1024
	WarningCap      = 32
)
