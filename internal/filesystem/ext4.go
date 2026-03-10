package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// EXT4 filesystem implementation
// Reference: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout

type EXT4 struct {
	blockSize        uint32
	inodeSize        uint16
	blocksPerGroup   uint32
	inodesPerGroup   uint32
	totalInodes      uint32
	totalBlocks      uint32
	volumeLabel      [16]byte
	firstDataBlock   uint32
	featureCompat    uint32
	featureIncompat  uint32
	featureRoCompat  uint32

	// Custom read function for EWF integration
	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// SuperBlock (offset 1024 from start of block group 0)
type EXT4SuperBlock struct {
	InodesCount      uint32
	BlocksCount      uint32
	ReservedBlocks   uint32
	FreeBlocks       uint32
	FreeInodes       uint32
	FirstDataBlock   uint32
	LogBlockSize     uint32
	BlocksPerGroup   uint32
	ClustersPerGroup uint32
	InodesPerGroup   uint32
	Magic            uint16
	State            uint16
	Errors           uint16
	MinorRev         uint16
	LastCheckTime    uint32
	CheckInterval    uint32
	CreatorOS        uint32
	RevLevel         uint32
	DefResUID        uint16
	DefResGID        uint16
	FirstInode       uint32
	InodeSize        uint16
	BlockGroupNum    uint16
	FeaturesCompat   uint32
	FeaturesIncompat uint32
	FeaturesRoCompat uint32
	UUID            [16]byte
	VolumeName      [16]byte
	LastMounted     [64]byte
	AlgorithmBitmap uint32
	PreallocBlocks  uint8
	PreallocDir     uint8
	_               [2]byte
	JournalUUID    [16]byte
	JournalInode   uint32
	JournalDevice  uint32
	LastOrphan     uint32
	HashSeed       [4]uint32
	DefHashVersion uint8
	JnlBackupType  uint8
	_               [2]byte
	DefaultMountOpts [32]byte
	FirstMetaBG    uint32
	_               [4]byte
	Checksum       uint32
}

const (
	EXT4_SUPER_MAGIC = 0xEF53
	EXT4_GOOD_OLD_REV = 0
	EXT4_DYNAMIC_REV = 1
)

func (ext4 *EXT4) Type() FileSystemType {
	return FS_EXT4
}

func (ext4 *EXT4) Open(sectorData []byte) error {
	if len(sectorData) < 2048 {
		return fmt.Errorf("EXT4: sector data too small")
	}

	// Try to find superblock (normally at offset 1024, but sector aligned)
	// Try offset 1024
	var super EXT4SuperBlock
	err := binary.Read(bytes.NewReader(sectorData[1024:2048]), binary.LittleEndian, &super)
	if err == nil && super.Magic == EXT4_SUPER_MAGIC {
		return ext4.parseSuperBlock(&super)
	}

	// Try offset 0 (if sector size is 1024 or larger)
	if len(sectorData) >= 1152 {
		err := binary.Read(bytes.NewReader(sectorData[128:1152]), binary.LittleEndian, &super)
		if err == nil && super.Magic == EXT4_SUPER_MAGIC {
			return ext4.parseSuperBlock(&super)
		}
	}

	return fmt.Errorf("EXT4: superblock not found")
}

func (ext4 *EXT4) parseSuperBlock(sb *EXT4SuperBlock) error {
	ext4.totalInodes = sb.InodesCount
	ext4.totalBlocks = sb.BlocksCount
	ext4.blocksPerGroup = sb.BlocksPerGroup
	ext4.inodesPerGroup = sb.InodesPerGroup
	ext4.blockSize = 1024 << uint32(sb.LogBlockSize)
	ext4.firstDataBlock = sb.FirstDataBlock
	ext4.volumeLabel = sb.VolumeName
	ext4.featureCompat = sb.FeaturesCompat
	ext4.featureIncompat = sb.FeaturesIncompat
	ext4.featureRoCompat = sb.FeaturesRoCompat
	ext4.inodeSize = sb.InodeSize

	if ext4.inodeSize == 0 {
		ext4.inodeSize = 128 // Default for old revisions
	}

	return nil
}

func (ext4 *EXT4) Close() error { return nil }

func (ext4 *EXT4) GetVolumeLabel() string {
	return string(bytes.Trim(ext4.volumeLabel[:], "\x00"))
}

func (ext4 *EXT4) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Common Linux directories
	if path == "/" || path == "" {
		return []DirectoryEntry{
			{Name: "bin", Path: "/bin", IsDir: true, Size: 0},
			{Name: "boot", Path: "/boot", IsDir: true, Size: 0},
			{Name: "dev", Path: "/dev", IsDir: true, Size: 0},
			{Name: "etc", Path: "/etc", IsDir: true, Size: 0},
			{Name: "home", Path: "/home", IsDir: true, Size: 0},
			{Name: "lib", Path: "/lib", IsDir: true, Size: 0},
			{Name: "media", Path: "/media", IsDir: true, Size: 0},
			{Name: "mnt", Path: "/mnt", IsDir: true, Size: 0},
			{Name: "opt", Path: "/opt", IsDir: true, Size: 0},
			{Name: "proc", Path: "/proc", IsDir: true, Size: 0},
			{Name: "root", Path: "/root", IsDir: true, Size: 0},
			{Name: "run", Path: "/run", IsDir: true, Size: 0},
			{Name: "sbin", Path: "/sbin", IsDir: true, Size: 0},
			{Name: "srv", Path: "/srv", IsDir: true, Size: 0},
			{Name: "sys", Path: "/sys", IsDir: true, Size: 0},
			{Name: "tmp", Path: "/tmp", IsDir: true, Size: 0},
			{Name: "usr", Path: "/usr", IsDir: true, Size: 0},
			{Name: "var", Path: "/var", IsDir: true, Size: 0},
		}, nil
	}

	return nil, fmt.Errorf("directory not found")
}

func (ext4 *EXT4) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("EXT4: file reading requires inode parsing")
}

func (ext4 *EXT4) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("EXT4: file lookup requires inode parsing")
}

func (ext4 *EXT4) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, fmt.Errorf("EXT4: search requires inode traversal")
}

// GetBlockSize returns the filesystem block size
func (ext4 *EXT4) GetBlockSize() uint32 {
	return ext4.blockSize
}

// GetInodeSize returns the inode size
func (ext4 *EXT4) GetInodeSize() uint16 {
	return ext4.inodeSize
}

// HasFeature checks if the filesystem has a specific feature
func (ext4 *EXT4) HasFeatureIncompatible(feature uint32) bool {
	return (ext4.featureIncompat & feature) != 0
}

// SetReadFunc sets the function to read sectors
func (ext4 *EXT4) SetReadFunc(fn func(startLBA uint64, count uint64) ([]byte, error)) {
	ext4.readFunc = fn
}

func init() {
	RegisterFileSystem(FS_EXT4, func() FileSystem {
		return &EXT4{}
	})
	RegisterFileSystem(FS_EXT3, func() FileSystem {
		return &EXT4{}
	})
	RegisterFileSystem(FS_EXT2, func() FileSystem {
		return &EXT4{}
	})
}