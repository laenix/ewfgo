package filesystem

import (
	"fmt"
)

// FileSystemType represents the type of filesystem
type FileSystemType string

const (
	FS_NTFS       FileSystemType = "NTFS"
	FS_EXT2       FileSystemType = "ext2"
	FS_EXT3       FileSystemType = "ext3"
	FS_EXT4       FileSystemType = "ext4"
	FS_FAT12      FileSystemType = "FAT12"
	FS_FAT16      FileSystemType = "FAT16"
	FS_FAT32      FileSystemType = "FAT32"
	FS_EXFAT      FileSystemType = "exFAT"
	FS_HFS        FileSystemType = "HFS+"
	FS_APFS       FileSystemType = "APFS"
	FS_BTRFS      FileSystemType = "Btrfs"
	FS_XFS        FileSystemType = "XFS"
	FS_F2FS       FileSystemType = "F2FS"
	FS_SQUASHFS   FileSystemType = "SquashFS"
	FS_REFS       FileSystemType = "ReFS"
	FS_BITLOCKER  FileSystemType = "BitLocker"
	FS_LUKS       FileSystemType = "LUKS"
	FS_ZFS        FileSystemType = "ZFS"
	FS_RAID       FileSystemType = "RAID"
	FS_JFS        FileSystemType = "JFS"
	FS_UFS        FileSystemType = "UFS"
	FS_UNKNOWN    FileSystemType = "Unknown"
)

// FileMode represents file/directory permissions
type FileMode uint16

const (
	ModeDir       FileMode = 0x4000
	ModeRegular   FileMode = 0x8000
	ModeSymlink   FileMode = 0xA000
	ModeCharacter FileMode = 0x2000
	ModeBlock     FileMode = 0x6000
	ModeFIFO      FileMode = 0x1000
	ModeSocket    FileMode = 0xC000
)

// FileInfo contains metadata about a file or directory
type FileInfo struct {
	Name       string
	Path       string
	Size       uint64
	Mode       FileMode
	IsDir      bool
	ModTime    int64
	AccessTime int64
	CreateTime int64
	IsHidden   bool
	IsSystem   bool
	IsReadOnly bool
}

// DirectoryEntry represents an entry in a directory
type DirectoryEntry struct {
	Name     string
	Path     string
	Size     uint64
	IsDir    bool
	ModTime  int64
	// For FAT32: cluster number for subdirectory
	Cluster uint32
}

// FileSystem is the interface that must be implemented by filesystem handlers
type FileSystem interface {
	Type() FileSystemType
	Open(sectorData []byte) error
	Close() error
	ListDirectory(path string) ([]DirectoryEntry, error)
	GetFile(path string) ([]byte, error)
	GetFileByPath(path string) (*FileInfo, error)
	SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error)
	GetVolumeLabel() string
}

// DetectFileSystem detects the filesystem type from boot sector
func DetectFileSystem(sectorData []byte) FileSystemType {
	if len(sectorData) < 512 {
		return FS_UNKNOWN
	}

	// Check NTFS
	if string(sectorData[3:7]) == "NTFS" {
		return FS_NTFS
	}

	// Check FAT32
	if len(sectorData) >= 0x60 && string(sectorData[0x52:0x58]) == "FAT32" {
		return FS_FAT32
	}

	// Check FAT12/16
	if len(sectorData) >= 0x40 {
		if string(sectorData[0x36:0x3B]) == "MSDOS" || string(sectorData[0x36:0x3A]) == "FAT16" {
			return FS_FAT16
		}
	}

	// Check exFAT
	if len(sectorData) >= 11 && string(sectorData[3:11]) == "EXFAT   " {
		return FS_EXFAT
	}

	// Check HFS+
	if len(sectorData) >= 0x402 && string(sectorData[0x400:0x402]) == "H+" {
		return FS_HFS
	}

	// Check XFS (magic "XFSB" at various offsets)
	// Try offset 0, 512, 1024, 2048
	for _, offset := range []int{0, 512, 1024, 2048, 4096} {
		if len(sectorData) >= offset+4 && string(sectorData[offset:offset+4]) == "XFSB" {
			// Additional validation: check if superblock fields are reasonable
			// A real XFS superblock should have:
			// - blocksize: power of 2, between 512 and 65536
			// - blocks: > 0
			// - agcount: reasonable (typically 1-100)
			// - agblocks: reasonable (typically 1000-100000)
			if len(sectorData) >= offset+512 {
				blocksize := uint32(sectorData[offset+4])<<24 | uint32(sectorData[offset+5])<<16 | 
				              uint32(sectorData[offset+6])<<8 | uint32(sectorData[offset+7])
				blocks := uint32(sectorData[offset+8])<<24 | uint32(sectorData[offset+9])<<16 | 
				         uint32(sectorData[offset+10])<<8 | uint32(sectorData[offset+11])
				agcount := uint32(sectorData[offset+32])<<24 | uint32(sectorData[offset+33])<<16 | 
				           uint32(sectorData[offset+34])<<8 | uint32(sectorData[offset+35])
				agblocks := uint32(sectorData[offset+36])<<24 | uint32(sectorData[offset+37])<<16 | 
				            uint32(sectorData[offset+38])<<8 | uint32(sectorData[offset+39])
				
				// Validate: blocksize should be power of 2 between 512-65536
				validBlocksize := blocksize >= 512 && blocksize <= 65536 && (blocksize&(blocksize-1)) == 0
				// blocks should be > 0
				validBlocks := blocks > 0
				// agcount should be reasonable (1-100)
				validAGCount := agcount > 0 && agcount <= 100
				// agblocks should be reasonable
				validAGBlocks := agblocks > 100 && agblocks < 100000
				
				if validBlocksize && validBlocks && validAGCount && validAGBlocks {
					return FS_XFS
				} else {
					// XFSB magic found but fields invalid - might be fake or corrupted
					fmt.Printf("[FS] Warning: XFSB magic found but superblock fields invalid (blocksize=%d blocks=%d agcount=%d agblocks=%d)\n",
						blocksize, blocks, agcount, agblocks)
				}
			}
			// If we can't validate, still return XFS (backward compatibility)
			return FS_XFS
		}
	}

	// Check ext2/3/4 (magic at offset 0x438 in the superblock)
	// Superblock is typically at:
	// - Offset 1024 (0x400) for 1KB block filesystems
	// - Offset 2048 (0x800) for 2KB block filesystems  
	// - etc.
	// Magic (0xEF53) is at offset 0x38 within the superblock
	for _, sbOffset := range []int{1024, 2048, 4096} {
		if len(sectorData) >= sbOffset+0x440 {
			magic := uint16(sectorData[sbOffset+0x438]) | uint16(sectorData[sbOffset+0x439])<<8
			if magic == 0xEF53 {
				return FS_EXT4
			}
		}
	}

	// Check Btrfs (magic "BTRFS" or "_BHRf" at offset 0x40)
	for _, offset := range []int{64, 1024, 2048} {
		if len(sectorData) >= offset+8 {
			if string(sectorData[offset:offset+8]) == "BTRFS" || 
			   string(sectorData[offset:offset+8]) == "_BHRfS_M" {
				return FS_BTRFS
			}
		}
	}

	// Check SquashFS
	if len(sectorData) >= 4 {
		magic := uint32(sectorData[0]) | uint32(sectorData[1])<<8 | uint32(sectorData[2])<<16 | uint32(sectorData[3])<<24
		if magic == 0x68737173 || magic == 0x73717368 { // "sqsh" or "hsqs"
			return FS_SQUASHFS
		}
	}

	// Check F2FS (F2FS at offset 0x400)
	if len(sectorData) >= 1024+4 && string(sectorData[1024:1028]) == "F2FS" {
		return FS_F2FS
	}

	// Check LUKS (magic "LUKS\xba\xbe" at offset 0)
	if len(sectorData) >= 8 && string(sectorData[0:6]) == "LUKS" {
		return FS_LUKS
	}

	// Check ZFS (magic "ZFS" at offset 0x84)
	if len(sectorData) >= 136 && string(sectorData[0x84:0x88]) == "ZFS " {
		return FS_ZFS
	}

	// Check JFS (magic "JFS1" at offset 0x8000)
	if len(sectorData) >= 0x8004 && string(sectorData[0x8000:0x8004]) == "JFS1" {
		return FS_JFS
	}

	return FS_UNKNOWN
}

// DetectFileSystemFromGPT detects filesystem from GPT partition type GUID
func DetectFileSystemFromGPT(partitionTypeGUID string) FileSystemType {
	switch partitionTypeGUID {
	case "6DFD5706ABA4C44384E5933C69E4D7B9":
		return FS_EXT4
	}
	return FS_UNKNOWN
}

// FileSystemRegistry is a registry of available filesystem handlers
var filesystemRegistry = make(map[FileSystemType]func() FileSystem)

// RegisterFileSystem registers a filesystem handler
func RegisterFileSystem(fsType FileSystemType, factory func() FileSystem) {
	filesystemRegistry[fsType] = factory
}

// NewFileSystem creates a new filesystem instance based on type
func NewFileSystem(fsType FileSystemType) (FileSystem, error) {
	factory, ok := filesystemRegistry[fsType]
	if !ok {
		return nil, fmt.Errorf("unsupported filesystem type: %s", fsType)
	}
	return factory(), nil
}

// DetectAndOpen detects filesystem type and opens it with appropriate handler
func DetectAndOpen(sectorData []byte) (FileSystem, error) {
	fsType := DetectFileSystem(sectorData)
	if fsType == FS_UNKNOWN {
		return nil, fmt.Errorf("cannot detect filesystem type")
	}

	fs, err := NewFileSystem(fsType)
	if err != nil {
		return nil, err
	}

	if err := fs.Open(sectorData); err != nil {
		return nil, err
	}

	return fs, nil
}