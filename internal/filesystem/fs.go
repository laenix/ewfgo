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

	// Check ext2/3/4
	if len(sectorData) >= 0x400 {
		magic := uint16(sectorData[0x38C]) | uint16(sectorData[0x38D])<<8
		if magic == 0xEF53 {
			return FS_EXT4
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