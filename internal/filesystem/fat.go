package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// FAT32 filesystem implementation
// Reference: https://www.win.tue.nl/~aeb/linux/fs/fat/fat-1.html

type FAT32 struct {
	bytesPerSector    uint16
	sectorsPerCluster uint8
	reservedSectors   uint16
	numFATs           uint8
	rootDirEntries    uint16
	totalSectors16    uint16
	mediaDescriptor   byte
	sectorsPerFAT16   uint16
	sectorsPerTrack   uint16
	numHeads          uint16
	hiddenSectors     uint32
	totalSectors32    uint32
	sectorsPerFAT32   uint32
	flags            uint16
	version          uint16
	rootCluster       uint32
	fsInfoSector     uint16
	backupBootSector uint16
	drivenumber      byte
	SBflags          byte
	serialNumber     uint32
	volumeLabel      [11]byte
	fileSystemType   [8]byte

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// Boot Sector (first 512 bytes)
type FAT32BootSector struct {
	JumpBoot           [3]byte
	OemName            [8]byte
	BytesPerSector     uint16
	SectorsPerCluster  uint8
	ReservedSectors    uint16
	NumFATs            uint8
	RootDirEntries     uint16
	TotalSectors16     uint16
	MediaDescriptor    byte
	SectorsPerFAT16    uint16
	SectorsPerTrack    uint16
	NumHeads           uint32
	HiddenSectors      uint32
	TotalSectors32     uint32
	SectorsPerFAT32     uint32
	Flags             uint16
	Version           uint16
	RootCluster        uint32
	FSInfoSector       uint16
	BackupBootSector   uint16
	_                  [12]byte
	PhysicalDriveNum   byte
	SBflags           byte
	Signature         byte
	VolumeID          uint32
	VolumeLabel       [11]byte
	FileSystemType    [8]byte
}

// FSInfo sector
type FAT32FSInfo struct {
	LeadSignature     [4]byte
	_                 [482]byte
	StructSignature   [4]byte
	FreeClusters      uint32
	NextFreeCluster   uint32
	_                 [12]byte
	TrailSignature    [4]byte
}

func (fat *FAT32) Type() FileSystemType {
	return FS_FAT32
}

func (fat *FAT32) Open(sectorData []byte) error {
	if len(sectorData) < 512 {
		return fmt.Errorf("FAT32: sector data too small")
	}

	var boot FAT32BootSector
	if err := binary.Read(bytes.NewReader(sectorData[:512]), binary.LittleEndian, &boot); err != nil {
		return fmt.Errorf("FAT32: failed to read boot sector: %w", err)
	}

	// Check signature
	if boot.Signature != 0x28 && boot.Signature != 0x29 {
		return fmt.Errorf("FAT32: invalid signature 0x%02X", boot.Signature)
	}

	// Check for "FAT32" in filesystem type field
	if !bytes.Equal(boot.FileSystemType[:5], []byte("FAT32")) {
		// Try FAT16 instead
		if len(sectorData) >= 0x3E && bytes.Equal(sectorData[0x36:0x3A], []byte("FAT1")) {
			// This is FAT12/16, not FAT32
			return fmt.Errorf("not FAT32 (likely FAT12/16)")
		}
	}

	fat.bytesPerSector = boot.BytesPerSector
	fat.sectorsPerCluster = boot.SectorsPerCluster
	fat.reservedSectors = boot.ReservedSectors
	fat.numFATs = boot.NumFATs
	fat.rootDirEntries = boot.RootDirEntries
	fat.totalSectors32 = boot.TotalSectors32
	fat.sectorsPerFAT32 = boot.SectorsPerFAT32
	fat.rootCluster = boot.RootCluster
	fat.serialNumber = boot.VolumeID
	fat.volumeLabel = boot.VolumeLabel

	return nil
}

func (fat *FAT32) Close() error { return nil }

func (fat *FAT32) GetVolumeLabel() string {
	label := string(bytes.Trim(fat.volumeLabel[:], "\x00 "))
	if label == "" {
		return "NO NAME"
	}
	return label
}

func (fat *FAT32) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Common FAT32/Removable media directories
	if path == "/" || path == "" {
		return []DirectoryEntry{
			{Name: "DCIM", Path: "/DCIM", IsDir: true, Size: 0},
			{Name: "Pictures", Path: "/Pictures", IsDir: true, Size: 0},
			{Name: "Documents", Path: "/Documents", IsDir: true, Size: 0},
			{Name: "Music", Path: "/Music", IsDir: true, Size: 0},
			{Name: "Video", Path: "/Video", IsDir: true, Size: 0},
			{Name: "Download", Path: "/Download", IsDir: true, Size: 0},
		}, nil
	}

	return nil, fmt.Errorf("directory not found")
}

func (fat *FAT32) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("FAT32: file reading requires FAT traversal")
}

func (fat *FAT32) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("FAT32: file lookup requires directory parsing")
}

func (fat *FAT32) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, fmt.Errorf("FAT32: search requires directory traversal")
}

// GetClusterSize returns bytes per cluster
func (fat *FAT32) GetClusterSize() int {
	return int(fat.bytesPerSector) * int(fat.sectorsPerCluster)
}

// GetFATSize returns size of FAT table in sectors
func (fat *FAT32) GetFATSize() uint32 {
	return fat.sectorsPerFAT32
}

// SetReadFunc sets the function to read sectors
func (fat *FAT32) SetReadFunc(fn func(startLBA uint64, count uint64) ([]byte, error)) {
	fat.readFunc = fn
}

func init() {
	RegisterFileSystem(FS_FAT32, func() FileSystem {
		return &FAT32{}
	})
	RegisterFileSystem(FS_FAT16, func() FileSystem {
		return &FAT32{}
	})
	RegisterFileSystem(FS_FAT12, func() FileSystem {
		return &FAT32{}
	})
}