package filesystem

import (
	"bytes"
	"fmt"
)

// RAID detection and metadata parsing
// Supports Linux Software RAID (md), Intel Rapid Storage, Windows Storage Spaces

type RAID struct {
	raidType     string
	level        int
	deviceCount  int
	uuid         string
	totalDisks   int
	activeDisks  int
	layout       string
	chunkSize    int

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// Linux RAID superblock (at end of device, version 1.2)
type LinuxRAIDSuperblock struct {
	Magic           [32]byte   // "Linux RAID" or "LINUXR RAID"
	Version         uint8     // Superblock version
	DeviceUuid      [32]byte  // Internal per-device UUID
	CollectUuid     [32]byte  // Shared UUID for collection
	DeviceNumber    uint32    // Device slot number
	DevicePosition  uint32    // Position in array
	State           uint8     // Device state
	raidDisk        uint8     // Persistent raid disk number
	_               [2]byte   // Reserved
	EventsCount     uint64    // Event count
	_               [4]byte   // Reserved
	RecoveryProgress uint64   // Recovery progress (0-100000)
	DeviceSize      uint64    // Total size in 512-byte sectors
	ArrayState      uint8     // Overall array state
	_               [3]byte   // Reserved
}

// Intel RST (Rapid Storage Technology) metadata
type IntelRSTMetadata struct {
	Signature       [14]byte   // "IntelRaidMgmt"
	Version         uint8     
	_               [1]byte    // Reserved
	_               [2]byte    // Padding
	DiskCount       uint8     // Number of disks
	TotalSectors    uint64    // Total sectors
	_               [24]byte  // Reserved
}

// Windows Storage Spaces metadata (at sector 1MB)
type StorageSpacesMetadata struct {
	Signature       [16]byte   // "StorageSpaces"
	Version         uint64     // Version
	_               [8]byte    // Reserved
	PoolGuid        [16]byte   // Pool GUID
	_               [16]byte   // Reserved
	Width           uint32     // Number of columns (data disks)
	PhysicalDisks   uint32     // Physical disk count
	Interleave      uint32     // Interleave
	_               [56]byte  // Reserved
}

const (
	LinuxRaidMagic = "Linux RAID"
)

func (raid *RAID) Type() FileSystemType {
	return FS_RAID
}

func (raid *RAID) Open(sectorData []byte) error {
	if len(sectorData) < 512 {
		return fmt.Errorf("RAID: sector data too small")
	}

	// Check for Linux RAID superblock (at offset 0)
	// Version 1.2 superblock is at offset 16384 (32 sectors) from start
	offset := 32 * 512 // Default for version 1.2
	if len(sectorData) >= offset+512 {
		// Check at standard offset for version 1.2
		if bytes.Contains(sectorData[offset:offset+10], []byte("Linux RAID")) {
			raid.raidType = "Linux RAID (md)"
			return nil
		}
	}

	// Check at alternate offsets
	for _, off := range []int{0, 512, 1024, 2048, 4096} {
		if off+32 <= len(sectorData) {
			testStr := string(bytes.Trim(sectorData[off:off+32], "\x00"))
			if testStr == "Linux RAID" {
				raid.raidType = "Linux RAID (md)"
				return nil
			}
		}
	}

	// Check for Intel RST
	if len(sectorData) >= 14 && string(sectorData[:14]) == "IntelRaidMgmt" {
		raid.raidType = "Intel RST"
		return nil
	}

	// Check for Windows Storage Spaces
	if len(sectorData) >= 16 && string(sectorData[:16]) == "StorageSpaces" {
		raid.raidType = "Windows Storage Spaces"
		return nil
	}

	// Check GPT for RAID partition type
	// This would be detected by GPT partition type GUID
	raid.raidType = "Not detected"
	return nil
}

func (raid *RAID) Close() error { return nil }

func (raid *RAID) GetVolumeLabel() string {
	return raid.raidType
}

// GetRAIDType returns the type of RAID
func (raid *RAID) GetRAIDType() string {
	switch raid.raidType {
	case "Linux RAID (md)":
		return "Linux Software RAID"
	case "Intel RST":
		return "Intel Rapid Storage Technology"
	case "Windows Storage Spaces":
		return "Windows Storage Spaces"
	default:
		return "Generic RAID"
	}
}

// GetLevel returns RAID level (0=linear, 1=mirror, 4,5,6,10 etc)
func (raid *RAID) GetLevel() int {
	return raid.level
}

func (raid *RAID) ListDirectory(path string) ([]DirectoryEntry, error) {
	return nil, fmt.Errorf("RAID: not a filesystem, use disk image instead")
}

func (raid *RAID) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("RAID: not a filesystem")
}

func (raid *RAID) GetFileByPath(path string) (*FileInfo, error) {
	return nil, nil
}

func (raid *RAID) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

func init() {
	RegisterFileSystem(FS_RAID, func() FileSystem {
		return &RAID{}
	})
}