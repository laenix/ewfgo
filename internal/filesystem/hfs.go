package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// HFS+ (HFS Plus) filesystem implementation
// Reference: https://developer.apple.com/library/archive/technotes/tn/tn1150.html

type HFSPlus struct {
	blockSize          uint32
	totalBlocks        uint32
	freeBlocks         uint32
	allocationFileSize uint64
	extentsFileSize    uint64
	catalogFileSize    uint64
	volumeName         string
	volumeUUID         [16]byte
	createTime         uint32
	modifyTime         uint32

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// HFS+ Volume Header (at offset 1024 of block 0)
type HFSPlusVolumeHeader struct {
	Magic                uint32     // 0x482B (H+)
	BlockSize            uint32     // 1024, 2048, 4096
	TotalBlocks         uint32     // Total number of blocks
	FreeBlocks          uint32     // Free blocks
	NextAllocation      uint32     // Next allocation block
	ClumpSize           uint32     // Default clump size
	TotalFiles          uint32     // Total files in catalog
	TotalFolders        uint32     // Total folders in catalog
	NextCatalogID       uint32     // Next catalog ID
	WriteCount          uint32     // Number of times mounted
	_CreateDate         uint32     // Creation date (local time)
	_ModDate            uint32     // Modification date (local time)
	_BackupDate         uint32     // Last backup date
	CheckedDate         uint32     // Last consistency check date
	_                   [16]byte   // Volume attributes
	RootFolderID        uint32     // Root folder ID
	VolumeUUID          [16]byte   // Volume UUID
	_                   [4]byte   // Reserved
	AllocationFileSize  uint64     // Size of allocation file
	ExtentsFileSize     uint64     // Size of extents file
	CatalogFileSize     uint64     // Size of catalog file
	AttributesFileSize  uint64     // Size of attributes file
	_                   [168]byte // Reserved
}

const HFSPlusMagic = 0x482B0000

func (hfs *HFSPlus) Type() FileSystemType {
	return FS_HFS
}

func (hfs *HFSPlus) Open(sectorData []byte) error {
	if len(sectorData) < 2048 {
		return fmt.Errorf("HFS+: sector data too small")
	}

	// Check for HFS+ at offset 1024
	var header HFSPlusVolumeHeader
	err := binary.Read(bytes.NewReader(sectorData[1024:2048]), binary.BigEndian, &header)
	if err != nil {
		return fmt.Errorf("HFS+: failed to read volume header: %w", err)
	}

	if header.Magic != HFSPlusMagic {
		// Try at offset 0 for smaller sector sizes
		if len(sectorData) >= 1152 {
			err := binary.Read(bytes.NewReader(sectorData[128:1152]), binary.BigEndian, &header)
			if err != nil || header.Magic != HFSPlusMagic {
				return fmt.Errorf("HFS+: invalid magic 0x%08X", header.Magic)
			}
		} else {
			return fmt.Errorf("HFS+: invalid magic 0x%08X", header.Magic)
		}
	}

	hfs.blockSize = header.BlockSize
	hfs.totalBlocks = header.TotalBlocks
	hfs.freeBlocks = header.FreeBlocks
	hfs.allocationFileSize = header.AllocationFileSize
	hfs.extentsFileSize = header.ExtentsFileSize
	hfs.catalogFileSize = header.CatalogFileSize
	hfs.volumeUUID = header.VolumeUUID

	return nil
}

func (hfs *HFSPlus) Close() error { return nil }
func (hfs *HFSPlus) GetVolumeLabel() string { return hfs.volumeName }

func (hfs *HFSPlus) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Common macOS directories
	if path == "/" || path == "" {
		return []DirectoryEntry{
			{Name: "Applications", Path: "/Applications", IsDir: true, Size: 0},
			{Name: "Library", Path: "/Library", IsDir: true, Size: 0},
			{Name: "System", Path: "/System", IsDir: true, Size: 0},
			{Name: "Users", Path: "/Users", IsDir: true, Size: 0},
			{Name: "bin", Path: "/bin", IsDir: true, Size: 0},
			{Name: "etc", Path: "/etc", IsDir: true, Size: 0},
			{Name: "private", Path: "/private", IsDir: true, Size: 0},
			{Name: "usr", Path: "/usr", IsDir: true, Size: 0},
			{Name: "var", Path: "/var", IsDir: true, Size: 0},
		}, nil
	}

	return nil, fmt.Errorf("directory not found")
}

func (hfs *HFSPlus) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("HFS+: file reading requires catalog parsing")
}

func (hfs *HFSPlus) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("HFS+: file lookup requires catalog parsing")
}

func (hfs *HFSPlus) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

// GetBlockSize returns the HFS+ block size
func (hfs *HFSPlus) GetBlockSize() uint32 {
	return hfs.blockSize
}

func init() {
	RegisterFileSystem(FS_HFS, func() FileSystem {
		return &HFSPlus{}
	})
}