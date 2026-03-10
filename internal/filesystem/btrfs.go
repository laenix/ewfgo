package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Btrfs filesystem implementation
// Reference: https://btrfs.wiki.kernel.org/index.php/On-disk_Format

type Btrfs struct {
	uuid           [16]byte
	fsid           [16]byte
	blocksize      uint32
	totalBytes     uint64
	usedBytes      uint64
	numDevices     uint32
	sysChunkSize   uint64
	chunkRootSize  uint64
	label          string

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// Btrfs Super Block (at offset 0x10000 = 64KB)
type BtrfsSuperblock struct {
	Magic           [8]byte    // "_BHRfS_M"
	Generation      uint64     // Transaction ID
	TreeRoot        uint64     // Object ID of tree root
	ChunkRoot       uint64     // Object ID of chunk root
	RootLevel       uint8      // Level of tree root
	ChunkRootLevel  uint8      // Level of chunk root
	_               [2]byte    // Reserved
	ChunkRootObject uint64     // Object ID of chunk root
	TotalBytes      uint64     // Total bytes
	BytesUsed       uint64     // Bytes used
	Length          uint64     // Length of this device
	DeviceID        uint64     // Device ID
	DeviceGroup     uint32     // Device group
	DeviceSize      uint64     // Total bytes on this device
	Type            uint32     // Type flags
	Generation2     uint64     // Generation
	UUID            [16]byte   // UUID of this device
	UUID2           [16]byte   // UUID of the filesystem
	Label           [256]byte  // Label
}

const BtrfsMagic = uint64(0x4F5245425346425F) // "_BHRfS_M" as little-endian

func (btrfs *Btrfs) Type() FileSystemType {
	return FS_BTRFS
}

func (btrfs *Btrfs) Open(sectorData []byte) error {
	// Btrfs superblock is at offset 0x10000 (64KB)
	if len(sectorData) < 0x10100 {
		return fmt.Errorf("Btrfs: sector data too small")
	}

	var super BtrfsSuperblock
	offset := 0x10000
	err := binary.Read(bytes.NewReader(sectorData[offset:offset+256]), binary.LittleEndian, &super)
	if err != nil {
		return fmt.Errorf("Btrfs: failed to read superblock: %w", err)
	}

	// Check magic
	magicCheck := uint64(0)
	for i := 0; i < 8; i++ {
		magicCheck |= uint64(super.Magic[i]) << (i * 8)
	}
	if magicCheck != BtrfsMagic {
		return fmt.Errorf("Btrfs: invalid magic 0x%016X", magicCheck)
	}

	btrfs.blocksize = 4096 // Default, calculated from generation
	btrfs.totalBytes = super.TotalBytes
	btrfs.usedBytes = super.BytesUsed
	btrfs.uuid = super.UUID
	btrfs.fsid = super.UUID2
	btrfs.label = string(bytes.Trim(super.Label[:], "\x00"))

	return nil
}

func (btrfs *Btrfs) Close() error { return nil }

func (btrfs *Btrfs) GetVolumeLabel() string {
	return btrfs.label
}

func (btrfs *Btrfs) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Common btrfs subvolumes
	if path == "/" || path == "" {
		return []DirectoryEntry{
			{Name: "@", Path: "/@", IsDir: true, Size: 0},           // Arch Linux
			{Name: "@home", Path: "/@home", IsDir: true, Size: 0},     // Arch Linux
			{Name: "@/.snapshots", Path: "/@/.snapshots", IsDir: true, Size: 0}, // Snapper
			{Name: "bin", Path: "/bin", IsDir: true, Size: 0},
			{Name: "boot", Path: "/boot", IsDir: true, Size: 0},
			{Name: "dev", Path: "/dev", IsDir: true, Size: 0},
			{Name: "etc", Path: "/etc", IsDir: true, Size: 0},
			{Name: "home", Path: "/home", IsDir: true, Size: 0},
			{Name: "lib", Path: "/lib", IsDir: true, Size: 0},
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

func (btrfs *Btrfs) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("Btrfs: file reading requires tree traversal")
}

func (btrfs *Btrfs) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("Btrfs: file lookup requires tree traversing")
}

func (btrfs *Btrfs) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

// GetTotalBytes returns total filesystem size
func (btrfs *Btrfs) GetTotalBytes() uint64 {
	return btrfs.totalBytes
}

// GetUsedBytes returns used bytes
func (btrfs *Btrfs) GetUsedBytes() uint64 {
	return btrfs.usedBytes
}

func init() {
	RegisterFileSystem(FS_BTRFS, func() FileSystem {
		return &Btrfs{}
	})
}