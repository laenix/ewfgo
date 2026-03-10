package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// exFAT filesystem implementation
// Reference: https://docs.microsoft.com/en-us/windows/win32/fileio/exfat-specification

type EXFAT struct {
	partitionOffset    uint64
	volumeLength       uint64
	fatOffset          uint32
	fatLength          uint32
	clusterHeapOffset  uint32
	clusterCount       uint32
	firstClusterOfRoot uint32
	volumeSerialNumber uint32
	volumeLabel        string

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// exFAT Boot Sector (first 11 sectors, each 512 bytes)
type EXFATBootSector struct {
	JumpBoot           [3]byte
	FileSystemName     [8]byte    // "EXFAT   "
	_                  [53]byte   // Zero
	PartitionOffset   uint64     // Volume offset in sectors
	VolumeLength       uint64     // Volume length in sectors
	FATOffset          uint32     // FAT offset in sectors
	FATLength          uint32     // FAT length in sectors
	ClusterHeapOffset  uint32     // Cluster heap offset in sectors
	ClusterCount       uint32     // Total number of clusters
	FirstClusterOfRoot uint32     // First cluster of root directory
	_                  [8]byte    // Reserved
	VolumeSerialNumber uint32     // Volume serial number
	FileSystemRevision uint16    // File system revision
	VolumeFlags        uint16    // Volume flags
	BytesPerSector     uint8     // Bytes per sector shift
	SectorsPerClusterShift uint8 // Sectors per cluster shift
	NumberOfFats       uint8     // Number of FATs
	_                  [1]byte   // Drive select
	PercentInUse       uint8     // Percent in use
	_                  [7]byte   // Reserved
}

func (exfat *EXFAT) Type() FileSystemType {
	return FS_EXFAT
}

func (exfat *EXFAT) Open(sectorData []byte) error {
	if len(sectorData) < 512 {
		return fmt.Errorf("exFAT: sector data too small")
	}

	// Check signature at offset 0x03
	if string(sectorData[3:11]) != "EXFAT   " {
		return fmt.Errorf("exFAT: invalid signature")
	}

	var boot EXFATBootSector
	if err := binary.Read(bytes.NewReader(sectorData[:512]), binary.LittleEndian, &boot); err != nil {
		return fmt.Errorf("exFAT: failed to read boot sector: %w", err)
	}

	exfat.partitionOffset = boot.PartitionOffset
	exfat.volumeLength = boot.VolumeLength
	exfat.fatOffset = boot.FATOffset
	exfat.fatLength = boot.FATLength
	exfat.clusterHeapOffset = boot.ClusterHeapOffset
	exfat.clusterCount = boot.ClusterCount
	exfat.firstClusterOfRoot = boot.FirstClusterOfRoot
	exfat.volumeSerialNumber = boot.VolumeSerialNumber
	exfat.volumeLabel = "" // Stored in root directory

	return nil
}

func (exfat *EXFAT) Close() error { return nil }
func (exfat *EXFAT) GetVolumeLabel() string { return exfat.volumeLabel }

func (exfat *EXFAT) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Common exFAT directories (on removable media)
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

func (exfat *EXFAT) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("exFAT: file reading requires cluster chain traversal")
}

func (exfat *EXFAT) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("exFAT: file lookup requires directory parsing")
}

func (exfat *EXFAT) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

func (exfat *EXFAT) GetClusterSize() int {
	return 0 // Need to calculate from sector shift
}

func init() {
	RegisterFileSystem(FS_EXFAT, func() FileSystem {
		return &EXFAT{}
	})
}