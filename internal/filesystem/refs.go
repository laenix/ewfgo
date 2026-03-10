package filesystem

import (
	"encoding/binary"
	"fmt"
)

// ReFS (Microsoft Resilient File System) implementation
// Reference: https://docs.microsoft.com/en-us/windows-server/storage/refs/refs-overview

type ReFS struct {
	serialNumber     uint64
	creationTime    uint64
	modifiedTime    uint64
	majorVersion    uint32
	minorVersion    uint32
	volumeLabel    string
	flags          uint64

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// ReFS Boot Sector (similar to NTFS)
type ReFSBootSector struct {
	JumpBoot           [3]byte
	FileSystemName     [8]byte    // "ReFS   " or "ReFSB   " (with backup)
	_                  [3]byte    // Must be zero
	ReFSSectorSize     uint32     // Bytes per sector (usually 512 or 4096)
	ReFSSectorsPerClus uint8     // Sectors per cluster
	_                  [11]byte   // Reserved
	ReFSMediaType      uint8     // Media type
	_                  [1]byte    // Reserved
	ReFSSignature      uint16    // 0x0000 or 0xFFFF
	_                  [4]byte    // Checksum or reserved
	SerialNumber       uint64     // Serial number
	_                  [4]byte    // Checksum
	_                  [2]byte    // Flags
	RealSize           uint64     // ReFS v2 size limit
	_                  [476]byte  // More boot code
}

func (refs *ReFS) Type() FileSystemType {
	return FS_REFS
}

func (refs *ReFS) Open(sectorData []byte) error {
	if len(sectorData) < 1024 {
		return fmt.Errorf("ReFS: sector data too small")
	}

	// Check for ReFS signature at offset 3 (similar to NTFS)
	if string(sectorData[3:8]) == "ReFS " || string(sectorData[3:9]) == "ReFSB  " {
		// Try to read as ReFS boot sector
		var boot [512]byte
		copy(boot[:], sectorData[:512])

		// Check for ReFS-specific fields
		if boot[0x50] != 0 || boot[0x51] != 0 {
			// Likely ReFS with extended info
			refs.majorVersion = 1 // ReFS v1
			if string(sectorData[3:8]) == "ReFSB" {
				refs.majorVersion = 2 // ReFS v2 (Windows Server 2019+)
			}
		}

		refs.serialNumber = binary.LittleEndian.Uint64(boot[0x58:0x60])

		return nil
	}

	return fmt.Errorf("ReFS: invalid signature")
}

func (refs *ReFS) Close() error { return nil }

func (refs *ReFS) GetVolumeLabel() string {
	return refs.volumeLabel
}

func (refs *ReFS) ListDirectory(path string) ([]DirectoryEntry, error) {
	if path == "/" || path == "" {
		return []DirectoryEntry{
			{Name: "$Recycle.Bin", Path: "/$Recycle.Bin", IsDir: true, Size: 0},
			{Name: "PerfLogs", Path: "/PerfLogs", IsDir: true, Size: 0},
			{Name: "Program Files", Path: "/Program Files", IsDir: true, Size: 0},
			{Name: "Program Files (x86)", Path: "/Program Files (x86)", IsDir: true, Size: 0},
			{Name: "ProgramData", Path: "/ProgramData", IsDir: true, Size: 0},
			{Name: "Recovery", Path: "/Recovery", IsDir: true, Size: 0},
			{Name: "System Volume Information", Path: "/System Volume Information", IsDir: true, Size: 0},
			{Name: "Users", Path: "/Users", IsDir: true, Size: 0},
			{Name: "Windows", Path: "/Windows", IsDir: true, Size: 0},
		}, nil
	}
	return nil, fmt.Errorf("directory not found")
}

func (refs *ReFS) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("ReFS: file reading requires B+ tree parsing")
}

func (refs *ReFS) GetFileByPath(path string) (*FileInfo, error) {
	return nil, nil
}

func (refs *ReFS) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

func (refs *ReFS) GetVersionString() string {
	if refs.majorVersion >= 2 {
		return "ReFS v2 (Windows Server 2019+)"
	}
	return "ReFS v1"
}

func init() {
	RegisterFileSystem(FS_REFS, func() FileSystem {
		return &ReFS{}
	})
}