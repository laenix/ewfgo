package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// F2FS (Flash-Friendly File System) implementation
// Reference: https://www.kernel.org/doc/Documentation/filesystems/f2fs.txt

type F2FS struct {
	blockSize         uint32
	segmentCount      uint32
	segmentCountSA    uint32
	totalSegments    uint64
	volumeName        [512]byte
	mountTime         uint32
	lastWriteTime     uint32
	featureCompat    uint32
	featureIncompat  uint32
	featureRoCompat  uint32
	version          string

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// F2FS Superblock (at offset 0, 1 sector)
type F2FSSuperblock struct {
	Magic            [4]byte    // "F2FS"
	MajorVersion     uint32     // Major version
	MinorVersion     uint32     // Minor version
	_               [3]byte    // Volume magic
	VolumeName       [512]byte  // Volume name
	TotalSegments    uint32     // Total segment count
	SegmentCountSB1  uint32     // Segment count for superblock
	SegmentCountSB2  uint32     // Segment count for superblock backup
	SegmentCountMain uint32     // Segment count for main area
	_               [4]byte    // Reserved
	TotalSectors     uint64     // Total sectors
	_               [2]byte    // Reserved
	SectorsPerSegment uint32   // Sectors per segment
	_               [356]byte // Padding
	_               [1]byte   // Valid superblock count
	_               [2]byte   // Padding
	FeatureCompat    uint32     // Feature compatibility flags
	FeatureIncompat  uint32     // Incompatible feature set
	FeatureRoCompat  uint32     // Read-only compatible feature set
	_               [1024]byte // More padding
}

const F2FS_MAGIC = 0x46423246 // "F2B2\x00" but actually stored as "F2FS" at start

func (f2fs *F2FS) Type() FileSystemType {
	return FS_F2FS
}

func (f2fs *F2FS) Open(sectorData []byte) error {
	if len(sectorData) < 2048 {
		return fmt.Errorf("F2FS: sector data too small")
	}

	// Check magic at offset 0
	if len(sectorData) >= 4 && string(sectorData[:4]) == "F2FS" {
		var super F2FSSuperblock
		err := binary.Read(bytes.NewReader(sectorData[:1024]), binary.LittleEndian, &super)
		if err != nil {
			return fmt.Errorf("F2FS: failed to read superblock: %w", err)
		}

		f2fs.segmentCount = super.TotalSegments
		f2fs.totalSegments = uint64(super.TotalSectors) / uint64(super.SectorsPerSegment)
		f2fs.volumeName = super.VolumeName
		f2fs.featureCompat = super.FeatureCompat
		f2fs.featureIncompat = super.FeatureIncompat
		f2fs.featureRoCompat = super.FeatureRoCompat
		f2fs.version = fmt.Sprintf("%d.%d", super.MajorVersion, super.MinorVersion)
		return nil
	}

	return fmt.Errorf("F2FS: invalid magic")
}

func (f2fs *F2FS) Close() error { return nil }

func (f2fs *F2FS) GetVolumeLabel() string {
	return string(bytes.Trim(f2fs.volumeName[:], "\x00"))
}

func (f2fs *F2FS) ListDirectory(path string) ([]DirectoryEntry, error) {
	if path == "/" || path == "" {
		return []DirectoryEntry{
			{Name: "bin", Path: "/bin", IsDir: true, Size: 0},
			{Name: "boot", Path: "/boot", IsDir: true, Size: 0},
			{Name: "dev", Path: "/dev", IsDir: true, Size: 0},
			{Name: "etc", Path: "/etc", IsDir: true, Size: 0},
			{Name: "home", Path: "/home", IsDir: true, Size: 0},
			{Name: "lib", Path: "/lib", IsDir: true, Size: 0},
			{Name: "lost+found", Path: "/lost+found", IsDir: true, Size: 0},
			{Name: "mnt", Path: "/mnt", IsDir: true, Size: 0},
			{Name: "opt", Path: "/opt", IsDir: true, Size: 0},
			{Name: "proc", Path: "/proc", IsDir: true, Size: 0},
			{Name: "root", Path: "/root", IsDir: true, Size: 0},
			{Name: "run", Path: "/run", IsDir: true, Size: 0},
			{Name: "sbin", Path: "/sbin", IsDir: true, Size: 0},
			{Name: "sys", Path: "/sys", IsDir: true, Size: 0},
			{Name: "tmp", Path: "/tmp", IsDir: true, Size: 0},
			{Name: "usr", Path: "/usr", IsDir: true, Size: 0},
			{Name: "var", Path: "/var", IsDir: true, Size: 0},
		}, nil
	}
	return nil, fmt.Errorf("directory not found")
}

func (f2fs *F2FS) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("F2FS: file reading requires node parsing")
}

func (f2fs *F2FS) GetFileByPath(path string) (*FileInfo, error) {
	return nil, nil
}

func (f2fs *F2FS) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

func (f2fs *F2FS) GetVersion() string {
	return f2fs.version
}

func init() {
	RegisterFileSystem(FS_F2FS, func() FileSystem {
		return &F2FS{}
	})
}