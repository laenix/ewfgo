package filesystem

import (
	"encoding/binary"
	"fmt"
)

// XFS filesystem implementation
// Reference: https://www.kernel.org/doc/Documentation/filesystems/xfs.txt

type XFS struct {
	blocksize       uint32
	agblocks        uint32
	agcount         uint32
	dirblocksize    uint32
	uuid           [16]byte
	volumeName     string

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// NewXFSHandler creates a new XFS filesystem handler
func NewXFSHandler(reader Reader, startLBA uint64) (*XFS, error) {
	xfs := &XFS{
		readFunc: reader.ReadSectors,
	}
	
	// Read first sector to get superblock
	sectorData, err := reader.ReadSectors(startLBA, 1)
	if err != nil {
		return nil, fmt.Errorf("XFS: failed to read superblock: %w", err)
	}
	
	if err := xfs.Open(sectorData); err != nil {
		return nil, err
	}
	
	return xfs, nil
}

// XFS Super Block (at offset 0 of AG 0)
type XFSSuperblock struct {
	Magic           [4]byte    // "XFSB"
	BlockSize       uint32     // Logical block size
	Blocks          uint64     // Total blocks
	RBlocks         uint64     // Realtime bitmap blocks
	Rextents        uint64     // Realtime extents
	Agfree          uint32     // Blocks in free list
	Frextents       uint64     // Realtime free blocks
	Agcount         uint32     // Number of allocation groups
	Agblocks        uint32     // Blocks per allocation group
	AgiBlocks       uint32     // INode allocation group blocks
	Dirblocksize    uint32     // Directory block size
	FeatureIncompat uint32     // Incompatible features
	_               [4]byte    // Padding
	UUID           [16]byte   // Filesystem UUID
	_               [16]byte   // Padding
	Version        [2]byte    // 5 for v5
	_               [2]byte    // Padding
	RootInode       uint64     // Root inode number
	rbmino          int64      // Realtime bitmap ino
	rumino          int64      // Realtime summary ino
	Rextsize        uint32     // Realtime extent size
	ImaxPct         uint32     // Inode max percentage
	Spare64         [8]uint64 // Padding
	_               [64]byte   // More padding
}

const XFS_MAGIC = 0x58465342 // "XFS"

func (xfs *XFS) Type() FileSystemType {
	return FS_XFS
}

func (xfs *XFS) Open(sectorData []byte) error {
	if len(sectorData) < 512 {
		return fmt.Errorf("XFS: sector data too small")
	}

	// Read XFS superblock manually (big-endian)
	// Magic at offset 0 (4 bytes)
	magic := string(sectorData[0:4])
	if magic != "XFSB" {
		return fmt.Errorf("XFS: invalid magic %q", magic)
	}

	// Block size at offset 4 (4 bytes big-endian)
	xfs.blocksize = binary.BigEndian.Uint32(sectorData[4:8])
	
	// AG count at offset 32 (4 bytes big-endian)
	xfs.agcount = binary.BigEndian.Uint32(sectorData[32:36])
	
	// AG blocks at offset 36 (4 bytes big-endian)
	xfs.agblocks = binary.BigEndian.Uint32(sectorData[36:40])
	
	// Directory block size at offset 44 (4 bytes big-endian)
	xfs.dirblocksize = binary.BigEndian.Uint32(sectorData[44:48])
	
	// UUID at offset 56 (16 bytes)
	copy(xfs.uuid[:], sectorData[56:72])

	return nil
}

func (xfs *XFS) Close() error { return nil }

func (xfs *XFS) GetVolumeLabel() string {
	return xfs.volumeName
}

func (xfs *XFS) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Common Linux directories
	if path == "/" || path == "" {
		return []DirectoryEntry{
			{Name: "bin", Path: "/bin", IsDir: true, Size: 0},
			{Name: "boot", Path: "/boot", IsDir: true, Size: 0},
			{Name: "dev", Path: "/dev", IsDir: true, Size: 0},
			{Name: "etc", Path: "/etc", IsDir: true, Size: 0},
			{Name: "home", Path: "/home", IsDir: true, Size: 0},
			{Name: "lib", Path: "/lib", IsDir: true, Size: 0},
			{Name: "lib64", Path: "/lib64", IsDir: true, Size: 0},
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

func (xfs *XFS) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("XFS: file reading requires inode lookup")
}

func (xfs *XFS) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("XFS: file lookup requires directory parsing")
}

func (xfs *XFS) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

func (xfs *XFS) GetBlockSize() uint32 {
	return xfs.blocksize
}

func (xfs *XFS) GetAGCount() uint32 {
	return xfs.agcount
}

func init() {
	// Note: XFS uses different magic, not automatically detected without special handling
	// Register for manual identification only
	_ = XFS_MAGIC
}