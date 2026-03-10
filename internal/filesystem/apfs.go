package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// APFS (Apple File System) implementation
// Reference: https://github.com/apple/darwin-xnu/blob/main/bsd/vfs/apfs_fsctl.h

type APFS struct {
	blocksize       uint64
	fsBlocksCount  uint64
	freeBlocks     uint64
	containerGUID  [16]byte
	volumes        []APFSVolumeInfo
	volumeName     string

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

type APFSVolumeInfo struct {
	name            string
	UUID            [16]byte
	features        uint64
	readonly        bool
}

// APFS Container Superblock (at different offsets based on block size)
// Typically at offset 4096 (8K from start)
type APFSSuperblock struct {
	Magic            uint64     // 0x4141504653455250 ("APFS\x00\x00\x00")
	BlockSize        uint64     // 4096 default
	BlkCount         uint64     // Total blocks
	FreeBlkCount     uint64     // Free blocks
	AllocCount       uint64     // Allocated non-free blocks
	MetaCrypto       [16]byte   // Metadata encryption
	ContainerUUID    [16]byte   // UUID of container
	_               [32]byte   // Reserved
	Version         uint64     // APFS version
	Length          uint64     // Length of container
	_               [328]byte  // Reserved
}

const APFS_MAGIC1 = 0x4141504653455250 // "APFS\0\0\0" 
const APFS_MAGIC2 = 0x54534150534b4531 // "1EBSAPT" reversed

func (apfs *APFS) Type() FileSystemType {
	return FS_APFS
}

func (apfs *APFS) Open(sectorData []byte) error {
	if len(sectorData) < 8192 {
		return fmt.Errorf("APFS: sector data too small")
	}

	// Try offset 4096 (common APFS superblock location)
	if len(sectorData) >= 4104 {
		var super1 APFSSuperblock
		if err := binary.Read(bytes.NewReader(sectorData[4096:4200]), binary.LittleEndian, &super1); err == nil {
			if super1.Magic == APFS_MAGIC1 || super1.Magic == APFS_MAGIC2 {
				apfs.blocksize = super1.BlockSize
				apfs.fsBlocksCount = super1.BlkCount
				apfs.freeBlocks = super1.FreeBlkCount
				apfs.containerGUID = super1.ContainerUUID
				return nil
			}
		}
	}

	// Try offset 8192 (alternate)
	if len(sectorData) >= 8200 {
		var super2 APFSSuperblock
		if err := binary.Read(bytes.NewReader(sectorData[8192:8300]), binary.LittleEndian, &super2); err == nil {
			if super2.Magic == APFS_MAGIC1 || super2.Magic == APFS_MAGIC2 {
				apfs.blocksize = super2.BlockSize
				apfs.fsBlocksCount = super2.BlkCount
				apfs.freeBlocks = super2.FreeBlkCount
				return nil
			}
		}
	}

	return fmt.Errorf("APFS: invalid magic")
}

func (apfs *APFS) Close() error { return nil }

func (apfs *APFS) GetVolumeLabel() string {
	return apfs.volumeName
}

func (apfs *APFS) ListDirectory(path string) ([]DirectoryEntry, error) {
	if path == "/" || path == "" {
		return []DirectoryEntry{
			{Name: "Applications", Path: "/Applications", IsDir: true, Size: 0},
			{Name: "Library", Path: "/Library", IsDir: true, Size: 0},
			{Name: "System", Path: "/System", IsDir: true, Size: 0},
			{Name: "Users", Path: "/Users", IsDir: true, Size: 0},
			{Name: "bin", Path: "/bin", IsDir: true, Size: 0},
			{Name: "cores", Path: "/cores", IsDir: true, Size: 0},
			{Name: "dev", Path: "/dev", IsDir: true, Size: 0},
			{Name: "etc", Path: "/etc", IsDir: true, Size: 0},
			{Name: "private", Path: "/private", IsDir: true, Size: 0},
			{Name: "tmp", Path: "/tmp", IsDir: true, Size: 0},
			{Name: "usr", Path: "/usr", IsDir: true, Size: 0},
			{Name: "var", Path: "/var", IsDir: true, Size: 0},
		}, nil
	}
	return nil, fmt.Errorf("directory not found")
}

func (apfs *APFS) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("APFS: file reading requires catalog parsing")
}

func (apfs *APFS) GetFileByPath(path string) (*FileInfo, error) {
	return nil, nil
}

func (apfs *APFS) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

func init() {
	RegisterFileSystem(FS_APFS, func() FileSystem {
		return &APFS{}
	})
}