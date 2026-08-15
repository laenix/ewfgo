package detect

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// ZFS filesystem detection (read-only support)
// Reference: https://openzfs.github.io/openzfs-docs/docs/developer-resources/zfs-on-disk-format.html

type ZFS struct {
	poolGUID  uint64
	version   uint64
	name      string
	hostname  string
	bootfs    uint64
	encrypted bool

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// ZFS vdev label (at offset 256KB within each vdev)
type ZFSLabel struct {
	_          [128]byte
	BootHeader [256]byte
	NVPair0    [256]byte
	NVPair1    [256]byte
	_          [17408]byte
	Label0     [256000]byte // Contains vdev spec
}

// Detection using pool label
func (zfs *ZFS) Type() filesystem.FileSystemType {
	return filesystem.FS_ZFS
}

func (zfs *ZFS) Open(sectorData []byte) error {
	// ZFS has multiple labels at specific offsets (256KB, 512KB, etc within device)
	// Look for ZFS feature flags in metadata area
	if len(sectorData) < 256*1024 {
		return fmt.Errorf("ZFS: sector data too small for label")
	}

	// Check for ZFS magic in uberblock area (offset ~256KB from start + 128KB)
	// ZFS uses magic "ZBa0f583" in different locations
	// For now, we'll check some common signatur

	// ZFS typically spans entire disk, detected by partition type
	// This is more of a placeholder for future ZFS parsing
	zfs.name = "ZFS Pool"

	return nil
}

func (zfs *ZFS) Close() error { return nil }

func (zfs *ZFS) GetVolumeLabel() string {
	return zfs.name
}

// ListDirectory on the reader-less ZFS stub is an honest error: pool parsing
// requires a reader. Canned entries would fabricate evidence.
func (zfs *ZFS) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	return nil, fmt.Errorf("ZFS: directory parsing not yet implemented")
}

func (zfs *ZFS) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("ZFS: file reading requires pool parsing")
}

func (zfs *ZFS) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	return nil, fmt.Errorf("ZFS: file lookup requires pool parsing")
}

func (zfs *ZFS) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	return nil, fmt.Errorf("ZFS: search requires pool parsing")
}

func init() {
	filesystem.RegisterFileSystem(filesystem.FS_ZFS, func() filesystem.FileSystem {
		return &ZFS{}
	})
}
