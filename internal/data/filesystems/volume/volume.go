// Package volume opens a formatted volume (a partition or logical volume) from
// a ByteSource. It detects the filesystem from the volume's first sectors and
// constructs the existing reader-based handler through the sector adapter, so
// the filesystem stack runs on the new byte-oriented data plane.
package volume

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/filesystems/adapter"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/filesystem"

	_ "github.com/laenix/ewfgo/internal/filesystem/apfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/btrfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/exfat"
	_ "github.com/laenix/ewfgo/internal/filesystem/ext4"
	_ "github.com/laenix/ewfgo/internal/filesystem/fat"
	_ "github.com/laenix/ewfgo/internal/filesystem/ntfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/xfs"
)

// btrfsDetectionWindow is the largest fixed signature offset the detector
// needs (Btrfs at 64 KiB + 64, plus the magic).
const btrfsDetectionWindow = 0x10048

// Volume is a formatted volume opened over a ByteSource.
type Volume struct {
	Source source.ByteSource
	Type   filesystem.FileSystemType
	FS     filesystem.FileSystem
}

// Detect reads the volume's first sectors and returns the detected filesystem
// type. An unrecognized volume returns FS_UNKNOWN with a nil error.
func Detect(src source.ByteSource) (filesystem.FileSystemType, error) {
	if src.Len() < 512 {
		return filesystem.FS_UNKNOWN, nil
	}
	windowLen := src.Len()
	if windowLen > btrfsDetectionWindow {
		windowLen = btrfsDetectionWindow
	}
	window, err := source.ReadVecAt(src, 0, windowLen)
	if err != nil {
		return filesystem.FS_UNKNOWN, err
	}
	return filesystem.DetectFileSystem(window), nil
}

// Open detects the filesystem and constructs its reader-based handler. The
// volume's own first sector is LBA 0 from the handler's perspective; the
// ByteSource must already be windowed to the volume (a partition SubSource or
// a logical-volume source).
func Open(src source.ByteSource, sectorSize uint32) (*Volume, error) {
	if sectorSize < 512 || sectorSize&(sectorSize-1) != 0 {
		return nil, &source.Error{
			Kind:   source.ErrInvalidArgument,
			Reason: fmt.Sprintf("invalid sector size %d: must be a power of two >= 512", sectorSize),
		}
	}
	fsType, err := Detect(src)
	if err != nil {
		return nil, err
	}
	if fsType == filesystem.FS_UNKNOWN {
		return nil, &source.Error{
			Kind:   source.ErrUnsupported,
			Reason: "filesystem signature is not recognized",
		}
	}
	handler, err := filesystem.NewHandler(fsType, adapter.New(src, sectorSize), 0, src.Len())
	if err != nil {
		return nil, fmt.Errorf("open %s volume: %w", fsType, err)
	}
	return &Volume{Source: src, Type: fsType, FS: handler}, nil
}

// Close releases the filesystem handler.
func (v *Volume) Close() error {
	if v == nil || v.FS == nil {
		return nil
	}
	return v.FS.Close()
}
