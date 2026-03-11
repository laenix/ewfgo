package ewf

import (
	"github.com/laenix/ewfgo/internal/filesystem"
)

// ListFiles lists files in the specified partition.
// Returns directory entries for the root of the specified partition.
// This is a convenience method that calls ListDirectory with empty path.
func (e *EWFImage) ListFiles(partitionIndex int) ([]filesystem.DirectoryEntry, error) {
	return e.ListDirectory(partitionIndex, "")
}

// ListDirectory lists files in a specific directory path within a partition.
func (e *EWFImage) ListDirectory(partitionIndex int, dirPath string) ([]filesystem.DirectoryEntry, error) {
	parts, err := e.ScanFileSystems()
	if err != nil || len(parts) == 0 {
		return nil, err
	}

	idx := partitionIndex
	if idx < 0 {
		idx = 0
	}
	if idx >= len(parts) {
		return nil, ErrPartitionNotFound
	}

	p := parts[idx]
	fsType := p.FileSystem

	// Create filesystem handler based on type
	switch fsType {
	case "FAT32":
		handler, err := filesystem.NewFAT32Handler(e, p.StartSector, p.SizeSectors)
		if err != nil {
			return nil, err
		}
		return handler.ListDirectory(dirPath)
	
	case "NTFS":
		handler, err := filesystem.NewNTFSHandler(e, p.StartSector)
		if err != nil {
			return nil, err
		}
		// NTFS - only root for now
		return handler.ListDirectory(dirPath)
	
	case "ext4":
		handler, err := filesystem.NewExt4Handler(e, p.StartSector)
		if err != nil {
			return nil, err
		}
		return handler.ListDirectory(dirPath)
	
	case "XFS":
		handler, err := filesystem.NewXFSHandler(e, p.StartSector)
		if err != nil {
			return nil, err
		}
		return handler.ListDirectory(dirPath)
		
	default:
		return nil, ErrNotSupported
	}
}

// Common errors
var (
	ErrPartitionNotFound = &EWFError{"partition not found"}
	ErrNotSupported      = &EWFError{"operation not supported"}
)

// EWFError represents an EWF-specific error
type EWFError struct {
	msg string
}

func (e *EWFError) Error() string {
	return e.msg
}
