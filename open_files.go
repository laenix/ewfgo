package ewf

import (
	"github.com/laenix/ewfgo/internal/filesystem"
)

// ListFiles lists files in the specified partition.
// Returns directory entries for the root of the specified partition.
func (e *EWFImage) ListFiles(partitionIndex int) ([]filesystem.DirectoryEntry, error) {
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
		return handler.ListDirectory()
	
	case "FAT16", "FAT12":
		// TODO: Implement FAT16 handler
		return nil, ErrNotSupported
	
	case "NTFS":
		handler, err := filesystem.NewNTFSHandler(e, p.StartSector)
		if err != nil {
			return nil, err
		}
		return handler.ListDirectory()
		
	case "ext4":
		handler, err := filesystem.NewExt4Handler(e, p.StartSector)
		if err != nil {
			return nil, err
		}
		return handler.ListDirectory()
		
	default:
		return nil, ErrNotSupported
	}
}

// ListDirectory lists files in a specific directory path within a partition.
func (e *EWFImage) ListDirectory(partitionIndex int, dirPath string) ([]filesystem.DirectoryEntry, error) {
	// Currently only supports root directory
	if dirPath != "" && dirPath != "/" {
		return nil, ErrNotSupported
	}
	return e.ListFiles(partitionIndex)
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
