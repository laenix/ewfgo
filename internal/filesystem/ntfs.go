package filesystem

import (
	"fmt"
)

// NTFSHandler handles NTFS filesystem operations
type NTFSHandler struct {
	reader   Reader
	startLBA uint64

	// Parsed boot sector values
	sectorsPerCluster uint8
	mftCluster        int64
}

// NewNTFSHandler creates a new NTFS handler
func NewNTFSHandler(reader Reader, startLBA uint64) (*NTFSHandler, error) {
	h := &NTFSHandler{
		reader:   reader,
		startLBA: startLBA,
	}

	// Read boot sector to get MFT location
	bootData, err := reader.ReadSectors(startLBA, 1)
	if err != nil || len(bootData) < 512 {
		return nil, fmt.Errorf("failed to read boot sector: %w", err)
	}

	// Check for NTFS signature
	if len(bootData) >= 8 && string(bootData[3:7]) != "NTFS" {
		return nil, fmt.Errorf("not a valid NTFS filesystem")
	}

	// Get MFT cluster location from boot sector (offset 0x30)
	h.mftCluster = int64(bootData[0x30]) | int64(bootData[0x31])<<8 |
	              int64(bootData[0x32])<<16 | int64(bootData[0x33])<<24

	// Get sectors per cluster (offset 0x0D)
	h.sectorsPerCluster = bootData[0x0D]
	if h.sectorsPerCluster == 0 {
		h.sectorsPerCluster = 8 // default
	}

	fmt.Printf("[NTFS] MFT cluster: %d, sectors per cluster: %d\n", h.mftCluster, h.sectorsPerCluster)

	return h, nil
}

// ListDirectory lists files in the root directory
// For NTFS, path parameter is ignored for now (only root is supported)
func (h *NTFSHandler) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Calculate MFT sector
	mftSector := h.startLBA + uint64(h.mftCluster*int64(h.sectorsPerCluster))
	fmt.Printf("[NTFS] MFT sector: %d\n", mftSector)

	// Read more MFT records (256 records = 256KB)
	mftData, err := h.reader.ReadSectors(mftSector, 512)
	if err != nil {
		return nil, fmt.Errorf("failed to read MFT: %w", err)
	}

	// Parse MFT records to find filenames
	return h.parseMFTEntries(mftData)
}

// parseMFTEntries parses MFT records to extract filenames
func (h *NTFSHandler) parseMFTEntries(data []byte) ([]DirectoryEntry, error) {
	var entries []DirectoryEntry

	// Scan first 256 MFT records
	for rec := 0; rec < 256; rec++ {
		recStart := rec * 1024
		if recStart+1024 > len(data) {
			break
		}

		record := data[recStart:recStart+1024]

		// Check signature
		if string(record[0:4]) != "FILE" {
			continue
		}

		// Get flags
		flags := uint16(record[4]) | uint16(record[5])<<8
		if flags == 0 {
			continue // unused record
		}

		isDir := flags&0x01 != 0

		// Extract filename
		filename := h.extractFilename(record)

		if filename != "" && len(filename) >= 1 {
			entries = append(entries, DirectoryEntry{
				Name:   filename,
				Path:   "/" + filename,
				IsDir:  isDir,
				Size:   0, // Would need $DATA attribute for actual size
			})
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries found in MFT")
	}

	return entries, nil
}

// extractFilename attempts to extract UTF-16LE filename from MFT record
func (h *NTFSHandler) extractFilename(record []byte) string {
	// Search for UTF-16LE filename in the record
	// The filename typically starts at common offsets in the $FILE_NAME attribute
	
	// Try scanning from common $FILE_NAME attribute locations
	for start := 0x90; start < 800; start++ {
		// Look for filename: starts with valid filename char
		// Must be ASCII letter, $, or common chars
		if record[start] != '$' && 
		   !((record[start] >= 'A' && record[start] <= 'Z') || 
		     (record[start] >= 'a' && record[start] <= 'z')) {
			continue
		}
		
		// Check if next byte is 0 (UTF-16LE low byte)
		if start+1 >= len(record) || record[start+1] != 0 {
			continue
		}
		
		// Try to extract UTF-16LE string
		var chars []rune
		for j := start; j+1 < start+50 && j+1 < len(record); j += 2 {
			lo := record[j]
			hi := record[j+1]
			if hi != 0 {
				break
			}
			// Must be valid filename char
			if lo < 0x20 || lo > 126 {
				break
			}
			chars = append(chars, rune(lo))
		}
		
		// Require minimum length and valid characters
		if len(chars) >= 2 {
			name := string(chars)
			
			// Skip common non-filename patterns
			if name == ".." || name == "." {
				continue
			}
			
			// Skip single letter names
			if len(name) < 2 {
				continue
			}
			
			return name
		}
	}
	
	return ""
}

// Type returns the filesystem type
func (h *NTFSHandler) Type() FileSystemType {
	return FS_NTFS
}

// Open initializes the filesystem
func (h *NTFSHandler) Open(sectorData []byte) error {
	return nil
}

// Close closes the filesystem handler
func (h *NTFSHandler) Close() error {
	return nil
}

// GetFile reads a file
func (h *NTFSHandler) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetFileByPath gets file info
func (h *NTFSHandler) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

// SearchFiles searches for files
func (h *NTFSHandler) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetVolumeLabel returns the volume label
func (h *NTFSHandler) GetVolumeLabel() string {
	return ""
}
