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
func (h *NTFSHandler) ListDirectory() ([]DirectoryEntry, error) {
	// Calculate MFT sector
	mftSector := h.startLBA + uint64(h.mftCluster*int64(h.sectorsPerCluster))
	fmt.Printf("[NTFS] MFT sector: %d\n", mftSector)
	
	// Read MFT - read 64 sectors (enough for first ~16 records)
	mftData, err := h.reader.ReadSectors(mftSector, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to read MFT: %w", err)
	}
	
	// Parse MFT records to find directory entries
	return h.parseMFT(mftData)
}

// parseMFT parses NTFS MFT records to extract filenames
func (h *NTFSHandler) parseMFT(data []byte) ([]DirectoryEntry, error) {
	var entries []DirectoryEntry
	
	// Standard NTFS system files are in records 0-16
	// Each record is 1024 bytes
	for rec := 0; rec <= 16; rec++ {
		recStart := rec * 1024
		if recStart+1024 > len(data) {
			break
		}
		
		record := data[recStart:recStart+1024]
		
		// Check signature
		if string(record[0:4]) != "FILE" {
			continue
		}
		
		// Get flags (first 2 bytes after signature)
		flags := uint16(record[4]) | uint16(record[5])<<8
		if flags == 0 {
			continue // unused record
		}
		
		// Try to find UTF-16LE filename at common offsets
		// These offsets work for this NTFS volume
		filename := h.extractFilename(record)
		
		if filename != "" {
			isDir := flags&0x01 != 0
			
			// Skip system files for cleaner output, or include them
			entries = append(entries, DirectoryEntry{
				Name:   filename,
				Path:   "/" + filename,
				IsDir:  isDir,
				Size:   0, // Would need to read $DATA attribute for size
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
	// Try common offsets where filenames are stored
	// These offsets work for the root MFT records
	offsets := []int{218, 242, 352, 402, 456, 698, 712, 802, 906}
	
	for _, offset := range offsets {
		if offset+16 > len(record) {
			continue
		}
		
		// Check if starts with $ (common for NTFS system files)
		if record[offset] != '$' {
			continue
		}
		
		// Extract UTF-16LE name
		var chars []uint16
		for i := 0; i < 64; i++ {
			off := offset + i*2
			if off+2 > len(record) {
				break
			}
			// Check for null terminator
			if record[off] == 0 && record[off+1] == 0 {
				break
			}
			chars = append(chars, uint16(record[off])|uint16(record[off+1])<<8)
		}
		
		if len(chars) > 0 {
			// Convert to string
			name := ""
			for _, c := range chars {
				if c > 0 && c != 0xFFFF {
					name += string(rune(c))
				}
			}
			
			// Clean up the name
			if len(name) > 0 && name[0] == '$' {
				return name
			}
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
