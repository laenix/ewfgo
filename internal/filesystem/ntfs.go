package filesystem

import (
	"fmt"
)

// NTFSHandler handles NTFS filesystem operations
type NTFSHandler struct {
	reader   Reader
	startLBA uint64
}

// NewNTFSHandler creates a new NTFS handler
func NewNTFSHandler(reader Reader, startLBA uint64) (*NTFSHandler, error) {
	return &NTFSHandler{
		reader:   reader,
		startLBA: startLBA,
	}, nil
}

// ListDirectory lists files in the root directory
func (h *NTFSHandler) ListDirectory() ([]DirectoryEntry, error) {
	// Read NTFS boot sector to find MFT location
	bootData, err := h.reader.ReadSectors(h.startLBA, 1)
	if err != nil || len(bootData) < 512 {
		return nil, fmt.Errorf("failed to read boot sector: %w", err)
	}
	
	// Check for NTFS signature
	if len(bootData) >= 8 && string(bootData[3:7]) != "NTFS" {
		return nil, fmt.Errorf("not a valid NTFS filesystem")
	}
	
	// Get MFT cluster location from boot sector (offset 0x30)
	mftCluster := int64(bootData[0x30]) | int64(bootData[0x31])<<8 | 
	              int64(bootData[0x32])<<16 | int64(bootData[0x33])<<24
	
	// Get sectors per cluster (offset 0x0D)
	sectorsPerCluster := int(bootData[0x0D])
	if sectorsPerCluster == 0 {
		sectorsPerCluster = 8 // default
	}
	
	fmt.Printf("[NTFS] MFT cluster: %d, sectors per cluster: %d\n", mftCluster, sectorsPerCluster)
	
	// Calculate MFT sector
	mftSector := h.startLBA + uint64(mftCluster*int64(sectorsPerCluster))
	fmt.Printf("[NTFS] MFT sector: %d\n", mftSector)
	
	// Read MFT
	mftData, err := h.reader.ReadSectors(mftSector, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to read MFT: %w", err)
	}
	
	// Parse MFT entries
	return h.parseMFT(mftData)
}

// parseMFT parses NTFS MFT (Master File Table) entries
func (h *NTFSHandler) parseMFT(data []byte) ([]DirectoryEntry, error) {
	var entries []DirectoryEntry
	
	// Each MFT record is typically 1024 bytes
	recordSize := 1024
	
	for offset := 0; offset+recordSize <= len(data); offset += recordSize {
		record := data[offset : offset+recordSize]
		
		// Check for MFT signature "FILE"
		if len(record) < 4 || string(record[:4]) != "FILE" {
			continue
		}
		
		// Get flags (first 2 bytes after signature)
		flags := uint16(record[4]) | uint16(record[5])<<8
		if flags == 0 {
			// Empty record
			continue
		}
		
		// Get attribute offset
		attrOffset := int(record[0x14]) | int(record[0x15])<<8
		
		// Skip if attribute offset is beyond record
		if attrOffset+48 > len(record) {
			continue
		}
		
		// Look for $FILE_NAME attribute (type 0x30)
		attrType := uint32(record[attrOffset]) | uint32(record[attrOffset+1])<<8 | uint32(record[attrOffset+2])<<16 | uint32(record[attrOffset+3])<<24
		
		if attrType == 0x30 {
			// $FILE_NAME attribute
			nameLen := int(record[attrOffset+0x40])
			nameSpace := record[attrOffset+0x41]
			
			// Skip Win32 namespace filenames (more complex)
			if nameLen > 0 && nameLen < 255 && nameSpace == 0 {
				nameStart := attrOffset + 0x42
				if nameStart+nameLen*2 <= len(record) {
					// Filename is UTF-16LE
					var chars []uint16
					for i := 0; i < nameLen; i++ {
						off := nameStart + i*2
						if off+1 < len(record) {
							chars = append(chars, uint16(record[off])|uint16(record[off+1])<<8)
						}
					}
					
					// Convert to string
					name := ""
					for _, c := range chars {
						if c > 0 && c != 0xFFFF {
							name += string(rune(c))
						}
					}
					
					if name != "" && name != "." && name != ".." {
						isDir := flags&0x01 != 0
						entries = append(entries, DirectoryEntry{
							Name:   name,
							Path:   "/" + name,
							IsDir:  isDir,
							Size:   0,
						})
					}
				}
			}
		}
	}
	
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries found in MFT")
	}
	
	return entries, nil
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
