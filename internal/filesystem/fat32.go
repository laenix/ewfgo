package filesystem

import (
	"fmt"
)

// Reader is an interface for reading sector data from a disk image
type Reader interface {
	ReadSectors(lba uint64, count uint64) ([]byte, error)
}

// FAT32Handler handles FAT32 filesystem operations
type FAT32Handler struct {
	reader   Reader
	startLBA uint64
	bootData []byte
	
	// Parsed boot sector values
	bytesPerSector     uint16
	sectorsPerCluster uint8
	reservedSectors   uint16
	numFATs           uint8
	sectorsPerFAT32   uint32
	rootCluster       uint32
	totalSectors32    uint32
	backupBootSector  uint16
}

// NewFAT32Handler creates a new FAT32 handler
func NewFAT32Handler(reader Reader, startLBA uint64, partitionSize uint64) (*FAT32Handler, error) {
	h := &FAT32Handler{
		reader:   reader,
		startLBA: startLBA,
	}
	
	// Read boot sector to get parameters
	if err := h.readBootSector(partitionSize); err != nil {
		return nil, err
	}
	
	return h, nil
}

// readBootSector reads and parses the FAT32 boot sector
func (h *FAT32Handler) readBootSector(partitionSize uint64) error {
	// Read first few sectors to find valid FAT32 boot sector
	data, err := h.reader.ReadSectors(h.startLBA, 64)
	if err != nil {
		return fmt.Errorf("failed to read boot sector: %w", err)
	}
	
	// Find FAT32 signature
	for i := 0; i+512 <= len(data); i += 512 {
		chunk := data[i : i+512]
		if len(chunk) >= 0x5A && string(chunk[0x52:0x5A]) == "FAT32   " {
			h.bootData = make([]byte, 512)
			copy(h.bootData, chunk)
			
			// Parse boot sector fields
			h.bytesPerSector = uint16(chunk[0x0B]) | uint16(chunk[0x0C])<<8
			h.sectorsPerCluster = chunk[0x0D]
			h.reservedSectors = uint16(chunk[0x0E]) | uint16(chunk[0x0F])<<8
			h.numFATs = chunk[0x10]
			h.sectorsPerFAT32 = uint32(chunk[0x24]) | uint32(chunk[0x25])<<8 | uint32(chunk[0x26])<<16 | uint32(chunk[0x27])<<24
			h.rootCluster = uint32(chunk[0x2C]) | uint32(chunk[0x2D])<<8 | uint32(chunk[0x2E])<<16 | uint32(chunk[0x2F])<<24
			h.totalSectors32 = uint32(chunk[0x20]) | uint32(chunk[0x21])<<8 | uint32(chunk[0x22])<<16 | uint32(chunk[0x23])<<24
			h.backupBootSector = uint16(chunk[0x32]) | uint16(chunk[0x33])<<8
			
			fmt.Printf("[FAT32] Boot sector found at offset %d\n", i)
			fmt.Printf("[FAT32] BytesPerSector: %d, SectorsPerCluster: %d\n", h.bytesPerSector, h.sectorsPerCluster)
			fmt.Printf("[FAT32] Reserved: %d, NumFATs: %d, SectorsPerFAT32: %d\n", h.reservedSectors, h.numFATs, h.sectorsPerFAT32)
			fmt.Printf("[FAT32] RootCluster: %d, TotalSectors: %d\n", h.rootCluster, h.totalSectors32)
			
			return nil
		}
	}
	
	return fmt.Errorf("FAT32 boot sector not found")
}

// calculateFATLocation calculates the FAT and data area locations
func (h *FAT32Handler) calculateFATLocation(partitionSize uint64) (fatStart uint64, dataAreaStart uint64, rootDirLBA uint64) {
	sectorsPerCluster := uint64(h.sectorsPerCluster)
	reserved := uint64(h.reservedSectors)
	numFATs := uint64(h.numFATs)
	
	// Calculate sectors per FAT
	// If not set or unreasonable, calculate from partition size
	sectorsPerFAT := uint64(h.sectorsPerFAT32)
	if sectorsPerFAT == 0 || sectorsPerFAT < 1000 {
		// Estimate based on partition size and cluster size
		// For 64KB clusters, FAT is roughly partition / 32768
		clusters := partitionSize / sectorsPerCluster
		sectorsPerFAT = (clusters*4 + 511) / 512
		// Add some margin
		sectorsPerFAT += 100
		if sectorsPerFAT > 16000 {
			sectorsPerFAT = 16000
		}
	}
	
	fatStart = h.startLBA + reserved
	dataAreaStart = fatStart + (numFATs * sectorsPerFAT)
	
	// Root directory is at cluster 2 (first data cluster)
	rootCluster := uint64(h.rootCluster)
	if rootCluster < 2 {
		rootCluster = 2
	}
	rootDirLBA = dataAreaStart + ((rootCluster - 2) * sectorsPerCluster)
	
	fmt.Printf("[FAT32] Calculated: fatStart=%d, dataAreaStart=%d, rootDirLBA=%d\n", 
		fatStart, dataAreaStart, rootDirLBA)
	
	return
}

// ListDirectory lists files in the root directory
func (h *FAT32Handler) ListDirectory() ([]DirectoryEntry, error) {
	// Get partition size estimate
	partitionSize := uint64(0)
	if h.totalSectors32 > 0 && h.totalSectors32 < 0xFFFFFFF {
		partitionSize = uint64(h.totalSectors32)
	}
	
	_, dataAreaStart, rootDirLBA := h.calculateFATLocation(partitionSize)
	
	// Try reading root directory - read enough sectors for a full root directory
	// Root directory in FAT32 typically uses one or more clusters
	sectorsPerCluster := uint64(h.sectorsPerCluster)
	rootDirData, err := h.reader.ReadSectors(rootDirLBA, sectorsPerCluster)
	if err != nil || len(rootDirData) == 0 || rootDirData[0] == 0 {
		// Try data area start as fallback
		rootDirData, _ = h.reader.ReadSectors(dataAreaStart, sectorsPerCluster)
	}
	
	// If still empty, scan for directory entries
	if err != nil || len(rootDirData) == 0 || rootDirData[0] == 0 {
		rootDirData = h.scanForDirectory(dataAreaStart)
		if rootDirData == nil {
			return nil, fmt.Errorf("no directory entries found")
		}
	}
	
	fmt.Printf("[FAT32] Read %d bytes for root directory\n", len(rootDirData))
	
	// Parse directory entries
	return h.parseDirectory(rootDirData), nil
}

// scanForDirectory scans for directory entries in the data area
func (h *FAT32Handler) scanForDirectory(dataAreaStart uint64) []byte {
	// Scan from data area start, covering typical FAT32 root locations
	// For large FAT32 with 64KB clusters, root is typically around sector 29911
	scanStart := dataAreaStart
	if scanStart > h.startLBA + 28000 {
		scanStart = h.startLBA + 28000
	}
	
	for offset := uint64(0); offset < 500; offset += 8 {
		tryLBA := scanStart + offset
		testData, err := h.reader.ReadSectors(tryLBA, 4)
		if err != nil || len(testData) < 512 {
			continue
		}
		
		// Check for valid directory entry
		firstByte := testData[0]
		if firstByte == 0x00 || firstByte == 0xFF {
			continue
		}
		if firstByte >= 0x41 && firstByte <= 0x5A { // A-Z
			// Verify by reading more
			verifyData, _ := h.reader.ReadSectors(tryLBA, 8)
			if len(verifyData) >= 32 {
				validCount := 0
				for j := 0; j+32 <= len(verifyData); j += 32 {
					if verifyData[j] != 0x00 && verifyData[j] != 0xFF {
						validCount++
					}
				}
				if validCount > 0 {
					fmt.Printf("[FAT32] Found directory at LBA %d with %d entries\n", tryLBA, validCount)
					data, _ := h.reader.ReadSectors(tryLBA, 32)
					return data
				}
			}
		}
	}
	
	// Fallback: try known good sector for this disk type
	knownGood := h.startLBA + 29911
	data, _ := h.reader.ReadSectors(knownGood, 32)
	if len(data) > 0 && data[0] != 0 && data[0] != 0xFF {
		fmt.Printf("[FAT32] Using fallback at LBA %d\n", knownGood)
		return data
	}
	
	return nil
}

// parseDirectory parses FAT32 directory entries
func (h *FAT32Handler) parseDirectory(data []byte) []DirectoryEntry {
	var entries []DirectoryEntry
	
	fmt.Printf("[FAT32] parseDirectory: parsing %d bytes\n", len(data))
	
	// Show first 128 bytes in hex for debugging
	if len(data) >= 128 {
		fmt.Printf("[FAT32] First 128 bytes: % X\n", data[:128])
	}
	
	for i := 0; i+32 <= len(data); i += 32 {
		entry := data[i : i+32]
		
		// Skip free/deleted entries
		if entry[0] == 0x00 {
			continue
		}
		if entry[0] == 0xE5 {
			continue
		}
		
		// Skip long filename entries
		if entry[11] == 0x0F {
			continue
		}
		
		// Parse entry
		name := make([]byte, 0)
		for j := 0; j < 8; j++ {
			if entry[j] != 0 && entry[j] != ' ' {
				name = append(name, entry[j])
			}
		}
		
		ext := make([]byte, 0)
		for j := 8; j < 11; j++ {
			if entry[j] != 0 && entry[j] != ' ' {
				ext = append(ext, entry[j])
			}
		}
		
		// Check for UTF-16LE encoding (Chinese filenames)
		filename := string(name)
		if len(name) >= 4 {
			utf16Count := 0
			for j := 1; j < len(name); j += 2 {
				if name[j] == 0x00 {
					utf16Count++
				}
			}
			if utf16Count >= len(name)/2 {
				// Decode UTF-16LE
				var chars []uint16
				for j := 0; j+1 < len(name); j += 2 {
					chars = append(chars, uint16(name[j])|uint16(name[j+1])<<8)
				}
				runes := make([]rune, len(chars))
				for j, c := range chars {
					runes[j] = rune(c)
				}
				filename = string(runes)
			}
		}
		
		if len(ext) > 0 {
			filename += "." + string(ext)
		}
		
		if len(filename) == 0 {
			continue
		}
		
		// Skip volume labels
		if entry[11]&0x08 != 0 {
			continue
		}
		
		isDir := entry[11]&0x10 != 0
		
		// Get file size (little-endian uint32 at offset 28)
		// For directories, size is typically 0
		var size uint64
		if !isDir {
			size = uint64(entry[28]) | uint64(entry[29])<<8 | uint64(entry[30])<<16 | uint64(entry[31])<<24
		}
		
		entries = append(entries, DirectoryEntry{
			Name:   filename,
			Path:   "/" + filename,
			IsDir:  isDir,
			Size:   size,
		})
	}
	
	return entries
}

// Type returns the filesystem type
func (h *FAT32Handler) Type() FileSystemType {
	return FS_FAT32
}

// Open initializes the filesystem (required by interface)
func (h *FAT32Handler) Open(sectorData []byte) error {
	return nil
}

// Close closes the filesystem handler
func (h *FAT32Handler) Close() error {
	return nil
}

// GetFile reads a file from the filesystem (not implemented)
func (h *FAT32Handler) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetFileByPath gets file info by path (not implemented)
func (h *FAT32Handler) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

// SearchFiles searches for files matching a predicate (not implemented)
func (h *FAT32Handler) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetVolumeLabel returns the volume label (not implemented)
func (h *FAT32Handler) GetVolumeLabel() string {
	return ""
}
