package filesystem

import (
	"fmt"
	"strings"
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
	
	// Calculated values
	dataAreaStart uint64
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
	
	// Calculate FAT locations
	_, h.dataAreaStart, _ = h.calculateFATLocation(partitionSize)
	
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
	// Only use fallback calculation if sectorsPerFAT is clearly invalid (0 or very small)
	// A typical FAT32 sectorsPerFAT is at least a few hundred, so threshold of 100 is reasonable
	sectorsPerFAT := uint64(h.sectorsPerFAT32)
	if sectorsPerFAT == 0 || sectorsPerFAT < 100 {
		// Only use fallback for clearly invalid values
		clusters := partitionSize / sectorsPerCluster
		sectorsPerFAT = (clusters*4 + 511) / 512
		sectorsPerFAT += 100
		if sectorsPerFAT > 16000 {
			sectorsPerFAT = 16000
		}
		fmt.Printf("[FAT32] WARNING: Using fallback FAT size calculation: %d\n", sectorsPerFAT)
	}
	
	fatStart = h.startLBA + reserved
	dataAreaStart = fatStart + (numFATs * sectorsPerFAT)
	
	// Root directory is at cluster 2
	rootCluster := uint64(h.rootCluster)
	if rootCluster < 2 {
		rootCluster = 2
	}
	rootDirLBA = dataAreaStart + ((rootCluster - 2) * sectorsPerCluster)
	
	fmt.Printf("[FAT32] Calculated: fatStart=%d, dataAreaStart=%d, rootDirLBA=%d\n", 
		fatStart, dataAreaStart, rootDirLBA)
	
	return
}

// clusterToLBA converts a cluster number to absolute LBA
func (h *FAT32Handler) clusterToLBA(cluster uint32) uint64 {
	sectorsPerCluster := uint64(h.sectorsPerCluster)
	return h.dataAreaStart + (uint64(cluster) - 2) * sectorsPerCluster
}

// ListDirectory lists files in the specified directory path
// If path is empty or "/", lists root directory
func (h *FAT32Handler) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Parse path to find target directory
	if path == "" || path == "/" {
		// Root directory
		return h.readDirectory(h.rootCluster)
	}
	
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")
	
	// Find the directory by traversing path
	parts := strings.Split(path, "/")
	currentCluster := h.rootCluster
	
	for _, part := range parts {
		if part == "" {
			continue
		}
		
		// Read current directory to find next component
		entries, err := h.readDirectory(currentCluster)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}
		
		// Find the subdirectory
		found := false
		for _, e := range entries {
			if e.IsDir && e.Name == part {
				// Found - get cluster and continue
				currentCluster = e.Cluster
				found = true
				break
			}
		}
		
		if !found {
			return nil, fmt.Errorf("directory not found: %s", part)
		}
	}
	
	// Read final directory
	return h.readDirectory(currentCluster)
}

// readDirectory reads directory entries from a given cluster
func (h *FAT32Handler) readDirectory(cluster uint32) ([]DirectoryEntry, error) {
	// Convert cluster to LBA
	lba := h.clusterToLBA(cluster)
	
	// Read directory data (one cluster)
	sectorsToRead := uint64(h.sectorsPerCluster)
	data, err := h.reader.ReadSectors(lba, sectorsToRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory at cluster %d (LBA %d): %w", cluster, lba, err)
	}
	
	// Parse directory entries
	entries := h.parseDirectory(data)
	
	return entries, nil
}

// parseDirectory parses FAT32 directory entries
func (h *FAT32Handler) parseDirectory(data []byte) []DirectoryEntry {
	var entries []DirectoryEntry
	
	// Collect long filename entries
	var longNameParts []string
	var longNameSeq int
	
	for i := 0; i+32 <= len(data); i += 32 {
		entry := data[i : i+32]
		
		// Skip free/deleted entries
		if entry[0] == 0x00 {
			// End of directory
			break
		}
		if entry[0] == 0xE5 {
			// Deleted entry - reset long name buffer
			longNameParts = nil
			longNameSeq = 0
			continue
		}
		
		// Check if this is a long filename entry (attribute = 0x0F)
		if entry[11] == 0x0F {
			// Get sequence number (bits 0-5)
			seq := int(entry[0] & 0x3F)
			if seq == 0 || seq > 20 {
				longNameParts = nil
				longNameSeq = 0
				continue
			}
			
			// Check if this is a continuation of previous long name
			// Long names are stored in reverse order (last entry first)
			if seq != longNameSeq-1 && longNameSeq != 0 {
				// New long name, reset
				longNameParts = nil
			}
			longNameSeq = seq
			
			// Extract UTF-16LE characters from the entry
			// Bytes 1-10: chars 1-5, bytes 14-21: chars 6-11, bytes 28-31: chars 12-13
			var chars []uint16
			
			// Characters 1-5 at offsets 1,3,5,7,9
			for j := 1; j <= 9; j += 2 {
				char := uint16(entry[j]) | uint16(entry[j+1])<<8
				if char != 0xFFFF && char != 0 {
					chars = append(chars, char)
				}
			}
			// Characters 6-11 at offsets 14,16,18,20,22,24
			for j := 14; j <= 24; j += 2 {
				char := uint16(entry[j]) | uint16(entry[j+1])<<8
				if char != 0xFFFF && char != 0 {
					chars = append(chars, char)
				}
			}
			// Characters 12-13 at offsets 28,30
			for j := 28; j <= 30; j += 2 {
				char := uint16(entry[j]) | uint16(entry[j+1])<<8
				if char != 0xFFFF && char != 0 {
					chars = append(chars, char)
				}
			}
			
			// Convert UTF-16LE to string
			var sb strings.Builder
			for _, c := range chars {
				if c > 0 {
					sb.WriteRune(rune(c))
				}
			}
			part := sb.String()
			
			// Add to parts (in reverse order, so prepend)
			longNameParts = append([]string{part}, longNameParts...)
			
			continue
		}
		
		// This is a normal directory entry (short name)
		
		// Check if we have a long filename
		var filename string
		if len(longNameParts) > 0 {
			filename = strings.Join(longNameParts, "")
			// Remove any trailing null characters
			filename = strings.TrimRight(filename, "\x00")
		}
		
		// If no long filename, use short name
		if filename == "" {
			// Parse the short name field (8 bytes)
			name := make([]byte, 0)
			for j := 0; j < 8; j++ {
				if entry[j] != 0 && entry[j] != ' ' {
					name = append(name, entry[j])
				}
			}
			
			// Parse extension (3 bytes)
			ext := make([]byte, 0)
			for j := 8; j < 11; j++ {
				if entry[j] != 0 && entry[j] != ' ' {
					ext = append(ext, entry[j])
				}
			}
			
			// Check for UTF-16LE encoding (Chinese filenames)
			filename = string(name)
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
		}
		
		if len(filename) == 0 {
			longNameParts = nil
			longNameSeq = 0
			continue
		}
		
		// Skip volume labels
		if entry[11]&0x08 != 0 {
			longNameParts = nil
			longNameSeq = 0
			continue
		}
		
		isDir := entry[11]&0x10 != 0
		
		// Get file size
		size := uint64(entry[28]) | uint64(entry[29])<<8 | 
		       uint64(entry[30])<<16 | uint64(entry[31])<<24
		
		// Get first cluster (for subdirectories)
		cluster := uint32(entry[26]) | uint32(entry[27])<<8 | 
		          uint32(entry[20]) | uint32(entry[21])<<8
		
		entries = append(entries, DirectoryEntry{
			Name:     filename,
			Path:     "/" + filename,
			IsDir:    isDir,
			Size:     size,
			Cluster:  cluster,
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
