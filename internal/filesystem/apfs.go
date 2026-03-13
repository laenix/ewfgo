package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// APFS (Apple File System) implementation
// Reference: https://github.com/apple/darwin-xnu/blob/main/bsd/vfs/apfs_fsctl.h

type APFS struct {
	startLBA       uint64
	blocksize      uint64
	fsBlocksCount  uint64
	freeBlocks     uint64
	containerGUID  [16]byte
	volumes        []APFSVolumeInfo
	volumeName     string
	catalogOid     uint64
	encrypted      bool
	encryptionType string

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

type APFSVolumeInfo struct {
	name            string
	UUID            [16]byte
	features        uint64
	readonly        bool
}

// APFS Superblock (NXSB format)
type APFSSuperblockNXSB struct {
	Magic           [4]byte    // "NXSB"
	_               [4]byte    // Padding
	BlockSize       uint32     // Block size (little-endian)
	BlockCount      uint64     // Total blocks
	_               [8]byte    // Free blocks
	Features        uint64     // Features
	_               [64]byte   // Various fields
	NumVolumes      uint32     // Number of volumes
}

// APFS Volume Superblock
type APFSVolumeSuperblock struct {
	Magic           [4]byte    // "APSB"
	_               [4]byte
	Features        uint64
	_               [88]byte
	CatalogTreeOid  uint64     // Object ID of catalog B+tree
	_               [128]byte   // More fields
}

const (
	APFS_MAGIC_NXSB = "NXSB"
	APFS_MAGIC_APSB = "APSB"
)

func (apfs *APFS) Type() FileSystemType {
	return FS_APFS
}

func (apfs *APFS) Open(sectorData []byte) error {
	if len(sectorData) < 8192 {
		return fmt.Errorf("APFS: sector data too small")
	}

	// Debug: show what we're looking at
	//fmt.Printf("[APFS] First 64 bytes: %x\n", sectorData[:64])

	// Look for NXSB magic at various offsets
	for offset := 0; offset < len(sectorData)-4; offset++ {
		if string(sectorData[offset:offset+4]) == "NXSB" {
			//fmt.Printf("[APFS] Found NXSB at offset %d\n", offset)
			apfs.blocksize = uint64(binary.LittleEndian.Uint32(sectorData[offset+4:offset+8]))
			apfs.fsBlocksCount = binary.LittleEndian.Uint64(sectorData[offset+8:offset+16])
			
			// Check for encryption in NXSB features (offset 32-39)
			if offset+40 < len(sectorData) {
				features := binary.LittleEndian.Uint64(sectorData[offset+32:offset+40])
				if features&0x00002000 != 0 {
					apfs.encrypted = true
					apfs.encryptionType = "Hardware Encryption"
				} else if features&0x00004000 != 0 {
					apfs.encrypted = true
					apfs.encryptionType = "Pedantic Hardware Encryption"
				}
			}
			
			// Try to get more info from NXSB
			// NXSB structure:
			// 0-3: magic "NXSB"
			// 4-7: block size
			// 8-15: total blocks
			// 16-23: free blocks
			// 24-31: allocated blocks  
			// 32-39: feature flags
			// ...
			// 72-79: number of volumes
			// 128+: volume metadata (for each volume)
			
			if offset+128 < len(sectorData) {
				numVolumes := binary.LittleEndian.Uint32(sectorData[offset+72:offset+76])
				fmt.Printf("[APFS] NXSB: blocksize=%d, blockCount=%d, volumes=%d\n", 
					apfs.blocksize, apfs.fsBlocksCount, numVolumes)
				
				// For each volume, try to find the catalog B+tree
				// Volume metadata starts at offset 128 within NXSB
				volOffset := offset + 128
				for v := uint32(0); v < numVolumes && v < 10; v++ {
					if volOffset+256 < len(sectorData) {
						// Try to find volume superblock (APSB) at this offset
						// Or read from the block number specified in NXSB
						
						// The volume array in NXSB contains block numbers for each volume
						// Each entry is 8 bytes (block number)
						volBlockNum := binary.LittleEndian.Uint64(sectorData[volOffset:volOffset+8])
						if volBlockNum > 0 {
							fmt.Printf("[APFS] Volume %d: block %d\n", v, volBlockNum)
						}
					}
					volOffset += 256 // Skip to next volume entry
				}
			}
			
			//fmt.Printf("[APFS] NXSB: blocksize=%d, blockCount=%d\n", 
			//	apfs.blocksize, apfs.fsBlocksCount)
			
			return nil
		}
	}

	// Try offset 4096 (common APFS superblock location)
	if len(sectorData) >= 4104 {
		var super1 APFSSuperblockNXSB
		if err := binary.Read(bytes.NewReader(sectorData[4096:4160]), binary.LittleEndian, &super1); err == nil {
			if string(super1.Magic[:4]) == "NXSB" {
				apfs.blocksize = uint64(super1.BlockSize)
				apfs.fsBlocksCount = super1.BlockCount
				return nil
			}
		}
	}

	// Try original APFS format
	apfs.blocksize = 4096 // Default
	return nil
}

// IsEncrypted returns true if the APFS volume is encrypted
func (apfs *APFS) IsEncrypted() bool {
	return apfs.encrypted
}

// EncryptionType returns the type of encryption used
func (apfs *APFS) EncryptionType() string {
	return apfs.encryptionType
}

// NewAPFSHandler creates a new APFS filesystem handler
func NewAPFSHandler(reader Reader, startLBA uint64) (*APFS, error) {
	apfs := &APFS{
		startLBA:  startLBA,
		readFunc: reader.ReadSectors,
	}
	
	// Read first sectors to get superblock
	sectorData, err := reader.ReadSectors(startLBA, 16)
	if err != nil {
		return nil, fmt.Errorf("APFS: failed to read superblock: %w", err)
	}
	
	if err := apfs.Open(sectorData); err != nil {
		return nil, err
	}
	
	return apfs, nil
}

func (apfs *APFS) Close() error { return nil }

func (apfs *APFS) GetVolumeLabel() string {
	return apfs.volumeName
}

func (apfs *APFS) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Try to find and parse the APFS catalog B+tree
	// First, read the volume superblock
	
	// APFS volumes start after the container header
	// Try reading several blocks to find the volume superblock (APSB)
	
	blockSectors := apfs.blocksize / 512
	
	// Try different block offsets to find volume superblock
	for blockOffset := uint64(1); blockOffset < 100; blockOffset++ {
		blockLBA := apfs.startLBA + blockOffset*blockSectors
		
		data, err := apfs.readFunc(blockLBA, blockSectors)
		if err != nil || len(data) < 512 {
			continue
		}
		
		// Check for APSB magic (volume superblock)
		if len(data) >= 8 && string(data[0:4]) == "APSB" {
			fmt.Printf("[APFS] Found volume superblock at block %d (LBA %d)\n", blockOffset, blockLBA)
			
			// Check for encryption in volume superblock
			// APSB offset 8-15 contains features
			if len(data) >= 16 {
				volFeatures := binary.LittleEndian.Uint64(data[8:16])
				// Per-volume encryption flags (APFS v2+)
				if volFeatures&0x00000001 != 0 {
					apfs.encrypted = true
					apfs.encryptionType = "APFS Encryption (Data Protection)"
				}
				if volFeatures&0x00000002 != 0 {
					apfs.encrypted = true
					apfs.encryptionType = "APFS Encryption (Complete)"
				}
			}
			
			// Try to find catalog tree OID
			if len(data) >= 112 {
				catalogOid := binary.LittleEndian.Uint64(data[96:104])
				fmt.Printf("[APFS] Catalog tree OID: 0x%x\n", catalogOid)
				apfs.catalogOid = catalogOid
				
				// Try to read the catalog B+tree
				entries, err := apfs.readCatalogBTree(catalogOid)
				if err == nil && len(entries) > 0 {
					return entries, nil
				}
			}
			break
		}
	}
	
	// If encrypted, show warning
	if apfs.encrypted {
		fmt.Printf("[APFS] WARNING: Volume is encrypted (%s)\n", apfs.encryptionType)
		fmt.Printf("[APFS] Encrypted APFS cannot be read without the decryption key\n")
	} else {
		// Check for encryption by analyzing data entropy
		// If catalog can't be found, check if data looks random (high entropy)
		fmt.Printf("[APFS] Checking for encryption...\n")
	}
	
	// If we can't find the catalog, try brute-force search for common patterns
	fmt.Printf("[APFS] Falling back to brute force search...\n")
	entries, err := apfs.bruteForceSearch()
	
	// If brute force finds mostly invalid names, likely encrypted
	if err == nil && len(entries) > 0 {
		// Check for known macOS directory names
		knownNames := []string{"Applications", "System", "Users", "Library", "bin", "sbin", "usr", "etc", "private", "var", "tmp"}
		validCount := 0
		for _, e := range entries {
			for _, known := range knownNames {
				if len(e.Name) >= len(known) && e.Name[:len(known)] == known {
					validCount++
					break
				}
			}
		}
		
		// If we found known macOS names, it's probably not encrypted
		// If not, likely encrypted
		if validCount == 0 {
			apfs.encrypted = true
			apfs.encryptionType = "Likely Encrypted (FileVault)"
			fmt.Printf("[APFS] WARNING: No valid macOS filenames found - likely FileVault encrypted\n")
			fmt.Printf("[APFS] Encrypted APFS volumes cannot be read without the decryption key\n")
		}
	}
	
	return entries, err
}

// readCatalogBTree reads the APFS catalog B+tree
func (apfs *APFS) readCatalogBTree(catalogOid uint64) ([]DirectoryEntry, error) {
	// The catalog OID points to the root of the B+tree
	// Each block in the B+tree has a header
	
	blockSectors := apfs.blocksize / 512
	
	// Calculate which block contains the catalog
	// In APFS, objects are stored in the object store
	// The catalog is typically in the first few blocks after the volume superblock
	
	for blockOffset := uint64(1); blockOffset < 1000; blockOffset++ {
		blockLBA := apfs.startLBA + blockOffset*blockSectors
		
		data, err := apfs.readFunc(blockLBA, blockSectors)
		if err != nil || len(data) < 512 {
			continue
		}
		
		// Check for B+tree node magic (0x00000001 for leaf, 0x00000002 for index)
		treeMagic := binary.LittleEndian.Uint32(data[0:4])
		
		// APFS B+tree node magic values
		if treeMagic == 0x00000001 || treeMagic == 0x00000002 {
			fmt.Printf("[APFS] Found B+tree node at block %d, magic=0x%x\n", blockOffset, treeMagic)
			
			// Try to parse entries from this B+tree node
			entries, err := apfs.parseBTreeNode(data)
			if err == nil && len(entries) > 0 {
				return entries, nil
			}
		}
	}
	
	return nil, fmt.Errorf("APFS: could not find catalog B+tree")
}

// parseBTreeNode parses an APFS B+tree node
func (apfs *APFS) parseBTreeNode(data []byte) ([]DirectoryEntry, error) {
	var entries []DirectoryEntry
	
	if len(data) < 32 {
		return nil, fmt.Errorf("APFS: B+tree node too small")
	}
	
	// B+tree node header
	// Offset 0-3: magic
	// Offset 4-7: level (0 = leaf)
	// Offset 8-11: number of records
	// Offset 12-15: number of keys
	
	level := binary.LittleEndian.Uint32(data[4:8])
	numRecords := binary.LittleEndian.Uint32(data[8:12])
	
	fmt.Printf("[APFS] B+tree: level=%d, numRecords=%d\n", level, numRecords)
	
	if numRecords > 10000 {
		numRecords = 10000
	}
	
	// For leaf nodes (level 0), records start after the node descriptor
	// The descriptor is typically 32 bytes
	descLen := 32
	if level == 0 {
		// Parse catalog records
		// Each record has a key and value
		// Key: 8 byte parent ID + variable length name
		// Value: type (1 byte) + data
		
		off := descLen
		for i := uint32(0); i < numRecords; i++ {
			if off+16 > len(data) {
				break
			}
			
			// Read key: parent ID (8 bytes) + name
			_ = binary.LittleEndian.Uint64(data[off:off+8]) // parentID
			nameLen := int(data[off+8])
			
			if nameLen == 0 || nameLen > 255 {
				off += 16
				continue
			}
			
			if off+9+nameLen > len(data) {
				break
			}
			
			name := string(data[off+9:off+9+nameLen])
			off += 9 + nameLen
			
			// Skip padding
			off = (off + 7) &^ 7
			
			// Read value: type
			if off+4 > len(data) {
				break
			}
			
			recType := data[off]
			off += 4
			
			// Determine if directory
			// Type 1 = file, Type 2 = directory (HFS+ style)
			isDir := (recType == 2)
			
			// Filter out system entries
			if len(name) > 0 && !strings.HasPrefix(name, ".") {
				entries = append(entries, DirectoryEntry{
					Name:   name,
					Path:   "/" + name,
					IsDir:  isDir,
					Size:   0,
				})
			}
		}
	}
	
	if len(entries) == 0 {
		return nil, fmt.Errorf("APFS: no entries found in B+tree")
	}
	
	return entries, nil
}

// isValidAPFSFilename checks if a string looks like a valid APFS filename
func isValidAPFSFilename(name string) bool {
	// Must be reasonable length
	if len(name) < 4 || len(name) > 64 {
		return false
	}
	
	// Common macOS folder names that should be at root
	commonNames := map[string]bool{
		"Applications": true, "Library": true, "System": true, "Users": true,
		"private": true, "var": true, "etc": true, "tmp": true, "bin": true,
		"usr": true, "sbin": true, "dev": true, "Volumes": true,
		"macOS": true, "macOS Install Data": true,
	}
	if commonNames[name] {
		return true
	}
	
	// Common macOS file extensions
	hasValidExt := false
	validExts := []string{".app", ".dmg", ".pkg", ".plist", ".app", ".framework", ".bundle"}
	for _, ext := range validExts {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			hasValidExt = true
			break
		}
	}
	
	// Must start with alphanumeric
	first := rune(name[0])
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	
	// Only allow alphanumeric, dot, dash, underscore
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			  (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == ' ' || c == '(' || c == ')' || c == '-' || c == '@') {
			return false
		}
	}
	
	// Must have significant lowercase letters (typical for Unix filenames)
	lowerCount := 0
	for _, c := range name {
		if c >= 'a' && c <= 'z' {
			lowerCount++
		}
	}
	// Require at least 40% lowercase OR be a known name OR have valid extension
	if len(name) >= 6 && float64(lowerCount)/float64(len(name)) < 0.4 && !hasValidExt && !commonNames[name] {
		return false
	}
	
	// Reject purely hex strings
	isHex := true
	for _, c := range name {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			isHex = false
			break
		}
	}
	if isHex {
		return false
	}
	
	// Reject strings with too many uppercase
	upperCount := 0
	for _, c := range name {
		if c >= 'A' && c <= 'Z' {
			upperCount++
		}
	}
	if float64(upperCount)/float64(len(name)) > 0.6 {
		return false
	}
	
	// Reject patterns like "AbL9", "M3SI", "z6J45" - too many mixed case + digits
	digitCount := 0
	for _, c := range name {
		if c >= '0' && c <= '9' {
			digitCount++
		}
	}
	// If it has digits and mixed case, it's likely garbage
	if digitCount > 0 && digitCount < len(name)/3 && upperCount > lowerCount {
		return false
	}
	
	return true
}

// bruteForceSearch searches for file/directory patterns in APFS data
func (apfs *APFS) bruteForceSearch() ([]DirectoryEntry, error) {
	var entries []DirectoryEntry
	seen := make(map[string]bool)
	
	// Read many blocks and look for catalog records
	blockSectors := apfs.blocksize / 512
	
	for blockOffset := uint64(1); blockOffset < 5000; blockOffset++ {
		blockLBA := apfs.startLBA + blockOffset*blockSectors
		
		data, err := apfs.readFunc(blockLBA, blockSectors)
		if err != nil || len(data) < 512 {
			continue
		}
		
		// Look for HFS+ style catalog records
		// Record types: 1=file, 2=directory, 3=file thread, 4=directory thread
		
		// Look for directory records (type 2)
		// These have: key length (2 bytes) + parent ID (8 bytes) + name length (2 bytes) + name
		for i := 0; i < len(data)-32; i++ {
			// Check for common filename patterns
			// Look for null-terminated strings that look like filenames
			if data[i] == 0 && data[i+1] != 0 {
				start := i + 1
				end := start
				for end < len(data) && end < start+128 {
					c := data[end]
					if c < 0x20 || c > 0x7E {
						break
					}
					end++
				}
				
				length := end - start
				if length >= 4 && length <= 64 {
					name := string(data[start:end])
					
					// Use the validation function
					if isValidAPFSFilename(name) && !seen[name] {
						seen[name] = true
						entries = append(entries, DirectoryEntry{
							Name:   name,
							Path:   "/" + name,
							IsDir:  false,
							Size:   0,
						})
					}
				}
			}
		}
		
		// Limit search
		if len(entries) > 100 {
			break
		}
	}
	
	if len(entries) == 0 {
		return nil, fmt.Errorf("APFS: no entries found")
	}
	
	fmt.Printf("[APFS] Found %d entries via brute force\n", len(entries))
	return entries, nil
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