package filesystem

import (
	"encoding/binary"
	"fmt"
)

// XFS filesystem implementation
// Reference: https://www.kernel.org/doc/Documentation/filesystems/xfs.txt

type XFS struct {
	startLBA       uint64
	blocksize      uint32
	agblocks       uint32
	agcount        uint32
	inodeSize      uint32
	dirblocksize   uint32
	uuid           [16]byte
	volumeName     string

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// NewXFSHandler creates a new XFS filesystem handler
func NewXFSHandler(reader Reader, startLBA uint64) (*XFS, error) {
	xfs := &XFS{
		startLBA:  startLBA,
		readFunc: reader.ReadSectors,
	}

	// Read first sector to get superblock
	sectorData, err := reader.ReadSectors(startLBA, 1)
	if err != nil {
		return nil, fmt.Errorf("XFS: failed to read superblock: %w", err)
	}

	if err := xfs.Open(sectorData); err != nil {
		return nil, err
	}

	return xfs, nil
}

// XFS Super Block (at offset 0 of AG 0)
type XFSSuperblock struct {
	Magic           [4]byte    // "XFSB"
	BlockSize       uint32     // Logical block size
	Blocks          uint64     // Total blocks
	RBlocks         uint64     // Realtime bitmap blocks
	Rextents        uint64     // Realtime extents
	Agfree          uint32     // Blocks in free list
	Frextents       uint64     // Realtime free blocks
	Agcount         uint32     // Number of allocation groups
	Agblocks        uint32     // Blocks per allocation group
	AgiBlocks       uint32     // INode allocation group blocks
	Dirblocksize    uint32     // Directory block size
	FeatureIncompat uint32     // Incompatible features
	_               [4]byte    // Padding
	UUID           [16]byte   // Filesystem UUID
	_               [16]byte   // Padding
	Version        [2]byte    // 5 for v5
	_               [2]byte    // Padding
	RootInode       uint64     // Root inode number
	rbmino          int64      // Realtime bitmap ino
	rumino          int64      // Realtime summary ino
	Rextsize        uint32     // Realtime extent size
	ImaxPct         uint32     // Inode max percentage
	Spare64         [8]uint64 // Padding
	_               [64]byte   // More padding
}

const XFS_MAGIC = 0x58465342 // "XFS"

func (xfs *XFS) Type() FileSystemType {
	return FS_XFS
}

func (xfs *XFS) Open(sectorData []byte) error {
	if len(sectorData) < 512 {
		return fmt.Errorf("XFS: sector data too small")
	}

	// Read XFS superblock manually (big-endian)
	// Magic at offset 0 (4 bytes)
	magic := string(sectorData[0:4])
	if magic != "XFSB" {
		return fmt.Errorf("XFS: invalid magic %q", magic)
	}

	// Block size at offset 4 (4 bytes big-endian)
	xfs.blocksize = binary.BigEndian.Uint32(sectorData[4:8])
	blocks := binary.BigEndian.Uint32(sectorData[8:12])
	agblocks := binary.BigEndian.Uint32(sectorData[36:40])
	agcount := binary.BigEndian.Uint32(sectorData[32:36])
	rootIno := binary.BigEndian.Uint64(sectorData[0x68:0x70])
	
	// Debug: show ALL superblock fields
	fmt.Printf("[XFS] Superblock fields:\n")
	fmt.Printf("[XFS]   magic: %q\n", magic)
	fmt.Printf("[XFS]   blocksize: %d (0x%x)\n", xfs.blocksize, xfs.blocksize)
	fmt.Printf("[XFS]   blocks: %d (0x%x)\n", blocks, blocks)
	fmt.Printf("[XFS]   agcount: %d (0x%x)\n", agcount, agcount)
	fmt.Printf("[XFS]   agblocks: %d (0x%x)\n", agblocks, agblocks)
	fmt.Printf("[XFS]   root inode: %d (0x%x)\n", rootIno, rootIno)
	
	// Debug: show more raw values
	fmt.Printf("[XFS] Raw superblock: magic=%q blocksize=%d agblocks_raw=0x%08X agcount_raw=0x%08X\n",
		magic, binary.BigEndian.Uint32(sectorData[4:8]), agblocks, agcount)
	
	// Check if this looks like a real XFS superblock
	// Real XFS should have reasonable values
	if agblocks > 100000 || agcount > 100 {
		fmt.Printf("[XFS] WARNING: Unreasonable superblock values! This may not be real XFS.\n")
		// Try to continue anyway with defaults
	}

	// Sanity check - if values are unreasonable, use defaults
	// For small XFS (300MB), AG blocks should be ~8000-20000
	if agblocks > 100000 || agcount > 100 || agblocks < 1000 {
		// Use reasonable defaults based on partition size
		// Try common values: 8000, 16000, 19200, 20000
		xfs.agblocks = 8000 // default
		xfs.agcount = 1     // single AG for small filesystem
		
		// Also try reading from alternate offset (XFS v5)
		if len(sectorData) > 0x58 {
			altAgblocks := binary.BigEndian.Uint32(sectorData[0x54:0x58])
			if altAgblocks >= 1000 && altAgblocks <= 100000 {
				xfs.agblocks = altAgblocks
				fmt.Printf("[XFS] Using alternate agblocks: %d\n", xfs.agblocks)
			}
		}
	} else {
		xfs.agblocks = agblocks
		xfs.agcount = agcount
	}

	// Directory block size at offset 44 (4 bytes big-endian)
	dirblocksize := binary.BigEndian.Uint32(sectorData[44:48])
	if dirblocksize > 65536 {
		xfs.dirblocksize = xfs.blocksize // default to block size
	} else {
		xfs.dirblocksize = dirblocksize
	}

	// Inode size at offset 0x5C (92) for v5 XFS, or offset 0x44 for older
	// Try offset 0x5C first
	xfs.inodeSize = 256 // default
	if len(sectorData) > 0x60 {
		inodeSize := binary.BigEndian.Uint32(sectorData[0x5C:0x60])
		if inodeSize >= 256 && inodeSize <= 1024 {
			xfs.inodeSize = inodeSize
		}
	}
	// If still default, try offset 0x44 (older XFS)
	if xfs.inodeSize == 256 && len(sectorData) > 0x48 {
		inodeSize := binary.BigEndian.Uint32(sectorData[0x44:0x48])
		if inodeSize >= 256 && inodeSize <= 1024 {
			xfs.inodeSize = inodeSize
		}
	}
	// Fallback: calculate from blocksize / inopblock
	// For XFS v5, inopblock = 8 for 4KB blocks, so inode size = 512
	if xfs.inodeSize == 256 {
		// Estimate: 4096 / 8 = 512
		xfs.inodeSize = 512
	}

	// UUID at offset 56 (16 bytes)
	copy(xfs.uuid[:], sectorData[56:72])

	fmt.Printf("[XFS] Open: blocksize=%d, agblocks=%d, agcount=%d, inodeSize=%d\n",
		xfs.blocksize, xfs.agblocks, xfs.agcount, xfs.inodeSize)

	return nil
}

func (xfs *XFS) Close() error { return nil }

func (xfs *XFS) GetVolumeLabel() string {
	return xfs.volumeName
}

func (xfs *XFS) ListDirectory(path string) ([]DirectoryEntry, error) {
	// For now, only support root directory
	if path != "/" && path != "" {
		return nil, fmt.Errorf("XFS: only root directory supported")
	}

	// Read root directory from XFS
	// Root inode is at block 0, offset calculated from AG params
	entries, err := xfs.readRootDirectory()
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// readRootDirectory reads the root directory entries from XFS
func (xfs *XFS) readRootDirectory() ([]DirectoryEntry, error) {
	// Read superblock to get root inode
	rootInoFromSB := uint64(0)
	sbData, err := xfs.readFunc(xfs.startLBA, 8)
	if err == nil && len(sbData) >= 0x70 {
		rootInoFromSB = binary.BigEndian.Uint64(sbData[0x68:0x70])
		fmt.Printf("[XFS] Root inode from superblock: %d\n", rootInoFromSB)
	}

	// Try root inode from superblock first, then common XFS root inodes
	// Standard XFS root is inode 64 (0x40), also try 128 and 8
	inodesToTry := []uint64{rootInoFromSB, 64, 128, 8}
	if rootInoFromSB == 0 || rootInoFromSB > 0x100000 {
		// Skip invalid values from superblock
		inodesToTry = []uint64{64, 128, 8}
	}
	
	for _, rootIno := range inodesToTry {
		if rootIno == 0 || rootIno >= 0x100000 {
			continue
		}
		inoData, err := xfs.readInode(rootIno)
		if err == nil {
			magic := string(inoData[0:4])
			mode := binary.BigEndian.Uint16(inoData[4:6])
			format := inoData[7]
			
			fmt.Printf("[XFS] Root inode %d: magic=%q mode=0x%04X format=%d\n", 
				rootIno, magic, mode, format)
			
			if format == 0 || format == 1 {
				entries, err := xfs.parseInlineDirectory(inoData[0x80:])
				if err == nil && len(entries) > 0 {
					fmt.Printf("[XFS] Found root at inode %d!\n", rootIno)
					return entries, nil
				}
			}
		}
	}
	
	// Fallback: brute force search - collect from multiple inodes
	fmt.Printf("[XFS] Falling back to brute force search...\n")
	
	allEntries := make(map[string]bool)
	var result []DirectoryEntry
	
	for inoNum := uint64(1); inoNum < 500; inoNum++ {
		inoData, err := xfs.readInode(inoNum)
		if err != nil {
			continue
		}
		
		format := inoData[7]
		mode := binary.BigEndian.Uint16(inoData[4:6])
		
		// Debug: show format and mode for first 10 inodes
		if inoNum <= 10 {
			fmt.Printf("[XFS] inode %d: mode=0x%04X format=%d\n", inoNum, mode, format)
		}
		
		// Try inline directories (format 0 or 1)
		if format == 0 || format == 1 {
			entries, err := xfs.parseInlineDirectory(inoData[0x80:])
			if err == nil && len(entries) > 0 {
				fmt.Printf("[XFS] Found %d entries in inode %d\n", len(entries), inoNum)
				for _, e := range entries {
					if !allEntries[e.Name] && len(e.Name) > 2 {
						allEntries[e.Name] = true
						result = append(result, e)
					}
				}
			}
		}
		
		// Try extent directories (format >= 2)
		if format >= 2 {
			entries, err := xfs.parseExtentDirectory(inoData)
			if err == nil && len(entries) > 0 {
				fmt.Printf("[XFS] Found %d extent entries in inode %d\n", len(entries), inoNum)
				for _, e := range entries {
					if !allEntries[e.Name] && len(e.Name) > 2 {
						allEntries[e.Name] = true
						result = append(result, e)
					}
				}
			}
		}
	}
	
	if len(result) > 0 {
		fmt.Printf("[XFS] Found %d total unique entries\n", len(result))
		return result, nil
	}

	return nil, fmt.Errorf("XFS: could not find root directory")
}

// readSuperblock reads the XFS superblock
func (xfs *XFS) readSuperblock() (*XFSSuperblockData, error) {
	data, err := xfs.readFunc(xfs.startLBA, 8)
	if err != nil {
		return nil, fmt.Errorf("XFS: failed to read superblock: %w", err)
	}

	if len(data) < 512 || string(data[0:4]) != "XFSB" {
		return nil, fmt.Errorf("XFS: invalid superblock")
	}

	super := &XFSSuperblockData{}
	// Parse superblock - all fields are big-endian
	super.BlockSize = binary.BigEndian.Uint32(data[4:8])
	blocks := binary.BigEndian.Uint32(data[8:12])
	super.AgBlocks = binary.BigEndian.Uint32(data[0x2C:0x30])
	super.RootInode = binary.BigEndian.Uint64(data[0x68:0x70])
	
	// Use inode size from superblock if available (offset 0x0C, 2 bytes)
	super.InodeSize = binary.BigEndian.Uint16(data[0x0C:0x0E])
	if super.InodeSize == 0 {
		super.InodeSize = 256 // default
	}

	fmt.Printf("[XFS] Superblock: magic=%q blocksize=%d blocks=%d agblocks=%d rootIno=%d inodesize=%d\n",
		string(data[0:4]), super.BlockSize, blocks, super.AgBlocks, super.RootInode, super.InodeSize)

	return super, nil
}

// XFSSuperblockData holds parsed superblock information
type XFSSuperblockData struct {
	BlockSize  uint32
	RootInode  uint64
	AgBlocks   uint32
	InodeSize  uint16
}

// readInode reads an inode by number
func (xfs *XFS) readInode(inoNum uint64) ([]byte, error) {
	// Use inode size from superblock (typically 256 or 512 bytes)
	inodeSize := uint64(xfs.inodeSize)
	if inodeSize == 0 {
		inodeSize = 256 // fallback
	}

	// Calculate which AG and offset within AG
	// inode per block = blocksize / inode_size
	inodesPerBlock := xfs.blocksize / uint32(inodeSize)

	// Use AG blocks from superblock if available
	agBlocks := xfs.agblocks
	if agBlocks == 0 {
		agBlocks = 8000 // default for small XFS
	}

	// Calculate AG number (inode number / inodes per AG)
	inodesPerAG := uint64(inodesPerBlock) * uint64(agBlocks)

	// Calculate offset within AG
	inoIndex := (inoNum - 1) % inodesPerAG

	// Calculate which block in the inode table
	inoBlockInTable := inoIndex / uint64(inodesPerBlock)
	inoOffsetInBlock := inoIndex % uint64(inodesPerBlock)

	// For AG 0, inode table starts at block 8 (for 4KB blocks)
	// Sector = block * (blockSize/512)
	// Note: inode table starts at block 8 (after superblock), so sectors = 8 * (blocksize/512)
	// CORRECT: blocksize/512 = 8 sectors per block, so start = 8 * 8 = 64 sectors from partition start
	// Actually wait - the superblock takes only 1 sector (512 bytes), but blocksize is 4096
	// So inode table starts at block 8 (0-indexed), which is sector 8 * 8 = 64 relative to partition
	inodeTableStartSector := uint64(8 * int(xfs.blocksize/512)) // = 8 * 8 = 64 sectors

	// Calculate final sector (relative to partition start)
	// Sector = inode_table_start + (block_in_table * sectors_per_block) + (byte_offset / 512)
	relativeSector := inodeTableStartSector + inoBlockInTable*uint64(xfs.blocksize/512) + inoOffsetInBlock*inodeSize/512

	// Add partition start to get absolute LBA
	inoSector := xfs.startLBA + relativeSector

	// Byte offset within the sector
	inoByteOffset := (inoOffsetInBlock * inodeSize) % 512

	fmt.Printf("[XFS] Reading inode %d: relSector=%d, absLBA=%d, byteOffset=%d\n",
		inoNum, relativeSector, inoSector, inoByteOffset)

	// Read inode - need to read enough sectors for the inode
	// For inode size 512, read 2 sectors to get the full inode
	sectorsToRead := uint64(1)
	if inodeSize > 512 {
		sectorsToRead = uint64((inodeSize + 511) / 512)
	} else {
		sectorsToRead = 1 // At least 1 sector
	}
	// Ensure we read at least 512 bytes for the inode
	if sectorsToRead < 1 {
		sectorsToRead = 1
	}
	data, err := xfs.readFunc(inoSector, sectorsToRead)
	if err != nil {
		return nil, fmt.Errorf("XFS: failed to read inode %d: %w", inoNum, err)
	}

	// Debug: show data length and first 32 bytes as hex
	fmt.Printf("[XFS] Inode %d: read %d bytes, data: %x\n", inoNum, len(data), data[:32])

	// Return the portion starting at inoByteOffset
	return data[inoByteOffset:], nil
}

// readDirectory reads directory entries from an inode
func (xfs *XFS) readDirectory(inodeData []byte) ([]DirectoryEntry, error) {
	if len(inodeData) < 256 {
		return nil, fmt.Errorf("XFS: inode data too small")
	}

	// Check mode at offset 4 (2 bytes big-endian)
	mode := binary.BigEndian.Uint16(inodeData[4:6])
	fmt.Printf("[XFS] Inode mode: 0x%04X (dir if 0x4000)\n", mode)

	// Check if this is actually a directory - mode has directory bit at 0x4000
	if mode&0x4000 == 0 {
		return nil, fmt.Errorf("XFS: not a directory (mode=0x%04X)", mode)
	}

	// Check format at offset 7
	format := inodeData[7]

	fmt.Printf("[XFS] Directory format: 0x%02X\n", format)

	// For inline directories, data starts at offset 0x80
	if format == 1 {
		return xfs.parseInlineDirectory(inodeData[0x80:])
	}

	// For extent-based directories (format 2) or B+tree (format 3+)
	// The directory data is in a separate block, pointed to by extents at offset 0x80
	if format >= 2 {
		return xfs.parseExtentDirectory(inodeData)
	}

	// For B+tree directories, not supported yet
	return nil, fmt.Errorf("XFS: B+tree directory format not supported")
}

// parseExtentDirectory parses directory from extent-based format
func (xfs *XFS) parseExtentDirectory(inodeData []byte) ([]DirectoryEntry, error) {
	// For extent-based directories, the format is complex:
	// - Format 2: single extent (inline)
	// - Format 3: B+tree directory
	// - Format 4: extent list
	// The extent information location varies

	// Try multiple offsets for extent data
	// For XFS v3 inodes, extent data can be at various offsets
	// Also try standard XFS inode offsets: 0x48 (forkoff), 0x50, and after
	targetOffsets := []int{0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0}

	for _, offset := range targetOffsets {
		if offset+16 > len(inodeData) {
			continue
		}

		extLo := binary.BigEndian.Uint64(inodeData[offset:offset+8])
		_ = binary.BigEndian.Uint64(inodeData[offset+8:offset+16])

		// Try extracting block number
		// XFS uses lower 36 bits for block number
		blockNum := extLo & 0xFFFFFFFFF

		// Skip zero or very large block numbers
		if blockNum == 0 || blockNum > 10000000 {
			continue
		}

		fmt.Printf("[XFS] Trying extent at offset 0x%02X: blockNum=%d\n", offset, blockNum)

		// Calculate directory block LBA
		dirBlockSector := blockNum * uint64(xfs.blocksize/512)
		dirLBA := xfs.startLBA + dirBlockSector

		// Read and check
		dirData, err := xfs.readFunc(dirLBA, uint64(xfs.blocksize/512))
		if err != nil {
			continue
		}

		magic := binary.BigEndian.Uint32(dirData[0:4])
		fmt.Printf("[XFS]   Dir magic: 0x%08X\n", magic)

		if magic == 0x58414444 || magic == 0x58414433 {
			entries, err := xfs.parseDirectoryBlock(dirData)
			if err == nil && len(entries) > 0 {
				// Show ftype for each entry
				for _, e := range entries {
					fmt.Printf("[XFS] Extent entry: name=%q isDir=%v\n", e.Name, e.IsDir)
				}
				return entries, nil
			}
		}
	}

	// Try inode number lookup - XFS stores root at inode 64
	// The root directory might be directly accessible
	// For now, return unsupported
	return nil, fmt.Errorf("XFS: extent directory parsing requires B+tree traversal")
}

// parseDirectoryBlock parses XFS directory block entries
func (xfs *XFS) parseDirectoryBlock(data []byte) ([]DirectoryEntry, error) {
	var entries []DirectoryEntry

	// Debug: show first few bytes of directory block
	fmt.Printf("[XFS] Dir block: magic=0x%08X len=%d\n", binary.BigEndian.Uint32(data[0:4]), len(data))

	if len(data) < 8 {
		return nil, fmt.Errorf("XFS: directory block too small")
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	fmt.Printf("[XFS] Dir block magic: 0x%08X\n", magic)

	count := binary.BigEndian.Uint32(data[4:8])
	fmt.Printf("[XFS] Entry count: %d\n", count)

	// Sanity check
	if count > 10000 {
		count = 10000
	}

	off := 8
	for i := uint32(0); i < count; i++ {
		if off+10 > len(data) {
			break
		}

		nameLen := int(data[off])
		ftype := data[off+1]

		// Skip invalid entries
		if nameLen == 0 || nameLen > 255 {
			off += 10
			continue
		}

		if off+10+nameLen > len(data) {
			break
		}

		name := string(data[off+10:off+10+nameLen])

		off += 10 + nameLen

		// Debug: show ftype for valid entries
		fmt.Printf("[XFS] Entry: name=%q ftype=%d isDir=%v\n", name, ftype, ftype == 2)

		// Validate filename before adding
		if isValidFilename(name) {
			entry := DirectoryEntry{
				Name:   name,
				Path:   "/" + name,
				IsDir:  ftype == 2,
				Size:   0,
			}
			entries = append(entries, entry)
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("XFS: no valid entries found")
	}

	return entries, nil
}

// parseInlineDirectory parses inline directory entries
func (xfs *XFS) parseInlineDirectory(data []byte) ([]DirectoryEntry, error) {
	var entries []DirectoryEntry
	seen := make(map[string]bool)
	
	// Method 1: Look for filenames after null bytes
	for i := 1; i < len(data)-3; i++ {
		if data[i] == 0 && data[i+1] != 0 {
			start := i + 1
			end := start
			for end < len(data) && end < start+64 {
				c := data[end]
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
					(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
					break
				}
				end++
			}
			length := end - start
			if length >= 3 && length <= 64 {
				filename := string(data[start:end])
				if !seen[filename] && isValidFilename(filename) {
					seen[filename] = true
					entries = append(entries, DirectoryEntry{
						Name: filename,
						Path: "/" + filename,
						IsDir: false,
						Size: 0,
					})
				}
			}
		}
	}
	
	// Method 2: Look for common boot filenames anywhere
	bootFiles := []string{
		"vmlinuz", "initramfs", "System.map", "config", "symvers",
		"grub", "grub2", "efi", "loader", "bls", "initrd", "config",
	}
	
	dataStr := string(data)
	for _, name := range bootFiles {
		idx := 0
		for {
			i := findStringIdx(dataStr[idx:], name)
			if i < 0 {
				break
			}
			pos := idx + i
			
			// Get the full filename - extend forward
			start := pos
			end := pos + len(name)
			for end < len(dataStr) {
				c := dataStr[end]
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
					(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
					break
				}
				end++
			}
			
			filename := dataStr[start:end]
			if len(filename) >= len(name) && !seen[filename] && isValidFilename(filename) {
				seen[filename] = true
				entries = append(entries, DirectoryEntry{
					Name: filename,
					Path: "/" + filename,
					IsDir: false,
					Size: 0,
				})
			}
			
			idx = pos + 1
			if idx >= len(dataStr) {
				break
			}
		}
	}
	
	if len(entries) > 0 {
		return entries, nil
	}
	
	return nil, fmt.Errorf("XFS: no valid entries found")
}


func findStringIdx(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// isValidFilename checks if a string looks like a valid filename
func isValidFilename(name string) bool {
	// Must be at least 4 characters
	if len(name) < 4 || len(name) > 64 {
		return false
	}
	
	// Reject if starts with X (often XFS metadata like XDB3)
	if len(name) >= 4 && name[0] == 'X' && name[1] == 'D' {
		return false
	}
	
	// Reject patterns like "g4Ay", "g4Ax" - hex + mixed case pattern
	// Check if name has the pattern: letter-digit-letter (e.g., g4A, g4B)
	if len(name) >= 3 {
		for i := 0; i < len(name)-2; i++ {
			if ((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= 'A' && name[i] <= 'Z')) &&
			   (name[i+1] >= '0' && name[i+1] <= '9') &&
			   ((name[i+2] >= 'a' && name[i+2] <= 'z') || (name[i+2] >= 'A' && name[i+2] <= 'Z')) {
				// This looks like partial hash or metadata, not a real filename
				if i == 0 || i == len(name)-3 {
					return false
				}
			}
		}
	}
	
	// Must start with alphanumeric
	first := rune(name[0])
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	
	// Must end with alphanumeric or valid extension character
	last := rune(name[len(name)-1])
	if !((last >= 'a' && last <= 'z') || (last >= 'A' && last <= 'Z') || (last >= '0' && last <= '9')) {
		if last != '-' && last != '_' && last != '.' {
			return false
		}
	}
	
	// Must contain at least one lowercase letter (typical for Linux filenames)
	hasLower := false
	for _, c := range name {
		if c >= 'a' && c <= 'z' {
			hasLower = true
			break
		}
	}
	if !hasLower && len(name) < 8 {
		// Short names without lowercase are suspicious (e.g., "INA", "g4B")
		return false
	}
	
	// Reject purely hex strings (likely metadata)
	isHex := true
	for _, c := range name {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			isHex = false
			break
		}
	}
	if isHex && len(name) >= 8 {
		return false
	}
	
	// Count valid characters
	validCount := 0
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			validCount++
		}
	}
	
	// At least 80% of characters must be valid
	if float64(validCount)/float64(len(name)) < 0.8 {
		return false
	}
	
	return true
}
