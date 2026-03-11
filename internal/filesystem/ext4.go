package filesystem

import (
	"encoding/binary"
	"fmt"
)

// Ext4Handler handles ext4 filesystem operations
type Ext4Handler struct {
	reader   Reader
	startLBA uint64
	
	// Parsed superblock values
	blockSize       uint32
	blocksPerGroup  uint32
	inodesPerGroup  uint32
	inodeSize       uint16
	firstDataBlock  uint32
	inodeTableStart uint64
}

// NewExt4Handler creates a new ext4 handler
func NewExt4Handler(reader Reader, startLBA uint64) (*Ext4Handler, error) {
	h := &Ext4Handler{
		reader:   reader,
		startLBA: startLBA,
	}
	
	// Read superblock
	if err := h.readSuperblock(); err != nil {
		return nil, err
	}
	
	return h, nil
}

// readSuperblock reads and parses the ext4 superblock
func (h *Ext4Handler) readSuperblock() error {
	// Superblock is at offset 1024 (1KB) from start of filesystem
	// Try 1KB offset first (1KB block size case)
	sbData, err := h.reader.ReadSectors(h.startLBA, 8)
	if err != nil {
		return fmt.Errorf("failed to read superblock: %w", err)
	}
	
	// Check for ext4 magic at offset 1024 + 0x38 (0x53EF)
	superblockOffset := 1024 // offset within sector data
	if len(sbData) >= superblockOffset+2 {
		magic := binary.BigEndian.Uint16(sbData[superblockOffset+0x38:])
		if magic == 0x53EF {
			return h.parseSuperblock(sbData[superblockOffset:])
		}
	}
	
	// Try at offset 4096 (4KB block size case)
	if len(sbData) >= 4096+2 {
		magic := binary.BigEndian.Uint16(sbData[4096+0x38:])
		if magic == 0x53EF {
			return h.parseSuperblock(sbData[4096:])
		}
	}
	
	// Try backup superblocks (at block 1 for 1KB blocks, or block 8193 for 4KB blocks)
	backupOffsets := []uint64{8193, 32768, 131072}
	for _, offset := range backupOffsets {
		backupData, err := h.reader.ReadSectors(h.startLBA+offset, 8)
		if err != nil {
			continue
		}
		if len(backupData) >= 1024+2 {
			magic := binary.BigEndian.Uint16(backupData[1024+0x38:])
			if magic == 0x53EF {
				fmt.Printf("[ext4] Found backup superblock at offset %d\n", offset)
				return h.parseSuperblock(backupData[1024:])
			}
		}
	}
	
	return fmt.Errorf("ext4 superblock not found")
}

// parseSuperblock parses the ext4 superblock
func (h *Ext4Handler) parseSuperblock(data []byte) error {
	if len(data) < 1024 {
		return fmt.Errorf("superblock data too small")
	}
	
	// s_log_block_size (offset 0x18)
	logBlockSize := binary.LittleEndian.Uint32(data[0x18:])
	h.blockSize = 1024 << logBlockSize
	
	// s_blocks_per_group (offset 0x20)
	h.blocksPerGroup = binary.LittleEndian.Uint32(data[0x20:])
	
	// s_inodes_per_group (offset 0x28)
	h.inodesPerGroup = binary.LittleEndian.Uint32(data[0x28:])
	
	// s_inode_size (offset 0x58)
	h.inodeSize = binary.LittleEndian.Uint16(data[0x58:])
	if h.inodeSize == 0 {
		h.inodeSize = 128 // default
	}
	
	// s_first_data_block (offset 0x14)
	h.firstDataBlock = binary.LittleEndian.Uint32(data[0x14:])
	
	fmt.Printf("[ext4] Block size: %d, Blocks per group: %d, Inodes per group: %d, Inode size: %d\n",
		h.blockSize, h.blocksPerGroup, h.inodesPerGroup, h.inodeSize)
	fmt.Printf("[ext4] First data block: %d\n", h.firstDataBlock)
	
	return nil
}

// ListDirectory lists files in the root directory (/)
func (h *Ext4Handler) ListDirectory() ([]DirectoryEntry, error) {
	// Root directory inode is typically inode 2
	return h.readDirectory(2)
}

// readDirectory reads directory entries from a given inode
func (h *Ext4Handler) readDirectory(inodeNum uint32) ([]DirectoryEntry, error) {
	// Calculate which block group this inode is in
	groupNum := (inodeNum - 1) / h.inodesPerGroup
	inodeIndex := (inodeNum - 1) % h.inodesPerGroup
	
	// Group descriptor table is right after superblock/block group 0
	// GDT is at block 1 (or block 2 for 1KB blocks)
	var gdtBlock uint64 = uint64(h.firstDataBlock) + 1
	if h.blockSize == 1024 {
		gdtBlock = uint64(h.firstDataBlock) + 2
	}
	
	// Each group descriptor is 64 bytes (ext4)
	groupDescOffset := gdtBlock*uint64(h.blockSize) + uint64(groupNum)*64
	groupDescSector := uint64(groupDescOffset) / 512
	groupDescData, err := h.reader.ReadSectors(h.startLBA+groupDescSector, 8)
	if err != nil {
		return nil, fmt.Errorf("failed to read group descriptor: %w", err)
	}
	
	groupDesc := groupDescData[groupDescOffset%512:]
	
	// Get inode table block
	inodeTableBlock := binary.LittleEndian.Uint32(groupDesc[0x08:])
	
	// Calculate inode offset within table
	inodeOffset := uint64(inodeIndex) * uint64(h.inodeSize)
	inodeSector := (uint64(inodeTableBlock)*uint64(h.blockSize) + inodeOffset) / 512
	
	inodeSizeSectors := (uint64(h.inodeSize) * 2) / 512
	if inodeSizeSectors < 1 {
		inodeSizeSectors = 1
	}
	inodeData, err := h.reader.ReadSectors(h.startLBA+inodeSector, inodeSizeSectors)
	if err != nil {
		return nil, fmt.Errorf("failed to read inode: %w", err)
	}
	
	// Get inode data (starts at offset within sector)
	inode := inodeData[inodeOffset%512:]
	
	// Check i_mode for directory
	mode := binary.LittleEndian.Uint16(inode[0x00:])
	if mode&0x4000 == 0 {
		return nil, fmt.Errorf("inode is not a directory")
	}
	
	// Get block pointers (i_block array at offset 0x28)
	// For simplicity, use first block
	blockPtr := binary.LittleEndian.Uint32(inode[0x28:])
	if blockPtr == 0 {
		return nil, fmt.Errorf("directory has no data blocks")
	}
	
	// Read directory data
	dirSector := (uint64(blockPtr) * uint64(h.blockSize)) / 512
	blockSectors := uint64(h.blockSize) / 512 * 4
	dirData, err := h.reader.ReadSectors(h.startLBA+dirSector, blockSectors)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}
	
	return h.parseDirectory(dirData), nil
}

// parseDirectory parses ext4 directory entries
func (h *Ext4Handler) parseDirectory(data []byte) []DirectoryEntry {
	var entries []DirectoryEntry
	
	offset := 0
	for offset+8 <= len(data) {
		// dir_rec_len (offset 0x00)
		recLen := binary.LittleEndian.Uint16(data[offset:])
		if recLen == 0 {
			break
		}
		
		// dir_inode (offset 0x04)
		inode := binary.LittleEndian.Uint32(data[offset+0x04:])
		if inode == 0 {
			offset += int(recLen)
			continue
		}
		
		// dir_name_len (offset 0x06)
		nameLen := int(data[offset+0x06])
		
		// dir_file_type (offset 0x07)
		fileType := data[offset+0x07]
		
		// Skip "." and ".."
		name := string(data[offset+0x08 : offset+0x08+nameLen])
		if name == "." || name == ".." {
			offset += int(recLen)
			continue
		}
		
		// File type: 1=regular, 2=directory, 3=char dev, 4=block dev, 5=pipe, 6=socket, 7=symlink
		isDir := fileType == 2
		
		entries = append(entries, DirectoryEntry{
			Name:   name,
			Path:   "/" + name,
			IsDir:  isDir,
			Size:   0, // Would need to read inode for size
		})
		
		offset += int(recLen)
	}
	
	return entries
}

// Type returns the filesystem type
func (h *Ext4Handler) Type() FileSystemType {
	return FS_EXT4
}

// Open initializes the filesystem
func (h *Ext4Handler) Open(sectorData []byte) error {
	return nil
}

// Close closes the filesystem handler
func (h *Ext4Handler) Close() error {
	return nil
}

// GetFile reads a file
func (h *Ext4Handler) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetFileByPath gets file info
func (h *Ext4Handler) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

// SearchFiles searches for files
func (h *Ext4Handler) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetVolumeLabel returns the volume label
func (h *Ext4Handler) GetVolumeLabel() string {
	return ""
}
