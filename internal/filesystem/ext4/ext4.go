// Package ext4 provides an ext4 filesystem handler adapted from the parent
// filesystem package. It qualifies every parent identifier with filesystem.
package ext4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// Ext4 filesystem constants
const (
	// ext4ExtentsFlag is the EXTENTS_FL i_flags bit: the inode uses the extent
	// tree (not legacy direct/indirect block pointers).
	ext4ExtentsFlag = 0x80000
	// ext4ExtentMagic is the extent tree header magic (0xF30A).
	ext4ExtentMagic = 0xF30A
	// ext4MaxExtentDepth bounds extent-tree recursion (a real tree is <=5).
	ext4MaxExtentDepth = 5
	// ext4MaxFileBlocks bounds the number of data blocks one read may fetch,
	// so a crafted i_size cannot force a huge allocation or read loop.
	ext4MaxFileBlocks = 1 << 20
	// ext4MaxExtentBlocks bounds the total coverage a validated extent tree may
	// claim, so a crafted tree cannot inflate the allocation bound.
	ext4MaxExtentBlocks = 1 << 24
	// ext4MaxSearchDepth bounds recursive directory traversal in SearchFiles.
	ext4MaxSearchDepth = 32
	// ext4MaxSearchCount bounds the number of results SearchFiles may return.
	ext4MaxSearchCount = 100000
)

// errExt4Hole marks a logical block with no extent mapping but a logical block
// inside the file's declared size. ext4 defines such blocks as sparse holes:
// they read as zero bytes (lastlog/wtmp are typically mostly holes). A reader
// distinguishes a hole from a structurally corrupt extent tree with errors.Is,
// so a hole is zero-filled while corruption still errors.
var errExt4Hole = errors.New("ext4: sparse hole")

// Ext4Handler handles ext4 filesystem operations
type Ext4Handler struct {
	reader   filesystem.Reader
	startLBA uint64

	// Parsed superblock values
	blockSize       uint32
	blocksPerGroup  uint32
	inodesPerGroup  uint32
	inodeSize       uint16
	firstDataBlock  uint64
	inodeTableStart uint64
	bigEndian       bool
	// descSize is the group-descriptor size in bytes (s_desc_size at 0xFE,
	// defaulting to 32 for a 32-bit filesystem or 64 when EXT4_FEATURE_INCOMPAT_64BIT
	// is set). mkfs wrote either value; a hardcoded 64 here reads a high group's
	// descriptor from the wrong slot and surfaces another group's inode as if it
	// were the target's — fabricated data.
	descSize uint16
	// superblockData is a copy of the superblock (for s_volume_name).
	superblockData []byte
}

// NewExt4Handler creates a new ext4 handler
func NewExt4Handler(reader filesystem.Reader, startLBA uint64) (*Ext4Handler, error) {
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
	// The registry factory produces a reader-less Ext4Handler; every data
	// operation must fail loudly rather than nil-dereference.
	if h.reader == nil {
		return fmt.Errorf("ext4: handler has no reader (construct with NewExt4Handler)")
	}
	// Read more sectors to find superblock (might be at LBA 1-2, not LBA 0)
	sbData, err := h.reader.ReadSectors(h.startLBA, 16)
	if err != nil {
		return fmt.Errorf("failed to read superblock: %w", err)
	}

	// Search for ext4 magic (0x53EF) at common offsets. The superblock sits at
	// byte 1024/2048/4096 of the filesystem depending on block size.
	searchOffsets := []int{1024, 4096, 2048, 6144}

	for _, offset := range searchOffsets {
		if len(sbData) >= offset+0x38+2 {
			magic := binary.BigEndian.Uint16(sbData[offset+0x38:])
			if magic == 0x53EF {
				return h.parseSuperblock(sbData[offset:])
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

	// ext4 on-disk structures are little-endian; keep a defensive big-endian
	// branch for the superblock only.
	logBlockSize := binary.LittleEndian.Uint32(data[0x18:])
	h.blockSize = 1024 << logBlockSize

	if h.blockSize > 1024*1024 || h.blockSize < 1024 {
		logBlockSize = binary.BigEndian.Uint32(data[0x18:])
		h.blockSize = 1024 << logBlockSize
		h.bigEndian = true
	}

	if h.bigEndian {
		h.blocksPerGroup = binary.BigEndian.Uint32(data[0x20:])
		h.inodesPerGroup = binary.BigEndian.Uint32(data[0x28:])
		h.inodeSize = binary.BigEndian.Uint16(data[0x58:])
		h.firstDataBlock = uint64(binary.BigEndian.Uint32(data[0x14:]))
	} else {
		h.blocksPerGroup = binary.LittleEndian.Uint32(data[0x20:])
		h.inodesPerGroup = binary.LittleEndian.Uint32(data[0x28:])
		h.inodeSize = binary.LittleEndian.Uint16(data[0x58:])
		h.firstDataBlock = uint64(binary.LittleEndian.Uint32(data[0x14:]))
	}

	// mkfs.ext4 always writes s_inode_size=256; keep a defensive default.
	if h.inodeSize == 0 {
		h.inodeSize = 256
	}

	// Group descriptor size: s_desc_size at 0xFE. When it is 0 the default is 32
	// bytes, or 64 when EXT4_FEATURE_INCOMPAT_64BIT (0x80) is set at 0x60. Using
	// the wrong stride reads every high group's descriptor from the wrong slot.
	h.descSize = binary.LittleEndian.Uint16(data[0xFE:])
	if h.descSize == 0 {
		if binary.LittleEndian.Uint32(data[0x60:])&0x80 != 0 {
			h.descSize = 64
		} else {
			h.descSize = 32
		}
	}

	// Keep a copy of the superblock for the volume label (s_volume_name).
	h.superblockData = append([]byte(nil), data[:1024]...)

	if h.blocksPerGroup == 0 || h.inodesPerGroup == 0 || h.blockSize == 0 {
		return fmt.Errorf("ext4: invalid superblock geometry (blockSize=%d blocksPerGroup=%d inodesPerGroup=%d)",
			h.blockSize, h.blocksPerGroup, h.inodesPerGroup)
	}
	return nil
}

// readInode reads the raw bytes of inode inodeNum. It resolves the block group
// via the GDT (inode_table_lo at +0x08, inode_table_hi at +0x34), locates the
// inode table, and slices the inode's inodeSize bytes out of the read sectors.
func (h *Ext4Handler) readInode(inodeNum uint32) ([]byte, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("ext4: handler has no reader (construct with NewExt4Handler)")
	}
	if inodeNum == 0 {
		return nil, fmt.Errorf("ext4: inode 0 is reserved")
	}
	if h.inodesPerGroup == 0 {
		return nil, fmt.Errorf("ext4: invalid inodesPerGroup 0")
	}

	groupNum := (inodeNum - 1) / h.inodesPerGroup
	inodeIndex := (inodeNum - 1) % h.inodesPerGroup

	// Group descriptor table is right after the superblock/block group 0.
	var gdtBlock uint64 = uint64(h.firstDataBlock) + 1
	if h.blockSize == 1024 {
		gdtBlock = uint64(h.firstDataBlock) + 2
	}

	descSize := uint64(h.descSize)
	if descSize == 0 {
		descSize = 64
	}
	groupDescOffset := gdtBlock*uint64(h.blockSize) + uint64(groupNum)*descSize
	groupDescSector := groupDescOffset / 512
	descSectors := (uint64(groupDescOffset%512) + descSize + 511) / 512

	targetLBA := h.startLBA + groupDescSector
	groupDescData, err := h.reader.ReadSectors(targetLBA, descSectors)
	if err != nil {
		return nil, fmt.Errorf("ext4: failed to read group descriptor (LBA %d): %w", targetLBA, err)
	}
	if uint64(groupDescOffset%512)+descSize > uint64(len(groupDescData)) {
		return nil, fmt.Errorf("ext4: short group descriptor read for inode %d", inodeNum)
	}
	groupDesc := groupDescData[groupDescOffset%512:]

	inodeTableLo := binary.LittleEndian.Uint32(groupDesc[0x08:])
	// inode_table_hi (+0x34) exists only in 64-byte descriptors; a 32-byte
	// descriptor ends at +0x20, so reading it there would grab the next
	// descriptor's bytes.
	var inodeTableHi uint32
	if descSize >= 0x38 {
		inodeTableHi = uint32(binary.LittleEndian.Uint16(groupDesc[0x34:]))
	}
	inodeTableBlock := uint64(inodeTableHi)<<32 | uint64(inodeTableLo)

	inodeSize := uint64(h.inodeSize)
	inodeOffset := uint64(inodeIndex) * inodeSize
	inodeSector := (inodeTableBlock*uint64(h.blockSize) + inodeOffset) / 512
	inodeSectors := (uint64(inodeOffset%512) + inodeSize + 511) / 512
	if inodeSectors < 1 {
		inodeSectors = 1
	}

	inodeTargetLBA := h.startLBA + inodeSector
	inodeData, err := h.reader.ReadSectors(inodeTargetLBA, inodeSectors)
	if err != nil {
		return nil, fmt.Errorf("ext4: failed to read inode %d: %w", inodeNum, err)
	}
	off := inodeOffset % 512
	if uint64(len(inodeData)) < off+inodeSize {
		return nil, fmt.Errorf("ext4: short inode %d read", inodeNum)
	}
	return inodeData[off : off+inodeSize], nil
}

// readBlockBytes reads one full filesystem block at physical block physBlock.
func (h *Ext4Handler) readBlockBytes(physBlock uint64) ([]byte, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("ext4: handler has no reader (construct with NewExt4Handler)")
	}
	blockSectors := uint64(h.blockSize) / 512
	lba := h.startLBA + physBlock*blockSectors
	data, err := h.reader.ReadSectors(lba, blockSectors)
	if err != nil {
		return nil, fmt.Errorf("ext4: failed to read block %d (LBA %d): %w", physBlock, lba, err)
	}
	if uint64(len(data)) < uint64(h.blockSize) {
		return nil, fmt.Errorf("ext4: short read of block %d: got %d bytes, want %d", physBlock, len(data), h.blockSize)
	}
	return data[:h.blockSize], nil
}

// extentCoverage returns the total number of data blocks the extent tree
// rooted at nodeData allocates, recursing through index nodes. It is bounded by
// ext4MaxExtentBlocks so a crafted tree cannot inflate the allocation bound.
func (h *Ext4Handler) extentCoverage(nodeData []byte, depth uint16) (uint64, error) {
	if len(nodeData) < 12 {
		return 0, fmt.Errorf("ext4: extent node too small")
	}
	if magic := binary.LittleEndian.Uint16(nodeData[0:2]); magic != ext4ExtentMagic {
		return 0, fmt.Errorf("ext4: bad extent magic 0x%04X", magic)
	}
	if depth > ext4MaxExtentDepth {
		return 0, fmt.Errorf("ext4: extent depth %d exceeds max %d", depth, ext4MaxExtentDepth)
	}
	ehEntries := int(binary.LittleEndian.Uint16(nodeData[2:4]))
	ehDepth := binary.LittleEndian.Uint16(nodeData[6:8])
	if ehDepth != depth {
		return 0, fmt.Errorf("ext4: extent depth mismatch %d != %d", ehDepth, depth)
	}
	if ehEntries > (len(nodeData)-12)/12 {
		return 0, fmt.Errorf("ext4: extent header entries %d exceed node capacity", ehEntries)
	}

	var total uint64
	if depth == 0 {
		for i := 0; i < ehEntries; i++ {
			total += uint64(binary.LittleEndian.Uint16(nodeData[12+i*12+4:]))
			if total > ext4MaxExtentBlocks {
				return 0, fmt.Errorf("ext4: extent coverage exceeds %d blocks", ext4MaxExtentBlocks)
			}
		}
		return total, nil
	}

	for i := 0; i < ehEntries; i++ {
		leafLo := uint64(binary.LittleEndian.Uint32(nodeData[12+i*12+4:]))
		leafHi := uint64(binary.LittleEndian.Uint16(nodeData[12+i*12+8:]))
		leafBlock := leafHi<<32 | leafLo
		leaf, err := h.readBlockBytes(leafBlock)
		if err != nil {
			return 0, err
		}
		c, err := h.extentCoverage(leaf, depth-1)
		if err != nil {
			return 0, err
		}
		total += c
		if total > ext4MaxExtentBlocks {
			return 0, fmt.Errorf("ext4: extent coverage exceeds %d blocks", ext4MaxExtentBlocks)
		}
	}
	return total, nil
}

// resolveExtent resolves logical file block fileBlock to a physical block,
// descending the extent tree rooted at nodeData (the inode extent root or an
// index-node block). depth is the expected tree depth of nodeData.
func (h *Ext4Handler) resolveExtent(nodeData []byte, fileBlock uint64, depth uint16) (uint64, error) {
	if len(nodeData) < 12 {
		return 0, fmt.Errorf("ext4: extent node too small")
	}
	if magic := binary.LittleEndian.Uint16(nodeData[0:2]); magic != ext4ExtentMagic {
		return 0, fmt.Errorf("ext4: bad extent magic 0x%04X", magic)
	}
	if depth > ext4MaxExtentDepth {
		return 0, fmt.Errorf("ext4: extent depth %d exceeds max %d", depth, ext4MaxExtentDepth)
	}
	ehEntries := int(binary.LittleEndian.Uint16(nodeData[2:4]))
	ehDepth := binary.LittleEndian.Uint16(nodeData[6:8])
	if ehDepth != depth {
		return 0, fmt.Errorf("ext4: extent depth mismatch %d != %d", ehDepth, depth)
	}
	if ehEntries > (len(nodeData)-12)/12 {
		return 0, fmt.Errorf("ext4: extent header entries %d exceed node capacity", ehEntries)
	}
	if ehEntries <= 0 {
		return 0, fmt.Errorf("ext4: extent node has no entries: %w", errExt4Hole)
	}

	if depth == 0 {
		// Leaf extents: find the one whose [ee_block, ee_block+ee_len) covers
		// fileBlock; physical block = start + (fileBlock - ee_block).
		for i := 0; i < ehEntries; i++ {
			ext := nodeData[12+i*12:]
			eeBlock := uint64(binary.LittleEndian.Uint32(ext[0:4]))
			eeLen := uint64(binary.LittleEndian.Uint16(ext[4:6]))
			if eeLen == 0 {
				continue
			}
			if fileBlock >= eeBlock && fileBlock < eeBlock+eeLen {
				start := uint64(binary.LittleEndian.Uint16(ext[6:8]))<<32 |
					uint64(binary.LittleEndian.Uint32(ext[8:12]))
				return start + (fileBlock - eeBlock), nil
			}
		}
		// No extent maps this block: a sparse hole within the declared size.
		return 0, fmt.Errorf("ext4: no extent covers file block %d: %w", fileBlock, errExt4Hole)
	}

	// Index node: pick the entry with the largest ei_block <= fileBlock, read
	// its child block, and descend.
	best := -1
	var bestBlock uint64
	for i := 0; i < ehEntries; i++ {
		idx := nodeData[12+i*12:]
		eiBlock := uint64(binary.LittleEndian.Uint32(idx[0:4]))
		if eiBlock <= fileBlock && (best < 0 || eiBlock > bestBlock) {
			best = i
			bestBlock = eiBlock
		}
	}
	if best < 0 {
		return 0, fmt.Errorf("ext4: no index entry covers file block %d: %w", fileBlock, errExt4Hole)
	}
	idx := nodeData[12+best*12:]
	leafLo := uint64(binary.LittleEndian.Uint32(idx[4:8]))
	leafHi := uint64(binary.LittleEndian.Uint16(idx[8:10]))
	leafBlock := leafHi<<32 | leafLo
	leaf, err := h.readBlockBytes(leafBlock)
	if err != nil {
		return 0, err
	}
	return h.resolveExtent(leaf, fileBlock, depth-1)
}

// inodeSizeOf returns the 64-bit file size (i_size_lo | i_size_high<<32).
func (h *Ext4Handler) inodeSizeOf(inodeData []byte) uint64 {
	lo := uint64(binary.LittleEndian.Uint32(inodeData[0x04:]))
	hi := uint64(binary.LittleEndian.Uint32(inodeData[0x6C:]))
	return lo | hi<<32
}

// readExtentData reads size bytes of a file described by inodeData through its
// extent tree. The declared size is validated against the extent coverage
// before any allocation, so a crafted huge i_size errors instead of OOMing.
func (h *Ext4Handler) readExtentData(inodeNum uint32, inodeData []byte, size uint64) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if len(inodeData) < 0x24 {
		return nil, fmt.Errorf("ext4: inode %d too small", inodeNum)
	}
	flags := binary.LittleEndian.Uint32(inodeData[0x20:])
	if flags&ext4ExtentsFlag == 0 {
		return nil, fmt.Errorf("ext4: inode %d uses unsupported (non-extent) block mapping", inodeNum)
	}
	if len(inodeData) < 0x28+12 {
		return nil, fmt.Errorf("ext4: inode %d too small for extent root", inodeNum)
	}
	root := inodeData[0x28:]
	if magic := binary.LittleEndian.Uint16(root[0:2]); magic != ext4ExtentMagic {
		return nil, fmt.Errorf("ext4: inode %d bad extent magic 0x%04X", inodeNum, magic)
	}
	ehDepth := binary.LittleEndian.Uint16(root[6:8])
	if ehDepth > ext4MaxExtentDepth {
		return nil, fmt.Errorf("ext4: extent depth %d exceeds max %d", ehDepth, ext4MaxExtentDepth)
	}

	blockSize := uint64(h.blockSize)
	// Compute the block count overflow-safe: a crafted i_size near 2^64 made the
	// old ceil-division (size+blockSize-1) wrap to a tiny value, slipping past
	// the guards below and panicking on out[:size]. h.blockSize is validated to
	// be >=1024, so size/blockSize + 1 cannot overflow uint64.
	fileBlocks := size / blockSize
	if size%blockSize != 0 {
		fileBlocks++
	}
	if fileBlocks > ext4MaxFileBlocks {
		return nil, fmt.Errorf("ext4: inode %d size %d exceeds maximum readable %d blocks", inodeNum, size, ext4MaxFileBlocks)
	}

	// The extent root is the 12-byte header + entries at inode offset 0x28.
	extentRoot := inodeData[0x28:]

	// Validate the extents cover the declared size before allocating.
	coverage, err := h.extentCoverage(extentRoot, ehDepth)
	if err != nil {
		return nil, err
	}
	if fileBlocks > coverage {
		return nil, fmt.Errorf("ext4: inode %d size %d needs %d blocks but extents cover %d", inodeNum, size, fileBlocks, coverage)
	}

	// Cap the eager preallocation; append grows the buffer for genuinely large
	// files (mirrors the XFS readExtents guard).
	initialCap := size
	if initialCap > 1<<20 {
		initialCap = 1 << 20
	}
	out := make([]byte, 0, initialCap)
	for n := uint64(0); n < fileBlocks; n++ {
		phys, err := h.resolveExtent(extentRoot, n, ehDepth)
		if err != nil {
			return nil, fmt.Errorf("ext4: inode %d file block %d: %w", inodeNum, n, err)
		}
		blk, err := h.readBlockBytes(phys)
		if err != nil {
			return nil, err
		}
		out = append(out, blk...)
	}
	return out[:size], nil
}

// resolvePathToInode walks a path from the root inode (2) through directory
// entries and returns the target inode number. The root itself has no entry.
func (h *Ext4Handler) resolvePathToInode(path string) (uint32, error) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return 0, fmt.Errorf("ext4: root path is a directory: %w", filesystem.ErrIsDirectory)
	}

	currentInode := uint32(2) // root inode
	var parts []string
	for _, p := range strings.Split(clean, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}

	for i, part := range parts {
		entries, err := h.readDirectory(currentInode, "")
		if err != nil {
			return 0, fmt.Errorf("ext4: failed to read directory while resolving %q: %w", part, err)
		}
		var match *filesystem.DirectoryEntry
		for j := range entries {
			if entries[j].Name == part {
				match = &entries[j]
				break
			}
		}
		if match == nil {
			return 0, fmt.Errorf("ext4: path component %q not found: %w", part, filesystem.ErrNotFound)
		}
		if i == len(parts)-1 {
			return uint32(match.Inode), nil
		}
		if !match.IsDir {
			return 0, fmt.Errorf("ext4: path component %q is not a directory: %w", part, filesystem.ErrNotDirectory)
		}
		currentInode = uint32(match.Inode)
	}
	return 0, fmt.Errorf("ext4: invalid path %q", path)
}

// ListDirectory lists files in a directory. Entries are returned with real
// absolute paths (parent-prefixed), so a consumer can resolve each one.
func (h *Ext4Handler) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	if path == "" || path == "/" {
		return h.readDirectory(2, "/")
	}
	inodeNum, err := h.resolvePathToInode(path)
	if err != nil {
		return nil, err
	}
	return h.readDirectory(inodeNum, "/"+strings.Trim(path, "/"))
}

// readDirectory reads directory entries from a given inode. parentPath is the
// directory's own path, used to build each entry's absolute Path.
func (h *Ext4Handler) readDirectory(inodeNum uint32, parentPath string) ([]filesystem.DirectoryEntry, error) {
	inodeData, err := h.readInode(inodeNum)
	if err != nil {
		return nil, err
	}
	if len(inodeData) < 0x24 {
		return nil, fmt.Errorf("ext4: inode %d too small for directory", inodeNum)
	}
	mode := binary.LittleEndian.Uint16(inodeData[0x00:])
	if mode&0x4000 == 0 {
		return nil, fmt.Errorf("ext4: inode %d is not a directory: %w", inodeNum, filesystem.ErrNotDirectory)
	}
	flags := binary.LittleEndian.Uint32(inodeData[0x20:])
	if flags&ext4ExtentsFlag == 0 {
		return nil, fmt.Errorf("ext4: directory inode %d uses unsupported (non-extent) block mapping", inodeNum)
	}

	size := h.inodeSizeOf(inodeData)
	dirData, err := h.readExtentData(inodeNum, inodeData, size)
	if err != nil {
		return nil, err
	}

	return h.parseDirectory(dirData, parentPath)
}

// parseDirectory parses ext4 directory entries. It is defensive against crafted
// on-disk data: a rec_len or name_len that overruns the block (or a degenerate
// rec_len) returns an explicit error instead of panicking on a slice bound.
// parentPath prefixes each entry's Path (see filesystem.JoinPath).
func (h *Ext4Handler) parseDirectory(data []byte, parentPath string) ([]filesystem.DirectoryEntry, error) {
	var entries []filesystem.DirectoryEntry

	offset := 0
	for offset+8 <= len(data) {
		// struct ext4_dir_entry_2 { inode(4), rec_len(2), name_len(1), file_type(1), name[...] }
		inode := binary.LittleEndian.Uint32(data[offset:])
		recLen := binary.LittleEndian.Uint16(data[offset+0x04:])
		if recLen == 0 {
			break
		}
		// A directory entry must be at least 8 bytes (the fixed header).
		if recLen < 8 {
			return entries, fmt.Errorf("ext4: malformed directory entry at offset %d: rec_len=%d", offset, recLen)
		}

		if inode == 0 {
			offset += int(recLen)
			continue
		}

		nameLen := int(data[offset+0x06])
		fileType := data[offset+0x07]

		// Bound the name slice so a crafted name_len that overruns the block
		// returns an error instead of panicking.
		if offset+0x08+nameLen > len(data) {
			return entries, fmt.Errorf("ext4: directory entry name overruns block at offset %d (name_len=%d)", offset, nameLen)
		}
		if 8+nameLen > int(recLen) {
			return entries, fmt.Errorf("ext4: malformed directory entry at offset %d: name_len=%d exceeds rec_len=%d", offset, nameLen, recLen)
		}

		// Skip "." and ".."
		name := string(data[offset+0x08 : offset+0x08+nameLen])
		if name == "." || name == ".." {
			offset += int(recLen)
			continue
		}

		// File type: 1=regular, 2=directory, 3=char dev, 4=block dev, 5=pipe, 6=socket, 7=symlink
		isDir := fileType == 2

		// The dirent carries no size — only the inode does. Read the child inode
		// for a real size (never a fabricated 0), like the other handlers.
		childSize := uint64(0)
		if childData, err := h.readInode(inode); err == nil && len(childData) >= 0x6E {
			childSize = h.inodeSizeOf(childData)
		}

		entries = append(entries, filesystem.DirectoryEntry{
			Name:  name,
			Path:  filesystem.JoinPath(parentPath, name),
			IsDir: isDir,
			Size:  childSize,
			Inode: uint64(inode),
		})

		offset += int(recLen)
	}

	return entries, nil
}

// Type returns the filesystem type
func (h *Ext4Handler) Type() filesystem.FileSystemType {
	return filesystem.FS_EXT4
}

// Open initializes the filesystem (required by interface)
func (h *Ext4Handler) Open(sectorData []byte) error {
	return nil
}

// Close closes the filesystem handler
func (h *Ext4Handler) Close() error {
	return nil
}

// GetFile reads a file's contents by resolving its inode and walking its extent
// tree. The root path (a directory) and missing paths return explicit errors.
func (h *Ext4Handler) GetFile(path string) ([]byte, error) {
	inodeNum, err := h.resolvePathToInode(path)
	if err != nil {
		return nil, err
	}
	inodeData, err := h.readInode(inodeNum)
	if err != nil {
		return nil, err
	}
	if len(inodeData) < 0x06 {
		return nil, fmt.Errorf("ext4: inode %d too small", inodeNum)
	}
	mode := binary.LittleEndian.Uint16(inodeData[0x00:])
	if mode&0x4000 != 0 {
		return nil, fmt.Errorf("ext4: path %q is a directory: %w", path, filesystem.ErrIsDirectory)
	}
	// A symlink's target is the file's data: a fast symlink stores it inline in
	// the inode's i_block area (offset 0x28, up to 60 bytes); a long one lives in
	// a data block. Return the real target rather than fabricating file content.
	if mode&0xF000 == 0xA000 {
		size := h.inodeSizeOf(inodeData)
		if size <= 60 && uint64(len(inodeData)) >= 0x28+size {
			return inodeData[0x28 : 0x28+size], nil
		}
		return h.readExtentData(inodeNum, inodeData, size)
	}
	size := h.inodeSizeOf(inodeData)
	return h.readExtentData(inodeNum, inodeData, size)
}

// GetFileByPath gets file info by path, reading the real inode metadata.
func (h *Ext4Handler) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	inodeNum, err := h.resolvePathToInode(path)
	if err != nil {
		return nil, err
	}
	inodeData, err := h.readInode(inodeNum)
	if err != nil {
		return nil, err
	}
	if len(inodeData) < 0x6E {
		return nil, fmt.Errorf("ext4: inode %d too small", inodeNum)
	}

	modeRaw := binary.LittleEndian.Uint16(inodeData[0x00:])
	isDir := modeRaw&0x4000 != 0
	isReg := modeRaw&0x8000 != 0
	var mode filesystem.FileMode
	switch {
	case isDir:
		mode = filesystem.ModeDir
	case isReg:
		mode = filesystem.ModeRegular
	}

	name := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		name = path[idx+1:]
	}

	return &filesystem.FileInfo{
		Name:    name,
		Path:    "/" + strings.Trim(path, "/"),
		Size:    h.inodeSizeOf(inodeData),
		Mode:    mode,
		IsDir:   isDir,
		ModTime: int64(binary.LittleEndian.Uint32(inodeData[0x0C:])),
	}, nil
}

// SearchFiles searches for files matching a predicate, recursing through
// directories. Depth and result count are bounded.
func (h *Ext4Handler) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	cleanRoot := strings.Trim(rootPath, "/")
	rootInode := uint32(2)
	base := ""
	if cleanRoot != "" {
		ino, err := h.resolvePathToInode(rootPath)
		if err != nil {
			return nil, err
		}
		rootInode = ino
		base = "/" + cleanRoot
	}

	results := make([]filesystem.FileInfo, 0)

	var walk func(inode uint32, dirPath string, depth int) error
	walk = func(inode uint32, dirPath string, depth int) error {
		if depth > ext4MaxSearchDepth {
			return nil
		}
		entries, err := h.readDirectory(inode, dirPath)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if len(results) >= ext4MaxSearchCount {
				return fmt.Errorf("ext4: search exceeded %d results", ext4MaxSearchCount)
			}
			inodeData, err := h.readInode(uint32(e.Inode))
			if err != nil {
				return err
			}
			if len(inodeData) < 0x6E {
				return fmt.Errorf("ext4: inode %d too small", e.Inode)
			}
			modeRaw := binary.LittleEndian.Uint16(inodeData[0x00:])
			isDir := modeRaw&0x4000 != 0
			var mode filesystem.FileMode = filesystem.ModeRegular
			if isDir {
				mode = filesystem.ModeDir
			}
			fi := filesystem.FileInfo{
				Name:    e.Name,
				Path:    dirPath + "/" + e.Name,
				Size:    h.inodeSizeOf(inodeData),
				Mode:    mode,
				IsDir:   isDir,
				ModTime: int64(binary.LittleEndian.Uint32(inodeData[0x0C:])),
			}
			if predicate(fi) {
				results = append(results, fi)
			}
			if isDir && depth < ext4MaxSearchDepth {
				if err := walk(uint32(e.Inode), fi.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(rootInode, base, 0); err != nil {
		return nil, err
	}
	return results, nil
}

// GetVolumeLabel returns the real ext4 volume label from the superblock
// s_volume_name[16] field (offset 0x78), or "" when empty.
func (h *Ext4Handler) GetVolumeLabel() string {
	if len(h.superblockData) >= 0x88 {
		return string(bytes.TrimRight(h.superblockData[0x78:0x88], "\x00"))
	}
	return ""
}

func init() {
	// The factory returns the reader-less Ext4Handler, whose data operations
	// return an explicit "no reader" error (never a nil dereference or a
	// fabricated listing). The real listing path is NewExt4Handler (reader-based,
	// used by open_files.go/evidence.go), so DetectAndOpen can never hand out a
	// canned listing.
	filesystem.RegisterFileSystem(filesystem.FS_EXT4, func() filesystem.FileSystem { return &Ext4Handler{} })
	filesystem.RegisterHandler(filesystem.FS_EXT4, func(r filesystem.Reader, startLBA, partitionSize uint64) (filesystem.FileSystem, error) {
		return NewExt4Handler(r, startLBA)
	})
}
