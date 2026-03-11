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
	
	// AG count at offset 32 (4 bytes big-endian)
	xfs.agcount = binary.BigEndian.Uint32(sectorData[32:36])
	
	// AG blocks at offset 36 (4 bytes big-endian)
	xfs.agblocks = binary.BigEndian.Uint32(sectorData[36:40])
	
	// Directory block size at offset 44 (4 bytes big-endian)
	xfs.dirblocksize = binary.BigEndian.Uint32(sectorData[44:48])
	
	// UUID at offset 56 (16 bytes)
	copy(xfs.uuid[:], sectorData[56:72])

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
	superblock, err := xfs.readSuperblock()
	if err != nil {
		return nil, err
	}
	
	// Read root inode
	rootIno, err := xfs.readInode(superblock.RootInode)
	if err != nil {
		return nil, err
	}
	
	// Read directory data
	return xfs.readDirectory(rootIno)
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
	super.RootInode = binary.BigEndian.Uint64(data[72:80])
	super.AgBlocks = binary.BigEndian.Uint32(data[36:40])
	super.InodeSize = binary.BigEndian.Uint16(data[44:46])
	
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
	// Calculate which AG and offset within AG
	// For simplicity, assume inode size = 256 and 64 inodes per block
	agSize := uint64(xfs.blocksize / 256 * 64) // rough estimate
	if agSize == 0 {
		agSize = 8192 // default
	}
	
	agNum := inoNum / agSize
	inoOffset := inoNum % agSize
	
	// Calculate LBA: AG starts at certain offset + inode table offset
	// For AG 0, inode table typically starts at block 8 (for 4KB blocks)
	inodeTableStart := uint64(8 * 4096 / 512) // block 8 in sectors
	inoSector := agNum*uint64(xfs.agblocks) + inodeTableStart + inoOffset
	
	// Read inode
	data, err := xfs.readFunc(inoSector, 2)
	if err != nil {
		return nil, fmt.Errorf("XFS: failed to read inode %d: %w", inoNum, err)
	}
	
	return data, nil
}

// readDirectory reads directory entries from an inode
func (xfs *XFS) readDirectory(inodeData []byte) ([]DirectoryEntry, error) {
	if len(inodeData) < 256 {
		return nil, fmt.Errorf("XFS: inode data too small")
	}
	
	// Check if inline directory (format = 1 at offset 0x47)
	format := inodeData[0x47]
	
	// For inline directories, data starts at offset 0x80
	if format == 1 {
		return xfs.parseInlineDirectory(inodeData[0x80:])
	}
	
	// For B+tree directories, not supported yet
	return nil, fmt.Errorf("XFS: B+tree directory format not supported")
}

// parseInlineDirectory parses inline directory entries
func (xfs *XFS) parseInlineDirectory(data []byte) ([]DirectoryEntry, error) {
	var entries []DirectoryEntry
	
	// XFS inline directory format:
	// - 4 bytes: magic (0x58414444 = "XADD")
	// - 4 bytes: number of entries
	// - Then entries: 1 byte name_len + 1 byte ftype + 8 bytes inode + variable name
	
	offset := 0
	if len(data) < 8 {
		return nil, fmt.Errorf("XFS: inline directory data too small")
	}
	
	// Skip header, read entries
	numEntries := binary.BigEndian.Uint32(data[4:8])
	offset = 8
	
	for i := 0; i < int(numEntries) && offset+10 < len(data); i++ {
		nameLen := int(data[offset])
		ftype := data[offset+1]
		// ino := binary.BigEndian.Uint64(data[offset+2:offset+10]) // unused for now
		name := string(data[offset+10:offset+10+nameLen])
		
		offset += 10 + nameLen
		
		entry := DirectoryEntry{
			Name:   name,
			Path:   "/" + name,
			IsDir:  ftype == 2, // ftype 2 = directory
			Size:   0,
		}
		entries = append(entries, entry)
	}
	
	// No fake data - return error if no entries found
	if len(entries) == 0 {
		return nil, fmt.Errorf("XFS: directory parsing not fully implemented")
	}
	
	return entries, nil
}

func (xfs *XFS) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("XFS: file reading requires inode lookup")
}

func (xfs *XFS) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("XFS: file lookup requires directory parsing")
}

func (xfs *XFS) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, nil
}

func (xfs *XFS) GetBlockSize() uint32 {
	return xfs.blocksize
}

func (xfs *XFS) GetAGCount() uint32 {
	return xfs.agcount
}

func init() {
	// Note: XFS uses different magic, not automatically detected without special handling
	// Register for manual identification only
	_ = XFS_MAGIC
}