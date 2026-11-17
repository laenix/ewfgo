package detect

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// SquashFS filesystem implementation
// Reference: https://github.com/plougher/squashfs-tools/

type SquashFS struct {
	sMajor         uint16
	sMinor         uint64
	bytesUsed      uint64
	inodeCount     uint64
	directoryCount uint64
	idCount        uint64
	blocksize      uint32
	fragments      uint32
	compression    string
	fragmentBlock  uint64
	lookupTable    uint64
	directoryTable uint64
	xattrTable     uint64

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// SquashFS Super Block (at offset 96 from start, usually 96 bytes into 1K)
type SquashFSSuperblock struct {
	Magic              [4]byte   // "hsqs" (little-endian: 0x73717368)
	Inodes             uint64    // Number of inodes
	ModifiedTime       uint64    // Last modified time (seconds since epoch)
	BlockSize          uint32    // Block size (bytes)
	FragmentCount      uint64    // Number of fragments
	CompressedSize     uint64    // Total compressed data size
	DirectoryCount     uint64    // Number of directories
	IDCount            uint64    // Number of IDs
	MajorVersion       uint16    // Major version
	MinorVersion       uint16    // Minor version
	RootInodeRef       uint64    // Root inode reference
	NumberOfInodes     uint64    // Total number of inodes (including holes)
	BlockSize_2        uint32    // Block size (repeated)
	_                  [3]byte   // Compression ID (0=zlib, 1=lzo, 2=lz4, 3=xz, 4=zstd)
	_                  [4]byte   // Flags
	_NOID              uint64    // Number of ID's
	Ext3Incompatible   uint32    // Ext3 incompatible flags
	CompressionOptions [128]byte // Compression options
}

const SquashFSMagic = 0x73717368 // "hsqs"

func (sqfs *SquashFS) Type() filesystem.FileSystemType {
	return filesystem.FS_SQUASHFS
}

func (sqfs *SquashFS) Open(sectorData []byte) error {
	if len(sectorData) < 2048 {
		return fmt.Errorf("SquashFS: sector data too small")
	}

	// Try at offset 96 (standard location)
	var super SquashFSSuperblock
	err := binary.Read(bytes.NewReader(sectorData[96:224]), binary.LittleEndian, &super)
	if err == nil && super.Magic[0] == 'h' && super.Magic[1] == 's' {
		return sqfs.parseSuperBlock(&super)
	}

	// Try at offset 0 (if no header)
	err = binary.Read(bytes.NewReader(sectorData[:96]), binary.LittleEndian, &super)
	if err == nil && super.Magic[0] == 'h' && super.Magic[1] == 's' {
		return sqfs.parseSuperBlock(&super)
	}

	return fmt.Errorf("SquashFS: invalid magic")
}

func (sqfs *SquashFS) parseSuperBlock(super *SquashFSSuperblock) error {
	sqfs.sMajor = uint16(super.MajorVersion)
	sqfs.sMinor = uint64(super.MinorVersion)
	sqfs.bytesUsed = super.CompressedSize
	sqfs.inodeCount = super.Inodes
	sqfs.directoryCount = super.DirectoryCount
	sqfs.blocksize = super.BlockSize

	// Determine compression type from data after superblock would need more parsing
	return nil
}

func (sqfs *SquashFS) Close() error { return nil }

func (sqfs *SquashFS) GetVolumeLabel() string {
	return "" // SquashFS typically has no volume label
}

// ListDirectory on the reader-less SquashFS stub is an honest error: metadata
// parsing requires a reader. Canned entries would fabricate evidence.
func (sqfs *SquashFS) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	return nil, fmt.Errorf("SquashFS: directory parsing not yet implemented")
}

func (sqfs *SquashFS) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("SquashFS: file reading requires metadata parsing")
}

func (sqfs *SquashFS) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	return nil, fmt.Errorf("SquashFS: file lookup requires metadata parsing")
}

func (sqfs *SquashFS) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	return nil, fmt.Errorf("SquashFS: search requires metadata parsing")
}

func (sqfs *SquashFS) GetBlockSize() uint32 {
	return sqfs.blocksize
}

func init() {
	filesystem.RegisterFileSystem(filesystem.FS_SQUASHFS, func() filesystem.FileSystem {
		return &SquashFS{}
	})
}
