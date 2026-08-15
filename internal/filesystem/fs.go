package filesystem

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Sentinel errors returned (possibly wrapped) by filesystem handlers and the
// ImageFS bridge. A consumer distinguishes forensic outcomes with errors.Is:
// a missing file (ErrNotFound) is a different finding than an unsupported
// filesystem/parser path (ErrUnsupported) or a path that exists but is not a
// regular file (ErrIsDirectory / ErrNotDirectory). Handlers return these
// sentinels; the ImageFS bridge wraps them with %w so errors.Is unwraps
// through the contextual partition/path prefix.
var (
	// ErrNotFound is returned when a path component or file does not exist.
	ErrNotFound = errors.New("not found")
	// ErrUnsupported is returned when the filesystem or parser path is not
	// implemented (detection-only filesystems, unimplemented attribute lists).
	ErrUnsupported = errors.New("unsupported")
	// ErrIsDirectory is returned when a file operation targets a directory.
	ErrIsDirectory = errors.New("is a directory")
	// ErrNotDirectory is returned when a directory operation targets a file.
	ErrNotDirectory = errors.New("not a directory")
)

// FileOpener is implemented by filesystem handlers that can open a file for
// streaming reads — a lazy, seekable io.ReadSeekCloser whose reads hit only the
// clusters/extents intersecting the accessed byte range (memory O(block), not
// O(file)). The ImageFS bridge type-asserts handlers against it; a handler
// without streaming support returns an explicit unsupported error instead.
type FileOpener interface {
	OpenFile(path string) (io.ReadSeekCloser, error)
}

// InodeOpener is the handle-based sibling of FileOpener. A walk that lists a
// directory already resolves each entry to the filesystem's native handle
// (inode, MFT record, first cluster — surfaced as DirectoryEntry.Inode /
// .Cluster), so opening by handle avoids re-resolving the full path through
// every directory block. On large trees that re-resolution dominates extraction
// cost, so consumers should prefer OpenInode when the handle is available.
//
// size is the file's byte size as reported by the directory entry. The
// inode-based filesystems (ext4, NTFS, APFS, Btrfs, XFS) read it from their own
// inode/record and ignore it; FAT/exFAT need it because the FAT directory entry
// is where the size lives.
type InodeOpener interface {
	OpenInode(inode uint64, size int64) (io.ReadSeekCloser, error)
}

// Reader is an interface for reading sector data from a disk image. It is the
// seam every reader-based handler reads through; the ewf package's internal
// decompressor satisfies it structurally.
type Reader interface {
	ReadSectors(lba uint64, count uint64) ([]byte, error)
}

// FileSystemType represents the type of filesystem
type FileSystemType string

const (
	FS_NTFS       FileSystemType = "NTFS"
	FS_EXT2       FileSystemType = "ext2"
	FS_EXT3       FileSystemType = "ext3"
	FS_EXT4       FileSystemType = "ext4"
	FS_FAT12      FileSystemType = "FAT12"
	FS_FAT16      FileSystemType = "FAT16"
	FS_FAT32      FileSystemType = "FAT32"
	FS_EXFAT      FileSystemType = "exFAT"
	FS_HFS        FileSystemType = "HFS+"
	FS_APFS       FileSystemType = "APFS"
	FS_BTRFS      FileSystemType = "Btrfs"
	FS_XFS        FileSystemType = "XFS"
	FS_F2FS       FileSystemType = "F2FS"
	FS_SQUASHFS   FileSystemType = "SquashFS"
	FS_REFS       FileSystemType = "ReFS"
	FS_BITLOCKER  FileSystemType = "BitLocker"
	FS_LUKS       FileSystemType = "LUKS"
	FS_ZFS        FileSystemType = "ZFS"
	FS_RAID       FileSystemType = "RAID"
	FS_JFS        FileSystemType = "JFS"
	FS_UFS        FileSystemType = "UFS"
	FS_UNKNOWN    FileSystemType = "Unknown"
)

// FileMode represents file/directory permissions
type FileMode uint16

const (
	ModeDir       FileMode = 0x4000
	ModeRegular   FileMode = 0x8000
	ModeSymlink   FileMode = 0xA000
	ModeCharacter FileMode = 0x2000
	ModeBlock     FileMode = 0x6000
	ModeFIFO      FileMode = 0x1000
	ModeSocket    FileMode = 0xC000
)

// FileInfo contains metadata about a file or directory
type FileInfo struct {
	Name       string
	Path       string
	Size       uint64
	Mode       FileMode
	IsDir      bool
	ModTime    int64
	AccessTime int64
	CreateTime int64
	IsHidden   bool
	IsSystem   bool
	IsReadOnly bool
}

// DirectoryEntry represents an entry in a directory
type DirectoryEntry struct {
	Name     string
	Path     string
	Size     uint64
	IsDir    bool
	ModTime  int64
	// AccessTime is the last-access time in Unix seconds (0 when the format
	// stores none, e.g. FAT's access date has no time-of-day component).
	AccessTime int64
	// CreateTime is the file-creation time in Unix seconds (0 when absent).
	CreateTime int64
	// For FAT32: cluster number for subdirectory
	Cluster uint32
	// For XFS: inode number
	Inode uint64
}

// FileSystem is the interface that must be implemented by filesystem handlers
type FileSystem interface {
	Type() FileSystemType
	Open(sectorData []byte) error
	Close() error
	ListDirectory(path string) ([]DirectoryEntry, error)
	GetFile(path string) ([]byte, error)
	GetFileByPath(path string) (*FileInfo, error)
	SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error)
	GetVolumeLabel() string
}

// DetectFileSystem detects the filesystem type from boot sector data.
//
// This is the single source of truth for filesystem detection: the public
// DetectFileSystem in the ewf package (open.go) delegates here. The btrfs
// superblock magic "_BHRfS_M" lives at byte offset 0x10040 (64 KiB + 0x40), so
// callers must provide a read window of at least 0x10048 bytes (129 sectors)
// to detect btrfs. The ext4 s_magic (0xEF53, little-endian) sits at offset
// 0x38 within the superblock, which always starts at byte 1024 from the
// partition start for every block size.
func DetectFileSystem(sectorData []byte) FileSystemType {
	if len(sectorData) < 512 {
		return FS_UNKNOWN
	}

	// Check NTFS (signature at offset 3)
	if len(sectorData) >= 8 && string(sectorData[3:7]) == "NTFS" {
		return FS_NTFS
	}

	// Check FAT32 ("FAT32   " at offset 0x52)
	if len(sectorData) >= 0x5A && string(sectorData[0x52:0x5A]) == "FAT32   " {
		return FS_FAT32
	}

	// Check FAT16 ("FAT16   " at offset 0x36)
	if len(sectorData) >= 0x3E && string(sectorData[0x36:0x3E]) == "FAT16   " {
		return FS_FAT16
	}

	// Check FAT12 (FS type field starts with "FAT1" at offset 0x36)
	if len(sectorData) >= 0x3E && string(sectorData[0x36:0x3A]) == "FAT1" {
		return FS_FAT12
	}

	// Check exFAT ("EXFAT   " at offset 3)
	if len(sectorData) >= 11 && string(sectorData[3:11]) == "EXFAT   " {
		return FS_EXFAT
	}

	// Check HFS+ (Apple TN1150: the volume header at byte 1024 holds the
	// 16-bit big-endian signature "H+" 0x482B / "HX" 0x4858 followed by the
	// 16-bit big-endian version 0x0004 / 0x0005)
	if len(sectorData) >= 1152 {
		switch binary.BigEndian.Uint32(sectorData[1024:1028]) {
		case 0x482B0004, 0x48580005: // "H+" v4, "HX" v5
			return FS_HFS
		}
	}

	// Check APFS (Apple File System Reference: the container superblock starts
	// at partition offset 0 and its 4-byte NXSB magic sits at offset 0x20,
	// after the 32-byte obj_phys header). In-window for the 4096-byte GPT
	// caller.
	if len(sectorData) >= 0x24 && string(sectorData[0x20:0x24]) == "NXSB" {
		return FS_APFS
	}

	// Check ext2/3/4 (s_magic 0xEF53 little-endian at offset 0x38 within the
	// superblock; the superblock always starts at byte 1024 from the partition
	// start — block 0 holds the 1024-byte boot block)
	if len(sectorData) >= 1024+0x3A &&
		binary.LittleEndian.Uint16(sectorData[1024+0x38:1024+0x3A]) == 0xEF53 {
		return FS_EXT4
	}

	// Check XFS ("XFSB", big-endian superblock at offset 0) with field
	// validation so a stray "XFSB" in unrelated data is not a false positive.
	if len(sectorData) >= 4 && string(sectorData[:4]) == "XFSB" {
		if len(sectorData) >= 512 {
			blocksize := binary.BigEndian.Uint32(sectorData[4:8])
			blocks := binary.BigEndian.Uint64(sectorData[8:16])
			agcount := binary.BigEndian.Uint32(sectorData[32:36])
			agblocks := binary.BigEndian.Uint32(sectorData[36:40])

			// Validate: blocksize should be a power of 2 between 512-65536
			validBlocksize := blocksize >= 512 && blocksize <= 65536 && (blocksize&(blocksize-1)) == 0
			// blocks should be > 0
			validBlocks := blocks > 0
			// agcount should be reasonable (1-100)
			validAGCount := agcount > 0 && agcount <= 100
			// agblocks should be reasonable
			validAGBlocks := agblocks > 100 && agblocks < 100000

			if validBlocksize && validBlocks && validAGCount && validAGBlocks {
				return FS_XFS
			}
			if validBlocksize {
				return FS_XFS
			}
		}
		return FS_UNKNOWN // XFSB magic found but superblock fields invalid
	}

	// Check SquashFS ("hsqs" at offset 96)
	if len(sectorData) >= 100 && string(sectorData[96:100]) == "hsqs" {
		return FS_SQUASHFS
	}

	// Check F2FS ("F2FS" at offset 0)
	if len(sectorData) >= 4 && string(sectorData[:4]) == "F2FS" {
		return FS_F2FS
	}

	// Check Btrfs (superblock magic "_BHRfS_M" at offset 0x10040)
	if len(sectorData) >= 0x10048 && string(sectorData[0x10040:0x10048]) == "_BHRfS_M" {
		return FS_BTRFS
	}

	// Check ReFS ("ReFS" or "ReFSB" at offset 3)
	if len(sectorData) >= 9 && (string(sectorData[3:7]) == "ReFS" || string(sectorData[3:8]) == "ReFSB") {
		return FS_REFS
	}

	// Check LUKS (magic "LUKS" at offset 0)
	if len(sectorData) >= 8 && string(sectorData[0:6]) == "LUKS" {
		return FS_LUKS
	}

	// Check ZFS (magic "ZFS " at offset 0x84)
	if len(sectorData) >= 136 && string(sectorData[0x84:0x88]) == "ZFS " {
		return FS_ZFS
	}

	// Check JFS (magic "JFS1" at offset 0x8000)
	if len(sectorData) >= 0x8004 && string(sectorData[0x8000:0x8004]) == "JFS1" {
		return FS_JFS
	}

	return FS_UNKNOWN
}

// DetectFileSystemFromGPT detects filesystem from GPT partition type GUID
func DetectFileSystemFromGPT(partitionTypeGUID string) FileSystemType {
	switch partitionTypeGUID {
	case "6DFD5706ABA4C44384E5933C69E4D7B9":
		return FS_EXT4
	}
	return FS_UNKNOWN
}

// FileSystemRegistry is a registry of available filesystem handlers.
//
// There are two registries, one per handler mode, both populated by each
// filesystem subpackage's init():
//
//   - filesystemRegistry: reader-less factories backing NewFileSystem /
//     DetectAndOpen. A factory returns the handler with no reader set, whose
//     directory/data operations all return an explicit error — the
//     defabrication gate (no handler may produce data without a reader).
//   - handlerRegistry: reader-based factories backing NewHandler, the seam the
//     ewf package opens filesystems through (OpenFileSystem).
//
// The parent filesystem package never imports the subpackages (that would be
// an import cycle: every subpackage imports the parent). Subpackage init()
// side effects fire when the root ewf package blank-imports them.
var filesystemRegistry = make(map[FileSystemType]func() FileSystem)

// RegisterFileSystem registers a reader-less filesystem factory.
func RegisterFileSystem(fsType FileSystemType, factory func() FileSystem) {
	filesystemRegistry[fsType] = factory
}

// NewFileSystem creates a new filesystem instance based on type
func NewFileSystem(fsType FileSystemType) (FileSystem, error) {
	factory, ok := filesystemRegistry[fsType]
	if !ok {
		return nil, fmt.Errorf("unsupported filesystem type: %s", fsType)
	}
	return factory(), nil
}

// HandlerFactory builds a reader-based filesystem handler. partitionSize is
// the partition size in bytes; only the FAT handler needs it (the others read
// their own geometry from the superblock).
type HandlerFactory func(r Reader, startLBA, partitionSize uint64) (FileSystem, error)

// handlerRegistry maps a filesystem type to its reader-based constructor.
var handlerRegistry = make(map[FileSystemType]HandlerFactory)

// RegisterHandler registers a reader-based filesystem constructor.
func RegisterHandler(fsType FileSystemType, factory HandlerFactory) {
	handlerRegistry[fsType] = factory
}

// NewHandler builds a reader-based handler for fsType. Types without a
// reader-based implementation (detection-only) return an explicit error.
func NewHandler(fsType FileSystemType, r Reader, startLBA, partitionSize uint64) (FileSystem, error) {
	factory, ok := handlerRegistry[fsType]
	if !ok {
		return nil, fmt.Errorf("unsupported filesystem type: %s", fsType)
	}
	return factory(r, startLBA, partitionSize)
}

// RegisteredFileSystems returns the sorted list of filesystem types that have
// a registered handler (reader-less or reader-based). The defabrication-gate
// test iterates it to enforce that every registered handler errors honestly
// when no reader is present.
func RegisteredFileSystems() []FileSystemType {
	types := make([]FileSystemType, 0, len(filesystemRegistry))
	for t := range filesystemRegistry {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

// DetectAndOpen detects filesystem type and opens it with appropriate handler
func DetectAndOpen(sectorData []byte) (FileSystem, error) {
	fsType := DetectFileSystem(sectorData)
	if fsType == FS_UNKNOWN {
		return nil, fmt.Errorf("cannot detect filesystem type")
	}

	fs, err := NewFileSystem(fsType)
	if err != nil {
		return nil, err
	}

	if err := fs.Open(sectorData); err != nil {
		return nil, err
	}

	return fs, nil
}