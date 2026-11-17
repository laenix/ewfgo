// Package jfs reads IBM JFS aggregates, read-only, from a source.ByteSource.
//
// It is a port of the Rust forensic-core JFS reader. The bootstrap chain is
// fixed by on-disk numbers rather than searched for:
//
//	superblock at byte 0x8000                     superblock.go
//	  -> aggregate inode table at 0xB000
//	    -> aggregate inode 2, the block map file  dmap.go
//	    -> aggregate inode 16, the fileset map    imap.go
//	      -> fileset inode 2, the root directory  dinode.go, dtree.go
//	        -> file data through extent trees      xtree.go, file.go
//
// Every read returns real bytes or an explicit error. Holes are the only zero
// bytes this reader manufactures, and they are holes the inode's own extent
// tree declares. A compressed extent, a block map with non-4-KiB pages, and a
// tree that loops are refused by name.
//
// Deliberately unported branches, each refused or reported rather than silently
// guessed at:
//
//   - log replay: an unclean aggregate is read as it sits on disk, and Info
//     reports the mount state;
//   - the secondary superblock at 0xF000 and the secondary aggregate inode
//     table: reported through Info.Ait2/Aim2 and the secondary-AIT flag, never
//     used to mount;
//   - compressed extents: ErrUnsupported;
//   - ACLs, extended attributes and the OS/2 extended-attribute area: their
//     descriptors are parsed but no content is read or exposed;
//   - recovery of freed inode slots or removed directory names: JFS removes a
//     name's entry when it is unlinked, so this reader lists live entries only
//     and reports no deleted-entry information.
package jfs

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxDirPages bounds a hostile directory tree.
const MaxDirPages = 65_536

// MaxPathDirectories bounds a whole-volume walk.
const MaxPathDirectories = 100_000

// MaxSymlinkBytes bounds a symbolic-link target read.
const MaxSymlinkBytes = 1 << 20

// VolumeStats is what a walk of the whole tree found.
type VolumeStats struct {
	Directories uint64
	Files       uint64
	Symlinks    uint64
	// Other counts sockets, devices, FIFOs and unknown modes.
	Other uint64
	// Entries counts live names, excluding "." and "..".
	Entries uint64
	// Unreadable counts names whose inode could not be read.
	Unreadable uint64
}

// Info is a volume's report.
type Info struct {
	Version uint32
	Offset  uint64

	SizeRaw      uint64
	SizeBlocks   uint64
	VolumeBlocks uint64
	Truncated    bool

	BlockSize uint32
	L2Bsize   uint16
	L2Bfactor uint16
	Pbsize    uint32
	L2Pbsize  uint16
	AGSize    uint32

	Flags     uint32
	FlagNames []string
	State     uint32
	StateName string
	Clean     bool
	Compress  uint32

	Ait2 Pxd
	Aim2 Pxd

	LogDev     uint32
	LogSerial  uint32
	LogPxd     Pxd
	FsckPxd    Pxd
	Time       Timestamp
	FsckLogLen uint32
	FsckLog    int8

	Fpack   string
	UUID    string
	Label   string
	LogUUID string

	HasDirectoryIndex bool
	IsOS2             bool
	HasInlineLog      bool
	SecondaryAITBad   bool
}

// Entry is one file or directory in a volume.
type Entry struct {
	Name        string
	Path        string
	Inode       uint32
	ParentInode uint32
	IsDir       bool
	IsFile      bool
	IsSymlink   bool
	Size        uint64
	Mode        uint32
	UID         uint32
	GID         uint32
	Links       uint32
	FileType    string

	Atime time.Time
	Ctime time.Time
	Mtime time.Time
	Otime time.Time

	// SymlinkTarget is filled for symbolic links.
	SymlinkTarget string

	// Deleted is always false for JFS: the format removes a name's entry when
	// it is unlinked, so no deleted name is provable here.
	Deleted bool
}

// Volume is an opened JFS aggregate.
type Volume struct {
	source       source.ByteSource
	superblock   *Superblock
	volumeBlocks uint64
	fileset      *inodeMap
	blockMap     *blockMap
	root         *LocatedInode
	fileID       atomic.Uint64
}

// Detect reports whether src looks like a JFS aggregate without mounting it.
func Detect(src source.ByteSource) (bool, error) {
	sb, err := DetectSuperblock(src)
	if err != nil {
		return false, err
	}
	return sb != nil, nil
}

// Open proves an aggregate through its bootstrap chain and returns it.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := ReadSuperblock(src)
	if err != nil {
		return nil, err
	}
	sizeBlocks := sb.SizeBlocks()
	if sizeBlocks == 0 {
		return nil, corruptf("the superblock records an empty aggregate")
	}
	if sb.Flags&JFSSwapBytes != 0 {
		return nil, unsupportedf("a byte-swapped aggregate (JFS_SWAP_BYTES); this reader decodes only the native little-endian layout")
	}
	present := src.Len() / BlockSize
	if present == 0 {
		return nil, corruptf("the source is shorter than one 4 KiB block")
	}
	volumeBlocks := sizeBlocks
	if present < volumeBlocks {
		volumeBlocks = present
	}

	bmapInode, err := readAggregateInode(src, BlockMapInode)
	if err != nil {
		return nil, err
	}
	blockMap, err := openBlockMap(src, volumeBlocks, bmapInode)
	if err != nil {
		return nil, err
	}
	if blockMap.control.MapSize != sizeBlocks {
		return nil, corruptf("the block map covers %d blocks but the superblock records %d",
			blockMap.control.MapSize, sizeBlocks)
	}
	fileset, err := openFilesetMap(src, volumeBlocks)
	if err != nil {
		return nil, err
	}
	root, err := fileset.resolveInode(src, volumeBlocks, RootInode)
	if err != nil {
		return nil, err
	}
	volume := &Volume{
		source:       src,
		superblock:   sb,
		volumeBlocks: volumeBlocks,
		fileset:      fileset,
		blockMap:     blockMap,
		root:         root,
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	if err := volume.probe(); err != nil {
		return nil, err
	}
	return volume, nil
}

// Info returns the volume's report.
func (v *Volume) Info() Info {
	sb := v.superblock
	return Info{
		Version:           sb.Version,
		Offset:            sb.Offset,
		SizeRaw:           sb.SizeRaw,
		SizeBlocks:        sb.SizeBlocks(),
		VolumeBlocks:      v.volumeBlocks,
		Truncated:         v.volumeBlocks < sb.SizeBlocks(),
		BlockSize:         sb.BlockSize,
		L2Bsize:           sb.L2Bsize,
		L2Bfactor:         sb.L2Bfactor,
		Pbsize:            sb.Pbsize,
		L2Pbsize:          sb.L2Pbsize,
		AGSize:            sb.AGSize,
		Flags:             sb.Flags,
		FlagNames:         sb.FlagNames(),
		State:             sb.State,
		StateName:         sb.StateName(),
		Clean:             sb.IsClean(),
		Compress:          sb.Compress,
		Ait2:              sb.Ait2,
		Aim2:              sb.Aim2,
		LogDev:            sb.LogDev,
		LogSerial:         sb.LogSerial,
		LogPxd:            sb.LogPxd,
		FsckPxd:           sb.FsckPxd,
		Time:              sb.Time,
		FsckLogLen:        sb.FsckLogLen,
		FsckLog:           sb.FsckLog,
		Fpack:             sb.FpackText(),
		UUID:              sb.UUIDText(),
		Label:             sb.LabelText(),
		LogUUID:           sb.LogUUIDText(),
		HasDirectoryIndex: sb.HasDirectoryIndex(),
		IsOS2:             sb.IsOS2(),
		HasInlineLog:      sb.HasInlineLog(),
		SecondaryAITBad:   sb.SecondaryAITBad(),
	}
}

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// BlockSize returns the volume's block size.
func (v *Volume) BlockSize() uint32 { return BlockSize }

// VolumeBlocks returns the blocks the image actually holds.
func (v *Volume) VolumeBlocks() uint64 { return v.volumeBlocks }

// IsTruncated reports whether the image ends before the aggregate's end.
func (v *Volume) IsTruncated() bool { return v.volumeBlocks < v.superblock.SizeBlocks() }

// IsClean reports whether the aggregate was cleanly unmounted.
func (v *Volume) IsClean() bool { return v.superblock.IsClean() }

// Inode resolves one inode number through the fileset map.
func (v *Volume) Inode(number uint32) (*LocatedInode, error) {
	return v.fileset.resolveInode(v.source, v.volumeBlocks, number)
}

func (v *Volume) readDirInode(inode *Dinode) ([]DirEntry, error) {
	return readDirectory(v.source, v.volumeBlocks, inode.DirectoryTreeRoot(),
		v.superblock.HasDirectoryIndex(), MaxDirPages)
}

func (v *Volume) lookup(directory uint32, name string) (*DirEntry, error) {
	located, err := v.Inode(directory)
	if err != nil {
		return nil, err
	}
	entries, err := v.readDirInode(located.Inode)
	if err != nil {
		return nil, err
	}
	for index := range entries {
		if entries[index].Name == name {
			return &entries[index], nil
		}
	}
	return nil, nil
}

// LookupPath resolves an absolute or root-relative path to an inode number.
// The bool is false when a component does not exist.
func (v *Volume) LookupPath(path string) (uint32, bool, error) {
	current := RootInode
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			parent := RootInode
			entry, err := v.lookup(current, "..")
			if err != nil {
				return 0, false, err
			}
			if entry != nil && entry.Inode != 0 {
				parent = entry.Inode
			}
			current = parent
			continue
		}
		entry, err := v.lookup(current, component)
		if err != nil {
			return 0, false, err
		}
		if entry == nil {
			return 0, false, nil
		}
		current = entry.Inode
	}
	return current, true, nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	located, err := v.Inode(number)
	if err != nil {
		return nil, err
	}
	name := pathName(path)
	clean := cleanPath(path, number == RootInode)
	if number == RootInode {
		name = "/"
	}
	entry := v.entryFromInode(name, clean, located.Inode)
	if located.Inode.IsSymlink() {
		target, err := v.symlinkTarget(located)
		if err != nil {
			return nil, err
		}
		entry.SymlinkTarget = target
	}
	return &entry, nil
}

// ListDir lists a directory's entries, excluding "." and "..".
func (v *Volume) ListDir(path string) ([]Entry, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	directory, err := v.Inode(number)
	if err != nil {
		return nil, err
	}
	if !directory.Inode.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	entries, err := v.readDirInode(directory.Inode)
	if err != nil {
		return nil, err
	}
	base := cleanPath(path, number == RootInode)
	out := make([]Entry, 0, len(entries))
	for _, dirEntry := range entries {
		if dirEntry.Name == "." || dirEntry.Name == ".." {
			continue
		}
		child, err := v.Inode(dirEntry.Inode)
		if err != nil {
			return nil, err
		}
		childPath := "/" + dirEntry.Name
		if base != "/" {
			childPath = base + "/" + dirEntry.Name
		}
		entry := v.entryFromInode(dirEntry.Name, childPath, child.Inode)
		entry.ParentInode = number
		if child.Inode.IsSymlink() {
			target, err := v.symlinkTarget(child)
			if err != nil {
				return nil, err
			}
			entry.SymlinkTarget = target
		}
		out = append(out, entry)
	}
	return out, nil
}

// OpenFile opens the file named by path as a byte source.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	located, err := v.Inode(number)
	if err != nil {
		return nil, err
	}
	if located.Inode.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	mapData, err := buildFileMap(v.source, v.volumeBlocks, located.Inode, located.Offset, MaxFilePages)
	if err != nil {
		return nil, err
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.source, mapData, number), nil
}

// SymlinkTarget returns the target of the symbolic link named by path.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	located, err := v.Inode(number)
	if err != nil {
		return "", err
	}
	if !located.Inode.IsSymlink() {
		return "", fmt.Errorf("%w: inode %d", ErrNotSymlink, number)
	}
	return v.symlinkTarget(located)
}

func (v *Volume) symlinkTarget(located *LocatedInode) (string, error) {
	if located.Inode.IsFastSymlink() {
		return trimTrailingNULs(string(located.Inode.FastSymlinkBytes())), nil
	}
	size := located.Inode.Size()
	if size > MaxSymlinkBytes {
		return "", unsupportedf("a %d-byte symbolic-link target, above the %d-byte limit", size, MaxSymlinkBytes)
	}
	if size > v.source.Len() {
		return "", corruptf("symbolic link inode %d claims %d target bytes but the image holds %d",
			located.Inode.Number(), size, v.source.Len())
	}
	mapData, err := buildFileMap(v.source, v.volumeBlocks, located.Inode, located.Offset, MaxFilePages)
	if err != nil {
		return "", err
	}
	buf := make([]byte, int(size))
	if _, err := mapData.readAt(v.source, 0, buf); err != nil {
		return "", err
	}
	return trimTrailingNULs(string(buf)), nil
}

// Stats counts the whole tree.
func (v *Volume) Stats() (VolumeStats, error) {
	var stats VolumeStats
	pending := []uint32{RootInode}
	seen := map[uint32]bool{RootInode: true}
	for len(pending) > 0 {
		directory := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		stats.Directories++
		located, err := v.Inode(directory)
		if err != nil {
			return stats, err
		}
		entries, err := v.readDirInode(located.Inode)
		if err != nil {
			return stats, err
		}
		for _, dirEntry := range entries {
			if dirEntry.Name == "." || dirEntry.Name == ".." {
				continue
			}
			stats.Entries++
			child, err := v.Inode(dirEntry.Inode)
			if err != nil {
				stats.Unreadable++
				continue
			}
			switch {
			case child.Inode.IsDir():
				if !seen[dirEntry.Inode] {
					seen[dirEntry.Inode] = true
					pending = append(pending, dirEntry.Inode)
				}
			case child.Inode.IsRegular():
				stats.Files++
			case child.Inode.IsSymlink():
				stats.Symlinks++
			default:
				stats.Other++
			}
		}
	}
	return stats, nil
}

// FreeSpace scans the aggregate's block map.
func (v *Volume) FreeSpace() (*FreeMap, error) {
	return v.blockMap.freeSpace(v.source, v.source.Len(), v.superblock.IsClean())
}

func (v *Volume) probe() error {
	if !v.root.Inode.IsDir() {
		return corruptf("the root inode (%d) is a %s, not a directory", RootInode, v.root.Inode.FileTypeName())
	}
	if err := validateDirRoot(v.root.Inode.DirectoryTreeRoot()); err != nil {
		return err
	}
	entries, err := v.readDirInode(v.root.Inode)
	if err != nil {
		return err
	}
	var hasDot, hasDotDot bool
	for _, entry := range entries {
		switch entry.Name {
		case ".":
			hasDot = true
		case "..":
			hasDotDot = true
		}
	}
	if !hasDot {
		return corruptf("the root directory has no `.` entry")
	}
	if !hasDotDot {
		return corruptf("the root directory has no `..` entry")
	}
	return nil
}

func (v *Volume) entryFromInode(name, path string, inode *Dinode) Entry {
	return Entry{
		Name:      name,
		Path:      path,
		Inode:     inode.Number(),
		IsDir:     inode.IsDir(),
		IsFile:    inode.IsRegular(),
		IsSymlink: inode.IsSymlink(),
		Size:      inode.Size(),
		Mode:      inode.Mode(),
		UID:       inode.UID(),
		GID:       inode.GID(),
		Links:     inode.Nlink(),
		FileType:  inode.FileTypeName(),
		Atime:     timestampTime(inode.Atime()),
		Ctime:     timestampTime(inode.Ctime()),
		Mtime:     timestampTime(inode.Mtime()),
		Otime:     timestampTime(inode.Otime()),
	}
}

func timestampTime(t Timestamp) time.Time {
	return time.Unix(int64(t.Sec), int64(t.Nsec)).UTC()
}

func trimTrailingNULs(text string) string {
	end := len(text)
	for end > 0 && text[end-1] == 0 {
		end--
	}
	return text[:end]
}

func pathName(path string) string {
	clean := strings.TrimRight(path, "/")
	if clean == "" {
		return "/"
	}
	if index := strings.LastIndexByte(clean, '/'); index >= 0 {
		return clean[index+1:]
	}
	return clean
}

func cleanPath(path string, root bool) string {
	if root {
		return "/"
	}
	var parts []string
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		parts = append(parts, component)
	}
	return "/" + strings.Join(parts, "/")
}
