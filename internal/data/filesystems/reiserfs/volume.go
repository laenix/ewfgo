// Package reiserfs reads ReiserFS 3.5 and 3.6 volumes, read-only, from a
// source.ByteSource.
//
// It is a port of the Rust forensic-core ReiserFS reader. ReiserFS keeps no
// inode table: every object is described by items in a B* tree, and a directory
// is an item whose body is a list of names.
//
//	superblock at byte 8192 or 65536              superblock.go
//	  -> the B* tree of the volume                node.go
//	    -> item heads and keys                    item.go
//	      -> stat data, the "inode"               stat.go
//	      -> directory items                      dir.go
//	      -> direct and indirect file bodies      file.go
//	        -> the mounted volume                 volume.go
//
// Names are found by scanning a directory's items, so the recorded hash
// function (unset, tea, rupasov, r5) is reported but never needed to enumerate.
// An unknown hash code is refused with ErrUnsupported. Direct items hold a
// packed tail; indirect items hold block pointers, with a zero pointer as a
// hole.
//
// Deliberately unported branches, each refused or reported rather than silently
// guessed at:
//
//   - journal replay: an unclean volume is read as it sits on disk;
//   - hash computation: directory items are scanned, so tea/rupasov/r5 need no
//     implementation; codes outside 0..3 are ErrUnsupported;
//   - extended attributes and ACLs: not decoded or exposed;
//   - free-block residue recovery (the reference's deleted.rs): DeletedScan
//     returns ErrUnsupported; hidden names, the format's directory-level
//     deletion evidence, are still listed by ListDir with Deleted set.
package reiserfs

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The root directory's object ids.
const (
	// RootObjectID is the root directory.
	RootObjectID uint32 = 2
	// RootParentObjectID is the root's recorded parent.
	RootParentObjectID uint32 = 1
)

// MaxPathDirectories bounds a whole-volume path search.
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
	// Entries counts live names, excluding ".", ".." and hidden entries.
	Entries uint64
	// RemovedNames counts hidden names left by a removal.
	RemovedNames uint64
	// Unreadable counts visible names whose object has no readable stat data.
	Unreadable uint64
	// FlaggedNames counts entries fsck marked with a bad offset or location.
	FlaggedNames uint64
}

// Info is a volume's report.
type Info struct {
	Version FsVersion
	Kind    string
	Offset  uint64

	BlockSize  uint32
	BlockCount uint32
	FreeBlocks uint32
	RootBlock  uint32

	JournalBlock        uint32
	JournalDev          uint32
	JournalSize         uint32
	JournalTransMax     uint32
	JournalBlockCount   uint32
	JournalMaxBatch     uint32
	JournalMaxCommitAge uint32
	JournalMaxTransAge  uint32

	OIDMaxSize uint16
	OIDCurSize uint16

	UmountState         uint16
	UmountStateName     string
	FSState             uint16
	FSStateName         string
	Clean               bool
	NotCleanlyUnmounted bool

	Hash     HashFunction
	HashName string

	TreeHeight         uint16
	BmapCount          uint32
	DiskVersion        uint16
	ReservedForJournal uint16
	InodeGeneration    uint32
	Flags              uint32
	AttributesCleared  bool

	UUID  string
	Label string

	MountCount    *uint16
	MaxMountCount *uint16
	LastCheck     *uint32
	CheckInterval *uint32
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
	Mode        uint16
	UID         uint32
	GID         uint32
	Links       uint32
	FileType    string

	Atime time.Time
	Ctime time.Time
	Mtime time.Time

	// SymlinkTarget is filled for symbolic links.
	SymlinkTarget string

	// Deleted is set for a hidden name: the format's directory-level deletion
	// evidence. A hidden name may still have readable stat data.
	Deleted bool
	// Hidden is the on-disk visibility bit, clear on a removed name.
	Hidden bool
	// Flagged reports fsck's bad-offset or bad-location mark.
	Flagged     bool
	BadOffset   bool
	BadLocation bool
	// HashOffset is the deh_offset hash word the name was sorted by.
	HashOffset uint32
	// Unreadable reports that no stat data item was found for the object.
	Unreadable bool

	DeviceNumber *uint32
	Generation   *uint32
	Blocks       *uint32
}

// Volume is an opened ReiserFS volume.
type Volume struct {
	source     source.ByteSource
	superblock *Superblock
	fileID     atomic.Uint64
}

// Detect reports whether src looks like a ReiserFS volume without mounting it.
func Detect(src source.ByteSource) (bool, error) {
	sb, err := DetectSuperblock(src)
	if err != nil {
		return false, err
	}
	return sb != nil, nil
}

// Open finds the superblock, validates it and proves the tree.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := ReadSuperblock(src)
	if err != nil {
		return nil, err
	}
	volume := &Volume{source: src, superblock: sb}
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
		Version:             sb.Version,
		Kind:                sb.Kind(),
		Offset:              sb.Offset,
		BlockSize:           sb.BlockSize,
		BlockCount:          sb.BlockCount,
		FreeBlocks:          sb.FreeBlocks,
		RootBlock:           sb.RootBlock,
		JournalBlock:        sb.JournalBlock,
		JournalDev:          sb.JournalDev,
		JournalSize:         sb.JournalSize,
		JournalTransMax:     sb.JournalTransMax,
		JournalBlockCount:   sb.JournalBlockCount,
		JournalMaxBatch:     sb.JournalMaxBatch,
		JournalMaxCommitAge: sb.JournalMaxCommitAge,
		JournalMaxTransAge:  sb.JournalMaxTransAge,
		OIDMaxSize:          sb.OIDMaxSize,
		OIDCurSize:          sb.OIDCurSize,
		UmountState:         sb.UmountState,
		UmountStateName:     sb.UmountStateName(),
		FSState:             sb.FSState,
		FSStateName:         sb.FSStateName(),
		Clean:               sb.IsClean(),
		NotCleanlyUnmounted: sb.WasNotCleanlyUnmounted(),
		Hash:                sb.Hash,
		HashName:            sb.Hash.Name(),
		TreeHeight:          sb.TreeHeight,
		BmapCount:           sb.BmapCount,
		DiskVersion:         sb.DiskVersion,
		ReservedForJournal:  sb.ReservedForJournal,
		InodeGeneration:     sb.InodeGeneration,
		Flags:               sb.Flags,
		AttributesCleared:   sb.AttributesCleared(),
		UUID:                sb.UUIDText(),
		Label:               sb.Label,
		MountCount:          sb.MountCount,
		MaxMountCount:       sb.MaxMountCount,
		LastCheck:           sb.LastCheck,
		CheckInterval:       sb.CheckInterval,
	}
}

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// Kind returns "reiserfs3.5" or "reiserfs3.6".
func (v *Volume) Kind() string { return v.superblock.Kind() }

// Version returns the format generation.
func (v *Volume) Version() FsVersion { return v.superblock.Version }

// Label returns the volume label.
func (v *Volume) Label() string { return v.superblock.Label }

// UUIDText returns the volume UUID in dashed form.
func (v *Volume) UUIDText() string { return v.superblock.UUIDText() }

// Hash returns the recorded name-hash function.
func (v *Volume) Hash() HashFunction { return v.superblock.Hash }

// BlockSize returns bytes in one block.
func (v *Volume) BlockSize() uint32 { return v.superblock.BlockSize }

// VolumeLen returns the bytes the filesystem spans.
func (v *Volume) VolumeLen() uint64 { return v.superblock.VolumeLen() }

// RootObjectID returns the root directory's object id.
func (v *Volume) RootObjectID() uint32 { return RootObjectID }

// IsClean reports whether both state fields agree the volume was clean.
func (v *Volume) IsClean() bool { return v.superblock.IsClean() }

// WasNotCleanlyUnmounted reports the unmount-state field.
func (v *Volume) WasNotCleanlyUnmounted() bool { return v.superblock.WasNotCleanlyUnmounted() }

// FreeSpace scans the volume's allocation bitmaps.
func (v *Volume) FreeSpace() (*FreeMap, error) {
	return freeSpace(v.source, v.superblock)
}

// DeletedScan reports that the reference reader's free-block residue scan
// (deleted.rs) is not ported. Hidden directory names remain available through
// ListDir with Entry.Deleted set.
func (v *Volume) DeletedScan() error {
	return unsupportedf("free-block residue recovery (the reference deleted.rs scan) is not ported; hidden names are reported by ListDir")
}

func (v *Volume) keyVersion() KeyVersion {
	if v.superblock.Version.KeysAreV2() {
		return KeyVersionV2
	}
	return KeyVersionV1
}

// readBlock reads one complete filesystem block.
func (v *Volume) readBlock(block uint32) ([]byte, error) {
	offset, err := v.superblock.BlockOffset(block)
	if err != nil {
		return nil, err
	}
	return source.ReadVecAt(v.source, offset, uint64(v.superblock.BlockSize))
}

// items walks the whole tree and returns every item in key order.
func (v *Volume) items() ([]LeafItem, error) {
	keyVersion := v.keyVersion()
	blockSize := int(v.superblock.BlockSize)
	var items []LeafItem
	seen := make(map[uint32]bool)
	stack := []uint32{v.superblock.RootBlock}
	for len(stack) > 0 {
		block := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if block >= v.superblock.BlockCount {
			return nil, corruptf("tree node %d is outside the volume's %d blocks", block, v.superblock.BlockCount)
		}
		if seen[block] {
			return nil, corruptf("tree loop: block %d is reachable more than once", block)
		}
		seen[block] = true
		raw, err := v.readBlock(block)
		if err != nil {
			return nil, err
		}
		head, err := ParseBlockHead(raw, keyVersion)
		if err != nil {
			return nil, err
		}
		switch {
		case head.Level == LeafLevel:
			leafItems, err := parseLeaf(block, raw, head, blockSize)
			if err != nil {
				return nil, err
			}
			items = append(items, leafItems...)
		case head.IsInternal():
			if head.Level > v.superblock.TreeHeight {
				return nil, corruptf("block %d has level %d above the superblock's tree height %d",
					block, head.Level, v.superblock.TreeHeight)
			}
			node, err := parseInternal(raw, head, blockSize, keyVersion)
			if err != nil {
				return nil, err
			}
			for index := len(node.Children) - 1; index >= 0; index-- {
				child := node.Children[index].Block
				if child >= v.superblock.BlockCount {
					return nil, corruptf("child pointer %d in block %d is past the volume's %d blocks",
						child, block, v.superblock.BlockCount)
				}
				stack = append(stack, child)
			}
		default:
			return nil, corruptf("block %d has tree level %d; leaves are %d and internal levels are 2..=%d",
				block, head.Level, LeafLevel, MaxHeight)
		}
	}
	return items, nil
}

// rootBlockHead decodes the root block head without walking the tree.
func (v *Volume) rootBlockHead() (*BlockHead, error) {
	raw, err := v.readBlock(v.superblock.RootBlock)
	if err != nil {
		return nil, err
	}
	return ParseBlockHead(raw, v.keyVersion())
}

// internalNode reads one internal node by block number.
func (v *Volume) internalNode(block uint32) (*InternalNode, error) {
	raw, err := v.readBlock(block)
	if err != nil {
		return nil, err
	}
	head, err := ParseBlockHead(raw, v.keyVersion())
	if err != nil {
		return nil, err
	}
	return parseInternal(raw, head, int(v.superblock.BlockSize), v.keyVersion())
}

func statItem(items []LeafItem, objectID uint32) *LeafItem {
	for index := range items {
		item := &items[index]
		if item.Head.Key.ObjectID == objectID && item.Head.Key.ItemType == ItemTypeStatData {
			return item
		}
	}
	return nil
}

func parseStatItem(item *LeafItem) (*StatData, error) {
	version := statVersionFromKeyVersion(item.Head.Key.Version)
	return ParseStatData(item.Body, version)
}

func statFromItems(items []LeafItem, objectID uint32) (*StatData, error) {
	item := statItem(items, objectID)
	if item == nil {
		return nil, corruptf("object %d has no stat data item", objectID)
	}
	return parseStatItem(item)
}

func decodeDirectory(items []LeafItem, objectID uint32) ([]DirEntry, error) {
	var entries []DirEntry
	for index := range items {
		item := &items[index]
		if item.Head.Key.ObjectID != objectID {
			continue
		}
		switch item.Head.Key.ItemType {
		case ItemTypeDirEntry:
			decoded, err := parseDirectoryItem(item.Body, item.Head.FreeSpaceOrCount)
			if err != nil {
				return nil, err
			}
			entries = append(entries, decoded...)
		case ItemTypeDirect:
			decoded, err := parseDirectoryTail(item.Body, item.Head.FreeSpaceOrCount)
			if err != nil {
				return nil, err
			}
			entries = append(entries, decoded...)
		case ItemTypeUnknown:
			return nil, unsupportedf("%s", item.Describe())
		}
	}
	return entries, nil
}

func lookup(items []LeafItem, directory uint32, name string) (*DirEntry, error) {
	entries, err := decodeDirectory(items, directory)
	if err != nil {
		return nil, err
	}
	for index := range entries {
		if entries[index].Name == name && entries[index].IsVisible() {
			return &entries[index], nil
		}
	}
	return nil, nil
}

// LookupPath resolves an absolute or root-relative path to an object id. The
// bool is false when a visible component does not exist.
func (v *Volume) LookupPath(path string) (uint32, bool, error) {
	items, err := v.items()
	if err != nil {
		return 0, false, err
	}
	current := RootObjectID
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			entry, err := lookup(items, current, "..")
			if err != nil {
				return 0, false, err
			}
			if entry != nil && entry.ObjectID != 0 {
				current = entry.ObjectID
			} else {
				current = RootObjectID
			}
			continue
		}
		entry, err := lookup(items, current, component)
		if err != nil {
			return 0, false, err
		}
		if entry == nil {
			return 0, false, nil
		}
		current = entry.ObjectID
	}
	return current, true, nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	objectID, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	items, err := v.items()
	if err != nil {
		return nil, err
	}
	stat, err := statFromItems(items, objectID)
	if err != nil {
		return nil, err
	}
	parent := uint32(0)
	if item := statItem(items, objectID); item != nil {
		parent = item.Head.Key.DirID
	}
	name := pathName(path)
	clean := cleanPath(path, objectID == RootObjectID)
	if objectID == RootObjectID {
		name = "/"
	}
	entry := v.entryFromStat(name, clean, objectID, parent, stat, nil)
	if stat.IsSymlink() {
		target, err := v.readSymlinkTarget(objectID, stat, items)
		if err != nil {
			return nil, err
		}
		entry.SymlinkTarget = target
	}
	return &entry, nil
}

// ListDir lists a directory's entries, excluding "." and "..". Hidden names are
// returned with Entry.Deleted set.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	objectID, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	items, err := v.items()
	if err != nil {
		return nil, err
	}
	stat, err := statFromItems(items, objectID)
	if err != nil {
		return nil, err
	}
	if !stat.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	entries, err := decodeDirectory(items, objectID)
	if err != nil {
		return nil, err
	}
	base := cleanPath(path, objectID == RootObjectID)
	out := make([]Entry, 0, len(entries))
	for index := range entries {
		dirEntry := &entries[index]
		if dirEntry.Name == "." || dirEntry.Name == ".." {
			continue
		}
		childName := dirEntry.Name
		childPath := "/" + childName
		if base != "/" {
			childPath = base + "/" + childName
		}
		parent := dirEntry.DirID
		if parent == 0 {
			parent = objectID
		}
		entry := Entry{
			Name:        childName,
			Path:        childPath,
			Inode:       dirEntry.ObjectID,
			ParentInode: parent,
			Deleted:     !dirEntry.IsVisible(),
			Hidden:      !dirEntry.IsVisible(),
			Flagged:     dirEntry.IsFlagged(),
			BadOffset:   dirEntry.HasBadOffset(),
			BadLocation: dirEntry.HasBadLocation(),
			HashOffset:  dirEntry.Offset,
		}
		childItem := statItem(items, dirEntry.ObjectID)
		if childItem == nil {
			entry.Unreadable = true
			out = append(out, entry)
			continue
		}
		childStat, err := parseStatItem(childItem)
		if err != nil {
			entry.Unreadable = true
			out = append(out, entry)
			continue
		}
		entry = v.entryFromStat(childName, childPath, dirEntry.ObjectID, parent, childStat, dirEntry)
		if childStat.IsSymlink() {
			target, err := v.readSymlinkTarget(dirEntry.ObjectID, childStat, items)
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
	objectID, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	items, err := v.items()
	if err != nil {
		return nil, err
	}
	stat, err := statFromItems(items, objectID)
	if err != nil {
		return nil, err
	}
	if stat.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	if !stat.IsRegular() && !stat.IsSymlink() {
		return nil, corruptf("object %d is a %s, not a regular file", objectID, stat.FileType().Name())
	}
	mapData, err := buildFileMap(v.superblock, objectID, stat.Size, items)
	if err != nil {
		return nil, err
	}
	id := source.ID(v.fileID.Add(1))
	return newReiserFileSource(id, v.source, mapData, objectID), nil
}

// SymlinkTarget returns the target of the symbolic link named by path.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	objectID, found, err := v.LookupPath(path)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	items, err := v.items()
	if err != nil {
		return "", err
	}
	stat, err := statFromItems(items, objectID)
	if err != nil {
		return "", err
	}
	if !stat.IsSymlink() {
		return "", fmt.Errorf("%w: object %d", ErrNotSymlink, objectID)
	}
	return v.readSymlinkTarget(objectID, stat, items)
}

func (v *Volume) readSymlinkTarget(objectID uint32, stat *StatData, items []LeafItem) (string, error) {
	size := stat.Size
	if size > MaxSymlinkBytes {
		return "", unsupportedf("a %d-byte symbolic-link target, above the %d-byte limit", size, MaxSymlinkBytes)
	}
	if size > v.source.Len() {
		return "", corruptf("symbolic link object %d claims %d target bytes but the image holds %d",
			objectID, size, v.source.Len())
	}
	mapData, err := buildFileMap(v.superblock, objectID, size, items)
	if err != nil {
		return "", err
	}
	buf := make([]byte, int(size))
	if _, err := mapData.readAt(v.source, 0, buf); err != nil {
		return "", err
	}
	for len(buf) > 0 && buf[len(buf)-1] == 0 {
		buf = buf[:len(buf)-1]
	}
	return lossyUTF8(buf), nil
}

// Stats counts the whole tree.
func (v *Volume) Stats() (VolumeStats, error) {
	items, err := v.items()
	if err != nil {
		return VolumeStats{}, err
	}
	var stats VolumeStats
	pending := []uint32{RootObjectID}
	seen := map[uint32]bool{RootObjectID: true}
	for len(pending) > 0 {
		directory := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		stats.Directories++
		entries, err := decodeDirectory(items, directory)
		if err != nil {
			return stats, err
		}
		for index := range entries {
			entry := &entries[index]
			if entry.Name == "." || entry.Name == ".." {
				continue
			}
			if !entry.IsVisible() {
				stats.RemovedNames++
				continue
			}
			if entry.IsFlagged() {
				stats.FlaggedNames++
			}
			item := statItem(items, entry.ObjectID)
			if item == nil {
				stats.Unreadable++
				continue
			}
			stat, err := parseStatItem(item)
			if err != nil {
				stats.Unreadable++
				continue
			}
			stats.Entries++
			switch {
			case stat.IsDirectory():
				if !seen[entry.ObjectID] {
					seen[entry.ObjectID] = true
					pending = append(pending, entry.ObjectID)
				}
			case stat.IsRegular():
				stats.Files++
			case stat.IsSymlink():
				stats.Symlinks++
			default:
				stats.Other++
			}
		}
	}
	return stats, nil
}

func (v *Volume) probe() error {
	root, err := v.rootBlockHead()
	if err != nil {
		return err
	}
	if root.Level != v.superblock.TreeHeight {
		return corruptf("root block %d has level %d but the superblock records tree height %d",
			v.superblock.RootBlock, root.Level, v.superblock.TreeHeight)
	}
	items, err := v.items()
	if err != nil {
		return err
	}
	rootStat, err := statFromItems(items, RootObjectID)
	if err != nil {
		return err
	}
	if !rootStat.IsDirectory() {
		return corruptf("the root object (%d) is a %s, not a directory", RootObjectID, rootStat.FileType().Name())
	}
	return nil
}

func (v *Volume) entryFromStat(name, path string, objectID, parent uint32, stat *StatData, dirEntry *DirEntry) Entry {
	entry := Entry{
		Name:         name,
		Path:         path,
		Inode:        objectID,
		ParentInode:  parent,
		IsDir:        stat.IsDirectory(),
		IsFile:       stat.IsRegular(),
		IsSymlink:    stat.IsSymlink(),
		Size:         stat.Size,
		Mode:         stat.Mode,
		UID:          stat.UID,
		GID:          stat.GID,
		Links:        stat.Nlink,
		FileType:     stat.FileType().Name(),
		Atime:        time.Unix(int64(stat.Atime), 0).UTC(),
		Ctime:        time.Unix(int64(stat.Ctime), 0).UTC(),
		Mtime:        time.Unix(int64(stat.Mtime), 0).UTC(),
		DeviceNumber: stat.DeviceNumber(),
		Generation:   stat.Generation(),
		Blocks:       stat.BlocksUsed(),
	}
	if dirEntry != nil {
		entry.Deleted = !dirEntry.IsVisible()
		entry.Hidden = !dirEntry.IsVisible()
		entry.Flagged = dirEntry.IsFlagged()
		entry.BadOffset = dirEntry.HasBadOffset()
		entry.BadLocation = dirEntry.HasBadLocation()
		entry.HashOffset = dirEntry.Offset
	}
	return entry
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
