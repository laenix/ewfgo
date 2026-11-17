// Package ocfs2 reads OCFS2 (the Oracle Cluster File System, version 2)
// volumes, read-only, from a source.ByteSource.
//
// It is a port of the Rust forensic-core OCFS2 reader. Filesystem block 2 holds
// the superblock, which is itself an ocfs2_dinode: its first bytes are the
// OCFSV2 signature and its id2 union records the block and cluster shifts, the
// cluster count, the volume label and UUID, the root and system directory inode
// numbers, and the filesystem generation. Every inode is one block beginning
// with INODE01 and the block number is the inode number. Files and directories
// map data through an extent tree, and small files and directories may keep
// their bytes inline in the inode.
//
// A directory is a stream of 12-byte-header records; "." and ".." are ordinary
// entries and an inode number of zero is a free or deleted slot. When the
// volume carries META_ECC, each directory block ends with a validated 64-byte
// DIRTRL1 trailer.
//
// Deliberately unported branches, each refused or reported rather than guessed
// at:
//
//   - a byte-swapped image, an unknown block or cluster size, and unknown
//     incompat feature bits are refused by name;
//   - an extent tree at or beyond OCFS2_MAX_PATH_DEPTH, a gap, an unwritten
//     extent, a non-cluster-aligned extent and a short map are refused, never
//     zero-filled;
//   - the indexed (dx_root/dx_node/dx_leaf) directory format is refused;
//   - the journal is not replayed, so only committed metadata is walked;
//   - the cluster bitmap is not decoded into a free-space map;
//   - deleted-name recovery is not read: a zero-inode directory slot is a free
//     slot and is skipped.
//
// i_atime, i_ctime and i_mtime are 64-bit Unix seconds with a 32-bit
// nanosecond remainder; a zero pair is "unset", not 1970. i_ctime is the
// status-change time, not a creation time, and OCFS2 stores no creation time.
package ocfs2

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Info is a volume-level report.
type Info struct {
	BlockSize    uint32
	BlockShift   uint32
	ClusterSize  uint32
	ClusterShift uint32

	TotalClusters uint32
	TotalBlocks   uint64
	VolumeBytes   uint64

	VolumeLabel string
	UUID        string
	Major       uint16
	Minor       uint16
	MaxSlots    uint16
	State       uint16

	FeatureCompat   uint32
	FeatureIncompat uint32
	FeatureROCompat uint32

	RootBlkno         uint64
	SystemDirBlkno    uint64
	FirstClusterGroup uint64
	FsGeneration      uint32

	MetaECC     bool
	InlineData  bool
	IndexedDirs bool
}

// Entry is one file or directory in a volume.
type Entry struct {
	Name        string
	Path        string
	Inode       uint64
	ParentInode uint64

	IsDir     bool
	IsFile    bool
	IsSymlink bool
	Kind      string

	Mode     uint16
	UID      uint32
	GID      uint32
	Links    uint32
	Size     uint64
	Clusters uint32

	// Allocated is the bytes the data stream allocates. AllocatedKnown is
	// false for directories and special files, and for an inode whose map
	// this reader refused.
	Allocated      uint64
	AllocatedKnown bool

	Atime    time.Time
	Ctime    time.Time
	Mtime    time.Time
	HasAtime bool
	HasCtime bool
	HasMtime bool

	// SymlinkTarget is filled for symbolic links.
	SymlinkTarget string

	// Deleted is always false for OCFS2: an unlinked name's directory entry
	// has inode number zero and is a free slot, so no deleted name is
	// provable here.
	Deleted bool
}

// WalkStats counts one whole-volume walk.
type WalkStats struct {
	Nodes       uint64
	Directories uint64
	Files       uint64
	Symlinks    uint64
	Other       uint64

	NodesRead     uint64
	BlocksRead    uint64
	ExtentBlocks  uint64
	ExtentRecords uint64
	Lookups       uint64

	Unreadable     uint64
	Undecodable    uint64
	Refusals       uint64
	Malformed      uint64
	DirectoryLoops uint64

	Warnings        []string
	WarningsDropped uint64
}

// Volume is an opened OCFS2 volume.
type Volume struct {
	source     source.ByteSource
	superblock *Superblock
	fileID     atomic.Uint64
}

// Open reads the superblock and the root directory inode, then returns the
// volume.
func Open(src source.ByteSource) (*Volume, error) {
	superblock, err := OpenSuperblock(src)
	if err != nil {
		return nil, err
	}
	root, err := ReadInode(src, superblock, superblock.RootBlkno)
	if err != nil {
		return nil, err
	}
	if !root.Kind.IsDirectory() {
		return nil, corruptf("the root inode at block %d is a %s, not a directory",
			superblock.RootBlkno, root.Kind.Label())
	}
	volume := &Volume{source: src, superblock: superblock}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	return volume, nil
}

// Info returns the volume-level report.
func (v *Volume) Info() Info {
	sb := v.superblock
	return Info{
		BlockSize:         sb.BlockSize,
		BlockShift:        sb.BlockShift,
		ClusterSize:       sb.ClusterSize,
		ClusterShift:      sb.ClusterShift,
		TotalClusters:     sb.TotalClusters,
		TotalBlocks:       sb.TotalBlocks,
		VolumeBytes:       sb.VolumeBytes,
		VolumeLabel:       sb.VolumeLabel,
		UUID:              sb.UUIDText(),
		Major:             sb.Major,
		Minor:             sb.Minor,
		MaxSlots:          sb.MaxSlots,
		State:             sb.State,
		FeatureCompat:     sb.FeatureCompat,
		FeatureIncompat:   sb.FeatureIncompat,
		FeatureROCompat:   sb.FeatureROCompat,
		RootBlkno:         sb.RootBlkno,
		SystemDirBlkno:    sb.SystemDirBlkno,
		FirstClusterGroup: sb.FirstClusterGroup,
		FsGeneration:      sb.FsGeneration,
		MetaECC:           sb.MetaECC(),
		InlineData:        sb.SupportsInlineData(),
		IndexedDirs:       sb.FeatureIncompat&FeatureIncompatIndexedDirs != 0,
	}
}

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// BlockSize returns the volume's block size.
func (v *Volume) BlockSize() uint32 { return v.superblock.BlockSize }

func (v *Volume) inode(block uint64) (*Inode, error) {
	return ReadInode(v.source, v.superblock, block)
}

func optionalTime(seconds *int64) (time.Time, bool) {
	if seconds == nil {
		return time.Time{}, false
	}
	return time.Unix(*seconds, 0).UTC(), true
}

func (v *Volume) directory(block uint64, inode *Inode) (*Directory, error) {
	return ReadDirectory(v.superblock, v.source, inode, source.ID(v.fileID.Add(1)))
}

func (v *Volume) lookup(directoryBlock uint64, name string) (*DirEntry, error) {
	inode, err := v.inode(directoryBlock)
	if err != nil {
		return nil, err
	}
	if !inode.Kind.IsDirectory() {
		return nil, fmt.Errorf("%w: inode %d", ErrNotDir, directoryBlock)
	}
	if inode.IsIndexedDirectory() {
		return nil, unsupportedf("directory inode %d uses the indexed (dx_root/dx_node/dx_leaf) format", inode.Block)
	}
	listing, err := v.directory(directoryBlock, inode)
	if err != nil {
		return nil, err
	}
	for index := range listing.Entries {
		if listing.Entries[index].Name == name {
			return &listing.Entries[index], nil
		}
	}
	return nil, nil
}

// LookupPath resolves a path to an inode block number. The bool is false when
// a component does not exist.
func (v *Volume) LookupPath(path string) (uint64, bool, error) {
	current := v.superblock.RootBlkno
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			parent := v.superblock.RootBlkno
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

func (v *Volume) entryFromInode(name, path string, inode *Inode) (Entry, error) {
	entry := Entry{
		Name:      name,
		Path:      path,
		Inode:     inode.Block,
		IsDir:     inode.Kind.IsDirectory(),
		IsFile:    inode.Kind.IsFile(),
		IsSymlink: inode.Kind.IsSymlink(),
		Kind:      inode.Kind.Label(),
		Mode:      inode.Mode,
		UID:       inode.UID,
		GID:       inode.GID,
		Links:     inode.Links,
		Size:      inode.Size,
		Clusters:  inode.Clusters,
	}
	entry.Atime, entry.HasAtime = optionalTime(inode.Accessed)
	entry.Ctime, entry.HasCtime = optionalTime(inode.Changed)
	entry.Mtime, entry.HasMtime = optionalTime(inode.Modified)

	switch {
	case inode.Kind.IsFile():
		file, err := newOcfs2FileSource(source.ID(v.fileID.Add(1)), v.source, v.superblock, inode)
		if err != nil {
			return entry, err
		}
		entry.Allocated = file.AllocatedBytes()
		entry.AllocatedKnown = true
	case inode.Kind.IsSymlink() && inode.FastSymlink != nil:
		entry.Allocated = 0
		entry.AllocatedKnown = true
		entry.SymlinkTarget = inode.FastSymlinkText()
	case inode.Kind.IsSymlink():
		file, err := newOcfs2FileSource(source.ID(v.fileID.Add(1)), v.source, v.superblock, inode)
		if err != nil {
			return entry, err
		}
		entry.Allocated = file.AllocatedBytes()
		entry.AllocatedKnown = true
		target, err := readLinkTarget(file, inode.Size)
		if err != nil {
			return entry, err
		}
		entry.SymlinkTarget = target
	}
	return entry, nil
}

func readLinkTarget(file *Ocfs2FileSource, size uint64) (string, error) {
	if size > MaxSymlinkBytes {
		return "", unsupportedf("a %d-byte symbolic-link target, above the %d-byte limit", size, MaxSymlinkBytes)
	}
	if size > uint64(maxInt()) {
		return "", corruptf("the symbolic-link target length does not fit in memory")
	}
	bytes := make([]byte, int(size))
	if _, err := file.readAt(0, bytes); err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	block, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.inode(block)
	if err != nil {
		return nil, err
	}
	name := pathName(path)
	clean := cleanPath(path)
	if block == v.superblock.RootBlkno {
		name = "/"
		clean = "/"
	}
	entry, err := v.entryFromInode(name, clean, inode)
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// ListDir lists a directory's entries, excluding "." and "..".
func (v *Volume) ListDir(path string) ([]Entry, error) {
	block, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.inode(block)
	if err != nil {
		return nil, err
	}
	if !inode.Kind.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	if inode.IsIndexedDirectory() {
		return nil, unsupportedf("directory inode %d uses the indexed (dx_root/dx_node/dx_leaf) format", inode.Block)
	}
	listing, err := v.directory(block, inode)
	if err != nil {
		return nil, err
	}
	base := cleanPath(path)
	if block == v.superblock.RootBlkno {
		base = "/"
	}
	out := make([]Entry, 0, len(listing.Entries))
	for _, dirEntry := range listing.Entries {
		if dirEntry.Name == "." || dirEntry.Name == ".." || dirEntry.Inode == 0 {
			continue
		}
		child, err := v.inode(dirEntry.Inode)
		if err != nil {
			return nil, err
		}
		childPath := "/" + dirEntry.Name
		if base != "/" {
			childPath = base + "/" + dirEntry.Name
		}
		entry, err := v.entryFromInode(dirEntry.Name, childPath, child)
		if err != nil {
			return nil, err
		}
		entry.ParentInode = block
		out = append(out, entry)
	}
	return out, nil
}

// OpenFile opens the file named by path as a byte source. A fast symbolic link
// returns its inode-embedded target; a slow symbolic link returns its
// extent-mapped stream. Directories and special files have no readable stream.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	block, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.inode(block)
	if err != nil {
		return nil, err
	}
	if inode.Kind.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	id := source.ID(v.fileID.Add(1))
	if inode.Kind.IsSymlink() && inode.FastSymlink != nil {
		return source.NewMemorySourceWithImage(id, v.source.ImageID(), append([]byte(nil), inode.FastSymlink...)), nil
	}
	if inode.Kind != KindFile && inode.Kind != KindSymlink {
		return nil, unsupportedf("inode block %d is a %s, which has no readable data stream", block, inode.Kind.Label())
	}
	file, err := newOcfs2FileSource(id, v.source, v.superblock, inode)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// SymlinkTarget returns the target of the symbolic link named by path.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	block, found, err := v.LookupPath(path)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.inode(block)
	if err != nil {
		return "", err
	}
	if !inode.Kind.IsSymlink() {
		return "", fmt.Errorf("%w: inode block %d", ErrNotSymlink, block)
	}
	if inode.FastSymlink != nil {
		return inode.FastSymlinkText(), nil
	}
	file, err := newOcfs2FileSource(source.ID(v.fileID.Add(1)), v.source, v.superblock, inode)
	if err != nil {
		return "", err
	}
	return readLinkTarget(file, inode.Size)
}

func (v *Volume) classify(stats *WalkStats, err error) {
	switch {
	case err == nil:
	case errors.Is(err, source.ErrUnsupported):
		stats.Refusals++
	case errors.Is(err, source.ErrCorrupt):
		stats.Malformed++
	}
}

func (stats *WalkStats) pushWarning(message string) {
	if len(stats.Warnings) < WarningCap {
		stats.Warnings = append(stats.Warnings, message)
	} else {
		stats.WarningsDropped++
	}
}

type walkDirectory struct {
	block uint64
	inode *Inode
}

// Walk reads every directory reachable from the root and counts what it finds.
// A directory reached by a second name is listed but not walked twice.
func (v *Volume) Walk() (WalkStats, error) {
	var stats WalkStats
	root, err := v.inode(v.superblock.RootBlkno)
	stats.NodesRead++
	stats.BlocksRead++
	if err != nil {
		return stats, err
	}
	if !root.Kind.IsDirectory() {
		return stats, corruptf("the root inode at block %d is a %s, not a directory",
			v.superblock.RootBlkno, root.Kind.Label())
	}
	stats.Nodes = 1
	stats.Directories = 1
	visited := map[uint64]bool{v.superblock.RootBlkno: true}
	queue := []walkDirectory{{block: v.superblock.RootBlkno, inode: root}}

	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		stats.Lookups++
		if directory.inode.IsIndexedDirectory() {
			err := unsupportedf("directory inode %d uses the indexed (dx_root/dx_node/dx_leaf) format", directory.block)
			stats.Unreadable++
			v.classify(&stats, err)
			stats.pushWarning(err.Error())
			continue
		}
		listing, err := v.directory(directory.block, directory.inode)
		if err != nil {
			stats.Unreadable++
			v.classify(&stats, err)
			stats.pushWarning("directory inode " + u64Text(directory.block) + ": " + err.Error())
			continue
		}
		stats.BlocksRead += listing.Blocks + listing.ExtentBlocks
		stats.ExtentBlocks += listing.ExtentBlocks
		stats.ExtentRecords += listing.ExtentRecords

		for _, entry := range listing.Entries {
			if entry.Name == "." || entry.Name == ".." {
				continue
			}
			if entry.Inode == 0 || entry.Inode >= v.superblock.TotalBlocks {
				stats.Malformed++
				stats.pushWarning("inode " + u64Text(entry.Inode) + " (" + entry.Name + ") names a block outside the volume")
				continue
			}
			child, err := v.inode(entry.Inode)
			stats.NodesRead++
			stats.BlocksRead++
			if err != nil {
				stats.Undecodable++
				v.classify(&stats, err)
				stats.pushWarning("inode " + u64Text(entry.Inode) + " (" + entry.Name + "): " + err.Error())
				continue
			}
			if stats.Nodes >= MaxNodes {
				return stats, corruptf("the image names more than %d entries", MaxNodes)
			}
			stats.Nodes++

			switch {
			case child.Kind.IsDirectory():
				stats.Directories++
				if !visited[entry.Inode] {
					visited[entry.Inode] = true
					queue = append(queue, walkDirectory{block: entry.Inode, inode: child})
				} else {
					stats.DirectoryLoops++
				}
			case child.Kind.IsFile():
				stats.Files++
			case child.Kind.IsSymlink():
				stats.Symlinks++
			default:
				stats.Other++
			}

			undecodable := false
			if child.Kind.IsFile() {
				file, err := newOcfs2FileSource(source.ID(v.fileID.Add(1)), v.source, v.superblock, child)
				if err != nil {
					undecodable = true
					v.classify(&stats, err)
					stats.pushWarning("file " + entry.Name + ": " + err.Error())
				} else {
					stats.ExtentBlocks += file.ExtentBlocksRead()
					stats.ExtentRecords += file.ExtentRecords()
					stats.BlocksRead += file.ExtentBlocksRead()
				}
			} else if child.Kind.IsSymlink() && child.FastSymlink == nil {
				file, err := newOcfs2FileSource(source.ID(v.fileID.Add(1)), v.source, v.superblock, child)
				if err != nil {
					undecodable = true
					v.classify(&stats, err)
					stats.pushWarning("symlink " + entry.Name + ": " + err.Error())
				} else {
					stats.ExtentBlocks += file.ExtentBlocksRead()
					stats.ExtentRecords += file.ExtentRecords()
					stats.BlocksRead += file.ExtentBlocksRead()
					if child.Size <= MaxSymlinkBytes {
						target := make([]byte, int(child.Size))
						if _, err := file.readAt(0, target); err != nil {
							undecodable = true
							v.classify(&stats, err)
							stats.pushWarning("symlink " + entry.Name + ": " + err.Error())
						}
					} else {
						stats.pushWarning("symlink " + entry.Name + ": target is more than the " +
							u64Text(MaxSymlinkBytes) + "-byte inline cap; open the link stream instead")
					}
				}
			}
			if undecodable {
				stats.Undecodable++
			}
		}
	}
	return stats, nil
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

func cleanPath(path string) string {
	var parts []string
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		parts = append(parts, component)
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}
