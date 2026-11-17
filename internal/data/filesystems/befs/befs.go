// Package befs reads BeFS images (the filesystem of BeOS and Haiku) from a
// source.ByteSource.
//
// It is a port of the Rust forensic-core BeFS reader. The superblock is a
// 512-byte structure at byte 512; it records the block size and shift, the
// block count, the inode size, the allocation-group shift and the block run of
// the root directory's inode. Every inode occupies one block, and an inode's
// file name is a *small data* attribute in the remainder of that block.
//
// A directory's data stream is a B+tree file. Its keys are names and its
// values are inode block numbers; "." names the directory itself and ".." its
// parent. This reader walks the tree's leaves from left to right, so it lists
// every name without inventing a parent-and-name key the format does not
// store.
//
// A stored time is a 64-bit value: seconds in the high 48 bits and a
// uniqueness counter in the low 16. The catalog reports the seconds and no
// time zone; a zero field is no time.
//
// Every read returns real bytes or an explicit error. Nothing is zero-filled,
// and a data stream whose runs leave a gap inside the declared size is refused
// rather than read.
//
// Deliberately unported branches, each refused or reported rather than silently
// guessed at:
//
//   - a byte-swapped or big-endian image is refused by name;
//   - unknown block sizes, non-string B+trees, duplicate-key and fragment
//     nodes, free nodes and deleted-name recovery are refused by name;
//   - deleted inodes are refused (`INODE_DELETED`), because deleted-name
//     recovery is not read;
//   - the allocation bitmap is not translated into a free-space map;
//   - the journal is not replayed: a dirty volume is walked from its committed
//     metadata with a warning.
package befs

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// RootRecord is the handle of the volume root: node zero.
const RootRecord uint64 = 0

// KindLabel is the filesystem name facts and listings report.
const KindLabel = "BeFS"

// Limits that bound a hostile image.
const (
	MaxDirectoryBytes uint64 = 64 * 1024 * 1024
	MaxNodes                 = 5_000_000
	MaxSymlinkBytes   uint64 = 64 * 1024
	WarningCap               = 32
)

// Entry is one name the walk found.
type Entry struct {
	Name string
	// Path is the display path, '/'-separated.
	Path string

	// Inode is the inode block number, which BeFS uses as the inode number.
	Inode uint64
	// ParentRecord is the handle of the parent node; ParentInode is the
	// parent's inode block number.
	ParentRecord uint64
	ParentInode  uint64
	HasParent    bool

	Kind InodeKind

	IsDir         bool
	IsFile        bool
	IsSymlink     bool
	IsFifo        bool
	IsSocket      bool
	IsBlockDevice bool
	IsCharDevice  bool
	IsUnknown     bool

	// Mode is the permission and type bits exactly as recorded.
	Mode uint32
	UID  int32
	GID  int32

	// Size is the logical length in bytes.
	Size uint64
	// Allocated is the bytes the data stream allocates. HasAllocated is false
	// for a directory or special file, and for a file whose block map did not
	// validate.
	Allocated    uint64
	HasAllocated bool

	// Seconds from the high 48 bits of the stored value.
	Created     time.Time
	Modified    time.Time
	Changed     time.Time
	HasCreated  bool
	HasModified bool
	HasChanged  bool

	SymlinkTarget string

	// Deleted is always false for a listed entry: a deleted inode is refused
	// during the walk, not reported.
	Deleted bool
}

// Stats counts one walk.
type Stats struct {
	// NodesRead is inodes read, including the root.
	NodesRead uint64
	// BlocksRead counts inode blocks, B+tree nodes and run-array blocks read.
	BlocksRead uint64
	TreeNodes  uint64
	Lookups    uint64
	Refusals   uint64
	Malformed  uint64
}

// Info is a volume's report.
type Info struct {
	Name string

	BlockSize  uint32
	BlockShift uint32
	NumBlocks  int64
	UsedBlocks int64
	InodeSize  uint32

	BlocksPerAG int32
	AGShift     uint32
	NumAGs      int32

	Flags        uint32
	Clean        bool
	State        string
	JournalStart int64
	JournalEnd   int64
	HasJournal   bool

	RootInode uint64

	Entries     int
	Directories int
	Files       int
	Symlinks    int

	BTreeNodes   uint64
	BTreeLookups uint64

	NodesRead  uint64
	BlocksRead uint64

	Refusals  uint64
	Malformed uint64

	Unreadable     uint64
	Undecodable    uint64
	DirectoryLoops uint64

	Warnings        []string
	WarningsDropped uint64
}

// node is one name inside the image, as the walk found it.
type node struct {
	record    uint64
	parent    uint64
	hasParent bool

	name string
	path string

	inodeNumber uint64
	kind        InodeKind
	mode        uint32
	uid         int32
	gid         int32
	size        uint64

	allocated    uint64
	hasAllocated bool

	created  *int64
	modified *int64
	changed  *int64

	symlinkTarget string
	children      []uint64
}

// Volume is an opened BeFS image.
type Volume struct {
	src    source.ByteSource
	sb     *superblock
	inodes []*inode
	nodes  []*node

	unreadable     uint64
	undecodable    uint64
	refusals       uint64
	malformed      uint64
	directoryLoops uint64

	nodesRead  uint64
	blocksRead uint64
	treeNodes  uint64
	lookups    uint64

	warnings        []string
	warningsDropped uint64

	nextID atomic.Uint64
}

// Detect reports whether src looks like a BeFS image without mounting it.
func Detect(src source.ByteSource) (bool, error) {
	return detectSuperblock(src)
}

// Open reads the superblock and walks every directory.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := readSuperblock(src)
	if err != nil {
		return nil, err
	}
	rootBlock, ok := sb.rootDir.toBlock(sb.agShift)
	if !ok {
		return nil, corruptf("the root directory inode's block overflows")
	}
	root, err := readInode(src, sb, rootBlock)
	if err != nil {
		return nil, err
	}
	if !root.kind.isDirectory() {
		return nil, corruptf("the root inode at block %d is a %s, not a directory",
			rootBlock, root.kind.label())
	}
	volume := &Volume{
		src:    src,
		sb:     sb,
		inodes: []*inode{root},
		nodes: []*node{{
			record:      RootRecord,
			hasParent:   false,
			name:        "/",
			path:        "/",
			inodeNumber: rootBlock,
			kind:        root.kind,
			mode:        root.mode,
			uid:         root.uid,
			gid:         root.gid,
			size:        root.size,
			created:     root.created,
			modified:    root.modified,
			changed:     root.changed,
		}},
		nodesRead:  1,
		blocksRead: 1,
	}
	volume.nextID.Store(uint64(src.SourceID()) + 1)
	volume.warnAboutVolumeState()
	if err := volume.walk(); err != nil {
		return nil, err
	}
	return volume, nil
}

func (v *Volume) warnAboutVolumeState() {
	sb := v.sb
	if sb.isClean() {
		if !sb.logBlocks.isZero() {
			v.pushWarning("the volume has a journal, which this reader does not replay")
		}
		return
	}
	var reason string
	switch {
	case sb.flags == FlagDirty:
		reason = "the volume is marked dirty"
	case sb.logStart != sb.logEnd:
		reason = fmt.Sprintf("the journal is not empty (start %d, end %d)", sb.logStart, sb.logEnd)
	default:
		reason = fmt.Sprintf("the volume flags 0x%08x are not clean", sb.flags)
	}
	v.pushWarning(reason + "; the journal is not replayed, so only committed metadata is walked")
}

func (v *Volume) walk() error {
	visited := map[uint64]bool{v.nodes[0].inodeNumber: true}
	queue := []int{0}
	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		v.lookups++
		listing, arrayBlocks, err := v.directoryListing(directory)
		if err != nil {
			v.unreadable++
			v.classify(err)
			v.pushWarning(fmt.Sprintf("directory %s: %v", v.nodes[directory].path, err))
			continue
		}
		v.treeNodes += listing.nodesRead
		v.blocksRead += listing.nodesRead + arrayBlocks
		v.malformed += listing.malformed
		parentPath := v.nodes[directory].path

		for _, item := range listing.entries {
			if item.name == "." || item.name == ".." {
				continue
			}
			if item.inode == 0 || item.inode >= uint64(v.sb.numBlocks) {
				v.malformed++
				v.pushWarning(fmt.Sprintf("directory %s: name %q names block %d, outside the volume",
					parentPath, item.name, item.inode))
				continue
			}
			inode, err := v.readInode(item.inode)
			if err != nil {
				v.undecodable++
				v.classify(err)
				v.pushWarning(fmt.Sprintf("directory %s: name %q: %v", parentPath, item.name, err))
				continue
			}
			if len(v.nodes) >= MaxNodes {
				return corruptf("the image names more than %d entries", MaxNodes)
			}
			path := "/" + item.name
			if parentPath != "/" {
				path = parentPath + "/" + item.name
			}
			var (
				undecodable   bool
				allocated     uint64
				hasAllocated  bool
				symlinkTarget string
			)

			switch {
			case inode.kind.isFile():
				file, err := newFileSource(v.src.SourceID(), v.src, v.sb, inode)
				if err != nil {
					undecodable = true
					v.classify(err)
					v.pushWarning(fmt.Sprintf("file %s: %v", path, err))
				} else {
					allocated = file.allocatedBytes()
					hasAllocated = true
					v.blocksRead += file.arrayBlocksRead()
				}
			case inode.kind.isSymlink() && inode.isLongSymlink():
				file, err := newFileSource(v.src.SourceID(), v.src, v.sb, inode)
				if err != nil {
					undecodable = true
					v.classify(err)
					v.pushWarning(fmt.Sprintf("symlink %s: %v", path, err))
				} else {
					allocated = file.allocatedBytes()
					hasAllocated = true
					v.blocksRead += file.arrayBlocksRead()
					if inode.size <= MaxSymlinkBytes {
						buf := make([]byte, int(inode.size))
						if _, err := file.readAt(0, buf); err != nil {
							undecodable = true
							v.classify(err)
							v.pushWarning(fmt.Sprintf("symlink %s: %v", path, err))
						} else {
							symlinkTarget = lossyUTF8(buf)
						}
					} else {
						v.pushWarning(fmt.Sprintf(
							"symlink %s: target is %d bytes, more than the %d-byte inline cap; open the link stream instead",
							path, inode.size, MaxSymlinkBytes))
					}
				}
			case inode.kind.isSymlink():
				allocated = 0
				hasAllocated = true
				symlinkTarget = inode.shortSymlinkText()
			}
			if undecodable {
				v.undecodable++
			}

			child := uint64(len(v.nodes))
			v.nodes = append(v.nodes, &node{
				record:        child,
				parent:        uint64(directory),
				hasParent:     true,
				name:          item.name,
				path:          path,
				inodeNumber:   inode.block,
				kind:          inode.kind,
				mode:          inode.mode,
				uid:           inode.uid,
				gid:           inode.gid,
				size:          inode.size,
				allocated:     allocated,
				hasAllocated:  hasAllocated,
				created:       inode.created,
				modified:      inode.modified,
				changed:       inode.changed,
				symlinkTarget: symlinkTarget,
			})
			v.inodes = append(v.inodes, inode)
			v.nodes[directory].children = append(v.nodes[directory].children, child)
			if inode.kind.isDirectory() {
				if !visited[inode.block] {
					visited[inode.block] = true
					queue = append(queue, int(child))
				} else {
					v.directoryLoops++
				}
			}
		}
	}
	return nil
}

// directoryListing reads and parses one directory's B+tree.
func (v *Volume) directoryListing(directory int) (*Listing, uint64, error) {
	inode := v.inodes[directory]
	if !inode.kind.isDirectory() {
		return nil, 0, corruptf("node %s is a %s, not a directory", v.nodes[directory].path, inode.kind.label())
	}
	size := inode.size
	if size == 0 {
		return nil, 0, corruptf("directory %s has no B+tree stream", v.nodes[directory].path)
	}
	if size > MaxDirectoryBytes {
		return nil, 0, corruptf("directory %s declares %d tree bytes, more than %d",
			v.nodes[directory].path, size, MaxDirectoryBytes)
	}
	file, err := newFileSource(v.src.SourceID(), v.src, v.sb, inode)
	if err != nil {
		return nil, 0, err
	}
	arrayBlocks := file.arrayBlocksRead()
	listing, err := readBTree(file)
	if err != nil {
		return nil, 0, err
	}
	return listing, arrayBlocks, nil
}

func (v *Volume) readInode(block uint64) (*inode, error) {
	inode, err := readInode(v.src, v.sb, block)
	if err != nil {
		return nil, err
	}
	v.nodesRead++
	v.blocksRead++
	return inode, nil
}

func (v *Volume) classify(err error) {
	switch {
	case errors.Is(err, source.ErrUnsupported):
		v.refusals++
	case errors.Is(err, source.ErrCorrupt):
		v.malformed++
	}
}

func (v *Volume) pushWarning(message string) {
	if len(v.warnings) >= WarningCap {
		v.warningsDropped++
		return
	}
	v.warnings = append(v.warnings, message)
}

func (v *Volume) inodeAt(record uint64) (*inode, error) {
	if record >= uint64(len(v.nodes)) {
		return nil, fmt.Errorf("%w: no node %d in this image", ErrNotFound, record)
	}
	return v.inodes[record], nil
}

// entryFor builds an Entry from one node.
func (v *Volume) entryFor(value *node) Entry {
	entry := Entry{
		Name:          value.name,
		Path:          value.path,
		Inode:         value.inodeNumber,
		Kind:          value.kind,
		IsDir:         value.kind == KindDirectory,
		IsFile:        value.kind == KindFile,
		IsSymlink:     value.kind == KindSymlink,
		IsFifo:        value.kind == KindFifo,
		IsSocket:      value.kind == KindSocket,
		IsBlockDevice: value.kind == KindBlockDevice,
		IsCharDevice:  value.kind == KindCharDevice,
		IsUnknown:     value.kind == KindUnknown,
		Mode:          value.mode,
		UID:           value.uid,
		GID:           value.gid,
		Size:          value.size,
		Allocated:     value.allocated,
		HasAllocated:  value.hasAllocated,
		SymlinkTarget: value.symlinkTarget,
	}
	if value.hasParent {
		entry.HasParent = true
		entry.ParentRecord = value.parent
		if value.parent < uint64(len(v.nodes)) {
			entry.ParentInode = v.nodes[value.parent].inodeNumber
		}
	}
	if value.created != nil {
		entry.Created = time.Unix(*value.created, 0).UTC()
		entry.HasCreated = true
	}
	if value.modified != nil {
		entry.Modified = time.Unix(*value.modified, 0).UTC()
		entry.HasModified = true
	}
	if value.changed != nil {
		entry.Changed = time.Unix(*value.changed, 0).UTC()
		entry.HasChanged = true
	}
	return entry
}

// resolve walks a '/'-separated path to its node. "" and "/" name the root.
func (v *Volume) resolve(path string) (*node, error) {
	if len(v.nodes) == 0 {
		return nil, corruptf("the walk has no root node")
	}
	current := 0
	for _, component := range strings.Split(path, "/") {
		switch component {
		case "", ".":
			continue
		case "..":
			if v.nodes[current].hasParent {
				current = int(v.nodes[current].parent)
			}
			continue
		}
		if v.nodes[current].kind != KindDirectory {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		found := false
		for _, child := range v.nodes[current].children {
			position := int(child)
			if position < 0 || position >= len(v.nodes) {
				continue
			}
			if v.nodes[position].name == component {
				current = position
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
	}
	return v.nodes[current], nil
}

// ListDir lists a directory's children, excluding "." and "..".
func (v *Volume) ListDir(path string) ([]Entry, error) {
	directory, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	if directory.kind != KindDirectory {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	out := make([]Entry, 0, len(directory.children))
	for _, child := range directory.children {
		position := int(child)
		if position < 0 || position >= len(v.nodes) {
			continue
		}
		entry := v.entryFor(v.nodes[position])
		entry.ParentInode = directory.inodeNumber
		out = append(out, entry)
	}
	return out, nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	value, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	entry := v.entryFor(value)
	return &entry, nil
}

// OpenFile opens a regular file's data stream. Directories and special files
// have no file data; a symbolic link's target can be opened with OpenSymlink.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	value, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	switch value.kind {
	case KindDirectory:
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	case KindFile:
	default:
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	inode, err := v.inodeAt(value.record)
	if err != nil {
		return nil, err
	}
	return newFileSource(source.ID(v.nextID.Add(1)), v.src, v.sb, inode)
}

// OpenSymlink opens a symbolic link's target as a stream. A short link's
// target is the bytes in its inode; a long link's target is its data stream.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	value, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	if value.kind != KindSymlink {
		return nil, fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	inode, err := v.inodeAt(value.record)
	if err != nil {
		return nil, err
	}
	if inode.shortSymlink != nil {
		data := append([]byte(nil), inode.shortSymlink...)
		return source.NewMemorySourceWithImage(source.ID(v.nextID.Add(1)), v.src.ImageID(), data), nil
	}
	return newFileSource(source.ID(v.nextID.Add(1)), v.src, v.sb, inode)
}

// Info returns the volume's report.
func (v *Volume) Info() Info {
	sb := v.sb
	directories := 0
	symlinks := 0
	for _, value := range v.nodes {
		if value.kind.isDirectory() {
			directories++
		}
		if value.kind.isSymlink() {
			symlinks++
		}
	}
	state := "clean"
	switch {
	case sb.isClean():
	case sb.flags == FlagDirty:
		state = "dirty"
	default:
		state = fmt.Sprintf("flags 0x%08x", sb.flags)
	}
	return Info{
		Name:            sb.name,
		BlockSize:       sb.blockSize,
		BlockShift:      sb.blockShift,
		NumBlocks:       sb.numBlocks,
		UsedBlocks:      sb.usedBlocks,
		InodeSize:       sb.inodeSize,
		BlocksPerAG:     sb.blocksPerAG,
		AGShift:         sb.agShift,
		NumAGs:          sb.numAGs,
		Flags:           sb.flags,
		Clean:           sb.isClean(),
		State:           state,
		JournalStart:    sb.logStart,
		JournalEnd:      sb.logEnd,
		HasJournal:      !sb.logBlocks.isZero() || sb.logStart != 0 || sb.logEnd != 0,
		RootInode:       v.nodes[0].inodeNumber,
		Entries:         len(v.nodes),
		Directories:     directories,
		Files:           len(v.nodes) - directories,
		Symlinks:        symlinks,
		BTreeNodes:      v.treeNodes,
		BTreeLookups:    v.lookups,
		NodesRead:       v.nodesRead,
		BlocksRead:      v.blocksRead,
		Refusals:        v.refusals,
		Malformed:       v.malformed,
		Unreadable:      v.unreadable,
		Undecodable:     v.undecodable,
		DirectoryLoops:  v.directoryLoops,
		Warnings:        append([]string(nil), v.warnings...),
		WarningsDropped: v.warningsDropped,
	}
}

// Stats returns the walk counters.
func (v *Volume) Stats() Stats {
	return Stats{
		NodesRead:  v.nodesRead,
		BlocksRead: v.blocksRead,
		TreeNodes:  v.treeNodes,
		Lookups:    v.lookups,
		Refusals:   v.refusals,
		Malformed:  v.malformed,
	}
}

// Warnings returns the messages collected while opening.
func (v *Volume) Warnings() []string { return append([]string(nil), v.warnings...) }

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *superblock { return v.sb }

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.src }
