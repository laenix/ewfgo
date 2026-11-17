package sysv

import (
	"fmt"
	pathpkg "path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	kindLabel = "System V"
	// maxDirectoryBytes bounds one directory listing.
	maxDirectoryBytes = 64 * 1024 * 1024
	// maxNodes bounds the walk rather than exhausting memory.
	maxNodes = 5_000_000
	// maxSymlinkBytes is the longest symbolic-link target accepted.
	maxSymlinkBytes = 4096
)

// Entry describes one name the walk found.
type Entry struct {
	Name string
	// Path is the display path, `/`-separated.
	Path string

	IsDir     bool
	IsFile    bool
	IsSymlink bool

	// Mode holds the permission and type bits exactly as recorded.
	Mode uint16
	UID  uint16
	GID  uint16

	// Size is a file's logical length or a directory's listing byte count.
	Size uint64
	// Allocated is the bytes the data zones allocate, meaningful only when
	// AllocatedKnown is true.
	Allocated      uint64
	AllocatedKnown bool

	InodeNumber uint32
	Links       uint16
	// Generation is the inode generation byte, recorded as stored.
	Generation uint8

	// Times are UTC Unix seconds. A zero field means the writer recorded no
	// time and the field is left as the zero Time.
	Atime time.Time
	Mtime time.Time
	Ctime time.Time

	// SymlinkTarget is the recorded target when SymlinkTargetKnown is true.
	SymlinkTarget      string
	SymlinkTargetKnown bool

	// Deleted is always false: the kernel clears a deleted name's inode
	// field, so the format retains no deleted name.
	Deleted bool
}

// Info is the volume-level description returned by Volume.Info.
type Info struct {
	Type string
	// Variant is the on-disk layout the signature selected.
	Variant string
	// ByteOrder describes how multi-byte fields are stored.
	ByteOrder string

	// Magic is the on-disk magic; HasMagic is false for Coherent.
	Magic    uint32
	HasMagic bool

	BlockSize     uint32
	FirstDataZone uint32
	Zones         uint32
	InodeCount    uint32

	InodeTableBlock uint32
	NameLength      int
	DirEntrySize    int

	VolumeName string
	PackName   string
	AFS        bool

	// State is s_state; HasState is false for Xenix and Coherent.
	State    uint32
	HasState bool
	// Clean reports a variant's clean marker when the variant defines one.
	Clean      bool
	CleanKnown bool

	TFree  uint32
	TInode uint16
	NInode uint16

	Entries     int
	Directories int
	Files       int
	Symlinks    int

	EmptySlots     uint64
	MalformedSlots uint64
	DirectoryLoops uint64
	Unreadable     uint64
	Undecodable    uint64
}

type node struct {
	name          string
	path          string
	parent        int
	inodeNumber   uint32
	kind          inodeKind
	mode          uint16
	uid           uint16
	gid           uint16
	size          uint64
	links         uint16
	generation    uint8
	atime         uint32
	mtime         uint32
	ctime         uint32
	allocated     uint64
	allocatedOK   bool
	symlinkTarget string
	symlinkOK     bool
	children      []int
}

// Volume is a mounted System V-family image.
type Volume struct {
	src        source.ByteSource
	superblock *superblock
	inodes     []inode
	nodes      []node
	paths      map[string]int

	emptySlots     uint64
	malformedSlots uint64
	directoryLoops uint64
	unreadable     uint64
	undecodable    uint64
}

var nextFileSourceID atomic.Uint64

// Open reads the superblock and walks every directory. The format has no
// index of names, so enumerating the image is the walk.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := readSuperblock(src)
	if err != nil {
		return nil, err
	}
	root, err := readInode(src, sb, rootInode)
	if err != nil {
		return nil, err
	}
	if root.kind != kindDirectory {
		return nil, corruptf("inode %d is a %s, not the root directory", rootInode, root.kind.label())
	}
	volume := &Volume{
		src:        src,
		superblock: sb,
		inodes:     []inode{*root},
		paths:      map[string]int{"/": 0},
		nodes: []node{{
			name:        "/",
			path:        "/",
			parent:      -1,
			inodeNumber: rootInode,
			kind:        root.kind,
			mode:        root.mode,
			uid:         root.uid,
			gid:         root.gid,
			size:        uint64(root.size),
			links:       root.links,
			generation:  root.generation,
			atime:       root.atime,
			mtime:       root.mtime,
			ctime:       root.ctime,
		}},
	}
	if root.size > 0 {
		if err := volume.walk(); err != nil {
			return nil, err
		}
	}
	return volume, nil
}

func (v *Volume) walk() error {
	visited := map[uint32]bool{rootInode: true}
	queue := []int{0}
	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]

		list, err := v.directoryListing(directory)
		if err != nil {
			v.unreadable++
			continue
		}
		v.emptySlots += list.empty
		v.malformedSlots += list.malformed
		parentPath := v.nodes[directory].path

		for _, entry := range list.entries {
			if entry.name == "." || entry.name == ".." {
				continue
			}
			in, err := readInode(v.src, v.superblock, entry.inode)
			if err != nil {
				v.undecodable++
				continue
			}
			if len(v.nodes) >= maxNodes {
				return corruptf("the image names more than %d entries", maxNodes)
			}
			path := "/" + entry.name
			if parentPath != "/" {
				path = parentPath + "/" + entry.name
			}

			undecodable := false
			var allocated uint64
			allocatedOK := false
			if in.kind.hasData() {
				file, err := v.fileSource(in)
				if err != nil {
					undecodable = true
				} else {
					allocated = file.allocatedBytes()
					allocatedOK = true
				}
			}
			target := ""
			targetOK := false
			if in.kind == kindSymlink {
				target, targetOK = v.symlinkTarget(in)
				if !targetOK {
					undecodable = true
				}
			}
			if undecodable {
				v.undecodable++
			}

			child := len(v.nodes)
			v.nodes = append(v.nodes, node{
				name:          entry.name,
				path:          path,
				parent:        directory,
				inodeNumber:   in.number,
				kind:          in.kind,
				mode:          in.mode,
				uid:           in.uid,
				gid:           in.gid,
				size:          uint64(in.size),
				links:         in.links,
				generation:    in.generation,
				atime:         in.atime,
				mtime:         in.mtime,
				ctime:         in.ctime,
				allocated:     allocated,
				allocatedOK:   allocatedOK,
				symlinkTarget: target,
				symlinkOK:     targetOK,
			})
			v.inodes = append(v.inodes, *in)
			v.nodes[directory].children = append(v.nodes[directory].children, child)
			v.paths[path] = child

			if in.kind != kindDirectory {
				continue
			}
			if visited[in.number] {
				// A second name for a directory is a hard link the format does
				// not allow; list it, but do not walk its contents twice.
				v.directoryLoops++
				continue
			}
			visited[in.number] = true
			queue = append(queue, child)
		}
	}
	return nil
}

func (v *Volume) directoryListing(directory int) (*listing, error) {
	in := &v.inodes[directory]
	size := uint64(in.size)
	if size == 0 {
		return &listing{}, nil
	}
	if size > maxDirectoryBytes {
		return nil, corruptf("directory %s declares %d listing bytes, more than %d",
			v.nodes[directory].path, size, maxDirectoryBytes)
	}
	file, err := v.fileSource(in)
	if err != nil {
		return nil, err
	}
	bytes := make([]byte, int(size))
	if _, err := file.readAt(0, bytes); err != nil {
		return nil, err
	}
	return parseDir(bytes, v.superblock.byteOrder)
}

func (v *Volume) fileSource(in *inode) (*fileSource, error) {
	id := source.ID(nextFileSourceID.Add(1) + 1_000_000)
	return newFileSource(id, v.src, v.superblock, in)
}

func (v *Volume) symlinkTarget(in *inode) (string, bool) {
	if in.size == 0 || uint64(in.size) > maxSymlinkBytes {
		return "", false
	}
	file, err := v.fileSource(in)
	if err != nil {
		return "", false
	}
	bytes := make([]byte, int(in.size))
	if _, err := file.readAt(0, bytes); err != nil {
		return "", false
	}
	return strings.ToValidUTF8(string(bytes), "�"), true
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return pathpkg.Clean(path)
}

func (v *Volume) lookup(path string) (int, error) {
	index, ok := v.paths[normalizePath(path)]
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrPathNotFound, path)
	}
	return index, nil
}

func (v *Volume) entryOf(index int) Entry {
	n := &v.nodes[index]
	return Entry{
		Name:               n.name,
		Path:               n.path,
		IsDir:              n.kind == kindDirectory,
		IsFile:             n.kind == kindFile,
		IsSymlink:          n.kind == kindSymlink,
		Mode:               n.mode,
		UID:                n.uid,
		GID:                n.gid,
		Size:               n.size,
		Allocated:          n.allocated,
		AllocatedKnown:     n.allocatedOK,
		InodeNumber:        n.inodeNumber,
		Links:              n.links,
		Generation:         n.generation,
		Atime:              stampTime(n.atime),
		Mtime:              stampTime(n.mtime),
		Ctime:              stampTime(n.ctime),
		SymlinkTarget:      n.symlinkTarget,
		SymlinkTargetKnown: n.symlinkOK,
	}
}

func stampTime(seconds uint32) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(int64(seconds), 0).UTC()
}

// ListDir returns the entries of the directory at path, in stored order.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := &v.nodes[index]
	if n.kind != kindDirectory {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotADirectory, n.path, n.kind.label())
	}
	entries := make([]Entry, 0, len(n.children))
	for _, child := range n.children {
		entries = append(entries, v.entryOf(child))
	}
	return entries, nil
}

// Stat returns the entry at path.
func (v *Volume) Stat(path string) (*Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.entryOf(index)
	return &entry, nil
}

// OpenFile opens a regular file's data.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := &v.nodes[index]
	if n.kind != kindFile {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotAFile, n.path, n.kind.label())
	}
	return v.fileSource(&v.inodes[index])
}

// OpenSymlink opens a symbolic link's target as a data stream.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := &v.nodes[index]
	if n.kind != kindSymlink {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotAFile, n.path, n.kind.label())
	}
	return v.fileSource(&v.inodes[index])
}

// FreeList walks the chained free-block list without building a map.
func (v *Volume) FreeList() (*FreeList, error) {
	return freeWalk(v.superblock, v.src)
}

// FreeSpace builds the free-space map from the verified free-block chain.
func (v *Volume) FreeSpace() (*FreeSpace, error) {
	return freeSpace(v.superblock, v.src, v.src.Len())
}

// Info returns volume-level facts.
func (v *Volume) Info() Info {
	directories := 0
	symlinks := 0
	for _, n := range v.nodes {
		if n.kind == kindDirectory {
			directories++
		}
		if n.kind == kindSymlink {
			symlinks++
		}
	}
	sb := v.superblock
	clean, cleanKnown := sb.clean()
	return Info{
		Type:            kindLabel,
		Variant:         sb.variant.label(),
		ByteOrder:       sb.byteOrder.label(),
		Magic:           sb.magic,
		HasMagic:        sb.hasMagic,
		BlockSize:       sb.blockSize,
		FirstDataZone:   sb.firstDataZone(),
		Zones:           sb.zones(),
		InodeCount:      sb.inodeCount(),
		InodeTableBlock: firstInodeZone,
		NameLength:      nameLength,
		DirEntrySize:    directoryEntrySize,
		VolumeName:      sb.fname,
		PackName:        sb.fpack,
		AFS:             sb.afs,
		State:           sb.state,
		HasState:        sb.hasState,
		Clean:           clean,
		CleanKnown:      cleanKnown,
		TFree:           sb.tfree,
		TInode:          sb.tinode,
		NInode:          sb.ninode,
		Entries:         len(v.nodes),
		Directories:     directories,
		Files:           len(v.nodes) - directories,
		Symlinks:        symlinks,
		EmptySlots:      v.emptySlots,
		MalformedSlots:  v.malformedSlots,
		DirectoryLoops:  v.directoryLoops,
		Unreadable:      v.unreadable,
		Undecodable:     v.undecodable,
	}
}
