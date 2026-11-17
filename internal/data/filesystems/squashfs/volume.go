package squashfs

import (
	"fmt"
	pathpkg "path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// kindLabel is the filesystem's name as facts and listings report it.
	kindLabel = "SquashFS"
	// maxDirectoryBytes bounds one directory listing.
	maxDirectoryBytes = 64 * 1024 * 1024
	// maxNodes bounds the walk.
	maxNodes = 5_000_000
)

// Entry describes one name the walk found.
type Entry struct {
	Name string
	// Path is the display path, `/`-separated.
	Path string

	IsDir     bool
	IsFile    bool
	IsSymlink bool

	// Mode holds the permission bits as recorded; the type bits belong to the
	// IsDir/IsFile/IsSymlink flags and, for special nodes, nothing here.
	Mode uint16
	UID  uint32
	GID  uint32

	// Size is a file's length or a directory's listing byte count.
	Size uint64
	// Allocated is the bytes the file actually stores.
	Allocated uint64

	// Modified is the modification time in UTC.
	Modified time.Time

	InodeNumber uint32
	// InodeRef is the `(block << 16) | offset` directory entry reference.
	InodeRef uint64
	NLink    uint32

	SymlinkTarget string

	// HasXattr says an extended inode carries an attribute index.
	HasXattr bool
	// Fragment is meaningful only when HasFragment is true.
	Fragment    uint32
	HasFragment bool
	// Blocks is the number of data block entries.
	Blocks int
}

// Info is the volume-level description returned by Volume.Info.
type Info struct {
	Type        string
	Version     string
	BlockSize   uint32
	Compression string
	InodeCount  uint32
	Fragments   uint32
	IDCount     uint16
	BytesUsed   uint64
	Entries     int
	Created     time.Time
	Flags       uint16

	XattrIDs   uint32
	XattrError string

	ExportInodes uint32
	ExportBlocks int
	ExportError  string

	Unreadable      uint64
	Undecodable     uint64
	DuplicateInodes uint64
}

type node struct {
	name          string
	path          string
	parent        int
	inodeRef      uint64
	kind          inodeKind
	mode          uint16
	uid           uint32
	gid           uint32
	modified      uint32
	nlink         uint32
	size          uint64
	allocated     uint64
	fragment      uint32
	blocks        int
	symlinkTarget string
	inodeNumber   uint32
	hasXattr      bool
}

// Volume is a mounted SquashFS 4.0 image.
type Volume struct {
	src    source.ByteSource
	sb     *superblock
	tables *tables
	inodes []*inode
	nodes  []node
	paths  map[string]int

	xattrs    *xattrTable
	xattrErr  error
	export    *ExportTable
	exportErr error

	unreadable      uint64
	undecodable     uint64
	duplicateInodes uint64
}

var nextFileSourceID atomic.Uint64

// Open reads the superblock, its tables and every directory, then walks the
// tree. The walk happens eagerly because SquashFS has no separate name index:
// enumerating the image is the walk.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := readSuperblock(src)
	if err != nil {
		return nil, err
	}
	tables, err := readTables(src, sb)
	if err != nil {
		return nil, err
	}
	xattrs, xattrErr := readXattrTable(src, sb)
	export, exportErr := readExportTable(src, sb)
	vol := &Volume{
		src:       src,
		sb:        sb,
		tables:    tables,
		paths:     make(map[string]int),
		xattrs:    xattrs,
		xattrErr:  xattrErr,
		export:    export,
		exportErr: exportErr,
	}
	if err := vol.walk(); err != nil {
		return nil, err
	}
	return vol, nil
}

func (v *Volume) walk() error {
	cache := newMetadataCache(v.sb.compression)
	root, err := readInode(cache, v.src, v.sb.blockSize, v.sb.inodeTableStart, v.sb.rootInode)
	if err != nil {
		return err
	}
	if root.kind != kindDirectory {
		return corruptf("the root inode is a %s, not a directory", root.kind.label())
	}
	uid, gid, err := v.owner(cache, root)
	if err != nil {
		return err
	}
	v.inodes = append(v.inodes, root)
	v.nodes = append(v.nodes, node{
		name:        "/",
		path:        "/",
		parent:      -1,
		inodeRef:    v.sb.rootInode,
		kind:        root.kind,
		mode:        root.mode,
		uid:         uid,
		gid:         gid,
		modified:    root.modified,
		nlink:       root.nlink,
		size:        root.size,
		allocated:   root.size,
		fragment:    invalidFragment,
		inodeNumber: root.inodeNumber,
		hasXattr:    root.extended && root.xattr != invalidFragment,
	})
	v.paths["/"] = 0

	visited := map[uint64]bool{v.sb.rootInode: true}
	seenInodes := map[uint32]bool{root.inodeNumber: true}
	queue := []int{0}

	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]

		listing, err := v.directoryEntries(cache, directory)
		if err != nil {
			v.unreadable++
			continue
		}
		parentPath := v.nodes[directory].path
		for _, entry := range listing {
			if len(v.nodes) >= maxNodes {
				return corruptf("the image names more than %d entries", maxNodes)
			}
			in, err := readInode(cache, v.src, v.sb.blockSize, v.sb.inodeTableStart, entry.inodeRef)
			if err != nil {
				v.undecodable++
				continue
			}
			childUID, childGID, err := v.owner(cache, in)
			if err != nil {
				return err
			}
			if !seenInodes[in.inodeNumber] {
				seenInodes[in.inodeNumber] = true
			} else {
				v.duplicateInodes++
			}
			path := entry.name
			if parentPath == "/" {
				path = "/" + path
			} else {
				path = parentPath + "/" + path
			}
			var allocated uint64
			if in.kind == kindFile {
				allocated = allocatedBytes(in, v.sb.blockSize)
			}
			child := len(v.nodes)
			v.nodes = append(v.nodes, node{
				name:          entry.name,
				path:          path,
				parent:        directory,
				inodeRef:      entry.inodeRef,
				kind:          in.kind,
				mode:          in.mode,
				uid:           childUID,
				gid:           childGID,
				modified:      in.modified,
				nlink:         in.nlink,
				size:          in.size,
				allocated:     allocated,
				fragment:      in.fragment,
				blocks:        len(in.blocks),
				symlinkTarget: in.symlinkTarget,
				inodeNumber:   in.inodeNumber,
				hasXattr:      in.extended && in.xattr != invalidFragment,
			})
			isDirectory := in.kind == kindDirectory
			v.inodes = append(v.inodes, in)
			v.paths[path] = child
			if isDirectory && !visited[entry.inodeRef] {
				visited[entry.inodeRef] = true
				queue = append(queue, child)
			}
		}
	}
	return nil
}

func (v *Volume) directoryEntries(cache *metadataCache, directory int) ([]dirEntry, error) {
	in := v.inodes[directory]
	if in.size == 0 {
		return nil, nil
	}
	if in.size > maxDirectoryBytes {
		return nil, corruptf("directory %s declares %d listing bytes, more than %d",
			v.nodes[directory].path, in.size, maxDirectoryBytes)
	}
	block := v.sb.directoryTableStart + in.startBlock
	if block < v.sb.directoryTableStart {
		return nil, corruptf("a directory block address overflows")
	}
	bytes, err := cache.span(v.src, block, int(in.dirOffset), int(in.size))
	if err != nil {
		return nil, err
	}
	return parseDir(bytes)
}

func (v *Volume) owner(cache *metadataCache, in *inode) (uint32, uint32, error) {
	uid, err := v.tables.id(cache, v.src, in.uidIndex)
	if err != nil {
		return 0, 0, err
	}
	gid, err := v.tables.id(cache, v.src, in.gidIndex)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
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
	n := v.nodes[index]
	return Entry{
		Name:          n.name,
		Path:          n.path,
		IsDir:         n.kind == kindDirectory,
		IsFile:        n.kind == kindFile,
		IsSymlink:     n.kind == kindSymlink,
		Mode:          n.mode,
		UID:           n.uid,
		GID:           n.gid,
		Size:          n.size,
		Allocated:     n.allocated,
		Modified:      time.Unix(int64(n.modified), 0).UTC(),
		InodeNumber:   n.inodeNumber,
		InodeRef:      n.inodeRef,
		NLink:         n.nlink,
		SymlinkTarget: n.symlinkTarget,
		HasXattr:      n.hasXattr,
		Fragment:      n.fragment,
		HasFragment:   n.fragment != invalidFragment,
		Blocks:        n.blocks,
	}
}

// ListDir returns the entries of the directory at path, in stored order.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := v.nodes[index]
	if n.kind != kindDirectory {
		return nil, fmt.Errorf("squashfs: %s is a %s, not a directory", n.path, n.kind.label())
	}
	entries := make([]Entry, 0)
	// Child indices are not stored, so find them by parent. The path map also
	// gives exact names; scanning the walk keeps stored order.
	for child := range v.nodes {
		if v.nodes[child].parent == index {
			entries = append(entries, v.entryOf(child))
		}
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
	n := v.nodes[index]
	if n.kind != kindFile {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotAFile, n.path, n.kind.label())
	}
	cache := newUncachedMetadata(v.sb.compression)
	id := source.ID(nextFileSourceID.Add(1) + 1_000_000)
	return newFileSource(id, v.src, v.sb.compression, v.sb.blockSize, v.inodes[index], v.tables, cache)
}

// Xattrs returns the extended attributes of the node at path. A node that
// cannot carry attributes returns (nil, nil).
func (v *Volume) Xattrs(path string) (*XattrList, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	in := v.inodes[index]
	if !in.extended || in.xattr == invalidFragment {
		return nil, nil
	}
	if v.xattrs == nil {
		cause := ""
		if v.xattrErr != nil {
			cause = fmt.Sprintf(" (%v)", v.xattrErr)
		}
		return nil, fmt.Errorf("squashfs: node %s carries xattr index %d but the image has no xattr table%s",
			path, in.xattr, cause)
	}
	cache := newUncachedMetadata(v.sb.compression)
	return v.xattrs.attributes(cache, v.src, in.xattr)
}

// InodeByNumber resolves an inode number through the export table.
func (v *Volume) InodeByNumber(number uint32) (*Entry, error) {
	if v.export == nil {
		if v.exportErr != nil {
			return nil, fmt.Errorf("squashfs: inode number %d cannot be looked up: %w", number, v.exportErr)
		}
		return nil, fmt.Errorf("%w: %d", ErrInodeNotFound, number)
	}
	cache := newUncachedMetadata(v.sb.compression)
	ref, found, err := v.export.lookup(cache, v.src, number)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %d", ErrInodeNotFound, number)
	}
	in, err := readInode(cache, v.src, v.sb.blockSize, v.sb.inodeTableStart, ref)
	if err != nil {
		return nil, err
	}
	if in.inodeNumber != number {
		return nil, corruptf("inode number %d resolves to reference %#x, whose header says inode %d",
			number, ref, in.inodeNumber)
	}
	entry := Entry{
		IsDir:         in.kind == kindDirectory,
		IsFile:        in.kind == kindFile,
		IsSymlink:     in.kind == kindSymlink,
		Mode:          in.mode,
		Size:          in.size,
		Modified:      time.Unix(int64(in.modified), 0).UTC(),
		InodeNumber:   in.inodeNumber,
		InodeRef:      ref,
		NLink:         in.nlink,
		SymlinkTarget: in.symlinkTarget,
		HasXattr:      in.extended && in.xattr != invalidFragment,
		Fragment:      in.fragment,
		HasFragment:   in.fragment != invalidFragment,
		Blocks:        len(in.blocks),
	}
	return &entry, nil
}

// ExportError reports why a declared export table could not be read.
func (v *Volume) ExportError() error { return v.exportErr }

// Info returns volume-level facts.
func (v *Volume) Info() Info {
	info := Info{
		Type:            kindLabel,
		Version:         fmt.Sprintf("%d.%d", v.sb.versionMajor, v.sb.versionMinor),
		BlockSize:       v.sb.blockSize,
		Compression:     compressionName(v.sb.compression),
		InodeCount:      v.sb.inodeCount,
		Fragments:       v.sb.fragments,
		IDCount:         v.sb.idCount,
		BytesUsed:       v.sb.bytesUsed,
		Entries:         len(v.nodes),
		Flags:           v.sb.flags,
		Unreadable:      v.unreadable,
		Undecodable:     v.undecodable,
		DuplicateInodes: v.duplicateInodes,
	}
	if v.sb.created != 0 {
		info.Created = time.Unix(int64(v.sb.created), 0).UTC()
	}
	if v.xattrs != nil {
		info.XattrIDs = v.xattrs.ids
	}
	if v.xattrErr != nil {
		info.XattrError = v.xattrErr.Error()
	}
	if v.export != nil {
		info.ExportInodes = v.export.Inodes()
		info.ExportBlocks = v.export.Blocks()
	}
	if v.exportErr != nil {
		info.ExportError = v.exportErr.Error()
	}
	return info
}
