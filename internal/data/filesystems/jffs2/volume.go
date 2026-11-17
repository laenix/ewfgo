package jffs2

import (
	"fmt"
	pathpkg "path"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// JFFS2 has no superblock and no inode table: an image is a sequence of
// self-describing nodes. Opening a volume means scanning every node once,
// letting the highest version win, and walking the directory entries the scan
// proved. This file is the Go port of the Rust reference's `mod.rs`.

const (
	// KindLabel is the filesystem name facts and listings report.
	KindLabel = "JFFS2"

	// RootIno is the root directory's inode number.
	RootIno uint32 = 1
	// ROOTIno is the reference's spelling of the root inode number.
	ROOTIno = RootIno

	// scanChunk is how many bytes the node scan reads at a time.
	scanChunk = 1 << 20
	// detectBytes is how far Detect searches for the first node.
	detectBytes uint64 = 1 << 20
	// detectChunk is how many bytes Detect reads at a time.
	detectChunk = 64 * 1024
	// maxNodes bounds the walk, as the reference's MAX_NODES does.
	maxNodes = 5_000_000
	// maxSymlinkBytes is the longest symlink target this reader accepts.
	maxSymlinkBytes uint64 = 64 * 1024
)

// NodeKind is what a name is, as its inode's mode says.
type NodeKind uint8

const (
	// KindDirectory is a directory.
	KindDirectory NodeKind = iota
	// KindFile is a regular file.
	KindFile
	// KindSymlink is a symbolic link.
	KindSymlink
	// KindSpecial is a device node, fifo, or socket: no data stream.
	KindSpecial
)

// Label returns the kind's name.
func (k NodeKind) Label() string {
	switch k {
	case KindDirectory:
		return "directory"
	case KindFile:
		return "regular file"
	case KindSymlink:
		return "symbolic link"
	case KindSpecial:
		return "special file"
	default:
		return "unknown"
	}
}

// kindFromMode maps a mode's file-type bits to a kind. A mode naming no file
// type has no kind, which the walk counts as undecodable.
func kindFromMode(mode uint32) (NodeKind, bool) {
	switch mode & 0o170000 {
	case 0o040000:
		return KindDirectory, true
	case 0o100000:
		return KindFile, true
	case 0o120000:
		return KindSymlink, true
	case 0o020000, 0o060000, 0o010000, 0o140000:
		return KindSpecial, true
	default:
		return 0, false
	}
}

// Entry is one name the walk found.
type Entry struct {
	Name string
	// Path is the display path, `/`-separated.
	Path string

	Inode       uint32
	ParentInode uint32

	IsDir     bool
	IsFile    bool
	IsSymlink bool
	IsSpecial bool

	Mode uint32
	UID  uint32
	GID  uint32
	// Size is a file's or symlink's length; directories and special files
	// report zero, as the reference does.
	Size uint64

	// Version is the inode version the metadata came from.
	Version uint32

	// Allocated is the stored byte count behind the live fragments. It is
	// meaningful only when HasAllocated is set: directories, symlinks,
	// special files, and files whose compressor this reader refused report
	// no allocated count.
	Allocated    uint64
	HasAllocated bool

	SymlinkTarget string

	Atime time.Time
	Mtime time.Time
	Ctime time.Time

	// Deleted is always false for JFFS2 entries that are listed; tombstones
	// are counted in Info.DeletedNames but never surface as entries.
	Deleted bool
}

// Info is the volume's report.
type Info struct {
	Type string

	RootIno uint32
	// Entries counts the live names the walk found, the root included.
	Entries int

	DirentNodes uint64
	InodeNodes  uint64
	// ValidNodes counts nodes whose header verified, including cleanmarkers
	// and other node types the walk does not use.
	ValidNodes uint64
	// InvalidNodes counts nodes that failed their header, body, or data CRC.
	InvalidNodes uint64
	// DeletedNames counts names whose newest dirent is a tombstone.
	DeletedNames uint64
	// Undecodable counts names whose inode was missing, untyped, refused by
	// an unsupported compressor, or whose symlink target could not be read.
	Undecodable uint64
	// Unreadable is kept for a uniform volume interface; a JFFS2 listing is
	// the dirent set, so the scan itself never leaves a directory unread.
	Unreadable uint64
	// Compressors is the sorted set of compressor labels seen on inode
	// nodes, as the reference's BTreeSet reports them.
	Compressors []string
}

// walkNode is one live name as the BFS walk assembled it. Children are
// indices into Volume.entries, which is what preserves two hard links to one
// inode as two distinct names.
type walkNode struct {
	record    uint32
	parent    uint32
	hasParent bool
	name      string
	path      string

	kind NodeKind

	mode uint32
	uid  uint16
	gid  uint16
	size uint64

	allocated     uint64
	hasAllocated  bool
	symlinkTarget string

	atime   time.Time
	mtime   time.Time
	ctime   time.Time
	version uint32

	children []int
}

// direntChild is one live name under a parent, as the dirent versions resolved
// it.
type direntChild struct {
	name string
	ino  uint32
}

// Volume is an opened JFFS2 image.
type Volume struct {
	source source.ByteSource

	// entries is the walked tree, the root first. Tests in this package read
	// it directly; ListDir returns the same nodes through Entry.
	entries []walkNode
	// index maps an inode number to the first entry that named it, which is
	// what a handle resolves to and what stops a duplicate directory inode
	// from being walked twice.
	index map[uint32]int
	// inodes holds every inode node by inode, in scan order.
	inodes map[uint32][]InodeNode
	// newest holds the highest-version inode node for each inode.
	newest map[uint32]InodeNode

	unreadable   uint64
	undecodable  uint64
	deletedNames uint64
	validNodes   uint64
	invalidNodes uint64
	direntNodes  uint64
	inodeNodes   uint64
	compressors  []string

	fileID atomic.Uint64
}

// scanResult is what a scan collected.
type scanResult struct {
	dirents      []Dirent
	inodes       []InodeNode
	validNodes   uint64
	invalidNodes uint64
}

// Detect reports whether src looks like a JFFS2 image without mounting it.
//
// JFFS2 has no superblock to test, so detection depends on finding a dirent or
// inode node whose header verifies within the first megabyte. A freshly erased
// image holding only cleanmarkers is not detected; it carries no names, and an
// explicit Open still reads it.
func Detect(src source.ByteSource) (bool, error) {
	imageLen := src.Len()
	limit := imageLen
	if limit > detectBytes {
		limit = detectBytes
	}
	var pos uint64
	for pos+headerBytes <= limit {
		remaining := limit - pos
		want := remaining
		if want > detectChunk {
			want = detectChunk
		}
		buf, err := source.ReadVecAt(src, pos, want)
		if err != nil {
			return false, err
		}
		i := 0
		for i+headerBytes <= len(buf) {
			if buf[i] == byte(magic&0xff) && buf[i+1] == byte(magic>>8) {
				at := pos + uint64(i)
				header, ok, err := parseNodeHeader(buf[i : i+headerBytes])
				if err == nil && ok {
					if (header.NodeType == nodeTypeDirent || header.NodeType == nodeTypeInode) &&
						at+uint64(header.TotalLen) <= imageLen {
						return true, nil
					}
				}
			}
			i += 4
		}
		next := (len(buf) - (headerBytes - 1) + 3) &^ 3
		pos += uint64(next)
	}
	return false, nil
}

// Open scans the image for nodes, resolves versions, and walks the tree.
func Open(src source.ByteSource) (*Volume, error) {
	scanned, err := scanImage(src)
	if err != nil {
		return nil, err
	}

	inodes := make(map[uint32][]InodeNode)
	compressorSet := make(map[string]struct{})
	for _, node := range scanned.inodes {
		compressorSet[node.Compression.Label()] = struct{}{}
		inodes[node.Ino] = append(inodes[node.Ino], node)
	}

	newest := make(map[uint32]InodeNode)
	for ino, list := range inodes {
		best := list[0]
		for _, node := range list[1:] {
			if node.Version > best.Version ||
				(node.Version == best.Version && node.DataOffset > best.DataOffset) {
				best = node
			}
		}
		newest[ino] = best
	}

	// The highest version of each (parent, name) is the name's fate; a
	// higher-version tombstone hides every older dirent that wrote it. On an
	// exact tie the later scanned dirent wins, matching the reference's
	// `>=` replacement.
	type direntKey struct {
		pino uint32
		name string
	}
	latest := make(map[direntKey]Dirent)
	for _, dirent := range scanned.dirents {
		key := direntKey{pino: dirent.Pino, name: dirent.Name}
		old, seen := latest[key]
		if !seen || dirent.Version >= old.Version {
			latest[key] = dirent
		}
	}

	children := make(map[uint32][]direntChild)
	var deletedNames uint64
	for key, dirent := range latest {
		if dirent.IsDeletion() {
			deletedNames++
			continue
		}
		children[key.pino] = append(children[key.pino], direntChild{name: key.name, ino: dirent.Ino})
	}
	for ino := range children {
		list := children[ino]
		sort.SliceStable(list, func(i, j int) bool { return list[i].name < list[j].name })
		children[ino] = list
	}

	if root, ok := newest[RootIno]; ok {
		kind, known := kindFromMode(root.Mode)
		if !known {
			return nil, corruptf("inode %d is the root but its mode %#o names no file type",
				RootIno, root.Mode)
		}
		if kind != KindDirectory {
			return nil, corruptf("inode %d is the root but its mode names a %s, not a directory",
				RootIno, kind.Label())
		}
	}

	labels := make([]string, 0, len(compressorSet))
	for label := range compressorSet {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	volume := &Volume{
		source:       src,
		index:        make(map[uint32]int),
		inodes:       inodes,
		newest:       newest,
		deletedNames: deletedNames,
		validNodes:   scanned.validNodes,
		invalidNodes: scanned.invalidNodes,
		direntNodes:  uint64(len(scanned.dirents)),
		inodeNodes:   uint64(len(scanned.inodes)),
		compressors:  labels,
	}
	volume.fileID.Store(uint64(src.SourceID()))
	if err := volume.walk(children); err != nil {
		return nil, err
	}
	return volume, nil
}

// KindLabel returns the filesystem's name.
func (v *Volume) KindLabel() string { return KindLabel }

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// RootIno returns the root directory's inode number.
func (v *Volume) RootIno() uint32 { return RootIno }

// Info returns the volume's report.
func (v *Volume) Info() Info {
	return Info{
		Type:         KindLabel,
		RootIno:      RootIno,
		Entries:      len(v.entries),
		DirentNodes:  v.direntNodes,
		InodeNodes:   v.inodeNodes,
		ValidNodes:   v.validNodes,
		InvalidNodes: v.invalidNodes,
		DeletedNames: v.deletedNames,
		Undecodable:  v.undecodable,
		Unreadable:   v.unreadable,
		Compressors:  append([]string(nil), v.compressors...),
	}
}

// Inode returns the newest inode node behind a handle. The bool is false when
// no inode node names it.
func (v *Volume) Inode(ino uint32) (*InodeNode, bool) {
	node, ok := v.newest[ino]
	if !ok {
		return nil, false
	}
	return &node, true
}

// Stat returns the entry named by path. An empty path names the root.
func (v *Volume) Stat(path string) (*Entry, error) {
	index, err := v.lookupPath(path)
	if err != nil {
		return nil, err
	}
	entry := v.entryOf(index)
	return &entry, nil
}

// ListDir lists a directory's live names, sorted by name.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	index, err := v.lookupPath(path)
	if err != nil {
		return nil, err
	}
	node := &v.entries[index]
	if node.kind != KindDirectory {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	out := make([]Entry, 0, len(node.children))
	for _, child := range node.children {
		out = append(out, v.entryOf(child))
	}
	return out, nil
}

// OpenFile opens a regular file's data stream. A directory, symlink, or
// special file has no data stream here and returns a typed error.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	index, err := v.lookupPath(path)
	if err != nil {
		return nil, err
	}
	node := &v.entries[index]
	switch node.kind {
	case KindFile:
		file, err := v.fileSource(node.record)
		if err != nil {
			return nil, err
		}
		return file, nil
	case KindDirectory:
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	default:
		return nil, fmt.Errorf("%w: %s", ErrNotFile, path)
	}
}

// OpenSymlink opens a symbolic link's target bytes as a stream.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	index, err := v.lookupPath(path)
	if err != nil {
		return nil, err
	}
	node := &v.entries[index]
	if node.kind != KindSymlink {
		return nil, fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	file, err := v.fileSource(node.record)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// lookupPath resolves a path to an entry index, normalising `.`, `..`, and
// repeated slashes. A component that names a non-directory is ErrNotDir; a
// name the walk did not find is ErrNotFound.
func (v *Volume) lookupPath(path string) (int, error) {
	clean := normalizePath(path)
	if clean == "/" {
		return 0, nil
	}
	current := 0
	for _, component := range strings.Split(clean, "/") {
		if component == "" {
			continue
		}
		if v.entries[current].kind != KindDirectory {
			return 0, fmt.Errorf("%w: %s", ErrNotDir, path)
		}
		found := -1
		for _, child := range v.entries[current].children {
			if v.entries[child].name == component {
				found = child
				break
			}
		}
		if found < 0 {
			return 0, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		current = found
	}
	return current, nil
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

// entryOf converts one walked node to the public Entry.
func (v *Volume) entryOf(index int) Entry {
	node := &v.entries[index]
	var parent uint32
	if node.hasParent {
		parent = node.parent
	}
	return Entry{
		Name:          node.name,
		Path:          node.path,
		Inode:         node.record,
		ParentInode:   parent,
		IsDir:         node.kind == KindDirectory,
		IsFile:        node.kind == KindFile,
		IsSymlink:     node.kind == KindSymlink,
		IsSpecial:     node.kind == KindSpecial,
		Mode:          node.mode,
		UID:           uint32(node.uid),
		GID:           uint32(node.gid),
		Size:          node.size,
		Version:       node.version,
		Allocated:     node.allocated,
		HasAllocated:  node.hasAllocated,
		SymlinkTarget: node.symlinkTarget,
		Atime:         node.atime,
		Mtime:         node.mtime,
		Ctime:         node.ctime,
	}
}

// walk builds the live tree from the resolved dirent children, breadth first
// from the root. The root is always present: a root dirent set proves the root
// was a directory even when its inode node was never written.
func (v *Volume) walk(children map[uint32][]direntChild) error {
	root := walkNode{
		record: RootIno,
		name:   "/",
		path:   "/",
		kind:   KindDirectory,
	}
	if meta, ok := v.newest[RootIno]; ok {
		root.mode = meta.Mode
		root.uid = meta.UID
		root.gid = meta.GID
		root.mtime = timestamp(meta.MTime)
		root.ctime = timestamp(meta.CTime)
		root.atime = timestamp(meta.ATime)
		root.version = meta.Version
	}
	v.entries = append(v.entries, root)
	v.index[RootIno] = 0

	queue := []uint32{RootIno}
	visited := map[uint32]bool{RootIno: true}

	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]

		directoryIndex, ok := v.index[directory]
		if !ok {
			continue
		}
		parentPath := v.entries[directoryIndex].path
		list := children[directory]

		for _, child := range list {
			if len(v.entries) >= maxNodes {
				return corruptf("the image names more than %d entries", maxNodes)
			}
			meta, ok := v.newest[child.ino]
			if !ok {
				v.undecodable++
				continue
			}
			kind, known := kindFromMode(meta.Mode)
			if !known {
				v.undecodable++
				continue
			}

			path := "/" + child.name
			if parentPath != "/" {
				path = parentPath + "/" + child.name
			}

			var allocated uint64
			hasAllocated := false
			var symlinkTarget string
			switch kind {
			case KindFile:
				file, err := v.fileSource(child.ino)
				if err != nil {
					v.undecodable++
				} else {
					allocated = file.AllocatedBytes()
					hasAllocated = true
				}
			case KindSymlink:
				if target, ok := v.symlinkTarget(child.ino); ok {
					symlinkTarget = target
				} else {
					v.undecodable++
				}
			case KindDirectory, KindSpecial:
			}

			size := uint64(0)
			if kind == KindFile || kind == KindSymlink {
				size = uint64(meta.Size)
			}

			childIndex := len(v.entries)
			v.entries = append(v.entries, walkNode{
				record:        child.ino,
				parent:        directory,
				hasParent:     true,
				name:          child.name,
				path:          path,
				kind:          kind,
				mode:          meta.Mode,
				uid:           meta.UID,
				gid:           meta.GID,
				size:          size,
				allocated:     allocated,
				hasAllocated:  hasAllocated,
				symlinkTarget: symlinkTarget,
				atime:         timestamp(meta.ATime),
				mtime:         timestamp(meta.MTime),
				ctime:         timestamp(meta.CTime),
				version:       meta.Version,
			})
			if _, exists := v.index[child.ino]; !exists {
				v.index[child.ino] = childIndex
			}
			v.entries[directoryIndex].children = append(v.entries[directoryIndex].children, childIndex)

			if kind == KindDirectory && !visited[child.ino] {
				visited[child.ino] = true
				queue = append(queue, child.ino)
			}
		}
	}
	return nil
}

// fileSource assembles a file or symlink stream from every inode node of the
// handle. The length is the newest node's isize.
func (v *Volume) fileSource(ino uint32) (*Jffs2FileSource, error) {
	nodes, ok := v.inodes[ino]
	if !ok {
		return nil, corruptf("inode %d has no nodes", ino)
	}
	newest, ok := v.newest[ino]
	if !ok {
		return nil, corruptf("inode %d has no newest node", ino)
	}
	id := source.ID(v.fileID.Add(1))
	return buildJffs2FileSource(id, v.source, ino, nodes, uint64(newest.Size), v.source.Len())
}

// symlinkTarget reads a symbolic link's target. A missing, empty, oversized,
// or unreadable target is none, which the walk counts as undecodable.
func (v *Volume) symlinkTarget(ino uint32) (string, bool) {
	meta, ok := v.newest[ino]
	if !ok {
		return "", false
	}
	size := uint64(meta.Size)
	if size == 0 || size > maxSymlinkBytes {
		return "", false
	}
	file, err := v.fileSource(ino)
	if err != nil {
		return "", false
	}
	buf := make([]byte, size)
	n, err := file.ReadAt(0, buf)
	if err != nil {
		return "", false
	}
	return strings.ToValidUTF8(string(buf[:n]), "�"), true
}

// timestamp turns a u32 seconds field into a UTC time. Zero is the format's
// "no time", which is the zero time here.
func timestamp(value uint32) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(int64(value), 0).UTC()
}

// scanImage scans the whole image for nodes, four aligned bytes at a time.
func scanImage(src source.ByteSource) (*scanResult, error) {
	imageLen := src.Len()
	result := &scanResult{}
	var pos uint64
	for pos+headerBytes <= imageLen {
		remaining := imageLen - pos
		want := remaining
		if want > scanChunk {
			want = scanChunk
		}
		buf, err := source.ReadVecAt(src, pos, want)
		if err != nil {
			return nil, err
		}

		i := 0
		var resume uint64
		hasResume := false
		for i+headerBytes <= len(buf) {
			if buf[i] == byte(magic&0xff) && buf[i+1] == byte(magic>>8) {
				absolute := pos + uint64(i)
				totlen, isNode, err := readNode(src, absolute, imageLen, result)
				if err != nil {
					return nil, err
				}
				if isNode {
					after := absolute + uint64(totlen)
					if after > pos+uint64(len(buf)) {
						// The node runs past this buffer; resume at its end
						// so its data is never searched for magic.
						resume = after
						hasResume = true
						break
					}
					i = int(after - pos)
					continue
				}
			}
			i += 4
		}

		if hasResume {
			pos = resume
		} else {
			// The first aligned candidate whose 12-byte header is not wholly
			// in this buffer starts at or after `len - 11`.
			next := (len(buf) - (headerBytes - 1) + 3) &^ 3
			pos += uint64(next)
		}
	}
	return result, nil
}

// readNode parses and records the node at offset.
//
// The bool reports a header that verified, which lets the scanner skip the
// node's data. A header that fails its checks, or a node that runs past the
// image, is corruption: counted and stepped over four bytes. Only a source
// read error aborts the scan.
func readNode(src source.ByteSource, offset, imageLen uint64, result *scanResult) (uint32, bool, error) {
	headerBytesBuf := make([]byte, headerBytes)
	if err := source.ReadExactAt(src, offset, headerBytesBuf); err != nil {
		return 0, false, err
	}
	header, ok, err := parseNodeHeader(headerBytesBuf)
	if err != nil {
		result.invalidNodes++
		return 0, false, nil
	}
	if !ok {
		return 0, false, nil
	}
	if offset+uint64(header.TotalLen) > imageLen {
		result.invalidNodes++
		return header.TotalLen, false, nil
	}
	bytes, err := source.ReadVecAt(src, offset, uint64(header.TotalLen))
	if err != nil {
		return 0, false, err
	}
	result.validNodes++

	switch header.NodeType {
	case nodeTypeDirent:
		dirent, parseErr := ParseDirent(bytes)
		if parseErr != nil {
			result.invalidNodes++
		} else {
			result.dirents = append(result.dirents, *dirent)
		}
	case nodeTypeInode:
		inode, parseErr := ParseInodeNode(bytes, offset)
		if parseErr != nil {
			result.invalidNodes++
			break
		}
		end := uint64(inodeFixedBytes) + uint64(inode.CSize)
		if end <= uint64(len(bytes)) && crc32IEEE(bytes[inodeFixedBytes:int(end)]) == inode.DataCRC {
			result.inodes = append(result.inodes, *inode)
		} else {
			result.invalidNodes++
		}
	}
	return header.TotalLen, true, nil
}
