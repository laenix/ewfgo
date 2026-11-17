package erofs

import (
	"fmt"
	"math"
	pathpkg "path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// EROFS is the compressed read-only filesystem Android uses for its system
// and vendor partitions. A 128-byte superblock at byte 1024 names the root
// directory's node id, the block size, and where the inode area starts. Every
// inode is addressed by a 64-bit node id into that area, in 32-byte slots:
// iloc = meta_blkaddr * block_size + (nid << 5). A directory listing is the
// only place a name exists, so opening the image walks every directory once;
// the walk is the inventory.
//
// A handle is the node id itself. Two hard-linked names therefore share a
// handle.

const (
	kindLabel = "EROFS"
	// maxDirectoryBytes bounds one directory listing.
	maxDirectoryBytes = 64 * 1024 * 1024
	// maxNodes bounds the walk.
	maxNodes = 5_000_000
	// maxSymlinkBytes is the longest symbolic-link target accepted.
	maxSymlinkBytes = 64 * 1024
	// inodeReadBytes is the most an inode slot can occupy.
	inodeReadBytes = int(inodeExtendedBytes)
)

// Entry describes one name the walk found.
type Entry struct {
	Name string
	// Path is the display path, '/'-separated.
	Path string

	IsDir     bool
	IsFile    bool
	IsSymlink bool

	// Mode holds the permission and type bits exactly as recorded.
	Mode uint16
	UID  uint32
	GID  uint32

	// Size is a file's length or a directory's listing byte count.
	Size uint64
	// Allocated is the bytes the file stores; meaningful only when
	// AllocatedKnown is true (a file whose layout this reader refused keeps its
	// name but no allocation).
	Allocated      uint64
	AllocatedKnown bool

	// Inode is the node id directory entries store.
	Inode uint64
	// InodeOffset is the absolute image offset of the inode slot.
	InodeOffset uint64
	NLink       uint32
	// Layout is the recorded data layout, as a label.
	Layout string

	// Modified is the extended inode's stored time when the superblock's mtime
	// feature makes it evidence.
	Modified    time.Time
	HasModified bool
	// Changed is the same stored time; EROFS records one time and the reader
	// applies it to both.
	Changed    time.Time
	HasChanged bool

	SymlinkTarget string
}

// Info is the volume-level description returned by Volume.Info.
type Info struct {
	Type      string
	Version   string
	BlockSize uint32
	BlockBits uint8
	Blocks    uint32
	Inodes    uint64
	RootNID   uint32
	Entries   int

	VolumeName  string
	UUID        string
	UUIDPresent bool

	FeatureCompat   uint32
	FeatureIncompat uint32
	CompatNames     []string
	IncompatNames   []string

	Checksum         uint32
	ChecksumRecorded bool

	BuildTime        time.Time
	BuildTimeSeconds uint64
	BuildTimeNsec    uint32
	HasMtime         bool

	AvailableComprAlgs uint16
	ExtSlots           uint8

	Unreadable  uint64
	Undecodable uint64
}

type node struct {
	record         uint64
	parent         int
	name           string
	path           string
	inodeOffset    uint64
	inode          inode
	size           uint64
	allocated      uint64
	allocatedKnown bool
	symlinkTarget  string
	children       []int
}

// Volume is an opened EROFS image.
type Volume struct {
	src         source.ByteSource
	sb          superblock
	inodes      map[uint64]inode
	nodes       []node
	index       map[uint64]int
	paths       map[string]int
	unreadable  uint64
	undecodable uint64
}

var nextFileSourceID atomic.Uint64

// Detect reports whether byte 1024 carries an EROFS superblock.
func Detect(src source.ByteSource) (bool, error) {
	return detectSource(src)
}

// Open reads the superblock and walks every directory. The walk happens here
// rather than lazily because the image has no index of names.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := readSuperblock(src)
	if err != nil {
		return nil, err
	}
	vol := &Volume{
		src:    src,
		sb:     sb,
		inodes: make(map[uint64]inode),
		index:  make(map[uint64]int),
		paths:  make(map[string]int),
	}
	if err := vol.walk(); err != nil {
		return nil, err
	}
	return vol, nil
}

func (v *Volume) walk() error {
	rootRecord := uint64(v.sb.rootNID)
	root, err := v.loadInode(rootRecord)
	if err != nil {
		return err
	}
	if root.kind != kindDirectory {
		return corruptf("the root node %d is a %s, not a directory",
			rootRecord, root.kind.label())
	}
	rootOffset, err := v.sb.iloc(rootRecord)
	if err != nil {
		return err
	}
	v.nodes = append(v.nodes, node{
		record:      rootRecord,
		parent:      -1,
		name:        "/",
		path:        "/",
		inodeOffset: rootOffset,
		inode:       root,
		size:        root.size,
	})
	v.index[rootRecord] = 0
	v.paths["/"] = 0

	visited := map[uint64]bool{rootRecord: true}
	queue := []uint64{rootRecord}
	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		directoryIndex, ok := v.index[directory]
		if !ok {
			continue
		}
		listing, err := v.directoryEntries(directory)
		if err != nil {
			v.unreadable++
			continue
		}
		parentPath := v.nodes[directoryIndex].path
		for _, entry := range listing {
			if len(v.nodes) >= maxNodes {
				return corruptf("the image names more than %d entries", maxNodes)
			}
			in, err := v.loadInode(entry.nid)
			if err != nil {
				v.undecodable++
				continue
			}
			path := entry.name
			if parentPath == "/" {
				path = "/" + path
			} else {
				path = parentPath + "/" + path
			}
			offset, err := v.sb.iloc(entry.nid)
			if err != nil {
				v.undecodable++
				continue
			}
			child := node{
				record:      entry.nid,
				parent:      directoryIndex,
				name:        entry.name,
				path:        path,
				inodeOffset: offset,
				inode:       in,
				size:        in.size,
			}
			if in.kind == kindFile {
				file, err := v.fileSource(entry.nid, &in)
				if err != nil {
					v.undecodable++
				} else {
					child.allocated = file.allocatedBytes()
					child.allocatedKnown = true
				}
			}
			if in.kind == kindSymlink {
				target, ok := v.symlinkTarget(entry.nid, &in)
				if ok {
					child.symlinkTarget = target
				} else {
					v.undecodable++
				}
			}

			childIndex := len(v.nodes)
			v.nodes = append(v.nodes, child)
			if _, exists := v.index[entry.nid]; !exists {
				v.index[entry.nid] = childIndex
			}
			v.paths[path] = childIndex
			v.nodes[directoryIndex].children = append(v.nodes[directoryIndex].children, childIndex)
			if in.kind == kindDirectory && !visited[entry.nid] {
				visited[entry.nid] = true
				queue = append(queue, entry.nid)
			}
		}
	}
	return nil
}

// directoryEntries reads and parses one directory's listing, block by block.
func (v *Volume) directoryEntries(directory uint64) ([]dirEntry, error) {
	in, err := v.inodeFor(directory)
	if err != nil {
		return nil, err
	}
	size := in.size
	if size == 0 {
		return nil, nil
	}
	if size > maxDirectoryBytes {
		return nil, corruptf(
			"directory node %d declares %d listing bytes, more than %d",
			directory, size, maxDirectoryBytes)
	}
	file, err := v.fileSource(directory, &in)
	if err != nil {
		return nil, err
	}
	bytes := make([]byte, size)
	if got, err := file.readAtInternal(0, bytes); err != nil || uint64(got) != size {
		if err != nil {
			return nil, err
		}
		return nil, corruptf("directory node %d yielded %d of %d bytes", directory, got, size)
	}
	blockSize := v.sb.blockSize()
	blocks := size / blockSize
	if size%blockSize != 0 {
		blocks++
	}
	var entries []dirEntry
	for index := uint64(0); index < blocks; index++ {
		start := index * blockSize
		remaining := size - start
		max := remaining
		if max > blockSize {
			max = blockSize
		}
		block := bytes[start : start+max]
		parsed, err := parseDirBlock(block, int(max))
		if err != nil {
			return nil, err
		}
		entries = append(entries, parsed...)
	}
	return entries, nil
}

// symlinkTarget reads a symbolic link's target through the same layouts a file
// uses.
func (v *Volume) symlinkTarget(record uint64, in *inode) (string, bool) {
	if in.size == 0 || in.size > maxSymlinkBytes {
		return "", false
	}
	file, err := v.fileSource(record, in)
	if err != nil {
		return "", false
	}
	bytes := make([]byte, in.size)
	if _, err := file.readAtInternal(0, bytes); err != nil {
		return "", false
	}
	return strings.ToValidUTF8(string(bytes), "�"), true
}

func (v *Volume) inodeFor(record uint64) (inode, error) {
	if in, ok := v.inodes[record]; ok {
		return in, nil
	}
	return v.readInodeAt(record)
}

func (v *Volume) loadInode(record uint64) (inode, error) {
	in, err := v.readInodeAt(record)
	if err != nil {
		return inode{}, err
	}
	v.inodes[record] = in
	return in, nil
}

func (v *Volume) readInodeAt(record uint64) (inode, error) {
	if record == 0 {
		return inode{}, corruptf("node id zero names no inode")
	}
	offset, err := v.sb.iloc(record)
	if err != nil {
		return inode{}, err
	}
	limit := v.sb.limit()
	if offset >= limit {
		return inode{}, corruptf("node %d's inode at %d is past byte %d",
			record, offset, limit)
	}
	want := minU64(limit-offset, uint64(inodeReadBytes))
	bytes := make([]byte, want)
	if err := source.ReadExactAt(v.src, offset, bytes); err != nil {
		return inode{}, err
	}
	return parseInode(bytes, v.sb.hasMtime())
}

// fileSource is the stream for an inode, refusing every layout this reader
// does not serve.
func (v *Volume) fileSource(record uint64, in *inode) (*fileSource, error) {
	id := source.ID(nextFileSourceID.Add(1) + 4_000_000)
	blockSize := v.sb.blockSize()
	limit := v.sb.limit()
	switch in.layout {
	case layoutFlatPlain:
		return newPlainFileSource(id, v.src, in.rawBlkaddr(), in.size, blockSize, limit)
	case layoutFlatInline:
		offset, err := v.sb.iloc(record)
		if err != nil {
			return nil, err
		}
		inBlock := offset % blockSize
		header := in.headerBytes()
		if header > blockSize-inBlock {
			return nil, corruptf(
				"node %d's %d-byte inode and xattr body do not fit in its block",
				record, header)
		}
		room := blockSize - inBlock - header
		if in.size > room {
			return nil, corruptf(
				"node %d's %d inline data bytes do not fit in its block after a %d-byte inode and xattr body",
				record, in.size, header)
		}
		start, ok := checkedAdd(offset, header)
		if !ok {
			return nil, corruptf("node %d's inline data overflows the address space", record)
		}
		return newInlineFileSource(id, v.src, start, in.size, limit)
	case layoutCompressedFull, layoutCompressedCompact:
		offset, err := v.sb.iloc(record)
		if err != nil {
			return nil, err
		}
		header, err := readHeader(v.src, &v.sb, *in, offset)
		if err != nil {
			return nil, err
		}
		extents, err := extents(v.src, &v.sb, *in, offset, header)
		if err != nil {
			return nil, err
		}
		return newCompressedFileSource(id, v.src, extents,
			header.lclusterSize(), blockSize, in.size, limit)
	default:
		return nil, unsupportedf("node %d uses the %s layout, which this reader does not decode",
			record, in.layout.label())
	}
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

func inodeTime(in inode) (time.Time, bool) {
	if !in.mtimeValid || in.mtimeSec > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.Unix(int64(in.mtimeSec), int64(in.mtimeNsec)).UTC(), true
}

func (v *Volume) entryOf(index int) Entry {
	n := v.nodes[index]
	modified, hasModified := inodeTime(n.inode)
	return Entry{
		Name:           n.name,
		Path:           n.path,
		IsDir:          n.inode.kind == kindDirectory,
		IsFile:         n.inode.kind == kindFile,
		IsSymlink:      n.inode.kind == kindSymlink,
		Mode:           n.inode.mode,
		UID:            n.inode.uid,
		GID:            n.inode.gid,
		Size:           n.size,
		Allocated:      n.allocated,
		AllocatedKnown: n.allocatedKnown,
		Inode:          n.record,
		InodeOffset:    n.inodeOffset,
		NLink:          n.inode.nlink,
		Layout:         n.inode.layout.label(),
		Modified:       modified,
		HasModified:    hasModified,
		Changed:        modified,
		HasChanged:     hasModified,
		SymlinkTarget:  n.symlinkTarget,
	}
}

// Info returns volume-level facts.
func (v *Volume) Info() Info {
	sb := v.sb
	info := Info{
		Type:               kindLabel,
		Version:            "1.0",
		BlockSize:          uint32(sb.blockSize()),
		BlockBits:          sb.blockBits,
		Blocks:             sb.blocks,
		Inodes:             sb.inos,
		RootNID:            uint32(sb.rootNID),
		Entries:            len(v.nodes),
		VolumeName:         sb.volumeName,
		FeatureCompat:      sb.featureCompat,
		FeatureIncompat:    sb.featureIncompat,
		CompatNames:        compatNames(sb.featureCompat),
		IncompatNames:      incompatNames(sb.featureIncompat),
		Checksum:           sb.checksum,
		ChecksumRecorded:   sb.hasCompat(featureCompatSBChecksum),
		BuildTimeSeconds:   sb.buildTime,
		BuildTimeNsec:      sb.buildTimeNsec,
		HasMtime:           sb.hasMtime(),
		AvailableComprAlgs: sb.availableComprAlgs,
		ExtSlots:           sb.extSlots,
		Unreadable:         v.unreadable,
		Undecodable:        v.undecodable,
	}
	if sb.hasUUID() {
		info.UUID = sb.uuidText()
		info.UUIDPresent = true
	}
	if sb.buildTime <= math.MaxInt64 {
		info.BuildTime = time.Unix(int64(sb.buildTime), int64(sb.buildTimeNsec)).UTC()
	}
	return info
}

// ListDir returns the entries of the directory at path, in stored order.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := v.nodes[index]
	if n.inode.kind != kindDirectory {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotDirectory, n.path, n.inode.kind.label())
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
	n := v.nodes[index]
	if n.inode.kind != kindFile {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotAFile, n.path, n.inode.kind.label())
	}
	return v.fileSource(n.record, &n.inode)
}

// OpenSymlink opens a symbolic link's target bytes as a stream. OpenFile does
// not serve a link; the target is also available on Entry.SymlinkTarget.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := v.nodes[index]
	if n.inode.kind != kindSymlink {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotASymlink, n.path, n.inode.kind.label())
	}
	return v.fileSource(n.record, &n.inode)
}
