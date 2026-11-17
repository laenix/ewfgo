package cramfs

import (
	"fmt"
	pathpkg "path"
	"strings"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/source"
)

// CramFS is a compressed read-only image with no timestamps and no inode
// table. A 76-byte superblock (at byte zero, or 512 behind a boot header) ends
// in the root inode; every other inode lives inside the directory listing that
// names it, followed by the name. A listing is a sequence of
// (twelve-byte inode, name padded to four bytes) entries with no header, no
// count and no "." or "..". There are no hard links and no deleted names: a
// removal rewrites the image.
//
// A handle is a node index in this mount's walk, zero being the root, because
// the format records neither an inode number nor an inode table.

const (
	kindLabel = "CramFS"
	// rootRecord is the handle of the volume root.
	rootRecord uint64 = 0
	// maxDirectoryBytes bounds one directory listing.
	maxDirectoryBytes = 64 * 1024 * 1024
	// maxNodes bounds the walk.
	maxNodes = 5_000_000
	// maxSymlinkBytes is the longest symbolic-link target accepted.
	maxSymlinkBytes = 4096
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
	// Allocated is the bytes the file stores; it is meaningful only when
	// AllocatedKnown is true (a file whose block table did not validate keeps
	// its name but no allocation).
	Allocated      uint64
	AllocatedKnown bool

	// InodeOffset is the absolute image offset of the twelve-byte inode.
	InodeOffset uint64
	// Handle is the node index this mount uses to address the entry; zero is
	// the root. CramFS records no inode number of its own.
	Handle uint64

	SymlinkTarget string
}

// Info is the volume-level description returned by Volume.Info.
type Info struct {
	Type        string
	Version     string // "2" when the fsid version-2 flag is set, else "1"
	BlockSize   uint32
	Entries     int
	Name        string
	Base        uint64
	SignatureOK bool

	Flags     uint32
	FlagNames []string

	// Size, Edition, Blocks, Files and CRC are meaningful for an FSID
	// version-2 superblock. CRC is reported as recorded; VerifyCRC compares it.
	Size    uint32
	Edition uint32
	Blocks  uint32
	Files   uint32
	CRC     uint32
	Future  uint32

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

// Volume is an opened CramFS image.
type Volume struct {
	src         source.ByteSource
	sb          superblock
	inodes      []inode
	nodes       []node
	paths       map[string]int
	unreadable  uint64
	undecodable uint64
}

var nextFileSourceID atomic.Uint64

// Detect reports whether byte zero or byte 512 carries a CramFS superblock.
// A big-endian image is recognised and refused by name.
func Detect(src source.ByteSource) (bool, error) {
	_, found, err := detectBase(src)
	if err != nil {
		return false, err
	}
	return found, nil
}

// Open reads the superblock and walks every directory. The walk happens here
// rather than lazily because the image has no index of names: enumerating it
// is the walk.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := readSuperblock(src)
	if err != nil {
		return nil, err
	}
	vol := &Volume{src: src, sb: sb, paths: make(map[string]int)}
	if err := vol.walk(); err != nil {
		return nil, err
	}
	return vol, nil
}

func (v *Volume) walk() error {
	root := v.sb.root
	v.inodes = append(v.inodes, root)
	v.nodes = append(v.nodes, node{
		record:      rootRecord,
		parent:      -1,
		name:        "/",
		path:        "/",
		inodeOffset: 0,
		inode:       root,
		size:        uint64(root.size),
	})
	v.paths["/"] = 0

	if v.sb.isEmpty() {
		return nil
	}

	visited := map[uint64]bool{root.dataOffset(): true}
	queue := []int{0}
	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]

		listing, err := v.directoryEntries(directory)
		if err != nil {
			v.unreadable++
			continue
		}
		parentPath := v.nodes[directory].path
		for _, entry := range listing {
			if len(v.nodes) >= maxNodes {
				return corruptf("the image names more than %d entries", maxNodes)
			}
			path := entry.name
			if parentPath == "/" {
				path = "/" + path
			} else {
				path = parentPath + "/" + path
			}

			child := node{
				record:      uint64(len(v.nodes)),
				parent:      directory,
				name:        entry.name,
				path:        path,
				inodeOffset: entry.offset,
				inode:       entry.inode,
				size:        uint64(entry.inode.size),
			}
			if entry.inode.kind == inodeFile {
				file, err := v.fileSource(entry.inode)
				if err != nil {
					v.undecodable++
				} else {
					child.allocated = file.allocatedBytes()
					child.allocatedKnown = true
				}
			}
			if entry.inode.kind == inodeSymlink {
				target, ok := v.symlinkTarget(entry.inode)
				if ok {
					child.symlinkTarget = target
				} else {
					v.undecodable++
				}
			}

			index := len(v.nodes)
			v.nodes = append(v.nodes, child)
			v.inodes = append(v.inodes, entry.inode)
			v.nodes[directory].children = append(v.nodes[directory].children, index)
			v.paths[path] = index

			if entry.inode.kind == inodeDirectory {
				offset := entry.inode.dataOffset()
				if !visited[offset] {
					visited[offset] = true
					queue = append(queue, index)
				}
			}
		}
	}
	return nil
}

// directoryEntries reads and parses one directory's listing.
func (v *Volume) directoryEntries(directory int) ([]dirEntry, error) {
	in := v.inodes[directory]
	size := uint64(in.size)
	if size == 0 {
		return nil, nil
	}
	if size > maxDirectoryBytes {
		return nil, corruptf("directory %s declares %d listing bytes, more than %d",
			v.nodes[directory].path, size, maxDirectoryBytes)
	}
	start := in.dataOffset()
	limit := v.sb.limit(v.src.Len())
	if start > limit || size > limit-start {
		return nil, corruptf("directory %s at %d of %d bytes runs past byte %d",
			v.nodes[directory].path, start, size, limit)
	}
	bytes := make([]byte, size)
	if err := source.ReadExactAt(v.src, start, bytes); err != nil {
		return nil, err
	}
	return parseDir(bytes, start)
}

// symlinkTarget reads a symbolic link's target from its block table.
func (v *Volume) symlinkTarget(in inode) (string, bool) {
	size := uint64(in.size)
	if size == 0 || size > maxSymlinkBytes {
		return "", false
	}
	file, err := v.fileSource(in)
	if err != nil {
		return "", false
	}
	bytes := make([]byte, size)
	if _, err := file.readAtInternal(0, bytes); err != nil {
		return "", false
	}
	return strings.ToValidUTF8(string(bytes), "�"), true
}

func (v *Volume) fileSource(in inode) (*fileSource, error) {
	id := source.ID(nextFileSourceID.Add(1) + 3_000_000)
	return newFileSource(id, v.src, v.sb.limit(v.src.Len()), in.dataOffset(), uint64(in.size))
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
		Name:           n.name,
		Path:           n.path,
		IsDir:          n.inode.kind == inodeDirectory,
		IsFile:         n.inode.kind == inodeFile,
		IsSymlink:      n.inode.kind == inodeSymlink,
		Mode:           n.inode.mode,
		UID:            uint32(n.inode.uid),
		GID:            uint32(n.inode.gid),
		Size:           n.size,
		Allocated:      n.allocated,
		AllocatedKnown: n.allocatedKnown,
		InodeOffset:    n.inodeOffset,
		Handle:         n.record,
		SymlinkTarget:  n.symlinkTarget,
	}
}

// Info returns volume-level facts.
func (v *Volume) Info() Info {
	version := "1"
	if v.sb.hasFSIDv2() {
		version = "2"
	}
	return Info{
		Type:        kindLabel,
		Version:     version,
		BlockSize:   uint32(blockSize),
		Entries:     len(v.nodes),
		Name:        v.sb.name,
		Base:        v.sb.base,
		SignatureOK: v.sb.signatureOK,
		Flags:       v.sb.flags,
		FlagNames:   flagNames(v.sb.flags),
		Size:        v.sb.size,
		Edition:     v.sb.edition,
		Blocks:      v.sb.blocks,
		Files:       v.sb.files,
		CRC:         v.sb.crc,
		Future:      v.sb.future,
		Unreadable:  v.unreadable,
		Undecodable: v.undecodable,
	}
}

// VerifyCRC compares the superblock's fsid checksum with a fresh CRC-32 over
// the image. It reads every declared image byte and is therefore never done as
// a side effect of Open.
func (v *Volume) VerifyCRC() (CRCVerification, error) {
	return v.sb.verifyCRC(v.src)
}

// ListDir returns the entries of the directory at path, in stored order.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := v.nodes[index]
	if n.inode.kind != inodeDirectory {
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
	if n.inode.kind != inodeFile {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotAFile, n.path, n.inode.kind.label())
	}
	return v.fileSource(n.inode)
}

// OpenSymlink opens a symbolic link's target bytes as a stream. OpenFile does
// not serve a link; the target is also available on Entry.SymlinkTarget.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := v.nodes[index]
	if n.inode.kind != inodeSymlink {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotASymlink, n.path, n.inode.kind.label())
	}
	return v.fileSource(n.inode)
}
