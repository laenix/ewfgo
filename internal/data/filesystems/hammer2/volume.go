// Package hammer2 reads HAMMER2 (DragonFly BSD) images, read-only, from a
// source.ByteSource. It is a Go port of forensic-core's HAMMER2 reader.
//
// HAMMER2 is a copy-on-write, block-addressed filesystem. The bootstrap chain
// is:
//
//	volume header, best of four zone copies   superblock.go
//	  -> super-root inode, key 0              tree.go
//	    -> directory trees of INODE/DIRENT     tree.go, dirent.go
//	      -> file data through block refs      file.go
//
// The reader decodes the volume header (all four copies, CRC-checked, highest
// mirror_tid selected), both inode forms (blockset and 512-byte embedded
// data), directory trees with indirect blocks, inline and external names and
// the PFS hidden-inode store, regular-file and symbolic-link data, and sparse
// holes (HAMMER2 defines an unmapped logical block as zero bytes, reported as
// RangeHole when ranges are exported).
//
// Deliberately unported branches, each refused or reported rather than
// silently guessed at:
//
//   - compressed blocks (LZ4, zlib and AUTOZERO): ErrUnsupported;
//   - freemap blocks and the freemap check algorithm: ErrUnsupported; free
//     space is therefore unavailable and the header's allocator counters are
//     recorded facts only;
//   - reverse-endian (ABO) volumes, multi-volume sets and format versions
//     above 2: ErrUnsupported;
//   - journal replay and older COW versions: only the current tree is walked;
//   - deleted names, whiteouts and superseded directory entries: no deleted
//     name is recovered, so Entry.Deleted is always false.
//
// Times are microseconds since the Unix epoch; a stored zero is reported as
// absent, never as 1970. The kernel never writes btime, but a non-zero stored
// value is reported as the creation time.
package hammer2

import (
	"fmt"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

// KindLabel is the label this reader reports.
const KindLabel = "HAMMER2"

// RootRecord is the walk ordinal of the volume root.
const RootRecord uint64 = 0

// RootKey is HAMMER2_SROOT_KEY: the super-root's key in the volume header.
const RootKey uint64 = 0

// MaxNodes bounds a hostile walk.
const MaxNodes = 5_000_000

// maxDirectoryDepth bounds how far below the root the walk follows
// directories, matching the MaxPathDepth convention of the sibling readers.
// HAMMER2 records no depth on disk, and a crafted image can chain a directory
// to itself through PFS-root references, making every occurrence a new tree
// owner. A depth bound keeps the displayed paths and the recursion finite;
// entries below the bound are listed but not walked.
const maxDirectoryDepth = 512

// maxPathBytes bounds one displayed path. POSIX PATH_MAX is 4096 bytes and a
// HAMMER2 name is at most 256 bytes, so a longer path cannot name a usable
// file. An entry whose path would exceed this is counted malformed and not
// entered into the walk.
const maxPathBytes = 4096

// maxTotalPathBytes bounds the sum of every path string the walk retains.
// A single small indirect block names hundreds of references, so a crafted
// image can multiply a handful of inode records into millions of nodes; this
// keeps the retained path strings bounded independently of that count.
const maxTotalPathBytes = 256 << 20

// MaxSymlinkBytes is the longest symbolic-link target read into an Entry.
const MaxSymlinkBytes uint64 = 64 * 1024

const warningCap = 32

// VolumeStats is what a walk of the whole tree found.
type VolumeStats struct {
	// NodesRead counts inode records read, including linked inodes read again.
	NodesRead uint64
	// BlocksRead counts inode, indirect and external-name blocks read.
	BlocksRead uint64
	// RefsScanned counts tree references examined.
	RefsScanned uint64
	// Refusals counts structures this reader does not decode.
	Refusals uint64
	// Malformed counts structurally invalid records.
	Malformed uint64
}

// Info is a volume's report.
type Info struct {
	Type   string
	FSID   string
	FSType string

	Version            uint32
	VolumeHeaderZone   uint32
	VolumeHeaderOffset uint64
	VoluSize           uint64
	TotalSize          uint64
	AllocatorSize      uint64
	AllocatorFree      uint64
	AllocatorBeg       uint64
	MirrorTid          uint64
	FreemapTid         uint64
	BulkfreeTid        uint64
	CopyID             uint8
	FreemapVersion     uint8
	PeerType           uint8
	NVolumes           uint8

	Entries     int
	Directories int
	Files       int
	Symlinks    int
	PFSRoots    int

	Stats VolumeStats

	Unreadable     uint64
	Undecodable    uint64
	DirectoryLoops uint64

	Warnings        []string
	WarningsDropped uint64
}

// Entry is one name the walk found.
type Entry struct {
	Name string
	// Path is the display path, '/'-separated. The root's path is "/".
	Path   string
	Record uint64
	// ParentRecord is nil for the root.
	ParentRecord *uint64
	// Inode is the HAMMER2 inode number.
	Inode uint64

	IsDir     bool
	IsFile    bool
	IsSymlink bool
	// FileType is the kind's label.
	FileType string

	// Mode is the permission and type bits as recorded.
	Mode  uint32
	UID   uint32
	GID   uint32
	Links uint64
	// Size is the logical length in bytes.
	Size uint64
	// Allocated is nil for a directory or special file, and for a file whose
	// block map did not validate.
	Allocated *uint64

	// Times are microseconds since the Unix epoch; nil when the stored field
	// is zero.
	Accessed *int64
	Modified *int64
	Changed  *int64
	Created  *int64

	// SymlinkTarget is the link text when it was read inline.
	SymlinkTarget string
	// PFSRoot marks a directory that owns a PFS hidden-inode store.
	PFSRoot bool

	// Deleted is always false: HAMMER2 deleted names are not recovered.
	Deleted bool
}

type node struct {
	record    uint64
	parent    *uint64
	name      string
	path      string
	inode     uint64
	kind      InodeKind
	mode      uint32
	uid       uint32
	gid       uint32
	links     uint64
	size      uint64
	allocated *uint64
	accessed  *int64
	modified  *int64
	changed   *int64
	created   *int64
	symlink   string
	pfsRoot   bool
	children  []uint64
}

type treeVisit struct {
	owner uint64
	inum  uint64
}

type queueItem struct {
	record    uint64
	treeOwner uint64
	inherited HiddenMap
	// depth is how many directory levels below the root this record sits.
	depth uint32
}

// Volume is an opened HAMMER2 image.
type Volume struct {
	source     source.ByteSource
	superblock *Superblock
	inodes     []Inode
	nodes      []node
	ownsHidden []bool
	childIndex map[uint64]map[string]uint64
	dirErrors  map[uint64]error

	unreadable      uint64
	undecodable     uint64
	refusals        uint64
	malformed       uint64
	directoryLoops  uint64
	nodesRead       uint64
	blocksRead      uint64
	refsScanned     uint64
	warnings        []string
	warningsDropped uint64

	fileID atomic.Uint64
}

// Detect reports whether src starts with a HAMMER2 volume-header magic in any
// of the four zone copies.
func Detect(src source.ByteSource) (bool, error) {
	return detect(src)
}

// Open reads the volume header and walks every directory reachable from the
// super-root.
func Open(src source.ByteSource) (*Volume, error) {
	superblock, err := ReadSuperblock(src)
	if err != nil {
		return nil, err
	}
	volume := &Volume{
		source:     src,
		superblock: superblock,
		childIndex: make(map[uint64]map[string]uint64),
		dirErrors:  make(map[uint64]error),
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	volume.pushWarning("HAMMER2 is copy-on-write; only the current tree is walked and older committed versions retained by COW are not recovered")
	volume.pushWarning("the freemap (allocation map) is not decoded; free space and a complete allocation account are unavailable, and the volume header's allocator counters are recorded facts only")
	volume.pushWarning("deleted names, whiteouts and superseded directory entries are not recovered; the volume reports no deleted names")
	volume.pushWarning("timestamps are stored in microseconds since the Unix epoch; a zero field is reported as absent, the kernel never writes btime, and the stored atime is reported even though HAMMER2's getattr substitutes mtime")
	if superblock.Zone > 0 {
		volume.pushWarning(fmt.Sprintf(
			"volume header zone %d at byte %d was selected; the earlier copies were absent, invalid or older",
			superblock.Zone, superblock.VolumeOffset))
	}
	if superblock.FSType == FSTypeRFC {
		volume.pushWarning("the volume header fstype uses RFC 4122 byte order rather than DragonFly's native struct field order; both encode the HAMMER2 UUID and this reader accepts both")
	}
	if err := volume.walk(); err != nil {
		return nil, err
	}
	return volume, nil
}

// KindLabel returns the filesystem's name.
func (v *Volume) KindLabel() string { return KindLabel }

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed volume header.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// RootRecord returns the root's walk ordinal.
func (v *Volume) RootRecord() uint64 { return RootRecord }

// Unreadable counts directories or entries whose data could not be read.
func (v *Volume) Unreadable() uint64 { return v.unreadable }

// Undecodable counts names whose inode, block map or link target could not
// be read.
func (v *Volume) Undecodable() uint64 { return v.undecodable }

// Refusals counts structures this reader does not decode.
func (v *Volume) Refusals() uint64 { return v.refusals }

// Malformed counts structurally invalid records.
func (v *Volume) Malformed() uint64 { return v.malformed }

// DirectoryLoops counts directories reached by a second name: listed but not
// walked twice.
func (v *Volume) DirectoryLoops() uint64 { return v.directoryLoops }

// Stats returns the walk's counters.
func (v *Volume) Stats() VolumeStats {
	return VolumeStats{
		NodesRead:   v.nodesRead,
		BlocksRead:  v.blocksRead,
		RefsScanned: v.refsScanned,
		Refusals:    v.refusals,
		Malformed:   v.malformed,
	}
}

// Warnings returns the volume's retained warnings.
func (v *Volume) Warnings() []string { return v.warnings }

// WarningsDropped returns how many warnings were discarded past the cap.
func (v *Volume) WarningsDropped() uint64 { return v.warningsDropped }

// NodeCount returns the number of nodes the walk found.
func (v *Volume) NodeCount() int { return len(v.nodes) }

// Info returns the volume's report.
func (v *Volume) Info() Info {
	var directories, files, symlinks, pfsRoots int
	for _, n := range v.nodes {
		switch {
		case n.kind.IsDirectory():
			directories++
		case n.kind.IsRegular():
			files++
		case n.kind.IsSymlink():
			symlinks++
		}
		if n.pfsRoot {
			pfsRoots++
		}
	}
	return Info{
		Type:               KindLabel,
		FSID:               v.superblock.FSIDHex(),
		FSType:             FSTypeUUID,
		Version:            v.superblock.Version,
		VolumeHeaderZone:   v.superblock.Zone,
		VolumeHeaderOffset: v.superblock.VolumeOffset,
		VoluSize:           v.superblock.VoluSize,
		TotalSize:          v.superblock.TotalSize,
		AllocatorSize:      v.superblock.AllocatorSize,
		AllocatorFree:      v.superblock.AllocatorFree,
		AllocatorBeg:       v.superblock.AllocatorBeg,
		MirrorTid:          v.superblock.MirrorTid,
		FreemapTid:         v.superblock.FreemapTid,
		BulkfreeTid:        v.superblock.BulkfreeTid,
		CopyID:             v.superblock.CopyID,
		FreemapVersion:     v.superblock.FreemapVersion,
		PeerType:           v.superblock.PeerType,
		NVolumes:           v.superblock.NVolumes,
		Entries:            len(v.nodes),
		Directories:        directories,
		Files:              files,
		Symlinks:           symlinks,
		PFSRoots:           pfsRoots,
		Stats:              v.Stats(),
		Unreadable:         v.unreadable,
		Undecodable:        v.undecodable,
		DirectoryLoops:     v.directoryLoops,
		Warnings:           append([]string(nil), v.warnings...),
		WarningsDropped:    v.warningsDropped,
	}
}

// ListDir lists a directory's entries. A directory whose data could not be
// read returns that recorded error rather than an empty listing.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	record, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := &v.nodes[record]
	if !n.kind.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	if err := v.dirErrors[record]; err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(n.children))
	for _, child := range n.children {
		out = append(out, v.entry(child))
	}
	return out, nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	record, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.entry(record)
	return &entry, nil
}

// OpenFile opens the regular file named by path as a byte source.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	record, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	inode := &v.inodes[record]
	if inode.Kind.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	if inode.Kind != KindRegular {
		return nil, fmt.Errorf("%w: %s", ErrNotFile, path)
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.source, inode)
}

// OpenSymlink opens a symbolic link's target as a byte source. A short
// link's target is embedded in its inode; a long link's target is its data
// stream.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	record, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	inode := &v.inodes[record]
	if inode.Kind != KindSymlink {
		return nil, fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.source, inode)
}

// SymlinkTarget returns the link text recorded in the walk.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	record, err := v.lookup(path)
	if err != nil {
		return "", err
	}
	n := &v.nodes[record]
	if n.kind != KindSymlink {
		return "", fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	if n.symlink == "" {
		return "", fmt.Errorf("%w: %s", ErrNoSymlinkTarget, path)
	}
	return n.symlink, nil
}

func (v *Volume) entry(record uint64) Entry {
	n := &v.nodes[record]
	return Entry{
		Name:          n.name,
		Path:          n.path,
		Record:        n.record,
		ParentRecord:  n.parent,
		Inode:         n.inode,
		IsDir:         n.kind.IsDirectory(),
		IsFile:        n.kind.IsRegular(),
		IsSymlink:     n.kind.IsSymlink(),
		FileType:      n.kind.String(),
		Mode:          n.mode,
		UID:           n.uid,
		GID:           n.gid,
		Links:         n.links,
		Size:          n.size,
		Allocated:     n.allocated,
		Accessed:      n.accessed,
		Modified:      n.modified,
		Changed:       n.changed,
		Created:       n.created,
		SymlinkTarget: n.symlink,
		PFSRoot:       n.pfsRoot,
	}
}

func (v *Volume) lookup(path string) (uint64, error) {
	record := RootRecord
	if path == "" || path == "/" {
		return record, nil
	}
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			if parent := v.nodes[record].parent; parent != nil {
				record = *parent
			}
			continue
		}
		next, ok := v.childIndex[record][component]
		if !ok {
			return 0, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		record = next
	}
	return record, nil
}

func (v *Volume) walk() error {
	rootReference, ok := firstNonEmpty(v.superblock.SrootBlockset)
	if !ok {
		return corruptf("the volume header's super-root blockset is empty; there is no key-0 inode to start the walk")
	}
	if rootReference.BType != BrefTypeInode {
		return corruptf("the volume header's super-root blockset holds a %s reference, not an inode",
			TypeLabel(rootReference.BType))
	}
	if rootReference.Key != RootKey {
		return corruptf("the volume header's super-root reference has key %d (0x%016x), not the super-root key 0",
			rootReference.Key, rootReference.Key)
	}

	state := NewScanState()
	rootInode, err := readInodeRef(v.source, rootReference, "the super-root inode", state)
	if err != nil {
		return err
	}
	if !rootInode.Kind.IsDirectory() {
		return corruptf("the super-root inode is a %s, not a directory", rootInode.Kind)
	}

	rootNode := nodeFromInode(RootRecord, nil, "/", "/", rootInode, nil, "", false)
	v.nodes = append(v.nodes, rootNode)
	v.inodes = append(v.inodes, *rootInode)
	v.ownsHidden = append(v.ownsHidden, true)

	visited := map[treeVisit]bool{{owner: RootRecord, inum: rootInode.Inum}: true}
	queue := []queueItem{{record: RootRecord, treeOwner: RootRecord, inherited: HiddenMap{}}}
	pathBytes := uint64(len(rootNode.path))
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		inode := v.inodes[item.record]
		path := v.nodes[item.record].path
		ownsHidden := v.ownsHidden[item.record]
		scan, err := scanDirectory(v.source, &inode, item.inherited, ownsHidden,
			"directory "+path, state)
		if err != nil {
			return err
		}
		effective := item.inherited
		if ownsHidden {
			effective = scan.Hidden
		}

		for index := range scan.Entries {
			entry := &scan.Entries[index]
			if len(v.nodes) >= MaxNodes {
				return corruptf("the image names more than %d entries", MaxNodes)
			}
			parent := item.record
			parentPath := v.nodes[parent].path
			childPath := "/" + entry.Name
			if parentPath != "/" {
				childPath = parentPath + "/" + entry.Name
			}
			if len(childPath) > maxPathBytes {
				state.Malformed++
				state.Warn(fmt.Sprintf(
					"%s: the path is %d bytes, longer than the %d-byte limit; the entry is not walked",
					childPath, len(childPath), maxPathBytes))
				continue
			}
			if pathBytes+uint64(len(childPath)) > maxTotalPathBytes {
				return corruptf("the image's directory paths exceed %d bytes; refusing to retain more",
					maxTotalPathBytes)
			}
			pathBytes += uint64(len(childPath))
			allocated, symlinkTarget, extra := v.describeEntry(entry, childPath, state)
			child := uint64(len(v.nodes))
			isDirectory := entry.Inode.Kind.IsDirectory()
			childOwns := entry.PFSRoot
			if childOwns && !isDirectory {
				state.Malformed++
				state.Warn(fmt.Sprintf("entry %s: a %s carries the PFS-root flag; only a directory can own a PFS",
					childPath, entry.Inode.Kind))
				childOwns = false
			}
			childTreeOwner := item.treeOwner
			if childOwns {
				childTreeOwner = child
			}
			parentRecord := parent
			parentCopy := parentRecord
			node := nodeFromInode(child, &parentCopy, entry.Name, childPath, entry.Inode,
				allocated, symlinkTarget, childOwns)
			v.nodes = append(v.nodes, node)
			v.inodes = append(v.inodes, *entry.Inode)
			v.ownsHidden = append(v.ownsHidden, childOwns)
			v.nodes[parent].children = append(v.nodes[parent].children, child)
			if v.childIndex[parent] == nil {
				v.childIndex[parent] = make(map[string]uint64)
			}
			if _, exists := v.childIndex[parent][entry.Name]; !exists {
				v.childIndex[parent][entry.Name] = child
			}
			v.blocksRead += extra
			if isDirectory {
				key := treeVisit{owner: childTreeOwner, inum: entry.Inode.Inum}
				if !visited[key] {
					visited[key] = true
					if item.depth >= maxDirectoryDepth {
						state.Malformed++
						state.Warn(fmt.Sprintf(
							"directory %s: not walked; it is deeper than the %d-level directory limit",
							childPath, maxDirectoryDepth))
					} else {
						queue = append(queue, queueItem{
							record: child, treeOwner: childTreeOwner, inherited: effective,
							depth: item.depth + 1,
						})
					}
				} else {
					state.DirectoryLoops++
				}
			}
		}
	}

	v.unreadable = state.Unreadable
	v.undecodable = state.Undecodable
	v.refusals = state.Refusals
	v.malformed = state.Malformed
	v.directoryLoops = state.DirectoryLoops
	v.nodesRead = state.NodesRead
	v.blocksRead += state.BlocksRead
	v.refsScanned = state.RefsScanned
	v.warnings = append(v.warnings, state.Warnings...)
	v.warningsDropped += state.WarningsDropped
	if len(v.warnings) > warningCap {
		extra := len(v.warnings) - warningCap
		v.warnings = v.warnings[:warningCap]
		v.warningsDropped += uint64(extra)
	}
	return nil
}

func firstNonEmpty(set *Blockset) (*Blockref, bool) {
	if set == nil {
		return nil, false
	}
	for index := range set.Refs() {
		ref := set.Refs()[index]
		if ref.BType != BrefTypeEmpty {
			return &ref, true
		}
	}
	return nil, false
}

func nodeFromInode(record uint64, parent *uint64, name, path string, inode *Inode,
	allocated *uint64, symlinkTarget string, pfsRoot bool) node {
	return node{
		record:    record,
		parent:    parent,
		name:      name,
		path:      path,
		inode:     inode.Inum,
		kind:      inode.Kind,
		mode:      inode.Mode,
		uid:       inode.UID,
		gid:       inode.GID,
		links:     inode.NLinks,
		size:      inode.Size,
		allocated: allocated,
		accessed:  inode.Atime,
		modified:  inode.Mtime,
		changed:   inode.Ctime,
		created:   inode.Btime,
		symlink:   symlinkTarget,
		pfsRoot:   pfsRoot,
	}
}

// describeEntry reports allocated bytes, link text and blocks read for one
// file, symlink or special entry.
func (v *Volume) describeEntry(entry *VisibleEntry, path string, state *ScanState) (*uint64, string, uint64) {
	switch entry.Inode.Kind {
	case KindRegular:
		file, err := newFileSource(0, v.source, entry.Inode)
		if err != nil {
			state.Undecodable++
			state.Classify(err)
			state.Warn(fmt.Sprintf("file %s: %v", path, err))
			return nil, "", 0
		}
		allocated := file.AllocatedBytes()
		return &allocated, "", file.ExtentBlocksRead()
	case KindSymlink:
		file, err := newFileSource(0, v.source, entry.Inode)
		if err != nil {
			state.Undecodable++
			state.Classify(err)
			state.Warn(fmt.Sprintf("symlink %s: %v", path, err))
			return nil, "", 0
		}
		blocks := file.ExtentBlocksRead()
		allocatedValue := file.AllocatedBytes()
		allocated := &allocatedValue
		if entry.Inode.Size > MaxSymlinkBytes {
			state.Warn(fmt.Sprintf(
				"symlink %s: target is %d bytes, more than the %d-byte inline cap",
				path, entry.Inode.Size, MaxSymlinkBytes))
			return allocated, "", blocks
		}
		bytes := make([]byte, int(entry.Inode.Size))
		if _, err := file.readAt(0, bytes); err != nil {
			state.Undecodable++
			state.Classify(err)
			state.Warn(fmt.Sprintf("symlink %s: %v", path, err))
			return allocated, "", blocks
		}
		if !utf8.Valid(bytes) {
			state.Warn(fmt.Sprintf("symlink %s: target is not valid UTF-8; no target text is reported", path))
			return allocated, "", blocks
		}
		return allocated, string(bytes), blocks
	default:
		return nil, "", 0
	}
}

func (v *Volume) pushWarning(message string) {
	if len(v.warnings) < warningCap {
		v.warnings = append(v.warnings, message)
	} else {
		v.warningsDropped++
	}
}
