// Package gfs2 reads Red Hat's Global File System 2 (GFS2) images, read-only,
// from a source.ByteSource. It is a Go port of forensic-core's GFS2 reader.
//
// The layout is fixed:
//
//	superblock at byte 65536                       superblock.go
//	  -> root dinode and master dinode             inode.go
//	    -> directories: stuffed dirents or JD blocks dir.go
//	      -> file data through the pointer tree    extent.go, file.go
//
// Every inode is a dinode in one filesystem block; its block number is its
// inode number. Directories are journaled data: a stuffed directory keeps its
// dirents in the dinode, an unstuffed one stores them in JD blocks after a
// 24-byte metadata header. Only the linear directory format is decoded:
// EXHASH directories are refused by name.
//
// Every read returns real bytes or an explicit error. GFS2 defines no sparse
// hole this reader zero-fills: a zero pointer inside a file's declared length
// is refused rather than fabricated. A byte-swapped image, a GFS1 superblock,
// an unknown block size, journaled-data regular files or symbolic links,
// out-of-range pointers and deleted-name recovery are refused or skipped by
// name. Resource-group headers, allocation bitmaps and the journal are not
// decoded; the committed metadata is walked with a warning, and free space is
// not reported.
//
// Deliberately unported branches, each refused or reported rather than
// silently guessed at:
//
//   - journal replay: the volume is walked as it sits on disk;
//   - EXHASH directories: ErrUnsupported;
//   - journaled-data (GFS2_DIF_JDATA) regular files and symbolic links:
//     ErrUnsupported;
//   - GFS1 images and byte-swapped images: ErrUnsupported;
//   - extended attributes, resource-group headers and allocation bitmaps:
//     their fields are recorded but no content is decoded;
//   - deleted names: a dirent whose inode or formal number is zero is a free
//     slot and is skipped, so Entry.Deleted is always false.
package gfs2

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/source"
)

// KindLabel is the filesystem name facts and listings report.
const KindLabel = "GFS2"

// MaxNodes bounds a hostile walk.
const MaxNodes = 5_000_000

// MaxSymlinkBytes is the longest symbolic-link target read into an Entry.
const MaxSymlinkBytes uint64 = 64 * 1024

// RootRecord is the handle of the volume root.
const RootRecord uint64 = 0

// warningCap is the warnings kept per volume.
const warningCap = 32

// VolumeStats is what a walk of the whole tree found.
type VolumeStats struct {
	// NodesRead counts dinodes read, including the root and master.
	NodesRead uint64
	// BlocksRead counts dinode blocks and directory data blocks.
	BlocksRead uint64
	// ExtentBlocks counts indirect blocks read resolving pointer trees.
	ExtentBlocks uint64
	// ExtentRecords counts pointer slots examined, at every level.
	ExtentRecords uint64
	// Lookups counts directories walked.
	Lookups uint64
	// Refusals counts structures this reader does not decode.
	Refusals uint64
	// Malformed counts structurally invalid records encountered.
	Malformed uint64
}

// Info is a volume's report.
type Info struct {
	Type string
	UUID string

	BlockSize   uint32
	BlockShift  uint32
	Blocks      uint64
	VolumeBytes uint64

	FSFormat        uint32
	MultihostFormat uint32
	LockProto       string
	LockTable       string

	RootBlock    uint64
	RootFormal   uint64
	MasterBlock  uint64
	MasterFormal uint64

	Entries     int
	Directories int
	Files       int
	Symlinks    int

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
	Path string
	// Record is the node's ordinal in the walk, zero for the root.
	Record uint64
	// ParentRecord is nil for the root.
	ParentRecord *uint64
	// Inode is the dinode block number, which GFS2 uses as the inode number.
	Inode uint64

	IsDir     bool
	IsFile    bool
	IsSymlink bool
	// FileType is the kind's label: "file", "directory", "symlink", "fifo",
	// "socket", "block device", "character device" or "unknown".
	FileType string

	// Mode is the permission and type bits exactly as recorded.
	Mode uint32
	UID  uint32
	GID  uint32
	// Links is di_nlink.
	Links uint32
	// Size is the logical length in bytes.
	Size uint64
	// Allocated is nil for a directory or special file, and for a file whose
	// pointer tree did not validate.
	Allocated *uint64

	// AccessTime, ModifyTime and ChangeTime are Unix seconds; nil when the
	// stored pair is zero. GFS2 stores no creation time.
	AccessTime *int64
	ModifyTime *int64
	ChangeTime *int64

	// SymlinkTarget is the link text when the target was read inline.
	SymlinkTarget string

	// Deleted is always false: GFS2 removes a name's entry when it is
	// unlinked, and this reader skips free slots.
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
	links     uint32
	size      uint64
	allocated *uint64
	accessed  *int64
	modified  *int64
	changed   *int64
	symlink   string
	children  []uint64
}

// Volume is an opened GFS2 image.
type Volume struct {
	source     source.ByteSource
	superblock *Superblock
	inodes     []Dinode
	nodes      []node
	childIndex map[uint64]map[string]uint64
	dirErrors  map[uint64]error

	unreadable      uint64
	undecodable     uint64
	refusals        uint64
	malformed       uint64
	directoryLoops  uint64
	nodesRead       uint64
	blocksRead      uint64
	extentBlocks    uint64
	extentRecords   uint64
	lookups         uint64
	warnings        []string
	warningsDropped uint64

	fileID atomic.Uint64
}

// Detect reports whether src looks like a GFS2 image without mounting it.
func Detect(src source.ByteSource) (bool, error) {
	return detectSuperblock(src)
}

// Open reads the superblock and walks every directory.
func Open(src source.ByteSource) (*Volume, error) {
	superblock, err := ReadSuperblock(src)
	if err != nil {
		return nil, err
	}
	root, err := ReadInode(src, superblock, superblock.RootAddr)
	if err != nil {
		return nil, err
	}
	if !root.IsDirectory() {
		return nil, corruptf("the root inode at block %d is a %s, not a directory",
			superblock.RootAddr, root.Kind)
	}
	// The master directory is system metadata, not part of the user
	// namespace. It is read to prove that the superblock's second inum
	// resolves; it is not walked.
	master, err := ReadInode(src, superblock, superblock.MasterAddr)
	if err != nil {
		return nil, err
	}
	if !master.IsDirectory() {
		return nil, corruptf("the master inode at block %d is a %s, not a directory",
			superblock.MasterAddr, master.Kind)
	}

	volume := &Volume{
		source:     src,
		superblock: superblock,
		inodes:     []Dinode{*root},
		nodes: []node{{
			record:   RootRecord,
			name:     "/",
			path:     "/",
			inode:    root.Block,
			kind:     root.Kind,
			mode:     root.Mode,
			uid:      root.UID,
			gid:      root.GID,
			links:    root.Links,
			size:     root.Size,
			accessed: root.Accessed,
			modified: root.Modified,
			changed:  root.Changed,
		}},
		childIndex: make(map[uint64]map[string]uint64),
		dirErrors:  make(map[uint64]error),
		nodesRead:  2,
		blocksRead: 2,
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	volume.pushWarning("the volume is journaled; the journal is not replayed, so only committed metadata is walked")
	volume.pushWarning("resource-group headers and allocation bitmaps are not decoded; only live metadata is read")
	if err := volume.walk(); err != nil {
		return nil, err
	}
	return volume, nil
}

// KindLabel returns the filesystem's name.
func (v *Volume) KindLabel() string { return KindLabel }

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// BlockSize returns the filesystem block size.
func (v *Volume) BlockSize() uint32 { return v.superblock.BlockSize }

// RootRecord returns the root's walk ordinal.
func (v *Volume) RootRecord() uint64 { return RootRecord }

// Unreadable counts directories whose data could not be read or parsed.
func (v *Volume) Unreadable() uint64 { return v.unreadable }

// Undecodable counts names whose dinode, pointer tree or link target could
// not be read.
func (v *Volume) Undecodable() uint64 { return v.undecodable }

// Refusals counts structures this reader does not decode.
func (v *Volume) Refusals() uint64 { return v.refusals }

// Malformed counts structurally invalid records.
func (v *Volume) Malformed() uint64 { return v.malformed }

// DirectoryLoops counts directories reached by a second name: they are
// listed but not walked twice.
func (v *Volume) DirectoryLoops() uint64 { return v.directoryLoops }

// Stats returns the walk's counters.
func (v *Volume) Stats() VolumeStats {
	return VolumeStats{
		NodesRead:     v.nodesRead,
		BlocksRead:    v.blocksRead,
		ExtentBlocks:  v.extentBlocks,
		ExtentRecords: v.extentRecords,
		Lookups:       v.lookups,
		Refusals:      v.refusals,
		Malformed:     v.malformed,
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
	var directories, files, symlinks int
	for _, n := range v.nodes {
		switch {
		case n.kind.IsDirectory():
			directories++
		case n.kind.IsFile():
			files++
		case n.kind.IsSymlink():
			symlinks++
		}
	}
	info := Info{
		Type:            KindLabel,
		UUID:            v.superblock.UUIDHex(),
		BlockSize:       v.superblock.BlockSize,
		BlockShift:      v.superblock.BlockShift,
		Blocks:          v.superblock.TotalBlocks,
		VolumeBytes:     v.superblock.VolumeBytes,
		FSFormat:        v.superblock.FSFormat,
		MultihostFormat: v.superblock.MultihostFormat,
		LockProto:       v.superblock.LockProto,
		LockTable:       v.superblock.LockTable,
		RootBlock:       v.superblock.RootAddr,
		RootFormal:      v.superblock.RootFormal,
		MasterBlock:     v.superblock.MasterAddr,
		MasterFormal:    v.superblock.MasterFormal,
		Entries:         len(v.nodes),
		Directories:     directories,
		Files:           files,
		Symlinks:        symlinks,
		Stats:           v.Stats(),
		Unreadable:      v.unreadable,
		Undecodable:     v.undecodable,
		DirectoryLoops:  v.directoryLoops,
		Warnings:        append([]string(nil), v.warnings...),
		WarningsDropped: v.warningsDropped,
	}
	return info
}

// ListDir lists a directory's entries, excluding "." and "..". A directory
// whose data could not be read returns that recorded error rather than an
// empty listing.
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
	if inode.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	if !inode.IsFile() {
		return nil, fmt.Errorf("%w: %s", ErrNotFile, path)
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.source, v.superblock, inode)
}

// OpenSymlink opens a symbolic link's target as a byte source. A stuffed
// link's target is the bytes in its dinode; a block-mapped link's target is
// its pointer-tree stream.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	record, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	inode := &v.inodes[record]
	if !inode.IsSymlink() {
		return nil, fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.source, v.superblock, inode)
}

// SymlinkTarget returns the link text recorded in the walk.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	record, err := v.lookup(path)
	if err != nil {
		return "", err
	}
	n := &v.nodes[record]
	if !n.kind.IsSymlink() {
		return "", fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	if n.symlink == "" {
		return "", fmt.Errorf("%w: %s", ErrNoSymlinkTarget, path)
	}
	return n.symlink, nil
}

func (v *Volume) entry(record uint64) Entry {
	n := &v.nodes[record]
	entry := Entry{
		Name:          n.name,
		Path:          n.path,
		Record:        n.record,
		ParentRecord:  n.parent,
		Inode:         n.inode,
		IsDir:         n.kind.IsDirectory(),
		IsFile:        n.kind.IsFile(),
		IsSymlink:     n.kind.IsSymlink(),
		FileType:      n.kind.String(),
		Mode:          n.mode,
		UID:           n.uid,
		GID:           n.gid,
		Links:         n.links,
		Size:          n.size,
		Allocated:     n.allocated,
		AccessTime:    n.accessed,
		ModifyTime:    n.modified,
		ChangeTime:    n.changed,
		SymlinkTarget: n.symlink,
	}
	return entry
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
	visited := map[uint64]bool{v.nodes[0].inode: true}
	queue := []uint64{RootRecord}

	for len(queue) > 0 {
		record := queue[0]
		queue = queue[1:]
		v.lookups++

		listing, err := readDirectory(v.superblock, v.source, &v.inodes[record])
		if err != nil {
			v.unreadable++
			v.classify(err)
			v.dirErrors[record] = err
			v.pushWarning(fmt.Sprintf("directory %s: %v", v.nodes[record].path, err))
			continue
		}
		v.blocksRead += listing.Blocks + listing.ExtentBlocks
		v.extentBlocks += listing.ExtentBlocks
		v.extentRecords += listing.ExtentRecords
		parentPath := v.nodes[record].path

		for _, dirEntry := range listing.Entries {
			if dirEntry.Name == "." || dirEntry.Name == ".." {
				continue
			}
			if dirEntry.Inode == 0 || dirEntry.Inode >= v.superblock.TotalBlocks {
				v.malformed++
				v.pushWarning(fmt.Sprintf(
					"directory %s: name %q names block %d, outside the volume",
					parentPath, dirEntry.Name, dirEntry.Inode))
				continue
			}
			inode, err := v.readInode(dirEntry.Inode)
			if err != nil {
				v.undecodable++
				v.classify(err)
				v.pushWarning(fmt.Sprintf("directory %s: name %q: %v",
					parentPath, dirEntry.Name, err))
				continue
			}
			if len(v.nodes) >= MaxNodes {
				return corruptf("the image names more than %d entries", MaxNodes)
			}
			path := "/" + dirEntry.Name
			if parentPath != "/" {
				path = parentPath + "/" + dirEntry.Name
			}
			var allocated *uint64
			var symlinkTarget string
			undecodable := false

			switch {
			case inode.IsFile():
				file, err := newFileSource(v.source.SourceID(), v.source, v.superblock, inode)
				if err != nil {
					undecodable = true
					v.classify(err)
					v.pushWarning(fmt.Sprintf("file %s: %v", path, err))
					break
				}
				value := file.AllocatedBytes()
				allocated = &value
				v.extentBlocks += file.ExtentBlocksRead()
				v.extentRecords += file.ExtentRecords()
				v.blocksRead += file.ExtentBlocksRead()
			case inode.IsSymlink() && inode.Stuffed == nil:
				file, err := newFileSource(v.source.SourceID(), v.source, v.superblock, inode)
				if err != nil {
					undecodable = true
					v.classify(err)
					v.pushWarning(fmt.Sprintf("symlink %s: %v", path, err))
					break
				}
				value := file.AllocatedBytes()
				allocated = &value
				v.extentBlocks += file.ExtentBlocksRead()
				v.extentRecords += file.ExtentRecords()
				v.blocksRead += file.ExtentBlocksRead()
				if inode.Size <= MaxSymlinkBytes {
					bytes := make([]byte, int(inode.Size))
					if _, err := file.readAt(0, bytes); err != nil {
						undecodable = true
						v.classify(err)
						v.pushWarning(fmt.Sprintf("symlink %s: %v", path, err))
					} else {
						symlinkTarget = string(bytes)
					}
				} else {
					v.pushWarning(fmt.Sprintf(
						"symlink %s: target is %d bytes, more than the %d-byte inline cap; open the link stream instead",
						path, inode.Size, MaxSymlinkBytes))
				}
			case inode.IsSymlink():
				zero := uint64(0)
				allocated = &zero
				symlinkTarget = inode.StuffedText()
			}
			if undecodable {
				v.undecodable++
			}

			child := uint64(len(v.nodes))
			parentRecord := record
			parentCopy := parentRecord
			v.nodes = append(v.nodes, node{
				record:    child,
				parent:    &parentCopy,
				name:      dirEntry.Name,
				path:      path,
				inode:     inode.Block,
				kind:      inode.Kind,
				mode:      inode.Mode,
				uid:       inode.UID,
				gid:       inode.GID,
				links:     inode.Links,
				size:      inode.Size,
				allocated: allocated,
				accessed:  inode.Accessed,
				modified:  inode.Modified,
				changed:   inode.Changed,
				symlink:   symlinkTarget,
			})
			v.inodes = append(v.inodes, *inode)
			v.nodes[record].children = append(v.nodes[record].children, child)
			if v.childIndex[record] == nil {
				v.childIndex[record] = make(map[string]uint64)
			}
			if _, exists := v.childIndex[record][dirEntry.Name]; !exists {
				v.childIndex[record][dirEntry.Name] = child
			}
			if inode.IsDirectory() {
				if !visited[inode.Block] {
					visited[inode.Block] = true
					queue = append(queue, child)
				} else {
					v.directoryLoops++
				}
			}
		}
	}
	return nil
}

func (v *Volume) readInode(block uint64) (*Dinode, error) {
	inode, err := ReadInode(v.source, v.superblock, block)
	if err != nil {
		return nil, err
	}
	v.nodesRead++
	v.blocksRead++
	return inode, nil
}

func (v *Volume) classify(err error) {
	switch {
	case err == nil:
		return
	case isUnsupported(err):
		v.refusals++
	case isCorrupt(err):
		v.malformed++
	}
}

func (v *Volume) pushWarning(message string) {
	if len(v.warnings) < warningCap {
		v.warnings = append(v.warnings, message)
	} else {
		v.warningsDropped++
	}
}
