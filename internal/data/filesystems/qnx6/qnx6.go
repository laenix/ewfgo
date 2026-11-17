// Package qnx6 reads QNX6 (the QNX Neutrino "Power-Safe" filesystem) images,
// read-only, from a source.ByteSource. It is a Go port of the Rust
// forensic-core QNX6 reader.
//
// The layout:
//
//	A normal image begins with an 8 KiB bootblock, then a 4 KiB superblock
//	area, so the primary superblock is at byte 8192 and filesystem block zero
//	starts at byte 12288. The superblock is repeated after the data area. The
//	Audi MMI 3G variant puts its primary copy at byte zero, uses a slightly
//	different field layout, and starts its data area after a single 4 KiB
//	superblock area. All three positions are inspected; the valid copy with
//	the highest 64-bit sb_serial is active. The magic proves the byte order,
//	and both little-endian and big-endian volumes are read.
//
// Inodes are 128-byte records numbered from one. The superblock's Inode root
// node describes the inode-table stream. A file's blocks come from the inode's
// 16 pointers and di_filelevels-deep pointer tree: depth zero uses the
// pointers directly, deeper trees read pointer blocks down to the data.
// ^uint32(0) means unused; zero is a valid block. A directory is a stream of
// 32-byte slots with optional long-name records in the Longfile stream. A
// symbolic link's target is an ordinary block-mapped data stream.
//
// Times: di_ftime is the creation time; di_mtime, di_atime and di_ctime are
// modification, access and status-change times. All are 32-bit Unix seconds,
// and a stored zero is "unset" and becomes no catalog field. No time zone is
// recorded.
//
// What a walk proves: a handle is the node's ordinal in the walk, 0 being the
// root. The 1-based inode number is reported separately and joins the node to
// other artifacts. A directory reached by a second name is listed but not
// walked twice; a hard-linked file is listed under each name that reaches it.
//
// What is not read:
//
//   - the allocation bitmap is not decoded, so no free-space map is offered;
//   - deleted inodes (di_status 2), deleted directory slots, reclaimed data
//     and shadowed superblock copies are not decoded;
//   - holes (unused pointers), out-of-range pointers, bad long-name
//     checksums, unknown block sizes and pointer depths beyond five are
//     refused by name. Nothing is zero-filled.
//
// Every read returns real bytes or an explicit error.
package qnx6

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/source"
)

// RootRecord is the handle of the volume root: node zero.
const RootRecord uint64 = 0

// RootInode is the 1-based inode number of the root directory.
const RootInode uint64 = 1

// KindLabel is the filesystem name facts and listings report.
const KindLabel = "QNX6"

// Limits that bound a hostile image.
const (
	// MaxNodes is the most nodes a walk retains.
	MaxNodes = 5_000_000
	// MaxSymlinkBytes is the longest symbolic-link target read into an entry.
	MaxSymlinkBytes uint64 = 64 * 1024
	// WarningCap is the warnings retained per volume.
	WarningCap = 32
)

// maxDirectoryDepth bounds how far below the root the walk follows
// directories.
const maxDirectoryDepth = 512

// maxPathBytes bounds one displayed path.
const maxPathBytes = 4096

// maxTotalPathBytes bounds the sum of every path string the walk retains.
const maxTotalPathBytes = 256 << 20

// Entry is one name the walk found.
type Entry struct {
	Name string
	// Path is the display path, '/'-separated. The root's path is "/".
	Path   string
	Record uint64
	// ParentRecord is nil for the root.
	ParentRecord *uint64
	// Inode is the 1-based QNX6 inode number.
	Inode uint64

	Kind     InodeKind
	FileType string

	IsDir         bool
	IsFile        bool
	IsSymlink     bool
	IsFifo        bool
	IsSocket      bool
	IsBlockDevice bool
	IsCharDevice  bool
	IsUnknown     bool

	// Mode is the permission and type bits exactly as recorded.
	Mode uint16
	UID  uint32
	GID  uint32
	// Size is the logical length in bytes.
	Size uint64
	// Allocated is nil for a directory or special file, and for a file whose
	// pointer tree did not validate.
	Allocated *uint64

	// Times are Unix seconds; nil when the stored field is zero.
	Created  *int64
	Modified *int64
	Accessed *int64
	Changed  *int64

	// SymlinkTarget is the link text when it was read inline.
	SymlinkTarget string
	// HasSymlinkTarget distinguishes a read target from one that was not
	// read (too long or unreadable).
	HasSymlinkTarget bool

	// Deleted is always false: a deleted inode is refused during the walk,
	// not reported.
	Deleted bool
}

type node struct {
	record uint64
	parent *uint64

	name string
	path string

	inodeNumber uint64
	kind        InodeKind
	mode        uint16
	uid         uint32
	gid         uint32
	size        uint64

	allocated *uint64
	created   *int64
	modified  *int64
	accessed  *int64
	changed   *int64

	symlinkTarget    string
	hasSymlinkTarget bool

	children []uint64
}

// Stats counts one walk.
type Stats struct {
	// NodesRead is inodes read, including the root.
	NodesRead uint64
	// BlocksRead counts inode-table, directory and pointer data blocks read.
	BlocksRead uint64
	// ExtentBlocks counts pointer blocks read while resolving streams.
	ExtentBlocks uint64
	// ExtentRecords counts pointer slots examined, at every level.
	ExtentRecords uint64
	// Lookups counts directories walked.
	Lookups uint64
	// Refusals counts structures refused because this reader does not decode
	// them.
	Refusals uint64
	// Malformed counts structurally invalid records encountered.
	Malformed uint64
}

// Info is a volume's report.
type Info struct {
	Type      string
	ByteOrder string
	Layout    string

	Serial   uint64
	Version1 uint16
	Version2 uint16
	Flags    uint32

	BlockSize   uint32
	BlockShift  uint32
	Blocks      uint32
	VolumeBytes uint64
	Inodes      uint32
	FreeInodes  uint32
	FreeBlocks  uint32
	AllocGroup  uint32

	BootblockBytes   uint64
	FSBlockOffset    uint64
	SuperblockOffset uint64
	SuperblockCopies int
	RootInode        uint64

	VolumeID           string
	SuperblockCreated  uint32
	SuperblockAccessed uint32

	Entries     int
	Directories int
	Files       int
	Symlinks    int

	ExtentBlocks  uint64
	ExtentRecords uint64
	ExtentLookups uint64
	NodesRead     uint64
	BlocksRead    uint64
	Refusals      uint64
	Malformed     uint64

	Unreadable     uint64
	Undecodable    uint64
	DirectoryLoops uint64

	Warnings        []string
	WarningsDropped uint64
}

// Volume is an opened QNX6 image.
type Volume struct {
	source     source.ByteSource
	superblock *Superblock
	inodes     []*Inode
	nodes      []*node

	childIndex map[uint64]map[string]uint64
	dirErrors  map[uint64]error

	unreadable     uint64
	undecodable    uint64
	refusals       uint64
	malformed      uint64
	directoryLoops uint64

	nodesRead     uint64
	blocksRead    uint64
	extentBlocks  uint64
	extentRecords uint64
	lookups       uint64

	warnings        []string
	warningsDropped uint64

	fileID atomic.Uint64
}

// Detect reports whether src looks like a QNX6 image without mounting it. A
// magic without a matching checksum is an error by name rather than a
// positive identification.
func Detect(src source.ByteSource) (bool, error) {
	return detectSuperblock(src)
}

// Open reads the superblock and walks every directory.
func Open(src source.ByteSource) (*Volume, error) {
	superblock, err := ReadSuperblock(src)
	if err != nil {
		return nil, err
	}
	root, err := ReadInode(src, superblock, RootInode)
	if err != nil {
		return nil, err
	}
	if !root.Kind.IsDirectory() {
		return nil, corruptf("the root inode %d is a %s, not a directory", RootInode, root.Kind.Label())
	}

	volume := &Volume{
		source:     src,
		superblock: superblock,
		inodes:     []*Inode{root},
		nodes: []*node{
			{
				record:      RootRecord,
				name:        "/",
				path:        "/",
				inodeNumber: root.Number,
				kind:        root.Kind,
				mode:        root.Mode,
				uid:         root.UID,
				gid:         root.GID,
				size:        root.Size,
				created:     root.Created,
				modified:    root.Modified,
				accessed:    root.Accessed,
				changed:     root.Changed,
			},
		},
		childIndex: make(map[uint64]map[string]uint64),
		dirErrors:  make(map[uint64]error),
		nodesRead:  1,
		blocksRead: 1,
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	volume.pushWarning("the allocation bitmap is not decoded, so free-block accounting is offered as the superblock's recorded count only")
	volume.pushWarning("deleted inodes and reclaimed directory slots are not decoded; only live metadata is walked")

	validCopies := 0
	for _, copyInfo := range superblock.Copies {
		if copyInfo.Valid {
			validCopies++
		}
	}
	if validCopies < 2 {
		volume.pushWarning(fmt.Sprintf(
			"only %d of the inspected superblock copies validated; the active copy at byte %d was used",
			validCopies, superblock.CopyOffset))
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

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// BlockSize returns the filesystem block size in bytes.
func (v *Volume) BlockSize() uint32 { return v.superblock.BlockSize }

// RootRecord returns the root's walk ordinal.
func (v *Volume) RootRecord() uint64 { return RootRecord }

// NodeCount returns the number of nodes the walk found.
func (v *Volume) NodeCount() int { return len(v.nodes) }

// Unreadable counts directories whose data could not be read or parsed.
func (v *Volume) Unreadable() uint64 { return v.unreadable }

// Undecodable counts names whose inode, pointer tree or link target could not
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
func (v *Volume) Stats() Stats {
	return Stats{
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
func (v *Volume) Warnings() []string { return append([]string(nil), v.warnings...) }

// WarningsDropped returns how many warnings were discarded past the cap.
func (v *Volume) WarningsDropped() uint64 { return v.warningsDropped }

// Entries returns every node the walk found, the root first.
func (v *Volume) Entries() []Entry {
	out := make([]Entry, 0, len(v.nodes))
	for record := range v.nodes {
		out = append(out, v.entryFor(uint64(record)))
	}
	return out
}

// Nodes is an alias for Entries, matching sibling readers.
func (v *Volume) Nodes() []Entry { return v.Entries() }

// Info returns the volume's report.
func (v *Volume) Info() Info {
	var directories, files, symlinks int
	for _, value := range v.nodes {
		switch {
		case value.kind.IsDirectory():
			directories++
		case value.kind.IsFile():
			files++
		case value.kind.IsSymlink():
			symlinks++
		}
	}
	validCopies := 0
	for _, copyInfo := range v.superblock.Copies {
		if copyInfo.Valid {
			validCopies++
		}
	}
	return Info{
		Type:               KindLabel,
		ByteOrder:          v.superblock.Order.Label(),
		Layout:             v.superblock.Layout.Label(),
		Serial:             v.superblock.Serial,
		Version1:           v.superblock.Version1,
		Version2:           v.superblock.Version2,
		Flags:              v.superblock.Flags,
		BlockSize:          v.superblock.BlockSize,
		BlockShift:         v.superblock.BlockShift(),
		Blocks:             v.superblock.NumBlocks,
		VolumeBytes:        v.superblock.VolumeBytes(),
		Inodes:             v.superblock.NumInodes,
		FreeInodes:         v.superblock.FreeInodes,
		FreeBlocks:         v.superblock.FreeBlocks,
		AllocGroup:         v.superblock.AllocGroup,
		BootblockBytes:     v.superblock.BootblockBytes,
		FSBlockOffset:      v.superblock.BlksOff,
		SuperblockOffset:   v.superblock.CopyOffset,
		SuperblockCopies:   validCopies,
		RootInode:          RootInode,
		VolumeID:           v.superblock.VolumeID(),
		SuperblockCreated:  v.superblock.Ctime,
		SuperblockAccessed: v.superblock.Atime,
		Entries:            len(v.nodes),
		Directories:        directories,
		Files:              files,
		Symlinks:           symlinks,
		ExtentBlocks:       v.extentBlocks,
		ExtentRecords:      v.extentRecords,
		ExtentLookups:      v.lookups,
		NodesRead:          v.nodesRead,
		BlocksRead:         v.blocksRead,
		Refusals:           v.refusals,
		Malformed:          v.malformed,
		Unreadable:         v.unreadable,
		Undecodable:        v.undecodable,
		DirectoryLoops:     v.directoryLoops,
		Warnings:           append([]string(nil), v.warnings...),
		WarningsDropped:    v.warningsDropped,
	}
}

// Facts returns the volume-level facts as ordered key/value pairs, mirroring
// the reference reader's catalog facts.
func (v *Volume) Facts() [][2]string {
	superblock := v.superblock
	directories := 0
	files := 0
	symlinks := 0
	for _, value := range v.nodes {
		switch {
		case value.kind.IsDirectory():
			directories++
		case value.kind.IsFile():
			files++
		case value.kind.IsSymlink():
			symlinks++
		}
	}
	validCopies := 0
	for _, copyInfo := range superblock.Copies {
		if copyInfo.Valid {
			validCopies++
		}
	}
	facts := [][2]string{
		{"type", KindLabel},
		{"byte_order", superblock.Order.Label()},
		{"layout", superblock.Layout.Label()},
		{"serial", formatUint(superblock.Serial)},
		{"version1", formatUint(uint64(superblock.Version1))},
		{"version2", formatUint(uint64(superblock.Version2))},
		{"flags", formatUint(uint64(superblock.Flags))},
		{"block_size", formatUint(uint64(superblock.BlockSize))},
		{"block_shift", formatUint(uint64(superblock.BlockShift()))},
		{"blocks", formatUint(uint64(superblock.NumBlocks))},
		{"volume_bytes", formatUint(superblock.VolumeBytes())},
		{"inodes", formatUint(uint64(superblock.NumInodes))},
		{"free_inodes", formatUint(uint64(superblock.FreeInodes))},
		{"free_blocks", formatUint(uint64(superblock.FreeBlocks))},
		{"allocgroup", formatUint(uint64(superblock.AllocGroup))},
		{"bootblock_bytes", formatUint(superblock.BootblockBytes)},
		{"fs_block_offset", formatUint(superblock.BlksOff)},
		{"superblock_offset", formatUint(superblock.CopyOffset)},
		{"superblock_copies", formatUint(uint64(validCopies))},
		{"root_inode", formatUint(RootInode)},
		{"entries", formatUint(uint64(len(v.nodes)))},
		{"directories", formatUint(uint64(directories))},
		{"files", formatUint(uint64(files))},
		{"symlinks", formatUint(uint64(symlinks))},
		{"extent_blocks", formatUint(v.extentBlocks)},
		{"extent_records", formatUint(v.extentRecords)},
		{"extent_lookups", formatUint(v.lookups)},
		{"nodes_read", formatUint(v.nodesRead)},
		{"blocks_read", formatUint(v.blocksRead)},
		{"refusals", formatUint(v.refusals)},
		{"malformed", formatUint(v.malformed)},
		{"warnings", formatUint(uint64(len(v.warnings)) + v.warningsDropped)},
	}
	if volumeID := superblock.VolumeID(); volumeID != "" {
		facts = append(facts, [2]string{"volume_id", volumeID})
	}
	if superblock.Ctime != 0 {
		facts = append(facts, [2]string{"superblock_created", formatUint(uint64(superblock.Ctime))})
	}
	if superblock.Atime != 0 {
		facts = append(facts, [2]string{"superblock_accessed", formatUint(uint64(superblock.Atime))})
	}
	if v.warningsDropped > 0 {
		facts = append(facts, [2]string{"warnings_dropped", formatUint(v.warningsDropped)})
	}
	if v.unreadable > 0 {
		facts = append(facts, [2]string{"unreadable", formatUint(v.unreadable)})
	}
	if v.undecodable > 0 {
		facts = append(facts, [2]string{"undecodable", formatUint(v.undecodable)})
	}
	if v.directoryLoops > 0 {
		facts = append(facts, [2]string{"directory_loops", formatUint(v.directoryLoops)})
	}
	return facts
}

// ListDir lists a directory's children, excluding "." and "..". A directory
// whose data could not be read returns that recorded error rather than an
// empty listing.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	record, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	if !v.nodes[record].kind.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	if err := v.dirErrors[record]; err != nil {
		return nil, err
	}
	children := v.nodes[record].children
	out := make([]Entry, 0, len(children))
	for _, child := range children {
		out = append(out, v.entryFor(child))
	}
	return out, nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	record, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	entry := v.entryFor(record)
	return &entry, nil
}

// OpenFile opens a regular file's data stream. Directories and special files
// have no file data; a symbolic link's target can be opened with OpenSymlink.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	record, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	inode := v.inodes[record]
	if inode.Kind.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	if !inode.Kind.IsFile() {
		return nil, fmt.Errorf("%w: %s", ErrNotFile, path)
	}
	return newFileSource(source.ID(v.fileID.Add(1)), v.source, v.superblock, inode)
}

// OpenSymlink opens a symbolic link's target as a stream. The target is an
// ordinary block-mapped data stream for QNX6.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	record, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	inode := v.inodes[record]
	if !inode.Kind.IsSymlink() {
		return nil, fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	return newFileSource(source.ID(v.fileID.Add(1)), v.source, v.superblock, inode)
}

// SymlinkTarget returns the link text recorded in the walk.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	record, err := v.resolve(path)
	if err != nil {
		return "", err
	}
	value := v.nodes[record]
	if !value.kind.IsSymlink() {
		return "", fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	if !value.hasSymlinkTarget {
		return "", fmt.Errorf("%w: %s", ErrNoSymlinkTarget, path)
	}
	return value.symlinkTarget, nil
}

func (v *Volume) resolve(path string) (uint64, error) {
	record := RootRecord
	if path == "" || path == "/" {
		return record, nil
	}
	for _, component := range strings.Split(path, "/") {
		switch component {
		case "", ".":
			continue
		case "..":
			if parent := v.nodes[record].parent; parent != nil {
				record = *parent
			}
			continue
		}
		if !v.nodes[record].kind.IsDirectory() {
			return 0, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		next, ok := v.childIndex[record][component]
		if !ok {
			return 0, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		record = next
	}
	return record, nil
}

func (v *Volume) entryFor(record uint64) Entry {
	value := v.nodes[record]
	entry := Entry{
		Name:             value.name,
		Path:             value.path,
		Record:           value.record,
		Inode:            value.inodeNumber,
		Kind:             value.kind,
		FileType:         value.kind.Label(),
		IsDir:            value.kind.IsDirectory(),
		IsFile:           value.kind.IsFile(),
		IsSymlink:        value.kind.IsSymlink(),
		IsFifo:           value.kind == KindFifo,
		IsSocket:         value.kind == KindSocket,
		IsBlockDevice:    value.kind == KindBlockDevice,
		IsCharDevice:     value.kind == KindCharDevice,
		IsUnknown:        value.kind == KindUnknown,
		Mode:             value.mode,
		UID:              value.uid,
		GID:              value.gid,
		Size:             value.size,
		Allocated:        copyUint64(value.allocated),
		Created:          copyInt64(value.created),
		Modified:         copyInt64(value.modified),
		Accessed:         copyInt64(value.accessed),
		Changed:          copyInt64(value.changed),
		SymlinkTarget:    value.symlinkTarget,
		HasSymlinkTarget: value.hasSymlinkTarget,
	}
	if value.parent != nil {
		parent := *value.parent
		entry.ParentRecord = &parent
	}
	return entry
}

func copyUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func copyInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (v *Volume) directoryListing(record uint64) (*Directory, error) {
	inode := v.inodes[record]
	if !inode.Kind.IsDirectory() {
		return nil, corruptf("node %s is a %s, not a directory",
			v.nodes[record].path, inode.Kind.Label())
	}
	return readDirectory(v.superblock, v.source, inode)
}

func (v *Volume) readInode(number uint64) (*Inode, error) {
	inode, err := ReadInode(v.source, v.superblock, number)
	if err != nil {
		return nil, err
	}
	v.nodesRead++
	v.blocksRead++
	return inode, nil
}

type walkItem struct {
	record uint64
	depth  int
}

func (v *Volume) walk() error {
	visited := map[uint64]bool{v.nodes[0].inodeNumber: true}
	queue := []walkItem{{record: RootRecord, depth: 0}}
	pathBytes := uint64(len(v.nodes[0].path))

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		v.lookups++

		listing, err := v.directoryListing(item.record)
		if err != nil {
			v.unreadable++
			v.classify(err)
			v.dirErrors[item.record] = err
			v.pushWarning(fmt.Sprintf("directory %s: %v", v.nodes[item.record].path, err))
			continue
		}
		v.blocksRead += listing.Blocks + listing.ExtentBlocks
		v.extentBlocks += listing.ExtentBlocks
		v.extentRecords += listing.ExtentRecords
		parentPath := v.nodes[item.record].path

		for _, entry := range listing.Entries {
			if entry.Name == "." || entry.Name == ".." {
				continue
			}
			if entry.Inode == 0 || entry.Inode > uint64(v.superblock.NumInodes) {
				v.malformed++
				v.pushWarning(fmt.Sprintf(
					"directory %s: name %q names inode %d, outside the volume's 1..=%d",
					parentPath, entry.Name, entry.Inode, v.superblock.NumInodes))
				continue
			}
			inode, err := v.readInode(entry.Inode)
			if err != nil {
				v.undecodable++
				v.classify(err)
				v.pushWarning(fmt.Sprintf("directory %s: name %q: %v", parentPath, entry.Name, err))
				continue
			}
			if len(v.nodes) >= MaxNodes {
				return corruptf("the image names more than %d entries", MaxNodes)
			}
			path := "/" + entry.Name
			if parentPath != "/" {
				path = parentPath + "/" + entry.Name
			}
			if len(path) > maxPathBytes {
				v.malformed++
				v.pushWarning(fmt.Sprintf(
					"%s: the path is %d bytes, longer than the %d-byte limit; the entry is not walked",
					path, len(path), maxPathBytes))
				continue
			}
			if pathBytes+uint64(len(path)) > maxTotalPathBytes {
				return corruptf("the image's directory paths exceed %d bytes; refusing to retain more",
					maxTotalPathBytes)
			}
			pathBytes += uint64(len(path))

			var (
				undecodable      bool
				allocated        *uint64
				symlinkTarget    string
				hasSymlinkTarget bool
			)
			switch inode.Kind {
			case KindFile:
				file, err := newFileSource(0, v.source, v.superblock, inode)
				if err != nil {
					undecodable = true
					v.classify(err)
					v.pushWarning(fmt.Sprintf("file %s: %v", path, err))
				} else {
					value := file.AllocatedBytes()
					allocated = &value
					v.extentBlocks += file.ExtentBlocksRead()
					v.extentRecords += file.ExtentRecords()
					v.blocksRead += file.ExtentBlocksRead()
				}
			case KindSymlink:
				file, err := newFileSource(0, v.source, v.superblock, inode)
				if err != nil {
					undecodable = true
					v.classify(err)
					v.pushWarning(fmt.Sprintf("symlink %s: %v", path, err))
				} else {
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
							symlinkTarget = lossyUTF8(bytes)
							hasSymlinkTarget = true
						}
					} else {
						v.pushWarning(fmt.Sprintf(
							"symlink %s: target is %d bytes, more than the %d-byte inline cap; open the link stream instead",
							path, inode.Size, MaxSymlinkBytes))
					}
				}
			}
			if undecodable {
				v.undecodable++
			}

			child := uint64(len(v.nodes))
			parent := item.record
			isDirectory := inode.Kind.IsDirectory()
			v.nodes = append(v.nodes, &node{
				record:           child,
				parent:           &parent,
				name:             entry.Name,
				path:             path,
				inodeNumber:      inode.Number,
				kind:             inode.Kind,
				mode:             inode.Mode,
				uid:              inode.UID,
				gid:              inode.GID,
				size:             inode.Size,
				allocated:        allocated,
				created:          inode.Created,
				modified:         inode.Modified,
				accessed:         inode.Accessed,
				changed:          inode.Changed,
				symlinkTarget:    symlinkTarget,
				hasSymlinkTarget: hasSymlinkTarget,
			})
			v.inodes = append(v.inodes, inode)
			v.nodes[item.record].children = append(v.nodes[item.record].children, child)
			if v.childIndex[item.record] == nil {
				v.childIndex[item.record] = make(map[string]uint64)
			}
			if _, exists := v.childIndex[item.record][entry.Name]; !exists {
				v.childIndex[item.record][entry.Name] = child
			}
			if isDirectory {
				if !visited[inode.Number] {
					visited[inode.Number] = true
					if item.depth >= maxDirectoryDepth {
						v.malformed++
						v.pushWarning(fmt.Sprintf(
							"directory %s: not walked; it is deeper than the %d-level directory limit",
							path, maxDirectoryDepth))
					} else {
						queue = append(queue, walkItem{record: child, depth: item.depth + 1})
					}
				} else {
					v.directoryLoops++
				}
			}
		}
	}
	return nil
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
	if len(v.warnings) < WarningCap {
		v.warnings = append(v.warnings, message)
		return
	}
	v.warningsDropped++
}
