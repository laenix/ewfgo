// Package hfs reads classic HFS volumes (the Mac OS filesystem HFS+ replaced)
// from a source.ByteSource.
//
// It is a port of the Rust forensic-core classic-HFS reader. The volume opens
// with a Master Directory Block at byte 1024. Its catalog file and extents
// overflow file are B-trees stored in ordinary forks: the catalog holds folder
// records, file records and the thread records that link a catalog node back
// to its parent and name; a file's first three extents live in its catalog
// record and further extents live in the overflow tree, keyed by file ID, fork
// and the logical block where the continuation starts.
//
// Names are Mac OS Roman bytes mapped through the standard table. Times are
// seconds since 1904-01-01 in the machine's local wall clock; this reader
// treats the wall clock as UTC and reports that basis in Info.TimeBasis rather
// than inventing an offset. Folder records carry no timestamps, and the format
// has neither an access time nor a metadata-change time.
//
// Every read returns real bytes or an explicit error. Classic HFS defines no
// sparse fork encoding, so a logical byte that no extent covers is reported as
// corrupt rather than zero-filled.
//
// Deliberately unported branches, each refused, reported or documented rather
// than guessed at:
//
//   - the allocation bitmap is not decoded; Info reports drFreeBks as recorded;
//   - no deleted names are recovered: classic HFS keeps no unlinked directory
//     entries, so a removed name is gone from the catalog;
//   - a byte-swapped (little-endian) MDB is refused by name;
//   - classic HFS stores no POSIX mode, UID, GID, symbolic links, access time
//     or metadata-change time, so those Entry fields stay zero/false and
//     Entry.SymlinkTarget is always empty;
//   - the extents overflow file's own first three extents come from the MDB
//     and no more are followed; a tree that needs more is warned about, not
//     guessed;
//   - both the data and resource forks are readable, but Finder aliases are
//     not followed.
package hfs

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Catalog node IDs and fork types fixed by the format.
const (
	RootDirectoryID uint32 = 2
	RootParentID    uint32 = 1
	ExtentsFileID   uint32 = 3
	CatalogFileID   uint32 = 4
	ForkData        uint8  = 0x00
	ForkResource    uint8  = 0xFF
)

// KindLabel is the filesystem name facts and listings report.
const KindLabel = "HFS"

// MaxOverflowLookups bounds an overflow chain so a corrupt key cannot loop.
const MaxOverflowLookups = 1024

// WarningCap is the number of warnings kept before the rest are suppressed.
const WarningCap = 32

// timeBasisLocalWallClock names the convention the reader applies to the
// stored timestamps.
const timeBasisLocalWallClock = "local_wall_clock_read_as_utc"

// hfsEpochUnix is 1904-01-01 in Unix seconds.
const hfsEpochUnix int64 = 2_082_844_800

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not describe a healthy classic
	// HFS volume.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the volume uses a documented feature this reader
	// deliberately does not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrNotFound means a path component did not resolve.
	ErrNotFound = errors.New("hfs: path not found")
	// ErrNotDir means a path named something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("hfs: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("hfs: is a directory")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

// Entry is one file or directory in a volume.
type Entry struct {
	Name string
	// Path is the display path, '/'-separated.
	Path string

	Inode       uint32
	ParentInode uint32

	IsDir     bool
	IsFile    bool
	IsSymlink bool

	// Size is the data fork's logical length; a directory's is zero.
	Size uint64
	// Allocated is the data fork's physical length. HasAllocated is false for
	// directories.
	Allocated    uint64
	HasAllocated bool

	// ResourceSize and ResourceAllocated describe the resource fork.
	ResourceSize      uint64
	ResourceAllocated uint64

	// Mode, UID and GID are always zero: classic HFS records none of them.
	Mode uint32
	UID  uint32
	GID  uint32

	// The three stored times. HasX is true when the field is non-zero.
	Created     time.Time
	Modified    time.Time
	Backup      time.Time
	HasCreated  bool
	HasModified bool
	HasBackup   bool

	// FinderType and FinderCreator are the four-byte Finder type and creator
	// codes as stored.
	FinderType    uint32
	FinderCreator uint32

	// SymlinkTarget is always empty: classic HFS has no symbolic links.
	SymlinkTarget string
	// Deleted is always false: classic HFS keeps no unlinked directory entries.
	Deleted bool
}

// VolumeStats counts what opening found.
type VolumeStats struct {
	CatalogNodeSize    uint16
	CatalogTotalNodes  uint32
	CatalogLeafRecords uint64
	Folders            uint64
	Files              uint64
	Threads            uint64
	OtherRecords       uint64
	MalformedRecords   uint64
	// Extents overflow lookups performed while flattening forks.
	ExtentsLookups uint64
	ExtentsFound   uint64
	ExtentsMissing uint64
	WarningsCapped bool
}

// Info is a volume's report.
type Info struct {
	Name      string
	Signature uint16

	AllocationBlockSize uint32
	AllocationBlocks    uint16
	AllocationStart     uint16
	AllocationBase      uint64
	FreeBlocks          uint16
	NextCNID            uint32
	FileCount           uint32
	DirectoryCount      uint32
	RootFiles           uint16
	RootDirectories     uint16

	CreateDate    time.Time
	ModifyDate    time.Time
	HasCreateDate bool
	HasModifyDate bool
	Unmounted     bool

	CatalogNodeSize    uint16
	CatalogTotalNodes  uint32
	CatalogLeafRecords uint64
	Folders            uint64
	Files              uint64
	Threads            uint64
	OtherRecords       uint64
	MalformedRecords   uint64

	ExtentsLookups uint64
	ExtentsFound   uint64
	ExtentsMissing uint64

	// DeclaredBytes is the allocation area the MDB describes; Truncated is
	// true when the source is shorter.
	DeclaredBytes uint64
	Truncated     bool

	Warnings       []string
	WarningsCapped bool

	// TimeBasis names the convention applied to the stored timestamps.
	TimeBasis string
}

// node is one catalogued folder or file.
type node struct {
	record    uint32
	parentID  uint32
	hasParent bool
	name      string
	path      string
	children  []uint32

	isDir bool

	size              uint64
	allocated         uint64
	hasAllocated      bool
	resourceSize      uint64
	resourceAllocated uint64

	created  uint32
	modified uint32
	backup   uint32

	finderType    uint32
	finderCreator uint32

	dataFork     *fork
	resourceFork *fork
}

// rawEntry is one catalog record before the tree is built.
type rawEntry struct {
	id           uint32
	parentID     uint32
	name         string
	isDir        bool
	valence      uint16
	hasValence   bool
	file         *fileRecord
	dataFork     *fork
	resourceFork *fork
}

// Volume is an opened classic HFS volume.
type Volume struct {
	src           source.ByteSource
	mdb           *MasterDirectoryBlock
	nodes         []node
	index         map[uint32]int
	rootID        uint32
	catalogHeader treeHeader
	stats         VolumeStats
	warnings      []string
	declaredBytes uint64
	truncated     bool
	nextID        atomic.Uint64
}

// Detect reports whether src looks like a classic HFS volume without
// mounting it.
func Detect(src source.ByteSource) (bool, error) {
	return detectMDB(src)
}

// Open reads the MDB, flattens both forks of every catalogued file, and walks
// the catalog.
func Open(src source.ByteSource) (*Volume, error) {
	mdb, err := ReadMDB(src)
	if err != nil {
		return nil, err
	}
	volume := &Volume{
		src:    src,
		mdb:    mdb,
		rootID: RootDirectoryID,
		index:  make(map[uint32]int),
	}
	volume.nextID.Store(uint64(src.SourceID()) + 1)

	blockSize := mdb.AllocationBlockSize
	base := mdb.AllocationBase()
	volume.declaredBytes = base + saturatingMul(uint64(mdb.AllocationBlocks), uint64(blockSize))
	if volume.declaredBytes > src.Len() {
		volume.truncated = true
		volume.pushWarning(fmt.Sprintf("the volume declares %d bytes but the source holds %d",
			volume.declaredBytes, src.Len()))
	}

	// The extents file's own extents cannot be resolved through itself: its
	// first three come from the MDB and that is all a reader can follow.
	extentsFork, err := forkFromRecord(mdb.ExtentsExtents, uint64(mdb.ExtentsFileSize), blockSize, base)
	if err != nil {
		return nil, err
	}
	neededExtents := ceilDiv(uint64(mdb.ExtentsFileSize), uint64(blockSize))
	if extentsFork.allocationBlocks < neededExtents {
		volume.pushWarning("the extents overflow file needs more than the three extents its MDB record holds")
	}
	var extentsTree *bTree
	if mdb.ExtentsFileSize > 0 {
		extentsTree, err = openBTree(src, extentsFork)
		if err != nil {
			return nil, err
		}
	}

	catalogFork, err := volume.flattenFork(mdb.CatalogExtents, uint64(mdb.CatalogFileSize),
		CatalogFileID, ForkData, extentsTree)
	if err != nil {
		return nil, err
	}
	catalogTree, err := openBTree(src, catalogFork)
	if err != nil {
		return nil, err
	}
	volume.catalogHeader = catalogTree.header
	volume.stats.CatalogNodeSize = catalogTree.header.nodeSize
	volume.stats.CatalogTotalNodes = catalogTree.header.totalNodes

	var entries []rawEntry
	seen := make(map[uint32]bool)
	err = catalogTree.walkLeaves(func(key, data []byte) (bool, error) {
		volume.stats.CatalogLeafRecords++
		catalogKey, err := parseCatalogKey(key)
		if err != nil {
			volume.stats.MalformedRecords++
			volume.pushWarning(err.Error())
			return true, nil
		}
		record, err := parseCatalogRecord(catalogKey, data)
		if err != nil {
			volume.stats.MalformedRecords++
			volume.pushWarning(err.Error())
			return true, nil
		}
		switch record.kind {
		case recordFolder:
			if seen[record.directoryID] {
				volume.stats.MalformedRecords++
				volume.pushWarning(fmt.Sprintf("catalog node %d appears more than once", record.directoryID))
				return true, nil
			}
			seen[record.directoryID] = true
			volume.stats.Folders++
			entries = append(entries, rawEntry{
				id:         record.directoryID,
				parentID:   catalogKey.parentID,
				name:       catalogKey.name,
				isDir:      true,
				valence:    record.valence,
				hasValence: true,
			})
		case recordFile:
			file := record.file
			if seen[file.fileID] {
				volume.stats.MalformedRecords++
				volume.pushWarning(fmt.Sprintf("catalog node %d appears more than once", file.fileID))
				return true, nil
			}
			seen[file.fileID] = true
			volume.stats.Files++
			entries = append(entries, rawEntry{
				id:       file.fileID,
				parentID: catalogKey.parentID,
				name:     catalogKey.name,
				isDir:    false,
				file:     file,
			})
		case recordThread:
			volume.stats.Threads++
		default:
			volume.stats.OtherRecords++
			volume.pushWarning(fmt.Sprintf("catalog record type %#06x is not decoded", record.otherType))
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	rootEntry := -1
	for index := range entries {
		if entries[index].id == RootDirectoryID {
			rootEntry = index
			break
		}
	}
	if rootEntry < 0 {
		return nil, corruptf("the catalog has no root folder record (catalog node 2)")
	}
	if entries[rootEntry].parentID != RootParentID {
		volume.pushWarning(fmt.Sprintf("the root folder record names parent %d, not %d",
			entries[rootEntry].parentID, RootParentID))
	}
	if entries[rootEntry].name != mdb.Name {
		volume.pushWarning(fmt.Sprintf("the root folder record names %q but the volume is named %q",
			entries[rootEntry].name, mdb.Name))
	}

	// Flatten each file's forks while the entries are still together, so an
	// overflow lookup is counted once.
	for index := range entries {
		entry := &entries[index]
		if entry.file == nil {
			continue
		}
		if entry.file.dataSize > 0 {
			value, err := volume.flattenFork(entry.file.dataExtents, uint64(entry.file.dataSize),
				entry.file.fileID, ForkData, extentsTree)
			if err != nil {
				return nil, err
			}
			entry.dataFork = &value
		}
		if entry.file.resourceSize > 0 {
			value, err := volume.flattenFork(entry.file.resourceExtents, uint64(entry.file.resourceSize),
				entry.file.fileID, ForkResource, extentsTree)
			if err != nil {
				return nil, err
			}
			entry.resourceFork = &value
		}
	}

	volume.nodes = make([]node, len(entries))
	for index := range entries {
		volume.nodes[index] = nodeFromEntry(&entries[index])
	}
	sort.Slice(volume.nodes, func(left, right int) bool {
		return volume.nodes[left].record < volume.nodes[right].record
	})
	for position := range volume.nodes {
		volume.index[volume.nodes[position].record] = position
	}

	// Children keep catalog order, which is key order; a child whose parent is
	// missing stays listed with its recorded parent but gains no path.
	children := make([][]uint32, len(volume.nodes))
	for index := range entries {
		entry := &entries[index]
		if entry.id == RootDirectoryID {
			continue
		}
		if parent, ok := volume.index[entry.parentID]; ok {
			children[parent] = append(children[parent], entry.id)
		}
	}
	for position := range volume.nodes {
		volume.nodes[position].children = children[position]
	}

	rootPosition := volume.index[RootDirectoryID]
	volume.nodes[rootPosition].hasParent = false
	volume.nodes[rootPosition].path = "/"

	stack := []uint32{RootDirectoryID}
	visited := make([]bool, len(volume.nodes))
	visited[rootPosition] = true
	for len(stack) > 0 {
		record := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		position, ok := volume.index[record]
		if !ok {
			continue
		}
		parentPath := volume.nodes[position].path
		for _, child := range volume.nodes[position].children {
			childPosition, ok := volume.index[child]
			if !ok {
				continue
			}
			if visited[childPosition] {
				volume.pushWarning(fmt.Sprintf("catalog node %d is reachable more than once", child))
				continue
			}
			visited[childPosition] = true
			name := volume.nodes[childPosition].name
			if parentPath == "/" {
				volume.nodes[childPosition].path = "/" + name
			} else {
				volume.nodes[childPosition].path = parentPath + "/" + name
			}
			stack = append(stack, child)
		}
	}

	// The root record's valence is the number of names the writer thought it
	// held. Compare it with what the catalog actually lists.
	if entries[rootEntry].hasValence {
		recorded := uint64(entries[rootEntry].valence)
		listed := uint64(len(volume.nodes[rootPosition].children))
		if recorded != listed {
			volume.pushWarning(fmt.Sprintf(
				"the root folder record declares %d entries but the catalog holds %d", recorded, listed))
		}
	}
	return volume, nil
}

// flattenFork follows the extents overflow tree when the catalog record's
// three extents do not cover the whole fork.
func (v *Volume) flattenFork(record ExtentRecord, logicalSize uint64, fileID uint32,
	forkType uint8, extentsTree *bTree) (fork, error) {
	mdb := v.mdb
	blockSize := mdb.AllocationBlockSize
	base := mdb.AllocationBase()
	value, err := forkFromRecord(record, logicalSize, blockSize, base)
	if err != nil {
		return fork{}, err
	}
	needed := ceilDiv(logicalSize, uint64(blockSize))
	if value.allocationBlocks >= needed {
		return value, nil
	}
	if extentsTree == nil {
		v.pushWarning(fmt.Sprintf(
			"file %d needs %d allocation blocks but has no extents overflow file", fileID, needed))
		return value, nil
	}
	lookups := 0
	for value.allocationBlocks < needed {
		if lookups >= MaxOverflowLookups {
			v.pushWarning(fmt.Sprintf("file %d needs more than %d overflow extents",
				fileID, MaxOverflowLookups))
			break
		}
		if value.allocationBlocks > 0xFFFF {
			v.pushWarning(fmt.Sprintf("file %d passes the 16-bit extent key's %d block limit",
				fileID, 0xFFFF))
			break
		}
		startBlock := uint16(value.allocationBlocks)
		key := overflowKey(fileID, forkType, startBlock)
		v.stats.ExtentsLookups++
		lookups++
		data, err := extentsTree.search(key)
		if err != nil {
			return value, err
		}
		if data == nil {
			v.stats.ExtentsMissing++
			v.pushWarning(fmt.Sprintf("file %d fork %#04x has no overflow extent at block %d",
				fileID, forkType, startBlock))
			break
		}
		if len(data) < ExtentRecordBytes {
			v.pushWarning(fmt.Sprintf("file %d's overflow record at block %d is %d bytes",
				fileID, startBlock, len(data)))
			break
		}
		continuation, err := readExtentRecord(data, 0)
		if err != nil {
			return value, err
		}
		if describedBlocks(continuation) == 0 {
			v.pushWarning(fmt.Sprintf("file %d's overflow record at block %d is empty",
				fileID, startBlock))
			break
		}
		v.stats.ExtentsFound++
		value.append(continuation, blockSize, base)
	}
	return value, nil
}

// overflowKey is the eight-byte key payload of an extents overflow record.
func overflowKey(fileID uint32, forkType uint8, startBlock uint16) []byte {
	return []byte{
		forkType, 0,
		byte(fileID >> 24), byte(fileID >> 16), byte(fileID >> 8), byte(fileID),
		byte(startBlock >> 8), byte(startBlock),
	}
}

func nodeFromEntry(entry *rawEntry) node {
	value := node{
		record:       entry.id,
		parentID:     entry.parentID,
		hasParent:    true,
		name:         entry.name,
		isDir:        entry.isDir,
		dataFork:     entry.dataFork,
		resourceFork: entry.resourceFork,
	}
	if entry.file != nil {
		value.size = uint64(entry.file.dataSize)
		value.allocated = uint64(entry.file.dataPhysicalSize)
		value.hasAllocated = true
		value.resourceSize = uint64(entry.file.resourceSize)
		value.resourceAllocated = uint64(entry.file.resourcePhysicalSize)
		value.created = entry.file.created
		value.modified = entry.file.modified
		value.backup = entry.file.backup
		value.finderType = entry.file.finderType
		value.finderCreator = entry.file.finderCreator
	}
	return value
}

// Info returns the volume's report.
func (v *Volume) Info() Info {
	mdb := v.mdb
	createDate := hfsTime(mdb.CreateDate)
	modifyDate := hfsTime(mdb.ModifyDate)
	return Info{
		Name:                mdb.Name,
		Signature:           mdb.Signature,
		AllocationBlockSize: mdb.AllocationBlockSize,
		AllocationBlocks:    mdb.AllocationBlocks,
		AllocationStart:     mdb.AllocationStart,
		AllocationBase:      mdb.AllocationBase(),
		FreeBlocks:          mdb.FreeBlocks,
		NextCNID:            mdb.NextCNID,
		FileCount:           mdb.FileCount,
		DirectoryCount:      mdb.DirectoryCount,
		RootFiles:           mdb.RootFiles,
		RootDirectories:     mdb.RootDirectories,
		CreateDate:          createDate,
		ModifyDate:          modifyDate,
		HasCreateDate:       mdb.CreateDate != 0,
		HasModifyDate:       mdb.ModifyDate != 0,
		Unmounted:           mdb.IsUnmounted(),
		CatalogNodeSize:     v.stats.CatalogNodeSize,
		CatalogTotalNodes:   v.stats.CatalogTotalNodes,
		CatalogLeafRecords:  v.stats.CatalogLeafRecords,
		Folders:             v.stats.Folders,
		Files:               v.stats.Files,
		Threads:             v.stats.Threads,
		OtherRecords:        v.stats.OtherRecords,
		MalformedRecords:    v.stats.MalformedRecords,
		ExtentsLookups:      v.stats.ExtentsLookups,
		ExtentsFound:        v.stats.ExtentsFound,
		ExtentsMissing:      v.stats.ExtentsMissing,
		DeclaredBytes:       v.declaredBytes,
		Truncated:           v.truncated,
		Warnings:            append([]string(nil), v.warnings...),
		WarningsCapped:      v.stats.WarningsCapped,
		TimeBasis:           timeBasisLocalWallClock,
	}
}

// Stats returns the walk counters.
func (v *Volume) Stats() VolumeStats { return v.stats }

// Warnings returns the messages collected while opening.
func (v *Volume) Warnings() []string { return append([]string(nil), v.warnings...) }

// MDB returns the parsed Master Directory Block.
func (v *Volume) MDB() *MasterDirectoryBlock { return v.mdb }

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.src }

// entryFor builds an Entry from one node.
func (v *Volume) entryFor(value *node) Entry {
	name := value.name
	path := value.path
	if value.record == v.rootID {
		name = "/"
		path = "/"
	}
	parent := uint32(0)
	if value.hasParent {
		parent = value.parentID
	}
	entry := Entry{
		Name:              name,
		Path:              path,
		Inode:             value.record,
		ParentInode:       parent,
		IsDir:             value.isDir,
		IsFile:            !value.isDir,
		Size:              value.size,
		Allocated:         value.allocated,
		HasAllocated:      value.hasAllocated,
		ResourceSize:      value.resourceSize,
		ResourceAllocated: value.resourceAllocated,
		FinderType:        value.finderType,
		FinderCreator:     value.finderCreator,
	}
	if value.created != 0 {
		entry.Created = hfsTime(value.created)
		entry.HasCreated = true
	}
	if value.modified != 0 {
		entry.Modified = hfsTime(value.modified)
		entry.HasModified = true
	}
	if value.backup != 0 {
		entry.Backup = hfsTime(value.backup)
		entry.HasBackup = true
	}
	return entry
}

// resolve walks a '/'-separated path to its node. "" and "/" name the root.
func (v *Volume) resolve(path string) (*node, error) {
	current, ok := v.index[v.rootID]
	if !ok {
		return nil, corruptf("the catalog index has no root")
	}
	for _, component := range strings.Split(path, "/") {
		switch component {
		case "", ".":
			continue
		case "..":
			if v.nodes[current].hasParent {
				parent, ok := v.index[v.nodes[current].parentID]
				if !ok {
					return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
				}
				current = parent
			}
			continue
		}
		if !v.nodes[current].isDir {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		found := false
		for _, child := range v.nodes[current].children {
			position, ok := v.index[child]
			if !ok {
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
	return &v.nodes[current], nil
}

// ListDir lists a directory's children in catalog order.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	directory, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	if !directory.isDir {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	out := make([]Entry, 0, len(directory.children))
	for _, child := range directory.children {
		position, ok := v.index[child]
		if !ok {
			continue
		}
		entry := v.entryFor(&v.nodes[position])
		entry.ParentInode = directory.record
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

// OpenFile opens the file named by path as a byte source. An empty file yields
// a zero-length source.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	value, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	if value.isDir {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	return v.forkSource(value.dataFork), nil
}

// OpenResourceFork opens a file's resource fork. A file with no resource fork
// yields a zero-length source.
func (v *Volume) OpenResourceFork(path string) (source.ByteSource, error) {
	value, err := v.resolve(path)
	if err != nil {
		return nil, err
	}
	if value.isDir {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	return v.forkSource(value.resourceFork), nil
}

// HasResourceFork reports whether a file records a non-empty resource fork.
func (v *Volume) HasResourceFork(path string) bool {
	value, err := v.resolve(path)
	if err != nil {
		return false
	}
	return !value.isDir && value.resourceFork != nil
}

func (v *Volume) forkSource(value *fork) source.ByteSource {
	id := source.ID(v.nextID.Add(1))
	if value == nil {
		return newForkSource(id, v.src, fork{})
	}
	return newForkSource(id, v.src, *value)
}

func (v *Volume) pushWarning(message string) {
	if len(v.warnings) >= WarningCap {
		v.stats.WarningsCapped = true
		return
	}
	for _, existing := range v.warnings {
		if existing == message {
			return
		}
	}
	v.warnings = append(v.warnings, message)
}

// hfsTime converts stored seconds since 1904 to a UTC time; zero is unset.
func hfsTime(seconds uint32) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(int64(seconds)-hfsEpochUnix, 0).UTC()
}

func ceilDiv(value, divisor uint64) uint64 {
	if divisor == 0 {
		return 0
	}
	return value/divisor + boolToUint(value%divisor != 0)
}

func boolToUint(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
