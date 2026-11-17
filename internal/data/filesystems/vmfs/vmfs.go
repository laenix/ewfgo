// Package vmfs reads VMFS5 and VMFS6 datastores, read-only, through the data
// layer's ByteSource contract. It is a pure-Go port of forensic-core's VMFS
// reader.
//
// # Layout
//
// The volume information block sits at byte 0x100000 (1 MiB), with the
// little-endian magic 0xc001d00d; the filesystem information block sits at byte
// 0x200000 (2 MiB), with the magic 0x2fabf15e. The filesystem information
// records the version byte (3 for VMFS5, 4 for VMFS6), the label and UUID, the
// 1 MiB file-block size, the sub-block size and the FDC header/bitmap counts.
// Detection reads the volume magic at its fixed offset, then validates the
// filesystem geometry before claiming the slot.
//
// File descriptors live in the FDC pool, whose header is at block 25. The root
// directory is FDC entry 0, item 0: a descriptor with block id
// VMFS_BLK_FD_BUILD(0, 0, 0) = 4. Descriptors hold a 256-entry block array
// (32-bit on VMFS5, 64-bit on VMFS6); a direct map points at 1 MiB file blocks,
// and a single-indirect map points at 64 KiB pointer blocks in the .pbc.sf
// cache, each holding 1024 file-block addresses. Directories are streams of
// 288-byte records (type, block_id, record_id, name).
//
// # Times
//
// VMFS stores access, status-change and modification times as 32-bit Unix
// seconds and no creation time. A zero field is unset, not 1970; Entry uses the
// zero time.Time for it. The format records no time zone.
//
// # What a walk proves
//
// Open walks every directory, as the on-disk name inventory is the only index.
// An Entry's Record is the node's ordinal in the walk, 0 being the root. The
// file descriptor's block id is reported separately as InodeNumber. A
// directory reached by a second name is listed but not walked twice; a file
// reached by a second name is listed under each name.
//
// # What is not read
//
// VMFS3 and VMFS4 images are refused by name, as are sub-block (SB) data,
// double-indirect (PB2) maps and the VMFS5 extended zero-level address space.
// A byte-swapped image, an unknown version or block size, a descriptor whose
// map does not cover its size, a zero block address and an out-of-range block
// are refused rather than guessed at or zero-filled. Sparse holes are refused:
// VMFS does not define a hole this reader can prove, so a zero block address is
// always an error and never a run of zeros. Deleted-file recovery is out of
// scope: type-zero directory slots are counted and their surviving names are
// reported through Entry.UnusedSlots/Entry.DeletedNames and Info.UnusedSlots,
// but no deleted name becomes a catalog Entry. The file-block and sub-block
// bitmaps are not decoded into a free-space map, and the VMFS journal is not
// replayed, so only committed metadata is walked. System files such as .vh.sf,
// .fdc.sf, .fbb.sf and .pbc.sf are listed as ordinary entries; only .pbc.sf's
// bitmap header is interpreted, and only to locate pointer blocks. The Rust
// reference exposes no PB2 heartbeat region, so none is read here; PB2 maps are
// refused by name.
package vmfs

import (
	"errors"
	"fmt"
	pathpkg "path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// kindLabel is the filesystem's name as facts and listings report it.
	kindLabel = "VMFS"
	// maxNodes bounds the walk rather than exhausting memory.
	maxNodes = 5_000_000
	// maxSymlinkBytes is the longest symbolic-link target read into an Entry.
	maxSymlinkBytes uint64 = 64 * 1024
	// warningCap is the number of warnings kept per volume.
	warningCap = 32
)

// Entry describes one name the walk found.
type Entry struct {
	Name string
	// Path is the display path, '/'-separated. The root's is "/".
	Path string

	IsDir     bool
	IsFile    bool
	IsSymlink bool

	// Mode holds the permission and type bits as recorded (lower 16 bits).
	Mode  uint16
	UID   uint32
	GID   uint32
	NLink uint32
	// Flags is the descriptor's flags field, recorded as-is.
	Flags uint32

	// Size is the logical length in bytes.
	Size uint64
	// Allocated is the bytes the data stream allocates. It is meaningful only
	// when AllocatedKnown is true: directories, and files whose block map did
	// not validate, have no known allocation.
	Allocated      uint64
	AllocatedKnown bool

	// InodeNumber is the file descriptor's block id, which joins the node to
	// other artifacts. It is not the walk ordinal.
	InodeNumber uint32
	// RecordID is the descriptor's generation (id2).
	RecordID uint32
	// Record is the node's ordinal in the walk, 0 being the root.
	Record uint64
	// ParentRecord is the walk ordinal of the parent directory. It is
	// meaningful only when HasParent is true.
	ParentRecord uint64
	HasParent    bool

	// Times are UTC. A zero time.Time means the descriptor's field was zero
	// (unset), not 1970.
	Modified time.Time
	Changed  time.Time
	Accessed time.Time

	// SymlinkTarget is the target bytes read for a symbolic link. It is empty
	// when the target is not read, either because the descriptor's map failed
	// or because the target exceeds maxSymlinkBytes; the latter sets
	// SymlinkTargetTruncated.
	SymlinkTarget          string
	SymlinkTargetTruncated bool

	// UnusedSlots counts type-zero records in this directory, including
	// all-zero padding records. It is meaningful only for directories.
	UnusedSlots uint64
	// DeletedNames holds names that survive in type-zero slots of this
	// directory, bounded to 16. They are reported, not recovered: no deleted
	// name becomes an Entry.
	DeletedNames []string
}

// Info is the volume-level description returned by Volume.Info.
type Info struct {
	Type         string
	Version      uint8
	VersionLabel string

	VolumeInfoVersion uint32
	FSVolumeVersion   uint32

	BlockSize       uint32
	SubblockSize    uint32
	DeviceBlockSize uint32
	VolumeLabel     string
	VolumeName      string
	UUID            string
	VolumeUUID      string
	Mode            uint32

	FDCHeaderSize      uint32
	FDCBitmapCount     uint32
	FDCItems           uint32
	FDCAreas           uint32
	FDSize             uint32
	MetadataHeaderSize uint32
	FileBlockEntries   uint32

	PointerBlockSize   uint64
	PointerBlockItems  uint64
	WideBlockAddresses bool

	Blocks      uint64
	VolumeBytes uint64
	RootInode   uint32

	Entries     int
	Directories uint64
	Files       uint64
	Symlinks    uint64

	PointerBlocks  uint64
	PointerRecords uint64
	ExtentLookups  uint64
	NodesRead      uint64
	BlocksRead     uint64

	Refusals       uint64
	Malformed      uint64
	Unreadable     uint64
	Undecodable    uint64
	DirectoryLoops uint64
	UnusedSlots    uint64

	PBCLoaded bool

	Warnings        []string
	WarningsDropped uint64
}

type node struct {
	entry    Entry
	parent   int
	children []int
}

// Volume is an opened VMFS5 or VMFS6 datastore.
type Volume struct {
	src source.ByteSource
	sb  *superblock
	fdc bitmapHeader
	pbc *pbc

	inodes []*inode
	nodes  []node
	paths  map[string]int

	unreadable      uint64
	undecodable     uint64
	refusals        uint64
	malformed       uint64
	directoryLoops  uint64
	unusedSlots     uint64
	nodesRead       uint64
	blocksRead      uint64
	pointerBlocks   uint64
	pointerRecords  uint64
	lookups         uint64
	warnings        []string
	warningsDropped uint64

	fileID atomic.Uint64
}

// Open reads the information blocks, loads the pointer-block cache when one is
// present, and walks every directory.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := readSuperblock(src)
	if err != nil {
		return nil, err
	}
	if sb.blocks <= fdcBaseBlock {
		return nil, corruptf("the source is %d whole %d-byte blocks, too short for the file-descriptor bitmap header at block %d",
			sb.blocks, sb.blockSize, fdcBaseBlock)
	}
	fdcAt, ok := sb.blockOffset(fdcBaseBlock)
	if !ok {
		return nil, corruptf("the FDC block's byte offset overflows")
	}
	fdc, err := readBitmapHeader(src, fdcAt, sb.fdSize, "the file-descriptor bitmap header at block 25")
	if err != nil {
		return nil, err
	}
	if fdc.hdrSize != sb.fdcHeaderSize {
		return nil, corruptf("the FDC header at byte %d declares a %d-byte header, but the filesystem information declares %d",
			fdcAt, fdc.hdrSize, sb.fdcHeaderSize)
	}
	root, err := readInode(src, sb, &fdc, rootBlockID)
	if err != nil {
		return nil, err
	}
	if !root.kind.isDirectory() {
		return nil, corruptf("the root file descriptor 0x%08x at block %d is a %s, not a directory",
			rootBlockID, fdcBaseBlock, root.kind.label())
	}

	v := &Volume{
		src:        src,
		sb:         sb,
		fdc:        fdc,
		inodes:     []*inode{root},
		paths:      make(map[string]int),
		nodesRead:  1,
		blocksRead: 1,
	}
	v.fileID.Store(uint64(src.SourceID()) + 1_000_000)
	v.nodes = append(v.nodes, node{
		parent: -1,
		entry: Entry{
			Name:        "/",
			Path:        "/",
			IsDir:       true,
			Mode:        root.mode,
			UID:         root.uid,
			GID:         root.gid,
			NLink:       root.links,
			Flags:       root.flags,
			Size:        root.size,
			InodeNumber: root.blockID,
			RecordID:    root.id2,
			Record:      0,
			Modified:    unixTime(root.modified),
			Changed:     unixTime(root.changed),
			Accessed:    unixTime(root.accessed),
		},
	})
	v.paths["/"] = 0

	v.pushWarning("VMFS is a clustered, journaled filesystem; the journal is not replayed, so only committed metadata is walked, and deleted-file recovery is not read")
	v.loadPBC()
	if err := v.walk(); err != nil {
		return nil, err
	}
	return v, nil
}

func unixTime(seconds uint32) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(int64(seconds), 0).UTC()
}

// walk reads every directory breadth-first, listing each name once.
func (v *Volume) walk() error {
	visited := map[uint32]bool{v.nodes[0].entry.InodeNumber: true}
	queue := []int{0}

	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		v.lookups++

		listing, err := v.directoryListing(directory)
		if err != nil {
			v.unreadable++
			v.classify(err)
			v.pushWarning(fmt.Sprintf("directory %s: %v", v.nodes[directory].entry.Path, err))
			continue
		}
		v.blocksRead += listing.blocks + listing.extentBlocks
		v.pointerBlocks += listing.extentBlocks
		v.pointerRecords += listing.extentRecords
		v.unusedSlots += listing.unusedSlots
		v.nodes[directory].entry.UnusedSlots = listing.unusedSlots
		v.nodes[directory].entry.DeletedNames = append([]string(nil), listing.unusedNames...)
		if listing.unusedSlots > 0 {
			names := ""
			if len(listing.unusedNames) > 0 {
				names = fmt.Sprintf("; surviving names: %q", listing.unusedNames)
			}
			v.pushWarning(fmt.Sprintf("directory %s: %d type-0 (unused or deleted) slots%s; deleted-file recovery is not read",
				v.nodes[directory].entry.Path, listing.unusedSlots, names))
		}
		parentPath := v.nodes[directory].entry.Path

		for _, de := range listing.entries {
			if de.name == "." || de.name == ".." {
				continue
			}
			in, err := v.readInodeRecord(de.blockID)
			if err != nil {
				v.undecodable++
				v.classify(err)
				v.pushWarning(fmt.Sprintf("directory %s: name %q: %v", parentPath, de.name, err))
				continue
			}
			expected, ok := kindForType(de.fileType)
			if !ok {
				// The directory parser already refuses unknown types, so this
				// is defensive parity with the reference, not a reachable path.
				v.malformed++
				v.pushWarning(fmt.Sprintf("directory %s: name %q has unknown type %d", parentPath, de.name, de.fileType))
				continue
			}
			if in.kind != expected {
				v.malformed++
				v.pushWarning(fmt.Sprintf("directory %s: name %q is type %d in the directory but a %s in its descriptor",
					parentPath, de.name, de.fileType, in.kind.label()))
				continue
			}
			if de.recordID != 0 && de.recordID != in.id2 {
				v.malformed++
				v.pushWarning(fmt.Sprintf("directory %s: name %q names record %d but descriptor 0x%08x names record %d",
					parentPath, de.name, de.recordID, in.blockID, in.id2))
				continue
			}
			if len(v.nodes) >= maxNodes {
				return corruptf("the image names more than %d entries", maxNodes)
			}
			path := de.name
			if parentPath == "/" {
				path = "/" + path
			} else {
				path = parentPath + "/" + path
			}

			undecodable := false
			var allocated uint64
			allocatedKnown := false
			var symlinkTarget string
			symlinkTruncated := false

			switch in.kind {
			case kindFile:
				file, err := v.fileSourceFor(in)
				if err != nil {
					undecodable = true
					v.classify(err)
					v.pushWarning(fmt.Sprintf("file %s: %v", path, err))
				} else {
					allocated = file.allocatedBytes()
					allocatedKnown = true
					v.pointerBlocks += file.extentBlocksRead()
					v.pointerRecords += file.extentRecords()
					v.blocksRead += file.extentBlocksRead()
				}
			case kindSymlink:
				file, err := v.fileSourceFor(in)
				if err != nil {
					undecodable = true
					v.classify(err)
					v.pushWarning(fmt.Sprintf("symlink %s: %v", path, err))
				} else {
					allocated = file.allocatedBytes()
					allocatedKnown = true
					v.pointerBlocks += file.extentBlocksRead()
					v.pointerRecords += file.extentRecords()
					v.blocksRead += file.extentBlocksRead()
					if in.size <= maxSymlinkBytes {
						bytes := make([]byte, int(in.size))
						if _, err := file.readAtInternal(0, bytes); err != nil {
							undecodable = true
							v.classify(err)
							v.pushWarning(fmt.Sprintf("symlink %s: %v", path, err))
						} else {
							symlinkTarget = string(bytes)
						}
					} else {
						symlinkTruncated = true
						v.pushWarning(fmt.Sprintf("symlink %s: target is %d bytes, more than the %d-byte inline cap; open the link stream instead",
							path, in.size, maxSymlinkBytes))
					}
				}
			case kindDirectory:
				// Children are walked below.
			}
			if undecodable {
				v.undecodable++
			}

			child := len(v.nodes)
			entry := Entry{
				Name:                   de.name,
				Path:                   path,
				IsDir:                  in.kind.isDirectory(),
				IsFile:                 in.kind.isFile(),
				IsSymlink:              in.kind.isSymlink(),
				Mode:                   in.mode,
				UID:                    in.uid,
				GID:                    in.gid,
				NLink:                  in.links,
				Flags:                  in.flags,
				Size:                   in.size,
				Allocated:              allocated,
				AllocatedKnown:         allocatedKnown,
				InodeNumber:            in.blockID,
				RecordID:               in.id2,
				Record:                 uint64(child),
				ParentRecord:           uint64(directory),
				HasParent:              true,
				Modified:               unixTime(in.modified),
				Changed:                unixTime(in.changed),
				Accessed:               unixTime(in.accessed),
				SymlinkTarget:          symlinkTarget,
				SymlinkTargetTruncated: symlinkTruncated,
			}
			v.nodes = append(v.nodes, node{entry: entry, parent: directory})
			v.inodes = append(v.inodes, in)
			v.paths[path] = child
			v.nodes[directory].children = append(v.nodes[directory].children, child)
			if in.kind.isDirectory() {
				if !visited[in.blockID] {
					visited[in.blockID] = true
					queue = append(queue, child)
				} else {
					v.directoryLoops++
				}
			}
		}
	}
	return nil
}

func kindForType(fileType uint32) (inodeKind, bool) {
	switch fileType {
	case 1:
		return kindFile, true
	case 2:
		return kindDirectory, true
	case 3:
		return kindSymlink, true
	default:
		return 0, false
	}
}

// directoryListing reads and parses one directory's data stream.
func (v *Volume) directoryListing(directory int) (*dirListing, error) {
	in := v.inodes[directory]
	if !in.kind.isDirectory() {
		return nil, corruptf("node %s is a %s, not a directory", v.nodes[directory].entry.Path, in.kind.label())
	}
	return readDir(v.sb, v.src, in, v.pbc)
}

func (v *Volume) readInodeRecord(blockID uint32) (*inode, error) {
	in, err := readInode(v.src, v.sb, &v.fdc, blockID)
	if err != nil {
		return nil, err
	}
	v.nodesRead++
	v.blocksRead++
	return in, nil
}

func (v *Volume) fileSourceFor(in *inode) (*fileSource, error) {
	return newFileSource(v.src.SourceID(), v.src, v.sb, in, v.pbc)
}

// loadPBC locates and loads .pbc.sf from the root directory, if it is present.
// A missing cache is not an issue: only a file whose descriptor uses a
// single-indirect map needs it. A present cache that cannot be read is reported
// as a warning so the rest of the volume still walks.
func (v *Volume) loadPBC() {
	root := v.inodes[0]
	listing, err := readDir(v.sb, v.src, root, nil)
	if err != nil {
		// The walk reports an unreadable root itself.
		return
	}
	for _, de := range listing.entries {
		if de.name != "." {
			continue
		}
		if de.blockID != root.blockID || (de.recordID != 0 && de.recordID != root.id2) {
			v.pushWarning(fmt.Sprintf("the root directory's \".\" entry names block id 0x%08x/record %d but the root descriptor is 0x%08x/record %d",
				de.blockID, de.recordID, root.blockID, root.id2))
			return
		}
		break
	}

	var entry *dirEntry
	for i := range listing.entries {
		if listing.entries[i].name == pbcName && listing.entries[i].isFile() {
			entry = &listing.entries[i]
			break
		}
	}
	if entry == nil {
		return
	}
	in, err := readInode(v.src, v.sb, &v.fdc, entry.blockID)
	if err != nil {
		v.pushWarning(fmt.Sprintf("%s: %v", pbcName, err))
		return
	}
	if entry.recordID != 0 && entry.recordID != in.id2 {
		v.pushWarning(fmt.Sprintf("%s: the directory names record %d but the descriptor at block id 0x%08x names record %d",
			pbcName, entry.recordID, in.blockID, in.id2))
		return
	}
	file, err := newFileSource(v.src.SourceID(), v.src, v.sb, in, nil)
	if err != nil {
		v.pushWarning(fmt.Sprintf("%s: %v", pbcName, err))
		return
	}
	loaded, err := loadPBC(file)
	if err != nil {
		v.pushWarning(fmt.Sprintf("%s: %v", pbcName, err))
		return
	}
	v.pbc = loaded
	v.nodesRead++
	v.blocksRead++
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
	if len(v.warnings) < warningCap {
		v.warnings = append(v.warnings, message)
	} else {
		v.warningsDropped++
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

func (v *Volume) entryCopy(index int) Entry {
	entry := v.nodes[index].entry
	entry.DeletedNames = append([]string(nil), entry.DeletedNames...)
	return entry
}

// ListDir returns the entries of the directory at path, in stored order.
// "" and "/" both name the root.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.nodes[index].entry
	if !entry.IsDir {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotDir, entry.Path, entryKindLabel(entry))
	}
	children := v.nodes[index].children
	entries := make([]Entry, 0, len(children))
	for _, child := range children {
		entries = append(entries, v.entryCopy(child))
	}
	return entries, nil
}

// Stat returns the entry at path. "" and "/" both name the root.
func (v *Volume) Stat(path string) (*Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.entryCopy(index)
	return &entry, nil
}

// OpenFile opens a regular file's data. A directory or symbolic link has no
// regular-file stream and returns ErrNotAFile.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.nodes[index].entry
	if !entry.IsFile {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotAFile, entry.Path, entryKindLabel(entry))
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.src, v.sb, v.inodes[index], v.pbc)
}

// OpenSymlink opens a symbolic link's target as a data stream.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.nodes[index].entry
	if !entry.IsSymlink {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotSymlink, entry.Path, entryKindLabel(entry))
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.src, v.sb, v.inodes[index], v.pbc)
}

// DeletedEntries returns the names that survive in type-zero slots of the
// directory at path, bounded to 16. They are reported, not recovered.
func (v *Volume) DeletedEntries(path string) ([]string, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.nodes[index].entry
	if !entry.IsDir {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotDir, entry.Path, entryKindLabel(entry))
	}
	return append([]string(nil), entry.DeletedNames...), nil
}

func entryKindLabel(entry Entry) string {
	switch {
	case entry.IsDir:
		return "directory"
	case entry.IsSymlink:
		return "symlink"
	case entry.IsFile:
		return "file"
	default:
		return "node"
	}
}

// Info returns volume-level facts.
func (v *Volume) Info() Info {
	sb := v.sb
	var directories, files, symlinks uint64
	for i := range v.nodes {
		switch {
		case v.nodes[i].entry.IsDir:
			directories++
		case v.nodes[i].entry.IsSymlink:
			symlinks++
		case v.nodes[i].entry.IsFile:
			files++
		}
	}
	return Info{
		Type:               kindLabel,
		Version:            sb.version,
		VersionLabel:       sb.versionLabel,
		VolumeInfoVersion:  sb.volumeInfoVersion,
		FSVolumeVersion:    sb.fsVolumeVersion,
		BlockSize:          sb.blockSize,
		SubblockSize:       sb.subblockSize,
		DeviceBlockSize:    sb.deviceBlockSize,
		VolumeLabel:        sb.volumeLabel,
		VolumeName:         sb.volumeName,
		UUID:               sb.uuidHex(),
		VolumeUUID:         sb.volumeUUIDHex(),
		Mode:               sb.mode,
		FDCHeaderSize:      v.fdc.hdrSize,
		FDCBitmapCount:     sb.fdcBitmapCount,
		FDCItems:           v.fdc.totalItems,
		FDCAreas:           v.fdc.areaCount,
		FDSize:             sb.fdSize,
		MetadataHeaderSize: sb.metadataHeaderSize,
		FileBlockEntries:   sb.fileBlockEntries,
		PointerBlockSize:   uint64(pointerBlockItemSize),
		PointerBlockItems:  pointerBlockItems,
		WideBlockAddresses: sb.wideBlockAddresses,
		Blocks:             sb.blocks,
		VolumeBytes:        sb.volumeBytes,
		RootInode:          rootBlockID,
		Entries:            len(v.nodes),
		Directories:        directories,
		Files:              files,
		Symlinks:           symlinks,
		PointerBlocks:      v.pointerBlocks,
		PointerRecords:     v.pointerRecords,
		ExtentLookups:      v.lookups,
		NodesRead:          v.nodesRead,
		BlocksRead:         v.blocksRead,
		Refusals:           v.refusals,
		Malformed:          v.malformed,
		Unreadable:         v.unreadable,
		Undecodable:        v.undecodable,
		DirectoryLoops:     v.directoryLoops,
		UnusedSlots:        v.unusedSlots,
		PBCLoaded:          v.pbc != nil,
		Warnings:           append([]string(nil), v.warnings...),
		WarningsDropped:    v.warningsDropped,
	}
}
