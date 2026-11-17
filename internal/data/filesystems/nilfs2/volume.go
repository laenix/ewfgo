// Package nilfs2 reads NILFS2 (the New Implementation of a Log-structured File
// System, version 2) volumes, read-only, from a source.ByteSource.
//
// It is a port of the Rust forensic-core NILFS2 reader. NILFS2 is append-only:
// the primary superblock at byte 1024 (and its backup at the last 4 KiB page
// boundary) names the last partial segment and the last checkpoint. That
// segment's summary ends at a checksummed super root holding the four metadata
// inodes — DAT, cpfile, sufile and ifile. Inodes are 128-byte records in the
// inode file; an ordinary inode's seven direct pointers are virtual block
// numbers translated through the DAT file, while metadata inodes' pointers are
// physical.
//
// Only the newest checkpoint's super root is read. Older checkpoints are not
// replayed, so a name removed after the last checkpoint leaves no entry.
// Allocation bitmaps and palloc group counters are not decoded, so no free
// space map is computed; the superblock's declared free-block count is
// reported as a recorded fact. B-tree block maps, logical blocks past the seven
// direct pointers, holes, unallocated DAT entries, palloc groups beyond group
// zero and out-of-range pointers are refused by name rather than guessed at or
// zero-filled.
//
// Times are whole Unix seconds (NILFS2 stores no sub-second part); a zero
// field is "unset" and is reported as such, never as 1970. i_ctime is the
// status-change time, not a creation time, so no creation time is exposed.
//
// Deleted-name recovery is not performed: an entry whose inode number is zero
// is a free slot and is skipped.
package nilfs2

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Info is a volume-level report. Times carry a Has flag because a zero stored
// field means "unset".
type Info struct {
	BlockSize     uint32
	LogBlockSize  uint32
	Revision      uint32
	MinorRevision uint32
	VolumeName    string
	UUID          string

	VolumeBytes         uint64
	DeviceBytes         uint64
	TotalBlocks         uint64
	FirstDataBlock      uint64
	BlocksPerSegment    uint64
	Segments            uint64
	RSegmentsPercentage int32

	LastCNO            uint64
	LastPseg           uint64
	LastSeq            uint64
	DeclaredFreeBlocks uint64
	MountCount         uint64
	MaxMountCount      int64
	CheckInterval      uint32
	Errors             int32
	FirstIno           uint64

	SuperblockBytes  uint16
	SuperblockOffset uint64
	FromBackup       bool
	BackupStatus     string
	SourceBytes      uint64
	Flags            uint16
	FeatureCompat    uint32
	FeatureROCompat  uint32

	SuperblockCtime    time.Time
	HasSuperblockCtime bool
	SuperblockMtime    time.Time
	HasSuperblockMtime bool
	SuperblockWtime    time.Time
	HasSuperblockWtime bool
	LastCheck          time.Time
	HasLastCheck       bool

	SegmentBlock         uint64
	SegmentSequence      uint64
	SegmentCNO           uint64
	SegmentNBlocks       uint32
	SegmentNFinfo        uint32
	SegmentSumBytes      uint32
	SegmentChecksumBytes int
	SegmentCreate        time.Time
	HasSegmentCreate     bool

	SuperRootBlock         uint64
	SuperRootBytes         uint16
	SuperRootFlags         uint16
	SuperRootNongcCtime    time.Time
	HasSuperRootNongcCtime bool
}

// Entry is one file or directory in a volume.
type Entry struct {
	Name        string
	Path        string
	Inode       uint64
	ParentInode uint64

	IsDir     bool
	IsFile    bool
	IsSymlink bool
	Kind      string

	Mode  uint16
	UID   uint32
	GID   uint32
	Links uint16
	Size  uint64

	// Allocated is the bytes the data stream allocates. AllocatedKnown is
	// false for directories and special files, and for an inode whose map
	// this reader refused.
	Allocated      uint64
	AllocatedKnown bool

	Atime    time.Time
	Ctime    time.Time
	Mtime    time.Time
	HasAtime bool
	HasCtime bool
	HasMtime bool

	// SymlinkTarget is filled for symbolic links.
	SymlinkTarget string

	// Deleted is always false for NILFS2: an unlinked name's directory entry
	// has inode number zero and is a free slot, so no deleted name is
	// provable here.
	Deleted bool
}

// WalkStats counts one whole-volume walk.
type WalkStats struct {
	// Nodes counts every name recorded, the root included.
	Nodes       uint64
	Directories uint64
	Files       uint64
	Symlinks    uint64
	Other       uint64

	NodesRead     uint64
	BlocksRead    uint64
	ExtentBlocks  uint64
	ExtentRecords uint64
	Lookups       uint64

	Unreadable     uint64
	Undecodable    uint64
	Refusals       uint64
	Malformed      uint64
	DirectoryLoops uint64

	Warnings        []string
	WarningsDropped uint64
}

// Volume is an opened NILFS2 volume.
type Volume struct {
	source     source.ByteSource
	superblock *Superblock
	summary    *Summary
	superRoot  *SuperRoot
	fileID     atomic.Uint64
}

// Open proves the superblock, the last checkpoint's segment summary and super
// root, and the root inode, then returns the volume.
func Open(src source.ByteSource) (*Volume, error) {
	superblock, err := ReadSuperblock(src)
	if err != nil {
		return nil, err
	}
	summary, err := ReadSummary(src, superblock)
	if err != nil {
		return nil, err
	}
	superRoot, err := ReadSuperRoot(src, superblock, summary.SuperRootBlock)
	if err != nil {
		return nil, err
	}
	if _, err := NewDat(superRoot.Dat); err != nil {
		return nil, err
	}
	ifile, err := NewIfile(superRoot.Ifile)
	if err != nil {
		return nil, err
	}
	root, err := ifile.ReadInode(superblock, src, RootInode)
	if err != nil {
		return nil, err
	}
	if !root.Kind.IsDirectory() {
		return nil, corruptf("the root inode %d is a %s, not a directory", RootInode, root.Kind.Label())
	}
	volume := &Volume{
		source:     src,
		superblock: superblock,
		summary:    summary,
		superRoot:  superRoot,
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	return volume, nil
}

// Info returns the volume-level report.
func (v *Volume) Info() Info {
	sb := v.superblock
	summary := v.summary
	superRoot := v.superRoot
	info := Info{
		BlockSize:            sb.BlockSize,
		LogBlockSize:         sb.LogBlockSize,
		Revision:             sb.RevLevel,
		MinorRevision:        sb.MinorRevLevel,
		VolumeName:           sb.VolumeName,
		UUID:                 sb.UUIDText(),
		VolumeBytes:          sb.VolumeBytes,
		DeviceBytes:          sb.DevSize,
		TotalBlocks:          sb.TotalBlocks,
		FirstDataBlock:       sb.FirstDataBlock,
		BlocksPerSegment:     sb.BlocksPerSegment,
		Segments:             sb.NSegments,
		RSegmentsPercentage:  sb.RSegmentsPercent,
		LastCNO:              sb.LastCNO,
		LastPseg:             sb.LastPseg,
		LastSeq:              sb.LastSeq,
		DeclaredFreeBlocks:   sb.FreeBlocksCount,
		MountCount:           sb.MntCount,
		MaxMountCount:        sb.MaxMntCount,
		CheckInterval:        sb.Checkinterval,
		Errors:               sb.Errors,
		FirstIno:             sb.FirstIno,
		SuperblockBytes:      sb.SuperblockBytes,
		SuperblockOffset:     sb.Offset,
		FromBackup:           sb.FromBackup,
		BackupStatus:         sb.BackupStatus,
		SourceBytes:          sb.SourceBytes,
		Flags:                sb.Flags,
		FeatureCompat:        sb.FeatureCompat,
		FeatureROCompat:      sb.FeatureROCompat,
		SegmentBlock:         summary.Block,
		SegmentSequence:      summary.Seq,
		SegmentCNO:           summary.CNO,
		SegmentNBlocks:       summary.NBlocks,
		SegmentNFinfo:        summary.NFinfo,
		SegmentSumBytes:      summary.SumBytes,
		SegmentChecksumBytes: summary.ChecksumBytes,
		SuperRootBlock:       superRoot.Block,
		SuperRootBytes:       superRoot.Bytes,
		SuperRootFlags:       superRoot.Flags,
	}
	info.SuperblockCtime, info.HasSuperblockCtime = optionalTime(sb.Ctime)
	info.SuperblockMtime, info.HasSuperblockMtime = optionalTime(sb.Mtime)
	info.SuperblockWtime, info.HasSuperblockWtime = optionalTime(sb.Wtime)
	info.LastCheck, info.HasLastCheck = optionalTime(sb.Lastcheck)
	info.SegmentCreate, info.HasSegmentCreate = optionalTime(summary.Create)
	info.SuperRootNongcCtime, info.HasSuperRootNongcCtime = optionalTime(superRoot.NongcCtime)
	return info
}

func optionalTime(seconds *int64) (time.Time, bool) {
	if seconds == nil {
		return time.Time{}, false
	}
	return time.Unix(*seconds, 0).UTC(), true
}

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// Summary returns the parsed newest segment summary.
func (v *Volume) Summary() *Summary { return v.summary }

// SuperRoot returns the newest checkpoint's metadata inodes.
func (v *Volume) SuperRoot() *SuperRoot { return v.superRoot }

// BlockSize returns the volume's block size.
func (v *Volume) BlockSize() uint32 { return v.superblock.BlockSize }

func (v *Volume) newDat() (*Dat, error) { return NewDat(v.superRoot.Dat) }

func (v *Volume) inode(number uint64) (*Inode, error) {
	ifile, err := NewIfile(v.superRoot.Ifile)
	if err != nil {
		return nil, err
	}
	return ifile.ReadInode(v.superblock, v.source, number)
}

func (v *Volume) fileSourceWithDat(dat *Dat, inode *Inode, id source.ID) (*Nilfs2FileSource, error) {
	return newNilfs2FileSource(id, v.source, v.superblock, inode, dat)
}

type directoryListing struct {
	entries       []DirEntry
	blocks        uint64
	extentBlocks  uint64
	extentRecords uint64
}

func (v *Volume) directoryListing(inode *Inode, dat *Dat) (*directoryListing, error) {
	if !inode.Kind.IsDirectory() {
		return nil, corruptf("inode %d is a %s, not a directory", inode.Number(), inode.Kind.Label())
	}
	if inode.Size > MaxDirectoryBytes {
		return nil, corruptf("directory inode declares %d bytes, more than the %d-byte cap",
			inode.Size, MaxDirectoryBytes)
	}
	file, err := v.fileSourceWithDat(dat, inode, source.ID(v.fileID.Add(1)))
	if err != nil {
		return nil, err
	}
	bytes := make([]byte, int(inode.Size))
	if err := source.ReadExactAt(file, 0, bytes); err != nil {
		return nil, err
	}
	entries, err := ParseDirectory(bytes, int(v.superblock.BlockSize), inode.Size, "a directory")
	if err != nil {
		return nil, err
	}
	blocks := inode.Size / uint64(v.superblock.BlockSize)
	if inode.Size%uint64(v.superblock.BlockSize) != 0 {
		blocks++
	}
	return &directoryListing{
		entries:       entries,
		blocks:        blocks,
		extentBlocks:  file.ExtentBlocksRead(),
		extentRecords: file.ExtentRecords(),
	}, nil
}

// lookup resolves one name in a directory inode.
func (v *Volume) lookup(directory uint64, name string) (*DirEntry, error) {
	inode, err := v.inode(directory)
	if err != nil {
		return nil, err
	}
	dat, err := v.newDat()
	if err != nil {
		return nil, err
	}
	listing, err := v.directoryListing(inode, dat)
	if err != nil {
		return nil, err
	}
	for index := range listing.entries {
		if listing.entries[index].Name == name {
			return &listing.entries[index], nil
		}
	}
	return nil, nil
}

// LookupPath resolves a path to an inode number. The bool is false when a
// component does not exist.
func (v *Volume) LookupPath(path string) (uint64, bool, error) {
	current := RootInode
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			parent := RootInode
			entry, err := v.lookup(current, "..")
			if err != nil {
				return 0, false, err
			}
			if entry != nil && entry.Inode != 0 {
				parent = entry.Inode
			}
			current = parent
			continue
		}
		entry, err := v.lookup(current, component)
		if err != nil {
			return 0, false, err
		}
		if entry == nil {
			return 0, false, nil
		}
		current = entry.Inode
	}
	return current, true, nil
}

func (v *Volume) entryFromInode(dat *Dat, name, path string, inode *Inode) (Entry, error) {
	entry := Entry{
		Name:      name,
		Path:      path,
		Inode:     inode.Number(),
		IsDir:     inode.Kind.IsDirectory(),
		IsFile:    inode.Kind.IsFile(),
		IsSymlink: inode.Kind.IsSymlink(),
		Kind:      inode.Kind.Label(),
		Mode:      inode.Mode,
		UID:       inode.UID,
		GID:       inode.GID,
		Links:     inode.Links,
		Size:      inode.Size,
	}
	entry.Atime, entry.HasAtime = optionalTime(inode.Accessed)
	entry.Ctime, entry.HasCtime = optionalTime(inode.Changed)
	entry.Mtime, entry.HasMtime = optionalTime(inode.Modified)

	switch {
	case inode.Kind.IsFile():
		file, err := v.fileSourceWithDat(dat, inode, source.ID(v.fileID.Add(1)))
		if err != nil {
			return entry, err
		}
		entry.Allocated = file.AllocatedBytes()
		entry.AllocatedKnown = true
	case inode.Kind.IsSymlink() && inode.Inline != nil:
		entry.Allocated = 0
		entry.AllocatedKnown = true
		entry.SymlinkTarget = inode.InlineText()
	case inode.Kind.IsSymlink():
		file, err := v.fileSourceWithDat(dat, inode, source.ID(v.fileID.Add(1)))
		if err != nil {
			return entry, err
		}
		entry.Allocated = file.AllocatedBytes()
		entry.AllocatedKnown = true
		target, err := readLinkTarget(file, inode.Size)
		if err != nil {
			return entry, err
		}
		entry.SymlinkTarget = target
	}
	return entry, nil
}

func readLinkTarget(file *Nilfs2FileSource, size uint64) (string, error) {
	if size > MaxSymlinkBytes {
		return "", unsupportedf("a %d-byte symbolic-link target, above the %d-byte limit", size, MaxSymlinkBytes)
	}
	if size > uint64(maxInt()) {
		return "", corruptf("the symbolic-link target length does not fit in memory")
	}
	bytes := make([]byte, int(size))
	if _, err := file.readAt(0, bytes); err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.inode(number)
	if err != nil {
		return nil, err
	}
	dat, err := v.newDat()
	if err != nil {
		return nil, err
	}
	name := pathName(path)
	clean := cleanPath(path)
	if number == RootInode {
		name = "/"
		clean = "/"
	}
	entry, err := v.entryFromInode(dat, name, clean, inode)
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// ListDir lists a directory's entries, excluding "." and "..".
func (v *Volume) ListDir(path string) ([]Entry, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.inode(number)
	if err != nil {
		return nil, err
	}
	if !inode.Kind.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	dat, err := v.newDat()
	if err != nil {
		return nil, err
	}
	listing, err := v.directoryListing(inode, dat)
	if err != nil {
		return nil, err
	}
	base := cleanPath(path)
	if number == RootInode {
		base = "/"
	}
	out := make([]Entry, 0, len(listing.entries))
	for _, dirEntry := range listing.entries {
		if dirEntry.Name == "." || dirEntry.Name == ".." || dirEntry.Inode == 0 {
			continue
		}
		child, err := v.inode(dirEntry.Inode)
		if err != nil {
			return nil, err
		}
		childPath := "/" + dirEntry.Name
		if base != "/" {
			childPath = base + "/" + dirEntry.Name
		}
		entry, err := v.entryFromInode(dat, dirEntry.Name, childPath, child)
		if err != nil {
			return nil, err
		}
		entry.ParentInode = number
		out = append(out, entry)
	}
	return out, nil
}

// OpenFile opens the file named by path as a byte source. A fast symbolic link
// returns its inode-embedded target; a slow symbolic link returns its
// block-mapped stream. Directories and special files have no readable stream.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.inode(number)
	if err != nil {
		return nil, err
	}
	if inode.Kind.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	id := source.ID(v.fileID.Add(1))
	if inode.Kind.IsSymlink() && inode.Inline != nil {
		return source.NewMemorySourceWithImage(id, v.source.ImageID(), append([]byte(nil), inode.Inline...)), nil
	}
	if inode.Kind != KindFile && inode.Kind != KindSymlink {
		return nil, unsupportedf("inode %d is a %s, which has no readable data stream", number, inode.Kind.Label())
	}
	dat, err := v.newDat()
	if err != nil {
		return nil, err
	}
	file, err := v.fileSourceWithDat(dat, inode, id)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// SymlinkTarget returns the target of the symbolic link named by path.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.inode(number)
	if err != nil {
		return "", err
	}
	if !inode.Kind.IsSymlink() {
		return "", fmt.Errorf("%w: inode %d", ErrNotSymlink, number)
	}
	if inode.Inline != nil {
		return inode.InlineText(), nil
	}
	dat, err := v.newDat()
	if err != nil {
		return "", err
	}
	file, err := v.fileSourceWithDat(dat, inode, source.ID(v.fileID.Add(1)))
	if err != nil {
		return "", err
	}
	return readLinkTarget(file, inode.Size)
}

func (v *Volume) classify(stats *WalkStats, err error) {
	switch {
	case err == nil:
	case errors.Is(err, source.ErrUnsupported):
		stats.Refusals++
	case errors.Is(err, source.ErrCorrupt):
		stats.Malformed++
	}
}

func (stats *WalkStats) pushWarning(message string) {
	if len(stats.Warnings) < WarningCap {
		stats.Warnings = append(stats.Warnings, message)
	} else {
		stats.WarningsDropped++
	}
}

type walkDirectory struct {
	number uint64
	inode  *Inode
}

// Walk reads every directory reachable from the root and counts what it finds.
// A directory reached by a second name is listed but not walked twice.
func (v *Volume) Walk() (WalkStats, error) {
	var stats WalkStats
	dat, err := v.newDat()
	if err != nil {
		return stats, err
	}
	ifile, err := NewIfile(v.superRoot.Ifile)
	if err != nil {
		return stats, err
	}
	root, err := ifile.ReadInode(v.superblock, v.source, RootInode)
	stats.NodesRead++
	stats.BlocksRead++
	if err != nil {
		return stats, err
	}
	if !root.Kind.IsDirectory() {
		return stats, corruptf("the root inode %d is a %s, not a directory", RootInode, root.Kind.Label())
	}
	stats.Nodes = 1
	stats.Directories = 1
	visited := map[uint64]bool{RootInode: true}
	queue := []walkDirectory{{number: RootInode, inode: root}}

	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		stats.Lookups++
		listing, err := v.directoryListing(directory.inode, dat)
		if err != nil {
			stats.Unreadable++
			v.classify(&stats, err)
			stats.pushWarning("directory inode " + u64Text(directory.number) + ": " + err.Error())
			continue
		}
		stats.BlocksRead += listing.blocks
		stats.ExtentBlocks += listing.extentBlocks
		stats.ExtentRecords += listing.extentRecords

		for _, entry := range listing.entries {
			if entry.Name == "." || entry.Name == ".." || entry.Inode == 0 {
				continue
			}
			child, err := ifile.ReadInode(v.superblock, v.source, entry.Inode)
			stats.NodesRead++
			stats.BlocksRead++
			if err != nil {
				stats.Undecodable++
				v.classify(&stats, err)
				stats.pushWarning("inode " + u64Text(entry.Inode) + " (" + entry.Name + "): " + err.Error())
				continue
			}
			if stats.Nodes >= MaxNodes {
				return stats, corruptf("the image names more than %d entries", MaxNodes)
			}
			stats.Nodes++

			// Kind counters are recorded whether or not the data stream decodes,
			// exactly as the walk records the node itself.
			switch {
			case child.Kind.IsDirectory():
				stats.Directories++
				if !visited[entry.Inode] {
					visited[entry.Inode] = true
					queue = append(queue, walkDirectory{number: entry.Inode, inode: child})
				} else {
					stats.DirectoryLoops++
				}
			case child.Kind.IsFile():
				stats.Files++
			case child.Kind.IsSymlink():
				stats.Symlinks++
			default:
				stats.Other++
			}

			undecodable := false
			if child.Kind.IsFile() {
				file, err := v.fileSourceWithDat(dat, child, source.ID(v.fileID.Add(1)))
				if err != nil {
					undecodable = true
					v.classify(&stats, err)
					stats.pushWarning("file " + entry.Name + ": " + err.Error())
				} else {
					stats.ExtentBlocks += file.ExtentBlocksRead()
					stats.ExtentRecords += file.ExtentRecords()
					stats.BlocksRead += file.ExtentBlocksRead()
				}
			} else if child.Kind.IsSymlink() && child.Inline == nil {
				file, err := v.fileSourceWithDat(dat, child, source.ID(v.fileID.Add(1)))
				if err != nil {
					undecodable = true
					v.classify(&stats, err)
					stats.pushWarning("symlink " + entry.Name + ": " + err.Error())
				} else {
					stats.ExtentBlocks += file.ExtentBlocksRead()
					stats.ExtentRecords += file.ExtentRecords()
					stats.BlocksRead += file.ExtentBlocksRead()
					if child.Size <= MaxSymlinkBytes {
						target := make([]byte, int(child.Size))
						if _, err := file.readAt(0, target); err != nil {
							undecodable = true
							v.classify(&stats, err)
							stats.pushWarning("symlink " + entry.Name + ": " + err.Error())
						}
					} else {
						stats.pushWarning("symlink " + entry.Name + ": target is more than the " +
							u64Text(MaxSymlinkBytes) + "-byte inline cap; open the link stream instead")
					}
				}
			}
			if undecodable {
				stats.Undecodable++
			}
		}
	}
	return stats, nil
}

func pathName(path string) string {
	clean := strings.TrimRight(path, "/")
	if clean == "" {
		return "/"
	}
	if index := strings.LastIndexByte(clean, '/'); index >= 0 {
		return clean[index+1:]
	}
	return clean
}

func cleanPath(path string) string {
	var parts []string
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		parts = append(parts, component)
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}
