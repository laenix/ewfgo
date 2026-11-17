// Package ufs reads UFS1 and UFS2 (the Berkeley Fast File System) volumes,
// read-only, from a source.ByteSource.
//
// It is a port of the Rust forensic-core UFS reader. Both generations share
// one superblock layout and one directory format; they differ in the inode and
// the width of a block pointer:
//
//	superblock at 64 KiB (UFS2), 8 KiB (UFS1), 0 or 256 KiB   superblock.go
//	  -> cylinder groups, each with its own header block     cgroup.go
//	    -> inode tables inside each group                    inode.go
//	      -> direct + 3-level indirect block pointers        blockmap.go
//	        -> 512-byte directory chunks                     dir.go
//	          -> file data as a byte source                  file.go
//	            -> freed inodes and reclaimed names          deleted.go
//
// Every read returns real bytes or an explicit error. Holes are the only zero
// bytes this reader manufactures, and they are holes a zero block pointer
// declares; they stay visible as source.RangeHole in provenance.
//
// Deliberately unported branches, each refused or reported rather than
// silently guessed at:
//
//   - Soft Updates and the SU+J journal are not replayed: an unclean volume is
//     read as it sits on disk and Info reports the mount state;
//   - extended attributes (ufs_extattr), ACLs and UFS2 extended-attribute
//     blocks are not decoded;
//   - the 4.2BSD inode layout is refused by name (ErrUnsupported);
//   - metadata check-hash kinds beyond CK_SUPERBLOCK, CK_CYLGRP and CK_INODE
//     are refused by name;
//   - a volume whose geometry does not self-check is refused, never guessed
//     at.
//
// Deleted names are recovered only in the forms the format leaves behind: a
// stale record whose inode slot is free, and a freed record still legible in
// the slack behind a grown d_reclen. A name is attached to an inode only when
// the bitmap proves the slot free and the residue passes the structural gate.
package ufs

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Reader bounds.
const (
	// MaxPathDirectories is the directories one path search may visit.
	MaxPathDirectories = 100_000
	// MaxSymlinkBytes is the longest symbolic-link target this reader reads
	// out of blocks.
	MaxSymlinkBytes = 65_536
	// MaxDeletedDirectories is the live directories a deleted scan may read.
	MaxDeletedDirectories = 65_536
)

// Info is a volume's report.
type Info struct {
	Kind  string
	Label string
	// Offset is where the superblock was found.
	Offset    uint64
	BigEndian bool

	BlockSize        uint32
	FragSize         uint32
	Frag             uint32
	InodeSize        uint32
	InodesPerBlock   uint32
	PointersPerBlock uint32
	CGSize           uint32
	Groups           uint32
	InodesPerGroup   uint32
	FragsPerGroup    uint32
	SizeFrags        uint64
	DSizeFrags       uint64
	VolumeBytes      uint64

	VolumeName string
	MountPoint string
	ID         [2]uint32

	Flags         int32
	FlagNames     []string
	Clean         bool
	NeedsFsck     bool
	SUJ           bool
	Metackhash    uint32
	MaxSymlinkLen int32
	OldInodeFmt   int32

	SuperblockOffset uint64
	FloppyLayout     bool
}

// Entry is one file or directory in a volume.
type Entry struct {
	Name        string
	Path        string
	Inode       uint32
	ParentInode uint32

	IsDir     bool
	IsFile    bool
	IsSymlink bool
	FileType  string

	Size  uint64
	Mode  uint16
	UID   uint32
	GID   uint32
	Links uint16

	Atime           time.Time
	Mtime           time.Time
	Ctime           time.Time
	HasCreationTime bool
	CreationTime    time.Time

	// SymlinkTarget is the recorded target for a symbolic link.
	SymlinkTarget string

	// Deleted marks a stale directory record whose inode slot is free. UFS
	// merges a removed name into its predecessor, so this residue is the only
	// deleted name a live directory listing can expose.
	Deleted bool
}

// VolumeStats is what a walk of the whole tree found.
type VolumeStats struct {
	Directories uint64
	Files       uint64
	Symlinks    uint64
	// Other counts sockets, devices, FIFOs and unknown modes.
	Other uint64
	// Entries counts live names, excluding "." and ".." and stale names.
	Entries uint64
	// DeletedNames counts stale records whose inode slot is cleared.
	DeletedNames uint64
	// Unreadable counts names whose inode could not be read.
	Unreadable uint64
	// UntiledBlocks counts directory chunks that did not tile.
	UntiledBlocks uint64
	// Whiteouts counts union-mount whiteouts.
	Whiteouts uint64
	// FreedBytes counts bytes inside freed directory records.
	FreedBytes uint64
}

type dirStats struct {
	Untiled    uint64
	Whiteouts  uint64
	FreedBytes uint64
}

// Volume is an opened UFS1 or UFS2 volume.
type Volume struct {
	source     source.ByteSource
	superblock *Superblock
	fileID     atomic.Uint64
}

// Detect reports whether src looks like a UFS volume without mounting it. A
// magic at one of the four offsets in either byte order is not enough by
// itself: the geometry is validated too.
func Detect(src source.ByteSource) (bool, error) {
	sb, err := ReadSuperblock(src)
	if err != nil {
		return false, err
	}
	return sb != nil, nil
}

// Open finds a superblock, validates its geometry, and proves the volume by
// reading cylinder group 0 and the root inode.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := ReadSuperblock(src)
	if err != nil {
		return nil, err
	}
	if sb == nil {
		return nil, corruptf("no UFS1 or UFS2 superblock at any of the four standard offsets")
	}
	volume := &Volume{source: src, superblock: sb}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	if err := volume.probe(); err != nil {
		return nil, err
	}
	return volume, nil
}

// Info returns the volume's report.
func (v *Volume) Info() Info {
	sb := v.superblock
	return Info{
		Kind:             sb.Kind(),
		Label:            sb.Label(),
		Offset:           sb.Offset,
		BigEndian:        sb.Endian == BigEndian,
		BlockSize:        sb.BSize,
		FragSize:         sb.FSize,
		Frag:             sb.Frag,
		InodeSize:        uint32(sb.InodeSize()),
		InodesPerBlock:   sb.InoPB,
		PointersPerBlock: sb.NIndir,
		CGSize:           sb.CGSize,
		Groups:           sb.NCG,
		InodesPerGroup:   sb.IPG,
		FragsPerGroup:    sb.FPG,
		SizeFrags:        sb.SizeFrags,
		DSizeFrags:       sb.DSizeFrags,
		VolumeBytes:      sb.VolumeLen(),
		VolumeName:       sb.VolumeName,
		MountPoint:       sb.MountPoint,
		ID:               sb.ID,
		Flags:            sb.Flags,
		FlagNames:        sb.FlagNames(),
		Clean:            sb.IsClean(),
		NeedsFsck:        sb.NeedsFsck(),
		SUJ:              sb.HasSoftUpdatesJournal(),
		Metackhash:       sb.Metackhash,
		MaxSymlinkLen:    sb.MaxSymlinkLen,
		OldInodeFmt:      sb.OldInodeFmt,
		SuperblockOffset: sb.Offset,
		FloppyLayout:     sb.Offset == SBLOCK_FLOPPY && sb.Version == UFS1,
	}
}

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// Kind returns "ufs1" or "ufs2".
func (v *Volume) Kind() string { return v.superblock.Kind() }

// Label returns "UFS1" or "UFS2".
func (v *Volume) Label() string { return v.superblock.Label() }

// BlockSize returns fs_bsize.
func (v *Volume) BlockSize() uint32 { return v.superblock.BSize }

// FragSize returns fs_fsize.
func (v *Volume) FragSize() uint32 { return v.superblock.FSize }

// InodeSize returns the on-disk inode size.
func (v *Volume) InodeSize() int { return v.superblock.InodeSize() }

// RootInode returns the fixed root inode number, 2.
func (v *Volume) RootInode() uint32 { return RootInode }

// VolumeLen returns the bytes the superblock declares.
func (v *Volume) VolumeLen() uint64 { return v.superblock.VolumeLen() }

// VolumeName returns fs_volname.
func (v *Volume) VolumeName() string { return v.superblock.VolumeName }

// MountPoint returns fs_fsmnt.
func (v *Volume) MountPoint() string { return v.superblock.MountPoint }

// IsClean reports whether the last unmount was clean.
func (v *Volume) IsClean() bool { return v.superblock.IsClean() }

// NeedsFsck reports whether the volume is flagged for repair.
func (v *Volume) NeedsFsck() bool { return v.superblock.NeedsFsck() }

// HasSoftUpdatesJournal reports whether SU+J was in use. The journal is not
// replayed.
func (v *Volume) HasSoftUpdatesJournal() bool { return v.superblock.HasSoftUpdatesJournal() }

// CheckHash verifies the superblock's own check hash when one is maintained.
func (v *Volume) CheckHash() (maintained, valid bool, err error) {
	return v.superblock.CheckHash(v.source)
}

// CylinderGroup reads one cylinder group's header.
func (v *Volume) CylinderGroup(index uint64) (*CylinderGroup, error) {
	return ReadCylinderGroup(v.source, v.superblock, index)
}

// InodeBitmap reads one cylinder group's inode bitmap.
func (v *Volume) InodeBitmap(index uint64) (*InodeBitmap, error) {
	return ReadInodeBitmap(v.source, v.superblock, index)
}

// FreeSpace scans the cylinder-group fragment bitmaps.
func (v *Volume) FreeSpace() (*FreeSpace, error) {
	return freeSpace(v.source, v.superblock)
}

// ReadInodeBytes reads one inode's on-disk bytes.
func (v *Volume) ReadInodeBytes(number uint32) ([]byte, error) {
	offset, err := v.superblock.InodeOffset(number)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, v.superblock.InodeSize())
	if err := source.ReadExactAt(v.source, offset, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Inode reads one inode by number.
func (v *Volume) Inode(number uint32) (*Inode, error) {
	raw, err := v.ReadInodeBytes(number)
	if err != nil {
		return nil, err
	}
	return ParseInode(number, raw, v.superblock.Version, v.superblock.Endian)
}

// InodeCheckHash verifies an inode's check hash when the volume maintains one.
func (v *Volume) InodeCheckHash(number uint32) (maintained, valid bool, err error) {
	if !v.superblock.Checks(CK_INODE) {
		return false, false, nil
	}
	raw, err := v.ReadInodeBytes(number)
	if err != nil {
		return true, false, err
	}
	if v.superblock.Endian.U16(raw, 0) == 0 {
		return false, false, nil
	}
	stored := v.superblock.Endian.U32(raw, 244)
	clear(raw[244:248])
	return true, foundation.CRC32C(raw) == stored, nil
}

// ExtentMap resolves an inode's data runs.
func (v *Volume) ExtentMap(inode *Inode) (*ExtentMap, error) {
	if inode.IsFastSymlink(v.superblock.MaxSymlinkLen) {
		return nil, unsupportedf("inode %d stores its target inside the inode", inode.Number)
	}
	return BuildExtentMap(v.source, v.superblock, inode)
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
	inode, err := v.Inode(number)
	if err != nil {
		return "", err
	}
	if !inode.IsSymlink() {
		return "", fmt.Errorf("%w: inode %d", ErrNotSymlink, number)
	}
	return v.symlinkTarget(inode)
}

func (v *Volume) symlinkTarget(inode *Inode) (string, error) {
	if inode.IsFastSymlink(v.superblock.MaxSymlinkLen) {
		end := inode.Size
		if end > uint64(len(inode.InlineLink())) {
			end = uint64(len(inode.InlineLink()))
		}
		return cString(inode.InlineLink()[:end]), nil
	}
	mapData, err := BuildExtentMap(v.source, v.superblock, inode)
	if err != nil {
		return "", err
	}
	length := mapData.Len()
	if length > MaxSymlinkBytes {
		length = MaxSymlinkBytes
	}
	raw := make([]byte, int(length))
	if _, err := mapData.ReadAt(v.source, 0, raw); err != nil {
		return "", err
	}
	return cString(raw), nil
}

// ReadDir lists a directory's live records in stored order. Stale records are
// included; use ReadDirWithResidue to see slack residue as well.
func (v *Volume) ReadDir(directory uint32) ([]DirRecord, error) {
	entries, _, _, err := v.readDirBlocks(directory)
	return entries, err
}

// ReadDirWithResidue lists a directory together with the records still legible
// in the slack behind its live records.
func (v *Volume) ReadDirWithResidue(directory uint32) ([]DirRecord, []SlackRecord, error) {
	entries, slack, _, err := v.readDirBlocks(directory)
	return entries, slack, err
}

func (v *Volume) readDirBlocks(directory uint32) ([]DirRecord, []SlackRecord, dirStats, error) {
	var stats dirStats
	inode, err := v.Inode(directory)
	if err != nil {
		return nil, nil, stats, err
	}
	if !inode.IsDirectory() {
		return nil, nil, stats, corruptf("inode %d is not a directory", directory)
	}
	if err := CheckDirSize(inode.Size); err != nil {
		return nil, nil, stats, err
	}
	var entries []DirRecord
	var slack []SlackRecord
	if inode.Size == 0 {
		return entries, slack, stats, nil
	}
	mapData, err := BuildExtentMap(v.source, v.superblock, inode)
	if err != nil {
		return nil, nil, stats, err
	}
	blockSize := v.superblock.BlockSize()
	oldFormat := UsesOldFormat(v.superblock.MaxSymlinkLen)
	buffer := make([]byte, int(blockSize))
	blocks := inode.Size / blockSize
	if inode.Size%blockSize != 0 {
		blocks++
	}
	for index := uint64(0); index < blocks; index++ {
		offset := index * blockSize
		length := inode.Size - offset
		if length > blockSize {
			length = blockSize
		}
		view := buffer[:int(length)]
		clear(view)
		if _, err := mapData.ReadAt(v.source, offset, view); err != nil {
			// One unreadable block must not hide the rest of the directory.
			stats.Untiled++
			continue
		}
		// A record may not cross a 512-byte chunk and each chunk is written as
		// one sector, so damage in one chunk says nothing about its neighbours.
		for start := 0; start < len(view); {
			end := start + DirBlockSize
			if end > len(view) {
				end = len(view)
			}
			parsed := ParseDirBlock(view[start:end], offset+uint64(start), v.superblock.Endian, oldFormat)
			if !parsed.Tiled {
				stats.Untiled++
			}
			stats.Whiteouts += parsed.Whiteouts
			stats.FreedBytes += parsed.FreedBytes
			entries = append(entries, parsed.Entries...)
			slack = append(slack, parsed.Slack...)
			start = end
		}
	}
	return entries, slack, stats, nil
}

// lookup finds one live name in a directory. A record whose inode is cleared
// is a deleted name, not a live file, and is skipped.
func (v *Volume) lookup(directory uint32, name string) (*DirRecord, error) {
	entries, err := v.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for index := range entries {
		if entries[index].Name != name {
			continue
		}
		inode, err := v.Inode(entries[index].Inode)
		if err != nil {
			// A record that cannot be read is not provably stale; Rust's lookup
			// returns it rather than hiding the name.
			return &entries[index], nil
		}
		if inode.IsCleared() {
			continue
		}
		return &entries[index], nil
	}
	return nil, nil
}

// LookupPath resolves an absolute or root-relative path to an inode number.
// found is false when a component does not exist.
func (v *Volume) LookupPath(path string) (number uint32, found bool, err error) {
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

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.Inode(number)
	if err != nil {
		return nil, err
	}
	name := pathName(path)
	clean := cleanPath(path)
	if number == RootInode {
		name = "/"
		clean = "/"
	}
	entry := entryFromInode(name, clean, inode)
	if inode.IsSymlink() {
		target, err := v.symlinkTarget(inode)
		if err != nil {
			return nil, err
		}
		entry.SymlinkTarget = target
	}
	return &entry, nil
}

// ListDir lists a directory's entries, excluding "." and "..". A stale record
// is returned with Deleted set; Stat and LookupPath skip it.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.Inode(number)
	if err != nil {
		return nil, err
	}
	if !inode.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	entries, _, err := v.ReadDirWithResidue(number)
	if err != nil {
		return nil, err
	}
	base := cleanPath(path)
	out := make([]Entry, 0, len(entries))
	for _, record := range entries {
		if record.Name == "." || record.Name == ".." {
			continue
		}
		child, err := v.Inode(record.Inode)
		if err != nil {
			return nil, err
		}
		childPath := "/" + record.Name
		if base != "/" {
			childPath = base + "/" + record.Name
		}
		if child.IsCleared() {
			entry := entryFromInode(record.Name, childPath, child)
			entry.Deleted = true
			entry.ParentInode = number
			out = append(out, entry)
			continue
		}
		entry := entryFromInode(record.Name, childPath, child)
		entry.ParentInode = number
		if child.IsSymlink() {
			target, err := v.symlinkTarget(child)
			if err != nil {
				return nil, err
			}
			entry.SymlinkTarget = target
		}
		out = append(out, entry)
	}
	return out, nil
}

// OpenFile opens the file named by path as a byte source.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	number, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.Inode(number)
	if err != nil {
		return nil, err
	}
	if inode.IsCleared() {
		return nil, corruptf("inode %d is cleared", number)
	}
	if inode.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	if inode.IsFastSymlink(v.superblock.MaxSymlinkLen) {
		return nil, unsupportedf("inode %d stores its target inside the inode; use SymlinkTarget", number)
	}
	mapData, err := BuildExtentMap(v.source, v.superblock, inode)
	if err != nil {
		return nil, err
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.source, mapData, number), nil
}

// PathOf finds the shallowest path that names an inode. The search runs
// breadth-first from the root because only directories hold "..".
func (v *Volume) PathOf(number uint32) (path string, found bool, err error) {
	if number == RootInode {
		return "/", true, nil
	}
	type item struct {
		inode uint32
		path  string
	}
	queue := []item{{RootInode, ""}}
	seen := map[uint32]bool{RootInode: true}
	visited := 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		visited++
		if visited > MaxPathDirectories {
			return "", false, nil
		}
		entries, err := v.ReadDir(current.inode)
		if err != nil {
			return "", false, err
		}
		for _, record := range entries {
			if record.Name == "." || record.Name == ".." {
				continue
			}
			childPath := joinPath(current.path, record.Name)
			if record.Inode == number {
				return childPath, true, nil
			}
			inode, err := v.Inode(record.Inode)
			if err != nil {
				continue
			}
			if inode.IsDirectory() && !seen[record.Inode] {
				seen[record.Inode] = true
				queue = append(queue, item{record.Inode, childPath})
			}
		}
	}
	return "", false, nil
}

// Stats counts the whole tree.
func (v *Volume) Stats() (VolumeStats, error) {
	var stats VolumeStats
	pending := []uint32{RootInode}
	seen := map[uint32]bool{RootInode: true}
	for len(pending) > 0 {
		directory := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		stats.Directories++
		entries, _, block, err := v.readDirBlocks(directory)
		if err != nil {
			return stats, err
		}
		stats.UntiledBlocks += block.Untiled
		stats.Whiteouts += block.Whiteouts
		stats.FreedBytes += block.FreedBytes
		for _, record := range entries {
			if record.Name == "." || record.Name == ".." {
				continue
			}
			inode, err := v.Inode(record.Inode)
			if err != nil {
				stats.Unreadable++
				continue
			}
			if inode.IsCleared() {
				stats.DeletedNames++
				continue
			}
			stats.Entries++
			switch inode.FileType() {
			case InodeDirectory:
				if !seen[record.Inode] {
					seen[record.Inode] = true
					pending = append(pending, record.Inode)
				}
			case InodeRegular:
				stats.Files++
			case InodeSymlink:
				stats.Symlinks++
			default:
				stats.Other++
			}
		}
	}
	return stats, nil
}

func (v *Volume) probe() error {
	if _, err := v.CylinderGroup(0); err != nil {
		return err
	}
	root, err := v.Inode(RootInode)
	if err != nil {
		return err
	}
	if !root.IsDirectory() {
		return corruptf("inode 2 is not a directory")
	}
	return nil
}

func entryFromInode(name, path string, inode *Inode) Entry {
	entry := Entry{
		Name:      name,
		Path:      path,
		Inode:     inode.Number,
		IsDir:     inode.IsDirectory(),
		IsFile:    inode.IsRegular(),
		IsSymlink: inode.IsSymlink(),
		FileType:  inode.FileType().Name(),
		Size:      inode.Size,
		Mode:      inode.Mode,
		UID:       inode.UID,
		GID:       inode.GID,
		Links:     inode.Links,
		Atime:     timeFrom(inode.AccessTime),
		Mtime:     timeFrom(inode.ModificationTime),
		Ctime:     timeFrom(inode.ChangeTime),
	}
	if inode.CreationTime != nil {
		entry.HasCreationTime = true
		entry.CreationTime = timeFrom(*inode.CreationTime)
	}
	return entry
}

func timeFrom(value UfsTime) time.Time {
	return time.Unix(value.Seconds, int64(value.Nanos)).UTC()
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
	parts := make([]string, 0, 4)
	for _, component := range strings.Split(path, "/") {
		switch component {
		case "", ".":
			continue
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		default:
			parts = append(parts, component)
		}
	}
	return "/" + strings.Join(parts, "/")
}

func joinPath(base, name string) string {
	if base == "" || base == "/" {
		return "/" + name
	}
	return base + "/" + name
}

func cString(raw []byte) string {
	for index, value := range raw {
		if value == 0 {
			return lossyUTF8(raw[:index])
		}
	}
	return lossyUTF8(raw)
}
