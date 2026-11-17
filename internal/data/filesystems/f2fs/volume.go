package f2fs

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxPathDepth is how many parent steps a path walk may follow.
const MaxPathDepth = 512

// VolumeStats is what a walk of the whole tree found.
type VolumeStats struct {
	Directories        uint64
	Files              uint64
	Symlinks           uint64
	Other              uint64
	Entries            uint64
	UnreadableBlocks   uint64
	FileTypeMismatches uint64
	UnreadableInodes   uint64
}

// Info is the volume's report.
type Info struct {
	VersionMajor uint16
	VersionMinor uint16

	BlockSize          uint32
	BlocksPerSegment   uint32
	SegmentsPerSection uint32
	SectionsPerZone    uint32
	BlockCount         uint64

	SectionCount     uint32
	SegmentCount     uint32
	SegmentCountCkpt uint32
	SegmentCountSIT  uint32
	SegmentCountNAT  uint32
	SegmentCountSSA  uint32
	SegmentCountMain uint32

	Segment0Blkaddr uint32
	CPBlkaddr       uint32
	SITBlkaddr      uint32
	NATBlkaddr      uint32
	SSABlkaddr      uint32
	MainBlkaddr     uint32

	RootIno uint32
	NodeIno uint32
	MetaIno uint32

	CheckpointVersion uint64
	CheckpointFlags   uint32
	CheckpointCopy    int
	UserBlockCount    uint64
	ValidBlockCount   uint64
	ValidNodeCount    uint32
	ValidInodeCount   uint32
	NextFreeNID       uint32
	FreeSegmentCount  uint32
	Clean             bool
	CheckpointError   bool

	FeatureBits uint32
	Features    []string
	VolumeName  string
	UUID        string
}

// Entry is one file or directory in a volume.
type Entry struct {
	Name        string
	Path        string
	Inode       uint32
	ParentInode uint32
	IsDir       bool
	IsSymlink   bool
	Mode        uint16
	Size        uint64
	UID         uint32
	GID         uint32
	Links       uint32

	Atime     time.Time
	Ctime     time.Time
	Mtime     time.Time
	Crtime    time.Time
	HasCrtime bool

	InlineData             bool
	InlineDentry           bool
	Compressed             bool
	CompressAlgorithm      string
	CompressLogClusterSize uint8
	CompressedBlocks       uint64

	// Deleted is set on entries reported by deleted-block recovery.
	Deleted bool
}

// Volume is an opened F2FS volume.
type Volume struct {
	source     source.ByteSource
	superblock *Superblock
	checkpoint *Checkpoint
	nat        *NATTable
	recovery   *Recovery
	fileID     atomic.Uint64
}

// Open opens a volume, proving each layer before returning it.
func Open(src source.ByteSource) (*Volume, error) {
	sb, err := ReadSuperblock(src)
	if err != nil {
		return nil, err
	}
	if err := sb.CheckSupported(); err != nil {
		return nil, err
	}
	if err := sb.CheckLength(src); err != nil {
		return nil, err
	}
	cp, err := ReadCheckpoint(src, sb)
	if err != nil {
		return nil, err
	}
	var recoveryData *Recovery
	if !cp.IsClean() {
		recoveryData, err = recover(src, sb, cp)
		if err != nil {
			return nil, err
		}
	}
	var journal []NATJournalEntry
	if recoveryData != nil {
		journal = recoveryData.NATJournal()
	}
	nat, err := DetectNATWithJournal(src, sb, cp, journal)
	if err != nil {
		return nil, err
	}
	volume := &Volume{
		source:     src,
		superblock: sb,
		checkpoint: cp,
		nat:        nat,
		recovery:   recoveryData,
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	if err := volume.probe(); err != nil {
		return nil, err
	}
	return volume, nil
}

// Info returns the volume's report.
func (v *Volume) Info() Info {
	sb := v.superblock
	cp := v.checkpoint
	uuid := sb.UUID
	return Info{
		VersionMajor:       sb.Major,
		VersionMinor:       sb.Minor,
		BlockSize:          sb.BlockSize,
		BlocksPerSegment:   sb.BlocksPerSegment,
		SegmentsPerSection: sb.SegmentsPerSection,
		SectionsPerZone:    sb.SectionsPerZone,
		BlockCount:         sb.BlockCount,
		SectionCount:       sb.SectionCount,
		SegmentCount:       sb.SegmentCount,
		SegmentCountCkpt:   sb.SegmentCountCkpt,
		SegmentCountSIT:    sb.SegmentCountSIT,
		SegmentCountNAT:    sb.SegmentCountNAT,
		SegmentCountSSA:    sb.SegmentCountSSA,
		SegmentCountMain:   sb.SegmentCountMain,
		Segment0Blkaddr:    sb.Segment0Blkaddr,
		CPBlkaddr:          sb.CPBlkaddr,
		SITBlkaddr:         sb.SITBlkaddr,
		NATBlkaddr:         sb.NATBlkaddr,
		SSABlkaddr:         sb.SSABlkaddr,
		MainBlkaddr:        sb.MainBlkaddr,
		RootIno:            sb.RootIno,
		NodeIno:            sb.NodeIno,
		MetaIno:            sb.MetaIno,
		CheckpointVersion:  cp.Version,
		CheckpointFlags:    cp.Flags,
		CheckpointCopy:     cp.Copy,
		UserBlockCount:     cp.UserBlockCount,
		ValidBlockCount:    cp.ValidBlockCount,
		ValidNodeCount:     cp.ValidNodeCount,
		ValidInodeCount:    cp.ValidInodeCount,
		NextFreeNID:        cp.NextFreeNID,
		FreeSegmentCount:   cp.FreeSegmentCount,
		Clean:              cp.IsClean(),
		CheckpointError:    cp.HadError(),
		FeatureBits:        sb.Feature,
		Features:           sb.FeatureNames(),
		VolumeName:         sb.Label,
		UUID: fmt.Sprintf("%x-%x-%x-%x-%x",
			uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]),
	}
}

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed superblock.
func (v *Volume) Superblock() *Superblock { return v.superblock }

// Checkpoint returns the chosen checkpoint.
func (v *Volume) Checkpoint() *Checkpoint { return v.checkpoint }

// NAT returns the node address table.
func (v *Volume) NAT() *NATTable { return v.nat }

// Recovery returns the journal replay, when the checkpoint was not clean.
func (v *Volume) Recovery() *Recovery { return v.recovery }

// BlockSize returns the volume's block size.
func (v *Volume) BlockSize() uint32 { return v.superblock.BlockSize }

// UUID returns the volume's UUID bytes.
func (v *Volume) UUID() [16]byte { return v.superblock.UUID }

// VolumeName returns the volume label.
func (v *Volume) VolumeName() string { return v.superblock.Label }

// RootIno returns the root inode number.
func (v *Volume) RootIno() uint32 { return v.superblock.RootIno }

// IsClean reports whether the checkpoint marked a clean unmount.
func (v *Volume) IsClean() bool { return v.checkpoint.IsClean() }

// HadError reports whether the checkpoint recorded a write error.
func (v *Volume) HadError() bool { return v.checkpoint.HadError() }

// HasFeature reports whether the volume sets a feature bit.
func (v *Volume) HasFeature(feature uint32) bool {
	return v.superblock.Feature&feature != 0
}

// Inode reads the inode numbered ino.
func (v *Volume) Inode(ino uint32) (*Inode, error) {
	block, err := v.nat.NodeBlock(v.source, ino)
	if err != nil {
		return nil, err
	}
	bytes, err := source.ReadVecAt(v.source, v.superblock.ByteOffset(block), uint64(v.superblock.BlockSize))
	if err != nil {
		return nil, err
	}
	return ParseInode(bytes, v.superblock.BlockSize, ino)
}

// FileMap returns the block map of inode.
func (v *Volume) FileMap(inode *Inode) (*FileMap, error) {
	return NewFileMap(v.source, v.nat, inode)
}

// FileSourceByIno opens ino as a byte source.
func (v *Volume) FileSourceByIno(ino uint32) (*F2fsFileSource, error) {
	inode, err := v.Inode(ino)
	if err != nil {
		return nil, err
	}
	if inode.IsDir() {
		return nil, ErrIsDir
	}
	blockMap, err := v.FileMap(inode)
	if err != nil {
		return nil, err
	}
	id := source.ID(v.fileID.Add(1))
	return NewFileSource(id, blockMap, ino), nil
}

// ReadDir lists a directory in slot order, including "." and "..".
func (v *Volume) ReadDir(directory uint32) ([]DirEntry, error) {
	entries, _, err := v.directory(directory)
	return entries, err
}

func (v *Volume) directory(directory uint32) ([]DirEntry, uint64, error) {
	inode, err := v.Inode(directory)
	if err != nil {
		return nil, 0, err
	}
	if !inode.IsDir() {
		return nil, 0, fmt.Errorf("%w: inode %d is not a directory", ErrNotDir, directory)
	}
	if err := inode.CheckReadable(); err != nil {
		return nil, 0, err
	}
	blockMap, err := v.FileMap(inode)
	if err != nil {
		return nil, 0, err
	}
	blockSize := v.superblock.BlockSize
	size := inode.Size
	var entries []DirEntry
	var unreadable uint64
	buf := make([]byte, blockSize)
	blocks := (size + uint64(blockSize) - 1) / uint64(blockSize)
	for index := uint64(0); index < blocks; index++ {
		offset := index * uint64(blockSize)
		length := size - offset
		if length > uint64(blockSize) {
			length = uint64(blockSize)
		}
		clear(buf)
		if _, err := blockMap.ReadAt(offset, buf[:length]); err != nil {
			unreadable++
			continue
		}
		block, err := ParseDirBlock(buf, blockSize)
		if err != nil {
			unreadable++
			continue
		}
		entries = append(entries, block...)
	}
	return entries, unreadable, nil
}

// Lookup finds one name in directory.  Names compare byte-wise.
func (v *Volume) Lookup(directory uint32, name string) (*DirEntry, error) {
	entries, err := v.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for index := range entries {
		if !IsDot(entries[index].Name) && string(entries[index].Name) == name {
			return &entries[index], nil
		}
	}
	return nil, nil
}

// LookupPath resolves an absolute or root-relative path to an inode number.
// The bool is false when a component does not exist.
func (v *Volume) LookupPath(path string) (uint32, bool, error) {
	root := v.RootIno()
	current := root
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			parent := root
			entry, err := v.Lookup(current, "..")
			if err != nil {
				return 0, false, err
			}
			if entry != nil {
				parent = entry.Ino
			}
			if parent == 0 {
				parent = root
			}
			current = parent
			continue
		}
		entry, err := v.Lookup(current, component)
		if err != nil {
			return 0, false, err
		}
		if entry == nil {
			return 0, false, nil
		}
		current = entry.Ino
	}
	return current, true, nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	ino, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.Inode(ino)
	if err != nil {
		return nil, err
	}
	name := pathName(path)
	if ino == v.RootIno() {
		name = "/"
	}
	entry := v.entryFromInode(name, cleanPath(path, ino == v.RootIno()), inode)
	return &entry, nil
}

// ListDir lists a directory's entries, excluding "." and "..".
func (v *Volume) ListDir(path string) ([]Entry, error) {
	ino, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	directory, err := v.Inode(ino)
	if err != nil {
		return nil, err
	}
	if !directory.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	entries, _, err := v.directory(ino)
	if err != nil {
		return nil, err
	}
	base := cleanPath(path, ino == v.RootIno())
	out := make([]Entry, 0, len(entries))
	for _, dirEntry := range entries {
		if IsDot(dirEntry.Name) {
			continue
		}
		inode, err := v.Inode(dirEntry.Ino)
		if err != nil {
			return nil, err
		}
		childPath := "/" + string(dirEntry.Name)
		if base != "/" {
			childPath = base + "/" + string(dirEntry.Name)
		}
		out = append(out, v.entryFromInode(string(dirEntry.Name), childPath, inode))
	}
	return out, nil
}

// OpenFile opens the file named by path as a byte source.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	ino, found, err := v.LookupPath(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	inode, err := v.Inode(ino)
	if err != nil {
		return nil, err
	}
	if inode.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	}
	blockMap, err := v.FileMap(inode)
	if err != nil {
		return nil, err
	}
	id := source.ID(v.fileID.Add(1))
	return NewFileSource(id, blockMap, ino), nil
}

// PathOf finds an inode's path by following the parent inode recorded in each
// inode.  The bool is false when no name was found.
func (v *Volume) PathOf(ino uint32) (string, bool, error) {
	root := v.RootIno()
	if ino == root {
		return "/", true, nil
	}
	var parts []string
	current := ino
	seen := map[uint32]bool{current: true}
	for current != root {
		if len(parts) >= MaxPathDepth {
			return "", false, nil
		}
		inode, err := v.Inode(current)
		if err != nil {
			return "", false, nil
		}
		parent := inode.Pino
		if parent == 0 || seen[parent] {
			return "", false, nil
		}
		seen[parent] = true
		listing, err := v.ReadDir(parent)
		if err != nil {
			return "", false, nil
		}
		var found *DirEntry
		for index := range listing {
			if listing[index].Ino == current && !IsDot(listing[index].Name) {
				found = &listing[index]
				break
			}
		}
		if found == nil {
			return "", false, nil
		}
		parts = append(parts, string(found.Name))
		current = parent
	}
	for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
		parts[left], parts[right] = parts[right], parts[left]
	}
	return "/" + strings.Join(parts, "/"), true, nil
}

// SymlinkTarget returns the target of a symbolic link.
func (v *Volume) SymlinkTarget(ino uint32) (string, error) {
	inode, err := v.Inode(ino)
	if err != nil {
		return "", err
	}
	if !inode.IsSymlink() {
		return "", fmt.Errorf("%w: inode %d", ErrNotSymlink, ino)
	}
	if target := inode.SymlinkTarget(); target != nil {
		return string(target), nil
	}
	blockMap, err := v.FileMap(inode)
	if err != nil {
		return "", err
	}
	length := inode.Size
	if length > 65536 {
		length = 65536
	}
	bytes := make([]byte, length)
	if _, err := blockMap.ReadAt(0, bytes); err != nil {
		return "", err
	}
	if end := strings.IndexByte(string(bytes), 0); end >= 0 {
		bytes = bytes[:end]
	}
	return string(bytes), nil
}

// Stats counts the whole tree.
func (v *Volume) Stats() (VolumeStats, error) {
	root := v.RootIno()
	var stats VolumeStats
	pending := []uint32{root}
	seen := map[uint32]bool{root: true}
	for len(pending) > 0 {
		directory := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		stats.Directories++
		entries, unreadable, err := v.directory(directory)
		if err != nil {
			stats.UnreadableBlocks++
			continue
		}
		stats.UnreadableBlocks += unreadable
		for _, entry := range entries {
			if IsDot(entry.Name) {
				continue
			}
			stats.Entries++
			inode, err := v.Inode(entry.Ino)
			if err != nil {
				stats.UnreadableInodes++
				continue
			}
			if inode.FileType() != dirFileType(entry.FileType) {
				stats.FileTypeMismatches++
			}
			switch {
			case inode.IsDir():
				if !seen[entry.Ino] {
					seen[entry.Ino] = true
					pending = append(pending, entry.Ino)
				}
			case inode.IsRegular():
				stats.Files++
			case inode.IsSymlink():
				stats.Symlinks++
			default:
				stats.Other++
			}
		}
	}
	return stats, nil
}

func (v *Volume) probe() error {
	root, err := v.Inode(v.RootIno())
	if err != nil {
		return err
	}
	if !root.IsDir() {
		return invalidf("the root inode %d is not a directory", v.RootIno())
	}
	return root.CheckReadable()
}

func (v *Volume) entryFromInode(name, path string, inode *Inode) Entry {
	entry := Entry{
		Name:                   name,
		Path:                   path,
		Inode:                  inode.Ino,
		ParentInode:            inode.Pino,
		IsDir:                  inode.IsDir(),
		IsSymlink:              inode.IsSymlink(),
		Mode:                   inode.Mode,
		Size:                   inode.Size,
		UID:                    inode.UID,
		GID:                    inode.GID,
		Links:                  inode.Links,
		Atime:                  f2fsTimeToTime(inode.Atime),
		Ctime:                  f2fsTimeToTime(inode.Ctime),
		Mtime:                  f2fsTimeToTime(inode.Mtime),
		InlineData:             inode.InlineFlags&InlineData != 0,
		InlineDentry:           inode.InlineFlags&InlineDentry != 0,
		Compressed:             inode.IsCompressed(),
		CompressAlgorithm:      inode.CompressAlgorithmName(),
		CompressLogClusterSize: inode.LogClusterSize,
		CompressedBlocks:       inode.CompressedBlocks,
	}
	if inode.Crtime != nil {
		entry.Crtime = f2fsTimeToTime(*inode.Crtime)
		entry.HasCrtime = true
	}
	return entry
}

func f2fsTimeToTime(t F2fsTime) time.Time {
	const maxSeconds = uint64(1<<63 - 1)
	if t.Seconds > maxSeconds {
		return time.Time{}
	}
	return time.Unix(int64(t.Seconds), int64(t.Nanos)).UTC()
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

func cleanPath(path string, root bool) string {
	if root {
		return "/"
	}
	var parts []string
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." {
			continue
		}
		parts = append(parts, component)
	}
	return "/" + strings.Join(parts, "/")
}

// dirFileType maps a directory entry's file-type hint to mode bits.  DT_UNKNOWN
// maps to a value no inode's mode can equal.
func dirFileType(fileType uint8) uint16 {
	switch fileType {
	case DTDir:
		return SIFDIR
	case DTReg:
		return SIFREG
	case DTLnk:
		return SIFLNK
	case DTFifo:
		return 0x1000
	case DTChr:
		return 0x2000
	case DTBlk:
		return 0x6000
	case DTSock:
		return 0xC000
	default:
		return ^uint16(0)
	}
}
