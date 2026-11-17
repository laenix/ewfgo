// Package hpfs reads OS/2 HPFS volumes, read-only, from a source.ByteSource.
//
// It is a port of the Rust forensic-core HPFS reader. The bootstrap chain is
// fixed by on-disk numbers:
//
//	boot block at byte 0                           superblock.go
//	  main superblock at byte 0x2000
//	    spare block at byte 0x2200 (magic checked, no geometry taken)
//	      root fnode at superblock.root_fnode     fnode.go
//	        directory B+ tree of dnodes           dir.go
//	          file runs stored in the fnode       file.go
//
// A 512-byte boot block sits at byte 0. The main superblock is at sector 16;
// the block at sector 17 is the spare block, which holds hotfix bookkeeping
// rather than a second copy of the superblock. Every file and directory begins
// with an fnode, and a directory's data is a B+ tree of four-sector dnodes.
//
// # Times
//
// HPFS records creation, access and write times as 32-bit second counts in
// local time; the zone is not stored in the image. This reader therefore keeps
// every non-zero value as a raw integer and emits no event time: a local-time
// count without its zone is not an instant, and inventing UTC would move every
// event by an unknown amount. Entry.Mtime, Entry.Atime and Entry.Ctime are
// zero; WriteTimeRaw, ReadTimeRaw and CreationTimeRaw carry the on-disk values.
//
// # Names
//
// HPFS names are up to 255 bytes in an OEM code page. Only printable ASCII in
// code page zero is decoded. Any other entry is listed with Undecodable set,
// its raw bytes in RawName, and an empty Name; no code page is guessed.
//
// # What is not read
//
//   - Extended attributes and ACLs: sizes and presence are reported, their
//     contents are never decoded.
//   - The internal (anode) form of the fnode B+ tree: a file that outgrows its
//     eight in-fnode runs is refused by name rather than served a partial map.
//   - Deleted files: HPFS keeps no undelete index this reader follows, so
//     Entry.Deleted is always false.
//   - POSIX ownership and modes do not exist in HPFS; UID, GID and Mode are
//     zero rather than made up.
//
// Nothing is zero-filled to stand in for missing metadata. Holes between a
// file's runs are the only zeroes manufactured, and they are reported as
// source.RangeHole.
package hpfs

import (
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Info is a volume's report.
type Info struct {
	SectorBytes       uint32
	SectorsPerCluster uint8
	VolumeSerial      uint32
	VolumeLabel       string

	Version     uint8
	FuncVersion uint8
	RootFnode   uint32
	NSectors    uint32
	NBadblocks  uint32
	Bitmaps     uint32
	Badblocks   uint32

	LastChkdskRaw   uint32
	LastOptimizeRaw uint32
	NDirBand        uint32
	DirBandStart    uint32
	DirBandEnd      uint32
	DirBandBitmap   uint32
	UserIDTable     uint32
	VolumeName      string

	DeclaredBytes uint64
	VolumeBytes   uint64
	SourceBytes   uint64
	Truncated     bool

	SpareMagic  uint32
	SpareMagic1 uint32

	// Warnings records the volume-level caveats this reader always reports.
	Warnings []string
}

// Entry is one file or directory in a volume.
type Entry struct {
	Name string
	Path string
	// RawName is the on-disk name bytes. It is always filled for directory
	// entries.
	RawName []byte
	// Undecodable reports that Name could not be decoded as printable ASCII
	// in code page zero. Such an entry has no path and cannot be looked up.
	Undecodable bool

	Inode       uint32
	ParentInode uint32
	IsDir       bool
	IsFile      bool
	IsSymlink   bool
	Size        uint64
	Mode        uint32
	UID         uint32
	GID         uint32
	Links       uint32

	// Atime, Ctime and Mtime are zero: HPFS times are local-time second
	// counts with no zone. The raw values are below.
	Atime time.Time
	Ctime time.Time
	Mtime time.Time

	WriteTimeRaw    uint32
	ReadTimeRaw     uint32
	CreationTimeRaw uint32

	Flags1   uint8
	Flags2   uint8
	EASize   uint32
	ACLCount uint8
	CodePage uint8

	// Allocated counts the bytes the fnode's runs allocate. HasAllocated is
	// false for directories and for a file whose map did not validate.
	Allocated    uint64
	HasAllocated bool

	FnodeFlags uint16
	BtreeFlags uint8

	// TypeMismatch reports that the directory entry and the fnode disagree
	// about whether the name is a directory; the fnode is used.
	TypeMismatch bool

	// Deleted is always false: HPFS removes a name's entry when it is
	// unlinked, so this reader cannot prove a deleted name.
	Deleted bool
}

// VolumeStats is what a walk of the whole tree found.
type VolumeStats struct {
	Directories uint64
	Files       uint64
	Entries     uint64
	FnodesRead  uint64
	DnodesRead  uint64
	Unreadable  uint64
	Refusals    uint64
	Malformed   uint64
}

// Volume is an opened HPFS volume.
type Volume struct {
	source      source.ByteSource
	superblocks Superblocks
	root        *Fnode
	fileID      atomic.Uint64
}

// Detect reports whether src looks like an HPFS volume without mounting it.
func Detect(src source.ByteSource) (bool, error) {
	return detectSuperblocks(src)
}

// Open proves a volume through its boot/superblock pair and root fnode.
func Open(src source.ByteSource) (*Volume, error) {
	blocks, err := ReadSuperblocks(src)
	if err != nil {
		return nil, err
	}
	root, err := readFnode(src, &blocks.Main, blocks.Main.RootFnode)
	if err != nil {
		return nil, err
	}
	if !root.IsDirectory() {
		return nil, corruptf("the root fnode in sector %d is not a directory", blocks.Main.RootFnode)
	}
	volume := &Volume{source: src, superblocks: *blocks, root: root}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	return volume, nil
}

// Info returns the volume's report.
func (v *Volume) Info() Info {
	main := v.superblocks.Main
	boot := v.superblocks.Boot
	return Info{
		SectorBytes:       uint32(SectorBytes),
		SectorsPerCluster: boot.SectorsPerCluster,
		VolumeSerial:      boot.VolumeSerial,
		VolumeLabel:       boot.VolumeLabel,
		Version:           main.Version,
		FuncVersion:       main.FuncVersion,
		RootFnode:         main.RootFnode,
		NSectors:          main.NSectors,
		NBadblocks:        main.NBadblocks,
		Bitmaps:           main.Bitmaps,
		Badblocks:         main.Badblocks,
		LastChkdskRaw:     main.LastChkdsk,
		LastOptimizeRaw:   main.LastOptimize,
		NDirBand:          main.NDirBand,
		DirBandStart:      main.DirBandStart,
		DirBandEnd:        main.DirBandEnd,
		DirBandBitmap:     main.DirBandBitmap,
		UserIDTable:       main.UserIDTable,
		VolumeName:        main.VolumeName,
		DeclaredBytes:     main.DeclaredBytes,
		VolumeBytes:       main.VolumeBytes,
		SourceBytes:       main.SourceBytes,
		Truncated:         main.VolumeBytes < main.DeclaredBytes,
		SpareMagic:        v.superblocks.Spare.Magic,
		SpareMagic1:       v.superblocks.Spare.Magic1,
		Warnings: []string{
			"HPFS timestamps are local-time second counts with no zone in the image; raw values are kept and no event time is emitted",
			"extended attributes and ACLs are counted from their size fields but never decoded",
		},
	}
}

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns the parsed main superblock.
func (v *Volume) Superblock() *Superblock { return &v.superblocks.Main }

// Boot returns the parsed boot block.
func (v *Volume) Boot() *BootBlock { return &v.superblocks.Boot }

// Spare returns the parsed spare block.
func (v *Volume) Spare() *SpareBlock { return &v.superblocks.Spare }

// RootFnode returns the root fnode.
func (v *Volume) RootFnode() *Fnode { return v.root }

type resolved struct {
	fnode  *Fnode
	parent uint32
	entry  *dirEntry
	root   bool
	clean  string
}

func (v *Volume) lookup(path string) (*resolved, error) {
	clean := cleanPath(path)
	current := v.superblocks.Main.RootFnode
	parent := uint32(0)
	var last *dirEntry
	var stack []uint32
	if clean != "/" {
		for _, component := range strings.Split(clean, "/") {
			if component == "" || component == "." {
				continue
			}
			if component == ".." {
				if len(stack) == 0 {
					current = v.superblocks.Main.RootFnode
					parent = 0
					last = nil
					continue
				}
				current = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if len(stack) > 0 {
					parent = stack[len(stack)-1]
				} else {
					parent = 0
				}
				last = nil
				continue
			}
			located, err := readFnode(v.source, &v.superblocks.Main, current)
			if err != nil {
				return nil, err
			}
			if !located.IsDirectory() {
				return nil, ErrNotDir
			}
			listing, err := readDirectory(v.source, &v.superblocks.Main, located)
			if err != nil {
				return nil, err
			}
			found := false
			for index := range listing.Entries {
				if listing.Entries[index].Name == component {
					entry := listing.Entries[index]
					last = &entry
					parent = current
					stack = append(stack, current)
					current = entry.Fnode
					found = true
					break
				}
			}
			if !found {
				return nil, ErrNotFound
			}
		}
	}
	fnode, err := readFnode(v.source, &v.superblocks.Main, current)
	if err != nil {
		return nil, err
	}
	return &resolved{
		fnode:  fnode,
		parent: parent,
		entry:  last,
		root:   clean == "/",
		clean:  clean,
	}, nil
}

// LookupPath resolves a path to its fnode sector. The bool is false when a
// component does not exist.
func (v *Volume) LookupPath(path string) (uint32, bool, error) {
	item, err := v.lookup(path)
	if err != nil {
		if err == ErrNotFound {
			return 0, false, nil
		}
		return 0, false, err
	}
	return item.fnode.Sector, true, nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) {
	item, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	if item.root {
		entry := v.entryFromFnode("/", "/", 0, item.fnode, nil, true)
		return &entry, nil
	}
	name := item.entry.Name
	entry := v.entryFromFnode(name, item.clean, item.parent, item.fnode, item.entry, false)
	return &entry, nil
}

// ListDir lists a directory's entries, excluding "." and "..".
func (v *Volume) ListDir(path string) ([]Entry, error) {
	item, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	if !item.fnode.IsDirectory() {
		return nil, ErrNotDir
	}
	listing, err := readDirectory(v.source, &v.superblocks.Main, item.fnode)
	if err != nil {
		return nil, err
	}
	base := item.clean
	if base == "" {
		base = "/"
	}
	parentInode := item.fnode.Sector
	out := make([]Entry, 0, len(listing.Entries))
	for index := range listing.Entries {
		raw := &listing.Entries[index]
		if raw.Name == "." || raw.Name == ".." {
			continue
		}
		child, err := readFnode(v.source, &v.superblocks.Main, raw.Fnode)
		if err != nil {
			return nil, err
		}
		name := raw.Name
		childPath := ""
		if name != "" {
			if base == "/" {
				childPath = "/" + name
			} else {
				childPath = base + "/" + name
			}
		}
		out = append(out, v.entryFromFnode(name, childPath, parentInode, child, raw, false))
	}
	return out, nil
}

// OpenFile opens the file named by path as a byte source.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	item, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	if item.fnode.IsDirectory() {
		return nil, ErrIsDir
	}
	id := source.ID(v.fileID.Add(1))
	return newHpfsFileSource(id, v.source, item.fnode)
}

// FreeSpace scans the volume's allocation bitmap.
func (v *Volume) FreeSpace() (*FreeSpace, error) {
	return freeSpace(v.source, &v.superblocks.Main)
}

// Stats walks every directory and counts what it finds. A directory or name
// that cannot be read is counted, not allowed to hide the rest of the tree.
func (v *Volume) Stats() (VolumeStats, error) {
	var stats VolumeStats
	type pending struct {
		sector uint32
	}
	queue := []pending{{v.superblocks.Main.RootFnode}}
	seen := make(map[uint32]bool)
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if seen[item.sector] {
			continue
		}
		seen[item.sector] = true
		located, err := readFnode(v.source, &v.superblocks.Main, item.sector)
		if err != nil {
			return stats, err
		}
		stats.FnodesRead++
		if !located.IsDirectory() {
			continue
		}
		stats.Directories++
		listing, err := readDirectory(v.source, &v.superblocks.Main, located)
		if err != nil {
			stats.Unreadable++
			classifyHPFSError(&stats, err)
			continue
		}
		stats.DnodesRead += uint64(listing.Dnodes)
		for index := range listing.Entries {
			raw := &listing.Entries[index]
			if raw.Name == "." || raw.Name == ".." {
				continue
			}
			stats.Entries++
			child, err := readFnode(v.source, &v.superblocks.Main, raw.Fnode)
			if err != nil {
				stats.Unreadable++
				classifyHPFSError(&stats, err)
				continue
			}
			stats.FnodesRead++
			switch {
			case child.IsDirectory():
				if !seen[child.Sector] {
					queue = append(queue, pending{child.Sector})
				}
			default:
				stats.Files++
			}
		}
	}
	return stats, nil
}

func classifyHPFSError(stats *VolumeStats, err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, source.ErrUnsupported):
		stats.Refusals++
	case errors.Is(err, source.ErrCorrupt):
		stats.Malformed++
	}
}

func (v *Volume) entryFromFnode(name, path string, parent uint32, fnode *Fnode, raw *dirEntry, root bool) Entry {
	isDir := fnode.IsDirectory()
	entry := Entry{
		Name:        name,
		Path:        path,
		Inode:       fnode.Sector,
		ParentInode: parent,
		IsDir:       isDir,
		IsFile:      !isDir,
		IsSymlink:   false,
		Size:        0,
		Mode:        0,
		UID:         0,
		GID:         0,
		Links:       0,
		FnodeFlags:  fnode.Flags,
		BtreeFlags:  fnode.BtreeFlags,
		Deleted:     false,
	}
	if !isDir {
		entry.Size = fnode.FileSize
		entry.Allocated = fnode.AllocatedBytes()
		entry.HasAllocated = true
	}
	if raw != nil {
		entry.RawName = append([]byte(nil), raw.RawName...)
		entry.Undecodable = raw.Undecodable
		entry.Flags1 = raw.Flags1
		entry.Flags2 = raw.Flags2
		entry.WriteTimeRaw = raw.WriteTime
		entry.ReadTimeRaw = raw.ReadTime
		entry.CreationTimeRaw = raw.CreateTime
		entry.ACLCount = raw.ACLCount
		entry.CodePage = raw.CodePage
		entry.EASize = raw.EASize
		if raw.HasExtendedAttributes() {
			alternate := fnode.EASizeDisk
			if uint32(fnode.EASizeFnode) > alternate {
				alternate = uint32(fnode.EASizeFnode)
			}
			if alternate > entry.EASize {
				entry.EASize = alternate
			}
		}
		entry.TypeMismatch = raw.IsDirectory() != isDir
	} else if root {
		entry.EASize = fnode.EASizeDisk
	}
	return entry
}

func cleanPath(path string) string {
	var parts []string
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
