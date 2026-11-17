package hammer2

import (
	"fmt"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// maxTreeDepth is the longest directory tree path this reader follows.
const maxTreeDepth = 16

// maxScanBrefs is the references one walk may examine before refusing.
const maxScanBrefs uint64 = 5_000_000

// HiddenMap maps an inode number (bit 63 clear) to the reference that stores
// that inode.
type HiddenMap map[uint64]Blockref

// ScanState is the counters and warnings shared by a directory walk.
type ScanState struct {
	NodesRead       uint64
	BlocksRead      uint64
	RefsScanned     uint64
	Unreadable      uint64
	Undecodable     uint64
	Refusals        uint64
	Malformed       uint64
	DirectoryLoops  uint64
	Warnings        []string
	WarningsDropped uint64
}

// NewScanState returns empty counters.
func NewScanState() *ScanState { return &ScanState{} }

// Warn keeps at most warningCap texts, counting the rest.
func (s *ScanState) Warn(message string) {
	if len(s.Warnings) < warningCap {
		s.Warnings = append(s.Warnings, message)
	} else {
		s.WarningsDropped++
	}
}

// Classify counts a refusal or a malformed record.
func (s *ScanState) Classify(err error) {
	switch {
	case err == nil:
		return
	case isUnsupported(err):
		s.Refusals++
	case isCorrupt(err):
		s.Malformed++
	}
}

// VisibleEntry is one visible name recovered from a directory tree.
type VisibleEntry struct {
	Name  string
	Inode *Inode
	// PFSRoot reports whether the reference or inode marks a PFS root, which
	// owns its own hidden-inode store.
	PFSRoot bool
}

// DirectoryScan is the result of scanning one directory inode.
type DirectoryScan struct {
	Entries []VisibleEntry
	Hidden  HiddenMap
}

// readInodeRef reads one INODE reference: checks the radix, verifies the
// 1 KiB check code, decodes the inode, and rejects a high-bit inode number.
func readInodeRef(src source.ByteSource, ref *Blockref, what string, state *ScanState) (*Inode, error) {
	if ref.BType != BrefTypeInode {
		return nil, corruptf("%s is not an inode reference (type %d)", what, ref.BType)
	}
	if ref.Radix() != 10 {
		return nil, corruptf("%s covers a radix-%d block; HAMMER2 inodes are 1024 bytes",
			what, ref.Radix())
	}
	bytes, err := ref.ReadBytes(src, what)
	if err != nil {
		return nil, err
	}
	state.BlocksRead++
	inode, err := ParseInode(bytes[:InodeBytes], what)
	if err != nil {
		return nil, err
	}
	if inode.Inum&DirhashVisible != 0 {
		return nil, corruptf("%s records inode number %d with bit 63 set; inode numbers are name hashes without that bit",
			what, inode.Inum)
	}
	offset := ref.PhysicalOffset()
	inode.MediaOffset = &offset
	state.NodesRead++
	return inode, nil
}

// readHiddenInode reads the hidden inode inum through the map, checking that
// the inode number it records is the one that was looked up.
func readHiddenInode(src source.ByteSource, hidden HiddenMap, inum uint64, state *ScanState) (*Inode, error) {
	what := fmt.Sprintf("the hidden inode for number %d", inum)
	ref, ok := hidden[inum]
	if !ok {
		return nil, corruptf("no hidden inode %d in this PFS", inum)
	}
	inode, err := readInodeRef(src, &ref, what, state)
	if err != nil {
		return nil, err
	}
	if inode.Inum != inum {
		return nil, corruptf("%s records inode number %d instead", what, inode.Inum)
	}
	return inode, nil
}

// collectLeaves adds every leaf reference below ref to leaves, reading
// indirect blocks along the way. A subtree that cannot be read is counted
// and skipped.
func collectLeaves(src source.ByteSource, ref *Blockref, what string, depth uint32,
	state *ScanState, leaves *[]Blockref) error {
	if depth > maxTreeDepth {
		return corruptf("%s nests deeper than the %d-level limit", what, maxTreeDepth)
	}
	state.RefsScanned++
	if state.RefsScanned > maxScanBrefs {
		return corruptf("the image holds more than %d tree references", maxScanBrefs)
	}
	switch ref.BType {
	case BrefTypeEmpty:
		return nil
	case BrefTypeInode, BrefTypeDirent:
		*leaves = append(*leaves, *ref)
		return nil
	case BrefTypeIndirect:
		block, err := ref.ReadBytes(src, what+" indirect block")
		if err != nil {
			state.Unreadable++
			state.Classify(err)
			state.Warn(fmt.Sprintf("%s: %v", what, err))
			return nil
		}
		state.BlocksRead++
		for index := 0; index < len(block)/BlockrefBytes; index++ {
			child, err := ParseBlockref(block[index*BlockrefBytes:(index+1)*BlockrefBytes],
				fmt.Sprintf("%s indirect slot %d", what, index))
			if err != nil {
				return err
			}
			if err := collectLeaves(src, child, what, depth+1, state, leaves); err != nil {
				return err
			}
		}
		return nil
	case BrefTypeData:
		state.Malformed++
		state.Warn(fmt.Sprintf("%s: a data reference appears in a directory tree", what))
		return nil
	default:
		state.Refusals++
		state.Warn(fmt.Sprintf("%s: skipped a %s reference in a directory tree", what, TypeLabel(ref.BType)))
		return nil
	}
}

// decodeDirent decodes a visible DIRENT reference, reading the external name
// block when the name is longer than 64 bytes.
func decodeDirent(src source.ByteSource, ref *Blockref, what string, state *ScanState) (string, uint64, error) {
	head, err := ParseDirentHead(ref, what)
	if err != nil {
		return "", 0, err
	}
	if head == nil {
		return "", 0, corruptf("%s is an empty directory-entry reference", what)
	}
	var dirent *Dirent
	if head.NeedsExternalName() {
		block, err := ref.ReadBytes(src, what+" external name block")
		if err != nil {
			return "", 0, err
		}
		state.BlocksRead++
		dirent, err = ExternalDirent(ref, block, what)
		if err != nil {
			return "", 0, err
		}
	} else {
		dirent, err = InlineDirent(ref, what)
		if err != nil {
			return "", 0, err
		}
	}
	if dirent == nil {
		return "", 0, corruptf("%s could not be decoded", what)
	}
	name, err := dirent.Name()
	if err != nil {
		return "", 0, err
	}
	return name, dirent.Inum, nil
}

// scanDirectory scans one directory inode's tree. ownsHidden is true for the
// super-root and every PFS root; other directories resolve DIRENT inode
// numbers through inherited.
func scanDirectory(src source.ByteSource, inode *Inode, inherited HiddenMap, ownsHidden bool,
	what string, state *ScanState) (*DirectoryScan, error) {
	if inode.Blockset == nil {
		return nil, corruptf("%s is a directory whose inode has no blockset", what)
	}
	var leaves []Blockref
	for index := range inode.Blockset.Refs() {
		root := inode.Blockset.Refs()[index]
		if root.BType != BrefTypeEmpty {
			if err := collectLeaves(src, &root, what, 0, state, &leaves); err != nil {
				return nil, err
			}
		}
	}
	// The kernel returns entries in key order, so a second reference with the
	// same key is a redundant copy.
	sort.SliceStable(leaves, func(left, right int) bool { return leaves[left].Key < leaves[right].Key })

	hidden := HiddenMap{}
	if ownsHidden {
		for index := range leaves {
			ref := &leaves[index]
			if ref.BType != BrefTypeInode || ref.Visible() {
				continue
			}
			if ref.Key == 0 {
				state.Malformed++
				state.Warn(fmt.Sprintf("%s: a hidden inode uses key 0, which is not an inode number", what))
				continue
			}
			if err := ref.ValidateMethods("a hidden inode"); err != nil {
				state.Classify(err)
				state.Warn(fmt.Sprintf("%s: hidden inode %d: %v", what, ref.Key, err))
				continue
			}
			if _, exists := hidden[ref.Key]; exists {
				state.Malformed++
				state.Warn(fmt.Sprintf("%s: hidden inode %d appears more than once; the first copy is used",
					what, ref.Key))
				continue
			}
			hidden[ref.Key] = *ref
		}
	}

	mapToUse := inherited
	if ownsHidden {
		mapToUse = hidden
	}
	entries := make([]VisibleEntry, 0, len(leaves))
	var previousVisible uint64
	havePrevious := false
	for index := range leaves {
		ref := &leaves[index]
		if ref.Visible() {
			if havePrevious && previousVisible == ref.Key {
				state.Warn(fmt.Sprintf("%s: a duplicate reference for visible key 0x%016x was skipped as a redundant copy",
					what, ref.Key))
				continue
			}
			previousVisible = ref.Key
			havePrevious = true
		}
		switch ref.BType {
		case BrefTypeInode:
			if !ref.Visible() {
				if !ownsHidden {
					state.Malformed++
					state.Warn(fmt.Sprintf("%s: a hidden inode appears below a subdirectory, where HAMMER2 does not store them", what))
				}
				continue
			}
			entryWhat := what + ": an inode entry"
			entry, err := readInodeRef(src, ref, entryWhat, state)
			if err != nil {
				state.Undecodable++
				state.Classify(err)
				state.Warn(fmt.Sprintf("%s: %v", entryWhat, err))
				continue
			}
			name, err := entry.Name()
			if err != nil {
				state.Undecodable++
				state.Classify(err)
				state.Warn(fmt.Sprintf("%s: %v", entryWhat, err))
				continue
			}
			// An INODE reference carries its name inside the inode, but it is
			// still one path component: a crafted name with a slash, NUL or a
			// dot entry would corrupt the displayed path, so apply the same
			// rule as for a DIRENT name.
			if err := validateName(entry.Filename, entryWhat); err != nil {
				state.Undecodable++
				state.Classify(err)
				state.Warn(fmt.Sprintf("%s: %v", entryWhat, err))
				continue
			}
			if name == "" {
				state.Malformed++
				state.Warn(fmt.Sprintf("%s has an empty filename", entryWhat))
				continue
			}
			entries = append(entries, VisibleEntry{
				Name:    name,
				Inode:   entry,
				PFSRoot: ref.PFSRoot() || entry.IsPFSRoot(),
			})
		case BrefTypeDirent:
			if !ref.Visible() {
				state.Malformed++
				state.Warn(fmt.Sprintf("%s: a named directory entry does not set the visible key bit", what))
				continue
			}
			entryWhat := what + ": a directory entry"
			name, inum, err := decodeDirent(src, ref, entryWhat, state)
			if err != nil {
				state.Undecodable++
				state.Classify(err)
				state.Warn(fmt.Sprintf("%s: %v", entryWhat, err))
				continue
			}
			entry, err := readHiddenInode(src, mapToUse, inum, state)
			if err != nil {
				state.Undecodable++
				state.Classify(err)
				state.Warn(fmt.Sprintf("%s %q resolves to inode %d: %v", entryWhat, name, inum, err))
				continue
			}
			entries = append(entries, VisibleEntry{
				Name:    name,
				Inode:   entry,
				PFSRoot: ref.PFSRoot() || entry.IsPFSRoot(),
			})
		}
	}
	return &DirectoryScan{Entries: entries, Hidden: hidden}, nil
}
