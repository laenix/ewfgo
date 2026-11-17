package jfs

import (
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The JFS extent B+ tree. Every byte of a file lives in an extent described by
// a 16-byte xad: a flag byte, a 40-bit logical offset in filesystem blocks,
// and a physical extent descriptor. The root is inside the inode (288 bytes);
// internal nodes are whole 4 KiB pages addressed absolutely.
const (
	// XtEntryStart is the first entry slot; the first two are the header.
	XtEntryStart = 2
	// XtRootMaxSlot is how many entries a 288-byte root holds.
	XtRootMaxSlot = 18
	// XtPageMaxSlot is how many entries a 4096-byte page holds.
	XtPageMaxSlot = 256
	// XtRootBytes is the size of an inode's tree root.
	XtRootBytes = 288
	// MaxTreeHeight is the deepest tree the kernel allows.
	MaxTreeHeight = 8
)

// Xad is one extent allocation descriptor.
type Xad struct {
	Flag    uint8
	Logical uint64
	Address uint64
	Len     uint32
}

// IsCompressed reports whether this reader must refuse the extent.
func (x Xad) IsCompressed() bool { return x.Flag&XadCompressed != 0 }

// IsNotRecorded reports whether the extent is allocated but never written; it
// reads as zeroes.
func (x Xad) IsNotRecorded() bool { return x.Flag&XadNotRecorded != 0 }

// End returns the first logical block past the extent.
func (x Xad) End() (uint64, error) {
	end := x.Logical + uint64(x.Len)
	if end < x.Logical {
		return 0, corruptf("an extent's logical end overflows")
	}
	return end, nil
}

// PhysicalEnd returns the first physical block past the extent.
func (x Xad) PhysicalEnd() (uint64, error) {
	end := x.Address + uint64(x.Len)
	if end < x.Address {
		return 0, corruptf("an extent's physical end overflows")
	}
	return end, nil
}

type xtNode struct {
	raw     []byte
	root    bool
	address uint64
}

func parseXtRoot(raw []byte) (*xtNode, error) {
	if len(raw) < XtRootBytes {
		return nil, corruptf("an extent tree root needs %d bytes, not %d", XtRootBytes, len(raw))
	}
	node := &xtNode{raw: raw[:XtRootBytes], root: true}
	if err := node.validateHeader(); err != nil {
		return nil, err
	}
	return node, nil
}

func parseXtPage(src source.ByteSource, volumeBlocks, address uint64) (*xtNode, error) {
	if address == 0 {
		return nil, corruptf("an extent tree page has address zero")
	}
	if address >= volumeBlocks {
		return nil, corruptf("extent tree page %d is outside the aggregate's %d blocks", address, volumeBlocks)
	}
	offset := address * BlockSize
	if offset/BlockSize != address {
		return nil, corruptf("an extent tree page offset overflows")
	}
	raw, err := source.ReadVecAt(src, offset, BlockSize)
	if err != nil {
		return nil, err
	}
	node := &xtNode{raw: raw, address: address}
	if err := node.validateHeader(); err != nil {
		return nil, err
	}
	return node, nil
}

func (n *xtNode) flag() uint8 { return n.raw[16] }

func (n *xtNode) isLeaf() bool { return n.flag()&BTLeaf != 0 }

func (n *xtNode) isInternal() bool { return n.flag()&BTInternal != 0 }

func (n *xtNode) nextIndex() int { return int(le16(n.raw, 18)) }

func (n *xtNode) maxEntry() int { return int(le16(n.raw, 20)) }

func (n *xtNode) limit() int {
	if n.root {
		return XtRootMaxSlot
	}
	return XtPageMaxSlot
}

func (n *xtNode) validateHeader() error {
	nextIndex := n.nextIndex()
	maxEntry := n.maxEntry()
	limit := n.limit()
	if nextIndex < XtEntryStart {
		return corruptf("an extent tree node holds %d entries; the first two slots are the header", nextIndex)
	}
	if nextIndex > maxEntry {
		return corruptf("an extent tree node's nextindex %d exceeds its maxentry %d", nextIndex, maxEntry)
	}
	if maxEntry > limit || maxEntry*16 > len(n.raw) {
		kind := "page"
		if n.root {
			kind = "root"
		}
		return corruptf("an extent tree %s claims %d entries; the structure holds at most %d", kind, maxEntry, limit)
	}
	if n.flag()&BTType == 0 || n.isLeaf() == n.isInternal() {
		return corruptf("an extent tree node's flag %#04x is neither a leaf nor an internal node", n.flag())
	}
	return nil
}

func (n *xtNode) entry(index int) Xad {
	at := index * 16
	pxd, _ := ParsePxd(n.raw, at+8)
	return Xad{
		Flag:    n.raw[at],
		Logical: uint64(n.raw[at+3])<<32 | uint64(le32(n.raw, at+4)),
		Address: pxd.Address,
		Len:     pxd.Len,
	}
}

func (n *xtNode) entries() []Xad {
	next := n.nextIndex()
	out := make([]Xad, 0, next-XtEntryStart)
	for index := XtEntryStart; index < next; index++ {
		out = append(out, n.entry(index))
	}
	return out
}

// lookupExtent finds the extent covering logical block lblock in an inode's
// extent tree. A block in no extent is a hole and yields (nil, nil).
func lookupExtent(src source.ByteSource, volumeBlocks uint64, root []byte, lblock uint64) (*Xad, error) {
	node, err := parseXtRoot(root)
	if err != nil {
		return nil, err
	}
	seen := make(map[uint64]bool)
	depth := 0
	for {
		entries := node.entries()
		if node.isLeaf() {
			var chosen *Xad
			for index := range entries {
				if entries[index].Logical <= lblock {
					chosen = &entries[index]
				} else {
					break
				}
			}
			if chosen == nil {
				return nil, nil
			}
			end, err := chosen.End()
			if err != nil {
				return nil, err
			}
			if lblock < end {
				return chosen, nil
			}
			return nil, nil
		}
		if len(entries) == 0 {
			return nil, corruptf("an internal extent tree node holds no child entries")
		}
		child := entries[0]
		for index := range entries {
			if entries[index].Logical <= lblock {
				child = entries[index]
			} else {
				break
			}
		}
		depth++
		if depth > MaxTreeHeight {
			return nil, corruptf("the extent tree is deeper than %d levels", MaxTreeHeight)
		}
		if seen[child.Address] {
			return nil, corruptf("extent tree loop: page %d is reached more than once", child.Address)
		}
		seen[child.Address] = true
		node, err = parseXtPage(src, volumeBlocks, child.Address)
		if err != nil {
			return nil, err
		}
	}
}

// collectExtents returns every leaf extent of an inode's extent tree, sorted
// by logical block. maxPages bounds a hostile tree.
func collectExtents(src source.ByteSource, volumeBlocks uint64, root []byte, maxPages int) ([]Xad, error) {
	rootNode, err := parseXtRoot(root)
	if err != nil {
		return nil, err
	}
	var out []Xad
	seen := make(map[uint64]bool)
	stack := []*xtNode{rootNode}
	pages := 0
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node.isLeaf() {
			out = append(out, node.entries()...)
			continue
		}
		if !node.isInternal() {
			continue
		}
		entries := node.entries()
		for index := len(entries) - 1; index >= 0; index-- {
			pages++
			if pages > maxPages {
				return nil, corruptf("the extent tree has more than %d pages", maxPages)
			}
			address := entries[index].Address
			if seen[address] {
				return nil, corruptf("extent tree loop: page %d is reached more than once", address)
			}
			seen[address] = true
			child, err := parseXtPage(src, volumeBlocks, address)
			if err != nil {
				return nil, err
			}
			stack = append(stack, child)
		}
	}
	sort.Slice(out, func(left, right int) bool { return out[left].Logical < out[right].Logical })
	return out, nil
}

// logicalBlock maps one logical block of an inode's own data stream to its
// disk address. The bool is false for a hole or a not-recorded extent.
func logicalBlock(src source.ByteSource, volumeBlocks uint64, root []byte, lblock uint64) (uint64, bool, error) {
	extent, err := lookupExtent(src, volumeBlocks, root, lblock)
	if err != nil {
		return 0, false, err
	}
	if extent == nil {
		return 0, false, nil
	}
	if extent.IsCompressed() {
		return 0, false, unsupportedf("a compressed extent at logical block %d of a metadata file", lblock)
	}
	if extent.IsNotRecorded() {
		return 0, false, nil
	}
	within := lblock - extent.Logical
	address := extent.Address + within
	if address < extent.Address {
		return 0, false, corruptf("an extent address overflows")
	}
	return address, true, nil
}

// readLogicalBlock reads one 4 KiB page of an inode's data stream. A block
// with no extent reads as zeroes, matching sparse-file behaviour.
func readLogicalBlock(src source.ByteSource, volumeBlocks uint64, root []byte, lblock uint64) ([]byte, error) {
	out := make([]byte, BlockSize)
	address, present, err := logicalBlock(src, volumeBlocks, root, lblock)
	if err != nil {
		return nil, err
	}
	if !present {
		return out, nil
	}
	if address >= volumeBlocks {
		return nil, corruptf("metadata block %d is outside the aggregate's %d blocks", address, volumeBlocks)
	}
	if err := source.ReadExactAt(src, address*BlockSize, out); err != nil {
		return nil, err
	}
	return out, nil
}
