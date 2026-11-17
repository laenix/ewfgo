package jfs

import (
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The JFS directory B+ tree. A directory has the same shape as an extent tree:
// a 288-byte root inside the inode and whole 4 KiB pages below it. Entries are
// 32-byte slots; the sorted entry table is an array of slot indices that gives
// the entries in name order. Names are little-endian UTF-16 code units, with a
// longer name continuing through slots linked by the `next` byte.
const (
	// DtRootBytes is the size of an inode's directory tree root.
	DtRootBytes = 288
	// DtPageBytes is the size of one directory tree page.
	DtPageBytes = 4096
	// DtRootMaxSlot is the number of slots a root holds, header included.
	DtRootMaxSlot = 9
	// DtPageMaxSlot is the number of slots a page holds.
	DtPageMaxSlot = 128
	// DtEntryStart is the first slot an entry may use.
	DtEntryStart = 1
	// DtLeafHeaderDataLen is the inline name length with the index word.
	DtLeafHeaderDataLen = 11
	// DtLeafHeaderDataLenLegacy is the inline name length without it.
	DtLeafHeaderDataLenLegacy = 13
	// DtSlotDataLen is the name units a continuation slot holds.
	DtSlotDataLen = 15
	// MaxNameSlots bounds a name's continuation chain.
	MaxNameSlots = 32
)

// DirEntry is one live directory entry.
type DirEntry struct {
	// Name is the decoded UTF-16 name, with unpaired surrogates replaced.
	Name string
	// Inode is the inode number the entry names.
	Inode uint32
	// Index is the persistent directory index, when the volume has one.
	Index uint32
	// Slot is the entry's slot in its node.
	Slot uint16
	// Page is the page's block address; zero for the inode's root.
	Page uint64
}

type dirNode struct {
	raw     []byte
	root    bool
	address uint64
}

func parseDirRoot(raw []byte) (*dirNode, error) {
	if len(raw) < DtRootBytes {
		return nil, corruptf("a directory tree root needs %d bytes, not %d", DtRootBytes, len(raw))
	}
	node := &dirNode{raw: raw[:DtRootBytes], root: true}
	if err := node.validateHeader(); err != nil {
		return nil, err
	}
	return node, nil
}

func parseDirPage(src source.ByteSource, volumeBlocks, address uint64) (*dirNode, error) {
	if address == 0 || address >= volumeBlocks {
		return nil, corruptf("directory page %d is outside the aggregate's %d blocks", address, volumeBlocks)
	}
	raw, err := source.ReadVecAt(src, address*BlockSize, DtPageBytes)
	if err != nil {
		return nil, err
	}
	node := &dirNode{raw: raw, address: address}
	if err := node.validateHeader(); err != nil {
		return nil, err
	}
	return node, nil
}

func (n *dirNode) flag() uint8 { return n.raw[16] }

func (n *dirNode) isLeaf() bool { return n.flag()&BTLeaf != 0 }

func (n *dirNode) isInternal() bool { return n.flag()&BTInternal != 0 }

func (n *dirNode) nextIndex() int { return int(n.raw[17]) }

func (n *dirNode) maxSlot() int {
	if n.root {
		return DtRootMaxSlot
	}
	return int(n.raw[20])
}

func (n *dirNode) stblIndex() int {
	if n.root {
		return 24
	}
	return int(n.raw[21]) * 32
}

func (n *dirNode) stbl(index int) (int, error) {
	at := n.stblIndex() + index
	if at < 0 || at >= len(n.raw) {
		return 0, corruptf("the sorted entry table index %d is past the %d-byte node", index, len(n.raw))
	}
	slot := int(n.raw[at])
	if slot < DtEntryStart || slot >= n.maxSlot() {
		return 0, corruptf("the sorted entry table names slot %d; this node has slots %d..%d",
			slot, DtEntryStart, n.maxSlot())
	}
	return slot, nil
}

func (n *dirNode) nextPage() uint64 {
	if n.root {
		return 0
	}
	return le64(n.raw, 0)
}

func (n *dirNode) validateHeader() error {
	if n.root {
		if n.flag()&BTRoot == 0 {
			return corruptf("a directory tree root does not carry the root flag")
		}
		if n.nextIndex() > DtRootMaxSlot-DtEntryStart {
			return corruptf("a directory root claims %d entries; it holds at most %d",
				n.nextIndex(), DtRootMaxSlot-DtEntryStart)
		}
	} else {
		maxSlot := n.maxSlot()
		if maxSlot < DtEntryStart+1 || maxSlot > DtPageMaxSlot {
			return corruptf("a directory page claims %d slots; a 4096-byte page holds at most %d",
				maxSlot, DtPageMaxSlot)
		}
		stblIndex := int(n.raw[21])
		if stblIndex >= maxSlot {
			return corruptf("a directory page puts its sorted entry table at slot %d, outside its %d slots",
				stblIndex, maxSlot)
		}
		end := n.stblIndex() + n.nextIndex()
		if end > DtPageBytes || end < n.stblIndex() {
			return corruptf("a directory page's sorted entry table runs past its %d bytes", DtPageBytes)
		}
		if n.nextIndex() >= maxSlot {
			return corruptf("a directory page claims %d entries but only %d slots", n.nextIndex(), maxSlot)
		}
	}
	if n.isLeaf() == n.isInternal() {
		return corruptf("a directory node's flag %#04x is neither a leaf nor an internal node", n.flag())
	}
	return nil
}

func (n *dirNode) firstChild() (Pxd, error) {
	slot, err := n.stbl(0)
	if err != nil {
		return Pxd{}, err
	}
	return ParsePxd(n.raw, slot*32)
}

func (n *dirNode) entries(dirIndex bool) ([]DirEntry, error) {
	count := n.nextIndex()
	headerChars := DtLeafHeaderDataLenLegacy
	if dirIndex {
		headerChars = DtLeafHeaderDataLen
	}
	out := make([]DirEntry, 0, count)
	for index := 0; index < count; index++ {
		slot, err := n.stbl(index)
		if err != nil {
			return nil, err
		}
		at := slot * 32
		inode := le32(n.raw, at)
		namlen := int(n.raw[at+5])
		if namlen == 0 {
			return nil, corruptf("directory slot %d has a zero-length name", slot)
		}
		units := make([]uint16, 0, namlen)
		take := namlen
		if take > headerChars {
			take = headerChars
		}
		for unit := 0; unit < take; unit++ {
			units = append(units, le16(n.raw, at+6+unit*2))
		}
		remaining := namlen - take
		next := int8(n.raw[at+4])
		chained := 0
		for next >= 0 {
			if remaining == 0 {
				return nil, corruptf("directory slot %d continues a name that is already complete", slot)
			}
			chained++
			if chained > MaxNameSlots {
				return nil, corruptf("directory slot %d chains more than %d continuation slots", slot, MaxNameSlots)
			}
			continuation := int(next)
			if continuation < DtEntryStart || continuation >= n.maxSlot() {
				return nil, corruptf("directory slot %d continues at slot %d, outside its %d slots",
					slot, continuation, n.maxSlot())
			}
			cat := continuation * 32
			take = remaining
			if take > DtSlotDataLen {
				take = DtSlotDataLen
			}
			for unit := 0; unit < take; unit++ {
				units = append(units, le16(n.raw, cat+2+unit*2))
			}
			remaining -= take
			next = int8(n.raw[cat])
		}
		if remaining != 0 {
			return nil, corruptf("directory slot %d declares %d name code units but its slots hold %d",
				slot, namlen, namlen-remaining)
		}
		indexWord := uint32(0)
		if dirIndex {
			indexWord = le32(n.raw, at+28)
		}
		out = append(out, DirEntry{
			Name:  string(utf16.Decode(units)),
			Inode: inode,
			Index: indexWord,
			Slot:  uint16(slot),
			Page:  n.address,
		})
	}
	return out, nil
}

// validateDirRoot checks a 288-byte directory tree root without walking it.
func validateDirRoot(root []byte) error {
	_, err := parseDirRoot(root)
	return err
}

// readDirectory returns every live entry of a directory, in tree order.
func readDirectory(src source.ByteSource, volumeBlocks uint64, root []byte, dirIndex bool, maxPages int) ([]DirEntry, error) {
	node, err := parseDirRoot(root)
	if err != nil {
		return nil, err
	}
	var out []DirEntry
	seen := make(map[uint64]bool)
	pages := 0
	depth := 0
	for {
		if node.isLeaf() {
			entries, err := node.entries(dirIndex)
			if err != nil {
				return nil, err
			}
			out = append(out, entries...)
			next := node.nextPage()
			if node.root || next == 0 {
				break
			}
			pages++
			if pages > maxPages {
				return nil, corruptf("the directory has more than %d pages", maxPages)
			}
			if seen[next] {
				return nil, corruptf("directory loop: page %d is reached more than once", next)
			}
			seen[next] = true
			node, err = parseDirPage(src, volumeBlocks, next)
			if err != nil {
				return nil, err
			}
			continue
		}
		if node.nextIndex() == 0 {
			break
		}
		child, err := node.firstChild()
		if err != nil {
			return nil, err
		}
		if child.Len != 1 {
			return nil, corruptf("a directory internal entry covers %d blocks; a directory page is one block", child.Len)
		}
		depth++
		if depth > 8 {
			return nil, corruptf("the directory tree is deeper than 8 levels")
		}
		if seen[child.Address] {
			return nil, corruptf("directory loop: page %d is reached more than once", child.Address)
		}
		seen[child.Address] = true
		node, err = parseDirPage(src, volumeBlocks, child.Address)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
