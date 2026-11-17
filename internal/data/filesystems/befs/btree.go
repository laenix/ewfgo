package befs

import (
	"bytes"

	"github.com/laenix/ewfgo/internal/data/source"
)

// B+tree constants.
const (
	TreeMagic       uint32 = 0x69f6_c2e8
	HeaderBytes            = 40
	NodeHeaderBytes        = 28
	MinKeyLength           = 1
	MaxKeyLength           = 256
	BPlusTreeNull   int64  = -1
	BPlusTreeFree   int64  = -2
	StringType      uint32 = 0
	MaxTreeNodeSize uint32 = 64 * 1024
	MaxTreeDepth    uint32 = 32
	MaxTreeNodes           = 1_000_000
	MaxEntries             = 5_000_000
)

// treeHeader is a parsed B+tree header.
type treeHeader struct {
	nodeSize    uint32
	maxLevels   uint32
	dataType    uint32
	root        int64
	free        int64
	maximumSize int64
}

func (h *treeHeader) lastNodeStart() (uint64, bool) {
	if h.maximumSize <= 0 || uint64(h.maximumSize) < uint64(h.nodeSize) {
		return 0, false
	}
	return uint64(h.maximumSize) - uint64(h.nodeSize), true
}

func (h *treeHeader) isValidLink(link int64) bool {
	if link == BPlusTreeNull {
		return true
	}
	last, ok := h.lastNodeStart()
	return link > 0 && ok && uint64(link) <= last
}

// Listing is the result of listing one directory tree.
type Listing struct {
	entries   []entry
	nodesRead uint64
	malformed uint64
}

// entry is one name from a directory tree.
type entry struct {
	name  string
	inode uint64
}

// readTreeHeader reads and validates the tree header.
func readTreeHeader(stream source.ByteSource) (*treeHeader, error) {
	if stream.Len() < HeaderBytes {
		return nil, corruptf("a B+tree needs a %d-byte header, but its stream is %d bytes",
			HeaderBytes, stream.Len())
	}
	raw := make([]byte, HeaderBytes)
	if err := source.ReadExactAt(stream, 0, raw); err != nil {
		return nil, err
	}
	magic := le32(raw, 0)
	if magic != TreeMagic {
		if magic == reverse32(TreeMagic) {
			return nil, unsupportedf("a byte-swapped (big-endian) B+tree header; this reader decodes little-endian images only")
		}
		return nil, corruptf("a directory tree has magic %#08x, expected %#08x", magic, TreeMagic)
	}
	header := &treeHeader{
		nodeSize:    le32(raw, 4),
		maxLevels:   le32(raw, 8),
		dataType:    le32(raw, 12),
		root:        int64(le64(raw, 16)),
		free:        int64(le64(raw, 24)),
		maximumSize: int64(le64(raw, 32)),
	}
	if header.nodeSize < 64 || header.nodeSize > MaxTreeNodeSize || header.nodeSize%8 != 0 {
		return nil, corruptf("a directory tree declares a node size of %d; expected a multiple of 8 in 64..=%d",
			header.nodeSize, MaxTreeNodeSize)
	}
	if header.maxLevels == 0 || header.maxLevels > MaxTreeDepth {
		return nil, unsupportedf("a directory tree declares %d levels; this reader descends at most %d",
			header.maxLevels, MaxTreeDepth)
	}
	if header.dataType != StringType {
		return nil, unsupportedf("a directory tree declares data type %d; only string-keyed trees are read", header.dataType)
	}
	if header.maximumSize <= 0 || uint64(header.maximumSize) != stream.Len() ||
		uint64(header.maximumSize)%uint64(header.nodeSize) != 0 {
		return nil, corruptf("a directory tree declares %d bytes, but its stream is %d bytes and a whole number of %d byte nodes is required",
			header.maximumSize, stream.Len(), header.nodeSize)
	}
	if header.root <= 0 || !header.isValidLink(header.root) {
		return nil, corruptf("a directory tree has root pointer %#016x, which is not a node in its %d byte stream",
			uint64(header.root), header.maximumSize)
	}
	if _, _, err := checkLink(header, header.root, "the root node", false); err != nil {
		return nil, err
	}
	if header.free != BPlusTreeNull {
		if _, _, err := checkLink(header, header.free, "the free node", false); err != nil {
			return nil, err
		}
	}
	return header, nil
}

// readBTree reads every name in a directory tree.
func readBTree(stream source.ByteSource) (*Listing, error) {
	header, err := readTreeHeader(stream)
	if err != nil {
		return nil, err
	}

	// Descend the leftmost path to the first leaf.
	visited := make(map[uint64]bool)
	offset := header.root
	var nodesRead uint64
	var level uint32
	var firstLeafOffset uint64
	var firstLeafBytes []byte
	for {
		at, ok, err := checkLink(header, offset, "a tree child", false)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, corruptf("a tree child is the null link where a node is required")
		}
		if visited[at] {
			return nil, corruptf("a directory tree loops back to node %d", at)
		}
		visited[at] = true
		if nodesRead >= MaxTreeNodes {
			return nil, corruptf("a directory tree has more than %d nodes", MaxTreeNodes)
		}
		raw, err := readTreeNode(stream, header, at)
		if err != nil {
			return nil, err
		}
		nodesRead++
		node, err := parseTreeNode(raw, header)
		if err != nil {
			return nil, err
		}
		if node.isLeaf() {
			firstLeafOffset = at
			firstLeafBytes = raw
			break
		}
		level++
		if level >= header.maxLevels {
			return nil, corruptf("a directory tree descends past its declared %d levels", header.maxLevels)
		}
		var next int64
		if node.numKeys > 0 {
			next, err = node.value(0)
			if err != nil {
				return nil, err
			}
		} else {
			next = node.overflow
		}
		offset = next
	}

	listing := &Listing{nodesRead: nodesRead}
	names := make(map[string]bool)
	currentOffset := firstLeafOffset
	currentBytes := firstLeafBytes
	for {
		node, err := parseTreeNode(currentBytes, header)
		if err != nil {
			return nil, err
		}
		if !node.isLeaf() {
			return nil, corruptf("node %d on a leaf chain is an interior node", currentOffset)
		}
		for index := 0; index < node.numKeys; index++ {
			key, err := node.key(index)
			if err != nil {
				return nil, err
			}
			if bytes.IndexByte(key, 0) >= 0 {
				listing.malformed++
				continue
			}
			name := lossyUTF8(key)
			inode, err := node.value(index)
			if err != nil {
				return nil, err
			}
			if inode <= 0 {
				listing.malformed++
				continue
			}
			if names[name] {
				// A directory tree cannot hold one name twice; list the first
				// and count the duplicate.
				listing.malformed++
				continue
			}
			if len(listing.entries) >= MaxEntries {
				return nil, corruptf("a directory tree holds more than %d names", MaxEntries)
			}
			names[name] = true
			listing.entries = append(listing.entries, entry{name: name, inode: uint64(inode)})
		}

		next := node.right
		if next == BPlusTreeNull {
			break
		}
		at, ok, err := checkLink(header, next, "a right sibling", false)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, corruptf("a right sibling is the null link where a node is required")
		}
		if visited[at] {
			return nil, corruptf("a directory tree's leaf chain loops back to node %d", at)
		}
		visited[at] = true
		if listing.nodesRead >= MaxTreeNodes {
			return nil, corruptf("a directory tree has more than %d nodes", MaxTreeNodes)
		}
		currentBytes, err = readTreeNode(stream, header, at)
		if err != nil {
			return nil, err
		}
		currentOffset = at
		listing.nodesRead++
	}
	return listing, nil
}

// checkLink validates a node pointer and returns it as an offset.
func checkLink(header *treeHeader, link int64, what string, allowNull bool) (uint64, bool, error) {
	switch {
	case link == BPlusTreeNull:
		if allowNull {
			return 0, false, nil
		}
		return 0, false, corruptf("%s is the null tree link where a node is required", what)
	case link == BPlusTreeFree:
		return 0, false, unsupportedf("%s points into the B+tree free list; free-node recovery is not read", what)
	case link < 0 || uint64(link)>>62 != 0:
		return 0, false, unsupportedf("%s is a duplicate or fragment tree link (%#016x); duplicate-key trees are not read",
			what, uint64(link))
	}
	at := uint64(link)
	if at%uint64(header.nodeSize) != 0 || !header.isValidLink(link) {
		return 0, false, corruptf("%s (offset %d) is not a node-aligned block inside the %d byte tree",
			what, at, header.maximumSize)
	}
	return at, true, nil
}

// readTreeNode reads one whole node.
func readTreeNode(stream source.ByteSource, header *treeHeader, offset uint64) ([]byte, error) {
	size := uint64(header.nodeSize)
	end := offset + size
	if end < offset {
		return nil, corruptf("a B+tree node overflows the byte address space")
	}
	if end > stream.Len() {
		return nil, corruptf("a B+tree node at offset %d runs past the %d byte tree stream", offset, stream.Len())
	}
	raw := make([]byte, header.nodeSize)
	if err := source.ReadExactAt(stream, offset, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// btreeNode is a checked view of one node.
type btreeNode struct {
	bytes        []byte
	numKeys      int
	allKeyLength int
	right        int64
	overflow     int64
}

func parseTreeNode(raw []byte, header *treeHeader) (*btreeNode, error) {
	if uint32(len(raw)) != header.nodeSize {
		return nil, corruptf("a B+tree node is %d bytes, not the declared %d", len(raw), header.nodeSize)
	}
	left := int64(le64(raw, 0))
	right := int64(le64(raw, 8))
	overflow := int64(le64(raw, 16))
	numKeys := int(le16(raw, 24))
	allKeyLength := int(le16(raw, 26))

	if _, _, err := checkLink(header, left, "a node's left link", true); err != nil {
		return nil, err
	}
	if _, _, err := checkLink(header, right, "a node's right link", true); err != nil {
		return nil, err
	}
	if overflow != BPlusTreeNull {
		if _, _, err := checkLink(header, overflow, "a node's overflow link", false); err != nil {
			return nil, err
		}
	}

	keysEnd := NodeHeaderBytes + allKeyLength
	if keysEnd < NodeHeaderBytes {
		return nil, corruptf("a B+tree node's key area overflows")
	}
	lengthsStart := (keysEnd + 7) &^ 7
	valuesStart := lengthsStart + numKeys*2
	used := valuesStart + numKeys*8
	if used < valuesStart || keysEnd > len(raw) || used > len(raw) {
		return nil, corruptf("a B+tree node declares %d keys (%d key bytes) but needs %d of its %d bytes",
			numKeys, allKeyLength, used, len(raw))
	}
	if numKeys == 0 {
		if allKeyLength != 0 {
			return nil, corruptf("a B+tree node has key bytes but no keys")
		}
	} else {
		previous := 0
		for index := 0; index < numKeys; index++ {
			at := lengthsStart + index*2
			total := int(le16(raw, at))
			if total < previous {
				return nil, corruptf("a B+tree node's key lengths are not cumulative at key %d", index)
			}
			length := total - previous
			if length < MinKeyLength || length > MaxKeyLength {
				return nil, corruptf("a B+tree node's key %d is %d bytes; keys are %d..=%d bytes",
					index, length, MinKeyLength, MaxKeyLength)
			}
			previous = total
		}
		if previous != allKeyLength {
			return nil, corruptf("a B+tree node's last key ends at %d, but its key area is %d bytes",
				previous, allKeyLength)
		}
	}
	return &btreeNode{
		bytes:        raw,
		numKeys:      numKeys,
		allKeyLength: allKeyLength,
		right:        right,
		overflow:     overflow,
	}, nil
}

func (n *btreeNode) isLeaf() bool { return n.overflow == BPlusTreeNull }

func (n *btreeNode) key(index int) ([]byte, error) {
	if index >= n.numKeys {
		return nil, corruptf("B+tree key %d is outside a node with %d keys", index, n.numKeys)
	}
	lengthsStart := (NodeHeaderBytes + n.allKeyLength + 7) &^ 7
	start := NodeHeaderBytes
	total := 0
	for at := 0; at < index; at++ {
		total = int(le16(n.bytes, lengthsStart+at*2))
	}
	start += total
	end := int(le16(n.bytes, lengthsStart+index*2))
	from := start
	to := NodeHeaderBytes + end
	if to > len(n.bytes) || from > to {
		return nil, corruptf("a B+tree key runs outside its node")
	}
	return n.bytes[from:to], nil
}

func (n *btreeNode) value(index int) (int64, error) {
	if index >= n.numKeys {
		return 0, corruptf("B+tree value %d is outside a node with %d keys", index, n.numKeys)
	}
	lengthsStart := (NodeHeaderBytes + n.allKeyLength + 7) &^ 7
	valuesStart := lengthsStart + n.numKeys*2
	at := valuesStart + index*8
	return int64(le64(n.bytes, at)), nil
}

func reverse32(value uint32) uint32 {
	return value<<24 | value>>24 | (value>>8)&0xff00 | (value<<8)&0xff0000
}
