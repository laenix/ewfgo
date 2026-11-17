package hfsplus

// A reader for the HFS+ B-tree files.
//
// The catalog, extents-overflow, and attributes files all share one node
// format:
//
//	node:   [descriptor 14B][record 0][record 1]...[free space][offset table]
//	record: [keyLength u16][key (padded to even)][record data]
//
// The offset table at the end of a node holds records+1 big-endian offsets;
// the last is the start of free space.  This module is key-agnostic: callers
// pass a comparison over raw key payloads, so the catalog (case-folded names)
// and the extents tree (big-endian integers) share the traversal code.

import (
	"math/bits"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	nodeDescriptorLen = 14
	headerRecordLen   = 106
	minNodeSize       = 512
	maxNodeSize       = 32 * 1024
	maxTreeDepth      = 16
	maxNodeCount      = 4_000_000

	keyCompareBinary      = 0xBC
	keyCompareCaseFolding = 0xCF
)

// NodeKind is the node descriptor's kind byte.
type NodeKind int8

const (
	// NodeLeaf carries keyed records.
	NodeLeaf NodeKind = -1
	// NodeIndex routes to child nodes.
	NodeIndex NodeKind = 0
	// NodeHeader is node 0.
	NodeHeader NodeKind = 1
	// NodeMapKind carries the used/free node bitmap.
	NodeMapKind NodeKind = 2
)

func (k NodeKind) String() string {
	switch k {
	case NodeLeaf:
		return "leaf"
	case NodeIndex:
		return "index"
	case NodeHeader:
		return "header"
	case NodeMapKind:
		return "map"
	default:
		return "unknown"
	}
}

// NodeDescriptor is the 14-byte prefix of every node.
type NodeDescriptor struct {
	Forward  uint32
	Backward uint32
	Kind     NodeKind
	Height   uint8
	Records  uint16
}

// Node is one parsed B-tree node.
type Node struct {
	bytes      []byte
	descriptor NodeDescriptor
	offsets    []uint16
}

func parseNode(bytes []byte) (*Node, error) {
	if len(bytes) < nodeDescriptorLen+2 {
		return nil, invalidf("B-tree node is %d bytes, smaller than a descriptor", len(bytes))
	}
	descriptor := NodeDescriptor{
		Forward:  be32(bytes, 0),
		Backward: be32(bytes, 4),
		Kind:     NodeKind(int8(bytes[8])),
		Height:   bytes[9],
		Records:  be16(bytes, 10),
	}
	records := int(descriptor.Records)
	if records+1 > (len(bytes)-nodeDescriptorLen)/2 {
		return nil, invalidf("node declares %d records, more than its %d bytes can index", records, len(bytes))
	}
	tableStart := len(bytes) - 2*(records+1)
	offsets := make([]uint16, records+1)
	for i := 0; i <= records; i++ {
		offsets[i] = be16(bytes, tableStart+2*i)
	}
	free := int(offsets[records])
	if free > tableStart {
		return nil, invalidf("free-space offset %d overlaps the offset table at %d", free, tableStart)
	}
	previous := uint16(nodeDescriptorLen)
	for _, offset := range offsets {
		if offset < previous || int(offset) > free {
			return nil, invalidf("record offset %d is out of order or beyond free space %d", offset, free)
		}
		previous = offset
	}
	if descriptor.Kind == NodeHeader && int(offsets[0]) != nodeDescriptorLen {
		return nil, invalidf("header node's first record starts at %d, expected %d", offsets[0], nodeDescriptorLen)
	}
	return &Node{bytes: bytes, descriptor: descriptor, offsets: offsets}, nil
}

// Descriptor returns the node descriptor.
func (n *Node) Descriptor() NodeDescriptor { return n.descriptor }

// Kind returns the node kind.
func (n *Node) Kind() NodeKind { return n.descriptor.Kind }

// RecordCount returns the number of records.
func (n *Node) RecordCount() int { return int(n.descriptor.Records) }

// Bytes returns the node bytes, free space and offset table included.
func (n *Node) Bytes() []byte { return n.bytes }

// freeSpace returns the unused region between the last record and the offset
// table, where a deleted record's bytes can outlive the deletion.
func (n *Node) freeSpace() (int, int) {
	start := int(n.offsets[len(n.offsets)-1])
	end := len(n.bytes) - 2*len(n.offsets)
	return start, end
}

func (n *Node) record(index int) ([]byte, error) {
	if index < 0 || index >= n.RecordCount() {
		return nil, invalidf("record %d is outside a node with %d records", index, n.RecordCount())
	}
	return n.bytes[int(n.offsets[index]):int(n.offsets[index+1])], nil
}

func (n *Node) key(index int) ([]byte, error) {
	record, err := n.record(index)
	if err != nil {
		return nil, err
	}
	if len(record) < 2 {
		return nil, invalidf("record is too short to carry a key length")
	}
	keyLen := int(be16(record, 0))
	if 2+keyLen > len(record) {
		return nil, invalidf("record %d key length %d exceeds its %d bytes", index, keyLen, len(record))
	}
	return record[2 : 2+keyLen], nil
}

func (n *Node) data(index int) ([]byte, error) {
	record, err := n.record(index)
	if err != nil {
		return nil, err
	}
	if len(record) < 2 {
		return nil, invalidf("record is too short to carry a key length")
	}
	keyLen := int(be16(record, 0))
	dataStart := (2 + keyLen + 1) &^ 1
	if dataStart > len(record) {
		return nil, invalidf("record %d data starts at %d, past its %d bytes", index, dataStart, len(record))
	}
	return record[dataStart:], nil
}

func (n *Node) child(index int) (uint32, error) {
	data, err := n.data(index)
	if err != nil {
		return 0, err
	}
	if len(data) < 4 {
		return 0, invalidf("index record %d carries %d bytes of child pointer", index, len(data))
	}
	return be32(data, 0), nil
}

// TreeHeader is the BTHeaderRec read from node 0.
type TreeHeader struct {
	Depth          uint16
	Root           uint32
	LeafRecords    uint32
	FirstLeaf      uint32
	LastLeaf       uint32
	NodeSize       uint16
	MaxKeyLen      uint16
	TotalNodes     uint32
	FreeNodes      uint32
	KeyCompareType uint8
}

func parseTreeHeader(bytes []byte) (*TreeHeader, error) {
	if len(bytes) < headerRecordLen {
		return nil, invalidf("B-tree header record is %d bytes, expected %d", len(bytes), headerRecordLen)
	}
	return &TreeHeader{
		Depth:          be16(bytes, 0),
		Root:           be32(bytes, 2),
		LeafRecords:    be32(bytes, 6),
		FirstLeaf:      be32(bytes, 10),
		LastLeaf:       be32(bytes, 14),
		NodeSize:       be16(bytes, 18),
		MaxKeyLen:      be16(bytes, 20),
		TotalNodes:     be32(bytes, 22),
		FreeNodes:      be32(bytes, 26),
		KeyCompareType: bytes[37],
	}, nil
}

// IsEmpty reports whether the tree declares no depth.
func (h *TreeHeader) IsEmpty() bool { return h.Depth == 0 }

// BinaryCompare reports whether the tree uses HFSX's byte-wise comparison.
func (h *TreeHeader) BinaryCompare() bool { return h.KeyCompareType == keyCompareBinary }

// NodeMap is the used/free bitmap in a header node's map record.
type NodeMap struct {
	bitmap     []byte
	totalNodes uint32
}

func parseNodeMap(node *Node, header *TreeHeader, logicalSize uint64) (*NodeMap, error) {
	if node.Kind() != NodeHeader {
		return nil, invalidf("node 0 is a %s node, not a header node", node.Kind())
	}
	if header.TotalNodes == 0 {
		return nil, invalidf("B-tree header declares zero nodes")
	}
	if len(node.bytes) != int(header.NodeSize) {
		return nil, invalidf("header node is %d bytes, but the header declares node size %d", len(node.bytes), header.NodeSize)
	}
	nodesBytes := uint64(header.TotalNodes) * uint64(header.NodeSize)
	if nodesBytes > logicalSize {
		return nil, invalidf("B-tree declares %d bytes of nodes but its fork holds %d", nodesBytes, logicalSize)
	}
	if node.RecordCount() < 3 {
		return nil, invalidf("header node holds %d record(s), so it has no map record", node.RecordCount())
	}
	record, err := node.record(2)
	if err != nil {
		return nil, err
	}
	needed := (int(header.TotalNodes) + 7) / 8
	if len(record) < needed {
		return nil, invalidf("map record is %d bytes, less than the %d byte(s) its %d nodes need", len(record), needed, header.TotalNodes)
	}
	return &NodeMap{bitmap: append([]byte(nil), record[:needed]...), totalNodes: header.TotalNodes}, nil
}

// TotalNodes returns the number of nodes the map describes.
func (m *NodeMap) TotalNodes() uint32 { return m.totalNodes }

// IsUsed reports whether the map marks a node in use.  Out-of-range numbers
// are never in use.
func (m *NodeMap) IsUsed(number uint32) bool {
	if number >= m.totalNodes {
		return false
	}
	return m.bitmap[number/8]&(0x80>>(number%8)) != 0
}

// UsedNodes counts the nodes marked in use.
func (m *NodeMap) UsedNodes() uint32 {
	var used uint32
	for _, b := range m.bitmap {
		used += uint32(bits.OnesCount8(b))
	}
	padding := len(m.bitmap)*8 - int(m.totalNodes)
	if padding > 0 {
		mask := byte(0xFF >> (8 - padding))
		used -= uint32(bits.OnesCount8(m.bitmap[len(m.bitmap)-1] & mask))
	}
	return used
}

// FreeNodes counts the nodes marked free.
func (m *NodeMap) FreeNodes() uint32 { return m.totalNodes - m.UsedNodes() }

// KeyCompare orders two key payloads.
type KeyCompare func(a, b []byte) int

// BTree is one of the volume's B-tree files.
type BTree struct {
	header      TreeHeader
	extents     ForkExtents
	blockSize   uint32
	logicalSize uint64
}

func openBTree(src source.ByteSource, blockSize uint32, fork Fork, extents ForkExtents, requireCovered bool) (*BTree, error) {
	if extents.IsEmpty() {
		return nil, invalidf("B-tree fork has no extents")
	}
	// The node size lives inside node 0, so read the smallest legal node first.
	prefix := make([]byte, minNodeSize)
	if err := extents.ReadExact(src, blockSize, 0, prefix); err != nil {
		return nil, err
	}
	nodeSize := be16(prefix, nodeDescriptorLen+18)
	if nodeSize < minNodeSize || nodeSize > maxNodeSize || nodeSize&(nodeSize-1) != 0 {
		return nil, invalidf("B-tree node size %d is not a power of two in %d..=%d", nodeSize, minNodeSize, maxNodeSize)
	}
	node0 := make([]byte, int(nodeSize))
	if err := extents.ReadExact(src, blockSize, 0, node0); err != nil {
		return nil, err
	}
	node, err := parseNode(node0)
	if err != nil {
		return nil, err
	}
	if node.Kind() != NodeHeader {
		return nil, invalidf("B-tree node 0 is a %s node, expected a header node", node.Kind())
	}
	header, err := parseTreeHeader(node.bytes[nodeDescriptorLen:])
	if err != nil {
		return nil, err
	}
	if header.NodeSize != nodeSize {
		return nil, invalidf("B-tree header declares node size %d, but node 0 is %d bytes", header.NodeSize, nodeSize)
	}
	if header.TotalNodes == 0 {
		return nil, invalidf("B-tree declares zero nodes")
	}
	if header.TotalNodes > maxNodeCount {
		return nil, unsupportedf("B-tree declares %d nodes, above the %d node safety limit", header.TotalNodes, maxNodeCount)
	}
	if header.Depth > maxTreeDepth {
		return nil, unsupportedf("B-tree depth %d exceeds the %d level safety limit", header.Depth, maxTreeDepth)
	}
	nodesBytes := uint64(header.TotalNodes) * uint64(nodeSize)
	if nodesBytes > fork.LogicalSize {
		return nil, invalidf("B-tree declares %d bytes of nodes but its fork holds %d", nodesBytes, fork.LogicalSize)
	}
	if requireCovered && nodesBytes > extents.CoveredBytes(blockSize) {
		return nil, unsupportedf("B-tree needs %d bytes but its known extents cover %d", nodesBytes, extents.CoveredBytes(blockSize))
	}
	if header.Depth == 0 {
		if header.Root != 0 || header.FirstLeaf != 0 || header.LastLeaf != 0 {
			return nil, invalidf("empty B-tree still references a root or leaf node")
		}
	} else {
		for _, ref := range []struct {
			what string
			node uint32
		}{{"root", header.Root}, {"first leaf", header.FirstLeaf}, {"last leaf", header.LastLeaf}} {
			if ref.node >= header.TotalNodes {
				return nil, invalidf("B-tree %s node %d is outside %d nodes", ref.what, ref.node, header.TotalNodes)
			}
		}
	}
	return &BTree{header: *header, extents: extents, blockSize: blockSize, logicalSize: fork.LogicalSize}, nil
}

// Header returns the tree header.
func (t *BTree) Header() *TreeHeader { return &t.header }

// Extents returns the tree's resolved extents.
func (t *BTree) Extents() ForkExtents { return t.extents }

// NodeMap reads node 0's map record.
func (t *BTree) NodeMap(src source.ByteSource) (*NodeMap, error) {
	node, err := t.node(src, 0)
	if err != nil {
		return nil, err
	}
	return parseNodeMap(node, &t.header, t.logicalSize)
}

func (t *BTree) node(src source.ByteSource, number uint32) (*Node, error) {
	if number >= t.header.TotalNodes {
		return nil, invalidf("B-tree node %d is outside %d nodes", number, t.header.TotalNodes)
	}
	offset := uint64(number) * uint64(t.header.NodeSize)
	bytes := make([]byte, int(t.header.NodeSize))
	if err := t.extents.ReadExact(src, t.blockSize, offset, bytes); err != nil {
		return nil, err
	}
	return parseNode(bytes)
}

func (t *BTree) findLeaf(src source.ByteSource, target []byte, compare KeyCompare) (*Node, int, error) {
	number := t.header.Root
	remaining := t.header.Depth
	for {
		node, err := t.node(src, number)
		if err != nil {
			return nil, 0, err
		}
		switch node.Kind() {
		case NodeLeaf:
			index := 0
			for index < node.RecordCount() {
				key, err := node.key(index)
				if err != nil {
					return nil, 0, err
				}
				if compare(key, target) >= 0 {
					break
				}
				index++
			}
			return node, index, nil
		case NodeIndex:
			count := node.RecordCount()
			if count == 0 {
				return nil, 0, invalidf("index node has no records")
			}
			chosen := 0
			for index := 0; index < count; index++ {
				key, err := node.key(index)
				if err != nil {
					return nil, 0, err
				}
				if compare(key, target) > 0 {
					break
				}
				chosen = index
			}
			child, err := node.child(chosen)
			if err != nil {
				return nil, 0, err
			}
			number = child
			if remaining == 0 {
				return nil, 0, invalidf("index chain is deeper than the header's declared tree depth")
			}
			remaining--
		default:
			return nil, 0, invalidf("expected an index or leaf node, found a %s node", node.Kind())
		}
	}
}

// Lookup finds an exact key, returning its key and data bytes.
func (t *BTree) Lookup(src source.ByteSource, target []byte, compare KeyCompare) (key, data []byte, found bool, err error) {
	if t.header.Depth == 0 {
		return nil, nil, false, nil
	}
	err = t.Scan(src, target, compare, func(recordKey, recordData []byte) (bool, error) {
		switch cmp := compare(recordKey, target); {
		case cmp < 0:
			return true, nil
		case cmp > 0:
			return false, nil
		default:
			key = append([]byte(nil), recordKey...)
			data = append([]byte(nil), recordData...)
			found = true
			return false, nil
		}
	})
	return key, data, found, err
}

// Scan visits leaf records in key order from start.  Returning false from the
// visitor stops the walk.
func (t *BTree) Scan(src source.ByteSource, start []byte, compare KeyCompare, visit func(key, data []byte) (bool, error)) error {
	if t.header.Depth == 0 {
		return nil
	}
	node, index, err := t.findLeaf(src, start, compare)
	if err != nil {
		return err
	}
	var visited uint32
	for {
		for index < node.RecordCount() {
			key, err := node.key(index)
			if err != nil {
				return err
			}
			data, err := node.data(index)
			if err != nil {
				return err
			}
			cont, err := visit(key, data)
			if err != nil {
				return err
			}
			if !cont {
				return nil
			}
			index++
		}
		visited++
		if visited > t.header.TotalNodes {
			return invalidf("B-tree leaf chain loops back on itself")
		}
		next := node.Descriptor().Forward
		if next == 0 {
			return nil
		}
		if next >= t.header.TotalNodes {
			return invalidf("leaf forward link %d is outside %d nodes", next, t.header.TotalNodes)
		}
		node, err = t.node(src, next)
		if err != nil {
			return err
		}
		if node.Kind() != NodeLeaf {
			return invalidf("leaf forward link points at a %s node", node.Kind())
		}
		index = 0
	}
}

// ScanAll visits every leaf record in key order.  An empty key is below every
// real key in both comparators.
func (t *BTree) ScanAll(src source.ByteSource, compare KeyCompare, visit func(key, data []byte) (bool, error)) error {
	return t.Scan(src, nil, compare, visit)
}

// forEachLeaf visits each leaf node of the chain.
func (t *BTree) forEachLeaf(src source.ByteSource, visit func(number uint32, node *Node) (bool, error)) error {
	if t.header.Depth == 0 {
		return nil
	}
	number := t.header.FirstLeaf
	var visited uint32
	for {
		node, err := t.node(src, number)
		if err != nil {
			return err
		}
		if node.Kind() != NodeLeaf {
			return invalidf("leaf chain reached node %d, a %s node", number, node.Kind())
		}
		cont, err := visit(number, node)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
		visited++
		if visited > t.header.TotalNodes {
			return invalidf("B-tree leaf chain loops back on itself")
		}
		next := node.Descriptor().Forward
		if next == 0 {
			return nil
		}
		if next >= t.header.TotalNodes {
			return invalidf("leaf forward link %d is outside %d nodes", next, t.header.TotalNodes)
		}
		number = next
	}
}
