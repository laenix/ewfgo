package hfs

import (
	"bytes"

	"github.com/laenix/ewfgo/internal/data/source"
)

// NodeDescriptorBytes is the size of a node descriptor.
const NodeDescriptorBytes = 14

// HeaderRecordBytes is the size of the header record in the header node.
const HeaderRecordBytes = 106

// MinNodeSize is the smallest node a valid tree may declare.
const MinNodeSize = 512

// MaxNodeSize is the largest node this reader accepts.
const MaxNodeSize = 32 * 1024

// MaxTreeDepth bounds a search descent.
const MaxTreeDepth = 16

// treeHeader is the catalog or extents tree header record.
type treeHeader struct {
	depth         uint16
	rootNode      uint32
	leafRecords   uint32
	firstLeafNode uint32
	lastLeafNode  uint32
	nodeSize      uint16
	maxKeyLength  uint16
	totalNodes    uint32
	freeNodes     uint32
	clumpSize     uint32
	btreeType     uint8
	keyCompare    uint8
	attributes    uint32
}

// nodeDescriptor is one node's 14-byte descriptor.
type nodeDescriptor struct {
	forward  uint32
	backward uint32
	kind     int8
	height   uint8
	records  uint16
}

func (d nodeDescriptor) isLeaf() bool   { return d.kind == -1 }
func (d nodeDescriptor) isIndex() bool  { return d.kind == 0 }
func (d nodeDescriptor) isHeader() bool { return d.kind == 1 }

// bTree is a tree over one fork.
type bTree struct {
	src    source.ByteSource
	fork   fork
	header treeHeader
}

// openBTree reads the header node and validates the tree geometry.
func openBTree(src source.ByteSource, value fork) (*bTree, error) {
	if value.logicalSize < MinNodeSize {
		return nil, corruptf("a B-tree fork of %d bytes cannot hold a header node", value.logicalSize)
	}
	head := make([]byte, MinNodeSize)
	got, err := value.readAt(src, 0, head)
	if err != nil {
		return nil, err
	}
	if got != len(head) {
		return nil, source.NewUnexpectedEOF(uint64(got))
	}
	descriptor, err := readNodeDescriptor(head)
	if err != nil {
		return nil, err
	}
	if !descriptor.isHeader() {
		return nil, corruptf("the first B-tree node is kind %d rather than a header node", descriptor.kind)
	}
	if len(head)-NodeDescriptorBytes < HeaderRecordBytes {
		return nil, corruptf("the header record is truncated")
	}
	header, err := readTreeHeader(head[NodeDescriptorBytes : NodeDescriptorBytes+HeaderRecordBytes])
	if err != nil {
		return nil, err
	}
	if header.nodeSize < MinNodeSize || header.nodeSize > MaxNodeSize || header.nodeSize&(header.nodeSize-1) != 0 {
		return nil, corruptf("the tree declares node size %d, which is not a power of two between %d and %d",
			header.nodeSize, MinNodeSize, MaxNodeSize)
	}
	if header.totalNodes == 0 {
		return nil, corruptf("the tree declares no nodes")
	}
	if uint64(header.nodeSize) > value.logicalSize {
		return nil, corruptf("a %d byte node does not fit the tree's %d byte fork",
			header.nodeSize, value.logicalSize)
	}
	return &bTree{src: src, fork: value, header: header}, nil
}

// walkLeaves visits every leaf record in tree order.
func (t *bTree) walkLeaves(visit func(key, data []byte) (bool, error)) error {
	nodeNumber := t.header.firstLeafNode
	var seen uint64
	for {
		if nodeNumber == 0 {
			return nil
		}
		if seen >= uint64(t.header.totalNodes) {
			return corruptf("the leaf chain revisits more nodes than the tree declares")
		}
		seen++
		node, err := t.readNode(nodeNumber)
		if err != nil {
			return err
		}
		descriptor, err := readNodeDescriptor(node)
		if err != nil {
			return err
		}
		if !descriptor.isLeaf() {
			return corruptf("node %d in the leaf chain is kind %d", nodeNumber, descriptor.kind)
		}
		offsets, err := t.readOffsets(node, descriptor)
		if err != nil {
			return err
		}
		for index := 0; index < int(descriptor.records); index++ {
			key, data, deleted, err := recordParts(node, offsets[index], offsets[index+1])
			if err != nil {
				return err
			}
			if deleted {
				continue
			}
			keep, err := visit(key, data)
			if err != nil {
				return err
			}
			if !keep {
				return nil
			}
		}
		nodeNumber = descriptor.forward
	}
}

// search returns the data of the leaf record whose key equals target. Keys
// compare byte for byte.
func (t *bTree) search(target []byte) ([]byte, error) {
	nodeNumber := t.header.rootNode
	depth := uint16(0)
	maxDepth := t.header.depth
	if maxDepth > MaxTreeDepth {
		maxDepth = MaxTreeDepth
	}
	for nodeNumber != 0 {
		if depth > maxDepth {
			return nil, corruptf("the tree descends deeper than its header declares")
		}
		depth++
		node, err := t.readNode(nodeNumber)
		if err != nil {
			return nil, err
		}
		descriptor, err := readNodeDescriptor(node)
		if err != nil {
			return nil, err
		}
		offsets, err := t.readOffsets(node, descriptor)
		if err != nil {
			return nil, err
		}
		if descriptor.isLeaf() {
			for index := 0; index < int(descriptor.records); index++ {
				key, data, deleted, err := recordParts(node, offsets[index], offsets[index+1])
				if err != nil {
					return nil, err
				}
				if deleted {
					continue
				}
				if bytes.Equal(key, target) {
					return append([]byte(nil), data...), nil
				}
			}
			return nil, nil
		}
		if !descriptor.isIndex() {
			return nil, corruptf("node %d on the search path is kind %d", nodeNumber, descriptor.kind)
		}
		chosen := -1
		first := -1
		for index := 0; index < int(descriptor.records); index++ {
			key, data, deleted, err := recordParts(node, offsets[index], offsets[index+1])
			if err != nil {
				return nil, err
			}
			if deleted {
				continue
			}
			if len(data) < 4 {
				return nil, corruptf("an index record in node %d has no child number", nodeNumber)
			}
			child := int(be32(data, 0))
			if first < 0 {
				first = child
			}
			if bytes.Compare(key, target) <= 0 {
				chosen = child
			} else {
				break
			}
		}
		switch {
		case chosen >= 0:
			nodeNumber = uint32(chosen)
		case first >= 0:
			nodeNumber = uint32(first)
		default:
			nodeNumber = 0
		}
	}
	return nil, nil
}

// readNode reads one whole node.
func (t *bTree) readNode(number uint32) ([]byte, error) {
	size := uint64(t.header.nodeSize)
	if uint64(number) > (^uint64(0))/size {
		return nil, corruptf("a node offset overflows the address space")
	}
	offset := uint64(number) * size
	if offset > t.fork.logicalSize || size > t.fork.logicalSize-offset {
		return nil, corruptf("node %d starts at %d, past the tree's %d bytes", number, offset, t.fork.logicalSize)
	}
	node := make([]byte, int(size))
	got, err := t.fork.readAt(t.src, offset, node)
	if err != nil {
		return nil, err
	}
	if got != len(node) {
		return nil, source.NewUnexpectedEOF(offset + uint64(got))
	}
	return node, nil
}

// readOffsets reads and validates a node's offset table.
func (t *bTree) readOffsets(node []byte, descriptor nodeDescriptor) ([]int, error) {
	count := int(descriptor.records)
	entries := count + 1
	tableBytes := entries * 2
	if tableBytes/2 != entries {
		return nil, corruptf("a node's offset table overflows")
	}
	tableStart := len(node) - tableBytes
	if tableStart < NodeDescriptorBytes {
		return nil, corruptf("a node's offset table runs into its descriptor")
	}
	offsets := make([]int, entries)
	for index := 0; index < entries; index++ {
		at := tableStart + index*2
		offsets[index] = int(be16(node, at))
	}
	for index := 0; index+1 < len(offsets); index++ {
		first, second := offsets[index], offsets[index+1]
		if first < NodeDescriptorBytes || first > second || second > tableStart {
			return nil, corruptf("a node's record offsets are not monotonic inside the node")
		}
	}
	return offsets, nil
}

// recordParts splits one record into its key and data. A zero key length
// marks a deleted record, whose key and data are gone.
func recordParts(node []byte, start, end int) (key, data []byte, deleted bool, err error) {
	if start < 0 || start >= end || end > len(node) {
		return nil, nil, false, corruptf("a record's offsets do not name a byte range")
	}
	keyLength := int(node[start])
	if keyLength == 0 {
		return nil, nil, true, nil
	}
	keyStart := start + 1
	keyEnd := keyStart + keyLength
	if keyEnd < keyStart || keyEnd > end {
		return nil, nil, false, corruptf("a record's key runs into the next record")
	}
	dataStart := keyEnd
	if (1+keyLength)%2 == 1 {
		dataStart++
	}
	if dataStart > end {
		return nil, nil, false, corruptf("a record's padded key runs into the next record")
	}
	return node[keyStart:keyEnd], node[dataStart:end], false, nil
}

func readNodeDescriptor(node []byte) (nodeDescriptor, error) {
	if len(node) < NodeDescriptorBytes {
		return nodeDescriptor{}, corruptf("a node is shorter than its descriptor")
	}
	return nodeDescriptor{
		forward:  be32(node, 0),
		backward: be32(node, 4),
		kind:     int8(node[8]),
		height:   node[9],
		records:  be16(node, 10),
	}, nil
}

func readTreeHeader(raw []byte) (treeHeader, error) {
	if len(raw) < HeaderRecordBytes {
		return treeHeader{}, corruptf("the header record is truncated")
	}
	return treeHeader{
		depth:         be16(raw, 0),
		rootNode:      be32(raw, 2),
		leafRecords:   be32(raw, 6),
		firstLeafNode: be32(raw, 10),
		lastLeafNode:  be32(raw, 14),
		nodeSize:      be16(raw, 18),
		maxKeyLength:  be16(raw, 20),
		totalNodes:    be32(raw, 22),
		freeNodes:     be32(raw, 26),
		clumpSize:     be32(raw, 32),
		btreeType:     raw[36],
		keyCompare:    raw[37],
		attributes:    be32(raw, 38),
	}, nil
}

func be16(raw []byte, at int) uint16 { return uint16(raw[at])<<8 | uint16(raw[at+1]) }

func be32(raw []byte, at int) uint32 {
	return uint32(raw[at])<<24 | uint32(raw[at+1])<<16 | uint32(raw[at+2])<<8 | uint32(raw[at+3])
}
