package reiserfs

// ReiserFS tree nodes. Every node starts with a 24-byte block head; a leaf
// follows it with items, and an internal node follows it with keys and one
// more child pointer than keys.
const (
	// BlockHeadLen is the bytes in a block head.
	BlockHeadLen = 24
	// DiskChildLen is the bytes in an internal child pointer.
	DiskChildLen = 8
	// FreeLevel marks a freed block, never a live node.
	FreeLevel uint16 = 0
	// LeafLevel marks a leaf node.
	LeafLevel uint16 = 1
	// LEAF_LEVEL is the on-disk name for LeafLevel.
	LEAF_LEVEL = LeafLevel
)

// BlockHead is a decoded node header.
type BlockHead struct {
	Level              uint16
	NrItems            uint16
	FreeSpace          uint16
	Reserved           uint16
	RightDelimitingKey Key
}

// IsLeaf reports whether the node is a leaf.
func (h BlockHead) IsLeaf() bool { return h.Level == LeafLevel }

// IsInternal reports whether the node is an internal level the format defines.
func (h BlockHead) IsInternal() bool { return h.Level >= 2 && h.Level <= MaxHeight }

// DiskChild is one pointer from an internal node to a child.
type DiskChild struct {
	Block    uint32
	Size     uint16
	Reserved uint16
}

// InternalNode is an internal node's keys and child pointers.
type InternalNode struct {
	Keys     []Key
	Children []DiskChild
}

// ParseBlockHead decodes a node header. The right delimiting key uses the
// filesystem's key encoding because an internal key carries no item version.
func ParseBlockHead(raw []byte, keyVersion KeyVersion) (*BlockHead, error) {
	if len(raw) < BlockHeadLen {
		return nil, corruptf("a block is %d bytes, shorter than the %d-byte block head", len(raw), BlockHeadLen)
	}
	key, err := ParseKey(raw, 8, keyVersion)
	if err != nil {
		return nil, err
	}
	return &BlockHead{
		Level:              le16(raw, 0),
		NrItems:            le16(raw, 2),
		FreeSpace:          le16(raw, 4),
		Reserved:           le16(raw, 6),
		RightDelimitingKey: *key,
	}, nil
}

func parseLeaf(block uint32, raw []byte, head *BlockHead, blockSize int) ([]LeafItem, error) {
	if head.Level != LeafLevel {
		return nil, corruptf("block %d has level %d, not the leaf level %d", block, head.Level, LeafLevel)
	}
	return parseLeafItems(block, raw, head.NrItems, blockSize)
}

func parseInternal(raw []byte, head *BlockHead, blockSize int, keyVersion KeyVersion) (*InternalNode, error) {
	if !head.IsInternal() {
		return nil, corruptf("block has level %d, not an internal level 2..=%d", head.Level, MaxHeight)
	}
	nrItems := int(head.NrItems)
	keysEnd := BlockHeadLen + nrItems*KeyLen
	if keysEnd < BlockHeadLen {
		return nil, corruptf("the key array length overflows")
	}
	childCount := nrItems + 1
	childrenEnd := keysEnd + childCount*DiskChildLen
	if childrenEnd < keysEnd || childrenEnd > blockSize {
		return nil, corruptf("an internal node with %d keys needs %d bytes of a %d-byte node",
			nrItems, childrenEnd, blockSize)
	}
	keys := make([]Key, 0, nrItems)
	for index := 0; index < nrItems; index++ {
		key, err := ParseKey(raw, BlockHeadLen+index*KeyLen, keyVersion)
		if err != nil {
			return nil, err
		}
		keys = append(keys, *key)
	}
	children := make([]DiskChild, 0, childCount)
	for index := 0; index < childCount; index++ {
		at := keysEnd + index*DiskChildLen
		children = append(children, DiskChild{
			Block:    le32(raw, at),
			Size:     le16(raw, at+4),
			Reserved: le16(raw, at+6),
		})
	}
	return &InternalNode{Keys: keys, Children: children}, nil
}
