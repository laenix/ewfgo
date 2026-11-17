package reiserfs

// ReiserFS keys, item heads and leaf items. An item is named by a 16-byte key
// and described by a 24-byte item head. Both encodings changed between 3.5 and
// 3.6.
const (
	// KeyLen is the bytes in a key.
	KeyLen = 16
	// ItemHeadLen is the bytes in an item head.
	ItemHeadLen = 24
)

// Item type codes, in the kernel's numbering.
const (
	TypeStatData uint8 = 0
	TypeIndirect uint8 = 1
	TypeDirect   uint8 = 2
	TypeDirEntry uint8 = 3
	TypeAny      uint8 = 15
)

// Item versions stored in ih_version.
const (
	ItemVersion1 uint16 = 0
	ItemVersion2 uint16 = 1
)

// 3.5 uniqueness words.
const (
	V1StatUniqueness     uint32 = 0
	V1IndirectUniqueness uint32 = 0xffff_fffe
	V1DirectUniqueness   uint32 = 0xffff_ffff
	V1DirEntryUniqueness uint32 = 500
	V1AnyUniqueness      uint32 = 555
)

// OffsetV2Mask is the low 60 bits of a 3.6 offset word.
const OffsetV2Mask uint64 = uint64(1)<<60 - 1

// OffsetV2TypeShift is the item type's shift in a 3.6 offset word.
const OffsetV2TypeShift uint32 = 60

// KeyVersion is which key encoding an item uses.
type KeyVersion int

const (
	// KeyVersionV1 is the 3.5 encoding.
	KeyVersionV1 KeyVersion = iota
	// KeyVersionV2 is the 3.6 encoding.
	KeyVersionV2
)

func keyVersionFromItemVersion(version uint16) KeyVersion {
	if version&0x7fff == ItemVersion1 {
		return KeyVersionV1
	}
	return KeyVersionV2
}

// ItemType is the decoded item kind.
type ItemType int

const (
	// ItemTypeStatData is stat data: mode, ownership, size and times.
	ItemTypeStatData ItemType = iota
	// ItemTypeIndirect is an array of 32-bit block pointers.
	ItemTypeIndirect
	// ItemTypeDirect is file bytes stored in the leaf.
	ItemTypeDirect
	// ItemTypeDirEntry is a directory entry body.
	ItemTypeDirEntry
	// ItemTypeAny is the comparison wildcard.
	ItemTypeAny
	// ItemTypeUnknown is a type with no documented meaning. RawType keeps the
	// number.
	ItemTypeUnknown
)

func itemTypeFromV2(code uint8) ItemType {
	switch code {
	case TypeStatData:
		return ItemTypeStatData
	case TypeIndirect:
		return ItemTypeIndirect
	case TypeDirect:
		return ItemTypeDirect
	case TypeDirEntry:
		return ItemTypeDirEntry
	case TypeAny:
		return ItemTypeAny
	default:
		return ItemTypeUnknown
	}
}

func itemTypeFromV1(uniqueness uint32) ItemType {
	switch uniqueness {
	case V1StatUniqueness:
		return ItemTypeStatData
	case V1IndirectUniqueness:
		return ItemTypeIndirect
	case V1DirectUniqueness:
		return ItemTypeDirect
	case V1DirEntryUniqueness:
		return ItemTypeDirEntry
	case V1AnyUniqueness:
		return ItemTypeAny
	default:
		return ItemTypeUnknown
	}
}

// Name returns a human-readable item kind.
func (t ItemType) Name() string {
	switch t {
	case ItemTypeStatData:
		return "stat data"
	case ItemTypeIndirect:
		return "indirect"
	case ItemTypeDirect:
		return "direct"
	case ItemTypeDirEntry:
		return "directory entry"
	case ItemTypeAny:
		return "any"
	default:
		return "not decoded"
	}
}

// IsDecoded reports whether this reader interprets the body.
func (t ItemType) IsDecoded() bool {
	switch t {
	case ItemTypeStatData, ItemTypeIndirect, ItemTypeDirect, ItemTypeDirEntry:
		return true
	default:
		return false
	}
}

// Key is the 16-byte name of one item.
type Key struct {
	DirID    uint32
	ObjectID uint32
	Offset   uint64
	ItemType ItemType
	// RawType is the uniqueness word in 3.5 or the four-bit type in 3.6.
	RawType uint32
	Version KeyVersion
}

// ParseKey decodes a key at raw[at:at+16] using the given encoding.
func ParseKey(raw []byte, at int, version KeyVersion) (*Key, error) {
	if at < 0 || at+KeyLen > len(raw) || at+KeyLen < at {
		return nil, corruptf("a key at byte %d runs past the %d-byte node", at, len(raw))
	}
	key := &Key{
		DirID:    le32(raw, at),
		ObjectID: le32(raw, at+4),
		Version:  version,
	}
	if version == KeyVersionV1 {
		key.Offset = uint64(le32(raw, at+8))
		key.RawType = le32(raw, at+12)
		key.ItemType = itemTypeFromV1(key.RawType)
		return key, nil
	}
	word := le64(raw, at+8)
	code := uint8(word >> OffsetV2TypeShift)
	key.Offset = word & OffsetV2Mask
	key.ItemType = itemTypeFromV2(code)
	key.RawType = uint32(code)
	return key, nil
}

// V2SortWord returns the key's 3.6 sort word.
func (k Key) V2SortWord() uint64 {
	return uint64(k.RawType&0xf)<<OffsetV2TypeShift | (k.Offset & OffsetV2Mask)
}

// ItemHead describes one item body.
type ItemHead struct {
	Key Key
	// FreeSpaceOrCount is free space for an indirect item and the entry count
	// for a directory item.
	FreeSpaceOrCount uint16
	ItemLen          uint16
	Location         uint16
	Version          uint16
}

func (h ItemHead) bodyRange(blockSize int) (int, int, error) {
	start := int(h.Location)
	length := int(h.ItemLen)
	end := start + length
	if end < start || end > blockSize {
		return 0, 0, corruptf("item at byte %d with length %d reaches byte %d, past the %d-byte node",
			start, length, end, blockSize)
	}
	return start, end, nil
}

// LeafItem is one item body plus its key and head.
type LeafItem struct {
	Block uint32
	Head  ItemHead
	Body  []byte
}

// Key returns the item's key.
func (i LeafItem) Key() Key { return i.Head.Key }

// Describe names an item this reader does not decode.
func (i LeafItem) Describe() string {
	if i.Head.Key.ItemType == ItemTypeUnknown {
		return "item type " + itoa(uint64(i.Head.Key.RawType)) + " is not decoded (key " +
			itoa(uint64(i.Head.Key.DirID)) + "/" + itoa(uint64(i.Head.Key.ObjectID)) + "/" +
			itoa(i.Head.Key.Offset) + ", " + itoa(uint64(i.Head.ItemLen)) + " bytes)"
	}
	return i.Head.Key.ItemType.Name() + " item (key " +
		itoa(uint64(i.Head.Key.DirID)) + "/" + itoa(uint64(i.Head.Key.ObjectID)) + "/" +
		itoa(i.Head.Key.Offset) + ", " + itoa(uint64(i.Head.ItemLen)) + " bytes)"
}

func parseItemHead(raw []byte, at int) (ItemHead, error) {
	if at < 0 || at+ItemHeadLen > len(raw) || at+ItemHeadLen < at {
		return ItemHead{}, corruptf("an item head at byte %d runs past the %d-byte node", at, len(raw))
	}
	version := le16(raw, at+22)
	keyVersion := keyVersionFromItemVersion(version)
	key, err := ParseKey(raw, at, keyVersion)
	if err != nil {
		return ItemHead{}, err
	}
	return ItemHead{
		Key:              *key,
		FreeSpaceOrCount: le16(raw, at+16),
		ItemLen:          le16(raw, at+18),
		Location:         le16(raw, at+20),
		Version:          version,
	}, nil
}

func parseLeafItems(block uint32, raw []byte, nrItems uint16, blockSize int) ([]LeafItem, error) {
	if len(raw) < blockSize {
		return nil, corruptf("leaf block %d is %d bytes, shorter than its declared %d", block, len(raw), blockSize)
	}
	headsStart := BlockHeadLen
	headsEnd := headsStart + int(nrItems)*ItemHeadLen
	if headsEnd < headsStart || headsEnd > blockSize {
		return nil, corruptf("leaf block %d declares %d item heads, needing %d bytes of a %d-byte node",
			block, nrItems, headsEnd, blockSize)
	}
	items := make([]LeafItem, 0, nrItems)
	for index := 0; index < int(nrItems); index++ {
		at := headsStart + index*ItemHeadLen
		head, err := parseItemHead(raw, at)
		if err != nil {
			return nil, err
		}
		location := int(head.Location)
		start, end, err := head.bodyRange(blockSize)
		if err != nil {
			return nil, err
		}
		if location < headsEnd {
			return nil, corruptf("item %d in block %d puts its body at byte %d, inside the item table ending at byte %d",
				index, block, location, headsEnd)
		}
		body := make([]byte, end-start)
		copy(body, raw[start:end])
		items = append(items, LeafItem{Block: block, Head: head, Body: body})
	}
	return items, nil
}

// itoa is a tiny local integer formatter used in diagnostics only.
func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	at := len(buf)
	for value > 0 {
		at--
		buf[at] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[at:])
}
