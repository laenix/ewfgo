package hfsplus

// HFS+ extended attributes.
//
// Every xattr is one leaf record of the attributes B-tree, keyed by
// (file CNID, start block, name).  A small value lives inline in the record; a
// large one is described by a fork whose extents are resolved like a file
// fork's, with continuation records under the same name at increasing start
// blocks.
//
//	key payload:   [pad u16][file id u32][start block u32][name length u16][name]
//	inline record: [type 0x10][reserved 8B][size u32][value]
//	fork record:   [type 0x20][reserved 4B][fork 80B]
//	extents record:[type 0x30][reserved 4B][eight extents 64B]

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// Attribute record types.
const (
	// AttrInlineData is a value stored in the leaf record.
	AttrInlineData uint32 = 0x10
	// AttrForkData is a value whose fork is described inline.
	AttrForkData uint32 = 0x20
	// AttrExtents continues a fork-described value's extents.
	AttrExtents uint32 = 0x30

	// MaxAttrNameUnits is the longest attribute name HFS+ stores.
	MaxAttrNameUnits = 127
	// MaxAttributeBytes is the largest value this reader materialises.
	MaxAttributeBytes uint64 = 32 << 20

	maxAttributeOverflowRecords = 100_000
)

// AttrKey is an attributes B-tree key.
type AttrKey struct {
	FileID     uint32
	StartBlock uint32
	Name       Name
}

func parseAttrKey(payload []byte) (AttrKey, error) {
	if len(payload) < 12 {
		return AttrKey{}, invalidf("attribute key is %d bytes, too short for its fixed fields", len(payload))
	}
	length := int(be16(payload, 10))
	end := 12 + length*2
	if end > len(payload) {
		return AttrKey{}, invalidf("attribute key declares %d name units, past its %d bytes", length, len(payload))
	}
	units := make([]uint16, length)
	for i := 0; i < length; i++ {
		units[i] = be16(payload, 12+2*i)
	}
	return AttrKey{
		FileID:     be32(payload, 2),
		StartBlock: be32(payload, 6),
		Name:       Name{Units: units},
	}, nil
}

func encodeAttrKey(key AttrKey) ([]byte, error) {
	if key.Name.Len() > MaxAttrNameUnits {
		return nil, invalidf("attribute name is %d UTF-16 units, above the %d unit limit", key.Name.Len(), MaxAttrNameUnits)
	}
	out := make([]byte, 0, 12+2*key.Name.Len())
	out = append(out, 0, 0)
	out = append(out, uint8(key.FileID>>24), uint8(key.FileID>>16), uint8(key.FileID>>8), uint8(key.FileID))
	out = append(out, uint8(key.StartBlock>>24), uint8(key.StartBlock>>16), uint8(key.StartBlock>>8), uint8(key.StartBlock))
	out = append(out, uint8(key.Name.Len()>>8), uint8(key.Name.Len()))
	for _, unit := range key.Name.Units {
		out = append(out, uint8(unit>>8), uint8(unit))
	}
	return out, nil
}

// CompareAttrPayloads orders two attribute key payloads.
func CompareAttrPayloads(a, b []byte, caseSensitive bool) int {
	aKey, aErr := parseAttrKey(a)
	bKey, bErr := parseAttrKey(b)
	if aErr != nil || bErr != nil {
		return bytesCompare(a, b)
	}
	if aKey.FileID != bKey.FileID {
		if aKey.FileID < bKey.FileID {
			return -1
		}
		return 1
	}
	if aKey.StartBlock != bKey.StartBlock {
		if aKey.StartBlock < bKey.StartBlock {
			return -1
		}
		return 1
	}
	return CompareNameUnits(aKey.Name.Units, bKey.Name.Units, caseSensitive)
}

// AttrRecord is a parsed attribute record.
type AttrRecord struct {
	Type    uint32
	Inline  []byte
	Fork    *Fork
	Extents []Extent
}

// ParseAttrRecord parses an attribute record body.
func ParseAttrRecord(bytes []byte) (*AttrRecord, error) {
	if len(bytes) < 4 {
		return nil, invalidf("attribute record is shorter than its type field")
	}
	recordType := be32(bytes, 0)
	switch recordType {
	case AttrInlineData:
		if len(bytes) < 16 {
			return nil, invalidf("inline attribute record is %d bytes, expected at least 16", len(bytes))
		}
		size := int(be32(bytes, 12))
		end := 16 + size
		if end > len(bytes) {
			return nil, invalidf("inline attribute declares %d bytes, more than its %d byte record holds", size, len(bytes))
		}
		return &AttrRecord{Type: recordType, Inline: append([]byte(nil), bytes[16:end]...)}, nil
	case AttrForkData:
		if len(bytes) < 8+ForkLen {
			return nil, invalidf("attribute fork record is %d bytes, expected at least %d", len(bytes), 8+ForkLen)
		}
		fork, err := parseFork(bytes[8 : 8+ForkLen])
		if err != nil {
			return nil, err
		}
		return &AttrRecord{Type: recordType, Fork: &fork}, nil
	case AttrExtents:
		if len(bytes) < 8+InlineExtents*8 {
			return nil, invalidf("attribute extents record is %d bytes, expected at least %d", len(bytes), 8+InlineExtents*8)
		}
		extents := make([]Extent, 0, InlineExtents)
		for i := 0; i < InlineExtents; i++ {
			at := 8 + i*8
			extents = append(extents, Extent{StartBlock: be32(bytes, at), BlockCount: be32(bytes, at+4)})
		}
		return &AttrRecord{Type: recordType, Extents: extents}, nil
	default:
		return nil, invalidf("unknown attribute record type 0x%04X", recordType)
	}
}

func readAttribute(tree *BTree, src source.ByteSource, blockSize uint32, caseSensitive bool, fileID uint32, name string) ([]byte, error) {
	attrName := NewName(name)
	if attrName.Len() > MaxAttrNameUnits {
		return nil, nil
	}
	key, err := encodeAttrKey(AttrKey{FileID: fileID, Name: attrName})
	if err != nil {
		return nil, err
	}
	compare := func(a, b []byte) int { return CompareAttrPayloads(a, b, caseSensitive) }
	_, data, found, err := tree.Lookup(src, key, compare)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	record, err := ParseAttrRecord(data)
	if err != nil {
		return nil, err
	}
	switch record.Type {
	case AttrInlineData:
		return record.Inline, nil
	case AttrForkData:
		fork := record.Fork
		if fork.LogicalSize > MaxAttributeBytes {
			return nil, invalidf("attribute %q of CNID %d declares %d bytes, above the %d byte limit",
				name, fileID, fork.LogicalSize, MaxAttributeBytes)
		}
		extents, err := resolveAttributeExtents(tree, src, caseSensitive, fileID, name, *fork)
		if err != nil {
			return nil, err
		}
		covered := extents.CoveredBytes(blockSize)
		if fork.LogicalSize > covered {
			return nil, invalidf("attribute %q of CNID %d declares %d bytes but its extents cover %d",
				name, fileID, fork.LogicalSize, covered)
		}
		value := make([]byte, int(fork.LogicalSize))
		if err := extents.ReadExact(src, blockSize, 0, value); err != nil {
			return nil, err
		}
		return value, nil
	default:
		return nil, invalidf("attribute %q of CNID %d starts with an extents continuation record", name, fileID)
	}
}

func resolveAttributeExtents(tree *BTree, src source.ByteSource, caseSensitive bool, fileID uint32, name string, fork Fork) (ForkExtents, error) {
	extents := fork.InlineExtents()
	var covered uint32
	for _, extent := range extents {
		covered += extent.BlockCount
	}
	compare := func(a, b []byte) int { return CompareAttrPayloads(a, b, caseSensitive) }
	records := 0
	for covered < fork.TotalBlocks {
		records++
		if records > maxAttributeOverflowRecords {
			return ForkExtents{}, invalidf("attribute %q of CNID %d needs more than %d overflow records",
				name, fileID, maxAttributeOverflowRecords)
		}
		key, err := encodeAttrKey(AttrKey{FileID: fileID, StartBlock: covered, Name: NewName(name)})
		if err != nil {
			return ForkExtents{}, err
		}
		_, data, found, err := tree.Lookup(src, key, compare)
		if err != nil {
			return ForkExtents{}, err
		}
		if !found {
			return ForkExtents{}, invalidf("attribute %q of CNID %d has no overflow record at block %d", name, fileID, covered)
		}
		record, err := ParseAttrRecord(data)
		if err != nil {
			return ForkExtents{}, err
		}
		if record.Type != AttrExtents {
			return ForkExtents{}, invalidf("attribute %q of CNID %d continues with a 0x%04X record, expected extents",
				name, fileID, record.Type)
		}
		var blocks uint32
		more := make([]Extent, 0, len(record.Extents))
		for _, extent := range record.Extents {
			if !extent.IsEmpty() {
				more = append(more, extent)
				blocks += extent.BlockCount
			}
		}
		if blocks == 0 {
			return ForkExtents{}, invalidf("attribute extent record for CNID %d at block %d is empty", fileID, covered)
		}
		covered += blocks
		extents = append(extents, more...)
	}
	if covered > fork.TotalBlocks {
		return ForkExtents{}, invalidf("attribute %q of CNID %d extents cover %d blocks, more than its declared %d",
			name, fileID, covered, fork.TotalBlocks)
	}
	return NewForkExtents(extents), nil
}
