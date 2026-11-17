package squashfs

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	idEntryBytes       = 16
	xattrIDsPerBlock   = 512
	valueOutOfLine     = 1 << 8
	namespaceMask      = 0xFF
	outOfLineRefBytes  = 8
	maxAttributes      = 4096
	maxXattrNameBytes  = 255
	maxValueBytes      = 64 * 1024
	maxListBytes       = 1024 * 1024
	xattrIDHeaderBytes = 16
)

func namespaceLabel(kind uint16) string {
	switch kind & namespaceMask {
	case 0:
		return "user"
	case 1:
		return "trusted"
	case 2:
		return "security"
	default:
		return "unknown"
	}
}

func namespacePrefix(kind uint16) string {
	switch kind & namespaceMask {
	case 0:
		return "user."
	case 1:
		return "trusted."
	case 2:
		return "security."
	default:
		return ""
	}
}

// Xattr is one attribute in an inode's list.
type Xattr struct {
	// Namespace is "user", "trusted", "security" or "unknown".
	Namespace string
	// Name is the name as stored, without the namespace prefix.
	Name string
	// FullName includes the namespace prefix.
	FullName string
	// Value is nil for an out-of-line value whose copy could not be read.
	Value []byte
	// OutOfLine says the value is stored once, elsewhere in the table.
	OutOfLine bool
	// OutOfLineReference is the (block << 16) | offset reference.
	OutOfLineReference uint64
}

// UnreadValue is an out-of-line value whose stored copy could not be read.
type UnreadValue struct {
	Name      string
	Reference uint64
	Reason    string
}

// XattrList is one inode's decoded attribute list.
type XattrList struct {
	Attributes       []Xattr
	OutOfLine        int
	Resolved         int
	LengthMismatches int
	UnreadValues     []UnreadValue
	// Unread is the declared bytes the entries did not account for.
	Unread uint32
}

type xattrTable struct {
	tableStart   uint64
	idTableStart uint64
	ids          uint32
	index        []uint64
}

// readXattrTable reads the xattr id table header and its metadata-block
// index. A nil table with a nil error means the superblock names none.
func readXattrTable(src source.ByteSource, sb *superblock) (*xattrTable, error) {
	start := sb.xattrIDTableStart
	if start == invalidTable {
		return nil, nil
	}
	if start > sb.bytesUsed || xattrIDHeaderBytes > sb.bytesUsed-start {
		return nil, corruptf("the xattr id table at %d does not fit in the %d bytes in use",
			start, sb.bytesUsed)
	}
	header := make([]byte, xattrIDHeaderBytes)
	if err := source.ReadExactAt(src, start, header); err != nil {
		return nil, err
	}
	tableStart := binary.LittleEndian.Uint64(header[0:8])
	ids := binary.LittleEndian.Uint32(header[8:12])
	if ids == 0 {
		return nil, nil
	}
	if tableStart >= start {
		return nil, corruptf("the xattr table at %d is not below its own id table at %d", tableStart, start)
	}
	blocks := int((ids + xattrIDsPerBlock - 1) / xattrIDsPerBlock)
	indexBytes := uint64(blocks) * 8
	if start+uint64(xattrIDHeaderBytes) > sb.bytesUsed ||
		indexBytes > sb.bytesUsed-start-uint64(xattrIDHeaderBytes) {
		return nil, corruptf("the xattr id index for %d entries does not fit in the %d bytes in use",
			ids, sb.bytesUsed)
	}
	raw := make([]byte, int(indexBytes))
	if err := source.ReadExactAt(src, start+xattrIDHeaderBytes, raw); err != nil {
		return nil, err
	}
	index := make([]uint64, blocks)
	for i := range index {
		index[i] = binary.LittleEndian.Uint64(raw[i*8:])
	}
	for block, address := range index {
		if address >= start {
			return nil, corruptf("xattr id block %d points at %d, not below the id table at %d",
				block, address, start)
		}
	}
	return &xattrTable{
		tableStart:   tableStart,
		idTableStart: start,
		ids:          ids,
		index:        index,
	}, nil
}

// xattrCursor is a position in the xattr table's metadata stream.
type xattrCursor struct {
	block  uint64
	offset int
}

func (c *xattrCursor) read(cache *metadataCache, src source.ByteSource, consumed *uint32, length int, declared uint32) ([]byte, error) {
	needed := uint64(*consumed) + uint64(length)
	if needed > uint64(declared) {
		return nil, corruptf("an xattr entry runs %d bytes into a list declared as %d bytes", needed, declared)
	}
	bytes, block, offset, err := cache.spanCursor(src, c.block, c.offset, length)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.offset = offset
	*consumed = uint32(needed)
	return bytes, nil
}

// attributes decodes one inode's attribute list.
func (t *xattrTable) attributes(cache *metadataCache, src source.ByteSource, index uint32) (*XattrList, error) {
	if index >= t.ids {
		return nil, corruptf("xattr index %d is past the %d entries in the id table", index, t.ids)
	}
	block := index / xattrIDsPerBlock
	offset := int(index%xattrIDsPerBlock) * idEntryBytes
	if int(block) >= len(t.index) {
		return nil, corruptf("no xattr id index entry for block %d", block)
	}
	entry, err := cache.span(src, t.index[block], offset, idEntryBytes)
	if err != nil {
		return nil, err
	}
	reference := binary.LittleEndian.Uint64(entry[0:8])
	count := binary.LittleEndian.Uint32(entry[8:12])
	size := binary.LittleEndian.Uint32(entry[12:16])

	if count > maxAttributes {
		return nil, corruptf("xattr index %d claims %d attributes, more than %d", index, count, maxAttributes)
	}
	if size > maxListBytes {
		return nil, corruptf("xattr index %d claims a %d-byte list, more than %d", index, size, maxListBytes)
	}
	if count == 0 {
		if size != 0 {
			return nil, corruptf("xattr index %d has no attributes but declares %d bytes", index, size)
		}
		return &XattrList{}, nil
	}
	if reference>>16 < t.tableStart {
		return nil, corruptf("xattr index %d points at %d, below the xattr table at %d",
			index, reference>>16, t.tableStart)
	}

	cursor := &xattrCursor{block: reference >> 16, offset: int(reference & 0xFFFF)}
	var consumed uint32
	list := &XattrList{Attributes: make([]Xattr, 0, minInt(int(count), 64))}
	for i := uint32(0); i < count; i++ {
		header, err := cursor.read(cache, src, &consumed, 4, size)
		if err != nil {
			return nil, err
		}
		kind := binary.LittleEndian.Uint16(header[0:2])
		nameLen := int(binary.LittleEndian.Uint16(header[2:4]))
		if nameLen > maxXattrNameBytes {
			return nil, corruptf("an xattr name claims %d bytes, more than %d", nameLen, maxXattrNameBytes)
		}
		nameBytes, err := cursor.read(cache, src, &consumed, nameLen, size)
		if err != nil {
			return nil, err
		}
		valueHeader, err := cursor.read(cache, src, &consumed, 4, size)
		if err != nil {
			return nil, err
		}
		valueLen := binary.LittleEndian.Uint32(valueHeader)
		namespace := namespaceLabel(kind)
		fullName := namespacePrefix(kind) + string(nameBytes)

		if kind&valueOutOfLine != 0 {
			raw, err := cursor.read(cache, src, &consumed, outOfLineRefBytes, size)
			if err != nil {
				return nil, err
			}
			ref := binary.LittleEndian.Uint64(raw)
			attribute := Xattr{
				Namespace:          namespace,
				Name:               string(nameBytes),
				FullName:           fullName,
				OutOfLine:          true,
				OutOfLineReference: ref,
			}
			if value, err := t.follow(cache, src, ref, fullName); err != nil {
				list.UnreadValues = append(list.UnreadValues, UnreadValue{
					Name:      fullName,
					Reference: ref,
					Reason:    err.Error(),
				})
			} else {
				if uint32(len(value)) != valueLen {
					list.LengthMismatches++
				}
				attribute.Value = value
				list.Resolved++
			}
			list.Attributes = append(list.Attributes, attribute)
			list.OutOfLine++
			continue
		}

		if valueLen > maxValueBytes {
			return nil, corruptf("an xattr value claims %d bytes, more than %d", valueLen, maxValueBytes)
		}
		value, err := cursor.read(cache, src, &consumed, int(valueLen), size)
		if err != nil {
			return nil, err
		}
		list.Attributes = append(list.Attributes, Xattr{
			Namespace: namespace,
			Name:      string(nameBytes),
			FullName:  fullName,
			Value:     value,
		})
	}
	list.Unread = size - consumed
	return list, nil
}

// follow reads the copy an out-of-line value names.
func (t *xattrTable) follow(cache *metadataCache, src source.ByteSource, reference uint64, attribute string) ([]byte, error) {
	block := reference >> 16
	offset := int(reference & 0xFFFF)
	if block < t.tableStart || block >= t.idTableStart {
		return nil, corruptf("%s's out-of-line value names block %d, outside the xattr table at %d-%d",
			attribute, block, t.tableStart, t.idTableStart)
	}
	header, block, offset, err := cache.spanCursor(src, block, offset, 4)
	if err != nil {
		return nil, err
	}
	stored := binary.LittleEndian.Uint32(header)
	if stored > maxValueBytes {
		return nil, corruptf("%s's out-of-line copy declares %d bytes, more than %d",
			attribute, stored, maxValueBytes)
	}
	value, nextBlock, nextOffset, err := cache.spanCursor(src, block, offset, int(stored))
	if err != nil {
		return nil, err
	}
	if nextBlock > t.idTableStart || (nextBlock == t.idTableStart && nextOffset != 0) {
		return nil, corruptf("%s's out-of-line value runs into the id table at %d",
			attribute, t.idTableStart)
	}
	return value, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
