// The LTP layer: a heap-on-node (HN), a BTree-on-heap (BTH) and the property
// context (PC) built on both.
//
// A node's data is a chain of blocks.  The first begins with an HNHDR: a
// 12-byte header, a run of heap allocations, and an HNPAGEMAP whose
// cAlloc+1 offsets delimit every allocation.  Every further block carries its
// own page map, so a heap spans as many blocks as the node data does.  A later
// block whose third byte is the heap signature carries HNBITMAPHDR, the
// 136-byte header that re-seeds the fill-level map; every other later block
// carries the abbreviated two-byte HNPAGEHDR.  hidUserRoot names the allocation
// that holds the higher-level structure; a HID's high word selects the block
// and its low word the one-based page-map entry.
//
// For a PC that structure is a BTHHEADER (bType 0xB5, cbKey 2, cbEnt 6), and
// each BTH record is a property id plus a six-byte value { wPropType, dwValue }.
// A type that fits in four bytes is stored in dwValue; every other type names a
// heap allocation that holds the value alone, or a subnode when the low five
// bits are 0x1F.
//
// A table context (client TC_CLIENT, bType 0x7C) uses the same heap but a
// different header: TCINFO carries a fixed-size row and a list of columns whose
// descriptors give each value's offset inside the row.  Every row begins with a
// four-byte row id and ends with a cell-existence bitmap: a clear bit means the
// column is not set for that row, not that its value is zero.  A variable-width
// value is stored as a four-byte HNID in the row.
package pst

const (
	hnhdrBytes       = 12
	hnpagehdrBytes   = 2
	hnbitmaphdrBytes = 136
	hnSignature      = 0xEC
	pcClient         = 0xBC
	tcClient         = 0x7C
	tcInfoType       = 0x7C
	bthType          = 0xB5
	bthHeaderBytes   = 8
	bthPCKeyBytes    = 2
	bthPCEntBytes    = 6
	maxBTHLevels     = 8
	tcInfoBytes      = 22
	tcOldescBytes    = 8
	tcRowIDBytes     = 4
	tcHNIDBytes      = 4
)

// rawValueKind is how a value wider than four bytes is named in a BTH record.
type rawValueKind uint8

const (
	rawHeap rawValueKind = iota
	rawSubnode
)

// rawValue is one property value before its MAPI type is interpreted.
type rawValue struct {
	kind    rawValueKind
	bytes   []byte // heap allocation, when kind is rawHeap
	subnode uint32 // subnode NID, when kind is rawSubnode
}

// rawProperty is one property as it sits in the heap.
type rawProperty struct {
	id    uint16
	kind  uint16
	value rawValue
}

// hidLayout is how a HID splits its 32 bits.  The first five are always zero
// (NID_TYPE_HID); the rest divide between the one-based allocation index and
// the heap data block: 11 and 16 bits for the 512-byte-page format, 14 and 13
// for the 4 KiB format.
type hidLayout struct {
	indexMask  uint32
	blockShift uint
}

func hidLayoutForPageBytes(pageBytes int) hidLayout {
	if pageBytes == 4096 {
		return hidLayout{indexMask: 0x3FFF, blockShift: 19}
	}
	return hidLayout{indexMask: 0x07FF, blockShift: 16}
}

// split returns the heap data block and the one-based allocation index.
func (l hidLayout) split(hid uint32) (block, encoded int) {
	return int(hid >> l.blockShift), int((hid >> 5) & l.indexMask)
}

// heap is a parsed HN: the node's data blocks and each block's allocation
// offsets.
type heap struct {
	blocks   [][]byte
	maps     [][]int
	layout   hidLayout
	client   byte
	userRoot uint32
}

// parseHeap parses every block of one node's heap.
func parseHeap(blocks [][]byte, layout hidLayout) (*heap, error) {
	if len(blocks) == 0 {
		return nil, corruptf("a heap-on-node needs at least one data block")
	}
	first := blocks[0]
	if len(first) < hnhdrBytes {
		return nil, corruptf("a heap-on-node needs at least %d bytes, the node holds %d", hnhdrBytes, len(first))
	}
	if first[2] != hnSignature {
		return nil, corruptf("the heap-on-node signature is 0x%02X, not 0x%02X", first[2], hnSignature)
	}
	client := first[3]
	userRoot := leU32(first, 4)
	maps := make([][]int, len(blocks))
	for index, data := range blocks {
		parsed, err := blockPageMap(data, index)
		if err != nil {
			return nil, err
		}
		maps[index] = parsed
	}
	return &heap{blocks: blocks, maps: maps, layout: layout, client: client, userRoot: userRoot}, nil
}

// allocation returns the bytes of the allocation hid names.  HID 0x20 is the
// first allocation, 0x40 the second.  A zero HID names no allocation.
func (h *heap) allocation(hid uint32) ([]byte, error) {
	block, encoded := h.layout.split(hid)
	if encoded == 0 {
		return nil, corruptf("heap id 0 names no allocation")
	}
	index := encoded - 1
	if block < 0 || block >= len(h.blocks) {
		return nil, corruptf("heap id 0x%08X names data block %d, the node holds %d", hid, block, len(h.blocks))
	}
	data := h.blocks[block]
	offsets := h.maps[block]
	if index < 0 || index >= len(offsets) {
		return nil, corruptf("heap allocation %d is outside the %d-entry page map of data block %d", index, len(offsets)-1, block)
	}
	if index+1 >= len(offsets) {
		return nil, corruptf("heap allocation %d has no end offset in data block %d", index, block)
	}
	start, end := offsets[index], offsets[index+1]
	if start < 0 || end < start || end > len(data) {
		return nil, corruptf("heap allocation %d of data block %d is %d..%d, outside its %d bytes", index, block, start, end, len(data))
	}
	return data[start:end], nil
}

// blockPageMap reads one block's page map from the header the block actually
// carries.
func blockPageMap(data []byte, block int) ([]int, error) {
	if block == 0 {
		return pageMap(data, hnhdrBytes, block)
	}
	if len(data) > 2 && data[2] == hnSignature {
		if parsed, err := pageMap(data, hnbitmaphdrBytes, block); err == nil {
			return parsed, nil
		}
	}
	return pageMap(data, hnpagehdrBytes, block)
}

// pageMap reads one HNPAGEMAP into its cAlloc+1 allocation offsets.
func pageMap(data []byte, header, block int) ([]int, error) {
	if len(data) < header {
		return nil, corruptf("heap data block %d holds %d bytes, short of its %d-byte header", block, len(data), header)
	}
	if header != hnpagehdrBytes && data[2] != hnSignature {
		prefix := data
		if len(prefix) > 4 {
			prefix = prefix[:4]
		}
		return nil, corruptf("heap data block %d does not begin with a heap page header (starts % X)", block, prefix)
	}
	ibHnpm := int(leU16(data, 0))
	if ibHnpm < header || ibHnpm+4 > len(data) {
		return nil, corruptf("the heap page map offset %d of data block %d is outside its %d bytes", ibHnpm, block, len(data))
	}
	count := int(leU16(data, ibHnpm))
	mapBytes := (count + 1) * 2
	if mapBytes < 0 || ibHnpm+4+mapBytes > len(data) {
		return nil, corruptf("the heap page map for %d allocations of data block %d runs past its %d bytes", count, block, len(data))
	}
	offsets := make([]int, 0, count+1)
	previous := 0
	for index := 0; index <= count; index++ {
		offset := int(leU16(data, ibHnpm+4+index*2))
		if index == 0 {
			if offset < header {
				return nil, corruptf("the first heap allocation of data block %d starts at %d, inside the heap header", block, offset)
			}
		} else if offset < previous {
			return nil, corruptf("heap allocation offsets of data block %d go backwards at index %d", block, index)
		}
		previous = offset
		offsets = append(offsets, offset)
	}
	limit := ibHnpm
	if len(data) < limit {
		limit = len(data)
	}
	if offsets[count] > limit {
		return nil, corruptf("the heap allocations of data block %d end at %d, past the page map at %d", block, offsets[count], ibHnpm)
	}
	return offsets, nil
}

// readPC reads a property context: the heap's PC client and its BTH records.
// maxProperties bounds the number of records.
func readPC(blocks [][]byte, layout hidLayout, maxProperties int) ([]rawProperty, error) {
	h, err := parseHeap(blocks, layout)
	if err != nil {
		return nil, err
	}
	if h.client != pcClient {
		return nil, unsupportedf("a heap with client signature 0x%02X; a property context uses 0x%02X", h.client, pcClient)
	}
	header, err := h.allocation(h.userRoot)
	if err != nil {
		return nil, err
	}
	if len(header) < bthHeaderBytes {
		return nil, corruptf("the BTH header is shorter than its eight bytes")
	}
	if header[0] != bthType {
		return nil, corruptf("the BTH type is 0x%02X, not 0x%02X", header[0], bthType)
	}
	cbKey := int(header[1])
	cbEnt := int(header[2])
	levels := header[3]
	if cbKey != bthPCKeyBytes || cbEnt != bthPCEntBytes {
		return nil, unsupportedf("a property BTH with %d-byte keys and %d-byte values; a property context uses 2 and 6", cbKey, cbEnt)
	}
	if levels > maxBTHLevels {
		return nil, corruptf("the BTH declares %d index levels", levels)
	}
	root := leU32(header, 4)
	if root == 0 {
		return nil, nil
	}
	if maxProperties <= 0 || maxProperties > maxPropertiesHard {
		maxProperties = maxPropertiesHard
	}
	var records []bthRecord
	if err := collectBTH(h, root, levels, cbKey, cbEnt, &records, maxProperties); err != nil {
		return nil, err
	}
	if len(records) > maxProperties {
		return nil, limitf("the property context holds more than %d properties", maxProperties)
	}
	properties := make([]rawProperty, 0, len(records))
	for _, record := range records {
		if len(record.key) < 2 || len(record.value) < 6 {
			return nil, corruptf("a BTH record is shorter than its key and value")
		}
		id := leU16(record.key, 0)
		kind := leU16(record.value, 0)
		field := record.value[2:6]
		if width, ok := inlineWidth(kind); ok {
			properties = append(properties, rawProperty{id: id, kind: kind, value: rawValue{kind: rawHeap, bytes: append([]byte(nil), field[:width]...)}})
			continue
		}
		hnid := leU32(field, 0)
		switch hnid & 0x1F {
		case 0:
			if hnid == 0 {
				// A zero HID holds no value at all.  A property that was
				// never set is absent, not empty.
				continue
			}
			value, err := h.allocation(hnid)
			if err != nil {
				return nil, corruptf("property 0x%04X typed 0x%04X names heap id 0x%08X: %v", id, kind, hnid, err)
			}
			properties = append(properties, rawProperty{id: id, kind: kind, value: rawValue{kind: rawHeap, bytes: append([]byte(nil), value...)}})
		case 0x1F:
			properties = append(properties, rawProperty{id: id, kind: kind, value: rawValue{kind: rawSubnode, subnode: hnid}})
		default:
			return nil, corruptf("property 0x%04X typed 0x%04X names 0x%08X, whose low five bits are a NID type of 0x%02X; a value is either a heap id (type 0) or a subnode (type 0x1F)", id, kind, hnid, hnid&0x1F)
		}
	}
	return properties, nil
}

// tcColumn is one table column as its TCOLDESC describes it.
type tcColumn struct {
	tag    uint32
	offset int
	width  int
	bit    uint8
}

func (c tcColumn) id() uint16       { return uint16(c.tag >> 16) }
func (c tcColumn) kind() uint16     { return uint16(c.tag) }
func (c tcColumn) isVariable() bool { return isVariableType(c.kind()) }

// rowMatrix is where a table's row matrix lives.
type rowMatrixKind uint8

const (
	rowMatrixEmpty rowMatrixKind = iota
	rowMatrixHeap
	rowMatrixSubnode
)

type rowMatrix struct {
	kind    rowMatrixKind
	bytes   []byte
	subnode uint32
}

// tcValue is one value in a table row, before its type is interpreted.
type tcValueKind uint8

const (
	tcValueBytes tcValueKind = iota
	tcValueSubnode
	tcValueAbsent
)

type tcValue struct {
	kind    tcValueKind
	bytes   []byte
	subnode uint32
}

// tcCell is one cell of a table row.
type tcCell struct {
	column int
	value  tcValue
}

// tcRow is one row of a table context.
type tcRow struct {
	id    uint32
	cells []tcCell
}

// tableContext is a parsed table context.
type tableContext struct {
	heap     *heap
	columns  []tcColumn
	rowSize  int
	cebStart int
	cebBytes int
	rows     rowMatrix
}

// readTableContext reads a table context from a node's (or subnode's) heap
// blocks.
func readTableContext(blocks [][]byte, layout hidLayout) (*tableContext, error) {
	h, err := parseHeap(blocks, layout)
	if err != nil {
		return nil, err
	}
	if h.client != tcClient {
		return nil, unsupportedf("a heap with client signature 0x%02X; a table context uses 0x%02X", h.client, tcClient)
	}
	header, err := h.allocation(h.userRoot)
	if err != nil {
		return nil, err
	}
	if len(header) < tcInfoBytes {
		return nil, corruptf("the table header is %d bytes, shorter than its %d", len(header), tcInfoBytes)
	}
	if header[0] != tcInfoType {
		return nil, corruptf("the table header type is 0x%02X, not 0x%02X", header[0], tcInfoType)
	}
	columnCount := int(header[1])
	if columnCount == 0 {
		return nil, corruptf("the table header declares no columns")
	}
	groupEnd := [4]int{int(leU16(header, 2)), int(leU16(header, 4)), int(leU16(header, 6)), int(leU16(header, 8))}
	for index := 1; index < 4; index++ {
		if groupEnd[index-1] > groupEnd[index] {
			return nil, corruptf("the table's group end offsets %v go backwards", groupEnd)
		}
	}
	rowSize := groupEnd[3]
	cebStart := groupEnd[2]
	if rowSize < tcRowIDBytes {
		return nil, corruptf("the table row size is %d bytes, shorter than its row id", rowSize)
	}
	if cebStart < tcRowIDBytes || cebStart > rowSize {
		return nil, corruptf("the table's cell bitmap starts at %d, outside its %d-byte row", cebStart, rowSize)
	}
	cebBytes := (columnCount + 7) / 8
	if cebStart+cebBytes > rowSize {
		return nil, corruptf("a %d-column table needs %d bitmap bytes at %d, past its %d-byte row", columnCount, cebBytes, cebStart, rowSize)
	}
	descriptors := columnCount * tcOldescBytes
	if descriptors/tcOldescBytes != columnCount {
		return nil, corruptf("the table's column count overflows")
	}
	if len(header) < tcInfoBytes+descriptors {
		return nil, corruptf("the table header holds %d bytes but %d column descriptors need %d", len(header), columnCount, tcInfoBytes+descriptors)
	}
	columns := make([]tcColumn, 0, columnCount)
	for index := 0; index < columnCount; index++ {
		at := tcInfoBytes + index*tcOldescBytes
		tag := leU32(header, at)
		offset := int(leU16(header, at+4))
		width := int(header[at+6])
		bit := header[at+7]
		if int(bit) >= columnCount {
			return nil, corruptf("column 0x%08X names cell bit %d, but the table has %d columns", tag, bit, columnCount)
		}
		if offset+width < offset || offset+width > cebStart {
			return nil, corruptf("column 0x%08X data %d..%d runs past the cell bitmap at %d", tag, offset, offset+width, cebStart)
		}
		columns = append(columns, tcColumn{tag: tag, offset: offset, width: width, bit: bit})
	}
	hnidRows := leU32(header, 14)
	var rows rowMatrix
	switch {
	case hnidRows == 0:
		rows = rowMatrix{kind: rowMatrixEmpty}
	case hnidRows&0x1F == 0:
		value, err := h.allocation(hnidRows)
		if err != nil {
			return nil, err
		}
		rows = rowMatrix{kind: rowMatrixHeap, bytes: append([]byte(nil), value...)}
	default:
		rows = rowMatrix{kind: rowMatrixSubnode, subnode: hnidRows}
	}
	return &tableContext{heap: h, columns: columns, rowSize: rowSize, cebStart: cebStart, cebBytes: cebBytes, rows: rows}, nil
}

// rowsIn parses the rows of one row-matrix block list.  HID cells are resolved
// here; subnode cells are left for the NDB layer, which knows the tree.
func (t *tableContext) rowsIn(matrix [][]byte, maxRows int, maxMatrixBytes uint64) ([]tcRow, error) {
	if maxRows <= 0 || maxRows > maxTCRowsHard {
		maxRows = maxTCRowsHard
	}
	if maxMatrixBytes == 0 || maxMatrixBytes > maxTCMatrixBytes {
		maxMatrixBytes = maxTCMatrixBytes
	}
	total := uint64(0)
	for _, block := range matrix {
		if uint64(len(block)) > maxMatrixBytes-total {
			return nil, limitf("the table's row matrix is over the %d-byte limit", maxMatrixBytes)
		}
		total += uint64(len(block))
	}
	var rows []tcRow
	for blockIndex, block := range matrix {
		if len(block) == 0 {
			continue
		}
		if len(block) < t.rowSize {
			return nil, corruptf("row-matrix block %d holds %d bytes, shorter than the %d-byte row", blockIndex, len(block), t.rowSize)
		}
		count := len(block) / t.rowSize
		for index := 0; index < count; index++ {
			at := index * t.rowSize
			row := block[at : at+t.rowSize]
			id := leU32(row, 0)
			ceb := row[t.cebStart : t.cebStart+t.cebBytes]
			cells := make([]tcCell, 0, len(t.columns))
			for columnIndex, column := range t.columns {
				if ceb[int(column.bit)/8]&(0x80>>(column.bit%8)) == 0 {
					continue
				}
				start := column.offset
				end := start + column.width
				if end > len(row) {
					return nil, corruptf("column 0x%08X data %d..%d is outside the %d-byte row", column.tag, start, end, len(row))
				}
				var value tcValue
				if column.isVariable() {
					if column.width != tcHNIDBytes {
						return nil, unsupportedf("variable-size column 0x%08X has a %d-byte HNID; the Unicode layout uses %d", column.tag, column.width, tcHNIDBytes)
					}
					hnid := leU32(row[start:end], 0)
					switch hnid & 0x1F {
					case 0:
						if hnid == 0 {
							value = tcValue{kind: tcValueAbsent}
						} else {
							bytes, err := t.heap.allocation(hnid)
							if err != nil {
								return nil, err
							}
							value = tcValue{kind: tcValueBytes, bytes: append([]byte(nil), bytes...)}
						}
					default:
						value = tcValue{kind: tcValueSubnode, subnode: hnid}
					}
				} else {
					value = tcValue{kind: tcValueBytes, bytes: append([]byte(nil), row[start:end]...)}
				}
				cells = append(cells, tcCell{column: columnIndex, value: value})
			}
			rows = append(rows, tcRow{id: id, cells: cells})
			if len(rows) > maxRows {
				return nil, limitf("the table holds more than %d rows", maxRows)
			}
		}
	}
	return rows, nil
}

// isVariableType reports the MAPI types whose row slot names the value
// elsewhere.  Every fixed-width type, including 8-byte and CLSID values, is
// stored in the row itself.
func isVariableType(kind uint16) bool {
	switch kind {
	case 0x000D, 0x001E, 0x001F, 0x0102, 0x101E, 0x101F, 0x1102:
		return true
	}
	return false
}

type bthRecord struct {
	key   []byte
	value []byte
}

// collectBTH walks one BTH level, collecting leaf (key, value) pairs.
func collectBTH(h *heap, hid uint32, level uint8, cbKey, cbEnt int, out *[]bthRecord, maxRecords int) error {
	data, err := h.allocation(hid)
	if err != nil {
		return err
	}
	entry := cbKey + cbEnt
	if level != 0 {
		entry = cbKey + 4
	}
	if entry == 0 || len(data)%entry != 0 {
		return corruptf("a BTH level of %d bytes does not divide into %d-byte entries", len(data), entry)
	}
	count := len(data) / entry
	if level != 0 && count == 0 {
		return corruptf("a BTH index level holds no entries")
	}
	for index := 0; index < count; index++ {
		at := index * entry
		if level == 0 {
			*out = append(*out, bthRecord{
				key:   append([]byte(nil), data[at:at+cbKey]...),
				value: append([]byte(nil), data[at+cbKey:at+entry]...),
			})
			if len(*out) > maxRecords {
				return limitf("the BTH holds more than %d records", maxRecords)
			}
			continue
		}
		child := leU32(data, at+cbKey)
		if child == 0 {
			return corruptf("a BTH index record points at no child")
		}
		if err := collectBTH(h, child, level-1, cbKey, cbEnt, out, maxRecords); err != nil {
			return err
		}
	}
	return nil
}

// inlineWidth is the width of a property type a BTH record keeps inline in
// its four-byte value field.  false means the field is the HID of a heap
// allocation instead (any type wider than four bytes, and every
// variable-length type).
func inlineWidth(kind uint16) (int, bool) {
	switch kind {
	case 0x0001:
		return 0, true // null
	case 0x0002, 0x000B:
		return 2, true // i2, boolean
	case 0x0003, 0x0004, 0x000A:
		return 4, true // i4, float, error
	}
	return 0, false
}
