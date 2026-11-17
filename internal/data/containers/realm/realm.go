// Package realm parses Realm mobile databases (`*.realm`).
//
// Realm Core stores an application database as a sequence of 8-byte-aligned
// nodes in one file. The header names the current top array, the top array
// names the group's table names and table refs, each table names a spec (its
// columns) and a cluster tree (its rows), and each cluster leaf names the
// column arrays that hold one value per row. Every array slot is either a file
// offset (a ref) or a small integer shifted left once with the low bit set (a
// tagged value).
//
// This reader is a pure-Go port of forensic-core's data/containers/realm.rs.
// It decodes the cluster layout used by file format versions 10 through 24.
// It reports the header, table/column/row hierarchy, each cell's byte offset, a
// typed value view, and the group's free lists.
//
// A column whose type or storage this build does not decode is kept in the
// table with a named refusal and contributes no cells. OpenCell refuses such a
// column explicitly with source.ErrUnsupported rather than returning a guessed
// value. Collections, string enums, big blobs, Decimal, ObjectId, TypedLink,
// UUID, Mixed and B+-tree column arrays are metadata-only for that reason.
//
// Because the whole file is parsed in one bounded pass, Open reads it through
// source.ByteSource and retains the parent for provenance. Limits bound the
// allocation and every structural count. The normal file form is supported;
// Realm's streaming form, whose top ref is all ones and whose footer lives at
// the end of the file, is refused by name. An encrypted Realm file without its
// key presents a missing mnemonic and is refused exactly as a corrupt file is.
package realm

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Magic is the four-byte Realm info-block mnemonic at offset 16.
	Magic = "T-DB"
	// HeaderBytes is the size of the Realm file header.
	HeaderBytes = 24
	// NodeHeaderBytes is the size of every node header.
	NodeHeaderBytes = 8
	// NodeMarker is the constant node prefix. It is a marker, not a checksum.
	NodeMarker uint32 = 0x41414141
	// MinFormatVersion is the oldest cluster layout this reader decodes.
	MinFormatVersion uint8 = 10
	// MaxFormatVersion is the newest cluster layout this reader decodes.
	MaxFormatVersion uint8 = 24
	// MaxFileBytes is the default bound on a file read into memory.
	MaxFileBytes uint64 = 1 << 30
	// MaxTables is the default bound on tables in one group.
	MaxTables = 1 << 20
	// MaxColumns is the default bound on columns in one table.
	MaxColumns = 1 << 20
	// MaxRows is the default bound on rows in one table.
	MaxRows = 10_000_000
	// MaxTreeDepth is the default bound on cluster-tree nesting.
	MaxTreeDepth = 64

	widthSchemeBits     = 0
	widthSchemeMultiply = 1
	widthSchemeIgnore   = 2

	tableKeyNull = 0x7FFF_FFFF
)

// Limits bounds one Open call. A zero count is a strict zero cap; set the
// fields from DefaultLimits for the reference bounds.
type Limits struct {
	MaxFileBytes uint64
	MaxTables    int
	MaxColumns   int
	MaxRows      uint64
	MaxTreeDepth int
}

// DefaultLimits returns the bounds used by Open.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes: MaxFileBytes,
		MaxTables:    MaxTables,
		MaxColumns:   MaxColumns,
		MaxRows:      MaxRows,
		MaxTreeDepth: MaxTreeDepth,
	}
}

// RouteFile reports whether a path is a Realm route hint. The mnemonic is
// re-checked by LooksLike/Open; a suffix alone is never evidence.
func RouteFile(path string) bool {
	normalized := strings.ReplaceAll(path, "\\", "/")
	at := strings.LastIndex(normalized, "/")
	name := normalized
	if at >= 0 {
		name = normalized[at+1:]
	}
	return len(name) > len(".realm") && strings.HasSuffix(strings.ToLower(name), ".realm")
}

// LooksLike reports whether head carries the Realm mnemonic. This is a cheap
// route test; Open remains the authority.
func LooksLike(head []byte) bool {
	return len(head) >= HeaderBytes && string(head[16:20]) == Magic
}

// ColumnType is a Realm column type code. Unknown codes are preserved.
type ColumnType uint8

const (
	ColumnInt       ColumnType = 0
	ColumnBool      ColumnType = 1
	ColumnString    ColumnType = 2
	ColumnBinary    ColumnType = 4
	ColumnMixed     ColumnType = 6
	ColumnTimestamp ColumnType = 8
	ColumnFloat     ColumnType = 9
	ColumnDouble    ColumnType = 10
	ColumnDecimal   ColumnType = 11
	ColumnLink      ColumnType = 12
	ColumnBackLink  ColumnType = 14
	ColumnObjectID  ColumnType = 15
	ColumnTypedLink ColumnType = 16
	ColumnUUID      ColumnType = 17
)

// ColumnTypeFromCode decodes a spec type code, preserving unknown values.
func ColumnTypeFromCode(code uint8) ColumnType { return ColumnType(code) }

// Code returns the raw type code.
func (t ColumnType) Code() uint8 { return uint8(t) }

// Label returns Realm Core's name for the type, or "Unknown".
func (t ColumnType) Label() string {
	switch t {
	case ColumnInt:
		return "Int"
	case ColumnBool:
		return "Bool"
	case ColumnString:
		return "String"
	case ColumnBinary:
		return "Binary"
	case ColumnMixed:
		return "Mixed"
	case ColumnTimestamp:
		return "Timestamp"
	case ColumnFloat:
		return "Float"
	case ColumnDouble:
		return "Double"
	case ColumnDecimal:
		return "Decimal"
	case ColumnLink:
		return "Link"
	case ColumnBackLink:
		return "BackLink"
	case ColumnObjectID:
		return "ObjectId"
	case ColumnTypedLink:
		return "TypedLink"
	case ColumnUUID:
		return "UUID"
	default:
		return "Unknown"
	}
}

// Known reports whether the code is one of the current Realm type codes.
func (t ColumnType) Known() bool {
	switch t {
	case ColumnInt, ColumnBool, ColumnString, ColumnBinary, ColumnMixed,
		ColumnTimestamp, ColumnFloat, ColumnDouble, ColumnDecimal, ColumnLink,
		ColumnBackLink, ColumnObjectID, ColumnTypedLink, ColumnUUID:
		return true
	default:
		return false
	}
}

// ValueKind identifies the decoded variant carried by Value.
type ValueKind uint8

const (
	ValueNull ValueKind = iota
	ValueInt
	ValueBool
	ValueString
	ValueFloat
	ValueDouble
	ValueTimestamp
	ValueBinary
	ValueLink
)

// String names the value variant.
func (k ValueKind) String() string {
	switch k {
	case ValueNull:
		return "Null"
	case ValueInt:
		return "Int"
	case ValueBool:
		return "Bool"
	case ValueString:
		return "String"
	case ValueFloat:
		return "Float"
	case ValueDouble:
		return "Double"
	case ValueTimestamp:
		return "Timestamp"
	case ValueBinary:
		return "Binary"
	case ValueLink:
		return "Link"
	default:
		return "Unknown"
	}
}

// Value is one cell value in the type its column declares.
//
// A value is only present when the column's storage was decoded. A refused
// column contributes no cell at all, so ValueNull always means the database
// stored null, never "not read".
type Value struct {
	Kind ValueKind

	Int     int64
	Bool    bool
	String  string
	Float   float32
	Double  float64
	Binary  []byte
	LinkKey int64

	TimestampSeconds int64
	TimestampNanos   int32

	LinkTargetTable uint32
	HasLinkTarget   bool
}

// Cell is one decoded cell and the file offset that holds it.
type Cell struct {
	Column int
	Offset uint64
	Value  Value
}

// Row is one object record, with cells in spec column order.
type Row struct {
	Key   uint64
	Index int
	Cells []Cell
}

// Column describes one spec column.
type Column struct {
	Name          string
	NameOffset    uint64
	HasNameOffset bool
	SpecIndex     int
	LeafIndex     int
	Type          ColumnType
	ColKey        uint64
	Nullable      bool
	Indexed       bool
	Unique        bool
	Collection    bool
	StringEnum    bool

	LinkTarget    uint32
	HasLinkTarget bool

	// Unsupported is non-empty when this build produced no cells for the
	// column. A decoded column leaves it empty even when it has no rows.
	Unsupported string
}

// Table is one decoded table.
type Table struct {
	Name          string
	NameOffset    uint64
	HasNameOffset bool
	Key           uint32
	TopRef        uint64
	Columns       []Column
	Rows          []Row
	Warnings      []string
}

// FreeChunk is one recorded free-list region.
type FreeChunk struct {
	Offset  uint64
	Length  uint64
	Version *uint64
}

// FreeLists is the group's decoded free lists.
type FreeLists struct {
	Chunks   []FreeChunk
	Warnings []string
}

// Header is the 24-byte file header, decoded.
type Header struct {
	TopRef        uint64
	TopSlot       uint8
	FormatVersion uint8
	Flags         uint8
	FileSize      uint64
	LogicalSize   uint64
}

// Database is a decoded Realm database.
type Database struct {
	Header   Header
	Free     FreeLists
	Tables   []Table
	Warnings []string

	parent   source.ByteSource
	sourceID source.ID
	stats    source.Stats
}

// RowCount returns the number of rows across every table.
func (d *Database) RowCount() int {
	total := 0
	for index := range d.Tables {
		total += len(d.Tables[index].Rows)
	}
	return total
}

// ColumnCount returns the number of columns across every table.
func (d *Database) ColumnCount() int {
	total := 0
	for index := range d.Tables {
		total += len(d.Tables[index].Columns)
	}
	return total
}

// Refusals returns every named column refusal as `table.column: reason`.
func (d *Database) Refusals() []string {
	var out []string
	for tableIndex := range d.Tables {
		table := &d.Tables[tableIndex]
		for columnIndex := range table.Columns {
			column := &table.Columns[columnIndex]
			if column.Unsupported == "" {
				continue
			}
			name := column.Name
			if name == "" {
				name = fmt.Sprintf("#%d", column.SpecIndex)
			}
			out = append(out, fmt.Sprintf("%s.%s: %s", table.Name, name, column.Unsupported))
		}
	}
	return out
}

// SourceID returns the id Open was given.
func (d *Database) SourceID() source.ID { return d.sourceID }

// ImageID returns the image that ultimately owns the parsed bytes.
func (d *Database) ImageID() source.ImageID {
	if d.parent == nil {
		return 0
	}
	return d.parent.ImageID()
}

// Parent returns the source the database was parsed from.
func (d *Database) Parent() source.ByteSource { return d.parent }

// Stats returns the parent-source counters captured when Open finished.
func (d *Database) Stats() source.Stats { return d.stats }

// TableAt returns a table by index.
func (d *Database) TableAt(index int) (*Table, bool) {
	if index < 0 || index >= len(d.Tables) {
		return nil, false
	}
	return &d.Tables[index], true
}

// FindTable returns the first table with the given name.
func (d *Database) FindTable(name string) (*Table, bool) {
	for index := range d.Tables {
		if d.Tables[index].Name == name {
			return &d.Tables[index], true
		}
	}
	return nil, false
}

// RowCount returns the number of rows in the table.
func (t *Table) RowCount() int { return len(t.Rows) }

// RowAt returns a row by index.
func (t *Table) RowAt(index int) (*Row, bool) {
	if index < 0 || index >= len(t.Rows) {
		return nil, false
	}
	return &t.Rows[index], true
}

// OpenRow returns a row by index or source.ErrOutOfRange.
func (t *Table) OpenRow(index int) (*Row, error) {
	if index < 0 || index >= len(t.Rows) {
		return nil, &source.Error{
			Kind: source.ErrOutOfRange, Offset: uint64(index), Len: 1, SourceLen: uint64(len(t.Rows)),
		}
	}
	return &t.Rows[index], nil
}

// ColumnAt returns a column by spec index.
func (t *Table) ColumnAt(index int) (*Column, bool) {
	if index < 0 || index >= len(t.Columns) {
		return nil, false
	}
	return &t.Columns[index], true
}

// FindColumn returns the first column with the given name and its spec index.
func (t *Table) FindColumn(name string) (*Column, int, bool) {
	for index := range t.Columns {
		if t.Columns[index].Name == name {
			return &t.Columns[index], index, true
		}
	}
	return nil, 0, false
}

// OpenCell returns one decoded cell. It refuses a metadata-only column with
// source.ErrUnsupported instead of pretending a cell was missing.
func (t *Table) OpenCell(row, column int) (Cell, error) {
	if row < 0 || row >= len(t.Rows) {
		return Cell{}, &source.Error{
			Kind: source.ErrOutOfRange, Offset: uint64(row), Len: 1, SourceLen: uint64(len(t.Rows)),
		}
	}
	if column < 0 || column >= len(t.Columns) {
		return Cell{}, &source.Error{
			Kind: source.ErrOutOfRange, Offset: uint64(column), Len: 1, SourceLen: uint64(len(t.Columns)),
		}
	}
	if reason := t.Columns[column].Unsupported; reason != "" {
		name := t.Columns[column].Name
		if name == "" {
			name = fmt.Sprintf("#%d", column)
		}
		return Cell{}, &source.Error{
			Kind:   source.ErrUnsupported,
			Reason: fmt.Sprintf("column %s.%s is metadata-only: %s", t.Name, name, reason),
		}
	}
	for _, cell := range t.Rows[row].Cells {
		if cell.Column == column {
			return cell, nil
		}
	}
	return Cell{}, &source.Error{
		Kind:   source.ErrCorrupt,
		Reason: fmt.Sprintf("decoded column %d produced no cell for row %d", column, row),
	}
}

// Open parses a Realm database through a bounded single read of parent.
func Open(id source.ID, parent source.ByteSource) (*Database, error) {
	return OpenWithLimits(id, parent, DefaultLimits())
}

// OpenWithLimits parses a Realm database with explicit bounds.
func OpenWithLimits(id source.ID, parent source.ByteSource, limits Limits) (*Database, error) {
	if parent == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil parent source"}
	}
	if limits.MaxTables < 0 || limits.MaxColumns < 0 || limits.MaxTreeDepth < 0 {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "negative Realm limit"}
	}
	fileSize := parent.Len()
	if fileSize > limits.MaxFileBytes {
		return nil, limitError(fmt.Sprintf(
			"file size %d bytes exceeds the %d-byte limit", fileSize, limits.MaxFileBytes,
		))
	}
	bytes, err := source.ReadVecAt(parent, 0, fileSize)
	if err != nil {
		return nil, err
	}
	database, err := parse(bytes, limits)
	if err != nil {
		return nil, err
	}
	database.parent = parent
	database.sourceID = id
	database.stats = parent.Stats()
	return database, nil
}

// ---------------------------------------------------------------------------
// Node layout.
// ---------------------------------------------------------------------------

type node struct {
	offset     uint64
	flags      uint8
	size       int
	scheme     uint64
	width      uint8
	dataOffset uint64
	data       []byte
}

func (n *node) isInner() bool { return n.flags&0x80 != 0 }
func (n *node) hasRefs() bool { return n.flags&0x40 != 0 }
func (n *node) context() bool { return n.flags&0x20 != 0 }

func (n *node) elementOffset(index int) uint64 {
	switch n.scheme {
	case widthSchemeBits:
		return n.dataOffset + uint64(index)*uint64(n.width)/8
	case widthSchemeMultiply:
		return n.dataOffset + uint64(index)*uint64(n.width)
	default:
		return n.dataOffset + uint64(index)
	}
}

func (n *node) valueU(index int) (uint64, error) {
	if index < 0 || index >= n.size {
		return 0, invalid(n.offset, fmt.Sprintf(
			"element %d is outside the node at %d (%d element(s))", index, n.offset, n.size,
		))
	}
	switch n.scheme {
	case widthSchemeIgnore:
		if index >= len(n.data) {
			return 0, invalid(n.offset, "byte-array element is outside its payload")
		}
		return uint64(n.data[index]), nil
	case widthSchemeMultiply:
		return n.readWide(index)
	default:
		return n.readBits(index)
	}
}

func (n *node) valueI(index int) (int64, error) {
	if index < 0 || index >= n.size {
		return 0, invalid(n.offset, fmt.Sprintf(
			"element %d is outside the node at %d (%d element(s))", index, n.offset, n.size,
		))
	}
	if n.scheme == widthSchemeIgnore {
		return int64(int8(n.data[index])), nil
	}
	if n.width == 0 {
		return 0, nil
	}
	raw, err := n.valueU(index)
	if err != nil {
		return 0, err
	}
	return signExtend(raw, n.width), nil
}

func (n *node) readBits(index int) (uint64, error) {
	width := n.width
	if width == 0 {
		return 0, nil
	}
	bit := index * int(width)
	if width <= 4 {
		byteIndex := bit / 8
		if byteIndex >= len(n.data) {
			return 0, invalid(n.offset, "bit element is outside its payload")
		}
		shift := bit % 8
		mask := (uint16(1) << width) - 1
		return uint64(n.data[byteIndex]>>shift) & uint64(mask), nil
	}
	if width == 64 {
		byteIndex := bit / 8
		if byteIndex+8 > len(n.data) {
			return 0, invalid(n.offset, "64-bit element is outside its payload")
		}
		return binary.LittleEndian.Uint64(n.data[byteIndex : byteIndex+8]), nil
	}
	if width == 8 || width == 16 || width == 32 {
		byteIndex := bit / 8
		length := int(width / 8)
		if byteIndex+length > len(n.data) {
			return 0, invalid(n.offset, "wide element is outside its payload")
		}
		return readLE(n.data[byteIndex : byteIndex+length]), nil
	}
	return 0, unsupportedError(fmt.Sprintf(
		"the node at %d uses a %d-bit element width", n.offset, width,
	))
}

func (n *node) readWide(index int) (uint64, error) {
	width := int(n.width)
	if width > 8 {
		return 0, unsupportedError(fmt.Sprintf(
			"the node at %d uses %d-byte elements", n.offset, width,
		))
	}
	byteIndex := index * width
	if byteIndex+width > len(n.data) {
		return 0, invalid(n.offset, "element is outside its payload")
	}
	return readLE(n.data[byteIndex : byteIndex+width]), nil
}

func (n *node) block(index int) ([]byte, error) {
	if n.scheme != widthSchemeMultiply {
		return nil, unsupportedError(fmt.Sprintf(
			"the node at %d is not a fixed-width block array", n.offset,
		))
	}
	width := int(n.width)
	start := index * width
	if start < 0 || start+width > len(n.data) {
		return nil, invalid(n.offset, "block element is outside its payload")
	}
	return n.data[start : start+width], nil
}

func (n *node) childRef(index int) (uint64, error) {
	raw, err := n.valueU(index)
	if err != nil {
		return 0, err
	}
	if raw&1 != 0 {
		return 0, invalid(n.offset, fmt.Sprintf(
			"slot %d of the node at %d is a tagged integer, not a ref", index, n.offset,
		))
	}
	return raw, nil
}

func readLE(bytes []byte) uint64 {
	var value uint64
	for index, current := range bytes {
		value |= uint64(current) << (8 * index)
	}
	return value
}

func signExtend(value uint64, width uint8) int64 {
	if width == 0 {
		return 0
	}
	if width >= 64 {
		return int64(value)
	}
	shift := 64 - uint(width)
	return int64(value<<shift) >> shift
}

func nodeAt(bytes []byte, offset uint64) (node, error) {
	if offset%8 != 0 {
		return node{}, invalid(offset, fmt.Sprintf("node ref %d is not 8-byte aligned", offset))
	}
	if offset < HeaderBytes {
		return node{}, invalid(offset, fmt.Sprintf(
			"node ref %d lies inside the %d-byte file header", offset, HeaderBytes,
		))
	}
	if offset > uint64(maxInt()) {
		return node{}, invalid(offset, fmt.Sprintf("node ref %d does not fit the address space", offset))
	}
	start := int(offset)
	if start+NodeHeaderBytes > len(bytes) {
		return node{}, invalid(offset, fmt.Sprintf(
			"node ref %d is outside the %d-byte file", offset, len(bytes),
		))
	}
	if binary.LittleEndian.Uint32(bytes[start:start+4]) != NodeMarker {
		return node{}, invalid(offset, fmt.Sprintf(
			"the node at %d does not start with the 0x41414141 marker", offset,
		))
	}
	flags := bytes[start+4]
	size := int(bytes[start+5])<<16 | int(bytes[start+6])<<8 | int(bytes[start+7])
	scheme := uint64((flags >> 3) & 0x03)
	if scheme == 3 {
		return node{}, unsupportedError(fmt.Sprintf(
			"the node at %d uses width encoding 3, which the Realm format reserves", offset,
		))
	}
	width := uint8(uint16(1)<<(flags&0x07)) >> 1
	var payload int
	switch scheme {
	case widthSchemeBits:
		bits := uint64(size) * uint64(width)
		if bits+7 < bits {
			return node{}, invalid(offset, fmt.Sprintf(
				"the node at %d overflows its element count", offset,
			))
		}
		payload = int((bits + 7) / 8)
	case widthSchemeMultiply:
		product := uint64(size) * uint64(width)
		if product > uint64(maxInt()) {
			return node{}, invalid(offset, fmt.Sprintf(
				"the node at %d overflows its element count", offset,
			))
		}
		payload = int(product)
	default:
		payload = size
	}
	dataOffset := start + NodeHeaderBytes
	end := dataOffset + payload
	if end < dataOffset || end > len(bytes) {
		return node{}, invalid(offset, fmt.Sprintf(
			"the node at %d needs %d payload byte(s), past the %d-byte file",
			offset, payload, len(bytes),
		))
	}
	return node{
		offset: offset, flags: flags, size: size, scheme: scheme, width: width,
		dataOffset: uint64(dataOffset), data: bytes[dataOffset:end],
	}, nil
}

func invalid(offset uint64, reason string) error {
	return source.NewCorrupt(offset, reason)
}

func unsupportedError(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func limitError(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: "Realm limit exceeded: " + reason}
}

func maxInt() int { return int(^uint(0) >> 1) }

// ---------------------------------------------------------------------------
// Whole-file parse.
// ---------------------------------------------------------------------------

func parse(bytes []byte, limits Limits) (*Database, error) {
	if len(bytes) < HeaderBytes {
		return nil, invalid(0, fmt.Sprintf(
			"a Realm header needs %d bytes; the file has %d", HeaderBytes, len(bytes),
		))
	}
	if len(bytes)%8 != 0 {
		return nil, invalid(0, fmt.Sprintf(
			"a Realm file is a sequence of 8-byte-aligned nodes; %d bytes is not a multiple of 8",
			len(bytes),
		))
	}
	if string(bytes[16:20]) != Magic {
		return nil, invalid(16,
			"not a Realm database: the T-DB mnemonic is absent at offset 16 "+
				"(an encrypted Realm file without its key, a truncated copy and a "+
				"non-Realm file present the same header)")
	}
	flags := bytes[23]
	if flags&^byte(0x01) != 0 {
		return nil, unsupportedError(fmt.Sprintf(
			"Realm header flag byte %#04x sets bits this reader does not know; "+
				"only the top-ref select bit (0x01) is defined", flags,
		))
	}
	topSlot := flags & 0x01
	formatVersion := bytes[20+int(topSlot)]
	topRef := readLE(bytes[int(topSlot)*8 : int(topSlot)*8+8])
	fileSize := uint64(len(bytes))
	if topSlot == 0 && topRef == ^uint64(0) {
		return nil, unsupportedError(
			"Realm streaming form (top ref all-ones with the footer at the end of " +
				"the file); this reader decodes only the normal file form",
		)
	}
	if formatVersion == 0 {
		if topRef != 0 {
			return nil, invalid(0, "Realm file format version 0 with a non-zero top ref")
		}
		return &Database{
			Header: Header{
				TopRef: topRef, TopSlot: topSlot, FormatVersion: formatVersion,
				Flags: flags, FileSize: fileSize, LogicalSize: 0,
			},
		}, nil
	}
	if formatVersion < MinFormatVersion || formatVersion > MaxFormatVersion {
		return nil, unsupportedError(fmt.Sprintf(
			"Realm file format version %d; this reader decodes the cluster node "+
				"layout used by versions %d through %d, so a version outside that "+
				"range is refused rather than guessed",
			formatVersion, MinFormatVersion, MaxFormatVersion,
		))
	}
	if topRef == 0 {
		return nil, invalid(0, "the Realm header names no top array but the file is not empty")
	}
	top, err := nodeAt(bytes, topRef)
	if err != nil {
		return nil, err
	}
	if top.isInner() {
		return nil, invalid(topRef, fmt.Sprintf(
			"the group top at %d is marked as an inner B+-tree node", topRef,
		))
	}
	if !top.hasRefs() {
		return nil, invalid(topRef, fmt.Sprintf(
			"the group top at %d is not a ref array", topRef,
		))
	}
	if top.size < 3 || top.size > 12 {
		return nil, unsupportedError(fmt.Sprintf(
			"the group top at %d has %d slot(s); Realm's group records at most 12",
			topRef, top.size,
		))
	}
	logicalRaw, err := top.valueU(2)
	if err != nil {
		return nil, err
	}
	if logicalRaw&1 == 0 {
		return nil, invalid(topRef,
			"the group top's logical file size is a ref, not a tagged integer")
	}
	logicalSize := logicalRaw >> 1
	if logicalSize > fileSize {
		return nil, invalid(topRef, fmt.Sprintf(
			"the group top records a logical size of %d bytes, above the physical "+
				"file size of %d; the file is truncated", logicalSize, fileSize,
		))
	}
	namesRef, err := top.childRef(0)
	if err != nil {
		return nil, err
	}
	tablesRef, err := top.childRef(1)
	if err != nil {
		return nil, err
	}
	if namesRef == 0 || tablesRef == 0 {
		return nil, invalid(topRef,
			"the group top does not name both the table-name array and the table-ref array")
	}
	names, err := nodeAt(bytes, namesRef)
	if err != nil {
		return nil, err
	}
	if names.isInner() || names.hasRefs() {
		return nil, invalid(namesRef, fmt.Sprintf(
			"the group's table-name array at %d is not a plain string array", namesRef,
		))
	}
	tablesNode, err := nodeAt(bytes, tablesRef)
	if err != nil {
		return nil, err
	}
	if tablesNode.isInner() || !tablesNode.hasRefs() {
		return nil, invalid(tablesRef, fmt.Sprintf(
			"the group's table-ref array at %d is not a ref array", tablesRef,
		))
	}
	if tablesNode.size > limits.MaxTables {
		return nil, limitError(fmt.Sprintf(
			"the group names %d tables, above the %d-table bound", tablesNode.size, limits.MaxTables,
		))
	}
	if names.size != tablesNode.size {
		return nil, invalid(topRef, fmt.Sprintf(
			"the group has %d table name(s) and %d table ref(s)", names.size, tablesNode.size,
		))
	}

	database := &Database{
		Header: Header{
			TopRef: topRef, TopSlot: topSlot, FormatVersion: formatVersion,
			Flags: flags, FileSize: fileSize, LogicalSize: logicalSize,
		},
		Free: readFreeLists(bytes, &top, fileSize),
	}
	seenNames := make(map[string]struct{})
	for index := 0; index < tablesNode.size; index++ {
		name, _, err := readShortString(&names, index, false)
		if err != nil {
			return nil, err
		}
		nameOffset := names.elementOffset(index)
		rawRef, err := tablesNode.valueU(index)
		if err != nil {
			return nil, err
		}
		if rawRef&1 != 0 {
			database.Warnings = append(database.Warnings, fmt.Sprintf(
				"table entry %d (%q) is a freed slot (tagged value %d), not a table", index, name, rawRef,
			))
			continue
		}
		if rawRef == 0 {
			database.Warnings = append(database.Warnings, fmt.Sprintf(
				"table entry %d (%q) holds no table ref", index, name,
			))
			continue
		}
		if _, ok := seenNames[name]; ok {
			database.Warnings = append(database.Warnings, fmt.Sprintf(
				"the group names the table %q more than once", name,
			))
		}
		seenNames[name] = struct{}{}
		table, err := parseTable(bytes, rawRef, name, nameOffset, limits)
		if err != nil {
			return nil, err
		}
		database.Tables = append(database.Tables, *table)
	}
	return database, nil
}

// ---------------------------------------------------------------------------
// Free lists.
// ---------------------------------------------------------------------------

func readFreeLists(bytes []byte, top *node, fileSize uint64) FreeLists {
	var free FreeLists
	refAt := func(index int) uint64 {
		if top.size <= index {
			return 0
		}
		ref, err := top.childRef(index)
		if err != nil {
			return 0
		}
		return ref
	}
	positionsRef := refAt(3)
	lengthsRef := refAt(4)
	versionsRef := refAt(5)
	if positionsRef == 0 && lengthsRef == 0 {
		return free
	}
	if positionsRef == 0 || lengthsRef == 0 {
		free.Warnings = append(free.Warnings,
			"the group records only one of the free-position and free-length arrays; "+
				"the free list is not reported")
		return free
	}
	positions, err := plainArray(bytes, positionsRef)
	if err != nil {
		free.Warnings = append(free.Warnings, "the free-position array could not be read: "+err.Error())
		return free
	}
	lengths, err := plainArray(bytes, lengthsRef)
	if err != nil {
		free.Warnings = append(free.Warnings, "the free-length array could not be read: "+err.Error())
		return free
	}
	var versions []uint64
	if versionsRef != 0 {
		versions, err = plainArray(bytes, versionsRef)
		if err != nil {
			free.Warnings = append(free.Warnings, "the free-version array could not be read: "+err.Error())
			versions = nil
		}
	}
	if len(positions) != len(lengths) {
		free.Warnings = append(free.Warnings, fmt.Sprintf(
			"the free list has %d position(s) and %d length(s)", len(positions), len(lengths),
		))
	}
	if versions != nil && len(versions) != len(positions) {
		free.Warnings = append(free.Warnings, fmt.Sprintf(
			"the free list has %d position(s) and %d version(s)", len(positions), len(versions),
		))
	}
	count := len(positions)
	if len(lengths) < count {
		count = len(lengths)
	}
	for index := 0; index < count; index++ {
		chunk := FreeChunk{Offset: positions[index], Length: lengths[index]}
		if versions != nil && index < len(versions) {
			version := versions[index]
			chunk.Version = &version
		}
		if chunk.Length > ^uint64(0)-chunk.Offset || chunk.Offset+chunk.Length > fileSize {
			free.Warnings = append(free.Warnings, fmt.Sprintf(
				"free region %d at %d (+%d B) lies outside the %d-byte file",
				index, chunk.Offset, chunk.Length, fileSize,
			))
		}
		free.Chunks = append(free.Chunks, chunk)
	}
	return free
}

func plainArray(bytes []byte, reference uint64) ([]uint64, error) {
	n, err := nodeAt(bytes, reference)
	if err != nil {
		return nil, err
	}
	if n.isInner() || n.hasRefs() {
		return nil, invalid(reference, fmt.Sprintf(
			"the array at %d is not a plain integer array", reference,
		))
	}
	values := make([]uint64, n.size)
	for index := 0; index < n.size; index++ {
		value, err := n.valueU(index)
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

// readShortString decodes an ArrayStringShort entry. The bool reports whether
// a value is present: a zero-width array and the width terminator encode null
// in a nullable array and the empty string in a non-nullable one.
func readShortString(n *node, index int, nullable bool) (string, bool, error) {
	if index < 0 || index >= n.size {
		return "", false, invalid(n.offset, fmt.Sprintf(
			"string index %d is outside the node at %d (%d element(s))", index, n.offset, n.size,
		))
	}
	if n.scheme != widthSchemeMultiply {
		return "", false, invalid(n.offset, fmt.Sprintf(
			"the string array at %d is not a fixed-width block array", n.offset,
		))
	}
	width := int(n.width)
	if width == 0 {
		return "", !nullable, nil
	}
	if width > 64 {
		return "", false, unsupportedError(fmt.Sprintf(
			"the string array at %d has a %d-byte block, above Realm's 64-byte limit",
			n.offset, width,
		))
	}
	block, err := n.block(index)
	if err != nil {
		return "", false, err
	}
	last := int(block[width-1])
	if last == width {
		return "", !nullable, nil
	}
	if last > width-1 {
		return "", false, invalid(n.offset, fmt.Sprintf(
			"the string at %d[%d] has a terminator byte of %d, above its %d-byte block",
			n.offset, index, last, width,
		))
	}
	length := (width - 1) - last
	if block[length] != 0 {
		return "", false, invalid(n.offset, fmt.Sprintf(
			"the string at %d[%d] is not NUL-terminated at byte %d", n.offset, index, length,
		))
	}
	if !utf8.Valid(block[:length]) {
		return "", false, invalid(n.offset, fmt.Sprintf(
			"the string at %d[%d] is not valid UTF-8", n.offset, index,
		))
	}
	return string(block[:length]), true, nil
}

// ---------------------------------------------------------------------------
// Tables, columns and rows.
// ---------------------------------------------------------------------------

func parseTable(bytes []byte, topRef uint64, name string, nameOffset uint64, limits Limits) (*Table, error) {
	top, err := nodeAt(bytes, topRef)
	if err != nil {
		return nil, err
	}
	if top.isInner() || !top.hasRefs() {
		return nil, invalid(topRef, fmt.Sprintf(
			"the top array of table %q at %d is not a ref array", name, topRef,
		))
	}
	if top.size < 4 {
		return nil, unsupportedError(fmt.Sprintf(
			"the top array of table %q has %d slot(s); the cluster format needs at least 4",
			name, top.size,
		))
	}
	rawKey, err := top.valueU(3)
	if err != nil {
		return nil, err
	}
	if rawKey&1 == 0 {
		return nil, invalid(topRef, fmt.Sprintf(
			"the table key of %q at %d is a ref, not a tagged integer", name, topRef,
		))
	}
	tableKey := uint32(rawKey >> 1)
	specRef, err := top.childRef(0)
	if err != nil {
		return nil, err
	}
	clusterRef, err := top.childRef(2)
	if err != nil {
		return nil, err
	}
	if specRef == 0 {
		return nil, invalid(topRef, fmt.Sprintf("table %q names no spec array", name))
	}
	spec, err := nodeAt(bytes, specRef)
	if err != nil {
		return nil, err
	}
	if spec.isInner() || !spec.hasRefs() {
		return nil, invalid(specRef, fmt.Sprintf(
			"the spec of table %q at %d is not a ref array", name, specRef,
		))
	}
	if spec.size < 6 {
		return nil, unsupportedError(fmt.Sprintf(
			"the spec of table %q has %d slot(s); column keys need 6", name, spec.size,
		))
	}
	refs := make([]uint64, 6)
	for index := 0; index < 6; index++ {
		refs[index], err = spec.childRef(index)
		if err != nil {
			return nil, err
		}
	}
	typesRef, namesRef, attrsRef := refs[0], refs[1], refs[2]
	enumRef, keysRef := refs[4], refs[5]
	if typesRef == 0 || namesRef == 0 || attrsRef == 0 || keysRef == 0 {
		return nil, unsupportedError(fmt.Sprintf(
			"the spec of table %q is missing the type, name, attribute or column-key array", name,
		))
	}
	types, err := nodeAt(bytes, typesRef)
	if err != nil {
		return nil, err
	}
	specNames, err := nodeAt(bytes, namesRef)
	if err != nil {
		return nil, err
	}
	attrs, err := nodeAt(bytes, attrsRef)
	if err != nil {
		return nil, err
	}
	keys, err := nodeAt(bytes, keysRef)
	if err != nil {
		return nil, err
	}
	for _, parallel := range []*node{&types, &attrs, &keys} {
		if parallel.isInner() || parallel.hasRefs() {
			return nil, invalid(parallel.offset, fmt.Sprintf(
				"a parallel spec array of table %q is not a plain integer array", name,
			))
		}
	}
	if specNames.isInner() || specNames.hasRefs() {
		return nil, invalid(specNames.offset, fmt.Sprintf(
			"the column-name array of table %q is not a short-string array", name,
		))
	}
	count := types.size
	if count > limits.MaxColumns {
		return nil, limitError(fmt.Sprintf(
			"table %q has %d columns, above the %d-column bound", name, count, limits.MaxColumns,
		))
	}
	if attrs.size != count || keys.size != count {
		return nil, invalid(specRef, fmt.Sprintf(
			"the spec of table %q has %d type(s), %d attribute(s) and %d key(s)",
			name, count, attrs.size, keys.size,
		))
	}

	var oppositeNode *node
	if top.size > 7 {
		if oppositeRef, err := top.childRef(7); err == nil && oppositeRef != 0 {
			opposite, err := nodeAt(bytes, oppositeRef)
			if err != nil {
				return nil, err
			}
			oppositeNode = &opposite
		}
	}
	var enumNode *node
	if enumRef != 0 {
		enums, err := nodeAt(bytes, enumRef)
		if err != nil {
			return nil, err
		}
		if enums.isInner() {
			return nil, invalid(enumRef, fmt.Sprintf(
				"the enum-key array of table %q is an inner B+-tree node", name,
			))
		}
		enumNode = &enums
	}

	columns := make([]Column, 0, count)
	var warnings []string
	nameCursor := 0
	for index := 0; index < count; index++ {
		typeValue, err := types.valueU(index)
		if err != nil {
			return nil, err
		}
		columnType := ColumnTypeFromCode(uint8(typeValue & 0xffff))
		attrValue, err := attrs.valueU(index)
		if err != nil {
			return nil, err
		}
		colKey, err := keys.valueU(index)
		if err != nil {
			return nil, err
		}
		specAttr := uint8(attrValue & 0xff)
		attr := uint32((colKey >> 22) & 0xff)
		if uint32(specAttr) != attr {
			warnings = append(warnings, fmt.Sprintf(
				"column %d stores attributes %#04x in the spec but %#04x in its column key",
				index, specAttr, attr,
			))
		}
		leafIndex := int(colKey & 0xffff)
		nullable := attr&16 != 0
		indexed := attr&1 != 0
		unique := attr&2 != 0
		collection := attr&(32|64|128) != 0
		keyType := uint8((colKey >> 16) & 0x3f)
		var unsupportedReason string
		setRefusal := func(reason string) {
			if unsupportedReason == "" {
				unsupportedReason = reason
			}
		}
		if keyType != columnType.Code() {
			setRefusal(fmt.Sprintf(
				"the column key names type code %d, but the spec types the column as %s (%d)",
				keyType, columnType.Label(), columnType.Code(),
			))
		}

		columnName := ""
		var columnNameOffset uint64
		hasNameOffset := false
		if columnType != ColumnBackLink {
			nameIndex := nameCursor
			nameCursor++
			value, present, err := readShortString(&specNames, nameIndex, false)
			if err != nil {
				return nil, err
			}
			if present {
				columnName = value
				columnNameOffset = specNames.elementOffset(nameIndex)
				hasNameOffset = true
			} else {
				warnings = append(warnings, fmt.Sprintf(
					"column %d has no stored name; the entry is reported as an empty name", index,
				))
			}
		}

		stringEnum := false
		if enumNode != nil && columnType == ColumnString {
			if index < enumNode.size {
				value, err := enumNode.valueU(index)
				if err != nil {
					return nil, err
				}
				stringEnum = value != 0
			} else {
				setRefusal(fmt.Sprintf(
					"the spec's enum-key array has %d entries, short of column %d",
					enumNode.size, index,
				))
			}
		}

		var linkTarget uint32
		hasLinkTarget := false
		if columnType == ColumnLink {
			if oppositeNode == nil {
				setRefusal("the table has no opposite-table array, so the link's target table is unknown")
			} else if leafIndex < oppositeNode.size {
				raw, err := oppositeNode.valueU(leafIndex)
				if err != nil {
					return nil, err
				}
				if raw == tableKeyNull {
					// The slot was never assigned; the target is unknown.
				} else if raw < tableKeyNull {
					linkTarget = uint32(raw)
					hasLinkTarget = true
				} else {
					setRefusal(fmt.Sprintf(
						"the opposite-table array records %#x for leaf index %d, "+
							"outside the table-key range", raw, leafIndex,
					))
				}
			} else {
				setRefusal(fmt.Sprintf(
					"the opposite-table array has no entry for leaf index %d", leafIndex,
				))
			}
		}
		if reason := columnTypeRefusal(columnType); reason != "" {
			setRefusal(reason)
		}
		if collection {
			setRefusal("collection column (list, set or dictionary); this reader decodes scalar columns only")
		}
		if stringEnum {
			setRefusal("string-enum column; its values are keys into a per-column enum table this reader does not resolve")
		}
		columns = append(columns, Column{
			Name: columnName, NameOffset: columnNameOffset, HasNameOffset: hasNameOffset,
			SpecIndex: index, LeafIndex: leafIndex, Type: columnType, ColKey: colKey,
			Nullable: nullable, Indexed: indexed, Unique: unique,
			Collection: collection, StringEnum: stringEnum,
			LinkTarget: linkTarget, HasLinkTarget: hasLinkTarget,
			Unsupported: unsupportedReason,
		})
	}
	if nameCursor != specNames.size {
		warnings = append(warnings, fmt.Sprintf(
			"the spec has %d stored name(s) for %d public column(s)", specNames.size, nameCursor,
		))
	}

	table := &Table{
		Name: name, NameOffset: nameOffset, HasNameOffset: true,
		Key: tableKey, TopRef: topRef, Columns: columns, Warnings: warnings,
	}
	leaves, err := collectClusterLeaves(bytes, clusterRef, limits)
	if err != nil {
		return nil, err
	}
	var totalRows uint64
	for index := range leaves {
		totalRows += uint64(leaves[index].count)
		if totalRows > limits.MaxRows {
			return nil, limitError(fmt.Sprintf(
				"table %q holds more than %d rows", name, limits.MaxRows,
			))
		}
	}

	decoded := make([][]columnValues, len(table.Columns))
	refusals := make([]string, len(table.Columns))
	for index := range table.Columns {
		column := &table.Columns[index]
		if column.Unsupported != "" {
			continue
		}
		perLeaf := make([]columnValues, len(leaves))
		var refusal string
		for leafIndex := range leaves {
			values, reason := decodeLeafColumn(bytes, &leaves[leafIndex], column)
			if reason != "" {
				refusal = reason
				break
			}
			perLeaf[leafIndex] = values
		}
		if refusal != "" {
			refusals[index] = refusal
			continue
		}
		decoded[index] = perLeaf
	}
	for index := range table.Columns {
		if refusals[index] != "" {
			table.Columns[index].Unsupported = refusals[index]
		}
	}

	table.Rows = make([]Row, 0, int(totalRows))
	base := 0
	for leafIndex := range leaves {
		leaf := &leaves[leafIndex]
		for local := 0; local < leaf.count; local++ {
			key, err := leaf.rowKey(local)
			if err != nil {
				return nil, err
			}
			cells := make([]Cell, 0, len(table.Columns))
			for columnIndex, perLeaf := range decoded {
				if perLeaf == nil {
					continue
				}
				values := &perLeaf[leafIndex]
				cells = append(cells, Cell{
					Column: columnIndex, Offset: values.offsets[local], Value: values.values[local],
				})
			}
			table.Rows = append(table.Rows, Row{Key: key, Index: base + local, Cells: cells})
		}
		base += leaf.count
	}
	return table, nil
}

func columnTypeRefusal(columnType ColumnType) string {
	switch columnType {
	case ColumnInt, ColumnBool, ColumnString, ColumnBinary, ColumnTimestamp,
		ColumnFloat, ColumnDouble, ColumnLink, ColumnBackLink:
		return ""
	case ColumnMixed:
		return "Mixed column; a value's runtime type tag is not decoded by this reader"
	case ColumnDecimal:
		return "Decimal column; its 128-bit mantissa layout is not decoded by this reader"
	case ColumnObjectID:
		return "ObjectId column; its 12-byte object identifier is not decoded by this reader"
	case ColumnUUID:
		return "UUID column; its 16-byte identifier is not decoded by this reader"
	case ColumnTypedLink:
		return "TypedLink column; its (table, row) pair is not decoded by this reader"
	default:
		return fmt.Sprintf(
			"column type code %d is not a current Realm type; the retired type is named and not guessed",
			columnType.Code(),
		)
	}
}

// ---------------------------------------------------------------------------
// Cluster tree.
// ---------------------------------------------------------------------------

type leaf struct {
	node    node
	baseKey uint64
	count   int
	keys    *node
}

func (l *leaf) rowKey(local int) (uint64, error) {
	var stored uint64
	if l.keys != nil {
		value, err := l.keys.valueU(local)
		if err != nil {
			return 0, err
		}
		stored = value
	} else {
		stored = uint64(local)
	}
	if stored > ^uint64(0)-l.baseKey {
		return 0, invalid(l.node.offset, "a cluster row key overflows 64 bits")
	}
	return stored + l.baseKey, nil
}

func leafFromNode(bytes []byte, n node, baseKey uint64) (leaf, error) {
	raw, err := n.valueU(0)
	if err != nil {
		return leaf{}, err
	}
	if raw&1 != 0 {
		count := raw >> 1
		if count > uint64(maxInt()) {
			return leaf{}, limitError("compact leaf row count exceeds the address space")
		}
		return leaf{node: n, baseKey: baseKey, count: int(count)}, nil
	}
	if raw == 0 {
		return leaf{node: n, baseKey: baseKey, count: 0}, nil
	}
	keys, err := nodeAt(bytes, raw)
	if err != nil {
		return leaf{}, err
	}
	if keys.isInner() || keys.hasRefs() {
		return leaf{}, invalid(raw, fmt.Sprintf(
			"the key array of the cluster leaf at %d is not a plain integer array", n.offset,
		))
	}
	return leaf{node: n, baseKey: baseKey, count: keys.size, keys: &keys}, nil
}

func collectClusterLeaves(bytes []byte, rootRef uint64, limits Limits) ([]leaf, error) {
	if rootRef == 0 {
		return nil, nil
	}
	var leaves []leaf
	visited := make(map[uint64]struct{})
	if err := collectLeavesInner(bytes, rootRef, 0, 0, limits, visited, &leaves); err != nil {
		return nil, err
	}
	return leaves, nil
}

func collectLeavesInner(bytes []byte, reference uint64, depth int, baseKey uint64, limits Limits, visited map[uint64]struct{}, leaves *[]leaf) error {
	if depth > limits.MaxTreeDepth {
		return limitError(fmt.Sprintf(
			"the cluster tree nests deeper than %d levels", limits.MaxTreeDepth,
		))
	}
	if _, ok := visited[reference]; ok {
		return invalid(reference, fmt.Sprintf(
			"the cluster tree at %d points back at an already-visited node (a cycle)", reference,
		))
	}
	visited[reference] = struct{}{}
	n, err := nodeAt(bytes, reference)
	if err != nil {
		return err
	}
	if !n.hasRefs() {
		return invalid(reference, fmt.Sprintf(
			"the cluster node at %d is not a ref array", reference,
		))
	}
	if !n.isInner() {
		decoded, err := leafFromNode(bytes, n, baseKey)
		if err != nil {
			return err
		}
		*leaves = append(*leaves, decoded)
		return nil
	}
	if n.size < 3 {
		return invalid(reference, fmt.Sprintf(
			"the cluster inner node at %d has %d slot(s)", reference, n.size,
		))
	}
	childCount := n.size - 3
	keysRef, err := n.valueU(0)
	if err != nil {
		return err
	}
	var keys *node
	if keysRef != 0 {
		decoded, err := nodeAt(bytes, keysRef)
		if err != nil {
			return err
		}
		if decoded.isInner() || decoded.hasRefs() {
			return invalid(keysRef, fmt.Sprintf(
				"the key array of the cluster inner node at %d is not a plain integer array",
				reference,
			))
		}
		if decoded.size != childCount {
			return invalid(reference, fmt.Sprintf(
				"the cluster inner node at %d has %d child(ren) but %d key(s)",
				reference, childCount, decoded.size,
			))
		}
		keys = &decoded
	}
	depthRaw, err := n.valueU(1)
	if err != nil {
		return err
	}
	if depthRaw&1 == 0 {
		return invalid(reference, fmt.Sprintf(
			"the subtree-depth slot of the cluster inner node at %d is a ref, not a tagged integer",
			reference,
		))
	}
	subtreeDepth := depthRaw >> 1
	if subtreeDepth > 7 {
		return unsupportedError(fmt.Sprintf(
			"the cluster inner node at %d records a subtree depth of %d, which this reader does not decode",
			reference, subtreeDepth,
		))
	}
	shift := subtreeDepth * 8
	for index := 0; index < childCount; index++ {
		child, err := n.childRef(index + 3)
		if err != nil {
			return err
		}
		if child == 0 {
			return invalid(reference, fmt.Sprintf(
				"the cluster inner node at %d has an empty child ref at slot %d",
				reference, index+3,
			))
		}
		var childOffset uint64
		if keys != nil {
			value, err := keys.valueU(index)
			if err != nil {
				return err
			}
			childOffset = value
		} else {
			if uint64(index) > ^uint64(0)>>shift {
				return invalid(reference, "a compact cluster child offset overflows the 64-bit key space")
			}
			childOffset = uint64(index) << shift
		}
		if childOffset > ^uint64(0)-baseKey {
			return invalid(reference, "a cluster child offset overflows the 64-bit key space")
		}
		if err := collectLeavesInner(bytes, child, depth+1, baseKey+childOffset, limits, visited, leaves); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Column decoding.
// ---------------------------------------------------------------------------

type columnValues struct {
	offsets []uint64
	values  []Value
}

func decodeLeafColumn(bytes []byte, l *leaf, column *Column) (columnValues, string) {
	slot := column.LeafIndex + 1
	if slot >= l.node.size {
		return columnValues{}, fmt.Sprintf(
			"the cluster leaf has no slot for leaf index %d (%d slot(s))",
			column.LeafIndex, l.node.size,
		)
	}
	raw, err := l.node.valueU(slot)
	if err != nil {
		return columnValues{}, err.Error()
	}
	if raw&1 != 0 {
		return columnValues{}, fmt.Sprintf(
			"the column slot for leaf index %d holds a tagged value, not a ref", column.LeafIndex,
		)
	}
	if raw == 0 {
		return columnValues{}, fmt.Sprintf(
			"the column slot for leaf index %d is a hole; its values are unavailable", column.LeafIndex,
		)
	}
	n, err := nodeAt(bytes, raw)
	if err != nil {
		return columnValues{}, err.Error()
	}
	if n.isInner() {
		return columnValues{}, "B+-tree column array (the leaf was split); this reader decodes a single array node"
	}
	values, reason := decodeColumn(bytes, &n, column, l.count)
	if reason != "" {
		return columnValues{}, reason
	}
	if len(values.offsets) != l.count || len(values.values) != l.count {
		return columnValues{}, fmt.Sprintf(
			"the column decoded %d value(s) for %d row(s)", len(values.values), l.count,
		)
	}
	return values, ""
}

func nullOrEmpty(nullable bool) Value {
	if nullable {
		return Value{Kind: ValueNull}
	}
	return Value{Kind: ValueString}
}

func decodeColumn(bytes []byte, n *node, column *Column, count int) (columnValues, string) {
	typeLabel := column.Type.Label()
	if n.hasRefs() &&
		column.Type != ColumnString && column.Type != ColumnBinary && column.Type != ColumnTimestamp {
		return columnValues{}, fmt.Sprintf("the %s column is stored as a ref array", typeLabel)
	}
	switch column.Type {
	case ColumnInt:
		return decodeInt(n, column, count)
	case ColumnBool:
		return decodeBool(n, count)
	case ColumnString:
		return decodeString(bytes, n, column, count)
	case ColumnBinary:
		return decodeBinary(bytes, n, count)
	case ColumnFloat:
		return decodeBasicFloat(n, count, true)
	case ColumnDouble:
		return decodeBasicFloat(n, count, false)
	case ColumnTimestamp:
		return decodeTimestamp(bytes, n, count)
	case ColumnLink:
		return decodeLink(n, column, count)
	case ColumnBackLink:
		return columnValues{}, "BackLink column; its values are derived from the target table and carry no cells"
	default:
		return columnValues{}, fmt.Sprintf("%s column is not decoded", typeLabel)
	}
}

func expectSize(n *node, count int, what string) string {
	if n.size != count {
		return fmt.Sprintf(
			"%s array holds %d element(s), but the leaf holds %d row(s)", what, n.size, count,
		)
	}
	return ""
}

func decodeInt(n *node, column *Column, count int) (columnValues, string) {
	offsets := make([]uint64, 0, count)
	values := make([]Value, 0, count)
	if column.Nullable {
		if n.size != count+1 {
			return columnValues{}, fmt.Sprintf(
				"nullable Int array holds %d element(s) for %d row(s); it needs one null sentinel",
				n.size, count,
			)
		}
		sentinel, err := n.valueU(0)
		if err != nil {
			return columnValues{}, err.Error()
		}
		for index := 0; index < count; index++ {
			raw, err := n.valueU(index + 1)
			if err != nil {
				return columnValues{}, err.Error()
			}
			offsets = append(offsets, n.elementOffset(index+1))
			if raw == sentinel {
				values = append(values, Value{Kind: ValueNull})
			} else {
				values = append(values, Value{Kind: ValueInt, Int: signExtend(raw, n.width)})
			}
		}
	} else {
		if reason := expectSize(n, count, "Int"); reason != "" {
			return columnValues{}, reason
		}
		for index := 0; index < count; index++ {
			value, err := n.valueI(index)
			if err != nil {
				return columnValues{}, err.Error()
			}
			offsets = append(offsets, n.elementOffset(index))
			values = append(values, Value{Kind: ValueInt, Int: value})
		}
	}
	return columnValues{offsets: offsets, values: values}, ""
}

func decodeBool(n *node, count int) (columnValues, string) {
	if reason := expectSize(n, count, "Bool"); reason != "" {
		return columnValues{}, reason
	}
	offsets := make([]uint64, 0, count)
	values := make([]Value, 0, count)
	for index := 0; index < count; index++ {
		raw, err := n.valueU(index)
		if err != nil {
			return columnValues{}, err.Error()
		}
		offsets = append(offsets, n.elementOffset(index))
		switch raw {
		case 3:
			values = append(values, Value{Kind: ValueNull})
		case 0:
			values = append(values, Value{Kind: ValueBool, Bool: false})
		default:
			values = append(values, Value{Kind: ValueBool, Bool: true})
		}
	}
	return columnValues{offsets: offsets, values: values}, ""
}

func decodeString(bytes []byte, n *node, column *Column, count int) (columnValues, string) {
	if n.hasRefs() {
		if n.context() {
			return columnValues{}, "string column in big-blob form (values above the small-blob bound); this reader decodes the fixed-width short-string and small-blob forms"
		}
		return decodeSmallBlobs(bytes, n, count, true)
	}
	if n.scheme != widthSchemeMultiply {
		return columnValues{}, "short-string column whose elements are not fixed-width blocks"
	}
	if reason := expectSize(n, count, "String"); reason != "" {
		return columnValues{}, reason
	}
	width := int(n.width)
	if width > 64 {
		return columnValues{}, fmt.Sprintf(
			"short-string column with a %d-byte block, above Realm's 64-byte limit", width,
		)
	}
	offsets := make([]uint64, 0, count)
	values := make([]Value, 0, count)
	for index := 0; index < count; index++ {
		offsets = append(offsets, n.elementOffset(index))
		if width == 0 {
			values = append(values, nullOrEmpty(column.Nullable))
			continue
		}
		block, err := n.block(index)
		if err != nil {
			return columnValues{}, err.Error()
		}
		last := int(block[width-1])
		if last == width {
			values = append(values, nullOrEmpty(column.Nullable))
			continue
		}
		if last > width-1 {
			return columnValues{}, fmt.Sprintf(
				"short string %d has a terminator byte of %d, above its %d-byte block",
				index, last, width,
			)
		}
		length := (width - 1) - last
		if block[length] != 0 {
			return columnValues{}, fmt.Sprintf(
				"short string %d is not NUL-terminated at byte %d", index, length,
			)
		}
		if !utf8.Valid(block[:length]) {
			return columnValues{}, fmt.Sprintf("short string %d is not valid UTF-8", index)
		}
		values = append(values, Value{Kind: ValueString, String: string(block[:length])})
	}
	return columnValues{offsets: offsets, values: values}, ""
}

func decodeBinary(bytes []byte, n *node, count int) (columnValues, string) {
	if !n.hasRefs() {
		return columnValues{}, "Binary column that is not a small-blob ref array"
	}
	if n.context() {
		return columnValues{}, "binary column in big-blob form (values above the small-blob bound); this reader decodes the small-blob form"
	}
	return decodeSmallBlobs(bytes, n, count, false)
}

func decodeSmallBlobs(bytes []byte, n *node, count int, isString bool) (columnValues, string) {
	if n.size != 3 {
		return columnValues{}, fmt.Sprintf(
			"small-blob array has %d ref(s); the null-carrying layout has 3", n.size,
		)
	}
	offsetsRef, err := n.childRef(0)
	if err != nil {
		return columnValues{}, err.Error()
	}
	blobRef, err := n.childRef(1)
	if err != nil {
		return columnValues{}, err.Error()
	}
	nullsRef, err := n.childRef(2)
	if err != nil {
		return columnValues{}, err.Error()
	}
	if offsetsRef == 0 || blobRef == 0 || nullsRef == 0 {
		return columnValues{}, "small-blob array has an empty offsets, blob or null ref"
	}
	offsetsNode, err := nodeAt(bytes, offsetsRef)
	if err != nil {
		return columnValues{}, err.Error()
	}
	blob, err := nodeAt(bytes, blobRef)
	if err != nil {
		return columnValues{}, err.Error()
	}
	nulls, err := nodeAt(bytes, nullsRef)
	if err != nil {
		return columnValues{}, err.Error()
	}
	for _, child := range []*node{&offsetsNode, &nulls} {
		if child.isInner() || child.hasRefs() {
			return columnValues{}, "small-blob offsets or null map is not a plain integer array"
		}
	}
	if reason := expectSize(&offsetsNode, count, "blob-offset"); reason != "" {
		return columnValues{}, reason
	}
	if reason := expectSize(&nulls, count, "blob-null"); reason != "" {
		return columnValues{}, reason
	}
	if blob.scheme != widthSchemeIgnore {
		return columnValues{}, fmt.Sprintf(
			"small-blob payload array uses width encoding %d, not the byte-array form", blob.scheme,
		)
	}
	offsets := make([]uint64, 0, count)
	values := make([]Value, 0, count)
	var previous uint64
	for index := 0; index < count; index++ {
		end, err := offsetsNode.valueU(index)
		if err != nil {
			return columnValues{}, err.Error()
		}
		if end < previous {
			return columnValues{}, fmt.Sprintf(
				"small-blob offset %d (%d) is below the previous end (%d)", index, end, previous,
			)
		}
		if end > uint64(len(blob.data)) {
			return columnValues{}, fmt.Sprintf(
				"small-blob offset %d (%d) is past the %d-byte payload", index, end, len(blob.data),
			)
		}
		begin := previous
		previous = end
		isNull, err := nulls.valueU(index)
		if err != nil {
			return columnValues{}, err.Error()
		}
		offsets = append(offsets, blob.dataOffset+begin)
		if isNull != 0 {
			values = append(values, Value{Kind: ValueNull})
			continue
		}
		start := int(begin)
		stop := int(end)
		if isString {
			if stop <= start {
				return columnValues{}, fmt.Sprintf(
					"string blob %d has no NUL terminator inside its %d byte(s)", index, stop-start,
				)
			}
			if blob.data[stop-1] != 0 {
				return columnValues{}, fmt.Sprintf(
					"string blob %d is not NUL-terminated at its last byte", index,
				)
			}
			if !utf8.Valid(blob.data[start : stop-1]) {
				return columnValues{}, fmt.Sprintf("string blob %d is not valid UTF-8", index)
			}
			values = append(values, Value{Kind: ValueString, String: string(blob.data[start : stop-1])})
		} else {
			payload := append([]byte(nil), blob.data[start:stop]...)
			values = append(values, Value{Kind: ValueBinary, Binary: payload})
		}
	}
	return columnValues{offsets: offsets, values: values}, ""
}

func decodeBasicFloat(n *node, count int, single bool) (columnValues, string) {
	expected := 8
	label := "Double"
	if single {
		expected = 4
		label = "Float"
	}
	if n.scheme != widthSchemeMultiply || int(n.width) != expected {
		return columnValues{}, fmt.Sprintf(
			"%s column is not a %d-byte element array", label, expected,
		)
	}
	if reason := expectSize(n, count, label); reason != "" {
		return columnValues{}, reason
	}
	offsets := make([]uint64, 0, count)
	values := make([]Value, 0, count)
	for index := 0; index < count; index++ {
		offsets = append(offsets, n.elementOffset(index))
		block, err := n.block(index)
		if err != nil {
			return columnValues{}, err.Error()
		}
		if single {
			bits := uint32(readLE(block))
			if bits == 0x7fc0_00aa {
				values = append(values, Value{Kind: ValueNull})
			} else {
				values = append(values, Value{Kind: ValueFloat, Float: math.Float32frombits(bits)})
			}
		} else {
			bits := readLE(block)
			if bits == 0x7ff8_0000_0000_00aa {
				values = append(values, Value{Kind: ValueNull})
			} else {
				values = append(values, Value{Kind: ValueDouble, Double: math.Float64frombits(bits)})
			}
		}
	}
	return columnValues{offsets: offsets, values: values}, ""
}

func decodeTimestamp(bytes []byte, n *node, count int) (columnValues, string) {
	if !n.hasRefs() || n.size != 2 {
		return columnValues{}, fmt.Sprintf(
			"Timestamp column is not the two-array (seconds, nanoseconds) form; it has %d slot(s)",
			n.size,
		)
	}
	secondsRef, err := n.childRef(0)
	if err != nil {
		return columnValues{}, err.Error()
	}
	nanosRef, err := n.childRef(1)
	if err != nil {
		return columnValues{}, err.Error()
	}
	if secondsRef == 0 || nanosRef == 0 {
		return columnValues{}, "Timestamp column has an empty seconds or nanoseconds array"
	}
	seconds, err := nodeAt(bytes, secondsRef)
	if err != nil {
		return columnValues{}, err.Error()
	}
	nanos, err := nodeAt(bytes, nanosRef)
	if err != nil {
		return columnValues{}, err.Error()
	}
	for _, child := range []*node{&seconds, &nanos} {
		if child.isInner() || child.hasRefs() {
			return columnValues{}, "Timestamp seconds or nanoseconds array is not a plain integer array"
		}
	}
	if seconds.size != count+1 {
		return columnValues{}, fmt.Sprintf(
			"Timestamp seconds array holds %d element(s) for %d row(s); it needs one null sentinel",
			seconds.size, count,
		)
	}
	if nanos.size != count {
		return columnValues{}, fmt.Sprintf(
			"Timestamp nanoseconds array holds %d element(s) for %d row(s)", nanos.size, count,
		)
	}
	sentinel, err := seconds.valueU(0)
	if err != nil {
		return columnValues{}, err.Error()
	}
	offsets := make([]uint64, 0, count)
	values := make([]Value, 0, count)
	for index := 0; index < count; index++ {
		raw, err := seconds.valueU(index + 1)
		if err != nil {
			return columnValues{}, err.Error()
		}
		offsets = append(offsets, seconds.elementOffset(index+1))
		if raw == sentinel {
			values = append(values, Value{Kind: ValueNull})
			continue
		}
		nanoseconds, err := nanos.valueI(index)
		if err != nil {
			return columnValues{}, err.Error()
		}
		values = append(values, Value{
			Kind: ValueTimestamp, TimestampSeconds: int64(raw), TimestampNanos: int32(nanoseconds),
		})
	}
	return columnValues{offsets: offsets, values: values}, ""
}

func decodeLink(n *node, column *Column, count int) (columnValues, string) {
	if reason := expectSize(n, count, "Link"); reason != "" {
		return columnValues{}, reason
	}
	offsets := make([]uint64, 0, count)
	values := make([]Value, 0, count)
	for index := 0; index < count; index++ {
		offsets = append(offsets, n.elementOffset(index))
		raw, err := n.valueI(index)
		if err != nil {
			return columnValues{}, err.Error()
		}
		if raw == 0 {
			values = append(values, Value{Kind: ValueNull})
		} else if raw == math.MinInt64 {
			return columnValues{}, "Link column contains a key that cannot be decremented"
		} else {
			values = append(values, Value{
				Kind: ValueLink, LinkKey: raw - 1,
				LinkTargetTable: column.LinkTarget, HasLinkTarget: column.HasLinkTarget,
			})
		}
	}
	return columnValues{offsets: offsets, values: values}, ""
}
