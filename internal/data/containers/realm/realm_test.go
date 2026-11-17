package realm

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---------------------------------------------------------------------------
// Hermetic Realm fixture builder.
//
// A Realm file is a 24-byte header followed by 8-byte-aligned nodes.  Every
// builder below writes real nodes, not opaque bytes: the node marker, flags,
// 24-bit element count and payload are all encoded from the same layout the
// reader parses.
// ---------------------------------------------------------------------------

type realmBuilder struct {
	buf []byte
}

func newRealmBuilder() *realmBuilder {
	return &realmBuilder{buf: make([]byte, HeaderBytes)}
}

func (b *realmBuilder) align8() {
	for len(b.buf)%8 != 0 {
		b.buf = append(b.buf, 0)
	}
}

func (b *realmBuilder) addNode(flags byte, size int, payload []byte) uint64 {
	b.align8()
	offset := uint64(len(b.buf))
	b.buf = append(b.buf,
		0x41, 0x41, 0x41, 0x41,
		flags,
		byte(size>>16), byte(size>>8), byte(size),
	)
	b.buf = append(b.buf, payload...)
	return offset
}

func widthCode(width int) byte {
	switch width {
	case 0:
		return 0
	case 1:
		return 1
	case 2:
		return 2
	case 4:
		return 3
	case 8:
		return 4
	case 16:
		return 5
	case 32:
		return 6
	case 64:
		return 7
	default:
		panic("unsupported fixture width")
	}
}

func nodeFlags(scheme, width int, hasRefs, inner, context bool) byte {
	flags := byte(scheme<<3) | widthCode(width)
	if hasRefs {
		flags |= 0x40
	}
	if inner {
		flags |= 0x80
	}
	if context {
		flags |= 0x20
	}
	return flags
}

func putLE64(buf []byte, at int, value uint64) {
	for index := 0; index < 8; index++ {
		buf[at+index] = byte(value >> (8 * index))
	}
}

func le64At(buf []byte, at int) uint64 {
	var value uint64
	for index := 0; index < 8; index++ {
		value |= uint64(buf[at+index]) << (8 * index)
	}
	return value
}

func (b *realmBuilder) addIntArray(values []uint64, width int) uint64 {
	payload := make([]byte, len(values)*width)
	for index, value := range values {
		for byteIndex := 0; byteIndex < width; byteIndex++ {
			payload[index*width+byteIndex] = byte(value >> (8 * byteIndex))
		}
	}
	return b.addNode(nodeFlags(1, width, false, false, false), len(values), payload)
}

func (b *realmBuilder) addBitsArray(values []uint64, bitWidth int) uint64 {
	payload := make([]byte, (len(values)*bitWidth+7)/8)
	for index, value := range values {
		bit := index * bitWidth
		for bitIndex := 0; bitIndex < bitWidth; bitIndex++ {
			if value>>bitIndex&1 != 0 {
				payload[(bit+bitIndex)/8] |= 1 << ((bit + bitIndex) % 8)
			}
		}
	}
	return b.addNode(nodeFlags(0, bitWidth, false, false, false), len(values), payload)
}

func (b *realmBuilder) addSignedIntArray(values []int64, byteWidth int) uint64 {
	raw := make([]uint64, len(values))
	for index, value := range values {
		raw[index] = uint64(value)
	}
	return b.addBitsArray(raw, byteWidth*8)
}

func (b *realmBuilder) addRefArray(refs []uint64) uint64 {
	return b.addRefArrayWithFlags(refs, false)
}

func (b *realmBuilder) addRefArrayWithFlags(refs []uint64, context bool) uint64 {
	payload := make([]byte, len(refs)*8)
	for index, ref := range refs {
		putLE64(payload, index*8, ref)
	}
	return b.addNode(nodeFlags(1, 8, true, false, context), len(refs), payload)
}

func (b *realmBuilder) addStringArray(width int, values []string) uint64 {
	payload := make([]byte, len(values)*width)
	for index, value := range values {
		if len(value) > width-1 {
			panic("fixture string does not fit")
		}
		block := payload[index*width : (index+1)*width]
		copy(block, value)
		block[len(value)] = 0
		block[width-1] = byte(width - 1 - len(value))
	}
	return b.addNode(nodeFlags(1, width, false, false, false), len(values), payload)
}

func (b *realmBuilder) addStringColumn(width int, values []string, nulls []bool) uint64 {
	payload := make([]byte, len(values)*width)
	for index, value := range values {
		block := payload[index*width : (index+1)*width]
		if nulls != nil && nulls[index] {
			block[width-1] = byte(width)
			continue
		}
		if len(value) > width-1 {
			panic("fixture string does not fit")
		}
		copy(block, value)
		block[len(value)] = 0
		block[width-1] = byte(width - 1 - len(value))
	}
	return b.addNode(nodeFlags(1, width, false, false, false), len(values), payload)
}

func (b *realmBuilder) addZeroWidthArray(size int) uint64 {
	return b.addNode(nodeFlags(1, 0, false, false, false), size, nil)
}

func (b *realmBuilder) addBlobArray(payload []byte) uint64 {
	return b.addNode(nodeFlags(2, 0, false, false, false), len(payload), payload)
}

func (b *realmBuilder) addSmallBlobs(payloads [][]byte, nulls []bool) uint64 {
	offsets := make([]uint64, len(payloads))
	nullValues := make([]uint64, len(payloads))
	var blob []byte
	for index, payload := range payloads {
		blob = append(blob, payload...)
		offsets[index] = uint64(len(blob))
		if nulls[index] {
			nullValues[index] = 1
		}
	}
	offsetsRef := b.addIntArray(offsets, 8)
	blobRef := b.addBlobArray(blob)
	nullsRef := b.addIntArray(nullValues, 1)
	return b.addRefArray([]uint64{offsetsRef, blobRef, nullsRef})
}

func (b *realmBuilder) addTimestampColumn(seconds []uint64, nanos []int64) uint64 {
	secondsRef := b.addIntArray(seconds, 8)
	nanosRef := b.addSignedIntArray(nanos, 8)
	return b.addRefArray([]uint64{secondsRef, nanosRef})
}

func (b *realmBuilder) addCompactLeaf(count int, columns map[int]uint64) uint64 {
	maxSlot := 0
	for leafIndex := range columns {
		if leafIndex+1 > maxSlot {
			maxSlot = leafIndex + 1
		}
	}
	slots := make([]uint64, maxSlot+1)
	slots[0] = uint64(count)<<1 | 1
	for leafIndex, ref := range columns {
		slots[leafIndex+1] = ref
	}
	return b.addRefArray(slots)
}

func (b *realmBuilder) addGeneralLeaf(keys []uint64, columns map[int]uint64) uint64 {
	keysRef := b.addIntArray(keys, 8)
	maxSlot := 0
	for leafIndex := range columns {
		if leafIndex+1 > maxSlot {
			maxSlot = leafIndex + 1
		}
	}
	slots := make([]uint64, maxSlot+1)
	slots[0] = keysRef
	for leafIndex, ref := range columns {
		slots[leafIndex+1] = ref
	}
	return b.addRefArray(slots)
}

func (b *realmBuilder) addInner(keysRef, subtreeDepth uint64, children []uint64) uint64 {
	slots := make([]uint64, 3+len(children))
	slots[0] = keysRef
	slots[1] = subtreeDepth<<1 | 1
	copy(slots[3:], children)
	payload := make([]byte, len(slots)*8)
	for index, ref := range slots {
		putLE64(payload, index*8, ref)
	}
	return b.addNode(nodeFlags(1, 8, true, true, false), len(slots), payload)
}

type colFixture struct {
	name      string
	code      uint8
	attr      uint8
	leafIndex int
	colKey    uint64
	hasColKey bool
}

func (b *realmBuilder) addTable(key uint32, columns []colFixture, cluster, oppositeRef, enumRef uint64) uint64 {
	typeValues := make([]uint64, len(columns))
	attrValues := make([]uint64, len(columns))
	keyValues := make([]uint64, len(columns))
	var names []string
	for index, column := range columns {
		typeValues[index] = uint64(column.code)
		attrValues[index] = uint64(column.attr)
		colKey := uint64(column.attr)<<22 | uint64(column.code)<<16 | uint64(column.leafIndex)
		if column.hasColKey {
			colKey = column.colKey
		}
		keyValues[index] = colKey
		if column.code != 14 {
			names = append(names, column.name)
		}
	}
	typesRef := b.addIntArray(typeValues, 8)
	namesRef := b.addStringArray(32, names)
	attrsRef := b.addIntArray(attrValues, 8)
	keysRef := b.addIntArray(keyValues, 8)
	specRef := b.addRefArray([]uint64{typesRef, namesRef, attrsRef, 0, enumRef, keysRef})
	topSlots := make([]uint64, 8)
	topSlots[0] = specRef
	topSlots[2] = cluster
	topSlots[3] = uint64(key)<<1 | 1
	topSlots[7] = oppositeRef
	return b.addRefArray(topSlots)
}

type groupSpec struct {
	formatVersion uint8
	topSlot       uint8
	headerFlags   uint8
	logical       *uint64
	freePos       uint64
	freeLen       uint64
	freeVer       uint64
	topSize       int
}

func (b *realmBuilder) finishGroup(names []string, tables []uint64, spec groupSpec) []byte {
	topSize := spec.topSize
	if topSize == 0 {
		topSize = 6
	}
	namesRef := b.addStringArray(32, names)
	tablesRef := b.addRefArray(tables)

	b.align8()
	start := uint64(len(b.buf))
	fileSize := start + uint64(8+topSize*8)
	logical := fileSize
	if spec.logical != nil {
		logical = *spec.logical
	}
	slots := make([]uint64, topSize)
	slots[0] = namesRef
	slots[1] = tablesRef
	slots[2] = logical<<1 | 1
	if topSize > 3 {
		slots[3] = spec.freePos
	}
	if topSize > 4 {
		slots[4] = spec.freeLen
	}
	if topSize > 5 {
		slots[5] = spec.freeVer
	}
	topRef := b.addRefArray(slots)

	version := spec.formatVersion
	if version == 0 {
		version = MaxFormatVersion
	}
	copy(b.buf[16:20], []byte(Magic))
	b.buf[20+int(spec.topSlot)] = version
	b.buf[23] = spec.topSlot | spec.headerFlags
	putLE64(b.buf, int(spec.topSlot)*8, topRef)
	return b.buf
}

func memorySource(data []byte) source.ByteSource {
	return source.NewMemorySourceWithImage(1, 9, data)
}

func openRealm(t *testing.T, data []byte) *Database {
	t.Helper()
	database, err := Open(1, memorySource(data))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return database
}

func mustTable(t *testing.T, database *Database, name string) *Table {
	t.Helper()
	table, ok := database.FindTable(name)
	if !ok {
		t.Fatalf("table %q not found", name)
	}
	return table
}

func mustColumn(t *testing.T, table *Table, name string) (int, *Column) {
	t.Helper()
	column, index, ok := table.FindColumn(name)
	if !ok {
		t.Fatalf("column %q not found in %q", name, table.Name)
	}
	return index, column
}

func mustCell(t *testing.T, table *Table, row, column int) Cell {
	t.Helper()
	cell, err := table.OpenCell(row, column)
	if err != nil {
		t.Fatalf("OpenCell(%d, %d) error = %v", row, column, err)
	}
	return cell
}

func basicFixture() []byte {
	b := newRealmBuilder()
	age := b.addSignedIntArray([]int64{30, 41}, 8)
	active := b.addIntArray([]uint64{0, 1}, 1)
	name := b.addStringArray(16, []string{"Alice", "Bob"})
	blob := b.addSmallBlobs([][]byte{{0x01, 0x02}, {0x03}}, []bool{false, false})
	timestamp := b.addTimestampColumn([]uint64{0, 1000, 1001}, []int64{500, 0})
	score := b.addIntArray([]uint64{uint64(math.Float32bits(1.5)), 0x7fc000aa}, 4)
	ratio := b.addIntArray([]uint64{math.Float64bits(2.5), 0x7ff80000000000aa}, 8)
	friend := b.addSignedIntArray([]int64{6, 0}, 8)
	maybeAge := b.addBitsArray([]uint64{99, 99, 7}, 64)
	maybeName := b.addStringColumn(8, []string{"x", ""}, []bool{false, true})

	columns := []colFixture{
		{name: "age", code: 0, leafIndex: 0},
		{name: "active", code: 1, leafIndex: 1},
		{name: "name", code: 2, leafIndex: 2},
		{name: "blob", code: 4, leafIndex: 3},
		{name: "ts", code: 8, leafIndex: 4},
		{name: "score", code: 9, leafIndex: 5},
		{name: "ratio", code: 10, leafIndex: 6},
		{name: "friend", code: 12, leafIndex: 7},
		{name: "maybeAge", code: 0, attr: 16, leafIndex: 8},
		{name: "maybeName", code: 2, attr: 16, leafIndex: 9},
	}
	leaf := b.addCompactLeaf(2, map[int]uint64{
		0: age, 1: active, 2: name, 3: blob, 4: timestamp,
		5: score, 6: ratio, 7: friend, 8: maybeAge, 9: maybeName,
	})
	oppositeValues := make([]uint64, 8)
	oppositeValues[7] = 2
	opposite := b.addIntArray(oppositeValues, 8)
	table := b.addTable(1, columns, leaf, opposite, 0)
	return b.finishGroup([]string{"Person"}, []uint64{table}, groupSpec{})
}

func TestRouteFileAndLooksLike(t *testing.T) {
	for _, path := range []string{"default.realm", `C:\profiles\default.REALM`, "a/b/x.realm"} {
		if !RouteFile(path) {
			t.Fatalf("RouteFile(%q) = false", path)
		}
	}
	for _, path := range []string{"realm", ".realm", "default.realm.bak", ""} {
		if RouteFile(path) {
			t.Fatalf("RouteFile(%q) = true", path)
		}
	}
	valid := basicFixture()
	if !LooksLike(valid) {
		t.Fatal("LooksLike(valid) = false")
	}
	if LooksLike(valid[:23]) || LooksLike([]byte("this is definitely not a realm database file")) {
		t.Fatal("LooksLike accepted a non-Realm header")
	}
}

func TestHeaderAndBasicMetadata(t *testing.T) {
	data := basicFixture()
	database := openRealm(t, data)
	if database.Header.TopSlot != 0 || database.Header.FormatVersion != MaxFormatVersion {
		t.Fatalf("header = %+v", database.Header)
	}
	if database.Header.TopRef == 0 || database.Header.FileSize != uint64(len(data)) {
		t.Fatalf("header = %+v", database.Header)
	}
	if database.Header.LogicalSize > database.Header.FileSize {
		t.Fatalf("logical size %d exceeds file size %d", database.Header.LogicalSize, database.Header.FileSize)
	}
	if database.Header.Flags != 0 {
		t.Fatalf("flags = %#x", database.Header.Flags)
	}
	if database.RowCount() != 2 || database.ColumnCount() != 10 {
		t.Fatalf("counts = %d rows, %d columns", database.RowCount(), database.ColumnCount())
	}
	if len(database.Refusals()) != 0 {
		t.Fatalf("refusals = %v", database.Refusals())
	}
	if database.SourceID() != 1 || database.ImageID() != 9 {
		t.Fatalf("source identity = %d/%d", database.SourceID(), database.ImageID())
	}
	if database.Parent() == nil || database.Parent().Len() != uint64(len(data)) {
		t.Fatal("database did not retain its parent source")
	}
	if database.Stats().BytesRead == 0 {
		t.Fatal("database stats recorded no read")
	}

	table := mustTable(t, database, "Person")
	if table.Key != 1 || table.TopRef == 0 || !table.HasNameOffset {
		t.Fatalf("table = %+v", table)
	}
	if len(table.Columns) != 10 || len(table.Rows) != 2 || len(table.Warnings) != 0 {
		t.Fatalf("table shape = %d columns, %d rows, warnings %v", len(table.Columns), len(table.Rows), table.Warnings)
	}
	if table.Rows[0].Key != 0 || table.Rows[0].Index != 0 || table.Rows[1].Key != 1 || table.Rows[1].Index != 1 {
		t.Fatalf("rows = %+v", table.Rows)
	}
	for _, column := range table.Columns {
		if !column.HasNameOffset || column.NameOffset == 0 {
			t.Fatalf("column %q has no name offset", column.Name)
		}
	}
	if !table.Columns[8].Nullable || !table.Columns[9].Nullable {
		t.Fatal("nullable attribute was not decoded")
	}
}

func TestTypedValues(t *testing.T) {
	database := openRealm(t, basicFixture())
	table := mustTable(t, database, "Person")

	ageIndex, _ := mustColumn(t, table, "age")
	if got := mustCell(t, table, 0, ageIndex).Value; got.Kind != ValueInt || got.Int != 30 {
		t.Fatalf("age[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, ageIndex).Value; got.Int != 41 {
		t.Fatalf("age[1] = %+v", got)
	}
	activeIndex, _ := mustColumn(t, table, "active")
	if got := mustCell(t, table, 0, activeIndex).Value; got.Kind != ValueBool || got.Bool {
		t.Fatalf("active[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, activeIndex).Value; !got.Bool {
		t.Fatalf("active[1] = %+v", got)
	}
	nameIndex, _ := mustColumn(t, table, "name")
	if got := mustCell(t, table, 0, nameIndex).Value; got.Kind != ValueString || got.String != "Alice" {
		t.Fatalf("name[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, nameIndex).Value; got.String != "Bob" {
		t.Fatalf("name[1] = %+v", got)
	}
	blobIndex, _ := mustColumn(t, table, "blob")
	if got := mustCell(t, table, 0, blobIndex).Value; got.Kind != ValueBinary || !bytes.Equal(got.Binary, []byte{1, 2}) {
		t.Fatalf("blob[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, blobIndex).Value; !bytes.Equal(got.Binary, []byte{3}) {
		t.Fatalf("blob[1] = %+v", got)
	}
	tsIndex, _ := mustColumn(t, table, "ts")
	if got := mustCell(t, table, 0, tsIndex).Value; got.Kind != ValueTimestamp ||
		got.TimestampSeconds != 1000 || got.TimestampNanos != 500 {
		t.Fatalf("ts[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, tsIndex).Value; got.TimestampSeconds != 1001 || got.TimestampNanos != 0 {
		t.Fatalf("ts[1] = %+v", got)
	}
	scoreIndex, _ := mustColumn(t, table, "score")
	if got := mustCell(t, table, 0, scoreIndex).Value; got.Kind != ValueFloat || got.Float != 1.5 {
		t.Fatalf("score[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, scoreIndex).Value; got.Kind != ValueNull {
		t.Fatalf("score[1] = %+v", got)
	}
	ratioIndex, _ := mustColumn(t, table, "ratio")
	if got := mustCell(t, table, 0, ratioIndex).Value; got.Kind != ValueDouble || got.Double != 2.5 {
		t.Fatalf("ratio[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, ratioIndex).Value; got.Kind != ValueNull {
		t.Fatalf("ratio[1] = %+v", got)
	}
	friendIndex, friendColumn := mustColumn(t, table, "friend")
	if got := mustCell(t, table, 0, friendIndex).Value; got.Kind != ValueLink ||
		!got.HasLinkTarget || got.LinkTargetTable != 2 || got.LinkKey != 5 {
		t.Fatalf("friend[0] = %+v (column %+v)", got, friendColumn)
	}
	if got := mustCell(t, table, 1, friendIndex).Value; got.Kind != ValueNull {
		t.Fatalf("friend[1] = %+v", got)
	}
	maybeAgeIndex, _ := mustColumn(t, table, "maybeAge")
	if got := mustCell(t, table, 0, maybeAgeIndex).Value; got.Kind != ValueNull {
		t.Fatalf("maybeAge[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, maybeAgeIndex).Value; got.Kind != ValueInt || got.Int != 7 {
		t.Fatalf("maybeAge[1] = %+v", got)
	}
	maybeNameIndex, _ := mustColumn(t, table, "maybeName")
	if got := mustCell(t, table, 0, maybeNameIndex).Value; got.Kind != ValueString || got.String != "x" {
		t.Fatalf("maybeName[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, maybeNameIndex).Value; got.Kind != ValueNull {
		t.Fatalf("maybeName[1] = %+v", got)
	}
}

func TestRecordOpeningAndRanges(t *testing.T) {
	database := openRealm(t, basicFixture())
	table := mustTable(t, database, "Person")

	row, err := table.OpenRow(1)
	if err != nil || row.Index != 1 || row.Key != 1 {
		t.Fatalf("OpenRow = %+v, %v", row, err)
	}
	if _, err := table.OpenRow(2); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("OpenRow(2) error = %v", err)
	}
	if _, err := table.OpenRow(-1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("OpenRow(-1) error = %v", err)
	}
	if row, ok := table.RowAt(0); !ok || row.Index != 0 {
		t.Fatalf("RowAt(0) = %+v, %v", row, ok)
	}
	if _, ok := table.RowAt(9); ok {
		t.Fatal("RowAt(9) reported a row")
	}
	if _, err := table.OpenCell(0, 99); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("OpenCell(column 99) error = %v", err)
	}
	if _, err := table.OpenCell(99, 0); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("OpenCell(row 99) error = %v", err)
	}
	if column, index, ok := table.FindColumn("name"); !ok || index != 2 || column.SpecIndex != 2 {
		t.Fatalf("FindColumn = %+v, %d, %v", column, index, ok)
	}
	if _, _, ok := table.FindColumn("missing"); ok {
		t.Fatal("FindColumn found a missing column")
	}
	if column, ok := table.ColumnAt(0); !ok || column.Name != "age" {
		t.Fatalf("ColumnAt = %+v, %v", column, ok)
	}
	if database.Tables[0].Rows[0].Cells[0].Offset == 0 {
		t.Fatal("cell offset was not recorded")
	}
}

func TestUnsupportedColumnsAreMetadataOnly(t *testing.T) {
	b := newRealmBuilder()
	intArray := b.addSignedIntArray([]int64{7}, 8)
	enumValues := make([]uint64, 6)
	enumValues[4] = 1
	enumRef := b.addRefArray(enumValues)
	columns := []colFixture{
		{name: "n", code: 0, leafIndex: 0},
		{name: "m", code: 6, leafIndex: 1},
		{name: "", code: 14, leafIndex: 2},
		{name: "tags", code: 0, attr: 32, leafIndex: 3},
		{name: "color", code: 2, leafIndex: 4},
		{name: "retired", code: 3, leafIndex: 5},
	}
	leaf := b.addCompactLeaf(1, map[int]uint64{0: intArray})
	tableRef := b.addTable(1, columns, leaf, 0, enumRef)
	data := b.finishGroup([]string{"Things"}, []uint64{tableRef}, groupSpec{})
	database := openRealm(t, data)
	table := mustTable(t, database, "Things")

	if len(table.Columns) != 6 {
		t.Fatalf("columns = %d", len(table.Columns))
	}
	for index := 1; index < 6; index++ {
		if table.Columns[index].Unsupported == "" {
			t.Fatalf("column %d (%s) was decoded", index, table.Columns[index].Name)
		}
	}
	if table.Columns[2].Name != "" || table.Columns[2].HasNameOffset {
		t.Fatalf("backlink column = %+v", table.Columns[2])
	}
	if !table.Columns[3].Collection {
		t.Fatal("collection attribute was not decoded")
	}
	if !table.Columns[4].StringEnum {
		t.Fatal("string-enum marker was not decoded")
	}
	if len(table.Rows) != 1 || len(table.Rows[0].Cells) != 1 {
		t.Fatalf("rows = %+v", table.Rows)
	}
	if got := mustCell(t, table, 0, 0).Value; got.Kind != ValueInt || got.Int != 7 {
		t.Fatalf("decoded cell = %+v", got)
	}
	if _, err := table.OpenCell(0, 4); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenCell(unsupported) error = %v", err)
	}
	if refusals := database.Refusals(); len(refusals) != 5 {
		t.Fatalf("refusals = %v", refusals)
	}
}

func TestStringForms(t *testing.T) {
	b := newRealmBuilder()
	zeroWidth := b.addZeroWidthArray(2)
	smallBlobStrings := b.addSmallBlobs([][]byte{[]byte("hi\x00"), []byte("bye\x00")}, []bool{false, false})
	short := b.addStringArray(8, []string{"a", ""})
	columns := []colFixture{
		{name: "zero", code: 2, leafIndex: 0},
		{name: "blobs", code: 2, leafIndex: 1},
		{name: "short", code: 2, leafIndex: 2},
	}
	leaf := b.addCompactLeaf(2, map[int]uint64{0: zeroWidth, 1: smallBlobStrings, 2: short})
	tableRef := b.addTable(1, columns, leaf, 0, 0)
	database := openRealm(t, b.finishGroup([]string{"Strings"}, []uint64{tableRef}, groupSpec{}))
	table := mustTable(t, database, "Strings")
	zeroIndex, _ := mustColumn(t, table, "zero")
	if got := mustCell(t, table, 0, zeroIndex).Value; got.Kind != ValueString || got.String != "" {
		t.Fatalf("zero-width[0] = %+v", got)
	}
	blobIndex, _ := mustColumn(t, table, "blobs")
	if got := mustCell(t, table, 0, blobIndex).Value; got.Kind != ValueString || got.String != "hi" {
		t.Fatalf("small-blob[0] = %+v", got)
	}
	if got := mustCell(t, table, 1, blobIndex).Value; got.String != "bye" {
		t.Fatalf("small-blob[1] = %+v", got)
	}
	shortIndex, _ := mustColumn(t, table, "short")
	if got := mustCell(t, table, 1, shortIndex).Value; got.Kind != ValueString || got.String != "" {
		t.Fatalf("short empty = %+v", got)
	}
}

func TestClusterInnerNodesAndBaseKeys(t *testing.T) {
	b := newRealmBuilder()
	column1 := b.addSignedIntArray([]int64{10, 20}, 8)
	column2 := b.addSignedIntArray([]int64{30}, 8)
	leaf1 := b.addGeneralLeaf([]uint64{1, 2}, map[int]uint64{0: column1})
	leaf2 := b.addGeneralLeaf([]uint64{1}, map[int]uint64{0: column2})
	innerKeys := b.addIntArray([]uint64{0, 10}, 8)
	inner := b.addInner(innerKeys, 0, []uint64{leaf1, leaf2})
	tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, inner, 0, 0)
	database := openRealm(t, b.finishGroup([]string{"Tree"}, []uint64{tableRef}, groupSpec{}))
	table := mustTable(t, database, "Tree")
	if len(table.Rows) != 3 {
		t.Fatalf("rows = %+v", table.Rows)
	}
	wantKeys := []uint64{1, 2, 11}
	wantValues := []int64{10, 20, 30}
	for index := range wantKeys {
		if table.Rows[index].Key != wantKeys[index] {
			t.Fatalf("row %d key = %d, want %d", index, table.Rows[index].Key, wantKeys[index])
		}
		if got := mustCell(t, table, index, 0).Value; got.Kind != ValueInt || got.Int != wantValues[index] {
			t.Fatalf("row %d value = %+v", index, got)
		}
	}
}

func TestCompactLeafBaseKey(t *testing.T) {
	b := newRealmBuilder()
	column1 := b.addSignedIntArray([]int64{1}, 8)
	compact := b.addCompactLeaf(1, map[int]uint64{0: column1})
	innerKeys := b.addIntArray([]uint64{0, 9}, 8)
	// A second child is needed for the key array to line up, but only the first
	// child is reachable in this fixture.
	unused := b.addCompactLeaf(0, nil)
	inner := b.addInner(innerKeys, 0, []uint64{compact, unused})
	tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, inner, 0, 0)
	database := openRealm(t, b.finishGroup([]string{"Compact"}, []uint64{tableRef}, groupSpec{}))
	table := mustTable(t, database, "Compact")
	if len(table.Rows) != 1 || table.Rows[0].Key != 0 {
		t.Fatalf("rows = %+v", table.Rows)
	}
}

func TestFreeLists(t *testing.T) {
	b := newRealmBuilder()
	positions := b.addIntArray([]uint64{100, 5000}, 8)
	lengths := b.addIntArray([]uint64{16, 8}, 8)
	versions := b.addIntArray([]uint64{3, 4}, 8)
	data := b.finishGroup(nil, nil, groupSpec{
		topSize: 6, freePos: positions, freeLen: lengths, freeVer: versions,
	})
	database := openRealm(t, data)
	if len(database.Free.Chunks) != 2 {
		t.Fatalf("free chunks = %+v", database.Free.Chunks)
	}
	if database.Free.Chunks[0].Offset != 100 || database.Free.Chunks[0].Length != 16 ||
		database.Free.Chunks[0].Version == nil || *database.Free.Chunks[0].Version != 3 {
		t.Fatalf("chunk 0 = %+v", database.Free.Chunks[0])
	}
	if len(database.Free.Warnings) == 0 || !strings.Contains(database.Free.Warnings[0], "free region 1") {
		t.Fatalf("warnings = %v", database.Free.Warnings)
	}
}

func TestPartialFreeListsWarn(t *testing.T) {
	b := newRealmBuilder()
	positions := b.addIntArray([]uint64{100}, 8)
	data := b.finishGroup(nil, nil, groupSpec{topSize: 4, freePos: positions})
	database := openRealm(t, data)
	if len(database.Free.Chunks) != 0 {
		t.Fatalf("chunks = %+v", database.Free.Chunks)
	}
	if len(database.Free.Warnings) != 1 || !strings.Contains(database.Free.Warnings[0], "only one") {
		t.Fatalf("warnings = %v", database.Free.Warnings)
	}
}

func TestDuplicateAndFreedTableSlots(t *testing.T) {
	b := newRealmBuilder()
	tableA := b.addTable(1, nil, 0, 0, 0)
	b2 := b
	refs := []uint64{tableA, tableA, 3, 0}
	data := b2.finishGroup([]string{"A", "A", "B", "C"}, refs, groupSpec{})
	database := openRealm(t, data)
	if len(database.Tables) != 2 {
		t.Fatalf("tables = %+v", database.Tables)
	}
	joined := strings.Join(database.Warnings, "\n")
	for _, needle := range []string{"more than once", "freed slot", "holds no table ref"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("warnings = %v, missing %q", database.Warnings, needle)
		}
	}
}

func TestTopSlotOneAndFormatVersion(t *testing.T) {
	b := newRealmBuilder()
	column := b.addSignedIntArray([]int64{5}, 8)
	leaf := b.addCompactLeaf(1, map[int]uint64{0: column})
	tableRef := b.addTable(7, []colFixture{{name: "n", code: 0, leafIndex: 0}}, leaf, 0, 0)
	data := b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{topSlot: 1, formatVersion: 20})
	database := openRealm(t, data)
	if database.Header.TopSlot != 1 || database.Header.FormatVersion != 20 {
		t.Fatalf("header = %+v", database.Header)
	}
	if database.Header.TopRef != le64At(data, 8) {
		t.Fatalf("top ref = %d, slot 1 = %d", database.Header.TopRef, le64At(data, 8))
	}
	if got := mustCell(t, mustTable(t, database, "T"), 0, 0).Value; got.Int != 5 {
		t.Fatalf("cell = %+v", got)
	}
}

func TestEmptyFormatVersionZero(t *testing.T) {
	data := make([]byte, 24)
	copy(data[16:20], []byte(Magic))
	data[20] = 0
	data[23] = 0
	database := openRealm(t, data)
	if database.Header.FormatVersion != 0 || database.Header.TopRef != 0 ||
		len(database.Tables) != 0 || database.RowCount() != 0 {
		t.Fatalf("database = %+v", database)
	}
}

func TestUnsupportedColumnStorage(t *testing.T) {
	t.Run("B+-tree column array", func(t *testing.T) {
		b := newRealmBuilder()
		array := b.addSignedIntArray([]int64{1}, 8)
		inner := b.addInner(0, 0, []uint64{array})
		leaf := b.addCompactLeaf(1, map[int]uint64{0: inner})
		tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, leaf, 0, 0)
		database := openRealm(t, b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{}))
		table := mustTable(t, database, "T")
		if !strings.Contains(table.Columns[0].Unsupported, "B+-tree") {
			t.Fatalf("unsupported = %q", table.Columns[0].Unsupported)
		}
		if len(table.Rows) != 1 || len(table.Rows[0].Cells) != 0 {
			t.Fatalf("rows = %+v", table.Rows)
		}
	})
	t.Run("big blob string", func(t *testing.T) {
		b := newRealmBuilder()
		ref := b.addRefArrayWithFlags([]uint64{1, 2, 3}, true)
		leaf := b.addCompactLeaf(1, map[int]uint64{0: ref})
		tableRef := b.addTable(1, []colFixture{{name: "s", code: 2, leafIndex: 0}}, leaf, 0, 0)
		database := openRealm(t, b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{}))
		table := mustTable(t, database, "T")
		if !strings.Contains(table.Columns[0].Unsupported, "big-blob") {
			t.Fatalf("unsupported = %q", table.Columns[0].Unsupported)
		}
	})
	t.Run("ref array for int", func(t *testing.T) {
		b := newRealmBuilder()
		ref := b.addRefArray([]uint64{1})
		leaf := b.addCompactLeaf(1, map[int]uint64{0: ref})
		tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, leaf, 0, 0)
		database := openRealm(t, b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{}))
		table := mustTable(t, database, "T")
		if !strings.Contains(table.Columns[0].Unsupported, "stored as a ref array") {
			t.Fatalf("unsupported = %q", table.Columns[0].Unsupported)
		}
	})
	t.Run("invalid short string UTF-8", func(t *testing.T) {
		b := newRealmBuilder()
		payload := make([]byte, 8)
		payload[0] = 0xff
		payload[1] = 0
		payload[7] = 6
		array := b.addNode(nodeFlags(1, 8, false, false, false), 1, payload)
		leaf := b.addCompactLeaf(1, map[int]uint64{0: array})
		tableRef := b.addTable(1, []colFixture{{name: "s", code: 2, leafIndex: 0}}, leaf, 0, 0)
		database := openRealm(t, b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{}))
		table := mustTable(t, database, "T")
		if !strings.Contains(table.Columns[0].Unsupported, "not valid UTF-8") {
			t.Fatalf("unsupported = %q", table.Columns[0].Unsupported)
		}
	})
}

func TestCycleIsRefused(t *testing.T) {
	b := newRealmBuilder()
	column := b.addSignedIntArray([]int64{1}, 8)
	leaf := b.addCompactLeaf(1, map[int]uint64{0: column})
	keys := b.addIntArray([]uint64{0}, 8)
	inner := b.addInner(keys, 0, []uint64{leaf})
	// Rewrite the inner node's first child ref to point at itself.
	putLE64(b.buf, int(inner)+8+3*8, inner)
	tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, inner, 0, 0)
	data := b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{})
	_, err := Open(1, memorySource(data))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("error = %q", err)
	}
}

func TestMalformedFiles(t *testing.T) {
	valid := basicFixture()
	topRef := le64At(valid, 0)

	cases := []struct {
		name   string
		data   []byte
		want   error
		needle string
		limits *Limits
	}{
		{name: "short header", data: make([]byte, 23), want: source.ErrCorrupt, needle: "header needs"},
		{name: "unaligned file", data: append(append([]byte(nil), valid...), 0), want: source.ErrCorrupt, needle: "multiple of 8"},
		{name: "missing magic", data: mutate(valid, 16, 0), want: source.ErrCorrupt, needle: "T-DB"},
		{name: "unknown flags", data: mutate(valid, 23, 0x80), want: source.ErrUnsupported, needle: "flag byte"},
		{name: "streaming form", data: streamingHeader(), want: source.ErrUnsupported, needle: "streaming form"},
		{name: "old version", data: mutate(valid, 20, 9), want: source.ErrUnsupported, needle: "format version 9"},
		{name: "version zero with top", data: mutate(valid, 20, 0), want: source.ErrCorrupt, needle: "version 0"},
		{name: "no top ref", data: setLE64(valid, 0, 0), want: source.ErrCorrupt, needle: "names no top array"},
		{name: "unaligned top", data: setLE64(valid, 0, topRef+1), want: source.ErrCorrupt, needle: "8-byte aligned"},
		{name: "bad marker", data: mutate(valid, int(topRef), 0), want: source.ErrCorrupt, needle: "marker"},
		{name: "node past file", data: setSize24(valid, int(topRef), 1<<20), want: source.ErrCorrupt, needle: "payload"},
		{name: "reserved scheme", data: mutate(valid, int(topRef)+4, 0x5c), want: source.ErrUnsupported, needle: "width encoding 3"},
		{name: "logical past file", data: setLogical(valid, topRef, uint64(len(valid))+1), want: source.ErrCorrupt, needle: "truncated"},
		{name: "file limit", data: valid, want: source.ErrUnsupported, needle: "limit", limits: &Limits{
			MaxFileBytes: uint64(len(valid) - 1), MaxTables: MaxTables, MaxColumns: MaxColumns,
			MaxRows: MaxRows, MaxTreeDepth: MaxTreeDepth,
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.limits == nil {
				_, err = Open(1, memorySource(test.data))
			} else {
				_, err = OpenWithLimits(1, memorySource(test.data), *test.limits)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("Open error = %v, want %v", err, test.want)
			}
			if !strings.Contains(err.Error(), test.needle) {
				t.Fatalf("error = %q, missing %q", err, test.needle)
			}
		})
	}
}

func mutate(data []byte, at int, value byte) []byte {
	out := append([]byte(nil), data...)
	out[at] = value
	return out
}

func setLE64(data []byte, at int, value uint64) []byte {
	out := append([]byte(nil), data...)
	putLE64(out, at, value)
	return out
}

func setSize24(data []byte, at int, size int) []byte {
	out := append([]byte(nil), data...)
	out[at+5] = byte(size >> 16)
	out[at+6] = byte(size >> 8)
	out[at+7] = byte(size)
	return out
}

func setLogical(data []byte, topRef, logical uint64) []byte {
	out := append([]byte(nil), data...)
	putLE64(out, int(topRef)+8+2*8, logical<<1|1)
	return out
}

func streamingHeader() []byte {
	data := make([]byte, 24)
	copy(data[16:20], []byte(Magic))
	data[20] = 24
	putLE64(data, 0, ^uint64(0))
	return data
}

func TestLimits(t *testing.T) {
	buildTwoTables := func() []byte {
		b := newRealmBuilder()
		one := b.addTable(1, nil, 0, 0, 0)
		two := b.addTable(2, nil, 0, 0, 0)
		return b.finishGroup([]string{"A", "B"}, []uint64{one, two}, groupSpec{})
	}
	data := buildTwoTables()
	base := DefaultLimits()
	tables := base
	tables.MaxTables = 1
	if _, err := OpenWithLimits(1, memorySource(data), tables); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("table limit error = %v", err)
	}

	b := newRealmBuilder()
	column := b.addSignedIntArray([]int64{1}, 8)
	leaf := b.addCompactLeaf(1, map[int]uint64{0: column})
	tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, leaf, 0, 0)
	oneTable := b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{})
	columns := base
	columns.MaxColumns = 0
	if _, err := OpenWithLimits(1, memorySource(oneTable), columns); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("column limit error = %v", err)
	}
	rows := base
	rows.MaxRows = 0
	if _, err := OpenWithLimits(1, memorySource(oneTable), rows); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("row limit error = %v", err)
	}
}

func TestTreeDepthLimit(t *testing.T) {
	b := newRealmBuilder()
	column := b.addSignedIntArray([]int64{1}, 8)
	leaf := b.addCompactLeaf(1, map[int]uint64{0: column})
	inner := b.addInner(0, 0, []uint64{leaf})
	tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, inner, 0, 0)
	data := b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{})
	limits := DefaultLimits()
	limits.MaxTreeDepth = 0
	if _, err := OpenWithLimits(1, memorySource(data), limits); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenWithLimits error = %v", err)
	}
}

func TestHeadFlagsAndEmptyNames(t *testing.T) {
	// A group with zero tables is valid: both name and ref arrays are empty.
	data := func() []byte {
		b := newRealmBuilder()
		return b.finishGroup(nil, nil, groupSpec{})
	}()
	database := openRealm(t, data)
	if len(database.Tables) != 0 || database.RowCount() != 0 {
		t.Fatalf("database = %+v", database)
	}
}

func TestIntElementWidthsAndSignExtension(t *testing.T) {
	cases := []struct {
		name  string
		width int
		raw   []uint64
		want  []int64
	}{
		{"1-bit", 1, []uint64{1, 0}, []int64{-1, 0}},
		{"2-bit", 2, []uint64{2, 1}, []int64{-2, 1}},
		{"4-bit", 4, []uint64{8, 7}, []int64{-8, 7}},
		{"8-bit", 8, []uint64{128, 127}, []int64{-128, 127}},
		{"16-bit", 16, []uint64{0x8000, 0x7fff}, []int64{-32768, 32767}},
		{"32-bit", 32, []uint64{0x80000000, 0x7fffffff}, []int64{-2147483648, 2147483647}},
		{"64-bit", 64, []uint64{^uint64(4), 42}, []int64{-5, 42}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			b := newRealmBuilder()
			array := b.addBitsArray(test.raw, test.width)
			leaf := b.addCompactLeaf(len(test.raw), map[int]uint64{0: array})
			tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, leaf, 0, 0)
			database := openRealm(t, b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{}))
			table := mustTable(t, database, "T")
			if table.RowCount() != len(test.want) {
				t.Fatalf("rows = %d", table.RowCount())
			}
			for index, want := range test.want {
				if got := mustCell(t, table, index, 0).Value; got.Kind != ValueInt || got.Int != want {
					t.Fatalf("value[%d] = %+v, want %d", index, got, want)
				}
			}
		})
	}
}

func TestColumnTypeMetadataAndAccessors(t *testing.T) {
	b := newRealmBuilder()
	columns := []colFixture{
		{name: "mixed", code: 6, leafIndex: 0},
		{name: "decimal", code: 11, leafIndex: 1},
		{name: "objectid", code: 15, leafIndex: 2},
		{name: "typed", code: 16, leafIndex: 3},
		{name: "uuid", code: 17, leafIndex: 4},
		{name: "retired", code: 3, leafIndex: 5},
		{name: "list", code: 0, attr: 64, leafIndex: 6},
	}
	tableRef := b.addTable(9, columns, 0, 0, 0)
	database := openRealm(t, b.finishGroup([]string{"Types"}, []uint64{tableRef}, groupSpec{}))
	table, ok := database.TableAt(0)
	if !ok || table.Name != "Types" || table.RowCount() != 0 {
		t.Fatalf("TableAt = %+v, %v", table, ok)
	}
	if _, ok := database.TableAt(1); ok {
		t.Fatal("TableAt(1) succeeded")
	}
	checks := []struct {
		index  int
		label  string
		known  bool
		needle string
	}{
		{0, "Mixed", true, "runtime type tag"},
		{1, "Decimal", true, "128-bit mantissa"},
		{2, "ObjectId", true, "12-byte"},
		{3, "TypedLink", true, "(table, row)"},
		{4, "UUID", true, "16-byte"},
		{5, "Unknown", false, "retired type"},
		{6, "Int", true, "collection column"},
	}
	for _, check := range checks {
		column := &table.Columns[check.index]
		if column.Type.Label() != check.label || column.Type.Known() != check.known {
			t.Fatalf("column %d type = %s (%v)", check.index, column.Type.Label(), column.Type.Known())
		}
		if !strings.Contains(column.Unsupported, check.needle) {
			t.Fatalf("column %d unsupported = %q", check.index, column.Unsupported)
		}
	}
	if ColumnTypeFromCode(3).Code() != 3 || ColumnTypeFromCode(3).Label() != "Unknown" {
		t.Fatal("unknown column type code was not preserved")
	}
	for _, test := range []struct {
		kind ValueKind
		want string
	}{
		{ValueNull, "Null"}, {ValueInt, "Int"}, {ValueBool, "Bool"},
		{ValueString, "String"}, {ValueFloat, "Float"}, {ValueDouble, "Double"},
		{ValueTimestamp, "Timestamp"}, {ValueBinary, "Binary"}, {ValueLink, "Link"},
		{ValueKind(99), "Unknown"},
	} {
		if test.kind.String() != test.want {
			t.Fatalf("ValueKind(%d) = %q, want %q", test.kind, test.kind.String(), test.want)
		}
	}
	if len(database.Refusals()) != len(columns) {
		t.Fatalf("refusals = %v", database.Refusals())
	}
}

func TestMalformedColumnStorages(t *testing.T) {
	buildAndCheck := func(t *testing.T, b *realmBuilder, column colFixture, array uint64, count int, needle string) {
		t.Helper()
		leaf := b.addCompactLeaf(count, map[int]uint64{0: array})
		tableRef := b.addTable(1, []colFixture{column}, leaf, 0, 0)
		database := openRealm(t, b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{}))
		table := mustTable(t, database, "T")
		if !strings.Contains(table.Columns[0].Unsupported, needle) {
			t.Fatalf("unsupported = %q, want %q", table.Columns[0].Unsupported, needle)
		}
		if len(table.Rows) != count || len(table.Rows[0].Cells) != 0 {
			t.Fatalf("rows = %+v", table.Rows)
		}
	}

	t.Run("string not fixed width", func(t *testing.T) {
		b := newRealmBuilder()
		buildAndCheck(t, b, colFixture{name: "s", code: 2, leafIndex: 0}, b.addBlobArray([]byte{1}), 1, "fixed-width")
	})
	t.Run("binary not small blobs", func(t *testing.T) {
		b := newRealmBuilder()
		buildAndCheck(t, b, colFixture{name: "b", code: 4, leafIndex: 0}, b.addIntArray([]uint64{1}, 8), 1, "not a small-blob")
	})
	t.Run("binary big blob", func(t *testing.T) {
		b := newRealmBuilder()
		ref := b.addRefArrayWithFlags([]uint64{1, 2, 3}, true)
		buildAndCheck(t, b, colFixture{name: "b", code: 4, leafIndex: 0}, ref, 1, "big-blob")
	})
	t.Run("blob offset past payload", func(t *testing.T) {
		b := newRealmBuilder()
		offsets := b.addIntArray([]uint64{5}, 8)
		blob := b.addBlobArray([]byte{1})
		nulls := b.addIntArray([]uint64{0}, 1)
		ref := b.addRefArray([]uint64{offsets, blob, nulls})
		buildAndCheck(t, b, colFixture{name: "b", code: 4, leafIndex: 0}, ref, 1, "past the 1-byte payload")
	})
	t.Run("blob offsets not monotonic", func(t *testing.T) {
		b := newRealmBuilder()
		offsets := b.addIntArray([]uint64{2, 1}, 8)
		blob := b.addBlobArray([]byte{1, 2})
		nulls := b.addIntArray([]uint64{0, 0}, 1)
		ref := b.addRefArray([]uint64{offsets, blob, nulls})
		buildAndCheck(t, b, colFixture{name: "b", code: 4, leafIndex: 0}, ref, 2, "below the previous end")
	})
	t.Run("string blob without NUL", func(t *testing.T) {
		b := newRealmBuilder()
		ref := b.addSmallBlobs([][]byte{{'a'}}, []bool{false})
		buildAndCheck(t, b, colFixture{name: "s", code: 2, leafIndex: 0}, ref, 1, "not NUL-terminated")
	})
	t.Run("timestamp shape", func(t *testing.T) {
		b := newRealmBuilder()
		ref := b.addRefArray([]uint64{1})
		buildAndCheck(t, b, colFixture{name: "ts", code: 8, leafIndex: 0}, ref, 1, "two-array")
	})
}

func TestClusterTreeErrors(t *testing.T) {
	t.Run("cluster not ref array", func(t *testing.T) {
		b := newRealmBuilder()
		array := b.addSignedIntArray([]int64{1}, 8)
		tableRef := b.addTable(1, []colFixture{{name: "n", code: 0, leafIndex: 0}}, array, 0, 0)
		data := b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{})
		if _, err := Open(1, memorySource(data)); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("inner key count mismatch", func(t *testing.T) {
		b := newRealmBuilder()
		leaf := b.addCompactLeaf(1, nil)
		keys := b.addIntArray([]uint64{0}, 8)
		inner := b.addInner(keys, 0, []uint64{leaf, leaf})
		tableRef := b.addTable(1, nil, inner, 0, 0)
		data := b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{})
		if _, err := Open(1, memorySource(data)); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("empty child ref", func(t *testing.T) {
		b := newRealmBuilder()
		inner := b.addInner(0, 0, []uint64{0})
		tableRef := b.addTable(1, nil, inner, 0, 0)
		data := b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{})
		if _, err := Open(1, memorySource(data)); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("inner key array is refs", func(t *testing.T) {
		b := newRealmBuilder()
		leaf := b.addCompactLeaf(1, nil)
		keys := b.addRefArray([]uint64{1})
		inner := b.addInner(keys, 0, []uint64{leaf})
		tableRef := b.addTable(1, nil, inner, 0, 0)
		data := b.finishGroup([]string{"T"}, []uint64{tableRef}, groupSpec{})
		if _, err := Open(1, memorySource(data)); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})
}

func TestFreeListMalformedArraysWarn(t *testing.T) {
	t.Run("version count mismatch", func(t *testing.T) {
		b := newRealmBuilder()
		positions := b.addIntArray([]uint64{100}, 8)
		lengths := b.addIntArray([]uint64{8}, 8)
		versions := b.addIntArray([]uint64{1, 2}, 8)
		database := openRealm(t, b.finishGroup(nil, nil, groupSpec{
			topSize: 6, freePos: positions, freeLen: lengths, freeVer: versions,
		}))
		if len(database.Free.Warnings) == 0 || !strings.Contains(database.Free.Warnings[0], "version(s)") {
			t.Fatalf("warnings = %v", database.Free.Warnings)
		}
	})
	t.Run("malformed position array", func(t *testing.T) {
		b := newRealmBuilder()
		positions := b.addRefArray([]uint64{1})
		lengths := b.addIntArray([]uint64{8}, 8)
		database := openRealm(t, b.finishGroup(nil, nil, groupSpec{
			topSize: 6, freePos: positions, freeLen: lengths,
		}))
		if len(database.Free.Warnings) == 0 || !strings.Contains(database.Free.Warnings[0], "free-position") {
			t.Fatalf("warnings = %v", database.Free.Warnings)
		}
	})
	t.Run("malformed version array", func(t *testing.T) {
		b := newRealmBuilder()
		positions := b.addIntArray([]uint64{100}, 8)
		lengths := b.addIntArray([]uint64{8}, 8)
		versions := b.addRefArray([]uint64{1})
		database := openRealm(t, b.finishGroup(nil, nil, groupSpec{
			topSize: 6, freePos: positions, freeLen: lengths, freeVer: versions,
		}))
		if len(database.Free.Warnings) == 0 || !strings.Contains(database.Free.Warnings[0], "free-version") {
			t.Fatalf("warnings = %v", database.Free.Warnings)
		}
		if len(database.Free.Chunks) != 1 || database.Free.Chunks[0].Version != nil {
			t.Fatalf("chunks = %+v", database.Free.Chunks)
		}
	})
}
