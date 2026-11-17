package pst

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"unicode/utf16"
)

// This file builds PST fixtures byte by byte.  Nothing here is read from a
// real store or produced by an external tool: the header, BTPAGEs, block
// trailers, heaps, BTH records and table contexts are all written by hand so
// the tests can mutate one field at a time.

type fixtureBuilder struct {
	format StoreFormat
	crypt  CryptMethod

	buf        []byte
	nbtOffset  int
	bbtOffset  int
	blocksEnd  int
	externalID uint64
	internalID uint64
	compress   bool

	blocks []blockRef
	nbt    []Node
	// Descriptors left in unused leaf slots past the live count.
	bbtFree []blockRef
	nbtFree []Node

	// Optional leaf-page offsets for branch-page fixtures.
	bbtLeafOffsets []int
	nbtLeafOffsets []int
}

func newFixture(format StoreFormat, crypt CryptMethod) *fixtureBuilder {
	f := &fixtureBuilder{
		format:     format,
		crypt:      crypt,
		externalID: 0x100,
		internalID: 0x2002,
	}
	if format == FormatUnicode4K {
		f.nbtOffset = 8192
		f.bbtOffset = 12288
		f.blocksEnd = 16384
	} else {
		f.nbtOffset = 1024
		f.bbtOffset = 1536
		f.blocksEnd = 2048
	}
	f.buf = make([]byte, f.blocksEnd)
	return f
}

func (f *fixtureBuilder) ensure(size int) {
	if size <= len(f.buf) {
		return
	}
	grown := make([]byte, size)
	copy(grown, f.buf)
	f.buf = grown
}

func (f *fixtureBuilder) nextExternalBID() uint64 {
	// Bit 0 is reserved and bit 1 is the internal-block flag, so external
	// BIDs advance by four.
	bid := f.externalID
	f.externalID += 4
	return bid
}

func (f *fixtureBuilder) nextInternalBID() uint64 {
	bid := f.internalID
	f.internalID += 4
	return bid
}

// addBlock appends one external leaf block and returns its BBT descriptor.
func (f *fixtureBuilder) addBlock(plain []byte, encoded bool) blockRef {
	compressed := f.compress && f.format == FormatUnicode4K
	return f.addRawBlock(f.nextExternalBID(), plain, encoded, compressed)
}

// addRawBlock appends one block with an explicit BID.
func (f *fixtureBuilder) addRawBlock(bid uint64, plain []byte, encoded, compressed bool) blockRef {
	reference := f.writeBlockBytes(bid, plain, encoded, compressed)
	f.blocks = append(f.blocks, reference)
	return reference
}

// addOrphanBlock writes a block whose bytes are in the file but whose
// descriptor is not in the live BBT.
func (f *fixtureBuilder) addOrphanBlock(plain []byte, encoded bool) blockRef {
	return f.writeBlockBytes(f.nextExternalBID(), plain, encoded, false)
}

func (f *fixtureBuilder) writeBlockBytes(bid uint64, plain []byte, encoded, compressed bool) blockRef {
	stored := append([]byte(nil), plain...)
	original := 0
	if compressed {
		var stream bytes.Buffer
		writer := zlib.NewWriter(&stream)
		if _, err := writer.Write(plain); err == nil {
			if err := writer.Close(); err == nil && stream.Len() < len(plain) {
				stored = append([]byte(nil), stream.Bytes()...)
				original = len(plain)
			}
		}
	}
	if encoded {
		switch f.crypt {
		case CryptPermute:
			permute(stored, true)
		case CryptCyclic:
			cyclic(stored, bid)
		}
	}
	geometry := blockGeometryForFormat(f.format)
	cb := len(stored)
	alloc, err := geometry.allocation(cb)
	if err != nil {
		panic(err)
	}
	ib := f.blocksEnd
	f.ensure(ib + alloc)
	copy(f.buf[ib:], stored)
	trailer := f.buf[ib+alloc-geometry.footer:]
	putU16(trailer, 0, uint16(cb))
	putU16(trailer, 2, blockSignature(uint64(ib), bid))
	if f.format.IsAnsi() {
		putU32(trailer, 4, uint32(bid))
		putU32(trailer, 8, crc32PST(f.buf[ib:ib+cb]))
	} else {
		putU32(trailer, 4, crc32PST(f.buf[ib:ib+cb]))
		putU64(trailer, 8, bid)
	}
	reference := blockRef{bid: bid, ib: uint64(ib), cb: uint16(cb), original: uint16(original)}
	f.blocksEnd = ib + alloc
	return reference
}

// addArray appends an XBLOCK/XXBLOCK and returns its descriptor.
func (f *fixtureBuilder) addArray(level uint8, children []uint64, total uint64) blockRef {
	bidBytes := 8
	if f.format.IsAnsi() {
		bidBytes = 4
	}
	data := make([]byte, 8+len(children)*bidBytes)
	data[0] = arrayType
	data[1] = level
	putU16(data, 2, uint16(len(children)))
	putU32(data, 4, uint32(total))
	for index, child := range children {
		at := 8 + index*bidBytes
		if bidBytes == 4 {
			putU32(data, at, uint32(child))
		} else {
			putU64(data, at, child)
		}
	}
	return f.addRawBlock(f.nextInternalBID(), data, false, false)
}

// writeBTPage writes one validated BTPAGE whose count is its entry count.
func (f *fixtureBuilder) writeBTPage(ib int, bid uint64, ptype byte, level byte, entries [][]byte, maximum int) {
	f.writeBTPageCount(ib, bid, ptype, level, entries, len(entries), maximum)
}

// writeBTPageCount writes a page whose slots past count may still hold bytes.
func (f *fixtureBuilder) writeBTPageCount(ib int, bid uint64, ptype byte, level byte, entries [][]byte, count, maximum int) {
	layout := pageLayoutForFormat(f.format)
	page := make([]byte, layout.pageBytes)
	entrySize := 0
	if len(entries) > 0 {
		entrySize = len(entries[0])
	}
	for index, entry := range entries {
		copy(page[index*entrySize:], entry)
	}
	if maximum < len(entries) {
		maximum = len(entries)
	}
	if count > maximum {
		count = maximum
	}
	if layout.countSize == 2 {
		putU16(page, layout.count, uint16(count))
		putU16(page, layout.maximum, uint16(maximum))
	} else {
		page[layout.count] = byte(count)
		page[layout.maximum] = byte(maximum)
	}
	page[layout.entrySize] = byte(entrySize)
	page[layout.level] = level
	page[layout.ptype] = ptype
	page[layout.ptype+1] = ptype
	if f.format.IsAnsi() {
		putU16(page, layout.ptype+2, blockSignature(uint64(ib), bid))
	}
	putU32(page, layout.crc, crc32PST(page[:layout.crcCover]))
	if layout.bidBytes == 4 {
		putU32(page, layout.bid, uint32(bid))
	} else {
		putU64(page, layout.bid, bid)
	}
	f.ensure(ib + layout.pageBytes)
	copy(f.buf[ib:], page)
}

func (f *fixtureBuilder) writeAllocationMaps() {
	if f.format == FormatUnicode4K {
		return
	}
	const firstAMap = 0x4400
	const firstPMap = 0x4600
	if f.blocksEnd > firstAMap {
		// The fixture's blocks occupy the fixed map location; leave the maps
		// out rather than overwriting data.
		return
	}
	f.ensure(firstPMap + pageBytes512)
	f.writeAllocationPage(firstAMap, AllocationAMap)
	f.writeAllocationPage(firstPMap, AllocationPMap)
}

func (f *fixtureBuilder) writeAllocationPage(offset int, ptype uint8) {
	layout := pageLayoutForFormat(f.format)
	page := make([]byte, layout.pageBytes)
	// The first eight bits mark the first 512 bytes (the map page itself) as
	// allocated, the shape a real store writes.
	page[0] = 0xFF
	page[layout.ptype] = ptype
	page[layout.ptype+1] = ptype
	if f.format.IsAnsi() {
		putU16(page, layout.ptype+2, blockSignature(uint64(offset), uint64(offset)))
		putU32(page, layout.bid, uint32(offset))
		putU32(page, layout.crc, crc32PST(page[:layout.crcCover]))
	} else {
		putU32(page, layout.crc, crc32PST(page[:layout.crcCover]))
		putU64(page, layout.bid, uint64(offset))
	}
	copy(f.buf[offset:], page)
}

func (f *fixtureBuilder) writeHeader() {
	if f.format.IsAnsi() {
		header := make([]byte, ansiHeaderBytes)
		copy(header[0:4], Signature[:])
		copy(header[8:10], []byte(MagicPST))
		putU16(header, 10, 14)
		putU16(header, 12, 14)
		putU32(header, 24, uint32(f.externalID))
		putU32(header, 32, 0x1234)
		putU32(header, 168, uint32(len(f.buf)))
		putU32(header, 184, 0x40)
		putU32(header, 188, uint32(f.nbtOffset))
		putU32(header, 192, 0x80)
		putU32(header, 196, uint32(f.bbtOffset))
		header[460] = 0x80
		header[461] = byte(f.crypt)
		putU32(header, 4, crc32PST(header[8:8+471]))
		copy(f.buf[:len(header)], header)
		return
	}
	header := make([]byte, headerBytes)
	copy(header[0:4], Signature[:])
	copy(header[8:10], []byte(MagicPST))
	version := uint16(23)
	if f.format == FormatUnicode4K {
		version = 36
	}
	putU16(header, 10, version)
	putU16(header, 12, version)
	putU32(header, 40, 0x1234)
	putU64(header, 184, uint64(len(f.buf)))
	putU64(header, 216, 0x40)
	putU64(header, 224, uint64(f.nbtOffset))
	putU64(header, 232, 0x80)
	putU64(header, 240, uint64(f.bbtOffset))
	header[512] = 0x80
	header[513] = byte(f.crypt)
	putU64(header, 516, f.externalID)
	putU32(header, 4, crc32PST(header[8:8+471]))
	putU32(header, 524, crc32PST(header[8:8+516]))
	copy(f.buf[:len(header)], header)
}

func (f *fixtureBuilder) build() []byte {
	f.writeAllocationMaps()
	// Block B-tree leaf.
	bbtEntries := make([][]byte, 0, len(f.blocks))
	sorted := append([]blockRef(nil), f.blocks...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].bid < sorted[i].bid {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for _, block := range sorted {
		bbtEntries = append(bbtEntries, f.bbtEntry(block))
	}
	if len(f.bbtLeafOffsets) == 0 {
		all := append([][]byte(nil), bbtEntries...)
		for _, block := range f.bbtFree {
			all = append(all, f.bbtEntry(block))
		}
		f.writeBTPageCount(f.bbtOffset, 0x80, bbtPageType, 0, all, len(bbtEntries), len(all))
	} else {
		f.writeBranchTree(f.bbtOffset, 0x80, bbtPageType, bbtEntries, f.bbtLeafOffsets, 0x180)
	}

	// Node B-tree leaf.
	nodes := append([]Node(nil), f.nbt...)
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if nodes[j].NID < nodes[i].NID {
				nodes[i], nodes[j] = nodes[j], nodes[i]
			}
		}
	}
	nbtEntries := make([][]byte, 0, len(nodes))
	for _, node := range nodes {
		nbtEntries = append(nbtEntries, f.nbtEntry(node))
	}
	if len(f.nbtLeafOffsets) == 0 {
		all := append([][]byte(nil), nbtEntries...)
		for _, node := range f.nbtFree {
			all = append(all, f.nbtEntry(node))
		}
		f.writeBTPageCount(f.nbtOffset, 0x40, nbtPageType, 0, all, len(nbtEntries), len(all))
	} else {
		f.writeBranchTree(f.nbtOffset, 0x40, nbtPageType, nbtEntries, f.nbtLeafOffsets, 0x1C0)
	}
	f.writeHeader()
	return append([]byte(nil), f.buf...)
}

// writeBranchTree splits entries across leaf pages and writes a branch root.
func (f *fixtureBuilder) writeBranchTree(rootOffset int, rootBID uint64, ptype byte, entries [][]byte, leafOffsets []int, firstLeafBID uint64) {
	parts := len(leafOffsets)
	if parts == 0 {
		parts = 1
	}
	branchEntries := make([][]byte, 0, parts)
	for part := 0; part < parts; part++ {
		start := part * len(entries) / parts
		end := (part + 1) * len(entries) / parts
		leafBID := firstLeafBID + uint64(part)*4
		f.writeBTPage(leafOffsets[part], leafBID, ptype, 0, entries[start:end], end-start)
		branchEntries = append(branchEntries, f.branchEntry(leafBID, leafOffsets[part]))
	}
	f.writeBTPage(rootOffset, rootBID, ptype, 1, branchEntries, len(branchEntries))
}

func (f *fixtureBuilder) branchEntry(childBID uint64, childIB int) []byte {
	if f.format.IsAnsi() {
		entry := make([]byte, 12)
		putU32(entry, 4, uint32(childBID))
		putU32(entry, 8, uint32(childIB))
		return entry
	}
	entry := make([]byte, 24)
	putU64(entry, 8, childBID)
	putU64(entry, 16, uint64(childIB))
	return entry
}

func (f *fixtureBuilder) nbtEntry(node Node) []byte {
	if f.format.IsAnsi() {
		entry := make([]byte, 16)
		putU32(entry, 0, uint32(node.NID))
		putU32(entry, 4, uint32(node.Data))
		putU32(entry, 8, uint32(node.Subnode))
		putU32(entry, 12, node.Parent)
		return entry
	}
	entry := make([]byte, 32)
	putU64(entry, 0, node.NID)
	putU64(entry, 8, node.Data)
	putU64(entry, 16, node.Subnode)
	putU32(entry, 24, node.Parent)
	return entry
}

func (f *fixtureBuilder) bbtEntry(block blockRef) []byte {
	if f.format.IsAnsi() {
		entry := make([]byte, 12)
		putU32(entry, 0, uint32(block.bid))
		putU32(entry, 4, uint32(block.ib))
		putU16(entry, 8, block.cb)
		return entry
	}
	entry := make([]byte, 24)
	putU64(entry, 0, block.bid)
	putU64(entry, 8, block.ib)
	putU16(entry, 16, block.cb)
	putU16(entry, 18, block.original)
	return entry
}

func putU16(data []byte, at int, value uint16) {
	binary.LittleEndian.PutUint16(data[at:], value)
}

func putU32(data []byte, at int, value uint32) {
	binary.LittleEndian.PutUint32(data[at:], value)
}

func putU64(data []byte, at int, value uint64) {
	binary.LittleEndian.PutUint64(data[at:], value)
}

// buildHeapBlock builds one HN block: the HNHDR, the allocations in order and
// the HNPAGEMAP that delimits them.
func buildHeapBlock(client byte, userRoot uint32, allocations [][]byte) []byte {
	block := make([]byte, hnhdrBytes)
	offsets := make([]int, 0, len(allocations)+1)
	for _, allocation := range allocations {
		offsets = append(offsets, len(block))
		block = append(block, allocation...)
	}
	offsets = append(offsets, len(block))
	ibHnpm := len(block)
	putU16(block, 0, uint16(ibHnpm))
	block[2] = hnSignature
	block[3] = client
	putU32(block, 4, userRoot)
	block[8], block[9], block[10], block[11] = 0x01, 0x02, 0x03, 0x04
	block = append(block, 0, 0, 0, 0)
	putU16(block, ibHnpm, uint16(len(allocations)))
	for _, offset := range offsets {
		block = appendU16(block, uint16(offset))
	}
	return block
}

func appendU16(data []byte, value uint16) []byte {
	return append(data, byte(value), byte(value>>8))
}

func hidFor(allocation int) uint32 {
	return uint32(allocation+1) << 5
}

type propSpec struct {
	id        uint16
	kind      uint16
	inline    []byte
	value     []byte
	subnode   uint32
	isSubnode bool
}

func pI4(id uint16, value int32) propSpec {
	inline := make([]byte, 4)
	putU32(inline, 0, uint32(value))
	return propSpec{id: id, kind: 0x0003, inline: inline}
}

func pBool(id uint16, value bool) propSpec {
	inline := make([]byte, 2)
	if value {
		inline[0] = 1
	}
	return propSpec{id: id, kind: 0x000B, inline: inline}
}

func pTime(id uint16, value Filetime) propSpec {
	bytes := make([]byte, 8)
	putU64(bytes, 0, uint64(value))
	return propSpec{id: id, kind: 0x0040, value: bytes}
}

func pText(format StoreFormat, id uint16, text string) propSpec {
	if format.IsAnsi() {
		return propSpec{id: id, kind: 0x001E, value: latin1z(text)}
	}
	return propSpec{id: id, kind: 0x001F, value: utf16z(text)}
}

func latin1z(text string) []byte {
	out := make([]byte, 0, len(text)+1)
	for _, r := range text {
		if r > 0xFF {
			out = append(out, '?')
			continue
		}
		out = append(out, byte(r))
	}
	return append(out, 0)
}

func pMultiText(format StoreFormat, id uint16, items []string) propSpec {
	if format.IsAnsi() {
		values := make([][]byte, len(items))
		for index, item := range items {
			values[index] = latin1z(item)
		}
		return propSpec{id: id, kind: 0x101E, value: multiValue(values)}
	}
	values := make([][]byte, len(items))
	for index, item := range items {
		values[index] = utf16z(item)
	}
	return propSpec{id: id, kind: 0x101F, value: multiValue(values)}
}

func pBinary(id uint16, value []byte) propSpec {
	return propSpec{id: id, kind: 0x0102, value: append([]byte(nil), value...)}
}

func pUnsupported(id, kind uint16, value []byte) propSpec {
	return propSpec{id: id, kind: kind, value: append([]byte(nil), value...)}
}

func pSubnode(id, kind uint16, subnode uint32) propSpec {
	return propSpec{id: id, kind: kind, subnode: subnode, isSubnode: true}
}

func utf16z(text string) []byte {
	units := utf16.Encode([]rune(text))
	out := make([]byte, 0, len(units)*2+2)
	for _, unit := range units {
		out = append(out, byte(unit), byte(unit>>8))
	}
	return append(out, 0, 0)
}

func multiValue(values [][]byte) []byte {
	out := make([]byte, 4, 4+4*len(values))
	putU32(out, 0, uint32(len(values)))
	offset := 4 + 4*len(values)
	offsets := make([]uint32, len(values))
	for index, value := range values {
		offsets[index] = uint32(offset)
		offset += len(value)
	}
	for _, item := range offsets {
		out = appendU32(out, item)
	}
	for _, value := range values {
		out = append(out, value...)
	}
	return out
}

func appendU32(data []byte, value uint32) []byte {
	return append(data, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

// pcBlock builds a property-context heap holding BTH records.
func pcBlock(properties []propSpec) []byte {
	allocations := make([][]byte, 2)
	records := make([]byte, 0, len(properties)*8)
	for _, property := range properties {
		field := make([]byte, 4)
		if property.isSubnode {
			putU32(field, 0, property.subnode)
		} else if width, ok := inlineWidth(property.kind); ok {
			copy(field[:width], property.inline)
		} else {
			allocations = append(allocations, property.value)
			putU32(field, 0, hidFor(len(allocations)-1))
		}
		record := make([]byte, 8)
		putU16(record, 0, property.id)
		putU16(record, 2, property.kind)
		copy(record[4:], field)
		records = append(records, record...)
	}
	allocations[1] = records
	header := make([]byte, bthHeaderBytes)
	header[0] = bthType
	header[1] = bthPCKeyBytes
	header[2] = bthPCEntBytes
	header[3] = 0
	putU32(header, 4, hidFor(1))
	allocations[0] = header
	return buildHeapBlock(pcClient, hidFor(0), allocations)
}

type slEntry struct {
	subnode uint32
	data    uint64
	nested  uint64
}

func slblock(format StoreFormat, entries []slEntry) []byte {
	layout := subnodeLayoutForFormat(format)
	block := make([]byte, layout.header)
	block[0] = subtreePageType
	block[1] = 0
	putU16(block, 2, uint16(len(entries)))
	for _, entry := range entries {
		if layout.ansi {
			block = appendU32(block, entry.subnode)
			block = appendU32(block, uint32(entry.data))
			block = appendU32(block, uint32(entry.nested))
			continue
		}
		block = append(block,
			byte(entry.subnode), byte(entry.subnode>>8), byte(entry.subnode>>16), byte(entry.subnode>>24), 0, 0, 0, 0)
		block = appendU64(block, entry.data)
		block = appendU64(block, entry.nested)
	}
	return block
}

// slIndexBlock builds a one-entry subnode index page naming childBID.
func slIndexBlock(format StoreFormat, childBID uint64) []byte {
	layout := subnodeLayoutForFormat(format)
	block := make([]byte, layout.header)
	block[0] = subtreePageType
	block[1] = 1
	putU16(block, 2, 1)
	if layout.ansi {
		block = appendU32(block, 0)
		block = appendU32(block, uint32(childBID))
		return block
	}
	block = appendU64(block, 0)
	return append(block, appendU64(nil, childBID)...)
}

// buildHeapPage builds a continuation block: the abbreviated HNPAGEHDR, or
// the full HNBITMAPHDR when bitmap is true.
func buildHeapPage(bitmap bool, client byte, userRoot uint32, allocations [][]byte) []byte {
	header := hnpagehdrBytes
	if bitmap {
		header = hnbitmaphdrBytes
	}
	block := make([]byte, header)
	if bitmap {
		block[2] = hnSignature
		block[3] = client
		putU32(block, 4, userRoot)
	}
	offsets := make([]int, 0, len(allocations)+1)
	for _, allocation := range allocations {
		offsets = append(offsets, len(block))
		block = append(block, allocation...)
	}
	offsets = append(offsets, len(block))
	ibHnpm := len(block)
	putU16(block, 0, uint16(ibHnpm))
	block = appendU16(block, uint16(len(allocations)))
	block = appendU16(block, 0)
	for _, offset := range offsets {
		block = appendU16(block, uint16(offset))
	}
	return block
}

func appendU64(data []byte, value uint64) []byte {
	return append(data, byte(value), byte(value>>8), byte(value>>16), byte(value>>24),
		byte(value>>32), byte(value>>40), byte(value>>48), byte(value>>56))
}

type tcColSpec struct {
	tag    uint32
	offset uint16
	width  uint8
	bit    uint8
}

func tcInfoBlock(columns []tcColSpec, groups [4]uint16, hnidRows uint32) []byte {
	header := make([]byte, tcInfoBytes+len(columns)*tcOldescBytes)
	header[0] = tcInfoType
	header[1] = byte(len(columns))
	for index, group := range groups {
		putU16(header, 2+index*2, group)
	}
	putU32(header, 14, hnidRows)
	for index, column := range columns {
		at := tcInfoBytes + index*tcOldescBytes
		putU32(header, at, column.tag)
		putU16(header, at+4, column.offset)
		header[at+6] = column.width
		header[at+7] = column.bit
	}
	return header
}

func tag(id, kind uint16) uint32 {
	return uint32(id)<<16 | uint32(kind)
}

// buildMainFixture builds a complete store: a root folder, an Inbox folder,
// an ordinary message with attachments and recipients, an associated message,
// and a second ordinary message with an empty body.  The strings, times and
// attachment bytes are known so callers can assert on them.
func buildMainFixture(format StoreFormat, crypt CryptMethod, compress bool) *fixtureBuilder {
	f := newFixture(format, crypt)
	f.compress = compress
	pc := func(properties []propSpec) []byte {
		if format.IsAnsi() {
			properties = append(properties, pI4(propMessageCodepage, 1252))
		}
		return pcBlock(properties)
	}
	sk := stringKind(format)

	rootPC := f.addBlock(pc([]propSpec{
		pText(format, propDisplayName, "Root"),
	}), true)
	inboxPC := f.addBlock(pc([]propSpec{
		pText(format, propDisplayName, "Inbox"),
		pI4(propContentCount, 2),
	}), true)

	// The reference LZFu stream from the RTF decoder's unit test.
	messagePC := f.addBlock(pc([]propSpec{
		pText(format, propSubject, "Quarterly numbers"),
		pText(format, propSenderName, "Alice"),
		pText(format, propSenderEmail, "EX"),
		pText(format, propSenderSMTPAddress, "alice@example.com"),
		pText(format, propMessageClass, "IPM.Note"),
		pTime(propClientSubmitTime, Filetime(132000000000000000)),
		pTime(propDeliveryTime, Filetime(132000000000000001)),
		pI4(propMessageSize, 1234),
		pI4(propMessageFlags, 0x20),
		pText(format, propBody, "Hello body"),
		pBinary(propHTML, []byte("<html>x</html>")),
		pBinary(propRTFCompressed, referenceRTFStream()),
		pText(format, propTransportHeaders, "Café"),
		pText(format, propInternetMessageID, "<id@example>"),
		pMultiText(format, propDisplayTo, []string{"Bob", "Carol"}),
		pBool(propHasAttachments, true),
		pUnsupported(0x7FFF, 0x1234, []byte{1, 2, 3, 4, 5}),
	}), true)
	emptyPC := f.addBlock(pc([]propSpec{
		pText(format, propSubject, "Empty body"),
		pText(format, propBody, ""),
	}), true)
	associatedPC := f.addBlock(pc([]propSpec{
		pText(format, propSubject, "Hidden"),
		pText(format, propMessageClass, "IPM.Note"),
	}), true)

	// One attachment object whose data is a subnode.  Its filename is not on
	// the object; the table's filename cell is a subnode, which exercises the
	// fallback and the nested table tree.
	attachmentData := f.addBlock([]byte("hello"), true)
	filenameBlock := f.addBlock(ansiOrUTF16(format, "report.pdf"), true)
	objectPC := f.addBlock(pc([]propSpec{
		pText(format, propAttachExtension, "pdf"),
		pText(format, propAttachMIME, "application/pdf"),
		pI4(propAttachMethod, 1),
		pI4(propAttachSize, 5),
		pTime(propAttachCreationTime, Filetime(132000000000000002)),
		pTime(propAttachModificationTime, Filetime(132000000000000003)),
		pText(format, propAttachContentID, "cid-1"),
		pSubnode(propAttachData, 0x0102, 0x03FF),
	}), true)
	objectNested := f.addBlock(slblock(format, []slEntry{{subnode: 0x03FF, data: attachmentData.bid}}), true)

	// Attachment table: one row naming object NID 0x2001; the row matrix is
	// in a subnode of the table's nested tree.
	row := make([]byte, 17)
	putU32(row, 0, 0x2001)
	putU32(row, 4, 0x0FFE)
	putU32(row, 8, 1)
	putU32(row, 12, 5)
	row[16] = 0xF0
	rowMatrixBlock := f.addBlock(row, true)
	tableNested := f.addBlock(slblock(format, []slEntry{
		{subnode: 0x0FFF, data: rowMatrixBlock.bid},
		{subnode: 0x0FFE, data: filenameBlock.bid},
	}), true)
	attachmentTable := f.addBlock(buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock([]tcColSpec{
			{tag: tag(propLTPRowID, 0x0003), offset: 0, width: 4, bit: 0},
			{tag: tag(propAttachFilename, sk), offset: 4, width: 4, bit: 1},
			{tag: tag(propAttachMethod, 0x0003), offset: 8, width: 4, bit: 2},
			{tag: tag(propAttachSize, 0x0003), offset: 12, width: 4, bit: 3},
		}, [4]uint16{12, 16, 16, 17}, 0x0FFF),
	}), true)

	// Recipient table with the row matrix and the four strings in the heap.
	stringAllocs := [][]byte{
		nil, // TCINFO
		ansiOrUTF16(format, "Alice"),
		ansiOrUTF16(format, "SMTP"),
		ansiOrUTF16(format, "alice@example.com"),
		ansiOrUTF16(format, "alice@example.com"),
		ansiOrUTF16(format, "Bob"),
		ansiOrUTF16(format, "SMTP"),
		ansiOrUTF16(format, "bob@example.com"),
		ansiOrUTF16(format, "bob@example.com"),
	}
	rowID := uint32(0x0601)
	recipientRow := make([]byte, 25)
	putU32(recipientRow, 0, rowID)
	putU32(recipientRow, 4, 1)
	putU32(recipientRow, 8, hidFor(1))
	putU32(recipientRow, 12, hidFor(2))
	putU32(recipientRow, 16, hidFor(3))
	putU32(recipientRow, 20, hidFor(4))
	recipientRow[24] = 0xFC
	secondRow := make([]byte, 25)
	putU32(secondRow, 0, rowID+1)
	putU32(secondRow, 4, 2)
	putU32(secondRow, 8, hidFor(5))
	putU32(secondRow, 12, hidFor(6))
	putU32(secondRow, 16, hidFor(7))
	putU32(secondRow, 20, hidFor(8))
	secondRow[24] = 0xFC
	matrix := append(recipientRow, secondRow...)
	stringAllocs[0] = tcInfoBlock([]tcColSpec{
		{tag: tag(propLTPRowID, 0x0003), offset: 0, width: 4, bit: 0},
		{tag: tag(propRecipientType, 0x0003), offset: 4, width: 4, bit: 1},
		{tag: tag(propDisplayName, sk), offset: 8, width: 4, bit: 2},
		{tag: tag(propAddressType, sk), offset: 12, width: 4, bit: 3},
		{tag: tag(propEmailAddress, sk), offset: 16, width: 4, bit: 4},
		{tag: tag(propSenderSMTP, sk), offset: 20, width: 4, bit: 5},
	}, [4]uint16{8, 24, 24, 25}, hidFor(9))
	stringAllocs = append(stringAllocs, matrix)
	recipientTable := f.addBlock(buildHeapBlock(tcClient, hidFor(0), stringAllocs), true)

	messageTree := f.addBlock(slblock(format, []slEntry{
		{subnode: AttachmentTableNID, data: attachmentTable.bid, nested: tableNested.bid},
		{subnode: RecipientTableNID, data: recipientTable.bid},
		{subnode: 0x2001, data: objectPC.bid, nested: objectNested.bid},
	}), true)

	f.nbt = []Node{
		{NID: 0x22, Data: rootPC.bid, Parent: 0x22},
		{NID: 0x42, Data: inboxPC.bid, Parent: 0x22},
		{NID: 0x1004, Data: messagePC.bid, Subnode: messageTree.bid, Parent: 0x42},
		{NID: 0x1008, Data: associatedPC.bid, Parent: 0x42},
		{NID: 0x1024, Data: emptyPC.bid, Parent: 0x42},
	}
	return f
}

func stringKind(format StoreFormat) uint16 {
	if format.IsAnsi() {
		return 0x001E
	}
	return 0x001F
}

func ansiOrUTF16(format StoreFormat, text string) []byte {
	if format.IsAnsi() {
		return latin1z(text)
	}
	return utf16z(text)
}

func referenceRTFStream() []byte {
	return []byte{
		0x41, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x4C, 0x5A, 0x46, 0x75, 0x4A, 0xDE, 0xF9,
		0x59, 0x6F, 0x00, 0x0A, 0x01, 0x03, 0x01, 0xF7, 0x02, 0xA2, 0x20, 0x07, 0x13, 0x02, 0x80,
		0x7D, 0x51, 0x0B, 0xA6, 0x20, 0x51, 0x75, 0x0A, 0xC0, 0x74, 0x04, 0x90, 0x6C, 0x70, 0x79,
		0x20, 0x6E, 0x75, 0x06, 0xD0, 0x04, 0x90, 0x06, 0x40, 0x61, 0xAB, 0x02, 0x40, 0x00, 0xD0,
		0x68, 0x09, 0x80, 0x2E, 0x0A, 0xA2, 0x7D, 0x11, 0xF0,
	}
}

const referenceRTFMarkup = "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Arial;}}\\f0\\fs20 Quarterly numbers attached.\\par}"

// buildTwoLevelArrayFixture builds a store with one message node whose data is
// an XXBLOCK -> XBLOCK -> two leaf blocks chain.
func buildTwoLevelArrayFixture() *fixtureBuilder {
	f := newFixture(FormatUnicode512, CryptNone)
	first := f.addBlock([]byte("hello "), true)
	second := f.addBlock([]byte("world"), true)
	total := uint64(len("hello ") + len("world"))
	xblock := f.addArray(1, []uint64{first.bid, second.bid}, total)
	xxblock := f.addArray(2, []uint64{xblock.bid}, total)
	f.nbt = []Node{{NID: 0x1004, Data: xxblock.bid, Parent: 0x42}}
	return f
}
