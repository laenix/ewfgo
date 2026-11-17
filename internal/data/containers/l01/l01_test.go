package l01

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---------------------------------------------------------------------------
// Synthetic L01 builder. These helpers are deliberately independent of the
// reader: every fixture is assembled byte by byte so a test failure points at
// the parser, not at a shared encoder.
// ---------------------------------------------------------------------------

var testEntryTypes = []string{
	"id", "p", "n", "ls", "lo", "po", "du", "src", "sub", "pm", "cid", "opr",
	"be", "ha", "sha", "snh", "cr", "wr", "ac", "mo", "dl", "ea",
}

var testSourceTypes = []string{
	"id", "n", "ev", "loc", "gu", "pgu", "dt", "mfr", "mo", "se", "do", "ip",
	"ma", "tb", "lo", "po", "aq", "ah", "sh",
}

var testSubjectTypes = []string{"id", "n"}
var testPermissionTypes = []string{"n", "pr", "s", "nta", "nti"}

func testAdler(data []byte) uint32 { return adler32.Checksum(data) }

func storedChunk(data []byte) []byte {
	out := append([]byte(nil), data...)
	var sum [4]byte
	binary.LittleEndian.PutUint32(sum[:], testAdler(data))
	return append(out, sum[:]...)
}

func volumeData(chunkCount, sectorsPerChunk, bytesPerSector uint32, sectorCount uint64) []byte {
	volume := make([]byte, 1052)
	volume[0] = 0x0e
	binary.LittleEndian.PutUint32(volume[4:], chunkCount)
	binary.LittleEndian.PutUint32(volume[8:], sectorsPerChunk)
	binary.LittleEndian.PutUint32(volume[12:], bytesPerSector)
	binary.LittleEndian.PutUint64(volume[16:], sectorCount)
	for i := 64; i < 80; i++ {
		volume[i] = 0x42
	}
	binary.LittleEndian.PutUint32(volume[1048:], testAdler(volume[:1048]))
	return volume
}

func tableData(baseOffset uint64, entries []uint32) []byte {
	table := make([]byte, 24)
	binary.LittleEndian.PutUint32(table[0:], uint32(len(entries)))
	binary.LittleEndian.PutUint64(table[8:], baseOffset)
	binary.LittleEndian.PutUint32(table[20:], testAdler(table[:20]))
	entryStart := len(table)
	for _, entry := range entries {
		var raw [4]byte
		binary.LittleEndian.PutUint32(raw[:], entry)
		table = append(table, raw[:]...)
	}
	var sum [4]byte
	binary.LittleEndian.PutUint32(sum[:], testAdler(table[entryStart:]))
	return append(table, sum[:]...)
}

type testSection struct {
	kind             string
	descriptorOffset uint64
	dataOffset       uint64
	dataSize         uint64
}

type testSegment struct {
	buf      []byte
	sections []testSection
}

func newTestSegment(number uint16, marker byte) *testSegment {
	buf := make([]byte, 13)
	copy(buf, []byte(Signature))
	buf[8] = marker
	binary.LittleEndian.PutUint16(buf[9:], number)
	return &testSegment{buf: buf}
}

func (b *testSegment) push(kind string, data []byte) uint64 {
	descriptorOffset := uint64(len(b.buf))
	dataOffset := descriptorOffset + 76
	b.buf = append(b.buf, make([]byte, 76)...)
	b.buf = append(b.buf, data...)
	b.sections = append(b.sections, testSection{
		kind:             kind,
		descriptorOffset: descriptorOffset,
		dataOffset:       dataOffset,
		dataSize:         uint64(len(data)),
	})
	return dataOffset
}

func (b *testSegment) setDescriptorBytes(kind string, at int, data []byte) {
	for _, section := range b.sections {
		if section.kind == kind {
			copy(b.buf[int(section.descriptorOffset)+at:], data)
			return
		}
	}
	panic("section not found: " + kind)
}

func (b *testSegment) finish() []byte {
	end := uint64(len(b.buf))
	for index, section := range b.sections {
		size := uint64(76) + section.dataSize
		next := section.descriptorOffset
		if section.kind != "done" && section.kind != "next" {
			if index+1 < len(b.sections) {
				next = b.sections[index+1].descriptorOffset
			} else {
				next = end
			}
		}
		start := int(section.descriptorOffset)
		for i := 0; i < 16; i++ {
			b.buf[start+i] = 0
		}
		copy(b.buf[start:], section.kind)
		binary.LittleEndian.PutUint64(b.buf[start+16:], next)
		binary.LittleEndian.PutUint64(b.buf[start+24:], size)
		binary.LittleEndian.PutUint32(b.buf[start+72:], testAdler(b.buf[start:start+72]))
	}
	return b.buf
}

// catalogText assembles the UTF-16 ltree text. Overrides let a test inject raw
// (possibly ill-formed) UTF-16 code units into one column of one row.
type testCatalogLine struct {
	text string
	raw  map[int][]uint16
}

type catalogText struct {
	lines []testCatalogLine
	bom   bool
}

func (c *catalogText) add(text string) { c.lines = append(c.lines, testCatalogLine{text: text}) }

func (c *catalogText) addRow(values []string, raw map[int][]uint16) {
	c.lines = append(c.lines, testCatalogLine{text: strings.Join(values, "\t"), raw: raw})
}

func encodeCatalogLine(line testCatalogLine) []uint16 {
	values := strings.Split(line.text, "\t")
	var units []uint16
	for index, value := range values {
		if index > 0 {
			units = append(units, '\t')
		}
		if line.raw != nil {
			if replacement, ok := line.raw[index]; ok {
				units = append(units, replacement...)
				continue
			}
		}
		units = append(units, utf16.Encode([]rune(value))...)
	}
	return units
}

func (c *catalogText) utf16Bytes() []byte {
	var units []uint16
	if c.bom {
		units = append(units, 0xfeff)
	}
	for index, line := range c.lines {
		if index > 0 {
			units = append(units, '\n')
		}
		units = append(units, encodeCatalogLine(line)...)
	}
	out := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(out[index*2:], unit)
	}
	return out
}

func valuesRow(types []string, values map[string]string) []string {
	row := make([]string, len(types))
	for index, kind := range types {
		row[index] = values[kind]
	}
	return row
}

func writeFlatCategory(c *catalogText, name string, types []string, records []map[string]string) {
	root := map[string]string{}
	var children []map[string]string
	if len(records) > 0 {
		root = records[0]
		children = records[1:]
	}
	c.add(name)
	c.add(fmt.Sprintf("%d\t1", len(children)))
	c.add(strings.Join(types, "\t"))
	c.add(fmt.Sprintf("0\t%d", len(children)))
	c.addRow(valuesRow(types, root), nil)
	for _, child := range children {
		c.add("0\t0")
		c.addRow(valuesRow(types, child), nil)
	}
	c.add("")
}

type fileNode struct {
	values   map[string]string
	raw      map[int][]uint16
	children []*fileNode
}

func newNode(values map[string]string, children ...*fileNode) *fileNode {
	return &fileNode{values: values, children: children}
}

func writeFileNode(c *catalogText, node *fileNode) {
	c.add(fmt.Sprintf("0\t%d", len(node.children)))
	c.addRow(valuesRow(testEntryTypes, node.values), node.raw)
	for _, child := range node.children {
		writeFileNode(c, child)
	}
}

func ltreePayload(mediaSize uint64, root *fileNode, sources, subjects []map[string]string, withBOM bool) []byte {
	c := &catalogText{bom: withBOM}
	c.add("5")
	c.add("rec")
	c.add("tb")
	c.add(strconv.FormatUint(mediaSize, 10))
	c.add("")
	writeFlatCategory(c, "perm", testPermissionTypes, []map[string]string{{"pr": "10"}})
	writeFlatCategory(c, "srce", testSourceTypes, sources)
	writeFlatCategory(c, "sub", testSubjectTypes, subjects)
	c.add("entry")
	c.add("0\t1")
	c.add(strings.Join(testEntryTypes, "\t"))
	writeFileNode(c, root)
	c.add("")

	text := c.utf16Bytes()
	payload := make([]byte, 48)
	sum := md5.Sum(text)
	copy(payload[:16], sum[:])
	binary.LittleEndian.PutUint64(payload[16:], uint64(len(text)))
	header := append([]byte(nil), payload[:48]...)
	for i := 24; i < 28; i++ {
		header[i] = 0
	}
	binary.LittleEndian.PutUint32(payload[24:], testAdler(header))
	return append(payload, text...)
}

type imageOptions struct {
	number       uint16
	marker       byte
	headerData   []byte
	headerMethod string
	terminal     string

	sources  []map[string]string
	subjects []map[string]string
	root     *fileNode

	mediaSize *uint64
	withBOM   bool

	sectorsData  []byte
	tableEntries []uint32
	tableBase    *uint64
	chunkSectors uint32
	sectorBytes  uint32
	sectorCount  uint64

	omitVolume  bool
	omitSectors bool
	omitTable   bool
	omitLTree   bool
	extra       []extraSection
}

type extraSection struct {
	kind string
	data []byte
}

func ptrU64(value uint64) *uint64 { return &value }

func buildImage(t *testing.T, options imageOptions) []byte {
	t.Helper()
	if options.number == 0 {
		options.number = 1
	}
	if options.marker == 0 {
		options.marker = 0x01
	}
	if options.terminal == "" {
		options.terminal = "done"
	}
	if options.chunkSectors == 0 {
		options.chunkSectors = 64
	}
	if options.sectorBytes == 0 {
		options.sectorBytes = 512
	}
	if options.sectorCount == 0 {
		options.sectorCount = 1
	}
	if options.root == nil {
		options.root = newNode(map[string]string{"id": "1", "p": "1", "n": "ROOT"})
	}
	if options.sectorsData == nil {
		options.sectorsData = storedChunk(nil)
	}
	mediaSize := uint64(0)
	if options.mediaSize != nil {
		mediaSize = *options.mediaSize
	} else {
		mediaSize = uint64(len(options.sectorsData))
	}

	segment := newTestSegment(options.number, options.marker)
	if options.headerData != nil {
		segment.push("header", options.headerData)
		if options.headerMethod != "" {
			segment.setDescriptorBytes("header", 32, []byte(options.headerMethod))
		}
	}
	if !options.omitVolume {
		segment.push("volume", volumeData(0, options.chunkSectors, options.sectorBytes, options.sectorCount))
	}
	var sectorsOffset uint64
	if !options.omitSectors {
		sectorsOffset = segment.push("sectors", options.sectorsData)
	}
	if !options.omitTable {
		base := sectorsOffset
		if options.tableBase != nil {
			base = *options.tableBase
		}
		entries := options.tableEntries
		if entries == nil {
			entries = []uint32{0}
		}
		segment.push("table", tableData(base, entries))
	}
	for _, extra := range options.extra {
		segment.push(extra.kind, extra.data)
	}
	if !options.omitLTree {
		segment.push("ltree", ltreePayload(mediaSize, options.root, options.sources, options.subjects, options.withBOM))
	}
	segment.push(options.terminal, nil)
	return segment.finish()
}

func findSection(t *testing.T, image []byte, kind string) (descriptor, data, size uint64) {
	t.Helper()
	offset := uint64(13)
	for {
		if offset+76 > uint64(len(image)) {
			t.Fatalf("section chain ran off the image looking for %q", kind)
		}
		found := string(bytes.TrimRight(image[offset:offset+16], "\x00"))
		next := binary.LittleEndian.Uint64(image[offset+16:])
		sectionSize := binary.LittleEndian.Uint64(image[offset+24:])
		if found == kind {
			return offset, offset + 76, sectionSize - 76
		}
		if found == "done" || found == "next" {
			break
		}
		offset = next
	}
	t.Fatalf("section %q not found", kind)
	return 0, 0, 0
}

func refreshDescriptorChecksum(image []byte, descriptor uint64) {
	binary.LittleEndian.PutUint32(image[descriptor+72:], testAdler(image[descriptor:descriptor+72]))
}

func setSectionMethod(t *testing.T, image []byte, kind, method string) {
	t.Helper()
	descriptor, _, _ := findSection(t, image, kind)
	for i := descriptor + 32; i < descriptor+72; i++ {
		image[i] = 0
	}
	copy(image[descriptor+32:], method)
	refreshDescriptorChecksum(image, descriptor)
}

func flipByte(t *testing.T, image []byte, offset uint64) {
	t.Helper()
	if offset >= uint64(len(image)) {
		t.Fatalf("flip offset %d outside image of %d bytes", offset, len(image))
	}
	image[offset] ^= 0xff
}

func mustOpen(t *testing.T, image []byte) *Image {
	t.Helper()
	img, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return img
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestOpenAndReadStoredImage(t *testing.T) {
	content := []byte("hello world")
	root := newNode(
		map[string]string{"id": "1", "p": "1", "n": "CASE"},
		newNode(map[string]string{
			"id": "2", "p": "0", "n": "hello.txt", "ls": "11", "du": "0",
			"ha": md5Hex(content), "sha": sha1Hex(content),
			"cr": "1142163845", "wr": "1142163846", "ac": "1142163847", "mo": "1142163848",
		}),
	)
	image := buildImage(t, imageOptions{
		root:        root,
		mediaSize:   ptrU64(uint64(len(content))),
		sectorsData: storedChunk(content),
	})
	img := mustOpen(t, image)

	info := img.Info()
	if info.Segments != 1 || len(info.SegmentNumbers) != 1 || info.SegmentNumbers[0] != 1 {
		t.Fatalf("segment report = %d %v", info.Segments, info.SegmentNumbers)
	}
	if !info.LogicalSizeSet || info.LogicalSize != uint64(len(content)) {
		t.Fatalf("logical size = %d set=%v", info.LogicalSize, info.LogicalSizeSet)
	}
	if !info.LogicalDataSizeSet || info.LogicalDataSize != uint64(len(content)) {
		t.Fatalf("logical data size = %d set=%v", info.LogicalDataSize, info.LogicalDataSizeSet)
	}
	if !info.ChunkSizeSet || info.ChunkSize != 64*512 {
		t.Fatalf("chunk size = %d set=%v", info.ChunkSize, info.ChunkSizeSet)
	}
	if info.MediaType != 0x0e || info.SectorsPerChunk != 64 || info.BytesPerSector != 512 {
		t.Fatalf("volume metadata = %#x %d %d", info.MediaType, info.SectorsPerChunk, info.BytesPerSector)
	}
	if info.Entries != 2 || info.Directories != 1 || info.Files != 1 || info.UnknownEntries != 0 {
		t.Fatalf("record counts = %d/%d/%d/%d", info.Entries, info.Directories, info.Files, info.UnknownEntries)
	}
	if info.Chunks != 1 || info.StoredChunks != 1 || info.CompressedChunks != 0 {
		t.Fatalf("chunk counts = %d/%d/%d", info.Chunks, info.StoredChunks, info.CompressedChunks)
	}
	if info.Compression != "stored" || info.Encrypted {
		t.Fatalf("compression = %q encrypted=%v", info.Compression, info.Encrypted)
	}
	if !info.LTreeMD5Present || !info.LTreeMD5OK || !info.LTreeHeaderAdlerPresent || !info.LTreeHeaderAdlerOK {
		t.Fatalf("ltree integrity = %+v", info)
	}
	if !info.RootIndexSet || info.RootIndex != 0 {
		t.Fatalf("root = %d set=%v", info.RootIndex, info.RootIndexSet)
	}
	if len(info.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", info.Warnings)
	}

	entries, err := img.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d", len(entries))
	}
	rootEntry := entries[0]
	if rootEntry.Kind != KindDirectory || rootEntry.Name != "CASE" || rootEntry.Path != "/CASE" ||
		rootEntry.Parent != -1 || rootEntry.Depth != 0 {
		t.Fatalf("root entry = %+v", rootEntry)
	}
	if len(rootEntry.Children) != 1 || rootEntry.Children[0] != 1 {
		t.Fatalf("root children = %v", rootEntry.Children)
	}
	file := entries[1]
	if file.Kind != KindFile || file.Name != "hello.txt" || file.Path != "/CASE/hello.txt" ||
		file.Parent != 0 || file.Depth != 1 || file.Deleted() {
		t.Fatalf("file entry = %+v", file)
	}
	if file.Size == nil || *file.Size != uint64(len(content)) {
		t.Fatalf("file size = %v", file.Size)
	}
	if file.MD5 != md5Hex(content) || file.SHA1 != sha1Hex(content) {
		t.Fatalf("file hashes = %q %q", file.MD5, file.SHA1)
	}
	if file.CreationTime == nil || *file.CreationTime != 1142163845 ||
		file.ModificationTime == nil || *file.ModificationTime != 1142163846 ||
		file.AccessTime == nil || *file.AccessTime != 1142163847 ||
		file.EntryModificationTime == nil || *file.EntryModificationTime != 1142163848 {
		t.Fatalf("file timestamps = %+v", file)
	}

	stream, err := img.OpenFile("/CASE/hello.txt", 42)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if stream.SourceID() != 42 || stream.Len() != uint64(len(content)) {
		t.Fatalf("stream id/len = %d/%d", stream.SourceID(), stream.Len())
	}
	buf := make([]byte, len(content))
	if n, err := stream.ReadAt(0, buf); err != nil || n != len(content) {
		t.Fatalf("read = %d, %v", n, err)
	}
	if !bytes.Equal(buf, content) {
		t.Fatalf("content = %q", buf)
	}
	part := make([]byte, 5)
	if n, err := stream.ReadAt(6, part); err != nil || n != 5 || string(part) != "world" {
		t.Fatalf("partial read = %d %q %v", n, part, err)
	}
	tail := make([]byte, 10)
	if n, err := stream.ReadAt(8, tail); err != nil || n != 3 || string(tail[:3]) != "rld" {
		t.Fatalf("tail read = %d %q %v", n, tail, err)
	}
	if _, err := stream.ReadAt(uint64(len(content)), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past EOF error = %v", err)
	}

	// The path without a leading slash is accepted too.
	if _, err := img.OpenFile("CASE/hello.txt", 43); err != nil {
		t.Fatalf("relative path OpenFile: %v", err)
	}
}

func TestZlibChunkIsDecompressed(t *testing.T) {
	content := []byte("compressed logical evidence payload")
	var encoded bytes.Buffer
	writer := zlib.NewWriter(&encoded)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	root := newNode(map[string]string{
		"id": "2", "p": "0", "n": "compressed.bin", "ls": strconv.Itoa(len(content)), "du": "0",
	})
	image := buildImage(t, imageOptions{
		root:         root,
		mediaSize:    ptrU64(uint64(len(content))),
		sectorsData:  encoded.Bytes(),
		tableEntries: []uint32{0x8000_0000},
	})
	img := mustOpen(t, image)
	info := img.Info()
	if info.Compression != "zlib" || info.CompressedChunks != 1 || info.StoredChunks != 0 {
		t.Fatalf("compression report = %q %d/%d", info.Compression, info.CompressedChunks, info.StoredChunks)
	}
	stream, err := img.OpenFile("/compressed.bin", 2)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got := make([]byte, len(content))
	if _, err := stream.ReadAt(0, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content = %q", got)
	}
}

func TestCorruptZlibChunkFailsRead(t *testing.T) {
	content := []byte("not actually zlib")
	root := newNode(map[string]string{
		"id": "2", "p": "0", "n": "bad.bin", "ls": strconv.Itoa(len(content)), "du": "0",
	})
	image := buildImage(t, imageOptions{
		root:         root,
		mediaSize:    ptrU64(uint64(len(content))),
		sectorsData:  content,
		tableEntries: []uint32{0x8000_0000},
	})
	img := mustOpen(t, image)
	stream, err := img.OpenFile("/bad.bin", 2)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := stream.ReadAt(0, make([]byte, len(content))); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("corrupt zlib read error = %v", err)
	}
}

func TestExtentsAndSparseEntryReads(t *testing.T) {
	media := []byte("ABCDEFGH")
	rootFile := func(values map[string]string) *fileNode {
		return newNode(values)
	}

	rows := []struct {
		name string
		rows map[string]string
		want []byte
	}{
		{
			name: "extents are read in order",
			rows: map[string]string{"id": "2", "p": "0", "n": "extents.bin", "ls": "8", "be": "2 0 4 4 4"},
			want: media,
		},
		{
			name: "a sparse extent reads as recorded zeros",
			rows: map[string]string{"id": "2", "p": "0", "n": "hole.bin", "ls": "8", "be": "2 0 4 S 0 4"},
			want: append(append([]byte(nil), media[:4]...), 0, 0, 0, 0),
		},
	}
	for _, test := range rows {
		image := buildImage(t, imageOptions{
			root:        rootFile(test.rows),
			mediaSize:   ptrU64(uint64(len(media))),
			sectorsData: storedChunk(media),
		})
		img := mustOpen(t, image)
		stream, err := img.OpenFile("/"+test.rows["n"], 7)
		if err != nil {
			t.Fatalf("%s: OpenFile: %v", test.name, err)
		}
		got := make([]byte, len(test.want))
		if _, err := stream.ReadAt(0, got); err != nil {
			t.Fatalf("%s: read: %v", test.name, err)
		}
		if !bytes.Equal(got, test.want) {
			t.Fatalf("%s: got %q want %q", test.name, got, test.want)
		}
	}

	// Short extent coverage must fail, never pad with zeroes.
	image := buildImage(t, imageOptions{
		root:        rootFile(map[string]string{"id": "2", "p": "0", "n": "short.bin", "ls": "8", "be": "2 0 4 4 2"}),
		mediaSize:   ptrU64(uint64(len(media))),
		sectorsData: storedChunk(media),
	})
	img := mustOpen(t, image)
	stream, err := img.OpenFile("/short.bin", 7)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	_, err = stream.ReadAt(0, make([]byte, 8))
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "extents cover") {
		t.Fatalf("short extent error = %v", err)
	}
}

func TestSparseEntryUsesStoredByteOrDuplicateOffset(t *testing.T) {
	image := buildImage(t, imageOptions{
		root:        newNode(map[string]string{"id": "2", "p": "0", "n": "sparse.bin", "ls": "4", "opr": "67108864", "be": "1 0 1"}),
		mediaSize:   ptrU64(1),
		sectorsData: storedChunk([]byte("Q")),
	})
	img := mustOpen(t, image)
	stream, err := img.OpenFile("/sparse.bin", 1)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got := make([]byte, 4)
	if _, err := stream.ReadAt(0, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "QQQQ" {
		t.Fatalf("stored byte = %q", got)
	}

	image = buildImage(t, imageOptions{
		root:        newNode(map[string]string{"id": "2", "p": "0", "n": "duplicate.bin", "ls": "4", "opr": "67108864", "du": "0"}),
		mediaSize:   ptrU64(4),
		sectorsData: storedChunk([]byte("WXYZ")),
	})
	img = mustOpen(t, image)
	stream, err = img.OpenFile("/duplicate.bin", 1)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got = make([]byte, 4)
	if _, err := stream.ReadAt(0, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "WXYZ" {
		t.Fatalf("duplicate offset = %q", got)
	}
}

func TestVerifyEntryHashes(t *testing.T) {
	media := []byte("ABCDEFGH")
	correct := md5Hex(media)
	wrongSHA := strings.Repeat("0", 39) + "1"
	image := buildImage(t, imageOptions{
		root: newNode(map[string]string{
			"id": "2", "p": "0", "n": "digest.bin", "ls": "8",
			"be": "1 0 8", "ha": correct, "sha": wrongSHA,
		}),
		mediaSize:   ptrU64(uint64(len(media))),
		sectorsData: storedChunk(media),
	})
	img := mustOpen(t, image)
	hashes, err := img.VerifyEntryHashes(0)
	if err != nil {
		t.Fatalf("VerifyEntryHashes: %v", err)
	}
	if hashes.MD5.Status != HashVerified || hashes.SHA1.Status != HashMismatch {
		t.Fatalf("hash statuses = %+v", hashes)
	}
	if hashes.SHA1.Declared != wrongSHA || hashes.SHA1.Computed != sha1Hex(media) {
		t.Fatalf("sha mismatch detail = %+v", hashes.SHA1)
	}
	if hashes.BytesHashed != uint64(len(media)) {
		t.Fatalf("bytes hashed = %d", hashes.BytesHashed)
	}

	// An all-zero digest means "not recorded", not "verified".
	image = buildImage(t, imageOptions{
		root: newNode(map[string]string{
			"id": "2", "p": "0", "n": "nodigest.bin", "ls": "8",
			"be": "1 0 8", "ha": strings.Repeat("0", 32),
		}),
		mediaSize:   ptrU64(uint64(len(media))),
		sectorsData: storedChunk(media),
	})
	img = mustOpen(t, image)
	hashes, err = img.VerifyEntryHashes(0)
	if err != nil {
		t.Fatalf("VerifyEntryHashes: %v", err)
	}
	if hashes.MD5.Status != HashNotDeclared || hashes.SHA1.Status != HashNotDeclared || hashes.BytesHashed != 0 {
		t.Fatalf("not-declared hashes = %+v", hashes)
	}
}

func TestPathErrorsAndDuplicates(t *testing.T) {
	duplicate := func(name string, offset string) *fileNode {
		return newNode(map[string]string{
			"id": "2", "p": "0", "n": name, "ls": "4", "du": offset,
		})
	}
	root := newNode(
		map[string]string{"id": "1", "p": "1", "n": "CASE"},
		newNode(map[string]string{"id": "3", "p": "1", "n": "docs"}),
		duplicate("same.txt", "0"),
		duplicate("same.txt", "4"),
	)
	image := buildImage(t, imageOptions{
		root:        root,
		mediaSize:   ptrU64(8),
		sectorsData: storedChunk([]byte("aaaabbbb")),
	})
	img := mustOpen(t, image)

	if _, err := img.OpenFile("/CASE/missing.txt", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing path error = %v", err)
	}
	if _, err := img.OpenFile("", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty path error = %v", err)
	}
	if _, err := img.OpenFile("/CASE/docs", 1); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("directory path error = %v", err)
	}
	if _, err := img.OpenFile("/CASE/same.txt", 1); !errors.Is(err, ErrAmbiguousPath) {
		t.Fatalf("ambiguous path error = %v", err)
	}

	entries, err := img.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %d", len(entries))
	}
	seen := 0
	for _, entry := range entries {
		if entry.Path == "/CASE/same.txt" {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("duplicate paths = %d", seen)
	}
}

func TestOddAndInvalidNamesArePreserved(t *testing.T) {
	unicodeRoot := newNode(
		map[string]string{"id": "1", "p": "1", "n": "CASE"},
		newNode(map[string]string{"id": "2", "p": "0", "n": "résumé final.txt", "ls": "1", "du": "0"}),
	)
	image := buildImage(t, imageOptions{
		root:        unicodeRoot,
		mediaSize:   ptrU64(1),
		sectorsData: storedChunk([]byte("A")),
	})
	img := mustOpen(t, image)
	entries, err := img.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if entries[1].Name != "résumé final.txt" || entries[1].Path != "/CASE/résumé final.txt" {
		t.Fatalf("unicode name = %q path = %q", entries[1].Name, entries[1].Path)
	}
	if _, err := img.OpenFile("/CASE/résumé final.txt", 1); err != nil {
		t.Fatalf("OpenFile unicode: %v", err)
	}

	// An ill-formed UTF-16 name is retained verbatim in NameUTF16 and exposed
	// lossily in Name; it must not fail the catalog.
	badName := newNode(map[string]string{"id": "2", "p": "0", "n": "placeholder", "ls": "1", "du": "0"})
	badName.raw = map[int][]uint16{2: {'A', 0xd800, 'B'}}
	rootBad := newNode(map[string]string{"id": "1", "p": "1", "n": "CASE"}, badName)
	image = buildImage(t, imageOptions{
		root:        rootBad,
		mediaSize:   ptrU64(1),
		sectorsData: storedChunk([]byte("A")),
	})
	img = mustOpen(t, image)
	entries, err = img.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if entries[1].NameUTF16 == nil || len(entries[1].NameUTF16) != 3 ||
		entries[1].NameUTF16[1] != 0xd800 {
		t.Fatalf("raw name = %v", entries[1].NameUTF16)
	}
	if !strings.Contains(entries[1].Name, "A") || !strings.Contains(entries[1].Name, "B") {
		t.Fatalf("lossy name = %q", entries[1].Name)
	}
}

func TestInvalidUTF16InANonNameFieldIsRefused(t *testing.T) {
	file := newNode(map[string]string{"id": "2", "p": "0", "n": "bad.bin", "ls": "1", "du": "0"})
	file.raw = map[int][]uint16{3: {'1', 0xd800}} // ls column is index 3
	root := newNode(map[string]string{"id": "1", "p": "1", "n": "CASE"}, file)
	image := buildImage(t, imageOptions{
		root:        root,
		mediaSize:   ptrU64(1),
		sectorsData: storedChunk([]byte("A")),
	})
	_, err := Open(source.NewMemorySource(1, image))
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "not valid UTF-16") {
		t.Fatalf("error = %v", err)
	}
}

func TestUnsupportedCompressionAndEncryption(t *testing.T) {
	bare := func(marker byte) []byte {
		image := make([]byte, 13)
		copy(image, []byte(Signature))
		image[8] = marker
		binary.LittleEndian.PutUint16(image[9:], 1)
		return image
	}
	cases := []struct {
		marker byte
		want   string
	}{
		{0x21, "zstd"},
		{0x81, "encrypted"},
		{0xa1, "encrypted"},
		{0x55, "unknown compression method"},
	}
	for _, test := range cases {
		_, err := Open(source.NewMemorySource(1, bare(test.marker)))
		if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("marker %#x error = %v", test.marker, err)
		}
	}

	// X-Ways encrypted and unknown vendor sections are refused by name.
	image := buildImage(t, imageOptions{
		root:  newNode(map[string]string{"id": "1", "p": "1", "n": "ROOT"}),
		extra: []extraSection{{kind: "x_encryption", data: []byte{0}}},
	})
	_, err := Open(source.NewMemorySource(1, image))
	if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("x_encryption error = %v", err)
	}

	image = buildImage(t, imageOptions{
		root:  newNode(map[string]string{"id": "1", "p": "1", "n": "ROOT"}),
		extra: []extraSection{{kind: "x_vendor_thing", data: []byte{0}}},
	})
	_, err = Open(source.NewMemorySource(1, image))
	if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "x_vendor_thing") {
		t.Fatalf("x_vendor error = %v", err)
	}

	image = buildImage(t, imageOptions{
		root:  newNode(map[string]string{"id": "1", "p": "1", "n": "ROOT"}),
		extra: []extraSection{{kind: "weird_vendor", data: []byte{0}}},
	})
	_, err = Open(source.NewMemorySource(1, image))
	if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "weird_vendor") {
		t.Fatalf("unknown section error = %v", err)
	}

	// A declared header compression method this reader does not know.
	image = buildImage(t, imageOptions{
		root:         newNode(map[string]string{"id": "1", "p": "1", "n": "ROOT"}),
		headerData:   []byte("1\nmain\nc\nx\n\n"),
		headerMethod: "lz4",
	})
	_, err = Open(source.NewMemorySource(1, image))
	if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "lz4") {
		t.Fatalf("header compression error = %v", err)
	}
}

func TestEWF2LogicalEvidenceIsRefused(t *testing.T) {
	image := make([]byte, 13)
	copy(image, []byte(LEF2Signature))
	binary.LittleEndian.PutUint16(image[9:], 1)
	_, err := Open(source.NewMemorySource(1, image))
	if !errors.Is(err, source.ErrUnsupported) ||
		!strings.Contains(err.Error(), "LEF2") || !strings.Contains(err.Error(), "EWF v2") {
		t.Fatalf("LEF2 error = %v", err)
	}
}

func TestBadChecksumsAreRefused(t *testing.T) {
	content := []byte("checksum content")
	root := newNode(map[string]string{"id": "2", "p": "0", "n": "check.bin", "ls": "16", "du": "0"})
	build := func() []byte {
		return buildImage(t, imageOptions{
			root:        root,
			mediaSize:   ptrU64(uint64(len(content))),
			sectorsData: storedChunk(content),
		})
	}

	t.Run("section descriptor", func(t *testing.T) {
		image := build()
		descriptor, _, _ := findSection(t, image, "volume")
		flipByte(t, image, descriptor+72)
		_, err := Open(source.NewMemorySource(1, image))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "descriptor Adler-32 mismatch") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("ltree header", func(t *testing.T) {
		image := build()
		_, data, _ := findSection(t, image, "ltree")
		flipByte(t, image, data+24)
		_, err := Open(source.NewMemorySource(1, image))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "ltree header Adler-32 mismatch") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("ltree text md5", func(t *testing.T) {
		image := build()
		_, data, _ := findSection(t, image, "ltree")
		flipByte(t, image, data+60) // inside the UTF-16 text
		_, err := Open(source.NewMemorySource(1, image))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "ltree text MD5") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("volume", func(t *testing.T) {
		image := build()
		_, data, _ := findSection(t, image, "volume")
		flipByte(t, image, data+1048)
		_, err := Open(source.NewMemorySource(1, image))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "volume section Adler-32 mismatch") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("table header", func(t *testing.T) {
		image := build()
		_, data, _ := findSection(t, image, "table")
		flipByte(t, image, data+20)
		_, err := Open(source.NewMemorySource(1, image))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "table header Adler-32 mismatch") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("table entries", func(t *testing.T) {
		image := build()
		_, data, _ := findSection(t, image, "table")
		flipByte(t, image, data+24+4) // footer after one entry
		_, err := Open(source.NewMemorySource(1, image))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "table entries Adler-32 mismatch") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("stored chunk", func(t *testing.T) {
		image := build()
		_, data, size := findSection(t, image, "sectors")
		flipByte(t, image, data+size-1)
		img := mustOpen(t, image)
		stream, err := img.OpenFile("/check.bin", 1)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		if _, err := stream.ReadAt(0, make([]byte, len(content))); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "Adler-32 mismatch") {
			t.Fatalf("read error = %v", err)
		}
	})
}

func TestTruncatedAndCorruptCatalogStructures(t *testing.T) {
	content := []byte("truncate me")
	root := newNode(map[string]string{"id": "2", "p": "0", "n": "f.bin", "ls": "11", "du": "0"})
	build := func(overrides ...func([]byte)) []byte {
		image := buildImage(t, imageOptions{
			root:        root,
			mediaSize:   ptrU64(uint64(len(content))),
			sectorsData: storedChunk(content),
		})
		for _, override := range overrides {
			override(image)
		}
		return image
	}

	if _, err := Open(source.NewMemorySource(1, build()[:40])); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated header error = %v", err)
	}
	if _, err := Open(source.NewMemorySource(1, build()[:len(build())/2])); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("truncated body error = %v", err)
	}

	image := build(func(img []byte) {
		_, data, _ := findSection(t, img, "ltree")
		binary.LittleEndian.PutUint64(img[data+16:], 1<<20)
	})
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated ltree text error = %v", err)
	}

	badRows := []struct {
		name string
		file *fileNode
		want string
	}{
		{"size is not a number", newNode(map[string]string{"id": "2", "p": "0", "n": "x", "ls": "nope", "du": "0"}), "not an unsigned integer"},
		{"extent count mismatch", newNode(map[string]string{"id": "2", "p": "0", "n": "x", "ls": "4", "be": "2 0 4"}), "declares 2 extents"},
		{"source id out of range", newNode(map[string]string{"id": "2", "p": "0", "n": "x", "ls": "0", "src": "5000000000"}), "outside i32"},
		{"hash length", newNode(map[string]string{"id": "2", "p": "0", "n": "x", "ls": "0", "ha": "abcd"}), "hex digits"},
		{"short name size", newNode(map[string]string{"id": "2", "p": "0", "n": "x", "ls": "0", "snh": "9 foo"}), "short name declares"},
	}
	for _, test := range badRows {
		image := buildImage(t, imageOptions{
			root:        test.file,
			mediaSize:   ptrU64(0),
			sectorsData: storedChunk(nil),
		})
		_, err := Open(source.NewMemorySource(1, image))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s error = %v", test.name, err)
		}
	}
}

func TestDecodeLinesRejectsOddByteCount(t *testing.T) {
	if _, err := decodeLines([]byte{0x00, 0x00, 0x41}); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), "odd UTF-16") {
		t.Fatalf("odd UTF-16 error = %v", err)
	}
}

func TestHeaderMetadataIsExposed(t *testing.T) {
	header := []byte("1\nmain\na\tc\tn\te\tt\tm\tu\tav\tov\nDescription\tCASE-42\tEVID-7\tJane Doe\tnote\t2020-01-02 03:04:05\t2020-01-03 04:05:06\t7.1\tWindows 10\n\n")
	root := newNode(map[string]string{"id": "1", "p": "1", "n": "CASE"})
	image := buildImage(t, imageOptions{
		root:        root,
		headerData:  header,
		mediaSize:   ptrU64(0),
		sectorsData: storedChunk(nil),
	})
	img := mustOpen(t, image)
	info := img.Info()
	if info.Header.CaseNumber != "CASE-42" || info.Header.EvidenceNumber != "EVID-7" ||
		info.Header.Examiner != "Jane Doe" || info.Header.Description != "Description" ||
		info.Header.Notes != "note" || info.Header.AcquisitionSoftware != "7.1" ||
		info.Header.AcquisitionOS != "Windows 10" ||
		info.Header.AcquisitionDate != "2020-01-02 03:04:05" ||
		info.Header.SystemDate != "2020-01-03 04:05:06" {
		t.Fatalf("header = %+v", info.Header)
	}
	if info.CaseNumber != "CASE-42" || info.EvidenceNumber != "EVID-7" {
		t.Fatalf("case/evidence = %q/%q", info.CaseNumber, info.EvidenceNumber)
	}

	// The same metadata compressed with zlib and declared in the descriptor.
	var encoded bytes.Buffer
	writer := zlib.NewWriter(&encoded)
	if _, err := writer.Write(header); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	image = buildImage(t, imageOptions{
		root:         root,
		headerData:   encoded.Bytes(),
		headerMethod: "zlib",
		mediaSize:    ptrU64(0),
		sectorsData:  storedChunk(nil),
	})
	img = mustOpen(t, image)
	if got := img.Info().Header.CaseNumber; got != "CASE-42" {
		t.Fatalf("compressed header case = %q", got)
	}

	// header2 is commonly zlib-compressed without naming the method.
	var warnings []string
	implicit := parseHeaderPayload(encoded.Bytes(), "", &warnings)
	if implicit.CaseNumber != "CASE-42" {
		t.Fatalf("implicit zlib header case = %q warnings=%v", implicit.CaseNumber, warnings)
	}
}

func TestMalformedHeaderIsAWarningNotAFailure(t *testing.T) {
	image := buildImage(t, imageOptions{
		root:        newNode(map[string]string{"id": "1", "p": "1", "n": "CASE"}),
		headerData:  []byte("not a header"),
		mediaSize:   ptrU64(0),
		sectorsData: storedChunk(nil),
	})
	img := mustOpen(t, image)
	info := img.Info()
	if info.Header.CaseNumber != "" {
		t.Fatalf("malformed header produced case %q", info.Header.CaseNumber)
	}
	found := false
	for _, warning := range info.Warnings {
		if strings.Contains(warning, "header") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v", info.Warnings)
	}
}

func TestSourceAndSubjectMetadata(t *testing.T) {
	sources := []map[string]string{
		{"id": "0"},
		{
			"id": "1", "n": "Drive C", "ev": "EVID-7", "loc": "Lab", "gu": "aabb",
			"pgu": "ccdd", "dt": "3", "mfr": "ACME", "mo": "Model X", "se": "SN123",
			"do": "corp.example", "ip": "10.0.0.1", "ma": "001122334455",
			"tb": "4096", "lo": "0", "po": "512", "aq": "1600000000",
			"ah": strings.Repeat("a", 32), "sh": strings.Repeat("b", 40),
		},
	}
	subjects := []map[string]string{
		{"id": "0"},
		{"id": "1", "n": "Subject One"},
	}
	image := buildImage(t, imageOptions{
		root:        newNode(map[string]string{"id": "1", "p": "1", "n": "CASE"}),
		sources:     sources,
		subjects:    subjects,
		mediaSize:   ptrU64(0),
		sectorsData: storedChunk(nil),
	})
	img := mustOpen(t, image)
	info := img.Info()
	if len(info.Sources) != 2 {
		t.Fatalf("sources = %d", len(info.Sources))
	}
	rootSource := info.Sources[0]
	if rootSource.Identifier == nil || *rootSource.Identifier != 0 {
		t.Fatalf("root source = %+v", rootSource)
	}
	drive := info.Sources[1]
	if drive.Name != "Drive C" || drive.EvidenceNumber != "EVID-7" || drive.Location != "Lab" ||
		drive.DeviceGUID != "aabb" || drive.PrimaryDeviceGUID != "ccdd" || drive.DriveType != "3" ||
		drive.Manufacturer != "ACME" || drive.Model != "Model X" || drive.SerialNumber != "SN123" ||
		drive.Domain != "corp.example" || drive.IPAddress != "10.0.0.1" ||
		drive.MACAddress != "001122334455" || drive.MD5 != strings.Repeat("a", 32) ||
		drive.SHA1 != strings.Repeat("b", 40) {
		t.Fatalf("drive source = %+v", drive)
	}
	if drive.Size == nil || *drive.Size != 4096 || drive.AcquisitionTime == nil ||
		*drive.AcquisitionTime != 1600000000 {
		t.Fatalf("drive numeric fields = %+v", drive)
	}
	if len(info.Subjects) != 2 || info.Subjects[1].Name != "Subject One" ||
		info.Subjects[1].Identifier == nil || *info.Subjects[1].Identifier != 1 {
		t.Fatalf("subjects = %+v", info.Subjects)
	}
	// No header section in this image, so the evidence number comes from srce.ev.
	if info.EvidenceNumber != "EVID-7" {
		t.Fatalf("evidence number fallback = %q", info.EvidenceNumber)
	}
}

func TestMultiSegmentSetIsOrderedByNumber(t *testing.T) {
	content := bytes.Repeat([]byte{'A'}, 2048)
	content = append(content, []byte("world")...)

	first := buildImage(t, imageOptions{
		number:       1,
		terminal:     "next",
		omitLTree:    true,
		chunkSectors: 4,
		sectorsData:  storedChunk(content[:2048]),
	})
	second := buildImage(t, imageOptions{
		number:       2,
		omitVolume:   true,
		chunkSectors: 4,
		root:         newNode(map[string]string{"id": "2", "p": "0", "n": "split.bin", "ls": "2053", "du": "0"}),
		mediaSize:    ptrU64(uint64(len(content))),
		sectorsData:  storedChunk(content[2048:]),
	})
	img, err := OpenSegments([]source.ByteSource{
		source.NewMemorySource(22, second),
		source.NewMemorySource(11, first),
	})
	if err != nil {
		t.Fatalf("OpenSegments: %v", err)
	}
	info := img.Info()
	if info.Segments != 2 || len(info.SegmentNumbers) != 2 ||
		info.SegmentNumbers[0] != 1 || info.SegmentNumbers[1] != 2 {
		t.Fatalf("segments = %d %v", info.Segments, info.SegmentNumbers)
	}
	if info.Chunks != 2 || !info.ChunkSizeSet || info.ChunkSize != 4*512 ||
		!info.LogicalSizeSet || info.LogicalSize != uint64(len(content)) {
		t.Fatalf("info = %+v", info)
	}
	stream, err := img.OpenFile("/split.bin", 3)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got := make([]byte, len(content))
	if _, err := stream.ReadAt(0, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: %d bytes", len(got))
	}

	// A set missing segment 1 is refused.
	if _, err := OpenSegments([]source.ByteSource{
		source.NewMemorySource(1, second),
	}); !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "incomplete or misnumbered") {
		t.Fatalf("misnumbered set error = %v", err)
	}
	if _, err := OpenSegments(nil); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("empty set error = %v", err)
	}
}

func TestTableWithoutSectorsIsRefused(t *testing.T) {
	badBase := uint64(1 << 30)
	image := buildImage(t, imageOptions{
		root:        newNode(map[string]string{"id": "1", "p": "1", "n": "ROOT"}),
		mediaSize:   ptrU64(0),
		sectorsData: storedChunk(nil),
		tableBase:   &badBase,
	})
	_, err := Open(source.NewMemorySource(1, image))
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "not inside a sectors section") {
		t.Fatalf("error = %v", err)
	}
}

func TestMissingChunkTableWarnsAndReadFails(t *testing.T) {
	image := buildImage(t, imageOptions{
		root:        newNode(map[string]string{"id": "2", "p": "0", "n": "f.bin", "ls": "1", "du": "0"}),
		mediaSize:   ptrU64(1),
		sectorsData: storedChunk([]byte("A")),
		omitTable:   true,
	})
	img := mustOpen(t, image)
	info := img.Info()
	if info.Chunks != 0 {
		t.Fatalf("chunks = %d", info.Chunks)
	}
	found := false
	for _, warning := range info.Warnings {
		if strings.Contains(warning, "no table") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v", info.Warnings)
	}
	stream, err := img.OpenFile("/f.bin", 1)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := stream.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("read error = %v", err)
	}
}

func TestSiblingSegmentFileName(t *testing.T) {
	cases := []struct {
		first  string
		number uint32
		want   string
		ok     bool
	}{
		{"case.L01", 2, "case.L02", true},
		{`C:\Evidence\CASE.l01`, 3, `C:\Evidence\CASE.l03`, true},
		{"case.L1", 12, "case.L12", true},
		{"case.L099", 100, "case.L100", true},
		{"case.Lx01", 2, "", false},
		{"case.E01", 2, "", false},
		{"case.L01.bak", 2, "", false},
		{"case.L0A", 2, "", false},
		{"case.L", 2, "", false},
		{"case.L01", 0, "", false},
	}
	for _, test := range cases {
		got, ok := SiblingSegmentFileName(test.first, test.number)
		if ok != test.ok || got != test.want {
			t.Fatalf("SiblingSegmentFileName(%q, %d) = %q, %v; want %q, %v",
				test.first, test.number, got, ok, test.want, test.ok)
		}
	}
}

func TestMatchesSignature(t *testing.T) {
	if !MatchesSignature([]byte(Signature)) {
		t.Fatal("LVF signature not matched")
	}
	if MatchesSignature([]byte("LVF")) || MatchesSignature([]byte(LEF2Signature)) {
		t.Fatal("unexpected signature match")
	}
}

func TestEntrySourceTranslation(t *testing.T) {
	content := []byte("ABCDEFGH")
	root := newNode(map[string]string{"id": "2", "p": "0", "n": "x.bin", "ls": "8",
		"be": "2 0 4 S 4 4"})
	image := buildImage(t, imageOptions{
		root:        root,
		mediaSize:   ptrU64(uint64(len(content))),
		sectorsData: storedChunk(content),
	})
	img := mustOpen(t, image)
	stream, err := img.OpenFile("/x.bin", 5)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	ranges, err := stream.Extents(0, 8)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 2 || ranges[0].Kind != source.RangeData || ranges[1].Kind != source.RangeZero {
		t.Fatalf("extents = %+v", ranges)
	}
	imageRanges, err := stream.MapToImage(0, 8)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(imageRanges) != 2 || imageRanges[0].Kind != source.RangeData ||
		imageRanges[1].Kind != source.RangeZero {
		t.Fatalf("image ranges = %+v", imageRanges)
	}
}

func TestReadEntryDataRejectsBadArguments(t *testing.T) {
	content := []byte("A")
	root := newNode(
		map[string]string{"id": "1", "p": "1", "n": "ROOT"},
		newNode(map[string]string{"id": "2", "p": "0", "n": "nosize.bin"}),
		newNode(map[string]string{"id": "3", "p": "0", "n": "nodata.bin", "ls": "4"}),
	)
	image := buildImage(t, imageOptions{
		root:        root,
		mediaSize:   ptrU64(uint64(len(content))),
		sectorsData: storedChunk(content),
	})
	img := mustOpen(t, image)

	if _, err := img.ReadEntryData(99); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("bad index error = %v", err)
	}
	if _, err := img.OpenFile("/ROOT/nosize.bin", 1); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("no size error = %v", err)
	}
	if _, err := img.OpenFile("/ROOT/nodata.bin", 1); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("no data error = %v", err)
	}
}

func TestDeletedEntryFlag(t *testing.T) {
	root := newNode(map[string]string{"id": "1", "p": "1", "n": "CASE"},
		newNode(map[string]string{"id": "2", "p": "0", "n": "gone.txt", "ls": "0", "dl": "1142163845"}),
	)
	image := buildImage(t, imageOptions{
		root:        root,
		mediaSize:   ptrU64(0),
		sectorsData: storedChunk(nil),
	})
	img := mustOpen(t, image)
	info := img.Info()
	if info.DeletedEntries != 1 {
		t.Fatalf("deleted count = %d", info.DeletedEntries)
	}
	entries, err := img.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if !entries[1].Deleted() || entries[1].DeletionTime == nil || *entries[1].DeletionTime != 1142163845 {
		t.Fatalf("deleted entry = %+v", entries[1])
	}
	deleted := img.DeletedEntries()
	if len(deleted) != 1 || deleted[0].Name != "gone.txt" {
		t.Fatalf("DeletedEntries = %+v", deleted)
	}
}

func TestFormatSignatureConstants(t *testing.T) {
	if len(Signature) != 8 {
		t.Fatalf("signature length = %d", len(Signature))
	}
	if FileHeaderBytes != 13 || SectionDescriptorBytes != 76 || LTreeHeaderBytes != 48 {
		t.Fatalf("layout constants = %d/%d/%d", FileHeaderBytes, SectionDescriptorBytes, LTreeHeaderBytes)
	}
	if SparseFlag != 0x04000000 || FolderFlag != 0x02000000 {
		t.Fatalf("flags = %#x/%#x", SparseFlag, FolderFlag)
	}
}
