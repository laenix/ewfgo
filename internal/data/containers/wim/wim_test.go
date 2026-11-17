package wim

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testChunk  = 32 * 1024
	testMTime  = uint64(133_000_000_000_000_000)
	testRootID = source.ID(1)
	testImage  = source.ImageID(9)
)

// ---------------------------------------------------------------------------
// A hermetic WIM fixture writer.
// ---------------------------------------------------------------------------

type testStream struct {
	name string
	data []byte
}

type testNode struct {
	dir      bool
	name     string
	short    *string
	data     []byte
	modified uint64
	stream   *testStream
	children []testNode
}

func testFile(name string, data []byte) testNode {
	return testNode{name: name, data: data, modified: testMTime}
}

func testFileWithStream(name string, data []byte, stream string, streamData []byte) testNode {
	short := "NOTES~1.TXT"
	return testNode{
		name: name, data: data, modified: testMTime, short: &short,
		stream: &testStream{name: stream, data: streamData},
	}
}

func testDir(name string, children ...testNode) testNode {
	return testNode{dir: true, name: name, modified: testMTime, children: children}
}

func testTree() []testNode {
	return []testNode{
		testFile("notes.txt", []byte("hello wim\n")),
		testFile("empty.txt", nil),
		testDir("Windows",
			testDir("System32", testFile("kernel32.dll", []byte("kernel bytes"))),
			testFile("readme.txt", []byte("read me")),
		),
	}
}

func testSHA1(data []byte) [20]byte {
	return sha1.Sum(data)
}

func align8(v uint64) uint64 { return (v + 7) &^ 7 }

func putU16(b []byte, at int, v uint16) {
	b[at], b[at+1] = byte(v), byte(v>>8)
}

func putU32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putU64(b []byte, at int, v uint64) {
	putU32(b, at, uint32(v))
	putU32(b, at+4, uint32(v>>32))
}

func utf16LE(text string) []byte {
	out := make([]byte, 0, len(text)*2)
	for _, unit := range []rune(text) {
		if unit <= 0xFFFF {
			out = append(out, byte(unit), byte(unit>>8))
			continue
		}
		unit -= 0x10000
		hi := uint16(0xD800 + (unit >> 10))
		lo := uint16(0xDC00 + (unit & 0x3FF))
		out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
	}
	return out
}

// literalXpress emits one XPRESS Huffman block with an all-literal table.
// The bit packing follows [MS-XCA] 2.2.4: 16-bit little-endian words read
// most-significant bit first.
func literalXpress(data []byte) []byte {
	out := make([]byte, 256)
	for i := 0; i < 128; i++ {
		out[i] = 0x88
	}
	bits := make([]bool, 0, len(data)*8+16)
	for _, byteValue := range data {
		for index := 7; index >= 0; index-- {
			bits = append(bits, (byteValue>>uint(index))&1 == 1)
		}
	}
	for len(bits)%16 != 0 {
		bits = append(bits, false)
	}
	words := make([]byte, len(bits)/8)
	for index, bit := range bits {
		if !bit {
			continue
		}
		word := index / 16
		within := 15 - (index % 16)
		at := word * 2
		if within >= 8 {
			at++
		}
		words[at] |= 1 << uint(within%8)
	}
	return append(out, words...)
}

func compressChunks(kind string, data []byte, chunk int) []byte {
	var chunks [][]byte
	for start := 0; start < len(data); start += chunk {
		end := start + chunk
		if end > len(data) {
			end = len(data)
		}
		switch kind {
		case "xpress":
			chunks = append(chunks, literalXpress(data[start:end]))
		case "lzx":
			chunks = append(chunks, lzxLiteralChunk(data[start:end]))
		default:
			panic("unknown compression " + kind)
		}
	}
	return joinChunks(chunks, chunk)
}

func joinChunks(chunks [][]byte, chunk int) []byte {
	var stored []byte
	if len(chunks) > 1 {
		running := uint64((len(chunks) - 1) * 4)
		table := make([]byte, 0, int(running))
		for _, part := range chunks[:len(chunks)-1] {
			running += uint64(len(part))
			var entry [4]byte
			putU32(entry[:], 0, uint32(running))
			table = append(table, entry[:]...)
		}
		stored = append(stored, table...)
	}
	for _, part := range chunks {
		stored = append(stored, part...)
	}
	return stored
}

func testStreamRecord(stream *testStream) []byte {
	units := utf16LE(stream.name)
	length := align8(uint64(StreamEntryBytes) + uint64(len(units)))
	record := make([]byte, length)
	putU64(record, 0, length)
	sum := testSHA1(stream.data)
	copy(record[16:36], sum[:])
	putU16(record, 36, uint16(len(units)))
	copy(record[StreamEntryBytes:], units)
	return record
}

func testEncodeDentry(name string, short *string, attributes uint32, subdir uint64,
	sha1Sum [20]byte, modified uint64, streams []*testStream) []byte {
	nameUnits := utf16LE(name)
	var shortUnits []byte
	if short != nil {
		shortUnits = utf16LE(*short)
	}
	var streamBytes []byte
	for _, stream := range streams {
		streamBytes = append(streamBytes, testStreamRecord(stream)...)
	}
	total := DirectoryEntryBytes + len(nameUnits) + len(shortUnits) + len(streamBytes)
	length := align8(uint64(total))
	record := make([]byte, length)
	putU64(record, 0, length)
	putU32(record, 8, attributes)
	putU32(record, 12, 0xFFFFFFFF)
	putU64(record, 16, subdir)
	putU64(record, 56, modified)
	copy(record[64:84], sha1Sum[:])
	putU16(record, 96, uint16(len(streams)))
	putU16(record, 98, uint16(len(shortUnits)))
	putU16(record, 100, uint16(len(nameUnits)))
	at := DirectoryEntryBytes
	copy(record[at:], nameUnits)
	at += len(nameUnits)
	copy(record[at:], shortUnits)
	at += len(shortUnits)
	copy(record[at:], streamBytes)
	return record
}

func testFileDentry(node testNode) []byte {
	var sum [20]byte
	if len(node.data) != 0 {
		sum = testSHA1(node.data)
	}
	var streams []*testStream
	if node.stream != nil {
		streams = append(streams, node.stream)
	}
	return testEncodeDentry(node.name, node.short, 0x80, 0, sum, node.modified, streams)
}

func testDirDentry(node testNode, subdir uint64) []byte {
	return testEncodeDentry(node.name, nil, AttributeDirectory, subdir, [20]byte{}, node.modified, nil)
}

func testNodeLen(node testNode) uint64 {
	if node.dir {
		return uint64(len(testDirDentry(node, 0)))
	}
	return uint64(len(testFileDentry(node)))
}

func testListLen(children []testNode) uint64 {
	var total uint64 = 8
	for _, child := range children {
		total += testNodeLen(child)
	}
	return total
}

func testLayout(children []testNode, securityLen uint64) (map[string]uint64, uint64) {
	rootList := securityLen + align8(uint64(DirectoryEntryBytes))
	offsets := map[string]uint64{"": rootList}
	var assign func(children []testNode, base string, cursor *uint64)
	assign = func(children []testNode, base string, cursor *uint64) {
		*cursor += testListLen(children)
		for index, child := range children {
			if !child.dir {
				continue
			}
			key := fmt.Sprintf("%s/%d", base, index)
			offsets[key] = *cursor
			assign(child.children, key, cursor)
		}
	}
	cursor := rootList
	assign(children, "", &cursor)
	return offsets, rootList
}

func testEncodeList(children []testNode, base string, offsets map[string]uint64) []byte {
	var out []byte
	for index, child := range children {
		if child.dir {
			out = append(out, testDirDentry(child, offsets[fmt.Sprintf("%s/%d", base, index)])...)
		} else {
			out = append(out, testFileDentry(child)...)
		}
	}
	out = append(out, make([]byte, 8)...)
	return out
}

func testGatherLists(children []testNode, base string, offsets map[string]uint64, out *[]struct {
	offset uint64
	bytes  []byte
}) {
	*out = append(*out, struct {
		offset uint64
		bytes  []byte
	}{offsets[base], testEncodeList(children, base, offsets)})
	for index, child := range children {
		if child.dir {
			testGatherLists(child.children, fmt.Sprintf("%s/%d", base, index), offsets, out)
		}
	}
}

func testSecurityBlock() []byte {
	descriptor := []byte("fixture-security-descriptor")
	total := uint64(16 + len(descriptor))
	block := make([]byte, align8(total))
	putU32(block, 0, uint32(total))
	putU32(block, 4, 1)
	putU64(block, 8, uint64(len(descriptor)))
	copy(block[16:], descriptor)
	return block
}

type testBlob struct {
	sha1 [20]byte
	data []byte
	refs uint32
}

func testAddBlob(blobs *[]testBlob, data []byte) {
	if len(data) == 0 {
		return
	}
	sum := testSHA1(data)
	for index := range *blobs {
		if (*blobs)[index].sha1 == sum {
			(*blobs)[index].refs++
			return
		}
	}
	*blobs = append(*blobs, testBlob{sha1: sum, data: data, refs: 1})
}

func testCollectBlobs(children []testNode, blobs *[]testBlob) {
	for _, child := range children {
		if child.dir {
			testCollectBlobs(child.children, blobs)
			continue
		}
		testAddBlob(blobs, child.data)
		if child.stream != nil {
			testAddBlob(blobs, child.stream.data)
		}
	}
}

func testCounts(children []testNode) (dirs, files, bytesTotal uint64) {
	for _, child := range children {
		if child.dir {
			dirs++
			d, f, b := testCounts(child.children)
			dirs += d
			files += f
			bytesTotal += b
			continue
		}
		files++
		bytesTotal += uint64(len(child.data))
	}
	return
}

func testXMLText(children []testNode) string {
	dirs, files, bytesTotal := testCounts(children)
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>`+"\r\n"+
		`<WIM>`+"\r\n"+
		`<TOTALBYTES>%d</TOTALBYTES>`+"\r\n"+
		`<IMAGE INDEX="1">`+"\r\n"+
		`<DIRCOUNT>%d</DIRCOUNT>`+"\r\n"+
		`<FILECOUNT>%d</FILECOUNT>`+"\r\n"+
		`<TOTALBYTES>%d</TOTALBYTES>`+"\r\n"+
		`<HARDLINKBYTES>0</HARDLINKBYTES>`+"\r\n"+
		`<NAME>Fixture Image</NAME>`+"\r\n"+
		`<DESCRIPTION>synthetic WIM</DESCRIPTION>`+"\r\n"+
		`<FLAGS>0</FLAGS>`+"\r\n"+
		`<WINDOWS><ARCH>9</ARCH><PRODUCTNAME>Fixture Windows</PRODUCTNAME>`+
		`<EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE>`+
		`<PRODUCTTYPE>WinNT</PRODUCTTYPE><SUITEMASK>0</SUITEMASK>`+
		`<LANGUAGES>en-US</LANGUAGES><SYSTEMROOT>WINDOWS</SYSTEMROOT></WINDOWS>`+"\r\n"+
		`</IMAGE>`+"\r\n"+
		`</WIM>`, bytesTotal, dirs, files, bytesTotal)
}

type testResource struct {
	compressedSize uint64
	offset         uint64
	originalSize   uint64
	flags          uint8
}

type wimSpec struct {
	tree    []testNode
	kind    string // "none", "xpress", "lzx"
	xmlMode string // "", "utf8", "utf16be"
	packed  bool
}

type wimParts struct {
	file         []byte
	metadata     []byte
	metadataSHA1 [20]byte
	security     uint64
	rootList     uint64
	metadataAt   uint64
}

func appendTestResource(out *[]byte, data []byte, flags uint8, kind string, chunk int) testResource {
	for len(*out)%8 != 0 {
		*out = append(*out, 0)
	}
	stored := data
	if flags&ResourceCompressed != 0 {
		stored = compressChunks(kind, data, chunk)
	}
	resource := testResource{
		compressedSize: uint64(len(stored)),
		offset:         uint64(len(*out)),
		originalSize:   uint64(len(data)),
		flags:          flags,
	}
	*out = append(*out, stored...)
	return resource
}

func writeTestResourceHeader(out []byte, at int, resource testResource) {
	raw := uint64(resource.flags)<<56 | (resource.compressedSize & 0x00FFFFFFFFFFFFFF)
	putU64(out, at, raw)
	putU64(out, at+8, resource.offset)
	putU64(out, at+16, resource.originalSize)
}

func buildWIM(t *testing.T, spec wimSpec) wimParts {
	t.Helper()
	if spec.kind == "" {
		spec.kind = "none"
	}
	security := testSecurityBlock()
	securityLen := uint64(len(security))
	rootLen := align8(uint64(DirectoryEntryBytes))
	rootList := securityLen + rootLen
	offsets, _ := testLayout(spec.tree, securityLen)

	metadata := append([]byte(nil), security...)
	root := testEncodeDentry("", nil, AttributeDirectory, rootList, [20]byte{}, testMTime, nil)
	root = append(root, make([]byte, int(rootLen)-len(root))...)
	metadata = append(metadata, root...)
	if uint64(len(metadata)) != rootList {
		t.Fatalf("fixture root list = %d, want %d", len(metadata), rootList)
	}
	var lists []struct {
		offset uint64
		bytes  []byte
	}
	testGatherLists(spec.tree, "", offsets, &lists)
	for _, list := range lists {
		if list.offset != uint64(len(metadata)) {
			t.Fatalf("fixture list order: offset %d, len %d", list.offset, len(metadata))
		}
		metadata = append(metadata, list.bytes...)
	}

	var blobs []testBlob
	testCollectBlobs(spec.tree, &blobs)
	xmlText := testXMLText(spec.tree)
	var xml []byte
	switch spec.xmlMode {
	case "utf8":
		xml = []byte(xmlText)
	case "utf16be":
		xml = []byte{0xFE, 0xFF}
		units := utf16LE(xmlText)
		for index := 0; index < len(units); index += 2 {
			xml = append(xml, units[index+1], units[index])
		}
	default:
		xml = utf16LE(xmlText)
	}

	out := make([]byte, HeaderBytes)
	copy(out[:len(Signature)], Signature)
	compressMetadata := spec.kind == "xpress"
	var metadataFlags uint8 = ResourceMetadata
	if compressMetadata {
		metadataFlags |= ResourceCompressed
	}
	metadataResource := appendTestResource(&out, metadata, metadataFlags, spec.kind, testChunk)
	metadataAt := metadataResource.offset

	blobFlags := uint8(0)
	if spec.kind != "none" {
		blobFlags |= ResourceCompressed
	}
	blobResources := make([]testResource, len(blobs))
	for index, blob := range blobs {
		blobResources[index] = appendTestResource(&out, blob.data, blobFlags, spec.kind, testChunk)
	}
	xmlFlags := uint8(0)
	if compressMetadata {
		xmlFlags |= ResourceCompressed
	}
	xmlResource := appendTestResource(&out, xml, xmlFlags, spec.kind, testChunk)

	type lookupRecord struct {
		resource testResource
		sha1     [20]byte
		refs     uint32
	}
	lookup := make([]lookupRecord, 0, len(blobs)+1)
	for index, blob := range blobs {
		lookup = append(lookup, lookupRecord{blobResources[index], blob.sha1, blob.refs})
	}
	lookup = append(lookup, lookupRecord{metadataResource, testSHA1(metadata), 1})
	sort.Slice(lookup, func(i, j int) bool {
		return bytes.Compare(lookup[i].sha1[:], lookup[j].sha1[:]) < 0
	})
	var lookupBytes []byte
	for _, record := range lookup {
		entry := make([]byte, LookupEntryBytes)
		writeTestResourceHeader(entry, 0, record.resource)
		putU32(entry, 24, 1)
		putU32(entry, 28, record.refs)
		copy(entry[32:52], record.sha1[:])
		lookupBytes = append(lookupBytes, entry...)
	}
	lookupResource := appendTestResource(&out, lookupBytes, 0, "none", testChunk)

	putU32(out, 0x08, HeaderBytes)
	putU32(out, 0x0C, Version1_13)
	var flags uint32
	switch spec.kind {
	case "xpress":
		flags = FlagCompression | FlagXpress
	case "lzx":
		flags = FlagCompression | FlagLzx
	}
	putU32(out, 0x10, flags)
	if spec.kind != "none" {
		putU32(out, 0x14, testChunk)
	}
	putU16(out, 0x28, 1)
	putU16(out, 0x2A, 1)
	putU32(out, 0x2C, 1)
	writeTestResourceHeader(out, 0x30, lookupResource)
	writeTestResourceHeader(out, 0x48, xmlResource)
	putU32(out, 0x78, 1)

	return wimParts{
		file:         out,
		metadata:     metadata,
		metadataSHA1: testSHA1(metadata),
		security:     securityLen,
		rootList:     rootList,
		metadataAt:   metadataAt,
	}
}

func openTestWIM(t *testing.T, file []byte) *Container {
	t.Helper()
	container, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return container
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	if src.Len() == 0 {
		return nil
	}
	data, err := source.ReadVecAt(src, 0, src.Len())
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	return data
}

func findLookupBytes(t *testing.T, file []byte, sum [20]byte) int {
	t.Helper()
	offset := int(testLE64(file, 0x38))
	size := int(testLE64(file, 0x40))
	for at := offset; at < offset+size; at += LookupEntryBytes {
		if bytes.Equal(file[at+32:at+52], sum[:]) {
			return at
		}
	}
	t.Fatalf("lookup entry for %x not found", sum)
	return -1
}

func testLE64(b []byte, at int) uint64 {
	return uint64(b[at]) | uint64(b[at+1])<<8 | uint64(b[at+2])<<16 | uint64(b[at+3])<<24 |
		uint64(b[at+4])<<32 | uint64(b[at+5])<<40 | uint64(b[at+6])<<48 | uint64(b[at+7])<<56
}

func patch32(file []byte, at int, v uint32) []byte {
	out := append([]byte(nil), file...)
	putU32(out, at, v)
	return out
}

func patch16(file []byte, at int, v uint16) []byte {
	out := append([]byte(nil), file...)
	putU16(out, at, v)
	return out
}

func patch64(file []byte, at int, v uint64) []byte {
	out := append([]byte(nil), file...)
	putU64(out, at, v)
	return out
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

func TestWIMDetect(t *testing.T) {
	if !Detect([]byte("MSWIM\x00\x00\x00rest")) {
		t.Fatal("Detect rejected the WIM signature")
	}
	for _, head := range [][]byte{nil, []byte("MSWI"), []byte("MSWIM\x00\x00\x01"), []byte("NOPE")} {
		if Detect(head) {
			t.Fatalf("Detect accepted %q", head)
		}
	}
}

func TestWIMHeaderAndBlobTable(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress"})
	container := openTestWIM(t, parts.file)
	if !Detect(parts.file) {
		t.Fatal("Detect rejected a built WIM")
	}
	info := container.Info()
	if info.Version != Version1_13 || info.Compression != Xpress ||
		info.ChunkSize != testChunk || info.ImageCount != 1 {
		t.Fatalf("info = %+v", info)
	}
	if info.PartNumber != 1 || info.TotalParts != 1 || info.BootIndex != 1 {
		t.Fatalf("part/boot = %+v", info)
	}
	if len(container.Images()) != 1 {
		t.Fatalf("images = %d", len(container.Images()))
	}
	stats := container.WIMStats()
	if stats.Files != 4 || stats.Directories != 2 || stats.SecurityDescriptors != 1 ||
		stats.LookupEntries != 4 || stats.UnresolvedHashes != 0 || stats.PackedResources != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	image := container.Images()[0]
	if image.Index != 1 || image.Name == nil || *image.Name != "Fixture Image" {
		t.Fatalf("image = %+v", image)
	}
	if image.Description == nil || *image.Description != "synthetic WIM" {
		t.Fatalf("description = %+v", image.Description)
	}
	if image.DeclaredFiles == nil || *image.DeclaredFiles != 4 ||
		image.DeclaredDirectories == nil || *image.DeclaredDirectories != 2 {
		t.Fatalf("declared = %+v", image)
	}
	if image.Windows == nil || image.Windows.EditionID == nil || *image.Windows.EditionID != "Professional" ||
		image.Windows.ProductName == nil || *image.Windows.ProductName != "Fixture Windows" {
		t.Fatalf("windows = %+v", image.Windows)
	}
	if image.SecurityDescriptorCount != 1 {
		t.Fatalf("security descriptors = %d", image.SecurityDescriptorCount)
	}
}

func TestWIMDirectoryTree(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress"})
	image := openTestWIM(t, parts.file).Images()[0]
	paths := make([]string, len(image.Entries))
	for index, entry := range image.Entries {
		paths[index] = entry.Path
	}
	want := []string{
		"notes.txt", "empty.txt", "Windows",
		"Windows/System32", "Windows/System32/kernel32.dll", "Windows/readme.txt",
	}
	if fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	notes := image.Entries[0]
	if notes.Size != 10 || !notes.Resolved || notes.Resource == nil {
		t.Fatalf("notes = %+v", notes)
	}
	if seconds, ok := notes.ModifiedUnix(); !ok || seconds != 1_655_526_400 {
		t.Fatalf("notes mtime = %d, %v", seconds, ok)
	}
	empty := image.Entries[1]
	if empty.Size != 0 || !empty.Resolved {
		t.Fatalf("empty = %+v", empty)
	}
	kernel := image.Entries[4]
	if kernel.Size != uint64(len("kernel bytes")) {
		t.Fatalf("kernel size = %d", kernel.Size)
	}
	for _, entry := range image.Entries {
		if entry.Attributes&AttributeDirectory != 0 && !entry.IsDirectory() {
			t.Fatalf("%s IsDirectory = false", entry.Path)
		}
	}
}

func TestWIMFileContentsXpress(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress"})
	container := openTestWIM(t, parts.file)
	entry, err := container.OpenEntry(1, "Windows/System32/kernel32.dll")
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	if got := string(readAll(t, entry)); got != "kernel bytes" {
		t.Fatalf("contents = %q", got)
	}
	if entry.Stats().DecompressedBytes != uint64(len("kernel bytes")) {
		t.Fatalf("decompressed = %d", entry.Stats().DecompressedBytes)
	}
}

func TestWIMMultiChunkFile(t *testing.T) {
	data := make([]byte, testChunk*2+17)
	for index := range data {
		data[index] = byte(index % 251)
	}
	parts := buildWIM(t, wimSpec{tree: []testNode{testFile("big.bin", data)}, kind: "xpress"})
	container := openTestWIM(t, parts.file)
	entry, err := container.OpenEntry(1, "big.bin")
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	if got := readAll(t, entry); !bytes.Equal(got, data) {
		t.Fatal("multi-chunk contents differ")
	}
	window := make([]byte, 64)
	if _, err := entry.ReadAt(testChunk-32, window); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(window, data[testChunk-32:testChunk+32]) {
		t.Fatal("read across a chunk boundary differs")
	}
	if entry.Stats().CacheMisses < 3 {
		t.Fatalf("cache misses = %d", entry.Stats().CacheMisses)
	}
}

func TestWIMCorruptHuffmanChunk(t *testing.T) {
	data := make([]byte, testChunk*2+17)
	for index := range data {
		data[index] = byte(index % 251)
	}
	parts := buildWIM(t, wimSpec{tree: []testNode{testFile("big.bin", data)}, kind: "xpress"})
	at := findLookupBytes(t, parts.file, testSHA1(data))
	resourceOffset := int(testLE64(parts.file, at+8))
	firstChunk := resourceOffset + 2*4
	for index := 0; index < 256; index++ {
		parts.file[firstChunk+index] = 0xFF
	}
	container, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, parts.file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	entry, err := container.OpenEntry(1, "big.bin")
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	_, err = entry.ReadAt(0, make([]byte, 16))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("does not inflate")) {
		t.Fatalf("error = %v, want inflate failure", err)
	}
}

func TestWIMPlainXpressStreamRejected(t *testing.T) {
	expected := []byte("hello wim\n")
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress"})
	at := findLookupBytes(t, parts.file, testSHA1(expected))
	resourceOffset := int(testLE64(parts.file, at+8))
	// A plain LZ77 Xpress stream is not Xpress Huffman: zero the Huffman table
	// and put a short plain stream in front of the chunk.
	for index := 0; index < 256; index++ {
		parts.file[resourceOffset+index] = 0
	}
	plain := []byte{0x04, 0, 0, 0}
	plain = append(plain, expected...)
	copy(parts.file[resourceOffset:], plain)

	container, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, parts.file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	entry, err := container.OpenEntry(1, "notes.txt")
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	_, err = entry.ReadAt(0, make([]byte, 10))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestWIMChunkTableInvalid(t *testing.T) {
	data := make([]byte, testChunk*2+17)
	for index := range data {
		data[index] = byte(index % 251)
	}
	parts := buildWIM(t, wimSpec{tree: []testNode{testFile("big.bin", data)}, kind: "xpress"})
	at := findLookupBytes(t, parts.file, testSHA1(data))
	resource := testLE64(parts.file, at+8)
	tableBytes := uint32(2 * 4)

	empty := patch32(parts.file, int(resource), tableBytes)
	container, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, empty))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if _, err := container.OpenEntry(1, "big.bin"); err == nil {
		t.Fatal("an empty chunk must not open")
	} else if !bytes.Contains([]byte(err.Error()), []byte("is empty")) {
		t.Fatalf("error = %v", err)
	}

	outside := patch32(parts.file, int(resource), 0xFFFFFFFF)
	container, err = Open(source.NewMemorySourceWithImage(testRootID, testImage, outside))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if _, err := container.OpenEntry(1, "big.bin"); err == nil {
		t.Fatal("an out-of-range chunk must not open")
	} else if !bytes.Contains([]byte(err.Error()), []byte("outside")) {
		t.Fatalf("error = %v", err)
	}
}

func TestWIMNamedStream(t *testing.T) {
	tree := []testNode{
		testFileWithStream("notes.txt", []byte("hello wim\n"), "Zone.Identifier",
			[]byte("[ZoneTransfer]\nZoneId=3\n")),
	}
	parts := buildWIM(t, wimSpec{tree: tree, kind: "xpress"})
	container := openTestWIM(t, parts.file)
	entry := container.Images()[0].Entries[0]
	if entry.ShortName == nil || *entry.ShortName != "NOTES~1.TXT" {
		t.Fatalf("short name = %+v", entry.ShortName)
	}
	if len(entry.Streams) != 1 || entry.Streams[0].Name != "Zone.Identifier" ||
		!entry.Streams[0].Resolved {
		t.Fatalf("streams = %+v", entry.Streams)
	}
	stream, err := container.OpenStream(1, "notes.txt", "Zone.Identifier")
	if err != nil {
		t.Fatalf("OpenStream error = %v", err)
	}
	if got := string(readAll(t, stream)); got != "[ZoneTransfer]\nZoneId=3\n" {
		t.Fatalf("stream contents = %q", got)
	}
}

func TestWIMUnresolvedHash(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	at := findLookupBytes(t, parts.file, testSHA1([]byte("hello wim\n")))
	for index := 0; index < 20; index++ {
		parts.file[at+32+index] = 0x5A
	}
	container := openTestWIM(t, parts.file)
	if container.WIMStats().UnresolvedHashes != 1 {
		t.Fatalf("unresolved = %d", container.WIMStats().UnresolvedHashes)
	}
	entry := container.Images()[0].Entries[0]
	if entry.Size != 0 || entry.Resolved || entry.Resource != nil {
		t.Fatalf("entry = %+v", entry)
	}
	_, err := container.OpenEntry(1, "notes.txt")
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("no blob")) {
		t.Fatalf("error = %v", err)
	}
}

func TestWIMUncompressed(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	container := openTestWIM(t, parts.file)
	if container.Info().Compression != None {
		t.Fatalf("compression = %v", container.Info().Compression)
	}
	entry, err := container.OpenEntry(1, "notes.txt")
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	if got := string(readAll(t, entry)); got != "hello wim\n" {
		t.Fatalf("contents = %q", got)
	}
	if entry.Stats().DecompressedBytes != 0 {
		t.Fatalf("decompressed = %d", entry.Stats().DecompressedBytes)
	}
	extents, err := entry.Extents(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].Len != 3 || extents[0].Kind != source.RangeData {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestWIMUnsupportedForms(t *testing.T) {
	base := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress"}).file

	cases := []struct {
		name string
		file []byte
		want error
		text string
	}{
		{"solid", patch32(base, 0x0C, VersionSolid), source.ErrUnsupported, "solid"},
		{"lzms", patch32(base, 0x10, FlagCompression|FlagLzms), source.ErrUnsupported, "LZMS"},
		{"unknown-algorithm", patch32(base, 0x10, FlagCompression), source.ErrUnsupported, "algorithm"},
		{"two-algorithms", patch32(base, 0x10, FlagCompression|FlagXpress|FlagLzx), source.ErrCorrupt, "more than one"},
		{"bare-algorithm", patch32(base, 0x10, FlagXpress), source.ErrCorrupt, "compression flag"},
		{"split", patch16(base, 0x2A, 2), source.ErrUnsupported, "split"},
		{"header-size", patch32(base, 0x08, 200), source.ErrUnsupported, "header"},
		{"version", patch32(base, 0x0C, 0x00010c00), source.ErrUnsupported, "version"},
		{"image-count", patch32(base, 0x2C, 2), source.ErrCorrupt, "declares 2"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, test.file))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(test.text)) {
				t.Fatalf("error = %v, want %q", err, test.text)
			}
		})
	}

	if _, err := Open(source.NewMemorySource(testRootID, []byte("MSWIM"))); !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("short header error = %v, want ErrUnexpectedEOF", err)
	}
	if _, err := Open(source.NewMemorySource(testRootID, make([]byte, HeaderBytes))); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("bad signature error = %v, want ErrUnsupported", err)
	}
}

func TestWIMLZXChunkSizeMustBeAPowerOfTwo(t *testing.T) {
	base := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress"}).file
	lzx := patch32(base, 0x10, FlagCompression|FlagLzx)
	lzx = patch32(lzx, 0x14, testChunk-512)
	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, lzx))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("power of two")) {
		t.Fatalf("error = %v", err)
	}
}

func TestWIMLookupPartNumber(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	at := findLookupBytes(t, parts.file, testSHA1([]byte("hello wim\n")))
	putU32(parts.file, at+24, 2)
	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, parts.file))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("part 2")) {
		t.Fatalf("error = %v", err)
	}
}

func TestWIMPackedResource(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	at := findLookupBytes(t, parts.file, testSHA1([]byte("hello wim\n")))
	parts.file[at+7] |= ResourcePacked
	container := openTestWIM(t, parts.file)
	if container.WIMStats().PackedResources != 1 {
		t.Fatalf("packed = %d", container.WIMStats().PackedResources)
	}
	_, err := container.OpenEntry(1, "notes.txt")
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("packed")) {
		t.Fatalf("error = %v", err)
	}
}

func TestWIMCycleIsCorrupt(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	// Find the Windows directory dentry in the root list: notes, empty,
	// Windows. Patch its subdir_offset to point back at the root list.
	notes := parseDentryForTest(t, parts.metadata, parts.rootList, false)
	empty := parseDentryForTest(t, parts.metadata, parts.rootList+notes.length, false)
	windowsAt := parts.rootList + notes.length + empty.length
	windows := parseDentryForTest(t, parts.metadata, windowsAt, false)
	if windows.name != "Windows" {
		t.Fatalf("third dentry = %q", windows.name)
	}
	putU64(parts.metadata, int(windowsAt)+16, parts.rootList)
	at := findLookupBytes(t, parts.file, parts.metadataSHA1)
	resourceOffset := testLE64(parts.file, at+8)
	resourceSize := testLE64(parts.file, at) & 0x00FFFFFFFFFFFFFF
	copy(parts.file[resourceOffset:resourceOffset+resourceSize], parts.metadata)

	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, parts.file))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("reached twice")) {
		t.Fatalf("error = %v", err)
	}
}

func TestWIMMetadataSeparatorIsCorrupt(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	notesAt := parts.rootList
	putU16(parts.metadata, int(notesAt)+DirectoryEntryBytes, '/')
	at := findLookupBytes(t, parts.file, parts.metadataSHA1)
	resourceOffset := testLE64(parts.file, at+8)
	resourceSize := testLE64(parts.file, at) & 0x00FFFFFFFFFFFFFF
	copy(parts.file[resourceOffset:resourceOffset+resourceSize], parts.metadata)

	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, parts.file))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("separator")) {
		t.Fatalf("error = %v", err)
	}
}

func TestWIMXMLEncodings(t *testing.T) {
	for _, mode := range []string{"utf8", "utf16be"} {
		t.Run(mode, func(t *testing.T) {
			parts := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress", xmlMode: mode})
			container := openTestWIM(t, parts.file)
			image := container.Images()[0]
			if image.Name == nil || *image.Name != "Fixture Image" {
				t.Fatalf("image = %+v", image)
			}
		})
	}
}

func TestWIMSecurityDataCorruption(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	at := findLookupBytes(t, parts.file, parts.metadataSHA1)
	resourceOffset := int(testLE64(parts.file, at+8))

	cases := []struct {
		name  string
		patch func([]byte)
		want  string
	}{
		{"size-table", func(file []byte) {
			putU32(file, resourceOffset, 8)
			putU32(file, resourceOffset+4, 2)
		}, "size table"},
		{"descriptors-fit", func(file []byte) { putU64(file, resourceOffset+8, 1000) }, "do not fit"},
		{"block-past-resource", func(file []byte) { putU32(file, resourceOffset, 10000) }, "metadata resource is"},
		{"too-many", func(file []byte) { putU32(file, resourceOffset+4, MaxSecurityEntries+1) }, "limit"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			file := append([]byte(nil), parts.file...)
			test.patch(file)
			_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
			if !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("error = %v, want ErrCorrupt", err)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(test.want)) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestWIMRootMustBeDirectory(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	putU32(parts.metadata, int(parts.security)+8, 0x80)
	at := findLookupBytes(t, parts.file, parts.metadataSHA1)
	resourceOffset := testLE64(parts.file, at+8)
	copy(parts.file[resourceOffset:], parts.metadata)
	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, parts.file))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not marked as a directory")) {
		t.Fatalf("error = %v", err)
	}
}

func TestWIMContainerSourceView(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "none"})
	container := openTestWIM(t, parts.file)
	if container.Len() != uint64(len(parts.file)) || container.SectorSize() != 512 ||
		container.ImageID() != testImage || container.IsEmpty() {
		t.Fatalf("source view = %d %d %d %v", container.Len(), container.SectorSize(),
			container.ImageID(), container.IsEmpty())
	}
	buf := make([]byte, 8)
	if _, err := container.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, parts.file[:8]) {
		t.Fatal("raw container view differs")
	}
	extents, err := container.Extents(0, 8)
	if err != nil || len(extents) != 1 || extents[0].Kind != source.RangeData {
		t.Fatalf("extents = %+v, %v", extents, err)
	}
	mapped, err := container.MapToImage(0, 8)
	if err != nil || len(mapped) != 1 || mapped[0].ImageID != testImage {
		t.Fatalf("mapped = %+v, %v", mapped, err)
	}
	if _, err := container.ReadAt(container.Len(), buf); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("past-end error = %v", err)
	}
}

// parseDentryForTest is a small independent reader used to locate fixture
// records; it deliberately does not call the parser under test.
type parsedDentryForTest struct {
	length uint64
	name   string
}

func parseDentryForTest(t *testing.T, metadata []byte, offset uint64, isRoot bool) parsedDentryForTest {
	t.Helper()
	length := testLE64(metadata, int(offset))
	nameBytes := int(metadata[offset+100]) | int(metadata[offset+101])<<8
	name := ""
	if nameBytes > 0 {
		units := make([]uint16, nameBytes/2)
		for index := range units {
			pos := int(offset) + DirectoryEntryBytes + index*2
			units[index] = uint16(metadata[pos]) | uint16(metadata[pos+1])<<8
		}
		name = string(runes(units))
	}
	if isRoot && name != "" {
		t.Fatalf("root has a name %q", name)
	}
	return parsedDentryForTest{length: length, name: name}
}

func runes(units []uint16) []rune {
	out := make([]rune, 0, len(units))
	for _, unit := range units {
		out = append(out, rune(unit))
	}
	return out
}
