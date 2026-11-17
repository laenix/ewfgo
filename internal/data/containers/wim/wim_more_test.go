package wim

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestWIMInfoFlagAccessors(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress"})
	head := append([]byte(nil), parts.file[:HeaderBytes]...)
	putU32(head, 0x10, FlagCompression|FlagXpress|FlagReadOnly|FlagResourceOnly|
		FlagMetadataOnly|FlagWriteInProgress|FlagRpFix)
	info, err := parseHeader(head, uint64(len(parts.file)))
	if err != nil {
		t.Fatalf("parseHeader error = %v", err)
	}
	if !info.IsReadOnly() || !info.IsResourceOnly() || !info.IsMetadataOnly() ||
		!info.IsWriteInProgress() || !info.IsReparseFixed() || info.IsSpanned() {
		t.Fatalf("flags = %+v", info)
	}
	if info.Compression.String() != "XPRESS Huffman" {
		t.Fatalf("compression label = %q", info.Compression.String())
	}
	if (Info{TotalParts: 2}).IsSpanned() != true {
		t.Fatal("a two-part header is not reported as spanned")
	}

	labels := map[Compression]string{
		None: "none", Xpress: "XPRESS Huffman", Lzx: "LZX", Lzms: "LZMS",
		Compression(99): "unknown",
	}
	for value, want := range labels {
		if got := value.String(); got != want {
			t.Fatalf("Compression(%d) = %q, want %q", value, got, want)
		}
	}
}

func TestWIMResourceAccessors(t *testing.T) {
	resource := Resource{
		CompressedSize: 1, Offset: 2, OriginalSize: 3,
		Flags: ResourceCompressed | ResourceMetadata | ResourceSpanned | ResourcePacked,
	}
	if !resource.IsCompressed() || !resource.IsMetadata() || !resource.IsSpanned() ||
		!resource.IsPacked() || resource.IsAbsent() {
		t.Fatalf("resource = %+v", resource)
	}
	if !(Resource{}).IsAbsent() {
		t.Fatal("the zero resource is not absent")
	}
}

func TestWIMXMLValidation(t *testing.T) {
	cases := []struct {
		name string
		xml  []byte
	}{
		{"empty", nil},
		{"odd-utf16", []byte{0xFF, 0xFE, 0x00}},
		{"unpaired-surrogate", []byte{0xFF, 0xFE, 0x00, 0xD8}},
		{"bad-utf8", append([]byte("<WIM>"), 0xFF, 0xFE)},
		{"wrong-root", utf16LE(`<FOO/>`)},
		{"index-zero", utf16LE(`<WIM><IMAGE INDEX="0"></IMAGE></WIM>`)},
		{"index-text", utf16LE(`<WIM><IMAGE INDEX="x"></IMAGE></WIM>`)},
		{"duplicate-index", utf16LE(`<WIM><IMAGE INDEX="1"/><IMAGE INDEX="1"/></WIM>`)},
		{"index-order", utf16LE(`<WIM><IMAGE INDEX="2"/></WIM>`)},
		{"count-text", utf16LE(`<WIM><IMAGE INDEX="1"><DIRCOUNT>x</DIRCOUNT></IMAGE></WIM>`)},
		{"broken-xml", utf16LE(`<WIM><IMAGE`)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseXML(test.xml); !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("parseXML error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestWIMDentryValidation(t *testing.T) {
	valid := testEncodeDentry("x", nil, 0x80, 0, [20]byte{}, testMTime, nil)
	if _, err := parseDentry(valid, 0, false); err != nil {
		t.Fatalf("the valid fixture was refused: %v", err)
	}

	check := func(name string, entry []byte, isRoot bool) {
		t.Helper()
		if _, err := parseDentry(entry, 0, isRoot); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("%s error = %v, want ErrCorrupt", name, err)
		}
	}

	check("root-with-name", valid, true)
	check("empty-name", testEncodeDentry("", nil, 0x80, 0, [20]byte{}, 0, nil), false)

	odd := append([]byte(nil), valid...)
	putU16(odd, 100, 1)
	check("odd-name", odd, false)

	surrogate := append([]byte(nil), valid...)
	putU16(surrogate, DirectoryEntryBytes, 0xD800)
	check("invalid-utf16", surrogate, false)

	separator := append([]byte(nil), valid...)
	putU16(separator, DirectoryEntryBytes, '/')
	check("path-separator", separator, false)

	colon := append([]byte(nil), valid...)
	putU16(colon, DirectoryEntryBytes, ':')
	check("colon", colon, false)

	nul := append([]byte(nil), valid...)
	putU16(nul, DirectoryEntryBytes, 0)
	check("nul", nul, false)

	stream := testEncodeDentry("x", nil, 0x80, 0, [20]byte{}, testMTime,
		[]*testStream{{name: "s", data: []byte("data")}})
	if _, err := parseDentry(stream, 0, false); err != nil {
		t.Fatalf("the valid stream fixture was refused: %v", err)
	}
	streamAt := DirectoryEntryBytes + 2 // the name is one UTF-16 unit
	shortLength := append([]byte(nil), stream...)
	putU64(shortLength, streamAt, 16)
	check("short-stream", shortLength, false)

	longName := append([]byte(nil), stream...)
	putU16(longName, streamAt+36, 1000)
	check("long-stream-name", longName, false)

	emptyName := append([]byte(nil), stream...)
	putU16(emptyName, streamAt+36, 0)
	check("empty-stream-name", emptyName, false)

	streamColon := append([]byte(nil), stream...)
	putU16(streamColon, streamAt+StreamEntryBytes, ':')
	check("stream-colon", streamColon, false)

	doubled := append([]byte(nil), stream...)
	putU16(doubled, 96, 2)
	check("missing-stream", doubled, false)
}

func TestWIMEntrySourceView(t *testing.T) {
	parts := buildWIM(t, wimSpec{tree: testTree(), kind: "xpress"})
	container := openTestWIM(t, parts.file)
	entry, err := container.OpenEntry(1, "Windows/System32/kernel32.dll")
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	if entry.SourceID() == 0 || entry.ImageID() != testImage || entry.SectorSize() != 512 ||
		entry.IsEmpty() || entry.Label() != "Windows/System32/kernel32.dll" {
		t.Fatalf("entry source view = %+v", entry)
	}
	buf := make([]byte, 12)
	if n, err := entry.ReadAtLossy(0, buf); err != nil || n != 12 {
		t.Fatalf("ReadAtLossy = %d, %v", n, err)
	}
	extents, err := entry.Extents(0, 12)
	if err != nil || len(extents) != 1 || extents[0].Kind != source.RangeData {
		t.Fatalf("compressed extents = %+v, %v", extents, err)
	}
	if _, err := entry.MapToImage(0, 12); err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}

	empty, err := container.OpenEntry(1, "empty.txt")
	if err != nil {
		t.Fatalf("OpenEntry(empty) error = %v", err)
	}
	if !empty.IsEmpty() || empty.Stats().BytesRead != 0 {
		t.Fatalf("empty source = %+v", empty)
	}
	if _, err := empty.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("empty ReadAt error = %v", err)
	}
	if extents, err := empty.Extents(0, 0); err != nil || len(extents) != 0 {
		t.Fatalf("empty extents = %+v, %v", extents, err)
	}

	if _, err := container.OpenEntry(1, "Windows"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("directory OpenEntry error = %v", err)
	}
	if _, err := container.OpenEntry(1, "missing"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("missing OpenEntry error = %v", err)
	}
	if _, err := container.OpenEntry(2, "notes.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("missing image error = %v", err)
	}
	if _, err := container.OpenStream(1, "notes.txt", "missing"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("missing stream error = %v", err)
	}
}

func TestWIMEntrySourceLossyCorruption(t *testing.T) {
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
	buf := bytes.Repeat([]byte{0xAA}, 100)
	n, err := entry.ReadAtLossy(0, buf)
	if err != nil || n != 100 {
		t.Fatalf("ReadAtLossy = %d, %v", n, err)
	}
	if !bytes.Equal(buf, make([]byte, 100)) {
		t.Fatal("lossy read did not zero-fill")
	}
	if entry.Stats().CorruptBytes != 100 {
		t.Fatalf("corrupt bytes = %d", entry.Stats().CorruptBytes)
	}
}

func TestWIMCompressionResourceBranches(t *testing.T) {
	// A compressed resource whose stored chunk equals its expected length is
	// stored, not inflated. Build a fixture and rewrite the chunk table and
	// payload so the first chunk is a literal copy of the output.
	data := []byte("stored chunk payload")
	parts := buildWIM(t, wimSpec{tree: []testNode{testFile("stored.bin", data)},
		kind: "xpress"})
	at := findLookupBytes(t, parts.file, testSHA1(data))
	resourceOffset := int(testLE64(parts.file, at+8))
	copy(parts.file[resourceOffset:resourceOffset+len(data)], data)
	// Claim exactly one stored chunk. The resource is still flagged
	// compressed, but a single chunk has no offset table, so its stored
	// length equals the expected output and the bytes are used as they are.
	raw := testLE64(parts.file, at)
	putU64(parts.file, at, (raw&^0x00FFFFFFFFFFFFFF)|uint64(len(data)))
	container, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, parts.file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	entry, err := container.OpenEntry(1, "stored.bin")
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	if got := string(readAll(t, entry)); got != string(data) {
		t.Fatalf("stored chunk = %q", got)
	}
	if entry.Stats().DecompressedBytes != 0 {
		t.Fatalf("a stored chunk was counted as decompressed: %d",
			entry.Stats().DecompressedBytes)
	}
}
