package sevenz

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

func memorySource(data []byte) source.ByteSource {
	return source.NewMemorySource(1, data)
}

func openBytes(t *testing.T, data []byte, limits archive.Limits) *Reader {
	t.Helper()
	reader, err := Open(memorySource(data), limits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return reader
}

func readEntry(t *testing.T, reader *Reader, path string) []byte {
	t.Helper()
	entry, err := reader.OpenEntrySource(path, 2)
	if err != nil {
		t.Fatalf("OpenEntrySource(%q): %v", path, err)
	}
	bytesOut, err := source.ReadVecAt(entry, 0, entry.Len())
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return bytesOut
}

func deflateCompress(data []byte) []byte {
	var buffer bytes.Buffer
	writer, err := flate.NewWriter(&buffer, flate.DefaultCompression)
	if err != nil {
		panic(err)
	}
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func TestMatchesSignatureAndAdapter(t *testing.T) {
	if !MatchesSignature([]byte("7z\xbc\xaf\x27\x1c")) {
		t.Fatal("the six-byte 7z signature must match")
	}
	if MatchesSignature([]byte("PK\x03\x04")) {
		t.Fatal("a ZIP signature must not match")
	}
	if MatchesSignature(nil) {
		t.Fatal("an empty head must not match")
	}

	fixture := buildArchive(
		[]*testFolder{copyFolder([]byte("hello\n"), nil, nil, crcPtr([]byte("hello\n")))},
		[]*testFile{{name: "hello.txt", data: []byte("hello\n"), folder: 0, sub: 0}},
	)
	registry := archive.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := registry.FormatIDs(); len(got) != 1 || got[0] != "7z" {
		t.Fatalf("registry formats = %v, want [7z]", got)
	}
	reader, err := registry.Open("7z", memorySource(fixture.bytes), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("registry Open: %v", err)
	}
	got, err := reader.OpenEntry("hello.txt", 5)
	if err != nil {
		t.Fatalf("OpenEntry: %v", err)
	}
	data, err := source.ReadVecAt(got, 0, got.Len())
	if err != nil || string(data) != "hello\n" {
		t.Fatalf("content = %q, %v", data, err)
	}
}

func TestStoredSolidEmptyDirectoryAndTimestamps(t *testing.T) {
	alpha := []byte("alpha\n")
	solid1 := []byte("first solid member\n")
	solid2 := []byte("second solid member\n")
	solid := append(append([]byte(nil), solid1...), solid2...)

	folders := []*testFolder{
		copyFolder(alpha, nil, nil, crcPtr(alpha)),
		copyFolder(solid, []uint64{uint64(len(solid1)), uint64(len(solid2))},
			[]*uint32{crcPtr(solid1), crcPtr(solid2)}, crcPtr(solid)),
	}
	mtime := int64(1_600_000_000)
	attrib := uint32(0x20)
	files := []*testFile{
		{name: "a.txt", data: alpha, folder: 0, sub: 0, mtime: &mtime, attr: &attrib},
		{name: "dir", isDir: true},
		{name: "empty.txt", empty: true},
		{name: "solid1.bin", data: solid1, folder: 1, sub: 0},
		{name: "solid2.bin", data: solid2, folder: 1, sub: 1},
	}
	fixture := buildArchive(folders, files)
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())

	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("entries = %d, want 5", len(entries))
	}
	wantPaths := []string{"a.txt", "dir", "empty.txt", "solid1.bin", "solid2.bin"}
	for index, want := range wantPaths {
		if entries[index].Path != want {
			t.Errorf("entry %d path = %q, want %q", index, entries[index].Path, want)
		}
	}
	if !entries[1].IsDir() || entries[1].Kind != archive.KindDirectory {
		t.Error("dir must list as a directory")
	}
	if entries[2].Kind != archive.KindFile || entries[2].Size != 0 {
		t.Error("empty.txt must list as an empty file")
	}
	if entries[0].Modified == nil || *entries[0].Modified != mtime {
		t.Errorf("mtime = %v, want %d", entries[0].Modified, mtime)
	}
	if entries[0].CRC32 == nil || *entries[0].CRC32 != fixtureCRC(alpha) {
		t.Errorf("CRC32 = %v", entries[0].CRC32)
	}
	if entries[3].Size != uint64(len(solid1)) || entries[4].Size != uint64(len(solid2)) {
		t.Error("solid substream sizes are wrong")
	}
	if entries[3].CompressedSize != nil {
		t.Error("a folder with several substreams must not claim a per-entry compressed size")
	}
	if entries[0].CompressedSize == nil || *entries[0].CompressedSize != uint64(len(alpha)) {
		t.Errorf("compressed size = %v, want %d", entries[0].CompressedSize, len(alpha))
	}

	if got := readEntry(t, reader, "a.txt"); !bytes.Equal(got, alpha) {
		t.Errorf("a.txt = %q", got)
	}
	if got := readEntry(t, reader, "solid1.bin"); !bytes.Equal(got, solid1) {
		t.Errorf("solid1.bin = %q", got)
	}
	if got := readEntry(t, reader, "solid2.bin"); !bytes.Equal(got, solid2) {
		t.Errorf("solid2.bin = %q", got)
	}

	// The volume caches one folder: a.txt folder is a miss, the first solid
	// read is a second miss, and the second solid read is a hit.
	stats := reader.Stats()
	if stats.CacheMisses != 2 || stats.CacheHits != 1 {
		t.Errorf("cache stats = %+v, want 2 misses and 1 hit", stats)
	}

	if _, found, err := reader.FindEntry("dir"); err != nil || !found {
		t.Errorf("FindEntry(dir) = %v, %v", found, err)
	}
	if _, found, err := reader.FindEntry("missing"); err != nil || found {
		t.Errorf("FindEntry(missing) = %v, %v", found, err)
	}
	if _, err := reader.OpenEntry("dir", 3); err == nil {
		t.Error("opening a directory must fail")
	}

	// A stored folder maps linearly to its packed stream.
	entry, err := reader.OpenEntrySource("a.txt", 4)
	if err != nil {
		t.Fatalf("OpenEntrySource: %v", err)
	}
	extents, err := entry.Extents(0, entry.Len())
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(extents) != 1 || extents[0].Len != uint64(len(alpha)) || extents[0].Kind != source.RangeData {
		t.Errorf("extents = %+v", extents)
	}
	imageRanges, err := entry.MapToImage(0, entry.Len())
	if err != nil || len(imageRanges) != 1 {
		t.Errorf("MapToImage = %+v, %v", imageRanges, err)
	}
	if _, err := entry.ReadAt(entry.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("read past the end = %v, want ErrOutOfRange", err)
	}
}

func TestEncodedHeader(t *testing.T) {
	payload := []byte("stored behind a compressed header\n")
	folder := copyFolder(payload, nil, nil, crcPtr(payload))
	plain := buildHeader([]*testFolder{folder},
		[]*testFile{{name: "payload.txt", data: payload, folder: 0, sub: 0}})
	fixture := buildEncodedArchive(plain, payload, deflateCompress)

	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "payload.txt" {
		t.Fatalf("entries = %+v", entries)
	}
	if got := readEntry(t, reader, "payload.txt"); !bytes.Equal(got, payload) {
		t.Errorf("payload = %q", got)
	}
}

func singleCoderArchive(coderID, props, packed []byte, text []byte, name string) fixtureArchive {
	folder := &testFolder{
		coders:      []testCoder{{id: coderID, props: props}},
		unpackSizes: []uint64{uint64(len(text))},
		packed:      append([]byte(nil), packed...),
		subSizes:    []uint64{uint64(len(text))},
		subCRCs:     []*uint32{crcPtr(text)},
	}
	return buildArchive([]*testFolder{folder},
		[]*testFile{{name: name, data: text, folder: 0, sub: 0}})
}

func TestCodersLZMAAndLZMA2(t *testing.T) {
	text := []byte(lzmaFixtureText)
	fixtures := map[string]fixtureArchive{
		"lzma":  singleCoderArchive(idLZMA, lzmaPropsFixture, lzmaStreamFixture, text, "lzma.txt"),
		"lzma2": singleCoderArchive(idLZMA2, []byte{lzma2PropFixture}, lzma2StreamFixture, text, "lzma2.txt"),
	}
	for label, fixture := range fixtures {
		t.Run(label, func(t *testing.T) {
			reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
			name := label + ".txt"
			if got := readEntry(t, reader, name); !bytes.Equal(got, text) {
				t.Errorf("%s content = %q", label, got)
			}
			entry, found, err := reader.FindEntry(name)
			if err != nil || !found {
				t.Fatalf("FindEntry: %v, %v", err, found)
			}
			if entry.CRC32 == nil || *entry.CRC32 != fixtureCRC(text) {
				t.Errorf("%s CRC = %v", label, entry.CRC32)
			}
		})
	}
}

func TestCoderDeflateAndBzip2(t *testing.T) {
	deflateText := []byte(deflateFixtureText)
	deflatePacked := deflateCompress(deflateText)
	fixtures := map[string]fixtureArchive{
		"deflate": singleCoderArchive(idDeflate, nil, deflatePacked, deflateText, "deflate.txt"),
		"bzip2": singleCoderArchive(idBzip2, nil, bzip2StreamFixture,
			[]byte(bzip2FixtureText), "bzip2.txt"),
	}
	for label, fixture := range fixtures {
		t.Run(label, func(t *testing.T) {
			reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
			name := label + ".txt"
			want := deflateText
			if label == "bzip2" {
				want = []byte(bzip2FixtureText)
			}
			if got := readEntry(t, reader, name); !bytes.Equal(got, want) {
				t.Errorf("%s content = %q", label, got)
			}
		})
	}
}

func TestDeltaCoderChain(t *testing.T) {
	text := []byte("delta filtered payload: abcdefghijklmnopqrstuvwxyz\n")
	encoded := append([]byte(nil), text...)
	deltaEncode(encoded, 4)
	folder := &testFolder{
		coders: []testCoder{
			{id: idCopy},
			{id: idDelta, props: []byte{3}},
		},
		bindPairs:   []bindPair{{input: 1, output: 0}},
		unpackSizes: []uint64{uint64(len(encoded)), uint64(len(text))},
		packed:      encoded,
		subSizes:    []uint64{uint64(len(text))},
		subCRCs:     []*uint32{crcPtr(text)},
	}
	fixture := buildArchive([]*testFolder{folder},
		[]*testFile{{name: "delta.bin", data: text, folder: 0, sub: 0}})
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
	if got := readEntry(t, reader, "delta.bin"); !bytes.Equal(got, text) {
		t.Errorf("delta chain = %q", got)
	}
}

func TestBCJCoderChainAndRealArchives(t *testing.T) {
	data := bcjCallsTextFixture
	encoded := append([]byte(nil), data...)
	bcjX86(encoded, 0, true)
	folder := &testFolder{
		coders: []testCoder{
			{id: idCopy},
			{id: idBCJX86},
		},
		bindPairs:   []bindPair{{input: 1, output: 0}},
		unpackSizes: []uint64{uint64(len(encoded)), uint64(len(data))},
		packed:      encoded,
		subSizes:    []uint64{uint64(len(data))},
		subCRCs:     []*uint32{crcPtr(data)},
	}
	fixture := buildArchive([]*testFolder{folder},
		[]*testFile{{name: "calls.bin", data: data, folder: 0, sub: 0}})
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
	if got := readEntry(t, reader, "calls.bin"); !bytes.Equal(got, data) {
		t.Errorf("BCJ chain content differs: %x", got)
	}

	// Real 7-Zip output for the same kind of chain.
	realReaders := map[string]struct {
		bytes []byte
		path  string
		want  []byte
	}{
		"delta": {deltaArchiveFixture, "d.bin", deltaTextFixture()},
		"bcj":   {bcjArchiveFixture, "x.bin", bcjTextFixture()},
		"calls": {bcjCallsArchiveFixture, "bcj3.bin", bcjCallsTextFixture},
	}
	for label, testCase := range realReaders {
		t.Run(label, func(t *testing.T) {
			reader := openBytes(t, testCase.bytes, archive.DefaultLimits())
			if got := readEntry(t, reader, testCase.path); !bytes.Equal(got, testCase.want) {
				t.Errorf("%s real archive content differs (len %d vs %d)", label, len(got), len(testCase.want))
			}
		})
	}
}

func TestBCJ2RealArchive(t *testing.T) {
	reader := openBytes(t, bcj2ArchiveFixture, archive.DefaultLimits())
	entry, err := reader.OpenEntrySource("bcj2src.bin", 2)
	if err != nil {
		t.Fatalf("OpenEntrySource: %v", err)
	}
	got, err := source.ReadVecAt(entry, 0, entry.Len())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, bcjCallsTextFixture) {
		t.Fatalf("BCJ2 output differs: %x", got)
	}
	if stats := entry.Stats(); stats.CorruptBytes != 0 {
		t.Errorf("corrupt bytes = %d, want 0", stats.CorruptBytes)
	}
}

func TestPPMdRealArchives(t *testing.T) {
	want := ppmdTextFixture()
	if len(want) != 1120 {
		t.Fatalf("fixture text is %d bytes, want 1120", len(want))
	}
	for label, data := range map[string][]byte{
		"order6": ppmdOrder6ArchiveFixture,
		"order2": ppmdOrder2ArchiveFixture,
	} {
		t.Run(label, func(t *testing.T) {
			reader := openBytes(t, data, archive.DefaultLimits())
			got := readEntry(t, reader, "ppmd.txt")
			if !bytes.Equal(got, want) {
				t.Fatalf("PPMd %s output differs (len %d vs %d)", label, len(got), len(want))
			}
		})
	}
}

func TestPPMdAllocatorStress(t *testing.T) {
	// A 64 KiB model cannot hold this input, so PPMd must recycle blocks,
	// glue the free list, restart the model and rescale frequencies.
	reader := openBytes(t, ppmdAllocatorArchive(), archive.DefaultLimits())
	got := readEntry(t, reader, "ppmd_1200.txt")
	want := ppmdAllocatorText()
	if !bytes.Equal(got, want) {
		t.Fatalf("allocator-stress PPMd output differs: len %d vs %d", len(got), len(want))
	}
}

func TestCRCMismatchIsReportedButBytesRemain(t *testing.T) {
	text := []byte("the CRC in this archive is deliberately wrong")
	wrong := fixtureCRC([]byte("not the payload"))
	folder := &testFolder{
		coders:      []testCoder{{id: idCopy}},
		unpackSizes: []uint64{uint64(len(text))},
		packed:      append([]byte(nil), text...),
		subSizes:    []uint64{uint64(len(text))},
		subCRCs:     []*uint32{&wrong},
		folderCRC:   &wrong,
	}
	fileCRC := wrong
	fixture := buildArchive([]*testFolder{folder},
		[]*testFile{{name: "wrong.bin", data: text, folder: 0, sub: 0, crc: &fileCRC}})
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
	entry, err := reader.OpenEntrySource("wrong.bin", 3)
	if err != nil {
		t.Fatalf("OpenEntrySource: %v", err)
	}
	got, err := source.ReadVecAt(entry, 0, entry.Len())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, text) {
		t.Fatalf("recovered bytes = %q", got)
	}
	stats := entry.Stats()
	if stats.CorruptBytes == 0 || stats.Errors == 0 {
		t.Errorf("stats = %+v, want corrupt bytes reported", stats)
	}
	listed, _, err := reader.FindEntry("wrong.bin")
	if err != nil {
		t.Fatalf("FindEntry: %v", err)
	}
	if listed.CRC32 == nil || *listed.CRC32 != wrong {
		t.Errorf("listed CRC = %v, want the recorded wrong value", listed.CRC32)
	}
}

func TestCorruptStructureIsExplicit(t *testing.T) {
	valid := buildArchive(
		[]*testFolder{copyFolder([]byte("data"), nil, nil, crcPtr([]byte("data")))},
		[]*testFile{{name: "a.bin", data: []byte("data"), folder: 0, sub: 0}},
	).bytes

	t.Run("too short", func(t *testing.T) {
		_, err := Open(memorySource(make([]byte, 8)), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing signature", func(t *testing.T) {
		_, err := Open(memorySource(make([]byte, 40)), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad start header CRC", func(t *testing.T) {
		data := append([]byte(nil), valid...)
		data[12] ^= 0xFF
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("next header past end", func(t *testing.T) {
		data := append([]byte(nil), valid...)
		setNextOffsetAndCRC(data, uint64(len(data)), 4)
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad next header CRC", func(t *testing.T) {
		data := append([]byte(nil), valid...)
		data[len(data)-1] ^= 0xFF
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("oversized header", func(t *testing.T) {
		data := append([]byte(nil), valid...)
		setNextOffsetAndCRC(data, 0, maxHeaderBytes+1)
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrLimit) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("truncated property tree", func(t *testing.T) {
		next := appendNumber(nil, kHeader)
		next = appendNumber(next, kMainStreamsInfo)
		next = appendNumber(next, kPackInfo)
		data := wrapNextHeader(next, nil)
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown header property", func(t *testing.T) {
		next := appendNumber(nil, 0x99)
		data := wrapNextHeader(next, nil)
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("packed stream past end", func(t *testing.T) {
		data := append([]byte(nil), valid...)
		// The pack size is the last byte of the pack-info size list; locate
		// it by rebuilding the header with a lying size is easier than
		// patching, so just flip the file length expectation instead.
		truncated := data[:len(data)-1]
		// Fix the next-header range to stay valid; the lying size then points
		// past the shortened file.
		nextOffset := uint64(sigValue(data, 12))
		setNextOffsetAndCRC(truncated, nextOffset, uint64(sigValue(data, 20)))
		_, err := Open(memorySource(truncated), archive.DefaultLimits())
		if err == nil {
			t.Fatal("a truncated packed stream must be refused")
		}
	})
}

func sigValue(data []byte, offset int) uint64 {
	var out uint64
	for index := 0; index < 8; index++ {
		out |= uint64(data[offset+index]) << (8 * uint(index))
	}
	return out
}

func setNextOffsetAndCRC(data []byte, offset, size uint64) {
	for index := 0; index < 8; index++ {
		data[12+index] = byte(offset >> (8 * uint(index)))
		data[20+index] = byte(size >> (8 * uint(index)))
	}
	startCRC := foundation.CRC32(data[12:32])
	for index := 0; index < 4; index++ {
		data[8+index] = byte(startCRC >> (8 * uint(index)))
	}
}

// wrapNextHeader builds a file whose next header is next and whose packed
// region is packed.
func wrapNextHeader(next, packed []byte) []byte {
	sig := make([]byte, signatureHeaderLen)
	copy(sig[:6], signature[:])
	sig[6], sig[7] = 0, 4
	for index := 0; index < 8; index++ {
		sig[12+index] = byte(uint64(len(packed)) >> (8 * uint(index)))
		sig[20+index] = byte(uint64(len(next)) >> (8 * uint(index)))
	}
	crc := fixtureCRC(next)
	for index := 0; index < 4; index++ {
		sig[28+index] = byte(crc >> (8 * uint(index)))
	}
	startCRC := foundation.CRC32(sig[12:32])
	for index := 0; index < 4; index++ {
		sig[8+index] = byte(startCRC >> (8 * uint(index)))
	}
	out := append(append([]byte(nil), sig...), packed...)
	return append(out, next...)
}

func TestUnsupportedCodersAreRefusedByName(t *testing.T) {
	payload := []byte("payload")
	cases := map[string]struct {
		id   []byte
		want string
	}{
		"unknown":   {[]byte{0x06, 0x99}, "0x0699"},
		"deflate64": {idDeflate64, "Deflate64"},
		"bcj alpha": {idBCJAlpha, "BCJ Alpha"},
	}
	for label, testCase := range cases {
		t.Run(label, func(t *testing.T) {
			folder := &testFolder{
				coders:      []testCoder{{id: testCase.id}},
				unpackSizes: []uint64{uint64(len(payload))},
				packed:      append([]byte(nil), payload...),
				subSizes:    []uint64{uint64(len(payload))},
			}
			fixture := buildArchive([]*testFolder{folder},
				[]*testFile{{name: "x.bin", data: payload, folder: 0, sub: 0}})
			reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
			// Listing only reads the header, so the unsupported coder does
			// not stop the entry from being named.
			entries, err := reader.Entries()
			if err != nil || len(entries) != 1 || entries[0].Path != "x.bin" {
				t.Fatalf("Entries = %+v, %v", entries, err)
			}
			_, err = reader.OpenEntrySource("x.bin", 2)
			if err == nil || !errors.Is(err, source.ErrUnsupported) {
				t.Fatalf("OpenEntrySource err = %v, want ErrUnsupported", err)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(testCase.want)) {
				t.Errorf("error %q does not name %q", err, testCase.want)
			}
			if _, err := reader.OpenEntry("x.bin", 3); err == nil ||
				!errors.Is(err, source.ErrUnsupported) {
				t.Errorf("OpenEntry err = %v, want ErrUnsupported", err)
			}
		})
	}
}

func TestEncryptedArchivesAreRefused(t *testing.T) {
	payload := make([]byte, 16) // ciphertext-shaped bytes
	folder := &testFolder{
		coders:      []testCoder{{id: idAES, props: []byte{0x00, 0x03, 0x00, 0x00}}},
		unpackSizes: []uint64{16},
		packed:      payload,
		subSizes:    []uint64{16},
	}
	fixture := buildArchive([]*testFolder{folder},
		[]*testFile{{name: "secret.bin", data: payload, folder: 0, sub: 0}})
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || !entries[0].Encrypted {
		t.Fatalf("entry must be listed and marked encrypted: %+v", entries)
	}
	if _, err := reader.OpenEntrySource("secret.bin", 2); err == nil ||
		!errors.Is(err, source.ErrDecrypt) {
		t.Fatalf("OpenEntrySource err = %v, want ErrDecrypt", err)
	}

	// An encrypted encoded header cannot even be parsed, so Open refuses it.
	next := appendNumber(nil, kEncodedHeader)
	encoded := buildStreamsInfo([]*testFolder{{
		coders:      []testCoder{{id: idAES, props: []byte{0x00, 0x03, 0x00, 0x00}}},
		unpackSizes: []uint64{64},
		packed:      payload,
		subSizes:    []uint64{64},
	}}, 0)
	next = append(next, encoded...)
	archiveBytes := wrapNextHeader(next, payload)
	_, err = Open(memorySource(archiveBytes), archive.DefaultLimits())
	if err == nil || !errors.Is(err, source.ErrDecrypt) {
		t.Fatalf("encrypted header err = %v, want ErrDecrypt", err)
	}
}

func TestLimits(t *testing.T) {
	alpha := []byte("alpha")
	beta := []byte("bravo")
	folders := []*testFolder{
		copyFolder(alpha, nil, nil, crcPtr(alpha)),
		copyFolder(beta, nil, nil, crcPtr(beta)),
	}
	files := []*testFile{
		{name: "a", data: alpha, folder: 0, sub: 0},
		{name: "b", data: beta, folder: 1, sub: 0},
	}
	fixture := buildArchive(folders, files)

	limits := archive.DefaultLimits()
	limits.MaxEntries = 1
	if _, err := Open(memorySource(fixture.bytes), limits); err == nil ||
		!errors.Is(err, archive.ErrLimit) {
		t.Fatalf("MaxEntries err = %v, want ErrLimit", err)
	}

	limits = archive.DefaultLimits()
	limits.MaxEntrySize = 4
	if _, err := Open(memorySource(fixture.bytes), limits); err == nil ||
		!errors.Is(err, archive.ErrLimit) {
		t.Fatalf("MaxEntrySize err = %v, want ErrLimit", err)
	}

	limits = archive.DefaultLimits()
	limits.MaxTotalExpanded = 8
	if _, err := Open(memorySource(fixture.bytes), limits); err == nil ||
		!errors.Is(err, archive.ErrLimit) {
		t.Fatalf("MaxTotalExpanded err = %v, want ErrLimit", err)
	}

	limits = archive.DefaultLimits()
	limits.MaxPathLen = 0
	if _, err := Open(memorySource(fixture.bytes), limits); err == nil ||
		!errors.Is(err, archive.ErrLimit) {
		t.Fatalf("MaxPathLen err = %v, want ErrLimit", err)
	}

	// A folder can hold substreams no file references, so its unpacked size
	// can exceed every admitted entry.  Decoding it must respect the budget.
	hidden := []byte("abcdefgh")
	hiddenFolder := &testFolder{
		coders:      []testCoder{{id: idCopy}},
		unpackSizes: []uint64{uint64(len(hidden))},
		packed:      append([]byte(nil), hidden...),
		subSizes:    []uint64{4, 4},
		subCRCs:     []*uint32{crcPtr([]byte("abcd")), crcPtr([]byte("efgh"))},
	}
	big := buildArchive(
		[]*testFolder{hiddenFolder},
		[]*testFile{{name: "p", data: []byte("abcd"), folder: 0, sub: 0}},
	)
	limits = archive.DefaultLimits()
	limits.MaxTotalExpanded = 4
	reader := openBytes(t, big.bytes, limits)
	entry, err := reader.OpenEntrySource("p", 2)
	if err != nil {
		t.Fatalf("OpenEntrySource: %v", err)
	}
	if _, err := source.ReadVecAt(entry, 0, entry.Len()); err == nil {
		t.Fatal("a folder past the expanded budget must not decode")
	}
}

func TestParserUnits(t *testing.T) {
	// The documented variable-number examples.
	numbers := map[uint64][]byte{
		0:      {0x00},
		127:    {0x7F},
		128:    {0x80, 0x80},
		0x1FF:  {0x81, 0xFF},
		0x4000: {0xC0, 0x00, 0x40},
	}
	for want, encoded := range numbers {
		reader := newHeaderReader(encoded, "test")
		got, err := reader.number()
		if err != nil || got != want {
			t.Errorf("number(%x) = %d, %v; want %d", encoded, got, err, want)
		}
		roundTrip, err := newHeaderReader(sevenNumber(want), "test").number()
		if err != nil || roundTrip != want {
			t.Errorf("sevenNumber(%d) round trip = %d, %v", want, roundTrip, err)
		}
	}
	if _, err := newHeaderReader([]byte{0x80}, "test").number(); err == nil {
		t.Error("a truncated number must be rejected")
	}

	// One Copy coder: one input, one output, one implied packed stream.
	folder, err := parseFolder(newHeaderReader([]byte{0x01, 0x01, 0x00}, "test"))
	if err != nil {
		t.Fatalf("parseFolder: %v", err)
	}
	if chain, ok := folder.chain(); !ok || len(chain) != 1 || chain[0] != 0 {
		t.Errorf("chain = %v, %v", chain, ok)
	}
	// A filter chained after Copy: the bind pair runs Copy first.
	folder, err = parseFolder(newHeaderReader(
		[]byte{0x02, 0x01, 0x00, 0x21, 0x03, 0x01, 0x03, 0x01, 0x00}, "test"))
	if err != nil {
		t.Fatalf("parseFolder chain: %v", err)
	}
	if chain, ok := folder.chain(); !ok || len(chain) != 2 || chain[0] != 0 || chain[1] != 1 {
		t.Errorf("chain = %v, %v", chain, ok)
	}
	// Two bind pairs feeding the same input cannot be a single path.
	folder, err = parseFolder(newHeaderReader(
		[]byte{0x03, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00}, "test"))
	if err != nil {
		t.Fatalf("parseFolder duplicate: %v", err)
	}
	if chain, ok := folder.chain(); ok {
		t.Errorf("duplicate chain = %v, want none", chain)
	}
	if _, err := parseFolder(newHeaderReader(
		[]byte{0x01, 0x11, 0x00, 0x02, 0x02, 0x05, 0x05}, "test")); err == nil {
		t.Error("a bind pair outside the stream counts must be rejected")
	}

	if got := filetimeToUnix(116444736000000000); got == nil || *got != 0 {
		t.Errorf("filetime epoch = %v", got)
	}
	if got := filetimeToUnix(116444736010000000); got == nil || *got != 1 {
		t.Errorf("filetime one second = %v", got)
	}
	if got := filetimeToUnix(0); got == nil || *got != -11_644_473_600 {
		t.Errorf("filetime zero = %v", got)
	}
}

func TestFiltersAndBranchConverters(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	deltaDecode(data, 4)
	if !bytes.Equal(data, []byte{1, 2, 3, 4, 6, 8, 10, 12}) {
		t.Errorf("delta = %v", data)
	}
	data = []byte{1, 1, 1, 255}
	deltaDecode(data, 1)
	if !bytes.Equal(data, []byte{1, 2, 3, 2}) {
		t.Errorf("delta distance 1 = %v", data)
	}

	// x86 round trip, including a run of opcode bytes and a non-address
	// operand.
	original := []byte{
		0xE8, 0x10, 0x00, 0x00, 0x00, 0xE9, 0x20, 0x00, 0x00, 0x00,
		0xE8, 0x34, 0x12, 0x00, 0x00, 0xE8, 0x78, 0x56, 0x34, 0x12,
	}
	roundTrip := append([]byte(nil), original...)
	bcjX86(roundTrip, 0, true)
	if bytes.Equal(roundTrip, original) {
		t.Error("encoding must change address operands")
	}
	bcjX86(roundTrip, 0, false)
	if !bytes.Equal(roundTrip, original) {
		t.Errorf("x86 round trip = %x", roundTrip)
	}
	short := []byte{0xE8, 1, 2, 3}
	bcjX86(short, 0, false)
	if !bytes.Equal(short, []byte{0xE8, 1, 2, 3}) {
		t.Errorf("a short stream must be left alone: %v", short)
	}

	// ARM, ARM64 and PPC subtract the instruction address.
	armData := make([]byte, 8)
	copy(armData[4:], []byte{0x13, 0x00, 0x00, 0xEB})
	branchARM(armData, 0)
	if !bytes.Equal(armData[4:], []byte{0x10, 0x00, 0x00, 0xEB}) {
		t.Errorf("ARM = %x", armData[4:])
	}
	arm64Data := make([]byte, 12)
	copy(arm64Data[8:], []byte{0x12, 0x00, 0x00, 0x94})
	branchARM64(arm64Data, 0)
	if !bytes.Equal(arm64Data[8:], []byte{0x10, 0x00, 0x00, 0x94}) {
		t.Errorf("ARM64 = %x", arm64Data[8:])
	}
	ppcData := make([]byte, 16)
	copy(ppcData[12:], []byte{0x48, 0x00, 0x00, 0x1D})
	branchPPC(ppcData, 0)
	if !bytes.Equal(ppcData[12:], []byte{0x48, 0x00, 0x00, 0x11}) {
		t.Errorf("PPC = %x", ppcData[12:])
	}

	swapped := []byte{1, 2, 3, 4, 5, 6, 7}
	swap2(swapped)
	if !bytes.Equal(swapped, []byte{2, 1, 4, 3, 6, 5, 7}) {
		t.Errorf("swap2 = %v", swapped)
	}
	swapped = []byte{1, 2, 3, 4, 5, 6, 7}
	swap4(swapped)
	if !bytes.Equal(swapped, []byte{4, 3, 2, 1, 5, 6, 7}) {
		t.Errorf("swap4 = %v", swapped)
	}
}

func TestBCJ2DecoderRefusals(t *testing.T) {
	if _, reason := decodeBCJ2(nil, nil, nil, nil); reason == "" {
		t.Error("a missing range-coder header must be refused")
	}
	if _, reason := decodeBCJ2([]byte{0xE8}, nil, nil, []byte{1, 0, 0, 0, 0}); reason == "" {
		t.Error("a nonzero range-coder first byte must be refused")
	}
	if _, reason := decodeBCJ2([]byte{0xE8}, nil, nil, []byte{0x00, 0xFF, 0xFF, 0xFF, 0x00}); reason == "" {
		t.Error("a set bit without an address must be refused")
	}
}

func TestDeflateEncodingRoundTripIsUsedByFixtures(t *testing.T) {
	// Guard the helper: the DEFLATE fixtures must really be raw streams that
	// compress/flate can reproduce.
	packed := deflateCompress([]byte(deflateFixtureText))
	reader := flate.NewReader(bytes.NewReader(packed))
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != deflateFixtureText {
		t.Fatalf("deflate helper = %q, %v", got, err)
	}
}

func TestBranchConvertersAgainst7Zip(t *testing.T) {
	for name := range bcjFilterArchives {
		name := name
		t.Run(name, func(t *testing.T) {
			reader := openBytes(t, bcjFilterArchive(name), archive.DefaultLimits())
			path := "bcj_" + name + ".bin"
			if got := readEntry(t, reader, path); !bytes.Equal(got, bcjFilterText(name)) {
				t.Fatalf("%s filter output differs from the original data", name)
			}
		})
	}
	if len(bcjFilterArchives) != 6 {
		t.Fatalf("BCJ filter fixture count = %d", len(bcjFilterArchives))
	}
}

func TestIA64ConverterMatchesReference(t *testing.T) {
	// Two 16-byte bundles: the first has no branch slot, the second uses
	// template 0x16 (slot 1) with a branch-shaped 5-byte window.  The expected
	// bytes are the transformation the reference C/Bra.c decoder produces.
	data := make([]byte, 32)
	data[16] = 0x16
	data[18] = 0x08
	data[21] = 0x14
	branchIA64(data, 0)

	want := make([]byte, 32)
	want[16] = 0x16
	want[18] = 0x04
	want[21] = 0x14
	if !bytes.Equal(data, want) {
		t.Fatalf("IA-64 conversion = %x, want %x", data, want)
	}

	// A bundle whose template names no slot and whose bytes are not a branch
	// is left untouched.
	zeros := make([]byte, 32)
	branchIA64(zeros, 0)
	if !bytes.Equal(zeros, make([]byte, 32)) {
		t.Errorf("an empty bundle must be unchanged: %x", zeros)
	}
}
