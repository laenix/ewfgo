package zip

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testMethodStored   = 0
	testMethodDeflated = 8

	testGPEncrypted       = 0x0001
	testGPStrongEncrypted = 0x0040
	testGPDataDescriptor  = 0x0008
	testGPUTF8            = 0x0800
)

var (
	eocdSigBytes         = []byte{0x50, 0x4b, 0x05, 0x06}
	zip64LocatorSigBytes = []byte{0x50, 0x4b, 0x06, 0x07}
	zip64EOCDSigBytes    = []byte{0x50, 0x4b, 0x06, 0x06}
	centralSigBytes      = []byte{0x50, 0x4b, 0x01, 0x02}
	localSigBytes        = []byte{0x50, 0x4b, 0x03, 0x04}
)

type zipSpec struct {
	name          string
	data          []byte
	method        uint16
	flags         uint16
	versionMade   uint16
	externalAttrs uint32
	crcOverride   *uint32
	extra         []byte
	zip64         bool
}

func fileSpec(name string, data []byte) zipSpec {
	return zipSpec{name: name, data: data, method: testMethodStored, flags: testGPUTF8, versionMade: 0x031E}
}

func deflatedSpec(name string, data []byte) zipSpec {
	spec := fileSpec(name, data)
	spec.method = testMethodDeflated
	return spec
}

func deflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func put16(buf []byte, at int, value uint16) { binary.LittleEndian.PutUint16(buf[at:], value) }
func put32(buf []byte, at int, value uint32) { binary.LittleEndian.PutUint32(buf[at:], value) }
func put64(buf []byte, at int, value uint64) { binary.LittleEndian.PutUint64(buf[at:], value) }

func zip64Extra(uncompressed, compressed, offset uint64) []byte {
	extra := make([]byte, 4+24)
	put16(extra, 0, 0x0001)
	put16(extra, 2, 24)
	put64(extra, 4, uncompressed)
	put64(extra, 12, compressed)
	put64(extra, 20, offset)
	return extra
}

// buildZip writes a synthetic archive; the reader shares only the published
// format with this builder.
func buildZip(t *testing.T, specs []zipSpec, comment string) []byte {
	t.Helper()
	var out []byte
	var central []byte
	anyZip64 := false

	for _, spec := range specs {
		if spec.zip64 {
			anyZip64 = true
		}
		payload := spec.data
		if spec.method == testMethodDeflated {
			payload = deflate(t, spec.data)
		}
		crc := foundation.CRC32(spec.data)
		if spec.crcOverride != nil {
			crc = *spec.crcOverride
		}
		offset := uint64(len(out))

		var localExtra []byte
		if spec.zip64 {
			localExtra = zip64Extra(uint64(len(spec.data)), uint64(len(payload)), offset)
		}
		localExtra = append(localExtra, spec.extra...)

		local := make([]byte, 30)
		copy(local, localSigBytes)
		put16(local, 4, 45)
		put16(local, 6, spec.flags)
		put16(local, 8, spec.method)
		put16(local, 10, 0)
		put16(local, 12, 0)
		put32(local, 14, crc)
		if spec.zip64 {
			put32(local, 18, 0xFFFFFFFF)
			put32(local, 22, 0xFFFFFFFF)
		} else {
			put32(local, 18, uint32(len(payload)))
			put32(local, 22, uint32(len(spec.data)))
		}
		put16(local, 26, uint16(len(spec.name)))
		put16(local, 28, uint16(len(localExtra)))
		out = append(out, local...)
		out = append(out, spec.name...)
		out = append(out, localExtra...)
		out = append(out, payload...)

		var centralExtra []byte
		if spec.zip64 {
			centralExtra = zip64Extra(uint64(len(spec.data)), uint64(len(payload)), offset)
		}
		centralExtra = append(centralExtra, spec.extra...)

		header := make([]byte, 46)
		copy(header, centralSigBytes)
		put16(header, 4, spec.versionMade)
		put16(header, 6, 45)
		put16(header, 8, spec.flags)
		put16(header, 10, spec.method)
		put16(header, 12, 0)
		put16(header, 14, 0)
		put32(header, 16, crc)
		if spec.zip64 {
			put32(header, 20, 0xFFFFFFFF)
			put32(header, 24, 0xFFFFFFFF)
		} else {
			put32(header, 20, uint32(len(payload)))
			put32(header, 24, uint32(len(spec.data)))
		}
		put16(header, 28, uint16(len(spec.name)))
		put16(header, 30, uint16(len(centralExtra)))
		put16(header, 32, 0)
		put16(header, 34, 0)
		put16(header, 36, 0)
		put32(header, 38, spec.externalAttrs)
		if spec.zip64 {
			put32(header, 42, 0xFFFFFFFF)
		} else {
			put32(header, 42, uint32(offset))
		}
		central = append(central, header...)
		central = append(central, spec.name...)
		central = append(central, centralExtra...)
	}

	cdOffset := uint64(len(out))
	out = append(out, central...)
	cdSize := uint64(len(central))
	entries := uint64(len(specs))

	if anyZip64 {
		zip64Offset := uint64(len(out))
		record := make([]byte, 56)
		copy(record, zip64EOCDSigBytes)
		put64(record, 4, 44)
		put16(record, 12, 45)
		put16(record, 14, 45)
		put32(record, 16, 0)
		put32(record, 20, 0)
		put64(record, 24, entries)
		put64(record, 32, entries)
		put64(record, 40, cdSize)
		put64(record, 48, cdOffset)
		out = append(out, record...)

		locator := make([]byte, 20)
		copy(locator, zip64LocatorSigBytes)
		put32(locator, 4, 0)
		put64(locator, 8, zip64Offset)
		put32(locator, 16, 1)
		out = append(out, locator...)
	}

	eocd := make([]byte, 22)
	copy(eocd, eocdSigBytes)
	if anyZip64 {
		put16(eocd, 8, 0xFFFF)
		put16(eocd, 10, 0xFFFF)
		put32(eocd, 12, 0xFFFFFFFF)
		put32(eocd, 16, 0xFFFFFFFF)
	} else {
		put16(eocd, 8, uint16(entries))
		put16(eocd, 10, uint16(entries))
		put32(eocd, 12, uint32(cdSize))
		put32(eocd, 16, uint32(cdOffset))
	}
	put16(eocd, 20, uint16(len(comment)))
	out = append(out, eocd...)
	out = append(out, comment...)
	return out
}

func openBytes(t *testing.T, data []byte) *Reader {
	t.Helper()
	reader, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	return reader
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	out := make([]byte, src.Len())
	done := 0
	for done < len(out) {
		n, err := src.ReadAt(uint64(done), out[done:])
		if err != nil {
			t.Fatalf("read at %d: %v", done, err)
		}
		if n == 0 {
			t.Fatalf("zero read at %d", done)
		}
		done += n
	}
	return out
}

func TestListsStoredDeflatedDirectoryAndUTF8(t *testing.T) {
	text := []byte("hello, forensic world\n")
	csv := []byte("id,name\n1,alpha\n2,beta\n")
	dir := fileSpec("data/", nil)
	dir.externalAttrs = 0o040755 << 16
	zipBytes := buildZip(t, []zipSpec{
		fileSpec("readme.txt", text),
		dir,
		deflatedSpec("data/records.csv", csv),
		fileSpec("记录.txt", []byte("zhongwen\n")),
	}, "")

	reader := openBytes(t, zipBytes)
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Path != "readme.txt" || entries[0].Size != uint64(len(text)) {
		t.Errorf("entry 0 = %+v", entries[0])
	}
	if entries[0].CRC32 == nil || *entries[0].CRC32 != foundation.CRC32(text) {
		t.Errorf("crc = %v", entries[0].CRC32)
	}
	if !entries[1].IsDir() || entries[1].Path != "data" {
		t.Errorf("entry 1 = %+v", entries[1])
	}
	if entries[2].Path != "data/records.csv" || entries[2].Size != uint64(len(csv)) {
		t.Errorf("entry 2 = %+v", entries[2])
	}
	if entries[2].CompressedSize == nil || *entries[2].CompressedSize != uint64(len(deflate(t, csv))) {
		t.Errorf("compressed size = %v", entries[2].CompressedSize)
	}
	if entries[3].Path != "记录.txt" {
		t.Errorf("entry 3 path = %q", entries[3].Path)
	}

	stored, err := reader.OpenEntry("readme.txt", 10)
	if err != nil {
		t.Fatalf("open stored: %v", err)
	}
	if stored.SourceID() != 10 || stored.Len() != uint64(len(text)) {
		t.Fatalf("stored id=%d len=%d", stored.SourceID(), stored.Len())
	}
	if got := readAll(t, stored); !bytes.Equal(got, text) {
		t.Errorf("stored bytes = %q", got)
	}

	deflated, err := reader.OpenEntry("data/records.csv", 11)
	if err != nil {
		t.Fatalf("open deflated: %v", err)
	}
	if got := readAll(t, deflated); !bytes.Equal(got, csv) {
		t.Errorf("deflated bytes = %q", got)
	}

	buf := make([]byte, 4)
	if n, err := deflated.ReadAt(3, buf); err != nil || n != 4 || string(buf) != "name" {
		t.Fatalf("random read: n=%d err=%v buf=%q", n, err, buf)
	}
}

func TestZip64SizesAndOffsetsAreResolved(t *testing.T) {
	data := []byte("zip64 payload")
	spec := fileSpec("big.txt", data)
	spec.zip64 = true
	reader := openBytes(t, buildZip(t, []zipSpec{spec}, ""))
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Size != uint64(len(data)) {
		t.Fatalf("entries = %+v", entries)
	}
	stream, err := reader.OpenEntry("big.txt", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, stream); !bytes.Equal(got, data) {
		t.Errorf("bytes = %q", got)
	}
}

func TestEntryExtentsMapToTheCompressedPayload(t *testing.T) {
	data := []byte("abcdefghij")
	reader := openBytes(t, buildZip(t, []zipSpec{
		fileSpec("stored.bin", data),
		deflatedSpec("deflated.bin", data),
	}, ""))

	stored, err := reader.OpenEntry("stored.bin", 2)
	if err != nil {
		t.Fatalf("open stored: %v", err)
	}
	zs := stored.(*EntrySource)
	extents, err := stored.Extents(2, 3)
	if err != nil {
		t.Fatalf("extents: %v", err)
	}
	if len(extents) != 1 || extents[0].ParentOffset != zs.DataOffset()+2 || extents[0].Len != 3 {
		t.Errorf("stored extents = %+v", extents)
	}

	deflated, err := reader.OpenEntry("deflated.bin", 3)
	if err != nil {
		t.Fatalf("open deflated: %v", err)
	}
	dz := deflated.(*EntrySource)
	extents, err = deflated.Extents(2, 3)
	if err != nil {
		t.Fatalf("deflated extents: %v", err)
	}
	if len(extents) != 1 || extents[0].ParentOffset != dz.DataOffset() || extents[0].Len != dz.CompressedSize() {
		t.Errorf("deflated extents = %+v", extents)
	}
}

func TestIdentifiesEncryptionSymlinksAndUnsupportedMethods(t *testing.T) {
	secret := fileSpec("secret.bin", []byte("not really encrypted"))
	secret.flags |= testGPEncrypted

	aesExtra := make([]byte, 11)
	put16(aesExtra, 0, 0x9901)
	put16(aesExtra, 2, 7)
	put16(aesExtra, 4, 2) // AE-2
	copy(aesExtra[6:8], "AE")
	aesExtra[8] = 3 // AES-256
	put16(aesExtra, 9, testMethodDeflated)
	aes := zipSpec{
		name:   "aes.bin",
		data:   []byte("ciphertext-ish"),
		method: 99,
		flags:  testGPUTF8,
		extra:  aesExtra,
		zip64:  false,
	}

	link := fileSpec("link", []byte("target"))
	link.externalAttrs = 0o120777 << 16

	ppmd := fileSpec("ppmd.bin", []byte("payload"))
	ppmd.method = 98

	reader := openBytes(t, buildZip(t, []zipSpec{secret, aes, link, ppmd}, ""))
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if !entries[0].Encrypted {
		t.Error("secret.bin should list as encrypted")
	}
	if !entries[1].Encrypted {
		t.Error("aes.bin should list as encrypted")
	}
	if entries[2].Kind != archive.KindSymlink {
		t.Errorf("link kind = %v", entries[2].Kind)
	}
	if _, err := reader.OpenEntry("secret.bin", 2); !errors.Is(err, archive.ErrEncrypted) {
		t.Errorf("secret open error = %v", err)
	}
	if _, err := reader.OpenEntry("aes.bin", 2); !errors.Is(err, archive.ErrEncrypted) {
		t.Errorf("aes open error = %v", err)
	}
	if _, err := reader.OpenEntry("ppmd.bin", 3); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("ppmd open error = %v", err)
	}
	if _, err := reader.OpenEntry("missing", 4); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("missing open error = %v", err)
	}
}

func TestCrcMismatchIsReportedButDataRemainsReadable(t *testing.T) {
	data := []byte("forensic bytes")
	bad := foundation.CRC32([]byte("different"))
	spec := fileSpec("bad.txt", data)
	spec.crcOverride = &bad
	reader := openBytes(t, buildZip(t, []zipSpec{spec}, ""))
	stream, err := reader.OpenEntry("bad.txt", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, stream); !bytes.Equal(got, data) {
		t.Errorf("bytes = %q", got)
	}
	if stream.Stats().CorruptBytes == 0 {
		t.Error("the CRC mismatch should be counted as corrupt bytes")
	}
}

func TestEnforcesEntryAndSizeLimits(t *testing.T) {
	data := buildZip(t, []zipSpec{
		fileSpec("a", []byte("a")),
		fileSpec("b", []byte("b")),
		fileSpec("c", []byte("c")),
	}, "")
	limits := archive.DefaultLimits()
	limits.MaxEntries = 2
	if _, err := Open(source.NewMemorySource(1, data), limits); !errors.Is(err, archive.ErrLimit) {
		t.Errorf("error = %v", err)
	}
}

func TestRejectsTraversalNamesAndMissingTrailers(t *testing.T) {
	if _, err := Open(source.NewMemorySource(1, buildZip(t, []zipSpec{fileSpec("../escape", []byte("x"))}, "")), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("traversal error = %v", err)
	}

	truncated := buildZip(t, []zipSpec{fileSpec("a", []byte("x"))}, "")
	truncated = truncated[:len(truncated)-8]
	if _, err := Open(source.NewMemorySource(1, truncated), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("truncated error = %v", err)
	}
}

func TestRejectsACorruptLocalHeader(t *testing.T) {
	data := buildZip(t, []zipSpec{fileSpec("a.txt", []byte("payload"))}, "")
	copy(data[:4], "XXXX")
	reader := openBytes(t, data)
	if _, err := reader.OpenEntry("a.txt", 2); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestEndOfCentralDirectoryCommentLengthIsExact(t *testing.T) {
	comment := "forensic comment"
	data := buildZip(t, []zipSpec{fileSpec("a.txt", []byte("payload"))}, comment)
	reader := openBytes(t, data)
	if _, ok, err := reader.FindEntry("a.txt"); err != nil || !ok {
		t.Fatalf("find = %v %v", ok, err)
	}
}

func TestRejectsDirectoriesAndDecoys(t *testing.T) {
	dir := fileSpec("data/", nil)
	reader := openBytes(t, buildZip(t, []zipSpec{dir}, ""))
	if _, err := reader.OpenEntry("data", 2); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("directory open error = %v", err)
	}
	if _, err := Open(source.NewMemorySource(1, []byte("this is not a zip file at all")), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("decoy error = %v", err)
	}
}

func TestMapsThroughTheParentImage(t *testing.T) {
	data := []byte("mapped bytes")
	parent := source.NewMemorySourceWithImage(1, 9, buildZip(t, []zipSpec{fileSpec("a.txt", data)}, ""))
	reader, err := Open(parent, archive.DefaultLimits())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	stream, err := reader.OpenEntry("a.txt", 2)
	if err != nil {
		t.Fatalf("open entry: %v", err)
	}
	mapped, err := stream.MapToImage(0, 3)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	zs := stream.(*EntrySource)
	if len(mapped) != 1 || mapped[0].ImageID != 9 || mapped[0].ImageOffset != zs.DataOffset() || mapped[0].Len != 3 {
		t.Errorf("mapped = %+v", mapped)
	}
}

func TestDecodesCP437AndDosTimes(t *testing.T) {
	if len(cp437Runes) != 128 {
		t.Fatalf("the CP437 table has %d runes, want 128", len(cp437Runes))
	}
	if cp437(0xFF) != ' ' {
		t.Errorf("cp437(0xFF) = %U, want U+00A0", cp437(0xFF))
	}
	got, err := decodeName([]byte{0x82}, false)
	if err != nil || got != "é" {
		t.Errorf("cp437(0x82) = %q, %v", got, err)
	}
	date := uint16((2020-1980)<<9 | (1 << 5) | 2)
	time := uint16(3<<11 | 4<<5 | 6/2)
	stamp := dosDateTime(date, time)
	if stamp == nil || *stamp != 1_577_934_246 {
		t.Errorf("dos datetime = %v", stamp)
	}
	if dosDateTime(0, 0) != nil {
		t.Error("zero date should be absent")
	}
}

func TestRegistryRegistersZipApkAndJar(t *testing.T) {
	registry := archive.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("register: %v", err)
	}
	if registry.Len() != 3 {
		t.Fatalf("len = %d", registry.Len())
	}
	data := buildZip(t, []zipSpec{fileSpec("a", []byte("x"))}, "")
	for _, id := range []string{"zip", "apk", "jar"} {
		reader, err := registry.Open(id, source.NewMemorySource(1, data), archive.DefaultLimits())
		if err != nil {
			t.Fatalf("open %s: %v", id, err)
		}
		if reader.FormatID() != id {
			t.Errorf("format id = %q, want %q", reader.FormatID(), id)
		}
		entries, err := reader.Entries()
		if err != nil || len(entries) != 1 {
			t.Errorf("%s entries = %v %v", id, entries, err)
		}
	}
}
