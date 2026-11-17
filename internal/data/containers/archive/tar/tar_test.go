package tar

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	blockSize = 512
	testMtime = int64(1_700_000_000)
)

type spec struct {
	name           string
	prefix         string
	link           string
	size           uint64
	mode           uint32
	flag           byte
	mtime          uint64
	signedChecksum bool
	base256Size    *uint64
}

func fileSpec(name string, size uint64) spec {
	return spec{name: name, size: size, mode: 0o644, flag: '0', mtime: uint64(testMtime)}
}

func dirSpec(name string) spec {
	s := fileSpec(name, 0)
	s.flag = '5'
	s.mode = 0o755
	return s
}

func linkSpec(name string, flag byte, target string) spec {
	s := fileSpec(name, 0)
	s.flag = flag
	s.link = target
	return s
}

func (s spec) withPrefix(prefix string) spec {
	s.prefix = prefix
	return s
}

func (s spec) signed() spec {
	s.signedChecksum = true
	return s
}

func (s spec) base256(size uint64) spec {
	s.base256Size = &size
	return s
}

func writeOctal(field []byte, value uint64) {
	for i := range field {
		field[i] = 0
	}
	digits := strconv.FormatUint(value, 8)
	if len(digits) >= len(field) {
		panic("octal value too wide")
	}
	start := len(field) - 1 - len(digits)
	copy(field[start:], digits)
}

func writeBase256(field []byte, value uint64) {
	for i := range field {
		field[i] = 0
	}
	field[0] = 0x80
	encoded := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		encoded[i] = byte(value)
		value >>= 8
	}
	copy(field[len(field)-len(encoded):], encoded)
}

func finalize(block []byte, signed bool) []byte {
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	var unsigned uint64
	var signedSum int64
	for _, b := range block {
		unsigned += uint64(b)
		signedSum += int64(int8(b))
	}
	stored := unsigned
	if signed && signedSum >= 0 {
		stored = uint64(signedSum)
	}
	writeOctal(block[148:156], stored)
	return block
}

func tarHeader(s spec) []byte {
	if len(s.name) >= 100 || len(s.prefix) >= 155 || len(s.link) >= 100 {
		panic("fixture field too wide")
	}
	block := make([]byte, blockSize)
	copy(block[0:], s.name)
	writeOctal(block[100:108], uint64(s.mode))
	writeOctal(block[108:116], 1000)
	writeOctal(block[116:124], 1000)
	if s.base256Size != nil {
		writeBase256(block[124:136], *s.base256Size)
	} else {
		writeOctal(block[124:136], s.size)
	}
	writeOctal(block[136:148], s.mtime)
	block[156] = s.flag
	copy(block[157:], s.link)
	copy(block[257:263], "ustar\x00")
	copy(block[263:265], "00")
	copy(block[265:269], "root")
	copy(block[297:301], "root")
	copy(block[345:], s.prefix)
	return finalize(block, s.signedChecksum)
}

func pushRaw(out *[]byte, s spec, data []byte) {
	*out = append(*out, tarHeader(s)...)
	*out = append(*out, data...)
	padding := (blockSize - len(data)%blockSize) % blockSize
	*out = append(*out, make([]byte, padding)...)
}

func push(out *[]byte, s spec, data []byte) {
	if s.size != uint64(len(data)) {
		panic("fixture size does not match data")
	}
	pushRaw(out, s, data)
}

func terminate(out *[]byte) {
	*out = append(*out, make([]byte, 2*blockSize)...)
}

func paxRecord(key, value string) string {
	body := key + "=" + value + "\n"
	length := len(body) + 2
	for {
		total := len(strconv.Itoa(length)) + 1 + len(body)
		if total == length {
			return strconv.Itoa(length) + " " + body
		}
		length = total
	}
}

func openBytes(t *testing.T, data []byte) *Reader {
	t.Helper()
	reader, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("open tar: %v", err)
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

func TestUstarListsFilesDirectoriesAndLinks(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/sh\n")
	notes := []byte("long-name payload\n")
	prefix := "very/long/directory/structure/that/uses/the/prefix/field/of/ustar"
	baseName := "a_file_name_that_is_quite_long_and_pushes_the_total_over_one_hundred_bytes.txt"

	var data []byte
	push(&data, fileSpec("etc/passwd", uint64(len(passwd))), passwd)
	push(&data, dirSpec("var/log/"), nil)
	push(&data, linkSpec("etc/link", '2', "/etc/passwd"), nil)
	push(&data, linkSpec("etc/passwd.hard", '1', "etc/passwd"), nil)
	push(&data, fileSpec(baseName, uint64(len(notes))).withPrefix(prefix), notes)
	terminate(&data)

	reader := openBytes(t, data)
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Path != "etc/passwd" || entries[0].Size != uint64(len(passwd)) {
		t.Errorf("entry 0 = %+v", entries[0])
	}
	if entries[0].Modified == nil || *entries[0].Modified != testMtime {
		t.Errorf("mtime = %v", entries[0].Modified)
	}
	if entries[1].Kind != archive.KindDirectory || entries[1].Path != "var/log" {
		t.Errorf("entry 1 = %+v", entries[1])
	}
	if entries[2].Kind != archive.KindSymlink {
		t.Errorf("entry 2 kind = %v", entries[2].Kind)
	}
	if entries[3].Kind != archive.KindOther {
		t.Errorf("hard link kind = %v", entries[3].Kind)
	}
	if entries[4].Path != prefix+"/"+baseName || entries[4].Size != uint64(len(notes)) {
		t.Errorf("entry 4 = %+v", entries[4])
	}
	if reader.TrailingBytes() != 0 {
		t.Errorf("trailing = %d", reader.TrailingBytes())
	}

	stream, err := reader.OpenEntry("etc/passwd", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if stream.SourceID() != 2 || stream.Len() != uint64(len(passwd)) {
		t.Fatalf("stream id=%d len=%d", stream.SourceID(), stream.Len())
	}
	if got := readAll(t, stream); !bytes.Equal(got, passwd) {
		t.Errorf("bytes = %q", got)
	}
	extents, err := stream.Extents(2, 3)
	if err != nil || len(extents) != 1 || extents[0].Len != 3 {
		t.Errorf("extents = %+v %v", extents, err)
	}

	if _, err := reader.OpenEntry("etc/link", 3); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("symlink open error = %v", err)
	}
	if _, err := reader.OpenEntry("var/log", 4); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("directory open error = %v", err)
	}
	if _, err := reader.OpenEntry("missing", 5); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("missing open error = %v", err)
	}
}

func TestGnuLongNameReplacesTheHeaderName(t *testing.T) {
	longName := "gnu/"
	for i := 0; i < 8; i++ {
		longName += "subdirectory/"
	}
	longName += "final-report.txt"
	if len(longName) <= 100 {
		t.Fatal("fixture name is not long")
	}
	payload := []byte(longName + "\x00")

	var data []byte
	push(&data, spec{name: "././@LongLink", size: uint64(len(payload)), mode: 0o644, flag: 'L', mtime: uint64(testMtime)}, payload)
	push(&data, fileSpec("truncated", 5), []byte("hello"))
	terminate(&data)

	reader := openBytes(t, data)
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if entries[0].Path != longName {
		t.Errorf("name = %q", entries[0].Path)
	}
	stream, err := reader.OpenEntry(longName, 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, stream); string(got) != "hello" {
		t.Errorf("bytes = %q", got)
	}
}

func TestPaxOverridesPathSizeLinkAndMtime(t *testing.T) {
	real := "pax/a path with spaces/and/unicode-中文.txt"
	payload := []byte("pax payload bytes")
	records := paxRecord("path", real) +
		paxRecord("linkpath", "target/elsewhere") +
		paxRecord("size", strconv.Itoa(len(payload))) +
		paxRecord("mtime", "1700000123.75")

	var data []byte
	push(&data, spec{name: "pax-placeholder", size: uint64(len(records)), mode: 0o644, flag: 'x', mtime: uint64(testMtime)}, []byte(records))
	pushRaw(&data, fileSpec("truncated-name", 0), payload)
	terminate(&data)

	reader := openBytes(t, data)
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if entries[0].Path != real {
		t.Errorf("path = %q", entries[0].Path)
	}
	if entries[0].Size != uint64(len(payload)) {
		t.Errorf("size = %d", entries[0].Size)
	}
	if entries[0].Modified == nil || *entries[0].Modified != 1_700_000_123 {
		t.Errorf("mtime = %v", entries[0].Modified)
	}
	stream, err := reader.OpenEntry(real, 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, stream); !bytes.Equal(got, payload) {
		t.Errorf("bytes = %q", got)
	}
}

func TestBase256SizeIsDecoded(t *testing.T) {
	data := bytes.Repeat([]byte("Z"), 700)
	var out []byte
	push(&out, fileSpec("large.bin", uint64(len(data))).base256(uint64(len(data))), data)
	terminate(&out)

	reader := openBytes(t, out)
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 || entries[0].Size != 700 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	stream, err := reader.OpenEntry("large.bin", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, stream); !bytes.Equal(got, data) {
		t.Errorf("bytes differ")
	}
}

func TestSignedChecksumsAreAccepted(t *testing.T) {
	data := []byte("café\n")
	var out []byte
	push(&out, fileSpec("café.txt", uint64(len(data))).signed(), data)
	terminate(&out)

	reader := openBytes(t, out)
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if entries[0].Path != "café.txt" || entries[0].Size != uint64(len(data)) {
		t.Errorf("entry = %+v", entries[0])
	}
}

func TestBadChecksumAfterFirstEntryIsCorrupt(t *testing.T) {
	var data []byte
	push(&data, fileSpec("first.txt", 3), []byte("one"))
	second := len(data)
	push(&data, fileSpec("second.txt", 3), []byte("two"))
	terminate(&data)
	data[second+20] ^= 0xFF

	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestTruncatedHeaderIsCorrupt(t *testing.T) {
	var data []byte
	push(&data, fileSpec("first.txt", 3), []byte("one"))
	data = append(data, tarHeader(fileSpec("second.txt", 0))[:200]...)
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestNonTarBufferIsNotClaimed(t *testing.T) {
	src := source.NewMemorySource(1, bytes.Repeat([]byte("X"), 2048))
	if Matches(src) {
		t.Error("random bytes should not match tar")
	}
	if _, err := Open(src, archive.DefaultLimits()); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("error = %v", err)
	}
}

func TestTwoZeroBlocksEndTheArchiveAndTrailingBytesAreCounted(t *testing.T) {
	var data []byte
	push(&data, fileSpec("only.txt", 4), []byte("data"))
	terminate(&data)
	trailing := []byte("appended evidence")
	data = append(data, trailing...)

	reader := openBytes(t, data)
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 || entries[0].Path != "only.txt" {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if reader.TrailingBytes() != uint64(len(trailing)) {
		t.Errorf("trailing = %d", reader.TrailingBytes())
	}
}

func TestUnknownTypeFlagsAndSparseRecordsAreRefused(t *testing.T) {
	var data []byte
	push(&data, spec{name: "weird", size: 0, mode: 0o644, flag: 'Z', mtime: uint64(testMtime)}, nil)
	terminate(&data)
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("unknown flag error = %v", err)
	}

	records := paxRecord("GNU.sparse.map", "0,100")
	var sparse []byte
	push(&sparse, spec{name: "pax-placeholder", size: uint64(len(records)), mode: 0o644, flag: 'x', mtime: uint64(testMtime)}, []byte(records))
	push(&sparse, fileSpec("sparse.bin", 100), make([]byte, 100))
	terminate(&sparse)
	if _, err := Open(source.NewMemorySource(1, sparse), archive.DefaultLimits()); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("sparse error = %v", err)
	}
}

func TestEnforcesBudget(t *testing.T) {
	var data []byte
	push(&data, fileSpec("a", 1), []byte("a"))
	push(&data, fileSpec("b", 1), []byte("b"))
	terminate(&data)
	limits := archive.DefaultLimits()
	limits.MaxEntries = 1
	if _, err := Open(source.NewMemorySource(1, data), limits); !errors.Is(err, archive.ErrLimit) {
		t.Errorf("error = %v", err)
	}
}

func TestRegistryAdapterListsAndReads(t *testing.T) {
	var data []byte
	push(&data, fileSpec("init", 10), []byte("#!/bin/sh\n"))
	terminate(&data)

	registry := archive.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("register: %v", err)
	}
	reader, err := registry.Open("tar", source.NewMemorySource(1, data), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if reader.FormatID() != "tar" {
		t.Errorf("format id = %q", reader.FormatID())
	}
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	stream, err := reader.OpenEntry("init", 9)
	if err != nil {
		t.Fatalf("open entry: %v", err)
	}
	if got := readAll(t, stream); string(got) != "#!/bin/sh\n" {
		t.Errorf("bytes = %q", got)
	}
}
