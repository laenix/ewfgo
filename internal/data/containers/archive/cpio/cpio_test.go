package cpio

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	newcMagic   = "070701"
	crcMagic    = "070702"
	odcMagic    = "070707"
	binaryMagic = 0o70707
	trailerName = "TRAILER!!!"
	testMtime   = uint32(1_700_000_000)

	sIFMT   = 0o170000
	sIFIFO  = 0o010000
	sIFCHR  = 0o020000
	sIFDIR  = 0o040000
	sIFBLK  = 0o060000
	sIFREG  = 0o100000
	sIFLNK  = 0o120000
	sIFSOCK = 0o140000
)

type spec struct {
	name  string
	mode  uint32
	data  []byte
	ino   uint64
	nlink uint32
	mtime uint32
}

func fileSpec(name string, data []byte) spec {
	return spec{name: name, mode: sIFREG | 0o644, data: data, ino: uint64(len(name) + 1), nlink: 1, mtime: testMtime}
}

func dirSpec(name string) spec {
	s := fileSpec(name, nil)
	s.mode = sIFDIR | 0o755
	return s
}

func symlinkSpec(name string, target []byte) spec {
	s := fileSpec(name, target)
	s.mode = sIFLNK | 0o777
	return s
}

func pushNewc(out *[]byte, s spec, magic string) {
	header := make([]byte, 0, 110)
	header = append(header, magic...)
	check := uint32(0)
	if magic == crcMagic {
		for _, b := range s.data {
			check += uint32(b)
		}
	}
	for _, value := range []uint64{
		s.ino, uint64(s.mode), 1000, 1000, uint64(s.nlink), uint64(s.mtime),
		uint64(len(s.data)), 0, 0, 0, 0, uint64(len(s.name) + 1), uint64(check),
	} {
		header = append(header, []byte(fmt.Sprintf("%08x", value))...)
	}
	if len(header) != 110 {
		panic("newc header length")
	}
	*out = append(*out, header...)
	*out = append(*out, s.name...)
	*out = append(*out, 0)
	pad4(out)
	*out = append(*out, s.data...)
	pad4(out)
}

func pad4(out *[]byte) {
	padding := (4 - len(*out)%4) % 4
	*out = append(*out, make([]byte, padding)...)
}

func newc(entries []spec, magic string, trailerPadding int) []byte {
	var out []byte
	for _, s := range entries {
		pushNewc(&out, s, magic)
	}
	pushNewc(&out, spec{name: trailerName, mtime: 0}, magic)
	out = append(out, make([]byte, trailerPadding)...)
	return out
}

func pushOdc(out *[]byte, s spec) {
	*out = append(*out, odcMagic...)
	fields := []struct {
		width int
		value uint64
	}{
		{6, 0},
		{6, s.ino},
		{6, uint64(s.mode)},
		{6, 1000},
		{6, 1000},
		{6, uint64(s.nlink)},
		{6, 0},
		{11, uint64(s.mtime)},
		{6, uint64(len(s.name) + 1)},
		{11, uint64(len(s.data))},
	}
	for _, f := range fields {
		*out = append(*out, []byte(fmt.Sprintf("%0*o", f.width, f.value))...)
	}
	*out = append(*out, s.name...)
	*out = append(*out, 0)
	*out = append(*out, s.data...)
}

func odc(entries []spec) []byte {
	var out []byte
	for _, s := range entries {
		pushOdc(&out, s)
	}
	pushOdc(&out, spec{name: trailerName, mtime: 0})
	return out
}

func pushBinary(out *[]byte, s spec, order BinaryOrder) {
	word := func(value uint16) {
		if order == OrderBig {
			*out = append(*out, byte(value>>8), byte(value))
		} else {
			*out = append(*out, byte(value), byte(value>>8))
		}
	}
	size := uint32(len(s.data))
	word(binaryMagic)
	word(0)
	word(uint16(s.ino))
	word(uint16(s.mode))
	word(1000)
	word(1000)
	word(uint16(s.nlink))
	word(0)
	word(uint16(s.mtime >> 16))
	word(uint16(s.mtime))
	word(uint16(len(s.name) + 1))
	word(uint16(size >> 16))
	word(uint16(size))
	*out = append(*out, s.name...)
	*out = append(*out, 0)
	if len(*out)%2 == 1 {
		*out = append(*out, 0)
	}
	*out = append(*out, s.data...)
	if len(*out)%2 == 1 {
		*out = append(*out, 0)
	}
}

func binary(entries []spec, order BinaryOrder) []byte {
	var out []byte
	for _, s := range entries {
		pushBinary(&out, s, order)
	}
	pushBinary(&out, spec{name: trailerName, mtime: 0}, order)
	return out
}

func openBytes(t *testing.T, data []byte) *Reader {
	t.Helper()
	reader, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("open cpio: %v", err)
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

func TestNewcListsFilesDirectoriesAndSymlinksAtAlignedOffsets(t *testing.T) {
	reader := openBytes(t, newc([]spec{
		fileSpec("init", []byte("#!/bin/sh\n")),
		dirSpec("etc"),
		symlinkSpec("etc/localtime", []byte("/usr/share/zoneinfo/UTC")),
		fileSpec("etc/hostname", []byte("evidence\n")),
	}, newcMagic, 512))

	if reader.Dialect() != DialectNewc {
		t.Errorf("dialect = %v", reader.Dialect())
	}
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %d", len(entries))
	}
	if reader.TrailingBytes() != 512 {
		t.Errorf("trailing = %d", reader.TrailingBytes())
	}
	if reader.Stats().Entries != 4 || reader.Stats().SkippedDots != 0 {
		t.Errorf("stats = %+v", reader.Stats())
	}

	raw := reader.RawEntries()
	if raw[0].Name != "init" || raw[0].Kind != EntryFile || raw[0].DataOffset != 116 || raw[0].Size != 10 {
		t.Errorf("entry 0 = %+v", raw[0])
	}
	if raw[0].Modified == nil || *raw[0].Modified != int64(testMtime) {
		t.Errorf("mtime = %v", raw[0].Modified)
	}
	if raw[1].HeaderOffset != 128 || raw[1].Kind != EntryDirectory {
		t.Errorf("entry 1 = %+v", raw[1])
	}
	if raw[2].Kind != EntrySymlink || raw[2].Link != "/usr/share/zoneinfo/UTC" {
		t.Errorf("entry 2 = %+v", raw[2])
	}
	if entries[3].Path != "etc/hostname" {
		t.Errorf("entry 3 path = %q", entries[3].Path)
	}

	stream, err := reader.OpenEntry("init", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if stream.SourceID() != 2 || stream.Len() != 10 {
		t.Fatalf("stream id=%d len=%d", stream.SourceID(), stream.Len())
	}
	if got := readAll(t, stream); string(got) != "#!/bin/sh\n" {
		t.Errorf("bytes = %q", got)
	}
	if _, err := reader.OpenEntry("etc", 3); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("directory open error = %v", err)
	}
}

func TestHardLinkReadsTheDataStoredWithTheLast(t *testing.T) {
	first := fileSpec("bin/sh", nil)
	first.ino = 77
	first.nlink = 2
	second := fileSpec("bin/busybox", []byte("ELF-ish payload"))
	second.ino = 77
	second.nlink = 2

	reader := openBytes(t, newc([]spec{first, second}, newcMagic, 0))
	raw := reader.RawEntries()
	if raw[0].DeclaredSize != 0 || raw[0].Size != 15 {
		t.Errorf("hardlink sizes = declared %d size %d", raw[0].DeclaredSize, raw[0].Size)
	}
	if raw[0].HardlinkOf != "bin/busybox" {
		t.Errorf("hardlink_of = %q", raw[0].HardlinkOf)
	}
	if raw[0].DataOffset != raw[1].DataOffset {
		t.Errorf("data offsets differ")
	}
	if reader.Stats().UnresolvedHardlinks != 0 {
		t.Errorf("unresolved = %d", reader.Stats().UnresolvedHardlinks)
	}
	stream, err := reader.OpenEntry("bin/sh", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, stream); string(got) != "ELF-ish payload" {
		t.Errorf("bytes = %q", got)
	}
}

func TestHardLinkWithoutItsDataMemberIsCountedAndStaysEmpty(t *testing.T) {
	orphan := fileSpec("lost", nil)
	orphan.ino = 9
	orphan.nlink = 3
	reader := openBytes(t, newc([]spec{orphan}, newcMagic, 0))
	raw := reader.RawEntries()
	if raw[0].Size != 0 {
		t.Errorf("size = %d", raw[0].Size)
	}
	if reader.Stats().UnresolvedHardlinks != 1 {
		t.Errorf("unresolved = %d", reader.Stats().UnresolvedHardlinks)
	}
}

func TestCrcDialectRecordsTheByteSum(t *testing.T) {
	reader := openBytes(t, newc([]spec{fileSpec("sum", []byte{1, 2, 3, 250})}, crcMagic, 0))
	if reader.Dialect() != DialectCrc {
		t.Errorf("dialect = %v", reader.Dialect())
	}
	raw := reader.RawEntries()
	if raw[0].Check != 1+2+3+250 {
		t.Errorf("check = %d", raw[0].Check)
	}
	stream, err := reader.OpenEntry("sum", 3)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, stream); !bytes.Equal(got, []byte{1, 2, 3, 250}) {
		t.Errorf("bytes = %v", got)
	}
}

func TestOdcHasNoPaddingBetweenEntries(t *testing.T) {
	reader := openBytes(t, odc([]spec{fileSpec("a", []byte("x")), fileSpec("bb", []byte("yz"))}))
	if reader.Dialect() != DialectOdc {
		t.Errorf("dialect = %v", reader.Dialect())
	}
	raw := reader.RawEntries()
	if raw[0].DataOffset != 78 {
		t.Errorf("entry 0 data offset = %d", raw[0].DataOffset)
	}
	if raw[1].HeaderOffset != 79 {
		t.Errorf("entry 1 header offset = %d", raw[1].HeaderOffset)
	}
	if raw[1].DataOffset != 79+76+3 {
		t.Errorf("entry 1 data offset = %d", raw[1].DataOffset)
	}
	if reader.TrailingBytes() != 0 {
		t.Errorf("trailing = %d", reader.TrailingBytes())
	}
}

func TestDotEntriesAreSkippedAndCounted(t *testing.T) {
	reader := openBytes(t, newc([]spec{dirSpec("."), fileSpec("real", []byte("data"))}, newcMagic, 0))
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if entries[0].Path != "real" {
		t.Errorf("path = %q", entries[0].Path)
	}
	if reader.Stats().SkippedDots != 1 {
		t.Errorf("skipped dots = %d", reader.Stats().SkippedDots)
	}
}

func TestTruncatedDataAreaIsRefusedAtItsHeader(t *testing.T) {
	data := newc([]spec{fileSpec("cut", []byte("0123456789"))}, newcMagic, 0)
	data = data[:120]
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestStreamWithoutATrailerIsTorn(t *testing.T) {
	data := newc([]spec{fileSpec("only", []byte("x"))}, newcMagic, 0)
	nameAt := bytes.Index(data, []byte(trailerName))
	if nameAt < 0 {
		t.Fatal("trailer not found")
	}
	data = data[:nameAt-110]
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestBinaryHeadersReadInBothByteOrders(t *testing.T) {
	for _, order := range []BinaryOrder{OrderLittle, OrderBig} {
		dir := dirSpec("etc")
		link := symlinkSpec("etc/link", []byte("target"))
		file := fileSpec("bb", []byte("data"))
		file.ino = 4
		reader := openBytes(t, binary([]spec{dir, link, file}, order))
		gotOrder := reader.BinaryOrder()
		if reader.Dialect() != DialectBinary || gotOrder == nil || *gotOrder != order {
			t.Errorf("dialect/order = %v/%v", reader.Dialect(), gotOrder)
		}
		raw := reader.RawEntries()
		if len(raw) != 3 {
			t.Fatalf("entries = %d", len(raw))
		}
		if raw[0].Name != "etc" || raw[0].DataOffset != 30 {
			t.Errorf("entry 0 = %+v", raw[0])
		}
		if raw[0].Modified == nil || *raw[0].Modified != int64(testMtime) {
			t.Errorf("mtime = %v", raw[0].Modified)
		}
		if raw[1].Kind != EntrySymlink || raw[1].Link != "target" {
			t.Errorf("entry 1 = %+v", raw[1])
		}
		if raw[1].DataOffset != 30+26+9+1 {
			t.Errorf("entry 1 data offset = %d", raw[1].DataOffset)
		}
		if raw[2].DataOffset != raw[2].HeaderOffset+26+3+1 {
			t.Errorf("entry 2 data offset = %d", raw[2].DataOffset)
		}
		if raw[2].Ino != 4 {
			t.Errorf("ino = %d", raw[2].Ino)
		}
		if reader.TrailingBytes() != 0 {
			t.Errorf("trailing = %d", reader.TrailingBytes())
		}
		stream, err := reader.OpenEntry("bb", 6)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if got := readAll(t, stream); string(got) != "data" {
			t.Errorf("bytes = %q", got)
		}
	}
}

func TestBinaryArchiveCutInsideItsHeaderIsRefused(t *testing.T) {
	data := []byte{0xC7, 0x71, 0, 0, 0, 0, 0, 0}
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestBinaryDataAreaPastTheEndIsRefused(t *testing.T) {
	data := binary([]spec{fileSpec("cut", []byte("0123456789"))}, OrderLittle)
	data = data[:30]
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestEntryWithoutFileTypeBitsIsRefused(t *testing.T) {
	odd := fileSpec("odd", nil)
	odd.mode = 0o644
	if _, err := Open(source.NewMemorySource(1, newc([]spec{odd}, newcMagic, 0)), archive.DefaultLimits()); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("error = %v", err)
	}
}

func TestRegistryListsMembersAndReadsAFileBack(t *testing.T) {
	registry := archive.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("register: %v", err)
	}
	data := newc([]spec{
		fileSpec("init", []byte("#!/bin/sh\n")),
		fileSpec("etc/hostname", []byte("evidence\n")),
	}, newcMagic, 0)
	reader, err := registry.Open("cpio", source.NewMemorySource(8, data), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if reader.FormatID() != "cpio" {
		t.Errorf("format id = %q", reader.FormatID())
	}
	entries, err := reader.Entries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if entries[0].Kind != archive.KindFile {
		t.Errorf("kind = %v", entries[0].Kind)
	}
	if entries[0].Modified == nil || *entries[0].Modified != int64(testMtime) {
		t.Errorf("mtime = %v", entries[0].Modified)
	}
	stream, err := reader.OpenEntry("init", 9)
	if err != nil {
		t.Fatalf("open entry: %v", err)
	}
	if got := readAll(t, stream); string(got) != "#!/bin/sh\n" {
		t.Errorf("bytes = %q", got)
	}
}

func TestUnsafeNamesAreSkippedAndCounted(t *testing.T) {
	reader := openBytes(t, newc([]spec{fileSpec("../escape", []byte("x")), fileSpec("safe", []byte("y"))}, newcMagic, 0))
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 || entries[0].Path != "safe" {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if reader.Stats().SkippedUnsafe != 1 {
		t.Errorf("skipped unsafe = %d", reader.Stats().SkippedUnsafe)
	}
}

func TestRejectsUnknownMagic(t *testing.T) {
	if _, err := Open(source.NewMemorySource(1, []byte("not a cpio archive")), archive.DefaultLimits()); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("error = %v", err)
	}
}
