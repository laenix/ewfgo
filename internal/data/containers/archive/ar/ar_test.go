package ar

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

const testMtime = uint64(1_700_000_000)

func member(name string, data []byte) []byte {
	header := bytes.Repeat([]byte{' '}, 60)
	if len(name) > 16 {
		panic("fixture name too long")
	}
	copy(header, name)
	put := func(field []byte, text string) {
		if len(text) > len(field) {
			panic("fixture field too wide")
		}
		copy(field, text)
	}
	put(header[16:28], strconv.FormatUint(testMtime, 10))
	put(header[28:34], "0")
	put(header[34:40], "0")
	put(header[40:48], "100644")
	put(header[48:58], strconv.Itoa(len(data)))
	header[58] = '`'
	header[59] = '\n'

	out := append([]byte{}, header...)
	out = append(out, data...)
	if len(data)%2 == 1 {
		out = append(out, '\n')
	}
	return out
}

func archiveBytes(members ...[]byte) []byte {
	out := append([]byte{}, Magic...)
	for _, m := range members {
		out = append(out, m...)
	}
	return out
}

func openBytes(t *testing.T, data []byte) *Reader {
	t.Helper()
	reader, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("open ar: %v", err)
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

func TestGnuLongNamesAndHeadersAreResolved(t *testing.T) {
	table := []byte("a-very-long-object-name.o/\n")
	reader := openBytes(t, archiveBytes(
		member("/", []byte{0, 0, 0, 0}),
		member("//", table),
		member("/0", []byte("long payload")),
		member("short.o/", []byte("five\n")),
	))
	if reader.Stats().SymbolTables != 1 || reader.Stats().LongNameTables != 1 {
		t.Errorf("stats = %+v", reader.Stats())
	}
	entries, err := reader.Entries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %v %v", entries, err)
	}

	long, ok, err := reader.FindEntry("a-very-long-object-name.o")
	if err != nil || !ok {
		t.Fatalf("find long = %v %v", ok, err)
	}
	if long.Size != 12 || long.Modified == nil || *long.Modified != int64(testMtime) {
		t.Errorf("long = %+v", long)
	}
	if _, ok, err := reader.FindEntry("short.o"); err != nil || !ok {
		t.Fatalf("find short = %v %v", ok, err)
	}

	stream, err := reader.OpenEntry("a-very-long-object-name.o", 2)
	if err != nil {
		t.Fatalf("open long: %v", err)
	}
	if got := readAll(t, stream); string(got) != "long payload" {
		t.Errorf("bytes = %q", got)
	}
	stream, err = reader.OpenEntry("short.o", 3)
	if err != nil {
		t.Fatalf("open short: %v", err)
	}
	if got := readAll(t, stream); string(got) != "five\n" {
		t.Errorf("bytes = %q", got)
	}
}

func TestBsdNamesAreStoredInTheDataArea(t *testing.T) {
	name := []byte("bsd-name.o")
	data := append(append([]byte{}, name...), []byte("payload")...)
	reader := openBytes(t, archiveBytes(member("#1/10", data)))
	entry, ok, err := reader.FindEntry("bsd-name.o")
	if err != nil || !ok {
		t.Fatalf("find = %v %v", ok, err)
	}
	if entry.Size != 7 {
		t.Errorf("size = %d", entry.Size)
	}
	stream, err := reader.OpenEntry("bsd-name.o", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, stream); string(got) != "payload" {
		t.Errorf("bytes = %q", got)
	}
}

func TestThinArchivesAreRefusedByName(t *testing.T) {
	data := append([]byte{}, ThinMagic...)
	data = append(data, member("short.o/", []byte("x\n"))...)
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("error = %v", err)
	}
}

func TestHeaderWithoutTheTrailerIsRefused(t *testing.T) {
	data := archiveBytes(member("short.o/", []byte("ab")))
	data[len(Magic)+58] = 'x'
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestLongNameOffsetOutsideTheTableIsRefused(t *testing.T) {
	data := archiveBytes(member("//", []byte("abc/\n")), member("/9", []byte("data")))
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestMemberThatRunsPastTheArchiveIsRefused(t *testing.T) {
	data := archiveBytes(member("short.o/", []byte("abc")))
	data = data[:len(data)-2]
	if _, err := Open(source.NewMemorySource(1, data), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
}

func TestUnsafeNamesAreCountedNotListed(t *testing.T) {
	reader := openBytes(t, archiveBytes(
		member("../escape.o/", []byte("x\n")),
		member("safe.o/", []byte("ok\n")),
	))
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 || entries[0].Path != "safe.o" {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if reader.Stats().SkippedUnsafe != 1 {
		t.Errorf("skipped = %d", reader.Stats().SkippedUnsafe)
	}
	if _, ok, err := reader.FindEntry("safe.o"); err != nil || !ok {
		t.Errorf("find = %v %v", ok, err)
	}
}

func TestTrailingNewlinesAreAcceptedAndCounted(t *testing.T) {
	data := archiveBytes(member("a.o/", []byte("ab")))
	data = append(data, '\n', '\n')
	reader := openBytes(t, data)
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	if reader.Stats().TrailingBytes != 2 {
		t.Errorf("trailing = %d", reader.Stats().TrailingBytes)
	}
}

func TestRegistryAdapterReadsAMember(t *testing.T) {
	registry := archive.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("register: %v", err)
	}
	reader, err := registry.Open("ar", source.NewMemorySource(1, archiveBytes(member("obj.o/", []byte("data")))), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if reader.FormatID() != "ar" {
		t.Errorf("format id = %q", reader.FormatID())
	}
	stream, err := reader.OpenEntry("obj.o", 2)
	if err != nil {
		t.Fatalf("open entry: %v", err)
	}
	if got := readAll(t, stream); string(got) != "data" {
		t.Errorf("bytes = %q", got)
	}
}

func TestRejectsADecoySignature(t *testing.T) {
	if _, err := Open(source.NewMemorySource(1, []byte("!<arch>\nnot really")), archive.DefaultLimits()); !errors.Is(err, archive.ErrInvalid) {
		t.Errorf("error = %v", err)
	}
	if _, err := Open(source.NewMemorySource(1, []byte("short")), archive.DefaultLimits()); !errors.Is(err, archive.ErrUnsupported) {
		t.Errorf("short error = %v", err)
	}
}

func TestBudgetIsEnforced(t *testing.T) {
	data := archiveBytes(member("a.o/", []byte("ab")), member("b.o/", []byte("cd")))
	limits := archive.DefaultLimits()
	limits.MaxEntries = 1
	if _, err := Open(source.NewMemorySource(1, data), limits); !errors.Is(err, archive.ErrLimit) {
		t.Errorf("error = %v", err)
	}
}
