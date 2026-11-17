package archive

import (
	"errors"
	"math"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func mustEntry(t *testing.T, raw string, kind Kind, size uint64) Entry {
	t.Helper()
	entry, err := NewEntry(raw, kind, size)
	if err != nil {
		t.Fatalf("NewEntry(%q): %v", raw, err)
	}
	return entry
}

func TestSanitizeEntryPathNormalizes(t *testing.T) {
	cases := map[string]string{
		"dir\\file.txt": "dir/file.txt",
		"./a/./b":       "a/b",
		"a//b/":         "a/b",
		"照片/2026.jpg":   "照片/2026.jpg",
	}
	for raw, want := range cases {
		got, err := sanitizeEntryPath(raw)
		if err != nil {
			t.Fatalf("sanitizeEntryPath(%q): %v", raw, err)
		}
		if got != want {
			t.Errorf("sanitizeEntryPath(%q) = %q, want %q", raw, got, want)
		}
	}

	entry := mustEntry(t, "dir\\sub\\", KindDirectory, 0)
	if entry.Path != "dir/sub" {
		t.Errorf("path = %q, want dir/sub", entry.Path)
	}
	if entry.RawPath != "dir\\sub\\" {
		t.Errorf("raw path = %q", entry.RawPath)
	}
	if !entry.IsDir() {
		t.Error("entry should be a directory")
	}
}

func TestSanitizeEntryPathRejectsUnsafe(t *testing.T) {
	for _, raw := range []string{
		"/etc/passwd",
		"\\windows\\system32",
		"C:\\Windows\\x.dll",
		"c:/x",
		"../secret",
		"a/../../secret",
		"",
		"/",
		".",
		"..",
		"a\x00b",
	} {
		if _, err := sanitizeEntryPath(raw); err == nil {
			t.Errorf("%q should be rejected", raw)
		}
	}
}

func TestBudgetEnforcesEntrySizeTotalAndPathLimits(t *testing.T) {
	limits := Limits{
		MaxEntries:       2,
		MaxEntrySize:     10,
		MaxTotalExpanded: 15,
		MaxDepth:         2,
		MaxPathLen:       8,
	}
	budget := NewBudget(limits)

	if err := budget.Admit(mustEntry(t, "a", KindFile, 10)); err != nil {
		t.Fatalf("admit a: %v", err)
	}
	if budget.Entries() != 1 || budget.Expanded() != 10 {
		t.Fatalf("entries=%d expanded=%d", budget.Entries(), budget.Expanded())
	}

	if err := budget.Admit(mustEntry(t, "b", KindFile, 11)); !errors.Is(err, ErrLimit) {
		t.Errorf("oversized entry error = %v", err)
	}
	if err := budget.Admit(mustEntry(t, "b", KindFile, 6)); !errors.Is(err, ErrLimit) {
		t.Errorf("over-total entry error = %v", err)
	}
	if err := budget.Admit(mustEntry(t, "b", KindFile, 5)); err != nil {
		t.Fatalf("admit b: %v", err)
	}
	if err := budget.Admit(mustEntry(t, "c", KindFile, 0)); !errors.Is(err, ErrLimit) {
		t.Errorf("over-count entry error = %v", err)
	}

	if err := NewBudget(limits).Admit(mustEntry(t, "0123456789", KindFile, 1)); !errors.Is(err, ErrLimit) {
		t.Errorf("over-long path error = %v", err)
	}

	if err := NewBudget(limits).CheckDepth(2); err != nil {
		t.Errorf("depth 2: %v", err)
	}
	if err := NewBudget(limits).CheckDepth(3); !errors.Is(err, ErrLimit) {
		t.Errorf("depth 3 should fail: %v", err)
	}
}

func TestDirectorySizesDoNotConsumeExpandedBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTotalExpanded = 10
	budget := NewBudget(limits)
	if err := budget.Admit(mustEntry(t, "dir", KindDirectory, math.MaxUint64)); err != nil {
		t.Fatalf("directory admit: %v", err)
	}
	if err := budget.Admit(mustEntry(t, "dir/file", KindFile, 10)); err != nil {
		t.Fatalf("file admit: %v", err)
	}
	if budget.Expanded() != 10 {
		t.Errorf("expanded = %d, want 10", budget.Expanded())
	}
}

type fakeReader struct{}

func (fakeReader) FormatID() string { return "zip" }

func (fakeReader) Entries() ([]Entry, error) {
	entry, err := NewEntry("a.txt", KindFile, 3)
	if err != nil {
		return nil, err
	}
	return []Entry{entry}, nil
}

func (fakeReader) FindEntry(path string) (Entry, bool, error) {
	return Find(fakeReader{}, path)
}

func (fakeReader) OpenEntry(path string, id source.ID) (source.ByteSource, error) {
	if path != "a.txt" {
		return nil, Invalidf("no entry %s", path)
	}
	return source.NewMemorySource(id, []byte("abc")), nil
}

type fakeAdapter struct{}

func (fakeAdapter) FormatID() string { return "zip" }

func (fakeAdapter) Open(_ source.ByteSource, _ Limits) (Reader, error) {
	return fakeReader{}, nil
}

func TestRegistryRoutesFormatsAndRejectsDuplicates(t *testing.T) {
	registry := NewRegistry()
	if !registry.IsEmpty() {
		t.Fatal("a new registry should be empty")
	}
	if err := registry.Register(fakeAdapter{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if registry.Len() != 1 {
		t.Fatalf("len = %d", registry.Len())
	}
	ids := registry.FormatIDs()
	if len(ids) != 1 || ids[0] != "zip" {
		t.Fatalf("format ids = %v", ids)
	}
	if err := registry.Register(fakeAdapter{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("duplicate registration error = %v", err)
	}

	src := source.NewMemorySource(1, []byte{0, 0, 0, 0})
	if _, err := registry.Open("7z", src, DefaultLimits()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown format error = %v", err)
	}

	reader, err := registry.Open("zip", src, DefaultLimits())
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	if reader.FormatID() != "zip" {
		t.Errorf("format id = %q", reader.FormatID())
	}
	entries, err := reader.Entries()
	if err != nil || len(entries) != 1 || entries[0].Path != "a.txt" {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	entry, ok, err := reader.FindEntry("a.txt")
	if err != nil || !ok || entry.Size != 3 {
		t.Fatalf("find a.txt = %v %v %v", entry, ok, err)
	}
	if _, ok, err := reader.FindEntry("missing"); err != nil || ok {
		t.Fatalf("find missing = %v %v", ok, err)
	}

	stream, err := reader.OpenEntry("a.txt", 2)
	if err != nil {
		t.Fatalf("open entry: %v", err)
	}
	if stream.SourceID() != 2 || stream.Len() != 3 {
		t.Fatalf("stream id=%d len=%d", stream.SourceID(), stream.Len())
	}
	if _, err := reader.OpenEntry("missing", 3); err == nil {
		t.Error("missing entry should fail")
	}
}
