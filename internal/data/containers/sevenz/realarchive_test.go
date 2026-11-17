package sevenz

import (
	"bytes"
	"sync"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

func TestRealLZMAKnownSizeArchive(t *testing.T) {
	reader := openBytes(t, realArchiveFixture("lzma_small"), archive.DefaultLimits())
	got := readEntry(t, reader, "lzma_small.txt")
	if want := realLzmaText(); !bytes.Equal(got, want) {
		t.Fatalf("LZMA content differs (len %d vs %d)", len(got), len(want))
	}
}

func TestRealLZMA2SolidArchive(t *testing.T) {
	reader := openBytes(t, realArchiveFixture("lzma2_solid"), archive.DefaultLimits())
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	want := realSolidTexts()
	for _, entry := range entries {
		expected, ok := want[entry.Path]
		if !ok {
			t.Fatalf("unexpected entry %q", entry.Path)
		}
		if entry.Size != uint64(len(expected)) {
			t.Errorf("%s size = %d, want %d", entry.Path, entry.Size, len(expected))
		}
		if entry.CompressedSize != nil {
			t.Errorf("%s must not claim a per-entry compressed size in a solid folder", entry.Path)
		}
	}
	for path, expected := range want {
		if got := readEntry(t, reader, path); string(got) != expected {
			t.Fatalf("%s content differs (len %d vs %d)", path, len(got), len(expected))
		}
	}
	// All three members share one solid folder: exactly one decode.
	stats := reader.Stats()
	if stats.CacheMisses != 1 || stats.CacheHits != 2 {
		t.Errorf("solid cache stats = %+v, want 1 miss and 2 hits", stats)
	}
}

func TestConcurrentSolidReads(t *testing.T) {
	// The folder cache is shared by every entry source; concurrent readers of
	// one solid folder must agree without a data race.
	reader := openBytes(t, realArchiveFixture("lzma2_solid"), archive.DefaultLimits())
	want := realSolidTexts()
	const workers = 8
	var wg sync.WaitGroup
	failures := make(chan string, workers)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for iteration := 0; iteration < 4; iteration++ {
				for path, expected := range want {
					entry, err := reader.OpenEntrySource(path, source.ID(100+worker))
					if err != nil {
						failures <- err.Error()
						return
					}
					got, err := source.ReadVecAt(entry, 0, entry.Len())
					if err != nil {
						failures <- err.Error()
						return
					}
					if string(got) != expected {
						failures <- "content mismatch for " + path
						return
					}
				}
			}
		}(worker)
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func TestRealDirectoryAndEmptyFileArchive(t *testing.T) {
	reader := openBytes(t, realTreeArchive(), archive.DefaultLimits())
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	want := []struct {
		path  string
		isDir bool
		size  uint64
	}{
		{"realtree", true, 0},
		{"realtree/dir", true, 0},
		{"realtree/empty.txt", false, 0},
		{"realtree/a.txt", false, 18},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %d, want %d: %+v", len(entries), len(want), entries)
	}
	for index, expected := range want {
		entry := entries[index]
		if entry.Path != expected.path || entry.IsDir() != expected.isDir || entry.Size != expected.size {
			t.Errorf("entry %d = {%q dir=%v size=%d}, want %+v",
				index, entry.Path, entry.IsDir(), entry.Size, expected)
		}
		if entry.Modified == nil {
			t.Errorf("%s has no modification time; the K_MTIME table did not parse", entry.Path)
		}
	}
	if got := readEntry(t, reader, "realtree/a.txt"); string(got) != "real file content\n" {
		t.Errorf("a.txt = %q", got)
	}
	if got := readEntry(t, reader, "realtree/empty.txt"); len(got) != 0 {
		t.Errorf("empty file = %q", got)
	}
	if _, err := reader.OpenEntrySource("realtree/dir", 2); err == nil {
		t.Error("a directory must not open as data")
	}
}
