package filesystem_test

import (
	"bytes"
	"testing"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/ntfs"
)

// ntfsFixture returns a handler over the committed NTFS fixture (partition
// start sector resolved from the image's own partition table).
func ntfsFixture(t *testing.T, name string) (*ntfs.NTFSHandler, *ewf.EWFImage) {
	t.Helper()
	img, err := ewf.Open(name)
	if err != nil {
		t.Fatalf("ewf.Open(%s): %v", name, err)
	}
	t.Cleanup(func() { img.Close() })

	parts, err := img.ScanFileSystems()
	if err != nil || len(parts) == 0 {
		t.Fatalf("ScanFileSystems: %v (parts=%d)", err, len(parts))
	}
	start := parts[0].StartSector
	h, err := ntfs.NewNTFSHandler(img, start)
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}
	return h, img
}

// TestNTFSFixture is the real-image test: the committed
// testdata/e01/ntfs-encase25-zlib.E01 fixture carries an injected fixture.txt
// (see testdata/injected.txt). Every assertion must hold against real on-disk
// NTFS data.
func TestNTFSFixture(t *testing.T) {
	h, _ := ntfsFixture(t, "../../testdata/e01/ntfs-encase25-zlib.E01")

	// Real directory listing includes the injected file with its exact name.
	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "fixture.txt" {
			found = true
			if e.IsDir {
				t.Errorf("fixture.txt listed as a directory")
			}
			if e.Size != 8 {
				t.Errorf("fixture.txt listed size = %d, want 8", e.Size)
			}
		}
	}
	if !found {
		t.Fatalf("fixture.txt not listed in root (got %d entries)", len(entries))
	}

	// Content read: exact bytes.
	data, err := h.GetFile("fixture.txt")
	if err != nil {
		t.Fatalf("GetFile(fixture.txt): %v", err)
	}
	if !bytes.Equal(data, []byte("fixture\n")) {
		t.Errorf("fixture.txt content = %q, want %q", string(data), "fixture\n")
	}

	// Metadata.
	fi, err := h.GetFileByPath("fixture.txt")
	if err != nil {
		t.Fatalf("GetFileByPath(fixture.txt): %v", err)
	}
	if fi.Name != "fixture.txt" || fi.IsDir || fi.Size != 8 {
		t.Errorf("unexpected FileInfo for fixture.txt: %+v", fi)
	}

	// Search finds exactly one.
	results, err := h.SearchFiles("/", func(f filesystem.FileInfo) bool {
		return f.Name == "fixture.txt"
	})
	if err != nil {
		t.Fatalf("SearchFiles: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchFiles(fixture.txt) = %d results, want 1: %+v", len(results), results)
	}

	// Volume label: mkfs.ntfs set FIXTURE on this fixture.
	if label := h.GetVolumeLabel(); label != "FIXTURE" {
		t.Errorf("GetVolumeLabel() = %q, want %q", label, "FIXTURE")
	}
}

// TestNTFSFixtureSubdirListing verifies real multi-level directory listing:
// the $Extend directory contains $Quota, $ObjId and $Reparse, all of which are
// NOT root entries (their $FILE_NAME parent is record 11, not the root).
func TestNTFSFixtureSubdirListing(t *testing.T) {
	h, _ := ntfsFixture(t, "../../testdata/e01/ntfs-encase25-zlib.E01")

	entries, err := h.ListDirectory("/$Extend")
	if err != nil {
		t.Fatalf("ListDirectory(/$Extend): %v", err)
	}
	want := map[string]bool{"$Quota": true, "$ObjId": true, "$Reparse": true}
	for _, e := range entries {
		delete(want, e.Name)
	}
	if len(want) != 0 {
		t.Errorf("$Extend listing missing %v (got %d entries)", want, len(entries))
	}

	// The system files under $Extend must not leak into the root listing.
	root, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	for _, e := range root {
		if e.Name == "$Quota" || e.Name == "$ObjId" || e.Name == "$Reparse" {
			t.Errorf("%q must not appear in the root listing (it lives in $Extend)", e.Name)
		}
	}
}

// TestNTFSFixtureMissingFile asserts honest errors for absent paths.
func TestNTFSFixtureMissingFile(t *testing.T) {
	h, _ := ntfsFixture(t, "../../testdata/e01/ntfs-encase25-zlib.E01")
	if _, err := h.GetFile("/no-such-file.txt"); err == nil {
		t.Fatal("GetFile on a missing path must error")
	}
	if _, err := h.GetFileByPath("/no-such-file.txt"); err == nil {
		t.Fatal("GetFileByPath on a missing path must error")
	}
}
