package filesystem_test

import (
	"path/filepath"
	"testing"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/fat"
)

// fat16Fixture opens a committed FAT16 E01 fixture and constructs a
// reader-backed FAT handler over the first detected partition.
func fat16Fixture(t *testing.T, name string) (*fat.FAT32Handler, *ewf.EWFImage) {
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
	h, err := fat.NewFAT32Handler(img, parts[0].StartSector, parts[0].SizeSectors*uint64(img.SectorSize()))
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}
	return h, img
}

// TestFAT16Fixture proves the unified FAT handler serves real FAT16 content
// from the committed fat16-* fixtures across every container variant. The
// verified on-disk layout: boot at LBA 2048, fixed root at LBA 2116 listing
// the volume label "FIXTURE16" then FIXTURE.TXT (size 8, cluster 2), whose
// data cluster holds "fixture\n".
func TestFAT16Fixture(t *testing.T) {
	variants := []string{
		"encase25-zlib",
		"encase25-zlib-slack",
		"encase6-zlib",
		"encase25-sections2",
		"encase6-sections2",
	}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			h, _ := fat16Fixture(t, filepath.Join("..", "..", "testdata", "e01", "fat16-"+variant+".E01"))

			if h.Type() != filesystem.FS_FAT16 {
				t.Fatalf("Type() = %v, want FS_FAT16", h.Type())
			}

			entries, err := h.ListDirectory("/")
			if err != nil {
				t.Fatalf("ListDirectory(/): %v", err)
			}
			found := false
			for _, e := range entries {
				if e.Name == "FIXTURE.TXT" {
					found = true
					if e.IsDir || e.Size != 8 {
						t.Fatalf("FIXTURE.TXT entry = %+v, want size 8 file", e)
					}
				}
			}
			if !found {
				t.Fatalf("FIXTURE.TXT not listed; entries = %+v", entries)
			}

			got, err := h.GetFile("FIXTURE.TXT")
			if err != nil {
				t.Fatalf("GetFile(FIXTURE.TXT): %v", err)
			}
			if string(got) != "fixture\n" {
				t.Fatalf("FIXTURE.TXT = %q, want %q", string(got), "fixture\n")
			}

			fi, err := h.GetFileByPath("FIXTURE.TXT")
			if err != nil {
				t.Fatalf("GetFileByPath(FIXTURE.TXT): %v", err)
			}
			if fi.Size != 8 || fi.IsDir {
				t.Fatalf("GetFileByPath = %+v, want size 8 non-dir", fi)
			}

			// SearchFiles must find the file through the fixed-root path.
			results, err := h.SearchFiles("/", func(fi filesystem.FileInfo) bool {
				return fi.Name == "FIXTURE.TXT"
			})
			if err != nil {
				t.Fatalf("SearchFiles: %v", err)
			}
			if len(results) != 1 || results[0].Name != "FIXTURE.TXT" {
				t.Fatalf("SearchFiles = %+v, want [FIXTURE.TXT]", results)
			}

			// A missing root-level file must error explicitly, never fabricate.
			if _, err := h.GetFile("MISSING.TXT"); err == nil {
				t.Fatal("GetFile(MISSING.TXT) succeeded, want not-found error")
			}
		})
	}
}
