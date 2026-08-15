package internal_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/filesystem/exfat"
	"github.com/laenix/ewfgo/internal/filesystem/ntfs"
)

// fsFixture returns the path to a checked-in FS E01 fixture. The optional
// variant is a container suffix (see containerVariants); without it the path
// points at the legacy <base>.E01 name.
func fsFixture(t *testing.T, name string, variants ...string) string {
	t.Helper()
	suffix := ""
	if len(variants) > 0 {
		suffix = "-" + variants[0]
	}
	return filepath.Join("..", "testdata", "e01", name+suffix+".E01")
}

// containerVariants is the 5-way E01 container cross-product (zlib only): the
// distinct code paths exercised are the EnCase 2-5 layout, a slack tail before
// the chunk data, the EnCase 6 base-offset table, and multi-section spanning.
var containerVariants = []string{
	"encase25-zlib",
	"encase25-zlib-slack",
	"encase6-zlib",
	"encase25-sections2",
	"encase6-sections2",
}

var fsDetectionCases = []struct {
	base string
	want string
}{
	{"fat32", "FAT32"},
	{"fat16", "FAT16"},
	{"exfat", "exFAT"},
	{"ext4", "ext4"},
	{"xfs", "XFS"},
	{"btrfs", "Btrfs"},
	{"ntfs", "NTFS"},
}

// fabricatedNames are the hard-coded names the pre-P0 stub listing handlers
// returned instead of real directory data. A listing containing any of them is
// a fabrication bug, never a real entry.
var fabricatedNames = []string{"DCIM", "Pictures", "bin", "boot", "etc"}

func isFabricatedName(name string) bool {
	for _, f := range fabricatedNames {
		if name == f {
			return true
		}
	}
	return false
}

// TestFSMatrix_Detection iterates the full FS x container cross-product: every
// <fs>-<variant>.E01 must have its filesystem detected. It also keeps the
// "no fabricated data" spirit of the original test: the public ListDirectory
// path must return either an explicit error (parser not yet implemented for
// exFAT/Btrfs/FAT16) or a REAL listing — never a fabricated one. This gate
// must be tightened per-FS as the FS parsers land in later tasks.
func TestFSMatrix_Detection(t *testing.T) {
	for _, tc := range fsDetectionCases {
		for _, variant := range containerVariants {
			t.Run(tc.base+"-"+variant, func(t *testing.T) {
				img, err := ewf.Open(fsFixture(t, tc.base, variant))
				if err != nil {
					t.Fatalf("ewf.Open: %v", err)
				}
				defer img.Close()
				parts, err := img.ScanFileSystems()
				if err != nil {
					t.Fatalf("ScanFileSystems: %v", err)
				}
				found := false
				for _, p := range parts {
					if p.FileSystem == tc.want {
						found = true
						break
					}
				}
				if !found {
					got := ""
					if len(parts) > 0 {
						got = parts[0].FileSystem
					}
					t.Fatalf("filesystem %s not detected (got %q)", tc.want, got)
				}

				// No-fabricated-data gate: explicit error is acceptable, a
				// fabricated listing is a failure.
				fs, err := img.OpenFileSystem(0)
				if err != nil {
					return
				}
				defer fs.Close()
				entries, err := fs.ListDir("")
				if err != nil {
					return
				}
				for _, e := range entries {
					if isFabricatedName(e.Name) {
						t.Fatalf("fabricated entry %q in %s-%s listing", e.Name, tc.base, variant)
					}
				}
			})
		}
	}
}

// TestFSMatrix_Listing asserts the known injected file is listed for FAT32,
// ext4 and NTFS across all 5 container variants (proving listing works through
// EnCase6 base-offset and multi-section spanning, not just the default layout).
func TestFSMatrix_Listing(t *testing.T) {
	cases := []struct {
		base string
		file string
		// empty marks filesystems whose root directory really holds no entries:
		// the XFS root shortform dir stores count=0 ("." and ".." are implicit
		// and never on disk), so the real parse yields an empty listing.
		empty bool
	}{
		{"fat32", "FIXTURE.TXT", false},
		{"fat16", "FIXTURE.TXT", false},
		{"ext4", "fixture.txt", false},
		{"ntfs", "fixture.txt", false},
		{"exfat", "fixture.txt", false},
		{"btrfs", "fixture.txt", false},
		{"xfs", "fixture.txt", true},
	}
	for _, tc := range cases {
		for _, variant := range containerVariants {
			t.Run(tc.base+"-"+variant, func(t *testing.T) {
				img, err := ewf.Open(fsFixture(t, tc.base, variant))
				if err != nil {
					t.Fatal(err)
				}
				defer img.Close()
				fs, err := img.OpenFileSystem(0)
				if err != nil {
					t.Fatalf("OpenFileSystem: %v", err)
				}
				defer fs.Close()
				entries, err := fs.ListDir("")
				if err != nil {
					t.Fatalf("ListDir: %v", err)
				}
				if tc.empty {
					if len(entries) != 0 {
						t.Fatalf("expected empty listing for %s, got %d entries", tc.base, len(entries))
					}
					return
				}
				for _, e := range entries {
					if e.Name == tc.file {
						return
					}
				}
				t.Fatalf("file %s not listed (%d entries)", tc.file, len(entries))
			})
		}
	}
}

// TestFSMatrix_InjectedReads is driven by testdata/injected.txt, the marker
// that scripts/gen_fs_fixtures.sh writes to record which raw FS images truly
// hold a real injected fixture file. Task 10 asserts injection-backed reads
// only where the listing parser is already real (FAT32 + ext4); the marker
// keeps the test honest for later tasks as those parsers land.
func TestFSMatrix_InjectedReads(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "injected.txt"))
	if err != nil {
		t.Fatalf("read injected.txt marker: %v (regenerate with scripts/gen_fs_fixtures.sh)", err)
	}
	injected := strings.Fields(string(data))

	// listingFileFor maps a filesystem to the file name its parser can list.
	// Task 10: FAT32 + ext4. Task 13 adds exFAT. Task 14 adds btrfs.
	// Task 17b adds fat16.
	listingFileFor := map[string]string{
		"fat32": "FIXTURE.TXT",
		"fat16": "FIXTURE.TXT",
		"ext4":  "fixture.txt",
		"exfat": "fixture.txt",
		"btrfs": "fixture.txt",
	}

	// Guard: the filesystems this task asserts must actually carry the
	// injection, otherwise the loop below is vacuous.
	for _, required := range []string{"fat32", "fat16", "ext4", "exfat", "btrfs"} {
		present := false
		for _, b := range injected {
			if b == required {
				present = true
				break
			}
		}
		if !present {
			t.Fatalf("injected.txt marker missing required filesystem %q (present: %v)", required, injected)
		}
	}

	for _, base := range injected {
		file, ok := listingFileFor[base]
		if !ok {
			continue // parser lands in a later task
		}
		for _, variant := range containerVariants {
			t.Run(base+"-"+variant, func(t *testing.T) {
				img, err := ewf.Open(fsFixture(t, base, variant))
				if err != nil {
					t.Fatal(err)
				}
				defer img.Close()
				fs, err := img.OpenFileSystem(0)
				if err != nil {
					t.Fatalf("OpenFileSystem: %v", err)
				}
				defer fs.Close()
				entries, err := fs.ListDir("")
				if err != nil {
					t.Fatalf("ListDir: %v", err)
				}
				for _, e := range entries {
					if e.Name == file {
						return
					}
				}
				t.Fatalf("injected file %s not listed (%d entries)", file, len(entries))
			})
		}
	}
}

// TestFSMatrix_NTFSInjectedRead asserts the NTFS parser's content read path
// (resident $DATA -> exact bytes) against every container variant of the NTFS
// fixture. It is gated on testdata/injected.txt: if the marker is missing the
// fixture carries no injected file and the loop would be vacuous, so it fails.
func TestFSMatrix_NTFSInjectedRead(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "injected.txt"))
	if err != nil {
		t.Fatalf("read injected.txt marker: %v (regenerate with scripts/gen_fs_fixtures.sh)", err)
	}
	hasNTFS := false
	for _, b := range strings.Fields(string(data)) {
		if b == "ntfs" {
			hasNTFS = true
			break
		}
	}
	if !hasNTFS {
		t.Fatal("injected.txt marker missing ntfs; fixture carries no injected file")
	}

	for _, variant := range containerVariants {
		t.Run("ntfs-"+variant, func(t *testing.T) {
			img, err := ewf.Open(fsFixture(t, "ntfs", variant))
			if err != nil {
				t.Fatal(err)
			}
			defer img.Close()
			parts, err := img.ScanFileSystems()
			if err != nil || len(parts) == 0 {
				t.Fatalf("ScanFileSystems: %v", err)
			}
			h, err := ntfs.NewNTFSHandler(img, parts[0].StartSector)
			if err != nil {
				t.Fatalf("NewNTFSHandler: %v", err)
			}
			got, err := h.GetFile("fixture.txt")
			if err != nil {
				t.Fatalf("GetFile(fixture.txt): %v", err)
			}
			if string(got) != "fixture\n" {
				t.Fatalf("fixture.txt content = %q, want %q", string(got), "fixture\n")
			}
		})
	}
}

// TestFSMatrix_EXFATInjectedRead asserts the exFAT parser's content read path
// (FAT cluster chain -> exact bytes) against every container variant of the
// exFAT fixture. It is gated on testdata/injected.txt: if the marker is missing
// the fixture carries no injected file and the loop would be vacuous, so it
// fails.
func TestFSMatrix_EXFATInjectedRead(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "injected.txt"))
	if err != nil {
		t.Fatalf("read injected.txt marker: %v (regenerate with scripts/gen_fs_fixtures.sh)", err)
	}
	hasExfat := false
	for _, b := range strings.Fields(string(data)) {
		if b == "exfat" {
			hasExfat = true
			break
		}
	}
	if !hasExfat {
		t.Fatal("injected.txt marker missing exfat; fixture carries no injected file")
	}

	for _, variant := range containerVariants {
		t.Run("exfat-"+variant, func(t *testing.T) {
			img, err := ewf.Open(fsFixture(t, "exfat", variant))
			if err != nil {
				t.Fatal(err)
			}
			defer img.Close()
			parts, err := img.ScanFileSystems()
			if err != nil || len(parts) == 0 {
				t.Fatalf("ScanFileSystems: %v", err)
			}
			h, err := exfat.NewEXFATHandler(img, parts[0].StartSector)
			if err != nil {
				t.Fatalf("NewEXFATHandler: %v", err)
			}
			got, err := h.GetFile("fixture.txt")
			if err != nil {
				t.Fatalf("GetFile(fixture.txt): %v", err)
			}
			if string(got) != "fixture\n" {
				t.Fatalf("fixture.txt content = %q, want %q", string(got), "fixture\n")
			}
		})
	}
}
