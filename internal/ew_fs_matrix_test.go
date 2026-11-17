package internal_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	forensic "github.com/laenix/ewfgo"
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

// openFixture opens an E01 fixture through the public API and returns the image
// plus its partitions. The image is closed at test cleanup.
func openFixture(t *testing.T, path string) (*forensic.Image, []*forensic.Partition) {
	t.Helper()
	ctx := context.Background()
	img, err := forensic.Open(ctx, path, forensic.Options{})
	if err != nil {
		t.Fatalf("forensic.Open: %v", err)
	}
	t.Cleanup(func() { img.Close() })
	parts, err := img.Partitions(ctx)
	if err != nil {
		t.Fatalf("Partitions: %v", err)
	}
	if len(parts) == 0 {
		t.Fatalf("%s: no partitions", path)
	}
	return img, parts
}

// TestFSMatrix_Detection iterates the full FS x container cross-product: every
// <fs>-<variant>.E01 must have its filesystem detected. It also keeps the
// "no fabricated data" spirit: the public listing path must return either an
// explicit error or a REAL listing — never a fabricated one.
func TestFSMatrix_Detection(t *testing.T) {
	ctx := context.Background()
	for _, tc := range fsDetectionCases {
		for _, variant := range containerVariants {
			t.Run(tc.base+"-"+variant, func(t *testing.T) {
				img, parts := openFixture(t, fsFixture(t, tc.base, variant))
				_ = img
				found := false
				for _, p := range parts {
					if p.Format() == tc.want {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("filesystem %s not detected (got %q)", tc.want, parts[0].Format())
				}

				fsys, err := parts[0].OpenFilesystem(ctx)
				if err != nil {
					return
				}
				defer fsys.Close()
				entries, err := fsys.ListDir(ctx, "/")
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
	ctx := context.Background()
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
				_, parts := openFixture(t, fsFixture(t, tc.base, variant))
				fsys, err := parts[0].OpenFilesystem(ctx)
				if err != nil {
					t.Fatalf("OpenFilesystem: %v", err)
				}
				defer fsys.Close()
				entries, err := fsys.ListDir(ctx, "/")
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
// hold a real injected fixture file.
func TestFSMatrix_InjectedReads(t *testing.T) {
	ctx := context.Background()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "injected.txt"))
	if err != nil {
		t.Fatalf("read injected.txt marker: %v (regenerate with scripts/gen_fs_fixtures.sh)", err)
	}
	injected := strings.Fields(string(data))

	listingFileFor := map[string]string{
		"fat32": "FIXTURE.TXT",
		"fat16": "FIXTURE.TXT",
		"ext4":  "fixture.txt",
		"exfat": "fixture.txt",
		"btrfs": "fixture.txt",
	}

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
			continue
		}
		for _, variant := range containerVariants {
			t.Run(base+"-"+variant, func(t *testing.T) {
				_, parts := openFixture(t, fsFixture(t, base, variant))
				fsys, err := parts[0].OpenFilesystem(ctx)
				if err != nil {
					t.Fatalf("OpenFilesystem: %v", err)
				}
				defer fsys.Close()
				entries, err := fsys.ListDir(ctx, "/")
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

// readFixtureFile opens a file through the public API and returns its exact
// content.
func readFixtureFile(t *testing.T, fsys forensic.FileSystem, name string) string {
	t.Helper()
	ctx := context.Background()
	file, err := fsys.Open(ctx, name)
	if err != nil {
		t.Fatalf("Open(%s): %v", name, err)
	}
	defer file.Close()
	data, err := file.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll(%s): %v", name, err)
	}
	return string(data)
}

// TestFSMatrix_NTFSInjectedRead asserts the NTFS parser's content read path
// (resident $DATA -> exact bytes) against every container variant of the NTFS
// fixture.
func TestFSMatrix_NTFSInjectedRead(t *testing.T) {
	ctx := context.Background()
	requireInjected(t, "ntfs")
	for _, variant := range containerVariants {
		t.Run("ntfs-"+variant, func(t *testing.T) {
			_, parts := openFixture(t, fsFixture(t, "ntfs", variant))
			fsys, err := parts[0].OpenFilesystem(ctx)
			if err != nil {
				t.Fatalf("OpenFilesystem: %v", err)
			}
			defer fsys.Close()
			if got := readFixtureFile(t, fsys, "fixture.txt"); got != "fixture\n" {
				t.Fatalf("fixture.txt content = %q, want %q", got, "fixture\n")
			}
		})
	}
}

// TestFSMatrix_EXFATInjectedRead asserts the exFAT parser's content read path
// (FAT cluster chain -> exact bytes) against every container variant of the
// exFAT fixture.
func TestFSMatrix_EXFATInjectedRead(t *testing.T) {
	ctx := context.Background()
	requireInjected(t, "exfat")
	for _, variant := range containerVariants {
		t.Run("exfat-"+variant, func(t *testing.T) {
			_, parts := openFixture(t, fsFixture(t, "exfat", variant))
			fsys, err := parts[0].OpenFilesystem(ctx)
			if err != nil {
				t.Fatalf("OpenFilesystem: %v", err)
			}
			defer fsys.Close()
			if got := readFixtureFile(t, fsys, "fixture.txt"); got != "fixture\n" {
				t.Fatalf("fixture.txt content = %q, want %q", got, "fixture\n")
			}
		})
	}
}

// requireInjected fails when testdata/injected.txt does not record base, which
// would make an injected-read test vacuous.
func requireInjected(t *testing.T, base string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "injected.txt"))
	if err != nil {
		t.Fatalf("read injected.txt marker: %v (regenerate with scripts/gen_fs_fixtures.sh)", err)
	}
	for _, b := range strings.Fields(string(data)) {
		if b == base {
			return
		}
	}
	t.Fatalf("injected.txt marker missing %s; fixture carries no injected file", base)
}
