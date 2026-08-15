package internal_test

// Evidence API tests: exercise the public forensic bridge (ImageFS) against the
// committed real-filesystem E01 fixtures. Every assertion reads real on-disk
// data through the exact-decompression path (readerAdapter -> internal
// ReadSectorData); nothing is fabricated. Tests are hermetic and cross-platform.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/ewffixture"
)

// evidenceFixture returns the path to a committed E01 fixture for the given FS
// base name and container variant (e.g. "fat32" + "encase25-zlib").
func evidenceFixture(t *testing.T, base, variant string) string {
	t.Helper()
	return filepath.Join("..", "testdata", "e01", base+"-"+variant+".E01")
}

// injectedFilesystems reads the injected.txt marker recording which fixtures
// carry a real injected fixture.txt file.
func injectedFilesystems(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "injected.txt"))
	if err != nil {
		t.Fatalf("read injected.txt marker: %v (regenerate with scripts/gen_fs_fixtures.sh)", err)
	}
	set := make(map[string]bool)
	for _, b := range strings.Fields(string(data)) {
		set[b] = true
	}
	return set
}

// onDiskFixtureName returns the on-disk name of the injected file for a
// filesystem. FAT stores only the 8.3 short name, so the FAT fixture's file is
// FIXTURE.TXT; every other filesystem keeps the lowercase fixture.txt.
func onDiskFixtureName(base string) string {
	if base == "fat32" || base == "fat16" {
		return "FIXTURE.TXT"
	}
	return "fixture.txt"
}

// readSignature describes a well-known on-disk signature at a known
// partition-relative byte offset. Reading it through ImageFS.ReadBlock proves
// the block path returns real decompressed on-disk data, never EWF container
// bytes and never a fabricated zero block.
type readSignature struct {
	off  int64
	pos  int
	want []byte
}

var readSignatures = map[string]readSignature{
	"fat32": {0, 0x52, []byte("FAT32")},
	"fat16": {0, 0x36, []byte("FAT16")},
	"exfat": {0, 3, []byte("EXFAT")},
	"ntfs":  {0, 3, []byte("NTFS")},
	"ext4":  {1024, 0x38, []byte{0x53, 0xEF}}, // s_magic 0xEF53 (little-endian)
	"btrfs": {65536, 0x40, []byte("_BHRfS_M")},
	"xfs":   {0, 0, []byte("XFSB")},
}

// TestEvidenceAPI_Reads drives the full ImageFS method set against every
// injected filesystem whose committed parser implements file-content reads
// (FAT32/FAT16, exFAT, NTFS, Btrfs, ext4): OpenFileSystem(0) -> ListDir("/")
// finds the fixture file, ReadFile returns exactly "fixture\n", and ReadBlock
// returns 512 real bytes carrying the filesystem's on-disk signature.
func TestEvidenceAPI_Reads(t *testing.T) {
	injected := injectedFilesystems(t)
	for _, base := range []string{"fat32", "fat16", "exfat", "ntfs", "btrfs", "ext4"} {
		if !injected[base] {
			t.Fatalf("injected.txt marker missing %s (fixture has no injected file)", base)
		}
		t.Run(base, func(t *testing.T) {
			img, err := ewf.Open(evidenceFixture(t, base, "encase25-zlib"))
			if err != nil {
				t.Fatalf("ewf.Open: %v", err)
			}
			defer img.Close()

			fs, err := img.OpenFileSystem(0)
			if err != nil {
				t.Fatalf("OpenFileSystem(0): %v", err)
			}
			defer fs.Close()

			// ListDir("/") must return a real listing containing the fixture file.
			entries, err := fs.ListDir("/")
			if err != nil {
				t.Fatalf("ListDir(\"/\"): %v", err)
			}
			name := onDiskFixtureName(base)
			if !listingContains(entries, name) {
				t.Fatalf("%s: %q not listed; entries = %v", base, name, entryNames(entries))
			}

			// ReadFile must return the exact injected content.
			data, err := fs.ReadFile(name)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", name, err)
			}
			if string(data) != "fixture\n" {
				t.Fatalf("ReadFile(%q) = %q, want %q", name, string(data), "fixture\n")
			}

			// ReadBlock(0, 512) must return exactly 512 real bytes.
			p := make([]byte, 512)
			n, err := fs.ReadBlock(0, p)
			if err != nil {
				t.Fatalf("ReadBlock(0,512): %v", err)
			}
			if n != 512 {
				t.Fatalf("ReadBlock(0,512) n = %d, want 512", n)
			}

			// A partition-relative read at the signature offset must carry the
			// filesystem's real on-disk signature.
			checkSignature(t, fs, base)
		})
	}
}

// TestEvidenceAPI_XFS_EmptyRoot asserts the XFS fixture's genuinely empty root
// is served as a real, empty, non-nil listing — no fabricated entries.
func TestEvidenceAPI_XFS_EmptyRoot(t *testing.T) {
	img, err := ewf.Open(evidenceFixture(t, "xfs", "encase25-zlib"))
	if err != nil {
		t.Fatalf("ewf.Open: %v", err)
	}
	defer img.Close()
	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem(0): %v", err)
	}
	defer fs.Close()
	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir(\"/\"): %v", err)
	}
	if entries == nil {
		t.Fatal("XFS ListDir(\"/\") returned a nil listing (fabrication risk)")
	}
	if len(entries) != 0 {
		t.Fatalf("XFS root is not empty: %v", entryNames(entries))
	}
	// ReadBlock on the XFS superblock proves the block path serves real data.
	checkSignature(t, fs, "xfs")
}

// TestEvidenceAPI_UnsupportedFS asserts OpenFileSystem on a filesystem label it
// does not support returns an explicit error — it never fabricates a handler.
// The image is built in-process (pure Go, hermetic): an MBR disk whose single
// partition holds a non-filesystem pattern and a type byte (0x82 = Linux Swap)
// that resolves to an unsupported label.
func TestEvidenceAPI_UnsupportedFS(t *testing.T) {
	fsImage := bytes.Repeat([]byte{0xAA}, 32*512) // 32 sectors, no FS signature
	disk := ewffixture.WrapMBRDisk(fsImage, 0x82, 2048)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	path := filepath.Join(t.TempDir(), "unsupported.E01")
	if err := os.WriteFile(path, e01, 0o600); err != nil {
		t.Fatal(err)
	}
	img, err := ewf.Open(path)
	if err != nil {
		t.Fatalf("ewf.Open: %v", err)
	}
	defer img.Close()

	parts, err := img.ScanFileSystems()
	if err != nil {
		t.Fatalf("ScanFileSystems: %v", err)
	}
	if len(parts) == 0 {
		t.Fatal("expected at least one partition in the crafted image")
	}
	if parts[0].FileSystem != "Swap" {
		t.Fatalf("expected crafted partition to resolve to \"Swap\", got %q", parts[0].FileSystem)
	}

	fs, err := img.OpenFileSystem(0)
	if err == nil {
		fs.Close()
		t.Fatal("OpenFileSystem on unsupported FS: expected an explicit error, got nil")
	}
}

// checkSignature reads one sector at the filesystem's signature offset through
// ImageFS.ReadBlock and asserts the on-disk signature bytes are present.
func checkSignature(t *testing.T, fs *ewf.ImageFS, base string) {
	t.Helper()
	sig, ok := readSignatures[base]
	if !ok {
		t.Fatalf("no signature defined for %s", base)
	}
	p := make([]byte, 512)
	n, err := fs.ReadBlock(sig.off, p)
	if err != nil {
		t.Fatalf("%s: ReadBlock(%d): %v", base, sig.off, err)
	}
	if n != 512 {
		t.Fatalf("%s: ReadBlock(%d) n = %d, want 512", base, sig.off, n)
	}
	got := p[sig.pos : sig.pos+len(sig.want)]
	if !bytes.Equal(got, sig.want) {
		t.Fatalf("%s: ReadBlock(%d) signature at +%d = %q, want %q", base, sig.off, sig.pos, got, sig.want)
	}
}

func listingContains(entries []ewf.FileEntry, name string) bool {
	for _, e := range entries {
		if e.Name == name {
			return true
		}
	}
	return false
}

func entryNames(entries []ewf.FileEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}
