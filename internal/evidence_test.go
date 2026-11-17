package internal_test

// Evidence API tests: exercise the public forensic API against the committed
// real-filesystem E01 fixtures. Every assertion reads real on-disk data through
// the exact-decompression path; nothing is fabricated. Tests are hermetic and
// cross-platform.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/ewffixture"
)

func evidenceFixture(t *testing.T, base, variant string) string {
	t.Helper()
	return filepath.Join("..", "testdata", "e01", base+"-"+variant+".E01")
}

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

func onDiskFixtureName(base string) string {
	if base == "fat32" || base == "fat16" {
		return "FIXTURE.TXT"
	}
	return "fixture.txt"
}

type readSignature struct {
	off  uint64
	pos  int
	want []byte
}

var readSignatures = map[string]readSignature{
	"fat32": {0, 0x52, []byte("FAT32")},
	"fat16": {0, 0x36, []byte("FAT16")},
	"exfat": {0, 3, []byte("EXFAT")},
	"ntfs":  {0, 3, []byte("NTFS")},
	"ext4":  {1024, 0x38, []byte{0x53, 0xEF}},
	"btrfs": {65536, 0x40, []byte("_BHRfS_M")},
	"xfs":   {0, 0, []byte("XFSB")},
}

// TestEvidenceAPI_Reads drives the full public method set against every
// injected filesystem whose committed parser implements file-content reads:
// Open -> Partitions -> OpenFilesystem -> ListDir("/") finds the fixture file,
// Open/ReadAll returns exactly "fixture\n", and the partition source serves
// real bytes carrying the filesystem's on-disk signature.
func TestEvidenceAPI_Reads(t *testing.T) {
	ctx := context.Background()
	injected := injectedFilesystems(t)
	for _, base := range []string{"fat32", "fat16", "exfat", "ntfs", "btrfs", "ext4"} {
		if !injected[base] {
			t.Fatalf("injected.txt marker missing %s (fixture has no injected file)", base)
		}
		t.Run(base, func(t *testing.T) {
			img, err := forensic.Open(ctx, evidenceFixture(t, base, "encase25-zlib"), forensic.Options{})
			if err != nil {
				t.Fatalf("forensic.Open: %v", err)
			}
			defer img.Close()

			parts, err := img.Partitions(ctx)
			if err != nil {
				t.Fatalf("Partitions: %v", err)
			}
			if len(parts) == 0 {
				t.Fatal("no partitions")
			}
			part := parts[0]
			fsys, err := part.OpenFilesystem(ctx)
			if err != nil {
				t.Fatalf("OpenFilesystem: %v", err)
			}
			defer fsys.Close()

			entries, err := fsys.ListDir(ctx, "/")
			if err != nil {
				t.Fatalf("ListDir(\"/\"): %v", err)
			}
			name := onDiskFixtureName(base)
			if !listingContains(entries, name) {
				t.Fatalf("%s: %q not listed; entries = %v", base, name, entryNames(entries))
			}

			file, err := fsys.Open(ctx, name)
			if err != nil {
				t.Fatalf("Open(%q): %v", name, err)
			}
			data, err := file.ReadAll()
			file.Close()
			if err != nil {
				t.Fatalf("ReadAll(%q): %v", name, err)
			}
			if string(data) != "fixture\n" {
				t.Fatalf("ReadAll(%q) = %q, want %q", name, string(data), "fixture\n")
			}

			p := make([]byte, 512)
			n, err := part.Source().ReadAt(0, p)
			if err != nil {
				t.Fatalf("partition ReadAt(0,512): %v", err)
			}
			if n != 512 {
				t.Fatalf("partition ReadAt(0,512) n = %d, want 512", n)
			}
			checkSignature(t, part.Source(), base)
		})
	}
}

// TestEvidenceAPI_XFS_EmptyRoot asserts the XFS fixture's genuinely empty root
// is served as a real, empty, non-nil listing — no fabricated entries.
func TestEvidenceAPI_XFS_EmptyRoot(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, evidenceFixture(t, "xfs", "encase25-zlib"), forensic.Options{})
	if err != nil {
		t.Fatalf("forensic.Open: %v", err)
	}
	defer img.Close()
	parts, err := img.Partitions(ctx)
	if err != nil || len(parts) == 0 {
		t.Fatalf("Partitions: %v (parts=%d)", err, len(parts))
	}
	fsys, err := parts[0].OpenFilesystem(ctx)
	if err != nil {
		t.Fatalf("OpenFilesystem: %v", err)
	}
	defer fsys.Close()
	entries, err := fsys.ListDir(ctx, "/")
	if err != nil {
		t.Fatalf("ListDir(\"/\"): %v", err)
	}
	if entries == nil {
		t.Fatal("XFS ListDir(\"/\") returned a nil listing (fabrication risk)")
	}
	if len(entries) != 0 {
		t.Fatalf("XFS root is not empty: %v", entryNames(entries))
	}
	checkSignature(t, parts[0].Source(), "xfs")
}

// TestEvidenceAPI_UnsupportedFS asserts OpenFilesystem on a partition with no
// recognised filesystem returns an explicit error — it never fabricates a
// handler. The table's type name still reports Linux swap; the detected volume
// format stays unknown because detection is signature-based.
func TestEvidenceAPI_UnsupportedFS(t *testing.T) {
	ctx := context.Background()
	fsImage := bytes.Repeat([]byte{0xAA}, 32*512)
	disk := ewffixture.WrapMBRDisk(fsImage, 0x82, 2048)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	path := filepath.Join(t.TempDir(), "unsupported.E01")
	if err := os.WriteFile(path, e01, 0o600); err != nil {
		t.Fatal(err)
	}
	img, err := forensic.Open(ctx, path, forensic.Options{})
	if err != nil {
		t.Fatalf("forensic.Open: %v", err)
	}
	defer img.Close()

	parts, err := img.Partitions(ctx)
	if err != nil {
		t.Fatalf("Partitions: %v", err)
	}
	if len(parts) == 0 {
		t.Fatal("expected at least one partition in the crafted image")
	}
	if parts[0].TypeName() != "Linux swap" {
		t.Fatalf("partition type name = %q, want Linux swap", parts[0].TypeName())
	}
	if parts[0].Format() != "unknown" {
		t.Fatalf("detected format = %q, want unknown (no filesystem signature)", parts[0].Format())
	}

	fsys, err := parts[0].OpenFilesystem(ctx)
	if err == nil {
		fsys.Close()
		t.Fatal("OpenFilesystem on unsupported FS: expected an explicit error, got nil")
	}
}

func checkSignature(t *testing.T, src forensic.ByteSource, base string) {
	t.Helper()
	sig, ok := readSignatures[base]
	if !ok {
		t.Fatalf("no signature defined for %s", base)
	}
	p := make([]byte, 512)
	n, err := src.ReadAt(sig.off, p)
	if err != nil {
		t.Fatalf("%s: ReadAt(%d): %v", base, sig.off, err)
	}
	if n != 512 {
		t.Fatalf("%s: ReadAt(%d) n = %d, want 512", base, sig.off, n)
	}
	got := p[sig.pos : sig.pos+len(sig.want)]
	if !bytes.Equal(got, sig.want) {
		t.Fatalf("%s: ReadAt(%d) signature at +%d = %q, want %q", base, sig.off, sig.pos, got, sig.want)
	}
}

func listingContains(entries []forensic.Entry, name string) bool {
	for _, e := range entries {
		if e.Name == name {
			return true
		}
	}
	return false
}

func entryNames(entries []forensic.Entry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}
