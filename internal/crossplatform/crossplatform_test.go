// Package crossplatform holds runtime behavioral assertions that must hold on
// every OS/arch the test suite runs on (Windows, Linux, macOS across
// amd64/arm64/riscv64 where the toolchain supports it).
//
// The hard enforcement of the build matrix (CGO_ENABLED=0, pure Go, no
// external processes, no syscall) lives in scripts/build-matrix.sh and
// scripts/check-hermetic.sh, not here: this test cannot re-run `go build` for
// every pair without violating the hermetic-test rule. What it does prove is
// that, wherever it runs, the public API returns byte-identical data (identical
// decompression -> identical parse -> identical bytes on every endianness), and
// that path handling is OS-neutral.
package crossplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"testing"

	forensic "github.com/laenix/ewfgo"
)

func fixturePath(t *testing.T, base, variant string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "e01", base+"-"+variant+".E01")
}

var supportedGOOS = map[string]bool{"windows": true, "linux": true, "darwin": true}
var supportedGOARCH = map[string]bool{"amd64": true, "arm64": true, "riscv64": true}

// TestNoCGO asserts trivial runtime invariants and documents where the real
// CGO/build-matrix enforcement lives. A test cannot shell out to `go build` or
// `go env` (not hermetic), so the substantive gate is the check script.
func TestNoCGO(t *testing.T) {
	if !supportedGOOS[runtime.GOOS] {
		t.Errorf("runtime.GOOS %q is outside the supported matrix (windows/linux/darwin)", runtime.GOOS)
	}
	if !supportedGOARCH[runtime.GOARCH] {
		t.Errorf("runtime.GOARCH %q is outside the supported matrix (amd64/arm64/riscv64)", runtime.GOARCH)
	}
	if runtime.NumCPU() < 1 {
		t.Errorf("runtime.NumCPU() = %d, want >= 1", runtime.NumCPU())
	}
}

// TestPathHandling asserts the public forensic API accepts both '/'-separated
// and Windows '\'-separated directory paths and normalizes them to the same
// listing. The filesystem handlers split on '/' internally, so a literal
// backslash is translated at the public boundary; this test pins that behavior
// on every OS.
func TestPathHandling(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixturePath(t, "ext4", "encase25-zlib"), forensic.Options{})
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

	rootSlash, err := fsys.ListDir(ctx, "/")
	if err != nil {
		t.Fatalf("ListDir(\"/\"): %v", err)
	}
	rootBS, err := fsys.ListDir(ctx, "\\")
	if err != nil {
		t.Fatalf("ListDir(\"\\\\\"): %v", err)
	}
	if len(rootSlash) == 0 {
		t.Fatalf("root listing unexpectedly empty")
	}
	if !sameEntries(rootSlash, rootBS) {
		t.Fatalf("root listing differs: slash=%v backslash=%v", namePathsOf(rootSlash), namePathsOf(rootBS))
	}

	lfSlash, err := fsys.ListDir(ctx, "/lost+found")
	if err != nil {
		t.Fatalf("ListDir(\"/lost+found\"): %v", err)
	}
	lfBS, err := fsys.ListDir(ctx, "\\lost+found")
	if err != nil {
		t.Fatalf("ListDir(\"\\\\lost+found\"): %v", err)
	}
	if !sameEntries(lfSlash, lfBS) {
		t.Fatalf("lost+found listing differs: slash=%v backslash=%v", namePathsOf(lfSlash), namePathsOf(lfBS))
	}

	want := readAll(t, fsys, "/fixture.txt")
	got := readAll(t, fsys, "\\fixture.txt")
	if got != want {
		t.Fatalf("ReadFile backslash = %q, want %q", got, want)
	}
}

func readAll(t *testing.T, fsys forensic.FileSystem, name string) string {
	t.Helper()
	ctx := context.Background()
	file, err := fsys.Open(ctx, name)
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	defer file.Close()
	data, err := file.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll(%q): %v", name, err)
	}
	return string(data)
}

// goldenFat32Sector0 is the SHA-256 of the first sector (LBA 0) of every fat32
// fixture, computed once from the committed testdata/e01/ images and embedded.
const goldenFat32Sector0 = "465d0cf878419711bbafc3f9563d959d1769ab5e068b4914756b658039946d6b"

// TestLittleEndianHeld asserts that reading the fat32-encase25-zlib fixture
// through the public API yields the exact golden sector bytes.
func TestLittleEndianHeld(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixturePath(t, "fat32", "encase25-zlib"), forensic.Options{})
	if err != nil {
		t.Fatalf("forensic.Open: %v", err)
	}
	defer img.Close()
	assertSector0Hash(t, img, goldenFat32Sector0)
}

// TestFixtureGoldenHashes pins the first-sector SHA-256 for every fat32
// container variant in testdata/e01/.
func TestFixtureGoldenHashes(t *testing.T) {
	variants := []string{
		"encase25-sections2",
		"encase25-zlib",
		"encase25-zlib-slack",
		"encase6-sections2",
		"encase6-zlib",
	}
	for _, v := range variants {
		v := v
		t.Run(v, func(t *testing.T) {
			img, err := forensic.Open(context.Background(), fixturePath(t, "fat32", v), forensic.Options{})
			if err != nil {
				t.Fatalf("forensic.Open(fat32-%s): %v", v, err)
			}
			defer img.Close()
			assertSector0Hash(t, img, goldenFat32Sector0)
		})
	}
}

func assertSector0Hash(t *testing.T, img *forensic.Image, wantHex string) {
	t.Helper()
	data := make([]byte, 512)
	n, err := img.Source().ReadAt(0, data)
	if err != nil {
		t.Fatalf("ReadAt(0,512): %v", err)
	}
	if n != 512 {
		t.Fatalf("ReadAt(0,512) n = %d, want 512", n)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != wantHex {
		t.Fatalf("sector 0 SHA-256 = %s, want %s (fixture drift or platform-dependent bytes)", got, wantHex)
	}
}

func sameEntries(a, b []forensic.Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Path != b[i].Path {
			return false
		}
	}
	return true
}

func namePathsOf(entries []forensic.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name+"@"+e.Path)
	}
	return out
}
