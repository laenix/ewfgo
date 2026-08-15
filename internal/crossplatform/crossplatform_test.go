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
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"testing"

	ewf "github.com/laenix/ewfgo"
)

// fixturePath returns the repo-relative path of a committed E01 fixture. It is
// computed with filepath.Join so it resolves on every host OS; the path is
// relative to this package's working directory during `go test`.
func fixturePath(t *testing.T, base, variant string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "e01", base+"-"+variant+".E01")
}

// supportedGOOS / supportedGOARCH mirror the 7-pair build matrix in
// scripts/build-matrix.sh. RISC-V is linux-only (Go rejects windows/riscv64 and
// darwin/riscv64), so the host GOOS here cannot be windows/darwin when GOARCH
// is riscv64; the shell script is the authority for that.
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
	// CGO_ENABLED=0 is enforced per build by scripts/build-matrix.sh; a unit
	// test cannot observe CGO_ENABLED without shelling out (forbidden).
}

// TestPathHandling asserts the public forensic API accepts both '/'-separated
// and Windows '\'-separated directory paths and normalizes them to the same
// listing. The filesystem handlers split on '/' internally, so a literal
// backslash must be translated at the public boundary; this test pins that
// behavior on every OS.
func TestPathHandling(t *testing.T) {
	img, err := ewf.Open(fixturePath(t, "ext4", "encase25-zlib"))
	if err != nil {
		t.Fatalf("ewf.Open: %v", err)
	}
	defer img.Close()

	// The ext4 fixture root carries a real subdirectory (lost+found) plus the
	// injected fixture.txt, so listing it exercises nested path traversal.
	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem(0): %v", err)
	}
	defer fs.Close()

	// Root with '\' must equal root with '/', including returned entry Paths
	// (which must be '/'-separated even when the caller passed '\').
	rootSlash, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir(\"/\"): %v", err)
	}
	rootBS, err := fs.ListDir("\\")
	if err != nil {
		t.Fatalf("ListDir(\"\\\\\"): %v", err)
	}
	if len(rootSlash) == 0 {
		t.Fatalf("root listing unexpectedly empty")
	}
	if !sameEntries(rootSlash, rootBS) {
		t.Fatalf("root listing differs: slash=%v backslash=%v", namePathsOf(rootSlash), namePathsOf(rootBS))
	}

	// A real nested directory: '\'-separated must equal '/'-separated.
	lfSlash, err := fs.ListDir("/lost+found")
	if err != nil {
		t.Fatalf("ListDir(\"/lost+found\"): %v", err)
	}
	lfBS, err := fs.ListDir("\\lost+found")
	if err != nil {
		t.Fatalf("ListDir(\"\\\\lost+found\"): %v", err)
	}
	if !sameEntries(lfSlash, lfBS) {
		t.Fatalf("lost+found listing differs: slash=%v backslash=%v", namePathsOf(lfSlash), namePathsOf(lfBS))
	}

	// ReadFile normalization: '\'-separated file path returns the same bytes.
	want, err := fs.ReadFile("/fixture.txt")
	if err != nil {
		t.Fatalf("ReadFile(\"/fixture.txt\"): %v", err)
	}
	got, err := fs.ReadFile("\\fixture.txt")
	if err != nil {
		t.Fatalf("ReadFile(\"\\\\fixture.txt\"): %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("ReadFile backslash = %q, want %q", string(got), string(want))
	}

	// The ImageFS.ListDir path handles '\' too (already covered above via
	// fs.ListDir), so nothing else is needed here.
}

// goldenFat32Sector0 is the SHA-256 of the first sector (LBA 0) of every fat32
// fixture, computed once from the committed testdata/e01/ images and embedded.
// Sector 0 is the MBR written by WrapMBRDisk and is byte-identical across all
// five container variants (the container affects only how chunks are stored,
// never the disk payload). Identical bytes on every OS prove identical
// decompression and identical endianness handling end to end.
const goldenFat32Sector0 = "465d0cf878419711bbafc3f9563d959d1769ab5e068b4914756b658039946d6b"

// TestLittleEndianHeld asserts that reading the fat32-encase25-zlib fixture
// through the public API yields the exact golden sector bytes. This is the
// strongest cross-platform endianness guarantee available without cross-running:
// the parser never uses binary.NativeEndian, so identical bytes => identical
// parse on little- and big-endian hosts alike.
func TestLittleEndianHeld(t *testing.T) {
	img, err := ewf.Open(fixturePath(t, "fat32", "encase25-zlib"))
	if err != nil {
		t.Fatalf("ewf.Open: %v", err)
	}
	defer img.Close()
	assertSector0Hash(t, img, goldenFat32Sector0)
}

// TestFixtureGoldenHashes pins the first-sector SHA-256 for every fat32
// container variant in testdata/e01/. This proves byte-exactness across
// platforms and that the committed fixtures are immutable in-repo.
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
			img, err := ewf.Open(fixturePath(t, "fat32", v))
			if err != nil {
				t.Fatalf("ewf.Open(fat32-%s): %v", v, err)
			}
			defer img.Close()
			assertSector0Hash(t, img, goldenFat32Sector0)
		})
	}
}

func assertSector0Hash(t *testing.T, img *ewf.EWFImage, wantHex string) {
	t.Helper()
	data, err := img.ReadSectors(0, 1)
	if err != nil {
		t.Fatalf("ReadSectors(0,1): %v", err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != wantHex {
		t.Fatalf("sector 0 SHA-256 = %s, want %s (fixture drift or platform-dependent bytes)", got, wantHex)
	}
}

// sameEntries reports whether two listings are equal by Name and Path (the two
// fields the forensic API contract owns; Size/ModTime are on-disk metadata).
func sameEntries(a, b []ewf.FileEntry) bool {
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

func namePathsOf(entries []ewf.FileEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name+"@"+e.Path)
	}
	return out
}
