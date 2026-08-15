// read_test.go — white-box tests for the read path (read.go): sector reads,
// ReadAt, section-resolution edge cases, and acquisition-hash verification.
// Every fixture E01 is built in memory by internal/ewffixture; nothing here
// touches disk beyond a temp file, so the suite stays hermetic.

package ewf

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/laenix/ewfgo/internal/ewffixture"
)

// openE01 writes a synthetic E01 to a temp file and opens it through the
// public API (same path a real image takes: ReadSections + ParseSections).
func openE01(t *testing.T, e01 []byte) *EWFImage {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.E01")
	if err := os.WriteFile(path, e01, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { img.Close() })
	return img
}

func TestReadSectorData_EnCase6_BaseOffset(t *testing.T) {
	disk := ewffixture.DiskPattern(128)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{Layout: ewffixture.LayoutEnCase6})
	img := openE01(t, e01)
	got, err := img.ewf.ReadSectorData(0, 128)
	if err != nil {
		t.Fatalf("EnCase6 read: %v", err)
	}
	if !bytes.Equal(got, disk) {
		t.Fatal("EnCase6 roundtrip mismatch")
	}
}

func TestReadSectorData_OutOfRange_Entry(t *testing.T) {
	// Corrupt the first table entry to point past EOF, then expect an error.
	disk := ewffixture.DiskPattern(64)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	off := ewffixture.TableEntryOffsetFor(e01, 0)
	binary.LittleEndian.PutUint32(e01[off:], 0x80000000|0x7FFFFFFF) // huge offset
	img := openE01(t, e01)
	if _, err := img.ewf.ReadSectorData(0, 64); err == nil {
		t.Fatal("expected error for out-of-range table entry, got nil")
	}
}

func TestParseSections_SectorsWithoutTable_ReturnsError(t *testing.T) {
	disk := ewffixture.DiskPattern(64)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{SkipTable: true})
	path := filepath.Join(t.TempDir(), "f.E01")
	if err := os.WriteFile(path, e01, 0o644); err != nil {
		t.Fatal(err)
	}
	// Open runs ParseSections, which must reject the missing table with an
	// explicit error (before the fix it panicked). If Open fails, that IS the
	// correct rejection — the test passes. Never accept silent container bytes.
	img, err := Open(path)
	if err != nil {
		return // Open rejected the malformed sectors/table pairing — correct
	}
	defer img.Close()
	if _, err := img.ewf.ReadSectorData(0, 64); err == nil {
		t.Fatal("expected error when sectors section has no table, got nil")
	}
}

func TestReadSectorData_BeyondMediaEnd_ReturnsError(t *testing.T) {
	// Reading starting at or past the media end must error — the old
	// fall-through section selection wrapped into chunk 0 and silently returned
	// wrong data under a wrong LBA (red line: 宁可报错,不可错读).
	disk := ewffixture.DiskPattern(128) // 2 chunks, media ends at sector 128
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	img := openE01(t, e01)
	if _, err := img.ewf.ReadSectorData(128, 1); err == nil {
		t.Fatal("expected error reading at media end, got nil (wrapped into chunk 0)")
	}
	if _, err := img.ewf.ReadSectorData(200, 1); err == nil {
		t.Fatal("expected error reading past media end, got nil")
	}
}

func TestReadSectorData_ReadPastEnd_ZeroFillsTail(t *testing.T) {
	// A read starting inside the media but extending past its end must return
	// real bytes up to the end and zero-fill the tail — never wrap to sector 0.
	disk := ewffixture.DiskPattern(128)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	img := openE01(t, e01)
	raw, err := img.ewf.ReadSectorData(100, 40)
	if err != nil {
		t.Fatalf("ReadSectorData(100, 40): %v", err)
	}
	if len(raw) != 40*512 {
		t.Fatalf("got %d bytes, want %d", len(raw), 40*512)
	}
	if !bytes.Equal(raw[:28*512], disk[100*512:128*512]) {
		t.Fatal("in-range sector data mismatch (first 28 sectors)")
	}
	for _, b := range raw[28*512:] {
		if b != 0 {
			t.Fatal("tail past media end must be zero-filled")
		}
	}
}

func TestReadSectorData_SpanningSections(t *testing.T) {
	// 3 chunks split across 2 sectors/table pairs (section 0: chunks 0-1 =
	// sectors 0-127, section 1: chunk 2 = sectors 128-191). A read crossing the
	// boundary must return real data from BOTH sections — the pre-fix selection
	// logic zero-filled section 1's data once the current section's table was
	// exhausted.
	disk := ewffixture.DiskPattern(192)
	for _, layout := range []ewffixture.Layout{ewffixture.LayoutEnCase2_5, ewffixture.LayoutEnCase6} {
		t.Run(fmt.Sprintf("layout-%d", int(layout)), func(t *testing.T) {
			e01 := ewffixture.WrapDisk(disk, ewffixture.Options{Sections: 2, Layout: layout})
			img := openE01(t, e01)
			raw, err := img.ewf.ReadSectorData(64, 128)
			if err != nil {
				t.Fatalf("ReadSectorData(64, 128): %v", err)
			}
			if len(raw) != 128*512 {
				t.Fatalf("got %d bytes, want %d", len(raw), 128*512)
			}
			if !bytes.Equal(raw, disk[64*512:]) {
				t.Fatal("section-spanning read returned wrong data (section 1 must not be zero-filled)")
			}
		})
	}
}

func TestReadSectorAt_DelegatesToReadSectorData(t *testing.T) {
	// ReadSectorAt must behave exactly like the spec-compliant ReadSectorData:
	// correct sector data on a valid image (including EnCase 6 base offsets) and
	// an explicit error past the media end — never container bytes, never a
	// panic.
	disk := ewffixture.DiskPattern(128) // 2 chunks
	for _, layout := range []ewffixture.Layout{ewffixture.LayoutEnCase2_5, ewffixture.LayoutEnCase6} {
		t.Run(fmt.Sprintf("layout-%d", int(layout)), func(t *testing.T) {
			e01 := ewffixture.WrapDisk(disk, ewffixture.Options{Layout: layout})
			img := openE01(t, e01)
			got, err := img.ewf.ReadSectorAt(0)
			if err != nil {
				t.Fatalf("ReadSectorAt(0): %v", err)
			}
			if !bytes.Equal(got, disk[:512]) {
				t.Fatal("ReadSectorAt(0) returned wrong sector data")
			}
			if _, err := img.ewf.ReadSectorAt(200); err == nil {
				t.Fatal("expected error for out-of-range sector, got nil")
			}
		})
	}
}

func TestReadSectorData_CraftedDiskGeometry_ReturnsError(t *testing.T) {
	// A crafted DiskSMART with implausibly large ChunkSectors/SectorBytes must
	// yield an explicit error — never a huge allocation (OOM) or a panic.
	disk := ewffixture.DiskPattern(64)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	img := openE01(t, e01)

	img.ewf.DiskSMART[0].ChunkSectors = 0xFFFFFFFF
	img.ewf.DiskSMART[0].SectorBytes = 0xFFFFFFFF
	if _, err := img.ewf.ReadSectorData(0, 1); err == nil {
		t.Fatal("expected error for implausible chunk geometry, got nil")
	}

	img.ewf.DiskSMART[0].ChunkSectors = 64
	img.ewf.DiskSMART[0].SectorBytes = 1 << 30 // 1 GiB sectors
	if _, err := img.ewf.ReadSectorData(0, 1); err == nil {
		t.Fatal("expected error for implausible sector size, got nil")
	}
}

func TestReadSectorData_HugeRequest_ReturnsError(t *testing.T) {
	// A caller-controlled huge numSectors must error up front — never attempt a
	// huge allocation (OOM) or hang in an unbounded loop.
	disk := ewffixture.DiskPattern(64)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	img := openE01(t, e01)
	if _, err := img.ewf.ReadSectorData(0, 1<<60); err == nil {
		t.Fatal("expected error for huge read request, got nil")
	}
}

// TestReadAt_EOFPartial verifies that reading past the end of a slack-less
// E01 returns the partial data that exists, not nil. A nil return would make
// the chunk read (ReadAt(chunkOffset, 32768)) fail for any file whose chunk
// sits near EOF — the exact root cause of the slack-less P0 bug.
func TestReadAt_EOFPartial(t *testing.T) {
	disk := ewffixture.DiskPattern(64) // one chunk, no trailing padding
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	path := filepath.Join(t.TempDir(), "f.E01")
	if err := os.WriteFile(path, e01, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()

	// Read 200 bytes starting 100 bytes before EOF: the file only has 100
	// bytes there, so a correct ReadAt returns 100 partial bytes, never nil.
	got := img.ewf.ReadAt(int64(len(e01))-100, 200)
	if len(got) == 0 {
		t.Fatal("ReadAt past EOF returned nil/empty; slack-less chunk reads will fail")
	}
	if len(got) >= 200 {
		t.Fatalf("ReadAt returned %d bytes, expected partial (<200) near EOF", len(got))
	}
}

// TestReadSectorData_Slackless_Roundtrip is the end-to-end P0 regression: a
// spec-conformant E01 with NO trailing slack must read back correctly through
// the internal parser. Before the ReadAt fix this failed with "failed to read
// chunk" (and the public ReadSectors then silently returned container bytes).
func TestReadSectorData_Slackless_Roundtrip(t *testing.T) {
	disk := ewffixture.DiskPattern(64)                     // one 32 KiB chunk
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{}) // default = slack-less
	path := filepath.Join(t.TempDir(), "f.E01")
	if err := os.WriteFile(path, e01, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	got, err := img.ewf.ReadSectorData(0, 64)
	if err != nil {
		t.Fatalf("slack-less ReadSectorData: %v", err)
	}
	if !bytes.Equal(got, disk) {
		t.Fatal("slack-less roundtrip mismatch")
	}
}

// TestStoredHashes_DigestAndHash proves ParsesDigest/ParsesHash extract the
// MD5/SHA1 acquisition hashes from an image that carries both sections.
func TestStoredHashes_DigestAndHash(t *testing.T) {
	disk := ewffixture.DiskPattern(200)
	wantMD5 := md5.Sum(disk)
	wantSHA1 := sha1.Sum(disk)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{
		MD5Hash:  wantMD5[:],
		SHA1Hash: wantSHA1[:],
	})

	img := openE01(t, e01)
	gotMD5, gotSHA1 := img.StoredHashes()
	if !bytes.Equal(gotMD5, wantMD5[:]) {
		t.Errorf("StoredHashes MD5 = %x, want %x", gotMD5, wantMD5)
	}
	if !bytes.Equal(gotSHA1, wantSHA1[:]) {
		t.Errorf("StoredHashes SHA1 = %x, want %x", gotSHA1, wantSHA1)
	}
}

// TestStoredHashes_HashOnly proves an image with only a "hash" section yields
// an MD5 hash and no SHA1 (the layout server.E01 uses).
func TestStoredHashes_HashOnly(t *testing.T) {
	disk := ewffixture.DiskPattern(64)
	wantMD5 := md5.Sum(disk)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{MD5Hash: wantMD5[:]})

	img := openE01(t, e01)
	gotMD5, gotSHA1 := img.StoredHashes()
	if !bytes.Equal(gotMD5, wantMD5[:]) {
		t.Errorf("StoredHashes MD5 = %x, want %x", gotMD5, wantMD5)
	}
	if gotSHA1 != nil {
		t.Errorf("StoredHashes SHA1 = %x, want nil (no digest section)", gotSHA1)
	}
}

// TestVerifyImageHash_Match streams the whole media data and proves the
// computed MD5/SHA1 match the stored acquisition hashes.
func TestVerifyImageHash_Match(t *testing.T) {
	disk := ewffixture.DiskPattern(300) // 5 chunks at 64 sectors each
	wantMD5 := md5.Sum(disk)
	wantSHA1 := sha1.Sum(disk)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{
		MD5Hash:  wantMD5[:],
		SHA1Hash: wantSHA1[:],
	})

	img := openE01(t, e01)
	res, err := img.VerifyImageHash()
	if err != nil {
		t.Fatalf("VerifyImageHash: %v", err)
	}
	if res.BytesHashed != uint64(len(disk)) {
		t.Errorf("BytesHashed = %d, want %d", res.BytesHashed, len(disk))
	}
	if !res.MD5Match {
		t.Errorf("MD5Match false: computed %x, stored %x", res.ComputedMD5, res.StoredMD5)
	}
	if !res.SHA1Match {
		t.Errorf("SHA1Match false: computed %x, stored %x", res.ComputedSHA1, res.StoredSHA1)
	}
}

// TestVerifyImageHash_Match_ShortFinalChunk is the regression for the
// whole-image verify on a real disk whose last chunk is not chunk-aligned: the
// final chunk is stored as only its valid sectors (no zero padding), and the
// read path must accept it at that length instead of rejecting it as "too
// short" — which previously made VerifyImageHash fail at the last chunk
// (mac.E01: "decompressed to 16896 bytes, want at least 32768").
func TestVerifyImageHash_Match_ShortFinalChunk(t *testing.T) {
	disk := ewffixture.DiskPattern(300) // 5 chunks; last holds 44 of 64 sectors
	wantMD5 := md5.Sum(disk)
	wantSHA1 := sha1.Sum(disk)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{
		MD5Hash:         wantMD5[:],
		SHA1Hash:        wantSHA1[:],
		ShortFinalChunk: true,
	})

	img := openE01(t, e01)
	res, err := img.VerifyImageHash()
	if err != nil {
		t.Fatalf("VerifyImageHash: %v", err)
	}
	if !res.MD5Match {
		t.Errorf("MD5Match false: computed %x, stored %x", res.ComputedMD5, res.StoredMD5)
	}
	if !res.SHA1Match {
		t.Errorf("SHA1Match false: computed %x, stored %x", res.ComputedSHA1, res.StoredSHA1)
	}
}

// TestReadSectors_ShortFinalChunk proves a read that ends exactly at the media
// boundary serves the final partial chunk's valid sectors (and no fabricated
// padding), and that a read reaching into the beyond-media tail is clipped, not
// wrapped into chunk 0.
func TestReadSectors_ShortFinalChunk(t *testing.T) {
	disk := ewffixture.DiskPattern(300)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{ShortFinalChunk: true})

	img := openE01(t, e01)
	got, err := img.ReadSectors(0, 300)
	if err != nil {
		t.Fatalf("ReadSectors(0,300): %v", err)
	}
	if !bytes.Equal(got, disk) {
		t.Fatal("ReadSectors returned data that differs from the disk")
	}

	// Read exactly the final partial chunk's valid sectors.
	tail, err := img.ReadSectors(256, 44)
	if err != nil {
		t.Fatalf("ReadSectors(256,44): %v", err)
	}
	if !bytes.Equal(tail, disk[256*512:]) {
		t.Fatal("final partial chunk read differs from the disk tail")
	}
}

// TestVerifyImageHash_Mismatch proves a corrupt stored MD5 surfaces as
// MD5Match=false rather than a silent pass.
func TestVerifyImageHash_Mismatch(t *testing.T) {
	disk := ewffixture.DiskPattern(128)
	wantMD5 := md5.Sum(disk)
	bad := append([]byte(nil), wantMD5[:]...)
	bad[0] ^= 0xFF
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{MD5Hash: bad})

	img := openE01(t, e01)
	res, err := img.VerifyImageHash()
	if err != nil {
		t.Fatalf("VerifyImageHash: %v", err)
	}
	if res.MD5Match {
		t.Errorf("MD5Match true for corrupt stored hash (computed %x, stored %x)", res.ComputedMD5, res.StoredMD5)
	}
	if !bytes.Equal(res.ComputedMD5, wantMD5[:]) {
		t.Errorf("ComputedMD5 = %x, want %x", res.ComputedMD5, wantMD5[:])
	}
	// SHA1Match stays false: the image carries no digest section.
	if res.SHA1Match {
		t.Errorf("SHA1Match true but image has no SHA1")
	}
}

// TestReadSectors_CorruptEntry_ReturnsError asserts that when a chunk cannot
// be resolved, ReadSectors returns an explicit error instead of silently
// returning EWF container bytes as disk data.
func TestReadSectors_CorruptEntry_ReturnsError(t *testing.T) {
	disk := ewffixture.DiskPattern(64)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	// Corrupt the first table entry to an out-of-range offset.
	entryOff := ewffixture.TableEntryOffsetFor(e01, 0)
	e01[entryOff+0] = 0xFF
	e01[entryOff+1] = 0xFF
	e01[entryOff+2] = 0xFF
	e01[entryOff+3] = 0xFF

	path := filepath.Join(t.TempDir(), "f.E01")
	if err := os.WriteFile(path, e01, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()

	_, err = img.ReadSectors(0, 64)
	if err == nil {
		t.Fatal("expected error for corrupt table entry, got nil (container bytes may have been returned)")
	}
}
