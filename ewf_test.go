package ewf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/laenix/ewfgo/internal/ewffixture"
)

func TestE01ContainerMatrix(t *testing.T) {
	const nSectors = uint64(128) // 2 chunks
	disk := ewffixture.DiskPattern(nSectors)

	cases := []struct {
		name    string
		opts    ewffixture.Options
		wantErr bool // true: expect an explicit error, never silent wrong data
	}{
		{"encase25-zlib-slack", ewffixture.Options{Layout: ewffixture.LayoutEnCase2_5, Compress: ewffixture.CompressZlib, SlackBytes: 512}, false},
		{"encase25-zlib-slackless", ewffixture.Options{Layout: ewffixture.LayoutEnCase2_5, Compress: ewffixture.CompressZlib, SlackBytes: 0}, false},
		{"encase25-none-slackless", ewffixture.Options{Layout: ewffixture.LayoutEnCase2_5, Compress: ewffixture.CompressNone, SlackBytes: 0}, false},
		{"encase6-zlib-slackless", ewffixture.Options{Layout: ewffixture.LayoutEnCase6, Compress: ewffixture.CompressZlib, SlackBytes: 0}, false},
		{"encase6-none-slackless", ewffixture.Options{Layout: ewffixture.LayoutEnCase6, Compress: ewffixture.CompressNone, SlackBytes: 0}, false},
		// Multi-table images: chunks split across 2 sectors/table pairs (design
		// spec matrix dimension "多 table 节"). 128 sectors = 2 chunks → each
		// section holds 1 chunk; the roundtrip read spans both sections.
		{"encase25-zlib-sections2", ewffixture.Options{Sections: 2}, false},
		{"encase6-zlib-sections2", ewffixture.Options{Layout: ewffixture.LayoutEnCase6, Sections: 2}, false},
		// EnCase 1 stores chunks inside the table section with no separate
		// sectors section; the parser synthesizes the sectors list from the
		// tables and the image roundtrips through the normal read path.
		{"encase1-zlib-slackless", ewffixture.Options{Layout: ewffixture.LayoutEnCase1, Compress: ewffixture.CompressZlib, SlackBytes: 0}, false},
		{"encase1-none-slackless", ewffixture.Options{Layout: ewffixture.LayoutEnCase1, Compress: ewffixture.CompressNone, SlackBytes: 0}, false},
		// No table section: parser must error, not panic.
		{"sectors-no-table", ewffixture.Options{SkipTable: true}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e01 := ewffixture.WrapDisk(disk, tc.opts)
			path := filepath.Join(t.TempDir(), "f.E01")
			if err := os.WriteFile(path, e01, 0o644); err != nil {
				t.Fatal(err)
			}
			img, err := Open(path)
			if err != nil {
				// Open runs ParseSections; a malformed fixture may be rejected
				// there. For wantErr cases that rejection is the correct
				// outcome; for roundtrip cases it is a bug.
				if tc.wantErr {
					return
				}
				t.Fatalf("Open: %v", err)
			}
			defer img.Close()

			raw, err := img.ewf.ReadSectorData(0, nSectors)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected explicit error, got %d bytes", len(raw))
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadSectorData: %v", err)
			}
			if !bytes.Equal(raw, disk) {
				t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(raw), len(disk))
			}
		})
	}
}

// TestSparseTail ensures a chunk table shorter than the full disk yields zeros
// for the missing tail (never container bytes).
func TestSparseTail(t *testing.T) {
	// Build a 1-chunk table but ask for 2 chunks worth of sectors.
	disk := ewffixture.DiskPattern(64)
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
	raw, err := img.ewf.ReadSectorData(0, 128)
	if err != nil {
		t.Fatalf("ReadSectorData: %v", err)
	}
	if len(raw) != 128*512 {
		t.Fatalf("got %d bytes, want %d", len(raw), 128*512)
	}
	if !bytes.Equal(raw[:64*512], disk) {
		t.Fatal("first chunk mismatch")
	}
	for _, b := range raw[64*512:] {
		if b != 0 {
			t.Fatal("tail chunk must be zero-filled")
		}
	}
}

// TestE01MultiSegment verifies multi-segment E01 images (E01 + E02) read as one
// logical disk. Both chunks are read individually and as a full roundtrip. The
// cross-boundary case uses a tables-only (EnCase 1) layout in both segments with
// chunk 0 in segment 1 and chunks 1..n-1 in segment 2; the raw cross-segment
// span read (head from segment 1 + tail from segment 2) is covered separately by
// TestReadAt_CrossSegmentSpan.
func TestE01MultiSegment(t *testing.T) {
	const nSectors = uint64(64) // 2 chunks of 32 sectors each
	disk := ewffixture.DiskPattern(nSectors)

	cases := []struct {
		name         string
		opts         ewffixture.Options
		crossSegment bool
	}{
		{"aligned-zlib", ewffixture.Options{ChunkSectors: 32, Compress: ewffixture.CompressZlib}, false},
		{"aligned-none", ewffixture.Options{ChunkSectors: 32, Compress: ewffixture.CompressNone}, false},
		// Tables-only EnCase 1 layout in both segments (chunk 0 in segment 1,
		// chunks 1..n-1 in segment 2). Exercises the EnCase 1 synthesis over
		// multiple segments. Both segments are valid EWF files, so sibling
		// validation accepts them.
		{"cross-boundary", ewffixture.Options{ChunkSectors: 32, Compress: ewffixture.CompressNone}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			segs := ewffixture.WrapDiskSegments(disk, tc.opts, tc.crossSegment)
			dir := t.TempDir()
			var paths []string
			for i, seg := range segs {
				p := filepath.Join(dir, fmt.Sprintf("img.E%02d", i+1))
				if err := os.WriteFile(p, seg, 0o644); err != nil {
					t.Fatal(err)
				}
				paths = append(paths, p)
			}
			img, err := Open(paths[0])
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer img.Close()

			chunk0, err := img.ewf.ReadSectorData(0, 32)
			if err != nil {
				t.Fatalf("ReadSectorData(0,32): %v", err)
			}
			if !bytes.Equal(chunk0, disk[:32*512]) {
				t.Fatal("chunk 0 mismatch (head of chunk must come from segment 1)")
			}

			chunk1, err := img.ewf.ReadSectorData(32, 32)
			if err != nil {
				t.Fatalf("ReadSectorData(32,32): %v", err)
			}
			if !bytes.Equal(chunk1, disk[32*512:]) {
				t.Fatal("chunk 1 mismatch (data must come from segment 2)")
			}

			all, err := img.ewf.ReadSectorData(0, nSectors)
			if err != nil {
				t.Fatalf("ReadSectorData(0,64): %v", err)
			}
			if !bytes.Equal(all, disk) {
				t.Fatalf("full roundtrip mismatch: got %d bytes, want %d", len(all), len(disk))
			}
		})
	}
}

// TestE01MultiSegment_ValidSiblingsReadExactBytes verifies that a valid
// two-segment image (both segments carrying the EVF signature and ascending
// segment numbers) reads back exact disk bytes with no error.
func TestE01MultiSegment_ValidSiblingsReadExactBytes(t *testing.T) {
	const nSectors = uint64(64)
	disk := ewffixture.DiskPattern(nSectors)
	segs := ewffixture.WrapDiskSegments(disk, ewffixture.Options{ChunkSectors: 32, Compress: ewffixture.CompressZlib}, false)
	dir := t.TempDir()
	var paths []string
	for i, seg := range segs {
		p := filepath.Join(dir, fmt.Sprintf("img.E%02d", i+1))
		if err := os.WriteFile(p, seg, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	img, err := Open(paths[0])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()
	raw, err := img.ewf.ReadSectorData(0, nSectors)
	if err != nil {
		t.Fatalf("ReadSectorData: %v", err)
	}
	if !bytes.Equal(raw, disk) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(raw), len(disk))
	}
}

// TestE01MultiSegment_GarbageSibling_OpenFails verifies that a valid
// two-segment image whose E02 is replaced by 34 garbage bytes makes Open fail
// loudly — the sibling is not a valid EWF segment (no EVF signature), and even
// without the signature check the segment walk would error. It must never
// silently zero-fill the second chunk.
func TestE01MultiSegment_GarbageSibling_OpenFails(t *testing.T) {
	const nSectors = uint64(64)
	disk := ewffixture.DiskPattern(nSectors)
	segs := ewffixture.WrapDiskSegments(disk, ewffixture.Options{ChunkSectors: 32, Compress: ewffixture.CompressZlib}, false)
	dir := t.TempDir()
	p1 := filepath.Join(dir, "img.E01")
	p2 := filepath.Join(dir, "img.E02")
	if err := os.WriteFile(p1, segs[0], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, bytes.Repeat([]byte{0xFF}, 34), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p1); err == nil {
		t.Fatal("expected Open to fail on garbage sibling segment, got nil")
	}
}

// TestOpen_MultiSegmentFailure_ClosesSiblingHandles verifies that when sibling
// discovery opens segments 2..k and then fails on segment k+1, the already-open
// sibling handles are closed. On Windows an open handle locks the file, so a
// successful Remove of the previously-opened E02 proves the leak is fixed.
func TestOpen_MultiSegmentFailure_ClosesSiblingHandles(t *testing.T) {
	const nSectors = uint64(64)
	disk := ewffixture.DiskPattern(nSectors)
	segs := ewffixture.WrapDiskSegments(disk, ewffixture.Options{ChunkSectors: 32, Compress: ewffixture.CompressZlib}, false)
	dir := t.TempDir()
	p1 := filepath.Join(dir, "img.E01")
	p2 := filepath.Join(dir, "img.E02")
	p3 := filepath.Join(dir, "img.E03")
	if err := os.WriteFile(p1, segs[0], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, segs[1], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p3, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p1); err == nil {
		t.Fatal("expected Open to fail on garbage E03 sibling")
	}
	if err := os.Remove(p2); err != nil {
		t.Fatalf("img.E02 still locked after failed open (segment handle leak): %v", err)
	}
}

// TestReadAt_CrossSegmentSpan verifies that a single ReadAt whose window
// crosses a segment boundary takes its head from segment 1 and its tail from
// segment 2, concatenated — the span-read path used for chunk reads that
// straddle two segment files.
func TestReadAt_CrossSegmentSpan(t *testing.T) {
	const nSectors = uint64(64)
	disk := ewffixture.DiskPattern(nSectors)
	segs := ewffixture.WrapDiskSegments(disk, ewffixture.Options{ChunkSectors: 32, Compress: ewffixture.CompressNone}, false)
	dir := t.TempDir()
	var paths []string
	for i, seg := range segs {
		p := filepath.Join(dir, fmt.Sprintf("img.E%02d", i+1))
		if err := os.WriteFile(p, seg, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	img, err := Open(paths[0])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	seg1Size := int64(len(segs[0]))
	got := img.ewf.ReadAt(seg1Size-100, 200)
	if len(got) != 200 {
		t.Fatalf("span read returned %d bytes, want 200", len(got))
	}
	if !bytes.Equal(got[:100], segs[0][seg1Size-100:]) {
		t.Fatal("span read head (segment 1) mismatch")
	}
	if !bytes.Equal(got[100:], segs[1][:100]) {
		t.Fatal("span read tail (segment 2) mismatch")
	}
}

// TestParseTable_NearEOFHugeSectionSize_NoPanic reproduces the crafted-input
// OOM panic: a "table" section whose descriptor sits in the last 100 bytes of a
// tiny image. Address+76 (the 24-byte table header) is readable, but
// Address+100 (the payload start) is at/past EOF, so the old guard
// `payloadStart < total` short-circuited and a SectionSize near 2^63 drove
// make([]byte, ~2^63) inside ReadAt — a panic. The parser must return an
// explicit error, never panic.
//
// File layout (113 bytes total):
//
//	[0:13)   EVF file header
//	[13:89)  "table" section descriptor: name, NextOffset=0, SectionSize=maxInt64
//	[89:113) 24 bytes of table header data so the header read succeeds
//
// payloadStart = 13+76+24 = 113 >= total = 113, the vulnerable path pre-fix.
func TestParseTable_NearEOFHugeSectionSize_NoPanic(t *testing.T) {
	const total = 113
	buf := make([]byte, total)
	copy(buf[0:8], []byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00})
	buf[8] = 0x01
	binary.LittleEndian.PutUint16(buf[9:], 1)
	copy(buf[13:29], []byte("table"))
	binary.LittleEndian.PutUint64(buf[13+16:], 0)                  // NextOffset: stop the walk
	binary.LittleEndian.PutUint64(buf[13+24:], 0x7FFFFFFFFFFFFFFF) // SectionSize ≈ 2^63

	path := filepath.Join(t.TempDir(), "f.E01")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := Open(path)
	if err == nil {
		defer img.Close()
		_, err = img.ewf.ReadSectorData(0, 1)
	}
	if err == nil {
		t.Fatal("expected explicit error for crafted near-EOF table section, got nil (no panic)")
	}
}

// TestParseHeader_HugeSectionSize_NoPanic reproduces the crafted-input OOM
// panic in ParseHeader: a "header"/"header2" section whose SectionSize is near
// 2^63 makes length = MaxInt64-76 pass the length<0 guard in ReadAt and reach
// make([]byte, ~2^63) — a panic. The parser must reject the absurd SectionSize
// with an explicit error and ParseSections must propagate it, never panic.
// Mirrors TestParseTable_NearEOFHugeSectionSize_NoPanic.
func TestParseHeader_HugeSectionSize_NoPanic(t *testing.T) {
	const total = 113
	buf := make([]byte, total)
	copy(buf[0:8], []byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00})
	buf[8] = 0x01
	binary.LittleEndian.PutUint16(buf[9:], 1)
	copy(buf[13:29], []byte("header"))
	binary.LittleEndian.PutUint64(buf[13+16:], 0)                  // NextOffset: stop the walk
	binary.LittleEndian.PutUint64(buf[13+24:], 0x7FFFFFFFFFFFFFFF) // SectionSize ≈ 2^63

	path := filepath.Join(t.TempDir(), "f.E01")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := Open(path)
	if err == nil {
		defer img.Close()
		_, err = img.ewf.ReadSectorData(0, 1)
	}
	if err == nil {
		t.Fatal("expected explicit error for crafted near-EOF header section, got nil (no panic)")
	}
}
