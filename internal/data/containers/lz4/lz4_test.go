package lz4

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const testText = "sshd[1]: Accepted password for alice from 198.51.100.7\n"

// The fixtures below were produced once by the reference LZ4 frame encoder
// (python-lz4, which wraps liblz4) and are embedded so the tests stay
// hermetic: no external tool or network at test time.
const (
	// A one-block frame whose block is stored (uncompressed), with the
	// content-size field present. Decodes to testText.
	lz4FrameStoredHex = "04224d1868403700000000000000bb37000080737368645b315d3a2041636365707465642070617373776f726420666f7220616c6963652066726f6d203139382e35312e3130302e370a00000000"
	// The same frame with block and content checksums enabled.
	lz4FrameStoredChecksumsHex = "04224d187c4037000000000000004537000080737368645b315d3a2041636365707465642070617373776f726420666f7220616c6963652066726f6d203139382e35312e3130302e370a22b70c9d0000000022b70c9d"
	// A compressed block, no content size. Decodes to testText repeated 20x.
	lz4FrameCompressedHex = "04224d1860408246000000ff28737368645b315d3a2041636365707465642070617373776f726420666f7220616c6963652066726f6d203139382e35312e3130302e370a3700ffffffff015030302e370a00000000"
	// A compressed block with block and content checksums. Decodes to
	// testText repeated 20x.
	lz4FrameCompressedChecksumsHex = "04224d187c404c040000000000008646000000ff28737368645b315d3a2041636365707465642070617373776f726420666f7220616c6963652066726f6d203139382e35312e3130302e370a3700ffffffff015030302e370aaa764b95000000007d917b9f"
	// Two dependent blocks (64 KiB each, history carried across the block
	// boundary) with the content-size field. Decodes to testText repeated
	// 2000x (110000 bytes).
	lz4FrameLinkedHex = "04224d184840b0ad0100000000009242010000ff28737368645b315d3a2041636365707465642070617373776f726420666f7220616c6963652066726f6d203139382e35312e3130302e370a3700ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb15020666f7220b80000000fe1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff465030302e370a00000000"
	// The same 110000 bytes as independent blocks: the second block starts
	// with its own literals instead of referencing the first.
	lz4FrameIndependentHex = "04224d186840b0ad010000000000f542010000ff28737368645b315d3a2041636365707465642070617373776f726420666f7220616c6963652066726f6d203139382e35312e3130302e370a3700ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb15020666f7220f0000000ff28616c6963652066726f6d203139382e35312e3130302e370a737368645b315d3a2041636365707465642070617373776f726420666f72203700ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f5030302e370a00000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}
	return b
}

func openBytes(t *testing.T, stored []byte, limits Limits) (*Source, error) {
	t.Helper()
	return Open(2, source.NewMemorySourceWithImage(1, 9, stored), limits)
}

func mustOpen(t *testing.T, stored []byte) *Source {
	t.Helper()
	src, err := openBytes(t, stored, DefaultLimits())
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return src
}

func assertBytes(t *testing.T, src *Source, want []byte) {
	t.Helper()
	if got := src.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("decoded %d bytes, want %d", len(got), len(want))
	}
	if src.Len() != uint64(len(want)) {
		t.Fatalf("Len = %d, want %d", src.Len(), len(want))
	}
	buf := make([]byte, src.Len())
	n, err := src.ReadAt(0, buf)
	if err != nil {
		t.Fatalf("ReadAt error = %v", err)
	}
	if n != len(buf) || !bytes.Equal(buf, want) {
		t.Fatalf("ReadAt delivered %d bytes, want %d", n, len(want))
	}
}

func TestMatchesSignature(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want bool
	}{
		{"frame", []byte{0x04, 0x22, 0x4D, 0x18}, true},
		{"legacy", []byte{0x02, 0x21, 0x4C, 0x18}, true},
		{"skippable first", []byte{0x50, 0x2A, 0x4D, 0x18}, true},
		{"skippable last", []byte{0x5F, 0x2A, 0x4D, 0x18}, true},
		{"short", []byte{0x04, 0x22, 0x4D}, false},
		{"bzip2", []byte("BZh9"), false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		if got := MatchesSignature(tc.head); got != tc.want {
			t.Errorf("MatchesSignature(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestOpenDecodesStoredBlockFrame(t *testing.T) {
	stored := mustHex(t, lz4FrameStoredHex)
	src := mustOpen(t, stored)
	assertBytes(t, src, []byte(testText))
	if src.CompressedLen() != uint64(len(stored)) {
		t.Fatalf("CompressedLen = %d, want %d", src.CompressedLen(), len(stored))
	}
	meta := src.Meta()
	if meta.CompressedLen != uint64(len(stored)) || meta.DecompressedLen != uint64(len(testText)) {
		t.Fatalf("meta = %+v", meta)
	}
}

func TestOpenDecodesCompressedBlockFrame(t *testing.T) {
	src := mustOpen(t, mustHex(t, lz4FrameCompressedHex))
	assertBytes(t, src, bytes.Repeat([]byte(testText), 20))
}

func TestOpenVerifiesBlockAndContentChecksums(t *testing.T) {
	src := mustOpen(t, mustHex(t, lz4FrameStoredChecksumsHex))
	assertBytes(t, src, []byte(testText))

	src = mustOpen(t, mustHex(t, lz4FrameCompressedChecksumsHex))
	assertBytes(t, src, bytes.Repeat([]byte(testText), 20))
}

func TestOpenDecodesLinkedBlocks(t *testing.T) {
	// The second block references the previous block's 64 KiB dictionary; a
	// decoder that ignored the dependency would fail here.
	src := mustOpen(t, mustHex(t, lz4FrameLinkedHex))
	assertBytes(t, src, bytes.Repeat([]byte(testText), 2000))
}

func TestOpenDecodesIndependentBlocks(t *testing.T) {
	src := mustOpen(t, mustHex(t, lz4FrameIndependentHex))
	assertBytes(t, src, bytes.Repeat([]byte(testText), 2000))
}

func TestOpenDecodesConcatenatedFrames(t *testing.T) {
	first := mustHex(t, lz4FrameStoredHex)
	bytesIn := append(append([]byte(nil), first...), first...)
	src := mustOpen(t, bytesIn)
	assertBytes(t, src, []byte(testText+testText))
	if src.CompressedLen() != uint64(len(bytesIn)) {
		t.Fatalf("CompressedLen = %d, want %d", src.CompressedLen(), len(bytesIn))
	}
}

func skippableFrame(magic uint32, payload []byte) []byte {
	out := make([]byte, 8, 8+len(payload))
	binary.LittleEndian.PutUint32(out[0:], magic)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(payload)))
	return append(out, payload...)
}

func TestOpenSkippableFrameContributesNoBytes(t *testing.T) {
	bytesIn := skippableFrame(0x184D2A50, []byte("skip"))
	bytesIn = append(bytesIn, mustHex(t, lz4FrameStoredHex)...)
	src := mustOpen(t, bytesIn)
	assertBytes(t, src, []byte(testText))
}

func TestOpenSkippableFramePastEOFIsCorrupt(t *testing.T) {
	// Declares 64 payload bytes but supplies only 5.
	bytesIn := make([]byte, 8, 13)
	binary.LittleEndian.PutUint32(bytesIn[0:], 0x184D2A5F)
	binary.LittleEndian.PutUint32(bytesIn[4:], 64)
	bytesIn = append(bytesIn, "short"...)
	_, err := openBytes(t, bytesIn, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "skippable") {
		t.Fatalf("error = %q, want it to name the skippable frame", err)
	}
}

func TestOpenLegacyMagicIsUnsupported(t *testing.T) {
	stored := append([]byte{0x02, 0x21, 0x4C, 0x18}, make([]byte, 8)...)
	_, err := openBytes(t, stored, DefaultLimits())
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open error = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("error = %q, want it to name legacy framing", err)
	}
}

func TestOpenRejectsNonFrame(t *testing.T) {
	_, err := openBytes(t, []byte("this is not lz4"), DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "LZ4") {
		t.Fatalf("error = %q, want it to name LZ4", err)
	}
}

func TestOpenTooShortIsCorrupt(t *testing.T) {
	_, err := openBytes(t, []byte{0x04, 0x22, 0x4D}, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Fatalf("error = %q, want a too-short diagnostic", err)
	}
}

func TestOpenTruncatedIsCorrupt(t *testing.T) {
	stored := mustHex(t, lz4FrameStoredHex)
	for _, cut := range []int{len(stored) - 5, 14, 6} {
		_, err := openBytes(t, stored[:cut], DefaultLimits())
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open(%d bytes) error = %v, want ErrCorrupt", cut, err)
		}
		if !strings.Contains(err.Error(), "LZ4") {
			t.Fatalf("Open(%d bytes) error = %q, want it to name LZ4", cut, err)
		}
	}
}

func TestOpenHeaderChecksumMismatch(t *testing.T) {
	stored := mustHex(t, lz4FrameStoredHex)
	stored[14] ^= 0x01 // header checksum (4 magic + FLG + BD + 8 content size)
	_, err := openBytes(t, stored, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "header checksum") {
		t.Fatalf("error = %q, want a header-checksum diagnostic", err)
	}
}

func TestOpenBlockChecksumMismatch(t *testing.T) {
	stored := mustHex(t, lz4FrameStoredChecksumsHex)
	stored[20] ^= 0x01 // inside the stored block payload
	_, err := openBytes(t, stored, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "block checksum") {
		t.Fatalf("error = %q, want a block-checksum diagnostic", err)
	}
}

func TestOpenContentChecksumMismatch(t *testing.T) {
	stored := mustHex(t, lz4FrameStoredChecksumsHex)
	stored[len(stored)-1] ^= 0x01 // content checksum
	_, err := openBytes(t, stored, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "content checksum") {
		t.Fatalf("error = %q, want a content-checksum diagnostic", err)
	}
}

func testFrameHeader(flg, bd byte, contentSize *uint64, dictID []byte) []byte {
	desc := []byte{flg, bd}
	if contentSize != nil {
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], *contentSize)
		desc = append(desc, encoded[:]...)
	}
	desc = append(desc, dictID...)
	frame := []byte{0x04, 0x22, 0x4D, 0x18}
	frame = append(frame, desc...)
	return append(frame, byte(xxh32(desc, 0)>>8))
}

func endMark() []byte { return []byte{0, 0, 0, 0} }

func TestOpenContentSizeMismatch(t *testing.T) {
	declared := uint64(3)
	frame := testFrameHeader(0x68, 0x40, &declared, nil)
	frame = append(frame, 0x05, 0x00, 0x00, 0x80) // stored block of 5 bytes
	frame = append(frame, []byte("hello")...)
	frame = append(frame, endMark()...)
	_, err := openBytes(t, frame, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "content size") {
		t.Fatalf("error = %q, want a content-size diagnostic", err)
	}
}

func TestOpenContentSizeAccepted(t *testing.T) {
	declared := uint64(5)
	frame := testFrameHeader(0x68, 0x40, &declared, nil)
	frame = append(frame, 0x05, 0x00, 0x00, 0x80)
	frame = append(frame, []byte("hello")...)
	frame = append(frame, endMark()...)
	src := mustOpen(t, frame)
	assertBytes(t, src, []byte("hello"))
}

func TestOpenUnsupportedVersion(t *testing.T) {
	frame := testFrameHeader(0x00, 0x40, nil, nil) // version bits 00
	frame = append(frame, endMark()...)
	_, err := openBytes(t, frame, DefaultLimits())
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open error = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "version") {
		t.Fatalf("error = %q, want a version diagnostic", err)
	}
}

func TestOpenInvalidBlockMaximumIsCorrupt(t *testing.T) {
	frame := testFrameHeader(0x60, 0x30, nil, nil) // block-max code 3 is invalid
	frame = append(frame, endMark()...)
	_, err := openBytes(t, frame, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "block maximum") {
		t.Fatalf("error = %q, want a block-maximum diagnostic", err)
	}
}

func TestOpenDictionaryIDUnsupported(t *testing.T) {
	// Version 01 and the dictionary-ID flag; a 4-byte dictionary ID follows.
	frame := testFrameHeader(0x41, 0x40, nil, []byte{1, 2, 3, 4})
	frame = append(frame, endMark()...)
	_, err := openBytes(t, frame, DefaultLimits())
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open error = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "dictionary") {
		t.Fatalf("error = %q, want a dictionary diagnostic", err)
	}
}

func TestOpenOutputLimit(t *testing.T) {
	src, err := openBytes(t, mustHex(t, lz4FrameStoredHex), Limits{MaxDecodedBytes: 8})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open error = %v, want ErrUnsupported", err)
	}
	if src != nil {
		t.Fatal("Open returned a source together with an error")
	}
	if !strings.Contains(err.Error(), "8-byte limit") {
		t.Fatalf("error = %q, want it to state the limit", err)
	}
}

func TestSourceByteContract(t *testing.T) {
	stored := mustHex(t, lz4FrameStoredHex)
	src := mustOpen(t, stored)

	if src.SourceID() != 2 || src.ImageID() != 9 || src.SectorSize() != 512 || src.IsEmpty() {
		t.Fatalf("identity = id %d image %d sector %d empty %v",
			src.SourceID(), src.ImageID(), src.SectorSize(), src.IsEmpty())
	}

	buf := make([]byte, 10)
	n, err := src.ReadAt(0, buf)
	if err != nil || n != 10 || string(buf) != testText[:10] {
		t.Fatalf("ReadAt(0,10) = %d, %v, %q", n, err, buf)
	}

	n, err = src.ReadAt(src.Len()-5, make([]byte, 10))
	if err != nil || n != 5 {
		t.Fatalf("ReadAt(short tail) = %d, %v", n, err)
	}

	if _, err := src.ReadAt(src.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt(past end) error = %v, want ErrOutOfRange", err)
	}

	if n, err := src.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("ReadAt(empty) = %d, %v", n, err)
	}

	if n, err := src.ReadAtLossy(0, buf); n != 10 || err != nil {
		t.Fatalf("ReadAtLossy = %d, %v", n, err)
	}

	stats := src.Stats()
	if stats.DecompressedBytes != uint64(len(testText)) || stats.Reads == 0 || stats.BytesRead == 0 {
		t.Fatalf("stats = %+v", stats)
	}

	extents, err := src.Extents(0, src.Len())
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	if len(extents) != 1 {
		t.Fatalf("extents = %+v", extents)
	}
	want := source.ParentRange{Parent: 1, ParentOffset: 0, Len: uint64(len(stored)), Kind: source.RangeData}
	if extents[0] != want {
		t.Fatalf("extent = %+v, want %+v", extents[0], want)
	}
	if _, err := src.Extents(src.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("Extents(past end) error = %v, want ErrOutOfRange", err)
	}
	if extents, err := src.Extents(0, 0); err != nil || len(extents) != 0 {
		t.Fatalf("Extents(0,0) = %+v, %v", extents, err)
	}

	images, err := src.MapToImage(0, src.Len())
	if err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}
	if len(images) != 1 || images[0].ImageID != 9 || images[0].ImageOffset != 0 ||
		images[0].Len != uint64(len(stored)) || images[0].Kind != source.RangeData {
		t.Fatalf("images = %+v", images)
	}
}

func TestOpenSkippableOnlyIsEmpty(t *testing.T) {
	src := mustOpen(t, skippableFrame(0x184D2A51, []byte("nothing")))
	if !src.IsEmpty() || src.Len() != 0 {
		t.Fatalf("skippable-only source len = %d", src.Len())
	}
}

// ioFailSource delegates everything except ReadAt, which fails, so the
// decoder's I/O error mapping is exercised.
type ioFailSource struct{ source.ByteSource }

func (s ioFailSource) ReadAt(offset uint64, _ []byte) (int, error) {
	return 0, source.NewIOError(offset, errors.New("backing store failed"))
}

func TestOpenPropagatesIOErrors(t *testing.T) {
	parent := ioFailSource{source.NewMemorySource(1, mustHex(t, lz4FrameStoredHex))}
	_, err := Open(2, parent, DefaultLimits())
	if !errors.Is(err, source.ErrIO) {
		t.Fatalf("Open error = %v, want ErrIO", err)
	}
}

func TestOpenRejectsReservedDescriptorBits(t *testing.T) {
	cases := []struct {
		name string
		flg  byte
		bd   byte
	}{
		{"FLG reserved bit", 0x62, 0x40},
		{"BD reserved low bits", 0x60, 0x41},
		{"BD reserved high bit", 0x60, 0xC0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := testFrameHeader(tc.flg, tc.bd, nil, nil)
			frame = append(frame, endMark()...)
			_, err := openBytes(t, frame, DefaultLimits())
			if !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("Open error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestOpenBlockLargerThanMaximum(t *testing.T) {
	frame := testFrameHeader(0x60, 0x40, nil, nil) // 64 KiB blocks
	frame = append(frame, 0x01, 0x00, 0x01, 0x00)  // 65537-byte block
	_, err := openBytes(t, frame, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "block maximum") {
		t.Fatalf("error = %q, want a block-maximum diagnostic", err)
	}
}

func TestOpenTruncatedContentChecksum(t *testing.T) {
	stored := mustHex(t, lz4FrameStoredChecksumsHex)
	_, err := openBytes(t, stored[:len(stored)-1], DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
}

func TestMapToImageBoundsAndAppend(t *testing.T) {
	src := mustOpen(t, mustHex(t, lz4FrameStoredHex))

	if images, err := src.MapToImage(0, 0); err != nil || images != nil {
		t.Fatalf("MapToImage(0,0) = %+v, %v", images, err)
	}
	if _, err := src.MapToImage(src.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("MapToImage(past end) error = %v, want ErrOutOfRange", err)
	}

	out, err := src.ExtentsInto(0, src.Len(), []source.ParentRange{{Parent: 7}})
	if err != nil {
		t.Fatalf("ExtentsInto error = %v", err)
	}
	if len(out) != 2 || out[0].Parent != 7 || out[1].Parent != 1 {
		t.Fatalf("ExtentsInto = %+v, want the existing entry preserved", out)
	}
}
