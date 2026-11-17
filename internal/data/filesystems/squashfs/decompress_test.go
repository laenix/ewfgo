package squashfs

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The compressed vectors below are embedded so the tests are hermetic: nothing
// reads the reference fixture tree at test time.
//
//   - lzmaVector is an LZMA-alone stream (13-byte header) produced by
//     liblzma, the format SquashFS's LZMA wrapper stores.
//   - xzVector is a complete .xz container with a CRC32 check, the format
//     SquashFS's XZ wrapper stores.
//   - lz4LiteralVector / lz4MatchVector are raw LZ4 blocks, one literal-only
//     and one with a back-reference.
//   - lzoLiteralVector / lzoMatchVector are raw LZO1X blocks; the literal one
//     is the reference crate's "hello, lzo world!" vector, the match one
//     exercises an overlapping back-reference at distance 3.
var (
	lzmaVector = []byte{
		0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x34, 0x19,
		0x49, 0xee, 0x8d, 0xef, 0x8c, 0x6a, 0x57, 0x93,
		0xf0, 0xc0, 0xda, 0xf6, 0x15, 0xb0, 0x9f, 0x5b,
		0x6f, 0x8a, 0x93, 0x3a, 0xff, 0xff, 0xb0, 0x04,
		0x00, 0x00,
	}
	xzVector = []byte{
		0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01,
		0x69, 0x22, 0xde, 0x36, 0x02, 0x00, 0x21, 0x01,
		0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3,
		0x01, 0x00, 0x0f, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
		0x2c, 0x20, 0x78, 0x7a, 0x20, 0x77, 0x6f, 0x72,
		0x6c, 0x64, 0x21, 0x00, 0xaf, 0xde, 0x3c, 0x05,
		0x00, 0x01, 0x24, 0x10, 0xe9, 0x44, 0xd9, 0xcc,
		0x90, 0x42, 0x99, 0x0d, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x59, 0x5a,
	}
	lz4LiteralVector = append(
		[]byte{0xf0, 0x02}, // token: 15 literals + a two-byte extension (17)
		[]byte("hello, lz4 world!")...,
	)
	lz4MatchVector = []byte{
		0x32, 'a', 'b', 'c', // token: 3 literals, match length 6
		0x03, 0x00, // match offset 3
		0x00, // final sequence with no literals
	}
	lzoLiteralVector = append(
		[]byte{34}, // first byte 17+17: 17 literals
		append([]byte("hello, lzo world!"), 0x11, 0x00, 0x00)...,
	)
	lzoMatchVector = []byte{
		0x17, 'a', 'b', 'c', 'a', 'b', 'c', // first byte 17+6: 6 literals
		0x48, 0x00, // M2 match: distance 3, length 3
		0x11, 0x00, 0x00, // end-of-stream marker
	}
)

type codecVector struct {
	name        string
	compression uint16
	stored      []byte
	want        []byte
}

func codecVectors(t *testing.T) []codecVector {
	t.Helper()
	return []codecVector{
		{"lzma", compressionLZMA, lzmaVector, []byte("hello, lzma world!")},
		{"lzo literal", compressionLZO, lzoLiteralVector, []byte("hello, lzo world!")},
		{"lzo match", compressionLZO, lzoMatchVector, []byte("abcabcabc")},
		{"xz", compressionXZ, xzVector, []byte("hello, xz world!")},
		{"lz4 literal", compressionLZ4, lz4LiteralVector, []byte("hello, lz4 world!")},
		{"lz4 match", compressionLZ4, lz4MatchVector, []byte("abcabcabc")},
	}
}

// TestDecompressBlockCodecs decodes one embedded block per new codec at the
// data-block bound and again at the exact decoded length.
func TestDecompressBlockCodecs(t *testing.T) {
	for _, vector := range codecVectors(t) {
		t.Run(vector.name, func(t *testing.T) {
			for _, limit := range []int{testBlockSize, len(vector.want)} {
				got, err := decompressBlock(vector.compression, vector.stored, limit)
				if err != nil {
					t.Fatalf("limit %d: %v", limit, err)
				}
				if !bytes.Equal(got, vector.want) {
					t.Fatalf("limit %d: got %q, want %q", limit, got, vector.want)
				}
			}
		})
	}
}

// TestReadMetadataBlockCodecs drives the same vectors through the metadata
// path, so a metadata block and a data block are both covered.
func TestReadMetadataBlockCodecs(t *testing.T) {
	for _, vector := range codecVectors(t) {
		t.Run(vector.name, func(t *testing.T) {
			image := make([]byte, 2+len(vector.stored))
			putU16(image, 0, uint16(len(vector.stored)))
			copy(image[2:], vector.stored)

			block, err := readMetadataBlock(source.NewMemorySource(1, image), vector.compression, 0)
			if err != nil {
				t.Fatalf("read metadata block: %v", err)
			}
			if !bytes.Equal(block.bytes, vector.want) {
				t.Fatalf("decoded %q, want %q", block.bytes, vector.want)
			}
			if block.next != uint64(len(image)) {
				t.Fatalf("next = %d, want %d", block.next, len(image))
			}
		})
	}
}

// TestCodecRefusesMalformedBlocks covers truncation, bad lengths, bad
// back-references, trailing bytes and undersized output bounds. Every case
// must fail explicitly and leave no partial output.
func TestCodecRefusesMalformedBlocks(t *testing.T) {
	mutate := func(vector []byte, edits ...func([]byte) []byte) []byte {
		out := append([]byte(nil), vector...)
		for _, edit := range edits {
			out = edit(out)
		}
		return out
	}
	flip := func(at int) func([]byte) []byte {
		return func(data []byte) []byte {
			data[at] ^= 0xff
			return data
		}
	}
	truncate := func(n int) func([]byte) []byte {
		return func(data []byte) []byte { return data[:len(data)-n] }
	}

	cases := []struct {
		name        string
		compression uint16
		stored      []byte
		limit       int
	}{
		{"lzma truncated", compressionLZMA, mutate(lzmaVector, truncate(3)), testBlockSize},
		{"lzma trailing byte", compressionLZMA, append(append([]byte(nil), lzmaVector...), 0), testBlockSize},
		{"lzma small bound", compressionLZMA, lzmaVector, 4},
		{"xz truncated", compressionXZ, mutate(xzVector, truncate(4)), testBlockSize},
		{"xz corrupted block", compressionXZ, mutate(xzVector, flip(32)), testBlockSize},
		{"xz small bound", compressionXZ, xzVector, 4},
		{"xz garbage", compressionXZ, []byte("not an xz stream at all, really"), testBlockSize},
		{"lzo truncated", compressionLZO, []byte{0x11, 0x00}, testBlockSize},
		{"lzo truncates a literal run", compressionLZO, []byte{0x17, 'a', 'b'}, testBlockSize},
		{"lzo trailing byte", compressionLZO, append(append([]byte(nil), lzoMatchVector...), 0), testBlockSize},
		{"lzo lookbehind", compressionLZO, []byte{18, 'a', 8, 0}, testBlockSize},
		{"lzo small bound", compressionLZO, lzoMatchVector, 8},
		{"lz4 empty", compressionLZ4, nil, testBlockSize},
		{"lz4 truncated literals", compressionLZ4, []byte{0xf0, 0x05, 'a'}, testBlockSize},
		{"lz4 zero offset", compressionLZ4, []byte{0x10, 'a', 0x00, 0x00}, testBlockSize},
		{"lz4 offset too far", compressionLZ4, []byte{0x10, 'a', 0x05, 0x00, 0x00}, testBlockSize},
		{"lz4 small bound", compressionLZ4, lz4LiteralVector, 15},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decompressBlock(c.compression, c.stored, c.limit)
			if err == nil {
				t.Fatalf("decoded %q, want an error", got)
			}
			if got != nil {
				t.Fatalf("returned %d partial bytes alongside %v", len(got), err)
			}
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("error %v is neither corrupt nor unsupported", err)
			}
		})
	}
}

// TestCodecRefusesTrailingXZData pins the container boundary: an XZ block is
// exactly one stream, so stored bytes after the footer are corruption.
func TestCodecRefusesTrailingXZData(t *testing.T) {
	// XZ stream padding is permitted by the container, so append a single
	// nonzero byte to make the trailing data unambiguously invalid.
	stored := append(append([]byte(nil), xzVector...), 0x01)
	if _, err := decompressBlock(compressionXZ, stored, testBlockSize); err == nil {
		t.Fatal("trailing xz data decoded without an error")
	}
}

// TestLZOVectorsEmbedded sanity-checks the hand-built LZO match block: the
// decoded output must be a repeat of the literal run, proving the
// back-reference path ran rather than a literal copy.
func TestLZOVectorsEmbedded(t *testing.T) {
	got, err := decodeLZO1X(lzoMatchVector, 64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, []byte("abcabcabc")) {
		t.Fatalf("decoded %q", got)
	}
}
