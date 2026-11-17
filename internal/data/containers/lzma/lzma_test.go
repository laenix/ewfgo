package lzma

// The fixtures below are embedded hex strings, so the tests need no external
// tool and no files on disk.
//
// Unknown-size fixtures (header size field 0xFFFFFFFFFFFFFFFF, end marker)
// were produced once during development with CPython 3.12's
// lzma.compress(data, format=lzma.FORMAT_ALONE), which uses liblzma.
//
// Known-size fixtures (header size field set, no end marker) were produced
// with lzma-rs 0.3.0 (lzma_compress_with_options and
// UnpackedSize::WriteToHeader(Some(len))); its dumb encoder emits literals
// only, which exercises the literal path. Every known-size fixture was also
// verified with CPython's lzma.decompress(..., format=lzma.FORMAT_ALONE).

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// unknownEmpty is lzma.compress(b"", format=FORMAT_ALONE).
	unknownEmpty = "5d00008000ffffffffffffffff0083fffbffffc0000000"
	// unknownText is lzma.compress(text, format=FORMAT_ALONE).
	unknownText = "5d00008000ffffffffffffffff002a1a08a2032566f14b78c5a205ff2ee6d9d2201aad34f8e21de84136fadc0669bb3ce410342709ebb366e3ed3742d7f7591ceddffffd07a000"
	// unknownBinary is lzma.compress(bytes(range(256)), format=FORMAT_ALONE).
	unknownBinary = "5d00008000ffffffffffffffff00000052500a84f99bb28021a969d627e03e065a5f048d53d404ba39570509c15524de9db871593160a19ff96f4973f2c8ea8cba1a8b29692180fe338366af466dec9e898a0b83f03c0e898e3fed5fe79e90d91cff32f4b2e03951b2d21415b4c571badb06e3799a9fbb38c1b000ac930baa0619031208155b9bc848f0322efe2da087c8f0a4e0d251eb8d675692b24d84c5f18631df6a625bc2792dd9f73c73ba747407d83ca9562224a166f85a845f3067d2f64b492e7f20ebdbf8100e947877c73f6befb4cd95e26ff6446e06cf0b821acbdb7af0578d98ff90c03ee6c1124175ee032896eb139b84caffff99600000"
	// unknownRepeat is lzma.compress(b"forensic "*200, format=FORMAT_ALONE).
	unknownRepeat = "5d00008000ffffffffffffffff00331bcaaae81a72fd1838b5e45de0c81efe2b176fde3c2b8103ffffe3bf8000"
	// unknownProps is lzma.compress(propsData(), format=FORMAT_ALONE,
	// filters=[{id: FILTER_LZMA1, preset: 6, lc: 0, lp: 2, pb: 0,
	// dict_size: 4096}]). Its property byte is 18.
	unknownProps = "1200100000ffffffffffffffff0026173a8e2fc9fc2dfec445e255bbcecbd509b62407b6eb04649760a19902fdabc689b3aa3a1b0e8304a737dc5d5f2d7c77e4bb41351072a7aa9be423b3c1d1bd871445593dc856d2af90f785e2e4e74bfaeeb7dd99a76063e7fad05a41fc1ff8cf2c3489c135a76a1aabe783cf6f7adfd431625d2bf57440da59d081bafeab37f10f93d9442bc0fefb0fb4b78e3aefddebe7ec17a02eb42f576d2465db0e03417b3dd2003a8dfffff9b7a000"

	// knownEmpty is lzma-rs's known-size encoding of b"".
	knownEmpty = "5d0000800000000000000000000000000000"
	// knownText is lzma-rs's known-size encoding of text.
	knownText = "5d000080004100000000000000002a1a08a2032566f14b78c5a205ff2ee6d9d2201aad34f8e21de84136fadc0669baa7fbdac4ef87e950a2a0462ed1c0904490e9283cb1b5b1600ee3473f865f22a9e0"
	// knownBinary is lzma-rs's known-size encoding of bytes(range(96)).
	knownBinary = "5d00008000600000000000000000000052500a84f99bb28021a969d627e03e065a5f048d53d404ba39570509c15524de9db871593160a19ff96f4973f2c8ea8cba1a8b29692180fe338366af466dec9e898a0b83f03c0e898e3fed5fe79e90d91cff32f4b2e03948c5cbd2"
	// knownRepeat is lzma-rs's known-size encoding of b"abc"*12.
	knownRepeat = "5d0000800024000000000000000030988897eaabdf05ff101341cfafa188529df2ff19582d1815307925b8659d"
)

func textBytes() []byte {
	return []byte("The quick brown fox jumps over the lazy dog. The quick brown fox.")
}

func binaryBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func repeatBytes() []byte {
	return []byte(strings.Repeat("forensic ", 200))
}

func propsData() []byte {
	seed := []byte("LZMA-alone properties fixture. ")
	out := append([]byte{}, bytes.Repeat(seed, 3)...)
	out = append(out, binaryBytes(64)...)
	out = append(out, bytes.Repeat(seed, 4)...)
	for i := 64; i < 128; i++ {
		out = append(out, byte(i))
	}
	return out
}

func knownRepeatBytes() []byte {
	return []byte(strings.Repeat("abc", 12))
}

func mustHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("fixture hex is invalid: %v", err)
	}
	return decoded
}

func TestDecodeFixtures(t *testing.T) {
	cases := []struct {
		name      string
		encoded   string
		want      []byte
		sizeKnown bool
		declared  uint64
		lc, lp    uint8
		pb        uint8
		dict      uint32
	}{
		{"unknown-empty", unknownEmpty, nil, false, unknownSize, 3, 0, 2, 0x00800000},
		{"unknown-text", unknownText, textBytes(), false, unknownSize, 3, 0, 2, 0x00800000},
		{"unknown-binary", unknownBinary, binaryBytes(256), false, unknownSize, 3, 0, 2, 0x00800000},
		{"unknown-repeat", unknownRepeat, repeatBytes(), false, unknownSize, 3, 0, 2, 0x00800000},
		{"unknown-props", unknownProps, propsData(), false, unknownSize, 0, 2, 0, 4096},
		{"known-empty", knownEmpty, nil, true, 0, 3, 0, 2, 0x00800000},
		{"known-text", knownText, textBytes(), true, 65, 3, 0, 2, 0x00800000},
		{"known-binary", knownBinary, binaryBytes(96), true, 96, 3, 0, 2, 0x00800000},
		{"known-repeat", knownRepeat, knownRepeatBytes(), true, 36, 3, 0, 2, 0x00800000},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			stored := mustHex(t, test.encoded)
			decoded, meta, err := decode(stored, Limits{})
			if err != nil {
				t.Fatalf("decode error = %v", err)
			}
			if !bytes.Equal(decoded, test.want) {
				t.Fatalf("decoded %d bytes, want %d", len(decoded), len(test.want))
			}
			if meta.CompressedLen != uint64(len(stored)) {
				t.Fatalf("CompressedLen = %d, want %d", meta.CompressedLen, len(stored))
			}
			if meta.DecompressedLen != uint64(len(test.want)) {
				t.Fatalf("DecompressedLen = %d, want %d", meta.DecompressedLen, len(test.want))
			}
			if meta.DictionarySize != test.dict {
				t.Fatalf("DictionarySize = %#x, want %#x", meta.DictionarySize, test.dict)
			}
			if meta.LC != test.lc || meta.LP != test.lp || meta.PB != test.pb {
				t.Fatalf("properties = lc %d lp %d pb %d, want %d/%d/%d",
					meta.LC, meta.LP, meta.PB, test.lc, test.lp, test.pb)
			}
			if meta.SizeKnown != test.sizeKnown {
				t.Fatalf("SizeKnown = %v, want %v", meta.SizeKnown, test.sizeKnown)
			}
			if meta.DeclaredSize != test.declared {
				t.Fatalf("DeclaredSize = %#x, want %#x", meta.DeclaredSize, test.declared)
			}
			if meta.EndMarker == test.sizeKnown {
				t.Fatalf("EndMarker = %v for sizeKnown = %v", meta.EndMarker, test.sizeKnown)
			}
		})
	}
}

func TestDecodeMatchesSignature(t *testing.T) {
	for _, test := range []struct {
		name string
		head []byte
		want bool
	}{
		{"unknown-text", mustHex(t, unknownText), true},
		{"known-text", mustHex(t, knownText), true},
		{"empty", nil, false},
		{"short", mustHex(t, unknownText)[:12], false},
		{"zero-dictionary", append([]byte{0x5D, 0, 0, 0, 0}, make([]byte, 8)...), false},
		{"invalid-property-ff", append([]byte{0xFF, 0, 0, 0x80, 0}, make([]byte, 8)...), false},
		{"invalid-property-lc-plus-lp", append([]byte{5, 0, 0, 0x80, 0}, make([]byte, 8)...), false},
		{"max-valid-property", append([]byte{184, 0, 0, 0x80, 0}, make([]byte, 8)...), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := MatchesSignature(test.head); got != test.want {
				t.Fatalf("MatchesSignature = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDecodeTruncated(t *testing.T) {
	text := mustHex(t, unknownText)
	binaryFixture := mustHex(t, unknownBinary)
	known := mustHex(t, knownText)
	knownEmptyFixture := mustHex(t, knownEmpty)

	cases := []struct {
		name string
		data []byte
	}{
		{"empty-input", nil},
		{"header-1", text[:1]},
		{"header-12", text[:12]},
		{"payload-shorter-than-range-init", text[:headerSize+4]},
		{"unknown-body-cut", text[:len(text)-1]},
		{"unknown-body-cut-mid", binaryFixture[:len(binaryFixture)/2]},
		{"unknown-end-marker-flush-cut", text[:len(text)-5]},
		{"unknown-end-marker-cut", text[:len(text)-6]},
		{"unknown-empty-flush-cut", mustHex(t, unknownEmpty)[:len(mustHex(t, unknownEmpty))-1]},
		{"known-empty-flush-cut", knownEmptyFixture[:len(knownEmptyFixture)-1]},
		{"known-text-flush-cut", known[:len(known)-1]},
		{"known-text-body-cut", known[:len(known)-8]},
		{"known-trailing-byte", append(append([]byte{}, known...), 0x00)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			out, err := Decode(test.data, Limits{})
			if !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("error = %v, want ErrCorrupt", err)
			}
			if out != nil {
				t.Fatalf("decoded %d bytes alongside the error", len(out))
			}
		})
	}
}

func TestDecodeInvalidHeader(t *testing.T) {
	payload := mustHex(t, unknownEmpty)[headerSize:]
	cases := []struct {
		name string
		prop byte
		dict uint32
	}{
		{"property-ff", 0xFF, 0x00800000},
		{"property-225", 225, 0x00800000},
		{"property-lc-plus-lp", 5, 0x00800000},
		{"zero-dictionary", 0x5D, 0},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			header := make([]byte, headerSize)
			header[0] = test.prop
			binary.LittleEndian.PutUint32(header[1:5], test.dict)
			binary.LittleEndian.PutUint64(header[5:], unknownSize)
			out, err := Decode(append(header, payload...), Limits{})
			if !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("error = %v, want ErrCorrupt", err)
			}
			if out != nil {
				t.Fatalf("decoded %d bytes alongside the error", len(out))
			}
		})
	}
}

func TestDecodeKnownSizeDisagreement(t *testing.T) {
	base := mustHex(t, knownText)
	for _, size := range []uint64{0, 1, 64, 66, 1000} {
		t.Run("declared-"+hex.EncodeToString([]byte{
			byte(size), byte(size >> 8), byte(size >> 16), byte(size >> 24),
			byte(size >> 32), byte(size >> 40), byte(size >> 48), byte(size >> 56),
		}), func(t *testing.T) {
			stored := append([]byte{}, base...)
			binary.LittleEndian.PutUint64(stored[5:13], size)
			out, err := Decode(stored, Limits{})
			if !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("declared size %d: error = %v, want ErrCorrupt", size, err)
			}
			if out != nil {
				t.Fatalf("declared size %d: decoded %d bytes alongside the error", size, len(out))
			}
		})
	}
}

func TestDecodeOutputLimits(t *testing.T) {
	text := mustHex(t, unknownText)
	known := mustHex(t, knownText)
	repeat := mustHex(t, unknownRepeat)

	t.Run("known-declared-over-limit", func(t *testing.T) {
		out, err := Decode(known, Limits{MaxDecodedBytes: 64})
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("error = %v, want ErrUnsupported", err)
		}
		if out != nil {
			t.Fatalf("decoded %d bytes alongside the error", len(out))
		}
	})

	t.Run("known-declared-at-limit", func(t *testing.T) {
		out, err := Decode(known, Limits{MaxDecodedBytes: 65})
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if !bytes.Equal(out, textBytes()) {
			t.Fatal("decoded bytes differ")
		}
	})

	t.Run("unknown-over-limit", func(t *testing.T) {
		out, err := Decode(text, Limits{MaxDecodedBytes: 64})
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("error = %v, want ErrUnsupported", err)
		}
		if out != nil {
			t.Fatalf("decoded %d bytes alongside the error", len(out))
		}
	})

	t.Run("unknown-repeat-over-limit", func(t *testing.T) {
		out, err := Decode(repeat, Limits{MaxDecodedBytes: 1799})
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("error = %v, want ErrUnsupported", err)
		}
		if out != nil {
			t.Fatalf("decoded %d bytes alongside the error", len(out))
		}
	})

	t.Run("compressed-over-limit", func(t *testing.T) {
		out, err := Decode(text, Limits{MaxCompressedBytes: uint64(len(text) - 1)})
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("error = %v, want ErrUnsupported", err)
		}
		if out != nil {
			t.Fatalf("decoded %d bytes alongside the error", len(out))
		}
	})
}

func TestDecodeEveryTruncation(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		encoded string
	}{
		{"unknown-text", unknownText},
		{"known-text", knownText},
		{"unknown-binary", unknownBinary},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			stored := mustHex(t, fixture.encoded)
			for cut := 0; cut < len(stored); cut++ {
				out, err := Decode(stored[:cut], Limits{})
				if err == nil {
					t.Fatalf("truncation at %d decoded %d bytes without an error", cut, len(out))
				}
				if out != nil {
					t.Fatalf("truncation at %d returned %d bytes alongside the error", cut, len(out))
				}
			}
			// The untruncated fixture still decodes.
			if _, err := Decode(stored, Limits{}); err != nil {
				t.Fatalf("full fixture error = %v", err)
			}
		})
	}
}

func TestDecodeHugeDeclaredSizeIsRefused(t *testing.T) {
	stored := mustHex(t, knownText)
	binary.LittleEndian.PutUint64(stored[5:13], 1<<60)
	out, err := Decode(stored, Limits{})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if out != nil {
		t.Fatalf("decoded %d bytes alongside the error", len(out))
	}
}

func TestOpenSource(t *testing.T) {
	stored := mustHex(t, unknownBinary)
	src := source.NewMemorySource(7, stored)
	opened, err := Open(9, src, Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	want := binaryBytes(256)
	if !bytes.Equal(opened.Bytes(), want) {
		t.Fatalf("decoded %d bytes, want %d", len(opened.Bytes()), len(want))
	}
	if opened.Len() != uint64(len(want)) {
		t.Fatalf("Len = %d", opened.Len())
	}
	if opened.CompressedLen() != uint64(len(stored)) {
		t.Fatalf("CompressedLen = %d", opened.CompressedLen())
	}
	if opened.SourceID() != 9 || opened.ImageID() != src.ImageID() {
		t.Fatal("source identity was not preserved")
	}
	if opened.SectorSize() != src.SectorSize() {
		t.Fatal("sector size was not inherited")
	}
	if opened.IsEmpty() {
		t.Fatal("IsEmpty = true")
	}

	buf := make([]byte, 32)
	n, err := opened.ReadAt(10, buf)
	if err != nil || n != len(buf) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if !bytes.Equal(buf, want[10:42]) {
		t.Fatalf("ReadAt returned %x", buf)
	}
	if _, err := opened.ReadAt(opened.Len(), buf); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt past end error = %v", err)
	}

	extents, err := opened.Extents(5, 10)
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	if len(extents) != 1 || extents[0].Parent != src.SourceID() ||
		extents[0].ParentOffset != 0 || extents[0].Len != uint64(len(stored)) {
		t.Fatalf("Extents = %+v", extents)
	}
	if _, err := opened.Extents(opened.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("Extents past end error = %v", err)
	}
	if _, err := opened.MapToImage(0, 1); err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}
	if got := opened.Stats().DecompressedBytes; got != uint64(len(want)) {
		t.Fatalf("DecompressedBytes = %d", got)
	}
	if opened.Meta().EndMarker != true || opened.Meta().SizeKnown != false {
		t.Fatalf("Meta = %+v", opened.Meta())
	}

	t.Run("short-source", func(t *testing.T) {
		short := source.NewMemorySource(1, make([]byte, headerSize-1))
		if _, err := Open(2, short, Limits{}); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("compressed-limit", func(t *testing.T) {
		if _, err := Open(2, src, Limits{MaxCompressedBytes: uint64(len(stored) - 1)}); !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("error = %v, want ErrUnsupported", err)
		}
	})
}

func TestDecodeDoesNotAliasInput(t *testing.T) {
	stored := mustHex(t, knownText)
	before := append([]byte{}, stored...)
	decoded, err := Decode(stored, Limits{})
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if !bytes.Equal(stored, before) {
		t.Fatal("Decode modified its input")
	}
	// The output must not share storage with the input.
	if len(decoded) > 0 && &decoded[0] == &stored[0] {
		t.Fatal("decoded output aliases the input")
	}
}

func TestDefaultLimits(t *testing.T) {
	limits := DefaultLimits()
	if limits.MaxDecodedBytes != MaxDecodedBytes || limits.MaxCompressedBytes != MaxCompressedBytes {
		t.Fatalf("DefaultLimits = %+v", limits)
	}
}
