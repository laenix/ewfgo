package rotated

import (
	"bytes"
	stdgzip "compress/gzip"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/gzip"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	lz4FrameStoredHex = "04224d1868403700000000000000bb37000080737368645b315d3a2041636365707465642070617373776f726420666f7220616c6963652066726f6d203139382e35312e3130302e370a00000000"
	lz4Text           = "sshd[1]: Accepted password for alice from 198.51.100.7\n"
	bzip2HelloHex     = "425a6839314159265359555a44f70000021980400010001264c0102000220069ea100305d3b62183c5dc914e14241556913dc0"
	bzip2Hello        = "hello bzip2"
	xzTextHex         = "fd377a585a0000016922de360200210116000000742fe5a3e000c3006c5d0026984a420bb4ebd87ff30eabfebdfc7d3582b4165f1846d1d9e62227d7b817333cae3167f26657aebcc3cacff80686f850f2b477e52f8f3bde04560cf4bc4dbe242a4d31c394866ea1c122574a580de2eeb71935c1fd34c7697d8ad51c07e6d8db3d92e6be0fb53c447bc8a00074cc31b700018401c4010000c5b8f9833e300d8b020000000001595a"
	xzText            = "Mar  1 10:00:00 host sshd[1]: Accepted password for alice from 198.51.100.7\n" +
		"Mar  1 10:00:01 host sshd[1]: session opened for user alice\n" +
		"Mar  1 10:00:02 host sshd[1]: session closed for user alice\n"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}
	return b
}

func gzipBytes(t *testing.T, data []byte, name string, mtime time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := stdgzip.NewWriter(&buf)
	w.Name = name
	w.ModTime = mtime
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func memorySource(data []byte) source.ByteSource {
	return source.NewMemorySourceWithImage(1, 9, data)
}

func TestCompressionLabels(t *testing.T) {
	cases := map[Compression]string{
		Gzip: "gzip", Bzip2: "bzip2", Lz4: "lz4", Xz: "xz", Zstd: "zstd",
	}
	for c, want := range cases {
		if got := c.Label(); got != want {
			t.Errorf("%d.Label() = %q, want %q", c, got, want)
		}
		if got := c.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", c, got, want)
		}
	}
	if got := Compression(99).Label(); got != "unknown" {
		t.Fatalf("unknown label = %q", got)
	}
}

func TestDetectAllCodecs(t *testing.T) {
	// XZ and Zstandard streams are only recognised here; decoding them is
	// refused. The magic bytes are enough for detection.
	cases := []struct {
		name string
		head []byte
		want Compression
	}{
		{"gzip", gzipBytes(t, []byte("x"), "", time.Time{}), Gzip},
		{"bzip2", mustHex(t, bzip2HelloHex), Bzip2},
		{"lz4", mustHex(t, lz4FrameStoredHex), Lz4},
		{"xz", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x00}, Xz},
		{"zstd", []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x00, 0x00}, Zstd},
	}
	for _, tc := range cases {
		got, ok := Detect(tc.head)
		if !ok || got != tc.want {
			t.Errorf("Detect(%s) = %v, %v; want %v, true", tc.name, got, ok, tc.want)
		}
		if !MatchesSignature(tc.head) {
			t.Errorf("MatchesSignature(%s) = false", tc.name)
		}
	}

	if _, ok := Detect([]byte("plain text")); ok {
		t.Error("Detect(plain text) claimed a codec")
	}
	if _, ok := Detect(nil); ok {
		t.Error("Detect(nil) claimed a codec")
	}
	if MatchesSignature([]byte{0x1F}) {
		t.Error("MatchesSignature(one-byte gzip prefix) = true")
	}
}

func TestEverySupportedCodecDecodesThroughTheFacade(t *testing.T) {
	cases := []struct {
		name   string
		stored []byte
		want   []byte
		codec  Compression
	}{
		{"gzip", gzipBytes(t, []byte("rotated gzip\n"), "auth.log.2.gz", time.Unix(1700000000, 0).UTC()), []byte("rotated gzip\n"), Gzip},
		{"bzip2", mustHex(t, bzip2HelloHex), []byte(bzip2Hello), Bzip2},
		{"lz4", mustHex(t, lz4FrameStoredHex), []byte(lz4Text), Lz4},
		{"xz", mustHex(t, xzTextHex), []byte(xzText), Xz},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, err := Decode(2, memorySource(tc.stored), DefaultLimits())
			if err != nil {
				t.Fatalf("Decode error = %v", err)
			}
			if src.Compression() != tc.codec {
				t.Fatalf("Compression = %v, want %v", src.Compression(), tc.codec)
			}
			if src.Compression().Label() != tc.name {
				t.Fatalf("label = %q", src.Compression().Label())
			}
			if src.CompressedLen() != uint64(len(tc.stored)) {
				t.Fatalf("CompressedLen = %d, want %d", src.CompressedLen(), len(tc.stored))
			}
			if src.Len() != uint64(len(tc.want)) {
				t.Fatalf("Len = %d, want %d", src.Len(), len(tc.want))
			}
			buf := make([]byte, src.Len())
			if n, err := src.ReadAt(0, buf); err != nil || n != len(buf) {
				t.Fatalf("ReadAt = %d, %v", n, err)
			}
			if !bytes.Equal(buf, tc.want) || !bytes.Equal(src.Bytes(), tc.want) {
				t.Fatalf("decoded = %q, want %q", buf, tc.want)
			}
		})
	}
}

func TestUnsupportedCodecsAreRefusedByName(t *testing.T) {
	cases := []struct {
		name   string
		stored []byte
		codec  Compression
		label  string
	}{
		{"zstd", []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x00, 0x00}, Zstd, "zstd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codec, ok := Detect(tc.stored)
			if !ok || codec != tc.codec {
				t.Fatalf("Detect = %v, %v", codec, ok)
			}
			src, err := Decode(2, memorySource(tc.stored), DefaultLimits())
			if !errors.Is(err, source.ErrUnsupported) {
				t.Fatalf("Decode error = %v, want ErrUnsupported", err)
			}
			if src != nil {
				t.Fatal("Decode returned a source together with an error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.label) {
				t.Fatalf("error = %q, want it to name %q", err, tc.label)
			}
			// The bytes must never be handed back as raw data.
			if errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("error = %v, unsupported codecs must not be reported as corruption", err)
			}
		})
	}
}

func TestUnclaimedBytesAreRefusedByName(t *testing.T) {
	src, err := Decode(2, memorySource([]byte("plain log line\n")), DefaultLimits())
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Decode error = %v, want ErrUnsupported", err)
	}
	if src != nil {
		t.Fatal("Decode returned a source for unclaimed bytes")
	}
	if !strings.Contains(err.Error(), "no gzip, bzip2, lz4, xz, or zstd signature") {
		t.Fatalf("error = %q, want the recognition diagnostic", err)
	}
}

func TestRenamedMemberKeepsItsCodec(t *testing.T) {
	// The dispatch is magic-based; names are never consulted. LZ4 bytes in a
	// member someone called ".gz" still decode as LZ4.
	src, err := Decode(2, memorySource(mustHex(t, lz4FrameStoredHex)), DefaultLimits())
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if src.Compression() != Lz4 {
		t.Fatalf("Compression = %v, want Lz4", src.Compression())
	}
	if string(src.Bytes()) != lz4Text {
		t.Fatalf("bytes = %q", src.Bytes())
	}
}

func TestOnlyGzipReportsProducerMetadata(t *testing.T) {
	mtime := time.Unix(1700000000, 0).UTC()

	gz := gzipBytes(t, []byte("x"), "auth.log.2.gz", mtime)
	src, err := Decode(2, memorySource(gz), DefaultLimits())
	if err != nil {
		t.Fatalf("Decode(gzip) error = %v", err)
	}
	if name, ok := src.OriginalName(); !ok || name != "auth.log.2.gz" {
		t.Fatalf("OriginalName = %q, %v", name, ok)
	}
	if stamp, ok := src.MTime(); !ok || stamp != 1700000000 {
		t.Fatalf("MTime = %d, %v", stamp, ok)
	}

	// A gzip member without a name still has a producer time (zero).
	src, err = Decode(2, memorySource(gzipBytes(t, []byte("x"), "", time.Time{})), DefaultLimits())
	if err != nil {
		t.Fatalf("Decode(gzip unnamed) error = %v", err)
	}
	if name, ok := src.OriginalName(); ok || name != "" {
		t.Fatalf("OriginalName = %q, %v; want absent", name, ok)
	}
	if stamp, ok := src.MTime(); !ok || stamp != 0 {
		t.Fatalf("MTime = %d, %v; want 0, true", stamp, ok)
	}

	for _, tc := range []struct {
		name   string
		stored []byte
	}{
		{"bzip2", mustHex(t, bzip2HelloHex)},
		{"lz4", mustHex(t, lz4FrameStoredHex)},
	} {
		src, err := Decode(2, memorySource(tc.stored), DefaultLimits())
		if err != nil {
			t.Fatalf("Decode(%s) error = %v", tc.name, err)
		}
		if name, ok := src.OriginalName(); ok || name != "" {
			t.Errorf("%s OriginalName = %q, %v; want absent", tc.name, name, ok)
		}
		if stamp, ok := src.MTime(); ok || stamp != 0 {
			t.Errorf("%s MTime = %d, %v; want absent", tc.name, stamp, ok)
		}
	}
}

func TestFacadeDelegatesByteSourceMethods(t *testing.T) {
	payload := []byte("facade payload\n")
	src, err := Decode(2, memorySource(gzipBytes(t, payload, "", time.Time{})), DefaultLimits())
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if src.SourceID() != 2 || src.ImageID() != 9 || src.SectorSize() != 512 || src.IsEmpty() {
		t.Fatalf("identity = id %d image %d sector %d empty %v",
			src.SourceID(), src.ImageID(), src.SectorSize(), src.IsEmpty())
	}
	if _, err := src.ReadAt(src.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt past end error = %v", err)
	}
	if n, err := src.ReadAtLossy(0, make([]byte, 3)); n != 3 || err != nil {
		t.Fatalf("ReadAtLossy = %d, %v", n, err)
	}
	if extents, err := src.Extents(0, src.Len()); err != nil || len(extents) == 0 {
		t.Fatalf("Extents = %+v, %v", extents, err)
	}
	extents, err := src.ExtentsInto(0, src.Len(), []source.ParentRange{{Parent: 42}})
	if err != nil || len(extents) != 2 || extents[0].Parent != 42 {
		t.Fatalf("ExtentsInto = %+v, %v", extents, err)
	}
	if images, err := src.MapToImage(0, src.Len()); err != nil || len(images) == 0 {
		t.Fatalf("MapToImage = %+v, %v", images, err)
	}
	if src.Label() != "gzip" {
		t.Fatalf("Label = %q, want gzip", src.Label())
	}
	if src.Stats().BytesRead == 0 {
		t.Fatal("Stats did not record the reads")
	}
}

func TestOpenHonoursCodecLimits(t *testing.T) {
	limits := DefaultLimits()
	limits.Gzip = gzip.Limits{MaxDecodedBytes: 2}
	_, err := Decode(2, memorySource(gzipBytes(t, []byte("hello"), "", time.Time{})), limits)
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Decode error = %v, want ErrUnsupported", err)
	}
}

func TestOpenUnknownCompression(t *testing.T) {
	_, err := Open(2, memorySource([]byte("x")), Compression(42), DefaultLimits())
	if !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("Open error = %v, want ErrInvalidArgument", err)
	}
}

func TestDecodeEmptySource(t *testing.T) {
	_, err := Decode(2, memorySource(nil), DefaultLimits())
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Decode error = %v, want ErrUnsupported", err)
	}
}
