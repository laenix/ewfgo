package lzfse

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad test fixture hex: " + err.Error())
	}
	return b
}

// genQuick reproduces the reference encoder's "quick" input.
func genQuick() []byte {
	return bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 30)
}

// genMixed reproduces the reference encoder's "mixed" input.
func genMixed() []byte {
	var out []byte
	for i := 0; i < 800; i++ {
		out = append(out, fmt.Sprintf("record %03d: status=ok value=%d\n", i%17, i*7%1000)...)
	}
	return out
}

// genMixed2 reproduces the reference encoder's second v2 block input.
func genMixed2() []byte {
	var out []byte
	for i := 0; i < 500; i++ {
		out = append(out, fmt.Sprintf("second table %03d: key=%x note=repeated note=repeated\n",
			i, uint64(i)*2654435761%65536)...)
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func TestDecodeReferenceVectors(t *testing.T) {
	for _, vector := range testVectors {
		t.Run(vector.name, func(t *testing.T) {
			got, err := Decode(vector.stream, Limits{})
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !bytes.Equal(got, vector.want) {
				t.Fatalf("decoded %d bytes, want %d (first mismatch at %d)",
					len(got), len(vector.want), firstDifference(got, vector.want))
			}

			fromReader, err := DecodeSource(bytes.NewReader(vector.stream), Limits{})
			if err != nil {
				t.Fatalf("DecodeSource: %v", err)
			}
			if !bytes.Equal(fromReader, vector.want) {
				t.Fatalf("DecodeSource decoded %d bytes, want %d", len(fromReader), len(vector.want))
			}
			if !MatchesSignature(vector.stream) {
				t.Fatalf("MatchesSignature = false for a valid stream")
			}
		})
	}
}

func firstDifference(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func TestDecodeEmptyStream(t *testing.T) {
	got, err := Decode([]byte("bvx$"), Limits{})
	if err != nil {
		t.Fatalf("Decode(bvx$): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Decode(bvx$) = %d bytes, want none", len(got))
	}
}

func TestDecodeReturnsNoPartialOutput(t *testing.T) {
	for _, vector := range testVectors {
		cuts := []int{0, 1, 2, 3, 4, 5, 7, 8, 11, 12, 13, 31, 32, 33, len(vector.stream) / 2, len(vector.stream) - 9, len(vector.stream) - 5, len(vector.stream) - 1}
		for _, cut := range cuts {
			if cut < 0 || cut >= len(vector.stream) {
				continue
			}
			got, err := Decode(vector.stream[:cut], Limits{})
			if err == nil {
				t.Fatalf("%s[:%d]: decoded %d bytes with no error", vector.name, cut, len(got))
			}
			if got != nil {
				t.Fatalf("%s[:%d]: returned %d partial bytes with error %v", vector.name, cut, len(got), err)
			}
			if !errors.Is(err, ErrUnexpectedEOF) && !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s[:%d]: error %v is not a decode sentinel", vector.name, cut, err)
			}
		}
	}
}

func TestTrailingGarbageRejected(t *testing.T) {
	for _, vector := range testVectors {
		for _, suffix := range [][]byte{[]byte("x"), []byte("bvx$"), vector.stream} {
			input := append(append([]byte(nil), vector.stream...), suffix...)
			got, err := Decode(input, Limits{})
			if err == nil {
				t.Fatalf("%s + %q: decoded with no error", vector.name, suffix)
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s + %q: error %v is not ErrCorrupt", vector.name, suffix, err)
			}
			if got != nil {
				t.Fatalf("%s + %q: returned partial output", vector.name, suffix)
			}
		}
	}
}

func TestBadAndUnsupportedMagic(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		kind  error
	}{
		{"empty", nil, ErrUnexpectedEOF},
		{"short", []byte("bvx"), ErrUnexpectedEOF},
		{"not lzfse", []byte("abcd"), ErrCorrupt},
		{"unknown bvx family", []byte("bvx?"), ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.input, Limits{})
			if got != nil {
				t.Fatalf("returned %d bytes on error", len(got))
			}
			if !errors.Is(err, tc.kind) {
				t.Fatalf("error = %v, want kind %v", err, tc.kind)
			}
			var structured *Error
			if !errors.As(err, &structured) {
				t.Fatalf("error %v is not *Error", err)
			}
			if structured.Kind != tc.kind {
				t.Fatalf("structured kind = %v, want %v", structured.Kind, tc.kind)
			}
		})
	}
}

func TestOutputLimits(t *testing.T) {
	for _, vector := range testVectors {
		if len(vector.want) == 0 {
			continue
		}
		t.Run(vector.name, func(t *testing.T) {
			// One byte short must be refused, and the failure must carry no data.
			got, err := Decode(vector.stream, Limits{MaxOutputBytes: uint64(len(vector.want) - 1)})
			if !errors.Is(err, ErrLimit) {
				t.Fatalf("limit-1: error = %v, want ErrLimit", err)
			}
			if got != nil {
				t.Fatalf("limit-1: returned %d partial bytes", len(got))
			}
			// Exactly enough must succeed.
			got, err = Decode(vector.stream, Limits{MaxOutputBytes: uint64(len(vector.want))})
			if err != nil {
				t.Fatalf("exact limit: %v", err)
			}
			if !bytes.Equal(got, vector.want) {
				t.Fatalf("exact limit: wrong output")
			}
			// Zero selects the default and must accept the stream.
			if _, err := Decode(vector.stream, Limits{}); err != nil {
				t.Fatalf("default limit: %v", err)
			}
		})
	}
}

func TestMatchesSignature(t *testing.T) {
	for _, magic := range []string{"bvx$", "bvx-", "bvxn", "bvx1", "bvx2"} {
		if !MatchesSignature([]byte(magic)) {
			t.Fatalf("MatchesSignature(%q) = false", magic)
		}
	}
	for _, input := range []string{"", "bvx", "bvx?", "abcd", "LZFS"} {
		if MatchesSignature([]byte(input)) {
			t.Fatalf("MatchesSignature(%q) = true", input)
		}
	}
}

func TestDecodeSourceErrors(t *testing.T) {
	if _, err := DecodeSource(nil, Limits{}); err == nil {
		t.Fatal("nil source accepted")
	}
	if _, err := DecodeSource(failingReader{}, Limits{}); err == nil {
		t.Fatal("read error swallowed")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestCorruptCompressedHeaders(t *testing.T) {
	// Use a single v2 block stream as the mutation base.
	var base []byte
	for _, vector := range testVectors {
		if vector.name == "mixed" {
			base = vector.stream
		}
	}
	if base == nil {
		t.Fatal("missing v2 fixture")
	}

	readU64 := func(b []byte, at int) uint64 {
		return uint64(readU32(b, at)) | uint64(readU32(b, at+4))<<32
	}

	cases := []struct {
		name   string
		mutate func([]byte) []byte
		kind   error
	}{
		{
			name: "literal count not a multiple of four",
			mutate: func(b []byte) []byte {
				p1 := readU64(b, 8)&^0xFFFFF | 2
				putU64(b, 8, p1)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "header size too small",
			mutate: func(b []byte) []byte {
				putU32(b, 24, v2HeaderSize-1)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "header size too large",
			mutate: func(b []byte) []byte {
				putU32(b, 24, v2HeaderSize+v2MaxWeightBytes+1)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "literal payload bound exceeded",
			mutate: func(b []byte) []byte {
				p1 := readU64(b, 8)
				p1 = p1&^(uint64(0xFFFFF)<<20) | uint64(2000)<<20
				putU64(b, 8, p1)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "LMD state outside table",
			mutate: func(b []byte) []byte {
				p3 := readU64(b, 24)
				p3 = p3&^(uint64(0x3FF)<<32) | uint64(200)<<32
				putU64(b, 24, p3)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "empty weight payload",
			mutate: func(b []byte) []byte {
				putU32(b, 24, v2HeaderSize)
				return b
			},
			kind: ErrUnexpectedEOF,
		},
		{
			name: "too many LMDs",
			mutate: func(b []byte) []byte {
				p1 := readU64(b, 8)
				p1 = p1&^(uint64(0xFFFFF)<<40) | uint64(lmdsPerBlock+1)<<40
				putU64(b, 8, p1)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "too many literals",
			mutate: func(b []byte) []byte {
				p1 := readU64(b, 8)
				p1 = p1&^0xFFFFF | uint64(literalsPerBlock+4)
				putU64(b, 8, p1)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "LMD payload shorter than its pad",
			mutate: func(b []byte) []byte {
				p2 := readU64(b, 16)
				p2 = p2&^(uint64(0xFFFFF)<<40) | uint64(7)<<40
				putU64(b, 16, p2)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "LMD payload above its bound",
			mutate: func(b []byte) []byte {
				p2 := readU64(b, 16)
				p2 = p2&^(uint64(0xFFFFF)<<40) | uint64(20000)<<40
				putU64(b, 16, p2)
				return b
			},
			kind: ErrCorrupt,
		},
		{
			name: "raw size above what the symbols can produce",
			mutate: func(b []byte) []byte {
				putU32(b, 4, 30_000_000)
				return b
			},
			kind: ErrCorrupt,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.mutate(append([]byte(nil), base...))
			got, err := Decode(input, Limits{})
			if !errors.Is(err, tc.kind) {
				t.Fatalf("error = %v, want kind %v", err, tc.kind)
			}
			if got != nil {
				t.Fatalf("returned %d bytes on error", len(got))
			}
		})
	}
}

func TestCorruptV1Header(t *testing.T) {
	var base []byte
	for _, vector := range testVectors {
		if vector.name == "v1" {
			base = vector.stream
		}
	}
	if base == nil {
		t.Fatal("missing v1 fixture")
	}
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "bit padding above seven",
			mutate: func(b []byte) []byte {
				putU32(b, 28, 0xFFFFFFF8) // wrapping_neg of a literal padding of eight
				return b
			},
		},
		{
			name: "declared payload smaller than its streams",
			mutate: func(b []byte) []byte {
				putU32(b, 8, 1)
				return b
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.mutate(append([]byte(nil), base...)), Limits{})
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v, want ErrCorrupt", err)
			}
			if got != nil {
				t.Fatalf("returned %d partial bytes", len(got))
			}
		})
	}
}

func putU32(b []byte, at int, v uint32) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
	b[at+2] = byte(v >> 16)
	b[at+3] = byte(v >> 24)
}

func putU64(b []byte, at int, v uint64) {
	putU32(b, at, uint32(v))
	putU32(b, at+4, uint32(v>>32))
}

// vnStream builds a bvxn block followed by the end marker.
func vnStream(rawLen uint32, payload []byte) []byte {
	out := []byte("bvxn")
	out = append(out, byte(rawLen), byte(rawLen>>8), byte(rawLen>>16), byte(rawLen>>24))
	n := uint32(len(payload))
	out = append(out, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	out = append(out, payload...)
	return append(out, "bvx$"...)
}

func lzvnEOS() []byte { return []byte{0x06, 0, 0, 0, 0, 0, 0, 0} }

func TestLZVNBlockEdgeCases(t *testing.T) {
	validPayload := append([]byte{0xE1, 'a'}, lzvnEOS()...)

	cases := []struct {
		name   string
		stream []byte
		kind   error
	}{
		{
			name:   "valid literal block",
			stream: vnStream(1, validPayload),
		},
		{
			name: "malformed end marker",
			stream: vnStream(1, append([]byte{0xE1, 'a'},
				0x06, 1, 0, 0, 0, 0, 0, 0)),
			kind: ErrCorrupt,
		},
		{
			name:   "trailing bytes after end marker",
			stream: vnStream(1, append(append([]byte{0xE1, 'a'}, lzvnEOS()...), 0x00)),
			kind:   ErrCorrupt,
		},
		{
			name:   "undefined opcode",
			stream: vnStream(0, append([]byte{0x70}, lzvnEOS()...)),
			kind:   ErrCorrupt,
		},
		{
			name:   "match without a previous distance",
			stream: vnStream(3, append([]byte{0x00, 0x05}, lzvnEOS()...)),
			kind:   ErrCorrupt,
		},
		{
			name:   "raw size disagrees with the payload",
			stream: vnStream(2, append([]byte{0xE1, 'a'}, lzvnEOS()...)),
			kind:   ErrCorrupt,
		},
		{
			name:   "payload without end marker",
			stream: vnStream(1, []byte{0xE1, 'a'}),
			kind:   ErrCorrupt,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.stream, Limits{})
			if tc.kind == nil {
				if err != nil {
					t.Fatalf("Decode: %v", err)
				}
				if string(got) != "a" {
					t.Fatalf("decoded %q, want %q", got, "a")
				}
				return
			}
			if !errors.Is(err, tc.kind) {
				t.Fatalf("error = %v, want kind %v", err, tc.kind)
			}
			if got != nil {
				t.Fatalf("returned %d bytes on error", len(got))
			}
		})
	}
}

func TestLZVNOverlap(t *testing.T) {
	// sml_d with two literals "ab" and a four-byte match at distance two:
	// "ab" + "abab" = "ababab".
	payload := []byte{0x88, 0x02, 'a', 'b'}
	payload = append(payload, lzvnEOS()...)
	got, err := Decode(vnStream(6, payload), Limits{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(got) != "ababab" {
		t.Fatalf("decoded %q, want %q", got, "ababab")
	}
}

func TestApplyOverlappingMatchAndDistanceReuse(t *testing.T) {
	d := &decoder{limit: 1 << 20}
	literals := []byte("abcZ")
	lmds := []lmd{
		{literal: 3},
		{literal: 0, match: 6, dist: 3},
		{literal: 1, match: 6, dist: 0}, // zero means reuse the previous distance
	}
	if err := d.apply(literals, lmds, 16, 0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	want := []byte("abcabcabcZbcZbcZ")
	if !bytes.Equal(d.out, want) {
		t.Fatalf("apply produced %q, want %q", d.out, want)
	}
}

func TestApplyDistanceUpdatesOnZeroLengthMatch(t *testing.T) {
	// The packed-distance state is updated even when an entry carries no
	// match; a later zero-distance entry must reuse that new distance.
	d := &decoder{limit: 1 << 20, out: []byte("0123456789")}
	literals := []byte("X")
	lmds := []lmd{
		{literal: 0, match: 0, dist: 5},
		{literal: 1, match: 3, dist: 0},
	}
	if err := d.apply(literals, lmds, 4, 0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if want := "0123456789X678"; string(d.out) != want {
		t.Fatalf("apply produced %q, want %q", d.out, want)
	}
}

func TestApplyRejectsImpossibleLMDs(t *testing.T) {
	cases := []struct {
		name     string
		out      []byte
		literals []byte
		lmds     []lmd
		rawLen   uint32
	}{
		{
			name:     "no distance to reuse",
			literals: []byte("a"),
			lmds:     []lmd{{literal: 1, match: 1, dist: 0}},
			rawLen:   2,
		},
		{
			name:     "distance before output",
			literals: []byte("a"),
			lmds:     []lmd{{literal: 1, match: 1, dist: 9}},
			rawLen:   2,
		},
		{
			name:     "literal overrun",
			literals: []byte("a"),
			lmds:     []lmd{{literal: 2}},
			rawLen:   2,
		},
		{
			name:     "declared size mismatch",
			literals: []byte("a"),
			lmds:     []lmd{{literal: 1}},
			rawLen:   2,
		},
		{
			name:     "produces too much",
			literals: []byte("abcd"),
			lmds:     []lmd{{literal: 4}},
			rawLen:   3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &decoder{limit: 1 << 20, out: append([]byte(nil), tc.out...)}
			err := d.apply(tc.literals, tc.lmds, tc.rawLen, 0)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestDecodeWeightRoundTrip(t *testing.T) {
	for value := uint16(0); value < 1048; value++ {
		code, n := encodeWeight(value)
		got, used, ok := decodeWeight(code)
		if !ok {
			t.Fatalf("weight %d: decodeWeight rejected an encoded code", value)
		}
		if got != value || used != n {
			t.Fatalf("weight %d: decoded %d with %d bits, want %d with %d bits", value, got, used, value, n)
		}
	}
}

// encodeWeight mirrors the reference encoder; it exists only to exercise the
// decoder against the full weight range.
func encodeWeight(value uint16) (uint64, uint32) {
	switch {
	case value == 0:
		return 0, 2
	case value == 1:
		return 2, 2
	case value == 2:
		return 1, 3
	case value == 3:
		return 5, 3
	case value == 4:
		return 3, 5
	case value == 5:
		return 11, 5
	case value == 6:
		return 19, 5
	case value == 7:
		return 27, 5
	case value < 24:
		return uint64(value-8)<<4 + 7, 8
	default:
		return uint64(value-24)<<4 + 15, 14
	}
}

func TestWeightTotalsRejected(t *testing.T) {
	// A v1 weight payload whose literal table sums to 65 of 64 states.
	payload := make([]byte, v1WeightBytes)
	for i := 0; i < 16; i++ {
		payload[i*2] = 4
	}
	payload[16*2] = 1 // one state too many: 64 + 1
	if _, err := loadWeightsV1(payload, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("loadWeightsV1: error = %v, want ErrCorrupt", err)
	}

	// The same payload with 64 states is accepted.
	payload[16*2] = 0
	if _, err := loadWeightsV1(payload, 0); err != nil {
		t.Fatalf("loadWeightsV1 rejected a normalized table: %v", err)
	}
}

func TestBitReaderMatchesReferenceBitOrder(t *testing.T) {
	for padding := 0; padding < 8; padding++ {
		data := make([]byte, 32)
		for i := range data {
			data[i] = byte(i*37 + 11)
		}
		// Zero the skipped high bits of the last byte.
		data[len(data)-1] &= byte(0xFF >> padding)

		br, err := newBitReader(data, padding, 0)
		if err != nil {
			t.Fatalf("padding %d: %v", padding, err)
		}
		pos := padding
		slow := func(n int) uint32 {
			var v uint32
			for i := 0; i < n; i++ {
				bitPos := pos + i
				byteIndex := len(data) - 1 - bitPos/8
				bitIndex := 7 - bitPos%8
				v = v<<1 | uint32((data[byteIndex]>>uint(bitIndex))&1)
			}
			pos += n
			return v
		}
		// Mirror the decoder's refill pattern: at most 54 bits between flushes,
		// and never run the reader past its required 64-bit lookahead.
		for group := 0; group < 3; group++ {
			for _, n := range []int{14, 17, 23} {
				want := slow(n)
				got := br.pull(n)
				if got != want {
					t.Fatalf("padding %d group %d: pull(%d) = %#x, want %#x", padding, group, n, got, want)
				}
			}
			br.flush()
		}
	}
}

func TestBitReaderRejectsBadStreams(t *testing.T) {
	if _, err := newBitReader([]byte{0, 0, 0}, 0, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short stream: error = %v, want ErrCorrupt", err)
	}
	data := make([]byte, 16)
	data[len(data)-1] = 0x80
	if _, err := newBitReader(data, 1, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("non-zero padding: error = %v, want ErrCorrupt", err)
	}
	if _, err := newBitReader(make([]byte, 16), 8, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("out-of-range padding: error = %v, want ErrCorrupt", err)
	}
}

func TestConcatenatedBlockSequence(t *testing.T) {
	// The reference vectors concatenate independently encoded blocks and a
	// single end marker; this confirms the decoder carries one stream state
	// across block boundaries.
	for _, name := range []string{"raw-then-vn", "vn-then-raw", "v2-v2", "v2-vn-raw"} {
		var vector *testVector
		for i := range testVectors {
			if testVectors[i].name == name {
				vector = &testVectors[i]
			}
		}
		if vector == nil {
			t.Fatalf("missing %s fixture", name)
		}
		got, err := Decode(vector.stream, Limits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, vector.want) {
			t.Fatalf("%s: wrong output", name)
		}
	}
}

func TestMutationsNeverPanic(t *testing.T) {
	// Deterministic byte mutations of valid streams must fail cleanly or
	// decode; they must never panic or return partial output alongside error.
	for _, vector := range testVectors {
		for pos := 0; pos < len(vector.stream); pos += max(1, len(vector.stream)/64) {
			for _, delta := range []byte{1, 0x80, 0xFF} {
				input := append([]byte(nil), vector.stream...)
				input[pos] ^= delta
				got, err := Decode(input, Limits{})
				if err != nil && got != nil {
					t.Fatalf("%s mutation at %d: %d partial bytes with error %v",
						vector.name, pos, len(got), err)
				}
			}
		}
	}
}

func TestErrorFormatting(t *testing.T) {
	err := corruptAt(7, "detail %d", 3)
	if !strings.Contains(err.Error(), "byte 7") || !strings.Contains(err.Error(), "detail 3") {
		t.Fatalf("unexpected error text: %v", err)
	}
	if err.Error() == "" {
		t.Fatal("empty error text")
	}
	bare := (&Error{Kind: ErrCorrupt, Offset: 3}).Error()
	if !strings.Contains(bare, "byte 3") {
		t.Fatalf("unexpected bare error text: %s", bare)
	}
}
