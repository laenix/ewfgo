package wim

import (
	"bytes"
	"strings"
	"testing"
)

// lzxUncompressedChunk emits one WIM-mode uncompressed LZX block. The block
// header is bit-packed; the twelve distance bytes and the data are raw bytes,
// because the decoder switches to byte mode after the padded header.
func lzxUncompressedChunk(data []byte) []byte {
	if len(data)%2 != 0 {
		panic("lzxUncompressedChunk needs an even length so no pad byte is needed")
	}
	w := &lzxBitWriter{}
	w.write(3, 3) // uncompressed
	w.write(0, 1)
	w.write(uint32(len(data)), 16)
	for w.bit%16 != 0 {
		w.write(0, 1)
	}
	chunk := w.bytes()
	for index := 0; index < 3; index++ {
		chunk = append(chunk, 1, 0, 0, 0)
	}
	return append(chunk, data...)
}

// canonicalCodes assigns canonical codes to a length array, in symbol order
// within each code length.
func canonicalCodes(lengths []byte) ([]uint32, []int) {
	codes := make([]uint32, len(lengths))
	sizes := make([]int, len(lengths))
	code := uint32(0)
	for length := 1; length <= 16; length++ {
		for symbol, candidate := range lengths {
			if int(candidate) == length {
				codes[symbol] = code
				sizes[symbol] = length
				code++
			}
		}
		code <<= 1
	}
	return codes, sizes
}

func emitZeroRun(w *lzxBitWriter, run int, codes []uint32, sizes []int) {
	switch {
	case run >= 20:
		w.write(codes[18], sizes[18])
		w.write(uint32(run-20), 5)
	case run >= 4:
		w.write(codes[17], sizes[17])
		w.write(uint32(run-4), 4)
	default:
		for index := 0; index < run; index++ {
			w.write(codes[0], sizes[0])
		}
	}
}

// emitLevels writes one pretree-coded level array, using zero runs for the
// gaps and a direct delta symbol for each named level.
func emitLevels(w *lzxBitWriter, count int, ones map[int]byte, codes []uint32, sizes []int) {
	pending := 0
	flush := func() {
		for pending > 0 {
			run := pending
			if run > 51 {
				run = 51
			}
			emitZeroRun(w, run, codes, sizes)
			pending -= run
		}
	}
	for index := 0; index < count; index++ {
		level, ok := ones[index]
		if !ok {
			pending++
			continue
		}
		flush()
		symbol := (17 - int(level)) % 17
		w.write(codes[symbol], sizes[symbol])
	}
	flush()
}

func lzxMatchChunk(withLiteral bool) []byte {
	w := &lzxBitWriter{}
	w.write(1, 3) // verbatim
	w.write(0, 1)
	w.write(6, 16) // one literal and a four-byte match, or the match alone
	pretree := make([]byte, 20)
	pretree[0], pretree[16], pretree[17], pretree[18] = 2, 2, 2, 2
	codes, sizes := canonicalCodes(pretree)
	emitPretree := func() {
		for _, length := range pretree {
			w.write(uint32(length), 4)
		}
	}
	// The main tree holds only symbol 65 ('A') and the match symbol for
	// slot 0, length 4 (symbol 258), each at one bit.
	emitPretree()
	emitLevels(w, 256, map[int]byte{65: 1}, codes, sizes)
	emitPretree()
	emitLevels(w, 240, map[int]byte{2: 1}, codes, sizes)
	emitPretree()
	emitLevels(w, 249, nil, codes, sizes)
	if withLiteral {
		w.write(0, 1) // literal 'A' (code 0)
		w.write(1, 1) // match symbol (code 1)
	} else {
		w.write(1, 1)
	}
	return w.bytes()
}

func TestLZXUncompressedBlock(t *testing.T) {
	data := []byte("an uncompressed LZX block!")
	if len(data)%2 != 0 {
		data = append(data, 0)
	}
	decoder := newTestLZX(t, 15)
	out, err := decoder.decode(lzxUncompressedChunk(data), len(data))
	if err != nil {
		t.Fatalf("decode error = %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("uncompressed output = %q", out)
	}
}

func TestLZXMatchCopiesHistory(t *testing.T) {
	decoder := newTestLZX(t, 15)
	out, err := decoder.decode(lzxMatchChunk(true), 5)
	if err != nil {
		t.Fatalf("decode error = %v", err)
	}
	if string(out) != "AAAAA" {
		t.Fatalf("match output = %q, want AAAAA", out)
	}
}

func TestLZXMatchBeforeStartIsRefused(t *testing.T) {
	decoder := newTestLZX(t, 15)
	_, err := decoder.decode(lzxMatchChunk(false), 6)
	if err == nil {
		t.Fatal("a match before the window start was accepted")
	}
	if !strings.Contains(err.Error(), "behind the start") {
		t.Fatalf("error = %v", err)
	}
}

func TestLZXZeroRunsCoverTheLevelArrays(t *testing.T) {
	// The match fixture encodes its level arrays with both zero-run symbols;
	// a successful decode is the assertion. This test names that coverage for
	// readers of the suite.
	if _, err := newTestLZX(t, 15).decode(lzxMatchChunk(true), 5); err != nil {
		t.Fatalf("decode error = %v", err)
	}
}
