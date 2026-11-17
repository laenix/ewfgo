package carving

import (
	"bytes"
	"testing"
)

// lzxCode is one canonical code in the test encoder.
type lzxCode struct {
	code   uint32
	length uint32
}

// lzxPack writes codes in the bit order the Xpress Huffman reader expects:
// sixteen-bit little-endian words, each word's bits most significant first.
func lzxPack(codes []lzxCode) []byte {
	var bits []bool
	for _, c := range codes {
		for index := c.length; index > 0; index-- {
			bits = append(bits, (c.code>>(index-1))&1 == 1)
		}
	}
	for len(bits)%16 != 0 {
		bits = append(bits, false)
	}
	out := make([]byte, len(bits)/8)
	for index, bit := range bits {
		if !bit {
			continue
		}
		word := index / 16
		within := 15 - (index % 16)
		byteIndex := word*2 + boolInt(within >= 8)
		out[byteIndex] |= 1 << (within % 8)
	}
	return out
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// lzxFlatTable is a complete table where every symbol is nine bits.
func lzxFlatTable() []byte {
	table := make([]byte, 256)
	for i := range table {
		table[i] = 0x99
	}
	return table
}

func lzxBlock(codes []lzxCode) []byte {
	stream := append(lzxFlatTable(), lzxPack(codes)...)
	return stream
}

func TestLzxpressLiteralsDecodeToTheirBytes(t *testing.T) {
	stream := lzxBlock([]lzxCode{{code: 'H', length: 9}, {code: 'i', length: 9}})
	decoded, _, err := lzxpressDecompressWithConsumed(stream, 2)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decoded, []byte("Hi")) {
		t.Fatalf("decoded = %q, want Hi", decoded)
	}
}

func TestLzxpressShortMatchRepeatsTheBytesBehindIt(t *testing.T) {
	matchSymbol := uint32(256 + (5 - 3))
	stream := lzxBlock([]lzxCode{{code: 'a', length: 9}, {code: matchSymbol, length: 9}})
	decoded, _, err := lzxpressDecompressWithConsumed(stream, 6)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decoded, []byte("aaaaaa")) {
		t.Fatalf("decoded = %q, want aaaaaa", decoded)
	}
}

func TestLzxpressDistanceBitsAreReadAfterTheSymbol(t *testing.T) {
	matchSymbol := uint32(256 + (1 << 4))
	stream := lzxBlock([]lzxCode{
		{code: 'b', length: 9},
		{code: 'c', length: 9},
		{code: matchSymbol, length: 9},
		{code: 0, length: 1},
	})
	decoded, _, err := lzxpressDecompressWithConsumed(stream, 5)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decoded, []byte("bcbcb")) {
		t.Fatalf("decoded = %q, want bcbcb", decoded)
	}
}

func TestLzxpressLengthNibbleOfFifteenReadsItsByteAtTheCursor(t *testing.T) {
	matchSymbol := uint32(256 + 15)
	stream := lzxBlock([]lzxCode{
		{code: 'x', length: 9},
		{code: 'x', length: 9},
		{code: matchSymbol, length: 9},
	})
	stream = append(stream, 0, 0, 10) // length = 10 + 15 + 3 = 28
	decoded, _, err := lzxpressDecompressWithConsumed(stream, 30)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decoded, bytes.Repeat([]byte("x"), 30)) {
		t.Fatalf("decoded = %q, want 30 x", decoded)
	}
}

func TestLzxpressIncompleteTableIsRefused(t *testing.T) {
	stream := make([]byte, 256)
	stream[0] = 0x01
	stream = append(stream, make([]byte, 8)...)
	if _, _, err := lzxpressDecompressWithConsumed(stream, 4); err == nil {
		t.Fatal("decompress accepted an incomplete table")
	}
}

func TestLzxpressMatchBeforeTheStartIsRefused(t *testing.T) {
	matchSymbol := uint32(256 + (10 << 4) + 3)
	stream := lzxBlock([]lzxCode{{code: matchSymbol, length: 9}, {code: 0, length: 10}})
	if _, _, err := lzxpressDecompressWithConsumed(stream, 4); err == nil {
		t.Fatal("decompress accepted a match before the start")
	}
}

func TestLzxpressStreamOverrunningTheDeclaredSizeIsRefused(t *testing.T) {
	matchSymbol := uint32(256 + (5 - 3))
	stream := lzxBlock([]lzxCode{{code: 'a', length: 9}, {code: matchSymbol, length: 9}})
	if _, _, err := lzxpressDecompressWithConsumed(stream, 3); err == nil {
		t.Fatal("decompress accepted a stream that overruns the declared size")
	}
}

func TestLzxpressMissingTableIsRefused(t *testing.T) {
	if _, _, err := lzxpressDecompressWithConsumed(make([]byte, 10), 10); err == nil {
		t.Fatal("decompress accepted a missing table")
	}
}
