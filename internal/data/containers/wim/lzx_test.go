package wim

import (
	"bytes"
	"errors"
	"testing"
)

// lzxBitWriter packs bits exactly the way the LZX bit reader consumes them:
// 16-bit little-endian words, most-significant bit first.
type lzxBitWriter struct {
	words []uint16
	bit   int
}

func (w *lzxBitWriter) write(value uint32, count int) {
	for index := count - 1; index >= 0; index-- {
		word := w.bit / 16
		for len(w.words) <= word {
			w.words = append(w.words, 0)
		}
		if (value>>uint(index))&1 != 0 {
			within := 15 - (w.bit % 16)
			w.words[word] |= 1 << uint(within)
		}
		w.bit++
	}
}

func (w *lzxBitWriter) bytes() []byte {
	for w.bit%16 != 0 {
		w.write(0, 1)
	}
	out := make([]byte, 0, len(w.words)*2)
	for _, word := range w.words {
		out = append(out, byte(word), byte(word>>8))
	}
	return out
}

// lzxLiteralChunk emits one WIM-mode LZX chunk made only of literal symbols.
// It uses a verbatim block, a main tree with 256 eight-bit literal codes, an
// empty length tree and a 32 KiB window (dict bits 15).
func lzxLiteralChunk(data []byte) []byte {
	if len(data) > 1<<15 {
		panic("lzxLiteralChunk input exceeds 32 KiB")
	}
	w := &lzxBitWriter{}
	w.write(1, 3) // verbatim block
	w.write(0, 1) // the long-size form, then a 16-bit size
	w.write(uint32(len(data)), 16)

	pretree := func() {
		// Two one-bit codes: symbol 0 = 0, symbol 9 = 1.
		for symbol := 0; symbol < 20; symbol++ {
			if symbol == 0 || symbol == 9 {
				w.write(1, 4)
			} else {
				w.write(0, 4)
			}
		}
	}
	pretree()
	for index := 0; index < 256; index++ {
		w.write(1, 1) // symbol 9: previous 0 - 9 mod 17 = 8
	}
	pretree()
	for index := 0; index < 240; index++ {
		w.write(0, 1) // symbol 0: level stays 0
	}
	pretree()
	for index := 0; index < 249; index++ {
		w.write(0, 1)
	}
	for _, value := range data {
		w.write(uint32(value), 8)
	}
	return w.bytes()
}

func newTestLZX(t *testing.T, bits int) *lzxDecoder {
	t.Helper()
	decoder, err := newLZXDecoder(bits, true)
	if err != nil {
		t.Fatalf("newLZXDecoder(%d) error = %v", bits, err)
	}
	return decoder
}

func TestLZXPositionTable(t *testing.T) {
	base, extra := lzxPositionTables()
	wantBase := map[int]uint32{
		2: 0, 3: 1, 4: 2, 5: 4, 6: 6, 7: 10, 8: 14, 9: 22,
		36: (1 << 18) - 2, 49: 1_966_078,
	}
	for slot, value := range wantBase {
		if base[slot] != value {
			t.Fatalf("base[%d] = %d, want %d", slot, base[slot], value)
		}
	}
	if !bytes.Equal(extra[:10], []byte{0, 0, 0, 0, 1, 1, 2, 2, 3, 3}) {
		t.Fatalf("extra = %v", extra[:10])
	}
	if extra[49] != 17 {
		t.Fatalf("extra[49] = %d", extra[49])
	}
}

func TestLZXBitStreamWordOrder(t *testing.T) {
	data := []byte{0xF0, 0x00, 0x34, 0x12}
	bits := newLZXBits(data)
	if value, err := bits.read(8); err != nil || value != 0x00 {
		t.Fatalf("read(8) = %#x, %v", value, err)
	}
	if value, err := bits.read(8); err != nil || value != 0xF0 {
		t.Fatalf("read(8) = %#x, %v", value, err)
	}
	if value, err := bits.read(16); err != nil || value != 0x1234 {
		t.Fatalf("read(16) = %#x, %v", value, err)
	}
	if _, err := bits.read(1); !errors.Is(err, errLZXTruncated) {
		t.Fatalf("past-end error = %v", err)
	}
}

func TestLZXBitStreamRebase(t *testing.T) {
	data := []byte{0xF0, 0x00, 0x34, 0x12}
	bits := newLZXBits(data)
	if _, err := bits.read(16); err != nil {
		t.Fatal(err)
	}
	bits.rebase(2)
	if value, err := bits.read(16); err != nil || value != 0x1234 {
		t.Fatalf("read after rebase = %#x, %v", value, err)
	}
}

func TestLZXHuffmanCanonicalCodes(t *testing.T) {
	tree, err := buildLZXHuffman([]byte{1, 2, 3, 3}, lzxTreeFull)
	if err != nil {
		t.Fatal(err)
	}
	// Codes 0, 10, 110, 111, padded into one 16-bit word.
	bits := newLZXBits([]byte{0x80, 0x5B})
	for want := uint16(0); want < 4; want++ {
		got, err := tree.decode(bits)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("symbol = %d, want %d", got, want)
		}
	}
}

func TestLZXHuffmanCompleteness(t *testing.T) {
	if _, err := buildLZXHuffman([]byte{2, 2, 2}, lzxTreeFull); err == nil {
		t.Fatal("an incomplete tree was accepted")
	}
	if _, err := buildLZXHuffman([]byte{2, 2, 2}, lzxTreeFullOrEmpty); err == nil {
		t.Fatal("an incomplete non-empty tree was accepted")
	}
	if _, err := buildLZXHuffman([]byte{0, 0, 0}, lzxTreeFullOrEmpty); err != nil {
		t.Fatalf("an empty allowed tree was refused: %v", err)
	}
	if _, err := buildLZXHuffman([]byte{1, 1, 1}, lzxTreeFull); err == nil {
		t.Fatal("an over-subscribed tree was accepted")
	}
}

func TestLZXWindowRange(t *testing.T) {
	if _, err := newLZXDecoder(14, true); err == nil {
		t.Fatal("14-bit window was accepted")
	}
	if _, err := newLZXDecoder(22, true); err == nil {
		t.Fatal("22-bit window was accepted")
	}
	for _, bits := range []int{15, 21} {
		if _, err := newLZXDecoder(bits, true); err != nil {
			t.Fatalf("%d-bit window refused: %v", bits, err)
		}
	}
}

func TestLZXDecodesLiteralChunk(t *testing.T) {
	data := make([]byte, 20_000)
	for index := range data {
		data[index] = byte('A' + index%23)
	}
	chunk := lzxLiteralChunk(data)
	decoder := newTestLZX(t, 15)
	out, err := decoder.decode(chunk, len(data))
	if err != nil {
		t.Fatalf("decode error = %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("decoded literals differ")
	}
}

func TestLZXRejectsReservedBlockAndTruncation(t *testing.T) {
	decoder := newTestLZX(t, 15)
	if _, err := decoder.decode(nil, 10); !errors.Is(err, errLZXTruncated) {
		t.Fatalf("empty input error = %v", err)
	}
	// Three reserved block-type bits (0) followed by enough bytes.
	w := &lzxBitWriter{}
	w.write(0, 3)
	w.write(0, 1)
	w.write(1, 16)
	decoder = newTestLZX(t, 15)
	if _, err := decoder.decode(w.bytes(), 1); err == nil {
		t.Fatal("reserved block type was accepted")
	}
}

func TestLZXX86Translation(t *testing.T) {
	decoder := newTestLZX(t, 15)

	data := make([]byte, 16)
	data[0] = 0xE8
	copy(data[1:5], []byte{5, 0, 0, 0})
	decoder.translationSize = 0x1000
	decoder.translated = 0
	decoder.translate(data)
	if !bytes.Equal(data[1:5], []byte{5, 0, 0, 0}) {
		t.Fatalf("position 0 operand = %v", data[1:5])
	}

	data = make([]byte, 16)
	data[0] = 0xE8
	copy(data[1:5], []byte{5, 0, 0, 0})
	decoder.translationSize = 0x1000
	decoder.translated = 0x100
	decoder.translate(data)
	var want uint32 = 5
	want -= 0x100
	if got := testLE32(data[1:5]); got != want {
		t.Fatalf("position 0x100 operand = %#x, want %#x", got, want)
	}

	data = make([]byte, 16)
	data[0] = 0xE8
	copy(data[1:5], []byte{0xF0, 0xFF, 0xFF, 0xFF})
	decoder.translationSize = 0x1000
	decoder.translated = 0x100
	decoder.translate(data)
	want = 0xFFFFFFF0
	want += 0x1000
	if got := testLE32(data[1:5]); got != want {
		t.Fatalf("high operand = %#x, want %#x", got, want)
	}

	// Ten bytes leaves too little room after the E8, so it is untouched.
	data = make([]byte, 10)
	data[0] = 0xE8
	copy(data[1:5], []byte{5, 0, 0, 0})
	before := append([]byte(nil), data...)
	decoder.translationSize = 0x1000
	decoder.translated = 0x100
	decoder.translate(data)
	if !bytes.Equal(data, before) {
		t.Fatal("a short tail was translated")
	}
}

func testLE32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// TestWIMLZXEndToEnd exercises LZX through the container path. Metadata and
// XML are stored uncompressed (the format allows per-resource storage), while
// the file blobs use LZX chunks, so no byte of the fixture depends on the
// reader's own LZX output.
func TestWIMLZXEndToEnd(t *testing.T) {
	data := make([]byte, testChunk+1234)
	for index := range data {
		data[index] = byte('a' + index%26)
	}
	tree := append(testTree(), testFile("big.bin", data))
	parts := buildWIM(t, wimSpec{tree: tree, kind: "lzx"})
	container := openTestWIM(t, parts.file)
	if container.Info().Compression != Lzx {
		t.Fatalf("compression = %v", container.Info().Compression)
	}
	entry, err := container.OpenEntry(1, "big.bin")
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	if got := readAll(t, entry); !bytes.Equal(got, data) {
		t.Fatal("LZX multi-chunk contents differ")
	}
	kernel, err := container.OpenEntry(1, "Windows/System32/kernel32.dll")
	if err != nil {
		t.Fatalf("OpenEntry(kernel) error = %v", err)
	}
	if got := string(readAll(t, kernel)); got != "kernel bytes" {
		t.Fatalf("kernel contents = %q", got)
	}
	if entry.Stats().DecompressedBytes != uint64(len(data)) {
		t.Fatalf("decompressed = %d", entry.Stats().DecompressedBytes)
	}
}
