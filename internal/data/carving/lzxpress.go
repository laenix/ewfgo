// Microsoft Xpress Huffman (LZXPRESS) decompression.
//
// This is the codec a compressed Windows Prefetch file wraps its body in
// (MAM\x04). A stream is a series of blocks, each of which expands to at most
// 64 KiB:
//
//	block
//	  0   256  code lengths: 512 symbols, 4 bits each
//	           byte k holds symbol 2k in its low nibble, 2k+1 in its high nibble
//	  256 ...  bit stream, read MSB-first from 16-bit little-endian words
//
// The code table is canonical: symbols are ordered by code length and then by
// symbol value, and the table must be complete (the code lengths must sum to
// exactly 2^15). A symbol below 256 is a literal byte. A symbol of 256 or more
// is an LZ77 match:
//
//	coded = symbol - 256
//	distance_bits = coded >> 4
//	length_nibble = coded & 15          length = length_nibble + 3
//	distance = (1 << distance_bits) + next distance_bits bits
//
// A length nibble of 15 escalates to a trailing byte and, when that byte is 255,
// to a trailing 16-bit word. Both escalations are read at the byte cursor the
// bit reader has already advanced past, not from the bit register.
//
// The decoder refuses a table that is incomplete or oversubscribed, a match that
// reaches before the start of the output, and a stream that produces more bytes
// than the container declared. It never returns a partial block as if it were
// the whole one.

package carving

import "fmt"

const (
	// One block expands to at most this many bytes.
	lzxBlockSize = 65536
	// Bytes of code-length table in front of every block.
	lzxTableBytes = 256
	// Symbols in the alphabet: 256 literals plus 256 match encodings.
	lzxSymbols = 512
	// Longest code the format allows.
	lzxMaxCodeBits = 15
	// Lookup entries for a complete 15-bit table.
	lzxTableEntries = 1 << lzxMaxCodeBits
	// Shortest match the format encodes.
	lzxMinMatch = 3
	// The escalation value at which a length nibble reads a trailing byte.
	lzxEscalatingNibble = 15
	// The escalation value at which a length byte reads a trailing word.
	lzxEscalatingByte = 255
)

// lzxpressDecompressWithConsumed decompresses input into exactly expected bytes
// and reports how many input bytes the stream used.
//
// A stream that stops short of expected is returned short rather than padded,
// and one that runs past it is refused; callers compare the length.
func lzxpressDecompressWithConsumed(input []byte, expected int) ([]byte, uint64, error) {
	capacity := expected
	if capacity > lzxBlockSize*4 {
		capacity = lzxBlockSize * 4
	}
	out := make([]byte, 0, capacity)
	offset := 0
	table := newLZXDecodeTable()
	for len(out) < expected {
		if offset > len(input) {
			offset = len(input)
		}
		block := input[offset:]
		if len(block) < lzxTableBytes {
			return nil, 0, fmt.Errorf("compressed block at offset %d ends inside its Huffman table", offset)
		}
		if err := table.fill(block[:lzxTableBytes], offset); err != nil {
			return nil, 0, err
		}
		bits := newLZXBitReader(block, lzxTableBytes)
		blockEnd := len(out) + lzxBlockSize
		for len(out) < blockEnd && len(out) < expected {
			symbol := table.symbol(bits)
			if symbol < 256 {
				out = append(out, byte(symbol))
				continue
			}
			coded := uint32(symbol) - 256
			distanceBits := coded >> 4
			distance := (uint32(1) << distanceBits) + bits.lookup(distanceBits)
			length := coded & 0x0F
			if length == lzxEscalatingNibble {
				length = uint32(bits.readByte()) + lzxEscalatingNibble
				if length == lzxEscalatingNibble+lzxEscalatingByte {
					length = bits.read16()
				}
			}
			length += lzxMinMatch
			bits.skip(distanceBits)
			if uint64(distance) > uint64(len(out)) {
				return nil, 0, fmt.Errorf(
					"a match at compressed offset %d reaches back %d byte(s) from only %d produced",
					offset, distance, len(out),
				)
			}
			end := len(out) + int(length)
			if end > expected {
				return nil, 0, fmt.Errorf(
					"the compressed stream expands past the %d bytes its container declares", expected,
				)
			}
			// A match may overlap its own output (aaaaaa is one literal and a
			// distance-1 match), so it is copied one byte at a time.
			for i := 0; i < int(length); i++ {
				out = append(out, out[len(out)-int(distance)])
			}
		}
		offset += bits.bytePosition()
		if offset >= len(input) {
			break
		}
	}
	return out, uint64(offset), nil
}

// lzxDecodeTable is a block's canonical decode table: 2^15 entries plus each
// symbol's length.
type lzxDecodeTable struct {
	entries []uint16
	lengths [lzxSymbols]byte
}

func newLZXDecodeTable() *lzxDecodeTable {
	return &lzxDecodeTable{entries: make([]uint16, lzxTableEntries)}
}

// fill builds the table from 256 bytes of packed nibbles.
func (t *lzxDecodeTable) fill(packed []byte, offset int) error {
	for index, b := range packed {
		t.lengths[index*2] = b & 0x0F
		t.lengths[index*2+1] = b >> 4
	}
	entry := 0
	for bitLength := 1; bitLength <= lzxMaxCodeBits; bitLength++ {
		for symbol := 0; symbol < lzxSymbols; symbol++ {
			if int(t.lengths[symbol]) != bitLength {
				continue
			}
			count := 1 << uint(lzxMaxCodeBits-bitLength)
			if entry+count > lzxTableEntries {
				return fmt.Errorf(
					"the Huffman code lengths at offset %d do not form a complete code", offset,
				)
			}
			for index := entry; index < entry+count; index++ {
				t.entries[index] = uint16(symbol)
			}
			entry += count
		}
	}
	if entry != lzxTableEntries {
		return fmt.Errorf(
			"the Huffman code lengths at offset %d do not form a complete code", offset,
		)
	}
	return nil
}

// symbol decodes the next symbol, consuming its code.
func (t *lzxDecodeTable) symbol(bits *lzxBitReader) uint16 {
	symbol := t.entries[bits.lookup(lzxMaxCodeBits)]
	bits.skip(uint32(t.lengths[symbol]))
	return symbol
}

// lzxBitReader is the bit register [MS-XCA] 2.2.4 describes: two 16-bit
// little-endian words with at least 16 bits of slack, so a code is always
// entirely inside it.
type lzxBitReader struct {
	data []byte
	// pos is the byte cursor. Trailing length bytes are read here, ahead of the
	// bits still held in the register.
	pos  int
	mask uint32
	bits int
}

// newLZXBitReader starts a block at pos: the first two words fill the register.
func newLZXBitReader(data []byte, pos int) *lzxBitReader {
	reader := &lzxBitReader{data: data, pos: pos}
	high := reader.read16()
	low := reader.read16()
	reader.mask = high<<16 | low
	reader.bits = 32
	return reader
}

// read16 reads one 16-bit little-endian word; past the end the missing bytes
// are zero and the cursor only advances over what exists.
func (r *lzxBitReader) read16() uint32 {
	available := len(r.data) - r.pos
	if available < 0 {
		available = 0
	}
	switch {
	case available == 0:
		return 0
	case available == 1:
		value := uint32(r.data[r.pos]) << 8
		r.pos++
		return value
	default:
		value := uint32(r.data[r.pos]) | uint32(r.data[r.pos+1])<<8
		r.pos += 2
		return value
	}
}

// lookup returns the next count bits, most significant first.
func (r *lzxBitReader) lookup(count uint32) uint32 {
	if count == 0 {
		return 0
	}
	return r.mask >> (32 - count)
}

func (r *lzxBitReader) skip(count uint32) {
	r.mask <<= count
	r.bits -= int(count)
	if r.bits < 16 {
		shift := uint32(16 - r.bits)
		r.mask += r.read16() << shift
		r.bits += 16
	}
}

func (r *lzxBitReader) readByte() byte {
	var value byte
	if r.pos >= 0 && r.pos < len(r.data) {
		value = r.data[r.pos]
	}
	r.pos++
	return value
}

// bytePosition is where the next block's table begins.
func (r *lzxBitReader) bytePosition() int {
	return r.pos
}
