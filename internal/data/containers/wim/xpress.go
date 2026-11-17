// XPRESS Huffman decompression ([MS-XCA] 2.2.4), the codec the WIM
// `XPRESS` header flag names. This is the LZ77+Huffman variant wimlib writes,
// not the plain LZ77 Xpress codec used by ESE.
//
// A stream is a series of blocks that expand to at most 64 KiB. Each block
// starts with 256 bytes of packed code lengths for 512 symbols, followed by a
// bit stream read most-significant bit first from 16-bit little-endian words.
// The code table must be complete; a match may not reach before the output.

package wim

import "fmt"

const (
	xpressBlockSize        = 65_536
	xpressTableBytes       = 256
	xpressSymbols          = 512
	xpressMaxCodeBits      = 15
	xpressTableEntries     = 1 << xpressMaxCodeBits
	xpressMinMatch         = 3
	xpressEscalatingNibble = 15
	xpressEscalatingByte   = 255
)

// xpressDecompress expands input into exactly expected bytes. A short result
// is returned short (the caller compares), and any structural error is
// reported instead of returning partial output.
func xpressDecompress(input []byte, expected int) ([]byte, error) {
	if expected < 0 {
		return nil, fmt.Errorf("XPRESS output size is negative")
	}
	out := make([]byte, 0, minInt(expected, xpressBlockSize*4))
	offset := 0
	table := &xpressTable{entries: make([]uint16, xpressTableEntries)}
	for len(out) < expected {
		if offset < 0 || offset > len(input) {
			offset = len(input)
		}
		block := input[offset:]
		if len(block) < xpressTableBytes {
			return nil, fmt.Errorf("compressed block at offset %d ends inside its Huffman table", offset)
		}
		if err := table.fill(block[:xpressTableBytes], offset); err != nil {
			return nil, err
		}
		bits := newXpressBits(block, xpressTableBytes)
		blockEnd := len(out) + xpressBlockSize
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
			if length == xpressEscalatingNibble {
				length = uint32(bits.readByte()) + xpressEscalatingNibble
				if length == xpressEscalatingNibble+xpressEscalatingByte {
					length = bits.read16()
				}
			}
			length += xpressMinMatch
			bits.skip(distanceBits)
			if uint64(distance) > uint64(len(out)) {
				return nil, fmt.Errorf(
					"a match at compressed offset %d reaches back %d byte(s) from only %d produced",
					offset, distance, len(out))
			}
			if uint64(len(out))+uint64(length) > uint64(expected) {
				return nil, fmt.Errorf(
					"the compressed stream expands past the %d bytes its container declares", expected)
			}
			for index := uint32(0); index < length; index++ {
				out = append(out, out[len(out)-int(distance)])
			}
		}
		offset += bits.bytePosition()
		if offset >= len(input) {
			break
		}
	}
	return out, nil
}

type xpressTable struct {
	entries []uint16
	lengths [xpressSymbols]byte
}

func (t *xpressTable) fill(packed []byte, offset int) error {
	for index, byteValue := range packed {
		t.lengths[index*2] = byteValue & 0x0F
		t.lengths[index*2+1] = byteValue >> 4
	}
	entry := 0
	for bitLength := 1; bitLength <= xpressMaxCodeBits; bitLength++ {
		for symbol := 0; symbol < xpressSymbols; symbol++ {
			if int(t.lengths[symbol]) != bitLength {
				continue
			}
			count := 1 << uint(xpressMaxCodeBits-bitLength)
			if entry+count > xpressTableEntries {
				return fmt.Errorf(
					"the Huffman code lengths at offset %d do not form a complete code", offset)
			}
			for index := entry; index < entry+count; index++ {
				t.entries[index] = uint16(symbol)
			}
			entry += count
		}
	}
	if entry != xpressTableEntries {
		return fmt.Errorf(
			"the Huffman code lengths at offset %d do not form a complete code", offset)
	}
	return nil
}

func (t *xpressTable) symbol(bits *xpressBits) uint16 {
	symbol := t.entries[bits.lookup(xpressMaxCodeBits)]
	bits.skip(uint32(t.lengths[symbol]))
	return symbol
}

// xpressBits is the bit register [MS-XCA] 2.2.4 describes: two 16-bit
// little-endian words with at least 16 bits of slack.
type xpressBits struct {
	data []byte
	pos  int
	mask uint32
	bits int
}

func newXpressBits(data []byte, pos int) *xpressBits {
	reader := &xpressBits{data: data, pos: pos}
	high := reader.read16()
	low := reader.read16()
	reader.mask = high<<16 | low
	reader.bits = 32
	return reader
}

func (r *xpressBits) read16() uint32 {
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

func (r *xpressBits) lookup(count uint32) uint32 {
	if count == 0 {
		return 0
	}
	return r.mask >> (32 - count)
}

func (r *xpressBits) skip(count uint32) {
	r.mask <<= count
	r.bits -= int(count)
	if r.bits < 16 {
		shift := uint32(16 - r.bits)
		r.mask += r.read16() << shift
		r.bits += 16
	}
}

func (r *xpressBits) readByte() byte {
	var value byte
	if r.pos >= 0 && r.pos < len(r.data) {
		value = r.data[r.pos]
	}
	r.pos++
	return value
}

func (r *xpressBits) bytePosition() int { return r.pos }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
