// LZX decompression (the WIM variant).
//
// The stream is a sequence of blocks read from 16-bit little-endian words,
// most significant bit first. A WIM chunk is independent: every chunk gets a
// fresh window of the header's chunk size, which must be a power of two from
// 32 KiB to 2 MiB. The decoder also applies the x86 E8 translation that LZX
// pre-filters into the stream, exactly as 7-Zip and wimlib do.
//
// Every read is bounds-checked and every Huffman tree must follow 7-Zip's
// completeness rule: a truncated stream, an oversubscribed or incomplete tree,
// and a match outside the window are errors, never zero-filled guesses.

package wim

import (
	"errors"
	"fmt"
	"math"
)

const (
	lzxBlockVerbatim     = 1
	lzxBlockAligned      = 2
	lzxBlockUncompressed = 3

	lzxNumHuffmanBits = 16
	lzxNumReps        = 3
	lzxNumLenSlots    = 8
	lzxMatchMinLen    = 2
	lzxNumLenSymbols  = 249
	lzxAlignTableSize = 8
	lzxNumPosSlots    = 50
	lzxNumLevelTable  = 20
	lzxLevelZero1     = 17
	lzxLevelZero2     = 18
	lzxLevelSame      = 19

	// Distance slots whose base reaches this threshold take aligned bits.
	lzxAlignThreshold = (1 << 4) - (lzxNumReps - 1)

	lzxDictBitsMin = 15
	lzxDictBitsMax = 21

	// WIM chunks carry no E8 flag; 7-Zip filters with this size.
	lzxWIMTranslationSize = 12_000_000
)

// errLZXTruncated reports a stream that ended before the declared output.
var errLZXTruncated = errors.New("the LZX stream ends before the declared output")

func lzxInvalid(reason string) error { return fmt.Errorf("LZX stream: %s", reason) }

func lzxLimit(reason string) error { return errors.New(reason) }

// lzxBits is a bit stream over one compressed chunk.
type lzxBits struct {
	data   []byte
	origin int
	offset int
}

func newLZXBits(data []byte) *lzxBits { return &lzxBits{data: data} }

func (b *lzxBits) word(index int) (uint16, error) {
	base := b.origin + index*2
	if base < b.origin || base+1 >= len(b.data) {
		return 0, errLZXTruncated
	}
	return uint16(b.data[base]) | uint16(b.data[base+1])<<8, nil
}

func (b *lzxBits) readBit() (uint32, error) {
	word, err := b.word(b.offset / 16)
	if err != nil {
		return 0, err
	}
	bit := uint32(word>>uint(15-(b.offset%16))) & 1
	b.offset++
	return bit, nil
}

func (b *lzxBits) read(count int) (uint32, error) {
	var value uint32
	for index := 0; index < count; index++ {
		bit, err := b.readBit()
		if err != nil {
			return 0, err
		}
		value = value<<1 | bit
	}
	return value, nil
}

func (b *lzxBits) alignWord() error {
	within := b.offset % 16
	if within == 0 {
		return nil
	}
	skipped, err := b.read(16 - within)
	if err != nil {
		return err
	}
	if skipped != 0 {
		return lzxInvalid("the padding before an uncompressed block is not zero")
	}
	return nil
}

func (b *lzxBits) bytePosition() (int, error) {
	if b.offset%8 != 0 {
		return 0, lzxInvalid("an LZX byte read at a bit position")
	}
	return b.origin + b.offset/8, nil
}

func (b *lzxBits) remainingBytes() (int, error) {
	position, err := b.bytePosition()
	if err != nil {
		return 0, err
	}
	if position > len(b.data) {
		return 0, nil
	}
	return len(b.data) - position, nil
}

func (b *lzxBits) rebase(byteOffset int) error {
	if byteOffset < 0 || byteOffset > len(b.data) {
		return errLZXTruncated
	}
	b.origin = byteOffset
	b.offset = 0
	return nil
}

func (b *lzxBits) readByte() (byte, error) {
	position, err := b.bytePosition()
	if err != nil {
		return 0, err
	}
	if position < 0 || position >= len(b.data) {
		return 0, errLZXTruncated
	}
	b.offset += 8
	return b.data[position], nil
}

func (b *lzxBits) readUint32LE() (uint32, error) {
	position, err := b.bytePosition()
	if err != nil {
		return 0, err
	}
	if position < 0 || position+4 > len(b.data) {
		return 0, errLZXTruncated
	}
	value := uint32(b.data[position]) | uint32(b.data[position+1])<<8 |
		uint32(b.data[position+2])<<16 | uint32(b.data[position+3])<<24
	b.offset += 32
	return value, nil
}

func (b *lzxBits) copyBytes(out []byte) error {
	position, err := b.bytePosition()
	if err != nil {
		return err
	}
	if position < 0 || position+len(out) > len(b.data) {
		return errLZXTruncated
	}
	copy(out, b.data[position:position+len(out)])
	b.offset += len(out) * 8
	return nil
}

func (b *lzxBits) finishBits() error {
	segment := len(b.data) - b.origin
	if segment%2 != 0 {
		return lzxInvalid("an LZX bit stream has an odd number of bytes")
	}
	total := segment * 8
	if b.offset > total {
		return errLZXTruncated
	}
	leftover := total - b.offset
	if leftover > 15 {
		return lzxInvalid("an LZX bit stream has whole words left after its output")
	}
	if leftover > 0 {
		within := b.offset % 16
		word, err := b.word(b.offset / 16)
		if err != nil {
			return err
		}
		mask := uint16(1)<<uint(16-within) - 1
		if word&mask != 0 {
			return lzxInvalid("unused LZX bits are not zero")
		}
	}
	return nil
}

func (b *lzxBits) finishBytes() error {
	position, err := b.bytePosition()
	if err != nil {
		return err
	}
	if position != len(b.data) {
		return lzxInvalid("an LZX chunk has bytes left after its declared output")
	}
	return nil
}

type lzxCompleteness int

const (
	lzxTreeFull lzxCompleteness = iota
	lzxTreeFullOrEmpty
)

// lzxHuffman is a canonical Huffman tree read most-significant bit first.
type lzxHuffman struct {
	counts      [lzxNumHuffmanBits + 1]uint16
	firstCode   [lzxNumHuffmanBits + 1]uint32
	firstSymbol [lzxNumHuffmanBits + 1]uint16
	symbols     []uint16
}

func buildLZXHuffman(lengths []byte, completeness lzxCompleteness) (*lzxHuffman, error) {
	tree := &lzxHuffman{}
	for _, length := range lengths {
		if int(length) > lzxNumHuffmanBits {
			return nil, lzxInvalid("a Huffman code is longer than 16 bits")
		}
		tree.counts[length]++
	}
	tree.counts[0] = 0

	left := int64(1)
	for _, count := range tree.counts[1:] {
		left = left*2 - int64(count)
		if left < 0 {
			return nil, lzxInvalid("a Huffman tree is over-subscribed")
		}
	}
	empty := true
	for _, count := range tree.counts {
		if count != 0 {
			empty = false
			break
		}
	}
	switch completeness {
	case lzxTreeFull:
		if left != 0 {
			return nil, lzxInvalid("a Huffman tree is incomplete")
		}
	case lzxTreeFullOrEmpty:
		if !empty && left != 0 {
			return nil, lzxInvalid("a Huffman tree is incomplete")
		}
	}

	var code uint32
	var index uint16
	for length := 1; length <= lzxNumHuffmanBits; length++ {
		tree.firstCode[length] = code
		tree.firstSymbol[length] = index
		code = (code + uint32(tree.counts[length])) << 1
		index += tree.counts[length]
	}
	tree.symbols = make([]uint16, 0, len(lengths))
	for length := 1; length <= lzxNumHuffmanBits; length++ {
		for symbol, candidate := range lengths {
			if int(candidate) == length {
				tree.symbols = append(tree.symbols, uint16(symbol))
			}
		}
	}
	return tree, nil
}

func (t *lzxHuffman) decode(bits *lzxBits) (uint16, error) {
	var code uint32
	for length := 1; length <= lzxNumHuffmanBits; length++ {
		bit, err := bits.readBit()
		if err != nil {
			return 0, err
		}
		code = code<<1 | bit
		first := t.firstCode[length]
		count := uint32(t.counts[length])
		if code >= first && code-first < count {
			offset := int(t.firstSymbol[length]) + int(code-first)
			if offset < 0 || offset >= len(t.symbols) {
				return 0, lzxInvalid("a Huffman code names no symbol")
			}
			return t.symbols[offset], nil
		}
	}
	return 0, lzxInvalid("a Huffman code is longer than 16 bits")
}

// lzxDecoder holds the window, pending block state, trees and the E8 state.
type lzxDecoder struct {
	dictBits int
	window   []byte
	position int
	overDict bool
	reps     [lzxNumReps]uint32

	posBase [lzxNumPosSlots]uint32
	extra   [lzxNumPosSlots]uint8

	mainLevels   []byte
	lengthLevels [lzxNumLenSymbols]byte
	main         *lzxHuffman
	lengths      *lzxHuffman
	aligned      *lzxHuffman

	alignThreshold uint32
	blockRemaining uint32
	uncompressed   bool
	skipByte       bool
	started        bool

	wimMode         bool
	translationSize uint32
	translated      uint32
}

func newLZXDecoder(dictBits int, wimMode bool) (*lzxDecoder, error) {
	if dictBits < lzxDictBitsMin || dictBits > lzxDictBitsMax {
		return nil, lzxInvalid("the LZX window is outside 15..=21 bits")
	}
	numPosSlots2 := dictBits
	if dictBits >= 20 {
		numPosSlots2 = 17 + (1 << uint(dictBits-18))
	}
	posBase, extra := lzxPositionTables()
	numPosLenSlots := numPosSlots2 * lzxNumLenSlots * 2
	return &lzxDecoder{
		dictBits:       dictBits,
		window:         make([]byte, 1<<uint(dictBits)),
		reps:           [lzxNumReps]uint32{1, 1, 1},
		posBase:        posBase,
		extra:          extra,
		mainLevels:     make([]byte, 256+numPosLenSlots),
		alignThreshold: math.MaxUint32,
		wimMode:        wimMode,
	}, nil
}

func (d *lzxDecoder) decode(input []byte, outputSize int) ([]byte, error) {
	if len(input) == 0 {
		return nil, errLZXTruncated
	}
	if outputSize <= 0 {
		return nil, lzxInvalid("an LZX chunk with no output")
	}
	if !d.started || d.wimMode {
		d.position = 0
		d.overDict = false
		d.reps = [lzxNumReps]uint32{1, 1, 1}
		d.blockRemaining = 0
		d.uncompressed = false
		d.skipByte = false
		d.aligned = nil
		d.alignThreshold = math.MaxUint32
		d.main = nil
		d.lengths = nil
		for index := range d.mainLevels {
			d.mainLevels[index] = 0
		}
		d.lengthLevels = [lzxNumLenSymbols]byte{}
		d.translated = 0
		if d.wimMode {
			d.translationSize = lzxWIMTranslationSize
		} else {
			d.translationSize = 0
		}
	} else if d.position == len(d.window) {
		d.position = 0
		d.overDict = true
	}
	if outputSize > len(d.window)-d.position {
		return nil, lzxLimit(fmt.Sprintf(
			"an LZX chunk of %d bytes does not fit in the %d byte window at offset %d",
			outputSize, len(d.window), d.position))
	}

	start := d.position
	bits := newLZXBits(input)
	byteMode := d.started && !d.wimMode && d.uncompressed

	if !d.started {
		d.started = true
		if !d.wimMode {
			flag, err := bits.readBit()
			if err != nil {
				return nil, err
			}
			if flag != 0 {
				high, err := bits.read(16)
				if err != nil {
					return nil, err
				}
				low, err := bits.read(16)
				if err != nil {
					return nil, err
				}
				d.translationSize = high<<16 | low
			} else {
				d.translationSize = 0
			}
		}
		d.reps = [lzxNumReps]uint32{1, 1, 1}
	}

	produced := 0
	for produced < outputSize {
		if d.blockRemaining == 0 {
			if d.skipByte {
				if !byteMode {
					return nil, lzxInvalid("the padding byte of an uncompressed block is in bit mode")
				}
				value, err := bits.readByte()
				if err != nil {
					return nil, err
				}
				if value != 0 {
					return nil, lzxInvalid("the padding byte of an uncompressed block is not zero")
				}
				d.skipByte = false
			}
			if d.uncompressed {
				byteOffset, err := bits.bytePosition()
				if err != nil {
					return nil, err
				}
				if err := bits.rebase(byteOffset); err != nil {
					return nil, err
				}
				byteMode = false
			}
			if err := d.readTables(bits, &byteMode); err != nil {
				return nil, err
			}
			continue
		}

		want := int(d.blockRemaining)
		if remaining := outputSize - produced; remaining < want {
			want = remaining
		}
		if d.uncompressed {
			if !byteMode {
				return nil, lzxInvalid("uncompressed LZX data outside byte mode")
			}
			if d.position+want > len(d.window) {
				return nil, errLZXTruncated
			}
			if err := bits.copyBytes(d.window[d.position : d.position+want]); err != nil {
				return nil, err
			}
			d.position += want
		} else {
			if byteMode {
				return nil, lzxInvalid("compressed LZX data inside byte mode")
			}
			if err := d.decodeMatches(bits, want); err != nil {
				return nil, err
			}
		}
		d.blockRemaining -= uint32(want)
		produced += want
	}

	if d.uncompressed && d.blockRemaining == 0 && d.skipByte && byteMode {
		remaining, err := bits.remainingBytes()
		if err != nil {
			return nil, err
		}
		if remaining == 1 {
			value, err := bits.readByte()
			if err != nil {
				return nil, err
			}
			if value != 0 {
				return nil, lzxInvalid("the padding byte of an uncompressed block is not zero")
			}
			d.skipByte = false
		}
	}
	if byteMode {
		if err := bits.finishBytes(); err != nil {
			return nil, err
		}
	} else if err := bits.finishBits(); err != nil {
		return nil, err
	}

	output := append([]byte(nil), d.window[start:start+produced]...)
	d.translate(output)
	return output, nil
}

func (d *lzxDecoder) readTables(bits *lzxBits, byteMode *bool) error {
	if *byteMode {
		return lzxInvalid("an LZX block header inside byte mode")
	}
	blockType, err := bits.read(3)
	if err != nil {
		return err
	}
	if blockType < lzxBlockVerbatim || blockType > lzxBlockUncompressed {
		return lzxInvalid("an LZX block type is reserved")
	}
	size, err := d.readBlockSize(bits)
	if err != nil {
		return err
	}
	if size == 0 {
		return lzxInvalid("an LZX block declares no output")
	}
	d.uncompressed = blockType == lzxBlockUncompressed
	d.skipByte = false
	d.blockRemaining = size

	if d.uncompressed {
		d.skipByte = size&1 != 0
		if err := bits.alignWord(); err != nil {
			return err
		}
		remaining, err := bits.remainingBytes()
		if err != nil {
			return err
		}
		if remaining < lzxNumReps*4 {
			return errLZXTruncated
		}
		var reps [lzxNumReps]uint32
		for index := range reps {
			value, err := bits.readUint32LE()
			if err != nil {
				return err
			}
			if value == 0 || int(value) > len(d.window)-lzxNumReps {
				return lzxInvalid("an uncompressed LZX distance is invalid")
			}
			reps[index] = value
		}
		d.reps = reps
		*byteMode = true
		return nil
	}

	d.alignThreshold = math.MaxUint32
	d.aligned = nil
	if blockType == lzxBlockAligned {
		var lengths [lzxAlignTableSize]byte
		allThree := true
		for index := range lengths {
			value, err := bits.read(3)
			if err != nil {
				return err
			}
			lengths[index] = byte(value)
			if value != 3 {
				allThree = false
			}
		}
		if !allThree {
			tree, err := buildLZXHuffman(lengths[:], lzxTreeFull)
			if err != nil {
				return err
			}
			d.aligned = tree
			d.alignThreshold = lzxAlignThreshold
		}
	}

	if err := readLZXLevels(bits, d.mainLevels[:256]); err != nil {
		return err
	}
	if err := readLZXLevels(bits, d.mainLevels[256:]); err != nil {
		return err
	}
	main, err := buildLZXHuffman(d.mainLevels, lzxTreeFull)
	if err != nil {
		return err
	}
	d.main = main

	if err := readLZXLevels(bits, d.lengthLevels[:]); err != nil {
		return err
	}
	lengths, err := buildLZXHuffman(d.lengthLevels[:], lzxTreeFullOrEmpty)
	if err != nil {
		return err
	}
	d.lengths = lengths
	return nil
}

func (d *lzxDecoder) readBlockSize(bits *lzxBits) (uint32, error) {
	if !d.wimMode {
		high, err := bits.read(16)
		if err != nil {
			return 0, err
		}
		low, err := bits.read(8)
		if err != nil {
			return 0, err
		}
		return high<<8 | low, nil
	}
	flag, err := bits.readBit()
	if err != nil {
		return 0, err
	}
	if flag != 0 {
		return 1 << 15, nil
	}
	low, err := bits.read(16)
	if err != nil {
		return 0, err
	}
	if d.dictBits >= 16 {
		high, err := bits.read(8)
		if err != nil {
			return 0, err
		}
		return low<<8 | high, nil
	}
	return low, nil
}

func (d *lzxDecoder) decodeMatches(bits *lzxBits, count int) error {
	if d.main == nil {
		return lzxInvalid("no main tree for a compressed block")
	}
	end := d.position + count
	for d.position < end {
		symbol, err := d.main.decode(bits)
		if err != nil {
			return err
		}
		if symbol < 256 {
			if d.position >= len(d.window) {
				return errLZXTruncated
			}
			d.window[d.position] = byte(symbol)
			d.position++
			continue
		}
		index := int(symbol) - 256
		slot := index / lzxNumLenSlots
		if slot >= lzxNumPosSlots {
			return lzxInvalid("an LZX match slot is out of range")
		}
		length := index%lzxNumLenSlots + lzxMatchMinLen
		if length == lzxNumLenSlots-1+lzxMatchMinLen {
			if d.lengths == nil {
				return lzxInvalid("no length tree for a long match")
			}
			extended, err := d.lengths.decode(bits)
			if err != nil {
				return err
			}
			length = int(extended) + lzxNumLenSlots - 1 + lzxMatchMinLen
		}
		distance, err := d.readDistance(bits, slot)
		if err != nil {
			return err
		}
		if distance == 0 || int(distance) > len(d.window) {
			return lzxInvalid("an LZX match distance is outside the window")
		}
		if length > end-d.position {
			return lzxInvalid("an LZX match runs past the end of its block")
		}
		if !d.overDict && int(distance) > d.position {
			return lzxInvalid("an LZX match reaches behind the start of the window")
		}
		d.copyMatch(int(distance), length)
	}
	return nil
}

func (d *lzxDecoder) readDistance(bits *lzxBits, slot int) (uint32, error) {
	if slot < lzxNumReps {
		distance := d.reps[slot]
		if slot != 0 {
			d.reps[slot] = d.reps[0]
		}
		d.reps[0] = distance
		return distance, nil
	}
	d.reps[2] = d.reps[1]
	d.reps[1] = d.reps[0]
	base := d.posBase[slot]
	aligned := d.alignThreshold != math.MaxUint32 && base >= d.alignThreshold
	direct := int(d.extra[slot])
	if aligned {
		direct -= 3
	}
	if direct < 0 {
		return 0, lzxInvalid("an aligned distance has too few extra bits")
	}
	value, err := bits.read(direct)
	if err != nil {
		return 0, err
	}
	var distance uint32
	if aligned {
		if d.aligned == nil {
			return 0, lzxInvalid("an aligned distance has no aligned tree")
		}
		low, err := d.aligned.decode(bits)
		if err != nil {
			return 0, err
		}
		distance = base + value<<3 + uint32(low)
	} else {
		distance = base + value
	}
	d.reps[0] = distance
	return distance, nil
}

func (d *lzxDecoder) copyMatch(distance, length int) {
	windowLen := len(d.window)
	source := (d.position + windowLen - distance) % windowLen
	target := d.position
	for index := 0; index < length; index++ {
		byteValue := d.window[source]
		d.window[target] = byteValue
		source = (source + 1) % windowLen
		target++
	}
	d.position = target
}

func (d *lzxDecoder) translate(data []byte) {
	if d.translationSize == 0 {
		d.translated += uint32(len(data))
		return
	}
	translation := d.translationSize
	index := 0
	for index+11 <= len(data) {
		if data[index] != 0xE8 {
			index++
			continue
		}
		raw := uint32(data[index+1]) | uint32(data[index+2])<<8 |
			uint32(data[index+3])<<16 | uint32(data[index+4])<<24
		current := d.translated + uint32(index)
		position := ^current
		value := raw
		if raw < translation {
			value = raw - current
		} else if raw > position {
			value = raw + translation
		}
		data[index+1] = byte(value)
		data[index+2] = byte(value >> 8)
		data[index+3] = byte(value >> 16)
		data[index+4] = byte(value >> 24)
		index += 5
	}
	d.translated += uint32(len(data))
	if d.translated >= 1<<30 {
		d.translationSize = 0
	}
}

// lzxPositionTables returns the position-slot base distances and extra-bit
// counts.
func lzxPositionTables() ([lzxNumPosSlots]uint32, [lzxNumPosSlots]uint8) {
	var base [lzxNumPosSlots]uint32
	var extra [lzxNumPosSlots]uint8
	var value uint32
	delta := uint32(1)
	for index := uint32(0); index < 17; index++ {
		base[2+index*2] = value
		extra[2+index*2] = uint8(index)
		value += delta
		base[3+index*2] = value
		extra[3+index*2] = uint8(index)
		value += delta
		delta *= 2
	}
	for slot := 36; slot < lzxNumPosSlots; slot++ {
		base[slot] = value
		extra[slot] = 17
		value += 1 << 17
	}
	return base, extra
}

// readLZXLevels reads one pretree-coded run of code lengths. Each length is
// delta-coded against the value the same slot held in the previous block, so
// out is state, not scratch space.
func readLZXLevels(bits *lzxBits, out []byte) error {
	var lengths [lzxNumLevelTable]byte
	for index := range lengths {
		value, err := bits.read(4)
		if err != nil {
			return err
		}
		lengths[index] = byte(value)
	}
	tree, err := buildLZXHuffman(lengths[:], lzxTreeFull)
	if err != nil {
		return err
	}
	index := 0
	for index < len(out) {
		symbol, err := tree.decode(bits)
		if err != nil {
			return err
		}
		switch {
		case symbol <= lzxNumHuffmanBits:
			delta := int(out[index]) - int(symbol)
			if delta < 0 {
				delta += lzxNumHuffmanBits + 1
			}
			out[index] = byte(delta)
			index++
		case symbol == lzxLevelZero1 || symbol == lzxLevelZero2:
			extraBits, minimum := 4, 4
			if symbol == lzxLevelZero2 {
				extraBits, minimum = 5, 20
			}
			value, err := bits.read(extraBits)
			if err != nil {
				return err
			}
			run := int(value) + minimum
			if index+run > len(out) {
				return lzxInvalid("a zero run overruns the code lengths")
			}
			for at := index; at < index+run; at++ {
				out[at] = 0
			}
			index += run
		case symbol == lzxLevelSame:
			value, err := bits.read(1)
			if err != nil {
				return err
			}
			run := int(value) + 4
			deltaSymbol, err := tree.decode(bits)
			if err != nil {
				return err
			}
			if deltaSymbol > lzxNumHuffmanBits {
				return lzxInvalid("a repeat run names no code length")
			}
			delta := int(out[index]) - int(deltaSymbol)
			if delta < 0 {
				delta += lzxNumHuffmanBits + 1
			}
			level := byte(delta)
			if index+run > len(out) {
				return lzxInvalid("a repeat run overruns the code lengths")
			}
			for at := index; at < index+run; at++ {
				out[at] = level
			}
			index += run
		default:
			return lzxInvalid("a level symbol is out of range")
		}
	}
	return nil
}
