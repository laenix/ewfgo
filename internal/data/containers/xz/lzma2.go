package xz

// LZMA2 and the LZMA range decoder used inside it.
//
// This file is a from-scratch, pure-Go implementation of the LZMA2 chunk
// layer and the LZMA symbol decoder it carries. It follows the algorithms in
// the public-domain xz-embedded decoder (Lasse Collin / Igor Pavlov), but the
// dictionary is the decoded output itself rather than a separately allocated
// ring buffer: .xz blocks reset the LZMA2 dictionary, and every distance is
// validated against both the bytes produced since that reset and the declared
// dictionary size.

import "fmt"

const (
	// rcTopValue is the range-decoder normalization threshold.
	rcTopValue uint32 = 1 << 24
	// rcBitModelTotal is the total of the 11-bit probability model.
	rcBitModelTotal uint32 = 1 << 11
	// rcMoveBits is the adaptation rate of the probability model.
	rcMoveBits uint32 = 5

	// posStatesMax is the maximum number of position states (pb <= 4).
	posStatesMax = 1 << 4
	// literalCoderSize is the size of one literal probability tree.
	literalCoderSize = 0x300
	// literalCodersMax bounds the literal-context index.
	literalCodersMax = 1 << 4

	matchLenMin = 2

	lenLowBits     = 3
	lenLowSymbols  = 1 << lenLowBits
	lenMidBits     = 3
	lenMidSymbols  = 1 << lenMidBits
	lenHighBits    = 8
	lenHighSymbols = 1 << lenHighBits

	distStates     = 4
	distSlotBits   = 6
	distSlots      = 1 << distSlotBits
	distModelStart = 4
	distModelEnd   = 14
	// fullDistances is the number of distances encoded with probability
	// trees; the reference table has one unused slot at index zero.
	fullDistances = 1 << (distModelEnd / 2)
	alignBits     = 4
	alignSize     = 1 << alignBits

	// lzma2MaxUncompressed is the largest LZMA chunk (21-bit size field).
	lzma2MaxUncompressed = 2 * 1024 * 1024
	// lzma2MaxUncompressedChunk is the largest uncompressed chunk (16-bit).
	lzma2MaxUncompressedChunk = 64 * 1024
)

// rangeDecoder decodes the LZMA range-coded bit stream. It reads from a
// bounded slice; reading past the end marks the decoder as failed instead of
// panicking. The caller discards all output when err is set.
type rangeDecoder struct {
	data []byte
	pos  int
	rnge uint32
	code uint32
	err  bool
}

// newRangeDecoder consumes the five-byte range-coder initialisation. The first
// byte is the carry byte and is discarded by the 32-bit shifts.
func newRangeDecoder(data []byte) (*rangeDecoder, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("range-coded chunk is %d bytes, need at least 5", len(data))
	}
	rc := &rangeDecoder{data: data, rnge: ^uint32(0)}
	for i := 0; i < 5; i++ {
		rc.code = rc.code<<8 | uint32(data[i])
	}
	rc.pos = 5
	return rc, nil
}

func (rc *rangeDecoder) normalize() {
	if rc.rnge >= rcTopValue {
		return
	}
	if rc.pos >= len(rc.data) {
		rc.err = true
		return
	}
	rc.rnge <<= 8
	rc.code = rc.code<<8 | uint32(rc.data[rc.pos])
	rc.pos++
}

// bit decodes one probability-coded bit.
func (rc *rangeDecoder) bit(prob *uint16) uint32 {
	rc.normalize()
	bound := (rc.rnge >> 11) * uint32(*prob)
	if rc.code < bound {
		rc.rnge = bound
		*prob += uint16((rcBitModelTotal - uint32(*prob)) >> rcMoveBits)
		return 0
	}
	rc.rnge -= bound
	rc.code -= bound
	*prob -= uint16(uint32(*prob) >> rcMoveBits)
	return 1
}

// direct decodes count direct (equiprobable) bits, most significant first.
func (rc *rangeDecoder) direct(count uint32) uint32 {
	var value uint32
	for i := uint32(0); i < count; i++ {
		rc.normalize()
		rc.rnge >>= 1
		var bit uint32
		if rc.code >= rc.rnge {
			rc.code -= rc.rnge
			bit = 1
		}
		value = value<<1 | bit
	}
	return value
}

// bitTree decodes a most-significant-bit-first binary tree.
func bitTree(rc *rangeDecoder, probs []uint16, bits uint32) uint32 {
	symbol := uint32(1)
	for i := uint32(0); i < bits; i++ {
		symbol = symbol<<1 | rc.bit(&probs[symbol])
	}
	return symbol - (1 << bits)
}

// bitTreeReverse decodes a least-significant-bit-first binary tree. probs must
// have room for indexes 1..(1<<bits)-1, matching the reference layout.
func bitTreeReverse(rc *rangeDecoder, probs []uint16, bits uint32) uint32 {
	symbol := uint32(1)
	var value uint32
	for i := uint32(0); i < bits; i++ {
		bit := rc.bit(&probs[symbol])
		symbol = symbol<<1 | bit
		value |= bit << i
	}
	return value
}

// lenDecoder is the shared match-length probability model.
type lenDecoder struct {
	choice  uint16
	choice2 uint16
	low     [posStatesMax][lenLowSymbols]uint16
	mid     [posStatesMax][lenMidSymbols]uint16
	high    [lenHighSymbols]uint16
}

// lzmaDecoder holds the LZMA state machine and probability model.
type lzmaDecoder struct {
	lc uint32
	lp uint32
	pb uint32

	posMask        uint32
	literalPosMask uint32

	state uint32
	reps  [4]uint32

	isMatch    [12][posStatesMax]uint16
	isRep      [12]uint16
	isRep0     [12]uint16
	isRep1     [12]uint16
	isRep2     [12]uint16
	isRep0Long [12][posStatesMax]uint16

	distSlot [distStates][distSlots]uint16
	// distSpecial has the reference layout: index zero is unused.
	distSpecial [fullDistances - distModelEnd + 1]uint16
	distAlign   [alignSize]uint16

	matchLen lenDecoder
	repLen   lenDecoder

	literal [literalCodersMax][literalCoderSize]uint16

	rc *rangeDecoder
}

// setProps decodes the five-bit-plus property byte and resets the model.
func (d *lzmaDecoder) setProps(prop byte) bool {
	if prop > (4*5+4)*9+8 {
		return false
	}
	p := uint32(prop)
	lc := p % 9
	p /= 9
	lp := p % 5
	pb := p / 5
	if pb > 4 || lc+lp > 4 {
		return false
	}
	d.lc = lc
	d.lp = lp
	d.pb = pb
	d.posMask = (1 << pb) - 1
	d.literalPosMask = (1 << lp) - 1
	d.reset()
	return true
}

// reset clears the state machine, repeat distances and probabilities.
func (d *lzmaDecoder) reset() {
	d.state = 0
	d.reps = [4]uint32{}
	const initial = uint16(rcBitModelTotal / 2)
	for i := range d.isMatch {
		for j := range d.isMatch[i] {
			d.isMatch[i][j] = initial
		}
	}
	for i := 0; i < 12; i++ {
		d.isRep[i] = initial
		d.isRep0[i] = initial
		d.isRep1[i] = initial
		d.isRep2[i] = initial
		for j := 0; j < posStatesMax; j++ {
			d.isRep0Long[i][j] = initial
		}
	}
	for i := range d.distSlot {
		for j := range d.distSlot[i] {
			d.distSlot[i][j] = initial
		}
	}
	for i := range d.distSpecial {
		d.distSpecial[i] = initial
	}
	for i := range d.distAlign {
		d.distAlign[i] = initial
	}
	d.matchLen = lenDecoder{}
	d.repLen = lenDecoder{}
	d.matchLen.choice = initial
	d.matchLen.choice2 = initial
	d.repLen.choice = initial
	d.repLen.choice2 = initial
	for i := range d.matchLen.low {
		for j := range d.matchLen.low[i] {
			d.matchLen.low[i][j] = initial
		}
	}
	for i := range d.matchLen.mid {
		for j := range d.matchLen.mid[i] {
			d.matchLen.mid[i][j] = initial
		}
	}
	for i := range d.matchLen.high {
		d.matchLen.high[i] = initial
	}
	for i := range d.repLen.low {
		for j := range d.repLen.low[i] {
			d.repLen.low[i][j] = initial
		}
	}
	for i := range d.repLen.mid {
		for j := range d.repLen.mid[i] {
			d.repLen.mid[i][j] = initial
		}
	}
	for i := range d.repLen.high {
		d.repLen.high[i] = initial
	}
	for i := range d.literal {
		for j := range d.literal[i] {
			d.literal[i][j] = initial
		}
	}
}

func lenToPosState(length int) uint32 {
	if length < distStates+matchLenMin {
		return uint32(length - matchLenMin)
	}
	return distStates - 1
}

// decodeLen decodes a match length (already including the minimum).
func (d *lzmaDecoder) decodeLen(l *lenDecoder, posState uint32) int {
	if d.rc.bit(&l.choice) == 0 {
		return int(bitTree(d.rc, l.low[posState][:], lenLowBits)) + matchLenMin
	}
	if d.rc.bit(&l.choice2) == 0 {
		return int(bitTree(d.rc, l.mid[posState][:], lenMidBits)) + matchLenMin + lenLowSymbols
	}
	return int(bitTree(d.rc, l.high[:], lenHighBits)) + matchLenMin + lenLowSymbols + lenMidSymbols
}

func (d *lzmaDecoder) setLiteralState() {
	switch {
	case d.state < 4:
		d.state = 0
	case d.state < 10:
		d.state -= 3
	default:
		d.state -= 6
	}
}

func (d *lzmaDecoder) setMatchState() {
	if d.state < 7 {
		d.state = 7
	} else {
		d.state = 10
	}
}

func (d *lzmaDecoder) setLongRepState() {
	if d.state < 7 {
		d.state = 8
	} else {
		d.state = 11
	}
}

func (d *lzmaDecoder) setShortRepState() {
	if d.state < 7 {
		d.state = 9
	} else {
		d.state = 11
	}
}

// decodeLiteral decodes one literal byte and appends it to out.
func (d *lzmaDecoder) decodeLiteral(out *[]byte, dictStart int) {
	posRel := uint32(len(*out) - dictStart)
	var prevByte byte
	if posRel > 0 {
		prevByte = (*out)[len(*out)-1]
	}
	context := uint32(prevByte)>>(8-d.lc) | (posRel&d.literalPosMask)<<d.lc
	probs := d.literal[context][:]

	var symbol uint32
	if d.state < 7 {
		symbol = 1
		for i := 0; i < 8; i++ {
			symbol = symbol<<1 | d.rc.bit(&probs[symbol])
		}
	} else {
		var matchByte byte
		if d.reps[0] < posRel {
			matchByte = (*out)[len(*out)-1-int(d.reps[0])]
		}
		symbol = 1
		for i := 7; i >= 0; i-- {
			matchBit := uint32(matchByte>>uint(i)) & 1
			bit := d.rc.bit(&probs[((1+matchBit)<<8)+symbol])
			symbol = symbol<<1 | bit
			if matchBit != bit {
				for ; i > 0; i-- {
					symbol = symbol<<1 | d.rc.bit(&probs[symbol])
				}
				break
			}
		}
	}
	*out = append(*out, byte(symbol))
	d.setLiteralState()
}

// decodeMatch decodes a new match: its length and distance.
func (d *lzmaDecoder) decodeMatch(posState uint32) (int, uint32) {
	d.setMatchState()
	d.reps[3], d.reps[2], d.reps[1] = d.reps[2], d.reps[1], d.reps[0]

	length := d.decodeLen(&d.matchLen, posState)
	slot := bitTree(d.rc, d.distSlot[lenToPosState(length)][:], distSlotBits)

	var dist uint32
	if slot < distModelStart {
		dist = slot
	} else {
		bits := (slot >> 1) - 1
		dist = (2 | (slot & 1)) << bits
		if slot < distModelEnd {
			dist += bitTreeReverse(d.rc, d.distSpecial[dist-slot:], bits)
		} else {
			dist += d.rc.direct(bits-alignBits) << alignBits
			dist += bitTreeReverse(d.rc, d.distAlign[:], alignBits)
		}
	}
	d.reps[0] = dist
	return length, dist
}

// decodeRepMatch decodes a repeated match. A short repeat yields length 1.
func (d *lzmaDecoder) decodeRepMatch(posState uint32) (int, uint32) {
	if d.rc.bit(&d.isRep0[d.state]) == 0 {
		if d.rc.bit(&d.isRep0Long[d.state][posState]) == 0 {
			d.setShortRepState()
			return 1, d.reps[0]
		}
	} else {
		var tmp uint32
		if d.rc.bit(&d.isRep1[d.state]) == 0 {
			tmp = d.reps[1]
		} else {
			if d.rc.bit(&d.isRep2[d.state]) == 0 {
				tmp = d.reps[2]
			} else {
				tmp = d.reps[3]
				d.reps[3] = d.reps[2]
			}
			d.reps[2] = d.reps[1]
		}
		d.reps[1] = d.reps[0]
		d.reps[0] = tmp
	}
	d.setLongRepState()
	return d.decodeLen(&d.repLen, posState), d.reps[0]
}

// decodeChunk decodes exactly target bytes of one LZMA chunk from data.
func (d *lzmaDecoder) decodeChunk(data []byte, out *[]byte, dictStart int, dictSize uint32, target int) error {
	rc, err := newRangeDecoder(data)
	if err != nil {
		return fmt.Errorf("LZMA2: %v", err)
	}
	d.rc = rc

	start := len(*out)
	for len(*out)-start < target {
		posRel := uint32(len(*out) - dictStart)
		posState := posRel & d.posMask
		if d.rc.bit(&d.isMatch[d.state][posState]) == 0 {
			d.decodeLiteral(out, dictStart)
			continue
		}

		var length int
		var dist uint32
		if d.rc.bit(&d.isRep[d.state]) != 0 {
			length, dist = d.decodeRepMatch(posState)
		} else {
			length, dist = d.decodeMatch(posState)
		}

		if length > target-(len(*out)-start) {
			return fmt.Errorf("LZMA2 match of %d bytes crosses the %d-byte chunk boundary", length, target)
		}
		if err := copyMatch(out, dist, length, dictStart, dictSize); err != nil {
			return err
		}
	}

	// The reference decoder normalizes once after the last symbol; a valid
	// chunk then has consumed every compressed byte and left code at zero.
	d.rc.normalize()
	if d.rc.err {
		return fmt.Errorf("LZMA2 range-coded data is truncated")
	}
	if d.rc.pos != len(data) {
		return fmt.Errorf("LZMA2 chunk has %d unused compressed bytes", len(data)-d.rc.pos)
	}
	if d.rc.code != 0 {
		return fmt.Errorf("LZMA2 range coder did not finish cleanly (code %#x)", d.rc.code)
	}
	return nil
}

// copyMatch appends length bytes copied from dist bytes back. Distances are
// validated against the bytes since the dictionary reset and the declared
// dictionary size.
func copyMatch(out *[]byte, dist uint32, length int, dictStart int, dictSize uint32) error {
	available := len(*out) - dictStart
	if uint64(dist) >= uint64(available) || uint64(dist) >= uint64(dictSize) {
		return fmt.Errorf("LZMA2 match distance %d exceeds %d bytes of dictionary", dist, available)
	}
	src := len(*out) - int(dist) - 1
	// Capacity was reserved for the whole chunk; appending one byte at a time
	// also handles overlaps correctly.
	for i := 0; i < length; i++ {
		*out = append(*out, (*out)[src+i])
	}
	return nil
}

// lzma2DictSize decodes the one-byte LZMA2 dictionary-size property. The
// property is validated (<= 40) by the block-header parser.
func lzma2DictSize(prop byte) uint32 {
	if prop >= 40 {
		return ^uint32(0)
	}
	return (2 | uint32(prop&1)) << (uint32(prop)>>1 + 11)
}

// decodeLZMA2 decodes one LZMA2 chunk stream from data, stopping after the
// end marker. It returns the number of stored bytes consumed and the number
// of bytes produced. declaredUncompressed, when known, must match.
func decodeLZMA2(data []byte, dictSize uint32, maxDecoded uint64, out *[]byte, baseOffset uint64, declaredUncompressed uint64, hasDeclared bool) (int, uint64, error) {
	blockStart := len(*out)
	needDictReset := true
	needProps := true
	dictStart := blockStart
	pos := 0

	var dec lzmaDecoder

	for {
		if pos >= len(data) {
			return 0, 0, corruptAt(baseOffset+uint64(pos), "xz LZMA2 stream is missing its end marker")
		}
		control := data[pos]
		controlAt := pos
		pos++

		if control == 0x00 {
			produced := uint64(len(*out) - blockStart)
			if hasDeclared && produced != declaredUncompressed {
				return 0, 0, corruptAt(baseOffset+uint64(controlAt),
					"xz block declared %d uncompressed bytes but LZMA2 produced %d", declaredUncompressed, produced)
			}
			return pos, produced, nil
		}

		switch {
		case control == 0x01 || control >= 0xE0:
			// An uncompressed chunk with a dictionary reset, or an LZMA
			// chunk whose reset bits include the dictionary.
			needDictReset = false
			needProps = true
			dictStart = len(*out)
		case needDictReset:
			return 0, 0, corruptAt(baseOffset+uint64(controlAt), "xz LZMA2 stream does not start with a dictionary reset")
		}

		if control < 0x80 {
			if control > 0x02 {
				return 0, 0, corruptAt(baseOffset+uint64(controlAt), "invalid LZMA2 control byte %#02x", control)
			}
			if pos+2 > len(data) {
				return 0, 0, corruptAt(baseOffset+uint64(pos), "xz LZMA2 uncompressed chunk header is truncated")
			}
			size := int(data[pos])<<8 | int(data[pos+1]) + 1
			pos += 2
			if size > lzma2MaxUncompressedChunk {
				return 0, 0, corruptAt(baseOffset+uint64(controlAt), "LZMA2 uncompressed chunk declares %d bytes", size)
			}
			if pos+size > len(data) {
				return 0, 0, corruptAt(baseOffset+uint64(pos), "xz LZMA2 uncompressed chunk is truncated")
			}
			if err := ensureCapacity(out, size, maxDecoded); err != nil {
				return 0, 0, err
			}
			*out = append(*out, data[pos:pos+size]...)
			pos += size
			continue
		}

		// LZMA chunk.
		if pos+2 > len(data) {
			return 0, 0, corruptAt(baseOffset+uint64(pos), "xz LZMA2 chunk header is truncated")
		}
		uncompressed := int(control&0x1F)<<16 | int(data[pos])<<8 | int(data[pos+1]) + 1
		pos += 2
		if pos+2 > len(data) {
			return 0, 0, corruptAt(baseOffset+uint64(pos), "xz LZMA2 chunk header is truncated")
		}
		compressed := int(data[pos])<<8 | int(data[pos+1]) + 1
		pos += 2

		switch {
		case control >= 0xC0:
			// New properties; setProps also resets the state and model.
			if pos >= len(data) {
				return 0, 0, corruptAt(baseOffset+uint64(pos), "xz LZMA2 chunk properties are truncated")
			}
			prop := data[pos]
			pos++
			if !dec.setProps(prop) {
				return 0, 0, corruptAt(baseOffset+uint64(pos-1), "invalid LZMA properties byte %#02x", prop)
			}
			needProps = false
		case control >= 0xA0:
			if needProps {
				return 0, 0, corruptAt(baseOffset+uint64(controlAt), "LZMA2 chunk uses the state without properties")
			}
			dec.reset()
		default:
			if needProps {
				return 0, 0, corruptAt(baseOffset+uint64(controlAt), "LZMA2 chunk uses the state without properties")
			}
		}

		if compressed < 5 {
			return 0, 0, corruptAt(baseOffset+uint64(controlAt), "LZMA2 chunk compressed size %d is too small", compressed)
		}
		if uncompressed > lzma2MaxUncompressed {
			return 0, 0, corruptAt(baseOffset+uint64(controlAt), "LZMA2 chunk uncompressed size %d is too large", uncompressed)
		}
		if pos+compressed > len(data) {
			return 0, 0, corruptAt(baseOffset+uint64(pos), "xz LZMA2 chunk data is truncated")
		}
		if err := ensureCapacity(out, uncompressed, maxDecoded); err != nil {
			return 0, 0, err
		}
		chunk := data[pos : pos+compressed]
		if err := dec.decodeChunk(chunk, out, dictStart, dictSize, uncompressed); err != nil {
			return 0, 0, corruptAt(baseOffset+uint64(controlAt), "%v", err)
		}
		pos += compressed
	}
}

// ensureCapacity reserves room for add more bytes, enforcing the output limit
// before any allocation. It never allocates more than maxDecoded.
func ensureCapacity(out *[]byte, add int, maxDecoded uint64) error {
	needed := uint64(len(*out)) + uint64(add)
	if needed > maxDecoded {
		return unsupported("decompressed xz output exceeds the %d-byte limit", maxDecoded)
	}
	if cap(*out) >= int(needed) {
		return nil
	}
	newCap := cap(*out) * 2
	if newCap < int(needed) {
		newCap = int(needed)
	}
	if uint64(newCap) > maxDecoded {
		newCap = int(maxDecoded)
	}
	if newCap < int(needed) {
		newCap = int(needed)
	}
	next := make([]byte, len(*out), newCap)
	copy(next, *out)
	*out = next
	return nil
}
