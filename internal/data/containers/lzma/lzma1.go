package lzma

// LZMA1 raw stream decoder.
//
// This is a from-scratch, pure-Go implementation of the LZMA1 symbol coder
// used inside the LZMA-alone container. It follows the reference algorithm
// (Igor Pavlov's LZMA SDK, as reimplemented in xz-embedded), but it is
// independent of the xz package: that package keeps its LZMA decoder private
// to LZMA2 chunk decoding and exports no reusable pieces.
//
// Unlike an LZMA2 chunk, an LZMA1-alone stream has no chunk boundaries: one
// probability model and one state machine span the whole payload. The
// dictionary is the output produced so far, bounded by the dictionary size
// stored in the LZMA-alone header. The payload ends when the declared
// uncompressed size is reached (known-size stream) or when an end marker
// (a new match whose distance code is 0xFFFFFFFF) is decoded (unknown-size
// stream).
//
// Every read past the stored data sets the range decoder's error flag; the
// symbol loop checks it after each symbol and turns it into an explicit
// truncation error. Output is never returned to the caller on error.

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
	// literalCodersMax bounds the literal-context index (lc + lp <= 4).
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
	// trees; the reference layout has one unused slot at index zero.
	fullDistances = 1 << (distModelEnd / 2)
	alignBits     = 4
	alignSize     = 1 << alignBits

	// endMarkerDistance is the sentinel distance that marks the end of an
	// unknown-size LZMA1 stream.
	endMarkerDistance uint32 = 0xFFFFFFFF
)

// rangeDecoder decodes the LZMA range-coded bit stream. Reads are bounded by
// the payload slice; running past the end sets err instead of panicking.
type rangeDecoder struct {
	data []byte
	pos  int
	rnge uint32
	code uint32
	err  bool
}

// newRangeDecoder consumes the five-byte range-coder initialisation. The
// first byte is the carry byte and is discarded by the 32-bit shifts.
func newRangeDecoder(data []byte) (*rangeDecoder, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("range-coded payload is %d bytes, need at least 5", len(data))
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

// bitTreeReverse decodes a least-significant-bit-first binary tree. probs
// must have room for indexes 1..(1<<bits)-1, matching the reference layout.
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

// lzmaDecoder holds the LZMA1 state machine and probability model.
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

// decodeProperties splits the one-byte lc/lp/pb property and rejects values
// the format does not define. The property encodes (pb*5 + lp)*9 + lc with
// lc + lp <= 4 and pb <= 4.
func decodeProperties(prop byte) (lc, lp, pb uint32, ok bool) {
	if prop > (4*5+4)*9+8 {
		return 0, 0, 0, false
	}
	p := uint32(prop)
	lc = p % 9
	p /= 9
	lp = p % 5
	pb = p / 5
	if pb > 4 || lc+lp > 4 {
		return 0, 0, 0, false
	}
	return lc, lp, pb, true
}

// validProperties reports whether prop is a defined lc/lp/pb property byte.
func validProperties(prop byte) bool {
	_, _, _, ok := decodeProperties(prop)
	return ok
}

// setProps configures the literal/position contexts and resets the model.
func (d *lzmaDecoder) setProps(prop byte) bool {
	lc, lp, pb, ok := decodeProperties(prop)
	if !ok {
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

// reset clears the state machine, repeat distances and probabilities. An
// LZMA1-alone stream calls this exactly once, before any symbol is decoded.
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
	d.matchLen = lenDecoder{choice: initial, choice2: initial}
	d.repLen = lenDecoder{choice: initial, choice2: initial}
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

// decodeLiteral decodes one literal byte. out holds the whole decoded stream
// so literal contexts and match bytes are indexed from its start.
func (d *lzmaDecoder) decodeLiteral(out *[]byte) {
	posRel := uint32(len(*out))
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
		// Matched literal: use the byte at reps[0] as the match byte. In a
		// valid stream reps[0] always points inside the output produced so
		// far, because every match that sets it was bounds-checked.
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

// decodeMatch decodes a new match: its length and distance (distance - 1).
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

// copyMatch appends length bytes copied from dist+1 bytes back. The distance
// is validated against the bytes already produced and the dictionary size
// declared in the LZMA-alone header.
func copyMatch(out *[]byte, dist uint32, length int, dictSize uint32) error {
	available := len(*out)
	if uint64(dist) >= uint64(available) || uint64(dist) >= uint64(dictSize) {
		return fmt.Errorf("match distance %d exceeds %d bytes of dictionary (dictionary size %d)",
			uint64(dist)+1, available, dictSize)
	}
	src := available - int(dist) - 1
	for i := 0; i < length; i++ {
		*out = append(*out, (*out)[src+i])
	}
	return nil
}

// finishPayload verifies that the range coder consumed the whole payload and
// ended in the clean state a conforming encoder produces. A truncated flush,
// trailing bytes or a nonzero final code are all explicit errors.
func finishPayload(rc *rangeDecoder) error {
	rc.normalize()
	if rc.err {
		return fmt.Errorf("range-coded payload is truncated")
	}
	if rc.pos != len(rc.data) {
		return fmt.Errorf("%d trailing bytes after the range-coded payload", len(rc.data)-rc.pos)
	}
	if rc.code != 0 {
		return fmt.Errorf("range coder did not finish cleanly (code %#x)", rc.code)
	}
	return nil
}
