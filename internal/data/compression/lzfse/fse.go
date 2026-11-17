package lzfse

import "math/bits"

// LZFSE entropy-coding constants. They come from Apple's liblzfse and are
// fixed by the format: symbol counts, state counts, value ranges and the
// payload-size bounds derived from them.
const (
	lStates = 64
	mStates = 64
	dStates = 256
	uStates = 1024

	lSymbols = 20
	mSymbols = 20
	dSymbols = 64
	uSymbols = 256
	nWeights = lSymbols + mSymbols + dSymbols + uSymbols

	maxLValue = 315
	maxMValue = 2359
	maxDValue = 262139

	lmdsPerBlock     = 10000
	literalsPerBlock = 4 * lmdsPerBlock

	maxLMDbits = 14 + 17 + 23

	v1HeaderSize = 50
	v2HeaderSize = 32
	// v1 stores 360 little-endian uint16 weights plus two padding bytes.
	v1WeightBytes = nWeights*2 + 2 // 722
	// v2 packs each weight in at most 14 bits.
	v2MaxWeightBytes = (nWeights*14 + 7) / 8 // 630

	// Table offsets inside the combined L/M/D state space.
	lOffset = 0
	mOffset = lStates
	dOffset = lStates + mStates
)

var (
	lExtraBits = [lSymbols]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8}
	lBaseValue = [lSymbols]uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60}

	mExtraBits = [mSymbols]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11}
	mBaseValue = [mSymbols]uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312}

	dExtraBits = [dSymbols]uint8{
		0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
		4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
		8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
		12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
	}
	dBaseValue = [dSymbols]uint32{
		0, 1, 2, 3, 4, 6, 8, 10, 12, 16,
		20, 24, 28, 36, 44, 52, 60, 76, 92, 108,
		124, 156, 188, 220, 252, 316, 380, 444, 508, 636,
		764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580,
		4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
		24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684,
		131068, 163836, 196604, 229372,
	}

	// Huffman-style coding of the frequency-table weights (v2 headers).
	weightBitsTable = [32]uint8{
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
	}
	weightValueTable = [32]int16{
		0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
		0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
	}
)

// weightSet holds one normalized frequency table per symbol class.
type weightSet struct {
	l [lSymbols]uint16
	m [mSymbols]uint16
	d [dSymbols]uint16
	u [uSymbols]uint16
}

// blockHeader is the parsed, validated header of a bvx1/bvx2 block.
type blockHeader struct {
	nRaw       uint32
	litNum     uint32
	litPayload uint32
	litBits    uint32
	litStates  [4]uint16
	lmdNum     uint32
	lmdPayload uint32
	lmdBits    uint32
	lmdStates  [3]uint16
	headerSize int
	weights    weightSet
}

// parseCompressedHeader parses the block at the start of src (base is the
// stream offset for error reporting) and validates every bound before the
// payload is touched.
func parseCompressedHeader(src []byte, base int, v1 bool) (*blockHeader, error) {
	h := &blockHeader{}
	if v1 {
		if len(src) < v1HeaderSize {
			return nil, eofAt(base, "truncated v1 block header")
		}
		h.nRaw = readU32(src, 4)
		declaredPayload := readU32(src, 8)
		h.litNum = readU32(src, 12)
		h.lmdNum = readU32(src, 16)
		h.litPayload = readU32(src, 20)
		h.lmdPayload = readU32(src, 24)
		h.litBits = 0 - readU32(src, 28)
		for i := range h.litStates {
			h.litStates[i] = readU16(src, 32+i*2)
		}
		h.lmdBits = 0 - readU32(src, 40)
		for i := range h.lmdStates {
			h.lmdStates[i] = readU16(src, 44+i*2)
		}
		// Unlike v2, the v1 header size field does not cover the raw weight
		// table; the full prefix is header + 722 weight bytes.
		h.headerSize = v1HeaderSize + v1WeightBytes
		if uint64(declaredPayload) < uint64(h.litPayload)+uint64(h.lmdPayload) {
			return nil, corruptAt(base+8, "v1 header declares %d payload bytes, fewer than its %d + %d streams",
				declaredPayload, h.litPayload, h.lmdPayload)
		}
	} else {
		if len(src) < v2HeaderSize {
			return nil, eofAt(base, "truncated v2 block header")
		}
		h.nRaw = readU32(src, 4)
		p1 := readU64(src, 8)
		p2 := readU64(src, 16)
		p3 := readU64(src, 24)
		h.litNum = uint32(p1 & 0xFFFFF)
		h.litPayload = uint32((p1 >> 20) & 0xFFFFF)
		h.lmdNum = uint32((p1 >> 40) & 0xFFFFF)
		h.litBits = 7 - uint32((p1>>60)&7)
		h.litStates[0] = uint16(p2 & 0x3FF)
		h.litStates[1] = uint16((p2 >> 10) & 0x3FF)
		h.litStates[2] = uint16((p2 >> 20) & 0x3FF)
		h.litStates[3] = uint16((p2 >> 30) & 0x3FF)
		h.lmdPayload = uint32((p2 >> 40) & 0xFFFFF)
		h.lmdBits = 7 - uint32((p2>>60)&7)
		headerSize := p3 & 0xFFFFFFFF
		h.lmdStates[0] = uint16((p3 >> 32) & 0x3FF)
		h.lmdStates[1] = uint16((p3 >> 42) & 0x3FF)
		h.lmdStates[2] = uint16((p3 >> 52) & 0x3FF)
		if headerSize < v2HeaderSize || headerSize > v2HeaderSize+v2MaxWeightBytes {
			return nil, corruptAt(base, "v2 header size %d is outside [%d, %d]",
				headerSize, v2HeaderSize, v2HeaderSize+v2MaxWeightBytes)
		}
		h.headerSize = int(headerSize)
	}

	if err := h.validate(base); err != nil {
		return nil, err
	}

	// The whole block must be present. This also guarantees the eight bytes
	// of lookahead borrowed by the literal bit reader are inside the stream.
	total := uint64(h.headerSize) + uint64(h.litPayload) + uint64(h.lmdPayload)
	if total > uint64(len(src)) {
		return nil, eofAt(base+len(src), "block needs %d bytes, only %d remain", total, len(src))
	}

	var err error
	if v1 {
		h.weights, err = loadWeightsV1(src[v1HeaderSize:h.headerSize], base+v1HeaderSize)
	} else {
		h.weights, err = loadWeightsV2(src[v2HeaderSize:h.headerSize], base+v2HeaderSize)
	}
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (h *blockHeader) validate(base int) error {
	if h.litNum%4 != 0 || h.litNum > literalsPerBlock {
		return corruptAt(base, "literal count %d is not a multiple of four in range", h.litNum)
	}
	if h.lmdNum > lmdsPerBlock {
		return corruptAt(base, "LMD count %d exceeds %d", h.lmdNum, lmdsPerBlock)
	}
	if h.litBits > 7 {
		return corruptAt(base, "literal bit padding %d exceeds seven", h.litBits)
	}
	if h.lmdBits > 7 {
		return corruptAt(base, "LMD bit padding %d exceeds seven", h.lmdBits)
	}
	for _, s := range h.litStates {
		if s >= uStates {
			return corruptAt(base, "literal state %d exceeds the %d-state table", s, uStates)
		}
	}
	if h.lmdStates[0] >= lStates || h.lmdStates[1] >= mStates || h.lmdStates[2] >= dStates {
		return corruptAt(base, "LMD state (%d,%d,%d) exceeds its table",
			h.lmdStates[0], h.lmdStates[1], h.lmdStates[2])
	}
	if maxLiteralPayload(h.litNum) < h.litPayload {
		return corruptAt(base, "literal payload %d exceeds the %d byte bound for %d literals",
			h.litPayload, maxLiteralPayload(h.litNum), h.litNum)
	}
	if h.lmdPayload < 8 {
		return corruptAt(base, "LMD payload %d is shorter than its eight byte pad", h.lmdPayload)
	}
	if maxLMDPayload(h.lmdNum) < h.lmdPayload {
		return corruptAt(base, "LMD payload %d exceeds the %d byte bound for %d LMDs",
			h.lmdPayload, maxLMDPayload(h.lmdNum), h.lmdNum)
	}
	if uint64(h.nRaw) > uint64(h.litNum)+uint64(h.lmdNum)*maxMValue {
		return corruptAt(base, "raw size %d exceeds the %d bytes its symbols can produce",
			h.nRaw, uint64(h.litNum)+uint64(h.lmdNum)*maxMValue)
	}
	return nil
}

func maxLiteralPayload(num uint32) uint32 {
	return 1024 + (num*10+7)/8
}

func maxLMDPayload(num uint32) uint32 {
	return 1024 + 8 + (num*maxLMDbits+7)/8
}

// loadWeightsV1 reads 360 little-endian uint16 weights.
func loadWeightsV1(src []byte, base int) (weightSet, error) {
	var w weightSet
	if len(src) < v1WeightBytes {
		return w, eofAt(base, "truncated v1 weight payload: %d bytes", len(src))
	}
	all := make([]uint16, 0, nWeights) // small and short-lived
	for i := 0; i < nWeights; i++ {
		all = append(all, readU16(src, i*2))
	}
	distribute(&w, all)
	if err := checkWeightTotals(&w, base); err != nil {
		return weightSet{}, err
	}
	return w, nil
}

// loadWeightsV2 unpacks the Huffman-coded weight payload. The packing is
// LSB-first with a 24-bit refill window; every input byte must be consumed and
// at most seven bits of padding may remain.
func loadWeightsV2(src []byte, base int) (weightSet, error) {
	var w weightSet
	all := make([]uint16, nWeights)
	var accum uint64
	accumBits := 0
	i := 0
	for n := range all {
		for i != len(src) && accumBits <= 24 {
			accum |= uint64(src[i]) << uint(accumBits)
			accumBits += 8
			i++
		}
		value, used, ok := decodeWeight(accum)
		if !ok {
			return weightSet{}, corruptAt(base+i, "invalid weight code")
		}
		all[n] = value
		accum >>= used
		accumBits -= int(used)
		if accumBits < 0 {
			return weightSet{}, eofAt(base+len(src), "weight payload ends inside a code")
		}
	}
	if accumBits >= 8 || i != len(src) {
		return weightSet{}, corruptAt(base+len(src), "weight payload has %d unconsumed bytes and %d leftover bits",
			len(src)-i, accumBits)
	}
	distribute(&w, all)
	if err := checkWeightTotals(&w, base); err != nil {
		return weightSet{}, err
	}
	return w, nil
}

// decodeWeight decodes one weight code from the low bits of u. It returns the
// value, the number of bits consumed and whether the code is valid.
func decodeWeight(u uint64) (uint16, uint32, bool) {
	index := u & 0x1F
	n := weightBitsTable[index]
	var value uint64
	switch n {
	case 8:
		value = 8 + ((u >> 4) & 0xF)
	case 14:
		value = 24 + ((u >> 4) & 0x3FF)
	default:
		v := weightValueTable[index]
		if v < 0 {
			return 0, 0, false
		}
		value = uint64(v)
	}
	return uint16(value), uint32(n), true
}

func distribute(w *weightSet, all []uint16) {
	copy(w.l[:], all[0:lSymbols])
	copy(w.m[:], all[lSymbols:lSymbols+mSymbols])
	copy(w.d[:], all[lSymbols+mSymbols:lSymbols+mSymbols+dSymbols])
	copy(w.u[:], all[lSymbols+mSymbols+dSymbols:nWeights])
}

func checkWeightTotals(w *weightSet, base int) error {
	if sum16(w.l[:]) > lStates || sum16(w.m[:]) > mStates ||
		sum16(w.d[:]) > dStates || sum16(w.u[:]) > uStates {
		return corruptAt(base, "normalized weight tables exceed their state counts")
	}
	return nil
}

func sum16(v []uint16) int {
	total := 0
	for _, x := range v {
		total += int(x)
	}
	return total
}

type vEntry struct {
	k     uint8
	vBits uint8
	delta int16
	vBase uint32
}

type uEntry struct {
	k      uint8
	symbol uint8
	delta  int16
}

type tables struct {
	v [lStates + mStates + dStates]vEntry
	u [uStates]uEntry
}

func buildTables(w *weightSet) *tables {
	t := &tables{}
	buildVTable(w.l[:], lExtraBits[:], lBaseValue[:], lOffset, t.v[lOffset:lOffset+lStates])
	buildVTable(w.m[:], mExtraBits[:], mBaseValue[:], mOffset, t.v[mOffset:mOffset+mStates])
	buildVTable(w.d[:], dExtraBits[:], dBaseValue[:], dOffset, t.v[dOffset:dOffset+dStates])
	buildUTable(w.u[:], t.u[:])
	return t
}

// buildVTable constructs the canonical FSE decoding table for one value
// symbol class. Weight totals were validated to fit in len(table).
func buildVTable(weights []uint16, extra []uint8, baseValue []uint32, offset int, table []vEntry) {
	nStates := uint32(len(table))
	nClz := uint32(bits.LeadingZeros32(nStates))
	total := 0
	for i, w16 := range weights {
		w := uint32(w16)
		if w == 0 {
			continue
		}
		k := uint32(bits.LeadingZeros32(w)) - nClz
		x := ((nStates << 1) >> k) - w
		e := vEntry{k: uint8(k), vBits: extra[i], vBase: baseValue[i]}
		for j := uint32(0); j < x; j++ {
			e.delta = int16(int32((w+j)<<k) - int32(nStates) + int32(offset))
			table[total+int(j)] = e
		}
		if k > 0 {
			e.k = uint8(k - 1)
			for j := x; j < w; j++ {
				e.delta = int16(int32((j-x)<<(k-1)) + int32(offset))
				table[total+int(j)] = e
			}
		}
		total += int(w)
	}
	// Unused states latch in place, so a stream that reaches one fails the
	// final-state check instead of reading outside the table.
	for i := total; i < len(table); i++ {
		table[i] = vEntry{delta: int16(offset + i)}
	}
}

func buildUTable(weights []uint16, table []uEntry) {
	nStates := uint32(len(table))
	nClz := uint32(bits.LeadingZeros32(nStates))
	total := 0
	for i, w16 := range weights {
		w := uint32(w16)
		if w == 0 {
			continue
		}
		k := uint32(bits.LeadingZeros32(w)) - nClz
		x := ((nStates << 1) >> k) - w
		e := uEntry{k: uint8(k), symbol: uint8(i)}
		for j := uint32(0); j < x; j++ {
			e.delta = int16(int32((w+j)<<k) - int32(nStates))
			table[total+int(j)] = e
		}
		if k > 0 {
			e.k = uint8(k - 1)
			for j := x; j < w; j++ {
				e.delta = int16(int32(j-x) << (k - 1))
				table[total+int(j)] = e
			}
		}
		total += int(w)
	}
	for i := total; i < len(table); i++ {
		table[i] = uEntry{delta: int16(i)}
	}
}

func (e vEntry) decode(br *bitReader, state *int) uint32 {
	next := br.pull(int(e.k))
	*state = int(next) + int(e.delta)
	low := br.pull(int(e.vBits))
	return e.vBase + low
}

func (e uEntry) decode(br *bitReader, state *int) byte {
	next := br.pull(int(e.k))
	*state = int(next) + int(e.delta)
	return e.symbol
}

// decodeLiterals decodes the literal FSE stream into litNum bytes (rounded up
// to a multiple of four, as the stream encodes four interleaved states).
func decodeLiterals(data []byte, h *blockHeader, t *tables, base int) ([]byte, error) {
	br, err := newBitReader(data, int(h.litBits), base)
	if err != nil {
		return nil, err
	}
	var state [4]int
	for i := range state {
		state[i] = int(h.litStates[i])
	}
	out := make([]byte, h.litNum)
	for i := 0; i < len(out); i += 4 {
		out[i] = t.u[state[0]].decode(br, &state[0])
		out[i+1] = t.u[state[1]].decode(br, &state[1])
		out[i+2] = t.u[state[2]].decode(br, &state[2])
		out[i+3] = t.u[state[3]].decode(br, &state[3])
		br.flush()
	}
	if err := br.finalize(); err != nil {
		return nil, err
	}
	if state != [4]int{} {
		return nil, corruptAt(base, "literal states did not return to zero")
	}
	return out, nil
}

// lmd is one decoded literal-length / match-length / match-distance triple.
type lmd struct {
	literal uint32
	match   uint32
	dist    uint32 // zero means "reuse the previous non-zero distance"
}

func decodeLMDs(data []byte, h *blockHeader, t *tables, base int) ([]lmd, error) {
	br, err := newBitReader(data, int(h.lmdBits), base)
	if err != nil {
		return nil, err
	}
	lState := int(h.lmdStates[0])
	mState := mOffset + int(h.lmdStates[1])
	dState := dOffset + int(h.lmdStates[2])
	out := make([]lmd, h.lmdNum)
	for i := range out {
		literal := t.v[lState].decode(br, &lState)
		match := t.v[mState].decode(br, &mState)
		dist := t.v[dState].decode(br, &dState)
		br.flush()
		out[i] = lmd{literal: literal, match: match, dist: dist}
	}
	if err := br.finalize(); err != nil {
		return nil, err
	}
	if lState != lOffset || mState != mOffset || dState != dOffset {
		return nil, corruptAt(base, "LMD states did not return to zero")
	}
	return out, nil
}

// apply turns the decoded literals and LMD triples into block bytes, appending
// to d.out. The declared raw length is authoritative: a stream that produces a
// different amount is corrupt, not silently truncated.
func (d *decoder) apply(literals []byte, lmds []lmd, rawLen uint32, blockOffset int) error {
	literalIndex := 0
	produced := uint64(0)
	for i := range lmds {
		entry := &lmds[i]
		if produced+uint64(entry.literal)+uint64(entry.match) > uint64(rawLen) {
			return corruptAt(blockOffset, "LMD entry %d would produce more than the declared %d bytes",
				i, rawLen)
		}
		if int(entry.literal) > len(literals)-literalIndex {
			return corruptAt(blockOffset, "LMD entry %d consumes %d literals, only %d remain",
				i, entry.literal, len(literals)-literalIndex)
		}
		// Literals are emitted before the match they precede, so the match
		// distance is measured against output that already includes them.
		d.out = append(d.out, literals[literalIndex:literalIndex+int(entry.literal)]...)
		literalIndex += int(entry.literal)
		produced += uint64(entry.literal)

		// The zero-distance packing is updated by every entry, including an
		// entry whose match length is zero; a later match may reuse it.
		if entry.dist != 0 {
			d.lastDist = entry.dist
		}
		if entry.match != 0 {
			if d.lastDist == 0 {
				return corruptAt(blockOffset, "LMD entry %d has a match but no previous distance", i)
			}
			if uint64(d.lastDist) > uint64(len(d.out)) {
				return corruptAt(blockOffset, "LMD entry %d match distance %d precedes the %d decoded bytes",
					i, d.lastDist, len(d.out))
			}
			from := len(d.out) - int(d.lastDist)
			for n := uint32(0); n < entry.match; n++ {
				// Byte at a time: matches may overlap the bytes they are
				// producing, which is how LZFSE encodes runs.
				d.out = append(d.out, d.out[from+int(n)])
			}
			produced += uint64(entry.match)
		}
	}
	if produced != uint64(rawLen) {
		return corruptAt(blockOffset, "decoded %d bytes, header declares %d", produced, rawLen)
	}
	if literalIndex > len(literals) {
		return corruptAt(blockOffset, "literal index %d exceeds the %d decoded literals",
			literalIndex, len(literals))
	}
	return nil
}
