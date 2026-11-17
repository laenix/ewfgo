package lzfse

// The FSE payloads are encoded backwards: the decoder starts at the end of the
// payload and consumes bits from the most significant bit of the last byte
// down, refilling a 64-bit window in eight-byte steps. The payload is written
// with up to seven zero padding bits in front and at least eight bytes of
// zero lookahead behind the first symbol, so the reader may walk its index
// before the payload start; reads there yield zero.

type bitReader struct {
	data      []byte
	accum     uint64
	accumBits int
	idx       int
	base      int // stream offset for error reporting
	err       error
}

func newBitReader(data []byte, padding int, base int) (*bitReader, error) {
	if len(data) < 8 {
		return nil, corruptAt(base, "FSE bit stream is %d bytes, shorter than its lookahead", len(data))
	}
	if padding < 0 || padding > 7 {
		return nil, corruptAt(base, "FSE bit padding %d is outside [0, 7]", padding)
	}
	r := &bitReader{data: data, idx: len(data) - 8, accumBits: 64 - padding, base: base}
	r.accum = readU64(data, r.idx)
	if padding != 0 && r.accum>>uint(r.accumBits) != 0 {
		return nil, corruptAt(base, "FSE bit stream has non-zero padding")
	}
	return r, nil
}

// pull consumes n bits, returning them in the order they appear in the stream
// (first bit most significant).
func (r *bitReader) pull(n int) uint32 {
	if r.err != nil {
		return 0
	}
	if n < 0 || n > 32 {
		r.err = corruptAt(r.base, "FSE symbol requests %d bits", n)
		return 0
	}
	r.accumBits -= n
	if r.accumBits < 0 {
		r.err = eofAt(r.base, "FSE bit stream exhausted")
		return 0
	}
	if n == 0 {
		return 0
	}
	mask := uint64(1)<<uint(n) - 1
	return uint32((r.accum >> uint(r.accumBits)) & mask)
}

func (r *bitReader) flush() {
	if r.err != nil {
		return
	}
	nBytes := (64 - r.accumBits) / 8
	r.idx -= nBytes
	r.accum = 0
	if r.idx >= 0 {
		r.accum = readU64(r.data, r.idx)
	}
	r.accumBits += nBytes * 8
}

func (r *bitReader) finalize() error {
	if r.err != nil {
		return r.err
	}
	r.flush()
	if r.err != nil {
		return r.err
	}
	if r.accumBits+r.idx*8 < 64 {
		return eofAt(r.base, "FSE bit stream ended before its padding")
	}
	return nil
}
