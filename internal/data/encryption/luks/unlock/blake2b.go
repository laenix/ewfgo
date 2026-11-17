package unlock

// BLAKE2b (RFC 7693).
//
// Argon2 hashes its parameter block, its initial state and the final tag with
// BLAKE2b, so a correct Argon2 needs a correct BLAKE2b underneath it. The Go
// standard library does not ship one, and this package is CGO-free with no
// external dependencies, so the 128-byte compression function lives here.

const (
	blake2bMaxOutput   = 64
	blake2bBlockBytes  = 128
	blake2bRounds      = 12
	blake2bSigmaRounds = 10
)

var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
}

var blake2bSigma = [10][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// blake2bDigest is an unkeyed BLAKE2b hasher with a fixed output length.
type blake2bDigest struct {
	h      [8]uint64
	t0     uint64
	t1     uint64
	buffer [blake2bBlockBytes]byte
	filled int
	outlen int
}

// newBlake2b returns a hasher producing outlen bytes, or false when the
// requested length has no definition in RFC 7693.
func newBlake2b(outlen int) (*blake2bDigest, bool) {
	if outlen <= 0 || outlen > blake2bMaxOutput {
		return nil, false
	}
	hasher := &blake2bDigest{h: blake2bIV, outlen: outlen}
	hasher.h[0] ^= 0x01010000 ^ uint64(outlen)
	return hasher, true
}

func (b *blake2bDigest) update(data []byte) {
	if b.filled+len(data) > blake2bBlockBytes {
		take := blake2bBlockBytes - b.filled
		copy(b.buffer[b.filled:], data[:take])
		b.filled = blake2bBlockBytes
		b.increment(uint64(blake2bBlockBytes))
		b.compress(false)
		b.buffer = [blake2bBlockBytes]byte{}
		b.filled = 0
		data = data[take:]
		// Whole blocks pass through; the final block must stay buffered so it
		// can be marked as the last one.
		for len(data) > blake2bBlockBytes {
			copy(b.buffer[:], data[:blake2bBlockBytes])
			b.increment(uint64(blake2bBlockBytes))
			b.compress(false)
			b.buffer = [blake2bBlockBytes]byte{}
			data = data[blake2bBlockBytes:]
		}
	}
	copy(b.buffer[b.filled:], data)
	b.filled += len(data)
}

func (b *blake2bDigest) finalize() []byte {
	b.increment(uint64(b.filled))
	for index := b.filled; index < blake2bBlockBytes; index++ {
		b.buffer[index] = 0
	}
	b.compress(true)
	out := make([]byte, 0, b.outlen)
	for _, word := range b.h {
		out = appendLE64(out, word)
	}
	return out[:b.outlen]
}

func (b *blake2bDigest) increment(bytes uint64) {
	sum := b.t0 + bytes
	if sum < b.t0 {
		b.t1++
	}
	b.t0 = sum
}

func (b *blake2bDigest) compress(last bool) {
	var m [16]uint64
	for index := range m {
		m[index] = le64(b.buffer[index*8 : index*8+8])
	}
	var v [16]uint64
	copy(v[:8], b.h[:])
	copy(v[8:], blake2bIV[:])
	v[12] ^= b.t0
	v[13] ^= b.t1
	if last {
		v[14] = ^v[14]
	}
	for round := 0; round < blake2bRounds; round++ {
		schedule := blake2bSigma[round%blake2bSigmaRounds]
		blake2bG(&v, 0, 4, 8, 12, m[schedule[0]], m[schedule[1]])
		blake2bG(&v, 1, 5, 9, 13, m[schedule[2]], m[schedule[3]])
		blake2bG(&v, 2, 6, 10, 14, m[schedule[4]], m[schedule[5]])
		blake2bG(&v, 3, 7, 11, 15, m[schedule[6]], m[schedule[7]])
		blake2bG(&v, 0, 5, 10, 15, m[schedule[8]], m[schedule[9]])
		blake2bG(&v, 1, 6, 11, 12, m[schedule[10]], m[schedule[11]])
		blake2bG(&v, 2, 7, 8, 13, m[schedule[12]], m[schedule[13]])
		blake2bG(&v, 3, 4, 9, 14, m[schedule[14]], m[schedule[15]])
	}
	for index := 0; index < 8; index++ {
		b.h[index] ^= v[index] ^ v[index+8]
	}
}

func blake2bG(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] = v[a] + v[b] + x
	v[d] = rotateRight64(v[d]^v[a], 32)
	v[c] = v[c] + v[d]
	v[b] = rotateRight64(v[b]^v[c], 24)
	v[a] = v[a] + v[b] + y
	v[d] = rotateRight64(v[d]^v[a], 16)
	v[c] = v[c] + v[d]
	v[b] = rotateRight64(v[b]^v[c], 63)
}

// blake2bHash is the one-shot unkeyed hash.
func blake2bHash(outlen int, data []byte) ([]byte, bool) {
	hasher, ok := newBlake2b(outlen)
	if !ok {
		return nil, false
	}
	hasher.update(data)
	return hasher.finalize(), true
}

func rotateRight64(value uint64, bits uint) uint64 {
	return value>>bits | value<<(64-bits)
}

func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func appendLE64(out []byte, value uint64) []byte {
	return append(out,
		byte(value), byte(value>>8), byte(value>>16), byte(value>>24),
		byte(value>>32), byte(value>>40), byte(value>>48), byte(value>>56))
}
