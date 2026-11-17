package unlock

// RIPEMD-160 (Dobbertin, Bosselaers, Preneel), the fourth PBKDF2 hash
// cryptsetup accepts for LUKS2 key slots and digests. The Go standard library
// has SHA-1, SHA-256 and SHA-512 but no RIPEMD-160, and this package takes no
// external dependencies, so the compression function lives here.
//
// It implements hash.Hash so it can be handed to the same PBKDF2 loop as the
// standard-library hashes. The test vectors in pbkdf2_test.go pin it to the
// published digests.

import "hash"

type ripemd160Digest struct {
	h   [5]uint32
	x   [64]byte
	nx  int
	len uint64
}

var _ hash.Hash = (*ripemd160Digest)(nil)

func newRIPEMD160() hash.Hash {
	return &ripemd160Digest{h: [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}}
}

func (d *ripemd160Digest) Reset() {
	d.h = [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	d.x = [64]byte{}
	d.nx = 0
	d.len = 0
}

func (d *ripemd160Digest) Size() int      { return 20 }
func (d *ripemd160Digest) BlockSize() int { return 64 }

func (d *ripemd160Digest) Write(p []byte) (int, error) {
	written := len(p)
	d.len += uint64(written)
	if d.nx > 0 {
		take := len(d.x) - d.nx
		if take > len(p) {
			take = len(p)
		}
		copy(d.x[d.nx:], p[:take])
		d.nx += take
		p = p[take:]
		if d.nx == len(d.x) {
			ripemd160Block(d, d.x[:])
			d.nx = 0
		}
	}
	for len(p) >= 64 {
		ripemd160Block(d, p[:64])
		p = p[64:]
	}
	if len(p) > 0 {
		copy(d.x[:], p)
		d.nx = len(p)
	}
	return written, nil
}

func (d *ripemd160Digest) Sum(in []byte) []byte {
	copied := *d
	length := copied.len
	var padding [72]byte
	padding[0] = 0x80
	padLen := 56 - int(length%64)
	if padLen <= 0 {
		padLen += 64
	}
	for index := 1; index < padLen; index++ {
		padding[index] = 0
	}
	bits := length << 3
	for index := 0; index < 8; index++ {
		padding[padLen+index] = byte(bits >> (8 * index))
	}
	_, _ = copied.Write(padding[:padLen+8])
	var out [20]byte
	for index, word := range copied.h {
		out[index*4] = byte(word)
		out[index*4+1] = byte(word >> 8)
		out[index*4+2] = byte(word >> 16)
		out[index*4+3] = byte(word >> 24)
	}
	return append(in, out[:]...)
}

var (
	ripemdR1 = [80]uint8{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
	}
	ripemdR2 = [80]uint8{
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
	}
	ripemdS1 = [80]uint8{
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
	}
	ripemdS2 = [80]uint8{
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
	}
)

func ripemd160Block(d *ripemd160Digest, block []byte) {
	var x [16]uint32
	for index := range x {
		base := index * 4
		x[index] = uint32(block[base]) | uint32(block[base+1])<<8 |
			uint32(block[base+2])<<16 | uint32(block[base+3])<<24
	}
	al, bl, cl, dl, el := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4]
	ar, br, cr, dr, er := al, bl, cl, dl, el
	for round := 0; round < 80; round++ {
		left := rotateLeft32(al+ripemdF(round, bl, cl, dl)+x[ripemdR1[round]]+ripemdK(round), uint(ripemdS1[round])) + el
		al, el, dl, cl, bl = el, dl, rotateLeft32(cl, 10), bl, left
		right := rotateLeft32(ar+ripemdF(79-round, br, cr, dr)+x[ripemdR2[round]]+ripemdKPrime(round), uint(ripemdS2[round])) + er
		ar, er, dr, cr, br = er, dr, rotateLeft32(cr, 10), br, right
	}
	t := d.h[1] + cl + dr
	d.h[1] = d.h[2] + dl + er
	d.h[2] = d.h[3] + el + ar
	d.h[3] = d.h[4] + al + br
	d.h[4] = d.h[0] + bl + cr
	d.h[0] = t
}

func ripemdF(round int, x, y, z uint32) uint32 {
	switch {
	case round < 16:
		return x ^ y ^ z
	case round < 32:
		return (x & y) | (^x & z)
	case round < 48:
		return (x | ^y) ^ z
	case round < 64:
		return (x & z) | (y & ^z)
	default:
		return x ^ (y | ^z)
	}
}

func ripemdK(round int) uint32 {
	switch {
	case round < 16:
		return 0x00000000
	case round < 32:
		return 0x5a827999
	case round < 48:
		return 0x6ed9eba1
	case round < 64:
		return 0x8f1bbcdc
	default:
		return 0xa953fd4e
	}
}

func ripemdKPrime(round int) uint32 {
	switch {
	case round < 16:
		return 0x50a28be6
	case round < 32:
		return 0x5c4dd124
	case round < 48:
		return 0x6d703ef3
	case round < 64:
		return 0x7a6d76e9
	default:
		return 0x00000000
	}
}

func rotateLeft32(value uint32, bits uint) uint32 {
	return value<<bits | value>>(32-bits)
}
