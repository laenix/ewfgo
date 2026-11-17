package squashfs

// LZO1X decompression.
//
// SquashFS stores each LZO block as one raw LZO1X stream (no container header
// or stored output size), exactly what liblzo2's lzo1x_1 family produces. This
// file is a direct port of the safe reference decoder, lzo1x_decompress_safe,
// with the same instruction set and the same refusal rules the Rust
// forensic-core reference gets from the pure-Rust `lzo` crate: the stream must
// end with the canonical end-of-stream marker, it must not leave a stored byte
// unread, and every length and back-reference is bounds-checked so a malformed
// block can neither read out of bounds nor allocate past the caller's bound.
//
// Attribution: the instruction decode below follows liblzo2's
// lzo1x_decompress_safe.c (the canonical public description of the LZO1X
// format). Back-references copy byte by byte, because a distance shorter than
// the match length deliberately repeats the bytes just written.

import "errors"

var (
	errLZOInputOverrun     = errors.New("compressed input ended prematurely")
	errLZOOutputOverrun    = errors.New("decoded output exceeds the block bound")
	errLZOLookbehind       = errors.New("a back-reference reaches before the output start")
	errLZOInputNotConsumed = errors.New("trailing bytes after the end-of-stream marker")
	errLZOMalformed        = errors.New("malformed compressed block")
)

// lzoM2MaxOffset is the distance bias that separates the M1 short-match form
// that follows a literal run from the ordinary M1 form.
const lzoM2MaxOffset = 0x0800

type lzoDecoder struct {
	src []byte
	dst []byte
	ip  int
	op  int
}

// decodeLZO1X decodes one raw LZO1X block, writing at most limit bytes. It
// returns an explicit error rather than any partial output.
func decodeLZO1X(input []byte, limit int) ([]byte, error) {
	if limit < 0 {
		return nil, corruptf("an lzo block has a %d-byte output bound", limit)
	}
	if len(input) < 3 {
		return nil, corruptf("an lzo block is %d bytes, shorter than its three-byte end marker", len(input))
	}
	d := &lzoDecoder{src: input, dst: make([]byte, limit)}
	written, err := d.run()
	if err != nil {
		return nil, corruptf("an lzo block did not decode: %v", err)
	}
	return d.dst[:written], nil
}

// run decodes the instruction stream and returns the decoded length.
func (d *lzoDecoder) run() (int, error) {
	state := 0
	// A first byte above 17 is an initial literal run of first-17 bytes. A run
	// shorter than four bytes behaves like the trailing literals of a prior
	// match, so the decoder enters the ordinary instruction loop in that state.
	if first := d.src[0]; first > 17 {
		d.ip = 1
		t := int(first) - 17
		if err := d.copyLiterals(t); err != nil {
			return 0, err
		}
		if t < 4 {
			state = t
		} else {
			state = 4
		}
	}

	for {
		token, err := d.readByte()
		if err != nil {
			return 0, err
		}
		t := int(token)
		var distance, length, next int

		switch {
		case t < 16:
			if state == 0 {
				// A literal run: length t+3, with the zero-byte extension
				// (base 18) when t is zero.
				n := t + 3
				if t == 0 {
					extra, err := d.lengthExtension()
					if err != nil {
						return 0, err
					}
					n = extra + 18
				}
				if err := d.copyLiterals(n); err != nil {
					return 0, err
				}
				state = 4
				continue
			}
			// A short match from a near distance. state 4 means the match
			// follows a literal run (three bytes at a distance biased by
			// lzoM2MaxOffset); any other state means it follows another match
			// (two bytes).
			next = t & 3
			b, err := d.readByte()
			if err != nil {
				return 0, err
			}
			if state == 4 {
				distance = 1 + lzoM2MaxOffset + (t >> 2) + (int(b) << 2)
				length = 3
			} else {
				distance = 1 + (t >> 2) + (int(b) << 2)
				length = 2
			}
		case t >= 64:
			// M2: short match, three distance bits in the token plus one byte.
			next = t & 3
			b, err := d.readByte()
			if err != nil {
				return 0, err
			}
			distance = 1 + ((t >> 2) & 7) + (int(b) << 3)
			length = (t >> 5) + 1
		case t >= 32:
			// M3: length in the low five bits (base 2, extension base 33),
			// then a little-endian distance.
			if (t & 31) == 0 {
				extra, err := d.lengthExtension()
				if err != nil {
					return 0, err
				}
				length = extra + 33
			} else {
				length = (t & 31) + 2
			}
			dist, err := d.readLE16()
			if err != nil {
				return 0, err
			}
			distance = 1 + (dist >> 2)
			next = dist & 3
		default:
			// M4 (16..=31): long match, or the end-of-stream marker.
			high := (t & 8) << 11
			if (t & 7) == 0 {
				extra, err := d.lengthExtension()
				if err != nil {
					return 0, err
				}
				length = extra + 9
			} else {
				length = (t & 7) + 2
			}
			dist, err := d.readLE16()
			if err != nil {
				return 0, err
			}
			distancePart := dist >> 2
			next = dist & 3
			if high == 0 && distancePart == 0 {
				// The canonical end-of-stream marker is 0x11 0x00 0x00.
				if length != 3 {
					return 0, errLZOMalformed
				}
				if d.ip != len(d.src) {
					return 0, errLZOInputNotConsumed
				}
				return d.op, nil
			}
			distance = high + distancePart + 0x4000
		}

		if err := d.copyMatch(distance, length); err != nil {
			return 0, err
		}
		if err := d.copyLiterals(next); err != nil {
			return 0, err
		}
		state = next
	}
}

// readByte reads one stored byte, or reports a truncated block.
func (d *lzoDecoder) readByte() (byte, error) {
	if d.ip >= len(d.src) {
		return 0, errLZOInputOverrun
	}
	b := d.src[d.ip]
	d.ip++
	return b, nil
}

// readLE16 reads the little-endian 16-bit distance field.
func (d *lzoDecoder) readLE16() (int, error) {
	lo, err := d.readByte()
	if err != nil {
		return 0, err
	}
	hi, err := d.readByte()
	if err != nil {
		return 0, err
	}
	return int(lo) | int(hi)<<8, nil
}

// lengthExtension reads the zero-byte length extension used when a length
// field saturates: every 0x00 byte is worth 255, then one terminator byte. The
// running total is checked against the output bound as it grows, so a crafted
// run cannot overflow the integer before the capacity check runs.
func (d *lzoDecoder) lengthExtension() (int, error) {
	total := 0
	for {
		b, err := d.readByte()
		if err != nil {
			return 0, err
		}
		if total > len(d.dst) {
			return 0, errLZOOutputOverrun
		}
		if b != 0 {
			total += int(b)
			break
		}
		total += 255
	}
	return total, nil
}

// copyLiterals copies n stored bytes to the output. The output bound is
// checked before the input bound, matching the reference decoder's refusal
// order.
func (d *lzoDecoder) copyLiterals(n int) error {
	if n < 0 || n > len(d.dst)-d.op {
		return errLZOOutputOverrun
	}
	if n > len(d.src)-d.ip {
		return errLZOInputOverrun
	}
	copy(d.dst[d.op:d.op+n], d.src[d.ip:d.ip+n])
	d.op += n
	d.ip += n
	return nil
}

// copyMatch copies length bytes from distance behind the output cursor,
// byte-by-byte so an overlapping match repeats correctly.
func (d *lzoDecoder) copyMatch(distance, length int) error {
	if distance <= 0 || distance > d.op {
		return errLZOLookbehind
	}
	if length < 0 || length > len(d.dst)-d.op {
		return errLZOOutputOverrun
	}
	src := d.op - distance
	for i := 0; i < length; i++ {
		d.dst[d.op+i] = d.dst[src+i]
	}
	d.op += length
	return nil
}
