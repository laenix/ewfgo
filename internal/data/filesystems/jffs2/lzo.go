package jffs2

import "errors"

// This file is a dependency-free LZO1X decoder, ported from the same safe
// decoder contract used by the Rust reference (liblzo2's
// lzo1x_decompress_safe, as exposed by the `lzo` crate). JFFS2 can store a
// node with the LZO compressor; this reader decodes it rather than refusing
// the image.

var (
	errLZOInputOverrun      = errors.New("lzo: compressed input ended prematurely")
	errLZOOutputOverrun     = errors.New("lzo: output buffer too small")
	errLZOLookbehindOverrun = errors.New("lzo: back-reference before output start")
	errLZOInputNotConsumed  = errors.New("lzo: trailing bytes after end-of-stream")
	errLZOMalformed         = errors.New("lzo: malformed compressed block")
)

func lzoReadByte(src []byte, ip *int) (byte, error) {
	if *ip >= len(src) {
		return 0, errLZOInputOverrun
	}
	value := src[*ip]
	*ip++
	return value, nil
}

func lzoReadLE16(src []byte, ip *int) (int, error) {
	low, err := lzoReadByte(src, ip)
	if err != nil {
		return 0, err
	}
	high, err := lzoReadByte(src, ip)
	if err != nil {
		return 0, err
	}
	return int(low) | int(high)<<8, nil
}

func lzoLengthExt(src []byte, ip *int) (int, error) {
	zeros := 0
	for {
		if *ip >= len(src) {
			return 0, errLZOInputOverrun
		}
		if src[*ip] != 0 {
			break
		}
		*ip++
		zeros++
	}
	term, err := lzoReadByte(src, ip)
	if err != nil {
		return 0, err
	}
	return zeros*255 + int(term), nil
}

func lzoCopyLiterals(src []byte, ip *int, dst []byte, op *int, count int) error {
	if count < 0 || count > len(dst)-*op {
		return errLZOOutputOverrun
	}
	if count > len(src)-*ip {
		return errLZOInputOverrun
	}
	copy(dst[*op:*op+count], src[*ip:*ip+count])
	*op += count
	*ip += count
	return nil
}

func lzoCopyMatch(dst []byte, op *int, distance, length int) error {
	if distance == 0 || distance > *op {
		return errLZOLookbehindOverrun
	}
	if length < 0 || length > len(dst)-*op {
		return errLZOOutputOverrun
	}
	start := *op - distance
	for index := 0; index < length; index++ {
		dst[*op+index] = dst[start+index]
	}
	*op += length
	return nil
}

// lzo1xDecompress decodes one raw LZO1X block into dst, returning the number
// of bytes written. dst must be large enough for the whole output; the block
// must end with the canonical end-of-stream marker and consume every input
// byte.
func lzo1xDecompress(src, dst []byte) (int, error) {
	if len(src) < 3 {
		return 0, errLZOInputOverrun
	}
	ip := 0
	op := 0
	state := 0
	if first := int(src[0]); first > 17 {
		ip = 1
		t := first - 17
		if err := lzoCopyLiterals(src, &ip, dst, &op, t); err != nil {
			return 0, err
		}
		if t < 4 {
			state = t
		} else {
			state = 4
		}
	}

	for {
		value, err := lzoReadByte(src, &ip)
		if err != nil {
			return 0, err
		}
		t := int(value)
		var distance, length, next int
		switch {
		case t < 16:
			if state == 0 {
				run := t + 3
				if t == 0 {
					ext, err := lzoLengthExt(src, &ip)
					if err != nil {
						return 0, err
					}
					run = ext + 18
				}
				if err := lzoCopyLiterals(src, &ip, dst, &op, run); err != nil {
					return 0, err
				}
				state = 4
				continue
			}
			next = t & 3
			if state == 4 {
				follow, err := lzoReadByte(src, &ip)
				if err != nil {
					return 0, err
				}
				distance = 1 + 2048 + (t >> 2) + int(follow)<<2
				length = 3
			} else {
				follow, err := lzoReadByte(src, &ip)
				if err != nil {
					return 0, err
				}
				distance = 1 + (t >> 2) + int(follow)<<2
				length = 2
			}
		case t >= 64:
			next = t & 3
			follow, err := lzoReadByte(src, &ip)
			if err != nil {
				return 0, err
			}
			distance = 1 + ((t >> 2) & 7) + int(follow)<<3
			length = (t >> 5) + 1
		case t >= 32:
			if t&31 == 0 {
				ext, err := lzoLengthExt(src, &ip)
				if err != nil {
					return 0, err
				}
				length = ext + 33
			} else {
				length = (t & 31) + 2
			}
			d, err := lzoReadLE16(src, &ip)
			if err != nil {
				return 0, err
			}
			distance = 1 + (d >> 2)
			next = d & 3
		default:
			hi := (t & 8) << 11
			if t&7 == 0 {
				ext, err := lzoLengthExt(src, &ip)
				if err != nil {
					return 0, err
				}
				length = ext + 9
			} else {
				length = (t & 7) + 2
			}
			d, err := lzoReadLE16(src, &ip)
			if err != nil {
				return 0, err
			}
			distPart := d >> 2
			next = d & 3
			if hi == 0 && distPart == 0 {
				if length != 3 {
					return 0, errLZOMalformed
				}
				if ip < len(src) {
					return 0, errLZOInputNotConsumed
				}
				return op, nil
			}
			distance = hi + distPart + 0x4000
		}
		if err := lzoCopyMatch(dst, &op, distance, length); err != nil {
			return 0, err
		}
		if err := lzoCopyLiterals(src, &ip, dst, &op, next); err != nil {
			return 0, err
		}
		state = next
	}
}
