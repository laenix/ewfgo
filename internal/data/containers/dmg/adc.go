// Apple Data Compression (ADC) for UDIF disk images.
//
// ADC is a byte-oriented LZ77 scheme: a control byte below 0x80 starts a
// literal run of control+1 bytes; a control byte with the high bit set is a
// back-reference of (control & 0x7f) + 3 bytes whose 16-bit big-endian
// distance follows and is biased by one. Every reference must lie inside the
// output produced so far, and the output is capped at the caller's declared
// size, so a damaged run is an error rather than a zero-filled guess.

package dmg

import "fmt"

// adcDecompress decodes one ADC stream, refusing output past limit.
func adcDecompress(stored []byte, limit int) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("ADC output size is negative")
	}
	capacity := limit
	if capacity > len(stored)*4 {
		capacity = len(stored) * 4
	}
	out := make([]byte, 0, capacity)
	pos := 0
	for pos < len(stored) {
		control := stored[pos]
		pos++
		if control&0x80 == 0 {
			length := int(control) + 1
			end := pos + length
			if end < pos || end > len(stored) {
				return nil, fmt.Errorf(
					"a literal run of %d bytes at offset %d passes the stored bytes", length, pos-1)
			}
			if len(out)+length < len(out) || len(out)+length > limit {
				return nil, fmt.Errorf("a literal run passes the declared %d-byte output", limit)
			}
			out = append(out, stored[pos:end]...)
			pos = end
			continue
		}
		if pos+2 > len(stored) {
			return nil, fmt.Errorf(
				"the match at offset %d is missing its 16-bit distance", pos-1)
		}
		distance := (int(stored[pos])<<8 | int(stored[pos+1])) + 1
		pos += 2
		length := int(control&0x7F) + 3
		if distance > len(out) {
			return nil, fmt.Errorf(
				"a match at offset %d refers %d bytes back, past the %d-byte output",
				pos-3, distance, len(out))
		}
		if len(out)+length < len(out) || len(out)+length > limit {
			return nil, fmt.Errorf("a match passes the declared %d-byte output", limit)
		}
		start := len(out) - distance
		for index := 0; index < length; index++ {
			out = append(out, out[start+index])
		}
	}
	return out, nil
}
