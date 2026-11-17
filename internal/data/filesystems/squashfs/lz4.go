package squashfs

// Raw LZ4 block decompression.
//
// SquashFS stores each LZ4 block as one bare LZ4 block (no frame header, no
// stored size). The block format carries no length of its own, so the caller's
// bound is the block size and the real decoded length is whatever the final
// sequence produces; the file reader then compares it against the logical
// block length, exactly as the Rust reference does with lz4_flex.
//
// Attribution: this decoder is copied from
// internal/data/containers/lz4/block.go in this repository (a pure-Go
// implementation of the same block format). That package's decoder is
// unexported and the package must not be edited, so the small routine is
// duplicated here; the LZ4 frame code does not apply to SquashFS.

import "fmt"

// lz4MinMatch is the shortest match the LZ4 block format encodes; the low
// nibble of a token stores the match length minus this bias.
const lz4MinMatch = 4

// decodeLZ4Block decodes one raw LZ4 block that must fit in maxBlock bytes.
func decodeLZ4Block(input []byte, maxBlock uint64) ([]byte, error) {
	// Start with a conservative hint capped at the caller's bound.
	hint := uint64(len(input))*3 + 64
	if hint > maxBlock {
		hint = maxBlock
	}
	out := make([]byte, 0, int(hint))

	offset := 0
	for {
		if offset >= len(input) {
			return nil, fmt.Errorf("truncated: missing token")
		}
		token := input[offset]
		offset++

		literalLen := int(token >> 4)
		if literalLen == 15 {
			extra, next, err := lz4ExtendedLength(input, offset)
			if err != nil {
				return nil, err
			}
			literalLen += extra
			offset = next
		}
		if uint64(len(out))+uint64(literalLen) > maxBlock {
			return nil, fmt.Errorf("output exceeds the %d-byte block maximum", maxBlock)
		}
		if literalLen > 0 {
			if literalLen > len(input)-offset {
				return nil, fmt.Errorf("truncated: %d literal bytes requested, %d remain",
					literalLen, len(input)-offset)
			}
			out = append(out, input[offset:offset+literalLen]...)
			offset += literalLen
		}

		// The last sequence of a block contains only literals.
		if offset == len(input) {
			break
		}

		if len(input)-offset < 2 {
			return nil, fmt.Errorf("truncated: match offset")
		}
		matchOffset := int(input[offset]) | int(input[offset+1])<<8
		offset += 2
		if matchOffset == 0 {
			return nil, fmt.Errorf("invalid: zero match offset")
		}
		if matchOffset > len(out) {
			return nil, fmt.Errorf("invalid: match offset %d exceeds %d bytes of history",
				matchOffset, len(out))
		}

		matchLen := int(token & 0x0F)
		if matchLen == 15 {
			extra, next, err := lz4ExtendedLength(input, offset)
			if err != nil {
				return nil, err
			}
			matchLen += extra
			offset = next
		}
		matchLen += lz4MinMatch
		if uint64(len(out))+uint64(matchLen) > maxBlock {
			return nil, fmt.Errorf("output exceeds the %d-byte block maximum", maxBlock)
		}

		src := len(out) - matchOffset
		// Append one byte at a time: matches may overlap themselves, which is
		// how LZ4 encodes runs.
		for i := 0; i < matchLen; i++ {
			out = append(out, out[src+i])
		}
	}
	return out, nil
}

// lz4ExtendedLength accumulates the 255-terminated extension bytes used when a
// length nibble is saturated. The bound keeps a malformed run from growing an
// unbounded integer before the output check runs.
func lz4ExtendedLength(input []byte, offset int) (int, int, error) {
	total := 0
	for {
		if offset >= len(input) {
			return 0, offset, fmt.Errorf("truncated: extended length")
		}
		b := input[offset]
		offset++
		total += int(b)
		if b != 255 {
			return total, offset, nil
		}
		if total > 1<<26 {
			return 0, offset, fmt.Errorf("invalid: extended length is too large")
		}
	}
}
