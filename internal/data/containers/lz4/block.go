package lz4

import "fmt"

// minMatch is the shortest match the LZ4 block format encodes; the low nibble
// of a token stores the match length minus this bias.
const minMatch = 4

// maxDictionary is the number of history bytes the LZ4 frame format allows a
// dependent block to reference. Match offsets are 16-bit, so 64 KiB suffices.
const maxDictionary = 64 * 1024

// decodeBlock decodes one LZ4 block. dict is the preceding uncompressed
// history for a dependent-block frame (nil for independent blocks); matches
// may reference it. The returned slice contains only the bytes this block
// produced, never the dictionary. maxBlock bounds the block's output, so a
// crafted block cannot allocate without limit.
func decodeBlock(input, dict []byte, maxBlock uint64) ([]byte, error) {
	if len(dict) > maxDictionary {
		dict = dict[len(dict)-maxDictionary:]
	}
	history := len(dict)

	// Start with a conservative hint. The frame format never produces more
	// than maxBlock bytes for one block, so the hint is capped there.
	hint := uint64(len(input))*3 + 64
	if hint > maxBlock {
		hint = maxBlock
	}
	out := make([]byte, history, history+int(hint))
	copy(out, dict)

	offset := 0
	for {
		if offset >= len(input) {
			return nil, fmt.Errorf("truncated: missing token")
		}
		token := input[offset]
		offset++

		literalLen := int(token >> 4)
		if literalLen == 15 {
			extra, next, err := extendedLength(input, offset)
			if err != nil {
				return nil, err
			}
			literalLen += extra
			offset = next
		}
		if uint64(len(out)-history)+uint64(literalLen) > maxBlock {
			return nil, fmt.Errorf("output exceeds the %d-byte block maximum", maxBlock)
		}
		if literalLen > 0 {
			if literalLen > len(input)-offset {
				return nil, fmt.Errorf("truncated: %d literal bytes requested, %d remain", literalLen, len(input)-offset)
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
			return nil, fmt.Errorf("invalid: match offset %d exceeds %d bytes of history", matchOffset, len(out))
		}

		matchLen := int(token & 0x0F)
		if matchLen == 15 {
			extra, next, err := extendedLength(input, offset)
			if err != nil {
				return nil, err
			}
			matchLen += extra
			offset = next
		}
		matchLen += minMatch
		if uint64(len(out)-history)+uint64(matchLen) > maxBlock {
			return nil, fmt.Errorf("output exceeds the %d-byte block maximum", maxBlock)
		}

		src := len(out) - matchOffset
		// Append one byte at a time: matches are allowed to overlap
		// themselves, which is how LZ4 encodes runs.
		for i := 0; i < matchLen; i++ {
			out = append(out, out[src+i])
		}
	}
	return out[history:], nil
}

// extendedLength accumulates the 255-terminated extension bytes used when a
// length nibble is saturated. The bound keeps a malformed run from growing an
// unbounded integer before the caller's output check runs.
func extendedLength(input []byte, offset int) (int, int, error) {
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
