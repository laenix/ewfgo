// The 7z byte filters: Delta and the x86 branch converter, plus the four-
// stream BCJ2 converter.
//
// A filter is a coder that consumes and produces the same number of bytes, so
// a folder declares one unpacked size for each and the stream length never
// changes.  Filters sit in a folder's coder chain next to the compressor; the
// folder's bind pairs say whether the filter runs before or after it.
//
// Both algorithms are the LZMA SDK's.  The x86 converter rewrites the rel32
// operand of E8 (CALL) and E9 (JMP) into a position-independent form so that a
// compressed executable has no address-dependent bytes; decoding adds the
// stream position back.

package sevenz

import "encoding/binary"

// deltaDecode decodes the Delta filter with the given distance.
//
// Each byte is added to the byte distance positions before it, starting from a
// state of zeros, so the first distance bytes are unchanged.
func deltaDecode(data []byte, distance int) {
	var state [256]byte
	position := 0
	for index := range data {
		value := data[index] + state[position]
		data[index] = value
		state[position] = value
		position++
		if position == distance {
			position = 0
		}
	}
}

// deltaEncode is the inverse of deltaDecode, used only by fixture writers.
func deltaEncode(data []byte, distance int) {
	var state [256]byte
	position := 0
	for index := range data {
		original := data[index]
		data[index] = original - state[position]
		state[position] = original
		position++
		if position == distance {
			position = 0
		}
	}
}

// msByteIsAddress reports whether a byte looks like the most significant byte
// of a branch target: 00 or FF, i.e. the address fits in a 16 MiB window.
func msByteIsAddress(value byte) bool {
	return (value+1)&0xFE == 0
}

var (
	maskToAllowedStatus = [8]bool{true, true, true, false, true, false, false, false}
	maskToBitNumber     = [8]uint32{0, 1, 2, 2, 3, 3, 3, 3}
)

// bcjX86 converts x86 E8/E9 operands between relative and absolute form.
//
// encoding turns a relative operand into an absolute one (what the
// compressor's filter does); decoding, the default use here, turns it back.
// startIP is the stream's address when the filter starts, zero for a whole 7z
// folder.
func bcjX86(data []byte, startIP uint32, encoding bool) {
	if len(data) < 5 {
		return
	}
	// The operand is relative to the end of the instruction, five bytes on.
	instructionIP := startIP + 5
	limit := len(data) - 4
	position := 0
	previousPosition := -1
	previousMask := uint32(0)

	for position < limit {
		opcode := data[position]
		if opcode != 0xE8 && opcode != 0xE9 {
			position++
			continue
		}

		// A candidate too close to the last one may be part of that
		// instruction's operand rather than an opcode of its own.
		gap := position - previousPosition
		if gap > 3 {
			previousMask = 0
		} else {
			shift := gap - 1
			if shift < 0 {
				shift = 0
			}
			previousMask = (previousMask << uint(shift)) & 7
			if previousMask != 0 {
				index := 4 - int(maskToBitNumber[previousMask])
				value := data[position+index]
				if !maskToAllowedStatus[previousMask] || msByteIsAddress(value) {
					previousPosition = position
					previousMask = ((previousMask << 1) & 7) | 1
					position++
					continue
				}
			}
		}
		previousPosition = position

		if !msByteIsAddress(data[position+4]) {
			previousMask = ((previousMask << 1) & 7) | 1
			position++
			continue
		}

		source := binary.LittleEndian.Uint32(data[position+1 : position+5])
		var destination uint32
		for {
			address := instructionIP + uint32(position)
			if encoding {
				destination = source + address
			} else {
				destination = source - address
			}
			if previousMask == 0 {
				break
			}
			shift := maskToBitNumber[previousMask] * 8
			value := byte(destination >> (24 - shift))
			if !msByteIsAddress(value) {
				break
			}
			// Rust's release-mode semantics mask a 32-bit shift count, so
			// 32-shift==32 shifts by zero (the SDK's C does the same on x86).
			source = destination ^ ((uint32(1) << ((32 - shift) & 31)) - 1)
		}
		if (destination>>24)&1 == 1 {
			data[position+4] = 0xFF
		} else {
			data[position+4] = 0x00
		}
		data[position+3] = byte(destination >> 16)
		data[position+2] = byte(destination >> 8)
		data[position+1] = byte(destination)
		position += 5
	}
}

// decodeBCJ2 decodes the BCJ2 converter's four streams into the original byte
// stream.
//
// BCJ2 splits a folder into a main stream that keeps every byte except the
// four-byte operand of each converted branch, two address streams holding the
// big-endian absolute targets of converted E8 (call) and E9/0F 8x (jump)
// instructions, and a range-coded rc stream that carries one bit per branch
// candidate -- whether its operand was moved out.  The decoder walks the main
// stream, copies bytes, and at every E8, E9 or 0F 8x marker reads a bit; a set
// bit pulls the next address and writes the relative operand
// target - (marker position + 5) back into the output.
//
// The output is exactly main.len() + call.len() + jump.len() bytes: each
// converted branch moves four bytes from an address stream into the output,
// and every address stream byte belongs to a converted branch.
func decodeBCJ2(main, call, jump, rc []byte) ([]byte, string) {
	// The range coder renormalizes once the range drops below 2^24.
	const top uint32 = 1 << 24

	if len(rc) < 5 {
		return nil, "BCJ2 range-coder stream is shorter than its five-byte header"
	}
	if rc[0] != 0 {
		return nil, "BCJ2 range-coder stream does not begin with a zero byte"
	}
	code := binary.BigEndian.Uint32(rc[1:5])
	if code == ^uint32(0) {
		return nil, "BCJ2 range-coder header is all ones"
	}
	rnge := ^uint32(0)
	rcPosition := 5
	var models [258]uint16
	for index := range models {
		models[index] = 1 << 10
	}
	output := make([]byte, 0, len(main)+len(call)+len(jump))
	callPosition := 0
	jumpPosition := 0
	// The range coder's context is the previous byte, which the encoder shifts
	// into the high eight bits; a converted branch leaves the operand's most
	// significant byte there instead.
	context := uint32(0)

	for _, value := range main {
		output = append(output, value)
		context = (context << 24) | uint32(value)
		marker := value == 0xE8 || value == 0xE9 ||
			(context-0x0F000080)&0xFFFFFFF0 == 0
		if !marker {
			continue
		}
		if rnge < top {
			if rcPosition >= len(rc) {
				return nil, "BCJ2 range-coder stream ends before its last decision"
			}
			rnge <<= 8
			code = (code << 8) | uint32(rc[rcPosition])
			rcPosition++
		}
		// E8 uses a model keyed by the byte before the opcode; E9 and 0F 8x
		// share two models chosen by one bit of the marker.
		callFlag := (context + 0x17) >> 6 & 1
		index := ((^callFlag + 1) & (context >> 24)) + callFlag + (context>>5)&1
		model := uint32(models[index])
		bound := (rnge >> 11) * model
		if code < bound {
			rnge = bound
			models[index] = uint16(model + ((2048 - model) >> 5))
			continue
		}
		rnge -= bound
		code -= bound
		models[index] = uint16(model - (model >> 5))

		toJump := (context+0x57)>>6&1 != 0
		var stream []byte
		var position *int
		var message string
		if toJump {
			stream, position = jump, &jumpPosition
			message = "BCJ2 jump stream ends before its last branch"
		} else {
			stream, position = call, &callPosition
			message = "BCJ2 call stream ends before its last branch"
		}
		if *position+4 > len(stream) {
			return nil, message
		}
		operand := stream[*position : *position+4]
		absolute := binary.BigEndian.Uint32(operand)
		*position += 4
		// The operand is relative to the end of the instruction, five bytes on.
		relative := absolute - (uint32(len(output)) + 4)
		var encoded [4]byte
		binary.LittleEndian.PutUint32(encoded[:], relative)
		output = append(output, encoded[:]...)
		context = relative >> 24
	}
	if callPosition != len(call) {
		return nil, "BCJ2 call stream holds bytes that no branch converted"
	}
	if jumpPosition != len(jump) {
		return nil, "BCJ2 jump stream holds bytes that no branch converted"
	}
	return output, ""
}
