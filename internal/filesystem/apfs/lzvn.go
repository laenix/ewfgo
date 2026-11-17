package apfs

import (
	"errors"
	"fmt"
)

// Apple LZVN (decmpfs types 7/8) decompression.
//
// Ported from Apple's open-source liblzfse lzvn_decode_base.c (BSD-3-Clause).
// The stream is a sequence of single-byte opcodes; most encode a short literal
// plus a distance/length back-match. Semantics are identical to the C decoder:
// matches may overlap (byte-by-byte, increasing address order), distances are
// relative to the output position, and every valid stream ends with an 8-byte
// end-of-stream marker (opcode 0x06).

// lzvnDecompress decompresses src into exactly outLen bytes. It returns an
// explicit error (never partial/guessed data) on a truncated, malformed, or
// overrunning stream — matching the project red line that reads must be real
// data or a clear error.
func lzvnDecompress(src []byte, outLen uint32) ([]byte, error) {
	out := make([]byte, outLen)
	if outLen == 0 {
		return out, nil
	}
	if len(src) == 0 {
		return nil, errors.New("lzvn: empty source")
	}
	sp := 0
	dp := 0
	var D uint64 // previous match distance

	overrun := func(what string) error {
		return fmt.Errorf("lzvn: %s overruns the %d-byte output", what, outLen)
	}

	for dp < len(out) {
		if sp >= len(src) {
			return nil, errors.New("lzvn: source exhausted before end of stream")
		}
		opc := src[sp]
		switch {

		// sml_d: {LLMMMDDD DDDDDDDD LITERAL}; literal 0-3, match 3-10, dist 11-bit.
		case opc <= 5 || (opc >= 8 && opc <= 13) ||
			(opc >= 16 && opc <= 21) || (opc >= 24 && opc <= 29) ||
			(opc >= 32 && opc <= 37) || (opc >= 40 && opc <= 45) ||
			(opc >= 48 && opc <= 53) || (opc >= 56 && opc <= 61) ||
			(opc >= 64 && opc <= 69) || (opc >= 72 && opc <= 77) ||
			(opc >= 80 && opc <= 85) || (opc >= 88 && opc <= 93) ||
			(opc >= 96 && opc <= 101) || (opc >= 104 && opc <= 109) ||
			(opc >= 128 && opc <= 133) || (opc >= 136 && opc <= 141) ||
			(opc >= 144 && opc <= 149) || (opc >= 152 && opc <= 157) ||
			(opc >= 192 && opc <= 197) || (opc >= 200 && opc <= 205):
			L := int((opc >> 6) & 3)
			M := int((opc>>3)&7) + 3
			if sp+2+L >= len(src) {
				return nil, errors.New("lzvn: sml_d source truncated")
			}
			D = uint64(opc&7)<<8 | uint64(src[sp+1])
			if dp+L > len(out) {
				return nil, overrun("sml_d literal")
			}
			sp += 2
			copy(out[dp:dp+L], src[sp:sp+L])
			sp += L
			dp += L
			if D == 0 || uint64(dp) < D {
				return nil, errors.New("lzvn: invalid match distance")
			}
			if dp+M > len(out) {
				return nil, overrun("sml_d match")
			}
			copyLzvnMatch(out, dp, D, M)
			dp += M

		// med_d: {101LLMMM DDDDDDMM DDDDDDDD LITERAL}; literal 0-3, match 3-18, dist 14-bit.
		case opc >= 160 && opc <= 191:
			L := int((opc >> 3) & 3)
			if sp+3+L >= len(src) {
				return nil, errors.New("lzvn: med_d source truncated")
			}
			opc23 := uint16(src[sp+1]) | uint16(src[sp+2])<<8
			M := int((uint16(opc&7)<<2 | opc23&3)) + 3
			D = uint64(opc23>>2) & 0x3fff
			if dp+L > len(out) {
				return nil, overrun("med_d literal")
			}
			sp += 3
			copy(out[dp:dp+L], src[sp:sp+L])
			sp += L
			dp += L
			if D == 0 || uint64(dp) < D {
				return nil, errors.New("lzvn: invalid match distance")
			}
			if dp+M > len(out) {
				return nil, overrun("med_d match")
			}
			copyLzvnMatch(out, dp, D, M)
			dp += M

		// lrg_d: {LLMMM111 DDDDDDDD DDDDDDDD LITERAL}; literal 0-3, match 3-10, dist 16-bit.
		case opc == 7 || opc == 15 || opc == 23 || opc == 31 || opc == 39 ||
			opc == 47 || opc == 55 || opc == 63 || opc == 71 || opc == 79 ||
			opc == 87 || opc == 95 || opc == 103 || opc == 111 || opc == 135 ||
			opc == 143 || opc == 151 || opc == 159 || opc == 199 || opc == 207:
			L := int((opc >> 6) & 3)
			M := int((opc>>3)&7) + 3
			if sp+3+L >= len(src) {
				return nil, errors.New("lzvn: lrg_d source truncated")
			}
			D = uint64(src[sp+1]) | uint64(src[sp+2])<<8
			if dp+L > len(out) {
				return nil, overrun("lrg_d literal")
			}
			sp += 3
			copy(out[dp:dp+L], src[sp:sp+L])
			sp += L
			dp += L
			if D == 0 || uint64(dp) < D {
				return nil, errors.New("lzvn: invalid match distance")
			}
			if dp+M > len(out) {
				return nil, overrun("lrg_d match")
			}
			copyLzvnMatch(out, dp, D, M)
			dp += M

		// pre_d: {LLMMM110 LITERAL}; literal 0-3, match 3-10, previous distance.
		case opc == 70 || opc == 78 || opc == 86 || opc == 94 || opc == 102 ||
			opc == 110 || opc == 134 || opc == 142 || opc == 150 || opc == 158 ||
			opc == 198 || opc == 206:
			L := int((opc >> 6) & 3)
			M := int((opc>>3)&7) + 3
			if sp+1+L >= len(src) {
				return nil, errors.New("lzvn: pre_d source truncated")
			}
			if dp+L > len(out) {
				return nil, overrun("pre_d literal")
			}
			sp++
			copy(out[dp:dp+L], src[sp:sp+L])
			sp += L
			dp += L
			if D == 0 || uint64(dp) < D {
				return nil, errors.New("lzvn: invalid match distance")
			}
			if dp+M > len(out) {
				return nil, overrun("pre_d match")
			}
			copyLzvnMatch(out, dp, D, M)
			dp += M

		// sml_m: {1111MMMM}; match 0-15, previous distance.
		case opc >= 241:
			M := int(opc & 15)
			if sp+1 >= len(src) {
				return nil, errors.New("lzvn: sml_m source truncated")
			}
			sp++
			if D == 0 || uint64(dp) < D {
				return nil, errors.New("lzvn: invalid match distance")
			}
			if dp+M > len(out) {
				return nil, overrun("sml_m match")
			}
			copyLzvnMatch(out, dp, D, M)
			dp += M

		// lrg_m: {11110000 MMMMMMMM}; match 16-271, previous distance.
		case opc == 240:
			if sp+2 >= len(src) {
				return nil, errors.New("lzvn: lrg_m source truncated")
			}
			M := int(src[sp+1]) + 16
			sp += 2
			if D == 0 || uint64(dp) < D {
				return nil, errors.New("lzvn: invalid match distance")
			}
			if dp+M > len(out) {
				return nil, overrun("lrg_m match")
			}
			copyLzvnMatch(out, dp, D, M)
			dp += M

		// sml_l: {1110LLLL LITERAL}; literal 0-15, distance preserved.
		case opc >= 225 && opc <= 239:
			L := int(opc & 15)
			if sp+1+L >= len(src) {
				return nil, errors.New("lzvn: sml_l source truncated")
			}
			if dp+L > len(out) {
				return nil, overrun("sml_l literal")
			}
			sp++
			copy(out[dp:dp+L], src[sp:sp+L])
			sp += L
			dp += L

		// lrg_l: {11100000 LLLLLLLL LITERAL}; literal 16-271, distance preserved.
		case opc == 224:
			if sp+2 >= len(src) {
				return nil, errors.New("lzvn: lrg_l source truncated")
			}
			L := int(src[sp+1]) + 16
			if sp+2+L >= len(src) { // opcode(2) + L literal + 1 next-opcode byte
				return nil, errors.New("lzvn: lrg_l source truncated")
			}
			if dp+L > len(out) {
				return nil, overrun("lrg_l literal")
			}
			sp += 2
			copy(out[dp:dp+L], src[sp:sp+L])
			sp += L
			dp += L

		// nop: consume one byte, distance preserved.
		case opc == 14 || opc == 22:
			if sp+1 >= len(src) {
				return nil, errors.New("lzvn: nop source truncated")
			}
			sp++

		// eos: 8-byte end-of-stream marker.
		case opc == 6:
			if sp+8 > len(src) {
				return nil, errors.New("lzvn: eos source truncated")
			}
			if dp != len(out) {
				return nil, fmt.Errorf("lzvn: eos after %d bytes, want %d", dp, len(out))
			}
			return out, nil

		default:
			return nil, fmt.Errorf("lzvn: undefined opcode 0x%02x", opc)
		}
	}
	if dp != len(out) {
		return nil, fmt.Errorf("lzvn: decoded %d bytes, want %d", dp, len(out))
	}
	return out, nil
}

// copyLzvnMatch copies M bytes from out[dp-D:dp-D+M] to out[dp:dp+M], forward,
// byte-by-byte so overlapping matches behave like a run-length expand (a match
// may reference bytes it is itself producing).
func copyLzvnMatch(out []byte, dp int, D uint64, M int) {
	from := dp - int(D)
	for i := 0; i < M; i++ {
		out[dp+i] = out[from+i]
	}
}
