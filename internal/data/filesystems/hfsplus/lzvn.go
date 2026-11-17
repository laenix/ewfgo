package hfsplus

// Apple LZVN decompression for decmpfs types 7 and 8.
//
// This is the LZVN state machine also used by the LZFSE package's `bvxn`
// block decoder.  It is duplicated here (rather than exported from that
// package) because the hfsplus reader must stay self-contained.  The stream is
// a sequence of one-byte opcodes; most encode a short literal plus a
// distance/length back-match.  Matches may overlap the bytes they produce, and
// every valid stream ends with the eight-byte end marker 0x06.
//
// Failure is explicit: a truncated, malformed, non-terminated or wrong-length
// stream returns an error rather than partial bytes.

import "errors"

// decodeLZVN decodes one LZVN payload into exactly outLen bytes.
func decodeLZVN(src []byte, outLen uint32) ([]byte, error) {
	const eosBytes = 8
	out := make([]byte, 0, outLen)
	sp := 0
	var distance uint64

	need := func(n int, what string) error {
		if n < 0 || len(src)-sp < n {
			return errors.New("lzvn: " + what + " is truncated")
		}
		return nil
	}
	literal := func(n int) error {
		if len(out)+n > int(outLen) {
			return errors.New("lzvn: literal overruns the declared output size")
		}
		out = append(out, src[sp:sp+n]...)
		sp += n
		return nil
	}
	match := func(n int) error {
		if distance == 0 {
			return errors.New("lzvn: match with no previous distance")
		}
		if uint64(len(out)) < distance {
			return errors.New("lzvn: match distance precedes the output")
		}
		if len(out)+n > int(outLen) {
			return errors.New("lzvn: match overruns the declared output size")
		}
		from := len(out) - int(distance)
		for i := 0; i < n; i++ {
			out = append(out, out[from+i])
		}
		return nil
	}

	for {
		if sp >= len(src) {
			return nil, errors.New("lzvn: payload ends before the end marker")
		}
		opc := src[sp]
		switch {
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
			// sml_d: LLMMMDDD DDDDDDDD, literal 0-3, match 3-10.
			litLen := int((opc >> 6) & 3)
			matchLen := int((opc>>3)&7) + 3
			if err := need(2+litLen, "sml_d"); err != nil {
				return nil, err
			}
			distance = uint64(opc&7)<<8 | uint64(src[sp+1])
			sp += 2
			if err := literal(litLen); err != nil {
				return nil, err
			}
			if err := match(matchLen); err != nil {
				return nil, err
			}

		case opc >= 160 && opc <= 191:
			// med_d: 101LLMMM DDDDDDMM DDDDDDDD, literal 0-3, match 3-18.
			litLen := int((opc >> 3) & 3)
			if err := need(3+litLen, "med_d"); err != nil {
				return nil, err
			}
			packed := uint16(src[sp+1]) | uint16(src[sp+2])<<8
			matchLen := int(uint16(opc&7)<<2|packed&3) + 3
			distance = uint64(packed>>2) & 0x3FFF
			sp += 3
			if err := literal(litLen); err != nil {
				return nil, err
			}
			if err := match(matchLen); err != nil {
				return nil, err
			}

		case opc == 7 || opc == 15 || opc == 23 || opc == 31 || opc == 39 ||
			opc == 47 || opc == 55 || opc == 63 || opc == 71 || opc == 79 ||
			opc == 87 || opc == 95 || opc == 103 || opc == 111 ||
			opc == 135 || opc == 143 || opc == 151 || opc == 159 ||
			opc == 199 || opc == 207:
			// lrg_d: LLMMM111 DDDDDDDD DDDDDDDD, literal 0-3, match 3-10.
			litLen := int((opc >> 6) & 3)
			matchLen := int((opc>>3)&7) + 3
			if err := need(3+litLen, "lrg_d"); err != nil {
				return nil, err
			}
			distance = uint64(src[sp+1]) | uint64(src[sp+2])<<8
			sp += 3
			if err := literal(litLen); err != nil {
				return nil, err
			}
			if err := match(matchLen); err != nil {
				return nil, err
			}

		case opc == 70 || opc == 78 || opc == 86 || opc == 94 || opc == 102 ||
			opc == 110 || opc == 134 || opc == 142 || opc == 150 || opc == 158 ||
			opc == 198 || opc == 206:
			// pre_d: LLMMM110, literal 1-3, match 3-10, previous distance.
			litLen := int((opc >> 6) & 3)
			matchLen := int((opc>>3)&7) + 3
			if err := need(1+litLen, "pre_d"); err != nil {
				return nil, err
			}
			sp++
			if err := literal(litLen); err != nil {
				return nil, err
			}
			if err := match(matchLen); err != nil {
				return nil, err
			}

		case opc >= 241:
			// sml_m: 1111MMMM, match 1-15, previous distance.
			matchLen := int(opc & 15)
			if err := need(1, "sml_m"); err != nil {
				return nil, err
			}
			sp++
			if err := match(matchLen); err != nil {
				return nil, err
			}

		case opc == 240:
			// lrg_m: 11110000 MMMMMMMM, match 16-271, previous distance.
			if err := need(2, "lrg_m"); err != nil {
				return nil, err
			}
			matchLen := int(src[sp+1]) + 16
			sp += 2
			if err := match(matchLen); err != nil {
				return nil, err
			}

		case opc >= 225 && opc <= 239:
			// sml_l: 1110LLLL, literal 1-15.
			litLen := int(opc & 15)
			if err := need(1+litLen, "sml_l"); err != nil {
				return nil, err
			}
			sp++
			if err := literal(litLen); err != nil {
				return nil, err
			}

		case opc == 224:
			// lrg_l: 11100000 LLLLLLLL, literal 16-271.
			if err := need(2, "lrg_l"); err != nil {
				return nil, err
			}
			litLen := int(src[sp+1]) + 16
			if err := need(2+litLen, "lrg_l"); err != nil {
				return nil, err
			}
			sp += 2
			if err := literal(litLen); err != nil {
				return nil, err
			}

		case opc == 14 || opc == 22:
			// nop, distance preserved.
			if err := need(1, "nop"); err != nil {
				return nil, err
			}
			sp++

		case opc == 6:
			// eos: exactly eight bytes at the end of the payload.
			if len(src)-sp < eosBytes {
				return nil, errors.New("lzvn: truncated end marker")
			}
			for i := 1; i < eosBytes; i++ {
				if src[sp+i] != 0 {
					return nil, errors.New("lzvn: malformed end marker")
				}
			}
			if sp+eosBytes != len(src) {
				return nil, errors.New("lzvn: trailing bytes after the end marker")
			}
			if len(out) != int(outLen) {
				return nil, errors.New("lzvn: decoded length does not match the declared size")
			}
			return out, nil

		default:
			return nil, errors.New("lzvn: undefined opcode")
		}
	}
}
