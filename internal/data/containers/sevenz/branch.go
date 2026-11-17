// The RISC branch converters: ARM, ARM-Thumb, ARM64, PowerPC, SPARC, IA-64
// and RISC-V.
//
// Like the x86 converter, each of these rewrites the relative displacement of
// a branch instruction into an absolute address so that a compressed
// executable has no position-dependent bytes.  Decoding subtracts the
// instruction's address (startIP + offset, usually the offset within the
// folder) back out and leaves every other byte alone.
//
// The algorithms are the LZMA SDK's C/Bra.c, ported instruction for
// instruction.  Their alignment and look-ahead rules matter: ARM/ARM64/PPC/
// SPARC work on 4-byte words, ARM-Thumb on 2-byte halves, IA-64 on 16-byte
// bundles and RISC-V on 2-byte instructions with six bytes of look-ahead.
// Trailing bytes that cannot hold a whole instruction are left unchanged, as
// the encoder leaves them.

package sevenz

import "encoding/binary"

// branchARM decodes the ARM (A32) branch converter.  BL has opcode EB in the
// most significant byte and a 24-bit word displacement relative to pc + 8.
func branchARM(data []byte, startIP uint32) {
	length := len(data) &^ 3
	for offset := 0; offset < length; offset += 4 {
		if data[offset+3] != 0xEB {
			continue
		}
		word := binary.LittleEndian.Uint32(data[offset : offset+4])
		displacement := (startIP + uint32(offset) + 8) >> 2
		word = (word-displacement)&0x00FFFFFF | 0xEB000000
		binary.LittleEndian.PutUint32(data[offset:offset+4], word)
	}
}

// branchARMThumb decodes the ARM-Thumb branch converter.  A 32-bit BL is
// written as two 16-bit halves (F0.. then F8..); the 22-bit halfword
// displacement is relative to pc + 4.
func branchARMThumb(data []byte, startIP uint32) {
	size := len(data) &^ 1
	if size <= 2 {
		return
	}
	limit := size - 2
	position := 0
	first := data[1]
	for {
		// Scan for the two halves of a BL.  first carries the high byte of the
		// previous halfword so one comparison covers both.
		var second byte
		for {
			if position >= limit {
				return
			}
			second = data[position+3]
			position += 2
			if second&(first^8) >= 0xF8 {
				break
			}
			if position >= limit {
				return
			}
			first = data[position+3]
			position += 2
			if first&(second^8) >= 0xF8 {
				break
			}
		}
		value := uint32(binary.LittleEndian.Uint16(data[position-2:position])) << 11
		value |= uint32(binary.LittleEndian.Uint16(data[position:position+2]) & 0x7FF)
		position += 2
		displacement := (startIP + uint32(position)) >> 1
		value -= displacement
		high := uint16((value>>11)&0x7FF) | 0xF000
		low := uint16(value) | 0xF800
		binary.LittleEndian.PutUint16(data[position-4:position-2], high)
		binary.LittleEndian.PutUint16(data[position-2:position], low)
	}
}

// branchARM64 decodes the ARM64 branch converter: BL (94xxxxxx, 26-bit word
// displacement) and ADRP (9xxxxxxx, page displacement).
func branchARM64(data []byte, startIP uint32) {
	length := len(data) &^ 3
	for offset := 0; offset < length; offset += 4 {
		word := binary.LittleEndian.Uint32(data[offset : offset+4])
		pc := startIP + uint32(offset)
		if (word-0x94000000)&0xFC000000 == 0 {
			word = (word-(pc>>2))&0x03FFFFFF | 0x94000000
			binary.LittleEndian.PutUint32(data[offset:offset+4], word)
		} else {
			word -= 0x90000000
			if word&0x9F000000 == 0 {
				// The immediate is stored shifted by the page size; flag is
				// the bit that distinguishes the two encodings.
				const flag uint32 = 1 << 20
				const mask uint32 = (1 << 24) - (flag << 1)
				word += flag
				if word&mask != 0 {
					continue
				}
				value := (word & 0xFFFFFFE0) | (word >> 26)
				value -= (pc >> 9) &^ 7
				word &= 0x1F
				word |= 0x90000000 | (value << 26)
				word |= 0x00FFFFE0 & ((value & 0x1FFFFF) - flag)
				binary.LittleEndian.PutUint32(data[offset:offset+4], word)
			}
		}
	}
}

// branchPPC decodes the PowerPC branch converter.  A branch instruction is
// 48xxxxxx with the low two bits 01; the 24-bit word displacement is relative
// to the instruction itself.  PowerPC is big-endian.
func branchPPC(data []byte, startIP uint32) {
	length := len(data) &^ 3
	for offset := 0; offset < length; offset += 4 {
		word := binary.BigEndian.Uint32(data[offset : offset+4])
		if (word-0x48000001)&0xFC000003 == 0 {
			pc := startIP + uint32(offset)
			word = (word-pc)&0x03FFFFFF | 0x48000000
			binary.BigEndian.PutUint32(data[offset:offset+4], word)
		}
	}
}

// branchSPARC decodes the SPARC branch converter.  CALL has opcode 01 and a
// 30-bit word displacement relative to the instruction.  SPARC is big-endian.
func branchSPARC(data []byte, startIP uint32) {
	// The CALL/JMPL opcode bit that the sign check uses.
	const flag uint32 = 1 << 22
	length := len(data) &^ 3
	for offset := 0; offset < length; offset += 4 {
		word := binary.BigEndian.Uint32(data[offset : offset+4])
		// Identify CALL/JMPL without masking the two opcode bits apart:
		// adding 5 << 29 and toggling 7 << 29 leaves the displacement alone
		// when the opcode is what the converter expects.
		word += 5 << 29
		word ^= 7 << 29
		word += flag
		if word&^((flag<<1)-1) == 0 {
			word <<= 2
			word -= startIP + uint32(offset)
			word &= (flag << 3) - 1
			word -= flag << 2
			word >>= 2
			word |= 1 << 30
			binary.BigEndian.PutUint32(data[offset:offset+4], word)
		}
	}
}

// branchIA64 decodes the IA-64 branch converter.  Instructions are packed
// three to a 16-byte bundle; the converter's template byte says which slots
// may hold a branch, and the branch displacement is stored across two slots.
func branchIA64(data []byte, startIP uint32) {
	length := len(data) &^ 15
	if length == 0 {
		return
	}
	position := 0
	pc := (startIP - (1 << 4)) >> 3 // pc >>= 4 - 1
	for {
		// Every bundle advances the program counter by two, because the
		// displacement is counted in 2-byte units.
		var slot uint32
		for {
			if position == length {
				return
			}
			slot = (0x334B0000 >> (data[position] & 0x1E)) & 3
			position += 16
			pc += 2
			if slot != 0 {
				break
			}
		}
		// m is the first slot of the bundle that may hold a branch.
		position = position + int(slot)*5 - 20
		for {
			if position < 0 || position+5 > len(data) {
				return
			}
			head := binary.LittleEndian.Uint32(data[position : position+4])
			tail := binary.LittleEndian.Uint32(data[position+1:position+5]) >> slot
			position += 5
			if (head>>slot)&(0x70<<1) == 0 &&
				(tail-(0x05000000<<1))&(0x0F000000<<1) == 0 {
				value := ((0x8FFFFF << 1) | 1) & tail
				tail ^= value
				pc |= ^uint32((0x1FFFFF << 1) | 1)
				value -= pc
				value &^= 0x600000 << 1
				value += 0x700000 << 1
				value &= (0x8FFFFF << 1) | 1
				tail |= value
				tail <<= slot
				binary.LittleEndian.PutUint32(data[position-4:position], tail)
			}
			slot++
			if slot&3 == 0 {
				break
			}
		}
	}
}

// branchRISCV decodes the RISC-V branch converter.  JAL and the AUIPC+JALR
// pair are rewritten; an instruction is two bytes, and a potential pair needs
// four more bytes of look-ahead.
func branchRISCV(data []byte, startIP uint32) {
	size := len(data) &^ 1
	if size <= 6 {
		return
	}
	limit := size - 6
	position := 0
	for {
		// A JAL (opcode 6F/EF) or AUIPC (17/97) has (low ^ 0x10) + 1 with
		// bits 0..2, 4..6 clear.
		var value uint32
		for {
			if position >= limit {
				return
			}
			low := binary.LittleEndian.Uint16(data[position : position+2])
			first := (uint32(low) ^ 0x10) + 1
			if first&0x77 == 0 {
				value = first
				break
			}
			next := binary.LittleEndian.Uint16(data[position+2 : position+4])
			probe := (uint32(next) ^ 0x10) + 1
			position += 4
			if probe&0x77 == 0 {
				position -= 2
				if position >= limit {
					return
				}
				value = probe
				break
			}
		}
		if value&8 == 0 {
			// JAL: a 21-bit halfword displacement spread through the word.
			a := value - (0x100 - 0x7F)
			if a&0xD80 != 0 {
				position += 2
				continue
			}
			old := (a + (0xEF - 0x7F)) & 0xFFF
			if position+4 > len(data) {
				return
			}
			value = (uint32(data[position+3]) << 1) |
				(uint32(data[position+2]) << 9) |
				((a & 0xF000) << 5)
			value -= startIP + uint32(position)
			a = old |
				((value << 11) & (1 << 31)) |
				((value << 20) & (0x3FF << 21)) |
				((value << 9) & (1 << 20)) |
				(value & (0xFF << 12))
			binary.LittleEndian.PutUint32(data[position:position+4], a)
			position += 4
			continue
		}
		// AUIPC+JALR pair.
		if position+8 > len(data) {
			return
		}
		lowValue := value
		word := binary.LittleEndian.Uint32(data[position : position+4])
		pc := startIP + uint32(position)
		if lowValue&0xE80 == 0 {
			register := word >> 27
			if riscvCheck2(lowValue, register) {
				target := binary.BigEndian.Uint32(data[position+4 : position+8])
				high := word >> 12
				target -= pc
				a := (register << 7) + 0x17 + ((target + 0x800) & 0xFFFFF000)
				tail := high | (target << 20)
				binary.LittleEndian.PutUint32(data[position:position+4], a)
				binary.LittleEndian.PutUint32(data[position+4:position+8], tail)
				position += 8
			} else {
				position += 4
			}
		} else {
			next := binary.LittleEndian.Uint32(data[position+4 : position+8])
			if !riscvCheck1(lowValue, next) {
				position += 6
			} else {
				high := (word & 0xFFFFF000) | (next >> 20)
				a := (next << 12) | (0x17 + (2 << 7))
				binary.LittleEndian.PutUint32(data[position:position+4], a)
				binary.LittleEndian.PutUint32(data[position+4:position+8], high)
				position += 8
			}
		}
	}
}

// riscvCheck1 is the SDK's RISCV_CHECK_1: the pair's AUIPC/JALR opcodes line
// up.
func riscvCheck1(value, next uint32) bool {
	return ((next-3)^(value<<8))&(0xF8000+3) == 0
}

// riscvCheck2 is the SDK's RISCV_CHECK_2: the pair is an AUIPC/JALR
// combination.
func riscvCheck2(value, register uint32) bool {
	return (value-((3<<12)|(2<<7)|8))<<18 < (register & 0x1D)
}

// swap2 reverses the byte order of every 2-byte word.
func swap2(data []byte) {
	length := len(data) &^ 1
	for offset := 0; offset < length; offset += 2 {
		data[offset], data[offset+1] = data[offset+1], data[offset]
	}
}

// swap4 reverses the byte order of every 4-byte word.
func swap4(data []byte) {
	length := len(data) &^ 3
	for offset := 0; offset < length; offset += 4 {
		data[offset], data[offset+1], data[offset+2], data[offset+3] =
			data[offset+3], data[offset+2], data[offset+1], data[offset]
	}
}
