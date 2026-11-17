package lz4

import "encoding/binary"

// xxHash32 constants, as defined by the reference algorithm.
const (
	prime32_1 uint32 = 2654435761
	prime32_2 uint32 = 2246822519
	prime32_3 uint32 = 3266489917
	prime32_4 uint32 = 668265263
	prime32_5 uint32 = 374761393
)

// xxh32 computes the 32-bit xxHash of input with the given seed. LZ4 frames
// always use seed 0, but the reference algorithm makes the seed part of the
// definition and tests pin it.
func xxh32(input []byte, seed uint32) uint32 {
	length := len(input)
	offset := 0
	var hash uint32

	if length >= 16 {
		v1 := seed + prime32_1 + prime32_2
		v2 := seed + prime32_2
		v3 := seed
		v4 := seed - prime32_1

		for ; offset <= length-16; offset += 16 {
			v1 = round32(v1, binary.LittleEndian.Uint32(input[offset:]))
			v2 = round32(v2, binary.LittleEndian.Uint32(input[offset+4:]))
			v3 = round32(v3, binary.LittleEndian.Uint32(input[offset+8:]))
			v4 = round32(v4, binary.LittleEndian.Uint32(input[offset+12:]))
		}

		hash = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)
	} else {
		hash = seed + prime32_5
	}

	hash += uint32(length)

	for ; offset <= length-4; offset += 4 {
		hash += binary.LittleEndian.Uint32(input[offset:]) * prime32_3
		hash = rotl32(hash, 17) * prime32_4
	}
	for ; offset < length; offset++ {
		hash += uint32(input[offset]) * prime32_5
		hash = rotl32(hash, 11) * prime32_1
	}

	hash ^= hash >> 15
	hash *= prime32_2
	hash ^= hash >> 13
	hash *= prime32_3
	hash ^= hash >> 16
	return hash
}

func round32(acc, lane uint32) uint32 {
	acc += lane * prime32_2
	acc = rotl32(acc, 13)
	return acc * prime32_1
}

func rotl32(value uint32, bits uint) uint32 {
	return value<<bits | value>>(32-bits)
}
