package hammer2

import "encoding/binary"

// XXH64 constants.
const (
	xxhPrime1 uint64 = 11400714785074694791
	xxhPrime2 uint64 = 14029467366897019727
	xxhPrime3 uint64 = 1609587929392839161
	xxhPrime4 uint64 = 9650029242287828579
	xxhPrime5 uint64 = 2870177450012600261
)

func xxhRound(accumulator, input uint64) uint64 {
	accumulator += input * xxhPrime2
	accumulator = rotateLeft(accumulator, 31)
	accumulator *= xxhPrime1
	return accumulator
}

func xxhMergeRound(accumulator, value uint64) uint64 {
	accumulator ^= xxhRound(0, value)
	accumulator = accumulator*xxhPrime1 + xxhPrime4
	return accumulator
}

func rotateLeft(value uint64, count uint) uint64 {
	return value<<count | value>>(64-count)
}

// xxh64 is the XXH64 hash with an explicit seed, as DragonFly uses for
// HAMMER2 block checks (XXH_HAMMER2_SEED).
func xxh64(data []byte, seed uint64) uint64 {
	length := len(data)
	var hash uint64
	if length >= 32 {
		v1 := seed + xxhPrime1 + xxhPrime2
		v2 := seed + xxhPrime2
		v3 := seed
		v4 := seed - xxhPrime1
		for len(data) >= 32 {
			v1 = xxhRound(v1, binary.LittleEndian.Uint64(data[0:8]))
			v2 = xxhRound(v2, binary.LittleEndian.Uint64(data[8:16]))
			v3 = xxhRound(v3, binary.LittleEndian.Uint64(data[16:24]))
			v4 = xxhRound(v4, binary.LittleEndian.Uint64(data[24:32]))
			data = data[32:]
		}
		hash = rotateLeft(v1, 1) + rotateLeft(v2, 7) + rotateLeft(v3, 12) + rotateLeft(v4, 18)
		hash = xxhMergeRound(hash, v1)
		hash = xxhMergeRound(hash, v2)
		hash = xxhMergeRound(hash, v3)
		hash = xxhMergeRound(hash, v4)
	} else {
		hash = seed + xxhPrime5
	}

	hash += uint64(length)
	if len(data) >= 8 {
		hash ^= xxhRound(0, binary.LittleEndian.Uint64(data[0:8]))
		hash = rotateLeft(hash, 27)*xxhPrime1 + xxhPrime4
		data = data[8:]
	}
	if len(data) >= 4 {
		hash ^= uint64(binary.LittleEndian.Uint32(data[0:4])) * xxhPrime1
		hash = rotateLeft(hash, 23)*xxhPrime2 + xxhPrime3
		data = data[4:]
	}
	for _, value := range data {
		hash ^= uint64(value) * xxhPrime5
		hash = rotateLeft(hash, 11) * xxhPrime1
	}

	hash ^= hash >> 33
	hash *= xxhPrime2
	hash ^= hash >> 29
	hash *= xxhPrime3
	hash ^= hash >> 32
	return hash
}
