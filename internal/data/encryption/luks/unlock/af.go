package unlock

// The anti-forensic splitter (AFsplitter) of the LUKS key slots.
//
// A key slot stores `stripes` blocks, all but the last random, such that the
// master key is recovered by XORing the processed blocks together. Each block
// is diffused with SHA-256 so no single block carries the key:
//
//	diffuse(block) = for each 32-byte chunk i: SHA256(be32(i) || chunk)[:len]
//	AF_merge: acc = 0
//	          for every stripe but the last: acc ^= stripe; acc = diffuse(acc)
//	          key = acc ^ last_stripe
//	AF_split: (the inverse, used by fixtures and tests)
//
// The block counter restarts at zero for every diffuse call.

import (
	"crypto/sha256"
	"encoding/binary"
)

const afDigestBytes = 32

func afDiffuse(block []byte) []byte {
	out := make([]byte, 0, len(block))
	message := make([]byte, 0, 4+afDigestBytes)
	for index, chunk := range chunks(block, afDigestBytes) {
		message = message[:0]
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], uint32(index))
		message = append(message, counter[:]...)
		message = append(message, chunk...)
		digest := sha256.Sum256(message)
		out = append(out, digest[:len(chunk)]...)
	}
	return out
}

// afMerge recovers a key from a decrypted stripe area.
func afMerge(area []byte, keyBytes int) ([]byte, error) {
	if keyBytes <= 0 {
		return nil, afErrorf("a %d-byte AF key size is not usable", keyBytes)
	}
	if len(area)%keyBytes != 0 {
		return nil, afErrorf("a %d-byte stripe area is not a whole number of %d-byte keys", len(area), keyBytes)
	}
	stripes := len(area) / keyBytes
	if stripes < 2 {
		return nil, afErrorf("an area of %d stripe(s) cannot hide a key", stripes)
	}
	accumulator := make([]byte, keyBytes)
	for index := 0; index < stripes-1; index++ {
		stripe := area[index*keyBytes : (index+1)*keyBytes]
		for offset := range accumulator {
			accumulator[offset] ^= stripe[offset]
		}
		accumulator = afDiffuse(accumulator)
	}
	last := area[(stripes-1)*keyBytes:]
	key := make([]byte, keyBytes)
	for offset := range key {
		key[offset] = accumulator[offset] ^ last[offset]
	}
	return key, nil
}

// afSplit is the inverse of afMerge; fill supplies the random stripes.
func afSplit(key []byte, stripes int, fill func([]byte)) ([]byte, error) {
	keyBytes := len(key)
	if keyBytes == 0 {
		return nil, afErrorf("a %d-byte AF key size is not usable", keyBytes)
	}
	if stripes < 2 {
		return nil, afErrorf("an area of %d stripe(s) cannot hide a key", stripes)
	}
	area := make([]byte, keyBytes*stripes)
	accumulator := make([]byte, keyBytes)
	for index := 0; index < stripes-1; index++ {
		stripe := area[index*keyBytes : (index+1)*keyBytes]
		fill(stripe)
		for offset := range accumulator {
			accumulator[offset] ^= stripe[offset]
		}
		accumulator = afDiffuse(accumulator)
	}
	last := area[(stripes-1)*keyBytes:]
	for offset := range accumulator {
		last[offset] = accumulator[offset] ^ key[offset]
	}
	return area, nil
}

func chunks(data []byte, size int) [][]byte {
	if len(data) == 0 {
		return nil
	}
	out := make([][]byte, 0, (len(data)+size-1)/size)
	for len(data) > 0 {
		take := size
		if take > len(data) {
			take = len(data)
		}
		out = append(out, data[:take])
		data = data[take:]
	}
	return out
}
