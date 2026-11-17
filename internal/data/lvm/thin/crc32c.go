package thin

import "github.com/laenix/ewfgo/internal/data/foundation"

// thinChecksum computes the stored word for a persistent-data block: CRC-32C
// over everything after the checksum field, seeded with all ones, XORed with
// the structure's salt.
func thinChecksum(block []byte, xor uint32) uint32 {
	return foundation.CRC32CSeeded(0xFFFFFFFF, block[4:]) ^ xor
}
