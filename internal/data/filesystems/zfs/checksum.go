package zfs

import (
	"crypto/sha256"
	"fmt"
)

// Checksum is the algorithm a block pointer names.
//
// OpenZFS stores the same digest in four 64-bit words in big-endian order
// whatever the host's byte order; on a little-endian host that is the SHA-256
// output with each eight-byte group reversed. Comparing the raw digest would
// reject every real pool.
type Checksum uint8

const (
	// ChecksumInherit is id 0; it resolves to fletcher4 when written.
	ChecksumInherit Checksum = iota
	// ChecksumFletcher2 is the legacy two-chain checksum.
	ChecksumFletcher2
	// ChecksumFletcher4 is the pool default.
	ChecksumFletcher4
	// ChecksumSHA256 is used for metadata on newer pools.
	ChecksumSHA256
	// ChecksumOff means the block is not checksummed.
	ChecksumOff
	// ChecksumOther is a named-but-unimplemented algorithm.
	ChecksumOther
)

func checksumFromID(id byte) Checksum {
	switch id {
	case 0:
		return ChecksumInherit
	case 1, 9: // `on` and `zilog2` both resolve to fletcher4 on disk
		return ChecksumFletcher4
	case 2:
		return ChecksumOff
	case 6:
		return ChecksumFletcher2
	case 7:
		return ChecksumFletcher4
	case 8:
		return ChecksumSHA256
	default:
		return ChecksumOther
	}
}

func (c Checksum) label() string {
	switch c {
	case ChecksumInherit:
		return "inherit"
	case ChecksumFletcher2:
		return "fletcher2"
	case ChecksumFletcher4:
		return "fletcher4"
	case ChecksumSHA256:
		return "sha256"
	case ChecksumOff:
		return "off"
	default:
		return "other"
	}
}

// name is the spelling used in a refusal; an unknown id keeps its number.
func (c Checksum) name(id byte) string {
	if c == ChecksumOther {
		return fmt.Sprintf("checksum id %d", id)
	}
	return c.label()
}

// fletcher4 accumulates the 32-bit little-endian words into four sums, as
// OpenZFS's fletcher_4_native does.
func fletcher4(bytes []byte) [4]uint64 {
	var a, b, c, d uint64
	for i := 0; i+4 <= len(bytes); i += 4 {
		value := uint64(uint32(bytes[i]) | uint32(bytes[i+1])<<8 | uint32(bytes[i+2])<<16 | uint32(bytes[i+3])<<24)
		a += value
		b += a
		c += b
		d += c
	}
	return [4]uint64{a, b, c, d}
}

// fletcher2 keeps two interleaved chains over 64-bit little-endian words.
func fletcher2(bytes []byte) [4]uint64 {
	var a0, a1, b0, b1 uint64
	for i := 0; i+16 <= len(bytes); i += 16 {
		low := leUint64(bytes[i : i+8])
		high := leUint64(bytes[i+8 : i+16])
		a0 += low
		a1 += high
		b0 += a0
		b1 += a1
	}
	return [4]uint64{a0, a1, b0, b1}
}

// verifyChecksum compares a block's stored 32-byte checksum with the bytes
// read for it. It returns false for a mismatch and an error only when the
// algorithm itself cannot be computed.
func verifyChecksum(checksum Checksum, bytes, stored []byte) (bool, error) {
	if len(stored) != 32 {
		return false, unsupportedf("a ZFS checksum is 32 bytes, not %d", len(stored))
	}
	switch checksum {
	case ChecksumOff:
		return true, nil
	case ChecksumInherit, ChecksumFletcher4:
		if len(bytes)%4 != 0 {
			return false, unsupportedf("fletcher4 over a block whose length is not a multiple of four")
		}
		words := fletcher4(bytes)
		for i := 0; i < 4; i++ {
			if leUint64(stored[i*8:i*8+8]) != words[i] {
				return false, nil
			}
		}
		return true, nil
	case ChecksumFletcher2:
		if len(bytes)%8 != 0 {
			return false, unsupportedf("fletcher2 over a block whose length is not a multiple of eight")
		}
		words := fletcher2(bytes)
		for i := 0; i < 4; i++ {
			if leUint64(stored[i*8:i*8+8]) != words[i] {
				return false, nil
			}
		}
		return true, nil
	case ChecksumSHA256:
		digest := sha256.Sum256(bytes)
		for i := 0; i < 32; i += 8 {
			for j := 0; j < 8; j++ {
				if digest[i+j] != stored[i+7-j] {
					return false, nil
				}
			}
		}
		return true, nil
	default:
		return false, unsupportedf("a ZFS checksum this reader does not implement (stored word %x)", stored[:4])
	}
}

func leUint64(bytes []byte) uint64 {
	return uint64(bytes[0]) | uint64(bytes[1])<<8 | uint64(bytes[2])<<16 | uint64(bytes[3])<<24 |
		uint64(bytes[4])<<32 | uint64(bytes[5])<<40 | uint64(bytes[6])<<48 | uint64(bytes[7])<<56
}
