// Package foundation holds the small shared primitives the data layer uses:
// CRC-32 variants, identifiers, and time formatting. It mirrors
// forensic-core's foundation module.
package foundation

var crc32Table = buildTable(0xEDB88320)
var crc32cTable = buildTable(0x82F63B78)

func buildTable(poly uint32) [256]uint32 {
	var table [256]uint32
	for index := 0; index < 256; index++ {
		value := uint32(index)
		for bit := 0; bit < 8; bit++ {
			if value&1 != 0 {
				value = (value >> 1) ^ poly
			} else {
				value >>= 1
			}
		}
		table[index] = value
	}
	return table
}

// CRC32Seeded is the reflected ISO-HDLC CRC-32 with an explicit seed and no
// final inversion.
func CRC32Seeded(seed uint32, data []byte) uint32 {
	crc := seed
	for _, b := range data {
		crc = crc32Table[(crc^uint32(b))&0xFF] ^ (crc >> 8)
	}
	return crc
}

// CRC32 is the usual ISO-HDLC CRC-32.
func CRC32(data []byte) uint32 {
	return ^CRC32Seeded(0xFFFFFFFF, data)
}

// CRC32CSeeded is the reflected Castagnoli CRC-32C with an explicit seed and
// no final inversion.
func CRC32CSeeded(seed uint32, data []byte) uint32 {
	crc := seed
	for _, b := range data {
		crc = crc32cTable[(crc^uint32(b))&0xFF] ^ (crc >> 8)
	}
	return crc
}

// CRC32C is the usual Castagnoli CRC-32C.
func CRC32C(data []byte) uint32 {
	return ^CRC32CSeeded(0xFFFFFFFF, data)
}
