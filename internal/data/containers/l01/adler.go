package l01

// adler32Checksum computes the Adler-32 checksum used throughout EWF/L01:
// section descriptors, volume sections, chunk tables, stored chunk trailers
// and the ltree header. It is implemented locally because foundation/crc32.go
// carries only the CRC variants.
func adler32Checksum(data []byte) uint32 {
	const modulus = 65521
	var a, b uint64 = 1, 0
	for _, value := range data {
		a += uint64(value)
		if a >= modulus {
			a -= modulus
		}
		b += a
		if b >= modulus {
			b -= modulus
		}
	}
	return uint32((b << 16) | a)
}
