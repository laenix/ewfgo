package f2fs

// Little-endian field readers shared by the parsers.  Every integer in the F2FS
// format is little-endian and packed, so a field past the end of the structure
// is an error, never a defaulted value.

func u8At(bytes []byte, offset int) (uint8, error) {
	if offset < 0 || offset >= len(bytes) {
		return 0, invalidf("a field at byte %d is past the structure", offset)
	}
	return bytes[offset], nil
}

func u16At(bytes []byte, offset int) (uint16, error) {
	if offset < 0 || offset+2 > len(bytes) || offset+2 < offset {
		return 0, invalidf("a field at byte %d is past the structure", offset)
	}
	return uint16(bytes[offset]) | uint16(bytes[offset+1])<<8, nil
}

func u32At(bytes []byte, offset int) (uint32, error) {
	if offset < 0 || offset+4 > len(bytes) || offset+4 < offset {
		return 0, invalidf("a field at byte %d is past the structure", offset)
	}
	return uint32(bytes[offset]) |
		uint32(bytes[offset+1])<<8 |
		uint32(bytes[offset+2])<<16 |
		uint32(bytes[offset+3])<<24, nil
}

func u64At(bytes []byte, offset int) (uint64, error) {
	lo, err := u32At(bytes, offset)
	if err != nil {
		return 0, err
	}
	hi, err := u32At(bytes, offset+4)
	if err != nil {
		return 0, err
	}
	return uint64(lo) | uint64(hi)<<32, nil
}

func putU16(bytes []byte, offset int, value uint16) {
	bytes[offset] = byte(value)
	bytes[offset+1] = byte(value >> 8)
}

func putU32(bytes []byte, offset int, value uint32) {
	bytes[offset] = byte(value)
	bytes[offset+1] = byte(value >> 8)
	bytes[offset+2] = byte(value >> 16)
	bytes[offset+3] = byte(value >> 24)
}

func putU64(bytes []byte, offset int, value uint64) {
	putU32(bytes, offset, uint32(value))
	putU32(bytes, offset+4, uint32(value>>32))
}

func bitSet(bitmap []byte, index int) bool {
	if index < 0 || index/8 >= len(bitmap) {
		return false
	}
	return bitmap[index/8]&(1<<uint(index%8)) != 0
}
