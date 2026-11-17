package udf

import "encoding/binary"

func le16ok(b []byte, at int) (uint16, bool) {
	if at < 0 || at+2 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b[at:]), true
}

func le32ok(b []byte, at int) (uint32, bool) {
	if at < 0 || at+4 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[at:]), true
}

func le64ok(b []byte, at int) (uint64, bool) {
	if at < 0 || at+8 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[at:]), true
}

func le16(b []byte, at int) uint16 {
	v, _ := le16ok(b, at)
	return v
}

func le32(b []byte, at int) uint32 {
	v, _ := le32ok(b, at)
	return v
}

func le64(b []byte, at int) uint64 {
	v, _ := le64ok(b, at)
	return v
}
