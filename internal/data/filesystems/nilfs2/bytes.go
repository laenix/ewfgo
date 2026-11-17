package nilfs2

// le16/le32/le64 decode little-endian words. Callers bound-check first; these
// helpers are the unchecked form used after a length check.
func le16(raw []byte, at int) uint16 {
	return uint16(raw[at]) | uint16(raw[at+1])<<8
}

func le32(raw []byte, at int) uint32 {
	return uint32(raw[at]) |
		uint32(raw[at+1])<<8 |
		uint32(raw[at+2])<<16 |
		uint32(raw[at+3])<<24
}

func le64(raw []byte, at int) uint64 {
	return uint64(le32(raw, at)) | uint64(le32(raw, at+4))<<32
}

func i32le(raw []byte, at int) int32 { return int32(le32(raw, at)) }

func i64le(raw []byte, at int) int64 { return int64(le64(raw, at)) }
