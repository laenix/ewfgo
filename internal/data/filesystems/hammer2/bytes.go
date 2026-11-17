package hammer2

// Little-endian readers. HAMMER2 stores every field little-endian. The
// parsers bound their structures before calling these, so the helpers do not
// repeat range checks.

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
