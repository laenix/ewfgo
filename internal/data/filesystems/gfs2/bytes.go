package gfs2

// Big-endian readers. GFS2 stores every field big-endian. The parsers bound
// their structures before calling these, so the helpers do not repeat range
// checks.

func be16(raw []byte, at int) uint16 {
	return uint16(raw[at])<<8 | uint16(raw[at+1])
}

func be32(raw []byte, at int) uint32 {
	return uint32(raw[at])<<24 |
		uint32(raw[at+1])<<16 |
		uint32(raw[at+2])<<8 |
		uint32(raw[at+3])
}

func be64(raw []byte, at int) uint64 {
	return uint64(be32(raw, at))<<32 | uint64(be32(raw, at+4))
}

// fixedString decodes a NUL-padded fixed-size text field.
func fixedString(raw []byte, at, length int) string {
	field := raw[at : at+length]
	end := len(field)
	for index, value := range field {
		if value == 0 {
			end = index
			break
		}
	}
	return string(field[:end])
}
