package leveldb

import "fmt"

// A bounded Snappy raw-block decoder. LevelDB stores a table block with
// compression byte 1 as one raw Snappy stream: a varint uncompressed length
// followed by literal and copy elements. The decoder never allocates beyond
// the declared length (itself bounded by the caller) and refuses a stream that
// produces a different length or leaves bytes unread.

// snappyDecompress decodes one raw Snappy stream into at most limit bytes.
func snappyDecompress(src []byte, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, limitError("a Snappy block decodes into a non-positive byte bound")
	}
	declared, at, ok := readVarint(src)
	if !ok {
		return nil, corrupt(0, "a Snappy block opens with no varint uncompressed length")
	}
	if declared > uint64(limit) {
		return nil, limitError("a Snappy block declares %d bytes, above the %d-byte bound", declared, limit)
	}
	// The declaration is bounded by limit, which the caller already caps, so
	// this allocation cannot be driven by a corrupt length.
	out := make([]byte, 0, int(declared))
	want := int(declared)
	for at < len(src) && len(out) < want {
		tag := src[at]
		at++
		switch tag & 0x03 {
		case 0: // literal
			length := int(tag >> 2)
			if length < 60 {
				length++
			} else {
				extra := length - 59
				if extra < 1 || extra > 4 || at+extra > len(src) {
					return nil, corrupt(0, "a Snappy literal length is truncated")
				}
				var encoded uint64
				for index := 0; index < extra; index++ {
					encoded |= uint64(src[at+index]) << (8 * index)
				}
				at += extra
				if encoded > uint64(want) {
					return nil, corrupt(0, "a Snappy literal runs past the declared length")
				}
				length = int(encoded) + 1
			}
			if length < 0 || at+length > len(src) {
				return nil, corrupt(0, "a Snappy literal runs past the compressed bytes")
			}
			if len(out)+length > want {
				return nil, corrupt(0, "a Snappy literal exceeds the declared length")
			}
			out = append(out, src[at:at+length]...)
			at += length
		case 1: // copy with a one-byte offset
			if at+1 > len(src) {
				return nil, corrupt(0, "a Snappy copy is truncated")
			}
			length := int((tag>>2)&0x07) + 4
			offset := int(tag>>5)<<8 | int(src[at])
			at++
			var err error
			out, err = snappyCopy(out, want, offset, length)
			if err != nil {
				return nil, err
			}
		case 2: // copy with a two-byte offset
			if at+2 > len(src) {
				return nil, corrupt(0, "a Snappy copy is truncated")
			}
			length := int(tag>>2) + 1
			offset := int(src[at]) | int(src[at+1])<<8
			at += 2
			var err error
			out, err = snappyCopy(out, want, offset, length)
			if err != nil {
				return nil, err
			}
		case 3: // copy with a four-byte offset
			if at+4 > len(src) {
				return nil, corrupt(0, "a Snappy copy is truncated")
			}
			length := int(tag>>2) + 1
			offset := int(src[at]) |
				int(src[at+1])<<8 |
				int(src[at+2])<<16 |
				int(src[at+3])<<24
			at += 4
			var err error
			out, err = snappyCopy(out, want, offset, length)
			if err != nil {
				return nil, err
			}
		}
	}
	if len(out) != want {
		return nil, corrupt(0, fmt.Sprintf(
			"a Snappy block produced %d of its declared %d bytes", len(out), want))
	}
	if at != len(src) {
		return nil, corrupt(0, fmt.Sprintf(
			"a Snappy block leaves %d compressed byte(s) unread", len(src)-at))
	}
	return out, nil
}

// snappyCopy appends length bytes copied from `offset` bytes back, allowing the
// source and destination to overlap as the format requires.
func snappyCopy(out []byte, want, offset, length int) ([]byte, error) {
	if offset <= 0 || offset > len(out) {
		return nil, corrupt(0, fmt.Sprintf(
			"a Snappy copy names offset %d with only %d byte(s) produced", offset, len(out)))
	}
	if len(out)+length > want {
		return nil, corrupt(0, "a Snappy copy exceeds the declared length")
	}
	for index := 0; index < length; index++ {
		out = append(out, out[len(out)-offset])
	}
	return out, nil
}
