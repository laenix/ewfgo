package iso9660

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

const (
	// recordHeader is the bytes before the file identifier.
	recordHeader = 33
	// flagDirectory marks a record that names a directory.
	flagDirectory = 0x02
	// flagMultiExtent marks a record whose data continues in the next record.
	flagMultiExtent = 0x80
)

// DirRecord is one directory record.
type DirRecord struct {
	Length          uint8
	ExtendedAttrLen uint8
	Extent          uint32
	DataLen         uint32
	Recording       [7]byte
	Flags           uint8
	UnitSize        uint8
	Gap             uint8
	VolumeSequence  uint16
	Identifier      []byte
	SystemUse       []byte
	FieldsAgree     bool
}

// IsDirectory reports whether the record names a directory.
func (r *DirRecord) IsDirectory() bool { return r.Flags&flagDirectory != 0 }

// IsMultiExtent reports whether the data continues in the next record.
func (r *DirRecord) IsMultiExtent() bool { return r.Flags&flagMultiExtent != 0 }

// IsDot reports the record named by a single zero byte: ".".
func (r *DirRecord) IsDot() bool { return len(r.Identifier) == 1 && r.Identifier[0] == 0 }

// IsDotDot reports the record named by a single one byte: "..".
func (r *DirRecord) IsDotDot() bool { return len(r.Identifier) == 1 && r.Identifier[0] == 1 }

// Version returns the ";version" suffix on a primary-tree name.
func (r *DirRecord) Version() (uint16, bool) {
	at := bytes.IndexByte(r.Identifier, ';')
	if at < 0 {
		return 0, false
	}
	digits := r.Identifier[at+1:]
	if len(digits) == 0 {
		return 0, false
	}
	var value uint16
	for _, b := range digits {
		if b < '0' || b > '9' {
			return 0, false
		}
		next := uint32(value)*10 + uint32(b-'0')
		if next > 0xFFFF {
			next = 0xFFFF
		}
		value = uint16(next)
	}
	return value, true
}

// records parses every record in one directory's bytes. blockSize is the
// volume's logical block size: a zero length byte pads to the next block, and
// a record never straddles one.
func records(bytes []byte, blockSize uint32) ([]DirRecord, error) {
	block := int(blockSize)
	if block == 0 {
		return nil, corruptf("logical block size is zero")
	}
	var out []DirRecord
	at := 0
	for at < len(bytes) {
		length := int(bytes[at])
		if length == 0 {
			next := (at/block + 1) * block
			if next <= at {
				break
			}
			at = next
			continue
		}
		if length < recordHeader+1 {
			return nil, corruptf("directory record at %d is %d bytes, shorter than its header", at, length)
		}
		end := at + length
		if end > len(bytes) {
			return nil, corruptf("directory record at %d runs past the extent", at)
		}
		raw := bytes[at:end]
		identAt := recordHeader
		identLen := int(raw[32])
		if identAt+identLen > len(raw) {
			return nil, corruptf("identifier at %d claims %d bytes in a %d-byte record", at, identLen, length)
		}
		record, err := parseRecord(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
		at = end
	}
	return out, nil
}

func parseRecord(raw []byte) (DirRecord, error) {
	extent, extentAgrees, err := bothU32(raw, 2)
	if err != nil {
		return DirRecord{}, err
	}
	dataLen, lenAgrees, err := bothU32(raw, 10)
	if err != nil {
		return DirRecord{}, err
	}
	sequence, seqAgrees, err := bothU16(raw, 28)
	if err != nil {
		return DirRecord{}, err
	}
	var recording [7]byte
	copy(recording[:], raw[18:25])
	identLen := int(raw[32])
	identifier := raw[recordHeader : recordHeader+identLen]
	systemAt := recordHeader + identLen
	if identLen%2 == 0 {
		systemAt++
	}
	if systemAt > len(raw) {
		systemAt = len(raw)
	}
	return DirRecord{
		Length:          raw[0],
		ExtendedAttrLen: raw[1],
		Extent:          extent,
		DataLen:         dataLen,
		Recording:       recording,
		Flags:           raw[25],
		UnitSize:        raw[26],
		Gap:             raw[27],
		VolumeSequence:  sequence,
		Identifier:      identifier,
		SystemUse:       raw[systemAt:],
		FieldsAgree:     extentAgrees && lenAgrees && seqAgrees,
	}, nil
}

// primaryName decodes a primary-tree identifier: ASCII d-characters with an
// optional ";version" suffix, where a trailing dot is also padding.
func primaryName(identifier []byte) (string, bool) {
	at := bytes.IndexByte(identifier, ';')
	if at < 0 {
		at = len(identifier)
	}
	name := identifier[:at]
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if len(name) == 0 {
		return "", false
	}
	out := make([]rune, len(name))
	for i, b := range name {
		out[i] = rune(b)
	}
	return string(out), true
}

// jolietName decodes a Joliet identifier: UCS-2 big-endian with the same
// optional version suffix.
func jolietName(identifier []byte) (string, bool) {
	if len(identifier) < 2 {
		return "", false
	}
	units := make([]uint16, 0, len(identifier)/2)
	for i := 0; i+2 <= len(identifier); i += 2 {
		unit := binary.BigEndian.Uint16(identifier[i:])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	text := string(utf16.Decode(units))
	if at := indexRune(text, ';'); at >= 0 {
		text = text[:at]
	}
	for len(text) > 0 && text[len(text)-1] == '.' {
		text = text[:len(text)-1]
	}
	if len(text) == 0 {
		return "", false
	}
	return text, true
}

func indexRune(text string, want rune) int {
	for i, r := range text {
		if r == want {
			return i
		}
	}
	return -1
}
