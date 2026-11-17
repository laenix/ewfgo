package udf

// The descriptor tag every UDF structure carries.
//
// Sixteen bytes say what the descriptor is, which revision wrote it, and where
// it was recorded, plus two independent integrity checks: a plain byte sum over
// the tag itself and a CRC-16/ITU-T over the descriptor body. A structure whose
// checks do not pass is refused by the reader rather than used with guessed
// fields.

// TagBytes is the size of a descriptor tag.
const TagBytes = 16

// Tag identifiers, named after ECMA-167's descriptor numbers.
const (
	TagPVD  = 0x0001
	TagAVDP = 0x0002
	TagVDP  = 0x0003
	TagIUVD = 0x0004
	TagPD   = 0x0005
	TagLVD  = 0x0006
	TagUSD  = 0x0007
	TagTD   = 0x0008
	TagLVID = 0x0009

	TagFSD  = 0x0100
	TagFID  = 0x0101
	TagAED  = 0x0102
	TagIE   = 0x0103
	TagTE   = 0x0104
	TagFE   = 0x0105
	TagEAHD = 0x0106
	TagUSE  = 0x0107
	TagSBD  = 0x0108
	TagPIE  = 0x0109
	TagEFE  = 0x010A
)

// Tag is a parsed descriptor tag.
type Tag struct {
	Ident   uint16
	Version uint16
	Serial  uint16
	CRC     uint16
	// CRCLength is the number of descriptor-body bytes the CRC covers.
	CRCLength uint16
	// Location is the block (or logical sector) the writer claims this
	// descriptor occupies.
	Location uint32
	// ChecksumOK says the tag's own byte-sum check matched.
	ChecksumOK bool
	// CRCChecked says the declared CRC length fitted the bytes that were read.
	CRCChecked bool
	// CRCOK says the body CRC matched. It is meaningful only when CRCChecked.
	CRCOK bool
}

// CRC16ITU is CRC-16/ITU-T: polynomial 0x1021, initial value 0xFFFF, neither
// reflected, no final inversion. UDF stores this over a descriptor body.
func CRC16ITU(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// Verified reports whether both checks that could be computed passed.
func (t Tag) Verified() bool {
	return t.ChecksumOK && t.CRCChecked && t.CRCOK
}

// Label is a short name for reports.
func (t Tag) Label() string {
	switch t.Ident {
	case TagPVD:
		return "primary"
	case TagAVDP:
		return "anchor"
	case TagVDP:
		return "volume-descriptor-pointer"
	case TagIUVD:
		return "implementation-use"
	case TagPD:
		return "partition"
	case TagLVD:
		return "logical-volume"
	case TagUSD:
		return "unallocated-space"
	case TagTD:
		return "terminator"
	case TagLVID:
		return "integrity"
	case TagFSD:
		return "file-set"
	case TagFID:
		return "file-identifier"
	case TagAED:
		return "allocation-extent"
	case TagIE:
		return "indirect-entry"
	case TagTE:
		return "terminal"
	case TagFE:
		return "file-entry"
	case TagEAHD:
		return "extended-attribute-header"
	case TagUSE:
		return "unallocated-space-entry"
	case TagSBD:
		return "space-bitmap"
	case TagPIE:
		return "path-table"
	case TagEFE:
		return "extended-file-entry"
	default:
		return "unknown"
	}
}

// ParseTag parses the tag at the start of b and checks both integrity fields
// against the bytes actually present. A buffer shorter than a tag, or one with
// no recognisable tag, yields false.
func ParseTag(b []byte) (Tag, bool) {
	if len(b) < TagBytes {
		return Tag{}, false
	}
	ident := le16(b, 0)
	if ident == 0 {
		return Tag{}, false
	}
	tag := Tag{
		Ident:     ident,
		Version:   le16(b, 2),
		Serial:    le16(b, 6),
		CRC:       le16(b, 8),
		CRCLength: le16(b, 10),
		Location:  le32(b, 12),
	}
	var sum uint16
	for i := 0; i < TagBytes; i++ {
		if i != 4 {
			sum += uint16(b[i])
		}
	}
	tag.ChecksumOK = byte(sum&0xFF) == b[4]
	if end := TagBytes + int(tag.CRCLength); end <= len(b) {
		tag.CRCChecked = true
		tag.CRCOK = CRC16ITU(b[TagBytes:end]) == tag.CRC
	}
	return tag, true
}

// descriptorTag parses a structure's tag and refuses one that does not verify.
func descriptorTag(b []byte, what string, block uint32) (Tag, error) {
	tag, ok := ParseTag(b)
	if !ok {
		reason := "the tag identifier is zero"
		if len(b) < TagBytes {
			reason = "the block is shorter than a tag"
		}
		return Tag{}, corruptf("%s at block %d carries no descriptor tag: %s", what, block, reason)
	}
	if !tag.Verified() {
		return Tag{}, corruptf("%s at block %d fails its tag checksum or body CRC", what, block)
	}
	return tag, nil
}
