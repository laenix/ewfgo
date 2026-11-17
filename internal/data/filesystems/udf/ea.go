package udf

// Extended attributes: the typed records an ICB carries beside its data.
//
// A file entry records the byte length of its extended-attribute space. The
// space opens with an extended-attribute header descriptor (tag 0x0106)
// followed by generic-format records: a type, a subtype, three reserved bytes,
// a length that includes the twelve-byte record header, and the value.
//
// Types 2048 (implementation use) and 65536 (application use) carry a
// four-byte used length and a thirty-two-byte registered identifier before the
// value. Every other type's value follows its record header.
//
// A space whose header does not verify, or whose records do not tile it, is
// refused by name rather than read as a shorter list.

// Bytes of the extended-attribute header descriptor.
const EAHeaderBytes = 24

// Bytes of a generic-format record header.
const EARecordHeaderBytes = 12

// Bytes before the value of a use attribute: used length and identifier.
const EAUsePrefixBytes = 16 + 32

const maxAttributes = 1024

// The attribute types ECMA-167 calls implementation use and application use.
const (
	EAImplementationUse uint32 = 2048
	EAApplicationUse    uint32 = 65536
)

// ExtendedAttribute is one record of an extended-attribute space.
type ExtendedAttribute struct {
	// Kind is ECMA-167's attribute type.
	Kind uint32
	// Subtype is the attribute subtype; the defined forms record 1.
	Subtype uint8
	// Length is the bytes the record claims, its header included.
	Length uint32
	// Label is the name ECMA-167 gives the type, or "" for a type this reader
	// does not name.
	Label string
	// Identifier is the registered identifier a use attribute carries.
	Identifier *RegId
	// Value is the value without the record header and, for a use attribute,
	// without the used length and identifier.
	Value []byte
}

// ParseExtendedAttributes parses an extended-attribute space. space must be
// exactly the bytes the file entry's lengthExtendedAttr names.
func ParseExtendedAttributes(space []byte) ([]ExtendedAttribute, error) {
	if len(space) < EAHeaderBytes {
		return nil, corruptf(
			"the extended-attribute space is %d bytes, shorter than its %d-byte header descriptor",
			len(space), EAHeaderBytes)
	}
	header, ok := ParseTag(space)
	if !ok {
		return nil, corruptf("the extended-attribute space does not open with a descriptor tag")
	}
	if header.Ident != TagEAHD {
		return nil, corruptf(
			"the extended-attribute space opens with a %s descriptor, not an extended-attribute header",
			header.Label())
	}
	if !header.Verified() {
		return nil, corruptf("the extended-attribute header descriptor's tag does not verify")
	}

	var attrs []ExtendedAttribute
	at := EAHeaderBytes
	for at < len(space) {
		rest := space[at:]
		allZero := true
		for _, v := range rest {
			if v != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			break
		}
		if len(attrs) >= maxAttributes {
			return nil, corruptf("the extended-attribute space holds more than %d records", maxAttributes)
		}
		if len(rest) < EARecordHeaderBytes {
			return nil, corruptf(
				"%d byte(s) of extended-attribute space at offset %d are shorter than a record header",
				len(rest), at)
		}
		kind := le32(rest, 0)
		subtype := rest[4]
		length := le32(rest, 8)
		lengthUsize := int(length)
		if lengthUsize < EARecordHeaderBytes {
			return nil, corruptf(
				"the extended attribute at offset %d claims %d bytes, less than its own header",
				at, length)
		}
		if lengthUsize > len(rest) {
			return nil, corruptf(
				"the extended attribute at offset %d claims %d bytes but only %d remain in the space",
				at, length, len(rest))
		}
		record := rest[:lengthUsize]
		attr := ExtendedAttribute{Kind: kind, Subtype: subtype, Length: length}
		attr.Label = eaLabel(kind)
		if kind == EAImplementationUse || kind == EAApplicationUse {
			if lengthUsize < EAUsePrefixBytes {
				return nil, corruptf(
					"the use attribute at offset %d is %d bytes, shorter than its used length and identifier",
					at, length)
			}
			used := int(le32(record, 12))
			if used > lengthUsize-EAUsePrefixBytes {
				return nil, corruptf(
					"the use attribute at offset %d claims %d value bytes inside a %d-byte record",
					at, used, length)
			}
			ident, ok := NewRegId(record[16:48])
			if ok {
				attr.Identifier = &ident
			}
			attr.Value = append([]byte(nil), record[EAUsePrefixBytes:EAUsePrefixBytes+used]...)
		} else {
			attr.Value = append([]byte(nil), record[EARecordHeaderBytes:]...)
		}
		attrs = append(attrs, attr)
		at += lengthUsize
	}
	return attrs, nil
}

func eaLabel(kind uint32) string {
	switch kind {
	case 1:
		return "character-set"
	case 3:
		return "alternate-permissions"
	case 5:
		return "file-times"
	case 6:
		return "information-times"
	case 12:
		return "device-specification"
	case EAImplementationUse:
		return "implementation-use"
	case EAApplicationUse:
		return "application-use"
	default:
		return ""
	}
}
