package udf

// File identifier descriptors: a directory's entries.
//
// A UDF directory is the file's bytes, split into descriptors that are not
// fixed length and do not fill a block: each begins with a tag, carries a long
// allocation descriptor pointing at the entry it names, and stores its name as
// a dstring. The whole descriptor is padded to a four-byte multiple, and that
// padding is part of the record.
//
// The parent entry is a real descriptor whose name is empty; the file
// characteristics byte flags it separately.

// Bytes of a file identifier descriptor before its implementation use.
const FIDHeader = 38

const (
	CharHidden    = 0x01
	CharDirectory = 0x02
	CharDeleted   = 0x04
	CharParent    = 0x08
	CharMetadata  = 0x10
)

// MaxFIDBytes bounds one descriptor: entries larger than this are a claim
// about the image, not a name.
const MaxFIDBytes = 4096

// FileIdentifier is one directory entry, borrowed from the directory's bytes.
type FileIdentifier struct {
	Tag             Tag
	Version         uint16
	Characteristics uint8
	// ICB is the file entry this name points at.
	ICB            LongAd
	LengthOfImpUse uint16
	// Identifier is the encoded name (a dstring), empty for the parent.
	Identifier []byte
	// TotalLength is the whole descriptor including its four-byte padding.
	TotalLength int
	// Offset is the descriptor's offset inside the directory bytes.
	Offset int
}

// IsDirectory reports the directory characteristic.
func (f FileIdentifier) IsDirectory() bool { return f.Characteristics&CharDirectory != 0 }

// IsDeleted reports the deleted characteristic.
func (f FileIdentifier) IsDeleted() bool { return f.Characteristics&CharDeleted != 0 }

// IsParent reports the parent characteristic.
func (f FileIdentifier) IsParent() bool { return f.Characteristics&CharParent != 0 }

// IsHidden reports the hidden characteristic.
func (f FileIdentifier) IsHidden() bool { return f.Characteristics&CharHidden != 0 }

// Name decodes the identifier. It returns false for the parent entry, an empty
// name, or an unknown compression scheme.
func (f FileIdentifier) Name() (string, bool) {
	if len(f.Identifier) == 0 {
		return "", false
	}
	name, ok := dstring(f.Identifier)
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

// ParseDirectoryEntries parses every descriptor in a directory's bytes.
// Parsing stops at the first descriptor that does not fit: a torn tail is
// common and is not allowed to invent entries.
func ParseDirectoryEntries(b []byte) []FileIdentifier {
	var out []FileIdentifier
	for at := 0; at+FIDHeader <= len(b); {
		if b[at] == 0 && b[at+1] == 0 {
			break
		}
		tag, ok := ParseTag(b[at:])
		if !ok || tag.Ident != TagFID {
			break
		}
		nameLen := int(b[at+19])
		icb, ok := longAD(b, at+20)
		if !ok {
			break
		}
		impUse := int(le16(b, at+36))
		total := FIDHeader + impUse + nameLen
		total = (total + 3) &^ 3
		if total > MaxFIDBytes || at+total > len(b) {
			break
		}
		identifierAt := at + FIDHeader + impUse
		out = append(out, FileIdentifier{
			Tag:             tag,
			Version:         le16(b, at+16),
			Characteristics: b[at+18],
			ICB:             icb,
			LengthOfImpUse:  uint16(impUse),
			Identifier:      b[identifierAt : identifierAt+nameLen],
			TotalLength:     total,
			Offset:          at,
		})
		at += total
	}
	return out
}
