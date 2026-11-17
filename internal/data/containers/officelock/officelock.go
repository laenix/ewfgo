// Package officelock reads Microsoft Office document owner/lock files.
//
// While Word, Excel, PowerPoint or another Office editor holds a document
// open it writes a peer file beside it.  The peer's name is the document's
// name with its first two characters replaced by "~$" (when the name is long
// enough to lose two characters), so "Report.docx" has a "~$port.docx" peer.
// The peer's stored name is reported, never the name it might once have had.
// The file holds the name of the account that had the document open:
//
//	layout A (Word, 162 bytes)          layout B (Excel/PowerPoint, 165 bytes)
//	offset  size  field                 offset  size  field
//	     0     1  single-byte length         0     1  single-byte length
//	     1    53  owner, single-byte         1    54  owner, single-byte
//	    54     2  UTF-16 length              55     2  UTF-16 length
//	    56   106  owner, UTF-16LE            57   108  owner, UTF-16LE
//
// The first byte is the number of bytes the single-byte slot uses for the
// name, and the 16-bit little-endian word that follows the slot is the number
// of UTF-16 code units in the Unicode slot.  Neither is a fixed marker: the
// two numbers agree only when the name is ASCII.  The single-byte length is
// one byte and the UTF-16 length is two, so a name of 11 ASCII characters
// starts "0b ... 0b 00"; a name held only in the Unicode slot can carry 0 in
// the first byte and a nonzero UTF-16 length.  Excel and PowerPoint reserve
// one more byte in the single-byte slot; the position of the UTF-16 length
// decides which layout a file uses, not the file name or its extension.
//
// Bytes past the two name slots are not interpreted.  In particular the
// Unicode slot is longer than the name it holds: after the name and its
// terminator the writers leave language tags, FILETIME values and other bytes
// inside the same field.  Those bytes are not decoded, and the slot is read to
// the length the file states, not to the first zero unit.
//
// The single-byte slot is decoded only when it is valid UTF-8; it is never
// decoded with a guessed code page.  Both slots are kept as stored.  This
// package does not expose a creation time: the reference reader does not
// interpret the FILETIME bytes, and this port does not invent one.
//
// # What the file proves
//
// The file proves Office wrote that name into this peer file while the
// document was open.  It does not prove the document's contents, that the
// named account is the one who last saved it, or that the document is still
// open now: Office normally removes the peer on close, but a crash, a stale
// image or a read-only source can leave one behind.  An absent peer proves
// nothing at all.
//
// This is a Go port of forensic-core's data/containers/office_lock.rs.  Every
// functional branch of the reference reader is ported; the only additions are
// name-based detection ([IsOwnerFileName]) and a source-backed [Open].
package officelock

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Length of the single-byte slot in layout A (Word).
const SingleByteSlotA = 0x35

// Length of the single-byte slot in layout B (Excel/PowerPoint).
const SingleByteSlotB = 0x36

// Offset of the UTF-16 length word in layout A.
const UTF16LengthA = 0x36

// Offset of the UTF-16 length word in layout B.
const UTF16LengthB = 0x37

// Offset of the first UTF-16 code unit in layout A.
const UTF16SlotA = 0x38

// Offset of the first UTF-16 code unit in layout B.
const UTF16SlotB = 0x39

// The full length of layout A (Word).
const LayoutABytes = 0xa2

// The full length of layout B (Excel/PowerPoint).
const LayoutBBytes = 0xa5

// Most UTF-16 code units layout A's slot can hold.
const MaxUnitsA = (LayoutABytes - UTF16SlotA) / 2

// Most UTF-16 code units layout B's slot can hold.
const MaxUnitsB = (LayoutBBytes - UTF16SlotB) / 2

// The smallest file that can carry either layout's named slots.
const MinBytes = UTF16SlotA + 2

// MaxBytes is the largest owner file this reader will look at.
const MaxBytes uint64 = 4096

// Error kinds for [Decode].  Callers test them with errors.Is.
var (
	// ErrNotAnOwnerFile means the first byte cannot be the single-byte name
	// length of either slot.
	ErrNotAnOwnerFile = errors.New("officelock: not an Office owner file")
	// ErrTruncated means the file is shorter than the layout its length words
	// describe.
	ErrTruncated = errors.New("officelock: truncated owner file")
	// ErrNoLayout means neither layout's UTF-16 length word fits the slots
	// this file has.
	ErrNoLayout = errors.New("officelock: no known owner-file layout")
	// ErrNoName means the layouts are present but carry no readable name in
	// either slot.
	ErrNoName = errors.New("officelock: neither owner name slot is text")
)

// Error is a detailed owner-file decode failure.  It unwraps to one of the
// Err* sentinels above.
type Error struct {
	// Kind is one of ErrNotAnOwnerFile, ErrTruncated, ErrNoLayout or ErrNoName.
	Kind error
	// First is the first byte as stored.
	First byte
	// Found and Needed are the byte counts for ErrTruncated.
	Found  int
	Needed int
	// AnsiLength is the single-byte length for ErrNoLayout.
	AnsiLength uint8
}

// Error implements error.
func (e *Error) Error() string {
	switch {
	case errors.Is(e.Kind, ErrNotAnOwnerFile):
		return fmt.Sprintf(
			"the first byte, 0x%02x, cannot be the single-byte name length of an Office owner file (the longer slot holds %d bytes)",
			e.First, SingleByteSlotB)
	case errors.Is(e.Kind, ErrTruncated):
		return fmt.Sprintf(
			"the file is %d bytes; the owner-file layout its length words describe is %d bytes",
			e.Found, e.Needed)
	case errors.Is(e.Kind, ErrNoLayout):
		return fmt.Sprintf(
			"neither layout's UTF-16 length word at 0x36 or 0x37 fits its slot (the single-byte length is %d)",
			e.AnsiLength)
	case errors.Is(e.Kind, ErrNoName):
		return "both owner name slots are empty and neither is text"
	default:
		return "officelock: owner file decode failed"
	}
}

// Unwrap exposes the kind sentinel to errors.Is/As.
func (e *Error) Unwrap() error { return e.Kind }

// OwnerFile is one decoded owner name.
type OwnerFile struct {
	// AnsiLength is the first byte, as stored: the single-byte slot's name
	// length.
	AnsiLength uint8
	// UTF16Length is the length word at the layout's offset: UTF-16 code
	// units.
	UTF16Length uint16
	// UTF16Offset is the offset of the first UTF-16 code unit: UTF16SlotA or
	// UTF16SlotB.
	UTF16Offset int
	// SingleByte is the name in the single-byte slot, when that slot is valid
	// UTF-8.
	SingleByte *string
	// UTF16 is the name in the UTF-16LE slot.
	UTF16 *string
}

// Owner returns the name this reader reports, preferring the Unicode slot.
func (o OwnerFile) Owner() (string, bool) {
	if o.UTF16 != nil {
		return *o.UTF16, true
	}
	if o.SingleByte != nil {
		return *o.SingleByte, true
	}
	return "", false
}

// SlotsAgree reports whether both slots carry a name and agree exactly.  An
// empty slot means "not written", not "disagrees".
func (o OwnerFile) SlotsAgree() bool {
	if o.SingleByte == nil || o.UTF16 == nil {
		return true
	}
	return *o.SingleByte == *o.UTF16
}

// Layout returns the layout label, for the fact list.
func (o OwnerFile) Layout() string {
	if o.UTF16Offset == UTF16SlotB {
		return "54-byte single-byte slot"
	}
	return "53-byte single-byte slot"
}

type candidate struct {
	utf16Length uint16
	utf16Offset int
	utf16       *string
	total       int
}

// Decode reads the owner name slots of one owner file.  The decision is a
// pure function of the bytes.
func Decode(bytes []byte) (*OwnerFile, error) {
	first := byte(0)
	if len(bytes) > 0 {
		first = bytes[0]
	}
	ansiLength := int(first)
	if ansiLength > SingleByteSlotB {
		return nil, &Error{Kind: ErrNotAnOwnerFile, First: first}
	}
	if len(bytes) < MinBytes {
		return nil, &Error{Kind: ErrTruncated, Found: len(bytes), Needed: MinBytes, First: first}
	}

	candidates := []*candidate{
		makeCandidate(bytes, UTF16LengthA, UTF16SlotA, SingleByteSlotA, MaxUnitsA, LayoutABytes),
		makeCandidate(bytes, UTF16LengthB, UTF16SlotB, SingleByteSlotB, MaxUnitsB, LayoutBBytes),
	}
	// A file shorter than the layout its own length words describe is
	// truncated, not a different layout: say which size was needed.
	short := -1
	for _, value := range candidates {
		if value != nil && (short < 0 || value.total < short) {
			short = value.total
		}
	}
	var decoded *candidate
	for _, value := range candidates {
		if value != nil && len(bytes) >= value.total {
			decoded = value
			break
		}
	}
	if decoded == nil {
		if short >= 0 {
			return nil, &Error{Kind: ErrTruncated, Found: len(bytes), Needed: short, First: first}
		}
		return nil, &Error{Kind: ErrNoLayout, AnsiLength: first, First: first}
	}

	singleByte := singleByteName(bytes, ansiLength)
	if singleByte == nil && decoded.utf16 == nil {
		return nil, &Error{Kind: ErrNoName, First: first}
	}
	return &OwnerFile{
		AnsiLength:  first,
		UTF16Length: decoded.utf16Length,
		UTF16Offset: decoded.utf16Offset,
		SingleByte:  singleByte,
		UTF16:       decoded.utf16,
	}, nil
}

// makeCandidate returns the layout when its length word fits the slot.
func makeCandidate(bytes []byte, lengthAt, utf16Offset, ansiSlot, maxUnits, total int) *candidate {
	if len(bytes) < ansiSlot+1 || len(bytes) < lengthAt+2 {
		return nil
	}
	ansiLength := int(bytes[0])
	if ansiLength > ansiSlot {
		return nil
	}
	utf16Length := int(bytes[lengthAt]) | int(bytes[lengthAt+1])<<8
	if utf16Length == 0 || utf16Length > maxUnits {
		return nil
	}
	end := utf16Offset + utf16Length*2
	if end > len(bytes) {
		return nil
	}
	// The rest of the single-byte slot is NUL or space padding; a slot that
	// carries other bytes does not belong to this name of this length.
	for _, value := range bytes[1+ansiLength : ansiSlot+1] {
		if value != 0 && value != ' ' {
			return nil
		}
	}
	return &candidate{
		utf16Length: uint16(utf16Length),
		utf16Offset: utf16Offset,
		utf16:       decodeUTF16(bytes[utf16Offset:end]),
		total:       total,
	}
}

// singleByteName reads the single-byte slot for the length the first byte
// states; a name is accepted only when it is valid UTF-8.
func singleByteName(bytes []byte, ansiLength int) *string {
	if ansiLength == 0 {
		return nil
	}
	raw := bytes[1 : 1+ansiLength]
	if !utf8.Valid(raw) {
		return nil
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil
	}
	return &text
}

// decodeUTF16 reads the UTF-16 slot to the code-unit count the file states.  A
// length that runs into a zero unit is not a name; the bytes after the name in
// the same slot are not interpreted.  Unpaired surrogates are not text.
func decodeUTF16(slot []byte) *string {
	values := make([]uint16, 0, len(slot)/2)
	for index := 0; index+1 < len(slot); index += 2 {
		unit := uint16(slot[index]) | uint16(slot[index+1])<<8
		if unit == 0 {
			return nil
		}
		values = append(values, unit)
	}
	decoded, ok := decodeUTF16Strict(values)
	if !ok {
		return nil
	}
	text := strings.TrimSpace(decoded)
	if text == "" {
		return nil
	}
	return &text
}

func decodeUTF16Strict(units []uint16) (string, bool) {
	var out strings.Builder
	out.Grow(len(units))
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if index+1 >= len(units) {
				return "", false
			}
			low := units[index+1]
			if low < 0xDC00 || low > 0xDFFF {
				return "", false
			}
			value := 0x10000 + (rune(unit)-0xD800)<<10 + (rune(low) - 0xDC00)
			out.WriteRune(value)
			index++
		case unit >= 0xDC00 && unit <= 0xDFFF:
			return "", false
		default:
			out.WriteRune(rune(unit))
		}
	}
	return out.String(), true
}

// IsOwnerFileName reports whether a stored file name is an Office owner file
// name: a base name that begins with "~$" and has at least one character after
// it.  Both "/" and "\" separators are accepted.
func IsOwnerFileName(name string) bool {
	normalized := strings.ReplaceAll(name, "\\", "/")
	base := normalized
	if index := strings.LastIndexByte(normalized, '/'); index >= 0 {
		base = normalized[index+1:]
	}
	return len(base) > 2 && strings.HasPrefix(base, "~$")
}

// Detect reports whether head looks like one of the two known owner-file
// layouts.  It is a structural sniff, not a decode: the two layouts carry no
// magic, so callers should combine it with [IsOwnerFileName] and treat a
// successful [Decode] as the actual evidence.
func Detect(head []byte) bool {
	if len(head) < MinBytes {
		return false
	}
	if int(head[0]) > SingleByteSlotB {
		return false
	}
	if makeCandidate(head, UTF16LengthA, UTF16SlotA, SingleByteSlotA, MaxUnitsA, LayoutABytes) != nil {
		return true
	}
	return makeCandidate(head, UTF16LengthB, UTF16SlotB, SingleByteSlotB, MaxUnitsB, LayoutBBytes) != nil
}

// Open reads and decodes one owner file from a source.
//
// Structural failures are mapped onto the source error taxonomy: an unknown
// variant (impossible length byte or no known layout) is ErrUnsupported,
// truncation is ErrUnexpectedEOF, and a file whose slots carry no name is
// ErrCorrupt.  A source above [MaxBytes] is refused as ErrUnsupported.  The
// [Decode] error text, with the exact byte counts, is preserved in the reason.
func Open(src source.ByteSource) (*OwnerFile, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	length := src.Len()
	if length > MaxBytes {
		return nil, &source.Error{
			Kind: source.ErrUnsupported,
			Reason: fmt.Sprintf(
				"the file is %d bytes, above the %d-byte bound for an Office owner file",
				length, MaxBytes),
		}
	}
	data, err := source.ReadVecAt(src, 0, length)
	if err != nil {
		return nil, err
	}
	owner, err := Decode(data)
	if err == nil {
		return owner, nil
	}
	var detail *Error
	if !errors.As(err, &detail) {
		return nil, err
	}
	kind := source.ErrUnsupported
	switch {
	case errors.Is(detail.Kind, ErrTruncated):
		kind = source.ErrUnexpectedEOF
	case errors.Is(detail.Kind, ErrNoName):
		kind = source.ErrCorrupt
	}
	return nil, &source.Error{Kind: kind, Reason: detail.Error()}
}
