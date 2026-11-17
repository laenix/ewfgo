package pst

import (
	"encoding/binary"
	"math"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// textContext is what a property context declares for its PtypString8 values.
type textContext struct {
	// ansi is true for an ANSI store, where PtypString8 is the normal text
	// type.
	ansi bool
	// codepage is a code page the property context itself declared.
	codepage    uint32
	hasCodepage bool
}

// decode turns one byte string into text and says how.  A declared code page
// is used only when this reader can decode it without loss.
func (c textContext) decode(bytes []byte) (string, TextBasis) {
	if c.ansi && c.hasCodepage {
		if text, ok := decodeCodePage(c.codepage, bytes); ok {
			return text, TextBasis{CodePage: c.codepage}
		}
	}
	return latin1(bytes), TextBasis{BytesPreserved: true}
}

// parseProperty types one property value.  maxMulti bounds a multi-value
// record's item count.
func parseProperty(id, kind uint16, value []byte, text textContext, maxMulti int) (Property, error) {
	property := Property{ID: id, Kind: kind}
	setBasis := func(basis TextBasis) {
		copied := basis
		property.TextBasis = &copied
	}
	switch kind {
	case 0x0001:
		property.Value = Value{Kind: ValueNull}
	case 0x0002:
		fixed, err := fixedBytes(id, kind, value, 2)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueI2, I2: int16(binary.LittleEndian.Uint16(fixed))}
	case 0x0003:
		fixed, err := fixedBytes(id, kind, value, 4)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueI4, I4: int32(binary.LittleEndian.Uint32(fixed))}
	case 0x0004:
		fixed, err := fixedBytes(id, kind, value, 4)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueFloat, Float: math.Float32frombits(binary.LittleEndian.Uint32(fixed))}
	case 0x0005:
		fixed, err := fixedBytes(id, kind, value, 8)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueDouble, Double: math.Float64frombits(binary.LittleEndian.Uint64(fixed))}
	case 0x0006:
		fixed, err := fixedBytes(id, kind, value, 8)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueCurrency, Currency: int64(binary.LittleEndian.Uint64(fixed))}
	case 0x0007:
		fixed, err := fixedBytes(id, kind, value, 8)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueAppTime, AppTime: math.Float64frombits(binary.LittleEndian.Uint64(fixed))}
	case 0x000A:
		fixed, err := fixedBytes(id, kind, value, 4)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueError, Error: binary.LittleEndian.Uint32(fixed)}
	case 0x000B:
		var flag bool
		switch len(value) {
		case 1:
			flag = value[0] != 0
		case 2:
			flag = binary.LittleEndian.Uint16(value) != 0
		default:
			return Property{}, corruptf("property 0x%04X typed BOOLEAN holds %d bytes", id, len(value))
		}
		property.Value = Value{Kind: ValueBoolean, Boolean: flag}
	case 0x0014:
		fixed, err := fixedBytes(id, kind, value, 8)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueI8, I8: int64(binary.LittleEndian.Uint64(fixed))}
	case 0x001E:
		decoded, basis := text.decode(value)
		setBasis(basis)
		property.Value = Value{Kind: ValueString, String: decoded}
	case 0x001F:
		if len(value)%2 != 0 {
			return Property{}, corruptf("property 0x%04X typed UNICODE holds an odd %d bytes", id, len(value))
		}
		property.Value = Value{Kind: ValueString, String: utf16le(value)}
	case 0x0040:
		fixed, err := fixedBytes(id, kind, value, 8)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueTime, Time: Filetime(binary.LittleEndian.Uint64(fixed))}
	case 0x000D:
		property.Value = Value{Kind: ValueObject, Object: append([]byte(nil), value...)}
	case 0x0048:
		fixed, err := fixedBytes(id, kind, value, 16)
		if err != nil {
			return Property{}, err
		}
		var clsid [16]byte
		copy(clsid[:], fixed)
		property.Value = Value{Kind: ValueCLSID, CLSID: clsid}
	case 0x0102:
		property.Value = Value{Kind: ValueBinary, Binary: append([]byte(nil), value...)}
	case 0x101E:
		decoded, basis, err := multiString8(id, value, text, maxMulti)
		if err != nil {
			return Property{}, err
		}
		setBasis(basis)
		property.Value = Value{Kind: ValueMultiString, MultiString: decoded}
	case 0x101F:
		decoded, err := multiString16(id, value, maxMulti)
		if err != nil {
			return Property{}, err
		}
		property.Value = Value{Kind: ValueMultiString, MultiString: decoded}
	default:
		property.Value = Value{Kind: ValueUnsupported, UnsupportedKind: kind, UnsupportedLen: len(value)}
	}
	return property, nil
}

func fixedBytes(id, kind uint16, value []byte, size int) ([]byte, error) {
	if len(value) != size {
		return nil, corruptf("property 0x%04X typed 0x%04X holds %d bytes, not %d", id, kind, len(value), size)
	}
	return value, nil
}

// multiValueSlices splits a PtypMultipleString record: ulCount, ulCount
// offsets relative to the record start, then the items.
func multiValueSlices(id uint16, bytes []byte, maxMulti int) ([][]byte, error) {
	if len(bytes) < 4 {
		return nil, corruptf("property 0x%04X typed MULTI-VALUE holds %d bytes, too short for a count", id, len(bytes))
	}
	count := uint64(binary.LittleEndian.Uint32(bytes))
	if maxMulti <= 0 {
		maxMulti = maxMultiValuesHard
	}
	if count > uint64(maxMulti) {
		return nil, limitf("property 0x%04X declares %d multi-value items, the maximum is %d", id, count, maxMulti)
	}
	dataStart := uint64(4) + count*4
	if dataStart > uint64(len(bytes)) {
		return nil, corruptf("property 0x%04X declares %d multi-value offsets in %d bytes", id, count, len(bytes))
	}
	offsets := make([]int, 0, count)
	previous := uint64(0)
	for index := uint64(0); index < count; index++ {
		offset := uint64(binary.LittleEndian.Uint32(bytes[4+index*4:]))
		if offset < dataStart || offset > uint64(len(bytes)) {
			return nil, corruptf("property 0x%04X multi-value offset %d is outside %d..=%d", id, offset, dataStart, len(bytes))
		}
		if index > 0 && offset < previous {
			return nil, corruptf("property 0x%04X multi-value offsets go backwards at %d", id, offset)
		}
		previous = offset
		offsets = append(offsets, int(offset))
	}
	slices := make([][]byte, 0, len(offsets))
	for index, start := range offsets {
		end := len(bytes)
		if index+1 < len(offsets) {
			end = offsets[index+1]
		}
		slices = append(slices, bytes[start:end])
	}
	return slices, nil
}

func multiString8(id uint16, bytes []byte, text textContext, maxMulti int) ([]string, TextBasis, error) {
	slices, err := multiValueSlices(id, bytes, maxMulti)
	if err != nil {
		return nil, TextBasis{}, err
	}
	values := make([]string, 0, len(slices))
	var first TextBasis
	var haveFirst bool
	mixed := false
	for _, slice := range slices {
		decoded, basis := text.decode(slice)
		if !haveFirst {
			first, haveFirst = basis, true
		} else if first != basis {
			mixed = true
		}
		values = append(values, decoded)
	}
	basis := first
	if mixed || !haveFirst {
		basis = TextBasis{BytesPreserved: true}
	}
	return values, basis, nil
}

func multiString16(id uint16, bytes []byte, maxMulti int) ([]string, error) {
	slices, err := multiValueSlices(id, bytes, maxMulti)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(slices))
	for _, slice := range slices {
		if len(slice)%2 != 0 {
			return nil, corruptf("property 0x%04X multi-value UTF-16 item holds an odd %d bytes", id, len(slice))
		}
		values = append(values, utf16le(slice))
	}
	return values, nil
}

// decodeCodePage decodes a byte string with a code page this reader
// implements.  false means the page is unknown or a byte has no mapping, and
// the caller must keep the bytes rather than substitute replacement
// characters.
func decodeCodePage(codepage uint32, bytes []byte) (string, bool) {
	switch codepage {
	case 65001: // UTF-8, strict
		if !utf8Valid(bytes) {
			return "", false
		}
		return trimTrailingNUL(string(bytes)), true
	case 20127: // US-ASCII
		for _, value := range bytes {
			if value >= 0x80 {
				return "", false
			}
		}
		return latin1(bytes), true
	case 28591: // ISO-8859-1
		return latin1(bytes), true
	case 1252:
		return decodeWindows1252(bytes)
	default:
		return "", false
	}
}

// decodeWindows1252 differs from Latin-1 in 0x80..0x9F.  The five unassigned
// positions make the declaration unprovable, so the bytes are preserved.
func decodeWindows1252(bytes []byte) (string, bool) {
	var high = [32]rune{
		'€', '\u0081', '‚', 'ƒ', '„', '…', '†',
		'‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u008D',
		'Ž', '\u008F', '\u0090', '‘', '’', '“', '”',
		'•', '–', '—', '˜', '™', 'š', '›',
		'œ', '\u009D', 'ž', 'Ÿ',
	}
	var builder strings.Builder
	builder.Grow(len(bytes))
	for _, value := range bytes {
		if value >= 0x80 && value <= 0x9F {
			decoded := high[value-0x80]
			switch decoded {
			case '\u0081', '\u008D', '\u008F', '\u0090', '\u009D':
				return "", false
			}
			builder.WriteRune(decoded)
			continue
		}
		builder.WriteRune(rune(value))
	}
	return trimTrailingNUL(builder.String()), true
}

func utf8Valid(bytes []byte) bool {
	// The standard library's UTF-8 validation accepts exactly what the
	// reference reader's std::str::from_utf8 accepts.
	return utf8.Valid(bytes)
}

func utf16le(bytes []byte) string {
	units := make([]uint16, 0, len(bytes)/2)
	for index := 0; index+1 < len(bytes); index += 2 {
		units = append(units, binary.LittleEndian.Uint16(bytes[index:]))
	}
	return trimTrailingNUL(string(utf16.Decode(units)))
}

func latin1(bytes []byte) string {
	runes := make([]rune, len(bytes))
	for index, value := range bytes {
		runes[index] = rune(value)
	}
	return trimTrailingNUL(string(runes))
}

func trimTrailingNUL(text string) string {
	return strings.TrimRight(text, "\x00")
}

func declaredCodepage(raw []rawProperty) (uint32, bool) {
	for _, id := range []uint16{propMessageCodepage, propInternetCodepage} {
		for _, property := range raw {
			if property.id != id || property.kind != 0x0003 {
				continue
			}
			if property.value.kind == rawHeap && len(property.value.bytes) == 4 {
				return binary.LittleEndian.Uint32(property.value.bytes), true
			}
		}
	}
	return 0, false
}

// valueOf returns the first property with id.
func valueOf(properties []Property, id uint16) *Value {
	for index := range properties {
		if properties[index].ID == id {
			return &properties[index].Value
		}
	}
	return nil
}

func propText(properties []Property, id uint16) *string {
	if value := valueOf(properties, id); value != nil && value.Kind == ValueString {
		text := value.String
		return &text
	}
	return nil
}

func propI4(properties []Property, id uint16) *int32 {
	if value := valueOf(properties, id); value != nil && value.Kind == ValueI4 {
		number := value.I4
		return &number
	}
	return nil
}

// propUnsigned returns a non-negative integer property, whichever signed
// width the store used.
func propUnsigned(properties []Property, id uint16) *uint32 {
	value := valueOf(properties, id)
	if value == nil {
		return nil
	}
	var number int64
	switch value.Kind {
	case ValueI2:
		number = int64(value.I2)
	case ValueI4:
		number = int64(value.I4)
	case ValueI8:
		number = value.I8
	default:
		return nil
	}
	if number < 0 || number > int64(^uint32(0)) {
		return nil
	}
	result := uint32(number)
	return &result
}

func propTime(properties []Property, id uint16) *Filetime {
	if value := valueOf(properties, id); value != nil && value.Kind == ValueTime {
		time := value.Time
		return &time
	}
	return nil
}

func propBool(properties []Property, id uint16) *bool {
	if value := valueOf(properties, id); value != nil && value.Kind == ValueBoolean {
		flag := value.Boolean
		return &flag
	}
	return nil
}

func propBinary(properties []Property, id uint16) []byte {
	if value := valueOf(properties, id); value != nil && value.Kind == ValueBinary {
		return append([]byte(nil), value.Binary...)
	}
	return nil
}

// displayList is one string or the items of a multi-value string exactly as
// stored.  An absent property is an empty list, not one empty item.
func displayList(properties []Property, id uint16) []string {
	value := valueOf(properties, id)
	if value == nil {
		return nil
	}
	switch value.Kind {
	case ValueString:
		return []string{value.String}
	case ValueMultiString:
		return append([]string(nil), value.MultiString...)
	default:
		return nil
	}
}

// propertyLen is the stored byte length of a property.  Text is measured in
// UTF-16 code units, which is how the property context holds it.
func propertyLen(properties []Property, id uint16) *uint64 {
	value := valueOf(properties, id)
	if value == nil {
		return nil
	}
	var length uint64
	switch value.Kind {
	case ValueString:
		length = uint64(len(utf16.Encode([]rune(value.String))) * 2)
	case ValueMultiString:
		for _, item := range value.MultiString {
			length += uint64(len(utf16.Encode([]rune(item))) * 2)
		}
	case ValueBinary:
		length = uint64(len(value.Binary))
	case ValueObject:
		length = uint64(len(value.Object))
	case ValueUnsupported:
		length = uint64(value.UnsupportedLen)
	}
	return &length
}

// senderOf returns the sender address and the property that supplied it.
func senderOf(properties []Property) (*string, string) {
	if address := propText(properties, propSenderSMTPAddress); address != nil {
		return address, "smtp-address"
	}
	if address := propText(properties, propSenderSMTP); address != nil {
		return address, "smtp-address-book"
	}
	if address := propText(properties, propSenderEmail); address != nil {
		return address, "email-address"
	}
	return nil, ""
}

func siblingNID(nid uint64, kind uint8) uint64 {
	return (nid &^ 0x1F) | uint64(kind)
}
