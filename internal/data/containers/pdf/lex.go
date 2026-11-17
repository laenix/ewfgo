// Package pdf reads PDF documents: object syntax, stream filters and
// cross-reference chains, and the facts an investigation reads out of the
// object graph.
//
// The reader is deliberately structural. It does not render pages or run
// JavaScript; it resolves the objects a PDF records and turns the parts that
// matter to an investigation — document identity, producer, dates, actions,
// embedded files, metadata — into facts. For an encrypted file the
// dictionaries and numbers are still read (they are not encrypted) while
// strings and streams are left opaque and the encryption handler is named.
// When a user password is supplied through [OpenWithPassword] and the handler
// is one this reader implements (Standard security handler V1/V2/V4/V5,
// R2–R6), strings and stream bodies are decrypted before they are decoded; a
// wrong password leaves the document opaque with a note.
//
// This is a Go port of forensic-core's data/containers/pdf module.
package pdf

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Whitespace a PDF tokenizer skips: NUL, tab, line feed, form feed, carriage
// return and space.
func isWhitespace(b byte) bool {
	return b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20
}

// isDelimiter reports punctuation that ends a token even when it is not
// whitespace.
func isDelimiter(b byte) bool {
	switch b {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

// isTokenEnd reports a token terminator.
func isTokenEnd(b byte) bool { return isWhitespace(b) || isDelimiter(b) }

const (
	// MaxNameBytes is the longest name this parser keeps. PDF names are short;
	// a name longer than this is a corrupt length field, not a name.
	MaxNameBytes = 1024
	// DefaultMaxDepth is the deepest array/dictionary nesting accepted.
	DefaultMaxDepth = 64
	// DefaultMaxValues is the most values one object may contain.
	DefaultMaxValues = 200_000
)

// Reference is a reference to an indirect object: `number generation R`.
type Reference struct {
	Number     uint32
	Generation uint16
}

// String renders the reference as it is written in a file.
func (r Reference) String() string {
	return fmt.Sprintf("%d %d R", r.Number, r.Generation)
}

// ValueKind names the type of a PDF value.
type ValueKind uint8

const (
	// KindNull is the null object.
	KindNull ValueKind = iota
	// KindBoolean is true or false.
	KindBoolean
	// KindInteger is an integer.
	KindInteger
	// KindReal is a real number.
	KindReal
	// KindString is a literal or hexadecimal string, decoded to bytes.
	KindString
	// KindName is a /Name, decoded (with #xx escapes applied).
	KindName
	// KindArray is an array.
	KindArray
	// KindDictionary is a dictionary.
	KindDictionary
	// KindReference is an indirect reference.
	KindReference
)

// Value is one parsed PDF value. The zero value is null.
type Value struct {
	kind    ValueKind
	boolean bool
	integer int64
	real    float64
	bytes   []byte
	name    []byte
	array   []Value
	dict    *Dict
	ref     Reference
}

// NullValue returns the null value.
func NullValue() Value { return Value{kind: KindNull} }

// BoolValue returns a boolean value.
func BoolValue(v bool) Value { return Value{kind: KindBoolean, boolean: v} }

// IntValue returns an integer value.
func IntValue(v int64) Value { return Value{kind: KindInteger, integer: v} }

// RealValue returns a real value.
func RealValue(v float64) Value { return Value{kind: KindReal, real: v} }

// StringValue returns a string value with the given decoded bytes.
func StringValue(b []byte) Value {
	return Value{kind: KindString, bytes: append([]byte(nil), b...)}
}

// NameValue returns a name value with the given decoded bytes.
func NameValue(b []byte) Value {
	return Value{kind: KindName, name: append([]byte(nil), b...)}
}

// ArrayValue returns an array value holding a copy of values.
func ArrayValue(values []Value) Value {
	return Value{kind: KindArray, array: append([]Value(nil), values...)}
}

// DictValue returns a dictionary value.
func DictValue(d *Dict) Value { return Value{kind: KindDictionary, dict: d} }

// RefValue returns an indirect reference value.
func RefValue(r Reference) Value { return Value{kind: KindReference, ref: r} }

// Kind returns the value's type.
func (v Value) Kind() ValueKind { return v.kind }

// AsInt returns the value as an integer, accepting a real with no fraction
// because some writers emit /Length 12.0.
func (v Value) AsInt() (int64, bool) {
	switch v.kind {
	case KindInteger:
		return v.integer, true
	case KindReal:
		if math.Trunc(v.real) == v.real && !math.IsInf(v.real, 0) && !math.IsNaN(v.real) {
			return int64(v.real), true
		}
	}
	return 0, false
}

// AsName returns the value's decoded name bytes.
func (v Value) AsName() ([]byte, bool) {
	if v.kind == KindName {
		return v.name, true
	}
	return nil, false
}

// AsDict returns the value's dictionary.
func (v Value) AsDict() (*Dict, bool) {
	if v.kind == KindDictionary && v.dict != nil {
		return v.dict, true
	}
	return nil, false
}

// AsArray returns the value's array.
func (v Value) AsArray() ([]Value, bool) {
	if v.kind == KindArray {
		return v.array, true
	}
	return nil, false
}

// AsBool returns the value's boolean.
func (v Value) AsBool() (bool, bool) {
	if v.kind == KindBoolean {
		return v.boolean, true
	}
	return false, false
}

// AsString returns the value's decoded string bytes.
func (v Value) AsString() ([]byte, bool) {
	if v.kind == KindString {
		return v.bytes, true
	}
	return nil, false
}

// AsReference returns the value's indirect reference.
func (v Value) AsReference() (Reference, bool) {
	if v.kind == KindReference {
		return v.ref, true
	}
	return Reference{}, false
}

// IsName reports whether value is the name wanted, case-sensitively.
func IsName(value Value, wanted []byte) bool {
	name, ok := value.AsName()
	return ok && string(name) == string(wanted)
}

// Clone returns a deep copy of the value.
func (v Value) Clone() Value {
	out := v
	switch v.kind {
	case KindString:
		out.bytes = append([]byte(nil), v.bytes...)
	case KindName:
		out.name = append([]byte(nil), v.name...)
	case KindArray:
		out.array = make([]Value, len(v.array))
		for i := range v.array {
			out.array[i] = v.array[i].Clone()
		}
	case KindDictionary:
		out.dict = v.dict.Clone()
	}
	return out
}

// String renders a short description for diagnostics.
func (v Value) String() string {
	switch v.kind {
	case KindNull:
		return "null"
	case KindBoolean:
		return strconv.FormatBool(v.boolean)
	case KindInteger:
		return strconv.FormatInt(v.integer, 10)
	case KindReal:
		return strconv.FormatFloat(v.real, 'g', -1, 64)
	case KindString:
		return fmt.Sprintf("(%d bytes)", len(v.bytes))
	case KindName:
		return "/" + lossyUTF8(v.name)
	case KindArray:
		return fmt.Sprintf("[%d values]", len(v.array))
	case KindDictionary:
		if v.dict == nil {
			return "<<>>"
		}
		return fmt.Sprintf("<<%d entries>>", v.dict.Len())
	case KindReference:
		return v.ref.String()
	}
	return "?"
}

// Dict is a PDF dictionary. Keys are name bytes, because a PDF name is a byte
// string and `#xx` escapes may produce any byte; Go strings carry arbitrary
// bytes, so they are the key type.
//
// Duplicate keys take the last value, which is what readers do.
type Dict struct {
	entries map[string]Value
}

// NewDict returns an empty dictionary.
func NewDict() *Dict { return &Dict{entries: make(map[string]Value)} }

// Set inserts or replaces the value for key.
func (d *Dict) Set(key string, value Value) {
	if d.entries == nil {
		d.entries = make(map[string]Value)
	}
	d.entries[key] = value
}

// SetBytes inserts or replaces the value for a byte key.
func (d *Dict) SetBytes(key []byte, value Value) { d.Set(string(key), value) }

// Get returns the value for key.
func (d *Dict) Get(key []byte) (Value, bool) {
	if d == nil {
		return Value{}, false
	}
	v, ok := d.entries[string(key)]
	return v, ok
}

// GetStringKey returns the value for a string key.
func (d *Dict) GetStringKey(key string) (Value, bool) {
	if d == nil {
		return Value{}, false
	}
	v, ok := d.entries[key]
	return v, ok
}

// Contains reports whether the dictionary has key.
func (d *Dict) Contains(key []byte) bool {
	if d == nil {
		return false
	}
	_, ok := d.entries[string(key)]
	return ok
}

// Len returns the number of entries.
func (d *Dict) Len() int {
	if d == nil {
		return 0
	}
	return len(d.entries)
}

// DictItem is one key/value pair from a dictionary, in sorted key order.
type DictItem struct {
	Key   []byte
	Value Value
}

// Items returns the entries in sorted key order, matching the Rust BTreeMap.
func (d *Dict) Items() []DictItem {
	if d == nil || len(d.entries) == 0 {
		return nil
	}
	keys := make([]string, 0, len(d.entries))
	for key := range d.entries {
		keys = append(keys, key)
	}
	sortStrings(keys)
	out := make([]DictItem, 0, len(keys))
	for _, key := range keys {
		out = append(out, DictItem{Key: []byte(key), Value: d.entries[key]})
	}
	return out
}

// Keys returns the dictionary keys in sorted order.
func (d *Dict) Keys() [][]byte {
	items := d.Items()
	out := make([][]byte, len(items))
	for i, item := range items {
		out[i] = item.Key
	}
	return out
}

// GetName returns the value for key when it is a name.
func (d *Dict) GetName(key []byte) ([]byte, bool) {
	v, ok := d.Get(key)
	if !ok {
		return nil, false
	}
	return v.AsName()
}

// GetInt returns the value for key when it is an integer (or integral real).
func (d *Dict) GetInt(key []byte) (int64, bool) {
	v, ok := d.Get(key)
	if !ok {
		return 0, false
	}
	return v.AsInt()
}

// GetBool returns the value for key when it is a boolean.
func (d *Dict) GetBool(key []byte) (bool, bool) {
	v, ok := d.Get(key)
	if !ok {
		return false, false
	}
	return v.AsBool()
}

// GetDict returns the value for key when it is a dictionary.
func (d *Dict) GetDict(key []byte) (*Dict, bool) {
	v, ok := d.Get(key)
	if !ok {
		return nil, false
	}
	return v.AsDict()
}

// GetArray returns the value for key when it is an array.
func (d *Dict) GetArray(key []byte) ([]Value, bool) {
	v, ok := d.Get(key)
	if !ok {
		return nil, false
	}
	return v.AsArray()
}

// GetRef returns the value for key when it is an indirect reference.
func (d *Dict) GetRef(key []byte) (Reference, bool) {
	v, ok := d.Get(key)
	if !ok {
		return Reference{}, false
	}
	return v.AsReference()
}

// Clone returns a deep copy of the dictionary.
func (d *Dict) Clone() *Dict {
	if d == nil {
		return nil
	}
	out := NewDict()
	for key, value := range d.entries {
		out.entries[key] = value.Clone()
	}
	return out
}

// sortStrings is a small insertion sort: dictionaries are short and this keeps
// the package free of an extra import in its hot path.
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// Parser is a recursive-descent parser over one byte slice.
//
// The slice is a window into the evidence; the parser never looks outside it.
// base is added to positions in error messages so an examiner sees the file
// offset, not the offset inside the window.
type Parser struct {
	bytes     []byte
	position  int
	depth     int
	values    int
	maxDepth  int
	maxValues int
	base      uint64
}

// NewParser returns a parser with the default nesting and value limits.
func NewParser(bytes []byte) *Parser {
	return NewParserWithLimits(bytes, DefaultMaxDepth, DefaultMaxValues)
}

// NewParserWithLimits returns a parser with explicit nesting and value limits.
func NewParserWithLimits(bytes []byte, maxDepth, maxValues int) *Parser {
	return &Parser{bytes: bytes, maxDepth: maxDepth, maxValues: maxValues}
}

// WithBase returns the parser with an error-position base offset.
func (p *Parser) WithBase(base uint64) *Parser {
	p.base = base
	return p
}

// Position returns the current byte position in the window.
func (p *Parser) Position() int { return p.position }

// SetPosition moves the parser, clamped to the window.
func (p *Parser) SetPosition(position int) {
	if position < 0 {
		position = 0
	}
	if position > len(p.bytes) {
		position = len(p.bytes)
	}
	p.position = position
}

// Remaining returns the bytes from the current position to the end.
func (p *Parser) Remaining() []byte { return p.bytes[p.position:] }

// AtEnd reports whether the parser has consumed the window.
func (p *Parser) AtEnd() bool { return p.position >= len(p.bytes) }

func (p *Parser) errorf(format string, args ...any) error {
	return corrupt(p.base+uint64(p.position), "PDF syntax at byte %d: %s",
		p.base+uint64(p.position), fmt.Sprintf(format, args...))
}

// SkipSpace skips whitespace and `%` comments.
func (p *Parser) SkipSpace() {
	for {
		for p.position < len(p.bytes) && isWhitespace(p.bytes[p.position]) {
			p.position++
		}
		if p.position < len(p.bytes) && p.bytes[p.position] == '%' {
			for p.position < len(p.bytes) && p.bytes[p.position] != '\n' && p.bytes[p.position] != '\r' {
				p.position++
			}
			continue
		}
		return
	}
}

// TakeKeyword reads a keyword (`obj`, `endobj`, `stream`, `trailer`, …) if it
// is next. A keyword must end at a delimiter or whitespace, so `truex` is not
// `true`.
func (p *Parser) TakeKeyword(keyword []byte) bool {
	p.SkipSpace()
	if len(p.bytes)-p.position < len(keyword) {
		return false
	}
	if string(p.bytes[p.position:p.position+len(keyword)]) != string(keyword) {
		return false
	}
	end := p.position + len(keyword)
	if end < len(p.bytes) && !isTokenEnd(p.bytes[end]) {
		return false
	}
	p.position = end
	return true
}

// ExpectKeyword reads a keyword or fails naming the expected text.
func (p *Parser) ExpectKeyword(keyword []byte) error {
	if p.TakeKeyword(keyword) {
		return nil
	}
	return p.errorf("expected `%s`", string(keyword))
}

// ParseValue parses one value.
func (p *Parser) ParseValue() (Value, error) {
	p.SkipSpace()
	if p.depth >= p.maxDepth {
		return Value{}, limitError("PDF object nesting deeper than %d levels", p.maxDepth)
	}
	p.values++
	if p.values > p.maxValues {
		return Value{}, limitError("PDF object holds more than %d values", p.maxValues)
	}
	if p.position >= len(p.bytes) {
		return Value{}, p.errorf("unexpected end of object")
	}
	b := p.bytes[p.position]
	switch {
	case b == '/':
		name, err := p.ParseName()
		if err != nil {
			return Value{}, err
		}
		return NameValue(name), nil
	case b == '(':
		s, err := p.ParseLiteralString()
		if err != nil {
			return Value{}, err
		}
		return StringValue(s), nil
	case b == '<' && p.position+1 < len(p.bytes) && p.bytes[p.position+1] == '<':
		p.position += 2
		p.depth++
		dict, err := p.parseDictBody()
		p.depth--
		if err != nil {
			return Value{}, err
		}
		return DictValue(dict), nil
	case b == '<':
		s, err := p.ParseHexString()
		if err != nil {
			return Value{}, err
		}
		return StringValue(s), nil
	case b == '[':
		p.position++
		p.depth++
		values, err := p.parseArrayBody()
		p.depth--
		if err != nil {
			return Value{}, err
		}
		return ArrayValue(values), nil
	case b == '+' || b == '-' || b == '.' || (b >= '0' && b <= '9'):
		return p.parseNumberOrReference()
	case b == 't':
		if err := p.ExpectKeyword([]byte("true")); err != nil {
			return Value{}, err
		}
		return BoolValue(true), nil
	case b == 'f':
		if err := p.ExpectKeyword([]byte("false")); err != nil {
			return Value{}, err
		}
		return BoolValue(false), nil
	case b == 'n':
		if err := p.ExpectKeyword([]byte("null")); err != nil {
			return Value{}, err
		}
		return NullValue(), nil
	default:
		return Value{}, p.errorf("unexpected token byte 0x%02x", b)
	}
}

func (p *Parser) parseDictBody() (*Dict, error) {
	dict := NewDict()
	for {
		p.SkipSpace()
		if p.position >= len(p.bytes) {
			return nil, p.errorf("dictionary is not terminated by >>")
		}
		if p.bytes[p.position] == '>' && p.position+1 < len(p.bytes) && p.bytes[p.position+1] == '>' {
			p.position += 2
			return dict, nil
		}
		if p.bytes[p.position] != '/' {
			return nil, p.errorf("dictionary key is not a name")
		}
		key, err := p.ParseName()
		if err != nil {
			return nil, err
		}
		value, err := p.ParseValue()
		if err != nil {
			return nil, err
		}
		dict.SetBytes(key, value)
	}
}

func (p *Parser) parseArrayBody() ([]Value, error) {
	var values []Value
	for {
		p.SkipSpace()
		if p.position >= len(p.bytes) {
			return nil, p.errorf("array is not terminated by ]")
		}
		if p.bytes[p.position] == ']' {
			p.position++
			return values, nil
		}
		value, err := p.ParseValue()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
}

// ParseName parses `/Name`, applying `#xx` escapes.
func (p *Parser) ParseName() ([]byte, error) {
	p.SkipSpace()
	if p.position >= len(p.bytes) || p.bytes[p.position] != '/' {
		return nil, p.errorf("expected a name")
	}
	p.position++
	var name []byte
	for p.position < len(p.bytes) {
		b := p.bytes[p.position]
		if isTokenEnd(b) {
			break
		}
		if b == '#' {
			if p.position+2 >= len(p.bytes) {
				return nil, p.errorf("name ends inside a #xx escape")
			}
			text := string(p.bytes[p.position+1 : p.position+3])
			value, err := strconv.ParseUint(text, 16, 8)
			if err != nil {
				return nil, p.errorf("name #xx escape is not hexadecimal")
			}
			name = append(name, byte(value))
			p.position += 3
		} else {
			name = append(name, b)
			p.position++
		}
		if len(name) > MaxNameBytes {
			return nil, limitError("PDF name longer than %d bytes", MaxNameBytes)
		}
	}
	return name, nil
}

// ParseLiteralString parses a literal `(…)` string. Balanced parentheses inside
// the string are part of it; escapes and octal codes are decoded; an unescaped
// end of line becomes a single line feed.
func (p *Parser) ParseLiteralString() ([]byte, error) {
	p.SkipSpace()
	if p.position >= len(p.bytes) || p.bytes[p.position] != '(' {
		return nil, p.errorf("expected a literal string")
	}
	p.position++
	var out []byte
	nesting := 1
	for p.position < len(p.bytes) {
		b := p.bytes[p.position]
		p.position++
		switch b {
		case '\\':
			if p.position >= len(p.bytes) {
				return nil, p.errorf("string ends after a backslash")
			}
			escaped := p.bytes[p.position]
			p.position++
			switch escaped {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, 0x08)
			case 'f':
				out = append(out, 0x0C)
			case '(', ')', '\\':
				out = append(out, escaped)
			case '\r':
				// A backslash before an end of line joins the lines; CR LF
				// counts as one terminator.
				if p.position < len(p.bytes) && p.bytes[p.position] == '\n' {
					p.position++
				}
			case '\n':
				// Joined line.
			default:
				if escaped >= '0' && escaped <= '7' {
					value := uint16(escaped - '0')
					for i := 0; i < 2; i++ {
						if p.position < len(p.bytes) && p.bytes[p.position] >= '0' && p.bytes[p.position] <= '7' {
							value = value*8 + uint16(p.bytes[p.position]-'0')
							p.position++
						} else {
							break
						}
					}
					out = append(out, byte(value&0xFF))
				} else {
					out = append(out, escaped)
				}
			}
		case '(':
			nesting++
			out = append(out, b)
		case ')':
			nesting--
			if nesting == 0 {
				return out, nil
			}
			out = append(out, b)
		case '\r':
			// An unescaped carriage return is an end of line; CR LF is one
			// terminator.
			if p.position < len(p.bytes) && p.bytes[p.position] == '\n' {
				p.position++
			}
			out = append(out, '\n')
		default:
			out = append(out, b)
		}
	}
	return nil, p.errorf("literal string is not terminated by )")
}

// ParseHexString parses a `<…>` hexadecimal string. An odd final digit is
// padded with zero, which is what the format prescribes.
func (p *Parser) ParseHexString() ([]byte, error) {
	p.SkipSpace()
	if p.position >= len(p.bytes) || p.bytes[p.position] != '<' {
		return nil, p.errorf("expected a hexadecimal string")
	}
	p.position++
	var out []byte
	var high int = -1
	for {
		if p.position >= len(p.bytes) {
			return nil, p.errorf("hexadecimal string is not terminated by >")
		}
		b := p.bytes[p.position]
		p.position++
		if b == '>' {
			if high >= 0 {
				out = append(out, byte(high)<<4)
			}
			return out, nil
		}
		if isWhitespace(b) {
			continue
		}
		digit, ok := hexValue(b)
		if !ok {
			return nil, p.errorf("0x%02x is not a hexadecimal digit", b)
		}
		if high >= 0 {
			out = append(out, byte(high)<<4|digit)
			high = -1
		} else {
			high = int(digit)
		}
	}
}

func (p *Parser) parseNumberOrReference() (Value, error) {
	start := p.position
	first, err := p.scanNumber(start)
	if err != nil {
		return Value{}, err
	}
	afterFirst := p.position
	if first.kind == KindInteger && first.integer >= 0 && uint64(first.integer) <= math.MaxUint32 {
		if ref, ok := p.tryReference(uint32(first.integer), afterFirst); ok {
			return RefValue(ref), nil
		}
	}
	p.position = afterFirst
	return first, nil
}

func (p *Parser) tryReference(number uint32, afterFirst int) (Reference, bool) {
	p.SkipSpace()
	digitsStart := p.position
	for p.position < len(p.bytes) && p.bytes[p.position] >= '0' && p.bytes[p.position] <= '9' {
		p.position++
	}
	if p.position == digitsStart || p.position-digitsStart > 5 {
		p.position = afterFirst
		return Reference{}, false
	}
	text := string(p.bytes[digitsStart:p.position])
	generation, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return Reference{}, false
	}
	p.SkipSpace()
	if p.TakeKeyword([]byte("R")) {
		return Reference{Number: number, Generation: uint16(generation)}, true
	}
	p.position = afterFirst
	return Reference{}, false
}

func (p *Parser) scanNumber(start int) (Value, error) {
	position := start
	if position < len(p.bytes) && (p.bytes[position] == '+' || p.bytes[position] == '-') {
		position++
	}
	digitsStart := position
	for position < len(p.bytes) && p.bytes[position] >= '0' && p.bytes[position] <= '9' {
		position++
	}
	integerDigits := position - digitsStart
	hasDot := false
	if position < len(p.bytes) && p.bytes[position] == '.' {
		hasDot = true
		position++
		for position < len(p.bytes) && p.bytes[position] >= '0' && p.bytes[position] <= '9' {
			position++
		}
	}
	after := position
	text := string(p.bytes[start:after])
	if integerDigits == 0 && !hasDot {
		p.position = start
		return Value{}, p.errorf("expected a number")
	}
	p.position = after
	if !hasDot {
		if value, err := strconv.ParseInt(text, 10, 64); err == nil {
			return IntValue(value), nil
		}
		// An integer wider than i64 is still a number; the real form keeps the
		// magnitude and loses low digits, which is preferable to refusing the
		// whole object.
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return Value{}, p.errorf("`%s` is not a number", text)
	}
	return RealValue(value), nil
}

// ParseIndirectHeader parses `number generation obj` and leaves the position
// just after `obj`.
func (p *Parser) ParseIndirectHeader() (Reference, error) {
	p.SkipSpace()
	number, err := p.ReadUnsigned("object number")
	if err != nil {
		return Reference{}, err
	}
	p.SkipSpace()
	generation, err := p.ReadUnsigned("generation number")
	if err != nil {
		return Reference{}, err
	}
	if generation > math.MaxUint16 {
		return Reference{}, p.errorf("generation %d exceeds 65535", generation)
	}
	if err := p.ExpectKeyword([]byte("obj")); err != nil {
		return Reference{}, err
	}
	if number > math.MaxUint32 {
		return Reference{}, p.errorf("object number %d exceeds 2^32-1", number)
	}
	return Reference{Number: uint32(number), Generation: uint16(generation)}, nil
}

// ReadUnsigned reads an unsigned integer, naming what it was expected to be.
func (p *Parser) ReadUnsigned(what string) (uint64, error) {
	p.SkipSpace()
	start := p.position
	for p.position < len(p.bytes) && p.bytes[p.position] >= '0' && p.bytes[p.position] <= '9' {
		p.position++
	}
	if p.position == start {
		return 0, p.errorf("expected %s", what)
	}
	text := string(p.bytes[start:p.position])
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, p.errorf("%s `%s` is too large", what, text)
	}
	return value, nil
}

// ParseStreamStart reads the `stream` keyword and its end of line after a
// stream dictionary. It returns the position of the first data byte.
func (p *Parser) ParseStreamStart() (int, error) {
	if err := p.ExpectKeyword([]byte("stream")); err != nil {
		return 0, err
	}
	if p.position < len(p.bytes) {
		switch b := p.bytes[p.position]; {
		case b == '\r':
			p.position++
			if p.position < len(p.bytes) && p.bytes[p.position] == '\n' {
				p.position++
			}
		case b == '\n':
			p.position++
		case isWhitespace(b):
			// The specification requires CRLF or LF. A lone other byte is
			// tolerated only when it is whitespace.
			p.position++
		default:
			return 0, p.errorf("`stream` is not followed by an end of line")
		}
	} else {
		return 0, p.errorf("`stream` is not followed by an end of line")
	}
	return p.position, nil
}

func hexValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// ParseFirstValue parses the first value in bytes, ignoring whatever follows.
func ParseFirstValue(bytes []byte) (Value, error) {
	p := NewParser(bytes)
	value, err := p.ParseValue()
	if err != nil {
		return Value{}, err
	}
	p.SkipSpace()
	return value, nil
}

// ParseIndirectPrefix parses `number generation obj` at the start of bytes,
// returning the reference and the offset of the value that follows.
func ParseIndirectPrefix(bytes []byte) (Reference, int, error) {
	p := NewParser(bytes)
	ref, err := p.ParseIndirectHeader()
	if err != nil {
		return Reference{}, 0, err
	}
	return ref, p.Position(), nil
}

// lossyUTF8 converts bytes to a string, replacing invalid UTF-8 with U+FFFD.
func lossyUTF8(b []byte) string {
	return strings.ToValidUTF8(string(b), "�")
}

// corrupt builds a corrupt-data error at a byte offset.
func corrupt(offset uint64, format string, args ...any) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: fmt.Sprintf(format, args...)}
}

// unsupported builds an unsupported-feature error.
func unsupported(format string, args ...any) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(format, args...)}
}

// limitError builds an unsupported-feature error for a resource bound. The
// bytes are readable in principle, but this reader refuses to expand them.
func limitError(format string, args ...any) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(format, args...)}
}
