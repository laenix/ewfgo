package zfs

import (
	"fmt"
	"strings"
)

// The XDR nvlist a vdev label carries. ZFS packs it with NV_ENCODE_XDR, so
// every integer is big-endian, strings are length-prefixed and padded to four
// bytes, and nested lists are embedded whole. The first pair's encoded size
// bounds the pair, which is what lets a decoder skip a value it does not
// understand without desynchronising the stream.

const (
	xdrDataTypeBoolean      = 1
	xdrDataTypeByte         = 2
	xdrDataTypeInt16        = 3
	xdrDataTypeUint16       = 4
	xdrDataTypeInt32        = 5
	xdrDataTypeUint32       = 6
	xdrDataTypeInt64        = 7
	xdrDataTypeUint64       = 8
	xdrDataTypeString       = 9
	xdrDataTypeByteArray    = 10
	xdrDataTypeInt16Array   = 11
	xdrDataTypeUint16Array  = 12
	xdrDataTypeInt32Array   = 13
	xdrDataTypeUint32Array  = 14
	xdrDataTypeInt64Array   = 15
	xdrDataTypeUint64Array  = 16
	xdrDataTypeStringArray  = 17
	xdrDataTypeHrtime       = 18
	xdrDataTypeNvlist       = 19
	xdrDataTypeNvlistArray  = 20
	xdrDataTypeBooleanValue = 21
	xdrDataTypeInt8         = 22
	xdrDataTypeUint8        = 23
	xdrDataTypeBooleanArray = 24
	xdrDataTypeInt8Array    = 25
	xdrDataTypeUint8Array   = 26
	xdrDataTypeDouble       = 27
)

// xdrStreamPrefix is the four bytes real pools put before the version word:
// every vdev label in the examined pools begins 01 01 00 00, then version 0.
const xdrStreamPrefix = 0x01010000

type valueKind uint8

const (
	valueBoolean valueKind = iota
	valueSigned
	valueUnsigned
	valueString
	valueBytes
	valueList
	valueLists
	valueSignedArray
	valueUnsignedArray
	valueStringArray
)

// Value is one decoded nvlist value.
type Value struct {
	kind          valueKind
	signed        int64
	unsigned      uint64
	text          string
	bytes         []byte
	list          *NvList
	lists         []NvList
	signedArray   []int64
	unsignedArray []uint64
	stringArray   []string
}

// NvList is a decoded list, in the order the pairs were written.
type NvList struct {
	entries []nvEntry
}

type nvEntry struct {
	name  string
	value Value
}

func (n *NvList) get(name string) (Value, bool) {
	if n == nil {
		return Value{}, false
	}
	for _, entry := range n.entries {
		if entry.name == name {
			return entry.value, true
		}
	}
	return Value{}, false
}

// String returns a string value, when the pair holds one.
func (n *NvList) String(name string) string {
	value, ok := n.get(name)
	if !ok || value.kind != valueString {
		return ""
	}
	return value.text
}

// Unsigned returns an unsigned value, or a non-negative signed one.
func (n *NvList) Unsigned(name string) (uint64, bool) {
	value, ok := n.get(name)
	if !ok {
		return 0, false
	}
	switch value.kind {
	case valueUnsigned:
		return value.unsigned, true
	case valueSigned:
		if value.signed < 0 {
			return 0, false
		}
		return uint64(value.signed), true
	}
	return 0, false
}

// List returns a nested list.
func (n *NvList) List(name string) *NvList {
	value, ok := n.get(name)
	if !ok || value.kind != valueList {
		return nil
	}
	return value.list
}

// Lists returns a nested list array.
func (n *NvList) Lists(name string) []NvList {
	value, ok := n.get(name)
	if !ok || value.kind != valueLists {
		return nil
	}
	return value.lists
}

// Names returns every pair's name in stored order.
func (n *NvList) Names() []string {
	if n == nil {
		return nil
	}
	out := make([]string, 0, len(n.entries))
	for _, entry := range n.entries {
		out = append(out, entry.name)
	}
	return out
}

// Len returns the pair count.
func (n *NvList) Len() int {
	if n == nil {
		return 0
	}
	return len(n.entries)
}

// parseNvlist decodes one XDR nvlist that occupies bytes. Trailing zero
// padding is normal; any other trailing byte is not.
func parseNvlist(bytes []byte) (*NvList, error) {
	list, used, err := decodeNvlistPrefix(bytes)
	if err != nil {
		return nil, err
	}
	remaining := bytes[used:]
	for _, b := range remaining {
		if b != 0 {
			return nil, corruptf("%d trailing byte(s) after the nvlist", len(remaining))
		}
	}
	return list, nil
}

// decodeNvlistPrefix decodes the list at the start of bytes, reporting how
// many bytes it used. A vdev label's nvlist sits in a fixed 112 KiB buffer
// that is not length-prefixed, so the label reader accepts whatever follows.
func decodeNvlistPrefix(bytes []byte) (*NvList, int, error) {
	cursor := &xdrCursor{bytes: bytes}
	first, err := cursor.u32()
	if err != nil {
		return nil, 0, err
	}
	version := first
	if first == xdrStreamPrefix {
		version, err = cursor.u32()
		if err != nil {
			return nil, 0, err
		}
	}
	list, err := decodeListBody(cursor, version, 0)
	if err != nil {
		return nil, 0, err
	}
	return list, cursor.pos, nil
}

func decodeList(cursor *xdrCursor, depth int) (*NvList, error) {
	version, err := cursor.u32()
	if err != nil {
		return nil, err
	}
	return decodeListBody(cursor, version, depth+1)
}

func decodeListBody(cursor *xdrCursor, version uint32, depth int) (*NvList, error) {
	if depth > maxNvlistDepth {
		return nil, corruptf("nvlist nests deeper than %d levels", maxNvlistDepth)
	}
	if version != 0 {
		return nil, unsupportedf("nvlist version %d; only version 0 is read", version)
	}
	flags, err := cursor.u32()
	if err != nil {
		return nil, err
	}
	if flags&^uint32(0x3) != 0 {
		return nil, corruptf("nvlist flags 0x%X have unknown bits", flags)
	}
	list := &NvList{}
	for {
		encoded, err := cursor.u32()
		if err != nil {
			return nil, err
		}
		decoded, err := cursor.u32()
		if err != nil {
			return nil, err
		}
		if encoded == 0 {
			if decoded != 0 {
				return nil, corruptf("nvlist ends with a half-zero pair")
			}
			break
		}
		start := cursor.pos
		name, err := cursor.string()
		if err != nil {
			return nil, err
		}
		kind, err := cursor.u32()
		if err != nil {
			return nil, err
		}
		nelem, err := cursor.u32()
		if err != nil {
			return nil, err
		}
		value, err := decodeValue(cursor, kind, nelem, depth)
		if err != nil {
			return nil, err
		}
		written := cursor.pos - start
		if written+8 != int(encoded) {
			return nil, corruptf("nvlist pair %q declares %d encoded bytes but holds %d", name, encoded, written+8)
		}
		for _, entry := range list.entries {
			if entry.name == name {
				return nil, corruptf("nvlist names %q twice", name)
			}
		}
		list.entries = append(list.entries, nvEntry{name: name, value: value})
		if len(list.entries) > 4096 {
			return nil, corruptf("nvlist holds more than 4096 pairs")
		}
	}
	return list, nil
}

func decodeValue(cursor *xdrCursor, kind, nelem uint32, depth int) (Value, error) {
	switch kind {
	case xdrDataTypeBoolean:
		return Value{kind: valueBoolean}, nil
	case xdrDataTypeBooleanValue, xdrDataTypeByte, xdrDataTypeUint8, xdrDataTypeUint16:
		value, err := cursor.u32()
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueUnsigned, unsigned: uint64(value)}, nil
	case xdrDataTypeInt8:
		value, err := cursor.u32()
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueSigned, signed: int64(int8(value))}, nil
	case xdrDataTypeInt16:
		value, err := cursor.u32()
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueSigned, signed: int64(int16(value))}, nil
	case xdrDataTypeInt32:
		value, err := cursor.u32()
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueSigned, signed: int64(int32(value))}, nil
	case xdrDataTypeUint32:
		value, err := cursor.u32()
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueUnsigned, unsigned: uint64(value)}, nil
	case xdrDataTypeInt64:
		value, err := cursor.u64()
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueSigned, signed: int64(value)}, nil
	case xdrDataTypeUint64, xdrDataTypeHrtime:
		value, err := cursor.u64()
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueUnsigned, unsigned: value}, nil
	case xdrDataTypeDouble:
		bytes, err := cursor.take(8)
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueBytes, bytes: append([]byte(nil), bytes...)}, nil
	case xdrDataTypeString:
		text, err := cursor.string()
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueString, text: text}, nil
	case xdrDataTypeByteArray:
		bytes, err := cursor.padded(int(nelem))
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueBytes, bytes: append([]byte(nil), bytes...)}, nil
	case xdrDataTypeInt16Array:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		values := make([]int64, 0, count)
		for i := 0; i < count; i++ {
			value, err := cursor.u32()
			if err != nil {
				return Value{}, err
			}
			values = append(values, int64(int16(value)))
		}
		return Value{kind: valueSignedArray, signedArray: values}, nil
	case xdrDataTypeUint16Array:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		values := make([]uint64, 0, count)
		for i := 0; i < count; i++ {
			value, err := cursor.u32()
			if err != nil {
				return Value{}, err
			}
			values = append(values, uint64(uint16(value)))
		}
		return Value{kind: valueUnsignedArray, unsignedArray: values}, nil
	case xdrDataTypeInt32Array:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		values := make([]int64, 0, count)
		for i := 0; i < count; i++ {
			value, err := cursor.u32()
			if err != nil {
				return Value{}, err
			}
			values = append(values, int64(int32(value)))
		}
		return Value{kind: valueSignedArray, signedArray: values}, nil
	case xdrDataTypeUint32Array:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		values := make([]uint64, 0, count)
		for i := 0; i < count; i++ {
			value, err := cursor.u32()
			if err != nil {
				return Value{}, err
			}
			values = append(values, uint64(value))
		}
		return Value{kind: valueUnsignedArray, unsignedArray: values}, nil
	case xdrDataTypeInt64Array:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		values := make([]int64, 0, count)
		for i := 0; i < count; i++ {
			value, err := cursor.u64()
			if err != nil {
				return Value{}, err
			}
			values = append(values, int64(value))
		}
		return Value{kind: valueSignedArray, signedArray: values}, nil
	case xdrDataTypeUint64Array:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		values := make([]uint64, 0, count)
		for i := 0; i < count; i++ {
			value, err := cursor.u64()
			if err != nil {
				return Value{}, err
			}
			values = append(values, value)
		}
		return Value{kind: valueUnsignedArray, unsignedArray: values}, nil
	case xdrDataTypeBooleanArray:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		for i := 0; i < count; i++ {
			if _, err := cursor.u32(); err != nil {
				return Value{}, err
			}
		}
		return Value{kind: valueBoolean}, nil
	case xdrDataTypeInt8Array, xdrDataTypeUint8Array:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		bytes, err := cursor.padded(count)
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueBytes, bytes: append([]byte(nil), bytes...)}, nil
	case xdrDataTypeStringArray:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		values := make([]string, 0, count)
		for i := 0; i < count; i++ {
			text, err := cursor.string()
			if err != nil {
				return Value{}, err
			}
			values = append(values, text)
		}
		return Value{kind: valueStringArray, stringArray: values}, nil
	case xdrDataTypeNvlist:
		child, err := decodeList(cursor, depth)
		if err != nil {
			return Value{}, err
		}
		return Value{kind: valueList, list: child}, nil
	case xdrDataTypeNvlistArray:
		count, err := cursor.arrayCount(nelem)
		if err != nil {
			return Value{}, err
		}
		children := make([]NvList, 0, count)
		for i := 0; i < count; i++ {
			child, err := decodeList(cursor, depth)
			if err != nil {
				return Value{}, err
			}
			children = append(children, *child)
		}
		return Value{kind: valueLists, lists: children}, nil
	default:
		return Value{}, unsupportedf("nvlist data type %d", kind)
	}
}

const (
	maxNvlistElements = 1 << 20
	// maxNvlistDepth bounds nested-list recursion so a hostile label cannot
	// exhaust the stack.
	maxNvlistDepth = 32
)

type xdrCursor struct {
	bytes []byte
	pos   int
}

func (c *xdrCursor) take(length int) ([]byte, error) {
	if length < 0 || c.pos > len(c.bytes)-length {
		remaining := 0
		if c.pos <= len(c.bytes) {
			remaining = len(c.bytes) - c.pos
		}
		return nil, corruptf("nvlist needs %d byte(s) at %d, only %d remain", length, c.pos, remaining)
	}
	out := c.bytes[c.pos : c.pos+length]
	c.pos += length
	return out, nil
}

func (c *xdrCursor) padded(length int) ([]byte, error) {
	out, err := c.take(length)
	if err != nil {
		return nil, err
	}
	pad := (4 - (length & 3)) & 3
	if _, err := c.take(pad); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *xdrCursor) u32() (uint32, error) {
	bytes, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]), nil
}

func (c *xdrCursor) u64() (uint64, error) {
	bytes, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return uint64(bytes[0])<<56 | uint64(bytes[1])<<48 | uint64(bytes[2])<<40 | uint64(bytes[3])<<32 |
		uint64(bytes[4])<<24 | uint64(bytes[5])<<16 | uint64(bytes[6])<<8 | uint64(bytes[7]), nil
}

func (c *xdrCursor) string() (string, error) {
	length, err := c.u32()
	if err != nil {
		return "", err
	}
	if length > 1<<20 {
		return "", corruptf("nvlist string longer than a megabyte")
	}
	bytes, err := c.padded(int(length))
	if err != nil {
		return "", err
	}
	if len(bytes) > 0 && bytes[len(bytes)-1] == 0 {
		return "", corruptf("nvlist string length includes its terminator")
	}
	if !validUTF8(bytes) {
		return "", corruptf("nvlist string is not valid UTF-8")
	}
	return string(bytes), nil
}

func (c *xdrCursor) arrayCount(declared uint32) (int, error) {
	count, err := c.u32()
	if err != nil {
		return 0, err
	}
	if count != declared {
		return 0, corruptf("nvlist array declares %d element(s) but XDR encodes %d", declared, count)
	}
	if count > maxNvlistElements {
		return 0, corruptf("nvlist array holds more than a million elements")
	}
	return int(count), nil
}

func validUTF8(bytes []byte) bool {
	return strings.ToValidUTF8(string(bytes), "\x00") == string(bytes)
}

func (v Value) String() string {
	switch v.kind {
	case valueSigned:
		return fmt.Sprintf("%d", v.signed)
	case valueUnsigned:
		return fmt.Sprintf("%d", v.unsigned)
	case valueString:
		return v.text
	case valueBoolean:
		return "true"
	default:
		return fmt.Sprintf("nvlist value kind %d", v.kind)
	}
}
