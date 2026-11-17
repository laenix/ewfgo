// Property-list parsing for UDIF resource forks.
//
// Apple writes the trailer's property list either as XML or as the binary
// `bplist00` document hdiutil produces. Both dialects are decoded here down to
// the same `resource-fork` / `blkx` structure, and every `blkx` value is
// Base64-decoded and validated as a `mish` block table before it is used.
//
// The XML reader expands no entities and drops a document type declaration by
// blanking it in place (document offsets stay stable); a declaration with an
// internal subset is left for the parser to refuse. The binary reader decodes
// only the object shapes a DMG resource fork uses: markers it does not
// understand are named errors, never guesses.

package dmg

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

// BinaryPlistSignature is the header of a binary property list.
const BinaryPlistSignature = "bplist00"

// MaxPlistObjects bounds the objects one binary property list may declare.
const MaxPlistObjects uint64 = 1_000_000

// rawTable is one decoded blkx blob and the name it was listed under.
type rawTable struct {
	name        *string
	firstSector uint64
	sectorCount uint64
	data        []byte
}

// parsePropertyList parses the resource-fork property list and decodes every
// blkx table.
func parsePropertyList(data []byte) ([]rawTable, error) {
	if bytes.HasPrefix(data, []byte(BinaryPlistSignature)) {
		return parseBinaryPropertyList(data)
	}
	text := stripDoctype(data)
	root, err := parseXMLTree(text)
	if err != nil {
		return nil, err
	}
	if root.name != "plist" {
		return nil, corruptDMG(0, fmt.Sprintf(
			"the resource fork's root element is <%s>, not <plist>", root.name))
	}
	top := firstChild(root, "dict")
	if top == nil {
		return nil, corruptDMG(0, "the property list has no top-level dictionary")
	}
	resource := dictValue(top, "resource-fork")
	if resource == nil || resource.name != "dict" {
		return nil, corruptDMG(0, "the property list has no resource-fork dictionary")
	}
	blkx := dictValue(resource, "blkx")
	if blkx == nil || blkx.name != "array" {
		return nil, corruptDMG(0, "the resource fork has no blkx array")
	}

	var tables []rawTable
	for _, entry := range blkx.children {
		if entry.name != "dict" {
			continue
		}
		name := ""
		for _, key := range []string{"Name", "CFName"} {
			value := dictValue(entry, key)
			if value != nil && value.name == "string" {
				name = value.text
				if name != "" {
					break
				}
			}
		}
		dataNode := dictValue(entry, "Data")
		if dataNode == nil {
			label := "<unnamed>"
			if name != "" {
				label = name
			}
			return nil, corruptDMG(0, fmt.Sprintf("the blkx entry %q carries no Data", label))
		}
		encoded := make([]byte, 0, len(dataNode.text))
		for index := 0; index < len(dataNode.text); index++ {
			byteValue := dataNode.text[index]
			if byteValue == ' ' || byteValue == '\t' || byteValue == '\r' || byteValue == '\n' {
				continue
			}
			encoded = append(encoded, byteValue)
		}
		data, err := decodeBase64Table(encoded)
		if err != nil {
			label := "<unnamed>"
			if name != "" {
				label = name
			}
			return nil, corruptDMG(0, fmt.Sprintf(
				"the blkx entry %q is not a Base64 block table: %v", label, err))
		}
		if err := pushRawTable(namePtr(name), data, &tables); err != nil {
			return nil, err
		}
	}
	return tables, nil
}

func namePtr(name string) *string {
	if name == "" {
		return nil
	}
	return &name
}

func decodeBase64Table(encoded []byte) ([]byte, error) {
	if len(encoded) > base64.StdEncoding.EncodedLen(MaxBlkxBytes) {
		return nil, fmt.Errorf("a block table larger than the %d-byte limit", MaxBlkxBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, err
	}
	if len(decoded) > MaxBlkxBytes {
		return nil, fmt.Errorf("a %d-byte block table, over the %d-byte limit",
			len(decoded), MaxBlkxBytes)
	}
	return decoded, nil
}

// pushRawTable validates one block table and appends it.
func pushRawTable(name *string, data []byte, tables *[]rawTable) error {
	label := "<unnamed>"
	if name != nil {
		label = *name
	}
	if len(data) < BlkxHeaderBytes {
		return corruptDMG(0, fmt.Sprintf(
			"the blkx entry %q is %d bytes, shorter than its own header", label, len(data)))
	}
	if !bytes.HasPrefix(data, []byte(BlkxSignature)) {
		return corruptDMG(0, fmt.Sprintf(
			"the blkx entry %q does not start with mish", label))
	}
	*tables = append(*tables, rawTable{
		name:        name,
		firstSector: be64(data, 8),
		sectorCount: be64(data, 16),
		data:        data,
	})
	return nil
}

// --- XML property lists -----------------------------------------------------

type xmlNode struct {
	name     string
	text     string
	children []*xmlNode
}

// parseXMLTree builds a minimal element tree. Only direct character data is
// kept; entities are never expanded.
func parseXMLTree(data []byte) (*xmlNode, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var root *xmlNode
	var stack []*xmlNode
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, corruptDMG(0, fmt.Sprintf(
				"the resource-fork property list is not readable XML: %v", err))
		}
		switch value := token.(type) {
		case xml.StartElement:
			node := &xmlNode{name: value.Name.Local}
			if len(stack) == 0 {
				if root == nil {
					root = node
				}
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, corruptDMG(0, "the property list closes an element that was never opened")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(value)
			}
		}
	}
	if root == nil {
		return nil, corruptDMG(0, "the property list is empty")
	}
	return root, nil
}

func firstChild(node *xmlNode, name string) *xmlNode {
	for _, child := range node.children {
		if child.name == name {
			return child
		}
	}
	return nil
}

// dictValue finds the value element that follows <key>name</key> in a
// dictionary.
func dictValue(dict *xmlNode, name string) *xmlNode {
	for index := 0; index < len(dict.children); index++ {
		child := dict.children[index]
		if child.name != "key" || child.text != name {
			continue
		}
		if index+1 < len(dict.children) {
			return dict.children[index+1]
		}
		return nil
	}
	return nil
}

// stripDoctype blanks a document type declaration in place, keeping offsets
// stable. A declaration with an internal subset is left for the parser to
// refuse, because this reader expands no entities.
func stripDoctype(data []byte) []byte {
	out := append([]byte(nil), data...)
	needle := []byte("<!DOCTYPE")
	start := bytes.Index(out, needle)
	if start < 0 {
		return out
	}
	var quote byte
	for index := start + len(needle); index < len(out); index++ {
		byteValue := out[index]
		if quote != 0 {
			if byteValue == quote {
				quote = 0
			}
			continue
		}
		switch byteValue {
		case '"', '\'':
			quote = byteValue
		case '[':
			return out
		case '>':
			for at := start; at <= index; at++ {
				out[at] = ' '
			}
			return out
		}
	}
	return out
}

// --- Binary property lists ---------------------------------------------------

const (
	plistNull = iota
	plistBool
	plistData
	plistString
	plistArray
	plistDict
)

type plistPair struct {
	key   int
	value int
}

// plistObject is one decoded binary property-list object.
type plistObject struct {
	kind  int
	data  []byte
	text  string
	refs  []int
	pairs []plistPair
}

// binaryPlist is a read-only view of a bplist00 document.
type binaryPlist struct {
	bytes   []byte
	offsets []int
	refSize int
	top     int
}

func openBinaryPlist(bytes []byte) (*binaryPlist, error) {
	if len(bytes) < 32 {
		return nil, corruptDMG(0, "the binary property list is shorter than its 32-byte trailer")
	}
	trailerAt := len(bytes) - 32
	trailer := bytes[trailerAt:]
	offsetSize := int(trailer[6])
	refSize := int(trailer[7])
	objectCount := be64(trailer, 8)
	top := be64(trailer, 16)
	offsetTable := be64(trailer, 24)

	if offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8 {
		return nil, corruptDMG(uint64(trailerAt+6), fmt.Sprintf(
			"the binary property-list trailer declares %d-byte offsets and %d-byte references",
			offsetSize, refSize))
	}
	if objectCount == 0 || objectCount > MaxPlistObjects {
		return nil, corruptDMG(uint64(trailerAt+8), fmt.Sprintf(
			"the binary property list declares %d objects", objectCount))
	}
	if top >= objectCount {
		return nil, corruptDMG(uint64(trailerAt+16), fmt.Sprintf(
			"the top object %d is outside the %d objects", top, objectCount))
	}
	tableBytes := objectCount * uint64(offsetSize)
	if tableBytes/uint64(offsetSize) != objectCount {
		return nil, corruptDMG(0, "the binary property-list offset table overflows")
	}
	tableEnd := offsetTable + tableBytes
	if tableEnd < offsetTable {
		return nil, corruptDMG(0, "the binary property-list offset table overflows")
	}
	if tableEnd > uint64(trailerAt) {
		return nil, corruptDMG(minU64DMG(offsetTable, uint64(trailerAt)), fmt.Sprintf(
			"the %d-entry offset table ends at %d, past the trailer at %d",
			objectCount, tableEnd, trailerAt))
	}
	if objectCount > uint64(maxIntDMG()) {
		return nil, corruptDMG(0, "the binary property list declares too many objects")
	}
	offsets := make([]int, int(objectCount))
	for index := uint64(0); index < objectCount; index++ {
		at := offsetTable + index*uint64(offsetSize)
		value, err := readBE(bytes, at, offsetSize)
		if err != nil {
			return nil, err
		}
		if value < uint64(len(BinaryPlistSignature)) || value >= offsetTable {
			return nil, corruptDMG(at, fmt.Sprintf(
				"object %d starts at %d, outside the object region %d..%d",
				index, value, len(BinaryPlistSignature), offsetTable))
		}
		offsets[index] = int(value)
	}
	return &binaryPlist{
		bytes:   bytes,
		offsets: offsets,
		refSize: refSize,
		top:     int(top),
	}, nil
}

func (p *binaryPlist) object(index int) (plistObject, error) {
	if index < 0 || index >= len(p.offsets) {
		return plistObject{}, corruptDMG(0, fmt.Sprintf(
			"object %d is outside the property list", index))
	}
	offset := p.offsets[index]
	if offset < 0 || offset >= len(p.bytes) {
		return plistObject{}, corruptDMG(uint64(offset), fmt.Sprintf(
			"object %d starts past the file", index))
	}
	marker := p.bytes[offset]
	info := marker & 0x0F
	cursor := offset + 1
	switch marker & 0xF0 {
	case 0x00:
		switch info {
		case 0x00:
			return plistObject{kind: plistNull}, nil
		case 0x08, 0x09:
			return plistObject{kind: plistBool}, nil
		default:
			return plistObject{}, corruptDMG(uint64(offset), fmt.Sprintf(
				"unsupported binary property-list marker %02X", marker))
		}
	case 0x10:
		return plistObject{}, corruptDMG(uint64(offset),
			"a binary property-list integer object is not part of a DMG resource fork")
	case 0x40:
		length, err := p.count(info, &cursor)
		if err != nil {
			return plistObject{}, err
		}
		data, err := p.slice(cursor, length)
		if err != nil {
			return plistObject{}, err
		}
		return plistObject{kind: plistData, data: data}, nil
	case 0x50:
		length, err := p.count(info, &cursor)
		if err != nil {
			return plistObject{}, err
		}
		data, err := p.slice(cursor, length)
		if err != nil {
			return plistObject{}, err
		}
		if !utf8.Valid(data) {
			return plistObject{}, corruptDMG(uint64(cursor),
				"an ASCII string in the binary property list is not UTF-8")
		}
		return plistObject{kind: plistString, text: string(data)}, nil
	case 0x60:
		length, err := p.count(info, &cursor)
		if err != nil {
			return plistObject{}, err
		}
		if length > maxIntDMG()/2 {
			return plistObject{}, corruptDMG(uint64(cursor), "a UTF-16 string length overflows")
		}
		data, err := p.slice(cursor, length*2)
		if err != nil {
			return plistObject{}, err
		}
		units := make([]uint16, length)
		for index := 0; index < length; index++ {
			units[index] = uint16(data[index*2])<<8 | uint16(data[index*2+1])
		}
		return plistObject{kind: plistString, text: string(utf16.Decode(units))}, nil
	case 0xA0:
		refs, err := p.refs(info, &cursor)
		if err != nil {
			return plistObject{}, err
		}
		return plistObject{kind: plistArray, refs: refs}, nil
	case 0xD0:
		count, err := p.count(info, &cursor)
		if err != nil {
			return plistObject{}, err
		}
		keys, err := p.readRefs(count, &cursor)
		if err != nil {
			return plistObject{}, err
		}
		values, err := p.readRefs(count, &cursor)
		if err != nil {
			return plistObject{}, err
		}
		pairs := make([]plistPair, len(keys))
		for index := range keys {
			pairs[index] = plistPair{key: keys[index], value: values[index]}
		}
		return plistObject{kind: plistDict, pairs: pairs}, nil
	case 0x80:
		return plistObject{}, corruptDMG(uint64(offset),
			"binary property-list UIDs are not needed for a DMG")
	default:
		return plistObject{}, corruptDMG(uint64(offset), fmt.Sprintf(
			"unsupported binary property-list marker %02X", marker))
	}
}

// lookup finds a dictionary value by key. Keys this reader does not understand
// as strings are skipped, never guessed. It returns -1 when the key is absent.
func (p *binaryPlist) lookup(pairs []plistPair, key string) (int, error) {
	for _, pair := range pairs {
		name, err := p.object(pair.key)
		if err != nil {
			return -1, err
		}
		if name.kind != plistString {
			continue
		}
		if name.text == key {
			return pair.value, nil
		}
	}
	return -1, nil
}

func (p *binaryPlist) readInt(info byte, cursor *int) (uint64, error) {
	var size int
	switch info {
	case 0:
		size = 1
	case 1:
		size = 2
	case 2:
		size = 4
	case 3:
		size = 8
	default:
		return 0, corruptDMG(uint64(*cursor), fmt.Sprintf(
			"a %d-byte integer is not a usable length", 1<<info))
	}
	value, err := readBE(p.bytes, uint64(*cursor), size)
	if err != nil {
		return 0, err
	}
	*cursor += size
	return value, nil
}

// count reads a length/count field: the low nibble itself, or an integer
// object that follows the marker when the nibble is 0xF.
func (p *binaryPlist) count(info byte, cursor *int) (int, error) {
	if info != 0x0F {
		return int(info), nil
	}
	if *cursor < 0 || *cursor >= len(p.bytes) {
		return 0, corruptDMG(uint64(*cursor),
			"an extended length is missing its integer object")
	}
	marker := p.bytes[*cursor]
	if marker&0xF0 != 0x10 || marker&0x0F > 3 {
		return 0, corruptDMG(uint64(*cursor), fmt.Sprintf(
			"an extended length uses marker %02X instead of an integer", marker))
	}
	(*cursor)++
	value, err := p.readInt(marker&0x0F, cursor)
	if err != nil {
		return 0, err
	}
	if value > uint64(maxIntDMG()) {
		return 0, corruptDMG(uint64(*cursor), "a binary property-list length overflows")
	}
	return int(value), nil
}

func (p *binaryPlist) refs(info byte, cursor *int) ([]int, error) {
	count, err := p.count(info, cursor)
	if err != nil {
		return nil, err
	}
	return p.readRefs(count, cursor)
}

func (p *binaryPlist) readRefs(count int, cursor *int) ([]int, error) {
	if count < 0 || count > maxIntDMG()/p.refSize {
		return nil, corruptDMG(uint64(*cursor), "a binary property-list reference array overflows")
	}
	bytes := count * p.refSize
	if _, err := p.slice(*cursor, bytes); err != nil {
		return nil, err
	}
	refs := make([]int, count)
	for index := 0; index < count; index++ {
		at := *cursor + index*p.refSize
		value, err := readBE(p.bytes, uint64(at), p.refSize)
		if err != nil {
			return nil, err
		}
		if value >= uint64(len(p.offsets)) {
			return nil, corruptDMG(uint64(at), fmt.Sprintf(
				"reference %d is outside the %d objects", value, len(p.offsets)))
		}
		refs[index] = int(value)
	}
	*cursor += bytes
	return refs, nil
}

func (p *binaryPlist) slice(start, length int) ([]byte, error) {
	if start < 0 || length < 0 || length > len(p.bytes) || start > len(p.bytes)-length {
		offset := start
		if offset < 0 {
			offset = 0
		}
		return nil, corruptDMG(uint64(offset), fmt.Sprintf(
			"a %d-byte value runs past the file", length))
	}
	return p.bytes[start : start+length], nil
}

// readBE reads a big-endian value of 1–8 bytes with bounds checks.
func readBE(bytes []byte, start uint64, size int) (uint64, error) {
	if size < 1 || size > 8 {
		return 0, corruptDMG(start, "a binary property-list field has an invalid width")
	}
	if start > uint64(len(bytes)) || uint64(size) > uint64(len(bytes))-start {
		return 0, corruptDMG(start, fmt.Sprintf(
			"a %d-byte field runs past the %d byte property list", size, len(bytes)))
	}
	var value uint64
	for index := 0; index < size; index++ {
		value = value<<8 | uint64(bytes[start+uint64(index)])
	}
	return value, nil
}

// parseBinaryPropertyList decodes every blkx table from a binary property
// list.
func parseBinaryPropertyList(bytes []byte) ([]rawTable, error) {
	plist, err := openBinaryPlist(bytes)
	if err != nil {
		return nil, err
	}
	top, err := plist.object(plist.top)
	if err != nil {
		return nil, err
	}
	if top.kind != plistDict {
		return nil, corruptDMG(0, "the binary property list's top object is not a dictionary")
	}
	resourceIndex, err := plist.lookup(top.pairs, "resource-fork")
	if err != nil {
		return nil, err
	}
	if resourceIndex < 0 {
		return nil, corruptDMG(0, "the property list has no resource-fork dictionary")
	}
	resource, err := plist.object(resourceIndex)
	if err != nil {
		return nil, err
	}
	if resource.kind != plistDict {
		return nil, corruptDMG(0, "the property list's resource-fork value is not a dictionary")
	}
	blkxIndex, err := plist.lookup(resource.pairs, "blkx")
	if err != nil {
		return nil, err
	}
	if blkxIndex < 0 {
		return nil, corruptDMG(0, "the resource fork has no blkx array")
	}
	blkx, err := plist.object(blkxIndex)
	if err != nil {
		return nil, err
	}
	if blkx.kind != plistArray {
		return nil, corruptDMG(0, "the resource fork's blkx value is not an array")
	}
	if len(blkx.refs) > MaxTables {
		return nil, unsupportedDMG(fmt.Sprintf(
			"%d block tables in one image", len(blkx.refs)))
	}

	tables := make([]rawTable, 0, len(blkx.refs))
	for _, index := range blkx.refs {
		entry, err := plist.object(index)
		if err != nil {
			return nil, err
		}
		if entry.kind != plistDict {
			return nil, corruptDMG(0,
				"a blkx entry in the property list is not a dictionary")
		}
		var name *string
		for _, key := range []string{"Name", "CFName"} {
			valueIndex, err := plist.lookup(entry.pairs, key)
			if err != nil {
				return nil, err
			}
			if valueIndex < 0 {
				continue
			}
			value, err := plist.object(valueIndex)
			if err != nil {
				return nil, err
			}
			if value.kind == plistString && value.text != "" {
				copied := value.text
				name = &copied
				break
			}
		}
		label := "<unnamed>"
		if name != nil {
			label = *name
		}
		dataIndex, err := plist.lookup(entry.pairs, "Data")
		if err != nil {
			return nil, err
		}
		if dataIndex < 0 {
			return nil, corruptDMG(0, fmt.Sprintf("the blkx entry %q carries no Data", label))
		}
		data, err := plist.object(dataIndex)
		if err != nil {
			return nil, err
		}
		if data.kind != plistData {
			return nil, corruptDMG(0, fmt.Sprintf(
				"the blkx entry %q stores Data as something other than bytes", label))
		}
		if len(data.data) > MaxBlkxBytes {
			return nil, unsupportedDMG(fmt.Sprintf("a %d byte blkx table", len(data.data)))
		}
		if err := pushRawTable(name, data.data, &tables); err != nil {
			return nil, err
		}
	}
	return tables, nil
}

func corruptDMG(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupportedDMG(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func maxIntDMG() int { return int(^uint(0) >> 1) }

func minU64DMG(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
