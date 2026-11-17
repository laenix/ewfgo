// Package mmkv decodes Tencent MMKV key-value stores. MMKV has no magic
// number; it is identified by its location below a `mmkv` directory. The first
// four bytes are the live payload size, followed by a protobuf-flavoured
// dictionary of append-only key/value records. This is a pure-Go port of
// forensic-core's data/containers/mmkv.rs.
package mmkv

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// HeaderBytes is the actual-size field before the payload.
	HeaderBytes = 4
	// MetaBytes is the full CRC-sidecar structure.
	MetaBytes = 112
	// MetaPrefixBytes is the smallest usable sidecar prefix.
	MetaPrefixBytes = 32
	// MaxStoreBytes bounds a store before reading.
	MaxStoreBytes uint64 = 64 * 1024 * 1024
	// MaxEntries bounds decoded records.
	MaxEntries = 1000000
	// MaxKeyBytes and MaxValueBytes bound one record.
	MaxKeyBytes   = 1 << 20
	MaxValueBytes = 8 * 1024 * 1024
	// MaxContainerEntries bounds a nested container.
	MaxContainerEntries = 100000
	// PreviewBytes is text kept in a preview.
	PreviewBytes = 512
	// HexBytes is opaque bytes rendered as hex.
	HexBytes = 64
	// MaxKnownVersion is the highest known meta version.
	MaxKnownVersion uint32 = 7
)

// Kind is a store file or its CRC sidecar.
type Kind uint8

const (
	KindStore Kind = iota
	KindMetaCrc
)

// Label returns "store" or "meta".
func (k Kind) Label() string {
	if k == KindMetaCrc {
		return "meta"
	}
	return "store"
}

// Boundary is how the entry stream's end was established.
type Boundary uint8

const (
	BoundaryEmpty Boundary = iota
	BoundaryHeader
	BoundaryScan
)

// Label returns "empty", "header" or "scan".
func (b Boundary) Label() string {
	switch b {
	case BoundaryEmpty:
		return "empty"
	case BoundaryHeader:
		return "header"
	default:
		return "scan"
	}
}

// ValueShape is what a value buffer is self-consistent with.
type ValueShape uint8

const (
	ShapeText ValueShape = iota
	ShapeContainer
	ShapeRaw
)

// Label returns "text", "container" or "raw".
func (s ValueShape) Label() string {
	switch s {
	case ShapeText:
		return "text"
	case ShapeContainer:
		return "container"
	default:
		return "raw"
	}
}

// ValueView is the bounded preview of one value.
type ValueView struct {
	Shape            ValueShape
	Text             string
	TextTruncated    bool
	ContainerEntries uint32
	HasContainer     bool
	RawHex           string
	RawTruncated     bool
}

// KeyFacts is the last replayed state of one key.
type KeyFacts struct {
	Key         string
	Offset      uint64
	RecordLen   uint64
	Live        bool
	HasValue    bool
	ValueLen    uint64
	ValueSHA256 string
	View        *ValueView
	Sets        uint32
	Deletes     uint32
}

// StoreSummary summarises one store file.
type StoreSummary struct {
	DeclaredSize    uint32
	PayloadBytes    uint64
	Boundary        Boundary
	Records         uint64
	Sets            uint64
	Deletes         uint64
	LiveKeys        uint64
	DeletedKeys     uint64
	OverwrittenKeys uint64
	KeyBytes        uint64
	ValueBytes      uint64
	TrailingBytes   uint64
	Truncated       bool
	Warnings        []string
}

// Store is a decoded store.
type Store struct {
	Summary StoreSummary
	Keys    []KeyFacts
}

// MetaSummary is a decoded CRC sidecar.
type MetaSummary struct {
	CRC            uint32
	Version        uint32
	Sequence       uint32
	IVHex          string
	ActualSize     uint32
	LastActualSize uint32
	LastCRC        uint32
	Flags          uint64
	Short          bool
	Warnings       []string
}

// RouteFile identifies a store or sidecar from its path.
func RouteFile(path string) (Kind, bool) {
	normalized := strings.ReplaceAll(path, "\\", "/")
	at := strings.LastIndex(normalized, "/")
	if at < 0 {
		return 0, false
	}
	parent, name := normalized[:at], normalized[at+1:]
	dirAt := strings.LastIndex(parent, "/")
	directory := parent
	if dirAt >= 0 {
		directory = parent[dirAt+1:]
	}
	if name == "" || !strings.EqualFold(directory, "mmkv") {
		return 0, false
	}
	if strings.HasSuffix(strings.ToLower(name), ".crc") {
		return KindMetaCrc, true
	}
	return KindStore, true
}

// Parse decodes one store file.
func Parse(bytes []byte) (*Store, error) {
	if uint64(len(bytes)) > MaxStoreBytes {
		return nil, unsupported(fmt.Sprintf("a %d byte store exceeds the %d byte limit", len(bytes), MaxStoreBytes))
	}
	if len(bytes) < HeaderBytes {
		return nil, corrupt(0, "an MMKV file needs at least the four-byte size header")
	}
	declared := le32(bytes, 0)
	var warnings []string
	truncated := false
	if len(bytes) == HeaderBytes {
		return finish(declared, 0, BoundaryEmpty, nil, 0, truncated, warnings), nil
	}

	boundary := BoundaryScan
	var records []record
	payloadEnd := HeaderBytes
	declaredEnd := HeaderBytes + int(declared)
	if declared > 0 && declaredEnd <= len(bytes) {
		var strict []record
		if err := readStream(bytes, HeaderBytes, declaredEnd, &strict, &truncated, &warnings); err == "" {
			if len(strict) > 0 || declared <= 2 {
				boundary = BoundaryHeader
				payloadEnd = declaredEnd
				records = strict
			} else {
				warnings = append(warnings, "the size header describes no records; the entry stream was scanned instead")
			}
		} else {
			warnings = append(warnings, fmt.Sprintf("the size header does not delimit a record stream (%s); the entry stream was scanned instead", err))
		}
	} else if declared > 0 {
		warnings = append(warnings, fmt.Sprintf("the size header (%d) reaches past the %d-byte file", declared, len(bytes)))
	}

	if boundary == BoundaryScan {
		start := HeaderBytes
		warningCount := len(warnings)
		err := readStream(bytes, start, len(bytes), &records, &truncated, &warnings)
		if err == "" {
			payloadEnd = len(bytes)
		} else {
			payloadEnd = lastRecordEnd(records)
			if payloadEnd == 0 {
				payloadEnd = HeaderBytes
			}
			if len(records) == 0 {
				reason := "no record decoded"
				if warningCount < len(warnings) {
					reason = warnings[warningCount]
				}
				return nil, unsupported("the payload does not decode as a plaintext MMKV dictionary; an encrypted store has no readable structure (" + reason + ")")
			}
			warnings = append(warnings, fmt.Sprintf("%d byte(s) after the last complete record were not decoded", len(bytes)-payloadEnd))
		}
	}
	trailing := len(bytes) - payloadEnd
	return finish(declared, payloadEnd-HeaderBytes, boundary, records, trailing, truncated, warnings), nil
}

type record struct {
	key    string
	offset int
	length int
	value  []byte
}

func finish(declared uint32, payloadBytes int, boundary Boundary, records []record, trailing int, truncated bool, warnings []string) *Store {
	states := make(map[string]*KeyFacts)
	var sets, deletes, keyBytes, valueBytes uint64
	for _, rec := range records {
		keyBytes += uint64(len(rec.key))
		valueBytes += uint64(len(rec.value))
		state, ok := states[rec.key]
		if !ok {
			state = &KeyFacts{Key: rec.key}
			states[rec.key] = state
		}
		state.Offset = uint64(rec.offset)
		state.RecordLen = uint64(rec.length)
		if len(rec.value) == 0 {
			state.Live = false
			state.Deletes++
			deletes++
			continue
		}
		state.Live = true
		state.HasValue = true
		state.Sets++
		state.ValueLen = uint64(len(rec.value))
		sum := sha256.Sum256(rec.value)
		state.ValueSHA256 = hex.EncodeToString(sum[:])
		view := classify(rec.value)
		state.View = &view
		sets++
	}

	keys := make([]KeyFacts, 0, len(states))
	var liveKeys, deletedKeys, overwritten uint64
	for _, state := range states {
		keys = append(keys, *state)
		if state.Live {
			liveKeys++
		} else {
			deletedKeys++
		}
		if state.Sets > 1 {
			overwritten++
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Key < keys[j].Key })
	return &Store{
		Summary: StoreSummary{
			DeclaredSize: declared, PayloadBytes: uint64(payloadBytes), Boundary: boundary,
			Records: uint64(len(records)), Sets: sets, Deletes: deletes,
			LiveKeys: liveKeys, DeletedKeys: deletedKeys, OverwrittenKeys: overwritten,
			KeyBytes: keyBytes, ValueBytes: valueBytes, TrailingBytes: uint64(trailing),
			Truncated: truncated, Warnings: warnings,
		},
		Keys: keys,
	}
}

func readStream(bytes []byte, start, end int, records *[]record, truncated *bool, warnings *[]string) string {
	position := start
	if position >= end {
		return ""
	}
	if _, used, ok := ReadVarint(bytes[position:end]); !ok {
		return "the map size varint is truncated"
	} else {
		position += used
	}
	for position < end {
		if len(*records) >= MaxEntries {
			*truncated = true
			*warnings = append(*warnings, fmt.Sprintf("only the first %d records were decoded", MaxEntries))
			break
		}
		recordStart := position
		keyLen, used, ok := ReadVarint(bytes[position:end])
		if !ok {
			return "a key length varint is truncated"
		}
		position += used
		if keyLen == 0 {
			return "a zero-length key cannot be a dictionary entry"
		}
		if keyLen > MaxKeyBytes {
			return fmt.Sprintf("a %d byte key exceeds the %d byte limit", keyLen, MaxKeyBytes)
		}
		if int(keyLen) > end-position {
			return "a key length reaches past the record stream"
		}
		keyRaw := bytes[position : position+int(keyLen)]
		position += int(keyLen)
		valueLen, used, ok := ReadVarint(bytes[position:end])
		if !ok {
			return "a value length varint is truncated"
		}
		position += used
		if valueLen > MaxValueBytes {
			return fmt.Sprintf("a %d byte value exceeds the %d byte limit", valueLen, MaxValueBytes)
		}
		if int(valueLen) > end-position {
			return "a value length reaches past the record stream"
		}
		value := bytes[position : position+int(valueLen)]
		position += int(valueLen)
		*records = append(*records, record{
			key: RenderKey(keyRaw), offset: recordStart, length: position - recordStart, value: value,
		})
	}
	return ""
}

func lastRecordEnd(records []record) int {
	if len(records) == 0 {
		return 0
	}
	last := records[len(records)-1]
	return last.offset + last.length
}

// RenderKey renders a key as printable UTF-8, or hexadecimal when it is not.
func RenderKey(raw []byte) string {
	if utf8.Valid(raw) && isPrintable(string(raw)) {
		return string(raw)
	}
	shown := raw
	if len(shown) > HexBytes {
		shown = shown[:HexBytes]
	}
	out := "0x" + hex.EncodeToString(shown)
	if len(raw) > HexBytes {
		out += "…"
	}
	return out
}

func isPrintable(text string) bool {
	for _, r := range text {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7F {
			return false
		}
	}
	return true
}

func classify(value []byte) ValueView {
	view := ValueView{Shape: ShapeRaw}
	if length, used, ok := ReadVarint(value); ok && length <= MaxValueBytes && int(length) == len(value)-used {
		body := value[used:]
		if utf8.Valid(body) && isPrintable(string(body)) {
			view.Shape = ShapeText
			view.Text, view.TextTruncated = previewText(string(body))
			return view
		}
		if entries, ok := containerEntries(body); ok {
			view.Shape = ShapeContainer
			view.ContainerEntries = entries
			view.HasContainer = true
			return view
		}
	}
	shown := value
	if len(shown) > HexBytes {
		shown = shown[:HexBytes]
	}
	view.RawHex = hex.EncodeToString(shown)
	view.RawTruncated = len(value) > HexBytes
	return view
}

func previewText(text string) (string, bool) {
	if len(text) <= PreviewBytes {
		return text, false
	}
	end := PreviewBytes
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end], true
}

func containerEntries(body []byte) (uint32, bool) {
	position := 0
	var entries uint32
	for position < len(body) {
		if int(entries) >= MaxContainerEntries {
			return 0, false
		}
		keyLen, used, ok := ReadVarint(body[position:])
		if !ok {
			return 0, false
		}
		position += used
		if keyLen == 0 || keyLen > MaxKeyBytes || int(keyLen) > len(body)-position {
			return 0, false
		}
		if !utf8.Valid(body[position : position+int(keyLen)]) {
			return 0, false
		}
		position += int(keyLen)
		valueLen, used, ok := ReadVarint(body[position:])
		if !ok {
			return 0, false
		}
		position += used
		if int(valueLen) > len(body)-position {
			return 0, false
		}
		position += int(valueLen)
		entries++
	}
	if entries == 0 {
		return 0, false
	}
	return entries, true
}

// ReadVarint reads a base-128 varint.
func ReadVarint(input []byte) (value uint64, used int, ok bool) {
	for index, b := range input {
		if index >= 10 {
			return 0, 0, false
		}
		value |= uint64(b&0x7F) << (index * 7)
		if b&0x80 == 0 {
			return value, index + 1, true
		}
	}
	return 0, 0, false
}

// ParseMeta decodes the CRC sidecar.
func ParseMeta(bytes []byte) (*MetaSummary, error) {
	if len(bytes) < MetaPrefixBytes {
		return nil, corrupt(0, fmt.Sprintf("an MMKV sidecar needs at least %d bytes, found %d", MetaPrefixBytes, len(bytes)))
	}
	summary := &MetaSummary{
		CRC: le32(bytes, 0), Version: le32(bytes, 4), Sequence: le32(bytes, 8),
		IVHex: hex.EncodeToString(bytes[12:28]), ActualSize: le32(bytes, 28),
		Short: len(bytes) < MetaBytes,
	}
	if len(bytes) >= 40 {
		summary.LastActualSize = le32(bytes, 32)
		summary.LastCRC = le32(bytes, 36)
	}
	if len(bytes) >= MetaBytes {
		summary.Flags = le64(bytes, 104)
	}
	if summary.Short {
		summary.Warnings = append(summary.Warnings,
			fmt.Sprintf("the sidecar is %d byte(s) long; the full structure is %d", len(bytes), MetaBytes))
	}
	if summary.Version >= MaxKnownVersion {
		summary.Warnings = append(summary.Warnings,
			fmt.Sprintf("meta version %d is outside the known range; fields are reported as stored", summary.Version))
	}
	return summary, nil
}

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func le32(bytes []byte, at int) uint32 {
	return uint32(bytes[at]) | uint32(bytes[at+1])<<8 | uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
}

func le64(bytes []byte, at int) uint64 {
	return uint64(le32(bytes, at)) | uint64(le32(bytes, at+4))<<32
}
