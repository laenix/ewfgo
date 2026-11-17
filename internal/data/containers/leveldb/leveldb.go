// Package leveldb reads LevelDB store directories and their individual files.
//
// LevelDB is the embedded key/value store behind Chromium's Local Storage,
// Session Storage, IndexedDB and shared_proto_db, many Android applications'
// preferences, and a long tail of desktop applications that ship it as a
// library. A store is a directory:
//
//	CURRENT          text: the name of the live manifest
//	MANIFEST-NNNNNN  a log of version edits: which tables are live
//	NNNNNN.ldb/.sst  sorted string tables
//	NNNNNN.log       write-ahead batches not yet flushed into a table
//
// Each file is self-describing enough to be read on its own, which is what
// this package reports: a table's key range, entry count and tombstones; a
// manifest's live table set, log number and sequence; CURRENT's pointer; and
// a WAL's newest batches. Nothing here knows what a key means — the software
// layer maps Chromium's or an application's schema onto these containers.
//
// This is a pure-Go port of forensic-core's data/containers/leveldb module.
// The byte-source layer has no notion of a directory, so OpenStore is
// available for a filesystem directory, while OpenTable, OpenManifest and
// OpenLog read one file at a time from a source.ByteSource.
//
// # Honesty rules
//
//   - A table is identified by its footer magic, not by its suffix; a `.sst`
//     that is not a table is refused by name.
//   - Keys and values are counted, and only the edge keys are rendered. A key
//     that is not printable UTF-8 is shown as hex, never lossily decoded.
//   - A table larger than the scan bound reports ScanComplete=false with the
//     blocks it did read; an entry count is never extrapolated.
//   - A manifest record whose CRC fails or whose fields do not decode is
//     counted, and the live set is reported as incomplete rather than partial.
//   - A WAL record is decoded only when its CRC matches; deletions are counted
//     apart from values.
package leveldb

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxInMemoryBytes bounds a whole manifest or WAL read into memory. A manifest
// is a few kilobytes and a WAL a few megabytes; the bound stops a misnamed file
// from being copied into memory.
const MaxInMemoryBytes uint64 = 64 * 1024 * 1024

// Kind is which LevelDB file a path names.
type Kind uint8

const (
	// KindTable is a sorted table (.ldb, .sst).
	KindTable Kind = iota
	// KindManifest is a MANIFEST-<number> version-edit log.
	KindManifest
	// KindCurrent is the CURRENT pointer.
	KindCurrent
	// KindWal is a NNNNNN.log write-ahead log.
	KindWal
)

// Label returns the human name of a file kind.
func (k Kind) Label() string {
	switch k {
	case KindTable:
		return "table"
	case KindManifest:
		return "manifest"
	case KindCurrent:
		return "current"
	case KindWal:
		return "wal"
	default:
		return "unknown"
	}
}

// Parser returns the parser name recorded in an artifact analysis.
func (k Kind) Parser() string {
	switch k {
	case KindTable:
		return "leveldb-table"
	case KindManifest:
		return "leveldb-manifest"
	case KindCurrent:
		return "leveldb-current"
	case KindWal:
		return "leveldb-wal"
	default:
		return "leveldb-unknown"
	}
}

// RouteFile routes a path to a LevelDB file kind.
//
// The table, manifest and CURRENT names are LevelDB's own and carry no
// ambiguity worth resolving from bytes first; the footer, the log records and
// the pointer's content are still checked before anything is decoded. A
// write-ahead log is the one name LevelDB shares with ordinary text logs, so
// it is routed only below a directory whose name says "leveldb", where a
// numeric .log file is the store's and not a system log.
func RouteFile(path string) (Kind, bool) {
	normalized := strings.ReplaceAll(path, "\\", "/")
	dir, name := "", normalized
	if at := strings.LastIndex(normalized, "/"); at >= 0 {
		dir, name = normalized[:at], normalized[at+1:]
	}
	lowered := strings.ToLower(name)
	if name == "CURRENT" {
		return KindCurrent, true
	}
	if strings.HasPrefix(lowered, "manifest-") {
		return KindManifest, true
	}
	if strings.HasSuffix(lowered, ".ldb") || strings.HasSuffix(lowered, ".sst") {
		return KindTable, true
	}
	if strings.HasSuffix(lowered, ".log") {
		stem := lowered[:len(lowered)-4]
		if isASCIIDigits(stem) && len(stem) >= 6 && strings.Contains(strings.ToLower(dir), "leveldb") {
			return KindWal, true
		}
	}
	return 0, false
}

// InternalTag is the sequence number and value type an internal key carries.
type InternalTag struct {
	// Sequence is the write sequence number.
	Sequence uint64
	// Kind is 0 for a deletion, 1 for a value; other values are
	// table-internal.
	Kind uint8
}

// SplitInternalKey splits an internal key into its user key and tag. It
// returns false when the key is shorter than the eight-byte tag.
func SplitInternalKey(key []byte) ([]byte, InternalTag, bool) {
	if len(key) < 8 {
		return nil, InternalTag{}, false
	}
	tag := uint64(key[len(key)-8]) |
		uint64(key[len(key)-7])<<8 |
		uint64(key[len(key)-6])<<16 |
		uint64(key[len(key)-5])<<24 |
		uint64(key[len(key)-4])<<32 |
		uint64(key[len(key)-3])<<40 |
		uint64(key[len(key)-2])<<48 |
		uint64(key[len(key)-1])<<56
	return key[:len(key)-8], InternalTag{Sequence: tag >> 8, Kind: uint8(tag)}, true
}

// UserKey returns the user key of an internal key.
func UserKey(key []byte) ([]byte, bool) {
	user, _, ok := SplitInternalKey(key)
	return user, ok
}

// renderKeyLimit is how many bytes of a key a report shows.
const renderKeyLimit = 64

// RenderKey renders a key for a report: text when it is printable UTF-8, hex
// otherwise. At most 64 bytes are shown; a longer key is marked with '…'.
func RenderKey(bytes []byte) string {
	shown := bytes
	if len(shown) > renderKeyLimit {
		shown = shown[:renderKeyLimit]
	}
	var out string
	if utf8.Valid(shown) && isPrintableText(shown) {
		out = string(shown)
	} else {
		out = "0x" + hex.EncodeToString(shown)
	}
	if len(bytes) > renderKeyLimit {
		out += "…"
	}
	return out
}

// RenderInternalKey renders an internal key by its user key.
func RenderInternalKey(key []byte) string {
	if user, ok := UserKey(key); ok {
		return RenderKey(user)
	}
	return RenderKey(key)
}

func isPrintableText(text []byte) bool {
	for len(text) > 0 {
		r, size := utf8.DecodeRune(text)
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if r != '\t' && unicode.IsControl(r) {
			return false
		}
		text = text[size:]
	}
	return true
}

func isASCIIDigits(text string) bool {
	if text == "" {
		return false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
}

// invalid reports a structurally invalid file.
func invalid(reason string) error {
	return &source.Error{Kind: source.ErrInvalidArgument, Reason: reason}
}

// corrupt reports bytes that exist but do not decode.
func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

// unsupported reports a recognised feature this reader cannot decode.
func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

// limitError reports a bound that the input exceeded.
func limitError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLimitExceeded, fmt.Sprintf(format, args...))
}

// readVarint reads a base-128 varint, returning the value and bytes consumed.
func readVarint(input []byte) (uint64, int, bool) {
	var value uint64
	for index := 0; index < 10; index++ {
		if index >= len(input) {
			return 0, 0, false
		}
		b := input[index]
		value |= uint64(b&0x7f) << (7 * index)
		if b&0x80 == 0 {
			return value, index + 1, true
		}
	}
	return 0, 0, false
}

// appendVarint appends a base-128 varint.
func appendVarint(out []byte, value uint64) []byte {
	for value >= 0x80 {
		out = append(out, byte(value&0x7f)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

func le32(bytes []byte, at int) uint32 {
	return uint32(bytes[at]) |
		uint32(bytes[at+1])<<8 |
		uint32(bytes[at+2])<<16 |
		uint32(bytes[at+3])<<24
}

func le64(bytes []byte, at int) uint64 {
	return uint64(le32(bytes, at)) | uint64(le32(bytes, at+4))<<32
}

func ptr[T any](value T) *T { return &value }
