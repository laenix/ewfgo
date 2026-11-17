package leveldb

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// MaxManifestBytes is the largest manifest this reader decodes in
	// memory.
	MaxManifestBytes uint64 = 64 * 1024 * 1024
	// MaxLiveTables is the most live tables a summary will list.
	MaxLiveTables = 100_000
)

// LiveTable is one table the manifest says is live.
type LiveTable struct {
	Level    uint32
	Number   uint64
	Size     uint64
	Smallest string
	Largest  string
}

// Manifest is what a manifest says about its database.
type Manifest struct {
	// Records is the number of log records read, including ones that did
	// not decode.
	Records uint64
	// Edits is the number of version edits that decoded and were applied.
	Edits uint64
	// ChecksumFailures is the number of records skipped because their CRC
	// did not match.
	ChecksumFailures uint64
	// DecodeFailures is the number of records skipped because their fields
	// did not decode.
	DecodeFailures uint64
	// Complete is true when every record was applied.
	Complete     bool
	Comparator   *string
	LogNumber    *uint64
	NextFile     *uint64
	LastSequence *uint64
	PrevLog      *uint64
	// DeletedFiles counts deleted_file entries seen across all edits.
	DeletedFiles uint64
	// LiveTables is the live set, ordered by level and file number.
	LiveTables []LiveTable
	// Warnings are issues that did not stop the parse.
	Warnings []string

	liveOverflowWarned bool
}

type liveTableKey struct {
	level  uint32
	number uint64
}

// Levels returns the number of live tables per level, in level order.
func (m *Manifest) Levels() [][2]int {
	var levels [][2]int
	for _, table := range m.LiveTables {
		if len(levels) > 0 && levels[len(levels)-1][0] == int(table.Level) {
			levels[len(levels)-1][1]++
		} else {
			levels = append(levels, [2]int{int(table.Level), 1})
		}
	}
	return levels
}

// LiveBytes is the sum of the live tables' declared sizes.
func (m *Manifest) LiveBytes() uint64 {
	var total uint64
	for _, table := range m.LiveTables {
		total += table.Size
	}
	return total
}

// MaxLevel is the highest level holding a table, if any.
func (m *Manifest) MaxLevel() (uint32, bool) {
	if len(m.LiveTables) == 0 {
		return 0, false
	}
	var highest uint32
	for _, table := range m.LiveTables {
		if table.Level > highest {
			highest = table.Level
		}
	}
	return highest, true
}

// OpenManifest reads and decodes a whole manifest with the default limits.
func OpenManifest(src source.ByteSource) (*Manifest, error) {
	return OpenManifestWithLimits(src, DefaultLogLimits())
}

// OpenManifestWithLimits reads and decodes a whole manifest.
func OpenManifestWithLimits(src source.ByteSource, limits LogLimits) (*Manifest, error) {
	limits = limits.normalized()
	max := MaxManifestBytes
	if uint64(limits.MaxBytes) < max {
		max = uint64(limits.MaxBytes)
	}
	bytes, err := readWholeSource(src, max)
	if err != nil {
		return nil, err
	}
	return parseManifestBytes(bytes, limits)
}

func parseManifestBytes(bytes []byte, limits LogLimits) (*Manifest, error) {
	scan, err := ScanLog(bytes, limits)
	if err != nil {
		return nil, err
	}
	manifest := &Manifest{
		Complete: !scan.StoppedAtLimit && scan.Incomplete == 0 && scan.Truncated == 0,
		Warnings: append([]string(nil), scan.Warnings...),
	}
	live := make(map[liveTableKey]LiveTable)
	for _, record := range scan.Records {
		manifest.Records++
		if !record.CRCOK {
			manifest.ChecksumFailures++
			manifest.Complete = false
			manifest.Warnings = append(manifest.Warnings, fmt.Sprintf(
				"manifest record at byte %d failed its checksum and was skipped", record.Offset))
			continue
		}
		edit, err := parseVersionEdit(record.Payload)
		if err != nil {
			manifest.DecodeFailures++
			manifest.Complete = false
			manifest.Warnings = append(manifest.Warnings, fmt.Sprintf(
				"manifest record at byte %d: %v", record.Offset, err))
			continue
		}
		manifest.Edits++
		applyVersionEdit(manifest, live, edit)
	}
	if manifest.Edits == 0 && manifest.Records > 0 {
		manifest.Warnings = append(manifest.Warnings,
			"no manifest record decoded; the live table set is unknown")
	}
	keys := make([]liveTableKey, 0, len(live))
	for key := range live {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].level != keys[j].level {
			return keys[i].level < keys[j].level
		}
		return keys[i].number < keys[j].number
	})
	manifest.LiveTables = make([]LiveTable, 0, len(keys))
	for _, key := range keys {
		manifest.LiveTables = append(manifest.LiveTables, live[key])
	}
	return manifest, nil
}

// VersionEdit is one decoded manifest record. It is not exported; callers
// receive the applied Manifest.
type versionEdit struct {
	comparator   *string
	logNumber    *uint64
	nextFile     *uint64
	lastSequence *uint64
	prevLog      *uint64
	deleted      [][2]uint64
	added        []LiveTable
}

func applyVersionEdit(manifest *Manifest, live map[liveTableKey]LiveTable, edit versionEdit) {
	if edit.comparator != nil {
		manifest.Comparator = edit.comparator
	}
	if edit.logNumber != nil {
		manifest.LogNumber = edit.logNumber
	}
	if edit.nextFile != nil {
		manifest.NextFile = edit.nextFile
	}
	if edit.lastSequence != nil {
		manifest.LastSequence = edit.lastSequence
	}
	if edit.prevLog != nil {
		manifest.PrevLog = edit.prevLog
	}
	for _, deleted := range edit.deleted {
		manifest.DeletedFiles++
		delete(live, liveTableKey{level: saturateU32(deleted[0]), number: deleted[1]})
	}
	for _, table := range edit.added {
		key := liveTableKey{level: table.Level, number: table.Number}
		if len(live) >= MaxLiveTables {
			if _, exists := live[key]; !exists {
				if !manifest.liveOverflowWarned {
					manifest.liveOverflowWarned = true
					manifest.Warnings = append(manifest.Warnings, fmt.Sprintf(
						"the manifest lists more than %d live tables; the rest were not kept",
						MaxLiveTables))
				}
				continue
			}
		}
		live[key] = table
	}
}

func parseVersionEdit(payload []byte) (versionEdit, error) {
	input := &editInput{bytes: payload}
	var edit versionEdit
	for {
		tag, ok := input.varint()
		if !ok {
			break
		}
		switch tag {
		case 1:
			bytes, err := input.slice()
			if err != nil {
				return versionEdit{}, err
			}
			// A comparator is not a key; preserving its bytes in a Go string
			// is exact and never lossy.
			edit.comparator = ptr(string(bytes))
		case 2:
			value, err := input.varintRequired("log number")
			if err != nil {
				return versionEdit{}, err
			}
			edit.logNumber = ptr(value)
		case 3:
			value, err := input.varintRequired("next file number")
			if err != nil {
				return versionEdit{}, err
			}
			edit.nextFile = ptr(value)
		case 4:
			value, err := input.varintRequired("last sequence")
			if err != nil {
				return versionEdit{}, err
			}
			edit.lastSequence = ptr(value)
		case 5:
			if _, err := input.varintRequired("compact pointer level"); err != nil {
				return versionEdit{}, err
			}
			if _, err := input.slice(); err != nil {
				return versionEdit{}, err
			}
		case 6:
			level, err := input.varintRequired("deleted file level")
			if err != nil {
				return versionEdit{}, err
			}
			number, err := input.varintRequired("deleted file number")
			if err != nil {
				return versionEdit{}, err
			}
			edit.deleted = append(edit.deleted, [2]uint64{level, number})
		case 7:
			level, err := input.varintRequired("new file level")
			if err != nil {
				return versionEdit{}, err
			}
			number, err := input.varintRequired("new file number")
			if err != nil {
				return versionEdit{}, err
			}
			size, err := input.varintRequired("new file size")
			if err != nil {
				return versionEdit{}, err
			}
			smallest, err := input.slice()
			if err != nil {
				return versionEdit{}, err
			}
			largest, err := input.slice()
			if err != nil {
				return versionEdit{}, err
			}
			edit.added = append(edit.added, LiveTable{
				Level:    saturateU32(level),
				Number:   number,
				Size:     size,
				Smallest: RenderInternalKey(smallest),
				Largest:  RenderInternalKey(largest),
			})
		case 9:
			value, err := input.varintRequired("previous log number")
			if err != nil {
				return versionEdit{}, err
			}
			edit.prevLog = ptr(value)
		default:
			// Unknown tags are what a newer LevelDB may write. The record is
			// unusable as a whole: skipping half an edit would invent state.
			return versionEdit{}, unsupported(fmt.Sprintf("manifest tag %d", tag))
		}
	}
	return edit, nil
}

type editInput struct {
	bytes []byte
	at    int
}

func (in *editInput) remaining() int {
	if in.at >= len(in.bytes) {
		return 0
	}
	return len(in.bytes) - in.at
}

// varint reads a varint, or reports false at the end of the record.
func (in *editInput) varint() (uint64, bool) {
	var value uint64
	for index := 0; index < 10; index++ {
		if in.at >= len(in.bytes) {
			return 0, false
		}
		b := in.bytes[in.at]
		in.at++
		value |= uint64(b&0x7f) << (7 * index)
		if b&0x80 == 0 {
			return value, true
		}
	}
	return 0, false
}

func (in *editInput) varintRequired(what string) (uint64, error) {
	value, ok := in.varint()
	if !ok {
		return 0, invalid(fmt.Sprintf("a version edit ends before its %s", what))
	}
	return value, nil
}

func (in *editInput) slice() ([]byte, error) {
	length, err := in.varintRequired("length")
	if err != nil {
		return nil, err
	}
	if length > uint64(in.remaining()) {
		return nil, invalid(fmt.Sprintf(
			"a %d-byte field runs past the %d remaining bytes", length, in.remaining()))
	}
	slice := in.bytes[in.at : in.at+int(length)]
	in.at += int(length)
	return slice, nil
}

func saturateU32(value uint64) uint32 {
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
}

// ParseCurrent decodes and validates the manifest name a CURRENT file holds.
func ParseCurrent(bytes []byte) (string, error) {
	text := string(bytes)
	if !utf8.Valid(bytes) {
		return "", invalid("CURRENT is not UTF-8 text")
	}
	name := strings.TrimSpace(text)
	if name == "" {
		return "", invalid("CURRENT names no manifest")
	}
	if strings.ContainsAny(name, `/\`) {
		return "", invalid(fmt.Sprintf(
			"CURRENT names `%s`, which is a path, not a manifest file", name))
	}
	return name, nil
}

// OpenCurrent reads CURRENT from a source and validates its pointer.
func OpenCurrent(src source.ByteSource) (string, error) {
	bytes, err := readWholeSource(src, MaxInMemoryBytes)
	if err != nil {
		return "", err
	}
	return ParseCurrent(bytes)
}

// EncodedEdit is a VersionEdit a fixture can encode: raw internal keys, not
// renderings.
type EncodedEdit struct {
	Comparator   *string
	LogNumber    *uint64
	NextFile     *uint64
	LastSequence *uint64
	PrevLog      *uint64
	Deleted      [][2]uint32
	Added        []EncodedFile
}

// EncodedFile is one new_file field.
type EncodedFile struct {
	Level    uint32
	Number   uint64
	Size     uint64
	Smallest []byte
	Largest  []byte
}

// EncodeEdit encodes one VersionEdit, as a fixture builder would. It is kept
// beside the decoder so the two agree on every tag; nothing in the reader
// writes a manifest.
func EncodeEdit(edit EncodedEdit) []byte {
	var out []byte
	if edit.Comparator != nil {
		out = append(out, 1)
		out = appendBytes(out, []byte(*edit.Comparator))
	}
	if edit.LogNumber != nil {
		out = append(out, 2)
		out = appendVarint(out, *edit.LogNumber)
	}
	if edit.NextFile != nil {
		out = append(out, 3)
		out = appendVarint(out, *edit.NextFile)
	}
	if edit.LastSequence != nil {
		out = append(out, 4)
		out = appendVarint(out, *edit.LastSequence)
	}
	for _, deleted := range edit.Deleted {
		out = append(out, 6)
		out = appendVarint(out, uint64(deleted[0]))
		out = appendVarint(out, uint64(deleted[1]))
	}
	for _, table := range edit.Added {
		out = append(out, 7)
		out = appendVarint(out, uint64(table.Level))
		out = appendVarint(out, table.Number)
		out = appendVarint(out, table.Size)
		out = appendBytes(out, table.Smallest)
		out = appendBytes(out, table.Largest)
	}
	if edit.PrevLog != nil {
		out = append(out, 9)
		out = appendVarint(out, *edit.PrevLog)
	}
	return out
}

func appendBytes(out, bytes []byte) []byte {
	out = appendVarint(out, uint64(len(bytes)))
	return append(out, bytes...)
}
