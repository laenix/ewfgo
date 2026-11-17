// Package ar reads Unix ar archives: .a static libraries, .deb packages, and
// the COFF archives a Windows linker imports.
//
// After the eight-byte "!<arch>\n" signature, every member is a 60-byte ASCII
// header followed by its data, with a single '\n' pad when the data length is
// odd.  Two members are metadata rather than files: a symbol table ("/",
// "/SYM64/", "__.SYMDEF", or "ARFILENAMES/") and a GNU long-name table ("//")
// whose bytes hold names referenced as "/N".  BSD and macOS write long names
// as "#1/LEN", with the first LEN bytes of the member's data holding the real
// name.
//
// Thin archives do not contain their members, so they are refused by name.
// Member bytes are stored verbatim: each entry is a window onto its parent.
// Unsafe member names go through the same path rules as every other archive
// and are counted, not listed.
package ar

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Magic is the global header of a normal archive.
var Magic = []byte("!<arch>\n")

// ThinMagic is the global header of a thin archive, which stores no members.
var ThinMagic = []byte("!<thin>\n")

// HeaderBytes is the size of one member header.
const HeaderBytes = 60

// MaxEntries bounds the member list.
const MaxEntries = 1_000_000

// Entry is one member as its header and name table describe it.
type Entry struct {
	HeaderOffset uint64
	Name         string
	RawName      string
	InvalidUTF8  bool
	Mode         uint32
	UID          uint32
	GID          uint32
	Modified     *int64
	Size         uint64
	DataOffset   uint64
}

// Stats counts what one scan saw without inventing members.
type Stats struct {
	Entries        int
	SymbolTables   uint64
	LongNameTables uint64
	SkippedUnsafe  uint64
	TrailingBytes  uint64
}

// Reader is a read-only ar archive.
type Reader struct {
	source   source.ByteSource
	entries  []Entry
	archives []archive.Entry
	byPath   map[string]int
	stats    Stats
}

// Matches reports whether source begins with either ar signature.
func Matches(src source.ByteSource) bool {
	if src.Len() < uint64(len(Magic)) {
		return false
	}
	magic := make([]byte, len(Magic))
	if err := source.ReadExactAt(src, 0, magic); err != nil {
		return false
	}
	return string(magic) == string(Magic) || string(magic) == string(ThinMagic)
}

type rawMember struct {
	headerOffset uint64
	nameField    string
	size         uint64
	dataOffset   uint64
	mode         uint32
	uid          uint32
	gid          uint32
	modified     *int64
}

type tableRange struct {
	offset uint64
	size   uint64
}

// Open scans every member header and resolves member names.
func Open(src source.ByteSource, limits archive.Limits) (*Reader, error) {
	sourceLen := src.Len()
	if sourceLen < uint64(len(Magic)) {
		return nil, archive.Unsupportedf("a source shorter than the 8-byte signature")
	}
	magic := make([]byte, len(Magic))
	if err := source.ReadExactAt(src, 0, magic); err != nil {
		return nil, err
	}
	if string(magic) == string(ThinMagic) {
		return nil, archive.Unsupportedf("a thin archive (its members live outside this file)")
	}
	if string(magic) != string(Magic) {
		return nil, archive.Unsupportedf("the signature %02x (expected %02x)", magic, Magic)
	}

	var raw []rawMember
	var symbolTables, longNameTables, skippedUnsafe uint64
	var longTable *tableRange
	var trailing uint64
	position := uint64(len(Magic))

	for {
		if position == sourceLen {
			break
		}
		remaining := sourceLen - position
		if remaining < HeaderBytes {
			if err := checkTrailing(src, position, remaining); err != nil {
				return nil, err
			}
			trailing = remaining
			break
		}

		header := make([]byte, HeaderBytes)
		if err := source.ReadExactAt(src, position, header); err != nil {
			return nil, err
		}
		if string(header[58:60]) != "`\n" {
			return nil, archive.Invalidf("the header at offset %d lacks the `\\n trailer", position)
		}

		nameField := fieldText(header[0:16])
		size, err := requiredDecimalField(header[48:58], "the member size", position)
		if err != nil {
			return nil, err
		}
		dataOffset := position + HeaderBytes
		if size > sourceLen-dataOffset {
			return nil, archive.Invalidf("the %d-byte member at offset %d runs past the %d-byte archive", size, position, sourceLen)
		}
		dataEnd := dataOffset + size

		paddedEnd := dataEnd
		if size&1 == 1 {
			paddedEnd = dataEnd + 1
		}
		// The pad byte is required between members.  A few writers stop right
		// after an odd-length final member, so a missing pad at the very end
		// is accepted rather than reported as corruption.
		if paddedEnd > sourceLen {
			if dataEnd == sourceLen {
				paddedEnd = dataEnd
			} else {
				return nil, archive.Invalidf("the archive ends inside a member's padding byte")
			}
		}

		if nameField == "//" {
			longNameTables++
			if longTable == nil {
				longTable = &tableRange{offset: dataOffset, size: size}
			}
		} else if isSymbolTable(nameField) {
			symbolTables++
		} else {
			member, err := buildRawMember(header, position, nameField, size, dataOffset)
			if err != nil {
				return nil, err
			}
			raw = append(raw, member)
		}
		if len(raw) > MaxEntries {
			return nil, archive.Unsupportedf("more than %d members", MaxEntries)
		}

		position = paddedEnd
	}

	var table []byte
	if longTable != nil {
		var err error
		table, err = source.ReadVecAt(src, longTable.offset, longTable.size)
		if err != nil {
			return nil, err
		}
	}

	budget := archive.NewBudget(limits)
	entries := make([]Entry, 0, len(raw))
	archives := make([]archive.Entry, 0, len(raw))
	byPath := make(map[string]int, len(raw))
	for _, member := range raw {
		name, invalidUTF8, dataOffset, size, err := resolveName(src, member, table)
		if err != nil {
			return nil, err
		}
		if name == "" {
			return nil, archive.Invalidf("the member at offset %d resolves to an empty name", member.headerOffset)
		}
		path, err := archive.SanitizeEntryPath(name)
		if err != nil {
			skippedUnsafe++
			continue
		}

		entry := Entry{
			HeaderOffset: member.headerOffset,
			Name:         path,
			RawName:      member.nameField,
			InvalidUTF8:  invalidUTF8,
			Mode:         member.mode,
			UID:          member.uid,
			GID:          member.gid,
			Modified:     member.modified,
			Size:         size,
			DataOffset:   dataOffset,
		}
		archiveEntry, err := archive.NewEntry(path, archive.KindFile, size)
		if err != nil {
			return nil, err
		}
		archiveEntry.Modified = member.modified
		if err := budget.Admit(archiveEntry); err != nil {
			return nil, err
		}
		if _, exists := byPath[archiveEntry.Path]; !exists {
			byPath[archiveEntry.Path] = len(entries)
		}
		entries = append(entries, entry)
		archives = append(archives, archiveEntry)
	}

	return &Reader{
		source:   src,
		entries:  entries,
		archives: archives,
		byPath:   byPath,
		stats: Stats{
			Entries:        len(entries),
			SymbolTables:   symbolTables,
			LongNameTables: longNameTables,
			SkippedUnsafe:  skippedUnsafe,
			TrailingBytes:  trailing,
		},
	}, nil
}

func buildRawMember(header []byte, position uint64, nameField string, size, dataOffset uint64) (rawMember, error) {
	mode := uint32(0)
	if value, ok := octalField(header[40:48]); ok {
		mode = value
	}
	uid := uint32(0)
	if value, ok := optionalDecimalField(header[28:34]); ok && value <= math.MaxUint32 {
		uid = uint32(value)
	}
	gid := uint32(0)
	if value, ok := optionalDecimalField(header[34:40]); ok && value <= math.MaxUint32 {
		gid = uint32(value)
	}
	var modified *int64
	if value, ok := optionalDecimalField(header[16:28]); ok && value <= math.MaxInt64 {
		stamp := int64(value)
		modified = &stamp
	}
	return rawMember{
		headerOffset: position,
		nameField:    nameField,
		size:         size,
		dataOffset:   dataOffset,
		mode:         mode,
		uid:          uid,
		gid:          gid,
		modified:     modified,
	}, nil
}

// FormatID implements archive.Reader.
func (r *Reader) FormatID() string { return "ar" }

// Entries implements archive.Reader.
func (r *Reader) Entries() ([]archive.Entry, error) {
	return append([]archive.Entry(nil), r.archives...), nil
}

// FindEntry implements archive.Reader.
func (r *Reader) FindEntry(path string) (archive.Entry, bool, error) {
	index, ok := r.byPath[path]
	if !ok {
		return archive.Entry{}, false, nil
	}
	return r.archives[index], true, nil
}

// OpenEntry implements archive.Reader.
func (r *Reader) OpenEntry(path string, sourceID source.ID) (source.ByteSource, error) {
	index, ok := r.byPath[path]
	if !ok {
		return nil, archive.Invalidf("AR has no entry named %s", path)
	}
	return newEntrySource(sourceID, r.source, r.entries[index]), nil
}

// RawEntries returns the format-level member records.
func (r *Reader) RawEntries() []Entry { return append([]Entry(nil), r.entries...) }

// Stats returns the scan counters.
func (r *Reader) Stats() Stats { return r.stats }

// Adapter registers the ar parser with the archive registry.
type Adapter struct{}

// FormatID implements archive.Adapter.
func (Adapter) FormatID() string { return "ar" }

// Open implements archive.Adapter.
func (Adapter) Open(src source.ByteSource, limits archive.Limits) (archive.Reader, error) {
	return Open(src, limits)
}

// Register adds the ar parser for the "ar" format id.
func Register(registry *archive.Registry) error {
	return registry.Register(Adapter{})
}

// resolveName returns the resolved name, the UTF-8 flag, the data offset, and
// the data length.
func resolveName(src source.ByteSource, member rawMember, table []byte) (string, bool, uint64, uint64, error) {
	field := member.nameField

	if strings.HasPrefix(field, "#1/") {
		length, err := strconv.ParseUint(field[len("#1/"):], 10, 64)
		if err != nil {
			return "", false, 0, 0, archive.Invalidf("the BSD name length %q is not a number", field[len("#1/"):])
		}
		if length > member.size {
			return "", false, 0, 0, archive.Invalidf("the BSD name length %d is larger than the %d-byte member", length, member.size)
		}
		bytes, err := source.ReadVecAt(src, member.dataOffset, length)
		if err != nil {
			return "", false, 0, 0, err
		}
		for len(bytes) > 0 && bytes[len(bytes)-1] == 0 {
			bytes = bytes[:len(bytes)-1]
		}
		name, invalid := lossy(bytes)
		return name, invalid, member.dataOffset + length, member.size - length, nil
	}

	if strings.HasPrefix(field, "/") {
		reference := field[1:]
		if reference != "" && allDigits(reference) {
			offset, err := strconv.ParseUint(reference, 10, 64)
			if err != nil {
				return "", false, 0, 0, archive.Invalidf("the long-name offset %q is out of range", reference)
			}
			if table == nil {
				return "", false, 0, 0, archive.Invalidf("the member references a long-name table that is not in the archive")
			}
			if offset >= uint64(len(table)) {
				return "", false, 0, 0, archive.Invalidf("the long-name offset %d is outside the %d-byte table", offset, len(table))
			}
			rest := table[offset:]
			end := len(rest)
			for i, b := range rest {
				if b == '\n' {
					end = i
					break
				}
			}
			name := rest[:end]
			for len(name) > 0 && name[len(name)-1] == '/' {
				name = name[:len(name)-1]
			}
			text, invalid := lossy(name)
			return text, invalid, member.dataOffset, member.size, nil
		}
	}

	name := field
	for strings.HasSuffix(name, "/") {
		name = name[:len(name)-1]
	}
	return name, false, member.dataOffset, member.size, nil
}

func isSymbolTable(name string) bool {
	switch name {
	case "/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "ARFILENAMES/":
		return true
	default:
		return false
	}
}

func checkTrailing(src source.ByteSource, offset, remaining uint64) error {
	if remaining == 0 {
		return nil
	}
	bytes, err := source.ReadVecAt(src, offset, remaining)
	if err != nil {
		return err
	}
	for _, b := range bytes {
		if b != '\n' && b != 0 {
			return archive.Invalidf("%d bytes follow the last member and are not padding", remaining)
		}
	}
	return nil
}

func fieldText(bytes []byte) string {
	text := lossyText(bytes)
	return strings.TrimRight(text, " ")
}

func requiredDecimalField(bytes []byte, what string, offset uint64) (uint64, error) {
	if !utf8.Valid(bytes) {
		return 0, archive.Invalidf("%s is not ASCII", what)
	}
	text := strings.Trim(string(bytes), " ")
	if text == "" {
		return 0, archive.Invalidf("%s is empty", what)
	}
	if !allDigits(text) {
		return 0, archive.Invalidf("%s %q is not a decimal number", what, text)
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, archive.Invalidf("%s %q overflows", what, text)
	}
	return value, nil
}

func optionalDecimalField(bytes []byte) (uint64, bool) {
	if !utf8.Valid(bytes) {
		return 0, false
	}
	text := strings.Trim(string(bytes), " ")
	if text == "" || !allDigits(text) {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func octalField(bytes []byte) (uint32, bool) {
	if !utf8.Valid(bytes) {
		return 0, false
	}
	text := strings.Trim(string(bytes), " ")
	if text == "" {
		return 0, true
	}
	value, err := strconv.ParseUint(text, 8, 32)
	if err != nil {
		return 0, false
	}
	return uint32(value), true
}

func allDigits(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
}

func lossy(bytes []byte) (string, bool) {
	if utf8.Valid(bytes) {
		return string(bytes), false
	}
	return lossyText(bytes), true
}

func lossyText(bytes []byte) string {
	if utf8.Valid(bytes) {
		return string(bytes)
	}
	return strings.ToValidUTF8(string(bytes), "�")
}

// EntrySource is one member's data exposed as a ByteSource.
type EntrySource struct {
	id       source.ID
	parent   source.ByteSource
	entry    Entry
	counters source.Counters
}

func newEntrySource(id source.ID, parent source.ByteSource, entry Entry) *EntrySource {
	return &EntrySource{id: id, parent: parent, entry: entry}
}

// Entry returns the member this source exposes.
func (s *EntrySource) Entry() Entry { return s.entry }

// DataOffset returns the offset of the data area in the parent.
func (s *EntrySource) DataOffset() uint64 { return s.entry.DataOffset }

// SourceID implements source.ByteSource.
func (s *EntrySource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *EntrySource) Len() uint64 { return s.entry.Size }

// ImageID implements source.ByteSource.
func (s *EntrySource) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *EntrySource) SectorSize() uint32 { return s.parent.SectorSize() }

// ReadAt implements source.ByteSource.
func (s *EntrySource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.entry.Size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.entry.Size)
	}
	want := uint64(len(buf))
	if want > s.entry.Size-offset {
		want = s.entry.Size - offset
	}
	n, err := s.parent.ReadAt(s.entry.DataOffset+offset, buf[:want])
	if err != nil {
		return n, err
	}
	s.counters.AddRead(n)
	return n, nil
}

// ReadAtLossy implements source.ByteSource.
func (s *EntrySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

// ExtentsInto implements source.ByteSource.
func (s *EntrySource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.entry.Size || length > s.entry.Size-offset {
		return out, source.NewOutOfRange(offset, length, s.entry.Size)
	}
	if length > 0 {
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: s.entry.DataOffset + offset,
			Len:          length,
			Kind:         source.RangeData,
		})
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *EntrySource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *EntrySource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.entry.Size || length > s.entry.Size-offset {
		return nil, source.NewOutOfRange(offset, length, s.entry.Size)
	}
	if length == 0 {
		return nil, nil
	}
	return s.parent.MapToImage(s.entry.DataOffset+offset, length)
}

// Stats implements source.ByteSource.
func (s *EntrySource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *EntrySource) IsEmpty() bool { return s.entry.Size == 0 }

var _ source.ByteSource = (*EntrySource)(nil)
