// Cross-reference sections and the trailer.
//
// A PDF names its objects indirectly: `12 0 R` means "the object written with
// number 12, generation 0", and the cross-reference section is the table that
// turns that name into a byte offset (or into a slot of an object stream). The
// last `startxref` at the end of the file names the section; incremental
// updates chain back through /Prev, so the newest definition of an object wins
// and older sections still name objects the update did not touch.
//
// Two forms exist and both are read here: the classic `xref` keyword followed
// by fixed-width entries and a trailer dictionary, and a compressed
// cross-reference stream whose entries are packed in binary fields described
// by /W, usually Flate-compressed with a PNG predictor. A hybrid file may also
// carry an /XRefStm that fills entries the classic table omits.
//
// When the chain cannot be read — a truncated tail, an offset past the end of
// the file, a /Prev loop — ReadXrefWithRepair scans the byte stream for object
// headers and rebuilds the table. The result is marked Repaired and every note
// explaining the decision is kept, because a rebuilt table is weaker evidence
// than one the file wrote itself.

package pdf

import (
	"bytes"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// DefaultMaxSectionBytes is the largest cross-reference section or stream
	// the reader will load (32 MiB).
	DefaultMaxSectionBytes = 32 * 1024 * 1024
	// DefaultMaxXrefObjects is the most objects a table may name.
	DefaultMaxXrefObjects = 4_000_000
	// DefaultMaxUpdates is the most incremental updates a /Prev chain may hold.
	DefaultMaxUpdates = 256
	// DefaultRepairBytes is how far into the file the repair scan reads.
	DefaultRepairBytes uint64 = 64 * 1024 * 1024
	// StartxrefWindow is how much of the tail is searched for startxref.
	StartxrefWindow uint64 = 64 * 1024
)

// XrefLimits bound cross-reference parsing.
type XrefLimits struct {
	MaxSectionBytes int
	MaxObjects      int
	MaxUpdates      int
	MaxRepairBytes  uint64
}

// DefaultXrefLimits returns the default bounds.
func DefaultXrefLimits() XrefLimits {
	return XrefLimits{
		MaxSectionBytes: DefaultMaxSectionBytes,
		MaxObjects:      DefaultMaxXrefObjects,
		MaxUpdates:      DefaultMaxUpdates,
		MaxRepairBytes:  DefaultRepairBytes,
	}
}

func (l XrefLimits) normalized() XrefLimits {
	def := DefaultXrefLimits()
	if l.MaxSectionBytes <= 0 {
		l.MaxSectionBytes = def.MaxSectionBytes
	}
	if l.MaxObjects <= 0 {
		l.MaxObjects = def.MaxObjects
	}
	if l.MaxUpdates <= 0 {
		l.MaxUpdates = def.MaxUpdates
	}
	if l.MaxRepairBytes == 0 {
		l.MaxRepairBytes = def.MaxRepairBytes
	}
	return l
}

// XrefKind is which syntax a cross-reference section uses.
type XrefKind uint8

const (
	// XrefKindTable is `xref … trailer`.
	XrefKindTable XrefKind = iota
	// XrefKindStream is an indirect object whose dictionary has /Type /XRef.
	XrefKindStream
)

// Label names the section syntax.
func (k XrefKind) Label() string {
	if k == XrefKindStream {
		return "stream"
	}
	return "table"
}

// XrefEntryKind is what one cross-reference entry describes.
type XrefEntryKind uint8

const (
	// EntryFree is a free slot.
	EntryFree XrefEntryKind = iota
	// EntryInFile is an object written directly in the file at Offset.
	EntryInFile
	// EntryInStream is an object stored inside an object stream.
	EntryInStream
)

// XrefEntry is one object named by a cross-reference section.
type XrefEntry struct {
	Kind       XrefEntryKind
	NextFree   uint32
	Offset     uint64
	Generation uint16
	Stream     uint32
	Index      uint32
}

// IsFree reports whether the entry is a free slot.
func (e XrefEntry) IsFree() bool { return e.Kind == EntryFree }

// GenerationValue returns the generation the section records, when it records
// one.
func (e XrefEntry) GenerationValue() (uint16, bool) {
	switch e.Kind {
	case EntryFree, EntryInFile:
		return e.Generation, true
	}
	return 0, false
}

// XrefSection is one section of the cross-reference chain.
type XrefSection struct {
	Kind    XrefKind
	Start   uint64
	Entries map[uint32]XrefEntry
	Trailer *Dict
	// Hybrid is the offset of an /XRefStm hybrid stream merged into this
	// table, if any.
	Hybrid *uint64
}

// Xref is a merged cross-reference chain, newest section first.
type Xref struct {
	Sections []XrefSection
	// Entries holds the newest entry for every object number.
	Entries map[uint32]XrefEntry
	// Trailer is the newest trailer, with keys older trailers still provide
	// filled in.
	Trailer  *Dict
	Updates  int
	Repaired bool
	Notes    []string
}

// Entry returns the newest entry for an object number.
func (x *Xref) Entry(number uint32) (XrefEntry, bool) {
	entry, ok := x.Entries[number]
	return entry, ok
}

// Root returns the catalog reference from the newest trailer that names one.
func (x *Xref) Root() (Reference, bool) {
	if x == nil || x.Trailer == nil {
		return Reference{}, false
	}
	return x.Trailer.GetRef([]byte("Root"))
}

// InfoRef returns the information dictionary reference.
func (x *Xref) InfoRef() (Reference, bool) {
	if x == nil || x.Trailer == nil {
		return Reference{}, false
	}
	return x.Trailer.GetRef([]byte("Info"))
}

// IsEncrypted reports whether a trailer carries an /Encrypt dictionary.
func (x *Xref) IsEncrypted() bool {
	if x == nil || x.Trailer == nil {
		return false
	}
	value, ok := x.Trailer.Get([]byte("Encrypt"))
	if !ok {
		return false
	}
	_, ok = value.AsDict()
	return ok
}

// ReadXref reads the cross-reference chain named by the last startxref.
func ReadXref(src source.ByteSource, limits XrefLimits) (*Xref, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	start, err := FindStartxref(src)
	if err != nil {
		return nil, err
	}
	return readChain(src, start, limits.normalized())
}

// ReadXrefWithRepair reads the chain, and rebuilds it by scanning when it
// cannot be read. A repaired table carries the original error in its Notes.
func ReadXrefWithRepair(src source.ByteSource, limits XrefLimits) (*Xref, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	limits = limits.normalized()
	chain, err := ReadXref(src, limits)
	if err == nil {
		return chain, nil
	}
	repaired, repairErr := RepairXref(src, limits)
	if repairErr != nil {
		return nil, repairErr
	}
	repaired.Notes = append(repaired.Notes,
		"cross-reference chain unreadable ("+err.Error()+"); rebuilt by scanning object headers")
	return repaired, nil
}

// FindStartxref returns the byte offset named by the last startxref keyword.
func FindStartxref(src source.ByteSource) (uint64, error) {
	if src == nil {
		return 0, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	length := src.Len()
	if length == 0 {
		return 0, corrupt(0, "PDF file is empty")
	}
	window := length
	if window > StartxrefWindow {
		window = StartxrefWindow
	}
	tail, err := readSource(src, length-window, window)
	if err != nil {
		return 0, err
	}
	keyword := []byte("startxref")
	position := bytes.LastIndex(tail, keyword)
	if position < 0 {
		return 0, corrupt(length-window, "no startxref keyword in the last %d bytes of the PDF", window)
	}
	parser := NewParser(tail[position+len(keyword):]).WithBase(length - window + uint64(position+len(keyword)))
	offset, err := parser.ReadUnsigned("startxref offset")
	if err != nil {
		return 0, err
	}
	if offset >= length {
		return 0, corrupt(length-window+uint64(position), "startxref names byte %d, past the end of the %d byte file", offset, length)
	}
	return offset, nil
}

func readChain(src source.ByteSource, start uint64, limits XrefLimits) (*Xref, error) {
	var sections []XrefSection
	visited := make(map[uint64]bool)
	next := start
	haveNext := true
	for haveNext {
		if len(sections) >= limits.MaxUpdates {
			return nil, limitError("cross-reference chain has more than %d sections", limits.MaxUpdates)
		}
		if visited[next] {
			return nil, corrupt(next, "cross-reference /Prev chain revisits byte %d", next)
		}
		visited[next] = true
		section, err := readSection(src, next, limits)
		if err != nil {
			return nil, err
		}
		if section.Trailer != nil {
			if streamOffset, ok := section.Trailer.GetInt([]byte("XRefStm")); ok {
				if streamOffset < 0 {
					return nil, corrupt(next, "/XRefStm names a negative offset")
				}
				offset := uint64(streamOffset)
				if offset < src.Len() {
					hybrid, err := readSection(src, offset, limits)
					if err != nil {
						return nil, err
					}
					if hybrid.Kind != XrefKindStream {
						return nil, corrupt(offset, "hybrid /XRefStm at byte %d is not an xref stream", offset)
					}
					for number, entry := range hybrid.Entries {
						if _, exists := section.Entries[number]; !exists {
							section.Entries[number] = entry
						}
					}
					section.Hybrid = &offset
				}
			}
		}

		var previous uint64
		havePrevious := false
		if section.Trailer != nil {
			value, hasPrev := section.Trailer.Get([]byte("Prev"))
			if hasPrev && value.Kind() != KindNull {
				offset, ok := value.AsInt()
				if !ok {
					return nil, corrupt(next, "/Prev is not an integer offset")
				}
				if offset < 0 {
					return nil, corrupt(next, "/Prev names a negative offset")
				}
				if uint64(offset) >= src.Len() {
					return nil, corrupt(next, "/Prev names byte %d, past the end of the %d byte file", offset, src.Len())
				}
				previous = uint64(offset)
				havePrevious = true
			}
		}
		sections = append(sections, section)
		next = previous
		haveNext = havePrevious
	}

	entries := make(map[uint32]XrefEntry)
	trailer := NewDict()
	for _, section := range sections {
		for number, entry := range section.Entries {
			if _, exists := entries[number]; !exists {
				entries[number] = entry
			}
		}
		if section.Trailer == nil {
			continue
		}
		for _, item := range section.Trailer.Items() {
			if string(item.Key) == "Prev" || string(item.Key) == "XRefStm" || trailer.Contains(item.Key) {
				continue
			}
			trailer.SetBytes(item.Key, item.Value)
		}
	}
	return &Xref{Sections: sections, Entries: entries, Trailer: trailer, Updates: len(sections)}, nil
}

func readSection(src source.ByteSource, offset uint64, limits XrefLimits) (XrefSection, error) {
	window, err := readWindow(src, offset, limits.MaxSectionBytes)
	if err != nil {
		return XrefSection{}, err
	}
	parser := NewParser(window).WithBase(offset)
	parser.SkipSpace()
	if parser.TakeKeyword([]byte("xref")) {
		entries, trailer, err := parseTable(parser, src.Len(), limits)
		if err != nil {
			return XrefSection{}, err
		}
		return XrefSection{Kind: XrefKindTable, Start: offset, Entries: entries, Trailer: trailer}, nil
	}

	parser.SkipSpace()
	reference, err := parser.ParseIndirectHeader()
	if err != nil {
		return XrefSection{}, err
	}
	value, err := parser.ParseValue()
	if err != nil {
		return XrefSection{}, err
	}
	dict, ok := value.AsDict()
	if !ok {
		return XrefSection{}, corrupt(offset, "xref object %d at byte %d is not a dictionary", reference.Number, offset)
	}
	if typeValue, hasType := dict.Get([]byte("Type")); hasType {
		if !IsName(typeValue, []byte("XRef")) {
			name, _ := typeValue.AsName()
			return XrefSection{}, corrupt(offset, "object at byte %d has /Type %s instead of /XRef", offset, lossyUTF8(name))
		}
	}
	if !dict.Contains([]byte("W")) {
		return XrefSection{}, corrupt(offset, "object at byte %d is not a cross-reference stream: it has no /W array", offset)
	}
	dataPosition, err := parser.ParseStreamStart()
	if err != nil {
		return XrefSection{}, err
	}
	dataOffset := offset + uint64(dataPosition)
	raw, err := sectionStreamBytes(src, window, offset, dataOffset, dict, limits.MaxSectionBytes)
	if err != nil {
		return XrefSection{}, err
	}
	decoded, err := DecodeStream(dict, raw, limits.MaxSectionBytes)
	if err != nil {
		return XrefSection{}, err
	}
	entries, err := parseStreamEntries(decoded.Bytes, dict, src.Len(), limits)
	if err != nil {
		return XrefSection{}, err
	}
	return XrefSection{Kind: XrefKindStream, Start: offset, Entries: entries, Trailer: dict}, nil
}

func readWindow(src source.ByteSource, offset uint64, max int) ([]byte, error) {
	length := src.Len()
	if offset >= length {
		return nil, corrupt(offset, "cross-reference offset %d is at or past the end of the %d byte file", offset, length)
	}
	want := length - offset
	if want > uint64(max) {
		want = uint64(max)
	}
	return readSource(src, offset, want)
}

// sectionStreamBytes returns the bytes of a stream whose dictionary is at the
// start of window. /Length is used when it is a direct integer; a length given
// indirectly cannot be resolved here, so the bytes are taken up to endstream.
func sectionStreamBytes(src source.ByteSource, window []byte, windowOffset, dataOffset uint64, dict *Dict, limit int) ([]byte, error) {
	if dataOffset < windowOffset {
		return nil, corrupt(dataOffset, "xref stream starts outside its own window")
	}
	local := dataOffset - windowOffset
	if local > uint64(len(window)) {
		return nil, corrupt(dataOffset, "xref stream data starts past the end of the section window")
	}
	if length, ok := dict.GetInt([]byte("Length")); ok {
		if length < 0 {
			return nil, corrupt(dataOffset, "stream /Length is negative")
		}
		if length > int64(limit) {
			return nil, limitError("PDF stream of %d bytes exceeds the %d byte limit", length, limit)
		}
		available := src.Len() - dataOffset
		if uint64(length) > available {
			return nil, corrupt(dataOffset, "stream /Length %d runs past the end of the %d byte file", length, src.Len())
		}
		return readSource(src, dataOffset, uint64(length))
	}
	rest := window[local:]
	end := bytes.Index(rest, []byte("endstream"))
	if end < 0 {
		return nil, corrupt(dataOffset, "stream has no direct /Length and no endstream keyword in its section window")
	}
	for end > 0 && (rest[end-1] == '\r' || rest[end-1] == '\n') {
		end--
	}
	return append([]byte(nil), rest[:end]...), nil
}

func parseTable(parser *Parser, sourceLen uint64, limits XrefLimits) (map[uint32]XrefEntry, *Dict, error) {
	entries := make(map[uint32]XrefEntry)
	for {
		parser.SkipSpace()
		if parser.TakeKeyword([]byte("trailer")) {
			value, err := parser.ParseValue()
			if err != nil {
				return nil, nil, err
			}
			dict, ok := value.AsDict()
			if !ok {
				return nil, nil, corrupt(parser.base+uint64(parser.Position()), "xref trailer is not a dictionary")
			}
			return entries, dict, nil
		}
		if parser.AtEnd() {
			return nil, nil, corrupt(parser.base+uint64(parser.Position()), "xref table ends without a trailer dictionary")
		}
		start, err := parser.ReadUnsigned("xref subsection start")
		if err != nil {
			return nil, nil, err
		}
		count, err := parser.ReadUnsigned("xref subsection count")
		if err != nil {
			return nil, nil, err
		}
		if count > uint64(limits.MaxObjects) {
			return nil, nil, limitError("xref subsection declares %d entries, more than the %d object limit", count, limits.MaxObjects)
		}
		end := start + count
		if end < start {
			return nil, nil, corrupt(parser.base+uint64(parser.Position()), "xref subsection range overflows")
		}
		if end > uint64(1)<<32 {
			return nil, nil, corrupt(parser.base+uint64(parser.Position()), "xref subsection ends at object %d, beyond the object number space", end)
		}
		for number := start; number < end; number++ {
			offset, err := parser.ReadUnsigned("xref entry offset")
			if err != nil {
				return nil, nil, err
			}
			generation, err := parser.ReadUnsigned("xref entry generation")
			if err != nil {
				return nil, nil, err
			}
			if generation > 65535 {
				return nil, nil, corrupt(parser.base+uint64(parser.Position()), "xref entry %d has generation %d, above 65535", number, generation)
			}
			parser.SkipSpace()
			position := parser.Position()
			if position >= len(parser.bytes) {
				return nil, nil, corrupt(parser.base+uint64(position), "xref table ends inside an entry")
			}
			kindByte := parser.bytes[position]
			parser.SetPosition(position + 1)
			var entry XrefEntry
			switch kindByte {
			case 'n':
				if offset >= sourceLen {
					return nil, nil, corrupt(parser.base+uint64(position),
						"xref entry %d names byte %d, past the end of the %d byte file", number, offset, sourceLen)
				}
				entry = XrefEntry{Kind: EntryInFile, Offset: offset, Generation: uint16(generation)}
			case 'f':
				nextFree := uint32(0xFFFFFFFF)
				if offset <= 0xFFFFFFFF {
					nextFree = uint32(offset)
				}
				entry = XrefEntry{Kind: EntryFree, NextFree: nextFree, Generation: uint16(generation)}
			default:
				return nil, nil, corrupt(parser.base+uint64(position), "xref entry %d has type 0x%02x, not `n` or `f`", number, kindByte)
			}
			if _, exists := entries[uint32(number)]; exists {
				return nil, nil, corrupt(parser.base+uint64(position), "xref table names object %d twice", number)
			}
			entries[uint32(number)] = entry
		}
	}
}

func parseStreamEntries(data []byte, dict *Dict, sourceLen uint64, limits XrefLimits) (map[uint32]XrefEntry, error) {
	widthValues, ok := dict.GetArray([]byte("W"))
	if !ok {
		return nil, corrupt(0, "cross-reference stream /W is not an array")
	}
	if len(widthValues) != 3 {
		return nil, corrupt(0, "cross-reference stream /W has %d entries, not three", len(widthValues))
	}
	var fields [3]int
	for index, value := range widthValues {
		width, ok := value.AsInt()
		if !ok {
			return nil, corrupt(0, "cross-reference stream /W holds a non-integer")
		}
		if width < 0 || width > 8 {
			return nil, corrupt(0, "cross-reference stream /W entry %d is %d, outside 0..=8", index, width)
		}
		fields[index] = int(width)
	}
	entrySize := fields[0] + fields[1] + fields[2]
	if entrySize == 0 {
		return nil, corrupt(0, "cross-reference stream /W describes zero-byte entries")
	}
	size, ok := dict.GetInt([]byte("Size"))
	if !ok {
		return nil, corrupt(0, "cross-reference stream has no /Size")
	}
	if size < 0 {
		return nil, corrupt(0, "cross-reference stream /Size is negative")
	}
	type indexRange struct{ start, count uint64 }
	var index []indexRange
	if value, hasIndex := dict.Get([]byte("Index")); hasIndex {
		values, ok := value.AsArray()
		if !ok {
			return nil, corrupt(0, "cross-reference stream /Index is not an array")
		}
		if len(values)%2 != 0 {
			return nil, corrupt(0, "cross-reference stream /Index has an odd number of entries")
		}
		for i := 0; i < len(values); i += 2 {
			start, ok := values[i].AsInt()
			if !ok || start < 0 {
				return nil, corrupt(0, "cross-reference /Index start is not a count")
			}
			count, ok := values[i+1].AsInt()
			if !ok || count < 0 {
				return nil, corrupt(0, "cross-reference /Index count is not a count")
			}
			index = append(index, indexRange{start: uint64(start), count: uint64(count)})
		}
	} else {
		index = []indexRange{{start: 0, count: uint64(size)}}
	}
	entries := make(map[uint32]XrefEntry)
	position := 0
	for _, r := range index {
		if r.count > uint64(limits.MaxObjects) {
			return nil, limitError("cross-reference stream subsection declares %d entries, more than the %d object limit", r.count, limits.MaxObjects)
		}
		end := r.start + r.count
		if end < r.start {
			return nil, corrupt(0, "cross-reference /Index range overflows")
		}
		if end > uint64(1)<<32 {
			return nil, corrupt(0, "cross-reference /Index ends at object %d", end)
		}
		for number := r.start; number < end; number++ {
			entryEnd := position + entrySize
			if entryEnd < position || entryEnd > len(data) {
				return nil, corrupt(0, "cross-reference stream ends inside the entry for object %d", number)
			}
			field := func(index int) uint64 { return readBigEndian(data, position, fields, index) }
			kind := uint64(1)
			if fields[0] != 0 {
				kind = field(0)
			}
			second := field(1)
			third := field(2)
			var entry XrefEntry
			switch kind {
			case 0:
				nextFree := uint32(0xFFFFFFFF)
				if second <= 0xFFFFFFFF {
					nextFree = uint32(second)
				}
				if third > 65535 {
					return nil, corrupt(0, "cross-reference entry %d has generation %d, above 65535", number, third)
				}
				entry = XrefEntry{Kind: EntryFree, NextFree: nextFree, Generation: uint16(third)}
			case 1:
				if second >= sourceLen {
					return nil, corrupt(0, "cross-reference entry %d names byte %d, past the end of the %d byte file", number, second, sourceLen)
				}
				if third > 65535 {
					return nil, corrupt(0, "cross-reference entry %d has generation %d, above 65535", number, third)
				}
				entry = XrefEntry{Kind: EntryInFile, Offset: second, Generation: uint16(third)}
			case 2:
				if second > 0xFFFFFFFF {
					return nil, corrupt(0, "cross-reference entry %d names object stream %d, above 2^32-1", number, second)
				}
				if third > 0xFFFFFFFF {
					return nil, corrupt(0, "cross-reference entry %d has an index above 2^32-1", number)
				}
				entry = XrefEntry{Kind: EntryInStream, Stream: uint32(second), Index: uint32(third)}
			default:
				return nil, corrupt(0, "cross-reference entry %d has type %d, not 0, 1 or 2", number, kind)
			}
			if _, exists := entries[uint32(number)]; exists {
				return nil, corrupt(0, "cross-reference stream names object %d twice", number)
			}
			entries[uint32(number)] = entry
			position = entryEnd
		}
	}
	return entries, nil
}

func readBigEndian(data []byte, start int, widths [3]int, field int) uint64 {
	offset := start
	for i := 0; i < field; i++ {
		offset += widths[i]
	}
	var value uint64
	for i := 0; i < widths[field]; i++ {
		value = value<<8 | uint64(data[offset+i])
	}
	return value
}

// RepairXref rebuilds a cross-reference table by scanning for
// `number generation obj`.
func RepairXref(src source.ByteSource, limits XrefLimits) (*Xref, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	limits = limits.normalized()
	length := src.Len()
	scan := length
	if scan > limits.MaxRepairBytes {
		scan = limits.MaxRepairBytes
	}
	window, err := readSource(src, 0, scan)
	if err != nil {
		return nil, err
	}
	var notes []string
	if uint64(scan) < length {
		notes = append(notes, sprintf("repair scanned the first %d of %d bytes for object headers", scan, length))
	}

	entries := make(map[uint32]XrefEntry)
	position := 0
	inComment := false
	for position < len(window) {
		b := window[position]
		if inComment {
			if b == '\n' || b == '\r' {
				inComment = false
			}
			position++
			continue
		}
		if b == '%' {
			inComment = true
			position++
			continue
		}
		if b >= '0' && b <= '9' && (position == 0 || isTokenBreak(window[position-1])) {
			if number, generation, after, ok := scanIndirectHeader(window, position); ok {
				if number != 0 && number <= 0xFFFFFFFF && generation <= 255 {
					entries[uint32(number)] = XrefEntry{Kind: EntryInFile, Offset: uint64(position), Generation: uint16(generation)}
					position = after
					continue
				}
			}
		}
		position++
	}
	if len(entries) == 0 {
		return nil, corrupt(0, "no indirect object headers were found while rebuilding the cross-reference")
	}

	// The last classic trailer in the file describes the newest state; an
	// incremental update writes one, so taking the last is taking the newest.
	trailer := NewDict()
	search := 0
	for {
		found := bytes.Index(window[search:], []byte("trailer"))
		if found < 0 {
			break
		}
		at := search + found
		if value, err := ParseFirstValue(window[at+7:]); err == nil {
			if dict, ok := value.AsDict(); ok {
				trailer = dict
			}
		}
		search = at + 7
	}
	if trailer.Len() == 0 {
		notes = append(notes, "no trailer dictionary was found; object headers alone rebuilt the table")
	}
	if !trailer.Contains([]byte("Root")) {
		if reference, ok := findCatalog(window); ok {
			trailer.SetBytes([]byte("Root"), RefValue(reference))
			notes = append(notes, sprintf("trailer had no /Root; object %d is the last /Type /Catalog found", reference.Number))
		}
	}
	if !trailer.Contains([]byte("Size")) {
		var maximum uint32
		haveMaximum := false
		for number := range entries {
			if !haveMaximum || number > maximum {
				maximum = number
				haveMaximum = true
			}
		}
		if haveMaximum {
			trailer.SetBytes([]byte("Size"), IntValue(int64(maximum)+1))
		}
	}

	return &Xref{Entries: entries, Trailer: trailer, Repaired: true, Notes: notes}, nil
}

func scanIndirectHeader(data []byte, start int) (uint64, uint64, int, bool) {
	position := start
	var number uint64
	digits := 0
	for position < len(data) && data[position] >= '0' && data[position] <= '9' {
		number = number*10 + uint64(data[position]-'0')
		if number > 0xFFFFFFFF {
			return 0, 0, 0, false
		}
		digits++
		if digits > 10 {
			return 0, 0, 0, false
		}
		position++
	}
	if digits == 0 || position >= len(data) || !isTokenBreak(data[position]) {
		return 0, 0, 0, false
	}
	skipBreak(data, &position)
	var generation uint64
	digits = 0
	for position < len(data) && data[position] >= '0' && data[position] <= '9' {
		generation = generation*10 + uint64(data[position]-'0')
		if generation > 0xFFFF {
			return 0, 0, 0, false
		}
		digits++
		if digits > 5 {
			return 0, 0, 0, false
		}
		position++
	}
	if digits == 0 {
		return 0, 0, 0, false
	}
	skipBreak(data, &position)
	if position+3 > len(data) || string(data[position:position+3]) != "obj" {
		return 0, 0, 0, false
	}
	after := position + 3
	if after < len(data) && !isTokenBreak(data[after]) {
		return 0, 0, 0, false
	}
	return number, generation, after, true
}

func skipBreak(data []byte, position *int) {
	for *position < len(data) && isTokenBreak(data[*position]) {
		*position = *position + 1
	}
}

// isTokenBreak reports whitespace or a delimiter ending a token in the repair
// scan.
func isTokenBreak(b byte) bool {
	return isWhitespace(b) || isDelimiter(b)
}

func findCatalog(window []byte) (Reference, bool) {
	needle := []byte("/Catalog")
	var found Reference
	haveFound := false
	search := 0
	for {
		position := bytes.Index(window[search:], needle)
		if position < 0 {
			break
		}
		at := search + position
		if start, ok := headerStartBefore(window, at); ok {
			parser := NewParser(window[start:]).WithBase(uint64(start))
			if reference, err := parser.ParseIndirectHeader(); err == nil {
				if value, err := parser.ParseValue(); err == nil {
					if dict, ok := value.AsDict(); ok {
						if IsNameValue(dict, []byte("Type"), []byte("Catalog")) {
							found = reference
							haveFound = true
						}
					}
				}
			}
		}
		search = at + len(needle)
	}
	return found, haveFound
}

// IsNameValue reports whether dict's key holds the given name.
func IsNameValue(dict *Dict, key, name []byte) bool {
	value, ok := dict.Get(key)
	if !ok {
		return false
	}
	got, ok := value.AsName()
	return ok && string(got) == string(name)
}

// headerStartBefore returns the start of the `number generation obj` header
// that precedes before, looking back at most 8 KiB and through one obj
// keyword.
func headerStartBefore(window []byte, before int) (int, bool) {
	limit := 0
	if before > 8192 {
		limit = before - 8192
	}
	found := bytes.Index(window[limit:before], []byte("obj"))
	if found < 0 {
		return 0, false
	}
	position := limit + found
	newlines := 0
	for position > limit {
		b := window[position-1]
		if b == '\n' || b == '\r' {
			newlines++
			if newlines > 2 {
				return 0, false
			}
		}
		position--
	}
	return position, true
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

func readSource(src source.ByteSource, offset, length uint64) ([]byte, error) {
	return source.ReadVecAt(src, offset, length)
}
