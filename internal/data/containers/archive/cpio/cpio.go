// Package cpio reads newc, crc, odc, and binary CPIO archives.
//
// CPIO has no index: it is a sequence of small headers, each followed by the
// file name and then the file's data.  The member that literally reads
// "TRAILER!!!" ends the stream.  This is what Linux initramfs images and many
// embedded firmware updates use.
//
// Four dialects are read:
//
//   - 070701 newc: 110-byte header, eight-digit hexadecimal fields, padded to
//     a four-byte boundary;
//   - 070702 crc: the same layout, with a byte-sum check field;
//   - 070707 odc: 76-byte header, fixed-width octal fields, no padding;
//   - the older binary form: a 26-byte header of 16-bit words, in the byte
//     order the magic selects, padded to a two-byte boundary.
//
// Member data is stored verbatim, so each entry is a window onto the parent.
// `.` and `..` entries and names that cannot become a safe relative path are
// skipped and counted.
package cpio

import (
	"bytes"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// HeaderNewc is the size of one newc/crc header.
	HeaderNewc = 110
	// HeaderOdc is the size of one odc header.
	HeaderOdc = 76
	// HeaderBinary is the size of one binary header.
	HeaderBinary = 26
	// MaxEntries bounds the member list.
	MaxEntries = 1_000_000
	// MaxNameBytes bounds a stored member name or symlink target.
	MaxNameBytes = 64 * 1024
	// TrailerName is the name that ends the archive.
	TrailerName = "TRAILER!!!"
)

var (
	// MagicNewc marks newc; header fields are hexadecimal and there is no
	// check value.
	MagicNewc = []byte("070701")
	// MagicCrc marks crc: the newc layout with a byte-sum check field.
	MagicCrc = []byte("070702")
	// MagicOdc is the old portable ASCII magic.
	MagicOdc = []byte("070707")
	// MagicBinary is the binary form's magic as a 16-bit word.
	MagicBinary uint16 = 0o70707
)

// Dialect is which CPIO stream layout an archive uses.
type Dialect uint8

const (
	// DialectNewc is the 070701 layout.
	DialectNewc Dialect = iota
	// DialectCrc is the 070702 layout.
	DialectCrc
	// DialectOdc is the old portable ASCII layout.
	DialectOdc
	// DialectBinary is the old binary layout.
	DialectBinary
)

// Label returns the dialect name.
func (d Dialect) Label() string {
	switch d {
	case DialectNewc:
		return "newc"
	case DialectCrc:
		return "crc"
	case DialectOdc:
		return "odc"
	default:
		return "binary"
	}
}

func (d Dialect) headerBytes() int {
	switch d {
	case DialectNewc, DialectCrc:
		return HeaderNewc
	case DialectOdc:
		return HeaderOdc
	default:
		return HeaderBinary
	}
}

// Alignment is the boundary the header's name and data are padded to: four
// bytes for newc/crc, two for the binary form, and none for odc.
func (d Dialect) Alignment() int {
	switch d {
	case DialectNewc, DialectCrc:
		return 4
	case DialectOdc:
		return 1
	default:
		return 2
	}
}

func (d Dialect) alignment() int { return d.Alignment() }

// BinaryOrder is the byte order of a binary header's 16-bit words.
type BinaryOrder uint8

const (
	// OrderLittle is little-endian, selected by the magic bytes 0xC7 0x71.
	OrderLittle BinaryOrder = iota
	// OrderBig is big-endian, selected by the magic bytes 0x71 0xC7.
	OrderBig
)

// Label returns the byte-order name.
func (o BinaryOrder) Label() string {
	if o == OrderBig {
		return "big-endian"
	}
	return "little-endian"
}

func binaryOrderFromMagic(bytes []byte) (BinaryOrder, bool) {
	if len(bytes) < 2 {
		return 0, false
	}
	switch {
	case bytes[0] == 0x71 && bytes[1] == 0xC7:
		return OrderBig, true
	case bytes[0] == 0xC7 && bytes[1] == 0x71:
		return OrderLittle, true
	default:
		return 0, false
	}
}

func (o BinaryOrder) word(bytes []byte) uint16 {
	if o == OrderBig {
		return uint16(bytes[0])<<8 | uint16(bytes[1])
	}
	return uint16(bytes[0]) | uint16(bytes[1])<<8
}

// EntryKind is what a member is, from the type bits of its mode word.
type EntryKind uint8

const (
	// EntryFile is a regular file.
	EntryFile EntryKind = iota
	// EntryDirectory is a directory.
	EntryDirectory
	// EntrySymlink is a symbolic link.
	EntrySymlink
	// EntryCharDevice is a character device.
	EntryCharDevice
	// EntryBlockDevice is a block device.
	EntryBlockDevice
	// EntryFifo is a named pipe.
	EntryFifo
	// EntrySocket is a socket.
	EntrySocket
)

// Label returns the human-readable kind name.
func (k EntryKind) Label() string {
	switch k {
	case EntryFile:
		return "file"
	case EntryDirectory:
		return "directory"
	case EntrySymlink:
		return "symlink"
	case EntryCharDevice:
		return "character device"
	case EntryBlockDevice:
		return "block device"
	case EntryFifo:
		return "fifo"
	default:
		return "socket"
	}
}

// HasData reports whether the entry's data area is the member's content.
func (k EntryKind) HasData() bool { return k == EntryFile }

const (
	modeTypeMask = 0o170000
	modeFIFO     = 0o010000
	modeChar     = 0o020000
	modeDir      = 0o040000
	modeBlock    = 0o060000
	modeRegular  = 0o100000
	modeSymlink  = 0o120000
	modeSocket   = 0o140000
)

func kindFromMode(mode uint32) (EntryKind, bool) {
	switch mode & modeTypeMask {
	case modeRegular:
		return EntryFile, true
	case modeDir:
		return EntryDirectory, true
	case modeSymlink:
		return EntrySymlink, true
	case modeChar:
		return EntryCharDevice, true
	case modeBlock:
		return EntryBlockDevice, true
	case modeFIFO:
		return EntryFifo, true
	case modeSocket:
		return EntrySocket, true
	default:
		return EntryFile, false
	}
}

func archiveKind(kind EntryKind) archive.Kind {
	switch kind {
	case EntryFile:
		return archive.KindFile
	case EntryDirectory:
		return archive.KindDirectory
	case EntrySymlink:
		return archive.KindSymlink
	default:
		return archive.KindOther
	}
}

// Entry is one member, as its header records it.
type Entry struct {
	HeaderOffset uint64
	Name         string
	InvalidUTF8  bool
	Kind         EntryKind
	Mode         uint32
	UID          uint32
	GID          uint32
	Ino          uint64
	Nlink        uint32
	Device       uint64
	Rdev         [2]uint32
	Modified     *int64
	Size         uint64
	DeclaredSize uint64
	DataOffset   uint64
	Check        uint32
	Link         string
	HardlinkOf   string
}

// IsDir reports whether the member is a directory.
func (e Entry) IsDir() bool { return e.Kind == EntryDirectory }

// HasStream reports whether the member has a payload that can be opened.
func (e Entry) HasStream() bool { return e.Kind.HasData() }

// Stats counts what one scan saw.
type Stats struct {
	Entries             int
	SkippedDots         uint64
	SkippedUnsafe       uint64
	UnresolvedHardlinks uint64
}

// Reader is a read-only CPIO archive.
type Reader struct {
	source      source.ByteSource
	dialect     Dialect
	binaryOrder *BinaryOrder
	entries     []Entry
	archives    []archive.Entry
	byPath      map[string]int
	trailing    uint64
	stats       Stats
}

// Matches reports whether source starts with an accepted magic.
func Matches(src source.ByteSource) bool {
	if src.Len() < 6 {
		return false
	}
	magic := make([]byte, 6)
	if err := source.ReadExactAt(src, 0, magic); err != nil {
		return false
	}
	if bytes.Equal(magic, MagicNewc) || bytes.Equal(magic, MagicCrc) || bytes.Equal(magic, MagicOdc) {
		return true
	}
	_, ok := binaryOrderFromMagic(magic)
	return ok
}

// Open scans the archive and lists its members.
func Open(src source.ByteSource, limits archive.Limits) (*Reader, error) {
	if src.Len() < 6 {
		return nil, archive.Unsupportedf("a source shorter than the 6-byte magic")
	}
	head := make([]byte, 6)
	if err := source.ReadExactAt(src, 0, head); err != nil {
		return nil, err
	}

	order, isBinary := binaryOrderFromMagic(head)
	var dialect Dialect
	switch {
	case bytes.Equal(head, MagicNewc):
		dialect = DialectNewc
	case bytes.Equal(head, MagicCrc):
		dialect = DialectCrc
	case bytes.Equal(head, MagicOdc):
		dialect = DialectOdc
	case isBinary:
		dialect = DialectBinary
	default:
		return nil, archive.Unsupportedf("the magic %q (expected newc, crc, odc, or a binary header)", string(head))
	}

	sourceLen := src.Len()
	headerBytes := dialect.headerBytes()
	budget := archive.NewBudget(limits)
	var entries []Entry
	var stats Stats
	var position uint64
	var trailing uint64

	for {
		if position > sourceLen || sourceLen-position < uint64(headerBytes) {
			return nil, archive.Invalidf("the archive ends inside a %d-byte header", headerBytes)
		}
		header := make([]byte, headerBytes)
		if err := source.ReadExactAt(src, position, header); err != nil {
			return nil, err
		}
		parsed, err := parseHeader(header, position, dialect, &order, isBinary)
		if err != nil {
			return nil, err
		}

		nameAt := position + uint64(headerBytes)
		if err := checkData(sourceLen, nameAt, parsed.nameSize, "the member name"); err != nil {
			return nil, err
		}
		nameBytes, err := readName(src, nameAt, parsed.nameSize, position)
		if err != nil {
			return nil, err
		}
		name, invalidUTF8 := decodeName(nameBytes)

		nameEnd := nameAt + parsed.nameSize
		dataOffset, err := align(nameEnd, dialect.alignment(), position)
		if err != nil {
			return nil, err
		}
		if err := checkData(sourceLen, dataOffset, parsed.size, "the entry's data"); err != nil {
			return nil, err
		}
		dataEnd := dataOffset + parsed.size
		next, err := align(dataEnd, dialect.alignment(), position)
		if err != nil {
			return nil, err
		}

		if name == TrailerName {
			if next <= sourceLen {
				trailing = sourceLen - next
			}
			break
		}

		kind, ok := kindFromMode(parsed.mode)
		if !ok {
			return nil, archive.Unsupportedf("entry %q at offset %d has no file-type bits in mode %o", name, position, parsed.mode)
		}
		if len(entries) >= MaxEntries {
			return nil, archive.Unsupportedf("more than %d entries", MaxEntries)
		}

		link := ""
		if kind == EntrySymlink {
			link, err = readSymlink(src, dataOffset, parsed.size, position)
			if err != nil {
				return nil, err
			}
		}

		entry := Entry{
			HeaderOffset: position,
			Name:         name,
			InvalidUTF8:  invalidUTF8,
			Kind:         kind,
			Mode:         parsed.mode,
			UID:          parsed.uid,
			GID:          parsed.gid,
			Ino:          parsed.ino,
			Nlink:        parsed.nlink,
			Device:       parsed.device,
			Rdev:         parsed.rdev,
			Size:         parsed.size,
			DeclaredSize: parsed.size,
			DataOffset:   dataOffset,
			Check:        parsed.check,
			Link:         link,
		}
		if parsed.mtime != 0 {
			stamp := int64(parsed.mtime)
			entry.Modified = &stamp
		}

		// `.` and `..` are directory names, not members an archive view can
		// place below a root.  They are counted, not listed.
		if name == "." || name == ".." {
			stats.SkippedDots++
		} else if _, err := archive.SanitizeEntryPath(name); err != nil {
			stats.SkippedUnsafe++
		} else {
			entries = append(entries, entry)
		}
		position = next
	}

	// Hard links: newc stores the data with one name of the group and a
	// zero-length entry with each earlier name.  Point the empty ones at the
	// member that carries the data.
	holders := make(map[hardlinkKey]int)
	for index, entry := range entries {
		if entry.Kind == EntryFile && entry.DeclaredSize > 0 && entry.Nlink > 1 {
			key := hardlinkKey{device: entry.Device, ino: entry.Ino}
			if _, exists := holders[key]; !exists {
				holders[key] = index
			}
		}
	}
	for index := range entries {
		entry := &entries[index]
		if entry.Kind != EntryFile || entry.Nlink <= 1 || entry.DeclaredSize != 0 {
			continue
		}
		holderIndex, ok := holders[hardlinkKey{device: entry.Device, ino: entry.Ino}]
		if !ok {
			stats.UnresolvedHardlinks++
			continue
		}
		holder := &entries[holderIndex]
		entry.DataOffset = holder.DataOffset
		entry.Size = holder.DeclaredSize
		entry.HardlinkOf = holder.Name
	}

	stats.Entries = len(entries)
	archives := make([]archive.Entry, 0, len(entries))
	byPath := make(map[string]int, len(entries))
	for index, entry := range entries {
		archiveEntry, err := archive.NewEntry(entry.Name, archiveKind(entry.Kind), entry.Size)
		if err != nil {
			return nil, err
		}
		archiveEntry.Modified = entry.Modified
		if err := budget.Admit(archiveEntry); err != nil {
			return nil, err
		}
		if _, exists := byPath[archiveEntry.Path]; !exists {
			byPath[archiveEntry.Path] = index
		}
		archives = append(archives, archiveEntry)
	}

	return &Reader{
		source:      src,
		dialect:     dialect,
		binaryOrder: orderPointer(dialect, order),
		entries:     entries,
		archives:    archives,
		byPath:      byPath,
		trailing:    trailing,
		stats:       stats,
	}, nil
}

func orderPointer(dialect Dialect, order BinaryOrder) *BinaryOrder {
	if dialect != DialectBinary {
		return nil
	}
	value := order
	return &value
}

type hardlinkKey struct {
	device uint64
	ino    uint64
}

// FormatID implements archive.Reader.
func (r *Reader) FormatID() string { return "cpio" }

// Dialect returns the stream dialect.
func (r *Reader) Dialect() Dialect { return r.dialect }

// BinaryOrder returns the byte order of a binary archive; nil for the ASCII
// dialects, whose fields carry their own encoding.
func (r *Reader) BinaryOrder() *BinaryOrder { return r.binaryOrder }

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
		return nil, archive.Invalidf("CPIO has no entry named %s", path)
	}
	entry := r.entries[index]
	if !entry.HasStream() {
		return nil, archive.Unsupportedf("the %s %s has no data stream", entry.Kind.Label(), entry.Name)
	}
	return newEntrySource(sourceID, r.source, entry), nil
}

// RawEntries returns the format-level member records.
func (r *Reader) RawEntries() []Entry { return append([]Entry(nil), r.entries...) }

// TrailingBytes returns the bytes after TRAILER!!!.
func (r *Reader) TrailingBytes() uint64 { return r.trailing }

// Stats returns the scan counters.
func (r *Reader) Stats() Stats { return r.stats }

// Adapter registers the CPIO parser with the archive registry.
type Adapter struct{}

// FormatID implements archive.Adapter.
func (Adapter) FormatID() string { return "cpio" }

// Open implements archive.Adapter.
func (Adapter) Open(src source.ByteSource, limits archive.Limits) (archive.Reader, error) {
	return Open(src, limits)
}

// Register adds the CPIO parser for the "cpio" format id.
func Register(registry *archive.Registry) error {
	return registry.Register(Adapter{})
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

type parsedHeader struct {
	ino      uint64
	mode     uint32
	uid      uint32
	gid      uint32
	nlink    uint32
	mtime    uint32
	size     uint64
	device   uint64
	rdev     [2]uint32
	nameSize uint64
	check    uint32
}

func parseHeader(bytes []byte, offset uint64, dialect Dialect, order *BinaryOrder, isBinary bool) (parsedHeader, error) {
	switch dialect {
	case DialectNewc, DialectCrc:
		return parseNewc(bytes, offset)
	case DialectOdc:
		return parseOdc(bytes, offset)
	default:
		if !isBinary || order == nil {
			return parsedHeader{}, archive.Invalidf("a binary header was opened without a byte order")
		}
		return parseBinary(bytes, offset, *order)
	}
}

func parseNewc(bytes []byte, offset uint64) (parsedHeader, error) {
	field := func(at int, what string) (uint64, error) {
		return hexField(bytes[at:at+8], what)
	}
	ino, err := field(6, "ino")
	if err != nil {
		return parsedHeader{}, err
	}
	mode, err := toU32Field(field, 14, "mode")
	if err != nil {
		return parsedHeader{}, err
	}
	uid, err := toU32Field(field, 22, "uid")
	if err != nil {
		return parsedHeader{}, err
	}
	gid, err := toU32Field(field, 30, "gid")
	if err != nil {
		return parsedHeader{}, err
	}
	nlink, err := toU32Field(field, 38, "nlink")
	if err != nil {
		return parsedHeader{}, err
	}
	mtime, err := toU32Field(field, 46, "mtime")
	if err != nil {
		return parsedHeader{}, err
	}
	size, err := field(54, "filesize")
	if err != nil {
		return parsedHeader{}, err
	}
	devMajor, err := field(62, "devmajor")
	if err != nil {
		return parsedHeader{}, err
	}
	devMinor, err := field(70, "devminor")
	if err != nil {
		return parsedHeader{}, err
	}
	rdevMajor, err := field(78, "rdevmajor")
	if err != nil {
		return parsedHeader{}, err
	}
	rdevMinor, err := field(86, "rdevminor")
	if err != nil {
		return parsedHeader{}, err
	}
	if rdevMajor > math.MaxUint32 {
		return parsedHeader{}, archive.Invalidf("the rdevmajor field does not fit in 32 bits")
	}
	if rdevMinor > math.MaxUint32 {
		return parsedHeader{}, archive.Invalidf("the rdevminor field does not fit in 32 bits")
	}
	nameSize, err := field(94, "namesize")
	if err != nil {
		return parsedHeader{}, err
	}
	check, err := toU32Field(field, 102, "check")
	if err != nil {
		return parsedHeader{}, err
	}

	return parsedHeader{
		ino:      ino,
		mode:     mode,
		uid:      uid,
		gid:      gid,
		nlink:    nlink,
		mtime:    mtime,
		size:     size,
		device:   devMajor<<32 | devMinor,
		rdev:     [2]uint32{uint32(rdevMajor), uint32(rdevMinor)},
		nameSize: nameSize,
		check:    check,
	}, nil
}

func parseOdc(bytes []byte, offset uint64) (parsedHeader, error) {
	field := func(at, width int, what string) (uint64, error) {
		return octalField(bytes[at:at+width], what)
	}
	device, err := field(6, 6, "dev")
	if err != nil {
		return parsedHeader{}, err
	}
	ino, err := field(12, 6, "ino")
	if err != nil {
		return parsedHeader{}, err
	}
	mode, err := toU32Odc(field, 18, 6, "mode")
	if err != nil {
		return parsedHeader{}, err
	}
	uid, err := toU32Odc(field, 24, 6, "uid")
	if err != nil {
		return parsedHeader{}, err
	}
	gid, err := toU32Odc(field, 30, 6, "gid")
	if err != nil {
		return parsedHeader{}, err
	}
	nlink, err := toU32Odc(field, 36, 6, "nlink")
	if err != nil {
		return parsedHeader{}, err
	}
	rdev, err := toU32Odc(field, 42, 6, "rdev")
	if err != nil {
		return parsedHeader{}, err
	}
	mtime, err := toU32Odc(field, 48, 11, "mtime")
	if err != nil {
		return parsedHeader{}, err
	}
	nameSize, err := field(59, 6, "namesize")
	if err != nil {
		return parsedHeader{}, err
	}
	size, err := field(65, 11, "filesize")
	if err != nil {
		return parsedHeader{}, err
	}

	return parsedHeader{
		ino:      ino,
		mode:     mode,
		uid:      uid,
		gid:      gid,
		nlink:    nlink,
		mtime:    mtime,
		size:     size,
		device:   device,
		rdev:     [2]uint32{rdev, 0},
		nameSize: nameSize,
	}, nil
}

func parseBinary(bytes []byte, offset uint64, order BinaryOrder) (parsedHeader, error) {
	word := func(at int) uint16 { return order.word(bytes[at : at+2]) }
	magic := word(0)
	if magic != MagicBinary {
		return parsedHeader{}, archive.Invalidf("the binary magic is %#o, not %#o", magic, MagicBinary)
	}
	mtime := uint32(word(16))<<16 | uint32(word(18))
	size := uint64(word(22))<<16 | uint64(word(24))
	return parsedHeader{
		ino:      uint64(word(4)),
		mode:     uint32(word(6)),
		uid:      uint32(word(8)),
		gid:      uint32(word(10)),
		nlink:    uint32(word(12)),
		mtime:    mtime,
		size:     size,
		device:   uint64(word(2)),
		rdev:     [2]uint32{uint32(word(14)), 0},
		nameSize: uint64(word(20)),
	}, nil
}

type fieldFunc func(at int, what string) (uint64, error)

func toU32Field(field fieldFunc, at int, what string) (uint32, error) {
	value, err := field(at, what)
	if err != nil {
		return 0, err
	}
	if value > math.MaxUint32 {
		return 0, archive.Invalidf("the %s field does not fit in 32 bits", what)
	}
	return uint32(value), nil
}

func toU32Odc(field func(at, width int, what string) (uint64, error), at, width int, what string) (uint32, error) {
	value, err := field(at, width, what)
	if err != nil {
		return 0, err
	}
	if value > math.MaxUint32 {
		return 0, archive.Invalidf("the %s field does not fit in 32 bits", what)
	}
	return uint32(value), nil
}

func hexField(bytes []byte, what string) (uint64, error) {
	var value uint64
	for _, b := range bytes {
		digit, ok := hexDigit(b)
		if !ok {
			return 0, archive.Invalidf("the %s field is not hexadecimal", what)
		}
		if value > (math.MaxUint64-uint64(digit))/16 {
			return 0, archive.Invalidf("the %s field overflows", what)
		}
		value = value*16 + uint64(digit)
	}
	return value, nil
}

func hexDigit(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func octalField(bytes []byte, what string) (uint64, error) {
	var value uint64
	for _, b := range bytes {
		if b < '0' || b > '7' {
			return 0, archive.Invalidf("the %s field is not octal", what)
		}
		digit := uint64(b - '0')
		if value > (math.MaxUint64-digit)/8 {
			return 0, archive.Invalidf("the %s field overflows", what)
		}
		value = value*8 + digit
	}
	return value, nil
}

func readName(src source.ByteSource, at, size, headerOffset uint64) ([]byte, error) {
	if size == 0 {
		return nil, archive.Invalidf("the entry at offset %d has an empty name", headerOffset)
	}
	if size > MaxNameBytes {
		return nil, archive.Unsupportedf("a %d-byte member name at offset %d", size, headerOffset)
	}
	bytes, err := source.ReadVecAt(src, at, size)
	if err != nil {
		return nil, err
	}
	for i, b := range bytes {
		if b == 0 {
			return bytes[:i], nil
		}
	}
	return nil, archive.Invalidf("the member name at offset %d is not NUL terminated inside its declared length", headerOffset)
}

func readSymlink(src source.ByteSource, at, size, offset uint64) (string, error) {
	if size > MaxNameBytes {
		return "", archive.Unsupportedf("a %d-byte symlink target at offset %d", size, offset)
	}
	bytes, err := source.ReadVecAt(src, at, size)
	if err != nil {
		return "", err
	}
	end := len(bytes)
	for i, b := range bytes {
		if b == 0 {
			end = i
			break
		}
	}
	return decodeLossy(bytes[:end]), nil
}

func decodeName(bytes []byte) (string, bool) {
	if utf8.Valid(bytes) {
		return string(bytes), false
	}
	return strings.ToValidUTF8(string(bytes), "�"), true
}

func decodeLossy(bytes []byte) string {
	if utf8.Valid(bytes) {
		return string(bytes)
	}
	return strings.ToValidUTF8(string(bytes), "�")
}

func align(position uint64, alignment int, headerOffset uint64) (uint64, error) {
	if alignment <= 1 {
		return position, nil
	}
	a := uint64(alignment)
	padding := (a - position%a) % a
	if position > math.MaxUint64-padding {
		return 0, archive.Invalidf("the entry offset overflows")
	}
	return position + padding, nil
}

func checkData(sourceLen, offset, size uint64, what string) error {
	if offset > sourceLen || size > sourceLen-offset {
		return archive.Invalidf("%s [%d, +%d) is outside the %d byte archive", what, offset, size, sourceLen)
	}
	return nil
}
