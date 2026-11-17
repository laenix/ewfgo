// Package tar reads POSIX ustar, old GNU, and PAX tar archives.
//
// A tar archive has no index: it is one 512-byte header per member, each
// followed by that member's data padded to a block boundary, ending with two
// zero blocks.  This reader walks the stream, verifies every header checksum,
// and resolves the three header dialects seen in evidence: POSIX.1-1988
// ustar (including the prefix field), old GNU long names and links, and PAX
// extended headers (path, linkpath, size, mtime).
//
// GNU sparse members are refused by name with an explicit unsupported error
// rather than misread; their stored bytes are not the logical file.  Members
// without a data area (directories, links, device nodes, fifos) are listed
// but cannot be opened.
package tar

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

// BlockSize is the size of every tar header and data block.
const BlockSize = 512

const (
	// MaxEntries bounds the member list.
	MaxEntries = 1_000_000
	// MaxExtendedBytes bounds a GNU long name/link or PAX record blob.
	MaxExtendedBytes = 1024 * 1024
)

// TarEntryKind is what a member is, from its type flag.
type TarEntryKind uint8

const (
	// EntryFile is a regular file (type flag '0' or NUL).
	EntryFile TarEntryKind = iota
	// EntryContiguous is a contiguous regular file (type flag '7').
	EntryContiguous
	// EntryHardLink is another name for an earlier member, with no data.
	EntryHardLink
	// EntrySymlink is a symbolic link, with no data.
	EntrySymlink
	// EntryCharDevice is a character device node.
	EntryCharDevice
	// EntryBlockDevice is a block device node.
	EntryBlockDevice
	// EntryDirectory is a directory.
	EntryDirectory
	// EntryFifo is a named pipe.
	EntryFifo
)

// Label returns the human-readable kind name.
func (k TarEntryKind) Label() string {
	switch k {
	case EntryFile:
		return "file"
	case EntryContiguous:
		return "contiguous file"
	case EntryHardLink:
		return "hard link"
	case EntrySymlink:
		return "symlink"
	case EntryCharDevice:
		return "character device"
	case EntryBlockDevice:
		return "block device"
	case EntryDirectory:
		return "directory"
	default:
		return "fifo"
	}
}

// HasData reports whether the member has a data area of its own.
func (k TarEntryKind) HasData() bool { return k == EntryFile || k == EntryContiguous }

func kindFromFlag(flag byte) (TarEntryKind, bool) {
	switch flag {
	case 0, '0':
		return EntryFile, true
	case '1':
		return EntryHardLink, true
	case '2':
		return EntrySymlink, true
	case '3':
		return EntryCharDevice, true
	case '4':
		return EntryBlockDevice, true
	case '5':
		return EntryDirectory, true
	case '6':
		return EntryFifo, true
	case '7':
		return EntryContiguous, true
	default:
		return EntryFile, false
	}
}

func archiveKind(kind TarEntryKind) archive.Kind {
	switch kind {
	case EntryFile, EntryContiguous:
		return archive.KindFile
	case EntryDirectory:
		return archive.KindDirectory
	case EntrySymlink:
		return archive.KindSymlink
	default:
		// Hard links, device nodes, and fifos have no payload of their own;
		// calling them files would invite a read that returns the wrong bytes.
		return archive.KindOther
	}
}

// Entry is one member as its header and extended headers describe it.
type Entry struct {
	HeaderOffset uint64
	Name         string
	Kind         TarEntryKind
	Size         uint64
	Modified     *int64
	Mode         uint32
	UID          uint32
	GID          uint32
	Uname        string
	Gname        string
	Link         string
	DataOffset   uint64
	StoredSize   uint64
}

// IsDir reports whether the member is a directory.
func (e Entry) IsDir() bool { return e.Kind == EntryDirectory }

// HasStream reports whether the member has a payload that can be opened.
func (e Entry) HasStream() bool { return e.Kind.HasData() }

// Reader is a read-only tar archive.
type Reader struct {
	source         source.ByteSource
	entries        []Entry
	archiveEntries []archive.Entry
	byPath         map[string]int
	trailingBytes  uint64
}

// Matches reports whether source begins with a header block whose checksum
// matches.  The checksum is the only self-description the format has.
func Matches(src source.ByteSource) bool {
	if src.Len() < BlockSize {
		return false
	}
	block := make([]byte, BlockSize)
	if err := source.ReadExactAt(src, 0, block); err != nil {
		return false
	}
	return !isZeroBlock(block) && verifyChecksum(block)
}

// Open scans the archive and lists its members.
func Open(src source.ByteSource, limits archive.Limits) (*Reader, error) {
	sourceLen := src.Len()
	if sourceLen < BlockSize {
		return nil, archive.Unsupportedf("a source shorter than one tar block")
	}

	first := make([]byte, BlockSize)
	if err := source.ReadExactAt(src, 0, first); err != nil {
		return nil, err
	}
	if isZeroBlock(first) || !verifyChecksum(first) {
		return nil, archive.Unsupportedf("a tar header (the first block's checksum does not match)")
	}

	budget := archive.NewBudget(limits)
	entries := make([]Entry, 0, 16)
	archiveEntries := make([]archive.Entry, 0, 16)
	byPath := make(map[string]int)
	var pending pendingHeaders
	var global paxAttrs
	var position uint64
	var trailing uint64

	for {
		block, ok, err := readBlock(src, position)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, archive.Invalidf("the archive ends without a two-block terminator")
		}

		if isZeroBlock(block) {
			secondOffset := position + BlockSize
			second, secondOK, err := readBlock(src, secondOffset)
			if err != nil {
				return nil, err
			}
			if !secondOK {
				return nil, archive.Invalidf("a single zero block does not end the archive")
			}
			if !isZeroBlock(second) {
				return nil, archive.Invalidf("a zero block is followed by a header, not the second terminator block")
			}
			if pending.headerOffset != nil {
				return nil, archive.Invalidf("an extended header at offset %d is not followed by an entry", *pending.headerOffset)
			}
			end := secondOffset + BlockSize
			if end <= sourceLen {
				trailing = sourceLen - end
			}
			break
		}

		if !verifyChecksum(block) {
			return nil, archive.Invalidf("the header at offset %d fails its checksum", position)
		}

		header, err := parseHeader(block, position)
		if err != nil {
			return nil, err
		}
		dataOffset := position + BlockSize

		switch header.kindFlag {
		case 'x', 'g':
			payload, err := readMetadata(src, dataOffset, header.size, "extended header")
			if err != nil {
				return nil, err
			}
			attrs, err := parsePax(payload, dataOffset)
			if err != nil {
				return nil, err
			}
			if header.kindFlag == 'g' {
				global.mergeGlobal(attrs)
			} else {
				pending.pax = pending.pax.overlay(attrs)
				if pending.headerOffset == nil {
					offset := position
					pending.headerOffset = &offset
				}
			}
			position, err = advance(position, dataOffset, header.size)
			if err != nil {
				return nil, err
			}

		case 'L', 'K':
			label := "GNU long name"
			if header.kindFlag == 'K' {
				label = "GNU long link"
			}
			payload, err := readMetadata(src, dataOffset, header.size, label)
			if err != nil {
				return nil, err
			}
			text := textField(payload)
			if header.kindFlag == 'L' {
				pending.longName = &text
			} else {
				pending.longLink = &text
			}
			if pending.headerOffset == nil {
				offset := position
				pending.headerOffset = &offset
			}
			position, err = advance(position, dataOffset, header.size)
			if err != nil {
				return nil, err
			}

		default:
			attrs := global.overlay(pending.pax)
			name := ""
			switch {
			case attrs.path != nil:
				name = *attrs.path
			case pending.longName != nil:
				name = *pending.longName
			default:
				name = header.name
			}
			if name == "" {
				return nil, archive.Invalidf("the entry at offset %d has an empty name", position)
			}

			if header.kindFlag == 'S' {
				return nil, archive.Unsupportedf("a GNU sparse file at offset %d", position)
			}
			kind, known := kindFromFlag(header.kindFlag)
			if !known {
				return nil, archive.Unsupportedf("%s", unknownTypeFlag(header.kindFlag, position))
			}
			// Old archives mark a directory only by the trailing slash on a
			// regular entry.
			if kind == EntryFile && strings.HasSuffix(name, "/") {
				kind = EntryDirectory
			}

			link := header.link
			if attrs.linkpath != nil {
				link = *attrs.linkpath
			} else if pending.longLink != nil {
				link = *pending.longLink
			}

			archiveSize := header.size
			if attrs.size != nil {
				archiveSize = *attrs.size
			}
			if err := checkData(sourceLen, dataOffset, archiveSize, "the entry's data"); err != nil {
				return nil, err
			}
			if len(entries) >= MaxEntries {
				return nil, archive.Unsupportedf("more than %d entries", MaxEntries)
			}

			modified := header.modified
			if attrs.mtime != nil {
				modified = attrs.mtime
			}
			entry := Entry{
				HeaderOffset: position,
				Name:         name,
				Kind:         kind,
				Size:         archiveSize,
				Modified:     modified,
				Mode:         header.mode,
				UID:          header.uid,
				GID:          header.gid,
				Uname:        header.uname,
				Gname:        header.gname,
				Link:         link,
				DataOffset:   dataOffset,
				StoredSize:   archiveSize,
			}

			archiveEntry, err := archive.NewEntry(name, archiveKind(kind), archiveSize)
			if err != nil {
				return nil, err
			}
			archiveEntry.Modified = modified
			if err := budget.Admit(archiveEntry); err != nil {
				return nil, err
			}
			if _, exists := byPath[archiveEntry.Path]; !exists {
				byPath[archiveEntry.Path] = len(entries)
			}
			entries = append(entries, entry)
			archiveEntries = append(archiveEntries, archiveEntry)

			position, err = advance(position, dataOffset, archiveSize)
			if err != nil {
				return nil, err
			}
			pending = pendingHeaders{}
		}
	}

	return &Reader{
		source:         src,
		entries:        entries,
		archiveEntries: archiveEntries,
		byPath:         byPath,
		trailingBytes:  trailing,
	}, nil
}

// FormatID implements archive.Reader.
func (r *Reader) FormatID() string { return "tar" }

// Entries implements archive.Reader.
func (r *Reader) Entries() ([]archive.Entry, error) {
	return append([]archive.Entry(nil), r.archiveEntries...), nil
}

// FindEntry implements archive.Reader.
func (r *Reader) FindEntry(path string) (archive.Entry, bool, error) {
	index, ok := r.byPath[path]
	if !ok {
		return archive.Entry{}, false, nil
	}
	return r.archiveEntries[index], true, nil
}

// OpenEntry implements archive.Reader.
func (r *Reader) OpenEntry(path string, sourceID source.ID) (source.ByteSource, error) {
	index, ok := r.byPath[path]
	if !ok {
		return nil, archive.Invalidf("TAR has no entry named %s", path)
	}
	entry := r.entries[index]
	if !entry.HasStream() {
		return nil, archive.Unsupportedf("the %s %s has no data stream", entry.Kind.Label(), entry.Name)
	}
	return newEntrySource(sourceID, r.source, entry), nil
}

// RawEntries returns the format-level member records.
func (r *Reader) RawEntries() []Entry { return append([]Entry(nil), r.entries...) }

// TrailingBytes returns the bytes after the terminating zero blocks.
func (r *Reader) TrailingBytes() uint64 { return r.trailingBytes }

// Adapter registers the TAR parser with the archive registry.
type Adapter struct{}

// FormatID implements archive.Adapter.
func (Adapter) FormatID() string { return "tar" }

// Open implements archive.Adapter.
func (Adapter) Open(src source.ByteSource, limits archive.Limits) (archive.Reader, error) {
	return Open(src, limits)
}

// Register adds the TAR parser for the "tar" format id.
func Register(registry *archive.Registry) error {
	return registry.Register(Adapter{})
}

// EntrySource is one member's data exposed as a ByteSource.  Tar stores
// member data verbatim, so this is a window onto the parent bounded by the
// declared size; block padding is never exposed.
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

// paxAttrs holds per-file or global PAX attributes this reader honours.
type paxAttrs struct {
	path     *string
	linkpath *string
	size     *uint64
	mtime    *int64
}

// overlay returns a copy where other wins over self.
func (a paxAttrs) overlay(other paxAttrs) paxAttrs {
	out := a
	if other.path != nil {
		out.path = other.path
	}
	if other.linkpath != nil {
		out.linkpath = other.linkpath
	}
	if other.size != nil {
		out.size = other.size
	}
	if other.mtime != nil {
		out.mtime = other.mtime
	}
	return out
}

// mergeGlobal folds a global header into the running set.  Only the attributes
// POSIX defines as global are taken.
func (a *paxAttrs) mergeGlobal(other paxAttrs) {
	if other.path != nil {
		a.path = other.path
	}
	if other.linkpath != nil {
		a.linkpath = other.linkpath
	}
	if other.size != nil {
		a.size = other.size
	}
	if other.mtime != nil {
		a.mtime = other.mtime
	}
}

type pendingHeaders struct {
	longName     *string
	longLink     *string
	pax          paxAttrs
	headerOffset *uint64
}

type header struct {
	name     string
	kindFlag byte
	link     string
	size     uint64
	modified *int64
	mode     uint32
	uid      uint32
	gid      uint32
	uname    string
	gname    string
}

func parseHeader(block []byte, offset uint64) (header, error) {
	nameField := textField(block[0:100])
	// Only POSIX ustar defines the prefix field.  GNU tar reuses that area for
	// other bookkeeping, so applying it there would corrupt the name.
	prefix := ""
	if string(block[257:263]) == "ustar\x00" {
		prefix = textField(block[345:500])
	}
	name := nameField
	if prefix != "" {
		name = prefix + "/" + nameField
	}

	size, present, err := parseNumeric(block[124:136], "size", offset)
	if err != nil {
		return header{}, err
	}
	if !present {
		size = 0
	}
	modified, err := parseTimestamp(block[136:148], offset)
	if err != nil {
		return header{}, err
	}
	mode, err := numericU32(block[100:108], "mode", offset)
	if err != nil {
		return header{}, err
	}
	uid, err := numericU32(block[108:116], "uid", offset)
	if err != nil {
		return header{}, err
	}
	gid, err := numericU32(block[116:124], "gid", offset)
	if err != nil {
		return header{}, err
	}

	return header{
		name:     name,
		kindFlag: block[156],
		link:     textField(block[157:257]),
		size:     size,
		modified: modified,
		mode:     mode,
		uid:      uid,
		gid:      gid,
		uname:    textField(block[265:297]),
		gname:    textField(block[297:329]),
	}, nil
}

// parseNumeric decodes a field that may be empty, octal, or GNU base-256.
func parseNumeric(field []byte, what string, offset uint64) (uint64, bool, error) {
	index := skipBlanks(field)
	if index < 0 {
		return 0, false, nil
	}
	field = field[index:]

	if field[0]&0x80 != 0 {
		value, ok := base256(field)
		if !ok {
			return 0, false, archive.Invalidf("the %s field is too wide", what)
		}
		if value.Sign() < 0 {
			return 0, false, archive.Invalidf("the %s field is negative", what)
		}
		if !value.IsUint64() {
			return 0, false, archive.Invalidf("the %s field overflows", what)
		}
		return value.Uint64(), true, nil
	}

	var value uint64
	digits := 0
	for _, b := range field {
		if b == 0 || b == ' ' {
			break
		}
		if b < '0' || b > '7' {
			return 0, false, archive.Invalidf("the %s field is not octal (0x%02X)", what, b)
		}
		digit := uint64(b - '0')
		if value > (math.MaxUint64-digit)/8 {
			return 0, false, archive.Invalidf("the %s field overflows", what)
		}
		value = value*8 + digit
		digits++
	}
	if digits == 0 {
		return 0, false, nil
	}
	return value, true, nil
}

// parseTimestamp decodes the mtime field, which alone may be negative.
func parseTimestamp(field []byte, offset uint64) (*int64, error) {
	index := skipBlanks(field)
	if index < 0 {
		return nil, nil
	}
	field = field[index:]

	if field[0]&0x80 != 0 {
		value, ok := base256(field)
		if !ok {
			return nil, archive.Invalidf("the mtime field is too wide")
		}
		if !value.IsInt64() {
			return nil, archive.Invalidf("the mtime field overflows")
		}
		v := value.Int64()
		return &v, nil
	}

	var value int64
	digits := 0
	for _, b := range field {
		if b == 0 || b == ' ' {
			break
		}
		if b < '0' || b > '7' {
			return nil, archive.Invalidf("the mtime field is not octal (0x%02X)", b)
		}
		digit := int64(b - '0')
		if value > (math.MaxInt64-digit)/8 {
			return nil, archive.Invalidf("the mtime field overflows")
		}
		value = value*8 + digit
		digits++
	}
	if digits == 0 {
		return nil, nil
	}
	return &value, nil
}

// base256 decodes GNU base-256: the high bit of the first byte is the marker,
// the next bit is the sign, and the rest is big-endian two's complement.
func base256(bytes []byte) (*big.Int, bool) {
	if len(bytes) == 0 {
		return nil, false
	}
	bits := 8 * len(bytes)
	if bits >= 128 {
		return nil, false
	}
	value := new(big.Int).SetUint64(uint64(bytes[0] & 0x7F))
	for _, b := range bytes[1:] {
		value.Lsh(value, 8)
		value.Or(value, big.NewInt(int64(b)))
	}
	if bytes[0]&0x40 != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	}
	return value, true
}

func skipBlanks(field []byte) int {
	for i, b := range field {
		if b != 0 && b != ' ' {
			return i
		}
	}
	return -1
}

func numericU32(field []byte, what string, offset uint64) (uint32, error) {
	value, present, err := parseNumeric(field, what, offset)
	if err != nil {
		return 0, err
	}
	if !present {
		return 0, nil
	}
	if value > math.MaxUint32 {
		return 0, archive.Invalidf("the %s field does not fit in 32 bits", what)
	}
	return uint32(value), nil
}

// verifyChecksum accepts both the unsigned and the signed-byte convention.
func verifyChecksum(block []byte) bool {
	stored, present, err := parseNumeric(block[148:156], "checksum", 0)
	if err != nil || !present {
		return false
	}

	var unsigned uint64
	var signed int64
	for index, b := range block {
		value := b
		if index >= 148 && index < 156 {
			value = ' '
		}
		unsigned += uint64(value)
		signed += int64(int8(value))
	}
	if stored == unsigned {
		return true
	}
	return stored <= math.MaxInt64 && int64(stored) == signed
}

func isZeroBlock(block []byte) bool {
	for _, b := range block {
		if b != 0 {
			return false
		}
	}
	return true
}

func readBlock(src source.ByteSource, offset uint64) ([]byte, bool, error) {
	length := src.Len()
	if offset >= length {
		return nil, false, nil
	}
	if length-offset < BlockSize {
		return nil, false, archive.Invalidf("the archive ends inside a header block at offset %d", offset)
	}
	block := make([]byte, BlockSize)
	if err := source.ReadExactAt(src, offset, block); err != nil {
		return nil, false, err
	}
	return block, true, nil
}

func checkData(sourceLen, offset, size uint64, what string) error {
	if offset > sourceLen || size > sourceLen-offset {
		return archive.Invalidf("%s [%d, +%d) is outside the %d byte archive", what, offset, size, sourceLen)
	}
	return nil
}

func readMetadata(src source.ByteSource, offset, size uint64, what string) ([]byte, error) {
	if size > MaxExtendedBytes {
		return nil, archive.Unsupportedf("a %d byte %s", size, what)
	}
	if err := checkData(src.Len(), offset, size, what); err != nil {
		return nil, err
	}
	return source.ReadVecAt(src, offset, size)
}

func advance(headerOffset, dataOffset, size uint64) (uint64, error) {
	padding := (BlockSize - size%BlockSize) % BlockSize
	end := dataOffset + size
	if end < dataOffset {
		return 0, archive.Invalidf("the header's data length overflows")
	}
	if end > math.MaxUint64-padding {
		return 0, archive.Invalidf("the header's data length overflows")
	}
	return end + padding, nil
}

func parsePax(records []byte, offset uint64) (paxAttrs, error) {
	var attrs paxAttrs
	position := 0
	for position < len(records) {
		rest := records[position:]
		// Writers pad the blob to the header's declared size with NULs.
		allZero := true
		for _, b := range rest {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			break
		}

		name := paxRecordName(rest)
		space := -1
		for i, b := range rest {
			if b == ' ' {
				space = i
				break
			}
		}
		if space < 0 {
			return attrs, archive.Invalidf("the PAX record at byte %d has no length field", position)
		}
		if space == 0 {
			return attrs, archive.Invalidf("the PAX record at byte %d (%q) has an empty length field", position, name)
		}

		length := 0
		for _, b := range rest[:space] {
			if b < '0' || b > '9' {
				return attrs, archive.Invalidf("the PAX record at byte %d (%q) has a non-numeric length", position, name)
			}
			if length > (int(^uint(0)>>1)-int(b-'0'))/10 {
				return attrs, archive.Invalidf("a PAX record length overflows")
			}
			length = length*10 + int(b-'0')
		}
		if length <= space+1 || length > len(rest) {
			return attrs, archive.Invalidf("the PAX record at byte %d (%q) declares %d bytes, which do not fit", position, name, length)
		}
		record := rest[:length]
		if record[length-1] != '\n' {
			return attrs, archive.Invalidf("the PAX record at byte %d (%q) does not end with a newline", position, name)
		}

		body := record[space+1 : length-1]
		equals := -1
		for i, b := range body {
			if b == '=' {
				equals = i
				break
			}
		}
		if equals < 0 {
			return attrs, archive.Invalidf("the PAX record at byte %d (%q) has no '='", position, textOf(body))
		}
		key := textOf(body[:equals])
		if err := applyPax(key, body[equals+1:], &attrs, offset); err != nil {
			return attrs, err
		}
		position += length
	}
	return attrs, nil
}

func paxRecordName(record []byte) string {
	space := -1
	for i, b := range record {
		if b == ' ' {
			space = i
			break
		}
	}
	if space < 0 {
		return ""
	}
	body := record[space+1:]
	end := len(body)
	for i, b := range body {
		if b == '=' || b == '\n' {
			end = i
			break
		}
	}
	return textOf(body[:end])
}

func applyPax(key string, value []byte, attrs *paxAttrs, offset uint64) error {
	switch key {
	case "path":
		text := textOf(value)
		attrs.path = &text
	case "linkpath":
		text := textOf(value)
		attrs.linkpath = &text
	case "size":
		size, err := parsePaxSize(value, key, offset)
		if err != nil {
			return err
		}
		attrs.size = &size
	case "mtime":
		text := textOf(value)
		integral := text
		if dot := strings.IndexByte(text, '.'); dot >= 0 {
			integral = text[:dot]
		}
		stamp, err := strconv.ParseInt(integral, 10, 64)
		if err != nil {
			return archive.Invalidf("the PAX record %q is not a time: %q", key, text)
		}
		attrs.mtime = &stamp
	default:
		if strings.HasPrefix(key, "GNU.sparse.") {
			// A sparse map changes how the data area is laid out; this port
			// refuses it by name rather than misreading the member.
			return archive.Unsupportedf("a GNU sparse file (PAX record %q)", key)
		}
		// Every other record is deliberately not interpreted.
	}
	return nil
}

func parsePaxSize(value []byte, key string, offset uint64) (uint64, error) {
	text := textOf(value)
	var number uint64
	if text == "" {
		return 0, archive.Invalidf("the PAX record %q is not a size: %q", key, text)
	}
	for _, b := range []byte(text) {
		if b < '0' || b > '9' {
			return 0, archive.Invalidf("the PAX record %q is not a size: %q", key, text)
		}
		digit := uint64(b - '0')
		if number > (math.MaxUint64-digit)/10 {
			return 0, archive.Invalidf("the PAX record %q overflows", key)
		}
		number = number*10 + digit
	}
	return number, nil
}

// textField decodes a fixed-width text field, ending at the first NUL.
func textField(bytes []byte) string {
	end := len(bytes)
	for i, b := range bytes {
		if b == 0 {
			end = i
			break
		}
	}
	return textOf(bytes[:end])
}

// textOf decodes bytes that carry no encoding flag.  UTF-8 is preferred;
// anything else is mapped through ISO-8859-1, which loses no bytes.
func textOf(bytes []byte) string {
	if utf8.Valid(bytes) {
		return string(bytes)
	}
	runes := make([]rune, len(bytes))
	for i, b := range bytes {
		runes[i] = rune(b)
	}
	return string(runes)
}

func unknownTypeFlag(flag byte, offset uint64) string {
	meaning := "unknown type"
	switch flag {
	case 'V':
		meaning = "GNU volume label"
	case 'D':
		meaning = "GNU incremental dump directory"
	case 'M':
		meaning = "GNU multi-volume continuation"
	case 'N':
		meaning = "GNU old long name"
	}
	return fmt.Sprintf("type flag 0x%02X (%s) at offset %d", flag, meaning, offset)
}
