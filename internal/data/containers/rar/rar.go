// Package rar reads RAR 5 archives.
//
// A RAR 5 archive is a chain of self-checked blocks. Each block starts with a
// CRC-32 over the rest of the header, a variable-length header size, the
// header type and common flags, the header's own fields, an optional extra
// area at the END of the header, and finally an optional data area. Every
// field that can be long is a RAR 5 variable-length integer (seven bits per
// byte, low group first, 0x80 marks another byte).
//
// Walking the blocks is the only way to list the archive: the end header
// closes the chain, and each file header carries its own name, sizes,
// timestamp and CRC-32. A damaged header is refused with its offset rather
// than skipped, because a skipped block changes what the archive appears to
// hold.
//
// # What is read
//
//   - Every file and directory entry, with its stored name (backslashes are
//     normalized to "/"; unsafe names are counted, not listed), unpacked size,
//     stored size, Windows attributes, host OS, modification time and CRC-32.
//   - The high-precision time extra (HTIME), in both the Unix and the Windows
//     FILETIME form; it wins over the inline 32-bit Unix time when both exist.
//   - Stored members (compression method 0). The first read reads the whole
//     member, checks its declared size and CRC-32, and caches it, so random
//     access afterwards is cheap. A mismatch is counted as corrupt bytes but
//     the recovered bytes remain readable.
//
// # What is refused
//
//   - RAR 4 archives: a different block layout with its own header CRC. Only
//     the RAR 5 form is read here (source.ErrUnsupported).
//   - Archives whose headers are encrypted (an encryption header appears
//     before the files), and members carrying an encryption extra
//     (source.ErrDecrypt).
//   - Compressed members: the RAR 5 decoder is proprietary LZ with its own
//     filters. Such members are listed with their stored size and refused by
//     name when opened (source.ErrUnsupported).
//   - Split members and multi-volume continuations, unknown header types that
//     are not marked skippable (source.ErrUnsupported), and members whose
//     unpacked size is unknown (source.ErrUnsupported).
//
// This is a Go port of forensic-core's data/containers/rar.rs.
package rar

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// The eight-byte signature of a RAR 5 archive.
const MagicRAR5 = "Rar!\x1a\x07\x01\x00"

// The seven-byte signature of a RAR 4 archive, which this reader refuses.
const MagicRAR4 = "Rar!\x1a\x07\x00"

// MaxHeaderBytes is the largest header this reader will hold. Headers are
// metadata; an archive that declares a multi-megabyte header is corrupt, not
// payload.
const MaxHeaderBytes uint64 = 16 * 1024 * 1024

// Block types.
const (
	typeMain       uint64 = 1
	typeFile       uint64 = 2
	typeService    uint64 = 3
	typeEncryption uint64 = 4
	typeEnd        uint64 = 5
)

// Common block flags.
const (
	flagExtra         uint64 = 0x0001
	flagData          uint64 = 0x0002
	flagSkipIfUnknown uint64 = 0x0004
	flagSplitBefore   uint64 = 0x0008
	flagSplitAfter    uint64 = 0x0010
)

// File header flags.
const (
	fileDirectory   uint64 = 0x0001
	fileMtime       uint64 = 0x0002
	fileCRC         uint64 = 0x0004
	fileUnknownSize uint64 = 0x0008
)

// Archive flags carried by the main header.
const (
	archiveVolume       uint64 = 0x0001
	archiveVolumeNumber uint64 = 0x0002
	archiveSolid        uint64 = 0x0004
	archiveLocked       uint64 = 0x0010
)

// Extra record types.
const (
	extraCrypt uint64 = 1
	extraHTime uint64 = 3
)

// HTIME flags.
const (
	htimeUnix  uint64 = 0x01
	htimeMtime uint64 = 0x02
)

// filetimeUnixOffset is the number of seconds between 1601-01-01 and
// 1970-01-01.
const filetimeUnixOffset int64 = 11_644_473_600

// Adapter registers RAR with the archive framework.
type Adapter struct{}

// FormatID implements archive.Adapter.
func (Adapter) FormatID() string { return "rar" }

// Open implements archive.Adapter.
func (Adapter) Open(src source.ByteSource, limits archive.Limits) (archive.Reader, error) {
	return Open(src, limits)
}

// Register adds the RAR parser to registry.
func Register(registry *archive.Registry) error { return registry.Register(Adapter{}) }

// Stats counts the block walk without inventing members.
type Stats struct {
	// Blocks are the headers whose CRC-32 was verified.
	Blocks uint64
	// FileHeaders are file headers, including directories and skipped unsafe
	// names.
	FileHeaders uint64
	// ServiceHeaders are service headers (QO, CMT, ACL, ...) carrying no
	// listed member.
	ServiceHeaders uint64
	// SkippedUnsafe counts names rejected by archive.SanitizeEntryPath.
	SkippedUnsafe uint64
	// InvalidNames counts names that were not valid UTF-8 and were decoded
	// lossily.
	InvalidNames uint64
	// SkippedUnknown counts unknown block types skipped because they carried
	// the skippable flag.
	SkippedUnknown uint64
	// TrailingBytes is the byte count after the end header.
	TrailingBytes uint64
}

// Entry is one member as its file header describes it.
type Entry struct {
	// HeaderOffset is the offset of the block's CRC-32 field.
	HeaderOffset uint64
	// DataOffset is the offset of the member's data area in the archive.
	DataOffset uint64
	// DataSize is the number of bytes the data area occupies in this archive.
	DataSize uint64
	// Size is the unpacked size the header declares.
	Size uint64
	// Method comes from compression_info bits 7..10 (0 = stored).
	Method uint32
	// CompressionInfo is the raw compression_info word.
	CompressionInfo uint64
	// HostOS is the host_os field: 0 Windows, 1 Unix.
	HostOS uint64
	// Attributes are the stored file attributes.
	Attributes uint64
	// Directory reports a directory member.
	Directory bool
	// Encrypted reports an encryption extra on the member.
	Encrypted bool
	// Split reports that the member continues in another volume.
	Split bool
	// Name is the stored name, decoded lossily when not valid UTF-8.
	Name string
	// CRC32 is the CRC-32 recorded by the header, when present.
	CRC32 *uint32
	// Modified is the modification Unix time, when present.
	Modified *int64
}

// IsStored reports whether this reader can produce the member's bytes.
func (e Entry) IsStored() bool {
	return e.Method == 0 && !e.Directory && !e.Encrypted && !e.Split
}

type record struct {
	entry  archive.Entry
	detail Entry
}

// Reader is a read-only RAR 5 archive.
type Reader struct {
	formatID     string
	source       source.ByteSource
	records      []record
	byPath       map[string]int
	limits       archive.Limits
	stats        Stats
	archiveFlags uint64
}

// Open opens a RAR 5 archive.
func Open(src source.ByteSource, limits archive.Limits) (*Reader, error) {
	return OpenAs("rar", src, limits)
}

// OpenAs opens a RAR 5 archive reporting formatID.
func OpenAs(formatID string, src source.ByteSource, limits archive.Limits) (*Reader, error) {
	if err := checkSignature(src); err != nil {
		return nil, err
	}

	budget := archive.NewBudget(limits)
	records := make([]record, 0)
	var stats Stats
	var archiveFlags uint64
	sourceLen := src.Len()
	position := uint64(len(MagicRAR5))

loop:
	for position < sourceLen {
		block, err := readBlock(src, position)
		if err != nil {
			return nil, err
		}
		position = block.nextOffset
		stats.Blocks++

		switch block.kind {
		case typeMain:
			flags, err := parseMain(block.headerData)
			if err != nil {
				return nil, err
			}
			archiveFlags |= flags

		case typeFile:
			stats.FileHeaders++
			file, err := parseFile(block)
			if err != nil {
				return nil, err
			}
			if file.invalidName {
				stats.InvalidNames++
			}
			kind := archive.KindFile
			if file.directory {
				kind = archive.KindDirectory
			}
			entry, err := archive.NewEntry(file.name, kind, file.size)
			if err != nil {
				// An unsafe name is counted, never listed.
				stats.SkippedUnsafe++
				continue
			}
			entry.CompressedSize = uint64Value(file.dataSize)
			entry.Modified = file.modified
			entry.CRC32 = file.crc32
			entry.Encrypted = file.encrypted
			if err := budget.Admit(entry); err != nil {
				return nil, err
			}
			records = append(records, record{
				entry: entry,
				detail: Entry{
					HeaderOffset:    block.headerOffset,
					DataOffset:      file.dataOffset,
					DataSize:        file.dataSize,
					Size:            file.size,
					Method:          file.method,
					CompressionInfo: file.compressionInfo,
					HostOS:          file.hostOS,
					Attributes:      file.attributes,
					Directory:       file.directory,
					Encrypted:       file.encrypted,
					Split:           file.split,
					Name:            file.name,
					CRC32:           file.crc32,
					Modified:        file.modified,
				},
			})

		case typeService:
			stats.ServiceHeaders++

		case typeEncryption:
			return nil, decryptf(block.headerOffset,
				"RAR archive headers are encrypted; a password is required before the file list exists")

		case typeEnd:
			if _, err := parseEnd(block.headerData); err != nil {
				return nil, err
			}
			stats.TrailingBytes = sourceLen - block.nextOffset
			break loop

		default:
			if block.flags&flagSkipIfUnknown != 0 {
				stats.SkippedUnknown++
			} else {
				return nil, unsupportedf("RAR header type %d at offset %d (not marked skippable)",
					block.kind, block.headerOffset)
			}
		}
	}

	if stats.Blocks == 0 {
		return nil, corruptf(0, "a RAR signature followed by no block headers")
	}

	byPath := make(map[string]int, len(records))
	for index := range records {
		if _, exists := byPath[records[index].entry.Path]; !exists {
			byPath[records[index].entry.Path] = index
		}
	}

	return &Reader{
		formatID:     formatID,
		source:       src,
		records:      records,
		byPath:       byPath,
		limits:       limits,
		stats:        stats,
		archiveFlags: archiveFlags,
	}, nil
}

// FormatID implements archive.Reader.
func (r *Reader) FormatID() string { return r.formatID }

// Limits returns the limits used while listing.
func (r *Reader) Limits() archive.Limits { return r.limits }

// Stats returns the block-walk counters.
func (r *Reader) Stats() Stats { return r.stats }

// ArchiveFlags returns the archive-level flags from the main header.
func (r *Reader) ArchiveFlags() uint64 { return r.archiveFlags }

// IsSolid reports the ARCHIVE_SOLID main-header flag.
func (r *Reader) IsSolid() bool { return r.archiveFlags&archiveSolid != 0 }

// IsVolume reports the ARCHIVE_VOLUME main-header flag.
func (r *Reader) IsVolume() bool { return r.archiveFlags&archiveVolume != 0 }

// IsLocked reports the ARCHIVE_LOCKED main-header flag.
func (r *Reader) IsLocked() bool { return r.archiveFlags&archiveLocked != 0 }

// Entries implements archive.Reader.
func (r *Reader) Entries() ([]archive.Entry, error) {
	out := make([]archive.Entry, len(r.records))
	for index := range r.records {
		out[index] = r.records[index].entry
	}
	return out, nil
}

// Details returns per-member header details, parallel to Entries.
func (r *Reader) Details() []Entry {
	out := make([]Entry, len(r.records))
	for index := range r.records {
		out[index] = r.records[index].detail
	}
	return out
}

// FindEntry implements archive.Reader.
func (r *Reader) FindEntry(path string) (archive.Entry, bool, error) {
	normalized, err := archive.SanitizeEntryPath(path)
	if err != nil {
		return archive.Entry{}, false, archive.Invalidf("%v", err)
	}
	index, ok := r.byPath[normalized]
	if !ok {
		return archive.Entry{}, false, nil
	}
	return r.records[index].entry, true, nil
}

// OpenEntry implements archive.Reader.
func (r *Reader) OpenEntry(path string, sourceID source.ID) (source.ByteSource, error) {
	return r.OpenEntrySource(path, sourceID)
}

// OpenEntrySource opens one stored entry with its concrete source type.
func (r *Reader) OpenEntrySource(path string, sourceID source.ID) (*EntrySource, error) {
	normalized, err := archive.SanitizeEntryPath(path)
	if err != nil {
		return nil, archive.Invalidf("%v", err)
	}
	index, ok := r.byPath[normalized]
	if !ok {
		return nil, archive.Invalidf("RAR has no entry named %s", path)
	}
	record := &r.records[index]
	detail := record.detail

	if detail.Directory {
		return nil, archive.Invalidf("RAR entry %s is a directory", record.entry.Path)
	}
	if detail.Encrypted {
		return nil, decryptf(detail.HeaderOffset,
			"RAR entry %s is encrypted; this reader has no key provider", record.entry.Path)
	}
	if detail.Split {
		return nil, unsupportedf("RAR entry %s continues in another volume", record.entry.Path)
	}
	if detail.Method != 0 {
		return nil, unsupportedf("RAR entry %s uses compression method %d; only stored members are read",
			record.entry.Path, detail.Method)
	}
	if detail.DataSize != detail.Size {
		return nil, corruptf(detail.DataOffset,
			"RAR entry %s declares %d unpacked bytes but its stored data area holds %d",
			record.entry.Path, detail.Size, detail.DataSize)
	}
	if detail.Size > r.limits.MaxEntrySize {
		return nil, archive.Limitf("RAR entry %s is larger than the configured limit", record.entry.Path)
	}

	return newEntrySource(sourceID, r.source, record.entry, detail.DataOffset, detail.DataSize), nil
}

// block is one block with its header split into fields and extra area.
type block struct {
	kind         uint64
	flags        uint64
	dataSize     uint64
	headerData   []byte
	extra        []byte
	headerOffset uint64
	dataOffset   uint64
	nextOffset   uint64
}

// fileHeader is the set of fields a file header carries, before name
// normalization.
type fileHeader struct {
	name            string
	invalidName     bool
	size            uint64
	modified        *int64
	crc32           *uint32
	method          uint32
	compressionInfo uint64
	hostOS          uint64
	attributes      uint64
	directory       bool
	encrypted       bool
	split           bool
	dataOffset      uint64
	dataSize        uint64
}

// extraInfo is the subset of extra records this reader consumes.
type extraInfo struct {
	modified  *int64
	encrypted bool
}

// formatError couples the source package's error taxonomy with the archive
// framework's, so a caller can test either set of sentinels. Error and Unwrap
// expose the source error; the archive sentinel is additional.
type formatError struct {
	primary error
	archive error
}

func (e *formatError) Error() string { return e.primary.Error() }

func (e *formatError) Unwrap() []error { return []error{e.primary, e.archive} }

func corruptPlain(format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	return &formatError{
		primary: fmt.Errorf("%w: %s", source.ErrCorrupt, reason),
		archive: fmt.Errorf("%w: %s", archive.ErrInvalid, reason),
	}
}

func corruptf(offset uint64, format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	return &formatError{
		primary: source.NewCorrupt(offset, reason),
		archive: fmt.Errorf("%w: %s", archive.ErrInvalid, reason),
	}
}

func unsupportedf(format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	return &formatError{
		primary: &source.Error{Kind: source.ErrUnsupported, Reason: reason},
		archive: fmt.Errorf("%w: %s", archive.ErrUnsupported, reason),
	}
}

func decryptf(offset uint64, format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	return &formatError{
		primary: &source.Error{Kind: source.ErrDecrypt, Offset: offset, Reason: reason},
		archive: fmt.Errorf("%w: %s", archive.ErrEncrypted, reason),
	}
}

func uint64Value(value uint64) *uint64 { return &value }

func checkedAdd(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

func checkSignature(src source.ByteSource) error {
	length := src.Len()
	if length < uint64(len(MagicRAR4)) {
		return corruptf(0, "a source shorter than the 7-byte RAR signature: %d bytes", length)
	}
	var head [8]byte
	take := len(head)
	if length < uint64(take) {
		take = int(length)
	}
	if err := source.ReadExactAt(src, 0, head[:take]); err != nil {
		return err
	}
	if take >= len(MagicRAR5) && string(head[:len(MagicRAR5)]) == MagicRAR5 {
		return nil
	}
	if string(head[:len(MagicRAR4)]) == MagicRAR4 {
		return unsupportedf("a RAR 4 archive; only the RAR 5 block layout is read")
	}
	return corruptf(0, "the RAR signature %x is neither RAR 4 nor RAR 5", head[:take])
}

// readVint decodes one RAR 5 variable-length integer from buf at *pos.
func readVint(buf []byte, pos *int) (uint64, error) {
	return readVintLimited(buf, pos, len(buf))
}

// readVintLimited decodes a vint that must end before limit.
func readVintLimited(buf []byte, pos *int, limit int) (uint64, error) {
	var value uint64
	var shift uint
	for {
		if *pos >= limit {
			return 0, corruptPlain("a RAR variable-length integer runs past the header")
		}
		octet := buf[*pos]
		*pos = *pos + 1
		if shift >= 64 || (shift == 63 && octet&0x7f > 1) {
			return 0, corruptPlain("a RAR variable-length integer overflows 64 bits")
		}
		value |= uint64(octet&0x7f) << shift
		if octet&0x80 == 0 {
			return value, nil
		}
		shift += 7
	}
}

func readU32(buf []byte, pos *int) (uint32, error) {
	return readU32Limited(buf, pos, len(buf))
}

func readU32Limited(buf []byte, pos *int, limit int) (uint32, error) {
	if limit-*pos < 4 {
		return 0, corruptPlain("a RAR fixed-width field runs past the header")
	}
	value := binary.LittleEndian.Uint32(buf[*pos:])
	*pos += 4
	return value, nil
}

func readU64Limited(buf []byte, pos *int, limit int) (uint64, error) {
	if limit-*pos < 8 {
		return 0, corruptPlain("a RAR fixed-width field runs past the header")
	}
	value := binary.LittleEndian.Uint64(buf[*pos:])
	*pos += 8
	return value, nil
}

// readBlock reads and verifies one block header at offset.
func readBlock(src source.ByteSource, offset uint64) (*block, error) {
	sourceLen := src.Len()
	remaining := sourceLen - offset
	if remaining < 5 {
		return nil, corruptf(offset, "%d trailing byte(s) cannot hold a block header", remaining)
	}

	// The size field is at most ten bytes; read it together with the CRC and
	// then the whole header in one more read.
	prefixLen := 4 + 10
	if remaining < uint64(prefixLen) {
		prefixLen = int(remaining)
	}
	prefix := make([]byte, prefixLen)
	if err := source.ReadExactAt(src, offset, prefix); err != nil {
		return nil, err
	}
	expectedCRC := binary.LittleEndian.Uint32(prefix[:4])

	pos := 4
	headerSize, err := readVint(prefix, &pos)
	if err != nil {
		return nil, err
	}
	sizeLen := uint64(pos - 4)
	if headerSize == 0 {
		return nil, corruptf(offset, "the block header declares zero bytes")
	}
	if headerSize > MaxHeaderBytes {
		return nil, archive.Limitf("RAR header at offset %d declares %d bytes", offset, headerSize)
	}
	headerBytesLen, ok := checkedAdd(sizeLen, headerSize)
	if !ok {
		return nil, corruptf(offset, "the header length overflows")
	}
	blockHeaderEnd, ok := checkedAdd(offset, 4)
	if !ok {
		return nil, corruptf(offset, "the block end overflows")
	}
	blockHeaderEnd, ok = checkedAdd(blockHeaderEnd, headerBytesLen)
	if !ok {
		return nil, corruptf(offset, "the block end overflows")
	}
	if blockHeaderEnd > sourceLen {
		return nil, corruptf(offset, "the %d-byte header runs past the %d-byte archive", headerSize, sourceLen)
	}

	headerStart, _ := checkedAdd(offset, 4)
	header, err := source.ReadVecAt(src, headerStart, headerBytesLen)
	if err != nil {
		return nil, err
	}
	if foundation.CRC32(header) != expectedCRC {
		return nil, corruptf(offset, "the block header CRC-32 does not match")
	}

	pos = int(sizeLen)
	kind, err := readVint(header, &pos)
	if err != nil {
		return nil, err
	}
	flags, err := readVint(header, &pos)
	if err != nil {
		return nil, err
	}
	var extraSize, dataSize uint64
	if flags&flagExtra != 0 {
		extraSize, err = readVint(header, &pos)
		if err != nil {
			return nil, err
		}
	}
	if flags&flagData != 0 {
		dataSize, err = readVint(header, &pos)
		if err != nil {
			return nil, err
		}
	}

	if extraSize > uint64(len(header)) {
		return nil, corruptf(offset,
			"the %d-byte extra area is longer than the %d-byte header", extraSize, len(header))
	}
	extraStart := len(header) - int(extraSize)
	if pos > extraStart {
		return nil, corruptf(offset, "the extra area overlaps the fixed header fields")
	}
	headerData := append([]byte(nil), header[pos:extraStart]...)
	extra := append([]byte(nil), header[extraStart:]...)

	dataOffset := blockHeaderEnd
	nextOffset, ok := checkedAdd(dataOffset, dataSize)
	if !ok {
		return nil, corruptf(offset, "the data area end overflows")
	}
	if nextOffset > sourceLen {
		return nil, corruptf(dataOffset,
			"the %d-byte data area runs past the %d-byte archive", dataSize, sourceLen)
	}

	return &block{
		kind:         kind,
		flags:        flags,
		dataSize:     dataSize,
		headerData:   headerData,
		extra:        extra,
		headerOffset: offset,
		dataOffset:   dataOffset,
		nextOffset:   nextOffset,
	}, nil
}

func parseMain(headerData []byte) (uint64, error) {
	pos := 0
	flags, err := readVint(headerData, &pos)
	if err != nil {
		return 0, err
	}
	if flags&archiveVolume != 0 && flags&archiveVolumeNumber != 0 {
		if _, err := readVint(headerData, &pos); err != nil {
			return 0, err
		}
	}
	return flags, nil
}

func parseEnd(headerData []byte) (uint64, error) {
	if len(headerData) == 0 {
		return 0, nil
	}
	pos := 0
	return readVint(headerData, &pos)
}

func parseFile(blk *block) (*fileHeader, error) {
	data := blk.headerData
	pos := 0
	fileFlags, err := readVint(data, &pos)
	if err != nil {
		return nil, err
	}
	size, err := readVint(data, &pos)
	if err != nil {
		return nil, err
	}
	attributes, err := readVint(data, &pos)
	if err != nil {
		return nil, err
	}

	if fileFlags&fileUnknownSize != 0 {
		return nil, unsupportedf("a RAR member at offset %d whose unpacked size is unknown",
			blk.headerOffset)
	}

	var modified *int64
	if fileFlags&fileMtime != 0 {
		value, err := readU32(data, &pos)
		if err != nil {
			return nil, err
		}
		seconds := int64(value)
		modified = &seconds
	}
	var crc32Value *uint32
	if fileFlags&fileCRC != 0 {
		value, err := readU32(data, &pos)
		if err != nil {
			return nil, err
		}
		crc32Value = &value
	}

	compressionInfo, err := readVint(data, &pos)
	if err != nil {
		return nil, err
	}
	hostOS, err := readVint(data, &pos)
	if err != nil {
		return nil, err
	}
	nameSize, err := readVint(data, &pos)
	if err != nil {
		return nil, err
	}
	if nameSize > uint64(len(data)-pos) {
		return nil, corruptf(blk.headerOffset, "the RAR name runs past the header")
	}
	nameEnd := pos + int(nameSize)
	nameBytes := data[pos:nameEnd]
	invalidName := !utf8.Valid(nameBytes)
	name := strings.ToValidUTF8(string(nameBytes), "�")

	extra, err := parseExtra(blk.extra, blk.headerOffset)
	if err != nil {
		return nil, err
	}
	if extra.modified != nil {
		modified = extra.modified
	}

	return &fileHeader{
		name:            name,
		invalidName:     invalidName,
		size:            size,
		modified:        modified,
		crc32:           crc32Value,
		method:          uint32((compressionInfo >> 7) & 0x7),
		compressionInfo: compressionInfo,
		hostOS:          hostOS,
		attributes:      attributes,
		directory:       fileFlags&fileDirectory != 0,
		encrypted:       extra.encrypted,
		split:           blk.flags&(flagSplitBefore|flagSplitAfter) != 0,
		dataOffset:      blk.dataOffset,
		dataSize:        blk.dataSize,
	}, nil
}

func parseExtra(extra []byte, headerOffset uint64) (extraInfo, error) {
	var info extraInfo
	pos := 0
	for pos < len(extra) {
		recordStart := pos
		recordSize, err := readVint(extra, &pos)
		if err != nil {
			return info, err
		}
		bodyStart := pos
		if recordSize > uint64(len(extra)-bodyStart) {
			return info, corruptf(headerOffset, "a RAR extra record runs past the extra area")
		}
		bodyEnd := bodyStart + int(recordSize)

		recordType, err := readVintLimited(extra, &pos, bodyEnd)
		if err != nil {
			return info, err
		}
		switch recordType {
		case extraCrypt:
			info.encrypted = true
		case extraHTime:
			flags, err := readVintLimited(extra, &pos, bodyEnd)
			if err != nil {
				return info, err
			}
			if flags&htimeMtime != 0 {
				if flags&htimeUnix != 0 {
					value, err := readU32Limited(extra, &pos, bodyEnd)
					if err != nil {
						return info, err
					}
					seconds := int64(value)
					info.modified = &seconds
				} else {
					ticks, err := readU64Limited(extra, &pos, bodyEnd)
					if err != nil {
						return info, err
					}
					seconds := filetimeToUnix(ticks)
					info.modified = &seconds
				}
			}
		}

		// Every record is skipped by its own size, so an extra type this
		// reader does not use cannot desynchronise the ones after it.
		pos = bodyEnd
		if pos <= recordStart {
			return info, corruptf(headerOffset, "a RAR extra record makes no progress")
		}
	}
	return info, nil
}

func filetimeToUnix(ticks uint64) int64 {
	seconds := int64(ticks / 10_000_000)
	return seconds - filetimeUnixOffset
}

var (
	_ archive.Adapter = Adapter{}
	_ archive.Reader  = (*Reader)(nil)
)
