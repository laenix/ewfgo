// Package xar reads Apple XAR archives, the container behind flat `.pkg`
// files.
//
// A XAR file is a 28-byte big-endian header, a zlib-compressed XML table of
// contents, and a heap that holds the payload bytes plus the archive
// checksum.  Every payload offset in the TOC is relative to the start of the
// heap, which is exactly header_size + toc_length_compressed; the reader turns
// those into absolute container offsets once and bounds-checks each range
// against the file.
//
// The TOC is the authority on what the archive holds: names, kinds, modes,
// ownership, timestamps, the stored length, the extracted length, and the two
// checksums XAR records for each payload.  Directories nest their children as
// further <file> elements, so the reader walks the tree and builds full paths.
//
// # What is and is not read
//
//   - Payload encodings application/octet-stream (stored), application/x-gzip
//     (a zlib stream, despite the name), application/x-bzip2 and
//     application/x-xz are decoded.  application/x-lzma is recognised and
//     listed, but this pure-Go port has no LZMA-alone decoder: opening one of
//     those payloads returns source.ErrUnsupported naming the declared
//     encoding.  Any other style is refused by name in the same way.  Listing
//     never decodes.
//   - The archive-level checksum, which covers the compressed TOC, is verified
//     when its style is SHA-1, MD5, or SHA-256; a mismatch is reported through
//     [Reader.TOChecksum], not hidden, and does not by itself refuse the
//     archive.
//   - Per-payload archived-checksum and extracted-checksum are verified
//     against the stored and decoded bytes on read.  A mismatch counts as
//     corrupt bytes and the bytes are still returned: a checksum can prove
//     alteration but cannot decide what the content should have been.
//   - Hard links name the target file's TOC id.  A link is pointed at the
//     data-bearing member and marked HardlinkOf; a link whose target is not in
//     the archive stays empty and is counted.
//   - Extended attributes (<ea>) are counted but not exposed as archive
//     members; they are not files in the package tree.
//   - Nothing is extracted to disk, and no path is trusted: every joined path
//     goes through archive.SanitizeEntryPath, the same sanitizer ZIP and CAB
//     use.  An unsafe name is counted and skipped.
//
// This is a Go port of forensic-core's data/containers/xar.rs.  Every
// functional branch of the reference reader is ported except the LZMA-alone
// and XZ decoders (see above), which are refused with an explicit error.  Two
// deliberate implementation differences are worth recording: payloads whose
// encoding is refused are refused without reading the stored bytes, and
// element and attribute names are matched on their local name because
// encoding/xml resolves namespace prefixes before this reader sees them (a
// namespaced TOC is therefore accepted where the reference's exact-name
// matcher would not).  Neither changes what bytes a supported payload yields.
package xar

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/containers/lzma"
	"github.com/laenix/ewfgo/internal/data/containers/xz"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Magic is the four-byte file signature.
var Magic = [4]byte{'x', 'a', 'r', '!'}

const (
	// HeaderBytes is the fixed part of the header; extensions only make it
	// longer.
	HeaderBytes = 28
	// MaxHeaderBytes is the largest header this reader follows by default.  The
	// field is a u16, but a header far past the documented 28 bytes is not
	// something to walk blind.
	MaxHeaderBytes uint16 = 4096
	// MaxTOCBytes is the largest compressed or inflated TOC this reader accepts
	// by default.
	MaxTOCBytes uint64 = 32 * 1024 * 1024
	// MaxEntries is the largest member list one archive may declare.
	MaxEntries = 1_000_000
	// MaxDepth is the deepest TOC nesting this reader follows.
	MaxDepth uint32 = 64
	// MaxXMLElements bounds the element count of one TOC document.
	MaxXMLElements = 1_000_000
	// MaxDecodedBytes is the default cap on one payload's stored and decoded
	// sizes, so a declared size cannot drive an unbounded allocation.
	MaxDecodedBytes uint64 = 4 * 1024 * 1024 * 1024

	// XARVersion is the only header version this reader follows.
	XARVersion uint16 = 1
)

const (
	octetStream = "application/octet-stream"
	zlibStream  = "application/x-gzip"
)

// Encoding is the compression style named by one <encoding> element.
type Encoding uint8

const (
	// EncodingStored is application/octet-stream: the bytes are stored as they
	// are.
	EncodingStored Encoding = iota
	// EncodingZlib is application/x-gzip: a zlib stream (RFC 1950), despite
	// the name.
	EncodingZlib
	// EncodingBzip2 is application/x-bzip2: one bzip2 stream.
	EncodingBzip2
	// EncodingLZMA is application/x-lzma: one LZMA-alone stream.  It is
	// recognised but not decoded by this pure-Go port.
	EncodingLZMA
	// EncodingXZ is application/x-xz: one XZ stream.  It is recognised but not
	// decoded by this pure-Go port.
	EncodingXZ
	// EncodingOther is any other style; the exact spelling stays in
	// [Data.Style].
	EncodingOther
)

func encodingFromStyle(style string) Encoding {
	switch style {
	case octetStream, "":
		return EncodingStored
	case zlibStream:
		return EncodingZlib
	case "application/x-bzip2":
		return EncodingBzip2
	case "application/x-lzma":
		return EncodingLZMA
	case "application/x-xz":
		return EncodingXZ
	default:
		return EncodingOther
	}
}

// Label returns a stable name for summaries and refusals.
func (e Encoding) Label() string {
	switch e {
	case EncodingStored:
		return "stored"
	case EncodingZlib:
		return "zlib"
	case EncodingBzip2:
		return "bzip2"
	case EncodingLZMA:
		return "lzma"
	case EncodingXZ:
		return "xz"
	default:
		return "other"
	}
}

// String returns the label, so the encoding prints readably in reports.
func (e Encoding) String() string { return e.Label() }

// IsSupported reports whether this reader decodes the encoding.  LZMA and XZ
// are recognised ([Encoding.IsKnown]) but have no decoder in this port.
func (e Encoding) IsSupported() bool {
	switch e {
	case EncodingStored, EncodingZlib, EncodingBzip2:
		return true
	default:
		return false
	}
}

// IsKnown reports whether the style is one the reference XAR schema names,
// whether or not this reader decodes it.
func (e Encoding) IsKnown() bool { return e != EncodingOther }

// Data is the stored location and declaration of one payload.
type Data struct {
	// Offset is the absolute offset in the container.
	Offset uint64
	// Length is the number of bytes stored in the heap.
	Length uint64
	// Size is the number of bytes the entry expands to.
	Size uint64
	// Style is the exact style attribute of the <encoding> element.
	Style string
	// Encoding is the interpreted style.
	Encoding Encoding
}

// Checksum is one checksum exactly as the TOC spelled it.
type Checksum struct {
	Style string
	Hex   string
}

// EntryKind is what a TOC entry represents.
type EntryKind uint8

const (
	// EntryKindFile is a regular file with a payload.
	EntryKindFile EntryKind = iota
	// EntryKindDirectory is a directory.
	EntryKindDirectory
	// EntryKindSymlink is a symbolic link.
	EntryKindSymlink
	// EntryKindHardlink is a file entry carrying <link type="hard">; its data
	// lives with the entry it names.
	EntryKindHardlink
)

// Label returns the human-readable kind name.
func (k EntryKind) Label() string {
	switch k {
	case EntryKindFile:
		return "file"
	case EntryKindDirectory:
		return "directory"
	case EntryKindSymlink:
		return "symlink"
	default:
		return "hard link"
	}
}

// String returns the label, so the kind prints readably in reports.
func (k EntryKind) String() string { return k.Label() }

// Entry is one member as the TOC describes it.
type Entry struct {
	// ID is the TOC id attribute, when present and numeric.
	ID *uint64
	// Path is the normalized path below the archive root.
	Path string
	// Name is the entry's own <name>, before joining.
	Name string
	// Kind is what the entry represents.
	Kind EntryKind
	// Mode is the permission bits parsed from <mode>, when present.
	Mode *uint32
	// UID and GID are the numeric ownership fields, when they fit u32.
	UID *uint32
	GID *uint32
	// User and Group are the symbolic ownership fields, when present.
	User  *string
	Group *string
	// Atime, Mtime and Ctime are Unix seconds, when the TOC carried a zoned
	// RFC 3339 timestamp.
	Atime *int64
	Mtime *int64
	Ctime *int64
	// Size is the extracted size.
	Size uint64
	// Data is the payload declaration, refilled for a resolved hard link.
	Data *Data
	// Link is a symbolic link's target, or a hard link's recorded target id.
	Link *string
	// HardlinkOf is the path of the member holding the data for a resolved
	// hard link.
	HardlinkOf *string
	// ExtractedChecksum and ArchivedChecksum are the two checksums recorded
	// under <data>.
	ExtractedChecksum *Checksum
	ArchivedChecksum  *Checksum
}

// IsDir reports whether the entry is a directory.
func (e *Entry) IsDir() bool { return e.Kind == EntryKindDirectory }

// Stats describes what the walk saw without inventing entries.
type Stats struct {
	Entries             int
	Files               uint64
	Directories         uint64
	Symlinks            uint64
	Hardlinks           uint64
	EAs                 uint64
	UnresolvedHardlinks uint64
	SkippedUnsafe       uint64
}

// TOCStatus is the outcome of checking the archive-level checksum against the
// compressed TOC bytes.
type TOCStatus uint8

const (
	// TOCNotRecorded means the header declares no checksum algorithm.
	TOCNotRecorded TOCStatus = iota
	// TOCVerified means a checksum is recorded and the compressed TOC matches.
	TOCVerified
	// TOCMismatch means a checksum is recorded and the compressed TOC does not
	// match.
	TOCMismatch
	// TOCAbsent means the header names an algorithm but the TOC has no
	// checksum element.
	TOCAbsent
	// TOCUnsupported means the header names an algorithm this reader cannot
	// compute.
	TOCUnsupported
	// TOCMalformed means the checksum element is not a valid offset/size/digest.
	TOCMalformed
)

// Label returns the human-readable status name.
func (s TOCStatus) Label() string {
	switch s {
	case TOCNotRecorded:
		return "not recorded"
	case TOCVerified:
		return "verified"
	case TOCMismatch:
		return "mismatch"
	case TOCAbsent:
		return "absent"
	case TOCUnsupported:
		return "unsupported"
	default:
		return "malformed"
	}
}

// String returns the label, so the status prints readably in reports.
func (s TOCStatus) String() string { return s.Label() }

// Limits are the resource bounds applied while parsing and reading.  A zero
// field takes the corresponding default, so a caller can raise one bound
// explicitly and leave an auditable decision in the case record.
type Limits struct {
	MaxHeaderBytes  uint16
	MaxTOCBytes     uint64
	MaxEntries      int
	MaxDepth        uint32
	MaxXMLElements  int
	MaxDecodedBytes uint64
}

// DefaultLimits returns the documented defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxHeaderBytes:  MaxHeaderBytes,
		MaxTOCBytes:     MaxTOCBytes,
		MaxEntries:      MaxEntries,
		MaxDepth:        MaxDepth,
		MaxXMLElements:  MaxXMLElements,
		MaxDecodedBytes: MaxDecodedBytes,
	}
}

func (l Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	if l.MaxHeaderBytes == 0 {
		l.MaxHeaderBytes = defaults.MaxHeaderBytes
	}
	if l.MaxTOCBytes == 0 {
		l.MaxTOCBytes = defaults.MaxTOCBytes
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = defaults.MaxEntries
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = defaults.MaxDepth
	}
	if l.MaxXMLElements == 0 {
		l.MaxXMLElements = defaults.MaxXMLElements
	}
	if l.MaxDecodedBytes == 0 {
		l.MaxDecodedBytes = defaults.MaxDecodedBytes
	}
	return l
}

// Reader is a parsed XAR container.  Payloads are decoded lazily.
type Reader struct {
	src         source.ByteSource
	limits      Limits
	version     uint16
	creation    *int64
	tocStatus   TOCStatus
	tocRecorded *Checksum
	heapOffset  uint64
	entries     []Entry
	byPath      map[string]int
	stats       Stats
}

// Open parses the header and TOC with the default limits.  Payloads are not
// touched.
func Open(src source.ByteSource) (*Reader, error) { return OpenWithLimits(src, DefaultLimits()) }

// OpenWithLimits parses the header and TOC with explicit resource bounds.
func OpenWithLimits(src source.ByteSource, limits Limits) (*Reader, error) {
	limits = limits.withDefaults()
	sourceLen := src.Len()
	if sourceLen < HeaderBytes {
		return nil, unsupported("a source shorter than the %d-byte header", HeaderBytes)
	}
	header, err := source.ReadVecAt(src, 0, HeaderBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:4], Magic[:]) {
		return nil, unsupported("the magic % x (expected % x)", header[:4], Magic[:])
	}

	headerSize := binary.BigEndian.Uint16(header[4:6])
	version := binary.BigEndian.Uint16(header[6:8])
	tocCompressed := binary.BigEndian.Uint64(header[8:16])
	tocUncompressed := binary.BigEndian.Uint64(header[16:24])
	checksumAlgorithm := binary.BigEndian.Uint32(header[24:28])

	if version != XARVersion {
		return nil, unsupported("header version %d", version)
	}
	if headerSize < HeaderBytes {
		return nil, corrupt(4, "the header size %d is below the 28-byte minimum", headerSize)
	}
	if headerSize > limits.MaxHeaderBytes {
		return nil, unsupported("a %d-byte header (this reader follows at most %d)", headerSize, limits.MaxHeaderBytes)
	}
	if tocCompressed == 0 || tocUncompressed == 0 {
		return nil, corrupt(8, "the header declares an empty TOC")
	}
	if tocCompressed > limits.MaxTOCBytes || tocUncompressed > limits.MaxTOCBytes {
		return nil, unsupported("a TOC of %d/%d bytes (limit %d)", tocCompressed, tocUncompressed, limits.MaxTOCBytes)
	}
	if tocUncompressed > uint64(math.MaxInt) {
		return nil, unsupported("a TOC that inflates to %d bytes, above this platform's limit", tocUncompressed)
	}

	heapOffset, overflow := addU64(uint64(headerSize), tocCompressed)
	if overflow {
		return nil, corrupt(8, "the heap offset overflows")
	}
	if heapOffset > sourceLen {
		return nil, corrupt(uint64(headerSize), "the %d-byte TOC runs past the %d-byte archive", tocCompressed, sourceLen)
	}

	compressed, err := source.ReadVecAt(src, uint64(headerSize), tocCompressed)
	if err != nil {
		return nil, err
	}
	tocBytes, exceeded, err := inflateZlib(compressed, tocUncompressed)
	if err != nil {
		return nil, corrupt(uint64(headerSize), "the TOC: %v", err)
	}
	if exceeded {
		return nil, unsupported("a TOC that inflates past its declared %d bytes", tocUncompressed)
	}
	if uint64(len(tocBytes)) != tocUncompressed {
		return nil, corrupt(uint64(headerSize),
			"the TOC inflated to %d bytes, the header declares %d", len(tocBytes), tocUncompressed)
	}

	root, err := parseXML(tocBytes, limits.MaxXMLElements)
	if err != nil {
		return nil, corrupt(uint64(headerSize), "the TOC XML: %v", err)
	}
	if root.name != "xar" {
		return nil, unsupported("a TOC rooted at <%s> instead of <xar>", root.name)
	}
	toc := root.child("toc")
	if toc == nil {
		return nil, unsupported("a XAR TOC without a <toc> element")
	}

	var creation *int64
	if text, ok := toc.childText("creation-time"); ok {
		if seconds, ok := parseTime(text); ok {
			creation = &seconds
		}
	}

	status, recorded, err := checkTOCChecksum(toc, checksumAlgorithm, heapOffset, src, sourceLen, compressed)
	if err != nil {
		return nil, err
	}

	walker := &tocWalker{sourceLen: sourceLen, heapOffset: heapOffset, limits: limits}
	if err := walker.walk(toc.children, "", 1); err != nil {
		return nil, err
	}
	if len(walker.entries) > limits.MaxEntries {
		return nil, unsupported("more than %d TOC entries", limits.MaxEntries)
	}
	resolveHardlinks(walker.entries, &walker.stats)

	byPath := make(map[string]int, len(walker.entries))
	for index := range walker.entries {
		if _, exists := byPath[walker.entries[index].Path]; !exists {
			byPath[walker.entries[index].Path] = index
		}
	}
	stats := walker.stats
	stats.Entries = len(walker.entries)

	return &Reader{
		src:         src,
		limits:      limits,
		version:     version,
		creation:    creation,
		tocStatus:   status,
		tocRecorded: recorded,
		heapOffset:  heapOffset,
		entries:     walker.entries,
		byPath:      byPath,
		stats:       stats,
	}, nil
}

// Version returns the header version.
func (r *Reader) Version() uint16 { return r.version }

// Creation returns the TOC's <creation-time> in Unix seconds, when it parsed.
func (r *Reader) Creation() *int64 { return r.creation }

// TOChecksum returns the archive-level checksum status.
func (r *Reader) TOChecksum() TOCStatus { return r.tocStatus }

// TOChecksumRecorded returns the checksum element exactly as recorded, when
// one was present.
func (r *Reader) TOChecksumRecorded() *Checksum { return r.tocRecorded }

// HeapOffset returns the absolute offset where payload offsets are measured
// from.
func (r *Reader) HeapOffset() uint64 { return r.heapOffset }

// Entries returns a copy of the member list in walk order.
func (r *Reader) Entries() []Entry { return append([]Entry(nil), r.entries...) }

// Entry returns the first member with this normalized path.
func (r *Reader) Entry(path string) (*Entry, bool) {
	index, ok := r.byPath[path]
	if !ok {
		return nil, false
	}
	return &r.entries[index], true
}

// Stats returns the counts gathered while walking the TOC.
func (r *Reader) Stats() Stats { return r.stats }

// OpenEntrySource opens one payload as a ByteSource.  Directories and symbolic
// links have no stream; a hard link without its data-bearing member is refused
// rather than presented as an empty file.
func (r *Reader) OpenEntrySource(path string, id source.ID) (*EntrySource, error) {
	normalized, err := archive.SanitizeEntryPath(path)
	if err != nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: err.Error()}
	}
	index, ok := r.byPath[normalized]
	if !ok {
		return nil, &source.Error{
			Kind:   source.ErrInvalidArgument,
			Reason: fmt.Sprintf("XAR has no entry named %s", path),
		}
	}
	entry := &r.entries[index]
	switch entry.Kind {
	case EntryKindDirectory:
		return nil, unsupported("the directory %s has no data stream", entry.Path)
	case EntryKindSymlink:
		target := "<none>"
		if entry.Link != nil {
			target = *entry.Link
		}
		return nil, unsupported("the symbolic link %s has no data stream (target %q)", entry.Path, target)
	}
	if entry.Data == nil {
		return nil, unsupported("the hard link %s has no data-bearing member in this archive", entry.Path)
	}
	return &EntrySource{
		id:         id,
		parent:     r.src,
		entry:      *entry,
		data:       *entry.Data,
		maxDecoded: r.limits.MaxDecodedBytes,
	}, nil
}

// OpenEntry opens one payload as a ByteSource.  It is the interface-shaped
// form of [Reader.OpenEntrySource].
func (r *Reader) OpenEntry(path string, id source.ID) (source.ByteSource, error) {
	return r.OpenEntrySource(path, id)
}

// tocWalker carries the walk state so the recursion stays explicit.
type tocWalker struct {
	sourceLen  uint64
	heapOffset uint64
	limits     Limits
	entries    []Entry
	stats      Stats
}

// walk visits the <file> children of the TOC or of one directory entry.
func (w *tocWalker) walk(children []*element, parent string, depth uint32) error {
	if depth > w.limits.MaxDepth {
		return unsupported("a TOC nested deeper than %d levels", w.limits.MaxDepth)
	}
	for _, node := range children {
		if node.name != "file" {
			continue
		}
		if len(w.entries) >= w.limits.MaxEntries {
			return unsupported("more than %d TOC entries", w.limits.MaxEntries)
		}

		name, ok := node.childText("name")
		if !ok {
			return unsupported("a TOC entry without a <name>")
		}
		rawPath := name
		if parent != "" {
			rawPath = parent + "/" + name
		}
		path, err := archive.SanitizeEntryPath(rawPath)
		if err != nil {
			w.stats.SkippedUnsafe++
			continue
		}

		typeText, ok := node.childText("type")
		if !ok {
			return unsupported("entry %q has no <type>", rawPath)
		}
		var kind EntryKind
		switch typeText {
		case "file":
			kind = EntryKindFile
			if link := node.child("link"); link != nil {
				if linkType, ok := link.attribute("type"); ok && linkType == "hard" {
					kind = EntryKindHardlink
				}
			}
		case "directory":
			kind = EntryKindDirectory
		case "symlink":
			kind = EntryKindSymlink
		default:
			return unsupported("entry %q has type %q", rawPath, typeText)
		}

		var link *string
		if linkNode := node.child("link"); linkNode != nil {
			target := strings.TrimSpace(linkNode.trimmedText())
			if target != "" {
				link = &target
			}
		}
		if kind == EntryKindSymlink && link == nil {
			return unsupported("the symbolic link %q has no target", rawPath)
		}

		size, _ := childU64(node, "size")
		var data *Data
		var extractedChecksum, archivedChecksum *Checksum
		if dataNode := node.child("data"); dataNode != nil {
			parsed, extracted, archived, err := parseData(dataNode, rawPath, size, w.sourceLen, w.heapOffset)
			if err != nil {
				return err
			}
			data = parsed
			extractedChecksum = extracted
			archivedChecksum = archived
		}
		if data != nil {
			if kind == EntryKindSymlink {
				return unsupported("the symbolic link %q carries a data area", rawPath)
			}
			if kind == EntryKindDirectory && data.Length != 0 {
				return unsupported("the directory %q carries %d stored bytes", rawPath, data.Length)
			}
		}
		w.stats.EAs += uint64(countChildren(node, "ea"))

		entry := Entry{
			Path:              path,
			Name:              name,
			Kind:              kind,
			Size:              size,
			Data:              data,
			Link:              link,
			ExtractedChecksum: extractedChecksum,
			ArchivedChecksum:  archivedChecksum,
		}
		if idText, ok := node.attribute("id"); ok {
			if id, err := strconv.ParseUint(idText, 10, 64); err == nil {
				entry.ID = &id
			}
		}
		if modeText, ok := node.childText("mode"); ok {
			if mode, ok := parseOctal(modeText); ok {
				entry.Mode = &mode
			}
		}
		if uid, ok := childU64(node, "uid"); ok && uid <= math.MaxUint32 {
			value := uint32(uid)
			entry.UID = &value
		}
		if gid, ok := childU64(node, "gid"); ok && gid <= math.MaxUint32 {
			value := uint32(gid)
			entry.GID = &value
		}
		if user, ok := node.childText("user"); ok {
			entry.User = &user
		}
		if group, ok := node.childText("group"); ok {
			entry.Group = &group
		}
		if text, ok := node.childText("atime"); ok {
			entry.Atime = parseTimePtr(text)
		}
		if text, ok := node.childText("mtime"); ok {
			entry.Mtime = parseTimePtr(text)
		}
		if text, ok := node.childText("ctime"); ok {
			entry.Ctime = parseTimePtr(text)
		}

		switch kind {
		case EntryKindFile:
			w.stats.Files++
		case EntryKindDirectory:
			w.stats.Directories++
		case EntryKindSymlink:
			w.stats.Symlinks++
		case EntryKindHardlink:
			w.stats.Hardlinks++
		}
		w.entries = append(w.entries, entry)

		if kind == EntryKindDirectory {
			if err := w.walk(node.children, path, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseData parses one <data> element and resolves its heap-relative offset.
// It returns the payload location plus its two recorded checksums: the archive
// spells them as children of <data>, and both apply to the payload.
func parseData(data *element, entry string, entrySize, sourceLen, heapOffset uint64) (*Data, *Checksum, *Checksum, error) {
	offset, ok := childU64(data, "offset")
	if !ok {
		return nil, nil, nil, corrupt(heapOffset, "entry %q has no data offset", entry)
	}
	length, ok := childU64(data, "length")
	if !ok {
		return nil, nil, nil, corrupt(heapOffset, "entry %q has no stored length", entry)
	}
	size := entrySize
	if declared, ok := childU64(data, "size"); ok {
		size = declared
	}
	style := octetStream
	if encodingNode := data.child("encoding"); encodingNode != nil {
		if value, ok := encodingNode.attribute("style"); ok {
			style = value
		}
	}
	encoding := encodingFromStyle(style)

	absolute, overflow := addU64(heapOffset, offset)
	if overflow {
		return nil, nil, nil, corrupt(heapOffset, "entry %q data offset overflows", entry)
	}
	end, overflow := addU64(absolute, length)
	if overflow {
		return nil, nil, nil, corrupt(absolute, "entry %q data length overflows", entry)
	}
	if end > sourceLen {
		return nil, nil, nil, corrupt(absolute,
			"entry %q data [%d, +%d) is outside the %d byte archive", entry, absolute, length, sourceLen)
	}

	return &Data{
			Offset:   absolute,
			Length:   length,
			Size:     size,
			Style:    style,
			Encoding: encoding,
		},
		parseChecksum(data, "extracted-checksum"),
		parseChecksum(data, "archived-checksum"),
		nil
}

// parseChecksum returns one <extracted-checksum> or <archived-checksum> child
// when both its style and its hex are present.
func parseChecksum(data *element, name string) *Checksum {
	node := data.child(name)
	if node == nil {
		return nil
	}
	style := ""
	if value, ok := node.attribute("style"); ok {
		style = strings.TrimSpace(value)
	}
	text := node.trimmedText()
	if style == "" || text == "" {
		return nil
	}
	return &Checksum{Style: style, Hex: text}
}

// checkTOCChecksum verifies the archive-level checksum that covers the
// compressed TOC.
func checkTOCChecksum(toc *element, algorithm uint32, heapOffset uint64, src source.ByteSource, sourceLen uint64, compressed []byte) (TOCStatus, *Checksum, error) {
	var style string
	switch algorithm {
	case 0:
		return TOCNotRecorded, nil, nil
	case 1:
		style = "sha1"
	case 2:
		style = "md5"
	case 3:
		style = "sha256"
	default:
		return TOCUnsupported, nil, nil
	}

	node := toc.child("checksum")
	if node == nil {
		return TOCAbsent, nil, nil
	}
	recordedStyle := style
	if value, ok := node.attribute("style"); ok {
		recordedStyle = value
	}
	recorded := &Checksum{Style: recordedStyle, Hex: node.trimmedText()}

	offset, hasOffset := childU64(node, "offset")
	size, hasSize := childU64(node, "size")
	if !hasOffset || !hasSize || size == 0 {
		return TOCMalformed, recorded, nil
	}
	absolute, overflow := addU64(heapOffset, offset)
	if overflow {
		return TOCMalformed, recorded, nil
	}
	end, overflow := addU64(absolute, size)
	if overflow || end > sourceLen {
		return TOCMalformed, recorded, nil
	}

	stored, err := source.ReadVecAt(src, absolute, size)
	if err != nil {
		return TOCMalformed, recorded, err
	}
	expected, known := digest(recordedStyle, compressed)
	if !known {
		return TOCUnsupported, recorded, nil
	}
	if bytes.Equal(expected, stored) {
		return TOCVerified, recorded, nil
	}
	return TOCMismatch, recorded, nil
}

// resolveHardlinks points <link type="hard"> entries at the member that holds
// the data.
func resolveHardlinks(entries []Entry, stats *Stats) {
	holders := make(map[uint64]int)
	for index := range entries {
		entry := &entries[index]
		if entry.Kind == EntryKindFile && entry.Data != nil && entry.ID != nil {
			holders[*entry.ID] = index
		}
	}
	type hardRef struct {
		index  int
		target *uint64
	}
	links := make([]hardRef, 0)
	for index := range entries {
		entry := &entries[index]
		if entry.Kind != EntryKindHardlink {
			continue
		}
		var target *uint64
		if entry.Link != nil {
			if value, err := strconv.ParseUint(strings.TrimSpace(*entry.Link), 10, 64); err == nil {
				target = &value
			}
		}
		links = append(links, hardRef{index: index, target: target})
	}
	for _, link := range links {
		if link.target == nil {
			stats.UnresolvedHardlinks++
			continue
		}
		holder, ok := holders[*link.target]
		if !ok {
			stats.UnresolvedHardlinks++
			continue
		}
		entries[link.index].Data = entries[holder].Data
		entries[link.index].Size = entries[holder].Size
		path := entries[holder].Path
		entries[link.index].HardlinkOf = &path
	}
}

// EntrySource is one payload exposed as a ByteSource.  Decoded bytes are
// cached after the first successful read.
type EntrySource struct {
	id         source.ID
	parent     source.ByteSource
	entry      Entry
	data       Data
	maxDecoded uint64

	mu       sync.Mutex
	cache    []byte
	cached   bool
	counters source.Counters
}

// Entry returns the TOC entry this source was opened from.
func (s *EntrySource) Entry() *Entry { return &s.entry }

// DataOffset returns the absolute offset of the stored bytes.
func (s *EntrySource) DataOffset() uint64 { return s.data.Offset }

// StoredSize returns the number of stored bytes.
func (s *EntrySource) StoredSize() uint64 { return s.data.Length }

// decode reads, verifies and decompresses the payload, caching the result.
func (s *EntrySource) decode() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached {
		s.counters.AddCacheHit()
		return s.cache, nil
	}
	s.counters.AddCacheMiss()

	declared := s.entry.Size
	if declared > s.maxDecoded {
		return nil, unsupported("entry %s declares %d decoded bytes, above the %d-byte read cap",
			s.entry.Path, declared, s.maxDecoded)
	}
	if s.data.Length > s.maxDecoded {
		return nil, unsupported("entry %s stores %d bytes, above the %d-byte read cap",
			s.entry.Path, s.data.Length, s.maxDecoded)
	}

	switch s.data.Encoding {
	case EncodingStored, EncodingZlib, EncodingBzip2, EncodingXZ, EncodingLZMA:
		// Decoded below.
	default:
		return nil, unsupported("the %q payload encoding", s.data.Style)
	}

	stored, err := source.ReadVecAt(s.parent, s.data.Offset, s.data.Length)
	if err != nil {
		return nil, err
	}
	isCorrupt := false
	if s.entry.ArchivedChecksum != nil {
		if match, known := verifyChecksum(s.entry.ArchivedChecksum, stored); known && !match {
			isCorrupt = true
		}
	}

	var decoded []byte
	switch s.data.Encoding {
	case EncodingStored:
		if s.data.Length != declared {
			isCorrupt = true
		}
		decoded = stored
	case EncodingZlib, EncodingBzip2:
		// The reference reader caps decompression at declared+1 so a stream
		// that expands past its declaration is refused.  One extra byte over
		// the declaration is truncated and counted below.
		limit := declared
		if limit < math.MaxUint64 {
			limit++
		}
		var out []byte
		var exceeded bool
		if s.data.Encoding == EncodingZlib {
			out, exceeded, err = inflateZlib(stored, limit)
		} else {
			out, exceeded, err = inflateBzip2(stored, limit)
		}
		if err != nil {
			return nil, corrupt(s.data.Offset, "%s stream: %v", s.data.Encoding.Label(), err)
		}
		if exceeded {
			return nil, corrupt(s.data.Offset, "%s stream: output exceeds the %d-byte limit",
				s.data.Encoding.Label(), limit)
		}
		s.counters.AddDecompressed(uint64(len(out)))
		decoded = out
	case EncodingXZ:
		limit := declared
		if limit < math.MaxUint64 {
			limit++
		}
		stream, openErr := xz.Open(1, source.NewMemorySource(1, stored), xz.Limits{
			MaxDecodedBytes:    limit,
			MaxCompressedBytes: uint64(len(stored)),
		})
		if openErr != nil {
			return nil, corrupt(s.data.Offset, "%s stream: %v", s.data.Encoding.Label(), openErr)
		}
		s.counters.AddDecompressed(stream.Len())
		decoded = stream.Bytes()
	case EncodingLZMA:
		limit := declared
		if limit < math.MaxUint64 {
			limit++
		}
		out, decodeErr := lzma.Decode(stored, lzma.Limits{
			MaxDecodedBytes:    limit,
			MaxCompressedBytes: uint64(len(stored)),
		})
		if decodeErr != nil {
			return nil, corrupt(s.data.Offset, "%s stream: %v", s.data.Encoding.Label(), decodeErr)
		}
		s.counters.AddDecompressed(uint64(len(out)))
		decoded = out
	}

	if uint64(len(decoded)) != declared {
		isCorrupt = true
		if uint64(len(decoded)) > declared {
			decoded = decoded[:int(declared)]
		}
	}
	if s.entry.ExtractedChecksum != nil {
		if match, known := verifyChecksum(s.entry.ExtractedChecksum, decoded); known && !match {
			isCorrupt = true
		}
	}
	if isCorrupt {
		s.counters.AddCorrupt(uint64(len(decoded)))
	}

	s.cache = decoded
	s.cached = true
	return decoded, nil
}

// SourceID implements source.ByteSource.
func (s *EntrySource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *EntrySource) Len() uint64 { return s.entry.Size }

// ImageID implements source.ByteSource.
func (s *EntrySource) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *EntrySource) SectorSize() uint32 { return s.parent.SectorSize() }

// IsEmpty implements source.ByteSource.
func (s *EntrySource) IsEmpty() bool { return s.entry.Size == 0 }

// Stats implements source.ByteSource.
func (s *EntrySource) Stats() source.Stats { return s.counters.Snapshot() }

// ReadAt implements source.ByteSource.
func (s *EntrySource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	size := s.entry.Size
	if offset >= size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), size)
	}
	want := size - offset
	if want > uint64(len(buf)) {
		want = uint64(len(buf))
	}

	decoded, err := s.decode()
	if err != nil {
		return 0, err
	}
	if offset >= uint64(len(decoded)) {
		return 0, corrupt(offset, "entry %s decoded %d bytes but declares %d",
			s.entry.Path, len(decoded), size)
	}
	n := int(want)
	if remaining := uint64(len(decoded)) - offset; uint64(n) > remaining {
		n = int(remaining)
	}
	copy(buf[:n], decoded[offset:offset+uint64(n)])
	s.counters.AddRead(n)
	return n, nil
}

// ReadAtLossy implements source.ByteSource.  A payload that cannot be decoded
// is zero-filled and counted, never partially invented.
func (s *EntrySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	size := s.entry.Size
	if offset >= size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), size)
	}
	want := size - offset
	if want > uint64(len(buf)) {
		want = uint64(len(buf))
	}
	n, err := s.ReadAt(offset, buf[:want])
	if err != nil {
		for index := uint64(0); index < want; index++ {
			buf[index] = 0
		}
		s.counters.AddCorrupt(want)
		return int(want), nil
	}
	return n, nil
}

// ExtentsInto implements source.ByteSource.
func (s *EntrySource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	size := s.entry.Size
	if offset > size || length > size-offset {
		return out, source.NewOutOfRange(offset, length, size)
	}
	if length == 0 {
		return out, nil
	}
	if s.data.Encoding == EncodingStored {
		if offset > s.data.Length || length > s.data.Length-offset {
			return out, source.NewOutOfRange(offset, length, s.data.Length)
		}
		return append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: s.data.Offset + offset,
			Len:          length,
			Kind:         source.RangeData,
		}), nil
	}
	kind := source.RangeData
	if s.data.Length == 0 && s.entry.Size > 0 {
		kind = source.RangeError
	}
	return append(out, source.ParentRange{
		Parent:       s.parent.SourceID(),
		ParentOffset: s.data.Offset,
		Len:          s.data.Length,
		Kind:         kind,
	}), nil
}

// Extents implements source.ByteSource.
func (s *EntrySource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *EntrySource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	size := s.entry.Size
	if offset > size || length > size-offset {
		return nil, source.NewOutOfRange(offset, length, size)
	}
	if length == 0 {
		return nil, nil
	}
	if s.data.Encoding == EncodingStored {
		return s.parent.MapToImage(s.data.Offset+offset, length)
	}
	if s.data.Length == 0 {
		return []source.ImageRange{{
			ImageID:     s.parent.ImageID(),
			ImageOffset: 0,
			Len:         length,
			Kind:        source.RangeError,
		}}, nil
	}
	return s.parent.MapToImage(s.data.Offset, s.data.Length)
}

// inflateZlib decodes one zlib stream, reading at most limit+1 bytes.  The
// bool reports that the stream produced more than limit bytes.
func inflateZlib(data []byte, limit uint64) ([]byte, bool, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false, err
	}
	out, exceeded, err := readLimited(reader, limit)
	closeErr := reader.Close()
	if err != nil {
		return nil, false, err
	}
	if closeErr != nil {
		return nil, false, closeErr
	}
	return out, exceeded, nil
}

// inflateBzip2 decodes one bzip2 stream.  The standard library decoder
// verifies the stream CRC.
func inflateBzip2(data []byte, limit uint64) ([]byte, bool, error) {
	if len(data) == 0 {
		return nil, false, fmt.Errorf("empty bzip2 stream")
	}
	return readLimited(bzip2.NewReader(bytes.NewReader(data)), limit)
}

func readLimited(reader io.Reader, limit uint64) ([]byte, bool, error) {
	if limit > uint64(math.MaxInt64-1) {
		limit = uint64(math.MaxInt64 - 1)
	}
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	if uint64(len(out)) > limit {
		return nil, true, nil
	}
	return out, false, nil
}

// digest computes an archive checksum.  The second result is false for a style
// this reader cannot compute.
func digest(style string, data []byte) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(style)) {
	case "sha1":
		sum := sha1.Sum(data)
		return sum[:], true
	case "md5":
		sum := md5.Sum(data)
		return sum[:], true
	case "sha256":
		sum := sha256.Sum256(data)
		return sum[:], true
	default:
		return nil, false
	}
}

// verifyChecksum reports whether data matches checksum.  The second result is
// false when the style is unsupported or the recorded hex is malformed; a
// malformed record is not itself a mismatch.
func verifyChecksum(checksum *Checksum, data []byte) (bool, bool) {
	expected, err := hex.DecodeString(strings.TrimSpace(checksum.Hex))
	if err != nil {
		return false, false
	}
	actual, known := digest(checksum.Style, data)
	if !known {
		return false, false
	}
	return bytes.Equal(actual, expected), true
}

func childU64(node *element, name string) (uint64, bool) {
	text, ok := node.childText(name)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func countChildren(node *element, name string) int {
	count := 0
	for _, child := range node.children {
		if child.name == name {
			count++
		}
	}
	return count
}

// parseOctal parses a mode the way the reference reader does: an optional
// "0o" prefix, otherwise one leading "0", then base-8 digits.
func parseOctal(text string) (uint32, bool) {
	trimmed := strings.TrimSpace(text)
	digits := trimmed
	if strings.HasPrefix(digits, "0o") {
		digits = digits[2:]
	} else if strings.HasPrefix(digits, "0") {
		digits = digits[1:]
	}
	if digits == "" {
		return 0, true
	}
	value, err := strconv.ParseUint(digits, 8, 32)
	if err != nil {
		return 0, false
	}
	return uint32(value), true
}

func parseTimePtr(text string) *int64 {
	seconds, ok := parseTime(text)
	if !ok {
		return nil
	}
	return &seconds
}

// parseTime parses a zoned RFC 3339 timestamp into whole Unix seconds.  A
// timestamp without a zone is refused rather than guessed.
func parseTime(text string) (int64, bool) {
	bytes := []byte(text)
	if len(bytes) < 20 {
		return 0, false
	}
	digits := func(from, to int) (int64, bool) {
		if from < 0 || to > len(bytes) || from > to {
			return 0, false
		}
		var value int64
		for _, digit := range bytes[from:to] {
			if digit < '0' || digit > '9' {
				return 0, false
			}
			value = value*10 + int64(digit-'0')
		}
		return value, true
	}
	if bytes[4] != '-' || bytes[7] != '-' || bytes[10] != 'T' ||
		bytes[13] != ':' || bytes[16] != ':' {
		return 0, false
	}
	year, ok := digits(0, 4)
	if !ok {
		return 0, false
	}
	month, ok := digits(5, 7)
	if !ok {
		return 0, false
	}
	day, ok := digits(8, 10)
	if !ok {
		return 0, false
	}
	hour, ok := digits(11, 13)
	if !ok {
		return 0, false
	}
	minute, ok := digits(14, 16)
	if !ok {
		return 0, false
	}
	second, ok := digits(17, 19)
	if !ok {
		return 0, false
	}
	if month < 1 || month > 12 || day == 0 || day > int64(daysInMonth(year, month)) ||
		hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}

	index := 19
	if index < len(bytes) && bytes[index] == '.' {
		index++
		start := index
		for index < len(bytes) && bytes[index] >= '0' && bytes[index] <= '9' && index-start < 9 {
			index++
		}
		if index == start {
			return 0, false
		}
	}

	var offsetSeconds int64
	if index >= len(bytes) {
		return 0, false
	}
	switch bytes[index] {
	case 'Z', 'z':
		if index+1 != len(bytes) {
			return 0, false
		}
	case '+', '-':
		sign := int64(1)
		if bytes[index] == '-' {
			sign = -1
		}
		rest := bytes[index+1:]
		var hours, minutes int64
		switch {
		case len(rest) == 5 && rest[2] == ':':
			hours, ok = digits(index+1, index+3)
			if !ok {
				return 0, false
			}
			minutes, ok = digits(index+4, index+6)
			if !ok {
				return 0, false
			}
		case len(rest) == 4:
			hours, ok = digits(index+1, index+3)
			if !ok {
				return 0, false
			}
			minutes, ok = digits(index+3, index+5)
			if !ok {
				return 0, false
			}
		default:
			return 0, false
		}
		if hours > 23 || minutes > 59 {
			return 0, false
		}
		offsetSeconds = sign * (hours*3600 + minutes*60)
	default:
		return 0, false
	}

	days := daysFromCivil(year, month, day)
	seconds := days*86400 + hour*3600 + minute*60 + second - offsetSeconds
	return seconds, true
}

func daysInMonth(year, month int64) int64 {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeapYear(year) {
			return 29
		}
		return 28
	default:
		return 0
	}
}

func isLeapYear(year int64) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

// daysFromCivil is Howard Hinnant's days_from_civil.
func daysFromCivil(year, month, day int64) int64 {
	if month <= 2 {
		year--
	}
	era := year / 400
	if year < 0 {
		era = (year - 399) / 400
	}
	yearOfEra := year - era*400
	monthPrime := (month + 9) % 12
	dayOfYear := (153*monthPrime+2)/5 + day - 1
	dayOfEra := yearOfEra*365 + yearOfEra/4 - yearOfEra/100 + dayOfYear
	return era*146097 + dayOfEra - 719468
}

func addU64(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum < a
}

func corrupt(offset uint64, format string, args ...any) error {
	return source.NewCorrupt(offset, fmt.Sprintf(format, args...))
}

func unsupported(format string, args ...any) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(format, args...)}
}
