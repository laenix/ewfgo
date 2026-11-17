// Package carving implements read-only signature carving over a ByteSource.
//
// Carving is the last resort of a recovery examination. When a volume's
// metadata no longer lists a file, the only thing left is the file's own
// structure: a header that says what it is and an end marker that says how long
// it is. This package searches a byte range for the headers of a set of
// formats, walks each candidate's own structure to its end marker or declared
// extent, rejects the candidates that do not walk cleanly, and reports the
// objects it kept with their provenance ranges.
//
// This is a Go port of forensic-core's data::carving module. The formats ported
// in this build are BMP, GIF, TIFF, WebP, EVTX (whole logs and standalone
// chunks), SQLite and Windows Prefetch (raw SCCA records and MAM containers).
// JPEG, PNG, PDF and ZIP are recognised by the header search but their walks
// are not ported; a hit for one of them returns ErrUnsupported rather than
// silently ignoring it.
//
// The scan is deliberately bounded: MaxObjectBytes stops a header that walks
// into the next gigabyte without meeting an end marker, and MaxObjects stops a
// range that is really a fuzz corpus. Both report Truncated instead of growing
// without bound.
package carving

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Largest object one header may claim. A file bigger than this is carved only
// when the caller raises the limit: the alternative is a bad header swallowing
// the rest of the image.
const DefaultMaxObjectBytes uint64 = 128 * 1024 * 1024

// Largest number of objects one pass reports.
const DefaultMaxObjects = 4096

// readChunk is the read size for the header search and for scanning inside an
// object.
const readChunk = 1 << 20

// ErrUnsupported reports a format or branch the Rust carving module recognises
// but this build does not port. It is the source package's sentinel so callers
// keep one error taxonomy across the data plane.
var ErrUnsupported = source.ErrUnsupported

// CarvedFormat names one format the header search looks for.
type CarvedFormat int

// The formats, in the Rust enum's declaration order. That order is what breaks
// ties between two hits at the same offset.
const (
	FormatJpeg CarvedFormat = iota
	FormatPng
	FormatPdf
	FormatZip
	FormatEvtx
	FormatEvtxChunk
	FormatSqlite
	FormatGif
	FormatBmp
	FormatTiff
	FormatWebP
	FormatPrefetch
)

// ID is the stable identifier written to datasets and used by the CLI.
func (f CarvedFormat) ID() string {
	switch f {
	case FormatJpeg:
		return "jpeg"
	case FormatPng:
		return "png"
	case FormatPdf:
		return "pdf"
	case FormatZip:
		return "zip"
	case FormatEvtx:
		return "evtx"
	case FormatEvtxChunk:
		return "evtx-chunk"
	case FormatSqlite:
		return "sqlite"
	case FormatGif:
		return "gif"
	case FormatBmp:
		return "bmp"
	case FormatTiff:
		return "tiff"
	case FormatWebP:
		return "webp"
	case FormatPrefetch:
		return "prefetch"
	default:
		return "unknown"
	}
}

// Label is the human-readable format name.
func (f CarvedFormat) Label() string {
	switch f {
	case FormatJpeg:
		return "JPEG image"
	case FormatPng:
		return "PNG image"
	case FormatPdf:
		return "PDF document"
	case FormatZip:
		return "ZIP archive"
	case FormatEvtx:
		return "Windows event log"
	case FormatEvtxChunk:
		return "EVTX chunk"
	case FormatSqlite:
		return "SQLite 3 database"
	case FormatGif:
		return "GIF image"
	case FormatBmp:
		return "BMP image"
	case FormatTiff:
		return "TIFF image"
	case FormatWebP:
		return "WebP image"
	case FormatPrefetch:
		return "Windows Prefetch file"
	default:
		return "unknown"
	}
}

// Extension is the file name extension used when a carved object is written
// out. A chunk is not a standalone log file, so it does not get the .evtx its
// container would.
func (f CarvedFormat) Extension() string {
	switch f {
	case FormatJpeg:
		return "jpg"
	case FormatPng:
		return "png"
	case FormatPdf:
		return "pdf"
	case FormatZip:
		return "zip"
	case FormatEvtx:
		return "evtx"
	case FormatEvtxChunk:
		return "evtx-chunk"
	case FormatSqlite:
		return "sqlite"
	case FormatGif:
		return "gif"
	case FormatBmp:
		return "bmp"
	case FormatTiff:
		return "tiff"
	case FormatWebP:
		return "webp"
	case FormatPrefetch:
		return "pf"
	default:
		return ""
	}
}

// magic is one header, the format it names, and the offset in the format where
// it lives. At is non-zero only where the format's signature is not its first
// bytes: a raw prefetch record starts with a version word and its SCCA
// signature follows at offset 4.
type magic struct {
	format CarvedFormat
	bytes  []byte
	at     uint32
}

var magics = []magic{
	{FormatJpeg, []byte{0xFF, 0xD8, 0xFF}, 0},
	{FormatPng, []byte("\x89PNG\r\n\x1a\n"), 0},
	{FormatPdf, []byte("%PDF-"), 0},
	{FormatZip, []byte("PK\x03\x04"), 0},
	{FormatEvtx, []byte("ElfFile\x00"), 0},
	{FormatEvtxChunk, []byte("ElfChnk\x00"), 0},
	{FormatSqlite, []byte("SQLite format 3\x00"), 0},
	{FormatGif, []byte("GIF87a"), 0},
	{FormatGif, []byte("GIF89a"), 0},
	{FormatBmp, []byte("BM"), 0},
	{FormatTiff, []byte("II*\x00"), 0},
	{FormatTiff, []byte("MM\x00*"), 0},
	{FormatWebP, []byte("RIFF"), 0},
	// A raw prefetch record: version u32, then SCCA. The candidate start is the
	// version word, four bytes before the signature.
	{FormatPrefetch, []byte("SCCA"), 4},
	// A MAM container: the signature is the first bytes and its header states
	// the decoded size.
	{FormatPrefetch, []byte("MAM\x04"), 0},
}

// magicsByFirst indexes magics by their first byte, so the one-pass search only
// compares against headers that can possibly match.
var magicsByFirst [256][]int

func init() {
	for index := range magics {
		first := magics[index].bytes[0]
		magicsByFirst[first] = append(magicsByFirst[first], index)
	}
}

// CarveOptions says how far one carve pass looks and how much it may report.
type CarveOptions struct {
	MaxObjectBytes uint64
	MaxObjects     int
}

// DefaultCarveOptions returns the module's default bounds.
func DefaultCarveOptions() CarveOptions {
	return CarveOptions{
		MaxObjectBytes: DefaultMaxObjectBytes,
		MaxObjects:     DefaultMaxObjects,
	}
}

// CarvedObject is one object the carve pass found.
type CarvedObject struct {
	// Offset is the absolute offset in the source.
	Offset uint64
	// Len is the bytes from Offset to the end marker (or to the bound, when
	// Terminated is false).
	Len uint64
	// Format names the object's format.
	Format CarvedFormat
	// Terminated is true when the format's own end marker was reached. Only a
	// terminated object has a length the file itself states.
	Terminated bool
	// Detail describes what the walk saw, in words: segment or chunk counts,
	// the end marker's offset, and anything the format could not be checked for.
	Detail string
	// InsideOf is the offset of the carved object whose extent contains this
	// one, if any.
	InsideOf *uint64
}

// CarveReport is what one carve pass found.
type CarveReport struct {
	// Start is the first byte of the searched range.
	Start uint64
	// BytesScanned is the number of bytes covered by the search.
	BytesScanned uint64
	// Objects holds the carved objects, ordered by offset.
	Objects []CarvedObject
	// Rejected is the count of header hits that did not walk to a valid
	// structure.
	Rejected int
	// Unreadable is the number of bytes of the searched range the source could
	// not deliver. They were searched as zeros: a header inside them is
	// invisible, and an object that ran into them stops there.
	Unreadable uint64
	// Truncated is true when the object cap or the end of the range stopped the
	// walk.
	Truncated bool
}

// TopLevel returns the objects that start a file rather than sitting inside one.
func (r *CarveReport) TopLevel() []CarvedObject {
	out := make([]CarvedObject, 0, len(r.Objects))
	for _, object := range r.Objects {
		if object.InsideOf == nil {
			out = append(out, object)
		}
	}
	return out
}

// bounds is the end of one object, as its own structure reports it.
type bounds struct {
	End        uint64
	Terminated bool
	Detail     string
}

// Carve carves the length bytes at start in one pass over the range.
//
// A zero-length range, or one that starts past the end of the source, is a
// successful empty report: there is nothing to carve, which is not an error.
func Carve(src source.ByteSource, start, length uint64, options CarveOptions) (*CarveReport, error) {
	total := src.Len()
	begin := start
	if begin > total {
		begin = total
	}
	end := satAdd(begin, length)
	if end > total {
		end = total
	}

	hits, unreadable := findHeaders(src, begin, end)

	objects := make([]CarvedObject, 0)
	rejected := 0
	truncated := false
	for _, hit := range hits {
		if len(objects) >= options.MaxObjects {
			truncated = true
			break
		}
		limit := satAdd(hit.offset, options.MaxObjectBytes)
		if limit > end {
			limit = end
		}
		// A walk that cannot read its next byte has no structure to confirm;
		// the hit is counted as refused and the rest of the pass continues.
		walked, err := formatBounds(src, hit.format, hit.offset, limit)
		if err != nil {
			var sourceErr *source.Error
			if errors.As(err, &sourceErr) {
				walked = nil
			} else {
				return nil, err
			}
		}
		if walked == nil {
			rejected++
			continue
		}
		objects = append(objects, CarvedObject{
			Offset:     hit.offset,
			Len:        walked.End - hit.offset,
			Format:     hit.format,
			Terminated: walked.Terminated,
			Detail:     walked.Detail,
		})
	}

	markInside(objects)
	// An object that ran to the bound instead of an end marker means the pass
	// did not see the rest of that object; the report says so once.
	for index := range objects {
		if !objects[index].Terminated {
			truncated = true
			break
		}
	}

	return &CarveReport{
		Start:        begin,
		BytesScanned: end - begin,
		Objects:      objects,
		Rejected:     rejected,
		Unreadable:   unreadable,
		Truncated:    truncated,
	}, nil
}

// markInside marks objects that fall inside another carved object's extent.
//
// Only a terminated object contributes an extent: an object that never met its
// end marker has a length the scan chose, not one the file states, and using
// that guess to swallow later hits would turn a truncated file into a claim
// that the rest of the image belongs to it.
func markInside(objects []CarvedObject) {
	type openRange struct {
		offset uint64
		end    uint64
	}
	var open []openRange
	for index := range objects {
		for len(open) > 0 {
			last := open[len(open)-1]
			if last.end <= objects[index].Offset {
				open = open[:len(open)-1]
			} else {
				break
			}
		}
		if len(open) > 0 {
			container := open[len(open)-1].offset
			objects[index].InsideOf = &container
		}
		if objects[index].Terminated {
			open = append(open, openRange{
				offset: objects[index].Offset,
				end:    satAdd(objects[index].Offset, objects[index].Len),
			})
		}
	}
}

// formatBounds dispatches one candidate to its format's walk. A nil result with
// a nil error means the candidate was refused.
func formatBounds(src source.ByteSource, format CarvedFormat, start, limit uint64) (*bounds, error) {
	switch format {
	case FormatEvtx:
		return evtxFileBounds(src, start, limit)
	case FormatEvtxChunk:
		return evtxChunkBounds(src, start, limit)
	case FormatSqlite:
		return sqliteBounds(src, start, limit)
	case FormatGif:
		return gifBounds(src, start, limit)
	case FormatBmp:
		return bmpBounds(src, start, limit)
	case FormatTiff:
		return tiffBounds(src, start, limit)
	case FormatWebP:
		return webpBounds(src, start, limit)
	case FormatPrefetch:
		return prefetchBounds(src, start, limit)
	case FormatJpeg, FormatPng, FormatPdf, FormatZip:
		return nil, fmt.Errorf("%s carving is not ported: %w", format.ID(), ErrUnsupported)
	default:
		return nil, fmt.Errorf("format %d: %w", format, ErrUnsupported)
	}
}

// hit is one header found by the scan.
type hit struct {
	offset uint64
	format CarvedFormat
}

// readLossy fills buffer from at, counting the bytes the source could not
// deliver. The source's lossy mode zero-fills unreadable bytes, so the walk
// continues past a damaged region instead of failing the whole pass.
func readLossy(src source.ByteSource, at uint64, buffer []byte) uint64 {
	before := src.Stats().CorruptBytes
	_, _ = src.ReadAtLossy(at, buffer)
	after := src.Stats().CorruptBytes
	if after < before {
		return 0
	}
	return after - before
}

// findHeaders finds every header in [from, to) in one pass over the bytes,
// returning the number of bytes the source could not deliver.
func findHeaders(src source.ByteSource, from, to uint64) ([]hit, uint64) {
	// The longest magic is the SQLite header; overlapping reads by one byte
	// less than that cannot miss a header split across two chunks.
	const overlap uint64 = 15
	var unreadable uint64
	var hits []hit
	base := from
	for base < to {
		length := uint64(readChunk)
		if remaining := to - base; remaining < length {
			length = remaining
		}
		buffer := make([]byte, int(length))
		// Bytes the source cannot deliver are searched as zeros rather than
		// failing the pass: a damaged image still holds what is readable.
		unreadable += readLossy(src, base, buffer)
		for index, first := range buffer {
			for _, magicIndex := range magicsByFirst[first] {
				entry := magics[magicIndex]
				end := index + len(entry.bytes)
				if end > len(buffer) || !bytes.Equal(buffer[index:end], entry.bytes) {
					continue
				}
				// The candidate is the format's own start, which may be before
				// the signature (a prefetch version word). It is only skipped
				// when it falls before the requested range.
				position := base + uint64(index)
				if position < uint64(entry.at) {
					continue
				}
				candidate := position - uint64(entry.at)
				if candidate >= from {
					hits = append(hits, hit{offset: candidate, format: entry.format})
				}
			}
		}
		next := base + length
		if next >= to || length < uint64(readChunk) {
			break
		}
		base = next - overlap
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].offset != hits[j].offset {
			return hits[i].offset < hits[j].offset
		}
		return hits[i].format < hits[j].format
	})
	return dedupHits(hits), unreadable
}

func dedupHits(hits []hit) []hit {
	if len(hits) == 0 {
		return hits
	}
	out := hits[:1]
	for _, entry := range hits[1:] {
		if entry != out[len(out)-1] {
			out = append(out, entry)
		}
	}
	return out
}

// find searches [from, to) for needle, in chunks. It uses strict reads, as the
// Rust module does for the end-marker searches in the unported walks.
func find(src source.ByteSource, from, to uint64, needle []byte) (uint64, bool, error) {
	if len(needle) == 0 || from >= to {
		return 0, false, nil
	}
	overlap := uint64(len(needle) - 1)
	base := from
	for base < to {
		length := minU64(uint64(readChunk), to-base)
		buffer := make([]byte, int(length))
		if err := source.ReadExactAt(src, base, buffer); err != nil {
			return 0, false, err
		}
		if index := bytes.Index(buffer, needle); index >= 0 {
			return base + uint64(index), true, nil
		}
		next := base + length
		if next >= to || length < uint64(readChunk) {
			break
		}
		skip := overlap
		if skip > length {
			skip = length
		}
		base = next - skip
	}
	return 0, false, nil
}

func readU8(src source.ByteSource, at, limit uint64) (byte, bool, error) {
	if at >= limit {
		return 0, false, nil
	}
	var buffer [1]byte
	if err := source.ReadExactAt(src, at, buffer[:]); err != nil {
		return 0, false, err
	}
	return buffer[0], true, nil
}

func readU16BE(src source.ByteSource, at, limit uint64) (uint16, bool, error) {
	if satAdd(at, 2) > limit {
		return 0, false, nil
	}
	var buffer [2]byte
	if err := source.ReadExactAt(src, at, buffer[:]); err != nil {
		return 0, false, err
	}
	return uint16(buffer[0])<<8 | uint16(buffer[1]), true, nil
}

func readU32BE(src source.ByteSource, at, limit uint64) (uint32, error) {
	if satAdd(at, 4) > limit {
		return 0, source.NewUnexpectedEOF(at)
	}
	var buffer [4]byte
	if err := source.ReadExactAt(src, at, buffer[:]); err != nil {
		return 0, err
	}
	return uint32(buffer[0])<<24 | uint32(buffer[1])<<16 | uint32(buffer[2])<<8 | uint32(buffer[3]), nil
}

func readVec(src source.ByteSource, at, length uint64) ([]byte, error) {
	buffer := make([]byte, int(length))
	if err := source.ReadExactAt(src, at, buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

// crcRange is CRC32 (IEEE) over length bytes at at, read in chunks.
//
// CRC32Seeded returns the raw state with no final inversion, which is exactly
// what is needed to carry the value across chunk boundaries: the concatenated
// range hashes to the same value as one buffer would.
func crcRange(src source.ByteSource, at, length uint64) (uint32, error) {
	bufferLength := minU64(uint64(readChunk), length)
	if bufferLength == 0 {
		bufferLength = 1
	}
	buffer := make([]byte, int(bufferLength))
	done := uint64(0)
	state := uint32(0xFFFFFFFF)
	for done < length {
		take := minU64(uint64(readChunk), length-done)
		if err := source.ReadExactAt(src, at+done, buffer[:take]); err != nil {
			return 0, err
		}
		state = foundation.CRC32Seeded(state, buffer[:take])
		done += take
	}
	return ^state, nil
}

// truncatedAt is a walk that stopped at the bound instead of at an end marker,
// with how many steps it managed first.
func truncatedAt(limit uint64, seen uint32, why string) *bounds {
	detail := why
	if seen > 0 {
		detail = fmt.Sprintf("%d step(s) walked, then: %s", seen, why)
	}
	return &bounds{End: limit, Terminated: false, Detail: detail}
}

// cappedAt is a walk that stopped because a named count cap was reached. The
// cap is a limit of this scan, not a length the file states, so the detail
// names it.
func cappedAt(end, seen, cap uint64, what string) *bounds {
	return &bounds{
		End:        end,
		Terminated: false,
		Detail:     fmt.Sprintf("limit: %s cap of %d reached after %d step(s)", what, cap, seen),
	}
}

func satAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

func satSub(a, b uint64) uint64 {
	if b >= a {
		return 0
	}
	return a - b
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
