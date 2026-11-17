// Windows Prefetch (.pf) carving.
//
// A prefetch record is either an 84-byte SCCA header followed by its file
// information and sections, or a MAM\x04 container whose 8-byte header declares
// the decoded size and whose body is an Xpress Huffman stream that expands to
// exactly that record. Windows 8 and later store the container; deleting the
// file leaves whichever form was on disk.
//
// A signature alone proves nothing: SCCA is four ordinary bytes. A candidate is
// kept only when the version is one this reader knows, the file-information
// layout matches that version, the executable field is a terminated printable
// UTF-16LE string, every section span fits inside the declared record, and the
// declared size is within the 32 MiB a prefetch record can be. For a MAM\x04
// container the decoded length has to equal both the container's size and the
// SCCA header's own file-size field.
//
// A candidate that fails any of that is counted by the carve pass as rejected
// under this format's name; it is never emitted as a prefetch object. A record
// whose bytes exist but whose declared extent runs past the scan bound is kept
// as a truncated object, not as a complete file.

package carving

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode"

	"github.com/laenix/ewfgo/internal/data/source"
)

var (
	prefetchSignature    = []byte("SCCA")
	prefetchMAMSignature = []byte("MAM\x04")
)

// Container header: signature and the decoded size.
const prefetchMAMHeaderLen uint64 = 8

// The fixed header and where the file-information block begins.
const (
	prefetchHeaderLen        = 84
	prefetchExecutableOffset = 16
	prefetchExecutableBytes  = 60
	prefetchFileInfoOffset   = prefetchHeaderLen
)

// A prefetch record is at most 32 MiB by the format's own bound. A header
// claiming more is refused rather than allowed to swallow the image.
const prefetchMaxFileBytes uint64 = 32 * 1024 * 1024

// The smallest record any layout can be: the XP file information begins at 84
// and its metrics array at 152.
const prefetchMinFileBytes uint64 = 152

// Xpress Huffman codes are at most 15 bits, so a literal-only stream cannot
// exceed twice its output; the table of each 64 KiB block and the read-ahead fit
// in the fixed allowance.
const prefetchCompressedAllowance uint64 = 64 * 1024

// The packed Huffman code-length table that opens every Xpress Huffman block.
const prefetchLZXPressTableBytes uint64 = 256

// prefetchRecordInfo is what a valid record proved, used only for the carved
// object's detail.
type prefetchRecordInfo struct {
	version    uint32
	layout     string
	executable string
	runCount   uint32
}

// prefetchBounds bounds a candidate that starts at start, where the first magic
// byte was seen at start (MAM) or start+4 (the SCCA inside a raw record).
func prefetchBounds(src source.ByteSource, start, limit uint64) (*bounds, error) {
	available := satSub(limit, start)
	if available < 8 {
		return nil, nil
	}
	head, err := readVec(src, start, 8)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(head[0:4], prefetchMAMSignature) {
		return prefetchMAMBounds(src, start, limit, head)
	}
	if available < 16 {
		return nil, nil
	}
	head, err = readVec(src, start, 16)
	if err != nil {
		return nil, err
	}
	return prefetchRawBounds(src, start, limit, head)
}

// prefetchRawBounds bounds a raw (uncompressed) record: the declared file size
// is the extent.
func prefetchRawBounds(src source.ByteSource, start, limit uint64, head []byte) (*bounds, error) {
	if !bytes.Equal(head[4:8], prefetchSignature) {
		return nil, nil
	}
	version := binary.LittleEndian.Uint32(head[0:4])
	if !prefetchSupported(version) {
		return nil, nil
	}
	declared := uint64(binary.LittleEndian.Uint32(head[12:16]))
	if declared < prefetchMinFileBytes || declared > prefetchMaxFileBytes {
		return nil, nil
	}
	available := satSub(limit, start)
	if declared > available {
		// The start of the record is real, but its declared extent is past what
		// the scan may cover. Keep it as truncated only when the header that is
		// present still validates.
		prefixBytes := minU64(available, uint64(prefetchFileInfoOffset+8))
		prefix, err := readVec(src, start, prefixBytes)
		if err != nil {
			return nil, err
		}
		if prefetchHeaderSane(prefix, version) {
			return truncatedAt(limit, 0, fmt.Sprintf(
				"an SCCA header declares %d bytes but the scan ends at +%d",
				declared, available,
			)), nil
		}
		return nil, nil
	}
	body, err := readVec(src, start, declared)
	if err != nil {
		return nil, err
	}
	info, ok := prefetchValidateBody(body, declared)
	if !ok {
		return nil, nil
	}
	return &bounds{
		End:        start + declared,
		Terminated: true,
		Detail: fmt.Sprintf(
			"raw SCCA record, version %d, %s layout, %d bytes, %d run(s), executable %s",
			info.version, info.layout, declared, info.runCount, info.executable,
		),
	}, nil
}

// prefetchMAMBounds bounds a MAM container: decode the stream, validate the
// record it holds, and end the object where the compressed stream ends.
func prefetchMAMBounds(src source.ByteSource, start, limit uint64, head []byte) (*bounds, error) {
	declared := uint64(binary.LittleEndian.Uint32(head[4:8]))
	if declared < prefetchMinFileBytes || declared > prefetchMaxFileBytes {
		return nil, nil
	}
	available := satSub(satSub(limit, start), prefetchMAMHeaderLen)
	// Every Xpress Huffman block starts with a 256-byte packed code-length
	// table. Refuse a stream too short to hold one, and refuse an all-zero table
	// without reading the rest of the declared extent: that is the cheap shape
	// of both a damaged record and a repeated-magic false hit.
	if available < prefetchLZXPressTableBytes {
		return nil, nil
	}
	table, err := readVec(src, satAdd(start, prefetchMAMHeaderLen), prefetchLZXPressTableBytes)
	if err != nil {
		return nil, err
	}
	if allZero(table) {
		return nil, nil
	}
	allowance := satAdd(declared*2, prefetchCompressedAllowance)
	take := minU64(available, allowance)
	inputOffset := satAdd(start, prefetchMAMHeaderLen)
	input, err := readVec(src, inputOffset, take)
	if err != nil {
		return nil, err
	}
	decoded, consumed, err := lzxpressDecompressWithConsumed(input, int(declared))
	if err != nil {
		// A stream that is truncated, corrupt, or that names a size it does not
		// produce is refused and counted; no object is invented from it.
		return nil, nil
	}
	if uint64(len(decoded)) != declared {
		return nil, nil
	}
	consumed = minU64(consumed, take)
	if consumed == 0 {
		return nil, nil
	}
	info, ok := prefetchValidateBody(decoded, declared)
	if !ok {
		return nil, nil
	}
	return &bounds{
		End:        satAdd(inputOffset, consumed),
		Terminated: true,
		Detail: fmt.Sprintf(
			"MAM container, %d bytes expand to %d, version %d, %s layout, %d run(s), executable %s",
			consumed, declared, info.version, info.layout, info.runCount, info.executable,
		),
	}, nil
}

// prefetchSupported reports the versions the prefetch reader knows.
func prefetchSupported(version uint32) bool {
	switch version {
	case 17, 23, 26, 30, 31:
		return true
	default:
		return false
	}
}

// prefetchLayoutFor is the layout a version and metrics offset name, mirroring
// the reader. It returns the label, the metrics start, the metric entry size and
// the volume entry size.
func prefetchLayoutFor(version, metricsOffset uint32) (label string, metricsStart, metricBytes, volumeBytes int, ok bool) {
	var expected uint32
	switch version {
	case 17:
		label, expected, metricBytes, volumeBytes = "17", 152, 20, 40
	case 23:
		label, expected, metricBytes, volumeBytes = "23", 240, 32, 104
	case 26:
		label, expected, metricBytes, volumeBytes = "26", 304, 32, 104
	case 30:
		if metricsOffset == 296 {
			label, expected, metricBytes, volumeBytes = "30/31", 296, 32, 96
		} else {
			label, expected, metricBytes, volumeBytes = "30", 304, 32, 104
		}
	case 31:
		label, expected, metricBytes, volumeBytes = "30/31", 296, 32, 96
	default:
		return "", 0, 0, 0, false
	}
	if metricsOffset != expected {
		return "", 0, 0, 0, false
	}
	return label, int(expected), metricBytes, volumeBytes, true
}

// prefetchValidateBody validates a whole record. declared is the size the
// container promised; the record's own size field and its length must both
// equal it.
func prefetchValidateBody(body []byte, declared uint64) (prefetchRecordInfo, bool) {
	var empty prefetchRecordInfo
	if uint64(len(body)) != declared || len(body) < prefetchHeaderLen {
		return empty, false
	}
	if !bytes.Equal(body[4:8], prefetchSignature) {
		return empty, false
	}
	version, ok := prefetchU32At(body, 0)
	if !ok || !prefetchSupported(version) {
		return empty, false
	}
	sizeAt, ok := prefetchU32At(body, 12)
	if !ok || uint64(sizeAt) != declared {
		return empty, false
	}
	executable, ok := prefetchExecutableName(body)
	if !ok {
		return empty, false
	}
	metricsOffset, ok := prefetchU32At(body, prefetchFileInfoOffset)
	if !ok {
		return empty, false
	}
	layout, metricsStart, metricBytes, volumeBytes, ok := prefetchLayoutFor(version, metricsOffset)
	if !ok || metricsStart > len(body) {
		return empty, false
	}
	fi := prefetchFileInfoOffset
	metricsCount, ok := prefetchU32At(body, fi+4)
	if !ok {
		return empty, false
	}
	stringsOffset, ok := prefetchU32At(body, fi+16)
	if !ok {
		return empty, false
	}
	stringsSize, ok := prefetchU32At(body, fi+20)
	if !ok {
		return empty, false
	}
	volumesOffset, ok := prefetchU32At(body, fi+24)
	if !ok {
		return empty, false
	}
	volumesCount, ok := prefetchU32At(body, fi+28)
	if !ok {
		return empty, false
	}
	volumesSize, ok := prefetchU32At(body, fi+32)
	if !ok {
		return empty, false
	}
	runCount, ok := prefetchU32At(body, fi+prefetchRunCountOffset(version, metricsOffset))
	if !ok {
		return empty, false
	}

	if !prefetchSpanFits(body, metricsOffset, metricsCount, metricBytes) {
		return empty, false
	}
	if !prefetchSpanFits(body, volumesOffset, volumesCount, volumeBytes) {
		return empty, false
	}
	if uint64(volumesOffset)+uint64(volumesSize) > uint64(len(body)) {
		return empty, false
	}
	if uint64(stringsOffset)+uint64(stringsSize) > uint64(len(body)) {
		return empty, false
	}
	return prefetchRecordInfo{
		version:    version,
		layout:     layout,
		executable: executable,
		runCount:   runCount,
	}, true
}

func prefetchRunCountOffset(version, metricsOffset uint32) int {
	switch version {
	case 17:
		return 60
	case 23:
		return 68
	case 30:
		// The version 30 compact layout is identified by its metrics pointer.
		if metricsOffset == 296 {
			return 116
		}
		return 124
	case 26:
		return 124
	case 31:
		return 116
	default:
		return 124
	}
}

// prefetchHeaderSane is the steps of the header a truncated record still has to
// pass.
func prefetchHeaderSane(prefix []byte, version uint32) bool {
	if len(prefix) < prefetchHeaderLen || !bytes.Equal(prefix[4:8], prefetchSignature) {
		return false
	}
	if !prefetchSupported(version) {
		return false
	}
	if _, ok := prefetchExecutableName(prefix); !ok {
		return false
	}
	metrics, ok := prefetchU32At(prefix, prefetchFileInfoOffset)
	if !ok {
		return false
	}
	_, _, _, _, ok = prefetchLayoutFor(version, metrics)
	return ok
}

// prefetchExecutableName decodes the 60-byte executable field: a terminated,
// non-empty UTF-16LE string with no control characters, NUL-padded to the end of
// the field.
func prefetchExecutableName(body []byte) (string, bool) {
	if len(body) < prefetchExecutableOffset+prefetchExecutableBytes {
		return "", false
	}
	field := body[prefetchExecutableOffset : prefetchExecutableOffset+prefetchExecutableBytes]
	var units []rune
	terminated := false
	for offset := 0; offset+2 <= len(field); offset += 2 {
		unit := binary.LittleEndian.Uint16(field[offset : offset+2])
		if unit == 0 {
			terminated = true
			continue
		}
		if terminated {
			// A NUL in the middle followed by text is not a NUL-padded field.
			return "", false
		}
		// char::from_u32 rejects surrogate code points; Go's rune conversion
		// would silently accept them.
		if unit >= 0xD800 && unit <= 0xDFFF {
			return "", false
		}
		character := rune(unit)
		if unicode.IsControl(character) {
			return "", false
		}
		units = append(units, character)
	}
	if !terminated || len(units) == 0 {
		return "", false
	}
	return string(units), true
}

func prefetchSpanFits(body []byte, offset, count uint32, entryBytes int) bool {
	end := uint64(offset) + uint64(count)*uint64(entryBytes)
	return end <= uint64(len(body))
}

func prefetchU32At(body []byte, at int) (uint32, bool) {
	if at < 0 || at+4 > len(body) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(body[at : at+4]), true
}
