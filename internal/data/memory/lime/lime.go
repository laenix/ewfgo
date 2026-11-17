// Package lime reads the container metadata of a LiME (Linux Memory
// Extractor) memory dump.
//
// A LiME dump is a chain of physical-memory ranges. Each range starts with a
// fixed 32-byte header and is followed by exactly the bytes between the two
// physical addresses the header names. Another header may follow the data, so
// the whole file is walked header, data, header, data until the source ends.
//
//	0x00  u32  magic, 0x4C694D45 (`EMiL` in little-endian bytes)
//	0x04  u32  version, 1
//	0x08  u64  start physical address (inclusive)
//	0x10  u64  end physical address (exclusive)
//	0x18  8 B  reserved / padding
//	0x20  ...  `end - start` bytes of memory, then the next header
//
// The reader reports the container only: version, header size, every range's
// start/end/length/file offsets, the physical span, gaps and overlaps,
// truncation and trailing bytes. It reads headers and skips payloads by
// length; it never interprets the memory itself and never invents a flat
// physical-address space. Range.OpenSource exposes each range's stored bytes
// as a bounded, read-only source window.
//
// This package is a pure-Go port of forensic-core's data/memory/lime.rs.
package lime

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Magic is the LiME magic as it appears on disk (`EMiL`).
var Magic = [4]byte{0x45, 0x4D, 0x69, 0x4C}

// MagicU32 is the magic as the unsigned value a LiME writer stores.
const MagicU32 uint32 = 0x4C69_4D45

// HeaderBytes is the fixed header length before each range's data.
const HeaderBytes uint64 = 32

// Version1 is the only header version this reader knows.
const Version1 uint32 = 1

// ReservedBytes is the reserved/padding length at the end of the header.
const ReservedBytes = 8

// Limits caps one LiME walk. The reader allocates one small record per range
// and a 32-byte header buffer; no allocation is sized by a field in the dump.
type Limits struct {
	// MaxRanges is the most ranges the chain may hold.
	MaxRanges int
	// MaxRangeBytes is the most data bytes one header may declare.
	MaxRangeBytes uint64
	// AllowTruncatedTail reports a final range cut short by the source instead
	// of refusing it with ErrRangeExtendsPastSource.
	AllowTruncatedTail bool
}

// DefaultLimits returns the reference limits.
func DefaultLimits() Limits {
	return Limits{
		MaxRanges: 4096,
		// 1 TiB is far above any real machine's addressable range and keeps
		// every derived sum inside u64.
		MaxRangeBytes:      1 << 40,
		AllowTruncatedTail: true,
	}
}

// Error kinds. Test them with errors.Is.
var (
	// ErrBadMagic means the first four bytes are not the LiME magic.
	ErrBadMagic = errors.New("memory/lime: bad magic")
	// ErrUnsupportedVersion means the header version is not 1.
	ErrUnsupportedVersion = errors.New("memory/lime: unsupported header version")
	// ErrHeaderDoesNotFit means fewer than 32 bytes remain where a header starts.
	ErrHeaderDoesNotFit = errors.New("memory/lime: header does not fit")
	// ErrBadRange means end < start, so the range length is not defined.
	ErrBadRange = errors.New("memory/lime: inverted range")
	// ErrRangeExtendsPastSource means a range's data leaves the source and
	// strict checking was requested.
	ErrRangeExtendsPastSource = errors.New("memory/lime: range extends past source")
	// ErrRangeTooLarge means one range exceeds Limits.MaxRangeBytes.
	ErrRangeTooLarge = errors.New("memory/lime: range too large")
	// ErrTooManyRanges means the chain exceeds Limits.MaxRanges.
	ErrTooManyRanges = errors.New("memory/lime: too many ranges")
	// ErrSpanOverflow means a sum of range lengths or the physical span does
	// not fit in uint64.
	ErrSpanOverflow = errors.New("memory/lime: span overflow")
	// ErrSource means the byte source failed while a header was read.
	ErrSource = errors.New("memory/lime: source error")
)

// Error is a structured LiME failure carrying the offsets that produced it.
type Error struct {
	Kind       error
	Offset     uint64
	Found      [4]byte
	Version    uint32
	Available  uint64
	Start      uint64
	End        uint64
	DataOffset uint64
	Length     uint64
	SourceLen  uint64
	Limit      uint64
	Err        error
}

func (e *Error) Error() string {
	switch {
	case errors.Is(e.Kind, ErrBadMagic):
		return fmt.Sprintf("LiME header at offset %d has magic % X, expected 45 4D 69 4C (`EMiL`)", e.Offset, e.Found)
	case errors.Is(e.Kind, ErrUnsupportedVersion):
		return fmt.Sprintf("unsupported LiME header version %d at offset %d (only version 1 is known)", e.Version, e.Offset)
	case errors.Is(e.Kind, ErrHeaderDoesNotFit):
		return fmt.Sprintf("LiME header at offset %d needs %d bytes, source has %d", e.Offset, HeaderBytes, e.Available)
	case errors.Is(e.Kind, ErrBadRange):
		return fmt.Sprintf("LiME range at offset %d has end %d before start %d", e.Offset, e.End, e.Start)
	case errors.Is(e.Kind, ErrRangeExtendsPastSource):
		return fmt.Sprintf("LiME range at offset %d declares %d data bytes at %d, past source length %d",
			e.Offset, e.Length, e.DataOffset, e.SourceLen)
	case errors.Is(e.Kind, ErrRangeTooLarge):
		return fmt.Sprintf("LiME range at offset %d declares %d bytes, over the %d-byte cap", e.Offset, e.Length, e.Limit)
	case errors.Is(e.Kind, ErrTooManyRanges):
		return fmt.Sprintf("LiME chain holds more than %d ranges", e.Limit)
	case errors.Is(e.Kind, ErrSpanOverflow):
		return "LiME ranges span more than u64::MAX bytes"
	case errors.Is(e.Kind, ErrSource):
		if e.Err != nil {
			return e.Err.Error()
		}
		return "LiME source read failed"
	default:
		if e.Err != nil {
			return e.Err.Error()
		}
		return "LiME error"
	}
}

// Unwrap exposes both the kind and the underlying cause to errors.Is/As.
func (e *Error) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.Kind != nil {
		out = append(out, e.Kind)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}

// Range is one range in the chain, with its container offsets.
type Range struct {
	// Index is the range's zero-based position in the chain.
	Index int
	// HeaderOffset is the file offset of this range's 32-byte header.
	HeaderOffset uint64
	// DataOffset is the file offset of the first data byte.
	DataOffset uint64
	// Start is the physical start address.
	Start uint64
	// End is the physical end address (exclusive).
	End uint64
	// Length is the declared data length, end - start.
	Length uint64
	// Stored is the number of data bytes actually present in the source.
	Stored uint64
	// Truncated is true when the source ends inside this range's data.
	Truncated bool
	// ReservedZero reports whether the eight reserved header bytes are zero.
	ReservedZero bool
	// GapBefore is the physical bytes between the previous end and this start.
	GapBefore uint64
	// OverlapBefore is the physical bytes this range overlaps the previous by.
	OverlapBefore uint64
	// ContiguousWithPrevious is true when this range starts exactly where the
	// previous one ended.
	ContiguousWithPrevious bool
}

// OpenSource returns a read-only window over the data bytes this range
// actually stores in the container.
//
// The window starts at Range.DataOffset and is Range.Stored bytes long. It is
// a container view, not a physical-address space: physical gaps between runs
// are not bridged and no missing bytes are zero-filled. A parent that no
// longer holds the declared bytes is refused with ErrRangeExtendsPastSource.
func (r Range) OpenSource(id source.ID, parent source.ByteSource) (*source.SubSource, error) {
	parentLen := parent.Len()
	if r.DataOffset > parentLen || r.Stored > parentLen-r.DataOffset {
		return nil, &Error{
			Kind:       ErrRangeExtendsPastSource,
			Offset:     r.HeaderOffset,
			DataOffset: r.DataOffset,
			Length:     r.Stored,
			SourceLen:  parentLen,
		}
	}
	return source.NewSubSource(id, parent, r.DataOffset, r.Stored)
}

// Report is the container metadata a LiME dump states.
type Report struct {
	// Version is the header version; all accepted headers are version 1.
	Version uint32
	// HeaderBytes is the header length before each range.
	HeaderBytes uint64
	// Ranges are in chain order.
	Ranges []Range
	// PhysicalStart is the lowest physical start address.
	PhysicalStart uint64
	// PhysicalEnd is the highest physical end address.
	PhysicalEnd uint64
	// PhysicalSpan is PhysicalEnd - PhysicalStart.
	PhysicalSpan uint64
	// DeclaredBytes is the sum of the declared range lengths.
	DeclaredBytes uint64
	// StoredBytes is the sum of the data bytes the source stores.
	StoredBytes uint64
	// Gaps is the number of adjacent pairs separated by a physical gap.
	Gaps int
	// GapBytes is the physical bytes in those gaps.
	GapBytes uint64
	// Overlaps is the number of adjacent pairs whose extents overlap.
	Overlaps int
	// OverlapBytes is the physical bytes in those overlaps.
	OverlapBytes uint64
	// Contiguous is true when every adjacent pair meets exactly.
	Contiguous bool
	// Sparse is true when at least one gap separates adjacent ranges.
	Sparse bool
	// FinalRangeTruncated is true when the last range runs past the source.
	FinalRangeTruncated bool
	// TruncatedBytes is the number of bytes missing from the final range.
	TruncatedBytes uint64
	// TrailingBytes is the bytes after the last complete range that do not
	// begin a header.
	TrailingBytes uint64
	// TrailingOffset is where those trailing bytes start, when non-nil.
	TrailingOffset *uint64
}

// RangeCount returns the number of ranges in the chain.
func (r *Report) RangeCount() int { return len(r.Ranges) }

// LayoutLabel returns a factual label for the spacing between adjacent ranges.
func (r *Report) LayoutLabel() string {
	if r.Contiguous {
		return "contiguous"
	}
	label := ""
	if r.Gaps > 0 {
		label = fmt.Sprintf("%d gap(s) of %d byte(s)", r.Gaps, r.GapBytes)
	}
	if r.Overlaps > 0 {
		if label != "" {
			label += ", "
		}
		label += fmt.Sprintf("%d overlap(s) of %d byte(s)", r.Overlaps, r.OverlapBytes)
	}
	return label
}

// LooksLike reports whether head starts with the LiME magic.
func LooksLike(head []byte) bool {
	return len(head) >= len(Magic) && [4]byte{head[0], head[1], head[2], head[3]} == Magic
}

// Read walks a LiME chain and reports its container metadata.
//
// Only fixed 32-byte headers are read. Range payloads are skipped by length,
// never read or interpreted.
func Read(src source.ByteSource, limits Limits) (*Report, error) {
	if limits.MaxRanges < 0 {
		limits.MaxRanges = 0
	}
	sourceLen := src.Len()
	if sourceLen < HeaderBytes {
		return nil, &Error{Kind: ErrHeaderDoesNotFit, Offset: 0, Available: sourceLen}
	}

	var ranges []Range
	var offset uint64
	var trailingBytes uint64
	var trailingOffset *uint64
	version := Version1

	for {
		remaining := sourceLen - offset
		if remaining < HeaderBytes {
			// A short tail after at least one complete range is not a header.
			trailingBytes = remaining
			if remaining > 0 {
				at := offset
				trailingOffset = &at
			}
			break
		}
		if len(ranges) >= limits.MaxRanges {
			return nil, &Error{Kind: ErrTooManyRanges, Limit: uint64(limits.MaxRanges)}
		}

		var header [HeaderBytes]byte
		if err := source.ReadExactAt(src, offset, header[:]); err != nil {
			return nil, &Error{Kind: ErrSource, Err: err}
		}

		found := [4]byte{header[0], header[1], header[2], header[3]}
		if found != Magic {
			if len(ranges) == 0 {
				return nil, &Error{Kind: ErrBadMagic, Offset: offset, Found: found}
			}
			// Bytes after the last complete range do not begin a header; the
			// chain has ended and the rest is a tail rather than a refusal.
			trailingBytes = sourceLen - offset
			at := offset
			trailingOffset = &at
			break
		}

		headerVersion := binary.LittleEndian.Uint32(header[4:8])
		if headerVersion != Version1 {
			return nil, &Error{Kind: ErrUnsupportedVersion, Offset: offset, Version: headerVersion}
		}
		version = headerVersion

		start := binary.LittleEndian.Uint64(header[8:16])
		end := binary.LittleEndian.Uint64(header[16:24])
		if end < start {
			return nil, &Error{Kind: ErrBadRange, Offset: offset, Start: start, End: end}
		}
		length := end - start
		if length > limits.MaxRangeBytes {
			return nil, &Error{Kind: ErrRangeTooLarge, Offset: offset, Length: length, Limit: limits.MaxRangeBytes}
		}

		dataOffset := offset + HeaderBytes
		available := sourceLen - dataOffset
		stored := length
		if stored > available {
			stored = available
		}
		truncated := stored < length
		if truncated && !limits.AllowTruncatedTail {
			return nil, &Error{
				Kind:       ErrRangeExtendsPastSource,
				Offset:     offset,
				DataOffset: dataOffset,
				Length:     length,
				SourceLen:  sourceLen,
			}
		}

		var gapBefore, overlapBefore uint64
		contiguousWithPrevious := true
		if len(ranges) > 0 {
			previous := ranges[len(ranges)-1]
			switch {
			case start > previous.End:
				gapBefore = start - previous.End
				contiguousWithPrevious = false
			case start < previous.End:
				overlapBefore = previous.End - start
				contiguousWithPrevious = false
			}
		}

		reservedZero := true
		for _, b := range header[24 : 24+ReservedBytes] {
			if b != 0 {
				reservedZero = false
				break
			}
		}

		ranges = append(ranges, Range{
			Index:                  len(ranges),
			HeaderOffset:           offset,
			DataOffset:             dataOffset,
			Start:                  start,
			End:                    end,
			Length:                 length,
			Stored:                 stored,
			Truncated:              truncated,
			ReservedZero:           reservedZero,
			GapBefore:              gapBefore,
			OverlapBefore:          overlapBefore,
			ContiguousWithPrevious: contiguousWithPrevious,
		})

		if truncated {
			// The source ends inside the declared data; there cannot be a
			// following header and no tail is left after this range.
			break
		}
		// length <= sourceLen-dataOffset here, so this cannot overflow.
		offset = dataOffset + length
	}

	declaredBytes, ok := sumU64(ranges, func(r Range) uint64 { return r.Length })
	if !ok {
		return nil, &Error{Kind: ErrSpanOverflow}
	}
	storedBytes, ok := sumU64(ranges, func(r Range) uint64 { return r.Stored })
	if !ok {
		return nil, &Error{Kind: ErrSpanOverflow}
	}
	gapBytes, ok := sumU64(ranges, func(r Range) uint64 { return r.GapBefore })
	if !ok {
		return nil, &Error{Kind: ErrSpanOverflow}
	}
	overlapBytes, ok := sumU64(ranges, func(r Range) uint64 { return r.OverlapBefore })
	if !ok {
		return nil, &Error{Kind: ErrSpanOverflow}
	}

	gaps := 0
	overlaps := 0
	for _, r := range ranges {
		if r.GapBefore > 0 {
			gaps++
		}
		if r.OverlapBefore > 0 {
			overlaps++
		}
	}

	physicalStart := ranges[0].Start
	physicalEnd := ranges[0].End
	contiguous := true
	for _, r := range ranges {
		if r.Start < physicalStart {
			physicalStart = r.Start
		}
		if r.End > physicalEnd {
			physicalEnd = r.End
		}
		if !r.ContiguousWithPrevious {
			contiguous = false
		}
	}

	final := ranges[len(ranges)-1]
	return &Report{
		Version:             version,
		HeaderBytes:         HeaderBytes,
		Ranges:              ranges,
		PhysicalStart:       physicalStart,
		PhysicalEnd:         physicalEnd,
		PhysicalSpan:        physicalEnd - physicalStart,
		DeclaredBytes:       declaredBytes,
		StoredBytes:         storedBytes,
		Gaps:                gaps,
		GapBytes:            gapBytes,
		Overlaps:            overlaps,
		OverlapBytes:        overlapBytes,
		Contiguous:          contiguous,
		Sparse:              gaps > 0,
		FinalRangeTruncated: final.Truncated,
		TruncatedBytes:      final.Length - final.Stored,
		TrailingBytes:       trailingBytes,
		TrailingOffset:      trailingOffset,
	}, nil
}

// sumU64 sums a range-length projection, refusing an overflow instead of
// wrapping or saturating.
func sumU64(ranges []Range, project func(Range) uint64) (uint64, bool) {
	var total uint64
	for _, r := range ranges {
		value := project(r)
		if value > ^uint64(0)-total {
			return 0, false
		}
		total += value
	}
	return total, true
}
