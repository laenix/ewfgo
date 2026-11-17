// Package source defines the byte-level data plane of the forensic engine.
//
// Everything above the image container reads through a ByteSource; the layer is
// read-only by design, and offset translation is explicit so any byte a parser
// reads can be traced back to the image. This package is a pure-Go port of the
// Rust data layer's source.rs contract.
package source

import (
	"errors"
	"fmt"
	"sync/atomic"
)

// ID identifies one node in the source graph.
type ID uint64

// ImageID identifies the image container that ultimately owns a byte range.
type ImageID uint64

// RangeKind is the nature of a translated byte range.
type RangeKind uint8

const (
	// RangeData is stored at the named offset in the parent.
	RangeData RangeKind = iota
	// RangeZero is an explicit zero region: zeros are the evidence, no parent
	// read is needed.
	RangeZero
	// RangeHole is unallocated space. It reads as zero but must stay
	// distinguishable from a stored zero for carving and deleted recovery.
	RangeHole
	// RangeError is a damaged region. Strict reads return an error; lossy reads
	// zero-fill and account for the bytes.
	RangeError
	// RangeDerived is computed from other parent ranges rather than stored in
	// one range (for example a RAID5 chunk rebuilt from parity). The parent is
	// the source itself and ParentOffset is its logical offset.
	RangeDerived
)

// ParentRange is a translated range in the immediate parent of a source.
type ParentRange struct {
	Parent       ID
	ParentOffset uint64
	Len          uint64
	Kind         RangeKind
}

// ImageRange is a translated range in the original image container.
type ImageRange struct {
	ImageID     ImageID
	ImageOffset uint64
	Len         uint64
	Kind        RangeKind
}

// Stats is a point-in-time snapshot of a source's counters.
type Stats struct {
	BytesRead         uint64
	Reads             uint64
	CacheHits         uint64
	CacheMisses       uint64
	DecompressedBytes uint64
	CorruptBytes      uint64
	Errors            uint64
}

// Counters is the thread-safe counter set shared by source implementations.
type Counters struct {
	bytesRead         atomic.Uint64
	reads             atomic.Uint64
	cacheHits         atomic.Uint64
	cacheMisses       atomic.Uint64
	decompressedBytes atomic.Uint64
	corruptBytes      atomic.Uint64
	errors            atomic.Uint64
}

// AddRead records one read call and the bytes it delivered.
func (c *Counters) AddRead(bytes int) {
	c.bytesRead.Add(uint64(bytes))
	c.reads.Add(1)
}

// AddCacheHit records a cache hit.
func (c *Counters) AddCacheHit() { c.cacheHits.Add(1) }

// AddCacheMiss records a cache miss.
func (c *Counters) AddCacheMiss() { c.cacheMisses.Add(1) }

// AddDecompressed records bytes produced by a decompression step.
func (c *Counters) AddDecompressed(bytes uint64) { c.decompressedBytes.Add(bytes) }

// AddCorrupt records unreadable bytes and one error.
func (c *Counters) AddCorrupt(bytes uint64) {
	c.corruptBytes.Add(bytes)
	c.errors.Add(1)
}

// AddError records one error.
func (c *Counters) AddError() { c.errors.Add(1) }

// Snapshot returns a consistent-enough copy of the counters.
func (c *Counters) Snapshot() Stats {
	return Stats{
		BytesRead:         c.bytesRead.Load(),
		Reads:             c.reads.Load(),
		CacheHits:         c.cacheHits.Load(),
		CacheMisses:       c.cacheMisses.Load(),
		DecompressedBytes: c.decompressedBytes.Load(),
		CorruptBytes:      c.corruptBytes.Load(),
		Errors:            c.errors.Load(),
	}
}

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrOutOfRange means the request starts at or beyond the end of the source.
	ErrOutOfRange = errors.New("source: out of range")
	// ErrUnexpectedEOF means the backing store ended before its declared length.
	ErrUnexpectedEOF = errors.New("source: unexpected end of source")
	// ErrCorrupt means the bytes exist but are not readable as the claimed format.
	ErrCorrupt = errors.New("source: corrupt data")
	// ErrIO means the backing store failed.
	ErrIO = errors.New("source: I/O error")
	// ErrUnsupported means the adapter recognises the feature but cannot read it.
	ErrUnsupported = errors.New("source: unsupported feature")
	// ErrDecrypt means decryption failed for the requested range.
	ErrDecrypt = errors.New("source: decryption failed")
	// ErrCancelled means the caller cancelled the operation.
	ErrCancelled = errors.New("source: cancelled")
	// ErrInvalidArgument means the request itself is malformed.
	ErrInvalidArgument = errors.New("source: invalid argument")
)

// Error is a structured read/translation failure. It carries the kind plus the
// offsets that produced it, so reports can explain the failure without parsing
// the message string.
type Error struct {
	// Kind is one of the Err* sentinels above.
	Kind error
	// Offset is the requested offset.
	Offset uint64
	// Len is the requested length.
	Len uint64
	// SourceLen is the source's logical length at the time of the request.
	SourceLen uint64
	// Reason is a human-readable detail for Corrupt/Decrypt/Unsupported.
	Reason string
	// Err is the underlying I/O error, if any.
	Err error
}

func (e *Error) Error() string {
	switch {
	case errors.Is(e.Kind, ErrOutOfRange):
		return fmt.Sprintf("read [%d, +%d) is outside source length %d", e.Offset, e.Len, e.SourceLen)
	case errors.Is(e.Kind, ErrUnexpectedEOF):
		return fmt.Sprintf("unexpected end of source at offset %d", e.Offset)
	case errors.Is(e.Kind, ErrCorrupt):
		return fmt.Sprintf("corrupt data at offset %d: %s", e.Offset, e.Reason)
	case errors.Is(e.Kind, ErrIO):
		if e.Err != nil {
			return fmt.Sprintf("I/O error at offset %d: %v", e.Offset, e.Err)
		}
		return fmt.Sprintf("I/O error at offset %d: %s", e.Offset, e.Reason)
	case errors.Is(e.Kind, ErrUnsupported):
		return fmt.Sprintf("unsupported feature: %s", e.Reason)
	case errors.Is(e.Kind, ErrDecrypt):
		return fmt.Sprintf("decryption failed at offset %d: %s", e.Offset, e.Reason)
	case errors.Is(e.Kind, ErrCancelled):
		return "operation cancelled"
	case errors.Is(e.Kind, ErrInvalidArgument):
		return fmt.Sprintf("invalid argument: %s", e.Reason)
	case e.Err != nil:
		return fmt.Sprintf("source: %v", e.Err)
	default:
		return "source error"
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

func outOfRange(offset, length, sourceLen uint64) *Error {
	return &Error{Kind: ErrOutOfRange, Offset: offset, Len: length, SourceLen: sourceLen}
}

func unexpectedEOF(offset uint64) *Error {
	return &Error{Kind: ErrUnexpectedEOF, Offset: offset}
}

func invalidArgument(reason string) *Error {
	return &Error{Kind: ErrInvalidArgument, Reason: reason}
}

// NewOutOfRange builds the structured error returned when a request starts at
// or beyond the end of a source. Adapters outside this package use it to keep
// the error taxonomy uniform.
func NewOutOfRange(offset, length, sourceLen uint64) *Error {
	return outOfRange(offset, length, sourceLen)
}

// NewUnexpectedEOF builds an unexpected-end-of-source error.
func NewUnexpectedEOF(offset uint64) *Error { return unexpectedEOF(offset) }

// NewIOError builds an I/O error that preserves the underlying cause.
func NewIOError(offset uint64, err error) *Error {
	return &Error{Kind: ErrIO, Offset: offset, Err: err}
}

// NewCorrupt builds a corrupt-data error for a specific offset.
func NewCorrupt(offset uint64, reason string) *Error {
	return &Error{Kind: ErrCorrupt, Offset: offset, Reason: reason}
}

// ByteSource is a read-only, random-access byte source.
//
// ReadAt may return a short read at end-of-source; it must return
// ErrOutOfRange when the start of the request is outside the source.
// Callers that need exactly len(buf) bytes should use ReadExactAt.
type ByteSource interface {
	SourceID() ID
	Len() uint64
	ImageID() ImageID
	SectorSize() uint32
	ReadAt(offset uint64, buf []byte) (int, error)
	ReadAtLossy(offset uint64, buf []byte) (int, error)
	ExtentsInto(offset, length uint64, out []ParentRange) ([]ParentRange, error)
	Extents(offset, length uint64) ([]ParentRange, error)
	MapToImage(offset, length uint64) ([]ImageRange, error)
	Stats() Stats
	IsEmpty() bool
}

// ReadExactAt reads exactly len(buf) bytes or fails with ErrUnexpectedEOF.
func ReadExactAt(src ByteSource, offset uint64, buf []byte) error {
	done := 0
	for done < len(buf) {
		at := offset + uint64(done)
		n, err := src.ReadAt(at, buf[done:])
		if err != nil {
			// A short tail is a normal ReadAt result, but if an implementation
			// reports the exact EOF position as out of range, surface it as the
			// exact-read contract's EOF error.
			if errors.Is(err, ErrOutOfRange) && at >= src.Len() {
				return unexpectedEOF(at)
			}
			return err
		}
		if n == 0 {
			return unexpectedEOF(at)
		}
		done += n
	}
	return nil
}

// ReadVecAt reads exactly length bytes into a new buffer.
func ReadVecAt(src ByteSource, offset, length uint64) ([]byte, error) {
	sourceLen := src.Len()
	if offset > sourceLen || length > sourceLen-offset {
		return nil, outOfRange(offset, length, sourceLen)
	}
	if length > uint64(maxInt()) {
		return nil, invalidArgument(fmt.Sprintf("length %d exceeds int", length))
	}
	buf := make([]byte, int(length))
	if err := ReadExactAt(src, offset, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func maxInt() int { return int(^uint(0) >> 1) }

// MemorySource serves an in-memory byte slice. It is the hermetic test source
// and the carrier for small decoded/decrypted regions.
type MemorySource struct {
	id         ID
	imageID    ImageID
	data       []byte
	sectorSize uint32
	counters   Counters
}

// NewMemorySource wraps data as a ByteSource.
func NewMemorySource(id ID, data []byte) *MemorySource {
	return &MemorySource{id: id, data: data, sectorSize: 512}
}

// NewMemorySourceWithImage wraps data and records the owning image.
func NewMemorySourceWithImage(id ID, imageID ImageID, data []byte) *MemorySource {
	return &MemorySource{id: id, imageID: imageID, data: data, sectorSize: 512}
}

// SourceID implements ByteSource.
func (s *MemorySource) SourceID() ID { return s.id }

// ImageID implements ByteSource.
func (s *MemorySource) ImageID() ImageID { return s.imageID }

// Len implements ByteSource.
func (s *MemorySource) Len() uint64 { return uint64(len(s.data)) }

// SectorSize implements ByteSource.
func (s *MemorySource) SectorSize() uint32 { return s.sectorSize }

// WithSectorSize overrides the sector-size hint. It returns the receiver so it
// can be chained at construction time.
func (s *MemorySource) WithSectorSize(size uint32) *MemorySource {
	s.sectorSize = size
	return s
}

// ReadAt implements ByteSource. An empty buffer always succeeds, a start at or
// past EOF is OutOfRange, and a request crossing EOF returns a short read
// without zero-filling the tail.
func (s *MemorySource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}

	sourceLen := s.Len()
	if offset >= sourceLen {
		return 0, outOfRange(offset, uint64(len(buf)), sourceLen)
	}

	n := int(minU64(sourceLen-offset, uint64(len(buf))))
	copy(buf[:n], s.data[offset:offset+uint64(n)])
	s.counters.AddRead(n)
	return n, nil
}

// ReadAtLossy implements ByteSource. An in-memory source has no damaged
// regions, so it is identical to ReadAt.
func (s *MemorySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

// ExtentsInto translates [offset, offset+length) into the immediate parent
// (itself) and appends to out. Existing entries are preserved.
func (s *MemorySource) ExtentsInto(offset, length uint64, out []ParentRange) ([]ParentRange, error) {
	sourceLen := s.Len()
	if offset > sourceLen || length > sourceLen-offset {
		return out, outOfRange(offset, length, sourceLen)
	}
	if length > 0 {
		out = append(out, ParentRange{
			Parent:       s.id,
			ParentOffset: offset,
			Len:          length,
			Kind:         RangeData,
		})
	}
	return out, nil
}

// Extents returns the complete translation for [offset, offset+length).
func (s *MemorySource) Extents(offset, length uint64) ([]ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage translates [offset, offset+length) all the way to image offsets.
func (s *MemorySource) MapToImage(offset, length uint64) ([]ImageRange, error) {
	sourceLen := s.Len()
	if offset > sourceLen || length > sourceLen-offset {
		return nil, outOfRange(offset, length, sourceLen)
	}
	if length == 0 {
		return nil, nil
	}
	return []ImageRange{{
		ImageID:     s.imageID,
		ImageOffset: offset,
		Len:         length,
		Kind:        RangeData,
	}}, nil
}

// Stats implements ByteSource.
func (s *MemorySource) Stats() Stats { return s.counters.Snapshot() }

// IsEmpty implements ByteSource.
func (s *MemorySource) IsEmpty() bool { return s.Len() == 0 }

var _ ByteSource = (*MemorySource)(nil)

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
