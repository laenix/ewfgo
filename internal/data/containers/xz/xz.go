// Package xz decodes XZ streams into a logical ByteSource.
//
// logrotate and journalctl compress rotated logs with XZ as often as with
// gzip (auth.log.3.xz, system@0000.journal.xz), and the data plane treats an
// XZ file like any other rotated member. Open decodes the whole file once and
// exposes the result read-only; it is the source-level counterpart of the Rust
// engine's XzSource.
//
// The decoder implements the .xz container directly: the stream header and
// its CRC32, block headers, LZMA2 blocks (both compressed chunks and stored
// uncompressed chunks), block padding, the index, and the stream footer.
// Concatenated streams are decoded in order and stream padding (four-byte
// groups of null bytes) is skipped. The LZMA2 chunk layer and the LZMA range
// decoder are pure Go.
//
// Every checksum the format stores is verified: the header, block-header,
// index and footer CRC32 values, and each block's CRC32 check. Index records
// are compared against the blocks that were parsed, and the footer's backward
// size and flags must agree with the index and header. A truncated or corrupt
// stream, CRC mismatch, size disagreement or output-limit violation is an
// explicit error, and partial output is never exposed.
//
// Integrity checks other than None and CRC32 (CRC64 and SHA-256) and filter
// chains other than a single LZMA2 filter are recognised but refused as
// unsupported.
package xz

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// MaxDecodedBytes is the default cap on decompressed output (512 MiB).
	MaxDecodedBytes uint64 = 512 * 1024 * 1024
	// MaxCompressedBytes is the default cap on stored bytes read from the
	// parent (256 MiB).
	MaxCompressedBytes uint64 = 256 * 1024 * 1024
)

// Limits bounds one decode.
type Limits struct {
	// MaxDecodedBytes is the maximum decoded bytes. Exceeding it is an error,
	// never a truncation. Zero selects MaxDecodedBytes.
	MaxDecodedBytes uint64
	// MaxCompressedBytes is the maximum stored bytes read from the parent.
	// Zero selects MaxCompressedBytes.
	MaxCompressedBytes uint64
}

// DefaultLimits returns the default caps.
func DefaultLimits() Limits {
	return Limits{MaxDecodedBytes: MaxDecodedBytes, MaxCompressedBytes: MaxCompressedBytes}
}

// Meta records what the decode did.
type Meta struct {
	// CompressedLen is the number of bytes read from the parent.
	CompressedLen uint64
	// DecompressedLen is the decoded bytes across every stream.
	DecompressedLen uint64
	// Streams is the number of XZ streams decoded.
	Streams uint64
	// PaddingBytes is the number of null stream-padding bytes skipped.
	PaddingBytes uint64
}

// Source is a decoded XZ file.
type Source struct {
	id       source.ID
	parent   source.ByteSource
	data     []byte
	meta     Meta
	counters source.Counters
}

// MatchesSignature reports whether head begins with the XZ stream magic.
func MatchesSignature(head []byte) bool {
	return len(head) >= 6 &&
		head[0] == 0xFD && head[1] == 0x37 && head[2] == 0x7A &&
		head[3] == 0x58 && head[4] == 0x5A && head[5] == 0x00
}

// Open decodes parent as one or more concatenated XZ streams.
func Open(id source.ID, parent source.ByteSource, limits Limits) (*Source, error) {
	if limits.MaxDecodedBytes == 0 {
		limits.MaxDecodedBytes = MaxDecodedBytes
	}
	if limits.MaxCompressedBytes == 0 {
		limits.MaxCompressedBytes = MaxCompressedBytes
	}
	// Output lives in a []byte; never accept a limit the address space cannot
	// represent.
	if limits.MaxDecodedBytes > uint64(maxInt()) {
		limits.MaxDecodedBytes = uint64(maxInt())
	}

	compressedLen := parent.Len()
	if compressedLen < 32 {
		return nil, corrupt(0, "xz file is too short (%d bytes)", compressedLen)
	}
	if compressedLen > limits.MaxCompressedBytes {
		return nil, unsupported("xz compressed size %d exceeds the %d-byte limit",
			compressedLen, limits.MaxCompressedBytes)
	}

	stored, err := source.ReadVecAt(parent, 0, compressedLen)
	if err != nil {
		return nil, mapReadError(0, err)
	}
	decoded, meta, err := decodeStreams(stored, limits)
	if err != nil {
		return nil, err
	}

	result := &Source{
		id:     id,
		parent: parent,
		data:   decoded,
		meta:   meta,
	}
	result.counters.AddDecompressed(meta.DecompressedLen)
	return result, nil
}

func maxInt() int { return int(^uint(0) >> 1) }

// Meta returns the recorded decode metadata.
func (s *Source) Meta() Meta { return s.meta }

// CompressedLen returns the stored stream length.
func (s *Source) CompressedLen() uint64 { return s.meta.CompressedLen }

// Bytes returns the decoded bytes.
func (s *Source) Bytes() []byte { return s.data }

// SourceID implements source.ByteSource.
func (s *Source) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *Source) Len() uint64 { return s.meta.DecompressedLen }

// ImageID implements source.ByteSource.
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *Source) SectorSize() uint32 { return s.parent.SectorSize() }

// IsEmpty implements source.ByteSource.
func (s *Source) IsEmpty() bool { return len(s.data) == 0 }

// Stats implements source.ByteSource.
func (s *Source) Stats() source.Stats { return s.counters.Snapshot() }

// ReadAt implements source.ByteSource.
func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.Len() {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.Len())
	}
	n := copy(buf, s.data[offset:])
	s.counters.AddRead(n)
	return n, nil
}

// ReadAtLossy implements source.ByteSource.
func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

// ExtentsInto implements source.ByteSource. LZMA2 has no random-access
// checkpoints, so any decoded range maps to the whole compressed stream.
func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.Len() || length > s.Len()-offset {
		return out, source.NewOutOfRange(offset, length, s.Len())
	}
	if length > 0 {
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: 0,
			Len:          s.meta.CompressedLen,
			Kind:         source.RangeData,
		})
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.Len() || length > s.Len()-offset {
		return nil, source.NewOutOfRange(offset, length, s.Len())
	}
	if length == 0 {
		return nil, nil
	}
	return s.parent.MapToImage(0, s.meta.CompressedLen)
}

var _ source.ByteSource = (*Source)(nil)

func corrupt(offset uint64, format string, args ...any) error {
	return corruptAt(offset, format, args...)
}

func corruptAt(offset uint64, format string, args ...any) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: fmt.Sprintf(format, args...)}
}

func unsupported(format string, args ...any) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(format, args...)}
}

func mapReadError(offset uint64, err error) error {
	switch {
	case errors.Is(err, source.ErrUnexpectedEOF), errors.Is(err, source.ErrOutOfRange):
		return corrupt(offset, "xz stream is truncated at offset %d", offset)
	case errors.Is(err, source.ErrIO):
		return source.NewIOError(offset, err)
	default:
		return corrupt(offset, "xz stream: %v", err)
	}
}
