// Package rotated dispatches rotated-log compression behind one ByteSource.
//
// Log rotation chooses a codec per policy, so one evidence volume can carry
// auth.log.2.gz, auth.log.3.bz2 and auth.log.4.lz4 side by side. This package
// recognises which codec a member is and hands every read through, so a caller
// that wants "the logical file" does not need a branch per codec. The codec is
// chosen by magic, never by the file name: a renamed member is still the codec
// its bytes say it is.
//
// Gzip, bzip2, LZ4 and XZ are decoded by the packages next door, each of which
// verifies its own framing. Zstandard is recognised by its magic but is not
// implemented here: Open and Decode return source.ErrUnsupported naming the
// codec, and never expose the stored bytes as if they were plain data.
package rotated

import (
	"fmt"
	"math"

	"github.com/laenix/ewfgo/internal/data/containers/bzip2"
	"github.com/laenix/ewfgo/internal/data/containers/gzip"
	"github.com/laenix/ewfgo/internal/data/containers/lz4"
	"github.com/laenix/ewfgo/internal/data/containers/xz"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Compression names a rotated-log codec.
type Compression uint8

const (
	// Gzip is RFC 1952 gzip framing.
	Gzip Compression = iota
	// Bzip2 is the bzip2 stream format.
	Bzip2
	// Lz4 is the LZ4 frame format.
	Lz4
	// Xz is the XZ stream format.
	Xz
	// Zstd is the Zstandard frame format. Recognised, not implemented.
	Zstd
)

// Label returns the codec's stable, lower-case name.
func (c Compression) Label() string {
	switch c {
	case Gzip:
		return "gzip"
	case Bzip2:
		return "bzip2"
	case Lz4:
		return "lz4"
	case Xz:
		return "xz"
	case Zstd:
		return "zstd"
	default:
		return "unknown"
	}
}

// String returns the codec label.
func (c Compression) String() string { return c.Label() }

// Limits selects the decode bounds for the codec that turns out to be
// present. XZ and Zstandard are recognised but not decoded, so they have no
// limits here.
type Limits struct {
	Gzip  gzip.Limits
	Bzip2 bzip2.Limits
	Lz4   lz4.Limits
	Xz    xz.Limits
}

// DefaultLimits returns the default bounds for every supported codec.
func DefaultLimits() Limits {
	return Limits{
		Gzip:  gzip.DefaultLimits(),
		Bzip2: bzip2.DefaultLimits(),
		Lz4:   lz4.DefaultLimits(),
		Xz:    xz.DefaultLimits(),
	}
}

// Detect reports which codec the first bytes name. The bool is false when no
// supported or recognised codec matches.
func Detect(head []byte) (Compression, bool) {
	switch {
	case gzip.MatchesSignature(head):
		return Gzip, true
	case bzip2.MatchesSignature(head):
		return Bzip2, true
	case lz4.MatchesSignature(head):
		return Lz4, true
	case matchesXZ(head):
		return Xz, true
	case matchesZstd(head):
		return Zstd, true
	default:
		return 0, false
	}
}

// MatchesSignature reports whether head begins with one of the recognised
// compressed-stream magics.
func MatchesSignature(head []byte) bool {
	_, ok := Detect(head)
	return ok
}

func matchesXZ(head []byte) bool {
	return len(head) >= 6 &&
		head[0] == 0xFD && head[1] == 0x37 && head[2] == 0x7A &&
		head[3] == 0x58 && head[4] == 0x5A && head[5] == 0x00
}

func matchesZstd(head []byte) bool {
	return len(head) >= 4 &&
		head[0] == 0x28 && head[1] == 0xB5 && head[2] == 0x2F && head[3] == 0xFD
}

// Source is one rotated member decoded into memory and exposed read-only.
// It is itself a source.ByteSource, so callers read the logical file without
// knowing which codec produced it.
type Source struct {
	compression   Compression
	inner         source.ByteSource
	data          []byte
	compressedLen uint64
	gzipMeta      *gzip.Meta
}

// Open decodes parent with the codec the caller detected.
func Open(id source.ID, parent source.ByteSource, compression Compression, limits Limits) (*Source, error) {
	switch compression {
	case Gzip:
		decoded, err := gzip.Open(id, parent, limits.Gzip)
		if err != nil {
			return nil, err
		}
		meta := decoded.Meta()
		return &Source{
			compression:   Gzip,
			inner:         decoded,
			data:          decoded.Bytes(),
			compressedLen: decoded.CompressedLen(),
			gzipMeta:      &meta,
		}, nil
	case Bzip2:
		decoded, err := bzip2.Open(id, parent, limits.Bzip2)
		if err != nil {
			return nil, err
		}
		return &Source{
			compression:   Bzip2,
			inner:         decoded,
			data:          decoded.Bytes(),
			compressedLen: decoded.CompressedLen(),
		}, nil
	case Lz4:
		decoded, err := lz4.Open(id, parent, limits.Lz4)
		if err != nil {
			return nil, err
		}
		return &Source{
			compression:   Lz4,
			inner:         decoded,
			data:          decoded.Bytes(),
			compressedLen: decoded.CompressedLen(),
		}, nil
	case Xz:
		decoded, err := xz.Open(id, parent, limits.Xz)
		if err != nil {
			return nil, err
		}
		return &Source{
			compression:   Xz,
			inner:         decoded,
			data:          decoded.Bytes(),
			compressedLen: decoded.CompressedLen(),
		}, nil
	case Zstd:
		return nil, unsupported("rotated log: zstd compression is recognised but not implemented")
	default:
		return nil, &source.Error{
			Kind:   source.ErrInvalidArgument,
			Reason: fmt.Sprintf("unknown compression codec %d", compression),
		}
	}
}

// Decode detects the codec from the first bytes and decodes in one step. Bytes
// that carry no recognised signature are an unsupported-feature error, never
// raw data.
func Decode(id source.ID, parent source.ByteSource, limits Limits) (*Source, error) {
	want := parent.Len()
	if want > 8 {
		want = 8
	}
	head := make([]byte, want)
	if want > 0 {
		if err := source.ReadExactAt(parent, 0, head); err != nil {
			return nil, err
		}
	}
	compression, ok := Detect(head)
	if !ok {
		return nil, unsupported("the bytes carry no gzip, bzip2, lz4, xz, or zstd signature")
	}
	return Open(id, parent, compression, limits)
}

// Compression returns the codec this source was decoded with.
func (s *Source) Compression() Compression { return s.compression }

// Label returns the detected codec's label.
func (s *Source) Label() string { return s.compression.Label() }

// CompressedLen returns the stored bytes read from the parent.
func (s *Source) CompressedLen() uint64 { return s.compressedLen }

// OriginalName returns the producer's original file name when the codec
// records one. Only gzip records it.
func (s *Source) OriginalName() (string, bool) {
	if s.gzipMeta != nil && s.gzipMeta.Name != "" {
		return s.gzipMeta.Name, true
	}
	return "", false
}

// MTime returns the producer's modification time in Unix seconds when the
// codec records one. Only gzip records it; zero means unset.
func (s *Source) MTime() (uint32, bool) {
	if s.gzipMeta == nil {
		return 0, false
	}
	if s.gzipMeta.ModTime.IsZero() {
		return 0, true
	}
	seconds := s.gzipMeta.ModTime.Unix()
	if seconds <= 0 {
		return 0, true
	}
	if seconds > math.MaxUint32 {
		return math.MaxUint32, true
	}
	return uint32(seconds), true
}

// Bytes returns the decoded bytes.
func (s *Source) Bytes() []byte { return s.data }

// SourceID implements source.ByteSource.
func (s *Source) SourceID() source.ID { return s.inner.SourceID() }

// Len implements source.ByteSource.
func (s *Source) Len() uint64 { return s.inner.Len() }

// ImageID implements source.ByteSource.
func (s *Source) ImageID() source.ImageID { return s.inner.ImageID() }

// SectorSize implements source.ByteSource.
func (s *Source) SectorSize() uint32 { return s.inner.SectorSize() }

// ReadAt implements source.ByteSource.
func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.inner.ReadAt(offset, buf)
}

// ReadAtLossy implements source.ByteSource.
func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.inner.ReadAtLossy(offset, buf)
}

// ExtentsInto implements source.ByteSource.
func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return s.inner.ExtentsInto(offset, length, out)
}

// Extents implements source.ByteSource.
func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.inner.Extents(offset, length)
}

// MapToImage implements source.ByteSource.
func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	return s.inner.MapToImage(offset, length)
}

// Stats implements source.ByteSource.
func (s *Source) Stats() source.Stats { return s.inner.Stats() }

// IsEmpty implements source.ByteSource.
func (s *Source) IsEmpty() bool { return s.inner.IsEmpty() }

var _ source.ByteSource = (*Source)(nil)

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}
