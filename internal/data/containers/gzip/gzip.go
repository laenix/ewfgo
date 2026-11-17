// Package gzip decodes gzip members into a logical ByteSource. It verifies
// the stream's CRC-32 and ISIZE through the standard decoder and bounds the
// decoded output, so a decompression bomb is an explicit refusal.
package gzip

import (
	"compress/gzip"
	"fmt"
	"io"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxDecodedBytes is the default decoded-output cap.
const MaxDecodedBytes uint64 = 512 * 1024 * 1024

// Limits bounds decoding.
type Limits struct {
	MaxDecodedBytes uint64
}

// DefaultLimits returns the default cap.
func DefaultLimits() Limits { return Limits{MaxDecodedBytes: MaxDecodedBytes} }

// Meta is the first member's header metadata.
type Meta struct {
	Name    string
	Comment string
	Extra   []byte
	ModTime time.Time
	OS      byte
}

// Source is a decoded gzip stream.
type Source struct {
	id            source.ID
	parent        source.ByteSource
	data          []byte
	compressedLen uint64
	meta          Meta
	counters      source.Counters
}

// MatchesSignature reports whether head begins with the gzip magic.
func MatchesSignature(head []byte) bool {
	return len(head) >= 2 && head[0] == 0x1F && head[1] == 0x8B
}

// Open decodes parent as one or more concatenated gzip members.
func Open(id source.ID, parent source.ByteSource, limits Limits) (*Source, error) {
	if limits.MaxDecodedBytes == 0 {
		limits.MaxDecodedBytes = MaxDecodedBytes
	}
	if parent.Len() == 0 {
		return nil, corrupt(0, "gzip stream is empty")
	}
	section := io.NewSectionReader(source.ReaderAt(parent), 0, int64(parent.Len()))
	reader, err := gzip.NewReader(section)
	if err != nil {
		return nil, corrupt(0, fmt.Sprintf("not a gzip stream: %v", err))
	}
	meta := Meta{
		Name: reader.Name, Comment: reader.Comment, ModTime: reader.ModTime,
		OS: reader.OS,
	}
	if len(reader.Extra) > 0 {
		meta.Extra = append([]byte(nil), reader.Extra...)
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limits.MaxDecodedBytes)+1))
	closeErr := reader.Close()
	if err != nil {
		return nil, corrupt(0, fmt.Sprintf("gzip stream does not decode: %v", err))
	}
	if closeErr != nil {
		return nil, corrupt(0, fmt.Sprintf("gzip stream does not decode: %v", closeErr))
	}
	if uint64(len(decoded)) > limits.MaxDecodedBytes {
		return nil, unsupported(fmt.Sprintf("decoded gzip output exceeds the %d-byte limit", limits.MaxDecodedBytes))
	}
	return &Source{id: id, parent: parent, data: decoded, compressedLen: parent.Len(), meta: meta}, nil
}

// Meta returns the first member's metadata.
func (s *Source) Meta() Meta { return s.meta }

// CompressedLen returns the stored stream length.
func (s *Source) CompressedLen() uint64 { return s.compressedLen }

// Bytes returns the decoded bytes.
func (s *Source) Bytes() []byte { return s.data }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return uint64(len(s.data)) }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *Source) SectorSize() uint32      { return 512 }
func (s *Source) IsEmpty() bool           { return len(s.data) == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= uint64(len(s.data)) {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), uint64(len(s.data)))
	}
	n := copy(buf, s.data[offset:])
	s.counters.AddRead(n)
	return n, nil
}

func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > uint64(len(s.data)) || length > uint64(len(s.data))-offset {
		return out, source.NewOutOfRange(offset, length, uint64(len(s.data)))
	}
	if length > 0 {
		out = append(out, source.ParentRange{
			Parent: s.id, ParentOffset: 0, Len: length, Kind: source.RangeDerived,
		})
	}
	return out, nil
}

func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > uint64(len(s.data)) || length > uint64(len(s.data))-offset {
		return nil, source.NewOutOfRange(offset, length, uint64(len(s.data)))
	}
	if length == 0 {
		return nil, nil
	}
	return []source.ImageRange{{
		ImageID: s.parent.ImageID(), ImageOffset: 0, Len: length, Kind: source.RangeDerived,
	}}, nil
}

var _ source.ByteSource = (*Source)(nil)

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}
