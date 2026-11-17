// Package bzip2 decodes bzip2 streams into a logical ByteSource. The standard
// library decoder verifies the stream CRC; decoded output is bounded.
package bzip2

import (
	"compress/bzip2"
	"fmt"
	"io"

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

// Source is a decoded bzip2 stream.
type Source struct {
	id            source.ID
	parent        source.ByteSource
	data          []byte
	compressedLen uint64
	counters      source.Counters
}

// MatchesSignature reports whether head begins with `BZh` plus a block-size
// digit 1..9.
func MatchesSignature(head []byte) bool {
	return len(head) >= 4 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h' &&
		head[3] >= '1' && head[3] <= '9'
}

// Open decodes parent as one bzip2 stream.
func Open(id source.ID, parent source.ByteSource, limits Limits) (*Source, error) {
	if limits.MaxDecodedBytes == 0 {
		limits.MaxDecodedBytes = MaxDecodedBytes
	}
	if parent.Len() == 0 {
		return nil, corrupt(0, "bzip2 stream is empty")
	}
	section := io.NewSectionReader(source.ReaderAt(parent), 0, int64(parent.Len()))
	reader := bzip2.NewReader(section)
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limits.MaxDecodedBytes)+1))
	if err != nil {
		return nil, corrupt(0, fmt.Sprintf("bzip2 stream does not decode: %v", err))
	}
	if uint64(len(decoded)) > limits.MaxDecodedBytes {
		return nil, unsupported(fmt.Sprintf("decoded bzip2 output exceeds the %d-byte limit", limits.MaxDecodedBytes))
	}
	return &Source{id: id, parent: parent, data: decoded, compressedLen: parent.Len()}, nil
}

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
