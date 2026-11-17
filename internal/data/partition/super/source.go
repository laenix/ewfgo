package super

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// PartitionSource is a logical partition read through the super image's
// extents. Zero spans read as zeroes; linear spans are read from the parent
// image without zero-filling a short read.
type PartitionSource struct {
	id       source.ID
	image    *Image
	index    int
	length   uint64
	spans    []Span
	counters source.Counters
}

// Index returns the partition's position in the super image's table.
func (s *PartitionSource) Index() int { return s.index }

// Name returns the logical partition name.
func (s *PartitionSource) Name() string { return s.image.partitions[s.index].Name }

// Image returns the super image the partition is read through.
func (s *PartitionSource) Image() *Image { return s.image }

func (s *PartitionSource) bounds(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

func (s *PartitionSource) readInto(offset uint64, buf []byte) (int, error) {
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	end := offset + uint64(want)
	done := 0
	for _, span := range s.spans {
		spanEnd := span.Logical + span.Len
		if spanEnd <= offset || span.Logical >= end {
			continue
		}
		start := span.Logical
		if start < offset {
			start = offset
		}
		stop := spanEnd
		if stop > end {
			stop = end
		}
		at := int(start - offset)
		length := int(stop - start)
		switch span.Target.Kind {
		case SpanLinear:
			physical := span.Target.ParentOffset + (start - span.Logical)
			// A short parent read stays short; a missing byte is not evidence
			// and is never replaced with zeroes.
			n, err := s.image.parent.ReadAt(physical, buf[at:at+length])
			if n > 0 && at+n > done {
				done = at + n
			}
			if err != nil {
				return done, err
			}
			if n < length {
				return done, nil
			}
		case SpanZero:
			clear(buf[at : at+length])
			if at+length > done {
				done = at + length
			}
		}
	}
	return done, nil
}

// SourceID implements source.ByteSource.
func (s *PartitionSource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *PartitionSource) Len() uint64 { return s.length }

// ImageID implements source.ByteSource.
func (s *PartitionSource) ImageID() source.ImageID { return s.image.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *PartitionSource) SectorSize() uint32 { return LPSectorBytes }

// ReadAt implements source.ByteSource.
func (s *PartitionSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	read, err := s.readInto(offset, buf)
	if err != nil {
		return 0, err
	}
	s.counters.AddRead(read)
	return read, nil
}

// ReadAtLossy implements source.ByteSource. A super image has no damaged
// regions of its own, so it is identical to ReadAt.
func (s *PartitionSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

// ExtentsInto implements source.ByteSource.
func (s *PartitionSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	for _, span := range s.spans {
		spanEnd := span.Logical + span.Len
		if spanEnd <= offset || span.Logical >= end {
			continue
		}
		start := span.Logical
		if start < offset {
			start = offset
		}
		stop := spanEnd
		if stop > end {
			stop = end
		}
		switch span.Target.Kind {
		case SpanLinear:
			out = append(out, source.ParentRange{
				Parent:       s.image.parent.SourceID(),
				ParentOffset: span.Target.ParentOffset + (start - span.Logical),
				Len:          stop - start,
				Kind:         source.RangeData,
			})
		case SpanZero:
			out = append(out, source.ParentRange{
				Parent:       s.id,
				ParentOffset: start,
				Len:          stop - start,
				Kind:         source.RangeHole,
			})
		}
	}
	return out, nil
}

// Extents returns the complete translation for [offset, offset+length).
func (s *PartitionSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *PartitionSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	end := offset + length
	var out []source.ImageRange
	for _, span := range s.spans {
		spanEnd := span.Logical + span.Len
		if spanEnd <= offset || span.Logical >= end {
			continue
		}
		start := span.Logical
		if start < offset {
			start = offset
		}
		stop := spanEnd
		if stop > end {
			stop = end
		}
		switch span.Target.Kind {
		case SpanLinear:
			physical := span.Target.ParentOffset + (start - span.Logical)
			mapped, err := s.image.parent.MapToImage(physical, stop-start)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
		case SpanZero:
			out = append(out, source.ImageRange{
				ImageID:     s.image.parent.ImageID(),
				ImageOffset: 0,
				Len:         stop - start,
				Kind:        source.RangeHole,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (s *PartitionSource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *PartitionSource) IsEmpty() bool { return s.length == 0 }

var _ source.ByteSource = (*PartitionSource)(nil)

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
