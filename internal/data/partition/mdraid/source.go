package mdraid

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Source is a ByteSource over one member's data area. For a RAID1 or multipath
// member this is the filesystem image; for a striped member it is one stripe
// and the caller must consult the superblock's level.
type Source struct {
	id         source.ID
	parent     source.ByteSource
	dataOffset uint64
	length     uint64
	counters   source.Counters
}

// NewSource opens the data area the superblock describes. A declared data size
// that runs past the device is clamped; the parser already refuses such a
// superblock, so this is a defensive bound for a hand-built one.
func NewSource(id source.ID, parent source.ByteSource, sb *Superblock) (*Source, error) {
	dataOffset := sb.DataOffsetBytes()
	parentLen := parent.Len()
	if dataOffset > parentLen {
		return nil, fmt.Errorf("%w: the mdraid data area starts at byte %d, past the %d-byte member",
			ErrCorrupt, dataOffset, parentLen)
	}
	available := parentLen - dataOffset
	declared := sb.DataSizeBytes()
	length := available
	if declared != 0 && declared < available {
		length = declared
	}
	return &Source{
		id:         id,
		parent:     parent,
		dataOffset: dataOffset,
		length:     length,
	}, nil
}

// DataOffset returns the byte offset of the data area within the member.
func (s *Source) DataOffset() uint64 { return s.dataOffset }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.length }
func (s *Source) SectorSize() uint32      { return uint32(SectorBytes) }
func (s *Source) IsEmpty() bool           { return s.length == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	n, err := s.parent.ReadAt(s.dataOffset+offset, buf[:want])
	if n > 0 {
		s.counters.AddRead(n)
	}
	return n, err
}

func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	n, err := s.parent.ReadAtLossy(s.dataOffset+offset, buf[:want])
	if n > 0 {
		s.counters.AddRead(n)
	}
	return n, err
}

func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.length || length > s.length-offset {
		return out, source.NewOutOfRange(offset, length, s.length)
	}
	if length == 0 {
		return out, nil
	}
	out = append(out, source.ParentRange{
		Parent:       s.parent.SourceID(),
		ParentOffset: s.dataOffset + offset,
		Len:          length,
		Kind:         source.RangeData,
	})
	return out, nil
}

func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.length || length > s.length-offset {
		return nil, source.NewOutOfRange(offset, length, s.length)
	}
	return s.parent.MapToImage(s.dataOffset+offset, length)
}

var _ source.ByteSource = (*Source)(nil)

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
