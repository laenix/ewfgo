package source

// SubSource is a contiguous window into another byte source. Partitions,
// logical volumes, and file views are all represented this way.
//
// Extents reports the shifted range against the immediate parent; MapToImage
// walks the rest of the chain to the image offset.
type SubSource struct {
	id         ID
	parent     ByteSource
	offset     uint64
	length     uint64
	sectorSize uint32
	counters   Counters
}

// NewSubSource creates a window [offset, offset+length) over parent. It
// rejects a window that is not fully inside the parent.
func NewSubSource(id ID, parent ByteSource, offset, length uint64) (*SubSource, error) {
	parentLen := parent.Len()
	if offset > parentLen || length > parentLen-offset {
		return nil, outOfRange(offset, length, parentLen)
	}
	return &SubSource{
		id:         id,
		parent:     parent,
		offset:     offset,
		length:     length,
		sectorSize: parent.SectorSize(),
	}, nil
}

// Parent returns the wrapped source.
func (s *SubSource) Parent() ByteSource { return s.parent }

// OffsetInParent returns the window's byte offset in the parent.
func (s *SubSource) OffsetInParent() uint64 { return s.offset }

// SourceID implements ByteSource.
func (s *SubSource) SourceID() ID { return s.id }

// Len implements ByteSource.
func (s *SubSource) Len() uint64 { return s.length }

// ImageID implements ByteSource.
func (s *SubSource) ImageID() ImageID { return s.parent.ImageID() }

// SectorSize implements ByteSource.
func (s *SubSource) SectorSize() uint32 { return s.sectorSize }

// ReadAt implements ByteSource.
func (s *SubSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, outOfRange(offset, uint64(len(buf)), s.length)
	}

	want := int(minU64(s.length-offset, uint64(len(buf))))
	n, err := s.parent.ReadAt(s.offset+offset, buf[:want])
	if n > 0 {
		s.counters.AddRead(n)
	}
	return n, err
}

// ReadAtLossy implements ByteSource's best-effort mode through the parent.
func (s *SubSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, outOfRange(offset, uint64(len(buf)), s.length)
	}

	want := int(minU64(s.length-offset, uint64(len(buf))))
	n, err := s.parent.ReadAtLossy(s.offset+offset, buf[:want])
	if n > 0 {
		s.counters.AddRead(n)
	}
	return n, err
}

// ExtentsInto translates [offset, offset+length) into the immediate parent.
func (s *SubSource) ExtentsInto(offset, length uint64, out []ParentRange) ([]ParentRange, error) {
	if offset > s.length || length > s.length-offset {
		return out, outOfRange(offset, length, s.length)
	}
	if length == 0 {
		return out, nil
	}
	out = append(out, ParentRange{
		Parent:       s.parent.SourceID(),
		ParentOffset: s.offset + offset,
		Len:          length,
		Kind:         RangeData,
	})
	return out, nil
}

// Extents returns the complete translation for [offset, offset+length).
func (s *SubSource) Extents(offset, length uint64) ([]ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage walks the full parent chain to image offsets.
func (s *SubSource) MapToImage(offset, length uint64) ([]ImageRange, error) {
	if offset > s.length || length > s.length-offset {
		return nil, outOfRange(offset, length, s.length)
	}
	return s.parent.MapToImage(s.offset+offset, length)
}

// Stats implements ByteSource.
func (s *SubSource) Stats() Stats { return s.counters.Snapshot() }

// IsEmpty implements ByteSource.
func (s *SubSource) IsEmpty() bool { return s.length == 0 }

var _ ByteSource = (*SubSource)(nil)
