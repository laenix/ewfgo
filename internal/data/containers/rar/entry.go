package rar

import (
	"fmt"
	"sync"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// EntrySource is one stored member exposed as a source.ByteSource.
//
// The first read reads the whole member, verifies its declared size and
// CRC-32, and caches the bytes, matching the other archive decoders. A
// mismatch is counted as corrupt bytes; the bytes themselves stay readable
// because recovering evidence matters more than proving it intact.
type EntrySource struct {
	id         source.ID
	parent     source.ByteSource
	entry      archive.Entry
	dataOffset uint64
	dataSize   uint64

	mu      sync.Mutex
	decoded bool
	cache   []byte

	counters source.Counters
}

func newEntrySource(id source.ID, parent source.ByteSource, entry archive.Entry, dataOffset, dataSize uint64) *EntrySource {
	return &EntrySource{
		id:         id,
		parent:     parent,
		entry:      entry,
		dataOffset: dataOffset,
		dataSize:   dataSize,
	}
}

// Entry returns the listed entry this source exposes.
func (s *EntrySource) Entry() archive.Entry { return s.entry }

// DataOffset returns the offset of the member's data area in the archive.
func (s *EntrySource) DataOffset() uint64 { return s.dataOffset }

// CompressedSize returns the bytes the data area occupies in the archive.
func (s *EntrySource) CompressedSize() uint64 { return s.dataSize }

func (s *EntrySource) decode() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decoded {
		s.counters.AddCacheHit()
		return s.cache, nil
	}
	s.counters.AddCacheMiss()

	bytes, err := source.ReadVecAt(s.parent, s.dataOffset, s.dataSize)
	if err != nil {
		return nil, err
	}
	corrupt := uint64(len(bytes)) != s.entry.Size
	if s.entry.CRC32 != nil && foundation.CRC32(bytes) != *s.entry.CRC32 {
		corrupt = true
	}
	if corrupt {
		s.counters.AddCorrupt(uint64(len(bytes)))
	}
	s.cache = bytes
	s.decoded = true
	return bytes, nil
}

// SourceID implements source.ByteSource.
func (s *EntrySource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *EntrySource) Len() uint64 { return s.entry.Size }

// ImageID implements source.ByteSource.
func (s *EntrySource) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *EntrySource) SectorSize() uint32 { return s.parent.SectorSize() }

// ReadAt implements source.ByteSource.
func (s *EntrySource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.entry.Size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.entry.Size)
	}

	want := uint64(len(buf))
	if want > s.entry.Size-offset {
		want = s.entry.Size - offset
	}
	data, err := s.decode()
	if err != nil {
		return 0, err
	}
	if offset > uint64(len(data)) || want > uint64(len(data))-offset {
		return 0, source.NewCorrupt(offset, fmt.Sprintf(
			"RAR member %s needs bytes [%d, %d) but its data area holds %d",
			s.entry.Path, offset, offset+want, len(data)))
	}
	copy(buf[:want], data[offset:offset+want])
	s.counters.AddRead(int(want))
	return int(want), nil
}

// ReadAtLossy implements source.ByteSource.
func (s *EntrySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.entry.Size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.entry.Size)
	}

	want := uint64(len(buf))
	if want > s.entry.Size-offset {
		want = s.entry.Size - offset
	}
	n, err := s.ReadAt(offset, buf[:int(want)])
	if err != nil {
		for index := 0; index < int(want); index++ {
			buf[index] = 0
		}
		s.counters.AddCorrupt(want)
		return int(want), nil
	}
	return n, nil
}

// ExtentsInto implements source.ByteSource.
func (s *EntrySource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.entry.Size || length > s.entry.Size-offset {
		return out, source.NewOutOfRange(offset, length, s.entry.Size)
	}
	if length == 0 {
		return out, nil
	}
	absolute, ok := checkedAdd(s.dataOffset, offset)
	if !ok {
		return out, source.NewCorrupt(offset, "the RAR member's data offset overflows")
	}
	out = append(out, source.ParentRange{
		Parent:       s.parent.SourceID(),
		ParentOffset: absolute,
		Len:          length,
		Kind:         source.RangeData,
	})
	return out, nil
}

// Extents implements source.ByteSource.
func (s *EntrySource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *EntrySource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.entry.Size || length > s.entry.Size-offset {
		return nil, source.NewOutOfRange(offset, length, s.entry.Size)
	}
	if length == 0 {
		return nil, nil
	}
	absolute, ok := checkedAdd(s.dataOffset, offset)
	if !ok {
		return nil, source.NewCorrupt(offset, "the RAR member's data offset overflows")
	}
	return s.parent.MapToImage(absolute, length)
}

// Stats implements source.ByteSource.
func (s *EntrySource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *EntrySource) IsEmpty() bool { return s.entry.Size == 0 }

var _ source.ByteSource = (*EntrySource)(nil)
