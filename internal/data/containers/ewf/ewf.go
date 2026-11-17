// Package ewf adapts the existing exact-decompression E01 reader to the
// byte-source data plane. The adapter is deliberately sector-reader shaped so
// it can wrap either the root ewf.EWFImage or an in-memory fixture without an
// import cycle.
package ewf

import (
	"io"

	"github.com/laenix/ewfgo/internal/data/source"
)

// SectorReader is the E01 decompression surface the adapter needs. The root
// ewf.EWFImage satisfies it.
type SectorReader interface {
	TotalSectors() uint64
	SectorSize() uint32
	ReadSectors(lba, count uint64) ([]byte, error)
}

// EWFSource exposes an E01 image as a ByteSource with arbitrary byte offsets.
// Reads are sector-aligned internally and copied to the caller's range, so
// filesystem parsers can request any offset without knowing the chunk geometry.
type EWFSource struct {
	id           source.ID
	imageID      source.ImageID
	reader       SectorReader
	sectorSize   uint32
	length       uint64
	totalSectors uint64
	counters     source.Counters
	closer       io.Closer
	path         string
	info         *Info
}

// NewEWFSource wraps reader. A zero sector size falls back to 512 rather than
// dividing by zero; the E01 parser itself never reports zero.
func NewEWFSource(id source.ID, imageID source.ImageID, reader SectorReader) *EWFSource {
	sectorSize := reader.SectorSize()
	if sectorSize == 0 {
		sectorSize = 512
	}
	return &EWFSource{
		id:           id,
		imageID:      imageID,
		reader:       reader,
		sectorSize:   sectorSize,
		length:       reader.TotalSectors() * uint64(sectorSize),
		totalSectors: reader.TotalSectors(),
	}
}

// Info returns the acquisition metadata when the source was opened from a file
// with OpenFile; a source built with NewEWFSource has nil metadata.
func (s *EWFSource) Info() *Info { return s.info }

// Path returns the E01 path the source was opened from, empty otherwise.
func (s *EWFSource) Path() string { return s.path }

// TotalSectors returns the media sector count.
func (s *EWFSource) TotalSectors() uint64 { return s.totalSectors }

// ReadSectors reads count whole sectors starting at lba through the exact-
// decompression path. It exists for the legacy reader-based filesystem handlers
// and is not part of the ByteSource contract.
func (s *EWFSource) ReadSectors(lba, count uint64) ([]byte, error) {
	if count == 0 {
		return []byte{}, nil
	}
	if lba >= s.totalSectors || count > s.totalSectors-lba {
		return nil, source.NewOutOfRange(lba*uint64(s.sectorSize), count*uint64(s.sectorSize), s.length)
	}
	data, err := s.reader.ReadSectors(lba, count)
	if err != nil {
		s.counters.AddError()
		return nil, source.NewIOError(lba*uint64(s.sectorSize), err)
	}
	s.counters.AddRead(len(data))
	return data, nil
}

// Close releases the underlying E01 segment files. It is a no-op for sources
// built over an in-memory or caller-owned SectorReader.
func (s *EWFSource) Close() error {
	if s.closer == nil {
		return nil
	}
	err := s.closer.Close()
	s.closer = nil
	return err
}

// SourceID implements source.ByteSource.
func (s *EWFSource) SourceID() source.ID { return s.id }

// ImageID implements source.ByteSource.
func (s *EWFSource) ImageID() source.ImageID { return s.imageID }

// Len implements source.ByteSource.
func (s *EWFSource) Len() uint64 { return s.length }

// SectorSize implements source.ByteSource.
func (s *EWFSource) SectorSize() uint32 { return s.sectorSize }

// ReadAt implements source.ByteSource. It reads the covering sectors through
// the exact-decompression path and copies the requested sub-range. A start at
// or past EOF is OutOfRange; a request crossing EOF is a short read.
func (s *EWFSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}

	want := int(minU64(s.length-offset, uint64(len(buf))))
	first := offset / uint64(s.sectorSize)
	last := (offset + uint64(want) - 1) / uint64(s.sectorSize)
	count := last - first + 1

	data, err := s.reader.ReadSectors(first, count)
	if err != nil {
		s.counters.AddError()
		return 0, source.NewIOError(offset, err)
	}

	needed := count * uint64(s.sectorSize)
	if uint64(len(data)) < needed {
		s.counters.AddError()
		return 0, source.NewUnexpectedEOF(offset + uint64(len(data)))
	}

	start := offset - first*uint64(s.sectorSize)
	copy(buf[:want], data[start:start+uint64(want)])
	s.counters.AddRead(want)
	return want, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode. A decompression
// or I/O failure zero-fills the requested range and is accounted as corrupt,
// so carving can continue; strict reads still fail loudly.
func (s *EWFSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}

	want := int(minU64(s.length-offset, uint64(len(buf))))
	n, err := s.ReadAt(offset, buf[:want])
	if err != nil {
		clear(buf[:want])
		s.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return n, nil
}

// ExtentsInto translates [offset, offset+length) into the immediate parent
// (this image) and appends to out.
func (s *EWFSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.length || length > s.length-offset {
		return out, source.NewOutOfRange(offset, length, s.length)
	}
	if length > 0 {
		out = append(out, source.ParentRange{
			Parent:       s.id,
			ParentOffset: offset,
			Len:          length,
			Kind:         source.RangeData,
		})
	}
	return out, nil
}

// Extents returns the complete translation for [offset, offset+length).
func (s *EWFSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage translates [offset, offset+length) to image offsets.
func (s *EWFSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.length || length > s.length-offset {
		return nil, source.NewOutOfRange(offset, length, s.length)
	}
	if length == 0 {
		return nil, nil
	}
	return []source.ImageRange{{
		ImageID:     s.imageID,
		ImageOffset: offset,
		Len:         length,
		Kind:        source.RangeData,
	}}, nil
}

// Stats implements source.ByteSource.
func (s *EWFSource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *EWFSource) IsEmpty() bool { return s.length == 0 }

var _ source.ByteSource = (*EWFSource)(nil)

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
