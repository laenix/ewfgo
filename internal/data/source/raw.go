package source

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ReaderAtSource adapts an io.ReaderAt to the byte-source contract. It is the
// base for raw image files and for decoded/decrypted regions that already have
// a positional reader.
//
// The backing reader must be safe for concurrent ReadAt calls; os.File is.
// There is deliberately no seek lock.
type ReaderAtSource struct {
	id         ID
	imageID    ImageID
	r          io.ReaderAt
	size       uint64
	sectorSize uint32
	closer     io.Closer
	counters   Counters
}

// NewReaderAtSource wraps r, whose logical length is size.
func NewReaderAtSource(id ID, imageID ImageID, r io.ReaderAt, size uint64) *ReaderAtSource {
	return &ReaderAtSource{id: id, imageID: imageID, r: r, size: size, sectorSize: 512}
}

// OpenRawFile opens a regular file read-only as a byte source.
func OpenRawFile(path string, id ID, imageID ImageID) (*ReaderAtSource, error) {
	return OpenRawFileWithSectorSize(path, id, imageID, 512)
}

// OpenRawFileWithSectorSize is OpenRawFile with an explicit sector-size hint.
// The size must be a power of two and at least 512.
func OpenRawFileWithSectorSize(path string, id ID, imageID ImageID, sectorSize uint32) (*ReaderAtSource, error) {
	if sectorSize < 512 || sectorSize&(sectorSize-1) != 0 {
		return nil, fmt.Errorf("invalid sector size %d: must be a power of two >= 512", sectorSize)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() < 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%s reports a negative size", path)
	}

	src := NewReaderAtSource(id, imageID, f, uint64(info.Size()))
	src.sectorSize = sectorSize
	src.closer = f
	return src, nil
}

// SourceID implements ByteSource.
func (s *ReaderAtSource) SourceID() ID { return s.id }

// ImageID implements ByteSource.
func (s *ReaderAtSource) ImageID() ImageID { return s.imageID }

// Len implements ByteSource.
func (s *ReaderAtSource) Len() uint64 { return s.size }

// SectorSize implements ByteSource.
func (s *ReaderAtSource) SectorSize() uint32 { return s.sectorSize }

// WithSectorSize overrides the sector-size hint.
func (s *ReaderAtSource) WithSectorSize(size uint32) *ReaderAtSource {
	s.sectorSize = size
	return s
}

// Close releases the backing file, if this source owns one.
func (s *ReaderAtSource) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// ReadAt implements ByteSource with strict semantics: unreadable bytes are an
// error, never a silent zero fill.
func (s *ReaderAtSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.size {
		return 0, outOfRange(offset, uint64(len(buf)), s.size)
	}

	want := int(minU64(s.size-offset, uint64(len(buf))))
	done := 0
	for done < want {
		n, err := s.r.ReadAt(buf[done:want], int64(offset+uint64(done)))
		if n < 0 || n > want-done {
			s.counters.AddError()
			return done, &Error{
				Kind:   ErrCorrupt,
				Offset: offset + uint64(done),
				Reason: "backing ReaderAt returned an invalid byte count",
			}
		}
		done += n
		if err != nil {
			if errors.Is(err, io.EOF) && done == want {
				break
			}
			s.counters.AddError()
			return done, &Error{Offset: offset + uint64(done), Err: err}
		}
		if n == 0 {
			s.counters.AddError()
			return done, unexpectedEOF(offset + uint64(done))
		}
	}

	s.counters.AddRead(done)
	return done, nil
}

// ReadAtLossy implements ByteSource's best-effort mode. Unreadable regions are
// zero-filled and counted as corrupt; carving and recovery can continue.
func (s *ReaderAtSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.size {
		return 0, outOfRange(offset, uint64(len(buf)), s.size)
	}

	want := int(minU64(s.size-offset, uint64(len(buf))))
	done := 0
	for done < want {
		n, err := s.r.ReadAt(buf[done:want], int64(offset+uint64(done)))
		valid := n
		if valid < 0 || valid > want-done {
			valid = 0
		}
		done += valid
		if err != nil || valid == 0 {
			remaining := uint64(want - done)
			clear(buf[done:want])
			if remaining > 0 {
				s.counters.AddCorrupt(remaining)
			}
			done = want
			break
		}
	}

	s.counters.AddRead(done)
	return done, nil
}

// ExtentsInto translates [offset, offset+length) into the immediate parent
// (itself) and appends to out.
func (s *ReaderAtSource) ExtentsInto(offset, length uint64, out []ParentRange) ([]ParentRange, error) {
	if offset > s.size || length > s.size-offset {
		return out, outOfRange(offset, length, s.size)
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
func (s *ReaderAtSource) Extents(offset, length uint64) ([]ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage translates [offset, offset+length) to image offsets.
func (s *ReaderAtSource) MapToImage(offset, length uint64) ([]ImageRange, error) {
	if offset > s.size || length > s.size-offset {
		return nil, outOfRange(offset, length, s.size)
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
func (s *ReaderAtSource) Stats() Stats { return s.counters.Snapshot() }

// IsEmpty implements ByteSource.
func (s *ReaderAtSource) IsEmpty() bool { return s.size == 0 }

var _ ByteSource = (*ReaderAtSource)(nil)
