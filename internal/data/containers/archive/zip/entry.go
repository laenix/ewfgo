package zip

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// EntrySource is one ZIP entry exposed as a ByteSource.
//
// Listing never decompresses.  The first read decodes the whole entry,
// verifies its declared size and CRC-32, and caches the bytes so random access
// stays cheap.  A decoded entry maps back to the compressed range it came
// from: stored entries map linearly, compressed entries map to the whole
// compressed extent because no checkpoint index exists.
type EntrySource struct {
	id             source.ID
	parent         source.ByteSource
	entry          archive.Entry
	dataOffset     uint64
	compressedSize uint64
	method         uint16
	expectedCRC    uint32
	checkCRC       bool

	mu        sync.Mutex
	decoded   bool
	cache     []byte
	crcResult *bool
	counters  source.Counters
}

func newEntrySource(id source.ID, parent source.ByteSource, entry archive.Entry, dataOffset, compressedSize uint64, method uint16) *EntrySource {
	expected := uint32(0)
	if entry.CRC32 != nil {
		expected = *entry.CRC32
	}
	return &EntrySource{
		id:             id,
		parent:         parent,
		entry:          entry,
		dataOffset:     dataOffset,
		compressedSize: compressedSize,
		method:         method,
		expectedCRC:    expected,
		checkCRC:       true,
	}
}

// Entry returns the listed entry this source exposes.
func (s *EntrySource) Entry() archive.Entry { return s.entry }

// DataOffset returns the offset of the entry's payload in the parent.
func (s *EntrySource) DataOffset() uint64 { return s.dataOffset }

// CompressedSize returns the compressed payload length.
func (s *EntrySource) CompressedSize() uint64 { return s.compressedSize }

// Method returns the compression method that produced the payload.
func (s *EntrySource) Method() uint16 { return s.method }

// CRC32Result reports the CRC comparison once the entry has been decoded.
// A nil result means the entry has not been read yet.
func (s *EntrySource) CRC32Result() *bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.crcResult
}

func (s *EntrySource) decode() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decoded {
		s.counters.AddCacheHit()
		return s.cache, nil
	}
	s.counters.AddCacheMiss()

	declared := s.entry.Size
	var decoded []byte
	corrupt := false

	switch s.method {
	case methodStored:
		payload, err := source.ReadVecAt(s.parent, s.dataOffset, s.compressedSize)
		if err != nil {
			return nil, err
		}
		decoded = payload

	case methodDeflated:
		compressed, err := source.ReadVecAt(s.parent, s.dataOffset, s.compressedSize)
		if err != nil {
			return nil, err
		}
		limit := declared
		if limit < math.MaxUint64 {
			limit++
		}
		if limit > math.MaxInt64 {
			return nil, source.NewCorrupt(s.dataOffset, "the declared size is too large to decode")
		}
		reader := flate.NewReader(bytes.NewReader(compressed))
		defer reader.Close()
		// Read at most one byte past the declared size: enough to detect a
		// lying header without letting a decompression bomb grow the buffer.
		decoded, err = io.ReadAll(io.LimitReader(reader, int64(limit)))
		if err != nil {
			return nil, source.NewCorrupt(s.dataOffset, fmt.Sprintf("deflate stream: %v", err))
		}
		s.counters.AddDecompressed(uint64(len(decoded)))

	default:
		return nil, source.NewCorrupt(s.dataOffset, fmt.Sprintf("compression method %d", s.method))
	}

	if s.method == methodStored && s.compressedSize != declared {
		corrupt = true
	}
	if uint64(len(decoded)) != declared {
		corrupt = true
		if uint64(len(decoded)) > declared {
			decoded = decoded[:declared]
		}
	}
	if s.checkCRC {
		ok := foundation.CRC32(decoded) == s.expectedCRC
		s.crcResult = &ok
		if !ok {
			corrupt = true
		}
	}
	if corrupt {
		s.counters.AddCorrupt(uint64(len(decoded)))
	}

	s.cache = decoded
	s.decoded = true
	return decoded, nil
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
	decoded, err := s.decode()
	if err != nil {
		return 0, err
	}
	if offset >= uint64(len(decoded)) {
		return 0, source.NewCorrupt(offset, fmt.Sprintf(
			"entry %s decoded %d bytes but declares %d", s.entry.Path, len(decoded), s.entry.Size))
	}
	n := want
	if n > uint64(len(decoded))-offset {
		n = uint64(len(decoded)) - offset
	}
	copy(buf[:n], decoded[offset:offset+n])
	s.counters.AddRead(int(n))
	return int(n), nil
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
	n, err := s.ReadAt(offset, buf[:want])
	if err != nil {
		for i := range buf[:want] {
			buf[i] = 0
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

	// A stored entry is a 1:1 byte stream, so an offset into the plaintext is
	// the same offset into the stored payload.  A compressed entry maps as a
	// whole to the payload it was decoded from.
	if s.method == methodStored {
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: s.dataOffset + offset,
			Len:          length,
			Kind:         source.RangeData,
		})
	} else {
		kind := source.RangeData
		if s.compressedSize == 0 && s.entry.Size > 0 {
			kind = source.RangeError
		}
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: s.dataOffset,
			Len:          s.compressedSize,
			Kind:         kind,
		})
	}
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
	if s.method == methodStored {
		return s.parent.MapToImage(s.dataOffset+offset, length)
	}
	if s.compressedSize == 0 {
		return []source.ImageRange{{
			ImageID:     s.parent.ImageID(),
			ImageOffset: 0,
			Len:         length,
			Kind:        source.RangeError,
		}}, nil
	}
	return s.parent.MapToImage(s.dataOffset, s.compressedSize)
}

// Stats implements source.ByteSource.
func (s *EntrySource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *EntrySource) IsEmpty() bool { return s.entry.Size == 0 }

var _ source.ByteSource = (*EntrySource)(nil)
