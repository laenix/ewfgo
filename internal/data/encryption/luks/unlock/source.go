package unlock

// Source is a LUKS volume's decrypted payload as a source.ByteSource.
//
// dm-crypt numbers each data unit from the segment's own iv_tweak, and LUKS2's
// segments concatenate into one logical payload: the first starts at logical
// zero, the next where it ends. A read is split at segment boundaries and
// each piece is widened to its segment's encryption sector, decrypted with
// that segment's numbering, and copied back out.
//
// A parent range the source cannot supply is an error, never a synthesized
// zero. The extents this source reports point at the encrypted image bytes,
// one parent range per segment, which is what a report needs to cite them.

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

type segmentReader struct {
	plan   segmentPlan
	cipher *sectorCipher
}

// Source is the decrypted payload of an opened LUKS volume.
type Source struct {
	id            source.ID
	parent        source.ByteSource
	segments      []segmentReader
	payloadOffset uint64
	ivTweak       uint64
	length        uint64
	sectorSize    uint32
	counters      source.Counters
}

var _ source.ByteSource = (*Source)(nil)

func newSource(id source.ID, parent source.ByteSource, plans []segmentPlan, masterKey []byte) (*Source, error) {
	if parent == nil {
		return nil, fmt.Errorf("%w: nil parent source", ErrSource)
	}
	if len(plans) == 0 {
		return nil, fmt.Errorf("%w: no payload segments", ErrGeometry)
	}
	last := plans[len(plans)-1]
	length := last.logicalOffset + last.size
	sectorSize := uint32(MinLUKS2SectorBytes)
	segments := make([]segmentReader, 0, len(plans))
	for _, plan := range plans {
		cipher, err := newSectorCipher(plan.spec, masterKey)
		if err != nil {
			return nil, err
		}
		if plan.sectorSize > sectorSize {
			sectorSize = plan.sectorSize
		}
		segments = append(segments, segmentReader{plan: plan, cipher: cipher})
	}
	return &Source{
		id:            id,
		parent:        parent,
		segments:      segments,
		payloadOffset: plans[0].physicalOffset,
		ivTweak:       plans[0].ivTweak,
		length:        length,
		sectorSize:    sectorSize,
	}, nil
}

// SourceID implements source.ByteSource.
func (s *Source) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *Source) Len() uint64 { return s.length }

// ImageID implements source.ByteSource.
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *Source) SectorSize() uint32 { return s.sectorSize }

// PayloadOffset returns where the payload begins in the encrypted volume.
func (s *Source) PayloadOffset() uint64 { return s.payloadOffset }

// IVTweak returns the tweak of the payload's first data unit.
func (s *Source) IVTweak() uint64 { return s.ivTweak }

// Stats implements source.ByteSource.
func (s *Source) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *Source) IsEmpty() bool { return s.length == 0 }

// ReadAt implements source.ByteSource.
func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readDecrypted(offset, buf, false)
}

// ReadAtLossy implements source.ByteSource.
func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readDecrypted(offset, buf, true)
}

func (s *Source) bounds(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

func (s *Source) segmentAt(offset uint64) *segmentReader {
	for index := range s.segments {
		segment := &s.segments[index]
		if offset >= segment.plan.logicalOffset && offset-segment.plan.logicalOffset < segment.plan.size {
			return segment
		}
	}
	return nil
}

func (s *Source) readDecrypted(offset uint64, out []byte, lossy bool) (int, error) {
	if len(out) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(out)), s.length)
	}
	want := s.length - offset
	if uint64(len(out)) < want {
		want = uint64(len(out))
	}
	done := 0
	at := offset
	for uint64(done) < want {
		segment := s.segmentAt(at)
		if segment == nil {
			return done, source.NewCorrupt(at, "no LUKS segment covers this offset")
		}
		within := at - segment.plan.logicalOffset
		take := segment.plan.size - within
		if remaining := want - uint64(done); take > remaining {
			take = remaining
		}
		n, err := segment.readDecrypted(s.parent, within, out[done:done+int(take)], lossy)
		if err != nil {
			return done + n, err
		}
		if uint64(n) != take {
			return done + n, source.NewUnexpectedEOF(at + uint64(n))
		}
		done += n
		at += uint64(n)
	}
	s.counters.AddRead(done)
	return done, nil
}

// readDecrypted reads [within, within+len(out)) of this segment and decrypts
// it. within is relative to the segment's logical start.
func (r *segmentReader) readDecrypted(parent source.ByteSource, within uint64, out []byte, lossy bool) (int, error) {
	want := r.plan.size - within
	if uint64(len(out)) < want {
		want = uint64(len(out))
	}
	if want == 0 {
		return 0, nil
	}
	sector := uint64(r.plan.sectorSize)
	alignedStart := within - within%sector
	end := within + want
	alignedEnd := end
	if remainder := alignedEnd % sector; remainder != 0 {
		alignedEnd += sector - remainder
		if alignedEnd < end { // the round-up wrapped
			alignedEnd = r.plan.size
		}
	}
	if alignedEnd > r.plan.size {
		alignedEnd = r.plan.size
	}
	alignedLen := alignedEnd - alignedStart
	physical := r.plan.physicalOffset + alignedStart
	buffer := make([]byte, int(alignedLen))
	var read int
	var err error
	if lossy {
		read, err = parent.ReadAtLossy(physical, buffer)
	} else {
		read, err = parent.ReadAt(physical, buffer)
	}
	if err != nil {
		return 0, readError(err)
	}
	if uint64(read) != alignedLen {
		// An unreadable range inside the validated layout is an error, not a
		// run of zeroes.
		return 0, source.NewUnexpectedEOF(physical + uint64(read))
	}
	for index := 0; index < len(buffer); index += int(sector) {
		stop := index + int(sector)
		if stop > len(buffer) {
			stop = len(buffer)
		}
		unit := buffer[index:stop]
		whole := len(unit) - len(unit)%aesBlockBytes
		if whole == 0 {
			continue
		}
		number := r.plan.ivTweak + alignedStart/sector + uint64(index)/sector
		if err := r.cipher.decryptSector(number, unit[:whole]); err != nil {
			return 0, &source.Error{
				Kind:      source.ErrDecrypt,
				Offset:    physical + uint64(index),
				Len:       uint64(whole),
				SourceLen: r.plan.size,
				Reason:    err.Error(),
			}
		}
	}
	skip := within - alignedStart
	copy(out[:want], buffer[skip:skip+want])
	return int(want), nil
}

// ExtentsInto implements source.ByteSource.
func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	for _, segment := range s.segments {
		segmentStart := segment.plan.logicalOffset
		segmentEnd := segmentStart + segment.plan.size
		start := offset
		if start < segmentStart {
			start = segmentStart
		}
		stop := end
		if stop > segmentEnd {
			stop = segmentEnd
		}
		if start < stop {
			out = append(out, source.ParentRange{
				Parent:       s.parent.SourceID(),
				ParentOffset: segment.plan.physicalOffset + (start - segmentStart),
				Len:          stop - start,
				Kind:         source.RangeData,
			})
		}
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	end := offset + length
	var out []source.ImageRange
	for _, segment := range s.segments {
		segmentStart := segment.plan.logicalOffset
		segmentEnd := segmentStart + segment.plan.size
		start := offset
		if start < segmentStart {
			start = segmentStart
		}
		stop := end
		if stop > segmentEnd {
			stop = segmentEnd
		}
		if start < stop {
			ranges, err := s.parent.MapToImage(
				segment.plan.physicalOffset+(start-segmentStart), stop-start)
			if err != nil {
				return nil, err
			}
			out = append(out, ranges...)
		}
	}
	return out, nil
}
