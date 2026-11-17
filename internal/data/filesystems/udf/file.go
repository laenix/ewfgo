package udf

// A file's extents exposed as a ByteSource.
//
// UDF file data is a list of allocation descriptors, each naming a block and a
// length. Two of the four descriptor types say the data is not recorded: the
// region exists in the file but was never written. Those ranges read as
// zeroes and are reported as RangeZero, so a sparse file is not mistaken for a
// dense one and an unwritten tail never returns whatever the media held.
//
// The logical length is the file entry's information length. Extents beyond it
// are not served; a length beyond the extents reads as a hole rather than an
// error, because a file entry that under-describes its own data still
// describes the file.

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// Run is one run of a file: where the bytes are, or a hole.
type Run struct {
	// Offset is the physical byte offset; zero for a hole.
	Offset uint64
	// Len is the number of logical bytes the run serves.
	Len uint64
	// Hole says the range was not recorded on the media.
	Hole bool
}

// IsHole reports whether the run is a hole.
func (r Run) IsHole() bool { return r.Hole }

// fileSource serves one file's bytes.
type fileSource struct {
	id       source.ID
	src      source.ByteSource
	runs     []Run
	length   uint64
	counters source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, runs []Run, length uint64) *fileSource {
	return &fileSource{id: id, src: src, runs: runs, length: length}
}

func (f *fileSource) readAtInternal(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.length)
	}
	want := int(minU64(f.length-offset, uint64(len(buf))))
	out := buf[:want]
	for i := range out {
		out[i] = 0
	}
	end := offset + uint64(want)
	var logical uint64
	for _, run := range f.runs {
		start := logical
		logical += run.Len
		if logical <= offset {
			continue
		}
		if start >= end {
			break
		}
		from := maxU64(offset, start)
		to := minU64(end, logical)
		if from >= to {
			continue
		}
		at := int(from - offset)
		n := int(to - from)
		if run.Hole {
			continue // already zeroed
		}
		physical := run.Offset + (from - start)
		if err := source.ReadExactAt(f.src, physical, out[at:at+n]); err != nil {
			return 0, err
		}
	}
	return want, nil
}

func (f *fileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.length || length > f.length-offset {
		return out, source.NewOutOfRange(offset, length, f.length)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	var logical uint64
	for _, run := range f.runs {
		start := logical
		logical += run.Len
		if logical <= offset {
			continue
		}
		if start >= end {
			break
		}
		from := maxU64(offset, start)
		to := minU64(end, logical)
		if from >= to {
			continue
		}
		if run.Hole {
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: 0,
				Len:          to - from,
				Kind:         source.RangeZero,
			})
			continue
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: run.Offset + (from - start),
			Len:          to - from,
			Kind:         source.RangeData,
		})
	}
	return out, nil
}

// SourceID implements source.ByteSource.
func (f *fileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *fileSource) Len() uint64 { return f.length }

// ImageID implements source.ByteSource.
func (f *fileSource) ImageID() source.ImageID { return f.src.ImageID() }

// SectorSize implements source.ByteSource.
func (f *fileSource) SectorSize() uint32 { return f.src.SectorSize() }

// ReadAt implements source.ByteSource with strict semantics.
func (f *fileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.readAtInternal(offset, buf)
	if err != nil {
		f.counters.AddError()
		return got, err
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy zero-fills unreadable bytes.
func (f *fileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.length)
	}
	want := int(minU64(f.length-offset, uint64(len(buf))))
	if got, err := f.readAtInternal(offset, buf[:want]); err == nil {
		return got, nil
	}
	for i := 0; i < want; i++ {
		buf[i] = 0
	}
	f.counters.AddCorrupt(uint64(want))
	return want, nil
}

// ExtentsInto translates [offset, offset+length) into the immediate parent.
func (f *fileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.extentsInto(f.src.SourceID(), offset, length, out)
}

// Extents returns the complete translation.
func (f *fileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.extentsInto(f.src.SourceID(), offset, length, nil)
}

// MapToImage translates the file's ranges all the way to image offsets.
func (f *fileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.extentsInto(f.src.SourceID(), offset, length, nil)
	if err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, r := range ranges {
		if r.Kind == source.RangeData {
			mapped, err := f.src.MapToImage(r.ParentOffset, r.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
		} else {
			out = append(out, source.ImageRange{
				ImageID:     f.src.ImageID(),
				ImageOffset: 0,
				Len:         r.Len,
				Kind:        r.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *fileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *fileSource) IsEmpty() bool { return f.length == 0 }

var _ source.ByteSource = (*fileSource)(nil)

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
