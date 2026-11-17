package iso9660

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// Run is one extent: where the bytes physically are and how many of them.
//
// A run with a non-zero Unit is interleaved: its logical bytes are split into
// Unit-byte file units, and each unit starts Unit+Gap bytes after the one
// before. Len is the number of file bytes the run serves.
type Run struct {
	Offset uint64
	Len    uint64
	// Unit is the bytes in each file unit; zero for a contiguous run.
	Unit uint64
	// Gap is the bytes skipped between file units; ignored when Unit is zero.
	Gap uint64
}

// ContiguousRun builds a contiguous run.
func ContiguousRun(offset, length uint64) Run {
	return Run{Offset: offset, Len: length}
}

// IsInterleaved reports whether the run declares a file unit size.
func (r Run) IsInterleaved() bool { return r.Unit != 0 }

// forEachSegment walks the physical pieces of the run's logical range
// [from, to), in order.
func forEachSegment(run Run, from, to uint64, fn func(physical, length uint64)) {
	at := from
	for at < to {
		remaining := to - at
		if run.Unit == 0 {
			fn(run.Offset+at, remaining)
			return
		}
		index := at / run.Unit
		inUnit := at % run.Unit
		length := minU64(run.Unit-inUnit, remaining)
		physical := run.Offset + index*(run.Unit+run.Gap) + inUnit
		fn(physical, length)
		at += length
	}
}

// fileSource serves one file's bytes.
type fileSource struct {
	id        source.ID
	src       source.ByteSource
	runs      []Run
	length    uint64
	storedLen uint64
	zisofs    *zisofsFile
	counters  source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, runs []Run, length uint64) *fileSource {
	return &fileSource{id: id, src: src, runs: runs, length: length, storedLen: length}
}

func newZisofsFileSource(id source.ID, src source.ByteSource, file *zisofsFile) *fileSource {
	run := file.runValue()
	return &fileSource{
		id:        id,
		src:       src,
		runs:      []Run{ContiguousRun(run.Offset, run.Len)},
		length:    file.len(),
		storedLen: file.storedLenValue(),
		zisofs:    file,
	}
}

// IsZisofs reports whether the file is served through zisofs decompression.
func (f *fileSource) IsZisofs() bool { return f.zisofs != nil }

// StoredLen returns the bytes the file occupies in the image.
func (f *fileSource) StoredLen() uint64 { return f.storedLen }

// allocatedBytes is what the extents cover, never more than the stored length.
func (f *fileSource) allocatedBytes() uint64 {
	var stored uint64
	for _, run := range f.runs {
		stored += run.Len
	}
	if stored > f.storedLen {
		stored = f.storedLen
	}
	if f.zisofs != nil {
		return stored
	}
	return minU64(stored, f.length)
}

// readAtInternalChecked serves a strict read.
func (f *fileSource) readAtInternalChecked(offset uint64, buf []byte) (int, error) {
	if f.zisofs != nil {
		return f.zisofs.readAt(f.src, offset, buf)
	}
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.length)
	}
	want := int(minU64(f.length-offset, uint64(len(buf))))
	out := buf[:want]
	end := offset + uint64(want)
	var logical uint64
	var readErr error
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
		forEachSegment(run, from-start, to-start, func(physical, length uint64) {
			if readErr != nil {
				return
			}
			n := int(length)
			readErr = source.ReadExactAt(f.src, physical, out[at:at+n])
			at += n
		})
		if readErr != nil {
			return 0, readErr
		}
	}
	return want, nil
}

func (f *fileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if f.zisofs != nil {
		return f.zisofs.extentsInto(parent, offset, length, out)
	}
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
		forEachSegment(run, from-start, to-start, func(physical, length uint64) {
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: physical,
				Len:          length,
				Kind:         source.RangeData,
			})
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
	got, err := f.readAtInternalChecked(offset, buf)
	if err != nil {
		f.counters.AddError()
		return got, err
	}
	if f.zisofs != nil {
		f.counters.AddDecompressed(uint64(got))
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy zero-fills unreadable bytes. A zisofs file keeps the strict
// path: zero-filling a block that did not inflate would invent content.
func (f *fileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if f.zisofs != nil {
		return f.ReadAt(offset, buf)
	}
	if offset >= f.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.length)
	}
	want := int(minU64(f.length-offset, uint64(len(buf))))
	if got, err := f.readAtInternalChecked(offset, buf[:want]); err == nil {
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

// MapToImage walks the parent chain to image offsets.
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
				ImageID: f.src.ImageID(),
				Len:     r.Len,
				Kind:    r.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *fileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *fileSource) IsEmpty() bool { return f.length == 0 }

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

var _ source.ByteSource = (*fileSource)(nil)
