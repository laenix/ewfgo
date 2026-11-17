package ufs

import (
	"errors"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Run is one run of file bytes backed by the volume, in byte units.
type Run struct {
	// Logical is the logical byte offset in the file.
	Logical uint64
	// Physical is the byte offset in the volume.
	Physical uint64
	Len      uint64
}

// ExtentMap is a file's runs in logical order plus its declared byte size.
// A logical range with no run is a hole: UFS names it with a zero block
// pointer, stores nothing there, and the range reads back as zeros while
// staying visible as a hole in provenance.
type ExtentMap struct {
	length uint64
	runs   []Run
}

// BuildExtentMap resolves an inode's fragment pointers into byte runs.
func BuildExtentMap(src source.ByteSource, sb *Superblock, inode *Inode) (*ExtentMap, error) {
	entries, err := ReadBlockMap(src, sb, inode)
	if err != nil {
		return nil, err
	}
	return extentMapFromEntries(sb, inode, entries)
}

func extentMapFromEntries(sb *Superblock, inode *Inode, entries []BlockEntry) (*ExtentMap, error) {
	blockSize := sb.BlockSize()
	runs := make([]Run, 0, len(entries))
	for _, entry := range entries {
		logical, ok := mulCheck(entry.LogicalBlock, blockSize)
		if !ok {
			return nil, corruptf("a block's logical offset overflows")
		}
		if logical >= inode.Size {
			continue
		}
		physical, err := sb.FragmentOffset(entry.Fragment)
		if err != nil {
			return nil, err
		}
		length := inode.Size - logical
		if length > blockSize {
			length = blockSize
		}
		if len(runs) > 0 {
			last := &runs[len(runs)-1]
			if satAdd(last.Logical, last.Len) == logical && satAdd(last.Physical, last.Len) == physical {
				last.Len = satAdd(last.Len, length)
				continue
			}
		}
		runs = append(runs, Run{Logical: logical, Physical: physical, Len: length})
	}
	return &ExtentMap{length: inode.Size, runs: runs}, nil
}

// Len returns the declared file length.
func (m *ExtentMap) Len() uint64 { return m.length }

// IsEmpty reports whether the file has no bytes.
func (m *ExtentMap) IsEmpty() bool { return m.length == 0 }

// Runs returns the runs in logical order.
func (m *ExtentMap) Runs() []Run { return m.runs }

// AllocatedBytes returns the bytes backed by stored fragments, clamped to the
// file size.
func (m *ExtentMap) AllocatedBytes() uint64 {
	var total uint64
	for _, run := range m.runs {
		start, end := m.byteRange(run)
		total += end - start
	}
	return total
}

func (m *ExtentMap) byteRange(run Run) (uint64, uint64) {
	start := run.Logical
	if start > m.length {
		start = m.length
	}
	end := satAdd(run.Logical, run.Len)
	if end > m.length {
		end = m.length
	}
	return start, end
}

// ReadAt reads up to len(buf) bytes starting at logical offset. Hole bytes are
// zero; the buffer past the declared length is left untouched.
func (m *ExtentMap) ReadAt(src source.ByteSource, offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= m.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), m.length)
	}
	want := len(buf)
	if remaining := m.length - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	out := buf[:want]
	clear(out)
	end := offset + uint64(want)
	for _, run := range m.runs {
		start, stop := m.byteRange(run)
		if stop <= offset {
			continue
		}
		if start >= end {
			break
		}
		from := offset
		if start > from {
			from = start
		}
		to := end
		if stop < to {
			to = stop
		}
		if from >= to {
			continue
		}
		into := from - start
		at := int(from - offset)
		count := int(to - from)
		physical, ok := addCheck(run.Physical, into)
		if !ok {
			return at, corruptf("a run's offset overflows")
		}
		if err := source.ReadExactAt(src, physical, out[at:at+count]); err != nil {
			return at, err
		}
	}
	return want, nil
}

// ExtentsInto translates a file range into ranges of the volume that holds it.
func (m *ExtentMap) ExtentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > m.length || length > m.length-offset {
		return out, source.NewOutOfRange(offset, length, m.length)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	cursor := offset
	for _, run := range m.runs {
		start, stop := m.byteRange(run)
		if stop <= offset {
			continue
		}
		if start >= end {
			break
		}
		from := offset
		if start > from {
			from = start
		}
		to := end
		if stop < to {
			to = stop
		}
		if from >= to {
			continue
		}
		if from > cursor {
			out = append(out, source.ParentRange{Parent: parent, Len: from - cursor, Kind: source.RangeHole})
		}
		physical, ok := addCheck(run.Physical, from-start)
		if !ok {
			return out, corruptf("a run's offset overflows")
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: physical,
			Len:          to - from,
			Kind:         source.RangeData,
		})
		cursor = to
	}
	if cursor < end {
		out = append(out, source.ParentRange{Parent: parent, Len: end - cursor, Kind: source.RangeHole})
	}
	return out, nil
}

// UfsFileSource is a file inside a UFS volume, readable as a byte source.
type UfsFileSource struct {
	id       source.ID
	source   source.ByteSource
	mapData  *ExtentMap
	inode    uint32
	counters source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, mapData *ExtentMap, inode uint32) *UfsFileSource {
	return &UfsFileSource{id: id, source: src, mapData: mapData, inode: inode}
}

// SourceID implements source.ByteSource.
func (f *UfsFileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *UfsFileSource) Len() uint64 { return f.mapData.Len() }

// ImageID implements source.ByteSource.
func (f *UfsFileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *UfsFileSource) SectorSize() uint32 { return f.source.SectorSize() }

// Inode returns the file's inode number.
func (f *UfsFileSource) Inode() uint32 { return f.inode }

// Extents returns the file's extent map.
func (f *UfsFileSource) ExtentsMap() *ExtentMap { return f.mapData }

// ReadAt implements source.ByteSource with strict semantics.
func (f *UfsFileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.mapData.ReadAt(f.source, offset, buf)
	if err != nil {
		return got, mapSourceError(err)
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *UfsFileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.mapData.Len() {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.mapData.Len())
	}
	want := len(buf)
	if remaining := f.mapData.Len() - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	got, err := f.ReadAt(offset, buf[:want])
	if err != nil {
		clear(buf[:want])
		f.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return got, nil
}

// ExtentsInto implements source.ByteSource.
func (f *UfsFileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.mapData.ExtentsInto(f.source.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *UfsFileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *UfsFileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Kind == source.RangeData {
			images, err := f.source.MapToImage(r.ParentOffset, r.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, images...)
			continue
		}
		out = append(out, source.ImageRange{
			ImageID:     f.source.ImageID(),
			ImageOffset: 0,
			Len:         r.Len,
			Kind:        r.Kind,
		})
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *UfsFileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *UfsFileSource) IsEmpty() bool { return f.mapData.IsEmpty() }

func mapSourceError(err error) error {
	if err == nil {
		return nil
	}
	var sourceErr *source.Error
	if errors.As(err, &sourceErr) {
		return err
	}
	if errors.Is(err, source.ErrUnsupported) {
		return &source.Error{Kind: source.ErrUnsupported, Reason: err.Error(), Err: err}
	}
	if errors.Is(err, source.ErrCorrupt) {
		return &source.Error{Kind: source.ErrCorrupt, Reason: err.Error(), Err: err}
	}
	return err
}

var _ source.ByteSource = (*UfsFileSource)(nil)
