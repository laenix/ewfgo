package hpfs

import (
	"errors"

	"github.com/laenix/ewfgo/internal/data/source"
)

// HpfsFileSource is a regular file inside an HPFS volume, readable as a byte
// source. A gap between the fnode's runs is a hole: it reads as zeroes and is
// reported as RangeHole, never as stored data.
type HpfsFileSource struct {
	id       source.ID
	source   source.ByteSource
	extents  []Extent
	len      uint64
	inode    uint32
	counters source.Counters
}

func newHpfsFileSource(id source.ID, src source.ByteSource, fnode *Fnode) (*HpfsFileSource, error) {
	if fnode.IsDirectory() {
		return nil, corruptf("the fnode in sector %d is a directory, not a file", fnode.Sector)
	}
	return &HpfsFileSource{
		id:      id,
		source:  src,
		extents: append([]Extent(nil), fnode.Extents...),
		len:     fnode.FileSize,
		inode:   fnode.Sector,
	}, nil
}

// SourceID implements source.ByteSource.
func (f *HpfsFileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *HpfsFileSource) Len() uint64 { return f.len }

// ImageID implements source.ByteSource.
func (f *HpfsFileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *HpfsFileSource) SectorSize() uint32 { return f.source.SectorSize() }

// Inode returns the fnode sector behind the file.
func (f *HpfsFileSource) Inode() uint32 { return f.inode }

// IsEmpty implements source.ByteSource.
func (f *HpfsFileSource) IsEmpty() bool { return f.len == 0 }

// Runs returns the validated byte runs in file order.
func (f *HpfsFileSource) Runs() []Extent {
	return append([]Extent(nil), f.extents...)
}

// AllocatedBytes counts allocation, not file length.
func (f *HpfsFileSource) AllocatedBytes() uint64 {
	var total uint64
	for _, extent := range f.extents {
		total += extent.Len
	}
	return total
}

func (f *HpfsFileSource) readAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.len {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.len)
	}
	want := len(buf)
	if remaining := f.len - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	out := buf[:want]
	clear(out)
	end := offset + uint64(want)
	for _, extent := range f.extents {
		extentEnd := extent.Logical + extent.Len
		if extentEnd <= offset || extent.Logical >= end {
			continue
		}
		from := offset
		if extent.Logical > from {
			from = extent.Logical
		}
		to := end
		if extentEnd < to {
			to = extentEnd
		}
		if from >= to {
			continue
		}
		physical := extent.Physical + (from - extent.Logical)
		if physical < extent.Physical {
			return int(from - offset), corruptf("a run's physical offset overflows")
		}
		at := int(from - offset)
		count := int(to - from)
		if err := source.ReadExactAt(f.source, physical, out[at:at+count]); err != nil {
			return at, err
		}
	}
	return want, nil
}

// ReadAt implements source.ByteSource with strict semantics.
func (f *HpfsFileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.readAt(offset, buf)
	if err != nil {
		return got, mapSourceError(err)
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *HpfsFileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.len {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.len)
	}
	want := len(buf)
	if remaining := f.len - offset; uint64(want) > remaining {
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

func (f *HpfsFileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.len || length > f.len-offset {
		return out, source.NewOutOfRange(offset, length, f.len)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	cursor := offset
	for _, extent := range f.extents {
		extentEnd := extent.Logical + extent.Len
		if extentEnd <= offset {
			continue
		}
		if extent.Logical >= end {
			break
		}
		from := offset
		if extent.Logical > from {
			from = extent.Logical
		}
		to := end
		if extentEnd < to {
			to = extentEnd
		}
		if from >= to {
			continue
		}
		if from > cursor {
			out = append(out, source.ParentRange{Parent: parent, Len: from - cursor, Kind: source.RangeHole})
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: extent.Physical + (from - extent.Logical),
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

// ExtentsInto implements source.ByteSource.
func (f *HpfsFileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.extentsInto(f.source.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *HpfsFileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *HpfsFileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, item := range ranges {
		if item.Kind == source.RangeData {
			mapped, err := f.source.MapToImage(item.ParentOffset, item.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
		} else {
			out = append(out, source.ImageRange{
				ImageID: f.source.ImageID(),
				Len:     item.Len,
				Kind:    item.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *HpfsFileSource) Stats() source.Stats { return f.counters.Snapshot() }

func mapSourceError(err error) error {
	if err == nil {
		return nil
	}
	var sourceErr *source.Error
	if errors.As(err, &sourceErr) {
		return err
	}
	if errors.Is(err, ErrUnsupported) {
		return &source.Error{Kind: source.ErrUnsupported, Reason: err.Error(), Err: err}
	}
	if errors.Is(err, ErrCorrupt) {
		return &source.Error{Kind: source.ErrCorrupt, Reason: err.Error(), Err: err}
	}
	return err
}

var _ source.ByteSource = (*HpfsFileSource)(nil)
