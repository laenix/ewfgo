package hfsplus

// A file fork exposed as a source.ByteSource.
//
// The extent list is resolved once when the source is opened, so a read costs
// one extent walk and no catalog lookups.  Reads are exact: a short request at
// the logical end is a short read, and a damaged extent is an error rather
// than a silent zero fill.

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// FileSource is one fork of one file.
type FileSource struct {
	id       source.ID
	volume   *Volume
	kind     ForkKind
	extents  ForkExtents
	length   uint64
	counters source.Counters
}

func newFileSource(id source.ID, volume *Volume, kind ForkKind, extents ForkExtents, length uint64) *FileSource {
	return &FileSource{id: id, volume: volume, kind: kind, extents: extents, length: length}
}

// Volume returns the volume that owns the fork.
func (f *FileSource) Volume() *Volume { return f.volume }

// ForkKind returns which fork this source serves.
func (f *FileSource) ForkKind() ForkKind { return f.kind }

// ExtentList returns the resolved extent list.
func (f *FileSource) ExtentList() ForkExtents { return f.extents }

// SourceID implements source.ByteSource.
func (f *FileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *FileSource) Len() uint64 { return f.length }

// ImageID implements source.ByteSource.
func (f *FileSource) ImageID() source.ImageID { return f.volume.src.ImageID() }

// SectorSize implements source.ByteSource.
func (f *FileSource) SectorSize() uint32 { return f.volume.src.SectorSize() }

// ReadAt implements source.ByteSource.  The start of the request must be
// inside the fork; a request crossing the end returns a short read.
func (f *FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	if offset >= f.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.length)
	}
	want := int(minU64(f.length-offset, uint64(len(buf))))
	n, err := f.extents.ReadAt(f.volume.src, f.volume.header.BlockSize, offset, buf[:want])
	f.counters.AddRead(n)
	return n, err
}

// ReadAtLossy is the best-effort mode: an unreadable range is zero-filled and
// counted as corrupt so carving can continue.
func (f *FileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.length)
	}
	want := int(minU64(f.length-offset, uint64(len(buf))))
	n, err := f.ReadAt(offset, buf[:want])
	if err != nil {
		for i := n; i < want; i++ {
			buf[i] = 0
		}
		f.counters.AddCorrupt(uint64(want - n))
		return want, nil
	}
	return n, nil
}

// ExtentsInto translates a fork range into ranges of the volume.
func (f *FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.length || length > f.length-offset {
		return out, source.NewOutOfRange(offset, length, f.length)
	}
	return f.extents.ExtentsInto(f.volume.src.SourceID(), f.volume.header.BlockSize, offset, length, out)
}

// Extents returns the complete translation for a fork range.
func (f *FileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage translates a fork range all the way to image offsets.
func (f *FileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, extent := range ranges {
		if extent.Kind == source.RangeData {
			child, err := f.volume.src.MapToImage(extent.ParentOffset, extent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
			continue
		}
		out = append(out, source.ImageRange{
			ImageID:     f.volume.src.ImageID(),
			ImageOffset: 0,
			Len:         extent.Len,
			Kind:        extent.Kind,
		})
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *FileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *FileSource) IsEmpty() bool { return f.length == 0 }

var _ source.ByteSource = (*FileSource)(nil)
