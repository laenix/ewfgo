package yaffs

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

type chunkRef struct {
	page  uint64
	bytes uint64
}

// FileSource is one live file's bytes, assembled from its data chunks.
type FileSource struct {
	id      source.ID
	parent  source.ByteSource
	layout  Layout
	chunks  []*chunkRef
	size    uint64
	counter source.Counters
}

// OpenFile opens the regular file named by path.  A deleted object has no
// stream; its chunks may already belong to another file.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	entry, err := v.Lookup(path)
	if err != nil {
		return nil, err
	}
	return v.openEntry(entry)
}

// OpenFileByInode opens a regular file by object id.  A hard link resolves to
// the object it points at.
func (v *Volume) OpenFileByInode(record uint64) (source.ByteSource, error) {
	entry, found := v.EntryByInode(record)
	if !found {
		return nil, fmt.Errorf("%w: object %d", ErrNotFound, record)
	}
	return v.openEntry(entry)
}

func (v *Volume) openEntry(entry *Entry) (source.ByteSource, error) {
	if entry.Deleted {
		return nil, fmt.Errorf("%w: %s", ErrDeleted, entry.Path)
	}
	if entry.IsDir {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, entry.Path)
	}
	if !entry.IsFile {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotFile, entry.Path, entry.Kind.Label())
	}
	id := uint32(entry.Inode)
	header := v.objects[id].header
	target := id
	if header.Kind == KindHardLink {
		target = header.Equivalent
	}
	object, found := v.objects[target]
	if !found {
		return nil, fmt.Errorf("%w: %s has no target object", ErrNotFile, entry.Path)
	}
	size := entry.Size
	page := uint64(v.layout.PageData)
	count := (size + page - 1) / page
	if count > uint64(MaxChunkID) {
		return nil, limitf("file %s declares %d bytes, more than this reader assembles", entry.Path, size)
	}
	chunks := make([]*chunkRef, count)
	for block := uint64(0); block < count; block++ {
		occurrence, present := object.chunks[uint32(block+1)]
		if !present {
			continue
		}
		available := uint64(occurrence.bytes)
		if available > page {
			available = page
		}
		chunks[block] = &chunkRef{page: occurrence.page, bytes: available}
	}
	return &FileSource{
		id:     source.ID(v.fileID.Add(1)),
		parent: v.source,
		layout: v.layout,
		chunks: chunks,
		size:   size,
	}, nil
}

// Len returns the file's declared length.
func (f *FileSource) Len() uint64 { return f.size }

// IsEmpty reports whether the file declares no bytes.
func (f *FileSource) IsEmpty() bool { return f.size == 0 }

// AllocatedBytes is the number of chunk bytes the image actually stores.
func (f *FileSource) AllocatedBytes() uint64 {
	var total uint64
	for _, chunk := range f.chunks {
		if chunk != nil {
			total += chunk.bytes
		}
	}
	return total
}

// SourceID implements source.ByteSource.
func (f *FileSource) SourceID() source.ID { return f.id }

// ImageID implements source.ByteSource.
func (f *FileSource) ImageID() source.ImageID { return f.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (f *FileSource) SectorSize() uint32 { return f.parent.SectorSize() }

// ReadAt implements source.ByteSource.  A missing chunk reads as zero; a chunk
// whose data is unreadable is an error, never a silent zero.
func (f *FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counter.AddRead(0)
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := int(minU64(f.size-offset, uint64(len(buf))))
	out := buf[:want]
	clear(out)
	page := uint64(f.layout.PageData)
	end := offset + uint64(want)
	first := offset / page
	last := (end - 1) / page
	for index := first; index <= last; index++ {
		block := int(index)
		if block < 0 || block >= len(f.chunks) {
			continue
		}
		start := index * page
		logical := minU64(f.size-start, page)
		from := maxU64(offset, start)
		to := minU64(end, start+logical)
		if from >= to {
			continue
		}
		at := int(from - offset)
		n := int(to - from)
		chunk := f.chunks[block]
		if chunk == nil {
			continue
		}
		within := from - start
		available := chunk.bytes - minU64(within, chunk.bytes)
		read := int(minU64(available, uint64(n)))
		if read > 0 {
			physical := chunk.page*uint64(f.layout.Stride) + within
			if err := source.ReadExactAt(f.parent, physical, out[at:at+read]); err != nil {
				return 0, err
			}
			f.counter.AddRead(read)
		}
	}
	return want, nil
}

// ReadAtLossy implements source.ByteSource; unreadable bytes are zero-filled
// and counted.
func (f *FileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counter.AddRead(0)
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := int(minU64(f.size-offset, uint64(len(buf))))
	if _, err := f.ReadAt(offset, buf[:want]); err != nil {
		clear(buf[:want])
		f.counter.AddCorrupt(uint64(want))
		return want, nil
	}
	return want, nil
}

// ExtentsInto implements source.ByteSource.  A missing chunk is a RangeHole;
// the tail of a short chunk is RangeZero.
func (f *FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	page := uint64(f.layout.PageData)
	end := offset + length
	first := offset / page
	last := (end - 1) / page
	for index := first; index <= last; index++ {
		block := int(index)
		if block < 0 || block >= len(f.chunks) {
			continue
		}
		start := index * page
		logical := minU64(f.size-start, page)
		from := maxU64(offset, start)
		to := minU64(end, start+logical)
		if from >= to {
			continue
		}
		within := from - start
		want := to - from
		chunk := f.chunks[block]
		if chunk == nil {
			out = append(out, source.ParentRange{
				Parent: f.parent.SourceID(),
				Len:    want,
				Kind:   source.RangeHole,
			})
			continue
		}
		available := chunk.bytes - minU64(within, chunk.bytes)
		if available > want {
			available = want
		}
		if available > 0 {
			out = append(out, source.ParentRange{
				Parent:       f.parent.SourceID(),
				ParentOffset: chunk.page*uint64(f.layout.Stride) + within,
				Len:          available,
				Kind:         source.RangeData,
			})
		}
		if available < want {
			out = append(out, source.ParentRange{
				Parent: f.parent.SourceID(),
				Len:    want - available,
				Kind:   source.RangeZero,
			})
		}
	}
	return out, nil
}

// Extents returns the complete translation for [offset, offset+length).
func (f *FileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage translates the requested range to image offsets.
func (f *FileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, parent := range ranges {
		if parent.Kind == source.RangeData {
			mapped, err := f.parent.MapToImage(parent.ParentOffset, parent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		out = append(out, source.ImageRange{
			ImageID: f.parent.ImageID(),
			Len:     parent.Len,
			Kind:    parent.Kind,
		})
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *FileSource) Stats() source.Stats { return f.counter.Snapshot() }

var _ source.ByteSource = (*FileSource)(nil)
