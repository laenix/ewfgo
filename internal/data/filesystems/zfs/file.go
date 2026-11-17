package zfs

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// FileSource is a ZPL regular file or symbolic link inside a ZFS dataset,
// readable as a byte source.
//
// A block pointer that is a hole reads as zero bytes; ZFS defines that, and
// ranges are exported as RangeHole so a consumer can tell hole bytes from
// stored zeros. Embedded payloads and compressed blocks are computed from
// their parent block, so their ranges are RangeDerived or name the stored
// block's physical extent.
type FileSource struct {
	id       source.ID
	source   source.ByteSource
	objset   *Objset
	node     *Dnode
	size     uint64
	counters source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, objset *Objset, node *Dnode, size uint64) *FileSource {
	return &FileSource{id: id, source: src, objset: objset, node: node, size: size}
}

// Object returns the ZPL object number this stream belongs to.
func (f *FileSource) Object() uint64 { return f.node.object }

// Size returns the logical length the file's ZPL_SIZE recorded.
func (f *FileSource) Size() uint64 { return f.size }

func (f *FileSource) readAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := uint64(len(buf))
	if remaining := f.size - offset; want > remaining {
		want = remaining
	}
	blockSize := f.node.dataBlockSize()
	if blockSize == 0 {
		return 0, corruptf("object %d has no data block size", f.node.object)
	}
	reader := newBlockReader(f.source)
	done := uint64(0)
	for done < want {
		position := offset + done
		within := position % blockSize
		take := blockSize - within
		if remaining := want - done; take > remaining {
			take = remaining
		}
		pointer, err := locateBlock(reader, f.node, position)
		if err != nil {
			return int(done), err
		}
		target := buf[done : done+take]
		if pointer.isHole() {
			clear(target)
			done += take
			continue
		}
		data, err := reader.read(pointer)
		if err != nil {
			return int(done), err
		}
		start := int(within)
		if start >= len(data) {
			clear(target)
			done += take
			continue
		}
		available := int(take)
		if len(data)-start < available {
			available = len(data) - start
		}
		copy(target[:available], data[start:start+available])
		clear(target[available:])
		done += take
	}
	return int(done), nil
}

// ReadAt implements source.ByteSource with strict semantics.
func (f *FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	got, err := f.readAt(offset, buf)
	if err != nil {
		f.counters.AddError()
		return got, err
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy zero-fills unreadable bytes and counts them as corrupt.
func (f *FileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := uint64(len(buf))
	if remaining := f.size - offset; want > remaining {
		want = remaining
	}
	if got, err := f.readAt(offset, buf[:want]); err == nil {
		return got, nil
	}
	clear(buf[:want])
	f.counters.AddCorrupt(want)
	return int(want), nil
}

func (f *FileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	reader := newBlockReader(f.source)
	var blocks []ObjectBlock
	if err := dataBlocksInto(reader, f.node, offset, length, &blocks); err != nil {
		return out, err
	}
	end := offset + length
	for _, block := range blocks {
		from := offset
		if block.logical > from {
			from = block.logical
		}
		to := end
		blockEnd := block.logical
		if block.len > ^uint64(0)-blockEnd {
			blockEnd = ^uint64(0)
		} else {
			blockEnd += block.len
		}
		if blockEnd < to {
			to = blockEnd
		}
		if from >= to {
			continue
		}
		switch {
		case block.pointer.isHole():
			out = append(out, source.ParentRange{Parent: parent, Len: to - from, Kind: source.RangeHole})
		case block.pointer.embedded():
			out = append(out, source.ParentRange{Parent: parent, Len: to - from, Kind: source.RangeDerived})
		default:
			physical, stored, ok, err := reader.location(block.pointer)
			if err != nil {
				return out, err
			}
			if !ok {
				return out, corruptf("object %d's block has no stored copy", f.node.object)
			}
			compression := block.pointer.compression()
			uncompressed := compression == CompressionOff || compression == CompressionInherit || compression == CompressionOn
			if uncompressed && block.pointer.lsize() == block.pointer.psize() {
				out = append(out, source.ParentRange{
					Parent:       parent,
					ParentOffset: physical + (from - block.logical),
					Len:          to - from,
					Kind:         source.RangeData,
				})
			} else {
				// The decoded bytes are not aligned to the stored ones, so the
				// whole stored region is what this range is derived from.
				out = append(out, source.ParentRange{
					Parent:       parent,
					ParentOffset: physical,
					Len:          stored,
					Kind:         source.RangeData,
				})
			}
		}
	}
	return out, nil
}

// ExtentsInto implements source.ByteSource.
func (f *FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.extentsInto(f.source.SourceID(), offset, length, out)
}

// Extents returns the complete translation.
func (f *FileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.extentsInto(f.source.SourceID(), offset, length, nil)
}

// MapToImage walks the parent chain to image offsets.
func (f *FileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, parentRange := range ranges {
		if parentRange.Kind == source.RangeData {
			mapped, err := f.source.MapToImage(parentRange.ParentOffset, parentRange.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		out = append(out, source.ImageRange{
			ImageID: f.source.ImageID(),
			Len:     parentRange.Len,
			Kind:    parentRange.Kind,
		})
	}
	return out, nil
}

// SourceID implements source.ByteSource.
func (f *FileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *FileSource) Len() uint64 { return f.size }

// ImageID implements source.ByteSource.
func (f *FileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *FileSource) SectorSize() uint32 { return f.source.SectorSize() }

// Stats implements source.ByteSource.
func (f *FileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *FileSource) IsEmpty() bool { return f.size == 0 }

var _ source.ByteSource = (*FileSource)(nil)

// sliceSource serves an in-memory byte slice (a symbolic link's target read
// from its attribute buffer) as a ByteSource. Its bytes are derived from the
// parent object, so ranges name no image offset.
type sliceSource struct {
	id       source.ID
	imageID  source.ImageID
	sector   uint32
	data     []byte
	counters source.Counters
}

func newSliceSource(id source.ID, imageID source.ImageID, sector uint32, data []byte) *sliceSource {
	if sector == 0 {
		sector = 512
	}
	return &sliceSource{id: id, imageID: imageID, sector: sector, data: append([]byte(nil), data...)}
}

func (s *sliceSource) SourceID() source.ID     { return s.id }
func (s *sliceSource) ImageID() source.ImageID { return s.imageID }
func (s *sliceSource) Len() uint64             { return uint64(len(s.data)) }
func (s *sliceSource) SectorSize() uint32      { return s.sector }
func (s *sliceSource) IsEmpty() bool           { return len(s.data) == 0 }
func (s *sliceSource) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *sliceSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= uint64(len(s.data)) {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), uint64(len(s.data)))
	}
	n := copy(buf, s.data[offset:])
	s.counters.AddRead(n)
	return n, nil
}

func (s *sliceSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

func (s *sliceSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	size := uint64(len(s.data))
	if offset > size || length > size-offset {
		return out, source.NewOutOfRange(offset, length, size)
	}
	if length > 0 {
		out = append(out, source.ParentRange{Parent: s.id, Len: length, Kind: source.RangeDerived})
	}
	return out, nil
}

func (s *sliceSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *sliceSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	size := uint64(len(s.data))
	if offset > size || length > size-offset {
		return nil, source.NewOutOfRange(offset, length, size)
	}
	if length == 0 {
		return nil, nil
	}
	return []source.ImageRange{{ImageID: s.imageID, Len: length, Kind: source.RangeDerived}}, nil
}

var _ source.ByteSource = (*sliceSource)(nil)
