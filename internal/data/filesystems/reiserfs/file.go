package reiserfs

import (
	"errors"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// A ReiserFS file body is described by indirect items (arrays of 32-bit block
// pointers) and one direct item (the file's tail stored inline). File-data key
// offsets are 1-based: the kernel writes pos1 + 1 where pos1 is the first byte
// the item holds.

// Run is one run of file bytes backed by the volume, in byte units.
type Run struct {
	Logical  uint64
	Physical uint64
	Len      uint64
}

type fileMap struct {
	length uint64
	runs   []Run
}

func buildFileMap(sb *Superblock, objectID uint32, size uint64, items []LeafItem) (*fileMap, error) {
	blockSize := uint64(sb.BlockSize)
	for _, item := range items {
		if item.Head.Key.ObjectID == objectID && item.Head.Key.ItemType == ItemTypeUnknown {
			return nil, unsupportedf("%s", item.Describe())
		}
	}

	var runs []Run
	var indirect []LeafItem
	for _, item := range items {
		if item.Head.Key.ObjectID == objectID && item.Head.Key.ItemType == ItemTypeIndirect {
			indirect = append(indirect, item)
		}
	}
	sort.Slice(indirect, func(left, right int) bool {
		if indirect[left].Head.Key.Offset != indirect[right].Head.Key.Offset {
			return indirect[left].Head.Key.Offset < indirect[right].Head.Key.Offset
		}
		return indirect[left].Head.Location < indirect[right].Head.Location
	})
	for _, item := range indirect {
		if len(item.Body)%4 != 0 {
			return nil, corruptf("an indirect item for object %d has %d body bytes, not a whole number of 4-byte pointers",
				objectID, len(item.Body))
		}
		base, ok := subtractOne(item.Head.Key.Offset)
		if !ok {
			return nil, corruptf("an indirect item for object %d has key offset 0; ReiserFS records the first file byte at offset 1",
				objectID)
		}
		free := uint64(item.Head.FreeSpaceOrCount)
		if free > blockSize {
			return nil, corruptf("an indirect item for object %d records %d free bytes in its last block, more than the %d-byte block",
				objectID, free, blockSize)
		}
		for index := 0; index*4+4 <= len(item.Body); index++ {
			pointer := le32(item.Body, index*4)
			logical := base + uint64(index)*blockSize
			if logical < base {
				return nil, corruptf("an indirect item's logical offset overflows")
			}
			if logical >= size {
				break
			}
			if pointer == 0 {
				continue
			}
			if pointer >= sb.BlockCount {
				return nil, corruptf("an indirect pointer %d in object %d is past the volume's %d blocks",
					pointer, objectID, sb.BlockCount)
			}
			physical := uint64(pointer) * blockSize
			runLen := size - logical
			if runLen > blockSize {
				runLen = blockSize
			}
			runs = append(runs, Run{Logical: logical, Physical: physical, Len: runLen})
		}
	}

	var direct []LeafItem
	for _, item := range items {
		if item.Head.Key.ObjectID == objectID && item.Head.Key.ItemType == ItemTypeDirect {
			direct = append(direct, item)
		}
	}
	sort.Slice(direct, func(left, right int) bool {
		if direct[left].Head.Key.Offset != direct[right].Head.Key.Offset {
			return direct[left].Head.Key.Offset < direct[right].Head.Key.Offset
		}
		return direct[left].Head.Location < direct[right].Head.Location
	})
	for _, item := range direct {
		logical, ok := subtractOne(item.Head.Key.Offset)
		if !ok {
			return nil, corruptf("a direct item for object %d has key offset 0; ReiserFS records the first file byte at offset 1",
				objectID)
		}
		if logical >= size {
			return nil, corruptf("a direct item for object %d starts at logical byte %d, at or past the file's %d bytes",
				objectID, logical, size)
		}
		runLen := size - logical
		if itemLen := uint64(item.Head.ItemLen); runLen > itemLen {
			runLen = itemLen
		}
		if runLen == 0 {
			continue
		}
		base := uint64(item.Block) * blockSize
		if item.Block != 0 && base/uint64(item.Block) != blockSize {
			return nil, corruptf("a direct item's physical offset overflows")
		}
		physical := base + uint64(item.Head.Location)
		if physical < base {
			return nil, corruptf("a direct item's physical offset overflows")
		}
		runs = append(runs, Run{Logical: logical, Physical: physical, Len: runLen})
	}

	sort.Slice(runs, func(left, right int) bool { return runs[left].Logical < runs[right].Logical })
	merged := make([]Run, 0, len(runs))
	for _, run := range runs {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			end := last.Logical + last.Len
			if run.Logical < end {
				return nil, corruptf("object %d has data items that overlap at logical byte %d", objectID, run.Logical)
			}
			if run.Logical == end && last.Physical+last.Len == run.Physical {
				last.Len += run.Len
				continue
			}
		}
		merged = append(merged, run)
	}
	return &fileMap{length: size, runs: merged}, nil
}

func subtractOne(value uint64) (uint64, bool) {
	if value == 0 {
		return 0, false
	}
	return value - 1, true
}

func (m *fileMap) len() uint64   { return m.length }
func (m *fileMap) isEmpty() bool { return m.length == 0 }

func (m *fileMap) byteRange(run Run) (uint64, uint64) {
	start := run.Logical
	if start > m.length {
		start = m.length
	}
	end := run.Logical + run.Len
	if end < run.Logical || end > m.length {
		end = m.length
	}
	return start, end
}

func (m *fileMap) readAt(src source.ByteSource, offset uint64, buf []byte) (int, error) {
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
		n := int(to - from)
		physical := run.Physical + into
		if physical < run.Physical {
			return at, corruptf("a run's physical offset overflows")
		}
		if err := source.ReadExactAt(src, physical, out[at:at+n]); err != nil {
			return at, err
		}
	}
	return want, nil
}

func (m *fileMap) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
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
		physical := run.Physical + (from - start)
		if physical < run.Physical {
			return out, corruptf("a run's physical offset overflows")
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

// ReiserFileSource is a file inside a ReiserFS volume, readable as a byte
// source.
type ReiserFileSource struct {
	id       source.ID
	source   source.ByteSource
	mapData  *fileMap
	objectID uint32
	counters source.Counters
}

func newReiserFileSource(id source.ID, src source.ByteSource, mapData *fileMap, objectID uint32) *ReiserFileSource {
	return &ReiserFileSource{id: id, source: src, mapData: mapData, objectID: objectID}
}

// SourceID implements source.ByteSource.
func (f *ReiserFileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *ReiserFileSource) Len() uint64 { return f.mapData.len() }

// ImageID implements source.ByteSource.
func (f *ReiserFileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *ReiserFileSource) SectorSize() uint32 { return f.source.SectorSize() }

// ObjectID returns the file's object id.
func (f *ReiserFileSource) ObjectID() uint32 { return f.objectID }

// ReadAt implements source.ByteSource with strict semantics.
func (f *ReiserFileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.mapData.readAt(f.source, offset, buf)
	if err != nil {
		return got, mapSourceError(err)
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *ReiserFileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.mapData.len() {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.mapData.len())
	}
	want := len(buf)
	if remaining := f.mapData.len() - offset; uint64(want) > remaining {
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
func (f *ReiserFileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.mapData.extentsInto(f.source.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *ReiserFileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *ReiserFileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Kind == source.RangeData {
			imageRanges, err := f.source.MapToImage(r.ParentOffset, r.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, imageRanges...)
		} else {
			out = append(out, source.ImageRange{
				ImageID:     f.source.ImageID(),
				ImageOffset: 0,
				Len:         r.Len,
				Kind:        r.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *ReiserFileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *ReiserFileSource) IsEmpty() bool { return f.mapData.isEmpty() }

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

var _ source.ByteSource = (*ReiserFileSource)(nil)
