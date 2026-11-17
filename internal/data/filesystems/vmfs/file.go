package vmfs

import (
	"fmt"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// fileSource exposes one VMFS file, directory stream or symbolic link as a
// ByteSource.
//
// The block map is resolved when the source is opened: every file block must be
// present, map a contiguous logical range, and cover the descriptor's declared
// size. A zero block address, an out-of-range block, a sub-block map or a
// double-indirect map is refused rather than zero-filled or guessed at. The
// last file block may be partly used; the descriptor's size cuts it short.
type fileSource struct {
	id             source.ID
	src            source.ByteSource
	extents        []extent
	size           uint64
	blockSize      uint64
	pointerBlocks  uint64
	pointerRecords uint64
	counters       source.Counters
}

// newFileSource resolves a file descriptor's data stream.
func newFileSource(id source.ID, src source.ByteSource, sb *superblock, in *inode, pbc *pbc) (*fileSource, error) {
	resolved, err := resolveExtents(sb, in, pbc)
	if err != nil {
		return nil, err
	}
	blockSize := in.blockSize
	var logical, physicalTotal uint64
	for _, ext := range resolved.extents {
		if ext.logical != logical {
			return nil, corruptf("file descriptor 0x%08x at byte 0x%x: its extents are not contiguous at logical byte %d",
				in.blockID, in.at, logical)
		}
		nextLogical, ok := addChecked(logical, ext.len)
		if !ok {
			return nil, corruptf("a file's logical size overflows")
		}
		logical = nextLogical
		nextPhysical, ok := addChecked(physicalTotal, ext.len)
		if !ok {
			return nil, corruptf("a file's allocation overflows")
		}
		physicalTotal = nextPhysical
	}
	allocated, err := in.allocatedBytes()
	if err != nil {
		return nil, err
	}
	if physicalTotal != allocated {
		return nil, corruptf("file descriptor 0x%08x at byte 0x%x: its extents cover %d bytes but it allocates %d",
			in.blockID, in.at, physicalTotal, allocated)
	}
	if logical < in.size {
		return nil, corruptf("file descriptor 0x%08x at byte 0x%x: its extents end at byte %d, before its declared %d",
			in.blockID, in.at, logical, in.size)
	}
	if uint64(len(resolved.extents)) > maxFileBlocks {
		return nil, unsupportedf("file descriptor 0x%08x at byte 0x%x needs %d extents, more than the %d-extent cap",
			in.blockID, in.at, len(resolved.extents), maxFileBlocks)
	}
	return &fileSource{
		id:             id,
		src:            src,
		extents:        resolved.extents,
		size:           in.size,
		blockSize:      blockSize,
		pointerBlocks:  resolved.pointerBlocks,
		pointerRecords: resolved.pointerRecords,
	}, nil
}

func (f *fileSource) extentCount() int         { return len(f.extents) }
func (f *fileSource) extentBlocksRead() uint64 { return f.pointerBlocks }
func (f *fileSource) extentRecords() uint64    { return f.pointerRecords }

func (f *fileSource) allocatedBytes() uint64 {
	var total uint64
	for _, ext := range f.extents {
		total += ext.len
	}
	return total
}

// physicalBlockAt returns the physical block holding offset.
func (f *fileSource) physicalBlockAt(offset uint64) (uint64, error) {
	ext, err := f.extentAt(offset)
	if err != nil {
		return 0, err
	}
	physical, ok := addChecked(ext.physical, offset-ext.logical)
	if !ok {
		return 0, corruptf("a physical offset overflows")
	}
	return physical / f.blockSize, nil
}

// readAtInternal reads logical bytes, refusing any offset outside the size.
func (f *fileSource) readAtInternal(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := int(minU64(f.size-offset, uint64(len(buf))))
	done := 0
	for done < want {
		logical := offset + uint64(done)
		ext, err := f.extentAt(logical)
		if err != nil {
			return 0, err
		}
		inside := logical - ext.logical
		take := int(minU64(ext.len-inside, uint64(want-done)))
		if take == 0 {
			return 0, corruptf("the data map for source %d has a zero-length extent", f.id)
		}
		at, ok := addChecked(ext.physical, inside)
		if !ok {
			return 0, corruptf("a physical offset overflows")
		}
		if err := source.ReadExactAt(f.src, at, buf[done:done+take]); err != nil {
			return 0, err
		}
		done += take
	}
	return want, nil
}

func (f *fileSource) extentAt(logical uint64) (extent, error) {
	if len(f.extents) == 0 {
		return extent{}, corruptf("the file has data but its block map is empty")
	}
	after := sort.Search(len(f.extents), func(i int) bool {
		return f.extents[i].logical > logical
	})
	if after == 0 {
		return extent{}, corruptf("logical byte %d is before the first mapped extent", logical)
	}
	return f.extents[after-1], nil
}

// extentsInto describes the stored ranges [offset, offset+length) reads from.
func (f *fileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	startIndex := sort.Search(len(f.extents), func(i int) bool {
		return f.extents[i].logical > offset
	})
	if startIndex > 0 {
		startIndex--
	}
	var covered uint64
	for _, ext := range f.extents[startIndex:] {
		extentEnd := ext.logical + ext.len
		if ext.logical >= end {
			break
		}
		if extentEnd <= offset {
			continue
		}
		from := maxU64(ext.logical, offset)
		to := minU64(extentEnd, end)
		if to <= from {
			continue
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: ext.physical + (from - ext.logical),
			Len:          to - from,
			Kind:         source.RangeData,
		})
		covered += to - from
	}
	if covered != length {
		return out, corruptf("the data map covers %d of %d requested bytes at offset %d", covered, length, offset)
	}
	return out, nil
}

// SourceID implements source.ByteSource.
func (f *fileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *fileSource) Len() uint64 { return f.size }

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

// ReadAtLossy zero-fills unreadable bytes and counts them as corrupt.
func (f *fileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := int(minU64(f.size-offset, uint64(len(buf))))
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
func (f *fileSource) IsEmpty() bool { return f.size == 0 }

func (f *fileSource) String() string {
	return fmt.Sprintf("vmfs file source %d (%d bytes, %d extents)", f.id, f.size, len(f.extents))
}

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
