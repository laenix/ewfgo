package gfs2

import (
	"errors"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxExtents is the most byte extents one file's map may hold.
const MaxExtents uint64 = 1_000_000

// Extent is one logical-to-physical block run, in bytes.
type Extent struct {
	Logical  uint64
	Physical uint64
	Len      uint64
}

type fileData struct {
	stuffed   []byte
	stuffedAt uint64
	runs      []Extent
}

// FileSource is a regular file or block-mapped symbolic link inside a GFS2
// image, readable as a byte source. Holes are refused: GFS2 has no hole this
// reader zero-fills.
type FileSource struct {
	id            source.ID
	source        source.ByteSource
	data          fileData
	size          uint64
	blockSize     uint64
	extentBlocks  uint64
	extentRecords uint64
	counters      source.Counters
}

// newFileSource resolves an inode's data stream.
func newFileSource(id source.ID, src source.ByteSource, superblock *Superblock, inode *Dinode) (*FileSource, error) {
	if inode.IsDirectory() {
		return nil, corruptf("dinode block %d is a directory, which the directory parser reads", inode.Block)
	}
	if !inode.IsFile() && !inode.IsSymlink() {
		return nil, corruptf("dinode block %d is a %s, which has no file data", inode.Block, inode.Kind)
	}
	blockSize := uint64(superblock.BlockSize)
	size := inode.Size

	if inode.Height == 0 {
		if inode.Stuffed == nil {
			return nil, corruptf("stuffed dinode block %d has no inline bytes", inode.Block)
		}
		if uint64(len(inode.Stuffed)) != size {
			return nil, corruptf("dinode block %d stores %d stuffed bytes but declares %d",
				inode.Block, len(inode.Stuffed), size)
		}
		base, ok := superblock.BlockOffset(inode.Block)
		if !ok {
			return nil, corruptf("a stuffed dinode's byte offset overflows")
		}
		at := base + DinodeSize
		if at < base {
			return nil, corruptf("a stuffed dinode's byte offset overflows")
		}
		return &FileSource{
			id:        id,
			source:    src,
			data:      fileData{stuffed: inode.Stuffed, stuffedAt: at},
			size:      size,
			blockSize: blockSize,
		}, nil
	}

	needed := (size + blockSize - 1) / blockSize
	blockMap, err := resolveMap(superblock, src, inode, needed)
	if err != nil {
		return nil, err
	}
	var runs []Extent
	for index, block := range blockMap.Blocks {
		logical := uint64(index) * blockSize
		if uint64(index) != 0 && logical/uint64(index) != blockSize {
			return nil, corruptf("a logical extent overflows")
		}
		physical := block * blockSize
		if block != 0 && physical/block != blockSize {
			return nil, corruptf("a physical extent overflows")
		}
		if len(runs) > 0 {
			last := &runs[len(runs)-1]
			if last.Physical+last.Len == physical {
				last.Len += blockSize
				continue
			}
		}
		if uint64(len(runs)) >= MaxExtents {
			return nil, unsupportedf("dinode block %d needs more than %d byte extents", inode.Block, MaxExtents)
		}
		runs = append(runs, Extent{Logical: logical, Physical: physical, Len: blockSize})
	}
	if len(runs) == 0 && size != 0 {
		return nil, corruptf("dinode block %d declares %d bytes but has no data blocks", inode.Block, size)
	}

	return &FileSource{
		id:            id,
		source:        src,
		data:          fileData{runs: runs},
		size:          size,
		blockSize:     blockSize,
		extentBlocks:  blockMap.MetadataBlocks,
		extentRecords: blockMap.Pointers,
	}, nil
}

// Runs returns the resolved byte extents; empty for a stuffed file.
func (f *FileSource) Runs() []Extent {
	if f.data.stuffed != nil {
		return nil
	}
	return f.data.runs
}

// ExtentBlocksRead returns the indirect blocks read while resolving the map.
func (f *FileSource) ExtentBlocksRead() uint64 { return f.extentBlocks }

// ExtentRecords returns the pointer slots examined while resolving the map.
func (f *FileSource) ExtentRecords() uint64 { return f.extentRecords }

// AllocatedBytes returns the bytes the file allocates. Stuffed data allocates
// no blocks.
func (f *FileSource) AllocatedBytes() uint64 {
	var total uint64
	for _, run := range f.data.runs {
		total += run.Len
	}
	return total
}

// PhysicalBlockAt returns the physical block holding offset in a block-mapped
// stream.
func (f *FileSource) PhysicalBlockAt(offset uint64) (uint64, error) {
	if f.data.stuffed != nil {
		return 0, corruptf("a stuffed stream has no separate physical block")
	}
	extent, err := f.extentAt(offset)
	if err != nil {
		return 0, err
	}
	physical := extent.Physical + (offset - extent.Logical)
	if physical < extent.Physical {
		return 0, corruptf("a physical offset overflows")
	}
	return physical / f.blockSize, nil
}

func (f *FileSource) extentAt(logical uint64) (Extent, error) {
	runs := f.data.runs
	if len(runs) == 0 {
		return Extent{}, corruptf("the file has data but its block map is empty")
	}
	after := partitionPoint(runs, func(extent Extent) bool { return extent.Logical <= logical })
	if after == 0 {
		return Extent{}, corruptf("logical byte %d is before the first mapped extent", logical)
	}
	extent := runs[after-1]
	if logical >= extent.Logical+extent.Len {
		return Extent{}, corruptf("logical byte %d is a hole between mapped extents", logical)
	}
	return extent, nil
}

func partitionPoint(runs []Extent, predicate func(Extent) bool) int {
	low, high := 0, len(runs)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if predicate(runs[middle]) {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low
}

// readAt reads strictly: the request must start inside the file, and any
// missing byte is an error rather than a zero.
func (f *FileSource) readAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := len(buf)
	if remaining := f.size - offset; uint64(want) > remaining {
		want = int(remaining)
	}

	if f.data.stuffed != nil {
		start := int(offset)
		end := start + want
		if end < start || end > len(f.data.stuffed) {
			return 0, corruptf("stuffed data holds %d bytes, short of a read to %d",
				len(f.data.stuffed), end)
		}
		copy(buf[:want], f.data.stuffed[start:end])
		return want, nil
	}

	done := 0
	for done < want {
		logical := offset + uint64(done)
		extent, err := f.extentAt(logical)
		if err != nil {
			return done, err
		}
		inside := logical - extent.Logical
		if inside >= extent.Len {
			return done, corruptf("logical byte %d falls outside the mapped extent", logical)
		}
		take := extent.Len - inside
		if uint64(want-done) < take {
			take = uint64(want - done)
		}
		if take == 0 {
			return done, corruptf("the data map for source %d has a zero-length extent", f.id)
		}
		at := extent.Physical + inside
		if err := source.ReadExactAt(f.source, at, buf[done:done+int(take)]); err != nil {
			return done, err
		}
		done += int(take)
	}
	return want, nil
}

// extentsInto appends the translation of [offset, offset+length) against the
// immediate parent.
func (f *FileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	if f.data.stuffed != nil {
		at := f.data.stuffedAt + offset
		if at < f.data.stuffedAt {
			return out, corruptf("a stuffed range's offset overflows")
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: at,
			Len:          length,
			Kind:         source.RangeData,
		})
		return out, nil
	}

	end := offset + length
	runs := f.data.runs
	startIndex := partitionPoint(runs, func(extent Extent) bool { return extent.Logical <= offset })
	if startIndex > 0 {
		startIndex--
	}
	var covered uint64
	for _, extent := range runs[startIndex:] {
		extentEnd := extent.Logical + extent.Len
		if extentEnd < extent.Logical {
			return out, corruptf("an extent's logical end overflows")
		}
		if extent.Logical >= end {
			break
		}
		if extentEnd <= offset {
			continue
		}
		from := extent.Logical
		if from < offset {
			from = offset
		}
		to := extentEnd
		if to > end {
			to = end
		}
		if to <= from {
			continue
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: extent.Physical + (from - extent.Logical),
			Len:          to - from,
			Kind:         source.RangeData,
		})
		covered += to - from
	}
	if covered != length {
		return out, corruptf("the data map covers %d of %d requested bytes at offset %d",
			covered, length, offset)
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

// ReadAt implements source.ByteSource with strict semantics.
func (f *FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.readAt(offset, buf)
	if err != nil {
		return got, mapError(err)
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *FileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := len(buf)
	if remaining := f.size - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	got, err := f.readAt(offset, buf[:want])
	if err != nil {
		clear(buf[:want])
		f.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return got, nil
}

// ExtentsInto implements source.ByteSource.
func (f *FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.extentsInto(f.source.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *FileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *FileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, parentRange := range ranges {
		if parentRange.Kind == source.RangeData {
			imageRanges, err := f.source.MapToImage(parentRange.ParentOffset, parentRange.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, imageRanges...)
		} else {
			out = append(out, source.ImageRange{
				ImageID:     f.source.ImageID(),
				ImageOffset: 0,
				Len:         parentRange.Len,
				Kind:        parentRange.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *FileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *FileSource) IsEmpty() bool { return f.size == 0 }

func mapError(err error) error {
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

var _ source.ByteSource = (*FileSource)(nil)
