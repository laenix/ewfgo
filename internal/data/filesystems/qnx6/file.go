package qnx6

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

// FileSource is a regular file or symbolic link inside a QNX6 image, readable
// as a byte source. Unlike filesystems with holes defined as zero, QNX6 has
// no inline/hole semantics here: every logical block the declared size
// reaches must map to an in-range block, and an unused pointer is refused.
type FileSource struct {
	id        source.ID
	source    source.ByteSource
	extents   []Extent
	size      uint64
	blockSize uint64

	extentBlocks  uint64
	extentRecords uint64
	counters      source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, superblock *Superblock, inode *Inode) (*FileSource, error) {
	if inode.Kind.IsDirectory() {
		return nil, corruptf("inode %d is a directory, which the directory parser reads", inode.Number)
	}
	if !(inode.Kind.IsFile() || inode.Kind.IsSymlink()) {
		return nil, corruptf("inode %d is a %s, which has no file data", inode.Number, inode.Kind.Label())
	}
	blockSize := uint64(superblock.BlockSize)
	size := inode.Size
	needed := (size + blockSize - 1) / blockSize
	mapResult, err := Resolve(superblock, src, inode.Ptrs, inode.Levels, needed,
		"inode "+formatUint(inode.Number))
	if err != nil {
		return nil, err
	}

	extents := make([]Extent, 0, len(mapResult.Blocks))
	for index, block := range mapResult.Blocks {
		logical := uint64(index) * blockSize
		physical, ok := superblock.BlockOffset(block)
		if !ok {
			return nil, corruptf("inode %d data block %d overflows the byte address space",
				inode.Number, block)
		}
		if len(extents) > 0 {
			last := &extents[len(extents)-1]
			if last.Physical+last.Len == physical {
				last.Len += blockSize
				continue
			}
		}
		if uint64(len(extents)) >= MaxExtents {
			return nil, unsupportedf("inode %d needs more than %d byte extents", inode.Number, MaxExtents)
		}
		extents = append(extents, Extent{Logical: logical, Physical: physical, Len: blockSize})
	}
	if len(extents) == 0 && size != 0 {
		return nil, corruptf("inode %d declares %d bytes but has no data blocks", inode.Number, size)
	}

	return &FileSource{
		id:            id,
		source:        src,
		extents:       extents,
		size:          size,
		blockSize:     blockSize,
		extentBlocks:  mapResult.MetadataBlocks,
		extentRecords: mapResult.Pointers,
	}, nil
}

func formatUint(value uint64) string {
	// A tiny decimal formatter keeps the hot path allocation-free and avoids
	// pulling fmt into this file.
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[position:])
}

// Len returns the logical length in bytes.
func (f *FileSource) Len() uint64 { return f.size }

// IsEmpty reports whether the file has zero length.
func (f *FileSource) IsEmpty() bool { return f.size == 0 }

// Runs returns the resolved byte extents, in logical order.
func (f *FileSource) Runs() []Extent { return f.extents }

// ExtentBlocksRead returns the pointer blocks read while resolving the map.
func (f *FileSource) ExtentBlocksRead() uint64 { return f.extentBlocks }

// ExtentRecords returns the pointer slots examined while resolving the map.
func (f *FileSource) ExtentRecords() uint64 { return f.extentRecords }

// AllocatedBytes returns the bytes the file allocates.
func (f *FileSource) AllocatedBytes() uint64 {
	var total uint64
	for _, extent := range f.extents {
		total += extent.Len
	}
	return total
}

// PhysicalBlockAt returns the physical block holding offset.
func (f *FileSource) PhysicalBlockAt(offset uint64) (uint64, error) {
	extent, err := f.extentAt(offset)
	if err != nil {
		return 0, err
	}
	return (extent.Physical + (offset - extent.Logical)) / f.blockSize, nil
}

func (f *FileSource) extentAt(logical uint64) (*Extent, error) {
	if len(f.extents) == 0 {
		return nil, corruptf("the file has data but its block map is empty")
	}
	low, high := 0, len(f.extents)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if f.extents[middle].Logical <= logical {
			low = middle + 1
		} else {
			high = middle
		}
	}
	if low == 0 {
		return nil, corruptf("logical byte %d is before the first mapped extent", logical)
	}
	extent := &f.extents[low-1]
	if logical >= extent.Logical+extent.Len {
		return nil, corruptf("logical byte %d is a hole between mapped extents", logical)
	}
	return extent, nil
}

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
		if err := source.ReadExactAt(f.source, extent.Physical+inside, buf[done:done+int(take)]); err != nil {
			return done, err
		}
		done += int(take)
	}
	return want, nil
}

func (f *FileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	start := 0
	for start < len(f.extents) && f.extents[start].Logical+f.extents[start].Len <= offset {
		start++
	}
	var covered uint64
	for index := start; index < len(f.extents); index++ {
		extent := f.extents[index]
		extentEnd := extent.Logical + extent.Len
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

// ImageID implements source.ByteSource.
func (f *FileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *FileSource) SectorSize() uint32 { return f.source.SectorSize() }

// ReadAt implements source.ByteSource with strict semantics: every byte is
// stored data or an error, never a zero fill.
func (f *FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
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

// ReadAtLossy implements source.ByteSource's best-effort mode: a damaged
// range is zero-filled and accounted.
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
	if _, err := f.readAt(offset, buf[:want]); err != nil {
		clear(buf[:want])
		f.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return want, nil
}

// ExtentsInto implements source.ByteSource.
func (f *FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	ranges, err := f.extentsInto(f.source.SourceID(), offset, length, out)
	if err != nil {
		return ranges, mapSourceError(err)
	}
	return ranges, nil
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

var _ source.ByteSource = (*FileSource)(nil)
