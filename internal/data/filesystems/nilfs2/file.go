package nilfs2

import (
	"errors"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxExtents bounds one file's byte extents.
const MaxExtents uint64 = 1_000_000

// Extent is one logical-to-physical block run, in byte units.
type Extent struct {
	Logical  uint64
	Physical uint64
	Len      uint64
}

// Nilfs2FileSource is a regular file, directory stream or slow symbolic link
// inside a NILFS2 volume, readable as a source.ByteSource. Every logical block
// is translated through the DAT file; holes are refused rather than
// zero-filled.
type Nilfs2FileSource struct {
	id            source.ID
	source        source.ByteSource
	superblock    *Superblock
	extents       []Extent
	size          uint64
	blockSize     uint64
	extentBlocks  uint64
	extentRecords uint64
	counters      source.Counters
}

func newNilfs2FileSource(id source.ID, src source.ByteSource, superblock *Superblock, inode *Inode, dat *Dat) (*Nilfs2FileSource, error) {
	if inode.Kind != KindFile && inode.Kind != KindDirectory && inode.Kind != KindSymlink {
		return nil, corruptf("the inode is a %s, which has no file data", inode.Kind.Label())
	}
	if inode.Kind == KindSymlink && inode.Inline != nil {
		return nil, corruptf("a fast symbolic link stores its target in the inode, not in a block map")
	}
	blockSize := uint64(superblock.BlockSize)
	size := inode.Size
	needed := size / blockSize
	if size%blockSize != 0 {
		needed++
	}
	blocksBefore := dat.BlocksRead
	mapData, err := ResolveDirect(superblock, inode, needed, "the file",
		func(virtual uint64) (uint64, error) {
			return dat.Translate(superblock, src, virtual)
		})
	if err != nil {
		return nil, err
	}
	extentBlocks := dat.BlocksRead - blocksBefore

	var extents []Extent
	for index, block := range mapData.Blocks {
		logical := uint64(index) * blockSize
		if index != 0 && logical/uint64(index) != blockSize {
			return nil, corruptf("a logical extent overflows")
		}
		physical := block * blockSize
		if block != 0 && physical/block != blockSize {
			return nil, corruptf("a physical extent overflows")
		}
		if len(extents) > 0 {
			last := &extents[len(extents)-1]
			lastPhysicalEnd := last.Physical + last.Len
			lastLogicalEnd := last.Logical + last.Len
			if lastPhysicalEnd >= last.Physical && lastLogicalEnd >= last.Logical &&
				lastPhysicalEnd == physical && lastLogicalEnd == logical {
				last.Len += blockSize
				continue
			}
		}
		if uint64(len(extents)) >= MaxExtents {
			return nil, unsupportedf("the file needs more than %d byte extents", MaxExtents)
		}
		extents = append(extents, Extent{Logical: logical, Physical: physical, Len: blockSize})
	}
	if len(extents) == 0 && size != 0 {
		return nil, corruptf("the inode declares %d bytes but has no data blocks", size)
	}
	return &Nilfs2FileSource{
		id:            id,
		source:        src,
		superblock:    superblock,
		extents:       extents,
		size:          size,
		blockSize:     blockSize,
		extentBlocks:  extentBlocks,
		extentRecords: mapData.Pointers,
	}, nil
}

// Len returns the inode's declared length.
func (f *Nilfs2FileSource) Len() uint64 { return f.size }

// IsEmpty reports whether the file declares no bytes.
func (f *Nilfs2FileSource) IsEmpty() bool { return f.size == 0 }

// Extents returns the resolved byte extents.
func (f *Nilfs2FileSource) ExtentsList() []Extent { return f.extents }

// ExtentBlocksRead returns DAT blocks read while resolving the map.
func (f *Nilfs2FileSource) ExtentBlocksRead() uint64 { return f.extentBlocks }

// ExtentRecords returns pointer slots examined while resolving the map.
func (f *Nilfs2FileSource) ExtentRecords() uint64 { return f.extentRecords }

// AllocatedBytes returns the bytes the file allocates.
func (f *Nilfs2FileSource) AllocatedBytes() uint64 {
	var total uint64
	for _, extent := range f.extents {
		total += extent.Len
	}
	return total
}

// PhysicalBlockAt returns the physical block holding offset.
func (f *Nilfs2FileSource) PhysicalBlockAt(offset uint64) (uint64, error) {
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

func (f *Nilfs2FileSource) extentAt(logical uint64) (Extent, error) {
	if len(f.extents) == 0 {
		return Extent{}, corruptf("the file has data but its block map is empty")
	}
	after := sort.Search(len(f.extents), func(index int) bool {
		return f.extents[index].Logical > logical
	})
	if after == 0 {
		return Extent{}, corruptf("logical byte %d is before the first mapped extent", logical)
	}
	extent := f.extents[after-1]
	end := extent.Logical + extent.Len
	if end < extent.Logical {
		end = ^uint64(0)
	}
	if logical >= end {
		return Extent{}, corruptf("logical byte %d is a hole between mapped extents", logical)
	}
	return extent, nil
}

func (f *Nilfs2FileSource) readAt(offset uint64, buf []byte) (int, error) {
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
		take := int(extent.Len - inside)
		if remaining := want - done; take > remaining {
			take = remaining
		}
		if take == 0 {
			return done, corruptf("the data map for source %d has a zero-length extent", f.id)
		}
		at := extent.Physical + inside
		if at < extent.Physical {
			return done, corruptf("a physical offset overflows")
		}
		if err := source.ReadExactAt(f.source, at, buf[done:done+take]); err != nil {
			return done, err
		}
		done += take
	}
	return want, nil
}

func (f *Nilfs2FileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	startIndex := sort.Search(len(f.extents), func(index int) bool {
		return f.extents[index].Logical > offset
	})
	if startIndex > 0 {
		startIndex--
	}
	var covered uint64
	for _, extent := range f.extents[startIndex:] {
		extentEnd := extent.Logical + extent.Len
		if extentEnd < extent.Logical {
			extentEnd = ^uint64(0)
		}
		if extent.Logical >= end {
			break
		}
		if extentEnd <= offset {
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
		return out, corruptf("the data map covers %d of %d requested bytes at offset %d", covered, length, offset)
	}
	return out, nil
}

// SourceID implements source.ByteSource.
func (f *Nilfs2FileSource) SourceID() source.ID { return f.id }

// ImageID implements source.ByteSource.
func (f *Nilfs2FileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *Nilfs2FileSource) SectorSize() uint32 { return f.source.SectorSize() }

// ReadAt implements source.ByteSource with strict semantics.
func (f *Nilfs2FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
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
func (f *Nilfs2FileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
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
	if got, err := f.readAt(offset, buf[:want]); err == nil {
		return got, nil
	}
	clear(buf[:want])
	f.counters.AddCorrupt(uint64(want))
	return want, nil
}

// ExtentsInto implements source.ByteSource.
func (f *Nilfs2FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	ranges, err := f.extentsInto(f.source.SourceID(), offset, length, out)
	if err != nil {
		return ranges, mapSourceError(err)
	}
	return ranges, nil
}

// Extents implements source.ByteSource.
func (f *Nilfs2FileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *Nilfs2FileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.extentsInto(f.source.SourceID(), offset, length, nil)
	if err != nil {
		return nil, mapSourceError(err)
	}
	var out []source.ImageRange
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
func (f *Nilfs2FileSource) Stats() source.Stats { return f.counters.Snapshot() }

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

var _ source.ByteSource = (*Nilfs2FileSource)(nil)
