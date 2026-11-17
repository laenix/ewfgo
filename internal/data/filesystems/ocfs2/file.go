package ocfs2

import (
	"errors"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxFileExtents bounds one file's byte extents.
const MaxFileExtents uint64 = MaxExtents

// Extent is one logical-to-physical block run, in byte units.
type Extent struct {
	Logical  uint64
	Physical uint64
	Len      uint64
}

type fileData struct {
	inline  bool
	bytes   []byte
	at      uint64
	extents []Extent
}

// Ocfs2FileSource is a regular file, directory stream or slow symbolic link
// inside an OCFS2 volume, readable as a source.ByteSource. Data is either
// inline in the dinode or mapped by an extent tree; gaps and short maps are
// refused rather than zero-filled.
type Ocfs2FileSource struct {
	id            source.ID
	source        source.ByteSource
	superblock    *Superblock
	data          fileData
	size          uint64
	blockSize     uint64
	extentBlocks  uint64
	extentRecords uint64
	counters      source.Counters
}

func newOcfs2FileSource(id source.ID, src source.ByteSource, superblock *Superblock, inode *Inode) (*Ocfs2FileSource, error) {
	if !inode.Kind.HasData() {
		return nil, corruptf("inode block %d is a %s, which has no file data", inode.Block, inode.Kind.Label())
	}
	if inode.FastSymlink != nil {
		return nil, corruptf("inode block %d is a fast symbolic link and has no data stream", inode.Block)
	}
	blockSize := uint64(superblock.BlockSize)
	size := inode.Size

	if inode.Inline != nil {
		if uint64(len(inode.Inline)) != size {
			return nil, corruptf("inode block %d has %d inline bytes but declares %d",
				inode.Block, len(inode.Inline), size)
		}
		offset, ok := superblock.BlockOffset(inode.Block)
		if !ok || offset > ^uint64(0)-InlineDataOffset {
			return nil, corruptf("an inline inode's byte offset overflows")
		}
		return &Ocfs2FileSource{
			id:         id,
			source:     src,
			superblock: superblock,
			data:       fileData{inline: true, bytes: append([]byte(nil), inode.Inline...), at: offset + InlineDataOffset},
			size:       size,
			blockSize:  blockSize,
		}, nil
	}

	list := inode.List
	if list == nil {
		return nil, corruptf("inode block %d has no extent list and no inline data", inode.Block)
	}
	mapData, err := ResolveExtents(superblock, src, inode.Block, list, inode.Clusters)
	if err != nil {
		return nil, err
	}
	clusterSize := uint64(superblock.ClusterSize)
	extents := make([]Extent, 0, len(mapData.Extents))
	logical := uint64(0)
	physicalTotal := uint64(0)
	for _, record := range mapData.Extents {
		runLogical := record.LogicalCluster * clusterSize
		if record.LogicalCluster != 0 && runLogical/record.LogicalCluster != clusterSize {
			return nil, corruptf("a logical extent overflows")
		}
		runPhysical := record.PhysicalBlock * blockSize
		if record.PhysicalBlock != 0 && runPhysical/record.PhysicalBlock != blockSize {
			return nil, corruptf("a physical extent overflows")
		}
		length := record.Clusters * clusterSize
		if record.Clusters != 0 && length/record.Clusters != clusterSize {
			return nil, corruptf("an extent length overflows")
		}
		if runLogical != logical {
			return nil, corruptf("inode block %d's extents are not contiguous at logical byte %d",
				inode.Block, logical)
		}
		if uint64(len(extents)) >= MaxFileExtents {
			return nil, unsupportedf("inode block %d needs more than %d extents", inode.Block, MaxFileExtents)
		}
		extents = append(extents, Extent{Logical: runLogical, Physical: runPhysical, Len: length})
		logical += length
		if logical < length {
			return nil, corruptf("a file's logical size overflows")
		}
		physicalTotal += length
		if physicalTotal < length {
			return nil, corruptf("a file's allocation overflows")
		}
	}
	allocated := uint64(inode.Clusters) * clusterSize
	if uint64(inode.Clusters) != 0 && allocated/uint64(inode.Clusters) != clusterSize {
		return nil, corruptf("a file's allocation overflows")
	}
	if physicalTotal != allocated {
		return nil, corruptf("inode block %d's extents cover %d bytes but it allocates %d",
			inode.Block, physicalTotal, allocated)
	}
	if logical < size {
		return nil, corruptf("inode block %d's extents end at byte %d, before its declared %d",
			inode.Block, logical, size)
	}

	return &Ocfs2FileSource{
		id:            id,
		source:        src,
		superblock:    superblock,
		data:          fileData{extents: extents},
		size:          size,
		blockSize:     blockSize,
		extentBlocks:  mapData.ExtentBlocks,
		extentRecords: mapData.Records,
	}, nil
}

// Len returns the inode's declared length.
func (f *Ocfs2FileSource) Len() uint64 { return f.size }

// IsEmpty reports whether the file declares no bytes.
func (f *Ocfs2FileSource) IsEmpty() bool { return f.size == 0 }

// ExtentRuns returns the resolved byte extents; empty for an inline file.
func (f *Ocfs2FileSource) ExtentRuns() []Extent { return f.data.extents }

// Inline reports whether the bytes live in the dinode.
func (f *Ocfs2FileSource) Inline() bool { return f.data.inline }

// ExtentBlocksRead returns extent blocks read resolving the map.
func (f *Ocfs2FileSource) ExtentBlocksRead() uint64 { return f.extentBlocks }

// ExtentRecords returns extent records examined resolving the map.
func (f *Ocfs2FileSource) ExtentRecords() uint64 { return f.extentRecords }

// AllocatedBytes returns the bytes the file allocates. Inline data allocates no
// clusters.
func (f *Ocfs2FileSource) AllocatedBytes() uint64 {
	var total uint64
	for _, extent := range f.data.extents {
		total += extent.Len
	}
	return total
}

// PhysicalBlockAt returns the physical block holding offset, for an
// extent-mapped stream.
func (f *Ocfs2FileSource) PhysicalBlockAt(offset uint64) (uint64, error) {
	if f.data.inline {
		return 0, corruptf("an inline stream has no separate physical block")
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

func (f *Ocfs2FileSource) extentAt(logical uint64) (Extent, error) {
	if len(f.data.extents) == 0 {
		return Extent{}, corruptf("the file has data but its block map is empty")
	}
	after := sort.Search(len(f.data.extents), func(index int) bool {
		return f.data.extents[index].Logical > logical
	})
	if after == 0 {
		return Extent{}, corruptf("logical byte %d is before the first mapped extent", logical)
	}
	extent := f.data.extents[after-1]
	end := extent.Logical + extent.Len
	if end < extent.Logical {
		end = ^uint64(0)
	}
	if logical >= end {
		return Extent{}, corruptf("logical byte %d is a hole between mapped extents", logical)
	}
	return extent, nil
}

func (f *Ocfs2FileSource) readAt(offset uint64, buf []byte) (int, error) {
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
	if f.data.inline {
		start := int(offset)
		copy(buf[:want], f.data.bytes[start:start+want])
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

func (f *Ocfs2FileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	if f.data.inline {
		at := f.data.at + offset
		if at < f.data.at {
			return out, corruptf("an inline range overflows")
		}
		out = append(out, source.ParentRange{Parent: parent, ParentOffset: at, Len: length, Kind: source.RangeData})
		return out, nil
	}
	end := offset + length
	startIndex := sort.Search(len(f.data.extents), func(index int) bool {
		return f.data.extents[index].Logical > offset
	})
	if startIndex > 0 {
		startIndex--
	}
	var covered uint64
	for _, extent := range f.data.extents[startIndex:] {
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
func (f *Ocfs2FileSource) SourceID() source.ID { return f.id }

// ImageID implements source.ByteSource.
func (f *Ocfs2FileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *Ocfs2FileSource) SectorSize() uint32 { return f.source.SectorSize() }

// ReadAt implements source.ByteSource with strict semantics.
func (f *Ocfs2FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
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
func (f *Ocfs2FileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
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
func (f *Ocfs2FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	ranges, err := f.extentsInto(f.source.SourceID(), offset, length, out)
	if err != nil {
		return ranges, mapSourceError(err)
	}
	return ranges, nil
}

// Extents implements source.ByteSource.
func (f *Ocfs2FileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *Ocfs2FileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
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
func (f *Ocfs2FileSource) Stats() source.Stats { return f.counters.Snapshot() }

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

var _ source.ByteSource = (*Ocfs2FileSource)(nil)
