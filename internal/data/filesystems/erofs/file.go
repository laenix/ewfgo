package erofs

import (
	"sort"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

// A file's data exposed as a source.ByteSource.
//
// A flat-plain inode names the block its data starts at; the data occupies
// that block and the ones after it contiguously, with the last block stored
// whole even though the declared length is exact. A block address of zero
// names a hole: block zero holds the superblock, so no file can start there,
// and every byte reads as zero.
//
// A flat-inline inode keeps its data inside the inode's own block, starting
// right after the inode and its xattr body.
//
// A compressed inode serves the pcluster extents its index names. Holes read
// as zeroes; a stored pcluster is decoded by the algorithm its HEAD names.

type run struct {
	offset uint64 // absolute image offset; zero for a hole
	length uint64 // logical bytes the run covers
	hole   bool
}

type compressedStream struct {
	extents      []extent
	lclusterSize uint64
	blockSize    uint64
	mu           sync.Mutex
	cached       bool
	cacheIndex   int
	cacheBytes   []byte
}

type fileSource struct {
	id         source.ID
	src        source.ByteSource
	runs       []run
	compressed *compressedStream
	size       uint64
	allocated  uint64
	counters   source.Counters
}

func newPlainFileSource(id source.ID, src source.ByteSource, startBlock uint32,
	size, blockSize, limit uint64) (*fileSource, error) {
	f := &fileSource{id: id, src: src, size: size}
	if size == 0 {
		return f, nil
	}
	if startBlock == 0 {
		f.runs = []run{{length: size, hole: true}}
		return f, nil
	}
	blocks := size / blockSize
	if size%blockSize != 0 {
		blocks++
	}
	stored, ok := checkedMul(blocks, blockSize)
	if !ok {
		return nil, corruptf("a file's stored size overflows the address space")
	}
	start, ok := checkedMul(uint64(startBlock), blockSize)
	if !ok {
		return nil, corruptf("a file's start block overflows the address space")
	}
	if start > limit || stored > limit-start {
		return nil, corruptf("the %d-block file at byte %d runs past byte %d",
			blocks, start, limit)
	}
	f.allocated = stored
	f.runs = []run{{offset: start, length: stored}}
	return f, nil
}

func newInlineFileSource(id source.ID, src source.ByteSource, start, size, limit uint64) (*fileSource, error) {
	if start > limit || size > limit-start {
		return nil, corruptf("inline data at %d of %d bytes runs past byte %d",
			start, size, limit)
	}
	f := &fileSource{id: id, src: src, size: size, allocated: size}
	if size > 0 {
		f.runs = []run{{offset: start, length: size}}
	}
	return f, nil
}

func newCompressedFileSource(id source.ID, src source.ByteSource, extents []extent,
	lclusterSize, blockSize, size, limit uint64) (*fileSource, error) {
	var logical, allocated uint64
	for _, e := range extents {
		if e.logical != logical {
			return nil, corruptf(
				"the pcluster at logical byte %d does not continue the one ending at %d",
				e.logical, logical)
		}
		if !e.hole {
			at, ok := checkedMul(uint64(e.pblk), blockSize)
			if !ok {
				return nil, corruptf("the pcluster at logical byte %d overflows the address space",
					e.logical)
			}
			if at > limit || e.stored > limit-at {
				return nil, corruptf(
					"the pcluster at logical byte %d stores bytes past the image's %d",
					e.logical, limit)
			}
			if allocated > ^uint64(0)-e.stored {
				return nil, corruptf("a pcluster's stored bytes overflow")
			}
			allocated += e.stored
		}
		nextLogical, ok := checkedAdd(e.logical, e.length)
		if !ok {
			return nil, corruptf("a pcluster end overflows the address space")
		}
		logical = nextLogical
	}
	if logical != size {
		return nil, corruptf("the pcluster index ends at logical byte %d, not the file's %d",
			logical, size)
	}
	return &fileSource{
		id:   id,
		src:  src,
		size: size,
		compressed: &compressedStream{
			extents:      extents,
			lclusterSize: lclusterSize,
			blockSize:    blockSize,
		},
		allocated: allocated,
	}, nil
}

func (f *fileSource) isHole() bool {
	if f.size == 0 {
		return false
	}
	if f.compressed != nil {
		for _, e := range f.compressed.extents {
			if !e.hole {
				return false
			}
		}
		return true
	}
	for _, r := range f.runs {
		if !r.hole {
			return false
		}
	}
	return true
}

func (f *fileSource) allocatedBytes() uint64 { return f.allocated }

func (f *fileSource) readAtInternal(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := f.size - offset
	if want > uint64(len(buf)) {
		want = uint64(len(buf))
	}
	out := buf[:want]
	end := offset + want
	if f.compressed != nil {
		return len(out), f.readCompressed(f.compressed, offset, end, out)
	}
	var logical uint64
	for _, r := range f.runs {
		start := logical
		logical += r.length
		if logical <= offset {
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
		if logical < to {
			to = logical
		}
		if from >= to {
			continue
		}
		at := from - offset
		n := to - from
		if r.hole {
			for i := at; i < at+n; i++ {
				out[i] = 0
			}
		} else {
			physical := r.offset + (from - start)
			if err := source.ReadExactAt(f.src, physical, out[at:at+n]); err != nil {
				return 0, err
			}
		}
	}
	return int(want), nil
}

func (f *fileSource) readCompressed(stream *compressedStream, offset, end uint64, out []byte) error {
	first := sort.Search(len(stream.extents), func(i int) bool {
		e := stream.extents[i]
		return e.logical+e.length > offset
	})
	for index := first; index < len(stream.extents); index++ {
		e := stream.extents[index]
		if e.logical >= end {
			break
		}
		from := offset
		if e.logical > from {
			from = e.logical
		}
		to := end
		if e.logical+e.length < to {
			to = e.logical + e.length
		}
		if from >= to {
			continue
		}
		decoded, err := f.decodedExtent(stream, index)
		if err != nil {
			return err
		}
		start := from - e.logical
		length := to - from
		at := from - offset
		copy(out[at:at+length], decoded[start:start+length])
	}
	return nil
}

func (f *fileSource) decodedExtent(stream *compressedStream, index int) ([]byte, error) {
	stream.mu.Lock()
	if stream.cached && stream.cacheIndex == index {
		bytes := stream.cacheBytes
		stream.mu.Unlock()
		return bytes, nil
	}
	stream.mu.Unlock()

	if index >= len(stream.extents) {
		return nil, corruptf("pcluster %d is past the extent list", index)
	}
	e := stream.extents[index]
	bytes, err := decodeExtent(f.src, e, stream.blockSize, stream.lclusterSize)
	if err != nil {
		return nil, err
	}
	if uint64(len(bytes)) != e.length {
		return nil, corruptf("pcluster %d decoded to %d bytes but covers %d",
			index, len(bytes), e.length)
	}
	stream.mu.Lock()
	stream.cached = true
	stream.cacheIndex = index
	stream.cacheBytes = bytes
	stream.mu.Unlock()
	return bytes, nil
}

func (f *fileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	if f.compressed != nil {
		first := sort.Search(len(f.compressed.extents), func(i int) bool {
			e := f.compressed.extents[i]
			return e.logical+e.length > offset
		})
		for index := first; index < len(f.compressed.extents); index++ {
			e := f.compressed.extents[index]
			if e.logical >= end {
				break
			}
			if e.hole {
				from := offset
				if e.logical > from {
					from = e.logical
				}
				to := end
				if e.logical+e.length < to {
					to = e.logical + e.length
				}
				if from < to {
					out = append(out, source.ParentRange{
						Parent: parent,
						Len:    to - from,
						Kind:   source.RangeZero,
					})
				}
			} else {
				// A compressed extent's bytes are derived from the whole
				// stored pcluster, so that is the region reported.
				out = append(out, source.ParentRange{
					Parent:       parent,
					ParentOffset: uint64(e.pblk) * f.compressed.blockSize,
					Len:          e.stored,
					Kind:         source.RangeData,
				})
			}
		}
		return out, nil
	}
	var logical uint64
	for _, r := range f.runs {
		start := logical
		logical += r.length
		if logical <= offset {
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
		if logical < to {
			to = logical
		}
		if from >= to {
			continue
		}
		kind := source.RangeData
		physical := r.offset + (from - start)
		if r.hole {
			kind = source.RangeZero
			physical = 0
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: physical,
			Len:          to - from,
			Kind:         kind,
		})
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
	want := f.size - offset
	if want > uint64(len(buf)) {
		want = uint64(len(buf))
	}
	if got, err := f.readAtInternal(offset, buf[:want]); err == nil {
		return got, nil
	}
	for i := uint64(0); i < want; i++ {
		buf[i] = 0
	}
	f.counters.AddCorrupt(want)
	return int(want), nil
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

func checkedAdd(a, b uint64) (uint64, bool) {
	if a > ^uint64(0)-b {
		return 0, false
	}
	return a + b, true
}

func checkedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
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
