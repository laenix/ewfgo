package hammer2

import (
	"errors"
	"math"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// LogicalBlock is the logical block size every HAMMER2 file uses.
const LogicalBlock uint64 = 65_536

// MinBlockBytes is HAMMER2_ALLOC_MIN, the smallest data allocation.
const MinBlockBytes uint64 = 1024

// MaxExtents is the most byte extents one file's map may hold.
const MaxExtents uint64 = 1_000_000

const maxFileBrefs = MaxExtents * 8

const maxFileDepth = 16

// Extent is one logical-to-physical block run, in bytes.
type Extent struct {
	Logical   uint64
	Physical  uint64
	Len       uint64
	CheckAlgo uint8
	Check     [64]byte
}

func (e *Extent) verify(bytes []byte, what string) error {
	return verifyCheckCode(e.CheckAlgo, e.Check[:], bytes, what)
}

// ExtentMap is the output of one strict block-tree scan.
type ExtentMap struct {
	Extents []Extent
	// IndirectBlocks is the indirect blocks read and verified.
	IndirectBlocks uint64
	// DataRefs is the data references collected.
	DataRefs uint64
}

func collectDataRefs(src source.ByteSource, ref *Blockref, what string, depth uint32,
	scanned, indirectBlocks *uint64, out *[]Blockref) error {
	if depth > maxFileDepth {
		return corruptf("%s nests deeper than the %d-level limit", what, maxFileDepth)
	}
	*scanned = *scanned + 1
	if *scanned > maxFileBrefs {
		return unsupportedf("%s needs more than %d tree references", what, maxFileBrefs)
	}
	switch ref.BType {
	case BrefTypeEmpty:
		return nil
	case BrefTypeData:
		if err := ref.ValidateMethods(what); err != nil {
			return err
		}
		if uint64(len(*out)) >= MaxExtents {
			return unsupportedf("%s needs more than %d data blocks", what, MaxExtents)
		}
		*out = append(*out, *ref)
		return nil
	case BrefTypeIndirect:
		radix := ref.Radix()
		if radix < 12 || radix > 16 {
			return corruptf("%s has an indirect block with radix %d; HAMMER2 indirect blocks are 4096 through 65536 bytes",
				what, radix)
		}
		block, err := ref.ReadBytes(src, what+" indirect block")
		if err != nil {
			return err
		}
		*indirectBlocks = *indirectBlocks + 1
		for index := 0; index < len(block)/BlockrefBytes; index++ {
			child, err := ParseBlockref(block[index*BlockrefBytes:(index+1)*BlockrefBytes],
				what+" indirect slot")
			if err != nil {
				return err
			}
			if err := collectDataRefs(src, child, what, depth+1, scanned, indirectBlocks, out); err != nil {
				return err
			}
		}
		return nil
	case BrefTypeInode, BrefTypeDirent:
		return corruptf("%s contains a %s reference in its data tree", what, TypeLabel(ref.BType))
	default:
		return unsupportedf("%s contains a %s reference in its data tree", what, TypeLabel(ref.BType))
	}
}

// resolveExtents builds the byte extent map for a block-mapped file. Every
// data reference is checked for a legal key, size and radix; holes are left
// implicit.
func resolveExtents(src source.ByteSource, inode *Inode, what string) (*ExtentMap, error) {
	if inode.IsDirectData() {
		return nil, corruptf("%s stores its data inside the inode; there is no block map", what)
	}
	if inode.Blockset == nil {
		return nil, corruptf("%s has no blockset", what)
	}
	size := inode.Size

	var references []Blockref
	var scanned, indirectBlocks uint64
	for index := range inode.Blockset.Refs() {
		root := inode.Blockset.Refs()[index]
		if root.BType == BrefTypeEmpty {
			continue
		}
		if err := collectDataRefs(src, &root, what, 0, &scanned, &indirectBlocks, &references); err != nil {
			return nil, err
		}
	}

	sort.SliceStable(references, func(left, right int) bool { return references[left].Key < references[right].Key })
	extents := make([]Extent, 0, len(references))
	var previousKey uint64
	havePrevious := false
	for index := range references {
		ref := &references[index]
		key := ref.Key
		if key&DirhashVisible != 0 {
			return nil, corruptf("%s has a data block key 0x%016x with bit 63 set", what, key)
		}
		if key&(LogicalBlock-1) != 0 {
			return nil, corruptf("%s has a data block key 0x%x, which is not %d byte aligned",
				what, key, LogicalBlock)
		}
		if key >= size {
			return nil, corruptf("%s has a data block at logical byte %d, past the %d-byte end of file",
				what, key, size)
		}
		if havePrevious && previousKey == key {
			// Fully associative sets may hold redundant copies of one
			// logical block; the kernel reads the first.
			continue
		}
		previousKey = key
		havePrevious = true

		radix := ref.Radix()
		if radix < 10 || radix > 16 {
			return nil, corruptf("%s has a data block with radix %d; HAMMER2 data allocations are %d through %d bytes",
				what, radix, MinBlockBytes, LogicalBlock)
		}
		length := uint64(1) << radix
		// key < size and length is at most one logical block, but a crafted
		// size near the top of the address space can still make the logical
		// end wrap. Every later range computation assumes it does not.
		if key > math.MaxUint64-length {
			return nil, corruptf("%s has a data block at logical byte %d covering %d bytes, which overflows the address space",
				what, key, length)
		}
		remaining := size - key
		if remaining >= LogicalBlock {
			if length != LogicalBlock {
				return nil, corruptf("%s has a %d-byte allocation at logical byte %d, which is not the end of the file; a full logical block must allocate %d bytes",
					what, length, key, LogicalBlock)
			}
		} else if length < remaining {
			return nil, corruptf("%s has a %d-byte allocation at logical byte %d but %d bytes remain; the block is too small",
				what, length, key, remaining)
		}
		physical := ref.PhysicalOffset()
		if physical == 0 {
			return nil, corruptf("%s maps logical byte %d to physical offset 0, which holds the volume header",
				what, key)
		}
		end := physical + length
		if end < physical {
			return nil, corruptf("%s: physical offset 0x%x overflows", what, physical)
		}
		if end > src.Len() {
			return nil, corruptf("%s maps logical byte %d to bytes 0x%x..0x%x, past the %d bytes the source holds",
				what, key, physical, end, src.Len())
		}
		extents = append(extents, Extent{
			Logical:   key,
			Physical:  physical,
			Len:       length,
			CheckAlgo: ref.CheckAlgo(),
			Check:     ref.Check,
		})
	}

	return &ExtentMap{Extents: extents, IndirectBlocks: indirectBlocks, DataRefs: uint64(len(references))}, nil
}

// FileSource is a regular file or block-mapped symbolic link inside a
// HAMMER2 image, readable as a byte source. Logical blocks with no reference
// are holes; HAMMER2 defines a hole read as zero bytes, and ranges are
// exported as RangeHole so a consumer can tell them from stored zeros.
type FileSource struct {
	id             source.ID
	source         source.ByteSource
	extents        []Extent
	size           uint64
	embedded       bool
	indirectBlocks uint64
	dataRefs       uint64
	counters       source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, inode *Inode) (*FileSource, error) {
	if inode.Kind != KindRegular && inode.Kind != KindSymlink {
		return nil, corruptf("the inode is a %s, which has no file data stream", inode.Kind)
	}
	size := inode.Size
	if inode.IsDirectData() {
		if inode.MediaOffset == nil {
			return nil, corruptf("an embedded inode has no recorded physical offset")
		}
		physical := *inode.MediaOffset + UnionOffset
		if physical < *inode.MediaOffset {
			return nil, corruptf("the embedded data offset overflows")
		}
		var extents []Extent
		if size != 0 {
			extents = []Extent{{
				Logical:   0,
				Physical:  physical,
				Len:       size,
				CheckAlgo: CheckNone,
			}}
		}
		return &FileSource{
			id:       id,
			source:   src,
			extents:  extents,
			size:     size,
			embedded: true,
		}, nil
	}
	extentMap, err := resolveExtents(src, inode, "the file")
	if err != nil {
		return nil, err
	}
	return &FileSource{
		id:             id,
		source:         src,
		extents:        extentMap.Extents,
		size:           size,
		indirectBlocks: extentMap.IndirectBlocks,
		dataRefs:       extentMap.DataRefs,
	}, nil
}

// Runs returns the resolved byte extents. Logical gaps between them are
// holes.
func (f *FileSource) Runs() []Extent { return f.extents }

// ExtentBlocksRead returns the indirect blocks read while resolving the map.
func (f *FileSource) ExtentBlocksRead() uint64 { return f.indirectBlocks }

// ExtentRecords returns the data references collected while resolving the
// map.
func (f *FileSource) ExtentRecords() uint64 { return f.dataRefs }

// AllocatedBytes returns the bytes the file physically allocates. Embedded
// data allocates nothing outside its inode.
func (f *FileSource) AllocatedBytes() uint64 {
	if f.embedded {
		return 0
	}
	var total uint64
	for _, extent := range f.extents {
		total += extent.Len
	}
	return total
}

func partitionPointExtents(extents []Extent, predicate func(Extent) bool) int {
	low, high := 0, len(extents)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if predicate(extents[middle]) {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low
}

func (f *FileSource) readExtent(extent *Extent, inside uint64, buf []byte) error {
	block := make([]byte, int(extent.Len))
	if err := source.ReadExactAt(f.source, extent.Physical, block); err != nil {
		return err
	}
	if err := extent.verify(block, "a file data block"); err != nil {
		return err
	}
	start := inside
	if start > uint64(len(block)) || uint64(len(buf)) > uint64(len(block))-start {
		return corruptf("an extent read runs past its %d-byte allocation", extent.Len)
	}
	copy(buf, block[start:start+uint64(len(buf))])
	return nil
}

// readAt reads with HAMMER2 hole semantics: an unmapped logical block reads
// as zero bytes.
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
	end := offset + uint64(want)
	done := 0
	for done < want {
		logical := offset + uint64(done)
		index := partitionPointExtents(f.extents, func(extent Extent) bool {
			return extent.Logical+extent.Len <= logical
		})
		if index < len(f.extents) && f.extents[index].Logical <= logical {
			extent := &f.extents[index]
			inside := logical - extent.Logical
			take := extent.Len - inside
			if uint64(want-done) < take {
				take = uint64(want - done)
			}
			if take == 0 {
				return done, corruptf("a file's data map has a zero-length extent")
			}
			if err := f.readExtent(extent, inside, buf[done:done+int(take)]); err != nil {
				return done, err
			}
			done += int(take)
			continue
		}
		// A hole: fill to the next extent (or the request's end).
		next := uint64(math.MaxUint64)
		if index < len(f.extents) {
			next = f.extents[index].Logical
		}
		stop := next
		if stop > end {
			stop = end
		}
		take := stop - logical
		if take == 0 {
			return done, corruptf("a hole at logical byte %d has no width", logical)
		}
		clear(buf[done : done+int(take)])
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
	position := offset
	index := partitionPointExtents(f.extents, func(extent Extent) bool {
		return extent.Logical+extent.Len <= position
	})
	for position < end {
		if index < len(f.extents) && f.extents[index].Logical <= position {
			extent := f.extents[index]
			to := extent.Logical + extent.Len
			if to > end {
				to = end
			}
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: extent.Physical + (position - extent.Logical),
				Len:          to - position,
				Kind:         source.RangeData,
			})
			position = to
			index++
			continue
		}
		next := uint64(math.MaxUint64)
		if index < len(f.extents) {
			next = f.extents[index].Logical
		}
		stop := next
		if stop > end {
			stop = end
		}
		if stop <= position {
			return out, corruptf("a hole at logical byte %d has no width", position)
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: 0,
			Len:          stop - position,
			Kind:         source.RangeHole,
		})
		position = stop
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
		return got, mapSourceError(err)
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
