package befs

import "github.com/laenix/ewfgo/internal/data/source"

// MaxExtents is the most extents one file's map may hold.
const MaxExtents uint64 = 1_000_000

// extent is one logical-to-physical run, in byte units.
type extent struct {
	logical  uint64
	physical uint64
	len      uint64
}

// fileSource is a regular file, directory tree stream or long symbolic link.
type fileSource struct {
	id          source.ID
	src         source.ByteSource
	extents     []extent
	size        uint64
	arrayBlocks uint64
	counters    source.Counters
}

// newFileSource resolves an inode's data stream.
func newFileSource(id source.ID, src source.ByteSource, sb *superblock, inode *inode) (*fileSource, error) {
	if inode.shortSymlink != nil {
		return nil, corruptf("inode block %d is a short symbolic link and has no data stream", inode.block)
	}
	switch inode.kind {
	case KindFile, KindDirectory, KindSymlink:
	default:
		return nil, corruptf("inode block %d is a %s, which has no file data", inode.block, inode.kind.label())
	}
	blockSize := uint64(sb.blockSize)
	size := inode.size
	if uint64(sb.numBlocks) > (^uint64(0))/blockSize {
		return nil, corruptf("the volume's byte size overflows")
	}
	volumeBytes := uint64(sb.numBlocks) * blockSize
	if size > volumeBytes {
		return nil, corruptf("inode block %d declares %d bytes, more than the %d-byte volume",
			inode.block, size, volumeBytes)
	}
	out := &fileSource{id: id, src: src, size: size}
	if size > 0 {
		if err := resolveStream(sb, src, inode, size, blockSize, &out.extents, &out.arrayBlocks); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// resolveStream builds the extent map.
func resolveStream(sb *superblock, src source.ByteSource, inode *inode, size, blockSize uint64,
	extents *[]extent, arrayBlocks *uint64) error {
	data := &inode.data
	logical := uint64(0)

	for _, run := range data.direct {
		if logical >= size {
			break
		}
		if run.isZero() {
			break
		}
		block, ok, err := sb.validateRun(run, "a direct data run")
		if err != nil {
			return err
		}
		if !ok {
			return corruptf("a direct data run is the zero run where data is required")
		}
		length, err := mulCheck(uint64(run.length), blockSize)
		if err != nil {
			return corruptf("a direct data run overflows the byte address space")
		}
		if err := pushExtent(extents, logical, block, length, blockSize); err != nil {
			return err
		}
		logical += length
	}

	if logical < size {
		if data.indirect.isZero() {
			return corruptf("inode block %d maps %d of its %d bytes and has no indirect run",
				inode.block, logical, size)
		}
		if uint64(data.maxDirectRange) != logical {
			return corruptf("inode block %d's direct runs cover %d bytes, but max_direct_range is %d",
				inode.block, logical, uint64(data.maxDirectRange))
		}
		if data.indirect.length == 0 {
			return corruptf("the indirect run has zero length")
		}
		first, ok, err := sb.validateRun(data.indirect, "the indirect array")
		if err != nil {
			return err
		}
		if !ok {
			return corruptf("the indirect array is the zero run")
		}
		runsPerBlock := blockSize / 8
		if runsPerBlock == 0 {
			return corruptf("the block size does not hold one block run")
		}
		for index := uint64(0); index < uint64(data.indirect.length); index++ {
			if logical >= size {
				break
			}
			if first > (^uint64(0))-index {
				return corruptf("an indirect array block overflows")
			}
			table, err := readRunTable(sb, src, first+index, runsPerBlock, arrayBlocks)
			if err != nil {
				return err
			}
			for _, run := range table {
				if logical >= size {
					break
				}
				if run.isZero() {
					continue
				}
				block, ok, err := sb.validateRun(run, "an indirect data run")
				if err != nil {
					return err
				}
				if !ok {
					return corruptf("an indirect data run is the zero run")
				}
				length, err := mulCheck(uint64(run.length), blockSize)
				if err != nil {
					return corruptf("an indirect data run overflows the byte address space")
				}
				if err := pushExtent(extents, logical, block, length, blockSize); err != nil {
					return err
				}
				logical += length
			}
		}
	}

	if logical < size {
		if data.doubleIndirect.isZero() {
			return corruptf("inode block %d maps %d of its %d bytes and has no double-indirect run",
				inode.block, logical, size)
		}
		if uint64(data.maxIndirectRange) != logical {
			return corruptf("inode block %d's indirect runs cover %d bytes, but max_indirect_range is %d",
				inode.block, logical, uint64(data.maxIndirectRange))
		}
		first, ok, err := sb.validateRun(data.doubleIndirect, "the double-indirect array")
		if err != nil {
			return err
		}
		if !ok {
			return corruptf("the double-indirect array is the zero run")
		}
		runsPerBlock := blockSize / 8
		if runsPerBlock == 0 {
			return corruptf("the block size does not hold one block run")
		}
		length := uint64(data.doubleIndirect.length)
		if length == 0 {
			return corruptf("the double-indirect run has zero length")
		}
		directSize, err := mulCheck(length, blockSize)
		if err != nil {
			return corruptf("a double-indirect unit overflows")
		}
		unitSize, err := mulCheck(length, directSize)
		if err != nil {
			return corruptf("a double-indirect range overflows")
		}
		indirectSize, err := mulCheck(unitSize, runsPerBlock)
		if err != nil {
			return corruptf("a double-indirect range overflows")
		}
		if directSize == 0 || indirectSize == 0 {
			return corruptf("a double-indirect range has zero size")
		}
		remaining := size - logical
		dataRuns := ceilDiv(remaining, directSize)
		if dataRuns > MaxExtents {
			return unsupportedf("inode block %d needs %d double-indirect data runs, more than the %d-extent mapping cap",
				inode.block, dataRuns, MaxExtents)
		}
		indexCount := ceilDiv(remaining, indirectSize)
		for index := uint64(0); index < indexCount; index++ {
			topIndex := index / runsPerBlock
			if first > (^uint64(0))-topIndex {
				return corruptf("a double-indirect top block overflows")
			}
			top, err := readRunTable(sb, src, first+topIndex, runsPerBlock, arrayBlocks)
			if err != nil {
				return err
			}
			topEntry := top[index%runsPerBlock]
			if topEntry.isZero() {
				return corruptf("double-indirect top entry %d is zero while inode block %d still has bytes to map",
					index, inode.block)
			}
			if uint64(topEntry.length) != length {
				return corruptf("double-indirect top run %d has length %d, expected %d",
					index, topEntry.length, length)
			}
			topData, ok, err := sb.validateRun(topEntry, "a double-indirect top run")
			if err != nil {
				return err
			}
			if !ok {
				return corruptf("a double-indirect top run is the zero run")
			}
			units, err := mulCheck(length, runsPerBlock)
			if err != nil {
				return corruptf("a double-indirect unit count overflows")
			}
			for current := uint64(0); current < units; current++ {
				withinCurrent, err := mulCheck(current, directSize)
				if err != nil {
					return corruptf("a double-indirect logical offset overflows")
				}
				withinIndex, err := mulCheck(index, indirectSize)
				if err != nil {
					return corruptf("a double-indirect logical offset overflows")
				}
				if withinIndex > (^uint64(0))-withinCurrent {
					return corruptf("a double-indirect logical offset overflows")
				}
				withinIndex += withinCurrent
				if logical > (^uint64(0))-withinIndex {
					return corruptf("a double-indirect logical offset overflows")
				}
				at := logical + withinIndex
				if at >= size {
					break
				}
				secondIndex := current / runsPerBlock
				if topData > (^uint64(0))-secondIndex {
					return corruptf("a double-indirect second-level block overflows")
				}
				second, err := readRunTable(sb, src, topData+secondIndex, runsPerBlock, arrayBlocks)
				if err != nil {
					return err
				}
				run := second[current%runsPerBlock]
				if run.isZero() {
					return corruptf("double-indirect data entry %d is zero while inode block %d still has bytes to map",
						current, inode.block)
				}
				if uint64(run.length) != length {
					return corruptf("double-indirect data run %d has length %d, expected %d",
						current, run.length, length)
				}
				block, ok, err := sb.validateRun(run, "a double-indirect data run")
				if err != nil {
					return err
				}
				if !ok {
					return corruptf("a double-indirect data run is the zero run")
				}
				if err := pushExtent(extents, at, block, directSize, blockSize); err != nil {
					return err
				}
			}
		}
		logical = size
	}

	if logical < size {
		return corruptf("inode block %d's runs map only %d of its %d bytes", inode.block, logical, size)
	}
	return validateMap(*extents, size, blockSize)
}

// pushExtent appends one extent and enforces the mapping cap.
func pushExtent(extents *[]extent, logical, block, length, blockSize uint64) error {
	if length == 0 || length%blockSize != 0 {
		return corruptf("a data run at logical byte %d has length %d, not a whole number of blocks", logical, length)
	}
	if uint64(len(*extents)) >= MaxExtents {
		return unsupportedf("the file needs more than %d extents", MaxExtents)
	}
	if len(*extents) > 0 {
		previous := (*extents)[len(*extents)-1]
		end := previous.logical + previous.len
		if end < previous.logical {
			return corruptf("an extent ends past the address space")
		}
		if end != logical {
			return corruptf("the data map is not contiguous: an extent ends at %d but the next starts at %d", end, logical)
		}
	} else if logical != 0 {
		return corruptf("the data map starts at logical byte %d, not 0", logical)
	}
	physical, err := mulCheck(block, blockSize)
	if err != nil {
		return corruptf("a data block overflows the byte address space")
	}
	*extents = append(*extents, extent{logical: logical, physical: physical, len: length})
	return nil
}

// validateMap checks that every byte of the declared size is mapped and no
// extent overlaps.
func validateMap(extents []extent, size, blockSize uint64) error {
	if size == 0 {
		return nil
	}
	if len(extents) == 0 {
		return corruptf("the file has data but its block map is empty")
	}
	if extents[0].logical != 0 {
		return corruptf("the file's first extent does not start at byte 0")
	}
	end := uint64(0)
	for _, value := range extents {
		if value.len == 0 || value.len%blockSize != 0 {
			return corruptf("an extent is not a whole number of blocks")
		}
		if value.logical != end {
			return corruptf("the file's extents are not contiguous at logical byte %d", value.logical)
		}
		end = value.logical + value.len
		if end < value.logical {
			return corruptf("an extent ends past the address space")
		}
	}
	if end < size {
		return corruptf("the file's block map ends at %d, before its declared %d bytes", end, size)
	}
	return nil
}

// readRunTable reads one block of block runs.
func readRunTable(sb *superblock, src source.ByteSource, block, runsPerBlock uint64, arrayBlocks *uint64) ([]blockRun, error) {
	if block == 0 || block >= uint64(sb.numBlocks) {
		return nil, corruptf("a data-stream array block %d is outside the %d blocks of the volume",
			block, sb.numBlocks)
	}
	at := sb.blockOffset(block)
	if at == ^uint64(0) {
		return nil, corruptf("array block %d overflows the byte address space", block)
	}
	size := int(sb.blockSize)
	if size <= 0 {
		return nil, corruptf("the block size does not fit in memory")
	}
	raw := make([]byte, size)
	if err := source.ReadExactAt(src, at, raw); err != nil {
		return nil, err
	}
	count := int(runsPerBlock)
	if count < 0 {
		return nil, corruptf("the runs per block does not fit in memory")
	}
	runs := make([]blockRun, 0, count)
	for index := 0; index < count; index++ {
		runs = append(runs, parseBlockRun(raw[index*8:index*8+8]))
	}
	*arrayBlocks++
	return runs, nil
}

func (f *fileSource) len() uint64   { return f.size }
func (f *fileSource) isEmpty() bool { return f.size == 0 }

// allocatedBytes is every named data run counted whole; the array blocks are
// metadata, not file data.
func (f *fileSource) allocatedBytes() uint64 {
	var total uint64
	for _, value := range f.extents {
		total += value.len
	}
	return total
}

func (f *fileSource) arrayBlocksRead() uint64 { return f.arrayBlocks }

func (f *fileSource) readAt(offset uint64, buf []byte) (int, error) {
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
		value, err := f.extentAt(logical)
		if err != nil {
			return done, err
		}
		inside := logical - value.logical
		if inside >= value.len {
			return done, corruptf("logical byte %d is past its mapped extent", logical)
		}
		available := value.len - inside
		take := uint64(want - done)
		if take > available {
			take = available
		}
		if take == 0 {
			return done, corruptf("the data map for inode %d has a zero-length extent", f.id)
		}
		at := value.physical + inside
		if at < value.physical {
			return done, corruptf("a data extent's physical offset overflows")
		}
		if err := source.ReadExactAt(f.src, at, buf[done:done+int(take)]); err != nil {
			return done, err
		}
		done += int(take)
	}
	return want, nil
}

func (f *fileSource) extentAt(logical uint64) (extent, error) {
	if len(f.extents) == 0 {
		return extent{}, corruptf("the file has data but its block map is empty")
	}
	low, high := 0, len(f.extents)
	for low < high {
		middle := (low + high) / 2
		if f.extents[middle].logical <= logical {
			low = middle + 1
		} else {
			high = middle
		}
	}
	if low == 0 {
		return extent{}, corruptf("logical byte %d is before the first mapped extent", logical)
	}
	return f.extents[low-1], nil
}

func (f *fileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	startIndex := 0
	if len(f.extents) > 0 {
		low, high := 0, len(f.extents)
		for low < high {
			middle := (low + high) / 2
			if f.extents[middle].logical <= offset {
				low = middle + 1
			} else {
				high = middle
			}
		}
		if low > 0 {
			startIndex = low - 1
		}
	}
	var covered uint64
	for _, value := range f.extents[startIndex:] {
		extentEnd := value.logical + value.len
		if extentEnd < value.logical {
			return out, corruptf("an extent ends past the address space")
		}
		if value.logical >= end {
			break
		}
		if extentEnd <= offset {
			continue
		}
		from := value.logical
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
		parentOffset := value.physical + (from - value.logical)
		if parentOffset < value.physical {
			return out, corruptf("a data extent's physical offset overflows")
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: parentOffset,
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
	got, err := f.readAt(offset, buf)
	if err != nil {
		return got, err
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *fileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
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
func (f *fileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.extentsInto(f.src.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *fileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *fileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, parentRange := range ranges {
		if parentRange.Kind == source.RangeData {
			images, err := f.src.MapToImage(parentRange.ParentOffset, parentRange.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, images...)
		} else {
			out = append(out, source.ImageRange{
				ImageID:     f.src.ImageID(),
				ImageOffset: 0,
				Len:         parentRange.Len,
				Kind:        parentRange.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *fileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *fileSource) IsEmpty() bool { return f.size == 0 }

func mulCheck(left, right uint64) (uint64, error) {
	if left != 0 && right > (^uint64(0))/left {
		return 0, corruptf("a data-stream multiplier overflows the address space")
	}
	return left * right, nil
}

var _ source.ByteSource = (*fileSource)(nil)
