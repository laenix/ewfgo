package f2fs

import (
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Free-space map constants.
const (
	// FreeSpaceBasis is reported with the map.
	FreeSpaceBasis = "f2fs.sit"
	// SITEntrySize is the size of one struct f2fs_sit_entry.
	SITEntrySize = 74
	// sitVBlocksMask selects the valid-block count from the raw field.
	sitVBlocksMask uint16 = 0x03ff
	// sitValidMapOffset is the offset of the valid map inside an entry.
	sitValidMapOffset = 2
	// sitValidMapSize is the 512-bit valid map.
	sitValidMapSize = 64
	// maxBlocksPerSegment is the format's own ceiling.
	maxBlocksPerSegment = uint64(sitValidMapSize * 8)
)

// FreeRun is one run of free bytes, at a volume-relative offset.
type FreeRun struct {
	Offset uint64
	Len    uint64
}

// End returns the first byte after the run.
func (r FreeRun) End() uint64 { return r.Offset + r.Len }

// FreeSpace is a volume's free bytes, as the segment information table
// describes them.
type FreeSpace struct {
	volumeLen uint64
	covered   uint64
	areaStart uint64
	basis     string
	freeBytes uint64
	runs      []FreeRun
}

// Runs returns the free runs, sorted and merged.
func (f *FreeSpace) Runs() []FreeRun { return f.runs }

// RunCount returns how many runs the map holds.
func (f *FreeSpace) RunCount() int { return len(f.runs) }

// FreeBytes returns the total free bytes in the described area.
func (f *FreeSpace) FreeBytes() uint64 { return f.freeBytes }

// Basis returns where the answer came from.
func (f *FreeSpace) Basis() string { return f.basis }

// Covered returns the end of the bytes the map describes.
func (f *FreeSpace) Covered() uint64 { return f.covered }

// AreaStart returns where the allocation area begins.
func (f *FreeSpace) AreaStart() uint64 { return f.areaStart }

// IsFree reports whether every byte of [offset, offset+len) lies in one free
// run.  Bytes outside [areaStart, covered) are never free.
func (f *FreeSpace) IsFree(offset, length uint64) bool {
	if length == 0 {
		return true
	}
	end := offset + length
	if end < offset || offset < f.areaStart || end > f.covered {
		return false
	}
	index := sort.Search(len(f.runs), func(i int) bool { return f.runs[i].Offset > offset })
	return index > 0 && f.runs[index-1].End() >= end
}

func newFreeSpace(volumeLen, covered, areaStart uint64, basis string, runs []FreeRun) (*FreeSpace, error) {
	if covered > volumeLen {
		covered = volumeLen
	}
	if areaStart > covered {
		areaStart = covered
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].Offset != runs[j].Offset {
			return runs[i].Offset < runs[j].Offset
		}
		return runs[i].Len < runs[j].Len
	})
	merged := make([]FreeRun, 0, len(runs))
	var total uint64
	for _, run := range runs {
		if run.Len == 0 {
			continue
		}
		if run.Offset < areaStart {
			return nil, invalidf("free run at %d lies before the allocation area, which starts at %d", run.Offset, areaStart)
		}
		if run.End() < run.Offset || run.End() > covered {
			return nil, invalidf("free run at %d (+%d) lies outside the %d-byte volume", run.Offset, run.Len, volumeLen)
		}
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if run.Offset < last.End() {
				return nil, invalidf("two free runs claim byte %d, so the allocation map contradicts itself", run.Offset)
			}
			if run.Offset == last.End() {
				last.Len += run.Len
				total += run.Len
				continue
			}
		}
		merged = append(merged, run)
		total += run.Len
	}
	return &FreeSpace{
		volumeLen: volumeLen,
		covered:   covered,
		areaStart: areaStart,
		basis:     basis,
		freeBytes: total,
		runs:      merged,
	}, nil
}

// FreeSpace reads the main area's free blocks from the segment information
// table.
func (v *Volume) FreeSpace() (*FreeSpace, error) {
	sb := v.superblock
	blockSize := uint64(sb.BlockSize)
	if blockSize < SITEntrySize {
		return nil, invalidf("a %d-byte block cannot hold a %d-byte SIT entry", blockSize, SITEntrySize)
	}
	blocksPerSegment := uint64(sb.BlocksPerSegment)
	if blocksPerSegment == 0 || blocksPerSegment > maxBlocksPerSegment {
		return nil, invalidf("a segment of %d blocks does not fit the format's %d-block ceiling",
			blocksPerSegment, maxBlocksPerSegment)
	}
	mainStart := uint64(sb.MainBlkaddr)
	mainSegments := uint64(sb.SegmentCountMain)
	if mainSegments == 0 {
		return nil, invalidf("the superblock declares no main segments")
	}
	mainEnd := mainStart*blockSize + mainSegments*blocksPerSegment*blockSize
	if mainEnd < mainStart*blockSize {
		return nil, invalidf("the main area address overflows the volume")
	}
	if mainEnd > v.source.Len() {
		return nil, invalidf("the main area ends at byte %d, past the %d readable bytes", mainEnd, v.source.Len())
	}
	perBlock := blockSize / SITEntrySize
	entryBlocks := (mainSegments + perBlock - 1) / perBlock
	sitBlocks := uint64(sb.SegmentCountSIT) * blocksPerSegment
	half := sitBlocks / 2
	entriesPerCopy := half * perBlock
	if mainSegments > entriesPerCopy {
		return nil, invalidf("the %d main segments need %d SIT entries, but one copy of the table holds only %d",
			mainSegments, mainSegments, entriesPerCopy)
	}
	bitmap := v.checkpoint.SITBitmap(v.nat.Layout())

	runs := make([]FreeRun, 0, mainSegments)
	for entryBlock := uint64(0); entryBlock < entryBlocks; entryBlock++ {
		sitSegment := entryBlock / blocksPerSegment
		second := bitSet(bitmap, int(sitSegment))
		physical := uint64(sb.SITBlkaddr) + entryBlock
		if second {
			physical += half
		}
		if physical*blockSize+blockSize > v.source.Len() {
			return nil, invalidf("SIT block %d sits at %d, past the %d readable bytes",
				entryBlock, physical, v.source.Len())
		}
		bytes, err := source.ReadVecAt(v.source, physical*blockSize, blockSize)
		if err != nil {
			return nil, err
		}
		firstSegment := entryBlock * perBlock
		count := mainSegments - firstSegment
		if count > perBlock {
			count = perBlock
		}
		for index := uint64(0); index < count; index++ {
			at := int(index) * SITEntrySize
			rawVBlocks := uint16(bytes[at]) | uint16(bytes[at+1])<<8
			vblocks := rawVBlocks & sitVBlocksMask
			validMap := bytes[at+sitValidMapOffset : at+sitValidMapOffset+sitValidMapSize]
			segment := firstSegment + index
			start := mainStart + segment*blocksPerSegment
			if override := v.replayedSIT(uint32(segment)); override != nil {
				vblocks = override.VBlocks
				validMap = override.ValidMap[:]
			}
			var err error
			runs, err = freeFromEntry(runs, validMap, vblocks, segment, start, blocksPerSegment, blockSize)
			if err != nil {
				return nil, err
			}
		}
	}
	return newFreeSpace(v.source.Len(), mainEnd, mainStart*blockSize, FreeSpaceBasis, runs)
}

func freeFromEntry(runs []FreeRun, validMap []byte, vblocks uint16, segment, start, blocksPerSegment, blockSize uint64) ([]FreeRun, error) {
	var set uint64
	for block := uint64(0); block < blocksPerSegment; block++ {
		if bitSet(validMap, int(block)) {
			set++
		}
	}
	for block := blocksPerSegment; block < maxBlocksPerSegment; block++ {
		if bitSet(validMap, int(block)) {
			return nil, invalidf("segment %d's valid map marks block %d, past the segment's %d blocks",
				segment, block, blocksPerSegment)
		}
	}
	if set != uint64(vblocks) {
		return nil, invalidf("segment %d counts %d valid blocks but its valid map marks %d, so the entry contradicts itself",
			segment, vblocks, set)
	}
	if vblocks == 0 {
		runs = append(runs, FreeRun{Offset: start * blockSize, Len: blocksPerSegment * blockSize})
		return runs, nil
	}
	block := uint64(0)
	for block < blocksPerSegment {
		if bitSet(validMap, int(block)) {
			block++
			continue
		}
		begin := block
		for block < blocksPerSegment && !bitSet(validMap, int(block)) {
			block++
		}
		runs = append(runs, FreeRun{
			Offset: (start + begin) * blockSize,
			Len:    (block - begin) * blockSize,
		})
	}
	return runs, nil
}
