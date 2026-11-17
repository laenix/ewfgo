package jfs

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The JFS aggregate block allocation map. The map is a file, described by
// aggregate inode 2, that covers the aggregate in 8192-block dmap pages. A
// dmap page holds a working bitmap and a persistent bitmap after 2048 bytes;
// in both, a set bit means allocated and block 0 is bit 31 of the first
// little-endian word.

// blockToDMap converts an aggregate block to the logical page of the block map
// file that describes it (BLKTODMAP).
func blockToDMap(block uint64) uint64 {
	return (block >> 13) + (block >> 23) + (block >> 33) + 4
}

type dbmap struct {
	MapSize     uint64
	NFree       uint64
	L2NBPerPage uint32
	NumAG       uint32
	MaxLevel    uint32
	MaxAG       uint32
	AGPref      uint32
	AGLevel     uint32
	AGHeight    uint32
	AGWidth     uint32
	AGStart     uint32
	AGL2Size    uint32
	AGFree      [MaxAllocationGroups]uint64
	AGSize      uint64
	MaxFreeBud  int8
}

func parseDbmap(raw []byte) (*dbmap, error) {
	if len(raw) < BlockSize {
		return nil, corruptf("a block map control page needs %d bytes, not %d", BlockSize, len(raw))
	}
	control := &dbmap{
		MapSize:     le64(raw, 0),
		NFree:       le64(raw, 8),
		L2NBPerPage: le32(raw, 16),
		NumAG:       le32(raw, 20),
		MaxLevel:    le32(raw, 24),
		MaxAG:       le32(raw, 28),
		AGPref:      le32(raw, 32),
		AGLevel:     le32(raw, 36),
		AGHeight:    le32(raw, 40),
		AGWidth:     le32(raw, 44),
		AGStart:     le32(raw, 48),
		AGL2Size:    le32(raw, 52),
		AGSize:      le64(raw, 1080),
		MaxFreeBud:  int8(raw[1088]),
	}
	if control.MapSize == 0 {
		return nil, corruptf("the block map covers zero blocks")
	}
	if control.L2NBPerPage != 0 {
		return nil, unsupportedf("the block map uses %d as log2(blocks per page); only 4 KiB pages are decoded",
			control.L2NBPerPage)
	}
	if control.NumAG == 0 || control.NumAG > MaxAllocationGroups {
		return nil, corruptf("the block map claims %d allocation groups; the format allows 1..=%d",
			control.NumAG, MaxAllocationGroups)
	}
	if control.MaxAG >= MaxAllocationGroups {
		return nil, corruptf("the block map's highest active allocation group is %d, outside 0..%d",
			control.MaxAG, MaxAllocationGroups)
	}
	if control.AGL2Size > 36 {
		return nil, corruptf("the block map's allocation-group shift %d is implausibly large", control.AGL2Size)
	}
	if control.AGSize == 0 {
		return nil, corruptf("the block map's allocation group size is zero")
	}
	for index := 0; index < MaxAllocationGroups; index++ {
		control.AGFree[index] = le64(raw, 56+index*8)
	}
	return control, nil
}

type blockMap struct {
	inode   *Dinode
	control *dbmap
}

func openBlockMap(src source.ByteSource, volumeBlocks uint64, inode *Dinode) (*blockMap, error) {
	raw, err := readLogicalBlock(src, volumeBlocks, inode.ExtentTreeRoot(), 0)
	if err != nil {
		return nil, err
	}
	control, err := parseDbmap(raw)
	if err != nil {
		return nil, err
	}
	return &blockMap{inode: inode, control: control}, nil
}

// FreeRun is one run of free bytes at a volume-relative offset.
type FreeRun struct {
	Offset uint64
	Len    uint64
}

// End returns the first byte after the run.
func (r FreeRun) End() uint64 { return r.Offset + r.Len }

// FreeSpace is a volume's free bytes, as its dmap bitmaps describe them.
type FreeSpace struct {
	volumeLen uint64
	covered   uint64
	basis     string
	freeBytes uint64
	runs      []FreeRun
	notes     []string
}

// Runs returns the free runs, sorted and merged.
func (f *FreeSpace) Runs() []FreeRun { return f.runs }

// RunCount returns how many runs the map holds.
func (f *FreeSpace) RunCount() int { return len(f.runs) }

// FreeBytes returns the total free bytes.
func (f *FreeSpace) FreeBytes() uint64 { return f.freeBytes }

// Basis returns where the answer came from.
func (f *FreeSpace) Basis() string { return f.basis }

// Covered returns the end of the bytes the map describes.
func (f *FreeSpace) Covered() uint64 { return f.covered }

// Notes returns the caveats the scan recorded.
func (f *FreeSpace) Notes() []string { return append([]string(nil), f.notes...) }

// IsFree reports whether every byte of [offset, offset+length) lies in one
// free run. Bytes outside the described area are never free.
func (f *FreeSpace) IsFree(offset, length uint64) bool {
	if length == 0 {
		return true
	}
	end := offset + length
	if end < offset || end > f.covered {
		return false
	}
	for _, run := range f.runs {
		if run.Offset > offset {
			break
		}
		if end <= run.Offset+run.Len {
			return true
		}
	}
	return false
}

// FreeMap is what scanning the block maps found.
type FreeMap struct {
	Space *FreeSpace
	// ScannedFree is the free-block count from the dmap bitmaps.
	ScannedFree uint64
	// ControlFree is the free-block count the control page records.
	ControlFree uint64
	// Persistent reports that the persistent (committed) map was used.
	Persistent bool
}

func (b *blockMap) freeSpace(src source.ByteSource, volumeLen uint64, clean bool) (*FreeMap, error) {
	mapsize := b.control.MapSize
	presentBlocks := volumeLen / BlockSize
	aggregatesCovered := mapsize
	if presentBlocks < aggregatesCovered {
		aggregatesCovered = presentBlocks
	}
	covered := aggregatesCovered * BlockSize
	basis := "jfs.dmap.working"
	if !clean {
		basis = "jfs.dmap.persistent"
	}
	space := &FreeSpace{volumeLen: volumeLen, covered: covered, basis: basis}
	if !clean {
		space.notes = append(space.notes,
			"the volume was not cleanly unmounted; free space is read from the persistent (committed) map, not the working map")
	}
	if aggregatesCovered < mapsize {
		space.notes = append(space.notes, fmt.Sprintf(
			"the aggregate records %d blocks but the image holds %d; only the first %d blocks are covered",
			mapsize, presentBlocks, aggregatesCovered))
	}
	dmapCount := (aggregatesCovered + BlocksPerDMap - 1) / BlocksPerDMap
	mapOffset := WMapOffset
	if !clean {
		mapOffset = PMapOffset
	}
	var scannedFree uint64
	for index := uint64(0); index < dmapCount; index++ {
		firstBlock := index * BlocksPerDMap
		logical := blockToDMap(firstBlock)
		raw, err := readLogicalBlock(src, presentBlocks, b.inode.ExtentTreeRoot(), logical)
		if err != nil {
			return nil, err
		}
		nblocks := uint64(le32(raw, 0))
		nfree := uint64(le32(raw, 4))
		start := le64(raw, 8)
		if start != firstBlock {
			return nil, corruptf("dmap %d starts at block %d, but its page position describes %d",
				index, start, firstBlock)
		}
		if nblocks == 0 || nblocks > BlocksPerDMap {
			return nil, corruptf("dmap %d covers %d blocks; a dmap covers at most %d",
				index, nblocks, BlocksPerDMap)
		}
		if start+nblocks < start || start+nblocks > mapsize {
			return nil, corruptf("dmap %d covers blocks %d..%d, past the aggregate's %d",
				index, start, start+nblocks, mapsize)
		}
		scanned := nblocks
		if remaining := aggregatesCovered - start; scanned > remaining {
			scanned = remaining
		}
		if scanned == nblocks {
			scannedFree += nfree
		} else {
			space.notes = append(space.notes, fmt.Sprintf(
				"dmap %d covers blocks %d..%d, but the image ends at block %d; only the present part is scanned",
				index, start, start+nblocks, aggregatesCovered))
		}
		if mapOffset+DMapMapBytes > len(raw) {
			return nil, corruptf("dmap %d has no bitmap at byte %d", index, mapOffset)
		}
		bitmap := raw[mapOffset : mapOffset+DMapMapBytes]
		for offset := uint64(0); offset < scanned; offset++ {
			word := le32(bitmap, int(offset/DBWord)*4)
			allocated := word&(uint32(1)<<(31-uint(offset%DBWord))) != 0
			if allocated {
				continue
			}
			block := firstBlock + offset
			space.runs = appendFreeRun(space.runs, block*BlockSize, BlockSize)
		}
	}
	if aggregatesCovered == mapsize && scannedFree != b.control.NFree {
		space.notes = append(space.notes, fmt.Sprintf(
			"the block map's control page records %d free blocks but its dmap pages count %d",
			b.control.NFree, scannedFree))
	}
	for _, run := range space.runs {
		space.freeBytes += run.Len
	}
	return &FreeMap{
		Space:       space,
		ScannedFree: scannedFree,
		ControlFree: b.control.NFree,
		Persistent:  !clean,
	}, nil
}

func appendFreeRun(runs []FreeRun, offset, length uint64) []FreeRun {
	if length == 0 {
		return runs
	}
	if len(runs) > 0 {
		last := &runs[len(runs)-1]
		if last.Offset+last.Len == offset {
			last.Len += length
			return runs
		}
	}
	return append(runs, FreeRun{Offset: offset, Len: length})
}
