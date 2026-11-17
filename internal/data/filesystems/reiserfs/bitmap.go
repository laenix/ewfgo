package reiserfs

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ReiserFS free blocks, read from the on-disk allocation bitmap. The old
// format packs bitmaps immediately after the 8 KiB superblock; the new format
// puts the first one after the 64 KiB band and each later one at the first
// block it describes. The kernel chooses between the two by where it found the
// superblock, so Superblock.Offset is the discriminator.
const (
	// DiskOffset is the new-format superblock's byte offset.
	DiskOffset uint64 = 64 * 1024
	// OldDiskOffset is the old-format superblock's byte offset.
	OldDiskOffset uint64 = 8 * 1024
)

// FreeMap is the result of scanning the block bitmaps.
type FreeMap struct {
	Space *FreeSpace
	// ScannedFree is the free-block count from the bitmaps.
	ScannedFree uint64
	// RecordedFree is the free-block count the superblock records.
	RecordedFree uint32
	// OldFormat reports that the bitmaps follow the 8 KiB superblock.
	OldFormat bool
}

// bitmapCount returns how many bitmap blocks a volume's block count needs.
func bitmapCount(sb *Superblock) uint32 {
	bits := uint64(sb.BlockSize) * 8
	return uint32((uint64(sb.BlockCount)-1)/bits + 1)
}

// bitmapBlock returns the block holding bitmap number index.
func bitmapBlock(sb *Superblock, index uint32) uint64 {
	blockSize := uint64(sb.BlockSize)
	if sb.Offset == OldDiskOffset {
		return sb.Offset/blockSize + 1 + uint64(index)
	}
	if index == 0 {
		return DiskOffset/blockSize + 1
	}
	return blockSize * 8 * uint64(index)
}

// FreeRun is one run of free bytes at a volume-relative offset.
type FreeRun struct {
	Offset uint64
	Len    uint64
}

// End returns the first byte after the run.
func (r FreeRun) End() uint64 { return r.Offset + r.Len }

// FreeSpace is a volume's free bytes, as its bitmaps describe them.
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

// IsFree reports whether every byte of [offset, offset+length) lies in one free
// run.
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

// freeSpace scans the bitmap blocks and returns the free-block runs.
func freeSpace(src source.ByteSource, sb *Superblock) (*FreeMap, error) {
	if sb.BlockSize == 0 || sb.BlockCount < 2 {
		return nil, corruptf("the superblock describes %d blocks of %d bytes, which cannot hold a bitmap",
			sb.BlockCount, sb.BlockSize)
	}
	blockSize := uint64(sb.BlockSize)
	blockCount := uint64(sb.BlockCount)
	covered := blockCount * blockSize
	if covered/blockSize != blockCount {
		return nil, corruptf("the volume's byte length overflows")
	}
	oldFormat := sb.Offset == OldDiskOffset
	count := bitmapCount(sb)
	space := &FreeSpace{volumeLen: src.Len(), covered: covered, basis: "reiserfs.bitmap"}
	if sb.FreeBlocks != 0 && uint64(sb.FreeBlocks) > blockCount {
		space.notes = append(space.notes, fmt.Sprintf(
			"the superblock records %d free blocks, more than the volume's %d", sb.FreeBlocks, blockCount))
	}
	if sb.BmapCount != 0 && sb.BmapCount != count {
		space.notes = append(space.notes, fmt.Sprintf(
			"the superblock records %d bitmap blocks, but %d blocks of %d bytes need %d; the block count is used",
			sb.BmapCount, blockCount, blockSize, count))
	}
	for index := uint32(0); index < count; index++ {
		number := bitmapBlock(sb, index)
		if number == 0 || number >= blockCount {
			return nil, corruptf("bitmap block %d is block %d, outside the volume's %d blocks",
				index, number, blockCount)
		}
		raw, err := source.ReadVecAt(src, number*blockSize, blockSize)
		if err != nil {
			return nil, err
		}
		first := uint64(index) * blockSize * 8
		bits := blockCount - first
		if maxBits := blockSize * 8; bits > maxBits {
			bits = maxBits
		}
		needed := (bits + 7) / 8
		if needed > uint64(len(raw)) {
			needed = uint64(len(raw))
		}
		for offset := uint64(0); offset < bits; offset++ {
			byteAt := offset / 8
			if byteAt >= needed {
				break
			}
			allocated := raw[byteAt]&(1<<(offset%8)) != 0
			if allocated {
				continue
			}
			block := first + offset
			space.runs = appendBitmapFreeRun(space.runs, block*blockSize, blockSize)
		}
	}
	for _, run := range space.runs {
		space.freeBytes += run.Len
	}
	scannedFree := space.freeBytes / blockSize
	if scannedFree != uint64(sb.FreeBlocks) {
		space.notes = append(space.notes, fmt.Sprintf(
			"the superblock records %d free blocks but the bitmaps mark %d", sb.FreeBlocks, scannedFree))
	}
	return &FreeMap{
		Space:        space,
		ScannedFree:  scannedFree,
		RecordedFree: sb.FreeBlocks,
		OldFormat:    oldFormat,
	}, nil
}

func appendBitmapFreeRun(runs []FreeRun, offset, length uint64) []FreeRun {
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
