package sysv

import (
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// maxFreeZones bounds a walked chain before the map is refused.
	maxFreeZones = 1_000_000
	// maxFreeChunks bounds a walked chain's continuation chunks.
	maxFreeChunks = 100_000
	// freeSpaceBasis is reported with the map.
	freeSpaceBasis = "sysv.free_list"
)

// FreeList is one walked free-block chain.
type FreeList struct {
	// Zones is every free zone, in the order the chain yielded it.
	Zones []uint32
	// Chunks is the number of continuation chunks followed.
	Chunks uint64
	// Declared is the superblock's claimed free count (s_tfree). It is
	// recorded but never trusted as the count.
	Declared uint32
}

// FreeBytes returns the bytes the listed zones cover at a block size.
func (f *FreeList) FreeBytes(blockSize uint32) uint64 {
	return uint64(len(f.Zones)) * uint64(blockSize)
}

// freeWalk walks the chained free-block list. SCO AFS's bitmap free list is
// not decoded and is refused with ErrUnsupported.
func freeWalk(sb *superblock, src source.ByteSource) (*FreeList, error) {
	if sb.afs {
		return nil, unsupportedVariant(
			"SCO AFS keeps a bitmap free list rather than the chained list this reader decodes")
	}
	blockSize := uint64(sb.blockSize)
	nicfree := sb.nicfree()
	entriesAt := sb.chunkEntriesOffset()

	chunk := make([]uint32, len(sb.free))
	copy(chunk, sb.free)
	if len(chunk) < nicfree {
		return nil, corruptedFreeList("the superblock's free chunk has " + utoa64(uint64(len(chunk))) +
			" entries, fewer than the " + utoa64(uint64(nicfree)) + " the variant defines")
	}
	count := int(sb.nfree)
	chunks := uint64(0)
	var zones []uint32
	seen := make(map[uint32]bool)

	for {
		if count > nicfree {
			return nil, corruptedFreeList("a free-list chunk declares " + utoa64(uint64(count)) +
				" entries, more than the " + utoa64(uint64(nicfree)) + " it can hold")
		}
		var zone uint32
		for index := count; index > 0; {
			index--
			zone = chunk[index]
			if zone == 0 {
				break
			}
			if !sb.isDataZone(zone) {
				return nil, corruptedFreeList("free zone " + utoa(zone) +
					" is outside the data zones " + utoa(sb.firstDataZone()) + ".." + utoa(sb.zones()))
			}
			if seen[zone] {
				return nil, loopDetected("the free list reaches zone " + utoa(zone) + " more than once")
			}
			seen[zone] = true
			zones = append(zones, zone)
			if len(zones) > maxFreeZones {
				return nil, corruptedFreeList("the free list names more than " +
					utoa64(maxFreeZones) + " zones, the mapping cap")
			}
		}
		if zone == 0 {
			break
		}

		// The last entry was the continuation chunk. It is itself free and
		// was counted above; read its header and entries.
		chunks++
		if chunks > maxFreeChunks {
			return nil, corruptedFreeList("the free list continues through more than " +
				utoa64(maxFreeChunks) + " chunks")
		}
		at, ok := sb.zoneOffset(zone)
		if !ok {
			return nil, corruptedFreeList("free-list zone " + utoa(zone) +
				" overflows the address space")
		}
		if at > src.Len() || blockSize > src.Len()-at {
			return nil, corruptedFreeList("free-list chunk " + utoa(zone) + " at byte " +
				utoa64(at) + " runs past the " + utoa64(src.Len()) + " byte source")
		}
		bytes := make([]byte, sb.blockSize)
		if err := source.ReadExactAt(src, at, bytes); err != nil {
			return nil, err
		}
		count = int(sb.byteOrder.u16(bytes, 0))
		chunk = make([]uint32, nicfree)
		for position := range chunk {
			chunk[position] = sb.byteOrder.u32(bytes, entriesAt+position*4)
		}
	}

	return &FreeList{Zones: zones, Chunks: chunks, Declared: sb.tfree}, nil
}

// FreeRun is one run of free bytes at a volume-relative offset.
type FreeRun struct {
	Offset uint64
	Len    uint64
}

// End returns the first byte after the run.
func (r FreeRun) End() uint64 { return r.Offset + r.Len }

// FreeSpace is a volume's free bytes, as the chained free-block list
// describes them.
type FreeSpace struct {
	volumeLen uint64
	covered   uint64
	areaStart uint64
	basis     string
	freeBytes uint64
	runs      []FreeRun
	notes     []string
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

// Notes returns the observations the builder recorded, such as a declared
// count that differs from the walked chain.
func (f *FreeSpace) Notes() []string {
	out := make([]string, len(f.notes))
	copy(out, f.notes)
	return out
}

// IsFree reports whether every byte of [offset, offset+len) lies in one free
// run. Bytes outside [areaStart, covered) are never free.
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

func newFreeSpace(volumeLen, covered, areaStart uint64, basis string, runs []FreeRun, notes []string) (*FreeSpace, error) {
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
			return nil, corruptedFreeList("free run at " + utoa64(run.Offset) +
				" lies before the allocation area, which starts at " + utoa64(areaStart))
		}
		if run.End() < run.Offset || run.End() > covered {
			return nil, corruptedFreeList("free run at " + utoa64(run.Offset) + " (+" +
				utoa64(run.Len) + ") lies outside the " + utoa64(volumeLen) + "-byte volume")
		}
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if run.Offset < last.End() {
				return nil, corruptedFreeList("two free runs claim byte " + utoa64(run.Offset) +
					", so the free list contradicts itself")
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
		notes:     notes,
	}, nil
}

// freeSpace walks the chain and turns it into a free-space map. The map covers
// the declared filesystem bytes clamped to the source length; its allocation
// area begins at the first data zone.
func freeSpace(sb *superblock, src source.ByteSource, volumeLen uint64) (*FreeSpace, error) {
	list, err := freeWalk(sb, src)
	if err != nil {
		return nil, err
	}
	blockSize := uint64(sb.blockSize)
	covered := sb.declaredBytes()
	if covered > src.Len() {
		covered = src.Len()
	}
	areaStart := satMul(uint64(sb.isize), blockSize)

	runs := make([]FreeRun, 0, len(list.Zones))
	for _, zone := range list.Zones {
		offset := uint64(zone) * blockSize
		end := satAdd(offset, blockSize)
		if offset < areaStart || end > covered {
			return nil, corruptedFreeList("free zone " + utoa(zone) + " covers bytes " +
				utoa64(offset) + ".." + utoa64(end) + ", outside the allocation area " +
				utoa64(areaStart) + ".." + utoa64(covered))
		}
		runs = append(runs, FreeRun{Offset: offset, Len: blockSize})
	}
	var notes []string
	if uint64(list.Declared) != uint64(len(list.Zones)) {
		notes = append(notes, "the superblock declares "+utoa(list.Declared)+
			" free blocks; the chain lists "+utoa64(uint64(len(list.Zones))))
	}
	if list.Chunks > 0 {
		notes = append(notes, "the chain continues through "+utoa64(list.Chunks)+" chunk block(s)")
	}
	return newFreeSpace(volumeLen, covered, areaStart, freeSpaceBasis, runs, notes)
}
