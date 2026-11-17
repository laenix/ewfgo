package sysv

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// maxFileBlocks bounds one file's resolved block map.
const maxFileBlocks = 4 * 1024 * 1024

// fileSource serves one regular file or symbolic-link target as a ByteSource.
type fileSource struct {
	id        source.ID
	src       source.ByteSource
	blockSize uint64
	// One entry per logical block; zero is a hole.
	blocks   []uint32
	size     uint64
	counters source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, sb *superblock, in *inode) (*fileSource, error) {
	blockSize := sb.zoneSize()
	if blockSize == 0 {
		return nil, corruptf("the superblock's block size is zero")
	}
	needed := (uint64(in.size) + blockSize - 1) / blockSize
	pointers := uint64(sb.blockSize / 4)
	capacity := capacityBlocks(pointers)
	if needed > capacity {
		return nil, boundsError("inode " + utoa(in.number) + " declares " + utoa(in.size) +
			" bytes, needing " + utoa64(needed) + " blocks; its pointer tree addresses only " +
			utoa64(capacity))
	}
	if needed > maxFileBlocks {
		return nil, mappingCap("inode " + utoa(in.number) + " needs " + utoa64(needed) +
			" blocks, more than the " + utoa64(maxFileBlocks) + "-block mapping cap")
	}
	resolver := &resolver{sb: sb, src: src, visited: map[uint32]bool{}}
	blocks, err := resolver.resolve(in, needed)
	if err != nil {
		return nil, err
	}
	return &fileSource{
		id:        id,
		src:       src,
		blockSize: blockSize,
		blocks:    blocks,
		size:      uint64(in.size),
	}, nil
}

// capacityBlocks is the number of logical blocks the pointer tree addresses.
func capacityBlocks(pointers uint64) uint64 {
	total := uint64(directPointers)
	level := pointers
	for depth := 0; depth < 3; depth++ {
		total = satAdd(total, level)
		level = satMul(level, pointers)
	}
	return total
}

type resolver struct {
	sb      *superblock
	src     source.ByteSource
	visited map[uint32]bool
}

func (r *resolver) resolve(in *inode, needed uint64) ([]uint32, error) {
	blocks := make([]uint32, needed)
	direct := uint64(directPointers)
	if direct > needed {
		direct = needed
	}
	copy(blocks, in.pointers[:direct])

	pointers := uint64(r.sb.blockSize / 4)
	single := pointers
	double := satMul(single, pointers)
	covered := direct

	if covered < needed {
		table, err := r.readTable(in.pointers[directPointers], in)
		if err != nil {
			return nil, err
		}
		if table != nil {
			if err := r.fill(blocks, uint64(directPointers), needed, table, 1, in); err != nil {
				return nil, err
			}
		}
		covered = minU64(satAdd(covered, single), needed)
	}
	if covered < needed {
		table, err := r.readTable(in.pointers[directPointers+1], in)
		if err != nil {
			return nil, err
		}
		if table != nil {
			base := uint64(directPointers) + single
			if err := r.fill(blocks, base, needed, table, 2, in); err != nil {
				return nil, err
			}
		}
		covered = minU64(satAdd(covered, double), needed)
	}
	if covered < needed {
		table, err := r.readTable(in.pointers[directPointers+2], in)
		if err != nil {
			return nil, err
		}
		if table != nil {
			base := uint64(directPointers) + single + double
			if err := r.fill(blocks, base, needed, table, 3, in); err != nil {
				return nil, err
			}
		}
	}

	for index, zone := range blocks {
		if zone != 0 && !r.sb.isDataZone(zone) {
			return nil, boundsError("inode " + utoa(in.number) + " block " + utoa64(uint64(index)) +
				" names zone " + utoa(zone) + ", outside the data zones " +
				utoa(r.sb.firstDataZone()) + ".." + utoa(r.sb.zones()))
		}
	}
	return blocks, nil
}

// fill fills one indirect level. depth is 1 for a table of data zones, 2 when
// each entry names another table, and 3 for the triple level. base is the
// logical block the table's first entry covers.
func (r *resolver) fill(out []uint32, base, needed uint64, table []uint32, depth int, in *inode) error {
	pointers := uint64(r.sb.blockSize / 4)
	span := uint64(1)
	for level := 1; level < depth; level++ {
		span = satMul(span, pointers)
	}
	for index, zone := range table {
		start := base + uint64(index)*span
		if start >= needed {
			break
		}
		if zone == 0 {
			// A zero pointer leaves its whole range as holes.
			continue
		}
		if depth == 1 {
			out[start] = zone
			continue
		}
		child, err := r.readTable(zone, in)
		if err != nil {
			return err
		}
		if child == nil {
			return boundsError("indirect zone " + utoa(zone) + " at logical block " +
				utoa64(start) + " is zero")
		}
		if err := r.fill(out, start, needed, child, depth-1, in); err != nil {
			return err
		}
	}
	return nil
}

// readTable reads one block of 32-bit zone numbers.
func (r *resolver) readTable(zone uint32, in *inode) ([]uint32, error) {
	if zone == 0 {
		return nil, nil
	}
	if !r.sb.isDataZone(zone) {
		return nil, boundsError("inode " + utoa(in.number) + " names indirect zone " + utoa(zone) +
			", outside the data zones " + utoa(r.sb.firstDataZone()) + ".." + utoa(r.sb.zones()))
	}
	if !r.visited[zone] {
		r.visited[zone] = true
	} else {
		return nil, loopDetected("inode " + utoa(in.number) + " reaches indirect zone " +
			utoa(zone) + " more than once")
	}
	at, ok := r.sb.zoneOffset(zone)
	if !ok {
		return nil, boundsError("zone " + utoa(zone) + " overflows the byte address space")
	}
	blockSize := uint64(r.sb.blockSize)
	if at > r.src.Len() || blockSize > r.src.Len()-at {
		return nil, boundsError("indirect zone " + utoa(zone) + " at byte " + utoa64(at) +
			" runs past the " + utoa64(r.src.Len()) + " byte source")
	}
	bytes := make([]byte, r.sb.blockSize)
	if err := source.ReadExactAt(r.src, at, bytes); err != nil {
		return nil, err
	}
	pointers := int(r.sb.blockSize / 4)
	table := make([]uint32, pointers)
	for index := range table {
		table[index] = r.sb.byteOrder.u32(bytes, index*4)
	}
	return table, nil
}

func (f *fileSource) allocatedBytes() uint64 {
	var count uint64
	for _, zone := range f.blocks {
		if zone != 0 {
			count++
		}
	}
	return count * f.blockSize
}

func (f *fileSource) readAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := int(minU64(f.size-offset, uint64(len(buf))))
	done := 0
	for done < want {
		logical := offset + uint64(done)
		index := logical / f.blockSize
		inside := logical % f.blockSize
		take := int(minU64(f.blockSize-inside, uint64(want-done)))
		zone := f.blocks[index]
		out := buf[done : done+take]
		if zone == 0 {
			for index := range out {
				out[index] = 0
			}
		} else {
			at := uint64(zone)*f.blockSize + inside
			if err := source.ReadExactAt(f.src, at, out); err != nil {
				return 0, err
			}
		}
		done += take
	}
	return want, nil
}

func (f *fileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	done := uint64(0)
	for done < length {
		logical := offset + done
		index := logical / f.blockSize
		inside := logical % f.blockSize
		take := minU64(f.blockSize-inside, length-done)
		zone := f.blocks[index]
		if zone == 0 {
			out = append(out, source.ParentRange{Parent: parent, Len: take, Kind: source.RangeZero})
		} else {
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: uint64(zone)*f.blockSize + inside,
				Len:          take,
				Kind:         source.RangeData,
			})
		}
		done += take
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
	want := int(minU64(f.size-offset, uint64(len(buf))))
	if got, err := f.readAt(offset, buf[:want]); err == nil {
		return got, nil
	}
	for index := 0; index < want; index++ {
		buf[index] = 0
	}
	f.counters.AddCorrupt(uint64(want))
	return want, nil
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
			out = append(out, source.ImageRange{ImageID: f.src.ImageID(), Len: r.Len, Kind: r.Kind})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *fileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *fileSource) IsEmpty() bool { return f.size == 0 }

func satAdd(a, b uint64) uint64 {
	if b > ^uint64(0)-a {
		return ^uint64(0)
	}
	return a + b
}

func satMul(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

var _ source.ByteSource = (*fileSource)(nil)
