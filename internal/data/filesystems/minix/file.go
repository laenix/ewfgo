package minix

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// directZones is the number of direct data zones in every version.
	directZones = 7
	// maxFileZones bounds one file's resolved zone map.
	maxFileZones = 4 * 1024 * 1024
)

// fileSource serves one regular file or symbolic-link target as a ByteSource.
type fileSource struct {
	id       source.ID
	src      source.ByteSource
	zoneSize uint64
	// One entry per logical zone; zero is a hole.
	zones    []uint32
	size     uint64
	counters source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, sb *superblock, in *inode) (*fileSource, error) {
	zoneSize := sb.zoneSize()
	if zoneSize == 0 {
		return nil, corruptf("the superblock's zone size is zero")
	}
	needed := (in.size + zoneSize - 1) / zoneSize
	if needed > maxFileZones {
		return nil, unsupportedf("inode %d needs %d zones, more than the %d-zone mapping cap",
			in.number, needed, maxFileZones)
	}
	zones, err := resolveZones(sb, src, in, needed)
	if err != nil {
		return nil, err
	}
	return &fileSource{
		id:       id,
		src:      src,
		zoneSize: zoneSize,
		zones:    zones,
		size:     in.size,
	}, nil
}

// resolveZones resolves every logical zone of an inode.
func resolveZones(sb *superblock, src source.ByteSource, in *inode, needed uint64) ([]uint32, error) {
	zones := make([]uint32, needed)
	direct := directZones
	if len(in.zones) < direct {
		direct = len(in.zones)
	}
	if uint64(direct) > needed {
		direct = int(needed)
	}
	copy(zones, in.zones[:direct])
	covered := uint64(direct)
	if covered >= needed {
		if err := validateZones(sb, in, zones); err != nil {
			return nil, err
		}
		return zones, nil
	}

	pointers := sb.pointersPerBlock()
	single := pointers
	double := satMul(pointers, pointers)
	triple := uint64(0)
	if sb.version.hasTripleIndirect() {
		triple = satMul(double, pointers)
	}
	capacity := uint64(directZones) + single + double + triple
	if needed > capacity {
		return nil, corruptf("inode %d declares %d bytes, needing %d zones; its indirect pointers address only %d",
			in.number, in.size, needed, capacity)
	}

	// Single indirect.
	if covered < needed {
		table, err := readTable(sb, src, in.zones[7])
		if err != nil {
			return nil, err
		}
		if table != nil {
			if err := fillZones(zones, directZones, needed, table, 1, sb, src, in); err != nil {
				return nil, err
			}
		}
		covered = minU64(covered+single, needed)
	}
	// Double indirect.
	if covered < needed {
		table, err := readTable(sb, src, in.zones[8])
		if err != nil {
			return nil, err
		}
		if table != nil {
			base := uint64(directZones) + single
			if err := fillZones(zones, base, needed, table, 2, sb, src, in); err != nil {
				return nil, err
			}
		}
		covered = minU64(covered+double, needed)
	}
	// Triple indirect (V2/V3 only).
	if covered < needed && sb.version.hasTripleIndirect() {
		table, err := readTable(sb, src, in.zones[9])
		if err != nil {
			return nil, err
		}
		if table != nil {
			base := uint64(directZones) + single + double
			if err := fillZones(zones, base, needed, table, 3, sb, src, in); err != nil {
				return nil, err
			}
		}
	}

	if err := validateZones(sb, in, zones); err != nil {
		return nil, err
	}
	return zones, nil
}

// fillZones fills one indirect level into the map. depth is 1 for a table of
// data zones, 2 when each entry names another table, and so on. base is the
// logical zone the table's first entry covers.
func fillZones(out []uint32, base, needed uint64, table []uint32, depth int,
	sb *superblock, src source.ByteSource, in *inode) error {
	pointers := sb.pointersPerBlock()
	span := uint64(1)
	for level := 1; level < depth; level++ {
		if pointers != 0 && span > ^uint64(0)/pointers {
			return corruptf("an indirect range overflows the address space")
		}
		span *= pointers
	}
	for index, zone := range table {
		start := base + uint64(index)*span
		if start >= needed {
			break
		}
		if zone == 0 {
			continue
		}
		if depth == 1 {
			out[start] = zone
			continue
		}
		child, err := readTable(sb, src, zone)
		if err != nil {
			return err
		}
		if child == nil {
			return corruptf("indirect zone %d at logical zone %d is zero", zone, start)
		}
		if err := fillZones(out, start, needed, child, depth-1, sb, src, in); err != nil {
			return err
		}
	}
	return nil
}

// readTable reads one block of zone pointers from `zone`.
func readTable(sb *superblock, src source.ByteSource, zone uint32) ([]uint32, error) {
	if zone == 0 {
		return nil, nil
	}
	if !sb.isDataZone(zone) {
		return nil, corruptf("indirect zone %d is outside the data zones %d..%d",
			zone, sb.firstData, sb.zones)
	}
	at, ok := sb.zoneOffset(zone)
	if !ok {
		return nil, corruptf("zone %d overflows the byte address space", zone)
	}
	blockSize := uint64(sb.blockSize)
	if at > src.Len() || blockSize > src.Len()-at {
		return nil, corruptf("indirect zone %d at byte %d runs past the %d byte source",
			zone, at, src.Len())
	}
	bytes := make([]byte, sb.blockSize)
	if err := source.ReadExactAt(src, at, bytes); err != nil {
		return nil, err
	}
	pointers := int(sb.pointersPerBlock())
	table := make([]uint32, pointers)
	if sb.version.pointerSize() == 2 {
		for index := range table {
			table[index] = uint32(bytes[index*2]) | uint32(bytes[index*2+1])<<8
		}
	} else {
		for index := range table {
			at := index * 4
			table[index] = uint32(bytes[at]) | uint32(bytes[at+1])<<8 |
				uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
		}
	}
	return table, nil
}

// validateZones requires every non-zero zone to be a declared data zone.
func validateZones(sb *superblock, in *inode, zones []uint32) error {
	for index, zone := range zones {
		if zone != 0 && !sb.isDataZone(zone) {
			return corruptf("inode %d zone %d is %d, outside the data zones %d..%d",
				in.number, index, zone, sb.firstData, sb.zones)
		}
	}
	return nil
}

func (f *fileSource) allocatedBytes() uint64 {
	var count uint64
	for _, zone := range f.zones {
		if zone != 0 {
			count++
		}
	}
	return count * f.zoneSize
}

// readAt fills buf from the logical offset, returning the short count at EOF.
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
		index := logical / f.zoneSize
		inside := logical % f.zoneSize
		take := int(minU64(f.zoneSize-inside, uint64(want-done)))
		zone := f.zones[index]
		out := buf[done : done+take]
		if zone == 0 {
			for index := range out {
				out[index] = 0
			}
		} else {
			at := uint64(zone)*f.zoneSize + inside
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
		index := logical / f.zoneSize
		inside := logical % f.zoneSize
		take := minU64(f.zoneSize-inside, length-done)
		zone := f.zones[index]
		if zone == 0 {
			out = append(out, source.ParentRange{Parent: parent, Len: take, Kind: source.RangeZero})
		} else {
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: uint64(zone)*f.zoneSize + inside,
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
