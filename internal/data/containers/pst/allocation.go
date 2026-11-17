// AMap (allocation map) and PMap (page allocation map) pages.
//
// [MS-PST] keeps two bit maps beside the block B-tree.  An AMap page holds a
// bitmap in which each bit tracks one allocation unit of the data section that
// immediately follows it: a 64-byte block for the 512-byte-page layouts, a
// 512-byte block for the 4 KiB layout.  A PMap page is the same, except each
// bit tracks one whole page (512 or 4096 bytes).  The first AMap sits at
// 0x4400 for the 512-byte-page layouts and at 0x22000 for the 4 KiB layout;
// the first PMap is one page after it.  A page repeats every
// payloadBits * unit bytes, where payloadBits is the bitmap size in bits.
//
// The block B-tree remains the authoritative source of block locations this
// reader uses; the maps are exposed for callers that need the allocation
// picture, or that want to compare it with the BBT.  A map page is parsed only
// when its trailer validates: type, repeat type and back pointer.  A bitmap
// byte is not evidence about who owns the unit, only whether the store marked
// it allocated.
package pst

import (
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// AllocationAMap is an allocation-map page (ptype 0x84).
	AllocationAMap uint8 = 0x84
	// AllocationPMap is a page-allocation-map page (ptype 0x83).
	AllocationPMap uint8 = 0x83
)

// AllocationKind is which allocation map a page is.
type AllocationKind uint8

const (
	// MapAMap tracks allocation units of the data section.
	MapAMap AllocationKind = iota
	// MapPMap tracks whole pages.
	MapPMap
)

// Label returns "amap" or "pmap".
func (k AllocationKind) Label() string {
	if k == MapPMap {
		return "pmap"
	}
	return "amap"
}

// String returns the label.
func (k AllocationKind) String() string { return k.Label() }

// AllocationMap is one parsed AMap or PMap page.
type AllocationMap struct {
	Kind AllocationKind
	// Index is the page's zero-based position among pages of this kind.
	Index int
	// Offset is the page's file offset (which is also its BID).
	Offset uint64
	// BID is the back pointer the page trailer stored.
	BID uint64
	// Bits is the stored bitmap, one bit per unit.  Bit 0 is the low bit of
	// Bits[0]; the first bit maps MappedStart.
	Bits []byte
	// UnitBytes is how many data bytes one bit tracks: 64 or 512 for an
	// AMap, the page size for a PMap.
	UnitBytes uint64
	// MappedStart is the file offset the first bit maps.  An AMap page maps
	// the data section beginning at itself.
	MappedStart uint64
}

// Allocated reports whether the store marked the unit at index allocated.  A
// map's bit order is least-significant bit first.
func (m AllocationMap) Allocated(index uint64) bool {
	byteIndex := index / 8
	if byteIndex >= uint64(len(m.Bits)) {
		return false
	}
	return m.Bits[byteIndex]&(1<<(index%8)) != 0
}

func allocationMapGeometry(format StoreFormat) (firstAMap, firstPMap, amapStep, pmapStep, payloadBytes, amapUnit, pmapUnit uint64) {
	pageBytes := uint64(format.PageBytes())
	if format == FormatUnicode4K {
		payloadBytes = 4072
		amapUnit = 512
		firstAMap = 0x22000
	} else {
		payloadBytes = 496
		amapUnit = 64
		firstAMap = 0x4400
	}
	firstPMap = firstAMap + pageBytes
	pmapUnit = pageBytes
	amapStep = payloadBytes * 8 * amapUnit
	pmapStep = payloadBytes * 8 * pmapUnit
	return
}

// AllocationMaps reads the AMap and PMap pages the store's layout places at
// fixed intervals.  It is separate from Open because the BBT, not the maps,
// carries the block locations the rest of this reader uses.
func (r *Reader) AllocationMaps() ([]AllocationMap, error) {
	firstAMap, firstPMap, amapStep, pmapStep, payload, amapUnit, pmapUnit := allocationMapGeometry(r.header.Format)
	maps := make([]AllocationMap, 0)
	if err := r.readAllocationKind(firstAMap, amapStep, amapUnit, payload, MapAMap, AllocationAMap, &maps); err != nil {
		return nil, err
	}
	if err := r.readAllocationKind(firstPMap, pmapStep, pmapUnit, payload, MapPMap, AllocationPMap, &maps); err != nil {
		return nil, err
	}
	sort.Slice(maps, func(i, j int) bool { return maps[i].Offset < maps[j].Offset })
	return maps, nil
}

func (r *Reader) readAllocationKind(first, step, unit, payload uint64, kind AllocationKind, ptype uint8, maps *[]AllocationMap) error {
	pageBytes := uint64(r.header.PageBytes)
	storeEnd := r.src.Len()
	if r.header.FileEOF != 0 && r.header.FileEOF < storeEnd {
		storeEnd = r.header.FileEOF
	}
	index := 0
	for offset := first; offset+pageBytes <= storeEnd; {
		page, err := r.readAllocationMapPage(offset, kind, ptype, unit, payload)
		if err != nil {
			return err
		}
		page.Index = index
		*maps = append(*maps, page)
		index++
		if index > r.limits.MaxPages {
			return limitf("the store has more than %d %s pages", r.limits.MaxPages, kind.Label())
		}
		if offset > ^uint64(0)-step {
			break
		}
		offset += step
	}
	return nil
}

func (r *Reader) readAllocationMapPage(offset uint64, kind AllocationKind, ptype uint8, unit, payload uint64) (AllocationMap, error) {
	layout := pageLayoutForFormat(r.header.Format)
	if offset+uint64(layout.pageBytes) > r.src.Len() {
		return AllocationMap{}, corruptf("the %s page at offset %d runs past the %d-byte source", kind.Label(), offset, r.src.Len())
	}
	buf, err := source.ReadVecAt(r.src, offset, uint64(layout.pageBytes))
	if err != nil {
		return AllocationMap{}, err
	}
	if buf[layout.ptype] != ptype || buf[layout.ptype+1] != buf[layout.ptype] {
		return AllocationMap{}, corruptf("the %s page at offset %d has type 0x%02X/0x%02X, not 0x%02X", kind.Label(), offset, buf[layout.ptype], buf[layout.ptype+1], ptype)
	}
	bid := layout.readBID(buf)
	if bid != offset {
		return AllocationMap{}, corruptf("the %s page at offset %d carries back pointer 0x%X", kind.Label(), offset, bid)
	}
	if crc32PST(buf[:layout.crcCover]) != leU32(buf, layout.crc) {
		r.checksumMismatches.Add(1)
	}
	if payload > uint64(len(buf)) {
		return AllocationMap{}, corruptf("the %s page at offset %d is shorter than its %d-byte map", kind.Label(), offset, payload)
	}
	bits := append([]byte(nil), buf[:payload]...)
	return AllocationMap{
		Kind:        kind,
		Offset:      offset,
		BID:         bid,
		Bits:        bits,
		UnitBytes:   unit,
		MappedStart: offset,
	}, nil
}
