package vmfs

import (
	"math"

	"github.com/laenix/ewfgo/internal/data/source"
)

// fdcBaseBlock is the block where the first file-descriptor bitmap header sits.
const fdcBaseBlock uint64 = 25

// bitmapEntrySize is the fixed byte span of one bitmap entry header (0x400).
const bitmapEntrySize uint64 = 0x400

// pointerBlockItemSize is the byte span of one pointer-block item (64 KiB).
const pointerBlockItemSize uint32 = 64 * 1024

// bitmapHeader is a validated vmfs_bitmap_header.
//
// The area after the header starts with bmp_entries_per_area bitmap entries of
// bitmapEntrySize bytes, followed by the items themselves, each data_size bytes.
// itemPos implements the documented position formula. The fixed size of one
// area is not trusted: the SANS figures and the documented formula disagree
// about whether bitmap entries occupy 0x400 or data_size bytes, so only the
// formula's own pieces are used and every item is bounds-checked when read.
type bitmapHeader struct {
	itemsPerBitmapEntry uint32
	bmpEntriesPerArea   uint32
	hdrSize             uint32
	dataSize            uint32
	areaSize            uint32
	totalItems          uint32
	areaCount           uint32
	// at is the byte offset where the header itself was read, for errors.
	at uint64
}

func mulChecked(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func addChecked(a, b uint64) (uint64, bool) {
	if a > math.MaxUint64-b {
		return 0, false
	}
	return a + b, true
}

// readBitmapHeader reads and validates one bitmap header at at.
func readBitmapHeader(src source.ByteSource, at uint64, expectedDataSize uint32, what string) (bitmapHeader, error) {
	end, ok := addChecked(at, 28)
	if !ok {
		return bitmapHeader{}, corruptf("%s at byte %d overflows", what, at)
	}
	if end > src.Len() {
		return bitmapHeader{}, corruptf("%s at byte %d needs 28 bytes, but the source is %d bytes", what, at, src.Len())
	}
	raw := make([]byte, 28)
	if err := source.ReadExactAt(src, at, raw); err != nil {
		return bitmapHeader{}, err
	}
	h := bitmapHeader{
		itemsPerBitmapEntry: le32(raw, 0),
		bmpEntriesPerArea:   le32(raw, 4),
		hdrSize:             le32(raw, 8),
		dataSize:            le32(raw, 12),
		areaSize:            le32(raw, 16),
		totalItems:          le32(raw, 20),
		areaCount:           le32(raw, 24),
		at:                  at,
	}
	if err := h.validate(expectedDataSize, what); err != nil {
		return bitmapHeader{}, err
	}
	return h, nil
}

func (h *bitmapHeader) validate(expectedDataSize uint32, what string) error {
	if h.itemsPerBitmapEntry == 0 || h.itemsPerBitmapEntry > 0x10_0000 {
		return corruptf("%s at byte %d declares %d items per bitmap entry", what, h.at, h.itemsPerBitmapEntry)
	}
	if h.bmpEntriesPerArea == 0 || h.bmpEntriesPerArea > 0x10_0000 {
		return corruptf("%s at byte %d declares %d bitmap entries per area", what, h.at, h.bmpEntriesPerArea)
	}
	if h.hdrSize == 0 {
		return corruptf("%s at byte %d declares a zero header size", what, h.at)
	}
	if h.dataSize != expectedDataSize {
		return corruptf("%s at byte %d declares %d-byte items, expected %d", what, h.at, h.dataSize, expectedDataSize)
	}
	if h.areaSize == 0 {
		return corruptf("%s at byte %d declares a zero area size", what, h.at)
	}
	if h.areaCount == 0 {
		return corruptf("%s at byte %d declares zero areas", what, h.at)
	}
	if h.totalItems == 0 {
		return corruptf("%s at byte %d declares zero items", what, h.at)
	}
	perArea, ok := mulChecked(uint64(h.itemsPerBitmapEntry), uint64(h.bmpEntriesPerArea))
	if !ok {
		return corruptf("%s at byte %d: items per area overflows", what, h.at)
	}
	total, ok := mulChecked(perArea, uint64(h.areaCount))
	if !ok {
		return corruptf("%s at byte %d: total items overflow", what, h.at)
	}
	if total != uint64(h.totalItems) {
		return corruptf("%s at byte %d: %d areas of %d items name %d, not the declared %d",
			what, h.at, h.areaCount, perArea, total, h.totalItems)
	}
	return nil
}

// itemPos returns the byte offset of one item relative to the header's start.
func (h *bitmapHeader) itemPos(entry, item uint32) (uint64, bool) {
	addr, ok := mulChecked(uint64(entry), uint64(h.itemsPerBitmapEntry))
	if !ok {
		return 0, false
	}
	addr, ok = addChecked(addr, uint64(item))
	if !ok {
		return 0, false
	}
	perArea, ok := mulChecked(uint64(h.itemsPerBitmapEntry), uint64(h.bmpEntriesPerArea))
	if !ok || perArea == 0 {
		return 0, false
	}
	if addr >= uint64(h.totalItems) {
		return 0, false
	}
	area := addr / perArea
	if area >= uint64(h.areaCount) {
		return 0, false
	}
	within := addr % perArea
	pos, ok := mulChecked(area, uint64(h.areaSize))
	if !ok {
		return 0, false
	}
	pos, ok = addChecked(pos, uint64(h.hdrSize))
	if !ok {
		return 0, false
	}
	bmpBytes, ok := mulChecked(uint64(h.bmpEntriesPerArea), bitmapEntrySize)
	if !ok {
		return 0, false
	}
	pos, ok = addChecked(pos, bmpBytes)
	if !ok {
		return 0, false
	}
	itemBytes, ok := mulChecked(within, uint64(h.dataSize))
	if !ok {
		return 0, false
	}
	return addChecked(pos, itemBytes)
}
