package vmfs

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// The pointer-block cache (".pbc.sf") is a system file in the root directory.
// A single-indirect map's descriptor entries name pointer blocks by their
// position in a bitmap, not by a physical block number: bits 6..27 are the
// bitmap entry and bits 28..31 the item within it. The bitmap header lives at
// the start of the ".pbc.sf" data stream, and each item is a 64 KiB pointer
// block holding 1024 32-bit file-block ids.
//
// This reader bootstraps the cache from the root directory: ".pbc.sf" is an
// ordinary directory entry, its descriptor is read through the FDC, and its own
// map must be direct. A cache that is missing, uses an indirect map, or whose
// header is not the 16-items-per-entry shape the pointer-block id encoding
// assumes is refused by name; the rest of the volume still walks.
const (
	// pbEntryShift and pbEntryMask select a pointer block id's bitmap entry.
	pbEntryShift uint32 = 6
	pbEntryMask  uint32 = 0x003f_ffff
	// pbItemShift and pbItemMask select its item within the bitmap entry.
	pbItemShift uint32 = 28
	pbItemMask  uint32 = 0xf

	// pbcItemsPerEntry is the bitmap item shape the pointer-block id encoding
	// assumes.
	pbcItemsPerEntry uint32 = 16

	// pbcName is the pointer-block cache's name in the root directory.
	pbcName = ".pbc.sf"
)

// pbc is a loaded pointer-block cache.
type pbc struct {
	header bitmapHeader
	file   *fileSource
}

// loadPBC parses the cache header from a ".pbc.sf" data stream.
func loadPBC(file *fileSource) (*pbc, error) {
	header, err := readBitmapHeader(file, 0, pointerBlockItemSize, "the pointer-block cache (\".pbc.sf\") header")
	if err != nil {
		return nil, err
	}
	if header.itemsPerBitmapEntry != pbcItemsPerEntry {
		return nil, unsupportedf("the pointer-block cache (\".pbc.sf\") header at byte %d declares %d items per bitmap entry; the pointer-block id encoding this reader decodes assumes %d",
			header.at, header.itemsPerBitmapEntry, pbcItemsPerEntry)
	}
	return &pbc{header: header, file: file}, nil
}

// readPointerBlock reads the 64 KiB pointer block one PB id names.
func (p *pbc) readPointerBlock(id, owner uint32) ([]byte, error) {
	if blockType(id) != blkTypePB {
		return nil, corruptf("pointer block id 0x%08x used by file descriptor 0x%08x has type %d, not a pointer block (type 3)",
			id, owner, blockType(id))
	}
	entry := (id >> pbEntryShift) & pbEntryMask
	item := (id >> pbItemShift) & pbItemMask
	pos, ok := p.header.itemPos(entry, item)
	if !ok {
		return nil, corruptf("pointer block 0x%08x (bitmap entry %d, item %d) used by file descriptor 0x%08x is outside the %d items the .pbc.sf header at byte %d declares",
			id, entry, item, owner, p.header.totalItems, p.header.at)
	}
	end, ok := addChecked(pos, uint64(pointerBlockItemSize))
	if !ok {
		return nil, corruptf("a pointer block's byte range overflows")
	}
	if end > p.file.Len() {
		return nil, corruptf("pointer block 0x%08x used by file descriptor 0x%08x at .pbc.sf byte %d needs %d bytes, but .pbc.sf is %d bytes",
			id, owner, pos, pointerBlockItemSize, p.file.Len())
	}
	bytes := make([]byte, pointerBlockItemSize)
	if err := source.ReadExactAt(p.file, pos, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}
