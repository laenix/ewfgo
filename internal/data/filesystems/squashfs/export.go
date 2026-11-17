package squashfs

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	exportEntryBytes    = 8
	exportEntriesPerBlk = metadataBytes / exportEntryBytes
	maxExportInodes     = 1 << 30
)

// ExportTable is the inode-number lookup table an image declares.
type ExportTable struct {
	index  []uint64
	inodes uint32
}

// readExportTable reads the table an image declares, if it declares one.
// Ok(nil, nil) means the image has no export table.
func readExportTable(src source.ByteSource, sb *superblock) (*ExportTable, error) {
	start := sb.exportTableStart
	if !sb.hasFlag(flagExport) {
		if start != invalidTable {
			return nil, corruptf("the superblock has no export flag but names an export table at %d", start)
		}
		return nil, nil
	}
	if start == invalidTable {
		return nil, corruptf("the export flag is set but the superblock names no export table")
	}
	if start >= sb.bytesUsed {
		return nil, corruptf("the export table at %d lies outside the %d bytes in use", start, sb.bytesUsed)
	}
	inodes := sb.inodeCount
	if inodes == 0 {
		return nil, corruptf("the export table is present but the image claims no inodes")
	}
	if inodes > maxExportInodes {
		return nil, corruptf("the export table would cover %d inode numbers, more than %d", inodes, maxExportInodes)
	}
	blocks := int((uint64(inodes)*exportEntryBytes + metadataBytes - 1) / metadataBytes)
	length := uint64(blocks) * exportEntryBytes
	if start > sb.bytesUsed || length > sb.bytesUsed-start {
		return nil, corruptf("a %d-byte export index at %d does not fit in the %d bytes in use",
			length, start, sb.bytesUsed)
	}
	raw := make([]byte, int(length))
	if err := source.ReadExactAt(src, start, raw); err != nil {
		return nil, err
	}
	index := make([]uint64, blocks)
	for i := range index {
		index[i] = binary.LittleEndian.Uint64(raw[i*exportEntryBytes:])
	}
	var previous uint64
	havePrevious := false
	for position, block := range index {
		if block >= start {
			return nil, corruptf("lookup block %d at %d does not lie before the export index at %d",
				position, block, start)
		}
		if block+2 > start {
			return nil, corruptf("lookup block %d at %d leaves no room for a metadata header",
				position, block)
		}
		if havePrevious && block <= previous {
			return nil, corruptf("lookup block %d at %d does not follow the previous block",
				position, block)
		}
		previous = block
		havePrevious = true
	}
	return &ExportTable{index: index, inodes: inodes}, nil
}

// Inodes is the number of inode numbers the table covers: 1 through this
// value.
func (t *ExportTable) Inodes() uint32 { return t.inodes }

// Blocks is the number of metadata blocks the index names.
func (t *ExportTable) Blocks() int { return len(t.index) }

// lookup returns the stored inode reference for number, when the number is
// inside the table.
func (t *ExportTable) lookup(cache *metadataCache, src source.ByteSource, number uint32) (uint64, bool, error) {
	if number == 0 || number > t.inodes {
		return 0, false, nil
	}
	index := uint64(number - 1)
	blockIndex := index / exportEntriesPerBlk
	if blockIndex >= uint64(len(t.index)) {
		return 0, false, nil
	}
	offset := int((index % exportEntriesPerBlk) * exportEntryBytes)
	entry, _, _, err := cache.spanCursor(src, t.index[blockIndex], offset, exportEntryBytes)
	if err != nil {
		return 0, false, err
	}
	return binary.LittleEndian.Uint64(entry), true, nil
}
