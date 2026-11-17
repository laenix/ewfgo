// SQLite 3 database carving.
//
// A SQLite database is a 100-byte header followed by a declared number of
// fixed-size pages. The header states the page size, the two format versions,
// the payload fractions, the reserved bytes per page and the schema format.
// Each following page starts with a b-tree page header whose cell pointers must
// land inside the page, and every cell carries varints and payload whose lengths
// have to fit the page (an overflow payload also carries the page number of the
// next overflow page).
//
// The walk validates all of that before the header's page count becomes an
// object extent. Freelist trunks and their leaf pages are part of the database
// and are read as pages too; an all-zero page is accepted as a free page, which
// is the byte a wiped free page holds. If the source ends before the declared
// pages do, the object is kept as truncated and no page is invented past the
// bytes that exist.

package carving

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// A page count above this is not walked: a header that names a million pages is
// either a huge database or a damaged one, and the carve bound would stop the
// walk anyway.
const sqliteMaxPages uint64 = 1 << 20

// Trunk pages in the freelist chain.
const sqliteMaxFreelistTrunks uint64 = 1 << 16

// Cell pointers, cells and freeblocks are all inside one page, so a page that
// needs more than this many freeblock steps is not a page.
const sqliteMaxFreeblocks = 256

const sqliteHeaderLen uint64 = 100

func sqliteBounds(src source.ByteSource, start, limit uint64) (*bounds, error) {
	if satSub(limit, start) < sqliteHeaderLen {
		return nil, nil
	}
	header, err := readVec(src, start, sqliteHeaderLen)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header[0:16], []byte("SQLite format 3\x00")) {
		return nil, nil
	}

	rawPageSize := binary.BigEndian.Uint16(header[16:18])
	var pageSize uint64
	switch {
	case rawPageSize == 1:
		pageSize = 65536
	case rawPageSize >= 512 && rawPageSize <= 32768 && rawPageSize&(rawPageSize-1) == 0:
		pageSize = uint64(rawPageSize)
	default:
		return nil, nil
	}
	writeVersion := header[18]
	readVersion := header[19]
	if !(writeVersion >= 1 && writeVersion <= 2) || !(readVersion >= 1 && readVersion <= 2) {
		return nil, nil
	}
	reserved := uint64(header[20])
	if reserved >= pageSize || pageSize-reserved < 480 {
		return nil, nil
	}
	// Payload fractions are fixed by the format; a header whose fractions
	// differ is not a database this walk knows.
	maxPayload, minPayload, leafPayload := header[21], header[22], header[23]
	if maxPayload != 64 || minPayload != 32 || leafPayload != 32 {
		return nil, nil
	}
	pageCount := uint64(binary.BigEndian.Uint32(header[28:32]))
	if pageCount == 0 {
		return nil, nil
	}
	schemaFormat := binary.BigEndian.Uint32(header[44:48])
	if schemaFormat < 1 || schemaFormat > 4 {
		return nil, nil
	}
	// The 20 bytes at 72..92 are reserved for expansion and are zero in a
	// database SQLite itself wrote.
	for _, b := range header[72:92] {
		if b != 0 {
			return nil, nil
		}
	}
	encoding := binary.BigEndian.Uint32(header[56:60])
	if encoding < 1 || encoding > 3 {
		return nil, nil
	}

	usable := pageSize - reserved
	firstTrunk := uint64(binary.BigEndian.Uint32(header[32:36]))
	freelistCount := uint64(binary.BigEndian.Uint32(header[36:40]))
	if (firstTrunk == 0) != (freelistCount == 0) {
		return nil, nil
	}
	if pageCount > sqliteMaxPages {
		end := satAdd(start, sqliteMaxPages*pageSize)
		if end > limit {
			end = limit
		}
		return cappedAt(end, sqliteMaxPages, sqliteMaxPages, "SQLite page"), nil
	}

	freelist, ok, err := sqliteReadFreelist(src, start, header, pageCount, pageSize, usable)
	if err != nil {
		var sourceErr *source.Error
		if errors.As(err, &sourceErr) {
			return nil, nil
		}
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	var freePages, pages uint64
	for index := uint64(1); index <= pageCount; index++ {
		pageAt := start + (index-1)*pageSize
		if satAdd(pageAt, pageSize) > limit {
			return truncatedAt(limit, uint32(pages), "the declared page count runs past the bound"), nil
		}
		page, err := readVec(src, pageAt, pageSize)
		if err != nil {
			return nil, err
		}
		headerAt := 0
		if index == 1 {
			headerAt = int(sqliteHeaderLen)
		}
		pageType := page[headerAt]
		// Page 1 holds the 100-byte header and must be a b-tree root; it can
		// never be a free page.
		if index == 1 && pageType == 0 {
			return nil, nil
		}
		onFreelist := freelist[index]
		if pageType == 0 || onFreelist {
			// A free page keeps no b-tree header; a freelist leaf may still hold
			// the bytes of the row it used to store.
			freePages++
			pages++
			continue
		}
		if pageType != 2 && pageType != 5 && pageType != 10 && pageType != 13 {
			return nil, nil
		}
		if !sqliteBtreePage(page, headerAt, usable, pageCount) {
			return nil, nil
		}
		pages++
	}

	return &bounds{
		End:        start + pageCount*pageSize,
		Terminated: true,
		Detail: fmt.Sprintf(
			"%d page(s) of %d bytes, %d free, schema format %d, page 1 header verified",
			pages, pageSize, freePages, schemaFormat,
		),
	}, nil
}

// sqliteReadFreelist walks the freelist trunk chain into a page-number bitmap.
//
// It returns ok=false when the chain is structurally impossible (a trunk
// pointing outside the database, a leaf count that does not fit the page, a
// loop). Returning the bitmap lets the page walk treat those pages as free even
// when their old bytes still look like a b-tree page.
func sqliteReadFreelist(src source.ByteSource, start uint64, header []byte, pageCount, pageSize, usable uint64) ([]bool, bool, error) {
	free := make([]bool, pageCount+1)
	trunk := uint64(binary.BigEndian.Uint32(header[32:36]))
	declared := uint64(binary.BigEndian.Uint32(header[36:40]))
	if trunk == 0 {
		return free, true, nil
	}
	var trunks, leaves uint64
	for trunk != 0 {
		if trunk == 1 || trunk > pageCount {
			return nil, false, nil
		}
		if free[trunk] {
			// A trunk seen twice is a loop.
			return nil, false, nil
		}
		free[trunk] = true
		trunks++
		if trunks > sqliteMaxFreelistTrunks {
			return nil, false, nil
		}
		pageAt := start + (trunk-1)*pageSize
		// The trunk header is the first 8 bytes of the page, independent of the
		// reserved bytes at its end.
		var head [8]byte
		if err := source.ReadExactAt(src, pageAt, head[:]); err != nil {
			return nil, false, err
		}
		next := uint64(binary.BigEndian.Uint32(head[0:4]))
		count := uint64(binary.BigEndian.Uint32(head[4:8]))
		if satAdd(8, count*4) > usable {
			return nil, false, nil
		}
		var leafBytes [4]byte
		for index := uint64(0); index < count; index++ {
			if err := source.ReadExactAt(src, pageAt+8+index*4, leafBytes[:]); err != nil {
				return nil, false, err
			}
			leaf := uint64(binary.BigEndian.Uint32(leafBytes[:]))
			if leaf == 0 || leaf == 1 || leaf > pageCount {
				return nil, false, nil
			}
			if free[leaf] {
				return nil, false, nil
			}
			free[leaf] = true
			leaves++
		}
		trunk = next
	}
	if trunks+leaves != declared {
		return nil, false, nil
	}
	return free, true, nil
}

// sqliteBtreePage validates one b-tree page header and every cell pointer it
// holds.
func sqliteBtreePage(page []byte, headerAt int, usable, pageCount uint64) bool {
	u := int(usable)
	if headerAt+8 > u {
		return false
	}
	kind := page[headerAt]
	interior := kind == 2 || kind == 5
	headerLen := 8
	if interior {
		headerLen = 12
	}
	headerEnd := headerAt + headerLen
	if headerEnd > u {
		return false
	}
	firstFree := int(binary.BigEndian.Uint16(page[headerAt+1 : headerAt+3]))
	cells := int(binary.BigEndian.Uint16(page[headerAt+3 : headerAt+5]))
	rawContent := int(binary.BigEndian.Uint16(page[headerAt+5 : headerAt+7]))
	fragmented := page[headerAt+7]
	if fragmented > 60 {
		return false
	}
	if firstFree != 0 {
		if firstFree < headerEnd || firstFree+4 > u {
			return false
		}
		free := firstFree
		steps := 0
		for free != 0 {
			steps++
			if steps > sqliteMaxFreeblocks || free+4 > u {
				return false
			}
			next := int(binary.BigEndian.Uint16(page[free : free+2]))
			size := int(binary.BigEndian.Uint16(page[free+2 : free+4]))
			if size < 4 || free+size > u {
				return false
			}
			if next != 0 && (next <= free || next+4 > u) {
				return false
			}
			free = next
		}
	}
	// The content area starts after the cell pointer array; 0 means 65536, which
	// is only meaningful when the page itself is that large.
	content := rawContent
	if rawContent == 0 {
		if usable != 65536 {
			return false
		}
		content = 65536
	}
	if content > u {
		return false
	}
	pointerEnd := headerEnd + cells*2
	if pointerEnd > u || pointerEnd > content {
		return false
	}
	for index := 0; index < cells; index++ {
		at := headerEnd + index*2
		cellAt := int(binary.BigEndian.Uint16(page[at : at+2]))
		if cellAt < content || cellAt >= u {
			return false
		}
		if !sqliteCell(page, cellAt, u, kind, pageCount) {
			return false
		}
	}
	return true
}

func sqliteCell(page []byte, at, usable int, kind byte, pageCount uint64) bool {
	cursor := at
	if kind == 2 || kind == 5 {
		if cursor+4 > usable {
			return false
		}
		pageNumber := uint64(binary.BigEndian.Uint32(page[cursor : cursor+4]))
		if pageNumber == 0 || pageNumber > pageCount {
			return false
		}
		cursor += 4
	}
	if kind == 5 {
		// Table interior: only the child pointer and a rowid.
		_, _, ok := sqliteVarint(page, cursor)
		return ok
	}
	payload, length, ok := sqliteVarint(page, cursor)
	if !ok {
		return false
	}
	cursor += length
	if kind == 13 {
		// Table leaf cells carry the rowid after the payload length.
		_, length, ok = sqliteVarint(page, cursor)
		if !ok {
			return false
		}
		cursor += length
	}
	minLocal, maxLocal := sqlitePayloadLimits(usable, kind)
	var local uint64
	if payload <= maxLocal {
		local = payload
	} else {
		local = minLocal + (payload-minLocal)%(uint64(usable)-4)
	}
	if local > payload {
		return false
	}
	end := cursor + int(local)
	if end > usable {
		return false
	}
	if local < payload {
		// Overflow payloads name the next overflow page right after the local
		// bytes; a zero or out-of-range number is not a page this database
		// declares.
		if end+4 > usable {
			return false
		}
		next := uint64(binary.BigEndian.Uint32(page[end : end+4]))
		if next == 0 || next > pageCount {
			return false
		}
		end += 4
	}
	return end <= usable
}

// sqlitePayloadLimits is SQLite's local-payload bounds. The minimum uses 32/255
// for both b-tree kinds; the maximum uses 32/255 for a table leaf (usable - 35)
// and 64/255 for the index pages, whose cells hold no rowid.
func sqlitePayloadLimits(usable int, kind byte) (minLocal, maxLocal uint64) {
	base := uint64(usable) - 12
	minLocal = base*32/255 - 23
	if kind == 2 || kind == 10 {
		maxLocal = base*64/255 - 23
	} else {
		maxLocal = uint64(usable) - 35
	}
	return minLocal, maxLocal
}

// sqliteVarint reads a SQLite varint: seven bits per byte, the ninth byte
// carrying eight bits.
func sqliteVarint(page []byte, at int) (uint64, int, bool) {
	var value uint64
	for index := 0; index < 9; index++ {
		position := at + index
		if position < 0 || position >= len(page) {
			return 0, 0, false
		}
		b := page[position]
		if index == 8 {
			return (value << 8) | uint64(b), 9, true
		}
		value = (value << 7) | uint64(b&0x7F)
		if b < 0x80 {
			return value, index + 1, true
		}
	}
	return 0, 0, false
}
