// TIFF carving.
//
// TIFF is a header (II*\0 little-endian or MM\0* big-endian), an offset to the
// first IFD, and a chain of IFDs. Each IFD states how many 12-byte entries
// follow; an entry states a type and a count, and when the value does not fit
// in the entry's four inline bytes it points at a file offset where the value
// lives. The walk follows every such pointer with bounds checks, follows the
// next-IFD chain with a visited set so a loop is refused, and extends the extent
// over the strip/tile data that the IFD references.
//
// The end is the highest byte any IFD table, out-of-line value or referenced
// strip/tile reaches. A referenced range that runs past the readable bytes marks
// the object truncated; an offset outside the file is a refusal.

package carving

import (
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// IFDs one TIFF may chain.
const tiffMaxIFDs uint64 = 256

// Entries one IFD may hold.
const tiffMaxEntries uint64 = 4096

// Elements one out-of-line value may hold.
const tiffMaxValues uint64 = 1 << 16

type tiffEndian uint8

const (
	tiffLittle tiffEndian = iota
	tiffBig
)

func (e tiffEndian) u16(bytes []byte) uint16 {
	if e == tiffLittle {
		return binary.LittleEndian.Uint16(bytes)
	}
	return binary.BigEndian.Uint16(bytes)
}

func (e tiffEndian) u32(bytes []byte) uint32 {
	if e == tiffLittle {
		return binary.LittleEndian.Uint32(bytes)
	}
	return binary.BigEndian.Uint32(bytes)
}

func tiffBounds(src source.ByteSource, start, limit uint64) (*bounds, error) {
	if satSub(limit, start) < 8 {
		return nil, nil
	}
	head, err := readVec(src, start, 8)
	if err != nil {
		return nil, err
	}
	var endian tiffEndian
	switch string(head[0:2]) {
	case "II":
		endian = tiffLittle
	case "MM":
		endian = tiffBig
	default:
		return nil, nil
	}
	if endian.u16(head[2:4]) != 42 {
		return nil, nil
	}
	firstIFD := uint64(endian.u32(head[4:8]))
	if firstIFD < 8 || firstIFD >= satSub(limit, start) {
		return nil, nil
	}

	visited := make(map[uint64]struct{})
	ifd := firstIFD
	var ifds, entries uint64
	end := start + 8
	for ifd != 0 {
		if ifds >= tiffMaxIFDs {
			return cappedAt(end, ifds, tiffMaxIFDs, "TIFF IFD"), nil
		}
		if ifd < 8 || ifd >= satSub(limit, start) {
			return nil, nil
		}
		if _, seen := visited[ifd]; seen {
			return nil, nil
		}
		visited[ifd] = struct{}{}
		ifds++

		at := start + ifd
		if satAdd(at, 2) > limit {
			return truncatedAt(limit, uint32(ifds), "the IFD entry count runs past the bound"), nil
		}
		countBytes, err := readVec(src, at, 2)
		if err != nil {
			return nil, err
		}
		count := uint64(endian.u16(countBytes))
		if count > tiffMaxEntries {
			return cappedAt(end, count, tiffMaxEntries, "TIFF IFD entry"), nil
		}
		table := 2 + count*12 + 4
		if satAdd(at, table) > limit {
			return truncatedAt(limit, uint32(ifds), "the IFD table runs past the bound"), nil
		}
		body, err := readVec(src, at, table)
		if err != nil {
			return nil, err
		}
		end = maxU64(end, at+table)
		entries += count

		var stripOffsets, stripCounts, tileOffsets, tileCounts []uint64

		for index := uint64(0); index < count; index++ {
			entry := body[2+index*12 : 2+index*12+12]
			tag := endian.u16(entry[0:2])
			kind := endian.u16(entry[2:4])
			values := uint64(endian.u32(entry[4:8]))
			size, ok := tiffTypeSize(kind)
			if !ok {
				return nil, nil
			}
			if values == 0 {
				return nil, nil
			}
			if values > tiffMaxValues {
				return cappedAt(end, values, tiffMaxValues, "TIFF value count"), nil
			}
			total, ok := mulNoOverflow(values, size)
			if !ok {
				return nil, nil
			}
			reference := tag == 273 || tag == 279 || tag == 324 || tag == 325
			numeric := kind == 3 || kind == 4
			if total <= 4 {
				if reference && numeric {
					if numbers, ok := tiffInlineNumbers(entry[8:8+total], endian, kind, values); ok {
						assignTIFFNumbers(tag, numbers, &stripOffsets, &stripCounts, &tileOffsets, &tileCounts)
					}
				}
				continue
			}
			offset := uint64(endian.u32(entry[8:12]))
			if offset < 8 || offset >= satSub(limit, start) {
				return nil, nil
			}
			if satAdd(start+offset, total) > limit {
				return truncatedAt(limit, uint32(ifds), "an out-of-line IFD value runs past the bound"), nil
			}
			end = maxU64(end, start+offset+total)
			// The value is read only when it is one of the tags whose offsets
			// this walk must cross-check. Other values are bounded by the same
			// check without being materialised.
			if reference && numeric {
				numbers, ok, err := tiffReadNumbers(src, endian, start+offset, kind, values)
				if err != nil {
					return nil, err
				}
				if !ok {
					return nil, nil
				}
				assignTIFFNumbers(tag, numbers, &stripOffsets, &stripCounts, &tileOffsets, &tileCounts)
			}
		}

		for _, pair := range [][2][]uint64{
			{stripOffsets, stripCounts},
			{tileOffsets, tileCounts},
		} {
			offsets, counts := pair[0], pair[1]
			for index, offset := range offsets {
				if index >= len(counts) {
					break
				}
				count := counts[index]
				if offset < 8 || offset >= satSub(limit, start) {
					return nil, nil
				}
				dataEnd := satAdd(start+offset, count)
				if dataEnd > limit {
					return truncatedAt(limit, uint32(ifds), "strip or tile data runs past the bound"), nil
				}
				end = maxU64(end, dataEnd)
			}
		}

		nextAt := at + 2 + count*12
		nextBytes, err := readVec(src, nextAt, 4)
		if err != nil {
			return nil, err
		}
		next := uint64(endian.u32(nextBytes))
		if next != 0 && (next < 8 || next >= satSub(limit, start)) {
			return nil, nil
		}
		ifd = next
	}

	byteOrder := "little-endian"
	if endian == tiffBig {
		byteOrder = "big-endian"
	}
	return &bounds{
		End:        end,
		Terminated: true,
		Detail: fmt.Sprintf(
			"%d IFD(s), %d entr(ies), %s byte order, data to +%d",
			ifds, entries, byteOrder, end-start,
		),
	}, nil
}

func tiffTypeSize(kind uint16) (uint64, bool) {
	switch kind {
	case 1, 2, 6, 7:
		return 1, true
	case 3, 8:
		return 2, true
	case 4, 9, 11, 13:
		return 4, true
	case 5, 10, 12:
		return 8, true
	default:
		return 0, false
	}
}

func tiffReadNumbers(src source.ByteSource, endian tiffEndian, at uint64, kind uint16, count uint64) ([]uint64, bool, error) {
	size, _ := tiffTypeSize(kind)
	bytes, err := readVec(src, at, count*size)
	if err != nil {
		return nil, false, err
	}
	numbers, ok := tiffInlineNumbers(bytes, endian, kind, count)
	return numbers, ok, nil
}

func tiffInlineNumbers(bytes []byte, endian tiffEndian, kind uint16, count uint64) ([]uint64, bool) {
	size, ok := tiffTypeSize(kind)
	if !ok {
		return nil, false
	}
	if uint64(len(bytes)) < count*size {
		return nil, false
	}
	out := make([]uint64, 0, count)
	for index := uint64(0); index < count; index++ {
		at := index * size
		switch kind {
		case 3:
			out = append(out, uint64(endian.u16(bytes[at:at+2])))
		case 4:
			out = append(out, uint64(endian.u32(bytes[at:at+4])))
		default:
			return nil, false
		}
	}
	return out, true
}

func assignTIFFNumbers(tag uint16, numbers []uint64, stripOffsets, stripCounts, tileOffsets, tileCounts *[]uint64) {
	switch tag {
	case 273:
		*stripOffsets = numbers
	case 279:
		*stripCounts = numbers
	case 324:
		*tileOffsets = numbers
	default:
		*tileCounts = numbers
	}
}

func mulNoOverflow(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
