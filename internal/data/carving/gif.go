// GIF carving.
//
// A GIF is a header (GIF87a or GIF89a), a logical screen descriptor with an
// optional global color table, then a sequence of blocks: image descriptors
// (each with its own optional color table and an LZW sub-block chain) and
// extensions (each with a sub-block chain). The file ends at the 0x3B trailer,
// which is the only block byte that is an end marker.
//
// Everything the walk needs is stated by the file: the color-table sizes and
// the sub-block lengths. A byte that is not one of the three introducers is a
// refusal, not a short file.

package carving

import (
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Blocks (top-level blocks plus sub-blocks) one object may hold.
const gifMaxBlocks uint64 = 1 << 16

func gifBounds(src source.ByteSource, start, limit uint64) (*bounds, error) {
	if satSub(limit, start) < 13 {
		return nil, nil
	}
	head, err := readVec(src, start, 13)
	if err != nil {
		return nil, err
	}
	signature := string(head[0:6])
	if signature != "GIF87a" && signature != "GIF89a" {
		return nil, nil
	}
	width := binary.LittleEndian.Uint16(head[6:8])
	height := binary.LittleEndian.Uint16(head[8:10])
	if width == 0 || height == 0 {
		return nil, nil
	}
	packed := head[10]
	at := start + 13
	if packed&0x80 != 0 {
		table := uint64(3) << ((packed & 0x07) + 1)
		if satAdd(at, table) > limit {
			return truncatedAt(limit, 0, "the global color table runs past the bound"), nil
		}
		at += table
	}

	var blocks uint64
	for {
		if at >= limit {
			return truncatedAt(limit, uint32(blocks), "ran out before the 0x3B trailer"), nil
		}
		introducer, _, err := readU8(src, at, limit)
		if err != nil {
			return nil, err
		}
		switch introducer {
		case 0x3B:
			return &bounds{
				End:        at + 1,
				Terminated: true,
				Detail: fmt.Sprintf(
					"%d block(s), %dx%d, trailer at +%d",
					blocks, width, height, at+1-start,
				),
			}, nil
		case 0x2C:
			if satAdd(at, 10) > limit {
				return truncatedAt(limit, uint32(blocks), "ran out inside an image descriptor"), nil
			}
			descriptor, err := readVec(src, at+1, 9)
			if err != nil {
				return nil, err
			}
			imageWidth := binary.LittleEndian.Uint16(descriptor[4:6])
			imageHeight := binary.LittleEndian.Uint16(descriptor[6:8])
			if imageWidth == 0 || imageHeight == 0 {
				return nil, nil
			}
			imagePacked := descriptor[8]
			next := at + 10
			if imagePacked&0x80 != 0 {
				table := uint64(3) << ((imagePacked & 0x07) + 1)
				if satAdd(next, table) > limit {
					return truncatedAt(limit, uint32(blocks), "a local color table runs past the bound"), nil
				}
				next += table
			}
			if next >= limit {
				return truncatedAt(limit, uint32(blocks), "ran out before the LZW code size"), nil
			}
			codeSize, _, err := readU8(src, next, limit)
			if err != nil {
				return nil, err
			}
			if codeSize < 2 || codeSize > 8 {
				return nil, nil
			}
			next++
			blocks++
			after, stopped, err := gifSubBlocks(src, next, limit, &blocks)
			if err != nil {
				return nil, err
			}
			if stopped != nil {
				return stopped, nil
			}
			at = after
		case 0x21:
			if satAdd(at, 2) > limit {
				return truncatedAt(limit, uint32(blocks), "ran out inside an extension"), nil
			}
			// The extension label is followed by its own sub-block chain; the
			// fixed headers of the graphic-control, plain-text and application
			// extensions are themselves the first sub-block.
			blocks++
			after, stopped, err := gifSubBlocks(src, at+2, limit, &blocks)
			if err != nil {
				return nil, err
			}
			if stopped != nil {
				return stopped, nil
			}
			at = after
		default:
			return nil, nil
		}
		if blocks > gifMaxBlocks {
			return cappedAt(at, blocks, gifMaxBlocks, "GIF block"), nil
		}
	}
}

// gifSubBlocks walks a sub-block chain, returning the offset just past its zero
// terminator. A non-nil stopped bounds carries a truncation or a cap hit.
func gifSubBlocks(src source.ByteSource, at, limit uint64, blocks *uint64) (uint64, *bounds, error) {
	for {
		if at >= limit {
			return 0, truncatedAt(limit, uint32(*blocks), "a sub-block chain runs past the bound"), nil
		}
		length, _, err := readU8(src, at, limit)
		if err != nil {
			return 0, nil, err
		}
		at++
		if length == 0 {
			return at, nil, nil
		}
		if satAdd(at, uint64(length)) > limit {
			return 0, truncatedAt(limit, uint32(*blocks), "a sub-block runs past the bound"), nil
		}
		at += uint64(length)
		*blocks++
		if *blocks > gifMaxBlocks {
			return 0, cappedAt(at, *blocks, gifMaxBlocks, "GIF block"), nil
		}
	}
}
