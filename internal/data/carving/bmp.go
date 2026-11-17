// BMP carving.
//
// A BMP starts with BM, then a file header that states the file size and the
// pixel-data offset, then a DIB header that states the geometry. The walk
// checks the DIB size against the known header families, reads width, height,
// planes and bits per pixel, and computes the row-padded pixel size for the
// uncompressed layouts. The declared file size has to agree with that geometry;
// it is then the object's end, not a search for the next magic. A declared size
// larger than the bytes the source can deliver is a truncation, never an
// invented tail.

package carving

import (
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// DIB headers larger than this are not BMP headers this walk knows.
const bmpMaxDIB uint32 = 4096

// Color-table entries a palette may declare.
const bmpMaxColors uint32 = 1 << 16

type bmpGeometry struct {
	width       int64
	height      int64
	bpp         uint32
	compression uint32
	imageSize   uint32
	dibSize     uint32
	palette     uint64
	pixelOffset uint64
}

func bmpBounds(src source.ByteSource, start, limit uint64) (*bounds, error) {
	if satSub(limit, start) < 18 {
		return nil, nil
	}
	file, err := readVec(src, start, 14)
	if err != nil {
		return nil, err
	}
	if file[0] != 'B' || file[1] != 'M' {
		return nil, nil
	}
	declared := uint64(binary.LittleEndian.Uint32(file[2:6]))
	pixelOffset := uint64(binary.LittleEndian.Uint32(file[10:14]))
	if declared <= 14 || pixelOffset < 18 || pixelOffset > declared {
		return nil, nil
	}
	if satAdd(start, 18) > limit {
		return truncatedAt(limit, 0, "ran out inside the DIB header size"), nil
	}
	dibHead, err := readVec(src, start+14, 4)
	if err != nil {
		return nil, err
	}
	dibSize := binary.LittleEndian.Uint32(dibHead)
	if !bmpKnownDIB(dibSize) || dibSize > bmpMaxDIB {
		return nil, nil
	}
	frame := uint64(14) + uint64(dibSize)
	if satAdd(start, frame) > limit {
		return truncatedAt(limit, 0, "the DIB header runs past the bound"), nil
	}
	dib, err := readVec(src, start+14, uint64(dibSize))
	if err != nil {
		return nil, err
	}
	geometry, ok := bmpGeometryFor(dib, dibSize == 12, pixelOffset)
	if !ok {
		return nil, nil
	}
	if geometry.pixelOffset < frame+geometry.palette {
		return nil, nil
	}
	// Palette bytes are part of the offset the file states; they must be
	// readable for the header to describe a real image.
	if satAdd(start, geometry.pixelOffset) > limit {
		return truncatedAt(limit, 0, "the pixel-data offset runs past the bound"), nil
	}

	expected, predictable, overflow := bmpPixelBytes(&geometry)
	if overflow {
		return nil, nil
	}
	if predictable {
		if expected != declared {
			return nil, nil
		}
	} else if declared < geometry.pixelOffset {
		return nil, nil
	}
	if satAdd(start, declared) > limit {
		return truncatedAt(limit, 0, "the declared file size runs past the bound"), nil
	}
	return &bounds{
		End:        start + declared,
		Terminated: true,
		Detail: fmt.Sprintf(
			"%dx%d %d-bit, DIB %d bytes, pixel data at +%d, %s, declared size %d",
			geometry.width, geometry.height, geometry.bpp, geometry.dibSize,
			geometry.pixelOffset, bmpCompressionLabel(geometry.compression), declared,
		),
	}, nil
}

func bmpKnownDIB(size uint32) bool {
	switch size {
	case 12, 40, 52, 56, 64, 108, 124:
		return true
	default:
		return false
	}
}

// bmpGeometryFor reads the DIB family that starts at the given size. The DIB
// families differ in where the geometry starts, not in its meaning.
func bmpGeometryFor(dib []byte, core bool, pixelOffset uint64) (bmpGeometry, bool) {
	var empty bmpGeometry
	if core {
		if len(dib) < 12 {
			return empty, false
		}
		width := int64(binary.LittleEndian.Uint16(dib[4:6]))
		height := int64(binary.LittleEndian.Uint16(dib[6:8]))
		planes := binary.LittleEndian.Uint16(dib[8:10])
		bpp := uint32(binary.LittleEndian.Uint16(dib[10:12]))
		if width <= 0 || height <= 0 || planes != 1 || !bmpCoreBPP(bpp) {
			return empty, false
		}
		var colors uint32
		if bpp <= 8 {
			colors = 1 << bpp
		}
		return bmpGeometry{
			width:       width,
			height:      height,
			bpp:         bpp,
			compression: 0,
			imageSize:   0,
			dibSize:     12,
			palette:     uint64(colors) * 3,
			pixelOffset: pixelOffset,
		}, true
	}
	if len(dib) < 40 {
		return empty, false
	}
	width := int64(int32(binary.LittleEndian.Uint32(dib[4:8])))
	height := int64(int32(binary.LittleEndian.Uint32(dib[8:12])))
	planes := binary.LittleEndian.Uint16(dib[12:14])
	bpp := uint32(binary.LittleEndian.Uint16(dib[14:16]))
	compression := binary.LittleEndian.Uint32(dib[16:20])
	imageSize := binary.LittleEndian.Uint32(dib[20:24])
	colorsUsed := binary.LittleEndian.Uint32(dib[36:40])
	if width <= 0 || height == 0 || planes != 1 {
		return empty, false
	}
	if !bmpExtendedBPP(bpp) {
		return empty, false
	}
	if compression > 5 {
		return empty, false
	}
	switch compression {
	case 0: // BI_RGB
	case 3: // BI_BITFIELDS only makes sense for the 16- and 32-bit layouts.
		if bpp != 16 && bpp != 32 {
			return empty, false
		}
	case 1: // BI_RLE8
		if bpp != 8 {
			return empty, false
		}
	case 2: // BI_RLE4
		if bpp != 4 {
			return empty, false
		}
	case 4, 5: // BI_JPEG and BI_PNG embed a whole image stream.
		if bpp != 16 && bpp != 24 && bpp != 32 {
			return empty, false
		}
	default:
		return empty, false
	}
	if colorsUsed > bmpMaxColors {
		return empty, false
	}
	var colors uint32
	if colorsUsed > 0 {
		colors = colorsUsed
	} else if bpp <= 8 {
		colors = 1 << bpp
	}
	dibSize := uint32(40)
	switch {
	case len(dib) >= 124:
		dibSize = 124
	case len(dib) >= 108:
		dibSize = 108
	case len(dib) >= 64:
		dibSize = 64
	case len(dib) >= 56:
		dibSize = 56
	case len(dib) >= 52:
		dibSize = 52
	}
	return bmpGeometry{
		width:       bmpAbs64(width),
		height:      height,
		bpp:         bpp,
		compression: compression,
		imageSize:   imageSize,
		dibSize:     dibSize,
		palette:     uint64(colors) * 4,
		pixelOffset: pixelOffset,
	}, true
}

func bmpCoreBPP(bpp uint32) bool {
	return bpp == 1 || bpp == 4 || bpp == 8 || bpp == 24
}

func bmpExtendedBPP(bpp uint32) bool {
	switch bpp {
	case 1, 4, 8, 16, 24, 32:
		return true
	default:
		return false
	}
}

// bmpPixelBytes is the file size the DIB geometry implies, or the embedded
// stream's own size for the compressed layouts. predictable is false when the
// geometry cannot predict a compressed size, so the declared size is the only
// claim; overflow reports arithmetic overflow, which refuses the candidate.
func bmpPixelBytes(geometry *bmpGeometry) (value uint64, predictable bool, overflow bool) {
	if geometry.compression == 0 || geometry.compression == 3 {
		absWidth := bmpAbs64(geometry.width)
		absHeight := bmpAbs64(geometry.height)
		row := ((uint64(geometry.bpp)*uint64(absWidth) + 31) / 32) * 4
		if absHeight != 0 && row > ^uint64(0)/uint64(absHeight) {
			return 0, false, true
		}
		pixels := row * uint64(absHeight)
		if geometry.pixelOffset > ^uint64(0)-pixels {
			return 0, false, true
		}
		return geometry.pixelOffset + pixels, true, false
	}
	if geometry.imageSize > 0 {
		if geometry.pixelOffset > ^uint64(0)-uint64(geometry.imageSize) {
			return 0, false, true
		}
		return geometry.pixelOffset + uint64(geometry.imageSize), true, false
	}
	// A compressed BMP without a stated image size has no length the geometry
	// can predict; the file header still declares one, and it has to at least
	// cover the pixel offset.
	return 0, false, false
}

func bmpAbs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func bmpCompressionLabel(compression uint32) string {
	switch compression {
	case 0:
		return "BI_RGB"
	case 1:
		return "BI_RLE8"
	case 2:
		return "BI_RLE4"
	case 3:
		return "BI_BITFIELDS"
	case 4:
		return "BI_JPEG"
	case 5:
		return "BI_PNG"
	default:
		return "unknown compression"
	}
}
