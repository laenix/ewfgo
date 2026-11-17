// WebP carving.
//
// WebP is a RIFF container: RIFF, a little-endian size at offset 4, WEBP at
// offset 8, then chunks (fourcc, little-endian size, payload, pad to an even
// length). The RIFF size is the file's own length claim. The walk follows the
// chunks to that end and requires the chunks to prove what they are: a VP8
// keyframe start code, a VP8L signature byte, a VP8X extension header with zero
// reserved bits, or one of the animation/auxiliary chunks with a minimum length.
// At least one image-bearing chunk must be present, and a VP8X must come first,
// as the format requires.

package carving

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// RIFF chunks one WebP may hold.
const webpMaxChunks uint64 = 1024

func webpBounds(src source.ByteSource, start, limit uint64) (*bounds, error) {
	if satSub(limit, start) < 12 {
		return nil, nil
	}
	head, err := readVec(src, start, 12)
	if err != nil {
		return nil, err
	}
	if string(head[0:4]) != "RIFF" || string(head[8:12]) != "WEBP" {
		return nil, nil
	}
	riffSize := uint64(binary.LittleEndian.Uint32(head[4:8]))
	if riffSize < 12 {
		return nil, nil
	}
	end := satAdd(start, satAdd(8, riffSize))
	if end > limit {
		return truncatedAt(limit, 0, "the RIFF size runs past the bound"), nil
	}

	at := start + 12
	var chunks, imageChunks uint64
	first := true
	for at < end {
		if satSub(end, at) < 8 {
			return nil, nil
		}
		chunkHead, err := readVec(src, at, 8)
		if err != nil {
			return nil, err
		}
		fourcc := chunkHead[0:4]
		size := uint64(binary.LittleEndian.Uint32(chunkHead[4:8]))
		payload := at + 8
		dataEnd := satAdd(payload, size)
		next := satAdd(dataEnd, size&1)
		if dataEnd > end || next > end {
			return nil, nil
		}
		// A WebP starts with the extended header or directly with the image
		// bitstream; any other first chunk means the file did not begin here.
		if first && !isWebPFirstChunk(fourcc) {
			return nil, nil
		}
		valid := false
		switch {
		case bytes.Equal(fourcc, []byte("VP8 ")):
			if size < 10 {
				return nil, nil
			}
			frame, err := readVec(src, payload, 10)
			if err != nil {
				return nil, err
			}
			valid = bytes.Equal(frame[3:6], []byte{0x9D, 0x01, 0x2A})
		case bytes.Equal(fourcc, []byte("VP8L")):
			if size < 5 {
				return nil, nil
			}
			header, err := readVec(src, payload, 5)
			if err != nil {
				return nil, err
			}
			valid = header[0] == 0x2F
		case bytes.Equal(fourcc, []byte("VP8X")):
			if size < 10 {
				return nil, nil
			}
			header, err := readVec(src, payload, 10)
			if err != nil {
				return nil, err
			}
			// Bits 0-1 of the flag byte are reserved, as are the three bytes
			// that follow it.
			valid = header[0]&0x03 == 0 && header[1] == 0 && header[2] == 0 && header[3] == 0
		case bytes.Equal(fourcc, []byte("ANIM")):
			valid = size >= 6
		case bytes.Equal(fourcc, []byte("ANMF")):
			valid = size >= 16
		case bytes.Equal(fourcc, []byte("ALPH")):
			valid = size >= 1
		case bytes.Equal(fourcc, []byte("ICCP")) ||
			bytes.Equal(fourcc, []byte("EXIF")) ||
			bytes.Equal(fourcc, []byte("XMP ")):
			valid = true
		default:
			valid = true
		}
		if !valid {
			return nil, nil
		}
		if bytes.Equal(fourcc, []byte("VP8 ")) ||
			bytes.Equal(fourcc, []byte("VP8L")) ||
			bytes.Equal(fourcc, []byte("ANMF")) {
			imageChunks++
		}
		first = false
		chunks++
		if chunks > webpMaxChunks {
			return cappedAt(at, chunks, webpMaxChunks, "WebP RIFF chunk"), nil
		}
		at = next
	}
	if at != end || imageChunks == 0 {
		return nil, nil
	}
	return &bounds{
		End:        end,
		Terminated: true,
		Detail: fmt.Sprintf(
			"%d RIFF chunk(s), %d image chunk(s), RIFF end at +%d",
			chunks, imageChunks, end-start,
		),
	}, nil
}

func isWebPFirstChunk(fourcc []byte) bool {
	return bytes.Equal(fourcc, []byte("VP8X")) ||
		bytes.Equal(fourcc, []byte("VP8 ")) ||
		bytes.Equal(fourcc, []byte("VP8L"))
}
