package zfs

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"io"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Reading and decompressing the block a pointer names. The pool's checksum
// covers the bytes as stored — after compression, including the four-byte LZ4
// length prefix — so verification happens before decoding. A block whose
// checksum disagrees is not returned as damaged data.
//
// A single-image reader knows one leaf vdev: a pointer naming any other vdev
// has no sibling image to read from and is refused by name rather than read
// from the wrong place.

// maxBlockSize is the largest block ZFS allocates, and the largest this
// reader will decode or allocate.
const maxBlockSize = 16 << 20

// BlockReader reads verified, decoded blocks from one image.
type BlockReader struct {
	source source.ByteSource
}

func newBlockReader(src source.ByteSource) *BlockReader {
	return &BlockReader{source: src}
}

// placement resolves a DVA to the physical offset of its stored bytes,
// without reading them.
func (r *BlockReader) placement(index int, dva Dva, psize uint64) (uint64, error) {
	if dva.gang() {
		return 0, unsupportedf("a gang block, whose child pointers are not followed")
	}
	if dva.vdev() != 0 {
		return 0, unsupportedf("a pointer into vdev %d, but this image holds vdev 0", dva.vdev())
	}
	rawOffset := dva.word1 & ((uint64(1) << 63) - 1)
	if rawOffset > (^uint64(0))>>minBlockShift {
		return 0, corruptf("dva %d's offset overflows a byte address", index)
	}
	logical := rawOffset << minBlockShift
	physical := logical + VDevLabelStartSize
	if physical < logical {
		return 0, corruptf("dva %d's physical offset overflows", index)
	}
	sourceLen := r.source.Len()
	deviceEnd := uint64(0)
	if sourceLen > VDevLabelEndSize {
		deviceEnd = sourceLen - VDevLabelEndSize
	}
	if physical > deviceEnd || psize > deviceEnd-physical {
		return 0, corruptf(
			"a %d-byte block at physical offset %d (dva %d offset %d) runs past the leaf's allocatable area, which ends at %d",
			psize, physical, index, logical, deviceEnd)
	}
	return physical, nil
}

// location resolves the copy a read would try first to its physical offset
// and stored length. Embedded pointers and holes name no stored copy and
// return ok=false.
func (r *BlockReader) location(bp BlockPointer) (physical, stored uint64, ok bool, err error) {
	if bp.crypt() {
		return 0, 0, false, unsupportedf("an encrypted or authenticated block pointer; the key is not available")
	}
	if bp.embedded() || bp.isHole() {
		return 0, 0, false, nil
	}
	if bp.lsize() > maxBlockSize || bp.psize() > maxBlockSize {
		return 0, 0, false, corruptf("a %d-byte block; ZFS blocks stop at %d", maxU64(bp.lsize(), bp.psize()), maxBlockSize)
	}
	psize := bp.psize()
	for index := 0; index < 3; index++ {
		dva, present := bp.dva(index)
		if !present {
			break
		}
		if dva.isEmpty() {
			continue
		}
		physical, err := r.placement(index, dva, psize)
		if err != nil {
			return 0, 0, false, err
		}
		return physical, psize, true, nil
	}
	return 0, 0, false, corruptf("a block pointer with no readable copy")
}

// read returns the logical bytes a pointer describes, verified and decoded.
func (r *BlockReader) read(bp BlockPointer) ([]byte, error) {
	if bp.crypt() {
		return nil, unsupportedf("an encrypted or authenticated block pointer; the key is not available")
	}
	if bp.embedded() {
		payload, err := bp.embeddedPayload()
		if err != nil {
			return nil, err
		}
		return decompressBlock(bp.compression(), payload, int(bp.lsize()), "an embedded block pointer")
	}
	if bp.isHole() {
		if bp.lsize() > maxBlockSize {
			return nil, corruptf("a hole of %d bytes", bp.lsize())
		}
		return make([]byte, int(bp.lsize())), nil
	}
	if bp.lsize() > maxBlockSize || bp.psize() > maxBlockSize {
		return nil, corruptf("a %d-byte block; ZFS blocks stop at %d", maxU64(bp.lsize(), bp.psize()), maxBlockSize)
	}
	checksum := bp.checksum()
	if checksum == ChecksumOther {
		return nil, unsupportedf("ZFS checksum id %d is not a fletcher or SHA-256 checksum", bp.checksumID())
	}
	physical, psize, ok, err := r.location(bp)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, corruptf("a block pointer with no readable copy")
	}
	stored := make([]byte, psize)
	if err := source.ReadExactAt(r.source, physical, stored); err != nil {
		return nil, err
	}
	verified, err := verifyChecksum(checksum, stored, bp.checksumBytes())
	if err != nil {
		return nil, err
	}
	if !verified {
		dva, _ := bp.dva(0)
		return nil, corruptf("%s checksum mismatch at physical offset %d (vdev %d dva 0 offset %d)",
			checksum.label(), physical, dva.vdev(), dva.offset())
	}
	if bp.compression() == CompressionOther {
		return nil, unsupportedf("compression id %d on a block", bp.compressionID())
	}
	return decompressBlock(bp.compression(), stored, int(bp.lsize()), "a block")
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// decompressBlock decodes a stored block body to exactly logical bytes.
func decompressBlock(compression Compression, stored []byte, logical int, what string) ([]byte, error) {
	if logical < 0 || logical > maxBlockSize {
		return nil, corruptf("%s claims %d logical bytes", what, logical)
	}
	var data []byte
	var err error
	switch {
	case compression == CompressionOff || compression == CompressionInherit || compression == CompressionOn:
		data = append([]byte(nil), stored...)
	case compression == CompressionEmpty:
		data = make([]byte, logical)
	case compression == CompressionLZJB:
		data, err = decodeLZJB(stored, logical)
	case compression == CompressionZLE:
		data, err = decodeZLE(stored, logical)
	case compression == CompressionLZ4:
		data, err = decodeLZ4(stored, logical)
	case compression.isGzip():
		data, err = decodeGzip(stored, logical)
	case compression == CompressionZstd:
		return nil, unsupportedf("%s uses zstd compression, which this pure-Go reader does not implement", what)
	default:
		return nil, unsupportedf("%s uses a compression algorithm this reader does not implement", what)
	}
	if err != nil {
		return nil, err
	}
	if len(data) != logical {
		return nil, corruptf("%s decoded to %d bytes; the pointer says %d", what, len(data), logical)
	}
	return data, nil
}

// decodeLZ4 reads ZFS's LZ4 block: a four-byte big-endian compressed length,
// then one raw LZ4 block.
//
// The prefix is not the logical size and not little-endian. OpenZFS writes
// BE_32(bufsiz), the exact number of bytes the compressor produced, because
// the stored block is rounded up to a sector and the decoder must know where
// the stream ends.
func decodeLZ4(stored []byte, logical int) ([]byte, error) {
	if len(stored) < 4 {
		return nil, corruptf("an LZ4 block shorter than its size prefix")
	}
	compressed := int(binary.BigEndian.Uint32(stored))
	if compressed == 0 || compressed+4 > len(stored) {
		return nil, corruptf("an LZ4 block declares %d compressed bytes; the stored block holds %d", compressed, len(stored))
	}
	return decodeLZ4Block(stored[4:4+compressed], logical)
}

func decodeLZ4Block(stored []byte, logical int) ([]byte, error) {
	out := make([]byte, 0, logical)
	position := 0
	for position < len(stored) {
		token := stored[position]
		position++
		literals := int(token >> 4)
		if literals == 15 {
			for {
				if position >= len(stored) {
					return nil, corruptf("an LZ4 literal length is truncated")
				}
				value := int(stored[position])
				position++
				literals += value
				if value != 255 {
					break
				}
			}
		}
		if literals < 0 || position > len(stored)-literals {
			return nil, corruptf("an LZ4 literal run passes the end of the block")
		}
		if literals > logical-len(out) {
			return nil, corruptf("an LZ4 literal run passes the logical size")
		}
		out = append(out, stored[position:position+literals]...)
		position += literals
		if position == len(stored) {
			break
		}
		if position+2 > len(stored) {
			return nil, corruptf("an LZ4 match offset is truncated")
		}
		offset := int(stored[position]) | int(stored[position+1])<<8
		position += 2
		if offset == 0 || offset > len(out) {
			return nil, corruptf("an LZ4 match offset points before the block")
		}
		match := int(token&0x0f) + 4
		if token&0x0f == 15 {
			for {
				if position >= len(stored) {
					return nil, corruptf("an LZ4 match length is truncated")
				}
				value := int(stored[position])
				position++
				match += value
				if value != 255 {
					break
				}
			}
		}
		if match > logical-len(out) {
			return nil, corruptf("an LZ4 match passes the logical size")
		}
		for i := 0; i < match; i++ {
			out = append(out, out[len(out)-offset])
		}
	}
	return out, nil
}

// decodeZLE reads zero-length encoding: a length byte then that many
// literals, or a run of zeroes when the length byte encodes more than the
// 64-byte literal limit.
func decodeZLE(stored []byte, logical int) ([]byte, error) {
	const literalLimit = 64
	out := make([]byte, 0, logical)
	position := 0
	for position < len(stored) && len(out) < logical {
		length := 1 + int(stored[position])
		position++
		if length <= literalLimit {
			if position > len(stored)-length {
				return nil, corruptf("a ZLE literal run passes the end of the block")
			}
			out = append(out, stored[position:position+length]...)
			position += length
			continue
		}
		length -= literalLimit
		if length > logical-len(out) {
			return nil, corruptf("a ZLE zero run passes the logical size")
		}
		out = append(out, make([]byte, length)...)
	}
	return out, nil
}

// decodeLZJB reads a bitmap byte, then eight items of either one literal or a
// three-bit-length / eleven-bit-distance back reference.
func decodeLZJB(stored []byte, logical int) ([]byte, error) {
	out := make([]byte, 0, logical)
	position := 0
	var copymap byte
	copymask := uint16(1) << 7
	for len(out) < logical {
		copymask <<= 1
		if copymask == 1<<8 {
			copymask = 1
			if position >= len(stored) {
				return nil, corruptf("an LZJB block ends inside a bitmap group")
			}
			copymap = stored[position]
			position++
		}
		if position >= len(stored) {
			return nil, corruptf("an LZJB block ends inside an item")
		}
		if copymap&byte(copymask) != 0 {
			if position+2 > len(stored) {
				return nil, corruptf("an LZJB back reference is truncated")
			}
			length := int(stored[position]>>2) + 3
			// OpenZFS stores the distance itself, not distance - 1, and a
			// match never has distance zero (the encoder requires a byte
			// before the match to compare against).
			distance := (int(stored[position]&0x03) << 8) | int(stored[position+1])
			position += 2
			if distance == 0 || distance > len(out) {
				return nil, corruptf("an LZJB back reference points before the block")
			}
			if length > logical-len(out) {
				return nil, corruptf("an LZJB back reference passes the logical size")
			}
			start := len(out) - distance
			for i := 0; i < length; i++ {
				out = append(out, out[start+i])
			}
			continue
		}
		out = append(out, stored[position])
		position++
	}
	return out, nil
}

// decodeGzip reads ZFS's gzip. OpenZFS's zlib wrapper writes an RFC 1950
// stream; a pool written by a variant that wrote raw DEFLATE is accepted as a
// fallback, since the block checksum has already vouched for the stored bytes.
func decodeGzip(stored []byte, logical int) ([]byte, error) {
	if data, ok := inflateZlib(stored, logical); ok {
		return data, nil
	}
	if data, ok := inflateFlate(stored, logical); ok {
		return data, nil
	}
	return nil, corruptf("a gzip block did not decode")
}

func inflateZlib(stored []byte, logical int) ([]byte, bool) {
	reader, err := zlib.NewReader(bytes.NewReader(stored))
	if err != nil {
		return nil, false
	}
	return inflateReader(reader, logical)
}

func inflateFlate(stored []byte, logical int) ([]byte, bool) {
	return inflateReader(flate.NewReader(bytes.NewReader(stored)), logical)
}

func inflateReader(reader io.ReadCloser, logical int) ([]byte, bool) {
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, int64(logical)+1))
	if err != nil || len(data) > logical {
		return nil, false
	}
	return data, true
}
