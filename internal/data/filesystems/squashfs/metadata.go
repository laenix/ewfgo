package squashfs

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"

	"github.com/laenix/ewfgo/internal/data/containers/lzma"
	"github.com/laenix/ewfgo/internal/data/containers/xz"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// metadataBytes is the decompressed size of one metadata block.
	metadataBytes = 8192
	// uncompressedBit marks a metadata payload stored without compression.
	uncompressedBit = 1 << 15
	// maxSpanBytes bounds one metadata lookup.
	maxSpanBytes = 64 * 1024 * 1024
	// cacheBlocks is how many metadata blocks stay decompressed.
	cacheBlocks = 256
)

// headerFields splits a metadata block header into stored length and the
// uncompressed flag. A stored length of zero means the full 8192 bytes.
func headerFields(header uint16) (int, bool) {
	stored := int(header &^ uncompressedBit)
	if stored == 0 {
		stored = metadataBytes
	}
	return stored, header&uncompressedBit != 0
}

// decompressBlock decodes one compressed metadata or data block with a hard
// output bound.
func decompressBlock(compression uint16, input []byte, limit int) ([]byte, error) {
	if limit < 0 {
		return nil, corruptf("a %s block has a %d-byte output bound",
			compressionName(compression), limit)
	}
	switch compression {
	case compressionZLIB:
		reader := flate.NewReader(bytes.NewReader(input))
		defer reader.Close()
		out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
		if err != nil {
			return nil, corruptf("a zlib block did not decode: %v", err)
		}
		if len(out) > limit {
			return nil, corruptf("a zlib block decoded past the %d-byte bound", limit)
		}
		return out, nil
	case compressionLZMA:
		return decodeLZMABlock(input, limit)
	case compressionLZO:
		return decodeLZO1X(input, limit)
	case compressionXZ:
		return decodeXZBlock(input, limit)
	case compressionLZ4:
		out, err := decodeLZ4Block(input, uint64(limit))
		if err != nil {
			return nil, corruptf("an lz4 block did not decode: %v", err)
		}
		return out, nil
	case compressionZSTD:
		// No pure-Go Zstandard decoder lives in this repository; the block is
		// refused by name rather than guessed at.
		return nil, unsupportedf("%s compression", compressionName(compression))
	default:
		return nil, unsupportedf("%s compression", compressionName(compression))
	}
}

// decodeLZMABlock decodes one LZMA-alone block. SquashFS's LZMA wrapper stores
// the compressor's native stream unchanged: the 13-byte LZMA-alone header
// (property byte, dictionary size, declared unpacked size) followed by the
// range-coded payload.
func decodeLZMABlock(input []byte, limit int) ([]byte, error) {
	// Both decoders read a zero limit as "use the default cap", which would
	// silently widen the caller's bound; a one-byte bound keeps zero meaningful
	// and the explicit check below rejects any output.
	bound := uint64(limit)
	if bound == 0 {
		bound = 1
	}
	out, err := lzma.Decode(input, lzma.Limits{
		MaxDecodedBytes:    bound,
		MaxCompressedBytes: uint64(len(input)),
	})
	if err != nil {
		return nil, codecError("lzma", err)
	}
	if len(out) > limit {
		return nil, corruptf("an lzma block decoded past the %d-byte bound", limit)
	}
	return out, nil
}

// decodeXZBlock decodes one complete .xz container, as SquashFS's XZ wrapper
// stores each block.
func decodeXZBlock(input []byte, limit int) ([]byte, error) {
	// As in decodeLZMABlock, zero must not fall back to the decoder's default
	// cap.
	bound := uint64(limit)
	if bound == 0 {
		bound = 1
	}
	const id source.ID = 1
	stream, err := xz.Open(id, source.NewMemorySource(id, input), xz.Limits{
		MaxDecodedBytes:    bound,
		MaxCompressedBytes: uint64(len(input)),
	})
	if err != nil {
		return nil, codecError("xz", err)
	}
	if len(stream.Bytes()) > limit {
		return nil, corruptf("an xz block decoded past the %d-byte bound", limit)
	}
	return stream.Bytes(), nil
}

// codecError reports a codec-layer failure without losing its kind: a feature
// the decoder refuses stays ErrUnsupported, everything else is corruption.
func codecError(name string, err error) error {
	if errors.Is(err, source.ErrUnsupported) {
		return unsupportedf("an %s block was refused: %v", name, err)
	}
	return corruptf("an %s block did not decode: %v", name, err)
}

type metadataBlock struct {
	bytes []byte
	next  uint64
}

// readMetadataBlock reads and decompresses the metadata block at block.
func readMetadataBlock(src source.ByteSource, compression uint16, block uint64) (*metadataBlock, error) {
	end := block + 2
	if end < block || end > src.Len() {
		return nil, corruptf("the metadata block at %d lies past the %d bytes of the source", block, src.Len())
	}
	header := make([]byte, 2)
	if err := source.ReadExactAt(src, block, header); err != nil {
		return nil, err
	}
	storedLen, uncompressed := headerFields(binary.LittleEndian.Uint16(header))
	if storedLen > metadataBytes {
		return nil, corruptf("the metadata block at %d claims %d stored bytes, more than %d",
			block, storedLen, metadataBytes)
	}
	next := end + uint64(storedLen)
	if next < end || next > src.Len() {
		return nil, corruptf("the metadata block at %d runs past the %d bytes of the source", block, src.Len())
	}
	stored := make([]byte, storedLen)
	if err := source.ReadExactAt(src, end, stored); err != nil {
		return nil, err
	}
	var decoded []byte
	if uncompressed {
		decoded = stored
	} else {
		out, err := decompressBlock(compression, stored, metadataBytes)
		if err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return nil, corruptf("the metadata block at %d decoded to nothing", block)
		}
		decoded = out
	}
	return &metadataBlock{bytes: decoded, next: next}, nil
}

// metadataCache is a bounded cache of decompressed metadata blocks.
type metadataCache struct {
	compression uint16
	capacity    int
	blocks      map[uint64]*metadataBlock
	order       []uint64
}

func newMetadataCache(compression uint16) *metadataCache {
	return &metadataCache{
		compression: compression,
		capacity:    cacheBlocks,
		blocks:      make(map[uint64]*metadataBlock),
	}
}

func newUncachedMetadata(compression uint16) *metadataCache {
	return &metadataCache{
		compression: compression,
		blocks:      make(map[uint64]*metadataBlock),
	}
}

func (c *metadataCache) block(src source.ByteSource, block uint64) (*metadataBlock, error) {
	if found, ok := c.blocks[block]; ok {
		return found, nil
	}
	entry, err := readMetadataBlock(src, c.compression, block)
	if err != nil {
		return nil, err
	}
	if c.capacity > 0 {
		for len(c.blocks) >= c.capacity && len(c.order) > 0 {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.blocks, oldest)
		}
		c.order = append(c.order, block)
		c.blocks[block] = entry
	}
	return entry, nil
}

// span reads len bytes starting at offset in the block at block, continuing
// into following blocks when the read crosses a boundary.
func (c *metadataCache) span(src source.ByteSource, block uint64, offset, length int) ([]byte, error) {
	out, _, _, err := c.spanCursor(src, block, offset, length)
	return out, err
}

// spanCursor is span, also reporting where the read stopped.
func (c *metadataCache) spanCursor(src source.ByteSource, block uint64, offset, length int) ([]byte, uint64, int, error) {
	if offset >= metadataBytes {
		return nil, 0, 0, corruptf("offset %d is past the %d-byte metadata block at %d",
			offset, metadataBytes, block)
	}
	if length < 0 || length > maxSpanBytes {
		return nil, 0, 0, corruptf("a %d-byte metadata span is outside the %d-byte bound", length, maxSpanBytes)
	}
	out := make([]byte, length)
	filled := 0
	for filled < length {
		entry, err := c.block(src, block)
		if err != nil {
			return nil, 0, 0, err
		}
		if offset >= len(entry.bytes) {
			return nil, 0, 0, corruptf("offset %d is past the %d decoded bytes of the metadata block at %d",
				offset, len(entry.bytes), block)
		}
		take := len(entry.bytes) - offset
		if remaining := length - filled; take > remaining {
			take = remaining
		}
		copy(out[filled:filled+take], entry.bytes[offset:offset+take])
		filled += take
		offset += take
		if offset == len(entry.bytes) {
			if entry.next <= block {
				return nil, 0, 0, corruptf("the metadata block at %d does not advance", block)
			}
			block = entry.next
			offset = 0
		}
	}
	return out, block, offset, nil
}
