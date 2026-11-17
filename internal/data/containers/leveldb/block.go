package leveldb

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/laenix/ewfgo/internal/data/foundation"
)

// BlockTrailerBytes is the compression byte plus four-byte checksum that
// follows every stored table block.
const BlockTrailerBytes = 5

// MaxBlockBytes is the largest block this reader will decompress. LevelDB's
// default block size is 4 KiB; the bound stops a corrupt handle from claiming
// memory.
const MaxBlockBytes = 64 * 1024 * 1024

// ChecksumKind is the algorithm a table names for its block trailers.
type ChecksumKind uint8

const (
	// ChecksumUnverified means the trailer is read but not recomputed.
	ChecksumUnverified ChecksumKind = iota
	// ChecksumCRC32C is LevelDB's masked CRC-32C over the payload and
	// compression byte.
	ChecksumCRC32C
)

// maskCRC applies LevelDB's mask to a CRC-32C before it is stored.
func maskCRC(crc uint32) uint32 {
	return bits.RotateLeft32(crc, -15) + 0xa282ead8
}

// BlockHandle names where a block lives and how many stored payload bytes it
// occupies. The five-byte trailer follows the payload.
type BlockHandle struct {
	Offset uint64
	Size   uint64
}

// DecodeBlockHandle decodes the two varints a handle is made of.
func DecodeBlockHandle(input []byte) (BlockHandle, int, bool) {
	offset, used, ok := readVarint(input)
	if !ok {
		return BlockHandle{}, 0, false
	}
	size, more, ok := readVarint(input[used:])
	if !ok {
		return BlockHandle{}, 0, false
	}
	return BlockHandle{Offset: offset, Size: size}, used + more, true
}

// Range checks the handle against a file length and returns the stored payload
// range.
func (h BlockHandle) Range(fileLen uint64) (offset, size uint64, err error) {
	end := h.Offset + h.Size
	if end < h.Offset {
		return 0, 0, invalid("a block handle overflows the file offset")
	}
	trailerEnd := end + BlockTrailerBytes
	if trailerEnd < end {
		return 0, 0, invalid("a block handle overflows the file offset")
	}
	if trailerEnd > fileLen {
		return 0, 0, invalid(fmt.Sprintf(
			"block [%d, %d) runs past the %d-byte table", h.Offset, trailerEnd, fileLen))
	}
	return h.Offset, h.Size, nil
}

// Block is a decoded block: decompressed bytes plus the compression byte it
// was stored with.
type Block struct {
	data        []byte
	compression byte
}

// DecodeBlock decodes a stored block: the payload plus its five-byte trailer.
// limit bounds the decompressed size. A CRC-32C trailer is verified unless
// checksum is ChecksumUnverified.
func DecodeBlock(stored []byte, checksum ChecksumKind, limit int) (*Block, error) {
	if len(stored) < BlockTrailerBytes {
		return nil, corrupt(0, fmt.Sprintf(
			"a stored block of %d bytes is shorter than its %d-byte trailer",
			len(stored), BlockTrailerBytes))
	}
	if limit <= 0 || limit > MaxBlockBytes {
		limit = MaxBlockBytes
	}
	split := len(stored) - BlockTrailerBytes
	payload := stored[:split]
	compression := stored[split]
	if checksum == ChecksumCRC32C {
		storedCRC := le32(stored, split+1)
		crc := foundation.CRC32CSeeded(foundation.CRC32CSeeded(0xFFFFFFFF, payload), []byte{compression})
		crc = ^crc
		masked := maskCRC(crc)
		if masked != storedCRC {
			return nil, corrupt(0, fmt.Sprintf(
				"a block checksum 0x%08x does not match the stored 0x%08x", masked, storedCRC))
		}
	}
	var data []byte
	switch compression {
	case 0:
		if len(payload) > limit {
			return nil, limitError("a stored block is %d bytes, above the %d-byte bound", len(payload), limit)
		}
		data = append([]byte(nil), payload...)
	case 1:
		decoded, err := snappyDecompress(payload, limit)
		if err != nil {
			if errors.Is(err, ErrLimitExceeded) {
				return nil, err
			}
			return nil, corrupt(0, fmt.Sprintf("a Snappy block did not decode: %v", err))
		}
		data = decoded
	default:
		return nil, unsupported(fmt.Sprintf("table block compression type %d", compression))
	}
	block := &Block{data: data, compression: compression}
	if err := block.validate(); err != nil {
		return nil, err
	}
	return block, nil
}

// BlockFromBytes builds a block from already-decompressed bytes.
func BlockFromBytes(data []byte) (*Block, error) {
	block := &Block{data: append([]byte(nil), data...)}
	if err := block.validate(); err != nil {
		return nil, err
	}
	return block, nil
}

// Compression returns the compression byte the block was stored with; zero for
// stored bytes.
func (b *Block) Compression() byte { return b.compression }

// Len returns the decompressed size.
func (b *Block) Len() int { return len(b.data) }

// IsEmpty reports whether the block has no bytes.
func (b *Block) IsEmpty() bool { return len(b.data) == 0 }

// restartCount returns the trailing restart-array count.
func (b *Block) restartCount() int {
	return int(le32(b.data, len(b.data)-4))
}

// validate checks the restart array against the block's own length.
func (b *Block) validate() error {
	length := len(b.data)
	if length < 4 {
		return corrupt(0, fmt.Sprintf("a block of %d bytes has no room for its restart count", length))
	}
	count := uint64(le32(b.data, length-4))
	arrayBytes := count * 4
	if arrayBytes+4 > uint64(length) {
		return corrupt(0, fmt.Sprintf(
			"a block of %d bytes cannot hold %d restart offsets", length, count))
	}
	entriesEnd := length - 4 - int(arrayBytes)
	restarts := b.data[entriesEnd : entriesEnd+int(arrayBytes)]
	bound := entriesEnd
	if bound < 1 {
		bound = 1
	}
	for at := 0; at+4 <= len(restarts); at += 4 {
		offset := int(le32(restarts, at))
		if offset >= bound {
			return corrupt(0, fmt.Sprintf(
				"a restart offset %d is outside the %d entry bytes", offset, entriesEnd))
		}
	}
	return nil
}

// entries returns the payload without its restart array.
func (b *Block) entries() []byte {
	length := len(b.data)
	count := uint64(le32(b.data, length-4))
	entriesEnd := length - 4 - int(count*4)
	return b.data[:entriesEnd]
}

// ForEach visits every entry in stored order. The key slice is rebuilt into one
// reusable buffer and is only valid for the duration of the call; the visitor
// returns false to stop. The number of entries visited is returned.
func (b *Block) ForEach(visit func(key, value []byte) bool) (int, error) {
	entries := b.entries()
	key := make([]byte, 0, 64)
	at := 0
	seen := 0
	for at < len(entries) {
		shared, used, ok := readVarint(entries[at:])
		if !ok {
			return seen, corrupt(0, fmt.Sprintf("entry at byte %d has no shared-length varint", at))
		}
		at += used
		unshared, used, ok := readVarint(entries[at:])
		if !ok {
			return seen, corrupt(0, fmt.Sprintf("entry at byte %d has no key-length varint", at))
		}
		at += used
		valueLen, used, ok := readVarint(entries[at:])
		if !ok {
			return seen, corrupt(0, fmt.Sprintf("entry at byte %d has no value-length varint", at))
		}
		at += used
		if shared > uint64(len(key)) {
			return seen, corrupt(0, fmt.Sprintf(
				"entry %d shares %d key bytes of a %d byte key", seen, shared, len(key)))
		}
		if unshared > uint64(len(entries)-at) {
			return seen, corrupt(0, fmt.Sprintf("entry %d's key runs past the entry bytes", seen))
		}
		keyEnd := at + int(unshared)
		key = key[:shared]
		key = append(key, entries[at:keyEnd]...)
		at = keyEnd
		if valueLen > uint64(len(entries)-at) {
			return seen, corrupt(0, fmt.Sprintf("entry %d's value runs past the entry bytes", seen))
		}
		valueEnd := at + int(valueLen)
		seen++
		if !visit(key, entries[at:valueEnd]) {
			return seen, nil
		}
		at = valueEnd
	}
	return seen, nil
}

// IndexValueFormat says how an index block encodes its values.
type IndexValueFormat struct {
	// DeltaEncoded is RocksDB format 4 and later: values carry a signed size
	// change rather than a full handle. This reader supports the LevelDB
	// layout only and refuses the flag explicitly.
	DeltaEncoded bool
	// FirstKey is kBinarySearchWithFirstKey: every value appends the data
	// block's first internal key.
	FirstKey bool
}

// ForEachIndex visits every entry of an index block, decoding its value as a
// block handle. Only the plain LevelDB layout is supported.
func (b *Block) ForEachIndex(format IndexValueFormat, visit func(key []byte, handle BlockHandle) bool) (int, error) {
	if format.DeltaEncoded || format.FirstKey {
		return 0, unsupported("a delta-encoded or first-key RocksDB index")
	}
	seen := 0
	var decodeErr error
	_, err := b.ForEach(func(key, value []byte) bool {
		handle, _, ok := DecodeBlockHandle(value)
		if !ok {
			decodeErr = corrupt(0, fmt.Sprintf("index entry %d holds no block handle", seen))
			return false
		}
		seen++
		return visit(key, handle)
	})
	if decodeErr != nil {
		return seen, decodeErr
	}
	return seen, err
}

// First returns the first entry, if the block is non-empty.
func (b *Block) First() (key, value []byte, ok bool, err error) {
	var found bool
	_, err = b.ForEach(func(k, v []byte) bool {
		key, value, found = append([]byte(nil), k...), append([]byte(nil), v...), true
		return false
	})
	return key, value, found, err
}

// Last returns the last entry, if the block is non-empty.
func (b *Block) Last() (key, value []byte, ok bool, err error) {
	var found bool
	_, err = b.ForEach(func(k, v []byte) bool {
		key, value, found = append([]byte(nil), k...), append([]byte(nil), v...), true
		return true
	})
	return key, value, found, err
}
