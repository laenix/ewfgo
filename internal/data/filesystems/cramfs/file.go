package cramfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

// A file's blocks, exposed as a source.ByteSource.
//
// A regular file — and a symbolic link's target — starts with a block pointer
// table: one 32-bit word per 4 KiB block. The top two bits say what a word
// means:
//
//   - end pointers (the original form): a word is one past the last stored
//     byte of its block, so a block starts where the previous one ended — or,
//     for block zero, right after the pointer table. Two equal words mean the
//     block stores nothing: a hole, which reads as zeroes.
//   - direct pointers (flag 0x800): the low 30 bits, shifted left two, are the
//     block's absolute start. With the uncompressed bit the block is stored
//     as-is; without it the first two bytes are the stored length and the zlib
//     stream follows.
//
// A block's uncompressed bit says its stored bytes are the block itself.
// Otherwise the stored bytes are a zlib stream, wrapper included.

const (
	// blockSize is fixed by the format, not by the superblock.
	blockSize uint64 = 4096
	// uncompressedBit marks a block stored without compression.
	uncompressedBit uint32 = 1 << 31
	// directBit marks an absolute-start pointer.
	directBit uint32 = 1 << 30
	// flagBits are the two pointer flag bits the address part never uses.
	flagBits uint32 = uncompressedBit | directBit
	// directShift is the divide-by-four of a direct pointer's address.
	directShift = 2
	// maxStored is the kernel's ceiling for one stored block.
	maxStored uint64 = 2 * blockSize
	// prefixBytes is the length prefix of a compressed direct block.
	prefixBytes uint64 = 2
)

// block is one block: where its stored bytes are, how many, and whether they
// are stored as-is.
type block struct {
	start    uint64 // absolute image offset; zero for a hole
	stored   uint64 // stored byte count; zero for a hole
	raw      bool   // the stored bytes are the block itself
	prefixed bool   // a compressed direct block starts with a 16-bit length
}

func (b block) isHole() bool { return b.stored == 0 }

// fileSource serves one regular file's or symlink target's logical bytes.
type fileSource struct {
	id       source.ID
	src      source.ByteSource
	blocks   []block
	size     uint64
	mu       sync.Mutex
	cached   bool
	cacheIdx int
	cacheBuf []byte
	counters source.Counters
}

// newFileSource reads a file's block pointer table and validates every block.
// tableOffset is the absolute image offset the inode named, size the file's
// length, and limit the last byte any read may touch.
func newFileSource(id source.ID, src source.ByteSource, limit, tableOffset, size uint64) (*fileSource, error) {
	f := &fileSource{id: id, src: src, size: size}
	if size == 0 {
		return f, nil
	}
	count := (size + blockSize - 1) / blockSize
	if count > ^uint64(0)/4 {
		return nil, corruptf("a block pointer table overflows the address space")
	}
	tableBytes := count * 4
	if tableOffset > ^uint64(0)-tableBytes {
		return nil, corruptf("a block pointer table overflows the address space")
	}
	tableEnd := tableOffset + tableBytes
	if tableEnd > limit {
		return nil, corruptf("the %d-entry block table at %d runs past byte %d",
			count, tableOffset, limit)
	}
	words := make([]byte, tableBytes)
	if err := source.ReadExactAt(src, tableOffset, words); err != nil {
		return nil, err
	}

	nextStart := tableEnd
	f.blocks = make([]block, 0, count)
	for index := uint64(0); index < count; index++ {
		at := index * 4
		word := binary.LittleEndian.Uint32(words[at:])
		raw := word&uncompressedBit != 0
		logical := size - index*blockSize
		if logical > blockSize {
			logical = blockSize
		}

		var b block
		if word&directBit != 0 {
			start := uint64(word&^flagBits) << directShift
			var stored uint64
			if raw {
				// A direct page is a whole 4 KiB of image; the file owns only
				// its own bytes.
				stored = logical
			} else {
				if start > limit || limit-start < prefixBytes {
					return nil, corruptf("block %d's length prefix at %d is past byte %d",
						index, start, limit)
				}
				var length [2]byte
				if err := source.ReadExactAt(src, start, length[:]); err != nil {
					return nil, err
				}
				stored = prefixBytes + uint64(binary.LittleEndian.Uint16(length[:]))
			}
			b = block{start: start, stored: stored, raw: raw, prefixed: !raw}
		} else {
			end := uint64(word &^ flagBits)
			if end < nextStart {
				return nil, corruptf("block %d ends at %d, before it starts at %d",
					index, end, nextStart)
			}
			b = block{start: nextStart, stored: end - nextStart, raw: raw}
		}

		if b.stored > maxStored {
			return nil, corruptf("block %d stores %d bytes, more than the %d-byte ceiling",
				index, b.stored, maxStored)
		}
		if b.raw && b.stored > blockSize {
			return nil, corruptf("uncompressed block %d stores %d bytes, more than a page",
				index, b.stored)
		}
		if b.start > limit || b.stored > limit-b.start {
			return nil, corruptf("block %d at %d of %d bytes runs past byte %d",
				index, b.start, b.stored, limit)
		}
		nextStart = b.start + b.stored
		if b.stored == 0 {
			b.start = 0
		}
		f.blocks = append(f.blocks, b)
	}
	return f, nil
}

func (f *fileSource) blockLen(index uint64) uint64 {
	start := index * blockSize
	remaining := f.size - start
	if remaining > blockSize {
		return blockSize
	}
	return remaining
}

// allocatedBytes is the bytes the file actually stores: holes store none and
// a compressed block counts its stored length, not its decoded one.
func (f *fileSource) allocatedBytes() uint64 {
	var total uint64
	for _, b := range f.blocks {
		total += b.stored
	}
	return total
}

// decodedBlock decodes one block, producing zeroes for a hole.
func (f *fileSource) decodedBlock(index uint64) ([]byte, error) {
	f.mu.Lock()
	if f.cached && f.cacheIdx == int(index) {
		buf := f.cacheBuf
		f.mu.Unlock()
		return buf, nil
	}
	f.mu.Unlock()

	if index >= uint64(len(f.blocks)) {
		return nil, corruptf("block %d is past the block list", index)
	}
	b := f.blocks[index]
	logical := f.blockLen(index)
	var out []byte
	if b.isHole() {
		out = make([]byte, logical)
	} else {
		stored := make([]byte, b.stored)
		if err := source.ReadExactAt(f.src, b.start, stored); err != nil {
			return nil, err
		}
		var decoded []byte
		if b.raw {
			decoded = stored
		} else {
			stream := stored
			if b.prefixed && uint64(len(stream)) >= prefixBytes {
				stream = stream[prefixBytes:]
			}
			var err error
			decoded, err = inflate(stream)
			if err != nil {
				return nil, err
			}
		}
		if uint64(len(decoded)) > blockSize {
			return nil, corruptf("block %d decoded to %d bytes, more than a page",
				index, len(decoded))
		}
		out = make([]byte, logical)
		n := uint64(len(decoded))
		if n > logical {
			n = logical
		}
		copy(out[:n], decoded[:n])
	}

	f.mu.Lock()
	f.cached = true
	f.cacheIdx = int(index)
	f.cacheBuf = out
	f.mu.Unlock()
	return out, nil
}

// inflate decodes one zlib-wrapped block, refusing output past a page.
func inflate(payload []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, corruptf("a block does not inflate: %v", err)
	}
	defer reader.Close()
	out, err := io.ReadAll(io.LimitReader(reader, int64(blockSize)+1))
	if err != nil {
		return nil, corruptf("a block does not inflate: %v", err)
	}
	if uint64(len(out)) > blockSize {
		return nil, corruptf("a block inflated to %d bytes, more than a page", len(out))
	}
	return out, nil
}

func (f *fileSource) readAtInternal(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := f.size - offset
	if want > uint64(len(buf)) {
		want = uint64(len(buf))
	}
	out := buf[:want]
	end := offset + want
	first := offset / blockSize
	last := (end - 1) / blockSize
	for index := first; index <= last; index++ {
		start := index * blockSize
		stop := start + f.blockLen(index)
		from := offset
		if start > from {
			from = start
		}
		to := end
		if stop < to {
			to = stop
		}
		if from >= to {
			continue
		}
		decoded, err := f.decodedBlock(index)
		if err != nil {
			return 0, err
		}
		into := from - start
		at := from - offset
		n := to - from
		copy(out[at:at+n], decoded[into:into+n])
	}
	return int(want), nil
}

// extentsInto describes the stored ranges [offset, offset+length) reads from.
func (f *fileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	first := offset / blockSize
	last := (end - 1) / blockSize
	for index := first; index <= last; index++ {
		start := index * blockSize
		stop := start + f.blockLen(index)
		from := offset
		if start > from {
			from = start
		}
		to := end
		if stop < to {
			to = stop
		}
		if from >= to {
			continue
		}
		b := f.blocks[index]
		switch {
		case b.isHole():
			out = append(out, source.ParentRange{
				Parent: parent,
				Len:    to - from,
				Kind:   source.RangeZero,
			})
		case b.raw:
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: b.start + (from - start),
				Len:          to - from,
				Kind:         source.RangeData,
			})
		default:
			// The decoded bytes are not aligned to the stored ones, so the
			// whole stored region is what this range is derived from.
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: b.start,
				Len:          b.stored,
				Kind:         source.RangeData,
			})
		}
	}
	return out, nil
}

// SourceID implements source.ByteSource.
func (f *fileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *fileSource) Len() uint64 { return f.size }

// ImageID implements source.ByteSource.
func (f *fileSource) ImageID() source.ImageID { return f.src.ImageID() }

// SectorSize implements source.ByteSource.
func (f *fileSource) SectorSize() uint32 { return f.src.SectorSize() }

// ReadAt implements source.ByteSource with strict semantics.
func (f *fileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.readAtInternal(offset, buf)
	if err != nil {
		f.counters.AddError()
		return got, err
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy zero-fills unreadable bytes and counts them as corrupt.
func (f *fileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := f.size - offset
	if want > uint64(len(buf)) {
		want = uint64(len(buf))
	}
	if got, err := f.readAtInternal(offset, buf[:want]); err == nil {
		return got, nil
	}
	for i := uint64(0); i < want; i++ {
		buf[i] = 0
	}
	f.counters.AddCorrupt(want)
	return int(want), nil
}

// ExtentsInto translates [offset, offset+length) into the immediate parent.
func (f *fileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.extentsInto(f.src.SourceID(), offset, length, out)
}

// Extents returns the complete translation.
func (f *fileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.extentsInto(f.src.SourceID(), offset, length, nil)
}

// MapToImage walks the parent chain to image offsets.
func (f *fileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.extentsInto(f.src.SourceID(), offset, length, nil)
	if err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, r := range ranges {
		if r.Kind == source.RangeData {
			mapped, err := f.src.MapToImage(r.ParentOffset, r.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
		} else {
			out = append(out, source.ImageRange{
				ImageID: f.src.ImageID(),
				Len:     r.Len,
				Kind:    r.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *fileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *fileSource) IsEmpty() bool { return f.size == 0 }

var _ source.ByteSource = (*fileSource)(nil)
