package squashfs

import (
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

// fragmentTail is the slice of a shared fragment block a file owns.
type fragmentTail struct {
	storedStart uint64
	storedSize  uint32
	offset      uint32
	length      uint64
}

type decodedCache struct {
	mu    sync.Mutex
	valid bool
	index int
	bytes []byte
}

// fileSource serves one regular file's logical bytes.
type fileSource struct {
	id            source.ID
	src           source.ByteSource
	compression   uint16
	blockSize     uint32
	size          uint64
	fragment      *fragmentTail
	fragmentIndex uint32
	offsets       []uint64
	blocks        []uint32
	blockCache    decodedCache
	fragCache     decodedCache
	counters      source.Counters
}

func newFileSource(
	id source.ID,
	src source.ByteSource,
	compression uint16,
	blockSize uint32,
	in *inode,
	tables *tables,
	cache *metadataCache,
) (*fileSource, error) {
	if in.kind != kindFile {
		return nil, corruptf("only a regular file has a data stream")
	}
	offsets := make([]uint64, 1, len(in.blocks)+1)
	at := in.startBlock
	offsets[0] = at
	for _, entry := range in.blocks {
		stored := uint64(entry & blockSizeMask)
		if entry != 0 && stored == 0 {
			return nil, corruptf("a block entry %#x stores no bytes but is not a hole", entry)
		}
		if stored > uint64(blockSize) {
			return nil, corruptf("a data block stores %d bytes, more than the %d-byte block", stored, blockSize)
		}
		next := at + stored
		if next < at {
			return nil, corruptf("a data block address overflows")
		}
		at = next
		offsets = append(offsets, at)
	}

	var tail *fragmentTail
	if in.fragment != invalidFragment {
		tailLen := in.size % uint64(blockSize)
		if tailLen == 0 {
			return nil, corruptf("a file with a fragment tail is a whole number of blocks")
		}
		entry, err := tables.fragment(cache, src, in.fragment)
		if err != nil {
			return nil, err
		}
		if entry.bytes() > blockSize {
			return nil, corruptf("fragment %d stores %d bytes, more than the %d-byte block",
				in.fragment, entry.bytes(), blockSize)
		}
		if uint64(in.fragmentOffset)+tailLen > uint64(blockSize) {
			return nil, corruptf("a fragment tail at offset %d of %d bytes runs past the block",
				in.fragmentOffset, tailLen)
		}
		tail = &fragmentTail{
			storedStart: entry.startBlock,
			storedSize:  entry.storedSize,
			offset:      in.fragmentOffset,
			length:      tailLen,
		}
	}

	return &fileSource{
		id:            id,
		src:           src,
		compression:   compression,
		blockSize:     blockSize,
		size:          in.size,
		fragment:      tail,
		fragmentIndex: in.fragment,
		offsets:       offsets,
		blocks:        in.blocks,
	}, nil
}

func (f *fileSource) blockLenAt(index int) uint64 {
	return blockLen(f.size, f.fragmentIndex, f.blockSize, index)
}

func (f *fileSource) decodedBlock(index int) ([]byte, error) {
	f.blockCache.mu.Lock()
	if f.blockCache.valid && f.blockCache.index == index {
		cached := f.blockCache.bytes
		f.blockCache.mu.Unlock()
		return cached, nil
	}
	f.blockCache.mu.Unlock()

	length := f.blockLenAt(index)
	if index >= len(f.blocks) {
		return nil, corruptf("block %d is past the block list", index)
	}
	entry := f.blocks[index]
	var bytes []byte
	if entry == 0 {
		bytes = make([]byte, length)
	} else {
		stored := int(entry & blockSizeMask)
		raw := make([]byte, stored)
		if err := source.ReadExactAt(f.src, f.offsets[index], raw); err != nil {
			return nil, err
		}
		if entry&uncompressedBlockBit != 0 {
			if uint64(stored) != length {
				return nil, corruptf("uncompressed block %d stores %d bytes but covers %d", index, stored, length)
			}
			bytes = raw
		} else {
			decoded, err := decompressBlock(f.compression, raw, int(f.blockSize))
			if err != nil {
				return nil, err
			}
			if uint64(len(decoded)) != length {
				return nil, corruptf("block %d decoded to %d bytes but covers %d", index, len(decoded), length)
			}
			bytes = decoded
		}
	}

	f.blockCache.mu.Lock()
	f.blockCache.valid = true
	f.blockCache.index = index
	f.blockCache.bytes = bytes
	f.blockCache.mu.Unlock()
	return bytes, nil
}

func (f *fileSource) decodedFragment() ([]byte, error) {
	f.fragCache.mu.Lock()
	if f.fragCache.valid {
		cached := f.fragCache.bytes
		f.fragCache.mu.Unlock()
		return cached, nil
	}
	f.fragCache.mu.Unlock()

	if f.fragment == nil {
		return nil, corruptf("this file has no fragment tail")
	}
	stored := int(f.fragment.storedSize & blockSizeMask)
	raw := make([]byte, stored)
	if err := source.ReadExactAt(f.src, f.fragment.storedStart, raw); err != nil {
		return nil, err
	}
	var bytes []byte
	if f.fragment.storedSize&uncompressedBlockBit != 0 {
		bytes = raw
	} else {
		decoded, err := decompressBlock(f.compression, raw, int(f.blockSize))
		if err != nil {
			return nil, err
		}
		bytes = decoded
	}

	f.fragCache.mu.Lock()
	f.fragCache.valid = true
	f.fragCache.bytes = bytes
	f.fragCache.mu.Unlock()
	return bytes, nil
}

func (f *fileSource) tailBytes(from uint64, length int) ([]byte, error) {
	if f.fragment == nil {
		return nil, corruptf("this file has no fragment tail")
	}
	fragment, err := f.decodedFragment()
	if err != nil {
		return nil, err
	}
	start := uint64(f.fragment.offset) + from
	end := start + uint64(length)
	if end < start || end > uint64(len(fragment)) {
		return nil, corruptf("a fragment tail ending at %d runs past the %d decoded bytes", end, len(fragment))
	}
	out := make([]byte, length)
	copy(out, fragment[start:end])
	return out, nil
}

func (f *fileSource) readAtInternal(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.size)
	}
	want := int(minU64(f.size-offset, uint64(len(buf))))
	out := buf[:want]
	end := offset + uint64(want)
	blockSize := uint64(f.blockSize)
	storedBlocks := uint64(len(f.blocks))
	first := offset / blockSize
	last := (end - 1) / blockSize
	for index := first; index <= last; index++ {
		start := index * blockSize
		var length uint64
		if index < storedBlocks {
			length = f.blockLenAt(int(index))
		} else {
			if f.fragment == nil {
				return 0, corruptf("block %d is past the block list", index)
			}
			length = f.fragment.length
		}
		stop := start + length
		from := maxU64(offset, start)
		to := minU64(end, stop)
		if from >= to {
			continue
		}
		at := int(from - offset)
		n := int(to - from)
		if index < storedBlocks {
			bytes, err := f.decodedBlock(int(index))
			if err != nil {
				return 0, err
			}
			into := int(from - start)
			copy(out[at:at+n], bytes[into:into+n])
		} else {
			tail, err := f.tailBytes(from-start, n)
			if err != nil {
				return 0, err
			}
			copy(out[at:at+n], tail)
		}
	}
	return want, nil
}

// extentsInto describes the stored ranges [offset, offset+len) reads from.
func (f *fileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.size || length > f.size-offset {
		return out, source.NewOutOfRange(offset, length, f.size)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	blockSize := uint64(f.blockSize)
	storedBlocks := uint64(len(f.blocks))
	first := offset / blockSize
	if first > storedBlocks {
		first = storedBlocks
	}
	last := (end - 1) / blockSize
	if last > storedBlocks {
		last = storedBlocks
	}
	for index := first; index <= last; index++ {
		start := index * blockSize
		if index >= storedBlocks {
			if f.fragment == nil {
				continue
			}
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: f.fragment.storedStart,
				Len:          uint64(f.fragment.storedSize & blockSizeMask),
				Kind:         source.RangeData,
			})
			continue
		}
		stop := start + f.blockLenAt(int(index))
		from := maxU64(offset, start)
		to := minU64(end, stop)
		if from >= to {
			continue
		}
		entry := f.blocks[index]
		switch {
		case entry == 0:
			out = append(out, source.ParentRange{Parent: parent, Len: to - from, Kind: source.RangeZero})
		case entry&uncompressedBlockBit != 0:
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: f.offsets[index] + (from - start),
				Len:          to - from,
				Kind:         source.RangeData,
			})
		default:
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: f.offsets[index],
				Len:          uint64(entry & blockSizeMask),
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
	want := int(minU64(f.size-offset, uint64(len(buf))))
	if got, err := f.readAtInternal(offset, buf[:want]); err == nil {
		return got, nil
	}
	for i := 0; i < want; i++ {
		buf[i] = 0
	}
	f.counters.AddCorrupt(uint64(want))
	return want, nil
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

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

var _ source.ByteSource = (*fileSource)(nil)
