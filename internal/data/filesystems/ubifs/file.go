package ubifs

import (
	"fmt"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

// FileSource is one regular file's bytes, assembled from its data nodes.
type FileSource struct {
	id      source.ID
	source  source.ByteSource
	device  Device
	length  uint64
	blocks  []FileBlock
	holes   []Hole
	counter source.Counters

	cacheMu sync.Mutex
	cache   map[uint64][]byte
}

// OpenFile opens the regular file named by path.
func (v *Volume) OpenFile(pathValue string) (source.ByteSource, error) {
	entry, err := v.Lookup(pathValue)
	if err != nil {
		return nil, err
	}
	return v.openEntry(entry)
}

// OpenFileByInode opens a regular file by inode number.
func (v *Volume) OpenFileByInode(inode uint64) (source.ByteSource, error) {
	entry, found := v.EntryByInode(inode)
	if !found {
		return nil, fmt.Errorf("%w: inode %d", ErrNotFound, inode)
	}
	return v.openEntry(entry)
}

func (v *Volume) openEntry(entry *Entry) (source.ByteSource, error) {
	if entry.IsDir {
		return nil, fmt.Errorf("%w: %s", ErrIsDir, entry.Path)
	}
	if !entry.IsFile {
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotFile, entry.Path, entry.Kind.Label())
	}
	if entry.Inode > uint64(^uint32(0)) {
		return nil, corruptf("inode number %d is outside UBIFS's key range", entry.Inode)
	}
	if entry.Size > MaxFileBytes {
		return nil, unsupportedf("file %s is %d bytes, past the %d-byte materialize cap",
			entry.Path, entry.Size, MaxFileBytes)
	}
	inode, found := v.inodes[uint32(entry.Inode)]
	if !found {
		return nil, corruptf("file %s has no inode node; its data cannot be addressed", entry.Path)
	}
	blocks := v.fileBlocks(uint32(entry.Inode), inode, entry.Size)
	holes := mergeHoles(blocks, entry.Size)
	return &FileSource{
		id:     source.ID(v.fileID.Add(1)),
		source: v.source,
		device: v.device,
		length: entry.Size,
		blocks: blocks,
		holes:  holes,
		cache:  make(map[uint64][]byte),
	}, nil
}

// OpenSymlink opens a symbolic link's target bytes.  The bytes live in the
// inode node and are mapped back to the image like any other inline payload.
func (v *Volume) OpenSymlink(pathValue string) (source.ByteSource, error) {
	entry, err := v.Lookup(pathValue)
	if err != nil {
		return nil, err
	}
	if !entry.IsSymlink {
		return nil, fmt.Errorf("%w: %s", ErrNotSymlink, pathValue)
	}
	inode, found := v.inodes[uint32(entry.Inode)]
	if !found {
		return nil, corruptf("symbolic link %s has no inode node", pathValue)
	}
	length := uint64(len(inode.inline))
	var blocks []FileBlock
	if length > 0 {
		imageOffset, err := v.device.imageOffset(inode.inlineLnum, inode.inlineLEBOffset)
		if err != nil {
			return nil, err
		}
		blocks = []FileBlock{{
			Block: 0, Offset: 0, Len: length, State: BlockInline, ImageOffset: imageOffset,
		}}
	}
	return &FileSource{
		id: source.ID(v.fileID.Add(1)), source: v.source, device: v.device,
		length: length, blocks: blocks, cache: make(map[uint64][]byte),
	}, nil
}

func (v *Volume) fileBlocks(inum uint32, inode inodeRecord, size uint64) []FileBlock {
	count := (size + BlockSize - 1) / BlockSize
	if count > MaxFileBytes/BlockSize {
		count = MaxFileBytes / BlockSize
	}
	blocks := make([]FileBlock, 0, count)
	for block := uint64(0); block < count; block++ {
		offset := block * BlockSize
		length := uint64(BlockSize)
		if remaining := size - offset; length > remaining {
			length = remaining
		}
		value := FileBlock{Block: block, Offset: offset, Len: length, State: BlockHole}
		if v.corruptData[dataKey{inum: inum, block: block}] {
			value.State = BlockCorrupt
		} else if record, found := v.data[dataKey{inum: inum, block: block}]; found {
			if record.size > MaxDecodedBlock || !compressionSupported(record.compression) {
				if record.size > MaxDecodedBlock {
					value.State = BlockCorrupt
				} else {
					value.State = BlockUnsupported
				}
				value.Compression = record.compression
			} else {
				value.State = BlockPresent
				value.ImageOffset = record.imageOffset
				value.StoredLen = record.storedLen
				value.Size = record.size
				value.Compression = record.compression
				value.Lnum = record.lnum
				value.LEBOffset = record.lebOffset
			}
		} else if block == 0 && len(inode.inline) > 0 && inode.isFile() {
			imageOffset, err := v.device.imageOffset(inode.inlineLnum, inode.inlineLEBOffset)
			if err == nil {
				value.State = BlockInline
				value.ImageOffset = imageOffset
			}
		}
		blocks = append(blocks, value)
	}
	return blocks
}

func mergeHoles(blocks []FileBlock, size uint64) []Hole {
	var holes []Hole
	var start uint64
	inHole := false
	for _, block := range blocks {
		if block.State == BlockHole {
			if !inHole {
				start = block.Offset
				inHole = true
			}
			continue
		}
		if inHole {
			holes = append(holes, Hole{Offset: start, Len: block.Offset - start})
			inHole = false
		}
	}
	if inHole {
		holes = append(holes, Hole{Offset: start, Len: size - start})
	}
	return holes
}

// Len returns the file's declared length.
func (f *FileSource) Len() uint64 { return f.length }

// IsEmpty reports whether the file declares no bytes.
func (f *FileSource) IsEmpty() bool { return f.length == 0 }

// Blocks returns the logical block plan.
func (f *FileSource) Blocks() []FileBlock {
	out := make([]FileBlock, len(f.blocks))
	copy(out, f.blocks)
	return out
}

// Holes returns merged sparse runs.
func (f *FileSource) Holes() []Hole {
	out := make([]Hole, len(f.holes))
	copy(out, f.holes)
	return out
}

// SourceID implements source.ByteSource.
func (f *FileSource) SourceID() source.ID { return f.id }

// ImageID implements source.ByteSource.
func (f *FileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *FileSource) SectorSize() uint32 { return f.source.SectorSize() }

// ReadAt implements source.ByteSource.
func (f *FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counter.AddRead(0)
		return 0, nil
	}
	if offset >= f.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.length)
	}
	want := int(minU64(f.length-offset, uint64(len(buf))))
	out := buf[:want]
	clear(out)
	if want == 0 {
		return 0, nil
	}
	end := offset + uint64(want)
	for _, block := range f.blocks {
		stop := block.Offset + block.Len
		if stop <= offset || block.Offset >= end {
			continue
		}
		from := maxU64(offset, block.Offset)
		to := minU64(end, stop)
		at := int(from - offset)
		n := int(to - from)
		within := from - block.Offset
		switch block.State {
		case BlockHole:
			continue
		case BlockCorrupt:
			return 0, corruptf("block %d of this file has a corrupt data node", block.Block)
		case BlockUnsupported:
			return 0, unsupportedf("block %d uses compression type %d (%s), which this reader does not decode",
				block.Block, block.Compression, compressionName(block.Compression))
		case BlockInline:
			bytes, err := f.inlineBlock(block)
			if err != nil {
				return 0, err
			}
			read := copy(out[at:at+n], bytes[minU64(within, uint64(len(bytes))):])
			if read > 0 {
				f.counter.AddRead(read)
			}
		case BlockPresent:
			bytes, err := f.decodeBlock(block)
			if err != nil {
				return 0, err
			}
			fromInline := minU64(within, uint64(len(bytes)))
			read := copy(out[at:at+n], bytes[fromInline:])
			if read > 0 {
				f.counter.AddRead(read)
			}
		}
	}
	return want, nil
}

func (f *FileSource) inlineBlock(block FileBlock) ([]byte, error) {
	if cached, ok := f.cached(block.Block); ok {
		return cached, nil
	}
	if block.Len > uint64(^uint(0)>>1) {
		return nil, limitf("inline block length %d exceeds int", block.Len)
	}
	bytes := make([]byte, int(block.Len))
	if err := source.ReadExactAt(f.source, block.ImageOffset, bytes); err != nil {
		return nil, err
	}
	f.store(block.Block, bytes)
	return bytes, nil
}

func (f *FileSource) decodeBlock(block FileBlock) ([]byte, error) {
	if cached, ok := f.cached(block.Block); ok {
		return cached, nil
	}
	if block.StoredLen > uint64(^uint(0)>>1) {
		return nil, limitf("stored block length %d exceeds int", block.StoredLen)
	}
	stored := make([]byte, int(block.StoredLen))
	if block.StoredLen > 0 {
		runs := f.device.imageRuns(block.Lnum, block.LEBOffset, block.StoredLen)
		if len(runs) == 0 {
			if err := source.ReadExactAt(f.source, block.ImageOffset, stored); err != nil {
				return nil, err
			}
		} else {
			done := 0
			for _, run := range runs {
				take := int(run[1])
				if take < 0 || done+take > len(stored) {
					return nil, corruptf("stored block run passes the block")
				}
				if err := source.ReadExactAt(f.source, run[0], stored[done:done+take]); err != nil {
					return nil, err
				}
				done += take
			}
			if done != len(stored) {
				return nil, corruptf("stored block runs cover %d of %d bytes", done, len(stored))
			}
		}
	}
	bytes, err := decodeUBIFSBlock(block.Compression, stored, int(block.Size))
	if err != nil {
		return nil, err
	}
	f.store(block.Block, bytes)
	return bytes, nil
}

func (f *FileSource) cached(block uint64) ([]byte, bool) {
	f.cacheMu.Lock()
	defer f.cacheMu.Unlock()
	bytes, ok := f.cache[block]
	return bytes, ok
}

func (f *FileSource) store(block uint64, bytes []byte) {
	f.cacheMu.Lock()
	defer f.cacheMu.Unlock()
	if len(f.cache) >= 8 {
		for key := range f.cache {
			delete(f.cache, key)
			break
		}
	}
	f.cache[block] = bytes
}

// ReadAtLossy implements source.ByteSource.
func (f *FileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counter.AddRead(0)
		return 0, nil
	}
	if offset >= f.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.length)
	}
	want := int(minU64(f.length-offset, uint64(len(buf))))
	if _, err := f.ReadAt(offset, buf[:want]); err != nil {
		clear(buf[:want])
		f.counter.AddCorrupt(uint64(want))
		return want, nil
	}
	return want, nil
}

// ExtentsInto implements source.ByteSource.  Holes are RangeHole; a corrupt or
// unsupported block is RangeError; compressed blocks map to their stored run
// because no smaller translation exists.
func (f *FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.length || length > f.length-offset {
		return out, source.NewOutOfRange(offset, length, f.length)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	parent := f.source.SourceID()
	for _, block := range f.blocks {
		blockEnd := block.Offset + block.Len
		if blockEnd <= offset || block.Offset >= end {
			continue
		}
		from := maxU64(offset, block.Offset)
		to := minU64(end, blockEnd)
		n := to - from
		within := from - block.Offset
		switch block.State {
		case BlockHole:
			out = append(out, source.ParentRange{Parent: parent, Len: n, Kind: source.RangeHole})
		case BlockCorrupt, BlockUnsupported:
			out = append(out, source.ParentRange{Parent: parent, Len: n, Kind: source.RangeError})
		case BlockInline:
			out = append(out, source.ParentRange{
				Parent: parent, ParentOffset: block.ImageOffset + within, Len: n, Kind: source.RangeData,
			})
		case BlockPresent:
			if block.Compression == 0 {
				runs := f.device.imageRuns(block.Lnum, block.LEBOffset+within, n)
				if len(runs) == 0 {
					out = append(out, source.ParentRange{
						Parent: parent, ParentOffset: block.ImageOffset + within, Len: n, Kind: source.RangeData,
					})
				} else {
					for _, run := range runs {
						out = append(out, source.ParentRange{
							Parent: parent, ParentOffset: run[0], Len: run[1], Kind: source.RangeData,
						})
					}
				}
			} else {
				out = append(out, source.ParentRange{
					Parent: parent, ParentOffset: block.ImageOffset, Len: block.StoredLen, Kind: source.RangeData,
				})
			}
		}
	}
	return out, nil
}

// Extents returns the complete translation for [offset, offset+length).
func (f *FileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage translates the requested range to image offsets.
func (f *FileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, parent := range ranges {
		if parent.Kind == source.RangeData {
			mapped, err := f.source.MapToImage(parent.ParentOffset, parent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		out = append(out, source.ImageRange{ImageID: f.source.ImageID(), Len: parent.Len, Kind: parent.Kind})
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *FileSource) Stats() source.Stats { return f.counter.Snapshot() }

var _ source.ByteSource = (*FileSource)(nil)

func minU64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

func maxU64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

var _ = sync.Mutex{}
