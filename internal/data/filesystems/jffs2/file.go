package jffs2

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"sort"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxDecodedNodeBytes bounds the logical range one inode node may supply.
const MaxDecodedNodeBytes uint64 = 64 * 1024 * 1024

// FragmentKind is the nature of one logical fragment of a file.
type FragmentKind uint8

const (
	// FragmentZero is a range the zero compressor stores nowhere.
	FragmentZero FragmentKind = iota
	// FragmentStored is a range whose logical bytes are the stored bytes.
	FragmentStored
	// FragmentCompressed is a range whose stored bytes decode to DSize bytes.
	FragmentCompressed
)

// Fragment is one logical range of a file and where its bytes live.
type Fragment struct {
	Offset uint64
	Len    uint64
	Kind   FragmentKind

	// ImageOffset is the storage location for Stored and Compressed
	// fragments.
	ImageOffset uint64
	CSize       uint32
	DSize       uint32
	Compression Compression
	// Skip is how many logical bytes of the source node are skipped before
	// this fragment starts.
	Skip uint64
	// Source identifies the inode node's stored data. It is zero for a Zero
	// fragment.
	Source uint64
}

func (f *Fragment) sourceOffset() (uint64, bool) {
	if f.Kind == FragmentZero {
		return 0, false
	}
	return f.Source, true
}

// Jffs2FileSource is a regular file or symbolic-link target inside a JFFS2
// image, assembled from its inode nodes.
type Jffs2FileSource struct {
	id        source.ID
	source    source.ByteSource
	fragments []Fragment
	len       uint64
	allocated uint64
	inode     uint32
	counters  source.Counters

	mu    sync.Mutex
	cache *decodedNode
}

type decodedNode struct {
	offset uint64
	data   []byte
}

func buildJffs2FileSource(id source.ID, src source.ByteSource, ino uint32, nodes []InodeNode, length, limit uint64) (*Jffs2FileSource, error) {
	if len(nodes) == 0 {
		return nil, corruptf("inode %d has no nodes to assemble", ino)
	}
	order := append([]InodeNode(nil), nodes...)
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].Version != order[j].Version {
			return order[i].Version < order[j].Version
		}
		return order[i].DataOffset < order[j].DataOffset
	})

	var fragments []Fragment
	sizes := make(map[uint64]uint32)
	for index := range order {
		node := &order[index]
		if !node.Compression.IsSupported() {
			return nil, unsupportedf("inode %d uses the %s compressor, which this reader does not decode",
				ino, node.Compression.Label())
		}
		dsize := uint64(node.DSize)
		if dsize > MaxDecodedNodeBytes {
			return nil, corruptf("inode %d has a node supplying %d bytes, more than the %d-byte bound a node may cover",
				ino, dsize, MaxDecodedNodeBytes)
		}
		offset := uint64(node.Offset)
		if offset >= length || dsize == 0 {
			continue
		}
		take := dsize
		if remaining := length - offset; take > remaining {
			take = remaining
		}
		stored := !node.Compression.IsZero()
		if stored {
			csize := uint64(node.CSize)
			if node.DataOffset > limit || csize > limit-node.DataOffset {
				return nil, corruptf("inode %d's %d-byte node at %d runs past byte %d",
					ino, csize, node.DataOffset, limit)
			}
			if !node.Compression.IsCompressed() && node.CSize != node.DSize {
				return nil, corruptf("inode %d stores %d bytes of uncompressed data for %d logical bytes",
					ino, node.CSize, node.DSize)
			}
			if node.Compression.IsCompressed() && node.CSize == 0 {
				return nil, corruptf("inode %d claims %d compressed bytes for %d logical bytes",
					ino, node.CSize, node.DSize)
			}
		}
		fragment := Fragment{Offset: offset, Len: take}
		switch {
		case node.Compression.IsZero():
			fragment.Kind = FragmentZero
		case node.Compression.IsCompressed():
			fragment.Kind = FragmentCompressed
			fragment.ImageOffset = node.DataOffset
			fragment.CSize = node.CSize
			fragment.DSize = node.DSize
			fragment.Compression = node.Compression
			fragment.Source = node.DataOffset
		default:
			fragment.Kind = FragmentStored
			fragment.ImageOffset = node.DataOffset
			fragment.Source = node.DataOffset
		}
		if fragment.Source != 0 {
			sizes[fragment.Source] = node.CSize
		}
		applyFragment(&fragments, fragment)
	}

	seen := make(map[uint64]bool)
	var allocated uint64
	for index := range fragments {
		if sourceOffset, ok := fragments[index].sourceOffset(); ok {
			if !seen[sourceOffset] {
				seen[sourceOffset] = true
				allocated += uint64(sizes[sourceOffset])
			}
		}
	}
	return &Jffs2FileSource{
		id:        id,
		source:    src,
		fragments: fragments,
		len:       length,
		allocated: allocated,
		inode:     ino,
	}, nil
}

// applyFragment trims or removes whatever existing fragments the new fragment
// covers, then inserts it. A newer inode node wins over the ranges it covers.
func applyFragment(fragments *[]Fragment, newFragment Fragment) {
	start := newFragment.Offset
	end := start + newFragment.Len
	next := make([]Fragment, 0, len(*fragments)+1)
	for _, fragment := range *fragments {
		fragmentStart := fragment.Offset
		fragmentEnd := fragmentStart + fragment.Len
		if fragmentEnd <= start || fragmentStart >= end {
			next = append(next, fragment)
			continue
		}
		if fragmentStart < start {
			left := fragment
			left.Len = start - fragmentStart
			next = append(next, left)
		}
		if fragmentEnd > end {
			cut := end - fragmentStart
			fragment.Offset = end
			fragment.Len = fragmentEnd - end
			if fragment.Kind != FragmentZero {
				fragment.Skip += cut
			}
			next = append(next, fragment)
		}
	}
	next = append(next, newFragment)
	sort.SliceStable(next, func(i, j int) bool { return next[i].Offset < next[j].Offset })
	*fragments = next
}

// Fragments returns the live logical fragments, sorted by offset.
func (f *Jffs2FileSource) Fragments() []Fragment {
	return append([]Fragment(nil), f.fragments...)
}

// Len implements source.ByteSource.
func (f *Jffs2FileSource) Len() uint64 { return f.len }

// SourceID implements source.ByteSource.
func (f *Jffs2FileSource) SourceID() source.ID { return f.id }

// ImageID implements source.ByteSource.
func (f *Jffs2FileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *Jffs2FileSource) SectorSize() uint32 { return f.source.SectorSize() }

// Inode returns the inode number behind the file.
func (f *Jffs2FileSource) Inode() uint32 { return f.inode }

// IsEmpty implements source.ByteSource.
func (f *Jffs2FileSource) IsEmpty() bool { return f.len == 0 }

// IsHole reports that the file is non-empty and every contained byte is a
// zero range supplied by the zero compressor or by an uncovered gap.
func (f *Jffs2FileSource) IsHole() bool {
	if f.len == 0 {
		return false
	}
	for _, fragment := range f.fragments {
		if fragment.Kind != FragmentZero {
			return false
		}
	}
	return true
}

// AllocatedBytes counts the stored bytes behind the live fragments, counting a
// compressed node by its stored size and each node once.
func (f *Jffs2FileSource) AllocatedBytes() uint64 { return f.allocated }

func (f *Jffs2FileSource) readAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.len {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.len)
	}
	want := len(buf)
	if remaining := f.len - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	out := buf[:want]
	clear(out)
	end := offset + uint64(want)
	for index := range f.fragments {
		fragment := &f.fragments[index]
		start := fragment.Offset
		stop := start + fragment.Len
		if stop <= offset {
			continue
		}
		if start >= end {
			break
		}
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
		at := int(from - offset)
		count := int(to - from)
		if err := f.copyFragment(fragment, from, out[at:at+count]); err != nil {
			return at, err
		}
	}
	return want, nil
}

func (f *Jffs2FileSource) copyFragment(fragment *Fragment, from uint64, out []byte) error {
	switch fragment.Kind {
	case FragmentZero:
		return nil
	case FragmentStored:
		physical := fragment.ImageOffset + fragment.Skip + (from - fragment.Offset)
		if physical < fragment.ImageOffset {
			return corruptf("a stored fragment's physical offset overflows")
		}
		return source.ReadExactAt(f.source, physical, out)
	case FragmentCompressed:
		decoded, err := f.decode(fragment.ImageOffset, fragment.CSize, fragment.DSize, fragment.Compression)
		if err != nil {
			return err
		}
		start := fragment.Skip + (from - fragment.Offset)
		stop := start + uint64(len(out))
		if stop > uint64(fragment.DSize) || stop > uint64(len(decoded)) {
			return corruptf("a compressed node at %d decoded to %d bytes, short of the %d a read needs",
				fragment.ImageOffset, len(decoded), stop)
		}
		copy(out, decoded[start:stop])
		return nil
	default:
		return corruptf("unknown fragment kind %d", fragment.Kind)
	}
}

func (f *Jffs2FileSource) decode(imageOffset uint64, csize, dsize uint32, compression Compression) ([]byte, error) {
	f.mu.Lock()
	if f.cache != nil && f.cache.offset == imageOffset {
		cached := f.cache.data
		f.mu.Unlock()
		return cached, nil
	}
	f.mu.Unlock()

	stored, err := source.ReadVecAt(f.source, imageOffset, uint64(csize))
	if err != nil {
		return nil, err
	}
	want := int(dsize)
	var decoded []byte
	switch compression {
	case CompressionZlib:
		decoded, err = decodeZlibNode(stored, want)
	case CompressionLzo:
		output := make([]byte, want)
		count, lzoErr := lzo1xDecompress(stored, output)
		if lzoErr != nil {
			err = corruptf("the lzo node at %d does not decode: %v", imageOffset, lzoErr)
		} else if count != want {
			err = corruptf("the lzo node at %d decodes to %d bytes, not its declared %d",
				imageOffset, count, dsize)
		} else {
			decoded = output
		}
	default:
		return nil, unsupportedf("the %s compressor has no decoder in this reader", compression.Label())
	}
	if err != nil {
		return nil, err
	}
	if len(decoded) != want {
		return nil, corruptf("the %s node at %d decodes to %d bytes, not its declared %d",
			compression.Label(), imageOffset, len(decoded), dsize)
	}
	f.mu.Lock()
	f.cache = &decodedNode{offset: imageOffset, data: decoded}
	f.mu.Unlock()
	return decoded, nil
}

func decodeZlibNode(stored []byte, want int) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(stored))
	if err != nil {
		return nil, corruptf("a zlib node does not open: %v", err)
	}
	defer reader.Close()
	limited := io.LimitReader(reader, int64(want)+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, corruptf("a zlib node does not decode: %v", err)
	}
	if len(out) > want {
		return nil, corruptf("a zlib node decodes to more than its declared %d bytes", want)
	}
	return out, nil
}

// ReadAt implements source.ByteSource with strict semantics.
func (f *Jffs2FileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.readAt(offset, buf)
	if err != nil {
		return got, mapSourceError(err)
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *Jffs2FileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.len {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.len)
	}
	want := len(buf)
	if remaining := f.len - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	got, err := f.ReadAt(offset, buf[:want])
	if err != nil {
		clear(buf[:want])
		f.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return got, nil
}

func (f *Jffs2FileSource) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.len || length > f.len-offset {
		return out, source.NewOutOfRange(offset, length, f.len)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	cursor := offset
	for index := range f.fragments {
		fragment := &f.fragments[index]
		start := fragment.Offset
		stop := start + fragment.Len
		if stop <= offset {
			continue
		}
		if start >= end {
			break
		}
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
		if from > cursor {
			out = append(out, source.ParentRange{Parent: parent, Len: from - cursor, Kind: source.RangeZero})
		}
		switch fragment.Kind {
		case FragmentZero:
			out = append(out, source.ParentRange{Parent: parent, Len: to - from, Kind: source.RangeZero})
		case FragmentStored:
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: fragment.ImageOffset + fragment.Skip + (from - start),
				Len:          to - from,
				Kind:         source.RangeData,
			})
		case FragmentCompressed:
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: fragment.ImageOffset,
				Len:          uint64(fragment.CSize),
				Kind:         source.RangeData,
			})
		}
		cursor = to
	}
	if end > cursor {
		out = append(out, source.ParentRange{Parent: parent, Len: end - cursor, Kind: source.RangeZero})
	}
	return out, nil
}

// ExtentsInto implements source.ByteSource.
func (f *Jffs2FileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.extentsInto(f.source.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *Jffs2FileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *Jffs2FileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, item := range ranges {
		if item.Kind == source.RangeData {
			mapped, err := f.source.MapToImage(item.ParentOffset, item.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
		} else {
			out = append(out, source.ImageRange{ImageID: f.source.ImageID(), Len: item.Len, Kind: item.Kind})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *Jffs2FileSource) Stats() source.Stats { return f.counters.Snapshot() }

func mapSourceError(err error) error {
	if err == nil {
		return nil
	}
	var sourceErr *source.Error
	if errors.As(err, &sourceErr) {
		return err
	}
	if errors.Is(err, ErrUnsupported) {
		return &source.Error{Kind: source.ErrUnsupported, Reason: err.Error(), Err: err}
	}
	if errors.Is(err, ErrCorrupt) {
		return &source.Error{Kind: source.ErrCorrupt, Reason: err.Error(), Err: err}
	}
	return err
}

var _ source.ByteSource = (*Jffs2FileSource)(nil)
