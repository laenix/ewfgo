package jfs

import (
	"errors"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxFilePages is the largest number of tree pages a file's extent tree may
// use.
const MaxFilePages = 65_536

// Run is one run of file bytes backed by the aggregate, in byte units.
type Run struct {
	Logical  uint64
	Physical uint64
	Len      uint64
}

type fileMap struct {
	length uint64
	runs   []Run
}

func buildFileMap(src source.ByteSource, volumeBlocks uint64, inode *Dinode, inodeOffset uint64, maxPages int) (*fileMap, error) {
	length := inode.Size()
	switch {
	case inode.IsDir():
		return nil, corruptf("inode %d is a directory, not a readable file", inode.Number())
	case !inode.IsRegular() && !inode.IsSymlink():
		return nil, corruptf("inode %d is a %s, not a readable file", inode.Number(), inode.FileTypeName())
	}
	if inode.IsFastSymlink() {
		physical := inodeOffset + InodeInlineOffset
		if physical < inodeOffset {
			return nil, corruptf("a fast symbolic link's inode offset overflows")
		}
		return &fileMap{length: length, runs: []Run{{Logical: 0, Physical: physical, Len: length}}}, nil
	}
	blockSize := uint64(BlockSize)
	extents, err := collectExtents(src, volumeBlocks, inode.ExtentTreeRoot(), maxPages)
	if err != nil {
		return nil, err
	}
	fileBlocks := (length + blockSize - 1) / blockSize
	var runs []Run
	for _, extent := range extents {
		if extent.IsCompressed() {
			return nil, unsupportedf("inode %d has a compressed extent at logical block %d",
				inode.Number(), extent.Logical)
		}
		if extent.Len == 0 {
			continue
		}
		if extent.Logical >= fileBlocks {
			continue
		}
		addressEnd, err := extent.PhysicalEnd()
		if err != nil {
			return nil, err
		}
		if extent.Address == 0 {
			return nil, corruptf("inode %d maps logical block %d to block zero", inode.Number(), extent.Logical)
		}
		if addressEnd > volumeBlocks {
			return nil, corruptf("inode %d maps to blocks %d..%d, past the aggregate's %d",
				inode.Number(), extent.Address, addressEnd, volumeBlocks)
		}
		logical := extent.Logical * blockSize
		if extent.Logical != 0 && logical/extent.Logical != blockSize {
			return nil, corruptf("an extent's logical offset overflows")
		}
		if extent.IsNotRecorded() {
			continue
		}
		if logical >= length {
			continue
		}
		physical := extent.Address * blockSize
		if extent.Address != 0 && physical/extent.Address != blockSize {
			return nil, corruptf("an extent's physical offset overflows")
		}
		runLen := uint64(extent.Len) * blockSize
		if remaining := length - logical; runLen > remaining {
			runLen = remaining
		}
		if runLen == 0 {
			continue
		}
		runs = append(runs, Run{Logical: logical, Physical: physical, Len: runLen})
	}
	sort.Slice(runs, func(left, right int) bool { return runs[left].Logical < runs[right].Logical })
	merged := make([]Run, 0, len(runs))
	for _, run := range runs {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			end := last.Logical + last.Len
			if run.Logical < end {
				return nil, corruptf("inode %d has extents that overlap at logical byte %d",
					inode.Number(), run.Logical)
			}
			if run.Logical == end && last.Physical+last.Len == run.Physical {
				last.Len += run.Len
				continue
			}
		}
		merged = append(merged, run)
	}
	return &fileMap{length: length, runs: merged}, nil
}

func (m *fileMap) len() uint64   { return m.length }
func (m *fileMap) isEmpty() bool { return m.length == 0 }

// allocatedBytes returns the bytes backed by stored blocks or inode-embedded
// bytes.
func (m *fileMap) allocatedBytes() uint64 {
	var total uint64
	for _, run := range m.runs {
		start, end := m.byteRange(run)
		total += end - start
	}
	return total
}

func (m *fileMap) byteRange(run Run) (uint64, uint64) {
	start := run.Logical
	if start > m.length {
		start = m.length
	}
	end := run.Logical + run.Len
	if end < run.Logical || end > m.length {
		end = m.length
	}
	return start, end
}

func (m *fileMap) readAt(src source.ByteSource, offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= m.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), m.length)
	}
	want := len(buf)
	if remaining := m.length - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	out := buf[:want]
	clear(out)
	end := offset + uint64(want)
	for _, run := range m.runs {
		start, stop := m.byteRange(run)
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
		into := from - start
		at := int(from - offset)
		n := int(to - from)
		physical := run.Physical + into
		if physical < run.Physical {
			return at, corruptf("a run's physical offset overflows")
		}
		if err := source.ReadExactAt(src, physical, out[at:at+n]); err != nil {
			return at, err
		}
	}
	return want, nil
}

func (m *fileMap) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > m.length || length > m.length-offset {
		return out, source.NewOutOfRange(offset, length, m.length)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	cursor := offset
	for _, run := range m.runs {
		start, stop := m.byteRange(run)
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
			out = append(out, source.ParentRange{Parent: parent, Len: from - cursor, Kind: source.RangeHole})
		}
		physical := run.Physical + (from - start)
		if physical < run.Physical {
			return out, corruptf("a run's physical offset overflows")
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: physical,
			Len:          to - from,
			Kind:         source.RangeData,
		})
		cursor = to
	}
	if cursor < end {
		out = append(out, source.ParentRange{Parent: parent, Len: end - cursor, Kind: source.RangeHole})
	}
	return out, nil
}

// JfsFileSource is a file inside a JFS aggregate, readable as a byte source.
type JfsFileSource struct {
	id       source.ID
	source   source.ByteSource
	mapData  *fileMap
	inode    uint32
	counters source.Counters
}

func newFileSource(id source.ID, src source.ByteSource, mapData *fileMap, inode uint32) *JfsFileSource {
	return &JfsFileSource{id: id, source: src, mapData: mapData, inode: inode}
}

// SourceID implements source.ByteSource.
func (f *JfsFileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *JfsFileSource) Len() uint64 { return f.mapData.len() }

// ImageID implements source.ByteSource.
func (f *JfsFileSource) ImageID() source.ImageID { return f.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *JfsFileSource) SectorSize() uint32 { return BlockSize }

// Inode returns the file's inode number.
func (f *JfsFileSource) Inode() uint32 { return f.inode }

// ReadAt implements source.ByteSource with strict semantics.
func (f *JfsFileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.mapData.readAt(f.source, offset, buf)
	if err != nil {
		return got, mapSourceError(err)
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *JfsFileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.mapData.len() {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.mapData.len())
	}
	want := len(buf)
	if remaining := f.mapData.len() - offset; uint64(want) > remaining {
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

// ExtentsInto implements source.ByteSource.
func (f *JfsFileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.mapData.extentsInto(f.source.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *JfsFileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *JfsFileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Kind == source.RangeData {
			imageRanges, err := f.source.MapToImage(r.ParentOffset, r.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, imageRanges...)
		} else {
			out = append(out, source.ImageRange{
				ImageID:     f.source.ImageID(),
				ImageOffset: 0,
				Len:         r.Len,
				Kind:        r.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *JfsFileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *JfsFileSource) IsEmpty() bool { return f.mapData.isEmpty() }

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

var _ source.ByteSource = (*JfsFileSource)(nil)
