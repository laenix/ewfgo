package hfs

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// ExtentsPerRecord is the number of runs a catalog record or an overflow leaf
// record carries.
const ExtentsPerRecord = 3

// ExtentBytes is the size of one extent descriptor.
const ExtentBytes = 4

// ExtentRecordBytes is the size of a full extent record.
const ExtentRecordBytes = ExtentsPerRecord * ExtentBytes

// Extent is one run of allocation blocks. A zero Blocks ends the record;
// Blocks is the only terminator, because Start 0 names a real allocation
// block.
type Extent struct {
	Start  uint16
	Blocks uint16
}

// IsEmpty reports whether the extent describes no blocks.
func (e Extent) IsEmpty() bool { return e.Blocks == 0 }

// ExtentRecord is the three extents a catalog record or an overflow leaf
// record holds.
type ExtentRecord [ExtentsPerRecord]Extent

// readExtentRecord reads one extent record from raw at offset.
func readExtentRecord(raw []byte, offset int) (ExtentRecord, error) {
	if offset < 0 || offset+ExtentRecordBytes < offset || offset+ExtentRecordBytes > len(raw) {
		return ExtentRecord{}, corruptf("an extent record at byte %d runs past its %d-byte structure", offset, len(raw))
	}
	var record ExtentRecord
	for index := range record {
		at := offset + index*ExtentBytes
		record[index] = Extent{
			Start:  be16(raw, at),
			Blocks: be16(raw, at+2),
		}
	}
	return record, nil
}

// describedBlocks is the total allocation blocks an extent record names.
func describedBlocks(record ExtentRecord) uint64 {
	var total uint64
	for _, extent := range record {
		total += uint64(extent.Blocks)
	}
	return total
}

// Run is one extent in logical order: an offset inside the fork, the image
// offset it maps to, and its length in bytes.
type Run struct {
	Offset      uint64
	ImageOffset uint64
	Len         uint64
}

// fork is a file fork flattened to image runs.
type fork struct {
	logicalSize      uint64
	runs             []Run
	allocationBlocks uint64
}

// forkFromRecord builds the runs of an extent record.
func forkFromRecord(record ExtentRecord, logicalSize uint64, blockSize uint32, allocationBase uint64) (fork, error) {
	var out fork
	out.logicalSize = logicalSize
	size := uint64(blockSize)
	var offset uint64
	for _, extent := range record {
		if extent.IsEmpty() {
			continue
		}
		start := uint64(extent.Start)
		if size != 0 && start > (^uint64(0))/size {
			return fork{}, corruptf("an extent start overflows the address space")
		}
		imageStart := start * size
		if imageStart > (^uint64(0))-allocationBase {
			return fork{}, corruptf("an extent start overflows the address space")
		}
		length := uint64(extent.Blocks) * size
		if length < uint64(extent.Blocks) {
			return fork{}, corruptf("an extent length overflows the address space")
		}
		if offset > (^uint64(0))-length {
			return fork{}, corruptf("a fork length overflows the address space")
		}
		out.runs = append(out.runs, Run{
			Offset:      offset,
			ImageOffset: allocationBase + imageStart,
			Len:         length,
		})
		offset += length
	}
	out.allocationBlocks = describedBlocks(record)
	return out, nil
}

// append continues a fork with the runs of an overflow extent record. The
// overflow record always continues the fork, so its runs start where the
// previous run ended. Overflowing arithmetic saturates, so a corrupt key
// cannot spin or panic; the reads that follow report the gap.
func (f *fork) append(record ExtentRecord, blockSize uint32, allocationBase uint64) {
	var offset uint64
	if len(f.runs) > 0 {
		last := f.runs[len(f.runs)-1]
		offset = last.Offset + last.Len
	}
	size := uint64(blockSize)
	for _, extent := range record {
		if extent.IsEmpty() {
			continue
		}
		imageStart := saturatingMul(uint64(extent.Start), size)
		imageOffset := allocationBase
		if imageOffset <= (^uint64(0))-imageStart {
			imageOffset += imageStart
		} else {
			imageOffset = ^uint64(0)
		}
		length := saturatingMul(uint64(extent.Blocks), size)
		f.runs = append(f.runs, Run{Offset: offset, ImageOffset: imageOffset, Len: length})
		if offset <= (^uint64(0))-length {
			offset += length
		} else {
			offset = ^uint64(0)
		}
		f.allocationBlocks = saturatingAdd(f.allocationBlocks, uint64(extent.Blocks))
	}
}

func saturatingMul(a, b uint64) uint64 {
	if a != 0 && b > (^uint64(0))/a {
		return ^uint64(0)
	}
	return a * b
}

func saturatingAdd(a, b uint64) uint64 {
	if a > (^uint64(0))-b {
		return ^uint64(0)
	}
	return a + b
}

// runAt returns the run covering a fork offset, or nil when none does.
func (f *fork) runAt(offset uint64) *Run {
	for index := range f.runs {
		run := &f.runs[index]
		if offset >= run.Offset && offset-run.Offset < run.Len {
			return run
		}
	}
	return nil
}

// readAt reads up to len(buf) bytes from the fork. Classic HFS defines no
// holes, so a logical byte no extent covers is corrupt rather than zero.
func (f *fork) readAt(src source.ByteSource, offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.logicalSize {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.logicalSize)
	}
	want := len(buf)
	if remaining := f.logicalSize - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	done := 0
	at := offset
	for done < want {
		run := f.runAt(at)
		if run == nil {
			return done, corruptf("a fork has no extent at logical byte %d of %d", at, f.logicalSize)
		}
		within := at - run.Offset
		available := run.Len - within
		take := uint64(want - done)
		if take > available {
			take = available
		}
		if take == 0 {
			return done, corruptf("a fork extent at logical byte %d has no bytes left", at)
		}
		image := run.ImageOffset + within
		if image < run.ImageOffset {
			return done, corruptf("a fork image offset overflows")
		}
		if err := source.ReadExactAt(src, image, buf[done:done+int(take)]); err != nil {
			return done, err
		}
		done += int(take)
		at += take
	}
	return done, nil
}

// extentsInto translates a fork range into ranges of the parent source.
func (f *fork) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.logicalSize || length > f.logicalSize-offset {
		return out, source.NewOutOfRange(offset, length, f.logicalSize)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	at := offset
	for at < end {
		run := f.runAt(at)
		if run == nil {
			return out, corruptf("a fork range has no extent at logical byte %d of %d", at, f.logicalSize)
		}
		within := at - run.Offset
		available := run.Len - within
		take := end - at
		if take > available {
			take = available
		}
		if take == 0 {
			return out, corruptf("a fork extent at logical byte %d has no bytes left", at)
		}
		image := run.ImageOffset + within
		if image < run.ImageOffset {
			return out, corruptf("a fork image offset overflows")
		}
		out = append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: image,
			Len:          take,
			Kind:         source.RangeData,
		})
		at += take
	}
	return out, nil
}

// forkSource exposes one fork as a source.ByteSource.
type forkSource struct {
	id       source.ID
	parent   source.ByteSource
	fork     fork
	counters source.Counters
}

func newForkSource(id source.ID, parent source.ByteSource, value fork) *forkSource {
	return &forkSource{id: id, parent: parent, fork: value}
}

// SourceID implements source.ByteSource.
func (f *forkSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *forkSource) Len() uint64 { return f.fork.logicalSize }

// ImageID implements source.ByteSource.
func (f *forkSource) ImageID() source.ImageID { return f.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (f *forkSource) SectorSize() uint32 { return f.parent.SectorSize() }

// ReadAt implements source.ByteSource with strict semantics.
func (f *forkSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.fork.readAt(f.parent, offset, buf)
	if err != nil {
		return got, err
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *forkSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.fork.logicalSize {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.fork.logicalSize)
	}
	want := len(buf)
	if remaining := f.fork.logicalSize - offset; uint64(want) > remaining {
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
func (f *forkSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.fork.extentsInto(f.parent.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *forkSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *forkSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, parentRange := range ranges {
		if parentRange.Kind == source.RangeData {
			images, err := f.parent.MapToImage(parentRange.ParentOffset, parentRange.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, images...)
		} else {
			out = append(out, source.ImageRange{
				ImageID:     f.parent.ImageID(),
				ImageOffset: 0,
				Len:         parentRange.Len,
				Kind:        parentRange.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *forkSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *forkSource) IsEmpty() bool { return f.fork.logicalSize == 0 }

var _ source.ByteSource = (*forkSource)(nil)
