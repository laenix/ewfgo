package hfsplus

// HFS+ forks and extents.
//
// An HFS+ file is a set of forks: the data fork holds the contents and the
// resource fork holds classic Mac OS resources.  A fork's first eight extent
// descriptors live inside the fork structure; any more are records in the
// extents-overflow B-tree, keyed by (fork type, file id, first block).
//
// ForkExtents is the flattened list for one fork and is the only place that
// understands the block-size arithmetic.

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// ForkKind selects one of a file's forks.
type ForkKind uint8

const (
	// ForkData is the normal file content.
	ForkData ForkKind = iota
	// ForkResource is the classic Mac OS resource fork.
	ForkResource
)

// Code is the byte the extents-overflow key uses for the fork type.
func (k ForkKind) Code() uint8 {
	if k == ForkResource {
		return 0xFF
	}
	return 0x00
}

func (k ForkKind) String() string {
	if k == ForkResource {
		return "resource"
	}
	return "data"
}

// ForkExtents is a fork's extents in logical order.
type ForkExtents struct {
	extents []Extent
	blocks  uint32
}

// NewForkExtents flattens an extent list.
func NewForkExtents(extents []Extent) ForkExtents {
	out := ForkExtents{extents: append([]Extent(nil), extents...)}
	for _, extent := range out.extents {
		out.blocks += extent.BlockCount
	}
	return out
}

// FromInline uses only a fork's eight inline descriptors.
func FromInline(fork Fork) ForkExtents { return NewForkExtents(fork.InlineExtents()) }

// Extents returns the flattened list.
func (f ForkExtents) Extents() []Extent { return f.extents }

// Blocks returns the allocation blocks the list covers.
func (f ForkExtents) Blocks() uint32 { return f.blocks }

// IsEmpty reports whether the list names no extent.
func (f ForkExtents) IsEmpty() bool { return len(f.extents) == 0 }

// CoveredBytes returns the bytes the extents cover at the given block size.
func (f ForkExtents) CoveredBytes(blockSize uint32) uint64 {
	return uint64(f.blocks) * uint64(blockSize)
}

// ReadAt reads up to len(buf) bytes of the fork starting at offset.
//
// A short read is returned only at the end of the extent coverage.  A zero
// start block is refused: HFS+ has no sparse files, so zero-filling it would
// invent bytes the fork never named.
func (f ForkExtents) ReadAt(src source.ByteSource, blockSize uint32, offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	covered := f.CoveredBytes(blockSize)
	if offset >= covered {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), covered)
	}
	want := int(minU64(covered-offset, uint64(len(buf))))
	done := 0
	var logical uint64
	for _, extent := range f.extents {
		extentLen := uint64(extent.BlockCount) * uint64(blockSize)
		extentEnd := logical + extentLen
		start := offset
		if start < logical {
			start = logical
		}
		stop := offset + uint64(want)
		if stop > extentEnd {
			stop = extentEnd
		}
		if start >= stop {
			logical = extentEnd
			if logical >= offset+uint64(want) {
				break
			}
			continue
		}
		into := start - logical
		n := int(stop - start)
		out := buf[done : done+n]
		if extent.StartBlock == 0 {
			return done, source.NewCorrupt(offset, "extent has a zero start block; HFS+ has no sparse files")
		}
		physical := uint64(extent.StartBlock)*uint64(blockSize) + into
		if err := source.ReadExactAt(src, physical, out); err != nil {
			return done, err
		}
		done += n
		logical = extentEnd
		if done >= want {
			break
		}
	}
	return done, nil
}

// ReadExact reads exactly len(buf) bytes, failing when the fork is shorter.
func (f ForkExtents) ReadExact(src source.ByteSource, blockSize uint32, offset uint64, buf []byte) error {
	got, err := f.ReadAt(src, blockSize, offset, buf)
	if err != nil {
		return err
	}
	if got != len(buf) {
		return source.NewUnexpectedEOF(offset + uint64(got))
	}
	return nil
}

// ExtentsInto translates a fork range into ranges of the volume that holds it.
func (f ForkExtents) ExtentsInto(parent source.ID, blockSize uint32, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	covered := f.CoveredBytes(blockSize)
	if offset > covered || length > covered-offset {
		return out, source.NewOutOfRange(offset, length, covered)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	var logical uint64
	for _, extent := range f.extents {
		extentLen := uint64(extent.BlockCount) * uint64(blockSize)
		extentEnd := logical + extentLen
		start := offset
		if start < logical {
			start = logical
		}
		stop := end
		if stop > extentEnd {
			stop = extentEnd
		}
		if start >= stop {
			logical = extentEnd
			if logical >= end {
				break
			}
			continue
		}
		into := start - logical
		if extent.StartBlock == 0 {
			out = append(out, source.ParentRange{
				Parent: parent, ParentOffset: 0, Len: stop - start, Kind: source.RangeHole,
			})
		} else {
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: uint64(extent.StartBlock)*uint64(blockSize) + into,
				Len:          stop - start,
				Kind:         source.RangeData,
			})
		}
		logical = extentEnd
		if logical >= end {
			break
		}
	}
	return out, nil
}

// ParseExtentsRecord parses the eight descriptors of an extents-overflow
// record, skipping empty descriptors.
func ParseExtentsRecord(bytes []byte) ([]Extent, error) {
	if len(bytes) < InlineExtents*8 {
		return nil, invalidf("extents overflow record is %d bytes, expected %d", len(bytes), InlineExtents*8)
	}
	extents := make([]Extent, 0, InlineExtents)
	for i := 0; i < InlineExtents; i++ {
		at := i * 8
		extent := Extent{StartBlock: be32(bytes, at), BlockCount: be32(bytes, at+4)}
		if !extent.IsEmpty() {
			extents = append(extents, extent)
		}
	}
	return extents, nil
}
