// Package adapter bridges the byte-oriented data plane to the sector-oriented
// filesystem handlers. It lets every existing handler read through a
// source.ByteSource without rewriting its parser, while keeping the strict
// rule that a sector read returns real data or an explicit error.
package adapter

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Reader adapts a ByteSource to the ReadSectors contract used by the
// filesystem handlers.
type Reader struct {
	Source     source.ByteSource
	SectorSize uint32
}

// New wraps src. A zero sector size falls back to 512.
func New(src source.ByteSource, sectorSize uint32) Reader {
	if sectorSize == 0 {
		sectorSize = 512
	}
	return Reader{Source: src, SectorSize: sectorSize}
}

// ReadSectors returns exactly count sectors starting at lba. A request that
// starts or ends outside the source is OutOfRange; a short backing read is an
// error, never a truncated result.
func (r Reader) ReadSectors(lba, count uint64) ([]byte, error) {
	if count == 0 {
		return []byte{}, nil
	}
	sectorSize := uint64(r.SectorSize)
	if sectorSize < 512 || sectorSize&(sectorSize-1) != 0 {
		return nil, &source.Error{
			Kind:   source.ErrInvalidArgument,
			Reason: fmt.Sprintf("invalid sector size %d", r.SectorSize),
		}
	}

	start, ok := mul(lba, sectorSize)
	if !ok {
		return nil, source.NewOutOfRange(lba, count, r.Source.Len()/sectorSize)
	}
	length, ok := mul(count, sectorSize)
	if !ok {
		return nil, source.NewOutOfRange(lba, count, r.Source.Len()/sectorSize)
	}
	sourceLen := r.Source.Len()
	if start > sourceLen || length > sourceLen-start {
		return nil, source.NewOutOfRange(start, length, sourceLen)
	}
	const maxRead = 1 << 30
	if length > maxRead {
		return nil, &source.Error{
			Kind:   source.ErrInvalidArgument,
			Reason: fmt.Sprintf("read request of %d bytes exceeds the %d-byte cap", length, maxRead),
		}
	}

	buf := make([]byte, int(length))
	if err := source.ReadExactAt(r.Source, start, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func mul(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}
