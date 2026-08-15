package nbd

// Exporter adapters over the public ewf surface. The nbd package stays public-
// facing only: it imports github.com/laenix/ewfgo (the exported EWFImage and
// ImageFS), never the internal package. Every sector read goes through the
// exact-decompression path, so a read served over NBD is the exact expected
// data or an explicit error — never raw EWF container bytes and never
// fabricated bytes.

import (
	"errors"
	"fmt"
	"io"

	ewf "github.com/laenix/ewfgo"
)

// imageExporter adapts a whole EWF image to the Exporter interface. ReadAt
// delegates to the public ewf.EWFImage.ReadSectors, which forwards to the
// internal exact-decompression path.
type imageExporter struct {
	img *ewf.EWFImage
}

// NewImageExporter returns an Exporter that serves a whole EWF image.
func NewImageExporter(img *ewf.EWFImage) Exporter {
	return &imageExporter{img: img}
}

// Size returns the image size in bytes.
func (e *imageExporter) Size() uint64 {
	return e.img.TotalSectors() * uint64(e.img.SectorSize())
}

// ReadAt implements io.ReaderAt semantics over the image, clamping the range to
// Size(): bytes past the end of the export are never fabricated, they are
// reported via io.EOF. off need not be sector-aligned; the covering sector
// range is read and sliced.
func (e *imageExporter) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("nbd: negative read offset")
	}
	uoff := uint64(off)
	size := e.Size()
	if uoff >= size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Clamp the requested range to the export size.
	want := uint64(len(p))
	if want > size-uoff {
		want = size - uoff
	}

	ss := uint64(e.img.SectorSize())
	if ss == 0 {
		ss = 512
	}
	startSector := uoff / ss
	intra := uoff % ss

	// Number of sectors needed to cover bytes [uoff, uoff+want). span <= size,
	// so the ceil-division cannot overflow.
	span := intra + want
	count := span / ss
	if span%ss != 0 {
		count++
	}

	raw, err := e.img.ReadSectors(startSector, count)
	if err != nil {
		return 0, fmt.Errorf("nbd: read image sectors %d..%d: %w", startSector, count, err)
	}
	if uint64(len(raw)) < span {
		return 0, fmt.Errorf("nbd: short decompressed read: got %d bytes, need %d", len(raw), span)
	}

	n := int(want)
	copy(p[:n], raw[intra:intra+want])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// partitionExporter adapts a single partition (partition-relative bytes) to the
// Exporter interface. ewf.ImageFS.ReadBlock already implements io.ReaderAt
// semantics — the readable prefix plus io.EOF past the end — so ReadAt is a thin
// delegate.
type partitionExporter struct {
	fs *ewf.ImageFS
}

// NewPartitionExporter returns an Exporter that serves the bytes of one
// partition, partition-relative (offset 0 is the partition start).
func NewPartitionExporter(fs *ewf.ImageFS) Exporter {
	return &partitionExporter{fs: fs}
}

// Size returns the partition size in bytes.
func (e *partitionExporter) Size() uint64 {
	sz := e.fs.Size()
	if sz < 0 {
		return 0
	}
	return uint64(sz)
}

// ReadAt delegates to ImageFS.ReadBlock, which returns the readable prefix
// together with io.EOF when the range extends past the partition end (io.ReaderAt
// semantics).
func (e *partitionExporter) ReadAt(p []byte, off int64) (int, error) {
	n, err := e.fs.ReadBlock(off, p)
	if err == io.EOF {
		// ReadBlock already returned n < len(p); surface the partial read with
		// io.EOF per io.ReaderAt semantics.
		return n, io.EOF
	}
	return n, err
}
