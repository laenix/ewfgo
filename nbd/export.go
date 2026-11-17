package nbd

// Exporter adapters over the public forensic byte source. The nbd package
// serves any source.ByteSource — a whole image or one partition — and every
// sector read goes through the source's exact decoding path, so a read served
// over NBD is the exact expected data or an explicit error, never raw
// container bytes and never fabricated bytes.

import (
	"errors"
	"io"

	forensic "github.com/laenix/ewfgo"
)

// sourceExporter adapts a ByteSource to the Exporter interface.
type sourceExporter struct {
	src forensic.ByteSource
}

// NewExporter returns an Exporter that serves src. Pass Image.Source() for a
// whole image or Partition.Source() for partition-relative bytes.
func NewExporter(src forensic.ByteSource) Exporter {
	return &sourceExporter{src: src}
}

// Size returns the source length in bytes.
func (e *sourceExporter) Size() uint64 { return e.src.Len() }

// ReadAt implements io.ReaderAt semantics over the source: a read at or past
// the end returns io.EOF, a range extending past the end returns the readable
// prefix with io.EOF, and decoder failures surface as errors.
func (e *sourceExporter) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("nbd: negative read offset")
	}
	size := e.src.Len()
	if uint64(off) >= size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	want := uint64(len(p))
	if want > size-uint64(off) {
		want = size - uint64(off)
	}
	n, err := e.src.ReadAt(uint64(off), p[:want])
	if errors.Is(err, forensic.ErrOutOfRange) {
		err = io.EOF
	}
	if err != nil {
		return n, err
	}
	if uint64(n) < uint64(len(p)) {
		return n, io.EOF
	}
	return n, nil
}
