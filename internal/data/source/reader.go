package source

import (
	"errors"
	"io"
)

// ReaderAt adapts a ByteSource to io.ReaderAt for streaming decoders.
//
// A read starting at or past the source's end returns io.EOF; a short read at
// the end returns the bytes plus io.EOF, matching the io.ReaderAt contract.
func ReaderAt(src ByteSource) io.ReaderAt { return byteSourceReaderAt{src: src} }

type byteSourceReaderAt struct{ src ByteSource }

func (r byteSourceReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("source: negative offset")
	}
	offset := uint64(off)
	if offset >= r.src.Len() {
		return 0, io.EOF
	}
	n, err := r.src.ReadAt(offset, p)
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
