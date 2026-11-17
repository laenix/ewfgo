// Package squashfs reads SquashFS 4.0 images through the data layer's
// ByteSource contract. It is a Go port of forensic-core's squashfs reader:
// the superblock and its tables, metadata-block decompression, every inode
// form, directory listings, file data with fragments and holes, the export
// table and extended attributes.
//
// Compression is limited to the codecs a pure-Go build can decode without new
// dependencies: zlib (bare DEFLATE streams, as SquashFS stores them), LZMA
// (LZMA-alone), LZO1X, XZ containers and raw LZ4 blocks. Zstandard blocks are
// recognised by name and refused with ErrUnsupported; strict reads never
// fabricate output for any codec.
package squashfs

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is.
var (
	// ErrCorrupt means the bytes exist but do not form the claimed structure.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a feature this reader does not
	// decode, such as a compressor with no pure-Go decoder here.
	ErrUnsupported = source.ErrUnsupported
	// ErrPathNotFound means no node has the requested path.
	ErrPathNotFound = errors.New("squashfs: path not found")
	// ErrNotAFile means the node has no data stream: a directory, symlink,
	// device, fifo or socket.
	ErrNotAFile = errors.New("squashfs: node has no data stream")
	// ErrInodeNotFound means an inode number lies outside the export table.
	ErrInodeNotFound = errors.New("squashfs: inode number not in the export table")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

func errIsUnsupported(err error) bool { return errors.Is(err, source.ErrUnsupported) }
