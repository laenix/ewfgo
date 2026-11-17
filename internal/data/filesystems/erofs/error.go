// Package erofs reads EROFS images through the data layer's ByteSource
// contract. It is a Go port of forensic-core's erofs reader: the version-1
// superblock at byte 1024, compact and extended inodes, directory blocks,
// flat-plain and flat-inline data, and the full and compact compressed-index
// encodings with their pcluster extents.
//
// Compression is limited to the codecs a pure-Go build can decode without new
// dependencies: DEFLATE (compress/flate). LZ4, MicroLZMA and Zstandard
// pclusters are recognised by name and refused with ErrUnsupported, naming the
// algorithm; uncompressed files, shifted pclusters and holes remain readable.
// Strict reads never fabricate a decoded byte.
//
// EROFS records one time on an extended inode when the superblock's mtime
// feature is set. It keeps no deleted names and no free-space map: a removal
// rewrites the image.
package erofs

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
	// decode, such as an LZ4 pcluster or a chunk-based inode.
	ErrUnsupported = source.ErrUnsupported
	// ErrPathNotFound means no node has the requested path.
	ErrPathNotFound = errors.New("erofs: path not found")
	// ErrNotAFile means the node has no data stream (a directory, symlink,
	// device, fifo or socket).
	ErrNotAFile = errors.New("erofs: node has no data stream")
	// ErrNotDirectory means path traversal expected a directory.
	ErrNotDirectory = errors.New("erofs: not a directory")
	// ErrNotASymlink means a symbolic-link operation named another kind.
	ErrNotASymlink = errors.New("erofs: not a symbolic link")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
