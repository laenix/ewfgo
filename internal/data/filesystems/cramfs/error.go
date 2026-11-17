// Package cramfs reads CramFS images through the data layer's ByteSource
// contract. It is a Go port of forensic-core's cramfs reader: the 76-byte
// superblock (at byte zero or 512), the twelve-byte inodes that live inside
// directory listings, directory parsing, and file data stored as either
// end-pointer or absolute-pointer block tables whose blocks are raw pages or
// zlib streams.
//
// CramFS records no timestamps and no inode numbers, and keeps no deleted
// names. Nothing here invents either. A big-endian image is refused by name:
// every field would need byte swapping. The fsid checksum is reported as
// recorded by Info and compared with the image only when VerifyCRC is called,
// because that pass reads every declared byte.
package cramfs

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
	// decode, such as a big-endian image.
	ErrUnsupported = source.ErrUnsupported
	// ErrPathNotFound means no node has the requested path.
	ErrPathNotFound = errors.New("cramfs: path not found")
	// ErrNotAFile means the node has no data stream (a directory, symlink,
	// device, fifo or socket).
	ErrNotAFile = errors.New("cramfs: node has no data stream")
	// ErrNotDirectory means path traversal expected a directory.
	ErrNotDirectory = errors.New("cramfs: not a directory")
	// ErrNotASymlink means a symbolic-link operation named another kind.
	ErrNotASymlink = errors.New("cramfs: not a symbolic link")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

func errIsUnsupported(err error) bool { return errors.Is(err, source.ErrUnsupported) }
