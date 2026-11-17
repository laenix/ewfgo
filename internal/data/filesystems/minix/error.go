// Package minix reads Minix v1, v2 and v3 filesystems through the data
// layer's read-only ByteSource contract. It is a Go port of forensic-core's
// minix reader: the three superblock layouts, the zone and inode bitmaps'
// geometry, 32- and 64-byte inodes, 16/32/64-byte directory entries, and the
// direct, single, double and triple indirect zone maps.
//
// Detection reads the magic at byte 1024. A magic in the wrong byte order is
// refused with ErrUnsupported rather than reinterpreted. The zone bitmap is
// not translated into a free-space map: the reference reader does not do so,
// and a corrupt bitmap therefore never blocks a live read. Minix clears a
// directory slot's inode number on deletion, so the format retains no deleted
// name and this package reports no deleted entries. V1 stores only a
// modification time; its access and change times are reported as unset.
//
// A file needing more zones than its inode's pointers can address, more than
// the reader's mapping cap, or a non-zero zone outside [first_data_zone,
// zones) is refused; nothing is partially read.
package minix

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is.
var (
	// ErrCorrupt means the bytes exist but do not form the claimed structure.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image is byte-swapped or uses a feature this
	// reader does not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrPathNotFound means no node has the requested path.
	ErrPathNotFound = sourceError("path not found")
	// ErrNotAFile means the node has no data stream for OpenFile: a
	// directory, symlink, device, fifo or socket.
	ErrNotAFile = sourceError("node has no data stream")
	// ErrNotADirectory means ListDir was called on a non-directory.
	ErrNotADirectory = sourceError("node is not a directory")
)

type sourceError string

func (e sourceError) Error() string { return "minix: " + string(e) }

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
