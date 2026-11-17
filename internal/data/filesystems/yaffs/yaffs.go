// Package yaffs reads YAFFS2 NAND filesystem images, read-only, from a
// source.ByteSource.
//
// YAFFS2 has no superblock and no inode table.  Every NAND page ends (or has in
// its spare area) a sixteen-byte tag naming the object, the chunk, the writer's
// serial number and the number of stored bytes.  Chunk zero is the object
// header; every other chunk is file data.  A later write of the same
// (object, chunk) pair shadows the earlier one, so the latest serial number
// wins and the header just before it is the shadow YAFFS keeps for a deleted
// name.
//
// The reader tries the common page/spare geometries, requires the root object
// header to prove the image is YAFFS2, rebuilds the live tree from the latest
// headers, and lists deleted objects under the path their shadow names.  It
// never returns bytes it did not read: a missing data chunk is a hole, a chunk
// that exists but is unreadable is an error, and a deleted object exposes no
// stream because its chunks may already have been reused.
//
// Only YAFFS2's packed sixteen-byte tags are decoded.  YAFFS1's eight-byte tags
// and its sixteen-bit names are refused by name.  Per-tag ECC is not verified:
// the dump carries no chip ECC layout, so the tag's own plausibility checks are
// the evidence available.  Sequence-number ordering covers a window of 2^31
// writes.  The per-page in-band tag is the primary layout; common 64- and
// 128-byte spare-area placements are tried after it.
package yaffs

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds.  Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not describe a consistent
	// YAFFS2 image.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a YAFFS feature this reader does
	// not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrUnexpectedEOF means the source ended before its declared geometry.
	ErrUnexpectedEOF = source.ErrUnexpectedEOF
	// ErrNotFound means no object has the requested path.
	ErrNotFound = errors.New("yaffs: path not found")
	// ErrNotDir means a path named a non-directory where a directory was
	// required.
	ErrNotDir = errors.New("yaffs: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("yaffs: is a directory")
	// ErrNotFile means a path names no regular file (a symlink, special file
	// or a deleted object).
	ErrNotFile = errors.New("yaffs: not a regular file")
	// ErrDeleted means a deleted object was asked for a data stream.
	ErrDeleted = errors.New("yaffs: object is deleted")
	// ErrTooLarge wraps ErrUnsupported for an image or object past a reader
	// bound.
	ErrTooLarge = fmt.Errorf("%w: limit exceeded", source.ErrUnsupported)
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}

func limitf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrTooLarge, fmt.Sprintf(format, args...))
}
