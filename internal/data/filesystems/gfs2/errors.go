package gfs2

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not describe a healthy GFS2
	// image. It is source.ErrCorrupt so a caller can branch on the data
	// layer's shared taxonomy.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a documented feature this reader
	// deliberately does not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrNotFound means a path component did not resolve.
	ErrNotFound = errors.New("gfs2: path not found")
	// ErrNotDir means a path named something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("gfs2: not a directory")
	// ErrIsDir means a path named a directory where a data stream was
	// required.
	ErrIsDir = errors.New("gfs2: is a directory")
	// ErrNotFile means the inode is not a regular file, so OpenFile cannot
	// open it.
	ErrNotFile = errors.New("gfs2: not a regular file")
	// ErrNotSymlink means a symbolic link was expected and the inode is not
	// one.
	ErrNotSymlink = errors.New("gfs2: not a symbolic link")
	// ErrNoSymlinkTarget means the link target was not read into the catalog,
	// either because it exceeded the inline cap or because it was
	// undecodable; SymlinkTargetStream still opens it.
	ErrNoSymlinkTarget = errors.New("gfs2: symbolic-link target not read inline")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

func isCorrupt(err error) bool { return errors.Is(err, source.ErrCorrupt) }

func isUnsupported(err error) bool { return errors.Is(err, source.ErrUnsupported) }
