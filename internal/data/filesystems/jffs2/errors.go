package jffs2

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not describe a healthy JFFS2
	// image.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a documented feature this reader
	// deliberately does not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrNotFound means a path component did not resolve.
	ErrNotFound = errors.New("jffs2: path not found")
	// ErrNotDir means a path named something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("jffs2: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("jffs2: is a directory")
	// ErrNotFile means a path named a symlink or special file, which has no
	// regular file data stream.
	ErrNotFile = errors.New("jffs2: not a regular file")
	// ErrNotSymlink means a symbolic link was expected and the name is not
	// one.
	ErrNotSymlink = errors.New("jffs2: not a symbolic link")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
