package befs

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not describe a healthy BeFS
	// image.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a documented feature this reader
	// deliberately does not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrNotFound means a path component did not resolve.
	ErrNotFound = errors.New("befs: path not found")
	// ErrNotDir means a path named something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("befs: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("befs: is a directory")
	// ErrNotRegular means a path named a non-regular file where a file was
	// required.
	ErrNotRegular = errors.New("befs: not a regular file")
	// ErrNotSymlink means a symbolic link was expected and the path is not
	// one.
	ErrNotSymlink = errors.New("befs: not a symbolic link")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
