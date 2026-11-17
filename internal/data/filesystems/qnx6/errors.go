package qnx6

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not describe a healthy QNX6
	// image. It is source.ErrCorrupt so callers can branch on the shared
	// taxonomy.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a documented feature this reader
	// deliberately does not decode, or a structure past a reader bound.
	ErrUnsupported = source.ErrUnsupported
	// ErrUnexpectedEOF means the source ended before a declared structure.
	ErrUnexpectedEOF = source.ErrUnexpectedEOF
	// ErrNotFound means a path component did not resolve.
	ErrNotFound = errors.New("qnx6: path not found")
	// ErrNotDir means a path named something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("qnx6: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("qnx6: is a directory")
	// ErrNotFile means a path names a symlink or special file, not a regular
	// file.
	ErrNotFile = errors.New("qnx6: not a regular file")
	// ErrNotSymlink means a symbolic link was expected and the path is not
	// one.
	ErrNotSymlink = errors.New("qnx6: not a symbolic link")
	// ErrNoSymlinkTarget means the link target was not read into the catalog,
	// either because it exceeded the inline cap or could not be read.
	ErrNoSymlinkTarget = errors.New("qnx6: symbolic-link target not read inline")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

func isCorrupt(err error) bool { return errors.Is(err, source.ErrCorrupt) }

func isUnsupported(err error) bool { return errors.Is(err, source.ErrUnsupported) }
