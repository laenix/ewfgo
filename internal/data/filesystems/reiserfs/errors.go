package reiserfs

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not describe a healthy ReiserFS
	// volume. It is source.ErrCorrupt so callers can branch on the data layer's
	// shared taxonomy.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the volume uses a documented feature this reader
	// deliberately does not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrNotFound means a path component did not resolve to a visible name.
	ErrNotFound = errors.New("reiserfs: path not found")
	// ErrNotDir means a path named something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("reiserfs: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("reiserfs: is a directory")
	// ErrNotSymlink means a symbolic link was expected and the object is not
	// one.
	ErrNotSymlink = errors.New("reiserfs: not a symbolic link")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
