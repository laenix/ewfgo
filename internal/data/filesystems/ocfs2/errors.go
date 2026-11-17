package ocfs2

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not describe a healthy OCFS2
	// volume. It is source.ErrCorrupt so callers can branch on the shared data
	// layer taxonomy.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the volume uses a documented feature this reader
	// deliberately does not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrNotFound means a path component did not resolve.
	ErrNotFound = errors.New("ocfs2: path not found")
	// ErrNotDir means a path named something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("ocfs2: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("ocfs2: is a directory")
	// ErrNotSymlink means a symbolic link was expected and the inode is not
	// one.
	ErrNotSymlink = errors.New("ocfs2: not a symbolic link")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
