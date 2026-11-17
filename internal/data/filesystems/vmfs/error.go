package vmfs

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but do not form the claimed VMFS
	// structure. It wraps source.ErrCorrupt.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a branch this reader does not decode,
	// such as VMFS3/VMFS4, sub-block data, double-indirect maps or a
	// byte-swapped image. It wraps source.ErrUnsupported.
	ErrUnsupported = source.ErrUnsupported
	// ErrPathNotFound means no node has the requested path.
	ErrPathNotFound = errors.New("vmfs: path not found")
	// ErrNotAFile means the node has no regular-file data stream: a directory
	// or a symbolic link.
	ErrNotAFile = errors.New("vmfs: node is not a regular file")
	// ErrNotDir means the path names something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("vmfs: node is not a directory")
	// ErrNotSymlink means a symbolic link was expected and the node is not one.
	ErrNotSymlink = errors.New("vmfs: node is not a symbolic link")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
