// Package iso9660 reads ISO 9660 optical images through the data layer's
// ByteSource contract. It is a Go port of forensic-core's iso9660 reader:
// volume descriptors (including Joliet), Rock Ridge SUSP entries, path tables
// in both byte orders, multi-extent and interleaved files, zisofs transparent
// compression and the El Torito boot catalog.
//
// Strict reads only: a corrupt or truncated structure is an error, never a
// fabricated byte. A feature the Rust reader supports is ported here; a
// feature it refuses is refused by name.
package iso9660

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is.
var (
	// ErrCorrupt means the bytes exist but do not form the claimed structure.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a feature this reader cannot read.
	ErrUnsupported = source.ErrUnsupported
	// ErrPathNotFound means no node has the requested path.
	ErrPathNotFound = errors.New("iso9660: path not found")
	// ErrNotAFile means the node has no data stream: a directory or symlink.
	ErrNotAFile = errors.New("iso9660: node has no data stream")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
