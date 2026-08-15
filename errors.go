package ewf

import "github.com/laenix/ewfgo/internal/filesystem"

// Sentinel errors for the Evidence bridge. They are re-exported aliases of the
// internal/filesystem sentinels so a consumer can classify a failure with
// errors.Is without depending on an internal package:
//
//	_, err := fs.ReadFile("path")
//	switch {
//	case errors.Is(err, ewf.ErrNotFound):
//	    // file genuinely absent — a finding, not a fault
//	case errors.Is(err, ewf.ErrUnsupported):
//	    // filesystem/parser path not implemented
//	case errors.Is(err, ewf.ErrIsDirectory):
//	    // path exists but is a directory
//	}
//
// The ImageFS bridge wraps handler errors with %w, so these unwrap through the
// contextual partition/path prefix.
var (
	// ErrNotFound is returned when a path component or file does not exist.
	ErrNotFound = filesystem.ErrNotFound
	// ErrUnsupported is returned when the filesystem or parser path is not
	// implemented (detection-only filesystems, unimplemented attribute lists).
	ErrUnsupported = filesystem.ErrUnsupported
	// ErrIsDirectory is returned when a file operation targets a directory.
	ErrIsDirectory = filesystem.ErrIsDirectory
	// ErrNotDirectory is returned when a directory operation targets a file.
	ErrNotDirectory = filesystem.ErrNotDirectory
)
