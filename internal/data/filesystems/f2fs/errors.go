// Package f2fs reads F2FS volumes, read-only, from a source.ByteSource.
//
// The package is a port of the Rust forensic-core F2FS reader.  It follows the
// same chain of trust: the superblock describes the geometry, one of the two
// checkpoints is the newest that verifies, the node address table says where
// each node id lives, and node blocks close with a footer that proves the block
// read is the one asked for.  Every read returns real bytes or an explicit
// error; holes are the only zero bytes this reader manufactures, and they are
// holes the inode's own address array declares.
package f2fs

import (
	"errors"
	"fmt"
)

// Error kinds.  Callers test them with errors.Is, never by string matching.
var (
	// ErrInvalid means the bytes exist but do not describe a consistent F2FS
	// structure.
	ErrInvalid = errors.New("f2fs: invalid filesystem")
	// ErrUnsupported means the volume uses a feature this reader cannot follow.
	ErrUnsupported = errors.New("f2fs: unsupported feature")
	// ErrNotFound means a path component did not resolve.
	ErrNotFound = errors.New("f2fs: path not found")
	// ErrNotDir means a path named something other than a directory where a
	// directory was required.
	ErrNotDir = errors.New("f2fs: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("f2fs: is a directory")
	// ErrNotSymlink means a symbolic link was expected and the inode is not one.
	ErrNotSymlink = errors.New("f2fs: not a symbolic link")
)

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// unsupportedf builds an unsupported-feature error that names the feature.
func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}
