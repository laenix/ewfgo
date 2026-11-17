package hfsplus

import (
	"errors"
	"fmt"
)

// Package-level error kinds.  Callers test them with errors.Is; the message
// always names the concrete offset or feature.
var (
	// ErrInvalid means the bytes do not form a usable HFS+ volume or record.
	ErrInvalid = errors.New("hfsplus: invalid volume")
	// ErrUnsupported means the read recognised a feature but cannot serve it.
	ErrUnsupported = errors.New("hfsplus: unsupported feature")
	// ErrNotFound means the path does not exist in the catalog.
	ErrNotFound = errors.New("hfsplus: not found")
	// ErrIsDirectory means a file operation was asked for a directory.
	ErrIsDirectory = errors.New("hfsplus: is a directory")
	// ErrNotDirectory means path traversal stepped through a non-directory.
	ErrNotDirectory = errors.New("hfsplus: not a directory")
)

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}
