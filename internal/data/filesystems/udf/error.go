// Package udf reads Universal Disk Format (ECMA-167 / OSTA UDF) optical and
// removable-media images through the data layer's ByteSource contract. It is a
// Go port of forensic-core's udf reader.
//
// The reader recognises the volume through the ECMA-167 volume recognition
// sequence (BEA01 followed by NSR02/NSR03), finds the anchor volume descriptor
// pointer at logical sector 256, reads the volume descriptor sequence
// (primary, partition, logical volume), locates the file set descriptor, and
// walks the directory tree from the root's information control block.
//
// Strict reads only: a descriptor tag that does not verify, a truncated
// structure, or an address outside its partition is an explicit error, never a
// fabricated byte. Features the Rust reader models but this port does not are
// refused by name with ErrUnsupported.
package udf

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is.
var (
	// ErrCorrupt means the bytes exist but are not the structure they claim.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the volume uses a feature this reader cannot read.
	ErrUnsupported = source.ErrUnsupported
	// ErrPathNotFound means no node has the requested path.
	ErrPathNotFound = errors.New("udf: path not found")
	// ErrNotDir means the path exists but is not a directory.
	ErrNotDir = errors.New("udf: path is not a directory")
	// ErrNotAFile means the path has no data stream: a directory or symlink.
	ErrNotAFile = errors.New("udf: path has no data stream")
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}
