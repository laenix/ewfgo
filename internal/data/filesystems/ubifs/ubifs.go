// Package ubifs reads UBI and UBIFS images, read-only, from a source.ByteSource.
//
// Two layers stand between a name and the bytes: UBI finds erase-block headers,
// volume headers, the volume table and the logical-to-physical erase-block
// map; UBIFS mounts one volume through the committed master node, walks the
// index B-tree and assembles files from their inode, dent, xent and data
// nodes.
//
// The reader follows the same chain of trust as the Rust forensic-core
// implementation.  A bare UBIFS image starts with a 4096-byte superblock; a
// UBI image is measured from its repeating erase-block headers, its volume
// headers and whichever page/OOB geometry makes a volume-table record or a
// UBIFS superblock verify.  Ambiguous geometry is refused by name rather than
// guessed.  Both master nodes are read and the newer verified one wins; equal
// sequence numbers are accepted only when their roots are identical.
//
// The index B-tree is the committed state a static image shows.  Neither the
// journal nor the LPT is replayed, and blank flash is not turned into a
// free-space claim.  A data block with no data node is a hole only because the
// inode's own length proves the block exists; a data node that is present but
// corrupt, or whose compressor is not decoded, is an error, never a hole.
// Timestamps are the inode's own seconds and nanoseconds; a zero/zero pair is
// unset and is not reported as 1970.
package ubifs

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// KindLabel is the filesystem name reports use.
const KindLabel = "UBIFS"

// RootIno is the UBIFS root inode number.
const RootIno uint64 = 1

// Magic is UBIFS's little-endian node magic.
const Magic uint32 = 0x0610_1831

// Error kinds.  Callers test them with errors.Is, never by string matching.
var (
	// ErrCorrupt means the bytes exist but contradict their own metadata.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the image uses a feature or geometry this reader
	// does not decode.
	ErrUnsupported = source.ErrUnsupported
	// ErrUnexpectedEOF means the source ended before a declared structure.
	ErrUnexpectedEOF = source.ErrUnexpectedEOF
	// ErrNotFound means a path component did not resolve.
	ErrNotFound = errors.New("ubifs: path not found")
	// ErrNotDir means a path named a non-directory where a directory was
	// required.
	ErrNotDir = errors.New("ubifs: not a directory")
	// ErrIsDir means a path named a directory where a file was required.
	ErrIsDir = errors.New("ubifs: is a directory")
	// ErrNotFile means a path names a symlink or special file, not a regular
	// file.
	ErrNotFile = errors.New("ubifs: not a regular file")
	// ErrNotSymlink means a symbolic link was expected and the entry is not
	// one.
	ErrNotSymlink = errors.New("ubifs: not a symbolic link")
	// ErrTooLarge wraps ErrUnsupported for an object past a reader bound.
	ErrTooLarge = fmt.Errorf("%w: limit exceeded", source.ErrUnsupported)
)

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}

func limitf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrTooLarge, fmt.Sprintf(format, args...))
}

// NodeKind is what a dent, xent or inode says a name is.
type NodeKind uint8

// UBIFS dent type values, in the order the format defines them.
const (
	TypeBlockDevice uint8 = 0
	TypeCharDevice  uint8 = 1
	TypeDir         uint8 = 2
	TypeFifo        uint8 = 3
	TypeReg         uint8 = 4
	TypeSock        uint8 = 5
	TypeSymlink     uint8 = 6
)

// Node kinds.  Other is a dent type this reader does not name.
const (
	KindDirectory NodeKind = iota
	KindFile
	KindSymlink
	KindCharDevice
	KindBlockDevice
	KindFifo
	KindSocket
	KindOther
)

// Label returns the kind's report name.
func (k NodeKind) Label() string {
	switch k {
	case KindDirectory:
		return "directory"
	case KindFile:
		return "regular file"
	case KindSymlink:
		return "symbolic link"
	case KindCharDevice:
		return "character device"
	case KindBlockDevice:
		return "block device"
	case KindFifo:
		return "fifo"
	case KindSocket:
		return "socket"
	default:
		return "other"
	}
}

// FromDentType maps a UBIFS dent type to a NodeKind.
func FromDentType(value uint8) (NodeKind, bool) {
	switch value {
	case TypeBlockDevice:
		return KindBlockDevice, true
	case TypeCharDevice:
		return KindCharDevice, true
	case TypeDir:
		return KindDirectory, true
	case TypeFifo:
		return KindFifo, true
	case TypeReg:
		return KindFile, true
	case TypeSock:
		return KindSocket, true
	case TypeSymlink:
		return KindSymlink, true
	default:
		return KindOther, false
	}
}

func kindFromMode(mode uint32) (NodeKind, bool) {
	switch mode & 0o170000 {
	case 0o040000:
		return KindDirectory, true
	case 0o100000:
		return KindFile, true
	case 0o120000:
		return KindSymlink, true
	case 0o020000:
		return KindCharDevice, true
	case 0o060000:
		return KindBlockDevice, true
	case 0o010000:
		return KindFifo, true
	case 0o140000:
		return KindSocket, true
	default:
		return KindOther, false
	}
}

// IsDirectory reports whether the kind is a directory.
func (k NodeKind) IsDirectory() bool { return k == KindDirectory }

// IsSymlink reports whether the kind is a symbolic link.
func (k NodeKind) IsSymlink() bool { return k == KindSymlink }

// IsFile reports whether the kind is a regular file.
func (k NodeKind) IsFile() bool { return k == KindFile }
