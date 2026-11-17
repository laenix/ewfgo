// Package sysv reads the System V family of filesystems through the data
// layer's read-only ByteSource contract: Xenix, System V Release 2, System V
// Release 4 and Coherent. It is a Go port of forensic-core's sysv reader.
//
// Detection follows the on-disk signatures only: the Xenix magic at byte 2040
// of its 1024-byte superblock, the System V magic at byte 1016 of the
// half-block at byte 512, and Coherent's name fields (it has no magic). The
// in-memory VFS magic constants some references cite are never written to
// disk and are not searched for. A System V image is split into Release 2 and
// Release 4 by the update time at the Release 4 offset, exactly as Linux's
// fs/sysv driver does.
//
// Inodes are 64 bytes and directory entries 16 bytes with 14-byte names in
// every verified variant. The ISC long-name layout and Xenix with 512-byte
// blocks are refused with ErrUnsupported rather than guessed. SCO AFS files
// remain readable, but its bitmap free list is not decoded: FreeList and
// FreeSpace return ErrUnsupported. The kernel clears a directory slot's inode
// on deletion, so no deleted name is recoverable and no entry is marked
// deleted.
package sysv

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is.
var (
	// ErrCorrupt means the bytes exist but do not form the claimed structure,
	// or a pointer lies outside the declared geometry.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnsupported means the variant or layout is recognised but not
	// decoded here.
	ErrUnsupported = source.ErrUnsupported
	// ErrPathNotFound means no node has the requested path.
	ErrPathNotFound = sourceError("path not found")
	// ErrNotAFile means the node has no data stream for OpenFile.
	ErrNotAFile = sourceError("node has no data stream")
	// ErrNotADirectory means ListDir was called on a non-directory.
	ErrNotADirectory = sourceError("node is not a directory")
)

type sourceError string

func (e sourceError) Error() string { return "sysv: " + string(e) }

func corruptf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

// The named refusals below carry the stable slugs the reference reader uses,
// so a report can group them without parsing prose.

func unsupportedVariant(detail string) error {
	return unsupportedf("unsupported-sysv-variant: %s", detail)
}

func badSuperblock(detail string) error {
	return corruptf("bad-sysv-superblock: %s", detail)
}

func unverifiedInodeLayout(detail string) error {
	return unsupportedf("unverified-inode-layout: %s", detail)
}

func boundsError(detail string) error {
	return corruptf("bounds: %s", detail)
}

func loopDetected(detail string) error {
	return corruptf("loop: %s", detail)
}

func mappingCap(detail string) error {
	return unsupportedf("mapping-cap: %s", detail)
}

func corruptedFreeList(detail string) error {
	return corruptf("corrupted-sysv-free-list: %s", detail)
}
