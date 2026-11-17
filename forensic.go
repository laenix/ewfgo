// Package forensic is the public API of the ewfgo forensic data engine.
//
// It opens evidence images (EWF/E01, raw disks and virtual-disk containers),
// exposes their partitions and volumes as byte sources, and opens the
// filesystem on a volume for directory and file reads. Every read is served by
// the exact-decompression/decoding path underneath: a read that cannot be
// served returns an explicit error, never fabricated, zero-filled or partial
// bytes presented as evidence.
//
// The typical flow is:
//
//	img, err := forensic.Open(ctx, "evidence.E01", forensic.Options{})
//	if err != nil { ... }
//	defer img.Close()
//
//	parts, err := img.Partitions(ctx)
//	if err != nil { ... }
//	for _, p := range parts {
//		fsys, err := p.OpenFilesystem(ctx)
//		if err != nil { continue }
//		entries, err := fsys.ListDir(ctx, "/")
//		...
//	}
//
// Byte ranges are addressed with ByteSource, a read-only interface that
// carries provenance: SourceID, ImageID, Extents and MapToImage trace any byte
// back to the image container that holds it.
package forensic

import (
	"context"
	"io"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ByteSource is a readable evidence byte range with provenance. Every layer
// (image container, partition, decoded stream, file) implements it.
type ByteSource = source.ByteSource

// ID identifies a node in a source provenance graph.
type ID = source.ID

// ImageID identifies the image container that owns a byte range.
type ImageID = source.ImageID

// ParentRange / ImageRange are the provenance translation results.
type (
	ParentRange = source.ParentRange
	ImageRange  = source.ImageRange
	RangeKind   = source.RangeKind
	Stats       = source.Stats
)

// Range kinds reported by Extents and MapToImage.
const (
	RangeData    = source.RangeData
	RangeZero    = source.RangeZero
	RangeHole    = source.RangeHole
	RangeError   = source.RangeError
	RangeDerived = source.RangeDerived
)

// Structured error kinds. Test them with errors.Is; never match on message text.
var (
	ErrOutOfRange      = source.ErrOutOfRange
	ErrUnexpectedEOF   = source.ErrUnexpectedEOF
	ErrCorrupt         = source.ErrCorrupt
	ErrIO              = source.ErrIO
	ErrUnsupported     = source.ErrUnsupported
	ErrDecrypt         = source.ErrDecrypt
	ErrCancelled       = source.ErrCancelled
	ErrInvalidArgument = source.ErrInvalidArgument
)

// Limits bounds parser resource use. The zero value selects conservative
// defaults: no entry/depth caps beyond the parsers' own validation.
type Limits struct {
	// MaxEntries caps a single directory listing. 0 means unlimited.
	MaxEntries uint64
	// MaxDepth caps Walk recursion. 0 means unlimited.
	MaxDepth int
	// MaxFileBytes caps ReadAll on a file. 0 means unlimited.
	MaxFileBytes uint64
}

// Options configure Open and OpenSource.
type Options struct {
	Limits Limits
	// SectorSize overrides the sector-size hint for raw files and OpenSource
	// inputs. Container-declared geometry (E01, VHDX, ...) takes precedence.
	// 0 uses the source's own sector size.
	SectorSize uint32
	// Resolver opens a side file (split VMDK extent) by name. nil resolves
	// names relative to the opened image's directory as read-only raw files.
	Resolver func(name string) (ByteSource, error)
}

func (o Options) sectorSize(src ByteSource, fallback uint32) uint32 {
	if o.SectorSize != 0 {
		return o.SectorSize
	}
	if src != nil && src.SectorSize() != 0 {
		return src.SectorSize()
	}
	if fallback != 0 {
		return fallback
	}
	return 512
}

// ReaderAt adapts a ByteSource to io.ReaderAt. A read at or past the end
// returns io.EOF; a short tail returns the bytes plus io.EOF.
func ReaderAt(src ByteSource) io.ReaderAt { return source.ReaderAt(src) }

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
