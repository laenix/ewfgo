package forensic

import (
	"context"
	"fmt"
	"io"

	"github.com/laenix/ewfgo/internal/data/aff4"
	"github.com/laenix/ewfgo/internal/data/source"
)

// AFF4Evidence is an opened AFF4 evidence container. AFF4 is a ZIP/RDF-based
// container that declares logical streams and, for disk images, a map or
// image stream whose bytes can be inspected like any other source.
type AFF4Evidence struct {
	path      string
	container *aff4.Container
	closers   []io.Closer
	limits    Limits
}

// AFF4Info summarizes the container's declarations.
type AFF4Info struct {
	Version     string
	FileSize    uint64
	Entries     int
	Files       int
	Directories int
	Streams     int
	Images      int
	Hashes      int
	Warnings    []string
}

// AFF4StreamInfo describes one declared stream.
type AFF4StreamInfo struct {
	URI         string
	Class       string
	Compression string
	Size        uint64
	HasSize     bool
}

// OpenAFF4 opens an AFF4 evidence container from a path.
func OpenAFF4(ctx context.Context, imagePath string, opts Options) (*AFF4Evidence, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open AFF4 %s: %w", imagePath, err)
	}
	container, err := OpenAFF4Source(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse AFF4 %s: %w", imagePath, err)
	}
	container.path = imagePath
	container.closers = []io.Closer{raw}
	return container, nil
}

// OpenAFF4Source opens an AFF4 container over an existing byte source. The
// source is not closed by AFF4Evidence.Close.
func OpenAFF4Source(ctx context.Context, src ByteSource, opts Options) (*AFF4Evidence, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil AFF4 source", ErrInvalidArgument)
	}
	limits := aff4.DefaultLimits()
	if opts.Limits.MaxEntries != 0 && int(opts.Limits.MaxEntries) < limits.MaxEntries {
		limits.MaxEntries = int(opts.Limits.MaxEntries)
	}
	if opts.Limits.MaxFileBytes != 0 && opts.Limits.MaxFileBytes < limits.MaxEntrySize {
		limits.MaxEntrySize = opts.Limits.MaxFileBytes
	}
	container, err := aff4.Open(src, limits)
	if err != nil {
		return nil, err
	}
	return &AFF4Evidence{container: container, limits: opts.Limits}, nil
}

// Path returns the AFF4 path.
func (a *AFF4Evidence) Path() string { return a.path }

// Info returns the container's declared facts.
func (a *AFF4Evidence) Info() AFF4Info {
	facts := a.container.Facts()
	return AFF4Info{
		Version:     a.container.Version(),
		FileSize:    facts.FileSize,
		Entries:     facts.EntryCount,
		Files:       facts.FileCount,
		Directories: facts.DirectoryCount,
		Streams:     len(facts.Streams),
		Images:      facts.ImageStreams,
		Hashes:      len(facts.Hashes),
		Warnings:    append([]string(nil), facts.Warnings...),
	}
}

// Streams returns every declared stream.
func (a *AFF4Evidence) Streams(ctx context.Context) ([]AFF4StreamInfo, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw := a.container.Streams()
	out := make([]AFF4StreamInfo, 0, len(raw))
	for i := range raw {
		stream := &raw[i]
		info := AFF4StreamInfo{
			URI:         stream.URI,
			Class:       stream.ClassLabel(),
			Compression: stream.Compression,
		}
		if stream.Size != nil {
			info.Size = *stream.Size
			info.HasSize = true
		}
		out = append(out, info)
	}
	return out, nil
}

// ImageSource returns the container's sole image stream as a byte source. A
// container with no image or several images returns an explicit error.
func (a *AFF4Evidence) ImageSource(ctx context.Context) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	stream, err := a.container.Image()
	if err != nil {
		return nil, fmt.Errorf("AFF4 image stream: %w", err)
	}
	return stream, nil
}

// OpenStream opens one declared stream by URI. Unsupported chunk codecs are
// reported when the stream is opened, never silently skipped.
func (a *AFF4Evidence) OpenStream(ctx context.Context, uri string) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	stream, err := a.container.OpenStream(uri)
	if err != nil {
		return nil, fmt.Errorf("open AFF4 stream %q: %w", uri, err)
	}
	return stream, nil
}

// Close releases the container's file handle. It is idempotent.
func (a *AFF4Evidence) Close() error {
	var firstErr error
	for _, closer := range a.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	a.closers = nil
	return firstErr
}
