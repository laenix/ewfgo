package forensic

import (
	"context"
	"fmt"
	"path"

	"github.com/laenix/ewfgo/internal/data/containers/rotated"
	"github.com/laenix/ewfgo/internal/data/source"
)

// DecodedStream is a single-file compressed stream (gzip, bzip2 or LZ4)
// exposed as a read-only file. The decoder verifies the stream's checksum and
// bounds the decoded output; a corrupt or over-limit stream is an explicit
// error.
type DecodedStream struct {
	*File
	format string
}

// Format returns "gzip", "bzip2" or "lz4".
func (d *DecodedStream) Format() string { return d.format }

// OpenCompressed opens a gzip, bzip2 or LZ4 file and returns its decoded bytes.
func OpenCompressed(ctx context.Context, imagePath string, opts Options) (*DecodedStream, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open compressed stream %s: %w", imagePath, err)
	}
	stream, err := OpenCompressedSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, err
	}
	stream.entry.Name = path.Base(imagePath)
	stream.entry.Path = path.Base(imagePath)
	stream.closer = raw
	return stream, nil
}

// OpenCompressedSource decodes a gzip, bzip2 or LZ4 stream over an existing
// byte source. The source is not closed by DecodedStream.Close.
func OpenCompressedSource(ctx context.Context, src ByteSource, opts Options) (*DecodedStream, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil compressed source", ErrInvalidArgument)
	}
	limits := rotated.DefaultLimits()
	if max := opts.Limits.MaxFileBytes; max != 0 {
		if limits.Gzip.MaxDecodedBytes == 0 || max < limits.Gzip.MaxDecodedBytes {
			limits.Gzip.MaxDecodedBytes = max
		}
		if limits.Bzip2.MaxDecodedBytes == 0 || max < limits.Bzip2.MaxDecodedBytes {
			limits.Bzip2.MaxDecodedBytes = max
		}
		if limits.Lz4.MaxDecodedBytes == 0 || max < limits.Lz4.MaxDecodedBytes {
			limits.Lz4.MaxDecodedBytes = max
		}
		if limits.Xz.MaxDecodedBytes == 0 || max < limits.Xz.MaxDecodedBytes {
			limits.Xz.MaxDecodedBytes = max
		}
	}
	decoded, err := rotated.Decode(1, src, limits)
	if err != nil {
		return nil, fmt.Errorf("decode compressed stream: %w", err)
	}
	format := decoded.Label()

	entry := Entry{Name: "decoded", Path: "decoded", Size: decoded.Len()}
	file := &File{
		entry: entry,
		size:  decoded.Len(),
		max:   opts.Limits.MaxFileBytes,
		src:   decoded,
	}
	return &DecodedStream{File: file, format: format}, nil
}
