package forensic

import (
	"context"
	"fmt"
	"io"

	"github.com/laenix/ewfgo/internal/data/containers/msdelta"
	"github.com/laenix/ewfgo/internal/data/source"
)

// DeltaPatch is an identified Microsoft Delta (PA19/PA30/PA31) patch file.
// This reader proves the signature and optional prefix CRC; reconstructing the
// target requires the base file and a delta applier, which is not implemented
// and is refused explicitly.
type DeltaPatch struct {
	path   string
	patch  *msdelta.Patch
	closer io.Closer
}

// DeltaInfo describes an identified delta patch.
type DeltaInfo struct {
	Kind            string
	SignatureOffset int
	HasPrefixCRC    bool
	Length          uint64
}

// OpenDelta identifies a Microsoft Delta patch. A source without one of the
// three signatures is refused with ErrUnsupported.
func OpenDelta(ctx context.Context, imagePath string, opts Options) (*DeltaPatch, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open delta patch %s: %w", imagePath, err)
	}
	patch, err := OpenDeltaSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse delta patch %s: %w", imagePath, err)
	}
	patch.path = imagePath
	patch.closer = raw
	return patch, nil
}

// OpenDeltaSource identifies a Microsoft Delta patch over an existing byte
// source. The source is not closed by DeltaPatch.Close.
func OpenDeltaSource(ctx context.Context, src ByteSource, opts Options) (*DeltaPatch, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil delta patch source", ErrInvalidArgument)
	}
	patch, err := msdelta.Open(src)
	if err != nil {
		return nil, err
	}
	return &DeltaPatch{patch: patch}, nil
}

// Path returns the patch path.
func (d *DeltaPatch) Path() string { return d.path }

// Info returns the patch metadata.
func (d *DeltaPatch) Info() DeltaInfo {
	return DeltaInfo{
		Kind:            d.patch.Kind().Label(),
		SignatureOffset: d.patch.SignatureOffset(),
		HasPrefixCRC:    d.patch.HasPrefixCRC(),
		Length:          d.patch.Len(),
	}
}

// PrefixCRCMatches verifies the optional checksum prefix. It returns false,
// nil when the patch records no prefix CRC.
func (d *DeltaPatch) PrefixCRCMatches(ctx context.Context) (bool, error) {
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	return d.patch.PrefixCRCMatches()
}

// Close releases the patch's file handle.
func (d *DeltaPatch) Close() error {
	if d.closer == nil {
		return nil
	}
	err := d.closer.Close()
	d.closer = nil
	return err
}
