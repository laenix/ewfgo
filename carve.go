package forensic

import (
	"context"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/carving"
)

// CarvedFormat identifies one signature-carved file format.
type CarvedFormat = carving.CarvedFormat

// CarvedObject is one object found by a carve pass.
type CarvedObject = carving.CarvedObject

// CarveReport is the result of one carve pass.
type CarveReport = carving.CarveReport

// CarveOptions bounds a carve pass.
type CarveOptions = carving.CarveOptions

// DefaultCarveOptions returns the module's resource defaults.
func DefaultCarveOptions() CarveOptions { return carving.DefaultCarveOptions() }

// Carve scans [start, start+length) for known file signatures and returns the
// objects whose own structure validates. The scan is lossy by design: bytes
// the source cannot deliver are searched as zeros and counted in
// CarveReport.Unreadable, while carved object boundaries are derived from the
// object's real headers, never from invented data.
func Carve(src ByteSource, start, length uint64, options CarveOptions) (*CarveReport, error) {
	if src == nil {
		return nil, fmt.Errorf("%w: nil carve source", ErrInvalidArgument)
	}
	return carving.Carve(src, start, length, options)
}

// Carve scans this image's decoded media.
func (i *Image) Carve(ctx context.Context, start, length uint64, options CarveOptions) (*CarveReport, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return Carve(i.source, start, length, options)
}

// Carve scans this partition-relative byte range.
func (p *Partition) Carve(ctx context.Context, start, length uint64, options CarveOptions) (*CarveReport, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return Carve(p.src, start, length, options)
}

// Carve scans this assembled volume.
func (v *Volume) Carve(ctx context.Context, start, length uint64, options CarveOptions) (*CarveReport, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if v.src == nil {
		return nil, fmt.Errorf("%w: volume %s cannot be assembled: %s", ErrUnsupported, v.name, v.issue)
	}
	return Carve(v.src, start, length, options)
}
