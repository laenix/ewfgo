package forensic

import (
	"context"
	"fmt"
	"io"

	"github.com/laenix/ewfgo/internal/data/containers/officelock"
	"github.com/laenix/ewfgo/internal/data/source"
)

// OfficeOwner is a decoded Microsoft Office owner/lock file (`~$...`). It
// records the user name the editing application wrote; it is not proof that the
// document is still open.
type OfficeOwner struct {
	path   string
	file   *officelock.OwnerFile
	closer io.Closer
}

// OpenOfficeOwner decodes an Office owner file.
func OpenOfficeOwner(ctx context.Context, imagePath string, opts Options) (*OfficeOwner, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open Office owner file %s: %w", imagePath, err)
	}
	owner, err := OpenOfficeOwnerSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse Office owner file %s: %w", imagePath, err)
	}
	owner.path = imagePath
	owner.closer = raw
	return owner, nil
}

// OpenOfficeOwnerSource decodes an Office owner file over an existing byte
// source. The source is not closed by OfficeOwner.Close.
func OpenOfficeOwnerSource(ctx context.Context, src ByteSource, opts Options) (*OfficeOwner, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil Office owner source", ErrInvalidArgument)
	}
	file, err := officelock.Open(src)
	if err != nil {
		return nil, err
	}
	return &OfficeOwner{file: file}, nil
}

// Path returns the owner-file path.
func (o *OfficeOwner) Path() string { return o.path }

// Owner returns the recorded user name, preferring the Unicode slot.
func (o *OfficeOwner) Owner() (string, bool) { return o.file.Owner() }

// Layout returns the owner-file layout label.
func (o *OfficeOwner) Layout() string { return o.file.Layout() }

// SlotsAgree reports whether the single-byte and UTF-16 slots agree exactly.
func (o *OfficeOwner) SlotsAgree() bool { return o.file.SlotsAgree() }

// IsOwnerFileName reports whether name has the `~$` owner-file convention.
func IsOwnerFileName(name string) bool { return officelock.IsOwnerFileName(name) }

// Close releases the owner file.
func (o *OfficeOwner) Close() error {
	if o.closer == nil {
		return nil
	}
	err := o.closer.Close()
	o.closer = nil
	return err
}
