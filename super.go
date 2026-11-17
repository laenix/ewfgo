package forensic

import (
	"context"
	"fmt"
	"io"

	"github.com/laenix/ewfgo/internal/data/partition/super"
	"github.com/laenix/ewfgo/internal/data/source"
)

// SuperImage is an opened Android `super.img` dynamic-partition image. Each
// logical partition is a source-backed byte stream assembled from linear and
// zero extents.
type SuperImage struct {
	path  string
	image *super.Image
	close io.Closer
}

// SuperInfo summarizes a super image.
type SuperInfo struct {
	MajorVersion   uint16
	MinorVersion   uint16
	MetadataSlot   uint32
	BackupGeometry bool
	Partitions     int
	Groups         int
	GeometrySHA256 string
	HeaderSHA256   string
	TablesSHA256   string
}

// SuperPartition describes one logical partition.
type SuperPartition struct {
	Name       string
	Group      string
	Size       uint64
	Attributes uint32
	Extents    int
}

// OpenSuper opens an Android super image.
func OpenSuper(ctx context.Context, imagePath string, opts Options) (*SuperImage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 4096))
	if err != nil {
		return nil, fmt.Errorf("open super image %s: %w", imagePath, err)
	}
	image, err := OpenSuperSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse super image %s: %w", imagePath, err)
	}
	image.path = imagePath
	image.close = raw
	return image, nil
}

// OpenSuperSource opens an Android super image over an existing byte source.
// The source is not closed by SuperImage.Close.
func OpenSuperSource(ctx context.Context, src ByteSource, opts Options) (*SuperImage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil super image source", ErrInvalidArgument)
	}
	image, err := super.Open(src)
	if err != nil {
		return nil, err
	}
	return &SuperImage{image: image}, nil
}

// Path returns the super image path.
func (s *SuperImage) Path() string { return s.path }

// Info returns the parsed geometry/header summary.
func (s *SuperImage) Info() SuperInfo {
	header := s.image.Header()
	return SuperInfo{
		MajorVersion:   header.MajorVersion,
		MinorVersion:   header.MinorVersion,
		MetadataSlot:   s.image.MetadataSlot(),
		BackupGeometry: s.image.UsedBackupGeometry(),
		Partitions:     len(s.image.Partitions()),
		Groups:         len(s.image.Groups()),
		GeometrySHA256: s.image.GeometryChecksumHex(),
		HeaderSHA256:   s.image.HeaderChecksumHex(),
		TablesSHA256:   s.image.TablesChecksumHex(),
	}
}

// Partitions returns the logical partitions in metadata order.
func (s *SuperImage) Partitions(ctx context.Context) ([]SuperPartition, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	groups := s.image.Groups()
	raw := s.image.Partitions()
	out := make([]SuperPartition, 0, len(raw))
	for i := range raw {
		partition := &raw[i]
		group := ""
		if int(partition.GroupIndex) < len(groups) {
			group = groups[partition.GroupIndex].Name
		}
		out = append(out, SuperPartition{
			Name:       partition.Name,
			Group:      group,
			Size:       partition.Len,
			Attributes: partition.Attributes,
			Extents:    int(partition.NumExtents),
		})
	}
	return out, nil
}

// OpenPartition opens one logical partition by name.
func (s *SuperImage) OpenPartition(ctx context.Context, name string) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	partitions := s.image.Partitions()
	for index := range partitions {
		if partitions[index].Name != name {
			continue
		}
		src, err := s.image.OpenPartition(source.ID(2_000_000+index), index)
		if err != nil {
			return nil, fmt.Errorf("open super partition %q: %w", name, err)
		}
		return src, nil
	}
	return nil, fmt.Errorf("%w: super image has no partition %q", ErrInvalidArgument, name)
}
