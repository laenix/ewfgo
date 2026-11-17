package forensic

import (
	"context"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/filesystems/probe"
	"github.com/laenix/ewfgo/internal/data/partition"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Partition is one partition-table entry, or the whole volume of an image that
// carries no partition table (WholeVolume reports which).
type Partition struct {
	index     int
	typeName  string
	offset    uint64
	length    uint64
	nodeID    source.ID
	format    probe.Kind
	label     string
	whole     bool
	src       ByteSource
	sector    uint32
	tableKind partition.Kind
	limits    Limits
}

// Index returns the partition-table index (0-based).
func (p *Partition) Index() int { return p.index }

// TypeName returns the partition type as the table names it (for MBR, the
// type byte's conventional name; for GPT, the partition name). It is table
// metadata, not filesystem detection.
func (p *Partition) TypeName() string { return p.typeName }

// Offset returns the partition's byte offset in the image.
func (p *Partition) Offset() uint64 { return p.offset }

// Length returns the partition's byte length.
func (p *Partition) Length() uint64 { return p.length }

// NodeID returns the partition's node in the provenance graph.
func (p *Partition) NodeID() source.ID { return p.nodeID }

// Source returns the partition-relative byte source. Offset 0 is the first
// byte of the partition.
func (p *Partition) Source() ByteSource { return p.src }

// Stats returns this partition source's read counters.
func (p *Partition) Stats() Stats { return p.src.Stats() }

// Format returns the detected volume format's display name ("NTFS", "FAT16",
// "ext4", "unknown", ...).
func (p *Partition) Format() string { return p.label }

// Encrypted reports whether an encryption layer (BitLocker, LUKS, CoreStorage)
// was detected; such a volume cannot be opened without keys.
func (p *Partition) Encrypted() bool { return p.format.Encrypted() }

// WholeVolume reports whether this entry is the entire image rather than a
// partition-table entry.
func (p *Partition) WholeVolume() bool { return p.whole }

// TableKind returns the partition table kind ("MBR", "GPT", "APM", "BSD" or
// "none").
func (p *Partition) TableKind() string { return p.tableKind.Label() }

// OpenFilesystem opens the filesystem detected on this partition. Encrypted or
// unsupported volumes return an explicit error.
func (p *Partition) OpenFilesystem(ctx context.Context) (FileSystem, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return openFilesystem(p.src, p.format, p.sector, p.limits)
}

// Partitions detects the image's partition table, probes every partition and
// returns them. For an image with no partition table but a recognised
// filesystem, it returns one WholeVolume entry. For an image with neither, it
// returns an empty slice.
func (i *Image) Partitions(ctx context.Context) ([]*Partition, error) {
	report, err := i.analysis(ctx)
	if err != nil {
		return nil, err
	}
	sector := i.SectorSize()

	if report.TableKind == partition.KindNone {
		if report.VolumeFormat == probe.None {
			return nil, nil
		}
		return []*Partition{{
			index:     0,
			typeName:  "whole volume",
			offset:    0,
			length:    i.source.Len(),
			nodeID:    i.source.SourceID(),
			format:    report.VolumeFormat,
			label:     volumeLabel(i.source, report.VolumeFormat),
			whole:     true,
			src:       i.source,
			sector:    sector,
			tableKind: report.TableKind,
			limits:    i.opts.Limits,
		}}, nil
	}

	partitions := make([]*Partition, 0, len(report.Partitions))
	for _, entry := range report.Partitions {
		src, ok := report.Graph.Source(entry.NodeID)
		if !ok {
			return nil, fmt.Errorf("%w: partition %d has no byte source", ErrCorrupt, entry.Index)
		}
		partitions = append(partitions, &Partition{
			index:     entry.Index,
			typeName:  entry.TypeName,
			offset:    entry.Offset,
			length:    entry.Length,
			nodeID:    entry.NodeID,
			format:    entry.Format,
			label:     volumeLabel(src, entry.Format),
			src:       src,
			sector:    sector,
			tableKind: report.TableKind,
			limits:    i.opts.Limits,
		})
	}
	return partitions, nil
}

// PartitionTable returns the detected table kind ("MBR", "GPT", "APM", "BSD" or
// "none").
func (i *Image) PartitionTable(ctx context.Context) (string, error) {
	report, err := i.analysis(ctx)
	if err != nil {
		return "", err
	}
	return report.TableKind.Label(), nil
}

// OpenFilesystem opens the filesystem of an image that has no partition table
// (a bare filesystem image). An image with a partition table returns an error
// directing the caller to Partitions.
func (i *Image) OpenFilesystem(ctx context.Context) (FileSystem, error) {
	report, err := i.analysis(ctx)
	if err != nil {
		return nil, err
	}
	if report.TableKind != partition.KindNone {
		return nil, fmt.Errorf("%w: image has a %s partition table; open one of Partitions()",
			ErrInvalidArgument, report.TableKind.Label())
	}
	return openFilesystem(i.source, report.VolumeFormat, i.SectorSize(), i.opts.Limits)
}
