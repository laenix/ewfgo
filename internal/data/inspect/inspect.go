// Package inspect turns one image ByteSource into a provenance graph: the
// partition table (when present), one node per partition, and one node per
// detected filesystem. It does not open filesystem handlers; callers can do
// that from the partition source with the volume package.
package inspect

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/filesystems/probe"
	"github.com/laenix/ewfgo/internal/data/filesystems/volume"
	"github.com/laenix/ewfgo/internal/data/partition"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/filesystem"
)

// PartitionReport is one partition and the filesystem detected at its start.
type PartitionReport struct {
	Index    int
	Offset   uint64
	Length   uint64
	TypeName string
	NodeID   source.ID
	FSType   filesystem.FileSystemType
	FSNodeID source.ID
	// Format is the data-layer probe result, including formats with no handler.
	Format probe.Kind
}

// Report is the inspection result for one image.
type Report struct {
	Graph     *source.SourceGraph
	TableKind partition.Kind
	// VolumeType/VolumeNodeID describe a bare volume image (no partition table).
	VolumeType   filesystem.FileSystemType
	VolumeNodeID source.ID
	VolumeFormat probe.Kind
	Partitions   []PartitionReport
	// NextID is the first node id not used by this report. Callers that add
	// higher layers (assembled volumes) allocate from here.
	NextID source.ID
}

// Image detects the partition table and filesystem signatures of img and
// records them in a validated SourceGraph. Node ids are assigned sequentially
// from uint64(id)+1.
func Image(id source.ID, img source.ByteSource, sectorSize uint32) (*Report, error) {
	if img == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil image source"}
	}
	if sectorSize < 512 || sectorSize&(sectorSize-1) != 0 {
		return nil, &source.Error{
			Kind:   source.ErrInvalidArgument,
			Reason: fmt.Sprintf("invalid sector size %d: must be a power of two >= 512", sectorSize),
		}
	}

	graph := source.NewSourceGraph()
	imageNode := source.NewSourceNode(id, source.SourceImage, img.Len(), nil, "image")
	if err := graph.AddNode(imageNode, img); err != nil {
		return nil, err
	}

	table, err := partition.Detect(img)
	if err != nil {
		return nil, fmt.Errorf("partition detect: %w", err)
	}
	report := &Report{Graph: graph, TableKind: table.Kind}
	next := uint64(id) + 1

	if table.Kind == partition.KindNone {
		fsType, err := volume.Detect(img)
		if err != nil {
			return nil, err
		}
		report.VolumeType = fsType
		format, err := probe.Detect(img)
		if err != nil {
			return nil, err
		}
		report.VolumeFormat = format
		if fsType != filesystem.FS_UNKNOWN {
			nodeID := source.ID(next)
			node := source.NewSourceNode(nodeID, source.SourceFileSystem, img.Len(),
				[]source.ParentRef{{Parent: id, OffsetInParent: 0, Len: img.Len()}}, string(fsType))
			if err := graph.AddNode(node, nil); err != nil {
				return nil, err
			}
			report.VolumeNodeID = nodeID
			next++
		}
		report.NextID = source.ID(next)
		if err := graph.Validate(); err != nil {
			return nil, err
		}
		return report, nil
	}

	for _, p := range table.Partitions() {
		partitionID := source.ID(next)
		next++
		sub, err := source.NewSubSource(partitionID, img, p.Offset, p.Len)
		if err != nil {
			return nil, fmt.Errorf("partition %d: %w", p.Index, err)
		}
		node := source.NewSourceNode(partitionID, source.SourcePartition, p.Len,
			[]source.ParentRef{{Parent: id, OffsetInParent: p.Offset, Len: p.Len}}, p.Name)
		if err := graph.AddNode(node, sub); err != nil {
			return nil, err
		}

		fsType, err := volume.Detect(sub)
		if err != nil {
			return nil, fmt.Errorf("partition %d: %w", p.Index, err)
		}
		format, err := probe.Detect(sub)
		if err != nil {
			return nil, fmt.Errorf("partition %d: %w", p.Index, err)
		}
		pr := PartitionReport{
			Index: p.Index, Offset: p.Offset, Length: p.Len,
			TypeName: p.Name, NodeID: partitionID, FSType: fsType, Format: format,
		}
		if fsType != filesystem.FS_UNKNOWN {
			fsID := source.ID(next)
			next++
			fsNode := source.NewSourceNode(fsID, source.SourceFileSystem, p.Len,
				[]source.ParentRef{{Parent: partitionID, OffsetInParent: 0, Len: p.Len}}, string(fsType))
			if err := graph.AddNode(fsNode, nil); err != nil {
				return nil, err
			}
			pr.FSNodeID = fsID
		}
		report.Partitions = append(report.Partitions, pr)
	}

	report.NextID = source.ID(next)
	if err := graph.Validate(); err != nil {
		return nil, err
	}
	return report, nil
}
