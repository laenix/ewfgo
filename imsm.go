package forensic

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	imsmcontainer "github.com/laenix/ewfgo/internal/data/partition/imsm"
	"github.com/laenix/ewfgo/internal/data/source"
)

// IMSMContainer is a parsed Intel Matrix RAID (IMSM) metadata parameter block
// from one member disk. The same container metadata is replicated on every
// member; assembling an array needs the member disks.
type IMSMContainer struct {
	path      string
	container *imsmcontainer.Container
	close     io.Closer

	nextID atomic.Uint64
}

// IMSMInfo summarizes an IMSM container.
type IMSMInfo struct {
	ContainerUUID string
	Version       string
	FamilyNum     uint32
	GenerationNum uint32
	SectorSize    uint32
	Disks         int
	Volumes       int
	DirtyVolumes  int
}

// IMSMDiskInfo describes one member disk record.
type IMSMDiskInfo struct {
	Index      int
	Serial     string
	TotalBytes uint64
	Configured bool
	Spare      bool
	Failed     bool
	Journal    bool
}

// IMSMVolumeInfo describes one RAID volume.
type IMSMVolumeInfo struct {
	Index     int
	Name      string
	UUID      string
	Level     string
	SizeBytes uint64
	Members   uint8
	MapState  uint8
	Degraded  bool
	Dirty     bool
}

// IMSMMember supplies one member disk image with its IMSM disk-table index.
type IMSMMember struct {
	DiskIndex uint8
	Source    ByteSource
}

// OpenIMSM parses one member disk's IMSM metadata.
func OpenIMSM(ctx context.Context, imagePath string, opts Options) (*IMSMContainer, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open IMSM member %s: %w", imagePath, err)
	}
	container, err := OpenIMSMSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse IMSM metadata %s: %w", imagePath, err)
	}
	container.path = imagePath
	container.close = raw
	return container, nil
}

// OpenIMSMSource parses one member disk's IMSM metadata over an existing byte
// source. The source is not closed by IMSMContainer.Close.
func OpenIMSMSource(ctx context.Context, src ByteSource, opts Options) (*IMSMContainer, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil IMSM member source", ErrInvalidArgument)
	}
	container, err := imsmcontainer.Parse(src)
	if err != nil {
		return nil, err
	}
	return &IMSMContainer{container: container}, nil
}

// Path returns the member image path.
func (c *IMSMContainer) Path() string { return c.path }

// Info returns the container-level metadata.
func (c *IMSMContainer) Info() IMSMInfo {
	info := IMSMInfo{
		ContainerUUID: c.container.ContainerUUID(),
		Version:       c.container.Version,
		FamilyNum:     c.container.FamilyNum,
		GenerationNum: c.container.GenerationNum,
		SectorSize:    c.container.SectorSize,
		Disks:         len(c.container.Disks),
		Volumes:       len(c.container.Volumes),
	}
	for i := range c.container.Volumes {
		if c.container.Volumes[i].IsDirty() {
			info.DirtyVolumes++
		}
	}
	return info
}

// Disks returns the member disk records.
func (c *IMSMContainer) Disks(ctx context.Context) ([]IMSMDiskInfo, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	out := make([]IMSMDiskInfo, 0, len(c.container.Disks))
	for index := range c.container.Disks {
		disk := &c.container.Disks[index]
		out = append(out, IMSMDiskInfo{
			Index: index, Serial: disk.Serial,
			TotalBytes: disk.TotalBytes(c.container.SectorSize),
			Configured: disk.Configured(), Spare: disk.Spare(),
			Failed: disk.Failed(), Journal: disk.Journal(),
		})
	}
	return out, nil
}

// Volumes returns the RAID volumes in the container.
func (c *IMSMContainer) Volumes(ctx context.Context) ([]IMSMVolumeInfo, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	out := make([]IMSMVolumeInfo, 0, len(c.container.Volumes))
	for index := range c.container.Volumes {
		volume := &c.container.Volumes[index]
		uuid, _ := c.container.VolumeUUID(index)
		out = append(out, IMSMVolumeInfo{
			Index: index, Name: volume.Name, UUID: uuid,
			Level:     volume.Map.Level().Label(),
			SizeBytes: volume.SizeBytes(c.container.SectorSize),
			Members:   volume.Map.NumMembers,
			MapState:  volume.Map.MapState,
			Degraded:  volume.Map.MapState == 2,
			Dirty:     volume.IsDirty(),
		})
	}
	return out, nil
}

// Assemble builds one RAID volume from the supplied member disks. RAID0/1/10
// are supported; RAID5 parity placement is refused explicitly (as in the
// reference reader), never served partially.
func (c *IMSMContainer) Assemble(ctx context.Context, volumeIndex int, members []IMSMMember) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	converted := make([]imsmcontainer.Member, 0, len(members))
	for _, member := range members {
		if member.Source == nil {
			return nil, fmt.Errorf("%w: IMSM member %d has no source", ErrInvalidArgument, member.DiskIndex)
		}
		converted = append(converted, imsmcontainer.Member{DiskIndex: member.DiskIndex, Source: member.Source})
	}
	id := source.ID(c.nextID.Add(1) + 1_000_000)
	array, err := imsmcontainer.Assemble(id, c.container, volumeIndex, converted)
	if err != nil {
		return nil, err
	}
	return array, nil
}

// Close releases the member image.
func (c *IMSMContainer) Close() error {
	if c.close == nil {
		return nil
	}
	err := c.close.Close()
	c.close = nil
	return err
}
