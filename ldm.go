package forensic

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/partition/ldm"
	"github.com/laenix/ewfgo/internal/data/source"
)

// LDM is a parsed Windows Logical Disk Manager database from one dynamic disk.
// The database describes the whole disk group; assembly needs the member disk
// images it names.
type LDM struct {
	path  string
	db    *ldm.Database
	src   ByteSource
	close io.Closer

	nextID atomic.Uint64
}

// LDMInfo summarizes the database.
type LDMInfo struct {
	DiskGUID         string
	DiskGroup        string
	DiskGroupGUID    string
	Version          string
	VMDBVersion      string
	BytesPerBlock    uint32
	Clean            bool
	Disks            int
	Volumes          int
	Partitions       int
	RecordsSkipped   int
	MalformedRecords int
}

// LDMDisk describes one dynamic disk.
type LDMDisk struct {
	ID         uint64
	Name       string
	GUID       string
	ThisDisk   bool
	Partitions int
}

// LDMVolume describes one dynamic volume.
type LDMVolume struct {
	ID            uint64
	Name          string
	Type          string
	State         string
	Layout        string
	GUID          string
	SizeBytes     uint64
	DriveHint     string
	PartitionType *uint8
	SpansDisks    bool
}

// LDMMember supplies one member disk image with its own parsed LDM database.
type LDMMember struct {
	Source   ByteSource
	Database *LDM
}

// OpenLDM parses one dynamic disk's LDM database. A disk with no LDM database
// returns ErrUnsupported.
func OpenLDM(ctx context.Context, imagePath string, opts Options) (*LDM, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open LDM disk %s: %w", imagePath, err)
	}
	database, err := OpenLDMSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse LDM database %s: %w", imagePath, err)
	}
	database.path = imagePath
	database.close = raw
	return database, nil
}

// OpenLDMSource parses one dynamic disk's LDM database over an existing byte
// source. The source is not closed by LDM.Close.
func OpenLDMSource(ctx context.Context, src ByteSource, opts Options) (*LDM, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil LDM source", ErrInvalidArgument)
	}
	db, err := ldm.Parse(src)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, fmt.Errorf("%w: source does not carry an LDM database", ErrUnsupported)
	}
	return &LDM{db: db, src: src}, nil
}

// Path returns the disk image path.
func (l *LDM) Path() string { return l.path }

// Info returns the database summary.
func (l *LDM) Info() LDMInfo {
	info := LDMInfo{
		Version:          fmt.Sprintf("%d.%d", l.db.Version.Major, l.db.Version.Minor),
		VMDBVersion:      fmt.Sprintf("%d.%d", l.db.VMDBVersion.Major, l.db.VMDBVersion.Minor),
		BytesPerBlock:    l.db.BytesPerBlock,
		Clean:            l.db.Clean,
		Disks:            len(l.db.Disks()),
		Volumes:          len(l.db.Volumes()),
		Partitions:       len(l.db.Partitions()),
		RecordsSkipped:   l.db.RecordsSkipped,
		MalformedRecords: l.db.MalformedRecords,
	}
	if l.db.DiskGUID != nil {
		info.DiskGUID = *l.db.DiskGUID
	}
	if l.db.DiskGroup != nil {
		info.DiskGroup = *l.db.DiskGroup
	}
	if l.db.DiskGroupGUID != nil {
		info.DiskGroupGUID = *l.db.DiskGroupGUID
	}
	return info
}

// Disks returns the disks the database knows.
func (l *LDM) Disks(ctx context.Context) ([]LDMDisk, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw := l.db.Disks()
	out := make([]LDMDisk, 0, len(raw))
	for _, disk := range raw {
		entry := LDMDisk{ID: disk.ID, ThisDisk: disk.ThisDisk, Partitions: len(disk.Partitions)}
		if disk.Name != nil {
			entry.Name = *disk.Name
		}
		if disk.GUID != nil {
			entry.GUID = *disk.GUID
		}
		out = append(out, entry)
	}
	return out, nil
}

// Volumes returns the dynamic volumes.
func (l *LDM) Volumes(ctx context.Context) ([]LDMVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw := l.db.Volumes()
	out := make([]LDMVolume, 0, len(raw))
	for _, volume := range raw {
		entry := LDMVolume{
			ID: volume.ID, Layout: volume.Layout.Label(),
			SpansDisks: volume.SpansDisks,
		}
		if volume.Name != nil {
			entry.Name = *volume.Name
		}
		if volume.VolumeType != nil {
			entry.Type = *volume.VolumeType
		}
		if volume.State != nil {
			entry.State = *volume.State
		}
		if volume.GUID != nil {
			entry.GUID = *volume.GUID
		}
		if volume.DriveHint != nil {
			entry.DriveHint = *volume.DriveHint
		}
		if volume.SizeSectors != nil {
			entry.SizeBytes = *volume.SizeSectors * uint64(l.db.BytesPerBlock)
		}
		entry.PartitionType = volume.PartitionType
		out = append(out, entry)
	}
	return out, nil
}

// findVolume returns the database's volume with the given object id.
func (l *LDM) findVolume(id uint64) (*ldm.Volume, error) {
	for _, volume := range l.db.Volumes() {
		if volume.ID == id {
			return volume, nil
		}
	}
	return nil, fmt.Errorf("%w: LDM database has no volume %d", ErrInvalidArgument, id)
}

// OpenVolume opens a concatenated volume whose extents live on this disk.
// Spanning, striped, mirrored and RAID-5 volumes need Assemble with every
// member disk.
func (l *LDM) OpenVolume(ctx context.Context, volumeID uint64) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	volume, err := l.findVolume(volumeID)
	if err != nil {
		return nil, err
	}
	id := source.ID(l.nextID.Add(1) + 1_000_000)
	assembled, err := ldm.OpenVolume(id, l.src, volume)
	if err != nil {
		return nil, err
	}
	return assembled, nil
}

// Assemble builds a dynamic volume from the supplied member disks.
func (l *LDM) Assemble(ctx context.Context, volumeID uint64, members []LDMMember) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	volume, err := l.findVolume(volumeID)
	if err != nil {
		return nil, err
	}
	converted := make([]ldm.DiskMember, 0, len(members))
	for _, member := range members {
		if member.Source == nil {
			return nil, fmt.Errorf("%w: LDM member has no source", ErrInvalidArgument)
		}
		if member.Database == nil {
			return nil, fmt.Errorf("%w: LDM member has no parsed database", ErrInvalidArgument)
		}
		converted = append(converted, ldm.NewDiskMember(member.Source, member.Database.db))
	}
	id := source.ID(l.nextID.Add(1) + 1_000_000)
	assembled, err := ldm.AssembleVolume(id, l.db, volume, converted)
	if err != nil {
		return nil, err
	}
	return assembled, nil
}

// Close releases the disk image.
func (l *LDM) Close() error {
	if l.close == nil {
		return nil
	}
	err := l.close.Close()
	l.close = nil
	return err
}
