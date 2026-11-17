package forensic

import (
	"context"
	"fmt"
	"sort"

	"github.com/laenix/ewfgo/internal/data/filesystems/probe"
	"github.com/laenix/ewfgo/internal/data/lvm"
	"github.com/laenix/ewfgo/internal/data/partition/mdraid"
	"github.com/laenix/ewfgo/internal/data/source"
)

// VolumeMember records one physical member of an assembled volume: the
// partition node it comes from, the data window used inside that partition and
// the role the volume manager assigned to it.
type VolumeMember struct {
	PartitionIndex int
	NodeID         source.ID
	Offset         uint64
	Length         uint64
	Role           uint16
	MemberUUID     string
}

// Volume is a logical volume assembled above partitions: a Linux mdraid array
// or an LVM logical volume. Volumes with missing members are still reported,
// with Readable false and Problem naming the missing piece.
type Volume struct {
	name     string
	kind     string
	label    string
	fsFormat probe.Kind
	src      ByteSource
	issue    string
	sector   uint32
	limits   Limits
	nodeID   source.ID
	members  []VolumeMember
}

// Name returns the volume name (md array name or "vg/lv").
func (v *Volume) Name() string { return v.name }

// Kind returns the assembly kind, for example "mdraid RAID5" or
// "LVM2 logical volume".
func (v *Volume) Kind() string { return v.kind }

// Source returns the assembled volume's byte source. It is nil when the
// volume cannot be assembled from this image.
func (v *Volume) Source() ByteSource { return v.src }

// Format returns the detected filesystem label on the volume, or "unknown".
func (v *Volume) Format() string { return v.label }

// SectorSize returns the sector size used for filesystem geometry.
func (v *Volume) SectorSize() uint32 { return v.sector }

// Length returns the assembled volume's byte length; 0 when unreadable.
func (v *Volume) Length() uint64 {
	if v.src == nil {
		return 0
	}
	return v.src.Len()
}

// Encrypted reports whether the volume carries an encryption layer.
func (v *Volume) Encrypted() bool { return v.fsFormat.Encrypted() }

// Encryption parses the encryption metadata of an encrypted assembled volume.
// It returns nil, nil when the volume carries no recognised encryption header.
func (v *Volume) Encryption(ctx context.Context) (*EncryptionInfo, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if v.src == nil {
		return nil, fmt.Errorf("%w: volume %s cannot be assembled: %s", ErrUnsupported, v.name, v.issue)
	}
	return readEncryption(v.src, v.fsFormat)
}

// NodeID returns the volume's provenance node; 0 for an unreadable volume.
func (v *Volume) NodeID() source.ID { return v.nodeID }

// Members returns the physical members backing the volume.
func (v *Volume) Members() []VolumeMember { return append([]VolumeMember(nil), v.members...) }

// Readable reports whether every member needed to read the volume is present.
func (v *Volume) Readable() bool { return v.src != nil }

// Problem explains why an unreadable volume cannot be assembled; empty when
// the volume is readable.
func (v *Volume) Problem() string { return v.issue }

// OpenFilesystem opens the filesystem detected on the volume.
func (v *Volume) OpenFilesystem(ctx context.Context) (FileSystem, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if v.src == nil {
		return nil, fmt.Errorf("%w: volume %s cannot be assembled: %s", ErrUnsupported, v.name, v.issue)
	}
	return openFilesystem(v.src, v.fsFormat, v.sector, v.limits)
}

// Volumes assembles Linux mdraid arrays and LVM logical volumes from the
// image's partitions. Devices that are plain filesystems are not reported here;
// use Partitions for those.
func (i *Image) Volumes(ctx context.Context) ([]*Volume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	i.volumeOnce.Do(func() {
		i.volumes, i.volumeErr = i.assembleVolumes(ctx)
	})
	return i.volumes, i.volumeErr
}

func (i *Image) allocID() source.ID {
	i.idMu.Lock()
	defer i.idMu.Unlock()
	if i.nextID == 0 {
		if i.report != nil && i.report.NextID != 0 {
			i.nextID = i.report.NextID
		} else {
			i.nextID = i.source.SourceID() + 1
		}
	}
	id := i.nextID
	i.nextID++
	return id
}

type mdMember struct {
	sb     *mdraid.Superblock
	part   *Partition
	offset uint64
	length uint64
	window source.ByteSource
}

type lvmMember struct {
	lvmInfo *lvm.LVM
	part    *Partition
	uuid    string
}

func (i *Image) assembleVolumes(ctx context.Context) ([]*Volume, error) {
	report, err := i.analysis(ctx)
	if err != nil {
		return nil, err
	}
	sector := i.SectorSize()
	partitions, err := i.Partitions(ctx)
	if err != nil {
		return nil, err
	}
	if len(partitions) == 0 {
		// A bare disk may still be an mdraid member (its superblock is not a
		// filesystem signature). Scan the whole image as one candidate.
		partitions = []*Partition{{
			index: 0, typeName: "whole volume", whole: true,
			length: i.source.Len(), nodeID: i.source.SourceID(),
			format: report.VolumeFormat, label: report.VolumeFormat.Label(),
			src: i.source, sector: sector, limits: i.opts.Limits,
		}}
	}

	var (
		volumes  []*Volume
		mdGroups = map[string][]*mdMember{}
		lvmGroup = map[string][]*lvmMember{}
	)

	for _, p := range partitions {
		// Probe hits are hints, not gates: mdraid 1.0/0.90 superblocks live at
		// the end of a member and a bare disk has no partition table at all.
		sb, mdErr := mdraid.Parse(p.src)
		if mdErr != nil {
			volumes = append(volumes, &Volume{
				name:   fmt.Sprintf("partition %d", p.Index()),
				kind:   "mdraid member",
				issue:  mdErr.Error(),
				sector: sector,
				limits: i.opts.Limits,
			})
		} else if sb != nil {
			mdGroups[sb.ArrayUUID()] = append(mdGroups[sb.ArrayUUID()], &mdMember{sb: sb, part: p})
		}

		if p.format == probe.LVM2 {
			info, lvmErr := lvm.Read(p.src)
			if lvmErr != nil {
				volumes = append(volumes, &Volume{
					name:   fmt.Sprintf("partition %d", p.Index()),
					kind:   "LVM2 physical volume",
					issue:  lvmErr.Error(),
					sector: sector,
					limits: i.opts.Limits,
				})
			} else if info != nil {
				pv := &lvmMember{lvmInfo: info, part: p, uuid: info.Label.PVUUID}
				if info.Group != nil {
					key := info.Group.UUID
					if key == "" {
						key = info.Group.Name
					}
					lvmGroup[key] = append(lvmGroup[key], pv)
				}
			}
		}
	}

	// mdraid arrays.
	mdNames := make([]string, 0, len(mdGroups))
	for key := range mdGroups {
		mdNames = append(mdNames, key)
	}
	sort.Strings(mdNames)
	for _, key := range mdNames {
		volume := i.assembleMDRaid(key, mdGroups[key], sector)
		volumes = append(volumes, volume)
	}

	// LVM volume groups.
	lvmKeys := make([]string, 0, len(lvmGroup))
	for key := range lvmGroup {
		lvmKeys = append(lvmKeys, key)
	}
	sort.Strings(lvmKeys)
	for _, key := range lvmKeys {
		volumes = append(volumes, i.assembleLVM(key, lvmGroup[key], sector)...)
	}

	if err := report.Graph.Validate(); err != nil {
		return nil, fmt.Errorf("volume graph: %w", err)
	}
	return volumes, nil
}

func (i *Image) assembleMDRaid(arrayUUID string, members []*mdMember, sector uint32) *Volume {
	name := arrayUUID
	if members[0].sb.SetName != "" {
		name = members[0].sb.SetName
	}
	kind := "mdraid " + members[0].sb.LevelName()
	volume := &Volume{name: name, kind: kind, label: "unknown", sector: sector, limits: i.opts.Limits}

	var (
		arrayMembers []mdraid.ArrayMember
		refs         []source.ParentRef
		infos        []VolumeMember
	)
	for _, member := range members {
		off := member.sb.DataOffsetBytes()
		if off > member.part.Length() {
			volume.issue = fmt.Sprintf("member on partition %d declares data offset %d beyond its %d bytes",
				member.part.Index(), off, member.part.Length())
			return volume
		}
		length := member.sb.DataSizeBytes()
		if length == 0 || off+length > member.part.Length() {
			length = member.part.Length() - off
		}
		if length == 0 {
			volume.issue = fmt.Sprintf("member on partition %d has an empty data area", member.part.Index())
			return volume
		}
		windowID := i.allocID()
		window, err := source.NewSubSource(windowID, member.part.src, off, length)
		if err != nil {
			volume.issue = err.Error()
			return volume
		}
		arrayMembers = append(arrayMembers, mdraid.ArrayMember{Superblock: member.sb, Data: window})
		refs = append(refs, source.ParentRef{Parent: member.part.NodeID(), OffsetInParent: off, Len: length})
		role, _ := member.sb.Role()
		infos = append(infos, VolumeMember{
			PartitionIndex: member.part.Index(), NodeID: member.part.NodeID(),
			Offset: off, Length: length, Role: role, MemberUUID: member.sb.MemberUUID(),
		})
	}

	id := i.allocID()
	var (
		assembled source.ByteSource
		err       error
	)
	switch members[0].sb.Level {
	case 0:
		assembled, err = mdraid.Raid0(id, arrayMembers)
	case 10:
		assembled, err = mdraid.Raid10(id, arrayMembers)
	case 4, 5, 6:
		assembled, err = mdraid.Raid456(id, arrayMembers)
	default:
		err = fmt.Errorf("%w: mdraid level %s", ErrUnsupported, members[0].sb.LevelName())
	}
	if err != nil {
		volume.issue = err.Error()
		return volume
	}

	volume.src = assembled
	volume.members = infos
	volume.nodeID = id
	i.addVolumeNode(volume, refs)
	return volume
}

func (i *Image) assembleLVM(key string, members []*lvmMember, sector uint32) []*Volume {
	group := members[0].lvmInfo.Group
	if group == nil {
		return nil
	}
	// Merge: every member must agree on group identity; OpenInGroup validates
	// the per-stripe PV UUIDs and refuses anything missing.
	pvs := make([]lvm.PhysicalVolumeSource, 0, len(members))
	var refs []source.ParentRef
	for _, member := range members {
		pvs = append(pvs, lvm.PhysicalVolumeSource{UUID: member.uuid, Source: member.part.src})
		refs = append(refs, source.ParentRef{Parent: member.part.NodeID(), OffsetInParent: 0, Len: member.part.Length()})
	}

	groupName := group.Name
	if groupName == "" {
		groupName = key
	}
	volumes := make([]*Volume, 0, len(group.LogicalVolumes))
	for _, logical := range group.LogicalVolumes {
		name := groupName + "/" + logical.Name
		volume := &Volume{
			name: name, kind: "LVM2 logical volume", label: "unknown", sector: sector, limits: i.opts.Limits,
		}
		id := i.allocID()
		assembled, err := lvm.OpenInGroup(id, group, pvs, logical.Name)
		if err != nil {
			volume.issue = err.Error()
			volumes = append(volumes, volume)
			continue
		}
		volume.src = assembled
		volume.nodeID = id
		for _, member := range members {
			volume.members = append(volume.members, VolumeMember{
				PartitionIndex: member.part.Index(), NodeID: member.part.NodeID(),
				Length: member.part.Length(), MemberUUID: member.uuid,
			})
		}
		i.addVolumeNode(volume, refs)
		volumes = append(volumes, volume)
	}
	return volumes
}

// addVolumeNode records a readable assembled volume in the provenance graph,
// probes its filesystem and adds a filesystem node when one is detected.
func (i *Image) addVolumeNode(v *Volume, refs []source.ParentRef) {
	if i.report == nil || i.report.Graph == nil {
		return
	}
	node := source.NewSourceNode(v.nodeID, source.SourceVolume, v.src.Len(), refs, v.kind+" "+v.name)
	if err := i.report.Graph.AddNode(node, v.src); err != nil {
		v.issue = err.Error()
		v.src = nil
		v.nodeID = 0
		return
	}
	format, err := probe.Detect(v.src)
	if err != nil {
		v.issue = err.Error()
		return
	}
	v.fsFormat = format
	v.label = volumeLabel(v.src, format)
	if format == probe.None || format.Encrypted() {
		return
	}
	fsID := i.allocID()
	fsNode := source.NewSourceNode(fsID, source.SourceFileSystem, v.src.Len(),
		[]source.ParentRef{{Parent: v.nodeID, OffsetInParent: 0, Len: v.src.Len()}}, v.label)
	if err := i.report.Graph.AddNode(fsNode, nil); err != nil {
		v.issue = err.Error()
	}
}
