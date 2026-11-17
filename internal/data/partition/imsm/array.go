package imsm

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Member is one member image offered to an array.
//
// Source is the member device (usually a partition or a whole-disk image), not
// a data-area view: ArraySource adds the volume's recorded data offset.
// DiskIndex is the disk table position this image was bound to, by
// Container.BindDisk or by a caller that knows the drive.
type Member struct {
	DiskIndex uint8
	Source    source.ByteSource
}

// StripePlacement records where one slot's data area lives.
type StripePlacement struct {
	// Role is the slot in the volume's map.
	Role uint16
	// DiskIndex is the disk table index recorded for the slot.
	DiskIndex uint8
	// Serial is the serial the disk record carries (empty when none was
	// written).
	Serial string
	// DataOffset is the byte offset of the data area within the member image.
	DataOffset uint64
	// Rebuilding reports whether the map marks this slot out of sync.
	Rebuilding bool
}

type mappingKind uint8

const (
	mappingRaid0 mappingKind = iota
	mappingRaid10
	mappingMirror
)

// mapping places one volume's logical chunks onto its slots.
type mapping struct {
	kind    mappingKind
	members uint64
}

func (m mapping) copyCount() uint64 {
	if m.kind == mappingRaid10 {
		return 2
	}
	return 1
}

// copyPlacement returns the slot and member-chunk index of one copy of a
// logical chunk. A mirror has no stripe placement and never calls this.
func (m mapping) copyPlacement(chunkIndex, copy uint64) (uint64, uint64) {
	switch m.kind {
	case mappingRaid0:
		return chunkIndex % m.members, chunkIndex / m.members
	case mappingRaid10:
		virtual := chunkIndex*2 + copy
		return virtual % m.members, virtual / m.members
	default:
		return 0, 0
	}
}

// ArraySource is a RAID0, RAID1 or RAID10 volume reassembled from its members'
// data areas.
//
// The source's logical length is the geometry the volume records, not the
// partition length: RAID0 exposes component*members, RAID1 one whole copy, and
// RAID10 component*members/2.
type ArraySource struct {
	id             source.ID
	imageID        source.ImageID
	level          Level
	chunkBytes     uint64
	sectorSize     uint32
	dataOffset     uint64
	componentBytes uint64
	length         uint64
	mapping        mapping
	// Indexed by slot; nil means the image does not hold that role.
	members []source.ByteSource
	// Slots whose member is present and not marked out of sync; a read takes
	// the first usable copy.
	usable []bool
	// RAID1's chosen whole-copy member.
	mirror     source.ByteSource
	mirrorRole uint16
	haveMirror bool
	missing    []uint16
	placements []StripePlacement
	counters   source.Counters
}

// Assemble assembles the volume at volumeIndex from the member images supplied.
//
// container must be the parsed MPB of the members (they all agree), and each
// Member must name the disk table index it was bound to. A member may appear
// once; a disk the volume does not use is ignored. Missing members of a
// redundant volume are reported through MissingRoles; a striped volume without
// every member is refused rather than zero-filled.
func Assemble(id source.ID, container *Container, volumeIndex int, members []Member) (*ArraySource, error) {
	if volumeIndex < 0 || volumeIndex >= len(container.Volumes) {
		return nil, unsupportedf("container %s has %d volume(s); index %d does not exist",
			container.ContainerUUID(), len(container.Volumes), volumeIndex)
	}
	volume := &container.Volumes[volumeIndex]
	volumeMap := &volume.Map
	level := volumeMap.Level()
	switch level {
	case LevelRaid0, LevelRaid1, LevelRaid10:
	case LevelRaid5:
		return nil, unsupportedf("IMSM volume %s (container %s) is RAID5; its parity rotation and rebuild are not implemented, so no partial volume is exposed",
			volumeLabel(container, volumeIndex), container.ContainerUUID())
	case LevelRaid6:
		return nil, unsupportedf("IMSM volume %s (container %s) records RAID6, which IMSM does not define; refusing to place it",
			volumeLabel(container, volumeIndex), container.ContainerUUID())
	default:
		return nil, unsupportedf("IMSM volume %s (container %s) records RAID level code %d, which this build does not place",
			volumeLabel(container, volumeIndex), container.ContainerUUID(), level.Code())
	}

	sector := uint64(container.SectorSize)
	chunkBytes := volumeMap.ChunkBytes(container.SectorSize)
	if chunkBytes == 0 {
		return nil, unsupportedf("IMSM volume %s records a chunk size of 0; stripes cannot be placed",
			volumeLabel(container, volumeIndex))
	}
	if chunkBytes%sector != 0 {
		return nil, unsupportedf("IMSM volume %s records a chunk of %d bytes, not a whole number of %d-byte sectors",
			volumeLabel(container, volumeIndex), chunkBytes, sector)
	}
	memberCount := int(volumeMap.NumMembers)
	if memberCount == 0 {
		return nil, unsupportedf("IMSM volume %s records zero members", volumeLabel(container, volumeIndex))
	}
	if memberCount > len(container.Disks) {
		return nil, unsupportedf("IMSM volume %s records %d members but container %s has only %d disk record(s)",
			volumeLabel(container, volumeIndex), memberCount, container.ContainerUUID(), len(container.Disks))
	}
	if level == LevelRaid10 && memberCount%2 != 0 {
		return nil, unsupportedf("IMSM RAID10 volume %s records an odd member count (%d); the near-2 layout pairs members and cannot place this map",
			volumeLabel(container, volumeIndex), memberCount)
	}
	if volumeMap.MapState == mapStateUninit {
		return nil, unsupportedf("IMSM volume %s is recorded as uninitialized; its copies are not known to hold the array's data, so nothing is exposed",
			volumeLabel(container, volumeIndex))
	}
	if volumeMap.MapState == mapStateFailed {
		return nil, unsupportedf("IMSM volume %s is recorded as failed; refusing to expose a partial volume",
			volumeLabel(container, volumeIndex))
	}

	componentBytes, ok := volumeMap.ComponentBytes(container.SectorSize)
	if !ok {
		return nil, unsupportedf("IMSM volume %s is %d data stripes of %d blocks; the per-member byte count overflows",
			volumeLabel(container, volumeIndex), volumeMap.NumDataStripes, volumeMap.BlocksPerStrip)
	}
	if componentBytes == 0 {
		return nil, unsupportedf("IMSM volume %s records a data area of 0 bytes; its geometry cannot be placed",
			volumeLabel(container, volumeIndex))
	}
	dataOffset := volumeMap.DataOffsetBytes(container.SectorSize)
	dataEnd, ok := checkedAdd(dataOffset, componentBytes)
	if !ok {
		return nil, unsupportedf("IMSM volume %s data area starts at %d and overflows a byte count",
			volumeLabel(container, volumeIndex), dataOffset)
	}

	// The recorded volume size and the map must describe the same array.
	// mdadm allows one MiB of rounding per data member; beyond that the map's
	// stripe count is stale and a component size cannot be derived.
	dataMembers := volumeMap.DataMembers()
	if dataMembers == 0 {
		return nil, unsupportedf("IMSM volume %s records %d members, which leaves no data member",
			volumeLabel(container, volumeIndex), memberCount)
	}
	recordedBytes := volume.SizeBytes(container.SectorSize)
	calculated, ok := checkedMul(componentBytes, dataMembers)
	if !ok {
		return nil, unsupportedf("IMSM volume %s is %d bytes per member over %d data member(s), which overflows a byte count",
			volumeLabel(container, volumeIndex), componentBytes, dataMembers)
	}
	tolerance := satMul(satMul(sectorsPerMiB, 512), dataMembers)
	if absDiff(calculated, recordedBytes) > tolerance {
		return nil, unsupportedf("IMSM volume %s records %d bytes but its map describes %d bytes (%d data member(s) of %d); the stripe count is inconsistent with the volume size, so the map may be stale",
			volumeLabel(container, volumeIndex), recordedBytes, calculated, dataMembers, componentBytes)
	}

	byDisk := make([]*Member, len(container.Disks))
	for index := range members {
		member := &members[index]
		diskIndex := int(member.DiskIndex)
		if diskIndex >= len(container.Disks) {
			return nil, unsupportedf("a member image is bound to disk index %d, but container %s records only %d disk(s)",
				diskIndex, container.ContainerUUID(), len(container.Disks))
		}
		if byDisk[diskIndex] != nil {
			return nil, unsupportedf("two member images of container %s are bound to disk %d; the same disk cannot be two members",
				container.ContainerUUID(), diskIndex)
		}
		byDisk[diskIndex] = member
	}

	roles := make([]source.ByteSource, memberCount)
	usable := make([]bool, memberCount)
	placements := make([]StripePlacement, 0, memberCount)
	for slot := 0; slot < memberCount; slot++ {
		diskIndex, ok := volumeMap.SlotDisk(slot)
		if !ok {
			continue
		}
		if int(diskIndex) >= len(container.Disks) {
			return nil, source.NewCorrupt(uint64(DiskTableOffset+DiskBytes*int(diskIndex)),
				fmt.Sprintf("volume %s slot %d records disk index %d, but the container has only %d disk(s)",
					volumeLabel(container, volumeIndex), slot, diskIndex, len(container.Disks)))
		}
		disk := &container.Disks[diskIndex]
		member := byDisk[diskIndex]
		if member == nil || member.Source == nil {
			continue
		}
		if disk.Failed() || !disk.Configured() {
			continue
		}
		sourceLen := member.Source.Len()
		if sourceLen%sector != 0 || disk.TotalBlocks != sourceLen/sector {
			return nil, unsupportedf("the image bound to disk %d of container %s is %d bytes, but the disk record says %d sectors of %d bytes; they are not the same device",
				diskIndex, container.ContainerUUID(), sourceLen, disk.TotalBlocks, sector)
		}
		if sourceLen < dataEnd {
			return nil, unsupportedf("the image bound to disk %d of container %s is %d bytes, shorter than the volume's data area, which ends at %d",
				diskIndex, container.ContainerUUID(), sourceLen, dataEnd)
		}
		rebuilding := volumeMap.SlotRebuilding(slot)
		roles[slot] = member.Source
		usable[slot] = !rebuilding
		placements = append(placements, StripePlacement{
			Role:       uint16(slot),
			DiskIndex:  diskIndex,
			Serial:     disk.Serial,
			DataOffset: dataOffset,
			Rebuilding: rebuilding,
		})
	}

	missing := make([]uint16, 0, memberCount)
	for slot := 0; slot < memberCount; slot++ {
		if roles[slot] == nil {
			missing = append(missing, uint16(slot))
		}
	}

	var placement mapping
	switch level {
	case LevelRaid0:
		for slot := 0; slot < memberCount; slot++ {
			if roles[slot] == nil {
				return nil, unsupportedf("IMSM RAID0 volume %s is missing role %d; a striped volume cannot be read without every member, and one stripe alone is not the array",
					volumeLabel(container, volumeIndex), slot)
			}
		}
		for slot := 0; slot < memberCount; slot++ {
			if !usable[slot] {
				return nil, unsupportedf("role %d of IMSM RAID0 volume %s is marked out of sync; a striped volume with a rebuilding member has no copy to fall back on",
					slot, volumeLabel(container, volumeIndex))
			}
		}
		placement = mapping{kind: mappingRaid0, members: uint64(memberCount)}
	case LevelRaid1:
		anyUsable := false
		for slot := 0; slot < memberCount; slot++ {
			if usable[slot] {
				anyUsable = true
				break
			}
		}
		if !anyUsable {
			present := 0
			for slot := 0; slot < memberCount; slot++ {
				if roles[slot] != nil {
					present++
				}
			}
			return nil, unsupportedf("the image holds %d member(s) of IMSM RAID1 volume %s, but every one is missing, failed or marked out of sync; no whole copy is available",
				present, volumeLabel(container, volumeIndex))
		}
		placement = mapping{kind: mappingMirror}
	case LevelRaid10:
		placement = mapping{kind: mappingRaid10, members: uint64(memberCount)}
		// The copy pattern repeats every members/gcd(members,2) chunks; one
		// cycle proves whether any chunk lost both copies.
		period := uint64(memberCount) / gcd(uint64(memberCount), 2)
		for chunk := uint64(0); chunk < period; chunk++ {
			readable := false
			for copyIndex := uint64(0); copyIndex < 2; copyIndex++ {
				slot, _ := placement.copyPlacement(chunk, copyIndex)
				if usable[slot] {
					readable = true
					break
				}
			}
			if !readable {
				first, _ := placement.copyPlacement(chunk, 0)
				second, _ := placement.copyPlacement(chunk, 1)
				return nil, unsupportedf("IMSM RAID10 volume %s lost every copy of logical chunk %d (slots %d, %d); a chunk is read from a surviving copy, but this one has none",
					volumeLabel(container, volumeIndex), chunk, first, second)
			}
		}
	}

	var length uint64
	switch level {
	case LevelRaid0:
		length, ok = checkedMul(componentBytes, uint64(memberCount))
	case LevelRaid1:
		length = componentBytes
	case LevelRaid10:
		chunks := componentBytes / chunkBytes
		chunks, ok = checkedMul(chunks, uint64(memberCount))
		if ok {
			chunks /= 2
			length, ok = checkedMul(chunks, chunkBytes)
		}
	}
	if !ok {
		return nil, unsupportedf("IMSM volume %s is %d members of %d bytes, which overflows a byte count",
			volumeLabel(container, volumeIndex), memberCount, componentBytes)
	}
	if length == 0 {
		return nil, unsupportedf("IMSM volume %s has no whole chunk to expose", volumeLabel(container, volumeIndex))
	}

	array := &ArraySource{
		id:             id,
		level:          level,
		chunkBytes:     chunkBytes,
		sectorSize:     container.SectorSize,
		dataOffset:     dataOffset,
		componentBytes: componentBytes,
		length:         length,
		mapping:        placement,
		members:        roles,
		usable:         usable,
		missing:        missing,
		placements:     placements,
	}
	if level == LevelRaid1 {
		for slot := 0; slot < memberCount; slot++ {
			if usable[slot] {
				array.mirrorRole = uint16(slot)
				array.haveMirror = true
				array.mirror = roles[slot]
				break
			}
		}
	}
	if array.mirror != nil {
		array.imageID = array.mirror.ImageID()
	} else {
		for _, role := range roles {
			if role != nil {
				array.imageID = role.ImageID()
				break
			}
		}
	}
	return array, nil
}

// MissingRoles returns the slots the image does not hold, in ascending order.
func (a *ArraySource) MissingRoles() []uint16 { return a.missing }

// Placements returns the slots this volume reads through, in slot order. An
// out-of-sync slot is included; Rebuilding says so.
func (a *ArraySource) Placements() []StripePlacement { return a.placements }

// MirrorRole returns the role whose data area a RAID1 volume reads as its
// whole copy.
func (a *ArraySource) MirrorRole() (uint16, bool) { return a.mirrorRole, a.haveMirror }

// ChunkBytes returns the chunk size in bytes.
func (a *ArraySource) ChunkBytes() uint64 { return a.chunkBytes }

// Level returns the volume's RAID level.
func (a *ArraySource) Level() Level { return a.level }

// DataOffset returns the byte offset of every member's data area within its
// image.
func (a *ArraySource) DataOffset() uint64 { return a.dataOffset }

// ComponentBytes returns the bytes each member devotes to the volume.
func (a *ArraySource) ComponentBytes() uint64 { return a.componentBytes }

func (a *ArraySource) bounds(offset, length uint64) error {
	if offset > a.length || length > a.length-offset {
		return source.NewOutOfRange(offset, length, a.length)
	}
	return nil
}

func (a *ArraySource) readInto(offset uint64, buf []byte, lossy bool) (int, error) {
	if len(buf) == 0 {
		a.counters.AddRead(0)
		return 0, nil
	}
	if offset >= a.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), a.length)
	}
	want := int(minU64(a.length-offset, uint64(len(buf))))
	if a.mapping.kind == mappingMirror {
		if a.mirror == nil {
			return 0, source.NewCorrupt(offset, "the RAID1 volume has no usable whole-copy member")
		}
		var n int
		var err error
		if lossy {
			n, err = a.mirror.ReadAtLossy(a.dataOffset+offset, buf[:want])
		} else {
			n, err = a.mirror.ReadAt(a.dataOffset+offset, buf[:want])
		}
		if n > 0 {
			a.counters.AddRead(n)
		}
		return n, err
	}

	done := 0
	err := a.forEachPiece(offset, offset+uint64(want), func(piece arrayPiece) (bool, error) {
		if piece.length > uint64(len(buf)-done) {
			return true, source.NewCorrupt(piece.memberOffset,
				fmt.Sprintf("slot %d maps %d bytes past the requested buffer", piece.slot, piece.length))
		}
		length := int(piece.length)
		target := buf[done : done+length]
		member := a.members[piece.slot]
		if member == nil {
			return true, source.NewCorrupt(piece.memberOffset,
				fmt.Sprintf("slot %d is missing, so the stripe cannot be read", piece.slot))
		}
		var n int
		var err error
		if lossy {
			n, err = member.ReadAtLossy(piece.memberOffset, target)
		} else {
			n, err = member.ReadAt(piece.memberOffset, target)
		}
		done += n
		if err != nil {
			return true, err
		}
		if n < length {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return 0, err
	}
	a.counters.AddRead(done)
	return done, nil
}

type arrayPiece struct {
	slot         int
	memberOffset uint64
	length       uint64
}

// forEachPiece walks one contiguous run of logical bytes on one member at a
// time. For RAID10 it chooses the first usable copy of each chunk.
func (a *ArraySource) forEachPiece(from, to uint64, fn func(arrayPiece) (bool, error)) error {
	at := from
	for at < to {
		index := at / a.chunkBytes
		within := at % a.chunkBytes
		length := a.chunkBytes - within
		if length > to-at {
			length = to - at
		}
		slot, memberChunk := a.mapping.copyPlacement(index, 0)
		if a.mapping.kind == mappingRaid10 {
			found := false
			for copyIndex := uint64(0); copyIndex < a.mapping.copyCount(); copyIndex++ {
				candidate, chunk := a.mapping.copyPlacement(index, copyIndex)
				if candidate < uint64(len(a.members)) && a.members[candidate] != nil && a.usable[candidate] {
					slot, memberChunk, found = candidate, chunk, true
					break
				}
			}
			if !found {
				return unsupportedf("logical chunk %d has no surviving usable copy", index)
			}
		}
		if slot >= uint64(len(a.members)) {
			return unsupportedf("logical chunk %d maps to slot %d outside the volume", index, slot)
		}
		piece := arrayPiece{
			slot:         int(slot),
			memberOffset: a.dataOffset + memberChunk*a.chunkBytes + within,
			length:       length,
		}
		at += length
		stop, err := fn(piece)
		if err != nil || stop {
			return err
		}
	}
	return nil
}

// ReadAt implements source.ByteSource.
func (a *ArraySource) ReadAt(offset uint64, buf []byte) (int, error) {
	return a.readInto(offset, buf, false)
}

// ReadAtLossy implements source.ByteSource.
func (a *ArraySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return a.readInto(offset, buf, true)
}

// ExtentsInto implements source.ByteSource.
func (a *ArraySource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := a.bounds(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	if a.mapping.kind == mappingMirror {
		if a.mirror == nil {
			return out, source.NewCorrupt(offset, "the RAID1 volume has no usable whole-copy member")
		}
		return a.mirror.ExtentsInto(a.dataOffset+offset, length, out)
	}
	err := a.forEachPiece(offset, offset+length, func(piece arrayPiece) (bool, error) {
		member := a.members[piece.slot]
		if member == nil {
			return true, source.NewCorrupt(piece.memberOffset,
				fmt.Sprintf("slot %d is missing, so the stripe cannot be mapped", piece.slot))
		}
		out = append(out, source.ParentRange{
			Parent:       member.SourceID(),
			ParentOffset: piece.memberOffset,
			Len:          piece.length,
			Kind:         source.RangeData,
		})
		return false, nil
	})
	return out, err
}

// Extents returns the complete translation for [offset, offset+length).
func (a *ArraySource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return a.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (a *ArraySource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := a.bounds(offset, length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	if a.mapping.kind == mappingMirror {
		if a.mirror == nil {
			return nil, source.NewCorrupt(offset, "the RAID1 volume has no usable whole-copy member")
		}
		return a.mirror.MapToImage(a.dataOffset+offset, length)
	}
	var out []source.ImageRange
	err := a.forEachPiece(offset, offset+length, func(piece arrayPiece) (bool, error) {
		member := a.members[piece.slot]
		if member == nil {
			return true, source.NewCorrupt(piece.memberOffset,
				fmt.Sprintf("slot %d is missing, so the stripe cannot be mapped", piece.slot))
		}
		mapped, err := member.MapToImage(piece.memberOffset, piece.length)
		if err != nil {
			return true, err
		}
		out = append(out, mapped...)
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (a *ArraySource) Stats() source.Stats { return a.counters.Snapshot() }

// SourceID implements source.ByteSource.
func (a *ArraySource) SourceID() source.ID { return a.id }

// Len implements source.ByteSource.
func (a *ArraySource) Len() uint64 { return a.length }

// ImageID implements source.ByteSource.
func (a *ArraySource) ImageID() source.ImageID { return a.imageID }

// SectorSize implements source.ByteSource.
func (a *ArraySource) SectorSize() uint32 { return a.sectorSize }

// IsEmpty implements source.ByteSource.
func (a *ArraySource) IsEmpty() bool { return a.length == 0 }

var _ source.ByteSource = (*ArraySource)(nil)

func volumeLabel(container *Container, index int) string {
	volume := &container.Volumes[index]
	if volume.Name == "" {
		return fmt.Sprintf("#%d", index)
	}
	return fmt.Sprintf("`%s` (#%d)", volume.Name, index)
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
