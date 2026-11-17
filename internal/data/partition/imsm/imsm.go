// Package imsm decodes Intel Matrix RAID / Rapid Storage Technology firmware
// metadata (IMSM) and reassembles its volumes. It is a pure-Go port of
// forensic-core's partition/imsm.rs.
//
// Every member of an IMSM container stores an identical Metadata Parameter
// Block (MPB) at the end of the device: the signature and header occupy the
// second-to-last sector, any further MPB sectors precede it in ascending
// physical order, and the final sector is the migration record. The logical
// MPB order is therefore [anchor][preceding sectors], which is the order the
// checksum covers and the order this package reassembles before parsing.
//
// The device's logical sector size (512 or 4096) is not recorded in the MPB,
// so Parse tries both anchors (deviceLen-1024 and deviceLen-8192). A signature
// at exactly one anchor is a claim decided by its checksum. A signature at both
// with both checksums valid is refused as ambiguous: guessing could misplace
// the volume table.
//
// The parser validates the MPB size range, the disk and device table bounds,
// every recorded disk index, the checksum over the MPB's 32-bit words, and the
// metadata version. Corrupt, truncated and unsupported structures return
// errors wrapping source.ErrCorrupt, source.ErrUnexpectedEOF and
// source.ErrUnsupported; nothing is zero-filled or guessed.
//
// Volumes are exposed as source.ByteSource. RAID0, RAID1 and RAID10 are
// assembled from member data windows. RAID5 is recognised but not assembled:
// its parity rotation and rebuild need the kernel's raid5_compute_sector and
// P/Q arithmetic, and the reference implementation deliberately refuses it.
// RAID6 is not an IMSM level. Those branches are reported as unsupported by
// name rather than exposed as a partial volume.
package imsm

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// MPBSignature is mdadm's MPB_SIGNATURE; it is exactly 24 bytes.
	MPBSignature = "Intel Raid ISM Cfg Sig. "
	// MPBSigLen is the signature length, mdadm's MPB_SIG_LEN.
	MPBSigLen = 24
	// MPBMinBytes is sizeof(struct imsm_super): header plus one disk record.
	MPBMinBytes = 264
	// MPBMaxSectors is MPB_SECTOR_CNT, the largest MPB mdadm accepts.
	MPBMaxSectors = 2210
	// DiskTableOffset is offsetof(struct imsm_super, disk[0]).
	DiskTableOffset = 0xD8
	// DiskBytes is sizeof(struct imsm_disk).
	DiskBytes = 48
	// DevMapOffset is offsetof(struct imsm_dev, vol.map[0]).
	DevMapOffset = 0x70
	// MapOrdOffset is offsetof(struct imsm_map, disk_ord_tbl[0]).
	MapOrdOffset = 48
	// MapBaseBytes is sizeof(struct imsm_map) including disk_ord_tbl[0].
	MapBaseBytes = 52
	// DevBaseBytes is sizeof(struct imsm_dev) with one member and no second map.
	DevBaseBytes = 164
	// Attr2TBDisk is MPB_ATTRIB_2TB_DISK: the high size words are valid.
	Attr2TBDisk uint32 = 0x04000000
	// DiskFlagSpare marks a spare disk record.
	DiskFlagSpare uint32 = 0x01
	// DiskFlagConfigured marks a configured data member.
	DiskFlagConfigured uint32 = 0x02
	// DiskFlagFailed marks a failed disk record.
	DiskFlagFailed uint32 = 0x04
	// DiskFlagJournal marks a journal disk record.
	DiskFlagJournal uint32 = 0x02000000
)

const (
	ordRebuild     uint32 = 1 << 24
	ordIndexMask   uint32 = 0x00FFFFFF
	ordUnrecorded  uint32 = ordIndexMask
	sectorsPerMiB  uint64 = 1 << 11
	maxIntValue           = int(^uint(0) >> 1)
	mapStateUninit uint8  = 1
	mapStateFailed uint8  = 3
)

// Errors. Callers test them with errors.Is.
var (
	// ErrUnsupported means the metadata names a feature this build cannot place.
	ErrUnsupported = source.ErrUnsupported
	// ErrCorrupt means the bytes exist but are not valid IMSM metadata.
	ErrCorrupt = source.ErrCorrupt
	// ErrUnexpectedEOF means a table or structure is truncated.
	ErrUnexpectedEOF = source.ErrUnexpectedEOF
)

var sectorSizes = [...]uint32{512, 4096}

// Level is the effective RAID level of a volume map. An unknown map level
// carries its raw code, which Code returns.
type Level uint8

const (
	// LevelRaid0 is a striped volume with no redundancy.
	LevelRaid0 Level = 0
	// LevelRaid1 is a two-member mirror.
	LevelRaid1 Level = 1
	// LevelRaid5 is a parity volume; recognised but not assembled.
	LevelRaid5 Level = 5
	// LevelRaid6 is not defined by IMSM; recognised for reporting only.
	LevelRaid6 Level = 6
	// LevelRaid10 is IMSM's near-2/far-1 layout.
	LevelRaid10 Level = 10
)

// Label returns the level name the kernel uses.
func (l Level) Label() string {
	switch l {
	case LevelRaid0:
		return "raid0"
	case LevelRaid1:
		return "raid1"
	case LevelRaid5:
		return "raid5"
	case LevelRaid6:
		return "raid6"
	case LevelRaid10:
		return "raid10"
	default:
		return "unknown"
	}
}

// Code returns the level code as the MPB stores it.
func (l Level) Code() uint8 { return uint8(l) }

// Disk is one physical disk in the container's disk table.
type Disk struct {
	// Serial is the 16-byte serial, decoded as text.
	Serial string
	// SCSIID is the host SCSI identifier mdadm stored; it is not a
	// self-identification.
	SCSIID uint32
	// Status holds DiskFlagSpare, DiskFlagConfigured, DiskFlagFailed and
	// DiskFlagJournal bits.
	Status uint32
	// OwnerCfgNum is the container configuration that owns this disk.
	OwnerCfgNum uint32
	// TotalBlocks is the device size in metadata sectors.
	TotalBlocks uint64
}

// Configured reports the configured data-member bit.
func (d *Disk) Configured() bool { return d.Status&DiskFlagConfigured != 0 }

// Failed reports the failed bit.
func (d *Disk) Failed() bool { return d.Status&DiskFlagFailed != 0 }

// Spare reports the spare bit.
func (d *Disk) Spare() bool { return d.Status&DiskFlagSpare != 0 }

// Journal reports the journal bit.
func (d *Disk) Journal() bool { return d.Status&DiskFlagJournal != 0 }

// TotalBytes returns the recorded device size in bytes, saturating on overflow.
func (d *Disk) TotalBytes(sectorSize uint32) uint64 {
	return satMul(d.TotalBlocks, uint64(sectorSize))
}

// Map is one volume map: the placement and geometry of a volume on its members.
type Map struct {
	// PBAOfLBA0 is the data-area start in metadata sectors.
	PBAOfLBA0 uint64
	// BlocksPerMember is recorded but not used for placement, matching mdadm.
	BlocksPerMember uint64
	// NumDataStripes is the number of data stripes per member.
	NumDataStripes uint64
	// BlocksPerStrip is the chunk size in metadata sectors.
	BlocksPerStrip uint16
	// MapState is 0 normal, 1 uninitialized, 2 degraded, 3 failed.
	MapState uint8
	// RAIDLevel is the raw level code.
	RAIDLevel uint8
	// NumMembers is the member count the volume was formatted with.
	NumMembers uint8
	// NumDomains is the copies/domains count (2 for levels 1 and 10).
	NumDomains uint8
	// FailedDiskNum is the failed slot, 0xFF when none.
	FailedDiskNum uint8
	// DDF is the DDF marker stored by the firmware.
	DDF uint8
	// DiskOrdTbl holds one entry per slot: a disk index in the low 24 bits and
	// the rebuild bit at bit 24.
	DiskOrdTbl []uint32
}

// Level returns the effective RAID level. A raw code of 1 over more than two
// members is IMSM's RAID10, which older firmware wrote as RAID1.
func (m *Map) Level() Level {
	switch m.RAIDLevel {
	case 0:
		return LevelRaid0
	case 1:
		if m.NumMembers == 2 {
			return LevelRaid1
		}
		return LevelRaid10
	case 5:
		return LevelRaid5
	case 6:
		return LevelRaid6
	case 10:
		return LevelRaid10
	default:
		return Level(m.RAIDLevel)
	}
}

// DataMembers returns the number of data members, the divisor mdadm uses to
// check the recorded volume size against the map.
func (m *Map) DataMembers() uint64 {
	members := uint64(m.NumMembers)
	switch m.Level() {
	case LevelRaid0:
		return members
	case LevelRaid1, LevelRaid10:
		return members / 2
	case LevelRaid5:
		if members == 0 {
			return 0
		}
		return members - 1
	case LevelRaid6:
		if members < 2 {
			return 0
		}
		return members - 2
	default:
		return 0
	}
}

// ChunkBytes returns the chunk size in bytes, saturating on overflow.
func (m *Map) ChunkBytes(sectorSize uint32) uint64 {
	return satMul(uint64(m.BlocksPerStrip), uint64(sectorSize))
}

// DataOffsetBytes returns the byte offset of the data area within every member.
func (m *Map) DataOffsetBytes(sectorSize uint32) uint64 {
	return satMul(m.PBAOfLBA0, uint64(sectorSize))
}

// ComponentBytes returns the bytes each member devotes to the volume
// (mdadm's per_dev_array_size). The boolean is false when the product
// overflows a uint64.
func (m *Map) ComponentBytes(sectorSize uint32) (uint64, bool) {
	factor := uint64(1)
	if m.Level() == LevelRaid1 || m.Level() == LevelRaid10 {
		factor = 2
	}
	value, ok := checkedMul(m.NumDataStripes, uint64(m.BlocksPerStrip))
	if !ok {
		return 0, false
	}
	value, ok = checkedMul(value, factor)
	if !ok {
		return 0, false
	}
	return checkedMul(value, uint64(sectorSize))
}

// SlotDisk returns the disk index recorded for slot, or false when the slot
// records no disk.
func (m *Map) SlotDisk(slot int) (uint8, bool) {
	if slot < 0 || slot >= len(m.DiskOrdTbl) {
		return 0, false
	}
	index := m.DiskOrdTbl[slot] & ordIndexMask
	if index == ordUnrecorded || index > 0xFF {
		return 0, false
	}
	return uint8(index), true
}

// SlotRebuilding reports whether the map marks slot out of sync.
func (m *Map) SlotRebuilding(slot int) bool {
	if slot < 0 || slot >= len(m.DiskOrdTbl) {
		return false
	}
	return m.DiskOrdTbl[slot]&ordRebuild != 0
}

// DiskSlot returns the slot a disk index occupies.
func (m *Map) DiskSlot(diskIndex uint8) (int, bool) {
	for slot := 0; slot < int(m.NumMembers); slot++ {
		if recorded, ok := m.SlotDisk(slot); ok && recorded == diskIndex {
			return slot, true
		}
	}
	return 0, false
}

// Volume is one volume in the container's device table.
type Volume struct {
	// Index is the position in the device table.
	Index int
	// Name is the 16-byte name decoded as text with trailing NULs removed.
	Name string
	// SizeBlocks is the logical volume size in metadata sectors, as recorded.
	SizeBlocks uint64
	// Status holds the volume status flags.
	Status uint32
	// NumSubVols is the sub-volume count; unused by current mdadm.
	NumSubVols uint8
	// RaidDevNum is my_vol_raid_dev_num.
	RaidDevNum uint16
	// RwhPolicy is the parity write-hole policy byte, reported as recorded.
	RwhPolicy uint8
	// MigrState is 0 normal, 1 migrating.
	MigrState uint8
	// Dirty is the RAIDVOL_DIRTY byte: 1 means the volume was not cleanly
	// shut down; 0 is a claim, not proof of a clean array.
	Dirty uint8
	// Map is the first (current) map.
	Map Map

	nameRaw [16]byte
}

// SizeBytes returns the logical array size in bytes, saturating on overflow.
func (v *Volume) SizeBytes(sectorSize uint32) uint64 {
	return satMul(v.SizeBlocks, uint64(sectorSize))
}

// IsDirty reports whether the volume says it was not cleanly shut down.
func (v *Volume) IsDirty() bool { return v.Dirty&1 != 0 }

// Container is one parsed IMSM MPB, shared by every member disk.
type Container struct {
	// SectorSize is the device logical sector size the MPB was read with.
	SectorSize uint32
	// Version is the version string stored after the signature.
	Version string
	// CheckSum is the stored checksum word.
	CheckSum uint32
	// MPBSize is the MPB size in bytes.
	MPBSize uint32
	// MPBOffset is the byte offset of the MPB's physical span in the source.
	MPBOffset uint64
	// FamilyNum is the container family identifier.
	FamilyNum uint32
	// OrigFamilyNum is the original family identifier; 0 on old metadata.
	OrigFamilyNum uint32
	// GenerationNum is the generation counter.
	GenerationNum uint32
	// Attributes holds the attribute bits.
	Attributes uint32
	// CreationTime is microseconds since the Unix epoch.
	CreationTime uint64
	// Disks is the disk table, in metadata order.
	Disks []Disk
	// Volumes is the volume (device) table, in metadata order.
	Volumes []Volume

	fingerprint [20]byte
}

// family returns the number mdadm hashes: OrigFamilyNum, falling back to
// FamilyNum when the metadata predates the field.
func (c *Container) family() uint32 {
	if c.OrigFamilyNum == 0 {
		return c.FamilyNum
	}
	return c.OrigFamilyNum
}

// ContainerUUID returns mdadm's container UUID: SHA-1 of the signature and
// family number, first 16 bytes, in colon-separated hex.
func (c *Container) ContainerUUID() string {
	input := make([]byte, MPBSigLen+4)
	copy(input, MPBSignature)
	binary.LittleEndian.PutUint32(input[MPBSigLen:], c.family())
	sum := sha1.Sum(input)
	return uuidText(sum[:16])
}

// VolumeUUID returns the UUID mdadm synthesizes for one volume: SHA-1 of the
// signature, family number, volume index and 16-byte name, first 16 bytes.
func (c *Container) VolumeUUID(index int) (string, bool) {
	if index < 0 || index >= len(c.Volumes) {
		return "", false
	}
	input := make([]byte, MPBSigLen+4+4+16)
	copy(input, MPBSignature)
	binary.LittleEndian.PutUint32(input[MPBSigLen:], c.family())
	binary.LittleEndian.PutUint32(input[MPBSigLen+4:], uint32(index))
	copy(input[MPBSigLen+8:], c.Volumes[index].nameRaw[:])
	sum := sha1.Sum(input)
	return uuidText(sum[:16]), true
}

// MetadataSpanBytes returns how many bytes the MPB's physical span occupies at
// the end of a member: ceil(mpbSize/sectorSize)+1 sectors.
func (c *Container) MetadataSpanBytes() uint64 {
	sectors := (uint64(c.MPBSize) + uint64(c.SectorSize) - 1) / uint64(c.SectorSize)
	return satMul(sectors+1, uint64(c.SectorSize))
}

// AgreesWith reports whether two members' metadata tables agree, ignoring only
// the checksum, which covers them, and the generation counter, which may
// legitimately differ after a partial write.
func (c *Container) AgreesWith(other *Container) bool {
	return c.fingerprint == other.fingerprint
}

// BindDisk binds a member image to a disk record by its length.
//
// The MPB is identical on every member and carries no drive identity an image
// can reproduce, so the only evidence linking an image to a disk record is the
// record's TotalBlocks against the image's length. The answer is accepted only
// when exactly one configured, non-failed record matches; equal-sized records
// are refused as ambiguous, and a length that matches only a spare, failed or
// journal record is refused with that state named.
func (c *Container) BindDisk(sourceLen uint64) (uint8, error) {
	sector := uint64(c.SectorSize)
	if sector == 0 || sourceLen%sector != 0 {
		return 0, unsupportedf("the image is %d bytes, not a whole number of the container's %d-byte sectors, so it cannot be one of its member disks", sourceLen, sector)
	}
	blocks := sourceLen / sector
	var candidates []int
	for index := range c.Disks {
		disk := &c.Disks[index]
		if disk.Configured() && !disk.Failed() && disk.TotalBlocks == blocks {
			candidates = append(candidates, index)
		}
	}
	switch len(candidates) {
	case 1:
		return uint8(candidates[0]), nil
	case 0:
		var sameSize []string
		for index := range c.Disks {
			disk := &c.Disks[index]
			if disk.TotalBlocks == blocks {
				sameSize = append(sameSize, describeDisk(disk))
			}
		}
		if len(sameSize) == 0 {
			return 0, unsupportedf("no configured disk record in container %s has this image's %d sectors (%d bytes); the image length does not match any member the metadata records",
				c.ContainerUUID(), blocks, sourceLen)
		}
		return 0, unsupportedf("the disk record(s) of this image's size are not data members: %s; a spare, failed or journal disk holds no volume bytes",
			strings.Join(sameSize, ", "))
	default:
		records := make([]string, len(candidates))
		for i, index := range candidates {
			records[i] = fmt.Sprintf("disk %d", index)
		}
		return 0, unsupportedf("container %s records %d member disks of the same size (%d sectors); an image cannot say which of %s it is, and this build refuses to assign one by order",
			c.ContainerUUID(), len(records), blocks, strings.Join(records, ", "))
	}
}

// BindDiskIndex binds a member image to a caller-supplied disk index, checking
// that the record really describes a configured member of this size.
func (c *Container) BindDiskIndex(index int, sourceLen uint64) error {
	if index < 0 || index >= len(c.Disks) {
		return unsupportedf("container %s records %d disk(s); index %d does not exist",
			c.ContainerUUID(), len(c.Disks), index)
	}
	disk := &c.Disks[index]
	if !disk.Configured() || disk.Failed() {
		return unsupportedf("disk %d of container %s is %s; it is not a configured data member",
			index, c.ContainerUUID(), diskState(disk))
	}
	sector := uint64(c.SectorSize)
	if sector == 0 || sourceLen%sector != 0 || disk.TotalBlocks != sourceLen/sector {
		return unsupportedf("disk %d of container %s records %d sectors but the image is %d bytes (%d sectors at %d bytes); they are not the same device",
			index, c.ContainerUUID(), disk.TotalBlocks, sourceLen, sourceLen/sector, sector)
	}
	return nil
}

func describeDisk(disk *Disk) string {
	serial := "(no serial)"
	if disk.Serial != "" {
		serial = fmt.Sprintf("`%s`", disk.Serial)
	}
	return fmt.Sprintf("%s (%s)", serial, diskState(disk))
}

func diskState(disk *Disk) string {
	var states []string
	if disk.Failed() {
		states = append(states, "failed")
	}
	if disk.Spare() {
		states = append(states, "spare")
	}
	if disk.Journal() {
		states = append(states, "journal")
	}
	if disk.Configured() {
		states = append(states, "configured")
	}
	if len(states) == 0 {
		states = append(states, "no state bit")
	}
	return strings.Join(states, "+")
}

// Parse reads an IMSM container from the end of src.
//
// A nil container with a nil error means no MPB signature was found at either
// possible anchor, so the source is not IMSM. A signature whose size, tables
// or checksum are wrong is an error: the source claims to be IMSM and this
// build will not look elsewhere.
func Parse(src source.ByteSource) (*Container, error) {
	length := src.Len()
	type anchor struct {
		sector uint32
		bytes  []byte
	}
	var anchors []anchor
	for _, sector := range sectorSizes {
		size := uint64(sector)
		if length < size*2 {
			continue
		}
		offset := length - size*2
		block, err := source.ReadVecAt(src, offset, size)
		if err != nil {
			return nil, err
		}
		if string(block[:MPBSigLen]) == MPBSignature {
			anchors = append(anchors, anchor{sector: sector, bytes: block})
		}
	}
	switch len(anchors) {
	case 0:
		return nil, nil
	case 1:
		return build(src, anchors[0].sector, anchors[0].bytes)
	}

	var built []*Container
	var firstErr error
	for _, candidate := range anchors {
		container, err := build(src, candidate.sector, candidate.bytes)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		built = append(built, container)
	}
	switch len(built) {
	case 1:
		return built[0], nil
	case 0:
		return nil, firstErr
	default:
		return nil, unsupportedf("an MPB signature is present at both the 512-byte and 4096-byte anchors and both verify; the device's logical sector size is ambiguous")
	}
}

func build(src source.ByteSource, sectorSize uint32, anchor []byte) (*Container, error) {
	sector := uint64(sectorSize)
	length := src.Len()
	mpbSize := le32(anchor, 0x24)
	if uint64(mpbSize) < MPBMinBytes {
		return nil, source.NewCorrupt(0x24,
			fmt.Sprintf("the MPB records %d bytes, smaller than the %d-byte header and one disk record", mpbSize, MPBMinBytes))
	}
	maxSize := uint64(MPBMaxSectors) * sector
	if uint64(mpbSize) > maxSize {
		return nil, source.NewCorrupt(0x24,
			fmt.Sprintf("the MPB records %d bytes, larger than the %d-byte maximum", mpbSize, maxSize))
	}
	sectors := (uint64(mpbSize) + sector - 1) / sector
	span := (sectors + 1) * sector
	if span > length {
		return nil, source.NewCorrupt(0x24,
			fmt.Sprintf("the MPB records %d bytes (%d sectors), but a %d-byte source cannot hold its %d-byte span at the end",
				mpbSize, sectors, length, span))
	}
	bufferBytes := sectors * sector
	if bufferBytes > uint64(maxIntValue) {
		return nil, source.NewCorrupt(0x24, "the MPB's logical buffer does not fit in memory")
	}
	buffer := make([]byte, int(bufferBytes))
	copy(buffer, anchor)
	if sectors > 1 {
		tailBytes := (sectors - 1) * sector
		tail, err := source.ReadVecAt(src, length-span, tailBytes)
		if err != nil {
			return nil, err
		}
		copy(buffer[sector:], tail)
	}
	if string(buffer[:MPBSigLen]) != MPBSignature {
		return nil, source.NewCorrupt(0, "the reassembled MPB does not start with the IMSM signature")
	}

	checkSum := le32(buffer, 0x20)
	var sum uint32
	limit := (int(mpbSize) / 4) * 4
	for at := 0; at < limit; at += 4 {
		sum += le32(buffer, at)
	}
	computed := sum - checkSum
	if computed != checkSum {
		return nil, source.NewCorrupt(0x20,
			fmt.Sprintf("the MPB checksum is %#010x but its %d bytes sum to %#010x", checkSum, mpbSize, computed))
	}

	version, err := decodeVersion(buffer)
	if err != nil {
		return nil, err
	}
	if !versionSupported(version) {
		return nil, unsupportedf("IMSM metadata version `%s` is not one this build has verified; the offsets decoded here are the 1.2.00-and-later layout", version)
	}

	familyNum := le32(buffer, 0x28)
	generationNum := le32(buffer, 0x2C)
	attributes := le32(buffer, 0x34)
	numDisks := int(buffer[0x38])
	numVolumes := int(buffer[0x39])
	origFamilyNum := le32(buffer, 0x40)
	creationTime := le64(buffer, 0x50)
	if numDisks == 0 {
		return nil, source.NewCorrupt(0x38, "the MPB records 0 disks; an IMSM container has at least one")
	}

	trustedHigh := attributes&Attr2TBDisk != 0
	diskTableEnd := uint64(DiskTableOffset) + uint64(DiskBytes)*uint64(numDisks)
	if diskTableEnd > uint64(mpbSize) {
		return nil, source.NewCorrupt(DiskTableOffset,
			fmt.Sprintf("the MPB records %d disks, so its disk table ends at %d, past its %d-byte size",
				numDisks, diskTableEnd, mpbSize))
	}

	disks := make([]Disk, 0, numDisks)
	for index := 0; index < numDisks; index++ {
		base := DiskTableOffset + DiskBytes*index
		raw := buffer[base : base+DiskBytes]
		totalLow := uint64(le32(raw, 0x10))
		totalHigh := uint64(0)
		if trustedHigh {
			totalHigh = uint64(le32(raw, 0x20))
		}
		disks = append(disks, Disk{
			Serial:      decodeText(raw[:16]),
			SCSIID:      le32(raw, 0x14),
			Status:      le32(raw, 0x18),
			OwnerCfgNum: le32(raw, 0x1C),
			TotalBlocks: totalLow | totalHigh<<32,
		})
	}

	volumes := make([]Volume, 0, numVolumes)
	offset := int(diskTableEnd)
	for index := 0; index < numVolumes; index++ {
		mapBase := offset + DevMapOffset
		if mapBase+MapBaseBytes > int(mpbSize) || mapBase+MapBaseBytes < mapBase {
			return nil, truncatedf(uint64(mapBase), "the MPB ends before volume #%d's map; the metadata is truncated", index)
		}
		numMembers := int(buffer[mapBase+0x10])
		if numMembers == 0 {
			return nil, source.NewCorrupt(uint64(mapBase+0x10), fmt.Sprintf("volume #%d records 0 members", index))
		}
		if numMembers > numDisks {
			return nil, source.NewCorrupt(uint64(mapBase+0x10),
				fmt.Sprintf("volume #%d records %d members but the container has only %d disk(s)",
					index, numMembers, numDisks))
		}
		devBytes := uint64(DevBaseBytes) + 4*uint64(numMembers-1)
		devEnd64, ok := checkedAdd(uint64(offset), devBytes)
		if !ok {
			return nil, truncatedf(uint64(offset), "volume #%d's device table entry overflows", index)
		}
		if devEnd64 > uint64(mpbSize) {
			return nil, source.NewCorrupt(uint64(offset),
				fmt.Sprintf("volume #%d needs %d bytes but the MPB ends after %d; the device table is truncated",
					index, devBytes, mpbSize))
		}
		devEnd := int(devEnd64)
		raw := buffer[offset:devEnd]

		sizeLow := uint64(le32(raw, 0x10))
		sizeHigh := uint64(0)
		if trustedHigh {
			sizeHigh = uint64(le32(raw, 0x14))
		}
		migrState := raw[0x58]
		if migrState != 0 {
			return nil, unsupportedf("IMSM volume #%d is in the middle of a metadata migration (migr_state %d); the current map is not the finished geometry, so it is not placed",
				index, migrState)
		}
		volumeMap, err := readMap(raw, mapBase-offset, trustedHigh, index)
		if err != nil {
			return nil, err
		}
		for slot := 0; slot < int(volumeMap.NumMembers); slot++ {
			if diskIndex, ok := volumeMap.SlotDisk(slot); ok && int(diskIndex) >= len(disks) {
				return nil, source.NewCorrupt(uint64(mapBase+MapOrdOffset+4*slot),
					fmt.Sprintf("volume #%d slot %d records disk index %d, but the container has only %d disk(s)",
						index, slot, diskIndex, len(disks)))
			}
		}
		var nameRaw [16]byte
		copy(nameRaw[:], raw[:16])
		volumes = append(volumes, Volume{
			Index:      index,
			Name:       decodeText(nameRaw[:]),
			SizeBlocks: sizeLow | sizeHigh<<32,
			Status:     le32(raw, 0x18),
			NumSubVols: raw[0x21],
			RaidDevNum: le16(raw, 0x28),
			RwhPolicy:  raw[0x32],
			MigrState:  migrState,
			Dirty:      raw[0x5A],
			Map:        volumeMap,
			nameRaw:    nameRaw,
		})
		offset = devEnd
	}

	fingerprintInput := append([]byte(nil), buffer...)
	for _, span := range [][2]int{{0x20, 0x24}, {0x2C, 0x30}} {
		for i := span[0]; i < span[1]; i++ {
			fingerprintInput[i] = 0
		}
	}
	fingerprint := sha1.Sum(fingerprintInput[:mpbSize])

	return &Container{
		SectorSize:    sectorSize,
		Version:       version,
		CheckSum:      checkSum,
		MPBSize:       mpbSize,
		MPBOffset:     length - span,
		FamilyNum:     familyNum,
		OrigFamilyNum: origFamilyNum,
		GenerationNum: generationNum,
		Attributes:    attributes,
		CreationTime:  creationTime,
		Disks:         disks,
		Volumes:       volumes,
		fingerprint:   fingerprint,
	}, nil
}

func readMap(raw []byte, base int, trustedHigh bool, volumeIndex int) (Map, error) {
	numMembers := raw[base+0x10]
	pbaLow := uint64(le32(raw, base))
	bpmLow := uint64(le32(raw, base+4))
	ndsLow := uint64(le32(raw, base+8))
	var pbaHigh, bpmHigh, ndsHigh uint64
	if trustedHigh {
		pbaHigh = uint64(le32(raw, base+0x14))
		bpmHigh = uint64(le32(raw, base+0x18))
		ndsHigh = uint64(le32(raw, base+0x1C))
	}
	blocksPerStrip := le16(raw, base+0x0C)
	mapState := raw[base+0x0E]
	raidLevel := raw[base+0x0F]
	numDomains := raw[base+0x11]
	failedDiskNum := raw[base+0x12]
	ddf := raw[base+0x13]

	ordAt := base + MapOrdOffset
	count := int(numMembers)
	diskOrdTbl := make([]uint32, count)
	for slot := 0; slot < count; slot++ {
		at := ordAt + 4*slot
		if at+4 > len(raw) {
			return Map{}, truncatedf(uint64(at), "the MPB ends before volume #%d's slot table; the metadata is truncated", volumeIndex)
		}
		diskOrdTbl[slot] = le32(raw, at)
	}
	if blocksPerStrip == 0 {
		return Map{}, source.NewCorrupt(uint64(base+0x0C), fmt.Sprintf("volume #%d records a chunk size of 0", volumeIndex))
	}
	return Map{
		PBAOfLBA0:       pbaLow | pbaHigh<<32,
		BlocksPerMember: bpmLow | bpmHigh<<32,
		NumDataStripes:  ndsLow | ndsHigh<<32,
		BlocksPerStrip:  blocksPerStrip,
		MapState:        mapState,
		RAIDLevel:       raidLevel,
		NumMembers:      numMembers,
		NumDomains:      numDomains,
		FailedDiskNum:   failedDiskNum,
		DDF:             ddf,
		DiskOrdTbl:      diskOrdTbl,
	}, nil
}

func decodeVersion(buffer []byte) (string, error) {
	raw := buffer[MPBSigLen:0x20]
	end := bytes.IndexByte(raw, 0)
	if end < 0 {
		end = len(raw)
	}
	if !utf8.Valid(raw[:end]) {
		return "", source.NewCorrupt(MPBSigLen, "the version string is not valid UTF-8")
	}
	return string(raw[:end]), nil
}

func versionSupported(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return false
	}
	minor, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return false
	}
	if _, err := strconv.ParseUint(parts[2], 10, 32); err != nil {
		return false
	}
	return (major == 1 && minor >= 2) || (major == 2 && minor == 0)
}

func decodeText(raw []byte) string {
	end := bytes.IndexByte(raw, 0)
	if end < 0 {
		end = len(raw)
	}
	return strings.ToValidUTF8(string(raw[:end]), "�")
}

func uuidText(raw []byte) string {
	var out strings.Builder
	for index := 0; index+4 <= len(raw); index += 4 {
		if index > 0 {
			out.WriteByte(':')
		}
		out.WriteString(hex.EncodeToString(raw[index : index+4]))
	}
	return out.String()
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

func truncatedf(offset uint64, format string, args ...any) error {
	return fmt.Errorf("%w: at offset %d: %s", source.ErrUnexpectedEOF, offset, fmt.Sprintf(format, args...))
}

func satMul(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}

func checkedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}

func checkedAdd(a, b uint64) (uint64, bool) {
	if b > ^uint64(0)-a {
		return 0, false
	}
	return a + b, true
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

func le16(raw []byte, at int) uint16 {
	return uint16(raw[at]) | uint16(raw[at+1])<<8
}

func le32(raw []byte, at int) uint32 {
	return uint32(raw[at]) | uint32(raw[at+1])<<8 | uint32(raw[at+2])<<16 | uint32(raw[at+3])<<24
}

func le64(raw []byte, at int) uint64 {
	return uint64(le32(raw, at)) | uint64(le32(raw, at+4))<<32
}
