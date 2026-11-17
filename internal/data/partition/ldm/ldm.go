// Package ldm decodes a Windows Logical Disk Manager (LDM, "dynamic disk")
// database and exposes the volumes it describes.
//
// An LDM disk is what Windows Disk Management calls a dynamic disk. The MBR
// keeps one partition entry of type 0x42 covering the whole disk, and the
// allocation map lives outside the partitions in a private database at the end
// of the disk. Without that database a dynamic disk looks like a disk with one
// unreadable partition; this package reads it read-only and reports which
// volumes it describes and where their extents sit.
//
// It is a pure-Go port of forensic-core's data/partition/ldm.rs and
// ldm_volume.rs. Parsing never fabricates bytes: a struct that announces
// itself and cannot be read is an error wrapping source.ErrCorrupt,
// source.ErrUnsupported or source.ErrUnexpectedEOF, not an empty database.
//
// # On-disk layout
//
// All LDM numbers are big-endian and all addresses are in logical blocks
// (Windows calls them sectors; the PRIVHEAD states their size at 0x10F). The
// primary sources are the Linux kernel's block/partitions/ldm.h and ldm.c, the
// reverse-engineered LDM documentation at reeves.fr/docs/file_systems/ldmdoc,
// and DiscUtils' LogicalDiskManager reader.
//
//	byte 0x000        MBR; a partition entry of type 0x42 marks a dynamic disk
//	block 6 (0xC00)   PRIVHEAD #1, the primary private header
//	...
//	private region    the last 2048 blocks (1 MiB on a 512-byte-block disk)
//	  + 0             (unused)
//	  + 1, + 2        TOCBLOCK copies at the head of the private region
//	  + 17            VMDB, the database header
//	  + 18 ..         VBLK records
//	  + 2045, + 2046  TOCBLOCK copies at the tail
//	  + 1856          PRIVHEAD #2
//	  + 2047          PRIVHEAD #3 (the last block of the disk)
//
// The PRIVHEAD is 512 bytes: magic "PRIVHEAD" at 0x00, major/minor version at
// 0x0C/0x0E (2.11 = 2000/XP/2003, 2.12 = Vista and later), disk GUID string at
// 0x30, host GUID at 0x70, disk-group GUID at 0xB0, disk-group name at 0xF0,
// bytes per block at 0x10F, public region start/size at 0x11B/0x123, private
// region start/size at 0x12B/0x133, and the primary/secondary TOC block
// addresses at 0x13B/0x143 (relative to the private region start). Only the
// first copy is at a fixed absolute address; the other copies are located from
// config_start.
//
// The TOCBLOCK is 512 bytes: magic "TOCBLOCK" at 0x00 and two 34-byte region
// descriptors at 0x24 and 0x46. Each names its region at +0x00, stores its
// start at +0x0A and its size at +0x12 (both relative to the private region).
// The first region is "config" and starts at block 17, so the VMDB begins at
// config_start + 17. The TOCBLOCK does not carry a VBLK count: it gives the
// region extent.
//
// The VMDB is 512 bytes: magic "VMDB" at 0x00, the sequence number of the last
// VBLK at 0x04, the VBLK record size at 0x08, the byte offset of the first VBLK
// from the VMDB at 0x0C, the update status at 0x10 (1 is clean), the version at
// 0x12/0x14 (4.10), the disk-group name at 0x16 and its GUID at 0x35.
//
// A VBLK record has a 24-byte header: magic "VBLK" at 0x00, sequence number at
// 0x04, group number at 0x08 (the fragment group), fragment number and
// fragment count at 0x0C/0x0E, update status at 0x10, record flags at 0x12,
// the kind/revision byte at 0x13, the declared body length at 0x14 (counted
// from 0x18), and the body from 0x18. Numbers in the body are one-byte-length-
// prefixed big-endian integers and names are one-byte-length-prefixed
// single-byte strings, not UTF-16.
//
// # Corrections to the common summary
//
// Several details that circulate in summaries are wrong, and this parser
// follows the primary sources instead:
//
//   - PRIVHEAD and TOCBLOCK are eight ASCII bytes, not UTF-16LE.
//   - The primary PRIVHEAD is at absolute block 6, not in the first block of
//     the private region. Copies 2 and 3 are at private blocks 1856 and 2047.
//   - The last 512 bytes of a dynamic disk are a PRIVHEAD, not a TOCBLOCK. The
//     tail TOCBLOCK copies are the two blocks before the private region ends
//     (blocks size-3 and size-2). Offset 0x1BE is the first MBR partition
//     entry, where the 0x42 type byte marks a dynamic disk.
//   - The VBLK kind codes are 0x32 component, 0x33 partition, 0x34/0x44 disk
//     (revisions 3 and 4), 0x35/0x45 disk group, and 0x51 volume. 0x51 is the
//     volume, not 0x32; 0x32 is the component, not 0x31.
//   - No primary source documents VBLK kinds 0x01/0x02. The database header is
//     the VMDB block with its own VMDB magic, outside the VBLK stream. Such
//     records are counted and named, never silently dropped.
//
// # What this package decodes
//
// Disk, partition, component and volume records; the volume → component →
// partition → disk chain that reconstructs a volume's extents; and the
// optional stripe geometry those records carry. See VolumeGeometry.
// AssembleVolume consumes that geometry plus one image per member disk and
// presents a concatenated, striped, mirrored or RAID-5 volume as a read-only
// source.ByteSource. Never is a missing member zero-filled: assembly refuses
// an incomplete layout by name (a *VolumeError), and a mirror falls back only
// to another complete copy.
//
// # What is not decoded
//
// The KLOG transaction log, the disk flag word, and the drive-letter hint is
// reported as the volume record's string, not resolved to a drive letter. The
// PRIVHEAD and TOCBLOCK byte-sum checksums are verified; both stored byte
// orders are accepted because no primary source states the writer's order.
// A clean VMDB's committed VBLK counts must equal the records that decode; an
// unclean VMDB is parsed and its pending counts are reported, not refused. All
// valid TOCBLOCK copies must agree on the config region. Disk and volume GUIDs
// are printed in the byte order the database stores them. A revision-4 disk
// record's binary GUID is matched against the PRIVHEAD in both byte orders for
// identity only; the printed value stays as stored. A GPT layout, where the
// database lives in a separate 1 MiB metadata partition, is not recognized:
// only the MBR tail layout is. The KLOG is not replayed.
package ldm

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Magic values of the structures this package parses.
const (
	// PrivHeadMagic is the magic of a 512-byte private header.
	PrivHeadMagic = "PRIVHEAD"
	// TOCBlockMagic is the magic of a 512-byte table-of-contents block.
	TOCBlockMagic = "TOCBLOCK"
	// VMDBMagic is the magic of the volume-manager database header.
	VMDBMagic = "VMDB"
	// VBLKMagic is the magic of a volume-block record.
	VBLKMagic = "VBLK"
)

// Documented layout constants.
const (
	// DatabaseBytes is the normal extent of the private database: the last
	// 1 MiB of the disk.
	DatabaseBytes uint64 = 1024 * 1024
	// PrivHeadPrimaryBlock is the block of the primary private header,
	// relative to the start of the device.
	PrivHeadPrimaryBlock uint64 = 6
	// PrivHeadBackupBlock is the block of the second private-header copy,
	// relative to the private region.
	PrivHeadBackupBlock uint64 = 1856
	// PrivHeadLastBlock is the block of the third private-header copy: the
	// last block of the disk.
	PrivHeadLastBlock uint64 = 2047
	// VMDBOffsetBlocks is the block of the VMDB, relative to the private
	// region, in a standard layout.
	VMDBOffsetBlocks uint64 = 17
	// SectorBytes is the block unit LDM addresses storage in.
	SectorBytes uint64 = 512
)

const (
	privHeadBytes        uint64 = 512
	structBytes          uint64 = 512
	vblkHeaderBytes             = 0x18
	maxVBLKStreamBytes   uint64 = 64 * 1024 * 1024
	maxVBLKFragmentCount uint16 = 4
)

// Copy identifies which TOCBLOCK pair answered.
//
// The private region carries a pair of TOCBLOCK copies at its head (private
// blocks 1 and 2) and another pair two blocks before its end. A reader that
// only trusts the head pair declares a readable disk unreadable when the head
// is overwritten, so both pairs are tried and the copy that answered is
// reported.
type Copy uint8

const (
	// CopyHead is a TOCBLOCK in the first half of the private region.
	CopyHead Copy = iota
	// CopyTail is a TOCBLOCK in the second half of the private region.
	CopyTail
)

// Label returns "head" or "tail".
func (c Copy) Label() string {
	if c == CopyHead {
		return "head"
	}
	return "tail"
}

// Layout is how a volume's extents combine into its logical contents.
type Layout uint8

const (
	// LayoutConcatenated means extents are joined end to end: a simple or
	// spanned volume.
	LayoutConcatenated Layout = iota
	// LayoutStripe means extents are interleaved in chunks (stripe set).
	LayoutStripe
	// LayoutRaid5 means extents form a RAID-5 set, one extent per group
	// holding parity.
	LayoutRaid5
	// LayoutMirrored means more than one component describes the volume: the
	// components are redundant copies, not pieces to concatenate.
	LayoutMirrored
	// LayoutUnknown means the layout byte is absent or not a documented value.
	LayoutUnknown
)

// Label returns the layout's name.
func (l Layout) Label() string {
	switch l {
	case LayoutConcatenated:
		return "concatenated"
	case LayoutStripe:
		return "stripe"
	case LayoutRaid5:
		return "raid5"
	case LayoutMirrored:
		return "mirrored"
	default:
		return "unknown"
	}
}

// Version is a two-part structure version, reported as stored.
type Version struct {
	Major uint16
	Minor uint16
}

// Region is a contiguous set of logical blocks, in device block units.
type Region struct {
	StartLBA uint64
	Sectors  uint64
}

// Range is a contiguous byte range in the evidence image.
type Range struct {
	Offset uint64
	Len    uint64
}

// KindCount is one VBLK kind that was present but not decoded.
type KindCount struct {
	Kind  uint8
	Label string
	Count int
}

// VmdbCounts is the VMDB header's VBLK counts for one database state.
//
// The committed counts at 0x85 describe the records the database claims to
// hold now; the pending counts at 0xA1 describe the state after any in-flight
// changes. Both are read so a clean database can be checked against the records
// that actually decoded.
type VmdbCounts struct {
	Volumes    uint32
	Components uint32
	Partitions uint32
	Disks      uint32
}

// Disk is one disk listed in the database.
type Disk struct {
	// ID is the VBLK object id; partitions reference their disk by this.
	ID uint64
	// Name is the disk's VBLK name, when recorded.
	Name *string
	// GUID is the disk GUID in the database's textual byte order.
	GUID *string
	// ThisDisk is true when this record's GUID matches the PRIVHEAD's disk
	// GUID, i.e. this is the disk the image was taken from.
	ThisDisk bool
	// Partitions are the partitions the database places on this disk.
	Partitions []Partition
}

// Partition is one piece of a volume on one disk.
type Partition struct {
	ID          uint64
	Name        *string
	DiskID      uint64
	ComponentID *uint64
	// StartLBA is relative to the public region start, in device blocks.
	StartLBA uint64
	// VolumeOffset is the offset of this partition inside the volume's
	// column, in blocks.
	VolumeOffset uint64
	SizeSectors  uint64
	// Flags is the partition flag word, reported verbatim.
	Flags uint32
	// Column is the index inside a striped or RAID-5 component, when the
	// record carries one (VBLK header flag 0x08). A concatenated partition
	// has none. Assembly places a stripe unit by this index, never by
	// guessing an order.
	Column *uint64
	// StripeBlocks is the owning component's stripe unit, in device blocks,
	// when the component record carries one (VBLK header flag 0x10).
	StripeBlocks *uint64
	// Columns is the owning component's column count, when it carries one.
	Columns *uint64
	// ChunkBlocks is the stripe (chunk) size the owning volume record states,
	// in device blocks, when it carries one (VBLK header flag 0x80).
	ChunkBlocks *uint64
	// ComponentLayout is the layout of the component this partition belongs
	// to.
	ComponentLayout Layout
}

// Extent is one physical piece of a volume.
type Extent struct {
	PartitionID uint64
	DiskID      uint64
	DiskName    *string
	// OnThisDisk is true when the extent's disk is the disk this database was
	// read from.
	OnThisDisk bool
	// StartLBA is the start of the partition on its own disk, relative to that
	// disk's public region start.
	StartLBA uint64
	// VolumeOffset is the offset of the extent inside the volume's logical
	// space.
	VolumeOffset uint64
	Sectors      uint64
	// Offset is the absolute byte offset in this image, only when OnThisDisk.
	Offset *uint64
	// Len is the byte length of the extent.
	Len uint64
}

// Volume is a volume described by the database.
type Volume struct {
	ID uint64
	// Name is the volume record's name.
	Name *string
	// VolumeType is the volume type string (`gen`, `raid5`, ...).
	VolumeType *string
	// State is the volume state string (`ACTIVE`, `SYNC`, ...).
	State *string
	// SizeSectors is the declared size, when the record states one.
	SizeSectors *uint64
	// DriveHint is the mount hint string, when the record carries one. It is
	// not a resolved drive letter.
	DriveHint *string
	// PartitionType is the filesystem partition type byte (0x07 NTFS,
	// 0x0B FAT32, ...).
	PartitionType *uint8
	GUID          *string
	// DeclaredComponents is the number of components the volume record itself
	// declares, before component records are matched against it.
	DeclaredComponents uint64
	// ComponentIDs are the component records whose volume id points here.
	ComponentIDs []uint64
	Layout       Layout
	Extents      []Extent
	// Range is a contiguous byte range, present only for a single
	// concatenated component whose extents are contiguous on this disk.
	Range *Range
	// SpansDisks is true when a known extent lives on another disk.
	SpansDisks bool
}

// ComponentPartition is one partition as it participates in a component's
// geometry.
type ComponentPartition struct {
	PartitionID uint64
	DiskID      uint64
	// Column is the column index for a stripe or RAID-5 set; nil for a
	// concatenation.
	Column *uint64
	// VolumeOffset is the offset inside the component, in device blocks.
	VolumeOffset uint64
	// StartLBA is the start on its own disk, relative to its public region.
	StartLBA    uint64
	SizeSectors uint64
}

// ComponentGeometry is the decoded geometry of one component.
//
// StripeBlocks and Columns come from the component record and are present only
// for a stripe set or RAID-5 set. ChunkBlocks is the optional stripe size the
// volume record carries, kept so a disagreement between the two records can be
// refused rather than resolved by picking one.
type ComponentGeometry struct {
	ID           uint64
	Layout       Layout
	StripeBlocks *uint64
	Columns      *uint64
	ChunkBlocks  *uint64
	Partitions   []ComponentPartition
}

// VolumeGeometry is everything needed to place a volume's partitions on its
// member disks.
type VolumeGeometry struct {
	VolumeID uint64
	// StripeBlocks and Columns are the stripe unit and column count common to
	// the volume's components, when they record one.
	StripeBlocks *uint64
	Columns      *uint64
	ChunkBlocks  *uint64
	Components   []ComponentGeometry
}

// Group is a disk group: the database's own group, holding the disks it knows
// and the volumes it describes.
type Group struct {
	Name    *string
	GUID    *string
	Disks   []Disk
	Volumes []Volume
	// UnresolvedPartitions are partitions whose disk record is absent from the
	// database; they are kept rather than dropped, but not attached to a
	// guessed disk.
	UnresolvedPartitions []Partition
}

// Database is a parsed LDM database.
type Database struct {
	// DiskGUID is the disk GUID from the PRIVHEAD, as stored.
	DiskGUID      *string
	DiskGroup     *string
	DiskGroupGUID *string
	// Version is the PRIVHEAD version, normally 2.11 or 2.12.
	Version Version
	// BytesPerBlock is the block size the database addresses storage in
	// (normally 512).
	BytesPerBlock uint32
	// PublicRegion is the public region, in absolute device blocks.
	PublicRegion Region
	// PrivateRegion is the private region, in absolute device blocks.
	PrivateRegion Region
	// ConfigRegion is the TOC's config region, converted to absolute device
	// blocks.
	ConfigRegion Region
	// PrivHeadOffset is the byte offset of the private-header copy that was
	// read.
	PrivHeadOffset uint64
	// Copy says which TOCBLOCK copy answered.
	Copy Copy
	// VMDBVersion is the VMDB version, normally 4.10.
	VMDBVersion Version
	// UpdateStatus is the VMDB update status: 1 is clean.
	UpdateStatus uint16
	// Clean is true when the VMDB reported a consistent state.
	Clean bool
	// CommittedCounts are the VBLK counts the VMDB says are committed.
	CommittedCounts VmdbCounts
	// PendingCounts are the VBLK counts the VMDB says are pending.
	PendingCounts VmdbCounts
	// VBLKCount is the sequence number of the last VBLK, i.e. the record count.
	VBLKCount uint32
	// VBLKSize is the size in bytes of one VBLK slot.
	VBLKSize uint32
	// VBLKOffset is the offset of the first VBLK from the VMDB block.
	VBLKOffset uint32
	// VBLKStart is the absolute byte offset of the first VBLK record.
	VBLKStart uint64
	// ThisDiskID is the object id of the disk whose GUID matches the
	// PRIVHEAD, when the database lists it.
	ThisDiskID     *uint64
	VolumeCount    int
	PartitionCount int
	// RecordsSkipped counts VBLK slots and records that could not be decoded:
	// empty slots, undecoded kinds, incomplete fragments.
	RecordsSkipped int
	// MalformedRecords counts records of a known kind whose body did not parse.
	MalformedRecords int
	// UndecodedKinds are the skipped kinds, with the count for each.
	UndecodedKinds []KindCount
	Groups         []Group
}

// Volumes returns every volume, across the (normally single) disk group.
func (d *Database) Volumes() []*Volume {
	var out []*Volume
	for gi := range d.Groups {
		for vi := range d.Groups[gi].Volumes {
			out = append(out, &d.Groups[gi].Volumes[vi])
		}
	}
	return out
}

// Disks returns every disk, across the (normally single) disk group.
func (d *Database) Disks() []*Disk {
	var out []*Disk
	for gi := range d.Groups {
		for di := range d.Groups[gi].Disks {
			out = append(out, &d.Groups[gi].Disks[di])
		}
	}
	return out
}

// Partitions returns every attached partition plus the unresolved ones.
func (d *Database) Partitions() []*Partition {
	var out []*Partition
	for gi := range d.Groups {
		group := &d.Groups[gi]
		for di := range group.Disks {
			for pi := range group.Disks[di].Partitions {
				out = append(out, &group.Disks[di].Partitions[pi])
			}
		}
		for pi := range group.UnresolvedPartitions {
			out = append(out, &group.UnresolvedPartitions[pi])
		}
	}
	return out
}

// Disk returns the disk record with VBLK object id id, when listed.
func (d *Database) Disk(id uint64) *Disk {
	for gi := range d.Groups {
		for di := range d.Groups[gi].Disks {
			if d.Groups[gi].Disks[di].ID == id {
				return &d.Groups[gi].Disks[di]
			}
		}
	}
	return nil
}

// VolumeGeometry reconstructs one volume's assembly geometry from the
// component and partition records that name it.
//
// The database describes the whole disk group, so this is complete even for
// partitions on disks the image does not hold. A volume whose component
// records are absent has no components here; assembly then refuses by name
// instead of inventing a layout.
func (d *Database) VolumeGeometry(volume *Volume) VolumeGeometry {
	partitions := d.Partitions()
	components := make([]ComponentGeometry, 0, len(volume.ComponentIDs))
	for _, componentID := range volume.ComponentIDs {
		id := componentID
		var parts []*Partition
		for _, partition := range partitions {
			if partition.ComponentID != nil && *partition.ComponentID == id {
				parts = append(parts, partition)
			}
		}
		// A column index is authoritative for a stripe or RAID-5 set; a
		// concatenated component has none and is ordered by its volume
		// offset. Ties fall back to the disk placement so the order is
		// deterministic even for a damaged record.
		sort.SliceStable(parts, func(i, j int) bool {
			return partitionSortKeyBefore(parts[i], parts[j])
		})
		component := ComponentGeometry{ID: id, Layout: LayoutUnknown}
		if len(parts) > 0 {
			first := parts[0]
			component.Layout = first.ComponentLayout
			component.StripeBlocks = first.StripeBlocks
			component.Columns = first.Columns
			component.ChunkBlocks = first.ChunkBlocks
		}
		for _, partition := range parts {
			component.Partitions = append(component.Partitions, ComponentPartition{
				PartitionID:  partition.ID,
				DiskID:       partition.DiskID,
				Column:       partition.Column,
				VolumeOffset: partition.VolumeOffset,
				StartLBA:     partition.StartLBA,
				SizeSectors:  partition.SizeSectors,
			})
		}
		components = append(components, component)
	}

	var first *ComponentGeometry
	for i := range components {
		if components[i].Columns != nil || components[i].StripeBlocks != nil {
			first = &components[i]
			break
		}
	}
	if first == nil && len(components) > 0 {
		first = &components[0]
	}
	geometry := VolumeGeometry{VolumeID: volume.ID, Components: components}
	if first != nil {
		geometry.StripeBlocks = first.StripeBlocks
		geometry.Columns = first.Columns
		geometry.ChunkBlocks = first.ChunkBlocks
	}
	return geometry
}

func partitionSortKeyBefore(a, b *Partition) bool {
	ac, bc := uint64(^uint64(0)), uint64(^uint64(0))
	if a.Column != nil {
		ac = *a.Column
	}
	if b.Column != nil {
		bc = *b.Column
	}
	if ac != bc {
		return ac < bc
	}
	if a.VolumeOffset != b.VolumeOffset {
		return a.VolumeOffset < b.VolumeOffset
	}
	if a.StartLBA != b.StartLBA {
		return a.StartLBA < b.StartLBA
	}
	return a.ID < b.ID
}

// KindLabel returns the name of a VBLK kind, or "unknown".
func KindLabel(kind uint8) string {
	switch kind {
	case 0x32:
		return "component"
	case 0x33:
		return "partition"
	case 0x34:
		return "disk (revision 3)"
	case 0x35:
		return "disk group (revision 3)"
	case 0x44:
		return "disk (revision 4)"
	case 0x45:
		return "disk group (revision 4)"
	case 0x51:
		return "volume"
	case 0x01, 0x02:
		return "undocumented database header"
	default:
		return "unknown"
	}
}

// MatchesTail reports whether tail contains a PRIVHEAD or TOCBLOCK magic.
//
// The database is at the end of the disk, so a head-of-file detector cannot see
// it. tail should be the last 1 MiB (or the whole device); a shorter buffer
// simply cannot contain the structures it is asked about. This is a hint only:
// Parse re-reads and validates whatever it finds.
func MatchesTail(tail []byte) bool {
	return containsBytes(tail, []byte(PrivHeadMagic)) || containsBytes(tail, []byte(TOCBlockMagic))
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Parse reads the LDM database of a dynamic disk.
//
// The private region is found from the PRIVHEAD, so the whole disk (or at least
// its last 1 MiB) must be readable. A nil database with a nil error means no
// PRIVHEAD was found at any of the documented locations: the image is not a
// dynamic disk. Once a PRIVHEAD announces itself, a database that cannot be
// read is an error rather than "no table".
func Parse(src source.ByteSource) (*Database, error) {
	length := src.Len()
	if length < 1024 {
		return nil, nil
	}

	unit := blockUnit(src)
	candidates := candidateOffsets(length, unit)

	var issue error
	var selectedAt uint64
	var head *privHead
	for _, at := range candidates {
		bytes, err := source.ReadVecAt(src, at, privHeadBytes)
		if err != nil {
			return nil, err
		}
		if string(bytes[0:8]) != PrivHeadMagic {
			continue
		}
		parsed, err := parsePrivHead(bytes)
		if err == nil {
			err = checkPrivHead(parsed, length)
		}
		if err != nil {
			if issue == nil {
				issue = err
			}
			continue
		}
		selectedAt, head = at, parsed
		break
	}
	if head == nil {
		return nil, issue
	}

	bpb := uint64(head.bytesPerBlock)
	privateStartByte, err := blocksToBytes(head.configStart, bpb, "private region start")
	if err != nil {
		return nil, err
	}

	// The TOCBLOCK pairs are at the head and tail of the private region; the
	// PRIVHEAD's own TOC addresses are preferred when they point inside it.
	tocBlocks := make(map[uint64]struct{})
	addTOC := func(block uint64) {
		if block < head.configSize {
			tocBlocks[block] = struct{}{}
		}
	}
	addTOC(1)
	addTOC(2)
	addTOC(saturatingSub(head.configSize, 3))
	addTOC(saturatingSub(head.configSize, 2))
	for _, block := range []uint64{head.tocPrimary, head.tocSecondary} {
		if block < head.configSize {
			tocBlocks[block] = struct{}{}
			if block > 0 {
				tocBlocks[block-1] = struct{}{}
			}
			tocBlocks[block+1] = struct{}{}
		}
	}
	blockList := make([]uint64, 0, len(tocBlocks))
	for block := range tocBlocks {
		blockList = append(blockList, block)
	}
	sort.Slice(blockList, func(i, j int) bool { return blockList[i] < blockList[j] })

	var tocIssue error
	type tocCopy struct {
		block uint64
		toc   *tocBlock
	}
	var tocCopies []tocCopy
	for _, block := range blockList {
		offset, err := blocksToBytes(block, bpb, "TOCBLOCK offset")
		if err != nil {
			return nil, err
		}
		at, ok := addChecked(privateStartByte, offset)
		if !ok {
			return nil, corruptf("LDM TOCBLOCK offset overflows u64")
		}
		bytes, err := source.ReadVecAt(src, at, structBytes)
		if err != nil {
			return nil, err
		}
		if string(bytes[0:8]) != TOCBlockMagic {
			continue
		}
		toc, err := parseTOCBlock(bytes)
		if err == nil {
			err = checkTOCBlock(toc, head)
		}
		if err != nil {
			if tocIssue == nil {
				tocIssue = err
			}
			continue
		}
		tocCopies = append(tocCopies, tocCopy{block: block, toc: toc})
	}
	if len(tocCopies) == 0 {
		if tocIssue != nil {
			return nil, tocIssue
		}
		return nil, corruptf("no TOCBLOCK at the head or the tail of the %d-block private region", head.configSize)
	}
	selected := tocCopies[0]
	toc := selected.toc
	// The head and tail copies are independent witnesses. A valid copy that
	// names a different config region is not silently preferred: the reader
	// cannot tell which copy the writer last committed.
	for _, other := range tocCopies[1:] {
		if other.toc.configStart != toc.configStart || other.toc.configSize != toc.configSize {
			return nil, corruptf(
				"LDM TOCBLOCK copies disagree: block %d names config [%d, +%d) but block %d names [%d, +%d)",
				selected.block, toc.configStart, toc.configSize,
				other.block, other.toc.configStart, other.toc.configSize)
		}
	}
	copyKind := CopyHead
	if selected.block >= head.configSize/2 {
		copyKind = CopyTail
	}

	configStartBlock, ok := addChecked(head.configStart, toc.configStart)
	if !ok {
		return nil, corruptf("LDM config region start overflows u64")
	}
	dbByte, err := blocksToBytes(configStartBlock, bpb, "VMDB offset")
	if err != nil {
		return nil, err
	}
	if dbByte > length || structBytes > length-dbByte {
		return nil, corruptf("LDM VMDB at block %d (byte %d) runs past the %d-byte device", configStartBlock, dbByte, length)
	}
	vmdbBytes, err := source.ReadVecAt(src, dbByte, structBytes)
	if err != nil {
		return nil, err
	}
	if string(vmdbBytes[0:4]) != VMDBMagic {
		return nil, corruptf("no VMDB magic at byte %d (block %d)", dbByte, configStartBlock)
	}
	vmdb, err := parseVMDB(vmdbBytes)
	if err != nil {
		return nil, err
	}

	vblkSize := uint64(vmdb.vblkSize)
	streamStart, ok := addChecked(dbByte, uint64(vmdb.vblkOffset))
	if !ok {
		return nil, corruptf("LDM VBLK stream offset overflows u64")
	}
	streamBytes, ok := mulChecked(vblkSize, uint64(vmdb.lastSeq))
	if !ok {
		return nil, corruptf("LDM VBLK stream length overflows u64")
	}
	if streamBytes > maxVBLKStreamBytes {
		return nil, corruptf(
			"LDM VBLK stream declares %d bytes, more than this reader accepts (%d)",
			streamBytes, maxVBLKStreamBytes)
	}
	streamEnd, ok := addChecked(streamStart, streamBytes)
	if !ok {
		return nil, corruptf("LDM VBLK stream end overflows u64")
	}
	configEndBlock, ok := addChecked(configStartBlock, toc.configSize)
	if !ok {
		return nil, corruptf("LDM config region end overflows u64")
	}
	configEndByte, err := blocksToBytes(configEndBlock, bpb, "config region end")
	if err != nil {
		return nil, err
	}
	privateEndBlock, ok := addChecked(head.configStart, head.configSize)
	if !ok {
		return nil, corruptf("LDM private region end overflows u64")
	}
	privateEndByte, err := blocksToBytes(privateEndBlock, bpb, "private region end")
	if err != nil {
		return nil, err
	}
	if streamEnd > configEndByte {
		return nil, corruptf(
			"LDM VBLK stream [%d, %d) runs past the config region ending at %d",
			streamStart, streamEnd, configEndByte)
	}
	if streamEnd > privateEndByte || streamEnd > length {
		return nil, corruptf(
			"LDM VBLK stream [%d, %d) runs past the device's %d bytes",
			streamStart, streamEnd, length)
	}

	var stream []byte
	if streamBytes != 0 {
		stream, err = source.ReadVecAt(src, streamStart, streamBytes)
		if err != nil {
			return nil, err
		}
	}
	raw := &rawRecords{undecoded: make(map[uint8]int)}
	if err := readVBLKs(stream, int(vmdb.vblkSize), vmdb.lastSeq, raw); err != nil {
		return nil, err
	}
	return buildDatabase(head, vmdb, toc, copyKind, selectedAt, configStartBlock, streamStart, bpb, length, raw)
}

func blockUnit(src source.ByteSource) uint64 {
	unit := uint64(src.SectorSize())
	if unit >= 512 && unit&(unit-1) == 0 {
		return unit
	}
	return 512
}

func candidateOffsets(length, unit uint64) []uint64 {
	raw := []uint64{
		PrivHeadPrimaryBlock * 512,
		PrivHeadPrimaryBlock * unit,
		saturatingSub(length, unit),
		saturatingSub(length, 192*unit),
		saturatingSub(length, PrivHeadLastBlock*unit),
	}
	seen := make(map[uint64]struct{}, len(raw))
	out := make([]uint64, 0, len(raw))
	for _, at := range raw {
		if at <= length && privHeadBytes <= length-at {
			if _, ok := seen[at]; !ok {
				seen[at] = struct{}{}
				out = append(out, at)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type privHead struct {
	version       Version
	diskGUID      string
	diskGroup     string
	diskGroupGUID string
	bytesPerBlock uint32
	logicalStart  uint64
	logicalSize   uint64
	configStart   uint64
	configSize    uint64
	tocPrimary    uint64
	tocSecondary  uint64
}

// blockChecksum is the checksum the LDM reference defines for PRIVHEAD and
// TOCBLOCK sectors: the wrapping sum of every byte except the four checksum
// bytes at 0x08.
func blockChecksum(bytes []byte) uint32 {
	var sum uint32
	for offset, value := range bytes {
		if offset >= 0x08 && offset < 0x0C {
			continue
		}
		sum += uint32(value)
	}
	return sum
}

// checkBlockChecksum verifies the byte-sum checksum of a 512-byte PRIVHEAD or
// TOCBLOCK. The reference states the value's meaning but not the byte order in
// which Windows stores it; both orders are accepted. A corrupt sector whose
// sum matches neither is refused by name.
func checkBlockChecksum(bytes []byte, what string) error {
	if len(bytes) < 0x0C {
		return unexpectedEOFF(0)
	}
	computed := blockChecksum(bytes)
	storedBE := binary.BigEndian.Uint32(bytes[0x08:0x0C])
	storedLE := binary.LittleEndian.Uint32(bytes[0x08:0x0C])
	if computed != storedBE && computed != storedLE {
		return corruptf(
			"LDM %s checksum is %#010x (byte-reversed %#010x), but the sector sums to %#010x",
			what, storedBE, storedLE, computed)
	}
	return nil
}

func parsePrivHead(bytes []byte) (*privHead, error) {
	if len(bytes) < 512 {
		return nil, unexpectedEOFF(0)
	}
	if err := checkBlockChecksum(bytes, "PRIVHEAD"); err != nil {
		return nil, err
	}
	version := Version{Major: binary.BigEndian.Uint16(bytes[0x0C:]), Minor: binary.BigEndian.Uint16(bytes[0x0E:])}
	if version.Major != 2 || (version.Minor != 11 && version.Minor != 12) {
		return nil, unsupportedf("LDM PRIVHEAD version %d.%d (expected 2.11 or 2.12)", version.Major, version.Minor)
	}
	bytesPerBlock := binary.BigEndian.Uint32(bytes[0x10F:])
	if bytesPerBlock == 0 {
		bytesPerBlock = 512
	}
	if bytesPerBlock < 512 || bytesPerBlock&(bytesPerBlock-1) != 0 || bytesPerBlock > 65536 {
		return nil, corruptf(
			"LDM PRIVHEAD declares %d bytes per block, which is not a power of two between 512 and 65536",
			bytesPerBlock)
	}
	return &privHead{
		version:       version,
		diskGUID:      fixedString(bytes, 0x30, 64),
		diskGroup:     fixedString(bytes, 0xF0, 31),
		diskGroupGUID: fixedString(bytes, 0xB0, 64),
		bytesPerBlock: bytesPerBlock,
		logicalStart:  binary.BigEndian.Uint64(bytes[0x11B:]),
		logicalSize:   binary.BigEndian.Uint64(bytes[0x123:]),
		configStart:   binary.BigEndian.Uint64(bytes[0x12B:]),
		configSize:    binary.BigEndian.Uint64(bytes[0x133:]),
		tocPrimary:    binary.BigEndian.Uint64(bytes[0x13B:]),
		tocSecondary:  binary.BigEndian.Uint64(bytes[0x143:]),
	}, nil
}

func checkPrivHead(head *privHead, length uint64) error {
	bpb := uint64(head.bytesPerBlock)
	blocks := length / bpb
	if head.configSize == 0 {
		return corruptf("LDM PRIVHEAD declares a zero-length private region")
	}
	end, ok := addChecked(head.configStart, head.configSize)
	if !ok {
		return corruptf("LDM private region end overflows u64")
	}
	if end > blocks {
		return corruptf(
			"LDM private region [%d, +%d) ends at block %d, the device holds %d blocks",
			head.configStart, head.configSize, end, blocks)
	}
	if head.logicalSize == 0 {
		return corruptf("LDM PRIVHEAD declares a zero-length public region")
	}
	publicEnd, ok := addChecked(head.logicalStart, head.logicalSize)
	if !ok {
		return corruptf("LDM public region end overflows u64")
	}
	if publicEnd > head.configStart {
		return corruptf(
			"LDM public region [%d, +%d) overlaps the private region at %d",
			head.logicalStart, head.logicalSize, head.configStart)
	}
	return nil
}

type tocBlock struct {
	configStart uint64
	configSize  uint64
}

func parseTOCBlock(bytes []byte) (*tocBlock, error) {
	if len(bytes) < 512 {
		return nil, unexpectedEOFF(0)
	}
	if err := checkBlockChecksum(bytes, "TOCBLOCK"); err != nil {
		return nil, err
	}
	name := fixedString(bytes, 0x24, 8)
	if name != "config" {
		return nil, corruptf("LDM TOCBLOCK's first region is %q, not \"config\"", name)
	}
	configStart := binary.BigEndian.Uint64(bytes[0x2E:])
	configSize := binary.BigEndian.Uint64(bytes[0x36:])
	if configSize == 0 {
		return nil, corruptf("LDM TOCBLOCK declares a zero-length config region")
	}
	return &tocBlock{configStart: configStart, configSize: configSize}, nil
}

func checkTOCBlock(toc *tocBlock, head *privHead) error {
	end, ok := addChecked(toc.configStart, toc.configSize)
	if !ok {
		return corruptf("LDM config region end overflows u64")
	}
	if end > head.configSize {
		return corruptf(
			"LDM TOCBLOCK config region [%d, +%d) runs past the %d-block private region",
			toc.configStart, toc.configSize, head.configSize)
	}
	return nil
}

type vmdb struct {
	lastSeq    uint32
	vblkSize   uint32
	vblkOffset uint32
	status     uint16
	version    Version
	groupName  string
	groupGUID  string
	committed  VmdbCounts
	pending    VmdbCounts
}

func parseVMDB(bytes []byte) (*vmdb, error) {
	if len(bytes) < 512 {
		return nil, unexpectedEOFF(0)
	}
	version := Version{Major: binary.BigEndian.Uint16(bytes[0x12:]), Minor: binary.BigEndian.Uint16(bytes[0x14:])}
	if version.Major != 4 {
		return nil, unsupportedf("LDM VMDB version %d.%d (expected 4.x)", version.Major, version.Minor)
	}
	vblkSize := binary.BigEndian.Uint32(bytes[0x08:])
	if vblkSize < 32 || vblkSize > 512 || 512%vblkSize != 0 {
		return nil, corruptf(
			"LDM VMDB declares a %d-byte VBLK, which cannot tile a 512-byte block", vblkSize)
	}
	return &vmdb{
		lastSeq:    binary.BigEndian.Uint32(bytes[0x04:]),
		vblkSize:   vblkSize,
		vblkOffset: binary.BigEndian.Uint32(bytes[0x0C:]),
		status:     binary.BigEndian.Uint16(bytes[0x10:]),
		version:    version,
		groupName:  fixedString(bytes, 0x16, 31),
		groupGUID:  fixedString(bytes, 0x35, 64),
		committed:  countsAt(bytes, 0x85),
		pending:    countsAt(bytes, 0xA1),
	}, nil
}

func countsAt(bytes []byte, offset int) VmdbCounts {
	return VmdbCounts{
		Volumes:    binary.BigEndian.Uint32(bytes[offset:]),
		Components: binary.BigEndian.Uint32(bytes[offset+4:]),
		Partitions: binary.BigEndian.Uint32(bytes[offset+8:]),
		Disks:      binary.BigEndian.Uint32(bytes[offset+12:]),
	}
}

// buildDatabase turns the decoded records into the public database, joining
// partitions to their disks and components and volumes to their partitions.
func buildDatabase(
	head *privHead,
	vmdb *vmdb,
	toc *tocBlock,
	copyKind Copy,
	privHeadOffset uint64,
	configStartBlock uint64,
	streamStart uint64,
	bpb uint64,
	length uint64,
	raw *rawRecords,
) (*Database, error) {
	diskGUIDKey := normalizeGUID(head.diskGUID)
	var thisDiskID *uint64
	for i := range raw.disks {
		disk := &raw.disks[i]
		if diskGUIDKey == "" {
			continue
		}
		matches := false
		if disk.guid != nil && normalizeGUID(*disk.guid) == diskGUIDKey {
			matches = true
		}
		if !matches && disk.guidAlternate != nil && normalizeGUID(*disk.guidAlternate) == diskGUIDKey {
			matches = true
		}
		if matches {
			id := disk.id
			thisDiskID = &id
			break
		}
	}

	// A partition on this disk must fit the public region it was cut from and
	// the device the image holds. A foreign disk's geometry is not known here,
	// so its extents are reported but not checked.
	for i := range raw.partitions {
		partition := &raw.partitions[i]
		if thisDiskID == nil || partition.diskID != *thisDiskID {
			continue
		}
		end, ok := addChecked(partition.startLBA, partition.sizeSectors)
		if !ok {
			return nil, corruptf("LDM partition end overflows u64")
		}
		if end > head.logicalSize {
			return nil, corruptf(
				"LDM partition %d [%d, +%d) ends at sector %d, past the %d-sector public region",
				partition.id, partition.startLBA, partition.sizeSectors, end, head.logicalSize)
		}
		absoluteEnd, ok := addChecked(head.logicalStart, end)
		if ok {
			absoluteEnd, ok = mulChecked(absoluteEnd, bpb)
		}
		if !ok {
			return nil, corruptf("LDM partition byte offset overflows u64")
		}
		if absoluteEnd > length {
			return nil, corruptf(
				"LDM partition %d ends at byte %d, past the %d-byte device",
				partition.id, absoluteEnd, length)
		}
	}

	disks := make([]Disk, 0, len(raw.disks))
	for i := range raw.disks {
		disk := &raw.disks[i]
		disks = append(disks, Disk{
			ID:       disk.id,
			Name:     disk.name,
			GUID:     disk.guid,
			ThisDisk: thisDiskID != nil && *thisDiskID == disk.id,
		})
	}
	var unresolved []Partition
	for i := range raw.partitions {
		partition := &raw.partitions[i]
		// A partition inherits its component's assembly geometry. The records
		// are independent, so the join is done here rather than assuming an
		// order in the VBLK stream.
		var component *componentRecord
		if partition.componentID != nil {
			component = raw.componentByID(*partition.componentID)
		}
		var chunkBlocks *uint64
		if component != nil && component.volumeID != nil {
			if volume := raw.volumeByID(*component.volumeID); volume != nil {
				chunkBlocks = volume.chunkBlocks
			}
		}
		entry := Partition{
			ID:              partition.id,
			Name:            partition.name,
			DiskID:          partition.diskID,
			ComponentID:     partition.componentID,
			StartLBA:        partition.startLBA,
			VolumeOffset:    partition.volumeOffset,
			SizeSectors:     partition.sizeSectors,
			Flags:           partition.flags,
			Column:          partition.column,
			ChunkBlocks:     chunkBlocks,
			ComponentLayout: LayoutUnknown,
		}
		if component != nil {
			entry.StripeBlocks = component.stripeBlocks
			entry.Columns = component.columns
			entry.ComponentLayout = component.layout
		}
		attached := false
		for di := range disks {
			if disks[di].ID == partition.diskID {
				disks[di].Partitions = append(disks[di].Partitions, entry)
				attached = true
				break
			}
		}
		if !attached {
			unresolved = append(unresolved, entry)
		}
	}
	for di := range disks {
		partitions := disks[di].Partitions
		sort.SliceStable(partitions, func(i, j int) bool { return partitions[i].StartLBA < partitions[j].StartLBA })
	}

	components := make([]*componentRecord, 0, len(raw.components))
	for i := range raw.components {
		components = append(components, &raw.components[i])
	}
	sort.SliceStable(components, func(i, j int) bool { return components[i].id < components[j].id })

	volumes := make([]Volume, 0, len(raw.volumes))
	for i := range raw.volumes {
		volume := &raw.volumes[i]
		var volumeComponents []*componentRecord
		for _, component := range components {
			if component.volumeID != nil && *component.volumeID == volume.id {
				volumeComponents = append(volumeComponents, component)
			}
		}
		var extents []Extent
		for _, component := range volumeComponents {
			var partitions []*partitionRecord
			for pi := range raw.partitions {
				partition := &raw.partitions[pi]
				if partition.componentID != nil && *partition.componentID == component.id {
					partitions = append(partitions, partition)
				}
			}
			sort.SliceStable(partitions, func(i, j int) bool {
				if partitions[i].volumeOffset != partitions[j].volumeOffset {
					return partitions[i].volumeOffset < partitions[j].volumeOffset
				}
				return partitions[i].startLBA < partitions[j].startLBA
			})
			for _, partition := range partitions {
				onThisDisk := thisDiskID != nil && partition.diskID == *thisDiskID
				var offset *uint64
				if onThisDisk {
					value, ok := addChecked(head.logicalStart, partition.startLBA)
					if ok {
						value, ok = mulChecked(value, bpb)
					}
					if !ok {
						return nil, corruptf("LDM partition byte offset overflows u64")
					}
					offset = &value
				}
				extentLen, ok := mulChecked(partition.sizeSectors, bpb)
				if !ok {
					return nil, corruptf("LDM partition byte length overflows u64")
				}
				var diskName *string
				for di := range raw.disks {
					if raw.disks[di].id == partition.diskID {
						diskName = raw.disks[di].name
						break
					}
				}
				extents = append(extents, Extent{
					PartitionID:  partition.id,
					DiskID:       partition.diskID,
					DiskName:     diskName,
					OnThisDisk:   onThisDisk,
					StartLBA:     partition.startLBA,
					VolumeOffset: partition.volumeOffset,
					Sectors:      partition.sizeSectors,
					Offset:       offset,
					Len:          extentLen,
				})
			}
		}
		sort.SliceStable(extents, func(i, j int) bool {
			if extents[i].VolumeOffset != extents[j].VolumeOffset {
				return extents[i].VolumeOffset < extents[j].VolumeOffset
			}
			return extents[i].StartLBA < extents[j].StartLBA
		})

		layout := LayoutUnknown
		if len(volumeComponents) > 1 {
			layout = LayoutMirrored
		} else if len(volumeComponents) == 1 {
			layout = volumeComponents[0].layout
		}
		spansDisks := thisDiskID != nil
		if spansDisks {
			spansDisks = false
			for _, extent := range extents {
				if !extent.OnThisDisk {
					spansDisks = true
					break
				}
			}
		}
		volumeRange, err := computeVolumeRange(volume, layout, extents, thisDiskID != nil, bpb)
		if err != nil {
			return nil, err
		}
		componentIDs := make([]uint64, 0, len(volumeComponents))
		for _, component := range volumeComponents {
			componentIDs = append(componentIDs, component.id)
		}
		size := volume.sizeSectors
		partitionType := volume.partitionType
		volumes = append(volumes, Volume{
			ID:                 volume.id,
			Name:               volume.name,
			VolumeType:         volume.volumeType,
			State:              volume.state,
			SizeSectors:        &size,
			DriveHint:          volume.driveHint,
			PartitionType:      &partitionType,
			GUID:               volume.guid,
			DeclaredComponents: volume.componentCount,
			ComponentIDs:       componentIDs,
			Layout:             layout,
			Extents:            extents,
			Range:              volumeRange,
			SpansDisks:         spansDisks,
		})
	}
	sort.SliceStable(volumes, func(i, j int) bool { return volumes[i].ID < volumes[j].ID })

	groupName := firstNonEmpty([]*string{
		stringPtrIfNotEmpty(vmdb.groupName),
		stringPtrIfNotEmpty(head.diskGroup),
	})
	if groupName == nil && len(raw.groups) > 0 {
		groupName = raw.groups[0].name
	}
	groupGUID := firstNonEmpty([]*string{
		stringPtrIfNotEmpty(vmdb.groupGUID),
		stringPtrIfNotEmpty(head.diskGroupGUID),
	})
	if groupGUID == nil && len(raw.groups) > 0 {
		groupGUID = raw.groups[0].guid
	}

	// The VMDB states how many volume, component, partition and disk VBLKs the
	// committed database holds. A clean database whose records do not decode to
	// those counts is inconsistent evidence, so the disagreement is refused by
	// name. An unclean database is still parsed and flagged.
	decodedCounts := VmdbCounts{
		Volumes:    uint32(len(raw.volumes)),
		Components: uint32(len(raw.components)),
		Partitions: uint32(len(raw.partitions)),
		Disks:      uint32(len(raw.disks)),
	}
	if vmdb.status == 1 && decodedCounts != vmdb.committed {
		return nil, corruptf(
			"LDM VMDB declares %d committed volume, %d component, %d partition and %d disk "+
				"VBLK(s), but %d volume, %d component, %d partition and %d disk record(s) decoded",
			vmdb.committed.Volumes, vmdb.committed.Components, vmdb.committed.Partitions, vmdb.committed.Disks,
			decodedCounts.Volumes, decodedCounts.Components, decodedCounts.Partitions, decodedCounts.Disks)
	}

	kinds := make([]uint8, 0, len(raw.undecoded))
	for kind := range raw.undecoded {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	undecoded := make([]KindCount, 0, len(kinds))
	for _, kind := range kinds {
		undecoded = append(undecoded, KindCount{Kind: kind, Label: KindLabel(kind), Count: raw.undecoded[kind]})
	}

	diskGUID := stringPtrIfNotEmpty(head.diskGUID)
	db := &Database{
		DiskGUID:         diskGUID,
		DiskGroup:        groupName,
		DiskGroupGUID:    groupGUID,
		Version:          head.version,
		BytesPerBlock:    head.bytesPerBlock,
		PublicRegion:     Region{StartLBA: head.logicalStart, Sectors: head.logicalSize},
		PrivateRegion:    Region{StartLBA: head.configStart, Sectors: head.configSize},
		ConfigRegion:     Region{StartLBA: configStartBlock, Sectors: toc.configSize},
		PrivHeadOffset:   privHeadOffset,
		Copy:             copyKind,
		VMDBVersion:      vmdb.version,
		UpdateStatus:     vmdb.status,
		Clean:            vmdb.status == 1,
		CommittedCounts:  vmdb.committed,
		PendingCounts:    vmdb.pending,
		VBLKCount:        vmdb.lastSeq,
		VBLKSize:         vmdb.vblkSize,
		VBLKOffset:       vmdb.vblkOffset,
		VBLKStart:        streamStart,
		ThisDiskID:       thisDiskID,
		VolumeCount:      len(volumes),
		PartitionCount:   len(raw.partitions),
		RecordsSkipped:   raw.skipped,
		MalformedRecords: raw.malformed,
		UndecodedKinds:   undecoded,
		Groups: []Group{{
			Name:                 groupName,
			GUID:                 groupGUID,
			Disks:                disks,
			Volumes:              volumes,
			UnresolvedPartitions: unresolved,
		}},
	}
	return db, nil
}

// computeVolumeRange returns a contiguous byte range only for a single
// concatenated component whose extents are physically contiguous on this disk
// and whose declared size matches the sum. Anything else is reported as no
// contiguous range.
func computeVolumeRange(volume *volumeRecord, layout Layout, extents []Extent, diskKnown bool, bpb uint64) (*Range, error) {
	if !diskKnown || layout != LayoutConcatenated || len(extents) == 0 {
		return nil, nil
	}
	for _, extent := range extents {
		if !extent.OnThisDisk {
			return nil, nil
		}
	}
	if extents[0].Offset == nil || extents[0].VolumeOffset != 0 {
		return nil, nil
	}
	firstOffset := *extents[0].Offset
	var running uint64
	for _, extent := range extents {
		if extent.VolumeOffset != running {
			return nil, nil
		}
		if extent.Offset == nil {
			return nil, nil
		}
		bytesOffset, ok := mulChecked(extent.VolumeOffset, bpb)
		if ok {
			bytesOffset, ok = addChecked(firstOffset, bytesOffset)
		}
		if !ok {
			return nil, corruptf("LDM volume extent offset overflows u64")
		}
		if *extent.Offset != bytesOffset {
			return nil, nil
		}
		var okAdd bool
		running, okAdd = addChecked(running, extent.Sectors)
		if !okAdd {
			return nil, corruptf("LDM volume size overflows u64")
		}
	}
	if volume.sizeSectors != running {
		return nil, nil
	}
	length, ok := mulChecked(running, bpb)
	if !ok {
		return nil, corruptf("LDM volume byte length overflows u64")
	}
	return &Range{Offset: firstOffset, Len: length}, nil
}

func firstNonEmpty(values []*string) *string {
	for _, value := range values {
		if value != nil && *value != "" {
			return value
		}
	}
	return nil
}

func stringPtrIfNotEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func normalizeGUID(text string) string {
	var b strings.Builder
	for _, character := range text {
		switch {
		case character >= '0' && character <= '9',
			character >= 'a' && character <= 'f',
			character >= 'A' && character <= 'F':
			b.WriteRune(unicode.ToLower(character))
		}
	}
	return b.String()
}

func formatGUIDBytes(bytes []byte) string {
	if len(bytes) != 16 {
		return ""
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexBytes(bytes[0:4]), hexBytes(bytes[4:6]), hexBytes(bytes[6:8]),
		hexBytes(bytes[8:10]), hexBytes(bytes[10:16]))
}

// formatGUIDBytesMixed renders the same bytes as a Microsoft GUID struct,
// whose first three fields are little-endian. It is used only to match a
// revision-4 disk record against the PRIVHEAD's textual disk GUID; the record's
// own bytes are not reordered for display.
func formatGUIDBytesMixed(bytes []byte) string {
	if len(bytes) != 16 {
		return ""
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexBytes([]byte{bytes[3], bytes[2], bytes[1], bytes[0]}),
		hexBytes([]byte{bytes[5], bytes[4]}),
		hexBytes([]byte{bytes[7], bytes[6]}),
		hexBytes(bytes[8:10]), hexBytes(bytes[10:16]))
}

func hexBytes(bytes []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(bytes)*2)
	for _, b := range bytes {
		out = append(out, digits[b>>4], digits[b&0x0F])
	}
	return string(out)
}

func fixedString(bytes []byte, offset, length int) string {
	if offset < 0 || length < 0 || offset > len(bytes) || length > len(bytes)-offset {
		return ""
	}
	raw := bytes[offset : offset+length]
	end := len(raw)
	for i, b := range raw {
		if b == 0 {
			end = i
			break
		}
	}
	text := strings.ToValidUTF8(string(raw[:end]), "�")
	return strings.TrimRightFunc(text, unicode.IsSpace)
}

func layoutFromByte(value uint8) Layout {
	switch value {
	case 1:
		return LayoutStripe
	case 2:
		return LayoutConcatenated
	case 3:
		return LayoutRaid5
	default:
		return LayoutUnknown
	}
}

func corruptf(format string, args ...any) error {
	return fmt.Errorf("ldm: %w: %s", source.ErrCorrupt, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("ldm: %w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

func unexpectedEOFF(offset uint64) error {
	return fmt.Errorf("ldm: %w: truncated structure at byte %d", source.ErrUnexpectedEOF, offset)
}

func blocksToBytes(blocks, bpb uint64, what string) (uint64, error) {
	value, ok := mulChecked(blocks, bpb)
	if !ok {
		return 0, corruptf("LDM %s overflows u64", what)
	}
	return value, nil
}

func addChecked(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

func mulChecked(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	product := a * b
	if product/b != a {
		return 0, false
	}
	return product, true
}

func saturatingSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
