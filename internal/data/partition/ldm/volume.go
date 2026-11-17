package ldm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// DiskMember is one member disk image and the LDM database read from it.
//
// The database is needed for the disk's identity (DiskGUID, ThisDiskID, disk
// name) and for its public-region origin, which turns a partition's
// disk-relative start into an image offset. Source is the image those bytes
// are read from.
type DiskMember struct {
	Source   source.ByteSource
	Database *Database
}

// NewDiskMember pairs a member image with its parsed database.
func NewDiskMember(src source.ByteSource, database *Database) DiskMember {
	return DiskMember{Source: src, Database: database}
}

// Disk returns the disk record this member's database says the image is, when
// it identifies one.
func (m DiskMember) Disk() *Disk {
	if m.Database == nil {
		return nil
	}
	for i := range m.Database.Groups {
		for j := range m.Database.Groups[i].Disks {
			if m.Database.Groups[i].Disks[j].ThisDisk {
				return &m.Database.Groups[i].Disks[j]
			}
		}
	}
	if m.Database.ThisDiskID != nil {
		return m.Database.Disk(*m.Database.ThisDiskID)
	}
	return nil
}

func (m DiskMember) label() string {
	if disk := m.Disk(); disk != nil {
		if disk.Name != nil {
			return fmt.Sprintf("`%s` (id %d)", *disk.Name, disk.ID)
		}
		return fmt.Sprintf("id %d", disk.ID)
	}
	if m.Database != nil && m.Database.DiskGUID != nil {
		return fmt.Sprintf("disk `%s`", *m.Database.DiskGUID)
	}
	return "an unidentified disk"
}

// Span is one extent's placement in a concatenated volume's logical byte
// stream.
//
// PartitionID is the VBLK partition record's object id, so a byte range mapped
// to ImageOffset .. ImageOffset+Len names the extent it came from. A striped,
// mirrored or RAID-5 volume has no single logical order; its physical extents
// are reported through Placement instead.
type Span struct {
	PartitionID uint64
	// VolumeOffset is the byte offset of the extent in the volume.
	VolumeOffset uint64
	// ImageOffset is the byte offset of the extent in the evidence image.
	ImageOffset uint64
	Len         uint64
}

// Placement is one physical extent and the member disk that holds it.
//
// A placement is emitted for every column of a stripe or RAID-5 set (a missing
// column has no Member and no ImageOffset) and for every extent of a
// concatenated or mirrored volume. A mirrored volume's placements carry the
// copy index, so a report can say which copy was read and which others were
// available.
type Placement struct {
	PartitionID uint64
	// ComponentID is the component record that owns the partition, when the
	// database names one.
	ComponentID uint64
	DiskID      uint64
	DiskName    *string
	DiskGUID    *string
	// Member is the index into the member slice handed to AssembleVolume,
	// when this disk's bytes are available.
	Member *int
	// ImageOffset is the byte offset of the extent in that member's image.
	ImageOffset *uint64
	Len         uint64
	// Column is the column index for a striped or RAID-5 volume.
	Column *uint64
	// Copy is the copy (component position) for a mirrored volume.
	Copy *int
}

// RedundancyKind is the class of redundancy a layout provides.
type RedundancyKind uint8

const (
	// RedundancyNone means a concatenated or striped volume: no redundancy.
	RedundancyNone RedundancyKind = iota
	// RedundancyMirrored means a mirrored volume: complete copies exist.
	RedundancyMirrored
	// RedundancyParity means a RAID-5 volume: one column can be rebuilt.
	RedundancyParity
)

// Redundancy reports whether a layout can still serve every byte it holds.
type Redundancy struct {
	Kind RedundancyKind
	// Mirrored: Copies is the number of components, Readable how many complete
	// copies survive, and Chosen which copy answers reads.
	Copies   int
	Readable int
	Chosen   int
	// Parity: Columns is the column count, DataColumns the data columns, and
	// Missing the columns rebuilt from parity while reading.
	Columns     int
	DataColumns int
	Missing     []uint64
}

// Degraded reports whether some redundancy is gone: a mirror lost a copy, or a
// parity set lost a column.
func (r Redundancy) Degraded() bool {
	switch r.Kind {
	case RedundancyMirrored:
		return r.Readable < r.Copies
	case RedundancyParity:
		return len(r.Missing) > 0
	default:
		return false
	}
}

// Label returns "none", "mirrored" or "parity".
func (r Redundancy) Label() string {
	switch r.Kind {
	case RedundancyMirrored:
		return "mirrored"
	case RedundancyParity:
		return "parity"
	default:
		return "none"
	}
}

// VolumeErrorKind identifies why a volume could not be exposed as one logical
// byte stream.
type VolumeErrorKind uint8

const (
	// VolumeErrUnsupportedLayout: the layout is not one this reader assembles.
	VolumeErrUnsupportedLayout VolumeErrorKind = iota
	// VolumeErrNoExtents: the database attached no extent to the volume.
	VolumeErrNoExtents
	// VolumeErrExtentOnOtherDisk: an extent lives on a disk this image does
	// not hold.
	VolumeErrExtentOnOtherDisk
	// VolumeErrMissingOffset: the extent claims this disk but has no byte
	// offset.
	VolumeErrMissingOffset
	// VolumeErrZeroLengthExtent: an extent of zero bytes cannot be a piece.
	VolumeErrZeroLengthExtent
	// VolumeErrDoesNotStartAtZero: the first extent does not begin at logical
	// byte zero.
	VolumeErrDoesNotStartAtZero
	// VolumeErrNotContiguous: extents leave a gap or overlap.
	VolumeErrNotContiguous
	// VolumeErrSizeMismatch: the joined extents do not match the declared size.
	VolumeErrSizeMismatch
	// VolumeErrOutsideImage: an extent's image range reaches past the evidence.
	VolumeErrOutsideImage
	// VolumeErrOverflow: a length or offset did not fit in uint64.
	VolumeErrOverflow
	// VolumeErrMissingMember: no supplied member holds an extent's disk.
	VolumeErrMissingMember
	// VolumeErrAmbiguousMember: more than one supplied member claims the disk.
	VolumeErrAmbiguousMember
	// VolumeErrInconsistentBlockSize: a member addresses storage in a different
	// block size than the database.
	VolumeErrInconsistentBlockSize
	// VolumeErrMissingPartition: the extent names a partition the database no
	// longer describes.
	VolumeErrMissingPartition
	// VolumeErrMissingComponent: the volume names a component whose partitions
	// are absent.
	VolumeErrMissingComponent
	// VolumeErrMultipleComponents: a stripe or RAID-5 volume should have one
	// component.
	VolumeErrMultipleComponents
	// VolumeErrMissingStripeGeometry: a stripe or RAID-5 component records no
	// usable stripe unit.
	VolumeErrMissingStripeGeometry
	// VolumeErrMissingColumnCount: a stripe or RAID-5 component records no
	// usable column count.
	VolumeErrMissingColumnCount
	// VolumeErrMissingColumn: a partition of a stripe names no column.
	VolumeErrMissingColumn
	// VolumeErrDuplicateColumn: two partitions of one component claim the same
	// column.
	VolumeErrDuplicateColumn
	// VolumeErrColumnOutOfRange: a partition's column is at or beyond the
	// component's column count.
	VolumeErrColumnOutOfRange
	// VolumeErrColumnCountMismatch: the component's partitions do not match its
	// column count.
	VolumeErrColumnCountMismatch
	// VolumeErrStripeUnitMismatch: the component and volume disagree about the
	// stripe unit.
	VolumeErrStripeUnitMismatch
	// VolumeErrUnequalColumns: the columns do not all have the same length.
	VolumeErrUnequalColumns
	// VolumeErrColumnTooShort: a column is too short for the chunks it must
	// hold.
	VolumeErrColumnTooShort
	// VolumeErrEmptyVolume: the volume declares no length and nothing supplies
	// one.
	VolumeErrEmptyVolume
	// VolumeErrTooManyMissing: a RAID-5 set is missing more columns than parity
	// can rebuild.
	VolumeErrTooManyMissing
	// VolumeErrNoCompleteCopy: no component of a mirrored volume is complete.
	VolumeErrNoCompleteCopy
	// VolumeErrUnsupportedComponentLayout: a mirror component is itself
	// striped, which this reader does not nest.
	VolumeErrUnsupportedComponentLayout
)

// VolumeError is the structured refusal returned by OpenVolume and
// AssembleVolume. Callers test Kind; the remaining fields carry the record
// numbers and lengths a report needs without parsing the message.
type VolumeError struct {
	Kind          VolumeErrorKind
	Layout        string
	Extents       int
	PartitionID   uint64
	DiskID        uint64
	DiskName      *string
	ComponentID   uint64
	Column        uint64
	Columns       uint64
	Expected      uint64
	Found         uint64
	Declared      uint64
	Assembled     uint64
	Offset        uint64
	Len           uint64
	ImageLen      uint64
	What          string
	Member        string
	ExpectedBlock uint32
	FoundBlock    uint32
	Copies        int
	Readable      int
	Components    int
	Candidates    int
	// MissingColumns lists the RAID-5 columns parity cannot supply.
	MissingColumns []uint64
	// Missing labels the member disks a mirror lost.
	Missing []string
}

func (e *VolumeError) Error() string {
	switch e.Kind {
	case VolumeErrUnsupportedLayout:
		return fmt.Sprintf(
			"layout `%s` across %d extent(s) is not assembled by the single-image reader; "+
				"supply every member disk and use the multi-disk assembly, or read a concatenated volume here",
			e.Layout, e.Extents)
	case VolumeErrNoExtents:
		return "the volume record has no extent the database attached to it"
	case VolumeErrExtentOnOtherDisk:
		if e.DiskName != nil {
			return fmt.Sprintf("extent %d lives on disk `%s`, which this image does not hold", e.PartitionID, *e.DiskName)
		}
		return fmt.Sprintf("extent %d lives on a disk this image does not hold", e.PartitionID)
	case VolumeErrMissingOffset:
		return fmt.Sprintf("extent %d is on this disk but has no byte offset", e.PartitionID)
	case VolumeErrZeroLengthExtent:
		return fmt.Sprintf("extent %d is zero bytes long", e.PartitionID)
	case VolumeErrDoesNotStartAtZero:
		return fmt.Sprintf("the first extent starts at volume byte %d, not zero", e.Found)
	case VolumeErrNotContiguous:
		kind := "gap"
		if e.Found <= e.Expected {
			kind = "overlap"
		}
		return fmt.Sprintf(
			"extent at volume byte %d follows one ending at %d; the extents have a %s",
			e.Found, e.Expected, kind)
	case VolumeErrSizeMismatch:
		return fmt.Sprintf(
			"the volume record declares %d bytes but its extents join to %d", e.Declared, e.Assembled)
	case VolumeErrOutsideImage:
		return fmt.Sprintf(
			"extent %d [%d, +%d) falls outside the %d-byte image", e.PartitionID, e.Offset, e.Len, e.ImageLen)
	case VolumeErrOverflow:
		return fmt.Sprintf("LDM %s overflows u64", e.What)
	case VolumeErrMissingMember:
		if e.DiskName != nil {
			return fmt.Sprintf(
				"extent %d lives on disk `%s` (id %d), which is not among the supplied member images",
				e.PartitionID, *e.DiskName, e.DiskID)
		}
		return fmt.Sprintf(
			"extent %d lives on disk id %d, which is not among the supplied member images",
			e.PartitionID, e.DiskID)
	case VolumeErrAmbiguousMember:
		if e.DiskName != nil {
			return fmt.Sprintf(
				"%d supplied members claim disk `%s` (id %d); refusing to choose which bytes are the disk",
				e.Candidates, *e.DiskName, e.DiskID)
		}
		return fmt.Sprintf(
			"%d supplied members claim disk id %d; refusing to choose which bytes are the disk",
			e.Candidates, e.DiskID)
	case VolumeErrInconsistentBlockSize:
		return fmt.Sprintf(
			"member %s addresses storage in %d-byte blocks, but the database's volume uses %d-byte blocks",
			e.Member, e.FoundBlock, e.ExpectedBlock)
	case VolumeErrMissingPartition:
		return fmt.Sprintf(
			"the volume names partition %d, which the database no longer describes", e.PartitionID)
	case VolumeErrMissingComponent:
		return fmt.Sprintf(
			"volume %d names no component whose partitions the database describes", e.ComponentID)
	case VolumeErrMultipleComponents:
		return fmt.Sprintf(
			"the `%s` volume has %d components; only one is mapped, so the stripe geometry is ambiguous",
			e.Layout, e.Components)
	case VolumeErrMissingStripeGeometry:
		return fmt.Sprintf(
			"component %d records no stripe unit; refusing to guess the stripe size", e.ComponentID)
	case VolumeErrMissingColumnCount:
		return fmt.Sprintf(
			"component %d records no column count; refusing to guess how the stripes interleave", e.ComponentID)
	case VolumeErrMissingColumn:
		return fmt.Sprintf(
			"partition %d of a stripe set names no column; refusing to guess its place in the stripe", e.PartitionID)
	case VolumeErrDuplicateColumn:
		return fmt.Sprintf("two partitions of one component claim column %d", e.Column)
	case VolumeErrColumnOutOfRange:
		return fmt.Sprintf(
			"partition claims column %d, but the component records only %d column(s)", e.Column, e.Columns)
	case VolumeErrColumnCountMismatch:
		return fmt.Sprintf(
			"the component records %d column(s) but %d partition(s) belong to it", e.Columns, e.Components)
	case VolumeErrStripeUnitMismatch:
		return fmt.Sprintf(
			"component %d records a %d-block stripe unit but the volume record says %d; refusing to choose",
			e.ComponentID, e.Expected, e.Found)
	case VolumeErrUnequalColumns:
		return fmt.Sprintf(
			"the stripe columns have unequal lengths (%d and %d bytes); the layout is not one this reader can place",
			e.Expected, e.Found)
	case VolumeErrColumnTooShort:
		return fmt.Sprintf(
			"column %d is %d bytes but must hold %d bytes of the volume", e.Column, e.Found, e.Expected)
	case VolumeErrEmptyVolume:
		return "the volume declares no length"
	case VolumeErrTooManyMissing:
		return fmt.Sprintf(
			"the image holds %d of the RAID-5 columns; %d are missing (%v) and parity can rebuild only one",
			e.Columns, len(e.MissingColumns), e.MissingColumns)
	case VolumeErrNoCompleteCopy:
		missing := "(none named)"
		if len(e.Missing) > 0 {
			missing = strings.Join(e.Missing, ", ")
		}
		return fmt.Sprintf(
			"the image holds %d complete copy of %d of the mirrored volume; the missing disk(s) %s leave no complete copy",
			e.Readable, e.Copies, missing)
	case VolumeErrUnsupportedComponentLayout:
		return fmt.Sprintf(
			"mirror component %d has layout `%s`; only a concatenated component can be a mirror copy",
			e.ComponentID, e.Layout)
	default:
		return "LDM volume assembly failed"
	}
}

// memberInfo is one supplied member after its disk identity is resolved.
type memberInfo struct {
	diskID   *uint64
	diskName *string
	source   source.ByteSource
}

type columnSlot struct {
	member      int
	imageOffset uint64
	len         uint64
}

type mappingKind uint8

const (
	mapConcatenated mappingKind = iota
	mapStripe
	mapParity
)

type volumeMapping struct {
	kind        mappingKind
	unit        uint64
	columns     uint64
	dataColumns uint64
	// slots holds one entry per physical column; a RAID-5 column that is
	// missing is nil.
	slots []*columnSlot
}

// VolumeSource is a read-only LDM volume over its extents.
type VolumeSource struct {
	id          source.ID
	imageID     source.ImageID
	name        string
	length      uint64
	mapping     volumeMapping
	spans       []Span
	spanMembers []int
	members     []memberInfo
	placements  []Placement
	redundancy  Redundancy
	counters    source.Counters
}

// Name returns the volume's name as the database records it.
func (s *VolumeSource) Name() string { return s.name }

// Spans returns every extent of a concatenated volume (or of the chosen mirror
// copy), in logical order.
func (s *VolumeSource) Spans() []Span { return s.spans }

// Placements returns every physical extent with the member disk that holds it.
func (s *VolumeSource) Placements() []Placement { return s.placements }

// Redundancy reports whether redundancy is intact, lost, or being used to
// rebuild bytes.
func (s *VolumeSource) Redundancy() Redundancy { return s.redundancy }

// SpanAt returns the span holding logical byte offset, for a concatenated
// volume or the chosen copy of a mirror.
func (s *VolumeSource) SpanAt(offset uint64) *Span {
	for i := range s.spans {
		span := &s.spans[i]
		if offset >= span.VolumeOffset && offset-span.VolumeOffset < span.Len {
			return span
		}
	}
	return nil
}

// PlacementAt returns the placement that supplies logical byte offset.
//
// For a mirror this is the chosen copy; for a RAID-5 set whose column is
// missing it names the placement with no member, because those bytes are
// rebuilt rather than stored.
func (s *VolumeSource) PlacementAt(offset uint64) *Placement {
	if offset >= s.length {
		return nil
	}
	switch s.mapping.kind {
	case mapConcatenated:
		span := s.SpanAt(offset)
		if span == nil {
			return nil
		}
		for i := range s.placements {
			placement := &s.placements[i]
			if placement.PartitionID == span.PartitionID &&
				placement.ImageOffset != nil && *placement.ImageOffset == span.ImageOffset {
				return placement
			}
		}
	case mapStripe:
		column := (offset / s.mapping.unit) % s.mapping.columns
		for i := range s.placements {
			placement := &s.placements[i]
			if placement.Column != nil && *placement.Column == column {
				return placement
			}
		}
	case mapParity:
		chunk := offset / s.mapping.unit
		stripe := chunk / s.mapping.dataColumns
		dataIndex := chunk % s.mapping.dataColumns
		column := dataColumn(stripe, dataIndex, s.mapping.columns)
		for i := range s.placements {
			placement := &s.placements[i]
			if placement.Column != nil && *placement.Column == column {
				return placement
			}
		}
	}
	return nil
}

// OpenVolume exposes a concatenated volume of the database read from parent.
//
// Every extent must live on this disk and carry a byte offset. The extents are
// sorted by VolumeOffset and must tile the volume from zero, with no gap and no
// overlap, and their total must equal the size the volume record states (when
// it states one).
func OpenVolume(id source.ID, parent source.ByteSource, volume *Volume) (*VolumeSource, error) {
	spans, err := planVolume(volume)
	if err != nil {
		return nil, err
	}
	var length uint64
	if len(spans) > 0 {
		last := spans[len(spans)-1]
		length = last.VolumeOffset + last.Len
	}
	imageLen := parent.Len()
	for _, span := range spans {
		if span.ImageOffset > imageLen || span.Len > imageLen-span.ImageOffset {
			return nil, &VolumeError{
				Kind: VolumeErrOutsideImage, PartitionID: span.PartitionID,
				Offset: span.ImageOffset, Len: span.Len, ImageLen: imageLen,
			}
		}
	}
	placements := make([]Placement, 0, len(spans))
	for i := range spans {
		span := &spans[i]
		var extent *Extent
		for j := range volume.Extents {
			if volume.Extents[j].PartitionID == span.PartitionID {
				extent = &volume.Extents[j]
				break
			}
		}
		placement := Placement{
			PartitionID: span.PartitionID,
			Member:      intPtr(0),
			ImageOffset: uint64Ptr(span.ImageOffset),
			Len:         span.Len,
		}
		if extent != nil {
			placement.DiskID = extent.DiskID
			placement.DiskName = extent.DiskName
		}
		placements = append(placements, placement)
	}
	name := ""
	if volume.Name != nil {
		name = *volume.Name
	}
	spanMembers := make([]int, len(spans))
	return &VolumeSource{
		id:          id,
		imageID:     parent.ImageID(),
		name:        name,
		length:      length,
		mapping:     volumeMapping{kind: mapConcatenated},
		spans:       spans,
		spanMembers: spanMembers,
		members:     []memberInfo{{source: parent}},
		placements:  placements,
	}, nil
}

// AssembleVolume assembles a volume from the database that names it and one
// image per member disk.
//
// owner is the database the volume reference came from; it describes the whole
// disk group, including partitions on disks not supplied. members may be in any
// order and may omit disks: a concatenated or striped volume then refuses by
// name, a mirror falls back to another complete copy, and a RAID-5 set rebuilds
// one missing column. Every member's database must address storage in the same
// block size as the owner's.
func AssembleVolume(id source.ID, owner *Database, volume *Volume, members []DiskMember) (*VolumeSource, error) {
	geometry := owner.VolumeGeometry(volume)
	placer := &placer{owner: owner, members: members, block: uint64(owner.BytesPerBlock)}
	if placer.block == 0 {
		placer.block = SectorBytes
	}
	switch volume.Layout {
	case LayoutConcatenated:
		return assembleConcatenated(id, volume, placer)
	case LayoutStripe:
		return assembleStripe(id, volume, &geometry, placer)
	case LayoutRaid5:
		return assembleRaid5(id, volume, &geometry, placer)
	case LayoutMirrored:
		return assembleMirrored(id, volume, &geometry, placer)
	default:
		return nil, &VolumeError{
			Kind: VolumeErrUnsupportedLayout, Layout: "unknown", Extents: len(volume.Extents),
		}
	}
}

func assembleConcatenated(id source.ID, volume *Volume, placer *placer) (*VolumeSource, error) {
	if len(volume.Extents) == 0 {
		return nil, &VolumeError{Kind: VolumeErrNoExtents}
	}
	block := placer.block
	extents := make([]*Extent, len(volume.Extents))
	for i := range volume.Extents {
		extents[i] = &volume.Extents[i]
		if extents[i].Sectors == 0 {
			return nil, &VolumeError{Kind: VolumeErrZeroLengthExtent, PartitionID: extents[i].PartitionID}
		}
	}
	sort.SliceStable(extents, func(i, j int) bool {
		if extents[i].VolumeOffset != extents[j].VolumeOffset {
			return extents[i].VolumeOffset < extents[j].VolumeOffset
		}
		return extents[i].PartitionID < extents[j].PartitionID
	})
	first, ok := mulChecked(extents[0].VolumeOffset, block)
	if !ok {
		return nil, &VolumeError{Kind: VolumeErrOverflow, What: "extent offset"}
	}
	if first != 0 {
		return nil, &VolumeError{Kind: VolumeErrDoesNotStartAtZero, Found: first}
	}

	spans := make([]Span, 0, len(extents))
	spanMembers := make([]int, 0, len(extents))
	placements := make([]Placement, 0, len(extents))
	var expected uint64
	for _, extent := range extents {
		found, ok := mulChecked(extent.VolumeOffset, block)
		if !ok {
			return nil, &VolumeError{Kind: VolumeErrOverflow, What: "extent offset"}
		}
		if found != expected {
			return nil, &VolumeError{Kind: VolumeErrNotContiguous, Expected: expected, Found: found}
		}
		partition, err := placer.partition(extent.PartitionID)
		if err != nil {
			return nil, err
		}
		member, foundMember, err := placer.resolve(extent.DiskID)
		if err != nil {
			return nil, err
		}
		if !foundMember {
			return nil, placer.missingMember(extent.DiskID, extent.PartitionID)
		}
		imageOffset, extentLen, err := placer.place(member, extent.StartLBA, extent.Sectors, extent.PartitionID)
		if err != nil {
			return nil, err
		}
		spans = append(spans, Span{
			PartitionID:  extent.PartitionID,
			VolumeOffset: found,
			ImageOffset:  imageOffset,
			Len:          extentLen,
		})
		spanMembers = append(spanMembers, member)
		placements = append(placements, placer.placement(
			partition, intPtr(member), uint64Ptr(imageOffset), extentLen, partition.Column, nil))
		expected, ok = addChecked(expected, extentLen)
		if !ok {
			return nil, &VolumeError{Kind: VolumeErrOverflow, What: "volume length"}
		}
	}

	declared, err := declaredBytes(volume, block)
	if err != nil {
		return nil, err
	}
	if declared != nil && *declared != expected {
		return nil, &VolumeError{Kind: VolumeErrSizeMismatch, Declared: *declared, Assembled: expected}
	}
	length := expected
	if declared != nil {
		length = *declared
	}
	if length == 0 {
		return nil, &VolumeError{Kind: VolumeErrEmptyVolume}
	}
	name := ""
	if volume.Name != nil {
		name = *volume.Name
	}
	return &VolumeSource{
		id:          id,
		imageID:     placer.firstImageID(),
		name:        name,
		length:      length,
		mapping:     volumeMapping{kind: mapConcatenated},
		spans:       spans,
		spanMembers: spanMembers,
		members:     placer.memberInfos(),
		placements:  placements,
	}, nil
}

func assembleStripe(id source.ID, volume *Volume, geometry *VolumeGeometry, placer *placer) (*VolumeSource, error) {
	component, err := singleComponent(geometry, "stripe")
	if err != nil {
		return nil, err
	}
	columns, err := requiredColumns(component, geometry)
	if err != nil {
		return nil, err
	}
	unitBlocks, err := requiredStripeBlocks(component, geometry)
	if err != nil {
		return nil, err
	}
	unit, ok := mulChecked(unitBlocks, placer.block)
	if !ok {
		return nil, &VolumeError{Kind: VolumeErrOverflow, What: "stripe unit"}
	}
	if unit == 0 {
		return nil, &VolumeError{Kind: VolumeErrMissingStripeGeometry, ComponentID: component.ID}
	}
	if uint64(len(component.Partitions)) != columns {
		return nil, &VolumeError{
			Kind: VolumeErrColumnCountMismatch, Columns: columns, Components: len(component.Partitions),
		}
	}

	slots := make([]*columnSlot, columns)
	placements := make([]Placement, 0, len(component.Partitions))
	for i := range component.Partitions {
		partition := &component.Partitions[i]
		if partition.Column == nil {
			return nil, &VolumeError{Kind: VolumeErrMissingColumn, PartitionID: partition.PartitionID}
		}
		column := *partition.Column
		if column >= columns {
			return nil, &VolumeError{Kind: VolumeErrColumnOutOfRange, Column: column, Columns: columns}
		}
		if slots[column] != nil {
			return nil, &VolumeError{Kind: VolumeErrDuplicateColumn, Column: column}
		}
		record, err := placer.partition(partition.PartitionID)
		if err != nil {
			return nil, err
		}
		member, foundMember, err := placer.resolve(partition.DiskID)
		if err != nil {
			return nil, err
		}
		if !foundMember {
			return nil, placer.missingMember(partition.DiskID, partition.PartitionID)
		}
		imageOffset, slotLen, err := placer.placePartition(member, partition)
		if err != nil {
			return nil, err
		}
		slots[column] = &columnSlot{member: member, imageOffset: imageOffset, len: slotLen}
		placements = append(placements, placer.placement(
			record, intPtr(member), uint64Ptr(imageOffset), slotLen, uint64Ptr(column), nil))
	}

	columnLen, err := equalColumnLength(placer, component.Partitions)
	if err != nil {
		return nil, err
	}
	capacity, ok := mulChecked(columnLen, columns)
	if !ok {
		return nil, &VolumeError{Kind: VolumeErrOverflow, What: "stripe capacity"}
	}
	length, err := volumeLength(volume, placer.block, capacity)
	if err != nil {
		return nil, err
	}
	totalChunks := divCeil(length, unit)
	for column := uint64(0); column < columns; column++ {
		need, ok := mulChecked(chunksInColumn(column, columns, totalChunks), unit)
		if !ok {
			return nil, &VolumeError{Kind: VolumeErrOverflow, What: "column length"}
		}
		have := uint64(0)
		if slots[column] != nil {
			have = slots[column].len
		}
		if have < need {
			return nil, &VolumeError{Kind: VolumeErrColumnTooShort, Column: column, Expected: need, Found: have}
		}
	}
	name := ""
	if volume.Name != nil {
		name = *volume.Name
	}
	return &VolumeSource{
		id:         id,
		imageID:    placer.firstImageID(),
		name:       name,
		length:     length,
		mapping:    volumeMapping{kind: mapStripe, unit: unit, columns: columns, slots: slots},
		members:    placer.memberInfos(),
		placements: placements,
	}, nil
}

func assembleRaid5(id source.ID, volume *Volume, geometry *VolumeGeometry, placer *placer) (*VolumeSource, error) {
	component, err := singleComponent(geometry, "raid5")
	if err != nil {
		return nil, err
	}
	columns, err := requiredColumns(component, geometry)
	if err != nil {
		return nil, err
	}
	unitBlocks, err := requiredStripeBlocks(component, geometry)
	if err != nil {
		return nil, err
	}
	unit, ok := mulChecked(unitBlocks, placer.block)
	if !ok {
		return nil, &VolumeError{Kind: VolumeErrOverflow, What: "stripe unit"}
	}
	if unit == 0 {
		return nil, &VolumeError{Kind: VolumeErrMissingStripeGeometry, ComponentID: component.ID}
	}
	if columns < 2 {
		return nil, &VolumeError{Kind: VolumeErrMissingColumnCount, ComponentID: component.ID}
	}
	dataColumns := columns - 1

	slots := make([]*columnSlot, columns)
	seen := make([]bool, columns)
	placements := make([]Placement, 0, len(component.Partitions))
	for i := range component.Partitions {
		partition := &component.Partitions[i]
		if partition.Column == nil {
			return nil, &VolumeError{Kind: VolumeErrMissingColumn, PartitionID: partition.PartitionID}
		}
		column := *partition.Column
		if column >= columns {
			return nil, &VolumeError{Kind: VolumeErrColumnOutOfRange, Column: column, Columns: columns}
		}
		if seen[column] {
			return nil, &VolumeError{Kind: VolumeErrDuplicateColumn, Column: column}
		}
		seen[column] = true
		record, err := placer.partition(partition.PartitionID)
		if err != nil {
			return nil, err
		}
		member, foundMember, err := placer.resolve(partition.DiskID)
		if err != nil {
			return nil, err
		}
		if foundMember {
			imageOffset, slotLen, err := placer.placePartition(member, partition)
			if err != nil {
				return nil, err
			}
			slots[column] = &columnSlot{member: member, imageOffset: imageOffset, len: slotLen}
			placements = append(placements, placer.placement(
				record, intPtr(member), uint64Ptr(imageOffset), slotLen, uint64Ptr(column), nil))
		} else {
			// One column may be rebuilt from parity; record it as a placement
			// with no member so a report can name the disk.
			slotLen, err := placer.columnLen(partition)
			if err != nil {
				return nil, err
			}
			placements = append(placements, placer.placement(
				record, nil, nil, slotLen, uint64Ptr(column), nil))
		}
	}
	missing := make([]uint64, 0, columns)
	for column := uint64(0); column < columns; column++ {
		if slots[column] == nil {
			missing = append(missing, column)
		}
	}
	if len(missing) > 1 {
		return nil, &VolumeError{
			Kind: VolumeErrTooManyMissing, Columns: columns, MissingColumns: missing,
		}
	}

	columnLen, err := equalColumnLength(placer, component.Partitions)
	if err != nil {
		return nil, err
	}
	capacity, ok := mulChecked(columnLen, dataColumns)
	if !ok {
		return nil, &VolumeError{Kind: VolumeErrOverflow, What: "RAID-5 capacity"}
	}
	length, err := volumeLength(volume, placer.block, capacity)
	if err != nil {
		return nil, err
	}
	totalChunks := divCeil(length, unit)
	stripes := divCeil(totalChunks, dataColumns)
	need, ok := mulChecked(stripes, unit)
	if !ok {
		return nil, &VolumeError{Kind: VolumeErrOverflow, What: "column length"}
	}
	for column := uint64(0); column < columns; column++ {
		have := uint64(0)
		if slots[column] != nil {
			have = slots[column].len
		} else if partition := partitionByColumn(component.Partitions, column); partition != nil {
			have, err = placer.columnLen(partition)
			if err != nil {
				return nil, err
			}
		}
		if have < need {
			return nil, &VolumeError{Kind: VolumeErrColumnTooShort, Column: column, Expected: need, Found: have}
		}
	}

	name := ""
	if volume.Name != nil {
		name = *volume.Name
	}
	return &VolumeSource{
		id:      id,
		imageID: placer.firstImageID(),
		name:    name,
		length:  length,
		mapping: volumeMapping{
			kind:        mapParity,
			unit:        unit,
			columns:     columns,
			dataColumns: dataColumns,
			slots:       slots,
		},
		members:    placer.memberInfos(),
		placements: placements,
		redundancy: Redundancy{
			Kind:        RedundancyParity,
			Columns:     int(columns),
			DataColumns: int(dataColumns),
			Missing:     missing,
		},
	}, nil
}

func assembleMirrored(id source.ID, volume *Volume, geometry *VolumeGeometry, placer *placer) (*VolumeSource, error) {
	if len(geometry.Components) == 0 {
		return nil, &VolumeError{Kind: VolumeErrMissingComponent, ComponentID: volume.ID}
	}
	declared, err := declaredBytes(volume, placer.block)
	if err != nil {
		return nil, err
	}
	type mirrorCopy struct {
		index       int
		spans       []Span
		spanMembers []int
		length      uint64
		complete    bool
	}
	var chosen *mirrorCopy
	var placements []Placement
	var missingLabels []string
	readable := 0

	for copyIndex := range geometry.Components {
		component := &geometry.Components[copyIndex]
		if component.Layout != LayoutConcatenated {
			return nil, &VolumeError{
				Kind: VolumeErrUnsupportedComponentLayout, ComponentID: component.ID, Layout: component.Layout.Label(),
			}
		}
		parts := make([]ComponentPartition, len(component.Partitions))
		copy(parts, component.Partitions)
		sort.SliceStable(parts, func(i, j int) bool {
			if parts[i].VolumeOffset != parts[j].VolumeOffset {
				return parts[i].VolumeOffset < parts[j].VolumeOffset
			}
			if parts[i].StartLBA != parts[j].StartLBA {
				return parts[i].StartLBA < parts[j].StartLBA
			}
			return parts[i].PartitionID < parts[j].PartitionID
		})
		copyEntry := mirrorCopy{index: copyIndex, complete: true}
		var expected uint64
		for i := range parts {
			part := &parts[i]
			found, ok := mulChecked(part.VolumeOffset, placer.block)
			if !ok {
				return nil, &VolumeError{Kind: VolumeErrOverflow, What: "extent offset"}
			}
			if found != expected {
				return nil, &VolumeError{Kind: VolumeErrNotContiguous, Expected: expected, Found: found}
			}
			record, err := placer.partition(part.PartitionID)
			if err != nil {
				return nil, err
			}
			member, foundMember, err := placer.resolve(part.DiskID)
			if err != nil {
				return nil, err
			}
			if foundMember {
				imageOffset, spanLen, err := placer.placePartition(member, part)
				if err != nil {
					return nil, err
				}
				copyEntry.spans = append(copyEntry.spans, Span{
					PartitionID:  part.PartitionID,
					VolumeOffset: found,
					ImageOffset:  imageOffset,
					Len:          spanLen,
				})
				copyEntry.spanMembers = append(copyEntry.spanMembers, member)
				placements = append(placements, placer.placement(
					record, intPtr(member), uint64Ptr(imageOffset), spanLen, part.Column, intPtr(copyIndex)))
				expected, ok = addChecked(expected, spanLen)
				if !ok {
					return nil, &VolumeError{Kind: VolumeErrOverflow, What: "volume length"}
				}
			} else {
				copyEntry.complete = false
				partLen, err := placer.columnLen(part)
				if err != nil {
					return nil, err
				}
				placements = append(placements, placer.placement(
					record, nil, nil, partLen, part.Column, intPtr(copyIndex)))
				expected, ok = addChecked(expected, partLen)
				if !ok {
					return nil, &VolumeError{Kind: VolumeErrOverflow, What: "volume length"}
				}
				missingLabels = append(missingLabels, placer.diskLabel(part.DiskID))
			}
		}
		copyEntry.length = expected
		if !copyEntry.complete {
			continue
		}
		readable++
		if declared != nil && *declared != copyEntry.length {
			return nil, &VolumeError{Kind: VolumeErrSizeMismatch, Declared: *declared, Assembled: copyEntry.length}
		}
		if chosen == nil {
			chosen = &copyEntry
		}
	}

	copies := len(geometry.Components)
	if chosen == nil {
		return nil, &VolumeError{
			Kind: VolumeErrNoCompleteCopy, Copies: copies, Readable: readable, Missing: missingLabels,
		}
	}
	length := chosen.length
	if declared != nil {
		length = *declared
	}
	if length == 0 {
		return nil, &VolumeError{Kind: VolumeErrEmptyVolume}
	}
	name := ""
	if volume.Name != nil {
		name = *volume.Name
	}
	chosenIndex := chosen.index
	return &VolumeSource{
		id:          id,
		imageID:     placer.firstImageID(),
		name:        name,
		length:      length,
		mapping:     volumeMapping{kind: mapConcatenated},
		spans:       chosen.spans,
		spanMembers: chosen.spanMembers,
		members:     placer.memberInfos(),
		placements:  placements,
		redundancy: Redundancy{
			Kind: RedundancyMirrored, Copies: copies, Readable: readable, Chosen: chosenIndex,
		},
	}, nil
}

// planVolume builds the logical span list for a single-image concatenated
// volume, refusing a volume whose pieces do not tile it.
func planVolume(volume *Volume) ([]Span, error) {
	if volume.Layout != LayoutConcatenated {
		return nil, &VolumeError{
			Kind: VolumeErrUnsupportedLayout, Layout: volume.Layout.Label(), Extents: len(volume.Extents),
		}
	}
	if len(volume.Extents) == 0 {
		return nil, &VolumeError{Kind: VolumeErrNoExtents}
	}
	extents := make([]*Extent, len(volume.Extents))
	for i := range volume.Extents {
		extents[i] = &volume.Extents[i]
		if !extents[i].OnThisDisk {
			return nil, &VolumeError{
				Kind: VolumeErrExtentOnOtherDisk, PartitionID: extents[i].PartitionID, DiskName: extents[i].DiskName,
			}
		}
		if extents[i].Sectors == 0 {
			return nil, &VolumeError{Kind: VolumeErrZeroLengthExtent, PartitionID: extents[i].PartitionID}
		}
	}
	sort.SliceStable(extents, func(i, j int) bool {
		if extents[i].VolumeOffset != extents[j].VolumeOffset {
			return extents[i].VolumeOffset < extents[j].VolumeOffset
		}
		return extents[i].PartitionID < extents[j].PartitionID
	})

	first, ok := mulChecked(extents[0].VolumeOffset, SectorBytes)
	if !ok {
		return nil, &VolumeError{Kind: VolumeErrOverflow, What: "extent offset"}
	}
	if first != 0 {
		return nil, &VolumeError{Kind: VolumeErrDoesNotStartAtZero, Found: first}
	}

	spans := make([]Span, 0, len(extents))
	var expected uint64
	for _, extent := range extents {
		found, ok := mulChecked(extent.VolumeOffset, SectorBytes)
		if !ok {
			return nil, &VolumeError{Kind: VolumeErrOverflow, What: "extent offset"}
		}
		length, ok := mulChecked(extent.Sectors, SectorBytes)
		if !ok {
			return nil, &VolumeError{Kind: VolumeErrOverflow, What: "extent length"}
		}
		if found != expected {
			return nil, &VolumeError{Kind: VolumeErrNotContiguous, Expected: expected, Found: found}
		}
		if extent.Offset == nil {
			return nil, &VolumeError{Kind: VolumeErrMissingOffset, PartitionID: extent.PartitionID}
		}
		spans = append(spans, Span{
			PartitionID:  extent.PartitionID,
			VolumeOffset: found,
			ImageOffset:  *extent.Offset,
			Len:          length,
		})
		expected, ok = addChecked(expected, length)
		if !ok {
			return nil, &VolumeError{Kind: VolumeErrOverflow, What: "volume length"}
		}
	}

	if volume.SizeSectors != nil {
		declared, ok := mulChecked(*volume.SizeSectors, SectorBytes)
		if !ok {
			return nil, &VolumeError{Kind: VolumeErrOverflow, What: "declared size"}
		}
		if declared != expected {
			return nil, &VolumeError{Kind: VolumeErrSizeMismatch, Declared: declared, Assembled: expected}
		}
	}
	return spans, nil
}

// placer resolves disks to supplied members and computes image offsets.
type placer struct {
	owner   *Database
	members []DiskMember
	block   uint64
}

func (p *placer) memberInfos() []memberInfo {
	out := make([]memberInfo, 0, len(p.members))
	for i := range p.members {
		member := &p.members[i]
		info := memberInfo{source: member.Source}
		if disk := member.Disk(); disk != nil {
			info.diskID = uint64Ptr(disk.ID)
			info.diskName = disk.Name
		}
		out = append(out, info)
	}
	return out
}

func (p *placer) firstImageID() source.ImageID {
	if len(p.members) == 0 {
		return 0
	}
	return p.members[0].Source.ImageID()
}

func (p *placer) partition(partitionID uint64) (*Partition, error) {
	for _, partition := range p.owner.Partitions() {
		if partition.ID == partitionID {
			return partition, nil
		}
	}
	return nil, &VolumeError{Kind: VolumeErrMissingPartition, PartitionID: partitionID}
}

// resolve maps a disk id to a member index.
//
// The strongest match is the disk GUID both databases carry; when the owner has
// no GUID the VBLK object id is next, and the disk name is a last resort.
func (p *placer) resolve(diskID uint64) (int, bool, error) {
	target := p.owner.Disk(diskID)
	var targetGUID string
	var targetName *string
	if target != nil {
		if target.GUID != nil {
			targetGUID = normalizeGUID(*target.GUID)
		}
		targetName = target.Name
	}

	if targetGUID != "" {
		var matches []int
		for i := range p.members {
			member := &p.members[i]
			if member.Database == nil || member.Database.DiskGUID == nil {
				continue
			}
			if normalizeGUID(*member.Database.DiskGUID) == targetGUID {
				matches = append(matches, i)
			}
		}
		if index, found, err := unique(matches, diskID, targetName); err != nil || found {
			return index, found, err
		}
	}

	var matches []int
	for i := range p.members {
		member := &p.members[i]
		if member.Database != nil && member.Database.ThisDiskID != nil && *member.Database.ThisDiskID == diskID {
			matches = append(matches, i)
		}
	}
	if index, found, err := unique(matches, diskID, targetName); err != nil || found {
		return index, found, err
	}

	if targetName != nil {
		matches = matches[:0]
		for i := range p.members {
			disk := p.members[i].Disk()
			if disk != nil && disk.Name != nil && *disk.Name == *targetName {
				matches = append(matches, i)
			}
		}
		if index, found, err := unique(matches, diskID, targetName); err != nil || found {
			return index, found, err
		}
	}
	return 0, false, nil
}

func (p *placer) missingMember(diskID, partitionID uint64) error {
	var diskName *string
	if disk := p.owner.Disk(diskID); disk != nil {
		diskName = disk.Name
	}
	return &VolumeError{Kind: VolumeErrMissingMember, PartitionID: partitionID, DiskID: diskID, DiskName: diskName}
}

func (p *placer) diskLabel(diskID uint64) string {
	if disk := p.owner.Disk(diskID); disk != nil {
		if disk.Name != nil {
			return fmt.Sprintf("`%s` (id %d)", *disk.Name, diskID)
		}
		return fmt.Sprintf("id %d", diskID)
	}
	return fmt.Sprintf("id %d", diskID)
}

func (p *placer) place(member int, startLBA, sectors, partitionID uint64) (uint64, uint64, error) {
	database := p.members[member].Database
	block := uint64(0)
	if database != nil {
		block = uint64(database.BytesPerBlock)
	}
	if block != p.block {
		found := uint32(0)
		if database != nil {
			found = database.BytesPerBlock
		}
		return 0, 0, &VolumeError{
			Kind: VolumeErrInconsistentBlockSize, Member: p.members[member].label(),
			ExpectedBlock: uint32(p.block), FoundBlock: found,
		}
	}
	publicStart := uint64(0)
	if database != nil {
		publicStart = database.PublicRegion.StartLBA
	}
	start, ok := addChecked(publicStart, startLBA)
	if !ok {
		return 0, 0, &VolumeError{Kind: VolumeErrOverflow, What: "partition start"}
	}
	imageOffset, ok := mulChecked(start, block)
	if !ok {
		return 0, 0, &VolumeError{Kind: VolumeErrOverflow, What: "partition offset"}
	}
	length, ok := mulChecked(sectors, block)
	if !ok {
		return 0, 0, &VolumeError{Kind: VolumeErrOverflow, What: "partition length"}
	}
	var imageLen uint64
	if p.members[member].Source != nil {
		imageLen = p.members[member].Source.Len()
	}
	if imageOffset > imageLen || length > imageLen-imageOffset {
		return 0, 0, &VolumeError{
			Kind: VolumeErrOutsideImage, PartitionID: partitionID,
			Offset: imageOffset, Len: length, ImageLen: imageLen,
		}
	}
	return imageOffset, length, nil
}

func (p *placer) placePartition(member int, partition *ComponentPartition) (uint64, uint64, error) {
	return p.place(member, partition.StartLBA, partition.SizeSectors, partition.PartitionID)
}

// columnLen returns a partition's length in bytes, using the block size all
// members share.
func (p *placer) columnLen(partition *ComponentPartition) (uint64, error) {
	length, ok := mulChecked(partition.SizeSectors, p.block)
	if !ok {
		return 0, &VolumeError{Kind: VolumeErrOverflow, What: "partition length"}
	}
	return length, nil
}

func (p *placer) placement(
	partition *Partition,
	member *int,
	imageOffset *uint64,
	length uint64,
	column *uint64,
	copyIndex *int,
) Placement {
	disk := p.owner.Disk(partition.DiskID)
	placement := Placement{
		PartitionID: partition.ID,
		DiskID:      partition.DiskID,
		ImageOffset: imageOffset,
		Len:         length,
		Column:      column,
		Copy:        copyIndex,
		Member:      member,
	}
	if partition.ComponentID != nil {
		placement.ComponentID = *partition.ComponentID
	}
	if disk != nil {
		placement.DiskName = disk.Name
	}
	if placement.DiskName == nil && member != nil {
		if memberDisk := p.members[*member].Disk(); memberDisk != nil {
			placement.DiskName = memberDisk.Name
		}
	}
	if member != nil && p.members[*member].Database != nil {
		placement.DiskGUID = p.members[*member].Database.DiskGUID
	}
	if placement.DiskGUID == nil && disk != nil {
		placement.DiskGUID = disk.GUID
	}
	return placement
}

func unique(matches []int, diskID uint64, diskName *string) (int, bool, error) {
	switch len(matches) {
	case 0:
		return 0, false, nil
	case 1:
		return matches[0], true, nil
	default:
		return 0, false, &VolumeError{
			Kind: VolumeErrAmbiguousMember, DiskID: diskID, DiskName: diskName, Candidates: len(matches),
		}
	}
}

func declaredBytes(volume *Volume, block uint64) (*uint64, error) {
	if volume.SizeSectors == nil {
		return nil, nil
	}
	bytes, ok := mulChecked(*volume.SizeSectors, block)
	if !ok {
		return nil, &VolumeError{Kind: VolumeErrOverflow, What: "declared size"}
	}
	if bytes == 0 {
		return nil, nil
	}
	return &bytes, nil
}

// volumeLength applies the declared-size rule shared by stripe and RAID-5:
// a declared size larger than the assembled capacity is refused, a smaller one
// truncates the usable volume, and an absent one uses the full capacity.
func volumeLength(volume *Volume, block, capacity uint64) (uint64, error) {
	declared, err := declaredBytes(volume, block)
	if err != nil {
		return 0, err
	}
	length := capacity
	if declared != nil {
		if *declared > capacity {
			return 0, &VolumeError{Kind: VolumeErrSizeMismatch, Declared: *declared, Assembled: capacity}
		}
		length = *declared
	}
	if length == 0 {
		return 0, &VolumeError{Kind: VolumeErrEmptyVolume}
	}
	return length, nil
}

func singleComponent(geometry *VolumeGeometry, layout string) (*ComponentGeometry, error) {
	switch len(geometry.Components) {
	case 0:
		return nil, &VolumeError{Kind: VolumeErrMissingComponent, ComponentID: geometry.VolumeID}
	case 1:
		return &geometry.Components[0], nil
	default:
		return nil, &VolumeError{
			Kind: VolumeErrMultipleComponents, Layout: layout, Components: len(geometry.Components),
		}
	}
}

func requiredColumns(component *ComponentGeometry, geometry *VolumeGeometry) (uint64, error) {
	columns := uint64(0)
	if component.Columns != nil {
		columns = *component.Columns
	} else if geometry.Columns != nil {
		columns = *geometry.Columns
	}
	if columns == 0 {
		return 0, &VolumeError{Kind: VolumeErrMissingColumnCount, ComponentID: component.ID}
	}
	return columns, nil
}

func requiredStripeBlocks(component *ComponentGeometry, geometry *VolumeGeometry) (uint64, error) {
	componentBlocks := component.StripeBlocks
	volumeBlocks := component.ChunkBlocks
	if volumeBlocks == nil {
		volumeBlocks = geometry.ChunkBlocks
	}
	var blocks uint64
	switch {
	case componentBlocks != nil && volumeBlocks != nil && *componentBlocks != *volumeBlocks:
		return 0, &VolumeError{
			Kind: VolumeErrStripeUnitMismatch, ComponentID: component.ID,
			Expected: *componentBlocks, Found: *volumeBlocks,
		}
	case componentBlocks != nil:
		blocks = *componentBlocks
	case volumeBlocks != nil:
		blocks = *volumeBlocks
	default:
		return 0, &VolumeError{Kind: VolumeErrMissingStripeGeometry, ComponentID: component.ID}
	}
	if blocks == 0 {
		return 0, &VolumeError{Kind: VolumeErrMissingStripeGeometry, ComponentID: component.ID}
	}
	return blocks, nil
}

func equalColumnLength(placer *placer, partitions []ComponentPartition) (uint64, error) {
	var first *uint64
	for i := range partitions {
		length, err := placer.columnLen(&partitions[i])
		if err != nil {
			return 0, err
		}
		if first == nil {
			first = &length
			continue
		}
		if *first != length {
			return 0, &VolumeError{Kind: VolumeErrUnequalColumns, Expected: *first, Found: length}
		}
	}
	if first == nil {
		return 0, &VolumeError{Kind: VolumeErrEmptyVolume}
	}
	return *first, nil
}

func partitionByColumn(partitions []ComponentPartition, column uint64) *ComponentPartition {
	for i := range partitions {
		if partitions[i].Column != nil && *partitions[i].Column == column {
			return &partitions[i]
		}
	}
	return nil
}

// chunksInColumn returns the number of logical chunks in 0..totalChunks stored
// on column of a classic columns-way stripe.
func chunksInColumn(column, columns, totalChunks uint64) uint64 {
	if column >= totalChunks {
		return 0
	}
	return (totalChunks-1-column)/columns + 1
}

// parityColumn returns the parity column of stripe.
//
// Windows LDM rotates parity one column left per stripe, with column zero on
// the last member for the first stripe: parity = columns - 1 - stripe%columns.
func parityColumn(stripe, columns uint64) uint64 {
	return columns - 1 - stripe%columns
}

// dataColumn returns the physical column holding logical data chunk dataIndex
// of stripe.
func dataColumn(stripe, dataIndex, columns uint64) uint64 {
	parity := parityColumn(stripe, columns)
	var seen uint64
	for column := uint64(0); column < columns; column++ {
		if column == parity {
			continue
		}
		if seen == dataIndex {
			return column
		}
		seen++
	}
	return 0
}

func divCeil(a, b uint64) uint64 {
	if b == 0 {
		return 0
	}
	return a/b + boolToUint64(a%b != 0)
}

func boolToUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func intPtr(value int) *int          { return &value }
func uint64Ptr(value uint64) *uint64 { return &value }

// ---------------------------------------------------------------------------
// ByteSource implementation
// ---------------------------------------------------------------------------

// SourceID implements source.ByteSource.
func (s *VolumeSource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *VolumeSource) Len() uint64 { return s.length }

// ImageID implements source.ByteSource.
func (s *VolumeSource) ImageID() source.ImageID { return s.imageID }

// SectorSize implements source.ByteSource.
func (s *VolumeSource) SectorSize() uint32 { return uint32(SectorBytes) }

// IsEmpty implements source.ByteSource.
func (s *VolumeSource) IsEmpty() bool { return s.length == 0 }

// Stats implements source.ByteSource.
func (s *VolumeSource) Stats() source.Stats { return s.counters.Snapshot() }

type pieceKind uint8

const (
	pieceDirect pieceKind = iota
	pieceRebuild
)

type piece struct {
	// logical is the logical offset of this piece inside the volume.
	logical uint64
	len     uint64
	kind    pieceKind
	// direct
	member int
	offset uint64
	// rebuild
	column uint64
}

func (s *VolumeSource) bounds(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

// forEachPiece walks the pieces of [from, to). The callback returns true to
// stop early.
func (s *VolumeSource) forEachPiece(from, to uint64, fn func(piece) (bool, error)) error {
	at := from
	for at < to {
		var next piece
		switch s.mapping.kind {
		case mapConcatenated:
			index := -1
			for i := range s.spans {
				span := &s.spans[i]
				if span.VolumeOffset+span.Len > at {
					index = i
					break
				}
			}
			if index < 0 {
				return nil
			}
			span := &s.spans[index]
			start := at
			if start < span.VolumeOffset {
				start = span.VolumeOffset
			}
			stop := span.VolumeOffset + span.Len
			if stop > to {
				stop = to
			}
			next = piece{
				logical: at,
				len:     stop - start,
				kind:    pieceDirect,
				member:  s.spanMembers[index],
				offset:  span.ImageOffset + (start - span.VolumeOffset),
			}
			at = stop
		case mapStripe:
			unit, columns := s.mapping.unit, s.mapping.columns
			chunk := at / unit
			within := at % unit
			length := unit - within
			if length > to-at {
				length = to - at
			}
			column := chunk % columns
			memberChunk := chunk / columns
			slot := s.mapping.slots[column]
			next = piece{
				logical: at,
				len:     length,
				kind:    pieceDirect,
				member:  slot.member,
				offset:  slot.imageOffset + memberChunk*unit + within,
			}
			at += length
		case mapParity:
			unit, columns, dataColumns := s.mapping.unit, s.mapping.columns, s.mapping.dataColumns
			chunk := at / unit
			within := at % unit
			length := unit - within
			if length > to-at {
				length = to - at
			}
			stripe := chunk / dataColumns
			dataIndex := chunk % dataColumns
			column := dataColumn(stripe, dataIndex, columns)
			memberOffset := stripe*unit + within
			next = piece{logical: at, len: length}
			if slot := s.mapping.slots[column]; slot != nil {
				next.kind = pieceDirect
				next.member = slot.member
				next.offset = slot.imageOffset + memberOffset
			} else {
				next.kind = pieceRebuild
				next.column = column
				next.offset = memberOffset
			}
			at += length
		default:
			return nil
		}
		if next.len == 0 {
			return nil
		}
		stop, err := fn(next)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
	return nil
}

func (s *VolumeSource) readInto(offset uint64, buf []byte, lossy bool) (int, error) {
	if err := s.bounds(offset, uint64(len(buf))); err != nil {
		return 0, err
	}
	want := uint64(len(buf))
	if remaining := s.length - offset; want > remaining {
		want = remaining
	}
	at := 0
	stopped := false
	err := s.forEachPiece(offset, offset+want, func(pc piece) (bool, error) {
		length := int(pc.len)
		target := buf[at : at+length]
		switch pc.kind {
		case pieceDirect:
			src := s.members[pc.member].source
			var read int
			var err error
			if lossy {
				read, err = src.ReadAtLossy(pc.offset, target)
			} else {
				read, err = src.ReadAt(pc.offset, target)
			}
			if err != nil {
				return true, err
			}
			at += read
			if read < length {
				// A short parent read stays short: the missing bytes never
				// read as zero, because that would pass a hole off as evidence.
				s.counters.AddRead(at)
				stopped = true
				return true, nil
			}
		case pieceRebuild:
			if err := s.rebuild(pc.column, pc.offset, target, lossy); err != nil {
				return true, err
			}
			at += length
		}
		return false, nil
	})
	if err != nil {
		return at, err
	}
	if stopped {
		return at, nil
	}
	s.counters.AddRead(int(want))
	return int(want), nil
}

// rebuild recovers one missing column's bytes from the same offsets on every
// other column of the stripe. Parity is the XOR of the data chunks, so the
// missing chunk is the XOR of all the chunks that survive, parity included.
func (s *VolumeSource) rebuild(missingColumn, memberOffset uint64, out []byte, lossy bool) error {
	if s.mapping.kind != mapParity {
		return source.NewCorrupt(memberOffset,
			"a non-parity volume has no parity to rebuild a missing column from")
	}
	stripe := memberOffset / s.mapping.unit
	columns := s.mapping.columns
	if missingColumn == parityColumn(stripe, columns) {
		return source.NewCorrupt(memberOffset, fmt.Sprintf(
			"column %d is parity and is never read; its bytes cannot be rebuilt from the data columns alone",
			missingColumn))
	}
	for i := range out {
		out[i] = 0
	}
	scratch := make([]byte, len(out))
	for column := uint64(0); column < columns; column++ {
		if column == missingColumn {
			continue
		}
		slot := s.mapping.slots[column]
		if slot == nil {
			return source.NewCorrupt(memberOffset, fmt.Sprintf(
				"column %d is also missing, so column %d cannot be rebuilt", column, missingColumn))
		}
		physical, ok := addChecked(slot.imageOffset, memberOffset)
		if !ok {
			return source.NewCorrupt(memberOffset, "RAID-5 member offset overflows u64")
		}
		src := s.members[slot.member].source
		var read int
		var err error
		if lossy {
			read, err = src.ReadAtLossy(physical, scratch)
		} else {
			read, err = src.ReadAt(physical, scratch)
		}
		if err != nil {
			return err
		}
		if read < len(scratch) {
			return source.NewCorrupt(physical, fmt.Sprintf(
				"member %s supplied %d of %d bytes while rebuilding column %d; refusing to invent the rest",
				s.memberLabel(slot.member), read, len(scratch), missingColumn))
		}
		for i := range out {
			out[i] ^= scratch[i]
		}
	}
	return nil
}

func (s *VolumeSource) memberLabel(index int) string {
	info := &s.members[index]
	switch {
	case info.diskName != nil && info.diskID != nil:
		return fmt.Sprintf("`%s` (id %d)", *info.diskName, *info.diskID)
	case info.diskName != nil:
		return fmt.Sprintf("`%s`", *info.diskName)
	case info.diskID != nil:
		return fmt.Sprintf("disk id %d", *info.diskID)
	default:
		return fmt.Sprintf("member %d", index)
	}
}

// ReadAt implements source.ByteSource.
func (s *VolumeSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	return s.readInto(offset, buf, false)
}

// ReadAtLossy implements source.ByteSource. A short read stays short: a
// missing extent byte is never replaced with zeroes.
func (s *VolumeSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	return s.readInto(offset, buf, true)
}

// ExtentsInto translates [offset, offset+length) into immediate parents and
// appends to out. Existing entries are preserved.
func (s *VolumeSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	err := s.forEachPiece(offset, offset+length, func(pc piece) (bool, error) {
		if pc.kind == pieceDirect {
			out = append(out, source.ParentRange{
				Parent:       s.members[pc.member].source.SourceID(),
				ParentOffset: pc.offset,
				Len:          pc.len,
				Kind:         source.RangeData,
			})
		} else {
			// Rebuilt bytes are not stored in any one parent: name the volume
			// itself so a report never points at the wrong member.
			out = append(out, source.ParentRange{
				Parent:       s.id,
				ParentOffset: pc.logical,
				Len:          pc.len,
				Kind:         source.RangeDerived,
			})
		}
		return false, nil
	})
	return out, err
}

// Extents returns the complete translation for [offset, offset+length).
func (s *VolumeSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage translates [offset, offset+length) all the way to image offsets.
func (s *VolumeSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return nil, err
	}
	var out []source.ImageRange
	if length == 0 {
		return out, nil
	}
	err := s.forEachPiece(offset, offset+length, func(pc piece) (bool, error) {
		if pc.kind == pieceDirect {
			ranges, err := s.members[pc.member].source.MapToImage(pc.offset, pc.len)
			if err != nil {
				return true, err
			}
			out = append(out, ranges...)
		} else {
			out = append(out, source.ImageRange{
				ImageID:     s.imageID,
				ImageOffset: 0,
				Len:         pc.len,
				Kind:        source.RangeDerived,
			})
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ source.ByteSource = (*VolumeSource)(nil)
