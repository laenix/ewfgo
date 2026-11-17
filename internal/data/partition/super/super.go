// Package super reads Android super images (super.img) and exposes their
// logical (dynamic) partitions.
//
// A super image is a physical block device whose first bytes are a geometry
// record and whose metadata slots describe logical partitions such as
// `system_a` and `vendor_a`. Partitions live in extents of the same device: a
// linear extent is a byte range, a zero extent reads as zeroes. A filesystem
// inside a logical partition is therefore indistinguishable from one inside an
// ordinary partition once its view is exposed.
//
// Every checksum the format defines is verified before the metadata is
// believed: the geometry's SHA-256, then the chosen slot header's and its table
// area's. Every table entry is bounds-checked inside its table, every
// partition's extent range inside the extent table, and every linear extent
// inside block device 0 and inside the image. A target source other than 0
// needs another block device this reader does not hold, so it is refused by
// name rather than read from the wrong place.
//
// Slot 0 is tried first, then the other declared slots; the first slot whose
// header and tables verify is used, and the choice is reported. Nothing here
// invents a "newest" slot: the layout does not record one.
//
// This is a pure-Go port of forensic-core's partition/super.rs. Structural and
// checksum failures wrap source.ErrCorrupt, truncated structures wrap
// source.ErrUnexpectedEOF, and unsupported target types/sources wrap
// source.ErrUnsupported. A *Error additionally carries the precise Kind for
// callers that need to distinguish the failure without matching strings.
package super

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// GeometryMagic is 0x616C4467, "gDla" when read little-endian.
	GeometryMagic uint32 = 0x616C4467
	// HeaderMagic is 0x414C5030, the LP metadata header signature.
	HeaderMagic uint32 = 0x414C5030
	// LPSectorBytes is the sector unit logical-partition addresses use.
	LPSectorBytes = 512
	// GeometryBlockBytes is the size of one geometry block at the image head.
	GeometryBlockBytes = 4096
	// FirstMetadataOffset is the canonical first metadata slot.
	FirstMetadataOffset = 4096
	// MinGeometryBytes and MaxGeometryBytes bound the geometry struct.
	MinGeometryBytes = 48
	MaxGeometryBytes = 4096
	// MinHeaderBytes and MaxHeaderBytes bound the metadata header.
	MinHeaderBytes = 128
	MaxHeaderBytes = 4096
	// MaxMetadataSize bounds one metadata slot before anything is read.
	MaxMetadataSize = 64 * 1024 * 1024
	// MaxTablesBytes bounds the tables area before it is allocated.
	MaxTablesBytes = 16 * 1024 * 1024
	// MaxSlots, MaxPartitions, MaxExtents, MaxGroups and MaxBlockDevices cap
	// the tables this reader walks.
	MaxSlots        = 64
	MaxPartitions   = 4096
	MaxExtents      = 65536
	MaxGroups       = 4096
	MaxBlockDevices = 64
	// Entry sizes the format defines.
	PartitionEntryBytes   = 52
	ExtentEntryBytes      = 24
	GroupEntryBytes       = 48
	BlockDeviceEntryBytes = 64
	// TargetLinear and TargetZero are the only extent target types read.
	TargetLinear uint32 = 0
	TargetZero   uint32 = 1
)

// Kind identifies a typed super-image failure.
type Kind string

const (
	// KindSignature means the first four bytes are not the geometry magic.
	KindSignature Kind = "signature"
	// KindTruncatedGeometry means the image ends before the geometry record.
	KindTruncatedGeometry Kind = "truncated_geometry"
	// KindGeometrySize means struct_size is outside the accepted range.
	KindGeometrySize Kind = "geometry_size"
	// KindGeometryChecksum means the geometry's SHA-256 does not match.
	KindGeometryChecksum Kind = "geometry_checksum"
	// KindMetadataMaxSize means metadata_max_size is zero, unaligned or too
	// large.
	KindMetadataMaxSize Kind = "metadata_max_size"
	// KindSlotCount means metadata_slot_count is zero or above the scan cap.
	KindSlotCount Kind = "slot_count"
	// KindNoValidSlot means no slot offset held a header that verified.
	KindNoValidSlot Kind = "no_valid_slot"
	// KindSlotOutsideImage means a slot or its header starts past the image.
	KindSlotOutsideImage Kind = "slot_outside_image"
	// KindSlotMagic means a slot has no LP header magic.
	KindSlotMagic Kind = "slot_magic"
	// KindHeaderSize means the metadata header size is outside the accepted
	// range.
	KindHeaderSize Kind = "header_size"
	// KindHeaderChecksum means the header's SHA-256 does not match.
	KindHeaderChecksum Kind = "header_checksum"
	// KindTablesOutsideSlot means the header and tables do not fit in a slot.
	KindTablesOutsideSlot Kind = "tables_outside_slot"
	// KindTablesChecksum means the table area's SHA-256 does not match.
	KindTablesChecksum Kind = "tables_checksum"
	// KindTableRange means a table descriptor points outside the table area.
	KindTableRange Kind = "table_range"
	// KindEntrySize means an entry is too small for the fields read.
	KindEntrySize Kind = "entry_size"
	// KindTableTooLarge means a table declares more entries than the cap.
	KindTableTooLarge Kind = "table_too_large"
	// KindUnsupportedTargetType means an extent names an unknown target type.
	KindUnsupportedTargetType Kind = "unsupported_target_type"
	// KindUnsupportedTargetSource means an extent lives on another block
	// device.
	KindUnsupportedTargetSource Kind = "unsupported_target_source"
	// KindNoBlockDevice means a linear extent exists but no block device is
	// named.
	KindNoBlockDevice Kind = "no_block_device"
	// KindPartitionExtentRange means a partition's extent range is outside the
	// extent table.
	KindPartitionExtentRange Kind = "partition_extent_range"
	// KindExtentOutsideBlockDevice means a linear extent reaches past block
	// device 0.
	KindExtentOutsideBlockDevice Kind = "extent_outside_block_device"
	// KindExtentOutsideImage means a linear extent reaches past the image.
	KindExtentOutsideImage Kind = "extent_outside_image"
	// KindNoSuchPartition means a requested partition index does not exist.
	KindNoSuchPartition Kind = "no_such_partition"
	// KindOverflow means an offset or length did not fit in a uint64.
	KindOverflow Kind = "overflow"
)

// Error is a typed super-image failure.
type Error struct {
	Kind         Kind
	Slot         uint32
	Offset       uint64
	Needed       uint64
	ImageLen     uint64
	Size         uint32
	Minimum      uint32
	Stored       string
	Computed     string
	Table        string
	Count        uint32
	Limit        uint32
	TargetType   uint32
	TargetSource uint32
	Extent       int
	Partition    string
	First        uint32
	Extents      uint32
	Index        int
	Partitions   int
	What         string
	HeaderSize   uint16
	TablesSize   uint32
	SlotSize     uint32
	DeviceSize   uint64
	Reason       string
}

// Error implements the error interface.
func (e *Error) Error() string {
	switch e.Kind {
	case KindSignature:
		return "not an Android super image (bad geometry magic)"
	case KindTruncatedGeometry:
		return fmt.Sprintf("the geometry record [%d, +%d) is outside the %d-byte image", e.Offset, e.Needed, e.ImageLen)
	case KindGeometrySize:
		return fmt.Sprintf("the geometry struct size %d is outside the %d..=%d range this reader accepts", e.Size, MinGeometryBytes, MaxGeometryBytes)
	case KindGeometryChecksum:
		return fmt.Sprintf("the geometry checksum does not match: stored %s, computed %s", e.Stored, e.Computed)
	case KindMetadataMaxSize:
		return fmt.Sprintf("metadata_max_size %d is zero, not a multiple of 512, or above %d", e.Size, MaxMetadataSize)
	case KindSlotCount:
		return fmt.Sprintf("metadata_slot_count %d is zero or above the %d-slot limit", e.Count, MaxSlots)
	case KindNoValidSlot:
		return fmt.Sprintf("none of the %d metadata slot(s) verified: %s", e.Count, e.Reason)
	case KindSlotOutsideImage:
		return fmt.Sprintf("metadata slot %d [%d, +%d) is outside the %d-byte image", e.Slot, e.Offset, e.Needed, e.ImageLen)
	case KindSlotMagic:
		return fmt.Sprintf("metadata slot %d at byte %d has no LP header magic", e.Slot, e.Offset)
	case KindHeaderSize:
		return fmt.Sprintf("metadata slot %d declares header_size %d, outside %d..=%d", e.Slot, e.HeaderSize, MinHeaderBytes, MaxHeaderBytes)
	case KindHeaderChecksum:
		return fmt.Sprintf("metadata slot %d header checksum does not match: stored %s, computed %s", e.Slot, e.Stored, e.Computed)
	case KindTablesOutsideSlot:
		return fmt.Sprintf("metadata slot %d header (%d) plus tables (%d) exceeds the %d-byte slot", e.Slot, e.HeaderSize, e.TablesSize, e.SlotSize)
	case KindTablesChecksum:
		return fmt.Sprintf("metadata slot %d table checksum does not match: stored %s, computed %s", e.Slot, e.Stored, e.Computed)
	case KindTableRange:
		return fmt.Sprintf("the %s table at offset %d (%d bytes) falls outside the %d-byte tables area after the %d-byte header", e.Table, e.Offset, e.Needed, e.SlotSize, e.HeaderSize)
	case KindEntrySize:
		return fmt.Sprintf("the %s table declares %d-byte entries; at least %d are needed", e.Table, e.Size, e.Minimum)
	case KindTableTooLarge:
		return fmt.Sprintf("the %s table declares %d entries, above the %d-entry limit", e.Table, e.Count, e.Limit)
	case KindUnsupportedTargetType:
		return fmt.Sprintf("extent %d has target type %d; only linear (0) and zero (1) are read", e.Extent, e.TargetType)
	case KindUnsupportedTargetSource:
		return fmt.Sprintf("extent %d lives on block device %d; only block device 0 is in this image", e.Extent, e.TargetSource)
	case KindNoBlockDevice:
		return fmt.Sprintf("extent %d is linear but the metadata names no block device", e.Extent)
	case KindPartitionExtentRange:
		return fmt.Sprintf("partition `%s` asks for extents %d..%d but the extent table holds %d", e.Partition, e.First, e.First+e.Count, e.Extents)
	case KindExtentOutsideBlockDevice:
		return fmt.Sprintf("partition `%s` extent %d [%d, +%d) falls outside the %d-byte block device", e.Partition, e.Extent, e.Offset, e.Needed, e.DeviceSize)
	case KindExtentOutsideImage:
		return fmt.Sprintf("partition `%s` extent %d [%d, +%d) falls outside the %d-byte super image", e.Partition, e.Extent, e.Offset, e.Needed, e.ImageLen)
	case KindNoSuchPartition:
		return fmt.Sprintf("partition index %d does not exist; the super image has %d", e.Index, e.Partitions)
	case KindOverflow:
		return fmt.Sprintf("Android super %s overflows u64", e.What)
	default:
		return "Android super error"
	}
}

// Unwrap maps the typed failure onto the shared source error taxonomy.
func (e *Error) Unwrap() error {
	switch e.Kind {
	case KindTruncatedGeometry, KindSlotOutsideImage:
		return source.ErrUnexpectedEOF
	case KindUnsupportedTargetType, KindUnsupportedTargetSource:
		return source.ErrUnsupported
	default:
		return source.ErrCorrupt
	}
}

// Geometry is the geometry record at offset zero (or at its backup copy).
type Geometry struct {
	StructSize         uint32
	MetadataMaxSize    uint32
	MetadataSlotCount  uint32
	LogicalBlockSize   *uint32
	FirstLogicalSector *uint64
	LastLogicalSector  *uint64
	// Checksum is the stored SHA-256, verbatim.
	Checksum [32]byte
}

// HeaderInfo holds the header fields the reader used, for reporting.
type HeaderInfo struct {
	MajorVersion   uint16
	MinorVersion   uint16
	HeaderSize     uint16
	TablesSize     uint32
	HeaderChecksum [32]byte
	TablesChecksum [32]byte
}

// Extent is one extent record, as stored.
type Extent struct {
	NumSectors   uint64
	TargetType   uint32
	TargetData   uint64
	TargetSource uint32
}

// ByteLen returns the extent length in bytes, saturating on overflow.
func (e Extent) ByteLen() uint64 { return satMul(e.NumSectors, LPSectorBytes) }

// IsZero reports a zero target.
func (e Extent) IsZero() bool { return e.TargetType == TargetZero }

// IsLinear reports a linear target.
func (e Extent) IsLinear() bool { return e.TargetType == TargetLinear }

// ParentOffset returns the byte offset in the super image for a linear extent.
func (e Extent) ParentOffset() (uint64, bool) {
	if !e.IsLinear() {
		return 0, false
	}
	return satMul(e.TargetData, LPSectorBytes), true
}

// SpanKind is the nature of one run of a logical partition's byte stream.
type SpanKind uint8

const (
	// SpanLinear is stored in the super image at ParentOffset.
	SpanLinear SpanKind = iota
	// SpanZero reads as zeroes; the writer stored nothing.
	SpanZero
)

// SpanTarget describes where one span lives.
type SpanTarget struct {
	Kind         SpanKind
	ParentOffset uint64
}

// Span is one run of a logical partition's byte stream.
type Span struct {
	Logical uint64
	Len     uint64
	Target  SpanTarget
}

// Partition is one logical partition with its extents resolved to spans.
type Partition struct {
	Name             string
	Attributes       uint32
	FirstExtentIndex uint32
	NumExtents       uint32
	GroupIndex       uint32
	Len              uint64
	// FirstLinearOffset is the image offset of the first linear extent, when
	// there is one.
	FirstLinearOffset *uint64
	Spans             []Span
}

// Group is one partition group record.
type Group struct {
	Name        string
	Flags       uint32
	MaximumSize uint64
}

// BlockDevice is block device 0, which is the super image itself here.
type BlockDevice struct {
	FirstLogicalSector uint64
	Alignment          uint32
	AlignmentOffset    uint32
	Size               uint64
	PartitionName      string
	Flags              uint32
}

// Detection is the typed result of a signature/geometry scan.
type Detection struct {
	// Present reports that at least one candidate offset carries the geometry
	// magic.
	Present bool
	// Signature reports the geometry magic was seen.
	Signature bool
	// GeometryValid reports that a geometry record parsed and its checksum
	// verified.
	GeometryValid bool
	// Kind is the failure kind when the magic is present but the geometry does
	// not verify; it is empty for an absent or valid geometry.
	Kind Kind
	// Backup reports that the valid geometry came from the backup block at
	// byte 4096.
	Backup bool
	// Offset is the geometry block that supplied Geometry.
	Offset uint64
	// Geometry is the verified record, or nil when GeometryValid is false.
	Geometry *Geometry
}

// Image is a parsed super image: geometry, one verified metadata slot, and the
// tables it holds. Partitions are exposed through OpenPartition.
type Image struct {
	parent             source.ByteSource
	geometry           Geometry
	usedBackupGeometry bool
	slot               uint32
	slotOffset         uint64
	header             HeaderInfo
	extents            []Extent
	groups             []Group
	blockDevices       []BlockDevice
	partitions         []Partition
}

type parsedSlot struct {
	slot         uint32
	slotOffset   uint64
	header       HeaderInfo
	extents      []Extent
	groups       []Group
	blockDevices []BlockDevice
	partitions   []Partition
}

// MatchesSignature reports whether head begins with the geometry magic.
func MatchesSignature(head []byte) bool {
	return len(head) >= 4 && le32(head, 0) == GeometryMagic
}

// MatchesGeometry reports whether head holds a geometry record whose checksum
// verifies. A magic without a matching checksum is not a super image.
func MatchesGeometry(head []byte) bool {
	_, err := parseGeometryBytes(head, 0)
	return err == nil
}

// Detect scans a source for a super-image geometry record and reports a typed
// detection result in one call. A source with no geometry magic returns a zero
// Detection and no error. When the magic is present but the geometry is
// truncated, malformed or fails its checksum, the Detection records the
// signature and Detect returns the typed *Error.
func Detect(src source.ByteSource) (Detection, error) {
	primary, primaryErr := readGeometry(src, 0)
	if primaryErr == nil {
		return Detection{
			Present:       true,
			Signature:     true,
			GeometryValid: true,
			Offset:        0,
			Geometry:      &primary,
		}, nil
	}
	backup, backupErr := readGeometry(src, GeometryBlockBytes)
	if backupErr == nil {
		return Detection{
			Present:       true,
			Signature:     true,
			GeometryValid: true,
			Backup:        true,
			Offset:        GeometryBlockBytes,
			Geometry:      &backup,
		}, nil
	}
	if hasGeometryMagic(src, 0) {
		return Detection{Present: true, Signature: true, Kind: kindOf(primaryErr), Offset: 0}, primaryErr
	}
	if hasGeometryMagic(src, GeometryBlockBytes) {
		return Detection{Present: true, Signature: true, Kind: kindOf(backupErr), Offset: GeometryBlockBytes}, backupErr
	}
	return Detection{}, nil
}

// OpenIfPresent opens src when its first bytes carry the geometry magic and
// returns nil, nil for anything else.
func OpenIfPresent(src source.ByteSource) (*Image, error) {
	var magic [4]byte
	n, err := src.ReadAtLossy(0, magic[:])
	if err != nil || n != 4 || !MatchesSignature(magic[:]) {
		return nil, nil
	}
	return Open(src)
}

// Open reads the geometry, chooses the first metadata slot whose header and
// tables verify, and resolves every logical partition.
func Open(parent source.ByteSource) (*Image, error) {
	geometry, err := readGeometry(parent, 0)
	usedBackup := false
	if err != nil {
		backup, backupErr := readGeometry(parent, GeometryBlockBytes)
		if backupErr != nil {
			return nil, err
		}
		geometry = backup
		usedBackup = true
	}
	if geometry.MetadataMaxSize == 0 || geometry.MetadataMaxSize%512 != 0 ||
		geometry.MetadataMaxSize > MaxMetadataSize {
		return nil, &Error{Kind: KindMetadataMaxSize, Size: geometry.MetadataMaxSize}
	}
	if geometry.MetadataSlotCount == 0 || geometry.MetadataSlotCount > MaxSlots {
		return nil, &Error{Kind: KindSlotCount, Count: geometry.MetadataSlotCount}
	}

	lastReason := "no slot offset was readable"
	// A missing magic at an offset we merely guessed is not evidence of a
	// corrupt image. A header that was present but failed its checksum is, so
	// keep the first such error and surface it if no slot works.
	var namedFailure *Error
	var chosen *parsedSlot
search:
	for slot := uint32(0); slot < geometry.MetadataSlotCount; slot++ {
		for _, base := range slotBases() {
			stride, ok := checkedMul(uint64(slot), uint64(geometry.MetadataMaxSize))
			if !ok {
				continue
			}
			offset, ok := checkedAdd(base, stride)
			if !ok {
				continue
			}
			parsed, slotErr := readSlot(parent, slot, offset, geometry.MetadataMaxSize)
			if slotErr == nil {
				chosen = parsed
				break search
			}
			if slotErr.Kind != KindSlotMagic && slotErr.Kind != KindSlotOutsideImage && namedFailure == nil {
				namedFailure = slotErr
			}
			lastReason = slotErr.Error()
		}
	}
	if chosen == nil {
		if namedFailure != nil {
			return nil, namedFailure
		}
		return nil, &Error{Kind: KindNoValidSlot, Count: geometry.MetadataSlotCount, Reason: lastReason}
	}

	return &Image{
		parent:             parent,
		geometry:           geometry,
		usedBackupGeometry: usedBackup,
		slot:               chosen.slot,
		slotOffset:         chosen.slotOffset,
		header:             chosen.header,
		extents:            chosen.extents,
		groups:             chosen.groups,
		blockDevices:       chosen.blockDevices,
		partitions:         chosen.partitions,
	}, nil
}

// Geometry returns the geometry record the image was read with.
func (i *Image) Geometry() *Geometry { return &i.geometry }

// UsedBackupGeometry reports that the primary geometry did not verify and the
// copy at byte 4096 did.
func (i *Image) UsedBackupGeometry() bool { return i.usedBackupGeometry }

// MetadataSlot returns the metadata slot that verified.
func (i *Image) MetadataSlot() uint32 { return i.slot }

// MetadataOffset returns the byte offset of that slot.
func (i *Image) MetadataOffset() uint64 { return i.slotOffset }

// Header returns the header fields the reader used.
func (i *Image) Header() *HeaderInfo { return &i.header }

// GeometryChecksumHex returns the stored geometry checksum in lower-case hex.
func (i *Image) GeometryChecksumHex() string { return hex.EncodeToString(i.geometry.Checksum[:]) }

// HeaderChecksumHex returns the stored header checksum in lower-case hex.
func (i *Image) HeaderChecksumHex() string { return hex.EncodeToString(i.header.HeaderChecksum[:]) }

// TablesChecksumHex returns the stored table checksum in lower-case hex.
func (i *Image) TablesChecksumHex() string { return hex.EncodeToString(i.header.TablesChecksum[:]) }

// Extents returns the extent table.
func (i *Image) Extents() []Extent { return i.extents }

// Groups returns the group table.
func (i *Image) Groups() []Group { return i.groups }

// BlockDevices returns the block device table.
func (i *Image) BlockDevices() []BlockDevice { return i.blockDevices }

// Partitions returns the resolved logical partitions.
func (i *Image) Partitions() []Partition { return i.partitions }

// BlockDevice returns block device 0, when the metadata names one.
func (i *Image) BlockDevice() *BlockDevice {
	if len(i.blockDevices) == 0 {
		return nil
	}
	return &i.blockDevices[0]
}

// OpenPartition returns a ByteSource view of one logical partition over this
// same super image.
func (i *Image) OpenPartition(id source.ID, index int) (*PartitionSource, error) {
	if index < 0 || index >= len(i.partitions) {
		return nil, &Error{Kind: KindNoSuchPartition, Index: index, Partitions: len(i.partitions)}
	}
	partition := &i.partitions[index]
	return &PartitionSource{
		id:     id,
		image:  i,
		index:  index,
		length: partition.Len,
		spans:  append([]Span(nil), partition.Spans...),
	}, nil
}

// slotBases returns the offsets a metadata slot may start at. The format
// description places slot 0 at 4096; images written by lpmake in the field put
// the slots after a backup geometry block (8192) or after both geometry copies
// (12288). The canonical offset is tried first.
func slotBases() [3]uint64 {
	return [3]uint64{FirstMetadataOffset, 8192, 12_288}
}

func readGeometry(parent source.ByteSource, offset uint64) (Geometry, error) {
	imageLen := parent.Len()
	if offset > imageLen || uint64(MinGeometryBytes) > imageLen-offset {
		return Geometry{}, &Error{
			Kind: KindTruncatedGeometry, Offset: offset,
			Needed: MinGeometryBytes, ImageLen: imageLen,
		}
	}
	head, err := source.ReadVecAt(parent, offset, MinGeometryBytes)
	if err != nil {
		return Geometry{}, &Error{
			Kind: KindTruncatedGeometry, Offset: offset,
			Needed: MinGeometryBytes, ImageLen: imageLen,
		}
	}
	structSize := le32(head, 4)
	if structSize < MinGeometryBytes || structSize > MaxGeometryBytes {
		return Geometry{}, &Error{Kind: KindGeometrySize, Size: structSize}
	}
	if uint64(structSize) > imageLen-offset {
		return Geometry{}, &Error{
			Kind: KindTruncatedGeometry, Offset: offset,
			Needed: uint64(structSize), ImageLen: imageLen,
		}
	}
	bytes, err := source.ReadVecAt(parent, offset, uint64(structSize))
	if err != nil {
		return Geometry{}, &Error{
			Kind: KindTruncatedGeometry, Offset: offset,
			Needed: uint64(structSize), ImageLen: imageLen,
		}
	}
	return parseGeometryBytes(bytes, offset)
}

func parseGeometryBytes(bytes []byte, offset uint64) (Geometry, error) {
	if len(bytes) < MinGeometryBytes {
		return Geometry{}, &Error{
			Kind: KindTruncatedGeometry, Offset: offset,
			Needed: MinGeometryBytes, ImageLen: uint64(len(bytes)),
		}
	}
	if le32(bytes, 0) != GeometryMagic {
		return Geometry{}, &Error{Kind: KindSignature}
	}
	structSize := le32(bytes, 4)
	if structSize < MinGeometryBytes || structSize > MaxGeometryBytes {
		return Geometry{}, &Error{Kind: KindGeometrySize, Size: structSize}
	}
	if uint64(len(bytes)) < uint64(structSize) {
		return Geometry{}, &Error{
			Kind: KindTruncatedGeometry, Offset: offset,
			Needed: uint64(structSize), ImageLen: uint64(len(bytes)),
		}
	}
	var stored [32]byte
	copy(stored[:], bytes[8:40])
	checked := append([]byte(nil), bytes[:structSize]...)
	for i := 8; i < 40; i++ {
		checked[i] = 0
	}
	computed := sha256.Sum256(checked)
	if computed != stored {
		return Geometry{}, &Error{
			Kind:     KindGeometryChecksum,
			Stored:   hex.EncodeToString(stored[:]),
			Computed: hex.EncodeToString(computed[:]),
		}
	}

	geometry := Geometry{
		StructSize:        structSize,
		MetadataMaxSize:   le32(bytes, 40),
		MetadataSlotCount: le32(bytes, 44),
		Checksum:          stored,
	}
	switch {
	case structSize >= 64:
		first := le64(bytes, 48)
		last := le64(bytes, 56)
		geometry.FirstLogicalSector = &first
		geometry.LastLogicalSector = &last
	case structSize >= 52:
		blockSize := le32(bytes, 48)
		geometry.LogicalBlockSize = &blockSize
	}
	return geometry, nil
}

// readSlot tries one metadata slot at one offset. A missing header magic is
// reported so the caller can move to the next offset, but a header that is
// present and does not verify is also reported, so a later slot can still win.
func readSlot(parent source.ByteSource, slot uint32, slotOffset uint64, metadataMaxSize uint32) (*parsedSlot, *Error) {
	imageLen := parent.Len()
	needed := uint64(MinHeaderBytes)
	if slotOffset > imageLen || needed > imageLen-slotOffset {
		return nil, &Error{
			Kind: KindSlotOutsideImage, Slot: slot, Offset: slotOffset,
			Needed: needed, ImageLen: imageLen,
		}
	}
	head, err := source.ReadVecAt(parent, slotOffset, needed)
	if err != nil {
		return nil, &Error{
			Kind: KindSlotOutsideImage, Slot: slot, Offset: slotOffset,
			Needed: needed, ImageLen: imageLen,
		}
	}
	if le32(head, 0) != HeaderMagic {
		return nil, &Error{Kind: KindSlotMagic, Slot: slot, Offset: slotOffset}
	}
	majorVersion := le16(head, 4)
	minorVersion := le16(head, 6)
	headerSize := le16(head, 8)
	if headerSize < MinHeaderBytes || headerSize > MaxHeaderBytes {
		return nil, &Error{Kind: KindHeaderSize, Slot: slot, HeaderSize: headerSize}
	}
	if uint32(headerSize) > metadataMaxSize {
		return nil, &Error{
			Kind: KindTablesOutsideSlot, Slot: slot, HeaderSize: headerSize,
			SlotSize: metadataMaxSize,
		}
	}
	headerBytes := head
	if int(headerSize) != len(head) {
		if slotOffset > imageLen || uint64(headerSize) > imageLen-slotOffset {
			return nil, &Error{
				Kind: KindSlotOutsideImage, Slot: slot, Offset: slotOffset,
				Needed: uint64(headerSize), ImageLen: imageLen,
			}
		}
		headerBytes, err = source.ReadVecAt(parent, slotOffset, uint64(headerSize))
		if err != nil {
			return nil, &Error{
				Kind: KindSlotOutsideImage, Slot: slot, Offset: slotOffset,
				Needed: uint64(headerSize), ImageLen: imageLen,
			}
		}
	}

	var storedHeader [32]byte
	copy(storedHeader[:], headerBytes[12:44])
	checkedHeader := append([]byte(nil), headerBytes...)
	for i := 12; i < 44; i++ {
		checkedHeader[i] = 0
	}
	computedHeader := sha256.Sum256(checkedHeader)
	if computedHeader != storedHeader {
		return nil, &Error{
			Kind: KindHeaderChecksum, Slot: slot,
			Stored:   hex.EncodeToString(storedHeader[:]),
			Computed: hex.EncodeToString(computedHeader[:]),
		}
	}

	tablesSize := le32(headerBytes, 44)
	var storedTables [32]byte
	copy(storedTables[:], headerBytes[48:80])
	if tablesSize > MaxTablesBytes {
		return nil, &Error{
			Kind: KindTablesOutsideSlot, Slot: slot, HeaderSize: headerSize,
			TablesSize: tablesSize, SlotSize: metadataMaxSize,
		}
	}
	if uint64(headerSize)+uint64(tablesSize) > uint64(metadataMaxSize) {
		return nil, &Error{
			Kind: KindTablesOutsideSlot, Slot: slot, HeaderSize: headerSize,
			TablesSize: tablesSize, SlotSize: metadataMaxSize,
		}
	}
	tablesOffset, ok := checkedAdd(slotOffset, uint64(headerSize))
	if !ok || tablesOffset > imageLen || uint64(tablesSize) > imageLen-tablesOffset {
		return nil, &Error{
			Kind: KindSlotOutsideImage, Slot: slot, Offset: tablesOffset,
			Needed: uint64(tablesSize), ImageLen: imageLen,
		}
	}
	tables, err := source.ReadVecAt(parent, tablesOffset, uint64(tablesSize))
	if err != nil {
		return nil, &Error{
			Kind: KindSlotOutsideImage, Slot: slot, Offset: tablesOffset,
			Needed: uint64(tablesSize), ImageLen: imageLen,
		}
	}
	computedTables := sha256.Sum256(tables)
	if computedTables != storedTables {
		return nil, &Error{
			Kind: KindTablesChecksum, Slot: slot,
			Stored:   hex.EncodeToString(storedTables[:]),
			Computed: hex.EncodeToString(computedTables[:]),
		}
	}

	partitionDesc := readTableDescriptor(headerBytes, 80)
	extentDesc := readTableDescriptor(headerBytes, 92)
	groupDesc := readTableDescriptor(headerBytes, 104)
	blockDeviceDesc := readTableDescriptor(headerBytes, 116)

	partitionBytes, tableErr := tableBytes("partition", tables, partitionDesc, headerSize, tablesSize, PartitionEntryBytes, MaxPartitions)
	if tableErr != nil {
		tableErr.Slot = slot
		return nil, tableErr
	}
	extentBytes, tableErr := tableBytes("extent", tables, extentDesc, headerSize, tablesSize, ExtentEntryBytes, MaxExtents)
	if tableErr != nil {
		tableErr.Slot = slot
		return nil, tableErr
	}
	groupBytes, tableErr := tableBytes("group", tables, groupDesc, headerSize, tablesSize, GroupEntryBytes, MaxGroups)
	if tableErr != nil {
		tableErr.Slot = slot
		return nil, tableErr
	}
	blockDeviceBytes, tableErr := tableBytes("block device", tables, blockDeviceDesc, headerSize, tablesSize, BlockDeviceEntryBytes, MaxBlockDevices)
	if tableErr != nil {
		tableErr.Slot = slot
		return nil, tableErr
	}

	extents := parseExtents(extentBytes, extentDesc.entrySize)
	groups := parseGroups(groupBytes, groupDesc.entrySize)
	blockDevices := parseBlockDevices(blockDeviceBytes, blockDeviceDesc.entrySize)
	var deviceSize *uint64
	if len(blockDevices) > 0 {
		size := blockDevices[0].Size
		deviceSize = &size
	}
	partitions, partErr := parsePartitions(partitionBytes, partitionDesc.entrySize, extents, groups, deviceSize, imageLen)
	if partErr != nil {
		partErr.Slot = slot
		return nil, partErr
	}

	return &parsedSlot{
		slot:       slot,
		slotOffset: slotOffset,
		header: HeaderInfo{
			MajorVersion:   majorVersion,
			MinorVersion:   minorVersion,
			HeaderSize:     headerSize,
			TablesSize:     tablesSize,
			HeaderChecksum: storedHeader,
			TablesChecksum: storedTables,
		},
		extents:      extents,
		groups:       groups,
		blockDevices: blockDevices,
		partitions:   partitions,
	}, nil
}

type tableDescriptor struct {
	offset     uint32
	numEntries uint32
	entrySize  uint32
}

func readTableDescriptor(header []byte, at int) tableDescriptor {
	return tableDescriptor{
		offset:     le32(header, at),
		numEntries: le32(header, at+4),
		entrySize:  le32(header, at+8),
	}
}

// tableBytes locates one table's bytes inside the tables area.
//
// The format stores table offsets relative to the header start, and the tables
// immediately follow the header, so a descriptor offset of header_size points
// at the first table. Writers in the field have also stored offsets relative to
// the tables area (the first table at 0); both readings are accepted,
// header-relative first, and the range is checked against tables_size either
// way.
func tableBytes(table string, tables []byte, descriptor tableDescriptor, headerSize uint16, tablesSize, minimumEntry, limit uint32) ([]byte, *Error) {
	if descriptor.entrySize < minimumEntry {
		return nil, &Error{
			Kind: KindEntrySize, Table: table,
			Size: descriptor.entrySize, Minimum: minimumEntry,
		}
	}
	if descriptor.numEntries > limit {
		return nil, &Error{
			Kind: KindTableTooLarge, Table: table,
			Count: descriptor.numEntries, Limit: limit,
		}
	}
	size, ok := checkedMul(uint64(descriptor.numEntries), uint64(descriptor.entrySize))
	if !ok {
		return nil, &Error{Kind: KindOverflow, What: "table size"}
	}
	if size == 0 {
		return tables[:0], nil
	}
	hs := uint64(headerSize)
	ts := uint64(tablesSize)
	offset := uint64(descriptor.offset)

	rangeErr := &Error{
		Kind: KindTableRange, Table: table, Offset: offset,
		Needed: size, SlotSize: tablesSize, HeaderSize: headerSize,
	}
	var start uint64
	if headerRelative, ok := checkedAdd(offset, size); ok && offset >= hs && headerRelative <= hs+ts {
		start = offset - hs
	} else if tableRelative, ok := checkedAdd(offset, size); ok && tableRelative <= ts {
		start = offset
	} else {
		return nil, rangeErr
	}
	end, ok := checkedAdd(start, size)
	if !ok || start > uint64(len(tables)) || end > uint64(len(tables)) {
		return nil, rangeErr
	}
	return tables[start:end], nil
}

func parseExtents(bytes []byte, stride uint32) []Extent {
	if stride == 0 || len(bytes) == 0 {
		return nil
	}
	step := int(stride)
	out := make([]Extent, 0, len(bytes)/step)
	for at := 0; at+step <= len(bytes); at += step {
		entry := bytes[at : at+step]
		out = append(out, Extent{
			NumSectors:   le64(entry, 0),
			TargetType:   le32(entry, 8),
			TargetData:   le64(entry, 12),
			TargetSource: le32(entry, 20),
		})
	}
	return out
}

func parseGroups(bytes []byte, stride uint32) []Group {
	if stride == 0 || len(bytes) == 0 {
		return nil
	}
	step := int(stride)
	out := make([]Group, 0, len(bytes)/step)
	for at := 0; at+step <= len(bytes); at += step {
		entry := bytes[at : at+step]
		out = append(out, Group{
			Name:        fixedName(entry[:36]),
			Flags:       le32(entry, 36),
			MaximumSize: le64(entry, 40),
		})
	}
	return out
}

func parseBlockDevices(bytes []byte, stride uint32) []BlockDevice {
	if stride == 0 || len(bytes) == 0 {
		return nil
	}
	step := int(stride)
	out := make([]BlockDevice, 0, len(bytes)/step)
	for at := 0; at+step <= len(bytes); at += step {
		entry := bytes[at : at+step]
		out = append(out, BlockDevice{
			FirstLogicalSector: le64(entry, 0),
			Alignment:          le32(entry, 8),
			AlignmentOffset:    le32(entry, 12),
			Size:               le64(entry, 16),
			PartitionName:      fixedName(entry[24:60]),
			Flags:              le32(entry, 60),
		})
	}
	return out
}

func parsePartitions(bytes []byte, stride uint32, extents []Extent, groups []Group, deviceSize *uint64, imageLen uint64) ([]Partition, *Error) {
	if stride == 0 || len(bytes) == 0 {
		return nil, nil
	}
	step := int(stride)
	out := make([]Partition, 0, len(bytes)/step)
	for at := 0; at+step <= len(bytes); at += step {
		entry := bytes[at : at+step]
		name := fixedName(entry[:36])
		attributes := le32(entry, 36)
		firstExtentIndex := le32(entry, 40)
		numExtents := le32(entry, 44)
		groupIndex := le32(entry, 48)

		firstOffset := uint64(firstExtentIndex)
		countOffset := uint64(numExtents)
		endOffset, ok := checkedAdd(firstOffset, countOffset)
		if !ok {
			return nil, &Error{Kind: KindOverflow, What: "partition extent range"}
		}
		if endOffset > uint64(len(extents)) {
			return nil, &Error{
				Kind: KindPartitionExtentRange, Partition: name,
				First: firstExtentIndex, Extents: uint32(len(extents)),
				Count: numExtents,
			}
		}
		first := int(firstOffset)
		end := int(endOffset)

		spans := make([]Span, 0, int(countOffset))
		logical := uint64(0)
		var firstLinearOffset *uint64
		for offset, extent := range extents[first:end] {
			extentIndex := first + offset
			if extent.TargetSource != 0 {
				return nil, &Error{
					Kind: KindUnsupportedTargetSource, Extent: extentIndex,
					TargetSource: extent.TargetSource,
				}
			}
			length, ok := checkedMul(extent.NumSectors, LPSectorBytes)
			if !ok {
				return nil, &Error{Kind: KindOverflow, What: "extent length"}
			}
			var target SpanTarget
			switch extent.TargetType {
			case TargetLinear:
				extentOffset, ok := checkedMul(extent.TargetData, LPSectorBytes)
				if !ok {
					return nil, &Error{Kind: KindOverflow, What: "extent offset"}
				}
				extentEnd, ok := checkedAdd(extentOffset, length)
				if !ok {
					return nil, &Error{Kind: KindOverflow, What: "extent end"}
				}
				if deviceSize != nil {
					if extentEnd > *deviceSize {
						return nil, &Error{
							Kind: KindExtentOutsideBlockDevice, Partition: name,
							Extent: extentIndex, Offset: extentOffset,
							Needed: length, DeviceSize: *deviceSize,
						}
					}
				} else {
					return nil, &Error{Kind: KindNoBlockDevice, Extent: extentIndex}
				}
				if extentEnd > imageLen {
					return nil, &Error{
						Kind: KindExtentOutsideImage, Partition: name,
						Extent: extentIndex, Offset: extentOffset,
						Needed: length, ImageLen: imageLen,
					}
				}
				if firstLinearOffset == nil {
					value := extentOffset
					firstLinearOffset = &value
				}
				target = SpanTarget{Kind: SpanLinear, ParentOffset: extentOffset}
			case TargetZero:
				target = SpanTarget{Kind: SpanZero}
			default:
				return nil, &Error{
					Kind: KindUnsupportedTargetType, Extent: extentIndex,
					TargetType: extent.TargetType,
				}
			}
			spans = append(spans, Span{Logical: logical, Len: length, Target: target})
			logical, ok = checkedAdd(logical, length)
			if !ok {
				return nil, &Error{Kind: KindOverflow, What: "partition length"}
			}
		}

		// The group index is metadata, not an extent placement. When the table
		// it names is missing or short the partition is still readable; the
		// name is simply not resolved.
		_ = groups

		out = append(out, Partition{
			Name:              name,
			Attributes:        attributes,
			FirstExtentIndex:  firstExtentIndex,
			NumExtents:        numExtents,
			GroupIndex:        groupIndex,
			Len:               logical,
			FirstLinearOffset: firstLinearOffset,
			Spans:             spans,
		})
	}
	return out, nil
}

func fixedName(bytes []byte) string {
	for index, b := range bytes {
		if b == 0 {
			bytes = bytes[:index]
			break
		}
	}
	return strings.ToValidUTF8(string(bytes), "�")
}

// hasGeometryMagic reports whether offset carries the geometry magic.
func kindOf(err error) Kind {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Kind
	}
	return ""
}

func hasGeometryMagic(src source.ByteSource, offset uint64) bool {
	length := src.Len()
	if offset > length || 4 > length-offset {
		return false
	}
	bytes, err := source.ReadVecAt(src, offset, 4)
	if err != nil {
		return false
	}
	return le32(bytes, 0) == GeometryMagic
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

func le16(bytes []byte, at int) uint16 {
	return uint16(bytes[at]) | uint16(bytes[at+1])<<8
}

func le32(bytes []byte, at int) uint32 {
	return uint32(bytes[at]) | uint32(bytes[at+1])<<8 | uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
}

func le64(bytes []byte, at int) uint64 {
	return uint64(le32(bytes, at)) | uint64(le32(bytes, at+4))<<32
}
