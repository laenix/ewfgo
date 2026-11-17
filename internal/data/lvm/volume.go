package lvm

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Volume errors. Callers test them with errors.Is.
var (
	ErrNoGroup               = errors.New("lvm: no volume group")
	ErrUnknownVolume         = errors.New("lvm: unknown logical volume")
	ErrNoExtentSize          = errors.New("lvm: no extent size")
	ErrUnknownPhysicalVolume = errors.New("lvm: unknown physical volume")
	ErrMissingPhysicalVolume = errors.New("lvm: physical volume not in the image")
	ErrNoPeStart             = errors.New("lvm: no pe_start")
	ErrUnsupportedLayout     = errors.New("lvm: unsupported logical-volume layout")
	ErrOverlap               = errors.New("lvm: overlapping segments")
	ErrOutsideParent         = errors.New("lvm: extent outside parent")
	ErrMissingMember         = errors.New("lvm: missing member image")
	ErrDuplicateMember       = errors.New("lvm: duplicate member image")
	ErrInconsistentExtent    = errors.New("lvm: inconsistent extent size")
	ErrZeroLengthSegment     = errors.New("lvm: zero-length segment")
	ErrAreaOutsidePV         = errors.New("lvm: stripe outside physical volume")
	ErrNotContiguous         = errors.New("lvm: logical extents not contiguous")
	ErrSizeMismatch          = errors.New("lvm: declared size mismatch")
	ErrDeviceSizeMismatch    = errors.New("lvm: device size mismatch")
	ErrOverflow              = errors.New("lvm: value overflows u64")
	ErrNoSegments            = errors.New("lvm: logical volume has no segments")
)

// PhysicalVolumeSource is one physical volume a logical volume's extents can
// be read from.
type PhysicalVolumeSource struct {
	// UUID is the label's 32-character form, without the dashes the text
	// metadata uses.
	UUID   string
	Source source.ByteSource
}

// LvmDiskMember is one physical-volume image and the LVM metadata read from it.
type LvmDiskMember struct {
	Source source.ByteSource
	LVM    *LVM
}

// StripePlacement is one physical volume a run's stripes sit on, and where the
// first of them starts.
type StripePlacement struct {
	// Parent indexes the logical volume's parents slice.
	Parent   uint16
	PVOffset uint64
}

// ExtentRun is one run of a logical volume and where it sits physically.
type ExtentRun struct {
	LVOffset    uint64
	Len         uint64
	PVOffset    uint64
	Parent      uint16
	StripeBytes uint64
	Stripes     []StripePlacement
}

// LvPlacement is one physical run of a logical volume.
type LvPlacement struct {
	PVUUID   string
	Member   int
	LVOffset uint64
	Offset   uint64
	Len      uint64
	Segment  uint64
	Column   *uint64
}

// LogicalVolumeSource is a read-only logical volume over one or more physical
// volumes.
type LogicalVolumeSource struct {
	id         source.ID
	parents    []PhysicalVolumeSource
	name       string
	length     uint64
	runs       []ExtentRun
	segments   []uint64 // segment index per run, parallel to runs
	placements []LvPlacement
	sectorSize uint32
	counters   source.Counters
}

// Open exposes logical volume name of l's group over parent, which must be the
// physical volume the metadata came from.
func Open(id source.ID, parent source.ByteSource, l *LVM, name string) (*LogicalVolumeSource, error) {
	if l.Group == nil {
		return nil, fmt.Errorf("%w", ErrNoGroup)
	}
	pvs := []PhysicalVolumeSource{{UUID: l.Label.PVUUID, Source: parent}}
	return OpenInGroup(id, l.Group, pvs, name)
}

// OpenInGroup exposes logical volume name of group over the physical volumes
// the caller found. A stripe on a PV outside pvs is refused: its bytes are not
// in this image, and zero would pass off a hole as data.
func OpenInGroup(id source.ID, group *VolumeGroup, pvs []PhysicalVolumeSource, name string) (*LogicalVolumeSource, error) {
	volume, ok := findLogicalVolume(group, name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownVolume, name)
	}
	if group.ExtentSize == 0 {
		return nil, fmt.Errorf("%w", ErrNoExtentSize)
	}
	extentBytes, ok := checkedMul64(group.ExtentSize, 512)
	if !ok {
		return nil, fmt.Errorf("%w: extent size", ErrOverflow)
	}

	type pending struct {
		run     ExtentRun
		segment uint64
	}
	var runs []pending

	for _, segment := range volume.Segments {
		stripeBytes, err := checkSegment(segment)
		if err != nil {
			return nil, err
		}
		length, ok := checkedMul64(segment.ExtentCount, extentBytes)
		if !ok {
			return nil, fmt.Errorf("%w: extent count", ErrOverflow)
		}
		if length == 0 {
			continue
		}
		lvOffset, ok := checkedMul64(segment.StartExtent, extentBytes)
		if !ok {
			return nil, fmt.Errorf("%w: segment start", ErrOverflow)
		}

		placements := make([]StripePlacement, 0, len(segment.Stripes))
		for _, stripe := range segment.Stripes {
			uuid := undashed(stripe.PVUUID)
			pv, ok := findPhysicalVolume(group, uuid)
			if !ok {
				return nil, fmt.Errorf("%w: %q", ErrUnknownPhysicalVolume, uuid)
			}
			member := -1
			for i, view := range pvs {
				if undashed(view.UUID) == uuid {
					member = i
					break
				}
			}
			if member < 0 {
				return nil, fmt.Errorf("%w: %q", ErrMissingPhysicalVolume, uuid)
			}
			if !pv.HasPEStart {
				return nil, fmt.Errorf("%w: logical volume %q", ErrNoPeStart, name)
			}
			if member > 0xFFFF {
				return nil, fmt.Errorf("%w: too many physical volumes", ErrUnsupportedLayout)
			}
			base, ok := checkedMul64(pv.PEStart, 512)
			if !ok {
				return nil, fmt.Errorf("%w: pe_start", ErrOverflow)
			}
			start, ok := checkedMul64(stripe.StartExtent, extentBytes)
			if !ok {
				return nil, fmt.Errorf("%w: stripe start", ErrOverflow)
			}
			pvOffset, ok := checkedAdd64(base, start)
			if !ok {
				return nil, fmt.Errorf("%w: physical offset", ErrOverflow)
			}
			placements = append(placements, StripePlacement{Parent: uint16(member), PVOffset: pvOffset})
		}
		if len(placements) == 0 {
			return nil, fmt.Errorf("%w: segment records no stripe", ErrUnsupportedLayout)
		}

		run := ExtentRun{
			LVOffset:    lvOffset,
			Len:         length,
			PVOffset:    placements[0].PVOffset,
			Parent:      placements[0].Parent,
			StripeBytes: stripeBytes,
		}
		if stripeBytes != 0 {
			run.Stripes = placements
		}
		runs = append(runs, pending{run: run, segment: segment.Index})
	}

	sort.SliceStable(runs, func(i, j int) bool { return runs[i].run.LVOffset < runs[j].run.LVOffset })

	var previousEnd uint64
	for _, item := range runs {
		if item.run.LVOffset < previousEnd {
			return nil, fmt.Errorf("%w at byte %d", ErrOverlap, item.run.LVOffset)
		}
		end, ok := checkedAdd64(item.run.LVOffset, item.run.Len)
		if !ok {
			return nil, fmt.Errorf("%w: logical range", ErrOverflow)
		}
		previousEnd = end
		if item.run.StripeBytes == 0 {
			parentLen := pvs[item.run.Parent].Source.Len()
			if item.run.PVOffset > parentLen || item.run.Len > parentLen-item.run.PVOffset {
				return nil, fmt.Errorf("%w: offset %d (+%d) parent %d",
					ErrOutsideParent, item.run.PVOffset, item.run.Len, parentLen)
			}
			continue
		}
		count := uint64(len(item.run.Stripes))
		for index, place := range item.run.Stripes {
			area := bytesOnStripe(item.run.Len, item.run.StripeBytes, count, uint64(index))
			parentLen := pvs[place.Parent].Source.Len()
			if place.PVOffset > parentLen || area > parentLen-place.PVOffset {
				return nil, fmt.Errorf("%w: offset %d (+%d) parent %d",
					ErrOutsideParent, place.PVOffset, area, parentLen)
			}
		}
	}

	lv := &LogicalVolumeSource{
		id:         id,
		parents:    append([]PhysicalVolumeSource(nil), pvs...),
		name:       name,
		length:     previousEnd,
		runs:       make([]ExtentRun, len(runs)),
		segments:   make([]uint64, len(runs)),
		sectorSize: 512,
	}
	if len(pvs) > 0 {
		lv.sectorSize = pvs[0].Source.SectorSize()
	}
	for i, item := range runs {
		lv.runs[i] = item.run
		lv.segments[i] = item.segment
	}
	lv.placements = placementsFor(lv.runs, lv.segments, lv.parents)
	return lv, nil
}

// Name returns the logical volume's name as the metadata records it.
func (s *LogicalVolumeSource) Name() string { return s.name }

// Parents returns the physical volumes the extents live on.
func (s *LogicalVolumeSource) Parents() []PhysicalVolumeSource { return s.parents }

// Runs returns the extent runs in logical order.
func (s *LogicalVolumeSource) Runs() []ExtentRun { return s.runs }

// Placements returns every physical run in logical order.
func (s *LogicalVolumeSource) Placements() []LvPlacement { return s.placements }

// AllocatedBytes returns the bytes covered by real extents.
func (s *LogicalVolumeSource) AllocatedBytes() uint64 {
	var total uint64
	for _, run := range s.runs {
		total += run.Len
	}
	return total
}

func (s *LogicalVolumeSource) SourceID() source.ID { return s.id }
func (s *LogicalVolumeSource) Len() uint64         { return s.length }
func (s *LogicalVolumeSource) SectorSize() uint32  { return s.sectorSize }
func (s *LogicalVolumeSource) IsEmpty() bool       { return s.length == 0 }
func (s *LogicalVolumeSource) Stats() source.Stats { return s.counters.Snapshot() }

func (s *LogicalVolumeSource) ImageID() source.ImageID {
	if len(s.parents) == 0 {
		return 0
	}
	return s.parents[0].Source.ImageID()
}

func (s *LogicalVolumeSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	n, err := s.readInto(offset, buf)
	if err != nil {
		return 0, err
	}
	s.counters.AddRead(n)
	return n, nil
}

func (s *LogicalVolumeSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

func (s *LogicalVolumeSource) readInto(offset uint64, buf []byte) (int, error) {
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	clear(buf[:want])
	end := offset + uint64(want)

	for i := range s.runs {
		run := &s.runs[i]
		runEnd := run.LVOffset + run.Len
		if runEnd <= offset || run.LVOffset >= end {
			continue
		}
		start := maxU64(run.LVOffset, offset)
		stop := minU64(runEnd, end)
		at := int(start - offset)
		short := false
		shortN := 0
		err := forEachPiece(run, start-run.LVOffset, stop-run.LVOffset,
			func(parent uint16, physical, length uint64) (bool, error) {
				chunk := buf[at : at+int(length)]
				n, err := s.parents[parent].Source.ReadAt(physical, chunk)
				if err != nil {
					return true, err
				}
				if n < len(chunk) {
					short = true
					shortN = at + n
					return true, nil
				}
				at += int(length)
				return false, nil
			})
		if err != nil {
			return 0, err
		}
		if short {
			return shortN, nil
		}
	}
	return want, nil
}

func (s *LogicalVolumeSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.length || length > s.length-offset {
		return out, source.NewOutOfRange(offset, length, s.length)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	cursor := offset

	for i := range s.runs {
		run := &s.runs[i]
		runEnd := run.LVOffset + run.Len
		if runEnd <= cursor || run.LVOffset >= end {
			continue
		}
		parentID := s.parents[run.Parent].Source.SourceID()
		if run.LVOffset > cursor {
			out = append(out, source.ParentRange{
				Parent: parentID, ParentOffset: 0, Len: run.LVOffset - cursor, Kind: source.RangeZero,
			})
		}
		start := maxU64(run.LVOffset, cursor)
		stop := minU64(runEnd, end)
		err := forEachPiece(run, start-run.LVOffset, stop-run.LVOffset,
			func(parent uint16, physical, pieceLen uint64) (bool, error) {
				out = append(out, source.ParentRange{
					Parent:       s.parents[parent].Source.SourceID(),
					ParentOffset: physical,
					Len:          pieceLen,
					Kind:         source.RangeData,
				})
				return false, nil
			})
		if err != nil {
			return out, err
		}
		cursor = stop
	}
	if cursor < end {
		out = append(out, source.ParentRange{
			Parent: s.parents[0].Source.SourceID(), ParentOffset: 0,
			Len: end - cursor, Kind: source.RangeZero,
		})
	}
	return out, nil
}

func (s *LogicalVolumeSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *LogicalVolumeSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	extents, err := s.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, extent := range extents {
		var parent *PhysicalVolumeSource
		for i := range s.parents {
			if s.parents[i].Source.SourceID() == extent.Parent {
				parent = &s.parents[i]
				break
			}
		}
		if parent != nil && extent.Kind == source.RangeData {
			mapped, err := parent.Source.MapToImage(extent.ParentOffset, extent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		imageID := s.ImageID()
		if parent != nil {
			imageID = parent.Source.ImageID()
		}
		out = append(out, source.ImageRange{
			ImageID: imageID, ImageOffset: 0, Len: extent.Len, Kind: extent.Kind,
		})
	}
	return out, nil
}

var _ source.ByteSource = (*LogicalVolumeSource)(nil)

func checkSegment(segment Segment) (uint64, error) {
	kind := segment.Kind
	if kind == "" {
		kind = "striped"
	}
	if kind != "striped" && kind != "linear" {
		return 0, fmt.Errorf("%w: segment type %q", ErrUnsupportedLayout, kind)
	}
	recorded := segment.StripeCount
	if recorded == 0 {
		recorded = uint64(len(segment.Stripes))
	}
	if recorded != uint64(len(segment.Stripes)) {
		return 0, fmt.Errorf("%w: stripe_count %d does not match %d recorded stripe(s)",
			ErrUnsupportedLayout, recorded, len(segment.Stripes))
	}
	if len(segment.Stripes) == 0 {
		return 0, fmt.Errorf("%w: segment records no stripe", ErrUnsupportedLayout)
	}
	if len(segment.Stripes) == 1 {
		return 0, nil
	}
	if !segment.HasStripeSize || segment.StripeSize == 0 {
		return 0, fmt.Errorf("%w: %d stripes without a stripe_size",
			ErrUnsupportedLayout, len(segment.Stripes))
	}
	count := uint64(len(segment.Stripes))
	if segment.ExtentCount%count != 0 {
		return 0, fmt.Errorf("%w: %d extents cannot be split evenly across %d stripes",
			ErrUnsupportedLayout, segment.ExtentCount, count)
	}
	stripeBytes, ok := checkedMul64(segment.StripeSize, 512)
	if !ok || stripeBytes == 0 {
		return 0, fmt.Errorf("%w: stripe size", ErrOverflow)
	}
	return stripeBytes, nil
}

func forEachPiece(run *ExtentRun, from, to uint64, fn func(parent uint16, physical, length uint64) (bool, error)) error {
	at := from
	for at < to {
		remaining := to - at
		if run.StripeBytes == 0 || len(run.Stripes) == 0 {
			physical := run.PVOffset + at
			at = to
			stop, err := fn(run.Parent, physical, remaining)
			if err != nil || stop {
				return err
			}
			continue
		}
		count := uint64(len(run.Stripes))
		chunk := at / run.StripeBytes
		within := at % run.StripeBytes
		length := run.StripeBytes - within
		if length > remaining {
			length = remaining
		}
		place := run.Stripes[chunk%count]
		physical := place.PVOffset + (chunk/count)*run.StripeBytes + within
		at += length
		stop, err := fn(place.Parent, physical, length)
		if err != nil || stop {
			return err
		}
	}
	return nil
}

func bytesOnStripe(length, stripeBytes, count, index uint64) uint64 {
	if length == 0 || stripeBytes == 0 || count == 0 {
		return 0
	}
	chunks := (length + stripeBytes - 1) / stripeBytes
	if index >= chunks {
		return 0
	}
	taken := (chunks-1-index)/count + 1
	last := chunks - 1
	if last%count == index {
		return (taken-1)*stripeBytes + (length - last*stripeBytes)
	}
	return taken * stripeBytes
}

func placementsFor(runs []ExtentRun, segments []uint64, parents []PhysicalVolumeSource) []LvPlacement {
	var placements []LvPlacement
	for index := range runs {
		run := &runs[index]
		segment := uint64(0)
		if index < len(segments) {
			segment = segments[index]
		}
		if run.StripeBytes == 0 || len(run.Stripes) == 0 {
			placements = append(placements, LvPlacement{
				PVUUID: parents[run.Parent].UUID, Member: int(run.Parent),
				LVOffset: run.LVOffset, Offset: run.PVOffset, Len: run.Len, Segment: segment,
			})
			continue
		}
		count := uint64(len(run.Stripes))
		for column, place := range run.Stripes {
			length := bytesOnStripe(run.Len, run.StripeBytes, count, uint64(column))
			if length == 0 {
				continue
			}
			col := uint64(column)
			placements = append(placements, LvPlacement{
				PVUUID: parents[place.Parent].UUID, Member: int(place.Parent),
				LVOffset: run.LVOffset, Offset: place.PVOffset, Len: length,
				Segment: segment, Column: &col,
			})
		}
	}
	return placements
}

func findLogicalVolume(group *VolumeGroup, name string) (LogicalVolume, bool) {
	for _, volume := range group.LogicalVolumes {
		if volume.Name == name {
			return volume, true
		}
	}
	return LogicalVolume{}, false
}

func findPhysicalVolume(group *VolumeGroup, uuid string) (PhysicalVolumeEntry, bool) {
	for _, pv := range group.PhysicalVolumes {
		if pv.UUID != "" && undashed(pv.UUID) == uuid {
			return pv, true
		}
	}
	return PhysicalVolumeEntry{}, false
}

// undashed strips the dashes LVM puts in text metadata, so the label's
// 32-character PV UUID and the metadata's dashed form compare equal.
func undashed(uuid string) string {
	return strings.ReplaceAll(uuid, "-", "")
}

func checkedMul64(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}

func checkedAdd64(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum >= a
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
