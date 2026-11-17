package imsm

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MemberSource is a ByteSource over one volume's data area on one member.
//
// The stream begins at the map's PBAOfLBA0 and is exactly one member's
// component (NumDataStripes*BlocksPerStrip sectors, doubled for RAID1/10).
// For a mirror that is a whole copy of the volume; for a striped member it is
// only that member's share, not the array, and the caller must consult the
// level before treating it as a volume. Every byte is translated back to the
// member's own offset, so a report can cite the image location a filesystem
// byte came from. A member too short to hold the recorded data area is refused
// rather than clamped.
type MemberSource struct {
	id         source.ID
	parent     source.ByteSource
	dataOffset uint64
	length     uint64
	sectorSize uint32
	counters   source.Counters
}

// NewMemberSource opens the data area container.Volumes[volumeIndex] records on
// one member image.
func NewMemberSource(id source.ID, parent source.ByteSource, container *Container, volumeIndex int) (*MemberSource, error) {
	if volumeIndex < 0 || volumeIndex >= len(container.Volumes) {
		return nil, unsupportedf("container %s records no volume %d", container.ContainerUUID(), volumeIndex)
	}
	volume := &container.Volumes[volumeIndex]
	component, ok := volume.Map.ComponentBytes(container.SectorSize)
	if !ok || component == 0 {
		reason := "zero stripes or blocks per stripe"
		if volume.Map.NumDataStripes != 0 && volume.Map.BlocksPerStrip != 0 {
			reason = "the per-member byte count overflows"
		}
		return nil, unsupportedf("volume %s records no placeable data area (%s)",
			volumeLabel(container, volumeIndex), reason)
	}
	dataOffset := volume.Map.DataOffsetBytes(container.SectorSize)
	parentLen := parent.Len()
	if dataOffset > parentLen {
		return nil, source.NewCorrupt(dataOffset,
			fmt.Sprintf("the IMSM data area of volume %s starts at byte %d, past the %d-byte member",
				volumeLabel(container, volumeIndex), dataOffset, parentLen))
	}
	if parentLen-dataOffset < component {
		return nil, unsupportedf("the member is %d bytes, shorter than volume %s's data area, which ends at byte %d",
			parentLen, volumeLabel(container, volumeIndex), dataOffset+component)
	}
	return &MemberSource{
		id:         id,
		parent:     parent,
		dataOffset: dataOffset,
		length:     component,
		sectorSize: container.SectorSize,
	}, nil
}

// DataOffset returns the byte offset of the data area within the member.
func (s *MemberSource) DataOffset() uint64 { return s.dataOffset }

func (s *MemberSource) bounds(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

// SourceID implements source.ByteSource.
func (s *MemberSource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *MemberSource) Len() uint64 { return s.length }

// ImageID implements source.ByteSource.
func (s *MemberSource) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *MemberSource) SectorSize() uint32 { return s.sectorSize }

// ReadAt implements source.ByteSource.
func (s *MemberSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if err := s.bounds(offset, uint64(len(buf))); err != nil {
		return 0, err
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	n, err := s.parent.ReadAt(s.dataOffset+offset, buf[:want])
	if n > 0 {
		s.counters.AddRead(n)
	}
	return n, err
}

// ReadAtLossy implements source.ByteSource.
func (s *MemberSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if err := s.bounds(offset, uint64(len(buf))); err != nil {
		return 0, err
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	n, err := s.parent.ReadAtLossy(s.dataOffset+offset, buf[:want])
	if n > 0 {
		s.counters.AddRead(n)
	}
	return n, err
}

// ExtentsInto implements source.ByteSource.
func (s *MemberSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	return append(out, source.ParentRange{
		Parent:       s.parent.SourceID(),
		ParentOffset: s.dataOffset + offset,
		Len:          length,
		Kind:         source.RangeData,
	}), nil
}

// Extents returns the complete translation for [offset, offset+length).
func (s *MemberSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *MemberSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return nil, err
	}
	return s.parent.MapToImage(s.dataOffset+offset, length)
}

// Stats implements source.ByteSource.
func (s *MemberSource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *MemberSource) IsEmpty() bool { return s.length == 0 }

var _ source.ByteSource = (*MemberSource)(nil)

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
