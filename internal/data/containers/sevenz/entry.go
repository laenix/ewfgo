// One 7z file exposed as a source.ByteSource.
//
// The bytes of an entry live inside its folder's decoded output.  The first
// read of any member decodes the folder through volume.folderBytes, which
// caches one folder at a time; a solid archive's members therefore share a
// single decode.  The folder's recorded CRC-32 and each substream's CRC are
// checked by the volume, and a mismatch is counted as corrupt bytes on this
// source without withholding the recovered data.
//
// A 7z entry has no offset of its own in the file: every member of a folder is
// derived from that folder's packed streams, so a logical range maps to all of
// them rather than to one region.

package sevenz

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

// EntrySource is one 7z file exposed as a ByteSource.
type EntrySource struct {
	id     source.ID
	parent source.ByteSource
	volume *volume
	entry  archive.Entry
	folder int
	sub    int
	// offset is the offset of the substream inside the decoded folder output.
	offset   uint64
	length   uint64
	counters source.Counters
}

// Entry returns the listed entry this source exposes.
func (s *EntrySource) Entry() archive.Entry { return s.entry }

// Folder returns the folder that holds this entry's bytes, when it has any.
func (s *EntrySource) Folder() (int, bool) {
	if s.volume == nil {
		return 0, false
	}
	return s.folder, true
}

// Substream returns the substream index inside Folder.
func (s *EntrySource) Substream() int { return s.sub }

func (s *EntrySource) folderData() (*cachedFolder, error) {
	if s.volume == nil {
		return nil, source.NewCorrupt(0, fmt.Sprintf("7z entry %s has no stream", s.entry.Path))
	}
	return s.volume.folderBytes(s.folder)
}

func (s *EntrySource) checkBounds(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

// SourceID implements source.ByteSource.
func (s *EntrySource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *EntrySource) Len() uint64 { return s.length }

// ImageID implements source.ByteSource.
func (s *EntrySource) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *EntrySource) SectorSize() uint32 { return s.parent.SectorSize() }

// ReadAt implements source.ByteSource.
func (s *EntrySource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := uint64(len(buf))
	if want > s.length-offset {
		want = s.length - offset
	}
	folder, err := s.folderData()
	if err != nil {
		return 0, err
	}
	start := s.offset + offset
	if start < s.offset || start > uint64(len(folder.bytes)) {
		return 0, source.NewCorrupt(offset, fmt.Sprintf(
			"7z entry %s lies past the decoded folder", s.entry.Path))
	}
	end := start + want
	if end < start || end > uint64(len(folder.bytes)) {
		return 0, source.NewCorrupt(offset, fmt.Sprintf(
			"7z entry %s needs folder bytes [%d, %d) but the folder decoded %d",
			s.entry.Path, start, end, len(folder.bytes)))
	}
	copy(buf[:want], folder.bytes[start:end])
	if s.sub >= 0 && s.sub < len(folder.corrupt) && folder.corrupt[s.sub] {
		s.counters.AddCorrupt(want)
	}
	s.counters.AddRead(int(want))
	return int(want), nil
}

// ReadAtLossy implements source.ByteSource.
func (s *EntrySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := uint64(len(buf))
	if want > s.length-offset {
		want = s.length - offset
	}
	n, err := s.ReadAt(offset, buf[:want])
	if err != nil {
		for index := range buf[:want] {
			buf[index] = 0
		}
		s.counters.AddCorrupt(want)
		return int(want), nil
	}
	return n, nil
}

// ExtentsInto implements source.ByteSource.
func (s *EntrySource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.checkBounds(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	if s.volume == nil {
		return out, nil
	}
	target, ok := s.volume.folder(s.folder)
	if !ok {
		return out, source.NewCorrupt(0, fmt.Sprintf(
			"7z entry %s names a missing folder", s.entry.Path))
	}
	start := target.firstPackStream
	if start < 0 {
		start = 0
	}
	if start > len(s.volume.packed) {
		start = len(s.volume.packed)
	}
	end := target.firstPackStream + target.packedCount
	if end < start {
		end = start
	}
	if end > len(s.volume.packed) {
		end = len(s.volume.packed)
	}
	if start == end {
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: 0,
			Len:          1,
			Kind:         source.RangeError,
		})
		return out, nil
	}
	for _, rng := range s.volume.packed[start:end] {
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: rng.offset,
			Len:          rng.size,
			Kind:         source.RangeData,
		})
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *EntrySource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *EntrySource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.checkBounds(offset, length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	if s.volume == nil {
		return nil, nil
	}
	target, ok := s.volume.folder(s.folder)
	if !ok {
		return nil, source.NewCorrupt(0, fmt.Sprintf(
			"7z entry %s names a missing folder", s.entry.Path))
	}
	start := target.firstPackStream
	if start < 0 {
		start = 0
	}
	if start > len(s.volume.packed) {
		start = len(s.volume.packed)
	}
	end := target.firstPackStream + target.packedCount
	if end < start {
		end = start
	}
	if end > len(s.volume.packed) {
		end = len(s.volume.packed)
	}
	if start == end {
		return []source.ImageRange{{
			ImageID:     s.parent.ImageID(),
			ImageOffset: 0,
			Len:         length,
			Kind:        source.RangeError,
		}}, nil
	}
	var ranges []source.ImageRange
	for _, rng := range s.volume.packed[start:end] {
		translated, err := s.parent.MapToImage(rng.offset, rng.size)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, translated...)
	}
	return ranges, nil
}

// Stats implements source.ByteSource.
func (s *EntrySource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *EntrySource) IsEmpty() bool { return s.length == 0 }

var _ source.ByteSource = (*EntrySource)(nil)
