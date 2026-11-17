package unlock

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
	"github.com/laenix/ewfgo/internal/data/source"
)

// bootBackup names the relocated copy of the volume's first sectors.
type bootBackup struct {
	offset uint64
	size   uint64
}

// Source is a decrypted BitLocker volume as a byte source.
//
// Logical sector n is stored at dataOffset + n in the encrypted volume (or in
// the relocated volume-header copy for the first backup sectors), and is
// decrypted with that physical byte offset as XTS sector number or CBC IV
// input.
type Source struct {
	id         source.ID
	parent     source.ByteSource
	cipher     *sectorCipher
	dataOffset uint64
	bootBackup *bootBackup
	length     uint64
	counters   source.Counters
}

func newSource(id source.ID, parent source.ByteSource, method uint16, fvek []byte,
	dataOffset uint64, backup *bootBackup, length uint64) (*Source, error) {
	if parent == nil {
		return nil, fmt.Errorf("%w: nil parent source", ErrGeometry)
	}
	cipher, err := newSectorCipher(method, fvek)
	if err != nil {
		return nil, err
	}
	if dataOffset > parent.Len() {
		return nil, fmt.Errorf("%w: data offset %d past end %d", ErrGeometry, dataOffset, parent.Len())
	}
	return &Source{
		id:         id,
		parent:     parent,
		cipher:     cipher,
		dataOffset: dataOffset,
		bootBackup: backup,
		length:     length,
	}, nil
}

// SourceID implements source.ByteSource.
func (s *Source) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *Source) Len() uint64 { return s.length }

// ImageID implements source.ByteSource.
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *Source) SectorSize() uint32 { return uint32(SectorBytes) }

// ReadAt implements source.ByteSource.
func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readDecrypted(offset, buf, false)
}

// ReadAtLossy implements source.ByteSource.
func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readDecrypted(offset, buf, true)
}

// DataOffset returns where the decrypted volume begins in the encrypted one.
func (s *Source) DataOffset() uint64 { return s.dataOffset }

// Stats implements source.ByteSource.
func (s *Source) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *Source) IsEmpty() bool { return s.length == 0 }

func (s *Source) bounds(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

func (s *Source) physical(logical uint64) uint64 {
	if s.bootBackup != nil && logical < s.bootBackup.size {
		return s.bootBackup.offset + logical
	}
	return s.dataOffset + logical
}

type physicalRun struct {
	physical uint64
	length   uint64
}

func (s *Source) physicalRuns(offset, length uint64) []physicalRun {
	if length == 0 {
		return nil
	}
	var runs []physicalRun
	logical := offset
	remaining := length
	for remaining > 0 {
		physical := s.physical(logical)
		run := remaining
		if s.bootBackup != nil && logical < s.bootBackup.size {
			if rest := s.bootBackup.size - logical; rest < run {
				run = rest
			}
		}
		runs = append(runs, physicalRun{physical: physical, length: run})
		logical += run
		remaining -= run
	}
	return runs
}

// ExtentsInto implements source.ByteSource. A range that straddles the
// relocated volume-header boundary is split into one run per physical region.
func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return out, err
	}
	for _, run := range s.physicalRuns(offset, length) {
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: run.physical,
			Len:          run.length,
			Kind:         source.RangeData,
		})
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.bounds(offset, length); err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, run := range s.physicalRuns(offset, length) {
		ranges, err := s.parent.MapToImage(run.physical, run.length)
		if err != nil {
			return nil, err
		}
		out = append(out, ranges...)
	}
	return out, nil
}

func (s *Source) readDecrypted(offset uint64, out []byte, lossy bool) (int, error) {
	if len(out) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(out)), s.length)
	}
	want := s.length - offset
	if uint64(len(out)) < want {
		want = uint64(len(out))
	}
	alignedStart := offset - offset%SectorBytes
	alignedEnd := offset + want
	if rem := alignedEnd % SectorBytes; rem != 0 {
		alignedEnd += SectorBytes - rem
	}
	alignedLen := int(alignedEnd - alignedStart)
	buffer := make([]byte, alignedLen)

	contiguous := true
	if s.bootBackup != nil {
		contiguous = alignedStart >= s.bootBackup.size || alignedEnd <= s.bootBackup.size
	}
	if contiguous {
		physical := s.physical(alignedStart)
		n, err := s.readParent(physical, buffer, lossy)
		if err != nil {
			return 0, err
		}
		buffer = buffer[:n]
		if err := s.decryptSectors(alignedStart, buffer); err != nil {
			return 0, decryptError(alignedStart, uint64(n), s.length, err)
		}
	} else {
		filled := 0
		for filled < len(buffer) {
			logical := alignedStart + uint64(filled)
			physical := s.physical(logical)
			run := uint64(len(buffer) - filled)
			if s.bootBackup != nil && logical < s.bootBackup.size {
				if rest := s.bootBackup.size - logical; rest < run {
					run = rest
				}
			}
			n, err := s.readParent(physical, buffer[filled:filled+int(run)], lossy)
			if n > 0 {
				if derr := s.decryptSectors(logical, buffer[filled:filled+n]); derr != nil {
					return 0, decryptError(logical, uint64(n), s.length, derr)
				}
			}
			filled += n
			if err != nil {
				return 0, err
			}
			if n == 0 || n < int(run) {
				break
			}
		}
		buffer = buffer[:filled]
	}

	skip := int(offset - alignedStart)
	available := 0
	if skip < len(buffer) {
		available = len(buffer) - skip
		if available > int(want) {
			available = int(want)
		}
		copy(out[:available], buffer[skip:skip+available])
	}
	s.counters.AddRead(available)
	return available, nil
}

func (s *Source) readParent(offset uint64, buf []byte, lossy bool) (int, error) {
	if lossy {
		return s.parent.ReadAtLossy(offset, buf)
	}
	return s.parent.ReadAt(offset, buf)
}

// decryptSectors decrypts sector-aligned buffer whose first byte is logical
// offset start.
func (s *Source) decryptSectors(start uint64, buffer []byte) error {
	if len(buffer) == 0 {
		return nil
	}
	first := start / SectorBytes
	for at := 0; at < len(buffer); at += int(SectorBytes) {
		end := at + int(SectorBytes)
		if end > len(buffer) {
			end = len(buffer)
		}
		logical := (first + uint64(at/int(SectorBytes))) * SectorBytes
		physical := s.physical(logical)
		if err := s.cipher.decrypt(physical, buffer[at:end]); err != nil {
			return fmt.Errorf("sector at logical offset %d: %w", logical, err)
		}
	}
	return nil
}

func decryptError(offset, length, sourceLen uint64, err error) error {
	return &source.Error{
		Kind:      source.ErrDecrypt,
		Offset:    offset,
		Len:       length,
		SourceLen: sourceLen,
		Reason:    err.Error(),
	}
}

// findDataArea finds where the decrypted volume begins.
//
// The first answer is an in-place boot record: a sector that decrypts to a
// boot record whose own sector count fits the bytes after it. When none is
// found, the volume-header copy the metadata block points at is tested and the
// data area is taken to start after the last metadata block.
func findDataArea(src source.ByteSource, cipher *sectorCipher, info *bitlocker.Info) (uint64, *bootBackup, error) {
	length := src.Len()
	limit := length
	if limit > MaxBootScanBytes {
		limit = MaxBootScanBytes
	}
	var best *uint64
	var bestSlack uint64
	for offset := SectorBytes; offset+SectorBytes <= limit; offset += SectorBytes {
		geometry, ok, err := bootRecordAt(src, cipher, offset, length)
		if err != nil {
			return 0, nil, err
		}
		if !ok {
			continue
		}
		available := length - offset
		if !geometry.fits(available) {
			continue
		}
		slack := available - geometry.declared()
		if best == nil || slack < bestSlack {
			found := offset
			best = &found
			bestSlack = slack
		}
		if slack == 0 {
			break
		}
	}
	if best != nil {
		return *best, nil, nil
	}

	metadata := info.Metadata
	if metadata == nil {
		return 0, nil, ErrNoVolumeBootRecord
	}
	headerOffset := metadata.Block.VolumeHeaderOffset
	if metadata.Block.HasVolumeHeaderOffset && headerOffset != 0 && headerOffset+SectorBytes <= length {
		if _, ok, err := bootRecordAt(src, cipher, headerOffset, length); err != nil {
			return 0, nil, err
		} else if ok {
			sectors := uint64(metadata.Block.VolumeHeaderSectors)
			if sectors == 0 {
				sectors = 16
			}
			backupBytes := sectors * SectorBytes
			if backupBytes > length-headerOffset {
				backupBytes = length - headerOffset
			}
			dataOffset := metadataEnd(info)
			if rem := dataOffset % SectorBytes; rem != 0 {
				dataOffset += SectorBytes - rem
			}
			if dataOffset < length {
				return dataOffset, &bootBackup{offset: headerOffset, size: backupBytes}, nil
			}
		}
	}
	return 0, nil, ErrNoVolumeBootRecord
}

// metadataEnd is where the last metadata block ends, from the volume header's
// offsets.
func metadataEnd(info *bitlocker.Info) uint64 {
	size := info.Volume.MetadataSize
	var end uint64
	for _, offset := range info.Volume.MetadataOffsets {
		if offset == 0 {
			continue
		}
		candidate := satAdd(offset, size)
		if candidate > end {
			end = candidate
		}
	}
	return end
}

func satAdd(a, b uint64) uint64 {
	if b > ^uint64(0)-a {
		return ^uint64(0)
	}
	return a + b
}

type bootGeometry struct {
	bytesPerSector uint64
	totalSectors   uint64
}

func (g bootGeometry) declared() uint64 {
	if g.bytesPerSector != 0 && g.totalSectors > ^uint64(0)/g.bytesPerSector {
		return ^uint64(0)
	}
	return g.bytesPerSector * g.totalSectors
}

func (g bootGeometry) fits(available uint64) bool {
	declared := g.declared()
	return declared != 0 && declared <= available && available-declared <= BootSizeSlackBytes
}

func bootRecordAt(src source.ByteSource, cipher *sectorCipher, offset, length uint64) (bootGeometry, bool, error) {
	var sector [SectorBytes]byte
	if offset+SectorBytes > length {
		return bootGeometry{}, false, nil
	}
	if err := source.ReadExactAt(src, offset, sector[:]); err != nil {
		return bootGeometry{}, false, nil
	}
	if err := cipher.decrypt(offset, sector[:]); err != nil {
		return bootGeometry{}, false, fmt.Errorf("%w: sector at %d: %v", ErrGeometry, offset, err)
	}
	geometry, ok := bootGeometryOf(sector[:])
	return geometry, ok, nil
}

func bootGeometryOf(sector []byte) (bootGeometry, bool) {
	if len(sector) < int(SectorBytes) || sector[510] != 0x55 || sector[511] != 0xaa {
		return bootGeometry{}, false
	}
	ntfs := string(sector[3:11]) == "NTFS    "
	exfat := string(sector[3:11]) == "EXFAT   "
	if !ntfs && !exfat {
		return bootGeometry{}, false
	}
	bytesPerSector := uint64(le16(sector, 0x0b))
	switch bytesPerSector {
	case 512, 1024, 2048, 4096:
	default:
		return bootGeometry{}, false
	}
	total := le64(sector, 0x28)
	if wide := uint64(le32(sector, 0x20)); wide > total {
		total = wide
	}
	return bootGeometry{bytesPerSector: bytesPerSector, totalSectors: total}, true
}

var _ source.ByteSource = (*Source)(nil)
