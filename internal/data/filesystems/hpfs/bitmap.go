package hpfs

import "github.com/laenix/ewfgo/internal/data/source"

// Allocation-bitmap geometry. The volume is divided into bands of 16384
// sectors (8 MiB); each band has a 2048-byte bitmap in which a set bit marks a
// free sector. The superblock's Bitmaps field names the first sector of an
// array of little-endian sector numbers, one per band.
const (
	// BandSectors is how many sectors one bitmap band covers.
	BandSectors uint64 = 16_384
	// BitmapBytes is one band's bitmap size.
	BitmapBytes uint64 = 2_048
	// BitmapSectors is how many sectors one bitmap occupies.
	BitmapSectors uint32 = 4
	// DirectoryEntries is how many sector numbers one directory sector holds.
	DirectoryEntries uint64 = 128
	// MaxBands bounds a free-space walk at 64 GiB.
	MaxBands uint64 = 8_192
)

// FreeRun is one run of free bytes at a volume-relative offset.
type FreeRun struct {
	Offset uint64
	Len    uint64
}

// End returns the first byte after the run.
func (r FreeRun) End() uint64 { return r.Offset + r.Len }

// FreeSpace is a volume's free bytes as its allocation bitmap describes them.
type FreeSpace struct {
	volumeLen uint64
	covered   uint64
	basis     string
	freeBytes uint64
	runs      []FreeRun
	notes     []string
}

// Runs returns the free runs, sorted and merged.
func (f *FreeSpace) Runs() []FreeRun { return f.runs }

// RunCount returns how many runs the map holds.
func (f *FreeSpace) RunCount() int { return len(f.runs) }

// FreeBytes returns the total free bytes.
func (f *FreeSpace) FreeBytes() uint64 { return f.freeBytes }

// Basis returns where the answer came from.
func (f *FreeSpace) Basis() string { return f.basis }

// Covered returns the end of the bytes the map describes.
func (f *FreeSpace) Covered() uint64 { return f.covered }

// Notes returns the caveats the scan recorded.
func (f *FreeSpace) Notes() []string { return append([]string(nil), f.notes...) }

// IsFree reports whether every byte of [offset, offset+length) lies in one
// free run. Bytes outside the described area are never free.
func (f *FreeSpace) IsFree(offset, length uint64) bool {
	if length == 0 {
		return true
	}
	end := offset + length
	if end < offset || end > f.covered {
		return false
	}
	for _, run := range f.runs {
		if run.Offset > offset {
			break
		}
		if end <= run.Offset+run.Len {
			return true
		}
	}
	return false
}

// freeSpace reads the allocation bitmap and builds the volume's free-space
// map. The scan is driven from the volume's own byte length, never from the
// declared size alone: a truncated image must not be credited with free
// sectors the source cannot show.
func freeSpace(src source.ByteSource, sb *Superblock) (*FreeSpace, error) {
	if sb.Bitmaps == 0 {
		return nil, unsupportedf("the superblock records no allocation-bitmap sector, so no sector's state is known")
	}
	coveredSectors := sb.VolumeBytes / SectorBytes
	if coveredSectors == 0 {
		return nil, corruptf("the image is shorter than one sector")
	}
	covered := coveredSectors * SectorBytes
	bands := (coveredSectors + BandSectors - 1) / BandSectors
	if bands == 0 {
		return nil, corruptf("the volume declares no sectors")
	}
	if bands > MaxBands {
		return nil, unsupportedf("the allocation bitmap covers %d bands; this reader walks at most %d (64 GiB)",
			bands, MaxBands)
	}
	directorySectors := (bands + DirectoryEntries - 1) / DirectoryEntries
	if directorySectors > 0xffff_ffff {
		return nil, corruptf("the bitmap-directory sector count overflows")
	}
	directoryStart, err := sb.ValidateSectorRange(uint32(sb.Bitmaps), uint32(directorySectors),
		"the bitmap directory")
	if err != nil {
		return nil, err
	}

	builder := &freeSpaceBuilder{}
	bitmap := make([]byte, BitmapBytes)
	for band := uint64(0); band < bands; band++ {
		entry := make([]byte, 4)
		entryOffset := directoryStart + band*4
		if err := source.ReadExactAt(src, entryOffset, entry); err != nil {
			return nil, err
		}
		bitmapSector := le32(entry, 0)
		if bitmapSector == 0 {
			return nil, corruptf("band %d has no allocation-bitmap sector recorded", band)
		}
		bitmapOffset, err := sb.ValidateSectorRange(bitmapSector, BitmapSectors,
			"the allocation bitmap for band "+itoa(int(band)))
		if err != nil {
			return nil, err
		}
		if err := source.ReadExactAt(src, bitmapOffset, bitmap); err != nil {
			return nil, err
		}
		start := band * BandSectors
		stop := start + BandSectors
		if stop > coveredSectors {
			stop = coveredSectors
		}
		for sector := start; sector < stop; sector++ {
			index := sector - start
			free := bitmap[index/8]&(1<<(index%8)) != 0
			builder.feed(sector, free)
		}
	}
	return builder.finish(sb.DeclaredBytes, covered), nil
}

type freeSpaceBuilder struct {
	runs      []FreeRun
	freeBytes uint64
}

func (b *freeSpaceBuilder) feed(sector uint64, free bool) {
	if !free {
		return
	}
	offset := sector * SectorBytes
	if len(b.runs) > 0 {
		last := &b.runs[len(b.runs)-1]
		if last.Offset+last.Len == offset {
			last.Len += SectorBytes
			b.freeBytes += SectorBytes
			return
		}
	}
	b.runs = append(b.runs, FreeRun{Offset: offset, Len: SectorBytes})
	b.freeBytes += SectorBytes
}

func (b *freeSpaceBuilder) finish(volumeLen, covered uint64) *FreeSpace {
	return &FreeSpace{
		volumeLen: volumeLen,
		covered:   covered,
		basis:     "hpfs.bitmap",
		freeBytes: b.freeBytes,
		runs:      b.runs,
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits [20]byte
	at := len(digits)
	for value > 0 {
		at--
		digits[at] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		at--
		digits[at] = '-'
	}
	return string(digits[at:])
}
