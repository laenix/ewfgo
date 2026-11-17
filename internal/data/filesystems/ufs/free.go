package ufs

import (
	"fmt"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// FreeRun is one run of free fragments as a byte range of the volume.
type FreeRun struct {
	Offset uint64
	Len    uint64
}

// End returns the first byte past the run.
func (r FreeRun) End() uint64 { return r.Offset + r.Len }

// FreeSpace is the free-fragment map read from the cylinder-group bitmaps.
//
// One bit stands for one fragment (fs_fsize), not one block. A set bit means
// allocated. The last group is usually short, and bits past its count are
// ignored rather than read as free.
type FreeSpace struct {
	covered      uint64
	volumeLen    uint64
	fragSize     uint64
	runs         []FreeRun
	notes        []string
	scannedFree  uint64
	recordedFree uint64
}

// Covered returns the bytes the superblock declares, whether or not the image
// holds them.
func (f *FreeSpace) Covered() uint64 { return f.covered }

// VolumeLen returns the image length the scan saw.
func (f *FreeSpace) VolumeLen() uint64 { return f.volumeLen }

// Runs returns the free runs in offset order.
func (f *FreeSpace) Runs() []FreeRun { return f.runs }

// Notes returns the caveats the scan recorded.
func (f *FreeSpace) Notes() []string { return append([]string(nil), f.notes...) }

// FreeBytes returns the free bytes the bitmaps marked.
func (f *FreeSpace) FreeBytes() uint64 { return f.scannedFree * f.fragSize }

// ScannedFree returns the free fragments counted from the bitmaps.
func (f *FreeSpace) ScannedFree() uint64 { return f.scannedFree }

// RecordedFree returns the free fragments the group summaries claim.
func (f *FreeSpace) RecordedFree() uint64 { return f.recordedFree }

// IsFree reports whether every byte in [offset, offset+length) lies in a free
// run. A range past the scanned volume is not free: the bitmap says nothing
// about it.
func (f *FreeSpace) IsFree(offset, length uint64) bool {
	if length == 0 {
		return offset <= f.covered
	}
	end, ok := addCheck(offset, length)
	if !ok || end > f.covered {
		return false
	}
	index := sort.Search(len(f.runs), func(index int) bool { return f.runs[index].Offset > offset }) - 1
	if index < 0 {
		return false
	}
	return f.runs[index].End() >= end
}

// freeSpace scans the cylinder-group fragment bitmaps.
func freeSpace(src source.ByteSource, sb *Superblock) (*FreeSpace, error) {
	frag := sb.FragSize()
	total := sb.SizeFrags
	fpg := uint64(sb.FPG)
	if frag == 0 || total == 0 || fpg == 0 {
		return nil, corruptf("the superblock declares no fragments, so there is no bitmap to scan")
	}
	volumeLen := src.Len()
	covered := satMul(total, frag)
	present := volumeLen / frag
	if present > total {
		present = total
	}
	space := &FreeSpace{covered: covered, volumeLen: volumeLen, fragSize: frag}
	if present < total {
		space.notes = append(space.notes, fmt.Sprintf(
			"the superblock declares %d fragments but the image holds %d; only the present groups are scanned",
			total, present))
	}
	if !sb.IsClean() {
		space.notes = append(space.notes, "the volume was not cleanly unmounted; free space is the last written bitmap state (Soft Updates and the SU+J journal are not replayed)")
	}
	cgSize := int(sb.CGSize)
	raw := make([]byte, cgSize)
	for index := uint64(0); index < uint64(sb.NCG); index++ {
		base := sb.CGBase(index)
		if base >= present {
			break
		}
		offset, err := sb.FragmentOffset(sb.CGTOD(index))
		if err != nil {
			return nil, err
		}
		if offset > volumeLen || uint64(cgSize) > volumeLen-offset {
			space.notes = append(space.notes, fmt.Sprintf(
				"cylinder group %d starts at byte %d, past the image's %d bytes; the group is not scanned",
				index, offset, volumeLen))
			break
		}
		if err := source.ReadExactAt(src, offset, raw); err != nil {
			return nil, err
		}
		if sb.Endian.U32(raw, 4) != CGMagic {
			return nil, corruptf("cylinder group %d at byte %d does not hold the %#08x magic", index, offset, CGMagic)
		}
		ndblk := uint64(sb.Endian.U32(raw, CGNDBlk))
		if ndblk == 0 || ndblk > fpg {
			return nil, corruptf("cylinder group %d claims %d fragments; a group holds 1..=%d", index, ndblk, fpg)
		}
		bits := ndblk
		if present-base < bits {
			bits = present - base
		}
		freeOff := int(sb.Endian.U32(raw, CGFreeOff))
		needed := int((bits + 7) / 8)
		if freeOff == 0 || freeOff > cgSize || needed > cgSize-freeOff {
			return nil, unsupportedf("cylinder group %d places its %d-byte free bitmap at byte %d of a %d-byte header", index, needed, freeOff, cgSize)
		}
		fragmentBase := base * frag
		for byteIndex := 0; byteIndex < needed; byteIndex++ {
			value := raw[freeOff+byteIndex]
			firstBit := uint64(byteIndex) * 8
			count := uint64(8)
			if bits-firstBit < count {
				count = bits - firstBit
			}
			if value == 0 {
				space.appendFreeRun(fragmentBase+firstBit*frag, count*frag)
				continue
			}
			for bit := uint64(0); bit < count; bit++ {
				if value&(1<<bit) == 0 {
					space.appendFreeRun(fragmentBase+(firstBit+bit)*frag, frag)
				}
			}
		}
		space.recordedFree += uint64(sb.Endian.U32(raw, CGNBFree))*uint64(sb.Frag) +
			uint64(sb.Endian.U32(raw, CGNFFree))
	}
	space.scannedFree = freeBytes(space.runs) / frag
	if space.scannedFree != space.recordedFree {
		space.notes = append(space.notes, fmt.Sprintf(
			"the cylinder-group summaries record %d free fragments but the bitmaps mark %d",
			space.recordedFree, space.scannedFree))
	}
	return space, nil
}

func (f *FreeSpace) appendFreeRun(offset, length uint64) {
	if length == 0 {
		return
	}
	if count := len(f.runs); count > 0 {
		last := &f.runs[count-1]
		if last.Offset+last.Len == offset {
			last.Len += length
			return
		}
	}
	f.runs = append(f.runs, FreeRun{Offset: offset, Len: length})
}

func freeBytes(runs []FreeRun) uint64 {
	var total uint64
	for _, run := range runs {
		total += run.Len
	}
	return total
}
