package ewf

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// fakeSectors is a hermetic sector device: byte i at offset i.
type fakeSectors struct {
	data       []byte
	sectorSize uint32
	err        error
}

func (f *fakeSectors) TotalSectors() uint64 {
	if f.sectorSize == 0 {
		return 0
	}
	return uint64(len(f.data)) / uint64(f.sectorSize)
}

func (f *fakeSectors) SectorSize() uint32 { return f.sectorSize }

func (f *fakeSectors) ReadSectors(lba, count uint64) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	start := lba * uint64(f.sectorSize)
	end := (lba + count) * uint64(f.sectorSize)
	if end > uint64(len(f.data)) {
		return nil, errors.New("fake: read past device end")
	}
	out := make([]byte, end-start)
	copy(out, f.data[start:end])
	return out, nil
}

func newDisk(sectors int, sectorSize uint32) *fakeSectors {
	data := make([]byte, sectors*int(sectorSize))
	for i := range data {
		data[i] = byte(i)
	}
	return &fakeSectors{data: data, sectorSize: sectorSize}
}

func TestEWFSourceReadsUnalignedRanges(t *testing.T) {
	disk := newDisk(4, 512)
	src := NewEWFSource(1, 9, disk)

	if src.Len() != 2048 {
		t.Fatalf("Len() = %d, want 2048", src.Len())
	}
	if src.SectorSize() != 512 {
		t.Fatalf("SectorSize() = %d, want 512", src.SectorSize())
	}
	if src.ImageID() != 9 {
		t.Fatalf("ImageID() = %d, want 9", src.ImageID())
	}

	// A 600-byte read at offset 100 crosses the first sector boundary.
	buf := make([]byte, 600)
	n, err := src.ReadAt(100, buf)
	if err != nil {
		t.Fatalf("ReadAt(100, 600) error = %v", err)
	}
	if n != 600 {
		t.Fatalf("ReadAt(100, 600) n = %d, want 600", n)
	}
	want := disk.data[100:700]
	if !bytes.Equal(buf, want) {
		t.Fatalf("ReadAt(100, 600) did not match the device bytes")
	}

	// A read that ends before EOF returns a full read.
	tail := make([]byte, 100)
	if n, err := src.ReadAt(1000, tail); err != nil || n != 100 {
		t.Fatalf("ReadAt(1000, 100) = %d, %v; want 100, nil", n, err)
	}
	if !bytes.Equal(tail, disk.data[1000:1100]) {
		t.Fatalf("ReadAt(1000, 100) returned wrong bytes")
	}
}

func TestEWFSourceReadEdges(t *testing.T) {
	disk := newDisk(2, 512)
	src := NewEWFSource(1, 9, disk)

	if n, err := src.ReadAt(1024, nil); err != nil || n != 0 {
		t.Fatalf("ReadAt(EOF, nil) = %d, %v; want 0, nil", n, err)
	}
	if _, err := src.ReadAt(1024, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt(EOF) error = %v, want ErrOutOfRange", err)
	}

	buf := make([]byte, 8)
	n, err := src.ReadAt(1020, buf)
	if err != nil {
		t.Fatalf("ReadAt(1020, 8) error = %v", err)
	}
	if n != 4 {
		t.Fatalf("ReadAt(1020, 8) n = %d, want 4", n)
	}
	if !bytes.Equal(buf[:n], disk.data[1020:1024]) {
		t.Fatalf("ReadAt(1020, 8) returned wrong tail bytes")
	}
	if buf[n] != 0 {
		t.Fatalf("ReadAt(1020, 8) wrote past the short read")
	}
}

func TestEWFSourceAlignsTo4096Sectors(t *testing.T) {
	disk := newDisk(2, 4096)
	src := NewEWFSource(1, 9, disk)

	buf := make([]byte, 5000)
	n, err := src.ReadAt(100, buf)
	if err != nil {
		t.Fatalf("ReadAt error = %v", err)
	}
	if n != 5000 {
		t.Fatalf("ReadAt n = %d, want 5000", n)
	}
	if !bytes.Equal(buf, disk.data[100:5100]) {
		t.Fatalf("ReadAt returned wrong 4096-sector-aligned bytes")
	}
}

func TestEWFSourcePropagatesReadErrors(t *testing.T) {
	boom := errors.New("decompress failed")
	disk := newDisk(2, 512)
	disk.err = boom
	src := NewEWFSource(1, 9, disk)

	_, err := src.ReadAt(0, make([]byte, 512))
	if !errors.Is(err, boom) {
		t.Fatalf("ReadAt error = %v, want the device error", err)
	}
	if !errors.Is(err, source.ErrIO) {
		t.Fatalf("ReadAt error = %v, want ErrIO", err)
	}
	if got := src.Stats().Errors; got != 1 {
		t.Fatalf("Stats().Errors = %d, want 1", got)
	}
}

func TestEWFSourceLossyZeroFills(t *testing.T) {
	disk := newDisk(2, 512)
	disk.err = errors.New("decompress failed")
	src := NewEWFSource(1, 9, disk)

	buf := bytes.Repeat([]byte{0xaa}, 512)
	n, err := src.ReadAtLossy(0, buf)
	if err != nil {
		t.Fatalf("ReadAtLossy error = %v", err)
	}
	if n != 512 {
		t.Fatalf("ReadAtLossy n = %d, want 512", n)
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("ReadAtLossy buf[%d] = %#x, want 0", i, b)
		}
	}
	if got := src.Stats().CorruptBytes; got != 512 {
		t.Fatalf("Stats().CorruptBytes = %d, want 512", got)
	}
}

func TestEWFSourceMapToImage(t *testing.T) {
	src := NewEWFSource(1, 9, newDisk(2, 512))

	got, err := src.MapToImage(100, 200)
	if err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}
	want := []source.ImageRange{{ImageID: 9, ImageOffset: 100, Len: 200, Kind: source.RangeData}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MapToImage = %+v, want %+v", got, want)
	}
}

func TestEWFSourceEmptyDevice(t *testing.T) {
	src := NewEWFSource(1, 9, &fakeSectors{sectorSize: 512})

	if !src.IsEmpty() {
		t.Fatal("IsEmpty() = false, want true")
	}
	if _, err := src.ReadAt(0, nil); err != nil {
		t.Fatalf("ReadAt(0, nil) error = %v", err)
	}
	if _, err := src.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt(0, 1) error = %v, want ErrOutOfRange", err)
	}
}
