package vmdk

import (
	"bytes"
	"compress/zlib"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func putLE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putLE64(b []byte, at int, v uint64) {
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

type sparseSpec struct {
	descriptor  string
	capacity    uint64
	gpt         uint32
	flags       uint32
	gdSector    uint64
	redundant   uint64
	entries     []uint32
	grainData   map[int]byte
	fileSectors int
}

func buildSparse(t *testing.T, spec sparseSpec) []byte {
	t.Helper()
	if spec.fileSectors == 0 {
		spec.fileSectors = 8
	}
	file := make([]byte, spec.fileSectors*512)
	copy(file[:4], Signature)
	putLE32(file, 4, 1)
	putLE32(file, 8, spec.flags)
	putLE64(file, 12, spec.capacity)
	putLE64(file, 20, 1) // grain size: 1 sector
	putLE64(file, 28, 1) // descriptor offset
	putLE64(file, 36, 1) // descriptor size
	putLE32(file, 44, spec.gpt)
	putLE64(file, 48, spec.redundant)
	putLE64(file, 56, spec.gdSector)
	copy(file[512:], spec.descriptor)

	// Grain directory at sector 2 (also the redundant copy in tests).
	putLE32(file, 2*512, 3)
	// Grain table at sector 3.
	for i, entry := range spec.entries {
		putLE32(file, 3*512+i*4, entry)
	}
	for grain, fill := range spec.grainData {
		start := (4 + grain) * 512
		for i := 0; i < 512; i++ {
			file[start+i] = fill
		}
	}
	return file
}

func descriptor(cid, parentCID, hint string) string {
	text := "# Disk DescriptorFile\nversion=1\nCID=" + cid + "\nparentCID=" + parentCID + "\ncreateType=\"monolithicSparse\"\n"
	if hint != "" {
		text += "parentFileNameHint=\"" + hint + "\"\n"
	}
	return text
}

func openExtent(t *testing.T, image []byte) *Source {
	t.Helper()
	src, err := Open(2, source.NewMemorySourceWithImage(9, 7, image))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return src
}

func TestSparseReadsGrains(t *testing.T) {
	image := buildSparse(t, sparseSpec{
		descriptor: descriptor("12345678", "ffffffff", ""),
		capacity:   2,
		gpt:        2,
		gdSector:   2,
		entries:    []uint32{4, 1},
		grainData:  map[int]byte{0: 'A'},
	})
	src := openExtent(t, image)
	if src.Len() != 1024 || src.SectorSize() != 512 {
		t.Fatalf("geometry = %d %d", src.Len(), src.SectorSize())
	}
	if info := src.Info(); info.Version != 1 || info.GrainSize != 1 || info.GrainsPerTable != 2 ||
		info.CID != "12345678" || info.ParentCID != "ffffffff" || info.Differencing {
		t.Fatalf("info = %+v", info)
	}

	buf := make([]byte, 1024)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], bytes.Repeat([]byte{'A'}, 512)) {
		t.Fatal("allocated grain did not read back")
	}
	if !bytes.Equal(buf[512:], make([]byte, 512)) {
		t.Fatal("explicitly zeroed grain is not zero")
	}

	extents, err := src.Extents(0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].Kind != source.RangeData ||
		extents[0].ParentOffset != 4*512 || extents[1].Kind != source.RangeZero {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestSparseUnallocatedIsZero(t *testing.T) {
	image := buildSparse(t, sparseSpec{
		descriptor: descriptor("12345678", "ffffffff", ""),
		capacity:   2,
		gpt:        2,
		gdSector:   2,
		entries:    []uint32{4, 0},
		grainData:  map[int]byte{0: 'A'},
	})
	src := openExtent(t, image)
	buf := make([]byte, 1024)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[512:], make([]byte, 512)) {
		t.Fatal("unallocated grain is not zero")
	}
}

func TestSparseRedundantDirectory(t *testing.T) {
	image := buildSparse(t, sparseSpec{
		descriptor: descriptor("12345678", "ffffffff", ""),
		capacity:   2,
		gpt:        2,
		flags:      flagRedundantDirectory,
		gdSector:   99, // outside the file
		redundant:  2,
		entries:    []uint32{4, 1},
		grainData:  map[int]byte{0: 'A'},
	})
	src := openExtent(t, image)
	if !src.Info().UsedRedundantDirectory {
		t.Fatal("redundant directory was not used")
	}
	buf := make([]byte, 512)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{'A'}, 512)) {
		t.Fatal("redundant-directory extent did not read its grain")
	}
}

func TestSparseDifferencingReadsParent(t *testing.T) {
	parentImage := buildSparse(t, sparseSpec{
		descriptor: descriptor("deadbeef", "ffffffff", ""),
		capacity:   2,
		gpt:        2,
		gdSector:   2,
		entries:    []uint32{4, 5},
		grainData:  map[int]byte{0: 'P', 1: 'Q'},
	})
	parent, err := Open(1, source.NewMemorySourceWithImage(9, 7, parentImage))
	if err != nil {
		t.Fatalf("parent Open error = %v", err)
	}

	childImage := buildSparse(t, sparseSpec{
		descriptor:  descriptor("cafebabe", "deadbeef", "parent.vmdk"),
		capacity:    2,
		gpt:         2,
		gdSector:    2,
		entries:     []uint32{4, 0},
		grainData:   map[int]byte{0: 'C'},
		fileSectors: 5,
	})
	child, err := OpenWithParent(2, source.NewMemorySourceWithImage(9, 7, childImage), parent)
	if err != nil {
		t.Fatalf("OpenWithParent error = %v", err)
	}
	if !child.Info().Differencing || child.Info().ParentFileHint != "parent.vmdk" {
		t.Fatalf("child info = %+v", child.Info())
	}

	buf := make([]byte, 1024)
	if _, err := child.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], bytes.Repeat([]byte{'C'}, 512)) {
		t.Fatal("child grain did not read back")
	}
	if !bytes.Equal(buf[512:], bytes.Repeat([]byte{'Q'}, 512)) {
		t.Fatal("unallocated child grain did not come from the parent")
	}

	extents, err := child.Extents(0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[1].Parent != 1 || extents[1].ParentOffset != 512 {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestSparseDifferencingRequiresMatchingParent(t *testing.T) {
	childImage := buildSparse(t, sparseSpec{
		descriptor:  descriptor("cafebabe", "deadbeef", "parent.vmdk"),
		capacity:    2,
		gpt:         2,
		gdSector:    2,
		entries:     []uint32{4, 0},
		grainData:   map[int]byte{0: 'C'},
		fileSectors: 5,
	})
	if _, err := Open(2, source.NewMemorySource(9, childImage)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(child without parent) error = %v, want ErrUnsupported", err)
	}

	parentImage := buildSparse(t, sparseSpec{
		descriptor: descriptor("12345678", "ffffffff", ""),
		capacity:   2,
		gpt:        2,
		gdSector:   2,
		entries:    []uint32{4, 5},
		grainData:  map[int]byte{0: 'P', 1: 'Q'},
	})
	parent, err := Open(1, source.NewMemorySource(9, parentImage))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithParent(2, source.NewMemorySource(9, childImage), parent); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenWithParent(wrong CID) error = %v, want ErrUnsupported", err)
	}
}

func TestSparseCompressedWithoutFooterIsCorrupt(t *testing.T) {
	image := buildSparse(t, sparseSpec{
		descriptor: descriptor("12345678", "ffffffff", ""),
		capacity:   2,
		gpt:        2,
		flags:      flagCompressed | flagMarkers,
		gdSector:   2,
		entries:    []uint32{0, 0},
	})
	if _, err := Open(2, source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(compressed without footer) error = %v, want ErrCorrupt", err)
	}
}

func TestSparseRejectsBadSignature(t *testing.T) {
	image := make([]byte, 4096)
	if _, err := Open(2, source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(bad signature) error = %v, want ErrUnsupported", err)
	}
}

func buildStreamOptimized(t *testing.T, payload []byte) ([]byte, uint64) {
	t.Helper()
	const fileSectors = 10
	file := make([]byte, fileSectors*512)
	copy(file[:4], Signature)
	putLE32(file, 4, 1)
	putLE32(file, 8, flagCompressed|flagMarkers)
	putLE64(file, 12, 1) // capacity: one grain
	putLE64(file, 20, 1) // grain size: one sector
	putLE32(file, 44, 1) // one grain per table
	putLE64(file, 56, gdAtEnd)
	file[77] = 1 // zlib

	putLE32(file, 2*512, 3) // grain directory -> grain table sector 3
	putLE32(file, 3*512, 4) // grain table -> grain data sector 4

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	putLE64(file, 4*512, grainMarkerCompressed) // marker LBA 0, compressed bit
	putLE32(file, 4*512+8, uint32(compressed.Len()))
	copy(file[4*512+12:], compressed.Bytes())

	footer := 7 * 512
	putLE32(file, footer+12, footerMarkerType)
	header := file[footer+512:]
	copy(header[:4], Signature)
	putLE32(header, 4, 1)
	putLE32(header, 8, flagCompressed|flagMarkers)
	putLE64(header, 12, 1)
	putLE64(header, 20, 1)
	putLE32(header, 44, 1)
	putLE64(header, 56, 2)
	header[77] = 1
	return file, uint64(compressed.Len())
}

func TestStreamOptimizedReadsCompressedGrain(t *testing.T) {
	payload := bytes.Repeat([]byte{'Z'}, 512)
	image, compressedLen := buildStreamOptimized(t, payload)
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, image))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if !src.Info().StreamOptimized || src.Info().FooterOffset == nil || *src.Info().FooterOffset != 7*512 {
		t.Fatalf("info = %+v", src.Info())
	}
	buf := make([]byte, 512)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatal("compressed grain did not read back")
	}

	extents, err := src.Extents(0, 512)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].Kind != source.RangeData ||
		extents[0].ParentOffset != 4*512+12 || extents[0].Len != compressedLen {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestStreamOptimizedRejectsPlainGrain(t *testing.T) {
	payload := bytes.Repeat([]byte{'Z'}, 512)
	image, _ := buildStreamOptimized(t, payload)
	clear(image[4*512 : 4*512+8]) // strip the compressed bit from the marker
	src, err := Open(2, source.NewMemorySource(1, image))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.ReadAt(0, make([]byte, 512)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("ReadAt error = %v, want ErrUnsupported", err)
	}
}
