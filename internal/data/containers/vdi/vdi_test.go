package vdi

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func putLE16(b []byte, at int, v uint16) { b[at], b[at+1] = byte(v), byte(v>>8) }
func putLE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
func putLE64(b []byte, at int, v uint64) {
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

type vdiSpec struct {
	kind       uint32
	mapOffset  uint32
	dataOffset uint32
	blockSize  uint32
	blocks     uint32
	virtual    uint64
	sectorSize uint32
	mapEntry1  uint32
}

func buildVDI(t *testing.T, spec vdiSpec, block0, block1 []byte) []byte {
	t.Helper()
	fileLen := int(spec.dataOffset) + int(spec.blockSize)*2
	if fileLen < 0x200 {
		fileLen = 0x200
	}
	file := make([]byte, fileLen)
	putLE32(file, SignatureOffset, Signature)
	putLE16(file, 0x44, 1)
	putLE16(file, 0x46, 0)
	putLE32(file, 0x48, 0x190)
	putLE32(file, 0x4C, spec.kind)
	copy(file[0x54:], "test comment")
	putLE32(file, 0x154, spec.mapOffset)
	putLE32(file, 0x158, spec.dataOffset)
	putLE32(file, 0x168, spec.sectorSize)
	putLE64(file, 0x170, spec.virtual)
	putLE32(file, 0x178, spec.blockSize)
	putLE32(file, 0x180, spec.blocks)
	putLE32(file, 0x184, 1)
	if spec.mapOffset != 0 {
		putLE32(file, int(spec.mapOffset), 0)
		putLE32(file, int(spec.mapOffset)+4, spec.mapEntry1)
	}
	copy(file[int(spec.dataOffset):], block0)
	copy(file[int(spec.dataOffset)+int(spec.blockSize):], block1)
	return file
}

func defaultSpec() vdiSpec {
	return vdiSpec{
		kind: ImageTypeDynamic, mapOffset: 0x200, dataOffset: 0x400,
		blockSize: 4096, blocks: 2, virtual: 8192, sectorSize: 512,
		mapEntry1: Unallocated,
	}
}

func TestDynamicVDI(t *testing.T) {
	file := buildVDI(t, defaultSpec(),
		bytes.Repeat([]byte{'D'}, 4096), bytes.Repeat([]byte{'X'}, 4096))
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if src.Len() != 8192 || src.BlockSize() != 4096 || src.Info().Kind != KindDynamic {
		t.Fatalf("info = %+v", src.Info())
	}
	if src.Info().Comment != "test comment" || src.Info().BlockMapOffset != 0x200 {
		t.Fatalf("info = %+v", src.Info())
	}
	buf := make([]byte, 8192)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:4096], bytes.Repeat([]byte{'D'}, 4096)) {
		t.Fatal("allocated block did not read back")
	}
	if !bytes.Equal(buf[4096:], make([]byte, 4096)) {
		t.Fatal("unallocated block is not zero")
	}
	extents, err := src.Extents(0, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].Kind != source.RangeData ||
		extents[0].ParentOffset != 0x400 || extents[1].Kind != source.RangeZero {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestStaticVDIWithoutMap(t *testing.T) {
	spec := defaultSpec()
	spec.kind = ImageTypeStatic
	spec.mapOffset = 0
	spec.dataOffset = 0x200
	file := buildVDI(t, spec,
		bytes.Repeat([]byte{'A'}, 4096), bytes.Repeat([]byte{'B'}, 4096))
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	buf := make([]byte, 8192)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:4096], bytes.Repeat([]byte{'A'}, 4096)) ||
		!bytes.Equal(buf[4096:], bytes.Repeat([]byte{'B'}, 4096)) {
		t.Fatal("static blocks did not read back")
	}
}

func TestVDIRefusals(t *testing.T) {
	badSig := buildVDI(t, defaultSpec(), make([]byte, 4096), make([]byte, 4096))
	putLE32(badSig, SignatureOffset, 0)
	if _, err := Open(2, source.NewMemorySource(1, badSig)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(bad signature) error = %v, want ErrCorrupt", err)
	}

	spec := defaultSpec()
	spec.kind = 3
	if _, err := Open(2, source.NewMemorySource(1, buildVDI(t, spec, make([]byte, 4096), make([]byte, 4096)))); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(type 3) error = %v, want ErrUnsupported", err)
	}

	spec = defaultSpec()
	spec.sectorSize = 4096
	if _, err := Open(2, source.NewMemorySource(1, buildVDI(t, spec, make([]byte, 4096), make([]byte, 4096)))); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(4096 sector) error = %v, want ErrUnsupported", err)
	}

	spec = defaultSpec()
	spec.mapOffset = 0
	if _, err := Open(2, source.NewMemorySource(1, buildVDI(t, spec, make([]byte, 4096), make([]byte, 4096)))); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(dynamic without map) error = %v, want ErrCorrupt", err)
	}

	spec = defaultSpec()
	spec.mapEntry1 = 100
	src, err := Open(2, source.NewMemorySource(1, buildVDI(t, spec, make([]byte, 4096), make([]byte, 4096))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.ReadAt(4096, make([]byte, 512)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ReadAt(map beyond file) error = %v, want ErrCorrupt", err)
	}
}
