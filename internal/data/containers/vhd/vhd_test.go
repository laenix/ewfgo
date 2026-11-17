package vhd

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func putBE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func putBE64(b []byte, at int, v uint64) {
	putBE32(b, at, uint32(v>>32))
	putBE32(b, at+4, uint32(v))
}

func sealFooter(b []byte) {
	putBE32(b, 64, footerChecksum(b, 64))
}

func buildFooter(kind uint32, virtualSize, dataOffset uint64, unique [16]byte, timestamp uint32) []byte {
	b := make([]byte, FooterBytes)
	copy(b[0:8], FooterCookie)
	putBE32(b, 8, 2)
	putBE32(b, 12, Version10)
	putBE64(b, 16, dataOffset)
	putBE32(b, 24, timestamp)
	copy(b[28:32], "qemu")
	putBE64(b, 40, virtualSize)
	putBE64(b, 48, virtualSize)
	putBE32(b, 60, kind)
	copy(b[68:84], unique[:])
	sealFooter(b)
	return b
}

func buildDynamicHeader(tableOffset uint64, entries, blockSize uint32, parentUnique [16]byte, parentTimestamp uint32) []byte {
	b := make([]byte, DynamicHeaderBytes)
	copy(b[0:8], DynamicCookie)
	putBE64(b, 16, tableOffset)
	putBE32(b, 24, Version10)
	putBE32(b, 28, entries)
	putBE32(b, 32, blockSize)
	copy(b[40:56], parentUnique[:])
	putBE32(b, 56, parentTimestamp)
	return b
}

func testIdentity(seed byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = seed + byte(i)
	}
	return id
}

func TestFixedVHD(t *testing.T) {
	guest := make([]byte, 4096)
	for i := range guest {
		guest[i] = byte(i)
	}
	file := append(append([]byte(nil), guest...), buildFooter(2, 4096, 0, testIdentity(0xA0), 0)...)

	src, err := Open(2, source.NewMemorySourceWithImage(1, 7, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if src.Len() != 4096 || src.Info().Kind != KindFixed || src.SectorSize() != 512 {
		t.Fatalf("source = len %d kind %v sector %d", src.Len(), src.Info().Kind, src.SectorSize())
	}
	if !src.Info().ChecksumOK {
		t.Fatal("footer checksum not verified")
	}

	buf := make([]byte, 4096)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, guest) {
		t.Fatal("fixed VHD did not return the guest bytes")
	}
	extents, err := src.Extents(0, 4096)
	if err != nil {
		t.Fatal(err)
	}
	want := []source.ParentRange{{Parent: 1, ParentOffset: 0, Len: 4096, Kind: source.RangeData}}
	if len(extents) != 1 || extents[0] != want[0] {
		t.Fatalf("Extents = %+v, want %+v", extents, want)
	}
}

func TestDynamicVHD(t *testing.T) {
	const block = 4096
	file := make([]byte, 2560+block+512)
	copy(file[512:], buildDynamicHeader(1536, 2, block, [16]byte{}, 0))
	putBE32(file, 1536, 4) // block 0 bitmap at sector 4 (2048)
	putBE32(file, 1540, Unallocated)
	for i := 0; i < block; i++ {
		file[2560+i] = 'D'
	}
	copy(file[2560+block:], buildFooter(3, 8192, 512, testIdentity(0xB0), 0))

	src, err := Open(2, source.NewMemorySourceWithImage(1, 7, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if src.Info().Kind != KindDynamic || src.BlockSize() != block {
		t.Fatalf("info = %+v", src.Info())
	}
	if src.Info().TableOffset != 1536 || src.Info().TableEntries != 2 {
		t.Fatalf("table = %d/%d", src.Info().TableOffset, src.Info().TableEntries)
	}

	buf := make([]byte, 8192)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:block], bytes.Repeat([]byte{'D'}, block)) {
		t.Fatal("allocated block did not read back")
	}
	if !bytes.Equal(buf[block:], make([]byte, block)) {
		t.Fatal("unallocated dynamic block is not zero")
	}

	extents, err := src.Extents(0, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].Kind != source.RangeData || extents[1].Kind != source.RangeZero {
		t.Fatalf("extents = %+v", extents)
	}
}

func buildParentVHD(t *testing.T, identity [16]byte, timestamp uint32) []byte {
	t.Helper()
	const block = 4096
	file := make([]byte, 11264+512)
	copy(file[512:], buildDynamicHeader(1536, 2, block, [16]byte{}, 0))
	putBE32(file, 1536, 4)  // block 0: bitmap 2048
	putBE32(file, 1540, 13) // block 1: bitmap 6656
	for i := 0; i < block; i++ {
		file[2560+i] = 'P'
		file[7168+i] = 'Q'
	}
	copy(file[11264:], buildFooter(3, 8192, 512, identity, timestamp))
	return file
}

func TestDifferencingVHD(t *testing.T) {
	parentIdentity := testIdentity(0xC0)
	parentFile := buildParentVHD(t, parentIdentity, 1234)
	parent, err := Open(1, source.NewMemorySourceWithImage(9, 7, parentFile))
	if err != nil {
		t.Fatalf("parent Open error = %v", err)
	}

	const block = 4096
	child := make([]byte, 2560+block+512)
	copy(child[512:], buildDynamicHeader(1536, 2, block, parentIdentity, 0))
	putBE32(child, 1536, 4) // block 0 bitmap at 2048
	putBE32(child, 1540, Unallocated)
	child[2048] = 0x80 // sector 0 present; sectors 1..7 come from the parent
	for i := 0; i < block; i++ {
		child[2560+i] = 'C'
	}
	copy(child[2560+block:], buildFooter(4, 8192, 512, testIdentity(0xD0), 0))

	src, err := OpenWithParent(2, source.NewMemorySourceWithImage(9, 7, child), parent)
	if err != nil {
		t.Fatalf("OpenWithParent error = %v", err)
	}
	if src.Info().Kind != KindDifferencing {
		t.Fatalf("kind = %v", src.Info().Kind)
	}

	buf := make([]byte, 8192)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], bytes.Repeat([]byte{'C'}, 512)) {
		t.Fatal("child sector 0 was not read from the child")
	}
	if !bytes.Equal(buf[512:block], bytes.Repeat([]byte{'P'}, block-512)) {
		t.Fatal("child sectors 1..7 were not read from the parent")
	}
	if !bytes.Equal(buf[block:], bytes.Repeat([]byte{'Q'}, block)) {
		t.Fatal("unallocated child block was not read from the parent")
	}

	extents, err := src.Extents(0, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) < 3 {
		t.Fatalf("extents = %+v", extents)
	}
	if extents[0].Parent != 9 || extents[0].Len != 512 {
		t.Fatalf("child extent = %+v", extents[0])
	}
	if extents[1].Parent != 1 || extents[1].ParentOffset != 512 {
		t.Fatalf("parent extent = %+v", extents[1])
	}
}

func TestDifferencingRequiresParent(t *testing.T) {
	child := make([]byte, 2560+4096+512)
	copy(child[512:], buildDynamicHeader(1536, 2, 4096, [16]byte{}, 0))
	copy(child[2560+4096:], buildFooter(4, 8192, 512, testIdentity(0xD0), 0))
	_, err := Open(2, source.NewMemorySource(1, child))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open error = %v, want ErrUnsupported", err)
	}
}

func TestDifferencingRejectsWrongParent(t *testing.T) {
	parentFile := buildParentVHD(t, testIdentity(0xC0), 1234)
	parent, err := Open(1, source.NewMemorySourceWithImage(9, 7, parentFile))
	if err != nil {
		t.Fatal(err)
	}
	child := make([]byte, 2560+4096+512)
	copy(child[512:], buildDynamicHeader(1536, 2, 4096, testIdentity(0xEE), 0))
	copy(child[2560+4096:], buildFooter(4, 8192, 512, testIdentity(0xD0), 0))

	_, err = OpenWithParent(2, source.NewMemorySourceWithImage(9, 7, child), parent)
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenWithParent error = %v, want ErrUnsupported", err)
	}
}
