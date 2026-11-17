package androidsparse

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

func buildHeader(blockSize, blocks, chunks uint32) []byte {
	h := make([]byte, FileHeaderBytes)
	putLE32(h, 0, Magic)
	putLE16(h, 4, 1)
	putLE16(h, 6, 0)
	putLE16(h, 8, FileHeaderBytes)
	putLE16(h, 10, ChunkHeaderBytes)
	putLE32(h, 12, blockSize)
	putLE32(h, 16, blocks)
	putLE32(h, 20, chunks)
	return h
}

func chunkHeader(kind uint16, blocks, total uint32) []byte {
	h := make([]byte, ChunkHeaderBytes)
	putLE16(h, 0, kind)
	putLE32(h, 4, blocks)
	putLE32(h, 8, total)
	return h
}

func buildSparse() []byte {
	const block = 512
	raw := bytes.Repeat([]byte{'R'}, block)
	fill := []byte{1, 2, 3, 4}
	crc := make([]byte, 4)
	putLE32(crc, 0, 0xAABBCCDD)

	var out []byte
	out = append(out, buildHeader(block, 3, 4)...)
	out = append(out, chunkHeader(ChunkRaw, 1, 12+block)...)
	out = append(out, raw...)
	out = append(out, chunkHeader(ChunkFill, 1, 12+4)...)
	out = append(out, fill...)
	out = append(out, chunkHeader(ChunkDontCare, 1, 12)...)
	out = append(out, chunkHeader(ChunkCRC32, 0, 12+4)...)
	out = append(out, crc...)
	return out
}

func TestSparseExpansion(t *testing.T) {
	file := buildSparse()
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if src.Len() != 3*512 {
		t.Fatalf("Len = %d", src.Len())
	}
	info := src.Info()
	if info.RawChunks != 1 || info.FillChunks != 1 || info.DontCareChunks != 1 || info.CRCChunks != 1 {
		t.Fatalf("info = %+v", info)
	}
	if len(info.CRCPoints) != 1 || info.CRCPoints[0].Offset != 1536 || info.CRCPoints[0].Expected != 0xAABBCCDD {
		t.Fatalf("crc points = %+v", info.CRCPoints)
	}

	buf := make([]byte, 3*512)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], bytes.Repeat([]byte{'R'}, 512)) {
		t.Fatal("raw chunk did not read back")
	}
	for i := 512; i < 1024; i++ {
		if buf[i] != []byte{1, 2, 3, 4}[(i-512)%4] {
			t.Fatalf("fill byte %d = %d", i, buf[i])
		}
	}
	if !bytes.Equal(buf[1024:], make([]byte, 512)) {
		t.Fatal("don't-care chunk is not zero")
	}

	extents, err := src.Extents(0, src.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 3 || extents[0].Kind != source.RangeData ||
		extents[1].Kind != source.RangeDerived || extents[2].Kind != source.RangeHole {
		t.Fatalf("extents = %+v", extents)
	}
	if extents[0].Parent != 1 || extents[0].ParentOffset != 40 {
		t.Fatalf("raw extent = %+v", extents[0])
	}
	if extents[1].Parent != 2 || extents[1].ParentOffset != 512 {
		t.Fatalf("fill extent = %+v", extents[1])
	}
}

func TestSparseReadCrossesSegments(t *testing.T) {
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, buildSparse()))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 600)
	if _, err := src.ReadAt(400, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:112], bytes.Repeat([]byte{'R'}, 112)) {
		t.Fatal("raw tail did not read back")
	}
	for i := 112; i < 600; i++ {
		if buf[i] != []byte{1, 2, 3, 4}[(i-112)%4] {
			t.Fatalf("fill byte %d = %d", i, buf[i])
		}
	}
}

func TestSparseRefusals(t *testing.T) {
	badMagic := buildSparse()
	putLE32(badMagic, 0, 0)
	if _, err := Open(2, source.NewMemorySource(1, badMagic)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(bad magic) error = %v", err)
	}

	badVersion := buildSparse()
	putLE16(badVersion, 4, 2)
	if _, err := Open(2, source.NewMemorySource(1, badVersion)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(version 2) error = %v", err)
	}

	badBlock := buildSparse()
	putLE32(badBlock, 12, 0)
	if _, err := Open(2, source.NewMemorySource(1, badBlock)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(zero block) error = %v", err)
	}

	badChunk := buildSparse()
	putLE16(badChunk, FileHeaderBytes, 0xBEEF)
	if _, err := Open(2, source.NewMemorySource(1, badChunk)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(unknown chunk) error = %v", err)
	}

	short := buildSparse()[:20]
	if _, err := Open(2, source.NewMemorySource(1, short)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(short) error = %v", err)
	}
}
