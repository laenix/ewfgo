package ewffixture

import (
	"bytes"
	"encoding/binary"
	"hash/adler32"
	"slices"
	"testing"
)

// sectionNames walks the section-descriptor chain and returns section names.
func sectionNames(t *testing.T, e01 []byte) []string {
	t.Helper()
	var names []string
	addr := int64(13)
	for {
		if int(addr)+sectionLen > len(e01) {
			break
		}
		name := string(bytes.TrimRight(e01[addr:addr+16], "\x00"))
		next := int64(binary.LittleEndian.Uint64(e01[addr+16:]))
		names = append(names, name)
		if name == "done" {
			break
		}
		if next <= addr {
			break
		}
		addr = next
	}
	return names
}

func TestWrapDisk_Magic(t *testing.T) {
	e01 := WrapDisk(DiskPattern(64), Options{})
	if !bytes.Equal(e01[0:8], []byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00}) {
		t.Fatal("bad EWF magic")
	}
}

func TestWrapDisk_SectionChain(t *testing.T) {
	e01 := WrapDisk(DiskPattern(64), Options{})
	got := sectionNames(t, e01)
	want := []string{"header2", "header", "volume", "disk", "sectors", "table", "table2", "data", "done"}
	if !slices.Equal(got, want) {
		t.Fatalf("section chain = %v, want %v", got, want)
	}
}

func TestWrapDisk_CompressedFlag(t *testing.T) {
	e01 := WrapDisk(DiskPattern(64), Options{})
	entry := binary.LittleEndian.Uint32(e01[TableEntryOffsetFor(e01, 0):])
	if entry&0x80000000 == 0 {
		t.Fatalf("chunk 0 entry 0x%08x must have the compressed MSB set", entry)
	}
}

func TestWrapDisk_UncompressedFooter(t *testing.T) {
	// In CompressNone mode each stored chunk is plain data + 4-byte Adler-32.
	e01 := WrapDisk(DiskPattern(64), Options{Compress: CompressNone})
	// Chunk 0 begins right after the sectors descriptor (no slack).
	sectorsAddr := int64(13)
	for {
		name := string(bytes.TrimRight(e01[sectorsAddr:sectorsAddr+16], "\x00"))
		if name == "sectors" {
			break
		}
		sectorsAddr = int64(binary.LittleEndian.Uint64(e01[sectorsAddr+16:]))
	}
	chunk := e01[sectorsAddr+sectionLen : sectorsAddr+sectionLen+int64(int(defaultChunkSectors)*sectorSize)+chunkFooterLen]
	data := chunk[:len(chunk)-chunkFooterLen]
	chk := binary.LittleEndian.Uint32(chunk[len(chunk)-chunkFooterLen:])
	if adler32.Checksum(data) != chk {
		t.Fatal("uncompressed chunk Adler-32 footer mismatch")
	}
}

func TestWrapDisk_MultiSection(t *testing.T) {
	e01 := WrapDisk(DiskPattern(192), Options{Sections: 2})
	names := sectionNames(t, e01)
	want := []string{"header2", "header", "volume", "disk",
		"sectors", "table", "table2",
		"sectors", "table", "table2",
		"data", "done"}
	if !slices.Equal(names, want) {
		t.Fatalf("section chain = %v, want %v", names, want)
	}
}
