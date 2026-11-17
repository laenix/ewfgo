package forensic_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	forensic "github.com/laenix/ewfgo"
)

const (
	cfbEndOfChain  = 0xFFFFFFFE
	cfbFreeSector  = 0xFFFFFFFF
	cfbFATSector   = 0xFFFFFFFD
	cfbNoEntry     = 0xFFFFFFFF
	cfbKindRoot    = 5
	cfbKindStream  = 2
	cfbSectorBytes = 512
)

// cfbFixture builds a minimal v3 compound file: a root storage with one
// 4096-byte stream (large enough to live in the regular FAT, not the mini
// stream).
func cfbFixture(t *testing.T) []byte {
	t.Helper()
	stream := make([]byte, 4096)
	copy(stream, "compound stream contents\n")

	put16 := func(b []byte, at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
	put32 := func(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }

	header := make([]byte, cfbSectorBytes)
	copy(header, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	put16(header, 24, 0x003E)
	put16(header, 26, 3)
	put16(header, 28, 0xFFFE)
	put16(header, 30, 9)
	put16(header, 32, 6)
	put32(header, 40, 0) // no extra directory sectors
	put32(header, 44, 1) // one FAT sector
	put32(header, 48, 1) // directory starts at sector 1
	put32(header, 56, 4096)
	put32(header, 60, 2) // miniFAT sector
	put32(header, 64, 1) // one miniFAT sector
	put32(header, 68, cfbEndOfChain)
	put32(header, 72, 0)
	put32(header, 76, 0) // DIFAT[0] = FAT sector 0
	for i := 1; i < 109; i++ {
		put32(header, 76+i*4, cfbFreeSector)
	}

	fat := make([]uint32, cfbSectorBytes/4)
	for i := range fat {
		fat[i] = cfbFreeSector
	}
	fat[0] = cfbFATSector
	fat[1] = cfbEndOfChain
	fat[2] = cfbEndOfChain
	for sector := uint32(3); sector < 11; sector++ {
		if sector == 10 {
			fat[sector] = cfbEndOfChain
		} else {
			fat[sector] = sector + 1
		}
	}
	fatBytes := make([]byte, cfbSectorBytes)
	for i, value := range fat {
		put32(fatBytes, i*4, value)
	}

	directory := make([]byte, cfbSectorBytes)
	entry := func(index int, name string, kind byte, left, right, child, start uint32, size uint64) {
		raw := directory[index*128 : (index+1)*128]
		units := append(utf16.Encode([]rune(name)), 0)
		for i, unit := range units {
			put16(raw, i*2, unit)
		}
		put16(raw, 64, uint16(len(units)*2))
		raw[66] = kind
		put32(raw, 68, left)
		put32(raw, 72, right)
		put32(raw, 76, child)
		put32(raw, 116, start)
		put32(raw, 120, uint32(size))
	}
	entry(0, "Root Entry", cfbKindRoot, cfbNoEntry, cfbNoEntry, 1, cfbEndOfChain, 0)
	entry(1, "Stream", cfbKindStream, cfbNoEntry, cfbNoEntry, cfbNoEntry, 3, uint64(len(stream)))

	out := append([]byte(nil), header...)
	out = append(out, fatBytes...)
	out = append(out, directory...)
	out = append(out, make([]byte, cfbSectorBytes)...) // miniFAT (unused)
	out = append(out, stream...)
	return out
}

func TestOpenOLE(t *testing.T) {
	path := filepath.Join(t.TempDir(), "document.doc")
	if err := os.WriteFile(path, cfbFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	doc, err := forensic.OpenOLE(ctx, path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenOLE: %v", err)
	}
	defer doc.Close()

	if doc.Version() != "3" || doc.SectorSize() != 512 {
		t.Fatalf("version=%s sector=%d", doc.Version(), doc.SectorSize())
	}
	entries, err := doc.Entries(ctx)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Path != "/" || !entries[0].IsStorage {
		t.Fatalf("root = %+v", entries[0])
	}
	if entries[1].Path != "/Stream" || entries[1].IsStorage || entries[1].Size != 4096 {
		t.Fatalf("stream = %+v", entries[1])
	}

	children, err := doc.ListStorage(ctx, "/")
	if err != nil || len(children) != 1 || children[0].Name != "Stream" {
		t.Fatalf("ListStorage = %+v, %v", children, err)
	}

	file, err := doc.Open(ctx, "/Stream")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, err := file.ReadAll()
	file.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(data) != 4096 || !bytes.HasPrefix(data, []byte("compound stream contents\n")) {
		t.Fatalf("stream contents = %d bytes %q", len(data), data[:32])
	}
}
