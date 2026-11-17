package forensic_test

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func limeFixture() []byte {
	var out []byte
	add := func(start, end uint64, data string) {
		header := make([]byte, 32)
		binary.LittleEndian.PutUint32(header[0:], 0x4C694D45)
		binary.LittleEndian.PutUint32(header[4:], 1)
		binary.LittleEndian.PutUint64(header[8:], start)
		binary.LittleEndian.PutUint64(header[16:], end)
		out = append(out, header...)
		out = append(out, data...)
	}
	add(0x1000, 0x1010, "0123456789abcdef")
	add(0x2000, 0x2008, "ABCDEFGH")
	return out
}

func TestOpenMemoryLiME(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.lime")
	if err := os.WriteFile(path, limeFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dump, err := forensic.OpenMemory(ctx, path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	defer dump.Close()

	if dump.Kind() != "LiME" {
		t.Fatalf("kind = %q", dump.Kind())
	}
	info := dump.Info()
	if info.Ranges != 2 || info.PhysicalStart != 0x1000 || info.PhysicalEnd != 0x2008 || info.StoredBytes != 24 {
		t.Fatalf("info = %+v", info)
	}
	runs := dump.Runs()
	if len(runs) != 2 || runs[0].Address != 0x1000 || runs[0].Length != 16 || runs[0].FileOffset != 32 || runs[1].Address != 0x2000 {
		t.Fatalf("runs = %+v", runs)
	}

	buf := make([]byte, 16)
	if n, err := dump.ReadAt(ctx, 0x1000, buf); err != nil || n != 16 {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if string(buf) != "0123456789abcdef" {
		t.Fatalf("memory = %q", buf)
	}
	part := make([]byte, 4)
	if _, err := dump.ReadAt(ctx, 0x1004, part); err != nil || string(part) != "4567" {
		t.Fatalf("ReadAt middle = %q, %v", part, err)
	}

	// A range crossing the physical gap must fail, never zero-fill.
	if _, err := dump.ReadAt(ctx, 0x1008, make([]byte, 16)); !errors.Is(err, forensic.ErrOutOfRange) {
		t.Fatalf("gap read = %v, want ErrOutOfRange", err)
	}
	if _, err := dump.ReadAt(ctx, 0x3000, make([]byte, 4)); !errors.Is(err, forensic.ErrOutOfRange) {
		t.Fatalf("absent address read = %v, want ErrOutOfRange", err)
	}
}

func TestOpenMemorySource(t *testing.T) {
	ctx := context.Background()
	dump, err := forensic.OpenMemorySource(ctx, source.NewMemorySource(1, limeFixture()), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenMemorySource: %v", err)
	}
	if dump.Kind() != "LiME" || len(dump.Runs()) != 2 {
		t.Fatalf("dump = %q runs=%d", dump.Kind(), len(dump.Runs()))
	}
	buf := make([]byte, 8)
	if _, err := dump.ReadAt(ctx, 0x2000, buf); err != nil || string(buf) != "ABCDEFGH" {
		t.Fatalf("ReadAt = %q, %v", buf, err)
	}
}

func TestOpenMemoryRejectsPlainFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(path, []byte("not a memory dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := forensic.OpenMemory(context.Background(), path, forensic.Options{}); !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("OpenMemory(plain) = %v, want ErrUnsupported", err)
	}
}
