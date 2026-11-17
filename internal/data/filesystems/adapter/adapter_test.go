package adapter

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestReaderReadsSectors(t *testing.T) {
	data := make([]byte, 8*512)
	for i := range data {
		data[i] = byte(i)
	}
	reader := New(source.NewMemorySource(1, data), 512)

	buf, err := reader.ReadSectors(2, 3)
	if err != nil {
		t.Fatalf("ReadSectors(2, 3) error = %v", err)
	}
	if !bytes.Equal(buf, data[2*512:5*512]) {
		t.Fatal("ReadSectors returned the wrong bytes")
	}

	buf, err = reader.ReadSectors(7, 1)
	if err != nil {
		t.Fatalf("ReadSectors(7, 1) error = %v", err)
	}
	if !bytes.Equal(buf, data[7*512:8*512]) {
		t.Fatal("ReadSectors(last sector) returned the wrong bytes")
	}
}

func TestReaderRejectsOutOfRange(t *testing.T) {
	reader := New(source.NewMemorySource(1, make([]byte, 4*512)), 512)

	if _, err := reader.ReadSectors(4, 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadSectors(4, 1) error = %v, want ErrOutOfRange", err)
	}
	if _, err := reader.ReadSectors(3, 2); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadSectors(3, 2) error = %v, want ErrOutOfRange", err)
	}
	if _, err := reader.ReadSectors(^uint64(0), 2); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadSectors(overflow) error = %v, want ErrOutOfRange", err)
	}
}

func TestReaderHandles4096Sectors(t *testing.T) {
	data := make([]byte, 2*4096)
	for i := range data {
		data[i] = byte(i % 251)
	}
	reader := New(source.NewMemorySource(1, data), 4096)

	buf, err := reader.ReadSectors(1, 1)
	if err != nil {
		t.Fatalf("ReadSectors error = %v", err)
	}
	if !bytes.Equal(buf, data[4096:8192]) {
		t.Fatal("4096-byte sector read returned the wrong bytes")
	}
}

func TestReaderZeroCount(t *testing.T) {
	reader := New(source.NewMemorySource(1, make([]byte, 512)), 512)
	buf, err := reader.ReadSectors(0, 0)
	if err != nil {
		t.Fatalf("ReadSectors(0, 0) error = %v", err)
	}
	if len(buf) != 0 {
		t.Fatalf("ReadSectors(0, 0) returned %d bytes", len(buf))
	}
}
