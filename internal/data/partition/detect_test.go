package partition

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestDetectGPTPrimary(t *testing.T) {
	table, err := Detect(source.NewMemorySource(1, buildGPT()))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if table.Kind != KindGPT || table.GPT == nil {
		t.Fatalf("Detect kind = %v, want GPT", table.Kind)
	}
	if table.GPT.Header.Copy != CopyPrimary {
		t.Fatalf("copy = %v, want primary", table.GPT.Header.Copy)
	}
	if got := len(table.Partitions()); got != 2 {
		t.Fatalf("partitions = %d, want 2", got)
	}
}

func TestDetectFallsBackToGPTBackup(t *testing.T) {
	data := buildGPT()
	data[int(testSector)+56] ^= 0xFF // corrupt the primary header's disk GUID

	table, err := Detect(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if table.Kind != KindGPT || table.GPT.Header.Copy != CopyBackup {
		t.Fatalf("Detect did not fall back to the backup GPT: %+v", table.GPT.Header)
	}
	if got := len(table.Partitions()); got != 2 {
		t.Fatalf("partitions = %d, want 2", got)
	}
}

func TestDetectMBR(t *testing.T) {
	table, err := Detect(source.NewMemorySource(1, imageWithMBR()))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if table.Kind != KindMBR || table.MBR == nil {
		t.Fatalf("Detect kind = %v, want MBR", table.Kind)
	}
	if got := len(table.Partitions()); got != 1 {
		t.Fatalf("partitions = %d, want 1", got)
	}
}

func TestDetectProtectiveOnlyMBR(t *testing.T) {
	data := make([]byte, 4*1024*1024)
	data[510], data[511] = 0x55, 0xAA
	writeMBREntry(data, 0, 0x00, 0xEE, 1, uint32(len(data)/512-1))

	table, err := Detect(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if table.Kind != KindMBR {
		t.Fatalf("Detect kind = %v, want the protective MBR", table.Kind)
	}
	if got := len(table.Partitions()); got != 1 || table.Partitions()[0].TypeID != 0xEE {
		t.Fatalf("protective partitions = %+v", table.Partitions())
	}
}

func TestDetectBootSectorIsNotAPartitionTable(t *testing.T) {
	data := make([]byte, 4096)
	data[510], data[511] = 0x55, 0xAA // a volume boot sector, no entries

	table, err := Detect(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if table.Kind != KindNone {
		t.Fatalf("Detect kind = %v, want none", table.Kind)
	}
}

func TestDetectEmptyDisk(t *testing.T) {
	table, err := Detect(source.NewMemorySource(1, nil))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if table.Kind != KindNone {
		t.Fatalf("Detect kind = %v, want none", table.Kind)
	}
}

func TestDetectDamagedGPTWithoutBackup(t *testing.T) {
	data := buildGPT()
	data[int(testSector)+56] ^= 0xFF // primary header CRC fails
	clear(data[int((testTotalSectors-1)*testSector) : int((testTotalSectors-1)*testSector)+8])

	_, err := Detect(source.NewMemorySource(1, data))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Detect error = %v, want ErrInvalid", err)
	}
}
