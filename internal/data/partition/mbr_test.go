package partition

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func writeMBREntry(table []byte, index int, status, typeID byte, startLBA, sectors uint32) {
	at := mbrEntryOffset + index*mbrEntrySize
	table[at] = status
	table[at+4] = typeID
	putLE32(table[at+8:], startLBA)
	putLE32(table[at+12:], sectors)
}

func putLE32(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

func imageWithMBR() []byte {
	data := make([]byte, 4*1024*1024)
	data[510], data[511] = 0x55, 0xAA
	writeMBREntry(data, 0, 0x80, 0x07, 2048, 2048)
	return data
}

func TestParseMBRPrimary(t *testing.T) {
	table, err := ParseMBR(source.NewMemorySource(1, imageWithMBR()))
	if err != nil {
		t.Fatalf("ParseMBR error = %v", err)
	}
	if len(table.Partitions) != 1 {
		t.Fatalf("partitions = %d, want 1", len(table.Partitions))
	}
	p := table.Partitions[0]
	if p.StartLBA != 2048 || p.SectorCount != 2048 {
		t.Fatalf("partition geometry = (%d, %d), want (2048, 2048)", p.StartLBA, p.SectorCount)
	}
	if p.Offset != 2048*512 || p.Len != 2048*512 {
		t.Fatalf("partition bytes = (%d, %d), want (%d, %d)", p.Offset, p.Len, 2048*512, 2048*512)
	}
	if p.TypeID != 0x07 || p.Name != "NTFS/exFAT" {
		t.Fatalf("partition type = %#x %q, want 0x07 %q", p.TypeID, p.Name, "NTFS/exFAT")
	}
	if !p.Bootable || p.IsContainer || p.Index != 0 {
		t.Fatalf("partition flags = bootable=%v container=%v index=%d", p.Bootable, p.IsContainer, p.Index)
	}
}

func TestParseMBRExtendedChain(t *testing.T) {
	data := make([]byte, 4*1024*1024)
	data[510], data[511] = 0x55, 0xAA
	writeMBREntry(data, 0, 0x00, 0x0F, 2048, 4096)

	ebr1 := int(2048 * 512)
	data[ebr1+510], data[ebr1+511] = 0x55, 0xAA
	writeMBREntry(data[ebr1:ebr1+512], 0, 0x00, 0x07, 1, 100)
	writeMBREntry(data[ebr1:ebr1+512], 1, 0x00, 0x0F, 101, 100)

	ebr2 := int(2149 * 512)
	data[ebr2+510], data[ebr2+511] = 0x55, 0xAA
	writeMBREntry(data[ebr2:ebr2+512], 0, 0x00, 0x83, 1, 100)

	table, err := ParseMBR(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("ParseMBR error = %v", err)
	}
	if len(table.Partitions) != 3 {
		t.Fatalf("partitions = %d, want 3", len(table.Partitions))
	}
	if !table.Partitions[0].IsContainer {
		t.Fatal("partition 0 should be the extended container")
	}
	if got := table.Partitions[1]; got.StartLBA != 2049 || got.Offset != 2049*512 || got.TypeID != 0x07 {
		t.Fatalf("logical partition 1 = %+v", got)
	}
	if got := table.Partitions[2]; got.StartLBA != 2150 || got.TypeID != 0x83 {
		t.Fatalf("logical partition 2 = %+v", got)
	}
}

func TestParseMBRRejectsPartitionPastDiskEnd(t *testing.T) {
	data := make([]byte, 4096)
	data[510], data[511] = 0x55, 0xAA
	writeMBREntry(data, 0, 0x00, 0x07, 1, 100)

	_, err := ParseMBR(source.NewMemorySource(1, data))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseMBR error = %v, want ErrInvalid", err)
	}
}

func TestParseMBRRejectsMissingSignature(t *testing.T) {
	data := make([]byte, 4096)
	if _, err := ParseMBR(source.NewMemorySource(1, data)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseMBR error = %v, want ErrInvalid", err)
	}
}

func TestMBRTypeName(t *testing.T) {
	if got := TypeName(0x07); got != "NTFS/exFAT" {
		t.Fatalf("TypeName(0x07) = %q", got)
	}
	if got := TypeName(0xFE); got != "LANstep" {
		t.Fatalf("TypeName(0xFE) = %q", got)
	}
	if got := TypeName(0x00); got != "" {
		t.Fatalf("TypeName(0x00) = %q, want empty", got)
	}
}
