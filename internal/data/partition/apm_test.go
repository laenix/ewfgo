package partition

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const testAPMBlocks = 32

func putBE32(dst []byte, v uint32) {
	dst[0] = byte(v >> 24)
	dst[1] = byte(v >> 16)
	dst[2] = byte(v >> 8)
	dst[3] = byte(v)
}

func putBE16(dst []byte, v uint16) {
	dst[0] = byte(v >> 8)
	dst[1] = byte(v)
}

func apmEntry(mapBlocks, start, count uint32, name, kind string, status uint32) []byte {
	b := make([]byte, 512)
	copy(b[0:2], "PM")
	putBE32(b[4:8], mapBlocks)
	putBE32(b[8:12], start)
	putBE32(b[12:16], count)
	copy(b[16:48], name)
	copy(b[48:80], kind)
	putBE32(b[88:92], status)
	return b
}

func apmImage(entries ...[]byte) []byte {
	image := make([]byte, testAPMBlocks*512)
	copy(image[0:2], "ER")
	putBE16(image[2:4], 512)
	putBE32(image[4:8], testAPMBlocks)
	for i, entry := range entries {
		at := (1 + i) * 512
		copy(image[at:at+512], entry)
	}
	return image
}

func TestParseAPMReportsVolumesAndSkipsTheMap(t *testing.T) {
	image := apmImage(
		apmEntry(2, 1, 2, "Apple", "Apple_partition_map", 0x33),
		apmEntry(2, 3, 20, "Macintosh HD", "Apple_HFS", 0x37),
	)
	table, err := ParseAPM(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("ParseAPM error = %v", err)
	}
	if table == nil {
		t.Fatal("ParseAPM = nil, want a map")
	}
	if table.MapBlocks != 2 || table.Skipped != 1 || len(table.Partitions) != 1 {
		t.Fatalf("table = mapBlocks=%d skipped=%d partitions=%d", table.MapBlocks, table.Skipped, len(table.Partitions))
	}
	p := table.Partitions[0]
	if p.Kind != KindAPM || p.StartLBA != 3 || p.SectorCount != 20 || p.Offset != 3*512 || p.Len != 20*512 {
		t.Fatalf("partition = %+v", p)
	}
	if p.Name != "Macintosh HD" || p.TypeGUID != "Apple_HFS" || p.Bootable {
		t.Fatalf("partition fields = name=%q type=%q bootable=%v", p.Name, p.TypeGUID, p.Bootable)
	}
	if table.Driver == nil || table.Driver.BlockSize != 512 || table.Driver.BlockCount != testAPMBlocks {
		t.Fatalf("driver = %+v", table.Driver)
	}
}

func TestParseAPMSkipsFreeSpace(t *testing.T) {
	image := apmImage(
		apmEntry(3, 1, 3, "", "Apple_partition_map", 0x33),
		apmEntry(3, 4, 8, "Untitled", "Apple_Free", 0),
		apmEntry(3, 12, 8, "Data", "Apple_HFS", 0x33),
	)
	table, err := ParseAPM(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatal(err)
	}
	if table.Skipped != 2 || len(table.Partitions) != 1 || table.Partitions[0].Name != "Data" {
		t.Fatalf("table = skipped=%d partitions=%+v", table.Skipped, table.Partitions)
	}
}

func TestParseAPMRejectsPartitionPastImage(t *testing.T) {
	image := apmImage(
		apmEntry(2, 1, 2, "", "Apple_partition_map", 0x33),
		apmEntry(2, 3, 100, "Too big", "Apple_HFS", 0x33),
	)
	_, err := ParseAPM(source.NewMemorySource(1, image))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseAPM error = %v, want ErrInvalid", err)
	}
}

func TestParseAPMRejectsShortMap(t *testing.T) {
	image := apmImage(
		apmEntry(3, 1, 3, "", "Apple_partition_map", 0x33),
		apmEntry(3, 4, 4, "Data", "Apple_HFS", 0x33),
	)
	_, err := ParseAPM(source.NewMemorySource(1, image))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseAPM error = %v, want ErrInvalid", err)
	}
}

func TestParseAPMRejectsMapSizeDisagreement(t *testing.T) {
	image := apmImage(
		apmEntry(2, 1, 2, "", "Apple_partition_map", 0x33),
		apmEntry(3, 3, 4, "Data", "Apple_HFS", 0x33),
	)
	_, err := ParseAPM(source.NewMemorySource(1, image))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseAPM error = %v, want ErrInvalid", err)
	}
}

func TestParseAPMDoesNotClaimNonAPM(t *testing.T) {
	table, err := ParseAPM(source.NewMemorySource(1, make([]byte, testAPMBlocks*512)))
	if err != nil || table != nil {
		t.Fatalf("ParseAPM(zeroed) = %+v, %v; want nil, nil", table, err)
	}

	image := make([]byte, testAPMBlocks*512)
	copy(image[512:514], "PM")
	putBE32(image[516:520], 0)
	table, err = ParseAPM(source.NewMemorySource(1, image))
	if err != nil || table != nil {
		t.Fatalf("ParseAPM(impossible map count) = %+v, %v; want nil, nil", table, err)
	}
}

func TestParseAPMWithoutDriverDescriptor(t *testing.T) {
	image := apmImage(
		apmEntry(2, 1, 2, "", "Apple_partition_map", 0x33),
		apmEntry(2, 3, 4, "Data", "Apple_HFS", 0x33),
	)
	image[0], image[1] = 0, 0
	table, err := ParseAPM(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatal(err)
	}
	if table == nil || table.Driver != nil || len(table.Partitions) != 1 {
		t.Fatalf("table = %+v", table)
	}
}

func TestDetectAPM(t *testing.T) {
	image := apmImage(
		apmEntry(2, 1, 2, "", "Apple_partition_map", 0x33),
		apmEntry(2, 3, 4, "Data", "Apple_HFS", 0x33),
	)
	table, err := Detect(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if table.Kind != KindAPM || table.APM == nil || len(table.Partitions()) != 1 {
		t.Fatalf("Detect = %+v", table)
	}
}
