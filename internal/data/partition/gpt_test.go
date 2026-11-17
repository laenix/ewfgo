package partition

import (
	"errors"
	"hash/crc32"
	"testing"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testSector       = uint64(512)
	testTotalSectors = uint64(2048)
)

func putLE64(dst []byte, v uint64) {
	for i := 0; i < 8; i++ {
		dst[i] = byte(v >> (8 * i))
	}
}

func writeGPTName(entry []byte, name string) {
	units := utf16.Encode([]rune(name))
	for i := 0; i < len(units) && i < 36; i++ {
		entry[56+i*2] = byte(units[i])
		entry[56+i*2+1] = byte(units[i] >> 8)
	}
}

func gptHeaderSector(currentLBA, backupLBA, entriesLBA uint64, entriesCRC uint32) []byte {
	header := make([]byte, 92)
	copy(header[0:8], GPTSignature)
	putLE32(header[8:12], 0x00010000)
	putLE32(header[12:16], 92)
	putLE64(header[24:32], currentLBA)
	putLE64(header[32:40], backupLBA)
	putLE64(header[40:48], 34)
	putLE64(header[48:56], testTotalSectors-34)
	for i := 56; i < 72; i++ {
		header[i] = 0x11
	}
	putLE64(header[72:80], entriesLBA)
	putLE32(header[80:84], 2)
	putLE32(header[84:88], 128)
	putLE32(header[88:92], entriesCRC)

	mut := append([]byte(nil), header...)
	for i := 16; i < 20; i++ {
		mut[i] = 0
	}
	putLE32(header[16:20], crc32.ChecksumIEEE(mut))
	return header
}

func buildGPT() []byte {
	data := make([]byte, testTotalSectors*testSector)
	data[510], data[511] = 0x55, 0xAA

	entriesOffset := int(2 * testSector)
	entries := make([]byte, 2*128)

	for i := 0; i < 16; i++ {
		entries[i] = 0xAA
		entries[16+i] = 0xBB
	}
	putLE64(entries[32:40], 100)
	putLE64(entries[40:48], 199)
	writeGPTName(entries[0:128], "Test0")

	for i := 0; i < 16; i++ {
		entries[128+i] = 0xCC
		entries[144+i] = 0xDD
	}
	putLE64(entries[160:168], 300)
	putLE64(entries[168:176], 399)
	writeGPTName(entries[128:256], "Test1")

	copy(data[entriesOffset:], entries)
	entriesCRC := crc32.ChecksumIEEE(entries)

	backupEntriesLBA := testTotalSectors - 3
	copy(data[int(backupEntriesLBA*testSector):], entries)

	header := gptHeaderSector(1, testTotalSectors-1, 2, entriesCRC)
	copy(data[int(testSector):], header)
	backup := gptHeaderSector(testTotalSectors-1, 1, backupEntriesLBA, entriesCRC)
	copy(data[int((testTotalSectors-1)*testSector):], backup)
	return data
}

func TestParseGPTPrimary(t *testing.T) {
	table, err := ParseGPT(source.NewMemorySource(1, buildGPT()), testSector)
	if err != nil {
		t.Fatalf("ParseGPT error = %v", err)
	}
	if len(table.Partitions) != 2 {
		t.Fatalf("partitions = %d, want 2", len(table.Partitions))
	}
	if table.Header.Copy != CopyPrimary || table.Header.CurrentLBA != 1 {
		t.Fatalf("header = %+v, want primary at LBA 1", table.Header)
	}
	if table.DiskGUID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("DiskGUID = %q", table.DiskGUID)
	}

	p0 := table.Partitions[0]
	if p0.StartLBA != 100 || p0.SectorCount != 100 || p0.Offset != 100*512 || p0.Len != 100*512 {
		t.Fatalf("partition 0 geometry = %+v", p0)
	}
	if p0.Name != "Test0" || p0.TypeGUID != "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA" {
		t.Fatalf("partition 0 = %q %q", p0.Name, p0.TypeGUID)
	}
	if p0.GUID != "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB" {
		t.Fatalf("partition 0 unique GUID = %q", p0.GUID)
	}
	if p0.Kind != KindGPT || p0.Index != 0 {
		t.Fatalf("partition 0 kind/index = %v/%d", p0.Kind, p0.Index)
	}
	if p1 := table.Partitions[1]; p1.StartLBA != 300 || p1.Name != "Test1" {
		t.Fatalf("partition 1 = %+v", p1)
	}
}

func TestParseGPTBackup(t *testing.T) {
	table, err := ParseGPTBackup(source.NewMemorySource(1, buildGPT()), testSector)
	if err != nil {
		t.Fatalf("ParseGPTBackup error = %v", err)
	}
	if table == nil {
		t.Fatal("ParseGPTBackup = nil, want backup table")
	}
	if table.Header.Copy != CopyBackup {
		t.Fatalf("Copy = %v, want backup", table.Header.Copy)
	}
	if table.Header.CurrentLBA != testTotalSectors-1 {
		t.Fatalf("CurrentLBA = %d, want %d", table.Header.CurrentLBA, testTotalSectors-1)
	}
	if len(table.Partitions) != 2 {
		t.Fatalf("partitions = %d, want 2", len(table.Partitions))
	}
}

func TestParseGPTBackupAbsent(t *testing.T) {
	data := make([]byte, testTotalSectors*testSector)
	table, err := ParseGPTBackup(source.NewMemorySource(1, data), testSector)
	if err != nil {
		t.Fatalf("ParseGPTBackup error = %v", err)
	}
	if table != nil {
		t.Fatalf("ParseGPTBackup = %+v, want nil for a disk without a backup header", table)
	}
}

func TestParseGPTRejectsHeaderCRCMismatch(t *testing.T) {
	data := buildGPT()
	data[int(testSector)+56] ^= 0xFF // disk GUID byte is inside the header CRC
	_, err := ParseGPT(source.NewMemorySource(1, data), testSector)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseGPT error = %v, want ErrInvalid", err)
	}
}

func TestParseGPTRejectsEntryCRCMismatch(t *testing.T) {
	data := buildGPT()
	data[int(2*testSector)+60] ^= 0xFF // name byte inside the entry array
	_, err := ParseGPT(source.NewMemorySource(1, data), testSector)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseGPT error = %v, want ErrInvalid", err)
	}
}

func TestParseGPTRejectsCurrentLBAMismatch(t *testing.T) {
	data := buildGPT()
	header := gptHeaderSector(2, testTotalSectors-1, 2, crc32.ChecksumIEEE(data[int(2*testSector):int(2*testSector)+256]))
	copy(data[int(testSector):], header)

	_, err := ParseGPT(source.NewMemorySource(1, data), testSector)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseGPT error = %v, want ErrInvalid", err)
	}
}

func TestGPTGUIDFormat(t *testing.T) {
	bytes := make([]byte, 16)
	for i := range bytes {
		bytes[i] = 0xAB
	}
	if got, want := GUIDString(bytes), "ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB"; got != want {
		t.Fatalf("GUIDString = %q, want %q", got, want)
	}
}
