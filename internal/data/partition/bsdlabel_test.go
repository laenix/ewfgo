package partition

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	bsdLabelMagic     = uint32(0x82564557)
	bsdLabelMagic64   = uint32(0xC4464C59)
	bsdTestSectors    = 128
	bsdTestSectorSize = 512
)

func putU16(order ByteOrder, dst []byte, v uint16) {
	if order == BigEndian {
		putBE16(dst, v)
		return
	}
	dst[0], dst[1] = byte(v), byte(v>>8)
}

func putU32(order ByteOrder, dst []byte, v uint32) {
	if order == BigEndian {
		putBE32(dst, v)
		return
	}
	putLE32(dst, v)
}

type bsdEntry struct {
	offset, size uint32
	fstype       byte
	offsetHigh   uint16
	sizeHigh     uint16
}

func buildBSDLabel(order ByteOrder, secsize uint32, version uint16, name string, entries ...bsdEntry) []byte {
	table := make([]byte, 148+len(entries)*16)
	putU32(order, table[0:], bsdLabelMagic)
	copy(table[8:24], name)
	putU32(order, table[40:], secsize)
	putU16(order, table[114:], version)
	putU32(order, table[132:], bsdLabelMagic)
	putU16(order, table[138:], uint16(len(entries)))
	for i, e := range entries {
		at := 148 + i*16
		putU32(order, table[at:], e.size)
		putU32(order, table[at+4:], e.offset)
		if version >= 1 {
			putU16(order, table[at+8:], e.offsetHigh)
			putU16(order, table[at+10:], e.sizeHigh)
		}
		table[at+12] = e.fstype
	}
	putU16(order, table[136:], 0)
	var sum uint16
	for i := 0; i+1 < len(table); i += 2 {
		sum ^= order.U16(table[i:], 0)
	}
	putU16(order, table[136:], sum)
	return table
}

func bsdDisk(label []byte) []byte {
	image := make([]byte, bsdTestSectors*bsdTestSectorSize)
	copy(image[512:], label)
	return image
}

func TestParseBSDLittleEndian(t *testing.T) {
	label := buildBSDLabel(LittleEndian, 512, 0, "SCSI",
		bsdEntry{offset: 1, size: 20, fstype: 7},
		bsdEntry{offset: 21, size: 10, fstype: 8},
	)
	table, err := ParseBSD(source.NewMemorySource(1, bsdDisk(label)))
	if err != nil {
		t.Fatalf("ParseBSD error = %v", err)
	}
	if table == nil {
		t.Fatal("ParseBSD = nil, want a label")
	}
	if table.ByteOrder != LittleEndian || table.SectorSize != 512 || table.Version != 0 {
		t.Fatalf("label header = %+v", table)
	}
	if table.DiskType != "SCSI" || table.NPartitions != 2 || table.LabelBlock != 512 {
		t.Fatalf("label metadata = %+v", table)
	}
	if !table.Checksum.Verified {
		t.Fatalf("checksum = %+v, want verified", table.Checksum)
	}
	if len(table.Partitions) != 2 {
		t.Fatalf("partitions = %d, want 2", len(table.Partitions))
	}
	p := table.Partitions[0]
	if p.StartLBA != 1 || p.SectorCount != 20 || p.Offset != 512 || p.Len != 20*512 {
		t.Fatalf("partition a = %+v", p)
	}
	if p.Name != "4.2BSD/FFS (a)" || p.TypeGUID != "4.2BSD/FFS (a)" || p.TypeID != 7 {
		t.Fatalf("partition a label = %q %q %#x", p.Name, p.TypeGUID, p.TypeID)
	}
	if q := table.Partitions[1]; q.Name != "MSDOS (b)" {
		t.Fatalf("partition b name = %q", q.Name)
	}
}

func TestParseBSDBigEndian(t *testing.T) {
	label := buildBSDLabel(BigEndian, 512, 0, "SCSI",
		bsdEntry{offset: 1, size: 20, fstype: 7},
	)
	table, err := ParseBSD(source.NewMemorySource(1, bsdDisk(label)))
	if err != nil {
		t.Fatalf("ParseBSD error = %v", err)
	}
	if table == nil || table.ByteOrder != BigEndian || len(table.Partitions) != 1 {
		t.Fatalf("table = %+v", table)
	}
}

func TestParseBSDSkipsUnusedAndZeroSize(t *testing.T) {
	label := buildBSDLabel(LittleEndian, 512, 0, "SCSI",
		bsdEntry{offset: 0, size: 10, fstype: 0},  // unused
		bsdEntry{offset: 10, size: 0, fstype: 7},  // zero size
		bsdEntry{offset: 11, size: 10, fstype: 7}, // real
	)
	table, err := ParseBSD(source.NewMemorySource(1, bsdDisk(label)))
	if err != nil {
		t.Fatal(err)
	}
	if table.Skipped != 2 || len(table.Partitions) != 1 {
		t.Fatalf("skipped = %d, partitions = %d", table.Skipped, len(table.Partitions))
	}
}

func TestParseBSDReportsChecksumMismatch(t *testing.T) {
	label := buildBSDLabel(LittleEndian, 512, 0, "SCSI",
		bsdEntry{offset: 1, size: 20, fstype: 7},
	)
	label[8] ^= 0xFF // mutate d_typename after the checksum was written
	table, err := ParseBSD(source.NewMemorySource(1, bsdDisk(label)))
	if err != nil {
		t.Fatalf("ParseBSD error = %v, want the label to still be read", err)
	}
	if table.Checksum.Verified {
		t.Fatal("checksum reported verified after mutation")
	}
}

func TestParseBSDDoesNotClaimMagicWithoutMagic2(t *testing.T) {
	label := buildBSDLabel(LittleEndian, 512, 0, "SCSI",
		bsdEntry{offset: 1, size: 20, fstype: 7},
	)
	putU32(LittleEndian, label[132:], 0)
	table, err := ParseBSD(source.NewMemorySource(1, bsdDisk(label)))
	if err != nil || table != nil {
		t.Fatalf("ParseBSD = %+v, %v; want nil, nil", table, err)
	}
}

func TestParseBSDRejectsTooManyPartitions(t *testing.T) {
	label := buildBSDLabel(LittleEndian, 512, 0, "SCSI")
	putU16(LittleEndian, label[138:], 23)
	_, err := ParseBSD(source.NewMemorySource(1, bsdDisk(label)))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseBSD error = %v, want ErrInvalid", err)
	}
}

func TestParseBSDRejectsPartitionPastDisk(t *testing.T) {
	label := buildBSDLabel(LittleEndian, 512, 0, "SCSI",
		bsdEntry{offset: 1, size: bsdTestSectors + 10, fstype: 7},
	)
	_, err := ParseBSD(source.NewMemorySource(1, bsdDisk(label)))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseBSD error = %v, want ErrInvalid", err)
	}
}

func TestParseBSDRefusesDragonFly64(t *testing.T) {
	image := make([]byte, bsdTestSectors*bsdTestSectorSize)
	putLE32(image[512:], bsdLabelMagic64)
	_, err := ParseBSD(source.NewMemorySource(1, image))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ParseBSD error = %v, want ErrUnsupported", err)
	}
}

func TestBSD48BitGeometry(t *testing.T) {
	entry := make([]byte, 16)
	putU32(LittleEndian, entry[0:], 0x00000010) // size low
	putU32(LittleEndian, entry[4:], 0x00000020) // offset low
	putU16(LittleEndian, entry[8:], 1)          // offset high
	putU16(LittleEndian, entry[10:], 2)         // size high
	entry[12] = 7

	start, count := bsdEntryGeometry(entry, LittleEndian, 1)
	if start != 0x1_00000020 || count != 0x2_00000010 {
		t.Fatalf("48-bit geometry = (%#x, %#x)", start, count)
	}

	start, count = bsdEntryGeometry(entry, LittleEndian, 0)
	if start != 0x20 || count != 0x10 {
		t.Fatalf("32-bit geometry = (%#x, %#x)", start, count)
	}
}

func TestDetectBSD(t *testing.T) {
	label := buildBSDLabel(LittleEndian, 512, 0, "SCSI",
		bsdEntry{offset: 1, size: 20, fstype: 7},
	)
	table, err := Detect(source.NewMemorySource(1, bsdDisk(label)))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if table.Kind != KindBSD || table.BSD == nil || len(table.Partitions()) != 1 {
		t.Fatalf("Detect = %+v", table)
	}
}
