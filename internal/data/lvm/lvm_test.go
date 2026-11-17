package lvm

import (
	"errors"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const testPVUUID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func testLVMMetadataText() string {
	return `vgtest {
    id = "vg-uuid"
    seqno = 2
    extent_size = 8192
    pv_count = 1
    lv_count = 1
    status = ["RESIZEABLE", "READ", "WRITE"]
    creation_host = "host"
    creation_time = 1700000000
    physical_volumes {
        pv0 {
            id = "` + testPVUUID + `"
            device = "/dev/sda2"
            pe_start = 2048
            pe_count = 100
        }
    }
    logical_volumes {
        root {
            id = "lv-uuid"
            status = ["READ", "WRITE"]
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 10
                type = "striped"
                stripe_count = 1
                stripes = [
                    "` + testPVUUID + `", 0
                ]
            }
        }
    }
}
`
}

func putLE64T(dst []byte, v uint64) {
	for i := 0; i < 8; i++ {
		dst[i] = byte(v >> (8 * i))
	}
}

func putLE32T(dst []byte, v uint32) {
	for i := 0; i < 4; i++ {
		dst[i] = byte(v >> (8 * i))
	}
}

func buildLVMDisk(text string) []byte {
	disk := make([]byte, 1<<20)
	const metadataOffset = 4096
	const metadataSize = 4096

	// Metadata-area header.
	header := make([]byte, 512)
	copy(header[4:20], mdaMagic)
	putLE32T(header[20:], 1)
	putLE64T(header[24:], metadataOffset)
	putLE64T(header[32:], metadataSize)
	putLE64T(header[40:], 512) // raw location offset from the area start
	putLE64T(header[48:], uint64(len(text)))
	putLE32T(header[56:], crc32.ChecksumIEEE([]byte(text)))
	putLE32T(header[60:], 0)
	copy(disk[metadataOffset:], header)
	zero := make([]byte, 4)
	copy(disk[metadataOffset:], zero)
	putLE32T(disk[metadataOffset:], crc32.ChecksumIEEE(disk[metadataOffset:metadataOffset+512]))
	copy(disk[metadataOffset+512:], text)

	// LABELONE sector.
	label := make([]byte, 512)
	copy(label[0:8], "LABELONE")
	putLE64T(label[8:], 1)
	copy(label[24:32], "LVM2 001")
	putLE32T(label[20:], 32)
	copy(label[32:64], testPVUUID)
	putLE64T(label[64:], uint64(len(disk)))
	// Data area list: (0, device size), null.
	putLE64T(label[72:], 0)
	putLE64T(label[80:], uint64(len(disk)))
	putLE64T(label[88:], 0)
	putLE64T(label[96:], 0)
	// Metadata area list: (offset, size), null.
	putLE64T(label[104:], metadataOffset)
	putLE64T(label[112:], metadataSize)
	putLE64T(label[120:], 0)
	putLE64T(label[128:], 0)
	putLE32T(label[16:], 0)
	putLE32T(label[16:], crc32.ChecksumIEEE(label))
	copy(disk[512:], label)
	return disk
}

func TestReadLVM(t *testing.T) {
	image := buildLVMDisk(testLVMMetadataText())
	got, err := Read(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if got == nil {
		t.Fatal("Read = nil, want a physical volume")
	}
	if got.Label.PVUUID != testPVUUID {
		t.Fatalf("PVUUID = %q", got.Label.PVUUID)
	}
	if !got.Label.ChecksumOK {
		t.Fatalf("label checksum = stored %08X computed %08X", got.Label.StoredCRC, got.Label.ComputedCRC)
	}
	if got.Label.DeviceSize != uint64(len(image)) {
		t.Fatalf("DeviceSize = %d, want %d", got.Label.DeviceSize, len(image))
	}
	if len(got.Label.DataAreas) != 1 || len(got.Label.MetadataAreas) != 1 {
		t.Fatalf("areas = data %+v metadata %+v", got.Label.DataAreas, got.Label.MetadataAreas)
	}
	if got.MetadataArea == nil || !got.MetadataArea.ChecksumOK {
		t.Fatalf("metadata area = %+v", got.MetadataArea)
	}
	if got.MetadataChecksumOK == nil || !*got.MetadataChecksumOK {
		t.Fatalf("metadata text checksum = %v", got.MetadataChecksumOK)
	}

	group := got.Group
	if group == nil {
		t.Fatal("Group = nil")
	}
	if group.Name != "vgtest" || group.UUID != "vg-uuid" || group.Seqno != 2 {
		t.Fatalf("group = %+v", group)
	}
	if group.ExtentSize != 8192 {
		t.Fatalf("ExtentSize = %d", group.ExtentSize)
	}
	if bytes, ok := group.ExtentBytes(); !ok || bytes != 8192*512 {
		t.Fatalf("ExtentBytes = %d, %v", bytes, ok)
	}
	if len(group.PhysicalVolumes) != 1 {
		t.Fatalf("PVs = %d", len(group.PhysicalVolumes))
	}
	pv := group.PhysicalVolumes[0]
	if pv.Name != "pv0" || pv.UUID != testPVUUID || pv.PEStart != 2048 || pv.PECount != 100 {
		t.Fatalf("PV = %+v", pv)
	}
	if len(group.LogicalVolumes) != 1 {
		t.Fatalf("LVs = %d", len(group.LogicalVolumes))
	}
	lv := group.LogicalVolumes[0]
	if lv.Name != "root" || lv.UUID != "lv-uuid" || len(lv.Segments) != 1 {
		t.Fatalf("LV = %+v", lv)
	}
	seg := lv.Segments[0]
	if seg.StartExtent != 0 || seg.ExtentCount != 10 || seg.Kind != "striped" || seg.StripeCount != 1 {
		t.Fatalf("segment = %+v", seg)
	}
	if len(seg.Stripes) != 1 || seg.Stripes[0].PVUUID != testPVUUID || seg.Stripes[0].StartExtent != 0 {
		t.Fatalf("stripes = %+v", seg.Stripes)
	}
	if got := lv.ExtentTotal(); got != 10 {
		t.Fatalf("ExtentTotal = %d, want 10", got)
	}
}

func TestReadLVMNoLabel(t *testing.T) {
	got, err := Read(source.NewMemorySource(1, make([]byte, 1<<20)))
	if err != nil || got != nil {
		t.Fatalf("Read(zeroed) = %+v, %v; want nil, nil", got, err)
	}
}

func TestReadLVMRejectsWrongLabelType(t *testing.T) {
	image := buildLVMDisk(testLVMMetadataText())
	copy(image[512+24:512+32], "LVM1 001")
	_, err := Read(source.NewMemorySource(1, image))
	if !errors.Is(err, ErrLabel) {
		t.Fatalf("Read error = %v, want ErrLabel", err)
	}
}

func TestReadLVMRejectsBadMetadataMagic(t *testing.T) {
	image := buildLVMDisk(testLVMMetadataText())
	copy(image[4096+4:4096+20], []byte("not-the-magic!!!"))
	_, err := Read(source.NewMemorySource(1, image))
	if !errors.Is(err, ErrMetadata) {
		t.Fatalf("Read error = %v, want ErrMetadata", err)
	}
}

func TestTextParserCommentsArraysAndEscapes(t *testing.T) {
	text := `
# leading comment
vg {
  status = ["READ", "WRITE"]   # trailing comment
  note = "a \"quoted\" value"
  nested {
    key = 42
  }
}
`
	group, err := decodeText([]byte(text))
	if err != nil {
		t.Fatalf("decodeText error = %v", err)
	}
	if group.Name != "vg" {
		t.Fatalf("name = %q", group.Name)
	}
	if len(group.Status) != 2 || group.Status[1] != "WRITE" {
		t.Fatalf("status = %+v", group.Status)
	}
	switch {
	case group.UUID != "":
		t.Fatalf("UUID = %q", group.UUID)
	}
}

func TestTextParserRejectsUnterminatedSection(t *testing.T) {
	_, err := decodeText([]byte(`vg { a = 1`))
	if !errors.Is(err, ErrText) {
		t.Fatalf("decodeText error = %v, want ErrText", err)
	}
}

func TestTextParserRejectsDeepNesting(t *testing.T) {
	_, err := decodeText([]byte(strings.Repeat("[", 64)))
	if !errors.Is(err, ErrText) {
		t.Fatalf("decodeText error = %v, want ErrText", err)
	}
}

func TestIdentifyLVM(t *testing.T) {
	image := buildLVMDisk(testLVMMetadataText())
	got, err := Identify(image)
	if err != nil {
		t.Fatalf("Identify error = %v", err)
	}
	if got == nil || got.Label.PVUUID != testPVUUID {
		t.Fatalf("Identify = %+v", got)
	}
}
