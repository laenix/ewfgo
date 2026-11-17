package super

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testHeaderSize   = 128
	testMetadataMax  = 65_536
	testSlotBase     = 4096
	testImageBytes   = 8 * 1024 * 1024
	testGeometrySize = 52
)

type tableBlob struct {
	data      []byte
	count     uint32
	entrySize uint32
}

func putU16(b []byte, at int, v uint16) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
}

func putU32(b []byte, at int, v uint32) {
	for i := 0; i < 4; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

func putU64(b []byte, at int, v uint64) {
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

// makeGeometry builds one 4096-byte geometry block. Only the fields the given
// struct_size defines are written, mirroring the format's versioning.
func makeGeometry(structSize, metadataMax, slotCount uint32) []byte {
	out := make([]byte, GeometryBlockBytes)
	putU32(out, 0, GeometryMagic)
	putU32(out, 4, structSize)
	putU32(out, 40, metadataMax)
	putU32(out, 44, slotCount)
	switch {
	case structSize >= 64:
		putU64(out, 48, 2048)
		putU64(out, 56, 16383)
	case structSize >= 52:
		putU32(out, 48, 4096)
	}
	sum := sha256.Sum256(out[:structSize])
	copy(out[8:40], sum[:])
	return out
}

func defaultGeometry(slotCount uint32) []byte {
	return makeGeometry(testGeometrySize, testMetadataMax, slotCount)
}

func descriptor(offset, numEntries, entrySize uint32) []byte {
	out := make([]byte, 12)
	putU32(out, 0, offset)
	putU32(out, 4, numEntries)
	putU32(out, 8, entrySize)
	return out
}

func partitionEntry(name string, firstExtent, extents, group uint32) []byte {
	out := make([]byte, PartitionEntryBytes)
	copy(out, name)
	putU32(out, 40, firstExtent)
	putU32(out, 44, extents)
	putU32(out, 48, group)
	return out
}

func extentEntry(numSectors uint64, targetType uint32, targetData uint64, source uint32) []byte {
	out := make([]byte, ExtentEntryBytes)
	putU64(out, 0, numSectors)
	putU32(out, 8, targetType)
	putU64(out, 12, targetData)
	putU32(out, 20, source)
	return out
}

func groupEntry(name string) []byte {
	out := make([]byte, GroupEntryBytes)
	copy(out, name)
	return out
}

func blockDeviceEntry(size uint64) []byte {
	out := make([]byte, BlockDeviceEntryBytes)
	putU64(out, 16, size)
	copy(out[24:], []byte("super"))
	return out
}

func concat(blobs ...[]byte) []byte {
	var out []byte
	for _, blob := range blobs {
		out = append(out, blob...)
	}
	return out
}

// assembleImageAt places the geometry at byte zero, the two metadata slots at
// slotBase, and pads the image to targetLen. Slots are laid out exactly as the
// reader expects: a header followed by the tables it describes.
func assembleImageAt(t *testing.T, geom []byte, slotBase uint64, targetLen int,
	parts, exts, groups, devices tableBlob) []byte {
	t.Helper()

	tables := concat(parts.data, exts.data, groups.data, devices.data)
	tablesSize := uint32(len(tables))

	header := make([]byte, testHeaderSize)
	putU32(header, 0, HeaderMagic)
	putU16(header, 4, 10)
	putU16(header, 6, 2)
	putU16(header, 8, testHeaderSize)
	putU32(header, 44, tablesSize)
	partitionOffset := uint32(testHeaderSize)
	extentOffset := partitionOffset + uint32(len(parts.data))
	groupOffset := extentOffset + uint32(len(exts.data))
	deviceOffset := groupOffset + uint32(len(groups.data))
	copy(header[80:92], descriptor(partitionOffset, parts.count, parts.entrySize))
	copy(header[92:104], descriptor(extentOffset, exts.count, exts.entrySize))
	copy(header[104:116], descriptor(groupOffset, groups.count, groups.entrySize))
	copy(header[116:128], descriptor(deviceOffset, devices.count, devices.entrySize))
	tablesSum := sha256.Sum256(tables)
	copy(header[48:80], tablesSum[:])
	headerSum := sha256.Sum256(header)
	copy(header[12:44], headerSum[:])

	slot := make([]byte, testMetadataMax)
	copy(slot, header)
	copy(slot[testHeaderSize:], tables)

	image := make([]byte, slotBase)
	copy(image, geom)
	image = append(image, slot...)
	image = append(image, slot...)
	if len(image) < targetLen {
		image = append(image, make([]byte, targetLen-len(image))...)
	}
	return image[:targetLen]
}

func sampleTables() (parts, exts, groups, devices tableBlob) {
	partitionBlob := concat(
		partitionEntry("system_a", 0, 1, 0),
		partitionEntry("vendor_a", 1, 1, 0),
	)
	extentBlob := concat(
		extentEntry(8192, TargetLinear, 2048, 0),
		extentEntry(1024, TargetZero, 0, 0),
	)
	groupBlob := groupEntry("group_a")
	deviceBlob := blockDeviceEntry(testImageBytes)
	return tableBlob{partitionBlob, 2, PartitionEntryBytes},
		tableBlob{extentBlob, 2, ExtentEntryBytes},
		tableBlob{groupBlob, 1, GroupEntryBytes},
		tableBlob{deviceBlob, 1, BlockDeviceEntryBytes}
}

// sample builds a super image with a 4 MiB linear partition at byte 1 MiB and a
// 512 KiB zero partition, exactly like the reference fixture.
func sample(t *testing.T) []byte {
	t.Helper()
	parts, exts, groups, devices := sampleTables()
	return assembleImageAt(t, defaultGeometry(2), testSlotBase, testImageBytes,
		parts, exts, groups, devices)
}

func openImage(t *testing.T, bytes []byte) *Image {
	t.Helper()
	image, err := Open(source.NewMemorySource(1, bytes))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if image == nil {
		t.Fatal("Open returned nil")
	}
	return image
}

func repairHeader(image []byte, base int) {
	header := append([]byte(nil), image[base:base+testHeaderSize]...)
	for i := 12; i < 44; i++ {
		header[i] = 0
	}
	sum := sha256.Sum256(header)
	copy(image[base+12:base+44], sum[:])
}

func repairSlot(image []byte, slot int) {
	base := testSlotBase + slot*testMetadataMax
	tablesSize := int(le32(image, base+44))
	tablesStart := base + testHeaderSize
	tables := image[tablesStart : tablesStart+tablesSize]
	tablesSum := sha256.Sum256(tables)
	copy(image[base+48:base+80], tablesSum[:])
	repairHeader(image, base)
}

func TestReadsBothPartitionsAndTheirSpans(t *testing.T) {
	image := sample(t)
	for i := 0; i < 16; i++ {
		image[1024*1024+i] = byte(0xA0 + i)
	}
	opened := openImage(t, image)

	if opened.MetadataSlot() != 0 {
		t.Fatalf("metadata slot = %d", opened.MetadataSlot())
	}
	if opened.MetadataOffset() != 4096 {
		t.Fatalf("metadata offset = %d", opened.MetadataOffset())
	}
	if opened.Geometry().MetadataSlotCount != 2 {
		t.Fatalf("slot count = %d", opened.Geometry().MetadataSlotCount)
	}
	if opened.Geometry().LogicalBlockSize == nil || *opened.Geometry().LogicalBlockSize != 4096 {
		t.Fatalf("logical block size = %v", opened.Geometry().LogicalBlockSize)
	}
	if opened.UsedBackupGeometry() {
		t.Fatal("primary geometry was valid but the backup was reported")
	}
	if len(opened.Partitions()) != 2 || len(opened.Extents()) != 2 {
		t.Fatalf("partitions/extents = %d/%d", len(opened.Partitions()), len(opened.Extents()))
	}
	if opened.Groups()[0].Name != "group_a" {
		t.Fatalf("group = %+v", opened.Groups()[0])
	}
	if opened.BlockDevices()[0].Size != testImageBytes {
		t.Fatalf("block device size = %d", opened.BlockDevices()[0].Size)
	}
	if opened.BlockDevice() == nil || opened.BlockDevice().PartitionName != "super" {
		t.Fatalf("block device = %+v", opened.BlockDevice())
	}

	system := opened.Partitions()[0]
	if system.Name != "system_a" || system.Len != 4*1024*1024 {
		t.Fatalf("system partition = %+v", system)
	}
	if system.FirstLinearOffset == nil || *system.FirstLinearOffset != 1024*1024 {
		t.Fatalf("system first linear offset = %v", system.FirstLinearOffset)
	}
	if len(system.Spans) != 1 || system.Spans[0].Logical != 0 ||
		system.Spans[0].Len != 4*1024*1024 ||
		system.Spans[0].Target.Kind != SpanLinear ||
		system.Spans[0].Target.ParentOffset != 1024*1024 {
		t.Fatalf("system spans = %+v", system.Spans)
	}

	vendor := opened.Partitions()[1]
	if vendor.Name != "vendor_a" || vendor.Len != 512*1024 {
		t.Fatalf("vendor partition = %+v", vendor)
	}
	if vendor.FirstLinearOffset != nil {
		t.Fatalf("vendor first linear offset = %v", vendor.FirstLinearOffset)
	}
	if len(vendor.Spans) != 1 || vendor.Spans[0].Target.Kind != SpanZero {
		t.Fatalf("vendor spans = %+v", vendor.Spans)
	}

	systemView, err := opened.OpenPartition(2, 0)
	if err != nil {
		t.Fatalf("OpenPartition(0) = %v", err)
	}
	buf := make([]byte, 16)
	if n, err := systemView.ReadAt(0, buf); err != nil || n != 16 {
		t.Fatalf("system read = %d, %v", n, err)
	}
	if string(buf) != string(image[1024*1024:1024*1024+16]) {
		t.Fatal("system read did not come from the linear extent")
	}
	if _, err := systemView.ReadAt(4*1024*1024, buf); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past system = %v", err)
	}
	if systemView.Name() != "system_a" || systemView.Index() != 0 {
		t.Fatalf("partition view = %q #%d", systemView.Name(), systemView.Index())
	}

	vendorView, err := opened.OpenPartition(3, 1)
	if err != nil {
		t.Fatalf("OpenPartition(1) = %v", err)
	}
	zeroes := make([]byte, 64)
	for i := range zeroes {
		zeroes[i] = 0xA5
	}
	if n, err := vendorView.ReadAt(0, zeroes); err != nil || n != 64 {
		t.Fatalf("vendor read = %d, %v", n, err)
	}
	for _, b := range zeroes {
		if b != 0 {
			t.Fatal("zero extent did not read as zeroes")
		}
	}
	extents, err := vendorView.Extents(0, 64)
	if err != nil || len(extents) != 1 || extents[0].Kind != source.RangeHole {
		t.Fatalf("vendor extents = %+v, %v", extents, err)
	}
}

func TestSecondSlotUsedWhenFirstDoesNotVerify(t *testing.T) {
	image := sample(t)
	image[4096+12] ^= 0xFF // break slot 0's header checksum
	opened := openImage(t, image)
	if opened.MetadataSlot() != 1 {
		t.Fatalf("metadata slot = %d", opened.MetadataSlot())
	}
	if opened.MetadataOffset() != 4096+testMetadataMax {
		t.Fatalf("metadata offset = %d", opened.MetadataOffset())
	}
}

func TestFirstVerifyingSlotWinsWhenBothAreValid(t *testing.T) {
	opened := openImage(t, sample(t))
	if opened.MetadataSlot() != 0 {
		t.Fatalf("metadata slot = %d; the reader must not invent a newest slot", opened.MetadataSlot())
	}
}

func TestBadGeometryChecksumRefusedAndBackupGeometryUsed(t *testing.T) {
	image := sample(t)
	image[8] ^= 0xFF
	_, err := Open(source.NewMemorySource(1, image))
	if err == nil {
		t.Fatal("a bad geometry checksum was accepted")
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindGeometryChecksum {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "geometry checksum") {
		t.Fatalf("message = %v", err)
	}
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error does not wrap ErrCorrupt: %v", err)
	}

	image = sample(t)
	image[8] ^= 0xFF
	copy(image[4096:4096+GeometryBlockBytes], defaultGeometry(2))
	opened := openImage(t, image)
	if !opened.UsedBackupGeometry() {
		t.Fatal("a valid backup geometry was not reported")
	}
}

func TestBadHeaderAndTableChecksumsRefused(t *testing.T) {
	image := sample(t)
	image[4096+12] ^= 0xFF
	image[4096+testMetadataMax+12] ^= 0xFF
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindHeaderChecksum {
		t.Fatalf("header checksum error = %v", err)
	}

	image = sample(t)
	image[4096+testHeaderSize+4] ^= 0xFF
	image[4096+testMetadataMax+testHeaderSize+4] ^= 0xFF
	_, err = Open(source.NewMemorySource(1, image))
	if !errors.As(err, &typed) || typed.Kind != KindTablesChecksum {
		t.Fatalf("table checksum error = %v", err)
	}
}

func TestBadEntrySizeRefused(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		putU32(image, base+80+8, 8)
		repairHeader(image, base)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindEntrySize {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "at least 52") {
		t.Fatalf("message = %v", err)
	}
}

func TestTableTooLargeAndTableRangeRefused(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		putU32(image, base+84, MaxPartitions+1)
		repairHeader(image, base)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindTableTooLarge {
		t.Fatalf("table-too-large error = %v", err)
	}

	image = sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		putU32(image, base+80, 0x100000)
		repairHeader(image, base)
	}
	_, err = Open(source.NewMemorySource(1, image))
	if !errors.As(err, &typed) || typed.Kind != KindTableRange {
		t.Fatalf("table-range error = %v", err)
	}
}

func TestExtentOutsideBlockDeviceRefused(t *testing.T) {
	image := sample(t)
	device := blockDeviceEntry(2 * 1024 * 1024)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		deviceOffset := base + testHeaderSize + 2*PartitionEntryBytes + 2*ExtentEntryBytes + 48
		copy(image[deviceOffset:], device)
		repairSlot(image, slot)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindExtentOutsideBlockDevice {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "block device") {
		t.Fatalf("message = %v", err)
	}
}

func TestExtentOutsideImageRefused(t *testing.T) {
	image := sample(t)[:256*1024]
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindExtentOutsideImage {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error does not wrap ErrCorrupt: %v", err)
	}
}

func TestNoBlockDeviceRefused(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		putU32(image, base+116+4, 0) // block device table: zero entries
		repairHeader(image, base)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindNoBlockDevice {
		t.Fatalf("error = %v", err)
	}
}

func TestNonzeroTargetSourceRefusedByName(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		extentOffset := base + testHeaderSize + 2*PartitionEntryBytes
		putU32(image, extentOffset+20, 1)
		repairSlot(image, slot)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindUnsupportedTargetSource ||
		typed.TargetSource != 1 {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "block device 1") {
		t.Fatalf("message = %v", err)
	}
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error does not wrap ErrUnsupported: %v", err)
	}
}

func TestUnsupportedTargetTypeRefused(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		extentOffset := base + testHeaderSize + 2*PartitionEntryBytes
		putU32(image, extentOffset+8, 5)
		repairSlot(image, slot)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindUnsupportedTargetType {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error does not wrap ErrUnsupported: %v", err)
	}
}

func TestPartitionExtentRangeRefused(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		partitionOffset := base + testHeaderSize
		putU32(image, partitionOffset+40, 2)
		putU32(image, partitionOffset+44, 2)
		repairSlot(image, slot)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindPartitionExtentRange {
		t.Fatalf("error = %v", err)
	}
}

func TestInvalidGeometryParametersRefused(t *testing.T) {
	tests := []struct {
		name string
		geom []byte
		kind Kind
	}{
		{"zero metadata max", makeGeometry(52, 0, 2), KindMetadataMaxSize},
		{"unaligned metadata max", makeGeometry(52, 65_537, 2), KindMetadataMaxSize},
		{"oversized metadata max", makeGeometry(52, MaxMetadataSize+512, 2), KindMetadataMaxSize},
		{"zero slots", makeGeometry(52, testMetadataMax, 0), KindSlotCount},
		{"too many slots", makeGeometry(52, testMetadataMax, MaxSlots+1), KindSlotCount},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parts, exts, groups, devices := sampleTables()
			image := assembleImageAt(t, test.geom, testSlotBase, testImageBytes,
				parts, exts, groups, devices)
			_, err := Open(source.NewMemorySource(1, image))
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != test.kind {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestInvalidHeaderSizeRefused(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		putU16(image, base+8, 64)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindHeaderSize {
		t.Fatalf("error = %v", err)
	}
}

func TestTablesOutsideSlotRefused(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		putU32(image, base+44, MaxTablesBytes+1)
		repairHeader(image, base)
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindTablesOutsideSlot {
		t.Fatalf("error = %v", err)
	}

	image = sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		putU32(image, base+44, testMetadataMax)
		repairHeader(image, base)
	}
	_, err = Open(source.NewMemorySource(1, image))
	if !errors.As(err, &typed) || typed.Kind != KindTablesOutsideSlot {
		t.Fatalf("header+tables overflow error = %v", err)
	}
}

func TestNoValidSlotRefused(t *testing.T) {
	image := sample(t)
	for slot := 0; slot < 2; slot++ {
		base := testSlotBase + slot*testMetadataMax
		for i := 0; i < 4; i++ {
			image[base+i] = 0
		}
	}
	_, err := Open(source.NewMemorySource(1, image))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindNoValidSlot {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "verified") {
		t.Fatalf("message = %v", err)
	}
}

func TestTruncatedGeometryRefused(t *testing.T) {
	_, err := Open(source.NewMemorySource(1, make([]byte, 20)))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindTruncatedGeometry {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("error does not wrap ErrUnexpectedEOF: %v", err)
	}

	// A truncated slot region still names a structured failure.
	_, err = Open(source.NewMemorySource(1, sample(t)[:4096+64]))
	if !errors.As(err, &typed) || typed.Kind != KindNoValidSlot {
		t.Fatalf("truncated slot error = %v", err)
	}
}

func TestGeometryStructSizeVariants(t *testing.T) {
	for _, size := range []uint32{48, 52, 64} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			geom := makeGeometry(size, testMetadataMax, 2)
			parts, exts, groups, devices := sampleTables()
			image := assembleImageAt(t, geom, testSlotBase, testImageBytes,
				parts, exts, groups, devices)
			opened := openImage(t, image)
			geometry := opened.Geometry()
			if geometry.StructSize != size {
				t.Fatalf("struct size = %d", geometry.StructSize)
			}
			switch {
			case size >= 64:
				if geometry.LogicalBlockSize != nil {
					t.Fatalf("logical block size = %v", geometry.LogicalBlockSize)
				}
				if geometry.FirstLogicalSector == nil || *geometry.FirstLogicalSector != 2048 ||
					geometry.LastLogicalSector == nil || *geometry.LastLogicalSector != 16383 {
					t.Fatalf("sector range = %v..%v", geometry.FirstLogicalSector, geometry.LastLogicalSector)
				}
			case size >= 52:
				if geometry.LogicalBlockSize == nil || *geometry.LogicalBlockSize != 4096 {
					t.Fatalf("logical block size = %v", geometry.LogicalBlockSize)
				}
				if geometry.FirstLogicalSector != nil || geometry.LastLogicalSector != nil {
					t.Fatal("old sector fields were reported for a block-size layout")
				}
			default:
				if geometry.LogicalBlockSize != nil || geometry.FirstLogicalSector != nil {
					t.Fatal("fields beyond struct_size 48 were reported")
				}
			}
		})
	}
}

func TestSlotBasesFallback(t *testing.T) {
	parts, exts, groups, devices := sampleTables()
	image := assembleImageAt(t, defaultGeometry(2), 8192, testImageBytes,
		parts, exts, groups, devices)
	opened := openImage(t, image)
	if opened.MetadataOffset() != 8192 {
		t.Fatalf("metadata offset = %d", opened.MetadataOffset())
	}
}

func TestDetectionRequiresVerifyingGeometry(t *testing.T) {
	image := sample(t)
	if !MatchesSignature(image) {
		t.Fatal("the sample image does not match the geometry signature")
	}
	if !MatchesGeometry(image) {
		t.Fatal("the sample geometry does not verify")
	}

	bad := append([]byte(nil), image...)
	bad[8] ^= 0xFF
	if !MatchesSignature(bad) {
		t.Fatal("the bad image lost its signature")
	}
	if MatchesGeometry(bad) {
		t.Fatal("a magic-only geometry verified")
	}
	if MatchesSignature(make([]byte, 4)) {
		t.Fatal("four zero bytes matched the geometry signature")
	}

	// A false positive: the magic followed by an impossible struct size.
	falsePositive := make([]byte, 64)
	putU32(falsePositive, 0, GeometryMagic)
	putU32(falsePositive, 4, 8)
	if !MatchesSignature(falsePositive) {
		t.Fatal("the false positive lost its signature")
	}
	if MatchesGeometry(falsePositive) {
		t.Fatal("an impossible struct size verified")
	}
}

func TestDetectReportsTypedStatus(t *testing.T) {
	notPresent, err := Detect(source.NewMemorySource(1, make([]byte, 16*1024)))
	if err != nil || notPresent.Present {
		t.Fatalf("zero source detection = %+v, %v", notPresent, err)
	}

	detection, err := Detect(source.NewMemorySource(1, sample(t)))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if !detection.Present || !detection.Signature || !detection.GeometryValid ||
		detection.Backup || detection.Offset != 0 || detection.Geometry == nil {
		t.Fatalf("detection = %+v", detection)
	}

	bad := sample(t)
	bad[8] ^= 0xFF
	detection, err = Detect(source.NewMemorySource(1, bad))
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != KindGeometryChecksum {
		t.Fatalf("bad checksum detection error = %v", err)
	}
	if !detection.Present || !detection.Signature || detection.GeometryValid ||
		detection.Kind != KindGeometryChecksum {
		t.Fatalf("bad checksum detection = %+v", detection)
	}

	falsePositive := make([]byte, 64)
	putU32(falsePositive, 0, GeometryMagic)
	putU32(falsePositive, 4, 8)
	detection, err = Detect(source.NewMemorySource(1, falsePositive))
	if !errors.As(err, &typed) || typed.Kind != KindGeometrySize {
		t.Fatalf("false positive detection error = %v", err)
	}
	if !detection.Present || !detection.Signature || detection.GeometryValid ||
		detection.Kind != KindGeometrySize {
		t.Fatalf("false positive detection = %+v", detection)
	}

	// A valid backup geometry is reported with its offset.
	backup := sample(t)
	backup[8] ^= 0xFF
	copy(backup[4096:4096+GeometryBlockBytes], defaultGeometry(2))
	detection, err = Detect(source.NewMemorySource(1, backup))
	if err != nil || !detection.GeometryValid || !detection.Backup ||
		detection.Offset != GeometryBlockBytes {
		t.Fatalf("backup detection = %+v, %v", detection, err)
	}
}

func TestOpenIfPresent(t *testing.T) {
	for _, bytes := range [][]byte{make([]byte, 512), make([]byte, 16*1024)} {
		opened, err := OpenIfPresent(source.NewMemorySource(1, bytes))
		if err != nil || opened != nil {
			t.Fatalf("OpenIfPresent(%d bytes) = %v, %v", len(bytes), opened, err)
		}
	}
	opened, err := OpenIfPresent(source.NewMemorySource(1, sample(t)))
	if err != nil || opened == nil {
		t.Fatalf("OpenIfPresent(sample) = %v, %v", opened, err)
	}
}

func TestPartitionSourceNeverReachesPastItsExtents(t *testing.T) {
	opened := openImage(t, sample(t))
	vendor, err := opened.OpenPartition(2, 1)
	if err != nil {
		t.Fatalf("OpenPartition = %v", err)
	}
	if vendor.Len() != 512*1024 || vendor.SectorSize() != 512 {
		t.Fatalf("vendor len/sector = %d/%d", vendor.Len(), vendor.SectorSize())
	}
	buf := make([]byte, 8)
	if _, err := vendor.ReadAt(512*1024, buf); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past the partition = %v", err)
	}
	if _, err := vendor.Extents(512*1024-4, 8); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extents past the partition = %v", err)
	}
	if n, err := vendor.ReadAt(900, nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	ranges, err := vendor.MapToImage(0, 8)
	if err != nil || len(ranges) != 1 || ranges[0].Kind != source.RangeHole {
		t.Fatalf("zero image ranges = %+v, %v", ranges, err)
	}
	if _, err := opened.OpenPartition(4, 9); err == nil {
		t.Fatal("a nonexistent partition index was accepted")
	}
	if vendor.Image() != opened {
		t.Fatal("partition source does not expose its image")
	}
}

func TestMultiExtentPartitionSpansAndReads(t *testing.T) {
	parts := tableBlob{partitionEntry("data_a", 0, 2, 0), 1, PartitionEntryBytes}
	exts := tableBlob{concat(
		extentEntry(2, TargetLinear, 2048, 0),
		extentEntry(2, TargetLinear, 4096, 0),
	), 2, ExtentEntryBytes}
	groups := tableBlob{groupEntry("group_a"), 1, GroupEntryBytes}
	devices := tableBlob{blockDeviceEntry(4 * 1024 * 1024), 1, BlockDeviceEntryBytes}

	image := assembleImageAt(t, defaultGeometry(1), testSlotBase, 4*1024*1024,
		parts, exts, groups, devices)
	first := make([]byte, 1024)
	second := make([]byte, 1024)
	for i := range first {
		first[i] = byte(i)
		second[i] = byte(255 - i)
	}
	copy(image[1024*1024:], first)
	copy(image[2*1024*1024:], second)

	opened := openImage(t, image)
	partition := opened.Partitions()[0]
	if partition.Len != 2048 || len(partition.Spans) != 2 {
		t.Fatalf("partition = %+v", partition)
	}
	if partition.Spans[1].Logical != 1024 ||
		partition.Spans[1].Target.ParentOffset != 2*1024*1024 {
		t.Fatalf("second span = %+v", partition.Spans[1])
	}

	view, err := opened.OpenPartition(2, 0)
	if err != nil {
		t.Fatalf("OpenPartition = %v", err)
	}
	got := make([]byte, 100)
	if n, err := view.ReadAt(1000, got); err != nil || n != 100 {
		t.Fatalf("cross-extent read = %d, %v", n, err)
	}
	want := append(append([]byte{}, first[1000:]...), second[:76]...)
	if string(got) != string(want) {
		t.Fatal("cross-extent read assembled the wrong bytes")
	}
	spans, err := view.Extents(1000, 100)
	if err != nil || len(spans) != 2 {
		t.Fatalf("cross-extent extents = %+v, %v", spans, err)
	}
	if spans[0].ParentOffset != 1024*1024+1000 || spans[0].Len != 24 ||
		spans[1].ParentOffset != 2*1024*1024 || spans[1].Len != 76 {
		t.Fatalf("cross-extent extents = %+v", spans)
	}
	mapped, err := view.MapToImage(1000, 100)
	if err != nil || len(mapped) != 2 ||
		mapped[0].ImageOffset != 1024*1024+1000 || mapped[1].ImageOffset != 2*1024*1024 {
		t.Fatalf("cross-extent image map = %+v, %v", mapped, err)
	}
}

func TestGeometryChecksumHexHelpers(t *testing.T) {
	opened := openImage(t, sample(t))
	if len(opened.GeometryChecksumHex()) != 64 ||
		len(opened.HeaderChecksumHex()) != 64 ||
		len(opened.TablesChecksumHex()) != 64 {
		t.Fatalf("checksum hex lengths = %d/%d/%d",
			len(opened.GeometryChecksumHex()),
			len(opened.HeaderChecksumHex()),
			len(opened.TablesChecksumHex()))
	}
	if opened.Header().MajorVersion != 10 || opened.Header().MinorVersion != 2 ||
		opened.Header().HeaderSize != testHeaderSize {
		t.Fatalf("header = %+v", opened.Header())
	}
}

func TestExtentHelpers(t *testing.T) {
	linear := Extent{NumSectors: 2, TargetType: TargetLinear, TargetData: 10}
	if linear.ByteLen() != 1024 || !linear.IsLinear() || linear.IsZero() {
		t.Fatalf("linear extent = %+v", linear)
	}
	if offset, ok := linear.ParentOffset(); !ok || offset != 5120 {
		t.Fatalf("linear parent offset = %d ok=%v", offset, ok)
	}
	zero := Extent{NumSectors: 2, TargetType: TargetZero}
	if !zero.IsZero() || zero.IsLinear() {
		t.Fatalf("zero extent = %+v", zero)
	}
	if _, ok := zero.ParentOffset(); ok {
		t.Fatal("a zero extent reported a parent offset")
	}
}
