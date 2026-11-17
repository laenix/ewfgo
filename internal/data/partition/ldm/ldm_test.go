package ldm

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestSimpleVolumeReportsContiguousRange(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 2048)
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db == nil {
		t.Fatal("Parse returned no database")
	}
	if db.DiskGUID == nil || *db.DiskGUID != testDiskGUID {
		t.Fatalf("disk GUID = %v", db.DiskGUID)
	}
	if db.Copy != CopyHead {
		t.Fatalf("copy = %v, want head", db.Copy)
	}
	if db.Version != (Version{2, 12}) {
		t.Fatalf("version = %v", db.Version)
	}
	if db.VolumeCount != 1 || db.PartitionCount != 2 {
		t.Fatalf("counts = %d volumes, %d partitions", db.VolumeCount, db.PartitionCount)
	}
	if db.RecordsSkipped != 0 {
		t.Fatalf("records skipped = %d", db.RecordsSkipped)
	}
	if db.ThisDiskID == nil || *db.ThisDiskID != testDiskID {
		t.Fatalf("this disk id = %v", db.ThisDiskID)
	}
	if len(db.Groups) != 1 {
		t.Fatalf("groups = %d", len(db.Groups))
	}
	group := &db.Groups[0]
	if len(group.Disks) != 1 {
		t.Fatalf("disks = %d", len(group.Disks))
	}
	if !group.Disks[0].ThisDisk {
		t.Fatal("the identified disk is not marked this disk")
	}
	if len(group.Disks[0].Partitions) != 2 {
		t.Fatalf("partitions = %d", len(group.Disks[0].Partitions))
	}

	volume := &group.Volumes[0]
	if volume.Name == nil || *volume.Name != "Volume1" {
		t.Fatalf("volume name = %v", volume.Name)
	}
	if volume.Layout != LayoutConcatenated {
		t.Fatalf("layout = %v", volume.Layout)
	}
	if volume.DeclaredComponents != 1 {
		t.Fatalf("declared components = %d", volume.DeclaredComponents)
	}
	if len(volume.ComponentIDs) != 1 || volume.ComponentIDs[0] != testComponentID {
		t.Fatalf("component ids = %v", volume.ComponentIDs)
	}
	if volume.SpansDisks {
		t.Fatal("volume unexpectedly spans disks")
	}
	if len(volume.Extents) != 2 {
		t.Fatalf("extents = %d", len(volume.Extents))
	}
	if volume.Extents[0].Offset == nil || *volume.Extents[0].Offset != testPublicStart*512 {
		t.Fatalf("extent 0 offset = %v", volume.Extents[0].Offset)
	}
	if volume.Extents[1].Offset == nil || *volume.Extents[1].Offset != (testPublicStart+1024)*512 {
		t.Fatalf("extent 1 offset = %v", volume.Extents[1].Offset)
	}
	want := Range{Offset: testPublicStart * 512, Len: 3072 * 512}
	if volume.Range == nil || *volume.Range != want {
		t.Fatalf("range = %v, want %v", volume.Range, want)
	}
}

func TestRevision4DiskGUIDIdentifiesThisDiskInStructOrder(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 2048)
	records[1] = vblk(0x44, 5, 0, diskV4Body(testDiskID, "Disk1", guidStructBytes()))
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.ThisDiskID == nil || *db.ThisDiskID != testDiskID {
		t.Fatalf("this disk id = %v", db.ThisDiskID)
	}
	if !db.Groups[0].Disks[0].ThisDisk {
		t.Fatal("revision-4 disk was not identified in struct byte order")
	}
	if db.Groups[0].Volumes[0].Range == nil {
		t.Fatal("a concatenated volume on this disk lost its range")
	}
	// The displayed GUID stays in the order the record stores it.
	if got := db.Groups[0].Disks[0].GUID; got == nil || *got != "ba284e1b-a12f-d211-883f-0016d3cca427" {
		t.Fatalf("stored GUID = %v", got)
	}
}

func TestVolumeWithExtentOnAnotherDiskSpansDisks(t *testing.T) {
	other := testOtherDiskID
	records := oneVolumeRecords(&other, 1024, 2048)
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 11}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	group := &db.Groups[0]
	if len(group.Disks) != 2 {
		t.Fatalf("disks = %d", len(group.Disks))
	}
	if db.ThisDiskID == nil || *db.ThisDiskID != testDiskID {
		t.Fatalf("this disk id = %v", db.ThisDiskID)
	}
	volume := &group.Volumes[0]
	if !volume.SpansDisks {
		t.Fatal("volume with a foreign extent did not report spanning")
	}
	if volume.Range != nil {
		t.Fatalf("spanning volume has a contiguous range: %v", volume.Range)
	}
	if len(volume.Extents) != 2 {
		t.Fatalf("extents = %d", len(volume.Extents))
	}
	if !volume.Extents[0].OnThisDisk || volume.Extents[0].Offset == nil {
		t.Fatalf("extent 0 = %+v", volume.Extents[0])
	}
	if volume.Extents[1].OnThisDisk || volume.Extents[1].Offset != nil {
		t.Fatalf("extent 1 = %+v", volume.Extents[1])
	}
	if volume.Extents[1].DiskName == nil || *volume.Extents[1].DiskName != "Disk2" {
		t.Fatalf("foreign extent disk name = %v", volume.Extents[1].DiskName)
	}
}

func TestDamagedHeadTOCFallsBackToTailCopy(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	db, err := parseImage(t, testImage(t, records, []uint64{2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.Copy != CopyTail {
		t.Fatalf("copy = %v, want tail", db.Copy)
	}
	if db.VolumeCount != 1 {
		t.Fatalf("volumes = %d", db.VolumeCount)
	}
}

func TestCorruptPrivHeadChecksumIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	for _, block := range []uint64{6, testPrivateStart + 1856, testPrivateStart + 2047} {
		image[block*512+0xF0] ^= 0xFF
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "PRIVHEAD checksum") {
		t.Fatalf("error = %v", err)
	}
}

func TestCorruptTOCBlockChecksumIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	for _, block := range []uint64{1, 2, 2045, 2046} {
		image[(testPrivateStart+block)*512+0x14] ^= 0xFF
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "TOCBLOCK checksum") {
		t.Fatalf("error = %v", err)
	}
}

func TestTOCCopiesThatDisagreeAreRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, nil, Version{2, 12})
	for _, block := range []uint64{1, 2} {
		writeTOCBlockSizes(image, block, 17, 2028)
	}
	for _, block := range []uint64{2045, 2046} {
		writeTOCBlockSizes(image, block, 17, 2020)
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "TOCBLOCK copies disagree") {
		t.Fatalf("error = %v", err)
	}
}

func TestVMDBVolumeCountThatDisagreesWithRecordsIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	putU32(image, int(testDBBlock)*512+0x85, 99)
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "99 committed volume") {
		t.Fatalf("error = %v", err)
	}
}

func TestUncleanDatabaseReportsPendingCounts(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	vmdb := int(testDBBlock) * 512
	putU16(image, vmdb+0x10, 2)
	putU32(image, vmdb+0xA1, 7)
	db, err := parseImage(t, image)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.Clean {
		t.Fatal("database reported clean")
	}
	if db.UpdateStatus != 2 {
		t.Fatalf("update status = %d", db.UpdateStatus)
	}
	if db.CommittedCounts.Volumes != 1 || db.PendingCounts.Volumes != 7 {
		t.Fatalf("counts = %+v / %+v", db.CommittedCounts, db.PendingCounts)
	}
	if db.VolumeCount != 1 {
		t.Fatalf("volumes = %d", db.VolumeCount)
	}
}

func TestImpossibleVBLKLengthIsCorrupt(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	putU32(records[1], 0x14, 0x1000)
	_, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "declares 4096 body bytes") {
		t.Fatalf("error = %v", err)
	}
}

func TestDeviceWithoutLDMSignatureIsNotClaimed(t *testing.T) {
	db, err := parseImage(t, make([]byte, int(testSectors*512)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db != nil {
		t.Fatalf("zero device parsed as LDM: %+v", db)
	}

	tail := make([]byte, 4096)
	copy(tail, "NTFS")
	db, err = Parse(source.NewMemorySource(1, tail))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db != nil {
		t.Fatal("non-LDM tail parsed as LDM")
	}
	if MatchesTail(tail) {
		t.Fatal("MatchesTail claimed a non-LDM tail")
	}
}

func TestTruncatedDeviceNeverPanics(t *testing.T) {
	db, err := Parse(source.NewMemorySource(1, make([]byte, 700)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db != nil {
		t.Fatal("short device parsed as LDM")
	}

	// A header that announces itself but whose private region cannot fit.
	image := make([]byte, 4096)
	writePrivHead(image, 6*512, Version{2, 12})
	_, err = parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "private region") {
		t.Fatalf("error = %v", err)
	}
}

func TestUnsupportedPrivHeadVersionIsRefusedByName(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	_, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{3, 0}))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "3.0") {
		t.Fatalf("error = %v", err)
	}
}

func TestTOCRegionPastPrivateRegionIsCorrupt(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, nil, Version{2, 12})
	for _, block := range []uint64{1, 2, 2045, 2046} {
		writeTOCBlockSizes(image, block, 17, 4000)
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "runs past the 2048-block private region") {
		t.Fatalf("error = %v", err)
	}
}

func TestExtentPastPublicRegionIsCorrupt(t *testing.T) {
	records := oneVolumeRecords(nil, 3000, 2000)
	_, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "public region") {
		t.Fatalf("error = %v", err)
	}
}

func TestMatchesTailRecognizesBackupStructures(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	tail := image[len(image)-1024*1024:]
	if !MatchesTail(tail) {
		t.Fatal("MatchesTail did not find the backup structures")
	}
	if !MatchesTail(image[:4096]) {
		t.Fatal("MatchesTail did not find the primary header")
	}
	if MatchesTail(nil) {
		t.Fatal("MatchesTail claimed an empty buffer")
	}
}

func TestAllVBLKTypesDecodeAndCrossLink(t *testing.T) {
	chunk := uint64(2)
	stripe := uint64(2)
	columns := uint64(2)
	hint := `\DosDevices\C:`
	records := [][]byte{
		vblk(0x45, 1, 0, groupV4Body("DgV4", [16]byte(guidBytes()))),
		vblk(0x44, 2, 0, diskV4Body(testDiskID, "Disk1", guidStructBytes())),
		vblk(0x32, 3, 0x10, componentBodyFlags(testComponentID, testVolumeID, 2, 1, &stripe, &columns)),
		vblk(0x33, 4, 0x08, partitionBodyColumn(testPartitionA, "Disk1-01", testDiskID, testComponentID, 0, 0, 1024, 0)),
		vblk(0x33, 5, 0x08, partitionBodyColumn(testPartitionB, "Disk1-02", testDiskID, testComponentID, 1024, 1024, 1024, 1)),
		vblk(0x51, 6, 0x82, volumeBodyFlags(testVolumeID, "Stripe", 2048, 1, 0x82, &chunk, &hint)),
	}
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	disk := db.Disk(testDiskID)
	if disk == nil {
		t.Fatal("revision-4 disk not listed")
	}
	if len(disk.Partitions) != 2 {
		t.Fatalf("disk partitions = %d", len(disk.Partitions))
	}
	for _, partition := range disk.Partitions {
		if partition.StripeBlocks == nil || *partition.StripeBlocks != 2 {
			t.Fatalf("partition %d stripe blocks = %v", partition.ID, partition.StripeBlocks)
		}
		if partition.Columns == nil || *partition.Columns != 2 {
			t.Fatalf("partition %d columns = %v", partition.ID, partition.Columns)
		}
		if partition.ChunkBlocks == nil || *partition.ChunkBlocks != 2 {
			t.Fatalf("partition %d chunk blocks = %v", partition.ID, partition.ChunkBlocks)
		}
		if partition.ComponentLayout != LayoutStripe {
			t.Fatalf("partition %d component layout = %v", partition.ID, partition.ComponentLayout)
		}
	}
	if disk.Partitions[0].Column == nil || *disk.Partitions[0].Column != 0 {
		t.Fatalf("partition 0 column = %v", disk.Partitions[0].Column)
	}
	volume := &db.Groups[0].Volumes[0]
	if volume.Layout != LayoutStripe {
		t.Fatalf("volume layout = %v", volume.Layout)
	}
	if geometry := db.VolumeGeometry(volume); geometry.ChunkBlocks == nil || *geometry.ChunkBlocks != 2 {
		t.Fatalf("geometry chunk blocks = %v", geometry.ChunkBlocks)
	}
	if volume.DriveHint == nil || *volume.DriveHint != hint {
		t.Fatalf("volume drive hint = %v", volume.DriveHint)
	}
	if volume.PartitionType == nil || *volume.PartitionType != 0x07 {
		t.Fatalf("volume partition type = %v", volume.PartitionType)
	}
	if volume.GUID == nil || *volume.GUID != "1b4e28ba-2fa1-11d2-883f-0016d3cca427" {
		t.Fatalf("volume GUID = %v", volume.GUID)
	}
	if volume.Range != nil {
		t.Fatalf("stripe volume has a contiguous range: %v", volume.Range)
	}

	geometry := db.VolumeGeometry(volume)
	if len(geometry.Components) != 1 {
		t.Fatalf("geometry components = %d", len(geometry.Components))
	}
	component := geometry.Components[0]
	if component.Layout != LayoutStripe || component.Columns == nil || *component.Columns != 2 {
		t.Fatalf("component geometry = %+v", component)
	}
	if len(component.Partitions) != 2 {
		t.Fatalf("component partitions = %d", len(component.Partitions))
	}
}

func TestPartitionOptionalFlagsAreConsumed(t *testing.T) {
	body := partitionBodyColumn(testPartitionA, "Disk1-01", testDiskID, testComponentID, 0, 0, 1024, 1)
	body = append(body, make([]byte, 8)...)
	pushVNum(&body, 3) // flag 0x02 hidden volume offset
	records := [][]byte{
		vblk(0x35, 1, 0, groupBody("Dg0")),
		vblk(0x34, 2, 0, diskBody(testDiskID, "Disk1", testDiskGUID)),
		vblk(0x32, 3, 0, componentBody(testComponentID, testVolumeID, 1)),
		vblk(0x33, 4, 0x2A, body),
		vblk(0x51, 5, 0, volumeBody(testVolumeID, "Volume1", 1024, 1)),
	}
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	partition := &db.Groups[0].Disks[0].Partitions[0]
	if partition.Column == nil || *partition.Column != 1 {
		t.Fatalf("column = %v", partition.Column)
	}
	if db.MalformedRecords != 0 || db.RecordsSkipped != 0 {
		t.Fatalf("skipped/malformed = %d/%d", db.RecordsSkipped, db.MalformedRecords)
	}
}

func TestVolumeOptionalFlagsAreConsumed(t *testing.T) {
	chunk := uint64(4)
	hint := `\DosDevices\D:`
	records := [][]byte{
		vblk(0x35, 1, 0, groupBody("Dg0")),
		vblk(0x34, 2, 0, diskBody(testDiskID, "Disk1", testDiskGUID)),
		vblk(0x32, 3, 0, componentBody(testComponentID, testVolumeID, 1)),
		vblk(0x33, 4, 0, partitionBody(testPartitionA, "Disk1-01", testDiskID, testComponentID, 0, 0, 1024)),
		vblk(0x51, 5, 0xAA, volumeBodyFlags(testVolumeID, "Volume1", 1024, 1, 0xAA, &chunk, &hint)),
	}
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	volume := &db.Groups[0].Volumes[0]
	if partition := &db.Groups[0].Disks[0].Partitions[0]; partition.ChunkBlocks == nil || *partition.ChunkBlocks != 4 {
		t.Fatalf("store chunk blocks = %v", partition.ChunkBlocks)
	}
	if volume.DriveHint == nil || *volume.DriveHint != hint {
		t.Fatalf("drive hint = %v", volume.DriveHint)
	}
	if db.MalformedRecords != 0 || db.RecordsSkipped != 0 {
		t.Fatalf("skipped/malformed = %d/%d", db.RecordsSkipped, db.MalformedRecords)
	}
}

func TestUnknownKindsAreCountedNotDropped(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	records = append(records, vblk(0x99, 11, 0, []byte{1, 2, 3, 4}))
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.RecordsSkipped != 1 || db.MalformedRecords != 0 {
		t.Fatalf("skipped/malformed = %d/%d", db.RecordsSkipped, db.MalformedRecords)
	}
	if len(db.UndecodedKinds) != 1 {
		t.Fatalf("undecoded kinds = %+v", db.UndecodedKinds)
	}
	kind := db.UndecodedKinds[0]
	if kind.Kind != 0x99 || kind.Count != 1 || kind.Label != "unknown" {
		t.Fatalf("undecoded kind = %+v", kind)
	}
}

func TestMalformedKnownRecordIsCounted(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	records = append(records, vblk(0x32, 11, 0, []byte{0x01, 0x08}))
	counts := VmdbCounts{Volumes: 1, Components: 1, Partitions: 2, Disks: 1}
	db, err := parseImage(t, testImageWithCounts(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}, &counts))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.MalformedRecords != 1 || db.RecordsSkipped != 1 {
		t.Fatalf("skipped/malformed = %d/%d", db.RecordsSkipped, db.MalformedRecords)
	}
}

func TestEmptySlotIsSkipped(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	putU32(image, int(testDBBlock)*512+0x04, uint32(len(records)+1))
	db, err := parseImage(t, image)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.RecordsSkipped != 1 {
		t.Fatalf("records skipped = %d", db.RecordsSkipped)
	}
}

func TestFragmentedVBLKIsReassembled(t *testing.T) {
	full := vblk(0x34, 5, 0, diskBody(testDiskID, "Disk1", testDiskGUID))
	split := len(full) / 2
	slot0 := make([]byte, testVBLKStride)
	slot1 := make([]byte, testVBLKStride)
	copy(slot0[:0x10], full[:0x10])
	putU16(slot0, 0x0C, 0)
	putU16(slot0, 0x0E, 2)
	copy(slot0[0x10:], full[0x10:split])
	copy(slot1[:0x10], full[:0x10])
	putU16(slot1, 0x0C, 1)
	putU16(slot1, 0x0E, 2)
	copy(slot1[0x10:], full[split:])

	records := [][]byte{
		vblk(0x35, 1, 0, groupBody("Dg0")),
		slot0,
		slot1,
		vblk(0x32, 7, 0, componentBody(testComponentID, testVolumeID, 2)),
		vblk(0x33, 8, 0, partitionBody(testPartitionA, "Disk1-01", testDiskID, testComponentID, 0, 0, 1024)),
		vblk(0x33, 9, 0, partitionBody(testPartitionB, "Disk1-02", testDiskID, testComponentID, 1024, 1024, 1024)),
		vblk(0x51, 10, 0, volumeBody(testVolumeID, "Volume1", 2048, 1)),
	}
	counts := VmdbCounts{Volumes: 1, Components: 1, Partitions: 2, Disks: 1}
	db, err := parseImage(t, testImageWithCounts(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}, &counts))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.ThisDiskID == nil || *db.ThisDiskID != testDiskID {
		t.Fatalf("fragmented disk did not decode: this disk = %v", db.ThisDiskID)
	}
	if db.MalformedRecords != 0 {
		t.Fatalf("malformed records = %d", db.MalformedRecords)
	}
}

func TestInvalidFragmentCountsAreSkipped(t *testing.T) {
	full := vblk(0x34, 5, 0, diskBody(testDiskID, "Disk1", testDiskGUID))
	zero := append([]byte(nil), full...)
	putU16(zero, 0x0E, 0)
	tooMany := append([]byte(nil), full...)
	putU16(tooMany, 0x0E, 5)
	records := [][]byte{
		vblk(0x35, 1, 0, groupBody("Dg0")),
		zero,
		tooMany,
	}
	counts := VmdbCounts{}
	db, err := parseImage(t, testImageWithCounts(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}, &counts))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.RecordsSkipped != 2 {
		t.Fatalf("records skipped = %d", db.RecordsSkipped)
	}
}

func TestUnknownComponentLayoutByteIsReported(t *testing.T) {
	records := [][]byte{
		vblk(0x35, 1, 0, groupBody("Dg0")),
		vblk(0x34, 2, 0, diskBody(testDiskID, "Disk1", testDiskGUID)),
		vblk(0x32, 3, 0, componentBodyFlags(testComponentID, testVolumeID, 1, 9, nil, nil)),
		vblk(0x33, 4, 0, partitionBody(testPartitionA, "Disk1-01", testDiskID, testComponentID, 0, 0, 1024)),
		vblk(0x51, 5, 0, volumeBody(testVolumeID, "Volume1", 1024, 1)),
	}
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.Groups[0].Volumes[0].Layout != LayoutUnknown {
		t.Fatalf("layout = %v", db.Groups[0].Volumes[0].Layout)
	}
}

func TestInvalidBytesPerBlockIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	for _, block := range []uint64{6, testPrivateStart + 1856, testPrivateStart + 2047} {
		putU32(image, int(block*512)+0x10F, 1000)
		restampPrivHead(image, block)
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "power of two") {
		t.Fatalf("error = %v", err)
	}
}

func TestZeroPrivateRegionIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	for _, block := range []uint64{6, testPrivateStart + 1856, testPrivateStart + 2047} {
		putU64(image, int(block*512)+0x133, 0)
		restampPrivHead(image, block)
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "zero-length private region") {
		t.Fatalf("error = %v", err)
	}
}

func TestPublicRegionOverlappingPrivateIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	for _, block := range []uint64{6, testPrivateStart + 1856, testPrivateStart + 2047} {
		putU64(image, int(block*512)+0x11B, 6000)
		putU64(image, int(block*512)+0x123, 1000)
		restampPrivHead(image, block)
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "overlaps the private region") {
		t.Fatalf("error = %v", err)
	}
}

func TestNoTOCBlockCopyIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	_, err := parseImage(t, testImage(t, records, nil, Version{2, 12}))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "no TOCBLOCK") {
		t.Fatalf("error = %v", err)
	}
}

func TestTOCRegionNotNamedConfigIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, nil, Version{2, 12})
	for _, block := range []uint64{1, 2, 2045, 2046} {
		writeTOCBlock(image, block)
		copy(image[(testPrivateStart+block)*512+0x24:], "logx")
		restampTOCBlock(image, block)
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), `not "config"`) {
		t.Fatalf("error = %v", err)
	}
}

func TestZeroLengthConfigTOCIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, nil, Version{2, 12})
	for _, block := range []uint64{1, 2, 2045, 2046} {
		writeTOCBlockSizes(image, block, 17, 0)
	}
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "zero-length config region") {
		t.Fatalf("error = %v", err)
	}
}

func TestVMDBVBLKSizeMustTileABlock(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	putU32(image, int(testDBBlock)*512+0x08, 100)
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "cannot tile a 512-byte block") {
		t.Fatalf("error = %v", err)
	}
}

func TestUnsupportedVMDBVersionIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	putU16(image, int(testDBBlock)*512+0x12, 5)
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "5.10") {
		t.Fatalf("error = %v", err)
	}
}

func TestVBLKStreamPastConfigRegionIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	putU32(image, int(testDBBlock)*512+0x0C, 2028*512)
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "runs past the config region") {
		t.Fatalf("error = %v", err)
	}
}

func TestBackupPrivHeadAloneIsEnough(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	copy(image[6*512:6*512+8], make([]byte, 8))
	db, err := parseImage(t, image)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	wantOffset := uint64((testPrivateStart + PrivHeadBackupBlock) * 512)
	if db.PrivHeadOffset != wantOffset {
		t.Fatalf("privhead offset = %d, want %d", db.PrivHeadOffset, wantOffset)
	}
}

func TestPartitionEndOverflowIsRefused(t *testing.T) {
	records := [][]byte{
		vblk(0x35, 1, 0, groupBody("Dg0")),
		vblk(0x34, 2, 0, diskBody(testDiskID, "Disk1", testDiskGUID)),
		vblk(0x32, 3, 0, componentBody(testComponentID, testVolumeID, 1)),
		vblk(0x33, 4, 0, partitionBody(testPartitionA, "Disk1-01", testDiskID, testComponentID, math.MaxUint64, 0, 2)),
		vblk(0x51, 5, 0, volumeBody(testVolumeID, "Volume1", 2, 1)),
	}
	_, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "overflows u64") {
		t.Fatalf("error = %v", err)
	}
}

func TestLittleEndianChecksumIsAccepted(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	for _, block := range []uint64{6, testPrivateStart + 1856, testPrivateStart + 2047} {
		at := int(block * 512)
		sum := blockChecksum(image[at : at+512])
		binary.LittleEndian.PutUint32(image[at+0x08:], sum)
	}
	for _, block := range []uint64{1, 2, 2045, 2046} {
		at := int((testPrivateStart + block) * 512)
		sum := blockChecksum(image[at : at+512])
		binary.LittleEndian.PutUint32(image[at+0x08:], sum)
	}
	db, err := parseImage(t, image)
	if err != nil {
		t.Fatalf("a byte-reversed checksum must be accepted: %v", err)
	}
	if db.VolumeCount != 1 {
		t.Fatalf("volumes = %d", db.VolumeCount)
	}
}

func TestVBLKStreamOverTheCapIsRefused(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
	vmdb := int(testDBBlock) * 512
	putU32(image, vmdb+0x08, 512)
	putU32(image, vmdb+0x04, 200000) // 512 * 200000 = ~102 MiB
	_, err := parseImage(t, image)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "more than this reader accepts") {
		t.Fatalf("error = %v", err)
	}
}

func TestUnresolvedPartitionIsKept(t *testing.T) {
	records := [][]byte{
		vblk(0x35, 1, 0, groupBody("Dg0")),
		vblk(0x34, 2, 0, diskBody(testDiskID, "Disk1", testDiskGUID)),
		vblk(0x32, 3, 0, componentBody(testComponentID, testVolumeID, 1)),
		vblk(0x33, 4, 0, partitionBody(testPartitionA, "Ghost-01", 99, testComponentID, 0, 0, 16)),
		vblk(0x51, 5, 0, volumeBody(testVolumeID, "Volume1", 16, 1)),
	}
	counts := VmdbCounts{Volumes: 1, Components: 1, Partitions: 1, Disks: 1}
	db, err := parseImage(t, testImageWithCounts(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}, &counts))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	group := &db.Groups[0]
	if len(group.Disks) != 1 || len(group.Disks[0].Partitions) != 0 {
		t.Fatalf("disk partitions = %d", len(group.Disks[0].Partitions))
	}
	if len(group.UnresolvedPartitions) != 1 {
		t.Fatalf("unresolved partitions = %+v", group.UnresolvedPartitions)
	}
	if len(db.Partitions()) != 1 {
		t.Fatalf("accessor partitions = %d", len(db.Partitions()))
	}
	volume := &group.Volumes[0]
	if len(volume.Extents) != 1 || volume.Extents[0].DiskName != nil {
		t.Fatalf("extents = %+v", volume.Extents)
	}
	if !volume.SpansDisks {
		t.Fatal("an extent on an unknown disk did not report spanning")
	}
	if volume.Range != nil {
		t.Fatalf("range = %v", volume.Range)
	}
}

func TestFragmentedRecordBodyOverrunIsRefused(t *testing.T) {
	full := make([]byte, vblkHeaderBytes+20)
	copy(full[0:4], VBLKMagic)
	putU32(full, 0x08, 1)
	putU16(full, 0x0C, 0)
	putU16(full, 0x0E, 2)
	full[0x13] = 0x34
	putU32(full, 0x14, 512) // more body than the record can hold

	split := 32 // keeps the whole declared body length in the first fragment
	slot0 := make([]byte, testVBLKStride)
	slot1 := make([]byte, testVBLKStride)
	copy(slot0[:0x10], full[:0x10])
	putU16(slot0, 0x0C, 0)
	putU16(slot0, 0x0E, 2)
	copy(slot0[0x10:], full[0x10:split])
	copy(slot1[:0x10], full[:0x10])
	putU16(slot1, 0x0C, 1)
	putU16(slot1, 0x0E, 2)
	copy(slot1[0x10:], full[split:])

	counts := VmdbCounts{}
	_, err := parseImage(t, testImageWithCounts(t, [][]byte{slot0, slot1}, []uint64{1, 2, 2045, 2046}, Version{2, 12}, &counts))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "fragmented LDM VBLK group") {
		t.Fatalf("error = %v", err)
	}
}

func TestUndocumentedDatabaseHeaderKindsAreCounted(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 1024)
	records = append(records,
		vblk(0x01, 11, 0, []byte{1, 2}),
		vblk(0x02, 12, 0, []byte{1, 2}),
	)
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if db.RecordsSkipped != 2 {
		t.Fatalf("records skipped = %d", db.RecordsSkipped)
	}
	if len(db.UndecodedKinds) != 2 {
		t.Fatalf("undecoded kinds = %+v", db.UndecodedKinds)
	}
	for i, kind := range []uint8{0x01, 0x02} {
		entry := db.UndecodedKinds[i]
		if entry.Kind != kind || entry.Count != 1 || entry.Label != "undocumented database header" {
			t.Fatalf("undecoded kind %d = %+v", i, entry)
		}
	}
}

func TestGroupRecordIsUsedWhenHeadersCarryNoName(t *testing.T) {
	cases := []struct {
		name     string
		kind     byte
		body     []byte
		wantName string
		wantGUID string
	}{
		{"revision3", 0x35, groupBody("DgV3"), "DgV3", testGroupGUID},
		{"revision4", 0x45, groupV4Body("DgV4", [16]byte(guidBytes())), "DgV4", "1b4e28ba-2fa1-11d2-883f-0016d3cca427"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := oneVolumeRecords(nil, 1024, 1024)
			records[0] = vblk(tc.kind, 4, 0, tc.body)
			image := testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12})
			for _, block := range []uint64{6, testPrivateStart + 1856, testPrivateStart + 2047} {
				at := int(block * 512)
				copy(image[at+0xB0:at+0xF0], make([]byte, 64))  // group GUID
				copy(image[at+0xF0:at+0x10F], make([]byte, 31)) // group name
				restampPrivHead(image, block)
			}
			vmdb := int(testDBBlock) * 512
			copy(image[vmdb+0x16:vmdb+0x35], make([]byte, 31)) // VMDB group name
			copy(image[vmdb+0x35:vmdb+0x75], make([]byte, 64)) // VMDB group GUID
			db, err := parseImage(t, image)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if db.DiskGroup == nil || *db.DiskGroup != tc.wantName {
				t.Fatalf("group name = %v, want %q", db.DiskGroup, tc.wantName)
			}
			if db.DiskGroupGUID == nil || *db.DiskGroupGUID != tc.wantGUID {
				t.Fatalf("group GUID = %v, want %q", db.DiskGroupGUID, tc.wantGUID)
			}
		})
	}
}

func TestKindLabel(t *testing.T) {
	cases := map[byte]string{
		0x32: "component",
		0x33: "partition",
		0x34: "disk (revision 3)",
		0x35: "disk group (revision 3)",
		0x44: "disk (revision 4)",
		0x45: "disk group (revision 4)",
		0x51: "volume",
		0x01: "undocumented database header",
		0x02: "undocumented database header",
		0x77: "unknown",
	}
	for kind, want := range cases {
		if got := KindLabel(kind); got != want {
			t.Errorf("KindLabel(%#x) = %q, want %q", kind, got, want)
		}
	}
}

func TestLayoutAndCopyLabels(t *testing.T) {
	for layout, want := range map[Layout]string{
		LayoutConcatenated: "concatenated",
		LayoutStripe:       "stripe",
		LayoutRaid5:        "raid5",
		LayoutMirrored:     "mirrored",
		LayoutUnknown:      "unknown",
	} {
		if got := layout.Label(); got != want {
			t.Errorf("Layout(%d).Label() = %q, want %q", layout, got, want)
		}
	}
	if CopyHead.Label() != "head" || CopyTail.Label() != "tail" {
		t.Fatal("copy labels are wrong")
	}
}

func TestDatabaseAccessors(t *testing.T) {
	records := oneVolumeRecords(nil, 1024, 2048)
	db, err := parseImage(t, testImage(t, records, []uint64{1, 2, 2045, 2046}, Version{2, 12}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(db.Volumes()) != 1 || len(db.Disks()) != 1 || len(db.Partitions()) != 2 {
		t.Fatalf("accessors = %d/%d/%d", len(db.Volumes()), len(db.Disks()), len(db.Partitions()))
	}
	if db.Disk(testDiskID) == nil || db.Disk(9999) != nil {
		t.Fatal("Disk lookup is wrong")
	}
	disk := db.Disks()[0]
	if disk.GUID == nil || *disk.GUID != testDiskGUID {
		t.Fatalf("disk GUID = %v", disk.GUID)
	}
}
