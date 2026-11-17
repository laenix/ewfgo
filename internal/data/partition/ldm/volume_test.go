package ldm

import (
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	volImageLen   = 8192
	volBlock      = uint64(512)
	volPublicBase = uint64(16)
	volUnit       = uint64(1024)
	volColumnLen  = 8 * volUnit
)

func spanExtent(partitionID, volumeOffset, sectors, imageOffset uint64) Extent {
	return Extent{
		PartitionID:  partitionID,
		DiskID:       1,
		DiskName:     ptrStr("Disk1"),
		OnThisDisk:   true,
		StartLBA:     imageOffset / SectorBytes,
		VolumeOffset: volumeOffset,
		Sectors:      sectors,
		Offset:       ptrU64(imageOffset),
		Len:          sectors * SectorBytes,
	}
}

func twoExtents() []Extent {
	return []Extent{spanExtent(9, 0, 4, 0), spanExtent(10, 4, 4, 4096)}
}

func testVolume(extents []Extent, sizeSectors *uint64, layout Layout) *Volume {
	return &Volume{
		ID:                 11,
		Name:               ptrStr("Volume1"),
		VolumeType:         ptrStr("gen"),
		State:              ptrStr("ACTIVE"),
		SizeSectors:        sizeSectors,
		PartitionType:      func() *uint8 { v := uint8(0x07); return &v }(),
		DeclaredComponents: 1,
		ComponentIDs:       []uint64{8},
		Layout:             layout,
		Extents:            extents,
	}
}

// patternSource is an image whose bytes are index%251, so a wrong offset is
// visible.
func patternSource(id source.ID) source.ByteSource {
	data := make([]byte, volImageLen)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return source.NewMemorySource(id, data)
}

func patternByte(at int) byte { return byte(at % 251) }

func openVolume(t *testing.T, volume *Volume) (*VolumeSource, error) {
	t.Helper()
	return OpenVolume(2, patternSource(1), volume)
}

func TestExtentsAreOrderedAndReadAcrossTheJoin(t *testing.T) {
	extents := []Extent{spanExtent(10, 4, 4, 4096), spanExtent(9, 0, 4, 0)}
	volume := testVolume(extents, ptrU64(8), LayoutConcatenated)
	vol, err := openVolume(t, volume)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if vol.Len() != 4096 {
		t.Fatalf("len = %d", vol.Len())
	}
	if vol.Name() != "Volume1" {
		t.Fatalf("name = %q", vol.Name())
	}
	spans := vol.Spans()
	if len(spans) != 2 || spans[0].PartitionID != 9 || spans[0].VolumeOffset != 0 || spans[0].ImageOffset != 0 {
		t.Fatalf("spans = %+v", spans)
	}
	if spans[1].PartitionID != 10 || spans[1].VolumeOffset != 2048 || spans[1].ImageOffset != 4096 {
		t.Fatalf("span 1 = %+v", spans[1])
	}

	// Eight bytes straddling the 2048-byte join come from extent A's tail and
	// extent B's head, not from adjacent image bytes.
	buf := make([]byte, 8)
	n, err := vol.ReadAt(2044, buf)
	if err != nil || n != 8 {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	var want []byte
	for _, index := range []int{2044, 2045, 2046, 2047, 4096, 4097, 4098, 4099} {
		want = append(want, patternByte(index))
	}
	for i := range want {
		if buf[i] != want[i] {
			t.Fatalf("byte %d = %#x, want %#x", i, buf[i], want[i])
		}
	}

	ranges, err := vol.MapToImage(2040, 16)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(ranges) != 2 || ranges[0].ImageOffset != 2040 || ranges[0].Len != 8 || ranges[0].Kind != source.RangeData ||
		ranges[1].ImageOffset != 4096 || ranges[1].Len != 8 || ranges[1].Kind != source.RangeData {
		t.Fatalf("image ranges = %+v", ranges)
	}
	parentRanges, err := vol.Extents(2040, 16)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(parentRanges) != 2 {
		t.Fatalf("parent ranges = %+v", parentRanges)
	}
	if span := vol.SpanAt(2048); span == nil || span.PartitionID != 10 {
		t.Fatalf("SpanAt(2048) = %+v", span)
	}
	if span := vol.SpanAt(4096); span != nil {
		t.Fatalf("SpanAt past end = %+v", span)
	}
	if placement := vol.PlacementAt(2048); placement == nil || placement.PartitionID != 10 {
		t.Fatalf("PlacementAt(2048) = %+v", placement)
	}
	if placement := vol.PlacementAt(4096); placement != nil {
		t.Fatalf("PlacementAt past end = %+v", placement)
	}
	if vol.SectorSize() != uint32(SectorBytes) || vol.ImageID() != 0 || vol.IsEmpty() {
		t.Fatalf("ByteSource metadata is wrong")
	}
	if vol.Redundancy().Label() != "none" || vol.Redundancy().Degraded() {
		t.Fatalf("redundancy = %+v", vol.Redundancy())
	}
}

func TestGapBetweenExtentsIsRefused(t *testing.T) {
	extents := []Extent{spanExtent(9, 0, 4, 0), spanExtent(10, 8, 4, 4096)}
	_, err := openVolume(t, testVolume(extents, ptrU64(12), LayoutConcatenated))
	assertVolumeError(t, err, VolumeErrNotContiguous, "gap")
}

func TestOverlapBetweenExtentsIsRefused(t *testing.T) {
	extents := []Extent{spanExtent(9, 0, 4, 0), spanExtent(10, 2, 4, 4096)}
	_, err := openVolume(t, testVolume(extents, ptrU64(8), LayoutConcatenated))
	assertVolumeError(t, err, VolumeErrNotContiguous, "overlap")
}

func TestDeclaredSizeMismatchIsRefused(t *testing.T) {
	_, err := openVolume(t, testVolume(twoExtents(), ptrU64(9), LayoutConcatenated))
	assertVolumeError(t, err, VolumeErrSizeMismatch, "declares")
	if verr := asVolumeError(t, err); verr.Declared != 9*512 || verr.Assembled != 8*512 {
		t.Fatalf("error fields = %+v", verr)
	}

	vol, err := openVolume(t, testVolume(twoExtents(), nil, LayoutConcatenated))
	if err != nil || vol.Len() != 4096 {
		t.Fatalf("a record with no size must fall back to the extents: %v", err)
	}
}

func TestExtentPastTheImageIsRefused(t *testing.T) {
	extents := []Extent{spanExtent(9, 0, 4, 0), spanExtent(10, 4, 4, 7000)}
	_, err := openVolume(t, testVolume(extents, ptrU64(8), LayoutConcatenated))
	assertVolumeError(t, err, VolumeErrOutsideImage, "outside")
	if verr := asVolumeError(t, err); verr.PartitionID != 10 {
		t.Fatalf("partition id = %d", verr.PartitionID)
	}
}

func TestOnlyAContiguousConcatenatedVolumeOnThisDiskIsOpened(t *testing.T) {
	extents := twoExtents()
	extents[1].DiskName = ptrStr("Disk2")
	extents[1].OnThisDisk = false
	extents[1].Offset = nil
	_, err := openVolume(t, testVolume(extents, ptrU64(8), LayoutConcatenated))
	assertVolumeError(t, err, VolumeErrExtentOnOtherDisk, "Disk2")

	_, err = openVolume(t, testVolume(twoExtents(), ptrU64(8), LayoutStripe))
	assertVolumeError(t, err, VolumeErrUnsupportedLayout, "not assembled")

	_, err = openVolume(t, testVolume(twoExtents(), ptrU64(8), LayoutRaid5))
	assertVolumeError(t, err, VolumeErrUnsupportedLayout, "raid5")

	_, err = openVolume(t, testVolume(twoExtents(), ptrU64(8), LayoutMirrored))
	assertVolumeError(t, err, VolumeErrUnsupportedLayout, "mirrored")
}

func TestMissingBeginningEmptyExtentAndMissingOffsetAreRefused(t *testing.T) {
	extents := []Extent{spanExtent(9, 4, 4, 0), spanExtent(10, 8, 4, 4096)}
	_, err := openVolume(t, testVolume(extents, ptrU64(12), LayoutConcatenated))
	assertVolumeError(t, err, VolumeErrDoesNotStartAtZero, "")

	extents = twoExtents()
	extents[0].Sectors = 0
	extents[0].Len = 0
	_, err = openVolume(t, testVolume(extents, ptrU64(8), LayoutConcatenated))
	assertVolumeError(t, err, VolumeErrZeroLengthExtent, "")

	extents = twoExtents()
	extents[0].Offset = nil
	_, err = openVolume(t, testVolume(extents, ptrU64(8), LayoutConcatenated))
	assertVolumeError(t, err, VolumeErrMissingOffset, "")
}

// ---------------------------------------------------------------------------
// Multi-member assembly, exercised without the parser: the database below
// provides disk identity and geometry directly.
// ---------------------------------------------------------------------------

func emptyRegion() Region { return Region{} }

func makeDatabase(disks []Disk, volumes []Volume) *Database {
	var thisDisk *uint64
	if len(disks) > 0 {
		thisDisk = ptrU64(disks[0].ID)
	}
	return &Database{
		DiskGUID:       ptrStr("disk-owner"),
		DiskGroup:      ptrStr("Dg0"),
		Version:        Version{2, 12},
		BytesPerBlock:  uint32(volBlock),
		PublicRegion:   Region{StartLBA: volPublicBase, Sectors: 1024},
		PrivateRegion:  emptyRegion(),
		ConfigRegion:   emptyRegion(),
		Copy:           CopyHead,
		VMDBVersion:    Version{4, 10},
		UpdateStatus:   1,
		Clean:          true,
		ThisDiskID:     thisDisk,
		VolumeCount:    len(volumes),
		PartitionCount: countPartitions(disks),
		Groups: []Group{{
			Name:                 ptrStr("Dg0"),
			Disks:                disks,
			Volumes:              volumes,
			UnresolvedPartitions: nil,
		}},
	}
}

func countPartitions(disks []Disk) int {
	n := 0
	for _, disk := range disks {
		n += len(disk.Partitions)
	}
	return n
}

func makePartition(id, diskID, componentID uint64, column *uint64, volumeOffset, sectors uint64, stripeBlocks, columns *uint64, layout Layout) Partition {
	partition := Partition{
		ID:              id,
		DiskID:          diskID,
		ComponentID:     ptrU64(componentID),
		StartLBA:        0,
		VolumeOffset:    volumeOffset,
		SizeSectors:     sectors,
		Column:          column,
		StripeBlocks:    stripeBlocks,
		Columns:         columns,
		ChunkBlocks:     stripeBlocks,
		ComponentLayout: layout,
	}
	return partition
}

func makeDisk(id uint64, name, guid string, partitions []Partition) Disk {
	return Disk{ID: id, Name: ptrStr(name), GUID: ptrStr(guid), Partitions: partitions}
}

func markerSource(id source.ID, marker byte) source.ByteSource {
	data := make([]byte, 2*volColumnLen+volPublicBase*volBlock)
	for i := range data {
		data[i] = marker
	}
	return source.NewMemorySource(id, data)
}

func dataSource(id source.ID, data []byte) source.ByteSource {
	return source.NewMemorySource(id, data)
}

// shortSource advertises the wrapped source's full length but only serves the
// first limit bytes. It models a member whose declared geometry is intact but
// whose reads run short, which must never be zero-filled by the volume.
type shortSource struct {
	source.ByteSource
	limit int
}

func (s shortSource) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.shortRead(offset, buf, false)
}

func (s shortSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.shortRead(offset, buf, true)
}

func (s shortSource) shortRead(offset uint64, buf []byte, lossy bool) (int, error) {
	if offset >= uint64(s.limit) {
		return 0, nil
	}
	allowed := s.limit - int(offset)
	if allowed < len(buf) {
		buf = buf[:allowed]
	}
	if lossy {
		return s.ByteSource.ReadAtLossy(offset, buf)
	}
	return s.ByteSource.ReadAt(offset, buf)
}

func makeMember(sourceID source.ID, src source.ByteSource, diskID uint64, guid string, db *Database) DiskMember {
	_ = sourceID
	memberDB := *db
	memberDB.DiskGUID = ptrStr(guid)
	memberDB.ThisDiskID = ptrU64(diskID)
	return NewDiskMember(src, &memberDB)
}

func redundantEqual(a, b Redundancy) bool {
	if a.Kind != b.Kind || a.Copies != b.Copies || a.Readable != b.Readable || a.Chosen != b.Chosen ||
		a.Columns != b.Columns || a.DataColumns != b.DataColumns || len(a.Missing) != len(b.Missing) {
		return false
	}
	for i := range a.Missing {
		if a.Missing[i] != b.Missing[i] {
			return false
		}
	}
	return true
}

func columnPartitions(component uint64, layout Layout, columns uint64) []Partition {
	sectors := volColumnLen / volBlock
	out := make([]Partition, 0, columns)
	for column := uint64(0); column < columns; column++ {
		out = append(out, makePartition(
			100+column,
			10+column,
			component,
			ptrU64(column),
			0,
			sectors,
			ptrU64(volUnit/volBlock),
			ptrU64(columns),
			layout,
		))
	}
	return out
}

func stripeVolume(dataColumns uint64) *Volume {
	sectors := volColumnLen * dataColumns / volBlock
	return &Volume{
		ID:                 77,
		Name:               ptrStr("Stripe"),
		VolumeType:         ptrStr("gen"),
		State:              ptrStr("ACTIVE"),
		SizeSectors:        ptrU64(sectors),
		PartitionType:      func() *uint8 { v := uint8(0x07); return &v }(),
		DeclaredComponents: 1,
		ComponentIDs:       []uint64{50},
		Layout:             LayoutStripe,
		SpansDisks:         true,
	}
}

func raid5Volume() *Volume {
	volume := stripeVolume(2)
	volume.Name = ptrStr("Raid5")
	volume.Layout = LayoutRaid5
	return volume
}

func TestStripeVolumeInterleavesItsColumns(t *testing.T) {
	partitions := columnPartitions(50, LayoutStripe, 2)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{partitions[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{partitions[1]}),
	}
	volume := stripeVolume(2)
	db := makeDatabase(disks, []Volume{*volume})
	members := []DiskMember{
		makeMember(101, markerSource(101, 0xA1), 10, "guid-1", db),
		makeMember(102, markerSource(102, 0xB2), 11, "guid-2", db),
	}
	vol, err := AssembleVolume(9, db, volume, members)
	if err != nil {
		t.Fatalf("AssembleVolume: %v", err)
	}
	if vol.Len() != 2*volColumnLen {
		t.Fatalf("len = %d", vol.Len())
	}
	if len(vol.Placements()) != 2 {
		t.Fatalf("placements = %d", len(vol.Placements()))
	}
	if vol.Redundancy().Degraded() || vol.Redundancy().Kind != RedundancyNone {
		t.Fatalf("redundancy = %+v", vol.Redundancy())
	}

	buf := make([]byte, vol.Len())
	if n, err := vol.ReadAt(0, buf); err != nil || n != len(buf) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	for index := 0; index < len(buf); index += int(volUnit) {
		want := byte(0xA1)
		if (index/int(volUnit))%2 != 0 {
			want = 0xB2
		}
		for _, b := range buf[index : index+int(volUnit)] {
			if b != want {
				t.Fatalf("chunk at %d = %#x, want %#x", index, b, want)
			}
		}
	}
	placement := vol.PlacementAt(volUnit)
	if placement == nil || placement.Column == nil || *placement.Column != 1 {
		t.Fatalf("PlacementAt(unit) = %+v", placement)
	}
	if placement.DiskName == nil || *placement.DiskName != "Disk2" {
		t.Fatalf("placement disk name = %v", placement.DiskName)
	}

	_, err = AssembleVolume(9, db, volume, members[:1])
	assertVolumeError(t, err, VolumeErrMissingMember, "Disk2")
}

func TestMirrorReadsFirstCompleteCopyAndReportsLoss(t *testing.T) {
	fullSectors := volColumnLen / volBlock * 2
	partitionsA := []Partition{makePartition(200, 10, 60, nil, 0, fullSectors, nil, nil, LayoutConcatenated)}
	partitionsB := []Partition{makePartition(201, 11, 61, nil, 0, fullSectors, nil, nil, LayoutConcatenated)}
	volume := stripeVolume(0)
	volume.Name = ptrStr("Mirror")
	volume.Layout = LayoutMirrored
	volume.ComponentIDs = []uint64{60, 61}
	volume.SizeSectors = ptrU64(fullSectors)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", partitionsA),
		makeDisk(11, "Disk2", "guid-2", partitionsB),
	}
	db := makeDatabase(disks, []Volume{*volume})
	first := makeMember(101, markerSource(101, 0xA1), 10, "guid-1", db)
	second := makeMember(102, markerSource(102, 0xB2), 11, "guid-2", db)

	vol, err := AssembleVolume(9, db, volume, []DiskMember{first, second})
	if err != nil {
		t.Fatalf("AssembleVolume: %v", err)
	}
	wantRedundancy := Redundancy{Kind: RedundancyMirrored, Copies: 2, Readable: 2, Chosen: 0}
	if !redundantEqual(vol.Redundancy(), wantRedundancy) {
		t.Fatalf("redundancy = %+v, want %+v", vol.Redundancy(), wantRedundancy)
	}
	buf := make([]byte, vol.Len())
	if _, err := vol.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	for _, b := range buf {
		if b != 0xA1 {
			t.Fatalf("mirror read %#x, want the first copy", b)
		}
	}

	degraded, err := AssembleVolume(10, db, volume, []DiskMember{second})
	if err != nil {
		t.Fatalf("degraded AssembleVolume: %v", err)
	}
	wantRedundancy = Redundancy{Kind: RedundancyMirrored, Copies: 2, Readable: 1, Chosen: 1}
	if !redundantEqual(degraded.Redundancy(), wantRedundancy) || !degraded.Redundancy().Degraded() {
		t.Fatalf("degraded redundancy = %+v", degraded.Redundancy())
	}
	if degraded.Redundancy().Label() != "mirrored" {
		t.Fatalf("redundancy label = %q", degraded.Redundancy().Label())
	}
	buf = make([]byte, degraded.Len())
	if _, err := degraded.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	for _, b := range buf {
		if b != 0xB2 {
			t.Fatalf("degraded mirror read %#x, want the second copy", b)
		}
	}

	_, err = AssembleVolume(11, db, volume, nil)
	assertVolumeError(t, err, VolumeErrNoCompleteCopy, "Disk1")
	if !strings.Contains(err.Error(), "Disk2") {
		t.Fatalf("error does not name both disks: %v", err)
	}
}

// raid5ColumnImages writes, for every stripe, two deterministic data chunks and
// their XOR into the rotating parity column. Each image is one column.
func raid5ColumnImages(columns, dataColumns uint64, stripes int) [][]byte {
	unit := int(volUnit)
	prefix := int(volPublicBase * volBlock)
	images := make([][]byte, columns)
	for column := range images {
		images[column] = make([]byte, prefix+int(volColumnLen))
	}
	for stripe := 0; stripe < stripes; stripe++ {
		chunks := make([][]byte, dataColumns)
		for di := uint64(0); di < dataColumns; di++ {
			chunk := make([]byte, unit)
			for i := range chunk {
				chunk[i] = byte(0x10 + stripe*int(dataColumns) + int(di) + i*3)
			}
			chunks[di] = chunk
			column := dataColumn(uint64(stripe), di, columns)
			copy(images[column][prefix+stripe*unit:], chunk)
		}
		parity := make([]byte, unit)
		for di := uint64(1); di < dataColumns; di++ {
			for i := range parity {
				parity[i] ^= chunks[di][i]
			}
		}
		for i := range parity {
			parity[i] ^= chunks[0][i]
		}
		column := parityColumn(uint64(stripe), columns)
		copy(images[column][prefix+stripe*unit:], parity)
	}
	return images
}

// stripeMembers supplies a member image for each pair of disks in db.
func stripeMembers(db *Database) []DiskMember {
	return []DiskMember{
		makeMember(101, markerSource(101, 0xA1), 10, "guid-1", db),
		makeMember(102, markerSource(102, 0xB2), 11, "guid-2", db),
	}
}

func TestRAID5RebuildsOneMissingColumn(t *testing.T) {
	const columns = uint64(3)
	partitions := columnPartitions(50, LayoutRaid5, columns)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{partitions[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{partitions[1]}),
		makeDisk(12, "Disk3", "guid-3", []Partition{partitions[2]}),
	}
	volume := raid5Volume()
	db := makeDatabase(disks, []Volume{*volume})
	totalChunks := *volume.SizeSectors / (volUnit / volBlock)
	stripes := int(totalChunks / 2)
	images := raid5ColumnImages(columns, 2, stripes)
	members := make([]DiskMember, 0, columns)
	for column := uint64(0); column < columns; column++ {
		members = append(members, makeMember(
			source.ID(101+column),
			dataSource(source.ID(101+column), images[column]),
			10+column,
			"guid-"+string(rune('1'+column)),
			db,
		))
	}

	full, err := AssembleVolume(9, db, volume, members)
	if err != nil {
		t.Fatalf("AssembleVolume: %v", err)
	}
	if full.Len() != 2*volColumnLen {
		t.Fatalf("len = %d", full.Len())
	}
	wantRedundancy := Redundancy{Kind: RedundancyParity, Columns: 3, DataColumns: 2}
	if !redundantEqual(full.Redundancy(), wantRedundancy) {
		t.Fatalf("redundancy = %+v", full.Redundancy())
	}
	good := make([]byte, full.Len())
	if _, err := full.ReadAt(0, good); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	// Verify the logical interleave against the source patterns.
	for chunk := 0; chunk < len(good)/int(volUnit); chunk++ {
		stripe := chunk / 2
		di := chunk % 2
		for i := 0; i < int(volUnit); i++ {
			want := byte(0x10 + stripe*2 + di + i*3)
			if good[chunk*int(volUnit)+i] != want {
				t.Fatalf("full chunk %d byte %d = %#x, want %#x", chunk, i, good[chunk*int(volUnit)+i], want)
			}
		}
	}
	if ranges, err := full.MapToImage(0, volUnit); err != nil || len(ranges) != 1 || ranges[0].Kind != source.RangeData {
		t.Fatalf("full ranges = %+v, %v", ranges, err)
	}

	degraded, err := AssembleVolume(10, db, volume, members[1:])
	if err != nil {
		t.Fatalf("degraded AssembleVolume: %v", err)
	}
	wantRedundancy = Redundancy{Kind: RedundancyParity, Columns: 3, DataColumns: 2, Missing: []uint64{0}}
	if !redundantEqual(degraded.Redundancy(), wantRedundancy) || !degraded.Redundancy().Degraded() {
		t.Fatalf("degraded redundancy = %+v", degraded.Redundancy())
	}
	rebuilt := make([]byte, degraded.Len())
	if _, err := degraded.ReadAt(0, rebuilt); err != nil {
		t.Fatalf("Rebuilt ReadAt: %v", err)
	}
	for i := range good {
		if rebuilt[i] != good[i] {
			t.Fatalf("rebuilt byte %d = %#x, want %#x", i, rebuilt[i], good[i])
		}
	}
	if degraded.Redundancy().Label() != "parity" {
		t.Fatalf("redundancy label = %q", degraded.Redundancy().Label())
	}
	lossy := make([]byte, degraded.Len())
	if n, err := degraded.ReadAtLossy(0, lossy); err != nil || n != len(lossy) {
		t.Fatalf("ReadAtLossy = %d, %v", n, err)
	}
	for i := range good {
		if lossy[i] != good[i] {
			t.Fatalf("lossy rebuilt byte %d = %#x, want %#x", i, lossy[i], good[i])
		}
	}
	missingPlacement := degraded.PlacementAt(0)
	if missingPlacement == nil || missingPlacement.Column == nil || *missingPlacement.Column != 0 ||
		missingPlacement.Member != nil {
		t.Fatalf("missing-column placement = %+v", missingPlacement)
	}
	ranges, err := degraded.MapToImage(0, volUnit)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	foundDerived := false
	for _, r := range ranges {
		if r.Kind == source.RangeDerived {
			foundDerived = true
		}
	}
	if !foundDerived {
		t.Fatalf("rebuilt range is not Derived: %+v", ranges)
	}
	// The rebuilt chunk is not stored in any parent member.
	parentRanges, err := degraded.Extents(0, volUnit)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(parentRanges) != 1 || parentRanges[0].Kind != source.RangeDerived || parentRanges[0].Parent != degraded.SourceID() {
		t.Fatalf("parent ranges = %+v", parentRanges)
	}

	_, err = AssembleVolume(11, db, volume, members[2:])
	assertVolumeError(t, err, VolumeErrTooManyMissing, "only one")
}

func TestStripeWithoutGeometryIsRefused(t *testing.T) {
	partitions := []Partition{
		makePartition(1, 10, 50, ptrU64(0), 0, 8, nil, ptrU64(2), LayoutStripe),
		makePartition(2, 11, 50, ptrU64(1), 0, 8, nil, ptrU64(2), LayoutStripe),
	}
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{partitions[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{partitions[1]}),
	}
	volume := stripeVolume(2)
	volume.SizeSectors = ptrU64(8)
	db := makeDatabase(disks, []Volume{*volume})
	_, err := AssembleVolume(9, db, volume, nil)
	assertVolumeError(t, err, VolumeErrMissingStripeGeometry, "stripe unit")
}

func TestAmbiguousMemberIsRefused(t *testing.T) {
	partitions := columnPartitions(50, LayoutStripe, 2)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{partitions[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{partitions[1]}),
	}
	volume := stripeVolume(2)
	db := makeDatabase(disks, []Volume{*volume})
	duplicate := makeMember(101, markerSource(101, 0xA1), 10, "guid-1", db)
	second := makeMember(102, markerSource(102, 0xB2), 11, "guid-2", db)
	_, err := AssembleVolume(9, db, volume, []DiskMember{duplicate, duplicate, second})
	assertVolumeError(t, err, VolumeErrAmbiguousMember, "claim disk")
}

func TestUnknownLayoutIsRefused(t *testing.T) {
	volume := testVolume(twoExtents(), ptrU64(8), LayoutUnknown)
	_, err := AssembleVolume(9, makeDatabase(nil, nil), volume, nil)
	assertVolumeError(t, err, VolumeErrUnsupportedLayout, "unknown")
}

func TestConcatenatedAssemblyNamesAMissingMember(t *testing.T) {
	partitions := []Partition{
		makePartition(200, 10, 60, nil, 0, 16, nil, nil, LayoutConcatenated),
		makePartition(201, 11, 61, nil, 16, 16, nil, nil, LayoutConcatenated),
	}
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{partitions[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{partitions[1]}),
	}
	volume := &Volume{
		ID:                 78,
		Name:               ptrStr("Span"),
		SizeSectors:        ptrU64(32),
		ComponentIDs:       []uint64{60, 61},
		Layout:             LayoutConcatenated,
		DeclaredComponents: 2,
	}
	volume.Extents = []Extent{
		{PartitionID: 200, DiskID: 10, DiskName: ptrStr("Disk1"), OnThisDisk: true, StartLBA: 0, VolumeOffset: 0, Sectors: 16, Offset: ptrU64(volPublicBase * volBlock), Len: volColumnLen},
		{PartitionID: 201, DiskID: 11, DiskName: ptrStr("Disk2"), OnThisDisk: false, StartLBA: 0, VolumeOffset: 16, Sectors: 16, Len: volColumnLen},
	}
	db := makeDatabase(disks, []Volume{*volume})
	first := makeMember(101, markerSource(101, 0xA1), 10, "guid-1", db)
	vol, err := AssembleVolume(9, db, volume, []DiskMember{first})
	assertVolumeError(t, err, VolumeErrMissingMember, "Disk2")
	if !strings.Contains(err.Error(), "not among the supplied member images") {
		t.Fatalf("error = %v", err)
	}
	_ = vol

	both := makeMember(102, markerSource(102, 0xB2), 11, "guid-2", db)
	vol, err = AssembleVolume(9, db, volume, []DiskMember{first, both})
	if err != nil {
		t.Fatalf("AssembleVolume: %v", err)
	}
	if vol.Len() != 2*volColumnLen {
		t.Fatalf("len = %d", vol.Len())
	}
	if len(vol.Spans()) != 2 {
		t.Fatalf("spans = %+v", vol.Spans())
	}
	buf := make([]byte, vol.Len())
	if n, err := vol.ReadAt(0, buf); err != nil || n != len(buf) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	for i := 0; i < int(volColumnLen); i++ {
		if buf[i] != 0xA1 {
			t.Fatalf("byte %d in the first span = %#x", i, buf[i])
		}
		if buf[int(volColumnLen)+i] != 0xB2 {
			t.Fatalf("byte %d in the second span = %#x", i, buf[int(volColumnLen)+i])
		}
	}
	span := vol.SpanAt(volColumnLen)
	if span == nil || span.PartitionID != 201 || span.ImageOffset != volPublicBase*volBlock {
		t.Fatalf("second span = %+v", span)
	}
	placement := vol.PlacementAt(volColumnLen)
	if placement == nil || placement.DiskID != 11 || placement.Member == nil || *placement.Member != 1 {
		t.Fatalf("second placement = %+v", placement)
	}
	ranges, err := vol.Extents(volColumnLen-8, 16)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 2 || ranges[0].Parent != source.ID(101) || ranges[1].Parent != source.ID(102) {
		t.Fatalf("parent ranges = %+v", ranges)
	}
}

func TestConcatenatedAssemblyRefusesAMissingPartitionRecord(t *testing.T) {
	volume := &Volume{
		ID:           79,
		Name:         ptrStr("Ghost"),
		SizeSectors:  ptrU64(8),
		ComponentIDs: []uint64{60},
		Layout:       LayoutConcatenated,
		Extents: []Extent{{
			PartitionID: 999, DiskID: 10, DiskName: ptrStr("Disk1"), OnThisDisk: true,
			VolumeOffset: 0, Sectors: 16, StartLBA: 0, Offset: ptrU64(volPublicBase * volBlock), Len: volColumnLen,
		}},
	}
	db := makeDatabase([]Disk{makeDisk(10, "Disk1", "guid-1", nil)}, []Volume{*volume})
	member := makeMember(101, markerSource(101, 0xA1), 10, "guid-1", db)
	_, err := AssembleVolume(9, db, volume, []DiskMember{member})
	assertVolumeError(t, err, VolumeErrMissingPartition, "")
}

func TestConcatenatedAssemblyNoExtentsAndZeroLength(t *testing.T) {
	volume := testVolume(nil, ptrU64(8), LayoutConcatenated)
	db := makeDatabase(nil, []Volume{*volume})
	_, err := AssembleVolume(9, db, volume, nil)
	assertVolumeError(t, err, VolumeErrNoExtents, "")

	extent := spanExtent(9, 0, 0, 0)
	volume = testVolume([]Extent{extent}, ptrU64(0), LayoutConcatenated)
	db = makeDatabase(nil, []Volume{*volume})
	_, err = AssembleVolume(9, db, volume, nil)
	assertVolumeError(t, err, VolumeErrZeroLengthExtent, "")
}

func TestStripeRefusesMissingAndInvalidColumns(t *testing.T) {
	base := columnPartitions(50, LayoutStripe, 2)
	setup := func(parts []Partition) (*Database, *Volume) {
		disks := []Disk{
			makeDisk(10, "Disk1", "guid-1", []Partition{parts[0]}),
			makeDisk(11, "Disk2", "guid-2", []Partition{parts[1]}),
		}
		volume := stripeVolume(2)
		return makeDatabase(disks, []Volume{*volume}), volume
	}

	missingColumn := append([]Partition(nil), base...)
	missingColumn[0].Column = nil
	db, volume := setup(missingColumn)
	_, err := AssembleVolume(9, db, volume, stripeMembers(db))
	assertVolumeError(t, err, VolumeErrMissingColumn, "")

	duplicate := append([]Partition(nil), base...)
	duplicate[1].Column = ptrU64(0)
	db, volume = setup(duplicate)
	_, err = AssembleVolume(9, db, volume, stripeMembers(db))
	assertVolumeError(t, err, VolumeErrDuplicateColumn, "column 0")

	outOfRange := append([]Partition(nil), base...)
	outOfRange[1].Column = ptrU64(2)
	db, volume = setup(outOfRange)
	_, err = AssembleVolume(9, db, volume, stripeMembers(db))
	assertVolumeError(t, err, VolumeErrColumnOutOfRange, "only 2")

	countMismatch := append([]Partition(nil), base...)
	countMismatch = append(countMismatch, makePartition(999, 12, 50, ptrU64(2), 0, volColumnLen/volBlock, ptrU64(2), ptrU64(3), LayoutStripe))
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{countMismatch[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{countMismatch[1]}),
		makeDisk(12, "Disk3", "guid-3", []Partition{countMismatch[2]}),
	}
	volume = stripeVolume(2)
	volume.ComponentIDs = []uint64{50}
	db = makeDatabase(disks, []Volume{*volume})
	_, err = AssembleVolume(9, db, volume, stripeMembers(db))
	assertVolumeError(t, err, VolumeErrColumnCountMismatch, "3 partition")
}

func TestStripeUnitMismatchAndUnequalColumns(t *testing.T) {
	parts := columnPartitions(50, LayoutStripe, 2)
	parts[0].ChunkBlocks = ptrU64(4)
	parts[1].ChunkBlocks = ptrU64(4)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{parts[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{parts[1]}),
	}
	volume := stripeVolume(2)
	db := makeDatabase(disks, []Volume{*volume})
	_, err := AssembleVolume(9, db, volume, stripeMembers(db))
	assertVolumeError(t, err, VolumeErrStripeUnitMismatch, "refusing to choose")

	parts = columnPartitions(50, LayoutStripe, 2)
	parts[1].SizeSectors++
	disks = []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{parts[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{parts[1]}),
	}
	db = makeDatabase(disks, []Volume{*volume})
	_, err = AssembleVolume(9, db, volume, stripeMembers(db))
	assertVolumeError(t, err, VolumeErrUnequalColumns, "unequal")
}

func TestStripeRefusesMissingComponentAndMultipleComponents(t *testing.T) {
	volume := stripeVolume(2)
	volume.ComponentIDs = nil
	db := makeDatabase(nil, []Volume{*volume})
	_, err := AssembleVolume(9, db, volume, nil)
	assertVolumeError(t, err, VolumeErrMissingComponent, "")

	parts := columnPartitions(50, LayoutStripe, 2)
	also := makePartition(300, 14, 51, ptrU64(0), 0, volColumnLen/volBlock, ptrU64(2), ptrU64(2), LayoutStripe)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{parts[0], also}),
		makeDisk(11, "Disk2", "guid-2", []Partition{parts[1]}),
	}
	volume = stripeVolume(2)
	volume.ComponentIDs = []uint64{50, 51}
	db = makeDatabase(disks, []Volume{*volume})
	_, err = AssembleVolume(9, db, volume, nil)
	assertVolumeError(t, err, VolumeErrMultipleComponents, "only one")
}

func TestMirrorRefusesANonConcatenatedCopy(t *testing.T) {
	partitionsA := []Partition{makePartition(200, 10, 60, nil, 0, 32, nil, nil, LayoutStripe)}
	partitionsB := []Partition{makePartition(201, 11, 61, nil, 0, 32, nil, nil, LayoutConcatenated)}
	volume := stripeVolume(0)
	volume.Layout = LayoutMirrored
	volume.ComponentIDs = []uint64{60, 61}
	volume.SizeSectors = ptrU64(32)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", partitionsA),
		makeDisk(11, "Disk2", "guid-2", partitionsB),
	}
	db := makeDatabase(disks, []Volume{*volume})
	_, err := AssembleVolume(9, db, volume, nil)
	assertVolumeError(t, err, VolumeErrUnsupportedComponentLayout, "only a concatenated")
}

func TestMirrorWithNoComponentsIsRefused(t *testing.T) {
	volume := stripeVolume(0)
	volume.Layout = LayoutMirrored
	volume.ComponentIDs = nil
	volume.SizeSectors = ptrU64(32)
	db := makeDatabase(nil, []Volume{*volume})
	_, err := AssembleVolume(9, db, volume, nil)
	assertVolumeError(t, err, VolumeErrMissingComponent, "")
}

func TestEmptyVolumeIsRefused(t *testing.T) {
	partitionsA := []Partition{makePartition(200, 10, 60, nil, 0, 0, nil, nil, LayoutConcatenated)}
	partitionsB := []Partition{makePartition(201, 11, 61, nil, 0, 0, nil, nil, LayoutConcatenated)}
	volume := stripeVolume(0)
	volume.Layout = LayoutMirrored
	volume.ComponentIDs = []uint64{60, 61}
	volume.SizeSectors = ptrU64(0)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", partitionsA),
		makeDisk(11, "Disk2", "guid-2", partitionsB),
	}
	db := makeDatabase(disks, []Volume{*volume})
	first := makeMember(101, markerSource(101, 0xA1), 10, "guid-1", db)
	_, err := AssembleVolume(9, db, volume, []DiskMember{first})
	assertVolumeError(t, err, VolumeErrEmptyVolume, "no length")
}

func TestInconsistentMemberBlockSizeIsRefused(t *testing.T) {
	partitions := []Partition{makePartition(200, 10, 60, nil, 0, 16, nil, nil, LayoutConcatenated)}
	volume := &Volume{
		ID:           80,
		Name:         ptrStr("BlockSize"),
		SizeSectors:  ptrU64(16),
		ComponentIDs: []uint64{60},
		Layout:       LayoutConcatenated,
		Extents: []Extent{{
			PartitionID: 200, DiskID: 10, DiskName: ptrStr("Disk1"), OnThisDisk: true,
			StartLBA: 0, VolumeOffset: 0, Sectors: 16, Offset: ptrU64(volPublicBase * volBlock), Len: volColumnLen,
		}},
	}
	disks := []Disk{makeDisk(10, "Disk1", "guid-1", partitions)}
	db := makeDatabase(disks, []Volume{*volume})
	member := makeMember(101, markerSource(101, 0xA1), 10, "guid-1", db)
	member.Database.BytesPerBlock = 4096
	_, err := AssembleVolume(9, db, volume, []DiskMember{member})
	assertVolumeError(t, err, VolumeErrInconsistentBlockSize, "4096-byte blocks")
	if verr := asVolumeError(t, err); verr.ExpectedBlock != 512 || verr.FoundBlock != 4096 {
		t.Fatalf("error fields = %+v", verr)
	}
}

func TestMemberExtentPastItsImageIsRefused(t *testing.T) {
	partitions := []Partition{makePartition(200, 10, 60, nil, 0, 16, nil, nil, LayoutConcatenated)}
	volume := &Volume{
		ID:           81,
		Name:         ptrStr("Outside"),
		SizeSectors:  ptrU64(16),
		ComponentIDs: []uint64{60},
		Layout:       LayoutConcatenated,
		Extents: []Extent{{
			PartitionID: 200, DiskID: 10, DiskName: ptrStr("Disk1"), OnThisDisk: true,
			StartLBA: 0, VolumeOffset: 0, Sectors: 16, Offset: ptrU64(volPublicBase * volBlock), Len: volColumnLen,
		}},
	}
	disks := []Disk{makeDisk(10, "Disk1", "guid-1", partitions)}
	db := makeDatabase(disks, []Volume{*volume})
	short := NewDiskMember(source.NewMemorySource(101, make([]byte, 4096)), func() *Database {
		copyDB := *db
		copyDB.DiskGUID = ptrStr("guid-1")
		copyDB.ThisDiskID = ptrU64(10)
		return &copyDB
	}())
	_, err := AssembleVolume(9, db, volume, []DiskMember{short})
	assertVolumeError(t, err, VolumeErrOutsideImage, "outside")
}

func TestRAID5NeedsAtLeastTwoColumns(t *testing.T) {
	partitions := columnPartitions(50, LayoutRaid5, 1)
	disks := []Disk{makeDisk(10, "Disk1", "guid-1", partitions)}
	volume := raid5Volume()
	volume.ComponentIDs = []uint64{50}
	db := makeDatabase(disks, []Volume{*volume})
	_, err := AssembleVolume(9, db, volume, nil)
	assertVolumeError(t, err, VolumeErrMissingColumnCount, "")
}

func TestShortReadsAreNeverZeroFilled(t *testing.T) {
	parent := shortSource{ByteSource: patternSource(1), limit: 4}
	vol, err := OpenVolume(2, parent, testVolume(twoExtents(), ptrU64(8), LayoutConcatenated))
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}

	for _, lossy := range []bool{false, true} {
		buf := make([]byte, 16)
		for i := range buf {
			buf[i] = 0xEE
		}
		var n int
		if lossy {
			n, err = vol.ReadAtLossy(0, buf)
		} else {
			n, err = vol.ReadAt(0, buf)
		}
		if err != nil {
			t.Fatalf("short read returned an error: %v", err)
		}
		if n != 4 {
			t.Fatalf("short read = %d, want 4", n)
		}
		for i := 0; i < n; i++ {
			if buf[i] != patternByte(i) {
				t.Fatalf("byte %d = %#x, want %#x", i, buf[i], patternByte(i))
			}
		}
		for i := n; i < len(buf); i++ {
			if buf[i] != 0xEE {
				t.Fatalf("byte %d was filled with %#x instead of being left short", i, buf[i])
			}
		}
	}
	if n, err := vol.ReadAt(10, make([]byte, 4)); err != nil || n != 0 {
		t.Fatalf("read past the short limit = %d, %v", n, err)
	}
	if vol.Stats().Reads == 0 {
		t.Fatal("read counters were not updated")
	}
}

func TestRAID5ShortMemberIsRefused(t *testing.T) {
	const columns = uint64(3)
	partitions := columnPartitions(50, LayoutRaid5, columns)
	disks := []Disk{
		makeDisk(10, "Disk1", "guid-1", []Partition{partitions[0]}),
		makeDisk(11, "Disk2", "guid-2", []Partition{partitions[1]}),
		makeDisk(12, "Disk3", "guid-3", []Partition{partitions[2]}),
	}
	volume := raid5Volume()
	db := makeDatabase(disks, []Volume{*volume})
	stripes := int(*volume.SizeSectors / (volUnit / volBlock) / 2)
	images := raid5ColumnImages(columns, 2, stripes)
	members := make([]DiskMember, 0, columns)
	for column := uint64(0); column < columns; column++ {
		members = append(members, makeMember(
			source.ID(101+column),
			dataSource(source.ID(101+column), images[column]),
			10+column,
			"guid-"+string(rune('1'+column)),
			db,
		))
	}
	// Column 0 is missing; both survivors advertise a full image but run short.
	survivors := []DiskMember{members[1], members[2]}
	for i := range survivors {
		survivors[i].Source = shortSource{ByteSource: survivors[i].Source, limit: 1}
	}
	degraded, err := AssembleVolume(10, db, volume, survivors)
	if err != nil {
		t.Fatalf("AssembleVolume: %v", err)
	}
	_, err = degraded.ReadAt(0, make([]byte, 64))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "refusing to invent") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "Disk2") && !strings.Contains(err.Error(), "Disk3") {
		t.Fatalf("error does not name the short member: %v", err)
	}
}

func TestVolumeErrorMessageForEveryKind(t *testing.T) {
	name := "Disk1"
	errs := []*VolumeError{
		{Kind: VolumeErrUnsupportedLayout, Layout: "stripe", Extents: 2},
		{Kind: VolumeErrNoExtents},
		{Kind: VolumeErrExtentOnOtherDisk, PartitionID: 1, DiskName: &name},
		{Kind: VolumeErrMissingOffset, PartitionID: 1},
		{Kind: VolumeErrZeroLengthExtent, PartitionID: 1},
		{Kind: VolumeErrDoesNotStartAtZero, Found: 512},
		{Kind: VolumeErrNotContiguous, Expected: 512, Found: 1024},
		{Kind: VolumeErrSizeMismatch, Declared: 10, Assembled: 8},
		{Kind: VolumeErrOutsideImage, PartitionID: 1, Offset: 0, Len: 9, ImageLen: 8},
		{Kind: VolumeErrOverflow, What: "length"},
		{Kind: VolumeErrMissingMember, PartitionID: 1, DiskID: 2, DiskName: &name},
		{Kind: VolumeErrAmbiguousMember, DiskID: 2, DiskName: &name, Candidates: 2},
		{Kind: VolumeErrInconsistentBlockSize, Member: "`Disk1`", ExpectedBlock: 512, FoundBlock: 4096},
		{Kind: VolumeErrMissingPartition, PartitionID: 1},
		{Kind: VolumeErrMissingComponent, ComponentID: 1},
		{Kind: VolumeErrMultipleComponents, Layout: "stripe", Components: 2},
		{Kind: VolumeErrMissingStripeGeometry, ComponentID: 1},
		{Kind: VolumeErrMissingColumnCount, ComponentID: 1},
		{Kind: VolumeErrMissingColumn, PartitionID: 1},
		{Kind: VolumeErrDuplicateColumn, Column: 1},
		{Kind: VolumeErrColumnOutOfRange, Column: 2, Columns: 2},
		{Kind: VolumeErrColumnCountMismatch, Columns: 2, Components: 3},
		{Kind: VolumeErrStripeUnitMismatch, ComponentID: 1, Expected: 2, Found: 4},
		{Kind: VolumeErrUnequalColumns, Expected: 8, Found: 4},
		{Kind: VolumeErrColumnTooShort, Column: 1, Expected: 8, Found: 4},
		{Kind: VolumeErrEmptyVolume},
		{Kind: VolumeErrTooManyMissing, Columns: 3, MissingColumns: []uint64{0, 1}},
		{Kind: VolumeErrNoCompleteCopy, Copies: 2, Readable: 0, Missing: []string{"Disk1", "Disk2"}},
		{Kind: VolumeErrUnsupportedComponentLayout, ComponentID: 1, Layout: "stripe"},
	}
	for _, err := range errs {
		if message := err.Error(); message == "" {
			t.Fatalf("kind %d has an empty message", err.Kind)
		}
	}
}

func TestReadAtBoundsAndEmptyBuffer(t *testing.T) {
	vol, err := openVolume(t, testVolume(twoExtents(), ptrU64(8), LayoutConcatenated))
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	if n, err := vol.ReadAt(4096, make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) || n != 0 {
		t.Fatalf("read past end = %d, %v", n, err)
	}
	if n, err := vol.ReadAt(0, nil); err != nil || n != 0 {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if _, err := vol.Extents(0, 4097); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extents past end = %v", err)
	}
	if _, err := vol.MapToImage(4096, 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("map past end = %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func assertVolumeError(t *testing.T, err error, kind VolumeErrorKind, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected VolumeError kind %d, got nil", kind)
	}
	var verr *VolumeError
	if !errors.As(err, &verr) {
		t.Fatalf("error %v is not a *VolumeError", err)
	}
	if verr.Kind != kind {
		t.Fatalf("kind = %d, want %d (%v)", verr.Kind, kind, err)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not contain %q", err.Error(), contains)
	}
}

func asVolumeError(t *testing.T, err error) *VolumeError {
	t.Helper()
	var verr *VolumeError
	if !errors.As(err, &verr) {
		t.Fatalf("error %v is not a *VolumeError", err)
	}
	return verr
}
