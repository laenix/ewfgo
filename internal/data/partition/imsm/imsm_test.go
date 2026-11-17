package imsm

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const testSector = 512

type diskSpec struct {
	serial string
	status uint32
	total  uint64
}

type volSpec struct {
	name      string
	level     uint8
	members   uint8
	bps       uint16
	nds       uint64
	pba       uint64
	size      uint64
	ords      []uint32
	migrState uint8
	mapState  uint8
	dirty     uint8
}

func componentSectors(spec *volSpec) uint64 {
	factor := uint64(1)
	if spec.level == 1 || spec.level == 10 {
		factor = 2
	}
	return spec.nds * uint64(spec.bps) * factor
}

func dataMembersSectors(spec *volSpec) uint64 {
	switch spec.level {
	case 0:
		return uint64(spec.members)
	case 1, 10:
		return uint64(spec.members) / 2
	case 5:
		return uint64(spec.members) - 1
	default:
		return uint64(spec.members)
	}
}

func newVolSpec(name string, level, members uint8, bps uint16, nds, pba uint64) volSpec {
	spec := volSpec{
		name:    name,
		level:   level,
		members: members,
		bps:     bps,
		nds:     nds,
		pba:     pba,
		ords:    make([]uint32, members),
	}
	for i := range spec.ords {
		spec.ords[i] = uint32(i)
	}
	spec.size = componentSectors(&spec) * dataMembersSectors(&spec)
	return spec
}

func configuredDisk(serial string, total uint64) diskSpec {
	return diskSpec{serial: serial, status: DiskFlagConfigured, total: total}
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

func buildMPB(disks []diskSpec, volumes []volSpec) []byte {
	buf := make([]byte, 32*1024)
	copy(buf, MPBSignature)
	copy(buf[MPBSigLen:0x20], []byte("1.3.00\x00\x00"))
	putU32(buf, 0x28, 0x11112222)
	putU32(buf, 0x2C, 7)
	putU32(buf, 0x34, Attr2TBDisk)
	buf[0x38] = byte(len(disks))
	buf[0x39] = byte(len(volumes))
	putU32(buf, 0x40, 0x11112222)
	putU64(buf, 0x50, 1_600_000_000_000_000)

	offset := int(DiskTableOffset)
	for index, disk := range disks {
		base := offset + int(DiskBytes)*index
		copy(buf[base:base+16], []byte(disk.serial))
		putU32(buf, base+0x10, uint32(disk.total))
		putU32(buf, base+0x14, uint32(index))
		putU32(buf, base+0x18, disk.status)
		putU32(buf, base+0x1C, 0x11112222)
	}
	offset += int(DiskBytes) * len(disks)

	for _, volume := range volumes {
		base := offset
		copy(buf[base:base+16], []byte(volume.name))
		putU32(buf, base+0x10, uint32(volume.size))
		buf[base+0x21] = 1
		buf[base+0x32] = 0
		buf[base+0x58] = volume.migrState
		buf[base+0x5A] = volume.dirty
		m := base + int(DevMapOffset)
		putU32(buf, m, uint32(volume.pba))
		putU32(buf, m+4, uint32(volume.nds*uint64(volume.bps)))
		putU32(buf, m+8, uint32(volume.nds))
		putU16(buf, m+0x0C, volume.bps)
		buf[m+0x0E] = volume.mapState
		buf[m+0x0F] = volume.level
		buf[m+0x10] = volume.members
		if volume.level == 1 || volume.level == 10 {
			buf[m+0x11] = 2
		} else {
			buf[m+0x11] = 1
		}
		buf[m+0x12] = 0xFF
		for slot, ord := range volume.ords {
			putU32(buf, m+int(MapOrdOffset)+4*slot, ord)
		}
		offset = base + int(DevBaseBytes) + 4*(int(volume.members)-1)
	}

	putU32(buf, 0x24, uint32(offset))
	fixChecksum(buf)
	return buf
}

func fixChecksum(buf []byte) {
	mpbSize := int(le32(buf, 0x24))
	for i := 0x20; i < 0x24; i++ {
		buf[i] = 0
	}
	var sum uint32
	for at := 0; at+4 <= mpbSize/4*4; at += 4 {
		sum += le32(buf, at)
	}
	putU32(buf, 0x20, sum)
}

type dataChunk struct {
	offset uint64
	bytes  []byte
}

func image(totalUnits, sector uint64, mpb []byte, data []dataChunk) []byte {
	length := totalUnits * sector
	bytes := make([]byte, length)
	mpbSize := uint64(le32(mpb, 0x24))
	sectors := (mpbSize + sector - 1) / sector
	span := (sectors + 1) * sector
	if length < span {
		panic("test image too small for its MPB")
	}
	anchor := length - 2*sector
	copy(bytes[anchor:anchor+sector], mpb[:sector])
	if sectors > 1 {
		start := length - span
		copy(bytes[start:start+(sectors-1)*sector], mpb[sector:sectors*sector])
	}
	for _, chunk := range data {
		copy(bytes[chunk.offset:], chunk.bytes)
	}
	return bytes
}

func memorySource(id source.ID, bytes []byte) source.ByteSource {
	return source.NewMemorySource(id, bytes)
}

func parseBytes(t *testing.T, bytes []byte) *Container {
	t.Helper()
	container, err := Parse(memorySource(1, bytes))
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if container == nil {
		t.Fatal("Parse returned nil container")
	}
	return container
}

func pattern(length int, seed byte) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte((i*7 + int(seed)*13) % 251)
	}
	return out
}

func arrayChunk(data []byte, index, chunk uint64) []byte {
	return data[index*chunk : (index+1)*chunk]
}

func fillRaid0(member []byte, sector, pba, chunk, slot, members uint64, data []byte) {
	chunks := uint64(len(data)) / chunk
	for index := uint64(0); index < chunks; index++ {
		if index%members == slot {
			at := pba*sector + (index/members)*chunk
			copy(member[at:at+chunk], arrayChunk(data, index, chunk))
		}
	}
}

func fillRaid10(member []byte, sector, pba, chunk, slot, members uint64, data []byte) {
	chunks := uint64(len(data)) / chunk
	for index := uint64(0); index < chunks; index++ {
		for copyIndex := uint64(0); copyIndex < 2; copyIndex++ {
			virtual := index*2 + copyIndex
			if virtual%members == slot {
				at := pba*sector + (virtual/members)*chunk
				copy(member[at:at+chunk], arrayChunk(data, index, chunk))
			}
		}
	}
}

func readAll(t *testing.T, array *ArraySource) []byte {
	t.Helper()
	out := make([]byte, array.Len())
	n, err := array.ReadAt(0, out)
	if err != nil {
		t.Fatalf("array read error = %v", err)
	}
	if n != len(out) {
		t.Fatalf("array read = %d of %d bytes", n, len(out))
	}
	return out
}

func hexUUID(bytes []byte) string {
	out := ""
	for index := 0; index+4 <= len(bytes); index += 4 {
		if index > 0 {
			out += ":"
		}
		out += hex.EncodeToString(bytes[index : index+4])
	}
	return out
}

func TestParsesContainerAndFields(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2075, testSector, mpb, nil))

	if container.SectorSize != 512 {
		t.Fatalf("sector size = %d", container.SectorSize)
	}
	if container.Version != "1.3.00" {
		t.Fatalf("version = %q", container.Version)
	}
	if container.FamilyNum != 0x11112222 || container.OrigFamilyNum != 0x11112222 {
		t.Fatalf("family = %#x/%#x", container.FamilyNum, container.OrigFamilyNum)
	}
	if container.GenerationNum != 7 {
		t.Fatalf("generation = %d", container.GenerationNum)
	}
	if container.CreationTime != 1_600_000_000_000_000 {
		t.Fatalf("creation time = %d", container.CreationTime)
	}
	if container.MPBOffset != 2075*512-1024 {
		t.Fatalf("mpb offset = %d", container.MPBOffset)
	}
	if len(container.Disks) != 2 || container.Disks[0].Serial != "DISK-A" ||
		container.Disks[0].TotalBlocks != 2075 || !container.Disks[0].Configured() ||
		container.Disks[0].Failed() || container.Disks[1].Serial != "DISK-B" {
		t.Fatalf("disks = %+v", container.Disks)
	}
	if len(container.Volumes) != 1 {
		t.Fatalf("volumes = %d", len(container.Volumes))
	}
	parsed := &container.Volumes[0]
	if parsed.Name != "Volume0" || parsed.Map.Level() != LevelRaid0 {
		t.Fatalf("volume = %+v", parsed)
	}
	if parsed.Map.NumMembers != 2 || parsed.Map.BlocksPerStrip != 8 || parsed.Map.NumDataStripes != 2 {
		t.Fatalf("map = %+v", parsed.Map)
	}
	if parsed.Map.ChunkBytes(512) != 4096 {
		t.Fatalf("chunk = %d", parsed.Map.ChunkBytes(512))
	}
	if parsed.Map.DataOffsetBytes(512) != 2048*512 {
		t.Fatalf("data offset = %d", parsed.Map.DataOffsetBytes(512))
	}
	if got, ok := parsed.Map.ComponentBytes(512); !ok || got != 8192 {
		t.Fatalf("component = %d ok=%v", got, ok)
	}
	if parsed.SizeBlocks != 32 || parsed.SizeBytes(512) != 16384 {
		t.Fatalf("size = %d/%d", parsed.SizeBlocks, parsed.SizeBytes(512))
	}
	if disk, ok := parsed.Map.SlotDisk(0); !ok || disk != 0 {
		t.Fatalf("slot 0 = %d ok=%v", disk, ok)
	}
	if disk, ok := parsed.Map.SlotDisk(1); !ok || disk != 1 {
		t.Fatalf("slot 1 = %d ok=%v", disk, ok)
	}
	if slot, ok := parsed.Map.DiskSlot(1); !ok || slot != 1 {
		t.Fatalf("disk 1 slot = %d ok=%v", slot, ok)
	}

	uuid := container.ContainerUUID()
	if len(uuid) != 35 {
		t.Fatalf("container uuid = %q", uuid)
	}
	volumeUUID, ok := container.VolumeUUID(0)
	if !ok || len(volumeUUID) != 35 {
		t.Fatalf("volume uuid = %q ok=%v", volumeUUID, ok)
	}
	if _, ok := container.VolumeUUID(1); ok {
		t.Fatal("volume 1 UUID unexpectedly exists")
	}
	input := append([]byte(MPBSignature), 0x22, 0x22, 0x11, 0x11)
	sum := sha1.Sum(input)
	if container.ContainerUUID() != hexUUID(sum[:16]) {
		t.Fatalf("container uuid %q does not match mdadm's formula", uuid)
	}
	if container.MetadataSpanBytes() != 1024 {
		t.Fatalf("metadata span = %d", container.MetadataSpanBytes())
	}
}

func TestShortOrZeroedSourceIsNotIMSM(t *testing.T) {
	for _, bytes := range [][]byte{make([]byte, 512), make([]byte, 16*1024)} {
		container, err := Parse(memorySource(1, bytes))
		if err != nil || container != nil {
			t.Fatalf("Parse(%d bytes) = %v, %v", len(bytes), container, err)
		}
	}
}

func TestParses4KSectorMetadata(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 256)
	disks := []diskSpec{configuredDisk("DISK-A", 278), configuredDisk("DISK-B", 279)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(278, 4096, mpb, nil))

	if container.SectorSize != 4096 {
		t.Fatalf("sector size = %d", container.SectorSize)
	}
	if container.Volumes[0].Map.ChunkBytes(4096) != 32768 {
		t.Fatalf("chunk = %d", container.Volumes[0].Map.ChunkBytes(4096))
	}
	if got, ok := container.Volumes[0].Map.ComponentBytes(4096); !ok || got != 65536 {
		t.Fatalf("component = %d ok=%v", got, ok)
	}
	if disk, err := container.BindDisk(278 * 4096); err != nil || disk != 0 {
		t.Fatalf("bind 278 = %d, %v", disk, err)
	}
	if disk, err := container.BindDisk(279 * 4096); err != nil || disk != 1 {
		t.Fatalf("bind 279 = %d, %v", disk, err)
	}
}

func TestRefusesAmbiguousSectorSize(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 256)
	disks := []diskSpec{configuredDisk("DISK-A", 278), configuredDisk("DISK-B", 279)}
	mpb := buildMPB(disks, []volSpec{volume})
	bytes := image(16, 4096, mpb, nil)
	length := len(bytes)
	copy(bytes[length-2*512:length-512], mpb[:512])

	container, err := Parse(memorySource(1, bytes))
	if err == nil || container != nil {
		t.Fatalf("Parse = %v, %v; want ambiguity error", container, err)
	}
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("error = %v", err)
	}
}

func TestReassemblesRotatedMultiSectorMPB(t *testing.T) {
	volumes := []volSpec{
		newVolSpec("Volume0", 0, 2, 8, 2, 2048),
		newVolSpec("Volume1", 1, 2, 8, 1, 2048),
	}
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, volumes)
	mpbSize := le32(mpb, 0x24)
	if mpbSize <= uint32(testSector) {
		t.Fatalf("fixture must span more than one sector, it is %d bytes", mpbSize)
	}

	container := parseBytes(t, image(2075, testSector, mpb, nil))
	if container.SectorSize != 512 || container.MPBSize != mpbSize {
		t.Fatalf("sector/mpb size = %d/%d", container.SectorSize, container.MPBSize)
	}
	if len(container.Volumes) != 2 {
		t.Fatalf("volumes = %d", len(container.Volumes))
	}
	if container.Volumes[0].Name != "Volume0" || container.Volumes[0].Map.Level() != LevelRaid0 {
		t.Fatalf("volume 0 = %+v", container.Volumes[0])
	}
	if container.Volumes[1].Name != "Volume1" || container.Volumes[1].Map.Level() != LevelRaid1 {
		t.Fatalf("volume 1 = %+v", container.Volumes[1])
	}
}

func TestAssemblesRaid0FromCrossedSlots(t *testing.T) {
	const chunk = uint64(4096)
	data := pattern(int(4*chunk), 3)
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	// Slot 0 is disk 1, slot 1 is disk 0.
	m := int(DiskTableOffset) + int(DiskBytes)*2 + int(DevMapOffset)
	putU32(mpb, m+int(MapOrdOffset), 1)
	putU32(mpb, m+int(MapOrdOffset)+4, 0)
	fixChecksum(mpb)

	container := parseBytes(t, image(2075, testSector, mpb, nil))
	if disk, _ := container.Volumes[0].Map.SlotDisk(0); disk != 1 {
		t.Fatalf("slot 0 disk = %d", disk)
	}
	if disk, _ := container.Volumes[0].Map.SlotDisk(1); disk != 0 {
		t.Fatalf("slot 1 disk = %d", disk)
	}

	disk0 := image(2075, testSector, mpb, nil)
	disk1 := image(2068, testSector, mpb, nil)
	fillRaid0(disk0, testSector, 2048, chunk, 1, 2, data)
	fillRaid0(disk1, testSector, 2048, chunk, 0, 2, data)
	members := []Member{
		{DiskIndex: 0, Source: memorySource(1, disk0)},
		{DiskIndex: 1, Source: memorySource(2, disk1)},
	}
	array, err := Assemble(9, container, 0, members)
	if err != nil {
		t.Fatalf("Assemble error = %v", err)
	}
	if array.Level() != LevelRaid0 || array.ChunkBytes() != 4096 ||
		array.DataOffset() != 2048*512 || array.Len() != 16384 {
		t.Fatalf("array = level %v chunk %d offset %d len %d",
			array.Level(), array.ChunkBytes(), array.DataOffset(), array.Len())
	}
	if len(array.MissingRoles()) != 0 {
		t.Fatalf("missing roles = %v", array.MissingRoles())
	}
	if got := readAll(t, array); string(got) != string(data) {
		t.Fatal("RAID0 read does not match the written data")
	}

	tail := make([]byte, 100)
	if n, err := array.ReadAt(4000, tail); err != nil || n != 100 {
		t.Fatalf("partial read = %d, %v", n, err)
	}
	if string(tail) != string(data[4000:4100]) {
		t.Fatal("partial read crossed the stripe boundary incorrectly")
	}
	extents, err := array.Extents(4000, 100)
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	if len(extents) != 2 {
		t.Fatalf("extents = %+v", extents)
	}
	if extents[0].ParentOffset != 2048*512+4000 || extents[0].Len != 96 {
		t.Fatalf("first extent = %+v", extents[0])
	}
	if extents[1].ParentOffset != 2048*512 || extents[1].Len != 4 {
		t.Fatalf("second extent = %+v", extents[1])
	}
}

func TestSingleMemberOfStripedArrayRefused(t *testing.T) {
	const chunk = uint64(4096)
	data := pattern(int(4*chunk), 4)
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2075, testSector, mpb, nil))
	disk0 := image(2075, testSector, mpb, nil)
	fillRaid0(disk0, testSector, 2048, chunk, 0, 2, data)

	_, err := Assemble(9, container, 0, []Member{{DiskIndex: 0, Source: memorySource(1, disk0)}})
	if err == nil || !strings.Contains(err.Error(), "missing role 1") {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error is not Unsupported: %v", err)
	}
}

func TestRaid0RebuildingRoleRefused(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	volume.ords[1] |= 1 << 24
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2075, testSector, mpb, nil))
	members := []Member{
		{DiskIndex: 0, Source: memorySource(1, image(2075, testSector, mpb, nil))},
		{DiskIndex: 1, Source: memorySource(2, image(2068, testSector, mpb, nil))},
	}
	_, err := Assemble(9, container, 0, members)
	if err == nil || !strings.Contains(err.Error(), "out of sync") {
		t.Fatalf("error = %v", err)
	}
}

func TestAssemblesMirrorAndBindsByLength(t *testing.T) {
	data := pattern(262144, 5)
	volume := newVolSpec("Volume0", 1, 2, 256, 1, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2568), configuredDisk("DISK-B", 2569)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2568, testSector, mpb, nil))

	if disk, err := container.BindDisk(2568 * 512); err != nil || disk != 0 {
		t.Fatalf("bind 2568 = %d, %v", disk, err)
	}
	if disk, err := container.BindDisk(2569 * 512); err != nil || disk != 1 {
		t.Fatalf("bind 2569 = %d, %v", disk, err)
	}
	if err := container.BindDiskIndex(0, 2568*512); err != nil {
		t.Fatalf("bind index 0 = %v", err)
	}
	if err := container.BindDiskIndex(1, 2568*512); err == nil {
		t.Fatal("bind index 1 accepted the wrong length")
	}

	disk0 := image(2568, testSector, mpb, nil)
	copy(disk0[2048*512:], data)
	array, err := Assemble(9, container, 0, []Member{{DiskIndex: 0, Source: memorySource(1, disk0)}})
	if err != nil {
		t.Fatalf("Assemble error = %v", err)
	}
	if array.Level() != LevelRaid1 || array.Len() != 262144 {
		t.Fatalf("array level %v len %d", array.Level(), array.Len())
	}
	if got := array.MissingRoles(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("missing roles = %v", got)
	}
	if role, ok := array.MirrorRole(); !ok || role != 0 {
		t.Fatalf("mirror role = %d ok=%v", role, ok)
	}
	if got := readAll(t, array); string(got) != string(data) {
		t.Fatal("mirror read does not match the written data")
	}

	extents, err := array.Extents(4096, 8192)
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	if len(extents) != 1 || extents[0].Parent != 1 ||
		extents[0].ParentOffset != 2048*512+4096 || extents[0].Len != 8192 ||
		extents[0].Kind != source.RangeData {
		t.Fatalf("extents = %+v", extents)
	}
	ranges, err := array.MapToImage(4096, 8192)
	if err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}
	if len(ranges) != 1 || ranges[0].ImageOffset != 2048*512+4096 || ranges[0].Len != 8192 {
		t.Fatalf("image ranges = %+v", ranges)
	}
}

func TestMirrorSkipsRebuildingSlot(t *testing.T) {
	data := pattern(262144, 7)
	volume := newVolSpec("Volume0", 1, 2, 256, 1, 2048)
	volume.ords[0] |= 1 << 24
	disks := []diskSpec{configuredDisk("DISK-A", 2568), configuredDisk("DISK-B", 2569)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2568, testSector, mpb, nil))
	if !container.Volumes[0].Map.SlotRebuilding(0) {
		t.Fatal("slot 0 is not marked rebuilding")
	}
	disk0 := image(2568, testSector, mpb, nil)
	disk1 := image(2569, testSector, mpb, nil)
	copy(disk0[2048*512:], data)
	copy(disk1[2048*512:], data)
	array, err := Assemble(9, container, 0, []Member{
		{DiskIndex: 0, Source: memorySource(1, disk0)},
		{DiskIndex: 1, Source: memorySource(2, disk1)},
	})
	if err != nil {
		t.Fatalf("Assemble error = %v", err)
	}
	if role, ok := array.MirrorRole(); !ok || role != 1 {
		t.Fatalf("mirror role = %d ok=%v; an out-of-sync slot must not be the only copy", role, ok)
	}
	if got := readAll(t, array); string(got) != string(data) {
		t.Fatal("mirror did not read the surviving slot")
	}
}

func TestMemberSourceStartsAtRecordedDataOffset(t *testing.T) {
	data := pattern(262144, 8)
	volume := newVolSpec("Volume0", 1, 2, 256, 1, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2568), configuredDisk("DISK-B", 2569)}
	mpb := buildMPB(disks, []volSpec{volume})
	disk0 := image(2568, testSector, mpb, nil)
	copy(disk0[2048*512:], data)
	container := parseBytes(t, disk0)

	member, err := NewMemberSource(4, memorySource(1, disk0), container, 0)
	if err != nil {
		t.Fatalf("NewMemberSource error = %v", err)
	}
	if member.DataOffset() != 2048*512 || member.Len() != 262144 ||
		member.SectorSize() != 512 {
		t.Fatalf("member offset=%d len=%d sector=%d",
			member.DataOffset(), member.Len(), member.SectorSize())
	}
	got := make([]byte, member.Len())
	if n, err := member.ReadAt(0, got); err != nil || n != len(got) {
		t.Fatalf("member read = %d, %v", n, err)
	}
	if string(got) != string(data) {
		t.Fatal("member data does not match")
	}
	extents, err := member.Extents(0, 16)
	if err != nil || len(extents) != 1 || extents[0].ParentOffset != 2048*512 {
		t.Fatalf("member extents = %+v, %v", extents, err)
	}
	past := make([]byte, 8)
	if _, err := member.ReadAt(member.Len(), past); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past the data area = %v", err)
	}
	if _, err := NewMemberSource(5, memorySource(1, make([]byte, 4096)), container, 9); err == nil {
		t.Fatal("a nonexistent volume index was accepted")
	}
	if _, err := NewMemberSource(6, memorySource(1, make([]byte, 4096)), container, 0); err == nil {
		t.Fatal("a member shorter than the data area was accepted")
	}
}

func TestAssemblesRaid10AndReadsSurvivingCopies(t *testing.T) {
	const chunk = uint64(4096)
	data := pattern(int(8*chunk), 6)
	volume := newVolSpec("Volume0", 10, 4, 8, 2, 2048)
	disks := []diskSpec{
		configuredDisk("DISK-A", 2084),
		configuredDisk("DISK-B", 2085),
		configuredDisk("DISK-C", 2086),
		configuredDisk("DISK-D", 2087),
	}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2084, testSector, mpb, nil))
	var members []Member
	for index, disk := range disks {
		bytes := image(disk.total, testSector, mpb, nil)
		fillRaid10(bytes, testSector, 2048, chunk, uint64(index), 4, data)
		members = append(members, Member{DiskIndex: uint8(index), Source: memorySource(source.ID(index+1), bytes)})
	}
	array, err := Assemble(9, container, 0, members)
	if err != nil {
		t.Fatalf("Assemble error = %v", err)
	}
	if array.Level() != LevelRaid10 || array.Len() != 32768 {
		t.Fatalf("level=%v len=%d", array.Level(), array.Len())
	}
	if got := readAll(t, array); string(got) != string(data) {
		t.Fatal("RAID10 read does not match")
	}

	degraded, err := Assemble(9, container, 0, members[1:])
	if err != nil {
		t.Fatalf("degraded Assemble error = %v", err)
	}
	if got := degraded.MissingRoles(); len(got) != 1 || got[0] != 0 {
		t.Fatalf("degraded missing roles = %v", got)
	}
	if got := readAll(t, degraded); string(got) != string(data) {
		t.Fatal("degraded RAID10 read does not match")
	}

	_, err = Assemble(9, container, 0, members[2:])
	if err == nil || !strings.Contains(err.Error(), "lost every copy") {
		t.Fatalf("error = %v", err)
	}
}

func TestRefusesParityAndUnknownLevels(t *testing.T) {
	disks := []diskSpec{
		configuredDisk("DISK-A", 2084),
		configuredDisk("DISK-B", 2085),
		configuredDisk("DISK-C", 2086),
		configuredDisk("DISK-D", 2087),
		configuredDisk("DISK-E", 2088),
		configuredDisk("DISK-F", 2089),
	}

	for _, test := range []struct {
		level uint8
		want  []string
	}{
		{5, []string{"RAID5", "parity"}},
		{6, []string{"RAID6", "does not define"}},
		{255, []string{"level code 255"}},
		{4, []string{"level code 4"}},
	} {
		volume := newVolSpec("Volume0", test.level, 3, 8, 2, 2048)
		mpb := buildMPB(disks, []volSpec{volume})
		container := parseBytes(t, image(2084, testSector, mpb, nil))
		_, err := Assemble(9, container, 0, nil)
		if err == nil {
			t.Fatalf("level %d assembled without error", test.level)
		}
		for _, want := range test.want {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("level %d error = %v; want %q", test.level, err, want)
			}
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("level %d error is not Unsupported: %v", test.level, err)
		}
	}
}

func TestRefusesMigratingVolume(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	volume.migrState = 1
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	_, err := Parse(memorySource(1, image(2075, testSector, mpb, nil)))
	if err == nil || !strings.Contains(err.Error(), "migration") {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error is not Unsupported: %v", err)
	}
}

func TestRefusesBadChecksum(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	mpb[DiskTableOffset] ^= 0xFF
	_, err := Parse(memorySource(1, image(2075, testSector, mpb, nil)))
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error is not Corrupt: %v", err)
	}
}

func TestRefusesUnsupportedVersion(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	mpb[MPBSigLen] = '9'
	fixChecksum(mpb)
	_, err := Parse(memorySource(1, image(2075, testSector, mpb, nil)))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error is not Unsupported: %v", err)
	}
}

func TestRefusesUndersizedAndOversizedMPB(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}

	mpb := buildMPB(disks, []volSpec{volume})
	putU32(mpb, 0x24, 200)
	_, err := Parse(memorySource(1, image(2075, testSector, mpb, nil)))
	if err == nil || !strings.Contains(err.Error(), "smaller") {
		t.Fatalf("undersized error = %v", err)
	}

	mpb = buildMPB(disks, []volSpec{volume})
	oversized := image(2075, testSector, mpb, nil)
	// Claim an MPB larger than the physical span the image can hold. The
	// anchor is the second-to-last sector; parse reads the size from there
	// before reassembling anything.
	putU32(oversized, len(oversized)-2*testSector+0x24, 1_100_000)
	_, err = Parse(memorySource(1, oversized))
	if err == nil || !strings.Contains(err.Error(), "cannot hold") {
		t.Fatalf("span error = %v", err)
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("span error is not Corrupt: %v", err)
	}
}

func TestRefusesTruncatedTables(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	mpb[0x39] = 2 // two volumes, but the device table holds only one
	fixChecksum(mpb)
	_, err := Parse(memorySource(1, image(2075, testSector, mpb, nil)))
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error = %v", err)
	}
	if !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatalf("error is not UnexpectedEOF: %v", err)
	}
}

func TestRefusesSlotNamingNonexistentDisk(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	volume.ords = []uint32{0, 7}
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	_, err := Parse(memorySource(1, image(2075, testSector, mpb, nil)))
	if err == nil || !strings.Contains(err.Error(), "disk index 7") {
		t.Fatalf("error = %v", err)
	}
}

func TestRefusesTwoMembersBoundToSameDisk(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2075, testSector, mpb, nil))
	members := []Member{
		{DiskIndex: 0, Source: memorySource(1, image(2075, testSector, mpb, nil))},
		{DiskIndex: 0, Source: memorySource(2, image(2068, testSector, mpb, nil))},
	}
	_, err := Assemble(9, container, 0, members)
	if err == nil || !strings.Contains(err.Error(), "bound to disk 0") {
		t.Fatalf("error = %v", err)
	}
}

func TestRefusesEqualSizedMembersAsAmbiguous(t *testing.T) {
	volume := newVolSpec("Volume0", 1, 2, 256, 1, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2568), configuredDisk("DISK-B", 2568)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2568, testSector, mpb, nil))
	_, err := container.BindDisk(2568 * 512)
	if err == nil || !strings.Contains(err.Error(), "same size") {
		t.Fatalf("error = %v", err)
	}
}

func TestBindDiskNamesSpareStateAndMissingSize(t *testing.T) {
	volume := newVolSpec("Volume0", 1, 2, 256, 1, 2048)
	spare := diskSpec{serial: "DISK-B", status: DiskFlagSpare, total: 2569}
	disks := []diskSpec{configuredDisk("DISK-A", 2568), spare}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2568, testSector, mpb, nil))
	_, err := container.BindDisk(2569 * 512)
	if err == nil || !strings.Contains(err.Error(), "spare") {
		t.Fatalf("spare bind error = %v", err)
	}
	_, err = container.BindDisk(9999 * 512)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("missing-size bind error = %v", err)
	}
	if _, err := container.BindDisk(2568*512 + 1); !strings.Contains(err.Error(), "whole number") {
		t.Fatalf("unaligned bind error = %v", err)
	}
}

func TestRefusesStaleStripeMap(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	volume.size += 3 * 2048
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2075, testSector, mpb, nil))
	_, err := Assemble(9, container, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("error = %v", err)
	}
}

func TestRefusesDataAreaPastImageEnd(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2000), configuredDisk("DISK-B", 2001)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2000, testSector, mpb, nil))
	members := []Member{
		{DiskIndex: 0, Source: memorySource(1, image(2000, testSector, mpb, nil))},
		{DiskIndex: 1, Source: memorySource(2, image(2001, testSector, mpb, nil))},
	}
	_, err := Assemble(9, container, 0, members)
	if err == nil || !strings.Contains(err.Error(), "shorter") {
		t.Fatalf("error = %v", err)
	}
}

func TestRefusesUninitializedAndFailedMaps(t *testing.T) {
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	for _, state := range []uint8{1, 3} {
		volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
		volume.mapState = state
		mpb := buildMPB(disks, []volSpec{volume})
		container := parseBytes(t, image(2075, testSector, mpb, nil))
		_, err := Assemble(9, container, 0, nil)
		want := "uninitialized"
		if state == 3 {
			want = "failed"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("map state %d error = %v", state, err)
		}
	}
}

func TestMembersAgreeAcrossGenerationsButNotTables(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	older := buildMPB(disks, []volSpec{volume})
	newer := buildMPB(disks, []volSpec{volume})
	putU32(newer, 0x2C, 8)
	fixChecksum(newer)
	olderContainer := parseBytes(t, image(2075, testSector, older, nil))
	newerContainer := parseBytes(t, image(2075, testSector, newer, nil))
	if !olderContainer.AgreesWith(newerContainer) {
		t.Fatal("members differing only in generation disagree")
	}

	otherDisks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-C", 2068)}
	other := buildMPB(otherDisks, []volSpec{volume})
	otherContainer := parseBytes(t, image(2075, testSector, other, nil))
	if olderContainer.AgreesWith(otherContainer) {
		t.Fatal("members with different disk tables agree")
	}
}

func TestMapLevelAndDataMembers(t *testing.T) {
	tests := []struct {
		level   uint8
		members uint8
		want    Level
		data    uint64
	}{
		{0, 2, LevelRaid0, 2},
		{1, 2, LevelRaid1, 1},
		{1, 3, LevelRaid10, 1},
		{5, 3, LevelRaid5, 2},
		{6, 4, LevelRaid6, 2},
		{10, 4, LevelRaid10, 2},
		{255, 2, Level(255), 0},
	}
	for _, test := range tests {
		m := Map{RAIDLevel: test.level, NumMembers: test.members}
		if got := m.Level(); got != test.want {
			t.Fatalf("level %d/%d = %v, want %v", test.level, test.members, got, test.want)
		}
		if got := m.DataMembers(); got != test.data {
			t.Fatalf("level %d/%d data members = %d, want %d", test.level, test.members, got, test.data)
		}
	}
	if LevelRaid10.Label() != "raid10" || Level(255).Label() != "unknown" {
		t.Fatalf("labels = %q/%q", LevelRaid10.Label(), Level(255).Label())
	}
	if LevelRaid10.Code() != 10 || Level(255).Code() != 255 {
		t.Fatalf("codes = %d/%d", LevelRaid10.Code(), Level(255).Code())
	}
}

func TestSlotDiskHandlesUnrecordedAndOversizedIndexes(t *testing.T) {
	m := Map{NumMembers: 4, DiskOrdTbl: []uint32{0, 0x00FFFFFF, 0x00000100, 0x01000000 | 2}}
	if _, ok := m.SlotDisk(1); ok {
		t.Fatal("an unrecorded slot returned a disk")
	}
	if _, ok := m.SlotDisk(2); ok {
		t.Fatal("a slot index above 255 returned a disk")
	}
	if _, ok := m.SlotDisk(4); ok {
		t.Fatal("a slot outside the table returned a disk")
	}
	if !m.SlotRebuilding(3) {
		t.Fatal("rebuild bit was not reported")
	}
	if slot, ok := m.DiskSlot(0); !ok || slot != 0 {
		t.Fatalf("disk 0 slot = %d ok=%v", slot, ok)
	}
}

func TestRefusesUnknownVolumeIndexAndNoPlaceableArea(t *testing.T) {
	volume := newVolSpec("Volume0", 0, 2, 8, 2, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2075), configuredDisk("DISK-B", 2068)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2075, testSector, mpb, nil))
	if _, err := Assemble(9, container, 9, nil); err == nil {
		t.Fatal("a nonexistent volume index was accepted")
	}

	zero := newVolSpec("Zero", 0, 2, 0, 2, 2048)
	mpb = buildMPB(disks, []volSpec{zero})
	_, err := Parse(memorySource(1, image(2075, testSector, mpb, nil)))
	if err == nil || !strings.Contains(err.Error(), "chunk size of 0") {
		t.Fatalf("zero chunk error = %v", err)
	}
}

func TestArrayAndMemberBounds(t *testing.T) {
	volume := newVolSpec("Volume0", 1, 2, 256, 1, 2048)
	disks := []diskSpec{configuredDisk("DISK-A", 2568), configuredDisk("DISK-B", 2569)}
	mpb := buildMPB(disks, []volSpec{volume})
	container := parseBytes(t, image(2568, testSector, mpb, nil))
	disk0 := image(2568, testSector, mpb, nil)
	array, err := Assemble(9, container, 0, []Member{{DiskIndex: 0, Source: memorySource(1, disk0)}})
	if err != nil {
		t.Fatalf("Assemble error = %v", err)
	}
	buf := make([]byte, 8)
	if n, err := array.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if _, err := array.ReadAt(array.Len(), buf); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("out-of-range read = %v", err)
	}
	if _, err := array.Extents(array.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("out-of-range extents = %v", err)
	}
	if _, err := array.MapToImage(array.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("out-of-range map = %v", err)
	}

	member, err := NewMemberSource(4, memorySource(1, disk0), container, 0)
	if err != nil {
		t.Fatalf("NewMemberSource error = %v", err)
	}
	if n, err := member.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("empty member read = %d, %v", n, err)
	}
	if _, err := member.Extents(member.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("out-of-range member extents = %v", err)
	}
	if !member.IsEmpty() && member.Len() == 0 {
		t.Fatal("inconsistent IsEmpty")
	}
}
