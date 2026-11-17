package mdraid

import (
	"errors"
	"reflect"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testSetName = "mdraid-test"
)

var (
	testSetUUID = [16]byte{0x3f, 0x2b, 0x1c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
		0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x19}
	testDevUUID = [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01}
)

func putU32(t *testing.T, b []byte, at int, v uint32) {
	t.Helper()
	if at+4 > len(b) {
		t.Fatalf("putU32 at %d out of %d bytes", at, len(b))
	}
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putU64(t *testing.T, b []byte, at int, v uint64) {
	t.Helper()
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

func putU16(t *testing.T, b []byte, at int, v uint16) {
	t.Helper()
	b[at], b[at+1] = byte(v), byte(v>>8)
}

func buildSB1(t *testing.T, level int32, chunkSectors, raidDisks, devNumber uint32, role uint16, dataOffset, dataSize uint64, maxDev uint32) []byte {
	t.Helper()
	sb := make([]byte, 4096)
	putU32(t, sb, 0x00, MDMagic)
	putU32(t, sb, 0x04, 1)
	putU32(t, sb, 0x08, 0)
	copy(sb[0x10:0x20], testSetUUID[:])
	copy(sb[0x20:0x40], testSetName)
	putU64(t, sb, 0x40, 1700000000)
	putU32(t, sb, 0x48, uint32(level))
	putU32(t, sb, 0x4C, 0)
	putU64(t, sb, 0x50, dataSize)
	putU32(t, sb, 0x58, chunkSectors)
	putU32(t, sb, 0x5C, raidDisks)
	putU64(t, sb, 0x80, dataOffset)
	putU64(t, sb, 0x88, dataSize)
	putU64(t, sb, 0x90, 8)
	putU32(t, sb, 0xA0, devNumber)
	copy(sb[0xA8:0xB8], testDevUUID[:])
	putU64(t, sb, 0xC0, 1700000001)
	putU64(t, sb, 0xC8, 7)
	putU32(t, sb, 0xDC, maxDev)
	for i := uint32(0); i < maxDev; i++ {
		value := uint16(0xFFFF)
		if i == devNumber {
			value = role
		}
		putU16(t, sb, 0x100+int(i)*2, value)
	}

	covered := append([]byte(nil), sb...)
	for i := 0xD8; i < 0xDC; i++ {
		covered[i] = 0
	}
	putU32(t, sb, 0xD8, foldChecksum(covered, 256+int(maxDev)*2, false))
	return sb
}

func imageWithSB1(sb []byte, dataOffsetSectors uint64, data []byte) []byte {
	image := make([]byte, int(dataOffsetSectors)*512+len(data))
	if len(image) < 8192 {
		image = make([]byte, 8192)
	}
	copy(image[4096:], sb)
	copy(image[int(dataOffsetSectors)*512:], data)
	return image
}

func TestParse1_2(t *testing.T) {
	sbBytes := buildSB1(t, 0, 128, 2, 0, 0, 2048, 200, 2)
	image := imageWithSB1(sbBytes, 2048, make([]byte, 200*512))

	got, err := Parse(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if got == nil {
		t.Fatal("Parse = nil")
	}
	if got.Version.Label() != "1.2" {
		t.Fatalf("version = %s, want 1.2", got.Version.Label())
	}
	if got.Level != 0 || got.LevelName() != "raid0" {
		t.Fatalf("level = %d %q", got.Level, got.LevelName())
	}
	if got.ChunkSizeBytes != 128*512 {
		t.Fatalf("chunk = %d", got.ChunkSizeBytes)
	}
	if got.RaidDisks != 2 || got.DevNumber != 0 {
		t.Fatalf("raidDisks=%d devNumber=%d", got.RaidDisks, got.DevNumber)
	}
	if got.DataOffsetBytes() != 2048*512 || got.DataSizeBytes() != 200*512 {
		t.Fatalf("data area = %d + %d", got.DataOffsetBytes(), got.DataSizeBytes())
	}
	if got.Checksum != ChecksumVerified {
		t.Fatalf("checksum = %v, want verified", got.Checksum)
	}
	role, ok := got.Role()
	if !ok || role != 0 {
		t.Fatalf("Role = %d, %v", role, ok)
	}
	if got.ArrayUUID() != "3f2b1c4d:5e6f7081:92a3b4c5:d6e7f819" {
		t.Fatalf("ArrayUUID = %q", got.ArrayUUID())
	}
	if got.SetName != testSetName {
		t.Fatalf("SetName = %q", got.SetName)
	}
	if got.CtimeSeconds() != 1700000000 || got.UpdatedSeconds() != 1700000001 {
		t.Fatalf("times = %d %d", got.CtimeSeconds(), got.UpdatedSeconds())
	}
}

func TestParse1_1(t *testing.T) {
	sbBytes := buildSB1(t, 1, 128, 1, 0, 0, 8, 100, 1)
	image := make([]byte, 8*512+100*512)
	copy(image[0:], sbBytes)

	got, err := Parse(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if got == nil || got.Version.Label() != "1.1" || got.Level != 1 {
		t.Fatalf("superblock = %+v", got)
	}
}

func TestParse090(t *testing.T) {
	const imageLen = 1 << 20
	image := make([]byte, imageLen)
	offset := int(sb0Offset(imageLen))
	sb := make([]byte, 4096)
	putU32(t, sb, 0x00, MDMagic)
	putU32(t, sb, 0x04, 0)
	putU32(t, sb, 0x08, 90)
	putU32(t, sb, 0x1C, 0)        // level
	putU32(t, sb, 0x20, 100)      // size in 1024-byte blocks
	putU32(t, sb, 0x28, 2)        // raid_disks
	putU32(t, sb, 0x84, 1)        // state: clean
	putU32(t, sb, 0x104, 64*1024) // chunk bytes
	putU32(t, sb, 0x100, 0)       // layout
	// Descriptor 0: role 0, state sync+active.
	desc := 0x200
	putU32(t, sb, desc+12, 0)
	putU32(t, sb, desc+16, 2|4)
	// Descriptor 1: role 1, state sync+active.
	desc1 := 0x200 + 128
	putU32(t, sb, desc1+12, 1)
	putU32(t, sb, desc1+16, 2|4)
	// this_disk: device number 0, role 0.
	putU32(t, sb, 0xF80, 0)
	putU32(t, sb, 0xF80+12, 0)
	putU32(t, sb, 0xF80+16, 2|4)

	covered := append([]byte(nil), sb...)
	for i := 0x98; i < 0x9C; i++ {
		covered[i] = 0
	}
	putU32(t, sb, 0x98, foldChecksum(covered, 4096, false))
	copy(image[offset:], sb)

	got, err := Parse(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if got == nil || got.Version.Label() != "0.90" {
		t.Fatalf("superblock = %+v", got)
	}
	if got.DataOffsetBytes() != 0 || got.DataSizeBytes() != uint64(offset) {
		t.Fatalf("data area = %d + %d, want 0 + %d", got.DataOffsetBytes(), got.DataSizeBytes(), offset)
	}
	if got.ComponentSizeBytes() != 100*1024 {
		t.Fatalf("component size = %d", got.ComponentSizeBytes())
	}
	if role, ok := got.Role(); !ok || role != 0 {
		t.Fatalf("Role = %d, %v", role, ok)
	}
	if clean := got.Clean(); clean == nil || !*clean {
		t.Fatalf("Clean = %v", clean)
	}
}

func TestSuperblockChecksumMismatchIsReportedNotFatal(t *testing.T) {
	sbBytes := buildSB1(t, 0, 128, 2, 0, 0, 2048, 200, 2)
	sbBytes[0xC8] ^= 0xFF // events, inside the checksum
	image := imageWithSB1(sbBytes, 2048, make([]byte, 200*512))

	got, err := Parse(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if got == nil || got.Checksum != ChecksumMismatch {
		t.Fatalf("checksum = %v", got)
	}
}

func TestMdSourceReadsDataArea(t *testing.T) {
	sbBytes := buildSB1(t, 0, 128, 2, 0, 0, 16, 10, 2)
	data := make([]byte, 5120)
	for i := range data {
		data[i] = byte(i)
	}
	image := imageWithSB1(sbBytes, 16, data)
	parent := source.NewMemorySourceWithImage(1, 7, image)

	sb, err := Parse(parent)
	if err != nil || sb == nil {
		t.Fatalf("Parse = %+v, %v", sb, err)
	}
	member, err := NewSource(2, parent, sb)
	if err != nil {
		t.Fatalf("NewSource error = %v", err)
	}
	if member.Len() != 5120 || member.SectorSize() != 512 {
		t.Fatalf("member = len %d sector %d", member.Len(), member.SectorSize())
	}

	buf := make([]byte, 5120)
	if _, err := member.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(buf, data) {
		t.Fatal("data area bytes do not match")
	}
	extents, err := member.Extents(0, 5120)
	if err != nil {
		t.Fatal(err)
	}
	want := []source.ParentRange{{Parent: 1, ParentOffset: 16 * 512, Len: 5120, Kind: source.RangeData}}
	if !reflect.DeepEqual(extents, want) {
		t.Fatalf("Extents = %+v, want %+v", extents, want)
	}
	imageRange, err := member.MapToImage(0, 5120)
	if err != nil {
		t.Fatal(err)
	}
	wantImage := []source.ImageRange{{ImageID: 7, ImageOffset: 16 * 512, Len: 5120, Kind: source.RangeData}}
	if !reflect.DeepEqual(imageRange, wantImage) {
		t.Fatalf("MapToImage = %+v, want %+v", imageRange, wantImage)
	}
}

func raid0Members(t *testing.T, dataSize uint64) []ArrayMember {
	t.Helper()
	const chunk = 128
	data0 := make([]byte, dataSize)
	data1 := make([]byte, dataSize)
	for i := uint64(0); i < dataSize; i++ {
		data0[i] = 'A'
		data1[i] = 'B'
	}
	for i := uint64(chunk * 512); i < dataSize; i++ {
		data0[i] = 'C'
		data1[i] = 'D'
	}
	return []ArrayMember{
		{Superblock: mustSB(t, 0, chunk, 2, 0, 0, 16, dataSize/512, 2), Data: source.NewMemorySource(1, data0)},
		{Superblock: mustSB(t, 0, chunk, 2, 1, 1, 16, dataSize/512, 2), Data: source.NewMemorySource(2, data1)},
	}
}

func mustSB(t *testing.T, level int32, chunkSectors, raidDisks, devNumber uint32, role uint16, dataOffset, dataSize uint64, maxDev uint32) *Superblock {
	t.Helper()
	image := imageWithSB1(buildSB1(t, level, chunkSectors, raidDisks, devNumber, role, dataOffset, dataSize, maxDev), dataOffset, make([]byte, dataSize*512))
	sb, err := Parse(source.NewMemorySource(99, image))
	if err != nil || sb == nil {
		t.Fatalf("mustSB: %+v, %v", sb, err)
	}
	return sb
}

func TestRaid0ReadsAcrossChunks(t *testing.T) {
	members := raid0Members(t, 2*128*512)
	array, err := Raid0(3, members)
	if err != nil {
		t.Fatalf("Raid0 error = %v", err)
	}
	if array.ChunkBytes() != 128*512 || array.Len() != 4*128*512 {
		t.Fatalf("array = chunk %d len %d", array.ChunkBytes(), array.Len())
	}

	buf := make([]byte, array.Len())
	if _, err := array.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	want := []byte{'A', 'B', 'C', 'D'}
	for chunk, expected := range want {
		for i := 0; i < 128*512; i++ {
			got := buf[chunk*128*512+i]
			if got != expected {
				t.Fatalf("chunk %d byte %d = %q, want %q", chunk, i, got, expected)
			}
		}
	}

	extents, err := array.Extents(0, array.Len())
	if err != nil {
		t.Fatal(err)
	}
	wantExtents := []source.ParentRange{
		{Parent: 1, ParentOffset: 0, Len: 128 * 512, Kind: source.RangeData},
		{Parent: 2, ParentOffset: 0, Len: 128 * 512, Kind: source.RangeData},
		{Parent: 1, ParentOffset: 128 * 512, Len: 128 * 512, Kind: source.RangeData},
		{Parent: 2, ParentOffset: 128 * 512, Len: 128 * 512, Kind: source.RangeData},
	}
	if !reflect.DeepEqual(extents, wantExtents) {
		t.Fatalf("Extents = %+v, want %+v", extents, wantExtents)
	}
}

func TestRaid0RequiresEveryRole(t *testing.T) {
	members := raid0Members(t, 2*128*512)
	_, err := Raid0(3, members[:1])
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Raid0 error = %v, want ErrUnsupported", err)
	}
}

func buildSB1WithLayout(t *testing.T, level int32, layout uint32, chunkSectors, raidDisks, devNumber uint32, role uint16, dataOffset, dataSize uint64, maxDev uint32) []byte {
	t.Helper()
	sb := buildSB1(t, level, chunkSectors, raidDisks, devNumber, role, dataOffset, dataSize, maxDev)
	putU32(t, sb, 0x4C, layout)
	covered := append([]byte(nil), sb...)
	for i := 0xD8; i < 0xDC; i++ {
		covered[i] = 0
	}
	putU32(t, sb, 0xD8, foldChecksum(covered, 256+int(maxDev)*2, false))
	return sb
}

func raid10Members(t *testing.T, layout uint32, chunkSectors uint32, componentBytes uint64) []ArrayMember {
	t.Helper()
	const disks = 4
	markers := []byte{'A', 'B', 'E', 'F'}
	// Second chunk of each member gets a distinct marker two letters up.
	second := []byte{'C', 'D', 'G', 'H'}
	members := make([]ArrayMember, 0, disks)
	for dev := uint32(0); dev < disks; dev++ {
		dataSize := componentBytes / 512
		sb := buildSB1WithLayout(t, 10, layout, chunkSectors, disks, dev, uint16(dev), 16, dataSize, disks)
		image := imageWithSB1(sb, 16, make([]byte, componentBytes))
		parsed, err := Parse(source.NewMemorySource(99, image))
		if err != nil || parsed == nil {
			t.Fatalf("raid10 member %d: %+v, %v", dev, parsed, err)
		}
		data := make([]byte, componentBytes)
		for i := uint64(0); i < componentBytes; i++ {
			if i < uint64(chunkSectors)*512 {
				data[i] = markers[dev]
			} else {
				data[i] = second[dev]
			}
		}
		members = append(members, ArrayMember{Superblock: parsed, Data: source.NewMemorySource(source.ID(dev+1), data)})
	}
	return members
}

func TestRaid10NearTwoReadsFirstCopy(t *testing.T) {
	const chunk = 64 * 1024
	members := raid10Members(t, 0x0102, 128, 2*chunk) // near=2, far=1
	array, err := Raid10(9, members)
	if err != nil {
		t.Fatalf("Raid10 error = %v", err)
	}
	if array.Len() != 4*chunk || array.ChunkBytes() != chunk {
		t.Fatalf("array = len %d chunk %d", array.Len(), array.ChunkBytes())
	}

	buf := make([]byte, array.Len())
	if _, err := array.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	want := []byte{'A', 'E', 'C', 'G'}
	for c, expected := range want {
		for i := 0; i < chunk; i++ {
			if got := buf[c*chunk+i]; got != expected {
				t.Fatalf("chunk %d byte %d = %q, want %q", c, i, got, expected)
			}
		}
	}

	extents, err := array.Extents(0, array.Len())
	if err != nil {
		t.Fatal(err)
	}
	wantRoles := []source.ID{1, 3, 1, 3}
	if len(extents) != len(wantRoles) {
		t.Fatalf("extents = %+v", extents)
	}
	for i, role := range wantRoles {
		if extents[i].Parent != role {
			t.Fatalf("extent %d parent = %d, want %d", i, extents[i].Parent, role)
		}
	}
}

func TestRaid10DegradedUsesSurvivingCopy(t *testing.T) {
	const chunk = 64 * 1024
	members := raid10Members(t, 0x0102, 128, 2*chunk)
	// Drop role 0; every chunk still has its second copy on role 1.
	array, err := Raid10(9, members[1:])
	if err != nil {
		t.Fatalf("Raid10 error = %v", err)
	}
	buf := make([]byte, array.Len())
	if _, err := array.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	want := []byte{'B', 'E', 'D', 'G'}
	for c, expected := range want {
		for i := 0; i < chunk; i++ {
			if got := buf[c*chunk+i]; got != expected {
				t.Fatalf("chunk %d byte %d = %q, want %q", c, i, got, expected)
			}
		}
	}
}

func TestRaid10RefusesWhenEveryCopyIsMissing(t *testing.T) {
	const chunk = 64 * 1024
	members := raid10Members(t, 0x0102, 128, 2*chunk)
	// Roles 0 and 1 are both copies of logical chunk 0.
	_, err := Raid10(9, members[2:])
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Raid10 error = %v, want ErrUnsupported", err)
	}
}

func TestRaid10RejectsWrongLevel(t *testing.T) {
	members := raid0Members(t, 2*128*512)
	if _, err := Raid10(9, members); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Raid10 error = %v, want ErrUnsupported", err)
	}
}
