package thin

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/lvm"
	"github.com/laenix/ewfgo/internal/data/source"
)

func putLE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putLE64(b []byte, at int, v uint64) {
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

func seal(block []byte, xor uint32) {
	putLE32(block, 0, 0)
	putLE32(block, 0, thinChecksum(block, xor))
}

func buildSuperblock() []byte {
	block := make([]byte, MetadataBlockBytes)
	putLE32(block, 4, 0)
	putLE64(block, 8, 0)
	copy(block[16:32], []byte("0123456789abcdef"))
	putLE64(block, 32, ThinMagic)
	putLE32(block, 40, 2)
	putLE32(block, 44, 1700000000)
	putLE64(block, 48, 5)
	putLE64(block, 56, 0)
	putLE64(block, 320, 2) // data mapping root
	putLE64(block, 328, 1) // device details root
	putLE32(block, 336, 8) // data block size in 512-byte sectors
	putLE32(block, 340, 4096)
	putLE64(block, 344, 16)
	seal(block, SuperblockCsumXor)
	return block
}

func buildNode(t *testing.T, location uint64, flags uint32, valueSize uint32, keys []uint64, values [][]byte) []byte {
	t.Helper()
	block := make([]byte, MetadataBlockBytes)
	putLE32(block, 4, flags)
	putLE64(block, 8, location)
	putLE32(block, 16, uint32(len(keys)))
	maxEntries := (MetadataBlockBytes - 32) / (8 + uint64(valueSize))
	putLE32(block, 20, uint32(maxEntries))
	putLE32(block, 24, valueSize)
	for i, key := range keys {
		putLE64(block, 32+i*8, key)
	}
	valuesAt := 32 + int(maxEntries)*8
	for i, value := range values {
		if len(value) != int(valueSize) {
			t.Fatalf("value %d is %d bytes, want %d", i, len(value), valueSize)
		}
		copy(block[valuesAt+i*int(valueSize):], value)
	}
	seal(block, BtreeCsumXor)
	return block
}

func packed(dataBlock, time uint64) []byte {
	value := make([]byte, 8)
	putLE64(value, 0, dataBlock<<24|time)
	return value
}

func buildMetadataImage(t *testing.T) []byte {
	t.Helper()
	image := make([]byte, 16*MetadataBlockBytes)
	copy(image[0:], buildSuperblock())

	details := make([]byte, 24)
	putLE64(details, 0, 2) // mapped blocks
	putLE64(details, 8, 4) // transaction
	copy(image[1*MetadataBlockBytes:], buildNode(t, 1, 0, 24, []uint64{0}, [][]byte{details}))

	mappingRoot := make([]byte, 8)
	putLE64(mappingRoot, 0, 3)
	copy(image[2*MetadataBlockBytes:], buildNode(t, 2, 0, 8, []uint64{0}, [][]byte{mappingRoot}))

	copy(image[3*MetadataBlockBytes:], buildNode(t, 3, 0, 8,
		[]uint64{0, 2}, [][]byte{packed(0, 1), packed(2, 1)}))
	return image
}

func buildGroup() *lvm.VolumeGroup {
	const pvUUID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	return &lvm.VolumeGroup{
		Name:       "vg",
		ExtentSize: 8, // 4096 bytes
		PhysicalVolumes: []lvm.PhysicalVolumeEntry{{
			Name: "pv0", UUID: pvUUID, PEStart: 8, PECount: 200, HasPEStart: true, HasPECount: true,
		}},
		LogicalVolumes: []lvm.LogicalVolume{
			{
				Name: "meta0",
				Segments: []lvm.Segment{{Index: 1, StartExtent: 0, ExtentCount: 16, Kind: "linear",
					StripeCount: 1, Stripes: []lvm.Stripe{{PVUUID: pvUUID, StartExtent: 0}}}},
			},
			{
				Name: "data0",
				Segments: []lvm.Segment{{Index: 1, StartExtent: 0, ExtentCount: 8, Kind: "linear",
					StripeCount: 1, Stripes: []lvm.Stripe{{PVUUID: pvUUID, StartExtent: 16}}}},
			},
			{
				Name: "pool0",
				Segments: []lvm.Segment{{Kind: "thin-pool", Other: []lvm.KV{
					{Key: "metadata", Value: "meta0"}, {Key: "pool", Value: "data0"},
				}}},
			},
			{
				Name: "thin0",
				Segments: []lvm.Segment{{Index: 1, StartExtent: 0, ExtentCount: 4, Kind: "thin",
					Other: []lvm.KV{
						{Key: "thin_pool", Value: "pool0"},
						{Key: "device_id", Value: "0"},
						{Key: "transaction_id", Value: "4"},
					}}},
			},
		},
	}
}

func buildPoolPV(t *testing.T) (source.ByteSource, *lvm.VolumeGroup) {
	t.Helper()
	const pvStart = 4096
	const dataStart = 4096 + 16*4096
	pv := make([]byte, 1<<20)
	copy(pv[pvStart:], buildMetadataImage(t))

	dataImage := make([]byte, 8*4096)
	for i := 0; i < 4096; i++ {
		dataImage[i] = 'X'
		dataImage[2*4096+i] = 'Y'
	}
	copy(pv[dataStart:], dataImage)
	return source.NewMemorySourceWithImage(1, 7, pv), buildGroup()
}

func TestParseSuperblock(t *testing.T) {
	sb, err := ParseSuperblock(buildSuperblock())
	if err != nil {
		t.Fatalf("ParseSuperblock error = %v", err)
	}
	if sb.Magic != ThinMagic || sb.Version != 2 || sb.TransID != 5 {
		t.Fatalf("superblock = %+v", sb)
	}
	if sb.DataBlockBytes() != 4096 || sb.MetadataNrBlocks != 16 {
		t.Fatalf("geometry = %d %d", sb.DataBlockBytes(), sb.MetadataNrBlocks)
	}
	if sb.DataMappingRoot != 2 || sb.DeviceDetailsRoot != 1 {
		t.Fatalf("roots = %d %d", sb.DataMappingRoot, sb.DeviceDetailsRoot)
	}
	if sb.NeedsCheck() {
		t.Fatal("NeedsCheck = true")
	}
}

func TestParseSuperblockRejectsCorruption(t *testing.T) {
	block := buildSuperblock()
	block[48] ^= 0xFF
	if _, err := ParseSuperblock(block); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ParseSuperblock error = %v, want ErrCorrupt", err)
	}

	block = buildSuperblock()
	putLE32(block, 4, 0x2) // unsupported flag
	seal(block, SuperblockCsumXor)
	if _, err := ParseSuperblock(block); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ParseSuperblock error = %v, want ErrUnsupported", err)
	}
}

func TestDecodeNodeRejectsDamage(t *testing.T) {
	nodeBytes := buildNode(t, 5, 0, 8, []uint64{0, 2}, [][]byte{packed(0, 1), packed(2, 1)})
	decoded, err := decodeNode(nodeBytes, 5, 8)
	if err != nil {
		t.Fatalf("decodeNode error = %v", err)
	}
	if len(decoded.keys) != 2 || le64(decoded.value(1))>>24 != 2 {
		t.Fatalf("node = %+v", decoded)
	}

	bad := append([]byte(nil), nodeBytes...)
	bad[32] ^= 0xFF // first key, inside the checksum
	if _, err := decodeNode(bad, 5, 8); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("decodeNode(checksum) error = %v, want ErrCorrupt", err)
	}

	bad = append([]byte(nil), nodeBytes...)
	if _, err := decodeNode(bad, 6, 8); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("decodeNode(blocknr) error = %v, want ErrCorrupt", err)
	}
}

func TestThinVolumeReadsMappedBlocksAndHoles(t *testing.T) {
	pv, group := buildPoolPV(t)
	pvs := []lvm.PhysicalVolumeSource{{UUID: group.PhysicalVolumes[0].UUID, Source: pv}}

	src, err := OpenInGroup(100, group, pvs, "thin0")
	if err != nil {
		t.Fatalf("OpenInGroup error = %v", err)
	}
	if src.Len() != 4*4096 {
		t.Fatalf("Len = %d, want %d", src.Len(), 4*4096)
	}
	if src.DataBlockBytes() != 4096 {
		t.Fatalf("DataBlockBytes = %d", src.DataBlockBytes())
	}
	if root, ok := src.MappingRoot(); !ok || root != 3 {
		t.Fatalf("MappingRoot = %d, %v", root, ok)
	}

	block := make([]byte, 4096)
	if _, err := src.ReadAt(0, block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, bytes.Repeat([]byte{'X'}, 4096)) {
		t.Fatal("block 0 does not read 'X'")
	}

	block = bytes.Repeat([]byte{0xaa}, 4096)
	if _, err := src.ReadAt(4096, block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, make([]byte, 4096)) {
		t.Fatal("unmapped block 1 is not a zero hole")
	}

	if _, err := src.ReadAt(8192, block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, bytes.Repeat([]byte{'Y'}, 4096)) {
		t.Fatal("block 2 does not read 'Y'")
	}

	extents, err := src.Extents(0, src.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 4 {
		t.Fatalf("extents = %+v", extents)
	}
	wantKinds := []source.RangeKind{source.RangeData, source.RangeHole, source.RangeData, source.RangeHole}
	for i, kind := range wantKinds {
		if extents[i].Kind != kind || extents[i].Len != 4096 {
			t.Fatalf("extent %d = %+v, want kind %v len 4096", i, extents[i], kind)
		}
	}
	if extents[0].ParentOffset != 0 || extents[2].ParentOffset != 8192 {
		t.Fatalf("data offsets = %d %d", extents[0].ParentOffset, extents[2].ParentOffset)
	}

	image, err := src.MapToImage(0, src.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(image) != 4 {
		t.Fatalf("image ranges = %+v", image)
	}
	if image[0].ImageID != 7 || image[0].ImageOffset != 4096+16*4096 {
		t.Fatalf("image[0] = %+v", image[0])
	}
	if image[1].Kind != source.RangeHole || image[3].Kind != source.RangeHole {
		t.Fatalf("holes = %+v %+v", image[1], image[3])
	}
}

func TestOpenInGroupRejectsUnknownPool(t *testing.T) {
	pv, group := buildPoolPV(t)
	group.LogicalVolumes[3].Segments[0].Other[0].Value = "missing"
	pvs := []lvm.PhysicalVolumeSource{{UUID: group.PhysicalVolumes[0].UUID, Source: pv}}
	if _, err := OpenInGroup(100, group, pvs, "thin0"); !errors.Is(err, ErrUnknownPool) {
		t.Fatalf("OpenInGroup error = %v, want ErrUnknownPool", err)
	}
}
