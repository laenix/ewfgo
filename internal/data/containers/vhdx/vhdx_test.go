package vhdx

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testBlock    = uint64(2 << 20)
	testHeader   = uint64(64 << 10)
	testRegions  = uint64(192 << 10)
	testMetadata = uint64(2 << 20)
	testBAT      = uint64(3 << 20)
	testPayload  = uint64(5 << 20)
)

func putLE16(b []byte, at int, v uint16) { b[at], b[at+1] = byte(v), byte(v>>8) }
func putLE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
func putLE64(b []byte, at int, v uint64) {
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

func seal(block []byte) {
	clear(block[4:8])
	putLE32(block, 4, foundation.CRC32C(block))
}

func utf16LE(text string) []byte {
	units := []rune(text)
	out := make([]byte, 0, len(units)*2)
	for _, r := range units {
		for _, u := range []uint16{uint16(r)} {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return out
}

func parentLocatorValue(linkage [16]byte, hint string) []byte {
	key := utf16LE("parent_linkage")
	value := utf16LE(formatGUID(linkage))
	key2 := utf16LE("parent_filename")
	value2 := utf16LE(hint)
	keyAt := 20 + 2*12
	valueAt := keyAt + len(key)
	key2At := valueAt + len(value)
	value2At := key2At + len(key2)
	bytes := make([]byte, value2At+len(value2))
	putLE16(bytes, 18, 2)
	entries := [][4]int{
		{keyAt, valueAt, len(key), len(value)},
		{key2At, value2At, len(key2), len(value2)},
	}
	for i, e := range entries {
		start := 20 + i*12
		putLE32(bytes, start, uint32(e[0]))
		putLE32(bytes, start+4, uint32(e[1]))
		putLE16(bytes, start+8, uint16(e[2]))
		putLE16(bytes, start+10, uint16(e[3]))
	}
	copy(bytes[keyAt:], key)
	copy(bytes[valueAt:], value)
	copy(bytes[key2At:], key2)
	copy(bytes[value2At:], value2)
	return bytes
}

type buildSpec struct {
	sectorSize  uint32
	writeGUID   [16]byte
	linkage     *[16]byte
	parentHint  string
	states      []uint64 // raw BAT state per payload block
	payload     [][]byte
	partialBits []byte
}

func buildVHDX(t *testing.T, spec buildSpec) []byte {
	t.Helper()
	blocks := len(spec.states)
	hasPartial := false
	for _, state := range spec.states {
		if state == blockPartiallyPresent {
			hasPartial = true
		}
	}
	sbOffset := testPayload + uint64(blocks)*testBlock
	fileLen := sbOffset
	if hasPartial {
		fileLen += 1 << 20
	}
	image := make([]byte, fileLen)
	copy(image[:8], Signature)

	header := make([]byte, headerSize)
	copy(header[:4], headerSignature)
	putLE64(header, 8, 1)
	copy(header[32:48], spec.writeGUID[:])
	putLE16(header, 66, 1)
	seal(header)
	copy(image[testHeader:], header)
	copy(image[2*testHeader:], header)

	regions := make([]byte, regionSize)
	copy(regions[:4], regionSignature)
	putLE32(regions, 8, 2)
	for i, entry := range []struct {
		guid   string
		offset uint64
		length uint64
	}{
		{metadataRegionGUID, testMetadata, 1 << 20},
		{batRegionGUID, testBAT, 2 << 20},
	} {
		start := 16 + i*metadataEntrySize
		copy(regions[start:], entry.guid)
		putLE64(regions, start+16, entry.offset)
		putLE32(regions, start+24, uint32(entry.length))
		putLE32(regions, start+28, 1)
	}
	seal(regions)
	copy(image[testRegions:], regions)
	copy(image[testRegions+testHeader:], regions)

	type item struct {
		id     string
		offset uint32
		value  []byte
	}
	parameters := make([]byte, 8)
	putLE32(parameters, 0, uint32(testBlock))
	if spec.linkage != nil {
		putLE32(parameters, 4, 2)
	}
	size := make([]byte, 8)
	putLE64(size, 0, uint64(blocks)*testBlock)
	diskID := bytes.Repeat([]byte{0x91}, 16)
	logical := make([]byte, 4)
	putLE32(logical, 0, spec.sectorSize)
	items := []item{
		{fileParametersID, 0x10000, parameters},
		{virtualDiskSizeID, 0x10008, size},
		{virtualDiskIDID, 0x10010, diskID},
		{logicalSectorSizeID, 0x10020, logical},
		{physicalSectorSizeID, 0x10024, logical},
	}
	if spec.linkage != nil {
		items = append(items, item{parentLocatorID, 0x10030, parentLocatorValue(*spec.linkage, spec.parentHint)})
	}
	tableLen := metadataHeaderSize + len(items)*metadataEntrySize
	table := make([]byte, tableLen)
	copy(table[:8], metadataSignature)
	putLE16(table, 10, uint16(len(items)))
	for i, it := range items {
		start := metadataHeaderSize + i*metadataEntrySize
		copy(table[start:], it.id)
		putLE32(table, start+16, it.offset)
		putLE32(table, start+20, uint32(len(it.value)))
		copy(image[testMetadata+uint64(it.offset):], it.value)
	}
	copy(image[testMetadata:], table)

	ratio := (uint64(1) << 23) * uint64(spec.sectorSize) / testBlock
	for i, state := range spec.states {
		entry := state
		switch state {
		case blockFullyPresent, blockPartiallyPresent:
			entry = testPayload + uint64(i)*testBlock | state
			if i < len(spec.payload) && len(spec.payload[i]) > 0 {
				copy(image[testPayload+uint64(i)*testBlock:], spec.payload[i])
			}
		}
		putLE64(image, int(testBAT)+i*8, entry)
		if state == blockPartiallyPresent {
			putLE64(image, int(testBAT)+int(ratio)*8, sbOffset|blockFullyPresent)
			copy(image[sbOffset:], spec.partialBits)
		}
	}
	return image
}

func openVHDX(t *testing.T, image []byte) *Source {
	t.Helper()
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, image))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return src
}

func TestVHDXDynamicStates(t *testing.T) {
	block0 := bytes.Repeat([]byte{'A'}, int(testBlock))
	image := buildVHDX(t, buildSpec{
		sectorSize: 512,
		states:     []uint64{blockFullyPresent, blockZero, blockNotPresent},
		payload:    [][]byte{block0},
	})
	src := openVHDX(t, image)
	if src.Len() != 3*testBlock || src.BlockSize() != testBlock || src.SectorSize() != 512 {
		t.Fatalf("geometry = len %d block %d sector %d", src.Len(), src.BlockSize(), src.SectorSize())
	}
	if src.Info().LogActive || src.Info().HeaderSequence != 1 {
		t.Fatalf("info = %+v", src.Info())
	}
	if src.BlockCount() != 3 {
		t.Fatalf("BlockCount = %d", src.BlockCount())
	}

	buf := make([]byte, 3*testBlock)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:testBlock], block0) {
		t.Fatal("fully present block did not read back")
	}
	if !bytes.Equal(buf[testBlock:], make([]byte, 2*testBlock)) {
		t.Fatal("zero/not-present blocks are not zero")
	}
	extents, err := src.Extents(0, src.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 3 || extents[0].Kind != source.RangeData ||
		extents[1].Kind != source.RangeZero || extents[2].Kind != source.RangeZero {
		t.Fatalf("extents = %+v", extents)
	}
	if extents[0].ParentOffset != testPayload {
		t.Fatalf("payload offset = %d, want %d", extents[0].ParentOffset, testPayload)
	}
}

func TestVHDXContainerInfo(t *testing.T) {
	image := buildVHDX(t, buildSpec{
		sectorSize: 4096,
		states:     []uint64{blockZero},
	})
	info, err := ReadContainerInfo(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("ReadContainerInfo error = %v", err)
	}
	if info.HasParent || info.VirtualDiskSize != testBlock || info.LogicalSectorSize != 4096 {
		t.Fatalf("info = %+v", info)
	}
}

func TestVHDXRejectsHeaderAndRegionDamage(t *testing.T) {
	image := buildVHDX(t, buildSpec{sectorSize: 512, states: []uint64{blockZero}})
	image[testHeader+8] ^= 0xFF
	image[2*testHeader+8] ^= 0xFF
	if _, err := Open(2, source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(bad headers) error = %v, want ErrCorrupt", err)
	}

	image = buildVHDX(t, buildSpec{sectorSize: 512, states: []uint64{blockZero}})
	image[testRegions+16] ^= 0xFF
	image[testRegions+testHeader+16] ^= 0xFF
	if _, err := Open(2, source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(bad regions) error = %v, want ErrCorrupt", err)
	}
}

func TestVHDXRejectsUndefinedBlock(t *testing.T) {
	image := buildVHDX(t, buildSpec{sectorSize: 512, states: []uint64{blockUndefined}})
	src := openVHDX(t, image)
	if _, err := src.ReadAt(0, make([]byte, 512)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("ReadAt error = %v, want ErrUnsupported", err)
	}
}

func TestVHDXDifferencingAndPartial(t *testing.T) {
	var parentGUID [16]byte
	for i := range parentGUID {
		parentGUID[i] = byte(0x40 + i)
	}
	parentBlock0 := bytes.Repeat([]byte{'P'}, int(testBlock))
	parentBlock1 := bytes.Repeat([]byte{'Q'}, int(testBlock))
	parentImage := buildVHDX(t, buildSpec{
		sectorSize: 512,
		writeGUID:  parentGUID,
		states:     []uint64{blockFullyPresent, blockFullyPresent, blockZero},
		payload:    [][]byte{parentBlock0, parentBlock1},
	})
	parent, err := Open(1, source.NewMemorySourceWithImage(1, 9, parentImage))
	if err != nil {
		t.Fatalf("parent Open error = %v", err)
	}

	childBlock0 := bytes.Repeat([]byte{'C'}, int(testBlock))
	childImage := buildVHDX(t, buildSpec{
		sectorSize: 512,
		writeGUID:  [16]byte{0xEE},
		linkage:    &parentGUID,
		parentHint: "parent.vhdx",
		states:     []uint64{blockFullyPresent, blockNotPresent, blockZero},
		payload:    [][]byte{childBlock0},
	})
	child, err := OpenWithParent(2, source.NewMemorySourceWithImage(1, 9, childImage), parent)
	if err != nil {
		t.Fatalf("OpenWithParent error = %v", err)
	}
	if child.Info().ParentLinkage == nil || *child.Info().ParentLinkage != parentGUID {
		t.Fatalf("linkage = %+v", child.Info().ParentLinkage)
	}
	if len(child.Info().ParentLocatorHints) != 1 || child.Info().ParentLocatorHints[0] != "parent.vhdx" {
		t.Fatalf("hints = %+v", child.Info().ParentLocatorHints)
	}
	buf := make([]byte, 3*testBlock)
	if _, err := child.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:testBlock], childBlock0) {
		t.Fatal("child block 0 did not read back")
	}
	if !bytes.Equal(buf[testBlock:2*testBlock], parentBlock1) {
		t.Fatal("not-present child block did not come from the parent")
	}
	if !bytes.Equal(buf[2*testBlock:], make([]byte, testBlock)) {
		t.Fatal("zero child block is not zero")
	}

	// Partial block: first eight 512-byte sectors from the child, the rest
	// from the parent.
	bits := make([]byte, 512)
	bits[0] = 0xFF
	partialImage := buildVHDX(t, buildSpec{
		sectorSize:  512,
		writeGUID:   [16]byte{0xEE},
		linkage:     &parentGUID,
		parentHint:  "parent.vhdx",
		states:      []uint64{blockPartiallyPresent, blockNotPresent, blockZero},
		payload:     [][]byte{childBlock0},
		partialBits: bits,
	})
	partial, err := OpenWithParent(2, source.NewMemorySourceWithImage(1, 9, partialImage), parent)
	if err != nil {
		t.Fatalf("OpenWithParent(partial) error = %v", err)
	}
	if _, err := partial.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:8*512], childBlock0[:8*512]) {
		t.Fatal("partial child sectors did not read back")
	}
	if !bytes.Equal(buf[8*512:testBlock], parentBlock0[8*512:]) {
		t.Fatal("partial parent sectors did not read back")
	}
}

func TestVHDXDifferencingRequiresParentAndChecksLinkage(t *testing.T) {
	var parentGUID [16]byte
	parentGUID[0] = 0x77
	childImage := buildVHDX(t, buildSpec{
		sectorSize: 512,
		writeGUID:  [16]byte{0xEE},
		linkage:    &parentGUID,
		parentHint: "parent.vhdx",
		states:     []uint64{blockZero},
	})
	if _, err := Open(2, source.NewMemorySource(1, childImage)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(child without parent) error = %v, want ErrUnsupported", err)
	}

	parentImage := buildVHDX(t, buildSpec{
		sectorSize: 512,
		writeGUID:  [16]byte{0x99},
		states:     []uint64{blockZero},
	})
	parent, err := Open(1, source.NewMemorySource(1, parentImage))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithParent(2, source.NewMemorySource(1, childImage), parent); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenWithParent(wrong linkage) error = %v, want ErrUnsupported", err)
	}
}
