package zfs

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// --- checksums ------------------------------------------------------------

func TestFletcher4AccumulatesEveryWord(t *testing.T) {
	one := leU64(0)[:4]
	le.PutUint32(one, 1)
	if got := fletcher4(one); got != [4]uint64{1, 1, 1, 1} {
		t.Fatalf("fletcher4(1) = %v", got)
	}
	two := make([]byte, 8)
	le.PutUint32(two[0:], 1)
	le.PutUint32(two[4:], 2)
	if got := fletcher4(two); got != [4]uint64{3, 4, 5, 6} {
		t.Fatalf("fletcher4(1,2) = %v", got)
	}
	three := append(two, make([]byte, 4)...)
	le.PutUint32(three[8:], 3)
	if got := fletcher4(three); got != [4]uint64{6, 10, 15, 21} {
		t.Fatalf("fletcher4(1,2,3) = %v", got)
	}
}

func TestFletcher2KeepsTwoChains(t *testing.T) {
	bytes := make([]byte, 32)
	for i := uint64(1); i <= 4; i++ {
		le.PutUint64(bytes[(i-1)*8:], i)
	}
	if got := fletcher2(bytes); got != [4]uint64{4, 6, 5, 8} {
		t.Fatalf("fletcher2 = %v", got)
	}
}

func TestChecksumVerifyMismatchAndUnknown(t *testing.T) {
	bytes := bytes.Repeat([]byte{7}, 512)
	stored := fletcherChecksumBytes(bytes, 7)
	ok, err := verifyChecksum(ChecksumFletcher4, bytes, stored)
	if err != nil || !ok {
		t.Fatalf("verify = %v, %v", ok, err)
	}
	wrong := append([]byte(nil), stored...)
	wrong[0] ^= 1
	ok, err = verifyChecksum(ChecksumFletcher4, bytes, wrong)
	if err != nil || ok {
		t.Fatalf("mismatched verify = %v, %v", ok, err)
	}
	if _, err := verifyChecksum(ChecksumOther, bytes, stored); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("unknown checksum = %v, want ErrUnsupported", err)
	}
	if _, err := verifyChecksum(ChecksumFletcher4, bytes[:511], stored); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("unaligned fletcher4 = %v, want ErrUnsupported", err)
	}
	if _, err := verifyChecksum(ChecksumFletcher4, bytes, stored[:31]); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("short stored checksum = %v, want ErrUnsupported", err)
	}
}

func TestSHA256StoredWordOrder(t *testing.T) {
	payload := []byte("zfs")
	digest := sha256.Sum256(payload)
	// The raw digest is not the on-disk order.
	if ok, err := verifyChecksum(ChecksumSHA256, payload, digest[:]); err != nil || ok {
		t.Fatalf("raw digest verify = %v, %v", ok, err)
	}
	stored := append([]byte(nil), digest[:]...)
	for i := 0; i < 32; i += 8 {
		reverse8(stored[i : i+8])
	}
	if ok, err := verifyChecksum(ChecksumSHA256, payload, stored); err != nil || !ok {
		t.Fatalf("word-swapped digest verify = %v, %v", ok, err)
	}
	if ok, _ := verifyChecksum(ChecksumSHA256, []byte("ZFS"), stored); ok {
		t.Fatal("different bytes verified")
	}
}

func TestChecksumIDs(t *testing.T) {
	cases := map[byte]Checksum{
		0:  ChecksumInherit,
		1:  ChecksumFletcher4,
		2:  ChecksumOff,
		6:  ChecksumFletcher2,
		7:  ChecksumFletcher4,
		8:  ChecksumSHA256,
		9:  ChecksumFletcher4,
		12: ChecksumOther,
	}
	for id, want := range cases {
		if got := checksumFromID(id); got != want {
			t.Fatalf("checksumFromID(%d) = %v, want %v", id, got, want)
		}
	}
	if name := ChecksumOther.name(12); !strings.Contains(name, "12") {
		t.Fatalf("other checksum name = %q", name)
	}
}

// --- block pointers -------------------------------------------------------

func TestBlockPointerFields(t *testing.T) {
	img := newTestImage()
	data := make([]byte, 16*1024)
	copy(data, "block pointer")
	phys := img.alloc(data)
	bpBytes := diskPointer(img, phys, 16*1024, 16*1024, 19, 0, 7, 2, 42, nil)
	bp, err := parseBlockPointer(bpBytes)
	if err != nil {
		t.Fatalf("parseBlockPointer: %v", err)
	}
	if bp.embedded() || bp.level() != 0 || bp.objectType() != 19 {
		t.Fatalf("pointer = %+v", bp)
	}
	if bp.checksum() != ChecksumFletcher4 || bp.compression() != CompressionOff {
		t.Fatalf("checksum %v compression %v", bp.checksum(), bp.compression())
	}
	if bp.lsize() != 16*1024 || bp.psize() != 16*1024 {
		t.Fatalf("sizes = %d/%d", bp.lsize(), bp.psize())
	}
	if bp.logicalBirth() != 42 || bp.physicalBirth() != 42 {
		t.Fatalf("births = %d/%d", bp.logicalBirth(), bp.physicalBirth())
	}
	dva, ok := bp.dva(0)
	if !ok {
		t.Fatal("no first DVA")
	}
	if dva.vdev() != 0 || dva.asize() != 16*1024 || dva.offset() != phys-VDevLabelStartSize {
		t.Fatalf("dva = vdev %d asize %d offset %d", dva.vdev(), dva.asize(), dva.offset())
	}
	if _, ok := bp.dva(3); ok {
		t.Fatal("a pointer has three DVAs")
	}
	if !bytes.Equal(bp.checksumBytes(), fletcherChecksumBytes(data, 7)) {
		t.Fatal("stored checksum bytes differ")
	}
}

func TestHoleAndEmbeddedPointers(t *testing.T) {
	hole, err := parseBlockPointer(make([]byte, 128))
	if err != nil {
		t.Fatalf("parse hole: %v", err)
	}
	if !hole.isHole() || hole.lsize() != 512 || hole.psize() != 512 {
		t.Fatalf("hole = %+v", hole)
	}
	payload := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	embedded, err := parseBlockPointer(embeddedPointer(payload, 36, 36, 19, 2, 0))
	if err != nil {
		t.Fatalf("parse embedded: %v", err)
	}
	if !embedded.embedded() || embedded.isHole() {
		t.Fatalf("embedded flags = %+v", embedded)
	}
	if embedded.checksum() != ChecksumOff {
		t.Fatalf("embedded checksum = %v", embedded.checksum())
	}
	got, err := embedded.embeddedPayload()
	if err != nil {
		t.Fatalf("embeddedPayload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q", got)
	}
}

func TestEmbeddedPayloadTooLarge(t *testing.T) {
	bpBytes := make([]byte, 128)
	prop := (uint64(1) << 39) | (uint64(112) << 25)
	le.PutUint64(bpBytes[48:], prop)
	bp, err := parseBlockPointer(bpBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := bp.embeddedPayload(); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("embeddedPayload = %v, want ErrCorrupt", err)
	}
}

func TestBlockPointerByteOrderBitIsInformational(t *testing.T) {
	img := newTestImage()
	data := make([]byte, 512)
	phys := img.alloc(data)
	raw := diskPointer(img, phys, 512, 512, 19, 0, 7, 2, 0, nil)
	le.PutUint64(raw[48:], le.Uint64(raw[48:])|(uint64(1)<<63))
	bp, err := parseBlockPointer(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bp.byteOrderBit() || bp.lsize() != 512 {
		t.Fatalf("byte order bit handling: %+v", bp)
	}
}

// --- uberblocks -----------------------------------------------------------

func TestUberblockParseAndSort(t *testing.T) {
	root := make([]byte, 128)
	slot := buildUberblock(99, 7, root)
	uberblock, err := parseUberblock(slot, 2, 17)
	if err != nil {
		t.Fatalf("parseUberblock: %v", err)
	}
	if uberblock == nil {
		t.Fatal("no uberblock")
	}
	if uberblock.TXG != 99 || uberblock.Version != spaVersion || uberblock.GUIDSum != 7 {
		t.Fatalf("uberblock = %+v", uberblock)
	}
	if uberblock.Label != 2 || uberblock.Slot != 17 {
		t.Fatalf("position = %d/%d", uberblock.Label, uberblock.Slot)
	}

	ring := make([]byte, UberblockRingSize)
	copy(ring, buildUberblock(1, 1, root))
	copy(ring[3*UberblockSize:], buildUberblock(9, 1, root))
	blocks, problems := scanUberblockRing(ring, 0)
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
	if len(blocks) != 2 || blocks[0].TXG != 9 || blocks[0].Slot != 3 || blocks[1].TXG != 1 {
		t.Fatalf("blocks = %+v", blocks)
	}
}

func TestUberblockBadVersionAndTXG(t *testing.T) {
	root := make([]byte, 128)
	slot := buildUberblock(10, 1, root)
	le.PutUint64(slot[8:], 9001)
	if _, err := parseUberblock(slot, 0, 0); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("version error = %v, want ErrUnsupported", err)
	}
	slot = buildUberblock(0, 1, root)
	if _, err := parseUberblock(slot, 0, 0); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("txg zero error = %v, want ErrCorrupt", err)
	}
	if block, err := parseUberblock(make([]byte, 100), 0, 0); err == nil || block != nil {
		t.Fatalf("short slot = %v, %v", block, err)
	} else if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short slot error = %v", err)
	}
}

// --- labels ---------------------------------------------------------------

func TestLabelOffsets(t *testing.T) {
	offsets := labelOffsets(4 << 20)
	if len(offsets) != 4 {
		t.Fatalf("offsets = %+v", offsets)
	}
	if offsets[0].offset != 0 || offsets[1].offset != 256<<10 {
		t.Fatalf("head pair = %+v", offsets)
	}
	if offsets[2].offset != (4<<20)-2*(256<<10) || offsets[3].offset != (4<<20)-(256<<10) {
		t.Fatalf("tail pair = %+v", offsets)
	}
	if got := labelOffsets((4 << 20) + 512); len(got) != 2 {
		t.Fatalf("unaligned offsets = %+v", got)
	}
}

func TestNVListDecode(t *testing.T) {
	nested := xdrList(xdrPair("type", xdrTypeString, 1, xdrString("disk")))
	data := xdrList(
		xdrPair("name", xdrTypeString, 1, xdrString("tank")),
		xdrPair("guid", xdrTypeUint64, 1, xdrU64(0x11223344)),
		xdrPair("vdev_tree", xdrTypeNvlist, 1, nested),
	)
	list, err := parseNvlist(data)
	if err != nil {
		t.Fatalf("parseNvlist: %v", err)
	}
	if list.String("name") != "tank" {
		t.Fatalf("name = %q", list.String("name"))
	}
	if value, ok := list.Unsigned("guid"); !ok || value != 0x11223344 {
		t.Fatalf("guid = %d %v", value, ok)
	}
	if child := list.List("vdev_tree"); child == nil || child.String("type") != "disk" {
		t.Fatalf("nested = %+v", child)
	}
}

func TestNVListMarkerAndTrailing(t *testing.T) {
	plain := xdrList(xdrPair("name", xdrTypeString, 1, xdrString("zroot")))
	marked := append(xdrU32(0x01010000), plain...)
	list, err := parseNvlist(marked)
	if err != nil {
		t.Fatalf("marked list: %v", err)
	}
	if list.String("name") != "zroot" {
		t.Fatalf("name = %q", list.String("name"))
	}
	withTrailing := append(append([]byte(nil), plain...), 0, 0, 0, 7)
	if _, err := parseNvlist(withTrailing); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("trailing bytes = %v, want ErrCorrupt", err)
	}
}

func TestNVListPairSizeLies(t *testing.T) {
	data := xdrList(xdrPair("name", xdrTypeString, 1, xdrString("tank")))
	data[8] = 0x7f
	if _, err := parseNvlist(data); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("pair size = %v, want ErrCorrupt", err)
	}
	versionTwo := xdrList()
	versionTwo[3] = 2
	if _, err := parseNvlist(versionTwo); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("version 2 = %v, want ErrUnsupported", err)
	}
}

func TestNVListStringAndArrayBounds(t *testing.T) {
	// A string that includes its NUL terminator in the declared length.
	value := xdrU32(4)
	value = append(value, "abc\x00"...)
	// Length 4 with a trailing zero is refused.
	data := xdrList(xdrPair("name", xdrTypeString, 1, value))
	if _, err := parseNvlist(data); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("NUL-terminated string length = %v", err)
	}
	// An array whose XDR count disagrees with its declared element count.
	arrayValue := xdrU32(2)
	arrayValue = append(arrayValue, xdrU64(1)...)
	data = xdrList(xdrPair("values", xdrTypeUint64, 1, arrayValue))
	if _, err := parseNvlist(data); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("array mismatch = %v", err)
	}
	// An unsupported data type is refused by number.
	data = xdrList(xdrPair("odd", 999, 1, nil))
	if _, err := parseNvlist(data); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("unknown type = %v", err)
	}
}

// --- dnodes ---------------------------------------------------------------

func TestDnodeParseAndBonus(t *testing.T) {
	node := buildDnode(dnodeSpec{
		kind:         dmuOtDslDataset,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtDslDataset,
		checksum:     7,
		compress:     2,
		datablkszsec: 32,
		maxblkid:     9,
		pointers:     [][]byte{make([]byte, 128)},
		bonus:        []byte{7, 7, 7, 7},
	})
	parsed, err := parseDnode(node, 3)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	if parsed.dataBlockSize() != 16*1024 || parsed.maxBlkID != 9 || parsed.isFree() {
		t.Fatalf("dnode = %+v", parsed)
	}
	if len(parsed.bonus) != 4 || parsed.bonus[0] != 7 {
		t.Fatalf("bonus = %v", parsed.bonus)
	}
}

func TestDnodeRejectsBadBonusAndLevels(t *testing.T) {
	base := dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtPlainFile,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers:     [][]byte{make([]byte, 128)},
		bonus:        []byte{0, 0},
	}
	tooLong := base
	tooLong.bonus = make([]byte, 400)
	if _, err := parseDnode(buildDnode(tooLong), 1); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bonus too long = %v", err)
	}
	deep := base
	deep.nlevels = 13
	if _, err := parseDnode(buildDnode(deep), 1); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("nlevels 13 = %v", err)
	}
	noPointer := base
	noPointer.pointers = nil
	if _, err := parseDnode(buildDnode(noPointer), 1); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("live dnode with no pointer = %v", err)
	}
	free := buildDnode(dnodeSpec{kind: 0})
	parsed, err := parseDnode(free, 4)
	if err != nil {
		t.Fatalf("free slot: %v", err)
	}
	if !parsed.isFree() || parsed.dataBlockSize() != 0 {
		t.Fatalf("free dnode = %+v", parsed)
	}
	short := make([]byte, 511)
	if _, err := parseDnode(short, 1); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short dnode = %v", err)
	}
}

func TestDnodeExtraSlotsAndSpill(t *testing.T) {
	spill := make([]byte, 128)
	spec := dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    17,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		extraSlots:   1,
		flags:        0x04,
		pointers:     [][]byte{make([]byte, 128)},
		bonus:        []byte{1, 2, 3, 4},
		spill:        spill,
	}
	node, err := parseDnode(buildDnode(spec), 5)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	if node.slotCount() != 2 || node.spillPointer() == nil {
		t.Fatalf("slot count %d spill %v", node.slotCount(), node.spillPointer())
	}
	if len(node.bonus) != 4 {
		t.Fatalf("bonus = %v", node.bonus)
	}
	// Claiming more slots than were read is refused.
	out := buildDnode(spec)
	out[12] = 3
	if _, err := parseDnode(out, 5); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short extra slots = %v", err)
	}
}

func TestObjectNumberBounds(t *testing.T) {
	objset := &Objset{}
	if _, err := objset.dnode(nil, 1<<48); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("object over 48 bits = %v", err)
	}
}

func TestIndirectTreeIndexesByDataBlock(t *testing.T) {
	img := newTestImage()
	indirect := make([]byte, 1024)
	for index := 0; index < 8; index++ {
		payload := append([]byte("block"), byte('0'+index))
		pointer := embeddedPointer(payload, uint64(len(payload)), uint64(len(payload)), dmuOtPlainFile, 2, 0)
		copy(indirect[index*128:], pointer)
	}
	phys := img.alloc(indirect)
	top := diskPointer(img, phys, 1024, 1024, dmuOtPlainFile, 1, 7, 2, 0, nil)
	nodeBytes := buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  10,
		nlevels:      2,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers:     [][]byte{top},
	})
	node, err := parseDnode(nodeBytes, 9)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	reader := newBlockReader(source.NewMemorySource(0, img.data))
	for index := 0; index < 8; index++ {
		got, err := readObject(reader, node, uint64(index*512), 6)
		if err != nil {
			t.Fatalf("read block %d: %v", index, err)
		}
		want := append([]byte("block"), byte('0'+index))
		if !bytes.Equal(got, want) {
			t.Fatalf("block %d = %q", index, got)
		}
	}
	if _, err := readObject(reader, node, 8*512, 1); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("read past direct pointers = %v", err)
	}
}

func TestDataBlocksWindowAndHoles(t *testing.T) {
	node := buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers: [][]byte{
			embeddedPointer([]byte("first block"), 512, 11, dmuOtPlainFile, 2, 0),
			make([]byte, 128),
			embeddedPointer([]byte("third block"), 512, 11, dmuOtPlainFile, 2, 0),
		},
	})
	parsed, err := parseDnode(node, 5)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	reader := newBlockReader(source.NewMemorySource(0, nil))
	var blocks []ObjectBlock
	if err := dataBlocksInto(reader, parsed, 300, 800, &blocks); err != nil {
		t.Fatalf("dataBlocksInto: %v", err)
	}
	if len(blocks) != 3 {
		t.Fatalf("blocks = %+v", blocks)
	}
	if blocks[0].logical != 0 || blocks[1].logical != 512 || blocks[2].logical != 1024 {
		t.Fatalf("logical offsets = %+v", blocks)
	}
	if !blocks[1].pointer.isHole() {
		t.Fatal("middle block is not a hole")
	}
	blocks = nil
	if err := dataBlocksInto(reader, parsed, 300, 400, &blocks); err != nil || len(blocks) != 2 {
		t.Fatalf("narrow window = %+v, %v", blocks, err)
	}
	if err := dataBlocksInto(reader, parsed, 1536, 512, &blocks); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("past direct pointers = %v", err)
	}
	// A whole-file provenance walk is bounded.
	var huge []ObjectBlock
	err = dataBlocksInto(reader, parsed, 0, (maxProvenanceBlocks+10)*512, &huge)
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("unbounded provenance = %v", err)
	}
}

// --- ZAPs -----------------------------------------------------------------

func TestMicroZAPEntries(t *testing.T) {
	block := buildMicroZAP([]microEntry{
		{"root_dataset", leU64(2)},
		{"config", leU64(3)},
	})
	entries, truncated, err := microEntries(block, 100)
	if err != nil {
		t.Fatalf("microEntries: %v", err)
	}
	if truncated || len(entries) != 2 {
		t.Fatalf("entries = %+v truncated %v", entries, truncated)
	}
	if entries[0].name != "root_dataset" || le.Uint64(entries[0].value) != 2 {
		t.Fatalf("first = %+v", entries[0])
	}
	if entries[0].value == nil {
		t.Fatal("micro value is nil")
	}
}

func TestMicroZAPBounds(t *testing.T) {
	block := buildMicroZAP([]microEntry{{"x", leU64(1)}})
	for i := 64 + 14; i < 64+64; i++ {
		block[i] = 'a'
	}
	if _, _, err := microEntries(block, 100); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("unterminated name = %v", err)
	}
	if _, _, err := microEntries(make([]byte, 100), 100); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("unaligned micro block = %v", err)
	}
}

func TestFatZAPLeafAndIntegerOrder(t *testing.T) {
	data := buildFatZAP([]fatEntry{
		{"ok", leU64(42), 8},
		{"two", append(leU64(1), leU64(0x0102030405060708)...), 8},
	})
	leaf := data[2048:]
	entries, truncated, err := leafEntries(leaf, 100)
	if err != nil {
		t.Fatalf("leafEntries: %v", err)
	}
	if truncated || len(entries) != 2 {
		t.Fatalf("entries = %+v truncated %v", entries, truncated)
	}
	if entries[0].name != "ok" || le.Uint64(entries[0].value) != 42 {
		t.Fatalf("first = %+v", entries[0])
	}
	if le.Uint64(entries[1].value[0:]) != 1 || le.Uint64(entries[1].value[8:]) != 0x0102030405060708 {
		t.Fatalf("integers = %x", entries[1].value)
	}
}

func TestFatZAPLeafRefusalsAndChainLoop(t *testing.T) {
	data := buildFatZAP([]fatEntry{{"name", leU64(1), 8}})
	leaf := append([]byte(nil), data[2048:]...)
	// A name without its NUL terminator.
	chunksStart := 48 + 2*(len(leaf)/32)
	nameChunk := chunksStart + leafChunkSize
	leaf[nameChunk+1+4] = 'y'
	if _, _, err := leafEntries(leaf, 100); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("name without NUL = %v", err)
	}

	// A chain that points back to itself never ends.
	loopLeaf := make([]byte, 512)
	le.PutUint64(loopLeaf[0:], zapZBTLeaf)
	le.PutUint32(loopLeaf[24:], zapLeafMagic)
	chunksStart = 48 + 2*(len(loopLeaf)/32)
	entry := chunksStart
	loopLeaf[entry] = chunkEntry
	loopLeaf[entry+1] = 1
	le.PutUint16(loopLeaf[entry+4:], 1)
	le.PutUint16(loopLeaf[entry+6:], 1024)
	le.PutUint16(loopLeaf[entry+8:], 2)
	le.PutUint16(loopLeaf[entry+10:], 1)
	first := chunksStart + leafChunkSize
	loopLeaf[first] = chunkArray
	loopLeaf[first+1] = 'a'
	le.PutUint16(loopLeaf[first+22:], 1) // points to itself
	if _, _, err := leafEntries(loopLeaf, 100); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("chain loop = %v", err)
	}

	// A leaf chunk that claims to be an entry but whose name chain runs into
	// a non-array chunk is refused.
	badLeaf := make([]byte, 512)
	le.PutUint64(badLeaf[0:], zapZBTLeaf)
	le.PutUint32(badLeaf[24:], zapLeafMagic)
	entry = chunksStart
	badLeaf[entry] = chunkEntry
	le.PutUint16(badLeaf[entry+4:], 1)
	le.PutUint16(badLeaf[entry+6:], 1)
	le.PutUint16(badLeaf[entry+8:], 2)
	le.PutUint16(badLeaf[entry+10:], 1)
	first = chunksStart + leafChunkSize
	badLeaf[first] = chunkEntry
	if _, _, err := leafEntries(badLeaf, 100); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bad chain type = %v", err)
	}
}

func TestFatZAPLeafMagicAndSize(t *testing.T) {
	leaf := make([]byte, 512)
	le.PutUint64(leaf[0:], zapZBTLeaf)
	le.PutUint32(leaf[24:], 0xdeadbeef)
	if _, _, err := leafEntries(leaf, 100); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bad leaf magic = %v", err)
	}
	if _, _, err := leafEntries(make([]byte, 100), 100); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("non-power-of-two leaf = %v", err)
	}
}

// --- ZPL ------------------------------------------------------------------

func TestZplDirentSplit(t *testing.T) {
	home, err := parseZplEntry("home", leU64(0x4000000000000002))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if home.object != 2 || home.dtype != DTypeDirectory {
		t.Fatalf("home = %+v", home)
	}
	entry, err := parseZplEntry(".cshrc", leU64(0x8000000000000105))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entry.object != 261 || entry.dtype != DTypeRegular {
		t.Fatalf("cshrc = %+v", entry)
	}
	if _, err := parseZplEntry("meta", leU64(0)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("object 0 = %v", err)
	}
	if _, err := parseZplEntry("short", []byte{1, 2, 3}); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short value = %v", err)
	}
	if object, ok := objectOf(leU64(0x4000000000000002)); !ok || object != 2 {
		t.Fatalf("objectOf = %d %v", object, ok)
	}
	if object, ok := objectOf([]byte{1}); ok || object != 0 {
		t.Fatalf("objectOf(short) = %d %v", object, ok)
	}
}

func TestDTypeLabels(t *testing.T) {
	cases := map[uint8]string{
		0: "unknown", 1: "fifo", 2: "character device", 4: "directory",
		6: "block device", 8: "regular file", 10: "symbolic link",
		12: "socket", 14: "whiteout", 3: "other",
	}
	for bits, want := range cases {
		if got := dTypeFromBits(bits).label(); got != want {
			t.Fatalf("dType(%d).label() = %q, want %q", bits, got, want)
		}
	}
}

// --- decompression --------------------------------------------------------

func TestZLEDecoder(t *testing.T) {
	stored := []byte{2, 'a', 'b', 'c', 0xff}
	out, err := decompressBlock(CompressionZLE, stored, 195, "a block")
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(out[:3]) != "abc" || !allZero(out[3:]) || len(out) != 195 {
		t.Fatalf("output = %q", out[:5])
	}
	if _, err := decompressBlock(CompressionZLE, []byte{2, 'a'}, 10, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("truncated literal run = %v", err)
	}
}

func TestLZJBDecoder(t *testing.T) {
	// Bitmap 0b0000_0010: literal, then a back reference of length 3,
	// distance 1.
	out, err := decompressBlock(CompressionLZJB, []byte{0x02, 'x', 0x00, 0x01}, 4, "a block")
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(out) != "xxxx" {
		t.Fatalf("output = %q", out)
	}
	if _, err := decompressBlock(CompressionLZJB, []byte{0x01, 0x00, 0x05}, 3, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("back reference before the block = %v", err)
	}
	if _, err := decompressBlock(CompressionLZJB, []byte{0x00}, 2, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("truncated literal = %v", err)
	}
}

func TestLZ4Decoder(t *testing.T) {
	stored := append([]byte{0, 0, 0, 0}, make([]byte, 4)...)
	if _, err := decompressBlock(CompressionLZ4, stored, 512, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("zero length = %v", err)
	}
	stored = append([]byte{0, 0, 0, 100}, make([]byte, 4)...)
	if _, err := decompressBlock(CompressionLZ4, stored, 512, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("length past block = %v", err)
	}
	var body []byte
	body = append(body, 0x50)
	body = append(body, []byte("hello")...)
	block := make([]byte, 4, 4+len(body)+2)
	binary.BigEndian.PutUint32(block, uint32(len(body)))
	block = append(block, body...)
	block = append(block, 0, 0) // sector rounding after the stream
	out, err := decompressBlock(CompressionLZ4, block, 5, "a block")
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("output = %q", out)
	}
	// A match may overlap its own output.
	overlap := []byte{0x12, 'a', 0x01, 0x00} // one literal 'a', match len 6 dist 1
	block = make([]byte, 4, 4+len(overlap))
	binary.BigEndian.PutUint32(block, uint32(len(overlap)))
	block = append(block, overlap...)
	out, err = decompressBlock(CompressionLZ4, block, 7, "a block")
	if err != nil {
		t.Fatalf("overlap decompress: %v", err)
	}
	if string(out) != "aaaaaaa" {
		t.Fatalf("overlap output = %q", out)
	}
}

func TestGzipDecoder(t *testing.T) {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write([]byte("gzip payload")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := decompressBlock(CompressionGzip, buf.Bytes(), 12, "a block")
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(out) != "gzip payload" {
		t.Fatalf("output = %q", out)
	}
	if _, err := decompressBlock(CompressionGzip, []byte{0xff, 0xff}, 12, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("garbage gzip = %v", err)
	}
}

func TestDecompressionRefusalsAndSizes(t *testing.T) {
	if _, err := decompressBlock(CompressionZstd, []byte{1, 2, 3}, 3, "a block"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("zstd = %v, want ErrUnsupported", err)
	}
	if _, err := decompressBlock(CompressionOther, []byte{1, 2, 3}, 3, "a block"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("other = %v, want ErrUnsupported", err)
	}
	if _, err := decompressBlock(CompressionOff, []byte{1, 2, 3}, 4, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("length mismatch = %v, want ErrCorrupt", err)
	}
	// A logical size over 16 MiB is refused before allocation.
	if _, err := decompressBlock(CompressionEmpty, nil, maxBlockSize+1, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("oversize logical = %v", err)
	}
}

// --- SA -------------------------------------------------------------------

func testSATables() *SaTables {
	layouts := map[uint16][]uint16{2: saLayout2, 3: saLayout3}
	attributes := map[uint16]SaAttribute{}
	for _, spec := range testSA {
		attributes[spec.id] = SaAttribute{ID: spec.id, Name: spec.name, Length: spec.length}
	}
	return &SaTables{layouts: layouts, attributes: attributes}
}

func TestDecodeSABuffer(t *testing.T) {
	tables := testSATables()
	values := defaultSAValues(testModeRegular, 1234)
	buffer := buildSABuffer(2, saLayout2, values)
	layout, decoded, err := decodeSABuffer(buffer, tables, 9, "bonus")
	if err != nil {
		t.Fatalf("decodeSABuffer: %v", err)
	}
	if layout != 2 {
		t.Fatalf("layout = %d", layout)
	}
	if le.Uint64(decoded["ZPL_MODE"]) != testModeRegular {
		t.Fatalf("mode = %x", decoded["ZPL_MODE"])
	}
	if le.Uint64(decoded["ZPL_SIZE"]) != 1234 {
		t.Fatalf("size = %d", le.Uint64(decoded["ZPL_SIZE"]))
	}
	if string(decoded["ZPL_ATIME"][:8]) != string(leU64(1_700_000_000)) {
		t.Fatalf("atime = %x", decoded["ZPL_ATIME"])
	}
}

func TestDecodeSAHeaderErrors(t *testing.T) {
	tables := testSATables()
	buffer := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 1))
	buffer[4] = 2 | (2 << 2) // header says 16 bytes (2*8), layout says 8
	if _, _, err := decodeSABuffer(buffer, tables, 3, "bonus"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("header mismatch = %v", err)
	}

	unknown := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 1))
	le.PutUint16(unknown[4:], 7|(1<<10))
	if _, _, err := decodeSABuffer(unknown, tables, 4, "bonus"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("unknown layout = %v", err)
	} else if !strings.Contains(err.Error(), "layout 7") {
		t.Fatalf("unknown layout error = %v", err)
	}

	missingTables := testSATables()
	missingTables.layouts[2] = append([]uint16{99}, saLayout2...)
	missingID := make([]byte, 8)
	le.PutUint32(missingID[0:], saMagic)
	le.PutUint16(missingID[4:], 2|(1<<10))
	if _, _, err := decodeSABuffer(missingID, missingTables, 5, "bonus"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("unregistered attribute = %v", err)
	} else if !strings.Contains(err.Error(), "99") {
		t.Fatalf("unregistered id error = %v", err)
	}

	if layout, values, err := decodeSABuffer(make([]byte, 64), tables, 1, "bonus"); err != nil || layout != 0 || len(values) != 0 {
		t.Fatalf("zero magic = %d %v %v", layout, values, err)
	}

	overrun := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 1))
	overrun = overrun[:len(overrun)-1]
	if _, _, err := decodeSABuffer(overrun, tables, 6, "bonus"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("attribute overrun = %v", err)
	}
}

func saValuesByName(values map[uint16][]byte) map[string][]byte {
	out := make(map[string][]byte, len(values))
	for id, value := range values {
		out[saSpec(id).name] = value
	}
	return out
}

func TestSummarizeAttributes(t *testing.T) {
	values := saValuesByName(defaultSAValues(0o100644, 1234))
	summary, err := summarizeAttributes(7, dmuOtPlainFile, AttributeSource{Layout: 2}, values)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if summary.Kind != DTypeRegular || summary.Size == nil || *summary.Size != 1234 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.UID == nil || *summary.UID != 1000 || summary.GID == nil || *summary.GID != 1000 {
		t.Fatalf("owner = %+v", summary)
	}
	if summary.Atime == nil || summary.Atime.Seconds != 1_700_000_000 || summary.Atime.Nanos != 123 {
		t.Fatalf("atime = %+v", summary.Atime)
	}
	if summary.Btime == nil || summary.Btime.Seconds != 1_700_000_300 {
		t.Fatalf("btime = %+v", summary.Btime)
	}
	if summary.Links == nil || *summary.Links != 1 || summary.Parent == nil || *summary.Parent != 2 {
		t.Fatalf("links/parent = %+v", summary)
	}

	// A symlink whose size disagrees with its target is refused.
	symlink := defaultSAValues(0o120777, 99)
	symlink[12] = []byte("/etc")
	if _, err := summarizeAttributes(8, dmuOtPlainFile, AttributeSource{Layout: 3}, saValuesByName(symlink)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("symlink size mismatch = %v", err)
	}
	// A nanosecond field past the end of its second is refused.
	bad := defaultSAValues(0o100644, 1)
	bad[6] = testTime(1, 1_000_000_000)
	if _, err := summarizeAttributes(9, dmuOtPlainFile, AttributeSource{Layout: 2}, saValuesByName(bad)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bad nanoseconds = %v", err)
	}
	// A mode-less directory is still a directory because its dnode says so.
	emptyMode := defaultSAValues(0o100644, 0)
	delete(emptyMode, 1)
	summary, err = summarizeAttributes(10, dmuOtDirectoryContents, AttributeSource{Layout: 2}, saValuesByName(emptyMode))
	if err != nil {
		t.Fatalf("directory summary: %v", err)
	}
	if summary.Kind != DTypeDirectory {
		t.Fatalf("directory kind = %v", summary.Kind)
	}
	if summary.Mode != nil {
		t.Fatalf("absent mode = %v", *summary.Mode)
	}
}

func TestSATablesRegistry(t *testing.T) {
	tables := testSATables()
	if got := tables.layout(2); len(got) != len(saLayout2) {
		t.Fatalf("layout 2 = %v", got)
	}
	if got, ok := tables.attribute(12); !ok || got.Name != "ZPL_SYMLINK" || got.Length != 0 {
		t.Fatalf("attribute 12 = %+v %v", got, ok)
	}
	if got, ok := tables.attributeByName("ZPL_MODE"); !ok || got.ID != 1 || got.Length != 8 {
		t.Fatalf("attribute by name = %+v %v", got, ok)
	}
}

// --- datasets -------------------------------------------------------------

func TestDatasetAndDslDirParse(t *testing.T) {
	bp := make([]byte, 128)
	bonus := datasetBonus(2, 1, 1_700_000_000, 123, 7, 10, 20, 30, 44, bp)
	phys, err := parseDatasetPhys(bonus)
	if err != nil {
		t.Fatalf("parseDatasetPhys: %v", err)
	}
	if phys.dirObj != 2 || phys.numChildren != 1 || !phys.isSnapshot() {
		t.Fatalf("dataset = %+v", phys)
	}
	if phys.creationTime != 1_700_000_000 || phys.creationTXG != 123 {
		t.Fatalf("creation = %d/%d", phys.creationTime, phys.creationTXG)
	}
	if phys.bp.lsize() != 512 {
		t.Fatalf("ds_bp lsize = %d", phys.bp.lsize())
	}
	if _, err := parseDatasetPhys(make([]byte, 200)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short dataset bonus = %v", err)
	}

	dir, err := parseDslDirPhys(dslDirBonus(2, 0, 9, 11))
	if err != nil {
		t.Fatalf("parseDslDirPhys: %v", err)
	}
	if dir.headDatasetObj != 2 || dir.parentObj != 0 || dir.childDirZapObj != 9 || dir.propsZapObj != 11 {
		t.Fatalf("dsl dir = %+v", dir)
	}
	short := dslDirBonus(2, 0, 9, 11)[:40]
	dir, err = parseDslDirPhys(short)
	if err != nil {
		t.Fatalf("short dsl dir: %v", err)
	}
	if dir.propsZapObj != 0 {
		t.Fatalf("property map in a short bonus = %d", dir.propsZapObj)
	}
}

// --- block reader bounds --------------------------------------------------

func TestBlockReaderBoundsAndRefusals(t *testing.T) {
	img := newTestImage()
	src := source.NewMemorySource(1, img.data)
	reader := newBlockReader(src)

	// A pointer into another vdev is refused by name on a single image.
	other := make([]byte, 128)
	le.PutUint64(other[0:], 1<<32|1)
	le.PutUint64(other[8:], 1)
	prop := uint64(0) | (0 << 16) | (2 << 32) | (2 << 40)
	le.PutUint64(other[48:], prop)
	bp, err := parseBlockPointer(other)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := reader.read(bp); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("vdev 1 = %v, want ErrUnsupported", err)
	}

	// A pointer whose extent runs into the trailing labels is refused.
	beyond := make([]byte, 128)
	le.PutUint64(beyond[0:], 1)
	le.PutUint64(beyond[8:], (uint64(len(img.data))-VDevLabelStartSize)>>9)
	le.PutUint64(beyond[48:], prop)
	bp, err = parseBlockPointer(beyond)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := reader.read(bp); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("past allocatable area = %v, want ErrCorrupt", err)
	}

	// A block larger than 16 MiB is refused before allocation.
	huge := make([]byte, 128)
	le.PutUint64(huge[0:], 1)
	le.PutUint64(huge[8:], 1)
	le.PutUint64(huge[48:], 0xffff|(0xffff<<16)) // lsize = 65536 sectors = 32 MiB
	bp, err = parseBlockPointer(huge)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := reader.read(bp); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("oversize block = %v, want ErrCorrupt", err)
	}

	// An encrypted pointer is refused before any DVA is considered.
	crypt := make([]byte, 128)
	le.PutUint64(crypt[0:], 1)
	le.PutUint64(crypt[8:], 1)
	cryptProp := uint64(1) << 61
	le.PutUint64(crypt[48:], cryptProp)
	bp, err = parseBlockPointer(crypt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := reader.read(bp); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("crypt pointer = %v, want ErrUnsupported", err)
	}

	// Embedded data decompresses from the pointer without touching a DVA.
	embeddedBp, err := parseBlockPointer(embeddedPointer([]byte("inline"), 6, 6, 19, 2, 0))
	if err != nil {
		t.Fatalf("parse embedded: %v", err)
	}
	got, err := reader.read(embeddedBp)
	if err != nil || string(got) != "inline" {
		t.Fatalf("embedded read = %q, %v", got, err)
	}

	// A hole reads as zeroes of the pointer's logical size.
	holeBp, err := parseBlockPointer(embeddedPointer(nil, 512, 1, 19, 2, 0))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_ = holeBp
	hole, err := parseBlockPointer(make([]byte, 128))
	if err != nil {
		t.Fatalf("parse hole: %v", err)
	}
	got, err = reader.read(hole)
	if err != nil || len(got) != 512 || !allZero(got) {
		t.Fatalf("hole read = %d, %v", len(got), err)
	}
}

func TestObjsetParseAndRefusals(t *testing.T) {
	img := newTestImage()
	objects := map[uint64][]byte{}
	objects[1] = img.microZAPDnode(1, []microEntry{{"ROOT", leU64(2)}})
	rootBP := img.addObjset(objects, objsetTypeZFS, 0)
	reader := newBlockReader(source.NewMemorySource(1, img.data))
	bytes, err := reader.read(mustParseBP(t, rootBP))
	if err != nil {
		t.Fatalf("read objset: %v", err)
	}
	objset, err := parseObjset(bytes)
	if err != nil {
		t.Fatalf("parseObjset: %v", err)
	}
	if objset.osType != ObjsetTypeZFS {
		t.Fatalf("type = %v", objset.osType)
	}
	if err := objset.requireZFS(); err != nil {
		t.Fatalf("requireZFS: %v", err)
	}
	if err := objset.requireMeta(); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("requireMeta on zfs = %v, want ErrUnsupported", err)
	}

	// A zvol dataset is refused by name.
	zvolObjects := map[uint64][]byte{}
	zvolObjects[1] = img.microZAPDnode(1, nil)
	zvolBP := img.addObjset(zvolObjects, objsetTypeZvol, 0)
	zvolBytes, err := reader.read(mustParseBP(t, zvolBP))
	if err != nil {
		t.Fatalf("read zvol objset: %v", err)
	}
	zvol, err := parseObjset(zvolBytes)
	if err != nil {
		t.Fatalf("parse zvol: %v", err)
	}
	if err := zvol.requireZFS(); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("zvol = %v, want ErrUnsupported", err)
	} else if !strings.Contains(err.Error(), "zvol") {
		t.Fatalf("zvol refusal = %v", err)
	}

	// An object set whose first dnode is not a dnode array is refused.
	bad := make([]byte, 2048)
	bad[0] = 19
	if _, err := parseObjset(bad); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("non-dnode first slot = %v", err)
	}
	if _, err := parseObjset(make([]byte, 512)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("small object set = %v", err)
	}
}

func mustParseBP(t *testing.T, raw []byte) BlockPointer {
	t.Helper()
	bp, err := parseBlockPointer(raw)
	if err != nil {
		t.Fatalf("parseBlockPointer: %v", err)
	}
	return bp
}
