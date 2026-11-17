package zfs

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestCheckDatasetBPRefusals(t *testing.T) {
	img := newTestImage()
	data := make([]byte, 2048)
	phys := img.alloc(data)
	good, err := parseBlockPointer(diskPointer(img, phys, 2048, 2048, dmuOtObjset, 0, 7, 2, 40, nil))
	if err != nil {
		t.Fatalf("parse good: %v", err)
	}
	if err := checkDatasetBP("dataset `tank`", &good, 100); err != nil {
		t.Fatalf("good pointer: %v", err)
	}

	hole, _ := parseBlockPointer(make([]byte, 128))
	if err := checkDatasetBP("s", &hole, 100); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "hole") {
		t.Fatalf("hole = %v", err)
	}
	embedded, _ := parseBlockPointer(embeddedPointer([]byte("x"), 1, 1, dmuOtObjset, 2, 0))
	if err := checkDatasetBP("s", &embedded, 100); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "embedded") {
		t.Fatalf("embedded = %v", err)
	}
	wrongType, _ := parseBlockPointer(diskPointer(img, phys, 2048, 2048, dmuOtPlainFile, 0, 7, 2, 40, nil))
	if err := checkDatasetBP("s", &wrongType, 100); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "object set") {
		t.Fatalf("wrong type = %v", err)
	}
	indirect, _ := parseBlockPointer(diskPointer(img, phys, 2048, 2048, dmuOtObjset, 2, 7, 2, 40, nil))
	if err := checkDatasetBP("s", &indirect, 100); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "level-2") {
		t.Fatalf("indirect = %v", err)
	}
	small, _ := parseBlockPointer(diskPointer(img, img.alloc(make([]byte, 512)), 512, 512, dmuOtObjset, 0, 7, 2, 40, nil))
	if err := checkDatasetBP("s", &small, 100); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "at least 1024") {
		t.Fatalf("small = %v", err)
	}
	future, _ := parseBlockPointer(diskPointer(img, phys, 2048, 2048, dmuOtObjset, 0, 7, 2, 150, nil))
	if err := checkDatasetBP("s", &future, 100); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "txg 150") {
		t.Fatalf("future birth = %v", err)
	}

	zeroASize := append([]byte(nil), diskPointer(img, phys, 2048, 2048, dmuOtObjset, 0, 7, 2, 40, nil)...)
	le.PutUint64(zeroASize[0:], 0) // asize 0
	le.PutUint64(zeroASize[8:], 8) // still a DVA
	bp, _ := parseBlockPointer(zeroASize)
	if err := checkDatasetBP("s", &bp, 100); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "allocates no bytes") {
		t.Fatalf("zero asize = %v", err)
	}
}

func TestChoosePoolTopologies(t *testing.T) {
	disk := func(id, guid uint64) VdevConfig {
		return VdevConfig{Kind: "disk", ID: id, IDPresent: true, GUID: guid, GUIDPresent: true}
	}
	twoLeaves := &VdevConfig{
		Kind: "root", GUIDPresent: true, GUID: 7,
		Children: []VdevConfig{disk(0, 11), disk(1, 12)},
	}
	var warnings []string
	_, err := choosePool([]Label{{
		Index: 0, TXG: 5,
		Pool: PoolConfig{GUID: 7, GUIDPresent: true, Vdev: twoLeaves},
	}}, &warnings)
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "2 leaf") {
		t.Fatalf("two leaves = %v", err)
	}

	_, err = choosePool([]Label{
		{Index: 0, TXG: 5, Pool: PoolConfig{GUID: 7, GUIDPresent: true, Vdev: &VdevConfig{Kind: "disk", GUIDPresent: true, GUID: 11}}},
		{Index: 1, TXG: 5, Pool: PoolConfig{GUID: 8, GUIDPresent: true, Vdev: &VdevConfig{Kind: "disk", GUIDPresent: true, GUID: 12}}},
	}, &warnings)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "different pools") {
		t.Fatalf("mixed pools = %v", err)
	}

	_, err = choosePool([]Label{{Index: 0, TXG: 5, Pool: PoolConfig{}}}, &warnings)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "no leaf") {
		t.Fatalf("no vdev = %v", err)
	}
}

func TestGuidSums(t *testing.T) {
	pool := PoolConfig{
		GUID: 7, GUIDPresent: true,
		Vdev: &VdevConfig{
			Kind: "root", GUID: 7, GUIDPresent: true,
			Children: []VdevConfig{
				{Kind: "disk", GUID: 11, GUIDPresent: true},
				{Kind: "disk", GUID: 12, GUIDPresent: true},
			},
		},
	}
	sums := guidSums(&pool)
	if !containsUint64(sums, 23) || !containsUint64(sums, 30) || containsUint64(sums, 0) {
		t.Fatalf("guid sums = %v", sums)
	}
	if got := guidSums(&PoolConfig{Vdev: &VdevConfig{Kind: "root"}}); got != nil {
		t.Fatalf("guidis sums without guids = %v", got)
	}
}

func TestMountpointFromProps(t *testing.T) {
	zap := func(entries ...ZapEntry) *Zap { return &Zap{items: entries} }
	value, err := mountpointFromProps(zap(ZapEntry{name: "mountpoint", value: []byte("/mnt\x00")}), 1)
	if err != nil || value == nil || *value != "/mnt" {
		t.Fatalf("local = %v, %v", value, err)
	}
	value, err = mountpointFromProps(zap(
		ZapEntry{name: "mountpoint$iuv", value: []byte("/iuv\x00")},
		ZapEntry{name: "mountpoint", value: []byte("/mnt\x00")},
	), 1)
	if err != nil || value == nil || *value != "/iuv" {
		t.Fatalf("index-update override = %v, %v", value, err)
	}
	value, err = mountpointFromProps(zap(
		ZapEntry{name: "mountpoint$recvd", value: []byte("/recv\x00")},
	), 1)
	if err != nil || value == nil || *value != "/recv" {
		t.Fatalf("received = %v, %v", value, err)
	}
	value, err = mountpointFromProps(zap(
		ZapEntry{name: "mountpoint$inherit", value: []byte{0}},
		ZapEntry{name: "mountpoint$recvd", value: []byte("/wrong\x00")},
	), 1)
	if err != nil || value != nil {
		t.Fatalf("inherit marker = %v, %v", value, err)
	}
	if _, err := mountpointFromProps(zap(
		ZapEntry{name: "mountpoint", value: []byte("/no-nul")},
	), 2); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("malformed = %v", err)
	}
}

func TestPropertyString(t *testing.T) {
	cases := []struct {
		value string
		want  string
		ok    bool
	}{
		{"/mnt\x00", "/mnt", true},
		{"/mnt\x00\x00\x00", "/mnt", true},
		{"/mnt", "", false},
		{"/mnt\x00x", "", false},
		{"\xff\x00", "", false},
	}
	for _, tc := range cases {
		got, ok := propertyString([]byte(tc.value))
		if ok != tc.ok || got != tc.want {
			t.Fatalf("propertyString(%q) = %q, %v", tc.value, got, ok)
		}
	}
	if _, ok := propertyString(make([]byte, maxPropertyBytes+1)); ok {
		t.Fatal("a property over the bound was accepted")
	}
}

func TestSnapshotEntryBranches(t *testing.T) {
	volume := openTestPool(t)
	reader := newBlockReader(volume.source)

	// Object 3 is the root head dataset: it is a DSL dataset, not a snapshot.
	snapshot, warning := snapshotEntry(reader, volume.MOS(), "tank", "head", 3, true)
	if snapshot.IsResolved() || !strings.Contains(snapshot.UnresolvedReason, "head dataset") || warning == "" {
		t.Fatalf("head dataset = %+v %q", snapshot, warning)
	}
	// A free MOS slot cannot be read as a dataset.
	snapshot, warning = snapshotEntry(reader, volume.MOS(), "tank", "free", 99, true)
	if snapshot.IsResolved() || warning == "" {
		t.Fatalf("free object = %+v %q", snapshot, warning)
	}
	// A ZAP value that is not an object id keeps its name but resolves no
	// object.
	snapshot, warning = snapshotEntry(reader, volume.MOS(), "tank", "weird", 0, false)
	if snapshot.IsResolved() || !strings.Contains(snapshot.UnresolvedReason, "8-byte") || warning == "" {
		t.Fatalf("bad value = %+v %q", snapshot, warning)
	}
}

func TestSpilledSAAndLegacySymlink(t *testing.T) {
	img := newTestImage()
	objects := map[uint64][]byte{}
	objects[1] = img.microZAPDnode(1, []microEntry{
		{"ROOT", leU64(2)},
		{"SA_ATTRS", leU64(3)},
	})
	objects[3] = img.microZAPDnode(1, []microEntry{
		{"LAYOUTS", leU64(4)},
		{"REGISTRY", leU64(5)},
	})
	objects[4] = img.fatZAPDnode(27, []fatEntry{
		{"6", layoutBytes([]uint16{1}), 2},
		{"7", layoutBytes([]uint16{2, 3}), 2},
	})
	objects[5] = img.fatZAPDnode(27, []fatEntry{
		{"ZPL_MODE", leU64(1 | (8 << 24)), 8},
		{"ZPL_SIZE", leU64(2 | (8 << 24)), 8},
		{"ZPL_UID", leU64(3 | (8 << 24)), 8},
	})

	// A file whose SA buffer is split across the bonus and a spill block.
	spillBuffer := buildSABuffer(7, []uint16{2, 3}, map[uint16][]byte{
		2: leU64(4242),
		3: leU64(1000),
	})
	spillBlock := make([]byte, 512)
	copy(spillBlock, spillBuffer)
	spillPhys := img.alloc(spillBlock)
	spillPointer := diskPointer(img, spillPhys, 512, 512, dmuOtSA, 0, 7, 2, 0, nil)
	bonus := buildSABuffer(6, []uint16{1}, map[uint16][]byte{1: leU64(0o100644)})
	objects[6] = buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtSA,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		flags:        dnodeFlagSpillBlkptr,
		pointers:     [][]byte{holePointer(0)},
		bonus:        bonus,
		spill:        spillPointer,
	})
	// A spilled bonus whose spill pointer is a hole is refused.
	objects[7] = buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtSA,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		flags:        dnodeFlagSpillBlkptr,
		pointers:     [][]byte{holePointer(0)},
		bonus:        make([]byte, 8),
		spill:        make([]byte, 128),
	})
	// A legacy znode symlink whose target did not fit in the bonus and lives
	// in the object's data block.
	target := bytes.Repeat([]byte("x"), 300)
	data := make([]byte, 512)
	copy(data, target)
	dataPhys := img.alloc(data)
	dataPointer := diskPointer(img, dataPhys, 512, 512, dmuOtPlainFile, 0, 7, 2, 0, nil)
	legacy := make([]byte, legacyZnodeSize)
	le.PutUint64(legacy[72:], 0o120777)
	le.PutUint64(legacy[80:], uint64(len(target)))
	objects[8] = buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtZnode,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers:     [][]byte{dataPointer},
		bonus:        legacy,
	})

	rootBP := img.addObjset(objects, objsetTypeZFS, 0)
	reader := newBlockReader(source.NewMemorySource(1, img.data))
	bp := mustParseBP(t, rootBP)
	objsetBytes, err := reader.read(bp)
	if err != nil {
		t.Fatalf("read objset: %v", err)
	}
	objset, err := parseObjset(objsetBytes)
	if err != nil {
		t.Fatalf("parse objset: %v", err)
	}
	tables, err := loadSATables(reader, objset)
	if err != nil {
		t.Fatalf("loadSATables: %v", err)
	}
	attributes, err := readAttributes(reader, objset, 6, tables)
	if err != nil {
		t.Fatalf("spilled attributes: %v", err)
	}
	if attributes.Mode == nil || *attributes.Mode != 0o100644 {
		t.Fatalf("mode = %v", attributes.Mode)
	}
	if attributes.Size == nil || *attributes.Size != 4242 {
		t.Fatalf("size = %v", attributes.Size)
	}
	if attributes.UID == nil || *attributes.UID != 1000 {
		t.Fatalf("uid = %v", attributes.UID)
	}
	if attributes.Source.Layout != 6 {
		t.Fatalf("source = %+v", attributes.Source)
	}
	if _, err := readAttributes(reader, objset, 7, tables); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "hole") {
		t.Fatalf("spill hole = %v", err)
	}
	symlink, err := readAttributes(reader, objset, 8, tables)
	if err != nil {
		t.Fatalf("legacy symlink: %v", err)
	}
	if symlink.Kind != DTypeSymlink || !bytes.Equal(symlink.Symlink, target) {
		t.Fatalf("legacy symlink kind=%v len=%d", symlink.Kind, len(symlink.Symlink))
	}
	if len(tables.layouts) != 2 || len(tables.attributes) != 3 {
		t.Fatalf("tables = %d layouts, %d attributes", len(tables.layouts), len(tables.attributes))
	}
}

func TestOpenWithLimits(t *testing.T) {
	img := buildTestImage(t)
	volume, err := OpenWithOptions(source.NewMemorySource(1, img.data), Options{
		DatasetLimit:   1,
		RootEntryLimit: 2,
		SnapshotLimit:  1,
		PathEntryLimit: 2,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	if len(volume.Datasets()) != 1 {
		t.Fatalf("datasets = %d", len(volume.Datasets()))
	}
	if !volume.root.RootTruncated() || volume.root.RootEntryCount() != 2 {
		t.Fatalf("root entries = %d truncated %v", volume.root.RootEntryCount(), volume.root.RootTruncated())
	}
	if len(volume.Snapshots()) != 1 || !volume.SnapshotsTruncated() {
		t.Fatalf("snapshots = %d truncated %v", len(volume.Snapshots()), volume.SnapshotsTruncated())
	}
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("ListDir entries = %d", len(entries))
	}
	if !hasWarning(volume.Warnings(), "dataset walk stopped") {
		t.Fatalf("missing limit warning: %v", volume.Warnings())
	}
}

func TestFileSourceInterfaces(t *testing.T) {
	volume := openTestPool(t)
	file := mustFile(t, volume, "/hello.txt")
	fs, ok := file.(*FileSource)
	if !ok {
		t.Fatalf("OpenFile returned %T", file)
	}
	if fs.Object() != 10 || fs.Size() != 11 {
		t.Fatalf("file source = %d/%d", fs.Object(), fs.Size())
	}
	if file.SourceID() == 0 || file.SectorSize() == 0 {
		t.Fatalf("source metadata = %d/%d", file.SourceID(), file.SectorSize())
	}
	ranges, err := file.ExtentsInto(0, 11, nil)
	if err != nil || len(ranges) != 1 || ranges[0].Kind != source.RangeDerived {
		t.Fatalf("ExtentsInto = %+v, %v", ranges, err)
	}
	buf := make([]byte, 11)
	if n, err := file.ReadAtLossy(0, buf); err != nil || n != 11 || string(buf) != "hello world" {
		t.Fatalf("ReadAtLossy = %d, %v, %q", n, err, buf)
	}
	if _, err := file.Extents(0, 12); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("past EOF extents = %v", err)
	}
	if _, err := file.MapToImage(0, 12); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("past EOF mapping = %v", err)
	}
}

func TestIndirectExtentsAndHoleSubtree(t *testing.T) {
	volume := openTestPool(t)
	file := mustFile(t, volume, "/indirect")
	ranges, err := file.Extents(0, 3*512)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 3 {
		t.Fatalf("ranges = %+v", ranges)
	}
	for _, r := range ranges {
		if r.Kind != source.RangeDerived || r.Len != 512 {
			t.Fatalf("range = %+v", r)
		}
	}

	// A hole at an indirect level stands for every data block below it.
	node := buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  10,
		nlevels:      2,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers:     [][]byte{holePointer(0)},
	})
	parsed, err := parseDnode(node, 1)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	reader := newBlockReader(source.NewMemorySource(0, nil))
	var blocks []ObjectBlock
	if err := dataBlocksInto(reader, parsed, 0, 3*512, &blocks); err != nil {
		t.Fatalf("dataBlocksInto: %v", err)
	}
	if len(blocks) != 3 {
		t.Fatalf("blocks = %+v", blocks)
	}
	for _, block := range blocks {
		if !block.pointer.isHole() {
			t.Fatalf("block = %+v", block)
		}
	}
}

func TestZapAccessors(t *testing.T) {
	zap := &Zap{items: []ZapEntry{
		{name: "object", value: leU64(5)},
		{name: "string", value: []byte("hello\x00")},
		{name: "bad", value: []byte{0xff, 0x00}},
	}}
	if zap.len() != 3 || zap.isEmpty() {
		t.Fatalf("len/isEmpty = %d/%v", zap.len(), zap.isEmpty())
	}
	if value, ok := zap.unsigned("object"); !ok || value != 5 {
		t.Fatalf("unsigned = %d, %v", value, ok)
	}
	if value, ok := zap.stringValue("string"); !ok || value != "hello" {
		t.Fatalf("string = %q, %v", value, ok)
	}
	if _, ok := zap.stringValue("bad"); ok {
		t.Fatal("invalid UTF-8 string was accepted")
	}
	if _, ok := zap.unsigned("string"); ok {
		t.Fatal("an eight-byte string was read as an integer")
	}
	if _, ok := zap.get("missing"); ok {
		t.Fatal("missing entry resolved")
	}
	if empty := (&Zap{}); !empty.isEmpty() || empty.len() != 0 {
		t.Fatal("empty zap")
	}
}

func TestObjsetEncryptionFlag(t *testing.T) {
	img := newTestImage()
	objects := map[uint64][]byte{}
	objects[1] = img.microZAPDnode(1, nil)
	rootBP := img.addObjset(objects, objsetTypeZFS, 0)
	reader := newBlockReader(source.NewMemorySource(1, img.data))
	objsetBytes, err := reader.read(mustParseBP(t, rootBP))
	if err != nil {
		t.Fatalf("read objset: %v", err)
	}
	objset, err := parseObjset(objsetBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if objset.isEncrypted() {
		t.Fatal("plain object set reports encryption")
	}
	objset.portableMAC[7] = 1
	objset.hasMACs = true
	if !objset.isEncrypted() {
		t.Fatal("non-zero MAC not reported")
	}
}

func TestNvlistArrays(t *testing.T) {
	// uint64 array
	value := xdrU32(2)
	value = append(value, xdrU64(7)...)
	value = append(value, xdrU64(9)...)
	data := xdrList(xdrPair("ids", xdrDataTypeUint64Array, 2, value))
	list, err := parseNvlist(data)
	if err != nil {
		t.Fatalf("uint64 array: %v", err)
	}
	if list.Len() != 1 {
		t.Fatalf("len = %d", list.Len())
	}
	negative := int32(-5)
	signed := xdrU32(1)
	signed = append(signed, xdrU32(uint32(negative))...)
	data = xdrList(xdrPair("signed", xdrDataTypeInt32Array, 1, signed))
	if _, err := parseNvlist(data); err != nil {
		t.Fatalf("int32 array: %v", err)
	}
	stringsValue := xdrU32(2)
	stringsValue = append(stringsValue, xdrString("a")...)
	stringsValue = append(stringsValue, xdrString("b")...)
	data = xdrList(xdrPair("names", xdrDataTypeStringArray, 2, stringsValue))
	if _, err := parseNvlist(data); err != nil {
		t.Fatalf("string array: %v", err)
	}
	// An array over the million-element bound is refused before allocating.
	over := xdrU32(1 << 21)
	data = xdrList(xdrPair("huge", xdrDataTypeUint64Array, 1<<21, over))
	if _, err := parseNvlist(data); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("huge array = %v", err)
	}
}

func TestNvlistDepthBound(t *testing.T) {
	nested := xdrList()
	for i := 0; i < maxNvlistDepth+8; i++ {
		nested = xdrList(xdrPair("n", xdrDataTypeNvlist, 1, nested))
	}
	if _, err := parseNvlist(nested); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("deep nvlist = %v, want ErrCorrupt", err)
	}
	shallow := xdrList()
	for i := 0; i < 4; i++ {
		shallow = xdrList(xdrPair("n", xdrDataTypeNvlist, 1, shallow))
	}
	if _, err := parseNvlist(shallow); err != nil {
		t.Fatalf("shallow nvlist: %v", err)
	}
}
