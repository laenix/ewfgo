package hfs

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- fixture geometry ------------------------------------------------------

const (
	testBlockSize     = 512
	testAllocation    = 4 // drAlBlSt, in 512-byte units
	testAllocationAbs = testAllocation * 512
	testVolumeBlocks  = 64
	testImageBytes    = testAllocationAbs + testVolumeBlocks*testBlockSize

	testExtentsBlocks = 2
	testCatalogBlocks = 4

	// Allocation-block layout.
	abExtents = 0
	abCatalog = 2
	abBig     = 6 // three blocks: 6, 7 and the overflow continuation's 8
	abInner   = 9
	abReadme  = 10
	abRes     = 11
	abResData = 12
)

// ---- big-endian fixture helpers -------------------------------------------

func putBE16(dst []byte, at int, value uint16) {
	dst[at] = byte(value >> 8)
	dst[at+1] = byte(value)
}

func putBE32(dst []byte, at int, value uint32) {
	dst[at] = byte(value >> 24)
	dst[at+1] = byte(value >> 16)
	dst[at+2] = byte(value >> 8)
	dst[at+3] = byte(value)
}

type fixtureExtent struct {
	start  uint16
	blocks uint16
}

func extentRecord(extents ...fixtureExtent) []byte {
	out := make([]byte, 12)
	for index, extent := range extents {
		if index >= 3 {
			break
		}
		putBE16(out, index*4, extent.start)
		putBE16(out, index*4+2, extent.blocks)
	}
	return out
}

func fixtureMDB(name string, extentsSize uint32, extents []fixtureExtent, catalogSize uint32, catalog []fixtureExtent) []byte {
	mdb := make([]byte, 162)
	putBE16(mdb, 0, 0x4244)
	putBE32(mdb, 2, 3_300_000_000)
	putBE32(mdb, 6, 3_300_100_000)
	putBE16(mdb, 10, 0x0100) // unmounted
	putBE16(mdb, 12, 5)
	putBE16(mdb, 14, 0)
	putBE16(mdb, 16, 0)
	putBE16(mdb, 18, testVolumeBlocks)
	putBE32(mdb, 20, testBlockSize)
	putBE32(mdb, 24, 0)
	putBE16(mdb, 28, testAllocation)
	putBE32(mdb, 30, 32)
	putBE16(mdb, 34, 40)
	mdb[36] = byte(len(name))
	copy(mdb[37:], name)
	putBE32(mdb, 64, 3_300_200_000)
	putBE32(mdb, 70, 7)
	putBE32(mdb, 74, 0)
	putBE32(mdb, 78, 0)
	putBE16(mdb, 82, 1)
	putBE32(mdb, 84, 5)
	putBE32(mdb, 88, 3)
	putBE32(mdb, 130, extentsSize)
	copy(mdb[134:146], extentRecord(extents...))
	putBE32(mdb, 146, catalogSize)
	copy(mdb[150:162], extentRecord(catalog...))
	return mdb
}

// btreeNode lays out a node the way the classic-HFS B-tree reader expects.
func btreeNode(nodeSize int, kind int8, forward, backward uint32, height uint8, records [][2][]byte) []byte {
	node := make([]byte, nodeSize)
	putBE32(node, 0, forward)
	putBE32(node, 4, backward)
	node[8] = byte(kind)
	node[9] = height
	putBE16(node, 10, uint16(len(records)))

	offsets := make([]int, len(records)+1)
	offsets[0] = 14
	at := 14
	for index, record := range records {
		key, data := record[0], record[1]
		if at >= nodeSize {
			panic("fixture node overflow")
		}
		node[at] = byte(len(key))
		at++
		copy(node[at:], key)
		at += len(key)
		if (1+len(key))%2 == 1 {
			at++
		}
		copy(node[at:], data)
		at += len(data)
		offsets[index+1] = at
	}
	tableStart := nodeSize - (len(records)+1)*2
	if at > tableStart {
		panic("fixture node records overlap its offset table")
	}
	for index, offset := range offsets {
		putBE16(node, tableStart+index*2, uint16(offset))
	}
	return node
}

func btreeHeader(nodeSize int, depth uint16, root, first, last, total uint32, leafRecords uint32) []byte {
	node := btreeNode(nodeSize, 1, 0, 0, 0, nil)
	putBE16(node, 14, depth)
	putBE32(node, 16, root)
	putBE32(node, 20, leafRecords)
	putBE32(node, 24, first)
	putBE32(node, 28, last)
	putBE16(node, 32, uint16(nodeSize))
	putBE16(node, 34, 8)
	putBE32(node, 36, total)
	putBE32(node, 40, 0)
	putBE32(node, 46, 0)
	node[50] = 0
	node[51] = 0xBC
	putBE32(node, 52, 0)
	return node
}

func catalogKeyBytes(parent uint32, name string) []byte {
	key := make([]byte, 6+len(name))
	putBE32(key, 1, parent)
	key[5] = byte(len(name))
	copy(key[6:], name)
	return key
}

func folderData(valence uint16, directoryID uint32) []byte {
	data := make([]byte, 10)
	putBE16(data, 0, 0x0100)
	putBE16(data, 2, 0)
	putBE16(data, 4, valence)
	putBE32(data, 6, directoryID)
	return data
}

func threadData(recordType uint16, parent uint32, name string) []byte {
	data := make([]byte, 15+len(name))
	putBE16(data, 0, recordType)
	putBE32(data, 10, parent)
	data[14] = byte(len(name))
	copy(data[15:], name)
	return data
}

type fileFixture struct {
	id           uint32
	name         string
	parent       uint32
	size         uint32
	physical     uint32
	dataExtents  []fixtureExtent
	resSize      uint32
	resPhysical  uint32
	resExtents   []fixtureExtent
	finderType   uint32
	finderCreate uint32
}

func fileData(f fileFixture) []byte {
	data := make([]byte, 98)
	putBE16(data, 0, 0x0200)
	putBE32(data, 4, f.finderType)
	putBE32(data, 8, f.finderCreate)
	putBE32(data, 20, f.id)
	putBE32(data, 26, f.size)
	putBE32(data, 30, f.physical)
	putBE32(data, 36, f.resSize)
	putBE32(data, 40, f.resPhysical)
	putBE32(data, 44, 3_400_000_000) // created
	putBE32(data, 48, 3_400_000_100) // modified
	putBE32(data, 52, 3_400_000_200) // backup
	copy(data[74:86], extentRecord(f.dataExtents...))
	copy(data[86:98], extentRecord(f.resExtents...))
	return data
}

// buildHFSImage synthesises a classic-HFS volume:
//
//	MDB at byte 1024
//	extents overflow B-tree at allocation blocks 0..1
//	catalog B-tree at allocation blocks 2..5
//	file data at allocation blocks 6..11
func buildHFSImage(t *testing.T) []byte {
	t.Helper()
	image := make([]byte, testImageBytes)
	base := testAllocationAbs

	// Master Directory Block.
	mdb := fixtureMDB("HFS Fixture", testExtentsBlocks*testBlockSize,
		[]fixtureExtent{{abExtents, testExtentsBlocks}},
		testCatalogBlocks*testBlockSize,
		[]fixtureExtent{{abCatalog, testCatalogBlocks}})
	copy(image[1024:], mdb)

	// Extents overflow tree: header node + one leaf record for file 20.
	extentsFork := base + abExtents*testBlockSize
	copy(image[extentsFork:], btreeHeader(512, 1, 1, 1, 1, 2, 1))
	overflowKey := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01}
	overflowData := extentRecord(fixtureExtent{7, 2})
	copy(image[extentsFork+512:], btreeNode(512, -1, 0, 0, 0, [][2][]byte{
		{overflowKey, overflowData},
	}))

	// Catalog tree: header node + two leaf nodes.
	catalogFork := base + abCatalog*testBlockSize
	copy(image[catalogFork:], btreeHeader(512, 1, 1, 1, 2, testCatalogBlocks, 13))

	leafOne := btreeNode(512, -1, 2, 0, 0, [][2][]byte{
		{catalogKeyBytes(1, "HFS Fixture"), folderData(5, 2)},
		{catalogKeyBytes(2, ""), threadData(0x0300, 1, "HFS Fixture")},
		{catalogKeyBytes(2, "readme.txt"), fileData(fileFixture{
			id: 16, name: "readme.txt", parent: 2, size: 10, physical: 512,
			dataExtents: []fixtureExtent{{abReadme, 1}}, finderType: 0x54455854, finderCreate: 0x74747874,
		})},
		{catalogKeyBytes(2, "big.bin"), fileData(fileFixture{
			id: 20, name: "big.bin", parent: 2, size: 1536, physical: 1536,
			dataExtents: []fixtureExtent{{abBig, 1}},
		})},
		{catalogKeyBytes(2, "empty.txt"), fileData(fileFixture{
			id: 21, name: "empty.txt", parent: 2, size: 0, physical: 0,
		})},
	})
	copy(image[catalogFork+512:], leafOne)

	leafTwo := btreeNode(512, -1, 0, 1, 0, [][2][]byte{
		{catalogKeyBytes(2, "sub"), folderData(2, 17)},
		{catalogKeyBytes(17, ""), threadData(0x0300, 2, "sub")},
		{catalogKeyBytes(17, "inner.bin"), fileData(fileFixture{
			id: 18, name: "inner.bin", parent: 17, size: 5, physical: 512,
			dataExtents: []fixtureExtent{{abInner, 1}},
		})},
		{catalogKeyBytes(17, "empty"), folderData(0, 19)},
		{catalogKeyBytes(18, ""), threadData(0x0400, 17, "inner.bin")},
		{catalogKeyBytes(19, ""), threadData(0x0300, 17, "empty")},
		{catalogKeyBytes(2, "res.bin"), fileData(fileFixture{
			id: 22, name: "res.bin", parent: 2, size: 3, physical: 512,
			dataExtents: []fixtureExtent{{abResData, 1}},
			resSize:     7,
			resPhysical: 512,
			resExtents:  []fixtureExtent{{abRes, 1}},
		})},
		{catalogKeyBytes(22, ""), threadData(0x0400, 2, "res.bin")},
	})
	copy(image[catalogFork+1024:], leafTwo)

	// Data blocks.
	fill := func(block int, value byte, prefix string) {
		at := base + block*testBlockSize
		for index := 0; index < testBlockSize; index++ {
			image[at+index] = value
		}
		copy(image[at:], prefix)
	}
	fill(abBig, 'A', "big-first\n")
	fill(abBig+1, 'B', "")
	fill(abBig+2, 'B', "")
	fill(abInner, 0, "inner")
	fill(abReadme, 0, "hello hfs\n")
	fill(abRes, 0, "RESDATA")
	fill(abResData, 0, "DAT")
	return image
}

func openHFS(t *testing.T, data []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func entryByName(t *testing.T, entries []Entry, name string) Entry {
	t.Helper()
	for _, entry := range entries {
		if entry.Name == name {
			return entry
		}
	}
	t.Fatalf("no entry named %q in %v", name, entryNames(entries))
	return Entry{}
}

func entryNames(entries []Entry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

// ---- detection and MDB -----------------------------------------------------

func TestDetect(t *testing.T) {
	if found, err := Detect(source.NewMemorySource(1, make([]byte, 100))); err != nil || found {
		t.Fatalf("short source: found=%v err=%v", found, err)
	}
	if found, err := Detect(source.NewMemorySource(1, make([]byte, 1024+162))); err != nil || found {
		t.Fatalf("no signature: found=%v err=%v", found, err)
	}
	if found, err := Detect(source.NewMemorySource(1, buildHFSImage(t))); err != nil || !found {
		t.Fatalf("fixture: found=%v err=%v", found, err)
	}

	// A little-endian signature is refused by name.
	swapped := buildHFSImage(t)
	swapped[1024] = 0x44
	swapped[1025] = 0x42
	if _, err := Detect(source.NewMemorySource(1, swapped)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("swapped signature error = %v", err)
	}

	// A present signature with broken geometry is corrupt, not absent.
	bad := buildHFSImage(t)
	putBE32(bad, 1024+20, 0)
	if _, err := Detect(source.NewMemorySource(1, bad)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bad block size error = %v", err)
	}

	// Too short for the MDB is simply "not HFS".
	if found, err := Detect(source.NewMemorySource(1, make([]byte, 1024+161))); err != nil || found {
		t.Fatalf("truncated MDB: found=%v err=%v", found, err)
	}
}

func TestMasterDirectoryBlock(t *testing.T) {
	image := buildHFSImage(t)
	mdb, err := ReadMDB(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("ReadMDB: %v", err)
	}
	if mdb.Signature != 0x4244 || mdb.Name != "HFS Fixture" {
		t.Fatalf("mdb = %+v", mdb)
	}
	if mdb.AllocationBlockSize != testBlockSize || mdb.AllocationBlocks != testVolumeBlocks {
		t.Fatalf("geometry = %d/%d", mdb.AllocationBlockSize, mdb.AllocationBlocks)
	}
	if mdb.AllocationBase() != testAllocationAbs {
		t.Fatalf("allocation base = %d", mdb.AllocationBase())
	}
	if !mdb.IsUnmounted() {
		t.Fatalf("fixture should be cleanly unmounted")
	}
	if mdb.CatalogFileSize != testCatalogBlocks*testBlockSize || mdb.CatalogExtents[0].Start != abCatalog || mdb.CatalogExtents[0].Blocks != testCatalogBlocks {
		t.Fatalf("catalog extents = %+v", mdb.CatalogExtents)
	}
	if mdb.ExtentsFileSize != testExtentsBlocks*testBlockSize || mdb.ExtentsExtents[0].Start != abExtents {
		t.Fatalf("extents extents = %+v", mdb.ExtentsExtents)
	}
	if mdb.FileCount != 5 || mdb.DirectoryCount != 3 {
		t.Fatalf("counts = %d/%d", mdb.FileCount, mdb.DirectoryCount)
	}
}

func TestMDBValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"zero allocation block size", func(m []byte) { putBE32(m, 20, 0) }},
		{"non power of two allocation block size", func(m []byte) { putBE32(m, 20, 1000) }},
		{"allocation block size below 512", func(m []byte) { putBE32(m, 20, 256) }},
		{"no allocation blocks", func(m []byte) { putBE16(m, 18, 0) }},
		{"allocation area inside the MDB", func(m []byte) { putBE16(m, 28, 2) }},
	}
	for _, tc := range cases {
		image := buildHFSImage(t)
		mdb := image[1024 : 1024+162]
		tc.mutate(mdb)
		if _, err := ReadMDB(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("%s: error = %v", tc.name, err)
		}
	}

	// A short structure never parses.
	if _, err := parseMDB(make([]byte, 161)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short parse error = %v", err)
	}
}

// ---- volume report ---------------------------------------------------------

func TestInfo(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	info := volume.Info()
	if info.Name != "HFS Fixture" || info.Signature != 0x4244 {
		t.Fatalf("name/signature = %q/%#x", info.Name, info.Signature)
	}
	if info.AllocationBlockSize != testBlockSize || info.AllocationBlocks != testVolumeBlocks {
		t.Fatalf("geometry = %+v", info)
	}
	if info.AllocationBase != testAllocationAbs || info.FreeBlocks != 40 || !info.Unmounted {
		t.Fatalf("volume flags = %+v", info)
	}
	if info.CatalogNodeSize != 512 || info.CatalogTotalNodes != testCatalogBlocks {
		t.Fatalf("catalog geometry = %+v", info)
	}
	if info.CatalogLeafRecords != 13 {
		t.Fatalf("leaf records = %d", info.CatalogLeafRecords)
	}
	if info.Folders != 3 || info.Files != 5 || info.Threads != 5 {
		t.Fatalf("record counts = %+v", info)
	}
	if info.MalformedRecords != 0 || info.OtherRecords != 0 {
		t.Fatalf("unexpected malformed/other = %+v", info)
	}
	if info.Truncated {
		t.Fatalf("fixture reported truncated")
	}
	if info.TimeBasis != timeBasisLocalWallClock {
		t.Fatalf("time basis = %q", info.TimeBasis)
	}
	if len(info.Warnings) != 0 {
		t.Fatalf("warnings = %v", info.Warnings)
	}
	if info.HasCreateDate {
		if want := hfsTime(3_300_000_000); !info.CreateDate.Equal(want) {
			t.Fatalf("create date = %v want %v", info.CreateDate, want)
		}
	} else {
		t.Fatalf("create date not reported")
	}

	stats := volume.Stats()
	if stats.CatalogNodeSize != 512 || stats.Folders != 3 || stats.Files != 5 || stats.Threads != 5 {
		t.Fatalf("stats = %+v", stats)
	}
}

// ---- directories -----------------------------------------------------------

func TestListDirRoot(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	want := "readme.txt,big.bin,empty.txt,sub,res.bin"
	if got := strings.Join(entryNames(entries), ","); got != want {
		t.Fatalf("names = %s want %s", got, want)
	}

	readme := entryByName(t, entries, "readme.txt")
	if readme.Path != "/readme.txt" || readme.Inode != 16 || readme.ParentInode != 2 {
		t.Fatalf("readme path = %+v", readme)
	}
	if !readme.IsFile || readme.IsDir || readme.IsSymlink {
		t.Fatalf("readme flags = %+v", readme)
	}
	if readme.Size != 10 || !readme.HasAllocated || readme.Allocated != 512 {
		t.Fatalf("readme size = %+v", readme)
	}
	if readme.FinderType != 0x54455854 || readme.FinderCreator != 0x74747874 {
		t.Fatalf("finder = %#x/%#x", readme.FinderType, readme.FinderCreator)
	}
	if !readme.HasCreated || !readme.Created.Equal(hfsTime(3_400_000_000)) {
		t.Fatalf("created = %v", readme.Created)
	}
	if !readme.HasModified || !readme.Modified.Equal(hfsTime(3_400_000_100)) {
		t.Fatalf("modified = %v", readme.Modified)
	}
	if !readme.HasBackup || !readme.Backup.Equal(hfsTime(3_400_000_200)) {
		t.Fatalf("backup = %v", readme.Backup)
	}
	// Classic HFS exposes no mode, ownership, symlink or deleted state.
	if readme.Mode != 0 || readme.UID != 0 || readme.GID != 0 || readme.SymlinkTarget != "" || readme.Deleted {
		t.Fatalf("unexpected POSIX metadata = %+v", readme)
	}

	sub := entryByName(t, entries, "sub")
	if !sub.IsDir || sub.IsFile || sub.Inode != 17 || sub.Size != 0 || sub.HasAllocated {
		t.Fatalf("sub = %+v", sub)
	}

	empty := entryByName(t, entries, "empty.txt")
	if empty.Size != 0 || !empty.HasAllocated || empty.Allocated != 0 {
		t.Fatalf("empty = %+v", empty)
	}
}

func TestStatNested(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	if root.Name != "/" || root.Path != "/" || !root.IsDir || root.Inode != 2 || root.ParentInode != 0 {
		t.Fatalf("root = %+v", root)
	}
	if other, err := volume.Stat(""); err != nil || other.Path != "/" {
		t.Fatalf("empty path stat = %+v err=%v", other, err)
	}
	inner, err := volume.Stat("sub/inner.bin")
	if err != nil {
		t.Fatalf("Stat inner: %v", err)
	}
	if inner.Name != "inner.bin" || inner.Path != "/sub/inner.bin" || inner.Inode != 18 || inner.Size != 5 {
		t.Fatalf("inner = %+v", inner)
	}
	if inner.ParentInode != 17 {
		t.Fatalf("inner parent = %d", inner.ParentInode)
	}
	sub, err := volume.Stat("/sub")
	if err != nil || !sub.IsDir || sub.Path != "/sub" {
		t.Fatalf("sub stat = %+v err=%v", sub, err)
	}

	// ".." walks back to the parent.
	up, err := volume.Stat("/sub/..")
	if err != nil || up.Path != "/" {
		t.Fatalf("dotdot = %+v err=%v", up, err)
	}
}

func TestEmptyDir(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	entries, err := volume.ListDir("/sub/empty")
	if err != nil {
		t.Fatalf("ListDir empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty dir has %d entries: %v", len(entries), entryNames(entries))
	}
}

func TestPathErrors(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	if _, err := volume.ListDir("/readme.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir file error = %v", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile dir error = %v", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenFile missing error = %v", err)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat missing error = %v", err)
	}
	if _, err := volume.Stat("/sub/inner.bin/extra"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("component through a file error = %v", err)
	}
}

// ---- file data -------------------------------------------------------------

func TestReadFile(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	readme, err := volume.OpenFile("/readme.txt")
	if err != nil {
		t.Fatalf("OpenFile readme: %v", err)
	}
	if readme.Len() != 10 || readme.IsEmpty() {
		t.Fatalf("readme length = %d", readme.Len())
	}
	buf := make([]byte, 10)
	if _, err := readme.ReadAt(0, buf); err != nil || string(buf) != "hello hfs\n" {
		t.Fatalf("readme = %q err=%v", buf, err)
	}

	empty, err := volume.OpenFile("/empty.txt")
	if err != nil {
		t.Fatalf("OpenFile empty: %v", err)
	}
	if empty.Len() != 0 || !empty.IsEmpty() {
		t.Fatalf("empty length = %d", empty.Len())
	}
	if _, err := empty.ReadAt(0, make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("empty read error = %v", err)
	}

	inner, err := volume.OpenFile("/sub/inner.bin")
	if err != nil {
		t.Fatalf("OpenFile inner: %v", err)
	}
	innerBuf := make([]byte, 5)
	if _, err := inner.ReadAt(0, innerBuf); err != nil || string(innerBuf) != "inner" {
		t.Fatalf("inner = %q err=%v", innerBuf, err)
	}
}

func TestExtentsOverflow(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	if stats := volume.Stats(); stats.ExtentsLookups != 1 || stats.ExtentsFound != 1 || stats.ExtentsMissing != 0 {
		t.Fatalf("overflow stats = %+v", stats)
	}
	file, err := volume.OpenFile("/big.bin")
	if err != nil {
		t.Fatalf("OpenFile big: %v", err)
	}
	if file.Len() != 1536 {
		t.Fatalf("big length = %d", file.Len())
	}
	all := make([]byte, 1536)
	if _, err := file.ReadAt(0, all); err != nil {
		t.Fatalf("ReadAt big: %v", err)
	}
	if string(all[:10]) != "big-first\n" {
		t.Fatalf("big head = %q", all[:10])
	}
	if all[511] != 'A' || all[512] != 'B' || all[1535] != 'B' {
		t.Fatalf("big boundary bytes = %#x %#x %#x", all[511], all[512], all[1535])
	}

	// A read across the extent boundary.
	cross := make([]byte, 40)
	if _, err := file.ReadAt(500, cross); err != nil {
		t.Fatalf("cross read: %v", err)
	}
	for index := 0; index < 12; index++ {
		if cross[index] != 'A' {
			t.Fatalf("cross[%d] = %#x", index, cross[index])
		}
	}
	for index := 12; index < 40; index++ {
		if cross[index] != 'B' {
			t.Fatalf("cross[%d] = %#x", index, cross[index])
		}
	}

	// Ranges translate to the two runs.
	ranges, err := file.Extents(0, 1536)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 2 || ranges[0].Kind != source.RangeData || ranges[1].Kind != source.RangeData {
		t.Fatalf("ranges = %+v", ranges)
	}
	if ranges[0].Len != 512 || ranges[0].ParentOffset != testAllocationAbs+abBig*testBlockSize {
		t.Fatalf("first range = %+v", ranges[0])
	}
	if ranges[1].Len != 1024 || ranges[1].ParentOffset != testAllocationAbs+(abBig+1)*testBlockSize {
		t.Fatalf("second range = %+v", ranges[1])
	}
	images, err := file.MapToImage(0, 1536)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(images) != 2 || images[0].ImageOffset != testAllocationAbs+abBig*testBlockSize {
		t.Fatalf("image ranges = %+v", images)
	}
}

func TestReadExtentsAndEOF(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	file, err := volume.OpenFile("/big.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := file.ReadAt(1536, make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("EOF error = %v", err)
	}
	tail := make([]byte, 32)
	got, err := file.ReadAt(1530, tail)
	if err != nil || got != 6 {
		t.Fatalf("tail read = %d err=%v", got, err)
	}
	if string(tail[:6]) != "BBBBBB" {
		t.Fatalf("tail = %q", tail[:6])
	}
	lossy := make([]byte, 16)
	if n, err := file.ReadAtLossy(1528, lossy); err != nil || n != 8 || string(lossy[:8]) != "BBBBBBBB" {
		t.Fatalf("lossy = %q (%d) err=%v", lossy, n, err)
	}
	if _, err := file.ReadAtLossy(1536, lossy); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy EOF error = %v", err)
	}
}

func TestResourceFork(t *testing.T) {
	volume := openHFS(t, buildHFSImage(t))
	if !volume.HasResourceFork("/res.bin") {
		t.Fatalf("res.bin reported no resource fork")
	}
	if volume.HasResourceFork("/readme.txt") {
		t.Fatalf("readme reported a resource fork")
	}
	resource, err := volume.OpenResourceFork("/res.bin")
	if err != nil {
		t.Fatalf("OpenResourceFork: %v", err)
	}
	if resource.Len() != 7 {
		t.Fatalf("resource length = %d", resource.Len())
	}
	buf := make([]byte, 7)
	if _, err := resource.ReadAt(0, buf); err != nil || string(buf) != "RESDATA" {
		t.Fatalf("resource = %q err=%v", buf, err)
	}
	data, err := volume.OpenFile("/res.bin")
	if err != nil {
		t.Fatalf("OpenFile res.bin: %v", err)
	}
	dataBuf := make([]byte, 3)
	if _, err := data.ReadAt(0, dataBuf); err != nil || string(dataBuf) != "DAT" {
		t.Fatalf("res data = %q err=%v", dataBuf, err)
	}
	if _, err := volume.OpenResourceFork("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("resource fork of a directory error = %v", err)
	}
}

// ---- B-tree behaviour ------------------------------------------------------

func mustFork(t *testing.T, record []byte, logical uint64, blockSize uint32, base uint64) fork {
	t.Helper()
	var extents ExtentRecord
	for index := 0; index < 3; index++ {
		extents[index] = Extent{
			Start:  be16(record, index*4),
			Blocks: be16(record, index*4+2),
		}
	}
	value, err := forkFromRecord(extents, logical, blockSize, base)
	if err != nil {
		t.Fatalf("forkFromRecord: %v", err)
	}
	return value
}

func TestBTreeDeletedRecordSkipped(t *testing.T) {
	image := make([]byte, 2048)
	copy(image, btreeHeader(512, 1, 1, 1, 1, 2, 2))
	leaf := btreeNode(512, -1, 0, 0, 0, [][2][]byte{
		{nil, nil}, // a deleted record: key length zero
		{catalogKeyBytes(2, "kept"), []byte("payload")},
	})
	copy(image[512:], leaf)
	src := source.NewMemorySource(1, image)
	tree, err := openBTree(src, mustFork(t, extentRecord(fixtureExtent{0, 4}), 2048, 512, 0))
	if err != nil {
		t.Fatalf("openBTree: %v", err)
	}
	var keys []string
	if err := tree.walkLeaves(func(key, data []byte) (bool, error) {
		keys = append(keys, string(key))
		return true, nil
	}); err != nil {
		t.Fatalf("walkLeaves: %v", err)
	}
	if len(keys) != 1 || !strings.Contains(keys[0], "kept") {
		t.Fatalf("keys = %v", keys)
	}
}

func TestBTreeCorruption(t *testing.T) {
	src := func(image []byte) source.ByteSource { return source.NewMemorySource(1, image) }
	goodHeader := func() []byte { return btreeHeader(512, 1, 1, 1, 1, 2, 1) }
	goodLeaf := func() []byte {
		return btreeNode(512, -1, 0, 0, 0, [][2][]byte{
			{catalogKeyBytes(2, "a"), []byte{0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}},
		})
	}
	treeImage := func(header, leaf []byte) []byte {
		image := make([]byte, 2048)
		copy(image, header)
		copy(image[512:], leaf)
		return image
	}
	open := func(header, leaf []byte) error {
		_, err := openBTree(src(treeImage(header, leaf)), mustFork(t, extentRecord(fixtureExtent{0, 4}), 2048, 512, 0))
		return err
	}

	// Header node of the wrong kind.
	badHeader := goodHeader()
	badHeader[8] = 0
	if err := open(badHeader, goodLeaf()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("header kind error = %v", err)
	}

	// Node size not a power of two.
	badHeader = goodHeader()
	putBE16(badHeader, 32, 513)
	if err := open(badHeader, goodLeaf()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("node size error = %v", err)
	}

	// No nodes declared.
	badHeader = goodHeader()
	putBE32(badHeader, 36, 0)
	if err := open(badHeader, goodLeaf()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("total nodes error = %v", err)
	}

	// A leaf chain that loops.
	loopLeaf := goodLeaf()
	putBE32(loopLeaf, 0, 1)
	tree, err := openBTree(src(treeImage(goodHeader(), loopLeaf)), mustFork(t, extentRecord(fixtureExtent{0, 4}), 2048, 512, 0))
	if err != nil {
		t.Fatalf("open loop tree: %v", err)
	}
	if err := tree.walkLeaves(func(key, data []byte) (bool, error) { return true, nil }); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("leaf loop error = %v", err)
	}

	// Non-monotonic offset table.
	badLeaf := goodLeaf()
	putBE16(badLeaf, 512-4, 10) // first offset below the descriptor
	if err := walkOnly(t, goodHeader(), badLeaf); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("offset table walk error = %v", err)
	}

	// A key that runs into the next record.
	badLeaf = goodLeaf()
	badLeaf[14] = 200
	if err := walkOnly(t, goodHeader(), badLeaf); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("key length error = %v", err)
	}

	// A forward link past the declared nodes.
	badLeaf = goodLeaf()
	putBE32(badLeaf, 0, 2) // total nodes is 2, so node 2 is outside
	if err := walkOnly(t, goodHeader(), badLeaf); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("forward link error = %v", err)
	}
}

func walkOnly(t *testing.T, header, leaf []byte) error {
	t.Helper()
	image := make([]byte, 2048)
	copy(image, header)
	copy(image[512:], leaf)
	tree, err := openBTree(source.NewMemorySource(1, image), mustFork(t, extentRecord(fixtureExtent{0, 4}), 2048, 512, 0))
	if err != nil {
		return err
	}
	return tree.walkLeaves(func(key, data []byte) (bool, error) { return true, nil })
}

func TestBTreeSearch(t *testing.T) {
	// Two leaf records: the exact key is found, an absent key is not.
	image := make([]byte, 2048)
	copy(image, btreeHeader(512, 1, 1, 1, 1, 2, 2))
	leaf := btreeNode(512, -1, 0, 0, 0, [][2][]byte{
		{catalogKeyBytes(2, "alpha"), []byte("one")},
		{catalogKeyBytes(2, "beta"), []byte("two")},
	})
	copy(image[512:], leaf)
	tree, err := openBTree(source.NewMemorySource(1, image), mustFork(t, extentRecord(fixtureExtent{0, 4}), 2048, 512, 0))
	if err != nil {
		t.Fatalf("openBTree: %v", err)
	}
	data, err := tree.search(catalogKeyBytes(2, "beta"))
	if err != nil || string(data) != "two" {
		t.Fatalf("search beta = %q err=%v", data, err)
	}
	data, err = tree.search(catalogKeyBytes(2, "gamma"))
	if err != nil || data != nil {
		t.Fatalf("search gamma = %q err=%v", data, err)
	}
}

// ---- overflow and corruption ----------------------------------------------

func TestOverflowTreeAbsent(t *testing.T) {
	image := buildHFSImage(t)
	// Remove the extents overflow file.
	mdb := image[1024 : 1024+162]
	putBE32(mdb, 130, 0)
	copy(mdb[134:146], make([]byte, 12))
	volume, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open without overflow tree: %v", err)
	}
	if !hasWarning(volume.Warnings(), "no extents overflow file") {
		t.Fatalf("warnings = %v", volume.Warnings())
	}
	file, err := volume.OpenFile("/big.bin")
	if err != nil {
		t.Fatalf("OpenFile big: %v", err)
	}
	// The first block is mapped; the rest is not, and must not be invented.
	if _, err := file.ReadAt(0, make([]byte, 512)); err != nil {
		t.Fatalf("first block: %v", err)
	}
	if _, err := file.ReadAt(512, make([]byte, 4)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("unmapped read error = %v", err)
	}
	if _, err := file.Extents(0, 1536); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("unmapped extents error = %v", err)
	}
}

func TestOverflowRecordMissing(t *testing.T) {
	image := buildHFSImage(t)
	// Point the overflow record at a different file ID.
	forIndex := testAllocationAbs + abExtents*testBlockSize + 512 + 20
	image[forIndex] = 0x63 // file 99 instead of 20
	volume, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	stats := volume.Stats()
	if stats.ExtentsMissing != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if !hasWarning(volume.Warnings(), "has no overflow extent") {
		t.Fatalf("warnings = %v", volume.Warnings())
	}
}

func TestOpenCorruption(t *testing.T) {
	// No root folder record.
	image := buildHFSImage(t)
	leafOne := testAllocationAbs + abCatalog*testBlockSize + 512
	putBE16(image, leafOne+32, 0x0900) // the root folder's record type
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("missing root error = %v", err)
	}

	// An index node on the leaf chain.
	image = buildHFSImage(t)
	leafTwo := testAllocationAbs + abCatalog*testBlockSize + 1024
	image[leafTwo+8] = 0
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("non-leaf chain error = %v", err)
	}
}

func TestTruncatedVolume(t *testing.T) {
	full := buildHFSImage(t)
	short := full[:20_000]
	volume, err := Open(source.NewMemorySource(1, short))
	if err != nil {
		t.Fatalf("Open truncated: %v", err)
	}
	info := volume.Info()
	if !info.Truncated {
		t.Fatalf("truncation not reported: %+v", info)
	}
	if info.DeclaredBytes != uint64(testImageBytes) {
		t.Fatalf("declared bytes = %d", info.DeclaredBytes)
	}
	if !hasWarning(volume.Warnings(), "declares") {
		t.Fatalf("warnings = %v", volume.Warnings())
	}
}

// ---- decoding primitives ---------------------------------------------------

func TestMacRoman(t *testing.T) {
	if got := decodeMacRoman([]byte("hello")); got != "hello" {
		t.Fatalf("ascii = %q", got)
	}
	if got := decodeMacRoman([]byte{0x8E}); got != "é" {
		t.Fatalf("0x8E = %q", got)
	}
	if got := decodeMacRoman([]byte{0x80, 0x8D, 0xA9}); got != "Äç©" {
		t.Fatalf("high bytes = %q", got)
	}
	if got := decodeMacRoman([]byte{0xF0}); got != "" {
		t.Fatalf("apple logo = %q", got)
	}

	key, err := parseCatalogKey([]byte{0, 0, 0, 0, 2, 4, 'c', 'a', 'f', 0x8E})
	if err != nil || key.parentID != 2 || key.name != "café" {
		t.Fatalf("catalog key = %+v err=%v", key, err)
	}
	if _, err := parseCatalogKey([]byte{0, 0, 0, 0, 2, 32}); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("oversized name error = %v", err)
	}
}

func TestHFSClock(t *testing.T) {
	want := time.Unix(3_400_000_000-2_082_844_800, 0).UTC()
	if got := hfsTime(3_400_000_000); !got.Equal(want) {
		t.Fatalf("hfsTime = %v want %v", got, want)
	}
	if !hfsTime(0).IsZero() {
		t.Fatalf("zero hfs time = %v", hfsTime(0))
	}
}

func hasWarning(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}
