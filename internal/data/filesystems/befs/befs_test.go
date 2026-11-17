package befs

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- fixture geometry ------------------------------------------------------

const (
	beBlockSize    = 1024
	beVolumeBlocks = 64
	beAGShift      = 6
	beInodeSize    = 1024
	beImageBytes   = beVolumeBlocks * beBlockSize

	// Block layout.
	blRootInode = 1
	blRootTree  = 2
	blSubInode  = 4
	blSubTree   = 5
	blFileInode = 7
	blFileData  = 8
	blInnerIno  = 9
	blInnerData = 10
	blEmptyIno  = 11
	blEmptyTree = 12
	blShortLink = 14
	blLongLink  = 15
	blLongData  = 16
	blBigInode  = 17
	blBigArray  = 18
	blBigData0  = 19
	blBigData1  = 20
	blGapInode  = 21
	blGapData   = 22
	blDeleted   = 23
	blBad       = 30
)

const (
	beMAGIC1    = 0x42465331
	beMAGIC2    = 0xdd121031
	beMAGIC3    = 0x15b6830e
	beByteOrder = 0x42494745
	beClean     = 0x434c454e
	beDirty     = 0x44495254
)

// ---- little-endian fixture helpers ----------------------------------------

func putLE16(dst []byte, at int, value uint16) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
}

func putLE32(dst []byte, at int, value uint32) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
	dst[at+2] = byte(value >> 16)
	dst[at+3] = byte(value >> 24)
}

func putLE64(dst []byte, at int, value uint64) {
	putLE32(dst, at, uint32(value))
	putLE32(dst, at+4, uint32(value>>32))
}

type runFixture struct {
	ag     int32
	start  uint16
	length uint16
}

func encodeRun(dst []byte, at int, run runFixture) {
	putLE32(dst, at, uint32(run.ag))
	putLE16(dst, at+4, run.start)
	putLE16(dst, at+6, run.length)
}

type streamFixture struct {
	direct      [12]runFixture
	maxDirect   int64
	indirect    runFixture
	maxIndirect int64
	double      runFixture
	maxDouble   int64
	size        int64
}

func encodeStream(dst []byte, at int, stream streamFixture) {
	for index, run := range stream.direct {
		encodeRun(dst, at+index*8, run)
	}
	putLE64(dst, at+96, uint64(stream.maxDirect))
	encodeRun(dst, at+104, stream.indirect)
	putLE64(dst, at+112, uint64(stream.maxIndirect))
	encodeRun(dst, at+120, stream.double)
	putLE64(dst, at+128, uint64(stream.maxDouble))
	putLE64(dst, at+136, uint64(stream.size))
}

type inodeFixture struct {
	block       uint64
	parent      uint64
	uid         int32
	gid         int32
	mode        uint32
	flags       uint32
	createdRaw  int64
	modifiedRaw int64
	changedRaw  int64
	stream      streamFixture
	shortTarget string
	name        string
}

const (
	inodeInUse       = 0x0001
	inodeDeleted     = 0x0010
	inodeNotReady    = 0x0020
	inodeLongSymlink = 0x0040
)

func beTimestamp(seconds int64) int64 { return seconds<<16 | 7 }

func bswap32(value uint32) uint32 {
	return value<<24 | value>>24 | (value>>8)&0xff00 | (value<<8)&0xff0000
}

func buildInode(f inodeFixture) []byte {
	raw := make([]byte, beInodeSize)
	putLE32(raw, 0, 0x3bbe0ad9)
	encodeRun(raw, 4, runFixture{ag: 0, start: uint16(f.block), length: 1})
	putLE32(raw, 12, uint32(f.uid))
	putLE32(raw, 16, uint32(f.gid))
	putLE32(raw, 20, f.mode)
	putLE32(raw, 24, f.flags)
	putLE64(raw, 28, uint64(f.createdRaw))
	putLE64(raw, 36, uint64(f.modifiedRaw))
	encodeRun(raw, 44, runFixture{ag: 0, start: uint16(f.parent), length: 1})
	putLE32(raw, 64, beInodeSize)
	if f.shortTarget != "" {
		copy(raw[72:216], f.shortTarget)
	} else {
		encodeStream(raw, 72, f.stream)
	}
	putLE64(raw, 216, uint64(f.changedRaw))
	writeInodeName(raw, f.name)
	return raw
}

func writeInodeName(raw []byte, name string) {
	if name == "" {
		return
	}
	putLE32(raw, 232, 0x43535452) // 'CSTR'
	putLE16(raw, 236, 1)
	putLE16(raw, 238, uint16(len(name)+1))
	raw[240] = 0x13
	copy(raw[244:], name)
	raw[244+len(name)] = 0
}

func buildSuperblock(data []byte) {
	at := 512
	copy(data[at:at+32], "BeFS Fixture\x00")
	putLE32(data, at+32, beMAGIC1)
	putLE32(data, at+36, beByteOrder)
	putLE32(data, at+40, beBlockSize)
	putLE32(data, at+44, 10)
	putLE64(data, at+48, beVolumeBlocks)
	putLE64(data, at+56, 24)
	putLE32(data, at+64, beInodeSize)
	putLE32(data, at+68, beMAGIC2)
	putLE32(data, at+72, 1) // blocks per AG
	putLE32(data, at+76, beAGShift)
	putLE32(data, at+80, 1) // one AG
	putLE32(data, at+84, beClean)
	putLE64(data, at+88, 0)  // log blocks
	putLE64(data, at+96, 0)  // log start
	putLE64(data, at+104, 0) // log end
	putLE32(data, at+112, beMAGIC3)
	encodeRun(data, at+116, runFixture{ag: 0, start: blRootInode, length: 1})
	encodeRun(data, at+124, runFixture{})
}

// bTreeNode lays out a BeFS B+tree node.
func bTreeNode(nodeSize int, left, right, overflow int64, keys [][]byte, values []int64) []byte {
	node := make([]byte, nodeSize)
	putLE64(node, 0, uint64(left))
	putLE64(node, 8, uint64(right))
	putLE64(node, 16, uint64(overflow))
	if len(keys) != len(values) {
		panic("fixture key/value mismatch")
	}
	putLE16(node, 24, uint16(len(keys)))
	total := 0
	for _, key := range keys {
		total += len(key)
	}
	putLE16(node, 26, uint16(total))
	at := 28
	for _, key := range keys {
		copy(node[at:], key)
		at += len(key)
	}
	lengths := (28 + total + 7) &^ 7
	previous := 0
	for index, key := range keys {
		previous += len(key)
		putLE16(node, lengths+index*2, uint16(previous))
	}
	valuesAt := lengths + len(keys)*2
	for index, value := range values {
		putLE64(node, valuesAt+index*8, uint64(value))
		_ = index
	}
	return node
}

func bTreeHeader(nodeSize, maxLevels, dataType uint32, root, free, maxSize int64) []byte {
	head := make([]byte, 40)
	putLE32(head, 0, 0x69f6c2e8)
	putLE32(head, 4, nodeSize)
	putLE32(head, 8, maxLevels)
	putLE32(head, 12, dataType)
	putLE64(head, 16, uint64(root))
	putLE64(head, 24, uint64(free))
	putLE64(head, 32, uint64(maxSize))
	return head
}

// treeStreams builds a 2048-byte directory stream whose header sits in block 0
// and whose single leaf node sits at offset 1024.
func treeStream(keys [][]byte, values []int64) []byte {
	stream := make([]byte, 2048)
	copy(stream, bTreeHeader(beBlockSize, 1, 0, beBlockSize, -1, 2048))
	copy(stream[beBlockSize:], bTreeNode(beBlockSize, -1, -1, -1, keys, values))
	return stream
}

func directoryStream() streamFixture {
	return streamFixture{
		direct: [12]runFixture{{ag: 0, start: blRootTree, length: 2}},
		size:   2048,
	}
}

func subDirectoryStream() streamFixture {
	return streamFixture{
		direct: [12]runFixture{{ag: 0, start: blSubTree, length: 2}},
		size:   2048,
	}
}

func emptyDirectoryStream() streamFixture {
	return streamFixture{
		direct: [12]runFixture{{ag: 0, start: blEmptyTree, length: 2}},
		size:   2048,
	}
}

func buildBeFSImage(t *testing.T) []byte {
	t.Helper()
	data := make([]byte, beImageBytes)
	buildSuperblock(data)

	put := func(block uint64, raw []byte) { copy(data[int(block)*beBlockSize:], raw) }

	put(blRootInode, buildInode(inodeFixture{
		block: blRootInode, parent: blRootInode, mode: 0x41ED, flags: inodeInUse,
		createdRaw: beTimestamp(1_700_000_000), modifiedRaw: beTimestamp(1_700_000_100),
		changedRaw: beTimestamp(1_700_000_200), stream: directoryStream(),
	}))
	put(blSubInode, buildInode(inodeFixture{
		block: blSubInode, parent: blRootInode, mode: 0x41ED, flags: inodeInUse,
		createdRaw: beTimestamp(1_700_000_000), modifiedRaw: beTimestamp(1_700_000_100),
		changedRaw: beTimestamp(1_700_000_200), stream: subDirectoryStream(),
	}))
	put(blFileInode, buildInode(inodeFixture{
		block: blFileInode, parent: blRootInode, uid: 500, gid: 501, mode: 0x81A4, flags: inodeInUse,
		createdRaw: beTimestamp(1_700_000_010), modifiedRaw: beTimestamp(1_700_000_020),
		changedRaw: beTimestamp(1_700_000_030), name: "file.txt",
		stream: streamFixture{
			direct: [12]runFixture{{ag: 0, start: blFileData, length: 1}},
			size:   9,
		},
	}))
	put(blInnerIno, buildInode(inodeFixture{
		block: blInnerIno, parent: blSubInode, mode: 0x81A4, flags: inodeInUse,
		stream: streamFixture{
			direct: [12]runFixture{{ag: 0, start: blInnerData, length: 1}},
			size:   11,
		},
	}))
	put(blEmptyIno, buildInode(inodeFixture{
		block: blEmptyIno, parent: blRootInode, mode: 0x41ED, flags: inodeInUse,
		stream: emptyDirectoryStream(),
	}))
	put(blShortLink, buildInode(inodeFixture{
		block: blShortLink, parent: blRootInode, mode: 0xA1FF, flags: inodeInUse,
		shortTarget: "file.txt",
	}))
	longTarget := "target/../path"
	put(blLongLink, buildInode(inodeFixture{
		block: blLongLink, parent: blRootInode, mode: 0xA1FF, flags: inodeInUse | inodeLongSymlink,
		stream: streamFixture{
			direct: [12]runFixture{{ag: 0, start: blLongData, length: 1}},
			size:   int64(len(longTarget)),
		},
	}))
	copy(data[int(blLongData)*beBlockSize:], longTarget)

	put(blBigInode, buildInode(inodeFixture{
		block: blBigInode, parent: blRootInode, mode: 0x81A4, flags: inodeInUse,
		stream: streamFixture{
			indirect:    runFixture{ag: 0, start: blBigArray, length: 1},
			maxIndirect: 2048,
			size:        2048,
		},
	}))
	array := make([]byte, beBlockSize)
	encodeRun(array, 0, runFixture{ag: 0, start: blBigData0, length: 1})
	encodeRun(array, 8, runFixture{ag: 0, start: blBigData1, length: 1})
	put(blBigArray, array)
	for index := 0; index < beBlockSize; index++ {
		data[int(blBigData0)*beBlockSize+index] = 'C'
		data[int(blBigData1)*beBlockSize+index] = 'D'
	}

	put(blGapInode, buildInode(inodeFixture{
		block: blGapInode, parent: blRootInode, mode: 0x81A4, flags: inodeInUse,
		stream: streamFixture{
			direct:    [12]runFixture{{ag: 0, start: blGapData, length: 1}},
			maxDirect: 1024,
			size:      2048,
		},
	}))
	for index := 0; index < beBlockSize; index++ {
		data[int(blGapData)*beBlockSize+index] = 'G'
	}

	put(blDeleted, buildInode(inodeFixture{
		block: blDeleted, parent: blRootInode, mode: 0x81A4, flags: inodeInUse | inodeDeleted,
		stream: streamFixture{
			direct: [12]runFixture{{ag: 0, start: blFileData, length: 1}},
			size:   9,
		},
	}))

	// Directory trees.
	rootStream := treeStream(
		[][]byte{[]byte("."), []byte(".."), []byte("file.txt"), []byte("sub"), []byte("empty"),
			[]byte("shortlink"), []byte("longlink"), []byte("big.bin"), []byte("gap.bin"),
			[]byte("deleted"), []byte("bad"), []byte("hard2")},
		[]int64{blRootInode, blRootInode, blFileInode, blSubInode, blEmptyIno,
			blShortLink, blLongLink, blBigInode, blGapInode, blDeleted, blBad, blFileInode},
	)
	put(blRootTree, rootStream)

	subStream := treeStream(
		[][]byte{[]byte("."), []byte(".."), []byte("inner.bin"), []byte("loop")},
		[]int64{blSubInode, blRootInode, blInnerIno, blSubInode},
	)
	put(blSubTree, subStream)

	emptyStream := treeStream(
		[][]byte{[]byte("."), []byte("..")},
		[]int64{blEmptyIno, blRootInode},
	)
	put(blEmptyTree, emptyStream)

	copy(data[int(blFileData)*beBlockSize:], "hello bef")
	copy(data[int(blInnerData)*beBlockSize:], "inner data\n")
	return data
}

func openBeFS(t *testing.T, data []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func beEntryByName(t *testing.T, entries []Entry, name string) Entry {
	t.Helper()
	for _, entry := range entries {
		if entry.Name == name {
			return entry
		}
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	t.Fatalf("no entry named %q in %v", name, names)
	return Entry{}
}

func beNames(entries []Entry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

// ---- detection and superblock ---------------------------------------------

func TestDetect(t *testing.T) {
	if found, err := Detect(source.NewMemorySource(1, make([]byte, 100))); err != nil || found {
		t.Fatalf("short source: found=%v err=%v", found, err)
	}
	if found, err := Detect(source.NewMemorySource(1, make([]byte, 1024))); err != nil || found {
		t.Fatalf("no magic: found=%v err=%v", found, err)
	}
	if found, err := Detect(source.NewMemorySource(1, buildBeFSImage(t))); err != nil || !found {
		t.Fatalf("fixture: found=%v err=%v", found, err)
	}

	swapped := buildBeFSImage(t)
	putLE32(swapped, 512+32, bswap32(beMAGIC1))
	if _, err := Detect(source.NewMemorySource(1, swapped)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("swapped magic error = %v", err)
	}

	marker := buildBeFSImage(t)
	putLE32(marker, 512+36, bswap32(beByteOrder))
	if _, err := Detect(source.NewMemorySource(1, marker)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("big-endian marker error = %v", err)
	}

	unknownSize := buildBeFSImage(t)
	putLE32(unknownSize, 512+40, 512)
	if _, err := Detect(source.NewMemorySource(1, unknownSize)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("block size error = %v", err)
	}

	badMagic2 := buildBeFSImage(t)
	putLE32(badMagic2, 512+68, 0)
	if _, err := Detect(source.NewMemorySource(1, badMagic2)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("magic2 error = %v", err)
	}

	badMagic3 := buildBeFSImage(t)
	putLE32(badMagic3, 512+112, 0)
	if _, err := Detect(source.NewMemorySource(1, badMagic3)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("magic3 error = %v", err)
	}

	// A recognised magic in a source too short for the whole superblock.
	truncated := make([]byte, 600)
	putLE32(truncated, 544, beMAGIC1)
	if _, err := Detect(source.NewMemorySource(1, truncated)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("truncated superblock error = %v", err)
	}
}

func TestSuperblock(t *testing.T) {
	data := buildBeFSImage(t)
	sb, err := readSuperblock(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("readSuperblock: %v", err)
	}
	if sb.name != "BeFS Fixture" || sb.blockSize != beBlockSize || sb.blockShift != 10 {
		t.Fatalf("superblock = %+v", sb)
	}
	if sb.numBlocks != beVolumeBlocks || sb.usedBlocks != 24 || sb.inodeSize != beInodeSize {
		t.Fatalf("geometry = %+v", sb)
	}
	if sb.agShift != beAGShift || sb.agBlocks() != 64 || sb.numAGs != 1 {
		t.Fatalf("allocation groups = %+v", sb)
	}
	if !sb.isClean() {
		t.Fatalf("fixture reported dirty")
	}
	if block, ok := sb.rootDir.toBlock(sb.agShift); !ok || block != blRootInode {
		t.Fatalf("root inode = %d ok=%v", block, ok)
	}
	if sb.blockOffset(blFileData) != blFileData*beBlockSize {
		t.Fatalf("block offset = %d", sb.blockOffset(blFileData))
	}
}

func TestSuperblockValidation(t *testing.T) {
	cases := []struct {
		name    string
		at      int
		value   uint64
		width   int
		unicode bool
	}{
		{"small block count", 48, 9, 8, false},
		{"used blocks above total", 56, beVolumeBlocks + 1, 8, false},
		{"block shift", 44, 5, 4, false},
		{"inode size", 64, 512, 4, false},
		{"blocks per ag", 72, 0, 4, false},
		{"ag shift zero", 76, 0, 4, false},
		{"ag shift too large", 76, 17, 4, false},
		{"no allocation groups", 80, 0, 4, false},
		{"inconsistent allocation groups", 80, 2, 4, false},
	}
	for _, tc := range cases {
		data := buildBeFSImage(t)
		writeWidth(data, 512+tc.at, tc.value, tc.width)
		if _, err := readSuperblock(source.NewMemorySource(1, data)); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("%s: error = %v", tc.name, err)
		}
	}

	// num_blocks times block_size may not exceed the source.
	data := buildBeFSImage(t)
	putLE64(data, 512+48, 128)
	putLE32(data, 512+76, 7) // 128 blocks per AG
	if _, err := readSuperblock(source.NewMemorySource(1, data)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("source too short error = %v", err)
	}

	// The root run must name exactly one inode.
	data = buildBeFSImage(t)
	encodeRun(data, 512+116, runFixture{ag: 0, start: blRootInode, length: 2})
	if _, err := readSuperblock(source.NewMemorySource(1, data)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("root run length error = %v", err)
	}
}

func writeWidth(dst []byte, at int, value uint64, width int) {
	switch width {
	case 4:
		putLE32(dst, at, uint32(value))
	case 8:
		putLE64(dst, at, value)
	default:
		panic("unsupported width")
	}
}

// ---- volume report ---------------------------------------------------------

func TestInfo(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	info := volume.Info()
	if info.Name != "BeFS Fixture" || info.BlockSize != beBlockSize || info.BlockShift != 10 {
		t.Fatalf("info = %+v", info)
	}
	if info.NumBlocks != beVolumeBlocks || info.UsedBlocks != 24 || info.InodeSize != beInodeSize {
		t.Fatalf("geometry = %+v", info)
	}
	if info.BlocksPerAG != 1 || info.AGShift != beAGShift || info.NumAGs != 1 {
		t.Fatalf("allocation groups = %+v", info)
	}
	if !info.Clean || info.State != "clean" {
		t.Fatalf("state = %q clean=%v", info.State, info.Clean)
	}
	if info.RootInode != blRootInode {
		t.Fatalf("root inode = %d", info.RootInode)
	}
	if info.Entries != 11 || info.Directories != 4 || info.Files != 7 || info.Symlinks != 2 {
		t.Fatalf("node counts = %+v", info)
	}
	if info.BTreeNodes != 3 || info.BTreeLookups != 3 {
		t.Fatalf("tree counters = %+v", info)
	}
	if info.NodesRead != 11 {
		t.Fatalf("nodes read = %d", info.NodesRead)
	}
	if info.Undecodable != 3 || info.DirectoryLoops != 1 || info.Unreadable != 0 || info.Malformed != 3 {
		t.Fatalf("walk counters = %+v", info)
	}
	if len(info.Warnings) != 3 || info.WarningsDropped != 0 {
		t.Fatalf("warnings = %v dropped=%d", info.Warnings, info.WarningsDropped)
	}
	if !hasBeWarning(info.Warnings, "gap.bin") {
		t.Fatalf("gap warning missing: %v", info.Warnings)
	}

	stats := volume.Stats()
	if stats.TreeNodes != 3 || stats.Lookups != 3 || stats.NodesRead != 11 || stats.Malformed != 3 {
		t.Fatalf("stats = %+v", stats)
	}
}

// ---- directories -----------------------------------------------------------

func TestListDirRoot(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	want := "file.txt,sub,empty,shortlink,longlink,big.bin,gap.bin,hard2"
	if got := strings.Join(beNames(entries), ","); got != want {
		t.Fatalf("names = %s want %s", got, want)
	}

	file := beEntryByName(t, entries, "file.txt")
	if file.Path != "/file.txt" || file.Inode != blFileInode || file.ParentInode != blRootInode {
		t.Fatalf("file = %+v", file)
	}
	if !file.IsFile || file.IsDir || file.IsSymlink {
		t.Fatalf("file flags = %+v", file)
	}
	if file.Size != 9 || !file.HasAllocated || file.Allocated != beBlockSize {
		t.Fatalf("file size = %+v", file)
	}
	if file.Mode != 0x81A4 || file.UID != 500 || file.GID != 501 {
		t.Fatalf("file metadata = %+v", file)
	}
	if !file.HasCreated || !file.Created.Equal(time.Unix(1_700_000_010, 0).UTC()) {
		t.Fatalf("created = %v", file.Created)
	}
	if !file.HasModified || !file.Modified.Equal(time.Unix(1_700_000_020, 0).UTC()) {
		t.Fatalf("modified = %v", file.Modified)
	}
	if !file.HasChanged || !file.Changed.Equal(time.Unix(1_700_000_030, 0).UTC()) {
		t.Fatalf("changed = %v", file.Changed)
	}

	sub := beEntryByName(t, entries, "sub")
	if !sub.IsDir || sub.Inode != blSubInode || sub.HasAllocated {
		t.Fatalf("sub = %+v", sub)
	}

	link := beEntryByName(t, entries, "shortlink")
	if !link.IsSymlink || link.SymlinkTarget != "file.txt" || !link.HasAllocated || link.Allocated != 0 {
		t.Fatalf("shortlink = %+v", link)
	}
	long := beEntryByName(t, entries, "longlink")
	if !long.IsSymlink || long.SymlinkTarget != "target/../path" {
		t.Fatalf("longlink = %+v", long)
	}
	if !long.HasAllocated || long.Allocated != beBlockSize {
		t.Fatalf("longlink allocation = %+v", long)
	}

	gap := beEntryByName(t, entries, "gap.bin")
	if gap.HasAllocated {
		t.Fatalf("gap.bin should have no validated allocation: %+v", gap)
	}

	hard := beEntryByName(t, entries, "hard2")
	if !hard.IsFile || hard.Inode != blFileInode || hard.Path != "/hard2" {
		t.Fatalf("hard2 = %+v", hard)
	}

	// A deleted inode and an unreadable inode are counted, not listed.
	if strings.Contains(strings.Join(beNames(entries), ","), "deleted") {
		t.Fatalf("deleted inode was listed")
	}
	if strings.Contains(strings.Join(beNames(entries), ","), "bad") {
		t.Fatalf("unreadable inode was listed")
	}
}

func TestStatNested(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	if root.Name != "/" || root.Path != "/" || !root.IsDir || root.Inode != blRootInode || root.HasParent {
		t.Fatalf("root = %+v", root)
	}
	if other, err := volume.Stat(""); err != nil || other.Path != "/" {
		t.Fatalf("empty stat = %+v err=%v", other, err)
	}
	inner, err := volume.Stat("sub/inner.bin")
	if err != nil {
		t.Fatalf("Stat inner: %v", err)
	}
	if inner.Name != "inner.bin" || inner.Path != "/sub/inner.bin" || inner.Inode != blInnerIno {
		t.Fatalf("inner = %+v", inner)
	}
	if inner.Size != 11 || inner.ParentInode != blSubInode {
		t.Fatalf("inner metadata = %+v", inner)
	}
	up, err := volume.Stat("/sub/..")
	if err != nil || up.Path != "/" {
		t.Fatalf("dotdot = %+v err=%v", up, err)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	if _, err := volume.Stat("/sub/inner.bin/x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("through-file error = %v", err)
	}
}

func TestEmptyDir(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	entries, err := volume.ListDir("/empty")
	if err != nil {
		t.Fatalf("ListDir empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty dir entries = %v", beNames(entries))
	}
}

func TestPathErrors(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	if _, err := volume.ListDir("/file.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir file error = %v", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile dir error = %v", err)
	}
	if _, err := volume.OpenFile("/shortlink"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("OpenFile symlink error = %v", err)
	}
	if _, err := volume.OpenSymlink("/file.txt"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("OpenSymlink file error = %v", err)
	}
}

// ---- file data -------------------------------------------------------------

func TestReadFile(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	file, err := volume.OpenFile("/file.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 9 || file.IsEmpty() {
		t.Fatalf("length = %d", file.Len())
	}
	buf := make([]byte, 9)
	if _, err := file.ReadAt(0, buf); err != nil || string(buf) != "hello bef" {
		t.Fatalf("data = %q err=%v", buf, err)
	}
	inner, err := volume.OpenFile("/sub/inner.bin")
	if err != nil {
		t.Fatalf("OpenFile inner: %v", err)
	}
	innerBuf := make([]byte, 11)
	if _, err := inner.ReadAt(0, innerBuf); err != nil || string(innerBuf) != "inner data\n" {
		t.Fatalf("inner = %q err=%v", innerBuf, err)
	}
	if _, err := volume.OpenFile("/gap.bin"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("gap file error = %v", err)
	}
}

func TestIndirectDataStream(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	file, err := volume.OpenFile("/big.bin")
	if err != nil {
		t.Fatalf("OpenFile big: %v", err)
	}
	if file.Len() != 2048 {
		t.Fatalf("length = %d", file.Len())
	}
	all := make([]byte, 2048)
	if _, err := file.ReadAt(0, all); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if all[0] != 'C' || all[1023] != 'C' || all[1024] != 'D' || all[2047] != 'D' {
		t.Fatalf("indirect data mismatch: %#x %#x %#x %#x", all[0], all[1023], all[1024], all[2047])
	}
	ranges, err := file.Extents(0, 2048)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 2 || ranges[0].ParentOffset != blBigData0*beBlockSize || ranges[1].ParentOffset != blBigData1*beBlockSize {
		t.Fatalf("ranges = %+v", ranges)
	}
	images, err := file.MapToImage(0, 2048)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(images) != 2 || images[0].ImageOffset != blBigData0*beBlockSize {
		t.Fatalf("images = %+v", images)
	}
	if _, err := file.ReadAt(2048, make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("EOF error = %v", err)
	}
	tail := make([]byte, 16)
	if n, err := file.ReadAt(2040, tail); err != nil || n != 8 {
		t.Fatalf("tail read = %d err=%v", n, err)
	}
	lossy := make([]byte, 16)
	if n, err := file.ReadAtLossy(2040, lossy); err != nil || n != 8 || string(lossy[:8]) != "DDDDDDDD" {
		t.Fatalf("lossy = %q (%d) err=%v", lossy, n, err)
	}
}

func TestSymlinks(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	short, err := volume.OpenSymlink("/shortlink")
	if err != nil {
		t.Fatalf("OpenSymlink short: %v", err)
	}
	if short.Len() != 8 {
		t.Fatalf("short length = %d", short.Len())
	}
	shortBuf := make([]byte, 8)
	if _, err := short.ReadAt(0, shortBuf); err != nil || string(shortBuf) != "file.txt" {
		t.Fatalf("short target = %q err=%v", shortBuf, err)
	}
	long, err := volume.OpenSymlink("/longlink")
	if err != nil {
		t.Fatalf("OpenSymlink long: %v", err)
	}
	longBuf := make([]byte, 14)
	if _, err := long.ReadAt(0, longBuf); err != nil || string(longBuf) != "target/../path" {
		t.Fatalf("long target = %q err=%v", longBuf, err)
	}
}

func TestDirectoryLoop(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	entries, err := volume.ListDir("/sub")
	if err != nil {
		t.Fatalf("ListDir sub: %v", err)
	}
	var loop *Entry
	for index := range entries {
		if entries[index].Name == "loop" {
			loop = &entries[index]
		}
	}
	if loop == nil || !loop.IsDir || loop.Inode != blSubInode {
		t.Fatalf("loop entry = %+v", loop)
	}
	if volume.Info().DirectoryLoops != 1 {
		t.Fatalf("directory loops = %d", volume.Info().DirectoryLoops)
	}
}

// ---- B+tree internals ------------------------------------------------------

func standardTreeStream() []byte {
	stream := make([]byte, 2048)
	copy(stream, bTreeHeader(beBlockSize, 1, 0, beBlockSize, -1, 2048))
	copy(stream[beBlockSize:], bTreeNode(beBlockSize, -1, -1, -1,
		[][]byte{[]byte("alpha"), []byte("beta")}, []int64{7, 8}))
	return stream
}

func readStandardTree(t *testing.T, stream []byte) (*Listing, error) {
	t.Helper()
	return readBTree(source.NewMemorySource(1, stream))
}

func TestBTreeRead(t *testing.T) {
	listing, err := readStandardTree(t, standardTreeStream())
	if err != nil {
		t.Fatalf("readBTree: %v", err)
	}
	if len(listing.entries) != 2 || listing.entries[0].name != "alpha" || listing.entries[0].inode != 7 {
		t.Fatalf("entries = %+v", listing.entries)
	}
	if listing.entries[1].name != "beta" || listing.entries[1].inode != 8 {
		t.Fatalf("entries = %+v", listing.entries)
	}
	if listing.nodesRead != 1 {
		t.Fatalf("nodes read = %d", listing.nodesRead)
	}
}

func TestBTreeCorruption(t *testing.T) {
	mutate := func(apply func([]byte)) []byte {
		stream := standardTreeStream()
		apply(stream)
		return stream
	}
	corrupt := func(name string, stream []byte) {
		t.Helper()
		if _, err := readStandardTree(t, stream); err == nil {
			t.Fatalf("%s: no error", name)
		}
	}
	corruptKind := func(name string, stream []byte, want error) {
		t.Helper()
		if _, err := readStandardTree(t, stream); !errors.Is(err, want) {
			t.Fatalf("%s: error = %v want %v", name, err, want)
		}
	}

	corruptKind("magic", mutate(func(s []byte) { putLE32(s, 0, 0) }), source.ErrCorrupt)
	corruptKind("swapped magic", mutate(func(s []byte) { putLE32(s, 0, 0xe8c2f669) }), source.ErrUnsupported)
	corruptKind("node size", mutate(func(s []byte) { putLE32(s, 4, 100) }), source.ErrCorrupt)
	corruptKind("node size floor", mutate(func(s []byte) { putLE32(s, 4, 32) }), source.ErrCorrupt)
	corruptKind("levels", mutate(func(s []byte) { putLE32(s, 8, 0) }), source.ErrUnsupported)
	corruptKind("data type", mutate(func(s []byte) { putLE32(s, 12, 1) }), source.ErrUnsupported)
	corruptKind("maximum size", mutate(func(s []byte) { putLE64(s, 32, 1024) }), source.ErrCorrupt)
	corruptKind("root zero", mutate(func(s []byte) { putLE64(s, 16, 0) }), source.ErrCorrupt)
	corruptKind("root unaligned", mutate(func(s []byte) { putLE64(s, 16, beBlockSize+8) }), source.ErrCorrupt)
	corruptKind("fragment link", mutate(func(s []byte) { putLE64(s, beBlockSize+8, ^uint64(2)) }), source.ErrUnsupported)
	corruptKind("free node", mutate(func(s []byte) { putLE64(s, 24, ^uint64(1)) }), source.ErrUnsupported)

	// A leaf whose right link returns to itself.
	corruptKind("leaf loop", mutate(func(s []byte) {
		putLE64(s, beBlockSize+8, beBlockSize)
	}), source.ErrCorrupt)

	// A leaf chain that reaches an interior node.
	stream := make([]byte, 3072)
	copy(stream, bTreeHeader(beBlockSize, 2, 0, beBlockSize, -1, 3072))
	copy(stream[beBlockSize:], bTreeNode(beBlockSize, -1, 2*beBlockSize, -1,
		[][]byte{[]byte("a")}, []int64{1}))
	copy(stream[2*beBlockSize:], bTreeNode(beBlockSize, -1, -1, beBlockSize, nil, nil))
	corruptKind("interior on leaf chain", stream, source.ErrCorrupt)

	// Key lengths must be cumulative and inside 1..=256.
	corrupt("key length zero", mutate(func(s []byte) {
		lengths := (28 + len("alphabeta") + 7) &^ 7
		putLE16(s, beBlockSize+lengths, 0)
	}))
	corrupt("key length non-cumulative", mutate(func(s []byte) {
		lengths := (28 + len("alphabeta") + 7) &^ 7
		putLE16(s, beBlockSize+lengths+2, 3)
	}))
	corrupt("key area overflow", mutate(func(s []byte) {
		putLE16(s, beBlockSize+26, 10_000)
	}))
}

func TestBTreeMalformedEntries(t *testing.T) {
	stream := make([]byte, 2048)
	copy(stream, bTreeHeader(beBlockSize, 1, 0, beBlockSize, -1, 2048))
	copy(stream[beBlockSize:], bTreeNode(beBlockSize, -1, -1, -1,
		[][]byte{[]byte{'n', 0, 'l'}, []byte("good"), []byte("zero")}, []int64{5, 6, 0}))
	listing, err := readBTree(source.NewMemorySource(1, stream))
	if err != nil {
		t.Fatalf("readBTree: %v", err)
	}
	if len(listing.entries) != 1 || listing.entries[0].name != "good" {
		t.Fatalf("entries = %+v", listing.entries)
	}
	if listing.malformed != 2 {
		t.Fatalf("malformed = %d", listing.malformed)
	}

	// A duplicated name lists the first and counts the second.
	stream = make([]byte, 2048)
	copy(stream, bTreeHeader(beBlockSize, 1, 0, beBlockSize, -1, 2048))
	copy(stream[beBlockSize:], bTreeNode(beBlockSize, -1, -1, -1,
		[][]byte{[]byte("dup"), []byte("dup")}, []int64{5, 6}))
	listing, err = readBTree(source.NewMemorySource(1, stream))
	if err != nil {
		t.Fatalf("readBTree duplicate: %v", err)
	}
	if len(listing.entries) != 1 || listing.malformed != 1 {
		t.Fatalf("duplicate listing = %+v", listing)
	}
}

// ---- inode internals -------------------------------------------------------

func TestTimestampAndKinds(t *testing.T) {
	if _, ok := timestampValue(0); ok {
		t.Fatalf("zero timestamp reported set")
	}
	if got := beTimestamp(1_700_000_000); got>>16 != 1_700_000_000 {
		t.Fatalf("timestamp shift = %d", got)
	}
	if value, ok := timestampValue(1_700_000_000 << 16); !ok || value != 1_700_000_000 {
		t.Fatalf("timestamp value = %d ok=%v", value, ok)
	}
	cases := []struct {
		mode uint32
		kind InodeKind
	}{
		{0x41ED, KindDirectory},
		{0x81A4, KindFile},
		{0xA1FF, KindSymlink},
		{0x1234, KindFifo},
		{0xC000, KindSocket},
		{0x6000, KindBlockDevice},
		{0x2000, KindCharDevice},
		{0x0000, KindUnknown},
	}
	for _, tc := range cases {
		if kind := kindFromMode(tc.mode); kind != tc.kind {
			t.Fatalf("mode %#x = %v want %v", tc.mode, kind, tc.kind)
		}
	}
}

func TestInodeParsing(t *testing.T) {
	data := buildBeFSImage(t)
	sb, err := readSuperblock(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("readSuperblock: %v", err)
	}
	inode, err := parseInode(data[blFileInode*beBlockSize:], blFileInode, sb)
	if err != nil {
		t.Fatalf("parseInode: %v", err)
	}
	if inode.kind != KindFile || inode.mode != 0x81A4 || inode.uid != 500 || inode.gid != 501 {
		t.Fatalf("inode = %+v", inode)
	}
	if inode.size != 9 || inode.name != "file.txt" {
		t.Fatalf("inode size/name = %d/%q", inode.size, inode.name)
	}
	if inode.created == nil || *inode.created != 1_700_000_010 {
		t.Fatalf("created = %v", inode.created)
	}
	if inode.isLongSymlink() {
		t.Fatalf("regular file reported as a long symlink")
	}

	shortRaw := data[blShortLink*beBlockSize:]
	short, err := parseInode(shortRaw, blShortLink, sb)
	if err != nil {
		t.Fatalf("parseInode short: %v", err)
	}
	if short.kind != KindSymlink || short.shortSymlink == nil || string(short.shortSymlink) != "file.txt" {
		t.Fatalf("short symlink = %+v", short)
	}
	if short.size != 8 {
		t.Fatalf("short symlink size = %d", short.size)
	}

	longRaw := data[blLongLink*beBlockSize:]
	long, err := parseInode(longRaw, blLongLink, sb)
	if err != nil {
		t.Fatalf("parseInode long: %v", err)
	}
	if !long.isLongSymlink() || long.size != 14 {
		t.Fatalf("long symlink = %+v", long)
	}
}

func TestInodeValidation(t *testing.T) {
	data := buildBeFSImage(t)
	sb, err := readSuperblock(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("readSuperblock: %v", err)
	}
	block := func() []byte {
		return append([]byte(nil), data[blDeleted*beBlockSize:(blDeleted+1)*beBlockSize]...)
	}
	if _, err := parseInode(block(), blDeleted, sb); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("deleted inode error = %v", err)
	}

	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"magic", func(raw []byte) { putLE32(raw, 0, 0) }},
		{"not in use", func(raw []byte) { putLE32(raw, 24, inodeLongSymlink) }},
		{"not ready", func(raw []byte) { putLE32(raw, 24, inodeInUse|inodeNotReady) }},
		{"inode size", func(raw []byte) { putLE32(raw, 64, 512) }},
		{"self name", func(raw []byte) { encodeRun(raw, 4, runFixture{ag: 0, start: 60, length: 1}) }},
		{"parent length", func(raw []byte) { encodeRun(raw, 44, runFixture{ag: 0, start: blRootInode, length: 2}) }},
		{"negative size", func(raw []byte) { putLE64(raw, 72+136, ^uint64(0)) }},
		{"negative max direct", func(raw []byte) { putLE64(raw, 72+96, ^uint64(0)) }},
	}
	for _, tc := range cases {
		raw := append([]byte(nil), data[blFileInode*beBlockSize:(blFileInode+1)*beBlockSize]...)
		tc.mutate(raw)
		if _, err := parseInode(raw, blFileInode, sb); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("%s: error = %v", tc.name, err)
		}
	}

	// A short symbolic link without a terminating NUL.
	shortRaw := append([]byte(nil), data[blShortLink*beBlockSize:(blShortLink+1)*beBlockSize]...)
	for index := 72; index < 216; index++ {
		shortRaw[index] = 'x'
	}
	if _, err := parseInode(shortRaw, blShortLink, sb); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("unterminated short symlink error = %v", err)
	}
}

// ---- file map internals ----------------------------------------------------

func TestFileMapGap(t *testing.T) {
	volume := openBeFS(t, buildBeFSImage(t))
	if _, err := volume.OpenFile("/gap.bin"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("gap map error = %v", err)
	}
}

func TestRunValidation(t *testing.T) {
	data := buildBeFSImage(t)
	sb, err := readSuperblock(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("readSuperblock: %v", err)
	}
	zero := blockRun{}
	if block, ok, err := sb.validateRun(zero, "test"); err != nil || ok || block != 0 {
		t.Fatalf("zero run = %d ok=%v err=%v", block, ok, err)
	}
	negative := blockRun{allocationGroup: -1, start: 1, length: 1}
	if _, _, err := sb.validateRun(negative, "test"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("negative group error = %v", err)
	}
	tooLarge := blockRun{allocationGroup: 0, start: 60, length: 10}
	if _, _, err := sb.validateRun(tooLarge, "test"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("past group error = %v", err)
	}
	zeroBlock := blockRun{allocationGroup: 0, start: 0, length: 1}
	if _, _, err := sb.validateRun(zeroBlock, "test"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("block zero error = %v", err)
	}
	if block, ok, err := sb.validateRun(blockRun{allocationGroup: 0, start: blFileData, length: 1}, "test"); err != nil || !ok || block != blFileData {
		t.Fatalf("valid run = %d ok=%v err=%v", block, ok, err)
	}
}

func TestDirtyVolumeWarning(t *testing.T) {
	data := buildBeFSImage(t)
	putLE32(data, 512+84, beDirty)
	volume := openBeFS(t, data)
	info := volume.Info()
	if info.Clean || info.State != "dirty" {
		t.Fatalf("state = %q clean=%v", info.State, info.Clean)
	}
	if !hasBeWarning(info.Warnings, "marked dirty") {
		t.Fatalf("warnings = %v", info.Warnings)
	}
}

func TestTruncatedImage(t *testing.T) {
	data := buildBeFSImage(t)
	short := data[:40*beBlockSize]
	if _, err := Open(source.NewMemorySource(1, short)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("truncated image error = %v", err)
	}
}

func hasBeWarning(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}
