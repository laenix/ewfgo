package jfs

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testBlockSize    = 4096
	testVolumeBlocks = 256
)

// ---- little-endian fixture helpers -----------------------------------------

func putU16(dst []byte, at int, value uint16) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
}

func putU32(dst []byte, at int, value uint32) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
	dst[at+2] = byte(value >> 16)
	dst[at+3] = byte(value >> 24)
}

func putU64(dst []byte, at int, value uint64) {
	putU32(dst, at, uint32(value))
	putU32(dst, at+4, uint32(value>>32))
}

func writePxd(dst []byte, at int, length uint32, address uint64) {
	word := (length & 0x00ff_ffff) | uint32(address>>32)<<24
	putU32(dst, at, word)
	putU32(dst, at+4, uint32(address))
}

func xadBytes(flag uint8, logical uint64, length uint32, address uint64) []byte {
	out := make([]byte, 16)
	out[0] = flag
	out[3] = byte(logical >> 32)
	putU32(out, 4, uint32(logical))
	writePxd(out, 8, length, address)
	return out
}

func xtRoot(flags uint8, entries [][]byte) []byte {
	out := make([]byte, 288)
	out[16] = flags
	putU16(out, 18, uint16(len(entries)+2))
	putU16(out, 20, 18)
	for index, entry := range entries {
		copy(out[(index+2)*16:], entry)
	}
	return out
}

func xtPage(flags uint8, entries [][]byte) []byte {
	out := make([]byte, testBlockSize)
	out[16] = flags
	putU16(out, 18, uint16(len(entries)+2))
	putU16(out, 20, 256)
	for index, entry := range entries {
		copy(out[(index+2)*16:], entry)
	}
	return out
}

type testDirEntry struct {
	inode uint32
	name  string
	index uint32
}

func nameUnits(name string) []uint16 { return utf16.Encode([]rune(name)) }

func writeDirEntry(dst []byte, slot int, entry testDirEntry, next int8, headerChars int) int {
	at := slot * 32
	units := nameUnits(entry.name)
	putU32(dst, at, entry.inode)
	dst[at+4] = byte(next)
	dst[at+5] = byte(len(units))
	take := len(units)
	if take > headerChars {
		take = headerChars
	}
	for index := 0; index < take; index++ {
		putU16(dst, at+6+index*2, units[index])
	}
	if headerChars == 11 {
		putU32(dst, at+28, entry.index)
	}
	return len(units) - take
}

func dirRoot(entries []testDirEntry, dirIndex bool) []byte {
	headerChars := 11
	if !dirIndex {
		headerChars = 13
	}
	out := make([]byte, 288)
	out[16] = BT_ROOT | BT_LEAF
	out[17] = byte(len(entries))
	for index, entry := range entries {
		slot := index + 1
		out[24+index] = byte(slot)
		writeDirEntry(out, slot, entry, -1, headerChars)
	}
	return out
}

func dirPage(flags uint8, next uint64, entries []testDirEntry, dirIndex bool) []byte {
	headerChars := 11
	if !dirIndex {
		headerChars = 13
	}
	out := make([]byte, testBlockSize)
	putU64(out, 0, next)
	out[16] = flags
	out[17] = byte(len(entries))
	out[20] = 128
	out[21] = 124
	stbl := 124 * 32
	for index, entry := range entries {
		slot := index + 1
		out[stbl+index] = byte(slot)
		writeDirEntry(out, slot, entry, -1, headerChars)
	}
	return out
}

func inodeBytes(number uint32, mode uint32, size uint64, nlink uint32) []byte {
	out := make([]byte, InodeSize)
	putU32(out, 0x00, 0x1234)
	putU32(out, 0x04, 0)
	putU32(out, 0x08, number)
	putU32(out, 0x0C, 1)
	putU64(out, 0x18, size)
	putU64(out, 0x20, (size+InodeSize-1)/InodeSize)
	putU32(out, 0x28, nlink)
	putU32(out, 0x2C, 1000)
	putU32(out, 0x30, 1000)
	putU32(out, 0x34, mode)
	putU32(out, 0x38, 1_700_000_000)
	putU32(out, 0x3C, 1)
	putU32(out, 0x40, 1_700_000_100)
	putU32(out, 0x48, 1_700_000_200)
	putU32(out, 0x50, 1_700_000_300)
	return out
}

func setInode(data []byte, block uint32, slot uint32, inode []byte) {
	at := int(block)*testBlockSize + int(slot)*InodeSize
	copy(data[at:at+InodeSize], inode)
}

func fillBlock(data []byte, block uint32, fill byte, prefix string) {
	at := int(block) * testBlockSize
	for index := 0; index < testBlockSize; index++ {
		data[at+index] = fill
	}
	copy(data[at:], prefix)
}

// ---- volume fixture --------------------------------------------------------

// buildJFSImage synthesises a complete, self-consistent JFS aggregate:
//
//	superblock at 0x8000
//	fixed aggregate inode table at 0xB000 (inodes 2 and 16)
//	block map control page at block 20, dmap page at block 23
//	fileset inode map control at block 21, IAG 0 at block 22
//	inode extent at blocks 24..27
//	file and directory data in blocks 30..40
func buildJFSImage(t *testing.T) []byte {
	t.Helper()
	data := make([]byte, testVolumeBlocks*testBlockSize)

	sb := make([]byte, 0xB8)
	copy(sb[0:4], []byte("JFS1"))
	putU32(sb, 0x04, 2)
	putU64(sb, 0x08, uint64(testVolumeBlocks)<<3)
	putU32(sb, 0x10, testBlockSize)
	putU16(sb, 0x14, 12)
	putU16(sb, 0x16, 3)
	putU32(sb, 0x18, 512)
	putU16(sb, 0x1C, 9)
	putU32(sb, 0x20, 8192)
	putU32(sb, 0x24, JFS_LINUX|JFS_DIR_INDEX)
	putU32(sb, 0x28, FM_CLEAN)
	putU32(sb, 0x2C, 0)
	writePxd(sb, 0x30, 4, 27)
	writePxd(sb, 0x38, 2, 21)
	putU32(sb, 0x40, 0)
	putU32(sb, 0x44, 0)
	writePxd(sb, 0x48, 1, 10)
	writePxd(sb, 0x50, 1, 12)
	putU32(sb, 0x58, 1_700_000_000)
	putU32(sb, 0x5C, 0)
	putU32(sb, 0x60, 0)
	sb[0x64] = 0
	copy(sb[0x65:0x70], []byte("jfspack"))
	for index := 0; index < 16; index++ {
		sb[0x88+index] = byte(index)
	}
	copy(sb[0x98:0xA8], []byte("jfs fixture"))
	for index := 0; index < 16; index++ {
		sb[0xA8+index] = byte(0xF0 + index)
	}
	copy(data[SuperblockOffset:], sb)

	// Aggregate inode 2 is the block map file; inode 16 is the fileset map.
	bmap := inodeBytes(2, 0x81A4, 0, 1)
	copy(bmap[0xE0:], xtRoot(BT_ROOT|BT_LEAF, [][]byte{
		xadBytes(0, 0, 1, 20),
		xadBytes(0, 4, 1, 23),
	}))
	copy(data[AITableOffset+2*InodeSize:], bmap)

	fileset := inodeBytes(16, 0x81A4, 0, 1)
	copy(fileset[0xE0:], xtRoot(BT_ROOT|BT_LEAF, [][]byte{
		xadBytes(0, 0, 1, 21),
		xadBytes(0, 1, 1, 22),
	}))
	copy(data[AITableOffset+16*InodeSize:], fileset)

	// Block map control page.
	control := data[20*testBlockSize : 21*testBlockSize]
	putU64(control, 0, testVolumeBlocks)
	putU64(control, 8, 5)
	putU32(control, 16, 0)
	putU32(control, 20, 1)
	putU32(control, 24, 1)
	putU32(control, 28, 0)
	putU32(control, 32, 0)
	putU32(control, 36, 0)
	putU32(control, 40, 0)
	putU32(control, 44, 1)
	putU32(control, 48, 0)
	putU32(control, 52, 8)
	putU64(control, 56, 5)
	putU64(control, 1080, 8192)
	control[1088] = 0

	// Fileset inode map control page.
	dinomap := data[21*testBlockSize : 22*testBlockSize]
	putU32(dinomap, 0, 0)
	putU32(dinomap, 4, 0)
	putU32(dinomap, 8, 40)
	putU32(dinomap, 12, 35)
	putU32(dinomap, 16, 4)
	putU32(dinomap, 20, 2)
	putU32(dinomap, 24, 0)
	putU32(dinomap, 28, 0)

	// Allocation group 0: the first inode extent is blocks 24..27.
	iag := data[22*testBlockSize : 23*testBlockSize]
	putU64(iag, 0, 0)
	putU32(iag, 8, 0)
	putU32(iag, 64, 35)
	putU32(iag, 68, 1)
	writePxd(iag, 3072, 4, 24)

	// Dmap page: 256 blocks, five free (100..103 and 200).
	dmap := data[23*testBlockSize : 24*testBlockSize]
	putU32(dmap, 0, testVolumeBlocks)
	putU32(dmap, 4, 5)
	putU64(dmap, 8, 0)
	for mapOffset := WMapOffset; mapOffset <= PMapOffset; mapOffset += PMapOffset - WMapOffset {
		for word := 0; word < testVolumeBlocks/32; word++ {
			putU32(dmap, mapOffset+word*4, 0xFFFF_FFFF)
		}
		for _, block := range []uint32{100, 101, 102, 103, 200} {
			word := block / 32
			bit := uint32(1) << (31 - block%32)
			at := mapOffset + int(word)*4
			putU32(dmap, at, mustU32(dmap, at)&^bit)
		}
	}

	// Root directory inode 2.
	root := inodeBytes(2, 0x41ED, testBlockSize, 2)
	copy(root[0xE0:], dirRoot([]testDirEntry{
		{2, ".", 0},
		{2, "..", 1},
		{3, "file.txt", 2},
		{4, "sub", 3},
		{5, "link", 4},
		{7, "hole.bin", 5},
		{8, "longlink", 6},
		{9, "deep", 7},
	}, true))
	setInode(data, 24, 2, root)

	// Regular file 3: two extents, 5000 bytes.
	file := inodeBytes(3, 0x81A4, 5000, 1)
	copy(file[0xE0:], xtRoot(BT_ROOT|BT_LEAF, [][]byte{
		xadBytes(0, 0, 1, 30),
		xadBytes(0, 1, 1, 31),
	}))
	setInode(data, 24, 3, file)
	fillBlock(data, 30, 'A', "first block\n")
	fillBlock(data, 31, 'B', "second")

	// Subdirectory 4.
	sub := inodeBytes(4, 0x41ED, testBlockSize, 2)
	copy(sub[0xE0:], dirRoot([]testDirEntry{
		{4, ".", 0},
		{2, "..", 1},
		{6, "inner.txt", 2},
		{10, "empty", 3},
	}, true))
	setInode(data, 24, 4, sub)

	// Fast symbolic link 5.
	link := inodeBytes(5, 0xA1FF, 9, 1)
	copy(link[0x100:], "/file.txt")
	setInode(data, 24, 5, link)

	// inner.txt inode 6.
	inner := inodeBytes(6, 0x81A4, 11, 1)
	copy(inner[0xE0:], xtRoot(BT_ROOT|BT_LEAF, [][]byte{xadBytes(0, 0, 1, 32)}))
	setInode(data, 24, 6, inner)
	fillBlock(data, 32, 0, "inner data\n")

	// Sparse file 7: logical blocks 0 and 2.
	hole := inodeBytes(7, 0x81A4, 3*testBlockSize, 1)
	copy(hole[0xE0:], xtRoot(BT_ROOT|BT_LEAF, [][]byte{
		xadBytes(0, 0, 1, 33),
		xadBytes(0, 2, 1, 34),
	}))
	setInode(data, 24, 7, hole)
	fillBlock(data, 33, 0, "hole start")
	fillBlock(data, 34, 0, "hole end")

	// Long symbolic link 8: 300 bytes of target in one block.
	target := strings.Repeat("a/", 150)
	longLink := inodeBytes(8, 0xA1FF, uint64(len(target)), 1)
	copy(longLink[0xE0:], xtRoot(BT_ROOT|BT_LEAF, [][]byte{xadBytes(0, 0, 1, 35)}))
	setInode(data, 25, 0, longLink)
	fillBlock(data, 35, 0, target)

	// Deep file 9: an internal extent-tree root pointing at a leaf page.
	deep := inodeBytes(9, 0x81A4, testBlockSize, 1)
	copy(deep[0xE0:], xtRoot(BT_ROOT|BT_INTERNAL, [][]byte{xadBytes(0, 0, 1, 40)}))
	setInode(data, 25, 1, deep)
	copy(data[40*testBlockSize:], xtPage(BT_LEAF, [][]byte{xadBytes(0, 0, 1, 36)}))
	fillBlock(data, 36, 0, "deep data")

	// Empty directory 10.
	empty := inodeBytes(10, 0x41ED, testBlockSize, 2)
	copy(empty[0xE0:], dirRoot([]testDirEntry{
		{10, ".", 0},
		{2, "..", 1},
	}, true))
	setInode(data, 25, 2, empty)

	return data
}

func mustU32(bytes []byte, at int) uint32 {
	return uint32(bytes[at]) | uint32(bytes[at+1])<<8 | uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
}

func openJFS(t *testing.T, data []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

// ---- detection and geometry ------------------------------------------------

func TestDetect(t *testing.T) {
	if found, err := Detect(source.NewMemorySource(1, make([]byte, SuperblockOffset))); err != nil || found {
		t.Fatalf("short source: found=%v err=%v", found, err)
	}
	zero := make([]byte, SuperblockOffset+0xB8)
	if found, err := Detect(source.NewMemorySource(1, zero)); err != nil || found {
		t.Fatalf("no magic: found=%v err=%v", found, err)
	}
	if found, err := Detect(source.NewMemorySource(1, buildJFSImage(t))); err != nil || !found {
		t.Fatalf("fixture: found=%v err=%v", found, err)
	}

	// The magic is present but the 184-byte structure is not.
	short := make([]byte, SuperblockOffset+4)
	copy(short[SuperblockOffset:], []byte("JFS1"))
	if _, err := Detect(source.NewMemorySource(1, short)); !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("truncated superblock error = %v", err)
	}

	// The magic is present but the geometry is wrong.
	bad := buildJFSImage(t)
	bad[SuperblockOffset+0x10] = 0
	bad[SuperblockOffset+0x11] = 0x04
	if _, err := Detect(source.NewMemorySource(1, bad)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad block size error = %v", err)
	}
}

func TestInfo(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	info := volume.Info()
	if info.Version != 2 || info.BlockSize != testBlockSize {
		t.Fatalf("version/block size = %d/%d", info.Version, info.BlockSize)
	}
	if info.SizeBlocks != testVolumeBlocks || info.VolumeBlocks != testVolumeBlocks {
		t.Fatalf("blocks = %d/%d", info.SizeBlocks, info.VolumeBlocks)
	}
	if info.Label != "jfs fixture" {
		t.Fatalf("label = %q", info.Label)
	}
	if info.UUID != "00010203-0405-0607-0809-0a0b0c0d0e0f" {
		t.Fatalf("uuid = %q", info.UUID)
	}
	if info.Fpack != "jfspack" {
		t.Fatalf("fpack = %q", info.Fpack)
	}
	if !info.Clean || info.StateName != "clean" {
		t.Fatalf("state = %q clean=%v", info.StateName, info.Clean)
	}
	if !info.HasDirectoryIndex || info.IsOS2 {
		t.Fatalf("flags = %+v", info)
	}
	if !strings.Contains(strings.Join(info.FlagNames, ","), "linux") {
		t.Fatalf("flag names = %v", info.FlagNames)
	}
	if info.Truncated {
		t.Fatalf("fixture reported truncated")
	}
	if info.Aim2.Len != 2 || info.Aim2.Address != 21 {
		t.Fatalf("aim2 = %+v", info.Aim2)
	}
}

// ---- directory and metadata ------------------------------------------------

func TestListDirRoot(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	want := []string{"file.txt", "sub", "link", "hole.bin", "longlink", "deep"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v", names)
	}
	for _, entry := range entries {
		switch entry.Name {
		case "file.txt":
			if entry.Inode != 3 || entry.IsDir || !entry.IsFile || entry.IsSymlink {
				t.Fatalf("file entry = %+v", entry)
			}
			if entry.Path != "/file.txt" || entry.Size != 5000 || entry.Mode != 0x81A4 {
				t.Fatalf("file metadata = %+v", entry)
			}
			if entry.UID != 1000 || entry.GID != 1000 || entry.Links != 1 {
				t.Fatalf("file ownership = %+v", entry)
			}
			if !entry.Atime.Equal(time.Unix(1_700_000_000, 1).UTC()) {
				t.Fatalf("atime = %v", entry.Atime)
			}
			if !entry.Mtime.Equal(time.Unix(1_700_000_200, 0).UTC()) {
				t.Fatalf("mtime = %v", entry.Mtime)
			}
			if !entry.Otime.Equal(time.Unix(1_700_000_300, 0).UTC()) {
				t.Fatalf("otime = %v", entry.Otime)
			}
		case "sub":
			if !entry.IsDir || entry.Inode != 4 || entry.Path != "/sub" {
				t.Fatalf("sub = %+v", entry)
			}
		case "link":
			if !entry.IsSymlink || entry.IsFile {
				t.Fatalf("link = %+v", entry)
			}
		case "longlink":
			if !entry.IsSymlink || entry.Size != 300 {
				t.Fatalf("longlink = %+v", entry)
			}
		}
	}
}

func TestStatNested(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	if root.Name != "/" || root.Path != "/" || !root.IsDir || root.Inode != 2 {
		t.Fatalf("root = %+v", root)
	}
	inner, err := volume.Stat("sub/inner.txt")
	if err != nil {
		t.Fatalf("Stat inner: %v", err)
	}
	if inner.Name != "inner.txt" || inner.Path != "/sub/inner.txt" {
		t.Fatalf("inner path = %+v", inner)
	}
	if inner.Inode != 6 || inner.Size != 11 || inner.Mode != 0x81A4 {
		t.Fatalf("inner metadata = %+v", inner)
	}
	link, err := volume.Stat("/link")
	if err != nil {
		t.Fatalf("Stat link: %v", err)
	}
	if link.SymlinkTarget != "/file.txt" {
		t.Fatalf("symlink target in stat = %q", link.SymlinkTarget)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
}

func TestEmptyDir(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	entries, err := volume.ListDir("/sub/empty")
	if err != nil {
		t.Fatalf("ListDir empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty dir has %d entries", len(entries))
	}
}

func TestPathErrors(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	if _, err := volume.ListDir("/file.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir file error = %v", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile dir error = %v", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenFile missing error = %v", err)
	}
	if _, err := volume.SymlinkTarget("/file.txt"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("SymlinkTarget file error = %v", err)
	}
}

// ---- file data -------------------------------------------------------------

func TestReadExtentsAndEOF(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	file, err := volume.OpenFile("/file.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 5000 || file.IsEmpty() {
		t.Fatalf("len = %d", file.Len())
	}
	all := make([]byte, 5000)
	if _, err := file.ReadAt(0, all); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(all[:12]) != "first block\n" {
		t.Fatalf("head = %q", all[:12])
	}
	if string(all[4096:4102]) != "second" {
		t.Fatalf("tail block = %q", all[4096:4102])
	}
	if all[4102] != 'B' {
		t.Fatalf("tail fill = %#x", all[4102])
	}

	part := make([]byte, 6)
	if _, err := file.ReadAt(4096, part); err != nil || string(part) != "second" {
		t.Fatalf("partial = %q err=%v", part, err)
	}
	tail := make([]byte, 32)
	got, err := file.ReadAt(4990, tail)
	if err != nil || got != 10 || string(tail[:10]) != "BBBBBBBBBB" {
		t.Fatalf("tail read = %q (%d) err=%v", tail[:got], got, err)
	}
	if _, err := file.ReadAt(5000, tail); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("EOF error = %v", err)
	}
}

func TestSparseHole(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	file, err := volume.OpenFile("/hole.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 3*testBlockSize {
		t.Fatalf("len = %d", file.Len())
	}
	buf := make([]byte, testBlockSize)
	if _, err := file.ReadAt(testBlockSize, buf); err != nil {
		t.Fatalf("ReadAt hole: %v", err)
	}
	for _, value := range buf {
		if value != 0 {
			t.Fatalf("hole byte = %#x", value)
		}
	}
	if _, err := file.ReadAt(0, buf); err != nil || string(buf[:10]) != "hole start" {
		t.Fatalf("first block = %q err=%v", buf[:10], err)
	}
	ranges, err := file.Extents(0, 3*testBlockSize)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	var kinds []source.RangeKind
	for _, r := range ranges {
		kinds = append(kinds, r.Kind)
	}
	if len(ranges) != 3 || kinds[0] != source.RangeData || kinds[1] != source.RangeHole || kinds[2] != source.RangeData {
		t.Fatalf("ranges = %+v kinds = %v", ranges, kinds)
	}
	if ranges[1].Len != testBlockSize {
		t.Fatalf("hole len = %d", ranges[1].Len)
	}
}

func TestSymlinkTargets(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	fast, err := volume.SymlinkTarget("/link")
	if err != nil || fast != "/file.txt" {
		t.Fatalf("fast target = %q err=%v", fast, err)
	}
	long, err := volume.SymlinkTarget("/longlink")
	if err != nil {
		t.Fatalf("long target: %v", err)
	}
	if long != strings.Repeat("a/", 150) {
		t.Fatalf("long target = %q", long)
	}
	// A symbolic link is also readable as a data source.
	sourceLink, err := volume.OpenFile("/link")
	if err != nil {
		t.Fatalf("OpenFile link: %v", err)
	}
	buf := make([]byte, 9)
	if _, err := sourceLink.ReadAt(0, buf); err != nil || string(buf) != "/file.txt" {
		t.Fatalf("link source = %q err=%v", buf, err)
	}
}

func TestInternalExtentTree(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	file, err := volume.OpenFile("/deep")
	if err != nil {
		t.Fatalf("OpenFile deep: %v", err)
	}
	buf := make([]byte, testBlockSize)
	if _, err := file.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt deep: %v", err)
	}
	if string(buf[:9]) != "deep data" {
		t.Fatalf("deep = %q", buf[:9])
	}
}

func TestStats(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	stats, err := volume.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Directories != 3 || stats.Files != 4 || stats.Symlinks != 2 || stats.Other != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.Entries != stats.Files+stats.Symlinks+stats.Directories-1 {
		t.Fatalf("entries = %d", stats.Entries)
	}
}

// ---- free space ------------------------------------------------------------

func TestFreeSpace(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	free, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if free.Persistent {
		t.Fatalf("clean volume used the persistent map")
	}
	if free.ScannedFree != 5 || free.ControlFree != 5 {
		t.Fatalf("free counts = %d/%d", free.ScannedFree, free.ControlFree)
	}
	space := free.Space
	if space.Basis() != "jfs.dmap.working" {
		t.Fatalf("basis = %q", space.Basis())
	}
	if space.FreeBytes() != 5*testBlockSize {
		t.Fatalf("free bytes = %d", space.FreeBytes())
	}
	runs := space.Runs()
	if len(runs) != 2 {
		t.Fatalf("runs = %+v", runs)
	}
	if runs[0].Offset != 100*testBlockSize || runs[0].Len != 4*testBlockSize {
		t.Fatalf("first run = %+v", runs[0])
	}
	if runs[1].Offset != 200*testBlockSize || runs[1].Len != testBlockSize {
		t.Fatalf("second run = %+v", runs[1])
	}
	if !space.IsFree(101*testBlockSize, testBlockSize) {
		t.Fatalf("block 101 not free")
	}
	if space.IsFree(0, testBlockSize) {
		t.Fatalf("block 0 reported free")
	}
	if space.IsFree(100*testBlockSize, 5*testBlockSize) {
		t.Fatalf("run crossing an allocated block reported free")
	}
}

// ---- directory tree internals ---------------------------------------------

func TestDirectoryLeafChain(t *testing.T) {
	image := make([]byte, 64*testBlockSize)
	copy(image[20*testBlockSize:], dirPage(BT_LEAF, 30, []testDirEntry{
		{2, ".", 0},
		{5, "hello", 1},
	}, true))
	copy(image[30*testBlockSize:], dirPage(BT_LEAF, 0, []testDirEntry{
		{6, "notes", 2},
	}, true))
	root := make([]byte, 288)
	root[16] = BT_ROOT | BT_INTERNAL
	root[17] = 1
	root[24] = 1
	writePxd(root, 32, 1, 20)

	entries, err := readDirectory(source.NewMemorySource(1, image), 64, root, true, 16)
	if err != nil {
		t.Fatalf("readDirectory: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	if strings.Join(names, ",") != ".,hello,notes" {
		t.Fatalf("names = %v", names)
	}
}

func TestDirectoryLeafChainLoop(t *testing.T) {
	image := make([]byte, 64*testBlockSize)
	copy(image[20*testBlockSize:], dirPage(BT_LEAF, 30, []testDirEntry{{5, "a", 0}}, true))
	copy(image[30*testBlockSize:], dirPage(BT_LEAF, 20, []testDirEntry{{6, "b", 0}}, true))
	root := make([]byte, 288)
	root[16] = BT_ROOT | BT_INTERNAL
	root[17] = 1
	root[24] = 1
	writePxd(root, 32, 1, 20)
	if _, err := readDirectory(source.NewMemorySource(1, image), 64, root, true, 16); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("loop error = %v", err)
	}
}

func TestLongDirectoryName(t *testing.T) {
	name := "a-name-longer-than-eleven"
	units := nameUnits(name)
	root := make([]byte, 288)
	root[16] = BT_ROOT | BT_LEAF
	root[17] = 1
	root[24] = 1
	// Slot 1 holds the header and the first eleven units.
	putU32(root, 32, 7)
	root[32+4] = 8 // continuation slot
	root[32+5] = byte(len(units))
	for index := 0; index < 11; index++ {
		putU16(root, 32+6+index*2, units[index])
	}
	// Slot 8 holds the rest and terminates the chain.
	root[8*32] = 0xFF
	for index := 11; index < len(units); index++ {
		putU16(root, 8*32+2+(index-11)*2, units[index])
	}
	entries, err := readDirectory(source.NewMemorySource(1, make([]byte, 64*testBlockSize)), 64, root, true, 16)
	if err != nil {
		t.Fatalf("readDirectory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != name || entries[0].Inode != 7 {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestDirectoryCorruption(t *testing.T) {
	// A sorted-entry-table slot outside the node.
	root := dirRoot([]testDirEntry{{2, ".", 0}}, true)
	root[24] = 0
	if _, err := readDirectory(source.NewMemorySource(1, make([]byte, 64*testBlockSize)), 64, root, true, 16); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("slot error = %v", err)
	}

	// A continuation chain that ends early.
	root = make([]byte, 288)
	root[16] = BT_ROOT | BT_LEAF
	root[17] = 1
	root[24] = 1
	putU32(root, 32, 7)
	root[32+4] = 8
	root[32+5] = 30
	root[8*32] = 0xFF
	if _, err := readDirectory(source.NewMemorySource(1, make([]byte, 64*testBlockSize)), 64, root, true, 16); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("chain error = %v", err)
	}

	// An internal entry whose extent is not one block.
	root = make([]byte, 288)
	root[16] = BT_ROOT | BT_INTERNAL
	root[17] = 1
	root[24] = 1
	writePxd(root, 32, 2, 20)
	if _, err := readDirectory(source.NewMemorySource(1, make([]byte, 64*testBlockSize)), 64, root, true, 16); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("extent length error = %v", err)
	}
}

// ---- extent tree internals -------------------------------------------------

func TestExtentTreeLookup(t *testing.T) {
	leaf := xtRoot(BT_ROOT|BT_LEAF, [][]byte{
		xadBytes(0, 0, 1, 40),
		xadBytes(0, 2, 1, 41),
	})
	src := source.NewMemorySource(1, make([]byte, 64*testBlockSize))
	entry, err := lookupExtent(src, 64, leaf, 0)
	if err != nil || entry == nil || entry.Address != 40 {
		t.Fatalf("lookup 0 = %+v err=%v", entry, err)
	}
	entry, err = lookupExtent(src, 64, leaf, 1)
	if err != nil || entry != nil {
		t.Fatalf("hole lookup = %+v err=%v", entry, err)
	}
	entry, err = lookupExtent(src, 64, leaf, 2)
	if err != nil || entry == nil || entry.Address != 41 {
		t.Fatalf("lookup 2 = %+v err=%v", entry, err)
	}

	// A page reached twice is a loop.
	image := make([]byte, 64*testBlockSize)
	copy(image[20*testBlockSize:], xtPage(BT_INTERNAL, [][]byte{xadBytes(0, 0, 1, 20)}))
	root := xtRoot(BT_ROOT|BT_INTERNAL, [][]byte{xadBytes(0, 0, 1, 20)})
	if _, err := lookupExtent(source.NewMemorySource(1, image), 64, root, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("loop error = %v", err)
	}

	// An entry count larger than a root holds.
	bad := xtRoot(BT_ROOT|BT_LEAF, nil)
	putU16(bad, 18, 19)
	putU16(bad, 20, 19)
	if _, err := lookupExtent(src, 64, bad, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("entry count error = %v", err)
	}
}

// ---- corruption and unported branches --------------------------------------

func TestOpenCorruption(t *testing.T) {
	// Block map size does not match the superblock.
	data := buildJFSImage(t)
	putU64(data[20*testBlockSize:], 0, testVolumeBlocks-1)
	if _, err := Open(source.NewMemorySource(1, data)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mapsize error = %v", err)
	}

	// An inode slot that holds another inode.
	data = buildJFSImage(t)
	putU32(data[24*testBlockSize+2*InodeSize+8:], 0, 99)
	if _, err := Open(source.NewMemorySource(1, data)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("inode number error = %v", err)
	}

	// A freed inode slot.
	data = buildJFSImage(t)
	putU32(data[24*testBlockSize+2*InodeSize+0x28:], 0, 0)
	if _, err := Open(source.NewMemorySource(1, data)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("zero link count error = %v", err)
	}

	// A root directory without ".".
	data = buildJFSImage(t)
	rootEntry := data[24*testBlockSize+2*InodeSize+0xE0:]
	rootEntry[17] = 1
	rootEntry[24] = 2
	if _, err := Open(source.NewMemorySource(1, data)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing dot error = %v", err)
	}
}

func TestFileCorruption(t *testing.T) {
	// A compressed extent is refused by name.
	data := buildJFSImage(t)
	inodeAt := 24*testBlockSize + 3*InodeSize
	data[inodeAt+0xE0+(2*16)] = XadCompressed
	if _, err := openJFS(t, data).OpenFile("/file.txt"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("compressed extent error = %v", err)
	}

	// Block zero is not a valid file extent.
	data = buildJFSImage(t)
	writePxd(data[inodeAt+0xE0+(2*16)+8:], 0, 1, 0)
	if _, err := openJFS(t, data).OpenFile("/file.txt"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("block zero error = %v", err)
	}

	// An extent past the aggregate.
	data = buildJFSImage(t)
	writePxd(data[inodeAt+0xE0+(2*16)+8:], 0, 1, testVolumeBlocks+1)
	if _, err := openJFS(t, data).OpenFile("/file.txt"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("past aggregate error = %v", err)
	}

	// Overlapping extents.
	data = buildJFSImage(t)
	writePxd(data[inodeAt+0xE0+(3*16)+8:], 0, 1, 31)
	putU32(data[inodeAt+0xE0+(3*16)+4:], 0, 0) // second extent starts at logical 0
	if _, err := openJFS(t, data).OpenFile("/file.txt"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("overlap error = %v", err)
	}
}

func TestTruncatedAggregate(t *testing.T) {
	data := buildJFSImage(t)
	short := data[:100*testBlockSize]
	volume, err := Open(source.NewMemorySource(1, short))
	if err != nil {
		t.Fatalf("Open truncated aggregate: %v", err)
	}
	if !volume.Info().Truncated || volume.Info().VolumeBlocks != 100 {
		t.Fatalf("truncation info = %+v", volume.Info())
	}
}

func TestDirectExtentPrimitives(t *testing.T) {
	pxd := Pxd{Len: 0x123456, Address: 0x1_2345_6789}
	raw := make([]byte, 8)
	writePxd(raw, 0, pxd.Len, pxd.Address)
	parsed, err := ParsePxd(raw, 0)
	if err != nil || parsed != pxd {
		t.Fatalf("pxd round trip = %+v err=%v", parsed, err)
	}
	if end, err := parsed.End(); err != nil || end != pxd.Address+uint64(pxd.Len) {
		t.Fatalf("end = %d err=%v", end, err)
	}
	tsRaw := make([]byte, 8)
	putU32(tsRaw, 0, 7)
	putU32(tsRaw, 4, 8)
	ts, err := ParseTimestamp(tsRaw, 0)
	if err != nil || ts.Sec != 7 || ts.Nsec != 8 {
		t.Fatalf("timestamp = %+v err=%v", ts, err)
	}
}

func TestSuperblockValidation(t *testing.T) {
	mutate := func(at int, value byte) []byte {
		data := buildJFSImage(t)
		data[int(SuperblockOffset)+at] = value
		return data
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"version", mutate(0x04, 3)},
		{"state", mutate(0x28, 0x20)},
		{"pad", mutate(0x1E, 1)},
		{"l2bsize", mutate(0x14, 11)},
		{"l2bfactor", mutate(0x16, 17)},
	}
	for _, tc := range cases {
		if _, err := Detect(source.NewMemorySource(1, tc.data)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s error = %v", tc.name, err)
		}
	}
	if _, err := ParseSuperblock(make([]byte, 10), SuperblockOffset); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short parse error = %v", err)
	}
}

func TestUnsupportedSwapFlag(t *testing.T) {
	data := buildJFSImage(t)
	flags := mustU32(data, int(SuperblockOffset+0x24))
	putU32(data, int(SuperblockOffset+0x24), flags|JFSSwapBytes)
	if found, err := Detect(source.NewMemorySource(1, data)); err != nil || !found {
		t.Fatalf("Detect swap: found=%v err=%v", found, err)
	}
	if _, err := Open(source.NewMemorySource(1, data)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("swap flag error = %v", err)
	}
}

func TestCompressedMetadataTree(t *testing.T) {
	data := buildJFSImage(t)
	entry := int(AITableOffset) + 2*InodeSize + 0xE0 + 2*16
	data[entry] = XadCompressed
	if _, err := Open(source.NewMemorySource(1, data)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("compressed metadata error = %v", err)
	}
}

func TestLegacyDirectoryHeader(t *testing.T) {
	name := "abcdefghijklm" // 13 code units, the legacy header width
	root := dirRoot([]testDirEntry{{7, name, 0}}, false)
	entries, err := readDirectory(source.NewMemorySource(1, make([]byte, 64*testBlockSize)), 64, root, false, 16)
	if err != nil {
		t.Fatalf("readDirectory legacy: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != name {
		t.Fatalf("legacy entries = %+v", entries)
	}

	// A fourteenth unit continues through a slot.
	name = "abcdefghijklmn"
	units := nameUnits(name)
	root = make([]byte, 288)
	root[16] = BT_ROOT | BT_LEAF
	root[17] = 1
	root[24] = 1
	putU32(root, 32, 7)
	root[32+4] = 8
	root[32+5] = byte(len(units))
	for index := 0; index < 13; index++ {
		putU16(root, 32+6+index*2, units[index])
	}
	root[8*32] = 0xFF
	putU16(root, 8*32+2, units[13])
	entries, err = readDirectory(source.NewMemorySource(1, make([]byte, 64*testBlockSize)), 64, root, false, 16)
	if err != nil || len(entries) != 1 || entries[0].Name != name {
		t.Fatalf("continued legacy name = %+v err=%v", entries, err)
	}
}

func TestFileSourceLossyAndImageMapping(t *testing.T) {
	volume := openJFS(t, buildJFSImage(t))
	file, err := volume.OpenFile("/file.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	lossy := make([]byte, 8)
	got, err := file.ReadAtLossy(0, lossy)
	if err != nil || got != 8 || string(lossy) != "first bl" {
		t.Fatalf("lossy = %q (%d) err=%v", lossy, got, err)
	}
	if _, err := file.ReadAtLossy(5000, lossy); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy EOF error = %v", err)
	}
	imageRanges, err := file.MapToImage(0, 12)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(imageRanges) != 1 || imageRanges[0].ImageOffset != 30*testBlockSize {
		t.Fatalf("image ranges = %+v", imageRanges)
	}
}

func TestFreeSpaceDirtyVolume(t *testing.T) {
	data := buildJFSImage(t)
	putU32(data, int(SuperblockOffset+0x28), FMDirty)
	volume := openJFS(t, data)
	if volume.Info().Clean {
		t.Fatalf("dirty volume reported clean")
	}
	free, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if !free.Persistent || free.Space.Basis() != "jfs.dmap.persistent" {
		t.Fatalf("dirty free map = persistent %v basis %q", free.Persistent, free.Space.Basis())
	}
	if !strings.Contains(strings.Join(free.Space.Notes(), " "), "persistent") {
		t.Fatalf("notes = %v", free.Space.Notes())
	}
}

func TestExtentPageBudget(t *testing.T) {
	image := make([]byte, 64*testBlockSize)
	copy(image[20*testBlockSize:], xtPage(BT_LEAF, [][]byte{xadBytes(0, 0, 1, 40)}))
	root := xtRoot(BT_ROOT|BT_INTERNAL, [][]byte{xadBytes(0, 0, 1, 20)})
	if _, err := collectExtents(source.NewMemorySource(1, image), 64, root, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("page budget error = %v", err)
	}
}

func TestDirectoryNameSurrogate(t *testing.T) {
	root := make([]byte, 288)
	root[16] = BT_ROOT | BT_LEAF
	root[17] = 1
	root[24] = 1
	putU32(root, 32, 9)
	root[32+4] = 0xFF
	root[32+5] = 2
	putU16(root, 32+6, 'a')
	putU16(root, 32+8, 0xD800) // an unpaired high surrogate
	entries, err := readDirectory(source.NewMemorySource(1, make([]byte, 64*testBlockSize)), 64, root, true, 16)
	if err != nil {
		t.Fatalf("readDirectory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "a�" {
		t.Fatalf("lossy name = %q", entries[0].Name)
	}
}
