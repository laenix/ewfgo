package hpfs

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	fixtureSectors = 64
	fixtureRoot    = 40
	fixtureRootDn  = 18
	fixtureChildDn = 22
	fixtureSubDn   = 26
	fixtureEmptyDn = 36
	fixtureBitmap  = 32
	fixtureBitmapD = 30
)

func fixturePutU16(dst []byte, at int, value uint16) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
}

func fixturePutU32(dst []byte, at int, value uint32) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
	dst[at+2] = byte(value >> 16)
	dst[at+3] = byte(value >> 24)
}

func fixtureSource(data []byte) source.ByteSource {
	return source.NewMemorySource(1, data)
}

type fixtureExtent struct {
	fileSec uint32
	length  uint32
	diskSec uint32
}

type fixtureEntry struct {
	name     []byte
	flags1   uint8
	flags2   uint8
	fnode    uint32
	down     uint32
	hasDown  bool
	size     uint32
	write    uint32
	read     uint32
	creation uint32
	eaSize   uint32
	acls     uint8
	codePage uint8
	length   uint16 // overrides the computed length when non-zero
	noLength bool   // leaves the length field zero
}

func fixtureBootAndSuper(dst []byte) {
	fixturePutU16(dst, 0x1fe, 0xaa55)
	dst[0x26] = 0x28
	fixturePutU16(dst, 0x0b, 512)
	dst[0x0d] = 1
	copy(dst[0x27:0x2b], []byte{0x78, 0x56, 0x34, 0x12})
	copy(dst[0x2b:0x36], []byte("HPFSTEST   "))
	copy(dst[0x36:0x3e], []byte("HPFS    "))

	at := 0x2000
	fixturePutU32(dst, at, mainMagic)
	fixturePutU32(dst, at+4, mainMagic1)
	dst[at+0x08] = 2
	dst[at+0x09] = 2
	fixturePutU32(dst, at+0x0c, fixtureRoot)
	fixturePutU32(dst, at+0x10, fixtureSectors)
	fixturePutU32(dst, at+0x18, fixtureBitmapD)
	fixturePutU32(dst, at+0x28, 0x11111111)
	fixturePutU32(dst, at+0x2c, 0x22222222)
	fixturePutU32(dst, at+0x60, 0x55555555)
	copy(dst[at+0x40:at+0x4c], []byte("hpfs-test!!!"))

	spare := 0x2200
	fixturePutU32(dst, spare, spareMagic)
	fixturePutU32(dst, spare+4, spareMagic1)
}

func fixtureFnode(dst []byte, sector uint32, directory bool, extents []fixtureExtent, size uint32, name string) {
	at := int(sector) * 512
	fixturePutU32(dst, at, fnodeMagic)
	if len(name) > 15 {
		name = name[:15]
	}
	dst[at+0x0c] = byte(len(name))
	copy(dst[at+0x0d:at+0x0d+len(name)], name)
	fixturePutU32(dst, at+0x1c, fixtureRoot)
	if directory {
		fixturePutU16(dst, at+0x36, flagDirectory)
	}
	dst[at+0x38] = 0
	dst[at+0x3d] = byte(len(extents))
	for index, extent := range extents {
		entryAt := at + 0x40 + index*12
		fixturePutU32(dst, entryAt, extent.fileSec)
		fixturePutU32(dst, entryAt+4, extent.length)
		fixturePutU32(dst, entryAt+8, extent.diskSec)
	}
	fixturePutU32(dst, at+0xa0, size)
}

func fixtureEntryBytes(entry fixtureEntry) []byte {
	downBytes := 0
	if entry.hasDown {
		downBytes = 4
	}
	length := int(entry.length)
	if length == 0 {
		length = (0x1f + len(entry.name) + downBytes + 3) &^ 3
	}
	out := make([]byte, length)
	if !entry.noLength {
		fixturePutU16(out, 0, uint16(length))
	}
	out[0x02] = entry.flags1
	out[0x03] = entry.flags2
	fixturePutU32(out, 0x04, entry.fnode)
	fixturePutU32(out, 0x08, entry.write)
	fixturePutU32(out, 0x0c, entry.size)
	fixturePutU32(out, 0x10, entry.read)
	fixturePutU32(out, 0x14, entry.creation)
	fixturePutU32(out, 0x18, entry.eaSize)
	out[0x1c] = entry.acls
	out[0x1d] = entry.codePage
	out[0x1e] = byte(len(entry.name))
	copy(out[0x1f:], entry.name)
	if entry.hasDown {
		fixturePutU32(out, length-4, entry.down)
	}
	return out
}

func fixtureDnode(dst []byte, sector uint32, entries []fixtureEntry) {
	at := int(sector) * 512
	fixturePutU32(dst, at, dnodeMagic)
	fixturePutU32(dst, at+0x08, 1)
	fixturePutU32(dst, at+0x0c, fixtureRoot)
	fixturePutU32(dst, at+0x10, sector)
	cursor := 0x14
	for _, entry := range entries {
		raw := fixtureEntryBytes(entry)
		copy(dst[at+cursor:at+cursor+len(raw)], raw)
		cursor += len(raw)
	}
	fixturePutU32(dst, at+0x04, uint32(cursor))
}

func fixturePhony(name []byte, flags1 uint8, fnode uint32) fixtureEntry {
	return fixtureEntry{name: name, flags1: flags1, fnode: fnode}
}

func fixtureImage() []byte {
	dst := make([]byte, fixtureSectors*512)
	fixtureBootAndSuper(dst)

	fixtureFnode(dst, fixtureRoot, true, []fixtureExtent{{0, 4, fixtureRootDn}}, 0, "")
	fixtureFnode(dst, 41, false, []fixtureExtent{{0, 2, 48}}, 1000, "hello.txt")
	fixtureFnode(dst, 42, true, []fixtureExtent{{0, 4, fixtureSubDn}}, 0, "sub")
	fixtureFnode(dst, 43, false, []fixtureExtent{{0, 1, 50}}, 512, "nested.bin")
	fixtureFnode(dst, 44, false, []fixtureExtent{{0, 1, 51}}, 10, "deep.bin")
	fixtureFnode(dst, 45, false, nil, 0, "empty")
	fixtureFnode(dst, 46, false, []fixtureExtent{{0, 1, 53}}, 1, "bplus")
	fixtureFnode(dst, 47, false, []fixtureExtent{{0, 1, 52}, {2, 1, 54}}, 1536, "hole.bin")
	fixtureFnode(dst, 55, true, []fixtureExtent{{0, 4, fixtureEmptyDn}}, 0, "emptydir")

	fileTimes := func(c fixtureEntry) fixtureEntry {
		c.write = 0x60000000
		c.read = 0x61000000
		c.creation = 0x5f000000
		return c
	}
	fixtureDnode(dst, fixtureRootDn, []fixtureEntry{
		fixturePhony([]byte{0x01, 0x01}, 0x01, fixtureRoot),
		fileTimes(fixtureEntry{name: []byte("hello.txt"), flags2: 0x20, fnode: 41}),
		fileTimes(fixtureEntry{name: []byte("sub"), flags2: 0x10, fnode: 42}),
		fileTimes(fixtureEntry{name: []byte("bplus"), flags1: 0x04, flags2: 0x20, fnode: 46, hasDown: true, down: fixtureChildDn}),
		fileTimes(fixtureEntry{name: []byte("empty"), flags2: 0x20, fnode: 45}),
		fileTimes(fixtureEntry{name: []byte("hole.bin"), flags2: 0x20, fnode: 47}),
		fileTimes(fixtureEntry{name: []byte("emptydir"), flags2: 0x10, fnode: 55}),
		fixturePhony([]byte{0xff}, 0x08, 0),
	})
	fixtureDnode(dst, fixtureChildDn, []fixtureEntry{
		fileTimes(fixtureEntry{name: []byte("deep.bin"), flags2: 0x20, fnode: 44}),
		fixturePhony([]byte{0xff}, 0x08, 0),
	})
	fixtureDnode(dst, fixtureSubDn, []fixtureEntry{
		fileTimes(fixtureEntry{name: []byte("nested.bin"), flags2: 0x20, fnode: 43}),
		fixturePhony([]byte{0xff}, 0x08, 0),
	})
	fixtureDnode(dst, fixtureEmptyDn, []fixtureEntry{
		fixturePhony([]byte{0x01, 0x01}, 0x01, 55),
		fixturePhony([]byte{0xff}, 0x08, 0),
	})

	for at := 48 * 512; at < 50*512; at++ {
		dst[at] = 'H'
	}
	for at := 50 * 512; at < 51*512; at++ {
		dst[at] = 'N'
	}
	for at := 51 * 512; at < 52*512; at++ {
		dst[at] = 'D'
	}
	for at := 52 * 512; at < 53*512; at++ {
		dst[at] = 'X'
	}
	for at := 53 * 512; at < 54*512; at++ {
		dst[at] = 'B'
	}
	for at := 54 * 512; at < 55*512; at++ {
		dst[at] = 'Y'
	}

	fixturePutU32(dst, fixtureBitmapD*512, fixtureBitmap)
	for sector := uint32(56); sector < fixtureSectors; sector++ {
		byteAt := fixtureBitmap*512 + int(sector/8)
		dst[byteAt] |= 1 << (sector % 8)
	}
	return dst
}

func rootEntryOffset(data []byte, index int) int {
	at := fixtureRootDn*512 + 0x14
	for i := 0; i < index; i++ {
		at += int(fixtureU16(data, at))
	}
	return at
}

func fixtureU16(data []byte, at int) uint16 {
	return uint16(data[at]) | uint16(data[at+1])<<8
}

func fixtureU32(data []byte, at int) uint32 {
	return uint32(data[at]) | uint32(data[at+1])<<8 | uint32(data[at+2])<<16 | uint32(data[at+3])<<24
}

func entriesByName(entries []Entry) map[string]Entry {
	out := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		out[entry.Name] = entry
	}
	return out
}

func TestDetect(t *testing.T) {
	ok, err := Detect(fixtureSource(fixtureImage()))
	if err != nil || !ok {
		t.Fatalf("Detect(valid) = %v, %v", ok, err)
	}

	zeros := make([]byte, fixtureSectors*512)
	ok, err = Detect(fixtureSource(zeros))
	if err != nil || ok {
		t.Fatalf("Detect(zeros) = %v, %v", ok, err)
	}

	short := make([]byte, 100)
	ok, err = Detect(fixtureSource(short))
	if err != nil || ok {
		t.Fatalf("Detect(short) = %v, %v", ok, err)
	}
}

func TestDetectClaimedButCorruptSuperblock(t *testing.T) {
	image := fixtureImage()
	// Keep the boot block claiming HPFS and break the main superblock.
	fixturePutU32(image, 0x2000, 0)
	ok, err := Detect(fixtureSource(image))
	if ok {
		t.Fatal("Detect accepted a corrupt claimed image")
	}
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Detect error = %v, want ErrCorrupt", err)
	}
}

func TestDetectMainMagicWithBrokenBoot(t *testing.T) {
	image := fixtureImage()
	image[0x1fe] = 0
	image[0x1ff] = 0
	ok, err := Detect(fixtureSource(image))
	if ok {
		t.Fatal("Detect accepted an image whose boot block failed")
	}
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Detect error = %v, want ErrCorrupt", err)
	}
}

func TestInfo(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	info := volume.Info()
	if info.Version != 2 || info.FuncVersion != 2 {
		t.Fatalf("version = %d/%d", info.Version, info.FuncVersion)
	}
	if info.RootFnode != fixtureRoot || info.NSectors != fixtureSectors {
		t.Fatalf("root/sectors = %d/%d", info.RootFnode, info.NSectors)
	}
	if info.Bitmaps != fixtureBitmapD || info.VolumeSerial != 0x12345678 {
		t.Fatalf("bitmaps/serial = %#x/%#x", info.Bitmaps, info.VolumeSerial)
	}
	if info.VolumeLabel != "HPFSTEST" || info.VolumeName != "hpfs-test!!!" {
		t.Fatalf("labels = %q/%q", info.VolumeLabel, info.VolumeName)
	}
	if info.DeclaredBytes != fixtureSectors*512 || info.VolumeBytes != fixtureSectors*512 || info.Truncated {
		t.Fatalf("sizes = %d/%d truncated=%v", info.DeclaredBytes, info.VolumeBytes, info.Truncated)
	}
	if info.LastChkdskRaw != 0x11111111 || info.LastOptimizeRaw != 0x22222222 {
		t.Fatalf("times = %#x/%#x", info.LastChkdskRaw, info.LastOptimizeRaw)
	}
	if info.UserIDTable != 0x55555555 {
		t.Fatalf("user id table = %#x", info.UserIDTable)
	}
	if len(info.Warnings) != 2 {
		t.Fatalf("warnings = %v", info.Warnings)
	}
}

func TestListDirRoot(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	want := []string{"hello.txt", "sub", "bplus", "empty", "hole.bin", "emptydir", "deep.bin"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v, want %v", names, want)
	}
	byName := entriesByName(entries)
	hello := byName["hello.txt"]
	if hello.IsDir || !hello.IsFile || hello.IsSymlink {
		t.Fatalf("hello kind = %+v", hello)
	}
	if hello.Size != 1000 || hello.Inode != 41 || hello.ParentInode != fixtureRoot {
		t.Fatalf("hello = %+v", hello)
	}
	if !hello.HasAllocated || hello.Allocated != 1024 {
		t.Fatalf("hello allocated = %d/%v", hello.Allocated, hello.HasAllocated)
	}
	if hello.WriteTimeRaw != 0x60000000 || hello.ReadTimeRaw != 0x61000000 || hello.CreationTimeRaw != 0x5f000000 {
		t.Fatalf("hello raw times = %#x/%#x/%#x", hello.WriteTimeRaw, hello.ReadTimeRaw, hello.CreationTimeRaw)
	}
	if hello.Flags2 != 0x20 {
		t.Fatalf("hello flags2 = %#x", hello.Flags2)
	}
	if hello.Path != "/hello.txt" {
		t.Fatalf("hello path = %q", hello.Path)
	}
	sub := byName["sub"]
	if !sub.IsDir || sub.IsFile || sub.Size != 0 {
		t.Fatalf("sub = %+v", sub)
	}
	if byName["deep.bin"].Size != 10 || byName["deep.bin"].Inode != 44 {
		t.Fatalf("deep.bin = %+v", byName["deep.bin"])
	}
}

func TestListDirNested(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := volume.ListDir("/sub")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "nested.bin" {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].ParentInode != 42 || entries[0].Size != 512 {
		t.Fatalf("nested = %+v", entries[0])
	}
}

func TestEmptyDirectory(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := volume.ListDir("/emptydir")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty directory returned %+v", entries)
	}
}

func TestStatNested(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := volume.Stat("/sub/nested.bin")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Name != "nested.bin" || entry.Path != "/sub/nested.bin" {
		t.Fatalf("names = %q/%q", entry.Name, entry.Path)
	}
	if entry.Inode != 43 || entry.ParentInode != 42 || entry.Size != 512 || !entry.IsFile {
		t.Fatalf("entry = %+v", entry)
	}
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatal(err)
	}
	if root.Name != "/" || root.Path != "/" || !root.IsDir || root.Inode != fixtureRoot {
		t.Fatalf("root = %+v", root)
	}
	dotdot, err := volume.Stat("/sub/../hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if dotdot.Inode != 41 {
		t.Fatalf(".. resolution = %+v", dotdot)
	}
}

func TestPathErrors(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat missing = %v", err)
	}
	if _, err := volume.Stat("/hello.txt/child"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("Stat through file = %v", err)
	}
	if _, err := volume.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir file = %v", err)
	}
	if _, err := volume.ListDir("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListDir missing = %v", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile directory = %v", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenFile missing = %v", err)
	}
}

func TestOpenFileReadsAcrossHole(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	file, err := volume.OpenFile("/hole.bin")
	if err != nil {
		t.Fatal(err)
	}
	if file.Len() != 1536 {
		t.Fatalf("len = %d", file.Len())
	}
	buf := make([]byte, 1536)
	n, err := file.ReadAt(0, buf)
	if err != nil || n != 1536 {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if !bytes.Equal(buf[:512], bytes.Repeat([]byte{'X'}, 512)) {
		t.Fatal("first extent bytes are wrong")
	}
	if !bytes.Equal(buf[512:1024], make([]byte, 512)) {
		t.Fatal("the hole did not read as zero")
	}
	if !bytes.Equal(buf[1024:], bytes.Repeat([]byte{'Y'}, 512)) {
		t.Fatal("second extent bytes are wrong")
	}
	if _, err := file.ReadAt(1536, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read at EOF = %v", err)
	}
	if n, err := file.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}

	hello, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	short := make([]byte, 2000)
	n, err = hello.ReadAt(0, short)
	if err != nil || n != 1000 {
		t.Fatalf("hello read = %d, %v", n, err)
	}
	if !bytes.Equal(short[:1000], bytes.Repeat([]byte{'H'}, 1000)) {
		t.Fatal("hello bytes are wrong")
	}
	empty, err := volume.OpenFile("/empty")
	if err != nil {
		t.Fatal(err)
	}
	if empty.Len() != 0 || !empty.IsEmpty() {
		t.Fatalf("empty = %d/%v", empty.Len(), empty.IsEmpty())
	}
	if _, err := empty.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("empty read = %v", err)
	}
}

func TestFileExtentsAndImageMapping(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	file, err := volume.OpenFile("/hole.bin")
	if err != nil {
		t.Fatal(err)
	}
	runs := file.(*HpfsFileSource).Runs()
	if len(runs) != 2 || runs[0].Physical != 52*512 || runs[1].Physical != 54*512 {
		t.Fatalf("runs = %+v", runs)
	}
	if file.(*HpfsFileSource).AllocatedBytes() != 1024 {
		t.Fatalf("allocated = %d", file.(*HpfsFileSource).AllocatedBytes())
	}
	ranges, err := file.Extents(0, 1536)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 3 {
		t.Fatalf("ranges = %+v", ranges)
	}
	if ranges[0].Kind != source.RangeData || ranges[0].ParentOffset != 52*512 ||
		ranges[1].Kind != source.RangeHole || ranges[1].Len != 512 ||
		ranges[2].Kind != source.RangeData || ranges[2].ParentOffset != 54*512 {
		t.Fatalf("ranges = %+v", ranges)
	}
	imageRanges, err := file.MapToImage(0, 1536)
	if err != nil {
		t.Fatal(err)
	}
	if len(imageRanges) != 3 ||
		imageRanges[0].Kind != source.RangeData || imageRanges[0].ImageOffset != 52*512 ||
		imageRanges[1].Kind != source.RangeHole || imageRanges[1].ImageOffset != 0 ||
		imageRanges[2].Kind != source.RangeData || imageRanges[2].ImageOffset != 54*512 {
		t.Fatalf("image ranges = %+v", imageRanges)
	}
	if _, err := file.Extents(1536, 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extents past EOF = %v", err)
	}
	if _, err := file.MapToImage(1536, 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("map past EOF = %v", err)
	}
}

func TestFileSourceStatsAndLossy(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := file.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if file.Stats().Reads == 0 || file.Stats().BytesRead != 16 {
		t.Fatalf("stats = %+v", file.Stats())
	}
	lossy := make([]byte, 2000)
	n, err := file.ReadAtLossy(0, lossy)
	if err != nil || n != 1000 {
		t.Fatalf("lossy = %d, %v", n, err)
	}
	if _, err := file.ReadAtLossy(1000, make([]byte, 8)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy past EOF = %v", err)
	}
}

func TestDirectoryLoop(t *testing.T) {
	image := fixtureImage()
	// The "bplus" entry is the fourth entry in the root dnode.
	at := rootEntryOffset(image, 3)
	fixturePutU32(image, at+int(fixtureU16(image, at))-4, fixtureRootDn)
	volume, err := Open(fixtureSource(image))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := volume.ListDir("/"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("loop error = %v", err)
	}
}

func TestDirectoryCorruption(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{"bad magic", func(data []byte) { fixturePutU32(data, fixtureRootDn*512, 0) }},
		{"first free too low", func(data []byte) { fixturePutU32(data, fixtureRootDn*512+4, 0x10) }},
		{"first free too high", func(data []byte) { fixturePutU32(data, fixtureRootDn*512+4, 3000) }},
		{"self sector mismatch", func(data []byte) { fixturePutU32(data, fixtureRootDn*512+0x10, 19) }},
		{"misaligned entry", func(data []byte) {
			at := rootEntryOffset(data, 1)
			fixturePutU16(data, at, 41)
		}},
		{"short entry", func(data []byte) {
			at := rootEntryOffset(data, 1)
			fixturePutU16(data, at, 31)
		}},
		{"entry crosses used region", func(data []byte) {
			at := rootEntryOffset(data, 1)
			fixturePutU32(data, fixtureRootDn*512+4, uint32(at+2))
		}},
		{"name length mismatch", func(data []byte) {
			at := rootEntryOffset(data, 1)
			data[at+0x1e] = 4
		}},
		{"down pointer too low", func(data []byte) {
			at := rootEntryOffset(data, 3)
			fixturePutU32(data, at+int(fixtureU16(data, at))-4, 1)
		}},
		{"down pointer past volume", func(data []byte) {
			at := rootEntryOffset(data, 3)
			fixturePutU32(data, at+int(fixtureU16(data, at))-4, 63)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := fixtureImage()
			test.mutate(image)
			volume, err := Open(fixtureSource(image))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := volume.ListDir("/"); !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("ListDir error = %v", err)
			}
		})
	}
}

func TestFnodeCorruption(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func([]byte)
		wantErr error
	}{
		{"bad magic", func(data []byte) { fixturePutU32(data, 41*512, 0) }, source.ErrCorrupt},
		{"internal btree", func(data []byte) { data[41*512+0x38] = btreeInternal }, source.ErrUnsupported},
		{"too many extents", func(data []byte) { data[41*512+0x3d] = 9 }, source.ErrCorrupt},
		{"zero length extent", func(data []byte) { fixturePutU32(data, 41*512+0x44, 0) }, source.ErrCorrupt},
		{"extent at sector zero", func(data []byte) { fixturePutU32(data, 41*512+0x48, 0) }, source.ErrCorrupt},
		{"overlapping extents", func(data []byte) {
			fixturePutU32(data, 41*512+0x4c, 1)
			fixturePutU32(data, 41*512+0x50, 1)
			fixturePutU32(data, 41*512+0x54, 53)
			data[41*512+0x3d] = 2
		}, source.ErrCorrupt},
		{"extent past volume", func(data []byte) { fixturePutU32(data, 41*512+0x48, 63) }, source.ErrCorrupt},
		{"directory without dnode", func(data []byte) { data[42*512+0x3d] = 0 }, source.ErrCorrupt},
		{"entry names fnode zero", func(data []byte) {
			at := rootEntryOffset(data, 1)
			fixturePutU32(data, at+0x04, 0)
		}, source.ErrCorrupt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := fixtureImage()
			test.mutate(image)
			volume, err := Open(fixtureSource(image))
			if err != nil {
				t.Fatal(err)
			}
			path := "/hello.txt"
			if test.name == "directory without dnode" {
				path = "/sub"
			}
			if _, err := volume.Stat(path); !errors.Is(err, test.wantErr) {
				t.Fatalf("Stat error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUndecodableNames(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte, int)
		raw    []byte
	}{
		{"non ASCII", func(data []byte, at int) { data[at+0x1f+3] = 0xe9 }, []byte("hel\xe9o.txt")},
		{"non zero code page", func(data []byte, at int) { data[at+0x1d] = 1 }, []byte("hello.txt")},
		{"slash", func(data []byte, at int) { data[at+0x1f+3] = '/' }, []byte("hel/o.txt")},
		{"backslash", func(data []byte, at int) { data[at+0x1f+3] = '\\' }, []byte("hel\\o.txt")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := fixtureImage()
			at := rootEntryOffset(image, 1)
			test.mutate(image, at)
			volume, err := Open(fixtureSource(image))
			if err != nil {
				t.Fatal(err)
			}
			entries, err := volume.ListDir("/")
			if err != nil {
				t.Fatal(err)
			}
			var found *Entry
			for index := range entries {
				if entries[index].Undecodable && bytes.Equal(entries[index].RawName, test.raw) {
					found = &entries[index]
				}
			}
			if found == nil {
				t.Fatalf("undecodable entry not listed: %+v", entries)
			}
			if found.Name != "" {
				t.Fatalf("undecodable name = %q", found.Name)
			}
			if _, err := volume.Stat("/hello.txt"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Stat undecodable = %v", err)
			}
		})
	}
}

func TestEntryExtendedAttributesAndFlags(t *testing.T) {
	image := fixtureImage()
	at := rootEntryOffset(image, 1)
	image[at+0x02] |= 0x10 // DE_HAS_EA
	image[at+0x1c] = 0xaa  // the low three bits are the ACL count
	fixturePutU32(image, 41*512+0x2c, 100)
	fixturePutU16(image, 41*512+0x34, 20)
	volume, err := Open(fixtureSource(image))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := volume.Stat("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if entry.EASize != 100 || entry.ACLCount != 2 {
		t.Fatalf("ea/acl = %d/%d", entry.EASize, entry.ACLCount)
	}
	if entry.Flags1&0x10 == 0 {
		t.Fatalf("flags1 = %#x", entry.Flags1)
	}
}

func TestLongDirectoryName(t *testing.T) {
	image := fixtureImage()
	longName := bytes.Repeat([]byte{'n'}, 255)
	volume, err := Open(fixtureSource(image))
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the root dnode with an extra maximal-length name.
	dnode := make([]byte, 2048)
	copy(dnode, image[fixtureRootDn*512:fixtureRootDn*512+0x14])
	cursor := 0x14
	entries := []fixtureEntry{
		fixturePhony([]byte{0x01, 0x01}, 0x01, fixtureRoot),
		{name: longName, flags2: 0x20, fnode: 41},
		fixturePhony([]byte{0xff}, 0x08, 0),
	}
	for _, entry := range entries {
		raw := fixtureEntryBytes(entry)
		copy(dnode[cursor:], raw)
		cursor += len(raw)
	}
	fixturePutU32(dnode, 0x04, uint32(cursor))
	copy(image[fixtureRootDn*512:], dnode)
	// The volume was opened before the image was mutated, so open it again.
	volume, err = Open(fixtureSource(image))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Name != string(longName) {
		t.Fatalf("long name entry = %+v", listed)
	}
}

func TestSuperblockValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func([]byte)
		wantErr error
	}{
		{"boot magic", func(data []byte) { fixturePutU16(data, 0x1fe, 0) }, source.ErrCorrupt},
		{"boot signature", func(data []byte) { data[0x26] = 0 }, source.ErrCorrupt},
		{"filesystem name", func(data []byte) { copy(data[0x36:], []byte("XXXX    ")) }, source.ErrCorrupt},
		{"sector size", func(data []byte) { fixturePutU16(data, 0x0b, 1024) }, source.ErrUnsupported},
		{"main magic", func(data []byte) { fixturePutU32(data, 0x2000, 0) }, source.ErrCorrupt},
		{"main magic1", func(data []byte) { fixturePutU32(data, 0x2004, 0) }, source.ErrCorrupt},
		{"version", func(data []byte) { data[0x2008] = 9 }, source.ErrUnsupported},
		{"functional version", func(data []byte) { data[0x2009] = 9 }, source.ErrUnsupported},
		{"zero sectors", func(data []byte) { fixturePutU32(data, 0x2010, 0) }, source.ErrCorrupt},
		{"zero root", func(data []byte) { fixturePutU32(data, 0x200c, 0) }, source.ErrCorrupt},
		{"root outside volume", func(data []byte) { fixturePutU32(data, 0x200c, 64) }, source.ErrCorrupt},
		{"bad blocks without list", func(data []byte) {
			fixturePutU32(data, 0x2014, 3)
			fixturePutU32(data, 0x2020, 0)
		}, source.ErrCorrupt},
		{"spare magic", func(data []byte) { fixturePutU32(data, 0x2200, 0) }, source.ErrCorrupt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := fixtureImage()
			test.mutate(image)
			_, err := Open(fixtureSource(image))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Open error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestOpenRootNotDirectory(t *testing.T) {
	image := fixtureImage()
	fixturePutU16(image, fixtureRoot*512+0x36, 0)
	if _, err := Open(fixtureSource(image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v", err)
	}
}

func TestTruncatedAggregate(t *testing.T) {
	image := fixtureImage()
	truncated := image[:60*512]
	volume, err := Open(fixtureSource(truncated))
	if err != nil {
		t.Fatal(err)
	}
	info := volume.Info()
	if !info.Truncated || info.VolumeBytes != 60*512 || info.DeclaredBytes != fixtureSectors*512 {
		t.Fatalf("info = %+v", info)
	}

	image = fixtureImage()
	fixturePutU32(image, 41*512+0x48, 60)
	volume, err = Open(fixtureSource(image[:60*512]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := volume.Stat("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Stat fnode past truncated source = %v", err)
	}
}

func TestFreeSpace(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	space, err := volume.FreeSpace()
	if err != nil {
		t.Fatal(err)
	}
	if space.FreeBytes() != 8*512 {
		t.Fatalf("free bytes = %d", space.FreeBytes())
	}
	runs := space.Runs()
	if len(runs) != 1 || runs[0].Offset != 56*512 || runs[0].Len != 8*512 {
		t.Fatalf("runs = %+v", runs)
	}
	if !space.IsFree(56*512, 8*512) || space.IsFree(55*512, 512) {
		t.Fatal("IsFree polarity is wrong")
	}
	if space.Covered() != fixtureSectors*512 || space.Basis() == "" {
		t.Fatalf("covered/basis = %d/%q", space.Covered(), space.Basis())
	}
}

func TestFreeSpaceRefusals(t *testing.T) {
	image := fixtureImage()
	volume, err := Open(fixtureSource(image))
	if err != nil {
		t.Fatal(err)
	}
	volume.superblocks.Main.Bitmaps = 0
	if _, err := volume.FreeSpace(); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("no bitmap sector = %v", err)
	}

	image = fixtureImage()
	fixturePutU32(image, fixtureBitmapD*512, 0)
	volume, err = Open(fixtureSource(image))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := volume.FreeSpace(); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("zero bitmap entry = %v", err)
	}

	image = fixtureImage()
	fixturePutU32(image, fixtureBitmapD*512, 62)
	volume, err = Open(fixtureSource(image))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := volume.FreeSpace(); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bitmap past volume = %v", err)
	}
}

func TestStats(t *testing.T) {
	volume, err := Open(fixtureSource(fixtureImage()))
	if err != nil {
		t.Fatal(err)
	}
	stats, err := volume.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Directories != 3 {
		t.Fatalf("directories = %d", stats.Directories)
	}
	if stats.Files != 6 {
		t.Fatalf("files = %d", stats.Files)
	}
	if stats.Entries < 7 {
		t.Fatalf("entries = %d", stats.Entries)
	}
}
