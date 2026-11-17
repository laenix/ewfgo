package gfs2

import (
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- fixture helpers -------------------------------------------------------

const (
	testBlockSize = 4096
	testBlocks    = 64
)

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

func putBE64(dst []byte, at int, value uint64) {
	putBE32(dst, at, uint32(value>>32))
	putBE32(dst, at+4, uint32(value))
}

// newImage allocates a whole number of blocks, long enough to hold the
// superblock at its fixed 64 KiB offset.
func newImage(blockSize uint32, blocks uint64) []byte {
	if minimum := SuperBlockOffset/uint64(blockSize) + 8; blocks < minimum {
		blocks = minimum
	}
	return make([]byte, blocks*uint64(blockSize))
}

func writeSuperblock(img []byte, blockSize uint32, root, master uint64) {
	at := int(SuperBlockOffset)
	putBE32(img, at+0x00, Magic)
	putBE32(img, at+0x04, MetaSB)
	putBE32(img, at+0x10, FormatSB)
	putBE32(img, at+0x18, FSFormatGFS2)
	putBE32(img, at+0x1c, MultihostFormatGFS2)
	putBE32(img, at+0x24, blockSize)
	putBE32(img, at+0x28, testLog2(blockSize))
	putBE64(img, at+0x30, master+1000)
	putBE64(img, at+0x38, master)
	putBE64(img, at+0x50, root+1000)
	putBE64(img, at+0x58, root)
	copy(img[at+0x60:at+0x6c], "lock_nolock")
	copy(img[at+0xa0:at+0xa8], "gfs2fs0")
	copy(img[at+0x100:at+0x110], []byte("gfs2testuuid0001"))
}

func testLog2(value uint32) uint32 {
	var shift uint32
	for shift < 32 && value&(1<<shift) == 0 {
		shift++
	}
	return shift
}

func metaHeaderAt(img []byte, blockSize uint32, block uint64, metaType, format uint32) {
	at := int(block * uint64(blockSize))
	putBE32(img, at+0x00, Magic)
	putBE32(img, at+0x04, metaType)
	putBE32(img, at+0x10, format)
}

func metaHeader(img []byte, block uint64, metaType, format uint32) {
	metaHeaderAt(img, testBlockSize, block, metaType, format)
}

func writeDinodeAt(img []byte, blockSize uint32, block uint64, mode uint32, size uint64, height uint16, flags uint32) int {
	metaHeaderAt(img, blockSize, block, MetaDI, FormatDI)
	at := int(block * uint64(blockSize))
	putBE64(img, at+0x18, block+1000)
	putBE64(img, at+0x20, block)
	putBE32(img, at+0x28, mode)
	putBE32(img, at+0x2c, 1000)
	putBE32(img, at+0x30, 100)
	putBE32(img, at+0x34, 1)
	putBE64(img, at+0x38, size)
	putBE32(img, at+0x80, flags)
	putBE16(img, at+0x8a, height)
	putBE16(img, at+0x92, 0)
	return at
}

func writeDinode(img []byte, block uint64, mode uint32, size uint64, height uint16, flags uint32) int {
	return writeDinodeAt(img, testBlockSize, block, mode, size, height, flags)
}

func writeStuffedInodeAt(img []byte, blockSize uint32, block uint64, mode uint32, data []byte) int {
	at := writeDinodeAt(img, blockSize, block, mode, uint64(len(data)), 0, 0)
	copy(img[at+DinodeSize:at+DinodeSize+len(data)], data)
	return at
}

func writeStuffedInode(img []byte, block uint64, mode uint32, data []byte) int {
	return writeStuffedInodeAt(img, testBlockSize, block, mode, data)
}

func writeFileInode(img []byte, block uint64, size uint64, pointers []uint64) int {
	at := writeDinode(img, block, modeFile|0o644, size, 1, 0)
	for index, pointer := range pointers {
		putBE64(img, at+DinodeSize+index*8, pointer)
	}
	return at
}

type direntSpec struct {
	formal   uint64
	inode    uint64
	name     string
	fileType uint16
	free     bool
	recLen   int
}

func direntBytes(spec direntSpec) []byte {
	length := spec.recLen
	if length == 0 {
		length = (DirentFixed + len(spec.name) + 7) &^ 7
	}
	if length < DirentFixed+len(spec.name) {
		length = DirentFixed + len(spec.name)
	}
	out := make([]byte, length)
	putBE16(out, 0x14, uint16(length))
	if spec.free {
		return out
	}
	putBE64(out, 0x00, spec.formal)
	putBE64(out, 0x08, spec.inode)
	putBE16(out, 0x14, uint16(length))
	putBE16(out, 0x16, uint16(len(spec.name)))
	putBE16(out, 0x18, spec.fileType)
	copy(out[DirentFixed:], spec.name)
	return out
}

func join(parts ...[]byte) []byte {
	var total int
	for _, part := range parts {
		total += len(part)
	}
	out := make([]byte, 0, total)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func dotEntries(self, parent uint64) (direntSpec, direntSpec) {
	return direntSpec{formal: self + 1000, inode: self, name: ".", fileType: 2},
		direntSpec{formal: parent + 1000, inode: parent, name: "..", fileType: 2}
}

func writeDirInodeAt(img []byte, blockSize uint32, block uint64, records []byte) int {
	return writeStuffedInodeAt(img, blockSize, block, modeDirectory|0o755, records)
}

func writeDirInode(img []byte, block uint64, records []byte) int {
	return writeDirInodeAt(img, testBlockSize, block, records)
}

func threeDigits(value int) string {
	return string([]byte{
		byte('0' + (value/100)%10),
		byte('0' + (value/10)%10),
		byte('0' + value%10),
	})
}

func testVolume(t *testing.T, img []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

// baseImage builds a valid image whose root and master are directories.
func baseImage() []byte {
	img := newImage(testBlockSize, testBlocks)
	writeSuperblock(img, testBlockSize, 20, 21)
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(direntBytes(dot), direntBytes(dotdot)))
	dot, dotdot = dotEntries(21, 21)
	writeDirInode(img, 21, join(direntBytes(dot), direntBytes(dotdot)))
	return img
}

func entryByName(t *testing.T, entries []Entry, name string) Entry {
	t.Helper()
	for _, entry := range entries {
		if entry.Name == name {
			return entry
		}
	}
	t.Fatalf("entry %q not in %v", name, entryNames(entries))
	return Entry{}
}

func entryNames(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Name)
	}
	return out
}

// ---- detection and superblock ---------------------------------------------

func TestDetect(t *testing.T) {
	t.Run("no magic", func(t *testing.T) {
		detected, err := Detect(source.NewMemorySource(1, make([]byte, 1<<17)))
		if err != nil || detected {
			t.Fatalf("Detect = %v, %v; want false, nil", detected, err)
		}
	})
	t.Run("short source", func(t *testing.T) {
		detected, err := Detect(source.NewMemorySource(1, make([]byte, 16)))
		if err != nil || detected {
			t.Fatalf("Detect = %v, %v; want false, nil", detected, err)
		}
	})
	t.Run("valid", func(t *testing.T) {
		detected, err := Detect(source.NewMemorySource(1, baseImage()))
		if err != nil || !detected {
			t.Fatalf("Detect = %v, %v; want true, nil", detected, err)
		}
	})
	t.Run("byte swapped", func(t *testing.T) {
		img := baseImage()
		putBE32(img, int(SuperBlockOffset), SwappedMagic)
		_, err := Detect(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "byte-swapped") {
			t.Fatalf("Detect error = %v, want unsupported byte-swapped", err)
		}
	})
	t.Run("gfs1", func(t *testing.T) {
		img := baseImage()
		putBE32(img, int(SuperBlockOffset)+0x18, FSFormatGFS1)
		_, err := Detect(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "GFS1") {
			t.Fatalf("Detect error = %v, want unsupported GFS1", err)
		}
	})
	t.Run("truncated superblock", func(t *testing.T) {
		img := baseImage()[:int(SuperBlockOffset)+0x40]
		_, err := Detect(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrUnexpectedEOF) {
			t.Fatalf("Detect error = %v, want unexpected EOF", err)
		}
	})
}

func TestSuperblockBlockSizes(t *testing.T) {
	for _, blockSize := range []uint32{512, 1024, 2048, 4096} {
		img := newImage(blockSize, 0)
		sbBlock := uint64(SuperBlockOffset / uint64(blockSize))
		root := sbBlock + 1
		master := sbBlock + 2
		writeSuperblock(img, blockSize, root, master)
		dot, dotdot := dotEntries(root, root)
		writeDirInodeAt(img, blockSize, root, join(direntBytes(dot), direntBytes(dotdot)))
		dot, dotdot = dotEntries(master, master)
		writeDirInodeAt(img, blockSize, master, join(direntBytes(dot), direntBytes(dotdot)))
		volume := testVolume(t, img)
		info := volume.Info()
		if info.BlockSize != blockSize || info.BlockShift != testLog2(blockSize) {
			t.Errorf("block size %d: info = %d/%d", blockSize, info.BlockSize, info.BlockShift)
		}
		if info.Blocks != uint64(len(img))/uint64(blockSize) {
			t.Errorf("block size %d: blocks = %d", blockSize, info.Blocks)
		}
		if info.RootBlock != root || info.MasterBlock != master {
			t.Errorf("block size %d: root/master = %d/%d", blockSize, info.RootBlock, info.MasterBlock)
		}
	}
}

func TestSuperblockRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func([]byte)
		wantErr error
		text    string
	}{
		{"block size", func(img []byte) { putBE32(img, int(SuperBlockOffset)+0x24, 1000) }, source.ErrUnsupported, "block size"},
		{"non power of two", func(img []byte) { putBE32(img, int(SuperBlockOffset)+0x24, 3000) }, source.ErrUnsupported, "block size"},
		{"block shift", func(img []byte) { putBE32(img, int(SuperBlockOffset)+0x28, 11) }, source.ErrCorrupt, "shift"},
		{"root out of range", func(img []byte) { putBE64(img, int(SuperBlockOffset)+0x58, 9999) }, source.ErrCorrupt, "out of range"},
		{"root equals master", func(img []byte) { putBE64(img, int(SuperBlockOffset)+0x58, 21) }, source.ErrCorrupt, "share"},
		{"root is superblock", func(img []byte) { putBE64(img, int(SuperBlockOffset)+0x58, 16) }, source.ErrCorrupt, "own block"},
		{"no lock protocol", func(img []byte) { clear(img[int(SuperBlockOffset)+0x60 : int(SuperBlockOffset)+0xa0]) }, source.ErrCorrupt, "lock protocol"},
		{"gfs1 multihost", func(img []byte) { putBE32(img, int(SuperBlockOffset)+0x1c, MultihostFormatGFS1) }, source.ErrUnsupported, "GFS1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			img := baseImage()
			testCase.mutate(img)
			_, err := Open(source.NewMemorySource(1, img))
			if !errors.Is(err, testCase.wantErr) || !strings.Contains(err.Error(), testCase.text) {
				t.Fatalf("Open error = %v, want %v containing %q", err, testCase.wantErr, testCase.text)
			}
		})
	}
}

func TestOpenRootAndMasterMustBeDirectories(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		img := baseImage()
		writeStuffedInode(img, 20, modeFile|0o644, []byte("x"))
		_, err := Open(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("Open error = %v", err)
		}
	})
	t.Run("master", func(t *testing.T) {
		img := baseImage()
		writeStuffedInode(img, 21, modeFile|0o644, []byte("x"))
		_, err := Open(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "master") {
			t.Fatalf("Open error = %v", err)
		}
	})
}

// ---- tree walking ----------------------------------------------------------

// treeImage lays out:
//
//	/hello.txt (stuffed file)
//	/sub (stuffed dir) -> /sub/inner (stuffed file)
//	/empty (stuffed dir with only dot entries)
//	/link (stuffed symlink -> hello.txt)
//	/fifo (fifo)
func treeImage() []byte {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(
		direntBytes(dot),
		direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1022, inode: 22, name: "hello.txt", fileType: 1}),
		direntBytes(direntSpec{formal: 1023, inode: 23, name: "sub", fileType: 2}),
		direntBytes(direntSpec{formal: 1026, inode: 26, name: "empty", fileType: 2}),
		direntBytes(direntSpec{formal: 1025, inode: 25, name: "link", fileType: 7}),
		direntBytes(direntSpec{formal: 1027, inode: 27, name: "fifo", fileType: 5}),
	))
	writeStuffedInode(img, 22, modeFile|0o644, []byte("hello"))
	dot, dotdot = dotEntries(23, 20)
	writeDirInode(img, 23, join(
		direntBytes(dot),
		direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1024, inode: 24, name: "inner", fileType: 1}),
	))
	writeStuffedInode(img, 24, modeFile|0o600, []byte("inside"))
	dot, dotdot = dotEntries(26, 20)
	writeDirInode(img, 26, join(direntBytes(dot), direntBytes(dotdot)))
	writeStuffedInode(img, 25, modeSymlink|0o777, []byte("hello.txt"))
	writeStuffedInode(img, 27, modeFifo|0o600, nil)
	return img
}

func TestWalkStuffedTree(t *testing.T) {
	volume := testVolume(t, treeImage())

	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat /: %v", err)
	}
	if !root.IsDir || root.Name != "/" || root.Path != "/" {
		t.Fatalf("root = %+v", root)
	}

	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir /: %v", err)
	}
	got := entryNames(entries)
	want := []string{"hello.txt", "sub", "empty", "link", "fifo"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("root entries = %v, want %v", got, want)
	}
	if _, err := volume.ListDir(""); err != nil {
		t.Fatalf("ListDir empty path: %v", err)
	}

	file := entryByName(t, entries, "hello.txt")
	if !file.IsFile || file.IsDir || file.IsSymlink {
		t.Errorf("hello.txt flags = %+v", file)
	}
	if file.Size != 5 || file.Mode != modeFile|0o644 || file.UID != 1000 || file.GID != 100 {
		t.Errorf("hello.txt metadata = %+v", file)
	}
	if file.Inode != 22 || file.Path != "/hello.txt" {
		t.Errorf("hello.txt identity = %+v", file)
	}

	sub := entryByName(t, entries, "sub")
	if !sub.IsDir {
		t.Errorf("sub is not a directory: %+v", sub)
	}
	inner, err := volume.Stat("/sub/inner")
	if err != nil {
		t.Fatalf("Stat /sub/inner: %v", err)
	}
	if inner.Name != "inner" || inner.Path != "/sub/inner" || inner.Size != 6 {
		t.Errorf("inner = %+v", inner)
	}
	if _, err := volume.Stat("sub/../hello.txt"); err != nil {
		t.Fatalf("dotdot path: %v", err)
	}

	empty, err := volume.ListDir("/empty")
	if err != nil {
		t.Fatalf("ListDir /empty: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("empty dir entries = %v", entryNames(empty))
	}

	link := entryByName(t, entries, "link")
	if !link.IsSymlink || link.SymlinkTarget != "hello.txt" {
		t.Errorf("link = %+v", link)
	}

	fifo := entryByName(t, entries, "fifo")
	if fifo.IsDir || fifo.IsFile || fifo.IsSymlink || fifo.FileType != "fifo" {
		t.Errorf("fifo = %+v", fifo)
	}

	if volume.DirectoryLoops() != 0 {
		t.Errorf("directory loops = %d", volume.DirectoryLoops())
	}
	stats := volume.Stats()
	if stats.NodesRead < 8 {
		t.Errorf("nodes read = %d", stats.NodesRead)
	}
	if stats.Lookups == 0 {
		t.Errorf("lookups = 0")
	}
}

func TestOpenFileStuffed(t *testing.T) {
	volume := testVolume(t, treeImage())
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 5 {
		t.Fatalf("Len = %d", file.Len())
	}
	buffer := make([]byte, 5)
	if _, err := file.ReadAt(0, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buffer) != "hello" {
		t.Fatalf("bytes = %q", buffer)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Errorf("OpenFile dir error = %v", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("OpenFile missing error = %v", err)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Stat missing error = %v", err)
	}
	if _, err := volume.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Errorf("ListDir file error = %v", err)
	}
}

func TestTimesAndSizes(t *testing.T) {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(
		direntBytes(dot), direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1022, inode: 22, name: "stamped", fileType: 1}),
	))
	at := writeStuffedInode(img, 22, modeFile|0o644, []byte("abcdef"))
	putBE64(img, at+0x48, 1_700_000_001) // atime
	putBE64(img, at+0x50, 1_700_000_002) // mtime
	putBE64(img, at+0x58, 1_700_000_003) // ctime
	putBE64(img, at+0x40, 7)             // di_blocks

	volume := testVolume(t, img)
	entry, err := volume.Stat("/stamped")
	if err != nil {
		t.Fatal(err)
	}
	if entry.AccessTime == nil || *entry.AccessTime != 1_700_000_001 {
		t.Errorf("atime = %v", entry.AccessTime)
	}
	if entry.ModifyTime == nil || *entry.ModifyTime != 1_700_000_002 {
		t.Errorf("mtime = %v", entry.ModifyTime)
	}
	if entry.ChangeTime == nil || *entry.ChangeTime != 1_700_000_003 {
		t.Errorf("ctime = %v", entry.ChangeTime)
	}
	if entry.Size != 6 || entry.Allocated == nil || *entry.Allocated != 0 {
		t.Errorf("size/allocated = %d/%v", entry.Size, entry.Allocated)
	}
}

func TestZeroTimePairIsUnset(t *testing.T) {
	volume := testVolume(t, treeImage())
	entry, err := volume.Stat("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if entry.AccessTime != nil || entry.ModifyTime != nil || entry.ChangeTime != nil {
		t.Errorf("zero timestamps reported: %+v", entry)
	}
}

// ---- block-mapped files ----------------------------------------------------

func fillBlock(img []byte, block uint64, value byte) {
	start := int(block * testBlockSize)
	for index := start; index < start+testBlockSize; index++ {
		img[index] = value
	}
}

func TestBlockMappedFileContiguous(t *testing.T) {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(
		direntBytes(dot), direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1022, inode: 22, name: "big", fileType: 1}),
	))
	writeFileInode(img, 22, 5000, []uint64{30, 31})
	fillBlock(img, 30, 'A')
	fillBlock(img, 31, 'B')

	volume := testVolume(t, img)
	entry, err := volume.Stat("/big")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Allocated == nil || *entry.Allocated != 8192 {
		t.Fatalf("allocated = %v, want 8192", entry.Allocated)
	}

	file, err := volume.OpenFile("/big")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buffer := make([]byte, 5000)
	if _, err := file.ReadAt(0, buffer); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	for index := 0; index < 4096; index++ {
		if buffer[index] != 'A' {
			t.Fatalf("byte %d = %q", index, buffer[index])
		}
	}
	for index := 4096; index < 5000; index++ {
		if buffer[index] != 'B' {
			t.Fatalf("byte %d = %q", index, buffer[index])
		}
	}
	if _, err := file.ReadAt(5000, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("read at end error = %v", err)
	}

	ranges, err := file.Extents(0, 5000)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 1 || ranges[0].Kind != source.RangeData || ranges[0].Len != 5000 {
		t.Errorf("extents = %+v", ranges)
	}
	if ranges[0].ParentOffset != 30*testBlockSize {
		t.Errorf("physical = %d", ranges[0].ParentOffset)
	}

	images, err := file.MapToImage(0, 10)
	if err != nil || len(images) != 1 || images[0].ImageOffset != 30*testBlockSize {
		t.Errorf("MapToImage = %+v, %v", images, err)
	}
}

func TestBlockMappedFileNonContiguous(t *testing.T) {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(
		direntBytes(dot), direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1022, inode: 22, name: "split", fileType: 1}),
	))
	writeFileInode(img, 22, 4097, []uint64{30, 32})
	fillBlock(img, 30, 'X')
	fillBlock(img, 32, 'Y')

	volume := testVolume(t, img)
	file, err := volume.OpenFile("/split")
	if err != nil {
		t.Fatal(err)
	}
	if sourceFile, ok := file.(*FileSource); ok {
		if len(sourceFile.Runs()) != 2 {
			t.Errorf("extent count = %d", len(sourceFile.Runs()))
		}
	}
	buffer := make([]byte, 4097)
	if _, err := file.ReadAt(0, buffer); err != nil {
		t.Fatal(err)
	}
	if buffer[4095] != 'X' || buffer[4096] != 'Y' {
		t.Errorf("boundary bytes = %q %q", buffer[4095], buffer[4096])
	}
	ranges, err := file.Extents(0, 4097)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 {
		t.Fatalf("ranges = %+v", ranges)
	}
}

func TestIndirectPointerTree(t *testing.T) {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(
		direntBytes(dot), direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1022, inode: 22, name: "deep", fileType: 1}),
	))
	// Height 2: the dinode's top pointer names an IN block (32), whose
	// pointers name data blocks 33, 34 and 35.
	at := writeDinode(img, 22, modeFile|0o644, 9000, 2, 0)
	putBE64(img, at+DinodeSize, 32)
	metaHeader(img, 32, MetaIN, FormatIN)
	putBE64(img, int(32*testBlockSize)+MetaHeaderSize, 33)
	putBE64(img, int(32*testBlockSize)+MetaHeaderSize+8, 34)
	putBE64(img, int(32*testBlockSize)+MetaHeaderSize+16, 35)
	fillBlock(img, 33, 'C')
	fillBlock(img, 34, 'D')
	fillBlock(img, 35, 'E')

	volume := testVolume(t, img)
	entry, err := volume.Stat("/deep")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Allocated == nil || *entry.Allocated != 12288 {
		t.Fatalf("allocated = %v", entry.Allocated)
	}
	stats := volume.Stats()
	if stats.ExtentBlocks != 1 {
		t.Errorf("extent blocks = %d", stats.ExtentBlocks)
	}
	file, err := volume.OpenFile("/deep")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 9000)
	if _, err := file.ReadAt(0, buffer); err != nil {
		t.Fatal(err)
	}
	if buffer[8191] != 'D' || buffer[8192] != 'E' {
		t.Errorf("boundary bytes = %q %q", buffer[8191], buffer[8192])
	}
}

func TestFileSourceFailures(t *testing.T) {
	cases := []struct {
		name   string
		setup  func([]byte)
		errIs  error
		substr string
	}{
		{
			name: "hole refused",
			setup: func(img []byte) {
				writeFileInode(img, 22, 4096, []uint64{0})
			},
			errIs:  source.ErrCorrupt,
			substr: "hole",
		},
		{
			name: "pointer out of range",
			setup: func(img []byte) {
				writeFileInode(img, 22, 4096, []uint64{9999})
			},
			errIs:  source.ErrCorrupt,
			substr: "out of range",
		},
		{
			name: "indirect block bad header",
			setup: func(img []byte) {
				at := writeDinode(img, 22, modeFile|0o644, 4096, 2, 0)
				putBE64(img, at+DinodeSize, 32)
				// No meta header at block 32.
			},
			errIs:  source.ErrCorrupt,
			substr: "magic",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			img := baseImage()
			dot, dotdot := dotEntries(20, 20)
			writeDirInode(img, 20, join(
				direntBytes(dot), direntBytes(dotdot),
				direntBytes(direntSpec{formal: 1022, inode: 22, name: "bad", fileType: 1}),
			))
			testCase.setup(img)
			volume := testVolume(t, img)
			// The walk lists the name but marks the stream undecodable.
			entry, err := volume.Stat("/bad")
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if entry.Allocated != nil {
				t.Errorf("allocated = %v, want nil", entry.Allocated)
			}
			if volume.Undecodable() == 0 {
				t.Errorf("undecodable counter = 0")
			}
			_, err = volume.OpenFile("/bad")
			if !errors.Is(err, testCase.errIs) || !strings.Contains(err.Error(), testCase.substr) {
				t.Fatalf("OpenFile error = %v, want %v containing %q", err, testCase.errIs, testCase.substr)
			}
		})
	}
}

func TestReadAtLossy(t *testing.T) {
	volume := testVolume(t, treeImage())
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	n, err := file.ReadAtLossy(0, buffer)
	if err != nil || n != 5 || string(buffer[:5]) != "hello" {
		t.Fatalf("lossy read = %d, %v, %q", n, err, buffer[:n])
	}
	if _, err := file.ReadAtLossy(10, buffer); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy out-of-range error = %v", err)
	}
}

// ---- directories -----------------------------------------------------------

func TestUnstuffedDirectoryAcrossJournalBlocks(t *testing.T) {
	img := baseImage()
	// The root is an unstuffed (height 1) directory mapped to two JD blocks.
	at := writeDinode(img, 20, modeDirectory|0o755, 0, 1, FlagJData)
	putBE64(img, at+DinodeSize, 30)
	putBE64(img, at+DinodeSize+8, 31)

	// 56-byte records, 72 per block, leave a 40-byte hole that a free slot
	// fills, so no record crosses a 4072-byte journal payload boundary.
	var records []byte
	for index := 0; index < 144; index++ {
		records = append(records, direntBytes(direntSpec{
			formal:   2000 + uint64(index),
			inode:    22,
			name:     "f" + threeDigits(index),
			fileType: 1,
			recLen:   56,
		})...)
		if index%72 == 71 {
			records = append(records, direntBytes(direntSpec{free: true, recLen: 40})...)
		}
	}
	putBE64(img, at+0x38, uint64(len(records))) // di_size
	writeStuffedInode(img, 22, modeFile|0o644, []byte("x"))

	jdata := testBlockSize - MetaHeaderSize
	for blockIndex := 0; blockIndex < 2; blockIndex++ {
		block := uint64(30 + blockIndex)
		metaHeader(img, block, MetaJD, FormatJD)
		start := blockIndex * jdata
		end := start + jdata
		if end > len(records) {
			end = len(records)
		}
		copy(img[int(block*testBlockSize)+MetaHeaderSize:], records[start:end])
	}

	volume := testVolume(t, img)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 144 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[143].Name != "f143" {
		t.Errorf("last = %q", entries[143].Name)
	}
	stats := volume.Stats()
	if stats.ExtentBlocks != 0 || stats.ExtentRecords == 0 {
		t.Errorf("stats = %+v", stats)
	}
}

func TestUnstuffedDirectoryBadJournalBlock(t *testing.T) {
	img := baseImage()
	at := writeDinode(img, 20, modeDirectory|0o755, 32, 1, FlagJData)
	putBE64(img, at+DinodeSize, 30)
	records := join(direntBytes(direntSpec{formal: 1022, inode: 22, name: "x", fileType: 1}))
	putBE64(img, at+0x38, uint64(len(records)))
	// Block 30 lacks the JD metadata header.
	volume := testVolume(t, img)
	if volume.Unreadable() == 0 {
		t.Errorf("unreadable = 0")
	}
	if _, err := volume.ListDir("/"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ListDir error = %v, want corrupt", err)
	}
}

func TestExhashDirectoryIsRefusedButOpenSucceeds(t *testing.T) {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(direntBytes(dot), direntBytes(dotdot)))
	at := int(20 * testBlockSize)
	putBE32(img, at+0x80, FlagExhash|FlagJData)
	// A stuffed EXHASH root is refused by name.
	volume := testVolume(t, img)
	if volume.Refusals() == 0 {
		t.Errorf("refusals = 0")
	}
	_, err := volume.ListDir("/")
	if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "EXHASH") {
		t.Fatalf("ListDir error = %v, want unsupported EXHASH", err)
	}
}

func TestDirectoryLoopIsListedOnce(t *testing.T) {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(
		direntBytes(dot), direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1023, inode: 23, name: "a", fileType: 2}),
		direntBytes(direntSpec{formal: 1023, inode: 23, name: "b", fileType: 2}),
	))
	dot, dotdot = dotEntries(23, 20)
	writeDirInode(img, 23, join(
		direntBytes(dot), direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1024, inode: 24, name: "leaf", fileType: 1}),
	))
	writeStuffedInode(img, 24, modeFile|0o644, []byte("leaf"))

	volume := testVolume(t, img)
	if volume.DirectoryLoops() != 1 {
		t.Errorf("directory loops = %d", volume.DirectoryLoops())
	}
	if _, err := volume.Stat("/a/leaf"); err != nil {
		t.Errorf("Stat /a/leaf: %v", err)
	}
	entries, err := volume.ListDir("/b")
	if err != nil {
		t.Fatalf("ListDir /b: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("second path walked twice: %v", entryNames(entries))
	}
}

// ---- corruption ------------------------------------------------------------

func TestDirectoryCorruption(t *testing.T) {
	cases := []struct {
		name    string
		records func() []byte
		text    string
	}{
		{"zero rec_len", func() []byte {
			record := direntBytes(direntSpec{formal: 1, inode: 22, name: "x", fileType: 1})
			putBE16(record, 0x14, 0)
			return record
		}, "rec_len"},
		{"unaligned rec_len", func() []byte {
			record := direntBytes(direntSpec{formal: 1, inode: 22, name: "x", fileType: 1, recLen: 49})
			return record
		}, "multiple of 8"},
		{"empty name", func() []byte {
			return direntBytes(direntSpec{formal: 1, inode: 22, name: "", fileType: 1})
		}, "empty name"},
		{"slash in name", func() []byte {
			return direntBytes(direntSpec{formal: 1, inode: 22, name: "a/b", fileType: 1})
		}, "slash"},
		{"nul in name", func() []byte {
			record := direntBytes(direntSpec{formal: 1, inode: 22, name: "ab", fileType: 1})
			record[DirentFixed+1] = 0
			return record
		}, "NUL"},
		{"file type out of range", func() []byte {
			return direntBytes(direntSpec{formal: 1, inode: 22, name: "x", fileType: 8})
		}, "file type"},
		{"name past rec_len", func() []byte {
			record := direntBytes(direntSpec{formal: 1, inode: 22, name: "x", fileType: 1, recLen: 48})
			putBE16(record, 0x16, 40)
			return record
		}, "past its rec_len"},
		{"short trailing bytes", func() []byte {
			return make([]byte, 16)
		}, "too short for a dirent"},
		{"record past declared end", func() []byte {
			record := direntBytes(direntSpec{formal: 1, inode: 22, name: "x", fileType: 1, recLen: 64})
			return record
		}, "past the"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			img := baseImage()
			records := testCase.records()
			writeDirInode(img, 20, records)
			if testCase.name == "record past declared end" {
				// Trim the declared size inside the dinode so the 64-byte
				// record extends past it.
				putBE64(img, int(20*testBlockSize)+0x38, uint64(len(records)-8))
			}
			volume := testVolume(t, img)
			_, err := volume.ListDir("/")
			if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), testCase.text) {
				t.Fatalf("ListDir error = %v, want corrupt containing %q", err, testCase.text)
			}
		})
	}
}

func TestInodeCorruption(t *testing.T) {
	cases := []struct {
		name  string
		setup func([]byte)
		errIs error
		text  string
	}{
		{"bad magic", func(img []byte) {
			putBE32(img, int(20*testBlockSize), 0xdeadbeef)
		}, source.ErrCorrupt, "magic"},
		{"wrong metatype", func(img []byte) {
			putBE32(img, int(20*testBlockSize)+4, MetaDI+1)
		}, source.ErrCorrupt, "metatype"},
		{"wrong format", func(img []byte) {
			putBE32(img, int(20*testBlockSize)+0x10, FormatDI+1)
		}, source.ErrCorrupt, "format"},
		{"address mismatch", func(img []byte) {
			putBE64(img, int(20*testBlockSize)+0x20, 21)
		}, source.ErrCorrupt, "names itself"},
		{"zero links", func(img []byte) {
			putBE32(img, int(20*testBlockSize)+0x34, 0)
		}, source.ErrCorrupt, "link count"},
		{"unknown mode", func(img []byte) {
			putBE32(img, int(20*testBlockSize)+0x28, 0)
		}, source.ErrCorrupt, "mode"},
		{"size larger than volume", func(img []byte) {
			putBE64(img, int(20*testBlockSize)+0x38, 1<<40)
			putBE32(img, int(20*testBlockSize)+0x28, modeFile|0o644)
			putBE16(img, int(20*testBlockSize)+0x8a, 1)
		}, source.ErrCorrupt, "more than"},
		{"timestamp nanoseconds", func(img []byte) {
			putBE32(img, int(20*testBlockSize)+0xb0, 1_000_000_000)
		}, source.ErrCorrupt, "nanoseconds"},
		{"height cap", func(img []byte) {
			putBE16(img, int(20*testBlockSize)+0x8a, MaxHeight+1)
		}, source.ErrUnsupported, "height"},
		{"journaled regular file", func(img []byte) {
			putBE32(img, int(20*testBlockSize)+0x80, FlagJData)
			putBE32(img, int(20*testBlockSize)+0x28, modeFile|0o644)
			putBE16(img, int(20*testBlockSize)+0x8a, 1)
		}, source.ErrUnsupported, "journaled"},
		{"non-directory exhash", func(img []byte) {
			putBE32(img, int(20*testBlockSize)+0x80, FlagExhash)
			putBE32(img, int(20*testBlockSize)+0x28, modeFile|0o644)
			putBE16(img, int(20*testBlockSize)+0x8a, 0)
		}, source.ErrCorrupt, "EXHASH"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			img := baseImage()
			testCase.setup(img)
			_, err := Open(source.NewMemorySource(1, img))
			if !errors.Is(err, testCase.errIs) || !strings.Contains(err.Error(), testCase.text) {
				t.Fatalf("Open error = %v, want %v containing %q", err, testCase.errIs, testCase.text)
			}
		})
	}
}

func TestUnreadableNamedInodeIsSkipped(t *testing.T) {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(
		direntBytes(dot), direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1022, inode: 22, name: "broken", fileType: 1}),
		direntBytes(direntSpec{formal: 1023, inode: 23, name: "good", fileType: 1}),
	))
	// Inode 22 is outside the volume range? No: make its magic invalid.
	writeStuffedInode(img, 22, modeFile|0o644, []byte("x"))
	putBE32(img, int(22*testBlockSize), 0)
	writeStuffedInode(img, 23, modeFile|0o644, []byte("y"))

	volume := testVolume(t, img)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "good" {
		t.Fatalf("entries = %v", entryNames(entries))
	}
	if volume.Undecodable() != 1 {
		t.Errorf("undecodable = %d", volume.Undecodable())
	}
	if len(volume.Warnings()) == 0 {
		t.Errorf("no warning recorded")
	}
}

func TestOutOfRangeNameIsMalformed(t *testing.T) {
	img := baseImage()
	dot, dotdot := dotEntries(20, 20)
	writeDirInode(img, 20, join(
		direntBytes(dot), direntBytes(dotdot),
		direntBytes(direntSpec{formal: 1022, inode: 9999, name: "outside", fileType: 1}),
	))
	volume := testVolume(t, img)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %v", entryNames(entries))
	}
	if volume.Malformed() == 0 {
		t.Errorf("malformed = 0")
	}
}

// ---- Info and source semantics --------------------------------------------

func TestInfo(t *testing.T) {
	volume := testVolume(t, treeImage())
	info := volume.Info()
	if info.Type != KindLabel {
		t.Errorf("type = %q", info.Type)
	}
	if info.UUID != "67667332746573747575696430303031" {
		t.Errorf("uuid = %q", info.UUID)
	}
	if info.FSFormat != FSFormatGFS2 || info.MultihostFormat != MultihostFormatGFS2 {
		t.Errorf("formats = %d/%d", info.FSFormat, info.MultihostFormat)
	}
	if info.LockProto != "lock_nolock" || info.LockTable != "gfs2fs0" {
		t.Errorf("lock = %q/%q", info.LockProto, info.LockTable)
	}
	if info.Entries != 7 {
		t.Errorf("entries = %d", info.Entries)
	}
	// root, hello.txt, sub, inner, empty, link, fifo
	if info.Directories != 3 || info.Files != 2 || info.Symlinks != 1 {
		t.Errorf("counts = dirs %d files %d links %d", info.Directories, info.Files, info.Symlinks)
	}
	if len(info.Warnings) == 0 {
		t.Errorf("warnings empty")
	}
}

func TestSourceSemantics(t *testing.T) {
	volume := testVolume(t, treeImage())
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if file.SourceID() == 0 || file.ImageID() != 0 || file.SectorSize() != 512 {
		t.Errorf("identity = %d/%d/%d", file.SourceID(), file.ImageID(), file.SectorSize())
	}
	short := make([]byte, 16)
	n, err := file.ReadAt(0, short)
	if err != nil || n != 5 {
		t.Fatalf("short read = %d, %v", n, err)
	}
	if string(short[:n]) != "hello" {
		t.Errorf("bytes = %q", short[:n])
	}
	if file.IsEmpty() {
		t.Errorf("IsEmpty = true for a five-byte file")
	}
	if stats := file.Stats(); stats.Reads == 0 {
		t.Errorf("stats = %+v", stats)
	}
}
