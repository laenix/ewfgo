package jffs2

import (
	"bytes"
	"compress/zlib"
	"errors"
	"hash/crc32"
	"sort"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	jfFileMode = 0o100644
	jfDirMode  = 0o040755
	jfLinkMode = 0o120777
	jfMCTime   = 1_700_000_000
	jfATime    = 1_700_000_300
	jfMTime    = 1_700_000_100
	jfCTime    = 1_700_000_200
)

func jfCRC(data []byte) uint32 { return crc32.ChecksumIEEE(data) }

type jfBuilder struct {
	data []byte
}

func (b *jfBuilder) header(nodetype uint16, totlen int) []byte {
	out := make([]byte, 12)
	out[0] = byte(magic & 0xff)
	out[1] = byte(magic >> 8)
	out[2] = byte(nodetype)
	out[3] = byte(nodetype >> 8)
	out[4] = byte(totlen)
	out[5] = byte(totlen >> 8)
	out[6] = byte(totlen >> 16)
	out[7] = byte(totlen >> 24)
	crc := jfCRC(out[:8])
	out[8] = byte(crc)
	out[9] = byte(crc >> 8)
	out[10] = byte(crc >> 16)
	out[11] = byte(crc >> 24)
	return out
}

func (b *jfBuilder) pushDirent(pino, version, ino uint32, name []byte) int {
	totlen := paddedLen(direntFixedBytes + len(name))
	out := make([]byte, totlen)
	copy(out, b.header(nodeTypeDirent, totlen))
	putLE32(out, 12, pino)
	putLE32(out, 16, version)
	putLE32(out, 20, ino)
	putLE32(out, 24, jfMCTime)
	out[28] = byte(len(name))
	out[29] = 1
	putLE32(out, 32, jfCRC(out[12:32]))
	copy(out[direntFixedBytes:], name)
	putLE32(out, 36, jfCRC(name))
	at := len(b.data)
	b.data = append(b.data, out...)
	return at
}

type jfInode struct {
	ino     uint32
	version uint32
	mode    uint32
	uid     uint16
	gid     uint16
	isize   uint32
	offset  uint32
	compr   byte
	data    []byte
	dsize   uint32
}

func (b *jfBuilder) pushInode(spec jfInode) int {
	totlen := paddedLen(inodeFixedBytes + len(spec.data))
	out := make([]byte, totlen)
	copy(out, b.header(nodeTypeInode, totlen))
	putLE32(out, 12, spec.ino)
	putLE32(out, 16, spec.version)
	putLE32(out, 20, spec.mode)
	putLE16(out, 24, spec.uid)
	putLE16(out, 26, spec.gid)
	putLE32(out, 28, spec.isize)
	putLE32(out, 32, jfATime)
	putLE32(out, 36, jfMTime)
	putLE32(out, 40, jfCTime)
	putLE32(out, 44, spec.offset)
	putLE32(out, 48, uint32(len(spec.data)))
	putLE32(out, 52, spec.dsize)
	out[56] = spec.compr
	putLE32(out, 60, jfCRC(spec.data))
	putLE32(out, 64, jfCRC(out[12:64]))
	copy(out[inodeFixedBytes:], spec.data)
	at := len(b.data)
	b.data = append(b.data, out...)
	return at
}

func (b *jfBuilder) pushRawHeader(nodetype uint16, totlen int) int {
	header := b.header(nodetype, totlen)
	at := len(b.data)
	b.data = append(b.data, header...)
	return at
}

func (b *jfBuilder) pushNode(nodetype uint16, totlen int) int {
	out := make([]byte, totlen)
	copy(out, b.header(nodetype, totlen))
	at := len(b.data)
	b.data = append(b.data, out...)
	return at
}

func paddedLen(length int) int { return (length + 3) &^ 3 }

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

func (b *jfBuilder) source() source.ByteSource {
	return source.NewMemorySource(1, append([]byte(nil), b.data...))
}

func (b *jfBuilder) open(t *testing.T) *Volume {
	t.Helper()
	volume, err := Open(b.source())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func mustRead(t *testing.T, file source.ByteSource, offset uint64, length int) []byte {
	t.Helper()
	buf := make([]byte, length)
	n, err := file.ReadAt(offset, buf)
	if err != nil {
		t.Fatalf("ReadAt(%d, %d): %v", offset, length, err)
	}
	return buf[:n]
}

func jfBasicBuilder() *jfBuilder {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode, uid: 1000, gid: 1001, dsize: 0})
	b.pushDirent(1, 1, 2, []byte("keep.txt"))
	b.pushDirent(1, 1, 3, []byte("gone.txt"))
	b.pushDirent(1, 2, 0, []byte("gone.txt"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, uid: 1000, gid: 1001, isize: 5, dsize: 5, data: []byte("Hello")})
	b.pushInode(jfInode{ino: 3, version: 1, mode: jfFileMode, uid: 1000, gid: 1001, isize: 4, dsize: 4, data: []byte("Bye!")})
	return b
}

func TestDetect(t *testing.T) {
	if ok, err := Detect(jfBasicBuilder().source()); err != nil || !ok {
		t.Fatalf("Detect(valid) = %v, %v", ok, err)
	}
	if ok, err := Detect(source.NewMemorySource(1, make([]byte, 8192))); err != nil || ok {
		t.Fatalf("Detect(zeros) = %v, %v", ok, err)
	}
	broken := &jfBuilder{}
	broken.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	broken.data[8] ^= 0xff
	if ok, err := Detect(broken.source()); err != nil || ok {
		t.Fatalf("Detect(broken header) = %v, %v", ok, err)
	}
	short := &jfBuilder{}
	short.pushRawHeader(nodeTypeInode, 41)
	if ok, err := Detect(short.source()); err != nil || ok {
		t.Fatalf("Detect(unaligned totlen) = %v, %v", ok, err)
	}
}

func TestDetectOnlyScansFirstMiB(t *testing.T) {
	prefix := make([]byte, 1<<20)
	b := &jfBuilder{data: prefix}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	if ok, err := Detect(b.source()); err != nil || ok {
		t.Fatalf("Detect(node after 1 MiB) = %v, %v", ok, err)
	}
	volume := b.open(t)
	if info := volume.Info(); info.RootIno != ROOTIno || len(volume.entries) != 1 {
		t.Fatalf("Open did not find the node: %+v", info)
	}
}

func TestOpenRootAndInfo(t *testing.T) {
	volume := jfBasicBuilder().open(t)
	info := volume.Info()
	if info.RootIno != 1 || info.DirentNodes != 3 || info.InodeNodes != 3 {
		t.Fatalf("info = %+v", info)
	}
	if info.ValidNodes != 6 || info.InvalidNodes != 0 {
		t.Fatalf("node counts = %+v", info)
	}
	if info.DeletedNames != 1 || info.Undecodable != 0 || info.Unreadable != 0 {
		t.Fatalf("name counts = %+v", info)
	}
	if info.Entries != 2 {
		t.Fatalf("entries = %d", info.Entries)
	}
	if len(info.Compressors) != 1 || info.Compressors[0] != "none" {
		t.Fatalf("compressors = %v", info.Compressors)
	}
	if volume.KindLabel() != "JFFS2" {
		t.Fatalf("kind = %q", volume.KindLabel())
	}
}

func TestListDirAndStat(t *testing.T) {
	volume := jfBasicBuilder().open(t)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "keep.txt" {
		t.Fatalf("entries = %+v", entries)
	}
	entry := entries[0]
	if entry.Path != "/keep.txt" || entry.Inode != 2 || entry.ParentInode != 1 {
		t.Fatalf("entry = %+v", entry)
	}
	if !entry.IsFile || entry.IsDir || entry.IsSymlink || entry.IsSpecial {
		t.Fatalf("kind = %+v", entry)
	}
	if entry.Size != 5 || entry.Mode != jfFileMode || entry.UID != 1000 || entry.GID != 1001 {
		t.Fatalf("metadata = %+v", entry)
	}
	if entry.Atime.Unix() != jfATime || entry.Mtime.Unix() != jfMTime || entry.Ctime.Unix() != jfCTime {
		t.Fatalf("times = %v/%v/%v", entry.Atime, entry.Mtime, entry.Ctime)
	}
	if entry.Version != 1 || !entry.HasAllocated || entry.Allocated != 5 || entry.Deleted {
		t.Fatalf("version/allocated = %+v", entry)
	}
	stat, err := volume.Stat("/keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	if stat.Inode != 2 || stat.Path != "/keep.txt" {
		t.Fatalf("stat = %+v", stat)
	}
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatal(err)
	}
	if root.Name != "/" || root.Path != "/" || !root.IsDir || root.Inode != 1 || root.Mode != jfDirMode {
		t.Fatalf("root = %+v", root)
	}
	emptyPath, err := volume.Stat("")
	if err != nil || emptyPath.Inode != 1 {
		t.Fatalf("empty path = %+v, %v", emptyPath, err)
	}
}

func TestNestedDirectories(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("dir"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfDirMode})
	b.pushDirent(2, 1, 3, []byte("inner.txt"))
	b.pushInode(jfInode{ino: 3, version: 1, mode: jfFileMode, isize: 4, dsize: 4, data: []byte("deep")})
	volume := b.open(t)

	entries, err := volume.ListDir("/dir")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "inner.txt" || entries[0].Path != "/dir/inner.txt" {
		t.Fatalf("entries = %+v", entries)
	}
	entry, err := volume.Stat("/dir/../dir/./inner.txt")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Inode != 3 {
		t.Fatalf("resolved = %+v", entry)
	}
	if got := mustRead(t, mustOpen(t, volume, "/dir/inner.txt"), 0, 4); string(got) != "deep" {
		t.Fatalf("read = %q", got)
	}
}

func mustOpen(t *testing.T, volume *Volume, path string) source.ByteSource {
	t.Helper()
	file, err := volume.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile(%q): %v", path, err)
	}
	return file
}

func TestInodeVersionsOverwrite(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("a.txt"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 4, dsize: 4, data: []byte("AAAA")})
	b.pushInode(jfInode{ino: 2, version: 2, mode: jfFileMode, uid: 7, gid: 8, isize: 5, offset: 2, dsize: 2, data: []byte("BB")})
	volume := b.open(t)

	if got := mustRead(t, mustOpen(t, volume, "/a.txt"), 0, 5); string(got) != "AABB\x00" {
		t.Fatalf("read = %q", got)
	}
	entry, err := volume.Stat("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Size != 5 || entry.Version != 2 || entry.UID != 7 || entry.GID != 8 {
		t.Fatalf("newest metadata = %+v", entry)
	}
	if !entry.HasAllocated || entry.Allocated != 6 {
		t.Fatalf("allocated = %+v", entry)
	}
	inode, ok := volume.Inode(2)
	if !ok || inode.Version != 2 {
		t.Fatalf("newest inode = %+v/%v", inode, ok)
	}
}

func TestObsoleteNodePastLengthSuppliesNothing(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("a.txt"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 4, dsize: 4, data: []byte("AAAA")})
	b.pushInode(jfInode{ino: 2, version: 2, mode: jfFileMode, isize: 4, offset: 8, dsize: 4, data: []byte("BBBB")})
	volume := b.open(t)
	if got := mustRead(t, mustOpen(t, volume, "/a.txt"), 0, 4); string(got) != "AAAA" {
		t.Fatalf("read = %q", got)
	}
	entry, _ := volume.Stat("/a.txt")
	if entry.Allocated != 4 {
		t.Fatalf("allocated = %d", entry.Allocated)
	}
}

func TestSparseZeroAndCopyNodes(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("sparse"))
	b.pushDirent(1, 1, 3, []byte("zero"))
	b.pushDirent(1, 1, 4, []byte("copy"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 6, offset: 2, dsize: 2, data: []byte("BB")})
	b.pushInode(jfInode{ino: 3, version: 1, mode: jfFileMode, isize: 4, dsize: 4, compr: 1})
	b.pushInode(jfInode{ino: 4, version: 1, mode: jfFileMode, isize: 4, dsize: 4, compr: 4, data: []byte("copy")})
	volume := b.open(t)

	sparse := mustOpen(t, volume, "/sparse")
	if got := mustRead(t, sparse, 0, 6); !bytes.Equal(got, []byte{0, 0, 'B', 'B', 0, 0}) {
		t.Fatalf("sparse = %q", got)
	}
	ranges, err := sparse.Extents(0, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 3 || ranges[0].Kind != source.RangeZero || ranges[1].Kind != source.RangeData ||
		ranges[2].Kind != source.RangeZero || ranges[1].ParentOffset == 0 {
		t.Fatalf("ranges = %+v", ranges)
	}
	imageRanges, err := sparse.MapToImage(0, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(imageRanges) != 3 || imageRanges[0].Kind != source.RangeZero || imageRanges[0].ImageOffset != 0 {
		t.Fatalf("image ranges = %+v", imageRanges)
	}

	zero := mustOpen(t, volume, "/zero")
	if got := mustRead(t, zero, 0, 4); !bytes.Equal(got, make([]byte, 4)) {
		t.Fatalf("zero = %q", got)
	}
	zeroEntry, _ := volume.Stat("/zero")
	if zeroEntry.Allocated != 0 || !zeroEntry.HasAllocated {
		t.Fatalf("zero allocated = %+v", zeroEntry)
	}
	if !zero.(*Jffs2FileSource).IsHole() {
		t.Fatal("the zero file should be a hole")
	}
	if got := mustRead(t, mustOpen(t, volume, "/copy"), 0, 4); string(got) != "copy" {
		t.Fatalf("copy = %q", got)
	}
}

func TestSymlink(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("link"))
	b.pushDirent(1, 1, 3, []byte("file"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfLinkMode, isize: 6, dsize: 6, data: []byte("target")})
	b.pushInode(jfInode{ino: 3, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("x")})
	volume := b.open(t)

	entry, err := volume.Stat("/link")
	if err != nil {
		t.Fatal(err)
	}
	if !entry.IsSymlink || entry.IsFile || entry.Size != 6 || entry.SymlinkTarget != "target" {
		t.Fatalf("symlink = %+v", entry)
	}
	if entry.HasAllocated {
		t.Fatalf("a symlink should not report an allocated byte count: %+v", entry)
	}
	if _, err := volume.OpenFile("/link"); !errors.Is(err, ErrNotFile) {
		t.Fatalf("OpenFile symlink = %v", err)
	}
	stream, err := volume.OpenSymlink("/link")
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, stream, 0, 6); string(got) != "target" {
		t.Fatalf("target bytes = %q", got)
	}
	if _, err := volume.OpenSymlink("/file"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("OpenSymlink file = %v", err)
	}
}

func TestDeletedNameIsCountedNotListed(t *testing.T) {
	volume := jfBasicBuilder().open(t)
	if info := volume.Info(); info.DeletedNames != 1 {
		t.Fatalf("deleted names = %d", info.DeletedNames)
	}
	if _, err := volume.Stat("/gone.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat deleted = %v", err)
	}
}

func TestHardLinks(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 9, []byte("hard1"))
	b.pushDirent(1, 1, 9, []byte("hard2"))
	b.pushInode(jfInode{ino: 9, version: 1, mode: jfFileMode, isize: 4, dsize: 4, data: []byte("same")})
	volume := b.open(t)

	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "hard1" || entries[1].Name != "hard2" {
		t.Fatalf("entries = %+v", entries)
	}
	if got := mustRead(t, mustOpen(t, volume, "/hard1"), 0, 4); string(got) != "same" {
		t.Fatalf("hard1 = %q", got)
	}
	if got := mustRead(t, mustOpen(t, volume, "/hard2"), 0, 4); string(got) != "same" {
		t.Fatalf("hard2 = %q", got)
	}
}

func TestDirectoryReferencesAreNotWalkedTwice(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("a"))
	b.pushDirent(1, 1, 2, []byte("b"))
	b.pushDirent(1, 1, 1, []byte("loop"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfDirMode})
	b.pushDirent(2, 1, 3, []byte("inner.txt"))
	b.pushInode(jfInode{ino: 3, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("x")})
	volume := b.open(t)

	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("root entries = %+v", entries)
	}
	a, err := volume.ListDir("/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0].Name != "inner.txt" {
		t.Fatalf("/a = %+v", a)
	}
	bEntries, err := volume.ListDir("/b")
	if err != nil {
		t.Fatal(err)
	}
	if len(bEntries) != 0 {
		t.Fatalf("/b was walked twice: %+v", bEntries)
	}
	if _, err := volume.Stat("/loop/inner.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("loop path = %v", err)
	}
}

func TestCorruptDirentIsSkipped(t *testing.T) {
	b := jfBasicBuilder()
	// jfBasicBuilder pushes the root inode first, then the dirents.
	direntAt := 68
	b.data[direntAt+30] ^= 0xff
	volume := b.open(t)
	info := volume.Info()
	if info.InvalidNodes != 1 || info.Entries != 1 {
		t.Fatalf("info = %+v", info)
	}
	if _, err := volume.Stat("/keep.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("name survived a corrupt dirent: %v", err)
	}
}

func TestBrokenHeaderCRCSkipsAndResumes(t *testing.T) {
	b := jfBasicBuilder()
	direntAt := 68
	b.data[direntAt+8] ^= 0xff
	volume := b.open(t)
	if info := volume.Info(); info.InvalidNodes == 0 {
		t.Fatalf("info = %+v", info)
	}
	if len(volume.entries) != 1 {
		t.Fatalf("entries = %+v", volume.entries)
	}
}

func TestInodeDataCRCMismatchDropsTheInode(t *testing.T) {
	b := jfBasicBuilder()
	// The file inode is the last node: root inode, three dirents, then the
	// file inode. Its data starts 68 bytes into that node.
	dataAt := 68 + 3*paddedLen(direntFixedBytes+len("keep.txt")) + inodeFixedBytes
	b.data[dataAt] ^= 0xff
	volume := b.open(t)
	info := volume.Info()
	if info.InvalidNodes != 1 {
		t.Fatalf("invalid nodes = %d", info.InvalidNodes)
	}
	if info.Undecodable != 1 {
		t.Fatalf("undecodable = %d", info.Undecodable)
	}
	if _, err := volume.Stat("/keep.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing inode still produced a name: %v", err)
	}
}

func TestUnknownNodeTypesAreCounted(t *testing.T) {
	b := jfBasicBuilder()
	b.pushNode(nodeTypeCleanmarker, 12)
	b.pushNode(nodeTypePadding, 12)
	b.pushNode(nodeTypeSummary, 12)
	volume := b.open(t)
	if info := volume.Info(); info.ValidNodes != 9 || info.InvalidNodes != 0 {
		t.Fatalf("info = %+v", info)
	}
}

func TestMalformedNodeLengthsAreCounted(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*jfBuilder)
	}{
		{"shorter than header", func(b *jfBuilder) { b.pushRawHeader(nodeTypeDirent, 8) }},
		{"not aligned", func(b *jfBuilder) { b.pushRawHeader(nodeTypeDirent, 13) }},
		{"beyond image", func(b *jfBuilder) { b.pushRawHeader(nodeTypeInode, 4096) }},
		{"above node cap", func(b *jfBuilder) { b.pushRawHeader(nodeTypeInode, int(maxNodeBytes)+4) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := jfBasicBuilder()
			test.mutate(b)
			volume := b.open(t)
			if info := volume.Info(); info.InvalidNodes == 0 {
				t.Fatalf("info = %+v", info)
			}
		})
	}
}

func TestDirentNameValidation(t *testing.T) {
	for _, name := range [][]byte{{'a', 0, 'b'}, []byte("a/b")} {
		b := &jfBuilder{}
		b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
		b.pushDirent(1, 1, 2, name)
		b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("x")})
		volume := b.open(t)
		if info := volume.Info(); info.InvalidNodes != 1 {
			t.Fatalf("name %q info = %+v", name, info)
		}
		entries, err := volume.ListDir("/")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("name %q was listed: %+v", name, entries)
		}
	}
}

func TestDirentNameCRC(t *testing.T) {
	b := jfBasicBuilder()
	direntAt := 68
	b.data[direntAt+direntFixedBytes] ^= 0x01
	volume := b.open(t)
	if info := volume.Info(); info.InvalidNodes != 1 {
		t.Fatalf("info = %+v", info)
	}
}

func TestInodeZeroAndZeroCompressorMismatchAreInvalid(t *testing.T) {
	tests := []struct {
		name  string
		inode jfInode
	}{
		{"inode zero", jfInode{ino: 0, version: 1, mode: jfFileMode, isize: 4, dsize: 4, data: []byte("data")}},
		{"zero compressor stores bytes", jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 64, dsize: 64, compr: 1, data: []byte("xyz")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &jfBuilder{}
			b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
			b.pushDirent(1, 1, 2, []byte("bad"))
			b.pushInode(test.inode)
			volume := b.open(t)
			if info := volume.Info(); info.InvalidNodes != 1 {
				t.Fatalf("info = %+v", info)
			}
		})
	}
}

func TestUnsupportedCompressors(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	for index, compr := range []byte{2, 3, 5, 9} {
		ino := uint32(index + 2)
		b.pushDirent(1, 1, ino, []byte("c"+string(rune('0'+index))))
		b.pushInode(jfInode{ino: ino, version: 1, mode: jfFileMode, isize: 4, dsize: 4, compr: compr, data: []byte("data")})
	}
	volume := b.open(t)
	info := volume.Info()
	if info.Undecodable != 4 {
		t.Fatalf("undecodable = %d", info.Undecodable)
	}
	// The reference collects labels in a BTreeSet, which orders strings
	// lexicographically: "rtime" sorts before "rubinmips" (t < u).
	want := []string{"dynrubin", "none", "rtime", "rubinmips", "unknown"}
	if strings.Join(info.Compressors, ",") != strings.Join(want, ",") {
		t.Fatalf("compressors = %v", info.Compressors)
	}
	for index := 0; index < 4; index++ {
		path := "/c" + string(rune('0'+index))
		entry, err := volume.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if entry.HasAllocated {
			t.Fatalf("%s allocated = %+v", path, entry)
		}
		if _, err := volume.OpenFile(path); !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("OpenFile(%s) = %v", path, err)
		}
	}
}

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zlib.NewWriter(&out)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestZlibNode(t *testing.T) {
	text := []byte("the quick brown fox jumps over the lazy dog")
	stored := zlibBytes(t, text)
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("z.txt"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: uint32(len(text)), dsize: uint32(len(text)), compr: 6, data: stored})
	volume := b.open(t)
	file := mustOpen(t, volume, "/z.txt")
	if got := mustRead(t, file, 0, len(text)); !bytes.Equal(got, text) {
		t.Fatalf("read = %q", got)
	}
	if got := mustRead(t, file, 0, len(text)); !bytes.Equal(got, text) {
		t.Fatalf("cached read = %q", got)
	}
	entry, _ := volume.Stat("/z.txt")
	if entry.Allocated != uint64(len(stored)) {
		t.Fatalf("allocated = %d, want %d", entry.Allocated, len(stored))
	}
}

func TestBadZlibNodes(t *testing.T) {
	tests := []struct {
		name   string
		dsize  uint32
		stored []byte
	}{
		{"not zlib", 10, []byte("notzlib")},
		{"short output", 4, zlibBytes(t, []byte("abc"))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &jfBuilder{}
			b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
			b.pushDirent(1, 1, 2, []byte("bad.z"))
			b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: test.dsize, dsize: test.dsize, compr: 6, data: test.stored})
			volume := b.open(t)
			file := mustOpen(t, volume, "/bad.z")
			buf := make([]byte, test.dsize)
			if _, err := file.ReadAt(0, buf); !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("read error = %v", err)
			}
		})
	}
}

func lzoBlock(data []byte) []byte {
	period := 0
	for candidate := 1; candidate <= 238 && candidate <= len(data); candidate++ {
		if len(data)-candidate < 3 {
			continue
		}
		ok := true
		for at := candidate; at < len(data); at++ {
			if data[at] != data[at-candidate] {
				ok = false
				break
			}
		}
		if ok {
			period = candidate
			break
		}
	}
	var out []byte
	if period > 0 {
		out = append(out, lzoLiteral(data[:period])...)
		out = append(out, lzoM3(period, len(data)-period)...)
	} else {
		out = append(out, lzoLiteral(data)...)
	}
	return append(out, 0x11, 0x00, 0x00)
}

func lzoLiteral(data []byte) []byte {
	var out []byte
	if len(data) <= 238 {
		out = append(out, byte(len(data)+17))
	} else {
		out = append(out, 0)
		out = append(out, lzoExtension(len(data)-18)...)
	}
	return append(out, data...)
}

func lzoM3(distance, length int) []byte {
	var out []byte
	if length <= 33 {
		out = append(out, byte(0x20+length-2))
	} else {
		out = append(out, 0x20)
		out = append(out, lzoExtension(length-33)...)
	}
	half := uint16(distance-1) << 2
	return append(out, byte(half), byte(half>>8))
}

func lzoExtension(value int) []byte {
	zeros := value / 255
	term := value % 255
	if term == 0 {
		zeros--
		term = 255
	}
	out := make([]byte, zeros)
	return append(out, byte(term))
}

func TestLZONode(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"literal", []byte("hello, lzo world!")},
		{"periodic", bytes.Repeat([]byte("ABCD"), 64)},
		{"long literal", bytes.Repeat([]byte("0123456789abcdef"), 40)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stored := lzoBlock(test.data)
			b := &jfBuilder{}
			b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
			b.pushDirent(1, 1, 2, []byte("lzo.bin"))
			b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: uint32(len(test.data)), dsize: uint32(len(test.data)), compr: 7, data: stored})
			volume := b.open(t)
			if got := mustRead(t, mustOpen(t, volume, "/lzo.bin"), 0, len(test.data)); !bytes.Equal(got, test.data) {
				t.Fatalf("read = %q", got)
			}
		})
	}
}

func TestBadLZONode(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("bad.lzo"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 16, dsize: 16, compr: 7, data: []byte{0x11}})
	volume := b.open(t)
	file := mustOpen(t, volume, "/bad.lzo")
	if _, err := file.ReadAt(0, make([]byte, 16)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("read error = %v", err)
	}
}

func TestRootValidation(t *testing.T) {
	t.Run("not a directory", func(t *testing.T) {
		b := &jfBuilder{}
		b.pushInode(jfInode{ino: 1, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("x")})
		if _, err := Open(b.source()); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open = %v", err)
		}
	})
	t.Run("unknown mode", func(t *testing.T) {
		b := &jfBuilder{}
		b.pushInode(jfInode{ino: 1, version: 1, mode: 0})
		if _, err := Open(b.source()); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open = %v", err)
		}
	})
	t.Run("no inode node", func(t *testing.T) {
		b := &jfBuilder{}
		b.pushDirent(1, 1, 2, []byte("only.txt"))
		b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("x")})
		volume := b.open(t)
		root, err := volume.Stat("/")
		if err != nil {
			t.Fatal(err)
		}
		if root.Mode != 0 || root.Version != 0 || !root.Atime.IsZero() {
			t.Fatalf("root = %+v", root)
		}
		if _, err := volume.Stat("/only.txt"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSpecialNodes(t *testing.T) {
	modes := []uint32{0o010644, 0o020644, 0o060644, 0o140644}
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	for index, mode := range modes {
		ino := uint32(index + 2)
		b.pushDirent(1, 1, ino, []byte("sp"+string(rune('0'+index))))
		b.pushInode(jfInode{ino: ino, version: 1, mode: mode, isize: 99, dsize: 0})
	}
	volume := b.open(t)
	for index := range modes {
		path := "/sp" + string(rune('0'+index))
		entry, err := volume.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !entry.IsSpecial || entry.IsFile || entry.IsDir || entry.IsSymlink || entry.Size != 0 {
			t.Fatalf("%s = %+v", path, entry)
		}
		if _, err := volume.OpenFile(path); !errors.Is(err, ErrNotFile) {
			t.Fatalf("OpenFile(%s) = %v", path, err)
		}
	}
}

func TestPathErrorsAndEmptyFile(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("file"))
	b.pushDirent(1, 1, 3, []byte("empty"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("x")})
	b.pushInode(jfInode{ino: 3, version: 1, mode: jfFileMode})
	volume := b.open(t)

	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat missing = %v", err)
	}
	if _, err := volume.Stat("/file/child"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("Stat through file = %v", err)
	}
	if _, err := volume.ListDir("/file"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir file = %v", err)
	}
	if _, err := volume.ListDir("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListDir missing = %v", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenFile missing = %v", err)
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
	if _, err := volume.Stat("/../file"); err != nil {
		t.Fatalf("dotdot at root = %v", err)
	}
}

func TestReadPastEndAndLossy(t *testing.T) {
	volume := jfBasicBuilder().open(t)
	file := mustOpen(t, volume, "/keep.txt")
	if _, err := file.ReadAt(5, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read at EOF = %v", err)
	}
	buf := make([]byte, 16)
	n, err := file.ReadAtLossy(0, buf)
	if err != nil || n != 5 {
		t.Fatalf("lossy = %d, %v", n, err)
	}
	if _, err := file.ReadAtLossy(5, buf); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy at EOF = %v", err)
	}
	if _, err := file.Extents(6, 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extents at EOF = %v", err)
	}
	if file.(*Jffs2FileSource).SourceID() == 0 || file.ImageID() != volume.Source().ImageID() {
		t.Fatalf("source identity = %d/%d", file.SourceID(), file.ImageID())
	}
}

func TestScanAcrossChunkBoundary(t *testing.T) {
	data := bytes.Repeat([]byte("Z"), (1<<20)+4096)
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("big.bin"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: uint32(len(data)), dsize: uint32(len(data)), data: data})
	volume := b.open(t)
	file := mustOpen(t, volume, "/big.bin")
	if file.Len() != uint64(len(data)) {
		t.Fatalf("len = %d", file.Len())
	}
	got := make([]byte, 16)
	if _, err := file.ReadAt(uint64(len(data)-16), got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte("Z"), 16)) {
		t.Fatalf("tail = %q", got)
	}
}

func TestMaxLengthNameAndLossyUTF8(t *testing.T) {
	longName := bytes.Repeat([]byte{'n'}, 255)
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, longName)
	b.pushDirent(1, 1, 3, []byte{'b', 'a', 'd', 0xff, 'n', 'a', 'm', 'e'})
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("x")})
	b.pushInode(jfInode{ino: 3, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("y")})
	volume := b.open(t)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Name != "bad�name" {
		t.Fatalf("lossy name = %q", entries[0].Name)
	}
	if entries[1].Name != string(longName) {
		t.Fatalf("long name length = %d", len(entries[1].Name))
	}
}

func TestCleanmarkerOnlyImageDetectsFalseButOpens(t *testing.T) {
	b := &jfBuilder{}
	b.pushNode(nodeTypeCleanmarker, 12)
	if ok, err := Detect(b.source()); err != nil || ok {
		t.Fatalf("Detect(cleanmarker) = %v, %v", ok, err)
	}
	if _, err := Open(b.source()); err != nil {
		t.Fatalf("Open(cleanmarker) = %v", err)
	}
}

// symlinkTarget refuses an empty or oversized target and counts the name
// undecodable, as the reference's MAX_SYMLINK_BYTES branch does.
func TestSymlinkTargetLimits(t *testing.T) {
	tests := []struct {
		name   string
		target []byte
	}{
		{"empty", nil},
		{"oversized", bytes.Repeat([]byte("t"), int(maxSymlinkBytes)+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &jfBuilder{}
			b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
			b.pushDirent(1, 1, 2, []byte("link"))
			b.pushInode(jfInode{ino: 2, version: 1, mode: jfLinkMode,
				isize: uint32(len(test.target)), dsize: uint32(len(test.target)), data: test.target})
			volume := b.open(t)
			entry, err := volume.Stat("/link")
			if err != nil {
				t.Fatal(err)
			}
			if !entry.IsSymlink || entry.SymlinkTarget != "" {
				t.Fatalf("symlink = %+v", entry)
			}
			if info := volume.Info(); info.Undecodable != 1 {
				t.Fatalf("undecodable = %d", info.Undecodable)
			}
		})
	}
}

// Two dirents at the same version: the later scanned one wins, matching the
// reference's `dirent.version >= entry.version` replacement.
func TestDirentVersionTieUsesLaterNode(t *testing.T) {
	b := &jfBuilder{}
	b.pushInode(jfInode{ino: 1, version: 1, mode: jfDirMode})
	b.pushDirent(1, 1, 2, []byte("tie"))
	b.pushDirent(1, 1, 3, []byte("tie"))
	b.pushInode(jfInode{ino: 2, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("x")})
	b.pushInode(jfInode{ino: 3, version: 1, mode: jfFileMode, isize: 1, dsize: 1, data: []byte("y")})
	volume := b.open(t)

	entry, err := volume.Stat("/tie")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Inode != 3 {
		t.Fatalf("tie resolved to inode %d", entry.Inode)
	}
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %+v", entries)
	}
}

// Detect requires the node to fit inside the source, as the reference's
// detect check does; a header declaring a longer node is not proof of JFFS2.
func TestDetectRejectsNodePastImage(t *testing.T) {
	b := &jfBuilder{}
	b.pushRawHeader(nodeTypeInode, 4096)
	if ok, err := Detect(b.source()); err != nil || ok {
		t.Fatalf("Detect(short image) = %v, %v", ok, err)
	}
}
