package erofs

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- synthetic image builders -------------------------------------------

const (
	testBlock       = 4096
	testMagic       = 0xe0f5_e1e2
	testSuperOffset = 1024
	testSuperBytes  = 128

	testModeFile    = 0o100644
	testModeDir     = 0o040755
	testModeSymlink = 0o120777

	testCompatMtime     = 0x0000_0002
	testIncompatPadding = 0x0000_0001
	testIncompatCfgs    = 0x0000_0002
	testIncompatDevice  = 0x0000_0008

	testLayoutPlain    = 0
	testLayoutFull     = 1
	testLayoutInline   = 2
	testLayoutCompact  = 3
	testLayoutChunked  = 4
	testAdvise2B       = 0x0001
	testAdviseBig1     = 0x0002
	testAdviseInline   = 0x0008
	testAdviseInter    = 0x0010
	testAdviseFragment = 0x0020
	testAdviseExtents  = 0x0001
	testLiHole         = 1 << 14
	testLiCblkCount    = 1 << 11
	testTypePlain      = 0
	testTypeHead1      = 1
	testTypeNonhead    = 2
	testTypeHead2      = 3
	testAlgLZ4         = 0
	testAlgLZMA        = 1
	testAlgDeflate     = 2
	testAlgZstd        = 3
)

func putE16(b []byte, at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
func putE32(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
func putE64(b []byte, at int, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }

func eIloc(meta uint32, nid uint64) int {
	return int(meta)*testBlock + int(nid)<<5
}

type eEnt struct {
	name     string
	nid      uint64
	fileType uint8
}

// eListing writes a directory listing at at and returns its byte length.
func eListing(img []byte, at int, entries []eEnt) int {
	cursor := at + len(entries)*12
	for index, entry := range entries {
		dirent := at + index*12
		putE64(img, dirent, entry.nid)
		putE16(img, dirent+8, uint16(cursor-at))
		img[dirent+10] = entry.fileType
		copy(img[cursor:], entry.name)
		cursor += len(entry.name) + 1
	}
	return cursor - at
}

func eCompact(img []byte, at int, layout uint16, xattr uint16, mode uint16, size uint32, unit uint32, nid uint64, uid, gid uint16) {
	putE16(img, at, layout<<1)
	putE16(img, at+2, xattr)
	putE16(img, at+4, mode)
	putE16(img, at+6, 1)
	putE32(img, at+8, size)
	putE32(img, at+16, unit)
	putE32(img, at+20, uint32(nid))
	putE16(img, at+24, uid)
	putE16(img, at+26, gid)
}

func eExtended(img []byte, at int, layout uint16, mode uint16, size uint64, unit uint32, nid uint64, mtime uint64, nsec uint32) {
	putE16(img, at, 1|layout<<1)
	putE16(img, at+4, mode)
	putE64(img, at+8, size)
	putE32(img, at+16, unit)
	putE32(img, at+20, uint32(nid))
	putE32(img, at+24, 10_000)
	putE32(img, at+28, 10_001)
	putE64(img, at+32, mtime)
	putE32(img, at+40, nsec)
	putE32(img, at+44, 1)
}

func eSuperblock(img []byte, blocks, meta uint32, rootNID uint16, inos uint64, compat, incompat uint32, name string, available uint16) {
	base := testSuperOffset
	putE32(img, base, testMagic)
	putE32(img, base+8, compat)
	img[base+12] = 12
	putE16(img, base+14, rootNID)
	putE64(img, base+16, inos)
	putE64(img, base+24, 1_700_000_000)
	putE32(img, base+36, blocks)
	putE32(img, base+40, meta)
	putE32(img, base+44, 0)
	for i := 0; i < 16; i++ {
		img[base+48+i] = byte(i + 1)
	}
	copy(img[base+64:base+80], name)
	putE32(img, base+80, incompat)
	putE16(img, base+84, available)
}

func ePattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i%26)
	}
	return out
}

func eDeflate(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

type eBasic struct {
	img     []byte
	hello   []byte
	zh      []byte
	inline  []byte
	rootLen int
}

const (
	nidRoot     = 36
	nidHello    = 100
	nidLink     = 102
	nidEmpty    = 104
	nidHole     = 106
	nidInline   = 108
	nidDir      = 112
	nidZH       = 114
	nidEmptyDir = 116
)

func buildBasic(t *testing.T) eBasic {
	t.Helper()
	const blocks = 6
	img := make([]byte, blocks*testBlock)
	eSuperblock(img, blocks, 0, nidRoot, 8, testCompatMtime, testIncompatPadding, "FORENSIC-EROFS", 0)

	hello := ePattern(5000, 'a')
	zh := append([]byte("说明.txt 的内容"), make([]byte, 100-len("说明.txt 的内容"))...)
	inlineText := []byte("inline body\n")

	rootAt := eIloc(0, nidRoot) + 32
	rootLen := eListing(img, rootAt, []eEnt{
		{"dir", nidDir, 2},
		{"empty.txt", nidEmpty, 1},
		{"hello.txt", nidHello, 1},
		{"hole.dat", nidHole, 1},
		{"inline.txt", nidInline, 1},
		{"link", nidLink, 7},
		{"emptydir", nidEmptyDir, 2},
	})
	eCompact(img, eIloc(0, nidRoot), testLayoutInline, 0, testModeDir, uint32(rootLen), 0, nidRoot, 0, 0)

	eCompact(img, eIloc(0, nidHello), testLayoutPlain, 0, testModeFile, uint32(len(hello)), 1, nidHello, 1000, 1000)
	copy(img[testBlock:], hello)

	linkAt := eIloc(0, nidLink)
	copy(img[linkAt+32:], "hello.txt")
	eCompact(img, linkAt, testLayoutInline, 0, testModeSymlink, 9, 0, nidLink, 1000, 1000)

	eCompact(img, eIloc(0, nidEmpty), testLayoutPlain, 0, testModeFile, 0, 0, nidEmpty, 1000, 1000)
	eCompact(img, eIloc(0, nidHole), testLayoutPlain, 0, testModeFile, 3000, 0, nidHole, 1000, 1000)

	inlineAt := eIloc(0, nidInline)
	for i := inlineAt + 32; i < inlineAt+48; i++ {
		img[i] = 0xAB
	}
	copy(img[inlineAt+48:], inlineText)
	eCompact(img, inlineAt, testLayoutInline, 2, testModeFile, uint32(len(inlineText)), 0, nidInline, 1000, 1000)

	dirAt := eIloc(0, nidDir) + 32
	dirLen := eListing(img, dirAt, []eEnt{{"说明.txt", nidZH, 1}})
	eCompact(img, eIloc(0, nidDir), testLayoutInline, 0, testModeDir, uint32(dirLen), 0, nidDir, 1000, 1000)

	eCompact(img, eIloc(0, nidEmptyDir), testLayoutInline, 0, testModeDir, 0, 0, nidEmptyDir, 1000, 1000)

	eExtended(img, eIloc(0, nidZH), testLayoutPlain, testModeFile, uint64(len(zh)), 3, nidZH, 1_700_000_900, 123_456_789)
	copy(img[3*testBlock:], zh)

	return eBasic{img: img, hello: hello, zh: zh, inline: inlineText, rootLen: rootLen}
}

func openErofs(t *testing.T, img []byte) *Volume {
	t.Helper()
	vol, err := Open(source.NewMemorySource(1, img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return vol
}

// ---- detection, superblock and walk -------------------------------------

func TestDetect(t *testing.T) {
	basic := buildBasic(t)
	ok, err := Detect(source.NewMemorySource(1, basic.img))
	if err != nil || !ok {
		t.Fatalf("Detect(valid) = %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, make([]byte, 8192)))
	if err != nil || ok {
		t.Errorf("Detect(zeroes) = %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, nil))
	if err != nil || ok {
		t.Errorf("Detect(empty) = %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, make([]byte, 1025)))
	if err != nil || ok {
		t.Errorf("Detect(short) = %v, %v", ok, err)
	}
}

func TestInfoAndWalk(t *testing.T) {
	basic := buildBasic(t)
	vol := openErofs(t, basic.img)

	info := vol.Info()
	if info.Type != "EROFS" || info.Version != "1.0" {
		t.Errorf("type/version = %q/%q", info.Type, info.Version)
	}
	if info.BlockSize != testBlock || info.BlockBits != 12 {
		t.Errorf("block size = %d/%d", info.BlockSize, info.BlockBits)
	}
	if info.Blocks != 6 || info.Inodes != 8 || info.RootNID != nidRoot {
		t.Errorf("blocks/inodes/root = %d/%d/%d", info.Blocks, info.Inodes, info.RootNID)
	}
	if info.VolumeName != "FORENSIC-EROFS" || !info.UUIDPresent {
		t.Errorf("name/uuid = %q/%v", info.VolumeName, info.UUIDPresent)
	}
	if info.UUID != "01020304-0506-0708-090a-0b0c0d0e0f10" {
		t.Errorf("uuid = %q", info.UUID)
	}
	if !info.HasMtime || info.BuildTimeSeconds != 1_700_000_000 {
		t.Errorf("mtime/build = %v/%d", info.HasMtime, info.BuildTimeSeconds)
	}
	if !info.BuildTime.Equal(time.Unix(1_700_000_000, 0).UTC()) {
		t.Errorf("build time = %v", info.BuildTime)
	}
	if info.Entries != 9 {
		t.Errorf("entries = %d", info.Entries)
	}
	if info.Unreadable != 0 || info.Undecodable != 0 {
		t.Errorf("counters = %d/%d", info.Unreadable, info.Undecodable)
	}
	if len(info.IncompatNames) != 1 || info.IncompatNames[0] != "zero_padding" {
		t.Errorf("incompat names = %v", info.IncompatNames)
	}

	root, err := vol.Stat("/")
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !root.IsDir || root.Name != "/" || root.Path != "/" || root.Mode != testModeDir {
		t.Errorf("root = %+v", root)
	}
	if root.Inode != nidRoot {
		t.Errorf("root inode = %d", root.Inode)
	}

	entries, err := vol.ListDir("")
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	want := []string{"dir", "empty.txt", "hello.txt", "hole.dat", "inline.txt", "link", "emptydir"}
	if len(entries) != len(want) {
		t.Fatalf("entries = %d", len(entries))
	}
	for i, name := range want {
		if entries[i].Name != name {
			t.Errorf("entry %d = %q, want %q", i, entries[i].Name, name)
		}
	}
	if entries[2].Path != "/hello.txt" || entries[2].Inode != nidHello || !entries[2].IsFile {
		t.Errorf("hello entry = %+v", entries[2])
	}
	if !entries[0].IsDir {
		t.Errorf("dir entry = %+v", entries[0])
	}

	nested, err := vol.ListDir("/dir")
	if err != nil || len(nested) != 1 || nested[0].Name != "说明.txt" || nested[0].Path != "/dir/说明.txt" {
		t.Errorf("nested listing = %+v, %v", nested, err)
	}
	if empty, err := vol.ListDir("/dir"); err != nil || len(empty) != 1 {
		t.Errorf("nested list length = %d, %v", len(empty), err)
	}
	if empty, err := vol.ListDir("/emptydir"); err != nil || len(empty) != 0 {
		t.Errorf("empty directory listing = %+v, %v", empty, err)
	}
	if empty, err := vol.ListDir("/empty.txt/"); err == nil {
		t.Errorf("listing a file should fail: %+v", empty)
	}

	if _, err := vol.Stat("/missing"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing stat = %v", err)
	}
	if _, err := vol.ListDir("/missing"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing list = %v", err)
	}
	if _, err := vol.ListDir("/hello.txt"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("list file = %v", err)
	}
	if _, err := vol.OpenFile("/dir"); !errors.Is(err, ErrNotAFile) {
		t.Errorf("open dir = %v", err)
	}
}

// ---- uncompressed data ---------------------------------------------------

func TestPlainFileReads(t *testing.T) {
	basic := buildBasic(t)
	vol := openErofs(t, basic.img)

	hello, err := vol.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if hello.Size != 5000 || hello.UID != 1000 || !hello.AllocatedKnown {
		t.Errorf("hello = %+v", hello)
	}
	if hello.Allocated != 8192 {
		t.Errorf("allocated = %d, want 8192 (the last block counts whole)", hello.Allocated)
	}

	file, err := vol.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	all := make([]byte, 5000)
	if err := source.ReadExactAt(file, 0, all); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(all, basic.hello) {
		t.Errorf("hello content mismatch")
	}
	// A read that stays inside the stored run but is bounded by the length.
	part := make([]byte, 50)
	if err := source.ReadExactAt(file, 4950, part); err != nil {
		t.Fatalf("tail read: %v", err)
	}
	if !bytes.Equal(part, basic.hello[4950:]) {
		t.Errorf("tail read mismatch")
	}
	if _, err := file.ReadAt(5000, make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("past end = %v", err)
	}

	ranges, err := file.Extents(0, 5000)
	if err != nil || len(ranges) != 1 {
		t.Fatalf("extents = %+v, %v", ranges, err)
	}
	if ranges[0].Kind != source.RangeData || ranges[0].ParentOffset != testBlock || ranges[0].Len != 5000 {
		t.Errorf("extent = %+v", ranges[0])
	}
	mapped, err := file.MapToImage(100, 50)
	if err != nil || len(mapped) != 1 || mapped[0].ImageOffset != testBlock+100 {
		t.Errorf("mapped = %+v, %v", mapped, err)
	}

	// A zero-length file has no stream and refuses a read.
	empty, err := vol.OpenFile("/empty.txt")
	if err != nil {
		t.Fatalf("open empty: %v", err)
	}
	if empty.Len() != 0 || !empty.IsEmpty() {
		t.Errorf("empty file = len %d", empty.Len())
	}
	if _, err := empty.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("empty read = %v", err)
	}
}

func TestHoleAndInlineData(t *testing.T) {
	basic := buildBasic(t)
	vol := openErofs(t, basic.img)

	hole, err := vol.Stat("/hole.dat")
	if err != nil {
		t.Fatalf("stat hole: %v", err)
	}
	if hole.Size != 3000 || !hole.AllocatedKnown || hole.Allocated != 0 {
		t.Errorf("hole = %+v", hole)
	}
	file, err := vol.OpenFile("/hole.dat")
	if err != nil {
		t.Fatalf("open hole: %v", err)
	}
	if impl, ok := file.(*fileSource); !ok || !impl.isHole() {
		t.Errorf("hole.dat should report as a hole")
	}
	buf := make([]byte, 3000)
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatalf("read hole: %v", err)
	}
	if !bytes.Equal(buf, make([]byte, 3000)) {
		t.Errorf("hole is not zeroes")
	}
	ranges, err := file.Extents(0, 3000)
	if err != nil || len(ranges) != 1 || ranges[0].Kind != source.RangeZero || ranges[0].Len != 3000 {
		t.Errorf("hole extent = %+v, %v", ranges, err)
	}

	inline, err := vol.Stat("/inline.txt")
	if err != nil {
		t.Fatalf("stat inline: %v", err)
	}
	if inline.Size != uint64(len(basic.inline)) || inline.Allocated != uint64(len(basic.inline)) {
		t.Errorf("inline = %+v", inline)
	}
	stream, err := vol.OpenFile("/inline.txt")
	if err != nil {
		t.Fatalf("open inline: %v", err)
	}
	got := make([]byte, len(basic.inline))
	if err := source.ReadExactAt(stream, 0, got); err != nil {
		t.Fatalf("read inline: %v", err)
	}
	if !bytes.Equal(got, basic.inline) {
		t.Errorf("inline content = %q", got)
	}
	// Two xattr slots are 12 + 4 bytes, so the data starts 48 bytes past the
	// inode's 32-byte-aligned slot.
	wantStart := uint64(eIloc(0, nidInline) + 32 + 16)
	ranges, err = stream.Extents(0, uint64(len(basic.inline)))
	if err != nil || len(ranges) != 1 || ranges[0].ParentOffset != wantStart {
		t.Errorf("inline extent = %+v, %v (want start %d)", ranges, err, wantStart)
	}
}

func TestSymlinkAndExtendedInode(t *testing.T) {
	basic := buildBasic(t)
	vol := openErofs(t, basic.img)

	link, err := vol.Stat("/link")
	if err != nil {
		t.Fatalf("stat link: %v", err)
	}
	if !link.IsSymlink || link.SymlinkTarget != "hello.txt" || link.Size != 9 {
		t.Errorf("link = %+v", link)
	}
	target, err := vol.OpenSymlink("/link")
	if err != nil {
		t.Fatalf("open symlink: %v", err)
	}
	got := make([]byte, 9)
	if err := source.ReadExactAt(target, 0, got); err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "hello.txt" {
		t.Errorf("target = %q", got)
	}
	if _, err := vol.OpenSymlink("/hello.txt"); !errors.Is(err, ErrNotASymlink) {
		t.Errorf("open non-symlink = %v", err)
	}

	note, err := vol.Stat("/dir/说明.txt")
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	if note.Size != 100 || note.UID != 10_000 || note.GID != 10_001 {
		t.Errorf("note = %+v", note)
	}
	if !note.HasModified || !note.Modified.Equal(time.Unix(1_700_000_900, 123_456_789).UTC()) {
		t.Errorf("note modified = %v", note.Modified)
	}
	if !note.Changed.Equal(note.Modified) {
		t.Errorf("change time should equal the one stored time")
	}
	file, err := vol.OpenFile("/dir/说明.txt")
	if err != nil {
		t.Fatalf("open note: %v", err)
	}
	buf := make([]byte, 100)
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatalf("read note: %v", err)
	}
	if !bytes.Equal(buf, basic.zh) {
		t.Errorf("note content mismatch")
	}
}

// ---- refusals and corruption --------------------------------------------

func TestChunkBasedInodeIsListedButRefused(t *testing.T) {
	basic := buildBasic(t)
	putE16(basic.img, eIloc(0, nidInline), testLayoutChunked<<1)
	vol := openErofs(t, basic.img)
	if vol.Info().Undecodable != 1 {
		t.Errorf("undecodable = %d", vol.Info().Undecodable)
	}
	entry, err := vol.Stat("/inline.txt")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if entry.AllocatedKnown {
		t.Errorf("chunk-based inode must not claim an allocation")
	}
	if _, err := vol.OpenFile("/inline.txt"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("open chunk-based = %v", err)
	}
}

func TestSuperblockRefusals(t *testing.T) {
	basic := buildBasic(t)

	badMagic := append([]byte{}, basic.img...)
	badMagic[testSuperOffset] = 0
	if _, err := Open(source.NewMemorySource(1, badMagic)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("bad magic = %v", err)
	}

	device := append([]byte{}, basic.img...)
	putE32(device, testSuperOffset+80, testIncompatDevice)
	if _, err := Open(source.NewMemorySource(1, device)); !errors.Is(err, ErrUnsupported) ||
		!strings.Contains(err.Error(), "multi-device") {
		t.Errorf("device table = %v", err)
	}

	unknown := append([]byte{}, basic.img...)
	putE32(unknown, testSuperOffset+80, 0x80)
	if _, err := Open(source.NewMemorySource(1, unknown)); !errors.Is(err, ErrUnsupported) ||
		!strings.Contains(err.Error(), "0x0000000080") {
		t.Errorf("unknown incompat = %v", err)
	}

	for _, bits := range []byte{8, 17} {
		badBits := append([]byte{}, basic.img...)
		badBits[testSuperOffset+12] = bits
		if _, err := Open(source.NewMemorySource(1, badBits)); !errors.Is(err, ErrCorrupt) {
			t.Errorf("block bits %d = %v", bits, err)
		}
	}

	noBlocks := append([]byte{}, basic.img...)
	putE32(noBlocks, testSuperOffset+36, 0)
	if _, err := Open(source.NewMemorySource(1, noBlocks)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("no blocks = %v", err)
	}

	tooWide := append([]byte{}, basic.img...)
	putE32(tooWide, testSuperOffset+36, 100)
	if _, err := Open(source.NewMemorySource(1, tooWide)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("declared past source = %v", err)
	}

	metaPast := append([]byte{}, basic.img...)
	putE32(metaPast, testSuperOffset+40, 6)
	if _, err := Open(source.NewMemorySource(1, metaPast)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("meta past blocks = %v", err)
	}

	rootZero := append([]byte{}, basic.img...)
	putE16(rootZero, testSuperOffset+14, 0)
	if _, err := Open(source.NewMemorySource(1, rootZero)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("root nid zero = %v", err)
	}

	xattrPast := append([]byte{}, basic.img...)
	putE32(xattrPast, testSuperOffset+44, 6)
	if _, err := Open(source.NewMemorySource(1, xattrPast)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("xattr area past blocks = %v", err)
	}

	if _, err := Open(source.NewMemorySource(1, basic.img[:1000])); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short source = %v", err)
	}

	notDir := append([]byte{}, basic.img...)
	putE16(notDir, eIloc(0, nidRoot)+4, testModeFile)
	if _, err := Open(source.NewMemorySource(1, notDir)); !errors.Is(err, ErrCorrupt) ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Errorf("non-directory root = %v", err)
	}
}

func TestUnreadableDirectoryIsCounted(t *testing.T) {
	basic := buildBasic(t)
	// Point the root's first dirent name inside the dirent array.
	rootAt := eIloc(0, nidRoot) + 32
	putE16(basic.img, rootAt+8, 4)
	vol := openErofs(t, basic.img)
	if vol.Info().Unreadable != 1 {
		t.Errorf("unreadable = %d", vol.Info().Unreadable)
	}
	if vol.Info().Entries != 1 {
		t.Errorf("entries = %d, want only the root", vol.Info().Entries)
	}
}

func TestParseInode(t *testing.T) {
	compact := make([]byte, 32)
	putE16(compact, 0, testLayoutPlain<<1)
	putE16(compact, 4, testModeFile)
	putE16(compact, 6, 1)
	putE32(compact, 8, 5000)
	putE32(compact, 16, 3)
	putE32(compact, 20, 7)
	putE16(compact, 24, 1000)
	putE16(compact, 26, 27)

	in, err := parseInode(compact, false)
	if err != nil {
		t.Fatalf("parse compact: %v", err)
	}
	if in.version != 0 || in.layout != layoutFlatPlain || in.kind != kindFile ||
		in.size != 5000 || in.unit != 3 || in.ino != 7 ||
		in.uid != 1000 || in.gid != 27 || in.headerBytes() != 32 || in.mtimeValid {
		t.Errorf("compact inode = %+v", in)
	}

	extended := make([]byte, 64)
	putE16(extended, 0, 1)
	putE16(extended, 4, testModeFile)
	putE64(extended, 8, 123_456_789)
	putE32(extended, 16, 9)
	putE32(extended, 20, 7)
	putE32(extended, 24, 100_000)
	putE32(extended, 28, 100_001)
	putE64(extended, 32, 1_700_000_100)
	putE32(extended, 40, 123_456_789)
	putE32(extended, 44, 2)
	in, err = parseInode(extended, true)
	if err != nil {
		t.Fatalf("parse extended: %v", err)
	}
	if in.headerBytes() != 64 || in.size != 123_456_789 || in.uid != 100_000 ||
		in.gid != 100_001 || in.nlink != 2 || !in.mtimeValid ||
		in.mtimeSec != 1_700_000_100 || in.mtimeNsec != 123_456_789 {
		t.Errorf("extended inode = %+v", in)
	}
	// Without the superblock's feature the time is not evidence.
	if noTime, err := parseInode(extended, false); err != nil || noTime.mtimeValid {
		t.Errorf("mtime without feature = %+v, %v", noTime, err)
	}
	// A zero second is unset, not 1970.
	putE64(extended, 32, 0)
	if zeroTime, err := parseInode(extended, true); err != nil || zeroTime.mtimeValid {
		t.Errorf("zero mtime = %+v, %v", zeroTime, err)
	}

	// Two xattr slots occupy 12 + 4 bytes.
	withXattr := append([]byte{}, compact...)
	putE16(withXattr, 2, 2)
	if in, err := parseInode(withXattr, false); err != nil || in.xattrBytes != 16 || in.headerBytes() != 48 {
		t.Errorf("xattr inode = %+v, %v", in, err)
	}

	badFormat := append([]byte{}, compact...)
	putE16(badFormat, 0, 0x0010)
	if _, err := parseInode(badFormat, false); !errors.Is(err, ErrUnsupported) {
		t.Errorf("format bits = %v", err)
	}
	unknownMode := append([]byte{}, compact...)
	putE16(unknownMode, 4, 0o150000)
	if _, err := parseInode(unknownMode, false); !errors.Is(err, ErrCorrupt) {
		t.Errorf("unknown mode = %v", err)
	}
	badLayout := append([]byte{}, compact...)
	putE16(badLayout, 0, 7<<1)
	if _, err := parseInode(badLayout, false); !errors.Is(err, ErrUnsupported) {
		t.Errorf("layout 7 = %v", err)
	}
	if _, err := parseInode(compact[:31], false); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short compact = %v", err)
	}
	if _, err := parseInode(extended[:63], true); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short extended = %v", err)
	}
}

func TestParseDirectoryBlock(t *testing.T) {
	block := func(entries []eEnt) []byte {
		namesStart := len(entries) * 12
		out := make([]byte, namesStart)
		cursor := namesStart
		for i, entry := range entries {
			putE64(out, i*12, entry.nid)
			putE16(out, i*12+8, uint16(cursor))
			out[i*12+10] = entry.fileType
			out = append(out, entry.name...)
			out = append(out, 0)
			cursor += len(entry.name) + 1
		}
		return out
	}

	payload := block([]eEnt{{"a", 5, 1}, {"dir", 45, 2}, {"link", 41, 7}})
	entries, err := parseDirBlock(payload, len(payload))
	if err != nil || len(entries) != 3 {
		t.Fatalf("parse = %+v, %v", entries, err)
	}
	if entries[0].name != "a" || entries[1].nid != 45 || entries[2].fileType != 7 {
		t.Errorf("entries = %+v", entries)
	}

	padded := append(append([]byte{}, payload...), make([]byte, 100)...)
	entries, err = parseDirBlock(padded, len(payload))
	if err != nil || entries[2].name != "link" {
		t.Errorf("padded parse = %+v, %v", entries, err)
	}

	// The final name may end exactly at the block's meaningful end.
	unterminated := block([]eEnt{{"abc", 5, 1}})
	unterminated = unterminated[:len(unterminated)-1]
	if entries, err := parseDirBlock(unterminated, len(unterminated)); err != nil || entries[0].name != "abc" {
		t.Errorf("unterminated = %+v, %v", entries, err)
	}

	if entries, err := parseDirBlock(payload, 0); err != nil || len(entries) != 0 {
		t.Errorf("empty max = %+v, %v", entries, err)
	}
	if _, err := parseDirBlock(payload, len(payload)+1); !errors.Is(err, ErrCorrupt) {
		t.Errorf("max past bytes = %v", err)
	}
	if _, err := parseDirBlock(payload[:8], 8); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short block = %v", err)
	}

	inside := append([]byte{}, payload...)
	putE16(inside, 12+8, 8)
	if _, err := parseDirBlock(inside, len(inside)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("name inside array = %v", err)
	}
	zeroNID := block([]eEnt{{"x", 0, 1}})
	if _, err := parseDirBlock(zeroNID, len(zeroNID)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("zero nid = %v", err)
	}
	badType := block([]eEnt{{"x", 5, 8}})
	if _, err := parseDirBlock(badType, len(badType)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("bad type = %v", err)
	}
	emptyName := make([]byte, 12)
	putE64(emptyName, 0, 5)
	putE16(emptyName, 8, 12)
	putE16(emptyName, 10, 0)
	if _, err := parseDirBlock(emptyName, len(emptyName)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("empty name = %v", err)
	}
}

// ---- compressed inodes ---------------------------------------------------

const (
	cMetaBlock = 20
	cBlocks    = 24

	cnFull    = 33
	cnCompact = 65
	cnHead2   = 97
	cnPlain   = 129
	cnHole    = 161
	cnLZ4     = 193
	cnLZMA    = 225
	cnZSTD    = 257
	cnBig     = 289
)

func cIloc(nid uint64) int { return eIloc(cMetaBlock, nid) }

func putMapHeader(img []byte, nid uint64, advise uint16, algByte, clusterBits byte) {
	at := cIloc(nid) + 32
	putE16(img, at+4, advise)
	img[at+6] = algByte
	img[at+7] = clusterBits
}

func putFullHead(img []byte, nid uint64, index int, kind, extra, clusterofs uint16, pblk uint32) {
	at := cIloc(nid) + 48 + index*8
	putE16(img, at, kind|extra)
	putE16(img, at+2, clusterofs)
	putE32(img, at+4, pblk)
}

func putFullNonhead(img []byte, nid uint64, index int, delta0, delta1 uint16) {
	at := cIloc(nid) + 48 + index*8
	putE16(img, at, testTypeNonhead)
	putE16(img, at+4, delta0)
	putE16(img, at+6, delta1)
}

func compactWord(lo uint16, kind uint16) uint32 {
	return uint32(lo) | uint32(kind)<<12
}

func storeBlock(img []byte, block int, payload []byte) {
	copy(img[block*testBlock:], payload)
}

type eCompressed struct {
	img     []byte
	full    []byte
	compact []byte
	head2   []byte
	plain   []byte
	big     []byte
}

func buildCompressed(t *testing.T) eCompressed {
	t.Helper()
	img := make([]byte, cBlocks*testBlock)
	eSuperblock(img, cBlocks, cMetaBlock, 1, 9, 0, testIncompatCfgs, "EROFS-COMPRESSED", 0x000f)

	names := []eEnt{
		{"big.bin", cnBig, 1},
		{"compact.bin", cnCompact, 1},
		{"deflate.bin", cnFull, 1},
		{"head2.bin", cnHead2, 1},
		{"hole.bin", cnHole, 1},
		{"lz4.bin", cnLZ4, 1},
		{"lzma.bin", cnLZMA, 1},
		{"plain.bin", cnPlain, 1},
		{"zstd.bin", cnZSTD, 1},
	}
	rootAt := cIloc(1) + 32
	rootLen := eListing(img, rootAt, names)
	eCompact(img, cIloc(1), testLayoutInline, 0, testModeDir, uint32(rootLen), 0, 1, 0, 0)

	full := ePattern(9000, 'F')
	compact := ePattern(9000, 'C')
	head2 := ePattern(4096, 'H')
	plain := ePattern(4096, 'P')
	big := ePattern(8192, 'G')

	storeBlock(img, 1, eDeflate(t, full[:8192]))
	storeBlock(img, 2, eDeflate(t, full[8192:]))
	storeBlock(img, 3, eDeflate(t, compact[:8192]))
	storeBlock(img, 4, eDeflate(t, compact[8192:]))
	storeBlock(img, 5, eDeflate(t, head2))
	storeBlock(img, 6, plain)
	storeBlock(img, 7, append(eDeflate(t, big), make([]byte, 4096)...))
	// Blocks 9..11 are named by the algorithms this reader refuses; their
	// contents are never decoded.

	// deflate.bin: full index, HEAD1 + NONHEAD + HEAD1.
	eCompact(img, cIloc(cnFull), testLayoutFull, 0, testModeFile, 9000, 1, cnFull, 1000, 1000)
	putMapHeader(img, cnFull, 0, testAlgDeflate|testAlgLZ4<<4, 0)
	putFullHead(img, cnFull, 0, testTypeHead1, 0, 0, 1)
	putFullNonhead(img, cnFull, 1, 1, 1)
	putFullHead(img, cnFull, 2, testTypeHead1, 0, 0, 2)

	// compact.bin: the same shape under the compact encoding.
	eCompact(img, cIloc(cnCompact), testLayoutCompact, 0, testModeFile, 9000, 1, cnCompact, 1000, 1000)
	putMapHeader(img, cnCompact, 0, testAlgDeflate|testAlgLZ4<<4, 0)
	ebase := cIloc(cnCompact) + 40
	putE32(img, ebase, compactWord(0, testTypeHead1)|compactWord(1, testTypeNonhead)<<16)
	putE32(img, ebase+4, 2) // first pcluster lives in block base+1 = 3
	putE32(img, ebase+8, compactWord(0, testTypeHead1))
	putE32(img, ebase+12, 3) // second pcluster in block 4

	// head2.bin: HEAD2 with DEFLATE in the high nibble.
	eCompact(img, cIloc(cnHead2), testLayoutFull, 0, testModeFile, 4096, 1, cnHead2, 1000, 1000)
	putMapHeader(img, cnHead2, 0, testAlgLZ4|testAlgDeflate<<4, 0)
	putFullHead(img, cnHead2, 0, testTypeHead2, 0, 0, 5)

	// plain.bin: a shifted pcluster stored verbatim.
	eCompact(img, cIloc(cnPlain), testLayoutFull, 0, testModeFile, 4096, 1, cnPlain, 1000, 1000)
	putMapHeader(img, cnPlain, 0, testAlgLZ4, 0)
	putFullHead(img, cnPlain, 0, testTypePlain, 0, 0, 6)

	// hole.bin: a PLAIN head with the hole bit and no stored block.
	eCompact(img, cIloc(cnHole), testLayoutFull, 0, testModeFile, 4096, 0, cnHole, 1000, 1000)
	putMapHeader(img, cnHole, 0, testAlgLZ4, 0)
	putFullHead(img, cnHole, 0, testTypePlain, testLiHole, 0, 0)

	// One single-pcluster file per algorithm this reader refuses.
	for _, spec := range []struct {
		nid  uint64
		alg  byte
		head uint16
		pblk uint32
	}{
		{cnLZ4, testAlgLZ4, testTypeHead1, 9},
		{cnLZMA, testAlgLZMA, testTypeHead1, 10},
		{cnZSTD, testAlgLZ4 | testAlgZstd<<4, testTypeHead2, 11},
	} {
		eCompact(img, cIloc(spec.nid), testLayoutFull, 0, testModeFile, 4096, 1, spec.nid, 1000, 1000)
		putMapHeader(img, spec.nid, 0, spec.alg, 0)
		putFullHead(img, spec.nid, 0, spec.head, 0, 0, spec.pblk)
	}

	// big.bin: one 8192-byte pcluster stored in two blocks, the count carried
	// by the first continuation's delta[0].
	eCompact(img, cIloc(cnBig), testLayoutFull, 0, testModeFile, 8192, 1, cnBig, 1000, 1000)
	putMapHeader(img, cnBig, testAdviseBig1, testAlgDeflate, 0)
	putFullHead(img, cnBig, 0, testTypeHead1, 0, 0, 7)
	putFullNonhead(img, cnBig, 1, testLiCblkCount|2, 1)

	return eCompressed{img: img, full: full, compact: compact, head2: head2, plain: plain, big: big}
}

func TestCompressedReads(t *testing.T) {
	fixture := buildCompressed(t)
	vol := openErofs(t, fixture.img)
	if vol.Info().Entries != 10 {
		t.Fatalf("entries = %d", vol.Info().Entries)
	}
	if vol.Info().Undecodable != 0 || vol.Info().Unreadable != 0 {
		t.Errorf("counters = %d/%d", vol.Info().Undecodable, vol.Info().Unreadable)
	}

	for _, tc := range []struct {
		path    string
		content []byte
		extents []uint64
	}{
		{"/deflate.bin", fixture.full, []uint64{testBlock, 2 * testBlock}},
		{"/compact.bin", fixture.compact, []uint64{3 * testBlock, 4 * testBlock}},
		{"/head2.bin", fixture.head2, []uint64{5 * testBlock}},
		{"/plain.bin", fixture.plain, []uint64{6 * testBlock}},
		{"/big.bin", fixture.big, []uint64{7 * testBlock}},
	} {
		entry, err := vol.Stat(tc.path)
		if err != nil {
			t.Fatalf("stat %s: %v", tc.path, err)
		}
		if entry.Size != uint64(len(tc.content)) {
			t.Errorf("%s size = %d", tc.path, entry.Size)
		}
		if !entry.AllocatedKnown {
			t.Errorf("%s allocation unknown", tc.path)
		}
		file, err := vol.OpenFile(tc.path)
		if err != nil {
			t.Fatalf("open %s: %v", tc.path, err)
		}
		buf := make([]byte, len(tc.content))
		if err := source.ReadExactAt(file, 0, buf); err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		if !bytes.Equal(buf, tc.content) {
			t.Errorf("%s content mismatch", tc.path)
		}
		// Crossing the boundary between two decoded pclusters.
		if len(tc.content) > 8400 {
			cross := make([]byte, 400)
			if err := source.ReadExactAt(file, 8000, cross); err != nil {
				t.Fatalf("cross %s: %v", tc.path, err)
			}
			if !bytes.Equal(cross, tc.content[8000:8400]) {
				t.Errorf("%s cross-boundary read mismatch", tc.path)
			}
		}
		ranges, err := file.Extents(0, uint64(len(tc.content)))
		if err != nil {
			t.Fatalf("extents %s: %v", tc.path, err)
		}
		if len(ranges) != len(tc.extents) {
			t.Fatalf("%s extents = %d, want %d", tc.path, len(ranges), len(tc.extents))
		}
		for i, want := range tc.extents {
			if ranges[i].Kind != source.RangeData || ranges[i].ParentOffset != want {
				t.Errorf("%s extent %d = %+v, want offset %d", tc.path, i, ranges[i], want)
			}
		}
	}

	// The 808-byte tail is one pcluster.
	file, err := vol.OpenFile("/deflate.bin")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	tail := make([]byte, 808)
	if err := source.ReadExactAt(file, 8192, tail); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if !bytes.Equal(tail, fixture.full[8192:]) {
		t.Errorf("tail mismatch")
	}
	if _, err := file.ReadAt(9000, make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("past end = %v", err)
	}

	// The hole pcluster reads as zeroes and reports a zero range.
	hole, err := vol.Stat("/hole.bin")
	if err != nil {
		t.Fatalf("stat hole: %v", err)
	}
	if !hole.AllocatedKnown || hole.Allocated != 0 {
		t.Errorf("hole allocation = %+v", hole)
	}
	holeFile, err := vol.OpenFile("/hole.bin")
	if err != nil {
		t.Fatalf("open hole: %v", err)
	}
	zeros := make([]byte, 4096)
	if err := source.ReadExactAt(holeFile, 0, zeros); err != nil {
		t.Fatalf("read hole: %v", err)
	}
	if !bytes.Equal(zeros, make([]byte, 4096)) {
		t.Errorf("hole is not zeroes")
	}
	ranges, err := holeFile.Extents(0, 4096)
	if err != nil || len(ranges) != 1 || ranges[0].Kind != source.RangeZero {
		t.Errorf("hole extents = %+v, %v", ranges, err)
	}
}

func TestUnsupportedCompressionAlgorithms(t *testing.T) {
	fixture := buildCompressed(t)
	vol := openErofs(t, fixture.img)
	for _, tc := range []struct {
		path string
		name string
	}{
		{"/lz4.bin", "LZ4"},
		{"/lzma.bin", "LZMA"},
		{"/zstd.bin", "Zstandard"},
	} {
		entry, err := vol.Stat(tc.path)
		if err != nil {
			t.Fatalf("stat %s: %v", tc.path, err)
		}
		if !entry.AllocatedKnown || entry.Allocated != 4096 {
			t.Errorf("%s allocation = %+v", tc.path, entry)
		}
		file, err := vol.OpenFile(tc.path)
		if err != nil {
			t.Fatalf("open %s: %v", tc.path, err)
		}
		if _, err := file.ReadAt(0, make([]byte, 16)); !errors.Is(err, ErrUnsupported) ||
			!strings.Contains(err.Error(), tc.name) {
			t.Errorf("%s read error = %v, want unsupported naming %s", tc.path, err, tc.name)
		}
		// The lossy path zero-fills the unreadable bytes and accounts for them.
		buf := make([]byte, 16)
		n, err := file.ReadAtLossy(0, buf)
		if err != nil || n != 16 || !bytes.Equal(buf, make([]byte, 16)) {
			t.Errorf("%s lossy read = %d, %v, %v", tc.path, n, err, buf)
		}
		if file.Stats().CorruptBytes != 16 {
			t.Errorf("%s corrupt bytes = %d", tc.path, file.Stats().CorruptBytes)
		}
	}
}

func TestCompressedFeatureRefusals(t *testing.T) {
	base := buildCompressed(t)

	checkUndecodable := func(t *testing.T, img []byte, path, want string) {
		t.Helper()
		vol := openErofs(t, img)
		if vol.Info().Undecodable != 1 {
			t.Errorf("undecodable = %d", vol.Info().Undecodable)
		}
		_, err := vol.OpenFile(path)
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), want) {
			t.Errorf("open error = %v, want %q", err, want)
		}
	}

	// A fragment pcluster.
	fragment := append([]byte{}, base.img...)
	putE16(fragment, cIloc(cnFull)+32+4, testAdviseFragment)
	checkUndecodable(t, fragment, "/deflate.bin", "fragment pcluster")

	// A pcluster stored inline in the inode.
	inline := append([]byte{}, base.img...)
	putE16(inline, cIloc(cnFull)+32+4, testAdviseInline)
	checkUndecodable(t, inline, "/deflate.bin", "inline pcluster")

	// The extent-table index.
	extents := append([]byte{}, base.img...)
	putE16(extents, cIloc(cnFull)+32+4, testAdviseExtents)
	checkUndecodable(t, extents, "/deflate.bin", "ADVISE_EXTENTS")

	// An interlaced PLAIN pcluster.
	interlaced := append([]byte{}, base.img...)
	putE16(interlaced, cIloc(cnPlain)+32+4, testAdviseInter)
	checkUndecodable(t, interlaced, "/plain.bin", "ADVISE_INTERLACED")

	// A file packed whole into the shared inode.
	packed := append([]byte{}, base.img...)
	packed[cIloc(cnFull)+32+7] = 0x80
	checkUndecodable(t, packed, "/deflate.bin", "packed inode")

	// Reserved cluster-bit fields.
	reserved := append([]byte{}, base.img...)
	reserved[cIloc(cnFull)+32+7] = 0x10
	checkUndecodable(t, reserved, "/deflate.bin", "reserved bits")

	// An algorithm id outside the four defined.
	unknownAlg := append([]byte{}, base.img...)
	unknownAlg[cIloc(cnFull)+32+6] = 4
	checkUndecodable(t, unknownAlg, "/deflate.bin", "algorithm id 4")

	// A compact index whose logical clusters are too large for the form.
	compactBits := append([]byte{}, base.img...)
	compactBits[cIloc(cnCompact)+32+7] = 3 // block bits 12 + 3 = 15
	checkUndecodable(t, compactBits, "/compact.bin", "compact index")

	// A compact index whose first logical cluster is a continuation.
	malformed := append([]byte{}, base.img...)
	compactStart := cIloc(cnCompact) + 40
	putE32(malformed, compactStart,
		compactWord(0, testTypeNonhead)|compactWord(1, testTypeNonhead)<<16)
	vol := openErofs(t, malformed)
	if vol.Info().Undecodable != 1 {
		t.Errorf("malformed compact undecodable = %d", vol.Info().Undecodable)
	}
	if _, err := vol.OpenFile("/compact.bin"); !errors.Is(err, ErrCorrupt) ||
		!strings.Contains(err.Error(), "continuation") {
		t.Errorf("malformed compact index = %v", err)
	}

	// A stored pcluster that runs past the declared image.
	past := append([]byte{}, base.img...)
	putE32(past, cIloc(cnLZ4)+48+4, 1_000_000)
	vol = openErofs(t, past)
	if vol.Info().Undecodable != 1 {
		t.Errorf("past-image undecodable = %d", vol.Info().Undecodable)
	}
	if _, err := vol.OpenFile("/lz4.bin"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("past-image open = %v", err)
	}
}

func TestAvailableAlgorithmMask(t *testing.T) {
	fixture := buildCompressed(t)
	putE16(fixture.img, testSuperOffset+84, 1<<testAlgLZ4) // only LZ4 is declared
	vol := openErofs(t, fixture.img)
	// Every DEFLATE file is refused by name; the LZ4 file is admitted (then its
	// decoder is the unsupported step, not the header).
	_, err := vol.OpenFile("/deflate.bin")
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "DEFLATE") {
		t.Errorf("deflate without availability = %v", err)
	}
}

func TestBigPclusterBlockCount(t *testing.T) {
	fixture := buildCompressed(t)

	// Removing the compressed-block count from the continuation is corruption.
	missing := append([]byte{}, fixture.img...)
	putE16(missing, cIloc(cnBig)+48+8+4, 1)
	vol := openErofs(t, missing)
	if vol.Info().Undecodable != 1 {
		t.Errorf("undecodable = %d", vol.Info().Undecodable)
	}
	if _, err := vol.OpenFile("/big.bin"); !errors.Is(err, ErrCorrupt) ||
		!strings.Contains(err.Error(), "does not count") {
		t.Errorf("missing block count = %v", err)
	}

	// A pcluster above the stored-byte bound is refused, not allocated.
	tooBig := append([]byte{}, fixture.img...)
	putE16(tooBig, cIloc(cnBig)+48+8+4, testLiCblkCount|513)
	vol = openErofs(t, tooBig)
	if vol.Info().Undecodable != 1 {
		t.Errorf("undecodable = %d", vol.Info().Undecodable)
	}
	if _, err := vol.OpenFile("/big.bin"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("oversized pcluster = %v", err)
	}
}

// ---- compacted two-byte index -------------------------------------------

const (
	dMetaBlock = 24
	dBlocks    = 32
	dnRoot     = 1
	dnDense    = 33
	dLclusters = 22
)

func dIloc(nid uint64) int { return eIloc(dMetaBlock, nid) }

func putCompact2B(img []byte, pack, entry int, value uint16) {
	bit := entry * 14
	byteAt := pack + bit/8
	shift := bit % 8
	word := binary.LittleEndian.Uint32(img[byteAt:])
	word |= uint32(value) << shift
	binary.LittleEndian.PutUint32(img[byteAt:], word)
}

func buildCompacted2B(t *testing.T) ([]byte, []byte) {
	t.Helper()
	img := make([]byte, dBlocks*testBlock)
	eSuperblock(img, dBlocks, dMetaBlock, dnRoot, 2, 0, testIncompatCfgs, "EROFS-2B-PACK", 0x000f)

	rootAt := dIloc(dnRoot) + 32
	rootLen := eListing(img, rootAt, []eEnt{{"dense.bin", dnDense, 1}})
	eCompact(img, dIloc(dnRoot), testLayoutInline, 0, testModeDir, uint32(rootLen), 0, dnRoot, 0, 0)

	content := ePattern(dLclusters*testBlock, 'D')
	ebase := dIloc(dnDense) + 40
	if ebase%32 != 8 {
		t.Fatalf("ebase alignment = %d", ebase%32)
	}

	// The leading 4 KiB region: two-entry packs, each a PLAIN head.
	for pair := 0; pair < 3; pair++ {
		pack := ebase + pair*8
		putE32(img, pack, compactWord(0, testTypePlain)|compactWord(0, testTypePlain)<<16)
		putE32(img, pack+4, uint32(pair*2))
	}
	// One 32-byte two-byte-record pack: lclusters 6..21, all PLAIN.
	pack := ebase + 24
	for entry := 0; entry < 16; entry++ {
		putCompact2B(img, pack, entry, uint16(testTypePlain)<<12)
	}
	putE32(img, pack+28, 6)

	for lcn := 0; lcn < dLclusters; lcn++ {
		storeBlock(img, 1+lcn, content[lcn*testBlock:(lcn+1)*testBlock])
	}

	eCompact(img, dIloc(dnDense), testLayoutCompact, 0, testModeFile, uint32(len(content)), 1, dnDense, 1000, 1000)
	mapHeader := dIloc(dnDense) + 32
	putE16(img, mapHeader+4, testAdvise2B)
	img[mapHeader+6] = testAlgLZ4
	img[mapHeader+7] = 0
	return img, content
}

func TestCompactedTwoByteIndex(t *testing.T) {
	img, content := buildCompacted2B(t)
	vol := openErofs(t, img)
	if vol.Info().Unreadable != 0 || vol.Info().Undecodable != 0 {
		t.Errorf("counters = %d/%d", vol.Info().Unreadable, vol.Info().Undecodable)
	}
	entry, err := vol.Stat("/dense.bin")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if entry.Size != uint64(len(content)) || entry.Allocated != uint64(len(content)) {
		t.Errorf("dense = %+v", entry)
	}
	file, err := vol.OpenFile("/dense.bin")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got := make([]byte, len(content))
	if err := source.ReadExactAt(file, 0, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch")
	}
	ranges, err := file.Extents(0, uint64(len(content)))
	if err != nil {
		t.Fatalf("extents: %v", err)
	}
	if len(ranges) != dLclusters {
		t.Fatalf("extents = %d", len(ranges))
	}
	for i, r := range ranges {
		if r.Kind != source.RangeData || r.ParentOffset != uint64(1+i)*testBlock || r.Len != testBlock {
			t.Errorf("extent %d = %+v", i, r)
		}
	}
	// The boundary between the leading 4 KiB region and the 14-bit pack.
	at := 6*testBlock - 16
	cross := make([]byte, 32)
	if err := source.ReadExactAt(file, uint64(at), cross); err != nil {
		t.Fatalf("cross: %v", err)
	}
	if !bytes.Equal(cross, content[at:at+32]) {
		t.Errorf("boundary read mismatch")
	}

	// A two-byte pack with 13-bit clusters is refused by name. The size is
	// enlarged so the file still reaches a two-byte pack at that cluster size.
	tooWide := append([]byte{}, img...)
	tooWide[dIloc(dnDense)+32+7] = 1
	putE32(tooWide, dIloc(dnDense)+8, 22*8192)
	vol = openErofs(t, tooWide)
	if vol.Info().Undecodable != 1 {
		t.Errorf("undecodable = %d", vol.Info().Undecodable)
	}
	if _, err := vol.OpenFile("/dense.bin"); !errors.Is(err, ErrUnsupported) ||
		!strings.Contains(err.Error(), "compacted-2b") {
		t.Errorf("wide 2b index = %v", err)
	}
}

func TestCompressedImageDetect(t *testing.T) {
	fixture := buildCompressed(t)
	ok, err := Detect(source.NewMemorySource(1, fixture.img))
	if err != nil || !ok {
		t.Errorf("Detect(compressed) = %v, %v", ok, err)
	}
}

func TestDirectoryCycleDoesNotLoop(t *testing.T) {
	const blocks = 2
	img := make([]byte, blocks*testBlock)
	eSuperblock(img, blocks, 0, nidRoot, 1, 0, 0, "CYCLE", 0)
	rootAt := eIloc(0, nidRoot) + 32
	rootLen := eListing(img, rootAt, []eEnt{{"loop", nidRoot, 2}})
	eCompact(img, eIloc(0, nidRoot), testLayoutInline, 0, testModeDir, uint32(rootLen), 0, nidRoot, 0, 0)

	vol := openErofs(t, img)
	if vol.Info().Entries != 2 {
		t.Fatalf("entries = %d", vol.Info().Entries)
	}
	entries, err := vol.ListDir("/loop")
	if err != nil {
		t.Fatalf("list loop: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a cycle was listed as children: %+v", entries)
	}
}
