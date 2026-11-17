package cramfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- synthetic image builders -------------------------------------------

const (
	testMagic        = 0x28cd_3d45
	testWrongEndian  = 0x453d_cd28
	testSuperBytes   = 76
	testBlockSize    = 4096
	testMODE_FILE    = 0o100644
	testMODE_DIR     = 0o040755
	testMODE_SYMLINK = 0o120777

	flagFSIDV2          = 0x0000_0001
	flagSorted          = 0x0000_0002
	testFlagHoles       = 0x0000_0100
	flagExtPointers     = 0x0000_0800
	flagShiftedRoot     = 0x0000_0400
	testUncompressedBit = 1 << 31
	testDirectBit       = 1 << 30
	testMaxStoredBlk    = 2 * testBlockSize
)

func putU16(b []byte, at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
func putU32(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }

func cInode(mode uint16, uid uint16, size uint32, gid uint8, nameWords uint8, offsetUnits uint32) []byte {
	out := make([]byte, 12)
	putU32(out, 0, uint32(mode)|uint32(uid)<<16)
	putU32(out, 4, (size&0x00FF_FFFF)|uint32(gid)<<24)
	putU32(out, 8, uint32(nameWords&0x3f)|offsetUnits<<6)
	return out
}

func cEntry(name string, inode []byte) []byte {
	words := (len(name) + 3) / 4
	out := make([]byte, 12+words*4)
	copy(out, inode)
	copy(out[12:], name)
	return out
}

func cListingSize(names ...string) int {
	total := 0
	for _, name := range names {
		total += 12 + ((len(name)+3)/4)*4
	}
	return total
}

func cPattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i%26)
	}
	return out
}

func cZlib(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

type cBuilder struct {
	img []byte
	at  int
}

func newCBuilder(size int) *cBuilder { return &cBuilder{img: make([]byte, size)} }

func (b *cBuilder) alloc(n int) int {
	off := (b.at + 3) &^ 3
	if off+n > len(b.img) {
		b.img = append(b.img, make([]byte, off+n-len(b.img))...)
	}
	b.at = off + n
	return off
}

func (b *cBuilder) write(at int, payload []byte) {
	copy(b.img[at:], payload)
}

// cWriteSuperblock fills the 76-byte superblock at base. crc is computed over
// the declared size with the checksum field zeroed, exactly as mkfs.cramfs
// does, when computeCRC is true.
func cWriteSuperblock(b *cBuilder, base int, root []byte, flags, size uint32, name string, edition, blockCount, fileCount uint32, computeCRC bool) {
	putU32(b.img, base, testMagic)
	putU32(b.img, base+4, size)
	putU32(b.img, base+8, flags)
	putU32(b.img, base+12, 0)
	copy(b.img[base+16:base+32], "Compressed ROMFS")
	putU32(b.img, base+32, 0)
	putU32(b.img, base+36, edition)
	putU32(b.img, base+40, blockCount)
	putU32(b.img, base+44, fileCount)
	copy(b.img[base+48:base+64], name)
	copy(b.img[base+64:base+76], root)
	if computeCRC {
		want := int(size)
		if want > len(b.img) {
			want = len(b.img)
		}
		putU32(b.img, base+32, crc32.ChecksumIEEE(b.img[:want]))
	}
}

type cBasicImage struct {
	img        []byte
	aRawOff    int
	aCompOff   int
	aCompLen   int
	bigRawOff  int
	subOff     int
	linkTarget int
}

// buildBasicCramfs builds the main fixture:
//
//	/            (root, inline listing at byte 76)
//	/a.txt       5000 bytes: raw block then a zlib block
//	/big.bin     12288 bytes: hole, raw block, hole
//	/empty       empty directory
//	/link        symlink whose target is a raw block
//	/sub/inner.txt  10 bytes
//	/zero        zero-length file
func buildBasicCramfs(t *testing.T) cBasicImage {
	t.Helper()
	rootNames := []string{"a.txt", "big.bin", "empty", "link", "sub", "zero"}
	rootLen := cListingSize(rootNames...)
	b := newCBuilder(testSuperBytes + rootLen)
	b.at = (testSuperBytes + rootLen + 3) &^ 3

	contentA := cPattern(5000, 'A')
	compA := cZlib(t, contentA[testBlockSize:])

	// a.txt: two end-pointer blocks, the first raw and the second zlib.
	aTable := b.alloc(8)
	aRaw := b.alloc(testBlockSize + len(compA))
	b.write(aRaw, contentA[:testBlockSize])
	b.write(aRaw+testBlockSize, compA)
	putU32(b.img, aTable, uint32(aRaw+testBlockSize)|testUncompressedBit)
	putU32(b.img, aTable+4, uint32(aRaw+testBlockSize+len(compA)))

	// big.bin: hole, one raw block, hole.
	bigContent := cPattern(testBlockSize, 'B')
	bigTable := b.alloc(12)
	bigRaw := b.alloc(testBlockSize)
	b.write(bigRaw, bigContent)
	putU32(b.img, bigTable, uint32(bigRaw))
	putU32(b.img, bigTable+4, uint32(bigRaw+testBlockSize)|testUncompressedBit)
	putU32(b.img, bigTable+8, uint32(bigRaw+testBlockSize))

	// sub/inner.txt.
	subNames := []string{"inner.txt"}
	subLen := cListingSize(subNames...)
	subOff := b.alloc(subLen)
	innerText := []byte("inner body")
	innerTable := b.alloc(4)
	innerOff := b.alloc(len(innerText))
	b.write(innerOff, innerText)
	putU32(b.img, innerTable, uint32(innerOff+len(innerText))|testUncompressedBit)
	innerInode := cInode(testMODE_FILE, 1000, uint32(len(innerText)), 27, uint8((len("inner.txt")+3)/4), uint32(innerTable>>2))
	subListing := cEntry("inner.txt", innerInode)
	b.write(subOff, subListing)
	subInode := cInode(testMODE_DIR, 1000, uint32(subLen), 27, uint8((len("sub")+3)/4), uint32(subOff>>2))

	// link -> target stored in one raw block.
	target := []byte("inner.txt")
	linkTable := b.alloc(4)
	linkTarget := b.alloc(len(target))
	b.write(linkTarget, target)
	putU32(b.img, linkTable, uint32(linkTarget+len(target))|testUncompressedBit)
	linkInode := cInode(testMODE_SYMLINK, 0, uint32(len(target)), 0, uint8((len("link")+3)/4), uint32(linkTable>>2))

	emptyInode := cInode(testMODE_DIR, 1000, 0, 27, uint8((len("empty")+3)/4), 0)
	zeroInode := cInode(testMODE_FILE, 1000, 0, 27, uint8((len("zero")+3)/4), 0)
	aInode := cInode(testMODE_FILE, 1000, uint32(len(contentA)), 27, uint8((len("a.txt")+3)/4), uint32(aTable>>2))
	bigInode := cInode(testMODE_FILE, 1000, 12288, 27, uint8((len("big.bin")+3)/4), uint32(bigTable>>2))

	rootListing := append([]byte{}, cEntry("a.txt", aInode)...)
	rootListing = append(rootListing, cEntry("big.bin", bigInode)...)
	rootListing = append(rootListing, cEntry("empty", emptyInode)...)
	rootListing = append(rootListing, cEntry("link", linkInode)...)
	rootListing = append(rootListing, cEntry("sub", subInode)...)
	rootListing = append(rootListing, cEntry("zero", zeroInode)...)
	b.write(testSuperBytes, rootListing)

	root := cInode(testMODE_DIR, 1000, uint32(rootLen), 27, 0, testSuperBytes>>2)
	cWriteSuperblock(b, 0, root, flagFSIDV2|flagSorted|flagHoles, uint32(len(b.img)),
		"TESTVOL", 7, uint32(len(b.img)/testBlockSize), 7, true)
	return cBasicImage{
		img:        b.img,
		aRawOff:    aRaw,
		aCompOff:   aRaw + testBlockSize,
		aCompLen:   len(compA),
		bigRawOff:  bigRaw,
		subOff:     subOff,
		linkTarget: linkTarget,
	}
}

func openCram(t *testing.T, img []byte) *Volume {
	t.Helper()
	vol, err := Open(source.NewMemorySource(1, img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return vol
}

// ---- detection and geometry ---------------------------------------------

func TestDetect(t *testing.T) {
	basic := buildBasicCramfs(t)
	ok, err := Detect(source.NewMemorySource(1, basic.img))
	if err != nil || !ok {
		t.Fatalf("Detect(valid) = %v, %v", ok, err)
	}

	zeros := make([]byte, 8192)
	ok, err = Detect(source.NewMemorySource(1, zeros))
	if err != nil || ok {
		t.Errorf("Detect(zeroes) = %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, nil))
	if err != nil || ok {
		t.Errorf("Detect(empty) = %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, []byte{1, 2, 3}))
	if err != nil || ok {
		t.Errorf("Detect(short) = %v, %v", ok, err)
	}

	// A big-endian image is named, never read as little-endian.
	be := make([]byte, 512)
	putU32(be, 0, testWrongEndian)
	_, err = Detect(source.NewMemorySource(1, be))
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "big-endian") {
		t.Errorf("Detect(big-endian) error = %v", err)
	}
	if _, err := Open(source.NewMemorySource(1, be)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Open(big-endian) error = %v", err)
	}
}

func TestInfoAndRootListing(t *testing.T) {
	basic := buildBasicCramfs(t)
	vol := openCram(t, basic.img)

	info := vol.Info()
	if info.Type != "CramFS" {
		t.Errorf("type = %q", info.Type)
	}
	if info.BlockSize != testBlockSize {
		t.Errorf("block size = %d", info.BlockSize)
	}
	if info.Version != "2" || info.Size != uint32(len(basic.img)) {
		t.Errorf("version/size = %q/%d", info.Version, info.Size)
	}
	if info.Name != "TESTVOL" || info.Edition != 7 {
		t.Errorf("name/edition = %q/%d", info.Name, info.Edition)
	}
	if !info.SignatureOK {
		t.Errorf("signature should be OK")
	}
	if info.Entries != 8 { // root, a.txt, big.bin, empty, link, sub, zero, sub/inner.txt
		t.Errorf("entries = %d", info.Entries)
	}
	if info.Unreadable != 0 || info.Undecodable != 0 {
		t.Errorf("counters = %d/%d", info.Unreadable, info.Undecodable)
	}

	root, err := vol.Stat("/")
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !root.IsDir || root.Name != "/" || root.Path != "/" {
		t.Errorf("root = %+v", root)
	}
	if root.Mode != testMODE_DIR || root.UID != 1000 || root.GID != 27 {
		t.Errorf("root mode/owner = %#o %d/%d", root.Mode, root.UID, root.GID)
	}

	entries, err := vol.ListDir("/")
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	if len(entries) != 6 {
		t.Fatalf("root entries = %d", len(entries))
	}
	want := []string{"a.txt", "big.bin", "empty", "link", "sub", "zero"}
	for i, name := range want {
		if entries[i].Name != name {
			t.Errorf("entry %d = %q, want %q", i, entries[i].Name, name)
		}
	}
	if entries[0].Path != "/a.txt" || !entries[0].IsFile || entries[0].Size != 5000 {
		t.Errorf("a.txt = %+v", entries[0])
	}
	if !entries[2].IsDir {
		t.Errorf("empty should be a directory")
	}
	if !entries[3].IsSymlink || entries[3].SymlinkTarget != "inner.txt" {
		t.Errorf("link = %+v", entries[3])
	}

	// "" and "/" both name the root.
	byEmpty, err := vol.Stat("")
	if err != nil || byEmpty.Path != "/" {
		t.Errorf("stat empty path = %+v, %v", byEmpty, err)
	}
	// A relative path is rooted too.
	rel, err := vol.Stat("sub/inner.txt")
	if err != nil || rel.Path != "/sub/inner.txt" {
		t.Errorf("relative stat = %+v, %v", rel, err)
	}

	sub, err := vol.ListDir("/sub")
	if err != nil {
		t.Fatalf("list sub: %v", err)
	}
	if len(sub) != 1 || sub[0].Name != "inner.txt" || sub[0].Size != uint64(len("inner body")) {
		t.Errorf("sub listing = %+v", sub)
	}

	empty, err := vol.ListDir("/empty")
	if err != nil || len(empty) != 0 {
		t.Errorf("empty listing = %+v, %v", empty, err)
	}

	if _, err := vol.Stat("/nope"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing stat error = %v", err)
	}
	if _, err := vol.ListDir("/a.txt"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("list file error = %v", err)
	}
	if _, err := vol.OpenFile("/sub"); !errors.Is(err, ErrNotAFile) {
		t.Errorf("open dir error = %v", err)
	}
	if _, err := vol.OpenFile("/link"); !errors.Is(err, ErrNotAFile) {
		t.Errorf("open symlink error = %v", err)
	}
}

// ---- file data -----------------------------------------------------------

func TestFileReadsCrossingBlocks(t *testing.T) {
	basic := buildBasicCramfs(t)
	vol := openCram(t, basic.img)
	contentA := cPattern(5000, 'A')

	file, err := vol.OpenFile("/a.txt")
	if err != nil {
		t.Fatalf("open a.txt: %v", err)
	}
	if file.Len() != 5000 {
		t.Fatalf("length = %d", file.Len())
	}
	all := make([]byte, 5000)
	if err := source.ReadExactAt(file, 0, all); err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(all, contentA) {
		t.Errorf("a.txt content mismatch")
	}

	// A read starting in the raw block and ending in the zlib block.
	cross := make([]byte, 100)
	if err := source.ReadExactAt(file, 4000, cross); err != nil {
		t.Fatalf("cross read: %v", err)
	}
	if !bytes.Equal(cross, contentA[4000:4100]) {
		t.Errorf("cross read = %q", cross)
	}

	if _, err := file.ReadAt(file.Len(), make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("past end = %v", err)
	}
	if n, err := file.ReadAt(0, nil); n != 0 || err != nil {
		t.Errorf("empty read = %d, %v", n, err)
	}

	// Extents: the raw block names its image bytes; the zlib block names the
	// whole stored region it was decoded from.
	ranges, err := file.Extents(0, 5000)
	if err != nil {
		t.Fatalf("extents: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("extents = %d", len(ranges))
	}
	if ranges[0].Kind != source.RangeData || ranges[0].ParentOffset != uint64(basic.aRawOff) || ranges[0].Len != testBlockSize {
		t.Errorf("raw extent = %+v", ranges[0])
	}
	if ranges[1].Kind != source.RangeData || ranges[1].ParentOffset != uint64(basic.aCompOff) || ranges[1].Len != uint64(basic.aCompLen) {
		t.Errorf("compressed extent = %+v", ranges[1])
	}
	mapped, err := file.MapToImage(4000, 100)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(mapped) < 1 || mapped[0].ImageOffset != uint64(basic.aRawOff)+4000 {
		t.Errorf("mapped = %+v", mapped)
	}

	zero, err := vol.OpenFile("/zero")
	if err != nil {
		t.Fatalf("open zero: %v", err)
	}
	if zero.Len() != 0 || !zero.IsEmpty() {
		t.Errorf("zero file = len %d empty %v", zero.Len(), zero.IsEmpty())
	}
	if _, err := zero.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("zero read = %v", err)
	}
}

func TestSparseHoles(t *testing.T) {
	basic := buildBasicCramfs(t)
	vol := openCram(t, basic.img)

	file, err := vol.OpenFile("/big.bin")
	if err != nil {
		t.Fatalf("open big.bin: %v", err)
	}
	if file.Len() != 12288 {
		t.Fatalf("length = %d", file.Len())
	}
	all := make([]byte, 12288)
	if err := source.ReadExactAt(file, 0, all); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(all[:testBlockSize], make([]byte, testBlockSize)) {
		t.Errorf("first block is not a hole of zeroes")
	}
	bigContent := cPattern(testBlockSize, 'B')
	if !bytes.Equal(all[testBlockSize:2*testBlockSize], bigContent) {
		t.Errorf("middle block mismatch")
	}
	if !bytes.Equal(all[2*testBlockSize:], make([]byte, testBlockSize)) {
		t.Errorf("last block is not a hole of zeroes")
	}

	ranges, err := file.Extents(0, 12288)
	if err != nil {
		t.Fatalf("extents: %v", err)
	}
	if len(ranges) != 3 {
		t.Fatalf("extents = %d", len(ranges))
	}
	if ranges[0].Kind != source.RangeZero || ranges[0].Len != testBlockSize {
		t.Errorf("hole extent = %+v", ranges[0])
	}
	if ranges[1].Kind != source.RangeData || ranges[1].ParentOffset != uint64(basic.bigRawOff) {
		t.Errorf("raw extent = %+v", ranges[1])
	}
	if ranges[2].Kind != source.RangeZero {
		t.Errorf("tail hole = %+v", ranges[2])
	}

	// Reading a hole yields zeros through both strict and lossy paths.
	zero := make([]byte, 16)
	if err := source.ReadExactAt(file, 0, zero); err != nil {
		t.Fatalf("hole read: %v", err)
	}
	if !bytes.Equal(zero, make([]byte, 16)) {
		t.Errorf("hole read = %v", zero)
	}
	n, err := file.ReadAtLossy(0, zero)
	if err != nil || n != 16 || !bytes.Equal(zero, make([]byte, 16)) {
		t.Errorf("lossy hole read = %d, %v, %v", n, err, zero)
	}
}

func TestSymlinkTarget(t *testing.T) {
	basic := buildBasicCramfs(t)
	vol := openCram(t, basic.img)

	entry, err := vol.Stat("/link")
	if err != nil {
		t.Fatalf("stat link: %v", err)
	}
	if !entry.IsSymlink || entry.Size != uint64(len("inner.txt")) || entry.SymlinkTarget != "inner.txt" {
		t.Errorf("link = %+v", entry)
	}
	if got := basic.img[basic.linkTarget : basic.linkTarget+len("inner.txt")]; string(got) != "inner.txt" {
		t.Errorf("stored target = %q", got)
	}
	stream, err := vol.OpenSymlink("/link")
	if err != nil {
		t.Fatalf("open symlink: %v", err)
	}
	buf := make([]byte, 9)
	if err := source.ReadExactAt(stream, 0, buf); err != nil {
		t.Fatalf("read symlink: %v", err)
	}
	if string(buf) != "inner.txt" {
		t.Errorf("symlink stream = %q", buf)
	}
	if _, err := vol.OpenSymlink("/a.txt"); !errors.Is(err, ErrNotASymlink) {
		t.Errorf("open non-symlink = %v", err)
	}
}

func TestDirectBlockPointers(t *testing.T) {
	rootNames := []string{"direct.bin", "directz.txt"}
	rootLen := cListingSize(rootNames...)
	b := newCBuilder(testSuperBytes + rootLen)
	b.at = (testSuperBytes + rootLen + 3) &^ 3

	rawContent := cPattern(testBlockSize, 'D')
	table1 := b.alloc(4)
	rawOff := b.alloc(testBlockSize)
	b.write(rawOff, rawContent)
	putU32(b.img, table1, uint32(rawOff>>2)|testDirectBit|testUncompressedBit)

	compContent := cPattern(3000, 'E')
	comp := cZlib(t, compContent)
	table2 := b.alloc(4)
	compOff := b.alloc(2 + len(comp))
	putU16(b.img, compOff, uint16(len(comp)))
	b.write(compOff+2, comp)
	putU32(b.img, table2, uint32(compOff>>2)|testDirectBit)

	inode1 := cInode(testMODE_FILE, 1000, testBlockSize, 27, uint8((len("direct.bin")+3)/4), uint32(table1>>2))
	inode2 := cInode(testMODE_FILE, 1000, 3000, 27, uint8((len("directz.txt")+3)/4), uint32(table2>>2))
	listing := append([]byte{}, cEntry("direct.bin", inode1)...)
	listing = append(listing, cEntry("directz.txt", inode2)...)
	b.write(testSuperBytes, listing)
	root := cInode(testMODE_DIR, 0, uint32(rootLen), 0, 0, testSuperBytes>>2)
	cWriteSuperblock(b, 0, root, flagFSIDV2|flagExtPointers, uint32(len(b.img)),
		"DIRECT", 1, 1, 2, true)

	vol := openCram(t, b.img)
	raw, err := vol.OpenFile("/direct.bin")
	if err != nil {
		t.Fatalf("open direct.bin: %v", err)
	}
	got := make([]byte, testBlockSize)
	if err := source.ReadExactAt(raw, 0, got); err != nil {
		t.Fatalf("read direct.bin: %v", err)
	}
	if !bytes.Equal(got, rawContent) {
		t.Errorf("direct raw content mismatch")
	}
	compressed, err := vol.OpenFile("/directz.txt")
	if err != nil {
		t.Fatalf("open directz.txt: %v", err)
	}
	got = make([]byte, 3000)
	if err := source.ReadExactAt(compressed, 0, got); err != nil {
		t.Fatalf("read directz.txt: %v", err)
	}
	if !bytes.Equal(got, compContent) {
		t.Errorf("direct compressed content mismatch")
	}
	ranges, err := compressed.Extents(0, 3000)
	if err != nil || len(ranges) != 1 || ranges[0].ParentOffset != uint64(compOff) || ranges[0].Len != uint64(2+len(comp)) {
		t.Errorf("direct extent = %+v, %v", ranges, err)
	}
}

func TestShiftedImage(t *testing.T) {
	const base = 512
	rootNames := []string{"shift.txt"}
	rootLen := cListingSize(rootNames...)
	b := newCBuilder(base + testSuperBytes + rootLen)
	b.at = (base + testSuperBytes + rootLen + 3) &^ 3
	content := cPattern(1234, 'S')
	table := b.alloc(4)
	data := b.alloc(len(content))
	b.write(data, content)
	putU32(b.img, table, uint32(data+len(content))|testUncompressedBit)
	inode := cInode(testMODE_FILE, 0, uint32(len(content)), 0, uint8((len("shift.txt")+3)/4), uint32(table>>2))
	b.write(base+testSuperBytes, cEntry("shift.txt", inode))
	root := cInode(testMODE_DIR, 0, uint32(rootLen), 0, 0, uint32((base+testSuperBytes)>>2))
	cWriteSuperblock(b, base, root, flagFSIDV2, uint32(len(b.img)), "SHIFT", 1, 1, 1, false)

	ok, err := Detect(source.NewMemorySource(1, b.img))
	if err != nil || !ok {
		t.Fatalf("Detect(shifted) = %v, %v", ok, err)
	}
	vol := openCram(t, b.img)
	info := vol.Info()
	if info.Base != base {
		t.Errorf("base = %d", info.Base)
	}
	file, err := vol.OpenFile("/shift.txt")
	if err != nil {
		t.Fatalf("open shifted file: %v", err)
	}
	got := make([]byte, len(content))
	if err := source.ReadExactAt(file, 0, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("shifted content mismatch")
	}
	// A shifted image's checksummed range is not established, so no verdict.
	verification, err := vol.VerifyCRC()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verification.State != CRCShifted || verification.HasComputed {
		t.Errorf("verification = %+v", verification)
	}
}

func TestEmptyImage(t *testing.T) {
	img := make([]byte, testSuperBytes)
	root := cInode(testMODE_DIR, 0, 0, 0, 0, 0)
	cWriteSuperblock(&cBuilder{img: img}, 0, root, flagFSIDV2, testSuperBytes, "", 1, 0, 0, true)

	vol := openCram(t, img)
	if got := vol.Info().Entries; got != 1 {
		t.Errorf("entries = %d", got)
	}
	entries, err := vol.ListDir("/")
	if err != nil || len(entries) != 0 {
		t.Errorf("root listing = %+v, %v", entries, err)
	}
}

func TestCRCVerification(t *testing.T) {
	basic := buildBasicCramfs(t)
	vol := openCram(t, basic.img)
	verification, err := vol.VerifyCRC()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verification.State != CRCVerified {
		t.Errorf("state = %v", verification.State)
	}
	if !verification.HasComputed || verification.Computed != verification.Stored {
		t.Errorf("verification = %+v", verification)
	}

	// Changing a byte the walk does not depend on makes the checksum disagree.
	mutated := append([]byte{}, basic.img...)
	mutated[12] = 0xFF // the reserved "future" word
	vol = openCram(t, mutated)
	verification, err = vol.VerifyCRC()
	if err != nil {
		t.Fatalf("verify mutated: %v", err)
	}
	if verification.State != CRCMismatch || !verification.HasComputed {
		t.Errorf("mutated verification = %+v", verification)
	}

	// A zero checksum field is reported as not recorded, not a mismatch.
	notRecorded := append([]byte{}, basic.img...)
	putU32(notRecorded, 32, 0)
	vol = openCram(t, notRecorded)
	verification, err = vol.VerifyCRC()
	if err != nil {
		t.Fatalf("verify zero crc: %v", err)
	}
	if verification.State != CRCNotRecorded || !verification.HasComputed {
		t.Errorf("zero-crc verification = %+v", verification)
	}

	// FSID version 1 does not define the field as a checksum.
	_, err = Open(source.NewMemorySource(1, basic.img))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v1 := append([]byte{}, basic.img...)
	putU32(v1, 8, flagSorted)
	sizeV1 := make([]byte, len(v1))
	copy(sizeV1, v1)
	vol = openCram(t, sizeV1)
	verification, err = vol.VerifyCRC()
	if err != nil {
		t.Fatalf("verify v1: %v", err)
	}
	if verification.State != CRCNotVersion2 || verification.HasComputed {
		t.Errorf("v1 verification = %+v", verification)
	}
}

func TestDirectoryCycleDoesNotLoop(t *testing.T) {
	rootLen := cListingSize("loop")
	b := newCBuilder(testSuperBytes + rootLen)
	loopInode := cInode(testMODE_DIR, 0, uint32(rootLen), 0, uint8((len("loop")+3)/4), testSuperBytes>>2)
	b.write(testSuperBytes, cEntry("loop", loopInode))
	root := cInode(testMODE_DIR, 0, uint32(rootLen), 0, 0, testSuperBytes>>2)
	cWriteSuperblock(b, 0, root, flagFSIDV2, uint32(len(b.img)), "", 1, 1, 1, true)

	vol := openCram(t, b.img)
	if got := vol.Info().Entries; got != 2 {
		t.Fatalf("entries = %d", got)
	}
	entries, err := vol.ListDir("/loop")
	if err != nil {
		t.Fatalf("list loop: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a cycle was listed as children: %+v", entries)
	}
}

func TestUnreadableAndUndecodableAreCounted(t *testing.T) {
	// A directory whose listing runs past the declared image is counted, not
	// invented; a file whose block table is corrupt is listed without an
	// allocation.
	rootNames := []string{"bad", "file"}
	rootLen := cListingSize(rootNames...)
	b := newCBuilder(testSuperBytes + rootLen)
	b.at = (testSuperBytes + rootLen + 3) &^ 3
	badInode := cInode(testMODE_DIR, 0, 0x1_0000, 0, uint8((len("bad")+3)/4), uint32((testSuperBytes+rootLen)>>2)) // 64 KiB listing past the image
	fileTable := b.alloc(4)
	putU32(b.img, fileTable, 0xFFFF_FFFF) // an end far past the image
	fileInode := cInode(testMODE_FILE, 0, 10, 0, uint8((len("file")+3)/4), uint32(fileTable>>2))
	listing := append([]byte{}, cEntry("bad", badInode)...)
	listing = append(listing, cEntry("file", fileInode)...)
	b.write(testSuperBytes, listing)
	root := cInode(testMODE_DIR, 0, uint32(rootLen), 0, 0, testSuperBytes>>2)
	cWriteSuperblock(b, 0, root, flagFSIDV2, uint32(len(b.img)), "", 1, 1, 2, true)

	vol := openCram(t, b.img)
	info := vol.Info()
	if info.Entries != 3 {
		t.Errorf("entries = %d", info.Entries)
	}
	if info.Unreadable != 1 || info.Undecodable != 1 {
		t.Errorf("counters = %d/%d", info.Unreadable, info.Undecodable)
	}
	file, err := vol.Stat("/file")
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if file.AllocatedKnown {
		t.Errorf("a corrupt block table must not claim an allocation: %+v", file)
	}
	if _, err := vol.OpenFile("/file"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("open corrupt file error = %v", err)
	}
}

// ---- corruption and bounds ----------------------------------------------

func TestCorruptAndTruncated(t *testing.T) {
	basic := buildBasicCramfs(t)

	if _, err := Open(source.NewMemorySource(1, basic.img[:40])); !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Errorf("truncated superblock error = %v", err)
	}
	if _, err := Open(source.NewMemorySource(1, make([]byte, 4))); !errors.Is(err, ErrCorrupt) {
		t.Errorf("four-byte non-magic image error = %v", err)
	}

	// Unknown feature bits change what offsets mean and are refused by value.
	unknown := append([]byte{}, basic.img...)
	putU32(unknown, 8, flagFSIDV2|0x8000_0000)
	if _, err := Open(source.NewMemorySource(1, unknown)); !errors.Is(err, ErrUnsupported) ||
		!strings.Contains(err.Error(), "unknown bits") {
		t.Errorf("unknown flags error = %v", err)
	}

	// The root must be a directory.
	notDir := append([]byte{}, basic.img...)
	putU32(notDir, 64, uint32(testMODE_FILE)|uint32(0)<<16)
	if _, err := Open(source.NewMemorySource(1, notDir)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("non-directory root error = %v", err)
	}

	// The root listing must begin right after the superblock unless the
	// shifted-root flag says otherwise.
	shiftedRoot := append([]byte{}, basic.img...)
	putU32(shiftedRoot, 72, 1000<<6) // offset_units = 1000
	if _, err := Open(source.NewMemorySource(1, shiftedRoot)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("misplaced root error = %v", err)
	}

	// ...and the flag makes the same offset acceptable.
	shiftedRoot = append([]byte{}, shiftedRoot...)
	putU32(shiftedRoot, 8, flagFSIDV2|flagShiftedRoot)
	// Recompute the checksum so only the walk/geometry is under test; Open does
	// not verify it, but keep the fixture honest.
	if _, err := Open(source.NewMemorySource(1, shiftedRoot)); err != nil {
		t.Errorf("flagged shifted root should open: %v", err)
	}

	// A block table that runs past the declared limit.
	rootLen := cListingSize("f")
	b := newCBuilder(testSuperBytes + rootLen)
	b.write(testSuperBytes, cEntry("f", cInode(testMODE_FILE, 0, 10, 0, 1, uint32(len(b.img)>>2))))
	root := cInode(testMODE_DIR, 0, uint32(rootLen), 0, 0, testSuperBytes>>2)
	cWriteSuperblock(b, 0, root, flagFSIDV2, uint32(len(b.img)), "", 1, 1, 1, true)
	vol := openCram(t, b.img)
	if _, err := vol.OpenFile("/f"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("table past limit error = %v", err)
	}
}

func TestParseInodeAndDirectoryErrors(t *testing.T) {
	valid := cInode(testMODE_FILE, 0, 3, 0, 1, 1)
	in, err := parseInode(valid)
	if err != nil || in.kind != inodeFile || in.size != 3 || in.dataOffset() != 4 {
		t.Fatalf("parse inode = %+v, %v", in, err)
	}
	if _, err := parseInode(valid[:8]); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short inode error = %v", err)
	}
	unknownType := cInode(0o150000, 0, 1, 0, 1, 1)
	if _, err := parseInode(unknownType); !errors.Is(err, ErrCorrupt) {
		t.Errorf("unknown inode type error = %v", err)
	}
	if !isPadding(make([]byte, 12)) || isPadding(valid) {
		t.Errorf("padding detection is wrong")
	}

	good := append(cInode(testMODE_FILE, 0, 3, 0, 1, 1), []byte("abc\x00")...)
	entries, err := parseDir(good, 100)
	if err != nil || len(entries) != 1 || entries[0].name != "abc" || entries[0].offset != 100 {
		t.Fatalf("parse dir = %+v, %v", entries, err)
	}

	// Zero padding ends a listing without inventing a name.
	padded := append(append([]byte{}, good...), make([]byte, 12)...)
	entries, err = parseDir(padded, 0)
	if err != nil || len(entries) != 1 {
		t.Errorf("padded listing = %+v, %v", entries, err)
	}

	// A name that runs past the listing is corruption.
	truncated := append(cInode(testMODE_FILE, 0, 3, 0, 3, 1), []byte("ab")...)
	if _, err := parseDir(truncated, 0); !errors.Is(err, ErrCorrupt) {
		t.Errorf("truncated name error = %v", err)
	}
	// An all-zero name is corruption.
	zeroName := append(cInode(testMODE_FILE, 0, 3, 0, 1, 1), make([]byte, 4)...)
	if _, err := parseDir(zeroName, 0); !errors.Is(err, ErrCorrupt) {
		t.Errorf("zero name error = %v", err)
	}
	// An inode that does not fit at the tail is corruption.
	if _, err := parseDir(make([]byte, 12)[:4], 0); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short tail error = %v", err)
	}
}

func TestNameEdgeCases(t *testing.T) {
	long := strings.Repeat("n", 252)
	words := uint8((len(long) + 3) / 4)
	listing := append(cInode(testMODE_FILE, 0, 1, 0, words, 1), []byte(long)...)
	entries, err := parseDir(listing, 0)
	if err != nil || len(entries) != 1 || entries[0].name != long {
		t.Fatalf("252-byte name = %d bytes, %v", len(entries[0].name), err)
	}

	// Invalid UTF-8 is decoded lossily rather than losing the entry, as the
	// reference does.
	raw := append(cInode(testMODE_FILE, 0, 1, 0, 1, 1), []byte{0xFF, 'x', 0, 0}...)
	entries, err = parseDir(raw, 0)
	if err != nil || len(entries) != 1 || !strings.Contains(entries[0].name, "x") ||
		!strings.Contains(entries[0].name, "�") {
		t.Errorf("lossy name = %+v, %v", entries, err)
	}
}

func TestFileSourceBounds(t *testing.T) {
	img := make([]byte, 32768)
	base := source.NewMemorySource(1, img)

	// A file whose table takes 101 bytes but starts at the final byte.
	if _, err := newFileSource(2, base, uint64(len(img)), uint64(len(img)-1), 10); !errors.Is(err, ErrCorrupt) {
		t.Errorf("table past limit error = %v", err)
	}

	// A table whose end pointer goes backwards.
	table := 100
	putU32(img, table, 200)
	putU32(img, table+4, 150)
	if _, err := newFileSource(2, base, uint64(len(img)), uint64(table), 5000); !errors.Is(err, ErrCorrupt) {
		t.Errorf("backwards end pointer error = %v", err)
	}

	// Stored bytes above the kernel's two-page ceiling.
	putU32(img, table, uint32(table+8+9000)|testUncompressedBit)
	if _, err := newFileSource(2, base, uint64(len(img)), uint64(table), 5000); !errors.Is(err, ErrCorrupt) {
		t.Errorf("oversized block error = %v", err)
	}

	// An uncompressed block claiming more than a page.
	putU32(img, table, uint32(table+8+5000)|testUncompressedBit)
	if _, err := newFileSource(2, base, uint64(len(img)), uint64(table), 5000); !errors.Is(err, ErrCorrupt) {
		t.Errorf("oversized raw block error = %v", err)
	}

	// A direct block whose two-byte prefix is past the limit.
	putU32(img, table, uint32(len(img)>>2)|testDirectBit)
	if _, err := newFileSource(2, base, uint64(len(img)), uint64(table), 10); !errors.Is(err, ErrCorrupt) {
		t.Errorf("direct prefix past limit error = %v", err)
	}
}

func TestCorruptZlibBlock(t *testing.T) {
	// A compressed end-pointer block whose stored bytes are not a zlib stream.
	img := make([]byte, 4096)
	table := 100
	data := 104
	// One compressed block of sixteen stored bytes that is not a zlib stream.
	putU32(img, table, uint32(data+16))
	copy(img[data:], bytes.Repeat([]byte{0xAA}, 16))
	src := source.NewMemorySource(1, img)
	file, err := newFileSource(2, src, uint64(len(img)), uint64(table), 4096)
	if err != nil {
		t.Fatalf("new file source: %v", err)
	}
	if _, err := file.ReadAt(0, make([]byte, 16)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("corrupt zlib read error = %v", err)
	}
	// The lossy path zero-fills and accounts for the unreadable bytes.
	buf := make([]byte, 16)
	n, err := file.ReadAtLossy(0, buf)
	if err != nil || n != 16 || !bytes.Equal(buf, make([]byte, 16)) {
		t.Errorf("lossy corrupt read = %d, %v, %v", n, err, buf)
	}
	if file.Stats().CorruptBytes != 16 {
		t.Errorf("corrupt bytes = %d", file.Stats().CorruptBytes)
	}
}
