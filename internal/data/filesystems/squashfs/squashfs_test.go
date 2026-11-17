package squashfs

import (
	"bytes"
	"compress/flate"
	"errors"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- synthetic image builders -------------------------------------------

const (
	testBlockSize   = 4096
	testBlockLog    = 12
	testDataOffset  = 8192
	testInodeCount  = 4
	testInvalidFrag = 0xFFFF_FFFF
	testInvalidTbl  = ^uint64(0)
)

var helloPlain = []byte("Hello, SquashFS!\n")
var helloCompressedPlain = []byte("abcdefghijklmnopqrstuvwxyz012345")

func putU16(b []byte, at int, v uint16) { b[at] = byte(v); b[at+1] = byte(v >> 8) }
func putU32(b []byte, at int, v uint32) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
	b[at+2] = byte(v >> 16)
	b[at+3] = byte(v >> 24)
}
func putU64(b []byte, at int, v uint64) {
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func sqMeta(payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	putU16(out, 0, uint16(0x8000|uint16(len(payload))))
	copy(out[2:], payload)
	return out
}

func sqMetaDeflate(t *testing.T, payload []byte) []byte {
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
	stored := buf.Bytes()
	if len(stored) > 0x7FFF {
		t.Fatalf("compressed metadata too large: %d", len(stored))
	}
	out := make([]byte, 2+len(stored))
	putU16(out, 0, uint16(len(stored)))
	copy(out[2:], stored)
	return out
}

func deflateRaw(t *testing.T, payload []byte) []byte {
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

// rootListing stores three names: sub (inode +32), hello.txt (+64) and
// compressed.txt (+96). The inode table metadata block is block zero, so the
// directory headers name start_block 0.
func rootListing() []byte {
	type ent struct {
		offset uint16
		delta  int16
		typ    uint16
		name   string
	}
	entries := []ent{
		{32, 1, 1, "sub"},
		{64, 2, 2, "hello.txt"},
		{100, 3, 2, "compressed.txt"},
	}
	out := make([]byte, 12)
	putU32(out, 0, uint32(len(entries)-1))
	putU32(out, 4, 0) // inode table metadata block
	putU32(out, 8, 1) // base inode number
	for _, e := range entries {
		entry := make([]byte, 8+len(e.name))
		putU16(entry, 0, e.offset)
		putU16(entry, 2, uint16(e.delta))
		putU16(entry, 4, e.typ)
		putU16(entry, 6, uint16(len(e.name)-1))
		copy(entry[8:], e.name)
		out = append(out, entry...)
	}
	return out
}

func basicDirInode(mode uint16, inode uint32, startBlock uint32, nlink uint32, size uint16, dirOffset uint16) []byte {
	b := make([]byte, 32)
	putU16(b, 0, 1)
	putU16(b, 2, mode)
	putU16(b, 4, 0)
	putU16(b, 6, 1)
	putU32(b, 8, 1_700_000_000)
	putU32(b, 12, inode)
	putU32(b, 16, startBlock)
	putU32(b, 20, nlink)
	putU16(b, 24, size)
	putU16(b, 26, dirOffset)
	return b
}

func basicFileInode(mode uint16, inode uint32, startBlock, size uint32) []byte {
	b := make([]byte, 32)
	putU16(b, 0, 2)
	putU16(b, 2, mode)
	putU16(b, 4, 0)
	putU16(b, 6, 1)
	putU32(b, 8, 1_700_000_000)
	putU32(b, 12, inode)
	putU32(b, 16, startBlock)
	putU32(b, 20, testInvalidFrag)
	putU32(b, 24, 0)
	putU32(b, 28, size)
	return b
}

func extendedFileInode(mode uint16, inode uint32, startBlock, size uint64, xattr uint32) []byte {
	b := make([]byte, 56)
	putU16(b, 0, 9)
	putU16(b, 2, mode)
	putU16(b, 4, 0)
	putU16(b, 6, 1)
	putU32(b, 8, 1_700_000_000)
	putU32(b, 12, inode)
	putU64(b, 16, startBlock)
	putU64(b, 24, size)
	putU64(b, 32, 0)
	putU32(b, 40, 1)
	putU32(b, 44, testInvalidFrag)
	putU32(b, 48, 0)
	putU32(b, 52, xattr)
	return b
}

// buildSquashImage lays out a complete image with one directory tree:
//
//	/            (root, type 1)
//	/sub         (empty directory)
//	/hello.txt   (type 2, uncompressed data block)
//	/compressed.txt (type 9 extended, raw-DEFLATE data, xattr index 0)
//
// It also carries an id table, an export table and one xattr list.
func buildSquashImage(t *testing.T, compressedMetadata bool) []byte {
	t.Helper()
	encode := sqMeta
	if compressedMetadata {
		encode = func(payload []byte) []byte { return sqMetaDeflate(t, payload) }
	}

	// id table: uid index 0 -> 0, gid index 1 -> 1000.
	idPayload := make([]byte, 8)
	putU32(idPayload, 0, 0)
	putU32(idPayload, 4, 1000)
	idBlock := encode(idPayload)

	// export table payload: inode references for numbers 1..4.
	exportPayload := make([]byte, 32)
	putU64(exportPayload, 0, 0)
	putU64(exportPayload, 8, 32)
	putU64(exportPayload, 16, 64)
	putU64(exportPayload, 24, 100)
	exportBlock := encode(exportPayload)

	// xattr: one inline user.comment = "hi".
	var attrList []byte
	attrList = append(attrList, 0x00, 0x00) // type: user., inline
	attrList = append(attrList, 0x07, 0x00) // name length 7
	attrList = append(attrList, []byte("comment")...)
	attrList = append(attrList, 0x02, 0x00, 0x00, 0x00) // value length 2
	attrList = append(attrList, []byte("hi")...)
	attrBlock := sqMeta(attrList)

	idEntry := make([]byte, 16)
	putU32(idEntry, 8, 1)
	putU32(idEntry, 12, uint32(len(attrList)))

	// Fixed layout: data at testDataOffset, metadata before it.
	helloOff := uint32(testDataOffset)
	compressedData := deflateRaw(t, helloCompressedPlain)
	compressedOff := helloOff + uint32(len(helloPlain))

	idBlockOff := 96
	exportBlockOff := idBlockOff + len(idBlock)
	attrBlockOff := exportBlockOff + len(exportBlock)
	idEntryBlockOff := attrBlockOff + len(attrBlock)
	putU64(idEntry, 0, uint64(attrBlockOff)<<16)
	idEntryBlock := sqMeta(idEntry)
	xattrIdTableStart := idEntryBlockOff + len(idEntryBlock)
	idIndexStart := xattrIdTableStart + 24
	inodeTableStart := idIndexStart + 8

	// A regular file's block list follows its fixed header.
	helloInode := basicFileInode(0o644, 3, helloOff, uint32(len(helloPlain)))
	helloInode = appendU32(helloInode, 0x01000000|uint32(len(helloPlain)))
	compressedInode := extendedFileInode(0o600, 4, uint64(compressedOff), uint64(len(helloCompressedPlain)), 0)
	compressedInode = appendU32(compressedInode, uint32(len(compressedData)))

	inodePayload := append([]byte{}, basicDirInode(0o755, 1, 0, 3, uint16(len(rootListing())), 0)...)
	inodePayload = append(inodePayload, basicDirInode(0o700, 2, 0, 2, 0, 0)...)
	inodePayload = append(inodePayload, helloInode...)
	inodePayload = append(inodePayload, compressedInode...)
	inodeBlock := encode(inodePayload)

	dirBlock := encode(rootListing())
	dirTableStart := inodeTableStart + len(inodeBlock)

	exportIndexStart := int(compressedOff) + len(compressedData)
	bytesUsed := exportIndexStart + len(exportPayload)

	if want := 96 + len(idBlock) + len(exportBlock) + len(attrBlock) + len(idEntryBlock) + 24 + 8 + len(inodeBlock) + len(dirBlock); want > testDataOffset {
		t.Fatalf("metadata overlaps fixed data offset: %d > %d", want, testDataOffset)
	}

	image := make([]byte, bytesUsed)
	copy(image[idBlockOff:], idBlock)
	copy(image[exportBlockOff:], exportBlock)
	copy(image[attrBlockOff:], attrBlock)
	copy(image[idEntryBlockOff:], idEntryBlock)

	// xattr id table header and index.
	putU64(image, xattrIdTableStart, uint64(attrBlockOff))
	putU32(image, xattrIdTableStart+8, 1)
	putU64(image, xattrIdTableStart+16, uint64(idEntryBlockOff))

	// id index.
	putU64(image, idIndexStart, uint64(idBlockOff))

	copy(image[inodeTableStart:], inodeBlock)
	copy(image[dirTableStart:], dirBlock)
	copy(image[helloOff:], helloPlain)
	copy(image[compressedOff:], compressedData)
	putU64(image, exportIndexStart, uint64(exportBlockOff))

	// superblock.
	putU32(image, 0, 0x73717368) // "hsqs"
	putU32(image, 4, testInodeCount)
	putU32(image, 8, 1_600_000_000)
	putU32(image, 12, testBlockSize)
	putU32(image, 16, 0) // fragments
	putU16(image, 20, 1) // zlib
	putU16(image, 22, testBlockLog)
	putU16(image, 24, (1<<4)|(1<<7)) // NO_FRAGMENTS | EXPORT
	putU16(image, 26, 2)             // id_count
	putU16(image, 28, 4)
	putU16(image, 30, 0)
	putU64(image, 32, 0) // root inode ref
	putU64(image, 40, uint64(bytesUsed))
	putU64(image, 48, uint64(idIndexStart))
	putU64(image, 56, uint64(xattrIdTableStart))
	putU64(image, 64, uint64(inodeTableStart))
	putU64(image, 72, uint64(dirTableStart))
	putU64(image, 80, testInvalidTbl)
	putU64(image, 88, uint64(exportIndexStart))

	return image
}

var tailPlain = []byte("fragment")

// buildFragmentImage lays out a root directory holding one file whose entire
// content is a slice of a shared, compressed fragment block.
func buildFragmentImage(t *testing.T) []byte {
	t.Helper()
	const dataOff = 4096

	idPayload := make([]byte, 8)
	putU32(idPayload, 4, 1000)
	idBlock := sqMeta(idPayload)

	compressedTail := deflateRaw(t, tailPlain)
	entryPayload := make([]byte, 16)
	putU64(entryPayload, 0, dataOff)
	putU32(entryPayload, 8, uint32(len(compressedTail)))
	fragmentBlock := sqMeta(entryPayload)

	listing := make([]byte, 12+8+len("tail.bin"))
	putU32(listing, 0, 0) // one entry
	putU32(listing, 4, 0) // inode table metadata block zero
	putU32(listing, 8, 1) // base inode number
	putU16(listing, 12, 32)
	putU16(listing, 14, 1)
	putU16(listing, 16, 2)
	putU16(listing, 18, uint16(len("tail.bin")-1))
	copy(listing[20:], "tail.bin")

	idBlockOff := 96
	fragmentBlockOff := idBlockOff + len(idBlock)
	idIndexOff := fragmentBlockOff + len(fragmentBlock)
	fragmentIndexOff := idIndexOff + 8
	inodeTableStart := fragmentIndexOff + 8

	inodePayload := append([]byte{}, basicDirInode(0o755, 1, 0, 2, uint16(len(listing)), 0)...)
	fileInode := basicFileInode(0o644, 2, 0, uint32(len(tailPlain)))
	putU32(fileInode, 20, 0) // fragment 0
	putU32(fileInode, 24, 0) // fragment offset 0
	inodePayload = append(inodePayload, fileInode...)
	inodeBlock := sqMeta(inodePayload)
	dirTableStart := inodeTableStart + len(inodeBlock)
	dirBlock := sqMeta(listing)

	bytesUsed := dataOff + len(compressedTail)
	if want := dirTableStart + len(dirBlock); want > dataOff {
		t.Fatalf("fragment image metadata overlaps data: %d > %d", want, dataOff)
	}
	image := make([]byte, bytesUsed)
	copy(image[idBlockOff:], idBlock)
	copy(image[fragmentBlockOff:], fragmentBlock)
	putU64(image, idIndexOff, uint64(idBlockOff))
	putU64(image, fragmentIndexOff, uint64(fragmentBlockOff))
	copy(image[inodeTableStart:], inodeBlock)
	copy(image[dirTableStart:], dirBlock)
	copy(image[dataOff:], compressedTail)

	putU32(image, 0, 0x73717368)
	putU32(image, 4, 2)
	putU32(image, 8, 1_600_000_000)
	putU32(image, 12, testBlockSize)
	putU32(image, 16, 1) // one fragment
	putU16(image, 20, 1)
	putU16(image, 22, testBlockLog)
	putU16(image, 24, 0)
	putU16(image, 26, 2)
	putU16(image, 28, 4)
	putU16(image, 30, 0)
	putU64(image, 32, 0)
	putU64(image, 40, uint64(bytesUsed))
	putU64(image, 48, uint64(idIndexOff))
	putU64(image, 56, testInvalidTbl)
	putU64(image, 64, uint64(inodeTableStart))
	putU64(image, 72, uint64(dirTableStart))
	putU64(image, 80, uint64(fragmentIndexOff))
	putU64(image, 88, testInvalidTbl)
	return image
}

func TestFragmentTable(t *testing.T) {
	vol := openImage(t, buildFragmentImage(t))
	entry, err := vol.Stat("/tail.bin")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !entry.HasFragment || entry.Fragment != 0 {
		t.Errorf("fragment = %+v", entry)
	}
	if entry.Blocks != 0 {
		t.Errorf("a fragment-only file should have no data block entries, got %d", entry.Blocks)
	}
	if vol.Info().Fragments != 1 {
		t.Errorf("fragments = %d", vol.Info().Fragments)
	}
	file, err := vol.OpenFile("/tail.bin")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, len(tailPlain))
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, tailPlain) {
		t.Errorf("fragment tail = %q", buf)
	}
}

func openImage(t *testing.T, image []byte) *Volume {
	t.Helper()
	vol, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return vol
}

// ---- tests ---------------------------------------------------------------

func TestOpenInfoAndListing(t *testing.T) {
	vol := openImage(t, buildSquashImage(t, false))

	info := vol.Info()
	if info.Type != "SquashFS" {
		t.Errorf("type = %q", info.Type)
	}
	if info.Version != "4.0" {
		t.Errorf("version = %q", info.Version)
	}
	if info.BlockSize != testBlockSize {
		t.Errorf("block size = %d", info.BlockSize)
	}
	if info.Compression != "zlib" {
		t.Errorf("compression = %q", info.Compression)
	}
	if info.InodeCount != testInodeCount {
		t.Errorf("inode count = %d", info.InodeCount)
	}
	if info.Entries != 4 {
		t.Errorf("entries = %d", info.Entries)
	}
	if !info.Created.Equal(time.Unix(1_600_000_000, 0).UTC()) {
		t.Errorf("created = %v", info.Created)
	}
	if info.ExportInodes != testInodeCount || info.ExportBlocks != 1 || info.ExportError != "" {
		t.Errorf("export info = %+v", info)
	}

	root, err := vol.Stat("/")
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !root.IsDir || root.Name != "/" || root.Path != "/" {
		t.Errorf("root = %+v", root)
	}

	hello, err := vol.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("stat hello: %v", err)
	}
	if hello.IsDir || !hello.IsFile || hello.Size != uint64(len(helloPlain)) {
		t.Errorf("hello = %+v", hello)
	}
	if hello.Mode != 0o644 || hello.UID != 0 || hello.GID != 1000 {
		t.Errorf("hello owner/mode = %+v", hello)
	}
	if hello.InodeNumber != 3 || hello.InodeRef != 64 {
		t.Errorf("hello inode = %d ref %#x", hello.InodeNumber, hello.InodeRef)
	}
	if !hello.Modified.Equal(time.Unix(1_700_000_000, 0).UTC()) {
		t.Errorf("hello modified = %v", hello.Modified)
	}
	if hello.HasXattr {
		t.Errorf("hello should not carry an xattr index")
	}

	sub, err := vol.Stat("/sub")
	if err != nil {
		t.Fatalf("stat sub: %v", err)
	}
	if !sub.IsDir {
		t.Errorf("sub not a directory: %+v", sub)
	}

	entries, err := vol.ListDir("/")
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("root entries = %d", len(entries))
	}
	names := []string{entries[0].Name, entries[1].Name, entries[2].Name}
	want := []string{"sub", "hello.txt", "compressed.txt"}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, names[i], want[i])
		}
	}
	if entries[1].Path != "/hello.txt" {
		t.Errorf("entry path = %q", entries[1].Path)
	}

	empty, err := vol.ListDir("/sub")
	if err != nil {
		t.Fatalf("list sub: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("sub entries = %d", len(empty))
	}

	if _, err := vol.ListDir("/nope"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing dir error = %v", err)
	}
	if _, err := vol.Stat("/nope"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing stat error = %v", err)
	}
	if _, err := vol.ListDir("/hello.txt"); err == nil {
		t.Errorf("listing a file should fail")
	}
}

func TestOpenFileReads(t *testing.T) {
	vol := openImage(t, buildSquashImage(t, false))

	hello, err := vol.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("open hello: %v", err)
	}
	if hello.Len() != uint64(len(helloPlain)) {
		t.Fatalf("hello length = %d", hello.Len())
	}
	buf := make([]byte, len(helloPlain))
	if err := source.ReadExactAt(hello, 0, buf); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if !bytes.Equal(buf, helloPlain) {
		t.Errorf("hello = %q", buf)
	}
	if _, err := hello.ReadAt(hello.Len(), make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("read past end = %v", err)
	}

	compressed, err := vol.OpenFile("/compressed.txt")
	if err != nil {
		t.Fatalf("open compressed: %v", err)
	}
	cbuf := make([]byte, len(helloCompressedPlain))
	if err := source.ReadExactAt(compressed, 0, cbuf); err != nil {
		t.Fatalf("read compressed: %v", err)
	}
	if !bytes.Equal(cbuf, helloCompressedPlain) {
		t.Errorf("compressed = %q", cbuf)
	}

	if _, err := vol.OpenFile("/sub"); err == nil {
		t.Errorf("opening a directory should fail")
	}
	if _, err := vol.OpenFile("/nope"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing file error = %v", err)
	}

	// The extents name the physical data block.
	ranges, err := hello.Extents(0, uint64(len(helloPlain)))
	if err != nil {
		t.Fatalf("extents: %v", err)
	}
	if len(ranges) != 1 || ranges[0].ParentOffset != testDataOffset || ranges[0].Kind != source.RangeData {
		t.Errorf("extents = %+v", ranges)
	}
}

func TestXattrsAndExport(t *testing.T) {
	vol := openImage(t, buildSquashImage(t, false))

	entry, err := vol.Stat("/compressed.txt")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !entry.HasXattr {
		t.Fatalf("extended inode should report an xattr index")
	}
	list, err := vol.Xattrs("/compressed.txt")
	if err != nil {
		t.Fatalf("xattrs: %v", err)
	}
	if len(list.Attributes) != 1 {
		t.Fatalf("attributes = %d", len(list.Attributes))
	}
	attr := list.Attributes[0]
	if attr.FullName != "user.comment" || attr.Name != "comment" || attr.Namespace != "user" {
		t.Errorf("attr = %+v", attr)
	}
	if string(attr.Value) != "hi" || attr.OutOfLine {
		t.Errorf("attr value = %q out-of-line=%v", attr.Value, attr.OutOfLine)
	}

	if _, err := vol.InodeByNumber(100); err == nil {
		t.Errorf("inode 100 should be outside the table")
	}
	inode, err := vol.InodeByNumber(3)
	if err != nil {
		t.Fatalf("inode 3: %v", err)
	}
	if inode.InodeNumber != 3 || inode.Size != uint64(len(helloPlain)) || !inode.IsFile {
		t.Errorf("inode 3 = %+v", inode)
	}
	if _, err := vol.InodeByNumber(4); err != nil {
		t.Fatalf("inode 4: %v", err)
	}
}

func TestCompressedMetadata(t *testing.T) {
	vol := openImage(t, buildSquashImage(t, true))
	entries, err := vol.ListDir("/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d", len(entries))
	}
	file, err := vol.OpenFile("/compressed.txt")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, len(helloCompressedPlain))
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, helloCompressedPlain) {
		t.Errorf("payload = %q", buf)
	}
}

func TestUnsupportedCompression(t *testing.T) {
	// Zstandard is the one compressor this build has no decoder for.
	if _, err := decompressBlock(6, []byte{0}, testBlockSize); !errors.Is(err, ErrUnsupported) {
		t.Errorf("zstd error = %v, want unsupported", err)
	} else if !bytes.Contains([]byte(err.Error()), []byte("zstd")) {
		t.Errorf("zstd error = %v, want name %q", err, "zstd")
	}

	// A zlib block still decodes.
	plain := []byte("metadata payload")
	decoded, err := decompressBlock(1, deflateRaw(t, plain), testBlockSize)
	if err != nil {
		t.Fatalf("zlib decompress: %v", err)
	}
	if !bytes.Equal(decoded, plain) {
		t.Errorf("zlib decoded = %q", decoded)
	}

	// An image that declares Zstandard and stores a compressed metadata block
	// is refused by name at mount time.
	image := buildSquashImage(t, false)
	putU16(image, 20, 6) // compression = zstd
	idHeader := uint16(image[96]) | uint16(image[97])<<8
	putU16(image, 96, idHeader&0x7FFF) // clear the uncompressed bit
	_, err = Open(source.NewMemorySource(1, image))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("open zstd image error = %v, want unsupported", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("zstd")) {
		t.Errorf("error %v does not name zstd", err)
	}
}

func TestCorruptAndTruncated(t *testing.T) {
	good := buildSquashImage(t, false)

	if _, err := Open(source.NewMemorySource(1, good[:50])); err == nil {
		t.Errorf("short image should fail")
	}

	badMagic := append([]byte{}, good...)
	badMagic[0] = 'x'
	if _, err := Open(source.NewMemorySource(1, badMagic)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("bad magic error = %v", err)
	}

	badVersion := append([]byte{}, good...)
	putU16(badVersion, 28, 3)
	if _, err := Open(source.NewMemorySource(1, badVersion)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("version error = %v", err)
	}

	badLog := append([]byte{}, good...)
	putU16(badLog, 22, 10)
	if _, err := Open(source.NewMemorySource(1, badLog)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("block log error = %v", err)
	}

	// A directory header that claims more than 256 entries.
	header := make([]byte, 12)
	putU32(header, 0, 300)
	if _, err := parseDir(header); !errors.Is(err, ErrCorrupt) {
		t.Errorf("directory count error = %v", err)
	}
	if _, err := parseDir([]byte{1, 2, 3}); !errors.Is(err, ErrCorrupt) {
		t.Errorf("truncated directory header error = %v", err)
	}

	// A metadata block header that claims more than 8192 stored bytes.
	block := make([]byte, 4)
	putU16(block, 0, 9000)
	if _, err := readMetadataBlock(source.NewMemorySource(1, block), 1, 0); !errors.Is(err, ErrCorrupt) {
		t.Errorf("oversized metadata error = %v", err)
	}

	// An inode type that does not exist.
	inode := make([]byte, 32)
	putU16(inode, 0, 99)
	if _, err := parseInode(inode, testBlockSize); !errors.Is(err, ErrCorrupt) {
		t.Errorf("inode type error = %v", err)
	}
}

func TestDetect(t *testing.T) {
	good := buildSquashImage(t, false)
	ok, err := Detect(source.NewMemorySource(1, good))
	if err != nil || !ok {
		t.Errorf("Detect(valid) = %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, []byte("not squashfs")))
	if err != nil || ok {
		t.Errorf("Detect(invalid) = %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, nil))
	if err != nil || ok {
		t.Errorf("Detect(empty) = %v, %v", ok, err)
	}
}
