package reiserfs

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	rsBlockSize  = 4096
	rsBlockCount = 64
)

// ---- little-endian fixture helpers -----------------------------------------

func rsPutU16(dst []byte, at int, value uint16) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
}

func rsPutU32(dst []byte, at int, value uint32) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
	dst[at+2] = byte(value >> 16)
	dst[at+3] = byte(value >> 24)
}

func rsPutU64(dst []byte, at int, value uint64) {
	rsPutU32(dst, at, uint32(value))
	rsPutU32(dst, at+4, uint32(value>>32))
}

type rsKey struct {
	dirID    uint32
	objectID uint32
	offset   uint64
	typ      uint8
}

const (
	rsTypeStat     uint8 = 0
	rsTypeIndirect uint8 = 1
	rsTypeDirect   uint8 = 2
	rsTypeDir      uint8 = 3
	rsTypeUnknown  uint8 = 9
)

type rsItem struct {
	key   rsKey
	count uint16
	body  []byte
}

func rsWriteKey(dst []byte, at int, key rsKey, v2 bool) {
	rsPutU32(dst, at, key.dirID)
	rsPutU32(dst, at+4, key.objectID)
	if v2 {
		word := uint64(key.typ)<<60 | (key.offset & ((uint64(1) << 60) - 1))
		rsPutU64(dst, at+8, word)
		return
	}
	rsPutU32(dst, at+8, uint32(key.offset))
	var uniqueness uint32
	switch key.typ {
	case rsTypeStat:
		uniqueness = 0
	case rsTypeIndirect:
		uniqueness = 0xffff_fffe
	case rsTypeDirect:
		uniqueness = 0xffff_ffff
	case rsTypeDir:
		uniqueness = 500
	case 15:
		uniqueness = 555
	default:
		uniqueness = uint32(key.typ)
	}
	rsPutU32(dst, at+12, uniqueness)
}

func buildRSLeaf(block uint32, items []rsItem, v2 bool, blockSize int) []byte {
	raw := make([]byte, blockSize)
	rsPutU16(raw, 0, LEAF_LEVEL)
	rsPutU16(raw, 2, uint16(len(items)))
	headsEnd := BlockHeadLen + len(items)*ItemHeadLen
	cursor := blockSize
	for index, item := range items {
		cursor -= len(item.body)
		if cursor < headsEnd {
			panic("test leaf items do not fit")
		}
		at := BlockHeadLen + index*ItemHeadLen
		rsWriteKey(raw, at, item.key, v2)
		rsPutU16(raw, at+16, item.count)
		rsPutU16(raw, at+18, uint16(len(item.body)))
		rsPutU16(raw, at+20, uint16(cursor))
		if v2 {
			rsPutU16(raw, at+22, 1)
		}
		copy(raw[cursor:], item.body)
	}
	return raw
}

type rsDirEntry struct {
	name     string
	objectID uint32
	state    uint16
	offset   uint32
}

func rsDirBody(entries []rsDirEntry) []byte {
	headers := len(entries) * DEHeadLen
	names := 0
	for _, entry := range entries {
		names += len(entry.name)
	}
	body := make([]byte, headers+names)
	location := headers
	for index, entry := range entries {
		at := index * DEHeadLen
		rsPutU32(body, at, entry.offset)
		rsPutU32(body, at+4, 2)
		rsPutU32(body, at+8, entry.objectID)
		rsPutU16(body, at+12, uint16(location))
		rsPutU16(body, at+14, entry.state)
		copy(body[location:], entry.name)
		location += len(entry.name)
	}
	return body
}

func rsStatBody(v2 bool, mode uint16, nlink uint32, size uint64) []byte {
	if v2 {
		body := make([]byte, 44)
		rsPutU16(body, 0, mode)
		rsPutU16(body, 2, 3)
		rsPutU32(body, 4, nlink)
		rsPutU64(body, 8, size)
		rsPutU32(body, 16, 1000)
		rsPutU32(body, 20, 1000)
		rsPutU32(body, 24, 1_700_000_000)
		rsPutU32(body, 28, 1_700_000_100)
		rsPutU32(body, 32, 1_700_000_200)
		rsPutU32(body, 36, 20)
		rsPutU32(body, 40, 11)
		return body
	}
	body := make([]byte, 32)
	rsPutU16(body, 0, mode)
	rsPutU16(body, 2, uint16(nlink))
	rsPutU16(body, 4, 1000)
	rsPutU16(body, 6, 1000)
	rsPutU32(body, 8, uint32(size))
	rsPutU32(body, 12, 1_700_000_000)
	rsPutU32(body, 16, 1_700_000_100)
	rsPutU32(body, 20, 1_700_000_200)
	rsPutU32(body, 24, 20)
	rsPutU32(body, 28, 0xffff_ffff)
	return body
}

func rsStatKey(dirID, objectID uint32) rsKey {
	return rsKey{dirID: dirID, objectID: objectID, offset: 0, typ: rsTypeStat}
}

func rsDirKey(dirID, objectID uint32) rsKey {
	return rsKey{dirID: dirID, objectID: objectID, offset: 1, typ: rsTypeDir}
}

func rsDirectKey(dirID, objectID uint32, position uint64) rsKey {
	return rsKey{dirID: dirID, objectID: objectID, offset: position + 1, typ: rsTypeDirect}
}

func rsIndirectKey(dirID, objectID uint32, position uint64) rsKey {
	return rsKey{dirID: dirID, objectID: objectID, offset: position + 1, typ: rsTypeIndirect}
}

func standardItems(v2 bool) []rsItem {
	rootDir := rsDirBody([]rsDirEntry{
		{".", 2, DEHVisible, 0},
		{"..", 2, DEHVisible, 1},
		{"hello.txt", 3, DEHVisible, 2},
		{"sub", 4, DEHVisible, 3},
		{"link", 5, DEHVisible, 4},
		{"big.bin", 6, DEHVisible, 5},
		{"hidden", 7, 0, 6},
		{"flagged", 8, DEHVisible | DEHBadOffset | DEHBadLocation, 7},
		{"lnglink", 9, DEHVisible, 8},
		{"sparse", 12, DEHVisible, 9},
	})
	subDir := rsDirBody([]rsDirEntry{
		{".", 4, DEHVisible, 0},
		{"..", 2, DEHVisible, 1},
		{"inner.txt", 10, DEHVisible, 2},
		{"empty", 11, DEHVisible, 3},
	})
	emptyDir := rsDirBody([]rsDirEntry{
		{".", 11, DEHVisible, 0},
		{"..", 4, DEHVisible, 1},
	})
	direct := func(pos uint64, text string) []byte { return []byte(text) }
	return []rsItem{
		{key: rsStatKey(1, 2), body: rsStatBody(v2, S_IFDIR|0o755, 2, 0)},
		{key: rsDirKey(1, 2), count: 10, body: rootDir},
		{key: rsStatKey(2, 3), body: rsStatBody(v2, S_IFREG|0o644, 1, 13)},
		{key: rsDirectKey(2, 3, 0), body: direct(0, "hello reiser\n")},
		{key: rsStatKey(2, 4), body: rsStatBody(v2, S_IFDIR|0o755, 2, 0)},
		{key: rsDirKey(2, 4), count: 4, body: subDir},
		{key: rsStatKey(2, 5), body: rsStatBody(v2, S_IFLNK|0o777, 1, 10)},
		{key: rsDirectKey(2, 5, 0), body: direct(0, "/hello.txt")},
		{key: rsStatKey(2, 6), body: rsStatBody(v2, S_IFREG|0o644, 1, 4100)},
		{key: rsIndirectKey(2, 6, 0), body: []byte{6, 0, 0, 0}},
		{key: rsDirectKey(2, 6, 4096), body: []byte("tail")},
		{key: rsStatKey(2, 7), body: rsStatBody(v2, S_IFREG|0o644, 1, 4)},
		{key: rsDirectKey(2, 7, 0), body: []byte("gone")},
		{key: rsStatKey(2, 8), body: rsStatBody(v2, S_IFREG|0o644, 1, 3)},
		{key: rsDirectKey(2, 8, 0), body: []byte("bad")},
		{key: rsStatKey(2, 9), body: rsStatBody(v2, S_IFLNK|0o777, 1, 300)},
		{key: rsIndirectKey(2, 9, 0), body: []byte{9, 0, 0, 0}},
		{key: rsStatKey(4, 10), body: rsStatBody(v2, S_IFREG|0o644, 1, 6)},
		{key: rsDirectKey(4, 10, 0), body: []byte("inner\n")},
		{key: rsStatKey(2, 11), body: rsStatBody(v2, S_IFDIR|0o755, 2, 0)},
		{key: rsDirKey(2, 11), count: 2, body: emptyDir},
		{key: rsStatKey(2, 12), body: rsStatBody(v2, S_IFREG|0o644, 1, 3*rsBlockSize)},
		{key: rsIndirectKey(2, 12, 0), body: []byte{7, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0}},
	}
}

func standardExtras() map[uint32][]byte {
	longTarget := []byte(strings.Repeat("a/", 150))
	block6 := make([]byte, rsBlockSize)
	for index := range block6 {
		block6[index] = 'H'
	}
	copy(block6, "HEAD")
	block7 := make([]byte, rsBlockSize)
	for index := range block7 {
		block7[index] = 'S'
	}
	copy(block7, "SPARSE0")
	block8 := make([]byte, rsBlockSize)
	for index := range block8 {
		block8[index] = 'T'
	}
	copy(block8, "SPARSE2")
	block9 := make([]byte, rsBlockSize)
	copy(block9, longTarget)
	return map[uint32][]byte{
		6: block6,
		7: block7,
		8: block8,
		9: block9,
	}
}

type rsOptions struct {
	v2         bool
	offset     uint64
	hash       uint32
	hashSet    bool
	blockCount uint32
	rootBlock  uint32
	treeHeight uint16
	items      []rsItem
	rootRaw    []byte
	extra      map[uint32][]byte
	free       []uint32
}

func reiserImage(t *testing.T, opts rsOptions) []byte {
	t.Helper()
	if opts.blockCount == 0 {
		opts.blockCount = rsBlockCount
	}
	if opts.rootBlock == 0 {
		opts.rootBlock = 4
	}
	if opts.offset == 0 {
		opts.offset = SuperblockOffset35
	}
	if !opts.hashSet {
		if opts.v2 {
			opts.hash = HashR5Code
		} else {
			opts.hash = HashUnsetCode
		}
	}
	if opts.treeHeight == 0 {
		opts.treeHeight = 1
	}
	if opts.items == nil && opts.rootRaw == nil {
		opts.items = standardItems(opts.v2)
	}
	if opts.extra == nil && opts.items != nil {
		opts.extra = standardExtras()
	}
	data := make([]byte, int(opts.blockCount)*rsBlockSize)
	if opts.rootRaw == nil {
		opts.rootRaw = buildRSLeaf(opts.rootBlock, opts.items, opts.v2, rsBlockSize)
	}
	copy(data[int(opts.rootBlock)*rsBlockSize:], opts.rootRaw)
	for block, raw := range opts.extra {
		copy(data[int(block)*rsBlockSize:], raw)
	}

	// Bitmap: every block allocated except the requested free list.
	bitmapBlock := uint32(opts.offset/rsBlockSize + 1)
	if opts.offset != SuperblockOffset35 {
		bitmapBlock = uint32(SuperblockOffset36/rsBlockSize + 1)
	}
	bitmap := make([]byte, rsBlockSize)
	for block := uint32(0); block < opts.blockCount; block++ {
		bitmap[block/8] |= 1 << (block % 8)
	}
	for _, block := range opts.free {
		if block >= opts.blockCount {
			t.Fatalf("free block %d outside fixture", block)
		}
		bitmap[block/8] &^= 1 << (block % 8)
	}
	copy(data[int(bitmapBlock)*rsBlockSize:], bitmap)

	sb := make([]byte, SuperblockLen)
	rsPutU32(sb, 0x00, opts.blockCount)
	rsPutU32(sb, 0x04, uint32(len(opts.free)))
	rsPutU32(sb, 0x08, opts.rootBlock)
	rsPutU32(sb, 0x0C, 5)
	rsPutU32(sb, 0x10, 0)
	rsPutU32(sb, 0x14, 1)
	rsPutU32(sb, 0x18, 4)
	rsPutU32(sb, 0x1C, 1)
	rsPutU32(sb, 0x20, 900)
	rsPutU32(sb, 0x24, 5)
	rsPutU32(sb, 0x28, 30)
	rsPutU16(sb, 0x2C, rsBlockSize)
	rsPutU16(sb, 0x2E, 512)
	rsPutU16(sb, 0x30, 3)
	rsPutU16(sb, 0x32, FSCleanlyUnmounted)
	if opts.v2 {
		copy(sb[0x34:], Magic36)
	} else {
		copy(sb[0x34:], Magic35)
	}
	rsPutU16(sb, 0x3E, FSConsistent)
	rsPutU32(sb, 0x40, opts.hash)
	rsPutU16(sb, 0x44, opts.treeHeight)
	rsPutU16(sb, 0x46, 1)
	if opts.v2 {
		rsPutU16(sb, 0x48, 2)
	} else {
		rsPutU16(sb, 0x48, 0)
	}
	rsPutU16(sb, 0x4A, 0)
	rsPutU32(sb, 0x4C, 7)
	rsPutU32(sb, 0x50, 0)
	for index := 0; index < 16; index++ {
		sb[0x54+index] = byte(0x10 + index)
	}
	copy(sb[0x64:0x74], []byte("ReiserFS fixture"))
	if opts.v2 {
		rsPutU16(sb, 0x74, 12)
		rsPutU16(sb, 0x76, 30)
		rsPutU32(sb, 0x78, 1_700_000_000)
		rsPutU32(sb, 0x7C, 15_552_000)
	}
	copy(data[int(opts.offset):], sb)
	return data
}

func openReiser(t *testing.T, data []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func standardReiser(t *testing.T) *Volume {
	return openReiser(t, reiserImage(t, rsOptions{v2: true, free: []uint32{16, 17, 18, 19, 20}}))
}

// ---- detection and geometry ------------------------------------------------

func TestReiserDetect(t *testing.T) {
	if found, err := Detect(source.NewMemorySource(1, make([]byte, SuperblockOffset35))); err != nil || found {
		t.Fatalf("short source: found=%v err=%v", found, err)
	}
	zero := make([]byte, rsBlockCount*rsBlockSize)
	if found, err := Detect(source.NewMemorySource(1, zero)); err != nil || found {
		t.Fatalf("no magic: found=%v err=%v", found, err)
	}
	image := reiserImage(t, rsOptions{v2: true, free: []uint32{16, 17, 18, 19, 20}})
	if found, err := Detect(source.NewMemorySource(1, image)); err != nil || !found {
		t.Fatalf("fixture: found=%v err=%v", found, err)
	}

	bad := reiserImage(t, rsOptions{v2: true})
	rsPutU16(bad, int(SuperblockOffset35)+0x2C, 3000)
	if _, err := Detect(source.NewMemorySource(1, bad)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad block size error = %v", err)
	}

	bad = reiserImage(t, rsOptions{v2: true})
	rsPutU32(bad, int(SuperblockOffset35)+0x00, rsBlockCount+1)
	if _, err := Detect(source.NewMemorySource(1, bad)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("declared size error = %v", err)
	}

	bad = reiserImage(t, rsOptions{v2: true, hash: 9, hashSet: true})
	if _, err := Detect(source.NewMemorySource(1, bad)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown hash error = %v", err)
	}
}

func TestReiserInfo(t *testing.T) {
	volume := standardReiser(t)
	info := volume.Info()
	if info.Version != V36 || info.Kind != "reiserfs3.6" {
		t.Fatalf("version = %v %q", info.Version, info.Kind)
	}
	if info.BlockSize != rsBlockSize || info.BlockCount != rsBlockCount {
		t.Fatalf("geometry = %+v", info)
	}
	if info.RootBlock != 4 || info.TreeHeight != 1 || info.BmapCount != 1 {
		t.Fatalf("tree = %+v", info)
	}
	if info.Label != "ReiserFS fixture" {
		t.Fatalf("label = %q", info.Label)
	}
	if info.UUID != "10111213-1415-1617-1819-1a1b1c1d1e1f" {
		t.Fatalf("uuid = %q", info.UUID)
	}
	if !info.Clean || info.FSStateName != "consistent" || info.UmountStateName != "cleanly unmounted" {
		t.Fatalf("state = %+v", info)
	}
	if info.Hash != HashR5 || info.HashName != "r5" {
		t.Fatalf("hash = %v %q", info.Hash, info.HashName)
	}
	if info.MountCount == nil || *info.MountCount != 12 || info.LastCheck == nil {
		t.Fatalf("3.6 counters = %+v", info)
	}
}

// ---- directory and metadata ------------------------------------------------

func TestReiserListDir(t *testing.T) {
	volume := standardReiser(t)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	want := []string{"hello.txt", "sub", "link", "big.bin", "hidden", "flagged", "lnglink", "sparse"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v", names)
	}
	for _, entry := range entries {
		switch entry.Name {
		case "hello.txt":
			if entry.Inode != 3 || entry.IsDir || !entry.IsFile || entry.IsSymlink {
				t.Fatalf("hello = %+v", entry)
			}
			if entry.Path != "/hello.txt" || entry.Size != 13 || entry.Mode != S_IFREG|0o644 {
				t.Fatalf("hello metadata = %+v", entry)
			}
			if entry.UID != 1000 || entry.GID != 1000 || entry.Links != 1 {
				t.Fatalf("hello ownership = %+v", entry)
			}
			if !entry.Atime.Equal(time.Unix(1_700_000_000, 0).UTC()) {
				t.Fatalf("atime = %v", entry.Atime)
			}
			if entry.Deleted || entry.Hidden || entry.Flagged {
				t.Fatalf("hello flags = %+v", entry)
			}
		case "hidden":
			if !entry.Deleted || !entry.Hidden || entry.IsFile == false {
				t.Fatalf("hidden = %+v", entry)
			}
		case "flagged":
			if !entry.Flagged || !entry.BadOffset || !entry.BadLocation || entry.Deleted {
				t.Fatalf("flagged = %+v", entry)
			}
		case "sub":
			if !entry.IsDir || entry.Inode != 4 {
				t.Fatalf("sub = %+v", entry)
			}
		case "link":
			if !entry.IsSymlink || entry.Size != 10 {
				t.Fatalf("link = %+v", entry)
			}
		case "big.bin":
			if entry.Size != 4100 || !entry.IsFile {
				t.Fatalf("big = %+v", entry)
			}
		}
	}
}

func TestReiserStat(t *testing.T) {
	volume := standardReiser(t)
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	if root.Name != "/" || root.Path != "/" || !root.IsDir || root.Inode != RootObjectID {
		t.Fatalf("root = %+v", root)
	}
	inner, err := volume.Stat("/sub/inner.txt")
	if err != nil {
		t.Fatalf("Stat inner: %v", err)
	}
	if inner.Name != "inner.txt" || inner.Path != "/sub/inner.txt" || inner.Size != 6 {
		t.Fatalf("inner = %+v", inner)
	}
	if inner.ParentInode != 4 || inner.UID != 1000 {
		t.Fatalf("inner ownership = %+v", inner)
	}
	link, err := volume.Stat("/link")
	if err != nil {
		t.Fatalf("Stat link: %v", err)
	}
	if link.SymlinkTarget != "/hello.txt" {
		t.Fatalf("link target = %q", link.SymlinkTarget)
	}
	// A hidden name is listed but not resolvable.
	if _, err := volume.Stat("/hidden"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("hidden stat error = %v", err)
	}
}

func TestReiserPathErrors(t *testing.T) {
	volume := standardReiser(t)
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing stat error = %v", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing open error = %v", err)
	}
	if _, err := volume.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir file error = %v", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile dir error = %v", err)
	}
	if _, err := volume.SymlinkTarget("/hello.txt"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("SymlinkTarget file error = %v", err)
	}
}

func TestReiserEmptyDir(t *testing.T) {
	volume := standardReiser(t)
	entries, err := volume.ListDir("/sub/empty")
	if err != nil {
		t.Fatalf("ListDir empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty dir has %d entries", len(entries))
	}
}

// ---- file data -------------------------------------------------------------

func TestReiserReadDirect(t *testing.T) {
	volume := standardReiser(t)
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 13 {
		t.Fatalf("len = %d", file.Len())
	}
	buf := make([]byte, 13)
	if _, err := file.ReadAt(0, buf); err != nil || string(buf) != "hello reiser\n" {
		t.Fatalf("read = %q err=%v", buf, err)
	}
	part := make([]byte, 5)
	if _, err := file.ReadAt(6, part); err != nil || string(part) != "reise" {
		t.Fatalf("partial = %q err=%v", part, err)
	}
	tail := make([]byte, 32)
	got, err := file.ReadAt(8, tail)
	if err != nil || got != 5 || string(tail[:5]) != "iser\n" {
		t.Fatalf("tail = %q (%d) err=%v", tail[:got], got, err)
	}
	if _, err := file.ReadAt(13, tail); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("EOF error = %v", err)
	}
}

func TestReiserReadIndirectAndTail(t *testing.T) {
	volume := standardReiser(t)
	file, err := volume.OpenFile("/big.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 4100 {
		t.Fatalf("len = %d", file.Len())
	}
	buf := make([]byte, 4100)
	if _, err := file.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf[:4]) != "HEAD" {
		t.Fatalf("head = %q", buf[:4])
	}
	if string(buf[4096:]) != "tail" {
		t.Fatalf("tail = %q", buf[4096:])
	}
	if buf[4] != 'H' || buf[4095] != 'H' {
		t.Fatalf("indirect fill = %#x/%#x", buf[4], buf[4095])
	}
}

func TestReiserSparseHole(t *testing.T) {
	volume := standardReiser(t)
	file, err := volume.OpenFile("/sparse")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 3*rsBlockSize {
		t.Fatalf("len = %d", file.Len())
	}
	middle := make([]byte, rsBlockSize)
	if _, err := file.ReadAt(rsBlockSize, middle); err != nil {
		t.Fatalf("read hole: %v", err)
	}
	for _, value := range middle {
		if value != 0 {
			t.Fatalf("hole byte = %#x", value)
		}
	}
	first := make([]byte, 7)
	if _, err := file.ReadAt(0, first); err != nil || string(first) != "SPARSE0" {
		t.Fatalf("first = %q err=%v", first, err)
	}
	last := make([]byte, 7)
	if _, err := file.ReadAt(2*rsBlockSize, last); err != nil || string(last) != "SPARSE2" {
		t.Fatalf("last = %q err=%v", last, err)
	}
	ranges, err := file.Extents(0, 3*rsBlockSize)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 3 || ranges[0].Kind != source.RangeData ||
		ranges[1].Kind != source.RangeHole || ranges[2].Kind != source.RangeData {
		t.Fatalf("ranges = %+v", ranges)
	}
}

func TestReiserSymlinks(t *testing.T) {
	volume := standardReiser(t)
	fast, err := volume.SymlinkTarget("/link")
	if err != nil || fast != "/hello.txt" {
		t.Fatalf("fast target = %q err=%v", fast, err)
	}
	long, err := volume.SymlinkTarget("/lnglink")
	if err != nil {
		t.Fatalf("long target: %v", err)
	}
	if long != strings.Repeat("a/", 150) {
		t.Fatalf("long target = %q", long)
	}
}

func TestReiserStats(t *testing.T) {
	volume := standardReiser(t)
	stats, err := volume.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Directories != 3 || stats.Files != 5 || stats.Symlinks != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.Entries != 9 || stats.RemovedNames != 1 || stats.FlaggedNames != 1 {
		t.Fatalf("name stats = %+v", stats)
	}
}

// ---- free space ------------------------------------------------------------

func TestReiserFreeSpace(t *testing.T) {
	volume := standardReiser(t)
	free, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if free.RecordedFree != 5 || free.ScannedFree != 5 {
		t.Fatalf("free counts = %+v", free)
	}
	if free.Space.Basis() != "reiserfs.bitmap" || free.OldFormat != true {
		t.Fatalf("basis/format = %q/%v", free.Space.Basis(), free.OldFormat)
	}
	if free.Space.FreeBytes() != 5*rsBlockSize {
		t.Fatalf("free bytes = %d", free.Space.FreeBytes())
	}
	runs := free.Space.Runs()
	if len(runs) != 1 || runs[0].Offset != 16*rsBlockSize || runs[0].Len != 5*rsBlockSize {
		t.Fatalf("runs = %+v", runs)
	}
	if !free.Space.IsFree(17*rsBlockSize, rsBlockSize) {
		t.Fatalf("block 17 not free")
	}
	if free.Space.IsFree(0, rsBlockSize) {
		t.Fatalf("block 0 reported free")
	}
}

// ---- versions, offsets and hashes ------------------------------------------

func TestReiser35Layout(t *testing.T) {
	volume := openReiser(t, reiserImage(t, rsOptions{v2: false, free: []uint32{16, 17, 18, 19, 20}}))
	info := volume.Info()
	if info.Version != V35 || info.Kind != "reiserfs3.5" {
		t.Fatalf("version = %v %q", info.Version, info.Kind)
	}
	if info.MountCount != nil || info.LastCheck != nil {
		t.Fatalf("3.5 counters leaked: %+v", info)
	}
	if info.Hash != HashUnset || info.HashName != "unset" {
		t.Fatalf("hash = %v %q", info.Hash, info.HashName)
	}
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 8 {
		t.Fatalf("entries = %d", len(entries))
	}
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 13)
	if _, err := file.ReadAt(0, buf); err != nil || string(buf) != "hello reiser\n" {
		t.Fatalf("read = %q err=%v", buf, err)
	}
	stat, err := volume.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if stat.Size != 13 || stat.Links != 1 || stat.UID != 1000 {
		t.Fatalf("3.5 stat = %+v", stat)
	}
}

func TestReiserNewSuperblockOffset(t *testing.T) {
	data := reiserImage(t, rsOptions{v2: true, offset: SuperblockOffset36})
	if found, err := Detect(source.NewMemorySource(1, data)); err != nil || !found {
		t.Fatalf("Detect at 64 KiB: found=%v err=%v", found, err)
	}
	volume := openReiser(t, data)
	if volume.Info().Offset != SuperblockOffset36 {
		t.Fatalf("superblock offset = %d", volume.Info().Offset)
	}
	entries, err := volume.ListDir("/")
	if err != nil || len(entries) != 8 {
		t.Fatalf("ListDir = %d entries, err=%v", len(entries), err)
	}
	free, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if free.OldFormat {
		t.Fatalf("64 KiB volume reported old-format bitmaps")
	}
}

func TestReiserHashVariants(t *testing.T) {
	cases := []struct {
		code uint32
		name string
	}{
		{HashUnsetCode, "unset"},
		{HashTeaCode, "tea"},
		{HashYuraCode, "rupasov"},
		{HashR5Code, "r5"},
	}
	for _, tc := range cases {
		volume := openReiser(t, reiserImage(t, rsOptions{v2: true, hash: tc.code, hashSet: true}))
		info := volume.Info()
		if info.HashName != tc.name || uint32(info.Hash) != tc.code {
			t.Fatalf("hash %d = %v %q, want %q", tc.code, info.Hash, info.HashName, tc.name)
		}
		if _, err := volume.ListDir("/"); err != nil {
			t.Fatalf("hash %d ListDir: %v", tc.code, err)
		}
	}
}

// ---- tree shape and corruption ---------------------------------------------

func TestReiserInternalTree(t *testing.T) {
	all := standardItems(true)
	leaf10 := buildRSLeaf(10, all[:2], true, rsBlockSize) // root stat + root directory
	leaf11 := buildRSLeaf(11, all[2:], true, rsBlockSize) // everything else
	root := make([]byte, rsBlockSize)
	rsPutU16(root, 0, 2) // internal level
	rsPutU16(root, 2, 1) // one key
	rsWriteKey(root, BlockHeadLen, rsStatKey(1, 2), true)
	childAt := BlockHeadLen + KeyLen
	rsPutU32(root, childAt, 10)
	rsPutU16(root, childAt+4, 2)
	rsPutU32(root, childAt+8, 11)
	rsPutU16(root, childAt+12, uint16(len(all)-2))

	data := reiserImage(t, rsOptions{
		v2:         true,
		treeHeight: 2,
		rootRaw:    root,
		extra:      map[uint32][]byte{10: leaf10, 11: leaf11},
		free:       []uint32{16, 17, 18, 19, 20},
	})
	volume := openReiser(t, data)
	items, err := volume.items()
	if err != nil {
		t.Fatalf("items: %v", err)
	}
	if len(items) != len(all) {
		t.Fatalf("items = %d, want %d", len(items), len(all))
	}
	if entries, err := volume.ListDir("/"); err != nil || len(entries) != 8 {
		t.Fatalf("ListDir = %d entries, err=%v", len(entries), err)
	}
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 13)
	if _, err := file.ReadAt(0, buf); err != nil || string(buf) != "hello reiser\n" {
		t.Fatalf("read = %q err=%v", buf, err)
	}
}

func TestReiserCorruption(t *testing.T) {
	// A root leaf below the height the superblock records.
	image := reiserImage(t, rsOptions{v2: true, treeHeight: 2})
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("root level error = %v", err)
	}

	// A tree that points at itself.
	loop := make([]byte, rsBlockSize)
	rsPutU16(loop, 0, 2)
	rsPutU16(loop, 2, 1)
	rsPutU32(loop, BlockHeadLen+KeyLen, 4) // child is the root itself
	image = reiserImage(t, rsOptions{v2: true, treeHeight: 2, rootRaw: loop})
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tree loop error = %v", err)
	}

	// An item body that runs past its node.
	bad := make([]byte, rsBlockSize)
	rsPutU16(bad, 0, LEAF_LEVEL)
	rsPutU16(bad, 2, 1)
	rsPutU16(bad, BlockHeadLen+18, 5000)
	rsPutU16(bad, BlockHeadLen+20, 100)
	image = reiserImage(t, rsOptions{v2: true, rootRaw: bad})
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("item overrun error = %v", err)
	}

	// An item type the reader does not decode, attached to a file.
	items := standardItems(true)
	items = append(items, rsItem{
		key:  rsKey{dirID: 2, objectID: 3, offset: 99, typ: rsTypeUnknown},
		body: []byte("mystery"),
	})
	volume := openReiser(t, reiserImage(t, rsOptions{v2: true, items: items}))
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown item error = %v", err)
	}

	// An indirect pointer past the volume.
	items = standardItems(true)
	for index := range items {
		if items[index].key.objectID == 6 && items[index].key.typ == rsTypeIndirect {
			items[index].body = []byte{0xE8, 0x03, 0, 0} // 1000
		}
	}
	volume = openReiser(t, reiserImage(t, rsOptions{v2: true, items: items}))
	if _, err := volume.OpenFile("/big.bin"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("pointer past volume error = %v", err)
	}

	// A file-data key offset of zero.
	items = standardItems(true)
	for index := range items {
		if items[index].key.objectID == 6 && items[index].key.typ == rsTypeIndirect {
			items[index].key.offset = 0
		}
	}
	volume = openReiser(t, reiserImage(t, rsOptions{v2: true, items: items}))
	if _, err := volume.OpenFile("/big.bin"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("zero key offset error = %v", err)
	}

	// Data items whose logical ranges overlap.
	items = standardItems(true)
	for index := range items {
		if items[index].key.objectID == 6 && items[index].key.typ == rsTypeDirect {
			items[index].key.offset = 1 // logical byte 0, where the indirect item starts
		}
	}
	volume = openReiser(t, reiserImage(t, rsOptions{v2: true, items: items}))
	if _, err := volume.OpenFile("/big.bin"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("overlap error = %v", err)
	}

	// A directory name location inside the header table.
	items = standardItems(true)
	for index := range items {
		if items[index].key.objectID == 2 && items[index].key.typ == rsTypeDir {
			body := items[index].body
			rsPutU16(body, 12, 0)
		}
	}
	volume = openReiser(t, reiserImage(t, rsOptions{v2: true, items: items}))
	if _, err := volume.ListDir("/"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad name location error = %v", err)
	}

	// A child pointer past the volume.
	image = reiserImage(t, rsOptions{v2: true, treeHeight: 2, rootRaw: func() []byte {
		raw := make([]byte, rsBlockSize)
		rsPutU16(raw, 0, 2)
		rsPutU16(raw, 2, 1)
		rsPutU32(raw, BlockHeadLen+KeyLen, 1000)
		return raw
	}()})
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("child outside volume error = %v", err)
	}
}

func TestReiserNameEdgeCases(t *testing.T) {
	body := make([]byte, DEHeadLen+8)
	rsPutU32(body, 0, 1)
	rsPutU32(body, 4, 2)
	rsPutU32(body, 8, 3)
	rsPutU16(body, 12, DEHeadLen)
	rsPutU16(body, 14, DEHVisible)
	copy(body[DEHeadLen:], []byte{'a', 0xff, 'b', 0, 0, 0, 0, 0})
	entries, err := parseDirectoryItem(body, 1)
	if err != nil {
		t.Fatalf("parseDirectoryItem: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name, "a") || !strings.Contains(entries[0].Name, "�") {
		t.Fatalf("lossy name = %q", entries[0].Name)
	}
	if strings.Contains(entries[0].Name, "\x00") {
		t.Fatalf("trailing NUL not trimmed: %q", entries[0].Name)
	}

	// A directory tail typed as a direct item with entries is still a
	// directory body; one with a body but no count is refused.
	tail := rsDirBody([]rsDirEntry{{"tail.txt", 7, DEHVisible, 0}})
	tailEntries, err := parseDirectoryTail(tail, 1)
	if err != nil || len(tailEntries) != 1 || tailEntries[0].Name != "tail.txt" {
		t.Fatalf("tail = %+v err=%v", tailEntries, err)
	}
	if _, err := parseDirectoryTail(tail, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("zero-count tail error = %v", err)
	}
}

func TestReiserDeletedScanUnsupported(t *testing.T) {
	volume := standardReiser(t)
	if err := volume.DeletedScan(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("DeletedScan error = %v", err)
	}
}

func TestReiserPrimitives(t *testing.T) {
	// V2 key round trip.
	raw := make([]byte, KeyLen)
	key := rsKey{dirID: 2, objectID: 3, offset: 0x0abc_def0_1234_5678, typ: rsTypeDirect}
	rsWriteKey(raw, 0, key, true)
	parsed, err := ParseKey(raw, 0, KeyVersionV2)
	if err != nil || parsed.DirID != 2 || parsed.ObjectID != 3 || parsed.Offset != key.offset ||
		parsed.ItemType != ItemTypeDirect {
		t.Fatalf("v2 key = %+v err=%v", parsed, err)
	}
	// V1 key names its type by uniqueness.
	rsWriteKey(raw, 0, key, false)
	parsed, err = ParseKey(raw, 0, KeyVersionV1)
	if err != nil || parsed.ItemType != ItemTypeDirect || parsed.RawType != 0xffff_ffff {
		t.Fatalf("v1 key = %+v err=%v", parsed, err)
	}
	// An unknown type is preserved, not guessed.
	raw = make([]byte, KeyLen)
	rsWriteKey(raw, 0, rsKey{dirID: 4, objectID: 5, offset: 0, typ: 9}, true)
	parsed, err = ParseKey(raw, 0, KeyVersionV2)
	if err != nil || parsed.ItemType != ItemTypeUnknown || parsed.RawType != 9 {
		t.Fatalf("unknown key = %+v err=%v", parsed, err)
	}
}

func TestReiserJournalMagic(t *testing.T) {
	data := reiserImage(t, rsOptions{v2: true})
	copy(data[int(SuperblockOffset35)+0x34:], Magic36Journal)
	sb, err := ReadSuperblock(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("ReadSuperblock: %v", err)
	}
	if sb.Version != V36Journal || sb.Kind() != "reiserfs3.6" {
		t.Fatalf("journal version = %v %q", sb.Version, sb.Kind())
	}
	volume := openReiser(t, data)
	if volume.Info().Version != V36Journal {
		t.Fatalf("volume version = %v", volume.Info().Version)
	}
	if _, err := volume.ListDir("/"); err != nil {
		t.Fatalf("ListDir: %v", err)
	}
}

func TestReiserSuperblockValidation(t *testing.T) {
	cases := []struct {
		name   string
		offset int
		value  uint32
		wide   bool
	}{
		{"root block", 0x08, 99, true},
		{"tree height", 0x44, 0, false},
		{"journal block", 0x0C, rsBlockCount, true},
		{"bitmap count", 0x46, 0, false},
		{"block size", 0x2C, 3000, false},
	}
	for _, tc := range cases {
		data := reiserImage(t, rsOptions{v2: true})
		at := int(SuperblockOffset35) + tc.offset
		if tc.wide {
			rsPutU32(data, at, tc.value)
		} else {
			rsPutU16(data, at, uint16(tc.value))
		}
		if _, err := Detect(source.NewMemorySource(1, data)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s error = %v", tc.name, err)
		}
	}
	if _, err := ParseSuperblock(make([]byte, 10), SuperblockOffset35, V36); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short parse error = %v", err)
	}
	// A declared volume larger than the image is refused before any read.
	data := reiserImage(t, rsOptions{v2: true})
	if _, err := Detect(source.NewMemorySource(1, data[:50*rsBlockSize])); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated volume error = %v", err)
	}
}

func TestBitmapGeometry(t *testing.T) {
	old := &Superblock{Offset: SuperblockOffset35, BlockSize: 4096, BlockCount: 64}
	if got := bitmapCount(old); got != 1 {
		t.Fatalf("old count = %d", got)
	}
	if got := bitmapBlock(old, 0); got != 3 {
		t.Fatalf("old first bitmap = %d", got)
	}
	if got := bitmapBlock(old, 1); got != 4 {
		t.Fatalf("old second bitmap = %d", got)
	}
	newer := &Superblock{Offset: SuperblockOffset36, BlockSize: 4096, BlockCount: 1_000_000}
	if got := bitmapCount(newer); got != 31 {
		t.Fatalf("new count = %d", got)
	}
	if got := bitmapBlock(newer, 0); got != 17 {
		t.Fatalf("new first bitmap = %d", got)
	}
	if got := bitmapBlock(newer, 1); got != 32_768 {
		t.Fatalf("new second bitmap = %d", got)
	}
	small := &Superblock{Offset: SuperblockOffset35, BlockSize: 1024, BlockCount: 8_193}
	if got := bitmapCount(small); got != 2 {
		t.Fatalf("1 KiB count = %d", got)
	}
	if got := bitmapBlock(small, 0); got != 9 {
		t.Fatalf("1 KiB first bitmap = %d", got)
	}
}

func TestReiserFileSourceLossyAndImageMapping(t *testing.T) {
	volume := standardReiser(t)
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	lossy := make([]byte, 5)
	got, err := file.ReadAtLossy(0, lossy)
	if err != nil || got != 5 || string(lossy) != "hello" {
		t.Fatalf("lossy = %q (%d) err=%v", lossy, got, err)
	}
	if _, err := file.ReadAtLossy(13, lossy); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy EOF error = %v", err)
	}
	ranges, err := file.MapToImage(0, 5)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(ranges) != 1 || ranges[0].Len != 5 || ranges[0].Kind != source.RangeData {
		t.Fatalf("image ranges = %+v", ranges)
	}
}
