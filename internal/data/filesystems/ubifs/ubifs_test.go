package ubifs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testLEB      = 16384
	testLEBCnt   = 32
	testMasterSq = 100
)

func put32(bytes []byte, at int, value uint32) {
	binary.LittleEndian.PutUint32(bytes[at:], value)
}

func put64(bytes []byte, at int, value uint64) {
	binary.LittleEndian.PutUint64(bytes[at:], value)
}

func nodeBytes(nodeType uint8, length int, sqnum uint64) []byte {
	bytes := make([]byte, length)
	put32(bytes, 0, Magic)
	put64(bytes, 8, sqnum)
	put32(bytes, 16, uint32(length))
	bytes[20] = nodeType
	return bytes
}

func seal(bytes []byte) {
	put32(bytes, 4, foundation.CRC32Seeded(0xFFFF_FFFF, bytes[8:]))
}

func keyBytes(inum, kind, pos uint32) []byte {
	bytes := make([]byte, KeyBytes)
	put32(bytes, 0, inum)
	put32(bytes, 4, kind)
	put32(bytes, 8, pos)
	return bytes
}

func superblockBytes(lebSize uint32, lebCount uint32) []byte {
	bytes := nodeBytes(NodeSuperblock, MasterPage, 1)
	bytes[24] = 0
	bytes[25] = 0
	put32(bytes, 28, 0)
	put32(bytes, 32, 512)
	put32(bytes, 36, lebSize)
	put32(bytes, 40, lebCount)
	put32(bytes, 44, lebCount)
	put32(bytes, 72, 8)
	put32(bytes, 80, 5)
	put32(bytes, 84, 0)
	for index := 0; index < 16; index++ {
		bytes[108+index] = 0xa5
	}
	seal(bytes)
	return bytes
}

func masterBytes(sqnum uint64, rootLnum, rootOffs, rootLen uint32) []byte {
	bytes := nodeBytes(NodeMaster, MasterPage, sqnum)
	put64(bytes, 24, 20)
	put64(bytes, 32, sqnum)
	put32(bytes, 48, rootLnum)
	put32(bytes, 52, rootOffs)
	put32(bytes, 56, rootLen)
	put32(bytes, 64, 1)
	put32(bytes, 68, 0)
	seal(bytes)
	return bytes
}

func inodeNode(inum uint32, mode uint32, size uint64, inline []byte) []byte {
	length := InodeFixed + len(inline)
	bytes := nodeBytes(NodeInode, length, 5)
	copy(bytes[24:40], keyBytes(inum, KeyIno, 0))
	put64(bytes, 56, size)
	put64(bytes, 64, 1_700_000_300)
	put32(bytes, 88, 111)
	put64(bytes, 72, 1_700_000_200)
	put32(bytes, 92, 333)
	put64(bytes, 80, 1_700_000_100)
	put32(bytes, 96, 222)
	put32(bytes, 100, 1)
	put32(bytes, 104, 1000)
	put32(bytes, 108, 1001)
	put32(bytes, 112, mode)
	put32(bytes, 120, uint32(len(inline)))
	copy(bytes[InodeFixed:], inline)
	seal(bytes)
	return bytes
}

func dentNode(parent, hash uint32, name string, inum uint64, dentType uint8) []byte {
	length := DentFixed + len(name)
	bytes := nodeBytes(NodeDent, length, 6)
	copy(bytes[24:40], keyBytes(parent, KeyDent, hash))
	put64(bytes, 40, inum)
	bytes[52] = dentType
	binary.LittleEndian.PutUint16(bytes[54:56], uint16(len(name)))
	copy(bytes[56:], name)
	seal(bytes)
	return bytes
}

func xentNode(parent, hash uint32, name string, inum uint64, dentType uint8) []byte {
	bytes := dentNode(parent, hash, name, inum, dentType)
	bytes[20] = NodeXent
	seal(bytes)
	return bytes
}

func dataNode(inum uint32, block uint32, blockSize uint32, compression uint16, payload []byte) []byte {
	length := DataFixed + len(payload)
	bytes := nodeBytes(NodeData, length, 7)
	copy(bytes[24:40], keyBytes(inum, KeyData, block))
	put32(bytes, 40, blockSize)
	binary.LittleEndian.PutUint16(bytes[44:46], compression)
	copy(bytes[48:], payload)
	seal(bytes)
	return bytes
}

type testLeaf struct {
	key  NodeKey
	node []byte
}

func makeVolumeWithLEB(t *testing.T, lebSize uint32, lebCount uint32, leaves []testLeaf) []byte {
	t.Helper()
	sort.SliceStable(leaves, func(left, right int) bool {
		leftKey, rightKey := leaves[left].key.order(), leaves[right].key.order()
		return leftKey[0] < rightKey[0] ||
			(leftKey[0] == rightKey[0] && (leftKey[1] < rightKey[1] ||
				(leftKey[1] == rightKey[1] && leftKey[2] < rightKey[2])))
	})
	image := make([]byte, int(lebSize)*int(lebCount))
	write := func(lnum uint32, bytes []byte) uint32 {
		if uint32(len(bytes)) > lebSize {
			t.Fatalf("node of %d bytes does not fit LEB %d", len(bytes), lebSize)
		}
		base := int(lnum) * int(lebSize)
		copy(image[base:base+int(lebSize)], bytes)
		return lnum
	}
	write(0, superblockBytes(lebSize, lebCount))
	const rootLEB = 3
	nextLEB := uint32(4)
	leafOffset := uint32(0)
	type branch struct {
		lnum uint32
		offs uint32
		len  uint32
		key  NodeKey
	}
	branches := make([]branch, 0, len(leaves))
	for _, leaf := range leaves {
		if uint32(len(leaf.node)) > lebSize {
			t.Fatalf("node of %d bytes does not fit LEB %d", len(leaf.node), lebSize)
		}
		if leafOffset+uint32(len(leaf.node)) > lebSize {
			nextLEB++
			leafOffset = 0
		}
		if nextLEB >= lebCount {
			t.Fatalf("test volume exhausted at %d leaves", len(leaves))
		}
		base := int(nextLEB)*int(lebSize) + int(leafOffset)
		copy(image[base:base+len(leaf.node)], leaf.node)
		branches = append(branches, branch{lnum: nextLEB, offs: leafOffset, len: uint32(len(leaf.node)), key: leaf.key})
		leafOffset += uint32(len(leaf.node))
	}
	indexLen := IndexFixed + len(branches)*(BranchFixed+KeyBytes)
	indexLen = (indexLen + 7) &^ 7
	index := nodeBytes(NodeIndex, indexLen, 8)
	binary.LittleEndian.PutUint16(index[24:26], uint16(len(branches)))
	binary.LittleEndian.PutUint16(index[26:28], 0)
	for child, entry := range branches {
		at := IndexFixed + child*(BranchFixed+KeyBytes)
		put32(index, at, entry.lnum)
		put32(index, at+4, entry.offs)
		put32(index, at+8, entry.len)
		copy(index[at+BranchFixed:at+BranchFixed+KeyBytes], keyBytes(entry.key.Inum, entry.key.Kind, entry.key.Pos))
	}
	seal(index)
	write(rootLEB, index)
	write(1, masterBytes(testMasterSq, rootLEB, 0, uint32(indexLen)))
	write(2, masterBytes(testMasterSq-1, rootLEB, 0, uint32(indexLen)))
	return image
}

func makeVolume(t *testing.T, leaves []testLeaf) []byte {
	return makeVolumeWithLEB(t, testLEB, testLEBCnt, leaves)
}

func leaf(key NodeKey, node []byte) testLeaf { return testLeaf{key: key, node: node} }

func rootLeaf() testLeaf {
	return leaf(NodeKey{Inum: 1, Kind: KeyIno}, inodeNode(1, 0o040755, 0, nil))
}

func openTestVolume(t *testing.T, image []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func entryAt(t *testing.T, volume *Volume, path string) *Entry {
	t.Helper()
	entry, err := volume.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	return entry
}

func buildSample(t *testing.T) []byte {
	var leaves []testLeaf
	leaves = append(leaves, rootLeaf())
	leaves = append(leaves,
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 1}, dentNode(1, 1, "etc", 10, TypeDir)),
		leaf(NodeKey{Inum: 10, Kind: KeyIno}, inodeNode(10, 0o040755, 0, nil)),
		leaf(NodeKey{Inum: 10, Kind: KeyDent, Pos: 2}, dentNode(10, 2, "config", 11, TypeReg)),
		leaf(NodeKey{Inum: 11, Kind: KeyIno}, inodeNode(11, 0o100644, 11, nil)),
		leaf(NodeKey{Inum: 11, Kind: KeyData, Pos: 0}, dataNode(11, 0, 11, CompressionNone, []byte("hello ubifs"))),
		leaf(NodeKey{Inum: 10, Kind: KeyDent, Pos: 3}, dentNode(10, 3, "empty", 12, TypeDir)),
		leaf(NodeKey{Inum: 12, Kind: KeyIno}, inodeNode(12, 0o040755, 0, nil)),
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 4}, dentNode(1, 4, "target", 13, TypeSymlink)),
		leaf(NodeKey{Inum: 13, Kind: KeyIno}, inodeNode(13, 0o120777, 0, []byte("etc/config"))),
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 5}, dentNode(1, 5, "gone", 14, TypeReg)),
		leaf(NodeKey{Inum: 14, Kind: KeyIno}, inodeNode(14, 0o100644, 4, nil)),
		leaf(NodeKey{Inum: 1, Kind: KeyXent, Pos: 5}, xentNode(1, 5, "gone", 14, TypeReg)),
	)
	return makeVolume(t, leaves)
}

func TestDetectAndOpenBare(t *testing.T) {
	image := buildSample(t)
	found, err := Detect(source.NewMemorySource(1, image))
	if err != nil || !found {
		t.Fatalf("Detect(valid) = %v, %v", found, err)
	}
	volume := openTestVolume(t, image)
	if volume.Info().Kind != KindLabel || volume.Info().LEBSize != testLEB {
		t.Fatalf("info = %+v", volume.Info())
	}
	if volume.MasterSelection() != Master1 {
		t.Fatalf("master selection = %v", volume.MasterSelection())
	}
	if got := entryAt(t, volume, "/"); got.Kind != KindDirectory || got.Name != "/" {
		t.Fatalf("root = %+v", got)
	}
	if _, err := Detect(source.NewMemorySource(2, bytes.Repeat([]byte{0x11}, 8192))); err != nil {
		t.Fatalf("Detect(random) error = %v", err)
	}
}

func TestNestedDirectoriesAndRootPathForms(t *testing.T) {
	volume := openTestVolume(t, buildSample(t))
	etc := entryAt(t, volume, "/etc")
	if !etc.IsDir || etc.Inode != 10 {
		t.Fatalf("etc = %+v", etc)
	}
	config := entryAt(t, volume, "/etc/config")
	if !config.IsFile || config.Size != 11 || config.Mode != 0o100644 || config.UID != 1000 || config.GID != 1001 {
		t.Fatalf("config = %+v", config)
	}
	if !config.HasMtime || !config.Mtime.Equal(time.Unix(1_700_000_100, 222).UTC()) {
		t.Fatalf("mtime = %v (%v)", config.Mtime, config.HasMtime)
	}
	if !config.HasAtime || !config.Atime.Equal(time.Unix(1_700_000_300, 111).UTC()) {
		t.Fatalf("atime = %v", config.Atime)
	}
	if len(etc.Children) != 2 {
		t.Fatalf("etc children = %v", etc.Children)
	}
	empty := entryAt(t, volume, "/etc/empty")
	if !empty.IsDir {
		t.Fatalf("empty = %+v", empty)
	}
	if list, err := volume.ListDir("/etc"); err != nil || len(list) != 2 || list[0].Name != "config" {
		t.Fatalf("ListDir(/etc) = %+v, %v", list, err)
	}
	for _, pathValue := range []string{"", "/", "//", "/etc/.."} {
		entry, err := volume.Stat(pathValue)
		if err != nil || entry.Path != "/" {
			t.Fatalf("Stat(%q) = %+v, %v", pathValue, entry, err)
		}
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	if _, err := volume.ListDir("/etc/config"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir(file) error = %v", err)
	}
	if _, err := volume.OpenFile("/etc"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile(dir) error = %v", err)
	}
}

func TestFileReadsDataNodes(t *testing.T) {
	volume := openTestVolume(t, buildSample(t))
	file, err := volume.OpenFile("/etc/config")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 11)
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello ubifs" {
		t.Fatalf("file = %q", buf)
	}
	if n, err := file.ReadAt(6, make([]byte, 64)); err != nil || n != 5 {
		t.Fatalf("short read = %d, %v", n, err)
	}
	if !bytes.Equal(buf, []byte("hello ubifs")) {
		t.Fatalf("buffer mutated: %q", buf)
	}
}

func TestSymlinkTargetAndStream(t *testing.T) {
	volume := openTestVolume(t, buildSample(t))
	link := entryAt(t, volume, "/target")
	if !link.IsSymlink || link.SymlinkTarget != "etc/config" || link.Size != uint64(len("etc/config")) {
		t.Fatalf("link = %+v", link)
	}
	target, err := volume.SymlinkTarget("/target")
	if err != nil || target != "etc/config" {
		t.Fatalf("SymlinkTarget = %q, %v", target, err)
	}
	stream, err := volume.OpenSymlink("/target")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("etc/config"))
	if err := source.ReadExactAt(stream, 0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "etc/config" {
		t.Fatalf("symlink stream = %q", buf)
	}
	if _, err := volume.OpenFile("/target"); !errors.Is(err, ErrNotFile) {
		t.Fatalf("OpenFile(symlink) error = %v", err)
	}
	if _, err := volume.SymlinkTarget("/etc/config"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("SymlinkTarget(file) error = %v", err)
	}
}

func TestXentDeletionIsEvidenceNotALiveName(t *testing.T) {
	volume := openTestVolume(t, buildSample(t))
	if _, err := volume.Stat("/gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted name still live: %v", err)
	}
	deleted := volume.Deleted()
	if len(deleted) != 1 {
		t.Fatalf("deleted = %+v", deleted)
	}
	record := deleted[0]
	if record.Name != "gone" || record.Parent != 1 || !record.HasInum || record.Inum != 14 ||
		record.Kind != KindFile || !record.MatchedDent || record.Hash != 5 {
		t.Fatalf("deleted record = %+v", record)
	}
	if volume.DeletedNames() != 1 {
		t.Fatalf("DeletedNames = %d", volume.DeletedNames())
	}
}

func TestEmptyDirectoryAndHardLinks(t *testing.T) {
	var leaves []testLeaf
	leaves = append(leaves, rootLeaf())
	leaves = append(leaves,
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 1}, dentNode(1, 1, "empty", 10, TypeDir)),
		leaf(NodeKey{Inum: 10, Kind: KeyIno}, inodeNode(10, 0o040755, 0, nil)),
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 2}, dentNode(1, 2, "one", 11, TypeReg)),
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 3}, dentNode(1, 3, "two", 11, TypeReg)),
		leaf(NodeKey{Inum: 11, Kind: KeyIno}, inodeNode(11, 0o100600, 3, nil)),
		leaf(NodeKey{Inum: 11, Kind: KeyData, Pos: 0}, dataNode(11, 0, 3, CompressionNone, []byte("abc"))),
	)
	volume := openTestVolume(t, makeVolume(t, leaves))
	list, err := volume.ListDir("/empty")
	if err != nil || len(list) != 0 {
		t.Fatalf("empty dir = %+v, %v", list, err)
	}
	for _, name := range []string{"/one", "/two"} {
		file, err := volume.OpenFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		buf := make([]byte, 3)
		if err := source.ReadExactAt(file, 0, buf); err != nil || string(buf) != "abc" {
			t.Fatalf("%s = %q, %v", name, buf, err)
		}
	}
	one := entryAt(t, volume, "/one")
	two := entryAt(t, volume, "/two")
	if one.Inode != two.Inode || one.Path == two.Path {
		t.Fatalf("hard links = %+v / %+v", one, two)
	}
}

func TestSparseHolesAndPartiallyStoredBlocks(t *testing.T) {
	var leaves []testLeaf
	leaves = append(leaves, rootLeaf())
	leaves = append(leaves,
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 1}, dentNode(1, 1, "sparse", 10, TypeReg)),
		leaf(NodeKey{Inum: 10, Kind: KeyIno}, inodeNode(10, 0o100644, 3*BlockSize, nil)),
		leaf(NodeKey{Inum: 10, Kind: KeyData, Pos: 1}, dataNode(10, 1, BlockSize, CompressionNone, bytes.Repeat([]byte{'B'}, BlockSize))),
	)
	volume := openTestVolume(t, makeVolume(t, leaves))
	file, err := volume.OpenFile("/sparse")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, BlockSize)
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, make([]byte, BlockSize)) {
		t.Fatalf("first block is not a hole")
	}
	if err := source.ReadExactAt(file, BlockSize, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{'B'}, BlockSize)) {
		t.Fatalf("second block = %q", buf[:8])
	}
	sourceFile := file.(*FileSource)
	holes := sourceFile.Holes()
	if len(holes) != 2 || holes[0].Offset != 0 || holes[0].Len != BlockSize ||
		holes[1].Offset != 2*BlockSize || holes[1].Len != BlockSize {
		t.Fatalf("holes = %+v", holes)
	}
	ranges, err := file.Extents(0, 3*BlockSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) < 3 {
		t.Fatalf("extents = %+v", ranges)
	}
	first, second, third := ranges[0], ranges[1], ranges[2]
	if first.Kind != source.RangeHole || first.Len != BlockSize {
		t.Fatalf("first extent = %+v", first)
	}
	if second.Kind != source.RangeData || second.Len != BlockSize {
		t.Fatalf("second extent = %+v", second)
	}
	if third.Kind != source.RangeHole || third.Len != BlockSize {
		t.Fatalf("third extent = %+v", third)
	}
}

func TestInlineFileBytes(t *testing.T) {
	var leaves []testLeaf
	leaves = append(leaves, rootLeaf())
	payload := []byte("tiny inline file")
	leaves = append(leaves,
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 1}, dentNode(1, 1, "tiny", 10, TypeReg)),
		leaf(NodeKey{Inum: 10, Kind: KeyIno}, inodeNode(10, 0o100644, uint64(len(payload)), payload)),
	)
	volume := openTestVolume(t, makeVolume(t, leaves))
	file, err := volume.OpenFile("/tiny")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("inline = %q", buf)
	}
	blocks := file.(*FileSource).Blocks()
	if len(blocks) != 1 || blocks[0].State != BlockInline {
		t.Fatalf("blocks = %+v", blocks)
	}
}

func TestCompressedBlocks(t *testing.T) {
	var zlibBuffer bytes.Buffer
	writer := zlib.NewWriter(&zlibBuffer)
	if _, err := writer.Write([]byte("zlib compressed payload")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	lz4Payload := []byte{240, 7, 108, 122, 52, 32, 99, 111, 109, 112, 114, 101, 115, 115, 101, 100, 32, 112, 97, 121, 108, 111, 97, 100}
	zstdPayload := []byte{40, 181, 47, 253, 32, 23, 185, 0, 0, 122, 115, 116, 100, 32, 99, 111, 109, 112, 114, 101, 115, 115, 101, 100, 32, 112, 97, 121, 108, 111, 97, 100}
	lzoPayload := []byte{34, 104, 101, 108, 108, 111, 44, 32, 108, 122, 111, 32, 119, 111, 114, 108, 100, 33, 17, 0, 0}

	var leaves []testLeaf
	leaves = append(leaves, rootLeaf())
	leaves = append(leaves, leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 1}, dentNode(1, 1, "zlib", 10, TypeReg)))
	leaves = append(leaves, leaf(NodeKey{Inum: 10, Kind: KeyIno}, inodeNode(10, 0o100644, 23, nil)))
	leaves = append(leaves, leaf(NodeKey{Inum: 10, Kind: KeyData, Pos: 0}, dataNode(10, 0, 23, CompressionZLIB, zlibBuffer.Bytes())))
	leaves = append(leaves, leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 2}, dentNode(1, 2, "lz4", 11, TypeReg)))
	leaves = append(leaves, leaf(NodeKey{Inum: 11, Kind: KeyIno}, inodeNode(11, 0o100644, 22, nil)))
	leaves = append(leaves, leaf(NodeKey{Inum: 11, Kind: KeyData, Pos: 0}, dataNode(11, 0, 22, CompressionLZ4, lz4Payload)))
	leaves = append(leaves, leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 3}, dentNode(1, 3, "zstd", 12, TypeReg)))
	leaves = append(leaves, leaf(NodeKey{Inum: 12, Kind: KeyIno}, inodeNode(12, 0o100644, 23, nil)))
	leaves = append(leaves, leaf(NodeKey{Inum: 12, Kind: KeyData, Pos: 0}, dataNode(12, 0, 23, CompressionZSTD, zstdPayload)))
	leaves = append(leaves, leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 4}, dentNode(1, 4, "lzo", 13, TypeReg)))
	leaves = append(leaves, leaf(NodeKey{Inum: 13, Kind: KeyIno}, inodeNode(13, 0o100644, 17, nil)))
	leaves = append(leaves, leaf(NodeKey{Inum: 13, Kind: KeyData, Pos: 0}, dataNode(13, 0, 17, CompressionLZO, lzoPayload)))
	volume := openTestVolume(t, makeVolume(t, leaves))
	for name, want := range map[string]string{
		"/zlib": "zlib compressed payload",
		"/lz4":  "lz4 compressed payload",
		"/zstd": "zstd compressed payload",
		"/lzo":  "hello, lzo world!",
	} {
		file, err := volume.OpenFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		buf := make([]byte, len(want))
		if err := source.ReadExactAt(file, 0, buf); err != nil {
			t.Fatalf("%s read: %v", name, err)
		}
		if string(buf) != want {
			t.Fatalf("%s = %q, want %q", name, buf, want)
		}
	}
	for compression := uint16(0); compression <= 4; compression++ {
		if !compressionSupported(compression) {
			t.Fatalf("compression %d should be supported", compression)
		}
	}
	if compressionSupported(5) {
		t.Fatalf("compression 5 should be refused")
	}
}

func TestCorruptAndUnsupportedDataBlocksNeverBecomeHoles(t *testing.T) {
	corrupt := dataNode(10, 0, 4, CompressionNone, []byte("abcd"))
	corrupt[50] ^= 0xff
	var leaves []testLeaf
	leaves = append(leaves, rootLeaf())
	leaves = append(leaves,
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 1}, dentNode(1, 1, "bad", 10, TypeReg)),
		leaf(NodeKey{Inum: 10, Kind: KeyIno}, inodeNode(10, 0o100644, 4, nil)),
	)
	// The corrupt leaf has a good common header but a bad CRC, so the index
	// walk can still read its key and mark block 0 corrupt.
	corruptLeaf := leaf(NodeKey{Inum: 10, Kind: KeyData}, corrupt)
	leaves = append(leaves, corruptLeaf)
	volume := openTestVolume(t, makeVolume(t, leaves))
	file, err := volume.OpenFile("/bad")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.ReadAt(0, make([]byte, 4)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt block read error = %v", err)
	}
	if volume.Unreadable() != 1 {
		t.Fatalf("unreadable = %d", volume.Unreadable())
	}
	if volume.Undecodable() == 0 {
		t.Fatalf("corrupt node was not counted")
	}
	found := false
	for _, refusal := range volume.Refusals() {
		if strings.Contains(refusal.Feature, "corrupted node CRC") {
			found = true
		}
	}
	if !found {
		t.Fatalf("CRC refusal not reported: %+v", volume.Refusals())
	}

	unsupported := dataNode(11, 0, 4, 5, []byte("abcd"))
	var second []testLeaf
	second = append(second, rootLeaf())
	second = append(second,
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 1}, dentNode(1, 1, "future", 11, TypeReg)),
		leaf(NodeKey{Inum: 11, Kind: KeyIno}, inodeNode(11, 0o100644, 4, nil)),
		leaf(NodeKey{Inum: 11, Kind: KeyData}, unsupported),
	)
	volume = openTestVolume(t, makeVolume(t, second))
	file, err = volume.OpenFile("/future")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.ReadAt(0, make([]byte, 4)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported block read error = %v", err)
	}
	if volume.Unreadable() != 1 {
		t.Fatalf("unreadable = %d", volume.Unreadable())
	}
}

func TestMasterSelectionAndSuperblockRefusals(t *testing.T) {
	first := &MasterNode{Sqnum: 10, CRCOK: true, RootLnum: 3, RootOffs: 0, RootLen: 100}
	second := &MasterNode{Sqnum: 20, CRCOK: true, RootLnum: 4, RootOffs: 0, RootLen: 100}
	chosen, how, err := selectMaster(first, second)
	if err != nil || chosen.Sqnum != 20 || how != Master2 {
		t.Fatalf("select = %+v, %v, %v", chosen, how, err)
	}
	_, how, err = selectMaster(first, &MasterNode{Sqnum: 10, CRCOK: true, RootLnum: 3, RootOffs: 0, RootLen: 100})
	if err != nil || how != EqualIdentical {
		t.Fatalf("equal master = %v, %v", how, err)
	}
	if _, _, err := selectMaster(first, &MasterNode{Sqnum: 10, CRCOK: true, RootLnum: 4, RootOffs: 0, RootLen: 100}); err == nil {
		t.Fatal("equal sqnum with different roots was accepted")
	}
	if _, _, err := selectMaster(&MasterNode{Sqnum: 99, CRCOK: false}, nil); err == nil {
		t.Fatal("unverified master was accepted")
	}

	bytes := superblockBytes(testLEB, testLEBCnt)
	if _, err := ParseSuperblock(bytes); err != nil {
		t.Fatalf("parse superblock: %v", err)
	}
	badHash := append([]byte(nil), bytes...)
	badHash[24] = 3
	seal(badHash)
	if _, err := ParseSuperblock(badHash); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("bad key hash error = %v", err)
	}
	badFanout := append([]byte(nil), bytes...)
	put32(badFanout, 72, 1)
	seal(badFanout)
	if _, err := ParseSuperblock(badFanout); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("bad fanout error = %v", err)
	}
	badVersion := append([]byte(nil), bytes...)
	put32(badVersion, 80, 6)
	seal(badVersion)
	if _, err := ParseSuperblock(badVersion); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("bad version error = %v", err)
	}
	badCRC := append([]byte(nil), bytes...)
	badCRC[40] ^= 0xff
	if _, err := ParseSuperblock(badCRC); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad CRC error = %v", err)
	}
}

func TestIndexBoundsAndCyclesAreRefused(t *testing.T) {
	makeCycle := func() []byte {
		image := make([]byte, testLEB*6)
		copy(image[0:], superblockBytes(testLEB, 6))
		const rootLEB = 3
		indexLen := IndexFixed + (BranchFixed + KeyBytes)
		indexLen = (indexLen + 7) &^ 7
		index := nodeBytes(NodeIndex, indexLen, 8)
		binary.LittleEndian.PutUint16(index[24:26], 1)
		binary.LittleEndian.PutUint16(index[26:28], 0)
		put32(index, IndexFixed, rootLEB)
		put32(index, IndexFixed+4, 0)
		put32(index, IndexFixed+8, uint32(indexLen))
		copy(index[IndexFixed+BranchFixed:], keyBytes(1, KeyIno, 0))
		seal(index)
		copy(image[rootLEB*testLEB:], index)
		copy(image[testLEB:], masterBytes(testMasterSq, rootLEB, 0, uint32(indexLen)))
		copy(image[2*testLEB:], masterBytes(testMasterSq-1, rootLEB, 0, uint32(indexLen)))
		return image
	}
	volume := openTestVolume(t, makeCycle())
	found := false
	for _, refusal := range volume.Refusals() {
		if strings.Contains(refusal.Feature, "index depth cap reached") {
			found = true
		}
	}
	if !found {
		t.Fatalf("depth cap not reported: %+v", volume.Refusals())
	}
}

func TestTruncatedAndMalformedSources(t *testing.T) {
	image := buildSample(t)
	if _, err := Open(source.NewMemorySource(1, image[:100])); !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatalf("short Open error = %v", err)
	}
	mutated := append([]byte(nil), image...)
	mutated[0] ^= 0xff
	if _, err := Open(source.NewMemorySource(1, mutated)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad magic Open error = %v", err)
	}
	if _, err := Open(source.NewMemorySource(1, make([]byte, testLEB*4))); err == nil {
		t.Fatal("zero image opened")
	}
}

func TestFactsAndInfo(t *testing.T) {
	volume := openTestVolume(t, buildSample(t))
	info := volume.Info()
	if info.Entries != 5 || info.DeletedNames != 1 || info.InodeNodes == 0 ||
		info.DentNodes == 0 || info.XentNodes != 1 || info.DataNodes != 1 {
		t.Fatalf("info = %+v", info)
	}
	if info.RootInode != 1 || info.RootLevel != 0 || info.FormatVersion != 5 {
		t.Fatalf("root info = %+v", info)
	}
	facts := map[string]string{}
	for _, pair := range volume.Facts() {
		facts[pair[0]] = pair[1]
	}
	if facts["type"] != "UBIFS" || facts["leb_size"] != "16384" || facts["master_selection"] != "master1" {
		t.Fatalf("facts = %v", facts)
	}
	if !strings.Contains(strings.Join([]string{facts["index_root"], facts["index"], facts["nodes"]}, " "), "index node") {
		t.Fatalf("facts = %v", facts)
	}
}

// ---- UBI fixtures ----

const (
	ubiPEB      = 8192
	ubiVIDOff   = 64
	ubiDataOff  = 2048
	ubiLEB      = ubiPEB - ubiDataOff
	ubiPEBCount = 10
)

func crcHeaderBytes(bytes []byte) uint32 {
	return foundation.CRC32Seeded(0xFFFF_FFFF, bytes[:60])
}

func ubiPEBBytes(volID, lnum uint32, sqnum uint64) []byte {
	peb := bytes.Repeat([]byte{0xff}, ubiPEB)
	copy(peb[0:4], "UBI#")
	peb[4] = 1
	putBig64(peb, 8, uint64(lnum+1))
	putBig32(peb, 24, 1)
	binary.BigEndian.PutUint32(peb[60:64], crcHeaderBytes(peb))
	vid := ubiVIDOff
	copy(peb[vid:vid+4], "UBI!")
	peb[vid+4] = 1
	peb[vid+5] = 1
	peb[vid+7] = 0
	binary.BigEndian.PutUint32(peb[vid+8:], volID)
	binary.BigEndian.PutUint32(peb[vid+12:], lnum)
	binary.BigEndian.PutUint32(peb[vid+24:], 1)
	binary.BigEndian.PutUint64(peb[vid+40:], sqnum)
	binary.BigEndian.PutUint32(peb[vid+60:], crcHeaderBytes(peb[vid:vid+64]))
	return peb
}

func putBig32(bytes []byte, at int, value uint32) { binary.BigEndian.PutUint32(bytes[at:], value) }
func putBig64(bytes []byte, at int, value uint64) { binary.BigEndian.PutUint64(bytes[at:], value) }

func volumeTableRecord(volID, reserved uint32, name string) []byte {
	record := make([]byte, 172)
	putBig32(record, 0, reserved)
	putBig32(record, 4, 1)
	putBig32(record, 8, 0)
	putBig32(record, 12, 1)
	putBig32(record, 16, 0)
	putBig32(record, 20, uint32(len(name)))
	copy(record[24:], name)
	record[152] = 0
	binary.BigEndian.PutUint32(record[168:172], foundation.CRC32Seeded(0xFFFF_FFFF, record[:168]))
	return record
}

func putTableCopy(peb []byte, reserved uint32, name string) {
	record := volumeTableRecord(0, reserved, name)
	copy(peb[ubiDataOff:], record)
}

func buildUBIImage(t *testing.T, reserved uint32, name string) ([]byte, []byte) {
	t.Helper()
	const userLEBs = 6
	ubifs := makeVolumeWithLEB(t, ubiLEB, userLEBs, []testLeaf{
		rootLeaf(),
		leaf(NodeKey{Inum: 1, Kind: KeyDent, Pos: 1}, dentNode(1, 1, "ubi.txt", 10, TypeReg)),
		leaf(NodeKey{Inum: 10, Kind: KeyIno}, inodeNode(10, 0o100644, 5, nil)),
		leaf(NodeKey{Inum: 10, Kind: KeyData, Pos: 0}, dataNode(10, 0, 5, CompressionNone, []byte("hello"))),
	})
	image := make([]byte, ubiPEB*ubiPEBCount)
	for index := 0; index < ubiPEBCount; index++ {
		base := index * ubiPEB
		copy(image[base:], bytes.Repeat([]byte{0xff}, ubiPEB))
	}
	// Layout volume LEB 0 and 1.
	for index, lnum := range []uint32{0, 1} {
		peb := ubiPEBBytes(LayoutVolumeID, lnum, 100+uint64(lnum))
		putTableCopy(peb, reserved, name)
		copy(image[index*ubiPEB:], peb)
	}
	// User volume LEBs 0..5 in PEBs 2..7.
	for lnum := uint32(0); lnum < userLEBs; lnum++ {
		peb := ubiPEBBytes(0, lnum, 200+uint64(lnum))
		copy(peb[ubiDataOff:], ubifs[int(lnum)*ubiLEB:int(lnum+1)*ubiLEB])
		copy(image[(int(lnum)+2)*ubiPEB:], peb)
	}
	// Unmapped PEBs 8 and 9 carry valid EC headers but no VID.
	for index := 8; index < ubiPEBCount; index++ {
		peb := bytes.Repeat([]byte{0xff}, ubiPEB)
		copy(peb[0:4], "UBI#")
		peb[4] = 1
		binary.BigEndian.PutUint32(peb[60:64], crcHeaderBytes(peb))
		copy(image[index*ubiPEB:], peb)
	}
	return image, ubifs
}

func TestUBIGeometryTableAndLEBMapping(t *testing.T) {
	image, _ := buildUBIImage(t, 6, "rootfs")
	ubi, err := OpenUBI(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("OpenUBI: %v", err)
	}
	layout := ubi.Layout()
	if layout.PEBSize != ubiPEB || layout.PageSize != ubiPEB || layout.OOBSize != 0 ||
		layout.VIDOffset != ubiVIDOff || layout.DataOffset != ubiDataOff ||
		layout.LEBSize != ubiLEB || layout.PEBCount != ubiPEBCount {
		t.Fatalf("layout = %+v", layout)
	}
	if ubi.Table().State != TableVerified {
		t.Fatalf("table state = %v", ubi.Table().State)
	}
	volumes := ubi.Volumes()
	if len(volumes) != 1 || volumes[0].VolID != 0 || volumes[0].Name != "rootfs" ||
		volumes[0].ReservedPEBs != 6 || !volumes[0].UBIFS {
		t.Fatalf("volumes = %+v", volumes)
	}
	if length, found := ubi.VolumeLen(0); !found || length != 6*ubiLEB {
		t.Fatalf("volume len = %d, %v", length, found)
	}
	if !ubi.VolumeIsUBIFS(0) {
		t.Fatal("volume not marked UBIFS")
	}
	var magic [4]byte
	if err := ubi.ReadLEB(0, 0, 0, magic[:]); err != nil {
		t.Fatal(err)
	}
	if u32At(magic[:]) != Magic {
		t.Fatalf("LEB 0 magic = %#x", u32At(magic[:]))
	}
	offset, found := ubi.ImageOffset(0, 0, 0)
	if !found || offset != 2*ubiPEB+ubiDataOff {
		t.Fatalf("image offset = %d, %v", offset, found)
	}
	runs, found := ubi.ImageRanges(0, 0, 0, 4)
	if !found || len(runs) != 1 || runs[0] != [2]uint64{2*ubiPEB + ubiDataOff, 4} {
		t.Fatalf("image ranges = %+v, %v", runs, found)
	}
	if ubi.BadBlocks() != 0 || ubi.UnmappedPEBs() != 2 {
		t.Fatalf("blocks = bad %d unmapped %d", ubi.BadBlocks(), ubi.UnmappedPEBs())
	}
	if _, found := ubi.ImageOffset(0, 6, 0); found {
		t.Fatal("unmapped LEB resolved")
	}
	if err := ubi.ReadLEB(0, 6, 0, magic[:]); err == nil {
		t.Fatal("unmapped LEB read succeeded")
	}
}

func TestUBIMountsUBIFSVolume(t *testing.T) {
	image, _ := buildUBIImage(t, 6, "rootfs")
	volume, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open(UBI): %v", err)
	}
	info := volume.Info()
	if info.UBI == nil || info.UBI.VolID != 0 || info.UBI.VolumeName != "rootfs" ||
		info.UBI.TableState != TableVerified {
		t.Fatalf("UBI info = %+v", info.UBI)
	}
	entry := entryAt(t, volume, "/ubi.txt")
	if entry.Size != 5 {
		t.Fatalf("entry = %+v", entry)
	}
	file, err := volume.OpenFile("/ubi.txt")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("file = %q", buf)
	}
	found, err := Detect(source.NewMemorySource(1, image))
	if err != nil || !found {
		t.Fatalf("Detect(UBI) = %v, %v", found, err)
	}
	explicit, err := OpenVolume(source.NewMemorySource(1, image), 0)
	if err != nil {
		t.Fatalf("OpenVolume(0): %v", err)
	}
	if _, err := explicit.Stat("/ubi.txt"); err != nil {
		t.Fatalf("explicit volume stat: %v", err)
	}
	if _, err := OpenVolume(source.NewMemorySource(1, image), LayoutVolumeID); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("reserved volume error = %v", err)
	}
}

func TestUBITableDisagreementIsRefused(t *testing.T) {
	image, _ := buildUBIImage(t, 6, "rootfs")
	// Rewrite the second table copy with a different name and a valid CRC.
	second := ubiPEB
	peb := image[second : second+ubiPEB]
	putTableCopy(peb, 6, "other")
	ubi, err := OpenUBI(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("OpenUBI: %v", err)
	}
	if ubi.Table().State != TableDisagreement {
		t.Fatalf("table state = %v", ubi.Table().State)
	}
	if ubi.Volumes() != nil {
		t.Fatalf("disagreement returned volumes: %+v", ubi.Volumes())
	}
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open(disagreement) error = %v", err)
	}
}

func TestUBIHeaderCRCAndVolumeTableParsing(t *testing.T) {
	peb := ubiPEBBytes(LayoutVolumeID, 0, 1)
	ec, ok := parseEC(0, peb[:HeaderBytes])
	if !ok || !ec.Verified || ec.CRCState() != "verified" {
		t.Fatalf("EC = %+v, %v", ec, ok)
	}
	vid, ok := parseVID(ubiVIDOff, peb[ubiVIDOff:ubiVIDOff+HeaderBytes])
	if !ok || !vid.Verified || vid.VolID != LayoutVolumeID || vid.Lnum != 0 {
		t.Fatalf("VID = %+v, %v", vid, ok)
	}
	broken := append([]byte(nil), peb...)
	broken[10] ^= 0xff
	if header, ok := parseEC(0, broken[:HeaderBytes]); !ok || header.Verified {
		t.Fatalf("broken EC = %+v, %v", header, ok)
	}
	table := make([]byte, 172*2)
	copy(table, volumeTableRecord(0, 2, "root"))
	parsed := parseVolumeTable(table)
	if parsed == nil || parsed.VerifiedRecords != 1 || parsed.RecordStride != 172 ||
		parsed.Entries[0].Name != "root" || parsed.Entries[0].ReservedPEBs != 2 {
		t.Fatalf("table = %+v", parsed)
	}
	table[24] ^= 0xff
	if parseVolumeTable(table) != nil {
		t.Fatal("corrupt record parsed")
	}
}

func TestUBIAmbiguousOrMalformedHeaderSets(t *testing.T) {
	one := ubiPEBBytes(LayoutVolumeID, 0, 1)
	if _, err := OpenUBI(source.NewMemorySource(1, one)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("single PEB error = %v", err)
	}
	image := make([]byte, ubiPEB*2)
	copy(image, ubiPEBBytes(LayoutVolumeID, 0, 1))
	second := ubiPEBBytes(LayoutVolumeID, 1, 2)
	second[10] ^= 0xff
	binary.BigEndian.PutUint32(second[60:64], crcHeaderBytes(second))
	copy(image[ubiPEB:], second)
	if _, err := OpenUBI(source.NewMemorySource(1, image)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("two headers with one bad CRC error = %v", err)
	}
}

func TestUBIEmptySourceAndBareShort(t *testing.T) {
	found, err := Detect(source.NewMemorySource(1, nil))
	if err != nil || found {
		t.Fatalf("Detect(nil) = %v, %v", found, err)
	}
	if _, err := Open(source.NewMemorySource(1, nil)); !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatalf("Open(nil) error = %v", err)
	}
}
