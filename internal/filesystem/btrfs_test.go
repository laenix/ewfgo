package filesystem_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/btrfs"
)

// diskBinPattern returns the exact bytes of the fixture's disk.bin: 65536
// bytes of the deterministic pattern bytes(range(256)) repeated 256 times.
func diskBinPattern() []byte {
	pat := make([]byte, 256)
	for i := range pat {
		pat[i] = byte(i)
	}
	return bytes.Repeat(pat, 256)
}

// btrfsFixture returns a handler over the committed btrfs fixture (partition
// start sector resolved from the image's own partition table).
func btrfsFixture(t *testing.T, name string) (*btrfs.Btrfs, *ewf.EWFImage) {
	t.Helper()
	img, err := ewf.Open(name)
	if err != nil {
		t.Fatalf("ewf.Open(%s): %v", name, err)
	}
	t.Cleanup(func() { img.Close() })

	parts, err := img.ScanFileSystems()
	if err != nil || len(parts) == 0 {
		t.Fatalf("ScanFileSystems: %v (parts=%d)", err, len(parts))
	}
	h, err := btrfs.NewBtrfsHandler(img, parts[0].StartSector)
	if err != nil {
		t.Fatalf("NewBtrfsHandler: %v", err)
	}
	return h, img
}

// btrfsFixtureE01s is every committed btrfs E01 container variant, so the
// assertions below also prove disk-extent reads through EnCase6 base-offset and
// multi-section spanning, not just the default EnCase 2-5 zlib layout.
var btrfsFixtureE01s = []string{
	"btrfs-encase25-zlib.E01",
	"btrfs-encase25-zlib-slack.E01",
	"btrfs-encase6-zlib.E01",
	"btrfs-encase25-sections2.E01",
	"btrfs-encase6-sections2.E01",
}

// TestBtrfsFixture is the real-image test: the committed btrfs E01 fixtures
// carry an injected fixture.txt (inline extent) and disk.bin (a genuine
// on-disk EXTENT_DATA type-1 extent; see scripts/gen_fs_fixtures.sh). Every
// assertion must hold against real on-disk btrfs data parsed by the tree walk.
func TestBtrfsFixture(t *testing.T) {
	for _, name := range btrfsFixtureE01s {
		t.Run(name, func(t *testing.T) {
			h, _ := btrfsFixture(t, filepath.Join("..", "..", "testdata", "e01", name))

			// Real directory listing includes the injected files with their exact names
			// and sizes (from each child's INODE_ITEM), and no fabricated entries.
			entries, err := h.ListDirectory("/")
			if err != nil {
				t.Fatalf("ListDirectory(/): %v", err)
			}
			var foundFixture, foundDisk bool
			for _, e := range entries {
				if isFabricated(e.Name) {
					t.Fatalf("fabricated entry %q in btrfs listing", e.Name)
				}
				switch e.Name {
				case "fixture.txt":
					foundFixture = true
					if e.IsDir {
						t.Errorf("fixture.txt listed as a directory")
					}
					if e.Size != 8 {
						t.Errorf("fixture.txt listed size = %d, want 8", e.Size)
					}
				case "disk.bin":
					foundDisk = true
					if e.IsDir {
						t.Errorf("disk.bin listed as a directory")
					}
					if e.Size != 65536 {
						t.Errorf("disk.bin listed size = %d, want 65536", e.Size)
					}
				}
			}
			if !foundFixture {
				t.Fatalf("fixture.txt not listed in root (got %d entries)", len(entries))
			}
			if !foundDisk {
				t.Fatalf("disk.bin not listed in root (got %d entries)", len(entries))
			}

			// GetFile returns the exact injected bytes for the inline fixture.txt.
			got, err := h.GetFile("fixture.txt")
			if err != nil {
				t.Fatalf("GetFile(fixture.txt): %v", err)
			}
			if string(got) != "fixture\n" {
				t.Fatalf("fixture.txt content = %q, want %q", string(got), "fixture\n")
			}

			// disk.bin is a real (non-inline) EXTENT_DATA type-1 extent read through the
			// chunk map: GetFile must return the exact 65536 deterministic bytes.
			db, err := h.GetFile("disk.bin")
			if err != nil {
				t.Fatalf("GetFile(disk.bin): %v", err)
			}
			wantDB := diskBinPattern()
			if len(db) != len(wantDB) {
				t.Fatalf("GetFile(disk.bin) returned %d bytes, want %d", len(db), len(wantDB))
			}
			if !bytes.Equal(db, wantDB) {
				t.Fatalf("GetFile(disk.bin) content mismatch: got %x... want %x...",
					db[:min(len(db), 16)], wantDB[:16])
			}

			// GetFileByPath reports each inode's real size and type.
			fi, err := h.GetFileByPath("fixture.txt")
			if err != nil {
				t.Fatalf("GetFileByPath(fixture.txt): %v", err)
			}
			if fi.Size != 8 {
				t.Errorf("GetFileByPath size = %d, want 8", fi.Size)
			}
			if fi.IsDir {
				t.Errorf("GetFileByPath reports fixture.txt as a directory")
			}
			dfi, err := h.GetFileByPath("disk.bin")
			if err != nil {
				t.Fatalf("GetFileByPath(disk.bin): %v", err)
			}
			if dfi.Size != 65536 {
				t.Errorf("GetFileByPath(disk.bin) size = %d, want 65536", dfi.Size)
			}
			if dfi.IsDir {
				t.Errorf("GetFileByPath reports disk.bin as a directory")
			}

			// SearchFiles finds exactly the two injected files.
			results, err := h.SearchFiles("/", func(f filesystem.FileInfo) bool {
				return !f.IsDir
			})
			if err != nil {
				t.Fatalf("SearchFiles: %v", err)
			}
			if len(results) != 2 {
				t.Fatalf("SearchFiles found %d files, want exactly 2: %+v", len(results), results)
			}
			byName := map[string]uint64{}
			for _, r := range results {
				byName[r.Name] = r.Size
			}
			if byName["fixture.txt"] != 8 || byName["disk.bin"] != 65536 {
				t.Errorf("SearchFiles results = %+v, want fixture.txt size 8 and disk.bin size 65536", byName)
			}

			// Volume label is real on-disk data.
			if label := h.GetVolumeLabel(); label != "FIXTURE" {
				t.Errorf("GetVolumeLabel() = %q, want %q", label, "FIXTURE")
			}
		})
	}
}

// isFabricated mirrors the matrix test's fabrication gate: hard-coded names the
// pre-tree-walk stub would never have produced from real on-disk data.
func isFabricated(name string) bool {
	switch name {
	case "DCIM", "Pictures", "bin", "boot", "etc":
		return true
	}
	return false
}

// memBtrfsReader is a fake Reader over an in-memory byte slice used to feed
// malformed node data to the handler.
type memBtrfsReader struct {
	data []byte
}

func (r *memBtrfsReader) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	start := lba * 512
	end := start + count*512
	if end > uint64(len(r.data)) {
		return nil, fmt.Errorf("read past end of image")
	}
	return r.data[start:end], nil
}

const (
	fakeBtrfsNodesize  = 16384
	fakeBtrfsChunkRoot = 0x100000
	fakeBtrfsRootTree  = 0x140000
	fakeBtrfsImageSize = 0x200000
)

func putU32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:off+4], v) }
func putU64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:off+8], v) }

// buildFakeChunkItem builds a 1-stripe chunk item (48-byte header + 32-byte
// stripe) mapping logical chunkRoot to a physical address.
func buildFakeChunkItem(length, phys uint64) []byte {
	ci := make([]byte, 48+32)
	putU64(ci, 0, length)
	putU64(ci, 8, 1)                            // owner (extent tree)
	putU64(ci, 16, 0x10000)                     // stripe_len
	putU64(ci, 24, 0x1)                         // type: DATA single
	putU32(ci, 32, 0x10000)                     // io_align
	putU32(ci, 36, 0x10000)                     // io_width
	putU32(ci, 40, 0x1000)                      // sector_size
	binary.LittleEndian.PutUint16(ci[44:46], 1) // num_stripes
	binary.LittleEndian.PutUint16(ci[46:48], 0) // sub_stripes
	putU64(ci, 48, 1)                           // stripe[0] devid
	putU64(ci, 56, phys)                        // stripe[0] offset
	return ci
}

// buildFakeBtrfsImage builds a minimal in-memory btrfs image whose chunk tree
// is well-formed and whose root tree bytes can be supplied by the caller. This
// lets tests exercise the tree walk against malformed nodes.
func buildFakeBtrfsImage(rootTree []byte) *memBtrfsReader {
	img := make([]byte, fakeBtrfsImageSize)

	// Superblock at byte 0x10000 (64 KiB).
	sb := img[0x10000 : 0x10000+0x1000]
	copy(sb[0x40:0x48], "_BHRfS_M")
	putU64(sb, 0x50, fakeBtrfsRootTree)  // root (ROOT tree) bytenr
	putU64(sb, 0x58, fakeBtrfsChunkRoot) // chunk_root bytenr
	putU64(sb, 0x70, 0x1000000)          // total_bytes
	putU64(sb, 0x78, 0x1000)             // bytes_used
	putU64(sb, 0x88, 1)                  // num_devices
	putU32(sb, 0x90, 0x1000)             // sectorsize
	putU32(sb, 0x94, fakeBtrfsNodesize)  // nodesize
	putU32(sb, 0xa0, 129)                // sys_chunk_array_size
	// sys_chunk_array content: key{0, 0xe4, chunkRoot} + chunk item, placed at
	// the fixture's non-standard offset so the scan-based bootstrap finds it.
	putU64(sb, 0x2d0, 0)
	sb[0x2d8] = 0xe4
	putU64(sb, 0x2d9, fakeBtrfsChunkRoot)
	copy(sb[0x2d0+17:], buildFakeChunkItem(0x100000, fakeBtrfsChunkRoot))

	// Chunk tree leaf at phys 0x100000 (identity-mapped by the bootstrap chunk).
	chunkLeaf := make([]byte, fakeBtrfsNodesize)
	putU64(chunkLeaf, 48, fakeBtrfsChunkRoot)
	putU64(chunkLeaf, 88, 3) // CHUNK_TREE owner
	putU32(chunkLeaf, 96, 1) // nritems
	chunkLeaf[100] = 0       // level
	P := 101
	putU64(chunkLeaf, P, 256)
	chunkLeaf[P+8] = 0xe4
	putU64(chunkLeaf, P+9, fakeBtrfsChunkRoot)
	ci := buildFakeChunkItem(0x100000, fakeBtrfsChunkRoot)
	size := len(ci)
	off := fakeBtrfsNodesize - size - 101 // data at off+101, shift=101
	putU32(chunkLeaf, P+17, uint32(off))
	putU32(chunkLeaf, P+21, uint32(size))
	copy(chunkLeaf[off+101:], ci)
	copy(img[fakeBtrfsChunkRoot:fakeBtrfsChunkRoot+fakeBtrfsNodesize], chunkLeaf)

	// Root tree node at phys 0x140000 — supplied by the caller (malformed in
	// the corruption tests).
	if rootTree != nil {
		copy(img[fakeBtrfsRootTree:fakeBtrfsRootTree+len(rootTree)], rootTree)
	}
	return &memBtrfsReader{data: img}
}

// TestBtrfsMalformedNode feeds malformed node/superblock data to the handler
// and its tree walk: every malformed case must return an explicit error and
// never panic (解析红线).
func TestBtrfsMalformedNode(t *testing.T) {
	// Garbage reader: no valid superblock at all.
	if _, err := btrfs.NewBtrfsHandler(&memBtrfsReader{data: make([]byte, 0x40000)}, 0); err == nil {
		t.Fatal("NewBtrfsHandler must error on an image with no btrfs superblock")
	}

	// Well-formed superblock + chunk map, but the ROOT tree node is garbage.
	// The constructor succeeds (chunk map builds); the tree walk must error
	// when it tries to decode the root tree on ListDirectory.
	zeroRoot := make([]byte, fakeBtrfsNodesize)
	h, err := btrfs.NewBtrfsHandler(buildFakeBtrfsImage(zeroRoot), 0)
	if err != nil {
		t.Fatalf("NewBtrfsHandler with valid chunk map: %v", err)
	}
	if _, err := h.ListDirectory("/"); err == nil {
		t.Fatal("ListDirectory must error when the root tree node is malformed")
	}
	if _, err := h.GetFile("fixture.txt"); err == nil {
		t.Fatal("GetFile must error when the root tree node is malformed")
	}

	// Root tree node with an implausibly large item count.
	huge := make([]byte, fakeBtrfsNodesize)
	putU32(huge, 96, 0xFFFFFFF)
	h2, err := btrfs.NewBtrfsHandler(buildFakeBtrfsImage(huge), 0)
	if err != nil {
		t.Fatalf("NewBtrfsHandler with valid chunk map: %v", err)
	}
	if _, err := h2.ListDirectory("/"); err == nil {
		t.Fatal("ListDirectory must error on a node with an invalid item count")
	}

	// Malformed chunk tree leaf: the chunk map cannot be built from the tree.
	badChunkImg := buildFakeBtrfsImage(zeroRoot)
	copy(badChunkImg.data[fakeBtrfsChunkRoot:fakeBtrfsChunkRoot+fakeBtrfsNodesize], make([]byte, fakeBtrfsNodesize))
	if _, err := btrfs.NewBtrfsHandler(badChunkImg, 0); err == nil {
		t.Fatal("NewBtrfsHandler must error when the chunk tree node is malformed")
	}
}

// fakeBtrfsItem is a keyed item payload for building a fake btrfs leaf. Items
// must be supplied in ascending btrfs key order (objectid, type, offset).
type fakeBtrfsItem struct {
	objectid uint64
	typ      uint8
	offset   uint64
	data     []byte
}

// buildFakeLeaf builds a well-formed level-0 leaf node (nodesize 16 KiB) holding
// the given items, laid out so decodeNode's layout validation accepts it: the
// item array starts at byte 101 and item data runs downward from the node end
// (shift 0, data at data[off:off+size]).
func buildFakeLeaf(bytenr, owner uint64, items []fakeBtrfsItem) []byte {
	node := make([]byte, fakeBtrfsNodesize)
	putU64(node, 48, bytenr) // node bytenr
	putU64(node, 88, owner)  // tree owner
	putU32(node, 96, uint32(len(items)))
	node[100] = 0 // level 0 (leaf)
	P := 101
	cur := fakeBtrfsNodesize
	for i, it := range items {
		size := len(it.data)
		start := cur - size
		o := P + i*25 // 17-byte key + {off u32, size u32}
		putU64(node, o, it.objectid)
		node[o+8] = it.typ
		putU64(node, o+9, it.offset)
		putU32(node, o+17, uint32(start))
		putU32(node, o+21, uint32(size))
		copy(node[start:cur], it.data)
		cur = start
	}
	return node
}

// buildFakeInodeItem builds a 160-byte btrfs_inode_item with the given size and
// mode (size at offset 16, mode at offset 52, matching the parser).
func buildFakeInodeItem(size uint64, mode uint32) []byte {
	ii := make([]byte, 160)
	putU64(ii, 16, size)
	putU32(ii, 52, mode)
	return ii
}

// buildFakeDirItem builds a btrfs_dir_item naming child inode child as name
// (target inode at offset 0, name_len at 27, file type at 29, name at 30).
func buildFakeDirItem(child uint64, typ uint8, name string) []byte {
	di := make([]byte, 30+len(name))
	putU64(di, 0, child)
	binary.LittleEndian.PutUint16(di[27:29], uint16(len(name)))
	di[29] = typ
	copy(di[30:], name)
	return di
}

// buildFakeInlineExtent builds a type-0 (inline) EXTENT_DATA payload carrying the
// given bytes (21-byte file_extent_item header + inline data at offset 21).
func buildFakeInlineExtent(data []byte) []byte {
	fei := make([]byte, 21+len(data))
	fei[20] = 0 // BTRFS_FILE_EXTENT_INLINE
	copy(fei[21:], data)
	return fei
}

// buildCraftedInodeSizeImage builds a fake btrfs image whose file inode 257
// reports an INODE_ITEM st_size of 2^48 (a crafted on-disk value) but whose only
// EXTENT_DATA covers [extentOffset, extentOffset+len(content)) — a tiny amount of
// real data for a file that claims 256 TiB. The root tree leaf (with a ROOT_ITEM
// for the FS subvolume) and the FS tree leaf are both built with buildFakeLeaf,
// so the full tree walk succeeds and GetFile reaches the allocation path.
func buildCraftedInodeSizeImage(extentOffset uint64, content []byte) *memBtrfsReader {
	const (
		rootDirInode = 256
		fileInode    = 257
		fsRootBytenr = 0x180000
	)
	// ROOT_ITEM (objectid 5 = FS_TREE) whose tree-root bytenr lives at offset 176.
	rootItem := make([]byte, 184)
	putU64(rootItem, 176, fsRootBytenr)
	rootLeaf := buildFakeLeaf(fakeBtrfsRootTree, 1, []fakeBtrfsItem{
		{objectid: 5, typ: 132, offset: 0, data: rootItem},
	})
	img := buildFakeBtrfsImage(rootLeaf)

	// FS tree leaf: root dir inode 256, a DIR_ITEM resolving evil.bin to inode
	// 257, the crafted 2^48-sized INODE_ITEM for 257, and 257's tiny extent.
	fsLeaf := buildFakeLeaf(fsRootBytenr, 5, []fakeBtrfsItem{
		{objectid: rootDirInode, typ: 1, offset: 0, data: buildFakeInodeItem(0, 0x41ED)}, // dir mode 040755
		{objectid: rootDirInode, typ: 84, offset: 0, data: buildFakeDirItem(fileInode, 1, "evil.bin")},
		{objectid: fileInode, typ: 1, offset: 0, data: buildFakeInodeItem(1<<48, 0x81A4)}, // crafted size 2^48
		{objectid: fileInode, typ: 108, offset: extentOffset, data: buildFakeInlineExtent(content)},
	})
	copy(img.data[fsRootBytenr:fsRootBytenr+fakeBtrfsNodesize], fsLeaf)
	return img
}

// TestBtrfsCraftedInodeSize is RED-on-prefix: an INODE_ITEM whose st_size claims
// 2^48 while the file's real EXTENT_DATA is tiny made GetFile call
// make([]byte, 1<<48), which OOM-crashes the process. After the fix GetFile must
// bound the allocation by the inode's extent-backed coverage and hard cap —
// either returning exactly the small real data (clamp path) or failing with an
// explicit error when the extent-backed size exceeds 1 TiB (hard-cap path). It
// must never allocate hundreds of TiB, and must finish in well under a second.
func TestBtrfsCraftedInodeSize(t *testing.T) {
	// Clamp path: 2^48 claimed, but a 4-byte inline extent covers only [0,4).
	// GetFile must return exactly those 4 bytes — never a giant allocation.
	start := time.Now()
	h, err := btrfs.NewBtrfsHandler(buildCraftedInodeSizeImage(0, []byte("EVIL")), 0)
	if err != nil {
		t.Fatalf("NewBtrfsHandler: %v", err)
	}
	got, err := h.GetFile("evil.bin")
	if err != nil {
		t.Fatalf("GetFile(evil.bin): %v", err)
	}
	if len(got) > 1<<20 {
		t.Fatalf("GetFile returned %d bytes for a 4-byte extent (unbounded allocation)", len(got))
	}
	if string(got) != "EVIL" {
		t.Fatalf("GetFile content = %q, want %q", string(got), "EVIL")
	}

	// Hard-cap path: an inline extent at offset 2^41 pushes the extent-backed size
	// past 1 TiB, so GetFile must fail with an explicit error instead of allocating.
	h2, err := btrfs.NewBtrfsHandler(buildCraftedInodeSizeImage(1<<41, []byte("EVIL")), 0)
	if err != nil {
		t.Fatalf("NewBtrfsHandler (hard cap): %v", err)
	}
	_, err = h2.GetFile("evil.bin")
	if err == nil {
		t.Fatal("GetFile must error when the extent-backed size exceeds the hard cap")
	}
	if !strings.Contains(err.Error(), "exceeds the supported maximum") {
		t.Fatalf("GetFile error = %v, want a hard-cap error", err)
	}

	if d := time.Since(start); d > time.Second {
		t.Fatalf("TestBtrfsCraftedInodeSize took %v — a giant allocation likely occurred", d)
	}
}
