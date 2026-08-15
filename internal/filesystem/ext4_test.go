package filesystem_test

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/ext4"
)

// ext4Fixture opens a committed ext4 E01 fixture and constructs a
// reader-backed handler over the first detected partition.
func ext4Fixture(t *testing.T, name string) (*ext4.Ext4Handler, *ewf.EWFImage) {
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
	h, err := ext4.NewExt4Handler(img, parts[0].StartSector)
	if err != nil {
		t.Fatalf("NewExt4Handler: %v", err)
	}
	return h, img
}

// TestExt4Fixture proves real ext4 file reads from the committed ext4-*
// fixtures across every container variant. The verified on-disk layout:
// superblock at partition offset 1024, inode 12 (fixture.txt) with an extent
// pointing at physical block 2065 holding "fixture\n".
func TestExt4Fixture(t *testing.T) {
	variants := []string{
		"encase25-zlib",
		"encase25-zlib-slack",
		"encase6-zlib",
		"encase25-sections2",
		"encase6-sections2",
	}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			h, _ := ext4Fixture(t, filepath.Join("..", "..", "testdata", "e01", "ext4-"+variant+".E01"))

			if h.Type() != filesystem.FS_EXT4 {
				t.Fatalf("Type() = %v, want FS_EXT4", h.Type())
			}

			entries, err := h.ListDirectory("/")
			if err != nil {
				t.Fatalf("ListDirectory(/): %v", err)
			}
			found := false
			for _, e := range entries {
				if e.Name == "fixture.txt" {
					found = true
					if e.IsDir {
						t.Fatalf("fixture.txt listed as a directory: %+v", e)
					}
				}
			}
			if !found {
				t.Fatalf("fixture.txt not listed; entries = %+v", entries)
			}

			got, err := h.GetFile("fixture.txt")
			if err != nil {
				t.Fatalf("GetFile(fixture.txt): %v", err)
			}
			if string(got) != "fixture\n" {
				t.Fatalf("fixture.txt = %q, want %q", string(got), "fixture\n")
			}

			fi, err := h.GetFileByPath("fixture.txt")
			if err != nil {
				t.Fatalf("GetFileByPath(fixture.txt): %v", err)
			}
			if fi.Size != 8 || fi.IsDir {
				t.Fatalf("GetFileByPath = %+v, want size 8 non-dir", fi)
			}

			results, err := h.SearchFiles("/", func(fi filesystem.FileInfo) bool {
				return fi.Name == "fixture.txt"
			})
			if err != nil {
				t.Fatalf("SearchFiles: %v", err)
			}
			if len(results) != 1 || results[0].Name != "fixture.txt" {
				t.Fatalf("SearchFiles = %+v, want [fixture.txt]", results)
			}

			if got := h.GetVolumeLabel(); got != "FIXTURE" {
				t.Fatalf("GetVolumeLabel() = %q, want %q", got, "FIXTURE")
			}

			// A missing path must error explicitly, never fabricate.
			if _, err := h.GetFile("missing.txt"); err == nil {
				t.Fatal("GetFile(missing.txt) succeeded, want not-found error")
			}
			// Reading the root as a file must error (it is a directory).
			if _, err := h.GetFile("/"); err == nil {
				t.Fatal("GetFile(/) succeeded, want directory error")
			}
		})
	}
}

// --- In-memory ext4 image ---

type memExt4Reader struct {
	data []byte
}

func (r *memExt4Reader) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	start := lba * 512
	end := start + count*512
	if end > uint64(len(r.data)) {
		return nil, fmt.Errorf("ext4: read past end of image")
	}
	return r.data[start:end], nil
}

const (
	fakeExt4BlockSize     = 4096
	fakeExt4InodeSize     = 256
	fakeExt4InodeTableBlk = 2
	fakeExt4DirBlock      = 4
	fakeExt4DataBlock     = 5
)

func fakeExt4Superblock(sb []byte) {
	binary.LittleEndian.PutUint32(sb[0x00:], 16384) // s_inodes_count
	binary.LittleEndian.PutUint32(sb[0x04:], 32768) // s_blocks_count_lo
	binary.LittleEndian.PutUint32(sb[0x14:], 0)     // s_first_data_block
	binary.LittleEndian.PutUint32(sb[0x18:], 2)     // s_log_block_size -> 4096
	binary.LittleEndian.PutUint32(sb[0x20:], 32768) // s_blocks_per_group
	binary.LittleEndian.PutUint32(sb[0x28:], 16384) // s_inodes_per_group
	binary.LittleEndian.PutUint16(sb[0x38:], 0xEF53)
	binary.LittleEndian.PutUint16(sb[0x58:], fakeExt4InodeSize)
	copy(sb[0x78:0x7E], "FIXTURE")
}

func fakeExt4ExtentRoot(ino []byte, off int, eeBlock uint32, eeLen uint16, startLo uint32) {
	binary.LittleEndian.PutUint16(ino[off:], 0xF30A) // eh_magic
	binary.LittleEndian.PutUint16(ino[off+2:], 1)    // eh_entries
	binary.LittleEndian.PutUint16(ino[off+4:], 4)    // eh_max
	binary.LittleEndian.PutUint16(ino[off+6:], 0)    // eh_depth
	ext := ino[off+12:]
	binary.LittleEndian.PutUint32(ext[0:], eeBlock)
	binary.LittleEndian.PutUint16(ext[4:], eeLen)
	binary.LittleEndian.PutUint16(ext[6:], 0) // ee_start_hi
	binary.LittleEndian.PutUint32(ext[8:], startLo)
}

func fakeExt4DirEntry(blk []byte, off int, inode uint32, recLen uint16, nameLen int, ftype byte, name string) {
	binary.LittleEndian.PutUint32(blk[off:], inode)
	binary.LittleEndian.PutUint16(blk[off+4:], recLen)
	blk[off+6] = byte(nameLen)
	blk[off+7] = ftype
	copy(blk[off+8:], name)
}

// buildFakeExt4Image builds a minimal in-memory ext4 image (blockSize=4096)
// whose root dir (inode 2) lists fixture.txt (inode 12), a regular file whose
// extent points at data block 5 holding "fixture\n". mutate can corrupt or
// extend the image before the reader is returned.
func buildFakeExt4Image(mutate func(img []byte)) *memExt4Reader {
	img := make([]byte, 64*512) // 64 sectors

	// Superblock at byte 1024.
	fakeExt4Superblock(img[1024 : 1024+1024])

	// GDT at block 1 (byte 4096): inode table block 2.
	gdt := img[fakeExt4BlockSize:]
	binary.LittleEndian.PutUint32(gdt[0x08:], fakeExt4InodeTableBlk)
	binary.LittleEndian.PutUint16(gdt[0x34:], 0)

	// Inode table at block 2 (byte 8192).
	it := img[fakeExt4InodeTableBlk*fakeExt4BlockSize:]

	// Inode 2 (index 1): root directory, extent root at 0x28 -> block 4.
	rootIno := it[1*fakeExt4InodeSize:]
	binary.LittleEndian.PutUint16(rootIno[0x00:], 0x41ED) // 040755 dir
	binary.LittleEndian.PutUint32(rootIno[0x04:], fakeExt4BlockSize)
	binary.LittleEndian.PutUint32(rootIno[0x0C:], 1786616877)
	binary.LittleEndian.PutUint16(rootIno[0x1A:], 2)
	binary.LittleEndian.PutUint32(rootIno[0x20:], 0x80000) // EXTENTS_FL
	fakeExt4ExtentRoot(rootIno, 0x28, 0, 1, fakeExt4DirBlock)

	// Inode 12 (index 11): fixture.txt, extent root -> block 5.
	fileIno := it[11*fakeExt4InodeSize:]
	binary.LittleEndian.PutUint16(fileIno[0x00:], 0x81A4) // 0100644
	binary.LittleEndian.PutUint32(fileIno[0x04:], 8)
	binary.LittleEndian.PutUint32(fileIno[0x0C:], 1786616877)
	binary.LittleEndian.PutUint16(fileIno[0x1A:], 1)
	binary.LittleEndian.PutUint32(fileIno[0x20:], 0x80000) // EXTENTS_FL
	fakeExt4ExtentRoot(fileIno, 0x28, 0, 1, fakeExt4DataBlock)

	// Root directory block 4: ".", "..", "fixture.txt".
	dir := img[fakeExt4DirBlock*fakeExt4BlockSize:]
	fakeExt4DirEntry(dir, 0, 2, 12, 1, 2, ".")
	fakeExt4DirEntry(dir, 12, 2, 12, 2, 2, "..")
	fakeExt4DirEntry(dir, 24, 12, uint16(fakeExt4BlockSize-24), 11, 1, "fixture.txt")

	// Data block 5: the injected file content.
	copy(img[fakeExt4DataBlock*fakeExt4BlockSize:], "fixture\n")

	if mutate != nil {
		mutate(img)
	}
	return &memExt4Reader{data: img}
}

// TestExt4Malformed asserts that crafted on-disk corruption yields an explicit
// error from the content-read paths, never a panic and never fabricated data.
func TestExt4Malformed(t *testing.T) {
	// (a) An inode whose extent magic is garbage must error.
	t.Run("bad-extent-magic", func(t *testing.T) {
		h, err := ext4.NewExt4Handler(buildFakeExt4Image(func(img []byte) {
			fileIno := img[fakeExt4InodeTableBlk*fakeExt4BlockSize+11*fakeExt4InodeSize:]
			binary.LittleEndian.PutUint16(fileIno[0x28:], 0x1234)
		}), 0)
		if err != nil {
			return // rejected at open time: fine
		}
		if _, err := h.GetFile("fixture.txt"); err == nil {
			t.Fatal("bad extent magic: GetFile succeeded, want error")
		}
	})

	// (b) A declared i_size exceeding the extents' coverage must error without a
	// giant allocation (size 2 blocks, coverage 1 block).
	t.Run("size-exceeds-extents", func(t *testing.T) {
		h, err := ext4.NewExt4Handler(buildFakeExt4Image(func(img []byte) {
			fileIno := img[fakeExt4InodeTableBlk*fakeExt4BlockSize+11*fakeExt4InodeSize:]
			binary.LittleEndian.PutUint32(fileIno[0x04:], 2*fakeExt4BlockSize)
		}), 0)
		if err != nil {
			t.Fatalf("NewExt4Handler: %v", err)
		}
		if _, err := h.GetFile("fixture.txt"); err == nil {
			t.Fatal("size exceeds extents: GetFile succeeded, want error")
		}
	})

	// (c) A non-extent inode (i_flags without EXTENTS_FL) must error.
	t.Run("non-extent-inode", func(t *testing.T) {
		h, err := ext4.NewExt4Handler(buildFakeExt4Image(func(img []byte) {
			fileIno := img[fakeExt4InodeTableBlk*fakeExt4BlockSize+11*fakeExt4InodeSize:]
			binary.LittleEndian.PutUint32(fileIno[0x20:], 0)
		}), 0)
		if err != nil {
			t.Fatalf("NewExt4Handler: %v", err)
		}
		if _, err := h.GetFile("fixture.txt"); err == nil {
			t.Fatal("non-extent inode: GetFile succeeded, want error")
		}
	})

	// (d) A directory entry whose name_len exceeds its rec_len must error.
	t.Run("overrunning-name-len", func(t *testing.T) {
		h, err := ext4.NewExt4Handler(buildFakeExt4Image(func(img []byte) {
			dir := img[fakeExt4DirBlock*fakeExt4BlockSize:]
			// fixture.txt entry at offset 24: rec_len 12, name_len 255.
			binary.LittleEndian.PutUint16(dir[24+4:], 12)
			dir[24+6] = 255
		}), 0)
		if err != nil {
			t.Fatalf("NewExt4Handler: %v", err)
		}
		if _, err := h.ListDirectory("/"); err == nil {
			t.Fatal("overrunning name_len: ListDirectory succeeded, want error")
		}
	})

	// A crafted huge i_size must error at the read bound, not OOM.
	t.Run("huge-size", func(t *testing.T) {
		h, err := ext4.NewExt4Handler(buildFakeExt4Image(func(img []byte) {
			fileIno := img[fakeExt4InodeTableBlk*fakeExt4BlockSize+11*fakeExt4InodeSize:]
			binary.LittleEndian.PutUint32(fileIno[0x04:], 0)          // i_size_lo = 0
			binary.LittleEndian.PutUint32(fileIno[0x6C:], 1<<24)      // i_size_high -> 1<<56
		}), 0)
		if err != nil {
			t.Fatalf("NewExt4Handler(huge size): %v", err)
		}
		if _, err := h.GetFile("fixture.txt"); err == nil {
			t.Fatal("huge declared size: GetFile succeeded, want error")
		}
	})

	// (f) A crafted i_size at the 2^64 overflow boundary (i_size_lo and
	// i_size_high both 0xFFFFFFFF => size 2^64-1) must error explicitly, never
	// panic with a slice-bounds violation. The old ceil-division wrapped
	// fileBlocks to 0, slipped past both the max-blocks and extent-coverage
	// guards, and then panicked on out[:size].
	t.Run("i_size-overflow-boundary", func(t *testing.T) {
		// GetFile path: craft the regular file's i_size.
		h, err := ext4.NewExt4Handler(buildFakeExt4Image(func(img []byte) {
			fileIno := img[fakeExt4InodeTableBlk*fakeExt4BlockSize+11*fakeExt4InodeSize:]
			binary.LittleEndian.PutUint32(fileIno[0x04:], 0xFFFFFFFF) // i_size_lo
			binary.LittleEndian.PutUint32(fileIno[0x6C:], 0xFFFFFFFF) // i_size_high -> 2^64-1
		}), 0)
		if err != nil {
			t.Fatalf("NewExt4Handler(i_size overflow): %v", err)
		}
		if _, err := h.GetFile("fixture.txt"); err == nil {
			t.Fatal("i_size overflow boundary: GetFile succeeded, want error")
		}

		// ListDirectory path: craft the root directory inode's i_size so
		// readDirectory -> readExtentData hits the same arithmetic.
		h2, err := ext4.NewExt4Handler(buildFakeExt4Image(func(img []byte) {
			rootIno := img[fakeExt4InodeTableBlk*fakeExt4BlockSize+1*fakeExt4InodeSize:]
			binary.LittleEndian.PutUint32(rootIno[0x04:], 0xFFFFFFFF) // i_size_lo
			binary.LittleEndian.PutUint32(rootIno[0x6C:], 0xFFFFFFFF) // i_size_high -> 2^64-1
		}), 0)
		if err != nil {
			t.Fatalf("NewExt4Handler(i_size overflow): %v", err)
		}
		if _, err := h2.ListDirectory("/"); err == nil {
			t.Fatal("i_size overflow boundary: ListDirectory succeeded, want error")
		}
	})

	// A truncated image must error, not panic.
	t.Run("truncated", func(t *testing.T) {
		img := buildFakeExt4Image(nil)
		img.data = img.data[:512]
		h, err := ext4.NewExt4Handler(img, 0)
		if err == nil {
			if _, err := h.ListDirectory("/"); err == nil {
				t.Fatal("truncated image: ListDirectory succeeded, want error")
			}
		}
	})
}

// --- Group-descriptor-size regression (32 vs 64 byte descriptors) ---

// buildFakeExt4MultiGroup builds a three-group in-memory ext4 image whose root
// directory (inode 2, group 0) lists fixture.txt as inode 44 (group 2, index
// 11). descSize is the s_desc_size written to the superblock (32, 64, or 0 for
// the on-disk default): the group descriptors are laid out at that stride, and
// each group's inode table sits at a distinct block (2, 4, 6). A reader that
// strides the GDT at the wrong size resolves a high group's descriptor from the
// wrong slot and surfaces another block as its inode table — fabricated data.
func buildFakeExt4MultiGroup(descSize int) *memExt4Reader {
	const (
		blockSize    = 4096
		blocksPerGrp = 16
		inodesPerGrp = 16
		inodeSize    = 256
	)
	stride := descSize
	if stride == 0 {
		stride = 32 // on-disk default for a 32-bit filesystem (no 64BIT)
	}
	img := make([]byte, 32*blockSize)

	// Superblock at byte 1024; override geometry for three small groups.
	sb := img[1024 : 1024+1024]
	fakeExt4Superblock(sb)
	binary.LittleEndian.PutUint32(sb[0x20:], blocksPerGrp)
	binary.LittleEndian.PutUint32(sb[0x28:], inodesPerGrp)
	if descSize > 0 {
		binary.LittleEndian.PutUint16(sb[0xFE:], uint16(descSize)) // s_desc_size
	}

	// GDT at block 1: one descriptor per group, each pointing its inode table
	// at block 2+2*group.
	gdt := img[blockSize:]
	for g := 0; g < 3; g++ {
		desc := gdt[g*stride:]
		binary.LittleEndian.PutUint32(desc[0x08:], uint32(2+2*g)) // inode_table_lo
		if stride >= 64 {
			binary.LittleEndian.PutUint16(desc[0x34:], 0) // inode_table_hi
		}
	}

	// Group 0 inode table (block 2), inode index 1 = root directory.
	rootIno := img[2*blockSize+1*inodeSize:]
	binary.LittleEndian.PutUint16(rootIno[0x00:], 0x41ED) // 040755 dir
	binary.LittleEndian.PutUint32(rootIno[0x04:], blockSize)
	binary.LittleEndian.PutUint32(rootIno[0x0C:], 1786616877)
	binary.LittleEndian.PutUint16(rootIno[0x1A:], 2)
	binary.LittleEndian.PutUint32(rootIno[0x20:], 0x80000) // EXTENTS_FL
	fakeExt4ExtentRoot(rootIno, 0x28, 0, 1, 3)             // root dir data -> block 3

	// Group 2 inode table (block 6), index 11 = fixture.txt.
	fileIno := img[6*blockSize+11*inodeSize:]
	binary.LittleEndian.PutUint16(fileIno[0x00:], 0x81A4) // 0100644
	binary.LittleEndian.PutUint32(fileIno[0x04:], 8)
	binary.LittleEndian.PutUint32(fileIno[0x0C:], 1786616877)
	binary.LittleEndian.PutUint16(fileIno[0x1A:], 1)
	binary.LittleEndian.PutUint32(fileIno[0x20:], 0x80000) // EXTENTS_FL
	fakeExt4ExtentRoot(fileIno, 0x28, 0, 1, 7)             // file data -> block 7

	// Root directory block 3: ".", "..", fixture.txt -> inode 44.
	dir := img[3*blockSize:]
	fakeExt4DirEntry(dir, 0, 2, 12, 1, 2, ".")
	fakeExt4DirEntry(dir, 12, 2, 12, 2, 2, "..")
	fakeExt4DirEntry(dir, 24, 44, uint16(blockSize-24), 11, 1, "fixture.txt")

	// File data block 7.
	copy(img[7*blockSize:], "fixture\n")

	return &memExt4Reader{data: img}
}

// TestExt4GroupDescriptorSize is the regression test for the group-descriptor
// stride. The real 服务器检材二 and OpenWrt images carry s_desc_size=0 with no
// 64BIT flag (32-byte descriptors); a hardcoded 64-byte stride read every high
// group's descriptor from the wrong slot and surfaced another group's inode as
// the target's — fabricated data, forbidden by the correctness contract. Each
// case resolves fixture.txt whose inode lives in group 2, so the read must use
// the correct descriptor size to reach inode table block 6.
func TestExt4GroupDescriptorSize(t *testing.T) {
	cases := []struct {
		name     string
		descSize int // 0 = on-disk default (32, no 64BIT)
	}{
		{"s_desc_size-32", 32},
		{"s_desc_size-0-default-32", 0},
		{"s_desc_size-64", 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ext4.NewExt4Handler(buildFakeExt4MultiGroup(tc.descSize), 0)
			if err != nil {
				t.Fatalf("NewExt4Handler: %v", err)
			}

			entries, err := h.ListDirectory("/")
			if err != nil {
				t.Fatalf("ListDirectory(/): %v", err)
			}
			var got *filesystem.DirectoryEntry
			for i := range entries {
				if entries[i].Name == "fixture.txt" {
					got = &entries[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("fixture.txt not listed; entries = %+v", entries)
			}
			// The file's inode lives in group 2; the entry must reference that
			// inode, not whatever the wrong GDT stride happens to resolve.
			if got.Inode != 44 {
				t.Fatalf("fixture.txt inode = %d, want 44 (group 2)", got.Inode)
			}

			data, err := h.GetFile("fixture.txt")
			if err != nil {
				t.Fatalf("GetFile(fixture.txt): %v", err)
			}
			if string(data) != "fixture\n" {
				t.Fatalf("fixture.txt = %q, want %q", string(data), "fixture\n")
			}

			fi, err := h.GetFileByPath("fixture.txt")
			if err != nil {
				t.Fatalf("GetFileByPath(fixture.txt): %v", err)
			}
			if fi.Size != 8 || fi.IsDir {
				t.Fatalf("GetFileByPath = %+v, want size 8 non-dir", fi)
			}
		})
	}
}
