package filesystem_test

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/xfs"
)

// xfsFixture opens an XFS E01 fixture and constructs a reader-backed handler
// over the first detected partition.
func xfsFixture(t *testing.T, name string) (*xfs.XFS, *ewf.EWFImage) {
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
	h, err := xfs.NewXFSHandler(img, parts[0].StartSector)
	if err != nil {
		t.Fatalf("NewXFSHandler: %v", err)
	}
	return h, img
}

// TestXFSFixture is the real-image test: the committed xfs-encase25-zlib.E01
// fixture is a genuine mkfs.xfs image whose root directory is an empty shortform
// dir. The root's shortform data on disk stores count=0 — there is no stored
// "." or ".." (xfs_db synthesizes them) — so the real listing is an empty,
// non-nil slice. GetFile must return an explicit not-found error rather than
// fabricating the injected-file names other fixture filesystems use.
func TestXFSFixture(t *testing.T) {
	h, _ := xfsFixture(t, filepath.Join("..", "..", "testdata", "e01", "xfs-encase25-zlib.E01"))

	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	if entries == nil {
		t.Fatal("ListDirectory(/) returned nil slice")
	}
	if len(entries) != 0 {
		t.Fatalf("ListDirectory(/) = %d entries, want 0 (empty shortform root): %+v", len(entries), entries)
	}
	// The real parse must never surface a fabricated name.
	for _, e := range entries {
		if isFabricated(e.Name) {
			t.Fatalf("fabricated entry %q in XFS root listing", e.Name)
		}
	}

	// GetFile must fail explicitly: there is no fixture.txt on disk.
	if _, err := h.GetFile("fixture.txt"); err == nil {
		t.Fatal("GetFile(fixture.txt) succeeded, want not-found error")
	}
	if _, err := h.GetFileByPath("fixture.txt"); err == nil {
		t.Fatal("GetFileByPath(fixture.txt) succeeded, want not-found error")
	}

	// The volume label is the real sb_fname field.
	if got := h.GetVolumeLabel(); got != "FIXTURE" {
		t.Fatalf("GetVolumeLabel() = %q, want %q", got, "FIXTURE")
	}

	// SearchFiles must produce no results (empty root) without error.
	results, err := h.SearchFiles("/", func(fi filesystem.FileInfo) bool { return true })
	if err != nil {
		t.Fatalf("SearchFiles: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SearchFiles = %d results, want 0", len(results))
	}
}

// TestXFSFixtureAllVariants proves the real parse works through every committed
// container layout, not just the default EnCase 2-5 zlib one.
func TestXFSFixtureAllVariants(t *testing.T) {
	variants := []string{
		"xfs-encase25-zlib",
		"xfs-encase25-zlib-slack",
		"xfs-encase6-zlib",
		"xfs-encase25-sections2",
		"xfs-encase6-sections2",
	}
	for _, base := range variants {
		t.Run(base, func(t *testing.T) {
			h, _ := xfsFixture(t, filepath.Join("..", "..", "testdata", "e01", base+".E01"))
			entries, err := h.ListDirectory("/")
			if err != nil {
				t.Fatalf("ListDirectory(/): %v", err)
			}
			if entries == nil || len(entries) != 0 {
				t.Fatalf("ListDirectory(/) = %+v, want empty non-nil", entries)
			}
			for _, e := range entries {
				if isFabricated(e.Name) {
					t.Fatalf("fabricated entry %q in %s", e.Name, base)
				}
			}
			if got := h.GetVolumeLabel(); got != "FIXTURE" {
				t.Fatalf("GetVolumeLabel() = %q, want FIXTURE", got)
			}
		})
	}
}

// memXFSReader is a fake Reader over an in-memory byte slice used to feed the
// handler well-formed and malformed on-disk XFS structures.
type memXFSReader struct {
	data []byte
}

func (r *memXFSReader) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	start := lba * 512
	end := start + count*512
	if end > uint64(len(r.data)) {
		return nil, fmt.Errorf("xfs: read past end of image")
	}
	return r.data[start:end], nil
}

const (
	fakeXFSBlocksize  = 4096
	fakeXFSInodesize  = 512
	fakeXFSInopblock  = 8
	fakeXFSAgblocks   = 32768
	fakeXFSRootIno    = 128
	fakeXFSInobtBlock = 3
	fakeXFSInoBlock   = 16 // inode 128 chunk starts at fsb 16
)

// buildFakeXFSImage builds a minimal in-memory XFS image whose geometry matches
// the committed fixtures: 4096-byte blocks, 512-byte v3 inodes, 8 inodes per
// block, root inode 128 in a single inobt chunk. The root is an empty shortform
// directory. mutate (if non-nil) can corrupt or extend the image before the
// reader is returned.
func buildFakeXFSImage(mutate func(img []byte)) *memXFSReader {
	img := make([]byte, 0x11000)

	// Superblock (first sector).
	sb := img[0:512]
	copy(sb[0x00:0x04], "XFSB")
	binary.BigEndian.PutUint32(sb[0x04:], fakeXFSBlocksize)
	binary.BigEndian.PutUint64(sb[0x08:], 65536)          // dblocks
	binary.BigEndian.PutUint64(sb[0x38:], fakeXFSRootIno) // rootino
	binary.BigEndian.PutUint32(sb[0x54:], fakeXFSAgblocks)
	binary.BigEndian.PutUint32(sb[0x58:], 1) // agcount
	binary.BigEndian.PutUint16(sb[0x68:], fakeXFSInodesize)
	binary.BigEndian.PutUint16(sb[0x6a:], fakeXFSInopblock)
	copy(sb[0x6c:0x78], "FIXTURE")
	sb[0x78] = 12 // blocklog
	sb[0x79] = 9  // sectlog (512-byte sectors)
	sb[0x7b] = 3  // inopblog
	// features_incompat lives at 0xd8 (0xd0 is features_compat). The FTYPE bit
	// (0x1) is set so shortform entries carry a ftype byte, exercising the
	// real entry layout.
	binary.BigEndian.PutUint32(sb[0xd8:], 1)

	// AGI header (byte 1024 of AG 0).
	agi := img[1024 : 1024+512]
	copy(agi[0:4], "XAGI")
	binary.BigEndian.PutUint32(agi[0x14:], fakeXFSInobtBlock) // inobt root
	binary.BigEndian.PutUint32(agi[0x18:], 0)                 // level: leaf

	// inobt leaf block 3: one record covering inodes 128-191.
	ibt := img[fakeXFSInobtBlock*fakeXFSBlocksize:]
	copy(ibt[0:4], "IAB3")
	binary.BigEndian.PutUint16(ibt[4:], 0)                     // level
	binary.BigEndian.PutUint16(ibt[6:], 1)                     // numrecs
	binary.BigEndian.PutUint32(ibt[0x38:], 128)                // startino
	binary.BigEndian.PutUint64(ibt[0x40:], 0xfffffffffffffff8) // free: 128-130 allocated

	// Root dir inode 128: empty shortform dir (mode 040755, format local).
	ino := img[fakeXFSInoBlock*fakeXFSBlocksize:]
	binary.BigEndian.PutUint16(ino[0x00:], 0x494e)         // "IN"
	binary.BigEndian.PutUint16(ino[0x02:], 0x41ed)         // mode 040755 (dir)
	ino[0x04] = 3                                          // version
	ino[0x05] = 1                                          // format local
	binary.BigEndian.PutUint32(ino[0x10:], 2)              // nlink
	binary.BigEndian.PutUint64(ino[0x38:], 6)              // size
	ino[0xb0] = 0                                          // count
	ino[0xb1] = 0                                          // i8count
	binary.BigEndian.PutUint32(ino[0xb2:], fakeXFSRootIno) // parent

	if mutate != nil {
		mutate(img)
	}
	return &memXFSReader{data: img}
}

// xfsFileLayoutMutate returns a mutate callback that extends the fake image so
// the root shortform dir lists "fixture.txt" (inode 131), a regular file whose
// local data fork holds "fixture\n". The entry encodes the real on-disk layout
// for an ftype shortform dir: namelen(1) offset(2) name ftype(1) inumber(4).
func xfsFileLayoutMutate() func(img []byte) {
	return func(img []byte) {
		// Mark inode 131 (relIno 3) allocated in the inobt free bitmap.
		binary.BigEndian.PutUint64(img[fakeXFSInobtBlock*fakeXFSBlocksize+0x40:], 0xfffffffffffffff0)
		ino := img[fakeXFSInoBlock*fakeXFSBlocksize:]
		// Shortform header (6 bytes): count=1, i8count=0, parent(4)=128.
		ino[0xb0] = 1
		ino[0xb1] = 0
		binary.BigEndian.PutUint32(ino[0xb2:], 128)
		// Entry (19 bytes): namelen(1)=11, offset(2)=0, name(11)="fixture.txt",
		// ftype(1)=1 (XFS_DIR3_FT_REG), inumber(4)=131.
		ino[0xb6] = 11
		binary.BigEndian.PutUint16(ino[0xb7:], 0)
		copy(ino[0xb9:0xc4], "fixture.txt")
		ino[0xc4] = 1
		binary.BigEndian.PutUint32(ino[0xc5:], 131)
		// size = 6-byte header + 19-byte entry.
		binary.BigEndian.PutUint64(ino[0x38:], 6+19)
		// Regular file inode 131: local data fork holding "fixture\n".
		c := img[fakeXFSInoBlock*fakeXFSBlocksize+3*fakeXFSInodesize:]
		binary.BigEndian.PutUint16(c[0x00:], 0x494e)
		binary.BigEndian.PutUint16(c[0x02:], 0x81a4) // 0100644
		c[0x04] = 3
		c[0x05] = 1
		binary.BigEndian.PutUint32(c[0x10:], 1)
		binary.BigEndian.PutUint64(c[0x38:], 8)
		copy(c[0xb0:0xb8], "fixture\n")
	}
}

// xfsShortformI8Mutate is xfsFileLayoutMutate with the root shortform dir
// switched to the i8count>0 form: a 10-byte header (count, i8count, parent(8))
// and an entry with an 8-byte inumber (namelen(1) offset(2) name ftype(1)
// inumber(8)).
func xfsShortformI8Mutate() func(img []byte) {
	return func(img []byte) {
		binary.BigEndian.PutUint64(img[fakeXFSInobtBlock*fakeXFSBlocksize+0x40:], 0xfffffffffffffff0)
		ino := img[fakeXFSInoBlock*fakeXFSBlocksize:]
		// Shortform header (10 bytes): count=1, i8count=1, parent(8)=128.
		ino[0xb0] = 1
		ino[0xb1] = 1
		binary.BigEndian.PutUint64(ino[0xb2:], 128)
		// Entry (23 bytes): namelen(1)=11, offset(2)=0, name(11)="fixture.txt",
		// ftype(1)=1 (REG), inumber(8)=131.
		ino[0xba] = 11
		binary.BigEndian.PutUint16(ino[0xbb:], 0)
		copy(ino[0xbd:0xc8], "fixture.txt")
		ino[0xc8] = 1
		binary.BigEndian.PutUint64(ino[0xc9:], 131)
		// size = 10-byte header + 23-byte entry.
		binary.BigEndian.PutUint64(ino[0x38:], 10+23)
		// Regular file inode 131: local data fork holding "fixture\n".
		c := img[fakeXFSInoBlock*fakeXFSBlocksize+3*fakeXFSInodesize:]
		binary.BigEndian.PutUint16(c[0x00:], 0x494e)
		binary.BigEndian.PutUint16(c[0x02:], 0x81a4)
		c[0x04] = 3
		c[0x05] = 1
		binary.BigEndian.PutUint32(c[0x10:], 1)
		binary.BigEndian.PutUint64(c[0x38:], 8)
		copy(c[0xb0:0xb8], "fixture\n")
	}
}

// TestXFSFakeImage proves the shortform-entry and local-file data-fork paths
// against a well-formed in-memory image: the root lists a real "fixture.txt"
// entry, and GetFile returns the exact inline bytes.
func TestXFSFakeImage(t *testing.T) {
	h, err := xfs.NewXFSHandler(buildFakeXFSImage(xfsFileLayoutMutate()), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler: %v", err)
	}

	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "fixture.txt" || entries[0].IsDir || entries[0].Inode != 131 {
		t.Fatalf("ListDirectory(/) = %+v, want [fixture.txt inode 131 (file)]", entries)
	}

	got, err := h.GetFile("fixture.txt")
	if err != nil {
		t.Fatalf("GetFile(fixture.txt): %v", err)
	}
	if string(got) != "fixture\n" {
		t.Fatalf("GetFile(fixture.txt) = %q, want %q", string(got), "fixture\n")
	}

	fi, err := h.GetFileByPath("fixture.txt")
	if err != nil {
		t.Fatalf("GetFileByPath(fixture.txt): %v", err)
	}
	if fi.Size != 8 || fi.IsDir {
		t.Fatalf("GetFileByPath = %+v, want size 8 non-dir", fi)
	}

	// i8count>0 form: 10-byte header, 8-byte inumbers.
	t.Run("i8count", func(t *testing.T) {
		h, err := xfs.NewXFSHandler(buildFakeXFSImage(xfsShortformI8Mutate()), 0)
		if err != nil {
			t.Fatalf("NewXFSHandler(i8count): %v", err)
		}
		entries, err := h.ListDirectory("/")
		if err != nil {
			t.Fatalf("i8count ListDirectory(/): %v", err)
		}
		if len(entries) != 1 || entries[0].Name != "fixture.txt" || entries[0].IsDir || entries[0].Inode != 131 {
			t.Fatalf("i8count ListDirectory(/) = %+v, want [fixture.txt inode 131 (file)]", entries)
		}
		got, err := h.GetFile("fixture.txt")
		if err != nil {
			t.Fatalf("i8count GetFile(fixture.txt): %v", err)
		}
		if string(got) != "fixture\n" {
			t.Fatalf("i8count GetFile(fixture.txt) = %q, want %q", string(got), "fixture\n")
		}
	})
}

// TestXFSMalformed asserts that crafted on-disk corruption yields an explicit
// error, never a panic and never fabricated data.
func TestXFSMalformed(t *testing.T) {
	badMagic := func(t *testing.T, mutate func(img []byte), stage string) {
		t.Helper()
		img := buildFakeXFSImage(mutate)
		h, err := xfs.NewXFSHandler(img, 0)
		if err != nil {
			return // rejected at open time: fine
		}
		if _, err := h.ListDirectory("/"); err == nil {
			t.Fatalf("%s: ListDirectory succeeded, want error", stage)
		}
	}

	// Corrupt superblock magic: Open must reject it. (Byte 0 is already 'X',
	// so corrupt byte 1 instead.)
	badMagic(t, func(img []byte) { img[1] = 'Q' }, "bad superblock magic")

	// Corrupt inode magic: readInode must reject the inode.
	badMagic(t, func(img []byte) {
		binary.BigEndian.PutUint16(img[fakeXFSInoBlock*fakeXFSBlocksize:], 0x1234)
	}, "bad inode magic")

	// Corrupt inobt magic: readInode must reject the leaf.
	badMagic(t, func(img []byte) {
		copy(img[fakeXFSInobtBlock*fakeXFSBlocksize:], "WOW")
	}, "bad inobt magic")

	// Shortform dir count=1 but size=6: the single entry header must be
	// rejected as out of bounds.
	badMagic(t, func(img []byte) { img[fakeXFSInoBlock*fakeXFSBlocksize+0xb0] = 1 }, "sf count exceeds data")

	// Corrupt free bitmap: inode 128 marked free must be rejected.
	badMagic(t, func(img []byte) {
		binary.BigEndian.PutUint64(img[fakeXFSInobtBlock*fakeXFSBlocksize+0x40:], 0xffffffffffffffff)
	}, "inode marked free")

	// Truncated image: reads past the end must error, not panic.
	img := buildFakeXFSImage(nil)
	img.data = img.data[:512]
	h, err := xfs.NewXFSHandler(img, 0)
	if err == nil {
		if _, err := h.ListDirectory("/"); err == nil {
			t.Fatal("truncated image: ListDirectory succeeded, want error")
		}
	}

	// Malformed inode fed directly to GetFile must error, not panic.
	h2, err := xfs.NewXFSHandler(buildFakeXFSImage(func(img []byte) {
		binary.BigEndian.PutUint16(img[fakeXFSInoBlock*fakeXFSBlocksize:], 0x1234)
	}), 0)
	if err == nil {
		if _, err := h2.GetFile("fixture.txt"); err == nil {
			t.Fatal("bad inode: GetFile succeeded, want error")
		}
	}

	// A forged huge file size must error instead of attempting a giant
	// allocation or read.
	h3, err := xfs.NewXFSHandler(buildFakeXFSImage(func(img []byte) {
		xfsFileLayoutMutate()(img)
		// di_size of inode 131 (relIno 3) -> absurd value.
		binary.BigEndian.PutUint64(img[fakeXFSInoBlock*fakeXFSBlocksize+3*fakeXFSInodesize+0x38:], 1<<42)
	}), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler(huge size): %v", err)
	}
	if _, err := h3.GetFile("fixture.txt"); err == nil {
		t.Fatal("huge declared size: GetFile succeeded, want error")
	}

	// A forged local file whose declared size exceeds the inline fork must
	// error, not panic.
	h4, err := xfs.NewXFSHandler(buildFakeXFSImage(func(img []byte) {
		xfsFileLayoutMutate()(img)
		binary.BigEndian.PutUint64(img[fakeXFSInoBlock*fakeXFSBlocksize+3*fakeXFSInodesize+0x38:], 4096)
	}), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler(local oversize): %v", err)
	}
	if _, err := h4.GetFile("fixture.txt"); err == nil {
		t.Fatal("local oversize: GetFile succeeded, want error")
	}

	// A crafted di_forkoff whose data-fork end (core_end + forkoff*8) overruns
	// the 512-byte inode (forkoff >= 43, mirroring the kernel's XFS_DFORK_BOFF >=
	// XFS_LITINO check) must surface as an explicit error from dataForkLimit,
	// never a slice-bounds panic from ino[176:limit]. Small forkoffs are valid:
	// the attr fork sits at core_end + forkoff*8, never before the core.
	for _, forkoff := range []byte{43, 128, 255} {
		forkoff := forkoff
		t.Run(fmt.Sprintf("forkoff-%d", forkoff), func(t *testing.T) {
			h, err := xfs.NewXFSHandler(buildFakeXFSImage(func(img []byte) {
				root := img[fakeXFSInoBlock*fakeXFSBlocksize:]
				root[0x05] = 2       // format = extents
				root[0x52] = forkoff // di_forkoff
			}), 0)
			if err != nil {
				t.Fatalf("NewXFSHandler(forkoff=%d): %v", forkoff, err)
			}
			if _, err := h.ListDirectory("/"); err == nil {
				t.Fatalf("forkoff=%d: ListDirectory(/) succeeded, want error", forkoff)
			}
			if _, err := h.GetFile("fixture.txt"); err == nil {
				t.Fatalf("forkoff=%d: GetFile succeeded, want error", forkoff)
			}
		})
	}

	// A crafted shortform dir di_size must be checked against the data fork
	// LENGTH (limit-176, i.e. 336 for the default 512-byte inode), not against the
	// fork's END offset 512; and a dir too short for the 2-byte count/i8count
	// header must error. di_size in {1, 337, 400, 512} must surface as an explicit
	// error, never a slice-bounds panic and never a read past the inode.
	for _, size := range []uint64{1, 337, 400, 512} {
		size := size
		t.Run(fmt.Sprintf("sf-size-%d", size), func(t *testing.T) {
			h, err := xfs.NewXFSHandler(buildFakeXFSImage(func(img []byte) {
				binary.BigEndian.PutUint64(img[fakeXFSInoBlock*fakeXFSBlocksize+0x38:], size)
			}), 0)
			if err != nil {
				t.Fatalf("NewXFSHandler(sf size=%d): %v", size, err)
			}
			if _, err := h.ListDirectory("/"); err == nil {
				t.Fatalf("sf size=%d: ListDirectory(/) succeeded, want error", size)
			}
			if _, err := h.GetFile("fixture.txt"); err == nil {
				t.Fatalf("sf size=%d: GetFile(fixture.txt) succeeded, want error", size)
			}
		})
	}
}

// Small-AG geometry constants. The image mimics a real "small AG" filesystem
// (server.E01 p0/p2): sb_agblocks=16 but sb_agblklog=5 (2^5=32), so a bmbt
// startblock encodes agno<<5|agbno and must be converted via
// agno*agblocks+agbno — the identity only holds when agblocks==2^agblklog.
const (
	fakeSmallAGBlocksize = 4096
	fakeSmallAGInodesize = 512
	fakeSmallAGInopblock = 8
	fakeSmallAGAblocks   = 16 // AG size in blocks; != 2^agblklog (small-AG)
	fakeSmallAGAgcount   = 2
	fakeSmallAGAgblklog  = 5 // 2^5 = 32 != agblocks 16
	fakeSmallAGRootIno   = 64
	fakeSmallAGInoBlock  = 8  // inode 64 chunk at fsb 8 (AG 0 agbno 8)
	fakeSmallAGDirBlock  = 21 // fsb 21 = AG 1 agbno 5 (physical)
	fakeSmallAGFileBlock = 22 // fsb 22 = AG 1 agbno 6 (physical)
)

// buildFakeXFSSmallAG builds a small-AG XFS image whose root dir (inode 64,
// fmt=2) has one extent into AG 1 (encoded startblock 37, real fsb 21) holding
// an XDD3 dir-data block listing "smallag.txt" (inode 65), and whose file
// inode 65 has one extent into AG 1 (encoded 38, real fsb 22) holding "HELLO".
// Every on-disk extent in AG 1 is stored with the agno<<agblklog encoding, so
// a parser that treats the raw startblock as a linear fsb either reads past
// the image or lands on the wrong block.
func buildFakeXFSSmallAG(mutate func(img []byte)) *memXFSReader {
	img := make([]byte, 32*fakeSmallAGBlocksize)

	sb := img[0:512]
	copy(sb[0x00:0x04], "XFSB")
	binary.BigEndian.PutUint32(sb[0x04:], fakeSmallAGBlocksize)
	binary.BigEndian.PutUint64(sb[0x08:], 32)              // dblocks
	binary.BigEndian.PutUint64(sb[0x38:], fakeSmallAGRootIno)
	binary.BigEndian.PutUint32(sb[0x54:], fakeSmallAGAblocks)
	binary.BigEndian.PutUint32(sb[0x58:], fakeSmallAGAgcount)
	binary.BigEndian.PutUint16(sb[0x68:], fakeSmallAGInodesize)
	binary.BigEndian.PutUint16(sb[0x6a:], fakeSmallAGInopblock)
	copy(sb[0x6c:0x78], "FIXTURE")
	sb[0x78] = 12 // blocklog
	sb[0x79] = 9  // sectlog
	sb[0x7b] = 3  // inopblog
	sb[0x7c] = fakeSmallAGAgblklog
	binary.BigEndian.PutUint32(sb[0xd8:], 1) // FTYPE

	// AGI (byte 1024 of AG 0): inobt root at fsb 3, leaf level.
	agi := img[1024 : 1024+512]
	copy(agi[0:4], "XAGI")
	binary.BigEndian.PutUint32(agi[0x14:], 3)
	binary.BigEndian.PutUint32(agi[0x18:], 0)

	// inobt leaf at fsb 3: one record, inodes 64-127, 64+65 allocated.
	ibt := img[3*fakeSmallAGBlocksize:]
	copy(ibt[0:4], "IAB3")
	binary.BigEndian.PutUint16(ibt[4:], 0)
	binary.BigEndian.PutUint16(ibt[6:], 1)
	binary.BigEndian.PutUint32(ibt[0x38:], 64)
	binary.BigEndian.PutUint64(ibt[0x40:], 0xfffffffffffffffc) // bits 0,1 clear: inodes 64,65 allocated

	// Root dir inode 64 at fsb 8: fmt=2 (extents), one extent -> AG1 agbno 5.
	root := img[fakeSmallAGInoBlock*fakeSmallAGBlocksize:]
	binary.BigEndian.PutUint16(root[0x00:], 0x494e)
	binary.BigEndian.PutUint16(root[0x02:], 0x41ed) // 040755 dir
	root[0x04] = 3
	root[0x05] = 2                                              // format extents
	binary.BigEndian.PutUint32(root[0x10:], 2)                  // nlink
	binary.BigEndian.PutUint64(root[0x38:], fakeSmallAGBlocksize) // size = one block
	binary.BigEndian.PutUint32(root[0x4c:], 1)                  // nextents
	binary.BigEndian.PutUint64(root[0xb0:], 0)                  // l0: startoff 0
	binary.BigEndian.PutUint64(root[0xb8:], uint64(37)<<21|1)   // l1: startblock 37 (AG1<<5|5), count 1

	// File inode 65 at fsb 8 byte 512: fmt=2, one extent -> AG1 agbno 6.
	fi := img[fakeSmallAGInoBlock*fakeSmallAGBlocksize+fakeSmallAGInodesize:]
	binary.BigEndian.PutUint16(fi[0x00:], 0x494e)
	binary.BigEndian.PutUint16(fi[0x02:], 0x81a4) // 0100644
	fi[0x04] = 3
	fi[0x05] = 2
	binary.BigEndian.PutUint32(fi[0x10:], 1)     // nlink
	binary.BigEndian.PutUint64(fi[0x38:], 5)     // size = "HELLO"
	binary.BigEndian.PutUint32(fi[0x4c:], 1)     // nextents
	binary.BigEndian.PutUint64(fi[0xb0:], 0)     // l0: startoff 0
	binary.BigEndian.PutUint64(fi[0xb8:], uint64(38)<<21|1) // l1: startblock 38 (AG1<<5|6), count 1

	// XDD3 dir-data block at fsb 21 (AG 1 agbno 5): header + one entry.
	d := img[fakeSmallAGDirBlock*fakeSmallAGBlocksize:]
	copy(d[0:4], "XDD3")
	binary.BigEndian.PutUint64(d[0x40:], 65) // inode
	d[0x48] = 11                             // namelen
	copy(d[0x49:0x54], "smallag.txt")
	d[0x54] = 1                    // ftype REG
	binary.BigEndian.PutUint16(d[0x56:], 0x40) // tag = own offset

	// File data "HELLO" at fsb 22 (AG 1 agbno 6).
	copy(img[fakeSmallAGFileBlock*fakeSmallAGBlocksize:], "HELLO")

	if mutate != nil {
		mutate(img)
	}
	return &memXFSReader{data: img}
}

// TestXFSSmallAGExtents proves the small-AG fsbToFsb conversion end-to-end:
// a fmt=2 directory and a regular file whose extents live in AG 1 decode to
// the physical AG-relative blocks (agno*agblocks+agbno), not the encoded
// agno<<agblklog|agbno values. Before the fix the raw startblock read either
// failed (out of range) or landed on the wrong block for every AG>0 extent.
func TestXFSSmallAGExtents(t *testing.T) {
	h, err := xfs.NewXFSHandler(buildFakeXFSSmallAG(nil), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler: %v", err)
	}

	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "smallag.txt" || entries[0].IsDir || entries[0].Inode != 65 {
		t.Fatalf("ListDirectory(/) = %+v, want [smallag.txt inode 65 (file)]", entries)
	}

	got, err := h.GetFile("smallag.txt")
	if err != nil {
		t.Fatalf("GetFile(smallag.txt): %v", err)
	}
	if string(got) != "HELLO" {
		t.Fatalf("GetFile(smallag.txt) = %q, want %q", string(got), "HELLO")
	}
}

// TestXFSSmallAGXDD3Tail proves that an XDD3 dir-data block (no dir3 tail)
// accepts entries that extend to the exact 4096-byte block boundary. Reserving
// the XDB3 8-byte tail on an XDD3 block would drop the final entry. The block
// is a chain of 14 full 255-char entries (slot 272) plus a final 212-char entry
// (slot 224) that ends exactly at 4096 — the real grub2/i386-pc layout.
func TestXFSSmallAGXDD3Tail(t *testing.T) {
	h, err := xfs.NewXFSHandler(buildFakeXFSSmallAG(func(img []byte) {
		d := img[fakeSmallAGDirBlock*fakeSmallAGBlocksize:]
		clear(d)
		copy(d[0:4], "XDD3")
		off := 0x40
		for i := 0; i < 14; i++ { // 14 entries of 255-char names, slot 272
			slot := 272
			binary.BigEndian.PutUint64(d[off:], 65)
			d[off+8] = 255
			for j := 0; j < 255; j++ {
				d[off+9+j] = 'a'
			}
			d[off+9+255] = 1 // ftype REG
			binary.BigEndian.PutUint16(d[off+slot-2:off+slot], uint16(off))
			off += slot
		}
		slot := 224 // final entry, namelen 212; 64 + 14*272 + 224 == 4096 exactly
		binary.BigEndian.PutUint64(d[off:], 65)
		d[off+8] = 212
		for j := 0; j < 212; j++ {
			d[off+9+j] = 'a'
		}
		d[off+9+212] = 1 // ftype REG
		binary.BigEndian.PutUint16(d[off+slot-2:off+slot], uint16(off))
		off += slot
		if off != 4096 {
			panic(fmt.Sprintf("tail block off-by: %d", off))
		}
	}), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler: %v", err)
	}

	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	if len(entries) != 15 {
		t.Fatalf("ListDirectory(/) = %d entries, want 15 (14 full + final ending at block end)", len(entries))
	}
	for _, e := range entries {
		if e.Inode != 65 {
			t.Fatalf("entry %q has inode %d, want 65", e.Name, e.Inode)
		}
	}
}

// xfsBtreeFileMutate turns the fake image's inode 131 (fixture.txt) into a
// format-3 (btree) data fork: a compact bmdr root in the inode points at a v5
// bmbt leaf block (fsb 1) whose single extent record covers fsb 2, where the
// file content lives. This exercises the full bmdr root -> bmbt leaf -> extent
// -> block-read chain hermetically.
func xfsBtreeFileMutate() func(img []byte) {
	return func(img []byte) {
		xfsFileLayoutMutate()(img)
		// Make the filesystem v5 (CRC) so the bmbt leaf uses the 72-byte header.
		// The authoritative v5 marker is the low nibble of sb_versionnum being 5
		// (XFS_SB_VERSION_5); the CRCBIT in sb_features2 is not reliable on real
		// images, so it must not gate the CRC check.
		sb := img[0:512]
		binary.BigEndian.PutUint16(sb[0x64:], 0xb4b5)
		binary.BigEndian.PutUint32(sb[0xc8:], 1)
		// bmbt leaf at fsb 1, records at +72 (XFS_BTREE_LBLOCK_CRC_LEN).
		leaf := img[1*fakeXFSBlocksize:]
		copy(leaf[0:4], "BMA3")
		binary.BigEndian.PutUint16(leaf[4:], 0)              // level 0 (leaf)
		binary.BigEndian.PutUint16(leaf[6:], 1)              // numrecs
		binary.BigEndian.PutUint64(leaf[72:80], 0)           // l0: startoff 0, startblock low bits 0
		binary.BigEndian.PutUint64(leaf[80:88], (2<<21)|1)   // l1: startblock 2 (AG0 agbno 2), count 1
		copy(img[2*fakeXFSBlocksize:], "btree-content\n")    // data block at fsb 2
		// Inode 131 (relIno 3): format btree, size 14, bmdr root in the data fork.
		c := img[fakeXFSInoBlock*fakeXFSBlocksize+3*fakeXFSInodesize:]
		c[0x05] = 3                                 // format btree
		binary.BigEndian.PutUint64(c[0x38:], 14)    // di_size
		binary.BigEndian.PutUint16(c[0xb0:], 1)     // bmdr level 1 (interior)
		binary.BigEndian.PutUint16(c[0xb2:], 1)     // bmdr numrecs 1
		binary.BigEndian.PutUint64(c[0xb4:], 0)     // key: br_startoff 0
		// Pointers sit after the full maxrecs key section: fork is ino[0xb0:0x200]
		// (336 bytes), DSIZE=336, maxrecs=(336-4)/16=20, ptrsOff=4+20*8=164. Root
		// pointers are packed xfs_fsblock_t (agno<<agblklog | agbno); AG0 agbno 1
		// packs to 1 with agblklog=15, expanding back to fsb 1 via fsbToFsb.
		binary.BigEndian.PutUint64(c[0xb0+164:], 1) // root ptr: packed fsb 1
	}
}

// TestXFSBtreeDataFork proves a format-3 (btree) data fork reads correctly
// through the bmdr inode-resident root and the bmbt tree beneath it.
func TestXFSBtreeDataFork(t *testing.T) {
	h, err := xfs.NewXFSHandler(buildFakeXFSImage(xfsBtreeFileMutate()), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler: %v", err)
	}
	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "fixture.txt" || entries[0].Inode != 131 {
		t.Fatalf("ListDirectory(/) = %+v, want [fixture.txt inode 131]", entries)
	}
	got, err := h.GetFile("fixture.txt")
	if err != nil {
		t.Fatalf("GetFile(fixture.txt): %v", err)
	}
	if string(got) != "btree-content\n" {
		t.Fatalf("GetFile(fixture.txt) = %q, want %q", string(got), "btree-content\n")
	}
}

// xfsSymlinkMutate builds a fake root shortform dir listing: "fixture.txt"
// (file), "sub" (dir containing "inner.txt"), "link" (relative symlink to
// "fixture.txt"), "linkdir" (absolute symlink to "/sub"), and "loop" (a
// self-referential symlink). Symlink targets live inline in the local data
// fork, the short-link format.
func xfsSymlinkMutate() func(img []byte) {
	return func(img []byte) {
		// Allocate inodes 128-135 (clear free bits 0-7).
		binary.BigEndian.PutUint64(img[fakeXFSInobtBlock*fakeXFSBlocksize+0x40:], 0xffffffffffffff00)

		base := fakeXFSInoBlock * fakeXFSBlocksize
		root := img[base:]
		root[0xb0] = 5 // count
		root[0xb1] = 0 // i8count
		binary.BigEndian.PutUint32(root[0xb2:], 128)
		off := 0xb6 // after the 6-byte shortform header
		add := func(name string, ino uint32, ft byte) {
			root[off] = byte(len(name))
			binary.BigEndian.PutUint16(root[off+1:], 0)
			copy(root[off+3:off+3+len(name)], name)
			root[off+3+len(name)] = ft
			binary.BigEndian.PutUint32(root[off+4+len(name):], ino)
			off += 8 + len(name)
		}
		add("fixture.txt", 131, 1) // FT_REG
		add("sub", 129, 2)         // FT_DIR
		add("link", 132, 7)        // FT_SYMLINK
		add("linkdir", 133, 7)     // FT_SYMLINK
		add("loop", 135, 7)        // FT_SYMLINK
		binary.BigEndian.PutUint64(root[0x38:], 6+uint64(off-0xb6))

		// "sub" dir inode 129 (relIno 1): shortform dir with "inner.txt" (inode 134).
		s := img[base+fakeXFSInodesize:]
		binary.BigEndian.PutUint16(s[0x00:], 0x494e)
		binary.BigEndian.PutUint16(s[0x02:], 0x41ed)
		s[0x04] = 3
		s[0x05] = 1
		binary.BigEndian.PutUint32(s[0x10:], 2)
		s[0xb0] = 1
		s[0xb1] = 0
		binary.BigEndian.PutUint32(s[0xb2:], 128)
		s[0xb6] = 9 // namelen "inner.txt"
		binary.BigEndian.PutUint16(s[0xb7:], 0)
		copy(s[0xb9:0xc2], "inner.txt")
		s[0xc2] = 1 // FT_REG
		binary.BigEndian.PutUint32(s[0xc3:], 134)
		binary.BigEndian.PutUint64(s[0x38:], 6+17) // 6-byte header + (8+9)-byte entry

		// "fixture.txt" file inode 131 (relIno 3): local "fixture\n".
		f := img[base+3*fakeXFSInodesize:]
		binary.BigEndian.PutUint16(f[0x00:], 0x494e)
		binary.BigEndian.PutUint16(f[0x02:], 0x81a4)
		f[0x04] = 3
		f[0x05] = 1
		binary.BigEndian.PutUint32(f[0x10:], 1)
		binary.BigEndian.PutUint64(f[0x38:], 8)
		copy(f[0xb0:0xb8], "fixture\n")

		// "link" symlink inode 132 (relIno 4): relative target "fixture.txt".
		l := img[base+4*fakeXFSInodesize:]
		binary.BigEndian.PutUint16(l[0x00:], 0x494e)
		binary.BigEndian.PutUint16(l[0x02:], 0xa1ff) // 0120777 symlink
		l[0x04] = 3
		l[0x05] = 1
		binary.BigEndian.PutUint32(l[0x10:], 1)
		binary.BigEndian.PutUint64(l[0x38:], 11) // len("fixture.txt")
		copy(l[0xb0:0xbb], "fixture.txt")

		// "linkdir" symlink inode 133 (relIno 5): absolute target "/sub".
		ld := img[base+5*fakeXFSInodesize:]
		binary.BigEndian.PutUint16(ld[0x00:], 0x494e)
		binary.BigEndian.PutUint16(ld[0x02:], 0xa1ff)
		ld[0x04] = 3
		ld[0x05] = 1
		binary.BigEndian.PutUint32(ld[0x10:], 1)
		binary.BigEndian.PutUint64(ld[0x38:], 4) // len("/sub")
		copy(ld[0xb0:0xb4], "/sub")

		// "loop" symlink inode 135 (relIno 7): self-referential target "loop".
		lo := img[base+7*fakeXFSInodesize:]
		binary.BigEndian.PutUint16(lo[0x00:], 0x494e)
		binary.BigEndian.PutUint16(lo[0x02:], 0xa1ff)
		lo[0x04] = 3
		lo[0x05] = 1
		binary.BigEndian.PutUint32(lo[0x10:], 1)
		binary.BigEndian.PutUint64(lo[0x38:], 4) // len("loop")
		copy(lo[0xb0:0xb4], "loop")
	}
}

// TestXFSSymlink proves symlink targets are read as real data and followed
// with the settled semantics: GetFile/GetFileByPath stop at a final symlink,
// while ListDirectory/SearchFiles follow it.
func TestXFSSymlink(t *testing.T) {
	h, err := xfs.NewXFSHandler(buildFakeXFSImage(xfsSymlinkMutate()), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler: %v", err)
	}

	// GetFile on a final symlink returns the target string, not the content.
	got, err := h.GetFile("link")
	if err != nil {
		t.Fatalf("GetFile(link): %v", err)
	}
	if string(got) != "fixture.txt" {
		t.Fatalf("GetFile(link) = %q, want %q", string(got), "fixture.txt")
	}

	// GetFileByPath reports the symlink itself (mode symlink, non-dir).
	fi, err := h.GetFileByPath("link")
	if err != nil {
		t.Fatalf("GetFileByPath(link): %v", err)
	}
	if fi.Mode != 0xa000 || fi.IsDir {
		t.Fatalf("GetFileByPath(link) = %+v, want symlink mode 0xa000 non-dir", fi)
	}

	// ListDirectory follows an absolute final symlink to its target directory.
	entries, err := h.ListDirectory("linkdir")
	if err != nil {
		t.Fatalf("ListDirectory(linkdir): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "inner.txt" || entries[0].Inode != 134 {
		t.Fatalf("ListDirectory(linkdir) = %+v, want [inner.txt inode 134]", entries)
	}

	// GetFile on an absolute symlink to a directory returns the target string.
	if got, err := h.GetFile("linkdir"); err != nil || string(got) != "/sub" {
		t.Fatalf("GetFile(linkdir) = %q, %v; want %q", got, err, "/sub")
	}

	// ListDirectory following a symlink to a file errors explicitly.
	if _, err := h.ListDirectory("link"); err == nil {
		t.Fatal("ListDirectory(link): succeeded, want error (final target is a file)")
	}

	// A self-referential symlink errors instead of hanging.
	if _, err := h.ListDirectory("loop"); err == nil {
		t.Fatal("ListDirectory(loop): succeeded, want symlink-loop error")
	}

	// A direct path through a real directory still lists its contents.
	if entries, err := h.ListDirectory("sub"); err != nil || len(entries) != 1 || entries[0].Name != "inner.txt" {
		t.Fatalf("ListDirectory(sub) = %+v, %v; want [inner.txt]", entries, err)
	}
}

// xfsDotDirMutate turns the fake root into a block-format (fmt=2) directory
// whose data block stores the real on-disk "." and ".." self/parent entries
// plus a genuine "real.txt" file entry. Block/node-format XFS directories
// persist those entries, unlike shortform dirs where they are implicit.
func xfsDotDirMutate() func(img []byte) {
	return func(img []byte) {
		xfsFileLayoutMutate()(img)
		ino := img[fakeXFSInoBlock*fakeXFSBlocksize:]
		ino[0x05] = 2                                       // format extents
		binary.BigEndian.PutUint64(ino[0x38:], 4096)        // size = one block
		binary.BigEndian.PutUint32(ino[0x4c:], 1)           // nextents
		binary.BigEndian.PutUint64(ino[0xb0:], 0)           // l0: startoff 0
		binary.BigEndian.PutUint64(ino[0xb8:], uint64(8)<<21|1) // l1: startblock fsb 8, count 1

		d := img[8*fakeXFSBlocksize:]
		copy(d[0:4], "XDD3")
		off := 0x40
		add := func(name string, inumber uint64, ftype byte) {
			binary.BigEndian.PutUint64(d[off:], inumber)
			d[off+8] = byte(len(name))
			copy(d[off+9:off+9+len(name)], name)
			d[off+9+len(name)] = ftype
			slot := (len(name) + 12 + 7) &^ 7
			binary.BigEndian.PutUint16(d[off+slot-2:off+slot], uint16(off))
			off += slot
		}
		add(".", 128, 2)       // self
		add("..", 128, 2)      // parent
		add("real.txt", 131, 1) // genuine file
	}
}

// TestXFSDotEntriesFilter proves the public listing excludes the "." and ".."
// self/parent entries (matching the FAT32/ext4 convention, so a downstream
// walker cannot recurse into "." and loop) while parent resolution still works:
// resolvePath still reads ".." from the raw, unfiltered directory data.
func TestXFSDotEntriesFilter(t *testing.T) {
	h, err := xfs.NewXFSHandler(buildFakeXFSImage(xfsDotDirMutate()), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler: %v", err)
	}
	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "real.txt" || entries[0].Inode != 131 {
		t.Fatalf("ListDirectory(/) = %+v, want [real.txt inode 131] (dot entries filtered)", entries)
	}
	// The raw block still carries "..", and resolvePath follows it to the root,
	// so a path containing ".." keeps working after filtering.
	fi, err := h.GetFileByPath("/..")
	if err != nil {
		t.Fatalf("GetFileByPath(/..): %v", err)
	}
	if !fi.IsDir || fi.Name != ".." {
		t.Fatalf("GetFileByPath(/..) = %+v, want root dir", fi)
	}
}
