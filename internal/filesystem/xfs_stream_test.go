package filesystem_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"

	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/xfs"
)

// buildFakeXFSStreamImage builds a fake XFS image whose root shortform dir
// lists regular files in every data-fork format the streaming reader must
// handle: multi.bin (extents, 2 blocks), sparse.bin (extents with a hole),
// empty.txt (size 0) and local.txt (inline data), plus a symlink.
func buildFakeXFSStreamImage() *memXFSReader {
	img := make([]byte, 0x22000) // 34 blocks: data at fsb 17-20

	// Superblock (first sector) — same geometry as buildFakeXFSImage.
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
	// FTYPE feature bit so shortform entries carry a ftype byte.
	binary.BigEndian.PutUint32(sb[0xd8:], 1)

	// AGI header (byte 1024 of AG 0).
	agi := img[1024 : 1024+512]
	copy(agi[0:4], "XAGI")
	binary.BigEndian.PutUint32(agi[0x14:], fakeXFSInobtBlock) // inobt root
	binary.BigEndian.PutUint32(agi[0x18:], 0)                 // level: leaf

	// inobt leaf block 3: one record covering inodes 128-191, with inodes
	// 128-135 allocated (bits 0-6 clear in the free bitmap).
	ibt := img[fakeXFSInobtBlock*fakeXFSBlocksize:]
	copy(ibt[0:4], "IAB3")
	binary.BigEndian.PutUint16(ibt[4:], 0)     // level
	binary.BigEndian.PutUint16(ibt[6:], 1)     // numrecs
	binary.BigEndian.PutUint32(ibt[0x38:], 128) // startino
	binary.BigEndian.PutUint64(ibt[0x40:], 0xffffffffffffff00)

	// Root dir inode 128: shortform dir listing the five entries below.
	ino := img[fakeXFSInoBlock*fakeXFSBlocksize:]
	binary.BigEndian.PutUint16(ino[0x00:], 0x494e) // "IN"
	binary.BigEndian.PutUint16(ino[0x02:], 0x41ed) // mode 040755 (dir)
	ino[0x04] = 3
	ino[0x05] = 1 // format local
	binary.BigEndian.PutUint32(ino[0x10:], 2)
	ino[0xb0] = 5 // count
	ino[0xb1] = 0 // i8count
	binary.BigEndian.PutUint32(ino[0xb2:], fakeXFSRootIno)
	// Entries: namelen(1) offset(2) name ftype(1) inumber(4).
	off := 0
	addEntry := func(name string, ftype byte, inoNum uint32) {
		d := ino[0xb6:]
		d[off] = byte(len(name))
		binary.BigEndian.PutUint16(d[off+1:], uint16(off))
		copy(d[off+3:], name)
		d[off+3+len(name)] = ftype
		binary.BigEndian.PutUint32(d[off+4+len(name):], inoNum)
		off += 8 + len(name)
	}
	addEntry("multi.bin", 1, 131)
	addEntry("sparse.bin", 1, 132)
	addEntry("empty.txt", 1, 133)
	addEntry("local.txt", 1, 134)
	addEntry("link", 7, 135)
	binary.BigEndian.PutUint64(ino[0x38:], uint64(6+off)) // size

	// Inode 131 (multi.bin): extents, one 2-block extent at fsb 17.
	m := img[fakeXFSInoBlock*fakeXFSBlocksize+3*fakeXFSInodesize:]
	binary.BigEndian.PutUint16(m[0x00:], 0x494e)
	binary.BigEndian.PutUint16(m[0x02:], 0x81a4) // 0100644
	m[0x04] = 3
	m[0x05] = 2 // format extents
	binary.BigEndian.PutUint32(m[0x10:], 1)
	binary.BigEndian.PutUint64(m[0x38:], 8192) // size
	binary.BigEndian.PutUint32(m[0x4c:], 1)    // nextents
	// extent {startoff:0, startblock:17, blockcount:2}
	// xfs_bmbt_rec: l0 = (startoff<<9) | (startblock>>43), l1 = (startblock<<21)|count.
	binary.BigEndian.PutUint64(m[0xb0:], 0)
	binary.BigEndian.PutUint64(m[0xb8:], 17<<21|2)

	// Inode 132 (sparse.bin): extents {0,19,1}, {2,20,1}; block 1 is a hole.
	s := img[fakeXFSInoBlock*fakeXFSBlocksize+4*fakeXFSInodesize:]
	binary.BigEndian.PutUint16(s[0x00:], 0x494e)
	binary.BigEndian.PutUint16(s[0x02:], 0x81a4)
	s[0x04] = 3
	s[0x05] = 2
	binary.BigEndian.PutUint32(s[0x10:], 1)
	binary.BigEndian.PutUint64(s[0x38:], 12288) // 3 blocks
	binary.BigEndian.PutUint32(s[0x4c:], 2)     // nextents
	binary.BigEndian.PutUint64(s[0xb0:], 0)
	binary.BigEndian.PutUint64(s[0xb8:], 19<<21|1)
	binary.BigEndian.PutUint64(s[0xc0:], 2<<9) // startoff 2; startblock top bits zero
	binary.BigEndian.PutUint64(s[0xc8:], 20<<21|1)

	// Inode 133 (empty.txt): size 0, no extents.
	e := img[fakeXFSInoBlock*fakeXFSBlocksize+5*fakeXFSInodesize:]
	binary.BigEndian.PutUint16(e[0x00:], 0x494e)
	binary.BigEndian.PutUint16(e[0x02:], 0x81a4)
	e[0x04] = 3
	e[0x05] = 2
	binary.BigEndian.PutUint32(e[0x10:], 1)
	binary.BigEndian.PutUint64(e[0x38:], 0)

	// Inode 134 (local.txt): inline data fork "hello\n".
	l := img[fakeXFSInoBlock*fakeXFSBlocksize+6*fakeXFSInodesize:]
	binary.BigEndian.PutUint16(l[0x00:], 0x494e)
	binary.BigEndian.PutUint16(l[0x02:], 0x81a4)
	l[0x04] = 3
	l[0x05] = 1 // format local
	binary.BigEndian.PutUint32(l[0x10:], 1)
	binary.BigEndian.PutUint64(l[0x38:], 6)
	copy(l[0xb0:0xb6], "hello\n")

	// Inode 135 (link): symlink whose content is a target string.
	ln := img[fakeXFSInoBlock*fakeXFSBlocksize+7*fakeXFSInodesize:]
	binary.BigEndian.PutUint16(ln[0x00:], 0x494e)
	binary.BigEndian.PutUint16(ln[0x02:], 0xa1ff) // 0120777 symlink
	ln[0x04] = 3
	ln[0x05] = 1
	binary.BigEndian.PutUint32(ln[0x10:], 1)
	binary.BigEndian.PutUint64(ln[0x38:], 11)
	copy(ln[0xb0:0xbb], "fixture.txt")

	// Data blocks: 17 = 0xAA, 18 = 0xBB, 19 = 0xCC, 20 = 0xDD.
	fill := func(fsb int, val byte) {
		for i := fsb * fakeXFSBlocksize; i < (fsb+1)*fakeXFSBlocksize; i++ {
			img[i] = val
		}
	}
	fill(17, 0xAA)
	fill(18, 0xBB)
	fill(19, 0xCC)
	fill(20, 0xDD)

	return &memXFSReader{data: img}
}

func xfsStreamHandler(t *testing.T) *xfs.XFS {
	t.Helper()
	h, err := xfs.NewXFSHandler(buildFakeXFSStreamImage(), 0)
	if err != nil {
		t.Fatalf("NewXFSHandler: %v", err)
	}
	return h
}

// TestXFSOpenFileStreamsMultiBlock verifies a two-block extent file streams
// correctly, byte for byte, including a ReadAt that crosses the block boundary.
func TestXFSOpenFileStreamsMultiBlock(t *testing.T) {
	h := xfsStreamHandler(t)

	rc, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile(multi.bin): %v", err)
	}
	defer rc.Close()

	want := make([]byte, 8192)
	for i := 0; i < 4096; i++ {
		want[i] = 0xAA
	}
	for i := 4096; i < 8192; i++ {
		want[i] = 0xBB
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("multi.bin content mismatch: got %d bytes", len(got))
	}

	// Cross-boundary ReadAt.
	ra := rc.(io.ReaderAt)
	buf := make([]byte, 8)
	if n, err := ra.ReadAt(buf, 4093); n != 8 || err != nil {
		t.Fatalf("ReadAt(4093): n=%d err=%v", n, err)
	}
	if !bytes.Equal(buf, []byte{0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}) {
		t.Fatalf("cross-boundary ReadAt = %x", buf)
	}
}

// TestXFSOpenFileSparse verifies a file with an unallocated block within its
// declared size reads the hole as zeros, matching XFS sparse semantics.
func TestXFSOpenFileSparse(t *testing.T) {
	h := xfsStreamHandler(t)

	rc, err := h.OpenFile("sparse.bin")
	if err != nil {
		t.Fatalf("OpenFile(sparse.bin): %v", err)
	}
	defer rc.Close()

	want := make([]byte, 12288)
	for i := 0; i < 4096; i++ {
		want[i] = 0xCC
	}
	for i := 8192; i < 12288; i++ {
		want[i] = 0xDD
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("sparse.bin mismatch (hole not zero): got %d bytes", len(got))
	}

	// Mid-hole ReadAt returns zeros.
	ra := rc.(io.ReaderAt)
	buf := make([]byte, 16)
	if n, err := ra.ReadAt(buf, 4100); n != 16 || err != nil {
		t.Fatalf("ReadAt(4100): n=%d err=%v", n, err)
	}
	for _, b := range buf {
		if b != 0 {
			t.Fatalf("hole ReadAt = %x, want zeros", buf)
		}
	}
}

// TestXFSOpenFileEmpty verifies a size-0 file reads cleanly as io.EOF.
func TestXFSOpenFileEmpty(t *testing.T) {
	h := xfsStreamHandler(t)

	rc, err := h.OpenFile("empty.txt")
	if err != nil {
		t.Fatalf("OpenFile(empty.txt): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll(empty.txt): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty.txt = %d bytes, want 0", len(got))
	}
	if _, err := rc.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("Seek end: %v", err)
	}
}

// TestXFSOpenFileLocal verifies an inline (local data fork) file streams.
func TestXFSOpenFileLocal(t *testing.T) {
	h := xfsStreamHandler(t)

	rc, err := h.OpenFile("local.txt")
	if err != nil {
		t.Fatalf("OpenFile(local.txt): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("local.txt = %q, want %q", string(got), "hello\n")
	}
}

// TestXFSOpenFileErrors verifies the sentinel errors unwrap through the XFS
// handler's path resolution, and that a symlink is not streamed.
func TestXFSOpenFileErrors(t *testing.T) {
	h := xfsStreamHandler(t)

	if _, err := h.OpenFile("missing.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("OpenFile(missing.txt) err = %v, want ErrNotFound", err)
	}
	if _, err := h.OpenFile("/"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("OpenFile(/) err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.OpenFile("multi.bin/child"); !errors.Is(err, filesystem.ErrNotDirectory) {
		t.Errorf("OpenFile(multi.bin/child) err = %v, want ErrNotDirectory", err)
	}
	if _, err := h.OpenFile("link"); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Errorf("OpenFile(link) err = %v, want ErrUnsupported", err)
	}
}

// TestXFSOpenFileConcurrentReadAt verifies concurrent ReadAt on the same handle
// returns byte-identical data (the io.ReaderAt contract sqlite's VFS asserts).
func TestXFSOpenFileConcurrentReadAt(t *testing.T) {
	h := xfsStreamHandler(t)

	rc, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	ra := rc.(io.ReaderAt)

	want := make([]byte, 8192)
	for i := 0; i < 4096; i++ {
		want[i] = 0xAA
	}
	for i := 4096; i < 8192; i++ {
		want[i] = 0xBB
	}

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				buf := make([]byte, 64)
				off := int64(i*13) % 8128
				n, err := ra.ReadAt(buf, off)
				if err != nil {
					errs <- fmt.Errorf("worker ReadAt(%d): %v", off, err)
					return
				}
				if n != len(buf) || !bytes.Equal(buf, want[off:off+64]) {
					errs <- fmt.Errorf("worker ReadAt(%d): data mismatch", off)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestXFSOpenFileIndependentHandles verifies two open handles share no cursor
// state: interleaved Read calls stay independent.
func TestXFSOpenFileIndependentHandles(t *testing.T) {
	h := xfsStreamHandler(t)

	a, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile(a): %v", err)
	}
	defer a.Close()
	b, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile(b): %v", err)
	}
	defer b.Close()

	if _, err := a.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("a.Read: %v", err)
	}
	// a is at offset 4096 (block 1, 0xBB); b is still at 0 (0xAA).
	ab := make([]byte, 4)
	if _, err := a.Read(ab); err != nil {
		t.Fatalf("a.Read(ab): %v", err)
	}
	if ab[0] != 0xBB {
		t.Fatalf("a offset 4096 = %02x, want 0xBB", ab[0])
	}
	bb := make([]byte, 4)
	if _, err := b.Read(bb); err != nil {
		t.Fatalf("b.Read(bb): %v", err)
	}
	if bb[0] != 0xAA {
		t.Fatalf("b offset 0 = %02x, want 0xAA", bb[0])
	}
}

// TestXFSOpenFileRealFixtureSentinel verifies the streaming path on a real
// committed XFS E01 (whose root is an empty shortform dir): sentinels unwrap
// and missing files error rather than fabricating content.
func TestXFSOpenFileRealFixtureSentinel(t *testing.T) {
	h, img := xfsFixture(t, filepath.Join("..", "..", "testdata", "e01", "xfs-encase25-zlib.E01"))
	defer img.Close()

	if _, err := h.OpenFile("fixture.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("OpenFile(fixture.txt) err = %v, want ErrNotFound", err)
	}
	if _, err := h.OpenFile("/"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("OpenFile(/) err = %v, want ErrIsDirectory", err)
	}
}
