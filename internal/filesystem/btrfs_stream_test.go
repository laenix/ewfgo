package filesystem_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/btrfs"
)

// buildFakeDiskExtent builds a REG (typ 1) EXTENT_DATA payload pointing at
// logical diskBytenr (offset 0 in the extent) holding numBytes file bytes.
func buildFakeDiskExtent(diskBytenr, numBytes uint64) []byte {
	fei := make([]byte, 53)
	fei[20] = 1 // BTRFS_FILE_EXTENT_REG
	putU64(fei, 21, diskBytenr)
	putU64(fei, 29, numBytes)
	putU64(fei, 37, 0) // offset in extent
	putU64(fei, 45, numBytes)
	return fei
}

// buildFakePreallocExtent builds a PREALLOC (typ 2) EXTENT_DATA payload with no
// backing data (disk_bytenr 0): such an extent reads as zeros.
func buildFakePreallocExtent(numBytes uint64) []byte {
	fei := make([]byte, 53)
	fei[20] = 2 // BTRFS_FILE_EXTENT_PREALLOC
	putU64(fei, 21, 0)
	putU64(fei, 45, numBytes)
	return fei
}

// buildFakeBtrfsStreamImage builds a fake btrfs image whose FS tree lists the
// regular files every streaming path must handle: multi.bin (two disk extents),
// sparse.bin (disk extent + hole + disk extent), inline.txt (inline extent),
// empty.txt (size 0), prealloc.bin (PREALLOC without backing data), and link (a
// symlink). Disk data lives in the identity-mapped region [0x1C0000, 0x200000).
func buildFakeBtrfsStreamImage() *memBtrfsReader {
	const (
		fsRootBytenr = 0x180000
		dirIno       = 256
		multiIno     = 257
		sparseIno    = 258
		inlineIno    = 259
		emptyIno     = 260
		preallocIno  = 261
		linkIno      = 262
	)
	rootItem := make([]byte, 184)
	putU64(rootItem, 176, fsRootBytenr)
	rootLeaf := buildFakeLeaf(fakeBtrfsRootTree, 1, []fakeBtrfsItem{
		{objectid: 5, typ: 132, offset: 0, data: rootItem},
	})
	img := buildFakeBtrfsImage(rootLeaf)

	fsLeaf := buildFakeLeaf(fsRootBytenr, 5, []fakeBtrfsItem{
		// Root directory inode 256 + its five DIR_ITEMs (ascending key order).
		{objectid: dirIno, typ: 1, offset: 0, data: buildFakeInodeItem(0, 0x41ED)},
		{objectid: dirIno, typ: 84, offset: 0, data: buildFakeDirItem(multiIno, 1, "multi.bin")},
		{objectid: dirIno, typ: 84, offset: 1, data: buildFakeDirItem(sparseIno, 1, "sparse.bin")},
		{objectid: dirIno, typ: 84, offset: 2, data: buildFakeDirItem(inlineIno, 1, "inline.txt")},
		{objectid: dirIno, typ: 84, offset: 3, data: buildFakeDirItem(emptyIno, 1, "empty.txt")},
		{objectid: dirIno, typ: 84, offset: 4, data: buildFakeDirItem(preallocIno, 1, "prealloc.bin")},
		{objectid: dirIno, typ: 84, offset: 5, data: buildFakeDirItem(linkIno, 7, "link")},

		// multi.bin: two disk extents of 0xAA / 0xBB, size 8192.
		{objectid: multiIno, typ: 1, offset: 0, data: buildFakeInodeItem(8192, 0x81A4)},
		{objectid: multiIno, typ: 108, offset: 0, data: buildFakeDiskExtent(0x1C0000, 4096)},
		{objectid: multiIno, typ: 108, offset: 4096, data: buildFakeDiskExtent(0x1C1000, 4096)},

		// sparse.bin: disk extent, then a 4096-byte hole, then a disk extent.
		{objectid: sparseIno, typ: 1, offset: 0, data: buildFakeInodeItem(12288, 0x81A4)},
		{objectid: sparseIno, typ: 108, offset: 0, data: buildFakeDiskExtent(0x1C2000, 4096)},
		{objectid: sparseIno, typ: 108, offset: 8192, data: buildFakeDiskExtent(0x1C3000, 4096)},

		// inline.txt: inline extent "hello\n".
		{objectid: inlineIno, typ: 1, offset: 0, data: buildFakeInodeItem(6, 0x81A4)},
		{objectid: inlineIno, typ: 108, offset: 0, data: buildFakeInlineExtent([]byte("hello\n"))},

		// empty.txt: size 0, no EXTENT_DATA items at all.
		{objectid: emptyIno, typ: 1, offset: 0, data: buildFakeInodeItem(0, 0x81A4)},

		// prealloc.bin: PREALLOC extent without backing data — reads as zeros.
		{objectid: preallocIno, typ: 1, offset: 0, data: buildFakeInodeItem(4096, 0x81A4)},
		{objectid: preallocIno, typ: 108, offset: 0, data: buildFakePreallocExtent(4096)},

		// link: symlink inode (mode 0120777); its content is a target string.
		{objectid: linkIno, typ: 1, offset: 0, data: buildFakeInodeItem(12, 0xA1FF)},
		{objectid: linkIno, typ: 108, offset: 0, data: buildFakeInlineExtent([]byte("fixture.txt"))},
	})
	copy(img.data[fsRootBytenr:fsRootBytenr+fakeBtrfsNodesize], fsLeaf)

	// Disk extent bytes: 0x1C0000 = 0xAA, 0x1C1000 = 0xBB, 0x1C2000 = 0xCC,
	// 0x1C3000 = 0xDD (each 4096 bytes).
	fill := func(phys uint64, val byte) {
		for i := phys; i < phys+4096; i++ {
			img.data[i] = val
		}
	}
	fill(0x1C0000, 0xAA)
	fill(0x1C1000, 0xBB)
	fill(0x1C2000, 0xCC)
	fill(0x1C3000, 0xDD)
	return img
}

func btrfsStreamHandler(t *testing.T) *btrfs.Btrfs {
	t.Helper()
	h, err := btrfs.NewBtrfsHandler(buildFakeBtrfsStreamImage(), 0)
	if err != nil {
		t.Fatalf("NewBtrfsHandler: %v", err)
	}
	return h
}

// TestBtrfsOpenFileStreamsMultiBlock verifies a file spanning two disk extents
// streams byte for byte, including a ReadAt that crosses the extent boundary.
func TestBtrfsOpenFileStreamsMultiBlock(t *testing.T) {
	h := btrfsStreamHandler(t)

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

	// Cross-extent-boundary ReadAt.
	ra := rc.(io.ReaderAt)
	buf := make([]byte, 8)
	if n, err := ra.ReadAt(buf, 4093); n != 8 || err != nil {
		t.Fatalf("ReadAt(4093): n=%d err=%v", n, err)
	}
	if !bytes.Equal(buf, []byte{0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}) {
		t.Fatalf("cross-boundary ReadAt = %x", buf)
	}
}

// TestBtrfsOpenFileSparse verifies the gap between two EXTENT_DATA items reads
// as zeros, matching btrfs sparse-file semantics.
func TestBtrfsOpenFileSparse(t *testing.T) {
	h := btrfsStreamHandler(t)

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

// TestBtrfsOpenFilePrealloc verifies a PREALLOC extent without backing data
// (disk_bytenr 0) reads as zeros.
func TestBtrfsOpenFilePrealloc(t *testing.T) {
	h := btrfsStreamHandler(t)

	rc, err := h.OpenFile("prealloc.bin")
	if err != nil {
		t.Fatalf("OpenFile(prealloc.bin): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 4096 {
		t.Fatalf("prealloc.bin = %d bytes, want 4096", len(got))
	}
	for i, b := range got {
		if b != 0 {
			t.Fatalf("prealloc.bin[%d] = %02x, want 0", i, b)
		}
	}
}

// TestBtrfsOpenFileInline verifies an inline extent streams.
func TestBtrfsOpenFileInline(t *testing.T) {
	h := btrfsStreamHandler(t)

	rc, err := h.OpenFile("inline.txt")
	if err != nil {
		t.Fatalf("OpenFile(inline.txt): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("inline.txt = %q, want %q", string(got), "hello\n")
	}
}

// TestBtrfsOpenFileEmpty verifies a size-0 file reads cleanly as io.EOF.
func TestBtrfsOpenFileEmpty(t *testing.T) {
	h := btrfsStreamHandler(t)

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

// TestBtrfsOpenFileErrors verifies the sentinel errors unwrap through path
// resolution, and that a symlink is not streamed.
func TestBtrfsOpenFileErrors(t *testing.T) {
	h := btrfsStreamHandler(t)

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

// TestBtrfsOpenFileConcurrentReadAt verifies concurrent ReadAt on the same
// handle returns byte-identical data (the io.ReaderAt contract sqlite asserts).
func TestBtrfsOpenFileConcurrentReadAt(t *testing.T) {
	h := btrfsStreamHandler(t)

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

// TestBtrfsOpenFileIndependentHandles verifies two open handles share no cursor
// state: interleaved Read calls stay independent.
func TestBtrfsOpenFileIndependentHandles(t *testing.T) {
	h := btrfsStreamHandler(t)

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
	// a is at offset 4096 (second extent, 0xBB); b is still at 0 (0xAA).
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

// TestBtrfsOpenFileRealFixture streams real on-disk files from every committed
// btrfs E01 variant: disk.bin (a genuine disk-extent file) must be byte
// identical to GetFile, and fixture.txt (inline) must match its injected bytes.
func TestBtrfsOpenFileRealFixture(t *testing.T) {
	for _, name := range btrfsFixtureE01s {
		t.Run(name, func(t *testing.T) {
			h, img := btrfsFixture(t, filepath.Join("..", "..", "testdata", "e01", name))
			defer img.Close()

			// disk.bin: streaming must equal GetFile byte for byte (both read the
			// same disk extents through the same chunk map).
			rc, err := h.OpenFile("disk.bin")
			if err != nil {
				t.Fatalf("OpenFile(disk.bin): %v", err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("ReadAll(disk.bin): %v", err)
			}
			want := diskBinPattern()
			if !bytes.Equal(got, want) {
				t.Fatalf("streamed disk.bin mismatch: got %d bytes", len(got))
			}

			// fixture.txt: inline extent streams its injected bytes.
			rc, err = h.OpenFile("fixture.txt")
			if err != nil {
				t.Fatalf("OpenFile(fixture.txt): %v", err)
			}
			got, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("ReadAll(fixture.txt): %v", err)
			}
			if string(got) != "fixture\n" {
				t.Fatalf("fixture.txt = %q, want %q", string(got), "fixture\n")
			}

			// Sentinels unwrap through the real tree walk; nothing is fabricated.
			if _, err := h.OpenFile("missing.txt"); !errors.Is(err, filesystem.ErrNotFound) {
				t.Errorf("OpenFile(missing.txt) err = %v, want ErrNotFound", err)
			}
			if _, err := h.OpenFile("/"); !errors.Is(err, filesystem.ErrIsDirectory) {
				t.Errorf("OpenFile(/) err = %v, want ErrIsDirectory", err)
			}
			if _, err := h.OpenFile("disk.bin/child"); !errors.Is(err, filesystem.ErrNotDirectory) {
				t.Errorf("OpenFile(disk.bin/child) err = %v, want ErrNotDirectory", err)
			}
		})
	}
}

// TestBtrfsOpenFileReaderAtContract guards the io.ReaderAt contract: a read
// that runs past the end of the file must return the real prefix with io.EOF
// (n < len(p) implies a non-nil error), and an empty buffer reads as n=0.
func TestBtrfsOpenFileReaderAtContract(t *testing.T) {
	h := btrfsStreamHandler(t)

	rc, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	ra := rc.(io.ReaderAt)

	// Prefix read at the very end: [8192, 8196) → 0 bytes + io.EOF.
	buf := make([]byte, 4)
	n, err := ra.ReadAt(buf, 8192)
	if n != 0 || err != io.EOF {
		t.Fatalf("ReadAt(8192) = (%d, %v), want (0, io.EOF)", n, err)
	}

	// Partial tail read: [8188, 8196) → 4 real bytes + io.EOF.
	buf = make([]byte, 8)
	n, err = ra.ReadAt(buf, 8188)
	if n != 4 || err != io.EOF {
		t.Fatalf("ReadAt(8188) = (%d, %v), want (4, io.EOF)", n, err)
	}
	if !bytes.Equal(buf[:4], []byte{0xBB, 0xBB, 0xBB, 0xBB}) {
		t.Fatalf("tail bytes = %x, want 0xBB x4", buf[:4])
	}

	// Empty buffer at EOF reads as (0, io.EOF), matching stdlib bytes.Reader.
	if n, err := ra.ReadAt(nil, 8192); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt(nil, 8192) = (%d, %v), want (0, io.EOF)", n, err)
	}
}

// TestBtrfsOpenFileCompressionRejected verifies a compressed EXTENT_DATA item is
// an explicit error, never silently streamed as fake content (EWF 红线).
func TestBtrfsOpenFileCompressionRejected(t *testing.T) {
	const (
		fsRootBytenr = 0x180000
		dirIno       = 256
		fileIno      = 257
	)
	rootItem := make([]byte, 184)
	putU64(rootItem, 176, fsRootBytenr)
	rootLeaf := buildFakeLeaf(fakeBtrfsRootTree, 1, []fakeBtrfsItem{
		{objectid: 5, typ: 132, offset: 0, data: rootItem},
	})
	img := buildFakeBtrfsImage(rootLeaf)

	// A disk extent whose compression byte (offset 16) is set to zlib (1).
	comp := buildFakeDiskExtent(0x1C0000, 4096)
	comp[16] = 1 // BTRFS_COMPRESS_ZLIB
	fsLeaf := buildFakeLeaf(fsRootBytenr, 5, []fakeBtrfsItem{
		{objectid: dirIno, typ: 1, offset: 0, data: buildFakeInodeItem(0, 0x41ED)},
		{objectid: dirIno, typ: 84, offset: 0, data: buildFakeDirItem(fileIno, 1, "z.bin")},
		{objectid: fileIno, typ: 1, offset: 0, data: buildFakeInodeItem(4096, 0x81A4)},
		{objectid: fileIno, typ: 108, offset: 0, data: comp},
	})
	copy(img.data[fsRootBytenr:fsRootBytenr+fakeBtrfsNodesize], fsLeaf)

	h, err := btrfs.NewBtrfsHandler(img, 0)
	if err != nil {
		t.Fatalf("NewBtrfsHandler: %v", err)
	}
	rc, err := h.OpenFile("z.bin")
	if err == nil {
		rc.Close()
		t.Fatal("OpenFile must error on a compressed extent")
	}
	if !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("OpenFile error = %v, want a compression error", err)
	}
}
