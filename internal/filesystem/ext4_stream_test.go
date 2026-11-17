package filesystem_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"

	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/ext4"
)

// TestExt4OpenFileStreamsFixture validates the streaming reader against a
// committed ext4 E01 fixture: OpenFile serves the same bytes as GetFile, with
// position-independent ReadAt and cursor-based Read/Seek.
func TestExt4OpenFileStreamsFixture(t *testing.T) {
	h, _ := ext4Fixture(t, filepath.Join("..", "..", "testdata", "e01", "ext4-encase25-zlib.E01"))

	rc, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile(fixture.txt): %v", err)
	}
	defer rc.Close()

	// Whole-file read via Read (cursor).
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "fixture\n" {
		t.Fatalf("ReadAll = %q, want %q", got, "fixture\n")
	}

	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile returned %T, want io.ReaderAt (for VFS position-independent reads)", rc)
	}

	// ReadAt is position-independent: read the tail from offset 4.
	var tail [4]byte
	if n, err := ra.ReadAt(tail[:], 4); n != 4 || err != nil {
		t.Fatalf("ReadAt(off 4) = %d, %v, want 4, nil", n, err)
	}
	if string(tail[:]) != "ure\n" {
		t.Fatalf("ReadAt(off 4) = %q, want %q", tail[:], "ure\n")
	}

	// ReadAt exactly at EOF returns io.EOF.
	var b [8]byte
	if n, err := ra.ReadAt(b[:], 8); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt(off 8) = %d, %v, want 0, io.EOF", n, err)
	}
	// ReadAt past EOF returns the readable prefix plus io.EOF.
	var big [64]byte
	if n, err := ra.ReadAt(big[:], 6); n != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt(off 6) = %d, %v, want 2, io.EOF", n, err)
	}

	// Seek from the end returns the file size.
	if pos, err := rc.Seek(0, io.SeekEnd); err != nil || pos != 8 {
		t.Fatalf("Seek(0, End) = %d, %v, want 8, nil", pos, err)
	}
	// Rewind and read the whole file through the cursor.
	if pos, err := rc.Seek(0, io.SeekStart); err != nil || pos != 0 {
		t.Fatalf("Seek(0, Start) = %d, %v, want 0, nil", pos, err)
	}
	var whole [8]byte
	if n, err := rc.Read(whole[:]); n != 8 || err != nil {
		t.Fatalf("Read after Seek(0) = %d, %v, want 8, nil", n, err)
	}
	if string(whole[:]) != "fixture\n" {
		t.Fatalf("Read after Seek(0) = %q, want %q", whole[:], "fixture\n")
	}
}

// TestExt4OpenFileErrors pins the sentinel errors: a missing path must be
// ErrNotFound, a directory ErrIsDirectory — the same contract FAT's reader
// honors, so a consumer can distinguish outcomes with errors.Is.
func TestExt4OpenFileErrors(t *testing.T) {
	h, _ := ext4Fixture(t, filepath.Join("..", "..", "testdata", "e01", "ext4-encase25-zlib.E01"))

	if _, err := h.OpenFile("missing.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("OpenFile(missing.txt) err = %v, want ErrNotFound", err)
	}
	if _, err := h.OpenFile("/"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Fatalf("OpenFile(/) err = %v, want ErrIsDirectory", err)
	}
}

// TestExt4OpenFileMultiBlock streams a two-extent file across a block boundary
// and asserts the bytes match the raw image — the reader must touch both blocks
// and splice them correctly.
func TestExt4OpenFileMultiBlock(t *testing.T) {
	const size = 2*4096 - 3 // spans blocks 5 and 6
	var img []byte
	reader := buildFakeExt4Image(func(b []byte) {
		// Inode table block 2, inode 12 (index 11): fixture.txt -> 2-block file.
		ino := b[2*4096+11*256:]
		binary.LittleEndian.PutUint32(ino[0x04:], size)
		fakeExt4ExtentRoot(ino, 0x28, 0, 2, 5)
		// Second data block 6: a recognizable byte pattern.
		data := b[6*4096 : 6*4096+4093]
		for i := range data {
			data[i] = byte(i % 251)
		}
		img = b
	})
	h, err := ext4.NewExt4Handler(reader, 0)
	if err != nil {
		t.Fatalf("NewExt4Handler: %v", err)
	}

	rc, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile(fixture.txt): %v", err)
	}
	defer rc.Close()

	want := append(append([]byte{}, img[5*4096:6*4096]...), img[6*4096:6*4096+4093]...)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != size || string(got) != string(want) {
		t.Fatalf("streamed %d bytes, want %d; content mismatch (splice across blocks wrong)", len(got), size)
	}
}

// TestExt4OpenFileSparseTail asserts a file whose declared size exceeds the
// extent allocation reads the missing tail as zeros. That is ext4's defined
// sparse-file semantic (lastlog/wtmp are mostly holes): unallocated blocks
// within the declared size are holes, not corruption.
func TestExt4OpenFileSparseTail(t *testing.T) {
	reader := buildFakeExt4Image(func(b []byte) {
		ino := b[2*4096+11*256:]
		binary.LittleEndian.PutUint32(ino[0x04:], 3*4096) // declared size needs 3 blocks
		fakeExt4ExtentRoot(ino, 0x28, 0, 2, 5)            // but only 2 are allocated
	})
	h, err := ext4.NewExt4Handler(reader, 0)
	if err != nil {
		t.Fatalf("NewExt4Handler: %v", err)
	}

	rc, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile(fixture.txt): %v", err)
	}
	defer rc.Close()

	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile returned %T, want io.ReaderAt", rc)
	}
	buf := make([]byte, 3*4096)
	n, err := ra.ReadAt(buf, 0)
	if n != 3*4096 || err != nil {
		t.Fatalf("ReadAt = %d, %v, want %d, nil (sparse tail reads as zeros)", n, err, 3*4096)
	}
	// The allocated prefix is real image content; the tail is zero-filled.
	if !bytes.Equal(buf[2*4096:], make([]byte, 4096)) {
		t.Fatalf("sparse tail not zero-filled")
	}
	if string(buf[:8]) != "fixture\n" {
		t.Fatalf("allocated prefix corrupted: %q", buf[:8])
	}
}

// TestExt4OpenFileMidHole asserts an unallocated block between two extents
// reads as zeros (a hole in the middle of a file), while surrounding blocks
// stay real image data.
func TestExt4OpenFileMidHole(t *testing.T) {
	reader := buildFakeExt4Image(func(b []byte) {
		ino := b[2*4096+11*256:]
		// Two extents [0,1) and [2,3), leaving block 1 a hole. Declared size
		// covers all three blocks.
		binary.LittleEndian.PutUint32(ino[0x04:], 3*4096)
		binary.LittleEndian.PutUint16(ino[0x28:], 0xF30A) // eh_magic
		binary.LittleEndian.PutUint16(ino[0x2A:], 2)      // eh_entries
		binary.LittleEndian.PutUint16(ino[0x2C:], 4)      // eh_max
		binary.LittleEndian.PutUint16(ino[0x2E:], 0)      // eh_depth
		// extent[0]: ee_block=0, ee_len=1, start=5
		binary.LittleEndian.PutUint32(ino[0x34:], 0)
		binary.LittleEndian.PutUint16(ino[0x38:], 1)
		binary.LittleEndian.PutUint16(ino[0x3A:], 0)
		binary.LittleEndian.PutUint32(ino[0x3C:], 5)
		// extent[1]: ee_block=2, ee_len=1, start=6
		binary.LittleEndian.PutUint32(ino[0x40:], 2)
		binary.LittleEndian.PutUint16(ino[0x44:], 1)
		binary.LittleEndian.PutUint16(ino[0x46:], 0)
		binary.LittleEndian.PutUint32(ino[0x48:], 6)
		// Block 6: marker content so the second extent is distinguishable.
		copy(b[6*4096:], "SECOND")
	})
	h, err := ext4.NewExt4Handler(reader, 0)
	if err != nil {
		t.Fatalf("NewExt4Handler: %v", err)
	}

	rc, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile(fixture.txt): %v", err)
	}
	defer rc.Close()

	ra, _ := rc.(io.ReaderAt)
	buf := make([]byte, 3*4096)
	if n, err := ra.ReadAt(buf, 0); n != 3*4096 || err != nil {
		t.Fatalf("ReadAt = %d, %v, want %d, nil", n, err, 3*4096)
	}
	if string(buf[0:8]) != "fixture\n" {
		t.Fatalf("block 0 corrupted: %q", buf[0:8])
	}
	if !bytes.Equal(buf[4096:8192], make([]byte, 4096)) {
		t.Fatalf("hole (block 1) not zero-filled")
	}
	if string(buf[8192:8198]) != "SECOND" {
		t.Fatalf("block 2 corrupted: %q", buf[8192:8198])
	}
}

// TestExt4OpenFileEmptyFile asserts a zero-size regular file streams cleanly:
// Read and ReadAt return io.EOF immediately (no cluster/block resolution, no
// error). The reader for a size-0 file carries no block size, so this guards
// the EOF-before-blockSize ordering in readAt.
func TestExt4OpenFileEmptyFile(t *testing.T) {
	reader := buildFakeExt4Image(func(b []byte) {
		ino := b[fakeExt4InodeTableBlk*fakeExt4BlockSize+11*fakeExt4InodeSize:]
		binary.LittleEndian.PutUint32(ino[0x04:], 0) // i_size = 0
	})
	h, err := ext4.NewExt4Handler(reader, 0)
	if err != nil {
		t.Fatalf("NewExt4Handler: %v", err)
	}

	rc, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile(fixture.txt): %v", err)
	}
	defer rc.Close()

	var buf [4]byte
	if n, err := rc.Read(buf[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read on empty file = %d, %v, want 0, io.EOF", n, err)
	}
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile returned %T, want io.ReaderAt", rc)
	}
	if n, err := ra.ReadAt(buf[:], 0); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt on empty file = %d, %v, want 0, io.EOF", n, err)
	}
}

// TestExt4OpenFileConcurrentReadAt hammers a two-block file with concurrent,
// position-independent ReadAt calls and verifies every byte against the known
// image content. The reader holds no mutable state after open (unlike FAT's
// lazy cluster chain), so it needs no internal lock; this test pins that
// guarantee under -race.
func TestExt4OpenFileConcurrentReadAt(t *testing.T) {
	const size = 2*fakeExt4BlockSize - 3 // spans physical blocks 5 and 6
	var img []byte
	reader := buildFakeExt4Image(func(b []byte) {
		ino := b[fakeExt4InodeTableBlk*fakeExt4BlockSize+11*fakeExt4InodeSize:]
		binary.LittleEndian.PutUint32(ino[0x04:], size)
		fakeExt4ExtentRoot(ino, 0x28, 0, 2, fakeExt4DataBlock)
		// Distinct per-block patterns so a splice or offset bug is visible.
		for i := 0; i < fakeExt4BlockSize; i++ {
			b[fakeExt4DataBlock*fakeExt4BlockSize+i] = byte(i % 251)
		}
		for i := 0; i < size-fakeExt4BlockSize; i++ {
			b[(fakeExt4DataBlock+1)*fakeExt4BlockSize+i] = byte(i % 199)
		}
		img = b
	})
	h, err := ext4.NewExt4Handler(reader, 0)
	if err != nil {
		t.Fatalf("NewExt4Handler: %v", err)
	}
	rc, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile(fixture.txt): %v", err)
	}
	defer rc.Close()
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile returned %T, want io.ReaderAt", rc)
	}
	want := string(img[fakeExt4DataBlock*fakeExt4BlockSize : fakeExt4DataBlock*fakeExt4BlockSize+size])

	const workers = 16
	const iters = 200
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(w)))
			for i := 0; i < iters; i++ {
				off := int64(rng.Intn(size))
				l := rng.Intn(64) + 1
				if off+int64(l) > size {
					l = int(size - off)
				}
				buf := make([]byte, l)
				n, err := ra.ReadAt(buf, off)
				if err != nil && !errors.Is(err, io.EOF) {
					errCh <- fmt.Errorf("worker %d: ReadAt(%d, %d): %v", w, off, l, err)
					return
				}
				if int64(n) != int64(l) || string(buf[:n]) != want[off:off+int64(n)] {
					errCh <- fmt.Errorf("worker %d: mismatch at off %d len %d", w, off, l)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestExt4OpenFileIndependentHandles opens the same file twice and interleaves
// cursor reads; the two handles must not share any position state.
func TestExt4OpenFileIndependentHandles(t *testing.T) {
	h, err := ext4.NewExt4Handler(buildFakeExt4Image(nil), 0)
	if err != nil {
		t.Fatalf("NewExt4Handler: %v", err)
	}
	rc1, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile(fixture.txt): %v", err)
	}
	defer rc1.Close()
	rc2, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("second OpenFile(fixture.txt): %v", err)
	}
	defer rc2.Close()

	// Read half of the file on handle 1, the whole file on handle 2, then the
	// other half on handle 1: each handle keeps its own cursor.
	var b1, b2 [8]byte
	if n, err := rc1.Read(b1[:4]); n != 4 || err != nil {
		t.Fatalf("rc1 first read = %d, %v, want 4, nil", n, err)
	}
	if n, err := rc2.Read(b2[:]); n != 8 || err != nil {
		t.Fatalf("rc2 read = %d, %v, want 8, nil", n, err)
	}
	if n, err := rc1.Read(b1[4:]); n != 4 || err != nil {
		t.Fatalf("rc1 second read = %d, %v, want 4, nil", n, err)
	}
	if string(b1[:]) != "fixture\n" || string(b2[:]) != "fixture\n" {
		t.Fatalf("handle contents diverged: rc1=%q rc2=%q, want %q", b1, b2, "fixture\n")
	}
}

// mutateExt4Subdir extends the standard fake image with a real subdirectory:
// root lists "subdir" (inode 13, dir data at block 6) holding "nested.txt"
// (inode 14, content at block 7). fixture.txt's root entry is shrunk to make
// room.
func mutateExt4Subdir(img []byte) {
	it := img[fakeExt4InodeTableBlk*fakeExt4BlockSize:]

	// Inode 13 (index 12): subdir, extent root -> block 6.
	sub := it[12*fakeExt4InodeSize:]
	binary.LittleEndian.PutUint16(sub[0x00:], 0x41ED) // 040755 dir
	binary.LittleEndian.PutUint32(sub[0x04:], fakeExt4BlockSize)
	binary.LittleEndian.PutUint32(sub[0x0C:], 1786616877)
	binary.LittleEndian.PutUint16(sub[0x1A:], 2)
	binary.LittleEndian.PutUint32(sub[0x20:], 0x80000) // EXTENTS_FL
	fakeExt4ExtentRoot(sub, 0x28, 0, 1, 6)

	// Inode 14 (index 13): nested.txt, extent root -> block 7.
	nf := it[13*fakeExt4InodeSize:]
	binary.LittleEndian.PutUint16(nf[0x00:], 0x81A4) // 0100644
	binary.LittleEndian.PutUint32(nf[0x04:], 7)
	binary.LittleEndian.PutUint32(nf[0x0C:], 1786616877)
	binary.LittleEndian.PutUint16(nf[0x1A:], 1)
	binary.LittleEndian.PutUint32(nf[0x20:], 0x80000) // EXTENTS_FL
	fakeExt4ExtentRoot(nf, 0x28, 0, 1, 7)

	// Subdir block 6: ".", "..", "nested.txt".
	sd := img[6*fakeExt4BlockSize:]
	fakeExt4DirEntry(sd, 0, 13, 12, 1, 2, ".")
	fakeExt4DirEntry(sd, 12, 13, 12, 2, 2, "..")
	fakeExt4DirEntry(sd, 24, 14, uint16(fakeExt4BlockSize-24), 10, 1, "nested.txt")

	// Root dir block 4: shrink fixture.txt's rec_len to 20, append subdir.
	dir := img[fakeExt4DirBlock*fakeExt4BlockSize:]
	binary.LittleEndian.PutUint16(dir[24+4:], 20) // fixture.txt rec_len (8+11=19 padded to 4)
	fakeExt4DirEntry(dir, 44, 13, uint16(fakeExt4BlockSize-44), 6, 2, "subdir")

	// nested.txt content in block 7.
	copy(img[7*fakeExt4BlockSize:], "nested\n")
}

// TestExt4OpenFileDirAndNotDirSentinels pins the same sentinel contract the
// other streaming readers honor: OpenFile on a directory is ErrIsDirectory, a
// path threading through a file is ErrNotDirectory, and ListDirectory on a file
// is ErrNotDirectory. A nested regular file streams correctly through the
// subdirectory.
func TestExt4OpenFileDirAndNotDirSentinels(t *testing.T) {
	h, err := ext4.NewExt4Handler(buildFakeExt4Image(mutateExt4Subdir), 0)
	if err != nil {
		t.Fatalf("NewExt4Handler: %v", err)
	}

	if _, err := h.OpenFile("subdir"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Fatalf("OpenFile(subdir) err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.OpenFile("fixture.txt/nested.txt"); !errors.Is(err, filesystem.ErrNotDirectory) {
		t.Fatalf("OpenFile(fixture.txt/nested.txt) err = %v, want ErrNotDirectory", err)
	}
	if _, err := h.ListDirectory("fixture.txt"); !errors.Is(err, filesystem.ErrNotDirectory) {
		t.Fatalf("ListDirectory(fixture.txt) err = %v, want ErrNotDirectory", err)
	}

	rc, err := h.OpenFile("subdir/nested.txt")
	if err != nil {
		t.Fatalf("OpenFile(subdir/nested.txt): %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll(subdir/nested.txt): %v", err)
	}
	if string(got) != "nested\n" {
		t.Fatalf("subdir/nested.txt = %q, want %q", got, "nested\n")
	}
}
