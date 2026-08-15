package ewf

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"testing"
)

// TestImageFSOpenFileStreaming verifies the Evidence bridge's streaming path
// end to end: ImageFS.OpenFile returns a lazy io.ReadSeekCloser that is
// byte-identical to ReadFile, on a real committed E01 fixture.
func TestImageFSOpenFileStreaming(t *testing.T) {
	img, err := Open(filepath.Join("testdata", "e01", "fat16-encase6-zlib.E01"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem: %v", err)
	}
	defer fs.Close()

	want, err := fs.ReadFile("/FIXTURE.TXT")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(want) != "fixture\n" {
		t.Fatalf("FIXTURE.TXT = %q, want %q", string(want), "fixture\n")
	}

	rc, err := fs.OpenFile("/FIXTURE.TXT")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("streamed content = %q, want %q", string(got), string(want))
	}

	// The concrete reader implements io.ReaderAt (the contract sqlite's VFS
	// layer asserts on).
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}
	buf := make([]byte, 4)
	if n, err := ra.ReadAt(buf, 0); n != 4 || err != nil {
		t.Fatalf("ReadAt(0): n=%d err=%v", n, err)
	}
	if !bytes.Equal(buf, want[:4]) {
		t.Errorf("ReadAt(0) = %q, want %q", buf, want[:4])
	}
}

// TestImageFSStreamingSentinels verifies the exported sentinels unwrap through
// the Evidence bridge's contextual partition/path error wrapping.
func TestImageFSStreamingSentinels(t *testing.T) {
	img, err := Open(filepath.Join("testdata", "e01", "fat16-encase6-zlib.E01"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem: %v", err)
	}
	defer fs.Close()

	if _, err := fs.ReadFile("/MISSING.TXT"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ReadFile missing err = %v, want ewf.ErrNotFound", err)
	}
	if _, err := fs.OpenFile("/MISSING.TXT"); !errors.Is(err, ErrNotFound) {
		t.Errorf("OpenFile missing err = %v, want ewf.ErrNotFound", err)
	}
	// FIXTURE.TXT is a file, so treating it as a directory must classify as
	// not-a-directory (the "path exists but wrong type" case).
	if _, err := fs.OpenFile("/FIXTURE.TXT/child"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("OpenFile under a file err = %v, want ewf.ErrNotDirectory", err)
	}
}

// TestImageFSOpenFileStreamingExt4 verifies the Evidence bridge's streaming path
// for ext4 end to end on a real committed fixture: OpenFile is byte-identical to
// ReadFile, the concrete reader implements io.ReaderAt, and the sentinel errors
// unwrap through the partition/path context prefix.
func TestImageFSOpenFileStreamingExt4(t *testing.T) {
	img, err := Open(filepath.Join("testdata", "e01", "ext4-encase25-zlib.E01"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem: %v", err)
	}
	defer fs.Close()

	want, err := fs.ReadFile("fixture.txt")
	if err != nil {
		t.Fatalf("ReadFile(fixture.txt): %v", err)
	}
	if string(want) != "fixture\n" {
		t.Fatalf("fixture.txt = %q, want %q", string(want), "fixture\n")
	}

	rc, err := fs.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile(fixture.txt): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("streamed content = %q, want %q", string(got), string(want))
	}

	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}
	buf := make([]byte, 4)
	if n, err := ra.ReadAt(buf, 0); n != 4 || err != nil {
		t.Fatalf("ReadAt(0): n=%d err=%v", n, err)
	}
	if !bytes.Equal(buf, want[:4]) {
		t.Errorf("ReadAt(0) = %q, want %q", buf, want[:4])
	}

	// Sentinel errors unwrap through the ImageFS context prefix.
	if _, err := fs.OpenFile("missing.txt"); !errors.Is(err, ErrNotFound) {
		t.Errorf("OpenFile(missing.txt) err = %v, want ewf.ErrNotFound", err)
	}
	if _, err := fs.OpenFile("/"); !errors.Is(err, ErrIsDirectory) {
		t.Errorf("OpenFile(/) err = %v, want ewf.ErrIsDirectory", err)
	}
	if _, err := fs.OpenFile("fixture.txt/child"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("OpenFile(fixture.txt/child) err = %v, want ewf.ErrNotDirectory", err)
	}
}

// TestImageFSOpenFileStreamingBtrfs verifies the Evidence bridge's streaming
// path for btrfs on a real committed fixture: OpenFile on disk.bin (a genuine
// on-disk EXTENT_DATA type-1 extent) is byte-identical to ReadFile, the concrete
// reader implements io.ReaderAt, and the sentinel errors unwrap through the
// partition/path context prefix.
func TestImageFSOpenFileStreamingBtrfs(t *testing.T) {
	img, err := Open(filepath.Join("testdata", "e01", "btrfs-encase25-zlib.E01"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem: %v", err)
	}
	defer fs.Close()

	want, err := fs.ReadFile("disk.bin")
	if err != nil {
		t.Fatalf("ReadFile(disk.bin): %v", err)
	}
	if len(want) != 65536 {
		t.Fatalf("disk.bin size = %d, want 65536", len(want))
	}

	rc, err := fs.OpenFile("disk.bin")
	if err != nil {
		t.Fatalf("OpenFile(disk.bin): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("streamed disk.bin (%d bytes) != ReadFile (%d bytes)", len(got), len(want))
	}

	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}
	buf := make([]byte, 4)
	if n, err := ra.ReadAt(buf, 0); n != 4 || err != nil {
		t.Fatalf("ReadAt(0): n=%d err=%v", n, err)
	}
	if !bytes.Equal(buf, want[:4]) {
		t.Errorf("ReadAt(0) = %x, want %x", buf, want[:4])
	}

	// Sentinel errors unwrap through the ImageFS context prefix.
	if _, err := fs.OpenFile("missing.txt"); !errors.Is(err, ErrNotFound) {
		t.Errorf("OpenFile(missing.txt) err = %v, want ewf.ErrNotFound", err)
	}
	if _, err := fs.OpenFile("/"); !errors.Is(err, ErrIsDirectory) {
		t.Errorf("OpenFile(/) err = %v, want ewf.ErrIsDirectory", err)
	}
	if _, err := fs.OpenFile("disk.bin/child"); !errors.Is(err, ErrNotDirectory) {
		t.Errorf("OpenFile(disk.bin/child) err = %v, want ewf.ErrNotDirectory", err)
	}
}

// TestImageFSOpenFileStreamingXFS verifies the Evidence bridge's streaming path
// for XFS on the committed fixture, whose root is an empty shortform directory:
// sentinels unwrap through the context prefix and a missing file errors rather
// than fabricating content.
func TestImageFSOpenFileStreamingXFS(t *testing.T) {
	img, err := Open(filepath.Join("testdata", "e01", "xfs-encase25-zlib.E01"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem: %v", err)
	}
	defer fs.Close()

	if _, err := fs.OpenFile("fixture.txt"); !errors.Is(err, ErrNotFound) {
		t.Errorf("OpenFile(fixture.txt) err = %v, want ewf.ErrNotFound", err)
	}
	if _, err := fs.OpenFile("/"); !errors.Is(err, ErrIsDirectory) {
		t.Errorf("OpenFile(/) err = %v, want ewf.ErrIsDirectory", err)
	}
}

// TestImageFSHashPassthrough verifies StoredHashes and VerifyImageHash surface
// through ImageFS unchanged from the underlying EWFImage, and that both paths
// degrade cleanly after Close.
func TestImageFSHashPassthrough(t *testing.T) {
	img, err := Open(filepath.Join("testdata", "e01", "fat16-encase6-zlib.E01"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem: %v", err)
	}

	// Passthrough must match the image's own view, stored or not.
	storedMD5, storedSHA1 := fs.StoredHashes()
	imgMD5, imgSHA1 := img.StoredHashes()
	if !bytes.Equal(storedMD5, imgMD5) || !bytes.Equal(storedSHA1, imgSHA1) {
		t.Errorf("ImageFS.StoredHashes() = (%x, %x), want image passthrough (%x, %x)",
			storedMD5, storedSHA1, imgMD5, imgSHA1)
	}

	res, err := fs.VerifyImageHash()
	if err != nil {
		t.Fatalf("VerifyImageHash: %v", err)
	}
	if res.BytesHashed == 0 {
		t.Errorf("VerifyImageHash hashed 0 bytes")
	}
	if len(res.StoredMD5) > 0 && !res.MD5Match {
		t.Errorf("stored MD5 %x does not match computed %x", res.StoredMD5, res.ComputedMD5)
	}
	if len(res.StoredSHA1) > 0 && !res.SHA1Match {
		t.Errorf("stored SHA1 %x does not match computed %x", res.StoredSHA1, res.ComputedSHA1)
	}

	// After Close, both paths degrade cleanly instead of panicking.
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := fs.OpenFile("/FIXTURE.TXT"); err == nil {
		t.Error("OpenFile after Close should error")
	}
	if md5h, _ := fs.StoredHashes(); md5h != nil {
		t.Errorf("StoredHashes after Close = %x, want nil", md5h)
	}
	if _, err := fs.VerifyImageHash(); err == nil {
		t.Error("VerifyImageHash after Close should error")
	}
}
