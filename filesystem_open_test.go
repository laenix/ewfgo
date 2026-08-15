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
