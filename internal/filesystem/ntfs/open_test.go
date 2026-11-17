package ntfs

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// TestNTFSOpenFileResident verifies the streaming reader over a resident
// $DATA stream is byte-identical to GetFile and behaves as a seekable
// io.ReadSeekCloser.
func TestNTFSOpenFileResident(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}

	want, err := h.GetFile("hello.txt")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if string(want) != "hello world" {
		t.Fatalf("hello.txt content = %q, want %q", string(want), "hello world")
	}

	rc, err := h.OpenFile("hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}

	all, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(all, want) {
		t.Fatalf("streamed content differs from GetFile content")
	}

	for _, off := range []int64{0, 1, 5, 10} {
		buf := make([]byte, 4)
		wantN, wantErr := 4, error(nil)
		if off+4 > int64(len(want)) {
			wantN = len(want) - int(off)
			wantErr = io.EOF
		}
		n, err := ra.ReadAt(buf, off)
		if n != wantN || (wantErr == nil && err != nil) || (wantErr != nil && !errors.Is(err, io.EOF)) {
			t.Errorf("ReadAt(%d): n=%d err=%v, want n=%d err=%v", off, n, err, wantN, wantErr)
			continue
		}
		if !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
			t.Errorf("ReadAt(%d) = %q, want %q", off, buf[:n], want[off:off+int64(n)])
		}
	}

	// Seek + Read.
	if _, err := rc.Seek(6, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	chunk := make([]byte, 5)
	n, err := rc.Read(chunk)
	if err != nil || n != 5 {
		t.Fatalf("Read after Seek: n=%d err=%v", n, err)
	}
	if !bytes.Equal(chunk, []byte("world")) {
		t.Errorf("post-seek read = %q, want %q", chunk, "world")
	}
}

// TestNTFSOpenFileNonResident verifies the streaming reader over a non-resident
// $DATA stream (data-run list) is byte-identical to GetFile and honors the
// io.ReaderAt contract across the run boundary.
func TestNTFSOpenFileNonResident(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}

	want, err := h.GetFile("big.bin")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if len(want) != 4096 {
		t.Fatalf("big.bin length = %d, want 4096", len(want))
	}

	rc, err := h.OpenFile("big.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}

	all, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(all, want) {
		t.Fatalf("streamed big.bin differs from GetFile content")
	}

	// ReadAt spanning the 4096-byte cluster boundary of the run.
	for _, off := range []int64{0, 4095, 4096, 4097, 5000} {
		buf := make([]byte, 4)
		wantN, wantErr := 4, error(nil)
		if off >= int64(len(want)) {
			wantN, wantErr = 0, io.EOF
		} else if off+4 > int64(len(want)) {
			wantN, wantErr = len(want)-int(off), io.EOF
		}
		n, err := ra.ReadAt(buf, off)
		if n != wantN || (wantErr == nil && err != nil) || (wantErr != nil && !errors.Is(err, io.EOF)) {
			t.Errorf("ReadAt(%d): n=%d err=%v, want n=%d err=%v", off, n, err, wantN, wantErr)
			continue
		}
		if n > 0 && !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
			t.Errorf("ReadAt(%d) = %x, want %x", off, buf[:n], want[off:off+int64(n)])
		}
	}

	// ReadAt at EOF returns io.EOF.
	if _, err := ra.ReadAt(make([]byte, 4), 4096); err != io.EOF {
		t.Errorf("ReadAt at EOF err = %v, want io.EOF", err)
	}
	// A read that ends past EOF returns the readable prefix plus io.EOF
	// (io.ReaderAt requires a non-nil error when n < len(p)).
	got := make([]byte, 8)
	n, err := ra.ReadAt(got, 4092)
	if n != 4 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt(4092, 8) = (n=%d, err=%v), want (4, io.EOF)", n, err)
	}
	if !bytes.Equal(got[:n], want[4092:]) {
		t.Errorf("ReadAt(4092,8) prefix = %x, want %x", got[:n], want[4092:])
	}
}

// TestNTFSOpenFileNested verifies path resolution through directories works in
// the streaming path.
func TestNTFSOpenFileNested(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}
	rc, err := h.OpenFile("/subdir/nested.txt")
	if err != nil {
		t.Fatalf("OpenFile(/subdir/nested.txt): %v", err)
	}
	defer rc.Close()
	all, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(all) != "nested content" {
		t.Errorf("nested content = %q, want %q", string(all), "nested content")
	}
}

// TestNTFSOpenFileSentinelErrors verifies that errors from the streaming path
// and the legacy path unwrap to the exported sentinels.
func TestNTFSOpenFileSentinelErrors(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}

	if _, err := h.GetFile("doesnotexist.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("GetFile missing path err = %v, want ErrNotFound", err)
	}
	if _, err := h.GetFile("subdir"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("GetFile directory path err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.OpenFile("doesnotexist.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("OpenFile missing path err = %v, want ErrNotFound", err)
	}
	if _, err := h.OpenFile("subdir"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("OpenFile directory path err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.ListDirectory("hello.txt"); !errors.Is(err, filesystem.ErrNotDirectory) {
		t.Errorf("ListDirectory on a file err = %v, want ErrNotDirectory", err)
	}
}
