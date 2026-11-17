package source

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestOpenRawFile pins the file-backed source contract: positional reads, a
// short tail at EOF, an explicit error for a start at EOF, and counters.
func TestOpenRawFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.bin")
	if err := os.WriteFile(path, []byte("abcdefghij"), 0o600); err != nil {
		t.Fatal(err)
	}

	src, err := OpenRawFile(path, 1, 2)
	if err != nil {
		t.Fatalf("OpenRawFile error = %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if got := src.Len(); got != 10 {
		t.Fatalf("Len() = %d, want 10", got)
	}
	if got := src.SectorSize(); got != 512 {
		t.Fatalf("SectorSize() = %d, want 512", got)
	}
	if got := src.ImageID(); got != 2 {
		t.Fatalf("ImageID() = %d, want 2", got)
	}

	buf := make([]byte, 4)
	n, err := src.ReadAt(2, buf)
	if err != nil {
		t.Fatalf("ReadAt(2) error = %v", err)
	}
	if n != 4 || string(buf) != "cdef" {
		t.Fatalf("ReadAt(2) = %d, %q; want 4, %q", n, buf, "cdef")
	}

	tail := make([]byte, 8)
	n, err = src.ReadAt(6, tail)
	if err != nil {
		t.Fatalf("ReadAt(6) error = %v", err)
	}
	if n != 4 || string(tail[:n]) != "ghij" {
		t.Fatalf("ReadAt(6) = %d, %q; want 4, %q", n, tail[:n], "ghij")
	}

	if _, err := src.ReadAt(10, buf); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("ReadAt(10) error = %v, want ErrOutOfRange", err)
	}

	stats := src.Stats()
	if stats.Reads != 2 || stats.BytesRead != 8 {
		t.Fatalf("Stats() = %+v, want 2 reads / 8 bytes", stats)
	}
}

// TestOpenRawFileRejectsBadSectorSize checks the geometry guard.
func TestOpenRawFileRejectsBadSectorSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, size := range []uint32{0, 256, 513, 1000} {
		if _, err := OpenRawFileWithSectorSize(path, 1, 1, size); err == nil {
			t.Fatalf("OpenRawFileWithSectorSize(%d) error = nil, want rejection", size)
		}
	}

	src, err := OpenRawFileWithSectorSize(path, 1, 1, 4096)
	if err != nil {
		t.Fatalf("OpenRawFileWithSectorSize(4096) error = %v", err)
	}
	_ = src.Close()
}

// TestOpenRawFileRejectsDirectory keeps a directory handle from being treated
// as evidence.
func TestOpenRawFileRejectsDirectory(t *testing.T) {
	if _, err := OpenRawFile(t.TempDir(), 1, 1); err == nil {
		t.Fatal("OpenRawFile(dir) error = nil, want rejection")
	}
}

// TestReaderAtSourceLossyZeroFills checks the lossy mode used by carving and
// recovery: an unreadable region becomes zeroes and corrupt statistics, never
// a silent success with stale buffer contents.
func TestReaderAtSourceLossyZeroFills(t *testing.T) {
	boom := errors.New("media error")
	src := NewReaderAtSource(1, 1, errReaderAt{err: boom}, 10)

	buf := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	n, err := src.ReadAtLossy(0, buf)
	if err != nil {
		t.Fatalf("ReadAtLossy error = %v", err)
	}
	if n != 10 {
		t.Fatalf("ReadAtLossy n = %d, want 10", n)
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("ReadAtLossy buf[%d] = %#x, want 0", i, b)
		}
	}
	stats := src.Stats()
	if stats.CorruptBytes != 10 || stats.Errors != 1 {
		t.Fatalf("Stats() = %+v, want 10 corrupt bytes / 1 error", stats)
	}
}

// TestReaderAtSourceStrictReturnsIOError keeps the strict path honest.
func TestReaderAtSourceStrictReturnsIOError(t *testing.T) {
	boom := errors.New("media error")
	src := NewReaderAtSource(1, 1, errReaderAt{err: boom}, 10)

	if _, err := src.ReadAt(0, make([]byte, 4)); !errors.Is(err, boom) {
		t.Fatalf("ReadAt error = %v, want the underlying I/O error", err)
	}
	if stats := src.Stats(); stats.Errors != 1 {
		t.Fatalf("Stats().Errors = %d, want 1", stats.Errors)
	}
}

// TestReaderAtSourceUnexpectedEOF rejects a backing store that claims more
// bytes than it can deliver.
func TestReaderAtSourceUnexpectedEOF(t *testing.T) {
	src := NewReaderAtSource(1, 1, zeroReaderAt{}, 10)

	_, err := src.ReadAt(0, make([]byte, 4))
	if !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatalf("ReadAt error = %v, want ErrUnexpectedEOF", err)
	}
}

// TestReaderAtSourceConcurrentReads verifies that positional reads do not share
// mutable state, which is the reason the file source has no seek lock.
func TestReaderAtSourceConcurrentReads(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), "raw.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := OpenRawFile(path, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			off := uint64(i * 512)
			buf := make([]byte, 128)
			n, err := src.ReadAt(off, buf)
			if err != nil {
				errs <- err
				return
			}
			if n != len(buf) || buf[0] != data[off] {
				errs <- errors.New("concurrent read returned wrong data")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

type errReaderAt struct{ err error }

func (r errReaderAt) ReadAt(p []byte, off int64) (int, error) { return 0, r.err }

type zeroReaderAt struct{}

func (zeroReaderAt) ReadAt(p []byte, off int64) (int, error) { return 0, nil }

var _ io.ReaderAt = errReaderAt{}
var _ io.ReaderAt = zeroReaderAt{}
