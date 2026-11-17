package source

import (
	"errors"
	"io"
	"testing"
)

func TestReaderAtAdapter(t *testing.T) {
	src := NewMemorySource(1, []byte("abcdef"))
	reader := ReaderAt(src)

	buf := make([]byte, 3)
	n, err := reader.ReadAt(buf, 2)
	if err != nil || n != 3 || string(buf) != "cde" {
		t.Fatalf("ReadAt(2) = %d, %v, %q", n, err, buf)
	}

	n, err = reader.ReadAt(buf, 5)
	if !errors.Is(err, io.EOF) || n != 1 || string(buf[:n]) != "f" {
		t.Fatalf("ReadAt(5) = %d, %v, %q; want 1 byte and EOF", n, err, buf[:n])
	}

	if _, err := reader.ReadAt(buf, 6); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt(6) error = %v, want EOF", err)
	}
	if _, err := reader.ReadAt(buf, -1); err == nil {
		t.Fatal("ReadAt(-1) error = nil")
	}
}
