package ewf_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	ewfcontainer "github.com/laenix/ewfgo/internal/data/containers/ewf"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/ewffixture"
)

// TestEWFSourceEndToEnd proves the new byte plane reads real E01 bytes through
// the existing exact-decompression path: every unaligned window must equal the
// original disk byte for byte, and a read at EOF must fail instead of returning
// container bytes.
func TestEWFSourceEndToEnd(t *testing.T) {
	disk := ewffixture.DiskPattern(128)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})

	path := filepath.Join(t.TempDir(), "disk.E01")
	if err := os.WriteFile(path, e01, 0o600); err != nil {
		t.Fatal(err)
	}

	src, _, err := ewfcontainer.OpenFile(1, 1, path)
	if err != nil {
		t.Fatalf("Open E01 fixture: %v", err)
	}
	defer src.Close()
	if got, want := src.Len(), uint64(len(disk)); got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}

	windows := []struct{ offset, length int }{
		{0, 512},
		{100, 600},
		{32768, 4096},
		{len(disk) - 100, 200},
	}
	for _, tc := range windows {
		buf := make([]byte, tc.length)
		n, err := src.ReadAt(uint64(tc.offset), buf)
		if err != nil {
			t.Fatalf("ReadAt(%d, %d) error = %v", tc.offset, tc.length, err)
		}
		wantN := tc.length
		if tc.offset+tc.length > len(disk) {
			wantN = len(disk) - tc.offset
		}
		if n != wantN {
			t.Fatalf("ReadAt(%d, %d) n = %d, want %d", tc.offset, tc.length, n, wantN)
		}
		if !bytes.Equal(buf[:n], disk[tc.offset:tc.offset+n]) {
			t.Fatalf("ReadAt(%d, %d) did not match the original disk", tc.offset, tc.length)
		}
	}

	if _, err := src.ReadAt(uint64(len(disk)), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt(EOF) error = %v, want ErrOutOfRange", err)
	}
}
