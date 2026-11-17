package ewf_test

import (
	"bytes"
	"errors"
	"testing"

	ewfcontainer "github.com/laenix/ewfgo/internal/data/containers/ewf"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/ewffixture"
)

// TestOpenSourcesEmbeddedE01 proves an E01 can be opened from bytes (for
// example an archive member) with the same exact-decompression result as the
// file-backed opener.
func TestOpenSourcesEmbeddedE01(t *testing.T) {
	disk := ewffixture.DiskPattern(128)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})

	embedded := source.NewMemorySource(1, e01)
	src, _, err := ewfcontainer.OpenSources(1, 1, []source.ByteSource{embedded})
	if err != nil {
		t.Fatalf("OpenSources: %v", err)
	}
	if src.Len() != uint64(len(disk)) {
		t.Fatalf("Len = %d, want %d", src.Len(), len(disk))
	}
	windows := []struct{ offset, length int }{
		{0, 512},
		{100, 600},
		{len(disk) - 100, 200},
	}
	for _, tc := range windows {
		buf := make([]byte, tc.length)
		n, err := src.ReadAt(uint64(tc.offset), buf)
		if err != nil {
			t.Fatalf("ReadAt(%d,%d): %v", tc.offset, tc.length, err)
		}
		if !bytes.Equal(buf[:n], disk[tc.offset:tc.offset+n]) {
			t.Fatalf("ReadAt(%d,%d) differs", tc.offset, tc.length)
		}
	}
	if _, err := src.ReadAt(uint64(len(disk)), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("EOF error = %v, want ErrOutOfRange", err)
	}
}
