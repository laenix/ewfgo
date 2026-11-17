package source

import (
	"errors"
	"reflect"
	"testing"
)

func TestSubSourceReadsAndTranslates(t *testing.T) {
	parent := NewMemorySourceWithImage(1, 7, []byte("0123456789"))
	sub, err := NewSubSource(2, parent, 3, 4)
	if err != nil {
		t.Fatalf("NewSubSource error = %v", err)
	}

	if got := sub.Len(); got != 4 {
		t.Fatalf("Len() = %d, want 4", got)
	}
	if got := sub.ImageID(); got != 7 {
		t.Fatalf("ImageID() = %d, want 7", got)
	}
	if got := sub.SectorSize(); got != 512 {
		t.Fatalf("SectorSize() = %d, want 512", got)
	}

	buf := make([]byte, 4)
	n, err := sub.ReadAt(0, buf)
	if err != nil {
		t.Fatalf("ReadAt(0) error = %v", err)
	}
	if n != 4 || string(buf) != "3456" {
		t.Fatalf("ReadAt(0) = %d, %q; want 4, %q", n, buf, "3456")
	}

	extents, err := sub.Extents(0, 4)
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	wantExtents := []ParentRange{{Parent: 1, ParentOffset: 3, Len: 4, Kind: RangeData}}
	if !reflect.DeepEqual(extents, wantExtents) {
		t.Fatalf("Extents = %+v, want %+v", extents, wantExtents)
	}

	image, err := sub.MapToImage(1, 2)
	if err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}
	wantImage := []ImageRange{{ImageID: 7, ImageOffset: 4, Len: 2, Kind: RangeData}}
	if !reflect.DeepEqual(image, wantImage) {
		t.Fatalf("MapToImage = %+v, want %+v", image, wantImage)
	}
}

// TestSubSourceExtentsStopAtImmediateParent proves the provenance split:
// Extents names the immediate parent while MapToImage walks the whole chain.
func TestSubSourceExtentsStopAtImmediateParent(t *testing.T) {
	parent := NewMemorySourceWithImage(1, 7, []byte("0123456789"))
	middle, err := NewSubSource(2, parent, 2, 6)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := NewSubSource(3, middle, 1, 3)
	if err != nil {
		t.Fatal(err)
	}

	extents, err := leaf.Extents(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantExtents := []ParentRange{{Parent: 2, ParentOffset: 1, Len: 3, Kind: RangeData}}
	if !reflect.DeepEqual(extents, wantExtents) {
		t.Fatalf("Extents = %+v, want %+v", extents, wantExtents)
	}

	image, err := leaf.MapToImage(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantImage := []ImageRange{{ImageID: 7, ImageOffset: 3, Len: 3, Kind: RangeData}}
	if !reflect.DeepEqual(image, wantImage) {
		t.Fatalf("MapToImage = %+v, want %+v", image, wantImage)
	}
}

func TestNewSubSourceRejectsWindowOutsideParent(t *testing.T) {
	parent := NewMemorySourceWithImage(1, 7, []byte("0123456789"))

	for _, tc := range []struct{ offset, length uint64 }{
		{8, 8},
		{10, 1},
		{11, 0},
		{0, 11},
	} {
		if _, err := NewSubSource(2, parent, tc.offset, tc.length); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("NewSubSource(%d, %d) error = %v, want ErrOutOfRange", tc.offset, tc.length, err)
		}
	}
}

func TestSubSourceReadAtWindowEdges(t *testing.T) {
	parent := NewMemorySourceWithImage(1, 7, []byte("0123456789"))
	sub, err := NewSubSource(2, parent, 3, 4)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sub.ReadAt(4, make([]byte, 1)); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("ReadAt(4) error = %v, want ErrOutOfRange", err)
	}

	buf := make([]byte, 8)
	n, err := sub.ReadAt(2, buf)
	if err != nil {
		t.Fatalf("ReadAt(2, 8) error = %v", err)
	}
	if n != 2 || string(buf[:n]) != "56" {
		t.Fatalf("ReadAt(2, 8) = %d, %q; want 2, %q", n, buf[:n], "56")
	}

	if _, err := sub.ReadAt(0, nil); err != nil {
		t.Fatalf("ReadAt(0, nil) error = %v", err)
	}
}

// TestSubSourceLossyDelegates checks that best-effort mode reaches the parent
// and keeps its zero-fill accounting.
func TestSubSourceLossyDelegates(t *testing.T) {
	boom := errors.New("media error")
	parent := NewReaderAtSource(1, 7, errReaderAt{err: boom}, 10)
	sub, err := NewSubSource(2, parent, 2, 4)
	if err != nil {
		t.Fatal(err)
	}

	buf := []byte{0xaa, 0xaa, 0xaa, 0xaa}
	n, err := sub.ReadAtLossy(0, buf)
	if err != nil {
		t.Fatalf("ReadAtLossy error = %v", err)
	}
	if n != 4 {
		t.Fatalf("ReadAtLossy n = %d, want 4", n)
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("ReadAtLossy buf[%d] = %#x, want 0", i, b)
		}
	}
}
