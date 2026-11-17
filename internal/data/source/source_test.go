package source

import (
	"errors"
	"reflect"
	"testing"
)

// TestMemorySourceReadAt pins the ByteSource read contract that every adapter
// above the image container depends on. The rules are copied verbatim from the
// Rust data layer (docs: evidence-parsing-layer-design.md §5.3):
//
//   - an empty buffer always succeeds, even past EOF;
//   - the start of a request at or past EOF is OutOfRange;
//   - a request that starts in bounds but crosses EOF returns a short read,
//     never zero-fills the tail.
func TestMemorySourceReadAt(t *testing.T) {
	src := NewMemorySource(1, []byte("hello world"))

	t.Run("empty buffer is ok even past EOF", func(t *testing.T) {
		n, err := src.ReadAt(999, nil)
		if err != nil {
			t.Fatalf("ReadAt(999, nil) error = %v, want nil", err)
		}
		if n != 0 {
			t.Fatalf("ReadAt(999, nil) n = %d, want 0", n)
		}
	})

	t.Run("reads inside the source", func(t *testing.T) {
		buf := make([]byte, 5)
		n, err := src.ReadAt(6, buf)
		if err != nil {
			t.Fatalf("ReadAt(6) error = %v, want nil", err)
		}
		if n != 5 {
			t.Fatalf("ReadAt(6) n = %d, want 5", n)
		}
		if got := string(buf); got != "world" {
			t.Fatalf("ReadAt(6) = %q, want %q", got, "world")
		}
	})

	t.Run("short read when the buffer crosses EOF", func(t *testing.T) {
		buf := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
		n, err := src.ReadAt(8, buf)
		if err != nil {
			t.Fatalf("ReadAt(8) error = %v, want nil", err)
		}
		if n != 3 {
			t.Fatalf("ReadAt(8) n = %d, want 3", n)
		}
		if got := string(buf[:n]); got != "rld" {
			t.Fatalf("ReadAt(8) = %q, want %q", got, "rld")
		}
		if buf[n] != 0xaa {
			t.Fatalf("ReadAt(8) wrote past the short read: buf[%d] = %#x", n, buf[n])
		}
	})

	t.Run("start at EOF is out of range", func(t *testing.T) {
		buf := make([]byte, 4)
		n, err := src.ReadAt(11, buf)
		if !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("ReadAt(11) error = %v, want ErrOutOfRange", err)
		}
		var se *Error
		if !errors.As(err, &se) {
			t.Fatalf("ReadAt(11) error = %T, want *Error", err)
		}
		if se.Offset != 11 || se.Len != 4 || se.SourceLen != 11 {
			t.Fatalf("ReadAt(11) error = %+v, want offset=11 len=4 sourceLen=11", se)
		}
		if n != 0 {
			t.Fatalf("ReadAt(11) n = %d, want 0", n)
		}
	})

	t.Run("start past EOF is out of range", func(t *testing.T) {
		n, err := src.ReadAt(99, make([]byte, 4))
		if !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("ReadAt(99) error = %v, want ErrOutOfRange", err)
		}
		if n != 0 {
			t.Fatalf("ReadAt(99) n = %d, want 0", n)
		}
	})
}

// TestMemorySourceExtents pins the provenance mapping: a source with no parent
// layer maps to itself, and a zero-length range produces no entries.
func TestMemorySourceExtents(t *testing.T) {
	src := NewMemorySourceWithImage(7, 42, []byte("hello world"))

	t.Run("data range maps to the source", func(t *testing.T) {
		got, err := src.Extents(2, 4)
		if err != nil {
			t.Fatalf("Extents(2, 4) error = %v", err)
		}
		want := []ParentRange{{Parent: 7, ParentOffset: 2, Len: 4, Kind: RangeData}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Extents(2, 4) = %+v, want %+v", got, want)
		}
	})

	t.Run("empty range produces no entries", func(t *testing.T) {
		got, err := src.Extents(11, 0)
		if err != nil {
			t.Fatalf("Extents(11, 0) error = %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("Extents(11, 0) = %+v, want no entries", got)
		}
	})

	t.Run("range past EOF is out of range", func(t *testing.T) {
		_, err := src.Extents(8, 4)
		if !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("Extents(8, 4) error = %v, want ErrOutOfRange", err)
		}
	})

	t.Run("ExtentsInto preserves existing entries", func(t *testing.T) {
		out := []ParentRange{{Parent: 99, ParentOffset: 0, Len: 1, Kind: RangeData}}
		out, err := src.ExtentsInto(0, 2, out)
		if err != nil {
			t.Fatalf("ExtentsInto error = %v", err)
		}
		if len(out) != 2 || out[0].Parent != 99 || out[1].Parent != 7 {
			t.Fatalf("ExtentsInto = %+v, want the caller's entry plus the new one", out)
		}
	})
}

// TestMemorySourceMapToImage pins the final hop of provenance: logical bytes
// map to the owning image's offsets.
func TestMemorySourceMapToImage(t *testing.T) {
	src := NewMemorySourceWithImage(7, 42, []byte("hello world"))

	got, err := src.MapToImage(3, 5)
	if err != nil {
		t.Fatalf("MapToImage(3, 5) error = %v", err)
	}
	want := []ImageRange{{ImageID: 42, ImageOffset: 3, Len: 5, Kind: RangeData}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MapToImage(3, 5) = %+v, want %+v", got, want)
	}

	empty, err := src.MapToImage(11, 0)
	if err != nil {
		t.Fatalf("MapToImage(11, 0) error = %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("MapToImage(11, 0) = %+v, want no entries", empty)
	}

	if _, err := src.MapToImage(10, 2); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("MapToImage(10, 2) error = %v, want ErrOutOfRange", err)
	}
}

// TestSourceStats checks the counters that reports and benchmarks rely on.
func TestSourceStats(t *testing.T) {
	src := NewMemorySource(1, []byte("abcdef"))
	buf := make([]byte, 3)

	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if _, err := src.ReadAt(2, buf); err != nil {
		t.Fatal(err)
	}
	// An out-of-range read is an error, not a read.
	if _, err := src.ReadAt(6, buf); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("ReadAt(6) error = %v, want ErrOutOfRange", err)
	}
	// An empty read is still counted as a read of zero bytes.
	if _, err := src.ReadAt(0, nil); err != nil {
		t.Fatal(err)
	}

	got := src.Stats()
	want := Stats{Reads: 3, BytesRead: 6}
	if got != want {
		t.Fatalf("Stats() = %+v, want %+v", got, want)
	}
}

// TestReadExactAt checks the strict helper: a short tail is an explicit EOF
// error, never a silently truncated buffer.
func TestReadExactAt(t *testing.T) {
	src := NewMemorySource(1, []byte("abc"))

	buf := make([]byte, 3)
	if err := ReadExactAt(src, 0, buf); err != nil {
		t.Fatalf("ReadExactAt(0, 3) error = %v", err)
	}
	if got := string(buf); got != "abc" {
		t.Fatalf("ReadExactAt(0, 3) = %q, want %q", got, "abc")
	}

	err := ReadExactAt(src, 0, make([]byte, 5))
	if !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatalf("ReadExactAt(0, 5) error = %v, want ErrUnexpectedEOF", err)
	}
}

// TestReadVecAt checks the allocating helper and its bounds guard.
func TestReadVecAt(t *testing.T) {
	src := NewMemorySource(1, []byte("abcd"))

	got, err := ReadVecAt(src, 1, 2)
	if err != nil {
		t.Fatalf("ReadVecAt(1, 2) error = %v", err)
	}
	if string(got) != "bc" {
		t.Fatalf("ReadVecAt(1, 2) = %q, want %q", got, "bc")
	}

	if _, err := ReadVecAt(src, 3, 2); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("ReadVecAt(3, 2) error = %v, want ErrOutOfRange", err)
	}
}
