package gzip

import (
	"bytes"
	stdgzip "compress/gzip"
	"errors"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

func gzipBytes(t *testing.T, data []byte, name string, mtime time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := stdgzip.NewWriter(&buf)
	writer.Name = name
	writer.ModTime = mtime
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGzipDecodesAndReportsMeta(t *testing.T) {
	mtime := time.Unix(1700000000, 0).UTC()
	stored := gzipBytes(t, []byte("hello gzip"), "auth.log", mtime)
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, stored), DefaultLimits())
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if src.Len() != uint64(len("hello gzip")) || src.CompressedLen() != uint64(len(stored)) {
		t.Fatalf("lengths = %d, %d", src.Len(), src.CompressedLen())
	}
	if src.Meta().Name != "auth.log" || !src.Meta().ModTime.Equal(mtime) {
		t.Fatalf("meta = %+v", src.Meta())
	}
	buf := make([]byte, src.Len())
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello gzip" {
		t.Fatalf("bytes = %q", buf)
	}
	extents, err := src.Extents(0, src.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].Kind != source.RangeDerived || extents[0].Parent != 2 {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestGzipMultiMember(t *testing.T) {
	first := gzipBytes(t, []byte("one"), "", time.Time{})
	second := gzipBytes(t, []byte("two"), "", time.Time{})
	src, err := Open(2, source.NewMemorySource(1, append(first, second...)), DefaultLimits())
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	buf := make([]byte, 6)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "onetwo" {
		t.Fatalf("multi-member decode = %q", buf)
	}
}

func TestGzipRejectsCorruption(t *testing.T) {
	stored := gzipBytes(t, []byte("payload"), "", time.Time{})
	stored[len(stored)-1] ^= 0xFF // ISIZE trailer byte
	if _, err := Open(2, source.NewMemorySource(1, stored), DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(corrupt) error = %v, want ErrCorrupt", err)
	}
	if _, err := Open(2, source.NewMemorySource(1, []byte("not gzip")), DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(not gzip) error = %v, want ErrCorrupt", err)
	}
}

func TestGzipOutputLimit(t *testing.T) {
	stored := gzipBytes(t, []byte("hello"), "", time.Time{})
	_, err := Open(2, source.NewMemorySource(1, stored), Limits{MaxDecodedBytes: 2})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(limit) error = %v, want ErrUnsupported", err)
	}
}
