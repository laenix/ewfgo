package bzip2

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const helloBzip2Hex = "425a6839314159265359555a44f70000021980400010001264c0102000220069ea100305d3b62183c5dc914e14241556913dc0"

func helloBzip2(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(helloBzip2Hex)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBzip2Decodes(t *testing.T) {
	stored := helloBzip2(t)
	if !MatchesSignature(stored) {
		t.Fatal("MatchesSignature = false")
	}
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, stored), DefaultLimits())
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if src.Len() != uint64(len("hello bzip2")) || src.CompressedLen() != uint64(len(stored)) {
		t.Fatalf("lengths = %d, %d", src.Len(), src.CompressedLen())
	}
	buf := make([]byte, src.Len())
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello bzip2" {
		t.Fatalf("decoded = %q", buf)
	}
}

func TestBzip2RejectsDamage(t *testing.T) {
	stored := helloBzip2(t)
	truncated := stored[:len(stored)/2]
	if _, err := Open(2, source.NewMemorySource(1, truncated), DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(truncated) error = %v, want ErrCorrupt", err)
	}
	if _, err := Open(2, source.NewMemorySource(1, []byte("not bzip2")), DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(not bzip2) error = %v, want ErrCorrupt", err)
	}
}

func TestBzip2OutputLimit(t *testing.T) {
	stored := helloBzip2(t)
	_, err := Open(2, source.NewMemorySource(1, stored), Limits{MaxDecodedBytes: 2})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(limit) error = %v, want ErrUnsupported", err)
	}
}
