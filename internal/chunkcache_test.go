package internal

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"os"
	"path/filepath"
	"testing"
)

func TestChunkCache_GetPut(t *testing.T) {
	c := newChunkCache(2 << 20)
	if _, ok := c.get(0, 0); ok {
		t.Fatal("cache should miss on empty")
	}
	c.put(0, 0, []byte("hello"))
	c.put(0, 0, []byte("hello updated"))
	d, ok := c.get(0, 0)
	if !ok || string(d) != "hello updated" {
		t.Fatalf("get after put: got %q ok=%v", d, ok)
	}
	// Distinct keys are separate entries.
	c.put(3, 7, []byte("other"))
	if d, ok := c.get(3, 7); !ok || string(d) != "other" {
		t.Fatalf("distinct key read back: got %q ok=%v", d, ok)
	}
}

// TestChunkCache_Eviction pins the byte-cap LRU semantics: evicting replaces
// the oldest entry with the newest, and a get moves its entry to the front so
// it survives a later insert.
func TestChunkCache_Eviction(t *testing.T) {
	const chunk = 32 << 10 // 32 KiB, the default EWF chunk size
	c := newChunkCache(chunk)
	c.put(0, 0, make([]byte, chunk))
	c.put(0, 1, make([]byte, chunk)) // evicts (0,0): size 2*chunk > cap
	if _, ok := c.get(0, 0); ok {
		t.Fatal("LRU should have evicted the oldest entry (0,0)")
	}
	if _, ok := c.get(0, 1); !ok {
		t.Fatal("(0,1) should still be cached")
	}
	// Touch (0,1) so it is MRU, then insert (0,2): (0,1) is now the LRU victim.
	c.put(0, 1, make([]byte, chunk))
	c.put(0, 2, make([]byte, chunk))
	if _, ok := c.get(0, 1); ok {
		t.Fatal("recency: touched (0,1) should have been evicted by the new insert")
	}
	if _, ok := c.get(0, 2); !ok {
		t.Fatal("(0,2) should still be cached")
	}
}

// TestChunkCache_ZeroCap documents that a zero-capacity cache inserts then
// immediately evicts (never grows), so get always misses.
func TestChunkCache_ZeroCap(t *testing.T) {
	c := newChunkCache(0)
	c.put(0, 0, make([]byte, 1024))
	if _, ok := c.get(0, 0); ok {
		t.Fatal("zero-cap cache must not retain entries")
	}
}

// buildSegmentEWF assembles the smallest possible EWFImage that serves readChunk
// from a raw file: a single segment handle and the logical offset model the
// parser would produce. readChunk only needs ReadAt, so this is sufficient to
// exercise both decompression branches hermetically.
func buildSegmentEWF(t *testing.T, data []byte) *EWFImage {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "chunk.bin")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return &EWFImage{segments: []*SegmentFile{{file: f, size: int64(len(data))}}}
}

// TestReadChunk_RawDeflateFallback verifies the EWF compression method 2 path:
// a raw DEFLATE (RFC 1951, no zlib header) chunk inflates through the flate
// fallback when zlib rejects the header.
func TestReadChunk_RawDeflateFallback(t *testing.T) {
	const chunkBytes = 32 << 10
	payload := bytes.Repeat([]byte{0xAB}, chunkBytes)
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes() // stored form: raw DEFLATE, no 0x78 zlib header

	e := buildSegmentEWF(t, raw)
	out, err := e.readChunk(0, chunkBytes, true, chunkBytes)
	if err != nil {
		t.Fatalf("raw-deflate chunk should inflate via fallback: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("raw-deflate roundtrip mismatch")
	}
}

// TestReadChunk_ShortZlibErrors pins the boundary of the flate fallback: a
// stream that IS valid zlib but decompresses to fewer than chunkBytes (a
// partial final chunk) must error directly and must NOT be re-parsed as raw
// DEFLATE. Before the two-phase dispatch this fell through to flate and
// returned the wrong error (or, on a crafted stream, wrong data).
func TestReadChunk_ShortZlibErrors(t *testing.T) {
	const chunkBytes = 32 << 10
	payload := bytes.Repeat([]byte{0x42}, 512) // deliberately short final chunk

	// zlib-encode the short payload.
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	e := buildSegmentEWF(t, z.Bytes())
	// expectedBytes == chunkBytes: the caller treats this chunk as full-size, so
	// a short stream is corruption and must error — the caller (ReadSectorData)
	// alone relaxes the length for the media's final partial chunk.
	_, err := e.readChunk(0, chunkBytes, true, chunkBytes)
	if err == nil {
		t.Fatal("short zlib chunk must error, not be re-read as deflate")
	}
	// The error is the zlib short-output error, not the "neither zlib nor
	// deflate" method-3 error.
	if err.Error() == "chunk at offset 0x0 is neither a zlib nor a raw DEFLATE stream (EWF method 3 LZ chunks are unsupported)" {
		t.Fatal("short zlib chunk misclassified as non-zlib; flate fallback ran on a zlib stream")
	}
}

// TestReadChunk_NotDeflateAnyMethod verifies a chunk that is neither zlib nor
// raw DEFLATE returns an explicit unsupported error — never container bytes.
func TestReadChunk_NotDeflateAnyMethod(t *testing.T) {
	const chunkBytes = 32 << 10
	// 0xFF first byte: reserved BTYPE=3, invalid in both zlib and deflate.
	garbage := bytes.Repeat([]byte{0xFF}, 64)
	e := buildSegmentEWF(t, garbage)
	if _, err := e.readChunk(0, chunkBytes, true, chunkBytes); err == nil {
		t.Fatal("garbage chunk must return an explicit error")
	}
}
