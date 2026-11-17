package leveldb

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestDecodeBlockEntriesAndRestarts(t *testing.T) {
	raw := buildRawBlockShared(
		[]testKV{
			{key: []byte("apple"), value: []byte("1")},
			{key: []byte("apply"), value: []byte("2")},
			{key: []byte("banana"), value: []byte("3")},
		},
		[]int{0, 4, 0},
		[]int{0, 2},
	)
	block, err := DecodeBlock(storedBlock(raw, 0), ChecksumCRC32C, 1024)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	var keys []string
	_, err = block.ForEach(func(key, value []byte) bool {
		keys = append(keys, string(key)+"="+string(value))
		return true
	})
	if err != nil {
		t.Fatalf("ForEach: %v", err)
	}
	if got := strings.Join(keys, ","); got != "apple=1,apply=2,banana=3" {
		t.Fatalf("keys = %q", got)
	}
	key, value, ok, err := block.Last()
	if err != nil || !ok || string(key) != "banana" || string(value) != "3" {
		t.Fatalf("Last = %q %q %v %v", key, value, ok, err)
	}
}

func TestDecodeBlockSnappy(t *testing.T) {
	raw := buildRawBlock([]testKV{
		{key: []byte("k1"), value: []byte("v1")},
		{key: []byte("k2"), value: []byte("v2")},
	})
	block, err := DecodeBlock(storedBlock(raw, 1), ChecksumCRC32C, 1024)
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if block.Compression() != 1 {
		t.Fatalf("compression = %d", block.Compression())
	}
	count, err := block.ForEach(func(_, _ []byte) bool { return true })
	if err != nil || count != 2 {
		t.Fatalf("ForEach count = %d, %v", count, err)
	}
}

func TestSnappyCopyElements(t *testing.T) {
	// Declared length 6: literal "abc", then a two-byte-offset copy of three
	// bytes from offset 3.
	stream := []byte{6, 2 << 2, 'a', 'b', 'c', (3-1)<<2 | 2, 3, 0}
	decoded, err := snappyDecompress(stream, 16)
	if err != nil {
		t.Fatalf("snappyDecompress: %v", err)
	}
	if string(decoded) != "abcabc" {
		t.Fatalf("decoded = %q", decoded)
	}
	// The same copy with an invalid offset is refused.
	bad := []byte{6, 2 << 2, 'a', 'b', 'c', (3-1)<<2 | 2, 9, 0}
	if _, err := snappyDecompress(bad, 16); err == nil {
		t.Fatal("an invalid copy offset decoded")
	}
}

func TestSnappyRefusesUnboundedDeclaration(t *testing.T) {
	// Declared length 100 with a 10-byte bound.
	stream := appendVarint(nil, 100)
	if _, err := snappyDecompress(stream, 10); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want a limit error", err)
	}
	// The declaration must be consumed by literals.
	short := appendVarint(nil, 5)
	if _, err := snappyDecompress(short, 16); err == nil {
		t.Fatal("a short Snappy stream decoded")
	}
}

func TestDecodeBlockChecksumCorruption(t *testing.T) {
	raw := buildRawBlock([]testKV{{key: []byte("k"), value: []byte("v")}})
	stored := storedBlock(raw, 0)
	stored[len(stored)-1] ^= 0xff
	_, err := DecodeBlock(stored, ChecksumCRC32C, 1024)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err = %v, want a checksum failure", err)
	}
	if _, err := DecodeBlock(stored, ChecksumUnverified, 1024); err != nil {
		t.Fatalf("unverified decode: %v", err)
	}
	if _, err := DecodeBlock(stored[:4], ChecksumCRC32C, 1024); err == nil {
		t.Fatal("a four-byte stored block decoded")
	}
}

func TestBlockValidatesItsRestartArray(t *testing.T) {
	raw := buildRawBlock([]testKV{{key: []byte("a"), value: nil}})
	// The restart array is the last eight bytes: one offset and the count.
	binary.LittleEndian.PutUint32(raw[len(raw)-8:], 100)
	if _, err := BlockFromBytes(raw); err == nil || !strings.Contains(err.Error(), "restart offset") {
		t.Fatalf("err = %v, want an out-of-range restart", err)
	}
	if _, err := BlockFromBytes([]byte{0, 0}); err == nil {
		t.Fatal("a two-byte block decoded")
	}
	// A restart offset of zero is allowed even when there are no entries.
	if _, err := BlockFromBytes([]byte{0, 0, 0, 0}); err != nil {
		t.Fatalf("empty block: %v", err)
	}
}

func TestBlockRejectsUnsupportedCompression(t *testing.T) {
	raw := buildRawBlock(nil)
	stored := storedBlock(raw, 7)
	_, err := DecodeBlock(stored, ChecksumUnverified, 1024)
	if err == nil || !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("err = %v, want unsupported", err)
	}
}

func TestBlockHandleRange(t *testing.T) {
	handle := BlockHandle{Offset: 128, Size: 5}
	// Five payload bytes plus the five-byte trailer need 138 bytes.
	if _, _, err := handle.Range(137); err == nil {
		t.Fatal("a handle past the file was accepted")
	}
	offset, size, err := handle.Range(138)
	if err != nil || offset != 128 || size != 5 {
		t.Fatalf("Range = %d %d %v", offset, size, err)
	}
	raw := []byte{0x80, 0x01, 5}
	decoded, used, ok := DecodeBlockHandle(raw)
	if !ok || used != 3 || decoded != handle {
		t.Fatalf("DecodeBlockHandle = %+v %d %v", decoded, used, ok)
	}
}
