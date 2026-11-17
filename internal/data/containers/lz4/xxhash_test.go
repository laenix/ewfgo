package lz4

import "testing"

// Known-answer vectors for xxHash32 with seed 0. The empty, one-byte and
// short inputs exercise the tail path; the final vector exercises the
// 16-byte stripe path.
func TestXXH32KnownVectors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want uint32
	}{
		{"empty", nil, 0x02CC5D05},
		{"one byte", []byte("a"), 0x550D7456},
		{"three bytes", []byte("abc"), 0x32D153FF},
		{"message digest", []byte("message digest"), 0x7C948494},
		{"stripe path", []byte("Nobody inspects the spammish repetition"), 0xE2293B2F},
	}
	for _, tc := range cases {
		if got := xxh32(tc.in, 0); got != tc.want {
			t.Errorf("xxh32(%q) = %#08x, want %#08x", tc.in, got, tc.want)
		}
	}
}

func TestXXH32SeedChangesResult(t *testing.T) {
	if xxh32([]byte("abc"), 0) == xxh32([]byte("abc"), 1) {
		t.Fatal("xxh32 ignores the seed")
	}
}

func TestXXH32IsPrefixIndependent(t *testing.T) {
	// A slice and a copy with the same bytes must hash the same; this guards
	// against accidental reads past the slice end.
	a := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	b := append([]byte(nil), a...)
	if xxh32(a, 0) != xxh32(b, 0) {
		t.Fatal("xxh32 differs for equal byte slices")
	}
}
