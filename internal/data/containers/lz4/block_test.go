package lz4

import (
	"bytes"
	"strings"
	"testing"
)

const testBlockMax = uint64(64 * 1024)

func TestDecodeBlockLiteralsAndMatch(t *testing.T) {
	// Sequence 1: token: 3 literals, match nibble 5 (=> 9 bytes), literal
	// "abc", offset 3. The match overlaps the literals it just emitted.
	// Sequence 2: the required trailing literals, "vwxyz".
	input := []byte{0x35, 'a', 'b', 'c', 0x03, 0x00, 0x50, 'v', 'w', 'x', 'y', 'z'}
	got, err := decodeBlock(input, nil, testBlockMax)
	if err != nil {
		t.Fatalf("decodeBlock error = %v", err)
	}
	if want := []byte("abcabcabcabcvwxyz"); !bytes.Equal(got, want) {
		t.Fatalf("decodeBlock = %q, want %q", got, want)
	}
}

func TestDecodeBlockLiteralOnly(t *testing.T) {
	input := append([]byte{0x50}, []byte("hello")...)
	got, err := decodeBlock(input, nil, testBlockMax)
	if err != nil {
		t.Fatalf("decodeBlock error = %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("decodeBlock = %q", got)
	}
}

func TestDecodeBlockLongLiteralLength(t *testing.T) {
	// 15 in the nibble plus one extension byte of 3 => 18 literals.
	payload := bytes.Repeat([]byte("x"), 18)
	input := append([]byte{0xF0, 0x03}, payload...)
	got, err := decodeBlock(input, nil, testBlockMax)
	if err != nil {
		t.Fatalf("decodeBlock error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decodeBlock = %q, want %q", got, payload)
	}
}

func TestDecodeBlockUsesDictionary(t *testing.T) {
	// No literals: a 4-byte match at offset 6 reads "abcd" from the prefix,
	// followed by the required trailing literals.
	input := []byte{0x00, 0x06, 0x00, 0x50, 'v', 'w', 'x', 'y', 'z'}
	got, err := decodeBlock(input, []byte("abcdef"), testBlockMax)
	if err != nil {
		t.Fatalf("decodeBlock error = %v", err)
	}
	if string(got) != "abcdvwxyz" {
		t.Fatalf("decodeBlock = %q, want %q", got, "abcdvwxyz")
	}
}

func TestDecodeBlockRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		dict  []byte
		max   uint64
		want  string
	}{
		{"empty", nil, nil, testBlockMax, "truncated"},
		{"truncated literals", []byte{0x21, 'a'}, nil, testBlockMax, "truncated"},
		{"truncated literal length", []byte{0xF0}, nil, testBlockMax, "truncated"},
		{"truncated offset", []byte{0x00, 0x01}, nil, testBlockMax, "truncated"},
		{"zero offset", []byte{0x00, 0x00, 0x00}, nil, testBlockMax, "offset"},
		{"offset beyond history", []byte{0x00, 0x05, 0x00}, nil, testBlockMax, "offset"},
		{"literals exceed cap", []byte{0x50, 'a', 'b', 'c', 'd', 'e'}, nil, 4, "maximum"},
		{"match exceeds cap", []byte{0x00, 0x04, 0x00}, []byte("abcd"), 3, "maximum"},
		// A block must end with a literal run; ending right after a match is
		// rejected by the reference decoder too.
		{"missing final literals", []byte{0x00, 0x04, 0x00}, []byte("abcd"), testBlockMax, "truncated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeBlock(tc.input, tc.dict, tc.max)
			if err == nil {
				t.Fatal("decodeBlock succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}
