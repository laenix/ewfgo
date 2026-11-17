package unlock

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// The fixtures' recovery password and salt are the vectors the Rust reference
// crate pins against an independent Python implementation. The expected
// stretched digest below is copied from that reference test; it pins the
// chain, not merely agreement with the fixture this package builds.
const (
	vectorPassword  = "Correct-Horse-Battery-Staple-42"
	vectorSaltText  = "BLFIXTURE-PW-SLT"
	vectorStretched = "1be6c395dc0d5180b5ca3243dd7d30eb680d936c06bf55849ee6ce5aeabe6fbf"
)

func hexString(bytes []byte) string { return hex.EncodeToString(bytes) }

func TestRecoveryKeyParsing(t *testing.T) {
	key, err := RecoveryKey(fixtureRecoveryPassword)
	if err != nil {
		t.Fatalf("RecoveryKey: %v", err)
	}
	want := []byte{
		0x39, 0x30, // 135795 / 11 = 12345
		0xa0, 0x5b, // 258016 / 11 = 23456
		0x07, 0x87, // 380237 / 11 = 34567
		0x6e, 0xb2, // 502458 / 11 = 45678
		0xd5, 0xdd, // 624679 / 11 = 56789
		0xff, 0xff, // 720885 / 11 = 65535
		0x83, 0x23, // 100001 / 11 = 9091
		0x50, 0xc3, // 550000 / 11 = 50000
	}
	if !bytes.Equal(key[:], want) {
		t.Fatalf("key = %x, want %x", key[:], want)
	}

	// Windows prints dashes; whitespace and dashes do not change the digits.
	plain := "135795258016380237502458624679720885100001550000"
	spaced := " 135795 258016\t380237\n502458-624679 720885 100001 550000 "
	for _, text := range []string{plain, spaced} {
		got, err := RecoveryKey(text)
		if err != nil {
			t.Fatalf("RecoveryKey(%q): %v", text, err)
		}
		if got != key {
			t.Fatalf("RecoveryKey(%q) = %x, want %x", text, got, key)
		}
	}

	cases := []struct {
		name string
		text string
		want error
	}{
		{"short", "135795-25801", ErrPasswordShape},
		{"letters", "13579a-258016-380237-502458-624679-720885-100001-550000", ErrPasswordShape},
		{"not-divisible", "135796-258016-380237-502458-624679-720885-100001-550000", ErrPasswordGroup},
		{"out-of-range", "720896-258016-380237-502458-624679-720885-100001-550000", ErrPasswordGroupRange},
		{"leading-zero-group", "000011-258016-380237-502458-624679-720885-100001-550000", ErrPasswordShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RecoveryKey(tc.text); !errors.Is(err, tc.want) {
				t.Fatalf("RecoveryKey error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestStretchPasswordMatchesIndependentVector(t *testing.T) {
	salt := [16]byte{}
	copy(salt[:], vectorSaltText)
	stretched, err := StretchPassword([]byte(vectorPassword), salt)
	if err != nil {
		t.Fatalf("StretchPassword: %v", err)
	}
	if got := hexString(stretched[:]); got != vectorStretched {
		t.Fatalf("stretched = %s, want %s", got, vectorStretched)
	}
}

func TestStretchInitialUsesDocumentedLayout(t *testing.T) {
	var initial [32]byte
	var salt [16]byte
	for i := range initial {
		initial[i] = byte(i + 1)
	}
	for i := range salt {
		salt[i] = byte(0x40 + i)
	}
	const iterations = 7
	got := StretchInitial(initial, salt, iterations)

	var updated [32]byte
	var input [32 + 32 + 16 + 8]byte
	copy(input[32:64], initial[:])
	copy(input[64:80], salt[:])
	for count := 0; count < iterations; count++ {
		copy(input[:32], updated[:])
		binary.LittleEndian.PutUint64(input[80:], uint64(count))
		updated = sha256.Sum256(input[:])
	}
	if got != updated {
		t.Fatalf("StretchInitial = %x, want %x", got, updated)
	}
	if got := StretchInitial(initial, salt, 0); got != ([32]byte{}) {
		t.Fatalf("StretchInitial with zero rounds = %x, want zero", got)
	}
}

func TestStretchKeyHashesTheRecoveryKeyFirst(t *testing.T) {
	key, err := RecoveryKey(fixtureRecoveryPassword)
	if err != nil {
		t.Fatal(err)
	}
	salt := [16]byte{1, 2, 3}
	got := StretchKey(key, salt, 3)

	initial := sha256.Sum256(key[:])
	want := StretchInitial(initial, salt, 3)
	if got != want {
		t.Fatalf("StretchKey = %x, want %x", got, want)
	}
}

func TestPasswordInitial(t *testing.T) {
	bom := []byte{0xef, 0xbb, 0xbf}
	withBOM, err := PasswordInitial(append(bom, []byte("correct horse")...))
	if err != nil {
		t.Fatalf("PasswordInitial(BOM): %v", err)
	}
	plain, err := PasswordInitial([]byte("correct horse"))
	if err != nil {
		t.Fatalf("PasswordInitial: %v", err)
	}
	if withBOM != plain {
		t.Fatal("a byte-order mark must be stripped")
	}

	// UTF-16LE, no terminator: encoding is case-sensitive.
	upper, err := PasswordInitial([]byte("Correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if upper == plain {
		t.Fatal("case-different passwords must hash differently")
	}

	// Independent recomputation: double SHA-256 over UTF-16LE.
	encoded := []byte{
		'c', 0, 'o', 0, 'r', 0, 'r', 0, 'e', 0, 'c', 0, 't', 0,
		' ', 0, 'h', 0, 'o', 0, 'r', 0, 's', 0, 'e', 0,
	}
	first := sha256.Sum256(encoded)
	want := sha256.Sum256(first[:])
	if plain != want {
		t.Fatalf("PasswordInitial = %x, want %x", plain, want)
	}

	if _, err := PasswordInitial([]byte{0xff, 0xfe, 0x00}); !errors.Is(err, ErrPasswordText) {
		t.Fatalf("invalid UTF-8 error = %v, want ErrPasswordText", err)
	}
}
