package unlock

import (
	"encoding/hex"
	"testing"
)

func hexString(data []byte) string { return hex.EncodeToString(data) }

func decodeHexTest(t *testing.T, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("hex %q: %v", text, err)
	}
	return decoded
}

func TestBlake2bRFC7693Vectors(t *testing.T) {
	// RFC 7693 Appendix A.
	cases := []struct {
		message string
		want    string
	}{
		{"", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"},
		{"abc", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"},
	}
	for _, test := range cases {
		got, ok := blake2bHash(64, []byte(test.message))
		if !ok {
			t.Fatalf("blake2bHash(%q) refused", test.message)
		}
		if hexString(got) != test.want {
			t.Fatalf("blake2b(%q) = %s, want %s", test.message, hexString(got), test.want)
		}
	}
}

func TestBlake2bOutputLengthIsAParameter(t *testing.T) {
	long, _ := blake2bHash(64, []byte("abc"))
	short, _ := blake2bHash(32, []byte("abc"))
	if len(short) != 32 {
		t.Fatalf("32-byte digest has %d bytes", len(short))
	}
	if hexString(long[:32]) == hexString(short) {
		t.Fatal("a 32-byte BLAKE2b is not a truncation of the 64-byte digest")
	}
}

func TestBlake2bSplitUpdatesMatchOneShot(t *testing.T) {
	data := make([]byte, 1000)
	for index := range data {
		data[index] = byte(index % 251)
	}
	oneShot, _ := blake2bHash(48, data)
	hasher, _ := newBlake2b(48)
	for offset := 0; offset < len(data); offset += 17 {
		end := offset + 17
		if end > len(data) {
			end = len(data)
		}
		hasher.update(data[offset:end])
	}
	if hexString(hasher.finalize()) != hexString(oneShot) {
		t.Fatal("split updates changed the digest")
	}
}

func TestBlake2bRefusesUnusableOutputLengths(t *testing.T) {
	for _, length := range []int{0, -1, 65, 128} {
		if _, ok := newBlake2b(length); ok {
			t.Fatalf("output length %d was accepted", length)
		}
	}
}
