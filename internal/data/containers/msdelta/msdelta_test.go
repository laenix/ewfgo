package msdelta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

func prefixed(body []byte) []byte {
	blob := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(blob, foundation.CRC32(body))
	return append(blob, body...)
}

func bodyOf(payload []byte) []byte {
	body := append([]byte{}, []byte("PA31")...)
	return append(body, payload...)
}

func TestIdentifyAtByteFour(t *testing.T) {
	for label, want := range map[string]Kind{
		"PA19": KindPA19,
		"PA30": KindPA30,
		"PA31": KindPA31,
	} {
		blob := append([]byte{0, 0, 0, 0}, []byte(label)...)
		blob = append(blob, make([]byte, 8)...)
		got, ok := Identify(blob)
		if !ok || got != want {
			t.Fatalf("Identify(%s at 4) = %v, %v", label, got, ok)
		}
		if got.Magic() != [4]byte{label[0], label[1], label[2], label[3]} {
			t.Fatalf("Magic = %q", got.Magic())
		}
		if got.Label() != label {
			t.Fatalf("Label = %q", got.Label())
		}
	}
}

func TestIdentifyAtByteZero(t *testing.T) {
	blob := append([]byte("PA30"), make([]byte, 12)...)
	got, ok := Identify(blob)
	if !ok || got != KindPA30 {
		t.Fatalf("Identify = %v, %v", got, ok)
	}

	// Exactly four bytes is enough for the magic-at-zero branch.
	if got, ok := Identify([]byte("PA19")); !ok || got != KindPA19 {
		t.Fatalf("Identify(PA19) = %v, %v", got, ok)
	}
}

func TestIdentifyRejectsOtherData(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("PA3"),
		[]byte("<?xml version=\"1.0\""),
		[]byte("XXXXPA3"),
		append([]byte("XXXX"), []byte("PA3")...),
	}
	for _, head := range cases {
		if kind, ok := Identify(head); ok {
			t.Fatalf("Identify(%q) = %v, want false", head, kind)
		}
	}
}

func TestPrefixCRC(t *testing.T) {
	body := bodyOf([]byte{1, 2, 3, 4, 5})
	blob := prefixed(body)
	if !PrefixCRCMatches(blob) {
		t.Fatal("a valid prefix CRC was not recognised")
	}

	corrupted := append([]byte{}, blob...)
	corrupted[0] ^= 0xFF
	if PrefixCRCMatches(corrupted) {
		t.Fatal("a corrupted prefix CRC still matched")
	}

	if PrefixCRCMatches(body) {
		t.Fatal("a patch without a checksum prefix matched")
	}
	if PrefixCRCMatches([]byte("PA31")) {
		t.Fatal("a four-byte magic matched")
	}
	if PrefixCRCMatches(nil) {
		t.Fatal("nil matched")
	}

	// The prefix describes the magic and body, not the prefix itself.
	wrongMagic := append([]byte{}, blob...)
	copy(wrongMagic[4:8], []byte("PA99"))
	if PrefixCRCMatches(wrongMagic) {
		t.Fatal("a non-delta rest was checksummed")
	}
}

func TestOpenMetadata(t *testing.T) {
	body := bodyOf([]byte{1, 2, 3, 4, 5})
	blob := prefixed(body)
	patch, err := Open(source.NewMemorySource(1, blob))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if patch.Kind() != KindPA31 {
		t.Fatalf("kind = %v", patch.Kind())
	}
	if patch.SignatureOffset() != 4 {
		t.Fatalf("signature offset = %d", patch.SignatureOffset())
	}
	if !patch.HasPrefixCRC() {
		t.Fatal("prefix CRC presence was not recorded")
	}
	matches, err := patch.PrefixCRCMatches()
	if err != nil {
		t.Fatalf("PrefixCRCMatches: %v", err)
	}
	if !matches {
		t.Fatal("valid CRC reported as a mismatch")
	}
	// A second call is served from the cached result.
	if again, err := patch.PrefixCRCMatches(); err != nil || !again {
		t.Fatalf("second PrefixCRCMatches = %v, %v", again, err)
	}
	if patch.Len() != uint64(len(blob)) {
		t.Fatalf("len = %d, want %d", patch.Len(), len(blob))
	}
}

func TestOpenCRCReportedNotEnforced(t *testing.T) {
	blob := prefixed(bodyOf([]byte{9, 9}))
	blob[0] ^= 0xFF
	patch, err := Open(source.NewMemorySource(1, blob))
	if err != nil {
		t.Fatalf("a bad CRC must not refuse identification: %v", err)
	}
	matches, err := patch.PrefixCRCMatches()
	if err != nil {
		t.Fatalf("PrefixCRCMatches: %v", err)
	}
	if matches {
		t.Fatal("corrupted CRC reported as a match")
	}
}

func TestOpenWithoutPrefix(t *testing.T) {
	blob := bodyOf([]byte{7, 7, 7})
	patch, err := Open(source.NewMemorySource(1, blob))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if patch.SignatureOffset() != 0 || patch.HasPrefixCRC() {
		t.Fatalf("signature offset = %d, prefix = %v", patch.SignatureOffset(), patch.HasPrefixCRC())
	}
	matches, err := patch.PrefixCRCMatches()
	if err != nil || matches {
		t.Fatalf("PrefixCRCMatches = %v, %v; want false, nil", matches, err)
	}
}

func TestOpenRejectsNonDelta(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte("PA3"),
		[]byte("<?xml version=\"1.0\"?><root/>"),
	} {
		patch, err := Open(source.NewMemorySource(1, data))
		if err == nil {
			t.Fatalf("Open(%q) = %+v, want an error", data, patch)
		}
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("error %v is not ErrUnsupported", err)
		}
		if !strings.Contains(err.Error(), "PA19") || !strings.Contains(err.Error(), "PA31") {
			t.Fatalf("error %q does not name the signatures", err)
		}
	}
}

func TestOpenShortSourceNeverFabricates(t *testing.T) {
	for length := 0; length < 4; length++ {
		data := bytes.Repeat([]byte("P"), length)
		if _, err := Open(source.NewMemorySource(1, data)); err == nil {
			t.Fatalf("Open(%q) succeeded", data)
		}
	}
}

func TestReconstructIsUnsupported(t *testing.T) {
	patch, err := Open(source.NewMemorySource(1, prefixed(bodyOf([]byte{1}))))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	src, err := patch.Reconstruct(2)
	if err == nil {
		t.Fatalf("Reconstruct = %v, want an error", src)
	}
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error %v is not ErrUnsupported", err)
	}
	text := err.Error()
	for _, part := range []string{"PA31", "delta", "base file"} {
		if !strings.Contains(text, part) {
			t.Fatalf("error %q does not mention %q", text, part)
		}
	}
}

func TestCRCMatchesAcrossReadChunks(t *testing.T) {
	payload := make([]byte, 200000)
	for index := range payload {
		payload[index] = byte(index*31 + 7)
	}
	blob := prefixed(bodyOf(payload))
	patch, err := Open(source.NewMemorySource(1, blob))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	matches, err := patch.PrefixCRCMatches()
	if err != nil {
		t.Fatalf("PrefixCRCMatches: %v", err)
	}
	if !matches {
		t.Fatal("streaming CRC disagreed with the whole-buffer CRC")
	}
}

func TestOpenPropagatesSourceErrors(t *testing.T) {
	failing := &failingSource{MemorySource: source.NewMemorySource(1, []byte("PA31xxxx"))}
	if _, err := Open(failing); !errors.Is(err, source.ErrIO) {
		t.Fatalf("Open error = %v, want ErrIO", err)
	}
}

type failingSource struct {
	*source.MemorySource
}

func (f *failingSource) ReadAt(offset uint64, buf []byte) (int, error) {
	return 0, source.NewIOError(offset, errors.New("synthetic read failure"))
}
