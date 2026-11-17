package sevenz

// Hermetic compatibility tests over the reference fixture corpus.
//
// fixturecorpus_test.go embeds the exact bytes the Rust fixture generator
// publishes as sevenz-basic, sevenz-deflate64 and sevenz-encrypted, so these
// tests never read the reference checkout at run time.

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

var (
	refStoredText  = []byte("7z copy member: stored, not compressed, and listed before the LZMA2 folder.\n")
	refPackedText  = []byte("7z LZMA2 member: this payload repeats itself so the stream compresses; this payload repeats itself so the stream compresses.\n")
	refUnicodeText = []byte("中文成员\n")
)

func decodeFixture(t *testing.T, name, encoded string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return decoded
}

// The reference writer packed EmptyStream/EmptyFile bit vectors
// least-significant first, the opposite of the order 7-Zip itself uses.  The
// reader must accept both without letting an empty file inherit a substream.
func TestReferenceBasicFixtureListsAndReadsEveryMember(t *testing.T) {
	reader := openBytes(t, decodeFixture(t, "sevenz-basic", rustBasicFixture), archive.DefaultLimits())
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	want := []struct {
		path string
		kind string
		size uint64
	}{
		{"docs", "directory", 0},
		{"docs/stored.txt", "file", uint64(len(refStoredText))},
		{"docs/packed.txt", "file", uint64(len(refPackedText))},
		{"empty.txt", "file", 0},
		{"中文.txt", "file", uint64(len(refUnicodeText))},
	}
	if len(entries) != len(want) {
		t.Fatalf("listed %d entries, want %d: %+v", len(entries), len(want), entries)
	}
	for index, expected := range want {
		entry := entries[index]
		if entry.Path != expected.path || entry.Kind.Label() != expected.kind || entry.Size != expected.size {
			t.Errorf("entry %d = {%q, %s, %d}, want {%q, %s, %d}", index,
				entry.Path, entry.Kind.Label(), entry.Size,
				expected.path, expected.kind, expected.size)
		}
	}

	for _, member := range []struct {
		path string
		want []byte
	}{
		{"docs/stored.txt", refStoredText},
		{"docs/packed.txt", refPackedText},
		{"中文.txt", refUnicodeText},
	} {
		if got := readEntry(t, reader, member.path); string(got) != string(member.want) {
			t.Errorf("%s = %q, want %q", member.path, got, member.want)
		}
	}

	// The empty member must stay empty.  If EmptyStream were misread it would
	// consume a substream and either fail the file table or expose another
	// member's bytes, so assert both the length and the absence of a folder.
	empty, err := reader.OpenEntrySource("empty.txt", 99)
	if err != nil {
		t.Fatalf("OpenEntrySource(empty.txt): %v", err)
	}
	if empty.Len() != 0 || !empty.IsEmpty() {
		t.Fatalf("empty.txt Len = %d, want 0", empty.Len())
	}
	if _, ok := empty.Folder(); ok {
		t.Error("empty.txt must not name a folder")
	}
	if _, err := empty.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("reading empty.txt = %v, want ErrOutOfRange", err)
	}
}

func TestReferenceDeflate64FixtureIsRefusedAtOpen(t *testing.T) {
	reader := openBytes(t, decodeFixture(t, "sevenz-deflate64", rustDeflate64Fixture), archive.DefaultLimits())
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "input.bin" || entries[0].Size != 90000 {
		t.Fatalf("entries = %+v, want one 90000-byte input.bin", entries)
	}
	if entries[0].Encrypted {
		t.Error("the Deflate64 fixture is not encrypted")
	}

	if _, err := reader.OpenEntrySource("input.bin", 2); err == nil ||
		!errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenEntrySource err = %v, want ErrUnsupported", err)
	} else if !strings.Contains(err.Error(), "Deflate64") {
		t.Errorf("error %q does not name Deflate64", err)
	}
	if _, err := reader.OpenEntry("input.bin", 3); err == nil ||
		!errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenEntry err = %v, want ErrUnsupported", err)
	}
}

func TestReferenceEncryptedFixtureIsRefusedAtOpen(t *testing.T) {
	reader := openBytes(t, decodeFixture(t, "sevenz-encrypted", rustEncryptedFixture), archive.DefaultLimits())
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	paths := []string{"secret/first.txt", "secret/second.txt"}
	if len(entries) != len(paths) {
		t.Fatalf("listed %d entries, want %d: %+v", len(entries), len(paths), entries)
	}
	for index, path := range paths {
		if entries[index].Path != path || !entries[index].Encrypted {
			t.Errorf("entry %d = {%q, encrypted=%v}, want an encrypted %q",
				index, entries[index].Path, entries[index].Encrypted, path)
		}
		if _, err := reader.OpenEntrySource(path, source.ID(10+index)); err == nil ||
			!errors.Is(err, source.ErrDecrypt) {
			t.Errorf("OpenEntrySource(%s) err = %v, want ErrDecrypt", path, err)
		}
		if _, err := reader.OpenEntry(path, source.ID(20+index)); err == nil ||
			!errors.Is(err, source.ErrDecrypt) {
			t.Errorf("OpenEntry(%s) err = %v, want ErrDecrypt", path, err)
		}
	}
}
