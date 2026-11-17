package hfsplus_test

import (
	"bytes"
	"errors"
	"testing"

	hfs "github.com/laenix/ewfgo/internal/data/filesystems/hfsplus"
)

// decmpfsImage opens a minimal volume holding only the compressed fixtures.
func decmpfsImage(t *testing.T, bitmapRaw bool) *hfs.Volume {
	t.Helper()
	volume, _ := openImage(t, imageOptions{
		attributes:       true,
		minimal:          true,
		decmpfs:          true,
		decmpfsBitmapRaw: bitmapRaw,
	})
	return volume
}

func TestDecmpfsInlineContent(t *testing.T) {
	volume := decmpfsImage(t, false)
	cases := []struct {
		path string
		want []byte
	}{
		{"/inline-zlib.bin", decmpfsZlibInlineContent},
		{"/inline-lzvn.bin", decmpfsLZVNInlineContent},
		{"/inline-raw.bin", decmpfsRawInlineContent},
		{"/inline-lzfse.bin", decmpfsLZFSEInlineContent},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			assertDecmpfsFile(t, volume, tc.path, tc.want)
		})
	}
}

func TestDecmpfsResourceForkContent(t *testing.T) {
	volume := decmpfsImage(t, false)
	cases := []struct {
		path string
		want []byte
	}{
		{"/rsrc-zlib.bin", decmpfsZlibResourceContent},
		{"/rsrc-lzvn.bin", decmpfsLZVNResourceContent},
		{"/rsrc-raw.bin", decmpfsRawResourceContent}, // stored as a ResourceFork xattr
		{"/rsrc-lzfse.bin", decmpfsLZFSEEResourceContent},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			assertDecmpfsFile(t, volume, tc.path, tc.want)
		})
	}
}

func assertDecmpfsFile(t *testing.T, volume *hfs.Volume, path string, want []byte) {
	t.Helper()
	if bytes.Equal(want, dataForkStub) {
		t.Fatalf("fixture content is the data-fork stub")
	}

	stream, err := volume.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if stream.Len() != uint64(len(want)) {
		t.Fatalf("OpenFile length = %d, want %d", stream.Len(), len(want))
	}
	if got := readAll(t, stream); !bytes.Equal(got, want) {
		t.Fatalf("OpenFile bytes = %q, want %q", got, want)
	}
	if bytes.Equal(readAll(t, stream), dataForkStub) {
		t.Fatal("OpenFile served the dataless data-fork stub")
	}

	// A direct positioned read sees the same decompressed content.
	buf := make([]byte, len(want))
	if n, err := stream.ReadAt(0, buf); err != nil || n != len(want) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("ReadAt bytes = %q", buf)
	}

	whole, err := volume.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(whole, want) {
		t.Fatalf("ReadFile = %q, want %q", whole, want)
	}

	entry, err := volume.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !entry.Compressed {
		t.Error("Stat does not report the file as compressed")
	}
	if entry.Size != uint64(len(want)) {
		t.Errorf("Stat size = %d, want %d (the declared uncompressed size)", entry.Size, len(want))
	}

	// ListDir reports the same declared size.
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	listed := entryByName(entries, entry.Name)
	if listed == nil || listed.Size != uint64(len(want)) || !listed.Compressed {
		t.Errorf("ListDir entry = %+v", listed)
	}
}

func TestDecmpfsResourceForkStaysRaw(t *testing.T) {
	volume := decmpfsImage(t, false)

	raw, err := volume.OpenFork("/rsrc-zlib.bin", hfs.ForkResource)
	if err != nil {
		t.Fatalf("OpenFork: %v", err)
	}
	want := classicResource(zlibStored(decmpfsZlibResourceContent))
	if got := readAll(t, raw); !bytes.Equal(got, want) {
		t.Errorf("resource fork = %d bytes, want %d", len(got), len(want))
	}

	// OpenFile serves the decompressed content, not the resource fork.
	content, err := volume.ReadFile("/rsrc-zlib.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Equal(content, want) {
		t.Fatal("OpenFile served the raw resource fork")
	}
	if !bytes.Equal(content, decmpfsZlibResourceContent) {
		t.Fatalf("content = %q", content)
	}
}

func TestDecmpfsErrors(t *testing.T) {
	volume := decmpfsImage(t, false)
	cases := []struct {
		path string
		kind error
	}{
		{"/size-mismatch.bin", hfs.ErrInvalid},
		{"/missing-rsrc.bin", hfs.ErrInvalid},
		{"/bad-magic.bin", hfs.ErrInvalid},
		{"/lzbitmap.bin", hfs.ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if _, err := volume.OpenFile(tc.path); !errors.Is(err, tc.kind) {
				t.Errorf("OpenFile error = %v, want %v", err, tc.kind)
			}
			if _, err := volume.ReadFile(tc.path); !errors.Is(err, tc.kind) {
				t.Errorf("ReadFile error = %v, want %v", err, tc.kind)
			}
			// A malformed stream must never fall back to the data-fork stub.
			if stream, err := volume.OpenFile(tc.path); err == nil {
				got := readAll(t, stream)
				if bytes.Equal(got, dataForkStub) {
					t.Error("malformed decmpfs served the dataless data-fork stub")
				}
			}
		})
	}
}

func TestDecmpfsLZBitmapRawCopy(t *testing.T) {
	volume := decmpfsImage(t, true)
	assertDecmpfsFile(t, volume, "/lzbitmap.bin", decmpfsLZBitmapRawContent)
}

func TestDecmpfsBadHeaderMakesStatExplicit(t *testing.T) {
	volume := decmpfsImage(t, false)
	if _, err := volume.Stat("/bad-magic.bin"); !errors.Is(err, hfs.ErrInvalid) {
		t.Errorf("Stat(bad magic) = %v, want ErrInvalid", err)
	}
}
