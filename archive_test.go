package forensic_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func zipFixture(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	if _, err := writer.Create("dir/"); err != nil {
		t.Fatal(err)
	}
	file, err := writer.Create("dir/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("hello archive\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOpenArchiveZIP(t *testing.T) {
	ctx := context.Background()
	archive, err := forensic.OpenArchiveSource(ctx, source.NewMemorySource(1, zipFixture(t)), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenArchiveSource: %v", err)
	}
	if archive.Format() != "zip" {
		t.Fatalf("Format = %q", archive.Format())
	}
	entries, err := archive.Entries(ctx)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2", entries)
	}
	var fileEntry *forensic.ArchiveEntry
	for i := range entries {
		if entries[i].Path == "dir/a.txt" {
			fileEntry = &entries[i]
		}
	}
	if fileEntry == nil || fileEntry.Kind != "file" || fileEntry.Size != 14 {
		t.Fatalf("dir/a.txt entry = %+v", fileEntry)
	}

	file, err := archive.Open(ctx, "/dir/a.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, err := file.ReadAll()
	file.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "hello archive\n" {
		t.Fatalf("content = %q", data)
	}
}

func TestOpenArchiveRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	file, err := writer.Create("../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = forensic.OpenArchiveSource(context.Background(), source.NewMemorySource(1, buf.Bytes()), forensic.Options{})
	if !errors.Is(err, forensic.ErrInvalidArgument) {
		t.Fatalf("OpenArchiveSource traversal error = %v, want ErrInvalidArgument", err)
	}
}

func TestOpenArchiveTAR(t *testing.T) {
	payload := []byte("tar payload\n")
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	if err := writer.WriteHeader(&tar.Header{Name: "payload.txt", Mode: 0o644, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	archive, err := forensic.OpenArchiveSource(ctx, source.NewMemorySource(1, buf.Bytes()), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenArchiveSource: %v", err)
	}
	if archive.Format() != "tar" {
		t.Fatalf("Format = %q", archive.Format())
	}
	file, err := archive.Open(ctx, "payload.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, err := file.ReadAll()
	file.Close()
	if err != nil || string(data) != string(payload) {
		t.Fatalf("ReadAll = %q, %v", data, err)
	}
}

func TestOpenArchiveRAR4Unsupported(t *testing.T) {
	data := append([]byte("Rar!\x1a\x07\x00"), make([]byte, 64)...)
	_, err := forensic.OpenArchiveSource(context.Background(), source.NewMemorySource(1, data), forensic.Options{})
	if !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("OpenArchive(RAR4) = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "RAR 4") {
		t.Fatalf("OpenArchive(RAR4) = %v, want mention of RAR 4", err)
	}
}

func TestOpenArchiveUnsupported(t *testing.T) {
	_, err := forensic.OpenArchiveSource(context.Background(), source.NewMemorySource(1, []byte("not an archive")), forensic.Options{})
	if !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
}

func TestOpenArchiveEntryLimit(t *testing.T) {
	_, err := forensic.OpenArchiveSource(context.Background(), source.NewMemorySource(1, zipFixture(t)),
		forensic.Options{Limits: forensic.Limits{MaxEntries: 1}})
	if !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("OpenArchiveSource over MaxEntries = %v, want ErrUnsupported", err)
	}
}

func TestArchiveOpenRejectsTraversalPath(t *testing.T) {
	ctx := context.Background()
	archive, err := forensic.OpenArchiveSource(ctx, source.NewMemorySource(1, zipFixture(t)), forensic.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Open(ctx, "../a.txt"); !errors.Is(err, forensic.ErrInvalidArgument) {
		t.Fatalf("Open traversal error = %v, want ErrInvalidArgument", err)
	}
	if _, err := archive.Open(ctx, "missing.txt"); err == nil || !strings.Contains(err.Error(), "missing.txt") {
		t.Fatalf("Open missing error = %v", err)
	}
}
