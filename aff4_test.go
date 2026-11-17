package forensic_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func aff4Fixture(t *testing.T) []byte {
	t.Helper()
	turtle := "@prefix aff4: <http://aff4.org/Schema#> .\n" +
		"@prefix hash: <http://aff4.org/Schema#> .\n" +
		"<aff4://image> a aff4:Image ;\n" +
		"    aff4:category aff4:imageStream ;\n" +
		"    aff4:size 8 ;\n" +
		"    aff4:chunkSize 4 ;\n" +
		"    aff4:chunksPerSegment 1 ;\n" +
		"    aff4:compressionMethod aff4:stored .\n"

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	members := []struct{ name, data string }{
		{"container.description", "AFF4-1.0\n"},
		{"information.turtle", turtle},
		{"image/00000000", "ABCD"},
		{"image/00000001", "EFGH"},
	}
	for _, member := range members {
		header := &zip.FileHeader{Name: member.name, Method: zip.Store}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(member.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOpenAFF4(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.aff4")
	if err := os.WriteFile(path, aff4Fixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	evidence, err := forensic.OpenAFF4(ctx, path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenAFF4: %v", err)
	}
	defer evidence.Close()

	info := evidence.Info()
	if info.Version != "1.0" || info.Streams != 1 || info.Images != 1 {
		t.Fatalf("info = %+v", info)
	}
	streams, err := evidence.Streams(ctx)
	if err != nil || len(streams) != 1 {
		t.Fatalf("Streams = %+v, %v", streams, err)
	}
	if streams[0].URI != "aff4://image" || streams[0].Class == "" {
		t.Fatalf("stream = %+v", streams[0])
	}

	src, err := evidence.ImageSource(ctx)
	if err != nil {
		t.Fatalf("ImageSource: %v", err)
	}
	if src.Len() != 8 {
		t.Fatalf("image length = %d", src.Len())
	}
	buf := make([]byte, 8)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "ABCDEFGH" {
		t.Fatalf("image = %q", buf)
	}
}

func TestOpenAFF4Source(t *testing.T) {
	ctx := context.Background()
	evidence, err := forensic.OpenAFF4Source(ctx, source.NewMemorySource(1, aff4Fixture(t)), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenAFF4Source: %v", err)
	}
	src, err := evidence.ImageSource(ctx)
	if err != nil {
		t.Fatalf("ImageSource: %v", err)
	}
	if src.Len() != 8 {
		t.Fatalf("image length = %d", src.Len())
	}
}

func TestOpenRejectsAFF4(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.aff4")
	if err := os.WriteFile(path, aff4Fixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := forensic.Open(context.Background(), path, forensic.Options{})
	if !errors.Is(err, forensic.ErrInvalidArgument) {
		t.Fatalf("Open(AFF4) = %v, want ErrInvalidArgument", err)
	}
	if !strings.Contains(err.Error(), "OpenAFF4") {
		t.Fatalf("Open(AFF4) = %v, want guidance to OpenAFF4", err)
	}
}
