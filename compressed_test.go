package forensic_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func TestOpenCompressedGzip(t *testing.T) {
	payload := bytes.Repeat([]byte("evidence stream\n"), 100)
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	writer.Name = "evidence.txt"
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "evidence.txt.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	stream, err := forensic.OpenCompressed(context.Background(), path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenCompressed: %v", err)
	}
	if stream.Format() != "gzip" || stream.Size() != uint64(len(payload)) {
		t.Fatalf("stream = %q %d", stream.Format(), stream.Size())
	}
	data, err := stream.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("decoded content differs (%d bytes vs %d)", len(data), len(payload))
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestOpenCompressedBzip2(t *testing.T) {
	const storedHex = "425a6839314159265359555a44f70000021980400010001264c0102000220069ea100305d3b62183c5dc914e14241556913dc0"
	data, err := hex.DecodeString(storedHex)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hello.bz2")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stream, err := forensic.OpenCompressed(context.Background(), path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenCompressed(bzip2): %v", err)
	}
	defer stream.Close()
	if stream.Format() != "bzip2" {
		t.Fatalf("format = %q", stream.Format())
	}
	content, err := stream.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(content) != "hello bzip2" {
		t.Fatalf("content = %q", content)
	}
}

func TestOpenCompressedSource(t *testing.T) {
	const storedHex = "425a6839314159265359555a44f70000021980400010001264c0102000220069ea100305d3b62183c5dc914e14241556913dc0"
	data, err := hex.DecodeString(storedHex)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := forensic.OpenCompressedSource(context.Background(), source.NewMemorySource(1, data), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenCompressedSource: %v", err)
	}
	content, err := stream.ReadAll()
	if err != nil || string(content) != "hello bzip2" {
		t.Fatalf("content = %q, %v", content, err)
	}
}

func TestOpenCompressedLZ4(t *testing.T) {
	const storedHex = "04224d1868403700000000000000bb37000080737368645b315d3a2041636365707465642070617373776f726420666f7220616c6963652066726f6d203139382e35312e3130302e370a00000000"
	data, err := hex.DecodeString(storedHex)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "evidence.log.lz4")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stream, err := forensic.OpenCompressed(context.Background(), path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenCompressed(lz4): %v", err)
	}
	defer stream.Close()
	if stream.Format() != "lz4" {
		t.Fatalf("format = %q", stream.Format())
	}
	content, err := stream.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	const want = "sshd[1]: Accepted password for alice from 198.51.100.7\n"
	if string(content) != want {
		t.Fatalf("content = %q, want %q", content, want)
	}
}

func TestOpenCompressedXZ(t *testing.T) {
	const storedHex = "fd377a585a0000016922de360200210116000000742fe5a3e000c3006c5d0026984a420bb4ebd87ff30eabfebdfc7d3582b4165f1846d1d9e62227d7b817333cae3167f26657aebcc3cacff80686f850f2b477e52f8f3bde04560cf4bc4dbe242a4d31c394866ea1c122574a580de2eeb71935c1fd34c7697d8ad51c07e6d8db3d92e6be0fb53c447bc8a00074cc31b700018401c4010000c5b8f9833e300d8b020000000001595a"
	data, err := hex.DecodeString(storedHex)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.log.xz")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stream, err := forensic.OpenCompressed(context.Background(), path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenCompressed(xz): %v", err)
	}
	defer stream.Close()
	if stream.Format() != "xz" {
		t.Fatalf("format = %q", stream.Format())
	}
	content, err := stream.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	const want = "Mar  1 10:00:00 host sshd[1]: Accepted password for alice from 198.51.100.7\n" +
		"Mar  1 10:00:01 host sshd[1]: session opened for user alice\n" +
		"Mar  1 10:00:02 host sshd[1]: session closed for user alice\n"
	if string(content) != want {
		t.Fatalf("content = %q, want %q", content, want)
	}
}

func TestOpenCompressedRejectsPlainFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(path, []byte("not compressed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := forensic.OpenCompressed(context.Background(), path, forensic.Options{}); err == nil {
		t.Fatal("OpenCompressed accepted a plain file")
	}
}
