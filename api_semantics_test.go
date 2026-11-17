package forensic_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	forensic "github.com/laenix/ewfgo"
)

func openFAT(t *testing.T, opts forensic.Options) (*forensic.Image, forensic.FileSystem) {
	t.Helper()
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixture(t, "fat16-encase6-zlib.E01"), opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { img.Close() })
	parts, err := img.Partitions(ctx)
	if err != nil || len(parts) == 0 {
		t.Fatalf("Partitions: %v (%d)", err, len(parts))
	}
	fsys, err := parts[0].OpenFilesystem(ctx)
	if err != nil {
		t.Fatalf("OpenFilesystem: %v", err)
	}
	t.Cleanup(func() { fsys.Close() })
	return img, fsys
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := forensic.Open(ctx, fixture(t, "fat16-encase6-zlib.E01"), forensic.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open(cancelled) = %v, want context.Canceled", err)
	}
	if _, err := forensic.OpenSource(ctx, nil, forensic.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenSource(cancelled) = %v, want context.Canceled", err)
	}

	_, fsys := openFAT(t, forensic.Options{})
	runCtx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := fsys.ListDir(runCtx, "/"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListDir(cancelled) = %v, want context.Canceled", err)
	}
	if err := fsys.Walk(runCtx, "/", func(forensic.Entry) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("Walk(cancelled) = %v, want context.Canceled", err)
	}
}

func TestMaxEntriesLimit(t *testing.T) {
	ctx := context.Background()
	// The ext4 fixture root carries both lost+found and fixture.txt.
	img, err := forensic.Open(ctx, fixture(t, "ext4-encase25-zlib.E01"),
		forensic.Options{Limits: forensic.Limits{MaxEntries: 1}})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()
	parts, err := img.Partitions(ctx)
	if err != nil || len(parts) == 0 {
		t.Fatalf("Partitions: %v (%d)", err, len(parts))
	}
	fsys, err := parts[0].OpenFilesystem(ctx)
	if err != nil {
		t.Fatalf("OpenFilesystem: %v", err)
	}
	defer fsys.Close()
	if _, err := fsys.ListDir(ctx, "/"); !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("ListDir over MaxEntries = %v, want ErrUnsupported", err)
	}
}

func TestFreeSpaceCapability(t *testing.T) {
	ctx := context.Background()
	_, fsys := openFAT(t, forensic.Options{})
	provider, ok := fsys.(forensic.FreeSpaceProvider)
	if !ok {
		t.Fatal("filesystem does not advertise FreeSpaceProvider")
	}
	if _, err := provider.FreeSpace(ctx); !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("FreeSpace on FAT = %v, want ErrUnsupported", err)
	}
}

func TestMaxFileBytesLimit(t *testing.T) {
	ctx := context.Background()
	_, fsys := openFAT(t, forensic.Options{Limits: forensic.Limits{MaxFileBytes: 4}})
	file, err := fsys.Open(ctx, "FIXTURE.TXT")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer file.Close()
	if _, err := file.ReadAll(); !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("ReadAll over MaxFileBytes = %v, want ErrUnsupported", err)
	}
	// Bounded reads remain available: the limit guards whole-file convenience,
	// not evidence access.
	buf := make([]byte, 4)
	if _, err := file.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt(4): %v", err)
	}
	if string(buf) != "fixt" {
		t.Fatalf("ReadAt content = %q", buf)
	}
}

func TestFileSeekAndConcurrentReadAt(t *testing.T) {
	ctx := context.Background()
	_, fsys := openFAT(t, forensic.Options{})
	file, err := fsys.Open(ctx, "FIXTURE.TXT")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer file.Close()

	first := make([]byte, 3)
	if _, err := file.Read(first); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(first) != "fix" {
		t.Fatalf("first read = %q", first)
	}
	// ReadAt must not change the logical Read position.
	probe := make([]byte, 2)
	if _, err := file.ReadAt(probe, 0); err != nil {
		t.Fatalf("ReadAt during sequential read: %v", err)
	}
	next := make([]byte, 1)
	if n, err := file.Read(next); err != nil || n != 1 {
		t.Fatalf("Read after ReadAt = %d, %v", n, err)
	}
	if string(next) != "t" {
		t.Fatalf("Read after ReadAt = %q, want %q", next, "t")
	}
	if _, err := file.Seek(4, 0); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	rest, err := readAllFromCurrent(file)
	if err != nil {
		t.Fatalf("read from seek: %v", err)
	}
	if string(rest) != "ure\n" {
		t.Fatalf("after seek = %q", rest)
	}

	want := []byte("fixture\n")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			offset := int64(i % len(want))
			buf := make([]byte, 2)
			n, err := file.ReadAt(buf, offset)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Errorf("concurrent ReadAt(%d): %v", offset, err)
				return
			}
			if !bytes.Equal(buf[:n], want[offset:offset+int64(n)]) {
				t.Errorf("concurrent ReadAt(%d) = %q, want %q", offset, buf[:n], want[offset:offset+int64(n)])
			}
		}(i)
	}
	wg.Wait()
}

// readAllFromCurrent reads the rest of a File through io.Reader.
func readAllFromCurrent(file *forensic.File) ([]byte, error) {
	var out []byte
	buf := make([]byte, 16)
	for {
		n, err := file.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
	}
}
