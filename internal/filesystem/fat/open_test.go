package fat

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// TestFAT32OpenFileStreaming verifies the streaming reader is byte-identical
// to GetFile, supports position-independent ReadAt across cluster boundaries,
// and implements Seek/Read/Close as an io.ReadSeekCloser.
func TestFAT32OpenFileStreaming(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	want, err := h.GetFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if len(want) != 1536 {
		t.Fatalf("HELLO.TXT size = %d, want 1536", len(want))
	}

	rc, err := h.OpenFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	// The concrete reader implements io.ReaderAt (sqlite's VFS type-asserts it).
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}

	// Whole-file Read matches GetFile byte for byte.
	all, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(all, want) {
		t.Fatalf("streamed content differs from GetFile content")
	}

	// ReadAt across and between 512-byte cluster boundaries.
	for _, off := range []int64{0, 1, 511, 512, 513, 700, 1530, 1535} {
		buf := make([]byte, 4)
		wantN, wantErr := 4, error(nil)
		if off+4 > int64(len(want)) {
			wantN = len(want) - int(off)
			wantErr = io.EOF
		}
		n, err := ra.ReadAt(buf, off)
		if n != wantN || (wantErr == nil && err != nil) || (wantErr != nil && !errors.Is(err, io.EOF)) {
			t.Errorf("ReadAt(%d): n=%d err=%v, want n=%d err=%v", off, n, err, wantN, wantErr)
			continue
		}
		if !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
			t.Errorf("ReadAt(%d) = %x, want %x", off, buf[:n], want[off:off+int64(n)])
		}
	}

	// ReadAt at or past EOF returns io.EOF.
	if _, err := ra.ReadAt(make([]byte, 4), int64(len(want))); err != io.EOF {
		t.Errorf("ReadAt at EOF err = %v, want io.EOF", err)
	}
	if _, err := ra.ReadAt(make([]byte, 4), int64(len(want))+100); err != io.EOF {
		t.Errorf("ReadAt past EOF err = %v, want io.EOF", err)
	}

	// Seek(Start) + Read.
	if _, err := rc.Seek(512, io.SeekStart); err != nil {
		t.Fatalf("Seek(Start,512): %v", err)
	}
	chunk := make([]byte, 10)
	n, err := rc.Read(chunk)
	if err != nil || n != 10 {
		t.Fatalf("Read after Seek: n=%d err=%v", n, err)
	}
	if !bytes.Equal(chunk, want[512:522]) {
		t.Errorf("post-seek read = %x, want %x", chunk, want[512:522])
	}

	// Seek(End,-3) reaches the final bytes; Read delivers them then EOF.
	pos, err := rc.Seek(-3, io.SeekEnd)
	if err != nil {
		t.Fatalf("Seek(End,-3): %v", err)
	}
	if pos != int64(len(want))-3 {
		t.Errorf("Seek(End,-3) pos = %d, want %d", pos, len(want)-3)
	}
	tail := make([]byte, 3)
	if _, err := rc.Read(tail); err != nil {
		t.Fatalf("Read after Seek(End): %v", err)
	}
	if !bytes.Equal(tail, want[len(want)-3:]) {
		t.Errorf("tail read = %x, want %x", tail, want[len(want)-3:])
	}
	if n, err := rc.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Errorf("Read at EOF = (n=%d, err=%v), want (0, io.EOF)", n, err)
	}

	// Seek(Current) advances relative to the current position.
	if _, err := rc.Seek(2, io.SeekCurrent); err != nil {
		t.Fatalf("Seek(Current,2): %v", err)
	}
	if _, err := rc.Seek(-1, io.SeekCurrent); err != nil {
		t.Fatalf("Seek(Current,-1): %v", err)
	}
	if n, err := rc.Read(make([]byte, 0)); n != 0 || (err != nil && err != io.EOF) {
		t.Errorf("Read(empty) = (n=%d, err=%v), want (0, nil) or (0, io.EOF)", n, err)
	}
}

// TestFAT32OpenFileConcurrentReadAt hammers a SINGLE handle with concurrent
// ReadAt calls at random offsets and verifies every byte matches GetFile. This
// is the regression guard for the D1 data race: extendTo mutates the shared
// cluster-chain state, which the handle mutex serializes. It cannot detect the
// race without the -race detector (CGO is off here), but it pins byte identity
// under contention so a CI run with CGO enabled catches any future regression.
func TestFAT32OpenFileConcurrentReadAt(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	want, err := h.GetFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}

	rc, err := h.OpenFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}

	const workers = 16
	const readsPerWorker = 200
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < readsPerWorker; i++ {
				off := rng.Intn(len(want))
				sz := rng.Intn(len(want)-off) + 1 // 1..remaining bytes
				buf := make([]byte, sz)
				n, err := ra.ReadAt(buf, int64(off))
				if n != sz || err != nil {
					errs <- fmt.Errorf("worker %d: ReadAt(%d, %d) n=%d err=%v", seed, off, sz, n, err)
					return
				}
				if !bytes.Equal(buf, want[off:off+sz]) {
					errs <- fmt.Errorf("worker %d: content mismatch at offset %d", seed, off)
					return
				}
			}
		}(int64(w))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestFAT32OpenFileTruncatedChain verifies the red line: a file whose declared
// size exceeds its cluster-chain allocation must surface an explicit error when
// the missing tail is touched, never fabricated bytes.
func TestFAT32OpenFileTruncatedChain(t *testing.T) {
	img := buildFAT32Image()
	// HELLO.TXT claims 2048 bytes but its chain (clusters 3,4,5) allocates 1536.
	rootOff := testDataAreaStart * testBPSSector
	le32(img, rootOff+28, 2048)

	h, err := NewFAT32Handler(&memFATReader{data: img}, 0, testTotalSectors)
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}
	rc, err := h.OpenFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}

	// Bytes within the allocated chain are real data.
	buf := make([]byte, 1536)
	if n, err := ra.ReadAt(buf, 0); err != nil || n != 1536 {
		t.Fatalf("ReadAt(0, 1536): n=%d err=%v, want full chain", n, err)
	}
	for i := 0; i < 1536; i++ {
		if want := byte('A' + i/512); buf[i] != want { // 0x41/0x42/0x43 per cluster
			t.Fatalf("byte %d = 0x%02X, want 0x%02X", i, buf[i], want)
		}
	}

	// The byte past the allocated chain must be an explicit error, not zeros.
	if _, err := ra.ReadAt(make([]byte, 1), 1536); err == nil {
		t.Fatal("ReadAt past allocated chain must error (truncated allocation), not fabricate a tail")
	}
}

// TestFAT32OpenFileSentinelErrors verifies that errors from the streaming path
// and the legacy path unwrap to the exported sentinels.
func TestFAT32OpenFileSentinelErrors(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	if _, err := h.GetFile("/DOESNOTEXIST.TXT"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("GetFile missing path err = %v, want ErrNotFound", err)
	}
	if _, err := h.GetFile("/SUBDIR"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("GetFile directory path err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.OpenFile("/DOESNOTEXIST.TXT"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("OpenFile missing path err = %v, want ErrNotFound", err)
	}
	if _, err := h.OpenFile("/SUBDIR"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("OpenFile directory path err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.GetFile("/HELLO.TXT/child"); !errors.Is(err, filesystem.ErrNotDirectory) {
		t.Errorf("GetFile under a file err = %v, want ErrNotDirectory", err)
	}
}

// TestFAT32OpenFileIndependentHandles verifies two open handles read
// independently: each OpenFile gets its own position and chain state.
func TestFAT32OpenFileIndependentHandles(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	a, err := h.OpenFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("OpenFile(a): %v", err)
	}
	defer a.Close()
	b, err := h.OpenFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("OpenFile(b): %v", err)
	}
	defer b.Close()

	// Advance handle a to offset 512.
	if _, err := a.Seek(512, io.SeekStart); err != nil {
		t.Fatalf("Seek(a): %v", err)
	}
	if _, err := a.Read(make([]byte, 3)); err != nil {
		t.Fatalf("Read(a): %v", err)
	}

	// Handle b still reads from offset 0.
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("ReadAll(b): %v", err)
	}
	want, _ := h.GetFile("/HELLO.TXT")
	if !bytes.Equal(got, want) {
		t.Errorf("handle b content differs from GetFile after handle a was seeked")
	}
}

// TestFAT32ParseDirectorySurrogateLFN verifies a VFAT long filename whose
// UTF-16 surrogate pair straddles the record boundary decodes correctly
// (𠮷 U+20BB7 -> units 0xD842 0xDFB7), instead of garbling per-rune.
func TestFAT32ParseDirectorySurrogateLFN(t *testing.T) {
	h := &FAT32Handler{}
	// 96 bytes = LFN record (0) + short entry (32) + end-of-directory marker (64).
	data := make([]byte, 96)

	// One LFN record: seq byte 0x40|1 (ordinal 1, LAST), attr 0x0F.
	data[0] = 0x41
	data[11] = 0x0F
	// UTF-16LE units of "𠮷.txt".
	units := []uint16{0xD842, 0xDFB7, 0x002E, 0x0074, 0x0078, 0x0074}
	for i, u := range units {
		le16(data, []int{1, 3, 5, 7, 9, 14}[i], u)
	}
	// Owning short entry.
	setDirEntry(data, 32, "JIMO    ", "TXT", 0x20, 3, 100)

	entries, end := h.parseDirectory(data, "")
	if len(entries) != 1 {
		t.Fatalf("parseDirectory: got %d entries, want 1", len(entries))
	}
	if !end {
		t.Errorf("parseDirectory did not reach end-of-directory marker")
	}
	if entries[0].Name != "𠮷.txt" {
		t.Errorf("LFN name = %q, want %q", entries[0].Name, "𠮷.txt")
	}
	if entries[0].Path != "/𠮷.txt" {
		t.Errorf("LFN path = %q, want %q", entries[0].Path, "/𠮷.txt")
	}
}

// TestFAT32ParseDirectoryTimestamps verifies DOS date/time fields decode into
// correct Unix times on the directory entry.
func TestFAT32ParseDirectoryTimestamps(t *testing.T) {
	h := &FAT32Handler{}
	data := make([]byte, 32)
	setDirEntry(data, 0, "HELLO   ", "TXT", 0x20, 3, 100)

	// 2024-03-15 14:30:12 UTC.
	date := uint16(44<<9 | 3<<5 | 15)     // (2024-1980)<<9 | month<<5 | day
	dosTime := uint16(14<<11 | 30<<5 | 6) // hour<<11 | minute<<5 | second/2
	le16(data, 24, date)                  // last-write date
	le16(data, 22, dosTime)               // last-write time
	le16(data, 16, date)                  // creation date
	le16(data, 14, dosTime)               // creation time
	le16(data, 18, date)                  // last-access date (date only)

	entries, _ := h.parseDirectory(data, "")
	if len(entries) != 1 {
		t.Fatalf("parseDirectory: got %d entries, want 1", len(entries))
	}
	e := entries[0]

	want := time.Date(2024, 3, 15, 14, 30, 12, 0, time.UTC).Unix()
	if e.ModTime != want {
		t.Errorf("ModTime = %d (%s), want %d (%s)", e.ModTime, time.Unix(e.ModTime, 0).UTC(), want, time.Unix(want, 0).UTC())
	}
	if e.CreateTime != want {
		t.Errorf("CreateTime = %d, want %d", e.CreateTime, want)
	}
	midnight := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC).Unix()
	if e.AccessTime != midnight {
		t.Errorf("AccessTime = %d, want %d (date-only, midnight)", e.AccessTime, midnight)
	}

	// A zeroed date field yields no timestamp, never a fabricated epoch.
	if e.Name == "" {
		t.Fatal("entry name empty")
	}
	if fatDateTimeToUnix(0, dosTime) != 0 {
		t.Errorf("fatDateTimeToUnix(0, time) = %d, want 0", fatDateTimeToUnix(0, dosTime))
	}
	// Out-of-range values (month 13) also yield 0.
	if v := fatDateTimeToUnix(13<<5|1, dosTime); v != 0 {
		t.Errorf("fatDateTimeToUnix(bad month) = %d, want 0", v)
	}
}
