package filesystem_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/exfat"
)

// exfatFixture returns a handler over the committed exFAT fixture (partition
// start sector resolved from the image's own partition table).
func exfatFixture(t *testing.T, name string) (*exfat.EXFAT, *ewf.EWFImage) {
	t.Helper()
	img, err := ewf.Open(name)
	if err != nil {
		t.Fatalf("ewf.Open(%s): %v", name, err)
	}
	t.Cleanup(func() { img.Close() })

	parts, err := img.ScanFileSystems()
	if err != nil || len(parts) == 0 {
		t.Fatalf("ScanFileSystems: %v (parts=%d)", err, len(parts))
	}
	h, err := exfat.NewEXFATHandler(img, parts[0].StartSector)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}
	return h, img
}

// TestEXFATFixture is the real-image test: the committed
// testdata/e01/exfat-encase25-zlib.E01 fixture carries an injected fixture.txt
// (see testdata/injected.txt). Every assertion must hold against real on-disk
// exFAT data.
func TestEXFATFixture(t *testing.T) {
	h, _ := exfatFixture(t, "../../testdata/e01/exfat-encase25-zlib.E01")

	// Real directory listing includes the injected file with its exact name and
	// size.
	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "fixture.txt" {
			found = true
			if e.IsDir {
				t.Errorf("fixture.txt listed as a directory")
			}
			if e.Size != 8 {
				t.Errorf("fixture.txt listed size = %d, want 8", e.Size)
			}
		}
	}
	if !found {
		t.Fatalf("fixture.txt not listed in root (got %d entries)", len(entries))
	}

	// Content read: exact bytes (FAT cluster-chain read).
	data, err := h.GetFile("fixture.txt")
	if err != nil {
		t.Fatalf("GetFile(fixture.txt): %v", err)
	}
	if !bytes.Equal(data, []byte("fixture\n")) {
		t.Errorf("fixture.txt content = %q, want %q", string(data), "fixture\n")
	}

	// Metadata: size 8, not a directory.
	fi, err := h.GetFileByPath("fixture.txt")
	if err != nil {
		t.Fatalf("GetFileByPath(fixture.txt): %v", err)
	}
	if fi.Name != "fixture.txt" || fi.IsDir || fi.Size != 8 {
		t.Errorf("unexpected FileInfo for fixture.txt: %+v", fi)
	}

	// Search finds exactly one.
	results, err := h.SearchFiles("/", func(f filesystem.FileInfo) bool {
		return f.Name == "fixture.txt"
	})
	if err != nil {
		t.Fatalf("SearchFiles: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchFiles(fixture.txt) = %d results, want 1: %+v", len(results), results)
	}

	// Volume label: mkfs.exfat -n FIXTURE set this on the fixture.
	if label := h.GetVolumeLabel(); label != "FIXTURE" {
		t.Errorf("GetVolumeLabel() = %q, want %q", label, "FIXTURE")
	}
}

// TestEXFATFixtureMissingFile asserts honest errors for absent paths.
func TestEXFATFixtureMissingFile(t *testing.T) {
	h, _ := exfatFixture(t, "../../testdata/e01/exfat-encase25-zlib.E01")
	if _, err := h.GetFile("/no-such-file.txt"); err == nil {
		t.Fatal("GetFile on a missing path must error")
	}
	if _, err := h.GetFileByPath("/no-such-file.txt"); err == nil {
		t.Fatal("GetFileByPath on a missing path must error")
	}
	if _, err := h.ListDirectory("/no-such-dir"); err == nil {
		t.Fatal("ListDirectory on a missing directory must error")
	}
}

// --- Crafted-input hardening (解析红线: never panic on crafted input) ---

// memExfatReader is a fake Reader over an in-memory byte slice (512-byte
// sectors), used to feed malformed on-disk structures to the parser.
type memExfatReader struct {
	data []byte
}

func (r *memExfatReader) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	start := uint64(512) * lba
	end := start + uint64(512)*count
	if end > uint64(len(r.data)) {
		return nil, fmt.Errorf("read out of bounds: lba=%d count=%d", lba, count)
	}
	return r.data[start:end], nil
}

// makeFakeExfatImage builds a minimal, internally consistent 4 MiB exFAT image
// (512-byte sectors, 8 sectors/cluster, root cluster 5, FAT at sector 2048).
// mutate may rewrite arbitrary bytes (or shrink the slice) before the handler is
// constructed; the returned slice is what the fake reader serves.
func makeFakeExfatImage(mutate func(img []byte) []byte) *memExfatReader {
	img := make([]byte, 4<<20)
	copy(img[3:11], "EXFAT   ")
	img[108] = 9                                    // bytes-per-sector shift -> 512
	img[109] = 3                                    // sectors-per-cluster shift -> 8
	binary.LittleEndian.PutUint32(img[80:84], 2048) // FatOffset (sectors)
	binary.LittleEndian.PutUint32(img[84:88], 8)    // FatLength (sectors)
	binary.LittleEndian.PutUint32(img[88:92], 4096) // ClusterHeapOffset (sectors)
	binary.LittleEndian.PutUint32(img[92:96], 1000) // ClusterCount
	binary.LittleEndian.PutUint32(img[96:100], 5)   // FirstClusterOfRoot
	if mutate != nil {
		img = mutate(img)
	}
	return &memExfatReader{data: img}
}

// setFat writes a 32-bit FAT entry for a cluster (FAT starts at sector 2048).
func setFat(img []byte, cluster uint32, value uint32) {
	off := int64(2048)*512 + int64(cluster)*4
	binary.LittleEndian.PutUint32(img[off:off+4], value)
}

// TestEXFATMalformedBootSector feeds a mangled boot sector to the handler
// constructor and Open: every malformed case must error, never panic.
func TestEXFATMalformedBootSector(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(img []byte) []byte
	}{
		{"truncated-boot", func(img []byte) []byte { return img[:256] }}, // short boot sector
		{"bad-signature", func(img []byte) []byte { copy(img[3:11], "NOTEXFAT"); return img }},
		{"bad-bps-shift", func(img []byte) []byte { img[108] = 30; return img }},
		{"bad-spc-shift", func(img []byte) []byte { img[109] = 30; return img }},
		{"zero-cluster-count", func(img []byte) []byte { binary.LittleEndian.PutUint32(img[92:96], 0); return img }},
		{"zero-heap-offset", func(img []byte) []byte { binary.LittleEndian.PutUint32(img[88:92], 0); return img }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeFakeExfatImage(tc.mutate)
			if _, err := exfat.NewEXFATHandler(r, 0); err == nil {
				t.Fatalf("NewEXFATHandler must error for %s", tc.name)
			}
		})
	}

	// Open() on a registered handler must also reject malformed boot data.
	fs, err := filesystem.NewFileSystem(filesystem.FS_EXFAT)
	if err != nil {
		t.Fatalf("NewFileSystem(exFAT): %v", err)
	}
	if err := fs.Open([]byte("short")); err == nil {
		t.Fatal("Open(truncated) must error")
	}
	if err := fs.Open(bytes.Repeat([]byte{0}, 512)); err == nil {
		t.Fatal("Open(no signature) must error")
	}
}

// TestEXFATMalformedClusterChain crafts valid boot sectors whose FAT root chain
// is corrupt: truncated (FAT entry 0), a self-cycle, and a bad-cluster marker.
// ListDirectory must return an explicit error, never panic or fabricate data.
func TestEXFATMalformedClusterChain(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(img []byte) []byte
	}{
		{"truncated-chain", func(img []byte) []byte { setFat(img, 5, 0); return img }},
		{"self-cycle", func(img []byte) []byte { setFat(img, 5, 5); return img }},
		{"bad-cluster", func(img []byte) []byte { setFat(img, 5, 0xFFFFFFF7); return img }},
		{"loop-two-clusters", func(img []byte) []byte {
			setFat(img, 5, 6)
			setFat(img, 6, 5)
			return img
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeFakeExfatImage(tc.mutate)
			h, err := exfat.NewEXFATHandler(r, 0)
			if err != nil {
				t.Fatalf("NewEXFATHandler: %v", err)
			}
			if _, err := h.ListDirectory("/"); err == nil {
				t.Fatalf("ListDirectory must error for %s", tc.name)
			}
		})
	}
}

// --- Crafted entry-set helpers (root cluster 5 = byte offset 4120*512 in the
// fake image built by makeFakeExfatImage: heap 4096 sectors + (5-2)*8 sectors). ---

const exfatFakeRootByteOffset = 4120 * 512

// exfatFileDirEntry builds a 0x85 file-directory entry (SecondaryCount@1,
// FileAttributes@4-5).
func exfatFileDirEntry(secCnt byte, attrs uint16) [32]byte {
	var e [32]byte
	e[0] = 0x85
	e[1] = secCnt
	binary.LittleEndian.PutUint16(e[4:6], attrs)
	return e
}

// exfatStreamEntry builds a 0xC0 stream-extension entry (NameLength@3,
// FirstCluster@20-23, DataLength@24-31).
func exfatStreamEntry(nameLen byte, firstCluster uint32, dataLength uint64) [32]byte {
	var e [32]byte
	e[0] = 0xC0
	e[3] = nameLen
	binary.LittleEndian.PutUint32(e[20:24], firstCluster)
	binary.LittleEndian.PutUint64(e[24:32], dataLength)
	return e
}

// exfatNameEntry builds a 0xC1 file-name entry carrying up to 15 UTF-16 units
// at bytes 2-31.
func exfatNameEntry(name string) [32]byte {
	var e [32]byte
	e[0] = 0xC1
	units := utf16.Encode([]rune(name))
	for j, u := range units {
		if j >= 15 {
			break
		}
		binary.LittleEndian.PutUint16(e[2+j*2:4+j*2], u)
	}
	return e
}

// writeExfatRootEntry writes a 32-byte directory entry at the given index within
// the root cluster of the fake image.
func writeExfatRootEntry(img []byte, index int, e [32]byte) {
	off := exfatFakeRootByteOffset + index*32
	copy(img[off:off+32], e[:])
}

// TestEXFATEmptySubdirFirstClusterZero is the 解析红线 regression for
// readDirectory(0): a genuine empty exFAT subdirectory stores FirstCluster = 0
// in its 0xC0 stream. Listing it must return an EMPTY NON-NIL slice (len 0) with
// no error — never (nil, nil) and never a panic.
func TestEXFATEmptySubdirFirstClusterZero(t *testing.T) {
	r := makeFakeExfatImage(func(img []byte) []byte {
		setFat(img, 5, 0xFFFFFFFF) // root dir: single cluster, end of chain
		// Entry set: 0x85 file-dir (directory attr 0x0010, 2 secondaries) +
		// 0xC0 stream with FirstCluster = 0 (empty subdir) + 0xC1 name.
		writeExfatRootEntry(img, 0, exfatFileDirEntry(2, 0x0010))
		writeExfatRootEntry(img, 1, exfatStreamEntry(8, 0, 0))
		writeExfatRootEntry(img, 2, exfatNameEntry("emptydir"))
		return img
	})
	h, err := exfat.NewEXFATHandler(r, 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}

	// The root lists the empty subdirectory itself, with FirstCluster preserved.
	root, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	var sub *filesystem.DirectoryEntry
	for i := range root {
		if root[i].Name == "emptydir" {
			sub = &root[i]
			break
		}
	}
	if sub == nil {
		t.Fatalf("emptydir not listed in root: %+v", root)
	}
	if !sub.IsDir {
		t.Fatalf("emptydir must be listed as a directory")
	}

	// Listing the empty subdir (FirstCluster = 0) must return an EMPTY NON-NIL
	// listing with no error: the red-line regression.
	entries, err := h.ListDirectory("/emptydir")
	if err != nil {
		t.Fatalf("ListDirectory(/emptydir) must not error: %v", err)
	}
	if entries == nil {
		t.Fatal("ListDirectory(/emptydir) returned nil slice; want empty non-nil []DirectoryEntry{}")
	}
	if len(entries) != 0 {
		t.Fatalf("ListDirectory(/emptydir) = %d entries, want 0: %+v", len(entries), entries)
	}

	// SearchFiles recurses into the empty subdir without error.
	if _, err := h.SearchFiles("/", func(filesystem.FileInfo) bool { return false }); err != nil {
		t.Fatalf("SearchFiles over the empty subdir: %v", err)
	}
}

// TestEXFATTruncatedNameSetErrors covers assembleSet's explicit error: a 0xC0
// stream whose NameLength exceeds the UTF-16 units actually carried by the 0xC1
// name entries is a truncated/malformed entry set, and must error rather than
// silently return a shortened (fabricated) name.
func TestEXFATTruncatedNameSetErrors(t *testing.T) {
	r := makeFakeExfatImage(func(img []byte) []byte {
		setFat(img, 5, 0xFFFFFFFF)
		// Set: 0x85 (regular file, 2 secondaries) + 0xC0 stream declaring a
		// 30-unit name + a single 0xC1 entry that can carry at most 15 units.
		writeExfatRootEntry(img, 0, exfatFileDirEntry(2, 0))
		writeExfatRootEntry(img, 1, exfatStreamEntry(30, 0, 0))
		writeExfatRootEntry(img, 2, exfatNameEntry("ABCDEFGHIJKLMNO"))
		return img
	})
	h, err := exfat.NewEXFATHandler(r, 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}
	if _, err := h.ListDirectory("/"); err == nil {
		t.Fatal("ListDirectory must error when a set's declared name length exceeds the carried units")
	} else if !strings.Contains(err.Error(), "name length 30 exceeds") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestEXFATOversizeDataLengthErrors covers readFileClusters' size guard: a 0xC0
// stream whose DataLength exceeds what its FAT cluster chain allocates must make
// GetFile return an explicit error — never a panic and never a short fabricated
// read.
func TestEXFATOversizeDataLengthErrors(t *testing.T) {
	r := makeFakeExfatImage(func(img []byte) []byte {
		setFat(img, 5, 0xFFFFFFFF) // root dir: single cluster, end of chain
		// "big.txt" FAT chain: cluster 7 -> 8 -> EOC (2 clusters = 8192 bytes).
		setFat(img, 7, 8)
		setFat(img, 8, 0xFFFFFFFF)
		// Set: 0x85 (regular file, 2 secondaries) + 0xC0 stream declaring
		// DataLength = 8193 — one byte more than the 8192-byte chain covers.
		writeExfatRootEntry(img, 0, exfatFileDirEntry(2, 0))
		writeExfatRootEntry(img, 1, exfatStreamEntry(7, 7, 8193))
		writeExfatRootEntry(img, 2, exfatNameEntry("big.txt"))
		return img
	})
	h, err := exfat.NewEXFATHandler(r, 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}
	if _, err := h.GetFile("big.txt"); err == nil {
		t.Fatal("GetFile must error when DataLength exceeds the FAT cluster chain")
	}
}

// --- Streaming reader (OpenFile) over crafted fake images ---

// fillExfatCluster fills the data area of a cluster in the fake image (cluster N
// lives at byte (4096 + (N-2)*8) * 512: heap sector 4096, 8 sectors/cluster).
func fillExfatCluster(img []byte, cluster uint32, b byte) {
	off := (4096 + int(cluster-2)*8) * 512
	for i := 0; i < 4096; i++ {
		img[off+i] = b
	}
}

// exfatFakeDataImage builds a fake exFAT image carrying one regular file
// "DATA.BIN": 9000 bytes spanning clusters 7->8->9->EOC (4096-byte clusters),
// each cluster filled with a distinct byte pattern (0x41/0x42/0x43) so reads
// that cross cluster boundaries are verifiable byte for byte.
func exfatFakeDataImage() *memExfatReader {
	return makeFakeExfatImage(func(img []byte) []byte {
		setFat(img, 5, 0xFFFFFFFF) // root dir: single cluster, end of chain
		setFat(img, 7, 8)
		setFat(img, 8, 9)
		setFat(img, 9, 0xFFFFFFFF)
		fillExfatCluster(img, 7, 0x41)
		fillExfatCluster(img, 8, 0x42)
		fillExfatCluster(img, 9, 0x43)
		writeExfatRootEntry(img, 0, exfatFileDirEntry(2, 0)) // DATA.BIN (regular, 2 secondaries)
		writeExfatRootEntry(img, 1, exfatStreamEntry(8, 7, 9000))
		writeExfatRootEntry(img, 2, exfatNameEntry("DATA.BIN"))
		return img
	})
}

// exfatFakeDataImageWant returns the expected 9000-byte content of DATA.BIN.
func exfatFakeDataImageWant() []byte {
	want := make([]byte, 9000)
	for i := range want {
		switch {
		case i < 4096:
			want[i] = 0x41
		case i < 8192:
			want[i] = 0x42
		default:
			want[i] = 0x43
		}
	}
	return want
}

// TestEXFATOpenFileStreaming verifies the streaming reader is byte-identical to
// GetFile, supports position-independent ReadAt across cluster boundaries, and
// implements Seek/Read/Close as an io.ReadSeekCloser.
func TestEXFATOpenFileStreaming(t *testing.T) {
	h, err := exfat.NewEXFATHandler(exfatFakeDataImage(), 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}

	want, err := h.GetFile("/DATA.BIN")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if len(want) != 9000 {
		t.Fatalf("DATA.BIN size = %d, want 9000", len(want))
	}

	rc, err := h.OpenFile("/DATA.BIN")
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

	// ReadAt across and between 4096-byte cluster boundaries.
	for _, off := range []int64{0, 1, 4095, 4096, 4097, 8191, 8192, 8193, 8998, 8999} {
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
	if _, err := rc.Seek(4096, io.SeekStart); err != nil {
		t.Fatalf("Seek(Start,4096): %v", err)
	}
	chunk := make([]byte, 10)
	n, err := rc.Read(chunk)
	if err != nil || n != 10 {
		t.Fatalf("Read after Seek: n=%d err=%v", n, err)
	}
	if !bytes.Equal(chunk, want[4096:4106]) {
		t.Errorf("post-seek read = %x, want %x", chunk, want[4096:4106])
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

// TestEXFATOpenFileConcurrentReadAt hammers a SINGLE handle with concurrent
// ReadAt calls at random offsets and verifies every byte matches GetFile. This
// is the regression guard for the same data race class as the FAT reader: the
// lazy extendTo mutates the shared cluster-chain state, which the handle mutex
// serializes. It cannot detect the race without the -race detector (CGO is off
// here), but it pins byte identity under contention so a CI run with CGO
// enabled catches any future regression.
func TestEXFATOpenFileConcurrentReadAt(t *testing.T) {
	h, err := exfat.NewEXFATHandler(exfatFakeDataImage(), 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}

	want, err := h.GetFile("/DATA.BIN")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}

	rc, err := h.OpenFile("/DATA.BIN")
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

// TestEXFATOpenFileTruncatedChain verifies the red line: a file whose declared
// DataLength exceeds its cluster-chain allocation must surface an explicit
// error when the missing tail is touched, never fabricated bytes.
func TestEXFATOpenFileTruncatedChain(t *testing.T) {
	r := makeFakeExfatImage(func(img []byte) []byte {
		setFat(img, 5, 0xFFFFFFFF) // root dir: single cluster, end of chain
		// "big.txt" declares 8193 bytes but its chain (7->8->EOC) allocates 8192.
		setFat(img, 7, 8)
		setFat(img, 8, 0xFFFFFFFF)
		fillExfatCluster(img, 7, 0x41)
		fillExfatCluster(img, 8, 0x42)
		writeExfatRootEntry(img, 0, exfatFileDirEntry(2, 0))
		writeExfatRootEntry(img, 1, exfatStreamEntry(7, 7, 8193))
		writeExfatRootEntry(img, 2, exfatNameEntry("big.txt"))
		return img
	})
	h, err := exfat.NewEXFATHandler(r, 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}
	rc, err := h.OpenFile("/big.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}

	// Bytes within the allocated chain are real data.
	buf := make([]byte, 8192)
	if n, err := ra.ReadAt(buf, 0); err != nil || n != 8192 {
		t.Fatalf("ReadAt(0, 8192): n=%d err=%v, want full chain", n, err)
	}
	for i := 0; i < 8192; i++ {
		if want := byte('A' + i/4096); buf[i] != want { // 0x41/0x42 per cluster
			t.Fatalf("byte %d = 0x%02X, want 0x%02X", i, buf[i], want)
		}
	}

	// The byte past the allocated chain must be an explicit error, not zeros.
	if _, err := ra.ReadAt(make([]byte, 1), 8192); err == nil {
		t.Fatal("ReadAt past allocated chain must error (truncated allocation), not fabricate a tail")
	}
}

// TestEXFATOpenFileSentinelErrors verifies that errors from the streaming path
// and the legacy path unwrap to the exported sentinels.
func TestEXFATOpenFileSentinelErrors(t *testing.T) {
	r := makeFakeExfatImage(func(img []byte) []byte {
		setFat(img, 5, 0xFFFFFFFF)
		setFat(img, 7, 8)
		setFat(img, 8, 9)
		setFat(img, 9, 0xFFFFFFFF)
		fillExfatCluster(img, 7, 0x41)
		fillExfatCluster(img, 8, 0x42)
		fillExfatCluster(img, 9, 0x43)
		// DATA.BIN (file) + emptydir (directory, FirstCluster 0 = empty subdir).
		writeExfatRootEntry(img, 0, exfatFileDirEntry(2, 0))
		writeExfatRootEntry(img, 1, exfatStreamEntry(8, 7, 9000))
		writeExfatRootEntry(img, 2, exfatNameEntry("DATA.BIN"))
		writeExfatRootEntry(img, 3, exfatFileDirEntry(2, 0x0010))
		writeExfatRootEntry(img, 4, exfatStreamEntry(8, 0, 0))
		writeExfatRootEntry(img, 5, exfatNameEntry("emptydir"))
		return img
	})
	h, err := exfat.NewEXFATHandler(r, 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}

	if _, err := h.GetFile("/DOESNOTEXIST.TXT"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("GetFile missing path err = %v, want ErrNotFound", err)
	}
	if _, err := h.OpenFile("/DOESNOTEXIST.TXT"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("OpenFile missing path err = %v, want ErrNotFound", err)
	}
	if _, err := h.ListDirectory("/DOESNOTEXIST"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("ListDirectory missing dir err = %v, want ErrNotFound", err)
	}
	if _, err := h.GetFile("/emptydir"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("GetFile directory path err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.OpenFile("/emptydir"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("OpenFile directory path err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.GetFile("/DATA.BIN/child"); !errors.Is(err, filesystem.ErrNotDirectory) {
		t.Errorf("GetFile under a file err = %v, want ErrNotDirectory", err)
	}
	if _, err := h.OpenFile("/DATA.BIN/child"); !errors.Is(err, filesystem.ErrNotDirectory) {
		t.Errorf("OpenFile under a file err = %v, want ErrNotDirectory", err)
	}
}

// TestEXFATOpenFileIndependentHandles verifies two open handles read
// independently: each OpenFile gets its own position and chain state.
func TestEXFATOpenFileIndependentHandles(t *testing.T) {
	h, err := exfat.NewEXFATHandler(exfatFakeDataImage(), 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}

	a, err := h.OpenFile("/DATA.BIN")
	if err != nil {
		t.Fatalf("OpenFile(a): %v", err)
	}
	defer a.Close()
	b, err := h.OpenFile("/DATA.BIN")
	if err != nil {
		t.Fatalf("OpenFile(b): %v", err)
	}
	defer b.Close()

	// Advance handle a to offset 4096.
	if _, err := a.Seek(4096, io.SeekStart); err != nil {
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
	want, _ := h.GetFile("/DATA.BIN")
	if !bytes.Equal(got, want) {
		t.Errorf("handle b content differs from GetFile after handle a was seeked")
	}
}

// TestEXFATOpenFileEmptyFile verifies an empty file (DataLength 0, FirstCluster
// 0) opens successfully and reads immediately to io.EOF.
func TestEXFATOpenFileEmptyFile(t *testing.T) {
	r := makeFakeExfatImage(func(img []byte) []byte {
		setFat(img, 5, 0xFFFFFFFF)
		writeExfatRootEntry(img, 0, exfatFileDirEntry(2, 0))
		writeExfatRootEntry(img, 1, exfatStreamEntry(9, 0, 0))
		writeExfatRootEntry(img, 2, exfatNameEntry("empty.txt"))
		return img
	})
	h, err := exfat.NewEXFATHandler(r, 0)
	if err != nil {
		t.Fatalf("NewEXFATHandler: %v", err)
	}

	data, err := h.GetFile("/empty.txt")
	if err != nil || len(data) != 0 {
		t.Fatalf("GetFile(empty.txt) = %d bytes err=%v, want 0 bytes nil err", len(data), err)
	}

	rc, err := h.OpenFile("/empty.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	if n, err := rc.Read(make([]byte, 10)); n != 0 || err != io.EOF {
		t.Errorf("Read on empty file = (n=%d, err=%v), want (0, io.EOF)", n, err)
	}
	if _, err := rc.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	ra, ok := rc.(io.ReaderAt)
	if !ok {
		t.Fatalf("OpenFile result is not an io.ReaderAt (got %T)", rc)
	}
	if _, err := ra.ReadAt(make([]byte, 4), 0); err != io.EOF {
		t.Errorf("ReadAt on empty file err = %v, want io.EOF", err)
	}
}

// TestEXFATFixtureOpenFileStreaming is the real-image check: the committed
// exFAT fixture's injected fixture.txt streams out byte-identical to the
// "fixture\n" content written at injection time.
func TestEXFATFixtureOpenFileStreaming(t *testing.T) {
	h, _ := exfatFixture(t, "../../testdata/e01/exfat-encase25-zlib.E01")
	rc, err := h.OpenFile("fixture.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, []byte("fixture\n")) {
		t.Errorf("streamed fixture.txt = %q, want %q", string(got), "fixture\n")
	}
}
