package fat

import (
	"fmt"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// --- Minimal in-memory FAT32 image builder ---

const (
	testBPSSector     = 512
	testTotalSectors  = 2048
	testReserved      = 32
	testNumFATs       = 2
	testSectorsPerFAT = 100                                          // must be >= 100 to avoid the fallback path
	testDataAreaStart = testReserved + testNumFATs*testSectorsPerFAT // 232
)

func le16(b []byte, off int, v uint16) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
}

func le32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

func putFatEntry(img []byte, fatBase, cluster int, value uint32) {
	off := fatBase + cluster*4
	le32(img, off, value)
}

// setDirEntry writes a 32-byte FAT directory entry at buf[off:off+32].
func setDirEntry(buf []byte, off int, name8, ext3 string, attr byte, cluster uint32, size uint32) {
	copy(buf[off:off+8], name8)
	copy(buf[off+8:off+11], ext3)
	buf[off+11] = attr
	le16(buf, off+20, uint16(cluster>>16))    // high word of first cluster
	le16(buf, off+26, uint16(cluster&0xFFFF)) // low word of first cluster
	le32(buf, off+28, size)
}

// buildFAT32Image builds a valid minimal FAT32 image:
//
//	cluster 2 (LBA 232) : root dir -> HELLO.TXT, SUBDIR
//	clusters 3,4,5      : HELLO.TXT content (0x41,0x42,0x43 patterns)
//	cluster 6 (LBA 236) : SUBDIR dir    -> NESTED.TXT
//	cluster 7 (LBA 237) : NESTED.TXT content ("nested content!")
func buildFAT32Image() []byte {
	img := make([]byte, testTotalSectors*testBPSSector)

	// Boot sector
	le16(img, 0x0B, testBPSSector)
	img[0x0D] = 1 // sectorsPerCluster
	le16(img, 0x0E, testReserved)
	img[0x10] = testNumFATs
	img[0x15] = 0xF8
	le16(img, 0x18, 32)
	le16(img, 0x1A, 64)
	le32(img, 0x20, testTotalSectors)
	le32(img, 0x24, testSectorsPerFAT)
	le32(img, 0x2C, 2) // rootCluster
	le16(img, 0x32, 2) // backupBootSector
	copy(img[0x52:0x5A], "FAT32   ")
	img[0x1FE] = 0x55
	img[0x1FF] = 0xAA

	// FAT1 (sector 32) and FAT2 (sector 132)
	fat1 := testReserved * testBPSSector
	putFatEntry(img, fat1, 0, 0x0FFFFFF8) // media byte
	putFatEntry(img, fat1, 1, 0x0FFFFFFF)
	putFatEntry(img, fat1, 2, 0x0FFFFFFF) // root dir
	putFatEntry(img, fat1, 3, 4)          // HELLO.TXT chain: 3 -> 4
	putFatEntry(img, fat1, 4, 5)          // 4 -> 5
	putFatEntry(img, fat1, 5, 0x0FFFFFFF) // EOC
	putFatEntry(img, fat1, 6, 0x0FFFFFFF) // SUBDIR
	putFatEntry(img, fat1, 7, 0x0FFFFFFF) // NESTED.TXT
	fat2 := (testReserved + testSectorsPerFAT) * testBPSSector
	copy(img[fat2:fat2+8*4], img[fat1:fat1+8*4])

	// Root directory (cluster 2, LBA = dataAreaStart)
	rootOff := testDataAreaStart * testBPSSector
	setDirEntry(img, rootOff+0, "HELLO   ", "TXT", 0x20, 3, 1536)
	setDirEntry(img, rootOff+32, "SUBDIR  ", "   ", 0x10, 6, 0)
	// rootOff+64 remains 0x00 (end marker)

	// SUBDIR (cluster 6, LBA = dataAreaStart + 4)
	subOff := (testDataAreaStart + 4) * testBPSSector
	setDirEntry(img, subOff+0, "NESTED  ", "TXT", 0x20, 7, 15)
	// subOff+32 remains 0x00 (end marker)

	// HELLO.TXT content: clusters 3,4,5 (LBA dataAreaStart+1,+2,+3)
	for i := 0; i < testBPSSector; i++ {
		img[(testDataAreaStart+1)*testBPSSector+i] = 0x41 // 'A'
		img[(testDataAreaStart+2)*testBPSSector+i] = 0x42 // 'B'
		img[(testDataAreaStart+3)*testBPSSector+i] = 0x43 // 'C'
	}

	// NESTED.TXT content (cluster 7, LBA dataAreaStart+5)
	content := []byte("nested content!")
	copy(img[(testDataAreaStart+5)*testBPSSector:], content)

	return img
}

// memFATReader is a fake Reader over an in-memory byte slice (512-byte sectors).
type memFATReader struct {
	data []byte
}

func (r *memFATReader) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	start := uint64(testBPSSector) * lba
	end := start + uint64(testBPSSector)*count
	if end > uint64(len(r.data)) {
		return nil, fmt.Errorf("read out of bounds: lba=%d count=%d", lba, count)
	}
	return r.data[start:end], nil
}

func newTestFAT32Handler() (*FAT32Handler, error) {
	return NewFAT32Handler(&memFATReader{data: buildFAT32Image()}, 0, testTotalSectors)
}

// --- Tests ---

func TestFAT32ListDirectory(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("root listing: got %d entries, want 2: %+v", len(entries), entries)
	}

	var gotHello, gotSubdir bool
	for _, e := range entries {
		switch e.Name {
		case "HELLO.TXT":
			gotHello = true
			if e.IsDir {
				t.Errorf("HELLO.TXT should be a file")
			}
			if e.Size != 1536 {
				t.Errorf("HELLO.TXT size = %d, want 1536", e.Size)
			}
			if e.Cluster != 3 {
				t.Errorf("HELLO.TXT cluster = %d, want 3", e.Cluster)
			}
		case "SUBDIR":
			gotSubdir = true
			if !e.IsDir {
				t.Errorf("SUBDIR should be a directory")
			}
			if e.Cluster != 6 {
				t.Errorf("SUBDIR cluster = %d, want 6", e.Cluster)
			}
		}
	}
	if !gotHello || !gotSubdir {
		t.Errorf("root listing missing entries: got %+v", entries)
	}

	// Subdirectory listing. The entry must carry its real absolute path under
	// the parent (regression: parseDirectory hardcoded "/" + name, so a
	// downstream walker stat'd NESTED.TXT at the wrong root-relative path).
	sub, err := h.ListDirectory("/SUBDIR")
	if err != nil {
		t.Fatalf("ListDirectory(/SUBDIR): %v", err)
	}
	if len(sub) != 1 || sub[0].Name != "NESTED.TXT" {
		t.Errorf("SUBDIR listing = %+v, want [NESTED.TXT]", sub)
	}
	if sub[0].Path != "/SUBDIR/NESTED.TXT" {
		t.Errorf("SUBDIR entry Path = %q, want %q", sub[0].Path, "/SUBDIR/NESTED.TXT")
	}
}

func TestFAT32GetFile(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	data, err := h.GetFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("GetFile(/HELLO.TXT): %v", err)
	}
	if len(data) != 1536 {
		t.Fatalf("HELLO.TXT length = %d, want 1536", len(data))
	}
	// Verify each of the 3 clusters was read from the correct cluster.
	for i := 0; i < 512; i++ {
		if data[i] != 0x41 {
			t.Fatalf("cluster 3 byte %d = 0x%02X, want 0x41", i, data[i])
		}
	}
	for i := 0; i < 512; i++ {
		if data[512+i] != 0x42 {
			t.Fatalf("cluster 4 byte %d = 0x%02X, want 0x42", i, data[512+i])
		}
	}
	for i := 0; i < 512; i++ {
		if data[1024+i] != 0x43 {
			t.Fatalf("cluster 5 byte %d = 0x%02X, want 0x43", i, data[1024+i])
		}
	}
}

func TestFAT32GetFileNested(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	data, err := h.GetFile("/SUBDIR/NESTED.TXT")
	if err != nil {
		t.Fatalf("GetFile(/SUBDIR/NESTED.TXT): %v", err)
	}
	if string(data) != "nested content!" {
		t.Errorf("nested file content = %q, want %q", string(data), "nested content!")
	}
}

func TestFAT32GetFileByPath(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	fi, err := h.GetFileByPath("/HELLO.TXT")
	if err != nil {
		t.Fatalf("GetFileByPath(/HELLO.TXT): %v", err)
	}
	if fi.Name != "HELLO.TXT" || fi.IsDir || fi.Size != 1536 || fi.ModTime != 0 {
		t.Errorf("unexpected FileInfo: %+v", fi)
	}

	d, err := h.GetFileByPath("/SUBDIR")
	if err != nil {
		t.Fatalf("GetFileByPath(/SUBDIR): %v", err)
	}
	if !d.IsDir {
		t.Errorf("SUBDIR should be IsDir: %+v", d)
	}
}

func TestFAT32SearchFiles(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	results, err := h.SearchFiles("/", func(fi filesystem.FileInfo) bool {
		return strings.HasSuffix(fi.Name, ".TXT")
	})
	if err != nil {
		t.Fatalf("SearchFiles(/): %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("SearchFiles found %d files, want 2: %+v", len(results), results)
	}
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.Path] = true
	}
	if !seen["/HELLO.TXT"] || !seen["/SUBDIR/NESTED.TXT"] {
		t.Errorf("search results missing expected paths: %+v", seen)
	}
}

func TestFAT32GetFileErrors(t *testing.T) {
	h, err := newTestFAT32Handler()
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	// Missing file must error, not fabricate data.
	if _, err := h.GetFile("/DOESNOTEXIST.TXT"); err == nil {
		t.Errorf("GetFile on missing path should error")
	}
	// Reading a directory as a file must error.
	if _, err := h.GetFile("/SUBDIR"); err == nil {
		t.Errorf("GetFile on a directory should error")
	}
}

// TestFAT32ParseDirectoryHighCluster is a regression test for a first-cluster
// parse bug: the high word of the cluster (dirent bytes 20-21) must land in
// bits 16-31. It previously OR-ed into bits 0-15, so any entry whose cluster
// is >= 65536 (0x10000) parsed as a wrong value — silently reading another
// file's chain, or reporting a bogus "truncated cluster chain" on real data.
func TestFAT32ParseDirectoryHighCluster(t *testing.T) {
	h := &FAT32Handler{}
	data := make([]byte, 32*3)

	// BIG.BIN with start cluster 0x10002 (low word 0x0002, high word 0x0001).
	setDirEntry(data, 0, "BIG     ", "BIN", 0x20, 0x10002, 32768)
	// SMALL.TXT with start cluster 3 (high word zero) — must stay 3.
	setDirEntry(data, 32, "SMALL   ", "TXT", 0x20, 3, 100)
	data[64] = 0 // end-of-directory marker

	entries, ended := h.parseDirectory(data, "")
	if !ended {
		t.Errorf("expected end-of-directory marker to terminate parsing")
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}
	if entries[0].Cluster != 0x10002 {
		t.Errorf("BIG.BIN cluster: got 0x%X, want 0x10002", entries[0].Cluster)
	}
	if entries[1].Cluster != 3 {
		t.Errorf("SMALL.TXT cluster: got %d, want 3", entries[1].Cluster)
	}
}

// lfnEntry writes a single-entry long-filename record (seq 0x41) for name,
// followed by the short entry written by setDirEntry, into data at offset.
// Returns the offset just past the short entry.
func lfnEntry(data []byte, offset int, name string, name8, ext3 string, attr byte, cluster uint32, size uint32) int {
	e := data[offset : offset+32]
	e[0] = 0x41 // sequence 1 + LAST_LONG_ENTRY
	e[11] = 0x0F
	// First 5 UTF-16 chars at offsets 1-10
	for i, c := range name {
		if i >= 5 {
			break
		}
		le16(data, offset+1+i*2, uint16(c))
	}
	return offset + 32 + setDirEntryAt(data, offset+32, name8, ext3, attr, cluster, size)
}

// setDirEntryAt is setDirEntry but returns the count of bytes written.
func setDirEntryAt(buf []byte, off int, name8, ext3 string, attr byte, cluster uint32, size uint32) int {
	copy(buf[off:off+8], name8)
	copy(buf[off+8:off+11], ext3)
	buf[off+11] = attr
	le16(buf, off+20, uint16(cluster>>16))    // high word of first cluster
	le16(buf, off+26, uint16(cluster&0xFFFF)) // low word of first cluster
	le32(buf, off+28, size)
	return 32
}

// TestFAT32ParseDirectoryLFNReset is a regression test for stale long names:
// a short entry that follows an LFN'd entry but has no LFN of its own must
// keep its short name. It previously inherited the previous entry's long name,
// so real files were reported under the wrong directory's name (e.g. an EFI
// boot directory's "BOOT.STL" appearing as the previous locale dir's "bg-BG").
func TestFAT32ParseDirectoryLFNReset(t *testing.T) {
	h := &FAT32Handler{}
	data := make([]byte, 32*4)

	// LFN "bg-BG" + short dir BG-BG (cluster 34).
	off := 0
	off = lfnEntry(data, off, "bg-BG", "BG-BG   ", "   ", 0x10, 34, 0)
	// Plain short-name file BOOT.STL with NO LFN record.
	setDirEntry(data, off, "BOOT    ", "STL", 0x20, 195, 5023)
	data[off+32] = 0

	entries, _ := h.parseDirectory(data, "")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}
	if entries[0].Name != "bg-BG" || !entries[0].IsDir || entries[0].Cluster != 34 {
		t.Errorf("entry[0]: got name=%q isDir=%v cluster=%d, want bg-BG dir cluster 34",
			entries[0].Name, entries[0].IsDir, entries[0].Cluster)
	}
	if entries[1].Name != "BOOT.STL" {
		t.Errorf("entry[1] name: got %q, want %q (stale LFN leaked)", entries[1].Name, "BOOT.STL")
	}
	if entries[1].Cluster != 195 || entries[1].Size != 5023 {
		t.Errorf("entry[1]: got cluster=%d size=%d, want 195/5023", entries[1].Cluster, entries[1].Size)
	}
}

// --- FAT12 in-memory image ---

// putFat12Entry writes one packed 12-bit FAT entry. Two clusters share a
// 3-byte group: the low cluster (even N) occupies bytes[g] and the low nibble
// of bytes[g+1]; the odd cluster occupies the high nibble of bytes[g+1] and
// bytes[g+2], where g = (N/2)*3.
func putFat12Entry(img []byte, fatBase, cluster int, value uint32) {
	g := (cluster / 2) * 3
	off := fatBase + g
	v := value & 0x0FFF
	if cluster%2 == 0 {
		img[off] = byte(v)
		img[off+1] = (img[off+1] & 0xF0) | byte(v>>8)
	} else {
		img[off+1] = (img[off+1] & 0x0F) | byte(v<<4&0xF0)
		img[off+2] = byte(v >> 4)
	}
}

// buildFAT12Image builds a minimal valid FAT12 image in memory:
//
//	bps=512, spc=1, reserved=1, numFATs=2, rootEntryCount=224, spf16=1
//	FAT1 @ sector 1, FAT2 @ sector 2
//	root dir (fixed region) @ LBA 3 (14 sectors) -> FOO.TXT (cluster 2), BAZ.TXT (cluster 3), SUBDIR (cluster 4)
//	cluster 2 (LBA 17) -> "bar", cluster 3 (LBA 18) -> "qux"
//	SUBDIR (cluster 4, LBA 19) -> NESTED.TXT (cluster 5, LBA 20 -> "nested-in-fat12")
//
// Cluster 2 exercises the even 12-bit formula and cluster 3 the odd one.
func buildFAT12Image() []byte {
	const bps = 512
	const totalSectors = 64
	img := make([]byte, totalSectors*bps)

	// Boot sector
	le16(img, 0x0B, bps)
	img[0x0D] = 1 // sectorsPerCluster
	le16(img, 0x0E, 1)
	img[0x10] = 2 // numFATs
	le16(img, 0x11, 224)
	le16(img, 0x13, totalSectors)
	img[0x15] = 0xF0 // media descriptor
	le16(img, 0x16, 1)
	copy(img[0x36:0x3E], "FAT12   ")
	img[0x1FE] = 0x55
	img[0x1FF] = 0xAA

	// FAT1 (sector 1) and FAT2 (sector 2), copied for consistency.
	fat1 := 1 * bps
	putFat12Entry(img, fat1, 0, 0xF00) // media byte lives in the cluster-0 entry
	putFat12Entry(img, fat1, 1, 0xFFF)
	putFat12Entry(img, fat1, 2, 0xFFF) // FOO.TXT EOC
	putFat12Entry(img, fat1, 3, 0xFFF) // BAZ.TXT EOC
	putFat12Entry(img, fat1, 4, 0xFFF) // SUBDIR EOC
	putFat12Entry(img, fat1, 5, 0xFFF) // NESTED.TXT EOC
	fat2 := 2 * bps
	copy(img[fat2:fat2+9], img[fat1:fat1+9])

	// Root directory (fixed region at LBA 3).
	rootBase := 3 * bps
	setDirEntry(img, rootBase+0, "FOO     ", "TXT", 0x20, 2, 3)
	setDirEntry(img, rootBase+32, "BAZ     ", "TXT", 0x20, 3, 3)
	setDirEntry(img, rootBase+64, "SUBDIR  ", "   ", 0x10, 4, 0)
	// rootBase+96 remains 0x00 (end marker)

	// SUBDIR (cluster 4, LBA 19): a real subdirectory carrying the conventional
	// "." (self) and ".." (parent) directory entries plus NESTED.TXT.
	subBase := 19 * bps
	setDirEntry(img, subBase+0, ".       ", "   ", 0x10, 4, 0)  // self reference
	setDirEntry(img, subBase+32, "..      ", "   ", 0x10, 0, 0) // parent (root, cluster 0)
	setDirEntry(img, subBase+64, "NESTED  ", "TXT", 0x20, 5, 15)
	// subBase+96 remains 0x00 (end marker)

	// Data clusters 2 and 3 (LBA 17 and 18).
	copy(img[17*bps:], "bar")
	copy(img[18*bps:], "qux")

	// NESTED.TXT content (cluster 5, LBA 20).
	copy(img[20*bps:], "nested-in-fat12")

	return img
}

// TestFAT12InMemory proves the packed 12-bit FAT path against a well-formed
// in-memory FAT12 image: the fixed-region root is listed and file contents are
// read through 12-bit chains (clusters 2 and 3, exercising both the even and
// odd packing formulas).
func TestFAT12InMemory(t *testing.T) {
	h, err := NewFAT32Handler(&memFATReader{data: buildFAT12Image()}, 0, 64)
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}
	if h.Type() != filesystem.FS_FAT12 {
		t.Fatalf("Type() = %v, want FS_FAT12", h.Type())
	}

	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Name] = true
	}
	if !seen["FOO.TXT"] || !seen["BAZ.TXT"] {
		t.Fatalf("root listing = %+v, want FOO.TXT and BAZ.TXT", entries)
	}

	got, err := h.GetFile("FOO.TXT")
	if err != nil {
		t.Fatalf("GetFile(FOO.TXT): %v", err)
	}
	if string(got) != "bar" {
		t.Fatalf("FOO.TXT = %q, want %q", string(got), "bar")
	}

	got, err = h.GetFile("BAZ.TXT")
	if err != nil {
		t.Fatalf("GetFile(BAZ.TXT): %v", err)
	}
	if string(got) != "qux" {
		t.Fatalf("BAZ.TXT = %q, want %q", string(got), "qux")
	}

	fi, err := h.GetFileByPath("/FOO.TXT")
	if err != nil {
		t.Fatalf("GetFileByPath(/FOO.TXT): %v", err)
	}
	if fi.Size != 3 || fi.IsDir {
		t.Fatalf("GetFileByPath = %+v, want size 3 non-dir", fi)
	}
}

// TestFAT12SearchFilesSubdir proves SearchFiles rooted at a real FAT12
// subdirectory walks that subdirectory's cluster chain — never the fixed root
// region. Regression: the walk's isRoot flag was always true for the first
// level, so a FAT12/16 search rooted at "/SUBDIR" read the fixed root region,
// mislabeling root files under the subdir path and doubling the subdir prefix.
func TestFAT12SearchFilesSubdir(t *testing.T) {
	h, err := NewFAT32Handler(&memFATReader{data: buildFAT12Image()}, 0, 64)
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}
	if h.Type() != filesystem.FS_FAT12 {
		t.Fatalf("Type() = %v, want FS_FAT12", h.Type())
	}

	// A subdirectory search returns exactly the subdir's own file.
	sub, err := h.SearchFiles("/SUBDIR", func(fi filesystem.FileInfo) bool {
		return strings.HasSuffix(fi.Name, ".TXT")
	})
	if err != nil {
		t.Fatalf("SearchFiles(/SUBDIR): %v", err)
	}
	if len(sub) != 1 {
		t.Fatalf("SearchFiles(/SUBDIR) = %+v, want exactly [/SUBDIR/NESTED.TXT]", sub)
	}
	if sub[0].Path != "/SUBDIR/NESTED.TXT" || sub[0].Name != "NESTED.TXT" {
		t.Fatalf("SearchFiles(/SUBDIR)[0] = %+v, want Path=/SUBDIR/NESTED.TXT", sub[0])
	}

	// The root search still finds the root files plus the nested one.
	root, err := h.SearchFiles("/", func(fi filesystem.FileInfo) bool {
		return strings.HasSuffix(fi.Name, ".TXT")
	})
	if err != nil {
		t.Fatalf("SearchFiles(/): %v", err)
	}
	seen := map[string]bool{}
	for _, r := range root {
		seen[r.Path] = true
	}
	want := map[string]bool{
		"/FOO.TXT":           true,
		"/BAZ.TXT":           true,
		"/SUBDIR/NESTED.TXT": true,
	}
	if len(root) != 3 {
		t.Fatalf("SearchFiles(/) found %d files, want 3: %+v", len(root), root)
	}
	for p := range want {
		if !seen[p] {
			t.Errorf("SearchFiles(/) missing %q (got %+v)", p, seen)
		}
	}
}

// TestFAT12SubdirSkipsDotAndDotDot proves the shared FAT12/16/32 directory
// parser skips the "." (self) and ".." (parent) entries of a real subdirectory.
// Listing them as real entries would let a downstream walker recurse into "."
// forever, fabricating nested paths. Both ListDirectory and SearchFiles must
// present only the subdirectory's actual entries.
func TestFAT12SubdirSkipsDotAndDotDot(t *testing.T) {
	h, err := NewFAT32Handler(&memFATReader{data: buildFAT12Image()}, 0, 64)
	if err != nil {
		t.Fatalf("NewFAT32Handler: %v", err)
	}

	sub, err := h.ListDirectory("/SUBDIR")
	if err != nil {
		t.Fatalf("ListDirectory(/SUBDIR): %v", err)
	}
	if len(sub) != 1 || sub[0].Name != "NESTED.TXT" {
		t.Fatalf("ListDirectory(/SUBDIR) = %+v, want exactly [NESTED.TXT] (no . or ..)", sub)
	}

	results, err := h.SearchFiles("/SUBDIR", func(fi filesystem.FileInfo) bool {
		return strings.HasSuffix(fi.Name, ".TXT")
	})
	if err != nil {
		t.Fatalf("SearchFiles(/SUBDIR): %v", err)
	}
	if len(results) != 1 || results[0].Path != "/SUBDIR/NESTED.TXT" {
		t.Fatalf("SearchFiles(/SUBDIR) = %+v, want exactly [/SUBDIR/NESTED.TXT] (no . or .. recursion)", results)
	}
}
