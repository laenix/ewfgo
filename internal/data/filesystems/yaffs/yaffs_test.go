package yaffs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testPage   = 2048
	testStride = testPage + TagBytes
)

func testHeader(kind uint32, parent uint32, name string, mtime uint32, size uint32, equivalent uint32) []byte {
	page := make([]byte, testPage)
	binary.LittleEndian.PutUint32(page[0:], kind)
	binary.LittleEndian.PutUint32(page[4:], parent)
	copy(page[10:], name)
	binary.LittleEndian.PutUint32(page[266:], 0o100644)
	binary.LittleEndian.PutUint32(page[270:], 1000)
	binary.LittleEndian.PutUint32(page[274:], 1001)
	binary.LittleEndian.PutUint32(page[278:], mtime)
	binary.LittleEndian.PutUint32(page[282:], mtime)
	binary.LittleEndian.PutUint32(page[286:], mtime)
	binary.LittleEndian.PutUint32(page[290:], size)
	binary.LittleEndian.PutUint32(page[294:], equivalent)
	return page
}

func dataPage(data []byte) []byte {
	page := make([]byte, testPage)
	copy(page, data)
	return page
}

func pushPage(image *[]byte, serial, object, chunk, bytes uint32, data []byte, erased bool) {
	*image = append(*image, data...)
	tag := make([]byte, TagBytes)
	if !erased {
		binary.LittleEndian.PutUint32(tag[0:], serial)
		binary.LittleEndian.PutUint32(tag[4:], object)
		binary.LittleEndian.PutUint32(tag[8:], chunk)
		binary.LittleEndian.PutUint32(tag[12:], bytes)
	} else {
		for index := range tag {
			tag[index] = 0xff
		}
	}
	*image = append(*image, tag...)
}

func sampleImage() []byte {
	var image []byte
	pushPage(&image, 1, 1, 0, testPage, testHeader(3, 1, "/", 1_600_000_000, 0, 0), false)
	pushPage(&image, 2, 2, 0, testPage, testHeader(3, 1, "lost+found", 1_600_000_001, 0, 0), false)
	pushPage(&image, 3, 10, 0, testPage, testHeader(3, 1, "data", 1_600_000_002, 0, 0), false)
	pushPage(&image, 4, 11, 0, testPage, testHeader(1, 10, "notes.txt", 1_600_000_003, 11, 0), false)
	pushPage(&image, 5, 11, 1, 11, dataPage([]byte("hello yaffs")), false)
	pushPage(&image, 6, 12, 0, testPage, testHeader(2, 10, "link", 1_600_000_004, 9, 0), false)
	pushPage(&image, 7, 12, 1, 9, dataPage([]byte("notes.txt")), false)
	pushPage(&image, 8, 13, 0, testPage, testHeader(4, 10, "alias", 1_600_000_005, 0, 11), false)
	pushPage(&image, 9, 14, 0, testPage, testHeader(1, 10, "old.log", 1_600_000_006, 4, 0), false)
	pushPage(&image, 10, 14, 1, 4, dataPage([]byte("gone")), false)
	pushPage(&image, 11, 14, 0, testPage, testHeader(1, UnlinkedObjectID, "old.log", 1_600_000_007, 4, 0), false)
	pushPage(&image, 12, 15, 0, testPage, testHeader(1, 99, "orphan.txt", 1_600_000_008, 0, 0), false)
	pushPage(&image, 0, 0, 0, 0, make([]byte, testPage), true)
	return image
}

func openImage(t *testing.T, image []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func findEntry(t *testing.T, volume *Volume, path string) *Entry {
	t.Helper()
	entry, err := volume.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	return entry
}

func TestDetectRequiresRootHeader(t *testing.T) {
	image := sampleImage()
	found, err := Detect(source.NewMemorySource(1, image))
	if err != nil || !found {
		t.Fatalf("Detect(valid) = %v, %v", found, err)
	}
	layout, err := DetectLayout(source.NewMemorySource(2, image))
	if err != nil {
		t.Fatal(err)
	}
	if layout == nil || layout.PageData != testPage || layout.Stride != testStride || layout.TagOffset != testPage {
		t.Fatalf("DetectLayout(valid) = %+v", layout)
	}

	random := source.NewMemorySource(3, bytes.Repeat([]byte{0x5a}, testStride*8))
	found, err = Detect(random)
	if err != nil || found {
		t.Fatalf("Detect(random) = %v, %v", found, err)
	}
}

func TestDetectSpareAreaLayouts(t *testing.T) {
	for _, layout := range []Layout{
		{PageData: 2048, Stride: 2112, TagOffset: 2048},
		{PageData: 2048, Stride: 2112, TagOffset: 2050},
		{PageData: 2048, Stride: 2176, TagOffset: 2048},
	} {
		var image []byte
		add := func(serial, object, chunk, bytes uint32, data []byte) {
			image = append(image, data[:layout.PageData]...)
			spare := make([]byte, layout.Stride-layout.PageData)
			for index := range spare {
				spare[index] = 0xff
			}
			tag := make([]byte, TagBytes)
			binary.LittleEndian.PutUint32(tag[0:], serial)
			binary.LittleEndian.PutUint32(tag[4:], object)
			binary.LittleEndian.PutUint32(tag[8:], chunk)
			binary.LittleEndian.PutUint32(tag[12:], bytes)
			copy(spare[layout.TagOffset-layout.PageData:], tag)
			image = append(image, spare...)
		}
		add(1, 1, 0, uint32(layout.PageData), testHeader(3, 1, "/", 1, 0, 0))
		add(2, 2, 0, uint32(layout.PageData), testHeader(3, 1, "lost+found", 2, 0, 0))
		add(3, 10, 0, uint32(layout.PageData), testHeader(1, 1, "file", 3, 4, 0))
		add(4, 10, 1, 4, dataPage([]byte("data")))
		found, err := Detect(source.NewMemorySource(1, image))
		if err != nil || !found {
			t.Fatalf("Detect(%+v) = %v, %v", layout, found, err)
		}
		volume, err := Open(source.NewMemorySource(1, image))
		if err != nil {
			t.Fatalf("Open(%+v): %v", layout, err)
		}
		if got := volume.Layout(); got != layout {
			t.Fatalf("layout = %+v, want %+v", got, layout)
		}
	}
}

func TestTreeRebuiltFromHeaders(t *testing.T) {
	volume := openImage(t, sampleImage())
	if got := findEntry(t, volume, "/"); got.Kind != KindDirectory || !got.IsDir || got.Name != "/" {
		t.Fatalf("root = %+v", got)
	}
	if got := findEntry(t, volume, "/lost+found"); got.Kind != KindDirectory {
		t.Fatalf("lost+found = %+v", got)
	}
	notes := findEntry(t, volume, "/data/notes.txt")
	if notes.Size != 11 || notes.Mode != 0o100644 || notes.UID != 1000 || notes.GID != 1001 {
		t.Fatalf("notes = %+v", notes)
	}
	if !notes.HasMtime || !notes.Mtime.Equal(time.Unix(1_600_000_003, 0).UTC()) {
		t.Fatalf("mtime = %v (%v)", notes.Mtime, notes.HasMtime)
	}
	if got := findEntry(t, volume, "/data/link"); got.Kind != KindSymlink || !got.IsSymlink {
		t.Fatalf("link = %+v", got)
	}
	if got := findEntry(t, volume, "/data/alias"); got.Kind != KindHardLink || got.Size != 11 || got.Allocated == nil || *got.Allocated != 11 {
		t.Fatalf("alias = %+v", got)
	}
	deleted := findEntry(t, volume, "/data/old.log")
	if !deleted.Deleted || deleted.Size != 4 || deleted.Allocated != nil {
		t.Fatalf("deleted = %+v", deleted)
	}
	if volume.UnresolvedDeleted() != 1 {
		t.Fatalf("unresolved deleted = %d, want 1", volume.UnresolvedDeleted())
	}
	if _, err := volume.Stat("/orphan.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan was placed at a path: %v", err)
	}
}

func TestFileReadsChunksHardLinkAndShortRead(t *testing.T) {
	volume := openImage(t, sampleImage())
	file, err := volume.OpenFile("/data/notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 11)
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello yaffs" {
		t.Fatalf("file = %q", buf)
	}
	if _, ok := file.(*FileSource); !ok {
		t.Fatalf("file source type %T", file)
	}

	link, err := volume.OpenFile("/data/alias")
	if err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, 11)
	if err := source.ReadExactAt(link, 0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello yaffs" {
		t.Fatalf("hard link = %q", buf)
	}

	n, err := file.ReadAt(6, make([]byte, 64))
	if err != nil {
		t.Fatalf("short read: %v", err)
	}
	if n != 5 {
		t.Fatalf("short read n = %d, want 5", n)
	}
}

func TestSymlinkTargetReadsChunks(t *testing.T) {
	volume := openImage(t, sampleImage())
	target, err := volume.SymlinkTarget("/data/link")
	if err != nil {
		t.Fatal(err)
	}
	if target != "notes.txt" {
		t.Fatalf("target = %q", target)
	}
	if _, err := volume.SymlinkTarget("/data/notes.txt"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("non-symlink error = %v", err)
	}
}

func TestDeletedObjectsExposeNoStream(t *testing.T) {
	volume := openImage(t, sampleImage())
	if _, err := volume.OpenFile("/data/old.log"); !errors.Is(err, ErrDeleted) {
		t.Fatalf("OpenFile(deleted) error = %v", err)
	}
	entries, err := volume.ListDir("/data")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "old.log") || !strings.Contains(joined, "alias") {
		t.Fatalf("ListDir(/data) = %v", names)
	}
	if names[0] != "alias" {
		t.Fatalf("ListDir not sorted: %v", names)
	}
}

func TestRootPathFormsAndErrors(t *testing.T) {
	volume := openImage(t, sampleImage())
	for _, path := range []string{"", "/", "//"} {
		if got, err := volume.Stat(path); err != nil || got.Path != "/" {
			t.Fatalf("Stat(%q) = %+v, %v", path, got, err)
		}
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	if _, err := volume.ListDir("/data/notes.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir(file) error = %v", err)
	}
	if _, err := volume.OpenFile("/data"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile(dir) error = %v", err)
	}
	if _, err := volume.OpenFile("/data/link"); !errors.Is(err, ErrNotFile) {
		t.Fatalf("OpenFile(symlink) error = %v", err)
	}
}

func TestMissingChunkIsAHoleAndShortChunkZeroesTail(t *testing.T) {
	var image []byte
	pushPage(&image, 1, 1, 0, testPage, testHeader(3, 1, "/", 1, 0, 0), false)
	pushPage(&image, 2, 2, 0, testPage, testHeader(3, 1, "lost+found", 2, 0, 0), false)
	pushPage(&image, 3, 10, 0, testPage, testHeader(1, 1, "hole.bin", 3, 4096, 0), false)
	pushPage(&image, 4, 11, 0, testPage, testHeader(1, 1, "short.bin", 4, 4096, 0), false)
	pushPage(&image, 5, 11, 1, 5, dataPage([]byte("hello")), false)
	volume := openImage(t, image)

	hole, err := volume.OpenFile("/hole.bin")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if err := source.ReadExactAt(hole, 0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, make([]byte, 4096)) {
		t.Fatalf("hole did not read zero")
	}
	ranges, err := hole.Extents(100, 3000)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) == 0 {
		t.Fatal("no extents")
	}
	for _, value := range ranges {
		if value.Kind != source.RangeHole {
			t.Fatalf("hole extent kind = %v", value.Kind)
		}
	}

	short, err := volume.OpenFile("/short.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := source.ReadExactAt(short, 0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:5], []byte("hello")) || !bytes.Equal(buf[5:], make([]byte, 4091)) {
		t.Fatalf("short chunk = %q", buf[:20])
	}
	ranges, err = short.Extents(0, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 3 || ranges[0].Kind != source.RangeData || ranges[0].Len != 5 ||
		ranges[1].Kind != source.RangeZero || ranges[1].Len != 2043 ||
		ranges[2].Kind != source.RangeHole || ranges[2].Len != 2048 {
		t.Fatalf("short extents = %+v", ranges)
	}
}

func TestNewerSerialShadowsOlderChunk(t *testing.T) {
	var image []byte
	pushPage(&image, 1, 1, 0, testPage, testHeader(3, 1, "/", 1, 0, 0), false)
	pushPage(&image, 2, 2, 0, testPage, testHeader(3, 1, "lost+found", 2, 0, 0), false)
	pushPage(&image, 3, 10, 0, testPage, testHeader(1, 1, "file", 3, 5, 0), false)
	pushPage(&image, 4, 10, 1, 5, dataPage([]byte("first")), false)
	pushPage(&image, 5, 10, 1, 6, dataPage([]byte("second")), false)
	volume := openImage(t, image)
	file, err := volume.OpenFile("/file")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "secon" {
		t.Fatalf("latest chunk = %q", buf)
	}
}

func TestInvalidTagsAreCountedAndErasedPagesIgnored(t *testing.T) {
	image := sampleImage()
	// One non-erased tag with object zero is not plausible.
	image = append(image, make([]byte, testPage)...)
	image = append(image, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	volume := openImage(t, image)
	if volume.Info().UnreadableTags != 1 {
		t.Fatalf("unreadable tags = %d", volume.Info().UnreadableTags)
	}
}

func TestDetectionRejectsTruncatedImage(t *testing.T) {
	image := sampleImage()
	found, err := Detect(source.NewMemorySource(1, image[:len(image)-1]))
	if err != nil || found {
		t.Fatalf("Detect(truncated) = %v, %v", found, err)
	}
	if _, err := Open(source.NewMemorySource(1, image[:len(image)-1])); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open(truncated) error = %v", err)
	}
}

func TestUnreachableDirectoryCycleTerminates(t *testing.T) {
	var image []byte
	pushPage(&image, 1, 1, 0, testPage, testHeader(3, 1, "/", 1, 0, 0), false)
	pushPage(&image, 2, 2, 0, testPage, testHeader(3, 1, "lost+found", 2, 0, 0), false)
	// Two objects that name each other are not reachable from the root.  The
	// walk must terminate and count them as unresolved rather than recurse.
	pushPage(&image, 3, 10, 0, testPage, testHeader(3, 11, "a", 3, 0, 0), false)
	pushPage(&image, 4, 11, 0, testPage, testHeader(3, 10, "b", 4, 0, 0), false)
	volume := openImage(t, image)
	if _, err := volume.Stat("/a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("/a error = %v", err)
	}
	if volume.UnresolvedDeleted() != 2 {
		t.Fatalf("unresolved = %d, want 2", volume.UnresolvedDeleted())
	}
	if got := volume.Info().Entries; got != 2 {
		t.Fatalf("entries = %d, want root and lost+found", got)
	}
}

func TestFactsAndInfoDescribeGeometry(t *testing.T) {
	volume := openImage(t, sampleImage())
	info := volume.Info()
	if info.PageSize != testPage || info.Stride != testStride || info.TagSize != TagBytes {
		t.Fatalf("info = %+v", info)
	}
	if !info.LostFound {
		t.Fatalf("lost+found not reported")
	}
	facts := map[string]string{}
	for _, pair := range volume.Facts() {
		facts[pair[0]] = pair[1]
	}
	if facts["page_size"] != "2048" || facts["stride"] != "2064" || facts["lost_found"] != "true" {
		t.Fatalf("facts = %v", facts)
	}
}
