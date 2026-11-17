package zfs

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func openTestPool(t *testing.T) *Volume {
	t.Helper()
	img := buildTestImage(t)
	volume, err := Open(source.NewMemorySource(1, img.data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func readAll(t *testing.T, file source.ByteSource) []byte {
	t.Helper()
	if file.Len() == 0 {
		return nil
	}
	buf := make([]byte, file.Len())
	n, err := file.ReadAt(0, buf)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if uint64(n) != file.Len() {
		t.Fatalf("ReadAt returned %d of %d bytes", n, file.Len())
	}
	return buf
}

func mustEntry(t *testing.T, volume *Volume, path string) *Entry {
	t.Helper()
	entry, err := volume.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	return entry
}

func mustFile(t *testing.T, volume *Volume, path string) source.ByteSource {
	t.Helper()
	file, err := volume.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile(%q): %v", path, err)
	}
	return file
}

func TestDetectAndOpen(t *testing.T) {
	img := buildTestImage(t)
	src := source.NewMemorySource(1, img.data)
	detected, err := Detect(src)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !detected {
		t.Fatal("Detect returned false for a ZFS image")
	}
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.KindLabel() != KindLabel {
		t.Fatalf("KindLabel = %q", volume.KindLabel())
	}
	if volume.Source() != src {
		t.Fatal("Source() did not return the opened source")
	}
}

func TestDetectShortAndNonZFS(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", make([]byte, 1024)},
		{"label-sized zeros", make([]byte, LabelSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detected, err := Detect(source.NewMemorySource(1, tc.data))
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if detected {
				t.Fatal("Detect claimed a non-ZFS image")
			}
			if _, err := Open(source.NewMemorySource(1, tc.data)); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Open error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestDetectMagicWithoutValidLabelIsAnError(t *testing.T) {
	data := make([]byte, LabelPhysOffset+LabelPhysSize)
	at := LabelPhysOffset + LabelPhysSize - LabelECKSize
	le.PutUint64(data[at:], ZECMagic)
	detected, err := Detect(source.NewMemorySource(1, data))
	if err == nil {
		t.Fatal("Detect accepted a magic with no verifying label")
	}
	if detected {
		t.Fatal("Detect claimed a pool after refusing it")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Detect error = %v, want ErrCorrupt", err)
	}
}

func TestInfo(t *testing.T) {
	volume := openTestPool(t)
	info := volume.Info()
	if info.Type != KindLabel {
		t.Fatalf("Info.Type = %q", info.Type)
	}
	if info.PoolName != "tank" {
		t.Fatalf("PoolName = %q", info.PoolName)
	}
	if !info.PoolGUIDPresent || info.PoolGUID != 7 {
		t.Fatalf("PoolGUID = %d present %v", info.PoolGUID, info.PoolGUIDPresent)
	}
	if info.TXG != 42 {
		t.Fatalf("TXG = %d", info.TXG)
	}
	if info.UberblockVersion != spaVersion {
		t.Fatalf("UberblockVersion = %d", info.UberblockVersion)
	}
	if info.Labels != 4 {
		t.Fatalf("Labels = %d", info.Labels)
	}
	if info.Datasets != 2 || info.Snapshots != 2 {
		t.Fatalf("datasets %d snapshots %d", info.Datasets, info.Snapshots)
	}
	if info.RootEntries != 21 {
		t.Fatalf("RootEntries = %d", info.RootEntries)
	}
	if info.Ashift != 12 {
		t.Fatalf("Ashift = %d", info.Ashift)
	}
	if len(info.FeaturesForRead) != 1 || info.FeaturesForRead[0] != "org.openzfs:test_feature" {
		t.Fatalf("FeaturesForRead = %v", info.FeaturesForRead)
	}
	if len(volume.Labels()) != 4 {
		t.Fatalf("Labels() = %d", len(volume.Labels()))
	}
	for _, label := range volume.Labels() {
		if label.Verified != "sha256" {
			t.Fatalf("label %d verified by %q", label.Index, label.Verified)
		}
	}
}

func TestRootListing(t *testing.T) {
	volume := openTestPool(t)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 21 {
		t.Fatalf("root has %d entries", len(entries))
	}
	byName := map[string]Entry{}
	for _, entry := range entries {
		byName[entry.Name] = entry
	}
	if entry := byName["hello.txt"]; !entry.IsFile || entry.Path != "/hello.txt" || entry.Object != 10 {
		t.Fatalf("hello entry = %+v", entry)
	}
	if entry := byName["sub"]; !entry.IsDir || entry.Kind != DTypeDirectory {
		t.Fatalf("sub entry = %+v", entry)
	}
	if entry := byName["link"]; !entry.IsSymlink {
		t.Fatalf("link entry = %+v", entry)
	}
	if entry := byName["badbonus"]; !entry.IsFile {
		// The dirent is the fact; unreadable attributes do not erase it.
		t.Fatalf("badbonus entry = %+v", entry)
	}
	if entry := byName["nosize"]; entry.HasSize {
		t.Fatalf("nosize reports a size: %+v", entry)
	}
	empty, err := volume.ListDir("/empty")
	if !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir on a file = %v, want ErrNotDir", err)
	}
	if empty != nil {
		t.Fatalf("ListDir on a file returned entries: %v", empty)
	}
}

func TestStatRootAndFileAttributes(t *testing.T) {
	volume := openTestPool(t)
	root := mustEntry(t, volume, "/")
	if !root.IsDir || root.Kind != DTypeDirectory {
		t.Fatalf("root = %+v", root)
	}
	if !root.HasMode || root.Mode&0o170000 != 0o040000 {
		t.Fatalf("root mode = %o", root.Mode)
	}
	if root.UID != 1000 || root.GID != 1000 {
		t.Fatalf("root owner = %d:%d", root.UID, root.GID)
	}
	if !root.HasMtime || root.Mtime.Unix() != 1_700_000_100 {
		t.Fatalf("root mtime = %v", root.Mtime)
	}

	hello := mustEntry(t, volume, "/hello.txt")
	if !hello.IsFile || hello.Size != 11 || !hello.HasSize {
		t.Fatalf("hello = %+v", hello)
	}
	if hello.Mode != 0o100644 || hello.UID != 1000 || hello.GID != 1000 || hello.Links != 1 {
		t.Fatalf("hello metadata = %+v", hello)
	}
	if !hello.HasAtime || hello.Atime.Unix() != 1_700_000_000 || hello.Atime.Nanosecond() != 123 {
		t.Fatalf("hello atime = %v (has %v)", hello.Atime, hello.HasAtime)
	}
	if !hello.HasBtime || hello.Btime.Unix() != 1_700_000_300 {
		t.Fatalf("hello btime = %v (has %v)", hello.Btime, hello.HasBtime)
	}
	if hello.Deleted {
		t.Fatal("Deleted is true for a live name")
	}
}

func TestStatErrors(t *testing.T) {
	volume := openTestPool(t)
	if _, err := volume.Stat("/does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing path error = %v, want ErrNotFound", err)
	}
	if _, err := volume.Stat("/hello.txt/x"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("traversal through a file = %v, want ErrNotDir", err)
	}
	if _, err := volume.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir(file) = %v, want ErrNotDir", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile(dir) = %v, want ErrIsDir", err)
	}
	if _, err := volume.OpenFile("/link"); !errors.Is(err, ErrNotFile) {
		t.Fatalf("OpenFile(link) = %v, want ErrNotFile", err)
	}
	if _, err := volume.OpenSymlink("/hello.txt"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("OpenSymlink(file) = %v, want ErrNotSymlink", err)
	}
}

func TestReadEmbeddedFile(t *testing.T) {
	volume := openTestPool(t)
	file := mustFile(t, volume, "/hello.txt")
	if file.Len() != 11 {
		t.Fatalf("file length = %d", file.Len())
	}
	if got := readAll(t, file); string(got) != "hello world" {
		t.Fatalf("content = %q", got)
	}
	if file.IsEmpty() {
		t.Fatal("IsEmpty is true for a non-empty file")
	}
	ranges, err := file.Extents(0, 11)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 1 || ranges[0].Kind != source.RangeDerived || ranges[0].Len != 11 {
		t.Fatalf("extents = %+v", ranges)
	}
	mapped, err := file.MapToImage(0, 11)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(mapped) != 1 || mapped[0].Kind != source.RangeDerived || mapped[0].Len != 11 {
		t.Fatalf("image ranges = %+v", mapped)
	}
	if file.Stats().BytesRead != 11 || file.Stats().Reads != 1 {
		t.Fatalf("stats after a read = %+v", file.Stats())
	}
}

func TestReadStoredFileAndImageMapping(t *testing.T) {
	volume := openTestPool(t)
	file := mustFile(t, volume, "/plain")
	got := readAll(t, file)
	if !bytes.HasPrefix(got, []byte("plain fletcher4")) {
		t.Fatalf("content = %q", got[:16])
	}
	ranges, err := file.Extents(0, 512)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 1 || ranges[0].Kind != source.RangeData {
		t.Fatalf("extents = %+v", ranges)
	}
	if ranges[0].ParentOffset < VDevLabelStartSize {
		t.Fatalf("physical %d is inside the label reservation", ranges[0].ParentOffset)
	}
	mapped, err := file.MapToImage(0, 512)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(mapped) != 1 || mapped[0].ImageOffset != ranges[0].ParentOffset {
		t.Fatalf("image ranges = %+v", mapped)
	}
}

func TestNestedPath(t *testing.T) {
	volume := openTestPool(t)
	entry := mustEntry(t, volume, "/sub/nested.txt")
	if entry.Size != 12 || entry.Mode != 0o100600 {
		t.Fatalf("nested entry = %+v", entry)
	}
	if got := readAll(t, mustFile(t, volume, "/sub/nested.txt")); string(got) != "nested bytes" {
		t.Fatalf("content = %q", got)
	}
	if got := readAll(t, mustFile(t, volume, "./sub/../sub/nested.txt")); string(got) != "nested bytes" {
		t.Fatalf("dot/dotdot content = %q", got)
	}
	entries, err := volume.ListDir("/sub")
	if err != nil {
		t.Fatalf("ListDir(/sub): %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "/sub/nested.txt" {
		t.Fatalf("sub entries = %+v", entries)
	}
	// A directory's self-reference is a finite path, never an infinite walk.
	if _, err := volume.Stat("/self/self/self"); err != nil {
		t.Fatalf("self-reference path: %v", err)
	}
}

func TestSymlink(t *testing.T) {
	volume := openTestPool(t)
	entry := mustEntry(t, volume, "/link")
	if !entry.IsSymlink || entry.SymlinkTarget != "/hello.txt" {
		t.Fatalf("link = %+v", entry)
	}
	if entry.Size != 10 {
		t.Fatalf("link size = %d", entry.Size)
	}
	target, err := volume.SymlinkTarget("/link")
	if err != nil {
		t.Fatalf("SymlinkTarget: %v", err)
	}
	if target != "/hello.txt" {
		t.Fatalf("target = %q", target)
	}
	file, err := volume.OpenSymlink("/link")
	if err != nil {
		t.Fatalf("OpenSymlink: %v", err)
	}
	if got := readAll(t, file); string(got) != "/hello.txt" {
		t.Fatalf("target bytes = %q", got)
	}
}

func TestHolesAndSparseRanges(t *testing.T) {
	volume := openTestPool(t)
	entry := mustEntry(t, volume, "/holey")
	if entry.Size != 1029 {
		t.Fatalf("size = %d", entry.Size)
	}
	file := mustFile(t, volume, "/holey")
	buf := make([]byte, 1029)
	n, err := file.ReadAt(0, buf)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != 1029 {
		t.Fatalf("read %d bytes", n)
	}
	if string(buf[:5]) != "first" {
		t.Fatalf("block 0 = %q", buf[:5])
	}
	for i := 5; i < 1024; i++ {
		if buf[i] != 0 {
			t.Fatalf("byte %d is %#x, want zero", i, buf[i])
		}
	}
	if string(buf[1024:]) != "third" {
		t.Fatalf("block 2 = %q", buf[1024:])
	}
	ranges, err := file.Extents(0, 1029)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 3 {
		t.Fatalf("extents = %+v", ranges)
	}
	if ranges[0].Kind != source.RangeDerived || ranges[0].Len != 512 {
		t.Fatalf("first range = %+v", ranges[0])
	}
	if ranges[1].Kind != source.RangeHole || ranges[1].Len != 512 {
		t.Fatalf("hole range = %+v", ranges[1])
	}
	if ranges[2].Kind != source.RangeDerived || ranges[2].Len != 5 {
		t.Fatalf("third range = %+v", ranges[2])
	}
	// A partial read inside the hole sees zeroes, never stored bytes.
	part := make([]byte, 10)
	if _, err := file.ReadAt(510, part); err != nil {
		t.Fatalf("ReadAt hole: %v", err)
	}
	for i, b := range part {
		if b != 0 {
			t.Fatalf("hole byte %d = %#x", i, b)
		}
	}
	if _, err := file.ReadAt(1029, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past EOF = %v", err)
	}
}

func TestEmptyFile(t *testing.T) {
	volume := openTestPool(t)
	entry := mustEntry(t, volume, "/empty")
	if entry.Size != 0 || !entry.HasSize {
		t.Fatalf("empty entry = %+v", entry)
	}
	file := mustFile(t, volume, "/empty")
	if !file.IsEmpty() || file.Len() != 0 {
		t.Fatalf("empty file len = %d", file.Len())
	}
	if _, err := file.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt on empty file = %v, want ErrOutOfRange", err)
	}
	ranges, err := file.Extents(0, 0)
	if err != nil || len(ranges) != 0 {
		t.Fatalf("empty extents = %+v, %v", ranges, err)
	}
}

func TestCompressionCodecs(t *testing.T) {
	volume := openTestPool(t)
	cases := []struct {
		path    string
		size    int
		prefix  string
		allZero bool
	}{
		{"/lzjb", 512, "lzjb content", false},
		{"/zle", 512, "ZLE!", false},
		{"/lz4", 512, "AAAA", false},
		{"/gzip", 512, "gzip content", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			file := mustFile(t, volume, tc.path)
			got := readAll(t, file)
			if len(got) != tc.size {
				t.Fatalf("decoded %d bytes, want %d", len(got), tc.size)
			}
			if !strings.HasPrefix(string(got), tc.prefix) {
				t.Fatalf("content starts %q", got[:minInt(16, len(got))])
			}
		})
	}
}

func TestZstdRefusedByName(t *testing.T) {
	volume := openTestPool(t)
	file := mustFile(t, volume, "/zstd")
	_, err := file.ReadAt(0, make([]byte, 512))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("zstd read = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "zstd") {
		t.Fatalf("refusal does not name zstd: %v", err)
	}
}

func TestChecksumVariants(t *testing.T) {
	volume := openTestPool(t)
	for _, path := range []string{"/plain", "/sha", "/f2"} {
		t.Run(path, func(t *testing.T) {
			got := readAll(t, mustFile(t, volume, path))
			if len(got) != 512 || allZero(got) {
				t.Fatalf("%s read %d zero=%v bytes", path, len(got), allZero(got))
			}
		})
	}
	if got := readAll(t, mustFile(t, volume, "/sha")); !bytes.HasPrefix(got, []byte("sha256 checked")) {
		t.Fatalf("sha content = %q", got[:16])
	}
	if got := readAll(t, mustFile(t, volume, "/f2")); !bytes.HasPrefix(got, []byte("fletcher2")) {
		t.Fatalf("fletcher2 content = %q", got[:16])
	}
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func TestIndirectTree(t *testing.T) {
	volume := openTestPool(t)
	file := mustFile(t, volume, "/indirect")
	if file.Len() != 3*512 {
		t.Fatalf("length = %d", file.Len())
	}
	for index, want := range []string{"block0", "block1", "block2"} {
		buf := make([]byte, len(want))
		if _, err := file.ReadAt(uint64(index*512), buf); err != nil {
			t.Fatalf("ReadAt block %d: %v", index, err)
		}
		if string(buf) != want {
			t.Fatalf("block %d = %q", index, buf)
		}
	}
}

func TestRefusedAndCorruptBlocks(t *testing.T) {
	volume := openTestPool(t)
	cases := []struct {
		path string
		want error
		text string
	}{
		{"/gang", source.ErrUnsupported, "gang"},
		{"/badck", source.ErrCorrupt, "checksum"},
		{"/badcompress", source.ErrUnsupported, "99"},
		{"/unknownck", source.ErrUnsupported, "12"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			file := mustFile(t, volume, tc.path)
			_, err := file.ReadAt(0, make([]byte, 512))
			if !errors.Is(err, tc.want) {
				t.Fatalf("read error = %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("error does not mention %q: %v", tc.text, err)
			}
		})
	}
}

func TestNoSizeAttributeIsRefused(t *testing.T) {
	volume := openTestPool(t)
	entry := mustEntry(t, volume, "/nosize")
	if entry.HasSize {
		t.Fatalf("nosize has a size: %+v", entry)
	}
	if _, err := volume.OpenFile("/nosize"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("OpenFile(nosize) = %v, want ErrCorrupt", err)
	}
}

func TestUnsupportedBonusTypeIsRefused(t *testing.T) {
	volume := openTestPool(t)
	if _, err := volume.Stat("/badbonus"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Stat(badbonus) = %v, want ErrUnsupported", err)
	}
}

func TestDatasets(t *testing.T) {
	volume := openTestPool(t)
	datasets := volume.Datasets()
	if len(datasets) != 2 {
		t.Fatalf("datasets = %+v", datasets)
	}
	if datasets[0].Name != "tank" || datasets[0].GUID != 111 || datasets[0].CreationTXG != 10 {
		t.Fatalf("root dataset = %+v", datasets[0])
	}
	if datasets[1].Name != "tank/child" || datasets[1].GUID != 222 {
		t.Fatalf("child dataset = %+v", datasets[1])
	}
	if !hasWarning(volume.Warnings(), "named twice") {
		t.Fatalf("dataset cycle warning missing: %v", volume.Warnings())
	}

	child, err := volume.OpenDataset("tank/child")
	if err != nil {
		t.Fatalf("OpenDataset: %v", err)
	}
	entry, err := child.Stat("child.txt")
	if err != nil {
		t.Fatalf("child Stat: %v", err)
	}
	if entry.Size != 10 || entry.UID != 1000 {
		t.Fatalf("child.txt = %+v", entry)
	}
	if got := readAll(t, mustViewFile(t, child, "child.txt")); string(got) != "child data" {
		t.Fatalf("child content = %q", got)
	}
	if _, err := volume.OpenDataset("tank/missing"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing dataset = %v, want ErrCorrupt", err)
	} else if !strings.Contains(err.Error(), "tank") {
		t.Fatalf("refusal does not quote the datasets: %v", err)
	}
}

func mustViewFile(t *testing.T, view interface {
	OpenFile(string) (source.ByteSource, error)
}, path string) source.ByteSource {
	t.Helper()
	file, err := view.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile(%q): %v", path, err)
	}
	return file
}

func hasWarning(warnings []string, text string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, text) {
			return true
		}
	}
	return false
}

func TestSnapshots(t *testing.T) {
	volume := openTestPool(t)
	snapshots := volume.Snapshots()
	if len(snapshots) != 2 {
		t.Fatalf("snapshots = %+v", snapshots)
	}
	names := []string{snapshots[0].Name, snapshots[1].Name}
	if names[0] != "tank@snap1" || names[1] != "tank/child@snap1" {
		t.Fatalf("snapshot names = %v", names)
	}
	for _, snapshot := range snapshots {
		if !snapshot.IsResolved() {
			t.Fatalf("snapshot %s is unresolved: %s", snapshot.Name, snapshot.UnresolvedReason)
		}
		if snapshot.CreationTXG != 11 || !snapshot.HasBP {
			t.Fatalf("snapshot = %+v", snapshot)
		}
	}
	if _, err := volume.OpenSnapshot("snap1"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ambiguous short name = %v, want ErrCorrupt", err)
	} else if !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguity refusal = %v", err)
	}
	mounted, err := volume.OpenSnapshot("tank@snap1")
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	if mounted.Snapshot().Name != "tank@snap1" || mounted.MountedTXG() != 42 {
		t.Fatalf("mounted = %+v", mounted.Snapshot())
	}
	entry, err := mounted.Stat("old.txt")
	if err != nil {
		t.Fatalf("snapshot Stat: %v", err)
	}
	if entry.Size != 12 {
		t.Fatalf("old.txt = %+v", entry)
	}
	if got := readAll(t, mustViewFile(t, mounted, "old.txt")); string(got) != "old contents" {
		t.Fatalf("snapshot content = %q", got)
	}
}

func TestDatasetMountpoint(t *testing.T) {
	volume := openTestPool(t)
	root, err := volume.DatasetMountpoint("tank")
	if err != nil {
		t.Fatalf("mountpoint root: %v", err)
	}
	if root == nil || *root != "/tank" {
		t.Fatalf("root mountpoint = %v", root)
	}
	child, err := volume.DatasetMountpoint("tank/child")
	if err != nil {
		t.Fatalf("mountpoint child: %v", err)
	}
	if child == nil || *child != "/tank" {
		t.Fatalf("child mountpoint = %v", child)
	}
}

func TestLabelChecksumVariants(t *testing.T) {
	img := buildTestImage(t)
	// Rewrite every label's checksum as fletcher4 and reopen.
	for _, label := range labelOffsets(uint64(len(img.data))) {
		eck := label.offset + LabelPhysOffset + LabelPhysSize - LabelECKSize
		buffer := append([]byte(nil), img.data[label.offset+LabelPhysOffset:label.offset+LabelPhysOffset+LabelPhysSize]...)
		verifier := make([]byte, 32)
		le.PutUint64(verifier, label.offset+LabelPhysOffset)
		copy(buffer[LabelPhysSize-LabelECKSize+8:], verifier)
		words := fletcher4(buffer)
		for i, word := range words {
			le.PutUint64(img.data[eck+8+uint64(i)*8:], word)
		}
	}
	volume, err := Open(source.NewMemorySource(1, img.data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, label := range volume.Labels() {
		if label.Verified != "fletcher4" {
			t.Fatalf("label %d verified by %q", label.Index, label.Verified)
		}
	}
}

func TestOneCorruptLabelStillOpens(t *testing.T) {
	img := buildTestImage(t)
	offsets := labelOffsets(uint64(len(img.data)))
	img.corruptLabelChecksum(offsets[1].offset)
	volume, err := Open(source.NewMemorySource(1, img.data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !hasWarning(volume.Warnings(), "label 1") {
		t.Fatalf("missing label warning: %v", volume.Warnings())
	}
}

func TestAllLabelsCorruptIsRefused(t *testing.T) {
	img := buildTestImage(t)
	for _, offset := range labelOffsets(uint64(len(img.data))) {
		img.corruptLabelChecksum(offset.offset)
	}
	_, err := Open(source.NewMemorySource(1, img.data))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open = %v, want ErrCorrupt", err)
	}
}

func TestTruncatedImageIsRefused(t *testing.T) {
	img := buildTestImage(t)
	src := source.NewMemorySource(1, img.data[:64<<10])
	detected, err := Detect(src)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if detected {
		t.Fatal("Detect claimed a truncated image")
	}
	if _, err := Open(src); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open = %v, want ErrCorrupt", err)
	}
}

func TestBrokenRootPointerIsRefused(t *testing.T) {
	img := buildTestImage(t)
	// Damage the root block pointer's checksum in every label's first slot.
	for _, label := range labelOffsets(uint64(len(img.data))) {
		ring := label.offset + LabelPhysOffset + LabelPhysSize
		le.PutUint64(img.data[ring+40+96:], 0)
		le.PutUint64(img.data[ring+40+104:], 0)
		le.PutUint64(img.data[ring+40+112:], 0)
		le.PutUint64(img.data[ring+40+120:], 0)
	}
	_, err := Open(source.NewMemorySource(1, img.data))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open = %v, want ErrCorrupt", err)
	}
}

func TestConcurrentReads(t *testing.T) {
	volume := openTestPool(t)
	const workers = 8
	const iterations = 25
	var wait sync.WaitGroup
	errs := make(chan error, workers*iterations)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < iterations; i++ {
				file, err := volume.OpenFile("/hello.txt")
				if err != nil {
					errs <- err
					return
				}
				buf := make([]byte, 11)
				if _, err := file.ReadAt(0, buf); err != nil {
					errs <- err
					return
				}
				if string(buf) != "hello world" {
					errs <- io.ErrUnexpectedEOF
					return
				}
				if _, err := volume.Stat("/sub/nested.txt"); err != nil {
					errs <- err
					return
				}
				if _, err := volume.ListDir("/"); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent access: %v", err)
	}
}
