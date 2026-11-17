package qnx6

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func fixtureSource(t *testing.T, opts fixtureOptions) (*Volume, source.ByteSource, []byte) {
	t.Helper()
	image := buildImage(opts)
	src := source.NewMemorySource(source.ID(7), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume, src, image
}

func TestCRC32AndNameChecksum(t *testing.T) {
	if got := CRC32BE(nil); got != 0 {
		t.Fatalf("CRC32BE(empty) = 0x%08x", got)
	}
	if got := CRC32BE([]byte("a")); got != 0xa864db20 {
		t.Fatalf("CRC32BE(a) = 0x%08x", got)
	}
	if got := NameChecksum([]byte("ab")); got != 0x80000092 {
		t.Fatalf("NameChecksum(ab) = 0x%08x", got)
	}
}

func TestDetectAndOpen(t *testing.T) {
	for _, order := range []ByteOrder{Little, Big} {
		image := buildImage(fixtureOptions{order: order, layout: LayoutStandard, serial: 100, backupSerial: 90})
		src := source.NewMemorySource(source.ID(1), image)
		detected, err := Detect(src)
		if err != nil {
			t.Fatalf("%v Detect: %v", order.Label(), err)
		}
		if !detected {
			t.Fatalf("%v Detect = false", order.Label())
		}
		volume, err := Open(src)
		if err != nil {
			t.Fatalf("%v Open: %v", order.Label(), err)
		}
		if volume.KindLabel() != KindLabel {
			t.Fatalf("KindLabel = %q", volume.KindLabel())
		}
		if volume.Source() != src {
			t.Fatal("Source did not return the opened source")
		}
		info := volume.Info()
		if info.Type != KindLabel || info.ByteOrder != order.Label() {
			t.Fatalf("Info = %+v", info)
		}
		if info.BlockSize != testBlockSize || info.Blocks != testNumBlocks || info.Inodes != testNumInodes {
			t.Fatalf("geometry = %+v", info)
		}
		if info.Layout != LayoutStandard.Label() {
			t.Fatalf("layout = %q", info.Layout)
		}
		if info.Serial != 100 {
			t.Fatalf("serial = %d", info.Serial)
		}
		if info.VolumeID != "qnx6test" {
			t.Fatalf("volume id = %q", info.VolumeID)
		}
		if info.SuperblockOffset != PrimaryOffset {
			t.Fatalf("superblock offset = %d", info.SuperblockOffset)
		}
		if info.SuperblockCopies != 2 {
			t.Fatalf("valid copies = %d", info.SuperblockCopies)
		}
	}
}

func TestRootListing(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir(/): %v", err)
	}
	if len(entries) != 8 {
		t.Fatalf("root has %d entries, want 8: %+v", len(entries), entries)
	}
	for _, name := range []string{helloName, subName, longName, linkName, multiName, treeName, emptyName, hardName} {
		if !containsName(entries, name) {
			t.Fatalf("root listing is missing %q: %+v", name, entries)
		}
	}
	for _, name := range []string{".", "..", "gone.txt", "ghost", "ignored"} {
		if containsName(entries, name) {
			t.Fatalf("root listing unexpectedly contains %q", name)
		}
	}
	info := volume.Info()
	if info.Entries != 12 || info.Directories != 3 || info.Files != 8 || info.Symlinks != 1 {
		t.Fatalf("counts = entries %d dirs %d files %d symlinks %d",
			info.Entries, info.Directories, info.Files, info.Symlinks)
	}
}

func TestNestedDirectories(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	sub, err := volume.ListDir("/sub")
	if err != nil {
		t.Fatalf("ListDir(/sub): %v", err)
	}
	if len(sub) != 2 || !containsName(sub, nestedName) || !containsName(sub, "subsub") {
		t.Fatalf("sub listing = %+v", sub)
	}
	deep, err := volume.ListDir("/sub/subsub")
	if err != nil {
		t.Fatalf("ListDir(/sub/subsub): %v", err)
	}
	if len(deep) != 1 || deep[0].Name != leafName {
		t.Fatalf("subsub listing = %+v", deep)
	}
	entry, err := volume.Stat("/sub/subsub/leaf.txt")
	if err != nil {
		t.Fatalf("Stat leaf: %v", err)
	}
	if !entry.IsFile || entry.Size != uint64(len(leafData)) {
		t.Fatalf("leaf entry = %+v", entry)
	}
	if entry.Path != "/sub/subsub/leaf.txt" {
		t.Fatalf("leaf path = %q", entry.Path)
	}
	if entry.ParentRecord == nil || *entry.ParentRecord == 0 {
		t.Fatalf("leaf parent = %v", entry.ParentRecord)
	}
	// ".." resolves back to the parent directory.
	parent, err := volume.Stat("/sub/subsub/..")
	if err != nil {
		t.Fatalf("Stat ..: %v", err)
	}
	if parent.Path != "/sub" {
		t.Fatalf(".. resolved to %q", parent.Path)
	}
}

func TestLongName(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	entry, err := volume.Stat("/" + longName)
	if err != nil {
		t.Fatalf("Stat long name: %v", err)
	}
	if entry.Name != longName || !entry.IsFile || entry.Size != uint64(len(longData)) {
		t.Fatalf("long entry = %+v", entry)
	}
	file, err := volume.OpenFile("/" + longName)
	if err != nil {
		t.Fatalf("OpenFile long name: %v", err)
	}
	data, err := source.ReadVecAt(file, 0, file.Len())
	if err != nil {
		t.Fatalf("read long name: %v", err)
	}
	if !bytes.Equal(data, longData) {
		t.Fatalf("long data = %q", data)
	}
}

func TestStatMetadata(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat(/): %v", err)
	}
	if root.Name != "/" || root.Path != "/" || root.ParentRecord != nil || !root.IsDir {
		t.Fatalf("root entry = %+v", root)
	}
	if root.Inode != RootInode {
		t.Fatalf("root inode = %d", root.Inode)
	}
	entry, err := volume.Stat("/" + helloName)
	if err != nil {
		t.Fatalf("Stat hello: %v", err)
	}
	if entry.Kind != KindFile || entry.FileType != "file" || !entry.IsFile {
		t.Fatalf("kind = %v / %q", entry.Kind, entry.FileType)
	}
	if entry.Mode != 0x81a4 || entry.UID != 1000 || entry.GID != 1000 {
		t.Fatalf("metadata = mode 0x%04x uid %d gid %d", entry.Mode, entry.UID, entry.GID)
	}
	if entry.Size != uint64(len(helloData)) {
		t.Fatalf("size = %d", entry.Size)
	}
	if entry.Allocated == nil || *entry.Allocated != testBlockSize {
		t.Fatalf("allocated = %v", entry.Allocated)
	}
	if entry.Created == nil || *entry.Created != 1_600_000_100 ||
		entry.Modified == nil || *entry.Modified != 1_600_000_200 ||
		entry.Accessed == nil || *entry.Accessed != 1_600_000_300 ||
		entry.Changed == nil || *entry.Changed != 1_600_000_400 {
		t.Fatalf("times = %v %v %v %v", entry.Created, entry.Modified, entry.Accessed, entry.Changed)
	}
	if entry.Inode != uint64(inoHello) {
		t.Fatalf("inode = %d", entry.Inode)
	}
	if entry.ParentRecord == nil || *entry.ParentRecord != RootRecord {
		t.Fatalf("parent = %v", entry.ParentRecord)
	}
	if entry.Deleted {
		t.Fatal("live entry reported Deleted")
	}
}

func TestFileReadAcrossBlocks(t *testing.T) {
	volume, src, _ := fixtureSource(t, defaultOptions())
	file, err := volume.OpenFile("/" + multiName)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != uint64(len(multiData)) {
		t.Fatalf("len = %d", file.Len())
	}
	data, err := source.ReadVecAt(file, 0, file.Len())
	if err != nil {
		t.Fatalf("ReadVecAt: %v", err)
	}
	if !bytes.Equal(data, multiData) {
		t.Fatal("file contents differ from the fixture")
	}
	crossing := make([]byte, 20)
	got, err := file.ReadAt(testBlockSize-6, crossing)
	if err != nil {
		t.Fatalf("cross-block ReadAt: %v", err)
	}
	if got != len(crossing) || !bytes.Equal(crossing, multiData[testBlockSize-6:testBlockSize+14]) {
		t.Fatalf("cross-block bytes = %x", crossing)
	}
	if _, err := file.ReadAt(file.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past EOF = %v", err)
	}
	if file.SourceID() <= src.SourceID() {
		t.Fatalf("file source id %d did not descend from %d", file.SourceID(), src.SourceID())
	}
	if file.ImageID() != src.ImageID() || file.SectorSize() != src.SectorSize() {
		t.Fatal("file source did not inherit image geometry")
	}
	runs := file.(*FileSource).Runs()
	if len(runs) != 1 || runs[0].Len != 2*testBlockSize {
		t.Fatalf("runs = %+v", runs)
	}
	if file.(*FileSource).AllocatedBytes() != 2*testBlockSize {
		t.Fatalf("allocated = %d", file.(*FileSource).AllocatedBytes())
	}
	ranges, err := file.Extents(0, file.Len())
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 1 || ranges[0].Kind != source.RangeData || ranges[0].Len != uint64(len(multiData)) {
		t.Fatalf("ranges = %+v", ranges)
	}
	imageRanges, err := file.MapToImage(0, 100)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(imageRanges) != 1 || imageRanges[0].Len != 100 {
		t.Fatalf("image ranges = %+v", imageRanges)
	}
	lossy, err := file.ReadAtLossy(0, make([]byte, 16))
	if err != nil || lossy != 16 || !bytes.Equal(mustRead(t, file, 0, 16), multiData[:16]) {
		t.Fatalf("ReadAtLossy = %d, %v", lossy, err)
	}
}

func mustRead(t *testing.T, file source.ByteSource, offset, length uint64) []byte {
	t.Helper()
	data, err := source.ReadVecAt(file, offset, length)
	if err != nil {
		t.Fatalf("read [%d,%d): %v", offset, length, err)
	}
	return data
}

func TestDepthOnePointerTree(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	file, err := volume.OpenFile("/" + treeName)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	data, err := source.ReadVecAt(file, 0, file.Len())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	expected := make([]byte, testBlockSize)
	for index := range expected {
		expected[index] = byte(0x40 + index%60)
	}
	if !bytes.Equal(data, expected) {
		t.Fatal("pointer-tree file contents differ")
	}
	value := file.(*FileSource)
	if value.ExtentBlocksRead() != 1 {
		t.Fatalf("pointer blocks read = %d, want 1", value.ExtentBlocksRead())
	}
	if value.ExtentRecords() < 2 {
		t.Fatalf("pointer records = %d, want at least 2", value.ExtentRecords())
	}
	physical, err := value.PhysicalBlockAt(0)
	if err != nil {
		t.Fatalf("PhysicalBlockAt: %v", err)
	}
	if physical != blockTreeData+3 {
		t.Fatalf("physical block = %d", physical)
	}
}

func TestSymlink(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	entry, err := volume.Stat("/" + linkName)
	if err != nil {
		t.Fatalf("Stat link: %v", err)
	}
	if !entry.IsSymlink || entry.FileType != "symlink" {
		t.Fatalf("link kind = %+v", entry)
	}
	if entry.SymlinkTarget != symlinkTarget || !entry.HasSymlinkTarget {
		t.Fatalf("inline target = %q (%v)", entry.SymlinkTarget, entry.HasSymlinkTarget)
	}
	target, err := volume.SymlinkTarget("/" + linkName)
	if err != nil || target != symlinkTarget {
		t.Fatalf("SymlinkTarget = %q, %v", target, err)
	}
	stream, err := volume.OpenSymlink("/" + linkName)
	if err != nil {
		t.Fatalf("OpenSymlink: %v", err)
	}
	data, err := source.ReadVecAt(stream, 0, stream.Len())
	if err != nil {
		t.Fatalf("read link: %v", err)
	}
	if string(data) != symlinkTarget {
		t.Fatalf("link stream = %q", data)
	}
	if _, err := volume.OpenFile("/" + linkName); !errors.Is(err, ErrNotFile) {
		t.Fatalf("OpenFile(symlink) = %v", err)
	}
	if _, err := volume.OpenSymlink("/" + helloName); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("OpenSymlink(file) = %v", err)
	}
}

func TestHardlink(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	first, err := volume.Stat("/" + helloName)
	if err != nil {
		t.Fatalf("Stat hello: %v", err)
	}
	second, err := volume.Stat("/" + hardName)
	if err != nil {
		t.Fatalf("Stat hardlink: %v", err)
	}
	if first.Inode != second.Inode || first.Inode != uint64(inoHello) {
		t.Fatalf("hardlink inodes = %d and %d", first.Inode, second.Inode)
	}
	if first.Record == second.Record {
		t.Fatal("hardlink names produced one node")
	}
	one, err := volume.OpenFile("/" + helloName)
	if err != nil {
		t.Fatalf("OpenFile hello: %v", err)
	}
	two, err := volume.OpenFile("/" + hardName)
	if err != nil {
		t.Fatalf("OpenFile hardlink: %v", err)
	}
	if !bytes.Equal(mustRead(t, one, 0, one.Len()), mustRead(t, two, 0, two.Len())) {
		t.Fatal("hardlinked names read different bytes")
	}
}

func TestEmptyFile(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	entry, err := volume.Stat("/" + emptyName)
	if err != nil {
		t.Fatalf("Stat empty: %v", err)
	}
	if entry.Size != 0 || entry.Allocated == nil || *entry.Allocated != 0 {
		t.Fatalf("empty entry = %+v", entry)
	}
	file, err := volume.OpenFile("/" + emptyName)
	if err != nil {
		t.Fatalf("OpenFile empty: %v", err)
	}
	if file.Len() != 0 || !file.IsEmpty() {
		t.Fatalf("empty len = %d", file.Len())
	}
	if got, err := file.ReadAt(0, nil); got != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", got, err)
	}
	if _, err := file.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("empty non-empty read = %v", err)
	}
}

func TestPathErrors(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	if _, err := volume.Stat("/does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Stat = %v", err)
	}
	if _, err := volume.ListDir("/" + helloName); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir(file) = %v", err)
	}
	if _, err := volume.OpenFile("/" + subName); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile(dir) = %v", err)
	}
	if _, err := volume.SymlinkTarget("/" + helloName); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("SymlinkTarget(file) = %v", err)
	}
}

func TestBigEndian(t *testing.T) {
	volume, _, _ := fixtureSource(t, fixtureOptions{order: Big, layout: LayoutStandard, serial: 100, backupSerial: 90})
	if got := volume.Info().ByteOrder; got != "big" {
		t.Fatalf("byte order = %q", got)
	}
	file, err := volume.OpenFile("/" + helloName)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if !bytes.Equal(mustRead(t, file, 0, file.Len()), helloData) {
		t.Fatal("big-endian file contents differ")
	}
}

func TestMMILayout(t *testing.T) {
	volume, src, _ := fixtureSource(t, fixtureOptions{order: Little, layout: LayoutMMI, serial: 7, backupSerial: 6})
	detected, err := Detect(src)
	if err != nil || !detected {
		t.Fatalf("Detect = %v, %v", detected, err)
	}
	info := volume.Info()
	if info.Layout != "mmi" {
		t.Fatalf("layout = %q", info.Layout)
	}
	if info.SuperblockOffset != AlternateOffset {
		t.Fatalf("superblock offset = %d", info.SuperblockOffset)
	}
	if info.FSBlockOffset != 1 {
		t.Fatalf("fs block offset = %d", info.FSBlockOffset)
	}
	if info.VolumeID != "" || info.SuperblockCreated != 0 || info.SuperblockAccessed != 0 {
		t.Fatalf("MMI fabricated fields: %+v", info)
	}
	if info.Serial != 7 {
		t.Fatalf("serial = %d", info.Serial)
	}
	file, err := volume.OpenFile("/" + helloName)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if !bytes.Equal(mustRead(t, file, 0, file.Len()), helloData) {
		t.Fatal("MMI file contents differ")
	}
}

func TestNewerBackupCopyBecomesActive(t *testing.T) {
	volume, _, _ := fixtureSource(t, fixtureOptions{order: Little, layout: LayoutStandard, serial: 100, backupSerial: 200})
	info := volume.Info()
	if info.Serial != 200 {
		t.Fatalf("serial = %d, want the newer backup's 200", info.Serial)
	}
	if info.SuperblockOffset != uint64(backupOffsetFor(LayoutStandard)) {
		t.Fatalf("active offset = %d", info.SuperblockOffset)
	}
	if info.SuperblockCopies != 2 {
		t.Fatalf("valid copies = %d", info.SuperblockCopies)
	}
}

func TestDeletedInodeRefused(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	if volume.Refusals() == 0 || volume.Undecodable() == 0 {
		t.Fatalf("deleted inode was not classified: %+v", volume.Stats())
	}
	if !warningsContain(volume.Warnings(), "deleted") {
		t.Fatalf("no warning names the deleted inode: %v", volume.Warnings())
	}
	if _, err := volume.Stat("/gone.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted name resolved: %v", err)
	}
}

func TestBadChecksum(t *testing.T) {
	image := buildImage(defaultOptions())
	offset := primaryOffsetFor(LayoutStandard)
	image[offset+0x100] ^= 0xff
	src := source.NewMemorySource(source.ID(1), image)
	detected, err := Detect(src)
	if err == nil {
		t.Fatal("Detect accepted a bad checksum")
	}
	if detected {
		t.Fatal("Detect reported true with an error")
	}
	if !errors.Is(err, source.ErrCorrupt) || !bytes.Contains([]byte(err.Error()), []byte("checksum")) {
		t.Fatalf("Detect error = %v", err)
	}
	if _, err := Open(src); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v", err)
	}
}

func TestNoMagic(t *testing.T) {
	src := source.NewMemorySource(source.ID(1), make([]byte, 68*testBlockSize))
	detected, err := Detect(src)
	if err != nil || detected {
		t.Fatalf("Detect = %v, %v", detected, err)
	}
	_, err = Open(src)
	if !errors.Is(err, source.ErrCorrupt) || !bytes.Contains([]byte(err.Error()), []byte("no QNX6 superblock magic")) {
		t.Fatalf("Open error = %v", err)
	}
}

func TestInvalidBlockSize(t *testing.T) {
	image := buildImage(defaultOptions())
	offset := primaryOffsetFor(LayoutStandard)
	putU32(Little, image, offset+blockSizeAt, 1234)
	refreshChecksum(image, offset, Little)
	src := source.NewMemorySource(source.ID(1), image)
	detected, err := Detect(src)
	if detected || err == nil {
		t.Fatalf("Detect = %v, %v", detected, err)
	}
	if !errors.Is(err, source.ErrUnsupported) || !bytes.Contains([]byte(err.Error()), []byte("block size")) {
		t.Fatalf("error = %v", err)
	}
}

func TestTruncatedSuperblock(t *testing.T) {
	image := buildImage(defaultOptions())
	truncated := image[:int(PrimaryOffset)+256]
	src := source.NewMemorySource(source.ID(1), truncated)
	detected, err := Detect(src)
	if detected || err == nil {
		t.Fatalf("Detect = %v, %v", detected, err)
	}
	if !errors.Is(err, source.ErrCorrupt) || !bytes.Contains([]byte(err.Error()), []byte("shorter")) {
		t.Fatalf("error = %v", err)
	}
}

func TestInodePointerOutOfRange(t *testing.T) {
	image := buildImage(defaultOptions())
	at := inodeOffset(LayoutStandard, inoHello)
	putU32(Little, image, at+0x24, testNumBlocks)
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Undecodable() == 0 || !warningsContain(volume.Warnings(), "out of range") {
		t.Fatalf("bad pointer not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
	if _, err := volume.OpenFile("/" + helloName); !errors.Is(err, source.ErrCorrupt) ||
		!bytes.Contains([]byte(err.Error()), []byte("out of range")) {
		t.Fatalf("OpenFile error = %v", err)
	}
}

func TestHoleRefused(t *testing.T) {
	image := buildImage(defaultOptions())
	at := inodeOffset(LayoutStandard, inoMulti)
	putU32(Little, image, at+0x24, Unused)
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Undecodable() == 0 || !warningsContain(volume.Warnings(), "hole") {
		t.Fatalf("hole not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
	if _, err := volume.OpenFile("/" + multiName); !errors.Is(err, source.ErrCorrupt) ||
		!bytes.Contains([]byte(err.Error()), []byte("hole")) {
		t.Fatalf("OpenFile error = %v", err)
	}
}

func TestUnsupportedPointerDepth(t *testing.T) {
	image := buildImage(defaultOptions())
	offset := primaryOffsetFor(LayoutStandard)
	image[offset+inodeRootAt+0x48] = 6
	refreshChecksum(image, offset, Little)
	src := source.NewMemorySource(source.ID(1), image)
	detected, err := Detect(src)
	if detected || err == nil {
		t.Fatalf("Detect = %v, %v", detected, err)
	}
	if !errors.Is(err, source.ErrUnsupported) || !bytes.Contains([]byte(err.Error()), []byte("depth")) {
		t.Fatalf("error = %v", err)
	}
	if _, err := Open(src); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open error = %v", err)
	}
}

func TestMalformedDirectorySlot(t *testing.T) {
	image := buildImage(defaultOptions())
	at := dataOffset(LayoutStandard, blockRootDir) + 2*DirEntrySize + 4
	image[at] = 40 // longer than ShortNameMax and not the long marker
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Unreadable() == 0 || !warningsContain(volume.Warnings(), "name length") {
		t.Fatalf("malformed slot not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
	if _, err := volume.ListDir("/"); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("name length")) {
		t.Fatalf("ListDir error = %v", err)
	}
}

func TestInvalidShortNameBytes(t *testing.T) {
	cases := []struct {
		name   string
		value  byte
		detail string
	}{
		{"slash", '/', "slash"},
		{"nul", 0, "NUL"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			image := buildImage(defaultOptions())
			at := dataOffset(LayoutStandard, blockRootDir) + 2*DirEntrySize + 5
			image[at] = test.value
			src := source.NewMemorySource(source.ID(1), image)
			volume, err := Open(src)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if volume.Unreadable() == 0 || !warningsContain(volume.Warnings(), test.detail) {
				t.Fatalf("invalid name not classified: %+v / %v", volume.Stats(), volume.Warnings())
			}
		})
	}
}

func TestMismatchedBackupGeometry(t *testing.T) {
	image := buildImage(defaultOptions())
	backup := backupOffsetFor(LayoutStandard)
	putU32(Little, image, backup+numBlocksAt, testNumBlocks-1)
	refreshChecksum(image, backup, Little)
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	info := volume.Info()
	if info.SuperblockCopies != 1 || info.SuperblockOffset != PrimaryOffset {
		t.Fatalf("active copy = offset %d, copies %d", info.SuperblockOffset, info.SuperblockCopies)
	}
	if !warningsContain(volume.Warnings(), "only 1 of the inspected") {
		t.Fatalf("warnings = %v", volume.Warnings())
	}
	copies := volume.Superblock().Copies
	if len(copies) != 3 || copies[2].Valid || !bytes.Contains([]byte(copies[2].Reason), []byte("disagrees")) {
		t.Fatalf("copies = %+v", copies)
	}
}

func TestBadLongNameChecksum(t *testing.T) {
	image := buildImage(defaultOptions())
	at := dataOffset(LayoutStandard, blockRootDir) + 4*DirEntrySize + 0x0c
	original := uint32(image[at]) | uint32(image[at+1])<<8 | uint32(image[at+2])<<16 | uint32(image[at+3])<<24
	putU32(Little, image, at, original^1)
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Unreadable() == 0 || !warningsContain(volume.Warnings(), "checksum") {
		t.Fatalf("bad long name not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
	if _, err := volume.ListDir("/"); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("checksum")) {
		t.Fatalf("ListDir error = %v", err)
	}
}

func TestSuperblockAccessors(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	superblock := volume.Superblock()
	if superblock.BlockShift() != 12 || superblock.PtrBits() != 10 {
		t.Fatalf("shift/ptrbits = %d/%d", superblock.BlockShift(), superblock.PtrBits())
	}
	if superblock.VolumeBytes() != testNumBlocks*testBlockSize {
		t.Fatalf("volume bytes = %d", superblock.VolumeBytes())
	}
	if superblock.BlksOff != 3 {
		t.Fatalf("blks_off = %d", superblock.BlksOff)
	}
	if superblock.BackupOffset() != uint64(backupOffsetFor(LayoutStandard)) {
		t.Fatalf("backup offset = %d", superblock.BackupOffset())
	}
	if err := superblock.ValidateBlock(testNumBlocks-1, "last"); err != nil {
		t.Fatalf("last block refused: %v", err)
	}
	if err := superblock.ValidateBlock(testNumBlocks, "past"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("past-end block = %v", err)
	}
	offset, ok := superblock.BlockOffset(blockHello)
	if !ok || offset != uint64(dataOffset(LayoutStandard, blockHello)) {
		t.Fatalf("block offset = %d (%v)", offset, ok)
	}
	if _, ok := superblock.BlockOffset(testNumBlocks); ok {
		t.Fatal("BlockOffset accepted a past-end block")
	}
}

func TestFacts(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	facts := make(map[string]string)
	for _, fact := range volume.Facts() {
		facts[fact[0]] = fact[1]
	}
	want := map[string]string{
		"type":              KindLabel,
		"byte_order":        "little",
		"layout":            "standard",
		"serial":            "100",
		"block_size":        "4096",
		"blocks":            "64",
		"inodes":            "64",
		"root_inode":        "1",
		"entries":           "12",
		"directories":       "3",
		"files":             "8",
		"symlinks":          "1",
		"superblock_copies": "2",
		"volume_id":         "qnx6test",
	}
	for key, value := range want {
		if facts[key] != value {
			t.Fatalf("fact %q = %q, want %q", key, facts[key], value)
		}
	}
}

func TestZeroTimestampIsUnset(t *testing.T) {
	image := buildImage(defaultOptions())
	at := inodeOffset(LayoutStandard, inoHello)
	for offset := 0x10; offset < 0x20; offset += 4 {
		putU32(Little, image, at+offset, 0)
	}
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entry, err := volume.Stat("/" + helloName)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if entry.Created != nil || entry.Modified != nil || entry.Accessed != nil || entry.Changed != nil {
		t.Fatalf("zero timestamps became times: %+v", entry)
	}
}

func TestAccessors(t *testing.T) {
	volume, _, _ := fixtureSource(t, defaultOptions())
	if volume.BlockSize() != testBlockSize {
		t.Fatalf("BlockSize = %d", volume.BlockSize())
	}
	if volume.RootRecord() != RootRecord {
		t.Fatalf("RootRecord = %d", volume.RootRecord())
	}
	if volume.NodeCount() != 12 || len(volume.Entries()) != 12 || len(volume.Nodes()) != 12 {
		t.Fatalf("node counts = %d/%d/%d", volume.NodeCount(), len(volume.Entries()), len(volume.Nodes()))
	}
	if volume.Stats().Lookups != 3 {
		t.Fatalf("lookups = %d, want 3 (root, sub, subsub)", volume.Stats().Lookups)
	}
	if volume.Malformed() != 0 || volume.DirectoryLoops() != 0 || volume.WarningsDropped() != 0 {
		t.Fatalf("unexpected counters: %+v", volume.Stats())
	}
	if len(volume.Warnings()) != 3 {
		t.Fatalf("warnings = %v", volume.Warnings())
	}
	_, _, _ = volume, volume.Superblock(), volume.Facts()
}

func TestKindLabels(t *testing.T) {
	cases := []struct {
		mode uint16
		kind InodeKind
		name string
	}{
		{0x8000, KindFile, "file"},
		{0x4000, KindDirectory, "directory"},
		{0xa000, KindSymlink, "symlink"},
		{0x1000, KindFifo, "fifo"},
		{0xc000, KindSocket, "socket"},
		{0x6000, KindBlockDevice, "block device"},
		{0x2000, KindCharDevice, "character device"},
		{0x0000, KindUnknown, "unknown"},
	}
	for _, test := range cases {
		if got := KindFromMode(test.mode | 0x1ff); got != test.kind {
			t.Fatalf("KindFromMode(0x%04x) = %v", test.mode, got)
		}
		if got := test.kind.Label(); got != test.name {
			t.Fatalf("Label(%v) = %q", test.kind, got)
		}
	}
	if !KindDirectory.IsDirectory() || KindDirectory.IsFile() || KindDirectory.IsSymlink() {
		t.Fatal("directory kind predicates disagree")
	}
	if !KindFile.IsFile() || !KindFile.HasData() || KindFifo.HasData() {
		t.Fatal("file kind predicates disagree")
	}
}

func TestShiftRight(t *testing.T) {
	if got := shiftRight(1, 64); got != 0 {
		t.Fatalf("shiftRight(1,64) = %d", got)
	}
	if got := shiftRight(8, 3); got != 1 {
		t.Fatalf("shiftRight(8,3) = %d", got)
	}
}

func TestCorruptInodeStatus(t *testing.T) {
	image := buildImage(defaultOptions())
	at := inodeOffset(LayoutStandard, inoHello)
	image[at+0x65] = 7
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Undecodable() == 0 || volume.Malformed() == 0 ||
		!warningsContain(volume.Warnings(), "status 7") {
		t.Fatalf("bad status not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
	if _, err := volume.Stat("/" + helloName); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat = %v", err)
	}
}

func TestInvalidInodeMode(t *testing.T) {
	image := buildImage(defaultOptions())
	at := inodeOffset(LayoutStandard, inoHello)
	putU16(Little, image, at+0x20, 0)
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Malformed() == 0 || !warningsContain(volume.Warnings(), "names no supported file type") {
		t.Fatalf("bad mode not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
}

func TestStatusModeMismatch(t *testing.T) {
	image := buildImage(defaultOptions())
	at := inodeOffset(LayoutStandard, inoHello)
	image[at+0x65] = StatusDirectory // mode still names a regular file
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Malformed() == 0 || !warningsContain(volume.Warnings(), "status 1") {
		t.Fatalf("status mismatch not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
}

func TestDirectoryEntryInodeOutOfRange(t *testing.T) {
	image := buildImage(defaultOptions())
	at := dataOffset(LayoutStandard, blockRootDir) + 2*DirEntrySize
	putU32(Little, image, at, 1000)
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Malformed() == 0 || !warningsContain(volume.Warnings(), "outside the volume") {
		t.Fatalf("out-of-range inode not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
	if _, err := volume.Stat("/" + helloName); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat = %v", err)
	}
}

func TestDirectoryLoopCounted(t *testing.T) {
	image := buildImage(defaultOptions())
	// The last subsub slot ("leaf.txt") is re-pointed at subsub itself.
	at := dataOffset(LayoutStandard, blockSubsubDir) + 2*DirEntrySize
	putU32(Little, image, at, inoSubsub)
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.DirectoryLoops() != 1 {
		t.Fatalf("directory loops = %d, want 1", volume.DirectoryLoops())
	}
	info := volume.Info()
	if info.DirectoryLoops != 1 || info.Directories != 4 || info.Files != 7 {
		t.Fatalf("counts with loop = %+v", info)
	}
}

func TestDirectorySizeMalformed(t *testing.T) {
	image := buildImage(defaultOptions())
	at := inodeOffset(LayoutStandard, inoRoot)
	putU64(Little, image, at, 100) // not a multiple of 32
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if volume.Unreadable() == 0 || !warningsContain(volume.Warnings(), "not a multiple") {
		t.Fatalf("bad directory size not classified: %+v / %v", volume.Stats(), volume.Warnings())
	}
	if _, err := volume.ListDir("/"); err == nil {
		t.Fatal("ListDir returned no error for an unreadable root")
	}
}

func TestReadInodeBounds(t *testing.T) {
	volume, src, _ := fixtureSource(t, defaultOptions())
	superblock := volume.Superblock()
	if _, err := ReadInode(src, superblock, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("inode 0 = %v", err)
	}
	if _, err := ReadInode(src, superblock, testNumInodes+1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("past-end inode = %v", err)
	}
}

func TestVolumeIDHexFallback(t *testing.T) {
	image := buildImage(defaultOptions())
	offset := primaryOffsetFor(LayoutStandard)
	for index := 0; index < 16; index++ {
		image[offset+volumeIDAt+index] = 0xff
	}
	refreshChecksum(image, offset, Little)
	src := source.NewMemorySource(source.ID(1), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := volume.Info().VolumeID; got != "ffffffffffffffffffffffffffffffff" {
		t.Fatalf("volume id = %q", got)
	}
}

func TestLossyZeroFill(t *testing.T) {
	image := buildImage(defaultOptions())
	src := source.NewMemorySource(source.ID(3), image)
	file := &FileSource{
		id:        4,
		source:    src,
		size:      2 * testBlockSize,
		blockSize: testBlockSize,
		extents: []Extent{{
			Logical:  0,
			Physical: uint64(dataOffset(LayoutStandard, blockHello)),
			Len:      testBlockSize,
		}},
	}
	buf := make([]byte, 16)
	for index := range buf {
		buf[index] = 0xaa
	}
	got, err := file.ReadAtLossy(testBlockSize, buf)
	if err != nil || got != len(buf) {
		t.Fatalf("ReadAtLossy = %d, %v", got, err)
	}
	for index, value := range buf {
		if value != 0 {
			t.Fatalf("lossy byte %d = 0x%02x, want zero", index, value)
		}
	}
	if file.Stats().CorruptBytes != uint64(len(buf)) {
		t.Fatalf("corrupt bytes = %d", file.Stats().CorruptBytes)
	}
	if _, err := file.ReadAt(testBlockSize, make([]byte, 16)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("strict read = %v", err)
	}
	if _, err := file.Extents(0, 2*testBlockSize); err == nil {
		t.Fatal("Extents did not report the gap")
	}
}

func TestReadAtLossyOnHealthySource(t *testing.T) {
	image := buildImage(defaultOptions())
	src := source.NewMemorySource(source.ID(9), image)
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	file, err := volume.OpenFile("/" + helloName)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 4)
	got, err := file.ReadAtLossy(0, buf)
	if err != nil || got != len(buf) || !bytes.Equal(buf, helloData[:4]) {
		t.Fatalf("ReadAtLossy = %d, %v, %x", got, err, buf)
	}
}
