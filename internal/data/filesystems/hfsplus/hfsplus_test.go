package hfsplus_test

import (
	"bytes"
	"errors"
	"testing"

	hfs "github.com/laenix/ewfgo/internal/data/filesystems/hfsplus"
	"github.com/laenix/ewfgo/internal/data/source"
)

func openImage(t *testing.T, opts imageOptions) (*hfs.Volume, *source.MemorySource) {
	t.Helper()
	src := source.NewMemorySource(1, buildVolume(opts))
	volume, err := hfs.Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume, src
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	buf := make([]byte, src.Len())
	if err := source.ReadExactAt(src, 0, buf); err != nil {
		t.Fatalf("read %d bytes: %v", src.Len(), err)
	}
	return buf
}

func entryByName(entries []hfs.Entry, name string) *hfs.Entry {
	for i := range entries {
		if entries[i].Name == name {
			return &entries[i]
		}
	}
	return nil
}

func TestOpenHeaderValidation(t *testing.T) {
	base := buildVolume(imageOptions{attributes: true})

	mutate := func(change func(header []byte)) []byte {
		image := append([]byte(nil), base...)
		change(image[testHeaderAt : testHeaderAt+512])
		return image
	}

	cases := []struct {
		name  string
		image []byte
	}{
		{"bad signature", mutate(func(h []byte) { put16(h, 0, 0x4141) })},
		{"wrong HFS+ version", mutate(func(h []byte) { put16(h, 2, 5) })},
		{"block size not a power of two", mutate(func(h []byte) { put32(h, 40, 3000) })},
		{"block size too small", mutate(func(h []byte) { put32(h, 40, 256) })},
		{"zero total blocks", mutate(func(h []byte) { put32(h, 44, 0) })},
		{"free blocks above total", mutate(func(h []byte) { put32(h, 48, 300) })},
		{"empty catalog", mutate(func(h []byte) {
			for i := 272; i < 352; i++ {
				h[i] = 0
			}
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hfs.Open(source.NewMemorySource(1, tc.image))
			if !errors.Is(err, hfs.ErrInvalid) {
				t.Fatalf("Open error = %v, want ErrInvalid", err)
			}
		})
	}

	t.Run("truncated image", func(t *testing.T) {
		if _, err := hfs.Open(source.NewMemorySource(1, base[:1200])); !errors.Is(err, hfs.ErrInvalid) {
			t.Fatalf("Open error = %v, want ErrInvalid", err)
		}
		if _, err := hfs.Open(source.NewMemorySource(1, make([]byte, 4096))); !errors.Is(err, hfs.ErrInvalid) {
			t.Fatalf("Open error = %v, want ErrInvalid", err)
		}
	})

	t.Run("HFSX opens case sensitive", func(t *testing.T) {
		volume, _ := openImage(t, imageOptions{caseSensitive: true, attributes: true})
		info, err := volume.Info()
		if err != nil {
			t.Fatalf("Info: %v", err)
		}
		if !info.CaseSensitive || info.Signature.Label() != "HFSX" {
			t.Fatalf("signature = %v, case sensitive = %v", info.Signature, info.CaseSensitive)
		}
	})
}

func TestInfoAndRootListing(t *testing.T) {
	volume, _ := openImage(t, imageOptions{attributes: true})
	info, err := volume.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != volumeName {
		t.Errorf("volume name = %q, want %q", info.Name, volumeName)
	}
	if info.UUID != "" {
		t.Errorf("UUID = %q, want empty for an unset volume id", info.UUID)
	}
	if info.Signature.Label() != "HFS+" || info.CaseSensitive {
		t.Errorf("signature = %v case sensitive = %v", info.Signature, info.CaseSensitive)
	}
	if info.BlockSize != testBlock || info.TotalBlocks != testTotalBlocks {
		t.Errorf("geometry = %d x %d", info.BlockSize, info.TotalBlocks)
	}
	if info.FreeBlocks >= info.TotalBlocks {
		t.Errorf("free blocks %d, total %d", info.FreeBlocks, info.TotalBlocks)
	}
	if info.FileCount != 7 || info.FolderCount != 4 {
		t.Errorf("counts = %d files, %d folders", info.FileCount, info.FolderCount)
	}
	if info.Journaled || info.Journal != nil {
		t.Errorf("volume unexpectedly journaled")
	}
	if info.Created.Unix() != 3_786_912_000-2_082_844_800 {
		t.Errorf("created = %d", info.Created.Unix())
	}

	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	wantOrder := []string{
		privateName, "link.txt", "MiXeD.txt", "Notes",
		"photo.bin", "readme.txt", "res.txt", "sym.txt",
	}
	if len(entries) != len(wantOrder) {
		t.Fatalf("listing has %d entries, want %d: %+v", len(entries), len(wantOrder), entries)
	}
	for i, want := range wantOrder {
		if entries[i].Name != want {
			t.Errorf("entry %d = %q, want %q", i, entries[i].Name, want)
		}
	}

	readme := entryByName(entries, "readme.txt")
	if readme == nil {
		t.Fatal("readme.txt missing from the root")
	}
	if readme.Path != "/readme.txt" || readme.IsDir {
		t.Errorf("readme path/isDir = %q/%v", readme.Path, readme.IsDir)
	}
	if readme.Size != uint64(len(readmeData)) || readme.Allocated != testBlock {
		t.Errorf("readme size/allocated = %d/%d", readme.Size, readme.Allocated)
	}
	if readme.Mode != 0o100644 || readme.UID != 501 || readme.GID != 20 {
		t.Errorf("readme mode/uid/gid = %o/%d/%d", readme.Mode, readme.UID, readme.GID)
	}
	if readme.Inode != cnidReadme || readme.Parent != cnidRoot {
		t.Errorf("readme cnid/parent = %d/%d", readme.Inode, readme.Parent)
	}
	if readme.CreateTime != 3_786_912_000 || readme.ModTime != 3_786_912_600 ||
		readme.AccessTime != 3_786_913_000 || readme.BackupTime != 3_786_912_000 {
		t.Errorf("readme timestamps = %+v", readme)
	}
	if readme.Deleted {
		t.Error("a live entry is marked deleted")
	}

	notes := entryByName(entries, "Notes")
	if notes == nil || !notes.IsDir || notes.Size != 0 {
		t.Fatalf("Notes entry = %+v", notes)
	}

	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat(/): %v", err)
	}
	if !root.IsDir || root.Path != "/" || root.Name != volumeName {
		t.Errorf("root = %+v", root)
	}
}

func TestStatAndPathErrors(t *testing.T) {
	volume, _ := openImage(t, imageOptions{attributes: true})

	if _, err := volume.Stat("/missing"); !errors.Is(err, hfs.ErrNotFound) {
		t.Errorf("Stat(/missing) = %v, want ErrNotFound", err)
	}
	if _, err := volume.Stat("/readme.txt/child"); !errors.Is(err, hfs.ErrNotDirectory) {
		t.Errorf("Stat through a file = %v, want ErrNotDirectory", err)
	}
	if _, err := volume.Stat("relative"); !errors.Is(err, hfs.ErrInvalid) {
		t.Errorf("relative path = %v, want ErrInvalid", err)
	}
	if _, err := volume.Stat(""); !errors.Is(err, hfs.ErrInvalid) {
		t.Errorf("empty path = %v, want ErrInvalid", err)
	}
	if _, err := volume.ListDir("/readme.txt"); !errors.Is(err, hfs.ErrNotDirectory) {
		t.Errorf("ListDir(file) = %v, want ErrNotDirectory", err)
	}
	if _, err := volume.ListDir("/missing"); !errors.Is(err, hfs.ErrNotFound) {
		t.Errorf("ListDir(missing) = %v, want ErrNotFound", err)
	}
	if _, err := volume.OpenFile("/Notes"); !errors.Is(err, hfs.ErrIsDirectory) {
		t.Errorf("OpenFile(directory) = %v, want ErrIsDirectory", err)
	}
	if _, err := volume.OpenFile("/nope"); !errors.Is(err, hfs.ErrNotFound) {
		t.Errorf("OpenFile(missing) = %v, want ErrNotFound", err)
	}
	if _, err := volume.OpenFork("/Notes", hfs.ForkData); !errors.Is(err, hfs.ErrIsDirectory) {
		t.Errorf("OpenFork(directory) = %v, want ErrIsDirectory", err)
	}
}

func TestReadFilesWithExtents(t *testing.T) {
	volume, _ := openImage(t, imageOptions{attributes: true})

	readme, err := volume.OpenFile("/readme.txt")
	if err != nil {
		t.Fatalf("OpenFile(readme): %v", err)
	}
	if readme.Len() != uint64(len(readmeData)) {
		t.Errorf("readme length = %d", readme.Len())
	}
	if got := readAll(t, readme); !bytes.Equal(got, readmeData) {
		t.Errorf("readme bytes = %q", got)
	}

	todo, err := volume.OpenFile("/Notes/todo.txt")
	if err != nil {
		t.Fatalf("OpenFile(todo): %v", err)
	}
	if got := readAll(t, todo); !bytes.Equal(got, todoData) {
		t.Errorf("todo.txt content mismatch: %d bytes", len(got))
	}

	photo, err := volume.OpenFile("/photo.bin")
	if err != nil {
		t.Fatalf("OpenFile(photo): %v", err)
	}
	if photo.Len() != uint64(len(photoData)) {
		t.Errorf("photo length = %d, want %d", photo.Len(), len(photoData))
	}
	if got := readAll(t, photo); !bytes.Equal(got, photoData) {
		t.Errorf("photo.bin content mismatch: got %d bytes", len(got))
	}

	// Reaching past the end is a structured out-of-range, not a zero fill.
	if _, err := photo.ReadAt(photo.Len(), make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("read at EOF = %v, want ErrOutOfRange", err)
	}
	buf := make([]byte, 16)
	n, err := photo.ReadAt(photo.Len()-4, buf)
	if err != nil || n != 4 {
		t.Errorf("short tail read = %d, %v; want 4, nil", n, err)
	}

	// A range spanning an extent boundary names both backing pieces.
	ranges, err := photo.Extents(3*testBlock, 2*testBlock)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("extent count = %d, want 2: %+v", len(ranges), ranges)
	}
	if ranges[0].ParentOffset != uint64(testPhotoFirst+3*2)*testBlock {
		t.Errorf("first parent offset = %d", ranges[0].ParentOffset)
	}
	if ranges[1].ParentOffset != uint64(testPhotoFirst+4*2)*testBlock {
		t.Errorf("second parent offset = %d", ranges[1].ParentOffset)
	}
	if ranges[0].Len != testBlock || ranges[1].Len != testBlock {
		t.Errorf("extent lengths = %d/%d", ranges[0].Len, ranges[1].Len)
	}

	// A cross-extent read stitches the two blocks.
	cross := make([]byte, 200)
	if _, err := todo.ReadAt(4000, cross); err != nil {
		t.Fatalf("cross-extent read: %v", err)
	}
	if !bytes.Equal(cross, todoData[4000:4200]) {
		t.Error("cross-extent read bytes mismatch")
	}
}

func TestResourceFork(t *testing.T) {
	volume, _ := openImage(t, imageOptions{attributes: true})

	entry, err := volume.Stat("/res.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if entry.Size != uint64(len(resData)) || entry.ResourceSize != uint64(len(resResource)) {
		t.Errorf("sizes = %d data / %d resource", entry.Size, entry.ResourceSize)
	}
	if !entry.HasResourceFork {
		t.Error("HasResourceFork is false")
	}

	data, err := volume.OpenFile("/res.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if got := readAll(t, data); !bytes.Equal(got, resData) {
		t.Errorf("data fork = %q", got)
	}

	resource, err := volume.OpenFork("/res.txt", hfs.ForkResource)
	if err != nil {
		t.Fatalf("OpenFork: %v", err)
	}
	if got := readAll(t, resource); !bytes.Equal(got, resResource) {
		t.Errorf("resource fork = %q", got)
	}
}

func TestHardLinkSymlinkAndCase(t *testing.T) {
	volume, _ := openImage(t, imageOptions{attributes: true})
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}

	link := entryByName(entries, "link.txt")
	if link == nil {
		t.Fatal("link.txt missing")
	}
	if !link.HardLink {
		t.Error("link.txt is not flagged as a hard link")
	}
	if link.Size != uint64(len(inodeData)) {
		t.Errorf("hard link size = %d, want the inode file's %d", link.Size, len(inodeData))
	}
	content, err := volume.OpenFile("/link.txt")
	if err != nil {
		t.Fatalf("OpenFile(link): %v", err)
	}
	if got := readAll(t, content); !bytes.Equal(got, inodeData) {
		t.Errorf("hard link content = %q", got)
	}

	sym := entryByName(entries, "sym.txt")
	if sym == nil || !sym.IsSymlink {
		t.Fatalf("sym.txt entry = %+v", sym)
	}
	if sym.Mode&0o170000 != 0o120000 {
		t.Errorf("symlink mode = %o", sym.Mode)
	}

	// HFS+ folds ASCII case, so the mixed-case file answers a lower-case name.
	if _, err := volume.Stat("/mixed.txt"); err != nil {
		t.Errorf("HFS+ case-insensitive Stat = %v", err)
	}

	caseSensitive, _ := openImage(t, imageOptions{caseSensitive: true, attributes: true})
	if _, err := caseSensitive.Stat("/mixed.txt"); !errors.Is(err, hfs.ErrNotFound) {
		t.Errorf("HFSX lower-case Stat = %v, want ErrNotFound", err)
	}
	if _, err := caseSensitive.Stat("/MiXeD.txt"); err != nil {
		t.Errorf("HFSX exact-case Stat = %v", err)
	}
}

func TestAttributes(t *testing.T) {
	volume, _ := openImage(t, imageOptions{attributes: true})

	small, err := volume.Attribute(cnidReadme, "user.test")
	if err != nil {
		t.Fatalf("Attribute(user.test): %v", err)
	}
	if !bytes.Equal(small, attrSmallValue) {
		t.Errorf("user.test = %q", small)
	}

	big, err := volume.Attribute(cnidReadme, "user.big")
	if err != nil {
		t.Fatalf("Attribute(user.big): %v", err)
	}
	if !bytes.Equal(big, attrBigValue) {
		t.Errorf("user.big = %d bytes, want %d", len(big), len(attrBigValue))
	}

	missing, err := volume.Attribute(cnidReadme, "user.none")
	if err != nil || missing != nil {
		t.Errorf("missing attribute = %v, %v; want nil, nil", missing, err)
	}
	if missing, err := volume.Attribute(9999, "user.test"); err != nil || missing != nil {
		t.Errorf("unknown file attribute = %v, %v", missing, err)
	}
}

func TestResidueRecovery(t *testing.T) {
	volume, _ := openImage(t, imageOptions{attributes: true, residue: true})
	report, err := volume.ScanResidue(64)
	if err != nil {
		t.Fatalf("ScanResidue: %v", err)
	}
	if !report.BitmapUsed || report.BitmapInUseNodes != 4 || report.BitmapFreeNodes != 0 {
		t.Errorf("node map = used %v inUse %d free %d", report.BitmapUsed, report.BitmapInUseNodes, report.BitmapFreeNodes)
	}
	if report.Leaves != 2 || report.BytesScanned == 0 {
		t.Errorf("leaves = %d, bytes scanned = %d", report.Leaves, report.BytesScanned)
	}

	var deleted *hfs.CatalogResidue
	var liveCopy *hfs.CatalogResidue
	var thread *hfs.CatalogResidue
	for i := range report.Residues {
		item := &report.Residues[i]
		switch item.Name {
		case "deleted.bin":
			if item.Kind == hfs.ResidueFile {
				deleted = item
			} else {
				thread = item
			}
		case "readme.txt":
			liveCopy = item
		}
	}
	if deleted == nil {
		t.Fatalf("deleted.bin residue missing: %+v", report.Residues)
	}
	if deleted.Kind != hfs.ResidueFile || deleted.Parent != cnidNotes || deleted.ID == nil ||
		*deleted.ID != cnidDeleted || deleted.Size == nil || *deleted.Size != testBlock {
		t.Errorf("deleted residue = %+v", deleted)
	}
	if !deleted.IsDeleted() || deleted.Fork == nil {
		t.Error("deleted residue is not marked deleted or carries no fork")
	}
	if thread == nil || thread.Kind != hfs.ResidueFileThread || thread.ID == nil || *thread.ID != cnidDeleted {
		t.Errorf("thread residue = %+v", thread)
	}
	if liveCopy == nil || !liveCopy.Live || liveCopy.IsDeleted() {
		t.Errorf("live-name residue = %+v", liveCopy)
	}

	free, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if !free.IsFree(uint64(testResidueBlock)*testBlock, testBlock) {
		t.Error("residue block is not marked free")
	}
	if free.IsFree(uint64(testReadmeBlock)*testBlock, testBlock) {
		t.Error("readme block is marked free")
	}

	verdict, err := volume.RecoverResidue(deleted, free, 1<<20)
	if err != nil {
		t.Fatalf("RecoverResidue: %v", err)
	}
	if verdict.Kind != hfs.ResidueContent {
		t.Fatalf("verdict = %v, want content", verdict.Kind)
	}
	if len(verdict.Bytes) != testBlock || !bytes.HasPrefix(verdict.Bytes, deletedData) {
		t.Errorf("recovered bytes = %d, prefix %q", len(verdict.Bytes), verdict.Bytes[:len(deletedData)])
	}
	if verdict.Size != testBlock || verdict.Truncated {
		t.Errorf("recovery metadata = %+v", verdict)
	}

	// The stale copy of a live name must be refused: its block is allocated.
	busy, err := volume.RecoverResidue(liveCopy, free, 1<<20)
	if err != nil {
		t.Fatalf("RecoverResidue(live copy): %v", err)
	}
	if busy.Kind != hfs.ResidueInUse {
		t.Errorf("live-copy verdict = %v, want in-use", busy.Kind)
	}
}

func TestJournal(t *testing.T) {
	volume, _ := openImage(t, imageOptions{attributes: true, journal: true})
	info, err := volume.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !info.Journaled || info.Journal == nil {
		t.Fatalf("journal info = %+v", info.Journal)
	}
	if info.Journal.Offset != testJournalOffset || info.Journal.Size != testJournalSize {
		t.Errorf("journal geometry = %d/%d", info.Journal.Offset, info.Journal.Size)
	}
	if !info.Journal.HeaderChecksumOK || !info.Journal.Pending || info.Journal.Transactions != 1 {
		t.Errorf("journal summary = %+v", info.Journal)
	}

	journal, err := volume.Journal()
	if err != nil {
		t.Fatalf("Journal: %v", err)
	}
	if !journal.Pending() || len(journal.Transactions) != 1 {
		t.Fatalf("transactions = %d", len(journal.Transactions))
	}
	if journal.Stats.Writes != 1 || journal.Stats.Bytes != testJournalSector {
		t.Errorf("stats = %+v", journal.Stats)
	}
	if !journal.Stats.BlockChecksums || journal.Stats.ChecksumMismatch || journal.Stats.Stopped {
		t.Errorf("checksum stats = %+v", journal.Stats)
	}
	writes := journal.Transactions[0].Writes
	if len(writes) != 1 {
		t.Fatalf("writes = %d", len(writes))
	}
	if writes[0].Sector != uint64(testReadmeBlock)*(testBlock/testJournalSector) {
		t.Errorf("destination sector = %d", writes[0].Sector)
	}
	if !bytes.HasPrefix(writes[0].Data, []byte("journal write")) {
		t.Errorf("journal bytes = %q", writes[0].Data)
	}

	if _, err := journal.Replay(volume, 99); !errors.Is(err, hfs.ErrUnsupported) {
		t.Errorf("Replay = %v, want ErrUnsupported", err)
	}
}

func TestJournalRejectsDamagedData(t *testing.T) {
	damaged := buildVolume(imageOptions{attributes: true, journal: true})
	// A corrupted block whose directory checksum now disagrees.
	damaged[testJournalOffset+testJournalStart+testJournalBlhdr] ^= 0xFF
	volume, err := hfs.Open(source.NewMemorySource(1, damaged))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	journal, err := volume.Journal()
	if err != nil {
		t.Fatalf("Journal: %v", err)
	}
	if !journal.Stats.ChecksumMismatch || journal.Stats.Transactions != 0 {
		t.Errorf("stats = %+v, want a checksum mismatch with no transaction", journal.Stats)
	}

	badMagic := buildVolume(imageOptions{attributes: true, journal: true})
	for i := 0; i < 4; i++ {
		badMagic[testJournalOffset+i] = 0
	}
	volume, err = hfs.Open(source.NewMemorySource(1, badMagic))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := volume.Journal(); !errors.Is(err, hfs.ErrInvalid) {
		t.Errorf("Journal with bad magic = %v, want ErrInvalid", err)
	}
}

func TestVolumeUUID(t *testing.T) {
	volume, _ := openImage(t, imageOptions{
		attributes: true,
		uuidID:     0x0123456789abcdef,
	})
	info, err := volume.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	const want = "de53349f-21ad-3c08-9044-ae10cd9587d3"
	if info.UUID != want {
		t.Errorf("UUID = %q, want %q", info.UUID, want)
	}
}
