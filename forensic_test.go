package forensic_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/ewffixture"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", "e01", name)
}

func TestOpenE01PartitionsAndFilesystem(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixture(t, "fat16-encase6-zlib.E01"), forensic.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	info := img.Info()
	if info.Format != "E01" || info.Size == 0 || info.SectorSize != 512 {
		t.Fatalf("Info = %+v", info)
	}
	if img.Size() != info.Size || img.SectorSize() != 512 {
		t.Fatalf("geometry mismatch: size=%d sector=%d", img.Size(), img.SectorSize())
	}

	parts, err := img.Partitions(ctx)
	if err != nil {
		t.Fatalf("Partitions: %v", err)
	}
	if len(parts) != 1 {
		t.Fatalf("partitions = %d, want 1", len(parts))
	}
	p := parts[0]
	if p.WholeVolume() || p.TableKind() != "MBR" || p.Format() != "FAT16" {
		t.Fatalf("partition = whole=%v table=%s format=%s", p.WholeVolume(), p.TableKind(), p.Format())
	}
	if p.Length() == 0 || p.Offset() == 0 {
		t.Fatalf("partition geometry = %d+%d", p.Offset(), p.Length())
	}

	// The partition source must serve real on-disk bytes (the FAT16 label sits
	// at offset 0x36), never EWF container bytes.
	head := make([]byte, 512)
	if _, err := p.Source().ReadAt(0, head); err != nil {
		t.Fatalf("partition ReadAt: %v", err)
	}
	if !bytes.Contains(head[:0x40], []byte("FAT16")) {
		t.Fatalf("partition head has no FAT16 label: % x", head[:0x40])
	}

	fsys, err := p.OpenFilesystem(ctx)
	if err != nil {
		t.Fatalf("OpenFilesystem: %v", err)
	}
	defer fsys.Close()
	if fsys.Type() != "FAT16" {
		t.Fatalf("fs type = %q", fsys.Type())
	}
	if fsys.Info().SectorSize != 512 || !fsys.Info().ReadOnly {
		t.Fatalf("fs info = %+v", fsys.Info())
	}

	entries, err := fsys.ListDir(ctx, "/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	var fixtureEntry *forensic.Entry
	for i := range entries {
		if entries[i].Name == "FIXTURE.TXT" {
			fixtureEntry = &entries[i]
		}
		if entries[i].Path == "" || entries[i].Path[0] != '/' {
			t.Fatalf("entry path is not absolute: %+v", entries[i])
		}
	}
	if fixtureEntry == nil {
		t.Fatalf("FIXTURE.TXT not in root: %v", entries)
	}

	stat, err := fsys.Stat(ctx, "\\FIXTURE.TXT")
	if err != nil {
		t.Fatalf("Stat with backslash: %v", err)
	}
	if stat.Name != "FIXTURE.TXT" || stat.Path != "/FIXTURE.TXT" {
		t.Fatalf("Stat = %+v", stat)
	}

	file, err := fsys.Open(ctx, "/FIXTURE.TXT")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer file.Close()
	data, err := file.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "fixture\n" {
		t.Fatalf("file content = %q", data)
	}
	if _, err := file.ReadAt(make([]byte, 4), int64(len(data))); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt past EOF error = %v, want io.EOF", err)
	}

	// Walk must reach the real file, not a synthetic tree.
	var walked []string
	err = fsys.Walk(ctx, "/", func(e forensic.Entry) error {
		walked = append(walked, e.Path)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	found := false
	for _, name := range walked {
		if name == "/FIXTURE.TXT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Walk did not visit /FIXTURE.TXT: %v", walked)
	}
}

func TestGraphHasImagePartitionAndFilesystem(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixture(t, "fat16-encase6-zlib.E01"), forensic.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()
	graph, err := img.Graph(ctx)
	if err != nil {
		t.Fatalf("Graph: %v", err)
	}
	if err := graph.Validate(); err != nil {
		t.Fatalf("graph Validate: %v", err)
	}
	if roots := graph.Roots(); len(roots) != 1 {
		t.Fatalf("roots = %v, want one image root", roots)
	}
}

func TestContainerGeometryWinsOverOption(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixture(t, "fat16-encase6-zlib.E01"), forensic.Options{SectorSize: 4096})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()
	if img.SectorSize() != 512 {
		t.Fatalf("SectorSize = %d, want the E01-declared 512", img.SectorSize())
	}
	parts, err := img.Partitions(ctx)
	if err != nil || len(parts) == 0 {
		t.Fatalf("Partitions: %v (%d)", err, len(parts))
	}
	fsys, err := parts[0].OpenFilesystem(ctx)
	if err != nil {
		t.Fatalf("OpenFilesystem: %v", err)
	}
	defer fsys.Close()
	entries, err := fsys.ListDir(ctx, "/")
	if err != nil || len(entries) == 0 {
		t.Fatalf("ListDir = %d, %v", len(entries), err)
	}
}

func TestVolumesOnPlainFilesystemImage(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixture(t, "fat16-encase6-zlib.E01"), forensic.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	volumes, err := img.Volumes(ctx)
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	if len(volumes) != 0 {
		t.Fatalf("plain FAT image produced volumes: %+v", volumes)
	}
	graph, err := img.Graph(ctx)
	if err != nil {
		t.Fatalf("Graph: %v", err)
	}
	if err := graph.Validate(); err != nil {
		t.Fatalf("graph after volume scan: %v", err)
	}
}

// mdMemberSuperblock builds a minimal mdraid 1.x superblock for one member.
func mdMemberSuperblock(t *testing.T, level int32, chunkSectors, raidDisks, devNumber uint32, role uint16, dataOffset, dataSize uint64) []byte {
	t.Helper()
	sb := make([]byte, 4096)
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(sb[at:], v) }
	put64 := func(at int, v uint64) { binary.LittleEndian.PutUint64(sb[at:], v) }
	put32(0x00, 0xA92B4EFC)
	put32(0x04, 1)
	for i := 0; i < 16; i++ {
		sb[0x10+i] = byte(0x40 + i)
	}
	copy(sb[0x20:0x40], "facade-raid0")
	put64(0x40, 1700000000)
	put32(0x48, uint32(level))
	put64(0x50, dataSize)
	put32(0x58, chunkSectors)
	put32(0x5C, raidDisks)
	put64(0x80, dataOffset)
	put64(0x88, dataSize)
	put64(0x90, 8)
	put32(0xA0, devNumber)
	for i := 0; i < 16; i++ {
		sb[0xA8+i] = byte(0xA0 + i + int(devNumber))
	}
	put64(0xC0, 1700000001)
	put64(0xC8, 7)
	put32(0xDC, raidDisks)
	for i := uint32(0); i < raidDisks; i++ {
		roleValue := uint16(0xFFFF)
		if i == devNumber {
			roleValue = role
		}
		binary.LittleEndian.PutUint16(sb[0x100+int(i)*2:], roleValue)
	}
	covered := append([]byte(nil), sb...)
	for i := 0xD8; i < 0xDC; i++ {
		covered[i] = 0
	}
	var sum uint64
	for i := 0; i < 260; i += 4 {
		sum += uint64(binary.LittleEndian.Uint32(covered[i:]))
	}
	binary.LittleEndian.PutUint32(sb[0xD8:], uint32((sum&0xFFFFFFFF)+(sum>>32)))
	return sb
}

func mdDisk(t *testing.T, members [][]byte, dataSize uint64) []byte {
	t.Helper()
	const firstLBA = 2048
	const memberSectors = 16
	total := firstLBA + memberSectors*len(members)
	disk := make([]byte, total*512)
	disk[510], disk[511] = 0x55, 0xAA
	for i, data := range members {
		lba := firstLBA + i*memberSectors
		entry := disk[446+i*16 : 446+i*16+16]
		entry[4] = 0xFD // Linux RAID
		binary.LittleEndian.PutUint32(entry[8:], uint32(lba))
		binary.LittleEndian.PutUint32(entry[12:], memberSectors)
		copy(disk[lba*512:], data)
	}
	_ = dataSize
	return disk
}

func TestVolumesAssemblesMDRaid0(t *testing.T) {
	ctx := context.Background()
	member0 := make([]byte, 16*512)
	member1 := make([]byte, 16*512)
	copy(member0, mdMemberSuperblock(t, 0, 8, 2, 0, 0, 8, 8))
	copy(member1, mdMemberSuperblock(t, 0, 8, 2, 1, 1, 8, 8))
	for i := 8 * 512; i < 16*512; i++ {
		member0[i] = 0x11
		member1[i] = 0x22
	}
	disk := mdDisk(t, [][]byte{member0, member1}, 8*512)

	img, err := forensic.OpenSource(ctx, source.NewMemorySource(1, disk), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenSource: %v", err)
	}
	volumes, err := img.Volumes(ctx)
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	if len(volumes) != 1 {
		for _, v := range volumes {
			t.Logf("volume name=%q kind=%q readable=%v problem=%q", v.Name(), v.Kind(), v.Readable(), v.Problem())
		}
		t.Fatalf("volumes = %d, want 1", len(volumes))
	}
	volume := volumes[0]
	if !volume.Readable() {
		t.Fatalf("volume not readable: %s", volume.Problem())
	}
	if volume.Kind() != "mdraid raid0" || volume.Name() != "facade-raid0" {
		t.Fatalf("volume = %q %q", volume.Kind(), volume.Name())
	}
	if len(volume.Members()) != 2 {
		t.Fatalf("members = %+v", volume.Members())
	}
	if volume.Source().Len() != 8*1024 {
		t.Fatalf("volume length = %d", volume.Source().Len())
	}
	buf := make([]byte, 8*1024)
	if _, err := volume.Source().ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	for i := 0; i < 8*1024; i++ {
		want := byte(0x11)
		if i >= 4*1024 {
			want = 0x22
		}
		if buf[i] != want {
			t.Fatalf("byte %d = %#x, want %#x", i, buf[i], want)
		}
	}

	graph, err := img.Graph(ctx)
	if err != nil {
		t.Fatalf("Graph: %v", err)
	}
	if err := graph.Validate(); err != nil {
		t.Fatalf("graph validation: %v", err)
	}
	if _, ok := graph.Node(volume.NodeID()); !ok {
		t.Fatalf("volume node %d missing from graph", volume.NodeID())
	}
}

func TestOpenSourceRawMBR(t *testing.T) {
	ctx := context.Background()
	fsImage := make([]byte, 8*512)
	copy(fsImage[3:], "NTFS    ")
	disk := ewffixture.WrapMBRDisk(fsImage, 0x07, 2048)

	src := source.NewMemorySourceWithImage(1, 7, disk)
	img, err := forensic.OpenSource(ctx, src, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenSource: %v", err)
	}
	if img.Info().Format != "source" || img.Size() != uint64(len(disk)) {
		t.Fatalf("info = %+v", img.Info())
	}
	parts, err := img.Partitions(ctx)
	if err != nil {
		t.Fatalf("Partitions: %v", err)
	}
	if len(parts) != 1 || parts[0].Format() != "NTFS" {
		t.Fatalf("partitions = %+v", parts)
	}
	if _, err := parts[0].OpenFilesystem(ctx); err == nil {
		t.Fatal("NTFS signature without a valid boot sector must fail to open, not fabricate a handler")
	}
}

func TestBareVolumeIsWholeVolume(t *testing.T) {
	ctx := context.Background()
	image := make([]byte, 4096)
	copy(image[0x52:0x5A], "FAT32   ")

	img, err := forensic.OpenSource(ctx, source.NewMemorySource(1, image), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenSource: %v", err)
	}
	parts, err := img.Partitions(ctx)
	if err != nil {
		t.Fatalf("Partitions: %v", err)
	}
	if len(parts) != 1 || !parts[0].WholeVolume() || parts[0].Format() != "FAT32" {
		t.Fatalf("parts = %+v", parts)
	}
	if _, err := img.OpenFilesystem(ctx); err == nil {
		t.Fatal("OpenFilesystem on a 4 KiB stub FAT32 should fail, not fabricate a handler")
	}
}

func TestUnsupportedAndEncryptedPartitions(t *testing.T) {
	ctx := context.Background()

	t.Run("unsupported", func(t *testing.T) {
		fsImage := bytes.Repeat([]byte{0xAA}, 32*512)
		disk := ewffixture.WrapMBRDisk(fsImage, 0x82, 2048)
		img, err := forensic.OpenSource(ctx, source.NewMemorySource(1, disk), forensic.Options{})
		if err != nil {
			t.Fatalf("OpenSource: %v", err)
		}
		parts, err := img.Partitions(ctx)
		if err != nil {
			t.Fatalf("Partitions: %v", err)
		}
		if len(parts) != 1 {
			t.Fatalf("partitions = %d", len(parts))
		}
		if parts[0].Format() != "unknown" {
			t.Fatalf("format = %q", parts[0].Format())
		}
		if _, err := parts[0].OpenFilesystem(ctx); !errors.Is(err, forensic.ErrUnsupported) {
			t.Fatalf("OpenFilesystem error = %v, want ErrUnsupported", err)
		}
	})

	t.Run("encrypted", func(t *testing.T) {
		fsImage := make([]byte, 8*512)
		copy(fsImage[3:], "-FVE-FS-")
		disk := ewffixture.WrapMBRDisk(fsImage, 0x07, 2048)
		img, err := forensic.OpenSource(ctx, source.NewMemorySource(1, disk), forensic.Options{})
		if err != nil {
			t.Fatalf("OpenSource: %v", err)
		}
		parts, err := img.Partitions(ctx)
		if err != nil {
			t.Fatalf("Partitions: %v", err)
		}
		if len(parts) != 1 || !parts[0].Encrypted() {
			t.Fatalf("parts = %+v", parts)
		}
		if _, err := parts[0].OpenFilesystem(ctx); !errors.Is(err, forensic.ErrDecrypt) {
			t.Fatalf("OpenFilesystem error = %v, want ErrDecrypt", err)
		}
	})
}

func TestEncryptionRouting(t *testing.T) {
	ctx := context.Background()

	img, err := forensic.OpenSource(ctx, source.NewMemorySource(1, make([]byte, 4096)), forensic.Options{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := img.Encryption(ctx)
	if err != nil {
		t.Fatalf("Encryption on a plain source: %v", err)
	}
	if info != nil {
		t.Fatalf("Encryption on a plain source = %+v, want nil", info)
	}

	// A recognised BitLocker signature with a truncated header must produce an
	// explicit parse error, never a zero-value "success".
	fsImage := make([]byte, 8*512)
	copy(fsImage[3:], "-FVE-FS-")
	disk := ewffixture.WrapMBRDisk(fsImage, 0x07, 2048)
	img2, err := forensic.OpenSource(ctx, source.NewMemorySource(1, disk), forensic.Options{})
	if err != nil {
		t.Fatal(err)
	}
	parts, err := img2.Partitions(ctx)
	if err != nil || len(parts) != 1 {
		t.Fatalf("Partitions: %v (%d)", err, len(parts))
	}
	enc, err := parts[0].Encryption(ctx)
	if err != nil {
		t.Fatalf("Encryption on a BitLocker partition: %v", err)
	}
	if enc == nil || enc.Format != "BitLocker" || !enc.MetadataOnly {
		t.Fatalf("Encryption = %+v, want BitLocker metadata", enc)
	}
}

func TestVerifyComputesRealHashes(t *testing.T) {
	ctx := context.Background()
	payload := bytes.Repeat([]byte("evidence"), 100)
	img, err := forensic.OpenSource(ctx, source.NewMemorySource(1, payload), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenSource: %v", err)
	}
	res, err := img.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := md5.Sum(payload)
	if !bytes.Equal(res.ComputedMD5, want[:]) {
		t.Fatalf("computed MD5 = %x, want %x", res.ComputedMD5, want)
	}
	if res.BytesHashed != uint64(len(payload)) {
		t.Fatalf("BytesHashed = %d", res.BytesHashed)
	}
	if res.MD5Match || res.SHA1Match {
		t.Fatalf("a source with no stored hashes must not report a match")
	}
}

func TestOpenRawFilePath(t *testing.T) {
	ctx := context.Background()
	fsImage := make([]byte, 8*512)
	copy(fsImage[3:], "NTFS    ")
	disk := ewffixture.WrapMBRDisk(fsImage, 0x07, 2048)
	path := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(path, disk, 0o600); err != nil {
		t.Fatal(err)
	}
	img, err := forensic.Open(ctx, path, forensic.Options{})
	if err != nil {
		t.Fatalf("Open raw: %v", err)
	}
	defer img.Close()
	if img.Format() != "raw" || img.Path() != path || img.Size() != uint64(len(disk)) {
		t.Fatalf("info = %+v", img.Info())
	}
	parts, err := img.Partitions(ctx)
	if err != nil {
		t.Fatalf("Partitions: %v", err)
	}
	if len(parts) != 1 || parts[0].Offset() != 2048*512 {
		t.Fatalf("parts = %+v", parts)
	}
}

func TestEWFMagicBeatsExtensionHeuristics(t *testing.T) {
	data, err := os.ReadFile(fixture(t, "fat16-encase6-zlib.E01"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "disguised.docx")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	img, err := forensic.Open(context.Background(), path, forensic.Options{})
	if err != nil {
		t.Fatalf("Open(E01 named .docx): %v", err)
	}
	defer img.Close()
	if img.Format() != "E01" {
		t.Fatalf("format = %q, want E01", img.Format())
	}
}

func TestOpenRejectsLogicalEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logical.L01")
	head := []byte{'L', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00, 0, 0, 0, 0, 0}
	if err := os.WriteFile(path, head, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := forensic.Open(context.Background(), path, forensic.Options{})
	if !errors.Is(err, forensic.ErrInvalidArgument) {
		t.Fatalf("Open(L01) error = %v, want ErrInvalidArgument", err)
	}
	if !strings.Contains(err.Error(), "OpenLogical") {
		t.Fatalf("Open(L01) error = %v, want guidance to OpenLogical", err)
	}
}

func realmHead() []byte {
	head := make([]byte, 64)
	copy(head[16:], "T-DB")
	return head
}

func certStoreHead() []byte {
	head := make([]byte, 64)
	copy(head[4:], "CERT")
	return head
}

func superHead() []byte {
	head := make([]byte, 512)
	binary.LittleEndian.PutUint32(head[0:], 0x616C4467)
	return head
}

func clfsHead() []byte {
	head := make([]byte, 0x88)
	head[0], head[1] = 0x15, 0x00
	binary.LittleEndian.PutUint64(head[0x78:], 0xC1F5C1F500005F1C)
	return head
}

func TestOpenRejectsNonDiskContainers(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"archive.zip", append([]byte("PK"), make([]byte, 64)...), "OpenArchive"},
		{"stream.gz", []byte{0x1f, 0x8b, 0x08, 0x00}, "OpenCompressed"},
		{"stream.lz4", []byte{0x04, 0x22, 0x4d, 0x18, 0, 0}, "OpenCompressed"},
		{"stream.xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, "OpenCompressed"},
		{"archive.rar", []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}, "OpenArchive"},
		{"archive.7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 0}, "OpenArchive"},
		{"document.doc", []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, "OpenOLE"},
		{"install.wim", []byte{'M', 'S', 'W', 'I', 'M', 0, 0, 0, 0, 0, 0, 0}, "OpenWIM"},
		{"log.blf", clfsHead(), "OpenCLFS"},
		{"super.img", superHead(), "OpenSuper"},
		{"~$report.docx", []byte("lock file"), "OpenOfficeOwner"},
		{"store.sst", certStoreHead(), "OpenCertificateStore"},
		{"default.realm", realmHead(), "OpenRealm"},
	}
	for _, tc := range cases {
		path := filepath.Join(dir, tc.name)
		if err := os.WriteFile(path, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := forensic.Open(context.Background(), path, forensic.Options{})
		if !errors.Is(err, forensic.ErrInvalidArgument) {
			t.Fatalf("%s: error = %v, want ErrInvalidArgument", tc.name, err)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error = %v, want mention of %s", tc.name, err, tc.want)
		}
	}
}

func TestOpenReportsUnimplementedCodecs(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"stream.zst", []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0}, "Zstandard"},
	}
	dir := t.TempDir()
	for _, tc := range cases {
		path := filepath.Join(dir, tc.name)
		if err := os.WriteFile(path, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := forensic.Open(context.Background(), path, forensic.Options{})
		if !errors.Is(err, forensic.ErrUnsupported) || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error = %v, want ErrUnsupported mentioning %s", tc.name, err, tc.want)
		}
	}
}

func TestOpenLDMRejectsPlainDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := forensic.OpenLDM(context.Background(), path, forensic.Options{}); !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("OpenLDM(plain) = %v, want ErrUnsupported", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	img, err := forensic.Open(context.Background(), fixture(t, "fat16-encase6-zlib.E01"), forensic.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := img.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := img.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
