package minix

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Magic variants, repeated here so the tests state the on-disk constants they
// exercise rather than importing implementation identifiers.
const (
	testMagicV1_14 = 0x137F
	testMagicV1_30 = 0x138F
	testMagicV2_14 = 0x2468
	testMagicV2_30 = 0x2478
	testMagicV3    = 0x4D5A
)

type minixImage struct {
	t       *testing.T
	data    []byte
	version int
	magic   uint16
	block   int

	inodeSize       int
	inodeTableBlock int
	entrySize       int
	nameLen         int

	ninodes   int
	zones     int
	firstData int
}

// newMinixImage builds an all-zero image with a valid superblock. Zones are
// one block each (s_log_zone_size 0) and the inode bitmap / zone bitmap each
// occupy one block, matching the fixtures in the Rust reference.
func newMinixImage(t *testing.T, version int, magic uint16, block, ninodes, zones, firstData int) *minixImage {
	t.Helper()
	inodeSize := 64
	if version == 1 {
		inodeSize = 32
	}
	entrySize, nameLen := 0, 0
	switch magic {
	case testMagicV1_14, testMagicV2_14:
		entrySize, nameLen = 16, 14
	case testMagicV1_30, testMagicV2_30:
		entrySize, nameLen = 32, 30
	case testMagicV3:
		entrySize, nameLen = 64, 60
	default:
		t.Fatalf("unknown test magic %#x", magic)
	}
	m := &minixImage{
		t:               t,
		data:            make([]byte, zones*block),
		version:         version,
		magic:           magic,
		block:           block,
		inodeSize:       inodeSize,
		inodeTableBlock: 2 + 1 + 1,
		entrySize:       entrySize,
		nameLen:         nameLen,
		ninodes:         ninodes,
		zones:           zones,
		firstData:       firstData,
	}
	at := 1024
	le := binary.LittleEndian
	if version == 3 {
		le.PutUint32(m.data[at:], uint32(ninodes))
		le.PutUint16(m.data[at+6:], 1) // inode bitmap blocks
		le.PutUint16(m.data[at+8:], 1) // zone bitmap blocks
		le.PutUint16(m.data[at+10:], uint16(firstData))
		le.PutUint16(m.data[at+12:], 0) // log zone size
		le.PutUint32(m.data[at+16:], 0x1000_0000)
		le.PutUint32(m.data[at+20:], uint32(zones))
		le.PutUint16(m.data[at+24:], testMagicV3)
		le.PutUint16(m.data[at+28:], uint16(block))
		m.data[at+30] = 2
		le.PutUint16(m.data[at+31:], 1)
		return m
	}
	le.PutUint16(m.data[at:], uint16(ninodes))
	if version == 1 {
		le.PutUint16(m.data[at+2:], uint16(zones))
	} else {
		le.PutUint16(m.data[at+2:], 0)
	}
	le.PutUint16(m.data[at+4:], 1) // inode bitmap blocks
	le.PutUint16(m.data[at+6:], 1) // zone bitmap blocks
	le.PutUint16(m.data[at+8:], uint16(firstData))
	le.PutUint16(m.data[at+10:], 0)
	le.PutUint32(m.data[at+12:], 0x1000_0000)
	le.PutUint16(m.data[at+16:], magic)
	le.PutUint16(m.data[at+18:], 1)
	le.PutUint32(m.data[at+20:], uint32(zones))
	return m
}

func (m *minixImage) zone(zone int) int { return zone * m.block }

func (m *minixImage) putData(zone int, contents []byte) {
	m.t.Helper()
	copy(m.data[m.zone(zone):], contents)
}

func (m *minixImage) putInodeV1(number int, mode uint16, uid uint16, gid, links uint8, size uint32, mtime uint32, zones []uint16) {
	m.t.Helper()
	at := m.inodeTableBlock*m.block + (number-1)*m.inodeSize
	b := m.data[at : at+m.inodeSize]
	le := binary.LittleEndian
	le.PutUint16(b[0:], mode)
	le.PutUint16(b[2:], uid)
	le.PutUint32(b[4:], size)
	le.PutUint32(b[8:], mtime)
	b[12] = gid
	b[13] = links
	for index, zone := range zones {
		if index >= 9 {
			break
		}
		le.PutUint16(b[14+index*2:], zone)
	}
}

func (m *minixImage) putInodeV2(number int, mode uint16, links, uid, gid uint16, size uint32, atime, mtime, ctime uint32, zones []uint32) {
	m.t.Helper()
	at := m.inodeTableBlock*m.block + (number-1)*m.inodeSize
	b := m.data[at : at+m.inodeSize]
	le := binary.LittleEndian
	le.PutUint16(b[0:], mode)
	le.PutUint16(b[2:], links)
	le.PutUint16(b[4:], uid)
	le.PutUint16(b[6:], gid)
	le.PutUint32(b[8:], size)
	le.PutUint32(b[12:], atime)
	le.PutUint32(b[16:], mtime)
	le.PutUint32(b[20:], ctime)
	for index, zone := range zones {
		if index >= 10 {
			break
		}
		le.PutUint32(b[24+index*4:], zone)
	}
}

func (m *minixImage) entry(inode int, name string) []byte {
	m.t.Helper()
	out := make([]byte, m.entrySize)
	if m.entrySize == 64 {
		binary.LittleEndian.PutUint32(out[0:], uint32(inode))
	} else {
		binary.LittleEndian.PutUint16(out[0:], uint16(inode))
	}
	if len(name) > m.nameLen {
		m.t.Fatalf("test name %q is longer than %d bytes", name, m.nameLen)
	}
	copy(out[m.inodeFieldSize():], name)
	return out
}

func (m *minixImage) inodeFieldSize() int {
	if m.entrySize == 64 {
		return 4
	}
	return 2
}

func (m *minixImage) putDir(zone int, entries ...[]byte) []byte {
	m.t.Helper()
	var out []byte
	for _, entry := range entries {
		out = append(out, entry...)
	}
	m.putData(zone, out)
	return out
}

func (m *minixImage) putIndirect(zone int, entries []uint32) {
	m.t.Helper()
	at := m.zone(zone)
	for index, value := range entries {
		binary.LittleEndian.PutUint32(m.data[at+index*4:], value)
	}
}

func (m *minixImage) putIndirect16(zone int, entries []uint16) {
	m.t.Helper()
	at := m.zone(zone)
	for index, value := range entries {
		binary.LittleEndian.PutUint16(m.data[at+index*2:], value)
	}
}

func (m *minixImage) emptyRoot() {
	m.t.Helper()
	if m.version == 1 {
		m.putInodeV1(1, 0o040755, 0, 0, 0, 0, 0, nil)
		return
	}
	m.putInodeV2(1, 0o040755, 0, 0, 0, 0, 0, 0, 0, nil)
}

func (m *minixImage) source() source.ByteSource {
	return source.NewMemorySource(1, m.data)
}

func (m *minixImage) open() (*Volume, error) {
	return Open(m.source())
}

func mustOpenMinix(t *testing.T, m *minixImage) *Volume {
	t.Helper()
	volume, err := m.open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	out, err := io.ReadAll(io.NewSectionReader(source.ReaderAt(src), 0, int64(src.Len())))
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	return out
}

func entryNames(entries []Entry) []string {
	out := make([]string, len(entries))
	for index, entry := range entries {
		out[index] = entry.Name
	}
	return out
}

func assertNames(t *testing.T, got []Entry, want ...string) {
	t.Helper()
	names := entryNames(got)
	if len(names) != len(want) {
		t.Fatalf("entries = %v, want %v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("entries = %v, want %v", names, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Detection

func TestDetectEveryMagicVariant(t *testing.T) {
	cases := []struct {
		name    string
		version int
		magic   uint16
		entry   int
	}{
		{"v1 14-byte", 1, testMagicV1_14, 16},
		{"v1 30-byte", 1, testMagicV1_30, 32},
		{"v2 14-byte", 2, testMagicV2_14, 16},
		{"v2 30-byte", 2, testMagicV2_30, 32},
		{"v3", 3, testMagicV3, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMinixImage(t, tc.version, tc.magic, 1024, 32, 64, 6)
			m.emptyRoot()
			ok, err := Detect(m.source())
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if !ok {
				t.Fatal("Detect = false, want true")
			}
			volume := mustOpenMinix(t, m)
			info := volume.Info()
			if info.Magic != tc.magic {
				t.Fatalf("Info.Magic = %#x, want %#x", info.Magic, tc.magic)
			}
			if info.DirEntrySize != tc.entry {
				t.Fatalf("Info.DirEntrySize = %d, want %d", info.DirEntrySize, tc.entry)
			}
			wantVersion := map[int]string{1: "V1", 2: "V2", 3: "V3"}[tc.version]
			if info.Version != wantVersion {
				t.Fatalf("Info.Version = %q, want %q", info.Version, wantVersion)
			}
		})
	}
}

func TestDetectRejectsNonMinixAndShortSources(t *testing.T) {
	ok, err := Detect(source.NewMemorySource(1, make([]byte, 4096)))
	if err != nil || ok {
		t.Fatalf("blank source: Detect = %v, %v; want false, nil", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, make([]byte, 1000)))
	if err != nil || ok {
		t.Fatalf("short source: Detect = %v, %v; want false, nil", ok, err)
	}
}

func TestDetectRefusesByteSwappedMagic(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	binary.LittleEndian.PutUint16(m.data[1024+16:], 0x7824) // swapped 0x2478
	ok, err := Detect(m.source())
	if ok {
		t.Fatal("Detect = true for a byte-swapped image")
	}
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Detect error = %v, want ErrUnsupported", err)
	}
}

func TestDetectReportsCorruptMinixGeometry(t *testing.T) {
	// The magic is present, so the source is Minix, but the inode table cannot
	// end before the first data zone.
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 3)
	ok, err := Detect(m.source())
	if !ok {
		t.Fatal("Detect = false, want true for a recognised magic")
	}
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Detect error = %v, want ErrCorrupt", err)
	}
}

// ---------------------------------------------------------------------------
// Superblock geometry

func TestSuperblockGeometry(t *testing.T) {
	t.Run("v2", func(t *testing.T) {
		m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
		m.emptyRoot()
		info := mustOpenMinix(t, m).Info()
		if info.InodeCount != 32 || info.Zones != 64 || info.FirstDataZone != 6 {
			t.Fatalf("geometry = %+v", info)
		}
		if info.BlockSize != 1024 || info.ZoneSize != 1024 {
			t.Fatalf("sizes = %+v", info)
		}
		if info.InodeTableBlock != 4 {
			t.Fatalf("InodeTableBlock = %d, want 4", info.InodeTableBlock)
		}
		if info.NameLength != 30 || info.DirEntrySize != 32 {
			t.Fatalf("directory shape = %+v", info)
		}
		if info.State != 1 {
			t.Fatalf("State = %d, want 1", info.State)
		}
	})
	t.Run("v1", func(t *testing.T) {
		m := newMinixImage(t, 1, testMagicV1_14, 1024, 32, 64, 6)
		m.emptyRoot()
		info := mustOpenMinix(t, m).Info()
		if info.Version != "V1" || info.NameLength != 14 || info.DirEntrySize != 16 {
			t.Fatalf("v1 shape = %+v", info)
		}
	})
	t.Run("v3 4096", func(t *testing.T) {
		m := newMinixImage(t, 3, testMagicV3, 4096, 32, 64, 6)
		m.emptyRoot()
		info := mustOpenMinix(t, m).Info()
		if info.BlockSize != 4096 || info.ZoneSize != 4096 {
			t.Fatalf("v3 sizes = %+v", info)
		}
		if info.NameLength != 60 || info.DirEntrySize != 64 {
			t.Fatalf("v3 shape = %+v", info)
		}
	})
}

func TestSuperblockRefusals(t *testing.T) {
	t.Run("short source", func(t *testing.T) {
		m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
		_, err := Open(source.NewMemorySource(1, m.data[:1000]))
		if !errors.Is(err, source.ErrCorrupt) && !errors.Is(err, source.ErrUnexpectedEOF) {
			t.Fatalf("Open error = %v, want corrupt/EOF", err)
		}
	})
	t.Run("zero inodes", func(t *testing.T) {
		m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
		binary.LittleEndian.PutUint16(m.data[1024:], 0)
		if _, err := m.open(); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})
	t.Run("inode table past first data zone", func(t *testing.T) {
		m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 3)
		if _, err := m.open(); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})
	t.Run("unreasonable log zone size", func(t *testing.T) {
		m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
		binary.LittleEndian.PutUint16(m.data[1024+10:], 9)
		if _, err := m.open(); !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("Open error = %v, want ErrUnsupported", err)
		}
	})
	t.Run("undefined V3 block size", func(t *testing.T) {
		m := newMinixImage(t, 3, testMagicV3, 4096, 32, 64, 6)
		binary.LittleEndian.PutUint16(m.data[1024+28:], 3000)
		if _, err := m.open(); !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("Open error = %v, want ErrUnsupported", err)
		}
	})
	t.Run("non-directory root", func(t *testing.T) {
		m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
		m.putInodeV2(1, 0o100644, 1, 0, 0, 0, 0, 0, 0, nil)
		if _, err := m.open(); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Listing, stat and regular files

func TestV2ListingAndFiles(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	// Garbage in the zone bitmap: this reader does not translate it, so it
	// must not affect a live read.
	for index := m.zone(3); index < m.zone(4); index++ {
		m.data[index] = 0xFF
	}
	root := m.putDir(6,
		m.entry(1, "."),
		m.entry(1, ".."),
		m.entry(2, "hello.txt"),
		m.entry(3, "sub"),
		m.entry(4, "empty"),
		m.entry(5, "link"),
		m.entry(6, "abcdefghijklmnopqrstuvwxyz1234"),
	)
	sub := m.putDir(8,
		m.entry(3, "."),
		m.entry(1, ".."),
		m.entry(7, "inner.txt"),
	)
	m.putData(7, []byte("hello world"))
	m.putData(9, []byte("hello.txt"))
	m.putData(10, []byte("nested"))
	m.putData(11, []byte("F"))
	m.putInodeV2(1, 0o040755, 3, 1000, 1000, uint32(len(root)), 1_700_000_001, 1_700_000_002, 1_700_000_003, []uint32{6})
	m.putInodeV2(2, 0o100644, 1, 1000, 27, 11, 0, 1_700_000_010, 0, []uint32{7})
	m.putInodeV2(3, 0o040755, 2, 1000, 27, uint32(len(sub)), 0, 0, 0, []uint32{8})
	m.putInodeV2(4, 0o040755, 2, 1000, 27, 0, 0, 0, 0, nil)
	m.putInodeV2(5, 0o120777, 1, 1000, 27, 9, 0, 0, 0, []uint32{9})
	m.putInodeV2(6, 0o100640, 1, 1000, 27, 1, 0, 0, 0, []uint32{11})
	m.putInodeV2(7, 0o100600, 1, 1000, 27, 6, 0, 0, 0, []uint32{10})

	volume := mustOpenMinix(t, m)
	info := volume.Info()
	if info.Entries != 7 || info.Directories != 3 || info.Files != 4 || info.Symlinks != 1 {
		t.Fatalf("counts = %+v", info)
	}

	rootEntries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir(/): %v", err)
	}
	assertNames(t, rootEntries, "hello.txt", "sub", "empty", "link", "abcdefghijklmnopqrstuvwxyz1234")
	if rootEntries[0].Path != "/hello.txt" || rootEntries[0].IsFile == false {
		t.Fatalf("hello entry = %+v", rootEntries[0])
	}
	if rootEntries[2].IsDir == false || rootEntries[2].Path != "/empty" {
		t.Fatalf("empty entry = %+v", rootEntries[2])
	}

	subEntries, err := volume.ListDir("sub")
	if err != nil {
		t.Fatalf("ListDir(sub): %v", err)
	}
	assertNames(t, subEntries, "inner.txt")
	if subEntries[0].Path != "/sub/inner.txt" {
		t.Fatalf("inner path = %q", subEntries[0].Path)
	}

	emptyEntries, err := volume.ListDir("/empty")
	if err != nil {
		t.Fatalf("ListDir(empty): %v", err)
	}
	if len(emptyEntries) != 0 {
		t.Fatalf("empty directory = %v", entryNames(emptyEntries))
	}

	hello, err := volume.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if hello.Size != 11 || hello.Mode != 0o100644 || hello.UID != 1000 || hello.GID != 27 {
		t.Fatalf("hello stat = %+v", hello)
	}
	if !hello.Atime.IsZero() {
		t.Fatalf("hello atime = %v, want unset", hello.Atime)
	}
	if !hello.Mtime.Equal(time.Unix(1_700_000_010, 0).UTC()) {
		t.Fatalf("hello mtime = %v", hello.Mtime)
	}
	if !hello.AllocatedKnown || hello.Allocated != 1024 {
		t.Fatalf("hello allocation = %+v", hello)
	}

	full, err := volume.Stat("/abcdefghijklmnopqrstuvwxyz1234")
	if err != nil {
		t.Fatalf("Stat full name: %v", err)
	}
	if full.Name != "abcdefghijklmnopqrstuvwxyz1234" {
		t.Fatalf("full name = %q", full.Name)
	}

	link, err := volume.Stat("/link")
	if err != nil {
		t.Fatalf("Stat link: %v", err)
	}
	if !link.IsSymlink || !link.SymlinkTargetKnown || link.SymlinkTarget != "hello.txt" {
		t.Fatalf("link entry = %+v", link)
	}

	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if got := string(readAll(t, file)); got != "hello world" {
		t.Fatalf("file contents = %q", got)
	}

	symlink, err := volume.OpenSymlink("/link")
	if err != nil {
		t.Fatalf("OpenSymlink: %v", err)
	}
	if got := string(readAll(t, symlink)); got != "hello.txt" {
		t.Fatalf("symlink target = %q", got)
	}

	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrNotAFile) {
		t.Fatalf("OpenFile(directory) = %v, want ErrNotAFile", err)
	}
	if _, err := volume.OpenFile("/link"); !errors.Is(err, ErrNotAFile) {
		t.Fatalf("OpenFile(symlink) = %v, want ErrNotAFile", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("OpenFile(missing) = %v, want ErrPathNotFound", err)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("Stat(missing) = %v, want ErrPathNotFound", err)
	}

	rootEntry, err := volume.Stat("")
	if err != nil {
		t.Fatalf("Stat(root): %v", err)
	}
	if !rootEntry.IsDir || rootEntry.Path != "/" || rootEntry.Name != "/" {
		t.Fatalf("root entry = %+v", rootEntry)
	}
}

func TestV1DirectSingleAndDoubleIndirect(t *testing.T) {
	m := newMinixImage(t, 1, testMagicV1_14, 1024, 32, 64, 6)
	root := m.putDir(6,
		m.entry(1, "."),
		m.entry(1, ".."),
		m.entry(2, "big"),
		m.entry(3, "single"),
		m.entry(4, "link"),
	)
	singleSize := uint32((7 + 1) * 1024)
	doubleSize := uint32((7 + 512 + 1) * 1024)
	m.putData(7, []byte("A"))
	m.putIndirect16(8, []uint16{9})
	m.putData(9, []byte("B"))
	m.putIndirect16(10, []uint16{11})
	m.putIndirect16(11, []uint16{12})
	m.putData(12, []byte("D"))
	m.putData(13, []byte("big"))
	m.putInodeV1(1, 0o040755, 1000, 27, 2, uint32(len(root)), 100, []uint16{6})
	m.putInodeV1(2, 0o100644, 1000, 27, 1, doubleSize, 200, []uint16{7, 0, 0, 0, 0, 0, 0, 0, 10})
	m.putInodeV1(3, 0o100644, 1000, 27, 1, singleSize, 300, []uint16{0, 0, 0, 0, 0, 0, 0, 8})
	m.putInodeV1(4, 0o120777, 1000, 27, 1, 3, 0, []uint16{13})

	volume := mustOpenMinix(t, m)

	big, err := volume.OpenFile("/big")
	if err != nil {
		t.Fatalf("OpenFile big: %v", err)
	}
	if got := string(readAll(t, big)); len(got) != int(doubleSize) || got[0] != 'A' || got[(7+512)*1024] != 'D' {
		t.Fatalf("big file read: len=%d first=%q double=%q", len(got), got[0], got[(7+512)*1024])
	}

	single, err := volume.OpenFile("/single")
	if err != nil {
		t.Fatalf("OpenFile single: %v", err)
	}
	got, err := source.ReadVecAt(single, 7*1024, 1)
	if err != nil {
		t.Fatalf("read single indirect: %v", err)
	}
	if got[0] != 'B' {
		t.Fatalf("single indirect byte = %q, want B", got)
	}
	hole, err := source.ReadVecAt(single, 1024, 1)
	if err != nil {
		t.Fatalf("read hole: %v", err)
	}
	if hole[0] != 0 {
		t.Fatalf("hole byte = %#x, want zero", hole[0])
	}
	extents, err := single.Extents(1024, 1)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(extents) != 1 || extents[0].Kind != source.RangeZero {
		t.Fatalf("hole extents = %+v", extents)
	}
}

func TestV2DoubleAndTripleIndirect(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	// Direct zone 0 -> A. Single indirect is absent. Double indirect's first
	// entry names data. Triple indirect is a three-level chain.
	const tripleBase = 7 + 256 + 65536
	tripleSize := uint32((tripleBase + 1) * 1024)
	root := m.putDir(6,
		m.entry(1, "."),
		m.entry(1, ".."),
		m.entry(2, "chatty"),
	)
	m.putData(7, []byte("A"))
	m.putIndirect(8, []uint32{9})  // triple table
	m.putIndirect(9, []uint32{10}) // double table
	m.putIndirect(10, []uint32{11})
	m.putData(11, []byte("T"))
	m.putInodeV2(1, 0o040755, 2, 0, 0, uint32(len(root)), 0, 0, 0, []uint32{6})
	m.putInodeV2(2, 0o100644, 1, 0, 0, tripleSize, 0, 0, 0, []uint32{7, 0, 0, 0, 0, 0, 0, 0, 0, 8})

	volume := mustOpenMinix(t, m)
	file, err := volume.OpenFile("/chatty")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got, err := source.ReadVecAt(file, tripleBase*1024, 1)
	if err != nil {
		t.Fatalf("read triple indirect: %v", err)
	}
	if got[0] != 'T' {
		t.Fatalf("triple indirect byte = %q, want T", got)
	}
	first, err := source.ReadVecAt(file, 0, 1)
	if err != nil {
		t.Fatalf("read direct: %v", err)
	}
	if first[0] != 'A' {
		t.Fatalf("direct byte = %q, want A", first[0])
	}
}

func TestV3FourByteDirectoryInodeNumbers(t *testing.T) {
	const ninodes = 70000
	m := newMinixImage(t, 3, testMagicV3, 4096, ninodes, 1200, 1098)
	root := m.putDir(1098,
		m.entry(1, "."),
		m.entry(1, ".."),
		m.entry(70000, "large"),
	)
	m.putData(1099, []byte("X"))
	m.putInodeV2(1, 0o040755, 2, 0, 0, uint32(len(root)), 0, 0, 0, []uint32{1098})
	m.putInodeV2(70000, 0o100644, 1, 0, 0, 1, 0, 0, 0, []uint32{1099})

	volume := mustOpenMinix(t, m)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	assertNames(t, entries, "large")
	if entries[0].InodeNumber != 70000 {
		t.Fatalf("inode number = %d, want 70000", entries[0].InodeNumber)
	}
	file, err := volume.OpenFile("/large")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if got := string(readAll(t, file)); got != "X" {
		t.Fatalf("contents = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Holes, allocation and extents

func TestHolesReadZeroAndExtentsMapData(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	root := m.putDir(6, m.entry(1, "."), m.entry(1, ".."), m.entry(2, "sparse"))
	m.putData(7, []byte("D"))
	m.putInodeV2(1, 0o040755, 2, 0, 0, uint32(len(root)), 0, 0, 0, []uint32{6})
	// Three zones: data, hole, data.
	m.putInodeV2(2, 0o100644, 1, 0, 0, 3*1024, 0, 0, 0, []uint32{7, 0, 8})
	m.putData(8, []byte("E"))

	volume := mustOpenMinix(t, m)
	file, err := volume.OpenFile("/sparse")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got, err := source.ReadVecAt(file, 0, 3*1024)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got[0] != 'D' || got[1024] != 0 || got[2*1024] != 'E' {
		t.Fatalf("sparse read = %q/%#x/%q", got[0], got[1024], got[2*1024])
	}
	extents, err := file.Extents(0, 3*1024)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(extents) != 3 {
		t.Fatalf("extents = %+v", extents)
	}
	if extents[0].Kind != source.RangeData || extents[1].Kind != source.RangeZero || extents[2].Kind != source.RangeData {
		t.Fatalf("extent kinds = %+v", extents)
	}
	entry, err := volume.Stat("/sparse")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !entry.AllocatedKnown || entry.Allocated != 2*1024 {
		t.Fatalf("allocated = %+v", entry)
	}
}

// ---------------------------------------------------------------------------
// Corruption and bounds

func TestOutOfRangeInodeIsCountedNotListed(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	root := m.putDir(6,
		m.entry(1, "."),
		m.entry(1, ".."),
		m.entry(999, "ghost"),
		m.entry(2, "real"),
	)
	m.putData(7, []byte("R"))
	m.putInodeV2(1, 0o040755, 2, 0, 0, uint32(len(root)), 0, 0, 0, []uint32{6})
	m.putInodeV2(2, 0o100644, 1, 0, 0, 1, 0, 0, 0, []uint32{7})

	volume := mustOpenMinix(t, m)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	assertNames(t, entries, "real")
	if volume.Info().Undecodable != 1 {
		t.Fatalf("Undecodable = %d, want 1", volume.Info().Undecodable)
	}
}

func TestMalformedAndEmptyDirectorySlotsAreCounted(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	var raw []byte
	raw = append(raw, m.entry(1, ".")...)
	raw = append(raw, m.entry(1, "..")...)
	raw = append(raw, m.entry(2, "ok")...)
	raw = append(raw, m.entry(0, "")...) // empty slot
	raw = append(raw, m.entry(5, "")...) // non-zero inode, empty name
	raw = append(raw, 0xAA)              // partial tail
	m.putData(6, raw)
	m.putData(7, []byte("K"))
	m.putInodeV2(1, 0o040755, 2, 0, 0, uint32(len(raw)), 0, 0, 0, []uint32{6})
	m.putInodeV2(2, 0o100644, 1, 0, 0, 1, 0, 0, 0, []uint32{7})

	volume := mustOpenMinix(t, m)
	info := volume.Info()
	if info.EmptySlots != 1 || info.MalformedSlots != 2 {
		t.Fatalf("slots = empty %d malformed %d", info.EmptySlots, info.MalformedSlots)
	}
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	assertNames(t, entries, "ok")
}

func TestFilePointingAtMetadataZoneIsUndecodable(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	root := m.putDir(6, m.entry(1, "."), m.entry(1, ".."), m.entry(2, "bad"))
	m.putInodeV2(1, 0o040755, 2, 0, 0, uint32(len(root)), 0, 0, 0, []uint32{6})
	// Zone 2 is metadata, below s_firstdatazone.
	m.putInodeV2(2, 0o100644, 1, 0, 0, 512, 0, 0, 0, []uint32{2})

	volume := mustOpenMinix(t, m)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	assertNames(t, entries, "bad")
	if entries[0].AllocatedKnown {
		t.Fatalf("allocation = %+v, want unknown", entries[0])
	}
	if volume.Info().Undecodable != 1 {
		t.Fatalf("Undecodable = %d, want 1", volume.Info().Undecodable)
	}
	if _, err := volume.OpenFile("/bad"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("OpenFile error = %v, want ErrCorrupt", err)
	}
}

func TestCorruptRootInodeIsAnEOF(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	// inode 1 starts at block 4; cutting there removes the whole table.
	_, err := Open(source.NewMemorySource(1, m.data[:4*1024]))
	if !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("Open error = %v, want ErrUnexpectedEOF", err)
	}
}

func TestOversizedDirectoryIsCountedUnreadable(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	m.putInodeV2(1, 0o040755, 2, 0, 0, 64*1024*1024+1, 0, 0, 0, []uint32{6})
	volume := mustOpenMinix(t, m)
	info := volume.Info()
	if info.Unreadable != 1 {
		t.Fatalf("Unreadable = %d, want 1", info.Unreadable)
	}
	if info.Entries != 1 {
		t.Fatalf("Entries = %d, want only the root", info.Entries)
	}
}

func TestOversizedSymlinkTargetIsUndecodable(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	root := m.putDir(6, m.entry(1, "."), m.entry(1, ".."), m.entry(2, "huge"))
	m.putInodeV2(1, 0o040755, 2, 0, 0, uint32(len(root)), 0, 0, 0, []uint32{6})
	m.putInodeV2(2, 0o120777, 1, 0, 0, 5000, 0, 0, 0, []uint32{7, 8, 9, 10, 11})

	volume := mustOpenMinix(t, m)
	entry, err := volume.Stat("/huge")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !entry.IsSymlink {
		t.Fatalf("entry = %+v", entry)
	}
	if entry.SymlinkTargetKnown {
		t.Fatalf("target = %q, want unknown", entry.SymlinkTarget)
	}
	if volume.Info().Undecodable != 1 {
		t.Fatalf("Undecodable = %d, want 1", volume.Info().Undecodable)
	}
}

func TestDirectoryLoopIsListedButNotWalkedTwice(t *testing.T) {
	m := newMinixImage(t, 2, testMagicV2_30, 1024, 32, 64, 6)
	root := m.putDir(6,
		m.entry(1, "."),
		m.entry(1, ".."),
		m.entry(3, "sub"),
		m.entry(3, "sub-again"),
	)
	sub := m.putDir(7, m.entry(3, "."), m.entry(1, ".."))
	m.putInodeV2(1, 0o040755, 2, 0, 0, uint32(len(root)), 0, 0, 0, []uint32{6})
	m.putInodeV2(3, 0o040755, 2, 0, 0, uint32(len(sub)), 0, 0, 0, []uint32{7})

	volume := mustOpenMinix(t, m)
	info := volume.Info()
	if info.DirectoryLoops != 1 {
		t.Fatalf("DirectoryLoops = %d, want 1", info.DirectoryLoops)
	}
	again, err := volume.ListDir("/sub-again")
	if err != nil {
		t.Fatalf("ListDir(sub-again): %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second directory name was walked: %v", entryNames(again))
	}
}

func TestNormalizePath(t *testing.T) {
	if got := normalizePath(""); got != "/" {
		t.Fatalf("normalizePath(\"\") = %q", got)
	}
	if got := normalizePath("a/../b"); got != "/b" {
		t.Fatalf("normalizePath = %q", got)
	}
}
