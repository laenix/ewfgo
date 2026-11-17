package sysv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Test-side layout identifiers.
const (
	testKindCoherent = 0
	testKindXenix    = 1
	testKindSysV2    = 2
	testKindSysV4    = 4

	testOrderLittle = 0
	testOrderBig    = 1
	testOrderPDP    = 2
)

const (
	testSysVMagic   = 0xfd187e20
	testXenixMagic  = 0x002b5544
	testJan11980    = 3652 * 24 * 60 * 60
	testSysV4Clean  = 0x7c269d38
	testSysV2Clean  = 0xcb096f43
	testAFSMarker16 = 0xffff
)

type sysvImage struct {
	t     *testing.T
	data  []byte
	kind  int
	order int
	block int
	isize int
	fsize int

	sbOffset int

	// Offsets of the fields this fixture manipulates after construction.
	nfreeOffset int
	freeOffset  int
	tfreeOffset int
	timeOffset  int
	stateOffset int
	fnameOffset int
	fpackOffset int
}

func blockType(block int) uint32 {
	switch block {
	case 512:
		return 1
	case 1024:
		return 2
	case 2048:
		return 3
	default:
		return 0
	}
}

func newSysVImage(t *testing.T, kind, order, block, isize, fsize int) *sysvImage {
	t.Helper()
	m := &sysvImage{
		t:     t,
		data:  make([]byte, fsize*block),
		kind:  kind,
		order: order,
		block: block,
		isize: isize,
		fsize: fsize,
	}
	switch kind {
	case testKindSysV4:
		m.sbOffset = 512
		m.nfreeOffset = 8
		m.freeOffset = 12
		m.tfreeOffset = 432
		m.timeOffset = 420
		m.stateOffset = 500
		m.fnameOffset = 440
		m.fpackOffset = 446
		m.put16(0, uint16(isize))
		m.put32(4, uint32(fsize))
		m.put32(420, 1_700_000_000)
		m.put32(500, 0)
		m.put32(504, testSysVMagic)
		m.put32(508, blockType(block))
		m.put16(436, 0)
	case testKindSysV2:
		m.sbOffset = 512
		m.nfreeOffset = 6
		m.freeOffset = 8
		m.tfreeOffset = 426
		m.timeOffset = 414
		m.stateOffset = 500
		m.fnameOffset = 432
		m.fpackOffset = 438
		m.put16(0, uint16(isize))
		m.put32(2, uint32(fsize))
		m.put32(414, 100)
		// Release 2 is selected by the Release 4 time offset, so both carry a
		// pre-1980 value.
		m.put32(420, 100)
		m.put32(500, 0)
		m.put32(504, testSysVMagic)
		m.put32(508, blockType(block))
		m.put16(430, 0)
	case testKindXenix:
		m.sbOffset = 1024
		m.nfreeOffset = 6
		m.freeOffset = 8
		m.tfreeOffset = 618
		m.timeOffset = 614
		m.stateOffset = -1
		m.fnameOffset = 632
		m.fpackOffset = 638
		m.put16(0, uint16(isize))
		m.put32(2, uint32(fsize))
		m.put32(614, 1_700_000_000)
		m.put16(622, 0)
		m.put32(1016, testXenixMagic)
		m.put32(1020, blockType(block))
	case testKindCoherent:
		m.sbOffset = 512
		m.nfreeOffset = 6
		m.freeOffset = 8
		m.tfreeOffset = 474
		m.timeOffset = 470
		m.stateOffset = -1
		m.fnameOffset = 484
		m.fpackOffset = 490
		m.put16(0, uint16(isize))
		m.put32(2, uint32(fsize))
		m.put32(470, 1_700_000_000)
		m.put16(478, 0)
		m.setNamesBytes("noname", "nopack")
	default:
		t.Fatalf("unknown test kind %d", kind)
	}
	return m
}

func (m *sysvImage) put16(offset int, value uint16) {
	at := m.sbOffset + offset
	switch m.order {
	case testOrderBig:
		binary.BigEndian.PutUint16(m.data[at:], value)
	default:
		binary.LittleEndian.PutUint16(m.data[at:], value)
	}
}

func (m *sysvImage) put32(offset int, value uint32) {
	at := m.sbOffset + offset
	value = m.encode32(value)
	switch m.order {
	case testOrderBig:
		binary.BigEndian.PutUint32(m.data[at:], value)
	default:
		binary.LittleEndian.PutUint32(m.data[at:], value)
	}
}

func (m *sysvImage) encode32(value uint32) uint32 {
	if m.order == testOrderPDP {
		return bits.RotateLeft32(value, 16)
	}
	return value
}

func (m *sysvImage) ptr24(value uint32) [3]byte {
	switch m.order {
	case testOrderBig:
		return [3]byte{byte(value >> 16), byte(value >> 8), byte(value)}
	case testOrderPDP:
		return [3]byte{byte(value >> 16), byte(value), byte(value >> 8)}
	default:
		return [3]byte{byte(value), byte(value >> 8), byte(value >> 16)}
	}
}

func (m *sysvImage) setFree(zones ...uint32) {
	m.put16(m.nfreeOffset, uint16(len(zones)))
	at := m.sbOffset + m.freeOffset
	for index := 0; index < 100; index++ {
		m.data[at+index*4] = 0
		m.data[at+index*4+1] = 0
		m.data[at+index*4+2] = 0
		m.data[at+index*4+3] = 0
	}
	for index, zone := range zones {
		raw := m.encode32(zone)
		switch m.order {
		case testOrderBig:
			binary.BigEndian.PutUint32(m.data[at+index*4:], raw)
		default:
			binary.LittleEndian.PutUint32(m.data[at+index*4:], raw)
		}
	}
}

func (m *sysvImage) setTFree(value uint32) { m.put32(m.tfreeOffset, value) }

func (m *sysvImage) setState(value uint32) { m.put32(m.stateOffset, value) }

func (m *sysvImage) setNamesBytes(volume, pack string) {
	for index, field := range []struct {
		at   int
		text string
	}{{m.fnameOffset, volume}, {m.fpackOffset, pack}} {
		_ = index
		for i := 0; i < 6; i++ {
			m.data[m.sbOffset+field.at+i] = ' '
		}
		copy(m.data[m.sbOffset+field.at:], field.text)
	}
}

func (m *sysvImage) inodeOffset(number int) int {
	return 2*m.block + (number-1)*64
}

func (m *sysvImage) putInode(number int, mode, nlink, uid, gid uint16, size uint32, generation uint8, times [3]uint32, pointers []uint32) {
	m.t.Helper()
	at := m.inodeOffset(number)
	b := m.data[at : at+64]
	m.put16At(b, 0, mode)
	m.put16At(b, 2, nlink)
	m.put16At(b, 4, uid)
	m.put16At(b, 6, gid)
	m.put32At(b, 8, size)
	for index, pointer := range pointers {
		if index >= 13 {
			break
		}
		raw := m.ptr24(pointer)
		copy(b[12+index*3:], raw[:])
	}
	b[51] = generation
	for index, seconds := range times {
		m.put32At(b, 52+index*4, seconds)
	}
}

func (m *sysvImage) put16At(dst []byte, at int, value uint16) {
	switch m.order {
	case testOrderBig:
		binary.BigEndian.PutUint16(dst[at:], value)
	default:
		binary.LittleEndian.PutUint16(dst[at:], value)
	}
}

func (m *sysvImage) put32At(dst []byte, at int, value uint32) {
	value = m.encode32(value)
	switch m.order {
	case testOrderBig:
		binary.BigEndian.PutUint32(dst[at:], value)
	default:
		binary.LittleEndian.PutUint32(dst[at:], value)
	}
}

func (m *sysvImage) entry(inode int, name string) []byte {
	m.t.Helper()
	if len(name) > 14 {
		m.t.Fatalf("test name %q is longer than 14 bytes", name)
	}
	out := make([]byte, 16)
	m.put16At(out, 0, uint16(inode))
	copy(out[2:], name)
	return out
}

func (m *sysvImage) putDir(zone int, entries ...[]byte) []byte {
	m.t.Helper()
	var out []byte
	for _, entry := range entries {
		out = append(out, entry...)
	}
	copy(m.data[zone*m.block:], out)
	return out
}

func (m *sysvImage) putData(zone int, contents []byte) {
	m.t.Helper()
	copy(m.data[zone*m.block:], contents)
}

func (m *sysvImage) putIndirect(zone int, entries []uint32) {
	m.t.Helper()
	at := zone * m.block
	for index, entry := range entries {
		raw := m.encode32(entry)
		switch m.order {
		case testOrderBig:
			binary.BigEndian.PutUint32(m.data[at+index*4:], raw)
		default:
			binary.LittleEndian.PutUint32(m.data[at+index*4:], raw)
		}
	}
}

func (m *sysvImage) source() source.ByteSource {
	return source.NewMemorySource(1, m.data)
}

func (m *sysvImage) open() (*Volume, error) { return Open(m.source()) }

func mustOpenSysV(t *testing.T, m *sysvImage) *Volume {
	t.Helper()
	volume, err := m.open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func readAllSysV(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	out, err := io.ReadAll(io.NewSectionReader(source.ReaderAt(src), 0, int64(src.Len())))
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	return out
}

func sysvNames(entries []Entry) []string {
	out := make([]string, len(entries))
	for index, entry := range entries {
		out[index] = entry.Name
	}
	return out
}

func assertSysvNames(t *testing.T, got []Entry, want ...string) {
	t.Helper()
	names := sysvNames(got)
	if len(names) != len(want) {
		t.Fatalf("entries = %v, want %v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("entries = %v, want %v", names, want)
		}
	}
}

// emptyRoot writes a zero-length root directory inode.
func (m *sysvImage) emptyRoot() {
	m.putInode(2, 0o040755, 2, 0, 0, 0, 0, [3]uint32{}, nil)
}

// buildTree writes the standard tree shared by the variant tests: a regular
// file, a subdirectory with a hard-linked name, an empty directory and a
// symlink.
func (m *sysvImage) buildTree() {
	rootZone := m.isize
	fileZone := rootZone + 1
	subZone := rootZone + 2
	linkZone := rootZone + 3
	sharedZone := rootZone + 4
	root := m.putDir(rootZone,
		m.entry(2, "."),
		m.entry(2, ".."),
		m.entry(3, "file.txt"),
		m.entry(4, "sub"),
		m.entry(5, "empty"),
		m.entry(6, "link"),
		m.entry(7, "abcdefghijklmn"),
	)
	sub := m.putDir(subZone,
		m.entry(4, "."),
		m.entry(2, ".."),
		m.entry(7, "inner.txt"),
	)
	m.putData(fileZone, []byte("file"))
	m.putData(sharedZone, []byte("shared"))
	m.putData(linkZone, []byte("file.txt"))
	m.putInode(2, 0o040755, 3, 1000, 27, uint32(len(root)), 1, [3]uint32{1_700_000_001, 1_700_000_002, 1_700_000_003}, []uint32{uint32(rootZone)})
	m.putInode(3, 0o100644, 1, 1000, 27, 4, 2, [3]uint32{0, 1_700_000_010, 0}, []uint32{uint32(fileZone)})
	m.putInode(4, 0o040755, 2, 1000, 27, uint32(len(sub)), 3, [3]uint32{}, []uint32{uint32(subZone)})
	m.putInode(5, 0o040755, 2, 1000, 27, 0, 4, [3]uint32{}, nil)
	m.putInode(6, 0o120777, 1, 1000, 27, 8, 5, [3]uint32{}, []uint32{uint32(linkZone)})
	m.putInode(7, 0o100600, 2, 1000, 27, 6, 6, [3]uint32{}, []uint32{uint32(sharedZone)})
}

// ---------------------------------------------------------------------------
// Detection

func TestDetectVariants(t *testing.T) {
	cases := []struct {
		name  string
		kind  int
		order int
		block int
		isize int
		fsize int
		setup func(*sysvImage)
		wantV string
		wantO string
	}{
		{"sysv4 little", testKindSysV4, testOrderLittle, 1024, 5, 64, nil, "System V Release 4", "little-endian"},
		{"sysv4 big", testKindSysV4, testOrderBig, 1024, 5, 64, nil, "System V Release 4", "big-endian"},
		{"sysv2 little", testKindSysV2, testOrderLittle, 1024, 5, 64, nil, "System V Release 2", "little-endian"},
		{"sysv2 big", testKindSysV2, testOrderBig, 1024, 5, 64, nil, "System V Release 2", "big-endian"},
		{"xenix little", testKindXenix, testOrderLittle, 1024, 4, 32, nil, "Xenix", "little-endian"},
		{"xenix big", testKindXenix, testOrderBig, 1024, 4, 32, nil, "Xenix", "big-endian"},
		{"coherent", testKindCoherent, testOrderPDP, 512, 4, 32, nil, "Coherent", "PDP-endian"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newSysVImage(t, tc.kind, tc.order, tc.block, tc.isize, tc.fsize)
			if tc.setup != nil {
				tc.setup(m)
			}
			m.emptyRoot()
			ok, err := Detect(m.source())
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if !ok {
				t.Fatal("Detect = false, want true")
			}
			volume := mustOpenSysV(t, m)
			info := volume.Info()
			if info.Variant != tc.wantV || info.ByteOrder != tc.wantO {
				t.Fatalf("variant/order = %q/%q", info.Variant, info.ByteOrder)
			}
		})
	}
}

func TestDetectRelease2VersusRelease4(t *testing.T) {
	// A pre-1980 update time at the Release 4 offset selects Release 2.
	m := newSysVImage(t, testKindSysV2, testOrderLittle, 1024, 5, 64)
	m.emptyRoot()
	volume := mustOpenSysV(t, m)
	if volume.Info().Variant != "System V Release 2" {
		t.Fatalf("variant = %q", volume.Info().Variant)
	}
	// A post-1980 value at the same offset selects Release 4 exactly as Linux
	// does, even on an image whose other fields were written in the Release 2
	// layout. Detection is the discriminator; the geometry is then read at the
	// Release 4 offsets, as Linux reads it, so only detection is asserted here.
	m2 := newSysVImage(t, testKindSysV2, testOrderLittle, 1024, 5, 64)
	m2.put32(420, 1_700_000_000)
	found, err := detectSuperblock(m2.source())
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if found == nil || found.variant != variantSysV4 {
		t.Fatalf("detection = %+v, want Release 4", found)
	}
}

func TestDetectAFSMarker(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	m.emptyRoot()
	m.put16(8, testAFSMarker16)
	volume := mustOpenSysV(t, m)
	if !volume.Info().AFS {
		t.Fatal("Info.AFS = false, want true")
	}
	if _, err := volume.FreeList(); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("FreeList error = %v, want ErrUnsupported", err)
	}
}

func TestDetectCoherentAlternateNames(t *testing.T) {
	for _, names := range [][2]string{{"noname", "nopack"}, {"xxxxx ", "xxxxx\n"}} {
		m := newSysVImage(t, testKindCoherent, testOrderPDP, 512, 4, 32)
		m.emptyRoot()
		m.setNamesBytes(names[0], names[1])
		ok, err := Detect(m.source())
		if err != nil || !ok {
			t.Fatalf("names %q/%q: Detect = %v, %v", names[0], names[1], ok, err)
		}
	}
}

func TestDetectUnknown(t *testing.T) {
	ok, err := Detect(source.NewMemorySource(1, make([]byte, 100)))
	if err != nil || ok {
		t.Fatalf("short: %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, make([]byte, 4096)))
	if err != nil || ok {
		t.Fatalf("blank: %v, %v", ok, err)
	}
}

// ---------------------------------------------------------------------------
// Superblock

func TestSuperblockGeometryAndCleanState(t *testing.T) {
	t.Run("sysv4", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.setNamesBytes("vol1", "pk1")
		m.setState(testSysV4Clean - 1_700_000_000)
		info := mustOpenSysV(t, m).Info()
		if info.BlockSize != 1024 || info.FirstDataZone != 5 || info.Zones != 64 || info.InodeCount != 48 {
			t.Fatalf("geometry = %+v", info)
		}
		if !info.HasMagic || info.Magic != testSysVMagic {
			t.Fatalf("magic = %+v", info)
		}
		if info.VolumeName != "vol1" || info.PackName != "pk1" {
			t.Fatalf("names = %+v", info)
		}
		if !info.CleanKnown || !info.Clean {
			t.Fatalf("clean = %v/%v", info.CleanKnown, info.Clean)
		}
		if info.InodeTableBlock != 2 || info.NameLength != 14 || info.DirEntrySize != 16 {
			t.Fatalf("layout = %+v", info)
		}
	})
	t.Run("sysv2 clean", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV2, testOrderBig, 1024, 5, 64)
		m.emptyRoot()
		m.setState(testSysV2Clean)
		info := mustOpenSysV(t, m).Info()
		if !info.CleanKnown || !info.Clean {
			t.Fatalf("clean = %v/%v", info.CleanKnown, info.Clean)
		}
	})
	t.Run("block sizes", func(t *testing.T) {
		for _, block := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprint(block), func(t *testing.T) {
				isize := 6
				fsize := 64
				if block == 2048 {
					isize, fsize = 3, 16
				}
				m := newSysVImage(t, testKindSysV4, testOrderLittle, block, isize, fsize)
				m.emptyRoot()
				info := mustOpenSysV(t, m).Info()
				if info.BlockSize != uint32(block) {
					t.Fatalf("BlockSize = %d, want %d", info.BlockSize, block)
				}
				wantInodes := uint32((isize - 2) * (block / 64))
				if info.InodeCount != wantInodes {
					t.Fatalf("InodeCount = %d, want %d", info.InodeCount, wantInodes)
				}
			})
		}
	})
}

func TestSuperblockRefusals(t *testing.T) {
	t.Run("no signature", func(t *testing.T) {
		_, err := Open(source.NewMemorySource(1, make([]byte, 4096)))
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})
	t.Run("isc long names", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.put32(508, 0x20)
		_, err := m.open()
		if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "unverified-inode-layout") {
			t.Fatalf("Open error = %v", err)
		}
	})
	t.Run("unknown s_type", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.put32(508, 7)
		_, err := m.open()
		if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "unsupported-sysv-variant") {
			t.Fatalf("Open error = %v", err)
		}
	})
	t.Run("xenix 512-byte blocks", func(t *testing.T) {
		m := newSysVImage(t, testKindXenix, testOrderLittle, 1024, 4, 32)
		m.emptyRoot()
		m.put32(1020, 1)
		_, err := m.open()
		if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "unverified-inode-layout") {
			t.Fatalf("Open error = %v", err)
		}
	})
	t.Run("backwards geometry", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.put32(4, 5)
		_, err := m.open()
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "bad-sysv-superblock") {
			t.Fatalf("Open error = %v", err)
		}
	})
	t.Run("no inode table", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 2, 64)
		m.emptyRoot()
		_, err := m.open()
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v", err)
		}
	})
	t.Run("tfree past the volume", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.setTFree(65)
		_, err := m.open()
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v", err)
		}
	})
	t.Run("non-directory root", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.putInode(2, 0o100644, 1, 0, 0, 0, 0, [3]uint32{}, nil)
		_, err := m.open()
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want ErrCorrupt", err)
		}
	})
	t.Run("truncated root inode", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		_, err := Open(source.NewMemorySource(1, m.data[:2100]))
		if !errors.Is(err, source.ErrUnexpectedEOF) {
			t.Fatalf("Open error = %v, want ErrUnexpectedEOF", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Listings and file data

func TestVariantTrees(t *testing.T) {
	cases := []struct {
		name  string
		kind  int
		order int
		block int
		isize int
		fsize int
	}{
		{"sysv4 little", testKindSysV4, testOrderLittle, 1024, 5, 64},
		{"sysv4 big", testKindSysV4, testOrderBig, 1024, 5, 64},
		{"sysv2 little", testKindSysV2, testOrderLittle, 1024, 5, 64},
		{"sysv2 big", testKindSysV2, testOrderBig, 1024, 5, 64},
		{"xenix little", testKindXenix, testOrderLittle, 1024, 4, 32},
		{"xenix big", testKindXenix, testOrderBig, 1024, 4, 32},
		{"coherent", testKindCoherent, testOrderPDP, 512, 4, 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newSysVImage(t, tc.kind, tc.order, tc.block, tc.isize, tc.fsize)
			m.buildTree()
			volume := mustOpenSysV(t, m)

			root, err := volume.ListDir("/")
			if err != nil {
				t.Fatalf("ListDir(/): %v", err)
			}
			assertSysvNames(t, root, "file.txt", "sub", "empty", "link", "abcdefghijklmn")
			if root[0].Path != "/file.txt" || !root[0].IsFile {
				t.Fatalf("file entry = %+v", root[0])
			}

			sub, err := volume.ListDir("sub")
			if err != nil {
				t.Fatalf("ListDir(sub): %v", err)
			}
			assertSysvNames(t, sub, "inner.txt")
			if sub[0].Path != "/sub/inner.txt" {
				t.Fatalf("inner path = %q", sub[0].Path)
			}
			empty, err := volume.ListDir("/empty")
			if err != nil || len(empty) != 0 {
				t.Fatalf("ListDir(empty) = %v, %v", sysvNames(empty), err)
			}

			file, err := volume.Stat("/file.txt")
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if file.Mode != 0o100644 || file.UID != 1000 || file.GID != 27 || file.Size != 4 {
				t.Fatalf("file stat = %+v", file)
			}
			if !file.Mtime.Equal(time.Unix(1_700_000_010, 0).UTC()) {
				t.Fatalf("mtime = %v", file.Mtime)
			}
			if !file.AllocatedKnown || file.Allocated != uint64(tc.block) {
				t.Fatalf("allocation = %+v", file)
			}

			// The two names reach one inode: the walk keeps both and the same
			// inode number.
			inner, err := volume.Stat("/sub/inner.txt")
			if err != nil {
				t.Fatalf("Stat inner: %v", err)
			}
			twin, err := volume.Stat("/abcdefghijklmn")
			if err != nil {
				t.Fatalf("Stat twin: %v", err)
			}
			if inner.InodeNumber != twin.InodeNumber {
				t.Fatalf("hard link inode numbers = %d/%d", inner.InodeNumber, twin.InodeNumber)
			}

			link, err := volume.Stat("/link")
			if err != nil {
				t.Fatalf("Stat link: %v", err)
			}
			if !link.IsSymlink || !link.SymlinkTargetKnown || link.SymlinkTarget != "file.txt" {
				t.Fatalf("link = %+v", link)
			}
			target, err := volume.OpenSymlink("/link")
			if err != nil {
				t.Fatalf("OpenSymlink: %v", err)
			}
			if got := string(readAllSysV(t, target)); got != "file.txt" {
				t.Fatalf("target = %q", got)
			}

			opened, err := volume.OpenFile("/file.txt")
			if err != nil {
				t.Fatalf("OpenFile: %v", err)
			}
			if got := string(readAllSysV(t, opened)); got != "file" {
				t.Fatalf("contents = %q", got)
			}
			if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrNotAFile) {
				t.Fatalf("OpenFile(dir) = %v", err)
			}
			if _, err := volume.OpenFile("/nope"); !errors.Is(err, ErrPathNotFound) {
				t.Fatalf("OpenFile(missing) = %v", err)
			}

			info := volume.Info()
			if info.Entries != 7 || info.Directories != 3 || info.Symlinks != 1 {
				t.Fatalf("counts = %+v", info)
			}
			if tc.kind == testKindCoherent {
				if info.VolumeName != "noname" || info.PackName != "nopack" || info.HasMagic {
					t.Fatalf("coherent facts = %+v", info)
				}
			}
		})
	}
}

func TestDirectSingleDoubleAndTripleIndirectReads(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	const tripleBase = 10 + 256 + 65536
	size := uint32((tripleBase + 1) * 1024)
	root := m.putDir(5,
		m.entry(2, "."),
		m.entry(2, ".."),
		m.entry(3, "big"),
	)
	m.putData(6, []byte("A"))
	m.putIndirect(7, []uint32{8})
	m.putData(8, []byte("S"))
	m.putIndirect(9, []uint32{10})
	m.putIndirect(10, []uint32{11})
	m.putData(11, []byte("D"))
	m.putIndirect(12, []uint32{13})
	m.putIndirect(13, []uint32{14})
	m.putIndirect(14, []uint32{15})
	m.putData(15, []byte("T"))
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(root)), 0, [3]uint32{}, []uint32{5})
	pointers := make([]uint32, 13)
	pointers[0] = 6
	pointers[10] = 7
	pointers[11] = 9
	pointers[12] = 12
	m.putInode(3, 0o100644, 1, 0, 0, size, 0, [3]uint32{}, pointers)

	volume := mustOpenSysV(t, m)
	file, err := volume.OpenFile("/big")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	for _, probe := range []struct {
		offset uint64
		want   byte
		label  string
	}{
		{0, 'A', "direct"},
		{10 * 1024, 'S', "single"},
		{266 * 1024, 'D', "double"},
		{tripleBase * 1024, 'T', "triple"},
	} {
		got, err := source.ReadVecAt(file, probe.offset, 1)
		if err != nil {
			t.Fatalf("read %s: %v", probe.label, err)
		}
		if got[0] != probe.want {
			t.Fatalf("%s byte = %q, want %q", probe.label, got[0], probe.want)
		}
	}
	entry, err := volume.Stat("/big")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !entry.AllocatedKnown || entry.Allocated != 4*1024 {
		t.Fatalf("allocation = %+v", entry)
	}
}

func TestSysVHolesAndExtents(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	root := m.putDir(5,
		m.entry(2, "."),
		m.entry(2, ".."),
		m.entry(3, "sparse"),
	)
	m.putData(6, []byte("D"))
	m.putData(7, []byte("E"))
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(root)), 0, [3]uint32{}, []uint32{5})
	m.putInode(3, 0o100644, 1, 0, 0, 3*1024, 0, [3]uint32{}, []uint32{6, 0, 7})

	volume := mustOpenSysV(t, m)
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
	if len(extents) != 3 || extents[1].Kind != source.RangeZero {
		t.Fatalf("extents = %+v", extents)
	}
}

// ---------------------------------------------------------------------------
// Corruption and bounds

func TestOutOfRangeInodeIsCounted(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	root := m.putDir(5,
		m.entry(2, "."),
		m.entry(2, ".."),
		m.entry(9999, "ghost"),
		m.entry(3, "real"),
	)
	m.putData(6, []byte("R"))
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(root)), 0, [3]uint32{}, []uint32{5})
	m.putInode(3, 0o100644, 1, 0, 0, 1, 0, [3]uint32{}, []uint32{6})

	volume := mustOpenSysV(t, m)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	assertSysvNames(t, entries, "real")
	if volume.Info().Undecodable != 1 {
		t.Fatalf("Undecodable = %d, want 1", volume.Info().Undecodable)
	}
}

func TestMalformedAndEmptySlots(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	var raw []byte
	raw = append(raw, m.entry(2, ".")...)
	raw = append(raw, m.entry(2, "..")...)
	raw = append(raw, m.entry(3, "ok")...)
	raw = append(raw, m.entry(0, "")...)
	raw = append(raw, m.entry(4, "")...)
	raw = append(raw, 0xAA)
	m.putDir(5, raw)
	m.putData(6, []byte("K"))
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(raw)), 0, [3]uint32{}, []uint32{5})
	m.putInode(3, 0o100644, 1, 0, 0, 1, 0, [3]uint32{}, []uint32{6})

	volume := mustOpenSysV(t, m)
	info := volume.Info()
	if info.EmptySlots != 1 || info.MalformedSlots != 2 {
		t.Fatalf("slots = empty %d malformed %d", info.EmptySlots, info.MalformedSlots)
	}
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	assertSysvNames(t, entries, "ok")
}

func TestIndirectZoneOutsideDataIsUndecodable(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	root := m.putDir(5, m.entry(2, "."), m.entry(2, ".."), m.entry(3, "bad"))
	pointers := make([]uint32, 13)
	pointers[10] = 3 // metadata zone
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(root)), 0, [3]uint32{}, []uint32{5})
	m.putInode(3, 0o100644, 1, 0, 0, 11*1024, 0, [3]uint32{}, pointers)

	volume := mustOpenSysV(t, m)
	entry, err := volume.Stat("/bad")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if entry.AllocatedKnown {
		t.Fatalf("allocation = %+v, want unknown", entry)
	}
	if volume.Info().Undecodable != 1 {
		t.Fatalf("Undecodable = %d, want 1", volume.Info().Undecodable)
	}
	if _, err := volume.OpenFile("/bad"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("OpenFile error = %v, want ErrCorrupt", err)
	}
}

func TestIndirectLoopIsRefused(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	root := m.putDir(5, m.entry(2, "."), m.entry(2, ".."), m.entry(3, "loop"))
	// Triple: zone 9 -> zone 10 -> zone 9 again.
	m.putIndirect(9, []uint32{10})
	m.putIndirect(10, []uint32{9})
	pointers := make([]uint32, 13)
	pointers[12] = 9
	const tripleBase = 10 + 256 + 65536
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(root)), 0, [3]uint32{}, []uint32{5})
	m.putInode(3, 0o100644, 1, 0, 0, (tripleBase+1)*1024, 0, [3]uint32{}, pointers)

	volume := mustOpenSysV(t, m)
	if volume.Info().Undecodable != 1 {
		t.Fatalf("Undecodable = %d, want 1", volume.Info().Undecodable)
	}
	_, err := volume.OpenFile("/loop")
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("OpenFile error = %v, want a loop refusal", err)
	}
}

func TestFileDataPastSourceFailsOnRead(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	root := m.putDir(5, m.entry(2, "."), m.entry(2, ".."), m.entry(3, "far"))
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(root)), 0, [3]uint32{}, []uint32{5})
	m.putInode(3, 0o100644, 1, 0, 0, 1024, 0, [3]uint32{}, []uint32{63})
	// The metadata and root directory fit; the file's zone does not.
	src := source.NewMemorySource(1, m.data[:6000])
	volume, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	file, err := volume.OpenFile("/far")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := source.ReadVecAt(file, 0, 1); err == nil {
		t.Fatal("read past the source returned no error")
	}
}

func TestBlockMapCapacityIsRefused(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 512, 4, 64)
	root := m.putDir(4, m.entry(2, "."), m.entry(2, ".."), m.entry(3, "huge"))
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(root)), 0, [3]uint32{}, []uint32{4})
	m.putInode(3, 0o100644, 1, 0, 0, 0xFFFF_FFFF, 0, [3]uint32{}, nil)

	volume := mustOpenSysV(t, m)
	entry, err := volume.Stat("/huge")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if entry.AllocatedKnown {
		t.Fatalf("allocation = %+v, want unknown", entry)
	}
	if _, err := volume.OpenFile("/huge"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("OpenFile error = %v, want ErrCorrupt", err)
	}
}

func TestDirectoryLoopIsListedButNotWalkedTwice(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	root := m.putDir(5,
		m.entry(2, "."),
		m.entry(2, ".."),
		m.entry(4, "sub"),
		m.entry(4, "sub-again"),
	)
	sub := m.putDir(6, m.entry(4, "."), m.entry(2, ".."))
	m.putInode(2, 0o040755, 2, 0, 0, uint32(len(root)), 0, [3]uint32{}, []uint32{5})
	m.putInode(4, 0o040755, 2, 0, 0, uint32(len(sub)), 0, [3]uint32{}, []uint32{6})

	volume := mustOpenSysV(t, m)
	if volume.Info().DirectoryLoops != 1 {
		t.Fatalf("DirectoryLoops = %d, want 1", volume.Info().DirectoryLoops)
	}
	again, err := volume.ListDir("/sub-again")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second directory name was walked: %v", sysvNames(again))
	}
}

// ---------------------------------------------------------------------------
// Free list and free-space map

func TestFreeListWalksTheChain(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	m.emptyRoot()
	m.setFree(5, 6)
	m.setTFree(3)
	// Zone 5 is a continuation chunk: count 2 at byte zero, entries at byte
	// four for Release 4. Entry 0 is the terminator, entry 1 is zone 7.
	at := 5 * 1024
	binary.LittleEndian.PutUint16(m.data[at:], 2)
	binary.LittleEndian.PutUint32(m.data[at+4:], 0)
	binary.LittleEndian.PutUint32(m.data[at+8:], 7)
	volume := mustOpenSysV(t, m)
	list, err := volume.FreeList()
	if err != nil {
		t.Fatalf("FreeList: %v", err)
	}
	want := []uint32{6, 5, 7}
	if len(list.Zones) != len(want) {
		t.Fatalf("zones = %v, want %v", list.Zones, want)
	}
	for index := range want {
		if list.Zones[index] != want[index] {
			t.Fatalf("zones = %v, want %v", list.Zones, want)
		}
	}
	if list.Chunks != 1 || list.Declared != 3 {
		t.Fatalf("chunks/declared = %d/%d", list.Chunks, list.Declared)
	}
	if list.FreeBytes(1024) != 3*1024 {
		t.Fatalf("FreeBytes = %d", list.FreeBytes(1024))
	}
}

func TestFreeSpaceMap(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	m.emptyRoot()
	m.setFree(5, 6)
	m.setTFree(3)
	at := 5 * 1024
	binary.LittleEndian.PutUint16(m.data[at:], 2)
	binary.LittleEndian.PutUint32(m.data[at+4:], 0)
	binary.LittleEndian.PutUint32(m.data[at+8:], 7)
	volume := mustOpenSysV(t, m)
	space, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if space.FreeBytes() != 3*1024 {
		t.Fatalf("FreeBytes = %d, want %d", space.FreeBytes(), 3*1024)
	}
	if space.AreaStart() != 5*1024 || space.Covered() != 64*1024 {
		t.Fatalf("area = %d..%d", space.AreaStart(), space.Covered())
	}
	if space.Basis() != "sysv.free_list" {
		t.Fatalf("basis = %q", space.Basis())
	}
	// Zones 5, 6 and 7 are contiguous, so the map merges them.
	if space.RunCount() != 1 || !space.IsFree(5*1024, 3*1024) {
		t.Fatalf("runs = %+v", space.Runs())
	}
	notes := space.Notes()
	if len(notes) != 1 || !strings.Contains(notes[0], "1 chunk block") {
		t.Fatalf("notes = %v", notes)
	}
}

func TestFreeSpaceNotesDeclaredMismatch(t *testing.T) {
	m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
	m.emptyRoot()
	m.setFree(5, 6)
	m.setTFree(9)
	volume := mustOpenSysV(t, m)
	space, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	found := false
	for _, note := range space.Notes() {
		if strings.Contains(note, "declares 9 free blocks") {
			found = true
		}
	}
	if !found {
		t.Fatalf("notes = %v, want the declared-count mismatch", space.Notes())
	}
}

func TestFreeListRefusals(t *testing.T) {
	t.Run("count above the chunk size", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.put16(8, 51)
		volume := mustOpenSysV(t, m)
		if _, err := volume.FreeList(); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "corrupted-sysv-free-list") {
			t.Fatalf("FreeList error = %v", err)
		}
	})
	t.Run("zone outside data", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.setFree(5, 3)
		volume := mustOpenSysV(t, m)
		if _, err := volume.FreeList(); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("FreeList error = %v", err)
		}
	})
	t.Run("repeated zone is a loop", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.setFree(5, 5)
		volume := mustOpenSysV(t, m)
		_, err := volume.FreeList()
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "loop") {
			t.Fatalf("FreeList error = %v", err)
		}
	})
	t.Run("continuation past the source", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.setFree(40)
		volume := mustOpenSysV(t, m)
		src := source.NewMemorySource(1, m.data[:40*1024])
		if _, err := freeWalk(volume.superblock, src); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("walk error = %v", err)
		}
	})
	t.Run("afs bitmap", func(t *testing.T) {
		m := newSysVImage(t, testKindSysV4, testOrderLittle, 1024, 5, 64)
		m.emptyRoot()
		m.put16(8, testAFSMarker16)
		volume := mustOpenSysV(t, m)
		if _, err := volume.FreeSpace(); !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("FreeSpace error = %v, want ErrUnsupported", err)
		}
	})
}
