package hammer2

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- fixture helpers -------------------------------------------------------

const (
	testVolSize   = 8 << 20 // volu_size must be 8 MiB aligned
	testImageSize = 1 << 20 // the source only needs to hold the structures
	testRootOff   = 0x10000
)

func putLE16(dst []byte, at int, value uint16) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
}

func putLE32(dst []byte, at int, value uint32) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
	dst[at+2] = byte(value >> 16)
	dst[at+3] = byte(value >> 24)
}

func putLE64(dst []byte, at int, value uint64) {
	putLE32(dst, at, uint32(value))
	putLE32(dst, at+4, uint32(value>>32))
}

// sealH2 recomputes the three volume-header CRCs in writer order.
func sealH2(img []byte) {
	sect1 := foundation.CRC32C(img[512 : 512+512])
	putLE32(img, ICRCSect1At, sect1)
	sect0 := foundation.CRC32C(img[0:508])
	putLE32(img, ICRCSect0At, sect0)
	whole := foundation.CRC32C(img[0:65532])
	putLE32(img, ICRCVolhdrAt, whole)
}

func refBytes(btype, methods byte, key, dataOff uint64, flags byte, embed, check []byte) []byte {
	out := make([]byte, BlockrefBytes)
	out[0x00] = btype
	out[0x01] = methods
	out[0x02] = 255
	out[0x05] = flags
	putLE64(out, 0x08, key)
	putLE64(out, 0x10, 1)
	putLE64(out, 0x18, 1)
	putLE64(out, 0x20, dataOff)
	putLE64(out, 0x28, 1)
	copy(out[0x30:0x40], embed)
	copy(out[0x40:0x80], check)
	return out
}

func blocksetBytes(refs ...[]byte) []byte {
	out := make([]byte, BlocksetBytes)
	for index, ref := range refs {
		if ref != nil {
			copy(out[index*BlockrefBytes:], ref)
		}
	}
	return out
}

func checkedMethods() byte { return CheckXXHash64 << 4 }

func dataRef(key, physical uint64, radix byte, payload []byte, checked bool) []byte {
	methods := byte(0)
	var check [64]byte
	if checked {
		methods = checkedMethods()
		putLE64(check[:], 0, xxh64(payload, XXHHammer2Seed))
	}
	return refBytes(BrefTypeData, methods, key, physical|uint64(radix), 0, nil, check[:])
}

func indirectRef(physical uint64, radix byte, payload []byte, checked bool) []byte {
	methods := byte(0)
	var check [64]byte
	if checked {
		methods = checkedMethods()
		putLE64(check[:], 0, xxh64(payload, XXHHammer2Seed))
	}
	return refBytes(BrefTypeIndirect, methods, 0, physical|uint64(radix), 0, nil, check[:])
}

func inodeRef(offset, key uint64, flags byte, inode []byte, checked bool) []byte {
	methods := byte(0)
	var check [64]byte
	if checked {
		methods = checkedMethods()
		putLE64(check[:], 0, xxh64(inode, XXHHammer2Seed))
	}
	return refBytes(BrefTypeInode, methods, key, offset|10, flags, nil, check[:])
}

func direntRef(key, inum uint64, name string, objectType byte) []byte {
	embed := make([]byte, 16)
	putLE64(embed, 0, inum)
	putLE16(embed, 8, uint16(len(name)))
	embed[10] = objectType
	check := make([]byte, 64)
	copy(check, name)
	return refBytes(BrefTypeDirent, 0, key, 0, 0, embed, check)
}

type inodeSpec struct {
	inum    uint64
	objType byte
	mode    uint32
	size    uint64
	name    string
	opFlags byte
	uid     uint32
	gid     uint32
	ctime   uint64
	mtime   uint64
	atime   uint64
	btime   uint64
	union   []byte
}

func inodeBytes(spec inodeSpec) []byte {
	out := make([]byte, InodeBytes)
	putLE16(out, 0x00, InodeVersion)
	out[0x03] = 1
	putLE64(out, 0x10, spec.ctime)
	putLE64(out, 0x18, spec.mtime)
	putLE64(out, 0x20, spec.atime)
	putLE64(out, 0x28, spec.btime)
	putLE32(out, UIDAt, spec.uid)
	putLE32(out, GIDAt, spec.gid)
	out[0x50] = spec.objType
	out[0x51] = spec.opFlags
	putLE32(out, 0x54, spec.mode)
	putLE64(out, 0x58, spec.inum)
	putLE64(out, 0x60, spec.size)
	putLE64(out, 0x68, 1)
	putLE16(out, 0x80, uint16(len(spec.name)))
	copy(out[FilenameOffset:], spec.name)
	if spec.union != nil {
		copy(out[UnionOffset:UnionOffset+EmbeddedBytes], spec.union)
	}
	return out
}

func dirInode(spec inodeSpec, refs ...[]byte) []byte {
	spec.objType = ObjtypeDirectory
	spec.union = blocksetBytes(refs...)
	return inodeBytes(spec)
}

func fileInode(inum uint64, name string, data []byte) []byte {
	return inodeBytes(inodeSpec{
		inum: inum, objType: ObjtypeRegfile, mode: 0o644, size: uint64(len(data)),
		name: name, opFlags: OpflagDirectData, union: data,
	})
}

func symlinkInode(inum uint64, name, target string) []byte {
	return inodeBytes(inodeSpec{
		inum: inum, objType: ObjtypeSoftlink, mode: 0o777, size: uint64(len(target)),
		name: name, opFlags: OpflagDirectData, union: []byte(target),
	})
}

// baseH2 builds a sealed volume header whose super-root names a key-0 inode
// reference at testRootOff.
func baseH2() []byte {
	img := make([]byte, testImageSize)
	putLE64(img, MagicAt, Magic)
	putLE64(img, VoluSizeAt, testVolSize)
	putLE32(img, VersionAt, VersionMultiVolumes)
	img[CopyIDAt] = 255
	img[FreemapVersionAt] = 1
	img[VolumeIDAt] = 0
	img[NVolumesAt] = 1
	copy(img[FSIDAt:FSIDAt+16], []byte("hammer2fixture01"))
	copy(img[FSTypeAt:FSTypeAt+16], FSTypeLE[:])
	putLE64(img, AllocatorSizeAt, 4<<20)
	putLE64(img, AllocatorFreeAt, 3<<20)
	putLE64(img, AllocatorBegAt, 1<<20)
	putLE64(img, MirrorTidAt, 1000)
	putLE64(img, FreemapTidAt, 900)
	putLE64(img, BulkfreeTidAt, 800)
	putLE64(img, TotalSizeAt, testVolSize)
	putLE64(img, VoluLoffAt, 0)
	for index := 1; index < MaxVolumes; index++ {
		putLE64(img, VoluLoffAt+index*8, ^uint64(0))
	}
	rootRef := inodeRef(testRootOff, 0, 0, nil, false)
	copy(img[SrootBlocksetAt:SrootBlocksetAt+BlockrefBytes], rootRef)
	// The super-root reference must name a real inode; a volume header on its
	// own is not an openable image. Every fixture starts with an empty root
	// directory here and tests overwrite it with their own tree.
	copy(img[testRootOff:testRootOff+InodeBytes], dirInode(inodeSpec{inum: 1, name: "/"}))
	sealH2(img)
	return img
}

func openH2(t *testing.T, img []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

func writeAt(dst []byte, offset uint64, src []byte) {
	copy(dst[offset:], src)
}

// ---- detection and the volume header --------------------------------------

func TestDetect(t *testing.T) {
	t.Run("no magic", func(t *testing.T) {
		detected, err := Detect(source.NewMemorySource(1, make([]byte, 4096)))
		if err != nil || detected {
			t.Fatalf("Detect = %v, %v; want false, nil", detected, err)
		}
	})
	t.Run("valid", func(t *testing.T) {
		detected, err := Detect(source.NewMemorySource(1, baseH2()))
		if err != nil || !detected {
			t.Fatalf("Detect = %v, %v; want true, nil", detected, err)
		}
	})
	t.Run("reversed magic", func(t *testing.T) {
		img := baseH2()
		putLE64(img, MagicAt, MagicReversed)
		detected, err := Detect(source.NewMemorySource(1, img))
		if err != nil || !detected {
			t.Fatalf("Detect = %v, %v; want true, nil", detected, err)
		}
	})
}

func TestSuperblock(t *testing.T) {
	volume := openH2(t, baseH2())
	sb := volume.Superblock()
	if sb.Zone != 0 || sb.Version != VersionMultiVolumes || sb.NVolumes != 1 {
		t.Errorf("header = %+v", sb)
	}
	if sb.VoluSize != testVolSize || sb.TotalSize != testVolSize {
		t.Errorf("sizes = %d/%d", sb.VoluSize, sb.TotalSize)
	}
	if sb.MirrorTid != 1000 || sb.FreemapTid != 900 || sb.BulkfreeTid != 800 {
		t.Errorf("tids = %d/%d/%d", sb.MirrorTid, sb.FreemapTid, sb.BulkfreeTid)
	}
	if sb.FSType != FSTypeLE {
		t.Errorf("fstype = %x", sb.FSType)
	}
	if !sb.FSTypeCanonical() {
		t.Errorf("fstype not canonical")
	}
	if sb.SourceBytes != testImageSize {
		t.Errorf("source bytes = %d", sb.SourceBytes)
	}
}

func TestHeaderRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func([]byte)
		wantErr error
		text    string
	}{
		{"crc mismatch", func(img []byte) { img[BootBegAt] ^= 0xff }, source.ErrCorrupt, "CRC"},
		{"version 3", func(img []byte) {
			putLE32(img, VersionAt, VersionWIP)
			sealH2(img)
		}, source.ErrUnsupported, "version 3"},
		{"multi volume", func(img []byte) {
			img[NVolumesAt] = 2
			sealH2(img)
		}, source.ErrUnsupported, "multi-volume"},
		{"foreign fstype", func(img []byte) {
			for index := 0; index < 16; index++ {
				img[FSTypeAt+index] = 0x11
			}
			sealH2(img)
		}, source.ErrCorrupt, "fstype"},
		{"volume id", func(img []byte) {
			img[VolumeIDAt] = 1
			sealH2(img)
		}, source.ErrUnsupported, "volume 1"},
		{"version 1 volume count", func(img []byte) {
			putLE32(img, VersionAt, VersionMin)
			img[NVolumesAt] = 1
			sealH2(img)
		}, source.ErrCorrupt, "version 1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			img := baseH2()
			testCase.mutate(img)
			_, err := Open(source.NewMemorySource(1, img))
			if !errors.Is(err, testCase.wantErr) || !strings.Contains(err.Error(), testCase.text) {
				t.Fatalf("Open error = %v, want %v containing %q", err, testCase.wantErr, testCase.text)
			}
		})
	}
}

func TestHeaderAcceptedVariants(t *testing.T) {
	t.Run("rfc fstype", func(t *testing.T) {
		img := baseH2()
		copy(img[FSTypeAt:FSTypeAt+16], FSTypeRFC[:])
		sealH2(img)
		if _, err := Open(source.NewMemorySource(1, img)); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})
	t.Run("version 1", func(t *testing.T) {
		img := baseH2()
		putLE32(img, VersionAt, VersionMin)
		img[NVolumesAt] = 0
		putLE64(img, TotalSizeAt, 0)
		for index := 0; index < MaxVolumes; index++ {
			putLE64(img, VoluLoffAt+index*8, 0)
		}
		sealH2(img)
		if _, err := Open(source.NewMemorySource(1, img)); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})
	t.Run("reversed magic", func(t *testing.T) {
		img := baseH2()
		putLE64(img, MagicAt, MagicReversed)
		sealH2(img)
		_, err := Open(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "reverse-endian") {
			t.Fatalf("Open error = %v", err)
		}
	})
	t.Run("later zone wins", func(t *testing.T) {
		img := baseH2()
		putLE64(img, MirrorTidAt, 5000)
		sealH2(img)
		sb, err := readAt(source.NewMemorySource(1, img), 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if sb.Zone != 1 || sb.MirrorTid != 5000 {
			t.Fatalf("zone/tid = %d/%d", sb.Zone, sb.MirrorTid)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		img := baseH2()[:1024]
		_, err := ReadSuperblock(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrUnexpectedEOF) {
			t.Fatalf("ReadSuperblock error = %v, want unexpected EOF", err)
		}
	})
}

// ---- block references ------------------------------------------------------

func TestBlockrefParse(t *testing.T) {
	raw := make([]byte, BlockrefBytes)
	raw[0x00] = BrefTypeInode
	raw[0x01] = 0x30
	raw[0x05] = BrefFlagPFSRoot
	putLE64(raw, 0x08, DirhashVisible|0x1234)
	putLE64(raw, 0x20, 0x12345600|10)
	ref, err := ParseBlockref(raw, "a reference")
	if err != nil {
		t.Fatal(err)
	}
	if ref.BType != BrefTypeInode || ref.CheckAlgo() != CheckXXHash64 || ref.CompAlgo() != CompNone {
		t.Errorf("type/methods = %+v", ref)
	}
	if !ref.Visible() || !ref.PFSRoot() {
		t.Errorf("visible/pfs = %v/%v", ref.Visible(), ref.PFSRoot())
	}
	if ref.Radix() != 10 || ref.PhysicalOffset() != 0x12345600 {
		t.Errorf("radix/offset = %d/0x%x", ref.Radix(), ref.PhysicalOffset())
	}
	if bytes, ok := ref.PhysicalBytes(); !ok || bytes != 1024 {
		t.Errorf("physical bytes = %d/%v", bytes, ok)
	}
	if _, err := ParseBlockref(make([]byte, 10), "short"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("short parse error = %v", err)
	}
}

func TestBlocksetNormalisesEmptySlots(t *testing.T) {
	raw := make([]byte, BlocksetBytes)
	raw[0] = BrefTypeInode
	putLE64(raw, 0x08, 0)
	putLE64(raw, 0x20, 0x2000|10)
	set, err := ParseBlockset(raw, "a blockset")
	if err != nil {
		t.Fatal(err)
	}
	if set.Refs()[0].BType != BrefTypeInode || set.Refs()[1].BType != BrefTypeEmpty {
		t.Errorf("slot types = %d/%d", set.Refs()[0].BType, set.Refs()[1].BType)
	}
}

func TestChecks(t *testing.T) {
	payload := []byte("hammer2 check payload")
	if got := xxh64(nil, 0); got != 0xef46db3751d8e999 {
		t.Fatalf("xxh64 empty = 0x%016x", got)
	}
	if got := xxh64([]byte("abc"), 0); got != 0x44bc2cf5ad770999 {
		t.Fatalf("xxh64 abc = 0x%016x", got)
	}

	crc := make([]byte, 64)
	putLE32(crc, 0, foundation.CRC32C(payload))
	if err := verifyCheckCode(CheckISCSI32, crc, payload, "a block"); err != nil {
		t.Errorf("crc32c verify: %v", err)
	}
	xxh := make([]byte, 64)
	putLE64(xxh, 0, xxh64(payload, XXHHammer2Seed))
	if err := verifyCheckCode(CheckXXHash64, xxh, payload, "a block"); err != nil {
		t.Errorf("xxh64 verify: %v", err)
	}
	digest := sha256.Sum256(payload)
	for index := 0; index < 8; index++ {
		digest[16+index] ^= digest[24+index]
	}
	sha := make([]byte, 64)
	copy(sha, digest[:24])
	if err := verifyCheckCode(CheckSHA192, sha, payload, "a block"); err != nil {
		t.Errorf("sha192 verify: %v", err)
	}
	corrupt := append([]byte(nil), payload...)
	corrupt[0] ^= 0xff
	if err := verifyCheckCode(CheckXXHash64, xxh, corrupt, "a block"); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), "XXH64") {
		t.Errorf("corrupt xxh error = %v", err)
	}
	if err := verifyCheckCode(CheckISCSI32, crc, corrupt, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("corrupt crc error = %v", err)
	}
	if err := verifyCheckCode(CheckSHA192, sha, corrupt, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("corrupt sha error = %v", err)
	}
}

func TestRefusalMethods(t *testing.T) {
	cases := []struct {
		methods byte
		text    string
	}{
		{0x31, "autozero"},
		{0x32, "LZ4"},
		{0x33, "zlib"},
		{0x50, "freemap"},
		{0x60, "unknown check"},
	}
	for _, testCase := range cases {
		ref := Blockref{Methods: testCase.methods}
		err := ref.ValidateMethods("a block")
		if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), testCase.text) {
			t.Errorf("methods 0x%02x error = %v, want %q", testCase.methods, err, testCase.text)
		}
	}
	if err := (&Blockref{Methods: 0}).ValidateMethods("a block"); err != nil {
		t.Errorf("uncompressed no-check refused: %v", err)
	}
}

func TestBlockrefReadBytes(t *testing.T) {
	payload := make([]byte, 1024)
	copy(payload, "hello block")
	img := make([]byte, 4096)
	writeAt(img, 2048, payload)
	ref := Blockref{DataOff: 2048 | 10, Methods: 0}
	src := source.NewMemorySource(1, img)
	got, err := ref.ReadBytes(src, "a block")
	if err != nil || string(got[:11]) != "hello block" {
		t.Fatalf("ReadBytes = %q, %v", got[:11], err)
	}

	zero := Blockref{DataOff: 2048}
	if _, err := zero.ReadBytes(src, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("radix zero error = %v", err)
	}
	atZero := Blockref{DataOff: 0 | 10}
	if _, err := atZero.ReadBytes(src, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("offset zero error = %v", err)
	}
	big := Blockref{DataOff: 2048 | 17}
	if _, err := big.ReadBytes(src, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("radix 17 error = %v", err)
	}
	past := Blockref{DataOff: 4096 | 10}
	if _, err := past.ReadBytes(src, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("past end error = %v", err)
	}
	short := source.NewMemorySource(1, make([]byte, 100))
	if _, err := (&Blockref{DataOff: 100 | 10}).ReadBytes(short, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("short source error = %v", err)
	}
}

// ---- inodes and directory entries -----------------------------------------

func TestInodeParse(t *testing.T) {
	base := inodeBytes(inodeSpec{inum: 42, objType: ObjtypeRegfile, mode: 0o644, size: 7, name: "a.txt"})
	inode, err := ParseInode(base, "a test inode")
	if err != nil {
		t.Fatal(err)
	}
	name, nameErr := inode.Name()
	if inode.Kind != KindRegular || inode.Inum != 42 || inode.Size != 7 || nameErr != nil || name != "a.txt" {
		t.Errorf("inode = %+v name=%q err=%v", inode, name, nameErr)
	}
	if inode.Ctime != nil || inode.Mtime != nil || inode.Atime != nil || inode.Btime != nil {
		t.Errorf("zero times reported: %+v", inode)
	}

	stamped := inodeBytes(inodeSpec{
		inum: 43, objType: ObjtypeRegfile, mode: 0o600, size: 3, name: "b",
		ctime: 1_600_000_000_123_456, mtime: 2, atime: 3, btime: 4, uid: 1000, gid: 100,
	})
	inode, err = ParseInode(stamped, "a stamped inode")
	if err != nil {
		t.Fatal(err)
	}
	if inode.Ctime == nil || *inode.Ctime != 1_600_000_000_123_456 {
		t.Errorf("ctime = %v", inode.Ctime)
	}
	if inode.UID != 1000 || inode.GID != 100 {
		t.Errorf("uid/gid = %d/%d", inode.UID, inode.GID)
	}
}

func TestInodeDirectData(t *testing.T) {
	spec := inodeSpec{inum: 1, objType: ObjtypeRegfile, size: 4, name: "d", opFlags: OpflagDirectData, union: []byte("data")}
	inode, err := ParseInode(inodeBytes(spec), "direct")
	if err != nil {
		t.Fatal(err)
	}
	if !inode.IsDirectData() || inode.Blockset != nil || string(inode.EmbeddedData()) != "data" {
		t.Errorf("direct inode = %+v", inode)
	}

	spec.size = 513
	if _, err := ParseInode(inodeBytes(spec), "too long"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("oversized direct data error = %v", err)
	}

	dir := inodeSpec{inum: 2, objType: ObjtypeDirectory, opFlags: OpflagDirectData, union: make([]byte, 4)}
	if _, err := ParseInode(inodeBytes(dir), "direct dir"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("direct directory error = %v", err)
	}
}

func TestInodeRefusals(t *testing.T) {
	cases := []struct {
		name  string
		bytes func() []byte
		errIs error
		text  string
	}{
		{"version", func() []byte {
			out := inodeBytes(inodeSpec{inum: 1, objType: ObjtypeRegfile, name: "x"})
			putLE16(out, 0, 2)
			return out
		}, source.ErrUnsupported, "inode version 2"},
		{"unknown type", func() []byte {
			return inodeBytes(inodeSpec{inum: 1, objType: ObjtypeUnknown, name: "x"})
		}, source.ErrCorrupt, "object type 0"},
		{"unsupported type", func() []byte {
			return inodeBytes(inodeSpec{inum: 1, objType: 3, name: "x"})
		}, source.ErrUnsupported, "object type 3"},
		{"long name", func() []byte {
			return inodeBytes(inodeSpec{inum: 1, objType: ObjtypeRegfile, name: strings.Repeat("a", 300)})
		}, source.ErrCorrupt, "300-byte filename"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ParseInode(testCase.bytes(), "an inode")
			if !errors.Is(err, testCase.errIs) || !strings.Contains(err.Error(), testCase.text) {
				t.Fatalf("error = %v, want %v containing %q", err, testCase.errIs, testCase.text)
			}
		})
	}
	t.Run("non utf8 name", func(t *testing.T) {
		out := inodeBytes(inodeSpec{inum: 1, objType: ObjtypeRegfile, name: "x"})
		out[FilenameOffset] = 0xff
		inode, err := ParseInode(out, "an inode")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inode.Name(); !errors.Is(err, source.ErrUnsupported) {
			t.Errorf("Name error = %v", err)
		}
	})
}

func TestDirent(t *testing.T) {
	ref, err := ParseBlockref(direntRef(0, 77, "hello.txt", ObjtypeRegfile), "a dirent")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := InlineDirent(ref, "a dirent")
	if err != nil || entry == nil {
		t.Fatal(err)
	}
	name, nameErr := entry.Name()
	if entry.Inum != 77 || nameErr != nil || name != "hello.txt" || entry.IsDirectory() {
		t.Errorf("dirent = %+v name=%q err=%v", entry, name, nameErr)
	}

	longName := strings.Repeat("a", 100)
	longRef, _ := ParseBlockref(direntRef(0, 9, longName, ObjtypeDirectory), "a dirent")
	if entry, err := InlineDirent(longRef, "a dirent"); err != nil || entry != nil {
		t.Fatalf("inline long name = %v, %v", entry, err)
	}
	block := make([]byte, 1024)
	copy(block, longName)
	entry, err = ExternalDirent(longRef, block, "a dirent")
	if err != nil {
		t.Fatalf("external: %v", err)
	}
	name, nameErr = entry.Name()
	if entry.Inum != 9 || nameErr != nil || name != longName || !entry.IsDirectory() {
		t.Fatalf("external = %+v name=%q err=%v", entry, name, nameErr)
	}
	if _, err := ExternalDirent(longRef, make([]byte, 64), "a dirent"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("short external block error = %v", err)
	}

	check := func(name string, inum uint64, text string) {
		ref, _ := ParseBlockref(direntRef(0, inum, name, ObjtypeRegfile), "a dirent")
		_, err := InlineDirent(ref, "a dirent")
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), text) {
			t.Errorf("%q error = %v, want corrupt containing %q", name, err, text)
		}
	}
	check("a/b", 1, "slash")
	check(".", 1, "reserved name")
	check("..", 1, "reserved name")
	check("", 1, "zero-length")
	nulRef, _ := ParseBlockref(direntRef(0, 1, "ab", ObjtypeRegfile), "a dirent")
	nulRef.Check[1] = 0
	if _, err := InlineDirent(nulRef, "a dirent"); !errors.Is(err, source.ErrCorrupt) {
		t.Errorf("nul name error = %v", err)
	}
	nonUTF, _ := ParseBlockref(direntRef(0, 1, "x", ObjtypeRegfile), "a dirent")
	nonUTF.Check[0] = 0xff
	entry, err = InlineDirent(nonUTF, "a dirent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Name(); !errors.Is(err, source.ErrUnsupported) {
		t.Errorf("non-utf8 dirent error = %v", err)
	}
}

// ---- tree walking ----------------------------------------------------------

type h2Fixture struct {
	img  []byte
	next uint64
}

func newH2Fixture() *h2Fixture {
	// testRootOff holds the super-root inode baseH2() wrote; the first
	// test-owned allocation must not overlap it.
	return &h2Fixture{img: baseH2(), next: testRootOff + InodeBytes}
}

func (f *h2Fixture) alloc(size uint64) uint64 {
	offset := f.next
	f.next += (size + 1023) &^ 1023
	if f.next > uint64(len(f.img)) {
		panic("hammer2 fixture exhausted")
	}
	return offset
}

func (f *h2Fixture) inodeAt(offset uint64, inode []byte) {
	writeAt(f.img, offset, inode)
}

// basicTree lays out a root directory with three names:
//
//	/hello.txt (direct data)
//	/sub (directory) -> /sub/inner
//	/hidden.txt (a DIRENT resolved through a hidden INODE in the root set)
func basicTree() (*h2Fixture, uint64) {
	f := newH2Fixture()
	helloOff := f.alloc(InodeBytes)
	innerOff := f.alloc(InodeBytes)
	subOff := f.alloc(InodeBytes)
	hiddenOff := f.alloc(InodeBytes)

	f.inodeAt(helloOff, fileInode(1001, "hello.txt", []byte("hello")))
	f.inodeAt(innerOff, fileInode(1002, "inner", []byte("inside")))
	f.inodeAt(subOff, dirInode(inodeSpec{inum: 1003, name: "sub"},
		inodeRef(innerOff, DirhashVisible|2, 0, nil, false)))
	f.inodeAt(hiddenOff, fileInode(7000, "hidden.txt", []byte("secret")))

	root := dirInode(inodeSpec{inum: 1, name: "/"},
		inodeRef(helloOff, DirhashVisible|1, 0, nil, false),
		inodeRef(subOff, DirhashVisible|2, 0, nil, false),
		direntRef(DirhashVisible|3, 7000, "hidden.txt", ObjtypeRegfile),
		inodeRef(hiddenOff, 7000, 0, nil, false),
	)
	f.inodeAt(testRootOff, root)
	return f, helloOff
}

func TestWalkBasicTree(t *testing.T) {
	f, _ := basicTree()
	volume := openH2(t, f.img)

	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat /: %v", err)
	}
	if !root.IsDir || root.Name != "/" || root.Path != "/" {
		t.Fatalf("root = %+v", root)
	}
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir /: %v", err)
	}
	if got := h2EntryNames(entries); strings.Join(got, ",") != "hello.txt,sub,hidden.txt" {
		t.Fatalf("entries = %v", got)
	}

	hello := h2Entry(entries, "hello.txt")
	if !hello.IsFile || hello.Size != 5 || hello.Inode != 1001 || hello.Mode != 0o644 {
		t.Errorf("hello = %+v", hello)
	}
	if hello.Allocated == nil || *hello.Allocated != 0 {
		t.Errorf("hello allocated = %v", hello.Allocated)
	}
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buffer := make([]byte, 5)
	if _, err := file.ReadAt(0, buffer); err != nil || string(buffer) != "hello" {
		t.Fatalf("read = %q, %v", buffer, err)
	}

	sub := h2Entry(entries, "sub")
	if !sub.IsDir {
		t.Errorf("sub = %+v", sub)
	}
	inner, err := volume.Stat("sub/inner")
	if err != nil {
		t.Fatalf("Stat inner: %v", err)
	}
	if inner.Path != "/sub/inner" || inner.Size != 6 {
		t.Errorf("inner = %+v", inner)
	}
	if _, err := volume.Stat("sub/../hello.txt"); err != nil {
		t.Errorf("dotdot path: %v", err)
	}

	hidden := h2Entry(entries, "hidden.txt")
	if hidden.Inode != 7000 || hidden.Size != 6 {
		t.Errorf("hidden = %+v", hidden)
	}
	hiddenFile, err := volume.OpenFile("/hidden.txt")
	if err != nil {
		t.Fatalf("OpenFile hidden: %v", err)
	}
	hiddenBuffer := make([]byte, 6)
	if _, err := hiddenFile.ReadAt(0, hiddenBuffer); err != nil || string(hiddenBuffer) != "secret" {
		t.Fatalf("hidden read = %q, %v", hiddenBuffer, err)
	}

	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing error = %v", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Errorf("dir error = %v", err)
	}
	if _, err := volume.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Errorf("ListDir file error = %v", err)
	}
	if stats := volume.Stats(); stats.RefsScanned == 0 || stats.NodesRead == 0 {
		t.Errorf("stats = %+v", stats)
	}
}

func h2EntryNames(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Name)
	}
	return out
}

func h2Entry(entries []Entry, name string) Entry {
	for _, entry := range entries {
		if entry.Name == name {
			return entry
		}
	}
	return Entry{}
}

func TestEmptyDirectoryAndTimes(t *testing.T) {
	f := newH2Fixture()
	emptyOff := f.alloc(InodeBytes)
	f.inodeAt(emptyOff, dirInode(inodeSpec{
		inum: 55, name: "empty", ctime: 1_700_000_000_000_001,
		mtime: 1_700_000_000_000_002, atime: 1_700_000_000_000_003,
		btime: 1_700_000_000_000_004, uid: 1000, gid: 100,
	}))
	root := dirInode(inodeSpec{inum: 1, name: "/"},
		inodeRef(emptyOff, DirhashVisible|1, 0, nil, false))
	f.inodeAt(testRootOff, root)

	volume := openH2(t, f.img)
	entries, err := volume.ListDir("/empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v", h2EntryNames(entries))
	}
	entry, err := volume.Stat("/empty")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Created == nil || *entry.Created != 1_700_000_000_000_004 {
		t.Errorf("btime = %v", entry.Created)
	}
	if entry.Accessed == nil || *entry.Accessed != 1_700_000_000_000_003 {
		t.Errorf("atime = %v", entry.Accessed)
	}
	if entry.UID != 1000 || entry.GID != 100 {
		t.Errorf("uid/gid = %d/%d", entry.UID, entry.GID)
	}
}

func TestIndirectDirectoryAndSpecialEntries(t *testing.T) {
	f := newH2Fixture()
	helloOff := f.alloc(InodeBytes)
	emptyOff := f.alloc(InodeBytes)
	linkOff := f.alloc(InodeBytes)
	fifoOff := f.alloc(InodeBytes)
	indirectOff := f.alloc(4096)

	f.inodeAt(helloOff, fileInode(1001, "hello", []byte("hi")))
	f.inodeAt(emptyOff, dirInode(inodeSpec{inum: 1002, name: "empty"}))
	f.inodeAt(linkOff, symlinkInode(1003, "link", "hello"))
	f.inodeAt(fifoOff, inodeBytes(inodeSpec{inum: 1004, objType: ObjtypeFifo, mode: 0o600, name: "fifo"}))

	block := blocksetBytes(
		inodeRef(helloOff, DirhashVisible|1, 0, nil, false),
		inodeRef(emptyOff, DirhashVisible|2, 0, nil, false),
		inodeRef(linkOff, DirhashVisible|3, 0, nil, false),
		inodeRef(fifoOff, DirhashVisible|4, 0, nil, false),
	)
	writeAt(f.img, indirectOff, block)
	root := dirInode(inodeSpec{inum: 1, name: "/"},
		indirectRef(indirectOff, 12, block, false))
	f.inodeAt(testRootOff, root)

	volume := openH2(t, f.img)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if got := h2EntryNames(entries); strings.Join(got, ",") != "hello,empty,link,fifo" {
		t.Fatalf("entries = %v", got)
	}
	link := h2Entry(entries, "link")
	if !link.IsSymlink || link.SymlinkTarget != "hello" {
		t.Errorf("link = %+v", link)
	}
	symlinkFile, err := volume.OpenSymlink("/link")
	if err != nil {
		t.Fatalf("OpenSymlink: %v", err)
	}
	buffer := make([]byte, 5)
	if _, err := symlinkFile.ReadAt(0, buffer); err != nil || string(buffer) != "hello" {
		t.Errorf("symlink read = %q, %v", buffer, err)
	}
	if target, err := volume.SymlinkTarget("/link"); err != nil || target != "hello" {
		t.Errorf("SymlinkTarget = %q, %v", target, err)
	}
	fifo := h2Entry(entries, "fifo")
	if fifo.IsFile || fifo.IsDir || fifo.IsSymlink || fifo.FileType != "FIFO" {
		t.Errorf("fifo = %+v", fifo)
	}
}

func TestPFSRootHiddenStore(t *testing.T) {
	f := newH2Fixture()
	pfsInodeOff := f.alloc(InodeBytes)
	hiddenOff := f.alloc(InodeBytes)
	secretOff := f.alloc(InodeBytes)

	f.inodeAt(secretOff, fileInode(8001, "inside-pfs", []byte("pfs")))
	f.inodeAt(hiddenOff, fileInode(8000, "hidden-pfs", []byte("hidden")))
	pfsInode := dirInode(inodeSpec{inum: 5000, name: "pfs"},
		direntRef(DirhashVisible|1, 8000, "hidden-pfs", ObjtypeRegfile),
		inodeRef(hiddenOff, 8000, 0, nil, false),
		inodeRef(secretOff, DirhashVisible|2, 0, nil, false),
	)
	f.inodeAt(pfsInodeOff, pfsInode)
	root := dirInode(inodeSpec{inum: 1, name: "/"},
		inodeRef(pfsInodeOff, DirhashVisible|1, BrefFlagPFSRoot, nil, false))
	f.inodeAt(testRootOff, root)

	volume := openH2(t, f.img)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	pfs := h2Entry(entries, "pfs")
	if !pfs.PFSRoot || !pfs.IsDir {
		t.Fatalf("pfs = %+v", pfs)
	}
	children, err := volume.ListDir("/pfs")
	if err != nil {
		t.Fatal(err)
	}
	if got := h2EntryNames(children); strings.Join(got, ",") != "hidden-pfs,inside-pfs" {
		t.Fatalf("pfs entries = %v", got)
	}
	if _, err := volume.Stat("/pfs/hidden-pfs"); err != nil {
		t.Errorf("hidden pfs entry: %v", err)
	}
	if info := volume.Info(); info.PFSRoots != 1 {
		t.Errorf("pfs roots = %d", info.PFSRoots)
	}
}

func TestDirectoryLoop(t *testing.T) {
	f := newH2Fixture()
	dirOff := f.alloc(InodeBytes)
	leafOff := f.alloc(InodeBytes)
	f.inodeAt(leafOff, fileInode(1002, "leaf", []byte("x")))
	f.inodeAt(dirOff, dirInode(inodeSpec{inum: 1001, name: "a"},
		inodeRef(leafOff, DirhashVisible|1, 0, nil, false)))
	root := dirInode(inodeSpec{inum: 1, name: "/"},
		inodeRef(dirOff, DirhashVisible|1, 0, nil, false),
		inodeRef(dirOff, DirhashVisible|2, 0, nil, false))
	f.inodeAt(testRootOff, root)

	volume := openH2(t, f.img)
	if volume.DirectoryLoops() != 1 {
		t.Errorf("loops = %d", volume.DirectoryLoops())
	}
	if _, err := volume.Stat("/a/leaf"); err != nil {
		t.Errorf("Stat a/leaf: %v", err)
	}
	// The second name is listed but not walked twice.
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("entries = %v", h2EntryNames(entries))
	}
}

func TestPFSRootSelfReferenceIsBounded(t *testing.T) {
	f := newH2Fixture()
	loopOff := f.alloc(InodeBytes)
	// A PFS root whose own tree carries a visible, PFS-root-flagged reference
	// to itself. Each pass makes the child a fresh tree owner, so the visited
	// map never matches; without a directory-depth bound this would recurse
	// forever while the displayed path grew without limit (the historical
	// OOM). The walk must stop and report the bounded recursion.
	f.inodeAt(loopOff, dirInode(inodeSpec{inum: 5000, name: "pfs"},
		inodeRef(loopOff, DirhashVisible|1, BrefFlagPFSRoot, nil, false)))
	f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"},
		inodeRef(loopOff, DirhashVisible|1, BrefFlagPFSRoot, nil, false)))

	volume := openH2(t, f.img)
	if volume.NodeCount() > maxDirectoryDepth+2 {
		t.Errorf("nodes = %d; the walk followed the PFS loop past its bound", volume.NodeCount())
	}
	if volume.Malformed() == 0 {
		t.Errorf("malformed = 0; the bounded depth was not reported")
	}
	if got := volume.Stats().NodesRead; got == 0 || got > uint64(maxDirectoryDepth)+2 {
		t.Errorf("nodes read = %d", got)
	}
}

// ---- files and holes -------------------------------------------------------

func TestBlockMappedFile(t *testing.T) {
	f := newH2Fixture()
	fileOff := f.alloc(InodeBytes)
	dataOffsets := []uint64{f.alloc(65536), f.alloc(65536), f.alloc(65536), f.alloc(4096)}
	payloads := [][]byte{
		bytesOf('A', 65536), bytesOf('B', 65536), bytesOf('C', 65536), bytesOf('D', 4096),
	}
	for index, offset := range dataOffsets {
		writeAt(f.img, offset, payloads[index])
	}
	const size = 200000
	refs := [][]byte{
		dataRef(0, dataOffsets[0], 16, payloads[0], true),
		dataRef(65536, dataOffsets[1], 16, payloads[1], true),
		dataRef(131072, dataOffsets[2], 16, payloads[2], true),
		dataRef(196608, dataOffsets[3], 12, payloads[3], true),
	}
	file := inodeBytes(inodeSpec{inum: 1001, objType: ObjtypeRegfile, mode: 0o644, size: size, name: "big", union: blocksetBytes(refs...)})
	f.inodeAt(fileOff, file)
	f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}, inodeRef(fileOff, DirhashVisible|1, 0, nil, false)))

	volume := openH2(t, f.img)
	entry, err := volume.Stat("/big")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Allocated == nil || *entry.Allocated != 200704 {
		t.Fatalf("allocated = %v", entry.Allocated)
	}
	sourceFile, err := volume.OpenFile("/big")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, size)
	if _, err := sourceFile.ReadAt(0, buffer); err != nil {
		t.Fatal(err)
	}
	if buffer[0] != 'A' || buffer[65535] != 'A' || buffer[65536] != 'B' ||
		buffer[131072] != 'C' || buffer[196608] != 'D' || buffer[size-1] != 'D' {
		t.Errorf("boundary bytes = %q %q %q %q %q", buffer[0], buffer[65536], buffer[131072], buffer[196608], buffer[size-1])
	}
	ranges, err := sourceFile.Extents(0, size)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 4 {
		t.Errorf("ranges = %d", len(ranges))
	}
	if _, err := sourceFile.ReadAt(size, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("end read error = %v", err)
	}
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = value
	}
	return out
}

func TestSparseHole(t *testing.T) {
	f := newH2Fixture()
	fileOff := f.alloc(InodeBytes)
	firstOff := f.alloc(65536)
	lastOff := f.alloc(65536)
	first := bytesOf('X', 65536)
	last := bytesOf('Y', 65536)
	writeAt(f.img, firstOff, first)
	writeAt(f.img, lastOff, last)
	const size = 196608
	file := inodeBytes(inodeSpec{inum: 1001, objType: ObjtypeRegfile, mode: 0o644, size: size, name: "holes", union: blocksetBytes(
		dataRef(0, firstOff, 16, first, false),
		dataRef(131072, lastOff, 16, last, false),
	)})
	f.inodeAt(fileOff, file)
	f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}, inodeRef(fileOff, DirhashVisible|1, 0, nil, false)))

	volume := openH2(t, f.img)
	entry, err := volume.Stat("/holes")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Allocated == nil || *entry.Allocated != 131072 {
		t.Fatalf("allocated = %v", entry.Allocated)
	}
	fileSource, err := volume.OpenFile("/holes")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, size)
	if _, err := fileSource.ReadAt(0, buffer); err != nil {
		t.Fatal(err)
	}
	if buffer[0] != 'X' || buffer[65535] != 'X' || buffer[65536] != 0 ||
		buffer[131071] != 0 || buffer[131072] != 'Y' {
		t.Errorf("hole bytes wrong")
	}
	ranges, err := fileSource.Extents(0, size)
	if err != nil {
		t.Fatal(err)
	}
	var holes, data uint64
	for _, r := range ranges {
		switch r.Kind {
		case source.RangeHole:
			holes += r.Len
		case source.RangeData:
			data += r.Len
		}
	}
	if holes != 65536 || data != 131072 {
		t.Errorf("holes/data = %d/%d ranges=%+v", holes, data, ranges)
	}
}

func TestIndirectFileData(t *testing.T) {
	f := newH2Fixture()
	fileOff := f.alloc(InodeBytes)
	indirectOff := f.alloc(4096)
	firstOff := f.alloc(65536)
	lastOff := f.alloc(4096)
	first := bytesOf('Q', 65536)
	last := bytesOf('R', 4096)
	writeAt(f.img, firstOff, first)
	writeAt(f.img, lastOff, last)
	block := blocksetBytes(
		dataRef(0, firstOff, 16, first, false),
		dataRef(65536, lastOff, 12, last, false),
	)
	writeAt(f.img, indirectOff, block)
	const size = 65536 + 4096
	file := inodeBytes(inodeSpec{inum: 1001, objType: ObjtypeRegfile, mode: 0o644, size: size, name: "indirect", union: blocksetBytes(
		indirectRef(indirectOff, 12, block, false),
	)})
	f.inodeAt(fileOff, file)
	f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}, inodeRef(fileOff, DirhashVisible|1, 0, nil, false)))

	volume := openH2(t, f.img)
	fileSource, err := volume.OpenFile("/indirect")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, size)
	if _, err := fileSource.ReadAt(0, buffer); err != nil {
		t.Fatal(err)
	}
	if buffer[65535] != 'Q' || buffer[65536] != 'R' {
		t.Errorf("indirect boundary wrong")
	}
	if stats := volume.Stats(); stats.BlocksRead < 2 {
		t.Errorf("blocks read = %d", stats.BlocksRead)
	}
}

func TestFileCheckIsVerifiedOnRead(t *testing.T) {
	f := newH2Fixture()
	fileOff := f.alloc(InodeBytes)
	dataOff := f.alloc(4096)
	payload := bytesOf('Z', 4096)
	writeAt(f.img, dataOff, payload)
	ref := dataRef(0, dataOff, 12, payload, true)
	// Corrupt the stored block after the check was computed.
	f.img[dataOff] ^= 0xff
	file := inodeBytes(inodeSpec{inum: 1001, objType: ObjtypeRegfile, mode: 0o644, size: 4096, name: "checked", union: blocksetBytes(ref)})
	f.inodeAt(fileOff, file)
	f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}, inodeRef(fileOff, DirhashVisible|1, 0, nil, false)))

	volume := openH2(t, f.img)
	fileSource, err := volume.OpenFile("/checked")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	_, err = fileSource.ReadAt(0, make([]byte, 4096))
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "XXH64") {
		t.Fatalf("read error = %v, want corrupt XXH64", err)
	}
}

func TestFileMapValidation(t *testing.T) {
	cases := []struct {
		name  string
		size  uint64
		ref   func(dataOff uint64) []byte
		errIs error
		text  string
	}{
		{"misaligned key", 131072, func(off uint64) []byte {
			return dataRef(1234, off, 16, make([]byte, 65536), false)
		}, source.ErrCorrupt, "aligned"},
		{"key past file", 65536, func(off uint64) []byte {
			return dataRef(65536, off, 16, make([]byte, 65536), false)
		}, source.ErrCorrupt, "past the"},
		{"visible bit key", 65536, func(off uint64) []byte {
			return dataRef(DirhashVisible, off, 16, make([]byte, 65536), false)
		}, source.ErrCorrupt, "bit 63"},
		{"radix too small", 65536, func(off uint64) []byte {
			return dataRef(0, off, 9, make([]byte, 512), false)
		}, source.ErrCorrupt, "radix"},
		{"last block too small", 200000, func(off uint64) []byte {
			return dataRef(196608, off, 10, make([]byte, 1024), false)
		}, source.ErrCorrupt, "too small"},
		{"physical zero", 1024, func(off uint64) []byte {
			return dataRef(0, 0, 10, make([]byte, 1024), false)
		}, source.ErrCorrupt, "offset 0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			f := newH2Fixture()
			fileOff := f.alloc(InodeBytes)
			dataOff := f.alloc(65536)
			ref := testCase.ref(dataOff)
			file := inodeBytes(inodeSpec{inum: 1001, objType: ObjtypeRegfile, mode: 0o644,
				size: testCase.size, name: "bad", union: blocksetBytes(ref)})
			f.inodeAt(fileOff, file)
			f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}, inodeRef(fileOff, DirhashVisible|1, 0, nil, false)))
			volume := openH2(t, f.img)
			entry, err := volume.Stat("/bad")
			if err != nil {
				t.Fatal(err)
			}
			if entry.Allocated != nil {
				t.Errorf("allocated = %v, want nil", entry.Allocated)
			}
			if volume.Undecodable() == 0 {
				t.Errorf("undecodable = 0")
			}
			_, err = volume.OpenFile("/bad")
			if !errors.Is(err, testCase.errIs) || !strings.Contains(err.Error(), testCase.text) {
				t.Fatalf("OpenFile error = %v, want %v containing %q", err, testCase.errIs, testCase.text)
			}
		})
	}
}

func TestDuplicateDataKeyIsRedundant(t *testing.T) {
	f := newH2Fixture()
	fileOff := f.alloc(InodeBytes)
	dataOff := f.alloc(65536)
	payload := bytesOf('K', 65536)
	writeAt(f.img, dataOff, payload)
	ref := dataRef(0, dataOff, 16, payload, false)
	file := inodeBytes(inodeSpec{inum: 1001, objType: ObjtypeRegfile, mode: 0o644, size: 100, name: "dup",
		union: blocksetBytes(ref, ref)})
	f.inodeAt(fileOff, file)
	f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}, inodeRef(fileOff, DirhashVisible|1, 0, nil, false)))

	volume := openH2(t, f.img)
	entry, err := volume.Stat("/dup")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Allocated == nil || *entry.Allocated != 65536 {
		t.Fatalf("allocated = %v", entry.Allocated)
	}
}

func TestDeepDataTreeRefused(t *testing.T) {
	f := newH2Fixture()
	fileOff := f.alloc(InodeBytes)
	const levels = 18
	offsets := make([]uint64, levels)
	for index := range offsets {
		offsets[index] = f.alloc(4096)
	}
	for index := 0; index < levels-1; index++ {
		child := indirectRef(offsets[index+1], 12, nil, false)
		writeAt(f.img, offsets[index], blocksetBytes(child))
	}
	writeAt(f.img, offsets[levels-1], make([]byte, 4096))
	file := inodeBytes(inodeSpec{inum: 1001, objType: ObjtypeRegfile, mode: 0o644, size: 65536, name: "deep",
		union: blocksetBytes(indirectRef(offsets[0], 12, nil, false))})
	f.inodeAt(fileOff, file)
	f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}, inodeRef(fileOff, DirhashVisible|1, 0, nil, false)))

	volume := openH2(t, f.img)
	_, err := volume.OpenFile("/deep")
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "nests deeper") {
		t.Fatalf("OpenFile error = %v", err)
	}
}

// ---- corrupt trees and scan resilience ------------------------------------

func TestOpenRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*h2Fixture)
		errIs error
		text  string
	}{
		{"empty super-root set", func(f *h2Fixture) {
			clear(f.img[SrootBlocksetAt : SrootBlocksetAt+BlocksetBytes])
			sealH2(f.img)
		}, source.ErrCorrupt, "empty"},
		{"super-root not inode", func(f *h2Fixture) {
			clear(f.img[SrootBlocksetAt : SrootBlocksetAt+BlocksetBytes])
			copy(f.img[SrootBlocksetAt:], refBytes(BrefTypeIndirect, 0, 0, 0x2000|12, 0, nil, nil))
			sealH2(f.img)
		}, source.ErrCorrupt, "not an inode"},
		{"super-root key", func(f *h2Fixture) {
			clear(f.img[SrootBlocksetAt : SrootBlocksetAt+BlocksetBytes])
			copy(f.img[SrootBlocksetAt:], inodeRef(testRootOff, 5, 0, nil, false))
			sealH2(f.img)
		}, source.ErrCorrupt, "key 5"},
		{"root not directory", func(f *h2Fixture) {
			f.inodeAt(testRootOff, fileInode(1, "/", []byte("x")))
		}, source.ErrCorrupt, "not a directory"},
		{"root inode check", func(f *h2Fixture) {
			inode := fileInode(1, "/", nil)
			root := dirInode(inodeSpec{inum: 1, name: "/"})
			copy(f.img[testRootOff:], root)
			clear(f.img[SrootBlocksetAt : SrootBlocksetAt+BlocksetBytes])
			copy(f.img[SrootBlocksetAt:], inodeRef(testRootOff, 0, 0, inode, true))
			sealH2(f.img)
		}, source.ErrCorrupt, "XXH64"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			f := newH2Fixture()
			f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}))
			testCase.setup(f)
			_, err := Open(source.NewMemorySource(1, f.img))
			if !errors.Is(err, testCase.errIs) || !strings.Contains(err.Error(), testCase.text) {
				t.Fatalf("Open error = %v, want %v containing %q", err, testCase.errIs, testCase.text)
			}
		})
	}
}

func TestBadLeafIsCountedAndSkipped(t *testing.T) {
	f := newH2Fixture()
	badOff := f.alloc(InodeBytes)
	goodOff := f.alloc(InodeBytes)
	bad := fileInode(1001, "bad", []byte("x"))
	// Seal the reference over different bytes than are stored so the check
	// genuinely fails; checking the same slice would produce a valid check.
	badCheckedBytes := append([]byte(nil), bad...)
	badCheckedBytes[0x60] ^= 0xff
	f.inodeAt(badOff, bad)
	f.inodeAt(goodOff, fileInode(1002, "good", []byte("y")))
	root := dirInode(inodeSpec{inum: 1, name: "/"},
		inodeRef(badOff, DirhashVisible|1, 0, badCheckedBytes, true),
		inodeRef(goodOff, DirhashVisible|2, 0, nil, false))
	f.inodeAt(testRootOff, root)

	volume := openH2(t, f.img)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if got := h2EntryNames(entries); strings.Join(got, ",") != "good" {
		t.Fatalf("entries = %v", got)
	}
	if volume.Undecodable() == 0 || len(volume.Warnings()) == 0 {
		t.Errorf("counters = undecodable %d warnings %d", volume.Undecodable(), len(volume.Warnings()))
	}
}

func TestMissingHiddenInode(t *testing.T) {
	f := newH2Fixture()
	root := dirInode(inodeSpec{inum: 1, name: "/"},
		direntRef(DirhashVisible|1, 9999, "ghost", ObjtypeRegfile))
	f.inodeAt(testRootOff, root)
	volume := openH2(t, f.img)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %v", h2EntryNames(entries))
	}
	if volume.Undecodable() == 0 {
		t.Errorf("undecodable = 0")
	}
}

func TestBadDirectoryReferences(t *testing.T) {
	t.Run("data reference", func(t *testing.T) {
		f := newH2Fixture()
		root := dirInode(inodeSpec{inum: 1, name: "/"},
			dataRef(DirhashVisible|1, f.alloc(4096), 12, make([]byte, 4096), false))
		f.inodeAt(testRootOff, root)
		volume := openH2(t, f.img)
		if volume.Malformed() == 0 {
			t.Errorf("malformed = 0")
		}
	})
	t.Run("unsupported reference", func(t *testing.T) {
		f := newH2Fixture()
		ref := refBytes(BrefTypeFreemap, 0, DirhashVisible|1, 0, 0, nil, nil)
		root := dirInode(inodeSpec{inum: 1, name: "/"}, ref)
		f.inodeAt(testRootOff, root)
		volume := openH2(t, f.img)
		if volume.Refusals() == 0 {
			t.Errorf("refusals = 0")
		}
	})
	t.Run("hidden inode below subdirectory", func(t *testing.T) {
		f := newH2Fixture()
		subOff := f.alloc(InodeBytes)
		hiddenOff := f.alloc(InodeBytes)
		f.inodeAt(hiddenOff, fileInode(7000, "hidden", []byte("x")))
		f.inodeAt(subOff, dirInode(inodeSpec{inum: 1001, name: "sub"},
			inodeRef(hiddenOff, 7000, 0, nil, false)))
		f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"},
			inodeRef(subOff, DirhashVisible|1, 0, nil, false)))
		volume := openH2(t, f.img)
		if volume.Malformed() == 0 {
			t.Errorf("malformed = 0")
		}
	})
	t.Run("duplicate visible key", func(t *testing.T) {
		f := newH2Fixture()
		firstOff := f.alloc(InodeBytes)
		secondOff := f.alloc(InodeBytes)
		f.inodeAt(firstOff, fileInode(1001, "first", []byte("a")))
		f.inodeAt(secondOff, fileInode(1002, "second", []byte("b")))
		root := dirInode(inodeSpec{inum: 1, name: "/"},
			inodeRef(firstOff, DirhashVisible|1, 0, nil, false),
			inodeRef(secondOff, DirhashVisible|1, 0, nil, false))
		f.inodeAt(testRootOff, root)
		volume := openH2(t, f.img)
		entries, err := volume.ListDir("/")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name != "first" {
			t.Errorf("entries = %v", h2EntryNames(entries))
		}
		if len(volume.Warnings()) == 0 {
			t.Errorf("no duplicate warning")
		}
	})
	t.Run("bad indirect subtree", func(t *testing.T) {
		f := newH2Fixture()
		goodOff := f.alloc(InodeBytes)
		badIndirect := f.alloc(4096)
		f.inodeAt(goodOff, fileInode(1001, "good", []byte("x")))
		root := dirInode(inodeSpec{inum: 1, name: "/"},
			indirectRef(badIndirect, 12, nil, true), // no valid check bytes
			inodeRef(goodOff, DirhashVisible|2, 0, nil, false))
		f.inodeAt(testRootOff, root)
		volume := openH2(t, f.img)
		entries, err := volume.ListDir("/")
		if err != nil {
			t.Fatal(err)
		}
		if got := h2EntryNames(entries); strings.Join(got, ",") != "good" {
			t.Errorf("entries = %v", got)
		}
		if volume.Unreadable() == 0 {
			t.Errorf("unreadable = 0")
		}
	})
}

func TestNonUTF8SymlinkTarget(t *testing.T) {
	f := newH2Fixture()
	linkOff := f.alloc(InodeBytes)
	target := []byte{0xff, 0xfe}
	f.inodeAt(linkOff, inodeBytes(inodeSpec{inum: 1001, objType: ObjtypeSoftlink, mode: 0o777, size: 2,
		name: "link", opFlags: OpflagDirectData, union: target}))
	f.inodeAt(testRootOff, dirInode(inodeSpec{inum: 1, name: "/"}, inodeRef(linkOff, DirhashVisible|1, 0, nil, false)))
	volume := openH2(t, f.img)
	entry, err := volume.Stat("/link")
	if err != nil {
		t.Fatal(err)
	}
	if entry.SymlinkTarget != "" {
		t.Errorf("target = %q", entry.SymlinkTarget)
	}
	if _, err := volume.SymlinkTarget("/link"); !errors.Is(err, ErrNoSymlinkTarget) {
		t.Errorf("SymlinkTarget error = %v", err)
	}
	if len(volume.Warnings()) == 0 {
		t.Errorf("no warning")
	}
}

// ---- Info and source semantics --------------------------------------------

func TestInfo(t *testing.T) {
	f, _ := basicTree()
	volume := openH2(t, f.img)
	info := volume.Info()
	if info.Type != KindLabel {
		t.Errorf("type = %q", info.Type)
	}
	if info.FSID == "" || info.Version != VersionMultiVolumes || info.NVolumes != 1 {
		t.Errorf("info = %+v", info)
	}
	if info.Entries != 5 { // root, hello, sub, hidden, inner
		t.Errorf("entries = %d", info.Entries)
	}
	if info.Directories != 2 || info.Files != 3 {
		t.Errorf("counts = dirs %d files %d", info.Directories, info.Files)
	}
	if len(info.Warnings) == 0 {
		t.Errorf("warnings empty")
	}
}

func TestSourceSemantics(t *testing.T) {
	f, _ := basicTree()
	volume := openH2(t, f.img)
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if file.SourceID() == 0 || file.SectorSize() != 512 || file.ImageID() != 0 {
		t.Errorf("identity = %d/%d/%d", file.SourceID(), file.SectorSize(), file.ImageID())
	}
	buffer := make([]byte, 8)
	if n, err := file.ReadAt(0, buffer); err != nil || n != 5 {
		t.Fatalf("short read = %d, %v", n, err)
	}
	if got, err := file.ReadAtLossy(0, buffer); err != nil || got != 5 {
		t.Errorf("lossy = %d, %v", got, err)
	}
	if _, err := file.ReadAtLossy(10, buffer); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("lossy out-of-range = %v", err)
	}
	if file.IsEmpty() {
		t.Errorf("IsEmpty")
	}
	if file.Stats().Reads == 0 {
		t.Errorf("stats = %+v", file.Stats())
	}
	ranges, err := file.Extents(0, 5)
	if err != nil || len(ranges) != 1 || ranges[0].Kind != source.RangeData {
		t.Errorf("extents = %+v, %v", ranges, err)
	}
	images, err := file.MapToImage(0, 5)
	if err != nil || len(images) != 1 {
		t.Errorf("images = %+v, %v", images, err)
	}
}
