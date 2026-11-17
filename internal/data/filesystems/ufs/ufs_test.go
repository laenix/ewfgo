package ufs

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- hermetic fixture geometry ---------------------------------------------

const (
	testBSize        = 8192
	testFSize        = 2048
	testFrag         = 4
	testBlocksPerGrp = 512
	testGroups       = 2
	testInodesPerGrp = 64
	testVolumeLen    = testBlocksPerGrp * testGroups * testFSize
	testUFS2Offset   = 65536
	testUFS1Offset   = 8192
	testSBIno        = int32(32)
	testCBIno        = int32(40)
	testIBIno        = int32(48)
	testDBIno        = int32(56)
)

const (
	fragRoot     = 100
	fragNotes    = 104
	fragSlow     = 108
	fragSub      = 112
	fragInner    = 116
	fragHole0    = 120
	fragHole2    = 124
	fragSingle   = 128
	fragSingle12 = 132
	fragSingle15 = 136
	fragDouble   = 140
	fragDoubleLf = 144
	fragDouble0  = 148
	fragDouble1  = 152
	fragTriple   = 156
	fragTriple2  = 160
	fragTriple1  = 164
	fragTriple0  = 168
	fragCorrupt  = 172
)

// ---- little-endian fixture writers -----------------------------------------

func putU16(dst []byte, at int, value uint16) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
}

func putU32(dst []byte, at int, value uint32) {
	dst[at] = byte(value)
	dst[at+1] = byte(value >> 8)
	dst[at+2] = byte(value >> 16)
	dst[at+3] = byte(value >> 24)
}

func putU64(dst []byte, at int, value uint64) {
	putU32(dst, at, uint32(value))
	putU32(dst, at+4, uint32(value>>32))
}

func putBE16(dst []byte, at int, value uint16) {
	dst[at] = byte(value >> 8)
	dst[at+1] = byte(value)
}

func putBE32(dst []byte, at int, value uint32) {
	dst[at] = byte(value >> 24)
	dst[at+1] = byte(value >> 16)
	dst[at+2] = byte(value >> 8)
	dst[at+3] = byte(value)
}

func putBE64(dst []byte, at int, value uint64) {
	putBE32(dst, at, uint32(value>>32))
	putBE32(dst, at+4, uint32(value))
}

// superblockBytes builds one coherent 1376-byte superblock. The geometry is
// the shape newfs writes and the reader validates.
func superblockBytes(version Version, endian Endian, offset uint64) []byte {
	raw := make([]byte, SuperblockLen)
	u32 := func(at int, value uint32) {
		if endian == BigEndian {
			putBE32(raw, at, value)
		} else {
			putU32(raw, at, value)
		}
	}
	u64 := func(at int, value uint64) {
		if endian == BigEndian {
			putBE64(raw, at, value)
		} else {
			putU64(raw, at, value)
		}
	}
	inopb := uint32(testBSize / version.InodeSize())
	nindir := uint32(testBSize / version.PointerSize())
	maxsymlink := uint32(120)
	if version == UFS1 {
		maxsymlink = 60
	}
	u32(8, uint32(testSBIno))
	u32(12, uint32(testCBIno))
	u32(16, uint32(testIBIno))
	u32(20, uint32(testDBIno))
	u32(36, testBlocksPerGrp*testGroups) // fs_old_size
	u32(40, 900)                         // fs_old_dsize
	u32(44, testGroups)
	u32(48, testBSize)
	u32(52, testFSize)
	u32(56, testFrag)
	u32(96, 2) // fragshift
	u32(100, 2)
	u32(104, 4096)
	u32(116, nindir)
	u32(120, inopb)
	u32(144, 0x12345678)
	u32(148, 0x9abcdef0)
	u32(160, 4096) // cgsize
	u32(184, testInodesPerGrp)
	u32(188, testBlocksPerGrp)
	raw[209] = 1 // clean
	copy(raw[212:221], "/forensic")
	copy(raw[680:686], "UFS-TS")
	u64(872, testVolumeLen) // provider size
	u64(992, 0)
	u64(1000, offset)
	u64(1072, 1_700_000_000)
	u64(1080, testBlocksPerGrp*testGroups)
	u64(1088, 900)
	u32(1208, 1_700_000_400)
	u32(1308, 0)                        // no check hashes
	u32(1312, uint32(FS_FLAGS_UPDATED)) // clean, 64-bit fields
	u32(1320, maxsymlink)               //
	u32(1324, uint32(FS_44INODEFMT))    //
	u32(1372, version.Magic())          // magic last
	return raw
}

// ---- fixture ---------------------------------------------------------------

type testRecord struct {
	inode uint32
	name  string
	kind  uint8
}

func dirRecord(inode uint32, name string, reclen int, kind uint8) []byte {
	out := make([]byte, reclen)
	putU32(out, 0, inode)
	putU16(out, 4, uint16(reclen))
	out[6] = kind
	out[7] = byte(len(name))
	copy(out[8:], name)
	return out
}

// dirChunk tiles one 512-byte directory chunk; the last record absorbs the
// slack exactly as the kernel leaves it.
func dirChunk(records []testRecord) []byte {
	chunk := make([]byte, 0, DirBlockSize)
	for index, record := range records {
		reclen := DirBlockSize - len(chunk)
		if index+1 < len(records) {
			reclen = direntLen(len(record.name))
		}
		chunk = append(chunk, dirRecord(record.inode, record.name, reclen, record.kind)...)
	}
	if len(chunk) != DirBlockSize {
		panic("directory fixture record does not tile one chunk")
	}
	return chunk
}

type fixture struct {
	t       *testing.T
	version Version
	image   []byte
}

func newFixture(t *testing.T, version Version) *fixture {
	t.Helper()
	return &fixture{t: t, version: version, image: make([]byte, testVolumeLen)}
}

func (f *fixture) superblockOffset() uint64 {
	if f.version == UFS1 {
		return testUFS1Offset
	}
	return testUFS2Offset
}

// installSuperblock writes the superblock and the two coherent cylinder-group
// headers at the offsets the geometry gives.
func (f *fixture) installSuperblock() {
	f.t.Helper()
	offset := f.superblockOffset()
	copy(f.image[offset:], superblockBytes(f.version, LittleEndian, offset))
	for group := uint64(0); group < testGroups; group++ {
		f.writeCylinderGroup(group, 0, nil, nil)
	}
	// A minimal root inode so Open's probe succeeds; buildStandard overwrites
	// it with the real directory.
	f.writeInode(RootInode, SIFDIR|0o755, 2, 0, nil, nil)
}

// cgOffset computes the byte offset of a cylinder group header using the same
// geometry the reader derives from the superblock.
func (f *fixture) cgOffset(group uint64) uint64 {
	base := group * testBlocksPerGrp
	return (base + uint64(testCBIno)) * testFSize
}

func (f *fixture) writeCylinderGroup(group uint64, usedOff uint32, usedBits []uint32, freeBits []uint32) {
	f.t.Helper()
	at := int(f.cgOffset(group))
	header := f.image[at : at+4096]
	putU32(header, 4, CGMagic)
	putU32(header, 20, testBlocksPerGrp)
	putU32(header, 92, usedOff)
	putU32(header, 96, 176)
	putU32(header, 116, testInodesPerGrp)
	putU32(header, 120, testInodesPerGrp)
	for _, bit := range usedBits {
		header[usedOff+bit/8] |= 1 << (bit % 8)
	}
	for _, bit := range freeBits {
		header[176+bit/8] |= 1 << (bit % 8)
	}
	// Record the summaries the real writer maintains so the scan's cross-check
	// agrees with the bitmap.
	freeFrags := testBlocksPerGrp - len(freeBits)
	putU32(header, 28, uint32(freeFrags/testFrag))
	putU32(header, 36, uint32(freeFrags%testFrag))
}

func (f *fixture) inodeOffset(number uint32) uint64 {
	group := uint64(number) / testInodesPerGrp
	index := uint64(number) % testInodesPerGrp
	inopb := uint64(testBSize / f.version.InodeSize())
	block := index / inopb
	slot := index % inopb
	fragment := group*testBlocksPerGrp + uint64(testIBIno) + block*testFrag
	return fragment*testFSize + slot*uint64(f.version.InodeSize())
}

func (f *fixture) writeInodeBytes(number uint32, raw []byte) {
	f.t.Helper()
	at := int(f.inodeOffset(number))
	copy(f.image[at:at+len(raw)], raw)
}

// inodeBytes builds a UFS1 or UFS2 inode. Pointers are fragment numbers.
func inodeBytes(version Version, mode uint16, links uint16, size uint64, db, ib []int64) []byte {
	raw := make([]byte, version.InodeSize())
	putU16(raw, 0, mode)
	putU16(raw, 2, links)
	if version == UFS1 {
		putU64(raw, 8, size)
		putU32(raw, 16, 1_700_000_000)
		putU32(raw, 20, 1)
		putU32(raw, 24, 1_700_000_100)
		putU32(raw, 28, 2)
		putU32(raw, 32, 1_700_000_200)
		putU32(raw, 36, 3)
		for index, pointer := range db {
			if index >= 12 {
				break
			}
			putU32(raw, 40+index*4, uint32(int32(pointer)))
		}
		for index, pointer := range ib {
			if index >= 3 {
				break
			}
			putU32(raw, 88+index*4, uint32(int32(pointer)))
		}
		putU32(raw, 104, uint32(len(db)*2))
		putU32(raw, 108, 7)
		putU32(raw, 112, 1000)
		putU32(raw, 116, 1000)
		return raw
	}
	putU32(raw, 4, 1000)
	putU32(raw, 8, 1000)
	putU64(raw, 16, size)
	putU64(raw, 24, uint64(len(db))*2)
	putU64(raw, 32, 1_700_000_000)
	putU32(raw, 64, 2)
	putU64(raw, 40, 1_700_000_100)
	putU32(raw, 68, 1)
	putU64(raw, 48, 1_700_000_200)
	putU32(raw, 72, 3)
	putU64(raw, 56, 1_700_000_300)
	putU32(raw, 76, 4)
	putU32(raw, 80, 9)
	putU32(raw, 88, 0)
	for index, pointer := range db {
		if index >= 12 {
			break
		}
		putU64(raw, 112+index*8, uint64(pointer))
	}
	for index, pointer := range ib {
		if index >= 3 {
			break
		}
		putU64(raw, 208+index*8, uint64(pointer))
	}
	return raw
}

func (f *fixture) writeInode(number uint32, mode uint16, links uint16, size uint64, db, ib []int64) {
	f.t.Helper()
	f.writeInodeBytes(number, inodeBytes(f.version, mode, links, size, db, ib))
}

func (f *fixture) writeFastSymlink(number uint32, target string) {
	f.t.Helper()
	raw := inodeBytes(f.version, SIFLNK|0o777, 1, uint64(len(target)), nil, nil)
	inline := 112
	if f.version == UFS1 {
		inline = 40
	}
	copy(raw[inline:inline+len(target)], target)
	f.writeInodeBytes(number, raw)
}

func (f *fixture) writeFrag(fragment uint64, data []byte) {
	f.t.Helper()
	at := int(fragment * testFSize)
	copy(f.image[at:at+len(data)], data)
}

func (f *fixture) source() source.ByteSource {
	return source.NewMemorySource(1, f.image)
}

func (f *fixture) open() *Volume {
	f.t.Helper()
	volume, err := Open(f.source())
	if err != nil {
		f.t.Fatalf("Open: %v", err)
	}
	return volume
}

// setRoot writes the root directory's only block at fragRoot and its inode.
func (f *fixture) setRoot(records []testRecord) {
	f.t.Helper()
	f.writeFrag(fragRoot, dirChunk(records))
	f.writeInode(RootInode, SIFDIR|0o755, 2, DirBlockSize, []int64{fragRoot}, nil)
}

// buildStandard synthesises the volume the main tests read.
func buildStandard(t *testing.T, version Version) *fixture {
	t.Helper()
	f := newFixture(t, version)
	f.installSuperblock()

	// Root directory.
	f.setRoot([]testRecord{
		{RootInode, ".", DT_DIR},
		{RootInode, "..", DT_DIR},
		{3, "notes.txt", DT_REG},
		{4, "fast", DT_LNK},
		{6, "slow", DT_LNK},
		{5, "stale", DT_REG},
		{7, "sub", DT_DIR},
		{9, "hole", DT_REG},
		{10, "big", DT_REG},
		{11, "double", DT_REG},
		{12, "triple", DT_REG},
		{7, "loop", DT_DIR},
		{13, "empty", DT_DIR},
		{14, "badptr", DT_REG},
		{15, "negative", DT_REG},
	})
	f.writeFrag(fragNotes, []byte("hello"))
	f.writeFastSymlink(4, "target.txt")
	f.writeFrag(fragSlow, bytes.Repeat([]byte("z"), 300))
	sub := dirChunk([]testRecord{
		{7, ".", DT_DIR},
		{RootInode, "..", DT_DIR},
		{8, "inner.txt", DT_REG},
	})
	f.writeFrag(fragSub, sub)
	f.writeFrag(fragInner, []byte("abc"))

	f.writeInode(3, SIFREG|0o644, 1, 5, []int64{fragNotes}, nil)
	f.writeInode(5, 0, 0, 0, nil, nil) // cleared: the stale record names it
	f.writeInode(6, SIFLNK|0o777, 1, 300, []int64{fragSlow}, nil)
	f.writeInode(7, SIFDIR|0o755, 2, DirBlockSize, []int64{fragSub}, nil)
	f.writeInode(8, SIFREG|0o644, 1, 3, []int64{fragInner}, nil)
	f.writeInode(13, SIFDIR|0o755, 2, 0, nil, nil)

	// A file with a hole in its second block.
	f.writeFrag(fragHole0, []byte("first"))
	f.writeFrag(fragHole2, []byte("third"))
	f.writeInode(9, SIFREG|0o644, 1, 3*testBSize, []int64{fragHole0, 0, fragHole2}, nil)

	putPointer := func(raw []byte, index int, value uint64) {
		if version == UFS1 {
			putU32(raw, index*4, uint32(value))
		} else {
			putU64(raw, index*8, value)
		}
	}

	// Single indirect: logical blocks 12 and 15.
	single := make([]byte, testBSize)
	putPointer(single, 0, fragSingle12)
	putPointer(single, 3, fragSingle15)
	f.writeFrag(fragSingle, single)
	f.writeFrag(fragSingle12, []byte("single-12"))
	f.writeFrag(fragSingle15, []byte("single-15"))
	f.writeInode(10, SIFREG|0o644, 1, 16*testBSize, nil, []int64{fragSingle, 0, 0})

	nindir := uint64(testBSize / version.PointerSize())

	// Double indirect: the first two blocks past the single-indirect range.
	doubleRoot := make([]byte, testBSize)
	putPointer(doubleRoot, 0, fragDoubleLf)
	doubleLeaf := make([]byte, testBSize)
	putPointer(doubleLeaf, 0, fragDouble0)
	putPointer(doubleLeaf, 1, fragDouble1)
	f.writeFrag(fragDouble, doubleRoot)
	f.writeFrag(fragDoubleLf, doubleLeaf)
	f.writeFrag(fragDouble0, []byte("double-0"))
	f.writeFrag(fragDouble1, []byte("double-1"))
	f.writeInode(11, SIFREG|0o644, 1, (12+nindir+2)*testBSize, nil, []int64{0, fragDouble, 0})

	// Triple indirect: one path down to logical block 12+1024+1024^2.
	tripleRoot := make([]byte, testBSize)
	putPointer(tripleRoot, 0, fragTriple2)
	tripleTwo := make([]byte, testBSize)
	putPointer(tripleTwo, 0, fragTriple1)
	tripleOne := make([]byte, testBSize)
	putPointer(tripleOne, 0, fragTriple0)
	f.writeFrag(fragTriple, tripleRoot)
	f.writeFrag(fragTriple2, tripleTwo)
	f.writeFrag(fragTriple1, tripleOne)
	f.writeFrag(fragTriple0, []byte("triple"))
	f.writeInode(12, SIFREG|0o644, 1, (12+nindir+nindir*nindir+1)*testBSize, nil, []int64{0, 0, fragTriple})

	f.writeInode(14, SIFREG|0o644, 1, testBSize, []int64{999999}, nil)
	f.writeInode(15, SIFREG|0o644, 1, testBSize, []int64{-1}, nil)

	// Inode 16 is an oversized directory that no root record names; inode 17
	// is a damaged directory used only by the parser tests.
	f.writeInode(16, SIFDIR|0o755, 2, MaxDirSize+1, nil, nil)
	corrupt := make([]byte, testBSize)
	copy(corrupt, dirChunk([]testRecord{
		{17, ".", DT_DIR},
		{RootInode, "..", DT_DIR},
		{3, "ok", DT_REG},
	}))
	copy(corrupt[DirBlockSize:], dirRecord(9, "x", DirBlockSize-8, DT_REG))
	putU32(corrupt, DirBlockSize+DirBlockSize-8, 9)
	putU16(corrupt, DirBlockSize+DirBlockSize-4, 24)
	corrupt[DirBlockSize+DirBlockSize-2] = DT_REG
	corrupt[DirBlockSize+DirBlockSize-1] = 10
	f.writeFrag(fragCorrupt, corrupt)
	f.writeInode(17, SIFDIR|0o755, 2, 2*DirBlockSize, []int64{fragCorrupt}, nil)

	return f
}

// ---- detection and superblock ---------------------------------------------

func TestDetectAndOpenUFS2(t *testing.T) {
	f := buildStandard(t, UFS2)
	looks, err := Detect(f.source())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !looks {
		t.Fatal("Detect did not recognise a UFS2 image")
	}
	volume := f.open()
	info := volume.Info()
	if info.Kind != "ufs2" || info.Label != "UFS2" {
		t.Fatalf("kind = %q/%q", info.Kind, info.Label)
	}
	if info.Offset != testUFS2Offset {
		t.Fatalf("offset = %d", info.Offset)
	}
	if info.BlockSize != testBSize || info.FragSize != testFSize {
		t.Fatalf("geometry = %d/%d", info.BlockSize, info.FragSize)
	}
	if info.InodeSize != 256 || info.InodesPerBlock != 32 || info.PointersPerBlock != 1024 {
		t.Fatalf("inode geometry = %d/%d/%d", info.InodeSize, info.InodesPerBlock, info.PointersPerBlock)
	}
	if info.Groups != testGroups || info.InodesPerGroup != testInodesPerGrp || info.FragsPerGroup != testBlocksPerGrp {
		t.Fatalf("group geometry = %d/%d/%d", info.Groups, info.InodesPerGroup, info.FragsPerGroup)
	}
	if info.VolumeName != "UFS-TS" || info.MountPoint != "/forensic" {
		t.Fatalf("names = %q/%q", info.VolumeName, info.MountPoint)
	}
	if !info.Clean {
		t.Fatal("a clean superblock was reported dirty")
	}
	if info.VolumeBytes != testVolumeLen {
		t.Fatalf("volume bytes = %d", info.VolumeBytes)
	}
	if volume.Superblock().ID != [2]uint32{0x12345678, 0x9abcdef0} {
		t.Fatalf("id = %v", volume.Superblock().ID)
	}
}

func TestDetectAndOpenUFS1(t *testing.T) {
	f := buildStandard(t, UFS1)
	volume := f.open()
	info := volume.Info()
	if info.Kind != "ufs1" || info.Label != "UFS1" {
		t.Fatalf("kind = %q/%q", info.Kind, info.Label)
	}
	if info.InodeSize != 128 || info.InodesPerBlock != 64 || info.PointersPerBlock != 2048 {
		t.Fatalf("inode geometry = %d/%d/%d", info.InodeSize, info.InodesPerBlock, info.PointersPerBlock)
	}
	if info.MaxSymlinkLen != 60 {
		t.Fatalf("maxsymlinklen = %d", info.MaxSymlinkLen)
	}
	file, err := volume.OpenFile("/notes.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := file.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("data = %q", buf)
	}
	if target, err := volume.SymlinkTarget("/fast"); err != nil || target != "target.txt" {
		t.Fatalf("UFS1 inline symlink = %q/%v", target, err)
	}
}

func TestUnknownMagicIsNotAUFSVolume(t *testing.T) {
	image := make([]byte, testVolumeLen)
	raw := superblockBytes(UFS2, LittleEndian, testUFS2Offset)
	putU32(raw, 1372, 0xDEAD_BEEF)
	copy(image[testUFS2Offset:], raw)
	looks, err := Detect(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if looks {
		t.Fatal("an unknown magic was accepted")
	}
}

func TestDetectAtFloppyAndAlternateOffsets(t *testing.T) {
	for _, offset := range []uint64{SBLOCK_FLOPPY, SBLOCK_PIGGY} {
		image := make([]byte, testVolumeLen)
		copy(image[offset:], superblockBytes(UFS1, LittleEndian, offset))
		looks, err := Detect(source.NewMemorySource(1, image))
		if err != nil {
			t.Fatalf("offset %d: Detect: %v", offset, err)
		}
		if !looks {
			t.Fatalf("offset %d: not detected", offset)
		}
		sb, err := ReadSuperblock(source.NewMemorySource(1, image))
		if err != nil || sb == nil {
			t.Fatalf("offset %d: ReadSuperblock: %v", offset, err)
		}
		if sb.Offset != offset {
			t.Fatalf("offset %d recorded as %d", offset, sb.Offset)
		}
	}
}

func TestDetectRejectsForeignData(t *testing.T) {
	image := bytes.Repeat([]byte{0xA5}, 1<<20)
	looks, err := Detect(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if looks {
		t.Fatal("foreign data was recognised as UFS")
	}
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v", err)
	}
}

func TestBadMagicIsRefused(t *testing.T) {
	raw := superblockBytes(UFS2, LittleEndian, testUFS2Offset)
	putU32(raw, 1372, FS_BAD_MAGIC)
	_, err := ParseSuperblock(raw, UFS2, LittleEndian, testUFS2Offset)
	if err == nil || !strings.Contains(err.Error(), "FS_BAD_MAGIC") {
		t.Fatalf("error = %v", err)
	}
}

func TestSuperblockGeometryValidation(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		value  uint32
		want   string
	}{
		{"block size", 48, 3000, "fs_bsize"},
		{"fragment shift", 96, 3, "fs_fragshift"},
		{"fsbtodb", 100, 3, "fs_fsbtodb"},
		{"inodes per block", 120, 31, "fs_inopb"},
		{"pointers per block", 116, 1000, "fs_nindir"},
		{"cylinder groups", 44, 0, "fs_ncg"},
		{"inodes per group", 184, 63, "fs_ipg"},
		{"fragments per group", 188, 0, "fs_fpg"},
		{"cylinder group size", 160, 100, "fs_cgsize"},
		{"inode format", 1324, 1, "inode format"},
		{"check hash kinds", 1308, 0x80, "metadata check-hash"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := superblockBytes(UFS2, LittleEndian, testUFS2Offset)
			putU32(raw, test.offset, test.value)
			_, err := ParseSuperblock(raw, UFS2, LittleEndian, testUFS2Offset)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func Test42BSDInodeFormatRefused(t *testing.T) {
	raw := superblockBytes(UFS2, LittleEndian, testUFS2Offset)
	bad := FS_42INODEFMT
	putU32(raw, 1324, uint32(bad))
	_, err := ParseSuperblock(raw, UFS2, LittleEndian, testUFS2Offset)
	if err == nil || !strings.Contains(err.Error(), "4.2BSD") || !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v", err)
	}
}

func TestBigEndianSuperblockDecodes(t *testing.T) {
	raw := superblockBytes(UFS2, BigEndian, testUFS2Offset)
	sb, err := ParseSuperblock(raw, UFS2, BigEndian, testUFS2Offset)
	if err != nil {
		t.Fatalf("ParseSuperblock: %v", err)
	}
	if sb.Endian != BigEndian || sb.BlockSize() != testBSize || sb.VolumeLen() != testVolumeLen {
		t.Fatalf("decoded = endian %d block %d len %d", sb.Endian, sb.BlockSize(), sb.VolumeLen())
	}
	image := make([]byte, testVolumeLen)
	copy(image[testUFS2Offset:], raw)
	looks, err := Detect(source.NewMemorySource(1, image))
	if err != nil || !looks {
		t.Fatalf("big-endian Detect = %v, %v", looks, err)
	}
}

func TestByteSwappedGeometryRefused(t *testing.T) {
	// A little-endian magic with big-endian geometry is a mixed-endian
	// superblock: the magic says one thing and every field another.
	raw := superblockBytes(UFS2, LittleEndian, testUFS2Offset)
	putBE32(raw, 48, testBSize)
	putBE32(raw, 52, testFSize)
	if _, err := ParseSuperblock(raw, UFS2, LittleEndian, testUFS2Offset); err == nil {
		t.Fatal("a mixed-endian superblock was accepted")
	}
	// Declaring the wrong byte order must fail the magic check.
	le := superblockBytes(UFS2, LittleEndian, testUFS2Offset)
	if _, err := ParseSuperblock(le, UFS2, BigEndian, testUFS2Offset); err == nil {
		t.Fatal("a little-endian superblock was accepted as big-endian")
	}
}

func TestSuperblockCheckHash(t *testing.T) {
	f := newFixture(t, UFS2)
	f.installSuperblock()
	raw := append([]byte(nil), f.image[testUFS2Offset:testUFS2Offset+SuperblockLen]...)
	putU32(raw, 1308, CK_SUPERBLOCK)
	putU32(raw, 104, 4096)
	copy(f.image[testUFS2Offset:], raw)
	hashed := append([]byte(nil), f.image[testUFS2Offset:testUFS2Offset+4096]...)
	clear(hashed[1304:1308])
	putU32(f.image, int(testUFS2Offset)+1304, foundation.CRC32C(hashed))
	volume := f.open()
	maintained, valid, err := volume.CheckHash()
	if err != nil || !maintained || !valid {
		t.Fatalf("CheckHash = %v/%v/%v", maintained, valid, err)
	}
	f.image[testUFS2Offset+700] ^= 0xFF
	_, valid, err = volume.CheckHash()
	if err != nil || valid {
		t.Fatalf("a damaged superblock hashed valid: %v", err)
	}
}

func TestCylinderGroupAndBitmap(t *testing.T) {
	f := newFixture(t, UFS2)
	f.installSuperblock()
	f.writeCylinderGroup(0, 168, []uint32{0, 1, 2, 3, 9}, nil)
	volume := f.open()
	group, err := volume.CylinderGroup(1)
	if err != nil {
		t.Fatalf("CylinderGroup: %v", err)
	}
	if group.Index != 1 || group.Magic != CGMagic || group.NDblk != testBlocksPerGrp {
		t.Fatalf("group = %+v", group)
	}
	bitmap, err := ReadInodeBitmap(f.source(), volume.Superblock(), 0)
	if err != nil {
		t.Fatalf("ReadInodeBitmap: %v", err)
	}
	if bitmap.FirstInode != 0 || bitmap.Count != testInodesPerGrp {
		t.Fatalf("bitmap = %+v", bitmap)
	}
	for _, slot := range []uint32{0, 1, 2, 3, 9} {
		if !bitmap.IsUsed(slot) {
			t.Fatalf("slot %d should be allocated", slot)
		}
	}
	for _, slot := range []uint32{4, 8, 10, 63} {
		if bitmap.IsUsed(slot) {
			t.Fatalf("slot %d should be free", slot)
		}
	}
	if !bitmap.IsUsed(testInodesPerGrp) {
		t.Fatal("a slot past the count must not read as free")
	}
	if _, err := volume.CylinderGroup(2); err == nil {
		t.Fatal("a group past the declared count was accepted")
	}
}

func TestCylinderGroupBitmapRefusals(t *testing.T) {
	t.Run("wrong magic", func(t *testing.T) {
		f := newFixture(t, UFS2)
		f.installSuperblock()
		putU32(f.image, int(f.cgOffset(0))+4, 0xDEADBEEF)
		if _, err := Open(f.source()); err == nil || !strings.Contains(err.Error(), "cylinder group 0") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("bitmap inside header", func(t *testing.T) {
		f := newFixture(t, UFS2)
		f.installSuperblock()
		f.writeCylinderGroup(0, 100, nil, nil)
		volume := f.open()
		_, err := ReadInodeBitmap(f.source(), volume.Superblock(), 0)
		if err == nil || !strings.Contains(err.Error(), "inode bitmap") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("group claims too many inodes", func(t *testing.T) {
		f := newFixture(t, UFS2)
		f.installSuperblock()
		f.writeCylinderGroup(0, 168, nil, nil)
		putU32(f.image, int(f.cgOffset(0))+116, testInodesPerGrp+1)
		volume := f.open()
		_, err := ReadInodeBitmap(f.source(), volume.Superblock(), 0)
		if err == nil || !strings.Contains(err.Error(), "claims 65") {
			t.Fatalf("error = %v", err)
		}
	})
}

// ---- inodes ----------------------------------------------------------------

func TestInodeParsing(t *testing.T) {
	ufs1 := inodeBytes(UFS1, SIFREG|0o644, 2, 12_345, []int64{77, 78}, []int64{90})
	inode, err := ParseInode(7, ufs1, UFS1, LittleEndian)
	if err != nil {
		t.Fatalf("ParseInode UFS1: %v", err)
	}
	if inode.Number != 7 || !inode.IsRegular() || inode.Links != 2 || inode.Size != 12_345 {
		t.Fatalf("inode = %+v", inode)
	}
	if inode.DB[0] != 77 || inode.DB[1] != 78 || inode.IB[0] != 90 {
		t.Fatalf("pointers = %v/%v", inode.DB, inode.IB)
	}
	if inode.UID != 1000 || inode.GID != 1000 || inode.Generation != 7 {
		t.Fatalf("ids = %d/%d/%d", inode.UID, inode.GID, inode.Generation)
	}
	if inode.AccessTime != (UfsTime{Seconds: 1_700_000_000, Nanos: 1}) {
		t.Fatalf("atime = %+v", inode.AccessTime)
	}
	if inode.CreationTime != nil || inode.CheckHash != nil || inode.FreeLink != nil {
		t.Fatal("a UFS1 inode acquired UFS2-only fields")
	}
	if len(inode.InlineLink()) != 60 {
		t.Fatalf("inline capacity = %d", len(inode.InlineLink()))
	}

	ufs2 := inodeBytes(UFS2, SIFLNK|0o777, 1, 12, []int64{1<<32 + 5}, []int64{300})
	inode, err = ParseInode(3, ufs2, UFS2, LittleEndian)
	if err != nil {
		t.Fatalf("ParseInode UFS2: %v", err)
	}
	if !inode.IsSymlink() || inode.DB[0] != 1<<32+5 || inode.IB[0] != 300 {
		t.Fatalf("inode = %+v", inode)
	}
	if inode.CreationTime == nil || inode.CreationTime.Seconds != 1_700_000_300 {
		t.Fatalf("birth time = %+v", inode.CreationTime)
	}
	if len(inode.InlineLink()) != 120 {
		t.Fatalf("inline capacity = %d", len(inode.InlineLink()))
	}
}

func TestShortAndClearedInodes(t *testing.T) {
	if _, err := ParseInode(2, make([]byte, 64), UFS2, LittleEndian); err == nil || !strings.Contains(err.Error(), "256") {
		t.Fatalf("short inode error = %v", err)
	}
	inode, err := ParseInode(9, make([]byte, 128), UFS1, LittleEndian)
	if err != nil {
		t.Fatalf("cleared inode: %v", err)
	}
	if !inode.IsCleared() || inode.FileType() != InodeUnknown {
		t.Fatalf("cleared inode = %+v", inode)
	}
}

func TestFastSymlinkBoundary(t *testing.T) {
	raw := inodeBytes(UFS2, SIFLNK|0o777, 1, 120, nil, nil)
	inode, err := ParseInode(3, raw, UFS2, LittleEndian)
	if err != nil {
		t.Fatalf("ParseInode: %v", err)
	}
	if inode.IsFastSymlink(120) {
		t.Fatal("a target exactly at the limit must be stored in blocks")
	}
	if inode.IsFastSymlink(119) {
		t.Fatal("a target longer than the limit must not be inline")
	}
	if !inode.IsFastSymlink(121) {
		t.Fatal("a target below the limit must be inline")
	}
	if inode.IsFastSymlink(0) {
		t.Fatal("maxsymlinklen 0 must disable inline targets")
	}
}

func TestBigEndianInodeDecodes(t *testing.T) {
	raw := make([]byte, 128)
	putBE16(raw, 0, SIFDIR|0o755)
	putBE16(raw, 2, 1)
	putBE64(raw, 8, 512)
	putBE32(raw, 40, 12)
	putBE32(raw, 112, 0)
	inode, err := ParseInode(2, raw, UFS1, BigEndian)
	if err != nil {
		t.Fatalf("ParseInode: %v", err)
	}
	if !inode.IsDirectory() || inode.Size != 512 || inode.DB[0] != 12 {
		t.Fatalf("inode = %+v", inode)
	}
}

// ---- directory parsing -----------------------------------------------------

func TestDirectoryRecordForms(t *testing.T) {
	chunk := dirChunk([]testRecord{
		{RootInode, ".", DT_DIR},
		{RootInode, "..", DT_DIR},
		{9, "notes.txt", DT_REG},
	})
	block := ParseDirBlock(chunk, 0, LittleEndian, false)
	if !block.Tiled || len(block.Entries) != 3 {
		t.Fatalf("block = %+v", block)
	}
	if block.Entries[2].Name != "notes.txt" || block.Entries[2].Offset != 24 {
		t.Fatalf("entry = %+v", block.Entries[2])
	}
	if block.Entries[2].RecordLength != uint16(DirBlockSize-24) {
		t.Fatalf("record length = %d", block.Entries[2].RecordLength)
	}

	// A grown record still holds the name it absorbed.
	slack := dirRecord(3, "live.txt", DirBlockSize, DT_REG)
	copy(slack[20:40], dirRecord(4, "gone.txt", 20, DT_REG))
	copy(slack[40:56], dirRecord(5, "older", 16, DT_REG))
	block = ParseDirBlock(slack, 0, LittleEndian, false)
	if !block.Tiled || len(block.Entries) != 1 {
		t.Fatalf("grown block = %+v", block)
	}
	if len(block.Slack) != 2 || block.Slack[0].Name != "gone.txt" || block.Slack[0].Inode != 4 {
		t.Fatalf("slack = %+v", block.Slack)
	}
}

func TestDirectoryFreeWhiteoutAndOldFormat(t *testing.T) {
	chunk := make([]byte, DirBlockSize)
	copy(chunk, dirRecord(2, ".", 12, DT_REG))
	putU32(chunk, 12, 0)
	putU16(chunk, 16, uint16(DirBlockSize-12))
	block := ParseDirBlock(chunk, 0, LittleEndian, false)
	if !block.Tiled || len(block.Entries) != 1 || block.FreedBytes != DirBlockSize-12 {
		t.Fatalf("freed block = %+v", block)
	}

	chunk = make([]byte, DirBlockSize)
	copy(chunk, dirRecord(1, "gone", DirBlockSize, DTWht))
	block = ParseDirBlock(chunk, 0, LittleEndian, false)
	if len(block.Entries) != 0 || block.Whiteouts != 1 || !block.Tiled {
		t.Fatalf("whiteout block = %+v", block)
	}

	old := make([]byte, DirBlockSize)
	putU32(old, 0, 7)
	putU16(old, 4, DirBlockSize)
	old[6] = 3 // namlen, not d_type
	copy(old[8:], "old")
	block = ParseDirBlock(old, 0, LittleEndian, true)
	if !block.Tiled || len(block.Entries) != 1 || block.Entries[0].Name != "old" {
		t.Fatalf("old-format block = %+v", block)
	}
	if block.Entries[0].Kind != DTUnknown {
		t.Fatalf("old-format kind = %d", block.Entries[0].Kind)
	}
	if !UsesOldFormat(0) || UsesOldFormat(60) {
		t.Fatal("UsesOldFormat boundary is wrong")
	}
}

func TestDirectoryUntiledChunk(t *testing.T) {
	chunk := make([]byte, DirBlockSize)
	copy(chunk, dirRecord(2, ".", DirBlockSize-8, DT_REG))
	putU32(chunk, DirBlockSize-8, 9)
	putU16(chunk, DirBlockSize-4, 24)
	block := ParseDirBlock(chunk, 0, LittleEndian, false)
	if block.Tiled {
		t.Fatal("a record crossing its chunk was accepted")
	}
	if len(block.Entries) != 1 || block.Entries[0].Name != "." {
		t.Fatalf("entries = %+v", block.Entries)
	}
}

func TestDirentLenAndKindMapping(t *testing.T) {
	if direntLen(0) != 12 || direntLen(3) != 12 || direntLen(4) != 16 || direntLen(255) != 264 {
		t.Fatalf("direntLen values = %d/%d/%d/%d", direntLen(0), direntLen(3), direntLen(4), direntLen(255))
	}
	if KindForMode(SIFDIR) != DTDir || KindForMode(SIFREG) != DTReg || KindForMode(SIFLNK) != DTLnk {
		t.Fatal("mode-to-dir-type mapping is wrong")
	}
}

// ---- volume tree -----------------------------------------------------------

func TestRootListingAndNestedDirectories(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
		if entry.Name == "." || entry.Name == ".." {
			t.Fatal("ListDir returned a dot entry")
		}
	}
	want := []string{"notes.txt", "fast", "slow", "stale", "sub", "hole", "big", "double", "triple", "loop", "empty", "badptr", "negative"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v", names)
	}
	notes := entries[0]
	if notes.Path != "/notes.txt" || notes.Inode != 3 || !notes.IsFile || notes.Size != 5 {
		t.Fatalf("notes = %+v", notes)
	}
	if notes.UID != 1000 || notes.GID != 1000 || notes.Mode != SIFREG|0o644 {
		t.Fatalf("metadata = %+v", notes)
	}
	if notes.Mtime != time.Unix(1_700_000_100, 2).UTC() {
		t.Fatalf("mtime = %v", notes.Mtime)
	}
	stale := entries[3]
	if !stale.Deleted || stale.Inode != 5 {
		t.Fatalf("stale = %+v", stale)
	}
	sub, err := volume.ListDir("/sub")
	if err != nil {
		t.Fatalf("ListDir /sub: %v", err)
	}
	if len(sub) != 1 || sub[0].Name != "inner.txt" || sub[0].Path != "/sub/inner.txt" || !sub[0].IsFile {
		t.Fatalf("sub = %+v", sub)
	}
	empty, err := volume.ListDir("/empty")
	if err != nil {
		t.Fatalf("ListDir /empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty = %+v", empty)
	}
	if _, err := volume.ListDir("/notes.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("non-directory error = %v", err)
	}
	if _, err := volume.ListDir("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
}

func TestStatAndStaleLookup(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	entry, err := volume.Stat("/sub/inner.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if entry.Name != "inner.txt" || entry.Path != "/sub/inner.txt" || entry.Size != 3 {
		t.Fatalf("entry = %+v", entry)
	}
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat /: %v", err)
	}
	if root.Name != "/" || !root.IsDir {
		t.Fatalf("root = %+v", root)
	}
	if _, err := volume.Stat("/stale"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale Stat error = %v", err)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Stat error = %v", err)
	}
}

func TestPathResolutionAndCycles(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	cases := map[string]uint32{
		"/sub/inner.txt":       8,
		"sub/.":                7,
		"/sub/../notes.txt":    3,
		"/sub/../../notes.txt": 3,
		"/loop/inner.txt":      8,
		"/loop/../sub":         7,
		"/../sub/./inner.txt":  8,
	}
	for path, want := range cases {
		got, found, err := volume.LookupPath(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !found || got != want {
			t.Fatalf("%s = %d/%v, want %d", path, got, found, want)
		}
	}
	if _, found, err := volume.LookupPath("/nope"); err != nil || found {
		t.Fatalf("nope = %v/%v", found, err)
	}
	if path, found, err := volume.PathOf(8); err != nil || !found || path != "/sub/inner.txt" {
		t.Fatalf("PathOf(8) = %q/%v/%v", path, found, err)
	}
	if path, found, err := volume.PathOf(RootInode); err != nil || !found || path != "/" {
		t.Fatalf("PathOf(root) = %q/%v/%v", path, found, err)
	}
	stats, err := volume.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Directories != 3 {
		t.Fatalf("a directory loop was counted more than once: %+v", stats)
	}
}

// ---- block maps and reads --------------------------------------------------

func TestDirectIndirectAndTripleReads(t *testing.T) {
	volume := buildStandard(t, UFS2).open()

	read := func(path string, at uint64, want string) {
		t.Helper()
		file, err := volume.OpenFile(path)
		if err != nil {
			t.Fatalf("%s: OpenFile: %v", path, err)
		}
		buf := make([]byte, len(want))
		if _, err := file.ReadAt(at, buf); err != nil {
			t.Fatalf("%s at %d: %v", path, at, err)
		}
		if string(buf) != want {
			t.Fatalf("%s at %d = %q, want %q", path, at, buf, want)
		}
	}
	read("/notes.txt", 0, "hello")
	read("/big", 12*testBSize, "single-12")
	read("/big", 15*testBSize, "single-15")
	nindir := uint64(testBSize / volume.Superblock().Version.PointerSize())
	doubleBase := uint64(12) + nindir
	tripleBase := doubleBase + nindir*nindir
	read("/double", doubleBase*testBSize, "double-0")
	read("/double", (doubleBase+1)*testBSize, "double-1")
	read("/triple", tripleBase*testBSize, "triple")

	// The triply indirect file only walked one path down its tree.
	file, err := volume.OpenFile("/triple")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != (tripleBase+1)*testBSize {
		t.Fatalf("length = %d", file.Len())
	}
	if _, err := volume.OpenFile("/empty"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("directory OpenFile error = %v", err)
	}
}

func TestUFS1IndirectReads(t *testing.T) {
	volume := buildStandard(t, UFS1).open()
	nindir := uint64(testBSize / volume.Superblock().Version.PointerSize())
	doubleBase := uint64(12) + nindir
	tripleBase := doubleBase + nindir*nindir
	cases := []struct {
		path string
		at   uint64
		want string
	}{
		{"/big", 12 * testBSize, "single-12"},
		{"/big", 15 * testBSize, "single-15"},
		{"/double", doubleBase * testBSize, "double-0"},
		{"/double", (doubleBase + 1) * testBSize, "double-1"},
		{"/triple", tripleBase * testBSize, "triple"},
	}
	for _, test := range cases {
		file, err := volume.OpenFile(test.path)
		if err != nil {
			t.Fatalf("%s: OpenFile: %v", test.path, err)
		}
		buf := make([]byte, len(test.want))
		if _, err := file.ReadAt(test.at, buf); err != nil {
			t.Fatalf("%s at %d: %v", test.path, test.at, err)
		}
		if string(buf) != test.want {
			t.Fatalf("%s at %d = %q, want %q", test.path, test.at, buf, test.want)
		}
	}
}

func TestBlockMapLoopTerminates(t *testing.T) {
	f := buildStandard(t, UFS2)
	loop := make([]byte, testBSize)
	putU64(loop, 0, fragDouble) // the double-indirect root points at itself
	f.writeFrag(fragDouble, loop)
	nindir := uint64(testBSize / UFS2.PointerSize())
	f.writeInode(20, SIFREG|0o644, 1, (12+nindir+1)*testBSize, nil, []int64{0, fragDouble, 0})
	volume := f.open()
	inode, err := volume.Inode(20)
	if err != nil {
		t.Fatalf("Inode: %v", err)
	}
	blockMap, err := ReadBlockMapAll(f.source(), volume.Superblock(), inode)
	if err != nil {
		t.Fatalf("ReadBlockMapAll: %v", err)
	}
	// The depth budget terminates the cycle: each level consumes one depth.
	if len(blockMap.Indirect) != 2 {
		t.Fatalf("indirect blocks = %v", blockMap.Indirect)
	}
	if len(blockMap.Blocks) != 1 || blockMap.Blocks[0].LogicalBlock != 12+nindir {
		t.Fatalf("blocks = %v", blockMap.Blocks)
	}
}

func TestHolesReadZeroAndStayVisible(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	file, err := volume.OpenFile("/hole")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 3*testBSize)
	if _, err := file.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf[:5]) != "first" || string(buf[2*testBSize:2*testBSize+5]) != "third" {
		t.Fatalf("data = %q ... %q", buf[:5], buf[2*testBSize:2*testBSize+5])
	}
	for index := testBSize; index < 2*testBSize; index++ {
		if buf[index] != 0 {
			t.Fatalf("hole byte %d = %#x", index, buf[index])
		}
	}
	extents, err := file.Extents(0, 3*testBSize)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(extents) != 3 {
		t.Fatalf("extents = %+v", extents)
	}
	if extents[0].Kind != source.RangeData || extents[0].ParentOffset != fragHole0*testFSize {
		t.Fatalf("extent 0 = %+v", extents[0])
	}
	if extents[1].Kind != source.RangeHole || extents[1].Len != testBSize {
		t.Fatalf("extent 1 = %+v", extents[1])
	}
	if extents[2].Kind != source.RangeData || extents[2].ParentOffset != fragHole2*testFSize {
		t.Fatalf("extent 2 = %+v", extents[2])
	}
}

func TestFileSourceCountersAndImageMap(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	file, err := volume.OpenFile("/notes.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := file.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if file.Stats().BytesRead != 5 {
		t.Fatalf("stats = %+v", file.Stats())
	}
	images, err := file.MapToImage(0, 5)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(images) != 1 || images[0].ImageOffset != fragNotes*testFSize || images[0].Kind != source.RangeData {
		t.Fatalf("images = %+v", images)
	}
	if empty, err := volume.OpenFile("/empty/../notes.txt"); err != nil || empty.Len() != 5 {
		t.Fatalf("path with ..: %v", err)
	}
}

func TestTailCutAndLossyRead(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	file, err := volume.OpenFile("/notes.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := bytes.Repeat([]byte{0xFF}, 32)
	got, err := file.ReadAt(0, buf)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if got != 5 || string(buf[:5]) != "hello" || buf[5] != 0xFF {
		t.Fatalf("got %d, buf %q", got, buf)
	}
	if _, err := file.ReadAt(5, buf); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past end error = %v", err)
	}
	if _, err := file.ReadAtLossy(5, buf); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy read past end error = %v", err)
	}
	got, err = file.ReadAtLossy(0, buf)
	if err != nil || got != 5 || string(buf[:5]) != "hello" {
		t.Fatalf("lossy = %d/%q/%v", got, buf[:5], err)
	}
}

func TestSymlinkTargets(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	fast, err := volume.Stat("/fast")
	if err != nil {
		t.Fatalf("Stat fast: %v", err)
	}
	if !fast.IsSymlink || fast.SymlinkTarget != "target.txt" {
		t.Fatalf("fast = %+v", fast)
	}
	if target, err := volume.SymlinkTarget("/fast"); err != nil || target != "target.txt" {
		t.Fatalf("SymlinkTarget fast = %q/%v", target, err)
	}
	slow, err := volume.Stat("/slow")
	if err != nil {
		t.Fatalf("Stat slow: %v", err)
	}
	if slow.SymlinkTarget != strings.Repeat("z", 300) {
		t.Fatalf("slow target length = %d", len(slow.SymlinkTarget))
	}
	if target, err := volume.SymlinkTarget("/slow"); err != nil || len(target) != 300 {
		t.Fatalf("SymlinkTarget slow = %d/%v", len(target), err)
	}
	if _, err := volume.SymlinkTarget("/notes.txt"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("non-symlink error = %v", err)
	}
	if _, err := volume.OpenFile("/fast"); err == nil || !strings.Contains(err.Error(), "inside the inode") {
		t.Fatalf("fast symlink OpenFile error = %v", err)
	}
}

// ---- corruption and bounds -------------------------------------------------

func TestPointerBoundsErrors(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	if _, err := volume.OpenFile("/badptr"); err == nil || !strings.Contains(err.Error(), "past the") {
		t.Fatalf("out-of-range pointer error = %v", err)
	}
	if _, err := volume.OpenFile("/negative"); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative pointer error = %v", err)
	}
	if _, err := volume.Inode(128); err == nil || !strings.Contains(err.Error(), "past the 2 declared") {
		t.Fatalf("missing group error = %v", err)
	}
	if _, err := volume.Inode(0); err == nil || !strings.Contains(err.Error(), "null inode") {
		t.Fatalf("inode zero error = %v", err)
	}
}

func TestHugeDirectoryRefused(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	if _, err := volume.ReadDir(16); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("huge directory error = %v", err)
	}
}

func TestCorruptDirectoryChunkKeepsGoodRecords(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	entries, slack, stats, err := volume.readDirBlocks(17)
	if err != nil {
		t.Fatalf("readDirBlocks: %v", err)
	}
	if len(slack) != 0 {
		t.Fatalf("slack = %+v", slack)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %+v", entries)
	}
	if stats.Untiled != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if entries[3].Name != "x" {
		t.Fatalf("last good entry = %+v", entries[3])
	}
}

func TestTruncatedImage(t *testing.T) {
	f := buildStandard(t, UFS2)
	truncated := f.image[:90000]
	looks, err := Detect(source.NewMemorySource(1, truncated))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !looks {
		t.Fatal("superblock missing from a truncated image")
	}
	if _, err := Open(source.NewMemorySource(1, truncated)); err == nil {
		t.Fatal("an image truncated before the root inode opened")
	}

	// A source shorter than the superblock itself is simply not UFS.
	short := source.NewMemorySource(1, f.image[:4096])
	looks, err = Detect(short)
	if err != nil || looks {
		t.Fatalf("short source = %v/%v", looks, err)
	}
}

func TestVolumeStats(t *testing.T) {
	volume := buildStandard(t, UFS2).open()
	stats, err := volume.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Directories != 3 || stats.Files != 8 || stats.Symlinks != 2 || stats.Other != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.Entries != 13 || stats.DeletedNames != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.UntiledBlocks != 0 || stats.Whiteouts != 0 || stats.Unreadable != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestUncleanVolumeReported(t *testing.T) {
	f := buildStandard(t, UFS2)
	raw := f.image[testUFS2Offset : testUFS2Offset+SuperblockLen]
	putU32(raw, 1312, uint32(FS_FLAGS_UPDATED)|uint32(FS_UNCLEAN))
	volume := f.open()
	if volume.IsClean() {
		t.Fatal("FS_UNCLEAN was ignored")
	}
	if volume.Superblock().Checks(CK_SUPERBLOCK) {
		t.Fatal("a volume without hash metadata claimed a superblock hash")
	}
	if volume.NeedsFsck() || volume.HasSoftUpdatesJournal() {
		t.Fatal("unexpected fsck/journal flags")
	}
}
