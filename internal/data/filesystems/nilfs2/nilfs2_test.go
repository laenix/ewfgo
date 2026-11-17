package nilfs2

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

var slowLinkTarget = strings.Repeat("slow-target-", 6)

const (
	testBlockSize = 4096
	testBlocks    = 32
	primaryOffset = 1024
	crcSeed       = 0x1234_5678
)

// ---- little-endian fixture helpers -----------------------------------------

func putU16(dst []byte, at int, value uint16) {
	binary.LittleEndian.PutUint16(dst[at:], value)
}

func putU32(dst []byte, at int, value uint32) {
	binary.LittleEndian.PutUint32(dst[at:], value)
}

func putU64(dst []byte, at int, value uint64) {
	binary.LittleEndian.PutUint64(dst[at:], value)
}

// nilfsInode builds the fixed 128-byte on-disk inode.
func nilfsInode(mode, links uint16, uid, gid uint32, size uint64, bmap [7]uint64) []byte {
	out := make([]byte, InodeSize)
	putU16(out, 0x00, mode)
	putU16(out, 0x02, links)
	putU32(out, 0x04, uid)
	putU32(out, 0x08, gid)
	putU64(out, 0x0c, size)
	putU64(out, 0x14, (size+511)/512)
	for index, pointer := range bmap {
		putU64(out, DirectPointerOffset+index*8, pointer)
	}
	return out
}

func setTimes(inode []byte, mtime, ctime, atime uint64) {
	putU64(inode, 0x1c, mtime)
	putU64(inode, 0x24, ctime)
	putU64(inode, 0x2c, atime)
}

type testDirent struct {
	inode    uint64
	name     string
	fileType uint8
}

// nilfsDirBlock writes one block of directory records: the named entries in
// order, then one free record that reaches the end of the block.
func nilfsDirBlock(blockSize int, entries []testDirent) []byte {
	out := make([]byte, blockSize)
	offset := 0
	write := func(inode uint64, name string, fileType uint8, recLen int) {
		putU64(out, offset, inode)
		putU16(out, offset+8, uint16(recLen))
		out[offset+10] = byte(len(name))
		out[offset+11] = fileType
		copy(out[offset+12:offset+12+len(name)], name)
		offset += recLen
	}
	for _, entry := range entries {
		recLen := (DirentHeader + len(entry.name) + 3) &^ 3
		write(entry.inode, entry.name, entry.fileType, recLen)
	}
	remaining := blockSize - offset
	if remaining < DirentHeader {
		panic("fixture directory entries do not leave room for a free record")
	}
	write(0, "", 0, remaining)
	return out
}

// buildNilfs2Image synthesises a complete, self-consistent NILFS2 image.
//
//	block 0..9    unused
//	block 10..12  DAT descriptor, bitmap and entry block
//	block 13,14   cpfile and sufile inodes' first blocks (never read)
//	block 16      last partial segment's summary
//	block 17      super root (DAT, cpfile, sufile, ifile inodes)
//	block 20..22  ifile descriptor, bitmap and inode entry block
//	block 24      root directory data
//	block 25      hello world file data
//	block 26      sub directory data
//	block 27      slow symbolic link target
//	block 28      inner file data
//	block 29      empty directory data
//	block 31      backup superblock
func buildNilfs2Image(t *testing.T) []byte {
	t.Helper()
	image := make([]byte, testBlockSize*testBlocks)

	at := primaryOffset
	putU32(image, at+0x00, 2)       // s_rev_level
	putU16(image, at+0x04, 0)       // s_minor_rev_level
	putU16(image, at+0x06, Magic)   // s_magic
	putU16(image, at+0x08, 1024)    // s_bytes
	putU16(image, at+0x0a, 0)       // s_flags
	putU32(image, at+0x0c, crcSeed) // s_crc_seed
	putU32(image, at+0x14, 2)       // s_log_block_size
	putU64(image, at+0x18, 2)       // s_nsegments
	putU64(image, at+0x20, testBlocks*testBlockSize)
	putU64(image, at+0x28, 0)             // s_first_data_block
	putU64(image, at+0x30, 16)            // s_blocks_per_segment
	putU32(image, at+0x38, 5)             // s_r_segments_percentage
	putU64(image, at+0x3c, 9)             // s_last_cno
	putU64(image, at+0x44, 16)            // s_last_pseg
	putU64(image, at+0x4c, 7)             // s_last_seq
	putU64(image, at+0x54, 3)             // s_free_blocks_count
	putU64(image, at+0x5c, 1_700_000_001) // s_ctime
	putU64(image, at+0x64, 1_700_000_002) // s_mtime
	putU64(image, at+0x6c, 1_700_000_003) // s_wtime
	putU64(image, at+0x74, 5)             // s_mnt_count
	putU64(image, at+0x7c, 30)            // s_max_mnt_count
	putU64(image, at+0x84, 1_700_000_004) // s_lastcheck
	putU32(image, at+0x88, 100)           // s_checkinterval
	putU32(image, at+0x8c, 1)             // s_errors
	putU64(image, at+0x90, FirstUserIno)  // s_first_ino
	copy(image[at+0x98:at+0x98+80], "nilfs2-fixture")
	copy(image[at+0xe8:at+0xf8], []byte("nilfs2fixture001"))
	putU32(image, at+0xf8, 0x0000_0002) // s_feature_compat
	putU32(image, at+0xfc, 0)           // s_feature_ro_compat

	covered := append([]byte(nil), image[at:at+1024]...)
	clear(covered[0x10:0x14])
	putU32(image, at+0x10, foundation.CRC32Seeded(crcSeed, covered))

	backup := (testBlocks - 1) * testBlockSize
	copy(image[backup:backup+1024], image[at:at+1024])

	// Segment summary at block 16.
	summaryAt := 16 * testBlockSize
	putU32(image, summaryAt+0x00, SummaryMagic)
	putU16(image, summaryAt+0x04, 64) // ss_bytes
	putU16(image, summaryAt+0x06, FlagLogEnd|FlagSuperRoot)
	putU64(image, summaryAt+0x08, 7)             // ss_seq
	putU64(image, summaryAt+0x10, 1_700_000_010) // ss_create
	putU32(image, summaryAt+0x18, 2)             // ss_nblocks
	putU32(image, summaryAt+0x1c, 3)             // ss_nfinfo
	putU32(image, summaryAt+0x20, 64)            // ss_sumbytes
	putU64(image, summaryAt+0x28, 9)             // ss_cno
	covered = append([]byte(nil), image[summaryAt:summaryAt+64]...)
	clear(covered[0x38:0x3c])
	putU32(image, summaryAt+0x38, foundation.CRC32Seeded(crcSeed, covered))

	datInode := nilfsInode(0x8180, 0, 0, 0, 3*testBlockSize, [7]uint64{10, 11, 12})
	cpInode := nilfsInode(0x8180, 0, 0, 0, testBlockSize, [7]uint64{13})
	suInode := nilfsInode(0x8180, 0, 0, 0, testBlockSize, [7]uint64{14})
	ifInode := nilfsInode(0x8180, 0, 0, 0, 3*testBlockSize, [7]uint64{20, 21, 22})

	// Super root at block 17.
	superRootAt := 17 * testBlockSize
	putU16(image, superRootAt+0x04, SuperRootBytes)
	putU16(image, superRootAt+0x06, 0)
	putU64(image, superRootAt+0x08, 1_700_000_020)
	copy(image[superRootAt+0x10:superRootAt+0x90], datInode)
	copy(image[superRootAt+0x90:superRootAt+0x110], cpInode)
	copy(image[superRootAt+0x110:superRootAt+0x190], suInode)
	copy(image[superRootAt+0x190:superRootAt+0x210], ifInode)
	covered = append([]byte(nil), image[superRootAt:superRootAt+SuperRootBytes]...)
	clear(covered[0x00:0x04])
	putU32(image, superRootAt+0x00, foundation.CRC32Seeded(crcSeed, covered))

	// DAT entries for virtual blocks 100..105.
	datEntries := 12 * testBlockSize
	for virtual, physical := range map[uint64]uint64{
		100: 24, 101: 25, 102: 26, 103: 27, 104: 28, 105: 29,
	} {
		entryAt := datEntries + int(virtual%128)*DatEntrySize
		putU64(image, entryAt+0x00, physical)
		putU64(image, entryAt+0x08, 1)
	}

	// User inodes live in ifile file block 2 (physical 22), entry n at n*128.
	ifileEntries := 22 * testBlockSize
	setInode := func(number uint64, inode []byte) {
		copy(image[ifileEntries+int(number)*InodeSize:], inode)
	}

	rootInode := nilfsInode(0x41ed, 3, 0, 0, testBlockSize, [7]uint64{100})
	setTimes(rootInode, 1_700_000_030, 1_700_000_031, 1_700_000_032)
	setInode(RootInode, rootInode)

	helloInode := nilfsInode(0x81a4, 1, 1000, 1000, 11, [7]uint64{101})
	setTimes(helloInode, 1_700_000_100, 1_700_000_200, 1_700_000_300)
	setInode(11, helloInode)

	subInode := nilfsInode(0x41ed, 2, 0, 0, testBlockSize, [7]uint64{102})
	setInode(12, subInode)

	fastInode := nilfsInode(0xa1ff, 1, 0, 0, uint64(len("/hello.txt")), [7]uint64{})
	copy(fastInode[DirectPointerOffset:], "/hello.txt")
	setInode(13, fastInode)

	slowInode := nilfsInode(0xa1ff, 1, 0, 0, uint64(len(slowLinkTarget)), [7]uint64{103})
	setInode(14, slowInode)

	innerInode := nilfsInode(0x81a4, 1, 1000, 1000, 5, [7]uint64{104})
	setInode(15, innerInode)

	emptyInode := nilfsInode(0x41ed, 2, 0, 0, testBlockSize, [7]uint64{105})
	setInode(16, emptyInode)

	// Directory data.
	rootData := nilfsDirBlock(testBlockSize, []testDirent{
		{1, ".", 2},
		{1, "..", 2},
		{11, "hello.txt", 1},
		{12, "sub", 2},
		{13, "fast", 7},
		{14, "slow", 7},
		{16, "empty", 2},
		{1, "loop", 2},
	})
	copy(image[24*testBlockSize:], rootData)
	copy(image[25*testBlockSize:], "hello world")
	subData := nilfsDirBlock(testBlockSize, []testDirent{
		{12, ".", 2},
		{1, "..", 2},
		{15, "inner.txt", 1},
	})
	copy(image[26*testBlockSize:], subData)
	copy(image[27*testBlockSize:], slowLinkTarget)
	copy(image[28*testBlockSize:], "inner")
	emptyData := nilfsDirBlock(testBlockSize, []testDirent{
		{16, ".", 2},
		{1, "..", 2},
	})
	copy(image[29*testBlockSize:], emptyData)

	return image
}

func openNilfs(t *testing.T, image []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

// ---- detection and superblock ----------------------------------------------

func TestDetect(t *testing.T) {
	if found, err := Detect(source.NewMemorySource(1, make([]byte, primaryOffset))); err != nil || found {
		t.Fatalf("short source: found=%v err=%v", found, err)
	}
	if found, err := Detect(source.NewMemorySource(1, make([]byte, testBlockSize))); err != nil || found {
		t.Fatalf("zero source: found=%v err=%v", found, err)
	}
	if found, err := Detect(source.NewMemorySource(1, buildNilfs2Image(t))); err != nil || !found {
		t.Fatalf("fixture: found=%v err=%v", found, err)
	}

	// A magic with a bad checksum and no usable backup is an error by name.
	image := buildNilfs2Image(t)
	image[primaryOffset+0x98] ^= 0xff
	image[(testBlocks-1)*testBlockSize+0x98] ^= 0xff
	if _, err := Detect(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bad checksum error = %v", err)
	}

	// No magic on either copy is a clean non-match.
	image = buildNilfs2Image(t)
	putU16(image, primaryOffset+0x06, 0x1111)
	putU16(image, (testBlocks-1)*testBlockSize+0x06, 0x1111)
	if found, err := Detect(source.NewMemorySource(1, image)); err != nil || found {
		t.Fatalf("no magic: found=%v err=%v", found, err)
	}

	// A source that ends before the fixed fields is refused.
	short := make([]byte, primaryOffset+8)
	putU16(short, primaryOffset+0x06, Magic)
	if _, err := Detect(source.NewMemorySource(1, short)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("truncated superblock error = %v", err)
	}
}

func TestSuperblockBackupFallback(t *testing.T) {
	image := buildNilfs2Image(t)
	image[primaryOffset+0x98] ^= 0xff // break the primary checksum only
	volume := openNilfs(t, image)
	info := volume.Info()
	if !info.FromBackup {
		t.Fatal("volume did not fall back to the backup superblock")
	}
	if info.BackupStatus != "valid" {
		t.Fatalf("backup status = %q", info.BackupStatus)
	}
	if info.SuperblockOffset != (testBlocks-1)*testBlockSize {
		t.Fatalf("superblock offset = %d", info.SuperblockOffset)
	}
	if info.VolumeName != "nilfs2-fixture" {
		t.Fatalf("volume name = %q", info.VolumeName)
	}
}

func TestUnsupportedSuperblockVariants(t *testing.T) {
	image := buildNilfs2Image(t)
	putU32(image, primaryOffset+0x00, MaxRevLevel+1)
	image[(testBlocks-1)*testBlockSize+0x00] = byte(MaxRevLevel + 1)
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("revision error = %v", err)
	}

	image = buildNilfs2Image(t)
	putU32(image, primaryOffset+0x14, MaxLogBlockSize+1)
	putU32(image, (testBlocks-1)*testBlockSize+0x14, MaxLogBlockSize+1)
	// Recompute both checksums so the block-size check is reached.
	fixSuperblockChecksums(image)
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("block size error = %v", err)
	}

	image = buildNilfs2Image(t)
	putU32(image, primaryOffset+0xf8, 0)
	putU32(image, primaryOffset+0xfc, 0x10)
	putU32(image, (testBlocks-1)*testBlockSize+0xfc, 0x10)
	fixSuperblockChecksums(image)
	if _, err := Detect(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("read-only feature error = %v", err)
	}
}

func fixSuperblockChecksums(image []byte) {
	covered := append([]byte(nil), image[primaryOffset:primaryOffset+1024]...)
	clear(covered[0x10:0x14])
	putU32(image, primaryOffset+0x10, foundation.CRC32Seeded(crcSeed, covered))
	copy(image[(testBlocks-1)*testBlockSize:], image[primaryOffset:primaryOffset+1024])
}

func TestInfo(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	info := volume.Info()
	if info.BlockSize != testBlockSize || info.LogBlockSize != 2 || info.Revision != 2 {
		t.Fatalf("geometry = %+v", info)
	}
	if info.VolumeName != "nilfs2-fixture" || info.UUID != "6e696c66733266697874757265303031" {
		t.Fatalf("label/uuid = %q/%q", info.VolumeName, info.UUID)
	}
	if info.TotalBlocks != testBlocks || info.VolumeBytes != testBlocks*testBlockSize {
		t.Fatalf("blocks = %d/%d", info.TotalBlocks, info.VolumeBytes)
	}
	if info.DeviceBytes != testBlocks*testBlockSize || info.SourceBytes != testBlocks*testBlockSize {
		t.Fatalf("device/source = %d/%d", info.DeviceBytes, info.SourceBytes)
	}
	if info.Segments != 2 || info.BlocksPerSegment != 16 {
		t.Fatalf("segments = %d/%d", info.Segments, info.BlocksPerSegment)
	}
	if info.LastCNO != 9 || info.LastPseg != 16 || info.LastSeq != 7 {
		t.Fatalf("last = %d/%d/%d", info.LastCNO, info.LastPseg, info.LastSeq)
	}
	if info.DeclaredFreeBlocks != 3 || info.MountCount != 5 || info.MaxMountCount != 30 {
		t.Fatalf("counts = %d/%d/%d", info.DeclaredFreeBlocks, info.MountCount, info.MaxMountCount)
	}
	if info.BackupStatus != "valid" || info.FromBackup {
		t.Fatalf("backup = %q/%v", info.BackupStatus, info.FromBackup)
	}
	if !info.HasSuperblockCtime || !info.SuperblockCtime.Equal(time.Unix(1_700_000_001, 0).UTC()) {
		t.Fatalf("ctime = %v/%v", info.HasSuperblockCtime, info.SuperblockCtime)
	}
	if info.SegmentBlock != 16 || info.SegmentSequence != 7 || info.SegmentCNO != 9 {
		t.Fatalf("summary = %+v", info)
	}
	if info.SegmentNBlocks != 2 || info.SegmentNFinfo != 3 {
		t.Fatalf("summary counts = %d/%d", info.SegmentNBlocks, info.SegmentNFinfo)
	}
	if !info.HasSegmentCreate || !info.SegmentCreate.Equal(time.Unix(1_700_000_010, 0).UTC()) {
		t.Fatalf("segment create = %v/%v", info.HasSegmentCreate, info.SegmentCreate)
	}
	if info.SuperRootBlock != 17 || info.SuperRootBytes != SuperRootBytes {
		t.Fatalf("super root = %d/%d", info.SuperRootBlock, info.SuperRootBytes)
	}
	if !info.HasSuperRootNongcCtime || !info.SuperRootNongcCtime.Equal(time.Unix(1_700_000_020, 0).UTC()) {
		t.Fatalf("nongc ctime = %v/%v", info.HasSuperRootNongcCtime, info.SuperRootNongcCtime)
	}
}

// ---- directories -----------------------------------------------------------

func TestListDirRoot(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	want := []string{"hello.txt", "sub", "fast", "slow", "empty", "loop"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v", names)
	}
	for _, entry := range entries {
		switch entry.Name {
		case "hello.txt":
			if entry.Inode != 11 || entry.ParentInode != RootInode {
				t.Fatalf("hello inode/parent = %d/%d", entry.Inode, entry.ParentInode)
			}
			if !entry.IsFile || entry.IsDir || entry.IsSymlink {
				t.Fatalf("hello flags = %+v", entry)
			}
			if entry.Path != "/hello.txt" || entry.Size != 11 || entry.Mode != 0x81a4 {
				t.Fatalf("hello metadata = %+v", entry)
			}
			if entry.UID != 1000 || entry.GID != 1000 || entry.Links != 1 {
				t.Fatalf("hello ownership = %+v", entry)
			}
			if !entry.AllocatedKnown || entry.Allocated != testBlockSize {
				t.Fatalf("hello allocation = %+v", entry)
			}
			if !entry.HasAtime || !entry.Atime.Equal(time.Unix(1_700_000_300, 0).UTC()) {
				t.Fatalf("hello atime = %v/%v", entry.HasAtime, entry.Atime)
			}
			if !entry.HasMtime || !entry.Mtime.Equal(time.Unix(1_700_000_100, 0).UTC()) {
				t.Fatalf("hello mtime = %v/%v", entry.HasMtime, entry.Mtime)
			}
			if !entry.HasCtime || !entry.Ctime.Equal(time.Unix(1_700_000_200, 0).UTC()) {
				t.Fatalf("hello ctime = %v/%v", entry.HasCtime, entry.Ctime)
			}
			if entry.Deleted {
				t.Fatal("live entry reported deleted")
			}
		case "sub":
			if !entry.IsDir || entry.Inode != 12 || entry.Path != "/sub" {
				t.Fatalf("sub = %+v", entry)
			}
			if entry.AllocatedKnown {
				t.Fatalf("directory reported allocation = %+v", entry)
			}
		case "fast":
			if !entry.IsSymlink || entry.SymlinkTarget != "/hello.txt" {
				t.Fatalf("fast = %+v", entry)
			}
			if !entry.AllocatedKnown || entry.Allocated != 0 {
				t.Fatalf("fast allocation = %+v", entry)
			}
		case "slow":
			if !entry.IsSymlink || entry.SymlinkTarget != slowLinkTarget {
				t.Fatalf("slow = %+v", entry)
			}
			if !entry.AllocatedKnown || entry.Allocated != testBlockSize {
				t.Fatalf("slow allocation = %+v", entry)
			}
		case "empty":
			if !entry.IsDir || entry.Inode != 16 {
				t.Fatalf("empty = %+v", entry)
			}
		case "loop":
			if !entry.IsDir || entry.Inode != RootInode {
				t.Fatalf("loop = %+v", entry)
			}
		}
	}
}

func TestStatNested(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	if root.Name != "/" || root.Path != "/" || !root.IsDir || root.Inode != RootInode {
		t.Fatalf("root = %+v", root)
	}
	inner, err := volume.Stat("sub/inner.txt")
	if err != nil {
		t.Fatalf("Stat inner: %v", err)
	}
	if inner.Name != "inner.txt" || inner.Path != "/sub/inner.txt" {
		t.Fatalf("inner path = %+v", inner)
	}
	if inner.Inode != 15 || inner.Size != 5 || inner.Mode != 0x81a4 {
		t.Fatalf("inner metadata = %+v", inner)
	}
	if !inner.AllocatedKnown || inner.Allocated != testBlockSize {
		t.Fatalf("inner allocation = %+v", inner)
	}
	link, err := volume.Stat("/fast")
	if err != nil {
		t.Fatalf("Stat fast: %v", err)
	}
	if link.SymlinkTarget != "/hello.txt" {
		t.Fatalf("fast target = %q", link.SymlinkTarget)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	// An unset stored time is not 1970.
	empty, err := volume.Stat("/empty")
	if err != nil {
		t.Fatalf("Stat empty: %v", err)
	}
	if empty.HasAtime || empty.HasMtime || empty.HasCtime {
		t.Fatalf("zero times reported as set: %+v", empty)
	}
}

func TestEmptyDir(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	entries, err := volume.ListDir("/empty")
	if err != nil {
		t.Fatalf("ListDir empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty dir has %d entries", len(entries))
	}
}

func TestPathErrors(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	if _, err := volume.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("ListDir file error = %v", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("OpenFile dir error = %v", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenFile missing error = %v", err)
	}
	if _, err := volume.SymlinkTarget("/hello.txt"); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("SymlinkTarget file error = %v", err)
	}
	if _, err := volume.ListDir("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListDir missing error = %v", err)
	}
}

// ---- file data -------------------------------------------------------------

func TestReadFileAndEOF(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 11 || file.IsEmpty() {
		t.Fatalf("len = %d empty=%v", file.Len(), file.IsEmpty())
	}
	buf := make([]byte, 11)
	if _, err := file.ReadAt(0, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "hello world" {
		t.Fatalf("content = %q", buf)
	}
	if _, err := file.ReadAt(11, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("EOF error = %v", err)
	}
	// A read that crosses the declared length is short, not zero-filled.
	short := make([]byte, 16)
	n, err := file.ReadAt(8, short)
	if err != nil || n != 3 || string(short[:n]) != "rld" {
		t.Fatalf("short read = %d/%q/%v", n, short[:n], err)
	}

	ranges, err := file.Extents(0, 11)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 1 || ranges[0].Kind != source.RangeData ||
		ranges[0].ParentOffset != 25*testBlockSize || ranges[0].Len != 11 {
		t.Fatalf("ranges = %+v", ranges)
	}
	imageRanges, err := file.MapToImage(0, 11)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(imageRanges) != 1 || imageRanges[0].ImageOffset != 25*testBlockSize {
		t.Fatalf("image ranges = %+v", imageRanges)
	}
}

func TestOpenFastAndSlowSymlinks(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	fast, err := volume.OpenFile("/fast")
	if err != nil {
		t.Fatalf("open fast symlink: %v", err)
	}
	target := make([]byte, fast.Len())
	if _, err := fast.ReadAt(0, target); err != nil {
		t.Fatalf("read fast symlink: %v", err)
	}
	if string(target) != "/hello.txt" {
		t.Fatalf("fast target = %q", target)
	}
	slow, err := volume.OpenFile("/slow")
	if err != nil {
		t.Fatalf("open slow symlink: %v", err)
	}
	target = make([]byte, slow.Len())
	if _, err := slow.ReadAt(0, target); err != nil {
		t.Fatalf("read slow symlink: %v", err)
	}
	if string(target) != slowLinkTarget {
		t.Fatalf("slow target = %q", target)
	}
	if got, err := volume.SymlinkTarget("/slow"); err != nil || got != slowLinkTarget {
		t.Fatalf("SymlinkTarget slow = %q/%v", got, err)
	}
	if got, err := volume.SymlinkTarget("/fast"); err != nil || got != "/hello.txt" {
		t.Fatalf("SymlinkTarget fast = %q/%v", got, err)
	}
}

func TestFileSourceLossyAndImageMapping(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 8)
	if n, err := file.ReadAtLossy(0, buf); err != nil || n != 8 || string(buf) != "hello wo" {
		t.Fatalf("lossy read = %d/%q/%v", n, buf, err)
	}
	if _, err := file.ReadAtLossy(11, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy EOF error = %v", err)
	}
	if _, err := file.Extents(5, 100); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extents out of range error = %v", err)
	}
	if _, err := file.ReadAt(0, make([]byte, 4)); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if stats := file.Stats(); stats.Reads == 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

// ---- walk ------------------------------------------------------------------

func TestWalk(t *testing.T) {
	volume := openNilfs(t, buildNilfs2Image(t))
	stats, err := volume.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if stats.Nodes != 8 {
		t.Fatalf("nodes = %d", stats.Nodes)
	}
	if stats.Directories != 4 {
		t.Fatalf("directories = %d", stats.Directories)
	}
	if stats.Files != 2 || stats.Symlinks != 2 {
		t.Fatalf("files/symlinks = %d/%d", stats.Files, stats.Symlinks)
	}
	if stats.DirectoryLoops != 1 {
		t.Fatalf("directory loops = %d", stats.DirectoryLoops)
	}
	if stats.Lookups != 3 {
		t.Fatalf("lookups = %d", stats.Lookups)
	}
	if stats.NodesRead != 8 {
		t.Fatalf("nodes read = %d", stats.NodesRead)
	}
	if stats.Malformed != 0 || stats.Refusals != 0 || stats.Undecodable != 0 {
		t.Fatalf("error counters = %+v", stats)
	}
}

func TestWalkTruncatedDirectoryData(t *testing.T) {
	image := buildNilfs2Image(t)
	// Point the root directory at an out-of-range virtual block.
	putU64(image, 22*testBlockSize+int(RootInode)*InodeSize+DirectPointerOffset, 500)
	volume := openNilfs(t, image)
	stats, err := volume.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if stats.Unreadable != 1 {
		t.Fatalf("unreadable = %d", stats.Unreadable)
	}
	if len(stats.Warnings) == 0 {
		t.Fatal("walk kept no warning")
	}
}

// ---- corruption and bounds -------------------------------------------------

func TestCorruption(t *testing.T) {
	// A summary without a super root is refused by name.
	image := buildNilfs2Image(t)
	putU16(image, 16*testBlockSize+0x06, FlagLogEnd)
	fixSummaryChecksum(image, 16*testBlockSize)
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("no super root error = %v", err)
	}

	// A zero last partial segment cannot locate a super root.
	image = buildNilfs2Image(t)
	putU64(image, primaryOffset+0x44, 0)
	fixSuperblockChecksums(image)
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("zero last_pseg error = %v", err)
	}

	// A super-root flag is unknown.
	image = buildNilfs2Image(t)
	putU16(image, 17*testBlockSize+0x06, 1)
	fixSuperRootChecksum(image, 17*testBlockSize)
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("super root flags error = %v", err)
	}

	// An inode with a zero link count is malformed.
	image = buildNilfs2Image(t)
	putU16(image, 22*testBlockSize+11*InodeSize+0x02, 0)
	volume := openNilfs(t, image)
	if _, err := volume.Stat("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("zero links error = %v", err)
	}

	// Unknown block-map flags are refused.
	image = buildNilfs2Image(t)
	putU64(image, 22*testBlockSize+11*InodeSize+0x40, 0x8)
	volume = openNilfs(t, image)
	if _, err := volume.Stat("/hello.txt"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("unknown bmap flags error = %v", err)
	}

	// A zero direct pointer is a hole, never zero-filled.
	image = buildNilfs2Image(t)
	putU64(image, 22*testBlockSize+11*InodeSize+DirectPointerOffset, 0)
	volume = openNilfs(t, image)
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("hole error = %v", err)
	}

	// More logical blocks than direct pointers needs the B-tree map.
	image = buildNilfs2Image(t)
	putU64(image, 22*testBlockSize+11*InodeSize+0x0c, 8*testBlockSize)
	for index := 1; index < DirectPointers; index++ {
		putU64(image, 22*testBlockSize+11*InodeSize+DirectPointerOffset+index*8, 101)
	}
	volume = openNilfs(t, image)
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("direct pointer overflow error = %v", err)
	}

	// A directory record that crosses a block boundary is refused.
	image = buildNilfs2Image(t)
	putU16(image, 24*testBlockSize+16+8, 0)
	volume = openNilfs(t, image)
	if _, err := volume.ListDir("/"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("zero rec_len error = %v", err)
	}

	// An inode number outside the first palloc group is refused by name.
	image = buildNilfs2Image(t)
	putU64(image, 24*testBlockSize+32, 32768)
	volume = openNilfs(t, image)
	if _, err := volume.ListDir("/"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("palloc group error = %v", err)
	}
}

func fixSummaryChecksum(image []byte, at int) {
	covered := append([]byte(nil), image[at:at+64]...)
	clear(covered[0x38:0x3c])
	putU32(image, at+0x38, foundation.CRC32Seeded(crcSeed, covered))
}

func fixSuperRootChecksum(image []byte, at int) {
	covered := append([]byte(nil), image[at:at+SuperRootBytes]...)
	clear(covered[0:4])
	putU32(image, at, foundation.CRC32Seeded(crcSeed, covered))
}

func TestSuperblockTruncation(t *testing.T) {
	image := buildNilfs2Image(t)
	// Cutting the backup copy is harmless: the primary is intact and the
	// declared device size is larger than the source.
	truncated := image[:testBlockSize*testBlocks-1]
	volume, err := Open(source.NewMemorySource(1, truncated))
	if err != nil {
		t.Fatalf("Open truncated tail: %v", err)
	}
	info := volume.Info()
	if info.TotalBlocks != testBlocks-1 {
		t.Fatalf("total blocks = %d", info.TotalBlocks)
	}
	if info.VolumeBytes >= info.DeviceBytes {
		t.Fatalf("volume bytes not shortened: %d/%d", info.VolumeBytes, info.DeviceBytes)
	}

	// Cutting to before the inode file's entry block makes Open fail.
	short := image[:20*testBlockSize]
	if _, err := Open(source.NewMemorySource(1, short)); !errors.Is(err, source.ErrCorrupt) && !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("short image error = %v", err)
	}
}

func TestPallocLayout(t *testing.T) {
	if got := EntriesPerGroup(4096); got != 32768 {
		t.Fatalf("entries per group = %d", got)
	}
	if got := EntriesPerBlock(4096, IfileEntrySize); got != 32 {
		t.Fatalf("ifile entries per block = %d", got)
	}
	if got := EntriesPerBlock(4096, DatEntrySize); got != 128 {
		t.Fatalf("dat entries per block = %d", got)
	}
	if got := BlocksPerGroup(4096, IfileEntrySize); got != 1025 {
		t.Fatalf("ifile blocks per group = %d", got)
	}
	cases := []struct {
		number    uint64
		entrySize int
		block     uint64
		offset    int
	}{
		{0, IfileEntrySize, 2, 0},
		{31, IfileEntrySize, 2, 31 * 128},
		{32, IfileEntrySize, 3, 0},
		{127, DatEntrySize, 2, 127 * 32},
		{128, DatEntrySize, 3, 0},
	}
	for _, c := range cases {
		block, offset, err := EntryLocation(4096, c.entrySize, c.number)
		if err != nil || block != c.block || offset != c.offset {
			t.Fatalf("entry %d/%d = %d/%d/%v, want %d/%d", c.number, c.entrySize, block, offset, err, c.block, c.offset)
		}
	}
	if _, _, err := EntryLocation(4096, DatEntrySize, 32768); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("group bound error = %v", err)
	}
}

func TestDirectoryParserBounds(t *testing.T) {
	bytes := nilfsDirBlock(128, []testDirent{{1, ".", 2}, {2, "..", 2}})
	entries, err := ParseDirectory(bytes, 128, 128, "a block")
	if err != nil || len(entries) != 2 {
		t.Fatalf("parse = %d/%v", len(entries), err)
	}
	// A record crossing the block end.
	bytes = nilfsDirBlock(128, []testDirent{{1, "x", 1}})
	putU16(bytes, 8, 200)
	if _, err := ParseDirectory(bytes, 128, 128, "a block"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("crossing error = %v", err)
	}
	// A free slot is skipped.
	bytes = make([]byte, 128)
	putU16(bytes, 8, 128)
	entries, err = ParseDirectory(bytes, 128, 128, "a block")
	if err != nil || len(entries) != 0 {
		t.Fatalf("free slot = %d/%v", len(entries), err)
	}
}

var _ = binary.LittleEndian
