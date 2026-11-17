package ocfs2

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testBlockSize  = 512
	defaultCluster = 8
	fixtureGen     = 7
	fixtureUUID    = "ocfs2fixtureuuid"
)

// Data and inode block numbers in the fixture. Data blocks are cluster-aligned
// (multiples of eight) so the extent validator accepts them.
const (
	rootDataBlock   = 16
	helloDataBlock  = 24
	subDataBlock    = 32
	slowDataBlock   = 40
	innerDataBlock  = 48
	emptyDataBlock  = 56
	systemDataBlock = 64
	extentLeafBlock = 72

	rootInodeBlock   = 3
	systemInodeBlock = 4
	helloInodeBlock  = 5
	subInodeBlock    = 6
	fastInodeBlock   = 7
	slowInodeBlock   = 8
	inlineInodeBlock = 9
	innerInodeBlock  = 10
	emptyInodeBlock  = 11
)

func putU16(dst []byte, at int, value uint16) { binary.LittleEndian.PutUint16(dst[at:], value) }
func putU32(dst []byte, at int, value uint32) { binary.LittleEndian.PutUint32(dst[at:], value) }
func putU64(dst []byte, at int, value uint64) { binary.LittleEndian.PutUint64(dst[at:], value) }

type testExtent struct {
	cpos     uint32
	clusters uint32
	physical uint64
	flags    uint8
}

type testDirent struct {
	inode    uint64
	name     string
	fileType uint8
}

// inodeBytes builds one dinode block.
func inodeBytes(blockSize int, block uint64, mode uint16, flags uint32, dyn uint16,
	uid, gid uint32, links uint32, size uint64, clusters uint32, extentDepth uint16,
	records []testExtent, inlineData []byte, fastTarget []byte) []byte {
	out := make([]byte, blockSize)
	copy(out, InodeSignature)
	putU16(out, 0x28, mode)
	putU32(out, 0x2c, flags)
	putU32(out, 0x50, uint32(block))
	putU32(out, 0x60, fixtureGen)
	putU64(out, 0x20, size)
	putU32(out, 0x14, clusters)
	putU32(out, 0x18, uid)
	putU32(out, 0x1c, gid)
	putU16(out, 0x2a, uint16(links))
	putU16(out, 0x10, uint16(links>>16))
	putU16(out, 0x74, dyn)
	putU64(out, 0x30, 1_700_000_300) // i_atime sec
	putU64(out, 0x38, 1_700_000_200) // i_ctime sec
	putU64(out, 0x40, 1_700_000_100) // i_mtime sec

	if inlineData != nil {
		putU16(out, InlineHeaderOffset, uint16(len(inlineData)))
		copy(out[InlineDataOffset:], inlineData)
		return out
	}
	if fastTarget != nil {
		copy(out[FastSymlinkOffset:], fastTarget)
		return out
	}
	listAt := InodeListOffset
	capacity := uint16((blockSize - (listAt + 16)) / 16)
	putU16(out, listAt+0x00, extentDepth)
	putU16(out, listAt+0x02, capacity)
	putU16(out, listAt+0x04, uint16(len(records)))
	for index, record := range records {
		at := listAt + 16 + index*16
		putU32(out, at+0, record.cpos)
		if extentDepth == 0 {
			putU32(out, at+4, (record.clusters&0xffff)|uint32(record.flags)<<24)
		} else {
			putU32(out, at+4, record.clusters)
		}
		putU64(out, at+8, record.physical)
	}
	return out
}

// dirBlock writes a directory block whose records tile the usable area and,
// under meta-ECC, appends a validated DIRTRL1 trailer.
func dirBlock(blockSize int, entries []testDirent, metaECC bool, physical, parentInode uint64) []byte {
	out := make([]byte, blockSize)
	usable := blockSize
	if metaECC {
		usable -= DirTrailerSize
	}
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
		recLen := (DirMemberLen + len(entry.name) + 3) &^ 3
		write(entry.inode, entry.name, entry.fileType, recLen)
	}
	remaining := usable - offset
	if remaining < DirMinRecLen {
		panic("fixture directory entries leave no room for a free record")
	}
	write(0, "", 0, remaining)
	if metaECC {
		at := blockSize - DirTrailerSize
		copy(out[at+0x10:at+0x10+len(DirTrailerSignature)], DirTrailerSignature)
		putU64(out, at+0x28, physical)
		putU64(out, at+0x30, parentInode)
	}
	return out
}

// dirEntriesExact writes entries with no trailing free record; the caller must
// size the buffer to the sum of the record lengths.
func dirEntriesExact(entries []testDirent) []byte {
	var out []byte
	for _, entry := range entries {
		recLen := (DirMemberLen + len(entry.name) + 3) &^ 3
		record := make([]byte, recLen)
		putU64(record, 0, entry.inode)
		putU16(record, 8, uint16(recLen))
		record[10] = byte(len(entry.name))
		record[11] = entry.fileType
		copy(record[12:], entry.name)
		out = append(out, record...)
	}
	return out
}

func superblockBlock(blockSize int, metaECC bool) []byte {
	out := make([]byte, blockSize)
	clusters := uint32(16)
	clusterSize := uint32(blockSize * defaultCluster)
	copy(out, Signature)
	putU32(out, 0x14, clusters)
	putU32(out, 0x2c, ValidFl|SuperBlockFl)
	putU32(out, 0x50, SuperBlockBlkno)
	putU32(out, 0x60, fixtureGen)
	at := Id2Offset
	putU16(out, at+0x00, 2) // major
	putU16(out, at+0x02, 0) // minor
	putU16(out, at+0x08, 0) // state
	if metaECC {
		putU32(out, at+0x20, FeatureIncompatMetaECC)
	}
	putU64(out, at+0x28, rootInodeBlock)
	putU64(out, at+0x30, systemInodeBlock)
	putU32(out, at+0x38, uint32(blockSizeTrailingZeros(blockSize)))
	putU32(out, at+0x3c, uint32(blockSizeTrailingZeros(int(clusterSize))))
	putU16(out, at+0x40, 1) // max slots
	putU64(out, at+0x48, 0) // first cluster group
	copy(out[at+0x50:at+0x50+64], "ocfs2-fixture")
	copy(out[at+0x90:at+0xa0], []byte(fixtureUUID))
	return out
}

func blockSizeTrailingZeros(value int) int {
	zeros := 0
	for value > 1 {
		value >>= 1
		zeros++
	}
	return zeros
}

// buildImage synthesises a complete, self-consistent OCFS2 volume.
func buildImage(t *testing.T, blockSize int, metaECC bool) []byte {
	t.Helper()
	totalBytes := blockSize * defaultCluster * 16
	image := make([]byte, totalBytes)
	copy(image[SuperBlockBlkno*blockSize:], superblockBlock(blockSize, metaECC))

	linkTarget := "hello.txt"
	writeInode := func(block int, inode []byte) {
		copy(image[block*blockSize:], inode)
	}
	fileInode := func(block int, mode uint16, size uint64, physical int) []byte {
		return inodeBytes(blockSize, uint64(block), mode, ValidFl, 0, 1000, 1000, 1,
			size, 1, 0, []testExtent{{cpos: 0, clusters: 1, physical: uint64(physical)}}, nil, nil)
	}
	dirInode := func(block int, physical int) []byte {
		inode := inodeBytes(blockSize, uint64(block), 0x41ed, ValidFl, 0, 0, 0, 2,
			uint64(blockSize), 1, 0, []testExtent{{cpos: 0, clusters: 1, physical: uint64(physical)}}, nil, nil)
		// Directory inodes in this fixture carry no stored times.
		putU64(inode, 0x30, 0)
		putU64(inode, 0x38, 0)
		putU64(inode, 0x40, 0)
		return inode
	}

	writeInode(rootInodeBlock, dirInode(rootInodeBlock, rootDataBlock))
	writeInode(systemInodeBlock, dirInode(systemInodeBlock, systemDataBlock))
	writeInode(helloInodeBlock, fileInode(helloInodeBlock, 0x81a4, 11, helloDataBlock))
	writeInode(subInodeBlock, dirInode(subInodeBlock, subDataBlock))
	writeInode(fastInodeBlock, inodeBytes(blockSize, fastInodeBlock, 0xa1ff, ValidFl, 0, 0, 0, 1,
		uint64(len(linkTarget)), 0, 0, nil, nil, []byte(linkTarget)))
	writeInode(slowInodeBlock, inodeBytes(blockSize, slowInodeBlock, 0xa1ff, ValidFl, 0, 0, 0, 1,
		uint64(len(linkTarget)), 1, 0, []testExtent{{cpos: 0, clusters: 1, physical: slowDataBlock}}, nil, nil))
	writeInode(inlineInodeBlock, inodeBytes(blockSize, inlineInodeBlock, 0x81a4, ValidFl, InlineDataFl,
		1000, 1000, 1, 6, 0, 0, nil, []byte("inline"), nil))
	writeInode(innerInodeBlock, fileInode(innerInodeBlock, 0x81a4, 5, innerDataBlock))
	writeInode(emptyInodeBlock, dirInode(emptyInodeBlock, emptyDataBlock))

	rootEntries := []testDirent{
		{rootInodeBlock, ".", 2},
		{rootInodeBlock, "..", 2},
		{helloInodeBlock, "hello.txt", 1},
		{subInodeBlock, "sub", 2},
		{fastInodeBlock, "fast", 7},
		{slowInodeBlock, "slow", 7},
		{inlineInodeBlock, "inline.txt", 1},
		{emptyInodeBlock, "empty", 2},
		{rootInodeBlock, "loop", 2},
	}
	copy(image[rootDataBlock*blockSize:], dirBlock(blockSize, rootEntries, metaECC, rootDataBlock, rootInodeBlock))
	copy(image[helloDataBlock*blockSize:], "hello world")
	subEntries := []testDirent{
		{subInodeBlock, ".", 2},
		{rootInodeBlock, "..", 2},
		{innerInodeBlock, "inner.txt", 1},
	}
	copy(image[subDataBlock*blockSize:], dirBlock(blockSize, subEntries, metaECC, subDataBlock, subInodeBlock))
	copy(image[slowDataBlock*blockSize:], linkTarget)
	copy(image[innerDataBlock*blockSize:], "inner")
	emptyEntries := []testDirent{
		{emptyInodeBlock, ".", 2},
		{rootInodeBlock, "..", 2},
	}
	copy(image[emptyDataBlock*blockSize:], dirBlock(blockSize, emptyEntries, metaECC, emptyDataBlock, emptyInodeBlock))
	systemEntries := []testDirent{
		{systemInodeBlock, ".", 2},
		{rootInodeBlock, "..", 2},
	}
	copy(image[systemDataBlock*blockSize:], dirBlock(blockSize, systemEntries, metaECC, systemDataBlock, systemInodeBlock))
	return image
}

func openOCFS2(t *testing.T, image []byte) *Volume {
	t.Helper()
	volume, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return volume
}

// ---- detection and superblock ----------------------------------------------

func TestDetectAllBlockSizes(t *testing.T) {
	for _, blockSize := range BlockSizes {
		image := buildImage(t, int(blockSize), false)
		found, err := Detect(source.NewMemorySource(1, image))
		if err != nil || !found {
			t.Fatalf("block size %d: found=%v err=%v", blockSize, found, err)
		}
		volume := openOCFS2(t, image)
		info := volume.Info()
		if info.BlockSize != blockSize || info.ClusterSize != blockSize*defaultCluster {
			t.Fatalf("block size %d geometry = %+v", blockSize, info)
		}
		if info.TotalClusters != 16 || info.TotalBlocks != 128 {
			t.Fatalf("block size %d counts = %d/%d", blockSize, info.TotalClusters, info.TotalBlocks)
		}
		if info.RootBlkno != rootInodeBlock || info.SystemDirBlkno != systemInodeBlock {
			t.Fatalf("block size %d root/system = %d/%d", blockSize, info.RootBlkno, info.SystemDirBlkno)
		}
		if info.VolumeLabel != "ocfs2-fixture" || info.UUID != "6f636673326669787475726575756964" {
			t.Fatalf("block size %d label/uuid = %q/%q", blockSize, info.VolumeLabel, info.UUID)
		}
		if info.FsGeneration != fixtureGen || info.MaxSlots != 1 {
			t.Fatalf("block size %d generation/slots = %d/%d", blockSize, info.FsGeneration, info.MaxSlots)
		}
	}
}

func TestDetectNoSignature(t *testing.T) {
	if found, err := Detect(source.NewMemorySource(1, make([]byte, 8192))); err != nil || found {
		t.Fatalf("zero image: found=%v err=%v", found, err)
	}
	if found, err := Detect(source.NewMemorySource(1, make([]byte, 1024))); err != nil || found {
		t.Fatalf("short image: found=%v err=%v", found, err)
	}
}

func TestDetectReversedSignature(t *testing.T) {
	image := buildImage(t, testBlockSize, false)
	at := SuperBlockBlkno * testBlockSize
	copy(image[at:], ReversedSignature)
	if _, err := Detect(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("reversed signature error = %v", err)
	}
}

func TestDetectByteSwappedFields(t *testing.T) {
	image := buildImage(t, testBlockSize, false)
	at := SuperBlockBlkno*testBlockSize + Id2Offset
	binary.BigEndian.PutUint32(image[at+0x38:], 9)
	binary.BigEndian.PutUint32(image[at+0x3c:], 12)
	if _, err := Detect(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("byte-swapped error = %v", err)
	}
}

func TestUnsupportedSuperblockFields(t *testing.T) {
	image := buildImage(t, testBlockSize, false)
	at := SuperBlockBlkno*testBlockSize + Id2Offset
	putU32(image, at+0x3c, 11) // cluster bits below 12
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("cluster bits error = %v", err)
	}

	image = buildImage(t, testBlockSize, false)
	at = SuperBlockBlkno*testBlockSize + Id2Offset
	putU64(image, at+0x28, 999) // root out of range
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("root range error = %v", err)
	}

	image = buildImage(t, testBlockSize, false)
	at = SuperBlockBlkno*testBlockSize + Id2Offset
	putU32(image, at+0x20, 0x1000_0000) // unknown incompat feature
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("incompat feature error = %v", err)
	}

	image = buildImage(t, testBlockSize, false)
	at = SuperBlockBlkno*testBlockSize + Id2Offset
	putU16(image, at+0x40, 0) // zero slots
	if _, err := Open(source.NewMemorySource(1, image)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("slot count error = %v", err)
	}
}

func TestInfo(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
	info := volume.Info()
	if info.BlockShift != 9 || info.ClusterShift != 12 {
		t.Fatalf("shifts = %d/%d", info.BlockShift, info.ClusterShift)
	}
	if info.Major != 2 || info.Minor != 0 || info.State != 0 {
		t.Fatalf("version/state = %d/%d/%d", info.Major, info.Minor, info.State)
	}
	if info.VolumeBytes != 16*4096 {
		t.Fatalf("volume bytes = %d", info.VolumeBytes)
	}
	if info.FeatureIncompat != 0 || info.MetaECC || info.InlineData || info.IndexedDirs {
		t.Fatalf("features = %+v", info)
	}
}

// ---- directories -----------------------------------------------------------

func TestListDirRoot(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	want := []string{"hello.txt", "sub", "fast", "slow", "inline.txt", "empty", "loop"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v", names)
	}
	for _, entry := range entries {
		switch entry.Name {
		case "hello.txt":
			if entry.Inode != helloInodeBlock || entry.ParentInode != rootInodeBlock {
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
			if !entry.AllocatedKnown || entry.Allocated != testBlockSize*defaultCluster {
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
			if !entry.IsDir || entry.Inode != subInodeBlock || entry.Path != "/sub" {
				t.Fatalf("sub = %+v", entry)
			}
			if entry.AllocatedKnown {
				t.Fatalf("directory reported allocation = %+v", entry)
			}
		case "fast":
			if !entry.IsSymlink || entry.SymlinkTarget != "hello.txt" {
				t.Fatalf("fast = %+v", entry)
			}
			if !entry.AllocatedKnown || entry.Allocated != 0 {
				t.Fatalf("fast allocation = %+v", entry)
			}
		case "slow":
			if !entry.IsSymlink || entry.SymlinkTarget != "hello.txt" {
				t.Fatalf("slow = %+v", entry)
			}
			if !entry.AllocatedKnown || entry.Allocated != testBlockSize*defaultCluster {
				t.Fatalf("slow allocation = %+v", entry)
			}
		case "inline.txt":
			if !entry.IsFile || entry.Size != 6 {
				t.Fatalf("inline = %+v", entry)
			}
			if !entry.AllocatedKnown || entry.Allocated != 0 {
				t.Fatalf("inline allocation = %+v", entry)
			}
		case "empty":
			if !entry.IsDir || entry.Inode != emptyInodeBlock {
				t.Fatalf("empty = %+v", entry)
			}
		case "loop":
			if !entry.IsDir || entry.Inode != rootInodeBlock {
				t.Fatalf("loop = %+v", entry)
			}
		}
	}
}

func TestStatNested(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
	root, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	if root.Name != "/" || root.Path != "/" || !root.IsDir || root.Inode != rootInodeBlock {
		t.Fatalf("root = %+v", root)
	}
	inner, err := volume.Stat("sub/inner.txt")
	if err != nil {
		t.Fatalf("Stat inner: %v", err)
	}
	if inner.Name != "inner.txt" || inner.Path != "/sub/inner.txt" || inner.Inode != innerInodeBlock {
		t.Fatalf("inner = %+v", inner)
	}
	if inner.Size != 5 || inner.Mode != 0x81a4 {
		t.Fatalf("inner metadata = %+v", inner)
	}
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	// A zero stored time is unset, not 1970.
	sub, err := volume.Stat("/sub")
	if err != nil {
		t.Fatalf("Stat sub: %v", err)
	}
	if sub.HasAtime || sub.HasMtime || sub.HasCtime {
		t.Fatalf("zero times reported set: %+v", sub)
	}
}

func TestEmptyDir(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
	entries, err := volume.ListDir("/empty")
	if err != nil {
		t.Fatalf("ListDir empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty dir has %d entries", len(entries))
	}
}

func TestPathErrors(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
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
}

// ---- file data -------------------------------------------------------------

func TestReadFileAndEOF(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if file.Len() != 11 || file.IsEmpty() {
		t.Fatalf("len = %d empty=%v", file.Len(), file.IsEmpty())
	}
	buf := make([]byte, 11)
	if _, err := file.ReadAt(0, buf); err != nil || string(buf) != "hello world" {
		t.Fatalf("content = %q err=%v", buf, err)
	}
	if _, err := file.ReadAt(11, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("EOF error = %v", err)
	}
	ranges, err := file.Extents(0, 11)
	if err != nil || len(ranges) != 1 {
		t.Fatalf("extents = %+v/%v", ranges, err)
	}
	if ranges[0].ParentOffset != helloDataBlock*testBlockSize {
		t.Fatalf("extent physical = %d", ranges[0].ParentOffset)
	}
	imageRanges, err := file.MapToImage(0, 11)
	if err != nil || len(imageRanges) != 1 || imageRanges[0].ImageOffset != helloDataBlock*testBlockSize {
		t.Fatalf("image ranges = %+v/%v", imageRanges, err)
	}
	if _, err := file.ReadAtLossy(11, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy EOF error = %v", err)
	}
}

func TestOpenInlineFile(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
	file, err := volume.OpenFile("/inline.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 6)
	if _, err := file.ReadAt(0, buf); err != nil || string(buf) != "inline" {
		t.Fatalf("inline content = %q/%v", buf, err)
	}
	ranges, err := file.Extents(0, 6)
	if err != nil || len(ranges) != 1 || ranges[0].Kind != source.RangeData {
		t.Fatalf("inline extents = %+v/%v", ranges, err)
	}
	expected := uint64(inlineInodeBlock*testBlockSize + InlineDataOffset)
	if ranges[0].ParentOffset != expected {
		t.Fatalf("inline offset = %d, want %d", ranges[0].ParentOffset, expected)
	}
}

func TestSymlinks(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
	fast, err := volume.OpenFile("/fast")
	if err != nil {
		t.Fatalf("open fast: %v", err)
	}
	buf := make([]byte, fast.Len())
	if _, err := fast.ReadAt(0, buf); err != nil || string(buf) != "hello.txt" {
		t.Fatalf("fast target = %q/%v", buf, err)
	}
	slow, err := volume.OpenFile("/slow")
	if err != nil {
		t.Fatalf("open slow: %v", err)
	}
	buf = make([]byte, slow.Len())
	if _, err := slow.ReadAt(0, buf); err != nil || string(buf) != "hello.txt" {
		t.Fatalf("slow target = %q/%v", buf, err)
	}
	if target, err := volume.SymlinkTarget("/fast"); err != nil || target != "hello.txt" {
		t.Fatalf("SymlinkTarget fast = %q/%v", target, err)
	}
	if target, err := volume.SymlinkTarget("/slow"); err != nil || target != "hello.txt" {
		t.Fatalf("SymlinkTarget slow = %q/%v", target, err)
	}
}

// ---- walk ------------------------------------------------------------------

func TestWalk(t *testing.T) {
	volume := openOCFS2(t, buildImage(t, testBlockSize, false))
	stats, err := volume.Walk()
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if stats.Nodes != 9 {
		t.Fatalf("nodes = %d", stats.Nodes)
	}
	if stats.Directories != 4 || stats.Files != 3 || stats.Symlinks != 2 {
		t.Fatalf("kinds = %d/%d/%d", stats.Directories, stats.Files, stats.Symlinks)
	}
	if stats.DirectoryLoops != 1 {
		t.Fatalf("loops = %d", stats.DirectoryLoops)
	}
	if stats.Lookups != 3 {
		t.Fatalf("lookups = %d", stats.Lookups)
	}
	if stats.NodesRead != 9 {
		t.Fatalf("nodes read = %d", stats.NodesRead)
	}
	if stats.Malformed != 0 || stats.Refusals != 0 || stats.Undecodable != 0 {
		t.Fatalf("counters = %+v", stats)
	}
}

// ---- metadata ECC, indexed and inline directories ---------------------------

func TestMetaECC(t *testing.T) {
	image := buildImage(t, testBlockSize, true)
	volume := openOCFS2(t, image)
	if !volume.Info().MetaECC {
		t.Fatal("MetaECC feature not reported")
	}
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir meta-ECC: %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("entries = %d", len(entries))
	}
	if _, err := volume.Walk(); err != nil {
		t.Fatalf("Walk meta-ECC: %v", err)
	}

	// A missing trailer is malformed.
	image = buildImage(t, testBlockSize, true)
	at := rootDataBlock*testBlockSize + testBlockSize - DirTrailerSize + 0x10
	clear(image[at : at+len(DirTrailerSignature)])
	volume = openOCFS2(t, image)
	if _, err := volume.ListDir("/"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("missing trailer error = %v", err)
	}

	// A trailer naming the wrong physical block is malformed.
	image = buildImage(t, testBlockSize, true)
	at = rootDataBlock*testBlockSize + testBlockSize - DirTrailerSize + 0x28
	putU64(image, at, 17)
	volume = openOCFS2(t, image)
	if _, err := volume.ListDir("/"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("wrong trailer block error = %v", err)
	}
}

func TestIndexedDirectoryRefused(t *testing.T) {
	image := buildImage(t, testBlockSize, false)
	putU16(image, rootInodeBlock*testBlockSize+0x74, IndexedDirFl)
	volume := openOCFS2(t, image)
	if _, err := volume.ListDir("/"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("indexed dir error = %v", err)
	}
}

func TestInlineDirectory(t *testing.T) {
	image := buildImage(t, testBlockSize, false)
	inline := dirEntriesExact([]testDirent{
		{rootInodeBlock, ".", 2},
		{rootInodeBlock, "..", 2},
		{helloInodeBlock, "hello.txt", 1},
	})
	root := inodeBytes(testBlockSize, rootInodeBlock, 0x41ed, ValidFl, InlineDataFl,
		0, 0, 2, uint64(len(inline)), 0, 0, nil, inline, nil)
	copy(image[rootInodeBlock*testBlockSize:], root)
	volume := openOCFS2(t, image)
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir inline: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "hello.txt" {
		t.Fatalf("inline entries = %+v", entries)
	}
	inner, err := volume.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat through inline dir: %v", err)
	}
	if inner.Inode != helloInodeBlock {
		t.Fatalf("hello inode = %d", inner.Inode)
	}
}

// ---- extent trees ----------------------------------------------------------

func TestExtentTreeDepthOne(t *testing.T) {
	image := buildImage(t, testBlockSize, false)
	hello := inodeBytes(testBlockSize, helloInodeBlock, 0x81a4, ValidFl, 0, 1000, 1000, 1,
		11, 1, 1, []testExtent{{cpos: 0, clusters: 1, physical: extentLeafBlock}}, nil, nil)
	copy(image[helloInodeBlock*testBlockSize:], hello)

	leaf := make([]byte, testBlockSize)
	copy(leaf, ExtentBlockSignature)
	putU32(leaf, 0x14, fixtureGen)
	putU64(leaf, 0x18, extentLeafBlock)
	putU16(leaf, ExtentBlockListOffset+0x00, 0)
	putU16(leaf, ExtentBlockListOffset+0x02, uint16((testBlockSize-(ExtentBlockListOffset+16))/16))
	putU16(leaf, ExtentBlockListOffset+0x04, 1)
	recordAt := ExtentBlockRecordsOffset
	putU32(leaf, recordAt, 0)
	putU32(leaf, recordAt+4, 1)
	putU64(leaf, recordAt+8, helloDataBlock)
	copy(image[extentLeafBlock*testBlockSize:], leaf)

	volume := openOCFS2(t, image)
	file, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 11)
	if _, err := file.ReadAt(0, buf); err != nil || string(buf) != "hello world" {
		t.Fatalf("content = %q/%v", buf, err)
	}
}

// ---- corruption and bounds -------------------------------------------------

func TestCorruption(t *testing.T) {
	// An orphaned inode is refused.
	image := buildImage(t, testBlockSize, false)
	putU32(image, helloInodeBlock*testBlockSize+0x2c, ValidFl|OrphanedFl)
	volume := openOCFS2(t, image)
	if _, err := volume.Stat("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("orphan error = %v", err)
	}

	// An inode from another filesystem generation is refused.
	image = buildImage(t, testBlockSize, false)
	putU32(image, helloInodeBlock*testBlockSize+0x60, fixtureGen+1)
	volume = openOCFS2(t, image)
	if _, err := volume.Stat("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("generation error = %v", err)
	}

	// An unwritten extent is refused rather than zero-filled.
	image = buildImage(t, testBlockSize, false)
	putU32(image, helloInodeBlock*testBlockSize+InodeListOffset+16+4, 1|1<<24)
	volume = openOCFS2(t, image)
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("unwritten error = %v", err)
	}

	// A gap in the logical clusters is refused.
	image = buildImage(t, testBlockSize, false)
	putU32(image, helloInodeBlock*testBlockSize+InodeListOffset+16, 5)
	volume = openOCFS2(t, image)
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("gap error = %v", err)
	}

	// A leaf extent on a non-cluster-aligned block is refused.
	image = buildImage(t, testBlockSize, false)
	putU64(image, helloInodeBlock*testBlockSize+InodeListOffset+24, 25)
	volume = openOCFS2(t, image)
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("alignment error = %v", err)
	}

	// An extent block without its signature is refused.
	image = buildImage(t, testBlockSize, false)
	hello := inodeBytes(testBlockSize, helloInodeBlock, 0x81a4, ValidFl, 0, 1000, 1000, 1,
		11, 1, 1, []testExtent{{cpos: 0, clusters: 1, physical: extentLeafBlock}}, nil, nil)
	copy(image[helloInodeBlock*testBlockSize:], hello)
	volume = openOCFS2(t, image)
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("extent block signature error = %v", err)
	}
}

func TestEmptyExtentList(t *testing.T) {
	image := buildImage(t, testBlockSize, false)
	putU16(image, helloInodeBlock*testBlockSize+InodeListOffset+0x04, 0) // next_free
	volume := openOCFS2(t, image)
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("empty list error = %v", err)
	}
}

func TestTruncatedVolume(t *testing.T) {
	image := buildImage(t, testBlockSize, false)
	if _, err := Open(source.NewMemorySource(1, image[:SuperBlockBlkno*testBlockSize+8])); err == nil {
		t.Fatal("Open accepted a truncated superblock block")
	}
	// A source shorter than the declared volume is refused by name.
	short := image[:len(image)-testBlockSize]
	if _, err := Open(source.NewMemorySource(1, short)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short volume error = %v", err)
	}
}

func TestSuperblockPrimitives(t *testing.T) {
	if SuperBlockBlkno != 2 {
		t.Fatalf("superblock block = %d", SuperBlockBlkno)
	}
	if string(Signature) != "OCFSV2" || string(InodeSignature) != "INODE01" ||
		string(ExtentBlockSignature) != "EXBLK01" || string(DirTrailerSignature) != "DIRTRL1" {
		t.Fatal("signature constants changed")
	}
	for _, blockSize := range BlockSizes {
		image := buildImage(t, int(blockSize), false)
		_ = image
	}
}
