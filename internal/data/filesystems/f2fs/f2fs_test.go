package f2fs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testBlockSize      = 4096
	testBlocksPerSeg   = 256
	testMainSegments   = 2
	testMainBlkaddr    = 1792
	testSegment0       = 512
	testSITBlkaddr     = 1024
	testNATBlkaddr     = 1280
	testSSABlkaddr     = 1536
	testRootIno        = 3
	testNodeIno        = 4
	testMetaIno        = 5
	testBlockCount     = testSegment0 + 7*testBlocksPerSeg
	natEntriesPerBlock = testBlockSize / NATEntrySize
)

func sampleSuperblock() []byte {
	bytes := make([]byte, SuperSize)
	putU32(bytes, 0, Magic)
	putU16(bytes, 4, 1)
	putU16(bytes, 6, 15)
	putU32(bytes, 8, 9)   // log sectors
	putU32(bytes, 12, 3)  // log sectors per block
	putU32(bytes, 16, 12) // log block size
	putU32(bytes, 20, 8)  // log blocks per segment
	putU32(bytes, 24, 1)  // segments per section
	putU32(bytes, 28, 1)  // sections per zone
	putU32(bytes, 32, 3068)
	putU64(bytes, 36, testBlockCount)
	putU32(bytes, 44, 7) // section count
	putU32(bytes, 48, 7) // segment count
	putU32(bytes, 52, 2) // checkpoint segments
	putU32(bytes, 56, 1) // SIT segments
	putU32(bytes, 60, 1) // NAT segments
	putU32(bytes, 64, 1) // SSA segments
	putU32(bytes, 68, testMainSegments)
	putU32(bytes, 72, testSegment0)
	putU32(bytes, 76, testSegment0)
	putU32(bytes, 80, testSITBlkaddr)
	putU32(bytes, 84, testNATBlkaddr)
	putU32(bytes, 88, testSSABlkaddr)
	putU32(bytes, 92, testMainBlkaddr)
	putU32(bytes, 96, testRootIno)
	putU32(bytes, 100, testNodeIno)
	putU32(bytes, 104, testMetaIno)
	for index := 0; index < 16; index++ {
		bytes[108+index] = 0x33
	}
	writeUTF16(bytes[124:], "f2fs fixture")
	return bytes
}

func writeUTF16(dst []byte, text string) {
	units := utf16.Encode([]rune(text))
	for index, unit := range units {
		if index*2+2 > len(dst) {
			return
		}
		putU16(dst, index*2, unit)
	}
}

func sampleCheckpointBytes(sb *Superblock, version uint64, flags uint32) []byte {
	bytes := make([]byte, sb.BlockSize)
	putU64(bytes, 0, version)
	putU64(bytes, 8, uint64(sb.SegmentCountMain)*uint64(sb.BlocksPerSegment))
	putU64(bytes, 16, 128)
	putU32(bytes, 24, 0)
	putU32(bytes, 28, 0)
	putU32(bytes, 32, 2)
	putU32(bytes, 132, flags)
	putU32(bytes, 136, 2)
	putU32(bytes, 140, 1)
	putU32(bytes, 144, 8)
	putU32(bytes, 148, 6)
	putU32(bytes, 152, 32)
	sitByteCount := uint32(((uint64(sb.SegmentCountSIT)*uint64(sb.BlocksPerSegment))/2 + 7) / 8)
	natByteCount := uint32((sb.NATBlocks()/2 + 7) / 8)
	putU32(bytes, 156, sitByteCount)
	putU32(bytes, 160, natByteCount)
	putU32(bytes, 164, uint32(BitmapOffset+64))
	putU64(bytes, 168, 1234)
	// The node-address bitmap comes first in the NatThenSit order and selects
	// the second table half for the blocks this fixture touches.
	for index := 0; index < int(natByteCount); index++ {
		bytes[BitmapOffset+index] = 0xFF
	}
	at := int(BitmapOffset + 64)
	crc := foundation.CRC32Seeded(Magic, bytes[:at])
	putU32(bytes, at, crc)
	return bytes
}

type testImage struct {
	t         *testing.T
	data      []byte
	sb        *Superblock
	cp        *Checkpoint
	nextBlock uint32
	used      map[uint32]bool
	rootBlock uint32
	nodeBlock uint32
}

func newTestImage(t *testing.T) *testImage {
	t.Helper()
	sbBytes := sampleSuperblock()
	sb, err := ParseSuperblock(sbBytes, SuperOffset)
	if err != nil {
		t.Fatalf("parse superblock: %v", err)
	}
	cpBytes := sampleCheckpointBytes(sb, 7, CPUmountFlag)
	cp, err := ParseCheckpoint(cpBytes, sb.CPBlkaddr, 0, sb)
	if err != nil {
		t.Fatalf("parse checkpoint: %v", err)
	}
	image := make([]byte, int(sb.BlockCount)*int(sb.BlockSize))
	copy(image[SuperOffset:], sbBytes)
	copy(image[sb.ByteOffset(sb.CPBlkaddr):], cpBytes)
	ti := &testImage{
		t:         t,
		data:      image,
		sb:        sb,
		cp:        cp,
		nextBlock: sb.MainBlkaddr,
		used:      make(map[uint32]bool),
	}
	ti.rootBlock = ti.allocBlock()
	ti.nodeBlock = ti.allocBlock()
	ti.setNAT(testRootIno, testRootIno, ti.rootBlock)
	ti.setNAT(testNodeIno, testNodeIno, ti.nodeBlock)
	return ti
}

func (ti *testImage) allocBlock() uint32 {
	block := ti.nextBlock
	if uint64(block) >= ti.sb.BlockCount {
		ti.t.Fatalf("test image main area exhausted")
	}
	ti.nextBlock++
	ti.used[block] = true
	return block
}

func (ti *testImage) putBlock(block uint32, contents []byte) {
	at := int(ti.sb.ByteOffset(block))
	copy(ti.data[at:at+int(ti.sb.BlockSize)], contents)
}

func (ti *testImage) putData(contents []byte) uint32 {
	block := ti.allocBlock()
	ti.putBlock(block, contents)
	return block
}

func (ti *testImage) putFooter(bytes []byte, nid, ino uint32) {
	at := len(bytes) - NodeFooterSize
	putU32(bytes, at, nid)
	putU32(bytes, at+4, ino)
	putU64(bytes, at+12, 1)
}

func (ti *testImage) putNode(nid, ino uint32, build func([]byte)) uint32 {
	block := ti.allocBlock()
	bytes := make([]byte, ti.sb.BlockSize)
	build(bytes)
	ti.putFooter(bytes, nid, ino)
	ti.putBlock(block, bytes)
	ti.setNAT(nid, ino, block)
	return block
}

func (ti *testImage) natEntryAt(nid uint32) int {
	offset := nid / natEntriesPerBlock
	half := uint32(ti.sb.NATBlocks() / 2)
	block := ti.sb.NATBlkaddr + offset
	if bitSet(ti.cp.NATBitmap(NatThenSit), int(offset)) {
		block += half
	}
	return int(ti.sb.ByteOffset(block)) + int(nid%natEntriesPerBlock)*NATEntrySize
}

func (ti *testImage) natBlock(nid uint32) uint32 {
	half := uint32(ti.sb.NATBlocks() / 2)
	offset := nid / natEntriesPerBlock
	block := ti.sb.NATBlkaddr + half + offset
	at := int(ti.sb.ByteOffset(block)) + int(nid%natEntriesPerBlock)*NATEntrySize
	return binary.LittleEndian.Uint32(ti.data[at+5 : at+9])
}

func (ti *testImage) setNAT(nid, ino, block uint32) {
	offset := nid / natEntriesPerBlock
	half := ti.sb.NATBlocks() / 2
	physical := uint64(ti.sb.NATBlkaddr) + half + uint64(offset)
	if bitSet(ti.cp.NATBitmap(NatThenSit), int(offset)) {
		// already the second half
	} else {
		physical = uint64(ti.sb.NATBlkaddr) + uint64(offset)
	}
	at := int(ti.sb.ByteOffset(uint32(physical))) + int(nid%natEntriesPerBlock)*NATEntrySize
	ti.data[at] = 1
	putU32(ti.data[at+1:], 0, ino)
	putU32(ti.data[at+5:], 0, block)
}

func (ti *testImage) setSIT(segment int, blocks []uint32) {
	var validMap [64]byte
	for _, block := range blocks {
		start := uint32(testMainBlkaddr) + uint32(segment)*testBlocksPerSeg
		if block < start || block >= start+testBlocksPerSeg {
			ti.t.Fatalf("block %d is not in segment %d", block, segment)
		}
		index := int(block - start)
		validMap[index/8] |= 1 << uint(index%8)
	}
	at := int(ti.sb.ByteOffset(testSITBlkaddr)) + segment*SITEntrySize
	putU16(ti.data, at, uint16(len(blocks)))
	copy(ti.data[at+sitValidMapOffset:at+sitValidMapOffset+sitValidMapSize], validMap[:])
	putU64(ti.data, at+66, 0)
}

func (ti *testImage) finalizeSIT() {
	bySegment := make(map[int][]uint32)
	for block := range ti.used {
		segment := int(block-testMainBlkaddr) / testBlocksPerSeg
		bySegment[segment] = append(bySegment[segment], block)
	}
	for segment := 0; segment < testMainSegments; segment++ {
		ti.setSIT(segment, bySegment[segment])
	}
}

func (ti *testImage) open() *Volume {
	ti.t.Helper()
	ti.finalizeSIT()
	volume, err := Open(source.NewMemorySource(1, ti.data))
	if err != nil {
		ti.t.Fatalf("open volume: %v", err)
	}
	return volume
}

func inodeFields(bytes []byte, mode uint16, inlineFlags uint8, size uint64, pino uint32) {
	putU16(bytes, 0, mode)
	bytes[3] = inlineFlags
	putU32(bytes, 4, 1000)
	putU32(bytes, 8, 1000)
	putU32(bytes, 12, 1)
	putU64(bytes, 16, size)
	putU64(bytes, 24, 8)
	putU64(bytes, 32, 1_700_000_000)
	putU64(bytes, 40, 1_700_000_100)
	putU64(bytes, 48, 1_700_000_200)
	putU32(bytes, 56, 1)
	putU32(bytes, 60, 2)
	putU32(bytes, 64, 3)
	putU32(bytes, 68, 1)
	putU32(bytes, 84, pino)
	bytes[347] = 0
}

func putAddress(bytes []byte, index int, block uint32) {
	putU32(bytes, AddrsOffset+index*4, block)
}

func putNIDs(bytes []byte, nids [NIDsPerInode]uint32) {
	at := len(bytes) - NodeFooterSize - SizeOfINid
	for index, nid := range nids {
		putU32(bytes, at+index*4, nid)
	}
}

func putDirEntry(block []byte, slot int, ino uint32, fileType uint8, name string) {
	block[slot/8] |= 1 << uint(slot%8)
	at := DirEntryOffset + slot*DirEntrySize
	putU32(block, at, uint32(slot*7))
	putU32(block, at+4, ino)
	putU16(block, at+8, uint16(len(name)))
	block[at+10] = fileType
	nameAt := DirFilenameOffset + slot*DirSlotSize
	copy(block[nameAt:], name)
}

func standardImage(t *testing.T) *testImage {
	t.Helper()
	ti := newTestImage(t)
	root := uint32(testRootIno)

	rootDir := make([]byte, testBlockSize)
	putDirEntry(rootDir, 0, root, DTDir, ".")
	putDirEntry(rootDir, 1, root, DTDir, "..")
	putDirEntry(rootDir, 2, 30, DTReg, "hello.txt")
	putDirEntry(rootDir, 4, 31, DTDir, "sub")
	putDirEntry(rootDir, 5, 33, DTReg, "inline.txt")
	putDirEntry(rootDir, 7, 34, DTLnk, "link")
	rootData := ti.putData(rootDir)

	helloData := ti.putData([]byte("hello from f2fs\n"))
	ti.putNode(30, 30, func(bytes []byte) {
		inodeFields(bytes, SIFREG|0644, 0, 16, root)
		putAddress(bytes, 0, helloData)
	})

	subDir := make([]byte, testBlockSize)
	putDirEntry(subDir, 0, 31, DTDir, ".")
	putDirEntry(subDir, 1, root, DTDir, "..")
	putDirEntry(subDir, 2, 32, DTReg, "inner.txt")
	subData := ti.putData(subDir)
	ti.putNode(31, 31, func(bytes []byte) {
		inodeFields(bytes, SIFDIR|0755, 0, testBlockSize, root)
		putAddress(bytes, 0, subData)
	})

	innerData := ti.putData([]byte("inner\n"))
	ti.putNode(32, 32, func(bytes []byte) {
		inodeFields(bytes, SIFREG|0644, 0, 6, 31)
		putAddress(bytes, 0, innerData)
	})

	ti.putNode(33, 33, func(bytes []byte) {
		inodeFields(bytes, SIFREG|0644, InlineData, 11, root)
		copy(bytes[AddrsOffset:], "inline body")
	})

	ti.putNode(34, 34, func(bytes []byte) {
		inodeFields(bytes, SIFLNK|0777, 0, 10, root)
		copy(bytes[AddrsOffset:], "/hello.txt")
	})

	rootInode := make([]byte, testBlockSize)
	inodeFields(rootInode, SIFDIR|0755, 0, testBlockSize, root)
	putAddress(rootInode, 0, rootData)
	ti.putFooter(rootInode, root, root)
	ti.putBlock(ti.rootBlock, rootInode)
	return ti
}

func TestOpenAndInfo(t *testing.T) {
	volume := standardImage(t).open()
	info := volume.Info()
	if info.VersionMajor != 1 || info.VersionMinor != 15 {
		t.Fatalf("version = %d.%d, want 1.15", info.VersionMajor, info.VersionMinor)
	}
	if info.BlockSize != testBlockSize {
		t.Fatalf("block size = %d", info.BlockSize)
	}
	if info.SegmentCount != 7 || info.SegmentCountMain != testMainSegments {
		t.Fatalf("segments = %d main = %d", info.SegmentCount, info.SegmentCountMain)
	}
	if info.RootIno != testRootIno || info.MainBlkaddr != testMainBlkaddr {
		t.Fatalf("root = %d main = %d", info.RootIno, info.MainBlkaddr)
	}
	if info.CheckpointVersion != 7 || !info.Clean {
		t.Fatalf("checkpoint version = %d clean = %v", info.CheckpointVersion, info.Clean)
	}
	if info.VolumeName != "f2fs fixture" {
		t.Fatalf("volume name = %q", info.VolumeName)
	}
	if info.UUID != "33333333-3333-3333-3333-333333333333" {
		t.Fatalf("uuid = %q", info.UUID)
	}
	if len(info.Features) != 0 {
		t.Fatalf("features = %v", info.Features)
	}
}

func TestListDirRoot(t *testing.T) {
	volume := standardImage(t).open()
	entries, err := volume.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	want := []string{"hello.txt", "sub", "inline.txt", "link"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v", names)
	}
	for _, entry := range entries {
		switch entry.Name {
		case "hello.txt":
			if entry.IsDir || entry.Inode != 30 || entry.ParentInode != testRootIno {
				t.Fatalf("hello entry = %+v", entry)
			}
			if entry.Size != 16 || entry.Mode&0xF000 != SIFREG {
				t.Fatalf("hello size/mode = %d/%#x", entry.Size, entry.Mode)
			}
			if entry.Path != "/hello.txt" {
				t.Fatalf("hello path = %q", entry.Path)
			}
			if !entry.Atime.Equal(time.Unix(1_700_000_000, 1).UTC()) {
				t.Fatalf("hello atime = %v", entry.Atime)
			}
		case "sub":
			if !entry.IsDir || entry.Inode != 31 {
				t.Fatalf("sub entry = %+v", entry)
			}
		case "inline.txt":
			if !entry.InlineData || entry.Size != 11 {
				t.Fatalf("inline entry = %+v", entry)
			}
		case "link":
			if !entry.IsSymlink {
				t.Fatalf("link entry = %+v", entry)
			}
		}
	}
}

func TestStat(t *testing.T) {
	volume := standardImage(t).open()
	entry, err := volume.Stat("/")
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	if entry.Name != "/" || !entry.IsDir || entry.Inode != testRootIno {
		t.Fatalf("root stat = %+v", entry)
	}
	entry, err = volume.Stat("sub/inner.txt")
	if err != nil {
		t.Fatalf("Stat inner: %v", err)
	}
	if entry.Name != "inner.txt" || entry.Path != "/sub/inner.txt" || entry.Size != 6 {
		t.Fatalf("inner stat = %+v", entry)
	}
	if entry.ParentInode != 31 || entry.UID != 1000 || entry.GID != 1000 {
		t.Fatalf("inner ownership = %+v", entry)
	}
}

func TestOpenFileInlineAndBlockMapped(t *testing.T) {
	volume := standardImage(t).open()

	inlineSource, err := volume.OpenFile("/inline.txt")
	if err != nil {
		t.Fatalf("OpenFile inline: %v", err)
	}
	inlineBytes := make([]byte, 64)
	n, err := inlineSource.ReadAt(0, inlineBytes)
	if err != nil {
		t.Fatalf("read inline: %v", err)
	}
	if n != 11 || string(inlineBytes[:n]) != "inline body" {
		t.Fatalf("inline = %q (%d)", inlineBytes[:n], n)
	}

	helloSource, err := volume.OpenFile("/hello.txt")
	if err != nil {
		t.Fatalf("OpenFile hello: %v", err)
	}
	if helloSource.Len() != 16 {
		t.Fatalf("hello len = %d", helloSource.Len())
	}
	all := make([]byte, 16)
	if _, err := helloSource.ReadAt(0, all); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if string(all) != "hello from f2fs\n" {
		t.Fatalf("hello = %q", all)
	}
	part := make([]byte, 4)
	if _, err := helloSource.ReadAt(6, part); err != nil {
		t.Fatalf("partial read: %v", err)
	}
	if string(part) != "from" {
		t.Fatalf("partial = %q", part)
	}
	// A read crossing EOF is short, not an error.
	tail := make([]byte, 32)
	got, err := helloSource.ReadAt(10, tail)
	if err != nil {
		t.Fatalf("tail read: %v", err)
	}
	if got != 6 || string(tail[:got]) != " f2fs\n" {
		t.Fatalf("tail = %q (%d)", tail[:got], got)
	}
	// A read at EOF is out of range.
	if _, err := helloSource.ReadAt(16, tail); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("EOF read error = %v", err)
	}
}

func TestDirectNodeTraversal(t *testing.T) {
	ti := newTestImage(t)
	root := uint32(testRootIno)

	deepData := ti.putData([]byte("deep block"))
	directNID := uint32(50)
	ti.putNode(directNID, 30, func(bytes []byte) {
		putU32(bytes, 1*4, deepData)
	})

	index := uint64(923 + 1)
	ti.putNode(30, 30, func(bytes []byte) {
		inodeFields(bytes, SIFREG|0644, 0, (index+2)*testBlockSize, root)
		var nids [NIDsPerInode]uint32
		nids[0] = directNID
		putNIDs(bytes, nids)
	})

	rootDir := make([]byte, testBlockSize)
	putDirEntry(rootDir, 0, root, DTDir, ".")
	putDirEntry(rootDir, 1, root, DTDir, "..")
	putDirEntry(rootDir, 2, 30, DTReg, "deep.bin")
	rootData := ti.putData(rootDir)
	rootInode := make([]byte, testBlockSize)
	inodeFields(rootInode, SIFDIR|0755, 0, testBlockSize, root)
	putAddress(rootInode, 0, rootData)
	ti.putFooter(rootInode, root, root)
	ti.putBlock(ti.rootBlock, rootInode)

	volume := ti.open()
	fileSource, err := volume.OpenFile("/deep.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, testBlockSize)
	if _, err := fileSource.ReadAt(index*testBlockSize, buf); err != nil {
		t.Fatalf("read deep: %v", err)
	}
	if string(buf[:10]) != "deep block" {
		t.Fatalf("deep = %q", buf[:10])
	}
	// The following block is a hole.
	if _, err := fileSource.ReadAt((index+1)*testBlockSize, buf); err != nil {
		t.Fatalf("read hole: %v", err)
	}
	for _, value := range buf {
		if value != 0 {
			t.Fatalf("hole contains %#x", value)
		}
	}
}

func TestIndirectNodeTraversal(t *testing.T) {
	ti := newTestImage(t)
	root := uint32(testRootIno)

	deepData := ti.putData([]byte("indirect block"))
	directNID := uint32(52)
	ti.putNode(directNID, 30, func(bytes []byte) {
		putU32(bytes, 7*4, deepData)
	})
	indirectNID := uint32(51)
	ti.putNode(indirectNID, 30, func(bytes []byte) {
		putU32(bytes, 0, directNID)
	})

	first := NodeEntries(testBlockSize)
	index := uint64(923 + 2*first + 7)
	ti.putNode(30, 30, func(bytes []byte) {
		inodeFields(bytes, SIFREG|0644, 0, (index+2)*testBlockSize, root)
		var nids [NIDsPerInode]uint32
		nids[2] = indirectNID
		putNIDs(bytes, nids)
	})

	rootDir := make([]byte, testBlockSize)
	putDirEntry(rootDir, 0, root, DTDir, ".")
	putDirEntry(rootDir, 1, root, DTDir, "..")
	putDirEntry(rootDir, 2, 30, DTReg, "indirect.bin")
	rootData := ti.putData(rootDir)
	rootInode := make([]byte, testBlockSize)
	inodeFields(rootInode, SIFDIR|0755, 0, testBlockSize, root)
	putAddress(rootInode, 0, rootData)
	ti.putFooter(rootInode, root, root)
	ti.putBlock(ti.rootBlock, rootInode)

	volume := ti.open()
	fileSource, err := volume.OpenFile("/indirect.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, testBlockSize)
	if _, err := fileSource.ReadAt(index*testBlockSize, buf); err != nil {
		t.Fatalf("read indirect: %v", err)
	}
	if string(buf[:14]) != "indirect block" {
		t.Fatalf("indirect = %q", buf[:14])
	}
}

func TestSymlinkTarget(t *testing.T) {
	volume := standardImage(t).open()
	target, err := volume.SymlinkTarget(34)
	if err != nil {
		t.Fatalf("SymlinkTarget: %v", err)
	}
	if target != "/hello.txt" {
		t.Fatalf("target = %q", target)
	}
	if _, err := volume.SymlinkTarget(30); !errors.Is(err, ErrNotSymlink) {
		t.Fatalf("non-symlink error = %v", err)
	}
	stats, err := volume.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Directories != 2 || stats.Files != 3 || stats.Symlinks != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestPathErrors(t *testing.T) {
	volume := standardImage(t).open()
	if _, err := volume.Stat("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing stat error = %v", err)
	}
	if _, err := volume.OpenFile("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing open error = %v", err)
	}
	if _, err := volume.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("file listdir error = %v", err)
	}
	if _, err := volume.OpenFile("/sub"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("dir open error = %v", err)
	}
}

func TestFreeSpace(t *testing.T) {
	volume := standardImage(t).open()
	free, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if free.Basis() != FreeSpaceBasis {
		t.Fatalf("basis = %q", free.Basis())
	}
	if free.RunCount() == 0 || free.FreeBytes() == 0 {
		t.Fatalf("free map = %d runs, %d bytes", free.RunCount(), free.FreeBytes())
	}
	var sum uint64
	for _, run := range free.Runs() {
		sum += run.Len
	}
	if sum != free.FreeBytes() {
		t.Fatalf("run bytes = %d, free bytes = %d", sum, free.FreeBytes())
	}
	// The root inode block is allocated; a never-allocated block is free.
	if free.IsFree(uint64(volume.superblock.MainBlkaddr)*uint64(testBlockSize), testBlockSize) {
		t.Fatalf("root block reported free")
	}
	unused := uint64(volume.superblock.MainBlkaddr + 500)
	if !free.IsFree(unused*uint64(testBlockSize), testBlockSize) {
		t.Fatalf("unused block %d reported allocated", unused)
	}
}

func TestCorruptStructures(t *testing.T) {
	if _, err := ParseSuperblock(make([]byte, SuperSize-1), SuperOffset); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short superblock error = %v", err)
	}
	badMagic := sampleSuperblock()
	putU32(badMagic, 0, 0)
	if _, err := ParseSuperblock(badMagic, SuperOffset); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad magic error = %v", err)
	}
	badGeometry := sampleSuperblock()
	putU32(badGeometry, 68, 3)
	if _, err := ParseSuperblock(badGeometry, SuperOffset); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad geometry error = %v", err)
	}

	// A damaged checkpoint copy in the image.
	ti := standardImage(t)
	ti.finalizeSIT()
	ti.data[int(ti.sb.ByteOffset(ti.sb.CPBlkaddr))+100] ^= 0xFF
	if _, err := Open(source.NewMemorySource(1, ti.data)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("damaged checkpoint error = %v", err)
	}

	// A truncated image.
	ti = standardImage(t)
	ti.finalizeSIT()
	short := ti.data[:len(ti.data)-testBlockSize]
	if _, err := Open(source.NewMemorySource(1, short)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("truncated image error = %v", err)
	}

	// A node-address table that confirms neither bitmap order.
	ti = standardImage(t)
	ti.finalizeSIT()
	nodeEntry := ti.natEntryAt(testNodeIno)
	for index := 0; index < NATEntrySize; index++ {
		ti.data[nodeEntry+index] = 0
	}
	if _, err := Open(source.NewMemorySource(1, ti.data)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad NAT error = %v", err)
	}

	// An inode footer that names another node id.
	ti = standardImage(t)
	ti.finalizeSIT()
	helloBlock := ti.natBlock(30)
	at := int(ti.sb.ByteOffset(helloBlock)) + testBlockSize - NodeFooterSize
	putU32(ti.data, at, 999)
	volume, err := Open(source.NewMemorySource(1, ti.data))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("footer mismatch error = %v", err)
	}

	// A data address outside the main area.
	ti = standardImage(t)
	ti.setNAT(30, 30, 32)
	volume = ti.open()
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("outside-main error = %v", err)
	}

	// An uncommitted data block is refused by name.
	ti = standardImage(t)
	ti.setNAT(30, 30, NewAddr)
	volume = ti.open()
	if _, err := volume.OpenFile("/hello.txt"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NEW_ADDR error = %v", err)
	}
}

func TestLZ4CompressedFile(t *testing.T) {
	ti := compressedImage(t, AlgorithmLZ4)
	volume := ti.open()
	fileSource, err := volume.OpenFile("/comp.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if fileSource.Len() != 8192 {
		t.Fatalf("len = %d", fileSource.Len())
	}
	buf := make([]byte, 8192)
	if _, err := fileSource.ReadAt(0, buf); err != nil {
		t.Fatalf("read compressed: %v", err)
	}
	for index, value := range buf {
		if value != 'A' {
			t.Fatalf("byte %d = %#x", index, value)
		}
	}
	part := make([]byte, 32)
	if _, err := fileSource.ReadAt(4000, part); err != nil {
		t.Fatalf("partial: %v", err)
	}
	for _, value := range part {
		if value != 'A' {
			t.Fatalf("partial byte = %#x", value)
		}
	}
	typed, ok := fileSource.(*F2fsFileSource)
	if !ok {
		t.Fatalf("source type = %T", fileSource)
	}
	report := typed.CompressionReport()
	if report.Decoded != 1 || report.Refused != 0 || report.Corrupt != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestUnsupportedCompressedAlgorithms(t *testing.T) {
	for _, algorithm := range []uint8{AlgorithmZSTD, AlgorithmLZORLE, AlgorithmLZO} {
		ti := compressedImage(t, algorithm)
		volume := ti.open()
		fileSource, err := volume.OpenFile("/comp.bin")
		if err != nil {
			t.Fatalf("OpenFile alg %d: %v", algorithm, err)
		}
		if _, err := fileSource.ReadAt(0, make([]byte, 16)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("algorithm %d error = %v", algorithm, err)
		}
	}
}

func compressedImage(t *testing.T, algorithm uint8) *testImage {
	t.Helper()
	ti := newTestImage(t)
	root := uint32(testRootIno)

	// One stored block: a 24-byte header followed by the LZ4 payload.
	payload := lz4LiteralAndRun(1, 'A', 8191)
	stored := make([]byte, testBlockSize)
	putU32(stored, 0, CompressMagic)
	putU32(stored, 4, uint32(len(payload)))
	putU32(stored, 8, 8192)
	stored[12] = algorithm
	copy(stored[CompressHeaderSize:], payload)
	storedBlock := ti.allocBlock()
	ti.putBlock(storedBlock, stored)

	ti.putNode(40, 40, func(bytes []byte) {
		inodeFields(bytes, SIFREG|0644, ExtraAttr, 8192, root)
		putU16(bytes, AddrsOffset, 40)
		putU64(bytes, AddrsOffset+24, 1) // i_compr_blocks
		bytes[AddrsOffset+32] = algorithm
		bytes[AddrsOffset+33] = 1 // log cluster size
		putU32(bytes, AddrsOffset+40, CompressAddr)
		putU32(bytes, AddrsOffset+44, storedBlock)
	})

	rootDir := make([]byte, testBlockSize)
	putDirEntry(rootDir, 0, root, DTDir, ".")
	putDirEntry(rootDir, 1, root, DTDir, "..")
	putDirEntry(rootDir, 2, 40, DTReg, "comp.bin")
	rootData := ti.putData(rootDir)
	rootInode := make([]byte, testBlockSize)
	inodeFields(rootInode, SIFDIR|0755, 0, testBlockSize, root)
	putAddress(rootInode, 0, rootData)
	ti.putFooter(rootInode, root, root)
	ti.putBlock(ti.rootBlock, rootInode)
	return ti
}

// lz4LiteralAndRun builds a raw LZ4 block: one literal byte, then a match that
// repeats it for the rest of the output.
func lz4LiteralAndRun(literal byte, value byte, matchLength int) []byte {
	length := matchLength - 4
	out := []byte{0x1F, value, 0x01, 0x00}
	length -= 15
	for length >= 255 {
		out = append(out, 255)
		length -= 255
	}
	out = append(out, byte(length))
	_ = literal
	return out
}

func TestDeletedRecovery(t *testing.T) {
	ti := newTestImage(t)
	root := uint32(testRootIno)

	rootDir := make([]byte, testBlockSize)
	putDirEntry(rootDir, 0, root, DTDir, ".")
	putDirEntry(rootDir, 1, root, DTDir, "..")
	rootData := ti.putData(rootDir)
	rootInode := make([]byte, testBlockSize)
	inodeFields(rootInode, SIFDIR|0755, 0, testBlockSize, root)
	putAddress(rootInode, 0, rootData)
	ti.putFooter(rootInode, root, root)
	ti.putBlock(ti.rootBlock, rootInode)

	// Three blocks the SIT leaves free: data, inode, stale directory.
	dataBlock := uint32(testMainBlkaddr + 200)
	inoBlock := uint32(testMainBlkaddr + 201)
	dirBlock := uint32(testMainBlkaddr + 202)

	data := make([]byte, testBlockSize)
	copy(data, "deleted!\n")
	ti.putBlock(dataBlock, data)

	staleInode := make([]byte, testBlockSize)
	inodeFields(staleInode, SIFREG|0644, 0, 9, root)
	putAddress(staleInode, 0, dataBlock)
	ti.putFooter(staleInode, 60, 60)
	ti.putBlock(inoBlock, staleInode)

	staleDir := make([]byte, testBlockSize)
	putDirEntry(staleDir, 0, root, DTDir, ".")
	putDirEntry(staleDir, 1, root, DTDir, "..")
	putDirEntry(staleDir, 2, 60, DTReg, "gone.txt")
	ti.putBlock(dirBlock, staleDir)

	volume := ti.open()
	scan, err := volume.DeletedScan(nil)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	if scan.Stats.ScannedBlocks == 0 || scan.Stats.DirectoryCandidates == 0 || scan.Stats.Candidates == 0 {
		t.Fatalf("stats = %+v", scan.Stats)
	}
	var entry *RecoveredEntry
	for index := range scan.Entries {
		if scan.Entries[index].Name == "gone.txt" {
			entry = &scan.Entries[index]
			break
		}
	}
	if entry == nil {
		t.Fatalf("gone.txt was not recovered: %+v", scan.Entries)
	}
	if entry.State != EntryDeleted || !entry.Deleted {
		t.Fatalf("entry state = %s deleted = %v", entry.State, entry.Deleted)
	}
	if !entry.HasPath || entry.Path != "/gone.txt" {
		t.Fatalf("entry path = %q (has=%v) reason=%q", entry.Path, entry.HasPath, entry.Reason)
	}
	recovered := scan.Inode(60)
	if recovered == nil {
		t.Fatalf("recovered inode 60 missing")
	}
	if !recovered.Content.IsRecoverable() {
		t.Fatalf("content = %q", recovered.Content.Reason())
	}
	deletedSource, err := volume.DeletedFileSource(scan, 60)
	if err != nil {
		t.Fatalf("DeletedFileSource: %v", err)
	}
	buf := make([]byte, 9)
	if _, err := deletedSource.ReadAt(0, buf); err != nil {
		t.Fatalf("read deleted: %v", err)
	}
	if string(buf) != "deleted!\n" {
		t.Fatalf("deleted bytes = %q", buf)
	}
}

func TestRecoveryJournal(t *testing.T) {
	sbBytes := sampleSuperblock()
	sb, err := ParseSuperblock(sbBytes, SuperOffset)
	if err != nil {
		t.Fatalf("superblock: %v", err)
	}
	// A dirty checkpoint whose pack holds three data summary blocks and a
	// closing checkpoint copy.
	cpBytes := sampleCheckpointBytes(sb, 9, 0)
	putU32(cpBytes, 136, 5) // pack block count
	putU32(cpBytes, 140, 1) // first summary block
	at := int(BitmapOffset + 64)
	crc := foundation.CRC32Seeded(Magic, cpBytes[:at])
	putU32(cpBytes, at, crc)
	cp, err := ParseCheckpoint(cpBytes, sb.CPBlkaddr, 0, sb)
	if err != nil {
		t.Fatalf("parse dirty checkpoint: %v", err)
	}

	image := make([]byte, int(sb.BlockCount)*int(sb.BlockSize))
	copy(image[SuperOffset:], sbBytes)
	copy(image[sb.ByteOffset(sb.CPBlkaddr):], cpBytes)
	copy(image[sb.ByteOffset(sb.CPBlkaddr+4):], cpBytes)

	rootBlock := sb.MainBlkaddr
	nodeBlock := sb.MainBlkaddr + 1
	helloBlock := sb.MainBlkaddr + 5

	ti := &testImage{t: t, data: image, sb: sb, cp: cp, nextBlock: helloBlock + 1, used: map[uint32]bool{}}
	// The inode the journal will point at.
	helloInode := make([]byte, testBlockSize)
	inodeFields(helloInode, SIFREG|0644, 0, 6, testRootIno)
	ti.putFooter(helloInode, 30, 30)
	ti.putBlock(helloBlock, helloInode)

	rootDir := make([]byte, testBlockSize)
	putDirEntry(rootDir, 0, testRootIno, DTDir, ".")
	putDirEntry(rootDir, 1, testRootIno, DTDir, "..")
	putDirEntry(rootDir, 2, 30, DTReg, "recovered.txt")
	rootData := ti.putData(rootDir)
	rootInode := make([]byte, testBlockSize)
	inodeFields(rootInode, SIFDIR|0755, 0, testBlockSize, testRootIno)
	putAddress(rootInode, 0, rootData)
	ti.putFooter(rootInode, testRootIno, testRootIno)
	ti.putBlock(rootBlock, rootInode)

	ti.setNAT(testRootIno, testRootIno, rootBlock)
	ti.setNAT(testNodeIno, testNodeIno, nodeBlock)
	// The table points at a different block; the journal override must win.
	ti.setNAT(30, 30, helloBlock+1)

	// Node-address journal in the hot data summary (block cp+1).
	journalAt := int(sb.ByteOffset(sb.CPBlkaddr+1)) + SummaryAreaSize
	putU16(image, journalAt, 1)
	putU32(image, journalAt+2, 30) // nid
	image[journalAt+6] = 1         // version
	putU32(image, journalAt+7, 30) // ino
	putU32(image, journalAt+11, helloBlock)

	volume, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("open dirty volume: %v", err)
	}
	if volume.IsClean() {
		t.Fatalf("volume reported clean")
	}
	recovery := volume.Recovery()
	if recovery == nil {
		t.Fatalf("no recovery report")
	}
	report := recovery.Report()
	if report.NATJournalEntries != 1 || report.DataSummaryBlocks != 3 {
		t.Fatalf("report = %+v", report)
	}
	entry, err := volume.NAT().Entry(volume.Source(), 30)
	if err != nil {
		t.Fatalf("journal entry: %v", err)
	}
	if entry.Block != helloBlock {
		t.Fatalf("journal block = %d, want %d", entry.Block, helloBlock)
	}
	inode, err := volume.Inode(30)
	if err != nil {
		t.Fatalf("journal inode: %v", err)
	}
	if inode.Ino != 30 {
		t.Fatalf("inode = %d", inode.Ino)
	}
	if _, err := volume.OpenFile("/recovered.txt"); err != nil {
		t.Fatalf("OpenFile via journal: %v", err)
	}
}

func TestBytesReader(t *testing.T) {
	bytes := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if value, err := u16At(bytes, 0); err != nil || value != 0x0201 {
		t.Fatalf("u16 = %#x, %v", value, err)
	}
	if value, err := u32At(bytes, 0); err != nil || value != 0x04030201 {
		t.Fatalf("u32 = %#x, %v", value, err)
	}
	if value, err := u64At(bytes, 0); err != nil || value != 0x0807060504030201 {
		t.Fatalf("u64 = %#x, %v", value, err)
	}
	if _, err := u64At(bytes, 1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short u64 error = %v", err)
	}
}

func TestDirBlockParsing(t *testing.T) {
	block := make([]byte, testBlockSize)
	putDirEntry(block, 0, 3, DTDir, ".")
	putDirEntry(block, 1, 3, DTDir, "..")
	putDirEntry(block, 2, 21, DTReg, "hello.txt")
	putDirEntry(block, 4, 22, DTDir, "中文目录")
	entries, err := ParseDirBlock(block, testBlockSize)
	if err != nil {
		t.Fatalf("ParseDirBlock: %v", err)
	}
	if len(entries) != 4 || entries[2].Ino != 21 || string(entries[3].Name) != "中文目录" {
		t.Fatalf("entries = %+v", entries)
	}
	if _, err := ParseDirBlock(block, 16384); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("foreign block error = %v", err)
	}
	if !bytes.Equal([]byte("hello.txt"), entries[2].Name) {
		t.Fatalf("name bytes = %v", entries[2].Name)
	}
}

func TestDeletedStillLiveEntry(t *testing.T) {
	ti := standardImage(t)
	// A stale directory block in free space that still names the live file.
	staleDir := make([]byte, testBlockSize)
	putDirEntry(staleDir, 0, testRootIno, DTDir, ".")
	putDirEntry(staleDir, 1, testRootIno, DTDir, "..")
	putDirEntry(staleDir, 2, 30, DTReg, "hello.txt")
	ti.putBlock(testMainBlkaddr+300, staleDir)

	volume := ti.open()
	scan, err := volume.DeletedScan(nil)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	var entry *RecoveredEntry
	for index := range scan.Entries {
		if scan.Entries[index].Name == "hello.txt" {
			entry = &scan.Entries[index]
			break
		}
	}
	if entry == nil {
		t.Fatalf("hello.txt was not offered as residue")
	}
	if entry.State != EntryStillLive || entry.Deleted {
		t.Fatalf("state = %s deleted = %v", entry.State, entry.Deleted)
	}
	if entry.HasPath {
		t.Fatalf("still-live entry carries a path %q", entry.Path)
	}
}

func TestDeletedContentRequiresFreeBlocks(t *testing.T) {
	ti := newTestImage(t)
	root := uint32(testRootIno)

	rootDir := make([]byte, testBlockSize)
	putDirEntry(rootDir, 0, root, DTDir, ".")
	putDirEntry(rootDir, 1, root, DTDir, "..")
	rootData := ti.putData(rootDir)
	rootInode := make([]byte, testBlockSize)
	inodeFields(rootInode, SIFDIR|0755, 0, testBlockSize, root)
	putAddress(rootInode, 0, rootData)
	ti.putFooter(rootInode, root, root)
	ti.putBlock(ti.rootBlock, rootInode)

	// The stale inode is free, but the block it names is still allocated.
	allocated := ti.putData([]byte("still allocated"))
	staleInode := make([]byte, testBlockSize)
	inodeFields(staleInode, SIFREG|0644, 0, 16, root)
	putAddress(staleInode, 0, allocated)
	ti.putFooter(staleInode, 61, 61)
	ti.putBlock(testMainBlkaddr+400, staleInode)

	volume := ti.open()
	scan, err := volume.DeletedScan(nil)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	recovered := scan.Inode(61)
	if recovered == nil {
		t.Fatalf("inode 61 was not recovered")
	}
	if recovered.Content.IsRecoverable() {
		t.Fatalf("content was offered although its data block is allocated")
	}
	if !strings.Contains(recovered.Content.Reason(), "still allocated") {
		t.Fatalf("reason = %q", recovered.Content.Reason())
	}
	if _, err := volume.DeletedFileSource(scan, 61); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("export error = %v", err)
	}
}
