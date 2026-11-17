package qnx6

import (
	"strings"
)

// The synthetic image layout. Every block assignment below is data-area
// relative; the builder translates them to device blocks with blks_off.
const (
	testBlockSize = 4096
	testNumBlocks = 64
	testNumInodes = 64
)

const (
	blockInodeRoot0 = 0
	blockInodeRoot1 = 1
	blockRootDir    = 2
	blockSubDir     = 3
	blockLongfile   = 4
	blockHello      = 5
	blockMulti0     = 6
	blockMulti1     = 7
	blockTreePtr    = 8
	blockTreeData   = 9
	blockSymlink    = 10
	blockSubsubDir  = 11
	blockNested     = 12
	blockLeaf       = 13
	blockLongData   = 14
)

const (
	inoRoot    uint32 = 1
	inoHello   uint32 = 2
	inoSub     uint32 = 3
	inoLong    uint32 = 4
	inoLink    uint32 = 5
	inoMulti   uint32 = 6
	inoTree    uint32 = 7
	inoDeleted uint32 = 8
	inoNested  uint32 = 9
	inoSubsub  uint32 = 10
	inoLeaf    uint32 = 11
	inoEmpty   uint32 = 12
)

const (
	helloName  = "hello.txt"
	hardName   = "hello-hard"
	subName    = "sub"
	linkName   = "link"
	multiName  = "multi.bin"
	treeName   = "tree.bin"
	emptyName  = "empty"
	nestedName = "nested.txt"
	leafName   = "leaf.txt"
)

var (
	longName      = "this-is-a-very-long-qnx6-file-name.txt"
	symlinkTarget = "../../hello.txt"
	helloData     = []byte("hello world")
	multiData     = makeMultiData()
	nestedData    = []byte("nested")
	leafData      = []byte("leaf!")
	longData      = []byte("long")
)

func makeMultiData() []byte {
	data := make([]byte, testBlockSize+100)
	for index := range data {
		data[index] = byte(index % 251)
	}
	return data
}

type fixtureOptions struct {
	order        ByteOrder
	layout       Layout
	serial       uint64
	backupSerial uint64
}

func defaultOptions() fixtureOptions {
	return fixtureOptions{order: Little, layout: LayoutStandard, serial: 100, backupSerial: 90}
}

// buildImage assembles a complete hermetic QNX6 image.
func buildImage(opts fixtureOptions) []byte {
	blockSize := uint64(testBlockSize)
	primaryOffset := PrimaryOffset
	blksOff := BootblockSize/blockSize + SuperblockArea/blockSize
	if opts.layout == LayoutMMI {
		primaryOffset = AlternateOffset
		blksOff = SuperblockArea / blockSize
	}
	backupOffset := (blksOff + testNumBlocks) * blockSize
	image := make([]byte, backupOffset+blockSize)

	writeBlock := func(block uint32, data []byte) {
		at := int((blksOff + uint64(block)) * blockSize)
		copy(image[at:at+testBlockSize], data)
	}

	// The inode table is a single byte stream spanning two blocks.
	inodeStream := make([]byte, testNumInodes*InodeSize)
	inodes := fixtureInodes(opts.order)
	for number, record := range inodes {
		at := uint64(number-1) * InodeSize
		copy(inodeStream[at:at+InodeSize], record)
	}
	writeBlock(blockInodeRoot0, inodeStream[:testBlockSize])
	writeBlock(blockInodeRoot1, inodeStream[testBlockSize:])

	writeBlock(blockRootDir, fixtureRootDirectory(opts.order))
	writeBlock(blockSubDir, fixtureSubDirectory(opts.order))
	writeBlock(blockSubsubDir, fixtureSubsubDirectory(opts.order))
	writeBlock(blockLongfile, makeLongRecord(opts.order, longName))

	helloBlock := make([]byte, testBlockSize)
	copy(helloBlock, helloData)
	writeBlock(blockHello, helloBlock)

	multiBlock0 := make([]byte, testBlockSize)
	copy(multiBlock0, multiData[:testBlockSize])
	writeBlock(blockMulti0, multiBlock0)
	multiBlock1 := make([]byte, testBlockSize)
	copy(multiBlock1, multiData[testBlockSize:])
	writeBlock(blockMulti1, multiBlock1)

	pointerBlock := make([]byte, testBlockSize)
	putU32(opts.order, pointerBlock, 0, blockTreeData)
	writeBlock(blockTreePtr, pointerBlock)
	treeData := make([]byte, testBlockSize)
	for index := range treeData {
		treeData[index] = byte(0x40 + index%60)
	}
	writeBlock(blockTreeData, treeData)

	symlinkBlock := make([]byte, testBlockSize)
	copy(symlinkBlock, symlinkTarget)
	writeBlock(blockSymlink, symlinkBlock)

	nestedBlock := make([]byte, testBlockSize)
	copy(nestedBlock, nestedData)
	writeBlock(blockNested, nestedBlock)

	leafBlock := make([]byte, testBlockSize)
	copy(leafBlock, leafData)
	writeBlock(blockLeaf, leafBlock)

	longBlock := make([]byte, testBlockSize)
	copy(longBlock, longData)
	writeBlock(blockLongData, longBlock)

	primary := makeSuperblock(opts.order, opts.layout, opts.serial, blockLongfile)
	copy(image[primaryOffset:primaryOffset+SuperblockSize], primary)
	backup := makeSuperblock(opts.order, opts.layout, opts.backupSerial, blockLongfile)
	copy(image[backupOffset:backupOffset+SuperblockSize], backup)
	return image
}

func fixtureInodes(order ByteOrder) map[uint32][]byte {
	unused := func() [16]uint32 {
		var ptrs [16]uint32
		for index := range ptrs {
			ptrs[index] = Unused
		}
		return ptrs
	}

	rootPtrs := unused()
	rootPtrs[0] = blockRootDir
	subPtrs := unused()
	subPtrs[0] = blockSubDir
	subsubPtrs := unused()
	subsubPtrs[0] = blockSubsubDir
	helloPtrs := unused()
	helloPtrs[0] = blockHello
	longPtrs := unused()
	longPtrs[0] = blockLongData
	linkPtrs := unused()
	linkPtrs[0] = blockSymlink
	multiPtrs := unused()
	multiPtrs[0] = blockMulti0
	multiPtrs[1] = blockMulti1
	treePtrs := unused()
	treePtrs[0] = blockTreePtr
	nestedPtrs := unused()
	nestedPtrs[0] = blockNested
	leafPtrs := unused()
	leafPtrs[0] = blockLeaf

	return map[uint32][]byte{
		inoRoot:    makeInode(order, uint64(13*DirEntrySize), 0, 0, 0x41ed, StatusDirectory, 0, rootPtrs),
		inoHello:   makeInode(order, uint64(len(helloData)), 1000, 1000, 0x81a4, StatusNormal, 0, helloPtrs),
		inoSub:     makeInode(order, uint64(4*DirEntrySize), 0, 0, 0x41ed, StatusDirectory, 0, subPtrs),
		inoLong:    makeInode(order, uint64(len(longData)), 1000, 1000, 0x81a4, StatusNormal, 0, longPtrs),
		inoLink:    makeInode(order, uint64(len(symlinkTarget)), 1000, 1000, 0xa1ff, StatusNormal, 0, linkPtrs),
		inoMulti:   makeInode(order, uint64(len(multiData)), 1000, 1000, 0x81a4, StatusNormal, 0, multiPtrs),
		inoTree:    makeInode(order, testBlockSize, 1000, 1000, 0x81a4, StatusNormal, 1, treePtrs),
		inoDeleted: makeInode(order, 0, 1000, 1000, 0x81a4, StatusDeleted, 0, unused()),
		inoNested:  makeInode(order, uint64(len(nestedData)), 1000, 1000, 0x81a4, StatusNormal, 0, nestedPtrs),
		inoSubsub:  makeInode(order, uint64(3*DirEntrySize), 0, 0, 0x41ed, StatusDirectory, 0, subsubPtrs),
		inoLeaf:    makeInode(order, uint64(len(leafData)), 1000, 1000, 0x81a4, StatusNormal, 0, leafPtrs),
		inoEmpty:   makeInode(order, 0, 1000, 1000, 0x81a4, StatusNormal, 0, unused()),
	}
}

func fixtureRootDirectory(order ByteOrder) []byte {
	longChecksum := NameChecksum([]byte(longName))
	slots := [][]byte{
		makeShortSlot(order, inoRoot, "."),
		makeShortSlot(order, inoRoot, ".."),
		makeShortSlot(order, inoHello, helloName),
		makeShortSlot(order, inoSub, subName),
		makeLongSlot(order, inoLong, 0, longChecksum),
		makeShortSlot(order, inoLink, linkName),
		makeShortSlot(order, inoMulti, multiName),
		makeShortSlot(order, inoTree, treeName),
		makeShortSlot(order, inoDeleted, "gone.txt"),
		makeShortSlot(order, inoEmpty, emptyName),
		makeShortSlot(order, inoHello, hardName),
		makeShortSlot(order, 0, "ghost"),
		makeZeroLengthSlot(order, inoEmpty, "ignored"),
	}
	return joinSlots(slots)
}

func fixtureSubDirectory(order ByteOrder) []byte {
	return joinSlots([][]byte{
		makeShortSlot(order, inoSub, "."),
		makeShortSlot(order, inoRoot, ".."),
		makeShortSlot(order, inoNested, nestedName),
		makeShortSlot(order, inoSubsub, "subsub"),
	})
}

func fixtureSubsubDirectory(order ByteOrder) []byte {
	return joinSlots([][]byte{
		makeShortSlot(order, inoSubsub, "."),
		makeShortSlot(order, inoSub, ".."),
		makeShortSlot(order, inoLeaf, leafName),
	})
}

func joinSlots(slots [][]byte) []byte {
	out := make([]byte, 0, len(slots)*DirEntrySize)
	for _, slot := range slots {
		out = append(out, slot...)
	}
	return out
}

func makeShortSlot(order ByteOrder, inode uint32, name string) []byte {
	slot := make([]byte, DirEntrySize)
	putU32(order, slot, 0, inode)
	if len(name) > ShortNameMax {
		panic("short slot name too long")
	}
	slot[4] = byte(len(name))
	copy(slot[5:], name)
	return slot
}

func makeLongSlot(order ByteOrder, inode, longBlock, checksum uint32) []byte {
	slot := make([]byte, DirEntrySize)
	putU32(order, slot, 0, inode)
	slot[4] = LongMarker
	putU32(order, slot, 8, longBlock)
	putU32(order, slot, 0x0c, checksum)
	return slot
}

func makeZeroLengthSlot(order ByteOrder, inode uint32, name string) []byte {
	slot := make([]byte, DirEntrySize)
	putU32(order, slot, 0, inode)
	slot[4] = 0
	copy(slot[5:], name)
	return slot
}

func makeLongRecord(order ByteOrder, name string) []byte {
	record := make([]byte, LongRecordSize)
	putU16(order, record, 0, uint16(len(name)))
	copy(record[2:], name)
	return record
}

func makeInode(order ByteOrder, size uint64, uid, gid uint32, mode uint16, status, levels uint8,
	ptrs [16]uint32) []byte {
	record := make([]byte, InodeSize)
	putU64(order, record, 0x00, size)
	putU32(order, record, 0x08, uid)
	putU32(order, record, 0x0c, gid)
	putU32(order, record, 0x10, 1_600_000_100)
	putU32(order, record, 0x14, 1_600_000_200)
	putU32(order, record, 0x18, 1_600_000_300)
	putU32(order, record, 0x1c, 1_600_000_400)
	putU16(order, record, 0x20, mode)
	putU16(order, record, 0x22, 0)
	for index, block := range ptrs {
		putU32(order, record, 0x24+index*4, block)
	}
	record[0x64] = levels
	record[0x65] = status
	return record
}

func makeSuperblock(order ByteOrder, layout Layout, serial uint64, longfileBlock uint32) []byte {
	superblock := make([]byte, SuperblockSize)
	putU32(order, superblock, 0, Magic)
	putU64(order, superblock, serialAt, serial)

	blockSizeOffset := blockSizeAt
	numInodesOffset := numInodesAt
	freeInodesOffset := freeInodesAt
	numBlocksOffset := numBlocksAt
	freeBlocksOffset := freeBlocksAt
	inodeOffset := inodeRootAt
	longfileOffset := longfileRootAt
	if layout == LayoutMMI {
		blockSizeOffset = mmiBlockSizeAt
		numInodesOffset = mmiNumInodesAt
		freeInodesOffset = mmiFreeInodesAt
		numBlocksOffset = mmiNumBlocksAt
		freeBlocksOffset = mmiFreeBlocksAt
		inodeOffset = mmiInodeRootAt
		longfileOffset = mmiLongfileRootAt
	} else {
		putU32(order, superblock, ctimeAt, 1_600_000_000)
		putU32(order, superblock, atimeAt, 1_600_000_100)
		putU32(order, superblock, flagsAt, 0)
		putU16(order, superblock, version1At, 1)
		putU16(order, superblock, version2At, 1)
		copy(superblock[volumeIDAt:volumeIDAt+16], "qnx6test")
		putU32(order, superblock, allocGroupAt, 1)
	}
	putU32(order, superblock, blockSizeOffset, testBlockSize)
	putU32(order, superblock, numInodesOffset, testNumInodes)
	putU32(order, superblock, freeInodesOffset, 50)
	putU32(order, superblock, numBlocksOffset, testNumBlocks)
	putU32(order, superblock, freeBlocksOffset, 10)

	writeRootNode(order, superblock, inodeOffset, uint64(testNumInodes)*InodeSize,
		[]rootPointer{{0, blockInodeRoot0}, {1, blockInodeRoot1}}, 0)
	writeRootNode(order, superblock, longfileOffset, LongRecordSize,
		[]rootPointer{{0, longfileBlock}}, 0)

	putU32(order, superblock, checksumAt, CRC32BE(superblock[8:SuperblockSize]))
	return superblock
}

type rootPointer struct {
	index int
	block uint32
}

func writeRootNode(order ByteOrder, bytes []byte, offset int, size uint64,
	pointers []rootPointer, levels uint8) {
	putU64(order, bytes, offset, size)
	for _, pointer := range pointers {
		putU32(order, bytes, offset+8+pointer.index*4, pointer.block)
	}
	bytes[offset+0x48] = levels
}

func putU16(order ByteOrder, bytes []byte, offset int, value uint16) {
	if order == Big {
		bytes[offset] = byte(value >> 8)
		bytes[offset+1] = byte(value)
		return
	}
	bytes[offset] = byte(value)
	bytes[offset+1] = byte(value >> 8)
}

func putU32(order ByteOrder, bytes []byte, offset int, value uint32) {
	if order == Big {
		bytes[offset] = byte(value >> 24)
		bytes[offset+1] = byte(value >> 16)
		bytes[offset+2] = byte(value >> 8)
		bytes[offset+3] = byte(value)
		return
	}
	bytes[offset] = byte(value)
	bytes[offset+1] = byte(value >> 8)
	bytes[offset+2] = byte(value >> 16)
	bytes[offset+3] = byte(value >> 24)
}

func putU64(order ByteOrder, bytes []byte, offset int, value uint64) {
	if order == Big {
		putU32(order, bytes, offset, uint32(value>>32))
		putU32(order, bytes, offset+4, uint32(value))
		return
	}
	putU32(order, bytes, offset, uint32(value))
	putU32(order, bytes, offset+4, uint32(value>>32))
}

// dataOffset returns the image byte offset of one data-area block.
func dataOffset(layout Layout, block uint32) int {
	blockSize := uint64(testBlockSize)
	blksOff := BootblockSize/blockSize + SuperblockArea/blockSize
	if layout == LayoutMMI {
		blksOff = SuperblockArea / blockSize
	}
	return int((blksOff + uint64(block)) * blockSize)
}

// inodeOffset returns the image byte offset of one inode record.
func inodeOffset(layout Layout, number uint32) int {
	stream := uint64(number-1) * InodeSize
	return dataOffset(layout, uint32(stream/testBlockSize)) + int(stream%testBlockSize)
}

// refreshChecksum recomputes the primary or backup superblock checksum after
// a test mutates a field.
func refreshChecksum(image []byte, offset int, order ByteOrder) {
	putU32(order, image, offset+checksumAt, CRC32BE(image[offset+8:offset+SuperblockSize]))
}

func primaryOffsetFor(layout Layout) int {
	if layout == LayoutMMI {
		return int(AlternateOffset)
	}
	return int(PrimaryOffset)
}

func backupOffsetFor(layout Layout) int {
	blockSize := uint64(testBlockSize)
	blksOff := BootblockSize/blockSize + SuperblockArea/blockSize
	if layout == LayoutMMI {
		blksOff = SuperblockArea / blockSize
	}
	return int((blksOff + testNumBlocks) * blockSize)
}

func containsName(entries []Entry, name string) bool {
	for _, entry := range entries {
		if entry.Name == name {
			return true
		}
	}
	return false
}

func warningsContain(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}
