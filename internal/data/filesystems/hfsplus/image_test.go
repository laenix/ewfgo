package hfsplus_test

// A hand-built HFS+ image, written byte by byte.  Nothing here calls the
// parser under test, so a bug in the reader cannot hide behind a shared
// encoder.  The layout mirrors the Rust fixture in
// forensic-fixtures/src/hfsplus.rs: a fragmented catalog whose last two nodes
// are reached through the extents-overflow tree, a file (photo.bin) with more
// inline extents than a fork descriptor holds, an attributes B-tree, an
// allocation file, and optional journal / residue material.

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"sort"
)

const (
	testBlock       = 4096
	testNode        = 4096
	testTotalBlocks = 256
	testImageLen    = testBlock * testTotalBlocks
	testHeaderAt    = 1024

	testCatalogStart    = 8
	testCatalogOverflow = 10
	testExtentsStart    = 16
	testAttrsStart      = 140

	testAllocBlock   = 1
	testReadmeBlock  = 48
	testResRsrcBlock = 49
	testTodoBlock1   = 50
	testResDataBlock = 51
	testTodoBlock2   = 52
	testSymBlock     = 53
	testMixedBlock   = 54
	testPhotoFirst   = 60
	testPhotoCount   = 10
	testInodeBlock   = 130
	testAttrFork1    = 142
	testAttrFork2    = 143
	testResidueBlock = 100

	testJournalInfoBlock = 200
	testJournalOffset    = 917_504
	testJournalSize      = 131_072
	testJournalSector    = 512
	testJournalBlhdr     = 4096
	testJournalStart     = 512

	cnidRoot     = 2
	cnidExtents  = 3
	cnidCatalog  = 4
	cnidReadme   = 16
	cnidNotes    = 17
	cnidTodo     = 18
	cnidPhoto    = 19
	cnidLink     = 20
	cnidInode    = 21
	cnidDeleted  = 23
	cnidPrivate  = 24
	cnidRes      = 26
	cnidSym      = 27
	cnidMixed    = 28
	cnidNextCNID = 64

	catalogCompareHFSPlus = 0xCF
	catalogCompareHFSX    = 0xBC

	recordFolder       = 1
	recordFile         = 2
	recordFolderThread = 3
	recordFileThread   = 4

	flagThreadExists = 0x0002
	flagHasAttrs     = 0x0004
	flagLinkChain    = 0x0020

	// Compressed files' data/resource blocks live in a range no base fixture
	// uses.
	testDecmpfsBlockBase = 150

	decmpfsAttrName        = "com.apple.decmpfs"
	resourceForkAttrName   = "com.apple.ResourceFork"
	decmpfsFirstCNID       = 40
	lzfseFixtureStreamText = "bvx-\x0e\x00\x00\x00hello, lzfse!\nbvx$"
)

var (
	volumeName  = "Test Volume"
	privateName = "\u0000\u0000\u0000\u0000HFS+ Private Data"
	readmeData  = []byte("Hello, HFS+!\n")
	resData     = []byte("data!")
	resResource = []byte("resource!")
	symData     = []byte("target")
	mixedData   = []byte("abc")
	inodeData   = []byte("shared inode content\n")
	deletedData = []byte("deleted payload")

	attrSmallValue = []byte("hello")
	attrBigValue   = patterned(2*testBlock, 0xAB)
	todoData       = patterned(5000, 0x07)
	photoData      = patterned(testPhotoCount*testBlock, 0x50)

	// Compressed-file content and the stub an untransparent reader would see.
	dataForkStub = []byte("dataless-data-fork")

	decmpfsZlibInlineContent     = []byte("inline zlib content: aaaaaaaaaaaaaaaaaaaaaaaaaa")
	decmpfsLZVNInlineContent     = []byte("hello")
	decmpfsRawInlineContent      = []byte("inline raw content")
	decmpfsLZFSEInlineContent    = []byte("hello, lzfse!\n")
	decmpfsZlibResourceContent   = []byte("resource-fork zlib content: bbbbbbbbbbbbbbbbb")
	decmpfsLZVNResourceContent   = []byte("hello")
	decmpfsRawResourceContent    = []byte("resource-fork raw content")
	decmpfsLZFSEEResourceContent = []byte("hello, lzfse!\n")
	decmpfsSizeMismatchContent   = []byte("size mismatch payload")
	decmpfsLZBitmapRawContent    = []byte("lzbitmap raw copy")
)

// decmpfsSpec describes one compressed file the fixture builder emits.
type decmpfsSpec struct {
	name    string
	cnid    uint32
	attr    []byte // com.apple.decmpfs value
	rsrc    []byte // catalog resource fork contents, or nil
	rsrcXat []byte // com.apple.ResourceFork attribute value, or nil
	dataBlk uint32
	rsrcBlk uint32
}

// decmpfsFixtureStream is the embedded LZFSE stream for "hello, lzfse!\n".
func decmpfsFixtureStream() []byte { return []byte(lzfseFixtureStreamText) }

// lzvnHelloStream is the minimal LZVN stream from the Rust reference: one
// five-byte literal run and the eight-byte end marker.
func lzvnHelloStream() []byte {
	return []byte{0xe5, 'h', 'e', 'l', 'l', 'o', 0x06, 0, 0, 0, 0, 0, 0, 0}
}

// zlibStored compresses data as a zlib stream.
func zlibStored(data []byte) []byte {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// decmpfsValue builds a com.apple.decmpfs value.
func decmpfsValue(typ uint32, size uint64, payload []byte) []byte {
	out := make([]byte, decmpfsHeaderLenTest)
	copy(out, []byte("fpmc"))
	binary.LittleEndian.PutUint32(out[4:8], typ)
	binary.LittleEndian.PutUint64(out[8:16], size)
	return append(out, payload...)
}

// classicResource builds the classic HFS+ resource fork layout: a big-endian
// data offset, a big-endian stream length at that offset, then the stream.
func classicResource(stream []byte) []byte {
	out := make([]byte, 16)
	put32(out, 0, 16)
	out = append(out, be32(uint32(len(stream)))...)
	return append(out, stream...)
}

const decmpfsHeaderLenTest = 16

// decmpfsSpecs returns the compressed files used by the decmpfs tests.  Each
// gets a data-fork stub and a resource block so allocation stays in range.
func decmpfsSpecs(opts imageOptions) []decmpfsSpec {
	specs := []decmpfsSpec{
		{name: "inline-zlib.bin", cnid: decmpfsFirstCNID,
			attr: decmpfsValue(3, uint64(len(decmpfsZlibInlineContent)), zlibStored(decmpfsZlibInlineContent))},
		{name: "inline-lzvn.bin", cnid: decmpfsFirstCNID + 1,
			attr: decmpfsValue(7, uint64(len(decmpfsLZVNInlineContent)), lzvnHelloStream())},
		{name: "inline-raw.bin", cnid: decmpfsFirstCNID + 2,
			attr: decmpfsValue(9, uint64(len(decmpfsRawInlineContent)), decmpfsRawInlineContent)},
		{name: "inline-lzfse.bin", cnid: decmpfsFirstCNID + 3,
			attr: decmpfsValue(11, uint64(len(decmpfsLZFSEInlineContent)), decmpfsFixtureStream())},
		{name: "rsrc-zlib.bin", cnid: decmpfsFirstCNID + 4,
			attr: decmpfsValue(4, uint64(len(decmpfsZlibResourceContent)), nil),
			rsrc: classicResource(zlibStored(decmpfsZlibResourceContent))},
		{name: "rsrc-lzvn.bin", cnid: decmpfsFirstCNID + 5,
			attr: decmpfsValue(8, uint64(len(decmpfsLZVNResourceContent)), nil),
			rsrc: classicResource(lzvnHelloStream())},
		{name: "rsrc-raw.bin", cnid: decmpfsFirstCNID + 6,
			attr:    decmpfsValue(10, uint64(len(decmpfsRawResourceContent)), nil),
			rsrcXat: classicResource(decmpfsRawResourceContent)},
		{name: "rsrc-lzfse.bin", cnid: decmpfsFirstCNID + 7,
			attr: decmpfsValue(12, uint64(len(decmpfsLZFSEEResourceContent)), nil),
			rsrc: classicResource(decmpfsFixtureStream())},
		{name: "size-mismatch.bin", cnid: decmpfsFirstCNID + 8,
			attr: decmpfsValue(3, uint64(len(decmpfsSizeMismatchContent))+1, zlibStored(decmpfsSizeMismatchContent))},
		{name: "missing-rsrc.bin", cnid: decmpfsFirstCNID + 9,
			attr: decmpfsValue(4, 8, nil)},
		{name: "bad-magic.bin", cnid: decmpfsFirstCNID + 10,
			attr: func() []byte {
				value := decmpfsValue(3, 4, zlibStored([]byte("data")))
				copy(value, []byte("xxxx"))
				return value
			}()},
		{name: "lzbitmap.bin", cnid: decmpfsFirstCNID + 11,
			attr: func() []byte {
				if opts.decmpfsBitmapRaw {
					payload := append([]byte{0xFF}, decmpfsLZBitmapRawContent...)
					return decmpfsValue(13, uint64(len(decmpfsLZBitmapRawContent)), payload)
				}
				return decmpfsValue(13, 8, []byte{0x01, 0x02, 0x03})
			}()},
	}
	for i := range specs {
		specs[i].dataBlk = testDecmpfsBlockBase + uint32(2*i)
		specs[i].rsrcBlk = testDecmpfsBlockBase + uint32(2*i+1)
	}
	return specs
}

type extent struct {
	start uint32
	count uint32
}

type forkSpec struct {
	size    uint64
	blocks  uint32
	extents []extent
}

type imageOptions struct {
	caseSensitive bool
	attributes    bool
	journal       bool
	residue       bool
	uuidID        uint64
	// minimal emits only the root folder plus the decmpfs fixtures, so a
	// dozen compressed files fit in the catalog's two leaves.
	minimal bool
	// decmpfs emits the compressed-file fixtures.
	decmpfs bool
	// decmpfsBitmapRaw serves the LZBitmap fixture's 0xFF raw-copy form
	// instead of an unsupported compressed stream.
	decmpfsBitmapRaw bool
}

type catalogRecord struct {
	key  []byte
	body []byte
}

func patterned(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i*7+i/251)
	}
	return out
}

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func be64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }

func put16(b []byte, at int, v uint16) { binary.BigEndian.PutUint16(b[at:], v) }
func put32(b []byte, at int, v uint32) { binary.BigEndian.PutUint32(b[at:], v) }
func put64(b []byte, at int, v uint64) { binary.BigEndian.PutUint64(b[at:], v) }

// --- key and record encoders ------------------------------------------------

func catalogKey(parent uint32, name string) []byte {
	units := utf16Units(name)
	out := make([]byte, 0, 6+2*len(units))
	out = append(out, be32(parent)...)
	out = append(out, be16(uint16(len(units)))...)
	for _, unit := range units {
		out = append(out, be16(unit)...)
	}
	return out
}

func utf16Units(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for _, r := range s {
		if r <= 0xFFFF {
			out = append(out, uint16(r))
			continue
		}
		r -= 0x10000
		out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
	}
	return out
}

func keyed(key, body []byte) []byte {
	out := make([]byte, 0, 2+len(key)+1+len(body))
	out = append(out, be16(uint16(len(key)))...)
	out = append(out, key...)
	if len(key)%2 == 1 {
		out = append(out, 0)
	}
	out = append(out, body...)
	return out
}

func keyPayload(record []byte) []byte {
	n := int(binary.BigEndian.Uint16(record[:2]))
	return record[2 : 2+n]
}

func writeFork(dst []byte, spec forkSpec) {
	for i := range dst {
		dst[i] = 0
	}
	put64(dst, 0, spec.size)
	put32(dst, 12, spec.blocks)
	for i, e := range spec.extents {
		put32(dst, 16+i*8, e.start)
		put32(dst, 16+i*8+4, e.count)
	}
}

func fileBody(id uint32, flags, mode uint16, special uint32, data, resource forkSpec) []byte {
	body := make([]byte, 248)
	put16(body, 0, recordFile)
	put16(body, 2, flags)
	put32(body, 8, id)
	put32(body, 12, 3_786_912_000) // create
	put32(body, 16, 3_786_912_600) // content modified
	put32(body, 20, 3_786_912_400) // attribute modified
	put32(body, 24, 3_786_913_000) // accessed
	put32(body, 28, 3_786_912_000) // backed up
	put32(body, 32, 501)           // owner
	put32(body, 36, 20)            // group
	put16(body, 42, mode)
	put32(body, 44, special)
	writeFork(body[88:168], data)
	writeFork(body[168:248], resource)
	return body
}

func folderBody(id, valence uint32, mode uint16) []byte {
	body := make([]byte, 88)
	put16(body, 0, recordFolder)
	put16(body, 2, flagThreadExists)
	put32(body, 4, valence)
	put32(body, 8, id)
	put32(body, 12, 3_786_912_000)
	put32(body, 16, 3_786_912_600)
	put32(body, 20, 3_786_912_400)
	put32(body, 24, 3_786_913_000)
	put32(body, 28, 3_786_912_000)
	put32(body, 32, 501)
	put32(body, 36, 20)
	put16(body, 42, mode)
	put32(body, 84, 0)
	return body
}

func threadBody(kind uint16, parent uint32, name string) []byte {
	units := utf16Units(name)
	body := make([]byte, 10+2*len(units))
	put16(body, 0, kind)
	put32(body, 4, parent)
	put16(body, 8, uint16(len(units)))
	for i, unit := range units {
		put16(body, 10+2*i, unit)
	}
	return body
}

// --- B-tree node encoder ----------------------------------------------------

// buildNode returns the node and the offset where free space starts.
func buildNode(kind int8, height uint8, forward, backward uint32, records [][]byte) ([]byte, int) {
	node := make([]byte, testNode)
	put32(node, 0, forward)
	put32(node, 4, backward)
	node[8] = byte(kind)
	node[9] = height
	put16(node, 10, uint16(len(records)))

	table := testNode - 2*(len(records)+1)
	at := 14
	for i, record := range records {
		if at+len(record) > table {
			panic("test node records overflow")
		}
		copy(node[at:], record)
		put16(node, table+2*i, uint16(at))
		at += len(record)
	}
	put16(node, table+2*len(records), uint16(at))
	return node, at
}

func btreeHeader(depth uint16, root, leafRecords, firstLeaf, lastLeaf, totalNodes uint32, compare byte) []byte {
	record := make([]byte, 106)
	put16(record, 0, depth)
	put32(record, 2, root)
	put32(record, 6, leafRecords)
	put32(record, 10, firstLeaf)
	put32(record, 14, lastLeaf)
	put16(record, 18, testNode)
	put16(record, 20, 520)
	put32(record, 22, totalNodes)
	put32(record, 26, 0)
	record[37] = compare
	return record
}

// --- catalog ordering -------------------------------------------------------

func foldUnit(unit uint16) uint16 {
	if unit >= 'A' && unit <= 'Z' {
		return unit + 32
	}
	return unit
}

func compareUnits(a, b []uint16, caseSensitive bool) int {
	shared := len(a)
	if len(b) < shared {
		shared = len(b)
	}
	for i := 0; i < shared; i++ {
		left, right := a[i], b[i]
		if !caseSensitive {
			left, right = foldUnit(left), foldUnit(right)
		}
		if left != right {
			if left < right {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func decodeKey(payload []byte) (uint32, []uint16) {
	parent := binary.BigEndian.Uint32(payload[0:4])
	n := int(binary.BigEndian.Uint16(payload[4:6]))
	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = binary.BigEndian.Uint16(payload[6+2*i:])
	}
	return parent, units
}

func compareCatalogKeys(a, b []byte, caseSensitive bool) int {
	aParent, aUnits := decodeKey(a)
	bParent, bUnits := decodeKey(b)
	switch {
	case aParent < bParent:
		return -1
	case aParent > bParent:
		return 1
	default:
		return compareUnits(aUnits, bUnits, caseSensitive)
	}
}

// --- extents tree records ---------------------------------------------------

func extentsKey(fileID, startBlock uint32) []byte {
	key := make([]byte, 10)
	put32(key, 2, fileID)
	put32(key, 6, startBlock)
	return key
}

func extentsRecord(extents []extent) []byte {
	record := make([]byte, 64)
	for i, e := range extents {
		put32(record, i*8, e.start)
		put32(record, i*8+4, e.count)
	}
	return record
}

// --- attributes tree records ------------------------------------------------

func attributeKey(fileID, startBlock uint32, name string) []byte {
	units := utf16Units(name)
	key := make([]byte, 0, 12+2*len(units))
	key = append(key, be16(0)...)
	key = append(key, be32(fileID)...)
	key = append(key, be32(startBlock)...)
	key = append(key, be16(uint16(len(units)))...)
	for _, unit := range units {
		key = append(key, be16(unit)...)
	}
	return key
}

func inlineAttribute(value []byte) []byte {
	record := make([]byte, 16+len(value))
	put32(record, 0, 0x10)
	put32(record, 12, uint32(len(value)))
	copy(record[16:], value)
	return record
}

func forkAttribute(fork forkSpec) []byte {
	record := make([]byte, 8+80)
	put32(record, 0, 0x20)
	writeFork(record[8:88], fork)
	return record
}

// --- the image --------------------------------------------------------------

func buildVolume(opts imageOptions) []byte {
	image := make([]byte, testImageLen)
	used := map[uint32]bool{0: true, testAllocBlock: true}
	mark := func(blocks ...uint32) {
		for _, block := range blocks {
			used[block] = true
		}
	}

	// Catalog records, sorted the way the tree's comparator orders them.
	var specs []decmpfsSpec
	if opts.decmpfs {
		specs = decmpfsSpecs(opts)
	}
	records := catalogRecords(opts, specs)
	compare := byte(catalogCompareHFSPlus)
	if opts.caseSensitive {
		compare = catalogCompareHFSX
	}
	sort.SliceStable(records, func(i, j int) bool {
		return compareCatalogKeys(records[i].key, records[j].key, opts.caseSensitive) < 0
	})
	split := len(records) / 2

	headerNode, _ := buildNode(1, 0, 0, 0, [][]byte{
		btreeHeader(2, 1, uint32(len(records)), 2, 3, 4, compare),
		make([]byte, 128),
		nodeMapRecord(4, []uint32{0, 1, 2, 3}),
	})
	indexNode, _ := buildNode(0, 1, 0, 0, [][]byte{
		keyed(records[0].key, be32(2)),
		keyed(records[split].key, be32(3)),
	})
	leafA, _ := buildNode(-1, 1, 3, 0, recordBodies(records[:split]))
	leafB, freeB := buildNode(-1, 1, 0, 2, recordBodies(records[split:]))
	if opts.residue {
		writeResidue(leafB, freeB)
	}
	copy(image[testCatalogStart*testBlock:], headerNode)
	copy(image[(testCatalogStart+1)*testBlock:], indexNode)
	copy(image[testCatalogOverflow*testBlock:], leafA)
	copy(image[(testCatalogOverflow+1)*testBlock:], leafB)
	mark(testCatalogStart, testCatalogStart+1, testCatalogOverflow, testCatalogOverflow+1)

	// Extents-overflow tree: catalog continuation and photo.bin's tail.
	extentsHeader, _ := buildNode(1, 0, 0, 0, [][]byte{
		btreeHeader(1, 1, 2, 1, 1, 2, catalogCompareHFSX),
	})
	extentsLeaf, _ := buildNode(-1, 1, 0, 0, [][]byte{
		keyed(extentsKey(cnidCatalog, 2), extentsRecord([]extent{{testCatalogOverflow, 2}})),
		keyed(extentsKey(cnidPhoto, 8), extentsRecord([]extent{
			{testPhotoFirst + 8*2, 1},
			{testPhotoFirst + 9*2, 1},
		})),
	})
	copy(image[testExtentsStart*testBlock:], extentsHeader)
	copy(image[(testExtentsStart+1)*testBlock:], extentsLeaf)
	mark(testExtentsStart, testExtentsStart+1)

	// Attributes B-tree: inline values, a fork-stored value, and the decmpfs /
	// resource-fork attributes of the compressed fixtures.
	if opts.attributes {
		attributes := attributeRecords(opts, specs)
		attrRecords := make([][]byte, len(attributes))
		for i, attribute := range attributes {
			attrRecords[i] = keyed(attribute.key, attribute.body)
		}
		attrHeader, _ := buildNode(1, 0, 0, 0, [][]byte{
			btreeHeader(1, 1, uint32(len(attributes)), 1, 1, 2, compare),
		})
		attrLeaf, _ := buildNode(-1, 1, 0, 0, attrRecords)
		copy(image[testAttrsStart*testBlock:], attrHeader)
		copy(image[(testAttrsStart+1)*testBlock:], attrLeaf)
		mark(testAttrsStart, testAttrsStart+1)
		if !opts.minimal {
			mark(testAttrFork1, testAttrFork2)
			copy(image[testAttrFork1*testBlock:], attrBigValue)
		}
	}

	// File contents.
	copy(image[testReadmeBlock*testBlock:], readmeData)
	copy(image[testResRsrcBlock*testBlock:], resResource)
	copy(image[testResDataBlock*testBlock:], resData)
	copy(image[testSymBlock*testBlock:], symData)
	copy(image[testMixedBlock*testBlock:], mixedData)
	copy(image[testInodeBlock*testBlock:], inodeData)
	copy(image[testTodoBlock1*testBlock:], todoData[:testBlock])
	copy(image[testTodoBlock2*testBlock:], todoData[testBlock:])
	for i := 0; i < testPhotoCount; i++ {
		block := uint32(testPhotoFirst + i*2)
		copy(image[int(block)*testBlock:], photoData[i*testBlock:(i+1)*testBlock])
		mark(block)
	}
	mark(testReadmeBlock, testRsrcBlock(), testTodoBlock1, testResDataBlock, testTodoBlock2,
		testSymBlock, testMixedBlock, testInodeBlock)

	// Compressed files: a non-empty stub data fork proves OpenFile does not
	// serve the dataless fork, and their resource forks when catalog-stored.
	for _, spec := range specs {
		copy(image[int(spec.dataBlk)*testBlock:], dataForkStub)
		mark(spec.dataBlk)
		if len(spec.rsrc) > 0 {
			copy(image[int(spec.rsrcBlk)*testBlock:], spec.rsrc)
			mark(spec.rsrcBlk)
		}
	}

	if opts.residue {
		copy(image[testResidueBlock*testBlock:], deletedData)
		// block 100 is deliberately left free in the allocation bitmap
	}

	// Allocation file: one bit per block, high bit first, set means used.
	allocation := make([]byte, (testTotalBlocks+7)/8)
	for block := uint32(0); block < testTotalBlocks; block++ {
		if used[block] {
			allocation[block/8] |= 0x80 >> (block % 8)
		}
	}
	copy(image[testAllocBlock*testBlock:], allocation)

	if opts.journal {
		writeJournal(image)
		mark(testJournalInfoBlock)
		for block := uint32(testJournalOffset / testBlock); block < testTotalBlocks; block++ {
			mark(block)
		}
	}

	freeBlocks := uint32(testTotalBlocks - len(used))
	writeVolumeHeader(image, opts, freeBlocks)
	return image
}

func testRsrcBlock() uint32 { return testResRsrcBlock }

func recordBodies(records []catalogRecord) [][]byte {
	out := make([][]byte, len(records))
	for i, record := range records {
		out[i] = keyed(record.key, record.body)
	}
	return out
}

func nodeMapRecord(totalNodes uint32, inUse []uint32) []byte {
	size := int((totalNodes+7)/8+3) / 4 * 4
	bitmap := make([]byte, size)
	for _, number := range inUse {
		if number < totalNodes {
			bitmap[number/8] |= 0x80 >> (number % 8)
		}
	}
	return bitmap
}

// catalogRecords assembles the minimal or full catalog plus any compressed
// fixtures.  A minimal volume keeps only the root and the decmpfs files so the
// two-leaf catalog cannot overflow.
func catalogRecords(opts imageOptions, specs []decmpfsSpec) []catalogRecord {
	if !opts.minimal {
		records := standardCatalogRecords()
		return append(records, decmpfsCatalogRecords(specs)...)
	}
	records := []catalogRecord{
		{key: catalogKey(1, volumeName), body: folderBody(cnidRoot, uint32(len(specs)), 0o40755)},
		{key: catalogKey(cnidRoot, ""), body: threadBody(recordFolderThread, 1, volumeName)},
	}
	return append(records, decmpfsCatalogRecords(specs)...)
}

func decmpfsCatalogRecords(specs []decmpfsSpec) []catalogRecord {
	records := make([]catalogRecord, 0, 2*len(specs))
	for _, spec := range specs {
		resource := forkSpec{}
		if len(spec.rsrc) > 0 {
			resource = forkSpec{
				size:    uint64(len(spec.rsrc)),
				blocks:  1,
				extents: []extent{{spec.rsrcBlk, 1}},
			}
		}
		records = append(records,
			catalogRecord{
				key: catalogKey(cnidRoot, spec.name),
				body: fileBody(spec.cnid, flagThreadExists|flagHasAttrs, 0o100644, 0,
					forkSpec{size: uint64(len(dataForkStub)), blocks: 1, extents: []extent{{spec.dataBlk, 1}}},
					resource),
			},
			catalogRecord{
				key:  catalogKey(spec.cnid, ""),
				body: threadBody(recordFileThread, cnidRoot, spec.name),
			},
		)
	}
	return records
}

func standardCatalogRecords() []catalogRecord {
	empty := forkSpec{}
	data := func(size uint64, blocks uint32, extents ...extent) forkSpec {
		return forkSpec{size: size, blocks: blocks, extents: extents}
	}
	records := []catalogRecord{
		{key: catalogKey(1, volumeName), body: folderBody(cnidRoot, 8, 0o40755)},
		{key: catalogKey(cnidRoot, ""), body: threadBody(recordFolderThread, 1, volumeName)},
		{key: catalogKey(cnidRoot, privateName), body: folderBody(cnidPrivate, 1, 0o40700)},
		{key: catalogKey(cnidRoot, "MiXeD.txt"), body: fileBody(cnidMixed, flagThreadExists, 0o100644, 0,
			data(uint64(len(mixedData)), 1, extent{testMixedBlock, 1}), empty)},
		{key: catalogKey(cnidRoot, "Notes"), body: folderBody(cnidNotes, 1, 0o40755)},
		{key: catalogKey(cnidRoot, "link.txt"), body: fileBody(cnidLink, flagThreadExists|flagLinkChain, 0o100644, cnidInode, empty, empty)},
		{key: catalogKey(cnidRoot, "photo.bin"), body: fileBody(cnidPhoto, flagThreadExists, 0o100644, 0,
			data(uint64(len(photoData)), testPhotoCount,
				extent{testPhotoFirst, 1}, extent{testPhotoFirst + 2, 1}, extent{testPhotoFirst + 4, 1},
				extent{testPhotoFirst + 6, 1}, extent{testPhotoFirst + 8, 1}, extent{testPhotoFirst + 10, 1},
				extent{testPhotoFirst + 12, 1}, extent{testPhotoFirst + 14, 1}), empty)},
		{key: catalogKey(cnidRoot, "readme.txt"), body: fileBody(cnidReadme, flagThreadExists, 0o100644, 0,
			data(uint64(len(readmeData)), 1, extent{testReadmeBlock, 1}), empty)},
		{key: catalogKey(cnidRoot, "res.txt"), body: fileBody(cnidRes, flagThreadExists|flagHasAttrs, 0o100644, 0,
			data(uint64(len(resData)), 1, extent{testResDataBlock, 1}),
			data(uint64(len(resResource)), 1, extent{testResRsrcBlock, 1}))},
		{key: catalogKey(cnidRoot, "sym.txt"), body: fileBody(cnidSym, flagThreadExists, 0o120777, 0,
			data(uint64(len(symData)), 1, extent{testSymBlock, 1}), empty)},
		{key: catalogKey(cnidReadme, ""), body: threadBody(recordFileThread, cnidRoot, "readme.txt")},
		{key: catalogKey(cnidNotes, ""), body: threadBody(recordFolderThread, cnidRoot, "Notes")},
		{key: catalogKey(cnidNotes, "todo.txt"), body: fileBody(cnidTodo, flagThreadExists, 0o100644, 0,
			data(uint64(len(todoData)), 2, extent{testTodoBlock1, 1}, extent{testTodoBlock2, 1}), empty)},
		{key: catalogKey(cnidTodo, ""), body: threadBody(recordFileThread, cnidNotes, "todo.txt")},
		{key: catalogKey(cnidPhoto, ""), body: threadBody(recordFileThread, cnidRoot, "photo.bin")},
		{key: catalogKey(cnidLink, ""), body: threadBody(recordFileThread, cnidRoot, "link.txt")},
		{key: catalogKey(cnidInode, ""), body: threadBody(recordFileThread, cnidPrivate, "iNode21")},
		{key: catalogKey(cnidPrivate, ""), body: threadBody(recordFolderThread, cnidRoot, privateName)},
		{key: catalogKey(cnidPrivate, "iNode21"), body: fileBody(cnidInode, flagThreadExists, 0o100600, 0,
			data(uint64(len(inodeData)), 1, extent{testInodeBlock, 1}), empty)},
		{key: catalogKey(cnidRes, ""), body: threadBody(recordFileThread, cnidRoot, "res.txt")},
		{key: catalogKey(cnidSym, ""), body: threadBody(recordFileThread, cnidRoot, "sym.txt")},
		{key: catalogKey(cnidMixed, ""), body: threadBody(recordFileThread, cnidRoot, "MiXeD.txt")},
	}
	return records
}

type attributeRecord struct {
	key  []byte
	body []byte
}

// attributeRecords emits the base attributes plus every compressed fixture's
// decmpfs marker and, when used, its com.apple.ResourceFork value.
func attributeRecords(opts imageOptions, specs []decmpfsSpec) []attributeRecord {
	var records []attributeRecord
	if !opts.minimal {
		records = append(records,
			attributeRecord{
				key: attributeKey(cnidReadme, 0, "user.big"),
				body: forkAttribute(forkSpec{
					size:    uint64(len(attrBigValue)),
					blocks:  2,
					extents: []extent{{testAttrFork1, 2}},
				}),
			},
			attributeRecord{key: attributeKey(cnidReadme, 0, "user.test"), body: inlineAttribute(attrSmallValue)},
			attributeRecord{key: attributeKey(cnidRes, 0, "user.data"), body: inlineAttribute(resData)},
		)
	}
	for _, spec := range specs {
		records = append(records, attributeRecord{
			key:  attributeKey(spec.cnid, 0, decmpfsAttrName),
			body: inlineAttribute(spec.attr),
		})
		if len(spec.rsrcXat) > 0 {
			records = append(records, attributeRecord{
				key:  attributeKey(spec.cnid, 0, resourceForkAttrName),
				body: inlineAttribute(spec.rsrcXat),
			})
		}
	}
	sort.SliceStable(records, func(i, j int) bool {
		af, as, an := decodeAttributeKey(records[i].key)
		bf, bs, bn := decodeAttributeKey(records[j].key)
		if af != bf {
			return af < bf
		}
		if as != bs {
			return as < bs
		}
		return compareUnits(an, bn, false) < 0
	})
	return records
}

func decodeAttributeKey(key []byte) (uint32, uint32, []uint16) {
	fileID := binary.BigEndian.Uint32(key[2:6])
	start := binary.BigEndian.Uint32(key[6:10])
	n := int(binary.BigEndian.Uint16(key[10:12]))
	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = binary.BigEndian.Uint16(key[12+2*i:])
	}
	return fileID, start, units
}

// writeResidue writes stale catalog records into a leaf's unused space.
func writeResidue(node []byte, free int) {
	empty := forkSpec{}
	stale := [][]byte{
		keyed(catalogKey(cnidNotes, "deleted.bin"), fileBody(cnidDeleted, flagThreadExists, 0o100644, 0,
			forkSpec{size: testBlock, blocks: 1, extents: []extent{{testResidueBlock, 1}}}, empty)),
		keyed(catalogKey(cnidDeleted, ""), threadBody(recordFileThread, cnidNotes, "deleted.bin")),
		keyed(catalogKey(cnidRoot, "readme.txt"), fileBody(cnidReadme, flagThreadExists, 0o100644, 0,
			forkSpec{size: uint64(len(readmeData)), blocks: 1, extents: []extent{{testReadmeBlock, 1}}}, empty)),
	}
	table := len(node) - 2*(int(binary.BigEndian.Uint16(node[10:12]))+1)
	pos := free
	for _, record := range stale {
		if pos+len(record) > table {
			panic("test residue overflows the node")
		}
		copy(node[pos:], record)
		pos += len(record)
	}
}

func writeVolumeHeader(image []byte, opts imageOptions, freeBlocks uint32) {
	header := image[testHeaderAt : testHeaderAt+512]
	for i := range header {
		header[i] = 0
	}
	signature, version := uint16(0x482B), uint16(4)
	if opts.caseSensitive {
		signature, version = 0x4858, 5
	}
	put16(header, 0, signature)
	put16(header, 2, version)
	attributes := uint32(0)
	if opts.journal {
		attributes = 0x0000_2000
		put32(header, 12, testJournalInfoBlock)
	}
	put32(header, 4, attributes)
	put32(header, 16, 3_786_912_000)
	put32(header, 20, 3_786_912_600)
	put32(header, 24, 3_786_912_000)
	put32(header, 28, 3_786_912_600)
	put32(header, 32, 7)
	put32(header, 36, 4)
	put32(header, 40, testBlock)
	put32(header, 44, testTotalBlocks)
	put32(header, 48, freeBlocks)
	put32(header, 64, cnidNextCNID)
	put32(header, 68, 4)
	if opts.uuidID != 0 {
		put32(header, 104, uint32(opts.uuidID>>32))
		put32(header, 108, uint32(opts.uuidID))
	}
	writeFork(header[112:192], forkSpec{size: (testTotalBlocks + 7) / 8, blocks: 1, extents: []extent{{testAllocBlock, 1}}})
	writeFork(header[192:272], forkSpec{size: 2 * testBlock, blocks: 2, extents: []extent{{testExtentsStart, 2}}})
	writeFork(header[272:352], forkSpec{size: 4 * testBlock, blocks: 4, extents: []extent{{testCatalogStart, 2}}})
	if opts.attributes {
		writeFork(header[352:432], forkSpec{size: 2 * testBlock, blocks: 2, extents: []extent{{testAttrsStart, 2}}})
	}
	writeFork(header[432:512], forkSpec{})
}

// --- journal ----------------------------------------------------------------

func writeJournal(image []byte) {
	jib := testJournalInfoBlock * testBlock
	for i := 0; i < 512; i++ {
		image[jib+i] = 0
	}
	put32(image, jib, 0x0000_0001) // JI_IN_FS
	put64(image, jib+36, testJournalOffset)
	put64(image, jib+44, testJournalSize)

	base := testJournalOffset
	for i := 0; i < testJournalSize; i++ {
		image[base+i] = 0
	}

	payload := make([]byte, testJournalSector)
	copy(payload, []byte("journal write\n"))

	headerAt := base + testJournalStart
	dataAt := headerAt + testJournalBlhdr
	copy(image[dataAt:], payload)

	put16(image, headerAt, 255) // max blocks
	put16(image, headerAt+2, 2) // control + one data block
	bytesUsed := uint64(testJournalBlhdr + testJournalSector)
	put32(image, headerAt+4, uint32(bytesUsed))
	put32(image, headerAt+12, 0x0000_0001) // check checksums
	destSector := uint64(testReadmeBlock) * (testBlock / testJournalSector)
	put64(image, headerAt+32, destSector)
	put32(image, headerAt+40, testJournalSector)
	put32(image, headerAt+44, journalChecksum(payload))
	put32(image, headerAt+8, verifyJournalChecksum(image[headerAt:headerAt+32], 8))

	put32(image, base, 0x4A4E_4C78) // JNLx
	put32(image, base+4, 0x1234_5678)
	put64(image, base+8, testJournalStart)
	put64(image, base+16, testJournalStart+bytesUsed)
	put64(image, base+24, testJournalSize)
	put32(image, base+32, testJournalBlhdr)
	put32(image, base+40, testJournalSector)
	put32(image, base+36, verifyJournalChecksum(image[base:base+44], 36))
}

func journalChecksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum = (sum << 8) ^ (sum + uint32(b))
	}
	return ^sum
}

func verifyJournalChecksum(data []byte, fieldAt int) uint32 {
	copyData := append([]byte(nil), data...)
	for i := fieldAt; i < fieldAt+4; i++ {
		copyData[i] = 0
	}
	return journalChecksum(copyData)
}
