package zfs

// Hermetic ZFS image builder used by the tests. It writes every structure the
// reader parses — labels, nvlist, uberblock, MOS, dnode arrays, ZAPs, SA
// tables, datasets and file blocks — into one in-memory image. No fixture
// outside this repository is read.

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

const testImageSize = 8 << 20

var le = binary.LittleEndian

func alignUp(value, align uint64) uint64 {
	if align == 0 {
		return value
	}
	if rem := value % align; rem != 0 {
		value += align - rem
	}
	return value
}

type testImage struct {
	data []byte
	next uint64
}

func newTestImage() *testImage {
	return &testImage{data: make([]byte, testImageSize), next: VDevLabelStartSize}
}

func (t *testImage) alloc(raw []byte) uint64 {
	size := alignUp(uint64(len(raw)), 512)
	at := t.next
	if at+size > testImageSize-VDevLabelEndSize {
		panic("test image exhausted")
	}
	copy(t.data[at:at+uint64(len(raw))], raw)
	t.next = at + size
	return at
}

func (t *testImage) clone() *testImage {
	return &testImage{data: append([]byte(nil), t.data...), next: t.next}
}

// --- block pointers ------------------------------------------------------

func fletcherChecksumBytes(stored []byte, id byte) []byte {
	out := make([]byte, 32)
	switch id {
	case 2: // off
		return out
	case 6:
		words := fletcher2(stored)
		for i, word := range words {
			le.PutUint64(out[i*8:], word)
		}
	case 7, 0, 1, 9:
		words := fletcher4(stored)
		for i, word := range words {
			le.PutUint64(out[i*8:], word)
		}
	case 8:
		digest := sha256.Sum256(stored)
		copy(out, digest[:])
		for i := 0; i < 32; i += 8 {
			reverse8(out[i : i+8])
		}
	default:
		for i := range out {
			out[i] = byte(i + 1)
		}
	}
	return out
}

func reverse8(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// diskPointer builds a non-embedded pointer. When override is non-nil it is
// used as the stored checksum instead of one computed from stored.
func diskPointer(t *testImage, phys, lsize, psize uint64, kind, level, cksum, comp byte, birth uint64, override []byte) []byte {
	if psize == 0 || psize%512 != 0 || lsize == 0 || lsize%512 != 0 {
		panic("test disk pointers use 512-byte sizes")
	}
	bp := make([]byte, 128)
	le.PutUint64(bp[0:], (psize>>9)|(uint64(0)<<32))
	le.PutUint64(bp[8:], (phys-VDevLabelStartSize)>>9)
	prop := (lsize>>9 - 1) |
		((psize>>9 - 1) << 16) |
		(uint64(comp) << 32) |
		(uint64(cksum) << 40) |
		(uint64(kind) << 48) |
		(uint64(level) << 56)
	le.PutUint64(bp[48:], prop)
	le.PutUint64(bp[80:], birth)
	stored := t.data[phys : phys+psize]
	sum := override
	if sum == nil {
		sum = fletcherChecksumBytes(stored, cksum)
	}
	copy(bp[96:], sum)
	return bp
}

// embeddedPointer writes a non-compressed embedded pointer.
func embeddedPointer(payload []byte, lsize, psize uint64, kind, comp byte, birth uint64) []byte {
	if len(payload) > 112 || psize > 112 {
		panic("an embedded payload is at most 112 bytes")
	}
	bp := make([]byte, 128)
	copy(bp[0:48], payload[:minInt(len(payload), 48)])
	if len(payload) > 48 {
		copy(bp[56:80], payload[48:minInt(len(payload), 72)])
	}
	if len(payload) > 72 {
		copy(bp[88:], payload[72:])
	}
	prop := (uint64(1) << 39) |
		(lsize - 1) |
		((psize - 1) << 25) |
		(uint64(comp) << 32) |
		(uint64(kind) << 48)
	le.PutUint64(bp[48:], prop)
	le.PutUint64(bp[80:], birth)
	return bp
}

func holePointer(birth uint64) []byte {
	bp := make([]byte, 128)
	le.PutUint64(bp[80:], birth)
	return bp
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- dnodes and objects ---------------------------------------------------

type dnodeSpec struct {
	kind         byte
	indblkshift  byte
	nlevels      byte
	bonustype    byte
	checksum     byte
	compress     byte
	flags        byte
	datablkszsec uint16
	maxblkid     uint64
	used         uint64
	extraSlots   byte
	pointers     [][]byte
	bonus        []byte
	spill        []byte
}

func buildDnode(spec dnodeSpec) []byte {
	slots := int(spec.extraSlots) + 1
	out := make([]byte, slots*512)
	out[0] = spec.kind
	out[1] = spec.indblkshift
	out[2] = spec.nlevels
	out[3] = byte(len(spec.pointers))
	out[4] = spec.bonustype
	out[5] = spec.checksum
	out[6] = spec.compress
	out[7] = spec.flags
	le.PutUint16(out[8:], spec.datablkszsec)
	le.PutUint16(out[10:], uint16(len(spec.bonus)))
	out[12] = spec.extraSlots
	le.PutUint64(out[16:], spec.maxblkid)
	le.PutUint64(out[24:], spec.used)
	for i, pointer := range spec.pointers {
		copy(out[64+i*128:], pointer)
	}
	bonusStart := 64 + len(spec.pointers)*128
	copy(out[bonusStart:], spec.bonus)
	if spec.spill != nil {
		copy(out[len(out)-128:], spec.spill)
	}
	return out
}

type microEntry struct {
	name  string
	value []byte
}

func buildMicroZAP(entries []microEntry) []byte {
	block := make([]byte, 512)
	le.PutUint64(block[0:], zapZBTMicro)
	if len(entries) > 7 {
		panic("a 512-byte micro ZAP holds seven entries")
	}
	for i, entry := range entries {
		at := 64 + i*64
		copy(block[at:at+minInt(len(entry.value), 8)], entry.value)
		copy(block[at+14:at+14+len(entry.name)], entry.name)
	}
	return block
}

func (t *testImage) microZAPDnode(kind byte, entries []microEntry) []byte {
	data := buildMicroZAP(entries)
	phys := t.alloc(data)
	pointer := diskPointer(t, phys, 512, 512, kind, 0, 7, 2, 0, nil)
	return buildDnode(dnodeSpec{
		kind:         kind,
		indblkshift:  14,
		nlevels:      1,
		datablkszsec: 1,
		pointers:     [][]byte{pointer},
	})
}

// fatEntry is one name/value pair in a fat ZAP. integerLen > 1 stores the
// value as big-endian integers of that width, exactly as OpenZFS does.
type fatEntry struct {
	name       string
	value      []byte
	integerLen int
}

func buildFatZAP(entries []fatEntry) []byte {
	const blockSize = 2048
	header := make([]byte, blockSize)
	le.PutUint64(header[0:], zapZBTHeader)
	le.PutUint64(header[8:], zapMagic)
	le.PutUint64(header[32:], 5)          // 32 embedded pointer-table slots
	le.PutUint64(header[blockSize/2:], 1) // leaf lives in object block 1
	leaf := make([]byte, blockSize)
	le.PutUint64(leaf[0:], zapZBTLeaf)
	le.PutUint32(leaf[24:], zapLeafMagic)

	hashEntries := blockSize / 32
	chunksStart := 48 + 2*hashEntries
	chunks := (blockSize-2*hashEntries)/leafChunkSize - 2
	nextChunk := 0
	allocChunk := func() int {
		if nextChunk >= chunks {
			panic("fat ZAP test block exhausted")
		}
		index := nextChunk
		nextChunk++
		return index
	}
	chunkAt := func(index int) []byte {
		start := chunksStart + index*leafChunkSize
		return leaf[start : start+leafChunkSize]
	}
	writeChain := func(data []byte) int {
		if len(data) == 0 {
			return 0
		}
		first := allocChunk()
		current := first
		position := 0
		for {
			chunk := chunkAt(current)
			chunk[0] = chunkArray
			n := copy(chunk[1:1+leafArrayBytes], data[position:])
			position += n
			if position >= len(data) {
				le.PutUint16(chunk[22:], chainEnd)
				break
			}
			next := allocChunk()
			le.PutUint16(chunk[22:], uint16(next))
			current = next
		}
		return first
	}
	// OpenZFS stores array integers most-significant byte first.
	encodeValue := func(value []byte, width int) []byte {
		if width <= 1 {
			return append([]byte(nil), value...)
		}
		out := append([]byte(nil), value...)
		for at := 0; at+width <= len(out); at += width {
			for i, j := at, at+width-1; i < j; i, j = i+1, j-1 {
				out[i], out[j] = out[j], out[i]
			}
		}
		return out
	}
	for _, entry := range entries {
		name := append([]byte(entry.name), 0)
		value := encodeValue(entry.value, entry.integerLen)
		entryChunk := allocChunk()
		nameChunk := writeChain(name)
		valueChunk := writeChain(value)
		chunk := chunkAt(entryChunk)
		chunk[0] = chunkEntry
		chunk[1] = byte(entry.integerLen)
		le.PutUint16(chunk[4:], uint16(nameChunk))
		le.PutUint16(chunk[6:], uint16(len(name)))
		le.PutUint16(chunk[8:], uint16(valueChunk))
		le.PutUint16(chunk[10:], uint16(len(value)/maxInt(1, entry.integerLen)))
	}
	return append(header, leaf...)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (t *testImage) fatZAPDnode(kind byte, entries []fatEntry) []byte {
	return t.fatZAPDnodeWithBonus(kind, 0, entries, nil)
}

func (t *testImage) fatZAPDnodeWithBonus(kind, bonusType byte, entries []fatEntry, bonus []byte) []byte {
	data := buildFatZAP(entries)
	headerPhys := t.alloc(data[:2048])
	leafPhys := t.alloc(data[2048:])
	first := diskPointer(t, headerPhys, 2048, 2048, kind, 0, 7, 2, 0, nil)
	second := diskPointer(t, leafPhys, 2048, 2048, kind, 0, 7, 2, 0, nil)
	return buildDnode(dnodeSpec{
		kind:         kind,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    bonusType,
		datablkszsec: 4,
		maxblkid:     1,
		pointers:     [][]byte{first, second},
		bonus:        bonus,
	})
}

// addObjset writes an object set whose dnode array is a single 16 KiB block,
// returning the block pointer a MOS dataset (or the uberblock) names.
func (t *testImage) addObjset(objects map[uint64][]byte, osType, birth uint64) []byte {
	const arraySize = 16384
	array := make([]byte, arraySize)
	highest := uint64(0)
	for object, record := range objects {
		at := object * 512
		if at+512 > arraySize {
			panic("test object set needs a larger dnode array")
		}
		copy(array[at:at+512], record)
		if object > highest {
			highest = object
		}
	}
	_ = highest
	arrayPhys := t.alloc(array)
	metaPointer := diskPointer(t, arrayPhys, arraySize, arraySize, dmuOtDnode, 0, 7, 2, birth, nil)
	meta := buildDnode(dnodeSpec{
		kind:         dmuOtDnode,
		indblkshift:  14,
		nlevels:      1,
		datablkszsec: arraySize / 512,
		pointers:     [][]byte{metaPointer},
	})
	objset := make([]byte, 2048)
	copy(objset[:512], meta)
	le.PutUint64(objset[osTypeOffset:], osType)
	osPhys := t.alloc(objset)
	return diskPointer(t, osPhys, 2048, 2048, dmuOtObjset, 0, 7, 2, birth, nil)
}

// --- SA tables ------------------------------------------------------------

type saAttrSpec struct {
	id     uint16
	name   string
	length uint16
}

var testSA = []saAttrSpec{
	{1, "ZPL_MODE", 8},
	{2, "ZPL_SIZE", 8},
	{3, "ZPL_UID", 8},
	{4, "ZPL_GID", 8},
	{5, "ZPL_LINKS", 8},
	{6, "ZPL_ATIME", 16},
	{7, "ZPL_MTIME", 16},
	{8, "ZPL_CTIME", 16},
	{9, "ZPL_CRTIME", 16},
	{10, "ZPL_GEN", 8},
	{11, "ZPL_PARENT", 8},
	{12, "ZPL_SYMLINK", 0},
	{13, "ZPL_FLAGS", 8},
	{14, "ZPL_RDEV", 8},
}

func saSpec(id uint16) saAttrSpec {
	for _, attribute := range testSA {
		if attribute.id == id {
			return attribute
		}
	}
	panic("unknown test SA attribute")
}

func leU16(value uint16) []byte {
	out := make([]byte, 2)
	le.PutUint16(out, value)
	return out
}

func leU64(value uint64) []byte {
	out := make([]byte, 8)
	le.PutUint64(out, value)
	return out
}

func testTime(seconds, nanos uint64) []byte {
	out := make([]byte, 16)
	le.PutUint64(out[0:], seconds)
	le.PutUint64(out[8:], nanos)
	return out
}

func buildSABuffer(layout uint16, ids []uint16, values map[uint16][]byte) []byte {
	variable := 0
	for _, id := range ids {
		if saSpec(id).length == 0 {
			variable++
		}
	}
	header := alignUp(uint64(6+2*variable), 8)
	buffer := make([]byte, header)
	le.PutUint32(buffer[0:], saMagic)
	info := layout | uint16((header/8)<<10)
	le.PutUint16(buffer[4:], info)
	cursor := uint64(header)
	variableIndex := 0
	for _, id := range ids {
		value := values[id]
		registered := saSpec(id)
		if registered.length == 0 {
			le.PutUint16(buffer[6+2*variableIndex:], uint16(len(value)))
			variableIndex++
		} else if uint16(len(value)) != registered.length {
			panic("test SA value length disagrees with its registration")
		}
		end := cursor + uint64(len(value))
		if end > uint64(len(buffer)) {
			buffer = append(buffer, make([]byte, end-uint64(len(buffer)))...)
		}
		copy(buffer[cursor:end], value)
		cursor = alignUp(end, 8)
	}
	if uint64(len(buffer)) < cursor {
		buffer = append(buffer, make([]byte, cursor-uint64(len(buffer)))...)
	}
	return buffer
}

func layoutBytes(ids []uint16) []byte {
	out := make([]byte, 0, len(ids)*2)
	for _, id := range ids {
		out = append(out, leU16(id)...)
	}
	return out
}

var saLayout2 = []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13}
var saLayout3 = []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 12}

func defaultSAValues(mode uint64, size uint64) map[uint16][]byte {
	return map[uint16][]byte{
		1:  leU64(mode),
		2:  leU64(size),
		3:  leU64(1000),
		4:  leU64(1000),
		5:  leU64(1),
		6:  testTime(1_700_000_000, 123),
		7:  testTime(1_700_000_100, 0),
		8:  testTime(1_700_000_200, 0),
		9:  testTime(1_700_000_300, 0),
		10: leU64(5),
		11: leU64(2),
		13: leU64(0),
	}
}

const (
	testModeRegular = uint64(0o100644)
	testModeDir     = uint64(0o040755)
	testModeSymlink = uint64(0o120777)
)

// --- higher level builders ------------------------------------------------

func (t *testImage) fileDnode(mode, size uint64, bonus []byte, pointers ...[]byte) []byte {
	return buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtSA,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		maxblkid:     uint64(maxInt(0, len(pointers)-1)),
		used:         size,
		pointers:     pointers,
		bonus:        bonus,
	})
}

func (t *testImage) regularFile(object uint64, content []byte, values map[uint16][]byte) []byte {
	payload := make([]byte, alignUp(uint64(len(content)), 512))
	copy(payload, content)
	phys := t.alloc(payload)
	pointer := diskPointer(t, phys, uint64(len(payload)), uint64(len(payload)), dmuOtPlainFile, 0, 7, 2, 41, nil)
	bonus := buildSABuffer(2, saLayout2, values)
	return t.fileDnode(testModeRegular, uint64(len(content)), bonus, pointer)
}

func (t *testImage) compressedFile(object uint64, content, stored []byte, comp byte) []byte {
	_ = object
	padded := make([]byte, alignUp(uint64(len(stored)), 512))
	copy(padded, stored)
	phys := t.alloc(padded)
	pointer := diskPointer(t, phys, 512, uint64(len(padded)), dmuOtPlainFile, 0, 7, comp, 41, nil)
	bonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 512))
	_ = content
	return t.fileDnode(testModeRegular, 512, bonus, pointer)
}

func zlibBytes(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write(content); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// lzjbLiterals encodes data as a literal-only LZJB stream.
func lzjbLiterals(data []byte) []byte {
	var out []byte
	for at := 0; at < len(data); at += 8 {
		out = append(out, 0)
		end := at + 8
		if end > len(data) {
			end = len(data)
		}
		out = append(out, data[at:end]...)
	}
	return out
}

func lz4Literals(data []byte) []byte {
	var body []byte
	length := len(data)
	if length < 15 {
		body = append(body, byte(length<<4))
	} else {
		body = append(body, 0xf0)
		remaining := length - 15
		for remaining >= 255 {
			body = append(body, 255)
			remaining -= 255
		}
		body = append(body, byte(remaining))
	}
	body = append(body, data...)
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}

func (t *testImage) buildNestedObjset(master, root, file uint64, fileName, content string, birth uint64) []byte {
	objects := map[uint64][]byte{}
	objects[master] = t.microZAPDnode(1, []microEntry{
		{"ROOT", leU64(root)},
	})
	objects[root] = t.microZAPDnode(dmuOtDirectoryContents, []microEntry{
		{fileName, leU64(uint64(zplDirentTypeRegular)<<direntTypeShift | file)},
	})
	legacy := make([]byte, legacyZnodeSize)
	le.PutUint64(legacy[72:], testModeRegular)
	le.PutUint64(legacy[80:], uint64(len(content)))
	le.PutUint64(legacy[96:], 1)
	le.PutUint64(legacy[128:], 1000)
	le.PutUint64(legacy[136:], 1000)
	payload := []byte(content)
	pointer := embeddedPointer(payload, uint64(len(payload)), uint64(len(payload)), dmuOtPlainFile, 2, birth)
	objects[file] = buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtZnode,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers:     [][]byte{pointer},
		bonus:        legacy,
	})
	return t.addObjset(objects, objsetTypeZFS, birth)
}

func dslDirBonus(head, parent, child, props uint64) []byte {
	bonus := make([]byte, 88)
	le.PutUint64(bonus[8:], head)
	le.PutUint64(bonus[16:], parent)
	le.PutUint64(bonus[32:], child)
	le.PutUint64(bonus[80:], props)
	return bonus
}

func datasetBonus(dirObj, numChildren, creationTime, creationTxg, snapnames, referenced, compressed, uncompressed, guid uint64, bp []byte) []byte {
	bonus := make([]byte, 256)
	le.PutUint64(bonus[0:], dirObj)
	le.PutUint64(bonus[40:], numChildren)
	le.PutUint64(bonus[48:], creationTime)
	le.PutUint64(bonus[56:], creationTxg)
	le.PutUint64(bonus[32:], snapnames)
	le.PutUint64(bonus[72:], referenced)
	le.PutUint64(bonus[80:], compressed)
	le.PutUint64(bonus[88:], uncompressed)
	le.PutUint64(bonus[112:], guid)
	copy(bonus[128:], bp)
	return bonus
}

func (t *testImage) metadataDnode(kind, bonusType byte, bonus []byte) []byte {
	spare := make([]byte, 512)
	phys := t.alloc(spare)
	pointer := diskPointer(t, phys, 512, 512, kind, 0, 7, 2, 0, nil)
	return buildDnode(dnodeSpec{
		kind:         kind,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    bonusType,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers:     [][]byte{pointer},
		bonus:        bonus,
	})
}

// buildTestImage assembles one complete pool with two datasets and two
// snapshots sharing a short name, so every structural branch has a subject.
func buildTestImage(t *testing.T) *testImage {
	t.Helper()
	img := newTestImage()

	// Root dataset object set contents.
	rootObjects := map[uint64][]byte{}

	// SA layout and registry maps, plus the SA master and dataset master.
	layoutZAP := []fatEntry{
		{"2", layoutBytes(saLayout2), 2},
		{"3", layoutBytes(saLayout3), 2},
	}
	registryZAP := make([]fatEntry, 0, len(testSA))
	for _, attribute := range testSA {
		registryZAP = append(registryZAP, fatEntry{
			name:       attribute.name,
			value:      leU64(uint64(attribute.id) | (uint64(attribute.length) << 24)),
			integerLen: 8,
		})
	}
	rootObjects[4] = img.fatZAPDnode(27, layoutZAP)
	rootObjects[5] = img.fatZAPDnode(27, registryZAP)
	rootObjects[3] = img.microZAPDnode(1, []microEntry{
		{"LAYOUTS", leU64(4)},
		{"REGISTRY", leU64(5)},
	})

	// Root directory entries.
	dirValues := func(object uint64, dtype DType) []byte {
		return leU64(object | uint64(dtype)<<direntTypeShift)
	}
	rootEntries := []fatEntry{
		{"hello.txt", dirValues(10, zplDirentTypeRegular), 8},
		{"sub", dirValues(11, zplDirentTypeDirectory), 8},
		{"link", dirValues(12, zplDirentTypeSymlink), 8},
		{"holey", dirValues(13, zplDirentTypeRegular), 8},
		{"empty", dirValues(14, zplDirentTypeRegular), 8},
		{"lzjb", dirValues(15, zplDirentTypeRegular), 8},
		{"zle", dirValues(16, zplDirentTypeRegular), 8},
		{"lz4", dirValues(17, zplDirentTypeRegular), 8},
		{"gzip", dirValues(18, zplDirentTypeRegular), 8},
		{"zstd", dirValues(19, zplDirentTypeRegular), 8},
		{"plain", dirValues(20, zplDirentTypeRegular), 8},
		{"sha", dirValues(21, zplDirentTypeRegular), 8},
		{"f2", dirValues(22, zplDirentTypeRegular), 8},
		{"indirect", dirValues(23, zplDirentTypeRegular), 8},
		{"gang", dirValues(24, zplDirentTypeRegular), 8},
		{"badck", dirValues(25, zplDirentTypeRegular), 8},
		{"badcompress", dirValues(26, zplDirentTypeRegular), 8},
		{"unknownck", dirValues(27, zplDirentTypeRegular), 8},
		{"nosize", dirValues(29, zplDirentTypeRegular), 8},
		{"badbonus", dirValues(30, zplDirentTypeRegular), 8},
		{"self", dirValues(2, zplDirentTypeDirectory), 8},
	}
	rootDirBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeDir, 512))
	rootObjects[2] = img.fatZAPDnodeWithBonus(dmuOtDirectoryContents, dmuOtSA, rootEntries, rootDirBonus)
	rootObjects[1] = img.microZAPDnode(1, []microEntry{
		{"ROOT", leU64(2)},
		{"SA_ATTRS", leU64(3)},
	})

	// An embedded regular file.
	helloBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 11))
	rootObjects[10] = img.fileDnode(testModeRegular, 11, helloBonus,
		embeddedPointer([]byte("hello world"), 11, 11, dmuOtPlainFile, 2, 41))

	// A nested directory with one embedded file.
	subEntries := []microEntry{
		{"nested.txt", dirValues(28, zplDirentTypeRegular)},
	}
	subBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeDir, 512))
	subData := buildMicroZAP(subEntries)
	subPhys := img.alloc(subData)
	subPointer := diskPointer(img, subPhys, 512, 512, dmuOtDirectoryContents, 0, 7, 2, 41, nil)
	rootObjects[11] = buildDnode(dnodeSpec{
		kind:         dmuOtDirectoryContents,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtSA,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers:     [][]byte{subPointer},
		bonus:        subBonus,
	})
	nestedBonus := buildSABuffer(2, saLayout2, defaultSAValues(0o100600, 12))
	rootObjects[28] = img.fileDnode(0o100600, 12, nestedBonus,
		embeddedPointer([]byte("nested bytes"), 12, 12, dmuOtPlainFile, 2, 41))

	// Symbolic link.
	linkTarget := []byte("/hello.txt")
	linkValues := defaultSAValues(testModeSymlink, uint64(len(linkTarget)))
	linkValues[12] = linkTarget
	linkBonus := buildSABuffer(3, saLayout3, linkValues)
	rootObjects[12] = img.fileDnode(testModeSymlink, uint64(len(linkTarget)), linkBonus,
		holePointer(41))

	// A file with an embedded block, a hole and another embedded block.
	holeySize := uint64(2*512 + 5)
	holeyBonus := buildSABuffer(5, []uint16{1, 2}, map[uint16][]byte{
		1: leU64(testModeRegular),
		2: leU64(holeySize),
	})
	rootObjects[13] = img.fileDnode(testModeRegular, holeySize, holeyBonus,
		embeddedPointer([]byte("first"), 5, 5, dmuOtPlainFile, 2, 41),
		holePointer(41),
		embeddedPointer([]byte("third"), 5, 5, dmuOtPlainFile, 2, 41))

	// Zero-length file.
	emptyBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 0))
	rootObjects[14] = img.fileDnode(testModeRegular, 0, emptyBonus, holePointer(41))

	// LZJB: a literal-only stream covering 512 logical bytes.
	lzjbContent := make([]byte, 512)
	copy(lzjbContent, "lzjb content")
	rootObjects[15] = img.compressedFile(15, lzjbContent, lzjbLiterals(lzjbContent), 3)

	// ZLE: four literals then zero runs to 512.
	zleStored := []byte{3, 'Z', 'L', 'E', '!', 0xff, 0xff, 64 + 124 - 1}
	rootObjects[16] = img.compressedFile(16, nil, zleStored, 14)

	// LZ4: a literal-only raw block.
	lz4Content := bytes.Repeat([]byte{'A'}, 512)
	rootObjects[17] = img.compressedFile(17, lz4Content, lz4Literals(lz4Content), 15)

	// gzip: an RFC 1950 stream.
	gzipContent := make([]byte, 512)
	copy(gzipContent, "gzip content")
	rootObjects[18] = img.compressedFile(18, gzipContent, zlibBytes(t, gzipContent), 5)

	// zstd: a valid checksum over bytes this reader refuses to decode.
	zstdStored := append([]byte("not zstd"), make([]byte, 504)...)
	rootObjects[19] = img.compressedFile(19, nil, zstdStored, 16)

	// plain (fletcher4), sha256 and fletcher2 blocks.
	plainContent := make([]byte, 512)
	copy(plainContent, "plain fletcher4")
	plainBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 512))
	plainPhys := img.alloc(plainContent)
	rootObjects[20] = img.fileDnode(testModeRegular, 512, plainBonus,
		diskPointer(img, plainPhys, 512, 512, dmuOtPlainFile, 0, 7, 2, 41, nil))

	shaContent := make([]byte, 512)
	copy(shaContent, "sha256 checked")
	shaBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 512))
	shaPhys := img.alloc(shaContent)
	rootObjects[21] = img.fileDnode(testModeRegular, 512, shaBonus,
		diskPointer(img, shaPhys, 512, 512, dmuOtPlainFile, 0, 8, 2, 41, nil))

	f2Content := make([]byte, 512)
	copy(f2Content, "fletcher2")
	f2Bonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 512))
	f2Phys := img.alloc(f2Content)
	rootObjects[22] = img.fileDnode(testModeRegular, 512, f2Bonus,
		diskPointer(img, f2Phys, 512, 512, dmuOtPlainFile, 0, 6, 2, 41, nil))

	// An indirect tree: 1 KiB indirect block, 512-byte data blocks.
	indirectBlock := make([]byte, 1024)
	for index, text := range []string{"block0", "block1", "block2"} {
		pointer := embeddedPointer([]byte(text), uint64(len(text)), uint64(len(text)), dmuOtPlainFile, 2, 41)
		copy(indirectBlock[index*128:], pointer)
	}
	indirectPhys := img.alloc(indirectBlock)
	indirectTop := diskPointer(img, indirectPhys, 1024, 1024, dmuOtPlainFile, 1, 7, 2, 41, nil)
	indirectBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 3*512))
	rootObjects[23] = buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  10,
		nlevels:      2,
		bonustype:    dmuOtSA,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		maxblkid:     2,
		pointers:     [][]byte{indirectTop},
		bonus:        indirectBonus,
	})

	// Gang block: the DVA's high bit says its children are elsewhere.
	gangContent := make([]byte, 512)
	copy(gangContent, "gang block")
	gangBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 512))
	gangPhys := img.alloc(gangContent)
	gangPointer := diskPointer(img, gangPhys, 512, 512, dmuOtPlainFile, 0, 7, 2, 41, nil)
	le.PutUint64(gangPointer[8:], le.Uint64(gangPointer[8:])|(uint64(1)<<63))
	rootObjects[24] = img.fileDnode(testModeRegular, 512, gangBonus, gangPointer)

	// A checksum that does not match its bytes.
	badContent := make([]byte, 512)
	copy(badContent, "corrupt checksum")
	badBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 512))
	badPhys := img.alloc(badContent)
	rootObjects[25] = img.fileDnode(testModeRegular, 512, badBonus,
		diskPointer(img, badPhys, 512, 512, dmuOtPlainFile, 0, 7, 2, 41, make([]byte, 32)))

	// An unknown compression id.
	unknownComp := make([]byte, 512)
	copy(unknownComp, "unknown compression")
	unknownCompBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 512))
	unknownCompPhys := img.alloc(unknownComp)
	rootObjects[26] = img.fileDnode(testModeRegular, 512, unknownCompBonus,
		diskPointer(img, unknownCompPhys, 512, 512, dmuOtPlainFile, 0, 7, 99, 41, nil))

	// An unknown checksum id.
	unknownSum := make([]byte, 512)
	copy(unknownSum, "unknown checksum")
	unknownSumBonus := buildSABuffer(2, saLayout2, defaultSAValues(testModeRegular, 512))
	unknownSumPhys := img.alloc(unknownSum)
	rootObjects[27] = img.fileDnode(testModeRegular, 512, unknownSumBonus,
		diskPointer(img, unknownSumPhys, 512, 512, dmuOtPlainFile, 0, 12, 2, 41, nil))

	// A regular object whose SA layout carries no ZPL_SIZE.
	noSizeIDs := []uint16{1, 3, 4}
	rootObjects[29] = buildDnode(dnodeSpec{
		kind:         dmuOtPlainFile,
		indblkshift:  14,
		nlevels:      1,
		bonustype:    dmuOtSA,
		checksum:     7,
		compress:     2,
		datablkszsec: 1,
		pointers:     [][]byte{holePointer(41)},
		bonus: buildSABuffer(4, noSizeIDs, map[uint16][]byte{
			1: leU64(testModeRegular),
			3: leU64(1000),
			4: leU64(1000),
		}),
	})
	// The extra layout 4 the object above uses.
	layoutZAP = append(layoutZAP,
		fatEntry{"4", layoutBytes(noSizeIDs), 2},
		fatEntry{"5", layoutBytes([]uint16{1, 2}), 2},
	)
	rootObjects[4] = img.fatZAPDnode(27, layoutZAP)

	// A regular object whose bonus type this reader does not decode.
	rootObjects[30] = img.metadataDnode(dmuOtPlainFile, 99, []byte{1, 2, 3, 4})

	rootBP := img.addObjset(rootObjects, objsetTypeZFS, 41)

	// Child dataset object set.
	childBP := img.buildNestedObjset(1, 2, 3, "child.txt", "child data", 41)
	// Snapshot object set.
	snapshotBP := img.buildNestedObjset(1, 2, 3, "old.txt", "old contents", 42)

	// MOS.
	mos := map[uint64][]byte{}
	mosObjects := []microEntry{
		{"root_dataset", leU64(2)},
	}
	mos[1] = img.microZAPDnode(1, mosObjects)
	mos[2] = img.metadataDnode(dmuOtDslDir, dmuOtDslDir, dslDirBonus(3, 0, 4, 10))
	mos[3] = img.metadataDnode(dmuOtZapMetadata, dmuOtDslDataset,
		datasetBonus(2, 0, 1_700_000_000, 10, 7, 1234, 1000, 2000, 111, rootBP))
	mos[4] = img.microZAPDnode(1, []microEntry{
		{"child", leU64(5)},
		{"loop", leU64(2)}, // a DSL directory that names the dataset walk's root
	})
	mos[5] = img.metadataDnode(dmuOtDslDir, dmuOtDslDir, dslDirBonus(6, 2, 0, 11))
	mos[6] = img.metadataDnode(dmuOtZapMetadata, dmuOtDslDataset,
		datasetBonus(5, 0, 1_700_000_050, 10, 9, 500, 400, 600, 222, childBP))
	mos[7] = img.microZAPDnode(1, []microEntry{
		{"snap1", leU64(8)},
	})
	mos[8] = img.metadataDnode(dmuOtZapMetadata, dmuOtDslDataset,
		datasetBonus(2, 1, 1_700_000_100, 11, 0, 700, 600, 800, 333, snapshotBP))
	mos[9] = img.microZAPDnode(1, []microEntry{
		{"snap1", leU64(8)},
	})
	mos[10] = img.microZAPDnode(1, []microEntry{
		{"mountpoint", []byte("/tank\x00")},
	})
	mos[11] = img.microZAPDnode(1, []microEntry{
		{"mountpoint$inherit", []byte{0}},
	})
	mosBP := img.addObjset(mos, objsetTypeMeta, 40)

	// Labels and uberblocks.
	img.writeLabels(t, mosBP, 42)
	return img
}

func (img *testImage) writeLabels(t *testing.T, mosBP []byte, txg uint64) {
	t.Helper()
	pool := nvlistForTest(txg)
	uberblock := buildUberblock(txg, 7+11, mosBP)
	for _, at := range labelOffsets(uint64(len(img.data))) {
		img.writeOneLabel(at.offset, uint64(at.index), pool, uberblock, "sha256")
	}
}

func (t *testImage) writeOneLabel(offset, index uint64, nvlist, uberblock []byte, algorithm string) {
	phys := make([]byte, LabelPhysSize)
	copy(phys, nvlist)
	eck := LabelPhysSize - LabelECKSize
	le.PutUint64(phys[eck:], ZECMagic)
	verifier := make([]byte, 32)
	le.PutUint64(verifier[0:], offset+LabelPhysOffset)
	copy(phys[eck+8:eck+40], verifier)
	var stored []byte
	if algorithm == "fletcher4" {
		words := fletcher4(phys)
		stored = make([]byte, 32)
		for i, word := range words {
			le.PutUint64(stored[i*8:], word)
		}
	} else {
		digest := sha256.Sum256(phys)
		stored = append([]byte(nil), digest[:]...)
		for i := 0; i < 32; i += 8 {
			reverse8(stored[i : i+8])
		}
	}
	copy(phys[eck+8:eck+40], stored)
	copy(t.data[offset+LabelPhysOffset:offset+LabelPhysOffset+LabelPhysSize], phys)

	ring := make([]byte, UberblockRingSize)
	copy(ring, uberblock)
	copy(t.data[offset+LabelPhysOffset+LabelPhysSize:], ring)
}

func buildUberblock(txg, guidSum uint64, rootBP []byte) []byte {
	slot := make([]byte, UberblockSize)
	le.PutUint64(slot[0:], UberblockMagic)
	le.PutUint64(slot[8:], spaVersion)
	le.PutUint64(slot[16:], txg)
	le.PutUint64(slot[24:], guidSum)
	le.PutUint64(slot[32:], 1_700_000_000)
	copy(slot[40:168], rootBP)
	le.PutUint64(slot[168:], 7)
	return slot
}

// --- XDR nvlist encoder ---------------------------------------------------

func xdrU32(value uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, value)
	return out
}

func xdrU64(value uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, value)
	return out
}

func xdrString(value string) []byte {
	out := xdrU32(uint32(len(value)))
	out = append(out, value...)
	if pad := (4 - len(value)&3) & 3; pad != 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

const (
	xdrTypeString      = 9
	xdrTypeUint64      = 8
	xdrTypeNvlist      = 19
	xdrTypeNvlistArray = 20
	xdrTypeBoolean     = 1
)

func xdrPair(name string, kind, nelem uint32, value []byte) []byte {
	encoded := 8 + len(xdrString(name)) + 4 + 4 + len(value)
	out := xdrU32(uint32(encoded))
	out = append(out, xdrU32(uint32(encoded))...)
	out = append(out, xdrString(name)...)
	out = append(out, xdrU32(kind)...)
	out = append(out, xdrU32(nelem)...)
	return append(out, value...)
}

func xdrList(pairs ...[]byte) []byte {
	out := xdrU32(0) // version
	out = append(out, xdrU32(1)...)
	for _, pair := range pairs {
		out = append(out, pair...)
	}
	out = append(out, xdrU32(0)...)
	return append(out, xdrU32(0)...)
}

func nvlistForTest(txg uint64) []byte {
	disk := xdrList(
		xdrPair("type", xdrTypeString, 1, xdrString("disk")),
		xdrPair("id", xdrTypeUint64, 1, xdrU64(0)),
		xdrPair("guid", xdrTypeUint64, 1, xdrU64(11)),
		xdrPair("path", xdrTypeString, 1, xdrString("/dev/test0")),
		xdrPair("asize", xdrTypeUint64, 1, xdrU64(testImageSize)),
		xdrPair("ashift", xdrTypeUint64, 1, xdrU64(12)),
	)
	children := xdrU32(1)
	children = append(children, disk...)
	root := xdrList(
		xdrPair("type", xdrTypeString, 1, xdrString("root")),
		xdrPair("id", xdrTypeUint64, 1, xdrU64(0)),
		xdrPair("guid", xdrTypeUint64, 1, xdrU64(7)),
		xdrPair("ashift", xdrTypeUint64, 1, xdrU64(12)),
		xdrPair("children", xdrTypeNvlistArray, 1, children),
	)
	features := xdrList(
		xdrPair("org.openzfs:test_feature", xdrTypeBoolean, 0, nil),
	)
	return xdrList(
		xdrPair("name", xdrTypeString, 1, xdrString("tank")),
		xdrPair("pool_guid", xdrTypeUint64, 1, xdrU64(7)),
		xdrPair("version", xdrTypeUint64, 1, xdrU64(5000)),
		xdrPair("txg", xdrTypeUint64, 1, xdrU64(txg)),
		xdrPair("vdev_tree", xdrTypeNvlist, 1, root),
		xdrPair("features_for_read", xdrTypeNvlist, 1, features),
	)
}

// patchLabelChecksum rewrites one label's checksum bytes without changing the
// structure, producing a label that fails verification.
func (t *testImage) corruptLabelChecksum(offset uint64) {
	at := offset + LabelPhysOffset + LabelPhysSize - LabelECKSize + 8
	t.data[at] ^= 0xff
}
