package udf

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The synthetic image this file builds is a complete, checksum-correct UDF
// volume: a volume recognition sequence, an anchor at sector 256, a four-block
// descriptor sequence (primary, partition, logical, terminator), a file set,
// and a partition holding a directory tree.
const (
	testBlockSize   = 2048
	testTotalBlocks = 300
	testPartStart   = 80
	testPartLen     = 100

	testFSDBlock        = 0
	testRootFEBlock     = 1
	testRootDirBlock    = 2
	testHelloFEBlock    = 3
	testHelloDataBlock  = 4
	testSubdirFEBlock   = 5
	testSubdirDirBlock  = 6
	testNestedFEBlock   = 7
	testNestedData      = 8
	testLinkFEBlock     = 9
	testLongFEBlock     = 10
	testLongDataBlock   = 11
	testIndirectIEBlock = 12
	testIndirectFEBlock = 13
	testIndirectData    = 14
	testExtendedFEBlock = 15
	testExtendedData    = 16
	testInlineFEBlock   = 17
	testAEDFEBlock      = 18
	testAEDBlock        = 19
	testBitmapBlock     = 20
	testAEDDataBlock    = 21
)

const (
	tagPVD  = 0x0001
	tagAVDP = 0x0002
	tagPD   = 0x0005
	tagLVD  = 0x0006
	tagTD   = 0x0008
	tagLVID = 0x0009
	tagFSD  = 0x0100
	tagFID  = 0x0101
	tagAED  = 0x0102
	tagIE   = 0x0103
	tagFE   = 0x0105
	tagEAHD = 0x0106
	tagSBD  = 0x0108
	tagEFE  = 0x010A
)

func put16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func put64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

func crc16ITU(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, v := range data {
		crc ^= uint16(v) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// sealTag writes a correct descriptor tag over b: identifier, version, the tag
// location, the body CRC and the tag byte sum.
func sealTag(b []byte, ident uint16, crcLen int, location uint32) {
	put16(b, 0, ident)
	put16(b, 2, 2)
	put16(b, 6, 0)
	put32(b, 12, location)
	put16(b, 8, crc16ITU(b[16:16+crcLen]))
	put16(b, 10, uint16(crcLen))
	var sum uint16
	for i := 0; i < 16; i++ {
		if i != 4 {
			sum += uint16(b[i])
		}
	}
	b[4] = byte(sum & 0xFF)
}

// resealTag recomputes both checks over an already-built descriptor.
func resealTag(b []byte, ident uint16, crcLen int) {
	location := binary.LittleEndian.Uint32(b[12:16])
	put16(b, 8, crc16ITU(b[16:16+crcLen]))
	put16(b, 10, uint16(crcLen))
	put16(b, 0, ident)
	put16(b, 2, 2)
	var sum uint16
	for i := 0; i < 16; i++ {
		if i != 4 {
			sum += uint16(b[i])
		}
	}
	b[4] = byte(sum & 0xFF)
	_ = location
}

func dstring8(s string) []byte {
	out := []byte{8}
	return append(out, []byte(s)...)
}

func putDString(b []byte, off, size int, s string) {
	v := dstring8(s)
	for i := 0; i < size; i++ {
		if i < len(v) {
			b[off+i] = v[i]
		} else {
			b[off+i] = 0
		}
	}
}

func putRegID(b []byte, off int, ident string, suffix uint16) {
	b[off] = 0
	copy(b[off+1:off+24], ident)
	put16(b, off+24, suffix)
}

func udfTimestamp(year int, month, day, hour, minute, second int) []byte {
	b := make([]byte, 12)
	put16(b, 0, 0x1000) // type 1, zone offset 0
	put16(b, 2, uint16(year))
	b[4] = byte(month)
	b[5] = byte(day)
	b[6] = byte(hour)
	b[7] = byte(minute)
	b[8] = byte(second)
	return b
}

func writeVRS(img []byte, sector int, ident string) {
	off := sector * testBlockSize
	img[off] = 0
	copy(img[off+1:off+6], ident)
	img[off+6] = 1
}

func buildAVDP(mainLen, mainLoc uint32) []byte {
	b := make([]byte, testBlockSize)
	put32(b, 16, mainLen)
	put32(b, 20, mainLoc)
	put32(b, 24, 0)
	put32(b, 28, 0)
	sealTag(b, tagAVDP, 496, 256)
	return b
}

func buildPVD(block uint32) []byte {
	b := make([]byte, testBlockSize)
	put32(b, 16, 0)
	put32(b, 20, 1)
	putDString(b, 24, 32, "TESTVOL")
	put16(b, 56, 1)
	put16(b, 58, 1)
	putDString(b, 72, 128, "TESTSET")
	putRegID(b, 344, "*ewfgo", 0x0102)
	copy(b[376:388], udfTimestamp(2024, 6, 15, 10, 30, 0))
	put16(b, 488, 0)
	sealTag(b, tagPVD, 496, block)
	return b
}

func buildPD(block uint32) []byte {
	b := make([]byte, testBlockSize)
	put32(b, 16, 1)
	put16(b, 20, 0)
	put16(b, 22, 0) // partition number
	putRegID(b, 24, "+NSR03", 0)
	put32(b, 184, 1) // read-only
	put32(b, 188, testPartStart)
	put32(b, 192, testPartLen)
	// Partition header descriptor: unallocated space bitmap short AD at 64.
	put32(b, 64, testBlockSize)
	put32(b, 68, testBitmapBlock)
	sealTag(b, tagPD, 496, block)
	return b
}

func buildLVD(block uint32) []byte {
	b := make([]byte, testBlockSize)
	put32(b, 16, 1)
	putDString(b, 84, 128, "LOGVOL")
	put32(b, 212, testBlockSize)
	putRegID(b, 216, "*OSTA UDF Compliant", 0x0201)
	// contents use: long allocation descriptor for the file set.
	put32(b, 248, testBlockSize)
	put32(b, 252, testFSDBlock)
	put16(b, 256, 0)
	put32(b, 264, 6) // partition map table length
	put32(b, 268, 1) // partition map count
	put32(b, 432, testBlockSize)
	put32(b, 436, 40) // integrity descriptor, volume block 40
	// Type 1 partition map.
	b[440] = 1
	b[441] = 6
	put16(b, 442, 1)
	put16(b, 444, 0)
	sealTag(b, tagLVD, 496, block)
	return b
}

func buildTD(block uint32) []byte {
	b := make([]byte, testBlockSize)
	sealTag(b, tagTD, 496, block)
	return b
}

func buildLVID(block uint32) []byte {
	b := make([]byte, testBlockSize)
	put32(b, 16, 1)
	put32(b, 28, 1) // closed
	put32(b, 72, 1) // one partition
	put32(b, 76, 44)
	put32(b, 80, 78)  // free blocks
	put32(b, 84, 100) // partition blocks
	imp := 88
	put32(b, imp+32, 5) // files
	put32(b, imp+36, 2) // directories
	put16(b, imp+40, 0x0201)
	put16(b, imp+42, 0x0201)
	sealTag(b, tagLVID, 496, block)
	return b
}

func buildFSD(block uint32) []byte {
	b := make([]byte, testBlockSize)
	copy(b[16:28], udfTimestamp(2024, 6, 15, 10, 0, 0))
	putDString(b, 112, 128, "FSDVOL")
	putDString(b, 304, 32, "FSSET")
	// Root ICB: long allocation descriptor at 400.
	put32(b, 400, testBlockSize)
	put32(b, 404, testRootFEBlock)
	put16(b, 408, 0)
	sealTag(b, tagFSD, 496, block)
	return b
}

// testFile describes a file entry for the builder.
type testFile struct {
	block     uint32
	fileType  uint8
	adKind    uint8
	infoLen   uint64
	dataBlock uint32
	inline    []byte
	useEFE    bool
	perms     uint32
	uid, gid  uint32
	links     uint16
	modified  []byte
	xattr     []byte
	unique    uint64
}

func buildFE(f testFile) []byte {
	b := make([]byte, testBlockSize)
	ident := uint16(tagFE)
	extAttrAt := 176
	if f.useEFE {
		ident = tagEFE
		extAttrAt = 216
	}
	// ICB tag at byte 16.
	put32(b, 16, 0)
	put16(b, 20, 4) // strategy 4
	put16(b, 22, 0)
	put16(b, 24, 1)
	b[27] = f.fileType
	put32(b, 28, testRootFEBlock)
	put16(b, 32, 0)
	put16(b, 34, uint16(f.adKind))
	put32(b, 36, f.uid)
	put32(b, 40, f.gid)
	put32(b, 44, f.perms)
	put16(b, 48, f.links)
	put64(b, 56, f.infoLen)
	if f.useEFE {
		put64(b, 72, f.infoLen)
	} else {
		put64(b, 64, f.infoLen)
	}
	mod := f.modified
	if mod == nil {
		mod = udfTimestamp(2024, 6, 15, 10, 30, 0)
	}
	if f.useEFE {
		copy(b[80:92], mod)
		copy(b[92:104], mod)
		copy(b[104:116], mod)
		copy(b[116:128], mod)
		put64(b, 200, f.unique)
	} else {
		copy(b[72:84], mod)
		copy(b[84:96], mod)
		copy(b[96:108], mod)
		put64(b, 160, f.unique)
	}
	copy(b[extAttrAt:], f.xattr)
	allocAt := extAttrAt + len(f.xattr)
	allocLen := 0
	switch f.adKind {
	case 0: // short
		put32(b, allocAt, uint32(f.infoLen))
		put32(b, allocAt+4, f.dataBlock)
		allocLen = 8
	case 1: // long
		put32(b, allocAt, uint32(f.infoLen))
		put32(b, allocAt+4, f.dataBlock)
		put16(b, allocAt+8, 0)
		allocLen = 16
	case 2: // extended
		put32(b, allocAt, uint32(f.infoLen))
		put32(b, allocAt+4, uint32(f.infoLen))
		put32(b, allocAt+8, uint32(f.infoLen))
		put32(b, allocAt+12, f.dataBlock)
		put16(b, allocAt+16, 0)
		allocLen = 20
	case 3: // in-ICB
		copy(b[allocAt:], f.inline)
		allocLen = 0
	}
	end := allocAt + allocLen
	if f.adKind == 3 {
		end = allocAt + len(f.inline)
	}
	if f.useEFE {
		put32(b, 208, uint32(len(f.xattr)))
		put32(b, 212, uint32(allocLen))
	} else {
		put32(b, 168, uint32(len(f.xattr)))
		put32(b, 172, uint32(allocLen))
	}
	sealTag(b, ident, end-16, f.block)
	return b
}

func buildFID(name []byte, characteristics byte, icbBlock uint32) []byte {
	const hdr = 38
	total := (hdr + len(name) + 3) &^ 3
	b := make([]byte, total)
	put16(b, 16, 2)
	b[18] = characteristics
	b[19] = byte(len(name))
	put32(b, 20, uint32(total))
	put32(b, 24, icbBlock)
	put16(b, 28, 0)
	put16(b, 36, 0)
	copy(b[hdr:], name)
	sealTag(b, tagFID, total-16, 0)
	return b
}

func buildIE(block, targetBlock uint32) []byte {
	b := make([]byte, testBlockSize)
	put32(b, 16, 0)
	put16(b, 20, 4)
	put16(b, 22, 0)
	put16(b, 24, 1)
	b[27] = 5
	put32(b, 28, testRootFEBlock)
	put16(b, 32, 0)
	put16(b, 34, 0)
	put32(b, 36, testBlockSize)
	put32(b, 40, targetBlock)
	put16(b, 44, 0)
	sealTag(b, tagIE, 32, block)
	return b
}

func buildAED(block, previous uint32, ads []byte) []byte {
	b := make([]byte, testBlockSize)
	put32(b, 16, previous)
	put32(b, 20, uint32(len(ads)))
	copy(b[24:], ads)
	sealTag(b, tagAED, 8+len(ads), block)
	return b
}

func buildBitmap(block uint32) []byte {
	b := make([]byte, testBlockSize)
	used := map[uint64]bool{}
	for i := uint64(0); i <= testAEDDataBlock; i++ {
		used[i] = true
	}
	used[testBitmapBlock] = true
	nbytes := (testPartLen + 7) / 8
	for i := 0; i < testPartLen; i++ {
		if !used[uint64(i)] {
			b[24+i/8] |= 1 << (i % 8)
		}
	}
	put32(b, 16, testPartLen)
	put32(b, 20, uint32(nbytes))
	sealTag(b, tagSBD, 8+nbytes, block)
	return b
}

// buildXattrSpace returns an extended-attribute space holding one
// application-use record.
func buildXattrSpace() []byte {
	value := []byte("hi")
	record := make([]byte, 12+4+32+len(value))
	put32(record, 0, 65536) // application use
	record[4] = 1
	put32(record, 8, uint32(len(record)))
	put32(record, 12, uint32(len(value)))
	putRegID(record, 16, "*ewfgo", 0)
	copy(record[48:], value)

	b := make([]byte, 24)
	b = append(b, record...)
	put32(b, 16, 0)
	put32(b, 20, 0)
	sealTag(b, tagEAHD, 8+len(record), 5)
	return b
}

func buildImage() []byte {
	img := make([]byte, testTotalBlocks*testBlockSize)
	blk := func(n uint64) []byte {
		return img[n*testBlockSize : (n+1)*testBlockSize]
	}
	part := func(rel uint32) []byte {
		return img[(testPartStart+rel)*testBlockSize : (testPartStart+rel+1)*testBlockSize]
	}

	writeVRS(img, 16, "BEA01")
	writeVRS(img, 17, "NSR02")
	writeVRS(img, 18, "TEA01")

	copy(blk(32), buildPVD(32))
	copy(blk(33), buildPD(33))
	copy(blk(34), buildLVD(34))
	copy(blk(35), buildTD(35))
	copy(blk(40), buildLVID(40))
	copy(blk(256), buildAVDP(4*testBlockSize, 32))

	copy(part(testFSDBlock), buildFSD(testFSDBlock))

	rootDir := concat(
		buildFID(nil, 0x08|0x02, testRootFEBlock),
		buildFID(dstring8("hello.txt"), 0, testHelloFEBlock),
		buildFID(dstring8("subdir"), 0x02, testSubdirFEBlock),
		buildFID(dstring8("link"), 0, testLinkFEBlock),
		buildFID(dstring8("long.bin"), 0, testLongFEBlock),
		buildFID(dstring8("indirect.bin"), 0, testIndirectIEBlock),
		buildFID(dstring8("ext.bin"), 0, testExtendedFEBlock),
		buildFID(dstring8("inline.txt"), 0, testInlineFEBlock),
		buildFID(dstring8("aed.bin"), 0, testAEDFEBlock),
	)
	subDir := concat(
		buildFID(nil, 0x08|0x02, testRootFEBlock),
		buildFID(dstring8("nested.bin"), 0, testNestedFEBlock),
	)

	copy(part(testRootFEBlock), buildFE(testFile{
		block: testRootFEBlock, fileType: 4, adKind: 0,
		infoLen: uint64(len(rootDir)), dataBlock: testRootDirBlock,
		perms: 0o755,
	}))
	copy(part(testRootDirBlock), rootDir)

	copy(part(testHelloFEBlock), buildFE(testFile{
		block: testHelloFEBlock, fileType: 5, adKind: 0,
		infoLen: 10, dataBlock: testHelloDataBlock,
		perms: 0o644, uid: 1000, gid: 1000, links: 1,
		xattr: buildXattrSpace(),
	}))
	copy(part(testHelloDataBlock), []byte("hello UDF\n"))

	copy(part(testSubdirFEBlock), buildFE(testFile{
		block: testSubdirFEBlock, fileType: 4, adKind: 0,
		infoLen: uint64(len(subDir)), dataBlock: testSubdirDirBlock,
		perms: 0o755,
	}))
	copy(part(testSubdirDirBlock), subDir)
	copy(part(testNestedFEBlock), buildFE(testFile{
		block: testNestedFEBlock, fileType: 5, adKind: 0,
		infoLen: 15, dataBlock: testNestedData,
	}))
	copy(part(testNestedData), []byte("nested contents"))

	linkData := append([]byte{5, byte(len(dstring8("hello.txt")))}, dstring8("hello.txt")...)
	copy(part(testLinkFEBlock), buildFE(testFile{
		block: testLinkFEBlock, fileType: 12, adKind: 3,
		infoLen: uint64(len(linkData)), inline: linkData,
	}))

	copy(part(testLongFEBlock), buildFE(testFile{
		block: testLongFEBlock, fileType: 5, adKind: 1,
		infoLen: 16, dataBlock: testLongDataBlock,
	}))
	copy(part(testLongDataBlock), []byte("long allocation\n"))

	copy(part(testIndirectIEBlock), buildIE(testIndirectIEBlock, testIndirectFEBlock))
	copy(part(testIndirectFEBlock), buildFE(testFile{
		block: testIndirectFEBlock, fileType: 5, adKind: 0,
		infoLen: 15, dataBlock: testIndirectData,
	}))
	copy(part(testIndirectData), []byte("indirect entry\n"))

	copy(part(testExtendedFEBlock), buildFE(testFile{
		block: testExtendedFEBlock, fileType: 5, adKind: 2,
		infoLen: 12, dataBlock: testExtendedData,
	}))
	copy(part(testExtendedData), []byte("extended ad\n"))

	copy(part(testInlineFEBlock), buildFE(testFile{
		block: testInlineFEBlock, fileType: 5, adKind: 3,
		infoLen: 12, inline: []byte("inline data\n"),
	}))

	// aed.bin: the file entry's only descriptor is a continuation pointer to
	// the AED block, whose own short descriptor names the data.
	copy(part(testAEDFEBlock), buildFE(testFile{
		block: testAEDFEBlock, fileType: 5, adKind: 0,
		infoLen: 10, dataBlock: 0,
	}))
	feBytes := part(testAEDFEBlock)
	put32(feBytes, 176, 0xC0000000) // continuation
	put32(feBytes, 180, testAEDBlock)
	resealTag(feBytes, tagFE, 176+8-16)
	ads := make([]byte, 8)
	put32(ads, 0, 10)
	put32(ads, 4, testAEDDataBlock)
	copy(part(testAEDBlock), buildAED(testAEDBlock, 0, ads))
	copy(part(testAEDDataBlock), []byte("aed chain\n"))

	copy(part(testBitmapBlock), buildBitmap(testBitmapBlock))
	return img
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func openTestImage(t *testing.T, img []byte) *Volume {
	t.Helper()
	v, err := Open(source.NewMemorySource(1, img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v
}

func TestOpenAndInfo(t *testing.T) {
	v := openTestImage(t, buildImage())
	info := v.Info()
	if info.Type != "UDF" {
		t.Errorf("type = %q", info.Type)
	}
	if info.BlockSize != testBlockSize {
		t.Errorf("block size = %d", info.BlockSize)
	}
	if info.VolumeID != "TESTVOL" || info.VolumeSetID != "TESTSET" {
		t.Errorf("identifiers = %q / %q", info.VolumeID, info.VolumeSetID)
	}
	if info.FileSetID != "FSSET" {
		t.Errorf("file set id = %q", info.FileSetID)
	}
	if info.UDFRevision != "2.01" {
		t.Errorf("revision = %q", info.UDFRevision)
	}
	if info.VRS != "NSR02" {
		t.Errorf("vrs = %q", info.VRS)
	}
	if info.RootICB.Block != testRootFEBlock || info.RootICB.Partition != 0 {
		t.Errorf("root ICB = %+v", info.RootICB)
	}
	if info.LogicalVolumeSize != testPartLen*testBlockSize {
		t.Errorf("logical volume size = %d", info.LogicalVolumeSize)
	}
	if len(info.PartitionMaps) != 1 || info.PartitionMaps[0].Kind != 1 {
		t.Fatalf("partition maps = %+v", info.PartitionMaps)
	}
	if len(info.Partitions) != 1 {
		t.Fatalf("partitions = %+v", info.Partitions)
	}
	if info.Partitions[0].Start != testPartStart || info.Partitions[0].Length != testPartLen {
		t.Errorf("partition = %+v", info.Partitions[0])
	}
	if info.VolumeClosed == nil || !*info.VolumeClosed {
		t.Errorf("volume closed = %v", info.VolumeClosed)
	}
}

func TestVolumeRecognitionNSR03(t *testing.T) {
	img := buildImage()
	copy(img[17*testBlockSize+1:17*testBlockSize+6], "NSR03")
	v := openTestImage(t, img)
	if got := v.Info().VRS; got != "NSR03" {
		t.Fatalf("VRS = %q, want NSR03", got)
	}
}

func TestMissingVolumeRecognition(t *testing.T) {
	img := buildImage()
	// Erase BEA01: only the anchor remains, which is not enough.
	for i := 0; i < 7; i++ {
		img[16*testBlockSize+i] = 0
	}
	if _, err := Open(source.NewMemorySource(1, img)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want corrupt", err)
	}
}

func TestListAndStat(t *testing.T) {
	v := openTestImage(t, buildImage())

	entries, err := v.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 8 {
		t.Fatalf("root entries = %d: %+v", len(entries), entries)
	}
	byName := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		byName[entry.Name] = entry
	}
	hello, ok := byName["hello.txt"]
	if !ok {
		t.Fatal("hello.txt missing from root")
	}
	if hello.IsDir || hello.IsSymlink || !hello.IsFile {
		t.Errorf("hello.txt flags: %+v", hello)
	}
	if hello.Size != 10 || hello.UID != 1000 || hello.GID != 1000 {
		t.Errorf("hello.txt = %+v", hello)
	}
	if hello.Permissions != 0o644 {
		t.Errorf("hello.txt permissions = %o", hello.Permissions)
	}
	if hello.Mode != 0o100644 {
		t.Errorf("hello.txt mode = %o, want %o", hello.Mode, uint32(0o100644))
	}
	if !hello.Modified.Equal(time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)) {
		t.Errorf("hello.txt modified = %v", hello.Modified)
	}
	if hello.ICB.Block != testHelloFEBlock || hello.ICB.Partition != 0 {
		t.Errorf("hello.txt ICB = %+v", hello.ICB)
	}
	if hello.AllocationType != "short" {
		t.Errorf("hello.txt allocation type = %q", hello.AllocationType)
	}
	if hello.Path != "/hello.txt" {
		t.Errorf("hello.txt path = %q", hello.Path)
	}

	subdir := byName["subdir"]
	if !subdir.IsDir || subdir.Size != 0 {
		t.Errorf("subdir = %+v", subdir)
	}
	if subdir.Mode != 0o040755 {
		t.Errorf("subdir mode = %o, want %o", subdir.Mode, uint32(0o040755))
	}
	nested, err := v.ListDir("/subdir")
	if err != nil {
		t.Fatalf("ListDir subdir: %v", err)
	}
	if len(nested) != 1 || nested[0].Name != "nested.bin" {
		t.Fatalf("subdir entries = %+v", nested)
	}

	link := byName["link"]
	if !link.IsSymlink || link.SymlinkTarget != "hello.txt" {
		t.Errorf("link = %+v", link)
	}

	for name, want := range map[string]string{
		"long.bin":     "long allocation\n",
		"indirect.bin": "indirect entry\n",
		"ext.bin":      "extended ad\n",
		"inline.txt":   "inline data\n",
		"aed.bin":      "aed chain\n",
	} {
		stat, err := v.Stat("/" + name)
		if err != nil {
			t.Fatalf("Stat %s: %v", name, err)
		}
		if stat.Size != uint64(len(want)) {
			t.Errorf("%s size = %d, want %d", name, stat.Size, len(want))
		}
	}

	// Stat on the root itself.
	root, err := v.Stat("/")
	if err != nil {
		t.Fatalf("Stat /: %v", err)
	}
	if !root.IsDir || root.Path != "/" {
		t.Errorf("root = %+v", root)
	}
}

func TestOpenFileReads(t *testing.T) {
	v := openTestImage(t, buildImage())
	for path, want := range map[string]string{
		"/hello.txt":         "hello UDF\n",
		"/long.bin":          "long allocation\n",
		"/indirect.bin":      "indirect entry\n",
		"/ext.bin":           "extended ad\n",
		"/inline.txt":        "inline data\n",
		"/aed.bin":           "aed chain\n",
		"/subdir/nested.bin": "nested contents",
	} {
		src, err := v.OpenFile(path)
		if err != nil {
			t.Fatalf("OpenFile %s: %v", path, err)
		}
		got, err := source.ReadVecAt(src, 0, src.Len())
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
		if src.Len() != uint64(len(want)) {
			t.Errorf("%s Len = %d", path, src.Len())
		}
	}
}

func TestPathAndStreamErrors(t *testing.T) {
	v := openTestImage(t, buildImage())
	if _, err := v.Stat("/missing"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("Stat missing error = %v", err)
	}
	if _, err := v.ListDir("/missing"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("ListDir missing error = %v", err)
	}
	if _, err := v.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Errorf("ListDir file error = %v", err)
	}
	if _, err := v.OpenFile("/subdir"); !errors.Is(err, ErrNotAFile) {
		t.Errorf("OpenFile directory error = %v", err)
	}
	if _, err := v.OpenFile("/link"); !errors.Is(err, ErrNotAFile) {
		t.Errorf("OpenFile symlink error = %v", err)
	}
	if _, err := v.Stat("/hello.txt/child"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("Stat through file error = %v", err)
	}
}

func TestBadDescriptorChecksumAndCRC(t *testing.T) {
	t.Run("checksum", func(t *testing.T) {
		img := buildImage()
		img[34*testBlockSize+4] ^= 0xFF // LVD tag checksum byte
		_, err := Open(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})
	t.Run("crc", func(t *testing.T) {
		img := buildImage()
		img[34*testBlockSize+100] ^= 0xFF // LVD body, tag intact
		_, err := Open(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})
	t.Run("anchor", func(t *testing.T) {
		img := buildImage()
		img[256*testBlockSize+4] ^= 0xFF
		_, err := Open(source.NewMemorySource(1, img))
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})
	t.Run("file entry", func(t *testing.T) {
		img := buildImage()
		off := (testPartStart+testHelloFEBlock)*testBlockSize + 100
		img[off] ^= 0xFF
		_, err := Open(source.NewMemorySource(1, img))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		// The damaged child is not attachable, so the name is absent rather
		// than invented.
		if _, err := openTestImage(t, img).Stat("/hello.txt"); !errors.Is(err, ErrPathNotFound) {
			t.Fatalf("Stat error = %v, want path not found", err)
		}
	})
}

func TestTruncatedImage(t *testing.T) {
	img := buildImage()
	// Keep the VRS but cut the image before the anchor at sector 256.
	_, err := Open(source.NewMemorySource(1, img[:20*testBlockSize]))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open truncated error = %v, want corrupt", err)
	}

	// A file set root beyond the partition is refused while reading the
	// descriptor set, not resolved to a guessed block.
	bad := buildImage()
	lvd := bad[34*testBlockSize : 35*testBlockSize]
	put32(lvd, 252, testPartLen+10)
	resealTag(lvd, tagLVD, 496)
	_, err = Open(source.NewMemorySource(1, bad))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open bad root error = %v, want corrupt", err)
	}
}

func TestUnsupportedPartitionMaps(t *testing.T) {
	build := func(kind byte, length byte, ident string) []byte {
		img := buildImage()
		lvd := img[34*testBlockSize : 35*testBlockSize]
		put32(lvd, 264, uint32(length))
		lvd[440] = kind
		lvd[441] = length
		if kind == 2 {
			copy(lvd[445:468], ident)
			put16(lvd, 468, 0x0201)
			put16(lvd, 476, 1)
			put16(lvd, 478, 0)
		}
		resealTag(lvd, tagLVD, 496)
		return img
	}

	t.Run("virtual", func(t *testing.T) {
		_, err := Open(source.NewMemorySource(1, build(2, 40, "*UDF Virtual Partition")))
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("Open error = %v, want unsupported", err)
		}
	})
	t.Run("metadata", func(t *testing.T) {
		_, err := Open(source.NewMemorySource(1, build(2, 64, "*UDF Metadata Partition")))
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("Open error = %v, want unsupported", err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		_, err := Open(source.NewMemorySource(1, build(9, 8, "")))
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("Open error = %v, want unsupported", err)
		}
	})
}

func TestFreeSpace(t *testing.T) {
	v := openTestImage(t, buildImage())
	free, err := v.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if free.BlockSize != testBlockSize {
		t.Errorf("block size = %d", free.BlockSize)
	}
	if free.PartitionBlocks != testPartLen {
		t.Errorf("partition blocks = %d", free.PartitionBlocks)
	}
	wantFree := uint64(testPartLen - (testAEDDataBlock + 1))
	if free.FreeBlocks != wantFree {
		t.Errorf("free blocks = %d, want %d", free.FreeBlocks, wantFree)
	}
	if free.IsBlockFree(0) {
		t.Error("block 0 reported free")
	}
	if free.IsBlockFree(testBitmapBlock) {
		t.Error("bitmap block reported free")
	}
	if !free.IsBlockFree(testAEDDataBlock + 1) {
		t.Error("first block after the used run not reported free")
	}
	if len(free.Runs) != 1 || free.Runs[0].Start != testAEDDataBlock+1 || free.Runs[0].Blocks != wantFree {
		t.Errorf("free runs = %+v", free.Runs)
	}
}

func TestFileSourceHoles(t *testing.T) {
	media := make([]byte, 4096)
	for i := range media {
		media[i] = 0xAA
	}
	parent := source.NewMemorySource(1, media)
	file := newFileSource(source.ID(2), parent, []Run{
		{Offset: 0, Len: 8},
		{Hole: true, Len: 8},
		{Offset: 24, Len: 8},
	}, 24)

	got := make([]byte, 24)
	n, err := file.ReadAt(0, got)
	if err != nil || n != 24 {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	for i := 0; i < 8; i++ {
		if got[i] != 0xAA || got[16+i] != 0xAA {
			t.Fatalf("data byte %d = %#x", i, got[i])
		}
	}
	for i := 8; i < 16; i++ {
		if got[i] != 0 {
			t.Fatalf("hole byte %d = %#x", i, got[i])
		}
	}

	ranges, err := file.Extents(0, 24)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(ranges) != 3 {
		t.Fatalf("ranges = %+v", ranges)
	}
	if ranges[0].Kind != source.RangeData || ranges[1].Kind != source.RangeZero || ranges[2].Kind != source.RangeData {
		t.Errorf("range kinds = %v, %v, %v", ranges[0].Kind, ranges[1].Kind, ranges[2].Kind)
	}
	if _, err := file.ReadAt(24, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("read past EOF error = %v", err)
	}
}

func TestMalformedExtendedAttributes(t *testing.T) {
	space := buildXattrSpace()
	space[2] ^= 0xFF // tag version: the byte-sum check no longer matches
	if _, err := ParseExtendedAttributes(space); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want corrupt", err)
	}
	if _, err := ParseExtendedAttributes(make([]byte, 12)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short space error = %v, want corrupt", err)
	}
}

func TestExtendedAttributes(t *testing.T) {
	v := openTestImage(t, buildImage())
	attrs, err := v.Xattrs("/hello.txt")
	if err != nil {
		t.Fatalf("Xattrs: %v", err)
	}
	if len(attrs) != 1 {
		t.Fatalf("attributes = %d", len(attrs))
	}
	if attrs[0].Kind != 65536 || attrs[0].Label != "application-use" {
		t.Errorf("attribute = %+v", attrs[0])
	}
	if string(attrs[0].Value) != "hi" {
		t.Errorf("value = %q", attrs[0].Value)
	}
	if attrs[0].Identifier == nil || attrs[0].Identifier.IdentText() != "*ewfgo" {
		t.Errorf("identifier = %+v", attrs[0].Identifier)
	}
}
