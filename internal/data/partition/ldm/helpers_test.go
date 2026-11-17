package ldm

import (
	"encoding/binary"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Hermetic LDM image builders. Every test image is assembled in memory; no
// external tooling, fixture file or network is used.

const (
	testSectors       uint64 = 8192 // 4 MiB at 512-byte blocks
	testPublicStart   uint64 = 2048
	testPublicSize    uint64 = 4096
	testPrivateStart  uint64 = 6144
	testPrivateSize   uint64 = 2048
	testDBBlock              = testPrivateStart + 17
	testVBLKStride           = 256
	testVBLKOffset           = 512
	testDiskGUID             = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
	testOtherDiskGUID        = "2c5f39cb-3ab2-22e3-9940-1127e4ddb538"
	testGroupGUID            = "3d6a4adc-4bc3-33f4-aa51-2238f5eed649"
	testDiskID        uint64 = 6
	testOtherDiskID   uint64 = 7
	testComponentID   uint64 = 8
	testPartitionA    uint64 = 9
	testPartitionB    uint64 = 10
	testVolumeID      uint64 = 11
)

func putU16(b []byte, at int, v uint16) { binary.BigEndian.PutUint16(b[at:], v) }
func putU32(b []byte, at int, v uint32) { binary.BigEndian.PutUint32(b[at:], v) }
func putU64(b []byte, at int, v uint64) { binary.BigEndian.PutUint64(b[at:], v) }

func testImage(t *testing.T, records [][]byte, tocBlocks []uint64, version Version) []byte {
	t.Helper()
	return testImageWithCounts(t, records, tocBlocks, version, nil)
}

// testImageWithCounts builds a whole dynamic disk. counts overrides the VMDB
// committed/pending VBLK counts; nil derives them from the records, which is
// what a correctly written database would state.
func testImageWithCounts(t *testing.T, records [][]byte, tocBlocks []uint64, version Version, counts *VmdbCounts) []byte {
	t.Helper()
	image := make([]byte, int(testSectors*512))
	writePrivHead(image, 6*512, version)
	writePrivHead(image, int((testPrivateStart+1856)*512), version)
	writePrivHead(image, int((testPrivateStart+2047)*512), version)
	for _, block := range tocBlocks {
		writeTOCBlock(image, block)
	}
	var derived VmdbCounts
	if counts == nil {
		derived = countsOf(records)
		counts = &derived
	}
	writeVMDB(image, records, *counts, 1)
	start := streamOffset()
	for index, record := range records {
		at := start + index*testVBLKStride
		if at+len(record) > len(image) {
			t.Fatalf("record %d does not fit the image", index)
		}
		copy(image[at:], record)
	}
	return image
}

func streamOffset() int { return int(testDBBlock)*512 + testVBLKOffset }

func writePrivHead(image []byte, at int, version Version) {
	sector := image[at : at+512]
	copy(sector[0:8], PrivHeadMagic)
	putU16(sector, 0x0C, version.Major)
	putU16(sector, 0x0E, version.Minor)
	putU64(sector, 0x20, 6)
	putU64(sector, 0x28, 1856)
	copy(sector[0x30:], testDiskGUID)
	copy(sector[0xB0:], testGroupGUID)
	copy(sector[0xF0:], "Dg0\x00")
	putU32(sector, 0x10F, 512)
	putU64(sector, 0x11B, testPublicStart)
	putU64(sector, 0x123, testPublicSize)
	putU64(sector, 0x12B, testPrivateStart)
	putU64(sector, 0x133, testPrivateSize)
	putU64(sector, 0x13B, 1)
	putU64(sector, 0x143, 2045)
	putU32(sector, 0x14B, 1)
	putU32(sector, 0x14F, 1)
	stampChecksum(sector)
}

func writeTOCBlock(image []byte, block uint64) {
	writeTOCBlockSizes(image, block, 17, 2028)
}

func writeTOCBlockSizes(image []byte, block, start, size uint64) {
	at := int((testPrivateStart + block) * 512)
	sector := image[at : at+512]
	copy(sector[0:8], TOCBlockMagic)
	copy(sector[0x24:], "config")
	putU64(sector, 0x2E, start)
	putU64(sector, 0x36, size)
	copy(sector[0x46:], "log")
	putU64(sector, 0x50, 2045)
	putU64(sector, 0x58, 3)
	stampChecksum(sector)
}

func stampChecksum(sector []byte) {
	sum := blockChecksum(sector)
	putU32(sector, 0x08, sum)
}

func restampPrivHead(image []byte, block uint64) {
	at := int(block * 512)
	stampChecksum(image[at : at+512])
}

func restampTOCBlock(image []byte, block uint64) {
	at := int((testPrivateStart + block) * 512)
	stampChecksum(image[at : at+512])
}

func writeVMDB(image []byte, records [][]byte, counts VmdbCounts, status uint16) {
	at := int(testDBBlock) * 512
	sector := image[at : at+512]
	copy(sector[0:4], VMDBMagic)
	putU32(sector, 0x04, uint32(len(records)))
	putU32(sector, 0x08, testVBLKStride)
	putU32(sector, 0x0C, testVBLKOffset)
	putU16(sector, 0x10, status)
	putU16(sector, 0x12, 4)
	putU16(sector, 0x14, 10)
	copy(sector[0x16:], "Dg0")
	copy(sector[0x35:], testGroupGUID)
	for _, field := range []struct {
		offset int
		value  uint32
	}{
		{0x85, counts.Volumes},
		{0x89, counts.Components},
		{0x8D, counts.Partitions},
		{0x91, counts.Disks},
		{0xA1, counts.Volumes},
		{0xA5, counts.Components},
		{0xA9, counts.Partitions},
		{0xAD, counts.Disks},
	} {
		putU32(sector, field.offset, field.value)
	}
}

func countsOf(records [][]byte) VmdbCounts {
	count := func(kind byte) uint32 {
		var n uint32
		for _, record := range records {
			if record[0x13] == kind {
				n++
			}
		}
		return n
	}
	return VmdbCounts{
		Volumes:    count(0x51),
		Components: count(0x32),
		Partitions: count(0x33),
		Disks:      count(0x34) + count(0x44),
	}
}

func vblk(kind byte, sequence uint32, flags byte, body []byte) []byte {
	return vblkFragments(kind, sequence, 1, 1, 1, flags, body, nil)
}

// vblkFragments builds one slot of a record (or fragment) of a larger record.
// headerTail is placed at byte 0x10; when nil it is derived from kind/body.
func vblkFragments(kind byte, sequence uint32, group uint32, fragment, fragments uint16, flags byte, body []byte, headerTail []byte) []byte {
	record := make([]byte, testVBLKStride)
	copy(record[0:4], VBLKMagic)
	putU32(record, 0x04, sequence)
	putU32(record, 0x08, group)
	putU16(record, 0x0C, fragment)
	putU16(record, 0x0E, fragments)
	record[0x12] = flags
	record[0x13] = kind
	if headerTail == nil {
		putU32(record, 0x14, uint32(len(body)))
		copy(record[0x18:], body)
	} else {
		copy(record[0x10:0x18], headerTail)
		copy(record[0x18:], body)
	}
	return record
}

func pushVNum(out *[]byte, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	first := 0
	for first < 8 && raw[first] == 0 {
		first++
	}
	*out = append(*out, byte(8-first))
	*out = append(*out, raw[first:]...)
}

func pushVStr(out *[]byte, value string) {
	*out = append(*out, byte(len(value)))
	*out = append(*out, value...)
}

func diskBody(id uint64, name, guid string) []byte {
	var body []byte
	pushVNum(&body, id)
	pushVStr(&body, name)
	pushVStr(&body, guid)
	pushVStr(&body, `\Device\Harddisk0\DR0`)
	var fixed [12]byte
	binary.BigEndian.PutUint32(fixed[0:4], 0)
	binary.BigEndian.PutUint64(fixed[4:12], 0)
	body = append(body, fixed[:]...)
	return body
}

func partitionBody(id uint64, name string, diskID, componentID, start, volumeOffset, size uint64) []byte {
	var body []byte
	pushVNum(&body, id)
	pushVStr(&body, name)
	var fixed [12]byte
	binary.BigEndian.PutUint32(fixed[0:4], 0)
	binary.BigEndian.PutUint64(fixed[4:12], 0)
	body = append(body, fixed[:]...)
	var startRaw [8]byte
	binary.BigEndian.PutUint64(startRaw[:], start)
	body = append(body, startRaw[:]...)
	var offsetRaw [8]byte
	binary.BigEndian.PutUint64(offsetRaw[:], volumeOffset)
	body = append(body, offsetRaw[:]...)
	pushVNum(&body, size)
	pushVNum(&body, componentID)
	pushVNum(&body, diskID)
	return body
}

// partitionBodyColumn appends the optional VBLK flag 0x08 column field.
func partitionBodyColumn(id uint64, name string, diskID, componentID, start, volumeOffset, size, column uint64) []byte {
	body := partitionBody(id, name, diskID, componentID, start, volumeOffset, size)
	pushVNum(&body, column)
	return body
}

func componentBody(id, volumeID, children uint64) []byte {
	return componentBodyFlags(id, volumeID, children, 2, nil, nil)
}

func componentBodyFlags(id, volumeID, children uint64, layout byte, stripeBlocks, columns *uint64) []byte {
	var body []byte
	pushVNum(&body, id)
	pushVStr(&body, "Volume1-01")
	pushVStr(&body, "ACTIVE")
	body = append(body, layout)
	body = append(body, 0, 0, 0, 0) // component flags
	pushVNum(&body, children)
	var zeros [16]byte
	body = append(body, zeros[:]...) // commit and reserved
	pushVNum(&body, volumeID)
	if stripeBlocks != nil {
		pushVNum(&body, *stripeBlocks)
	}
	if columns != nil {
		pushVNum(&body, *columns)
	}
	return body
}

func volumeBody(id uint64, name string, size, components uint64) []byte {
	return volumeBodyFlags(id, name, size, components, 0, nil, nil)
}

// volumeBodyFlags builds a volume record. flags must carry the VBLK header
// flags whose optional fields are supplied: 0x80 chunkBlocks, 0x02 driveHint,
// 0x08/0x20 unknown ids.
func volumeBodyFlags(id uint64, name string, size, components uint64, flags byte, chunkBlocks *uint64, driveHint *string) []byte {
	var body []byte
	pushVNum(&body, id)
	pushVStr(&body, name)
	pushVStr(&body, "gen")
	pushVStr(&body, "")
	var state [14]byte
	copy(state[:], "ACTIVE")
	body = append(body, state[:]...)
	body = append(body, 1) // read policy
	pushVNum(&body, 5)
	var fixed [4]byte
	body = append(body, fixed[:]...)
	pushVNum(&body, components)
	var zeros [16]byte
	body = append(body, zeros[:]...)
	pushVNum(&body, size)
	body = append(body, 0, 0, 0, 0)
	body = append(body, 0x07) // NTFS
	body = append(body, guidBytes()...)
	if flags&0x08 != 0 {
		pushVNum(&body, 1)
	}
	if flags&0x20 != 0 {
		pushVNum(&body, 2)
	}
	if flags&0x80 != 0 && chunkBlocks != nil {
		pushVNum(&body, *chunkBlocks)
	}
	if flags&0x02 != 0 && driveHint != nil {
		pushVStr(&body, *driveHint)
	}
	return body
}

func groupBody(name string) []byte {
	var body []byte
	pushVNum(&body, 5)
	pushVStr(&body, name)
	pushVStr(&body, testGroupGUID)
	var fixed [12]byte
	body = append(body, fixed[:]...)
	return body
}

func groupV4Body(name string, guid [16]byte) []byte {
	var body []byte
	pushVNum(&body, 5)
	pushVStr(&body, name)
	body = append(body, guid[:]...)
	body = append(body, make([]byte, 16)...)
	return body
}

func guidBytes() []byte {
	return []byte{
		0x1b, 0x4e, 0x28, 0xba, 0x2f, 0xa1, 0x11, 0xd2, 0x88, 0x3f, 0x00, 0x16, 0xd3, 0xcc,
		0xa4, 0x27,
	}
}

// guidStructBytes is the same GUID as a Microsoft GUID struct: the first three
// fields are little-endian, which is how a revision-4 record stores the bytes.
func guidStructBytes() []byte {
	return []byte{
		0xba, 0x28, 0x4e, 0x1b, 0xa1, 0x2f, 0xd2, 0x11, 0x88, 0x3f, 0x00, 0x16, 0xd3, 0xcc,
		0xa4, 0x27,
	}
}

func diskV4Body(id uint64, name string, guid []byte) []byte {
	var body []byte
	pushVNum(&body, id)
	pushVStr(&body, name)
	body = append(body, guid...)
	body = append(body, make([]byte, 16)...)
	pushVStr(&body, `\Device\Harddisk0\DR0`)
	var fixed [12]byte
	body = append(body, fixed[:]...)
	return body
}

func oneVolumeRecords(secondDisk *uint64, secondStart, secondSize uint64) [][]byte {
	records := [][]byte{
		vblk(0x35, 4, 0, groupBody("Dg0")),
		vblk(0x34, 5, 0, diskBody(testDiskID, "Disk1", testDiskGUID)),
	}
	if secondDisk != nil {
		records = append(records, vblk(0x34, 6, 0, diskBody(testOtherDiskID, "Disk2", testOtherDiskGUID)))
	}
	records = append(records,
		vblk(0x32, 7, 0, componentBody(testComponentID, testVolumeID, 2)),
		vblk(0x33, 8, 0, partitionBody(testPartitionA, "Disk1-01", testDiskID, testComponentID, 0, 0, 1024)),
	)
	diskID := testDiskID
	if secondDisk != nil {
		diskID = *secondDisk
	}
	records = append(records,
		vblk(0x33, 9, 0, partitionBody(testPartitionB, "Disk1-02", diskID, testComponentID, secondStart, 1024, secondSize)),
		vblk(0x51, 10, 0, volumeBody(testVolumeID, "Volume1", 1024+secondSize, 1)),
	)
	return records
}

func parseImage(t *testing.T, image []byte) (*Database, error) {
	t.Helper()
	return Parse(source.NewMemorySource(1, image))
}

func ptrU64(v uint64) *uint64 { return &v }
func ptrU8(v uint8) *uint8    { return &v }
func ptrStr(v string) *string { return &v }
