package dmg

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testSector = 512
	testRootID = source.ID(1)
	testImage  = source.ImageID(9)
)

// bzip2FourSectors is a bzip2 stream for four 512-byte sectors, each filled
// with its sector index (0, 1, 2, 3). It was produced once with a standard
// bzip2 encoder and is embedded so the test needs no encoder or external tool.
const bzip2FourSectors = "425a6839314159265359f66087280000004000f8000008200030cd00935325dc291a291c2c371dc4c6294f177245385090f6608728"

// ---------------------------------------------------------------------------
// A hermetic UDIF fixture writer.
// ---------------------------------------------------------------------------

type testKind int

const (
	kindZero testKind = iota
	kindRaw
	kindZlib
	kindBzip2
	kindLzfse
	kindLzma
	kindAdc
	kindComment
	kindTypeValue
)

type testRun struct {
	start      uint64
	sectors    uint64
	kind       testKind
	typeValue  uint32
	fileOffset *uint64
	fileLen    *uint64
}

type testTable struct {
	name          string
	runs          []testRun
	version       uint32
	countOverride uint32
	raw           []byte
}

type dmgSpec struct {
	tables              []testTable
	doctype             bool
	binary              bool
	segmentCount        uint32
	trailerVersion      uint32
	headerSize          uint32
	sectorCountOverride uint64
	xmlOverride         string
}

func dmgMedia(sectors uint64) []byte {
	data := make([]byte, sectors*testSector)
	for sector := uint64(0); sector < sectors; sector++ {
		start := sector * testSector
		for index := uint64(0); index < testSector; index++ {
			data[start+index] = byte(sector)
		}
	}
	return data
}

func zlibBytes(data []byte) []byte {
	var out bytes.Buffer
	writer := zlib.NewWriter(&out)
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

// adcLiteral encodes data as ADC literal runs of at most 128 bytes each.
func adcLiteral(data []byte) []byte {
	var out []byte
	for start := 0; start < len(data); start += 128 {
		end := start + 128
		if end > len(data) {
			end = len(data)
		}
		out = append(out, byte(end-start-1))
		out = append(out, data[start:end]...)
	}
	return out
}

func bzip2Bytes(data []byte) []byte {
	decoded, err := hex.DecodeString(bzip2FourSectors)
	if err != nil {
		panic(err)
	}
	return decoded
}

// lzmaFourSectors is FORMAT_ALONE LZMA of media[0:2048] (sectors of 0x00 ..
// 0x03), produced once with Python's lzma module and embedded so tests stay
// hermetic.
const lzmaFourSectors = "5d00008000ffffffffffffffff00006ffdfeb367df8090bff044c3d60695fb24039080fff78cc000"

func lzmaBytes(data []byte) []byte {
	decoded, err := hex.DecodeString(lzmaFourSectors)
	if err != nil {
		panic(err)
	}
	return decoded
}

// lzfseEightSectors is an LZFSE stream of 4096 'A' bytes, produced once with
// the reference LZFSE encoder and embedded so tests stay hermetic.
const lzfseEightSectors = "6276786e001000002b000000680141f0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff006060000000000000062767824"

func lzfseBytes(data []byte) []byte {
	decoded, err := hex.DecodeString(lzfseEightSectors)
	if err != nil {
		panic(err)
	}
	return decoded
}

func testRunType(run testRun) uint32 {
	switch run.kind {
	case kindZero:
		return RunZero
	case kindRaw:
		return RunRaw
	case kindZlib:
		return RunZlib
	case kindBzip2:
		return RunBzip2
	case kindLzfse:
		return RunLzfse
	case kindLzma:
		return RunLzma
	case kindAdc:
		return RunAdc
	case kindComment:
		return RunComment
	case kindTypeValue:
		return run.typeValue
	default:
		panic("unknown test run kind")
	}
}

func encodeTable(table testTable) []byte {
	if table.raw != nil {
		return table.raw
	}
	actualCount := len(table.runs) + 1
	count := uint32(actualCount)
	if table.countOverride != 0 {
		count = table.countOverride
	}
	version := table.version
	if version == 0 {
		version = 1
	}
	body := make([]byte, BlkxHeaderBytes+actualCount*RunBytes)
	copy(body[0:4], BlkxSignature)
	putBE32(body, 4, version)
	if len(table.runs) > 0 {
		putBE64(body, 8, table.runs[0].start)
	}
	var total uint64
	for _, run := range table.runs {
		total += run.sectors
	}
	putBE64(body, 16, total)
	putBE32(body, 32, 1)
	putBE32(body, 36, count)
	putBE32(body, BlkxHeaderBytes-4, count)
	for index, run := range table.runs {
		base := BlkxHeaderBytes + index*RunBytes
		putBE32(body, base, testRunType(run))
		putBE64(body, base+8, run.start)
		putBE64(body, base+16, run.sectors)
		if run.fileOffset != nil {
			putBE64(body, base+24, *run.fileOffset)
		}
		if run.fileLen != nil {
			putBE64(body, base+32, *run.fileLen)
		}
	}
	putBE32(body, BlkxHeaderBytes+(actualCount-1)*RunBytes, RunTerminator)
	return body
}

func putBE16(b []byte, at int, v uint16) {
	b[at], b[at+1] = byte(v>>8), byte(v)
}

func putBE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func putBE64(b []byte, at int, v uint64) {
	putBE32(b, at, uint32(v>>32))
	putBE32(b, at+4, uint32(v))
}

func be32At(b []byte, at int) uint32 {
	return uint32(b[at])<<24 | uint32(b[at+1])<<16 | uint32(b[at+2])<<8 | uint32(b[at+3])
}

func be64At(b []byte, at int) uint64 {
	return uint64(be32At(b, at))<<32 | uint64(be32At(b, at+4))
}

func xmlPlist(tables []struct {
	name string
	data []byte
}, doctype bool) []byte {
	var out bytes.Buffer
	out.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	if doctype {
		out.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" " +
			"\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	}
	out.WriteString("<plist version=\"1.0\">\n<dict>\n<key>resource-fork</key>\n<dict>\n" +
		"<key>blkx</key>\n<array>\n")
	for index, table := range tables {
		encoded := base64.StdEncoding.EncodeToString(table.data)
		var wrapped bytes.Buffer
		for at := 0; at < len(encoded); at += 64 {
			end := at + 64
			if end > len(encoded) {
				end = len(encoded)
			}
			wrapped.WriteString(encoded[at:end])
			wrapped.WriteString("\n")
		}
		fmt.Fprintf(&out, "<dict>\n<key>Attributes</key><string>0x0050</string>\n"+
			"<key>CFName</key><string>%s</string>\n<key>Data</key>\n<data>\n%s</data>\n"+
			"<key>ID</key><string>%d</string>\n</dict>\n", table.name, wrapped.String(), index)
	}
	out.WriteString("</array>\n</dict>\n</dict>\n</plist>\n")
	return out.Bytes()
}

func buildBinaryPlist(tables []struct {
	name string
	data []byte
}) []byte {
	counted := func(marker byte, bytes []byte) []byte {
		var out []byte
		if len(bytes) < 15 {
			out = append(out, marker|byte(len(bytes)))
		} else {
			out = append(out, marker|0x0F, 0x12)
			var length [4]byte
			putBE32(length[:], 0, uint32(len(bytes)))
			out = append(out, length[:]...)
		}
		return append(out, bytes...)
	}
	array := func(refs []byte) []byte {
		var out []byte
		if len(refs) < 15 {
			out = append(out, 0xA0|byte(len(refs)))
		} else {
			out = append(out, 0xAF, 0x12)
			var length [4]byte
			putBE32(length[:], 0, uint32(len(refs)))
			out = append(out, length[:]...)
		}
		return append(out, refs...)
	}
	ascii := func(text string) []byte { return counted(0x50, []byte(text)) }
	data := func(bytes []byte) []byte { return counted(0x40, bytes) }

	objects := [][]byte{
		{0xD1, 0x01, 0x02},
		ascii("resource-fork"),
		{0xD1, 0x03, 0x04},
		ascii("blkx"),
	}
	entryBase := len(objects) + 1
	refs := make([]byte, len(tables))
	for index := range tables {
		refs[index] = byte(entryBase + 4*index)
	}
	objects = append(objects, array(refs))
	for _, table := range tables {
		base := len(objects)
		objects = append(objects, []byte{
			0xD2,
			byte(base + 1), byte(base + 3),
			byte(base + 2), byte(base + 4),
		})
		objects = append(objects, ascii("Name"))
		objects = append(objects, ascii(table.name))
		objects = append(objects, ascii("Data"))
		objects = append(objects, data(table.data))
	}
	if len(objects) > 255 {
		panic("fixture needs one-byte object references")
	}

	out := append([]byte(nil), BinaryPlistSignature...)
	offsets := make([]uint16, 0, len(objects))
	for _, object := range objects {
		if len(out) > 0xFFFF {
			panic("fixture needs two-byte offsets")
		}
		offsets = append(offsets, uint16(len(out)))
		out = append(out, object...)
	}
	tableOffset := len(out)
	for _, offset := range offsets {
		var raw [2]byte
		putBE16(raw[:], 0, offset)
		out = append(out, raw[:]...)
	}
	var trailer [32]byte
	trailer[6] = 2
	trailer[7] = 1
	putBE64(trailer[:], 8, uint64(len(objects)))
	putBE64(trailer[:], 16, 0)
	putBE64(trailer[:], 24, uint64(tableOffset))
	out = append(out, trailer[:]...)
	return out
}

func buildDMG(t *testing.T, media []byte, spec dmgSpec) []byte {
	t.Helper()
	if len(media)%testSector != 0 {
		t.Fatal("fixture media is not sector aligned")
	}
	var data []byte
	type encodedTable struct {
		name string
		data []byte
	}
	var encoded []encodedTable
	for _, table := range spec.tables {
		for index := range table.runs {
			run := &table.runs[index]
			start := run.start * testSector
			end := start + run.sectors*testSector
			if int(end) > len(media) {
				t.Fatalf("fixture run exceeds media")
			}
			var stored []byte
			switch run.kind {
			case kindZero, kindComment, kindTypeValue:
			case kindRaw:
				stored = media[start:end]
			case kindZlib:
				stored = zlibBytes(media[start:end])
			case kindBzip2:
				stored = bzip2Bytes(media[start:end])
			case kindLzfse:
				stored = lzfseBytes(media[start:end])
			case kindLzma:
				stored = lzmaBytes(media[start:end])
			case kindAdc:
				stored = adcLiteral(media[start:end])
			}
			if run.fileOffset == nil {
				offset := uint64(len(data))
				run.fileOffset = &offset
			}
			if run.fileLen == nil && len(stored) > 0 {
				length := uint64(len(stored))
				run.fileLen = &length
			}
			if run.kind != kindZero && run.kind != kindComment && run.kind != kindTypeValue {
				if *run.fileOffset == uint64(len(data)) {
					data = append(data, stored...)
				}
			}
		}
		encoded = append(encoded, encodedTable{table.name, encodeTable(table)})
	}

	var plist []byte
	if spec.xmlOverride != "" {
		plist = []byte(spec.xmlOverride)
	} else if spec.binary {
		binaryTables := make([]struct {
			name string
			data []byte
		}, len(encoded))
		for index, table := range encoded {
			binaryTables[index].name = table.name
			binaryTables[index].data = table.data
		}
		plist = buildBinaryPlist(binaryTables)
	} else {
		xmlTables := make([]struct {
			name string
			data []byte
		}, len(encoded))
		for index, table := range encoded {
			xmlTables[index].name = table.name
			xmlTables[index].data = table.data
		}
		plist = xmlPlist(xmlTables, spec.doctype)
	}

	file := append([]byte(nil), data...)
	xmlOffset := uint64(len(file))
	file = append(file, plist...)
	xmlLength := uint64(len(file)) - xmlOffset
	trailerOffset := len(file)
	file = append(file, make([]byte, TrailerBytes)...)
	trailer := file[trailerOffset:]
	copy(trailer[0:4], TrailerSignature)
	version := spec.trailerVersion
	if version == 0 {
		version = 4
	}
	headerSize := spec.headerSize
	if headerSize == 0 {
		headerSize = TrailerBytes
	}
	putBE32(trailer, 4, version)
	putBE32(trailer, 8, headerSize)
	putBE64(trailer, 24, 0)
	putBE64(trailer, 32, uint64(len(data)))
	putBE32(trailer, 56, 1)
	segmentCount := spec.segmentCount
	if segmentCount == 0 {
		segmentCount = 1
	}
	putBE32(trailer, 60, segmentCount)
	putBE32(trailer, 80, 2)
	putBE64(trailer, 216, xmlOffset)
	putBE64(trailer, 224, xmlLength)
	putBE32(trailer, 352, 2)
	putBE32(trailer, 488, 1)
	sectors := spec.sectorCountOverride
	if sectors == 0 {
		sectors = uint64(len(media) / testSector)
	}
	putBE64(trailer, 492, sectors)
	return file
}

func openTestDMG(t *testing.T, file []byte) *Container {
	t.Helper()
	container, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return container
}

func oneTableDMG(t *testing.T, media []byte, runs []testRun) []byte {
	t.Helper()
	return buildDMG(t, media, dmgSpec{tables: []testTable{{
		name: "disk image (Apple_HFS : 3)",
		runs: runs,
	}}, doctype: true})
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

func TestDMGDetect(t *testing.T) {
	file := oneTableDMG(t, dmgMedia(4), []testRun{{start: 0, sectors: 4, kind: kindRaw}})
	if !Detect(file) {
		t.Fatal("Detect rejected a UDIF file")
	}
	if !Detect(file[len(file)-TrailerBytes:]) {
		t.Fatal("Detect rejected the trailer slice")
	}
	if Detect(file[:TrailerBytes]) {
		t.Fatal("Detect accepted the head of a UDIF file")
	}
	if Detect(nil) || Detect([]byte("koly")) {
		t.Fatal("Detect accepted a short tail")
	}
}

func TestDMGRawZlibAndUnstoredRuns(t *testing.T) {
	media := dmgMedia(32)
	for index := 12 * testSector; index < 20*testSector; index++ {
		media[index] = 0
	}
	file := oneTableDMG(t, media, []testRun{
		{start: 0, sectors: 4, kind: kindRaw},
		{start: 4, sectors: 8, kind: kindZlib},
		{start: 12, sectors: 8, kind: kindZero},
		{start: 20, sectors: 12, kind: kindZlib},
	})
	container := openTestDMG(t, file)
	if container.Len() != uint64(len(media)) || container.SectorSize() != 512 ||
		container.VirtualDiskSize() != uint64(len(media)) {
		t.Fatalf("geometry = %d %d %d", container.Len(), container.SectorSize(),
			container.VirtualDiskSize())
	}
	info := container.Info()
	if info.Version != 4 || info.SectorCount != 32 || len(info.Tables) != 1 ||
		info.Tables[0].Runs != 4 ||
		info.Tables[0].Name == nil || *info.Tables[0].Name != "disk image (Apple_HFS : 3)" {
		t.Fatalf("info = %+v", info)
	}
	if info.RawRuns != 1 || info.ZlibRuns != 2 || info.ZeroRuns != 1 {
		t.Fatalf("counts = %+v", info)
	}
	if !info.IsCompressed() || info.IsRaw() {
		t.Fatalf("compression flags = %v %v", info.IsCompressed(), info.IsRaw())
	}
	if got := info.StorageLabel(); got != "1 raw, 2 zlib, 1 unstored" {
		t.Fatalf("label = %q", got)
	}
	if info.DataChecksumType != 2 || info.MasterChecksumType != 2 || info.ImageVariant != 1 {
		t.Fatalf("checksum/variant = %+v", info)
	}

	out := make([]byte, len(media))
	if _, err := container.ReadAt(0, out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, media) {
		t.Fatal("media differs")
	}
	across := make([]byte, 3*testSector)
	if _, err := container.ReadAt(2*testSector, across); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(across, media[2*testSector:5*testSector]) {
		t.Fatal("read across a run boundary differs")
	}

	extents, err := container.Extents(12*testSector, 8*testSector)
	if err != nil || len(extents) != 1 || extents[0].Kind != source.RangeZero {
		t.Fatalf("zero extents = %+v, %v", extents, err)
	}
	extents, err = container.Extents(0, 4*testSector)
	if err != nil || len(extents) != 1 || extents[0].Kind != source.RangeData ||
		extents[0].ParentOffset != 0 {
		t.Fatalf("raw extents = %+v, %v", extents, err)
	}
	mapped, err := container.MapToImage(0, 4*testSector)
	if err != nil || len(mapped) != 1 || mapped[0].ImageID != testImage ||
		mapped[0].ImageOffset != 0 || mapped[0].Kind != source.RangeData {
		t.Fatalf("mapped = %+v, %v", mapped, err)
	}
	mapped, err = container.MapToImage(12*testSector, 4*testSector)
	if err != nil || len(mapped) != 1 || mapped[0].Kind != source.RangeZero {
		t.Fatalf("zero mapped = %+v, %v", mapped, err)
	}
}

func TestDMGBinaryPropertyList(t *testing.T) {
	media := dmgMedia(8)
	file := buildDMG(t, media, dmgSpec{
		tables: []testTable{{name: "disk image (Apple_HFS : 3)",
			runs: []testRun{{start: 0, sectors: 8, kind: kindRaw}}}},
		binary: true,
	})
	if !bytes.Contains(file, []byte(BinaryPlistSignature)) {
		t.Fatal("fixture does not carry a binary property list")
	}
	container := openTestDMG(t, file)
	info := container.Info()
	if len(info.Tables) != 1 || info.Tables[0].Name == nil ||
		*info.Tables[0].Name != "disk image (Apple_HFS : 3)" {
		t.Fatalf("info = %+v", info)
	}
	if info.RawRuns != 1 || info.ZlibRuns != 0 || info.ZeroRuns != 0 {
		t.Fatalf("counts = %+v", info)
	}
	out := make([]byte, len(media))
	if _, err := container.ReadAt(0, out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, media) {
		t.Fatal("binary-plist media differs")
	}
}

func TestDMGBinaryBlkxValidation(t *testing.T) {
	media := dmgMedia(1)
	file := buildDMG(t, media, dmgSpec{
		tables: []testTable{{name: "disk image", runs: []testRun{{start: 0, sectors: 1, kind: kindRaw}}}},
		binary: true,
	})
	at := bytes.Index(file, []byte(BlkxSignature))
	if at < 0 {
		t.Fatal("fixture carries no blkx table")
	}
	file[at] = 'x'
	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("does not start with mish")) {
		t.Fatalf("error = %v", err)
	}
}

func TestDMGTablesMerge(t *testing.T) {
	media := dmgMedia(16)
	file := buildDMG(t, media, dmgSpec{tables: []testTable{
		{name: "Driver Descriptor Map (DDM : 0)",
			runs: []testRun{{start: 0, sectors: 4, kind: kindRaw}}},
		{name: "disk image (Apple_HFS : 3)",
			runs: []testRun{{start: 4, sectors: 12, kind: kindZlib}}},
	}})
	container := openTestDMG(t, file)
	if container.Info().Tables[0].Runs != 1 || container.Info().Tables[0].FirstSector != 0 ||
		container.Info().Tables[1].FirstSector != 4 {
		t.Fatalf("tables = %+v", container.Info().Tables)
	}
	names := container.TableNames()
	if len(names) != 2 || names[0] != "Driver Descriptor Map (DDM : 0)" ||
		names[1] != "disk image (Apple_HFS : 3)" {
		t.Fatalf("names = %v", names)
	}
	out := make([]byte, len(media))
	if _, err := container.ReadAt(0, out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, media) {
		t.Fatal("merged disk differs")
	}
}

func TestDMGCompressedCodecs(t *testing.T) {
	media := dmgMedia(20)
	file := oneTableDMG(t, media, []testRun{
		{start: 0, sectors: 4, kind: kindBzip2},
		{start: 4, sectors: 4, kind: kindAdc},
		{start: 8, sectors: 4, kind: kindZlib},
	})
	container := openTestDMG(t, file)
	info := container.Info()
	if info.Bzip2Runs != 1 || info.AdcRuns != 1 || info.ZlibRuns != 1 ||
		info.LzfseRuns != 0 || info.LzmaRuns != 0 {
		t.Fatalf("counts = %+v", info)
	}
	if !info.IsCompressed() || info.IsRaw() {
		t.Fatalf("compression flags = %v %v", info.IsCompressed(), info.IsRaw())
	}
	out := make([]byte, 12*testSector)
	if _, err := container.ReadAt(0, out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, media[:12*testSector]) {
		t.Fatal("compressed media differs")
	}
	// Sectors 12..20 are covered by no run and read as zero.
	zero := make([]byte, 8*testSector)
	if _, err := container.ReadAt(12*testSector, zero); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(zero, make([]byte, len(zero))) {
		t.Fatal("uncovered gap is not zero")
	}
}

func TestDMGLZFSERunDecodes(t *testing.T) {
	media := bytes.Repeat([]byte{'A'}, 8*testSector)
	file := oneTableDMG(t, media, []testRun{
		{start: 0, sectors: 8, kind: kindLzfse},
	})
	container := openTestDMG(t, file)
	if info := container.Info(); info.LzfseRuns != 1 {
		t.Fatalf("counts = %+v", info)
	}
	out := make([]byte, len(media))
	if _, err := container.ReadAt(0, out); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(out, media) {
		t.Fatal("LZFSE-decoded media differs")
	}
}

func TestDMGLZMARunDecodes(t *testing.T) {
	media := dmgMedia(8)
	file := oneTableDMG(t, media, []testRun{
		{start: 0, sectors: 4, kind: kindLzma},
		{start: 4, sectors: 4, kind: kindRaw},
	})
	container := openTestDMG(t, file)
	if info := container.Info(); info.LzmaRuns != 1 {
		t.Fatalf("counts = %+v", info)
	}
	out := make([]byte, len(media))
	if _, err := container.ReadAt(0, out); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(out, media) {
		t.Fatal("LZMA-decoded media differs")
	}
}

func TestDMGCommentAndZeroSectorRunsIgnored(t *testing.T) {
	media := dmgMedia(8)
	run := testRun{start: 0, sectors: 4, kind: kindRaw}
	file := oneTableDMG(t, media, []testRun{
		run,
		{start: 4, sectors: 4, kind: kindComment},
	})
	container := openTestDMG(t, file)
	info := container.Info()
	if info.Tables[0].Runs != 1 || info.RawRuns != 1 || info.ZeroRuns != 0 {
		t.Fatalf("info = %+v", info)
	}
	out := make([]byte, len(media))
	if _, err := container.ReadAt(0, out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[:4*testSector], media[:4*testSector]) {
		t.Fatal("raw sector differs")
	}
	if !bytes.Equal(out[4*testSector:], make([]byte, 4*testSector)) {
		t.Fatal("comment-covered sector is not zero")
	}
}

func TestDMGUnknownRunType(t *testing.T) {
	media := dmgMedia(4)
	file := oneTableDMG(t, media, []testRun{
		{start: 0, sectors: 4, kind: kindTypeValue, typeValue: 0x80000009},
	})
	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unknown type 0x80000009")) {
		t.Fatalf("error = %v", err)
	}
}

func TestDMGSegmentedRefused(t *testing.T) {
	media := dmgMedia(4)
	file := buildDMG(t, media, dmgSpec{
		tables:       []testTable{{name: "disk", runs: []testRun{{start: 0, sectors: 4, kind: kindRaw}}}},
		segmentCount: 3,
	})
	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("segmented")) ||
		!bytes.Contains([]byte(err.Error()), []byte("segment 1 of 3")) {
		t.Fatalf("error = %v", err)
	}
}

func TestDMGOverlappingRunsCorrupt(t *testing.T) {
	media := dmgMedia(8)
	file := buildDMG(t, media, dmgSpec{tables: []testTable{
		{name: "first", runs: []testRun{{start: 0, sectors: 6, kind: kindRaw}}},
		{name: "second", runs: []testRun{{start: 2, sectors: 6, kind: kindRaw}}},
	}})
	_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("claimed by two runs")) {
		t.Fatalf("error = %v", err)
	}
}

func TestDMGDamagedZlibIsCorrupt(t *testing.T) {
	media := dmgMedia(4)
	file := oneTableDMG(t, media, []testRun{{start: 0, sectors: 4, kind: kindZlib}})
	file[0] ^= 0xFF // the data fork starts at byte 0
	container := openTestDMG(t, file)
	_, err := container.ReadAt(0, make([]byte, 512))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("did not inflate")) {
		t.Fatalf("error = %v", err)
	}
}

func TestDMGTrailerValidation(t *testing.T) {
	media := dmgMedia(4)
	base := buildDMG(t, media, dmgSpec{
		tables: []testTable{{name: "disk", runs: []testRun{{start: 0, sectors: 4, kind: kindRaw}}}},
	})
	trailerAt := len(base) - TrailerBytes

	cases := []struct {
		name string
		file []byte
		want error
		text string
	}{
		{"encrypted", patchBE32(base, trailerAt+4, 2), source.ErrDecrypt, "encrypt"},
		{"version", patchBE32(base, trailerAt+4, 3), source.ErrUnsupported, "version 3"},
		{"header-size", patchBE32(base, trailerAt+8, 500), source.ErrUnsupported, "trailer layout"},
		{"no-sectors", patchBE64(base, trailerAt+492, 0), source.ErrCorrupt, "no sectors"},
		{"no-plist", patchBE64(base, trailerAt+224, 0), source.ErrCorrupt, "no resource-fork property list"},
		{"data-fork", patchBE64(base, trailerAt+32, uint64(len(base))+1), source.ErrCorrupt, "data fork"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, test.file))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(test.text)) {
				t.Fatalf("error = %v, want %q", err, test.text)
			}
		})
	}

	bad := append([]byte(nil), base...)
	bad[trailerAt] = 'X'
	if Detect(bad) {
		t.Fatal("Detect accepted a broken trailer")
	}
	if _, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, bad)); err == nil {
		t.Fatal("Open accepted a broken trailer")
	}
	if _, err := Open(source.NewMemorySource(testRootID, make([]byte, 100))); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("short file error = %v, want ErrUnsupported", err)
	}
}

func TestDMGPropertyListErrors(t *testing.T) {
	media := dmgMedia(1)
	table := encodeTable(testTable{name: "disk",
		runs: []testRun{{start: 0, sectors: 1, kind: kindZero}}})
	encoded := base64.StdEncoding.EncodeToString(table)
	cases := []struct {
		name string
		xml  string
		text string
	}{
		{"root", `<notplist/>`, "root element"},
		{"no-resource-fork", `<plist><dict><key>x</key><string>y</string></dict></plist>`,
			"no resource-fork dictionary"},
		{"no-blkx", `<plist><dict><key>resource-fork</key><dict/></dict></plist>`,
			"no blkx array"},
		{"no-data", `<plist><dict><key>resource-fork</key><dict><key>blkx</key><array>` +
			`<dict><key>Name</key><string>x</string></dict></array></dict></dict></plist>`,
			"carries no Data"},
		{"bad-base64", `<plist><dict><key>resource-fork</key><dict><key>blkx</key><array>` +
			`<dict><key>Data</key><data>!!!!</data></dict></array></dict></dict></plist>`,
			"not a Base64 block table"},
		{"short-table", `<plist><dict><key>resource-fork</key><dict><key>blkx</key><array>` +
			`<dict><key>Data</key><data>` + base64.StdEncoding.EncodeToString([]byte("short")) +
			`</data></dict></array></dict></dict></plist>`, "shorter than its own header"},
		{"bad-mish", `<plist><dict><key>resource-fork</key><dict><key>blkx</key><array>` +
			`<dict><key>Data</key><data>` +
			base64.StdEncoding.EncodeToString(append([]byte("xxxx"), make([]byte, BlkxHeaderBytes)...)) +
			`</data></dict></array></dict></dict></plist>`, "does not start with mish"},
		{"valid", `<plist><dict><key>resource-fork</key><dict><key>blkx</key><array>` +
			`<dict><key>Data</key><data>` + encoded + `</data></dict></array></dict></dict></plist>`, ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			file := buildDMG(t, media, dmgSpec{xmlOverride: test.xml})
			_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
			if test.text == "" {
				if err != nil {
					t.Fatalf("Open error = %v", err)
				}
				return
			}
			if !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("error = %v, want ErrCorrupt", err)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(test.text)) {
				t.Fatalf("error = %v, want %q", err, test.text)
			}
		})
	}
}

func TestDMGRunTableValidation(t *testing.T) {
	media := dmgMedia(8)
	outside := uint64(1 << 40)
	cases := []struct {
		name string
		run  testRun
		text string
	}{
		{"past-disk", testRun{start: 4, sectors: 8, kind: kindRaw}, "past the 8"},
		{"stored-outside", testRun{start: 0, sectors: 1, kind: kindRaw, fileOffset: &outside},
			"outside the"},
		{"no-stored-bytes", testRun{start: 0, sectors: 1, kind: kindRaw}, "declares no stored bytes"},
	}
	zeroLength := uint64(0)
	cases[2].run.fileLen = &zeroLength
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var file []byte
			if test.name == "past-disk" {
				file = buildDMG(t, dmgMedia(16), dmgSpec{
					sectorCountOverride: 8,
					tables:              []testTable{{name: "disk", runs: []testRun{test.run}}},
				})
			} else {
				file = oneTableDMG(t, media, []testRun{test.run})
			}
			_, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file))
			if !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("error = %v, want ErrCorrupt", err)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(test.text)) {
				t.Fatalf("error = %v, want %q", err, test.text)
			}
		})
	}
}

func TestDMGRunTableHeaderValidation(t *testing.T) {
	media := dmgMedia(4)
	run := testRun{start: 0, sectors: 4, kind: kindRaw}
	file := buildDMG(t, media, dmgSpec{tables: []testTable{{
		name: "disk", runs: []testRun{run}, version: 2,
	}}})
	if _, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file)); !errors.Is(err, source.ErrUnsupported) ||
		!bytes.Contains([]byte(err.Error()), []byte("block-table version 2")) {
		t.Fatalf("version error = %v", err)
	}

	file = buildDMG(t, media, dmgSpec{tables: []testTable{{
		name: "disk", runs: []testRun{run}, countOverride: 1000,
	}}})
	if _, err := Open(source.NewMemorySourceWithImage(testRootID, testImage, file)); !errors.Is(err, source.ErrCorrupt) ||
		!bytes.Contains([]byte(err.Error()), []byte("declares 1000 runs")) {
		t.Fatalf("count error = %v", err)
	}
}

func TestDMGByteSourceBoundsAndLossy(t *testing.T) {
	media := dmgMedia(2)
	file := oneTableDMG(t, media, []testRun{{start: 0, sectors: 2, kind: kindRaw}})
	container := openTestDMG(t, file)
	if n, err := container.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if _, err := container.ReadAt(container.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("past end = %v", err)
	}
	if _, err := container.Extents(container.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extent past end = %v", err)
	}

	damaged := oneTableDMG(t, media, []testRun{{start: 0, sectors: 2, kind: kindZlib}})
	damaged[0] ^= 0xFF
	container = openTestDMG(t, damaged)
	buf := bytes.Repeat([]byte{0xAA}, 512)
	n, err := container.ReadAtLossy(0, buf)
	if err != nil || n != 512 {
		t.Fatalf("lossy read = %d, %v", n, err)
	}
	if !bytes.Equal(buf, make([]byte, 512)) {
		t.Fatal("lossy read did not zero-fill")
	}
	if container.Stats().CorruptBytes != 512 {
		t.Fatalf("corrupt bytes = %d", container.Stats().CorruptBytes)
	}
}

func TestDMGZeroRunsAndGaps(t *testing.T) {
	media := dmgMedia(8)
	file := oneTableDMG(t, media, []testRun{{start: 2, sectors: 2, kind: kindRaw}})
	container := openTestDMG(t, file)
	out := make([]byte, len(media))
	if _, err := container.ReadAt(0, out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[:2*testSector], make([]byte, 2*testSector)) ||
		!bytes.Equal(out[4*testSector:], make([]byte, 4*testSector)) {
		t.Fatal("gap is not zero")
	}
	if !bytes.Equal(out[2*testSector:4*testSector], media[2*testSector:4*testSector]) {
		t.Fatal("raw run differs")
	}
	extents, err := container.Extents(0, 8*testSector)
	if err != nil || len(extents) != 3 {
		t.Fatalf("extents = %+v, %v", extents, err)
	}
	if extents[0].Kind != source.RangeZero || extents[1].Kind != source.RangeData ||
		extents[2].Kind != source.RangeZero {
		t.Fatalf("extent kinds = %+v", extents)
	}
}

func patchBE32(file []byte, at int, value uint32) []byte {
	out := append([]byte(nil), file...)
	putBE32(out, at, value)
	return out
}

func patchBE64(file []byte, at int, value uint64) []byte {
	out := append([]byte(nil), file...)
	putBE64(out, at, value)
	return out
}

var _ = be64At
