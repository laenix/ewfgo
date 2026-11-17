package sevenz

// Hermetic 7z fixture builder.
//
// Every archive the tests read is assembled here from the property-tree
// grammar, with compressed payloads produced by the Go standard library or
// embedded as constants generated once during development.  No external tool
// runs at test time.

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"unicode/utf16"
)

func fixtureCRC(data []byte) uint32 { return crc32.ChecksumIEEE(data) }

// sevenNumber encodes one 7z variable-length number.
func sevenNumber(value uint64) []byte {
	if value < 0x80 {
		return []byte{byte(value)}
	}
	for count := 1; count <= 8; count++ {
		if count == 8 {
			out := []byte{0xFF}
			for index := 0; index < 8; index++ {
				out = append(out, byte(value>>(8*uint(index))))
			}
			return out
		}
		if value < uint64(1)<<(7*(count+1)) {
			first := byte(0xFF<<(8-count)) |
				byte((value>>(8*uint(count)))&((uint64(1)<<(7-uint(count)))-1))
			out := []byte{first}
			for index := 0; index < count; index++ {
				out = append(out, byte(value>>(8*uint(index))))
			}
			return out
		}
	}
	return nil
}

func appendNumber(dst []byte, value uint64) []byte { return append(dst, sevenNumber(value)...) }

// sevenBits encodes a bit vector, most-significant bit of each byte first.
func sevenBits(values []bool) []byte {
	out := make([]byte, (len(values)+7)/8)
	for index, value := range values {
		if value {
			out[index/8] |= 0x80 >> (index % 8)
		}
	}
	return out
}

func utf16Name(name string) []byte {
	units := utf16.Encode([]rune(name))
	out := make([]byte, 0, 2*len(units)+2)
	for _, unit := range units {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], unit)
		out = append(out, encoded[:]...)
	}
	return append(out, 0, 0)
}

func appendU32(dst []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(dst, encoded[:]...)
}

func appendU64(dst []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(dst, encoded[:]...)
}

// testCoder is one coder in a fixture folder.
type testCoder struct {
	id    []byte
	props []byte
}

// testFolder is one folder with exactly one packed stream.
type testFolder struct {
	coders      []testCoder
	bindPairs   []bindPair
	unpackSizes []uint64
	packed      []byte
	// subSizes holds one entry per substream.  Empty means one substream of
	// the folder's size.
	subSizes []uint64
	// subCRCs holds one entry per substream; nil entries are undefined.
	subCRCs []*uint32
	// folderCRC, when set, is the CRC-32 of the whole unpacked folder.
	folderCRC *uint32
}

func (f *testFolder) numSubstreams() int {
	if len(f.subSizes) == 0 {
		return 1
	}
	return len(f.subSizes)
}

func (f *testFolder) finalUnpackSize() uint64 {
	if len(f.unpackSizes) == 0 {
		return 0
	}
	return f.unpackSizes[len(f.unpackSizes)-1]
}

// testFile is one listed member.
type testFile struct {
	name   string
	data   []byte // payload for a non-empty file
	isDir  bool
	anti   bool
	empty  bool
	folder int // -1 when the file has no stream
	sub    int
	crc    *uint32
	mtime  *int64
	attr   *uint32
}

func (f *testFile) emptyStream() bool { return f.empty || f.isDir || f.anti || f.folder < 0 }

// fixtureArchive is a complete archive plus the packed payload it should hold.
type fixtureArchive struct {
	bytes  []byte
	packed []byte
}

// buildArchive assembles a plain-header archive.  The packed streams are
// concatenated in folder order immediately after the signature header.
func buildArchive(folders []*testFolder, files []*testFile) fixtureArchive {
	var packed []byte
	for _, folder := range folders {
		packed = append(packed, folder.packed...)
	}
	header := buildHeader(folders, files)

	sig := make([]byte, signatureHeaderLen)
	copy(sig[:6], signature[:])
	sig[6], sig[7] = 0, 4
	binary.LittleEndian.PutUint64(sig[12:20], uint64(len(packed)))
	binary.LittleEndian.PutUint64(sig[20:28], uint64(len(header)))
	nextCRC := fixtureCRC(header)
	binary.LittleEndian.PutUint32(sig[28:32], nextCRC)
	startCRC := fixtureCRC(sig[12:32])
	binary.LittleEndian.PutUint32(sig[8:12], startCRC)

	out := append(append([]byte(nil), sig...), packed...)
	out = append(out, header...)
	return fixtureArchive{bytes: out, packed: packed}
}

// buildEncodedArchive puts the same plain header behind a Deflate-encoded
// header.  compress must yield a raw DEFLATE stream for plainHeader.  The
// main payload keeps pack position zero; the compressed header sits after it.
func buildEncodedArchive(plainHeader, mainPacked []byte, compress func([]byte) []byte) fixtureArchive {
	stored := compress(plainHeader)
	folder := &testFolder{
		coders:      []testCoder{{id: idDeflate}},
		unpackSizes: []uint64{uint64(len(plainHeader))},
		packed:      stored,
		subSizes:    []uint64{uint64(len(plainHeader))},
	}
	crc := fixtureCRC(plainHeader)
	folder.folderCRC = &crc

	next := appendNumber(nil, kEncodedHeader)
	next = append(next, buildStreamsInfo([]*testFolder{folder}, uint64(len(mainPacked)))...)

	payload := append(append([]byte(nil), mainPacked...), stored...)
	sig := make([]byte, signatureHeaderLen)
	copy(sig[:6], signature[:])
	sig[6], sig[7] = 0, 4
	binary.LittleEndian.PutUint64(sig[12:20], uint64(len(payload)))
	binary.LittleEndian.PutUint64(sig[20:28], uint64(len(next)))
	binary.LittleEndian.PutUint32(sig[28:32], fixtureCRC(next))
	binary.LittleEndian.PutUint32(sig[8:12], fixtureCRC(sig[12:32]))

	out := append(append([]byte(nil), sig...), payload...)
	out = append(out, next...)
	return fixtureArchive{bytes: out, packed: payload}
}

func buildHeader(folders []*testFolder, files []*testFile) []byte {
	header := appendNumber(nil, kHeader)
	if len(folders) > 0 {
		header = appendNumber(header, kMainStreamsInfo)
		header = append(header, buildStreamsInfo(folders, 0)...)
	}
	header = append(header, buildFilesInfo(folders, files)...)
	header = appendNumber(header, kEnd)
	return header
}

func buildStreamsInfo(folders []*testFolder, packPos uint64) []byte {
	out := appendNumber(nil, kPackInfo)
	out = appendNumber(out, packPos)
	out = appendNumber(out, uint64(len(folders)))
	out = appendNumber(out, kSize)
	for _, folder := range folders {
		out = appendNumber(out, uint64(len(folder.packed)))
	}
	out = appendNumber(out, kEnd)

	out = appendNumber(out, kUnpackInfo)
	out = appendNumber(out, kFolder)
	out = appendNumber(out, uint64(len(folders)))
	out = append(out, 0) // folder data is inline
	for _, folder := range folders {
		out = append(out, encodeFolder(folder)...)
	}
	out = appendNumber(out, kCodersUnpackSize)
	for _, folder := range folders {
		for _, size := range folder.unpackSizes {
			out = appendNumber(out, size)
		}
	}
	if crcs := folderCRCs(folders); crcs != nil {
		out = appendNumber(out, kCRC)
		out = append(out, encodeDigests(crcs)...)
	}
	out = appendNumber(out, kEnd)

	if needsSubstreamsInfo(folders) {
		out = append(out, buildSubstreamsInfo(folders)...)
	}
	out = appendNumber(out, kEnd)
	return out
}

func encodeFolder(folder *testFolder) []byte {
	out := appendNumber(nil, uint64(len(folder.coders)))
	for _, coder := range folder.coders {
		flags := byte(len(coder.id) & 0x0F)
		if len(coder.props) > 0 {
			flags |= 0x20
		}
		out = append(out, flags)
		out = append(out, coder.id...)
		if len(coder.props) > 0 {
			out = appendNumber(out, uint64(len(coder.props)))
			out = append(out, coder.props...)
		}
	}
	for _, pair := range folder.bindPairs {
		out = appendNumber(out, pair.input)
		out = appendNumber(out, pair.output)
	}
	// Every fixture folder has one packed stream feeding the only unbound
	// input, so no explicit packed-input table is written.
	return out
}

func folderCRCs(folders []*testFolder) []*uint32 {
	any := false
	for _, folder := range folders {
		if folder.folderCRC != nil {
			any = true
		}
	}
	if !any {
		return nil
	}
	out := make([]*uint32, len(folders))
	for index, folder := range folders {
		out[index] = folder.folderCRC
	}
	return out
}

func needsSubstreamsInfo(folders []*testFolder) bool {
	// The reference resolver derives every folder's substream sizes from a
	// SubstreamsInfo property, so a folder without one is not a valid header
	// for it; the builder therefore always emits the property.
	return len(folders) > 0
}

func buildSubstreamsInfo(folders []*testFolder) []byte {
	out := appendNumber(nil, kSubstreamsInfo)
	out = appendNumber(out, kNumUnpackStream)
	for _, folder := range folders {
		out = appendNumber(out, uint64(folder.numSubstreams()))
	}
	out = appendNumber(out, kSize)
	for _, folder := range folders {
		count := folder.numSubstreams()
		if count <= 1 {
			continue
		}
		sizes := folder.subSizes
		for index := 0; index < count-1; index++ {
			out = appendNumber(out, sizes[index])
		}
	}

	// The CRC vector covers every substream except a single-substream folder
	// whose folder CRC already covers it.
	var needed []*uint32
	any := false
	for _, folder := range folders {
		if folder.numSubstreams() == 1 && folder.folderCRC != nil {
			continue
		}
		for sub := 0; sub < folder.numSubstreams(); sub++ {
			var value *uint32
			if sub < len(folder.subCRCs) {
				value = folder.subCRCs[sub]
			}
			if value != nil {
				any = true
			}
			needed = append(needed, value)
		}
	}
	if any {
		out = appendNumber(out, kCRC)
		out = append(out, encodeDigests(needed)...)
	}
	out = appendNumber(out, kEnd)
	return out
}

// encodeDigests writes an all-defined-or-bit-vector header and the defined
// digests.
func encodeDigests(values []*uint32) []byte {
	all := true
	for _, value := range values {
		if value == nil {
			all = false
			break
		}
	}
	var out []byte
	if all {
		out = append(out, 1)
	} else {
		out = append(out, 0)
		defined := make([]bool, len(values))
		for index, value := range values {
			defined[index] = value != nil
		}
		out = append(out, sevenBits(defined)...)
	}
	for _, value := range values {
		if value != nil {
			out = appendU32(out, *value)
		}
	}
	return out
}

func encodeDefinedValues(values []*uint64, width int) []byte {
	all := true
	for _, value := range values {
		if value == nil {
			all = false
			break
		}
	}
	var out []byte
	if all {
		out = append(out, 1)
	} else {
		out = append(out, 0)
		defined := make([]bool, len(values))
		for index, value := range values {
			defined[index] = value != nil
		}
		out = append(out, sevenBits(defined)...)
	}
	out = append(out, 0) // no external stream
	for _, value := range values {
		if value == nil {
			continue
		}
		switch width {
		case 4:
			out = appendU32(out, uint32(*value))
		case 8:
			out = appendU64(out, *value)
		}
	}
	return out
}

func buildFilesInfo(folders []*testFolder, files []*testFile) []byte {
	out := appendNumber(nil, kFilesInfo)
	out = appendNumber(out, uint64(len(files)))

	empty := make([]bool, len(files))
	anyEmpty, anyEmptyFile, anyAnti := false, false, false
	for index := range files {
		empty[index] = files[index].emptyStream()
		if empty[index] {
			anyEmpty = true
		}
	}
	// Build the empty-file and anti vectors with one slot per empty stream.
	emptyFiles := make([]bool, 0, countTrue(empty))
	anti := make([]bool, 0, countTrue(empty))
	for index := range files {
		if !empty[index] {
			continue
		}
		emptyFiles = append(emptyFiles, files[index].empty && !files[index].isDir && !files[index].anti)
		anti = append(anti, files[index].anti)
		if emptyFiles[len(emptyFiles)-1] {
			anyEmptyFile = true
		}
		if files[index].anti {
			anyAnti = true
		}
	}

	if anyEmpty {
		body := sevenBits(empty)
		out = appendNumber(out, kEmptyStream)
		out = appendNumber(out, uint64(len(body)))
		out = append(out, body...)
	}
	if anyEmptyFile {
		body := sevenBits(emptyFiles)
		out = appendNumber(out, kEmptyFile)
		out = appendNumber(out, uint64(len(body)))
		out = append(out, body...)
	}
	if anyAnti {
		body := sevenBits(anti)
		out = appendNumber(out, kAnti)
		out = appendNumber(out, uint64(len(body)))
		out = append(out, body...)
	}

	var names []byte
	names = append(names, 0)
	for index := range files {
		names = append(names, utf16Name(files[index].name)...)
	}
	out = appendNumber(out, kName)
	out = appendNumber(out, uint64(len(names)))
	out = append(out, names...)

	var mtimes []*uint64
	anyTime := false
	for index := range files {
		if files[index].mtime == nil {
			mtimes = append(mtimes, nil)
			continue
		}
		// mtime is Unix seconds; turn it back into a Windows FILETIME.
		ticks := uint64(*files[index].mtime+11_644_473_600) * 10_000_000
		mtimes = append(mtimes, &ticks)
		anyTime = true
	}
	if anyTime {
		body := encodeDefinedValues(mtimes, 8)
		out = appendNumber(out, kMTime)
		out = appendNumber(out, uint64(len(body)))
		out = append(out, body...)
	}

	var attrs []*uint64
	anyAttr := false
	for index := range files {
		if files[index].attr == nil {
			attrs = append(attrs, nil)
			continue
		}
		value := uint64(*files[index].attr)
		attrs = append(attrs, &value)
		anyAttr = true
	}
	if anyAttr {
		body := encodeDefinedValues(attrs, 4)
		out = appendNumber(out, kWinAttrib)
		out = appendNumber(out, uint64(len(body)))
		out = append(out, body...)
	}

	out = appendNumber(out, kEnd)
	return out
}

// copyFolder builds a one-coder Copy folder over payload.
func copyFolder(payload []byte, subSizes []uint64, subCRCs []*uint32, folderCRC *uint32) *testFolder {
	return &testFolder{
		coders:      []testCoder{{id: idCopy}},
		unpackSizes: []uint64{uint64(len(payload))},
		packed:      append([]byte(nil), payload...),
		subSizes:    subSizes,
		subCRCs:     subCRCs,
		folderCRC:   folderCRC,
	}
}

func crcPtr(data []byte) *uint32 {
	value := fixtureCRC(data)
	return &value
}

func int64Ptr(value int64) *int64 { return &value }
func u32Ptr(value uint32) *uint32 { return &value }

// Embedded payloads generated once during development with Python's lzma and
// bz2 modules.  Tests never invoke an external compressor for these.

const lzmaFixtureText = "LZMA and LZMA2 fixtures for the sevenz reader.\nLZMA and LZMA2 fixtures for the sevenz reader.\nLZMA and LZMA2 fixtures for the sevenz reader.\nLorem ipsum dolor sit amet, consectetur adipiscing elit.\nLorem ipsum dolor sit amet, consectetur adipiscing elit.\n"

var lzmaStreamFixture = []byte{0x00, 0x26, 0x16, 0x85, 0xbc, 0x45, 0xf0, 0xd0, 0x7e, 0x95, 0x60, 0x72, 0x7c, 0x28, 0x3f, 0x3f, 0x19, 0x77, 0x6f, 0xb4, 0xd0, 0x9a, 0x04, 0x70, 0x3e, 0x40, 0xc5, 0x6e, 0x98, 0xba, 0x83, 0xed, 0x65, 0xfa, 0x17, 0xcd, 0xbc, 0x44, 0x54, 0x7c, 0xef, 0x4c, 0x25, 0x37, 0x5c, 0x42, 0xc7, 0x24, 0xcc, 0x41, 0x74, 0xe8, 0xdc, 0xd0, 0xed, 0x75, 0x28, 0xfb, 0xd4, 0x2b, 0x8f, 0x3a, 0x45, 0x63, 0x10, 0xd1, 0xbf, 0x2c, 0x95, 0xd4, 0x22, 0x1e, 0x65, 0x71, 0xb0, 0x92, 0xcc, 0x20, 0x0a, 0x3b, 0xb9, 0xeb, 0x41, 0xeb, 0xa6, 0xb8, 0x29, 0xb7, 0x4e, 0x03, 0x57, 0x45, 0x97, 0xf3, 0x4b, 0xd0, 0x07, 0xfc, 0x2e, 0xb4, 0x15, 0xae, 0xff, 0xd1, 0x84, 0xd0, 0x00}
var lzmaPropsFixture = []byte{0x5d, 0x00, 0x00, 0x10, 0x00}
var lzma2StreamFixture = []byte{0xe0, 0x00, 0xfe, 0x00, 0x65, 0x5d, 0x00, 0x26, 0x16, 0x85, 0xbc, 0x45, 0xf0, 0xd0, 0x7e, 0x95, 0x60, 0x72, 0x7c, 0x28, 0x3f, 0x3f, 0x19, 0x77, 0x6f, 0xb4, 0xd0, 0x9a, 0x04, 0x70, 0x3e, 0x40, 0xc5, 0x6e, 0x98, 0xba, 0x83, 0xed, 0x65, 0xfa, 0x17, 0xcd, 0xbc, 0x44, 0x54, 0x7c, 0xef, 0x4c, 0x25, 0x37, 0x5c, 0x42, 0xc7, 0x24, 0xcc, 0x41, 0x74, 0xe8, 0xdc, 0xd0, 0xed, 0x75, 0x28, 0xfb, 0xd4, 0x2b, 0x8f, 0x3a, 0x45, 0x63, 0x10, 0xd1, 0xbf, 0x2c, 0x95, 0xd4, 0x22, 0x1e, 0x65, 0x71, 0xb0, 0x92, 0xcc, 0x20, 0x0a, 0x3b, 0xb9, 0xeb, 0x41, 0xeb, 0xa6, 0xb8, 0x29, 0xb7, 0x4e, 0x03, 0x57, 0x45, 0x97, 0xf3, 0x4b, 0xd0, 0x07, 0xfb, 0xe3, 0xc1, 0xe0, 0x00, 0x00}

const lzma2PropFixture byte = 16

const bzip2FixtureText = "Bzip2 payload for the Go sevenz reader.\nBzip2 payload for the Go sevenz reader.\nBzip2 payload for the Go sevenz reader.\nBzip2 payload for the Go sevenz reader.\n"

var bzip2StreamFixture = []byte{0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x9d, 0x78, 0x18, 0x00, 0x00, 0x00, 0x13, 0xdd, 0x80, 0x00, 0x10, 0x40, 0x01, 0x10, 0x00, 0x10, 0x80, 0x27, 0x65, 0xdd, 0x30, 0x20, 0x00, 0x70, 0x51, 0xa3, 0x20, 0x68, 0xd3, 0x23, 0x40, 0xaa, 0xa3, 0x40, 0xf5, 0x0d, 0x06, 0x98, 0x92, 0x20, 0x83, 0x42, 0xe7, 0x85, 0x05, 0x08, 0x37, 0x33, 0x20, 0xcc, 0x98, 0xec, 0xd8, 0xb1, 0xc9, 0x53, 0x72, 0xc4, 0xcb, 0x9c, 0x94, 0x2c, 0x54, 0xb1, 0x07, 0xa6, 0xa4, 0x8c, 0x31, 0x3c, 0x2e, 0x5c, 0xfc, 0x5d, 0xc9, 0x14, 0xe1, 0x42, 0x42, 0x75, 0xe0, 0x60, 0x00}

const deflateFixtureText = "Deflate payload through compress/flate.\nDeflate payload through compress/flate.\nDeflate payload through compress/flate.\n"

// Real archives written by 7-Zip 25.01, copied from the Rust reference's
// tests so the port is checked against bytes it did not author.

// DELTA_ARCHIVE is d.bin through -mf=Delta:4.
var deltaArchiveFixture = []byte{
	0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0x1d, 0x0e, 0x30, 0x87, 0x38, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x61,
	0x1e, 0x3f, 0xe0, 0x27, 0xff, 0x00, 0x30, 0x5d, 0x00, 0x00, 0x00, 0x52, 0x50, 0x0a, 0xa0,
	0xef, 0x9c, 0x54, 0xaa, 0x09, 0xdf, 0xd5, 0x01, 0xd3, 0xad, 0x98, 0xe2, 0x0b, 0xe0, 0x59,
	0x64, 0xf4, 0x0c, 0x83, 0x08, 0xd5, 0x5c, 0x45, 0x8f, 0xeb, 0x4c, 0x1b, 0xc8, 0x4d, 0x03,
	0xb4, 0x6a, 0x48, 0x5e, 0x3a, 0xb7, 0xef, 0xc9, 0xf3, 0x5f, 0x98, 0x00, 0x00, 0x01, 0x04,
	0x06, 0x00, 0x01, 0x09, 0x38, 0x00, 0x07, 0x0b, 0x01, 0x00, 0x02, 0x21, 0x21, 0x01, 0x03,
	0x21, 0x03, 0x01, 0x03, 0x01, 0x00, 0x0c, 0xa8, 0x00, 0xa8, 0x00, 0x00, 0x08, 0x0a, 0x01,
	0x9d, 0x3b, 0xce, 0xbb, 0x00, 0x00, 0x05, 0x01, 0x19, 0x03, 0x00, 0x00, 0x00, 0x11, 0x0d,
	0x00, 0x64, 0x00, 0x2e, 0x00, 0x62, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x14, 0x0a,
	0x01, 0x00, 0x8f, 0x00, 0x1d, 0x6b, 0x86, 0x69, 0xdd, 0x01, 0x15, 0x06, 0x01, 0x00, 0x20,
	0x00, 0x00, 0x00, 0x00, 0x00,
}

// DELTA_TEXT is the 10240-byte original: forty cycles of 0..255.
func deltaTextFixture() []byte {
	out := make([]byte, 0, 40*256)
	for cycle := 0; cycle < 40; cycle++ {
		for value := 0; value < 256; value++ {
			out = append(out, byte(value))
		}
	}
	return out
}

// BCJ_ARCHIVE is x.bin through -mf=BCJ.
var bcjArchiveFixture = []byte{
	0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0xf7, 0xd7, 0xf7, 0xb3, 0x21, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe9, 0x25,
	0x2a, 0x06, 0xe0, 0x00, 0xd6, 0x00, 0x19, 0x5d, 0x00, 0x45, 0x91, 0x3d, 0x07, 0xfb, 0x6f,
	0x24, 0x96, 0x3b, 0xf4, 0x20, 0xa2, 0x55, 0xb4, 0x0d, 0x61, 0x2c, 0x96, 0xcf, 0xd9, 0x79,
	0x01, 0xe9, 0x8c, 0x00, 0x00, 0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x21, 0x00, 0x07, 0x0b,
	0x01, 0x00, 0x02, 0x21, 0x21, 0x01, 0x00, 0x04, 0x03, 0x03, 0x01, 0x03, 0x01, 0x00, 0x0c,
	0x80, 0xd7, 0x80, 0xd7, 0x00, 0x08, 0x0a, 0x01, 0x87, 0xcd, 0x60, 0x60, 0x00, 0x00, 0x05,
	0x01, 0x19, 0x02, 0x00, 0x00, 0x11, 0x0d, 0x00, 0x78, 0x00, 0x2e, 0x00, 0x62, 0x00, 0x69,
	0x00, 0x6e, 0x00, 0x00, 0x00, 0x14, 0x0a, 0x01, 0x00, 0x8f, 0x00, 0x1d, 0x6b, 0x86, 0x69,
	0xdd, 0x01, 0x15, 0x06, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// BCJ_TEXT is the original x.bin.
func bcjTextFixture() []byte {
	out := make([]byte, 0, 20*9+5+10*3)
	for cycle := 0; cycle < 20; cycle++ {
		out = append(out, 0x8b, 0x45, 0x08, 0x83, 0xc0, 0x01, 0x89, 0x45, 0x0c)
	}
	out = append(out, []byte("hello")...)
	for cycle := 0; cycle < 10; cycle++ {
		out = append(out, 0x8b, 0x45, 0x08)
	}
	return out
}

// BCJ_CALLS_ARCHIVE is bcj3.bin through -mf=BCJ.
var bcjCallsArchiveFixture = []byte{
	0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0xf1, 0x06, 0xf2, 0xb3, 0x49, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xb1,
	0xec, 0x3e, 0xe0, 0x00, 0x49, 0x00, 0x41, 0x5d, 0x00, 0x74, 0x05, 0x3c, 0x19, 0x3d, 0xfd,
	0xa9, 0xbe, 0xd8, 0x18, 0x71, 0x19, 0xd3, 0x3a, 0xae, 0x47, 0x12, 0xbc, 0x44, 0x5d, 0x3f,
	0xfe, 0x2c, 0x12, 0x31, 0x6b, 0x71, 0x3e, 0xdf, 0x40, 0x99, 0x3f, 0x0a, 0x36, 0x48, 0xbd,
	0x74, 0xbc, 0x4e, 0xbe, 0x60, 0x32, 0xaf, 0x79, 0x95, 0x1d, 0x1d, 0xe9, 0xae, 0x8a, 0x4c,
	0x86, 0x18, 0xa0, 0xc3, 0xe6, 0xe3, 0xa4, 0x5b, 0x60, 0x73, 0xd2, 0x82, 0xe6, 0x00, 0x00,
	0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x49, 0x00, 0x07, 0x0b, 0x01, 0x00, 0x02, 0x21, 0x21,
	0x01, 0x00, 0x04, 0x03, 0x03, 0x01, 0x03, 0x01, 0x00, 0x0c, 0x4a, 0x4a, 0x00, 0x08, 0x0a,
	0x01, 0x39, 0x76, 0x10, 0xde, 0x00, 0x00, 0x05, 0x01, 0x19, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x11, 0x13, 0x00, 0x62, 0x00, 0x63, 0x00, 0x6a, 0x00, 0x33, 0x00, 0x2e, 0x00, 0x62, 0x00,
	0x69, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x19, 0x00, 0x14, 0x0a, 0x01, 0x00, 0x91, 0x23, 0x1b,
	0x3b, 0x88, 0x69, 0xdd, 0x01, 0x15, 0x06, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var bcjCallsTextFixture = []byte{
	0xe8, 0x10, 0x00, 0x00, 0x00, 0xe8, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0x34, 0x12, 0x00, 0x00,
	0xe8, 0x00, 0xff, 0x00, 0x00, 0xe9, 0xee, 0xff, 0xff, 0xff, 0xe8, 0x78, 0x56, 0x34, 0x12,
	0xe8, 0xe8, 0xe8, 0xe8, 0xe8, 0xe8, 0xe8, 0xe8, 0x8b, 0x45, 0x08, 0x83, 0xc0, 0x01, 0x89,
	0x45, 0x0c, 0xe8, 0x20, 0x00, 0x00, 0x00, 0xe8, 0x40, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c,
	0x6c, 0x6f, 0x2c, 0x20, 0x62, 0x63, 0x6a, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a,
}

// BCJ2_ARCHIVE is bcj2src.bin through -m0=BCJ2 -m1=LZMA2.
var bcj2ArchiveFixture = []byte{
	0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0xbd, 0xd5, 0x27, 0x5e, 0x54, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0x60,
	0x95, 0xf8, 0xe0, 0x00, 0x41, 0x00, 0x3e, 0x5d, 0x00, 0x74, 0x63, 0xbd, 0xff, 0xa3, 0xde,
	0x9b, 0x24, 0xd5, 0xb3, 0xdc, 0xe7, 0x0e, 0x4e, 0x07, 0x53, 0x5f, 0x84, 0x74, 0x37, 0xc7,
	0xcc, 0x12, 0xe6, 0xf1, 0xee, 0xbb, 0x2f, 0xde, 0xdd, 0xe6, 0x2d, 0x19, 0x0a, 0xb1, 0xdc,
	0xbe, 0x2b, 0x49, 0xcb, 0x7a, 0x88, 0xdd, 0x5f, 0x2b, 0x5d, 0x16, 0x70, 0x13, 0xd1, 0x5d,
	0x5f, 0xcd, 0x82, 0x08, 0xee, 0xbb, 0x5e, 0x7d, 0x49, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x15, 0x00, 0x00, 0x00, 0x07, 0x00, 0x87, 0xc1, 0xec, 0x00, 0x00, 0x01, 0x04, 0x06, 0x00,
	0x04, 0x09, 0x46, 0x04, 0x04, 0x06, 0x00, 0x07, 0x0b, 0x01, 0x00, 0x02, 0x21, 0x21, 0x01,
	0x00, 0x14, 0x03, 0x03, 0x01, 0x1b, 0x04, 0x01, 0x01, 0x00, 0x00, 0x02, 0x03, 0x04, 0x0c,
	0x42, 0x4a, 0x00, 0x08, 0x0a, 0x01, 0x39, 0x76, 0x10, 0xde, 0x00, 0x00, 0x05, 0x01, 0x19,
	0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x19, 0x00,
	0x62, 0x00, 0x63, 0x00, 0x6a, 0x00, 0x32, 0x00, 0x73, 0x00, 0x72, 0x00, 0x63, 0x00, 0x2e,
	0x00, 0x62, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x19, 0x02, 0x00, 0x00, 0x14, 0x0a,
	0x01, 0x00, 0x4e, 0x1f, 0x81, 0x32, 0x8a, 0x69, 0xdd, 0x01, 0x15, 0x06, 0x01, 0x00, 0x20,
	0x00, 0x00, 0x00, 0x00, 0x00,
}

// PPMD_ORDER6_ARCHIVE is ppmd.txt through -m0=PPMd:o6:mem1m -mx=9.
var ppmdOrder6ArchiveFixture = []byte{
	0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0x65, 0x5a, 0x8c, 0xc3, 0x6b, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x66,
	0x70, 0x9e, 0x00, 0x50, 0x01, 0xe2, 0xfb, 0xf5, 0x0e, 0xb6, 0x3e, 0x60, 0x73, 0xb8, 0x3e,
	0x5e, 0x8a, 0x97, 0x3a, 0xe6, 0x10, 0xc1, 0x71, 0xba, 0x77, 0x07, 0x3b, 0x66, 0x90, 0xc1,
	0xe6, 0x0c, 0x4e, 0xaa, 0x96, 0xfb, 0x28, 0x94, 0xad, 0x49, 0xa2, 0xe9, 0x61, 0x18, 0xba,
	0x73, 0x11, 0x5e, 0xa0, 0xda, 0xb0, 0x88, 0xf8, 0x78, 0x3d, 0x1b, 0xda, 0x85, 0xe3, 0x7e,
	0xa8, 0xbb, 0x69, 0x51, 0xc9, 0x20, 0x05, 0xdc, 0xcb, 0x38, 0xa9, 0xc6, 0xdd, 0x24, 0x76,
	0x51, 0xb8, 0xf7, 0x63, 0x80, 0x69, 0x15, 0xa7, 0x5f, 0xa6, 0xd3, 0xc7, 0x01, 0x40, 0xe3,
	0xa1, 0x00, 0x02, 0x35, 0xe1, 0x41, 0xfa, 0xe9, 0x89, 0x2d, 0x4b, 0x93, 0x24, 0xaa, 0xdf,
	0x63, 0x15, 0x80, 0x00, 0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x6b, 0x00, 0x07, 0x0b, 0x01,
	0x00, 0x01, 0x23, 0x03, 0x04, 0x01, 0x05, 0x06, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x84, 0x60,
	0x00, 0x08, 0x0a, 0x01, 0x03, 0x08, 0xbe, 0xfb, 0x00, 0x00, 0x05, 0x01, 0x19, 0x05, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x11, 0x13, 0x00, 0x70, 0x00, 0x70, 0x00, 0x6d, 0x00, 0x64, 0x00,
	0x2e, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x00, 0x00, 0x19, 0x00, 0x14, 0x0a, 0x01,
	0x00, 0x8b, 0x49, 0xdf, 0x9e, 0x8f, 0x69, 0xdd, 0x01, 0x15, 0x06, 0x01, 0x00, 0x20, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// PPMD_ORDER2_ARCHIVE is the same input through -m0=PPMd:o2:mem1m -mx=9.
var ppmdOrder2ArchiveFixture = []byte{
	0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0x20, 0xc0, 0x07, 0x6a, 0x9b, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e, 0xad,
	0xa5, 0xf7, 0x00, 0x50, 0x01, 0xe2, 0xfb, 0xf5, 0x0e, 0xb6, 0x3e, 0x60, 0x73, 0xb8, 0x3e,
	0x5e, 0x8a, 0x97, 0x3a, 0xe6, 0x10, 0xc1, 0x71, 0xba, 0x77, 0x07, 0x3b, 0x66, 0x90, 0xc1,
	0xe6, 0x0c, 0x4e, 0xaa, 0x96, 0xfa, 0xd2, 0x29, 0x5c, 0x4e, 0x01, 0x7d, 0x0b, 0x2f, 0x69,
	0xfa, 0x93, 0xee, 0x8a, 0xc9, 0x89, 0x2f, 0x5d, 0xc7, 0x5e, 0x96, 0xab, 0xb9, 0xd1, 0x30,
	0xe9, 0x90, 0xc7, 0x20, 0x3c, 0xa7, 0xd1, 0x70, 0x00, 0x04, 0x54, 0xa4, 0x56, 0xff, 0x2f,
	0x7f, 0x71, 0xec, 0x1a, 0x77, 0xd7, 0x75, 0x18, 0xd0, 0x5d, 0xd1, 0x64, 0x11, 0x40, 0x5e,
	0xb8, 0xcf, 0xe4, 0xc1, 0xcb, 0x2f, 0x35, 0x62, 0x37, 0xf3, 0x8d, 0x02, 0x3e, 0x53, 0x9f,
	0x5a, 0x5b, 0xe0, 0xc3, 0x93, 0xc6, 0x1c, 0x83, 0xa0, 0x31, 0x5f, 0x15, 0x1a, 0x3a, 0x97,
	0xc2, 0x85, 0x7d, 0x79, 0x7a, 0xb0, 0x55, 0x5c, 0xb0, 0xeb, 0xd8, 0x7c, 0x01, 0xbd, 0x39,
	0x4f, 0x25, 0x11, 0x4b, 0x35, 0x63, 0xf9, 0xf6, 0x73, 0x16, 0x6c, 0x24, 0xba, 0x89, 0x54,
	0x0d, 0x3b, 0xad, 0x02, 0xe4, 0xbd, 0x00, 0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x80, 0x9b,
	0x00, 0x07, 0x0b, 0x01, 0x00, 0x01, 0x23, 0x03, 0x04, 0x01, 0x05, 0x02, 0x00, 0x00, 0x01,
	0x00, 0x0c, 0x84, 0x60, 0x00, 0x08, 0x0a, 0x01, 0x03, 0x08, 0xbe, 0xfb, 0x00, 0x00, 0x05,
	0x01, 0x19, 0x04, 0x00, 0x00, 0x00, 0x00, 0x11, 0x13, 0x00, 0x70, 0x00, 0x70, 0x00, 0x6d,
	0x00, 0x64, 0x00, 0x2e, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x00, 0x00, 0x19, 0x00,
	0x14, 0x0a, 0x01, 0x00, 0x8b, 0x49, 0xdf, 0x9e, 0x8f, 0x69, 0xdd, 0x01, 0x15, 0x06, 0x01,
	0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// ppmdTextFixture is the 1120 bytes both PPMd archives were built from.
func ppmdTextFixture() []byte {
	var text []byte
	for line := 0; line < 14; line++ {
		text = append(text, fmt.Sprintf(
			"PPMd context %02d: the model predicts the next symbol from the symbols before it.\n",
			line)...)
	}
	return text
}

// ppmdAllocatorArchive is ppmd_1200.txt through
// -m0=PPMd:o6:mem64k -mx=9, written by 7-Zip 25.01.  The 64 KiB model is
// deliberately too small for the input, so decoding exercises the PPMd block
// allocator, its free-list glueing, model restarts and rescaling -- paths the
// two small order-6/order-2 fixtures never reach.
const ppmdAllocatorArchiveBase64 = `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
EAIAAAAAAA`

func ppmdAllocatorArchive() []byte {
	data, err := base64.StdEncoding.DecodeString(ppmdAllocatorArchiveBase64)
	if err != nil {
		panic(err)
	}
	return data
}

// ppmdAllocatorText generates the 1200 lines the allocator archive was built
// from.  The LCG and word table are the generator used to create the fixture.
func ppmdAllocatorText() []byte {
	words := strings.Fields("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima " +
		"mike november oscar papa quebec romeo sierra tango uniform victor whiskey " +
		"xray yankee zulu seven eight nine ten red green blue white black grey " +
		"north south east west spring summer autumn winter copper silver golden " +
		"river mountain forest desert island harbor valley meadow canyon")
	state := uint32(0x12345678)
	var out strings.Builder
	for line := 0; line < 1200; line++ {
		count := 6 + int(state&7)
		members := make([]string, 0, count)
		for index := 0; index < count; index++ {
			state = state*1664525 + 1013904223
			members = append(members, words[(state>>16)%uint32(len(words))])
		}
		fmt.Fprintf(&out, "line %05d: %s.\n", line, strings.Join(members, " "))
	}
	return []byte(out.String())
}

// Six real 7-Zip 25.01 filter archives over 4 KiB of crafted
// instruction-shaped data.  They pin the branch converters to the encoder
// that produced them without any external tool at test time.
var bcjFilterArchives = map[string]string{
	"arm64": `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`,
	"arm": `N3q8ryccAATl8XjEABAAAAAAAABiAAAAAAAAAJtSjQvi///r8P//6/7//+sMAADrGgAA6+j//+v2///rBAAA6xIAAOsgAADr7v//6/z//+sKAADrGAAA
6yYAAOv0///rAgAA6xAAAOseAADrLAAA6/r//+sIAADrFgAA6yQAAOsyAADrAAAA6w4AAOscAADrKgAA6zgAAOsGAADrFAAA6yIAAOswAADrPgAA6wwA
AOsaAADrKAAA6zYAAOtEAADrEgAA6yAAAOsuAADrPAAA60oAAOsYAADrJgAA6zQAAOtCAADrUAAA6x4AAOssAADrOgAA60gAAOtWAADrJAAA6zIAAOtA
AADrTgAA61wAAOsqAADrOAAA60YAAOtUAADrIgAA6zAAAOs+AADrTAAA61oAAOsoAADrNgAA60QAAOtSAADrYAAA6y4AAOs8AADrSgAA61gAAOtmAADr
NAAA60IAAOtQAADrXgAA62wAAOs6AADrSAAA61YAAOtkAADrcgAA60AAAOtOAADrXAAA62oAAOt4AADrRgAA61QAAOtiAADrcAAA634AAOtMAADrWgAA
62gAAOt2AADrhAAA61IAAOtgAADrbgAA63wAAOuKAADrWAAA62YAAOt0AADrggAA65AAAOteAADrbAAA63oAAOuIAADrlgAA62QAAOtyAADrgAAA644A
AOucAADragAA63gAAOuGAADrlAAA62IAAOtwAADrfgAA64wAAOuaAADraAAA63YAAOuEAADrkgAA66AAAOtuAADrfAAA64oAAOuYAADrpgAA63QAAOuC
AADrkAAA654AAOusAADregAA64gAAOuWAADrpAAA67IAAOuAAADrjgAA65wAAOuqAADruAAA64YAAOuUAADrogAA67AAAOu+AADrjAAA65oAAOuoAADr
tgAA68QAAOuSAADroAAA664AAOu8AADrygAA65gAAOumAADrtAAA68IAAOvQAADrngAA66wAAOu6AADryAAA69YAAOukAADrsgAA68AAAOvOAADr3AAA
66oAAOu4AADrxgAA69QAAOuiAADrsAAA674AAOvMAADr2gAA66gAAOu2AADrxAAA69IAAOvgAADrrgAA67wAAOvKAADr2AAA6+YAAOu0AADrwgAA69AA
AOveAADr7AAA67oAAOvIAADr1gAA6+QAAOvyAADrwAAA684AAOvcAADr6gAA6/gAAOvGAADr1AAA6+IAAOvwAADr/gAA68wAAOvaAADr6AAA6/YAAOsE
AQDr0gAA6+AAAOvuAADr/AAA6woBAOvYAADr5gAA6/QAAOsCAQDrEAEA694AAOvsAADr+gAA6wgBAOsWAQDr5AAA6/IAAOsAAQDrDgEA6xwBAOvqAADr
+AAA6wYBAOsUAQDr4gAA6/AAAOv+AADrDAEA6xoBAOvoAADr9gAA6wQBAOsSAQDrIAEA6+4AAOv8AADrCgEA6xgBAOsmAQDr9AAA6wIBAOsQAQDrHgEA
6ywBAOv6AADrCAEA6xYBAOskAQDrMgEA6wABAOsOAQDrHAEA6yoBAOs4AQDrBgEA6xQBAOsiAQDrMAEA6z4BAOsMAQDrGgEA6ygBAOs2AQDrRAEA6xIB
AOsgAQDrLgEA6zwBAOtKAQDrGAEA6yYBAOs0AQDrQgEA61ABAOseAQDrLAEA6zoBAOtIAQDrVgEA6yQBAOsyAQDrQAEA604BAOtcAQDrKgEA6zgBAOtG
AQDrVAEA6yIBAOswAQDrPgEA60wBAOtaAQDrKAEA6zYBAOtEAQDrUgEA62ABAOsuAQDrPAEA60oBAOtYAQDrZgEA6zQBAOtCAQDrUAEA614BAOtsAQDr
OgEA60gBAOtWAQDrZAEA63IBAOtAAQDrTgEA61wBAOtqAQDreAEA60YBAOtUAQDrYgEA63ABAOt+AQDrTAEA61oBAOtoAQDrdgEA64QBAOtSAQDrYAEA
624BAOt8AQDrigEA61gBAOtmAQDrdAEA64IBAOuQAQDrXgEA62wBAOt6AQDriAEA65YBAOtkAQDrcgEA64ABAOuOAQDrnAEA62oBAOt4AQDrhgEA65QB
AOtiAQDrcAEA634BAOuMAQDrmgEA62gBAOt2AQDrhAEA65IBAOugAQDrbgEA63wBAOuKAQDrmAEA66YBAOt0AQDrggEA65ABAOueAQDrrAEA63oBAOuI
AQDrlgEA66QBAOuyAQDrgAEA644BAOucAQDrqgEA67gBAOuGAQDrlAEA66IBAOuwAQDrvgEA64wBAOuaAQDrqAEA67YBAOvEAQDrkgEA66ABAOuuAQDr
vAEA68oBAOuYAQDrpgEA67QBAOvCAQDr0AEA654BAOusAQDrugEA68gBAOvWAQDrpAEA67IBAOvAAQDrzgEA69wBAOuqAQDruAEA68YBAOvUAQDrogEA
67ABAOu+AQDrzAEA69oBAOuoAQDrtgEA68QBAOvSAQDr4AEA664BAOu8AQDrygEA69gBAOvmAQDrtAEA68IBAOvQAQDr3gEA6+wBAOu6AQDryAEA69YB
AOvkAQDr8gEA68ABAOvOAQDr3AEA6+oBAOv4AQDrxgEA69QBAOviAQDr8AEA6/4BAOvMAQDr2gEA6+gBAOv2AQDrBAIA69IBAOvgAQDr7gEA6/wBAOsK
AgDr2AEA6+YBAOv0AQDrAgIA6xACAOveAQDr7AEA6/oBAOsIAgDrFgIA6+QBAOvyAQDrAAIA6w4CAOscAgDr6gEA6/gBAOsGAgDrFAIA6+IBAOvwAQDr
/gEA6wwCAOsaAgDr6AEA6/YBAOsEAgDrEgIA6yACAOvuAQDr/AEA6woCAOsYAgDrJgIA6/QBAOsCAgDrEAIA6x4CAOssAgDr+gEA6wgCAOsWAgDrJAIA
6zICAOsAAgDrDgIA6xwCAOsqAgDrOAIA6wYCAOsUAgDrIgIA6zACAOs+AgDrDAIA6xoCAOsoAgDrNgIA60QCAOsSAgDrIAIA6y4CAOs8AgDrSgIA6xgC
AOsmAgDrNAIA60ICAOtQAgDrHgIA6ywCAOs6AgDrSAIA61YCAOskAgDrMgIA60ACAOtOAgDrXAIA6yoCAOs4AgDrRgIA61QCAOsiAgDrMAIA6z4CAOtM
AgDrWgIA6ygCAOs2AgDrRAIA61ICAOtgAgDrLgIA6zwCAOtKAgDrWAIA62YCAOs0AgDrQgIA61ACAOteAgDrbAIA6zoCAOtIAgDrVgIA62QCAOtyAgDr
QAIA604CAOtcAgDragIA63gCAOtGAgDrVAIA62ICAOtwAgDrfgIA60wCAOtaAgDraAIA63YCAOuEAgDrUgIA62ACAOtuAgDrfAIA64oCAOtYAgDrZgIA
63QCAOuCAgDrkAIA614CAOtsAgDregIA64gCAOuWAgDrZAIA63ICAOuAAgDrjgIA65wCAOtqAgDreAIA64YCAOuUAgDrYgIA63ACAOt+AgDrjAIA65oC
AOtoAgDrdgIA64QCAOuSAgDroAIA624CAOt8AgDrigIA65gCAOumAgDrdAIA64ICAOuQAgDrngIA66wCAOt6AgDriAIA65YCAOukAgDrsgIA64ACAOuO
AgDrnAIA66oCAOu4AgDrhgIA65QCAOuiAgDrsAIA674CAOuMAgDrmgIA66gCAOu2AgDrxAIA65ICAOugAgDrrgIA67wCAOvKAgDrmAIA66YCAOu0AgDr
wgIA69ACAOueAgDrrAIA67oCAOvIAgDr1gIA66QCAOuyAgDrwAIA684CAOvcAgDrqgIA67gCAOvGAgDr1AIA66ICAOuwAgDrvgIA68wCAOvaAgDrqAIA
67YCAOvEAgDr0gIA6+ACAOuuAgDrvAIA68oCAOvYAgDr5gIA67QCAOvCAgDr0AIA694CAOvsAgDrugIA68gCAOvWAgDr5AIA6/ICAOvAAgDrzgIA69wC
AOvqAgDr+AIA68YCAOvUAgDr4gIA6/ACAOv+AgDrzAIA69oCAOvoAgDr9gIA6wQDAOvSAgDr4AIA6+4CAOv8AgDrCgMA69gCAOvmAgDr9AIA6wIDAOsQ
AwDr3gIA6+wCAOv6AgDrCAMA6xYDAOvkAgDr8gIA6wADAOsOAwDrHAMA6+oCAOv4AgDrBgMA6xQDAOviAgDr8AIA6/4CAOsMAwDrGgMA6+gCAOv2AgDr
BAMA6xIDAOsgAwDr7gIA6/wCAOsKAwDrGAMA6yYDAOv0AgDrAgMA6xADAOseAwDrLAMA6/oCAOsIAwDrFgMA6yQDAOsyAwDrAAMA6w4DAOscAwDrKgMA
6zgDAOsGAwDrFAMA6yIDAOswAwDrPgMA6wwDAOsaAwDrKAMA6zYDAOtEAwDrEgMA6yADAOsuAwDrPAMA60oDAOsYAwDrJgMA6zQDAOtCAwDrUAMA6x4D
AOssAwDrOgMA60gDAOtWAwDrJAMA6zIDAOtAAwDrTgMA61wDAOsqAwDrOAMA60YDAOtUAwDrIgMA6zADAOs+AwDrTAMA61oDAOsoAwDrNgMA60QDAOtS
AwDrYAMA6y4DAOs8AwDrSgMA61gDAOtmAwDrNAMA60IDAOtQAwDrXgMA62wDAOs6AwDrSAMA61YDAOtkAwDrcgMA60ADAOtOAwDrXAMA62oDAOt4AwDr
RgMA61QDAOtiAwDrcAMA634DAOtMAwDrWgMA62gDAOt2AwDrhAMA61IDAOtgAwDrbgMA63wDAOuKAwDrWAMA62YDAOt0AwDrggMA65ADAOteAwDrbAMA
63oDAOuIAwDrlgMA62QDAOtyAwDrgAMA644DAOucAwDragMA63gDAOuGAwDrlAMA62IDAOtwAwDrfgMA64wDAOuaAwDraAMA63YDAOuEAwDrkgMA66AD
AOtuAwDrfAMA64oDAOuYAwDrpgMA63QDAOuCAwDrkAMA654DAOusAwDregMA64gDAOuWAwDrpAMA67IDAOuAAwDrjgMA65wDAOuqAwDruAMA64YDAOuU
AwDrogMA67ADAOu+AwDrjAMA65oDAOuoAwDrtgMA68QDAOuSAwDroAMA664DAOu8AwDrygMA65gDAOumAwDrtAMA68IDAOvQAwDrngMA66wDAOu6AwDr
yAMA69YDAOukAwDrsgMA68ADAOvOAwDr3AMA66oDAOu4AwDrxgMA69QDAOuiAwDrsAMA674DAOvMAwDr2gMA66gDAOu2AwDrxAMA69IDAOvgAwDrrgMA
67wDAOvKAwDr2AMA6+YDAOu0AwDrwgMA69ADAOveAwDr7AMA67oDAOvIAwDr1gMA6+QDAOvyAwDrwAMA684DAOvcAwDr6gMA6/gDAOvGAwDr1AMA6+ID
AOvwAwDr/gMA68wDAOvaAwDr6AMA6/YDAOsEBADr0gMA6+ADAOvuAwDr/AMA6woEAOvYAwDr5gMA6/QDAOsCBADrEAQA694DAOvsAwDr+gMA6wgEAOsW
BADr5AMA6/IDAOsABADrDgQA6xwEAOvqAwDr+AMA6wYEAOsUBADrAQQGAAEJkAAABwsBAAEEAwMFAQyQAAAICgEtNMpuAAAFARkJAAAAAAAAAAAAERkA
YgBjAGoAXwBhAHIAbQAuAGIAaQBuAAAAGQIAABQKAQCdM2XiUnbdARUGAQAgAAAAAAA=`,
	"ppc": `N3q8ryccAAQm4eTlABAAAAAAAABiAAAAAAAAAPFbPJpL//+BS///uUv///FIAAApSAAAYUv//5lL///RSAAACUgAAEFIAAB5S///sUv//+lIAAAhSAAA
WUgAAJFL///JSAAAAUgAADlIAABxSAAAqUv//+FIAAAZSAAAUUgAAIlIAADBS///+UgAADFIAABpSAAAoUgAANlIAAARSAAASUgAAIFIAAC5SAAA8UgA
AClIAABhSAAAmUgAANFIAAEJSAAAQUgAAHlIAACxSAAA6UgAASFIAABZSAAAkUgAAMlIAAEBSAABOUgAAHFIAACpSAAA4UgAARlIAAFRSAAAiUgAAMFI
AAD5SAABMUgAAWlIAAChSAAA2UgAARFIAAFJSAAAgUgAALlIAADxSAABKUgAAWFIAACZSAAA0UgAAQlIAAFBSAABeUgAALFIAADpSAABIUgAAVlIAAGR
SAAAyUgAAQFIAAE5SAABcUgAAalIAADhSAABGUgAAVFIAAGJSAABwUgAAPlIAAExSAABaUgAAaFIAAHZSAABEUgAAUlIAAGBSAABuUgAAfFIAAEpSAAB
YUgAAZlIAAHRSAACCUgAAUFIAAF5SAABsUgAAelIAAIhSAABWUgAAZFIAAHJSAACAUgAAjlIAAFxSAABqUgAAeFIAAIZSAACUUgAAYlIAAHBSAAB+UgA
AjFIAAJpSAABoUgAAdlIAAIRSAACSUgAAYFIAAG5SAAB8UgAAilIAAJhSAABmUgAAdFIAAIJSAACQUgAAnlIAAGxSAAB6UgAAiFIAAJZSAACkUgAAclI
AAIBSAACOUgAAnFIAAKpSAAB4UgAAhlIAAJRSAACiUgAAsFIAAH5SAACMUgAAmlIAAKhSAAC2UgAAhFIAAJJSAACgUgAArlIAALxSAACKUgAAmFIAAKZ
SAAC0UgAAwlIAAJBSAACeUgAArFIAALpSAADIUgAAllIAAKRSAACyUgAAwFIAAM5SAACcUgAAqlIAALhSAADGUgAA1FIAAKJSAACwUgAAvlIAAMxSAAD
aUgAAqFIAALZSAADEUgAA0lIAAKBSAACuUgAAvFIAAMpSAADYUgAAplIAALRSAADCUgAA0FIAAN5SAACsUgAAulIAAMhSAADWUgAA5FIAALJSAADAUgA
AzlIAANxSAADqUgAAuFIAAMZSAADUUgAA4lIAAPBSAAC+UgAAzFIAANpSAADoUgAA9lIAAMRSAADSUgAA4FIAAO5SAAD8UgAAylIAANhSAADmUgAA9FI
AAQJSAADQUgAA3lIAAOxSAAD6UgABCFIAANZSAADkUgAA8lIAAQBSAAEOUgAA3FIAAOpSAAD4UgABBlIAARRSAADiUgAA8FIAAP5SAAEMUgABGlIAAOh
SAAD2UgABBFIAARJSAADgUgAA7lIAAPxSAAEKUgABGFIAAOZSAAD0UgABAlIAARBSAAEeUgAA7FIAAPpSAAEIUgABFlIAASRSAADyUgABAFIAAQ5SAAE
cUgABKlIAAPhSAAEGUgABFFIAASJSAAEwUgAA/lIAAQxSAAEaUgABKFIAATZSAAEEUgABElIAASBSAAEuUgABPFIAAQpSAAEYUgABJlIAATRSAAFCUgA
BEFIAAR5SAAEsUgABOlIAAUhSAAEWUgABJFIAATJSAAFAUgABTlIAARxSAAEqUgABOFIAAUZSAAFUUgABIlIAATBSAAE+UgABTFIAAVpSAAEoUgABNlI
AAURSAAFSUgABIFIAAS5SAAE8UgABSlIAAVhSAAEmUgABNFIAAUJSAAFQUgABXlIAASxSAAE6UgABSFIAAVZSAAFkUgABMlIAAUBSAAFOUgABXFIAAWp
SAAE4UgABRlIAAVRSAAFiUgABcFIAAT5SAAFMUgABWlIAAWhSAAF2UgABRFIAAVJSAAFgUgABblIAAXxSAAFKUgABWFIAAWZSAAF0UgABglIAAVBSAAF
eUgABbFIAAXpSAAGIUgABVlIAAWRSAAFyUgABgFIAAY5SAAFcUgABalIAAXhSAAGGUgABlFIAAWJSAAFwUgABflIAAYxSAAGaUgABaFIAAXZSAAGEUgA
BklIAAWBSAAFuUgABfFIAAYpSAAGYUgABZlIAAXRSAAGCUgABkFIAAZ5SAAFsUgABelIAAYhSAAGWUgABpFIAAXJSAAGAUgABjlIAAZxSAAGqUgABeFI
AAYZSAAGUUgABolIAAbBSAAF+UgABjFIAAZpSAAGoUgABtlIAAYRSAAGSUgABoFIAAa5SAAG8UgABilIAAZhSAAGmUgABtFIAAcJSAAGQUgABnlIAAax
SAAG6UgAByFIAAZZSAAGkUgABslIAAcBSAAHOUgABnFIAAapSAAG4UgABxlIAAdRSAAGiUgABsFIAAb5SAAHMUgAB2lIAAahSAAG2UgABxFIAAdJSAAG
gUgABrlIAAbxSAAHKUgAB2FIAAaZSAAG0UgABwlIAAdBSAAHeUgABrFIAAbpSAAHIUgAB1lIAAeRSAAGyUgABwFIAAc5SAAHcUgAB6lIAAbhSAAHGUgA
B1FIAAeJSAAHwUgABvlIAAcxSAAHaUgAB6FIAAfZSAAHEUgAB0lIAAeBSAAHuUgAB/FIAAcpSAAHYUgAB5lIAAfRSAAICUgAB0FIAAd5SAAHsUgAB+lI
AAghSAAHWUgAB5FIAAfJSAAIAUgACDlIAAdxSAAHqUgAB+FIAAgZSAAIUUgAB4lIAAfBSAAH+UgACDFIAAhpSAAHoUgAB9lIAAgRSAAISUgAB4FIAAe5
SAAH8UgACClIAAhhSAAHmUgAB9FIAAgJSAAIQUgACHlIAAexSAAH6UgACCFIAAhZSAAIkUgAB8lIAAgBSAAIOUgACHFIAAipSAAH4UgACBlIAAhRSAAI
iUgACMFIAAf5SAAIMUgACGlIAAihSAAI2UgACBFIAAhJSAAIgUgACLlIAAjxSAAIKUgACGFIAAiZSAAI0UgACQlIAAhBSAAIeUgACLFIAAjpSAAJIUgA
CFlIAAiRSAAIyUgACQFIAAk5SAAIcUgACKlIAAjhSAAJGUgACVFIAAiJSAAIwUgACPlIAAkxSAAJaUgACKFIAAjZSAAJEUgACUlIAAiBSAAIuUgACPFI
AAkpSAAJYUgACJlIAAjRSAAJCUgACUFIAAl5SAAIsUgACOlIAAkhSAAJWUgACZFIAAjJSAAJAUgACTlIAAlxSAAJqUgACOFIAAkZSAAJUUgACYlIAAnB
SAAI+UgACTFIAAlpSAAJoUgACdlIAAkRSAAJSUgACYFIAAm5SAAJ8UgACSlIAAlhSAAJmUgACdFIAAoJSAAJQUgACXlIAAmxSAAJ6UgACiFIAAlZSAAJ
kUgACclIAAoBSAAKOUgACXFIAAmpSAAJ4UgAChlIAApRSAAJiUgACcFIAAn5SAAKMUgACmlIAAmhSAAJ2UgAChFIAApJSAAJgUgACblIAAnxSAAKKUgA
CmFIAAmZSAAJ0UgACglIAApBSAAKeUgACbFIAAnpSAAKIUgACllIAAqRSAAJyUgACgFIAAo5SAAKcUgACqlIAAnhSAAKGUgAClFIAAqJSAAKwUgACflI
AAoxSAAKaUgACqFIAArZSAAKEUgACklIAAqBSAAKuUgACvFIAAopSAAKYUgACplIAArRSAALCUgACkFIAAp5SAAKsUgACulIAAshSAAKWUgACpFIAArJ
SAALAUgACzlIAApxSAAKqUgACuFIAAsZSAALUUgAColIAArBSAAK+UgACzFIAAtpSAAKoUgACtlIAAsRSAALSUgACoFIAAq5SAAK8UgACylIAAthSAAK
mUgACtFIAAsJSAALQUgAC3lIAAqxSAAK6UgACyFIAAtZSAALkUgACslIAAsBSAALOUgAC3FIAAupSAAK4UgACxlIAAtRSAALiUgAC8FIAAr5SAALMUgA
C2lIAAuhSAAL2UgACxFIAAtJSAALgUgAC7lIAAvxSAALKUgAC2FIAAuZSAAL0UgADAlIAAtBSAALeUgAC7FIAAvpSAAMIUgAC1lIAAuRSAALyUgADAFI
AAw5SAALcUgAC6lIAAvhSAAMGUgADFFIAAuJSAALwUgAC/lIAAwxSAAMaUgAC6FIAAvZSAAMEUgADElIAAuBSAALuUgAC/FIAAwpSAAMYUgAC5lIAAvR
SAAMCUgADEFIAAx5SAALsUgAC+lIAAwhSAAMWUgADJFIAAvJSAAMAUgADDlIAAxxSAAMqUgAC+FIAAwZSAAMUUgADIlIAAzBSAAL+UgADDFIAAxpSAAM
oUgADNlIAAwRSAAMSUgADIFIAAy5SAAM8UgADClIAAxhSAAMmUgADNFIAA0JSAAMQUgADHlIAAyxSAAM6UgADSFIAAxZSAAMkUgADMlIAA0BSAANOUgA
DHFIAAypSAAM4UgADRlIAA1RSAAMiUgADMFIAAz5SAANMUgADWlIAAyhSAAM2UgADRFIAA1JSAAMgUgADLlIAAzxSAANKUgADWFIAAyZSAAM0UgADQlI
AA1BSAANeUgADLFIAAzpSAANIUgADVlIAA2RSAAMyUgADQFIAA05SAANcUgADalIAAzhSAANGUgADVFIAA2JSAANwUgADPlIAA0xSAANaUgADaFIAA3Z
SAANEUgADUlIAA2BSAANuUgADfFIAA0pSAANYUgADZlIAA3RSAAOCUgADUFIAA15SAANsUgADelIAA4hSAANWUgADZFIAA3JSAAOAUgADjlIAA1xSAAN
qUgADeFIAA4ZSAAOUUgADYlIAA3BSAAN+UgADjFIAA5pSAANoUgADdlIAA4RSAAOSUgADYFIAA25SAAN8UgADilIAA5hSAANmUgADdFIAA4JSAAOQUgA
DnlIAA2xSAAN6UgADiFIAA5ZSAAOkUgADclIAA4BSAAOOUgADnFIAA6pSAAN4UgADhlIAA5RSAAOiUgADsFIAA35SAAOMUgADmlIAA6hSAAO2UgADhFI
AA5JSAAOgUgADrlIAA7xSAAOKUgADmFIAA6ZSAAO0UgADwlIAA5BSAAOeUgADrFIAA7pSAAPIUgADllIAA6RSAAOyUgADwFIAA85SAAOcUgADqlIAA7h
SAAPGUgAD1FIAA6JSAAOwUgADvlIAA8xSAAPaUgADqFIAA7ZSAAPEUgAD0lIAA6BSAAOuUgADvFIAA8pSAAPYUgADplIAA7RSAAPCUgAD0FIAA95SAAO
sUgADulIAA8hSAAPWUgAD5FIAA7JSAAPAUgADzlIAA9xSAAPqUgADuFIAA8ZSAAPUUgAD4lIAA/BSAAO+UgADzFIAA9pSAAPoUgAD9lIAA8RSAAPSUgA
D4FIAA+5SAAP8UgADylIAA9hSAAPmUgAD9FIABAJSAAPQUgAD3lIAA+xSAAP6UgAECFIAA9ZSAAPkUgAD8lIABABSAAQOUgAD3FIAA+pSAAP4UgAEBlI
ABBRSAAPiUgAD8FIAA/5SAAQMUgAEGlIAA+hSAAP2UgAEBFIABBJAQQGAAEJkAAABwsBAAEEAwMCBQyQAAAICgFm9TkBAAAFARkJAAAAAAAAAAAAERkA
YgBjAGoAXwBwAHAAYwAuAGIAaQBuAAAAGQIAABQKAQC4Y2biUnbdARUGAQAgAAAAAAA=`,
	"sparc": `N3q8ryccAASQKe1qABAAAAAAAABiAAAAAAAAABj3Dgx////gf///7n////xAAAAKQAAAGH///+Z////0QAAAAkAAABBAAAAef///7H////pAAAAIQAAA
FkAAACR////yQAAAAEAAAA5AAAAcQAAAKn////hAAAAGQAAAFEAAACJAAAAwf////kAAAAxAAAAaQAAAKEAAADZAAAAEQAAAEkAAACBAAAAuQAAAPEAA
AApAAAAYQAAAJkAAADRAAABCQAAAEEAAAB5AAAAsQAAAOkAAAEhAAAAWQAAAJEAAADJAAABAQAAATkAAABxAAAAqQAAAOEAAAEZAAABUQAAAIkAAADBA
AAA+QAAATEAAAFpAAAAoQAAANkAAAERAAABSQAAAIEAAAC5AAAA8QAAASkAAAFhAAAAmQAAANEAAAEJAAABQQAAAXkAAACxAAAA6QAAASEAAAFZAAABk
QAAAMkAAAEBAAABOQAAAXEAAAGpAAAA4QAAARkAAAFRAAABiQAAAcEAAAD5AAABMQAAAWkAAAGhAAAB2QAAAREAAAFJAAABgQAAAbkAAAHxAAABKQAAA
WEAAAGZAAAB0QAAAgkAAAFBAAABeQAAAbEAAAHpAAACIQAAAVkAAAGRAAAByQAAAgEAAAI5AAABcQAAAakAAAHhAAACGQAAAlEAAAGJAAABwQAAAfkAA
AIxAAACaQAAAaEAAAHZAAACEQAAAkkAAAGBAAABuQAAAfEAAAIpAAACYQAAAZkAAAHRAAACCQAAAkEAAAJ5AAABsQAAAekAAAIhAAACWQAAApEAAAHJA
AACAQAAAjkAAAJxAAACqQAAAeEAAAIZAAACUQAAAokAAALBAAAB+QAAAjEAAAJpAAACoQAAAtkAAAIRAAACSQAAAoEAAAK5AAAC8QAAAikAAAJhAAACm
QAAAtEAAAMJAAACQQAAAnkAAAKxAAAC6QAAAyEAAAJZAAACkQAAAskAAAMBAAADOQAAAnEAAAKpAAAC4QAAAxkAAANRAAACiQAAAsEAAAL5AAADMQAAA
2kAAAKhAAAC2QAAAxEAAANJAAACgQAAArkAAALxAAADKQAAA2EAAAKZAAAC0QAAAwkAAANBAAADeQAAArEAAALpAAADIQAAA1kAAAORAAACyQAAAwEAA
AM5AAADcQAAA6kAAALhAAADGQAAA1EAAAOJAAADwQAAAvkAAAMxAAADaQAAA6EAAAPZAAADEQAAA0kAAAOBAAADuQAAA/EAAAMpAAADYQAAA5kAAAPRA
AAECQAAA0EAAAN5AAADsQAAA+kAAAQhAAADWQAAA5EAAAPJAAAEAQAABDkAAANxAAADqQAAA+EAAAQZAAAEUQAAA4kAAAPBAAAD+QAABDEAAARpAAADo
QAAA9kAAAQRAAAESQAAA4EAAAO5AAAD8QAABCkAAARhAAADmQAAA9EAAAQJAAAEQQAABHkAAAOxAAAD6QAABCEAAARZAAAEkQAAA8kAAAQBAAAEOQAAB
HEAAASpAAAD4QAABBkAAARRAAAEiQAABMEAAAP5AAAEMQAABGkAAAShAAAE2QAABBEAAARJAAAEgQAABLkAAATxAAAEKQAABGEAAASZAAAE0QAABQkAA
ARBAAAEeQAABLEAAATpAAAFIQAABFkAAASRAAAEyQAABQEAAAU5AAAEcQAABKkAAAThAAAFGQAABVEAAASJAAAEwQAABPkAAAUxAAAFaQAABKEAAATZA
AAFEQAABUkAAASBAAAEuQAABPEAAAUpAAAFYQAABJkAAATRAAAFCQAABUEAAAV5AAAEsQAABOkAAAUhAAAFWQAABZEAAATJAAAFAQAABTkAAAVxAAAFq
QAABOEAAAUZAAAFUQAABYkAAAXBAAAE+QAABTEAAAVpAAAFoQAABdkAAAURAAAFSQAABYEAAAW5AAAF8QAABSkAAAVhAAAFmQAABdEAAAYJAAAFQQAAB
XkAAAWxAAAF6QAABiEAAAVZAAAFkQAABckAAAYBAAAGOQAABXEAAAWpAAAF4QAABhkAAAZRAAAFiQAABcEAAAX5AAAGMQAABmkAAAWhAAAF2QAABhEAA
AZJAAAFgQAABbkAAAXxAAAGKQAABmEAAAWZAAAF0QAABgkAAAZBAAAGeQAABbEAAAXpAAAGIQAABlkAAAaRAAAFyQAABgEAAAY5AAAGcQAABqkAAAXhA
AAGGQAABlEAAAaJAAAGwQAABfkAAAYxAAAGaQAABqEAAAbZAAAGEQAABkkAAAaBAAAGuQAABvEAAAYpAAAGYQAABpkAAAbRAAAHCQAABkEAAAZ5AAAGs
QAABukAAAchAAAGWQAABpEAAAbJAAAHAQAABzkAAAZxAAAGqQAABuEAAAcZAAAHUQAABokAAAbBAAAG+QAABzEAAAdpAAAGoQAABtkAAAcRAAAHSQAAB
oEAAAa5AAAG8QAABykAAAdhAAAGmQAABtEAAAcJAAAHQQAAB3kAAAaxAAAG6QAAByEAAAdZAAAHkQAABskAAAcBAAAHOQAAB3EAAAepAAAG4QAABxkAA
AdRAAAHiQAAB8EAAAb5AAAHMQAAB2kAAAehAAAH2QAABxEAAAdJAAAHgQAAB7kAAAfxAAAHKQAAB2EAAAeZAAAH0QAACAkAAAdBAAAHeQAAB7EAAAfpA
AAIIQAAB1kAAAeRAAAHyQAACAEAAAg5AAAHcQAAB6kAAAfhAAAIGQAACFEAAAeJAAAHwQAAB/kAAAgxAAAIaQAAB6EAAAfZAAAIEQAACEkAAAeBAAAHu
QAAB/EAAAgpAAAIYQAAB5kAAAfRAAAICQAACEEAAAh5AAAHsQAAB+kAAAghAAAIWQAACJEAAAfJAAAIAQAACDkAAAhxAAAIqQAAB+EAAAgZAAAIUQAAC
IkAAAjBAAAH+QAACDEAAAhpAAAIoQAACNkAAAgRAAAISQAACIEAAAi5AAAI8QAACCkAAAhhAAAImQAACNEAAAkJAAAIQQAACHkAAAixAAAI6QAACSEAA
AhZAAAIkQAACMkAAAkBAAAJOQAACHEAAAipAAAI4QAACRkAAAlRAAAIiQAACMEAAAj5AAAJMQAACWkAAAihAAAI2QAACREAAAlJAAAIgQAACLkAAAjxA
AAJKQAACWEAAAiZAAAI0QAACQkAAAlBAAAJeQAACLEAAAjpAAAJIQAACVkAAAmRAAAIyQAACQEAAAk5AAAJcQAACakAAAjhAAAJGQAACVEAAAmJAAAJw
QAACPkAAAkxAAAJaQAACaEAAAnZAAAJEQAACUkAAAmBAAAJuQAACfEAAAkpAAAJYQAACZkAAAnRAAAKCQAACUEAAAl5AAAJsQAACekAAAohAAAJWQAAC
ZEAAAnJAAAKAQAACjkAAAlxAAAJqQAACeEAAAoZAAAKUQAACYkAAAnBAAAJ+QAACjEAAAppAAAJoQAACdkAAAoRAAAKSQAACYEAAAm5AAAJ8QAACikAA
AphAAAJmQAACdEAAAoJAAAKQQAACnkAAAmxAAAJ6QAACiEAAApZAAAKkQAACckAAAoBAAAKOQAACnEAAAqpAAAJ4QAAChkAAApRAAAKiQAACsEAAAn5A
AAKMQAACmkAAAqhAAAK2QAAChEAAApJAAAKgQAACrkAAArxAAAKKQAACmEAAAqZAAAK0QAACwkAAApBAAAKeQAACrEAAArpAAALIQAAClkAAAqRAAAKy
QAACwEAAAs5AAAKcQAACqkAAArhAAALGQAAC1EAAAqJAAAKwQAACvkAAAsxAAALaQAACqEAAArZAAALEQAAC0kAAAqBAAAKuQAACvEAAAspAAALYQAAC
pkAAArRAAALCQAAC0EAAAt5AAAKsQAACukAAAshAAALWQAAC5EAAArJAAALAQAACzkAAAtxAAALqQAACuEAAAsZAAALUQAAC4kAAAvBAAAK+QAACzEAA
AtpAAALoQAAC9kAAAsRAAALSQAAC4EAAAu5AAAL8QAACykAAAthAAALmQAAC9EAAAwJAAALQQAAC3kAAAuxAAAL6QAADCEAAAtZAAALkQAAC8kAAAwBA
AAMOQAAC3EAAAupAAAL4QAADBkAAAxRAAALiQAAC8EAAAv5AAAMMQAADGkAAAuhAAAL2QAADBEAAAxJAAALgQAAC7kAAAvxAAAMKQAADGEAAAuZAAAL0
QAADAkAAAxBAAAMeQAAC7EAAAvpAAAMIQAADFkAAAyRAAALyQAADAEAAAw5AAAMcQAADKkAAAvhAAAMGQAADFEAAAyJAAAMwQAAC/kAAAwxAAAMaQAAD
KEAAAzZAAAMEQAADEkAAAyBAAAMuQAADPEAAAwpAAAMYQAADJkAAAzRAAANCQAADEEAAAx5AAAMsQAADOkAAA0hAAAMWQAADJEAAAzJAAANAQAADTkAA
AxxAAAMqQAADOEAAA0ZAAANUQAADIkAAAzBAAAM+QAADTEAAA1pAAAMoQAADNkAAA0RAAANSQAADIEAAAy5AAAM8QAADSkAAA1hAAAMmQAADNEAAA0JA
AANQQAADXkAAAyxAAAM6QAADSEAAA1ZAAANkQAADMkAAA0BAAANOQAADXEAAA2pAAAM4QAADRkAAA1RAAANiQAADcEAAAz5AAANMQAADWkAAA2hAAAN2
QAADREAAA1JAAANgQAADbkAAA3xAAANKQAADWEAAA2ZAAAN0QAADgkAAA1BAAANeQAADbEAAA3pAAAOIQAADVkAAA2RAAANyQAADgEAAA45AAANcQAAD
akAAA3hAAAOGQAADlEAAA2JAAANwQAADfkAAA4xAAAOaQAADaEAAA3ZAAAOEQAADkkAAA2BAAANuQAADfEAAA4pAAAOYQAADZkAAA3RAAAOCQAADkEAA
A55AAANsQAADekAAA4hAAAOWQAADpEAAA3JAAAOAQAADjkAAA5xAAAOqQAADeEAAA4ZAAAOUQAADokAAA7BAAAN+QAADjEAAA5pAAAOoQAADtkAAA4RA
AAOSQAADoEAAA65AAAO8QAADikAAA5hAAAOmQAADtEAAA8JAAAOQQAADnkAAA6xAAAO6QAADyEAAA5ZAAAOkQAADskAAA8BAAAPOQAADnEAAA6pAAAO4
QAADxkAAA9RAAAOiQAADsEAAA75AAAPMQAAD2kAAA6hAAAO2QAADxEAAA9JAAAOgQAADrkAAA7xAAAPKQAAD2EAAA6ZAAAO0QAADwkAAA9BAAAPeQAAD
rEAAA7pAAAPIQAAD1kAAA+RAAAOyQAADwEAAA85AAAPcQAAD6kAAA7hAAAPGQAAD1EAAA+JAAAPwQAADvkAAA8xAAAPaQAAD6EAAA/ZAAAPEQAAD0kAA
A+BAAAPuQAAD/EAAA8pAAAPYQAAD5kAAA/RAAAQCQAAD0EAAA95AAAPsQAAD+kAABAhAAAPWQAAD5EAAA/JAAAQAQAAEDkAAA9xAAAPqQAAD+EAABAZA
AAQUQAAD4kAAA/BAAAP+QAAEDEAABBpAAAPoQAAD9kAABARAAAQSAQQGAAEJkAAABwsBAAEEAwMIBQyQAAAICgG2Nrf4AAAFARkJAAAAAAAAAAAAER0A
YgBjAGoAXwBzAHAAYQByAGMALgBiAGkAbgAAABQKAQBxP2fiUnbdARUGAQAgAAAAAAA=`,
	"armt": `N3q8ryccAAR09dYxABAAAAAAAABiAAAAAAAAAG2gJ/cA8AL4APAp+ADwUPgA8Hf4APCe+ADwxfgA8Oz4APAT+QDwOvkA8GH5APCI+QDwr/kA8Nb5APD9
+QDwJPoA8Ev6APBy+gDwmfoA8MD6APDn+gDwDvsA8DX7APBc+wDwg/sA8Kr7APDR+wDw+PsA8B/8APBG/ADwbfwA8JT8APC7/ADw4vwA8An9APAw/QDw
V/0A8H79APCl/QDwzP0A8PP9APAa/gDwQf4A8Gj+APCP/gDwtv4A8N3+APAE/wDwK/8A8FL/APB5/wDwoP8A8Mf/APDu/wHwFfgB8Dz4AfBj+AHwivgB
8LH4AfDY+AHw//gB8Cb5AfBN+QHwdPkB8Jv5AfDC+QHw6fkB8BD6AfA3+gHwXvoB8IX6AfCs+gHw0/oB8Pr6AfAh+wHwSPsB8G/7AfCW+wHwvfsB8OT7
AfAL/AHwMvwB8Fn8AfCA/AHwp/wB8M78AfD1/AHwHP0B8EP9AfBq/QHwkf0B8Lj9AfDf/QHwBv4B8C3+AfBU/gHwe/4B8KL+AfDJ/gHw8P4B8Bf/AfA+
/wHwZf8B8Iz/AfCz/wHw2v8C8AH4AvAo+ALwT/gC8Hb4AvCd+ALwxPgC8Ov4AvAS+QLwOfkC8GD5AvCH+QLwrvkC8NX5AvD8+QLwI/oC8Er6AvBx+gLw
mPoC8L/6AvDm+gLwDfsC8DT7AvBb+wLwgvsC8Kn7AvDQ+wLw9/sC8B78AvBF/ALwbPwC8JP8AvC6/ALw4fwC8Aj9AvAv/QLwVv0C8H39AvCk/QLwy/0C
8PL9AvAZ/gLwQP4C8Gf+AvCO/gLwtf4C8Nz+AvAD/wLwKv8C8FH/AvB4/wLwn/8C8Mb/AvDt/wPwFPgD8Dv4A/Bi+APwifgD8LD4A/DX+APw/vgD8CX5
A/BM+QPwc/kD8Jr5A/DB+QPw6PkD8A/6A/A2+gPwXfoD8IT6A/Cr+gPw0voD8Pn6A/Ag+wPwR/sD8G77A/CV+wPwvPsD8OP7A/AK/APwMfwD8Fj8A/B/
/APwpvwD8M38A/D0/APwG/0D8EL9A/Bp/QPwkP0D8Lf9A/De/QPwBf4D8Cz+A/BT/gPwev4D8KH+A/DI/gPw7/4D8Bb/A/A9/wPwZP8D8Iv/A/Cy/wPw
2f8E8AD4BPAn+ATwTvgE8HX4BPCc+ATww/gE8Or4BPAR+QTwOPkE8F/5BPCG+QTwrfkE8NT5BPD7+QTwIvoE8En6BPBw+gTwl/oE8L76BPDl+gTwDPsE
8DP7BPBa+wTwgfsE8Kj7BPDP+wTw9vsE8B38BPBE/ATwa/wE8JL8BPC5/ATw4PwE8Af9BPAu/QTwVf0E8Hz9BPCj/QTwyv0E8PH9BPAY/gTwP/4E8Gb+
BPCN/gTwtP4E8Nv+BPAC/wTwKf8E8FD/BPB3/wTwnv8E8MX/BPDs/wXwE/gF8Dr4BfBh+AXwiPgF8K/4BfDW+AXw/fgF8CT5BfBL+QXwcvkF8Jn5BfDA
+QXw5/kF8A76BfA1+gXwXPoF8IP6BfCq+gXw0foF8Pj6BfAf+wXwRvsF8G37BfCU+wXwu/sF8OL7BfAJ/AXwMPwF8Ff8BfB+/AXwpfwF8Mz8BfDz/AXw
Gv0F8EH9BfBo/QXwj/0F8Lb9BfDd/QXwBP4F8Cv+BfBS/gXwef4F8KD+BfDH/gXw7v4F8BX/BfA8/wXwY/8F8Ir/BfCx/wXw2P8F8P//BvAm+AbwTfgG
8HT4BvCb+AbwwvgG8On4BvAQ+QbwN/kG8F75BvCF+QbwrPkG8NP5BvD6+QbwIfoG8Ej6BvBv+gbwlvoG8L36BvDk+gbwC/sG8DL7BvBZ+wbwgPsG8Kf7
BvDO+wbw9fsG8Bz8BvBD/AbwavwG8JH8BvC4/Abw3/wG8Ab9BvAt/QbwVP0G8Hv9BvCi/Qbwyf0G8PD9BvAX/gbwPv4G8GX+BvCM/gbws/4G8Nr+BvAB
/wbwKP8G8E//BvB2/wbwnf8G8MT/BvDr/wfwEvgH8Dn4B/Bg+Afwh/gH8K74B/DV+Afw/PgH8CP5B/BK+QfwcfkH8Jj5B/C/+Qfw5vkH8A36B/A0+gfw
W/oH8IL6B/Cp+gfw0PoH8Pf6B/Ae+wfwRfsH8Gz7B/CT+wfwuvsH8OH7B/AI/AfwL/wH8Fb8B/B9/AfwpPwH8Mv8B/Dy/AfwGf0H8ED9B/Bn/Qfwjv0H
8LX9B/Dc/QfwA/4H8Cr+B/BR/gfweP4H8J/+B/DG/gfw7f4H8BT/B/A7/wfwYv8H8In/B/Cw/wfw1/8H8P7/CPAl+AjwTPgI8HP4CPCa+AjwwfgI8Oj4
CPAP+QjwNvkI8F35CPCE+Qjwq/kI8NL5CPD5+QjwIPoI8Ef6CPBu+gjwlfoI8Lz6CPDj+gjwCvsI8DH7CPBY+wjwf/sI8Kb7CPDN+wjw9PsI8Bv8CPBC
/AjwafwI8JD8CPC3/Ajw3vwI8AX9CPAs/QjwU/0I8Hr9CPCh/QjwyP0I8O/9CPAW/gjwPf4I8GT+CPCL/gjwsv4I8Nn+CPAA/wjwJ/8I8E7/CPB1/wjw
nP8I8MP/CPDq/wnwEfgJ8Dj4CfBf+AnwhvgJ8K34CfDU+Anw+/gJ8CL5CfBJ+QnwcPkJ8Jf5CfC++Qnw5fkJ8Az6CfAz+gnwWvoJ8IH6CfCo+gnwz/oJ
8Pb6CfAd+wnwRPsJ8Gv7CfCS+wnwufsJ8OD7CfAH/AnwLvwJ8FX8CfB8/Anwo/wJ8Mr8CfDx/AnwGP0J8D/9CfBm/Qnwjf0J8LT9CfDb/QnwAv4J8Cn+
CfBQ/gnwd/4J8J7+CfDF/gnw7P4J8BP/CfA6/wnwYf8J8Ij/CfCv/wnw1v8J8P3/CvAk+ArwS/gK8HL4CvCZ+ArwwPgK8Of4CvAO+QrwNfkK8Fz5CvCD
+QrwqvkK8NH5CvD4+QrwH/oK8Eb6CvBt+grwlPoK8Lv6CvDi+grwCfsK8DD7CvBX+wrwfvsK8KX7CvDM+wrw8/sK8Br8CvBB/ArwaPwK8I/8CvC2/Arw
3fwK8AT9CvAr/QrwUv0K8Hn9CvCg/Qrwx/0K8O79CvAV/grwPP4K8GP+CvCK/grwsf4K8Nj+CvD//grwJv8K8E3/CvB0/wrwm/8K8ML/CvDp/wvwEPgL
8Df4C/Be+AvwhfgL8Kz4C/DT+Avw+vgL8CH5C/BI+Qvwb/kL8Jb5C/C9+Qvw5PkL8Av6C/Ay+gvwWfoL8ID6C/Cn+gvwzvoL8PX6C/Ac+wvwQ/sL8Gr7
C/CR+wvwuPsL8N/7C/AG/AvwLfwL8FT8C/B7/AvwovwL8Mn8C/Dw/AvwF/0L8D79C/Bl/QvwjP0L8LP9C/Da/QvwAf4L8Cj+C/BP/gvwdv4L8J3+C/DE
/gvw6/4L8BL/C/A5/wvwYP8L8If/C/Cu/wvw1f8L8Pz/DPAj+AzwSvgM8HH4DPCY+Azwv/gM8Ob4DPAN+QzwNPkM8Fv5DPCC+QzwqfkM8ND5DPD3+Qzw
HvoM8EX6DPBs+gzwk/oM8Lr6DPDh+gzwCPsM8C/7DPBW+wzwffsM8KT7DPDL+wzw8vsM8Bn8DPBA/AzwZ/wM8I78DPC1/Azw3PwM8AP9DPAq/QzwUf0M
8Hj9DPCf/Qzwxv0M8O39DPAU/gzwO/4M8GL+DPCJ/gzwsP4M8Nf+DPD+/gzwJf8M8Ez/DPBz/wzwmv8M8MH/DPDo/w3wD/gN8Db4DfBd+A3whPgN8Kv4
DfDS+A3w+fgN8CD5DfBH+Q3wbvkN8JX5DfC8+Q3w4/kN8Ar6DfAx+g3wWPoN8H/6DfCm+g3wzfoN8PT6DfAb+w3wQvsN8Gn7DfCQ+w3wt/sN8N77DfAF
/A3wLPwN8FP8DfB6/A3wofwN8Mj8DfDv/A3wFv0N8D39DfBk/Q3wi/0N8LL9DfDZ/Q3wAP4N8Cf+DfBO/g3wdf4N8Jz+DfDD/g3w6v4N8BH/DfA4/w3w
X/8N8Ib/DfCt/w3w1P8N8Pv/DvAi+A7wSfgO8HD4DvCX+A7wvvgO8OX4DvAM+Q7wM/kO8Fr5DvCB+Q7wqPkO8M/5DvD2+Q7wHfoO8ET6DvBr+g7wkvoO
8Ln6DvDg+g7wB/sO8C77DvBV+w7wfPsO8KP7DvDK+w7w8fsO8Bj8DvA//A7wZvwO8I38DvC0/A7w2/wO8AL9DvAp/Q7wUP0O8Hf9DvCe/Q7wxf0O8Oz9
DvAT/g7wOv4O8GH+DvCI/g7wr/4O8Nb+DvD9/g7wJP8O8Ev/DvBy/w7wmf8O8MD/DvDn/w/wDvgP8DX4D/Bc+A/wg/gP8Kr4D/DR+A/w+PgP8B/5D/BG
+Q/wbfkP8JT5D/C7+Q/w4vkP8An6D/Aw+g/wV/oP8H76D/Cl+g/wzPoP8PP6D/Aa+w/wQfsP8Gj7D/CP+w/wtvsP8N37D/AE/A/wK/wP8FL8D/B5/A/w
oPwP8Mf8D/Du/A/wFf0P8Dz9D/Bj/Q/wiv0P8LH9D/DY/Q/w//0P8Cb+D/BN/g/wdP4P8Jv+D/DC/g/w6f4P8BD/D/A3/w/wXv8P8IX/D/Cs/w/w0/8P
8Pr/EPAh+BDwSPgQ8G/4EPCW+BDwvfgQ8OT4EPAL+RDwMvkQ8Fn5EPCA+RDwp/kQ8M75EPD1+RDwHPoQ8EP6EPBq+hDwkfoQ8Lj6EPDf+hDwBvsQ8C37
EPBU+xDwe/sQ8KL7EPDJ+xDw8PsQ8Bf8EPA+/BDwZfwQ8Iz8EPCz/BDw2vwQ8AH9EPAo/RDwT/0Q8Hb9EPCd/RDwxP0Q8Ov9EPAS/hDwOf4Q8GD+EPCH
/hDwrv4Q8NX+EPD8/hDwI/8Q8Er/EPBx/xDwmP8Q8L//EPDm/xHwDfgR8DT4EfBb+BHwgvgR8Kn4EfDQ+BHw9/gR8B75EfBF+RHwbPkR8JP5EfC6+RHw
4fkR8Aj6EfAv+hHwVvoR8H36EfCk+hHwy/oR8PL6EfAZ+xHwQPsR8Gf7EfCO+xHwtfsR8Nz7EfAD/BHwKvwR8FH8EfB4/BHwn/wR8Mb8EfDt/BHwFP0R
8Dv9EfBi/RHwif0R8LD9EfDX/RHw/v0R8CX+EfBM/hHwc/4R8Jr+EfDB/hHw6P4R8A//EfA2/xHwXf8R8IT/EfCr/xHw0v8R8Pn/EvAg+BLwR/gS8G74
EvCV+BLwvPgS8OP4EvAK+RLwMfkS8Fj5EvB/+RLwpvkS8M35EvD0+RLwG/oS8EL6EvBp+hLwkPoS8Lf6EvDe+hLwBfsS8Cz7EvBT+xLwevsS8KH7EvDI
+xLw7/sS8Bb8EvA9/BLwZPwS8Iv8EvCy/BLw2fwS8AD9EvAn/RLwTv0S8HX9EvCc/RLww/0S8Or9EvAR/hLwOP4S8F/+EvCG/hLwrf4S8NT+EvD7/hLw
Iv8S8En/EvBw/xLwl/8S8L7/EvDl/xPwDPgT8DP4E/Ba+BPwgfgT8Kj4E/DP+BPw9vgT8B35E/BE+RPwa/kT8JL5E/C5+RPw4PkT8Af6E/Au+hPwVfoT
8Hz6E/Cj+hPwyvoT8PH6E/AY+xPwP/sT8Gb7E/CN+xPwtPsT8Nv7AQQGAAEJkAAABwsBAAEEAwMHAQyQAAAICgF5bBt9AAAFARkJAAAAAAAAAAAAERsA
YgBjAGoAXwBhAHIAbQB0AC4AYgBpAG4AAAAZABQKAQB/gzf5UnbdARUGAQAgAAAAAAA=`,
	"riscv": `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`,
}

// bcjFilterArchive decodes one embedded filter archive.
func bcjFilterArchive(name string) []byte {
	data, err := base64.StdEncoding.DecodeString(bcjFilterArchives[name])
	if err != nil {
		panic(err)
	}
	return data
}

// bcjFilterText regenerates the 4096 bytes each filter archive was built
// from.  The generators mirror the one used to create the fixtures.
func bcjFilterText(name string) []byte {
	switch name {
	case "arm64":
		out := make([]byte, 0, 4096)
		for index := 0; index < 1024; index++ {
			var word uint32
			if index%2 == 0 {
				rel := ((index*13)%64 - 32) * 4
				word = uint32(0x94000000) | (uint32(rel>>2) & 0x3FFFFFF)
			} else {
				immhi := (index * 7) % (1 << 17)
				immlo := index % 4
				rd := index % 32
				word = uint32(0x90000000) | uint32(immlo)<<29 | uint32(immhi)<<5 | uint32(rd)
			}
			out = appendU32(out, word)
		}
		return out
	case "arm":
		out := make([]byte, 0, 4096)
		for index := 0; index < 1024; index++ {
			rel := ((index*13)%64 - 32) * 4
			word := uint32(0xEB000000) | (uint32(rel>>2) & 0xFFFFFF)
			out = appendU32(out, word)
		}
		return out
	case "ppc":
		out := make([]byte, 0, 4096)
		for index := 0; index < 1024; index++ {
			rel := ((index*13)%64 - 32) * 4
			word := uint32(0x48000001) | (uint32(rel) & 0x03FFFFFC)
			out = append(out, byte(word>>24), byte(word>>16), byte(word>>8), byte(word))
		}
		return out
	case "sparc":
		out := make([]byte, 0, 4096)
		for index := 0; index < 1024; index++ {
			rel := ((index*13)%64 - 32) * 4
			word := uint32(0x40000000) | (uint32(rel>>2) & 0x3FFFFFFF)
			out = append(out, byte(word>>24), byte(word>>16), byte(word>>8), byte(word))
		}
		return out
	case "armt":
		out := make([]byte, 0, 4096)
		for index := 0; index < 1024; index++ {
			value := (index * 37) & 0x1FFFFF
			high := uint16(0xF000) | uint16((value>>11)&0x7FF)
			low := uint16(0xF800) | uint16(value&0x7FF)
			out = append(out, byte(high), byte(high>>8), byte(low), byte(low>>8))
		}
		return out
	case "riscv":
		out := make([]byte, 0, 4096)
		state := uint32(0x12345678)
		for index := 0; index < 1024; index++ {
			state = state*1664525 + 1013904223
			word := uint32(0x6F) | (state & 0xFFFFF000)
			if index%3 == 0 {
				word = uint32(0x17) | (state & 0xFFFFE000)
			}
			out = appendU32(out, word)
		}
		return out
	}
	panic("unknown filter fixture " + name)
}

// Real 7-Zip 25.01 archives: one LZMA folder (the stream has no end
// marker, so it exercises the known-size path) and one solid LZMA2 folder
// with three substreams (one decode sliced into three files).
const lzmaSmallArchiveBase64 = `N3q8ryccAAQrJOfEhwAAAAAAAABqAAAAAAAAAGFkCQcAIIgKRlMq6Hp4FMDXdpgF4yYziQtkreU4vYG/lGoF04fGTwirNUcgpFDE6d21V6WfaeR59QaLPJo/X4RdCPE5VIfi53IO9MML3PRnnKSNUmAgf4UsCz66cS0G94sSa+rxGWTu3ZRXCWp3sbrTjOnApmGV4u1AJx1Ju3pterfenbI/EhnawQABBAYAAQmAhwAHCwEAASMDAQEFXQAQAAAMioYACAoBuODnjQAABQEZBAAAAAARHwBsAHoAbQBhAF8AcwBtAGEAbABsAC4AdAB4AHQAAAAZBAAAAAAUCgEAS3mknVN23QEVBgEAIAAAAAAA`

const lzma2SolidArchiveBase64 = `N3q8ryccAAQ/ZF/ZFAEAAAAAAAAjAAAAAAAAAImCO53gBPAAiV0AOZvJzftN+kMVtYiQ75wdXWJLZfJUmxspfjcY9TxoRUdJyWO4I6GtD3mk+KShDmn5EQGq/0SRwV0QVZ24IxdtJhmuYl51yoNqOW9eIPWtc4GUweCVXDFfiBCBrWquKuZ7yuai13ZnbRo5XkmletA2v2o/q9ziwixorAsVBpOYnOurfRpmSdtouQAAAACBMweuD9UwB+FWbCkfSB2atbdixLm94FUF56GbuWGxtMziNv5WxunuDHy3IZG4/zYoZ+DxtdwqnUdj80PzwwhbjmNuK1/p9u4fqUk3SVXjjf/dwtOlgb5T4bt+Uz/GyjMsbkzfHzO3nVVv/XgZ68qXGymyAYpb+VXwlxhq9mdc+AAXBoCRAQmAgwAHCwEAASMDAQEFXQAQAAAMgMoKAVVX46AAAA==`

func realArchiveFixture(name string) []byte {
	var encoded string
	switch name {
	case "lzma_small":
		encoded = lzmaSmallArchiveBase64
	case "lzma2_solid":
		encoded = lzma2SolidArchiveBase64
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	return data
}

func realLzmaText() []byte {
	first := strings.Repeat("A real 7-Zip LZMA stream with a known unpacked size.\n", 7)
	part := first + "The decoder must take the known-size path because 7-Zip omits the end marker.\n"
	return []byte(strings.Repeat(part, 6))
}

func realSolidTexts() map[string]string {
	return map[string]string{
		"solid_one.txt":   strings.Repeat("solid member one: the quick brown fox jumps over the lazy dog.\n", 9),
		"solid_two.txt":   strings.Repeat("solid member two: pack my box with five dozen liquor jugs.\n", 7),
		"solid_three.txt": strings.Repeat("solid member three: how vexingly quick daft zebras jump.\n", 5),
	}
}

// realTreeArchiveBase64 is a 7-Zip 25.01 LZMA2 archive holding one
// directory, one empty file and one file with content (216 bytes).
const realTreeArchiveBase64 = `N3q8ryccAAR2/QMClgAAAAAAAAAiAAAAAAAAAObxpMoBABFyZWFsIGZpbGUgY29udGVudAoAAACBMweuD89dLwwHyEN/QbH6/eXHfdsfbpTQDoggFQrJHvPMdb3D3unl6uufYGdc1fiiRPi4DhZR+/De7Q96JLfGvcxYMh76KJ6h0qstNF3Ayw6TcYTnU9xa3UFCOzzCQwdGWc7HTjwUpp+NXsN9NqquLSV4FZbc+lUDc0Tyd4AXBhYBCYCAAAcLAQABIwMBAQVdABAAAAyA3goBG9V2wQAA`

func realTreeArchive() []byte {
	data, err := base64.StdEncoding.DecodeString(realTreeArchiveBase64)
	if err != nil {
		panic(err)
	}
	return data
}
