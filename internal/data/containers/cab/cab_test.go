package cab

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const testBlock = 32 * 1024

var (
	testDOSDate = uint16(((2026 - 1980) << 9) | (10 << 5) | 26)
	testDOSTime = uint16(12 << 11)
)

type cabFileSpec struct {
	name           []byte
	data           []byte
	folder         int
	utf            bool
	attributes     uint16
	offsetOverride *uint32
	sizeOverride   *uint32
}

type cabFolderSpec struct {
	method               uint16
	prefix               []byte
	corruptChecksumBlock int
}

type cabReserve struct {
	header uint16
	folder uint8
	data   uint16
}

type cabPair struct {
	cabinet string
	disk    string
}

type cabBuilder struct {
	versionMajor byte
	versionMinor byte
	flags        uint16
	setID        uint16
	cabinetIndex uint16
	reserve      *cabReserve
	prev         *cabPair
	next         *cabPair
	folders      []cabFolderSpec
	files        []cabFileSpec
}

func newCabBuilder() *cabBuilder {
	return &cabBuilder{versionMajor: 1, versionMinor: 3}
}

type builtBlock struct {
	stored   []byte
	uncomp   uint16
	checksum uint32
}

func lcgBytes(seed uint32, length int) []byte {
	state := seed
	out := make([]byte, length)
	for i := range out {
		state = state*1664525 + 1013904223
		out[i] = byte(state >> 24)
	}
	return out
}

func deflateWithWindow(t *testing.T, window, chunk []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := flate.NewWriterDict(&buf, flate.DefaultCompression, window)
	if err != nil {
		t.Fatalf("flate.NewWriterDict: %v", err)
	}
	if _, err := writer.Write(chunk); err != nil {
		t.Fatalf("deflate chunk: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close deflate chunk: %v", err)
	}
	return buf.Bytes()
}

func buildCab(t *testing.T, b *cabBuilder) []byte {
	t.Helper()
	payloads := make([][]byte, len(b.folders))
	for i := range b.folders {
		payloads[i] = append([]byte(nil), b.folders[i].prefix...)
	}
	offsets := make([]uint32, len(b.files))
	for i := range b.files {
		f := &b.files[i]
		offset := uint32(len(payloads[f.folder]))
		payloads[f.folder] = append(payloads[f.folder], f.data...)
		if f.offsetOverride != nil {
			offset = *f.offsetOverride
		}
		offsets[i] = offset
	}

	blocks := make([][]builtBlock, len(b.folders))
	for fi := range b.folders {
		spec := &b.folders[fi]
		window := make([]byte, MSZIPWindow)
		for start := 0; start < len(payloads[fi]); start += testBlock {
			end := start + testBlock
			if end > len(payloads[fi]) {
				end = len(payloads[fi])
			}
			chunk := payloads[fi][start:end]
			var stored []byte
			if spec.method&0x000F == MethodMSZIP {
				stored = append([]byte("CK"), deflateWithWindow(t, window, chunk)...)
			} else {
				stored = append([]byte(nil), chunk...)
			}
			checksum := dataChecksum(stored, uint16(len(stored)), uint16(len(chunk)))
			if spec.corruptChecksumBlock == start/testBlock {
				checksum ^= 1
			}
			blocks[fi] = append(blocks[fi], builtBlock{
				stored:   stored,
				uncomp:   uint16(len(chunk)),
				checksum: checksum,
			})
			if spec.method&0x000F == MethodMSZIP {
				combined := append(append([]byte(nil), window...), chunk...)
				if len(combined) > MSZIPWindow {
					combined = combined[len(combined)-MSZIPWindow:]
				}
				window = combined
			}
		}
	}

	var names []byte
	if b.prev != nil {
		names = append(names, b.prev.cabinet...)
		names = append(names, 0)
		names = append(names, b.prev.disk...)
		names = append(names, 0)
	}
	if b.next != nil {
		names = append(names, b.next.cabinet...)
		names = append(names, 0)
		names = append(names, b.next.disk...)
		names = append(names, 0)
	}

	headerFixed := 36
	reserveBytes := 0
	folderReserve := 0
	dataReserve := 0
	if b.reserve != nil {
		reserveBytes = 5 + int(b.reserve.header)
		folderReserve = int(b.reserve.folder)
		dataReserve = int(b.reserve.data)
	}
	foldersStart := headerFixed + reserveBytes + len(names)
	folderStride := 8 + folderReserve
	filesStart := foldersStart + len(b.folders)*folderStride
	filesLength := 0
	for _, f := range b.files {
		filesLength += 16 + len(f.name) + 1
	}
	dataStart := filesStart + filesLength

	folderStarts := make([]uint32, len(b.folders))
	cursor := dataStart
	for fi, folderBlocks := range blocks {
		folderStarts[fi] = uint32(cursor)
		for _, block := range folderBlocks {
			cursor += 8 + len(block.stored) + dataReserve
		}
	}
	total := cursor
	if total > int(^uint32(0)) {
		t.Fatal("fixture cabinet is too large")
	}

	flags := b.flags
	if b.reserve != nil {
		flags |= FLAG_RESERVE_PRESENT
	}
	if b.prev != nil {
		flags |= FLAG_PREV_CABINET
	}
	if b.next != nil {
		flags |= FLAG_NEXT_CABINET
	}

	out := make([]byte, 0, total)
	out = append(out, 'M', 'S', 'C', 'F')
	out = appendU32(out, 0)             // reserved1
	out = appendU32(out, uint32(total)) // cbCabinet
	out = appendU32(out, 0)             // reserved2
	out = appendU32(out, uint32(filesStart))
	out = appendU32(out, 0) // reserved3
	out = append(out, b.versionMinor, b.versionMajor)
	out = appendU16(out, uint16(len(b.folders)))
	out = appendU16(out, uint16(len(b.files)))
	out = appendU16(out, flags)
	out = appendU16(out, b.setID)
	out = appendU16(out, b.cabinetIndex)
	if b.reserve != nil {
		out = appendU16(out, b.reserve.header)
		out = append(out, b.reserve.folder)
		out = appendU16(out, b.reserve.data)
		for i := 0; i < int(b.reserve.header); i++ {
			out = append(out, 0xAA)
		}
	}
	out = append(out, names...)
	if len(out) != foldersStart {
		t.Fatalf("header length %d, folders start %d", len(out), foldersStart)
	}

	for fi, folderBlocks := range blocks {
		out = appendU32(out, folderStarts[fi])
		out = appendU16(out, uint16(len(folderBlocks)))
		out = appendU16(out, b.folders[fi].method)
		for i := 0; i < folderReserve; i++ {
			out = append(out, 0xBB)
		}
	}
	if len(out) != filesStart {
		t.Fatalf("folder table end %d, files start %d", len(out), filesStart)
	}

	for i := range b.files {
		f := &b.files[i]
		size := uint32(len(f.data))
		if f.sizeOverride != nil {
			size = *f.sizeOverride
		}
		attributes := f.attributes
		if f.utf {
			attributes |= ATTR_NAME_IS_UTF
		}
		out = appendU32(out, size)
		out = appendU32(out, offsets[i])
		out = appendU16(out, uint16(f.folder))
		out = appendU16(out, testDOSDate)
		out = appendU16(out, testDOSTime)
		out = appendU16(out, attributes)
		out = append(out, f.name...)
		out = append(out, 0)
	}
	if len(out) != dataStart {
		t.Fatalf("file table end %d, data start %d", len(out), dataStart)
	}

	for _, folderBlocks := range blocks {
		for _, block := range folderBlocks {
			out = appendU32(out, block.checksum)
			out = appendU16(out, uint16(len(block.stored)))
			out = appendU16(out, block.uncomp)
			out = append(out, block.stored...)
			for i := 0; i < dataReserve; i++ {
				out = append(out, 0xCC)
			}
		}
	}
	if len(out) != total {
		t.Fatalf("cabinet length %d, declared %d", len(out), total)
	}
	return out
}

func appendU16(out []byte, value uint16) []byte {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], value)
	return append(out, buf[:]...)
}

func appendU32(out []byte, value uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	return append(out, buf[:]...)
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	data, err := source.ReadVecAt(src, 0, src.Len())
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	return data
}

func TestStoredAndMSZIPFolders(t *testing.T) {
	payload := lcgBytes(0x12345678, testBlock)
	previousTail := append([]byte(nil), payload[len(payload)-7168:]...)
	for _, seed := range []uint32{0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35} {
		block := append([]byte(nil), previousTail...)
		block = append(block, lcgBytes(seed, testBlock-7168)...)
		previousTail = append([]byte(nil), block[len(block)-7168:]...)
		payload = append(payload, block...)
	}

	notes := []byte("cabinet fixture notes\n")
	extra := []byte("second file in the stored folder")
	b := newCabBuilder()
	b.folders = []cabFolderSpec{
		{method: MethodNone, corruptChecksumBlock: -1},
		{method: MethodMSZIP, corruptChecksumBlock: -1},
	}
	b.files = []cabFileSpec{
		{name: []byte("dir\\notes.txt"), data: notes, folder: 0},
		{name: []byte("extra.txt"), data: extra, folder: 0},
		{name: []byte("payload.bin"), data: payload, folder: 1},
	}
	data := buildCab(t, b)

	cabinet, err := Open(source.NewMemorySourceWithImage(1, 3, data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	info := cabinet.Info()
	if info.CBCabinet != uint32(len(data)) || info.FolderCount != 2 || info.FileCount != 3 {
		t.Fatalf("info = %+v", info)
	}
	if major, minor := info.Version(); major != 1 || minor != 3 {
		t.Fatalf("version = %d.%d", major, minor)
	}
	folders := cabinet.Folders()
	if len(folders) != 2 {
		t.Fatalf("folders = %d", len(folders))
	}
	if folders[1].Compression != CompressionMSZIP || folders[1].DataBlocks != 4 {
		t.Fatalf("MSZIP folder = %+v", folders[1])
	}
	if len(folders[1].Blocks) != 4 {
		t.Fatalf("MSZIP blocks = %d", len(folders[1].Blocks))
	}
	files := cabinet.Files()
	if len(files) != 3 {
		t.Fatalf("files = %d", len(files))
	}
	if files[0].Path != "dir/notes.txt" || files[0].RawPath != "dir\\notes.txt" {
		t.Fatalf("first entry = %+v", files[0])
	}
	wantModified := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC).Unix()
	if files[0].Modified == nil || *files[0].Modified != wantModified {
		t.Fatalf("modified = %v, want %d", files[0].Modified, wantModified)
	}
	if !files[0].IsComplete() || files[0].Size != uint64(len(notes)) {
		t.Fatalf("first entry completeness = %+v", files[0])
	}
	if files[2].Size != uint64(len(payload)) {
		t.Fatalf("payload size = %d", files[2].Size)
	}

	notesStream, err := cabinet.OpenFile("dir\\notes.txt", 7)
	if err != nil {
		t.Fatalf("OpenFile(notes): %v", err)
	}
	if got := readAll(t, notesStream); !bytes.Equal(got, notes) {
		t.Fatalf("notes = %q", got)
	}
	if notesStream.SourceID() != 7 {
		t.Fatalf("stream id = %d", notesStream.SourceID())
	}

	extraStream, err := cabinet.OpenFile("extra.txt", 8)
	if err != nil {
		t.Fatalf("OpenFile(extra): %v", err)
	}
	if got := readAll(t, extraStream); !bytes.Equal(got, extra) {
		t.Fatalf("extra = %q", got)
	}

	payloadStream, err := cabinet.OpenFile("payload.bin", 9)
	if err != nil {
		t.Fatalf("OpenFile(payload): %v", err)
	}
	if got := readAll(t, payloadStream); !bytes.Equal(got, payload) {
		t.Fatalf("payload differs: got %d bytes, want %d", len(got), len(payload))
	}
	if cabinet.ChecksumMismatches() != 0 {
		t.Fatalf("checksum mismatches = %d", cabinet.ChecksumMismatches())
	}
}

func TestMSZIPFolderWithFilesStartingMidFolder(t *testing.T) {
	first := lcgBytes(0xDDCCBBAA, 40000)
	second := lcgBytes(0x01020304, 30000)
	b := newCabBuilder()
	b.folders = []cabFolderSpec{{method: MethodMSZIP, corruptChecksumBlock: -1}}
	b.files = []cabFileSpec{
		{name: []byte("first.bin"), data: first, folder: 0},
		{name: []byte("second.bin"), data: second, folder: 0},
	}
	cabinet, err := Open(source.NewMemorySource(1, buildCab(t, b)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	secondStream, err := cabinet.OpenFile("second.bin", 1)
	if err != nil {
		t.Fatalf("OpenFile(second): %v", err)
	}
	if got := readAll(t, secondStream); !bytes.Equal(got, second) {
		t.Fatalf("second file differs: %d bytes", len(got))
	}
}

func TestCodepage437Table(t *testing.T) {
	if len(cp437Runes) != 128 {
		t.Fatalf("cp437 high table has %d runes, want 128", len(cp437Runes))
	}
	if cp437(0x82) != 'é' || cp437(0x80) != 'Ç' || cp437(0xFF) != ' ' {
		t.Fatalf("cp437 samples = %q %q %q", cp437(0x80), cp437(0x82), cp437(0xFF))
	}
}

func TestNamesUTF8AndANSI(t *testing.T) {
	b := newCabBuilder()
	b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: -1}}
	b.files = []cabFileSpec{
		{name: []byte("照片\\notes.txt"), data: []byte("utf8\n"), folder: 0, utf: true},
		{name: []byte("caf\x82.txt"), data: []byte("ansi\n"), folder: 0},
	}
	bytes := buildCab(t, b)
	cabinet, err := Open(source.NewMemorySource(1, bytes))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	files := cabinet.Files()
	if len(files) != 2 {
		t.Fatalf("files = %d", len(files))
	}
	if files[0].Path != "照片/notes.txt" || files[0].RawPath != "照片\\notes.txt" || !files[0].UTF8Name {
		t.Fatalf("UTF-8 entry = %+v", files[0])
	}
	if files[1].Path != "café.txt" || files[1].UTF8Name {
		t.Fatalf("ANSI entry = %+v", files[1])
	}
	utfStream, err := cabinet.OpenFile("照片/notes.txt", 1)
	if err != nil {
		t.Fatalf("OpenFile(UTF-8): %v", err)
	}
	if got := readAll(t, utfStream); string(got) != "utf8\n" {
		t.Fatalf("UTF-8 data = %q", got)
	}
	ansiStream, err := cabinet.OpenFile("café.txt", 2)
	if err != nil {
		t.Fatalf("OpenFile(ANSI): %v", err)
	}
	if got := readAll(t, ansiStream); string(got) != "ansi\n" {
		t.Fatalf("ANSI data = %q", got)
	}
	byIndex, err := cabinet.OpenEntry(1, 3)
	if err != nil {
		t.Fatalf("OpenEntry(1): %v", err)
	}
	if got := readAll(t, byIndex); string(got) != "ansi\n" {
		t.Fatalf("ANSI data by index = %q", got)
	}
}

func TestChecksumMismatchIsWarning(t *testing.T) {
	b := newCabBuilder()
	b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: 0}}
	b.files = []cabFileSpec{{name: []byte("a.bin"), data: []byte("payload"), folder: 0}}
	bytes := buildCab(t, b)
	cabinet, err := Open(source.NewMemorySource(1, bytes))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	stream, err := cabinet.OpenFile("a.bin", 1)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if got := readAll(t, stream); string(got) != "payload" {
		t.Fatalf("data = %q", got)
	}
	if cabinet.ChecksumMismatches() != 1 {
		t.Fatalf("checksum mismatches = %d", cabinet.ChecksumMismatches())
	}
}

func TestDataChecksumTail(t *testing.T) {
	cases := []struct {
		stored   []byte
		cbData   uint16
		cbUncomp uint16
		want     uint32
	}{
		{[]byte{0x01, 0x02, 0x03, 0x04}, 0, 0, 0x04030201},
		{[]byte{0xF1, 0xF7}, 0, 0, 0x0000F1F7},
		{[]byte{0x00, 0xBC}, 682, 0, 682 ^ 0x000000BC},
		{[]byte{0x11, 0x22, 0x33}, 1, 2, 0x00020001 ^ 0x112233},
	}
	for _, tc := range cases {
		if got := dataChecksum(tc.stored, tc.cbData, tc.cbUncomp); got != tc.want {
			t.Fatalf("dataChecksum(%x, %d, %d) = 0x%08X, want 0x%08X",
				tc.stored, tc.cbData, tc.cbUncomp, got, tc.want)
		}
	}
}

func TestUnsupportedCompression(t *testing.T) {
	t.Run("quantum is refused at open", func(t *testing.T) {
		b := newCabBuilder()
		b.folders = []cabFolderSpec{{method: MethodQuantum, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a"), data: []byte("x"), folder: 0}}
		_, err := Open(source.NewMemorySource(1, buildCab(t, b)))
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("Open error = %v, want unsupported", err)
		}
		if !contains(err.Error(), "Quantum") || !contains(err.Error(), "2") {
			t.Fatalf("error does not name Quantum (type 2): %v", err)
		}
	})

	t.Run("unknown type is refused at open", func(t *testing.T) {
		b := newCabBuilder()
		b.folders = []cabFolderSpec{{method: 9, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a"), data: []byte("x"), folder: 0}}
		_, err := Open(source.NewMemorySource(1, buildCab(t, b)))
		if !errors.Is(err, source.ErrUnsupported) || !contains(err.Error(), "9") {
			t.Fatalf("Open error = %v, want unsupported unknown type 9", err)
		}
	})

	t.Run("LZX is listed but not decoded", func(t *testing.T) {
		b := newCabBuilder()
		b.folders = []cabFolderSpec{{method: 0x1503, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a"), data: []byte("x"), folder: 0}}
		bytes := buildCab(t, b)
		cabinet, err := Open(source.NewMemorySource(1, bytes))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		folder := cabinet.Folders()[0]
		if folder.Compression != CompressionLZX || folder.TypeCompress>>8 != 21 {
			t.Fatalf("LZX folder = %+v", folder)
		}
		if len(cabinet.Files()) != 1 {
			t.Fatalf("files = %d", len(cabinet.Files()))
		}
		_, err = cabinet.OpenFile("a", 1)
		if !errors.Is(err, source.ErrUnsupported) || !contains(err.Error(), "LZX") {
			t.Fatalf("OpenFile error = %v, want unsupported naming LZX", err)
		}
	})

	t.Run("LZX with zero-bit window is refused at open", func(t *testing.T) {
		b := newCabBuilder()
		b.folders = []cabFolderSpec{{method: MethodLZX, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a"), data: []byte("x"), folder: 0}}
		_, err := Open(source.NewMemorySource(1, buildCab(t, b)))
		if !errors.Is(err, source.ErrUnsupported) || !contains(err.Error(), "LZX") {
			t.Fatalf("Open error = %v, want unsupported LZX window", err)
		}
	})

	t.Run("reserved compression bits are refused", func(t *testing.T) {
		b := newCabBuilder()
		b.folders = []cabFolderSpec{{method: 0x0100, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a"), data: []byte("x"), folder: 0}}
		_, err := Open(source.NewMemorySource(1, buildCab(t, b)))
		if !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("Open error = %v, want unsupported reserved bits", err)
		}
	})
}

func TestTruncatedAndCorruptCabinets(t *testing.T) {
	newValid := func() []byte {
		b := newCabBuilder()
		b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a.bin"), data: lcgBytes(1, 1000), folder: 0}}
		return buildCab(t, b)
	}

	t.Run("truncated body", func(t *testing.T) {
		bytes := newValid()
		_, err := Open(source.NewMemorySource(1, bytes[:len(bytes)-16]))
		if !errors.Is(err, source.ErrCorrupt) || !contains(err.Error(), "declares") {
			t.Fatalf("Open error = %v, want corrupt declaring size", err)
		}
	})

	t.Run("short header", func(t *testing.T) {
		_, err := Open(source.NewMemorySource(1, make([]byte, 10)))
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		bytes := newValid()
		bytes[0] = 'X'
		_, err := Open(source.NewMemorySource(1, bytes))
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})

	t.Run("unsupported version", func(t *testing.T) {
		b := newCabBuilder()
		b.versionMajor, b.versionMinor = 2, 1
		b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a"), data: []byte("x"), folder: 0}}
		_, err := Open(source.NewMemorySource(1, buildCab(t, b)))
		if !errors.Is(err, source.ErrUnsupported) || !contains(err.Error(), "2.1") {
			t.Fatalf("Open error = %v, want unsupported version 2.1", err)
		}
	})

	t.Run("encrypted flag", func(t *testing.T) {
		b := newCabBuilder()
		b.flags |= FLAG_ENCRYPTED
		b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a"), data: []byte("x"), folder: 0}}
		_, err := Open(source.NewMemorySource(1, buildCab(t, b)))
		if !errors.Is(err, source.ErrUnsupported) || !contains(err.Error(), "0x0008") {
			t.Fatalf("Open error = %v, want unsupported encrypted flag", err)
		}
	})

	t.Run("reserved header flag", func(t *testing.T) {
		b := newCabBuilder()
		b.flags |= 0x1000
		b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a"), data: []byte("x"), folder: 0}}
		_, err := Open(source.NewMemorySource(1, buildCab(t, b)))
		if !errors.Is(err, source.ErrUnsupported) || !contains(err.Error(), "1000") {
			t.Fatalf("Open error = %v, want unsupported reserved flag", err)
		}
	})

	t.Run("entry past its folder", func(t *testing.T) {
		b := newCabBuilder()
		size := uint32(100)
		b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: -1}}
		b.files = []cabFileSpec{{name: []byte("a.bin"), data: []byte("short"), folder: 0, sizeOverride: &size}}
		_, err := Open(source.NewMemorySource(1, buildCab(t, b)))
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})

	t.Run("entry names a missing folder", func(t *testing.T) {
		bytes := newValid()
		coffFiles := binary.LittleEndian.Uint32(bytes[16:])
		binary.LittleEndian.PutUint16(bytes[coffFiles+8:], 9)
		_, err := Open(source.NewMemorySource(1, bytes))
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})
}

func TestMultiPartSets(t *testing.T) {
	b := newCabBuilder()
	size := uint32(11)
	b.setID = 0x1234
	b.cabinetIndex = 1
	b.prev = &cabPair{cabinet: "part0.cab", disk: "disk0"}
	b.next = &cabPair{cabinet: "part2.cab", disk: "disk2"}
	b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: -1}}
	b.files = []cabFileSpec{{name: []byte("part1.bin"), data: []byte("first"), folder: 0, sizeOverride: &size}}

	cabinet, err := Open(source.NewMemorySource(1, buildCab(t, b)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	info := cabinet.Info()
	if !info.IsMultiPart() || !info.HasPrev() || !info.HasNext() {
		t.Fatalf("multi-part flags = %+v", info)
	}
	if info.SetID != 0x1234 || info.CabinetIndex != 1 {
		t.Fatalf("set identity = %+v", info)
	}
	if info.CabinetPrev == nil || *info.CabinetPrev != "part0.cab" ||
		info.DiskPrev == nil || *info.DiskPrev != "disk0" ||
		info.CabinetNext == nil || *info.CabinetNext != "part2.cab" ||
		info.DiskNext == nil || *info.DiskNext != "disk2" {
		t.Fatalf("multi-part names = %+v", info)
	}
	if !cabinet.IsMultiPart() {
		t.Fatal("Cabinet.IsMultiPart = false")
	}
	entry := cabinet.Files()[0]
	if entry.Available != 5 || entry.IsComplete() {
		t.Fatalf("continued entry = %+v", entry)
	}
	_, err = cabinet.OpenFile("part1.bin", 1)
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenFile error = %v, want unsupported", err)
	}
	if !contains(err.Error(), "next cabinet") || !contains(err.Error(), "part2.cab") {
		t.Fatalf("error does not name the next cabinet: %v", err)
	}
}

func TestReserveAreasAreSkipped(t *testing.T) {
	b := newCabBuilder()
	b.reserve = &cabReserve{header: 7, folder: 3, data: 5}
	b.folders = []cabFolderSpec{
		{method: MethodNone, corruptChecksumBlock: -1},
		{method: MethodMSZIP, corruptChecksumBlock: -1},
	}
	b.files = []cabFileSpec{
		{name: []byte("a\\b.txt"), data: []byte("reserved\n"), folder: 0},
		{name: []byte("c.bin"), data: lcgBytes(7, 40000), folder: 1},
	}
	data := buildCab(t, b)
	cabinet, err := Open(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	info := cabinet.Info()
	if info.HeaderReserve != 7 || info.FolderReserve != 3 || info.DataReserve != 5 {
		t.Fatalf("reserve fields = %+v", info)
	}
	first, err := cabinet.OpenFile("a/b.txt", 1)
	if err != nil {
		t.Fatalf("OpenFile(a/b.txt): %v", err)
	}
	if got := readAll(t, first); string(got) != "reserved\n" {
		t.Fatalf("first data = %q", got)
	}
	second, err := cabinet.OpenFile("c.bin", 2)
	if err != nil {
		t.Fatalf("OpenFile(c.bin): %v", err)
	}
	if got := readAll(t, second); len(got) != 40000 {
		t.Fatalf("second data length = %d", len(got))
	}
}

func TestPathsAndEmptyFiles(t *testing.T) {
	b := newCabBuilder()
	b.folders = []cabFolderSpec{{method: MethodNone, corruptChecksumBlock: -1}}
	b.files = []cabFileSpec{
		{name: []byte("a.txt"), data: []byte("abc"), folder: 0},
		{name: []byte("empty.bin"), data: nil, folder: 0},
	}
	bytes := buildCab(t, b)
	cabinet, err := Open(source.NewMemorySource(1, bytes))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if entry, ok := cabinet.Find("a.txt"); !ok || entry.Size != 3 {
		t.Fatalf("Find(a.txt) = %+v, %v", entry, ok)
	}
	if _, ok := cabinet.Find("missing"); ok {
		t.Fatal("Find(missing) found an entry")
	}
	if _, ok := cabinet.Find("../x"); ok {
		t.Fatal("Find(../x) found an entry")
	}
	if _, err := cabinet.OpenFile("missing", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenFile(missing) error = %v", err)
	}
	if _, err := cabinet.OpenFile("../x", 1); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("OpenFile(../x) error = %v", err)
	}
	empty, err := cabinet.OpenFile("empty.bin", 5)
	if err != nil {
		t.Fatalf("OpenFile(empty): %v", err)
	}
	if empty.Len() != 0 {
		t.Fatalf("empty length = %d", empty.Len())
	}
	if _, ok := cabinet.Entry(9); ok {
		t.Fatal("Entry(9) exists")
	}
	if _, err := cabinet.OpenEntry(9, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenEntry(9) error = %v", err)
	}
}

func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}
