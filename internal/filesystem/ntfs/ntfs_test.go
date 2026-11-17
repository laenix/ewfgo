package ntfs

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// --- Minimal in-memory NTFS image builder ---

func nle16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func nle32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func nle64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

// ntfsResidentAttr appends a resident attribute (24-byte header + aligned value).
func ntfsResidentAttr(buf []byte, typ uint32, id uint16, value []byte) []byte {
	start := len(buf)
	total := 24 + len(value)
	total = (total + 7) &^ 7
	header := make([]byte, 24)
	nle32(header, 0, typ)
	nle32(header, 4, uint32(total))
	header[9] = 0 // name length
	nle16(header, 10, 0x18)
	nle16(header, 14, id)
	nle32(header, 16, uint32(len(value)))
	nle16(header, 20, 0x18)
	buf = append(buf, header...)
	buf = append(buf, value...)
	for len(buf)-start < total {
		buf = append(buf, 0)
	}
	return buf
}

// ntfsNonResidentAttr appends a non-resident attribute (0x40-byte header + runs).
func ntfsNonResidentAttr(buf []byte, typ uint32, id uint16, startVCN, lastVCN uint64, realSize uint64, runs []byte) []byte {
	start := len(buf)
	total := 0x40 + len(runs)
	total = (total + 7) &^ 7
	header := make([]byte, 0x40)
	nle32(header, 0, typ)
	nle32(header, 4, uint32(total))
	header[8] = 1 // non-resident
	nle16(header, 10, 0x18)
	nle16(header, 14, id)
	nle64(header, 0x10, startVCN)
	nle64(header, 0x18, lastVCN)
	nle16(header, 0x20, 0x40)     // mapping pairs offset
	nle64(header, 0x28, realSize) // allocated size
	nle64(header, 0x30, realSize) // real size
	nle64(header, 0x38, realSize) // initialized size
	buf = append(buf, header...)
	buf = append(buf, runs...)
	for len(buf)-start < total {
		buf = append(buf, 0)
	}
	return buf
}

// ntfsFileNameValue builds a $FILE_NAME attribute value.
func ntfsFileNameValue(parent uint64, name string, isDir bool) []byte {
	val := make([]byte, 0x42+len(name)*2)
	nle64(val, 0x00, parent) // parent file reference (record number only)
	nle64(val, 0x28, 0)      // allocated size
	nle64(val, 0x30, 0)      // real size
	if isDir {
		nle32(val, 0x38, 0x10000000)
	}
	val[0x40] = byte(len(name)) // name length (ASCII names)
	val[0x41] = 0               // namespace: POSIX
	for i, c := range []byte(name) {
		nle16(val, 0x42+i*2, uint16(c))
	}
	return val
}

// ntfsFileNameValueUnits builds a $FILE_NAME value from raw UTF-16LE code units
// (used to construct surrogate pairs that a per-unit decode would mangle).
func ntfsFileNameValueUnits(parent uint64, units []uint16) []byte {
	val := make([]byte, 0x42+len(units)*2)
	nle64(val, 0x00, parent) // parent file reference (record number only)
	nle64(val, 0x28, 0)      // allocated size
	nle64(val, 0x30, 0)      // real size
	val[0x40] = byte(len(units))
	val[0x41] = 0 // namespace: POSIX
	for i, u := range units {
		nle16(val, 0x42+i*2, u)
	}
	return val
}

// ntfsBuildRecord builds a single valid MFT record (with correct fixup array).
func ntfsBuildRecord(recNum uint64, name string, parent uint64, isDir bool, residentData []byte, nonResRuns []byte, nonResSize uint64, volumeLabel string) []byte {
	return ntfsBuildRecordRaw(recNum, isDir, func(body []byte) []byte {
		// $STANDARD_INFORMATION
		siVal := make([]byte, 0x48)
		nle32(siVal, 0x20, 0x20) // FILE_ATTRIBUTE_ARCHIVE
		body = ntfsResidentAttr(body, attrStandardInformation, 0, siVal)
		// $FILE_NAME
		body = ntfsResidentAttr(body, attrFileName, 1, ntfsFileNameValue(parent, name, isDir))
		if volumeLabel != "" {
			vn := make([]byte, 0)
			for _, c := range []byte(volumeLabel) {
				vn = append(vn, c, 0)
			}
			body = ntfsResidentAttr(body, attrVolumeName, 2, vn)
			body = ntfsResidentAttr(body, attrData, 3, nil)
		} else if nonResRuns != nil {
			body = ntfsNonResidentAttr(body, attrData, 2, 0, nonResSize/4096-1, nonResSize, nonResRuns)
		} else {
			body = ntfsResidentAttr(body, attrData, 2, residentData)
		}
		return body
	})
}

// ntfsBuildRecordRaw builds a valid MFT record (with fixup array) whose
// attribute body is supplied by buildBody.
func ntfsBuildRecordRaw(recNum uint64, isDir bool, buildBody func([]byte) []byte) []byte {
	rec := make([]byte, ntfsDefaultRecordSize)
	copy(rec[0:4], "FILE")
	nle16(rec, 0x04, 0x2A) // USA offset
	rec[0x06] = 3          // USA count (sequence + 2 sectors)
	nle16(rec, 0x10, 1)    // sequence number
	nle16(rec, 0x12, 1)    // hard link count
	nle16(rec, 0x14, 56)   // first attribute offset
	var flags uint16 = mftRecordInUse
	if isDir {
		flags |= mftRecordDir
	}
	nle16(rec, 0x16, flags)
	nle32(rec, 0x1C, ntfsDefaultRecordSize) // allocated size
	nle16(rec, 0x28, 1)                     // next attribute id

	body := buildBody(nil)
	// $END marker
	end := make([]byte, 16)
	nle32(end, 0, 0xFFFFFFFF)
	nle32(end, 4, 8)
	body = append(body, end...)

	copy(rec[56:], body)
	nle32(rec, 0x18, uint32(56+len(body))) // used size
	ntfsApplyFixup(rec, recNum)
	return rec
}

// ntfsApplyFixup writes the update-sequence array: the sequence number into the
// tail of each 512-byte block, stashing the original tail bytes.
func ntfsApplyFixup(rec []byte, recNum uint64) {
	seq := uint16(recNum + 1)
	nle16(rec, 0x2A, seq)
	for s := 0; s < 2; s++ {
		secOff := s * 512
		saved := rec[secOff+510 : secOff+512]
		faOff := 0x2A + 2 + s*2
		copy(rec[faOff:faOff+2], saved)
		nle16(rec, secOff+510, seq)
	}
}

// ntfsImage constants.
const (
	ntfsTestSPC      = 8
	ntfsTestMFTLCN   = 4
	ntfsTestNumRecs  = 24
	ntfsTestDataLCN  = 10
	ntfsTestTotalCls = 12
)

// buildNTFSImage builds a minimal valid NTFS image in memory.
//
//	cluster 0 : boot sector (NTFS signature, spc=8, MFT at LCN 4)
//	clusters 4-9 : MFT (24 x 1024-byte records)
//	cluster 10-11: big.bin data
//
// Records: 0=$MFT, 3=$Volume(label FIXTURE), 5=root, 16=hello.txt,
// 17=big.bin, 18=subdir, 19=nested.txt (in subdir).
func buildNTFSImage() []byte { return buildNTFSImageWith(512, ntfsTestSPC) }

// buildNTFSImageWith builds the minimal valid NTFS image with the given logical
// sector size and sectors-per-cluster. The MFT record size is left at the boot
// sector default (field 0x40 = 0 -> 1024 bytes), matching ntfsBuildRecord.
func buildNTFSImageWith(bps, spc int) []byte {
	img := make([]byte, ntfsTestTotalCls*4096)

	// Boot sector
	copy(img[3:7], "NTFS")
	nle16(img, 0x0B, uint16(bps))                          // bytes per sector
	img[0x0D] = byte(spc)                                  // sectors per cluster
	nle64(img, 0x28, uint64(ntfsTestTotalCls)*uint64(spc)) // total sectors
	nle64(img, 0x30, ntfsTestMFTLCN)                       // MFT LCN
	img[0x1FE] = 0x55
	img[0x1FF] = 0xAA

	mftOff := ntfsTestMFTLCN * 4096
	mftRealSize := uint64(ntfsTestNumRecs * ntfsDefaultRecordSize)
	// record 0: $MFT (non-resident, runs: VCN0..5 -> LCN4..9)
	copy(img[mftOff:], ntfsBuildRecord(0, "$MFT", 5, false, nil, []byte{0x11, 0x06, 0x04, 0x00}, mftRealSize, ""))
	// record 3: $Volume with label FIXTURE
	copy(img[mftOff+3*ntfsDefaultRecordSize:], ntfsBuildRecord(3, "$Volume", 5, false, nil, nil, 0, "FIXTURE"))
	// record 5: root "."
	copy(img[mftOff+5*ntfsDefaultRecordSize:], ntfsBuildRecord(5, ".", 5, true, nil, nil, 0, ""))
	// record 16: hello.txt (resident)
	copy(img[mftOff+16*ntfsDefaultRecordSize:], ntfsBuildRecord(16, "hello.txt", 5, false, []byte("hello world"), nil, 0, ""))
	// record 17: big.bin (non-resident, 2 clusters at LCN 10)
	copy(img[mftOff+17*ntfsDefaultRecordSize:], ntfsBuildRecord(17, "big.bin", 5, false, nil, []byte{0x11, 0x02, 0x0A, 0x00}, 4096, ""))
	// record 18: subdir
	copy(img[mftOff+18*ntfsDefaultRecordSize:], ntfsBuildRecord(18, "subdir", 5, true, nil, nil, 0, ""))
	// record 19: nested.txt (resident, in subdir)
	copy(img[mftOff+19*ntfsDefaultRecordSize:], ntfsBuildRecord(19, "nested.txt", 18, false, []byte("nested content"), nil, 0, ""))

	// big.bin content
	bigOff := ntfsTestDataLCN * 4096
	for i := 0; i < 4096; i++ {
		img[bigOff+i] = byte(i) // recognizable byte pattern 0x00..0xFF
	}
	return img
}

// memNTFSReader is a fake filesystem.Reader over an in-memory byte slice.
// sectorSize defaults to 512 when zero (a 512-byte sector image).
type memNTFSReader struct {
	data       []byte
	sectorSize int
}

func (r *memNTFSReader) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	ss := r.sectorSize
	if ss == 0 {
		ss = 512
	}
	start := lba * uint64(ss)
	end := start + count*uint64(ss)
	if end > uint64(len(r.data)) {
		return nil, fmt.Errorf("read out of bounds: lba=%d count=%d", lba, count)
	}
	return r.data[start:end], nil
}

func newTestNTFSHandler() (*NTFSHandler, error) {
	return NewNTFSHandler(&memNTFSReader{data: buildNTFSImage()}, 0)
}

// --- Tests ---

func TestNTFSListDirectory(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}

	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory(/): %v", err)
	}
	byName := map[string]filesystem.DirectoryEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	for _, want := range []string{"$MFT", "$Volume", "hello.txt", "big.bin", "subdir"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("root listing missing %q (got %d entries)", want, len(entries))
		}
	}
	if _, ok := byName["."]; ok {
		t.Errorf("root listing must not include the self-referencing \".\" entry")
	}
	if byName["hello.txt"].Size != 11 {
		t.Errorf("hello.txt size = %d, want 11", byName["hello.txt"].Size)
	}
	if byName["big.bin"].Size != 4096 {
		t.Errorf("big.bin size = %d, want 4096", byName["big.bin"].Size)
	}
	if byName["subdir"].IsDir != true {
		t.Errorf("subdir should be IsDir")
	}
	if byName["hello.txt"].IsDir {
		t.Errorf("hello.txt should not be IsDir")
	}

	// Subdirectory listing via MFT parent pointers.
	sub, err := h.ListDirectory("/subdir")
	if err != nil {
		t.Fatalf("ListDirectory(/subdir): %v", err)
	}
	if len(sub) != 1 || sub[0].Name != "nested.txt" {
		t.Errorf("subdir listing = %+v, want [nested.txt]", sub)
	}
}

func TestNTFSGetFile(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}

	data, err := h.GetFile("hello.txt")
	if err != nil {
		t.Fatalf("GetFile(hello.txt): %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("hello.txt content = %q, want %q", string(data), "hello world")
	}

	// Non-resident read via data runs.
	big, err := h.GetFile("big.bin")
	if err != nil {
		t.Fatalf("GetFile(big.bin): %v", err)
	}
	if len(big) != 4096 {
		t.Fatalf("big.bin length = %d, want 4096", len(big))
	}
	for i := 0; i < 4096; i++ {
		if big[i] != byte(i) {
			t.Fatalf("big.bin byte %d = 0x%02X, want 0x%02X", i, big[i], byte(i))
		}
	}

	// Nested path.
	nested, err := h.GetFile("/subdir/nested.txt")
	if err != nil {
		t.Fatalf("GetFile(/subdir/nested.txt): %v", err)
	}
	if string(nested) != "nested content" {
		t.Errorf("nested content = %q, want %q", string(nested), "nested content")
	}

	// Missing and directory paths must error, never fabricate.
	if _, err := h.GetFile("doesnotexist.txt"); err == nil {
		t.Errorf("GetFile on missing path should error")
	}
	if _, err := h.GetFile("subdir"); err == nil {
		t.Errorf("GetFile on a directory should error")
	}
}

func TestNTFSGetFileByPath(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}
	fi, err := h.GetFileByPath("hello.txt")
	if err != nil {
		t.Fatalf("GetFileByPath(hello.txt): %v", err)
	}
	if fi.Name != "hello.txt" || fi.IsDir || fi.Size != 11 {
		t.Errorf("unexpected FileInfo: %+v", fi)
	}
	if fi.Path != "/hello.txt" {
		t.Errorf("Path = %q, want /hello.txt", fi.Path)
	}

	d, err := h.GetFileByPath("/subdir")
	if err != nil {
		t.Fatalf("GetFileByPath(/subdir): %v", err)
	}
	if !d.IsDir {
		t.Errorf("subdir should be IsDir: %+v", d)
	}
}

func TestNTFSSearchFiles(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}

	results, err := h.SearchFiles("/", func(fi filesystem.FileInfo) bool {
		return strings.HasSuffix(fi.Name, ".txt") || fi.Name == "big.bin"
	})
	if err != nil {
		t.Fatalf("SearchFiles(/): %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("SearchFiles found %d files, want 3: %+v", len(results), results)
	}
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.Path] = true
	}
	if !seen["/hello.txt"] || !seen["/big.bin"] || !seen["/subdir/nested.txt"] {
		t.Errorf("search results missing expected paths: %+v", seen)
	}
}

func TestNTFSGetVolumeLabel(t *testing.T) {
	h, err := newTestNTFSHandler()
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}
	if got := h.GetVolumeLabel(); got != "FIXTURE" {
		t.Errorf("GetVolumeLabel() = %q, want %q", got, "FIXTURE")
	}
}

// TestNTFSGetFileAttributeList: a file whose unnamed $DATA lives in an external
// MFT record (signalled by an $ATTRIBUTE_LIST attribute and no local $DATA) must
// produce an explicit error from GetFile, never an empty buffer.
func TestNTFSGetFileAttributeList(t *testing.T) {
	img := buildNTFSImage()
	mftOff := ntfsTestMFTLCN * 4096
	rec := ntfsBuildRecordRaw(20, false, func(body []byte) []byte {
		siVal := make([]byte, 0x48)
		nle32(siVal, 0x20, 0x20)
		body = ntfsResidentAttr(body, attrStandardInformation, 0, siVal)
		body = ntfsResidentAttr(body, attrFileName, 1, ntfsFileNameValue(5, "ext.txt", false))
		// $ATTRIBUTE_LIST pointing at an external record; no unnamed $DATA here.
		al := make([]byte, 0x18)
		nle32(al, 0x00, attrData)
		body = ntfsResidentAttr(body, attrAttributeList, 2, al)
		return body
	})
	copy(img[mftOff+20*ntfsDefaultRecordSize:], rec)

	h, err := NewNTFSHandler(&memNTFSReader{data: img}, 0)
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}
	data, err := h.GetFile("ext.txt")
	if err == nil {
		t.Fatalf("GetFile on an attribute-list record must error (got %d bytes)", len(data))
	}
	// The record still lists real metadata; the read path alone is honest.
	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "ext.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("ext.txt should still be listed (its metadata is local)")
	}
}

// TestNTFSFixupSectorSizeDerivedFromRecord: fixup granularity must come from the
// record (512-byte USA blocks), not the volume's logical sector size.
func TestNTFSFixupSectorSizeDerivedFromRecord(t *testing.T) {
	h := &NTFSHandler{bytesPerSector: 4096}
	rec := ntfsBuildRecordRaw(1, false, func(body []byte) []byte {
		return ntfsResidentAttr(body, attrData, 0, []byte("data"))
	})
	if err := h.fixupRecord(rec); err != nil {
		t.Fatalf("fixupRecord on a 1024-byte record with 4096-byte sectors: %v", err)
	}
}

// TestNTFS4KnVolume: a 4096-byte-logical-sector volume whose MFT still uses
// 1024-byte records (boot field 0x40 = 0 -> default) must parse and list.
func TestNTFS4KnVolume(t *testing.T) {
	img := buildNTFSImageWith(4096, 1)
	h, err := NewNTFSHandler(&memNTFSReader{data: img, sectorSize: 4096}, 0)
	if err != nil {
		t.Fatalf("NewNTFSHandler on a 4Kn volume: %v", err)
	}
	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory on a 4Kn volume: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "hello.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hello.txt not listed on a 4Kn volume (%d entries)", len(entries))
	}
	data, err := h.GetFile("hello.txt")
	if err != nil {
		t.Fatalf("GetFile(hello.txt) on a 4Kn volume: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("4Kn hello.txt content = %q, want %q", string(data), "hello world")
	}
}

// TestNTFSFileNameSurrogatePair: a non-BMP file name (surrogate pair) must
// decode to a single rune, not two mangled runes.
func TestNTFSFileNameSurrogatePair(t *testing.T) {
	// U+1F600 GRINNING FACE encodes as the surrogate pair 0xD83D 0xDE00.
	emoji := []uint16{0xD83D, 0xDE00}
	img := buildNTFSImage()
	mftOff := ntfsTestMFTLCN * 4096
	rec := ntfsBuildRecordRaw(21, false, func(body []byte) []byte {
		siVal := make([]byte, 0x48)
		nle32(siVal, 0x20, 0x20)
		body = ntfsResidentAttr(body, attrStandardInformation, 0, siVal)
		body = ntfsResidentAttr(body, attrFileName, 1, ntfsFileNameValueUnits(5, emoji))
		return body
	})
	copy(img[mftOff+21*ntfsDefaultRecordSize:], rec)

	h, err := NewNTFSHandler(&memNTFSReader{data: img}, 0)
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}
	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory: %v", err)
	}
	for _, e := range entries {
		if e.Name == "\U0001F600" {
			return // decoded as a single rune
		}
	}
	t.Fatalf("surrogate-pair name not decoded as a single rune (got %d entries)", len(entries))
}

// --- Malformed input: explicit errors, never panics ---

func TestNTFSFixupMalformed(t *testing.T) {
	h := &NTFSHandler{bytesPerSector: 512}
	rec := make([]byte, 1024)
	copy(rec[0:4], "FILE")
	nle16(rec, 0x04, 0x2A)
	rec[0x06] = 3
	// Write a wrong sequence into a sector tail: fixup must fail.
	nle16(rec, 510, 0xFFFF)
	nle16(rec, 0x2A, 1)
	if err := h.fixupRecord(rec); err == nil {
		t.Fatal("fixupRecord should fail on mismatched sequence")
	}
}

func TestNTFSParseAttrsMalformed(t *testing.T) {
	h := &NTFSHandler{}
	rec := make([]byte, 1024)
	copy(rec[0:4], "FILE")
	nle16(rec, 0x14, 56)
	// Attribute header with an absurd length that overruns the record.
	nle32(rec, 56, attrData)
	nle32(rec, 60, 0xFFFF)
	if _, err := h.parseAttrs(rec); err == nil {
		t.Fatal("parseAttrs should error on an attribute length that overruns the record")
	}

	// First attribute offset past the record end.
	rec2 := make([]byte, 1024)
	copy(rec2[0:4], "FILE")
	nle16(rec2, 0x14, 1020)
	if _, err := h.parseAttrs(rec2); err == nil {
		t.Fatal("parseAttrs should error on an attribute header past the record end")
	}
}

func TestNTFSGetFileCorruptRecord(t *testing.T) {
	img := buildNTFSImage()
	// Corrupt record 16's fixup sequence byte so the record fails to repair.
	mftOff := ntfsTestMFTLCN * 4096
	recOff := mftOff + 16*ntfsDefaultRecordSize
	img[recOff+510] = 0x00 // overwrite the sequence in sector 0's tail
	h, err := NewNTFSHandler(&memNTFSReader{data: img}, 0)
	if err != nil {
		t.Fatalf("NewNTFSHandler: %v", err)
	}
	// hello.txt's record is corrupt: its listing entry must disappear and any
	// attempt to read it must be an explicit not-found error, never a panic or
	// fabricated data.
	if _, err := h.GetFile("hello.txt"); err == nil {
		t.Fatal("GetFile(hello.txt) on a corrupt record should error")
	}
	// The rest of the volume still lists real data.
	entries, err := h.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory after corruption: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name == "big.bin" {
			found = true
		}
	}
	if !found {
		t.Errorf("big.bin should still be listed after hello.txt corruption")
	}
}

func TestNTFSConstructorBadBoot(t *testing.T) {
	img := buildNTFSImage()
	copy(img[3:7], "XXXX")
	if _, err := NewNTFSHandler(&memNTFSReader{data: img}, 0); err == nil {
		t.Fatal("NewNTFSHandler should error on a non-NTFS boot sector")
	}

	// Corrupt MFT LCN to 0 -> constructor error, no panic.
	img2 := buildNTFSImage()
	nle64(img2, 0x30, 0)
	if _, err := NewNTFSHandler(&memNTFSReader{data: img2}, 0); err == nil {
		t.Fatal("NewNTFSHandler should error on an invalid MFT LCN")
	}
}
