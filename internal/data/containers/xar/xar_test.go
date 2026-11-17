package xar

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	helloText = "hello xar\n"
	innerText = "compressed payload\n"
)

// bzip2Inner is a bzip2 stream of innerText.  The bytes are embedded so the
// tests stay hermetic: the standard library decodes bzip2 but has no encoder.
var bzip2Inner = mustHex("425a68393141592653592732a9b40000025180001040002e06d8202000229a6261ea0806801b934af0190061357a2ee48a70a1204e655368")

func mustHex(text string) []byte {
	out, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return out
}

func zlibCompress(data []byte) []byte {
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

func digestBytes(style string, data []byte) []byte {
	switch style {
	case "sha1":
		sum := sha1.Sum(data)
		return sum[:]
	case "md5":
		sum := md5.Sum(data)
		return sum[:]
	case "sha256":
		sum := sha256.Sum256(data)
		return sum[:]
	}
	panic("unknown digest style " + style)
}

func digestHex(style string, data []byte) string {
	return hex.EncodeToString(digestBytes(style, data))
}

func tocDoc(body string) string {
	return "<xar><toc><creation-time>2026-10-30T12:00:00Z</creation-time>" + body + "</toc></xar>"
}

// xarParts assembles a container from already-compressed pieces.  Zero-valued
// fields fall back to the documented defaults, which makes each test say only
// what it is changing.
type xarParts struct {
	xml                  string
	compressed           []byte
	heap                 []byte
	algorithm            uint32
	headerSize           uint16
	version              uint16
	declaredCompressed   *uint64
	declaredUncompressed *uint64
}

func (p xarParts) bytes() []byte {
	headerSize := p.headerSize
	if headerSize == 0 {
		headerSize = HeaderBytes
	}
	version := p.version
	if version == 0 {
		version = XARVersion
	}
	compressedLen := uint64(len(p.compressed))
	if p.declaredCompressed != nil {
		compressedLen = *p.declaredCompressed
	}
	uncompressedLen := uint64(len(p.xml))
	if p.declaredUncompressed != nil {
		uncompressedLen = *p.declaredUncompressed
	}

	var out bytes.Buffer
	out.WriteString("xar!")
	_ = binary.Write(&out, binary.BigEndian, headerSize)
	_ = binary.Write(&out, binary.BigEndian, version)
	_ = binary.Write(&out, binary.BigEndian, compressedLen)
	_ = binary.Write(&out, binary.BigEndian, uncompressedLen)
	_ = binary.Write(&out, binary.BigEndian, p.algorithm)
	out.Write(p.compressed)
	out.Write(p.heap)
	return out.Bytes()
}

// plainArchive builds an archive whose header names no TOC checksum.  Data
// offsets in body are relative to the start of heap.
func plainArchive(body string, heap []byte, algorithm uint32) []byte {
	xml := tocDoc(body)
	return xarParts{
		xml:        xml,
		compressed: zlibCompress([]byte(xml)),
		heap:       heap,
		algorithm:  algorithm,
	}.bytes()
}

func sampleTOCBody(innerStyle string, innerStored []byte, helloExtracted string) string {
	return fmt.Sprintf(`
<checksum style="sha1"><offset>0</offset><size>20</size></checksum>
<file id="1"><name>hello.txt</name><type>file</type><mode>0644</mode><uid>501</uid>
  <gid>20</gid><user>alice</user><group>staff</group>
  <atime>2026-10-30T12:00:00Z</atime><mtime>2026-10-30T12:00:00Z</mtime>
  <ctime>2026-10-30T12:00:00Z</ctime><size>10</size>
  <ea id="1"><name>com.apple.quarantine</name><data>0000</data></ea>
  <data><length>10</length><offset>20</offset><size>10</size>
    <encoding style="application/octet-stream"/>
    <archived-checksum style="sha1">%s</archived-checksum>
    <extracted-checksum style="sha1">%s</extracted-checksum>
  </data>
</file>
<file id="2"><name>dir</name><type>directory</type><mode>0755</mode>
  <mtime>2026-10-30T12:00:00Z</mtime>
  <file id="3"><name>inner.bin</name><type>file</type><size>%d</size>
    <data><length>%d</length><offset>30</offset><size>%d</size>
      <encoding style="%s"/>
      <archived-checksum style="sha1">%s</archived-checksum>
      <extracted-checksum style="sha1">%s</extracted-checksum>
    </data>
  </file>
</file>
<file id="4"><name>link</name><type>symlink</type>
  <link type="symbolic">hello.txt</link></file>
<file id="5"><name>copy.txt</name><type>file</type><size>10</size>
  <link type="hard">1</link></file>`,
		digestHex("sha1", []byte(helloText)),
		helloExtracted,
		len(innerText),
		len(innerStored),
		len(innerText),
		innerStyle,
		digestHex("sha1", innerStored),
		digestHex("sha1", []byte(innerText)),
	)
}

// sampleParts returns the archive and the absolute heap offset.  The heap is
// the SHA-1 of the compressed TOC followed by hello.txt at heap offset 20 and
// the inner payload at 30.
func sampleParts(innerStyle string, innerStored []byte, helloExtracted string) ([]byte, uint64) {
	xml := tocDoc(sampleTOCBody(innerStyle, innerStored, helloExtracted))
	compressed := zlibCompress([]byte(xml))
	heap := append([]byte{}, digestBytes("sha1", compressed)...)
	heap = append(heap, []byte(helloText)...)
	heap = append(heap, innerStored...)
	bytes := xarParts{
		xml:        xml,
		compressed: compressed,
		heap:       heap,
		algorithm:  1,
	}.bytes()
	return bytes, uint64(HeaderBytes) + uint64(len(compressed))
}

func sampleZlib() []byte {
	bytes, _ := sampleParts("application/x-gzip", zlibCompress([]byte(innerText)), digestHex("sha1", []byte(helloText)))
	return bytes
}

func sampleBzip2() []byte {
	bytes, _ := sampleParts("application/x-bzip2", bzip2Inner, digestHex("sha1", []byte(helloText)))
	return bytes
}

func openBytes(t *testing.T, data []byte) *Reader {
	t.Helper()
	reader, err := Open(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return reader
}

func openBytesErr(t *testing.T, data []byte) error {
	t.Helper()
	reader, err := Open(source.NewMemorySource(1, data))
	if err == nil {
		t.Fatalf("Open unexpectedly succeeded with %d entries", len(reader.Entries()))
	}
	return err
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	out := make([]byte, src.Len())
	if err := source.ReadExactAt(src, 0, out); err != nil {
		t.Fatalf("read %d bytes from source %d: %v", src.Len(), src.SourceID(), err)
	}
	return out
}

func wantUnsupported(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an unsupported error, got nil")
	}
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error %v is not ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not mention %q", err, contains)
	}
}

func wantCorrupt(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a corrupt error, got nil")
	}
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error %v is not ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not mention %q", err, contains)
	}
}

func TestSampleListsEveryKindAndVerifiesTOC(t *testing.T) {
	reader := openBytes(t, sampleZlib())
	if reader.Version() != XARVersion {
		t.Fatalf("version = %d, want %d", reader.Version(), XARVersion)
	}
	if reader.TOChecksum() != TOCVerified {
		t.Fatalf("TOC checksum = %s, want verified", reader.TOChecksum())
	}
	if reader.Creation() == nil {
		t.Fatal("creation time was not parsed")
	}
	if got, want := *reader.Creation(), int64(1793361600); got != want {
		t.Fatalf("creation = %d, want %d", got, want)
	}

	stats := reader.Stats()
	if stats.Entries != 5 || stats.Files != 2 || stats.Directories != 1 ||
		stats.Symlinks != 1 || stats.Hardlinks != 1 || stats.EAs != 1 ||
		stats.UnresolvedHardlinks != 0 || stats.SkippedUnsafe != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	hello, ok := reader.Entry("hello.txt")
	if !ok {
		t.Fatal("hello.txt is missing")
	}
	if hello.Kind != EntryKindFile {
		t.Fatalf("hello kind = %s", hello.Kind)
	}
	if hello.Mode == nil || *hello.Mode != 0o644 {
		t.Fatalf("hello mode = %v", hello.Mode)
	}
	if hello.UID == nil || *hello.UID != 501 || hello.GID == nil || *hello.GID != 20 {
		t.Fatalf("hello uid/gid = %v/%v", hello.UID, hello.GID)
	}
	if hello.User == nil || *hello.User != "alice" || hello.Group == nil || *hello.Group != "staff" {
		t.Fatalf("hello user/group = %v/%v", hello.User, hello.Group)
	}
	if hello.Atime == nil || hello.Mtime == nil || hello.Ctime == nil {
		t.Fatalf("hello timestamps = %v/%v/%v", hello.Atime, hello.Mtime, hello.Ctime)
	}
	if hello.Size != 10 {
		t.Fatalf("hello size = %d", hello.Size)
	}
	if hello.Data == nil || hello.Data.Encoding != EncodingStored || hello.Data.Style != "application/octet-stream" {
		t.Fatalf("hello data = %+v", hello.Data)
	}
	if hello.ExtractedChecksum == nil || hello.ArchivedChecksum == nil {
		t.Fatal("hello checksums were not parsed")
	}

	inner, ok := reader.Entry("dir/inner.bin")
	if !ok {
		t.Fatal("dir/inner.bin is missing")
	}
	if inner.Data == nil || inner.Data.Encoding != EncodingZlib {
		t.Fatalf("inner data = %+v", inner.Data)
	}

	link, ok := reader.Entry("link")
	if !ok {
		t.Fatal("link is missing")
	}
	if link.Kind != EntryKindSymlink || link.Link == nil || *link.Link != "hello.txt" {
		t.Fatalf("link = %+v", link)
	}

	copyEntry, ok := reader.Entry("copy.txt")
	if !ok {
		t.Fatal("copy.txt is missing")
	}
	if copyEntry.Kind != EntryKindHardlink || copyEntry.HardlinkOf == nil || *copyEntry.HardlinkOf != "hello.txt" {
		t.Fatalf("copy = %+v", copyEntry)
	}
	if copyEntry.Size != 10 || copyEntry.Data == nil {
		t.Fatalf("resolved hard link = %+v", copyEntry)
	}
}

func TestStoredZlibAndHardLinkReadBack(t *testing.T) {
	reader := openBytes(t, sampleZlib())

	hello, err := reader.OpenEntrySource("hello.txt", 2)
	if err != nil {
		t.Fatalf("open hello: %v", err)
	}
	if got := readAll(t, hello); string(got) != helloText {
		t.Fatalf("hello = %q", got)
	}
	if hello.DataOffset() == 0 || hello.StoredSize() != 10 {
		t.Fatalf("hello data offset/stored = %d/%d", hello.DataOffset(), hello.StoredSize())
	}

	inner, err := reader.OpenEntrySource("dir/inner.bin", 3)
	if err != nil {
		t.Fatalf("open inner: %v", err)
	}
	if got := readAll(t, inner); string(got) != innerText {
		t.Fatalf("inner = %q", got)
	}
	if inner.Stats().DecompressedBytes < uint64(len(innerText)) {
		t.Fatalf("decompressed counter = %d", inner.Stats().DecompressedBytes)
	}

	copySource, err := reader.OpenEntrySource("copy.txt", 4)
	if err != nil {
		t.Fatalf("open hard link: %v", err)
	}
	if got := readAll(t, copySource); string(got) != helloText {
		t.Fatalf("hard link = %q", got)
	}
	if copySource.Stats().CacheMisses != 1 {
		t.Fatalf("hard link opened its own cache instead of the holder's data? misses = %d", copySource.Stats().CacheMisses)
	}

	_, err = reader.OpenEntrySource("dir", 5)
	wantUnsupported(t, err, "directory")
	_, err = reader.OpenEntrySource("link", 6)
	wantUnsupported(t, err, "symbolic")
	_, err = reader.OpenEntrySource("missing", 7)
	if !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("missing entry error = %v, want ErrInvalidArgument", err)
	}
}

func TestBzip2PayloadReadsBack(t *testing.T) {
	reader := openBytes(t, sampleBzip2())
	inner, ok := reader.Entry("dir/inner.bin")
	if !ok {
		t.Fatal("inner.bin is missing")
	}
	if inner.Data == nil || inner.Data.Encoding != EncodingBzip2 {
		t.Fatalf("inner encoding = %+v", inner.Data)
	}
	src, err := reader.OpenEntrySource("dir/inner.bin", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, src); string(got) != innerText {
		t.Fatalf("decoded = %q", got)
	}
}

func TestTOCMismatchIsReportedAndEntriesSurvive(t *testing.T) {
	bytes, heapOffset := sampleParts("application/x-gzip", zlibCompress([]byte(innerText)), digestHex("sha1", []byte(helloText)))
	bytes[heapOffset] ^= 0xFF
	reader := openBytes(t, bytes)
	if reader.TOChecksum() != TOCMismatch {
		t.Fatalf("TOC checksum = %s, want mismatch", reader.TOChecksum())
	}
	if len(reader.Entries()) != 5 {
		t.Fatalf("entries = %d after a mismatch", len(reader.Entries()))
	}
}

func TestWrongPayloadChecksumIsCountedAndBytesReturned(t *testing.T) {
	bytes, _ := sampleParts("application/x-gzip", zlibCompress([]byte(innerText)), strings.Repeat("00", 20))
	reader := openBytes(t, bytes)
	src, err := reader.OpenEntrySource("hello.txt", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, src); string(got) != helloText {
		t.Fatalf("bytes = %q", got)
	}
	if src.Stats().CorruptBytes != uint64(len(helloText)) {
		t.Fatalf("corrupt counter = %d, want %d", src.Stats().CorruptBytes, len(helloText))
	}
}

func TestWrongArchivedChecksumIsCounted(t *testing.T) {
	body := `<file id="1"><name>a.bin</name><type>file</type><size>10</size>
<data><length>10</length><offset>0</offset><size>10</size>
<archived-checksum style="sha1">0000000000000000000000000000000000000000</archived-checksum>
</data></file>`
	reader := openBytes(t, plainArchive(body, []byte(helloText), 0))
	src, err := reader.OpenEntrySource("a.bin", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readAll(t, src); string(got) != helloText {
		t.Fatalf("bytes = %q", got)
	}
	if src.Stats().CorruptBytes != uint64(len(helloText)) {
		t.Fatalf("corrupt counter = %d", src.Stats().CorruptBytes)
	}
}

func TestUnsupportedEncodingListedAndRefusedByName(t *testing.T) {
	body := `<file id="9"><name>packed.bin</name><type>file</type><size>5</size>
<data><length>0</length><offset>0</offset><size>5</size>
<encoding style="application/x-snappy"/></data></file>`
	reader := openBytes(t, plainArchive(body, nil, 0))
	if stats := reader.Stats(); stats.Entries != 1 {
		t.Fatalf("entries = %d", stats.Entries)
	}
	entry, ok := reader.Entry("packed.bin")
	if !ok || entry.Data == nil || entry.Data.Encoding != EncodingOther {
		t.Fatalf("entry = %+v", entry)
	}
	src, err := reader.OpenEntrySource("packed.bin", 2)
	if err != nil {
		t.Fatalf("listing must not decode: %v", err)
	}
	buf := make([]byte, 5)
	_, err = src.ReadAt(0, buf)
	wantUnsupported(t, err, "application/x-snappy")
}

func TestLZMAPayloadDecodes(t *testing.T) {
	const storedHex = "5d00008000ffffffffffffffff00331bcaaae81a72fd1838b5e45de0c81efe2b176fde3c2b8103ffffe3bf8000"
	want := strings.Repeat("forensic ", 200)
	stored := mustHex(storedHex)
	body := fmt.Sprintf(`<file id="1"><name>packed.log</name><type>file</type><size>%d</size>
<data><length>%d</length><offset>0</offset><size>%d</size>
<encoding style="application/x-lzma"/></data></file>`, len(want), len(stored), len(want))
	reader := openBytes(t, plainArchive(body, stored, 0))
	src, err := reader.OpenEntrySource("packed.log", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got := make([]byte, len(want))
	if n, err := src.ReadAt(0, got); err != nil || n != len(got) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if string(got) != want {
		t.Fatalf("decoded = %q, want %q", got, want)
	}
}

func TestXZPayloadDecodes(t *testing.T) {
	const storedHex = "fd377a585a0000016922de360200210116000000742fe5a3e000c3006c5d0026984a420bb4ebd87ff30eabfebdfc7d3582b4165f1846d1d9e62227d7b817333cae3167f26657aebcc3cacff80686f850f2b477e52f8f3bde04560cf4bc4dbe242a4d31c394866ea1c122574a580de2eeb71935c1fd34c7697d8ad51c07e6d8db3d92e6be0fb53c447bc8a00074cc31b700018401c4010000c5b8f9833e300d8b020000000001595a"
	want := "Mar  1 10:00:00 host sshd[1]: Accepted password for alice from 198.51.100.7\n" +
		"Mar  1 10:00:01 host sshd[1]: session opened for user alice\n" +
		"Mar  1 10:00:02 host sshd[1]: session closed for user alice\n"
	stored := mustHex(storedHex)
	body := fmt.Sprintf(`<file id="1"><name>packed.log</name><type>file</type><size>%d</size>
<data><length>%d</length><offset>0</offset><size>%d</size>
<encoding style="application/x-xz"/></data></file>`, len(want), len(stored), len(want))
	reader := openBytes(t, plainArchive(body, stored, 0))
	src, err := reader.OpenEntrySource("packed.log", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got := make([]byte, len(want))
	if n, err := src.ReadAt(0, got); err != nil || n != len(got) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	if string(got) != want {
		t.Fatalf("decoded = %q, want %q", got, want)
	}
}

func TestZlibAndBzip2CRCErrorsAreCorrupt(t *testing.T) {
	corruptZlib := zlibCompress([]byte(innerText))
	corruptZlib[len(corruptZlib)-1] ^= 0xFF
	body := fmt.Sprintf(`<file id="1"><name>a.bin</name><type>file</type><size>%d</size>
<data><length>%d</length><offset>0</offset><size>%d</size>
<encoding style="application/x-gzip"/></data></file>`, len(innerText), len(corruptZlib), len(innerText))
	reader := openBytes(t, plainArchive(body, corruptZlib, 0))
	src, err := reader.OpenEntrySource("a.bin", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, err = src.ReadAt(0, make([]byte, len(innerText)))
	wantCorrupt(t, err, "zlib stream")

	corruptBzip2 := append([]byte{}, bzip2Inner...)
	corruptBzip2[len(corruptBzip2)-1] ^= 0xFF
	body = fmt.Sprintf(`<file id="1"><name>b.bin</name><type>file</type><size>%d</size>
<data><length>%d</length><offset>0</offset><size>%d</size>
<encoding style="application/x-bzip2"/></data></file>`, len(innerText), len(corruptBzip2), len(innerText))
	reader = openBytes(t, plainArchive(body, corruptBzip2, 0))
	src, err = reader.OpenEntrySource("b.bin", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, err = src.ReadAt(0, make([]byte, len(innerText)))
	wantCorrupt(t, err, "bzip2 stream")
}

func TestDataRangePastArchiveRefusedAtOpen(t *testing.T) {
	body := `<file id="9"><name>gone.bin</name><type>file</type><size>10</size>
<data><length>10</length><offset>9999</offset><size>10</size>
<encoding style="application/octet-stream"/></data></file>`
	err := openBytesErr(t, plainArchive(body, nil, 0))
	wantCorrupt(t, err, "outside")
}

func TestDataOffsetOverflowRefusedAtOpen(t *testing.T) {
	body := `<file id="9"><name>gone.bin</name><type>file</type><size>1</size>
<data><length>1</length><offset>18446744073709551615</offset><size>1</size></data></file>`
	err := openBytesErr(t, plainArchive(body, nil, 0))
	wantCorrupt(t, err, "overflows")
}

func TestDataLengthOverflowRefusedAtOpen(t *testing.T) {
	body := `<file id="9"><name>gone.bin</name><type>file</type><size>1</size>
<data><length>18446744073709551615</length><offset>0</offset><size>1</size></data></file>`
	err := openBytesErr(t, plainArchive(body, nil, 0))
	wantCorrupt(t, err, "overflows")
}

func TestNotXARAndShortSource(t *testing.T) {
	err := openBytesErr(t, make([]byte, 64))
	wantUnsupported(t, err, "magic")

	err = openBytesErr(t, []byte("short"))
	wantUnsupported(t, err, "28-byte header")
}

func TestUnknownHeaderVersionRefused(t *testing.T) {
	bytes := sampleZlib()
	binary.BigEndian.PutUint16(bytes[6:], 7)
	err := openBytesErr(t, bytes)
	wantUnsupported(t, err, "version 7")
}

func TestHeaderSizeValidation(t *testing.T) {
	xml := tocDoc("")
	compressed := zlibCompress([]byte(xml))
	small := xarParts{xml: xml, compressed: compressed, headerSize: HeaderBytes - 1}
	err := openBytesErr(t, small.bytes())
	wantCorrupt(t, err, "28-byte minimum")

	large := xarParts{xml: xml, compressed: compressed, headerSize: MaxHeaderBytes + 1}
	err = openBytesErr(t, large.bytes())
	wantUnsupported(t, err, "header")
}

func TestTOCSizeValidation(t *testing.T) {
	xml := tocDoc("")
	compressed := zlibCompress([]byte(xml))

	empty := xarParts{xml: xml, compressed: compressed, declaredCompressed: ptrU64(0)}
	err := openBytesErr(t, empty.bytes())
	wantCorrupt(t, err, "empty TOC")

	tooLarge := xarParts{xml: xml, compressed: compressed, declaredCompressed: ptrU64(MaxTOCBytes + 1)}
	err = openBytesErr(t, tooLarge.bytes())
	wantUnsupported(t, err, "TOC")

	pastEnd := xarParts{xml: xml, compressed: compressed, declaredCompressed: ptrU64(uint64(len(compressed) + 10))}
	err = openBytesErr(t, pastEnd.bytes())
	wantCorrupt(t, err, "runs past")
}

func TestTOCInflatesToWrongLength(t *testing.T) {
	xml := tocDoc("")
	compressed := zlibCompress([]byte(xml))
	parts := xarParts{xml: xml, compressed: compressed, declaredUncompressed: ptrU64(uint64(len(xml) + 1))}
	err := openBytesErr(t, parts.bytes())
	wantCorrupt(t, err, "inflated")
}

func TestTruncatedTOCStreamIsCorrupt(t *testing.T) {
	xml := tocDoc("")
	compressed := zlibCompress([]byte(xml))
	truncated := compressed[:len(compressed)-3]
	parts := xarParts{xml: xml, compressed: truncated}
	err := openBytesErr(t, parts.bytes())
	wantCorrupt(t, err, "TOC")
}

func TestTOCXMLValidation(t *testing.T) {
	invalid := xarParts{
		xml:        "<xar><toc><file></toc></xar>",
		compressed: zlibCompress([]byte("<xar><toc><file></toc></xar>")),
	}
	err := openBytesErr(t, invalid.bytes())
	wantCorrupt(t, err, "TOC XML")

	wrongRootXML := "<zip><toc></toc></zip>"
	err = openBytesErr(t, xarParts{xml: wrongRootXML, compressed: zlibCompress([]byte(wrongRootXML))}.bytes())
	wantUnsupported(t, err, "instead of <xar>")

	noTOCXML := "<xar></xar>"
	err = openBytesErr(t, xarParts{xml: noTOCXML, compressed: zlibCompress([]byte(noTOCXML))}.bytes())
	wantUnsupported(t, err, "<toc>")

	doctypeXML := "<!DOCTYPE xar><xar><toc></toc></xar>"
	err = openBytesErr(t, xarParts{xml: doctypeXML, compressed: zlibCompress([]byte(doctypeXML))}.bytes())
	wantCorrupt(t, err, "document type")
}

func TestTOCXMLVariants(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<!-- a comment -->
<xar>
  <toc>
    <?some-pi value?>
    <creation-time>2026-10-30T13:00:00+01:00</creation-time>
    <file id="1">
      <name><![CDATA[hello.txt]]></name>
      <type>file</type>
      <size>10</size>
      <data><length>10</length><offset>0</offset><size>10</size>
        <encoding style="application/octet-stream"/></data>
    </file>
    <file id="2"><name>a&amp;b.txt</name><type>file</type><size>0</size></file>
  </toc>
</xar>`
	reader := openBytes(t, xarParts{xml: xml, compressed: zlibCompress([]byte(xml)), heap: []byte(helloText)}.bytes())
	if reader.Creation() == nil {
		t.Fatal("creation time was not parsed")
	}
	entry, ok := reader.Entry("hello.txt")
	if !ok || entry.Data == nil || entry.Data.Offset != reader.HeapOffset() {
		t.Fatalf("entry = %+v", entry)
	}
	if _, ok := reader.Entry("a&b.txt"); !ok {
		t.Fatal("entity-decoded name is missing")
	}
}

func TestEntryShapeValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		part string
	}{
		{"no-name", `<file id="1"><type>file</type></file>`, "name"},
		{"no-type", `<file id="1"><name>a</name></file>`, "type"},
		{"unknown-type", `<file id="1"><name>a</name><type>blockdev</type></file>`, "blockdev"},
		{"symlink-without-target", `<file id="1"><name>l</name><type>symlink</type></file>`, "symbolic link"},
		{"symlink-with-data", `<file id="1"><name>l</name><type>symlink</type><link>t</link><data><length>0</length><offset>0</offset><size>0</size></data></file>`, "data area"},
		{"directory-with-bytes", `<file id="1"><name>d</name><type>directory</type><data><length>1</length><offset>0</offset><size>1</size></data></file>`, "stored bytes"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			heap := []byte{}
			if testCase.name == "directory-with-bytes" {
				heap = []byte{0xAA}
			}
			err := openBytesErr(t, plainArchive(testCase.body, heap, 0))
			wantUnsupported(t, err, testCase.part)
		})
	}
}

func TestDirectoryWithZeroLengthDataIsAccepted(t *testing.T) {
	body := `<file id="1"><name>d</name><type>directory</type>
<data><length>0</length><offset>0</offset><size>0</size></data></file>`
	reader := openBytes(t, plainArchive(body, nil, 0))
	if stats := reader.Stats(); stats.Directories != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestPathTraversalIsSkipped(t *testing.T) {
	body := `<file id="1"><name>../evil</name><type>file</type><size>0</size></file>
<file id="2"><name>/abs</name><type>file</type><size>0</size></file>
<file id="3"><name>C:\evil</name><type>file</type><size>0</size></file>
<file id="4"><name>ok.txt</name><type>file</type><size>0</size></file>`
	reader := openBytes(t, plainArchive(body, nil, 0))
	if _, ok := reader.Entry("ok.txt"); !ok {
		t.Fatal("safe entry was dropped")
	}
	stats := reader.Stats()
	if stats.SkippedUnsafe != 3 {
		t.Fatalf("skipped = %d, want 3", stats.SkippedUnsafe)
	}
	if stats.Entries != 1 {
		t.Fatalf("entries = %d", stats.Entries)
	}
	for _, name := range []string{"../evil", "/abs", `C:\evil`} {
		if _, ok := reader.Entry(name); ok {
			t.Fatalf("unsafe name %q was admitted", name)
		}
	}
}

func TestNULInNameIsRejected(t *testing.T) {
	body := `<file id="1"><name>a&#0;b</name><type>file</type><size>0</size></file>`
	// XML itself forbids a NUL character reference; either the XML parse or
	// the path sanitizer must refuse it.  What must never happen is an entry
	// named "a\x00b" being admitted.
	reader, err := Open(source.NewMemorySource(1, plainArchive(body, nil, 0)))
	if err != nil {
		if !errors.Is(err, source.ErrCorrupt) && !errors.Is(err, source.ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		return
	}
	if _, ok := reader.Entry("a\x00b"); ok {
		t.Fatal("NUL-bearing name was admitted")
	}
	if reader.Stats().SkippedUnsafe != 1 {
		t.Fatalf("skipped = %d, want 1", reader.Stats().SkippedUnsafe)
	}
}

func TestEmptyArchive(t *testing.T) {
	reader := openBytes(t, plainArchive("", nil, 0))
	if len(reader.Entries()) != 0 || reader.Stats().Entries != 0 {
		t.Fatalf("entries = %d", len(reader.Entries()))
	}
	if reader.TOChecksum() != TOCNotRecorded {
		t.Fatalf("TOC checksum = %s", reader.TOChecksum())
	}
	if _, err := reader.OpenEntrySource("anything", 2); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("missing entry error = %v", err)
	}
}

func TestTOChecksumVariants(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		style     string
		algorithm uint32
	}{
		{"sha1", "sha1", 1},
		{"md5", "md5", 2},
		{"sha256", "sha256", 3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			xml := tocDoc("")
			compressed := zlibCompress([]byte(xml))
			size := len(digestBytes(testCase.style, nil))
			checksum := fmt.Sprintf(`<checksum style="%s"><offset>0</offset><size>%d</size></checksum>`,
				testCase.style, size)
			xml = tocDoc(checksum)
			compressed = zlibCompress([]byte(xml))
			heap := digestBytes(testCase.style, compressed)
			parts := xarParts{xml: xml, compressed: compressed, heap: heap, algorithm: testCase.algorithm}
			reader := openBytes(t, parts.bytes())
			if reader.TOChecksum() != TOCVerified {
				t.Fatalf("TOC checksum = %s, want verified", reader.TOChecksum())
			}
			recorded := reader.TOChecksumRecorded()
			if recorded == nil || recorded.Style != testCase.style {
				t.Fatalf("recorded = %+v", recorded)
			}
		})
	}

	t.Run("absent", func(t *testing.T) {
		xml := tocDoc("")
		parts := xarParts{xml: xml, compressed: zlibCompress([]byte(xml)), algorithm: 1}
		reader := openBytes(t, parts.bytes())
		if reader.TOChecksum() != TOCAbsent {
			t.Fatalf("TOC checksum = %s, want absent", reader.TOChecksum())
		}
	})

	t.Run("malformed", func(t *testing.T) {
		body := `<checksum style="sha1"><offset>0</offset></checksum>`
		xml := tocDoc(body)
		parts := xarParts{xml: xml, compressed: zlibCompress([]byte(xml)), algorithm: 1}
		reader := openBytes(t, parts.bytes())
		if reader.TOChecksum() != TOCMalformed {
			t.Fatalf("TOC checksum = %s, want malformed", reader.TOChecksum())
		}
		if reader.TOChecksumRecorded() == nil {
			t.Fatal("the malformed checksum was not recorded")
		}
	})

	t.Run("unknown-algorithm", func(t *testing.T) {
		xml := tocDoc("")
		parts := xarParts{xml: xml, compressed: zlibCompress([]byte(xml)), algorithm: 9}
		reader := openBytes(t, parts.bytes())
		if reader.TOChecksum() != TOCUnsupported {
			t.Fatalf("TOC checksum = %s, want unsupported", reader.TOChecksum())
		}
	})

	t.Run("unknown-style", func(t *testing.T) {
		body := `<checksum style="crc32"><offset>0</offset><size>4</size></checksum>`
		xml := tocDoc(body)
		compressed := zlibCompress([]byte(xml))
		parts := xarParts{xml: xml, compressed: compressed, heap: []byte{1, 2, 3, 4}, algorithm: 1}
		reader := openBytes(t, parts.bytes())
		if reader.TOChecksum() != TOCUnsupported {
			t.Fatalf("TOC checksum = %s, want unsupported", reader.TOChecksum())
		}
		if recorded := reader.TOChecksumRecorded(); recorded == nil || recorded.Style != "crc32" {
			t.Fatalf("recorded = %+v", recorded)
		}
	})

	t.Run("out-of-range-is-malformed", func(t *testing.T) {
		body := `<checksum style="sha1"><offset>99</offset><size>20</size></checksum>`
		xml := tocDoc(body)
		parts := xarParts{xml: xml, compressed: zlibCompress([]byte(xml)), algorithm: 1}
		reader := openBytes(t, parts.bytes())
		if reader.TOChecksum() != TOCMalformed {
			t.Fatalf("TOC checksum = %s, want malformed", reader.TOChecksum())
		}
	})
}

func TestEntryMetadataParsing(t *testing.T) {
	body := `<file id="7"><name>odd.txt</name><type>file</type><size>0</size>
<mode>0o755</mode><uid>4294967296</uid><gid>-1</gid>
<user></user><atime>not-a-time</atime><mtime>2026-10-30T12:00:00</mtime></file>`
	reader := openBytes(t, plainArchive(body, nil, 0))
	entry, ok := reader.Entry("odd.txt")
	if !ok {
		t.Fatal("entry is missing")
	}
	if entry.ID == nil || *entry.ID != 7 {
		t.Fatalf("id = %v", entry.ID)
	}
	if entry.Mode == nil || *entry.Mode != 0o755 {
		t.Fatalf("mode = %v", entry.Mode)
	}
	if entry.UID != nil {
		t.Fatalf("uid = %v, want nil for a value above u32", *entry.UID)
	}
	if entry.GID != nil {
		t.Fatalf("gid = %v, want nil for a negative value", *entry.GID)
	}
	if entry.User != nil {
		t.Fatalf("user = %v, want nil for empty text", *entry.User)
	}
	if entry.Atime != nil {
		t.Fatalf("atime = %v, want nil", *entry.Atime)
	}
	if entry.Mtime != nil {
		t.Fatalf("mtime = %v, want nil without a zone", *entry.Mtime)
	}
}

func TestUnresolvedHardLink(t *testing.T) {
	body := `<file id="2"><name>lost.txt</name><type>file</type><link type="hard">99</link></file>`
	reader := openBytes(t, plainArchive(body, nil, 0))
	if stats := reader.Stats(); stats.UnresolvedHardlinks != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	entry, ok := reader.Entry("lost.txt")
	if !ok || entry.Data != nil || entry.HardlinkOf != nil {
		t.Fatalf("entry = %+v", entry)
	}
	_, err := reader.OpenEntrySource("lost.txt", 2)
	wantUnsupported(t, err, "data-bearing member")
}

func TestLimits(t *testing.T) {
	t.Run("entries", func(t *testing.T) {
		body := `<file id="1"><name>a</name><type>file</type></file>
<file id="2"><name>b</name><type>file</type></file>`
		limits := DefaultLimits()
		limits.MaxEntries = 1
		_, err := OpenWithLimits(source.NewMemorySource(1, plainArchive(body, nil, 0)), limits)
		wantUnsupported(t, err, "more than 1")
	})

	t.Run("depth", func(t *testing.T) {
		body := `<file id="1"><name>d</name><type>directory</type>
<file id="2"><name>e</name><type>file</type></file></file>`
		limits := DefaultLimits()
		limits.MaxDepth = 1
		_, err := OpenWithLimits(source.NewMemorySource(1, plainArchive(body, nil, 0)), limits)
		wantUnsupported(t, err, "nested deeper than 1")
	})

	t.Run("header", func(t *testing.T) {
		xml := tocDoc("")
		parts := xarParts{xml: xml, compressed: zlibCompress([]byte(xml)), headerSize: 64}
		limits := DefaultLimits()
		limits.MaxHeaderBytes = 32
		_, err := OpenWithLimits(source.NewMemorySource(1, parts.bytes()), limits)
		wantUnsupported(t, err, "header")
	})

	t.Run("decoded-bytes", func(t *testing.T) {
		reader, err := OpenWithLimits(source.NewMemorySource(1, sampleZlib()), func() Limits {
			limits := DefaultLimits()
			limits.MaxDecodedBytes = 5
			return limits
		}())
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		src, err := reader.OpenEntrySource("hello.txt", 2)
		if err != nil {
			t.Fatalf("open entry: %v", err)
		}
		_, err = src.ReadAt(0, make([]byte, 10))
		wantUnsupported(t, err, "read cap")
	})
}

func TestStoredLengthMismatchIsCorrupt(t *testing.T) {
	body := `<file id="1"><name>short.bin</name><type>file</type><size>10</size>
<data><length>5</length><offset>0</offset><size>10</size>
<encoding style="application/octet-stream"/></data></file>`
	reader := openBytes(t, plainArchive(body, []byte("abcde"), 0))
	src, err := reader.OpenEntrySource("short.bin", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, 10)
	n, err := src.ReadAt(0, buf)
	if err != nil || n != 5 {
		t.Fatalf("read = %d, %v", n, err)
	}
	if src.Stats().CorruptBytes != 5 {
		t.Fatalf("corrupt = %d, want 5", src.Stats().CorruptBytes)
	}
	if _, err := src.ReadAt(6, buf[:1]); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("read past decoded bytes = %v, want ErrCorrupt", err)
	}
}

func TestZlibInflatingPastDeclaredIsCorrupt(t *testing.T) {
	// The declared size is far below the stream's real output, so the decoder
	// must stop at the limit and report corrupt rather than fabricate a size.
	body := fmt.Sprintf(`<file id="1"><name>bomb.bin</name><type>file</type><size>4</size>
<data><length>%d</length><offset>0</offset><size>4</size>
<encoding style="application/x-gzip"/></data></file>`, len(zlibCompress([]byte(innerText))))
	reader := openBytes(t, plainArchive(body, zlibCompress([]byte(innerText)), 0))
	src, err := reader.OpenEntrySource("bomb.bin", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, err = src.ReadAt(0, make([]byte, 4))
	wantCorrupt(t, err, "zlib stream")
}

func TestEntrySourceBoundsLossyAndCache(t *testing.T) {
	reader := openBytes(t, sampleZlib())
	src, err := reader.OpenEntrySource("hello.txt", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if n, err := src.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if _, err := src.ReadAt(10, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read at EOF = %v", err)
	}
	if _, err := src.ReadAt(11, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past EOF = %v", err)
	}

	first := make([]byte, 4)
	if _, err := src.ReadAt(0, first); err != nil {
		t.Fatalf("first read: %v", err)
	}
	second := make([]byte, 4)
	if _, err := src.ReadAt(2, second); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(second) != helloText[2:6] {
		t.Fatalf("second read = %q", second)
	}
	stats := src.Stats()
	if stats.CacheMisses != 1 || stats.CacheHits != 1 {
		t.Fatalf("cache counters = %+v", stats)
	}

	unsupportedSrc, err := reader.OpenEntrySource("packed", 3)
	_ = unsupportedSrc
	if err == nil {
		t.Fatal("packed entry should not exist")
	}

	body := `<file id="1"><name>packed.bin</name><type>file</type><size>5</size>
<data><length>5</length><offset>0</offset><size>5</size>
<encoding style="application/x-snappy"/></data></file>`
	packedReader := openBytes(t, plainArchive(body, []byte("abcde"), 0))
	packed, err := packedReader.OpenEntrySource("packed.bin", 4)
	if err != nil {
		t.Fatalf("open packed: %v", err)
	}
	buf := make([]byte, 5)
	n, err := packed.ReadAtLossy(0, buf)
	if err != nil || n != 5 {
		t.Fatalf("lossy read = %d, %v", n, err)
	}
	if !bytes.Equal(buf, make([]byte, 5)) {
		t.Fatalf("lossy read did not zero-fill: %v", buf)
	}
	if packed.Stats().CorruptBytes != 5 {
		t.Fatalf("corrupt = %d, want 5", packed.Stats().CorruptBytes)
	}
}

func TestExtentsAndMapToImage(t *testing.T) {
	reader := openBytes(t, sampleZlib())
	hello, err := reader.OpenEntrySource("hello.txt", 2)
	if err != nil {
		t.Fatalf("open hello: %v", err)
	}
	ranges, err := hello.Extents(2, 4)
	if err != nil {
		t.Fatalf("extents: %v", err)
	}
	if len(ranges) != 1 || ranges[0].Kind != source.RangeData || ranges[0].Len != 4 {
		t.Fatalf("ranges = %+v", ranges)
	}
	if ranges[0].ParentOffset != hello.DataOffset()+2 {
		t.Fatalf("parent offset = %d, want %d", ranges[0].ParentOffset, hello.DataOffset()+2)
	}
	if _, err := hello.Extents(8, 4); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extents past EOF = %v", err)
	}
	empty, err := hello.Extents(0, 0)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty extents = %+v, %v", empty, err)
	}

	images, err := hello.MapToImage(2, 4)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(images) != 1 || images[0].ImageOffset != hello.DataOffset()+2 || images[0].Len != 4 {
		t.Fatalf("images = %+v", images)
	}

	inner, err := reader.OpenEntrySource("dir/inner.bin", 3)
	if err != nil {
		t.Fatalf("open inner: %v", err)
	}
	compressedRanges, err := inner.Extents(0, 4)
	if err != nil {
		t.Fatalf("compressed extents: %v", err)
	}
	if len(compressedRanges) != 1 || compressedRanges[0].ParentOffset != inner.DataOffset() ||
		compressedRanges[0].Len != inner.StoredSize() {
		t.Fatalf("compressed ranges = %+v", compressedRanges)
	}
	compressedImages, err := inner.MapToImage(0, 4)
	if err != nil {
		t.Fatalf("compressed map: %v", err)
	}
	if len(compressedImages) != 1 || compressedImages[0].Len != inner.StoredSize() {
		t.Fatalf("compressed images = %+v", compressedImages)
	}
}

func TestConcurrentEntryReads(t *testing.T) {
	reader := openBytes(t, sampleZlib())
	src, err := reader.OpenEntrySource("dir/inner.bin", 2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var wait sync.WaitGroup
	errs := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			buf := make([]byte, len(innerText))
			if _, err := src.ReadAt(0, buf); err != nil {
				errs <- err
				return
			}
			if string(buf) != innerText {
				errs <- fmt.Errorf("decoded %q", buf)
			}
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if src.Stats().CacheHits == 0 {
		t.Fatal("concurrent reads never hit the decode cache")
	}
}

func TestAdapterListsAndBudgets(t *testing.T) {
	adapter := &Adapter{}
	if adapter.FormatID() != "xar" {
		t.Fatalf("format = %q", adapter.FormatID())
	}
	reader, err := adapter.Open(source.NewMemorySource(1, sampleZlib()), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("adapter open: %v", err)
	}
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Path != "hello.txt" || entries[0].Kind != archive.KindFile || entries[0].Size != 10 {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if entries[0].Modified == nil || entries[0].CompressedSize == nil || *entries[0].CompressedSize != 10 {
		t.Fatalf("first entry metadata = %+v", entries[0])
	}
	if entries[3].Kind != archive.KindSymlink {
		t.Fatalf("link kind = %v", entries[3].Kind)
	}
	found, ok, err := reader.FindEntry("dir")
	if err != nil || !ok || found.Kind != archive.KindDirectory {
		t.Fatalf("find dir = %+v, %v, %v", found, ok, err)
	}

	limits := archive.DefaultLimits()
	limits.MaxEntries = 2
	if _, err := adapter.Open(source.NewMemorySource(1, sampleZlib()), limits); !errors.Is(err, archive.ErrLimit) {
		t.Fatalf("budget error = %v, want archive.ErrLimit", err)
	}
}

func TestEncodingAndStatusLabels(t *testing.T) {
	for encoding, label := range map[Encoding]string{
		EncodingStored: "stored",
		EncodingZlib:   "zlib",
		EncodingBzip2:  "bzip2",
		EncodingLZMA:   "lzma",
		EncodingXZ:     "xz",
		EncodingOther:  "other",
	} {
		if encoding.Label() != label {
			t.Fatalf("%d label = %q, want %q", encoding, encoding.Label(), label)
		}
	}
	if !EncodingStored.IsSupported() || !EncodingZlib.IsSupported() || !EncodingBzip2.IsSupported() {
		t.Fatal("decoded encodings must report support")
	}
	if EncodingLZMA.IsSupported() || EncodingXZ.IsSupported() || EncodingOther.IsSupported() {
		t.Fatal("unported encodings must not report support")
	}
	if EncodingLZMA.IsKnown() != true || EncodingOther.IsKnown() != false {
		t.Fatal("IsKnown misclassifies an encoding")
	}
	for status, label := range map[TOCStatus]string{
		TOCNotRecorded: "not recorded",
		TOCVerified:    "verified",
		TOCMismatch:    "mismatch",
		TOCAbsent:      "absent",
		TOCUnsupported: "unsupported",
		TOCMalformed:   "malformed",
	} {
		if status.Label() != label {
			t.Fatalf("%d label = %q, want %q", status, status.Label(), label)
		}
	}
	for kind, label := range map[EntryKind]string{
		EntryKindFile:      "file",
		EntryKindDirectory: "directory",
		EntryKindSymlink:   "symlink",
		EntryKindHardlink:  "hard link",
	} {
		if kind.Label() != label {
			t.Fatalf("%d label = %q, want %q", kind, kind.Label(), label)
		}
	}
}

func TestEntriesAreCopied(t *testing.T) {
	reader := openBytes(t, sampleZlib())
	entries := reader.Entries()
	entries[0].Path = "mutated"
	if _, ok := reader.Entry("hello.txt"); !ok {
		t.Fatal("mutating the returned slice changed the reader")
	}
}

func ptrU64(value uint64) *uint64 { return &value }
