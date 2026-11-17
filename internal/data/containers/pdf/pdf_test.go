package pdf

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestMatchesSignature(t *testing.T) {
	if !MatchesSignature([]byte("%PDF-1.7\n")) {
		t.Fatal("classic header not matched")
	}
	if !MatchesSignature([]byte("junkjunk%PDF-1.4\n")) {
		t.Fatal("header after junk not matched")
	}
	if MatchesSignature([]byte("not a pdf")) {
		t.Fatal("non-PDF matched")
	}
}

func TestClassicDocumentReportsIdentityPagesAndActions(t *testing.T) {
	bytesValue := classicPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R /Lang (zh-CN) " +
			"/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>",
		"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
		"<< /Type /Page /Parent 2 0 R >>",
		"<< /Type /Page /Parent 2 0 R >>",
		"<< /Title (Evidence) /Author <FEFF00420069> " +
			"/Producer (writer 1.0) /CreationDate (D:20240102103000+08'00') >>",
	}, "/Root 1 0 R /Info 5 0 R /ID [<00112233> <44556677>]")

	document, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if document.HeaderVersion != "1.7" || document.Version != "1.7" {
		t.Fatalf("versions = %q / %q", document.HeaderVersion, document.Version)
	}
	info := document.Info()
	if info.Title == nil || *info.Title != "Evidence" {
		t.Fatalf("title = %v", info.Title)
	}
	if info.Author == nil || *info.Author != "Bi" {
		t.Fatalf("author = %v", info.Author)
	}
	if info.Producer == nil || *info.Producer != "writer 1.0" {
		t.Fatalf("producer = %v", info.Producer)
	}
	if info.CreationDate == nil {
		t.Fatal("creation date missing")
	}
	if info.CreationDate.OffsetMinutes == nil || *info.CreationDate.OffsetMinutes != 480 {
		t.Fatalf("offset = %v", info.CreationDate.OffsetMinutes)
	}
	if info.CreationDate.UnixSeconds == nil || *info.CreationDate.UnixSeconds != 1_704_162_600 {
		t.Fatalf("unix seconds = %v", info.CreationDate.UnixSeconds)
	}

	pages := document.Pages()
	if pages.Declared == nil || *pages.Declared != 2 || pages.Counted != 2 || pages.Depth != 1 {
		t.Fatalf("pages = %+v", pages)
	}
	if len(pages.Objects) != 2 || pages.Objects[0] != 3 || pages.Objects[1] != 4 {
		t.Fatalf("page objects = %v", pages.Objects)
	}
	if document.Catalog.Lang == nil || *document.Catalog.Lang != "zh-CN" {
		t.Fatalf("lang = %v", document.Catalog.Lang)
	}
	open := document.Catalog.OpenAction
	if open == nil || open.Kind != "JavaScript" || open.Script == nil || *open.Script != "app.alert(1)" {
		t.Fatalf("open action = %+v", open)
	}
	if len(document.Trailer.IDs) != 2 || document.Trailer.IDs[0] != "00112233" || document.Trailer.IDs[1] != "44556677" {
		t.Fatalf("IDs = %v", document.Trailer.IDs)
	}
	if document.Trailer.Updates != 1 || document.Trailer.Repaired {
		t.Fatalf("trailer = %+v", document.Trailer)
	}
	if document.Trailer.Size == nil || *document.Trailer.Size != 6 {
		t.Fatalf("trailer size = %v", document.Trailer.Size)
	}
	if document.Trailer.Root == nil || document.Trailer.Root.Number != 1 {
		t.Fatalf("trailer root = %v", document.Trailer.Root)
	}

	value, ok, err := document.Object(1)
	if err != nil || !ok {
		t.Fatalf("Object(1) = %v/%v/%v", value, ok, err)
	}
	if dict, ok := value.AsDict(); !ok || !IsNameValue(dict, []byte("Type"), []byte("Catalog")) {
		t.Fatalf("object 1 = %v", value)
	}

	resolved, wasReference, err := document.Resolve(RefValue(Reference{Number: 2, Generation: 0}))
	if err != nil || !wasReference {
		t.Fatalf("Resolve = %v/%v/%v", resolved, wasReference, err)
	}
	if dict, ok := resolved.AsDict(); !ok || !IsNameValue(dict, []byte("Type"), []byte("Pages")) {
		t.Fatalf("resolved = %v", resolved)
	}
	if _, _, err := document.Resolve(RefValue(Reference{Number: 99, Generation: 0})); err != nil {
		t.Fatalf("Resolve(absent) error = %v", err)
	}

	objects := document.Objects()
	if len(objects) != 6 || objects[0].Number != 0 || objects[0].Kind != ObjectFree {
		t.Fatalf("objects = %+v", objects)
	}
	stats := document.Stats()
	if stats.ObjectsLoaded == 0 || stats.XrefEntries != 6 || stats.Repaired {
		t.Fatalf("stats = %+v", stats)
	}
	if document.Source() == nil || document.Source().Len() != uint64(len(bytesValue)) {
		t.Fatalf("source = %v", document.Source())
	}
}

func TestEffectiveVersionComesFromCatalog(t *testing.T) {
	bytesValue := classicPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R /Version /2.0 >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
	}, "/Root 1 0 R")
	document, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if document.HeaderVersion != "1.7" || document.Version != "2.0" ||
		document.CatalogVersion == nil || *document.CatalogVersion != "2.0" {
		t.Fatalf("versions = %q / %q / %v", document.HeaderVersion, document.Version, document.CatalogVersion)
	}
}

func TestTextStringsFollowTheirByteOrderMark(t *testing.T) {
	for name, test := range map[string]struct {
		bytesValue []byte
		want       string
	}{
		"plain":  {[]byte("plain"), "plain"},
		"pdfdoc": {[]byte{0x18}, "˘"},
		"bullet": {[]byte{0x80}, "•"},
		"utf16b": {[]byte{0xFE, 0xFF, 0x00, 0x41}, "A"},
		"utf16l": {[]byte{0xFF, 0xFE, 0x41, 0x00}, "A"},
		"utf8":   {[]byte{0xEF, 0xBB, 0xBF, 'x'}, "x"},
	} {
		if got := DecodePDFText(test.bytesValue); got != test.want {
			t.Fatalf("%s = %q, want %q", name, got, test.want)
		}
	}
}

func TestPDFDatesTakeMissingFieldsAndZones(t *testing.T) {
	date := ParsePDFDate("D:2024")
	if date == nil || date.Month != 1 || date.Day != 1 || date.OffsetMinutes != nil || date.UnixSeconds == nil {
		t.Fatalf("date = %+v", date)
	}
	want := int64(1_704_067_200) // 2024-01-01T00:00:00Z
	if *date.UnixSeconds != want {
		t.Fatalf("2024 seconds = %d, want %d", *date.UnixSeconds, want)
	}
	utc := ParsePDFDate("20240229120000Z")
	if utc == nil || utc.OffsetMinutes == nil || *utc.OffsetMinutes != 0 || utc.UnixSeconds == nil {
		t.Fatalf("utc = %+v", utc)
	}
	west := ParsePDFDate("D:20240101120000-05'30'")
	if west == nil || west.OffsetMinutes == nil || *west.OffsetMinutes != -330 {
		t.Fatalf("west = %+v", west)
	}
	if west.UnixSeconds == nil || *west.UnixSeconds != 1_704_130_200 {
		t.Fatalf("west seconds = %v", west.UnixSeconds)
	}
	if ParsePDFDate("not a date") != nil {
		t.Fatal("invalid date parsed")
	}
	if ParsePDFDate("D:20241301") != nil && ParsePDFDate("D:20241301").UnixSeconds != nil {
		t.Fatal("month 13 produced an instant")
	}
}

func streamObjectText(entries string, data []byte) string {
	if entries != "" {
		entries = " " + entries
	}
	return fmt.Sprintf("<<%s /Length %d >>\nstream\n", entries, len(data)) + string(data) + "\nendstream"
}

func TestXrefStreamAndObjectStream(t *testing.T) {
	var prefix []byte
	prefix = append(prefix, []byte("%PDF-1.7\n")...)
	pagesAt := len(prefix)
	prefix = append(prefix, []byte("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")...)

	firstObject := "<< /Type /Catalog /Pages 2 0 R >>"
	infoObject := "<< /Title (Compressed) >>"
	header := fmt.Sprintf("1 0 3 %d", len(firstObject)+1)
	payload := firstObject + " " + infoObject
	objstmAt := len(prefix)
	objstmDict := fmt.Sprintf("<< /Type /ObjStm /N 2 /First %d /Length %d >>", len(header), len(header)+len(payload))
	prefix = append(prefix, []byte(fmt.Sprintf("4 0 obj\n%s\nstream\n%s%s\nendstream\nendobj\n",
		objstmDict, header, payload))...)
	xrefAt := len(prefix)

	rows := [][]byte{
		{0, 0, 0, 0, 0, 0, 0}, // object 0, free
		{2, 0, 0, 0, 4, 0, 0}, // object 1, in stream 4 slot 0
		{1, byte(pagesAt >> 24), byte(pagesAt >> 16), byte(pagesAt >> 8), byte(pagesAt), 0, 0},
		{2, 0, 0, 0, 4, 0, 1}, // object 3, in stream 4 slot 1
		{1, byte(objstmAt >> 24), byte(objstmAt >> 16), byte(objstmAt >> 8), byte(objstmAt), 0, 0},
		{1, byte(xrefAt >> 24), byte(xrefAt >> 16), byte(xrefAt >> 8), byte(xrefAt), 0, 0},
	}
	encoded := zlibBytes(pngRows(rows, 7))
	xrefDict := fmt.Sprintf("<< /Type /XRef /Size 6 /Root 1 0 R /Info 3 0 R /W [1 4 2] "+
		"/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >> /Length %d >>", len(encoded))
	bytesValue := append([]byte(nil), prefix...)
	bytesValue = append(bytesValue, []byte(fmt.Sprintf("5 0 obj\n%s\nstream\n", xrefDict))...)
	bytesValue = append(bytesValue, encoded...)
	bytesValue = append(bytesValue, []byte(fmt.Sprintf("\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", xrefAt))...)

	document, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v; notes: %v", err, documentNotes(err))
	}
	if document.Trailer.CompressedEntries != 2 {
		t.Fatalf("compressed entries = %d, notes = %v", document.Trailer.CompressedEntries, document.Notes())
	}
	if info := document.Info(); info.Title == nil || *info.Title != "Compressed" {
		t.Fatalf("title = %v, notes = %v", info.Title, document.Notes())
	}
	if pages := document.Pages(); pages.Declared == nil || *pages.Declared != 0 {
		t.Fatalf("declared pages = %v", pages.Declared)
	}
	value, ok, err := document.Object(1)
	if err != nil || !ok {
		t.Fatalf("Object(1) = %v/%v/%v", value, ok, err)
	}
	if dict, ok := value.AsDict(); !ok || !IsNameValue(dict, []byte("Type"), []byte("Catalog")) {
		t.Fatalf("object 1 = %v", value)
	}
	if len(document.Trailer.Sections) != 1 || document.Trailer.Sections[0] != "stream" {
		t.Fatalf("sections = %v", document.Trailer.Sections)
	}
}

func documentNotes(err error) []string { return []string{err.Error()} }

func TestIncrementalUpdateOverridesCatalog(t *testing.T) {
	base := classicPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
	}, "/Root 1 0 R")
	baseXref := startxrefOffset(t, base)
	updated := append([]byte(nil), base...)
	newObject := len(updated)
	updated = append(updated, []byte("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Lang (en) >>\nendobj\n")...)
	xrefAt := len(updated)
	updated = append(updated, []byte("xref\n0 1\n0000000000 65535 f \n1 1\n"+pad10(newObject)+
		" 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R /Prev "+itoa(int64(baseXref))+
		" >>\nstartxref\n"+itoa(int64(xrefAt))+"\n%%EOF\n")...)

	document, err := Open(testSource(updated), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if document.Trailer.Updates != 2 || len(document.Trailer.History) != 2 {
		t.Fatalf("trailer = %+v", document.Trailer)
	}
	if document.Catalog.Lang == nil || *document.Catalog.Lang != "en" {
		t.Fatalf("lang = %v; notes: %v", document.Catalog.Lang, document.Notes())
	}
	for _, section := range document.Trailer.History {
		if section.Kind != "table" || section.Entries == 0 {
			t.Fatalf("history = %+v", document.Trailer.History)
		}
	}
}

func TestMetadataAndAttachment(t *testing.T) {
	attachment := []byte("hello attachment")
	compressedAttachment := zlibBytes(attachment)
	xmp := []byte(`<?xpacket begin="` + "\uFEFF" + `" id="W5M0MpCehiHzreSzNTczkc9d"?>` +
		`<x:xmpmeta xmlns:x="adobe:ns:meta/">` +
		`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">` +
		`<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" ` +
		`xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreateDate="2024-01-02T03:04:05Z">` +
		`<dc:title><rdf:Alt><rdf:li xml:lang="x-default">Evidence Title</rdf:li></rdf:Alt></dc:title>` +
		`<dc:creator><rdf:Seq><rdf:li>Analyst</rdf:li></rdf:Seq></dc:creator>` +
		`</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)
	compressedXMP := zlibBytes(xmp)

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 8 0 R >> /Metadata 5 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
		"<< /Title (Doc Title) /Producer (Writer 2.0) >>",
		"<< /Unused true >>",
		streamObjectText("/Type /Metadata /Subtype /XML /Filter /FlateDecode", compressedXMP),
		"<< /Type /Filespec /F (attach.txt) /UF (attach.txt) /Desc (A note) " +
			"/Subtype /text#2Fplain /EF << /F 7 0 R >> " +
			"/Params << /Size 16 /CheckSum <00112233445566778899AABBCCDDEEFF> " +
			"/CreationDate (D:20240101120000Z) >> >>",
		streamObjectText("/Filter /FlateDecode", compressedAttachment),
		"<< /Names [(attach.txt) 6 0 R] >>",
	}
	bytesValue := classicPDF(objects, "/Root 1 0 R /Info 3 0 R")
	document, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}

	if document.Metadata == nil {
		t.Fatalf("metadata missing; notes: %v", document.Notes())
	}
	if document.Metadata.Bytes != len(xmp) || document.Metadata.Text != string(xmp) {
		t.Fatalf("metadata = %d bytes / %q", document.Metadata.Bytes, document.Metadata.Text)
	}
	fields := map[string]string{}
	for _, field := range document.Metadata.Fields {
		fields[field.Name] = field.Value
	}
	if fields["title"] != "Evidence Title" || fields["creator"] != "Analyst" ||
		fields["CreateDate"] != "2024-01-02T03:04:05Z" {
		t.Fatalf("XMP fields = %v", document.Metadata.Fields)
	}

	attachments := document.Attachments()
	if len(attachments) != 1 {
		t.Fatalf("attachments = %d; notes: %v", len(attachments), document.Notes())
	}
	file := attachments[0]
	if file.Name != "attach.txt" || file.Filename == nil || *file.Filename != "attach.txt" {
		t.Fatalf("attachment = %+v", file)
	}
	if file.Description == nil || *file.Description != "A note" {
		t.Fatalf("description = %v", file.Description)
	}
	if file.Subtype == nil || *file.Subtype != "text/plain" {
		t.Fatalf("subtype = %v", file.Subtype)
	}
	if file.Checksum == nil || *file.Checksum != "00112233445566778899aabbccddeeff" {
		t.Fatalf("checksum = %v", file.Checksum)
	}
	if file.CreationDate == nil || file.CreationDate.UnixSeconds == nil || *file.CreationDate.UnixSeconds != 1_704_110_400 {
		t.Fatalf("creation date = %+v", file.CreationDate)
	}
	if file.Size == nil || *file.Size != 16 || file.Bytes == nil || *file.Bytes != len(attachment) {
		t.Fatalf("sizes = %v / %v", file.Size, file.Bytes)
	}
	if file.SHA256 == nil || *file.SHA256 != sha256Hex(attachment) {
		t.Fatalf("sha256 = %v", file.SHA256)
	}
	if len(file.Filters) != 1 || file.Filters[0] != "FlateDecode" || file.Note != nil {
		t.Fatalf("filters = %v, note = %v", file.Filters, file.Note)
	}

	attachmentSource, err := document.OpenAttachment("attach.txt", 2)
	if err != nil {
		t.Fatalf("OpenAttachment error = %v", err)
	}
	if attachmentSource.Name() != "attach.txt" || attachmentSource.Len() != uint64(len(attachment)) {
		t.Fatalf("attachment source = %+v", attachmentSource)
	}
	if attachmentSource.Index() != 0 || attachmentSource.SourceID() != 2 ||
		attachmentSource.ImageID() != 0 || attachmentSource.SectorSize() != 512 ||
		attachmentSource.IsEmpty() {
		t.Fatalf("attachment source identity = %+v", attachmentSource)
	}
	if string(attachmentSource.Bytes()) != string(attachment) {
		t.Fatalf("attachment bytes = %q", attachmentSource.Bytes())
	}
	filters := attachmentSource.Filters()
	if len(filters) != 1 || filters[0] != "FlateDecode" {
		t.Fatalf("accessor filters = %v", filters)
	}
	read := make([]byte, 5)
	if n, err := attachmentSource.ReadAt(0, read); err != nil || n != 5 || string(read) != "hello" {
		t.Fatalf("ReadAt(0) = %d/%v/%q", n, err, read)
	}
	if n, err := attachmentSource.ReadAtLossy(6, read); err != nil || string(read[:n]) != "attac" {
		t.Fatalf("ReadAtLossy(6) = %d/%v/%q", n, err, read[:n])
	}
	if _, err := attachmentSource.ReadAt(16, read); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt(16) error = %v", err)
	}
	objectAt := bytes.Index(bytesValue, []byte("7 0 obj"))
	streamAt := bytes.Index(bytesValue[objectAt:], []byte("stream\n"))
	rawOffset := uint64(objectAt + streamAt + len("stream\n"))
	if attachmentSource.RawOffset() != rawOffset {
		t.Fatalf("raw offset = %d, want %d", attachmentSource.RawOffset(), rawOffset)
	}
	rawLength, hasLength := attachmentSource.RawLength()
	if !hasLength || rawLength != uint64(len(compressedAttachment)) {
		t.Fatalf("raw length = %d/%v, want %d", rawLength, hasLength, len(compressedAttachment))
	}
	extents, err := attachmentSource.Extents(0, 5)
	if err != nil || len(extents) != 1 || extents[0].Kind != source.RangeDerived ||
		extents[0].Parent != 2 || extents[0].Len != 5 {
		t.Fatalf("Extents = %+v/%v", extents, err)
	}
	images, err := attachmentSource.MapToImage(0, 5)
	if err != nil || len(images) != 1 || images[0].Kind != source.RangeDerived ||
		images[0].ImageOffset != rawOffset || images[0].Len != 5 {
		t.Fatalf("MapToImage = %+v/%v", images, err)
	}
	if attachmentSource.Stats().Reads == 0 {
		t.Fatal("attachment counters did not record the reads")
	}
	if _, err := attachmentSource.Extents(16, 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("Extents past end error = %v", err)
	}
	if _, err := document.OpenAttachment("missing", 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing attachment error = %v", err)
	}
}

func TestEncryptedDocumentNamesHandlerAndRefusesContent(t *testing.T) {
	zeros32 := strings.Repeat("00", 32)
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 7 0 R >> >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
		"<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4 " +
			"/O <" + zeros32 + "> /U <" + zeros32 + "> /EncryptMetadata false " +
			"/StmF /StdCF /StrF /StdCF /CF << /StdCF << /CFM /AESV2 /Length 16 >> >> >>",
		"<< /Title (secret) >>",
		"<< /Type /Filespec /F (secret.txt) /EF << /F 6 0 R >> >>",
		streamObjectText("", []byte("ciphertext")),
		"<< /Names [(secret.txt) 5 0 R] >>",
	}
	bytesValue := classicPDF(objects, "/Root 1 0 R /Info 4 0 R /Encrypt 3 0 R")
	document, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	encryption := document.Encrypted
	if encryption == nil {
		t.Fatalf("encryption missing; notes: %v", document.Notes())
	}
	if encryption.Filter == nil || *encryption.Filter != "Standard" ||
		encryption.Version == nil || *encryption.Version != 4 ||
		encryption.Revision == nil || *encryption.Revision != 4 ||
		encryption.LengthBits == nil || *encryption.LengthBits != 128 ||
		encryption.Permissions == nil || *encryption.Permissions != -4 {
		t.Fatalf("encryption = %+v", encryption)
	}
	if encryption.EncryptMetadata == nil || *encryption.EncryptMetadata {
		t.Fatalf("EncryptMetadata = %v", encryption.EncryptMetadata)
	}
	if encryption.OwnerEntryBytes == nil || *encryption.OwnerEntryBytes != 32 ||
		encryption.UserEntryBytes == nil || *encryption.UserEntryBytes != 32 {
		t.Fatalf("verifier lengths = %v / %v", encryption.OwnerEntryBytes, encryption.UserEntryBytes)
	}
	if len(encryption.CryptFilters) != 1 || encryption.CryptFilters[0] != "StdCF" ||
		encryption.CryptMethod == nil || *encryption.CryptMethod != "AESV2" ||
		encryption.StreamFilter == nil || *encryption.StreamFilter != "StdCF" {
		t.Fatalf("crypt filters = %+v", encryption)
	}
	if document.Info().Title != nil {
		t.Fatalf("encrypted title was decoded: %v", document.Info().Title)
	}
	if pages := document.Pages(); pages.Declared == nil || *pages.Declared != 0 {
		t.Fatalf("pages = %+v", pages)
	}
	if !strings.Contains(strings.Join(document.Notes(), "\n"), "encrypted; strings and streams were not decoded") {
		t.Fatalf("notes = %v", document.Notes())
	}
	if len(document.Attachments()) != 1 {
		t.Fatalf("attachments = %d", len(document.Attachments()))
	}
	if _, err := document.OpenAttachmentIndex(0, 2); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenAttachmentIndex error = %v, want ErrUnsupported", err)
	}
}

func TestCatalogActionsAcroFormAndOutlines(t *testing.T) {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /PageMode /UseOutlines /PageLayout /OneColumn " +
			"/Outlines 5 0 R /AcroForm 6 0 R " +
			"/AA << /Open << /S /JavaScript /JS (init) >> " +
			"/WC << /S /Launch /F (calc.exe) /D 3 >> >> " +
			"/Names << /JavaScript 9 0 R >> >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
		"<< /Type /Page /Parent 2 0 R >>",
		"<< /Unused true >>",
		"<< /Type /Outlines /Count 4 >>",
		"<< /Fields [7 0 R 8 0 R] /SigFlags 3 /NeedAppearances true /XFA (packet) >>",
		"<< /FT /Sig /T (sig1) /Kids [8 0 R] >>",
		"<< /FT /Tx >>",
		"<< /Names [(start) 11 0 R] >>",
		"(xfa packet)",
		"<< /S /JavaScript /JS (app.alert\\(1\\)) >>",
	}
	document, err := Open(testSource(classicPDF(objects, "/Root 1 0 R")), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if document.Catalog.PageMode == nil || *document.Catalog.PageMode != "UseOutlines" ||
		document.Catalog.PageLayout == nil || *document.Catalog.PageLayout != "OneColumn" {
		t.Fatalf("page mode/layout = %v / %v", document.Catalog.PageMode, document.Catalog.PageLayout)
	}
	if document.Catalog.Outlines == nil || *document.Catalog.Outlines != 4 {
		t.Fatalf("outlines = %v", document.Catalog.Outlines)
	}
	if !document.Catalog.HasNames || !document.Catalog.JavaScriptTree || document.Catalog.EmbeddedFileTree {
		t.Fatalf("name flags = %+v", document.Catalog)
	}
	form := document.Catalog.AcroForm
	if form == nil || !form.XFA || form.Fields != 2 || form.SignatureFields != 1 ||
		form.SigFlags == nil || *form.SigFlags != 3 ||
		form.NeedsAppearances == nil || !*form.NeedsAppearances {
		t.Fatalf("acro form = %+v", form)
	}

	actions := document.Catalog.Actions
	kinds := map[string]*Action{}
	for i := range actions {
		if actions[i].Event != nil {
			kinds[*actions[i].Event] = &actions[i]
		}
	}
	open := kinds["Open"]
	if open == nil || open.Kind != "JavaScript" || open.Script == nil || *open.Script != "init" {
		t.Fatalf("Open action = %+v; all = %+v", open, actions)
	}
	wc := kinds["WC"]
	if wc == nil || wc.Kind != "Launch" || wc.File == nil || *wc.File != "calc.exe" ||
		wc.Target == nil || *wc.Target != "page 3" {
		t.Fatalf("WC action = %+v", wc)
	}
	start := kinds["start"]
	if start == nil || start.Kind != "JavaScript" || start.Script == nil || *start.Script != "app.alert(1)" {
		t.Fatalf("start action = %+v", start)
	}
}

func TestTextAndMetadataLimitsTruncateOnBoundaries(t *testing.T) {
	xmp := []byte(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><dc:title>` + strings.Repeat("é", 20) + `</dc:title></x:xmpmeta>`)
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
		"<< /Title (" + strings.Repeat("é", 20) + ") >>",
		streamObjectText("/Subtype /XML", xmp),
	}
	document, err := Open(testSource(classicPDF(objects, "/Root 1 0 R /Info 3 0 R")), Limits{MaxTextBytes: 9})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if document.Info().Title == nil {
		t.Fatalf("title missing; notes = %v", document.Notes())
	}
	if len(*document.Info().Title) > 9 || !utf8.ValidString(*document.Info().Title) {
		t.Fatalf("truncated title = %q", *document.Info().Title)
	}
	if document.Metadata == nil || len(document.Metadata.Text) > 9 || !utf8.ValidString(document.Metadata.Text) {
		t.Fatalf("metadata = %+v", document.Metadata)
	}
	notes := strings.Join(document.Notes(), "\n")
	if !strings.Contains(notes, "text field truncated") || !strings.Contains(notes, "XMP packet truncated") {
		t.Fatalf("notes = %v", document.Notes())
	}
}

func TestOpenWithPasswordDecryptsRevisionTwoStrings(t *testing.T) {
	id0 := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	owner := bytes.Repeat([]byte{0x42}, 32)
	password := []byte("user")
	params := &encryptParams{
		hasVersion: true, version: 1,
		hasRevision: true, revision: 2,
		hasPermissions: true, permissions: -4,
		owner: owner, hasID0: true, id0: id0,
	}
	fileKey, err := deriveFileKey(params, password, 5)
	if err != nil {
		t.Fatalf("deriveFileKey error = %v", err)
	}
	userEntry := rc4(fileKey, passwordPadding[:])
	// Object 4 is the information dictionary; its generation is 0.
	titleKey := objectKey(fileKey, 4, 0, cipherRC4)
	titleCipher := rc4(titleKey, []byte("Secret"))
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
		"<< /Filter /Standard /V 1 /R 2 /P -4 /O <" + hexText(owner) + "> /U <" + hexText(userEntry) + "> >>",
		"<< /Title <" + hexText(titleCipher) + "> >>",
	}
	trailer := "/Root 1 0 R /Info 4 0 R /Encrypt 3 0 R /ID [<" + hexText(id0) + ">]"
	bytesValue := classicPDF(objects, trailer)

	opaque, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if opaque.Info().Title != nil {
		t.Fatalf("title without a password = %v", opaque.Info().Title)
	}

	decrypted, err := OpenWithPassword(testSource(bytesValue), Limits{}, password)
	if err != nil {
		t.Fatalf("OpenWithPassword error = %v", err)
	}
	if decrypted.Info().Title == nil || *decrypted.Info().Title != "Secret" {
		t.Fatalf("title = %v; notes = %v", decrypted.Info().Title, decrypted.Notes())
	}
	if !strings.Contains(strings.Join(decrypted.Notes(), "\n"), "user password verified; strings and streams were decrypted") {
		t.Fatalf("notes = %v", decrypted.Notes())
	}

	wrong, err := OpenWithPassword(testSource(bytesValue), Limits{}, []byte("wrong"))
	if err != nil {
		t.Fatalf("OpenWithPassword(wrong) error = %v", err)
	}
	if wrong.Info().Title != nil {
		t.Fatalf("wrong password decoded the title: %v", wrong.Info().Title)
	}
	if !strings.Contains(strings.Join(wrong.Notes(), "\n"), "not the user password") {
		t.Fatalf("wrong-password notes = %v", wrong.Notes())
	}
}

func TestRepairMarksTheDocument(t *testing.T) {
	bytesValue := classicPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
	}, "/Root 1 0 R")
	bytesValue = append(bytesValue, []byte("\nstartxref\n999999\n%%EOF\n")...)
	document, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if !document.Trailer.Repaired {
		t.Fatal("document was not marked repaired")
	}
	if pages := document.Pages(); pages.Declared == nil || *pages.Declared != 0 {
		t.Fatalf("pages = %+v; notes = %v", pages, document.Notes())
	}
	if !strings.Contains(strings.Join(document.Notes(), "\n"), "rebuilt by scanning") {
		t.Fatalf("notes = %v", document.Notes())
	}
}

func TestMalformedInputsAreRefused(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		_, err := Open(testSource(nil), Limits{})
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("error = %v, want ErrCorrupt", err)
		}
	})
	t.Run("no header", func(t *testing.T) {
		_, err := Open(testSource([]byte("this is not a PDF at all")), Limits{})
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("error = %v, want ErrCorrupt", err)
		}
	})
	t.Run("header but no objects", func(t *testing.T) {
		_, err := Open(testSource([]byte("%PDF-1.7\nstartxref\n0\n%%EOF\n")), Limits{})
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("error = %v, want ErrCorrupt", err)
		}
	})
	t.Run("truncated object body", func(t *testing.T) {
		objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [] /Count 0 >>"}
		bytesValue := classicPDF(objects, "/Root 1 0 R")
		index := bytes.Index(bytesValue, []byte("/Type /Catalog"))
		bytesValue[index] = '['
		document, err := Open(testSource(bytesValue), Limits{})
		if err != nil {
			return // a wholly unreadable file is also acceptable
		}
		if _, ok, err := document.Object(1); ok || err == nil {
			t.Fatalf("Object(1) = %v/%v/%v, want an error", Value{}, ok, err)
		}
	})
	t.Run("object header mismatch", func(t *testing.T) {
		body := "%PDF-1.7\n"
		first := len(body)
		body += "<< /Type /Catalog /Pages 2 0 R >>\n"
		// object 1 header points at object 2's offset.
		text := "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
			"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" +
			"xref\n0 3\n0000000000 65535 f \n" + pad10(first+1+len("1 0 obj\n")) +
			" 00000 n \n" + pad10(first+1+len("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")) +
			" 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n"
		// Compute the xref offset by building the prefix first.
		prefix := "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
			"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
		objectTwo := len("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
		xrefAt := len(prefix)
		full := prefix + "xref\n0 3\n0000000000 65535 f \n" + pad10(objectTwo) +
			" 00000 n \n" + pad10(objectTwo) + " 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\n" +
			"startxref\n" + itoa(int64(xrefAt)) + "\n%%EOF\n"
		_ = text
		document, err := Open(testSource([]byte(full)), Limits{})
		if err != nil {
			t.Fatalf("Open error = %v", err)
		}
		if _, ok, err := document.Object(1); ok || err == nil || !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Object(1) = %v/%v/%v, want ErrCorrupt", Value{}, ok, err)
		}
		if !strings.Contains(strings.Join(document.Notes(), "\n"), "catalog object could not be read") {
			t.Fatalf("notes = %v", document.Notes())
		}
	})
	t.Run("unterminated object", func(t *testing.T) {
		body := "%PDF-1.7\n1 0 obj\n<< /A [1 2\nendobj\nxref\n0 2\n0000000000 65535 f \n" +
			"0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n"
		xrefAt := len("%PDF-1.7\n1 0 obj\n<< /A [1 2\nendobj\n")
		body += itoa(int64(xrefAt)) + "\n%%EOF\n"
		document, err := Open(testSource([]byte(body)), Limits{})
		if err != nil {
			return
		}
		if _, _, err := document.Object(1); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Object(1) error = %v, want ErrCorrupt", err)
		}
	})
}

func TestCircularTreesStopAndNote(t *testing.T) {
	bytesValue := classicPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Pages /Kids [2 0 R] /Count 1 >>",
		"<< /Kids [4 0 R] >>",
	}, "/Root 1 0 R")
	document, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	notes := strings.Join(document.Notes(), "\n")
	if !strings.Contains(notes, "page tree references object 2 twice") {
		t.Fatalf("notes = %v", document.Notes())
	}
	if !strings.Contains(notes, "name tree references object 4 twice") {
		t.Fatalf("notes = %v", document.Notes())
	}
	pages := document.Pages()
	if pages.Counted != 0 || pages.Declared == nil || *pages.Declared != 1 {
		t.Fatalf("pages = %+v", pages)
	}
}

func TestSelfReferentialObjectStreamIsRefused(t *testing.T) {
	var prefix []byte
	prefix = append(prefix, []byte("%PDF-1.7\n")...)
	xrefAt := len(prefix)
	rows := [][]byte{
		{0, 0, 0, 0, 0, 0, 0},            // object 0 free
		{2, 0, 0, 0, 1, 0, 0},            // object 1 in stream 1 slot 0
		{1, 0, 0, 0, byte(xrefAt), 0, 0}, // object 2 is the xref stream
	}
	data := pngRows(rows, 7)
	xrefDict := fmt.Sprintf("<< /Type /XRef /Size 3 /Root 1 0 R /W [1 4 2] "+
		"/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >> /Length %d >>", len(zlibBytes(data)))
	bytesValue := append([]byte(nil), prefix...)
	bytesValue = append(bytesValue, []byte(fmt.Sprintf("2 0 obj\n%s\nstream\n", xrefDict))...)
	bytesValue = append(bytesValue, zlibBytes(data)...)
	bytesValue = append(bytesValue, []byte(fmt.Sprintf("\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", xrefAt))...)
	// Object 1 is said to be in object stream 1, which is also object 1.
	document, err := Open(testSource(bytesValue), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if _, _, err := document.Object(1); err == nil || !strings.Contains(err.Error(), "refers to itself") {
		t.Fatalf("Object(1) error = %v, want a self-reference refusal", err)
	}
}

func TestPagesAndObjectLimits(t *testing.T) {
	deep := "["
	for i := 0; i < 80; i++ {
		deep += "["
	}
	_, err := ParseFirstValue([]byte(deep))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("nested parse error = %v", err)
	}

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
	}
	bytesValue := classicPDF(objects, "/Root 1 0 R")
	document, err := Open(testSource(bytesValue), Limits{MaxObjects: 1})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if _, _, err := document.Object(2); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Object(2) error = %v, want a limit refusal", err)
	}
}

func TestUnsupportedStreamFilterIsNoted(t *testing.T) {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 5 0 R >> >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
		"<< /Type /Filespec /F (image.jpg) /EF << /F 4 0 R >> >>",
		streamObjectText("/Filter /DCTDecode", []byte("jpeg bytes")),
		"<< /Names [(image.jpg) 3 0 R] >>",
	}
	document, err := Open(testSource(classicPDF(objects, "/Root 1 0 R")), Limits{})
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	files := document.Attachments()
	if len(files) != 1 || files[0].Note == nil || !strings.Contains(*files[0].Note, "DCTDecode") {
		t.Fatalf("attachments = %+v", files)
	}
	if _, err := document.OpenAttachmentIndex(0, 2); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenAttachmentIndex error = %v, want ErrUnsupported", err)
	}
}

func TestMalformedVariantsDoNotPanic(t *testing.T) {
	full := classicPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 5 0 R >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R >>",
		"<< /Title (Robust) >>",
		"<< /Names [(f) 6 0 R] >>",
		streamObjectText("/Filter /FlateDecode", zlibBytes([]byte("payload"))),
	}, "/Root 1 0 R /Info 4 0 R")
	for length := 0; length < len(full); length += 7 {
		_, _ = Open(testSource(full[:length]), Limits{})
	}
	rng := rand.New(rand.NewSource(1))
	for attempt := 0; attempt < 60; attempt++ {
		mutated := append([]byte(nil), full...)
		for i := 0; i < 6; i++ {
			mutated[rng.Intn(len(mutated))] = byte(rng.Intn(256))
		}
		document, err := Open(testSource(mutated), Limits{MaxObjects: 64, MaxTreeNodes: 128})
		if err != nil {
			continue
		}
		_ = document.Objects()
		_ = document.Notes()
		_ = document.Stats()
		for number := uint32(0); number < 8; number++ {
			_, _, _ = document.Object(number)
		}
		for index := range document.Attachments() {
			_, _ = document.OpenAttachmentIndex(index, 1)
		}
	}
}

func TestNilSourceIsRefused(t *testing.T) {
	if _, err := Open(nil, Limits{}); err == nil || !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("Open(nil) error = %v, want ErrInvalidArgument", err)
	}
}
