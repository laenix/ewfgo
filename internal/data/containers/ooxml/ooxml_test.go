package ooxml

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	coreXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>Quarterly numbers</dc:title><dc:subject>Forecast</dc:subject><dc:creator>Alice</dc:creator>
<cp:keywords>finance; draft</cp:keywords><dc:description>Board pack</dc:description>
<cp:lastModifiedBy>Bob</cp:lastModifiedBy><cp:revision>7</cp:revision>
<dcterms:created xsi:type="dcterms:W3CDTF">2024-01-02T03:04:05Z</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">2024-02-03T04:05:06Z</dcterms:modified>
<dcterms:lastPrinted>2024-05-06T07:08:09.123456789+02:30</dcterms:lastPrinted>
<cp:category>Board</cp:category><cp:contentStatus>Final</cp:contentStatus>
<cp:identifier>CASE-1</cp:identifier><dc:language>en-GB</dc:language><cp:version>1.2</cp:version>
</cp:coreProperties>`

	appXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
<Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion>
<Company>Acme Ltd</Company><Manager>Carol</Manager>
<Template>\\fileserver\templates\report.dotm</Template>
<TotalTime>95</TotalTime><Pages>3</Pages><Words>1200</Words><Characters>7000</Characters>
<Lines>90</Lines><Paragraphs>22</Paragraphs><Slides>4</Slides><Notes>2</Notes><HiddenSlides>1</HiddenSlides>
<PresentationFormat>On-screen Show</PresentationFormat><DocSecurity>0</DocSecurity>
<ScaleCrop>false</ScaleCrop><LinksUpToDate>true</LinksUpToDate>
<SharedDoc>false</SharedDoc><HyperlinksChanged>yes</HyperlinksChanged>
</Properties>`

	customXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties">
<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Case ID"><vt:lpwstr xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">CASE-2024-001</vt:lpwstr></property>
<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="-3" name="Reviewed"><vt:bool xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">true</vt:bool></property>
</Properties>`

	contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

	documentXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p/></w:body></w:document>`

	wordRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://198.51.100.9/template.dotm" TargetMode="External"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="file:///C:/secret.txt" TargetMode="external"/>
</Relationships>`

	workbookXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>
<sheet name="Summary" sheetId="1" r:id="rId1"/>
<sheet name="Raw data" sheetId="2" state="hidden" r:id="rId2"/>
<sheet name="Scratch" sheetId="3" state="veryHidden" r:id="rId3"/>
</sheets>
<definedNames>
<definedName name="Report_Range">Summary!$A$1:$D$20</definedName>
<definedName name="Filter" localSheetId="1">'Raw data'!$A$2:$C$99</definedName>
</definedNames>
</workbook>`

	presentationXML = `<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldIdLst><p:sldId id="256"/><p:sldId id="257"/><p:sldId id="258"/></p:sldIdLst></p:presentation>`
)

type zipItem struct {
	name   string
	data   []byte
	method uint16
}

func zipPackage(t *testing.T, items []zipItem) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, item := range items {
		header := &zip.FileHeader{Name: item.name, Method: item.method}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", item.name, err)
		}
		if _, err := entry.Write(item.data); err != nil {
			t.Fatalf("write zip entry %q: %v", item.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func text(name string, data string) zipItem {
	return zipItem{name: name, data: []byte(data)}
}

func wordEntries(extra ...zipItem) []zipItem {
	items := []zipItem{
		text("[Content_Types].xml", contentTypesXML),
		text("docProps/core.xml", coreXML),
		text("docProps/app.xml", appXML),
		text("docProps/custom.xml", customXML),
		text("word/document.xml", documentXML),
		text("word/_rels/document.xml.rels", wordRelsXML),
	}
	return append(items, extra...)
}

func openPackage(t *testing.T, data []byte, limits Limits) *Document {
	t.Helper()
	document, err := Open(source.NewMemorySource(1, data), limits)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return document
}

func requireString(t *testing.T, got *string, want string) {
	t.Helper()
	if got == nil {
		t.Fatalf("value is nil, want %q", want)
	}
	if *got != want {
		t.Fatalf("value = %q, want %q", *got, want)
	}
}

func TestDetectRecognisesZIPSignatures(t *testing.T) {
	if !Detect([]byte("PK\x03\x04rest")) {
		t.Fatal("local-file signature not detected")
	}
	if !Detect([]byte("PK\x05\x06")) {
		t.Fatal("empty-archive signature not detected")
	}
	if Detect([]byte("xar!")) {
		t.Fatal("XAR detected as a ZIP")
	}
	if Detect(nil) {
		t.Fatal("empty head detected")
	}
}

func TestWordPackageExposesCoreAppCustomAndLinks(t *testing.T) {
	data := zipPackage(t, wordEntries(
		zipItem{name: "word/embeddings/oleObject1.bin", data: []byte("ole")},
		zipItem{name: "word/vbaProject.bin", data: []byte("vba")},
		zipItem{name: "_xmlsignatures/sig1.xml", data: []byte("<Signature/>")},
	))
	document := openPackage(t, data, Limits{})

	if document.Kind != KindWord {
		t.Fatalf("kind = %v, want Word", document.Kind)
	}
	if document.MainPart != "word/document.xml" {
		t.Fatalf("main part = %q", document.MainPart)
	}
	requireString(t, document.MainContentType, "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")

	requireString(t, document.Core.Title, "Quarterly numbers")
	requireString(t, document.Core.Subject, "Forecast")
	requireString(t, document.Core.Creator, "Alice")
	requireString(t, document.Core.Keywords, "finance; draft")
	requireString(t, document.Core.Description, "Board pack")
	requireString(t, document.Core.LastModifiedBy, "Bob")
	requireString(t, document.Core.Revision, "7")
	requireString(t, document.Core.Category, "Board")
	requireString(t, document.Core.ContentStatus, "Final")
	requireString(t, document.Core.Identifier, "CASE-1")
	requireString(t, document.Core.Language, "en-GB")
	requireString(t, document.Core.Version, "1.2")

	if document.Core.Created == nil || document.Core.Created.UnixSeconds == nil {
		t.Fatal("created time not parsed")
	}
	if got := *document.Core.Created.UnixSeconds; got != 1_704_164_645 {
		t.Fatalf("created seconds = %d", got)
	}
	if document.Core.Created.Nanos != 0 {
		t.Fatalf("created nanos = %d", document.Core.Created.Nanos)
	}
	if got := *document.Core.Modified.UnixSeconds; got != 1_706_933_106 {
		t.Fatalf("modified seconds = %d", got)
	}
	// 2024-05-06T07:08:09.123456789+02:30 is 2024-05-06T04:38:09.123456789Z.
	if got := *document.Core.LastPrinted.UnixSeconds; got != 1_714_970_289 {
		t.Fatalf("lastPrinted seconds = %d", got)
	}
	if document.Core.LastPrinted.Nanos != 123_456_789 {
		t.Fatalf("lastPrinted nanos = %d", document.Core.LastPrinted.Nanos)
	}

	requireString(t, document.App.Application, "Microsoft Office Word")
	requireString(t, document.App.AppVersion, "16.0000")
	requireString(t, document.App.Company, "Acme Ltd")
	requireString(t, document.App.Manager, "Carol")
	requireString(t, document.App.Template, `\\fileserver\templates\report.dotm`)
	if document.App.TotalTimeMinutes == nil || *document.App.TotalTimeMinutes != 95 {
		t.Fatal("total time not parsed")
	}
	if document.App.Pages == nil || *document.App.Pages != 3 {
		t.Fatal("pages not parsed")
	}
	if document.App.Words == nil || *document.App.Words != 1200 {
		t.Fatal("words not parsed")
	}
	if document.App.Characters == nil || *document.App.Characters != 7000 {
		t.Fatal("characters not parsed")
	}
	if document.App.Lines == nil || *document.App.Lines != 90 {
		t.Fatal("lines not parsed")
	}
	if document.App.Paragraphs == nil || *document.App.Paragraphs != 22 {
		t.Fatal("paragraphs not parsed")
	}
	if document.App.Slides == nil || *document.App.Slides != 4 {
		t.Fatal("slides not parsed")
	}
	if document.App.Notes == nil || *document.App.Notes != 2 {
		t.Fatal("notes not parsed")
	}
	if document.App.HiddenSlides == nil || *document.App.HiddenSlides != 1 {
		t.Fatal("hidden slides not parsed")
	}
	requireString(t, document.App.PresentationFormat, "On-screen Show")
	if document.App.DocSecurity == nil || *document.App.DocSecurity != 0 {
		t.Fatal("doc security not parsed")
	}
	if document.App.ScaleCrop == nil || *document.App.ScaleCrop {
		t.Fatal("scale crop not parsed")
	}
	if document.App.LinksUpToDate == nil || !*document.App.LinksUpToDate {
		t.Fatal("links up to date not parsed")
	}
	if document.App.SharedDoc == nil || *document.App.SharedDoc {
		t.Fatal("shared doc not parsed")
	}
	if document.App.HyperlinksChanged != nil {
		t.Fatal("an unrecognised boolean should stay nil")
	}

	if len(document.Custom) != 2 {
		t.Fatalf("custom properties = %d", len(document.Custom))
	}
	if document.Custom[0].Name != "Case ID" || document.Custom[0].PID == nil || *document.Custom[0].PID != 2 {
		t.Fatalf("first custom property = %+v", document.Custom[0])
	}
	requireString(t, document.Custom[0].FmtID, "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}")
	requireString(t, document.Custom[0].ValueType, "lpwstr")
	if document.Custom[0].Value != "CASE-2024-001" {
		t.Fatalf("custom value = %q", document.Custom[0].Value)
	}
	if document.Custom[1].PID == nil || *document.Custom[1].PID != -3 {
		t.Fatalf("second custom pid = %+v", document.Custom[1].PID)
	}
	requireString(t, document.Custom[1].ValueType, "bool")

	if len(document.ExternalRelationships) != 2 {
		t.Fatalf("external relationships = %d", len(document.ExternalRelationships))
	}
	if document.ExternalRelationships[0].Target != "http://198.51.100.9/template.dotm" {
		t.Fatalf("first target = %q", document.ExternalRelationships[0].Target)
	}
	requireString(t, document.ExternalRelationships[0].ID, "rId1")
	if document.ExternalRelationships[0].Part != "word/_rels/document.xml.rels" {
		t.Fatalf("relationship part = %q", document.ExternalRelationships[0].Part)
	}
	if !strings.HasSuffix(document.ExternalRelationships[0].Kind, "/attachedTemplate") {
		t.Fatalf("relationship kind = %q", document.ExternalRelationships[0].Kind)
	}
	if document.ExternalRelationships[1].Target != "file:///C:/secret.txt" {
		t.Fatalf("second target = %q", document.ExternalRelationships[1].Target)
	}

	if len(document.Embedded) != 1 || document.Embedded[0].Path != "word/embeddings/oleObject1.bin" {
		t.Fatalf("embedded = %+v", document.Embedded)
	}
	if document.Embedded[0].Size != 3 {
		t.Fatalf("embedded size = %d", document.Embedded[0].Size)
	}
	if !document.IsMacroEnabled() {
		t.Fatal("macro not detected")
	}
	if len(document.MacroParts) != 1 || document.MacroParts[0] != "word/vbaProject.bin" {
		t.Fatalf("macro parts = %v", document.MacroParts)
	}
	if len(document.Signatures) != 1 || document.Signatures[0] != "_xmlsignatures/sig1.xml" {
		t.Fatalf("signatures = %v", document.Signatures)
	}
	if len(document.Warnings) != 0 {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestWorkbookListsSheetsStatesAndDefinedNames(t *testing.T) {
	data := zipPackage(t, []zipItem{
		text("xl/workbook.xml", workbookXML),
		text("xl/worksheets/sheet1.xml", "<worksheet/>"),
	})
	document := openPackage(t, data, Limits{})
	if document.Kind != KindExcel {
		t.Fatalf("kind = %v, want Excel", document.Kind)
	}
	if len(document.Sheets) != 3 {
		t.Fatalf("sheets = %d", len(document.Sheets))
	}
	if document.Sheets[0].Name != "Summary" || document.Sheets[0].SheetID == nil || *document.Sheets[0].SheetID != 1 {
		t.Fatalf("first sheet = %+v", document.Sheets[0])
	}
	requireString(t, document.Sheets[0].RelationshipID, "rId1")
	if document.Sheets[0].IsHidden() {
		t.Fatal("Summary reported hidden")
	}
	if !document.Sheets[1].IsHidden() || !document.Sheets[2].IsHidden() {
		t.Fatal("hidden states not reported")
	}
	requireString(t, document.Sheets[2].State, "veryHidden")

	if len(document.DefinedNames) != 2 {
		t.Fatalf("defined names = %d", len(document.DefinedNames))
	}
	if document.DefinedNames[0].Name != "Report_Range" || document.DefinedNames[0].LocalSheetID != nil {
		t.Fatalf("first defined name = %+v", document.DefinedNames[0])
	}
	if document.DefinedNames[0].Value != "Summary!$A$1:$D$20" {
		t.Fatalf("first defined value = %q", document.DefinedNames[0].Value)
	}
	if document.DefinedNames[1].LocalSheetID == nil || *document.DefinedNames[1].LocalSheetID != 1 {
		t.Fatalf("second defined local id = %+v", document.DefinedNames[1].LocalSheetID)
	}
	if len(document.Warnings) != 0 {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestPresentationCountsSlides(t *testing.T) {
	document := openPackage(t, zipPackage(t, []zipItem{text("ppt/presentation.xml", presentationXML)}), Limits{})
	if document.Kind != KindPresentation {
		t.Fatalf("kind = %v, want Presentation", document.Kind)
	}
	if document.SlideCount == nil || *document.SlideCount != 3 {
		t.Fatalf("slide count = %+v", document.SlideCount)
	}
}

func TestZIPWithoutMainPartIsRefused(t *testing.T) {
	_, err := Open(source.NewMemorySource(1, zipPackage(t, []zipItem{text("a.txt", "x")})), Limits{})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if err == nil || !strings.Contains(err.Error(), "no OOXML main part") {
		t.Fatalf("error text = %v", err)
	}
}

func TestMalformedXMLWarnsAndPackageStillOpens(t *testing.T) {
	entries := []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/core.xml", "<cp:coreProperties><dc:title>"),
	}
	document := openPackage(t, zipPackage(t, entries), Limits{})
	if document.Kind != KindWord || document.Core.Title != nil {
		t.Fatalf("document = %+v", document)
	}
	if !hasWarning(document, "docProps/core.xml") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestDOCTYPEIsRefusedAsUnreadableXML(t *testing.T) {
	body := `<!DOCTYPE cp:coreProperties [ <!ENTITY x "y"> ]><cp:coreProperties><dc:title>&x;</dc:title></cp:coreProperties>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/core.xml", body),
	}), Limits{})
	if document.Core.Title != nil {
		t.Fatal("DOCTYPE body produced a title")
	}
	if !hasWarning(document, "not readable XML") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestDuplicateAttributeIsRefusedAsUnreadableXML(t *testing.T) {
	body := `<cp:coreProperties><dc:title x="1" x="2">T</dc:title></cp:coreProperties>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/core.xml", body),
	}), Limits{})
	if document.Core.Title != nil {
		t.Fatal("a document with duplicate attributes produced a title")
	}
	if !hasWarning(document, "not readable XML") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestPartAboveLimitIsNamedAndSkipped(t *testing.T) {
	data := zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/core.xml", coreXML),
	})
	document := openPackage(t, data, Limits{MaxPartBytes: 64})
	if document.Core.Title != nil {
		t.Fatal("oversized core part was read")
	}
	if !hasWarning(document, "above the 64-byte limit") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestCompressedBombPartIsSkippedBeforeInflation(t *testing.T) {
	bomb := bytes.Repeat([]byte("A"), 1<<20)
	data := zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		{name: "docProps/core.xml", data: bomb, method: zip.Deflate},
	})
	document := openPackage(t, data, Limits{MaxPartBytes: 64})
	if document.Core.Title != nil {
		t.Fatal("compressed bomb was read")
	}
	if !hasWarning(document, "above the 64-byte limit") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestTimeThatIsNotRFC3339KeepsItsText(t *testing.T) {
	body := `<cp:coreProperties><dcterms:created>2024-13-40</dcterms:created></cp:coreProperties>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/core.xml", body),
	}), Limits{})
	if document.Core.Created == nil {
		t.Fatal("created text missing")
	}
	if document.Core.Created.Text != "2024-13-40" {
		t.Fatalf("text = %q", document.Core.Created.Text)
	}
	if document.Core.Created.UnixSeconds != nil {
		t.Fatalf("invalid time parsed: %+v", document.Core.Created)
	}
	if document.Core.Created.Parsed() {
		t.Fatal("Parsed reported true")
	}
}

func TestRFC3339Variants(t *testing.T) {
	body := `<cp:coreProperties>` +
		`<dcterms:created>2024-01-02T03:04:05z</dcterms:created>` +
		`<dcterms:modified>2024-01-02T03:04:05+0230</dcterms:modified>` +
		`<dcterms:lastPrinted>2024-01-02T03:04:05.1Z</dcterms:lastPrinted>` +
		`</cp:coreProperties>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/core.xml", body),
	}), Limits{})
	if document.Core.Created.UnixSeconds == nil || *document.Core.Created.UnixSeconds != 1_704_164_645 {
		t.Fatalf("lowercase z not parsed: %+v", document.Core.Created)
	}
	if document.Core.Modified.UnixSeconds == nil || *document.Core.Modified.UnixSeconds != 1_704_155_645 {
		t.Fatalf("compact offset not parsed: %+v", document.Core.Modified)
	}
	if document.Core.LastPrinted.Nanos != 100_000_000 {
		t.Fatalf("fraction nanos = %d", document.Core.LastPrinted.Nanos)
	}
}

func TestPackageNamedOnlyByContentTypesIsStillIdentified(t *testing.T) {
	types := `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml"/></Types>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("[Content_Types].xml", types),
		text("visio/document.xml", "<VisioDocument/>"),
	}), Limits{})
	if document.Kind != KindOther {
		t.Fatalf("kind = %v, want Other", document.Kind)
	}
	if document.MainPart != "visio/document.xml" {
		t.Fatalf("main part = %q", document.MainPart)
	}
	requireString(t, document.MainContentType, "application/vnd.ms-visio.drawing.main+xml")
}

func TestContentTypesClassifyKnownMainParts(t *testing.T) {
	types := `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/xl/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("[Content_Types].xml", types),
		text("xl/custom.xml", "<workbook/>"),
	}), Limits{})
	if document.Kind != KindExcel {
		t.Fatalf("kind = %v, want Excel", document.Kind)
	}
	if document.MainPart != "xl/custom.xml" {
		t.Fatalf("main part = %q", document.MainPart)
	}
}

func TestContentTypeMatchIsCaseInsensitive(t *testing.T) {
	types := `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/WORD/Document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("[Content_Types].xml", types),
		text("WORD/Document.xml", documentXML),
	}), Limits{})
	if document.Kind != KindWord {
		t.Fatalf("kind = %v, want Word (the conventional name matches case-insensitively)", document.Kind)
	}
	requireString(t, document.MainContentType, "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
}

func TestSignaturePartIsReportedWithoutVerification(t *testing.T) {
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("_xmlsignatures/sig1.xml", "<Signature/>"),
	}), Limits{})
	if len(document.Signatures) != 1 || document.Signatures[0] != "_xmlsignatures/sig1.xml" {
		t.Fatalf("signatures = %v", document.Signatures)
	}
}

func TestSignaturePartsAreCapped(t *testing.T) {
	items := []zipItem{text("word/document.xml", documentXML)}
	for index := 0; index < 260; index++ {
		items = append(items, text(fmt.Sprintf("_xmlsignatures/sig%03d.xml", index), "<Signature/>"))
	}
	document := openPackage(t, zipPackage(t, items), Limits{})
	if len(document.Signatures) != MaxSignatures {
		t.Fatalf("signatures = %d, want %d", len(document.Signatures), MaxSignatures)
	}
}

func TestCustomPropertiesAreCapped(t *testing.T) {
	var body strings.Builder
	body.WriteString(`<Properties>`)
	for index := 0; index < MaxCustomProperties+1; index++ {
		fmt.Fprintf(&body, `<property name="p%d"><vt:lpwstr>v</vt:lpwstr></property>`, index)
	}
	body.WriteString(`</Properties>`)
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/custom.xml", body.String()),
	}), Limits{})
	if len(document.Custom) != MaxCustomProperties {
		t.Fatalf("custom = %d", len(document.Custom))
	}
	if !hasWarning(document, "more than 1024 custom properties") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestExternalRelationshipsAreCapped(t *testing.T) {
	var body strings.Builder
	body.WriteString(`<Relationships>`)
	for index := 0; index < MaxRelationships+1; index++ {
		fmt.Fprintf(&body, `<Relationship Id="r%d" Type="t" Target="http://x/%d" TargetMode="External"/>`, index, index)
	}
	body.WriteString(`</Relationships>`)
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("word/_rels/document.xml.rels", body.String()),
	}), Limits{})
	if len(document.ExternalRelationships) != MaxRelationships {
		t.Fatalf("relationships = %d", len(document.ExternalRelationships))
	}
	if !hasWarning(document, "more than 4096 external relationships") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestRelationshipPartsAreCapped(t *testing.T) {
	items := []zipItem{text("word/document.xml", documentXML)}
	for index := 0; index < MaxRelationshipParts+1; index++ {
		items = append(items, text(fmt.Sprintf("word/_rels/p%03d.xml.rels", index), `<Relationships/>`))
	}
	document := openPackage(t, zipPackage(t, items), Limits{})
	if !hasWarning(document, "more than 256 relationship parts") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestTextPropertiesAreCappedByCharacters(t *testing.T) {
	name := strings.Repeat("ü", MaxTextChars+10)
	body := `<Properties><property name="` + name + `"><vt:lpwstr>x</vt:lpwstr></property></Properties>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/custom.xml", body),
	}), Limits{})
	if len(document.Custom) != 1 {
		t.Fatalf("custom = %d", len(document.Custom))
	}
	if got := len([]rune(document.Custom[0].Name)); got != MaxTextChars {
		t.Fatalf("name length = %d runes, want %d", got, MaxTextChars)
	}
	if !hasWarning(document, "custom property name is longer than 4096 characters") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestEmbeddedObjectsAreCappedAndStopTheScan(t *testing.T) {
	items := []zipItem{text("word/document.xml", documentXML)}
	for index := 0; index < MaxEmbedded+1; index++ {
		items = append(items, zipItem{
			name: fmt.Sprintf("word/embeddings/o%04d.bin", index),
			data: []byte("x"),
		})
	}
	items = append(items, zipItem{name: "word/vbaProject.bin", data: []byte("vba")})
	document := openPackage(t, zipPackage(t, items), Limits{})
	if len(document.Embedded) != MaxEmbedded {
		t.Fatalf("embedded = %d", len(document.Embedded))
	}
	if !hasWarning(document, "more than 4096 objects") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
	if len(document.MacroParts) != 0 {
		t.Fatalf("the reference walk stops at the embedded cap; macros = %v", document.MacroParts)
	}
}

func TestEncryptedPartWarnsAndIsSkipped(t *testing.T) {
	data := rawZIP(t, []rawZIPEntry{
		{name: "word/document.xml", data: []byte(documentXML)},
		{name: "docProps/core.xml", data: []byte(coreXML), flags: 0x0001},
	})
	document := openPackage(t, data, Limits{})
	if document.Core.Title != nil {
		t.Fatal("encrypted part was read")
	}
	if !hasWarning(document, "docProps/core.xml is encrypted") {
		t.Fatalf("warnings = %v", document.Warnings)
	}
}

func TestUnsafeEntryNameIsRefused(t *testing.T) {
	data := rawZIP(t, []rawZIPEntry{
		{name: "../evil.xml", data: []byte("<x/>")},
		{name: "word/document.xml", data: []byte(documentXML)},
	})
	_, err := Open(source.NewMemorySource(1, data), Limits{})
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestTruncatedZIPIsRefused(t *testing.T) {
	data := zipPackage(t, []zipItem{text("word/document.xml", documentXML)})
	_, err := Open(source.NewMemorySource(1, data[:len(data)-10]), Limits{})
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestNilSourceIsInvalid(t *testing.T) {
	_, err := Open(nil, Limits{})
	if !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("error = %v, want ErrInvalidArgument", err)
	}
}

func TestRelationshipTargetsAreVerbatimAndNotResolved(t *testing.T) {
	rels := `<Relationships>` +
		`<Relationship Id="rId9" Type="t" Target="\\server\share\file.doc" TargetMode="External"/>` +
		`</Relationships>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("_rels/.rels", rels),
	}), Limits{})
	if len(document.ExternalRelationships) != 1 {
		t.Fatalf("relationships = %+v", document.ExternalRelationships)
	}
	if document.ExternalRelationships[0].Target != `\\server\share\file.doc` {
		t.Fatalf("target = %q", document.ExternalRelationships[0].Target)
	}
	if document.ExternalRelationships[0].Part != "_rels/.rels" {
		t.Fatalf("part = %q", document.ExternalRelationships[0].Part)
	}
}

func TestXMLLimitsAreEnforced(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		limits Limits
		warn   string
	}{
		{
			name:   "depth",
			body:   `<a><b><c/></b></a>`,
			limits: Limits{MaxXMLDepth: 2},
			warn:   "nesting is deeper than 2 elements",
		},
		{
			name:   "elements",
			body:   `<a><b/></a>`,
			limits: Limits{MaxXMLElements: 1},
			warn:   "more than 1 elements",
		},
		{
			name:   "text",
			body:   `<cp:coreProperties><dc:title>` + strings.Repeat("a", 100) + `</dc:title></cp:coreProperties>`,
			limits: Limits{MaxXMLTextBytes: 10},
			warn:   "more than 10 bytes of text",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			document := openPackage(t, zipPackage(t, []zipItem{
				text("word/document.xml", documentXML),
				text("docProps/core.xml", testCase.body),
			}), testCase.limits)
			if !hasWarning(document, testCase.warn) {
				t.Fatalf("warnings = %v", document.Warnings)
			}
		})
	}
}

func TestContentTypesWithoutAMainSuffixIsRefused(t *testing.T) {
	types := `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing"/></Types>`
	_, err := Open(source.NewMemorySource(1, zipPackage(t, []zipItem{
		text("[Content_Types].xml", types),
		text("visio/document.xml", "<VisioDocument/>"),
	})), Limits{})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v", err)
	}
}

func TestInvalidTimesKeepTheirTextAndAreNotParsed(t *testing.T) {
	cases := []string{
		"2024-01-02",
		"2024-02-30T00:00:00Z",
		"2024-01-02T03:04:05.Z",
		"2024-01-02T03:04:05.1234567890Z",
		"2024-01-02T03:04:05+24:00",
		"2024-01-02T25:04:05Z",
		"2024-01-02 03:04:05Z",
	}
	for _, value := range cases {
		body := `<cp:coreProperties><dcterms:created>` + value + `</dcterms:created></cp:coreProperties>`
		document := openPackage(t, zipPackage(t, []zipItem{
			text("word/document.xml", documentXML),
			text("docProps/core.xml", body),
		}), Limits{})
		if document.Core.Created == nil || document.Core.Created.Text != value {
			t.Fatalf("%q text = %+v", value, document.Core.Created)
		}
		if document.Core.Created.UnixSeconds != nil {
			t.Fatalf("%q wrongly parsed", value)
		}
	}
}

func TestCustomPropertyWithoutNameOrValue(t *testing.T) {
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/custom.xml", `<Properties><property/></Properties>`),
	}), Limits{})
	if len(document.Custom) != 1 {
		t.Fatalf("custom = %+v", document.Custom)
	}
	if document.Custom[0].Name != "unnamed" || document.Custom[0].FmtID != nil ||
		document.Custom[0].PID != nil || document.Custom[0].ValueType != nil || document.Custom[0].Value != "" {
		t.Fatalf("custom = %+v", document.Custom[0])
	}
}

func TestConventionalPartWithoutAManifestHasNoContentType(t *testing.T) {
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
	}), Limits{})
	if document.Kind != KindWord || document.MainContentType != nil {
		t.Fatalf("kind/content type = %v/%v", document.Kind, document.MainContentType)
	}
}

func TestZeroDocumentKindIsOther(t *testing.T) {
	var document Document
	if document.Kind != KindOther {
		t.Fatalf("zero kind = %v, want other", document.Kind)
	}
}

func TestKindLabels(t *testing.T) {
	cases := map[Kind]string{
		KindWord:         "word processing",
		KindExcel:        "spreadsheet",
		KindPresentation: "presentation",
		KindOther:        "other",
	}
	for kind, want := range cases {
		if got := kind.Label(); got != want {
			t.Fatalf("%d label = %q, want %q", kind, got, want)
		}
		if got := kind.String(); got != want {
			t.Fatalf("%d String = %q, want %q", kind, got, want)
		}
	}
}

func TestTimeUnixNanoOverflowIsReported(t *testing.T) {
	// 9999-12-31T23:59:59Z parses but its nanosecond value exceeds int64.
	body := `<cp:coreProperties><dcterms:created>9999-12-31T23:59:59Z</dcterms:created></cp:coreProperties>`
	document := openPackage(t, zipPackage(t, []zipItem{
		text("word/document.xml", documentXML),
		text("docProps/core.xml", body),
	}), Limits{})
	created := document.Core.Created
	if created == nil || created.UnixSeconds == nil {
		t.Fatal("time did not parse")
	}
	if _, ok := created.UnixNano(); ok {
		t.Fatal("UnixNano claimed a representable int64")
	}
}

func hasWarning(document *Document, needle string) bool {
	for _, warning := range document.Warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}

// rawZIPEntry is one stored member of a hand-built ZIP, with control over the
// general-purpose flags that archive/zip does not expose.
type rawZIPEntry struct {
	name  string
	data  []byte
	flags uint16
}

// rawZIP builds a stored-only ZIP with the given flags.  It is used for the
// encrypted-entry and unsafe-name tests.
func rawZIP(t *testing.T, entries []rawZIPEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	var central bytes.Buffer
	for _, entry := range entries {
		offset := uint32(out.Len())
		crc := crc32.ChecksumIEEE(entry.data)
		var local [30]byte
		copy(local[0:4], "PK\x03\x04")
		binary.LittleEndian.PutUint16(local[4:6], 20)
		binary.LittleEndian.PutUint16(local[6:8], entry.flags)
		binary.LittleEndian.PutUint16(local[10:12], 0)
		binary.LittleEndian.PutUint32(local[14:18], crc)
		binary.LittleEndian.PutUint32(local[18:22], uint32(len(entry.data)))
		binary.LittleEndian.PutUint32(local[22:26], uint32(len(entry.data)))
		binary.LittleEndian.PutUint16(local[26:28], uint16(len(entry.name)))
		out.Write(local[:])
		out.WriteString(entry.name)
		out.Write(entry.data)

		var header [46]byte
		copy(header[0:4], "PK\x01\x02")
		binary.LittleEndian.PutUint16(header[4:6], 20)
		binary.LittleEndian.PutUint16(header[6:8], 20)
		binary.LittleEndian.PutUint16(header[8:10], entry.flags)
		binary.LittleEndian.PutUint16(header[12:14], 0)
		binary.LittleEndian.PutUint32(header[16:20], crc)
		binary.LittleEndian.PutUint32(header[20:24], uint32(len(entry.data)))
		binary.LittleEndian.PutUint32(header[24:28], uint32(len(entry.data)))
		binary.LittleEndian.PutUint16(header[28:30], uint16(len(entry.name)))
		binary.LittleEndian.PutUint32(header[42:46], offset)
		central.Write(header[:])
		central.WriteString(entry.name)
	}
	directoryOffset := uint32(out.Len())
	out.Write(central.Bytes())
	var tail [22]byte
	copy(tail[0:4], "PK\x05\x06")
	binary.LittleEndian.PutUint16(tail[8:10], uint16(len(entries)))
	binary.LittleEndian.PutUint16(tail[10:12], uint16(len(entries)))
	binary.LittleEndian.PutUint32(tail[12:16], uint32(central.Len()))
	binary.LittleEndian.PutUint32(tail[16:20], directoryOffset)
	out.Write(tail[:])
	return out.Bytes()
}
