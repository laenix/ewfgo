package pdf

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func classicPDF(objects []string, trailer string) []byte {
	var builder strings.Builder
	builder.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for i, body := range objects {
		offsets[i] = builder.Len()
		builder.WriteString(itoa(int64(i + 1)))
		builder.WriteString(" 0 obj\n")
		builder.WriteString(body)
		builder.WriteString("\nendobj\n")
	}
	xrefAt := builder.Len()
	builder.WriteString("xref\n0 ")
	builder.WriteString(itoa(int64(len(objects) + 1)))
	builder.WriteString("\n0000000000 65535 f \n")
	for _, offset := range offsets {
		builder.WriteString(pad10(offset))
		builder.WriteString(" 00000 n \n")
	}
	builder.WriteString("trailer\n<< /Size ")
	builder.WriteString(itoa(int64(len(objects) + 1)))
	builder.WriteString(" ")
	builder.WriteString(trailer)
	builder.WriteString(" >>\nstartxref\n")
	builder.WriteString(itoa(int64(xrefAt)))
	builder.WriteString("\n%%EOF\n")
	return []byte(builder.String())
}

func pad10(value int) string {
	text := itoa(int64(value))
	for len(text) < 10 {
		text = "0" + text
	}
	return text
}

func testSource(bytesValue []byte) source.ByteSource {
	return source.NewMemorySource(1, bytesValue)
}

func startxrefOffset(t *testing.T, bytesValue []byte) int {
	t.Helper()
	position := bytes.LastIndex(bytesValue, []byte("startxref"))
	if position < 0 {
		t.Fatal("no startxref")
	}
	parser := NewParser(bytesValue[position+len("startxref"):])
	offset, err := parser.ReadUnsigned("startxref offset")
	if err != nil {
		t.Fatalf("startxref offset error = %v", err)
	}
	return int(offset)
}

func TestClassicTableNamesEachObject(t *testing.T) {
	pdf := classicPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
	}, "/Root 1 0 R")
	xref, err := ReadXref(testSource(pdf), DefaultXrefLimits())
	if err != nil {
		t.Fatalf("ReadXref error = %v", err)
	}
	if xref.Repaired || xref.Updates != 1 || len(xref.Sections) != 1 || xref.Sections[0].Kind != XrefKindTable {
		t.Fatalf("xref = %+v", xref)
	}
	root, ok := xref.Root()
	if !ok || root.Number != 1 {
		t.Fatalf("root = %+v/%v", root, ok)
	}
	if entry, ok := xref.Entry(0); !ok || !entry.IsFree() {
		t.Fatalf("object 0 = %+v/%v", entry, ok)
	}
	if entry, ok := xref.Entry(1); !ok || entry.Kind != EntryInFile || entry.Generation != 0 {
		t.Fatalf("object 1 = %+v/%v", entry, ok)
	}
	if _, ok := xref.Entry(3); ok {
		t.Fatal("object 3 should be absent")
	}
}

func TestIncrementalUpdateOverridesTheOlderEntry(t *testing.T) {
	base := classicPDF([]string{"<< /Type /Catalog >>"}, "/Root 1 0 R")
	baseXref := startxrefOffset(t, base)
	newObject := len(base)
	updated := append([]byte(nil), base...)
	updated = append(updated, []byte("1 0 obj\n<< /Type /Catalog /Lang (en) >>\nendobj\n")...)
	xrefAt := len(updated)
	text := "xref\n0 1\n0000000000 65535 f \n1 1\n" + pad10(newObject) +
		" 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R /Prev " + itoa(int64(baseXref)) +
		" >>\nstartxref\n" + itoa(int64(xrefAt)) + "\n%%EOF\n"
	updated = append(updated, []byte(text)...)

	xref, err := ReadXref(testSource(updated), DefaultXrefLimits())
	if err != nil {
		t.Fatalf("ReadXref error = %v", err)
	}
	if xref.Updates != 2 || len(xref.Sections) != 2 {
		t.Fatalf("updates = %d, sections = %d", xref.Updates, len(xref.Sections))
	}
	entry, ok := xref.Entry(1)
	if !ok || entry.Offset != uint64(newObject) {
		t.Fatalf("object 1 = %+v/%v, want offset %d", entry, ok, newObject)
	}
	if xref.Trailer.Contains([]byte("Prev")) {
		t.Fatal("merged trailer kept /Prev")
	}
}

func pngRows(rows [][]byte, columns int) []byte {
	var out []byte
	for _, row := range rows {
		if len(row) != columns {
			panic("row width")
		}
		out = append(out, 0)
		out = append(out, row...)
	}
	return out
}

func TestPrevLoopIsRefused(t *testing.T) {
	first := len("%PDF-1.7\n")
	text := "%PDF-1.7\n" +
		"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Prev " +
		itoa(int64(first)) + " >>\nstartxref\n" + itoa(int64(first)) + "\n%%EOF\n"
	_, err := ReadXref(testSource([]byte(text)), DefaultXrefLimits())
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "revisits") {
		t.Fatalf("error = %v, want a /Prev loop refusal", err)
	}
}

func TestDamagedChainIsRebuiltByScanning(t *testing.T) {
	bytesValue := classicPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
	}, "/Root 1 0 R")
	bytesValue = append(bytesValue, []byte("\nstartxref\n999999\n%%EOF\n")...)
	xref, err := ReadXrefWithRepair(testSource(bytesValue), DefaultXrefLimits())
	if err != nil {
		t.Fatalf("ReadXrefWithRepair error = %v", err)
	}
	if !xref.Repaired {
		t.Fatal("xref was not marked repaired")
	}
	if root, ok := xref.Root(); !ok || root.Number != 1 {
		t.Fatalf("root = %+v/%v", root, ok)
	}
	if !strings.Contains(strings.Join(xref.Notes, "\n"), "rebuilt by scanning") {
		t.Fatalf("notes = %v", xref.Notes)
	}
}

func TestRepairScanSkipsCommentBytes(t *testing.T) {
	text := "%PDF-1.4\n% 9 0 obj is a comment\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
	xref, err := RepairXref(testSource([]byte(text)), DefaultXrefLimits())
	if err != nil {
		t.Fatalf("RepairXref error = %v", err)
	}
	if _, ok := xref.Entry(9); ok {
		t.Fatal("comment bytes produced object 9")
	}
	if _, ok := xref.Entry(1); !ok {
		t.Fatal("object 1 was not found")
	}
	if root, ok := xref.Root(); !ok || root.Number != 1 {
		t.Fatalf("root = %+v/%v", root, ok)
	}
}

func TestXrefStreamWidthsAreValidated(t *testing.T) {
	for _, widths := range []string{"[1 4]", "[1 9 2]", "[0 0 0]", "[1 -1 2]"} {
		dict := testDict([][2]any{{"W", mustParseArray(t, widths)}})
		if _, err := parseStreamEntries(make([]byte, 16), dict, 1024, DefaultXrefLimits()); err == nil {
			t.Fatalf("/W %s was accepted", widths)
		}
	}
}

func mustParseArray(t *testing.T, text string) Value {
	t.Helper()
	value, err := ParseFirstValue([]byte(text))
	if err != nil {
		t.Fatalf("ParseFirstValue(%q) error = %v", text, err)
	}
	return value
}
