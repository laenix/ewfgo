package forensic_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

const docxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

const docxCore = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>Quarterly numbers</dc:title><dc:creator>Alice</dc:creator>
<cp:lastModifiedBy>Bob</cp:lastModifiedBy><cp:revision>7</cp:revision>
<dcterms:created xsi:type="dcterms:W3CDTF">2024-01-02T03:04:05Z</dcterms:created>
</cp:coreProperties>`

const docxRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://198.51.100.9/template.dotm" TargetMode="External"/>
</Relationships>`

func docxFixture(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	parts := []struct{ name, data string }{
		{"[Content_Types].xml", docxContentTypes},
		{"docProps/core.xml", docxCore},
		{"word/document.xml", `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`},
		{"word/_rels/document.xml.rels", docxRels},
	}
	for _, part := range parts {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: part.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(part.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOpenDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.docx")
	if err := os.WriteFile(path, docxFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := forensic.OpenDocument(context.Background(), path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}
	defer doc.Close()

	info := doc.Info()
	if info.Kind != "word processing" || info.MainPart != "word/document.xml" {
		t.Fatalf("info = %+v", info)
	}
	if info.Title != "Quarterly numbers" || info.Creator != "Alice" || info.LastModifiedBy != "Bob" || info.Revision != "7" {
		t.Fatalf("core = %+v", info)
	}
	if !info.HasCreated || !info.Created.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("created = %v (%v)", info.Created, info.HasCreated)
	}
	if info.MacroEnabled {
		t.Fatal("a package without a VBA part is marked macro-enabled")
	}

	rels, err := doc.ExternalRelationships(context.Background())
	if err != nil || len(rels) != 1 {
		t.Fatalf("relationships = %+v, %v", rels, err)
	}
	if rels[0].Target != "http://198.51.100.9/template.dotm" {
		t.Fatalf("target = %q", rels[0].Target)
	}
}

func TestOpenDocumentSource(t *testing.T) {
	doc, err := forensic.OpenDocumentSource(context.Background(), source.NewMemorySource(1, docxFixture(t)), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenDocumentSource: %v", err)
	}
	if doc.Info().Title != "Quarterly numbers" {
		t.Fatalf("title = %q", doc.Info().Title)
	}
}

func TestOpenRejectsDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.docx")
	if err := os.WriteFile(path, docxFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := forensic.Open(context.Background(), path, forensic.Options{})
	if !errors.Is(err, forensic.ErrInvalidArgument) || !strings.Contains(err.Error(), "OpenDocument") {
		t.Fatalf("Open(docx) = %v, want ErrInvalidArgument naming OpenDocument", err)
	}
}
