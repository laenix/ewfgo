package forensic

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/ooxml"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Document is an opened Office Open XML package (docx/xlsx/pptx and their
// macro-enabled/template forms). The body is not rendered; this reader reports
// the package facts used for attribution.
type Document struct {
	path  string
	doc   *ooxml.Document
	close io.Closer
}

// DocumentInfo is the attribution metadata of one OOXML package.
type DocumentInfo struct {
	Kind        string
	MainPart    string
	ContentType string

	Title          string
	Subject        string
	Creator        string
	LastModifiedBy string
	Revision       string
	Keywords       string
	Description    string
	Category       string
	ContentStatus  string
	Language       string
	Version        string

	Created     time.Time
	HasCreated  bool
	Modified    time.Time
	HasModified bool
	LastPrinted time.Time
	HasPrinted  bool

	Application        string
	AppVersion         string
	Company            string
	Manager            string
	Template           string
	PresentationFormat string
	Pages              uint32
	Words              uint32
	Slides             uint32
	SlideCount         int
	Sheets             int

	MacroEnabled bool
	MacroParts   []string
	Signatures   []string
	Warnings     []string
}

// DocumentRelationship is one external relationship target, reported verbatim.
type DocumentRelationship struct {
	Part   string
	Kind   string
	Target string
}

// DocumentObject is one embedded object member.
type DocumentObject struct {
	Path string
	Size uint64
}

// OpenDocument opens an OOXML package from a path.
func OpenDocument(ctx context.Context, imagePath string, opts Options) (*Document, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open OOXML package %s: %w", imagePath, err)
	}
	document, err := OpenDocumentSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse OOXML %s: %w", imagePath, err)
	}
	document.path = imagePath
	document.close = raw
	return document, nil
}

// OpenDocumentSource opens an OOXML package over an existing byte source (for
// example an archive entry or a nested node). The source is not closed by
// Document.Close.
func OpenDocumentSource(ctx context.Context, src ByteSource, opts Options) (*Document, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil OOXML source", ErrInvalidArgument)
	}
	limits := ooxml.DefaultLimits()
	if opts.Limits.MaxFileBytes != 0 && opts.Limits.MaxFileBytes < limits.MaxPartBytes {
		limits.MaxPartBytes = opts.Limits.MaxFileBytes
	}
	doc, err := ooxml.Open(src, limits)
	if err != nil {
		return nil, err
	}
	return &Document{doc: doc}, nil
}

// Path returns the package path.
func (d *Document) Path() string { return d.path }

// Info returns the package's attribution metadata.
func (d *Document) Info() DocumentInfo {
	doc := d.doc
	info := DocumentInfo{
		Kind:         doc.Kind.Label(),
		MainPart:     doc.MainPart,
		MacroEnabled: doc.IsMacroEnabled(),
		MacroParts:   append([]string(nil), doc.MacroParts...),
		Signatures:   append([]string(nil), doc.Signatures...),
		Warnings:     append([]string(nil), doc.Warnings...),
		Sheets:       len(doc.Sheets),
	}
	if doc.MainContentType != nil {
		info.ContentType = *doc.MainContentType
	}
	core := doc.Core
	info.Title = stringValue(core.Title)
	info.Subject = stringValue(core.Subject)
	info.Creator = stringValue(core.Creator)
	info.LastModifiedBy = stringValue(core.LastModifiedBy)
	info.Revision = stringValue(core.Revision)
	info.Keywords = stringValue(core.Keywords)
	info.Description = stringValue(core.Description)
	info.Category = stringValue(core.Category)
	info.ContentStatus = stringValue(core.ContentStatus)
	info.Language = stringValue(core.Language)
	info.Version = stringValue(core.Version)
	info.Created, info.HasCreated = documentTime(core.Created)
	info.Modified, info.HasModified = documentTime(core.Modified)
	info.LastPrinted, info.HasPrinted = documentTime(core.LastPrinted)

	app := doc.App
	info.Application = stringValue(app.Application)
	info.AppVersion = stringValue(app.AppVersion)
	info.Company = stringValue(app.Company)
	info.Manager = stringValue(app.Manager)
	info.Template = stringValue(app.Template)
	info.PresentationFormat = stringValue(app.PresentationFormat)
	if app.Pages != nil {
		info.Pages = *app.Pages
	}
	if app.Words != nil {
		info.Words = *app.Words
	}
	if app.Slides != nil {
		info.Slides = *app.Slides
	}
	if doc.SlideCount != nil {
		info.SlideCount = *doc.SlideCount
	}
	return info
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func documentTime(value *ooxml.Time) (time.Time, bool) {
	if value == nil || !value.Parsed() {
		return time.Time{}, false
	}
	return time.Unix(*value.UnixSeconds, int64(value.Nanos)).UTC(), true
}

// ExternalRelationships returns every relationship whose target is outside the
// package, verbatim and unresolved.
func (d *Document) ExternalRelationships(ctx context.Context) ([]DocumentRelationship, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw := d.doc.ExternalRelationships
	out := make([]DocumentRelationship, 0, len(raw))
	for _, rel := range raw {
		out = append(out, DocumentRelationship{Part: rel.Part, Kind: rel.Kind, Target: rel.Target})
	}
	return out, nil
}

// Embedded returns every embedded object member.
func (d *Document) Embedded(ctx context.Context) ([]DocumentObject, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw := d.doc.Embedded
	out := make([]DocumentObject, 0, len(raw))
	for _, object := range raw {
		out = append(out, DocumentObject{Path: object.Path, Size: object.Size})
	}
	return out, nil
}

// Close releases the package file.
func (d *Document) Close() error {
	if d.close == nil {
		return nil
	}
	err := d.close.Close()
	d.close = nil
	return err
}
