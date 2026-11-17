package forensic

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/pdf"
	"github.com/laenix/ewfgo/internal/data/source"
)

// PDFDocument is an opened PDF document. The page content is not rendered;
// this reader reports structure, metadata, encryption facts, actions and
// embedded files, and exposes attachment bytes as sources.
type PDFDocument struct {
	path   string
	doc    *pdf.Document
	closer io.Closer

	nextID atomic.Uint64
}

// PDFInfo summarizes a PDF document.
type PDFInfo struct {
	Path          string
	Version       string
	HeaderVersion string
	Linearized    bool
	Encrypted     bool
	Encryption    string

	Title       string
	Author      string
	Subject     string
	Keywords    string
	Creator     string
	Producer    string
	Created     time.Time
	HasCreated  bool
	Modified    time.Time
	HasModified bool

	PagesDeclared *uint32
	PagesCounted  uint32
	Outlines      *int64
	Attachments   int
	JavaScript    bool
	FormFields    int
	Signatures    int

	XrefSections   int
	XrefEntries    int
	Repaired       bool
	ObjectsLoaded  int
	ObjectStreams  int
	StreamsDecoded int
	DecodedBytes   uint64
	Notes          []string
	StringsOpaque  bool
	StreamsOpaque  bool
}

// PDFAttachment is one embedded file.
type PDFAttachment struct {
	Name        string
	Filename    string
	Description string
	Size        uint64
	HasSize     bool
	SHA256      string
	Filters     []string
	Note        string
}

// OpenPDF opens a PDF document from a path.
func OpenPDF(ctx context.Context, imagePath string, opts Options) (*PDFDocument, error) {
	return openPDF(ctx, imagePath, "", opts)
}

// OpenPDFWithPassword opens a PDF document with a password.
func OpenPDFWithPassword(ctx context.Context, imagePath, password string, opts Options) (*PDFDocument, error) {
	return openPDF(ctx, imagePath, password, opts)
}

func openPDF(ctx context.Context, imagePath, password string, opts Options) (*PDFDocument, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open PDF %s: %w", imagePath, err)
	}
	doc, err := openPDFDocument(ctx, raw, password, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse PDF %s: %w", imagePath, err)
	}
	doc.path = imagePath
	doc.closer = raw
	return doc, nil
}

// OpenPDFSource opens a PDF over an existing byte source.
func OpenPDFSource(ctx context.Context, src ByteSource, opts Options) (*PDFDocument, error) {
	return openPDFDocument(ctx, src, "", opts)
}

// OpenPDFSourceWithPassword opens a PDF over an existing byte source with a
// password.
func OpenPDFSourceWithPassword(ctx context.Context, src ByteSource, password string, opts Options) (*PDFDocument, error) {
	return openPDFDocument(ctx, src, password, opts)
}

func openPDFDocument(ctx context.Context, src ByteSource, password string, opts Options) (*PDFDocument, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil PDF source", ErrInvalidArgument)
	}
	limits := pdf.DefaultLimits()
	if max := opts.Limits.MaxFileBytes; max != 0 && max < uint64(limits.MaxDecodedBytes) {
		limits.MaxDecodedBytes = int(max)
	}
	var (
		doc *pdf.Document
		err error
	)
	if password == "" {
		doc, err = pdf.Open(src, limits)
	} else {
		doc, err = pdf.OpenWithPassword(src, limits, []byte(password))
	}
	if err != nil {
		return nil, err
	}
	return &PDFDocument{doc: doc}, nil
}

// Path returns the document path, empty for source opens.
func (d *PDFDocument) Path() string { return d.path }

// Info returns the document summary.
func (d *PDFDocument) Info() PDFInfo {
	info := d.doc.Info()
	pages := d.doc.Pages()
	stats := d.doc.Stats()
	out := PDFInfo{
		Path:           d.path,
		Version:        d.doc.Version,
		HeaderVersion:  d.doc.HeaderVersion,
		Linearized:     d.doc.Linearized,
		Encrypted:      d.doc.Encrypted != nil,
		PagesDeclared:  pages.Declared,
		PagesCounted:   pages.Counted,
		Attachments:    len(d.doc.EmbeddedFiles),
		XrefSections:   stats.XrefSections,
		XrefEntries:    stats.XrefEntries,
		Repaired:       stats.Repaired,
		ObjectsLoaded:  stats.ObjectsLoaded,
		ObjectStreams:  stats.ObjectStreams,
		StreamsDecoded: stats.StreamsDecoded,
		DecodedBytes:   stats.DecodedBytes,
		Notes:          d.doc.Notes(),
		StringsOpaque:  d.doc.StringsOpaque(),
		StreamsOpaque:  d.doc.StreamsOpaque(),
	}
	if text := info.Title; text != nil {
		out.Title = *text
	}
	if text := info.Author; text != nil {
		out.Author = *text
	}
	if text := info.Subject; text != nil {
		out.Subject = *text
	}
	if text := info.Keywords; text != nil {
		out.Keywords = *text
	}
	if text := info.Creator; text != nil {
		out.Creator = *text
	}
	if text := info.Producer; text != nil {
		out.Producer = *text
	}
	out.Created, out.HasCreated = pdfTime(info.CreationDate)
	out.Modified, out.HasModified = pdfTime(info.ModifiedDate)
	out.Outlines = d.doc.Catalog.Outlines
	out.JavaScript = d.doc.Catalog.JavaScriptTree
	if form := d.doc.Catalog.AcroForm; form != nil {
		out.FormFields = form.Fields
		out.Signatures = form.SignatureFields
	}
	if enc := d.doc.Encrypted; enc != nil {
		if filter := enc.Filter; filter != nil {
			out.Encryption = *filter
		}
		if method := enc.CryptMethod; method != nil {
			if out.Encryption != "" {
				out.Encryption += "/"
			}
			out.Encryption += *method
		}
	}
	return out
}

func pdfTime(date *pdf.Date) (time.Time, bool) {
	if date == nil || date.UnixSeconds == nil {
		return time.Time{}, false
	}
	return time.Unix(*date.UnixSeconds, 0).UTC(), true
}

// Attachments returns the embedded files.
func (d *PDFDocument) Attachments(ctx context.Context) ([]PDFAttachment, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw := d.doc.Attachments()
	out := make([]PDFAttachment, 0, len(raw))
	for _, file := range raw {
		entry := PDFAttachment{Name: file.Name, Filters: append([]string(nil), file.Filters...)}
		if file.Filename != nil {
			entry.Filename = *file.Filename
		}
		if file.Description != nil {
			entry.Description = *file.Description
		}
		if file.Size != nil && *file.Size >= 0 {
			entry.Size = uint64(*file.Size)
			entry.HasSize = true
		}
		if file.SHA256 != nil {
			entry.SHA256 = *file.SHA256
		}
		if file.Note != nil {
			entry.Note = *file.Note
		}
		out = append(out, entry)
	}
	return out, nil
}

// OpenAttachment returns one embedded file as a source. The name is the name
// the document's embedded-file tree gives it.
func (d *PDFDocument) OpenAttachment(ctx context.Context, name string) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	id := source.ID(d.nextID.Add(1) + 7_000_000)
	attachment, err := d.doc.OpenAttachment(name, id)
	if err != nil {
		return nil, err
	}
	return attachment, nil
}

// Close releases the document's file handle. It is idempotent.
func (d *PDFDocument) Close() error {
	if d.closer == nil {
		return nil
	}
	err := d.closer.Close()
	d.closer = nil
	return err
}
