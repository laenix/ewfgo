// Command pdf prints a PDF document's structure and metadata, and can write
// one embedded attachment to a file.
//
//	go run ./examples/pdf -image report.pdf
//	go run ./examples/pdf -image report.pdf -attachment payload.bin -out payload.raw
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	image := flag.String("image", "", "PDF file")
	password := flag.String("password", "", "document password, when encrypted")
	attachment := flag.String("attachment", "", "embedded file name to export")
	out := flag.String("out", "", "output path for -attachment")
	flag.Parse()
	if *image == "" {
		fmt.Fprintln(os.Stderr, "usage: pdf -image <document.pdf> [-password pw] [-attachment name -out path]")
		os.Exit(2)
	}
	if err := run(context.Background(), *image, *password, *attachment, *out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, image, password, attachment, out string) error {
	var (
		doc *forensic.PDFDocument
		err error
	)
	if password != "" {
		doc, err = forensic.OpenPDFWithPassword(ctx, image, password, forensic.Options{})
	} else {
		doc, err = forensic.OpenPDF(ctx, image, forensic.Options{})
	}
	if err != nil {
		return err
	}
	defer doc.Close()

	info := doc.Info()
	fmt.Printf("version      %s (header %s)\n", info.Version, info.HeaderVersion)
	if info.Encrypted {
		fmt.Printf("encryption   %s\n", info.Encryption)
	}
	fmt.Printf("pages        %d", info.PagesCounted)
	if info.PagesDeclared != nil {
		fmt.Printf(" (declared %d)", *info.PagesDeclared)
	}
	fmt.Println()
	for _, field := range []struct {
		label string
		value string
	}{
		{"title", info.Title}, {"author", info.Author}, {"subject", info.Subject},
		{"keywords", info.Keywords}, {"creator", info.Creator}, {"producer", info.Producer},
	} {
		if field.value != "" {
			fmt.Printf("%-12s %s\n", field.label, field.value)
		}
	}
	if info.HasCreated {
		fmt.Printf("created      %s\n", info.Created.Format("2006-01-02 15:04:05Z"))
	}
	if info.HasModified {
		fmt.Printf("modified     %s\n", info.Modified.Format("2006-01-02 15:04:05Z"))
	}
	if info.FormFields != 0 || info.Signatures != 0 {
		fmt.Printf("form         %d field(s), %d signature field(s)\n", info.FormFields, info.Signatures)
	}
	if info.JavaScript {
		fmt.Println("javascript   present")
	}
	if info.Repaired {
		fmt.Println("xref         repaired by scanning")
	}
	for _, note := range info.Notes {
		fmt.Println("note:", note)
	}

	attachments, err := doc.Attachments(ctx)
	if err != nil {
		return err
	}
	for _, file := range attachments {
		fmt.Printf("attachment   %-30s %d bytes", file.Name, file.Size)
		if file.SHA256 != "" {
			fmt.Printf(" sha256=%s", file.SHA256)
		}
		if file.Note != "" {
			fmt.Printf(" (%s)", file.Note)
		}
		fmt.Println()
	}

	if attachment == "" {
		return nil
	}
	if out == "" {
		return fmt.Errorf("-out is required with -attachment")
	}
	src, err := doc.OpenAttachment(ctx, attachment)
	if err != nil {
		return err
	}
	data := make([]byte, src.Len())
	if _, err := io.ReadFull(sourceReader{src: src}, data); err != nil {
		return err
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote        %s (%d bytes)\n", out, len(data))
	return nil
}

// sourceReader adapts a ByteSource to io.Reader at increasing offsets.
type sourceReader struct {
	src    forensic.ByteSource
	offset uint64
}

func (r sourceReader) Read(p []byte) (int, error) {
	if r.offset >= r.src.Len() {
		return 0, io.EOF
	}
	want := uint64(len(p))
	if remaining := r.src.Len() - r.offset; want > remaining {
		want = remaining
	}
	n, err := r.src.ReadAt(r.offset, p[:want])
	r.offset += uint64(n)
	if err != nil && n == 0 {
		return 0, err
	}
	return n, nil
}
