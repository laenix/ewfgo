// Command document prints the attribution metadata of an Office Open XML
// package (docx/xlsx/pptx and macro/template variants), plus external
// relationships and embedded objects.
//
// Usage:
//
//	go run ./examples/document -image report.docx
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	imagePath := flag.String("image", "", "OOXML package path")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: document -image <report.docx>")
		os.Exit(2)
	}
	if err := run(*imagePath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string) error {
	ctx := context.Background()
	doc, err := forensic.OpenDocument(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open document: %w", err)
	}
	defer doc.Close()

	info := doc.Info()
	fmt.Printf("package      : %s\n", imagePath)
	fmt.Printf("kind         : %s\n", info.Kind)
	fmt.Printf("main part    : %s\n", info.MainPart)
	if info.ContentType != "" {
		fmt.Printf("content type : %s\n", info.ContentType)
	}
	fmt.Printf("title        : %s\n", info.Title)
	fmt.Printf("creator      : %s\n", info.Creator)
	fmt.Printf("last modified: %s\n", info.LastModifiedBy)
	fmt.Printf("revision     : %s\n", info.Revision)
	fmt.Printf("application  : %s\n", info.Application)
	fmt.Printf("company      : %s\n", info.Company)
	fmt.Printf("template     : %s\n", info.Template)
	fmt.Printf("macro enabled: %v\n", info.MacroEnabled)
	if info.HasCreated {
		fmt.Printf("created      : %s\n", info.Created.Format("2006-01-02T15:04:05Z07:00"))
	}
	if info.HasModified {
		fmt.Printf("modified     : %s\n", info.Modified.Format("2006-01-02T15:04:05Z07:00"))
	}
	if info.SlideCount > 0 {
		fmt.Printf("slides       : %d\n", info.SlideCount)
	}
	if info.Sheets > 0 {
		fmt.Printf("sheets       : %d\n", info.Sheets)
	}

	relationships, err := doc.ExternalRelationships(ctx)
	if err != nil {
		return fmt.Errorf("list external relationships: %w", err)
	}
	fmt.Printf("\nexternal relationships: %d\n", len(relationships))
	for _, relationship := range relationships {
		fmt.Printf("  %s -> %s (%s)\n", relationship.Part, relationship.Target, relationship.Kind)
	}

	embedded, err := doc.Embedded(ctx)
	if err != nil {
		return fmt.Errorf("list embedded objects: %w", err)
	}
	fmt.Printf("\nembedded objects: %d\n", len(embedded))
	for _, object := range embedded {
		fmt.Printf("  %s (%d bytes)\n", object.Path, object.Size)
	}

	for _, warning := range info.Warnings {
		fmt.Println("warning:", warning)
	}
	return nil
}
