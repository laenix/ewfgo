// Command archive lists the entries of a ZIP, TAR, CPIO, ar, CAB, XAR or
// Android backup container and optionally reads one entry.
//
// Usage:
//
//	go run ./examples/archive -image backup.zip
//	go run ./examples/archive -image backup.zip -read dir/report.txt
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	imagePath := flag.String("image", "", "archive path")
	readPath := flag.String("read", "", "entry path to read")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: archive -image <archive> [-read entry]")
		os.Exit(2)
	}
	if err := run(*imagePath, *readPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath, readPath string) error {
	ctx := context.Background()
	archive, err := forensic.OpenArchive(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer archive.Close()

	fmt.Printf("archive     : %s\n", imagePath)
	fmt.Printf("format      : %s\n", archive.Format())

	entries, err := archive.Entries(ctx)
	if err != nil {
		return fmt.Errorf("list entries: %w", err)
	}
	fmt.Printf("entries     : %d\n\n", len(entries))

	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "path\tkind\tsize\tencrypted")
	for _, entry := range entries {
		fmt.Fprintf(table, "%s\t%s\t%d\t%v\n",
			entry.Path, entry.Kind, entry.Size, entry.Encrypted)
	}
	table.Flush()

	if readPath == "" {
		return nil
	}
	file, err := archive.Open(ctx, readPath)
	if err != nil {
		return fmt.Errorf("open entry %q: %w", readPath, err)
	}
	defer file.Close()

	data, err := file.ReadAll()
	if err != nil {
		return fmt.Errorf("read entry %q: %w", readPath, err)
	}
	fmt.Printf("\n%s (%d bytes):\n%s\n", readPath, len(data), data)
	return nil
}
