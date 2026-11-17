// Command logical opens an EnCase L01 logical evidence image, lists its
// catalog and optionally reads one acquired file.
//
// Usage:
//
//	go run ./examples/logical -image evidence.L01
//	go run ./examples/logical -image evidence.L01 -read /CASE/big.txt
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
	imagePath := flag.String("image", "", "L01 image path (sibling L02/L03 segments are auto-discovered)")
	readPath := flag.String("read", "", "catalog path to read")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: logical -image <path.L01> [-read /CASE/file]")
		os.Exit(2)
	}
	if err := run(*imagePath, *readPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath, readPath string) error {
	ctx := context.Background()
	image, err := forensic.OpenLogical(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open L01: %w", err)
	}
	defer image.Close()

	info := image.Info()
	fmt.Printf("image       : %s\n", imagePath)
	fmt.Printf("format      : %s\n", info.Format)
	fmt.Printf("media bytes : %d\n", info.Size)
	if info.CaseNumber != "" {
		fmt.Printf("case        : %s\n", info.CaseNumber)
	}
	if info.EvidenceNumber != "" {
		fmt.Printf("evidence    : %s\n", info.EvidenceNumber)
	}

	entries, err := image.Entries(ctx)
	if err != nil {
		return fmt.Errorf("read catalog: %w", err)
	}
	fmt.Printf("\ncatalog     : %d entries\n", len(entries))

	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "path\tdir\tdeleted\tsize\tMD5")
	for _, entry := range entries {
		fmt.Fprintf(table, "%s\t%v\t%v\t%d\t%s\n",
			entry.Path, entry.IsDir, entry.Deleted, entry.Size, entry.MD5)
	}
	table.Flush()

	if readPath == "" {
		return nil
	}
	file, err := image.Open(ctx, readPath)
	if err != nil {
		return fmt.Errorf("open %q: %w", readPath, err)
	}
	defer file.Close()

	data, err := file.ReadAll()
	if err != nil {
		return fmt.Errorf("read %q: %w", readPath, err)
	}
	fmt.Printf("\n%s (%d bytes):\n%s\n", readPath, len(data), data)
	return nil
}
