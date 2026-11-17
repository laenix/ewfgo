// Command forensic opens an evidence image, enumerates its partitions and
// filesystems, lists a directory, and optionally reads a file.
//
// Usage:
//
//	go run ./examples/forensic -image evidence.E01
//	go run ./examples/forensic -image evidence.E01 -partition 1 -dir /etc
//	go run ./examples/forensic -image evidence.E01 -read /etc/hosts
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
	imagePath := flag.String("image", "", "evidence image path (E01, raw, VHD, VHDX, VMDK, QCOW2, VDI, DMG, ...)")
	partitionIndex := flag.Int("partition", 0, "zero-based partition to open")
	dir := flag.String("dir", "/", "directory to list")
	readPath := flag.String("read", "", "file to read after listing")
	flag.Parse()

	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: forensic -image <path> [-partition N] [-dir /path] [-read /path]")
		os.Exit(2)
	}
	if err := run(*imagePath, *partitionIndex, *dir, *readPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string, partitionIndex int, dir, readPath string) error {
	ctx := context.Background()

	img, err := forensic.Open(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}
	defer img.Close()

	info := img.Info()
	fmt.Printf("image       : %s\n", imagePath)
	fmt.Printf("format      : %s\n", info.Format)
	fmt.Printf("size        : %d bytes (%d-byte sectors)\n", img.Size(), img.SectorSize())
	if info.CaseNumber != "" {
		fmt.Printf("case        : %s\n", info.CaseNumber)
	}
	if info.EvidenceNumber != "" {
		fmt.Printf("evidence    : %s\n", info.EvidenceNumber)
	}

	parts, err := img.Partitions(ctx)
	if err != nil {
		return fmt.Errorf("list partitions: %w", err)
	}
	if len(parts) == 0 {
		return fmt.Errorf("no partitions or recognised filesystem")
	}

	fmt.Println("\npartitions:")
	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "  #\ttype\tformat\toffset\tlength")
	for _, p := range parts {
		fmt.Fprintf(table, "  %d\t%s\t%s\t%d\t%d\n",
			p.Index(), p.TypeName(), p.Format(), p.Offset(), p.Length())
	}
	table.Flush()

	if partitionIndex < 0 || partitionIndex >= len(parts) {
		return fmt.Errorf("partition %d does not exist (image has %d)", partitionIndex, len(parts))
	}
	part := parts[partitionIndex]

	fsys, err := part.OpenFilesystem(ctx)
	if err != nil {
		return fmt.Errorf("open filesystem on partition %d: %w", partitionIndex, err)
	}
	defer fsys.Close()

	fmt.Printf("\nfilesystem  : %s\n", fsys.Type())
	fmt.Printf("volume info : %+v\n", fsys.Info())

	entries, err := fsys.ListDir(ctx, dir)
	if err != nil {
		return fmt.Errorf("list %q: %w", dir, err)
	}
	fmt.Printf("\n%s: %d entries\n", dir, len(entries))
	table = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "  name\tsize\ttype")
	for _, entry := range entries {
		kind := "file"
		if entry.IsDir {
			kind = "dir"
		}
		if entry.IsSymlink {
			kind = "symlink"
		}
		fmt.Fprintf(table, "  %s\t%d\t%s\n", entry.Name, entry.Size, kind)
	}
	table.Flush()

	if readPath == "" {
		return nil
	}
	file, err := fsys.Open(ctx, readPath)
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
