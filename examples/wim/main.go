// Command wim lists the images inside a Windows Imaging Format archive, lists
// one image's files, and optionally reads a file.
//
// Usage:
//
//	go run ./examples/wim -image install.wim
//	go run ./examples/wim -image install.wim -image-index 1 -read Windows/System32/drivers/etc/hosts
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
	imagePath := flag.String("image", "", "WIM path")
	imageIndex := flag.Uint("image-index", 1, "WIM image index")
	readPath := flag.String("read", "", "file path inside the image")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: wim -image <install.wim> [-image-index N] [-read path]")
		os.Exit(2)
	}
	if err := run(*imagePath, uint32(*imageIndex), *readPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string, imageIndex uint32, readPath string) error {
	ctx := context.Background()
	wim, err := forensic.OpenWIM(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open WIM: %w", err)
	}
	defer wim.Close()

	info := wim.Info()
	fmt.Printf("image file  : %s\n", imagePath)
	fmt.Printf("compression : %s\n", info.Compression)
	fmt.Printf("images      : %d\n\n", info.Images)

	images, err := wim.Images(ctx)
	if err != nil {
		return fmt.Errorf("list WIM images: %w", err)
	}
	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "index\tname\tfiles\tdirs")
	for _, image := range images {
		fmt.Fprintf(table, "%d\t%s\t%d\t%d\n",
			image.Index, image.Name, image.Files, image.Directories)
	}
	table.Flush()

	entries, err := wim.Entries(ctx, imageIndex)
	if err != nil {
		return fmt.Errorf("list entries of image %d: %w", imageIndex, err)
	}
	fmt.Printf("\nimage %d: %d entries\n", imageIndex, len(entries))
	table = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "path\tdir\tsize\tresolved")
	for _, entry := range entries {
		fmt.Fprintf(table, "%s\t%v\t%d\t%v\n",
			entry.Path, entry.IsDir, entry.Size, entry.Resolved)
	}
	table.Flush()

	if readPath == "" {
		return nil
	}
	file, err := wim.Open(ctx, imageIndex, readPath)
	if err != nil {
		return fmt.Errorf("open %q in image %d: %w", readPath, imageIndex, err)
	}
	defer file.Close()

	data, err := file.ReadAll()
	if err != nil {
		return fmt.Errorf("read %q: %w", readPath, err)
	}
	fmt.Printf("\n%s (%d bytes):\n%s\n", readPath, len(data), data)
	return nil
}
