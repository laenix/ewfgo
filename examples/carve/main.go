// Command carve finds known file signatures in an image. Use -out to export
// each top-level object to a directory; without it, only the report is printed.
//
// Usage:
//
//	go run ./examples/carve -image evidence.E01
//	go run ./examples/carve -image evidence.E01 -start 0 -length 104857600
//	go run ./examples/carve -image evidence.E01 -out ./carved
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	imagePath := flag.String("image", "", "evidence image path")
	start := flag.Uint64("start", 0, "first byte to scan")
	length := flag.Uint64("length", 0, "bytes to scan (0 = to the end)")
	outDir := flag.String("out", "", "export carved top-level objects to this directory")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: carve -image <path> [-start N] [-length N] [-out DIR]")
		os.Exit(2)
	}
	if err := run(*imagePath, *start, *length, *outDir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string, start, length uint64, outDir string) error {
	ctx := context.Background()
	img, err := forensic.Open(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}
	defer img.Close()

	if length == 0 {
		if start > img.Size() {
			return fmt.Errorf("start %d is past the %d-byte image", start, img.Size())
		}
		length = img.Size() - start
	}

	report, err := img.Carve(ctx, start, length, forensic.DefaultCarveOptions())
	if err != nil {
		return fmt.Errorf("carve: %w", err)
	}

	fmt.Printf("image        : %s\n", imagePath)
	fmt.Printf("range        : %d + %d\n", start, length)
	fmt.Printf("objects      : %d (%d top-level)\n", len(report.Objects), len(report.TopLevel()))
	fmt.Printf("rejected     : %d\n", report.Rejected)
	fmt.Printf("unreadable   : %d bytes\n", report.Unreadable)

	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "offset\tlength\tformat\tterminated\tdetail")
	for _, object := range report.TopLevel() {
		fmt.Fprintf(table, "%d\t%d\t%s\t%v\t%s\n",
			object.Offset, object.Len, object.Format.Label(), object.Terminated, object.Detail)
	}
	table.Flush()

	if outDir == "" {
		return nil
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, object := range report.TopLevel() {
		if !object.Terminated {
			continue
		}
		name := fmt.Sprintf("%016x.%s", object.Offset, object.Format.Extension())
		if err := exportObject(img.Source(), object.Offset, object.Len, filepath.Join(outDir, name)); err != nil {
			return fmt.Errorf("export object at %d: %w", object.Offset, err)
		}
		fmt.Printf("exported %s (%d bytes)\n", name, object.Len)
	}
	return nil
}

func exportObject(src forensic.ByteSource, offset, length uint64, target string) error {
	file, err := os.Create(target)
	if err != nil {
		return err
	}
	defer file.Close()

	const chunk = 1 << 20
	buf := make([]byte, chunk)
	for done := uint64(0); done < length; {
		want := uint64(chunk)
		if want > length-done {
			want = length - done
		}
		n, err := src.ReadAt(offset+done, buf[:want])
		if err != nil {
			return err
		}
		if uint64(n) != want {
			return io.ErrUnexpectedEOF
		}
		if _, err := file.Write(buf[:n]); err != nil {
			return err
		}
		done += uint64(n)
	}
	return file.Close()
}
