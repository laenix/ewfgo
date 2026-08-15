// Command forensic is a runnable example of the ewfgo forensic engine API.
//
// It opens an EWF/E01 evidence image, enumerates its partitions, lists the
// first partition's root directory and, if present, prints the content of a
// named file (default "fixture.txt").
//
// Usage:
//
//	go run ./examples/forensic <image.E01> [path-to-read]
package main

import (
	"fmt"
	"os"

	"github.com/laenix/ewfgo"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <image.E01> [path-to-read]\n", os.Args[0])
		os.Exit(2)
	}
	if err := run(os.Args[1], fileArg(os.Args)); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// fileArg returns the optional path argument, defaulting to "fixture.txt".
func fileArg(args []string) string {
	if len(args) >= 3 {
		return args[2]
	}
	return "fixture.txt"
}

func run(imagePath, readPath string) error {
	// Open auto-discovers sibling segments (E01/E02/...), so a single path
	// suffices for both single- and multi-segment images.
	img, err := ewf.Open(imagePath)
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}
	defer img.Close()

	fmt.Printf("image: %s\n", imagePath)
	fmt.Printf("  case number: %q\n", img.CaseNumber())
	fmt.Printf("  total sectors: %d (sector size %d)\n", img.TotalSectors(), img.SectorSize())

	parts, err := img.ScanFileSystems()
	if err != nil {
		return fmt.Errorf("scan filesystems: %w", err)
	}
	fmt.Printf("partitions: %d\n", len(parts))
	for _, p := range parts {
		fmt.Printf("  partition %d: type=%s fs=%q start=%d size=%d bytes\n",
			p.Index, p.TypeName, p.FileSystem, p.StartSector, p.SizeBytes)
	}
	if len(parts) == 0 {
		fmt.Println("no partitions found")
		return nil
	}

	// Open the first partition's filesystem and list its root.
	fs, err := img.OpenFileSystem(parts[0].Index)
	if err != nil {
		return fmt.Errorf("open filesystem of partition %d: %w", parts[0].Index, err)
	}
	defer fs.Close()

	fmt.Printf("partition %d filesystem: %s\n", parts[0].Index, fs.FSType())
	entries, err := fs.ListDir("/")
	if err != nil {
		return fmt.Errorf("list root of partition %d: %w", parts[0].Index, err)
	}
	fmt.Printf("root entries: %d\n", len(entries))
	for _, e := range entries {
		kind := "file"
		if e.IsDir {
			kind = "dir "
		}
		fmt.Printf("  %s %8d  %s\n", kind, e.Size, e.Name)
	}

	// Read a named file if present.
	data, err := fs.ReadFile(readPath)
	if err != nil {
		fmt.Printf("read %q: %v (file may not exist on this image)\n", readPath, err)
		return nil
	}
	fmt.Printf("%s (%d bytes):\n", readPath, len(data))
	fmt.Print(string(data))
	return nil
}
