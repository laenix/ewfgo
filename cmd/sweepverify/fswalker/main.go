package main

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"sort"
	"strings"

	forensic "github.com/laenix/ewfgo"
)

// Throwaway probe: walk a partition's filesystem tree through ewfgo's public
// API and print an `md5  path` manifest (paths root-relative, no leading slash)
// so it can be diffed against the Linux kernel's md5sum output on the same
// filesystem. Files that fail to read are printed as "ERR path".
func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: fswalker <image> <partition-index>")
		os.Exit(2)
	}
	ctx := context.Background()
	img, err := forensic.Open(ctx, os.Args[1], forensic.Options{})
	if err != nil {
		fmt.Println("open:", err)
		os.Exit(1)
	}
	defer img.Close()

	var part int
	fmt.Sscanf(os.Args[2], "%d", &part)
	parts, err := img.Partitions(ctx)
	if err != nil {
		fmt.Println("Partitions:", err)
		os.Exit(1)
	}
	if part < 0 || part >= len(parts) {
		fmt.Printf("partition index %d out of range (image has %d)\n", part, len(parts))
		os.Exit(1)
	}
	fsys, err := parts[part].OpenFilesystem(ctx)
	if err != nil {
		fmt.Println("OpenFilesystem:", err)
		os.Exit(1)
	}
	defer fsys.Close()

	var lines []string
	err = fsys.Walk(ctx, "/", func(entry forensic.Entry) error {
		if entry.IsDir {
			return nil
		}
		file, err := fsys.Open(ctx, entry.Path)
		if err != nil {
			lines = append(lines, "ERR "+entry.Path+" "+err.Error())
			return nil
		}
		data, err := file.ReadAll()
		file.Close()
		if err != nil {
			lines = append(lines, "ERR "+entry.Path+" "+err.Error())
			return nil
		}
		sum := md5.Sum(data)
		rel := strings.TrimPrefix(entry.Path, "/")
		lines = append(lines, fmt.Sprintf("%x  %s", sum, rel))
		return nil
	})
	if err != nil {
		fmt.Println("Walk:", err)
		os.Exit(1)
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
}
