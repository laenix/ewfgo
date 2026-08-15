package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"sort"
	"strings"

	ewf "github.com/laenix/ewfgo"
)

// Throwaway probe: walk a partition's filesystem tree through ewfgo's public
// API and print an `md5  path` manifest (paths root-relative, no leading slash)
// so it can be diffed against the Linux kernel's md5sum output on the same
// filesystem. Files that fail to read are printed as "ERR path".
func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: fswalker <E01> <partition>")
		os.Exit(2)
	}
	img, err := ewf.Open(os.Args[1])
	if err != nil {
		fmt.Println("open:", err)
		os.Exit(1)
	}
	defer img.Close()
	var part int
	fmt.Sscanf(os.Args[2], "%d", &part)
	fs, err := img.OpenFileSystem(part)
	if err != nil {
		fmt.Println("OpenFileSystem:", err)
		os.Exit(1)
	}
	defer fs.Close()

	var lines []string
	var walk func(dir string)
	walk = func(dir string) {
		entries, err := fs.ListDir(dir)
		if err != nil {
			lines = append(lines, "ERRDIR "+dir+" "+err.Error())
			return
		}
		for _, e := range entries {
			if e.Name == "." || e.Name == ".." {
				continue
			}
			if e.IsDir {
				walk(e.Path)
				continue
			}
			data, err := fs.ReadFile(e.Path)
			if err != nil {
				lines = append(lines, "ERR "+e.Path+" "+err.Error())
				continue
			}
			sum := md5.Sum(data)
			rel := strings.TrimPrefix(e.Path, "/")
			lines = append(lines, fmt.Sprintf("%x  %s", sum, rel))
		}
	}
	walk("/")
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
}
