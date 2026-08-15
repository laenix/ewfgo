package main

import (
	"fmt"
	"os"
	"path/filepath"

	ewf "github.com/laenix/ewfgo"
)

// Throwaway probe: print the metadata ewfgo parses for each E01 — media size
// and stored MD5/SHA1 — so it can be diffed against libewf's ewfinfo.
func main() {
	for _, path := range os.Args[1:] {
		img, err := ewf.Open(path)
		if err != nil {
			fmt.Printf("%s\tERROR\t%v\n", filepath.Base(path), err)
			continue
		}
		md5h, sha1h := img.StoredHashes()
		fmt.Printf("%s\tsectors=%d\tbytesper=%d\tmd5=%x\tsha1=%x\n",
			filepath.Base(path), img.TotalSectors(), img.SectorSize(), md5h, sha1h)
		img.Close()
	}
}
