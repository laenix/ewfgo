package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	forensic "github.com/laenix/ewfgo"
)

// Throwaway probe: print the metadata ewfgo parses for each image — media size
// and stored MD5/SHA1 — so it can be diffed against libewf's ewfinfo.
func main() {
	ctx := context.Background()
	for _, path := range os.Args[1:] {
		img, err := forensic.Open(ctx, path, forensic.Options{})
		if err != nil {
			fmt.Printf("%s\tERROR\t%v\n", filepath.Base(path), err)
			continue
		}
		info := img.Info()
		ss := img.SectorSize()
		sectors := img.Size() / uint64(ss)
		fmt.Printf("%s\tsectors=%d\tbytesper=%d\tmd5=%x\tsha1=%x\n",
			filepath.Base(path), sectors, ss, info.StoredMD5, info.StoredSHA1)
		img.Close()
	}
}
