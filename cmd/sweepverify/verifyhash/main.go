package main

import (
	"context"
	"fmt"
	"os"

	forensic "github.com/laenix/ewfgo"
)

// Throwaway probe: stream a whole image through Image.Verify and print whether
// the computed MD5/SHA1 match the hashes stored in the image.
func main() {
	ctx := context.Background()
	for _, path := range os.Args[1:] {
		img, err := forensic.Open(ctx, path, forensic.Options{})
		if err != nil {
			fmt.Println("open:", err)
			continue
		}
		info := img.Info()
		fmt.Printf("===== %s =====\n", path)
		fmt.Printf("  stored MD5 : %x\n", info.StoredMD5)
		fmt.Printf("  stored SHA1: %x\n", info.StoredSHA1)
		fmt.Printf("  media      : %d bytes\n", img.Size())
		res, err := img.Verify(ctx)
		if err != nil {
			fmt.Println("  verify:", err)
			img.Close()
			continue
		}
		fmt.Printf("  computed MD5 : %x  match=%v\n", res.ComputedMD5, res.MD5Match)
		fmt.Printf("  computed SHA1: %x  match=%v\n", res.ComputedSHA1, res.SHA1Match)
		fmt.Printf("  hashed %d bytes\n", res.BytesHashed)
		img.Close()
	}
}
