// Command verify streams an image through the strict read path and compares
// the computed MD5/SHA1 with the acquisition hashes stored in the container.
//
// Usage:
//
//	go run ./examples/verify -image evidence.E01
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	imagePath := flag.String("image", "", "evidence image path")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: verify -image <path>")
		os.Exit(2)
	}
	if err := run(*imagePath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string) error {
	ctx := context.Background()
	img, err := forensic.Open(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}
	defer img.Close()

	info := img.Info()
	fmt.Printf("image        : %s (%s)\n", imagePath, info.Format)
	fmt.Printf("media bytes  : %d\n", img.Size())
	fmt.Printf("stored MD5   : %s\n", hexOrNone(info.StoredMD5))
	fmt.Printf("stored SHA1  : %s\n", hexOrNone(info.StoredSHA1))

	res, err := img.Verify(ctx)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Printf("computed MD5 : %s  match=%v\n", hex.EncodeToString(res.ComputedMD5), res.MD5Match)
	fmt.Printf("computed SHA1: %s  match=%v\n", hex.EncodeToString(res.ComputedSHA1), res.SHA1Match)
	fmt.Printf("hashed bytes : %d\n", res.BytesHashed)
	return nil
}

func hexOrNone(value []byte) string {
	if len(value) == 0 {
		return "(not recorded)"
	}
	return hex.EncodeToString(value)
}
