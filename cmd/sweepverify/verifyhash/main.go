package main

import (
	"fmt"
	"os"

	ewf "github.com/laenix/ewfgo"
)

// Throwaway probe: stream a whole E01 through VerifyImageHash and print whether
// the computed MD5/SHA1 match the hashes stored in the image.
func main() {
	for _, path := range os.Args[1:] {
		img, err := ewf.Open(path)
		if err != nil {
			fmt.Println("open:", err)
			continue
		}
		md5h, sha1h := img.StoredHashes()
		fmt.Printf("===== %s =====\n", path)
		fmt.Printf("  stored MD5 : %x\n", md5h)
		fmt.Printf("  stored SHA1: %x\n", sha1h)
		fmt.Printf("  media      : %d sectors x %d B = %d bytes\n",
			img.TotalSectors(), img.SectorSize(), img.TotalSectors()*uint64(img.SectorSize()))
		res, err := img.VerifyImageHash()
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
