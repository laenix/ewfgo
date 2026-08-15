package main

import (
	"flag"
	"fmt"
	"time"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/apfs"
	"github.com/laenix/ewfgo/internal/filesystem/xfs"
)

// benchparse times the filesystem-parsing side of ewfgo: Open, ScanFileSystems,
// handler construction (mount chain / index build), and the first directory
// listing. This is the "解析" (parse) half of the speed question.
func main() {
	imgPath := flag.String("img", "", "E01 path")
	fs := flag.String("fs", "auto", "apfs | xfs | auto (from partition scan)")
	dir := flag.String("dir", "", "also time ListDirectory of this dir (e.g. /usr/lib64)")
	flag.Parse()
	if *imgPath == "" {
		fmt.Println("usage: benchparse -img <e01> [-fs apfs|xfs|auto] [-dir /path]")
		return
	}

	t := func(label string, fn func() (any, error)) {
		start := time.Now()
		v, err := fn()
		el := time.Since(start).Seconds()
		if err != nil {
			fmt.Printf("%-34s ERR %v\n", label, err)
			return
		}
		if n, ok := v.(int); ok {
			fmt.Printf("%-34s %6.3fs  (%d entries => %.0f entries/s)\n", label, el, n, float64(n)/el)
		} else {
			fmt.Printf("%-34s %6.3fs\n", label, el)
		}
	}

	var img *ewf.EWFImage
	t("Open", func() (any, error) {
		var err error
		img, err = ewf.Open(*imgPath)
		return nil, err
	})
	if img == nil {
		return
	}
	defer img.Close()

	var parts []ewf.PartitionInfo
	t("ScanFileSystems", func() (any, error) {
		var err error
		parts, err = img.ScanFileSystems()
		return nil, err
	})
	for i, p := range parts {
		fmt.Printf("  part %d: start=%d fs=%s\n", i, p.StartSector, p.FileSystem)
	}

	want := *fs
	if want == "auto" {
		for _, p := range parts {
			if p.FileSystem == "APFS" {
				want = "apfs"
				break
			}
			if p.FileSystem == "XFS" {
				want = "xfs"
				break
			}
		}
	}

	for i, p := range parts {
		if (want == "apfs" && p.FileSystem != "APFS") || (want == "xfs" && p.FileSystem != "XFS") {
			continue
		}
		start := p.StartSector
		var h filesystem.FileSystem
		t(fmt.Sprintf("part %d NewHandler(%s)", i, p.FileSystem), func() (any, error) {
			var err error
			switch p.FileSystem {
			case "APFS":
				h, err = apfs.NewAPFSHandler(img, start)
			case "XFS":
				h, err = xfs.NewXFSHandler(img, start)
			}
			return nil, err
		})
		if h == nil {
			continue
		}
		t(fmt.Sprintf("part %d ListDirectory(%q)", i, h.GetVolumeLabel()), func() (any, error) {
			entries, err := h.ListDirectory("")
			if err != nil {
				return 0, err
			}
			return len(entries), nil
		})
		if *dir != "" {
			t(fmt.Sprintf("part %d ListDirectory(%s)", i, *dir), func() (any, error) {
				entries, err := h.ListDirectory(*dir)
				if err != nil {
					return 0, err
				}
				return len(entries), nil
			})
		}
		h.Close()
	}
}
