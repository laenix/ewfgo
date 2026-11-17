package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	forensic "github.com/laenix/ewfgo"
)

// benchparse times the filesystem-parsing side of ewfgo through the public
// API: Open (container + metadata), Partitions (table + probe), OpenFilesystem
// (handler construction / tree build) and the first directory listing. This is
// the "解析" (parse) half of the speed question.
func main() {
	imgPath := flag.String("img", "", "image path (E01, raw, VHD, VHDX, VMDK, QCOW2, VDI)")
	fsKind := flag.String("fs", "auto", "partition filesystem to time (e.g. APFS, ext4, XFS, FAT32; auto = every detected volume)")
	dir := flag.String("dir", "", "also time ListDir of this directory (e.g. /usr/lib64)")
	flag.Parse()
	if *imgPath == "" {
		fmt.Println("usage: benchparse -img <image> [-fs <type>|auto] [-dir /path]")
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

	ctx := context.Background()
	var img *forensic.Image
	t("Open", func() (any, error) {
		var err error
		img, err = forensic.Open(ctx, *imgPath, forensic.Options{})
		return nil, err
	})
	if img == nil {
		return
	}
	defer img.Close()

	var parts []*forensic.Partition
	t("Partitions", func() (any, error) {
		var err error
		parts, err = img.Partitions(ctx)
		return nil, err
	})
	for i, p := range parts {
		fmt.Printf("  part %d: offset=%d format=%s\n", i, p.Offset(), p.Format())
	}

	for i, p := range parts {
		if *fsKind != "auto" && p.Format() != *fsKind {
			continue
		}
		var fsys forensic.FileSystem
		t(fmt.Sprintf("part %d OpenFilesystem(%s)", i, p.Format()), func() (any, error) {
			var err error
			fsys, err = p.OpenFilesystem(ctx)
			return nil, err
		})
		if fsys == nil {
			continue
		}
		t(fmt.Sprintf("part %d ListDir(\"/\")", i), func() (any, error) {
			entries, err := fsys.ListDir(ctx, "/")
			return len(entries), err
		})
		if *dir != "" {
			t(fmt.Sprintf("part %d ListDir(%s)", i, *dir), func() (any, error) {
				entries, err := fsys.ListDir(ctx, *dir)
				return len(entries), err
			})
		}
		fsys.Close()
	}
}
