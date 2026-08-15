package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/laenix/ewfgo/internal/ewffixture"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gen-fs":
		if len(os.Args) != 4 {
			usage()
		}
		genFS(os.Args[2], os.Args[3])
	case "gen-matrix":
		if len(os.Args) != 4 {
			usage()
		}
		genMatrix(os.Args[2], os.Args[3])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ewffixture gen-fs <raw-fs-dir> <e01-outdir>")
	fmt.Fprintln(os.Stderr, "       ewffixture gen-matrix <raw-fs-dir> <e01-outdir>")
	os.Exit(2)
}

// variants is the 5-way container cross-product: every raw filesystem image is
// wrapped once per variant so the full FS x container matrix exercises the
// distinct E01 code paths (layout, slack tail, multi-section spanning).
var variants = []struct {
	name string
	opts ewffixture.Options
}{
	{"encase25-zlib", ewffixture.Options{Layout: ewffixture.LayoutEnCase2_5, Compress: ewffixture.CompressZlib}},
	{"encase25-zlib-slack", ewffixture.Options{Layout: ewffixture.LayoutEnCase2_5, Compress: ewffixture.CompressZlib, SlackBytes: 512}},
	{"encase6-zlib", ewffixture.Options{Layout: ewffixture.LayoutEnCase6, Compress: ewffixture.CompressZlib}},
	{"encase25-sections2", ewffixture.Options{Layout: ewffixture.LayoutEnCase2_5, Compress: ewffixture.CompressZlib, Sections: 2}},
	{"encase6-sections2", ewffixture.Options{Layout: ewffixture.LayoutEnCase6, Compress: ewffixture.CompressZlib, Sections: 2}},
}

// genMatrix emits, for every <rawdir>/<base>.img, the 5 container variants as
// <e01outdir>/<base>-<variant>.E01.
func genMatrix(indir, outdir string) {
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, e := range imgs(indir) {
		base := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		fsImg := readImg(filepath.Join(indir, e.Name()))
		for _, v := range variants {
			e01 := wrapE01(fsImg, v.opts)
			writeE01(filepath.Join(outdir, base+"-"+v.name+".E01"), e01)
		}
	}
}

// genFS keeps the original one-E01-per-FS behavior (default EnCase 2-5 zlib).
func genFS(indir, outdir string) {
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, e := range imgs(indir) {
		base := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		e01 := wrapE01(readImg(filepath.Join(indir, e.Name())), ewffixture.Options{})
		writeE01(filepath.Join(outdir, base+".E01"), e01)
	}
}

func imgs(dir string) []os.DirEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var out []os.DirEntry
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".img" {
			out = append(out, e)
		}
	}
	return out
}

func readImg(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return b
}

// wrapE01 wraps a raw filesystem image into an MBR disk (Linux partition type
// 0x83 at LBA 2048) and then into a single-volume E01.
func wrapE01(fsImg []byte, opts ewffixture.Options) []byte {
	disk := ewffixture.WrapMBRDisk(fsImg, 0x83, 2048)
	return ewffixture.WrapDisk(disk, opts)
}

func writeE01(path string, e01 []byte) {
	if err := os.WriteFile(path, e01, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(e01))
}
