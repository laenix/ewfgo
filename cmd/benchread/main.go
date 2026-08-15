package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	ewf "github.com/laenix/ewfgo"
)

// benchread measures ewfgo's EWF-container read throughput: it opens an E01 and
// reads the first N GiB of media sequentially through the public ReadSectors
// API, discarding the data, and reports MiB/s. This is exactly the path a
// consumer (NBD server / forensic engine) takes.
func main() {
	imgPath := flag.String("img", "", "E01 path")
	gb := flag.Float64("gb", 4, "GiB of media to read")
	chunk := flag.Int("chunk", 1<<20, "sectors per ReadSectors call (512-byte)")
	raw := flag.Bool("raw", false, "read the container file sequentially (disk floor)")
	cpu := flag.String("cpu", "", "write CPU profile to file")
	flag.Parse()
	if *imgPath == "" {
		fmt.Println("usage: benchread -img <e01> -gb N [-chunk sectors] [-raw] [-cpu out]")
		return
	}
	if *cpu != "" {
		f, err := os.Create(*cpu)
		if err != nil {
			fmt.Println("cpuprofile:", err)
			return
		}
		pprof.StartCPUProfile(f)
		defer func() { pprof.StopCPUProfile(); f.Close() }()
	}
	if *raw {
		rawRead(*imgPath, *gb)
		return
	}

	start := time.Now()
	img, err := ewf.Open(*imgPath)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer img.Close()
	openDur := time.Since(start)

	total := img.TotalSectors()
	mediaBytes := total * 512
	readSectors := uint64(*gb * 1024 * 1024 * 1024 / 512)
	if readSectors > total {
		readSectors = total
	}
	c := uint64(*chunk)
	if c == 0 {
		c = 1
	}

	var bytes uint64
	start = time.Now()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-ticker.C:
				el := time.Since(start).Seconds()
				fmt.Printf("  ... %s in %.1fs (%.0f MiB/s)\n", fmtBytes(bytes), el,
					float64(bytes)/1024/1024/el)
			case <-done:
				return
			}
		}
	}()
	for lba := uint64(0); lba < readSectors; lba += c {
		n := c
		if lba+n > readSectors {
			n = readSectors - lba
		}
		data, err := img.ReadSectors(lba, n)
		if err != nil {
			fmt.Printf("read err at lba %d: %v\n", lba, err)
			return
		}
		bytes += uint64(len(data))
	}
	dur := time.Since(start)

	mb := float64(bytes) / 1024 / 1024
	fmt.Printf("image       : %s\n", *imgPath)
	fmt.Printf("media size  : %s (%d sectors)\n", fmtBytes(mediaBytes), total)
	fmt.Printf("open        : %.3fs\n", openDur.Seconds())
	fmt.Printf("read        : %s in %.2fs\n", fmtBytes(bytes), dur.Seconds())
	fmt.Printf("throughput  : %.1f MiB/s  (%.2f GiB/s)\n", mb/dur.Seconds(), mb/1024/dur.Seconds())
}

func rawRead(path string, gb float64) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer f.Close()
	target := uint64(gb * 1024 * 1024 * 1024)
	buf := make([]byte, 4<<20)
	var bytes uint64
	start := time.Now()
	for bytes < target {
		n, err := f.Read(buf)
		if err != nil {
			break
		}
		bytes += uint64(n)
	}
	dur := time.Since(start)
	mb := float64(bytes) / 1024 / 1024
	fmt.Printf("raw file read: %s in %.2fs => %.1f MiB/s\n",
		fmtBytes(bytes), dur.Seconds(), mb/dur.Seconds())
}

func fmtBytes(n uint64) string {
	const G = 1024 * 1024 * 1024
	if n >= G {
		return fmt.Sprintf("%.2f GiB", float64(n)/G)
	}
	return fmt.Sprintf("%d B", n)
}
