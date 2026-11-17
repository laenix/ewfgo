package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	forensic "github.com/laenix/ewfgo"
)

// benchread measures ewfgo's evidence read throughput: it opens an image and
// streams the first N GiB of decoded media through the public ByteSource strict
// read path, discarding the data, and reports MiB/s. This is exactly the path a
// consumer (NBD server / forensic engine) takes.
func main() {
	imgPath := flag.String("img", "", "image path")
	gb := flag.Float64("gb", 4, "GiB of media to read")
	chunk := flag.Int("chunk", 1<<20, "bytes per ReadAt call")
	raw := flag.Bool("raw", false, "read the container file sequentially (disk floor)")
	cpu := flag.String("cpu", "", "write CPU profile to file")
	flag.Parse()
	if *imgPath == "" {
		fmt.Println("usage: benchread -img <image> -gb N [-chunk bytes] [-raw] [-cpu out]")
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

	ctx := context.Background()
	start := time.Now()
	img, err := forensic.Open(ctx, *imgPath, forensic.Options{})
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer img.Close()
	openDur := time.Since(start)

	total := img.Size()
	target := uint64(*gb * 1024 * 1024 * 1024)
	if target > total {
		target = total
	}
	c := *chunk
	if c <= 0 {
		c = 1 << 20
	}
	buf := make([]byte, c)
	src := img.Source()

	var bytesRead uint64
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
				fmt.Printf("  ... %s in %.1fs (%.0f MiB/s)\n", fmtBytes(bytesRead), el,
					float64(bytesRead)/1024/1024/el)
			case <-done:
				return
			}
		}
	}()

	for offset := uint64(0); offset < target; {
		want := uint64(c)
		if want > target-offset {
			want = target - offset
		}
		n, err := src.ReadAt(offset, buf[:want])
		if err != nil {
			fmt.Printf("read err at offset %d: %v\n", offset, err)
			return
		}
		if uint64(n) != want {
			fmt.Printf("short read at offset %d: got %d, want %d\n", offset, n, want)
			return
		}
		bytesRead += uint64(n)
		offset += uint64(n)
	}
	dur := time.Since(start)

	mb := float64(bytesRead) / 1024 / 1024
	fmt.Printf("image       : %s (%s)\n", *imgPath, img.Format())
	fmt.Printf("media size  : %s\n", fmtBytes(total))
	fmt.Printf("open        : %.3fs\n", openDur.Seconds())
	fmt.Printf("read        : %s in %.2fs\n", fmtBytes(bytesRead), dur.Seconds())
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
