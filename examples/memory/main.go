// Command memory prints the metadata and address runs of a memory dump and
// optionally hex-dumps bytes at one address.
//
// Usage:
//
//	go run ./examples/memory -image memory.lime
//	go run ./examples/memory -image memory.lime -addr 0x1000 -length 512
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	imagePath := flag.String("image", "", "memory dump path (LiME, hiberfil, kernel dump or minidump)")
	addr := flag.Uint64("addr", 0, "address to dump")
	length := flag.Uint64("length", 0, "bytes to dump (0 = no dump)")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: memory -image <dump> [-addr N] [-length N]")
		os.Exit(2)
	}
	if err := run(*imagePath, *addr, *length); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string, addr, length uint64) error {
	ctx := context.Background()
	dump, err := forensic.OpenMemory(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open memory dump: %w", err)
	}
	defer dump.Close()

	info := dump.Info()
	fmt.Printf("image       : %s\n", imagePath)
	fmt.Printf("kind        : %s\n", info.Kind)
	if info.Bitness != "" {
		fmt.Printf("bitness     : %s\n", info.Bitness)
	}
	if info.DumpType != "" {
		fmt.Printf("dump type   : %s\n", info.DumpType)
	}
	if info.Architecture != "" {
		fmt.Printf("architecture: %s\n", info.Architecture)
	}
	fmt.Printf("runs        : %d\n", info.Ranges)
	if info.PhysicalStart != 0 || info.PhysicalEnd != 0 {
		fmt.Printf("physical    : %#x..%#x\n", info.PhysicalStart, info.PhysicalEnd)
	}

	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "address\tlength\tfile offset")
	for _, run := range dump.Runs() {
		fmt.Fprintf(table, "%#x\t%d\t%d\n", run.Address, run.Length, run.FileOffset)
	}
	table.Flush()

	for _, warning := range info.Warnings {
		fmt.Println("warning:", warning)
	}

	if length == 0 {
		return nil
	}
	if length > 1<<20 {
		return fmt.Errorf("-length %d is too large for this example (max 1 MiB)", length)
	}
	buf := make([]byte, length)
	if _, err := dump.ReadAt(ctx, addr, buf); err != nil {
		return fmt.Errorf("read memory at %#x: %w", addr, err)
	}
	fmt.Printf("\nmemory at %#x:\n%s", addr, hex.Dump(buf))
	return nil
}
