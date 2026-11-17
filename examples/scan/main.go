// Command scan searches an image for partition tables, boot sectors and
// filesystem superblocks. It is the recovery path when the partition table is
// damaged or overwritten.
//
// Usage:
//
//	go run ./examples/scan -image evidence.E01
//	go run ./examples/scan -image evidence.E01 -limit 67108864
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	imagePath := flag.String("image", "", "evidence image path")
	limit := flag.Uint64("limit", 0, "stop after this many bytes (0 = whole image)")
	maxCandidates := flag.Int("max-candidates", 0, "candidate cap (0 = library default)")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: scan -image <path> [-limit bytes] [-max-candidates N]")
		os.Exit(2)
	}
	if err := run(*imagePath, *limit, *maxCandidates); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string, limit uint64, maxCandidates int) error {
	ctx := context.Background()
	img, err := forensic.Open(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}
	defer img.Close()

	options := forensic.DefaultScanOptions()
	if limit != 0 {
		options.Limit = &limit
	}
	if maxCandidates > 0 {
		options.MaxCandidates = maxCandidates
	}

	report, err := img.Scan(ctx, options)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	fmt.Printf("image        : %s\n", imagePath)
	fmt.Printf("sector size  : %d\n", report.SectorSize)
	fmt.Printf("bytes scanned: %d\n", report.BytesScanned)
	fmt.Printf("candidates   : %d (%d top-level)\n", len(report.Candidates), len(report.TopLevel()))
	fmt.Printf("rejected hits: %d  truncated=%v\n", report.RejectedHits, report.Truncated)

	table := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "offset\tid\tlabel\tlength\tstatus\treason")
	for _, candidate := range report.TopLevel() {
		fmt.Fprintf(table, "%d\t%s\t%s\t%d\t%s\t%s\n",
			candidate.Offset, candidate.ID, candidate.Label,
			candidate.VolumeLen, candidate.Status, candidate.Reason)
	}
	table.Flush()
	return nil
}
