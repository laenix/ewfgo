package forensic_test

import (
	"context"
	"testing"

	forensic "github.com/laenix/ewfgo"
)

func TestScanFindsVolumeSignatures(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixture(t, "fat16-encase6-zlib.E01"), forensic.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()
	parts, err := img.Partitions(ctx)
	if err != nil || len(parts) == 0 {
		t.Fatalf("Partitions: %v (%d)", err, len(parts))
	}
	report, err := parts[0].Scan(ctx, forensic.DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.TopLevel()) == 0 {
		t.Fatalf("scan found no top-level volumes: %+v", report)
	}
	found := false
	for _, candidate := range report.TopLevel() {
		if candidate.Offset == 0 && candidate.Status != forensic.ScanRejected {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAT volume at offset 0 not confirmed: %+v", report.TopLevel())
	}
}
