package internal_test

import (
	"context"
	"path/filepath"
	"testing"

	forensic "github.com/laenix/ewfgo"
)

// TestBtrfsDetectedFromE01 pins the detection path against a real image: the
// data-layer probe checks the btrfs superblock magic "_BHRfS_M" at byte offset
// 0x10040 inside the partition window.
func TestBtrfsDetectedFromE01(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, filepath.Join("..", "testdata", "e01", "btrfs-encase25-zlib.E01"), forensic.Options{})
	if err != nil {
		t.Fatalf("forensic.Open: %v", err)
	}
	defer img.Close()

	parts, err := img.Partitions(ctx)
	if err != nil {
		t.Fatalf("Partitions: %v", err)
	}
	for _, p := range parts {
		if p.Format() == "Btrfs" {
			return
		}
	}
	t.Fatalf("Btrfs not detected in btrfs-encase25-zlib.E01: %+v", parts)
}
