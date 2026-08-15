package internal_test

import (
	"path/filepath"
	"testing"

	ewf "github.com/laenix/ewfgo"
)

// TestBtrfsDetectedFromE01 pins the surviving detection path against a real
// image: ewf.DetectFileSystem delegates to filesystem.DetectFileSystem, which
// probes the actual btrfs superblock magic "_BHRfS_M" at byte offset 0x10040
// (requiring the >=129-sector read window that ScanFileSystems already uses).
func TestBtrfsDetectedFromE01(t *testing.T) {
	img, err := ewf.Open(filepath.Join("..", "testdata", "e01", "btrfs-encase25-zlib.E01"))
	if err != nil {
		t.Fatalf("ewf.Open: %v", err)
	}
	defer img.Close()

	parts, err := img.ScanFileSystems()
	if err != nil {
		t.Fatalf("ScanFileSystems: %v", err)
	}
	for _, p := range parts {
		if p.FileSystem == "Btrfs" {
			return
		}
	}
	t.Fatalf("Btrfs not detected in btrfs-encase25-zlib.E01: %+v", parts)
}
