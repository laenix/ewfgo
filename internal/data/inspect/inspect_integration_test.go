package inspect

import (
	"os"
	"path/filepath"
	"testing"

	ewfcontainer "github.com/laenix/ewfgo/internal/data/containers/ewf"
	"github.com/laenix/ewfgo/internal/data/partition"
	"github.com/laenix/ewfgo/internal/ewffixture"
	"github.com/laenix/ewfgo/internal/filesystem"
)

// TestInspectE01EndToEnd proves the whole stack: E01 file -> exact
// decompression -> partition table -> partition window -> filesystem
// detection, all recorded in a validated source graph.
func TestInspectE01EndToEnd(t *testing.T) {
	fsImage := make([]byte, 8*512)
	copy(fsImage[3:], "NTFS    ")
	disk := ewffixture.WrapMBRDisk(fsImage, 0x07, 2048)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})

	path := filepath.Join(t.TempDir(), "disk.E01")
	if err := os.WriteFile(path, e01, 0o600); err != nil {
		t.Fatal(err)
	}
	src, _, err := ewfcontainer.OpenFile(10, 1, path)
	if err != nil {
		t.Fatalf("Open E01: %v", err)
	}
	defer src.Close()

	report, err := Image(10, src, 512)
	if err != nil {
		t.Fatalf("Image error = %v", err)
	}
	if report.TableKind != partition.KindMBR {
		t.Fatalf("TableKind = %v, want MBR", report.TableKind)
	}
	if len(report.Partitions) != 1 || report.Partitions[0].FSType != filesystem.FS_NTFS {
		t.Fatalf("partitions = %+v", report.Partitions)
	}
	if err := report.Graph.Validate(); err != nil {
		t.Fatalf("graph validation: %v", err)
	}
}
