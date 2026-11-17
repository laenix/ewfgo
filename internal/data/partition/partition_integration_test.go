package partition_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	ewfcontainer "github.com/laenix/ewfgo/internal/data/containers/ewf"
	"github.com/laenix/ewfgo/internal/data/partition"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/ewffixture"
)

// TestDetectMBROverE01 exercises the whole new stack: E01 container -> byte
// source -> partition table -> partition window. The window must read back the
// filesystem bytes byte-for-byte.
func TestDetectMBROverE01(t *testing.T) {
	fsImage := make([]byte, 8*512)
	for i := range fsImage {
		fsImage[i] = byte(i)
	}
	disk := ewffixture.WrapMBRDisk(fsImage, 0x07, 2048)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})

	path := filepath.Join(t.TempDir(), "disk.E01")
	if err := os.WriteFile(path, e01, 0o600); err != nil {
		t.Fatal(err)
	}
	image, _, err := ewfcontainer.OpenFile(1, 1, path)
	if err != nil {
		t.Fatalf("Open E01: %v", err)
	}
	defer image.Close()

	table, err := partition.Detect(image)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if table.Kind != partition.KindMBR {
		t.Fatalf("partition table kind = %v, want MBR", table.Kind)
	}
	partitions := table.Partitions()
	if len(partitions) != 1 {
		t.Fatalf("partitions = %d, want 1", len(partitions))
	}
	p := partitions[0]
	if p.StartLBA != 2048 || p.Offset != 2048*512 || p.Len != uint64(len(fsImage)) {
		t.Fatalf("partition = %+v", p)
	}

	window, err := source.NewSubSource(2, image, p.Offset, p.Len)
	if err != nil {
		t.Fatalf("NewSubSource: %v", err)
	}
	buf := make([]byte, len(fsImage))
	if _, err := window.ReadAt(0, buf); err != nil {
		t.Fatalf("partition read: %v", err)
	}
	if !bytes.Equal(buf, fsImage) {
		t.Fatal("partition window did not return the original filesystem bytes")
	}
}
