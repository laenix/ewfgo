package inspect

import (
	"testing"

	"github.com/laenix/ewfgo/internal/data/filesystems/probe"
	"github.com/laenix/ewfgo/internal/data/partition"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/ewffixture"
	"github.com/laenix/ewfgo/internal/filesystem"
)

func TestInspectMBRImage(t *testing.T) {
	fsImage := make([]byte, 8*512)
	copy(fsImage[3:], "NTFS    ")
	disk := ewffixture.WrapMBRDisk(fsImage, 0x07, 2048)

	report, err := Image(1, source.NewMemorySourceWithImage(1, 7, disk), 512)
	if err != nil {
		t.Fatalf("Image error = %v", err)
	}
	if report.TableKind != partition.KindMBR {
		t.Fatalf("TableKind = %v, want MBR", report.TableKind)
	}
	if len(report.Partitions) != 1 {
		t.Fatalf("partitions = %d, want 1", len(report.Partitions))
	}
	p := report.Partitions[0]
	if p.FSType != filesystem.FS_NTFS {
		t.Fatalf("partition FS = %v, want NTFS", p.FSType)
	}
	if p.Format != probe.NTFS {
		t.Fatalf("partition probe = %v, want NTFS", p.Format)
	}
	if p.Offset != 2048*512 || p.Length != uint64(len(fsImage)) {
		t.Fatalf("partition geometry = %d + %d", p.Offset, p.Length)
	}
	if err := report.Graph.Validate(); err != nil {
		t.Fatalf("graph validation: %v", err)
	}
	if _, ok := report.Graph.Node(p.NodeID); !ok {
		t.Fatal("partition node is missing from the graph")
	}
	if _, ok := report.Graph.Node(p.FSNodeID); !ok {
		t.Fatal("filesystem node is missing from the graph")
	}
}

func TestInspectBareVolume(t *testing.T) {
	image := make([]byte, 4096)
	copy(image[0x52:0x5A], "FAT32   ")

	report, err := Image(1, source.NewMemorySourceWithImage(1, 7, image), 512)
	if err != nil {
		t.Fatalf("Image error = %v", err)
	}
	if report.TableKind != partition.KindNone {
		t.Fatalf("TableKind = %v, want none", report.TableKind)
	}
	if report.VolumeType != filesystem.FS_FAT32 {
		t.Fatalf("VolumeType = %v, want FAT32", report.VolumeType)
	}
	if report.VolumeFormat != probe.FAT {
		t.Fatalf("VolumeFormat = %v, want FAT", report.VolumeFormat)
	}
	if err := report.Graph.Validate(); err != nil {
		t.Fatalf("graph validation: %v", err)
	}
}

func TestInspectEncryptedPartition(t *testing.T) {
	fsImage := make([]byte, 8*512)
	copy(fsImage[3:], "-FVE-FS-")
	disk := ewffixture.WrapMBRDisk(fsImage, 0x07, 2048)

	report, err := Image(1, source.NewMemorySourceWithImage(1, 7, disk), 512)
	if err != nil {
		t.Fatalf("Image error = %v", err)
	}
	if len(report.Partitions) != 1 {
		t.Fatalf("partitions = %d", len(report.Partitions))
	}
	if report.Partitions[0].Format != probe.BitLocker || !report.Partitions[0].Format.Encrypted() {
		t.Fatalf("partition format = %v", report.Partitions[0].Format)
	}
}

func TestInspectEmptyImage(t *testing.T) {
	report, err := Image(1, source.NewMemorySourceWithImage(1, 7, make([]byte, 4096)), 512)
	if err != nil {
		t.Fatalf("Image error = %v", err)
	}
	if report.TableKind != partition.KindNone || report.VolumeType != filesystem.FS_UNKNOWN {
		t.Fatalf("report = table %v volume %v", report.TableKind, report.VolumeType)
	}
	if err := report.Graph.Validate(); err != nil {
		t.Fatalf("graph validation: %v", err)
	}
}
