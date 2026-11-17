package partition

import (
	"testing"

	"github.com/laenix/ewfgo/internal/data/foundation"
)

func putLE16Sig(b []byte, at int, v uint16) {
	b[at], b[at+1] = byte(v), byte(v>>8)
}

func headWith(size int, fn func([]byte)) []byte {
	head := make([]byte, size)
	fn(head)
	return head
}

func TestVolumeSignature(t *testing.T) {
	btrfs := 64*1024 + 64
	cases := []struct {
		name  string
		head  []byte
		id    string
		label string
	}{
		{"ntfs", headWith(4096, func(h []byte) { copy(h[3:], "NTFS    ") }), "ntfs-volume", "NTFS"},
		{"fat32", headWith(4096, func(h []byte) { copy(h[82:], "FAT32   ") }), "fat-volume", "FAT32"},
		{"exfat", headWith(4096, func(h []byte) { copy(h[3:], "EXFAT   ") }), "exfat-volume", "exFAT"},
		{"bitlocker", headWith(4096, func(h []byte) { copy(h[3:], "-FVE-FS-") }), "bitlocker-volume", "BitLocker"},
		{"luks", headWith(4096, func(h []byte) { copy(h[0:], "LUKS\xba\xbe") }), "luks-volume", "LUKS"},
		{"lvm", headWith(4096, func(h []byte) { copy(h[0x200:], "LABELONE") }), "lvm-volume", "LVM2"},
		{"md", headWith(8192, func(h []byte) { copy(h[0x1000:], []byte{0xFC, 0x4E, 0x2B, 0xA9}) }), "md-volume", "Linux mdraid"},
		{"xfs", headWith(4096, func(h []byte) { copy(h[0:], "XFSB") }), "xfs-volume", "XFS"},
		{"squashfs", headWith(4096, func(h []byte) { copy(h[0:], "hsqs") }), "squashfs-volume", "SquashFS"},
		{"apfs", headWith(4096, func(h []byte) { copy(h[32:], "NXSB") }), "apfs-volume", "APFS"},
		{"btrfs", headWith(btrfs+16, func(h []byte) { copy(h[btrfs:], "_BHRfS_M") }), "btrfs-volume", "Btrfs"},
		{"hfsplus", headWith(4096, func(h []byte) { copy(h[1024:], "H+") }), "hfs-volume", "HFS+"},
		{"ext", headWith(4096, func(h []byte) { copy(h[1080:], []byte{0x53, 0xEF}) }), "ext-volume", "ext2/3/4"},
		{"iso", headWith(0x8802, func(h []byte) { copy(h[0x8001:], "CD001") }), "iso-volume", "ISO 9660"},
		{"udf", headWith(0x8900, func(h []byte) {
			copy(h[0x8001:], "BEA01")
			copy(h[0x8801:], "NSR02")
		}), "udf-volume", "UDF"},
		{"minix", headWith(4096, func(h []byte) { copy(h[1024+16:], []byte{0x7F, 0x13}) }), "minix-volume", "Minix"},
		{"qnx6", headWith(8192+4, func(h []byte) { copy(h[8192:], []byte{0x22, 0x11, 0x19, 0x68}) }), "qnx6-volume", "QNX6"},
		{"ocfs2", headWith(8192, func(h []byte) { copy(h[1024:], "OCFSV2") }), "ocfs2-volume", "OCFS2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, label, ok := VolumeSignature(tc.head)
			if !ok || id != tc.id || label != tc.label {
				t.Fatalf("VolumeSignature = %q, %q, %v; want %q, %q, true", id, label, ok, tc.id, tc.label)
			}
		})
	}
}

func TestVolumeSignatureCoreStorage(t *testing.T) {
	head := make([]byte, 512)
	putLE32(head[4:], 0xFFFFFFFF)
	putLE16Sig(head, 8, 1)
	putLE16Sig(head, 10, 0x0010)
	copy(head[88:90], "CS")
	putLE32(head[90:], 1)
	putLE32(head[96:], 4096)
	putLE32(head[0:], foundation.CRC32CSeeded(0xFFFFFFFF, head[8:512]))

	id, label, ok := VolumeSignature(head)
	if !ok || id != "corestorage-volume" || label != "Apple CoreStorage" {
		t.Fatalf("VolumeSignature(CoreStorage) = %q, %q, %v", id, label, ok)
	}

	head[300] ^= 0xFF // outside the CRC? no: 300 is inside 8..512
	id, _, ok = VolumeSignature(head)
	if ok {
		t.Fatalf("VolumeSignature accepted a CoreStorage header with a broken CRC: %q", id)
	}
}

func TestVolumeSignatureJFFS2(t *testing.T) {
	head := make([]byte, 4096)
	head[0], head[1] = 0x85, 0x19
	putLE32(head[8:], foundation.CRC32(head[0:8]))
	if id, _, ok := VolumeSignature(head); !ok || id != "jffs2-volume" {
		t.Fatalf("VolumeSignature(JFFS2) = %q, %v", id, ok)
	}
}

func TestVolumeSignatureRejectsZeros(t *testing.T) {
	if id, label, ok := VolumeSignature(make([]byte, 64*1024)); ok {
		t.Fatalf("VolumeSignature(zeros) = %q, %q", id, label)
	}
	if _, _, ok := VolumeSignature(nil); ok {
		t.Fatal("VolumeSignature(nil) claimed a signature")
	}
}
