package partition

import (
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/partition/corestorage"
)

// VolumeSignature recognises the filesystem or encryption layer at the start
// of a volume from its fixed magic bytes. It is the fallback for a dd of one
// volume that has no partition table, and it lets a caller name a volume it
// has no parser for instead of reporting a generic failure.
//
// head must hold at least the first 32 KiB to recognize ISO 9660/UDF and 64
// KiB + 64 for Btrfs; every other signature is inside the first 4 KiB.
func VolumeSignature(head []byte) (id, label string, ok bool) {
	at := func(offset int, bytes []byte) bool {
		if offset < 0 || offset+len(bytes) > len(head) {
			return false
		}
		for i, b := range bytes {
			if head[offset+i] != b {
				return false
			}
		}
		return true
	}
	atU32LE := func(offset int, value uint32) bool {
		return at(offset, []byte{byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)})
	}
	// Volume boot records.
	if at(3, []byte("NTFS    ")) {
		return "ntfs-volume", "NTFS", true
	}
	if at(3, []byte("ReFS    ")) {
		return "refs-volume", "ReFS", true
	}
	if at(3, []byte("EXFAT   ")) {
		return "exfat-volume", "exFAT", true
	}
	if at(3, []byte("-FVE-FS-")) {
		return "bitlocker-volume", "BitLocker", true
	}
	if at(82, []byte("FAT32   ")) {
		return "fat-volume", "FAT32", true
	}
	if at(54, []byte("FAT")) {
		return "fat-volume", "FAT", true
	}

	// Encryption and volume managers.
	if at(0, []byte("LUKS\xba\xbe")) {
		return "luks-volume", "LUKS", true
	}
	if at(0x200, []byte("LABELONE")) {
		return "lvm-volume", "LVM2", true
	}
	if at(0x1000, []byte{0xFC, 0x4E, 0x2B, 0xA9}) {
		return "md-volume", "Linux mdraid", true
	}
	if corestorage.LooksLikeVolumeHeader(head) {
		return "corestorage-volume", "Apple CoreStorage", true
	}
	if at(0, []byte("UBI#")) {
		return "ubi-volume", "UBI", true
	}
	if at(0, []byte{0x31, 0x18, 0x10, 0x06}) {
		return "ubifs-volume", "UBIFS", true
	}
	if len(head) >= 12 && head[0] == 0x85 && head[1] == 0x19 {
		stored := le32(head[8:12])
		if foundation.CRC32(head[0:8]) == stored {
			return "jffs2-volume", "JFFS2", true
		}
	}

	// Filesystems with a superblock at a fixed offset.
	if at(0, []byte("XFSB")) {
		return "xfs-volume", "XFS", true
	}
	if at(0, []byte("hsqs")) {
		return "squashfs-volume", "SquashFS", true
	}
	if at(0, []byte{0x45, 0x3D, 0xCD, 0x28}) || at(512, []byte{0x45, 0x3D, 0xCD, 0x28}) {
		return "cramfs-volume", "CramFS", true
	}
	if at(32, []byte("NXSB")) {
		return "apfs-volume", "APFS", true
	}
	if at(64*1024+64, []byte("_BHRfS_M")) {
		return "btrfs-volume", "Btrfs", true
	}
	if at(1024, []byte("H+")) || at(1024, []byte("HX")) {
		return "hfs-volume", "HFS+", true
	}
	if at(1024, []byte("BD")) {
		return "hfs-classic-volume", "HFS", true
	}
	if at(8*1024+52, []byte("ReIsErFs")) ||
		at(8*1024+52, []byte("ReIsEr2Fs")) ||
		at(8*1024+52, []byte("ReIsEr3Fs")) {
		return "reiserfs-volume", "ReiserFS", true
	}
	if at(0x36, []byte("HPFS")) &&
		atU32LE(0x2000, 0xF995E849) &&
		atU32LE(0x2004, 0xFA53E9C5) {
		return "hpfs-volume", "HPFS", true
	}
	if at(0x8000, []byte("JFS1")) {
		return "jfs-volume", "JFS", true
	}

	// Minix V1/V2 and V3 magics, in either byte order.
	for _, magic := range [][2]byte{
		{0x7F, 0x13}, {0x8F, 0x13}, {0x68, 0x24}, {0x78, 0x24},
		{0x13, 0x7F}, {0x13, 0x8F}, {0x24, 0x68}, {0x24, 0x78},
	} {
		if at(1024+16, magic[:]) {
			return "minix-volume", "Minix", true
		}
	}
	if at(1024+24, []byte{0x5A, 0x4D}) || at(1024+24, []byte{0x4D, 0x5A}) {
		return "minix-volume", "Minix", true
	}
	if at(512+32, []byte{0x31, 0x53, 0x46, 0x42}) || at(512+32, []byte{0x42, 0x46, 0x53, 0x31}) {
		return "befs-volume", "BeFS", true
	}
	for _, blockSize := range []int{512, 1024, 2048, 4096} {
		if at(2*blockSize, []byte("OCFSV2")) || at(2*blockSize, []byte("2VSFCO")) {
			return "ocfs2-volume", "OCFS2", true
		}
	}
	if (at(65536, []byte{0x01, 0x16, 0x19, 0x70}) || at(65536, []byte{0x70, 0x19, 0x16, 0x01})) &&
		at(65536+4, []byte{0x00, 0x00, 0x00, 0x01}) &&
		at(65536+0x10, []byte{0x00, 0x00, 0x00, 100}) {
		return "gfs2-volume", "GFS2", true
	}
	if at(0, []byte{0x22, 0x11, 0x19, 0x68}) || at(0, []byte{0x68, 0x19, 0x11, 0x22}) ||
		at(8192, []byte{0x22, 0x11, 0x19, 0x68}) || at(8192, []byte{0x68, 0x19, 0x11, 0x22}) {
		return "qnx6-volume", "QNX6", true
	}
	if at(512+504, []byte{0x20, 0x7E, 0x18, 0xFD}) || at(512+504, []byte{0xFD, 0x18, 0x7E, 0x20}) {
		return "sysv-volume", "System V", true
	}
	if at(1024+1016, []byte{0x44, 0x55, 0x2B, 0x00}) || at(1024+1016, []byte{0x00, 0x2B, 0x55, 0x44}) {
		return "sysv-volume", "Xenix", true
	}
	if at(1080, []byte{0x53, 0xEF}) {
		return "ext-volume", "ext2/3/4", true
	}
	if at(9564, []byte{0x54, 0x19, 0x01, 0x00}) || at(9564, []byte{0x00, 0x01, 0x19, 0x54}) {
		return "ufs-volume", "UFS1", true
	}
	if at(66908, []byte{0x19, 0x01, 0x54, 0x19}) || at(66908, []byte{0x19, 0x54, 0x01, 0x19}) {
		return "ufs-volume", "UFS2", true
	}
	if atU32LE(1024, 0xF2F52010) {
		return "f2fs-volume", "F2FS", true
	}
	if atU32LE(1024, 0xE0F5E1E2) {
		return "erofs-volume", "EROFS", true
	}

	// Optical media.
	if at(0x8001, []byte("CD001")) {
		return "iso-volume", "ISO 9660", true
	}
	if at(0x8001, []byte("BEA01")) &&
		(at(0x8801, []byte("NSR02")) || at(0x8801, []byte("NSR03"))) {
		return "udf-volume", "UDF", true
	}

	return "", "", false
}
