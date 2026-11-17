// Package probe identifies a volume's filesystem or encryption layer from the
// fixed signatures in its first sectors. It is the data layer's detection
// source of truth; it does not parse or open a volume.
package probe

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/filesystems/hammer2"
	"github.com/laenix/ewfgo/internal/data/filesystems/qnx6"
	"github.com/laenix/ewfgo/internal/data/filesystems/yaffs"
	"github.com/laenix/ewfgo/internal/data/filesystems/zfs"
	"github.com/laenix/ewfgo/internal/data/partition/corestorage"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Kind is a detected volume format.
type Kind uint8

const (
	None Kind = iota
	NTFS
	ReFS
	ExFAT
	FAT
	BitLocker
	APFS
	Ext
	XFS
	Btrfs
	HFSPlus
	HFSClassic
	F2FS
	SquashFS
	ISO9660
	UDF
	LUKS
	ZFS
	JFS
	ReiserFS
	LVM2
	MDRaid
	CoreStorage
	CramFS
	EROFS
	VMFS
	Minix
	SysV
	UFS
	HPFS
	GFS2
	NILFS2
	OCFS2
	BeFS
	UBIFS
	YAFFS
	JFFS2
	HAMMER2
	QNX6
)

// Label returns a human-readable format name.
func (k Kind) Label() string {
	switch k {
	case NTFS:
		return "NTFS"
	case ReFS:
		return "ReFS"
	case ExFAT:
		return "exFAT"
	case FAT:
		return "FAT"
	case BitLocker:
		return "BitLocker"
	case APFS:
		return "APFS"
	case Ext:
		return "ext2/3/4"
	case XFS:
		return "XFS"
	case Btrfs:
		return "Btrfs"
	case HFSPlus:
		return "HFS+"
	case HFSClassic:
		return "HFS"
	case F2FS:
		return "F2FS"
	case SquashFS:
		return "SquashFS"
	case ISO9660:
		return "ISO 9660"
	case UDF:
		return "UDF"
	case LUKS:
		return "LUKS"
	case ZFS:
		return "ZFS"
	case JFS:
		return "JFS"
	case ReiserFS:
		return "ReiserFS"
	case LVM2:
		return "LVM2"
	case MDRaid:
		return "Linux mdraid"
	case CoreStorage:
		return "Apple CoreStorage"
	case CramFS:
		return "CramFS"
	case EROFS:
		return "EROFS"
	case VMFS:
		return "VMFS"
	case Minix:
		return "Minix"
	case SysV:
		return "System V"
	case UFS:
		return "UFS"
	case HPFS:
		return "HPFS"
	case GFS2:
		return "GFS2"
	case NILFS2:
		return "NILFS2"
	case OCFS2:
		return "OCFS2"
	case BeFS:
		return "BeFS"
	case UBIFS:
		return "UBIFS"
	case YAFFS:
		return "YAFFS2"
	case JFFS2:
		return "JFFS2"
	case HAMMER2:
		return "HAMMER2"
	case QNX6:
		return "QNX6"
	default:
		return "unknown"
	}
}

// Encrypted reports whether the format is an encryption layer.
func (k Kind) Encrypted() bool { return k == BitLocker || k == LUKS || k == CoreStorage }

const (
	windowBytes = 68 * 1024
	// vmfsOffset is where the VMFS volume information block's magic lives.
	vmfsOffset = 0x100000
	vmfsMagic  = 0xC001D00D
)

// Detect reads the volume's signature window and returns the detected format.
func Detect(src source.ByteSource) (Kind, error) {
	if src.Len() < 512 {
		return None, nil
	}
	length := src.Len()
	if length > windowBytes {
		length = windowBytes
	}
	head, err := source.ReadVecAt(src, 0, length)
	if err != nil {
		return None, err
	}
	if kind := FromHead(head); kind != None {
		return kind, nil
	}
	// UFS alternate superblocks extend to 256 KiB.
	if src.Len() >= 256*1024+1376 {
		magic, err := source.ReadVecAt(src, 256*1024+1372, 4)
		if err != nil {
			return None, err
		}
		if ufsMagicAt(magic) {
			return UFS, nil
		}
	}
	// ZFS has no magic at the start of the vdev: its label sits at 0x4000 and
	// the embedded checksum must be verified, so the reader probes it.
	if matched, err := zfs.Detect(src); err != nil {
		return None, err
	} else if matched {
		return ZFS, nil
	}
	// YAFFS2 has no fixed signature; its tag/page geometry is probed last.
	if matched, err := yaffs.Detect(src); err == nil && matched {
		return YAFFS, nil
	}
	// VMFS puts its volume magic at 1 MiB, beyond the fast signature window.
	if src.Len() >= vmfsOffset+4 {
		magic, err := source.ReadVecAt(src, vmfsOffset, 4)
		if err != nil {
			return None, err
		}
		if binary.LittleEndian.Uint32(magic) == vmfsMagic {
			return VMFS, nil
		}
	}
	return None, nil
}

// ufsMagicAt reports a UFS1/UFS2 superblock magic in either byte order.
func ufsMagicAt(magic []byte) bool {
	if len(magic) < 4 {
		return false
	}
	little := binary.LittleEndian.Uint32(magic)
	big := binary.BigEndian.Uint32(magic)
	for _, candidate := range []uint32{little, big} {
		if candidate == 0x00011954 || candidate == 0x19540119 {
			return true
		}
	}
	return false
}

// FromHead identifies a format from an already-read head buffer.
func FromHead(head []byte) Kind {
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
	le32 := func(offset int) uint32 {
		if offset+4 > len(head) {
			return 0
		}
		return binary.LittleEndian.Uint32(head[offset:])
	}
	be32 := func(offset int) uint32 {
		if offset+4 > len(head) {
			return 0
		}
		return binary.BigEndian.Uint32(head[offset:])
	}

	// HAMMER2 volume headers live at zone 0 of a filesystem volume; the other
	// three copies are 2 GiB apart and are not scanned from the head window.
	if len(head) >= 8 {
		if magic := binary.LittleEndian.Uint64(head); magic == hammer2.Magic || magic == hammer2.MagicReversed {
			return HAMMER2
		}
	}
	if at(3, []byte("NTFS    ")) {
		return NTFS
	}
	if at(3, []byte("ReFS    ")) {
		return ReFS
	}
	if at(3, []byte("EXFAT   ")) {
		return ExFAT
	}
	if at(3, []byte("-FVE-FS-")) {
		return BitLocker
	}
	if at(82, []byte("FAT32   ")) || at(54, []byte("FAT")) {
		return FAT
	}
	if at(32, []byte("NXSB")) {
		return APFS
	}
	if len(head) >= 1024+0x3A && binary.LittleEndian.Uint16(head[1024+0x38:]) == 0xEF53 {
		return Ext
	}
	if at(0, []byte("XFSB")) {
		return XFS
	}
	if at(64*1024+64, []byte("_BHRfS_M")) {
		return Btrfs
	}
	if v := be32(1024); v == 0x482B0004 || v == 0x48580005 {
		return HFSPlus
	}
	if at(1024, []byte("BD")) {
		return HFSClassic
	}
	if le32(1024) == 0xF2F52010 {
		return F2FS
	}
	if le32(0) == 0x28CD3D45 {
		return CramFS
	}
	if len(head) >= 1050 {
		switch binary.LittleEndian.Uint16(head[1024+16:]) {
		case 0x137F, 0x138F, 0x2468, 0x2478:
			return Minix
		}
		if binary.LittleEndian.Uint16(head[1024+24:]) == 0x4D5A {
			return Minix
		}
	}
	if len(head) >= 64*1024+4 && binary.BigEndian.Uint32(head[64*1024:]) == 0x01161970 {
		return GFS2
	}
	for _, offset := range []int{1372, 8192 + 1372, 64*1024 + 1372} {
		if offset+4 <= len(head) && ufsMagicAt(head[offset:offset+4]) {
			return UFS
		}
	}
	if len(head) >= 0x2000+8 {
		if binary.LittleEndian.Uint32(head[0x2000:]) == 0xF995E849 &&
			binary.LittleEndian.Uint32(head[0x2000+4:]) == 0xFA53E9C5 {
			return HPFS
		}
	}
	if len(head) >= 1024+8 && binary.LittleEndian.Uint16(head[1024+6:]) == 0x3434 {
		return NILFS2
	}
	for _, offset := range []int{1024, 2048, 4096, 8192} {
		if offset+6 <= len(head) && string(head[offset:offset+6]) == "OCFSV2" {
			return OCFS2
		}
	}
	if len(head) >= 512+116 {
		if binary.LittleEndian.Uint32(head[512:]) == 0x42465331 &&
			binary.LittleEndian.Uint32(head[512+4:]) == 0xDD121031 &&
			binary.LittleEndian.Uint32(head[512+112:]) == 0x15B6830E {
			return BeFS
		}
	}
	if len(head) >= 2 && binary.LittleEndian.Uint16(head) == 0x1985 {
		return JFFS2
	}
	if len(head) >= 4 && (binary.LittleEndian.Uint32(head) == 0x06101831 ||
		string(head[:4]) == "UBI#") {
		return UBIFS
	}
	if len(head) >= 2044 {
		if binary.LittleEndian.Uint32(head[1016:]) == 0xFD187E20 ||
			binary.BigEndian.Uint32(head[1016:]) == 0xFD187E20 {
			return SysV
		}
		if binary.LittleEndian.Uint32(head[2040:]) == 0x002B5544 ||
			binary.BigEndian.Uint32(head[2040:]) == 0x002B5544 {
			return SysV
		}
		if at(996, []byte("noname")) && at(1002, []byte("nopack")) {
			return SysV
		}
	}
	if le32(1024) == 0xE0F5E1E2 {
		return EROFS
	}
	if at(0, []byte("hsqs")) {
		return SquashFS
	}
	if at(0x8001, []byte("CD001")) {
		return ISO9660
	}
	if at(0x8001, []byte("BEA01")) && (at(0x8801, []byte("NSR02")) || at(0x8801, []byte("NSR03"))) {
		return UDF
	}
	if at(0, []byte("LUKS\xba\xbe")) {
		return LUKS
	}
	// QNX6 superblocks are at 0x2000 on normal images and at 0 on Audi MMI
	// images; either byte order is valid.
	for _, offset := range []int{0, 0x2000} {
		if le32(offset) == qnx6.Magic || be32(offset) == qnx6.Magic {
			return QNX6
		}
	}
	if at(0x8000, []byte("JFS1")) {
		return JFS
	}
	if at(8*1024+52, []byte("ReIsErFs")) || at(8*1024+52, []byte("ReIsEr2Fs")) || at(8*1024+52, []byte("ReIsEr3Fs")) {
		return ReiserFS
	}
	if at(0x200, []byte("LABELONE")) {
		return LVM2
	}
	if at(0x1000, []byte{0xFC, 0x4E, 0x2B, 0xA9}) {
		return MDRaid
	}
	if corestorage.LooksLikeVolumeHeader(head) {
		return CoreStorage
	}
	return None
}
