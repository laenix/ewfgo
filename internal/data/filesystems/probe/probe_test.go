package probe

import (
	"encoding/binary"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func head(size int, fn func([]byte)) []byte {
	bytes := make([]byte, size)
	fn(bytes)
	return bytes
}

func TestFromHead(t *testing.T) {
	le32 := func(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	be32 := func(b []byte, at int, v uint32) { binary.BigEndian.PutUint32(b[at:], v) }
	cases := []struct {
		name string
		head []byte
		want Kind
	}{
		{"ntfs", head(512, func(b []byte) { copy(b[3:], "NTFS    ") }), NTFS},
		{"refs", head(512, func(b []byte) { copy(b[3:], "ReFS    ") }), ReFS},
		{"exfat", head(512, func(b []byte) { copy(b[3:], "EXFAT   ") }), ExFAT},
		{"bitlocker", head(512, func(b []byte) { copy(b[3:], "-FVE-FS-") }), BitLocker},
		{"fat32", head(512, func(b []byte) { copy(b[82:], "FAT32   ") }), FAT},
		{"apfs", head(512, func(b []byte) { copy(b[32:], "NXSB") }), APFS},
		{"ext", head(2048, func(b []byte) { binary.LittleEndian.PutUint16(b[1024+0x38:], 0xEF53) }), Ext},
		{"xfs", head(512, func(b []byte) { copy(b, "XFSB") }), XFS},
		{"btrfs", head(66*1024, func(b []byte) { copy(b[64*1024+64:], "_BHRfS_M") }), Btrfs},
		{"hfsplus", head(2048, func(b []byte) { be32(b, 1024, 0x482B0004) }), HFSPlus},
		{"hfsclassic", head(2048, func(b []byte) { copy(b[1024:], "BD") }), HFSClassic},
		{"f2fs", head(2048, func(b []byte) { le32(b, 1024, 0xF2F52010) }), F2FS},
		{"cramfs", head(512, func(b []byte) { le32(b, 0, 0x28CD3D45) }), CramFS},
		{"erofs", head(2048, func(b []byte) { le32(b, 1024, 0xE0F5E1E2) }), EROFS},
		{"minix", head(2048, func(b []byte) { binary.LittleEndian.PutUint16(b[1040:], 0x137F) }), Minix},
		{"minix3", head(2048, func(b []byte) { binary.LittleEndian.PutUint16(b[1048:], 0x4D5A) }), Minix},
		{"sysv", head(2048, func(b []byte) { binary.LittleEndian.PutUint32(b[1016:], 0xFD187E20) }), SysV},
		{"xenix", head(2048, func(b []byte) { binary.LittleEndian.PutUint32(b[2040:], 0x002B5544) }), SysV},
		{"ufs1", head(16*1024, func(b []byte) { binary.LittleEndian.PutUint32(b[8192+1372:], 0x00011954) }), UFS},
		{"ufs2be", head(80*1024, func(b []byte) { binary.BigEndian.PutUint32(b[64*1024+1372:], 0x19540119) }), UFS},
		{"hpfs", head(16*1024, func(b []byte) {
			binary.LittleEndian.PutUint32(b[0x2000:], 0xF995E849)
			binary.LittleEndian.PutUint32(b[0x2004:], 0xFA53E9C5)
		}), HPFS},
		{"gfs2", head(80*1024, func(b []byte) { binary.BigEndian.PutUint32(b[64*1024:], 0x01161970) }), GFS2},
		{"nilfs2", head(2048, func(b []byte) { binary.LittleEndian.PutUint16(b[1024+6:], 0x3434) }), NILFS2},
		{"ocfs2", head(16*1024, func(b []byte) { copy(b[8192:], "OCFSV2") }), OCFS2},
		{"befs", head(2048, func(b []byte) {
			binary.LittleEndian.PutUint32(b[512:], 0x42465331)
			binary.LittleEndian.PutUint32(b[512+4:], 0xDD121031)
			binary.LittleEndian.PutUint32(b[512+112:], 0x15B6830E)
		}), BeFS},
		{"ubifs", head(512, func(b []byte) { binary.LittleEndian.PutUint32(b[0:], 0x06101831) }), UBIFS},
		{"jffs2", head(512, func(b []byte) { binary.LittleEndian.PutUint16(b[0:], 0x1985) }), JFFS2},
		{"hammer2", head(512, func(b []byte) { binary.LittleEndian.PutUint64(b[0:], 0x48414d3205172011) }), HAMMER2},
		{"hammer2abo", head(512, func(b []byte) { binary.LittleEndian.PutUint64(b[0:], 0x11201705324d4148) }), HAMMER2},
		{"qnx6", head(16*1024, func(b []byte) { binary.LittleEndian.PutUint32(b[0x2000:], 0x68191122) }), QNX6},
		{"qnx6be", head(16*1024, func(b []byte) { binary.BigEndian.PutUint32(b[0x2000:], 0x68191122) }), QNX6},
		{"qnx6mmi", head(512, func(b []byte) { binary.BigEndian.PutUint32(b[0:], 0x68191122) }), QNX6},
		{"squashfs", head(512, func(b []byte) { copy(b, "hsqs") }), SquashFS},
		{"iso", head(0x8802, func(b []byte) { copy(b[0x8001:], "CD001") }), ISO9660},
		{"udf", head(0x8900, func(b []byte) {
			copy(b[0x8001:], "BEA01")
			copy(b[0x8801:], "NSR03")
		}), UDF},
		{"luks", head(512, func(b []byte) { copy(b, "LUKS\xba\xbe") }), LUKS},
		{"jfs", head(0x8004, func(b []byte) { copy(b[0x8000:], "JFS1") }), JFS},
		{"reiserfs", head(8*1024+64, func(b []byte) { copy(b[8*1024+52:], "ReIsEr2Fs") }), ReiserFS},
		{"lvm", head(4096, func(b []byte) { copy(b[0x200:], "LABELONE") }), LVM2},
		{"mdraid", head(8192, func(b []byte) { copy(b[0x1000:], []byte{0xFC, 0x4E, 0x2B, 0xA9}) }), MDRaid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FromHead(tc.head); got != tc.want {
				t.Fatalf("FromHead = %v, want %v", got, tc.want)
			}
		})
	}
	if got := FromHead(make([]byte, 4096)); got != None {
		t.Fatalf("FromHead(zeros) = %v", got)
	}
}

func TestDetect(t *testing.T) {
	bytes := head(2048, func(b []byte) { binary.LittleEndian.PutUint32(b[1024:], 0xF2F52010) })
	got, err := Detect(source.NewMemorySource(1, bytes))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if got != F2FS {
		t.Fatalf("Detect = %v, want F2FS", got)
	}
	vmfs := make([]byte, 0x100004)
	binary.LittleEndian.PutUint32(vmfs[0x100000:], 0xC001D00D)
	if got, err := Detect(source.NewMemorySource(1, vmfs)); err != nil || got != VMFS {
		t.Fatalf("Detect(VMFS) = %v, %v", got, err)
	}

	if !BitLocker.Encrypted() || !LUKS.Encrypted() || NTFS.Encrypted() {
		t.Fatal("Encrypted classification is wrong")
	}
}
