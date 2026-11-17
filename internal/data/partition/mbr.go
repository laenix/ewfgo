package partition

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	mbrSize        = 512
	mbrEntryOffset = 446
	mbrEntrySize   = 16
	maxEBR         = 128
)

// ParseMBR parses the DOS partition table at LBA 0, then walks every extended
// boot record chain it finds. It rejects a table whose partitions run past the
// source instead of clamping them.
func ParseMBR(src source.ByteSource) (*MBRTable, error) {
	secSize, err := sectorSize(src)
	if err != nil {
		return nil, err
	}
	totalSectors := src.Len() / secSize

	mbr, err := source.ReadVecAt(src, 0, mbrSize)
	if err != nil {
		return nil, err
	}
	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		return nil, invalid("missing 0x55AA MBR signature")
	}

	table := &MBRTable{DiskSignature: le32(mbr[440:444])}
	extendedBases := make([]uint64, 0, 1)

	for i := 0; i < 4; i++ {
		at := mbrEntryOffset + i*mbrEntrySize
		entry := mbr[at : at+mbrEntrySize]
		typeID := entry[4]
		startLBA := uint64(le32(entry[8:12]))
		sectors := uint64(le32(entry[12:16]))
		if typeID == 0 || sectors == 0 {
			continue
		}

		end := startLBA + sectors
		if end < startLBA {
			return nil, invalid("partition %d end overflows u64", i)
		}
		if end > totalSectors {
			return nil, invalid("partition %d ends at sector %d, disk has %d", i, end, totalSectors)
		}

		offset, ok := checkedMul(startLBA, secSize)
		if !ok {
			return nil, invalid("partition %d byte offset overflows u64", i)
		}
		length, ok := checkedMul(sectors, secSize)
		if !ok {
			return nil, invalid("partition %d byte length overflows u64", i)
		}

		isContainer := typeID == 0x05 || typeID == 0x0F || typeID == 0x85
		table.Partitions = append(table.Partitions, Partition{
			Index:       len(table.Partitions),
			Kind:        KindMBR,
			Bootable:    entry[0]&0x80 != 0,
			TypeID:      typeID,
			Name:        TypeName(typeID),
			StartLBA:    startLBA,
			SectorCount: sectors,
			Offset:      offset,
			Len:         length,
			IsContainer: isContainer,
		})
		if isContainer {
			extendedBases = append(extendedBases, startLBA)
		}
	}

	for _, base := range extendedBases {
		if err := parseEBRChain(src, base, totalSectors, secSize, table); err != nil {
			return nil, err
		}
	}

	return table, nil
}

func parseEBRChain(src source.ByteSource, baseLBA, totalSectors, secSize uint64, table *MBRTable) error {
	ebrLBA := baseLBA
	seen := make(map[uint64]struct{})

	for i := 0; i < maxEBR; i++ {
		if _, dup := seen[ebrLBA]; dup {
			return invalid("EBR loop at sector %d", ebrLBA)
		}
		seen[ebrLBA] = struct{}{}
		if ebrLBA >= totalSectors {
			return invalid("EBR sector %d is beyond disk end %d", ebrLBA, totalSectors)
		}

		ebrOffset, ok := checkedMul(ebrLBA, secSize)
		if !ok {
			return invalid("EBR byte offset overflows u64")
		}
		ebr, err := source.ReadVecAt(src, ebrOffset, mbrSize)
		if err != nil {
			return err
		}
		if ebr[510] != 0x55 || ebr[511] != 0xAA {
			return invalid("missing 0x55AA signature in EBR at sector %d", ebrLBA)
		}

		first := ebr[mbrEntryOffset : mbrEntryOffset+mbrEntrySize]
		if typeID := first[4]; typeID != 0 {
			relStart := uint64(le32(first[8:12]))
			sectors := uint64(le32(first[12:16]))
			if sectors != 0 {
				startLBA := ebrLBA + relStart
				if startLBA < ebrLBA {
					return invalid("logical partition LBA overflows u64")
				}
				end := startLBA + sectors
				if end < startLBA {
					return invalid("logical partition end overflows u64")
				}
				if end > totalSectors {
					return invalid("logical partition ends at sector %d, disk has %d", end, totalSectors)
				}
				offset, ok := checkedMul(startLBA, secSize)
				if !ok {
					return invalid("logical partition byte offset overflows u64")
				}
				length, ok := checkedMul(sectors, secSize)
				if !ok {
					return invalid("logical partition byte length overflows u64")
				}
				table.Partitions = append(table.Partitions, Partition{
					Index:       len(table.Partitions),
					Kind:        KindMBR,
					Bootable:    first[0]&0x80 != 0,
					TypeID:      typeID,
					Name:        TypeName(typeID),
					StartLBA:    startLBA,
					SectorCount: sectors,
					Offset:      offset,
					Len:         length,
					IsContainer: false,
				})
			}
		}

		second := ebr[mbrEntryOffset+mbrEntrySize : mbrEntryOffset+2*mbrEntrySize]
		linkType := second[4]
		relNext := uint64(le32(second[8:12]))
		if linkType == 0 || relNext == 0 {
			return nil
		}
		ebrLBA = baseLBA + relNext
		if ebrLBA < baseLBA {
			return invalid("next EBR LBA overflows u64")
		}
	}

	return invalid("EBR chain exceeds %d entries", maxEBR)
}

// TypeName returns the conventional name of an MBR partition type, or "" when
// the type is unknown. It is a fact about the on-disk type byte, not a claim
// that the partition's filesystem has been parsed.
func TypeName(id uint8) string { return mbrTypeNames[id] }

var mbrTypeNames = map[byte]string{
	0x01: "FAT12",
	0x04: "FAT16 (<32M)",
	0x05: "Extended (CHS)",
	0x06: "FAT16",
	0x07: "NTFS/exFAT",
	0x0B: "FAT32 (CHS)",
	0x0C: "FAT32 (LBA)",
	0x0E: "FAT16 (LBA)",
	0x0F: "Extended (LBA)",
	0x11: "Hidden FAT12",
	0x12: "Compaq diagnostics",
	0x14: "Hidden FAT16",
	0x16: "Hidden FAT16",
	0x17: "Hidden NTFS",
	0x1B: "Hidden FAT32",
	0x1C: "Hidden FAT32 (LBA)",
	0x1E: "Hidden FAT16 (LBA)",
	0x27: "Windows RE",
	0x42: "Windows LDM",
	0x4D: "QNX4",
	0x4E: "QNX4",
	0x4F: "QNX4",
	0x50: "OnTrack DM",
	0x51: "OnTrack DM6",
	0x52: "CP/M",
	0x53: "OnTrack DM6 Aux",
	0x54: "OnTrack DM6 Aux",
	0x55: "EZ-Drive",
	0x56: "Golden Bow",
	0x5C: "Priam",
	0x61: "SpeedStor",
	0x63: "Unix SysV",
	0x64: "Novell Netware",
	0x65: "Novell Netware",
	0x70: "DiskSecure",
	0x75: "PC/IX",
	0x80: "Old Minix",
	0x81: "Minix/Linux",
	0x82: "Linux swap",
	0x83: "Linux",
	0x84: "OS/2 hidden",
	0x85: "Linux extended",
	0x86: "NTFS volume set",
	0x87: "NTFS volume set",
	0x88: "Linux plaintext",
	0x8E: "Linux LVM",
	0x93: "Amoeba",
	0x94: "Amoeba BBT",
	0x9F: "BSD/OS",
	0xA0: "IBM Thinkpad",
	0xA5: "FreeBSD",
	0xA6: "OpenBSD",
	0xA7: "NeXTSTEP",
	0xA8: "macOS UFS",
	0xA9: "NetBSD",
	0xAB: "macOS boot",
	0xAF: "HFS/HFS+",
	0xB7: "BSDI",
	0xB8: "BSDI swap",
	0xBB: "Boot Wizard hidden",
	0xBE: "Solaris boot",
	0xBF: "Solaris",
	0xC1: "DRDOS FAT12",
	0xC4: "DRDOS FAT16",
	0xC6: "DRDOS FAT16",
	0xC7: "Syrinx",
	0xDA: "Non-FS data",
	0xDB: "CP/M",
	0xDE: "Dell utility",
	0xDF: "BootIt",
	0xE1: "DOS access",
	0xE3: "DOS R/O",
	0xE4: "SpeedStor",
	0xEB: "BeOS",
	0xEE: "GPT protective",
	0xEF: "EFI System",
	0xF0: "Linux/PA-RISC boot",
	0xF1: "SpeedStor",
	0xF2: "DOS secondary",
	0xF4: "SpeedStor",
	0xFB: "VMware VMFS",
	0xFC: "VMware swap",
	0xFD: "Linux RAID",
	0xFE: "LANstep",
	0xFF: "BBT",
}
