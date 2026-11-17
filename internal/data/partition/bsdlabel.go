package partition

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// BSD disklabels: the FreeBSD, OpenBSD, NetBSD and DragonFly partition table.
// A label lives in the second sector (byte 512 on 512-byte media, byte 4096 on
// 4 KiB media) and records up to 22 entries named a..p.
//
// Byte order is decided by d_magic and confirmed by d_magic2 at offset 132.
// Four matching bytes alone occur inside volume data, so nothing is claimed
// unless both copies agree. d_checksum is a plain XOR of 16-bit words; a
// mismatch is reported but the label is still read, because it may be the only
// layout description on the disk.

// LabelMagic is DISKMAGIC from <sys/sys/disklabel.h>.
const LabelMagic = uint32(0x82564557)

// DiskLabel64Magic is DragonFly's unrelated 64-bit label magic.
const DiskLabel64Magic = uint32(0xC4464C59)

// A whole-disk label is probed at these byte offsets, in order.
var LabelOffsets = []uint64{512, 4096}

const (
	// MaxPartitions is the most entries a classic label can hold.
	MaxPartitions = 22
	// partitionLetters is a..p.
	partitionLetters = 16
	// probeBytes is d_magic plus the repeated d_magic2 at offset 132.
	probeBytes = 136
)

const (
	dMagic       = 0
	dTypeName    = 8
	dPackName    = 24
	dSecSize     = 40
	dVersion     = 114
	dMagic2      = 132
	dChecksum    = 136
	dNPartitions = 138
	dPartitions  = 148
)

const (
	pSize          = 0
	pOffset        = 4
	pOffsetHigh    = 8
	pSizeHigh      = 10
	pFSType        = 12
	partitionBytes = 16
)

const version48Bit = 1

// ByteOrder is the byte order a label is stored in, decided by its magic.
type ByteOrder uint8

const (
	// LittleEndian is the usual FreeBSD/x86 label.
	LittleEndian ByteOrder = iota
	// BigEndian is an OpenBSD/NetBSD label on a big-endian port.
	BigEndian
)

// Label returns "little-endian" or "big-endian".
func (o ByteOrder) Label() string {
	if o == BigEndian {
		return "big-endian"
	}
	return "little-endian"
}

// U16 reads a 16-bit word in the label's byte order.
func (o ByteOrder) U16(b []byte, off int) uint16 {
	if o == BigEndian {
		return be16(b[off:])
	}
	return le16(b[off:])
}

// U32 reads a 32-bit word in the label's byte order.
func (o ByteOrder) U32(b []byte, off int) uint32 {
	if o == BigEndian {
		return be32(b[off:])
	}
	return le32(b[off:])
}

// ChecksumStatus is the result of the dkcksum() check. A mismatch is reported,
// never fatal.
type ChecksumStatus struct {
	// Verified is true when the stored word equals the XOR recomputed without it.
	Verified bool
	// Stored is the value on disk.
	Stored uint16
	// Computed is the value the stored word would need for the label to verify.
	Computed uint16
}

// Label returns "verified" or "mismatch".
func (c ChecksumStatus) Label() string {
	if c.Verified {
		return "verified"
	}
	return "mismatch"
}

// BsdDisklabel is a parsed BSD disklabel and the partitions it describes.
type BsdDisklabel struct {
	// LabelBlock is the byte offset at which the label was found.
	LabelBlock uint64
	ByteOrder  ByteOrder
	// SectorSize is d_secsize: the unit partition offsets and lengths use.
	SectorSize uint32
	// Version is 0 for the classic label, 1 for OpenBSD 48-bit addressing.
	Version uint16
	// DiskType is d_typename, trimmed.
	DiskType string
	// PackName is d_packname, trimmed.
	PackName string
	// NPartitions is d_npartitions, including unused entries.
	NPartitions uint16
	Checksum    ChecksumStatus
	// Skipped counts declared entries that are not partitions.
	Skipped    int
	Partitions []Partition
}

// ParseBSD parses a whole-disk BSD disklabel.
//
// A nil label with a nil error means neither label position holds a confirmed
// label. Once both magic copies agree, a structurally broken label is an error.
func ParseBSD(src source.ByteSource) (*BsdDisklabel, error) {
	if magic, err := readMagic(src, 512); err != nil {
		return nil, err
	} else if magic != nil && isDiskLabel64(magic) {
		return nil, unsupportedDiskLabel64()
	}

	for _, base := range LabelOffsets {
		magic, err := readMagic(src, base)
		if err != nil {
			return nil, err
		}
		if magic == nil {
			continue
		}
		order, ok := magicOrder(magic)
		if !ok {
			continue
		}
		if base+probeBytes > src.Len() {
			return nil, invalid("disklabel at byte %d is truncated: d_magic is present but the source ends at byte %d",
				base, src.Len())
		}
		probe, err := source.ReadVecAt(src, base, probeBytes)
		if err != nil {
			return nil, err
		}
		if order.U32(probe, dMagic2) != LabelMagic {
			// The four magic bytes occur inside volume data; without the
			// repeated copy at offset 132 this is not a label.
			continue
		}
		return ParseBSDAt(src, base)
	}
	return nil, nil
}

// ParseBSDAt parses the label beginning at base. Partition offsets are relative
// to the start of src, exactly as the label stores them.
func ParseBSDAt(src source.ByteSource, base uint64) (*BsdDisklabel, error) {
	headerEnd := base + dPartitions
	if headerEnd < base || headerEnd > src.Len() {
		return nil, invalid("disklabel at byte %d is truncated: its %d-byte header does not fit in %d bytes",
			base, dPartitions, src.Len())
	}

	header, err := source.ReadVecAt(src, base, dPartitions)
	if err != nil {
		return nil, err
	}
	if isDiskLabel64(header[dMagic : dMagic+4]) {
		return nil, unsupportedDiskLabel64()
	}
	order, ok := magicOrder(header[dMagic : dMagic+4])
	if !ok {
		return nil, invalid("no BSD disklabel magic 0x%08X at byte %d", LabelMagic, base)
	}
	if order.U32(header, dMagic2) != LabelMagic {
		return nil, invalid("disklabel at byte %d has d_magic but d_magic2 at offset %d does not repeat it",
			base, dMagic2)
	}

	secSize := order.U32(header, dSecSize)
	if secSize < 512 || secSize&(secSize-1) != 0 {
		return nil, invalid("disklabel at byte %d declares d_secsize %d: not a power-of-two sector size of at least 512 bytes",
			base, secSize)
	}

	version := order.U16(header, dVersion)
	if version > version48Bit {
		return nil, fmt.Errorf("%w: BSD disklabel at byte %d declares d_version %d; only version 0 (32-bit) and version 1 (OpenBSD 48-bit addressing) are defined",
			ErrUnsupported, base, version)
	}

	npartitions := order.U16(header, dNPartitions)
	entries := int(npartitions)
	if entries > MaxPartitions {
		return nil, invalid("disklabel at byte %d declares %d partitions; at most %d fit a classic label (OpenBSD's 64-entry extension is not read)",
			base, entries, MaxPartitions)
	}

	tableLen := dPartitions + entries*partitionBytes
	if base+uint64(tableLen) > src.Len() {
		return nil, invalid("disklabel at byte %d is truncated: its %d-entry partition array ends at byte %d but the source ends at byte %d",
			base, entries, base+uint64(tableLen), src.Len())
	}
	table, err := source.ReadVecAt(src, base, uint64(tableLen))
	if err != nil {
		return nil, err
	}

	// dkcksum(): XOR of the 16-bit words through the last declared entry. The
	// stored word itself is inside the range, so the value the writer would
	// have stored is the XOR with that word taken back out.
	stored := order.U16(table, dChecksum)
	computed := checksumWords(table[:tableLen], order) ^ stored
	checksum := ChecksumStatus{Verified: computed == stored, Stored: stored, Computed: computed}

	totalSectors := src.Len() / uint64(secSize)
	partitions := make([]Partition, 0, entries)
	skipped := 0
	for index := 0; index < entries; index++ {
		at := dPartitions + index*partitionBytes
		entry := table[at : at+partitionBytes]
		fstype := entry[pFSType]
		startLBA, sectorCount := bsdEntryGeometry(entry, order, version)

		if fstype == 0 || sectorCount == 0 {
			skipped++
			continue
		}

		label := bsdEntryLabel(index, fstype)
		description := bsdEntryDescription(index, fstype)
		end := startLBA + sectorCount
		if end < startLBA {
			return nil, invalid("%s end overflows the 64-bit sector number", description)
		}
		if end > totalSectors {
			return nil, invalid("%s ends at sector %d, the disk has %d sectors of %d bytes",
				description, end, totalSectors, secSize)
		}

		offset, ok := checkedMul(startLBA, uint64(secSize))
		if !ok {
			return nil, invalid("%s byte offset overflows u64", description)
		}
		length, ok := checkedMul(sectorCount, uint64(secSize))
		if !ok {
			return nil, invalid("%s byte length overflows u64", description)
		}

		partitions = append(partitions, Partition{
			Index:       len(partitions),
			Kind:        KindBSD,
			TypeID:      fstype,
			TypeGUID:    label,
			Name:        label,
			StartLBA:    startLBA,
			SectorCount: sectorCount,
			Offset:      offset,
			Len:         length,
		})
	}

	return &BsdDisklabel{
		LabelBlock:  base,
		ByteOrder:   order,
		SectorSize:  secSize,
		Version:     version,
		DiskType:    fixedString(header, dTypeName, 16),
		PackName:    fixedString(header, dPackName, 16),
		NPartitions: npartitions,
		Checksum:    checksum,
		Skipped:     skipped,
		Partitions:  partitions,
	}, nil
}

// BSDMatchesHead reports whether either whole-disk label position holds the
// LABEL magic in either byte order. It is the cheap detection gate; ParseBSD
// confirms the repeated d_magic2.
func BSDMatchesHead(head []byte) bool {
	for _, base := range LabelOffsets {
		at := int(base)
		if at+4 > len(head) {
			continue
		}
		if _, ok := magicOrder(head[at : at+4]); ok {
			return true
		}
	}
	return false
}

// BSDTypeName returns the conventional filesystem name for a disklabel fstype
// code, or ("", false) for a code this reader does not name.
func BSDTypeName(code uint8) (string, bool) {
	switch code {
	case 0:
		return "Unused", true
	case 1:
		return "Swap", true
	case 2:
		return "Version 6", true
	case 3:
		return "Version 7", true
	case 4:
		return "System V", true
	case 5:
		return "4.1BSD", true
	case 6:
		return "Eighth Edition", true
	case 7:
		return "4.2BSD/FFS", true
	case 8:
		return "MSDOS", true
	case 9:
		return "BSDI", true
	case 10:
		return "4.4LFS", true
	case 11:
		return "Boot", true
	case 13:
		return "HFS", true
	case 14:
		return "ADOS", true
	case 17, 18, 19:
		return "CD9660", true
	case 20:
		return "ccd", true
	case 21:
		return "Vinum", true
	case 26:
		return "RAID", true
	case 27:
		return "ZFS", true
	case 28:
		return "nandfs", true
	case 29:
		return "Apple UFS", true
	default:
		return "", false
	}
}

func bsdEntryGeometry(entry []byte, order ByteOrder, version uint16) (start, count uint64) {
	offsetLow := uint64(order.U32(entry, pOffset))
	sizeLow := uint64(order.U32(entry, pSize))
	if version >= version48Bit {
		return offsetLow | uint64(order.U16(entry, pOffsetHigh))<<32,
			sizeLow | uint64(order.U16(entry, pSizeHigh))<<32
	}
	return offsetLow, sizeLow
}

func bsdPartitionLetter(index int) (byte, bool) {
	if index < 0 || index >= partitionLetters {
		return 0, false
	}
	return byte('a' + index), true
}

func bsdTypeText(fstype uint8) string {
	if name, ok := BSDTypeName(fstype); ok {
		return name
	}
	return fmt.Sprintf("fstype 0x%02X", fstype)
}

func bsdEntryLabel(index int, fstype uint8) string {
	name := bsdTypeText(fstype)
	if letter, ok := bsdPartitionLetter(index); ok {
		return fmt.Sprintf("%s (%c)", name, letter)
	}
	return name
}

func bsdEntryDescription(index int, fstype uint8) string {
	name := bsdTypeText(fstype)
	if letter, ok := bsdPartitionLetter(index); ok {
		return fmt.Sprintf("partition %c (%s)", letter, name)
	}
	return fmt.Sprintf("partition %d (%s)", index, name)
}

func magicOrder(bytes []byte) (ByteOrder, bool) {
	if len(bytes) < 4 {
		return 0, false
	}
	switch {
	case le32(bytes) == LabelMagic:
		return LittleEndian, true
	case be32(bytes) == LabelMagic:
		return BigEndian, true
	default:
		return 0, false
	}
}

func isDiskLabel64(bytes []byte) bool {
	if len(bytes) < 4 {
		return false
	}
	return le32(bytes) == DiskLabel64Magic || be32(bytes) == DiskLabel64Magic
}

func readMagic(src source.ByteSource, at uint64) ([]byte, error) {
	if at+4 > src.Len() {
		return nil, nil
	}
	return source.ReadVecAt(src, at, 4)
}

func checksumWords(bytes []byte, order ByteOrder) uint16 {
	var sum uint16
	for i := 0; i+1 < len(bytes); i += 2 {
		sum ^= order.U16(bytes, i)
	}
	return sum
}

func unsupportedDiskLabel64() error {
	return fmt.Errorf("%w: DragonFly disklabel64 at byte %d (magic 0x%08X): the 64-bit label is a distinct format with byte-offset entries and is not read",
		ErrUnsupported, 512, DiskLabel64Magic)
}
