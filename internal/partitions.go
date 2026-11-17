package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// APM - Apple Partition Map
// Located in block 1-63 of Apple partition scheme disks
type APMEntry struct {
	Signature       uint32 // "APM" magic (0x504D)
	Reserved1       uint32
	NumberOfEntries uint32 // Number of partition entries
	EntrySize       uint32 // Size of each entry (usually 512)
	EntryPosition   uint32 // Block number of this entry
	Reserved2       uint32
	PartitionName   [32]byte // Partition name (UTF-8)
	PartitionType   [32]byte // Partition type (e.g., "Apple_HFS", "Linux")
	StartingSector  uint32
	EndingSector    uint32
	SizeInSectors   uint32
	Attributes      uint32 // Partition attributes
	Reserved3       [32]byte
}

const APMSignature = 0x504D // "PM"

// BSD Disklabel
// Located in sector 0 or 1, offset 512 bytes
type BSDDisklabel struct {
	Reserved        [88]byte
	Partitions      [8]BSDPartition
	Version         uint32
	Magic           uint32 // 0x82564557
	MSC             uint16
	LastModified    uint32
	BootAreaSize    uint32
	SwapAreaSize    uint32
	WriteCount      uint32
	WriteTime       [8]byte
	ExpansionSize   uint32
	MinFragmentSize uint32
	Optimize        uint8
	NumCylinders    uint32
	SectorsPerTrack uint32
	HeadsPerCyl     uint32
	NumTracksPerCyl uint32
	NumSectors      uint32
	StartSector     uint32
	EndSector       uint32
	SwapAreaStart   uint32
	SwapAreaEnd     uint32
	RamDiskStart    uint32
	RamDiskEnd      uint32
}

type BSDPartition struct {
	Offset      uint32 // Starting sector
	Size        uint32 // Number of sectors
	Fragment    uint8  // Fragment size (0 = 512, 1 = 1024, etc.)
	Type        uint8  // BSD partition type
	Deprecated1 uint8
	Deprecated2 uint8
	Flags       uint16 // Flags
}

const BSDMagic = 0x82564557

// ParseAPM parses Apple Partition Map from the given data
func ParseAPM(data []byte) ([]APMEntry, error) {
	if len(data) < 512 {
		return nil, fmt.Errorf("data too small for APM")
	}

	var entries []APMEntry
	pos := 0

	for pos+512 <= len(data) {
		var entry APMEntry
		err := binary.Read(bytes.NewReader(data[pos:pos+512]), binary.BigEndian, &entry)
		if err != nil {
			break
		}

		if entry.Signature != APMSignature {
			break
		}

		entries = append(entries, entry)

		// Check for last entry
		partType := string(bytes.Trim(entry.PartitionType[:], "\x00"))
		if partType == "Apple_Free" {
			break
		}

		pos += int(entry.EntrySize)
	}

	return entries, nil
}

// ParseBSDDisklabel parses BSD Disklabel from the given data
func ParseBSDDisklabel(data []byte) (*BSDDisklabel, error) {
	if len(data) < 512 {
		return nil, fmt.Errorf("data too small for BSD disklabel")
	}

	var label BSDDisklabel
	// BSD disklabel is typically at offset 512 in sector 0
	offset := 512

	err := binary.Read(bytes.NewReader(data[offset:offset+512]), binary.LittleEndian, &label)
	if err != nil {
		return nil, err
	}

	if label.Magic != BSDMagic {
		return nil, fmt.Errorf("invalid BSD magic: 0x%08X", label.Magic)
	}

	return &label, nil
}

// LVM2 Physical Volume Header
// Located at sector 1 (512 bytes)
type LVM2Header struct {
	Label       [8]byte // "_LVM2_PV"
	Reserved1   [8]byte
	PV_Size     uint64 // Size of PV
	LVMActivatd uint8  // LVM2 activated
	Reserved2   [8]byte
	VG_NameLen  uint32    // Length of VG name
	VG_Name     [128]byte // Volume Group name
	PV_Number   uint32    // PV number in VG
	Reserved3   [32]byte
	DataStart   uint64 // Offset to data area
	DataSize    uint64 // Size of data area
	MetaStart   uint64 // Offset to metadata area
	MetaSize    uint64 // Size of metadata area
}

const LVM2Signature = "_LVM2_PV"

// ParseLVM2 parses LVM2 Physical Volume header.
// The label block lives at bytes 512..1024, so the input must be at least 1024
// bytes — the old `len(data) < 512` guard let a 512-byte input through and then
// sliced data[512:1024], panicking. Guard the full range instead.
func ParseLVM2(data []byte) (*LVM2Header, error) {
	if len(data) < 1024 {
		return nil, fmt.Errorf("data too small for LVM2 header")
	}

	var lvm LVM2Header
	// LVM2 label is at sector 1, offset 0
	err := binary.Read(bytes.NewReader(data[512:512+512]), binary.BigEndian, &lvm)
	if err != nil {
		return nil, err
	}

	sig := string(lvm.Label[:])
	if sig != LVM2Signature {
		return nil, fmt.Errorf("invalid LVM2 signature: %s", sig)
	}

	return &lvm, nil
}
