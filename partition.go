package ewf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal"
	"github.com/laenix/ewfgo/internal/filesystem"
)

// MBR parses and returns the MBR (Master Boot Record) of the image.
func (e *EWFImage) MBR() (internal.MBR, error) {
	var mbr internal.MBR

	// Use ReadSectors to properly read the first sector
	data, err := e.ReadSectors(0, 1)
	if err != nil {
		return mbr, fmt.Errorf("failed to read sector 0: %w", err)
	}

	if len(data) >= 512 {
		binary.Read(bytes.NewReader(data[:512]), binary.LittleEndian, &mbr)
	}

	return mbr, nil
}

// GPT parses and returns the GPT (GUID Partition Table) of the image.
// It keeps the read pattern (sector 1 for the header, the header's partition
// table LBA for the entries) and delegates the byte-level decoding to
// internal.ParseGPTHeader / ParseGPTPartitions, the single source of truth.
func (e *EWFImage) GPT() (internal.GPT, error) {
	var gpt internal.GPT

	// Use ReadSectors to properly read LBA 1 (GPT header is at LBA 1)
	data, err := e.ReadSectors(1, 1)
	if err != nil {
		return gpt, fmt.Errorf("failed to read GPT header: %w", err)
	}

	hdr, ok := internal.ParseGPTHeader(data)
	if !ok {
		return gpt, fmt.Errorf("GPT header not found at LBA 1")
	}
	gpt.GPTHeader = hdr

	// Read partition table (GPT uses LBA 2 for partition table by default)
	partTableLBA := gpt.GPTHeader.PartitionStartLBA
	if partTableLBA < 2 {
		partTableLBA = 2 // Default partition table location
	}

	// Read partition entries
	partSize := int(gpt.GPTHeader.PartitionSize)
	if partSize == 0 {
		partSize = 128 // Default entry size
	}

	// Read partition table sectors
	numSectors := (uint64(gpt.GPTHeader.PartitionNumber) * uint64(partSize) + 511) / 512
	if numSectors == 0 || numSectors > 64 {
		numSectors = 64 // Limit to prevent excessive reads
	}

	partData, err := e.ReadSectors(partTableLBA, numSectors)
	if err != nil {
		return gpt, fmt.Errorf("failed to read partition table: %w", err)
	}

	internal.ParseGPTPartitions(&gpt, partData)
	return gpt, nil
}

// APM returns the Apple Partition Map if present.
func (e *EWFImage) APM() ([]internal.APMEntry, error) {
	// Read first sector
	data, err := e.ReadSectors(1, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to read sector 1: %w", err)
	}
	return internal.ParseAPM(data)
}

// BSD returns the BSD Disklabel if present.
func (e *EWFImage) BSD() (*internal.BSDDisklabel, error) {
	// Read sector 0
	data, err := e.ReadSectors(0, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to read sector 0: %w", err)
	}
	return internal.ParseBSDDisklabel(data)
}

// LVM2 returns the LVM2 Physical Volume header if present.
func (e *EWFImage) LVM2() (*internal.LVM2Header, error) {
	// Read sector 1 (where LVM2 header is typically stored)
	data, err := e.ReadSectors(1, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to read sector 1: %w", err)
	}
	return internal.ParseLVM2(data)
}

// DetectPartitionType attempts to detect additional partition formats.
// Returns a string describing the detected format.
func (e *EWFImage) DetectPartitionType() string {
	// Try APM (Apple Partition Map)
	_, err := e.APM()
	if err == nil {
		return "Apple Partition Map (APM)"
	}

	// Try BSD Disklabel
	_, err = e.BSD()
	if err == nil {
		return "BSD Disklabel"
	}

	// Try LVM2
	_, err = e.LVM2()
	if err == nil {
		return "LVM2 Physical Volume"
	}

	return "Unknown"
}

// PartitionInfo contains information about a detected partition.
type PartitionInfo struct {
	Index          int
	StartSector    uint64
	SizeSectors    uint64
	SizeBytes      uint64
	Type           string
	TypeCode       byte
	TypeName       string
	FileSystem     string
	FilesystemType filesystem.FileSystemType
}

// ScanFileSystems scans the image for partitions and detects filesystems.
// This is a simplified version that reads the MBR/GPT and detects filesystem types.
func (e *EWFImage) ScanFileSystems() ([]PartitionInfo, error) {
	var partitions []PartitionInfo

	// Try GPT first (check if GPT protective MBR exists)
	mbr, err := e.MBR()
	if err == nil {
		// Check for GPT protective partition (type 0xEE) or very large partition (>1TB suggests GPT)
		hasGPT := false
		for _, p := range mbr.PartitionTable {
			if p.PartitionType == 0xEE || (p.PartitionType == 0x9C && p.PartitionSize > 2000000) {
				hasGPT = true
				break
			}
		}

		// If GPT protective partition found, try GPT parsing
		if hasGPT {
			gpt, gptErr := e.GPT()
			if gptErr == nil && string(gpt.GPTHeader.Signature[:]) == "EFI PART" {
				// Parse GPT partitions
				for i := 0; i < 128; i++ {
					if gpt.GPTPartitionTable[i].StartLBA > 0 {
						startLBA := gpt.GPTPartitionTable[i].StartLBA
						endLBA := gpt.GPTPartitionTable[i].EndLBA

						// Try to detect filesystem by reading partition
						fsType := "Unknown"
						// Read a window large enough for every signature we check,
						// including the btrfs superblock magic at 0x10040 (64 KiB + 0x40).
						// Clamp to the partition size so tiny partitions don't read past
						// the end.
						partSize := endLBA - startLBA + 1
						readSectors := uint64(129) // 66048 bytes
						if readSectors > partSize {
							readSectors = partSize
						}
						partSector, err := e.ReadSectors(startLBA, readSectors)
						if err == nil {
							fsType = DetectFileSystem(partSector)
						}

						// Override with GUID-based guess if still unknown
						if fsType == "Unknown" {
							partTypeGUID := gpt.GPTPartitionTable[i].PartitionTypeGUID
							// Check for EFI System Partition (FAT)
							if len(partTypeGUID) >= 16 &&
								partTypeGUID[15] == 0xEF {
								fsType = "EFI"
							}
							// Check for APFS (Apple_APFS: 7C3457EF-0000-11AA-AA11-00306543ECAC)
							// GUID bytes: EF 57 34 7C 00 00 AA 11 AA 11 00 30 65 43 EC AC
							if len(partTypeGUID) >= 16 &&
								partTypeGUID[0] == 0xEF && partTypeGUID[1] == 0x57 &&
								partTypeGUID[2] == 0x34 && partTypeGUID[3] == 0x7C &&
								partTypeGUID[6] == 0xAA && partTypeGUID[7] == 0x11 {
								fsType = "APFS"
							}
						}

						pi := PartitionInfo{
							Index:       len(partitions),
							StartSector: startLBA,
							SizeSectors: endLBA - startLBA + 1,
							SizeBytes:   (endLBA - startLBA + 1) * 512,
							Type:        "GPT",
							TypeCode:    0xEE,
							TypeName:    "GPT",
							FileSystem:  fsType,
						}
						partitions = append(partitions, pi)
					}
				}

				// If we got GPT partitions, return them
				if len(partitions) > 0 {
					return partitions, nil
				}
			}
		}

		// Fall back to MBR parsing
		for _, p := range mbr.PartitionTable {
			if p.PartitionSize > 0 && p.PartitionType != 0x00 {
				pi := PartitionInfo{
					Index:       len(partitions),
					StartSector: uint64(p.StartLBA),
					SizeSectors: uint64(p.PartitionSize),
					SizeBytes:   uint64(p.PartitionSize) * 512,
					Type:        fmt.Sprintf("0x%02X", p.PartitionType),
					TypeCode:    p.PartitionType,
					TypeName:    getPartitionTypeName(p.PartitionType),
					FileSystem:  "Unknown",
				}

				// Try to detect filesystem in this partition
				if p.PartitionSize > 10 {
					// Read a window large enough for every signature we check,
					// including the btrfs superblock magic at 0x10040 (64 KiB + 0x40).
					// Clamp to the partition size so tiny partitions don't read past
					// the end.
					readSectors := uint64(129) // 66048 bytes
					if readSectors > uint64(p.PartitionSize) {
						readSectors = uint64(p.PartitionSize)
					}
					partSector, err := e.ReadSectors(uint64(p.StartLBA), readSectors)
					if err == nil {
						pi.FileSystem = DetectFileSystem(partSector)
					}
				}

				// If still unknown, guess from partition type code
				if pi.FileSystem == "Unknown" {
					pi.FileSystem = GuessFileSystemFromPartitionType(p.PartitionType)
				}

				partitions = append(partitions, pi)
			}
		}
	}

	return partitions, nil
}

// DetectFileSystem attempts to detect the filesystem type from boot sector data.
// It delegates to the single source of truth in internal/filesystem so the two
// copies can never drift apart (in particular, the btrfs probe at 0x10040).
func DetectFileSystem(sectorData []byte) string {
	return string(filesystem.DetectFileSystem(sectorData))
}

// getPartitionTypeName returns a human-readable name for partition type codes.
func getPartitionTypeName(t byte) string {
	names := map[byte]string{
		0x00: "Empty",
		0x01: "FAT12",
		0x04: "FAT16",
		0x05: "Extended",
		0x06: "FAT16",
		0x07: "NTFS/HPFS",
		0x0B: "FAT32 CHS",
		0x0C: "FAT32 LBA",
		0x0E: "FAT16 LBA",
		0x0F: "Extended LBA",
		0x11: "Hidden FAT12",
		0x14: "Hidden FAT16",
		0x16: "Hidden FAT16",
		0x1B: "Hidden FAT32",
		0x1C: "Hidden FAT32",
		0x1E: "Hidden FAT16 LBA",
		0x27: "Windows RE",
		0x82: "Linux Swap",
		0x83: "Linux",
		0x8E: "Linux LVM",
		0xEE: "GPT Protective",
		0xEF: "EFI",
		0xFD: "Linux RAID",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Type 0x%02X", t)
}

// GuessFileSystemFromPartitionType attempts to guess filesystem from MBR partition type code.
// This is a fallback when direct filesystem detection isn't possible.
func GuessFileSystemFromPartitionType(t byte) string {
	switch t {
	case 0x01:
		return "FAT12"
	case 0x04, 0x06, 0x0E, 0x14, 0x16, 0x1E:
		return "FAT16"
	case 0x0B, 0x0C, 0x1B, 0x1C:
		return "FAT32"
	case 0x07, 0x17, 0x27:
		return "NTFS"
	case 0x83:
		return "Unknown" // Could be ext2/3/4, XFS, btrfs, etc.
	case 0x8E:
		return "LVM"
	case 0x82:
		return "Swap"
	case 0xFD:
		return "RAID"
	case 0xEE:
		return "GPT"
	case 0xEF:
		return "EFI"
	default:
		return "Unknown"
	}
}
