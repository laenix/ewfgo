package ewf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/laenix/ewfgo/internal"
	"github.com/laenix/ewfgo/internal/filesystem"
)

// Open opens an EWF image file and parses its metadata.
// It supports E01 format and automatically handles multi-volume files if present.
//
// Example:
//
//	img, err := ewf.Open("/path/to/disk.E01")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer img.Close()
//
//	// Read metadata
//	fmt.Printf("Case: %s\n", img.CaseNumber())
//	fmt.Printf("Evidence: %s\n", img.EvidenceNumber())
//
//	// Scan filesystems
//	parts, _ := img.ScanFileSystems()
//	for _, p := range parts {
//		fmt.Printf("Partition %d: %s (%.2f GB)\n", p.Index, p.TypeName, float64(p.SizeBytes)/1024/1024/1024)
//	}
func Open(filepath string) (*EWFImage, error) {
	e := &internal.EWFImage{}
	_, err := e.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open EWF file: %w", err)
	}

	// Read and parse all sections
	e.ReadSections()
	if err := e.ParseSections(); err != nil {
		return nil, fmt.Errorf("failed to parse sections: %w", err)
	}

	// Create wrapper with exported methods
	return &EWFImage{
		ewf: e,
	}, nil
}

// EWFImage wraps the internal EWFImage and provides exported methods.
type EWFImage struct {
	ewf *internal.EWFImage
}

// Close closes the EWF image file.
func (e *EWFImage) Close() error {
	if e.ewf != nil {
		return e.ewf.Close()
	}
	return nil
}

// CaseNumber returns the case number from the EWF metadata.
func (e *EWFImage) CaseNumber() string {
	for _, h := range e.ewf.Headers {
		return h.L3_c
	}
	return ""
}

// EvidenceNumber returns the evidence number from the EWF metadata.
func (e *EWFImage) EvidenceNumber() string {
	for _, h := range e.ewf.Headers {
		return h.L3_n
	}
	return ""
}

// Examiner returns the examiner name from the EWF metadata.
func (e *EWFImage) Examiner() string {
	for _, h := range e.ewf.Headers {
		return h.L3_e
	}
	return ""
}

// TotalSectors returns the total number of sectors in the image.
func (e *EWFImage) TotalSectors() uint64 {
	for _, v := range e.ewf.DiskSMART {
		return v.SectorsCount
	}
	return 0
}

// SectorSize returns the size of each sector in bytes (usually 512).
func (e *EWFImage) SectorSize() uint32 {
	for _, v := range e.ewf.DiskSMART {
		return v.SectorBytes
	}
	return 512
}

// ReadSector reads a single sector at the given logical block address (LBA).
func (e *EWFImage) ReadSector(lba uint64) ([]byte, error) {
	return e.ReadSectors(lba, 1)
}

// ReadSectors reads multiple sectors starting at the given logical block address (LBA).
// It uses the table mapping to find compressed sector data and decompresses as needed.
func (e *EWFImage) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	if e.ewf == nil || e.ewf.Filepath() == "" {
		return nil, fmt.Errorf("no file opened")
	}

	// Try using the proper sector reading with decompression
	data, err := e.ewf.ReadSectorData(lba, count)
	if err != nil {
		// Fall back to direct file read if table not available
		sectorSize := int64(e.SectorSize())
		offset := int64(lba) * sectorSize
		length := int64(count) * sectorSize

		data = e.ewf.ReadAt(offset, length)
		if len(data) == 0 {
			return nil, fmt.Errorf("failed to read sectors at LBA %d: %v", lba, err)
		}
	}

	return data, nil
}

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
func (e *EWFImage) GPT() (internal.GPT, error) {
	var gpt internal.GPT
	
	// Use ReadSectors to properly read LBA 1 (GPT header is at LBA 1)
	data, err := e.ReadSectors(1, 1)
	if err != nil {
		return gpt, fmt.Errorf("failed to read GPT header: %w", err)
	}
	
	// Search for GPT header in sector data
	found := false
	for offset := 0; offset < len(data)-8; offset += 512 {
		if string(data[offset:offset+8]) == "EFI PART" {
			// Parse GPT header
			hdr := data[offset:offset+92]
			copy(gpt.GPTHeader.Signature[:], hdr[:8])
			gpt.GPTHeader.Version = binary.LittleEndian.Uint32(hdr[8:12])
			gpt.GPTHeader.HeaderSize = binary.LittleEndian.Uint32(hdr[12:16])
			gpt.GPTHeader.CurrentLBA = binary.LittleEndian.Uint64(hdr[24:32])
			gpt.GPTHeader.FirstLBA = binary.LittleEndian.Uint64(hdr[32:40])
			gpt.GPTHeader.LastLBA = binary.LittleEndian.Uint64(hdr[40:48])
			gpt.GPTHeader.PartitionStartLBA = binary.LittleEndian.Uint64(hdr[72:80])
			gpt.GPTHeader.PartitionNumber = binary.LittleEndian.Uint32(hdr[80:84])
			gpt.GPTHeader.PartitionSize = binary.LittleEndian.Uint32(hdr[84:88])
			found = true
			break
		}
	}
	
	if !found {
		return gpt, fmt.Errorf("GPT header not found at LBA 1")
	}
	
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
	
	// Parse partition entries
	for i := 0; i < int(gpt.GPTHeader.PartitionNumber) && i < 128; i++ {
		offset := i * partSize
		if offset+partSize > len(partData) {
			break
		}
		
		part := partData[offset:offset+partSize]
		startLBA := binary.LittleEndian.Uint64(part[32:40])
		endLBA := binary.LittleEndian.Uint64(part[40:48])
		
		if startLBA > 0 && startLBA < 0xFFFFFFFFFFFFFFFF {
			gpt.GPTPartitionTable[i].StartLBA = startLBA
			gpt.GPTPartitionTable[i].EndLBA = endLBA
			copy(gpt.GPTPartitionTable[i].PartitionTypeGUID[:], part[0:16])
			copy(gpt.GPTPartitionTable[i].PartitionGUID[:], part[16:32])
			copy(gpt.GPTPartitionTable[i].PartitionName[:], part[48:80])
		}
	}
	
	return gpt, nil
}

// GetDiskInfo returns the disk information from the EWF metadata.
func (e *EWFImage) GetDiskInfo() *DiskInfo {
	for _, v := range e.ewf.DiskSMART {
		return &DiskInfo{
			MediaType:        v.MediaType,
			TotalSectors:     v.SectorsCount,
			SectorBytes:      v.SectorBytes,
			CHS:              fmt.Sprintf("%d/%d/%d", v.CHScylinders, v.CHSheads, v.CHSsectors),
			CompressionLevel: v.CompressionLevel,
			SegmentFileSetID: fmt.Sprintf("%x", v.SegmentFileSetIdentifier),
		}
	}
	return nil
}

// DebugSections prints detailed section information for debugging
func (e *EWFImage) DebugSections() {
	fmt.Printf("=== Section Debug ===\n")
	fmt.Printf("Total Sections: %d\n", len(e.ewf.Sections))
	
	fmt.Printf("\n=== All Sections ===\n")
	for i, s := range e.ewf.Sections {
		fmt.Printf("Section %d: Type=%q, Address=%d, NextOffset=%d, Size=%d\n", 
			i, string(s.SectionTypeDefinition[:]), s.Address, s.NextOffset, s.SectionSize)
	}
	
	fmt.Printf("\n=== Sectors Sections ===\n")
	fmt.Printf("Total Sectors sections: %d\n", len(e.ewf.SectorsAddress))
	for i, s := range e.ewf.SectorsAddress {
		fmt.Printf("SectorSection %d: Address=%d, Size=%d\n", i, s.Address, s.SectionSize)
	}
	
	fmt.Printf("\n=== Table Sections ===\n")
	fmt.Printf("Total Table sections: %d\n", len(e.ewf.TableAddress))
	for i, t := range e.ewf.TableAddress {
		fmt.Printf("TableSection %d: Address=%d, Size=%d\n", i, t.Address, t.SectionSize)
	}
	
	fmt.Printf("\n=== Sectors with Tables ===\n")
	fmt.Printf("Total Sectors with TableEntry: %d\n", len(e.ewf.Sectors))
	for i, s := range e.ewf.Sectors {
		fmt.Printf("Sector[%d]: Address=%d, TableEntries=%d\n", 
			i, s.Address, len(s.TableEntry))
	}
	
	fmt.Printf("\n=== DiskSMART ===\n")
	fmt.Printf("Total DiskSMART: %d\n", len(e.ewf.DiskSMART))
	if len(e.ewf.DiskSMART) > 0 {
		ds := e.ewf.DiskSMART[0]
		fmt.Printf("SectorsCount: %d\n", ds.SectorsCount)
		fmt.Printf("ChunkSectors: %d\n", ds.ChunkSectors)
		fmt.Printf("SectorBytes: %d\n", ds.SectorBytes)
	}
}

// DiskInfo contains disk metadata from the EWF image.
type DiskInfo struct {
	MediaType        byte
	TotalSectors     uint64
	SectorBytes      uint32
	CHS              string
	CompressionLevel byte
	SegmentFileSetID string
}

// IsEWF checks if the given file is a valid EWF image.
func IsEWF(filepath string) bool {
	e := &internal.EWFImage{}
	_, err := e.Open(filepath)
	return err == nil
}

// FileExists checks if the given file exists.
func FileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
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
				idx := 1
				for i := 0; i < 128; i++ {
					if gpt.GPTPartitionTable[i].StartLBA > 0 {
						startLBA := gpt.GPTPartitionTable[i].StartLBA
						endLBA := gpt.GPTPartitionTable[i].EndLBA
						
						// Try to detect filesystem by reading partition
						fsType := "Unknown"
						partSector, err := e.ReadSectors(startLBA, 8)
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
							Index:          idx,
							StartSector:    startLBA,
							SizeSectors:    endLBA - startLBA + 1,
							SizeBytes:      (endLBA - startLBA + 1) * 512,
							Type:           "GPT",
							TypeCode:       0xEE,
							TypeName:       "GPT",
							FileSystem:     fsType,
						}
						partitions = append(partitions, pi)
						idx++
					}
				}
				
				// If we got GPT partitions, return them
				if len(partitions) > 0 {
					return partitions, nil
				}
			}
		}
		
		// Fall back to MBR parsing
		for i, p := range mbr.PartitionTable {
			if p.PartitionSize > 0 && p.PartitionType != 0x00 {
				pi := PartitionInfo{
					Index:          i + 1,
					StartSector:    uint64(p.StartLBA),
					SizeSectors:    uint64(p.PartitionSize),
					SizeBytes:      uint64(p.PartitionSize) * 512,
					Type:           fmt.Sprintf("0x%02X", p.PartitionType),
					TypeCode:       p.PartitionType,
					TypeName:       getPartitionTypeName(p.PartitionType),
					FileSystem:     "Unknown",
				}

				// Try to detect filesystem in this partition
				if p.PartitionSize > 10 {
					partSector, err := e.ReadSectors(uint64(p.StartLBA), 8)
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
// It searches through the provided data for known filesystem signatures.
func DetectFileSystem(sectorData []byte) string {
	if len(sectorData) < 512 {
		return "Unknown"
	}

	// For small data, check at offset 0 (traditional boot sector)
	if len(sectorData) >= 512 {
		// Check for NTFS (signature at offset 3)
		if len(sectorData) >= 8 && string(sectorData[3:7]) == "NTFS" {
			return "NTFS"
		}

		// Check for FAT32 (signature "FAT32   " at offset 0x52)
		if len(sectorData) >= 0x5A && string(sectorData[0x52:0x5A]) == "FAT32   " {
			return "FAT32"
		}

		// Check for FAT16 (signature "FAT16   " at offset 0x36)
		if len(sectorData) >= 0x3E && string(sectorData[0x36:0x3E]) == "FAT16   " {
			return "FAT16"
		}

		// Check for FAT12 (at offset 0x36)
		if len(sectorData) >= 0x3E && string(sectorData[0x36:0x3A]) == "FAT1" {
			return "FAT12"
		}

		// Check for exFAT ("EXFAT   " at offset 3)
		if len(sectorData) >= 11 && string(sectorData[3:11]) == "EXFAT   " {
			return "exFAT"
		}
	}

	// Check for HFS+ (magic at offset 1024)
	if len(sectorData) >= 1152 {
		magic := binary.BigEndian.Uint32(sectorData[1024:1028])
		if magic == 0x482B0000 {
			return "HFS+"
		}
	}

	// Check for APFS (magic at offset 4096)
	if len(sectorData) >= 4104 {
		magic := binary.LittleEndian.Uint64(sectorData[4096:4104])
		if magic == 0x4141504653455250 {
			return "APFS"
		}
	}

	// Check for Linux ext2/3/4 (superblock at offset 1080)
	if len(sectorData) >= 1088 {
		magic := binary.BigEndian.Uint16(sectorData[1080:1082])
		if magic == 0xEF53 {
			return "ext4"
		}
	}

	// Check for XFS ("XFSB" at offset 0)
	if len(sectorData) >= 4 && string(sectorData[:4]) == "XFSB" {
		return "XFS"
	}

	// Check for SquashFS ("hsqs" at offset 96)
	if len(sectorData) >= 100 && string(sectorData[96:100]) == "hsqs" {
		return "SquashFS"
	}

	// Check for F2FS ("F2FS" at offset 0)
	if len(sectorData) >= 4 && string(sectorData[:4]) == "F2FS" {
		return "F2FS"
	}

	// Check for Btrfs (magic at offset 0x10000)
	if len(sectorData) >= 0x10008 {
		magic := string(sectorData[0x10000:0x10008])
		if magic == "_BHRfS_M" {
			return "Btrfs"
		}
	}

	// Check for ReFS ("ReFS" or "ReFSB" at offset 3)
	if len(sectorData) >= 9 && (string(sectorData[3:7]) == "ReFS" || string(sectorData[3:8]) == "ReFSB") {
		return "ReFS"
	}

	return "Unknown"
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
		return "ext4"
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