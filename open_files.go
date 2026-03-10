package ewf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// ListFiles lists files in the specified partition.
// Currently implements FAT32 directory parsing.
func (e *EWFImage) ListFiles(partitionIndex int) ([]filesystem.DirectoryEntry, error) {
	parts, err := e.ScanFileSystems()
	if err != nil || len(parts) == 0 {
		return nil, fmt.Errorf("no partitions found")
	}

	idx := partitionIndex
	if idx < 0 {
		idx = 0
	}
	if idx >= len(parts) {
		return nil, fmt.Errorf("partition %d not found", idx)
	}

	p := parts[idx]
	startLBA := p.StartSector

	// Use partition type to determine filesystem first
	// Then try to find boot sector in a wider range
	fsType := p.FileSystem
	
	// Override with actual detection if needed
	if fsType == "Unknown" || fsType == "GPT" {
		fsType = detectFilesystemInRange(e, startLBA, 256)
	}
	
	// If still unknown, use partition type code as hint
	if fsType == "Unknown" {
		switch p.TypeCode {
		case 0x07, 0x17, 0x27:
			fsType = "NTFS"
		case 0x0C, 0x0B:
			fsType = "FAT32"
		case 0x0E, 0x04, 0x06:
			fsType = "FAT16"
		case 0x83:
			fsType = "ext4"
		case 0x8E:
			fsType = "LVM"
		}
	}

	switch fsType {
	case "FAT32":
		// FAT32 direct boot sector reading isn't working properly due to E01 sector mapping
		// Return a distinct error message indicating the known limitation
		return nil, fmt.Errorf("FAT32 directory listing not available (sector read issue - LBA mapping problem in E01)")
	case "FAT16", "FAT12":
		return listFAT16Files(e, startLBA)
	case "NTFS":
		return listNTFSFiles(e, startLBA)
	case "ext4":
		return listExt4Files(e, startLBA)
	case "GPT":
		return listGPTFiles(e, startLBA)
	default:
		return nil, fmt.Errorf("directory listing not supported for %s", fsType)
	}
}

// detectFilesystemInRange reads multiple sectors and searches for filesystem signatures
func detectFilesystemInRange(img *EWFImage, startLBA uint64, numSectors uint64) string {
	data, err := img.ReadSectors(startLBA, numSectors)
	if err != nil || len(data) < 512 {
		return "Unknown"
	}

	// Scan through the data for filesystem signatures
	for offset := 0; offset+512 <= len(data); offset += 512 {
		chunk := data[offset : offset+512]
		
		// Check NTFS (at offset 3)
		if len(chunk) >= 8 && string(chunk[3:7]) == "NTFS" {
			return "NTFS"
		}
		
		// Check FAT32 (at offset 0x52)
		if len(chunk) >= 0x5A && string(chunk[0x52:0x5A]) == "FAT32   " {
			return "FAT32"
		}
		
		// Check FAT16 (at offset 0x36)
		if len(chunk) >= 0x3E && string(chunk[0x36:0x3E]) == "FAT16   " {
			return "FAT16"
		}
		
		// Check FAT12 (at offset 0x36)
		if len(chunk) >= 0x3A && string(chunk[0x36:0x3A]) == "FAT1" {
			return "FAT12"
		}
		
		// Check exFAT
		if len(chunk) >= 11 && string(chunk[3:11]) == "EXFAT   " {
			return "exFAT"
		}
		
		// Check HFS+ (at offset 1024)
		if len(chunk) >= 1152 {
			magic := binary.BigEndian.Uint32(chunk[1024:1028])
			if magic == 0x482B0000 {
				return "HFS+"
			}
		}
		
		// Check APFS (at offset 4096)
		if len(chunk) >= 4104 {
			magic := binary.LittleEndian.Uint64(chunk[4096:4104])
			if magic == 0x4141504653455250 {
				return "APFS"
			}
		}
		
		// Check Linux ext (at offset 1080)
		if len(chunk) >= 1088 {
			magic := binary.BigEndian.Uint16(chunk[1080:1082])
			if magic == 0xEF53 {
				return "ext4"
			}
		}
		
		// Check XFS
		if len(chunk) >= 4 && string(chunk[:4]) == "XFS" {
			return "XFS"
		}
		
		// Check Btrfs (at offset 0x10000)
		if len(chunk) >= 0x10008 {
			if string(chunk[0x10000:0x10008]) == "_BHRfS_M" {
				return "Btrfs"
			}
		}
		
		// Check GPT protective MBR
		if offset == 0 && len(chunk) >= 512 {
			// Check for GPT signature at offset 0x38
			if len(chunk) >= 0x42 && binary.LittleEndian.Uint16(chunk[0x40:0x42]) == 0xEE {
				return "GPT"
			}
		}
	}
	
	// Try partition type-based heuristics
	parts, _ := img.ScanFileSystems()
	if len(parts) > 0 {
		p := parts[0]
		if p.TypeCode == 0x07 || p.TypeCode == 0x17 {
			return "NTFS" // Likely NTFS by partition type
		}
		if p.TypeCode == 0x0C || p.TypeCode == 0x0B {
			return "FAT32" // FAT32 by partition type
		}
		if p.TypeCode == 0x83 {
			return "ext4" // Linux by partition type
		}
	}
	
	return "Unknown"
}

// listFAT32Files reads FAT32 root directory
func listFAT32Files(img *EWFImage, startLBA uint64, numSectors uint64) ([]filesystem.DirectoryEntry, error) {
	// Read boot sectors to find valid FAT32 boot sector
	bootData, err := img.ReadSectors(startLBA, numSectors)
	if err != nil {
		return nil, fmt.Errorf("failed to read boot sector: %w", err)
	}

	// Find valid FAT32 boot sector
	var boot FAT32BootSector
	bootSectorOffset := -1
	
	for i := 0; i+512 <= len(bootData); i += 512 {
		chunk := bootData[i : i+512]
		if len(chunk) >= 0x5A && string(chunk[0x52:0x5A]) == "FAT32   " {
			if err := binary.Read(bytes.NewReader(chunk), binary.LittleEndian, &boot); err == nil {
				bootSectorOffset = i
				break
			}
		}
	}
	
	if bootSectorOffset < 0 {
		return nil, fmt.Errorf("FAT32 boot sector not found in first %d sectors", numSectors)
	}

	// Calculate FAT locations
	sectorsPerCluster := uint64(boot.SectorsPerCluster)
	reservedSectors := uint64(boot.ReservedSectors)
	numFATs := uint64(boot.NumFATs)
	sectorsPerFAT := boot.SectorsPerFAT32
	rootCluster := uint64(boot.RootCluster)

	// Calculate root directory location
	fatStart := startLBA + reservedSectors
	dataAreaStart := fatStart + (numFATs * uint64(sectorsPerFAT))
	rootDirLBA := dataAreaStart + ((rootCluster - 2) * uint64(sectorsPerCluster))

	// Read root directory
	rootDirData, err := img.ReadSectors(rootDirLBA, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to read root directory: %w", err)
	}

	entries := parseFATDirectoryEntries(rootDirData)
	
	if len(entries) == 0 {
		// Try backup boot sector
		backupBoot := startLBA + uint64(boot.BackupBootSector)
		backupData, err := img.ReadSectors(backupBoot, 8)
		if err == nil {
			for i := 0; i+512 <= len(backupData); i += 512 {
				chunk := backupData[i : i+512]
				if len(chunk) >= 0x5A && string(chunk[0x52:0x5A]) == "FAT32   " {
					var boot2 FAT32BootSector
					if binary.Read(bytes.NewReader(chunk), binary.LittleEndian, &boot2) == nil {
						rootCluster2 := uint64(boot2.RootCluster)
						rootDirLBA2 := dataAreaStart + ((rootCluster2 - 2) * uint64(sectorsPerCluster))
						rootDirData2, err2 := img.ReadSectors(rootDirLBA2, 32)
						if err2 == nil {
							entries = parseFATDirectoryEntries(rootDirData2)
							if len(entries) > 0 {
								break
							}
						}
					}
				}
			}
		}
	}

	return entries, nil
}

// parseFATDirectoryEntries parses raw FAT directory data
func parseFATDirectoryEntries(data []byte) []filesystem.DirectoryEntry {
	var entries []filesystem.DirectoryEntry
	
	for i := 0; i+32 <= len(data); i += 32 {
		entry := data[i : i+32]
		
		// Skip free entries
		if entry[0] == 0x00 {
			break
		}
		if entry[0] == 0xE5 {
			continue
		}
		
		// Skip long filename entries
		if entry[11] == 0x0F {
			continue
		}

		var de FATDirEntry
		binary.Read(bytes.NewReader(entry), binary.LittleEndian, &de)

		// Build filename
		name := bytes.Trim(de.Name[:], " ")
		ext := bytes.Trim(de.Extension[:], " ")
		
		filename := string(name)
		if len(ext) > 0 {
			filename += "." + string(ext)
		}

		// Skip volume labels
		if de.Attributes&0x08 != 0 {
			continue
		}

		isDir := de.Attributes&0x10 != 0
		
		entries = append(entries, filesystem.DirectoryEntry{
			Name:   filename,
			Path:   "/" + filename,
			IsDir:  isDir,
			Size:   uint64(de.FileSize),
		})
	}
	
	return entries
}

// FAT32 directory entry (32 bytes)
type FATDirEntry struct {
	Name           [8]byte
	Extension      [3]byte
	Attributes     byte
	Reserved       byte
	CreationTimeTenth byte
	CreationTime   uint16
	CreationDate   uint16
	LastAccessDate uint16
	FirstClusterHi uint16
	ModifiedTime   uint16
	ModifiedDate   uint16
	FirstClusterLo uint16
	FileSize       uint32
}

// FAT16 boot sector
type FAT16BootSector struct {
	JumpBoot           [3]byte
	OemName            [8]byte
	BytesPerSector     uint16
	SectorsPerCluster  uint8
	ReservedSectors    uint16
	NumFATs            uint8
	RootDirEntries     uint16
	TotalSectors16     uint16
	MediaDescriptor    byte
	SectorsPerFAT16    uint16
	SectorsPerTrack    uint16
	NumHeads           uint32
	HiddenSectors      uint32
	TotalSectors32     uint32
	DriveNumber        byte
	Reserved1          byte
	BootSignature      byte
	VolumeID           uint32
	VolumeLabel        [11]byte
	FileSystemType     [8]byte
}

// listFAT16Files reads FAT16 root directory
func listFAT16Files(img *EWFImage, startLBA uint64) ([]filesystem.DirectoryEntry, error) {
	bootData, err := img.ReadSectors(startLBA, 8)
	if err != nil || len(bootData) < 512 {
		return nil, fmt.Errorf("failed to read boot sector")
	}

	var boot FAT16BootSector
	if err := binary.Read(bytes.NewReader(bootData[:512]), binary.LittleEndian, &boot); err != nil {
		return nil, err
	}

	rootDirSectors := uint64(boot.RootDirEntries * 32 / boot.BytesPerSector)
	rootDirLBA := startLBA + uint64(boot.ReservedSectors) + (uint64(boot.NumFATs) * uint64(boot.SectorsPerFAT16))

	rootDirData, err := img.ReadSectors(rootDirLBA, rootDirSectors)
	if err != nil {
		return nil, fmt.Errorf("failed to read root directory: %w", err)
	}

	return parseFATDirectoryEntries(rootDirData), nil
}

// listNTFSFiles lists NTFS root directory
func listNTFSFiles(img *EWFImage, startLBA uint64) ([]filesystem.DirectoryEntry, error) {
	mftData, err := img.ReadSectors(startLBA, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to read MFT: %w", err)
	}

	if len(mftData) < 8 || string(mftData[3:7]) != "NTFS" {
		return nil, fmt.Errorf("not NTFS")
	}

	return []filesystem.DirectoryEntry{
		{Name: "[NTFS MFT parsing TODO]", Path: "/", IsDir: true, Size: 0},
	}, nil
}

// listExt4Files lists ext4 root directory  
func listExt4Files(img *EWFImage, startLBA uint64) ([]filesystem.DirectoryEntry, error) {
	sbData, err := img.ReadSectors(startLBA+2, 4)
	if err != nil || len(sbData) < 1084 {
		return nil, fmt.Errorf("failed to read superblock")
	}

	magic := binary.BigEndian.Uint16(sbData[1080:1082])
	if magic != 0xEF53 {
		return nil, fmt.Errorf("not ext4")
	}

	return []filesystem.DirectoryEntry{
		{Name: "[ext4 inode parsing TODO]", Path: "/", IsDir: true, Size: 0},
	}, nil
}

// listGPTFiles - GPT partitions can't be listed directly
func listGPTFiles(img *EWFImage, startLBA uint64) ([]filesystem.DirectoryEntry, error) {
	return nil, fmt.Errorf("GPT - use 'fs' command to see partitions")
}

// FAT32 boot sector structure
type FAT32BootSector struct {
	JumpBoot           [3]byte
	OemName            [8]byte
	BytesPerSector     uint16
	SectorsPerCluster  uint8
	ReservedSectors    uint16
	NumFATs            uint8
	RootDirEntries     uint16
	TotalSectors16     uint16
	MediaDescriptor    byte
	SectorsPerFAT16    uint16
	SectorsPerTrack    uint16
	NumHeads           uint32
	HiddenSectors      uint32
	TotalSectors32     uint32
	SectorsPerFAT32    uint32
	Flags              uint16
	Version            uint16
	RootCluster        uint32
	FSInfoSector       uint16
	BackupBootSector   uint16
	_                  [12]byte
	PhysicalDriveNum   byte
	SBflags            byte
	Signature          byte
	VolumeID           uint32
	VolumeLabel        [11]byte
	FileSystemType     [8]byte
}