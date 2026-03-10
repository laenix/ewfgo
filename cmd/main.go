package main

import (
	"fmt"
	"log"
	"os"

	ewf "github.com/laenix/ewfgo"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ewftool <path-to-e01-file> [command]")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  info     Show disk/partition info (default)")
		fmt.Println("  parts    List partitions")
		fmt.Println("  fs       Show filesystem info for each partition")
		fmt.Println("  ls       List root directory of first partition")
		os.Exit(1)
	}

	filepath := os.Args[1]
	command := "info"
	if len(os.Args) >= 3 {
		command = os.Args[2]
	}

	img, err := ewf.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer img.Close()

	// Run the selected command
	switch command {
	case "info":
		// Original info output
		if err := ewf.RunWithFile(filepath); err != nil {
			log.Fatal(err)
		}

	case "parts":
		showPartitions(img)

	case "fs":
		showFilesystems(img)

	case "ls":
		listRootFiles(img)
		// Try actual file reading too
		testFileReading(img)

	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Available: info, parts, fs, ls")
	}
}

func showPartitions(img *ewf.EWFImage) {
	disk := img.GetDiskInfo()
	if disk == nil {
		fmt.Println("No disk info available")
		return
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   Partition Table                       ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Total Size:  %-45s ║\n", formatSize(disk.TotalSectors))
	fmt.Printf("║ Block Size: %-45d ║\n", disk.SectorBytes)
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	
	// Since full partition table parsing would need more work,
	// show the basic info we can get
	fmt.Println("║ Partition detection requires file system parsing          ║")
	fmt.Println("║ Run: ewftool <file> fs  - to see filesystem info      ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func showFilesystems(img *ewf.EWFImage) {
	disk := img.GetDiskInfo()
	if disk == nil {
		fmt.Println("No disk info available")
		return
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Filesystem Detection                      ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════╣")
	
	// Scan for partitions with filesystem detection
	parts, err := img.ScanFileSystems()
	if err != nil {
		fmt.Println("║ Unable to read partitions                                       ║")
	} else {
		fmt.Println("║ Partition Table with Filesystem Detection:                     ║")
		for _, p := range parts {
			fmt.Printf("║   Part %d: %-8s | %-8s | %10s                     ║\n", 
				p.Index, p.TypeName, p.FileSystem, formatSize(p.SizeSectors))
		}
	}
	
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════╣")
	
	// Also show MBR info
	mbr, err := img.MBR()
	if err == nil {
		fmt.Printf("║ Disk Signature: 0x%X                                     ║\n", mbr.DiskSignature)
		fmt.Printf("║ Boot Signature: 0x%X                                       ║\n", mbr.BootSignature)
	}
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func listRootFiles(img *ewf.EWFImage) {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Root Directory Listing                   ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	
	// Get partition info
	parts, err := img.ScanFileSystems()
	if err != nil || len(parts) == 0 {
		fmt.Println("║ No partitions found                                         ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
		return
	}
	
	p := parts[0]
	fmt.Printf("║ Partition %d: %s at LBA %-10d                  ║\n", p.Index, p.FileSystem, p.StartSector)
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	
	// Try to list files
	entries, err := img.ListFiles(0)
	if err != nil {
		errStr := err.Error()
		if len(errStr) > 48 {
			errStr = errStr[:48]
		}
		fmt.Printf("║ Error: %-48s ║\n", errStr)
	} else {
		fmt.Printf("║ Found %d entries:                                         ║\n", len(entries))
		for i, e := range entries {
			if i < 20 {
				marker := "[FILE]"
				if e.IsDir {
					marker = "[DIR ]"
				}
				name := e.Name
				if len(name) > 30 {
					name = name[:30]
				}
				fmt.Printf("║   %s %-30s %10d bytes          ║\n", marker, name, e.Size)
			}
		}
		if len(entries) > 20 {
			fmt.Printf("║   ... and %d more                                        ║\n", len(entries)-20)
		}
	}
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

// Helper function to get partition type name
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
		0xEE: "GPT",
		0xEF: "EFI",
		0xFD: "Linux RAID",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Type 0x%02X", t)
}

func formatSize(sectors uint64) string {
	bytes := sectors * 512
	if bytes >= 1024*1024*1024*1024 {
		return fmt.Sprintf("%.2f TB", float64(bytes)/1024/1024/1024/1024)
	}
	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", float64(bytes)/1024/1024/1024)
	}
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(bytes)/1024/1024)
	}
	return fmt.Sprintf("%d KB", bytes/1024)
}

func testFileReading(img *ewf.EWFImage) {
	fmt.Println("")
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Testing File Reading                      ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	
	// First, show partition info 
	parts, err := img.ScanFileSystems()
	if err != nil || len(parts) == 0 {
		fmt.Println("║ No partitions found                                         ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
		return
	}
	
	for i, p := range parts {
		fmt.Printf("║ Partition %d: %-8s | %-8s | LBA %-10d | %s    ║\n", 
			i+1, p.TypeName, p.FileSystem, p.StartSector, formatSize(p.SizeSectors))
	}
	
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	
	// Try reading data from each partition
	for i := range parts {
		p := parts[i]
		fmt.Printf("║ Reading partition %d (start LBA: %d)...                     ║\n", i+1, p.StartSector)
		
		// Read some sectors from this partition
		data, err := img.ReadSectors(p.StartSector, 16)
		if err != nil {
			fmt.Printf("║   Error: %v                                          ║\n", err)
			continue
		}
		
		fmt.Printf("║   Read %d bytes from LBA %d                             ║\n", len(data), p.StartSector)
		
		// Show first 48 bytes as hex if we got data
		if len(data) > 48 {
			fmt.Print("║   First 48 bytes: ")
			for j := 0; j < 48; j++ {
				fmt.Printf("%02X ", data[j])
				if (j+1) % 16 == 0 {
					fmt.Println("║")
					fmt.Print("║                    ")
				}
			}
			fmt.Println("║")
			
			// Check filesystem signature in the data
			fs := ewf.DetectFileSystem(data)
			fmt.Printf("║   Detected filesystem from partition: %s                   ║\n", fs)
		}
	}
	
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}