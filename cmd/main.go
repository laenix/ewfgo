package main

import (
	"fmt"
	"log"
	"os"

	ewf "github.com/laenix/ewfgo"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ewftool <path-to-e01-file> [command] [path]")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  info     Show disk/partition info (default)")
		fmt.Println("  parts    List partitions")
		fmt.Println("  fs       Show filesystem info for each partition")
		fmt.Println("  ls       List directory (default: root)")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  ewftool image.E01 ls")
		fmt.Println("  ewftool image.E01 ls /")
		fmt.Println("  ewftool image.E01 ls VIDEO")
		fmt.Println("  ewftool image.E01 ls VIDEO/00")
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
		printImageInfo(img)

	case "parts":
		showPartitions(img)

	case "fs":
		showFilesystems(img)

	case "ls":
		// Optional: partition index and path argument
		// Usage: ls [partition#] [path]
		partitionIndex := 0
		dirPath := ""
		if len(os.Args) >= 4 {
			// Check if first arg is a number (partition index)
			fmt.Sscanf(os.Args[3], "%d", &partitionIndex)
			if len(os.Args) >= 5 {
				dirPath = os.Args[4]
			}
		}
		listDirectoryPartition(img, partitionIndex, dirPath)
		// Try actual file reading too
		testFileReading(img)

	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Available: info, parts, fs, ls")
	}
}

// printImageInfo prints the image metadata box from the public API.
func printImageInfo(img *ewf.EWFImage) {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                     EWF Image Info                        ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")

	caseNum := img.CaseNumber()
	if caseNum == "" {
		caseNum = "(none)"
	}
	fmt.Printf("║ Case:         %-42s ║\n", caseNum)

	evidenceNum := img.EvidenceNumber()
	if evidenceNum == "" {
		evidenceNum = "(none)"
	}
	fmt.Printf("║ Evidence:     %-42s ║\n", evidenceNum)

	if examiner := img.Examiner(); examiner != "" {
		fmt.Printf("║ Examiner:     %-42s ║\n", examiner)
	}

	// Disk info
	disk := img.GetDiskInfo()
	if disk != nil {
		fmt.Println("╠═══════════════════════════════════════════════════════════╣")
		fmt.Printf("║ Total Size:   %-42s ║\n", formatBytes(disk.TotalSectors*uint64(disk.SectorBytes)))
		fmt.Printf("║ Sector Size:  %-42d bytes║\n", disk.SectorBytes)
		fmt.Printf("║ Total Sectors: %-41d ║\n", disk.TotalSectors)

		compName := []string{"None", "Good", "Best"}
		compStr := "Unknown"
		if int(disk.CompressionLevel) >= 0 && int(disk.CompressionLevel) < len(compName) {
			compStr = compName[disk.CompressionLevel]
		}
		fmt.Printf("║ Compression:  %-42s ║\n", compStr)
	}

	// Partition / filesystem summary
	parts, err := img.ScanFileSystems()
	if err == nil && len(parts) > 0 {
		fmt.Println("╠═══════════════════════════════════════════════════════════╣")
		for i, p := range parts {
			if i == 0 {
				fmt.Printf("║ Partitions:   %-42s ║\n", fmt.Sprintf("%d found", len(parts)))
			}
			fmt.Printf("║   %d: %-10s | %-10s | %10s           ║\n",
				p.Index, p.TypeName, p.FileSystem, formatSize(p.SizeSectors))
		}
	}

	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
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

func listDirectory(img *ewf.EWFImage, dirPath string) {
	listDirectoryPartition(img, 0, dirPath)
}

func listDirectoryPartition(img *ewf.EWFImage, partitionIndex int, dirPath string) {
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

	idx := partitionIndex
	if idx < 0 || idx >= len(parts) {
		fmt.Printf("║ Invalid partition index %d (max %d)                          ║\n", idx, len(parts)-1)
		fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
		return
	}

	p := parts[idx]
	fmt.Printf("║ Partition %d: %s at LBA %-10d                  ║\n", p.Index, p.FileSystem, p.StartSector)

	if dirPath != "" {
		fmt.Printf("║ Directory: %-45s ║\n", dirPath)
	}

	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")

	// Open the partition's filesystem and list the directory through it.
	fs, err := img.OpenFileSystem(idx)
	if err != nil {
		errStr := err.Error()
		if len(errStr) > 48 {
			errStr = errStr[:48]
		}
		fmt.Printf("║ Error: %-48s ║\n", errStr)
		fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
		return
	}
	defer fs.Close()

	entries, err := fs.ListDir(dirPath)
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

func formatBytes(bytes uint64) string {
	if bytes >= 1024*1024*1024*1024 {
		return fmt.Sprintf("%.2f TB", float64(bytes)/1024/1024/1024/1024)
	}
	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", float64(bytes)/1024/1024/1024)
	}
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(bytes)/1024/1024)
	}
	return fmt.Sprintf("%d bytes", bytes)
}

func formatSize(sectors uint64) string {
	return formatBytes(sectors * 512)
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
				if (j+1)%16 == 0 {
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
