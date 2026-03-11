package ewf

import (
	"fmt"
	"os"

	"github.com/laenix/ewfgo/internal"
)

// Run parses an EWF file specified as command line argument
func Run() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ewftool <path-to-e01-file>")
		return
	}
	filepath := os.Args[1]
	RunWithFile(filepath)
}

// RunWithFile opens an EWF file and parses it
func RunWithFile(filepath string) error {
	// Open real EWF file using internal package
	ewfImg := &internal.EWFImage{}
	_, err := ewfImg.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	// Read and parse sections
	ewfImg.ReadSections()
	if err := ewfImg.ParseSections(); err != nil {
		fmt.Printf("Warning: failed to parse sections: %v\n", err)
	}

	// Print headers with fallback for missing metadata
	caseNum, evidenceNum, desc, examiner := "", "", "N/A", ""
	acquisitionTime := ""

	for _, h := range ewfImg.Headers {
		if h.L3_c != "" {
			caseNum = h.L3_c
		}
		if h.L3_n != "" {
			evidenceNum = h.L3_n
		}
		if h.L3_a != "" && h.L3_a != "untitled" {
			desc = h.L3_a
		}
		if h.L3_e != "" {
			examiner = h.L3_e
		}
		if h.L3_m != "" {
			acquisitionTime = h.L3_m
		}
	}

	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                     EWF Image Info                        ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")

	if caseNum != "" {
		fmt.Printf("║ Case:         %-42s ║\n", caseNum)
	} else {
		fmt.Printf("║ Case:         %-42s ║\n", "(none)")
	}

	if evidenceNum != "" {
		fmt.Printf("║ Evidence:     %-42s ║\n", evidenceNum)
	} else {
		fmt.Printf("║ Evidence:     %-42s ║\n", "(none)")
	}

	fmt.Printf("║ Description:  %-42s ║\n", desc)

	if examiner != "" {
		fmt.Printf("║ Examiner:     %-42s ║\n", examiner)
	}

	if acquisitionTime != "" {
		fmt.Printf("║ Acquired:     %-42s ║\n", acquisitionTime)
	}

	// Disk info
	totalSectors := uint64(0)
	sectorSize := uint32(512)
	compression := 0

	for _, v := range ewfImg.DiskSMART {
		totalSectors = v.SectorsCount
		sectorSize = v.SectorBytes
		compression = int(v.CompressionLevel)
	}

	fmt.Println("╠═══════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Total Size:   %-42s ║\n", formatSize(totalSectors, sectorSize))
	fmt.Printf("║ Sector Size:  %-42d bytes║\n", sectorSize)
	fmt.Printf("║ Total Sectors: %-41d ║\n", totalSectors)

	compName := []string{"None", "Good", "Best"}
	compStr := "Unknown"
	if compression >= 0 && compression < len(compName) {
		compStr = compName[compression]
	}
	fmt.Printf("║ Compression:  %-42s ║\n", compStr)

	// Image type detection
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")

	// Detect partition vs full disk
	isPartition := ewfImg.IsPartitionImage()
	if isPartition {
		fmt.Printf("║ Image Type:   %-42s ║\n", "Partition Image")
	} else {
		fmt.Printf("║ Image Type:   %-42s ║\n", "Full Disk Image")
	}

	// Partition type analysis
	partType := ewfImg.GetPartitionType()
	fmt.Printf("║ Partition:    %-42s ║\n", partType)

	// Detect RAID
	if ewfImg.DetectRAID() {
		fmt.Printf("║ RAID:         %-42s ║\n", "RAID signature detected")
	}

	// Detect LVM
	if ewfImg.DetectLVM() {
		fmt.Printf("║ LVM:          %-42s ║\n", "LVM2 Physical Volume detected")
	}

	fmt.Println("╚═══════════════════════════════════════════════════════════╝")

	return nil
}

func formatSize(sectors uint64, sectorSize uint32) string {
	bytes := sectors * uint64(sectorSize)

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
