package main

import (
	"fmt"
	"log"

	"github.com/laenix/ewfgo"
)

func main() {
	filepath := "/mnt/d/e01/pc-disk.E01"
	if len([]string{}) > 0 {
		// filepath = args[0]
	}

	// Open an EWF image
	img, err := ewf.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer img.Close()

	// Print metadata
	fmt.Println("=== EWF Image Info ===")
	fmt.Printf("Case Number: %s\n", img.CaseNumber())
	fmt.Printf("Evidence Number: %s\n", img.EvidenceNumber())
	fmt.Printf("Examiner: %s\n", img.Examiner())

	// Print disk info
	disk := img.GetDiskInfo()
	fmt.Printf("Total Sectors: %d\n", disk.TotalSectors)
	fmt.Printf("Sector Size: %d bytes\n", disk.SectorBytes)
	fmt.Printf("CHS: %s\n", disk.CHS)
	fmt.Printf("Compression Level: %d\n", disk.CompressionLevel)

	// Detect additional partition types
	fmt.Printf("\n=== Additional Partition Formats ===")
	fmt.Printf("Detected: %s\n", img.DetectPartitionType())

	// Try to parse APM (Apple Partition Map)
	apm, err := img.APM()
	if err == nil && len(apm) > 0 {
		// Print APM not using internal package (just names)
		fmt.Println("Apple Partition Map detected!")
		for i, e := range apm {
			fmt.Printf("  Partition %d\n", i)
		}
	}

	// Try to parse BSD Disklabel
	bsd, err := img.BSD()
	if err == nil {
		fmt.Println("BSD Disklabel detected!")
	}

	// Try to parse LVM2
	lvm, err := img.LVM2()
	if err == nil {
		fmt.Println("LVM2 Physical Volume detected!")
		fmt.Printf("  PV Size: %d bytes\n", lvm.PV_Size)
	}

	// Read MBR
	fmt.Println("\n=== MBR ===")
	mbr, err := img.MBR()
	if err != nil {
		fmt.Printf("MBR Error: %v\n", err)
	} else {
		fmt.Printf("Disk Signature: 0x%X\n", mbr.DiskSignature)
		for i, pt := range mbr.PartitionTable {
			if pt.PartitionType != 0 {
				fmt.Printf("Partition %d: Type=0x%02x, StartLBA=%d, Size=%d sectors\n",
					i, pt.PartitionType, pt.StartLBA, pt.PartitionSize)
			}
		}
	}

	// Read GPT
	fmt.Println("\n=== GPT ===")
	gpt, err := img.GPT()
	if err != nil {
		fmt.Printf("GPT Error: %v\n", err)
	} else {
		fmt.Printf("GPT GUID: %x\n", gpt.GPTHeader.GUID)
		fmt.Printf("First LBA: %d\n", gpt.GPTHeader.FirstLBA)
		fmt.Printf("Last LBA: %d\n", gpt.GPTHeader.LastLBA)
		fmt.Printf("Partition Count: %d\n", gpt.GPTHeader.PartitionNumber)
	}

	// Read first sector (boot sector)
	fmt.Println("\n=== First Sector (512 bytes) ===")
	sector, err := img.ReadSector(0)
	if err != nil {
		fmt.Printf("Read Error: %v\n", err)
	} else {
		fmt.Printf("First 64 bytes hex: %x\n", sector[:64])
	}
}