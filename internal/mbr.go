package internal

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
)

type MBR struct {
	BootCode       [440]byte         // 引导代码（GRUB/Windows Boot Manager）
	DiskSignature  uint32            // 磁盘签名（Windows NTFS 等使用）
	Reserved       uint16            // 保留字段（通常 0x0000）
	PartitionTable [4]PartitionEntry // 4个分区表项（每项16字节）
	BootSignature  uint16            // 结束标志（0x55AA）
}

type PartitionEntry struct {
	BootFlag      uint8   // 0x80=可启动，0x00=非启动
	StartCHS      [3]byte // CHS 起始地址（传统BIOS）
	PartitionType uint8   // 分区类型标识（0x07=NTFS，0x83=Linux…）
	EndCHS        [3]byte // CHS 结束地址
	StartLBA      uint32  // 分区起始扇区（LBA逻辑寻址）
	PartitionSize uint32  // 分区大小（扇区数）
}

func ParseMBR(ewf *EWFImage) {
	FirstSector := ewf.ReadAt(int64(ewf.Sectors[0].Address)+76, int64(ewf.Sectors[0].TableEntry[1])-int64(ewf.Sectors[0].TableEntry[0]))
	r, _ := zlib.NewReader(bytes.NewReader(FirstSector))
	var buf bytes.Buffer
	io.Copy(&buf, r)
	var mbr MBR
	binary.Read(bytes.NewReader(buf.Bytes()[:512]), binary.LittleEndian, &mbr)
	PrintMBR(mbr)
}

func PrintMBR(mbr MBR) {
	// 打印BootCode (前16字节作为示例)
	fmt.Println("BootCode (前16字节):")
	for i := 0; i < 16; i++ {
		fmt.Printf("%02X ", mbr.BootCode[i])
		if (i+1)%8 == 0 {
			fmt.Println()
		}
	}
	fmt.Println("... (共440字节)")

	// 打印DiskSignature
	fmt.Printf("DiskSignature: 0x%08X\n", mbr.DiskSignature)

	// 打印Reserved
	fmt.Printf("Reserved: 0x%04X\n", mbr.Reserved)

	// 打印PartitionTable
	fmt.Println("\nPartitionTable:")
	for i := 0; i < 4; i++ {
		entry := mbr.PartitionTable[i]
		fmt.Printf("\nPartition %d:\n", i+1)
		fmt.Printf("  BootFlag: 0x%02X", entry.BootFlag)
		if entry.BootFlag == 0x80 {
			fmt.Print(" (可启动)\n")
		} else {
			fmt.Print(" (非启动)\n")
		}

		// 打印CHS地址
		fmt.Printf("  StartCHS: %02X %02X %02X\n",
			entry.StartCHS[0], entry.StartCHS[1], entry.StartCHS[2])
		fmt.Printf("  PartitionType: 0x%02X", entry.PartitionType)
		switch entry.PartitionType {
		case 0x07:
			fmt.Print(" (NTFS/exFAT)\n")
		case 0x83:
			fmt.Print(" (Linux)\n")
		case 0xEE:
			fmt.Print(" (GPT保护分区)\n")
		default:
			fmt.Print(" (其他类型)\n")
		}
		fmt.Printf("  EndCHS: %02X %02X %02X\n",
			entry.EndCHS[0], entry.EndCHS[1], entry.EndCHS[2])
		fmt.Printf("  StartLBA: %d\n", entry.StartLBA)
		fmt.Printf("  PartitionSize: %d sectors\n", entry.PartitionSize)
	}

	// 打印BootSignature
	fmt.Printf("\nBootSignature: 0x%04X", mbr.BootSignature)
	if mbr.BootSignature == 0x55AA {
		fmt.Print(" (有效MBR)\n")
	} else {
		fmt.Print(" (无效MBR! 必须为0x55AA)\n")
	}
}
