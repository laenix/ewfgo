package internal

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

type GPT struct {
	GPTHeader         GPTHeader
	GPTPartitionTable [128]GPTPartitionTable
}

type GPTHeader struct {
	Signature         [8]byte
	Version           uint32
	HeaderSize        uint32
	HeaderCRC         uint32
	Reserved          uint32
	CurrentLBA        uint64
	BackupLBA         uint64
	FirstLBA          uint64
	LastLBA           uint64
	GUID              [16]byte
	PartitionStartLBA uint64
	PartitionNumber   uint32
	PartitionSize     uint32
	PartitionCRC      uint32
	Save              [420]byte
}

type GPTPartitionTable struct {
	PartitionTypeGUID [16]byte
	PartitionGUID     [16]byte
	StartLBA          uint64
	EndLBA            uint64
	AttributeFlag     [8]byte
	PartitionName     [72]byte
}

func ParseGPT(ewf *EWFImage) {
	FirstSector := ewf.ReadAt(int64(ewf.Sectors[0].Address)+76, int64(ewf.Sectors[0].TableEntry[1])-int64(ewf.Sectors[0].TableEntry[0]))
	r, _ := zlib.NewReader(bytes.NewReader(FirstSector))
	var buf bytes.Buffer
	io.Copy(&buf, r)
	var gpt GPT
	binary.Read(bytes.NewReader(buf.Bytes()[512:512+16896]), binary.LittleEndian, &gpt)
	PrintGPT(gpt)
}

func PrintGPT(gpt GPT) {
	// 打印GPTHeader
	fmt.Println("GPTHeader:")
	fmt.Printf("Signature: %s\n", string(gpt.GPTHeader.Signature[:]))
	fmt.Printf("Version: %d\n", gpt.GPTHeader.Version)
	fmt.Printf("HeaderSize: %d\n", gpt.GPTHeader.HeaderSize)
	fmt.Printf("HeaderCRC: %d\n", gpt.GPTHeader.HeaderCRC)
	fmt.Printf("Reserved: %d\n", gpt.GPTHeader.Reserved)
	fmt.Printf("CurrentLBA: %d\n", gpt.GPTHeader.CurrentLBA)
	fmt.Printf("BackupLBA: %d\n", gpt.GPTHeader.BackupLBA)
	fmt.Printf("FirstLBA: %d\n", gpt.GPTHeader.FirstLBA)
	fmt.Printf("LastLBA: %d\n", gpt.GPTHeader.LastLBA)

	// 格式化GUID输出
	fmt.Printf("GUID: ")
	for i := 0; i < 16; i++ {
		fmt.Printf("%02X", gpt.GPTHeader.GUID[i])
		if i == 3 || i == 5 || i == 7 || i == 9 {
			fmt.Printf("-")
		}
	}
	fmt.Println()

	fmt.Printf("PartitionStartLBA: %d\n", gpt.GPTHeader.PartitionStartLBA)
	fmt.Printf("PartitionNumber: %d\n", gpt.GPTHeader.PartitionNumber)
	fmt.Printf("PartitionSize: %d\n", gpt.GPTHeader.PartitionSize)
	fmt.Printf("PartitionCRC: %d\n", gpt.GPTHeader.PartitionCRC)

	// 打印Save区域
	fmt.Printf("Save: ")
	for i := 0; i < len(gpt.GPTHeader.Save); i++ {
		fmt.Printf("%02X", gpt.GPTHeader.Save[i])
		if (i+1)%16 == 0 {
			fmt.Println()
			if i != len(gpt.GPTHeader.Save)-1 {
				fmt.Printf("      ")
			}
		}
	}
	fmt.Println("")

	// 打印GPTPartitionTable
	fmt.Println("GPTPartitionTable:")
	for i := 0; i < 128; i++ {
		entry := gpt.GPTPartitionTable[i]

		// 如果是空分区则跳过
		if entry.StartLBA == 0 && entry.EndLBA == 0 {
			continue
		}

		fmt.Printf("Partition %d:\n", i+1)
		fmt.Printf("  PartitionTypeGUID: ")
		for j := 0; j < 16; j++ {
			fmt.Printf("%02X", entry.PartitionTypeGUID[j])
			if j == 3 || j == 5 || j == 7 || j == 9 {
				fmt.Printf("-")
			}
		}
		fmt.Println()

		fmt.Printf("  PartitionGUID: ")
		for j := 0; j < 16; j++ {
			fmt.Printf("%02X", entry.PartitionGUID[j])
			if j == 3 || j == 5 || j == 7 || j == 9 {
				fmt.Printf("-")
			}
		}
		fmt.Println()

		fmt.Printf("  StartLBA: %d\n", entry.StartLBA)
		fmt.Printf("  EndLBA: %d\n", entry.EndLBA)
		fmt.Printf("  AttributeFlag: %x\n", entry.AttributeFlag)

		// 解码UTF-16分区名
		name := make([]uint16, 0, 36)
		for j := 0; j < len(entry.PartitionName); j += 2 {
			if j+1 >= len(entry.PartitionName) {
				break
			}
			if entry.PartitionName[j] == 0 && entry.PartitionName[j+1] == 0 {
				break
			}
			name = append(name, binary.LittleEndian.Uint16(entry.PartitionName[j:j+2]))
		}
		fmt.Printf("  PartitionName: %s\n", string(utf16.Decode(name)))
		fmt.Println()
	}
}
