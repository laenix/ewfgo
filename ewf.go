package ewf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/laenix/ewfgo/internal"
)

func Run() {
	// filepath := "E:/qz/PC-disk.E01"
	// // filepath := "E:/qz/24CS_Phone.E01"
	// // filepath := "E:/qz/检材_服务器.E01"
	// ewf := &internal.EWFImage{}
	// ewf.Open(filepath)
	// ewf.ReadSections()
	// ewf.ParseSections()
	// internal.ParseMBR(ewf)
	// internal.ParseGPT(ewf)
	testData := "33C08ED0BC007C8EC08ED8BE007CBF0006B90002FCF3A450681C06CBFBB90400BDBE07807E00007C0B0F850E0183C510E2F1CD1888560055C6461105C6461000B441BBAA55CD135D720F81FB55AA7509F7C101007403FE46106660807E1000742666680000000066FF760868000068007C680100681000B4428A56008BF4CD139F83C4109EEB14B80102BB007C8A56008A76018A4E028A6E03CD136661731CFE4E11750C807E00800F848A00B280EB845532E48A5600CD135DEB9E813EFE7D55AA756EFF7600E88D007517FAB0D1E664E88300B0DFE660E87C00B0FFE664E87500FBB800BBCD1A6623C0753B6681FB54435041753281F90201722C666807BB00006668000200006668080000006653665366556668000000006668007C0000666168000007CD1A5A32F6EA007C0000CD18A0B707EB08A0B607EB03A0B50732E40500078BF0AC3C007409BB0700B40ECD10EBF2F4EBFD2BC9E464EB002402E0F82402C3496E76616C696420706172746974696F6E207461626C65004572726F72206C6F6164696E67206F7065726174696E672073797374656D004D697373696E67206F7065726174696E672073797374656D000000637B9AE760B141000080202100077F39060008000000900100007F3A0607FEFFFF00980100A21FFB0400FEFFFF27FEFFFF00B8FC040040120000FEFFFF0FFEFFFF00F80E050000710255AA"
	data, err := hex.DecodeString(testData)
	if err != nil {
		fmt.Println(err)
	}
	var mbr internal.MBR
	binary.Read(bytes.NewReader(data), binary.LittleEndian, &mbr)
	internal.PrintMBR(mbr)
}

// func Run() {
// 	filepath := "E:/qz/PC-disk.E01"
// 	// filepath := "E:/qz/24CS_Phone.E01"
// 	// filepath := "E:/qz/检材_服务器.E01"
// 	ewf := &internal.EWFImage{}
// 	ewf.Open(filepath)
// 	// fmt.Println(ewf.ReadAt(0, 13))
// 	// fmt.Printf("%x\n", ewf.ReadAt(46678322817, 76))
// 	ewf.ReadSections()
// 	// for k, v := range ewf.Sections {
// 	// 	fmt.Println(k)
// 	// 	fmt.Println(v)
// 	// 	fmt.Printf("%d %s %d %d\n", v.Address, v.SectionTypeDefinition, v.NextOffset, v.SectionSize)
// 	// }
// 	err := ewf.ParseSections()
// 	fmt.Println(err)
// 	// for k, v := range ewf.Headers {
// 	// 	fmt.Println(k)
// 	// 	fmt.Println(v)
// 	// 	fmt.Printf("描述: %s 案件编号: %s 证据编号: %s 检查员姓名: %s 备注信息: %s 存储介质型号: %s 介质序列号: %s 版本号:%s 平台信息:%s 获取日期和时间:%s 系统日期和时间:%s 密码哈希值:%s 未知字段:%s \n", v.L3_a, v.L3_c, v.L3_n, v.L3_e, v.L3_t, v.L3_md, v.L3_sn, v.L3_av, v.L3_ov, v.L3_m, v.L3_u, v.L3_p, v.L3_dc)
// 	// }

// 	for k, v := range ewf.DiskSMART {
// 		fmt.Println(k)
// 		fmt.Println(v)
// 		fmt.Printf("媒体类型: %d\n", v.MediaType)
// 		fmt.Printf("块数: %d\n", v.ChunkCount)
// 		fmt.Printf("每个块的扇区数: %d\n", v.ChunkSectors)
// 		fmt.Printf("每个扇区的字节数: %d\n", v.SectorBytes)
// 		fmt.Printf("总扇区数: %d\n", v.SectorsCount)
// 		fmt.Printf("CHS柱面数: %d\n", v.CHScylinders)
// 		fmt.Printf("CHS磁头数: %d\n", v.CHSheads)
// 		fmt.Printf("CHS扇区数: %d\n", v.CHSsectors)
// 		fmt.Printf("媒体标志: %d\n", v.MediaFlag)
// 		fmt.Printf("PALM卷起始扇区: %d\n", v.PALMVolumeStartSector)
// 		fmt.Printf("SMART日志起始扇区: %d\n", v.SMARTLogsStartSector)
// 		fmt.Printf("压缩级别: %d\n", v.CompressionLevel)
// 		fmt.Printf("扇区错误粒度: %d\n", v.SectorErrorGranularity)

// 		// 输出GUID/UUID（16字节）
// 		fmt.Printf("段文件集标识符(GUID/UUID): %02x\n", v.SegmentFileSetIdentifier)

// 		// 输出签名（5字节）
// 		fmt.Printf("标记: %s\n", string(v.Signature[:]))
// 		fmt.Printf("校验和: %d (0x%x)\n", v.CheckSum, v.CheckSum)
// 	}
// 	// fmt.Println(ewf.ReadAt(1932+76, 64))
// 	fmt.Println("sectors len", len(ewf.SectorsAddress))
// 	fmt.Println("tables len", len(ewf.TableAddress))
// 	// fmt.Println(ewf.Sectors)
// 	// 1932 32095 76
// 	// fmt.Println(ewf.ReadAt(1641+76, 2559-76))
// 	// fmt.Println(int64(ewf.Sectors[0].Address))
// 	// fmt.Println(int64(ewf.Sectors[0].TableEntry[0]))
// 	FirstSector := ewf.ReadAt(int64(ewf.Sectors[0].Address)+76, int64(ewf.Sectors[0].TableEntry[1])-int64(ewf.Sectors[0].TableEntry[0]))
// 	r, _ := zlib.NewReader(bytes.NewReader(FirstSector))
// 	var buf bytes.Buffer
// 	io.Copy(&buf, r)
// 	var mbr internal.MBR
// 	binary.Read(bytes.NewReader(buf.Bytes()[:512]), binary.LittleEndian, &mbr)
// 	fmt.Println("mbr", mbr)
// 	fmt.Printf("bootcode: %s DiskSignature: %d BootSignature %x\n", mbr.BootCode, mbr.DiskSignature, mbr.BootSignature)
// 	for _, v := range mbr.PartitionTable {
// 		fmt.Printf("BootFlag: %x PartitionType: %x PartitionSize:%x\n", v.BootFlag, v.PartitionType, v.PartitionSize)
// 	}
// 	var gpt internal.GPT
// 	binary.Read(bytes.NewReader(buf.Bytes()[512:512+16896]), binary.LittleEndian, &gpt)
// 	//
// 	// 打印GPTHeader
// 	fmt.Println("GPTHeader:")
// 	fmt.Printf("Signature: %s\n", string(gpt.GPTHeader.Signature[:]))
// 	fmt.Printf("Version: %d\n", gpt.GPTHeader.Version)
// 	fmt.Printf("HeaderSize: %d\n", gpt.GPTHeader.HeaderSize)
// 	fmt.Printf("HeaderCRC: %d\n", gpt.GPTHeader.HeaderCRC)
// 	fmt.Printf("Reserved: %d\n", gpt.GPTHeader.Reserved)
// 	fmt.Printf("CurrentLBA: %d\n", gpt.GPTHeader.CurrentLBA)
// 	fmt.Printf("BackupLBA: %d\n", gpt.GPTHeader.BackupLBA)
// 	fmt.Printf("FirstLBA: %d\n", gpt.GPTHeader.FirstLBA)
// 	fmt.Printf("LastLBA: %d\n", gpt.GPTHeader.LastLBA)

// 	// 格式化GUID输出
// 	fmt.Printf("GUID: ")
// 	for i := 0; i < 16; i++ {
// 		fmt.Printf("%02X", gpt.GPTHeader.GUID[i])
// 		if i == 3 || i == 5 || i == 7 || i == 9 {
// 			fmt.Printf("-")
// 		}
// 	}
// 	fmt.Println()

// 	fmt.Printf("PartitionStartLBA: %d\n", gpt.GPTHeader.PartitionStartLBA)
// 	fmt.Printf("PartitionNumber: %d\n", gpt.GPTHeader.PartitionNumber)
// 	fmt.Printf("PartitionSize: %d\n", gpt.GPTHeader.PartitionSize)
// 	fmt.Printf("PartitionCRC: %d\n", gpt.GPTHeader.PartitionCRC)

// 	// 打印Save区域
// 	fmt.Printf("Save: ")
// 	for i := 0; i < len(gpt.GPTHeader.Save); i++ {
// 		fmt.Printf("%02X", gpt.GPTHeader.Save[i])
// 		if (i+1)%16 == 0 {
// 			fmt.Println()
// 			if i != len(gpt.GPTHeader.Save)-1 {
// 				fmt.Printf("      ")
// 			}
// 		}
// 	}
// 	fmt.Println("\n")

// 	// 打印GPTPartitionTable
// 	fmt.Println("GPTPartitionTable:")
// 	for i := 0; i < 128; i++ {
// 		entry := gpt.GPTPartitionTable[i]

// 		// 如果是空分区则跳过
// 		if entry.StartLBA == 0 && entry.EndLBA == 0 {
// 			continue
// 		}

// 		fmt.Printf("Partition %d:\n", i+1)
// 		fmt.Printf("  PartitionTypeGUID: ")
// 		for j := 0; j < 16; j++ {
// 			fmt.Printf("%02X", entry.PartitionTypeGUID[j])
// 			if j == 3 || j == 5 || j == 7 || j == 9 {
// 				fmt.Printf("-")
// 			}
// 		}
// 		fmt.Println()

// 		fmt.Printf("  PartitionGUID: ")
// 		for j := 0; j < 16; j++ {
// 			fmt.Printf("%02X", entry.PartitionGUID[j])
// 			if j == 3 || j == 5 || j == 7 || j == 9 {
// 				fmt.Printf("-")
// 			}
// 		}
// 		fmt.Println()

// 		fmt.Printf("  StartLBA: %d\n", entry.StartLBA)
// 		fmt.Printf("  EndLBA: %d\n", entry.EndLBA)
// 		fmt.Printf("  AttributeFlag: %x\n", entry.AttributeFlag)

// 		// 解码UTF-16分区名
// 		name := make([]uint16, 0, 36)
// 		for j := 0; j < len(entry.PartitionName); j += 2 {
// 			if j+1 >= len(entry.PartitionName) {
// 				break
// 			}
// 			if entry.PartitionName[j] == 0 && entry.PartitionName[j+1] == 0 {
// 				break
// 			}
// 			name = append(name, binary.LittleEndian.Uint16(entry.PartitionName[j:j+2]))
// 		}
// 		fmt.Printf("  PartitionName: %s\n", string(utf16.Decode(name)))
// 		fmt.Println()
// 	}
// 	//

// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[0]), int64(ewf.Sectors[0].TableEntry[2])-int64(ewf.Sectors[0].TableEntry[1])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[31]), int64(ewf.Sectors[0].TableEntry[33])-int64(ewf.Sectors[0].TableEntry[32])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[32]), int64(ewf.Sectors[0].TableEntry[34])-int64(ewf.Sectors[0].TableEntry[33])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[33]), int64(ewf.Sectors[0].TableEntry[35])-int64(ewf.Sectors[0].TableEntry[34])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[34]), int64(ewf.Sectors[0].TableEntry[36])-int64(ewf.Sectors[0].TableEntry[35])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[5]), int64(ewf.Sectors[0].TableEntry[7])-int64(ewf.Sectors[0].TableEntry[6])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[6]), int64(ewf.Sectors[0].TableEntry[8])-int64(ewf.Sectors[0].TableEntry[7])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[7]), int64(ewf.Sectors[0].TableEntry[9])-int64(ewf.Sectors[0].TableEntry[8])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[8]), int64(ewf.Sectors[0].TableEntry[10])-int64(ewf.Sectors[0].TableEntry[9])))
// 	// fmt.Println(ewf.ReadAt(int64(ewf.Sectors[0].Address)+76+int64(ewf.Sectors[0].TableEntry[9]), int64(ewf.Sectors[0].TableEntry[11])-int64(ewf.Sectors[0].TableEntry[10])))

// }
