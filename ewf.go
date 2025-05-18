package ewf

import (
	"fmt"

	"github.com/laenix/ewfgo/internal"
)

func Run() {
	filepath := "E:/qz/检材_服务器.E01"
	ewf := &internal.EWFImage{}
	ewf.Open(filepath)
	// fmt.Println(ewf.ReadAt(0, 13))
	// fmt.Printf("%x\n", ewf.ReadAt(46678322817, 76))
	ewf.ReadSections()
	// for k, v := range ewf.Sections {
	// 	fmt.Println(k)
	// 	fmt.Println(v)
	// 	fmt.Printf("%d %s %d %d\n", v.Address, v.SectionTypeDefinition, v.NextOffset, v.SectionSize)
	// }
	err := ewf.ParseSections()
	fmt.Println(err)
	// for k, v := range ewf.Headers {
	// 	fmt.Println(k)
	// 	fmt.Println(v)
	// 	fmt.Printf("描述: %s 案件编号: %s 证据编号: %s 检查员姓名: %s 备注信息: %s 存储介质型号: %s 介质序列号: %s 版本号:%s 平台信息:%s 获取日期和时间:%s 系统日期和时间:%s 密码哈希值:%s 未知字段:%s \n", v.L3_a, v.L3_c, v.L3_n, v.L3_e, v.L3_t, v.L3_md, v.L3_sn, v.L3_av, v.L3_ov, v.L3_m, v.L3_u, v.L3_p, v.L3_dc)
	// }

	// for k, v := range ewf.Volumes {
	// 	fmt.Println(k)
	// 	fmt.Println(v)
	// 	fmt.Printf("保留:%d 数据块数量:%d 每块包含的扇区数量:%d 每扇区字节数:%d 扇区总数:%d 保留:%s 填充:%s 签名:%s 校验和:%x", v.Reserved, v.SegmentChunk, v.ChunkSectors, v.SectorsBytes, v.SectorCounts, v.Reserved2, v.Padding, v.Signature, v.CheckSum)
	// }
	// for k, v := range ewf.DiskSMART {
	// 	fmt.Println(k)
	// 	fmt.Println(v)
	// 	fmt.Printf("媒体类型: %d\n", v.MediaType)
	// 	fmt.Printf("块数: %d\n", v.ChunkCount)
	// 	fmt.Printf("每个块的扇区数: %d\n", v.ChunkSectors)
	// 	fmt.Printf("每个扇区的字节数: %d\n", v.SectorBytes)
	// 	fmt.Printf("总扇区数: %d\n", v.SectorsCount)
	// 	fmt.Printf("CHS柱面数: %d\n", v.CHScylinders)
	// 	fmt.Printf("CHS磁头数: %d\n", v.CHSheads)
	// 	fmt.Printf("CHS扇区数: %d\n", v.CHSsectors)
	// 	fmt.Printf("媒体标志: %d\n", v.MediaFlag)
	// 	fmt.Printf("PALM卷起始扇区: %d\n", v.PALMVolumeStartSector)
	// 	fmt.Printf("SMART日志起始扇区: %d\n", v.SMARTLogsStartSector)
	// 	fmt.Printf("压缩级别: %d\n", v.CompressionLevel)
	// 	fmt.Printf("扇区错误粒度: %d\n", v.SectorErrorGranularity)

	// 	// 输出GUID/UUID（16字节）
	// 	fmt.Printf("段文件集标识符(GUID/UUID): %02x\n", v.SegmentFileSetIdentifier)

	// 	// 输出签名（5字节）
	// 	fmt.Printf("标记: %s\n", string(v.Signature[:]))
	// 	fmt.Printf("校验和: %d (0x%x)\n", v.CheckSum, v.CheckSum)
	// }
	// fmt.Println(ewf.ReadAt(1932+76, 64))
	fmt.Println("sectors len", len(ewf.SectorsAddress))
	fmt.Println("tables len", len(ewf.TableAddress))
	fmt.Println(ewf.Sectors)
	// 1932 32095 76
	// fmt.Println(ewf.ReadAt(1932+76, 32095-76))
}
