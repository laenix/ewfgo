package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ewf "github.com/laenix/ewfgo"
)

func main() {
	// 命令行参数
	var (
		filePath     string
		startSector  uint64
		count        uint64
		outputPath   string
		format       string
		showProgress bool
	)

	flag.StringVar(&filePath, "file", "", "EWF文件路径（必须）")
	flag.Uint64Var(&startSector, "start", 0, "起始扇区号")
	flag.Uint64Var(&count, "count", 1, "扇区数量")
	flag.StringVar(&outputPath, "output", "", "输出文件路径")
	flag.StringVar(&format, "format", "hex", "输出格式：hex（十六进制）、raw（原始数据）、ascii（ASCII）")
	flag.BoolVar(&showProgress, "progress", true, "显示进度")
	flag.Parse()

	if filePath == "" {
		fmt.Println("用法:")
		fmt.Printf("  %s -file=<ewf文件路径> [-start=<起始扇区>] [-count=<扇区数量>] [-output=<输出文件>] [-format=<输出格式>] [-progress=<true|false>]\n", os.Args[0])
		os.Exit(1)
	}

	// 检查EWF文件
	if !ewf.IsEWFFile(filePath) {
		fmt.Println("错误: 提供的文件不是有效的EWF格式")
		os.Exit(1)
	}

	// 创建EWF镜像对象
	ewfImage := ewf.NewWithFilePath(filePath)

	// 解析EWF文件
	fmt.Println("正在解析EWF文件...")
	startTime := time.Now()
	if err := ewfImage.Parse(); err != nil {
		fmt.Printf("解析EWF文件失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("EWF文件解析完成，耗时: %v\n", time.Since(startTime))

	// 检查扇区范围
	if startSector >= ewfImage.GetSectorCount() {
		fmt.Printf("错误: 起始扇区号超出范围 (0-%d)\n", ewfImage.GetSectorCount()-1)
		os.Exit(1)
	}

	if startSector+count > ewfImage.GetSectorCount() {
		count = ewfImage.GetSectorCount() - startSector
		fmt.Printf("警告: 调整扇区数量为 %d\n", count)
	}

	// 读取扇区数据
	fmt.Printf("正在读取扇区 %d 到 %d...\n", startSector, startSector+count-1)

	// 分批读取扇区以显示进度
	const batchSize uint64 = 1000
	var data []byte
	for i := uint64(0); i < count; i += batchSize {
		currentBatch := batchSize
		if i+batchSize > count {
			currentBatch = count - i
		}

		batchData, err := ewfImage.ReadSectors(startSector+i, currentBatch)
		if err != nil {
			fmt.Printf("\n读取扇区失败: %v\n", err)
			os.Exit(1)
		}
		data = append(data, batchData...)

		if showProgress {
			progress := float64(i+currentBatch) / float64(count) * 100
			fmt.Printf("\r进度: %.1f%% (%d/%d 扇区)", progress, i+currentBatch, count)
		}
	}
	fmt.Println()

	// 处理输出
	if outputPath != "" {
		// 确保输出目录存在
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			fmt.Printf("创建输出目录失败: %v\n", err)
			os.Exit(1)
		}

		// 写入文件
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			fmt.Printf("写入输出文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("数据已写入文件: %s (%d 字节)\n", outputPath, len(data))
	} else {
		// 根据格式显示数据
		switch format {
		case "hex":
			displayHex(data)
		case "ascii":
			displayASCII(data)
		case "raw":
			fmt.Print(string(data))
		default:
			fmt.Printf("未知的输出格式: %s\n", format)
			os.Exit(1)
		}
	}
}

func displayHex(data []byte) {
	for i := 0; i < len(data); i += 16 {
		// 显示偏移量
		fmt.Printf("%08x  ", i)

		// 显示十六进制
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		// 显示ASCII
		fmt.Print(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			if data[i+j] >= 32 && data[i+j] <= 126 {
				fmt.Printf("%c", data[i+j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

func displayASCII(data []byte) {
	for _, b := range data {
		if b >= 32 && b <= 126 {
			fmt.Printf("%c", b)
		} else {
			fmt.Print(".")
		}
	}
	fmt.Println()
}
