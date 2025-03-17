package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	ewf "github.com/laenix/ewfgo"
)

func main() {
	// 命令行参数
	var (
		filePath    string
		action      string
		startSector uint64
		count       uint64
		outputPath  string
		fsPath      string // 文件系统路径
		vmdkPath    string // VMDK路径
	)

	flag.StringVar(&filePath, "file", "", "EWF文件路径（必须）")
	flag.StringVar(&action, "action", "info", "操作：info（显示信息）、extract（提取扇区）、list（列出部分）、fs（文件系统）、vmdk（流式VMDK）")
	flag.Uint64Var(&startSector, "start", 0, "起始扇区号（仅用于extract）")
	flag.Uint64Var(&count, "count", 1, "扇区数量（仅用于extract）")
	flag.StringVar(&outputPath, "output", "", "输出文件路径（仅用于extract和fs）")
	flag.StringVar(&fsPath, "path", "/", "文件系统路径（仅用于fs）")
	flag.StringVar(&vmdkPath, "vmdk", "", "VMDK路径（仅用于vmdk）")
	flag.Parse()

	if filePath == "" {
		fmt.Println("请提供EWF文件路径:")
		fmt.Printf("用法: %s -file=<ewf文件路径> [-action=<操作>] [-start=<起始扇区>] [-count=<扇区数量>] [-output=<输出文件>] [-path=<文件系统路径>] [-vmdk=<VMDK路径>]\n", os.Args[0])
		os.Exit(1)
	}

	// 检查是否为有效的EWF文件
	if !ewf.IsEWFFile(filePath) {
		fmt.Println("错误: 提供的文件不是有效的EWF格式")
		os.Exit(1)
	}

	fmt.Println("这是一个有效的EWF文件")

	// 创建并解析EWF镜像
	ewfimage := ewf.NewWithFilePath(filePath)
	err := ewfimage.Parse()
	if err != nil {
		fmt.Printf("解析EWF文件失败: %v\n", err)
		os.Exit(1)
	}

	// 根据操作类型执行相应的操作
	switch action {
	case "info":
		displayInfo(ewfimage)
	case "extract":
		extractSectors(ewfimage, startSector, count, outputPath)
	case "list":
		listSections(ewfimage)
	case "fs":
		handleFileSystem(ewfimage, fsPath, outputPath)
	case "vmdk":
		handleVMDK(ewfimage, vmdkPath)
	default:
		fmt.Printf("未知的操作类型: %s\n", action)
		os.Exit(1)
	}
}

// displayInfo 显示EWF镜像的基本信息
func displayInfo(ewfimage *ewf.EWFImage) {
	fmt.Println("\n==== EWF镜像信息 ====")
	fmt.Println(ewfimage)

	// 显示表信息
	if len(ewfimage.Tables) > 0 {
		table := ewfimage.Tables[0]
		fmt.Printf("\n第一个表内容 (共%d项):\n", table.EntryNumber)
		displayCount := 5
		if table.EntryNumber < 5 {
			displayCount = int(table.EntryNumber)
		}

		for i := 0; i < displayCount; i++ {
			fmt.Printf("  表项 %d: %s\n", i, &table.Entries[i])
		}
		fmt.Println("  ...")
	}

	// 尝试检测文件系统类型
	fs, err := ewfimage.GetFileSystem()
	if err != nil {
		fmt.Printf("\n检测文件系统失败: %v\n", err)
	} else if fs != nil {
		fmt.Printf("\n检测到文件系统类型: %s\n", fs.GetType())
	} else {
		fmt.Println("\n未检测到已知的文件系统类型")
	}
}

// listSections 列出所有部分
func listSections(ewfimage *ewf.EWFImage) {
	fmt.Println("\n==== EWF部分列表 ====")
	for i, section := range ewfimage.Sections {
		fmt.Printf("%3d: %s\n", i, section)
	}
}

// extractSectors 提取指定扇区并保存到文件
func extractSectors(ewfimage *ewf.EWFImage, startSector, count uint64, outputPath string) {
	if outputPath == "" {
		outputPath = fmt.Sprintf("sector_%d_%d.bin", startSector, count)
	}

	fmt.Printf("\n==== 提取扇区 ====\n")
	fmt.Printf("起始扇区: %d\n", startSector)
	fmt.Printf("扇区数量: %d\n", count)
	fmt.Printf("输出文件: %s\n", outputPath)

	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			fmt.Printf("创建输出目录失败: %v\n", err)
			return
		}
	}

	// 读取扇区
	data, err := ewfimage.ReadSectors(startSector, count)
	if err != nil {
		fmt.Printf("读取扇区失败: %v\n", err)
		return
	}

	// 写入文件
	err = os.WriteFile(outputPath, data, 0644)
	if err != nil {
		fmt.Printf("写入输出文件失败: %v\n", err)
		return
	}

	fmt.Printf("成功提取 %d 个扇区，总大小: %s\n",
		count, formatByteSize(uint64(len(data))))
}

// handleFileSystem 处理文件系统相关操作
func handleFileSystem(ewfimage *ewf.EWFImage, path string, outputPath string) {
	fmt.Println("\n==== 文件系统操作 ====")

	// 获取文件系统
	fs, err := ewfimage.GetFileSystem()
	if err != nil {
		fmt.Printf("获取文件系统失败: %v\n", err)
		return
	}

	if fs == nil {
		fmt.Println("未检测到已知的文件系统")
		return
	}

	fmt.Printf("文件系统类型: %s\n", fs.GetType())

	// 如果只是显示根目录
	if path == "/" && outputPath == "" {
		root, err := fs.GetRootDirectory()
		if err != nil {
			fmt.Printf("获取根目录失败: %v\n", err)
			return
		}

		// 列出根目录内容
		entries, err := root.GetEntries()
		if err != nil {
			fmt.Printf("读取根目录内容失败: %v\n", err)
			return
		}

		fmt.Printf("\n根目录包含 %d 个条目:\n", len(entries))
		for i, entry := range entries {
			typeStr := "文件"
			if entry.IsDirectory() {
				typeStr = "目录"
			}

			fmt.Printf("%3d: %-40s [%s] %s\n",
				i, entry.GetName(), typeStr, formatByteSize(entry.GetSize()))
		}
		return
	}

	// 处理提取文件或者列出目录
	if path != "" {
		isDir := false

		// 先尝试作为目录访问
		dir, err := fs.GetDirectoryByPath(path)
		if err == nil {
			isDir = true
			fmt.Printf("目录: %s\n", path)

			entries, err := dir.GetEntries()
			if err != nil {
				fmt.Printf("读取目录内容失败: %v\n", err)
				return
			}

			fmt.Printf("\n目录包含 %d 个条目:\n", len(entries))
			for i, entry := range entries {
				typeStr := "文件"
				if entry.IsDirectory() {
					typeStr = "目录"
				}

				fmt.Printf("%3d: %-40s [%s] %s\n",
					i, entry.GetName(), typeStr, formatByteSize(entry.GetSize()))
			}
		}

		// 如果不是目录，尝试作为文件访问
		if !isDir {
			file, err := fs.GetFileByPath(path)
			if err != nil {
				fmt.Printf("访问路径失败: %v\n", err)
				return
			}

			fmt.Printf("文件: %s\n", path)
			fmt.Printf("大小: %s\n", formatByteSize(file.GetSize()))

			// 如果提供了输出路径，提取文件
			if outputPath != "" {
				fmt.Printf("正在提取到: %s\n", outputPath)

				// 确保输出目录存在
				dir := filepath.Dir(outputPath)
				if dir != "." && dir != "" {
					err := os.MkdirAll(dir, 0755)
					if err != nil {
						fmt.Printf("创建输出目录失败: %v\n", err)
						return
					}
				}

				// 读取文件内容
				content, err := file.ReadAll()
				if err != nil {
					fmt.Printf("读取文件内容失败: %v\n", err)
					return
				}

				// 写入输出文件
				err = os.WriteFile(outputPath, content, 0644)
				if err != nil {
					fmt.Printf("写入输出文件失败: %v\n", err)
					return
				}

				fmt.Printf("成功提取文件，大小: %s\n", formatByteSize(uint64(len(content))))
			}
		}
	}
}

// formatByteSize 格式化字节大小为人类可读形式
func formatByteSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d 字节", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// handleVMDK 处理VMDK相关操作
func handleVMDK(ewf *ewf.EWFImage, vmdkPath string) {
	// 检查是否已经解析
	if ewf.DiskInfo == nil {
		fmt.Println("错误: EWF镜像未解析")
		os.Exit(1)
	}

	// 流式转换为VMDK
	fmt.Printf("开始转换VMDK: %s\n", vmdkPath)
	if err := ewf.StreamToVMDK(vmdkPath); err != nil {
		fmt.Printf("转换VMDK失败: %v\n", err)
		os.Exit(1)
	}

	// 生成VMX配置文件
	vmxPath := vmdkPath + ".vmx"
	fmt.Printf("生成VMX配置文件: %s\n", vmxPath)
	if err := ewf.GenerateVMX(vmxPath); err != nil {
		fmt.Printf("生成VMX配置失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("VMDK转换和VMX生成完成")
}
