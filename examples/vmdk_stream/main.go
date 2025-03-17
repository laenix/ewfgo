package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	ewf "github.com/laenix/ewfgo"
)

func main() {
	// 解析命令行参数
	inputFile := flag.String("i", "", "输入的E01文件路径")
	outputDir := flag.String("o", "", "输出目录路径")
	vmName := flag.String("n", "", "虚拟机名称")
	vmwarePath := flag.String("vmware", "", "VMware Workstation可执行文件路径")
	flag.Parse()

	// 检查必要参数
	if *inputFile == "" {
		fmt.Println("请指定输入文件路径，使用 -i 参数")
		os.Exit(1)
	}

	if *outputDir == "" {
		fmt.Println("请指定输出目录路径，使用 -o 参数")
		os.Exit(1)
	}

	if *vmName == "" {
		// 使用输入文件名作为虚拟机名称
		*vmName = strings.TrimSuffix(filepath.Base(*inputFile), filepath.Ext(*inputFile))
	}

	// 检查输入文件是否存在
	if _, err := os.Stat(*inputFile); os.IsNotExist(err) {
		fmt.Printf("输入文件不存在: %s\n", *inputFile)
		os.Exit(1)
	}

	// 创建输出目录
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Printf("创建输出目录失败: %v\n", err)
		os.Exit(1)
	}

	// 检查是否为E01文件
	if !ewf.IsEWFFile(*inputFile) {
		fmt.Printf("输入文件不是有效的E01文件: %s\n", *inputFile)
		os.Exit(1)
	}

	// 创建EWF镜像对象
	image := ewf.NewWithFilePath(*inputFile)

	// 解析EWF镜像
	fmt.Println("正在解析E01文件...")
	if err := image.Initialize(); err != nil {
		fmt.Printf("解析E01文件失败: %v\n", err)
		os.Exit(1)
	}
	defer image.Close()

	// 虚拟挂载镜像
	fmt.Println("正在虚拟挂载镜像...")
	if err := image.VirtualMount(); err != nil {
		fmt.Printf("虚拟挂载失败: %v\n", err)
		os.Exit(1)
	}

	// 设置输出文件路径
	vmdkPath := filepath.Join(*outputDir, *vmName+".vmdk")
	vmxPath := filepath.Join(*outputDir, *vmName+".vmx")

	// 流式转换为VMDK
	fmt.Println("正在转换为VMDK...")
	if err := image.StreamToVMDK(vmdkPath); err != nil {
		fmt.Printf("转换VMDK失败: %v\n", err)
		os.Exit(1)
	}

	// 生成VMX配置文件
	fmt.Println("正在生成VMX配置文件...")
	if err := image.GenerateVMX(vmxPath); err != nil {
		fmt.Printf("生成VMX配置失败: %v\n", err)
		os.Exit(1)
	}

	// 打印完成信息
	fmt.Println("\n转换完成！")
	fmt.Printf("VMDK文件: %s\n", vmdkPath)
	fmt.Printf("VMX文件: %s\n", vmxPath)

	// 打印系统信息
	if sysInfo := image.GetSystemInfo(); sysInfo != nil {
		fmt.Println("\n系统信息:")
		fmt.Printf("操作系统: %s\n", map[bool]string{true: "Windows", false: "Linux"}[sysInfo.IsWindows])
		fmt.Printf("版本: %s\n", sysInfo.Version)
		fmt.Printf("架构: %s\n", sysInfo.Arch)
		if len(sysInfo.Users) > 0 {
			fmt.Println("\n用户列表:")
			for _, user := range sysInfo.Users {
				fmt.Printf("- %s (管理员: %v)\n", user.Username, user.IsAdmin)
			}
		}
	}

	// 自动查找VMware Workstation路径
	if *vmwarePath == "" {
		*vmwarePath = findVMwarePath()
	}

	// 如果找到VMware路径，尝试启动虚拟机
	if *vmwarePath != "" {
		fmt.Println("\n正在启动VMware Workstation...")
		cmd := exec.Command(*vmwarePath, vmxPath)
		if err := cmd.Start(); err != nil {
			fmt.Printf("启动VMware失败: %v\n", err)
		} else {
			fmt.Println("已成功启动VMware Workstation！")
		}
	} else {
		fmt.Println("\n使用说明:")
		fmt.Println("1. 打开VMware Workstation/Player")
		fmt.Println("2. 选择'打开虚拟机'")
		fmt.Printf("3. 选择生成的VMX文件: %s\n", vmxPath)
		fmt.Println("4. 启动虚拟机")
	}
}

// findVMwarePath 查找VMware Workstation的可执行文件路径
func findVMwarePath() string {
	if runtime.GOOS == "windows" {
		// 常见的Windows安装路径
		paths := []string{
			"C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmware.exe",
			"C:\\Program Files\\VMware\\VMware Workstation\\vmware.exe",
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	} else if runtime.GOOS == "linux" {
		// Linux上的常见路径
		paths := []string{
			"/usr/bin/vmware",
			"/usr/local/bin/vmware",
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	return ""
}
