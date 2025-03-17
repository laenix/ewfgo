package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/filesystem"
)

func main() {
	// 命令行参数
	var (
		filePath     string
		fsPath       string
		outputPath   string
		recursive    bool
		showProgress bool
		workers      int
	)

	flag.StringVar(&filePath, "file", "", "EWF文件路径（必须）")
	flag.StringVar(&fsPath, "path", "/", "文件系统路径")
	flag.StringVar(&outputPath, "output", "", "输出目录路径")
	flag.BoolVar(&recursive, "recursive", false, "是否递归处理目录")
	flag.BoolVar(&showProgress, "progress", true, "显示进度")
	flag.IntVar(&workers, "workers", 4, "并发工作线程数")
	flag.Parse()

	if filePath == "" {
		fmt.Println("用法:")
		fmt.Printf("  %s -file=<ewf文件路径> [-path=<文件系统路径>] [-output=<输出目录>] [-recursive] [-progress=<true|false>] [-workers=<线程数>]\n", os.Args[0])
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

	// 获取文件系统
	fs, err := ewfImage.GetFileSystem()
	if err != nil {
		fmt.Printf("获取文件系统失败: %v\n", err)
		os.Exit(1)
	}

	// 获取指定路径的文件或目录
	entry, err := fs.GetFileByPath(fsPath)
	if err != nil {
		fmt.Printf("获取路径失败: %v\n", err)
		os.Exit(1)
	}

	// 创建进度统计
	var (
		totalFiles     uint64
		processedFiles uint64
		progressMutex  sync.Mutex
	)

	// 处理文件或目录
	if entry.IsDirectory() {
		// 计算总文件数
		if err := countFiles(entry, recursive, &totalFiles); err != nil {
			fmt.Printf("计算文件总数失败: %v\n", err)
			os.Exit(1)
		}

		// 创建工作池
		jobChan := make(chan filesystem.File, totalFiles)
		var wg sync.WaitGroup

		// 启动工作线程
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobChan {
					if err := processEntry(job, outputPath, &processedFiles, &progressMutex, showProgress, totalFiles); err != nil {
						fmt.Printf("\n处理文件失败 %s: %v\n", job.GetPath(), err)
					}
				}
			}()
		}

		// 收集文件
		if err := collectFiles(entry, recursive, jobChan); err != nil {
			fmt.Printf("收集文件失败: %v\n", err)
			os.Exit(1)
		}

		// 关闭工作通道并等待完成
		close(jobChan)
		wg.Wait()
	} else {
		if err := processEntry(entry, outputPath, &processedFiles, &progressMutex, showProgress, 1); err != nil {
			fmt.Printf("处理文件失败: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("\n处理完成! 共处理 %d 个文件\n", processedFiles)
}

func countFiles(entry filesystem.File, recursive bool, total *uint64) error {
	if entry.IsDirectory() {
		dir, ok := entry.(filesystem.Directory)
		if !ok {
			return fmt.Errorf("无法将文件转换为目录类型")
		}

		entries, err := dir.GetEntries()
		if err != nil {
			return err
		}

		for _, e := range entries {
			if e.IsDirectory() {
				if recursive {
					fileEntry, ok := e.(filesystem.File)
					if !ok {
						return fmt.Errorf("无法将条目转换为文件类型")
					}
					if err := countFiles(fileEntry, recursive, total); err != nil {
						return err
					}
				}
			} else {
				*total++
			}
		}
	} else {
		*total++
	}
	return nil
}

func collectFiles(entry filesystem.File, recursive bool, jobChan chan<- filesystem.File) error {
	if entry.IsDirectory() {
		dir, ok := entry.(filesystem.Directory)
		if !ok {
			return fmt.Errorf("无法将文件转换为目录类型")
		}

		entries, err := dir.GetEntries()
		if err != nil {
			return err
		}

		for _, e := range entries {
			if e.IsDirectory() {
				if recursive {
					fileEntry, ok := e.(filesystem.File)
					if !ok {
						return fmt.Errorf("无法将条目转换为文件类型")
					}
					if err := collectFiles(fileEntry, recursive, jobChan); err != nil {
						return err
					}
				}
			} else {
				fileEntry, ok := e.(filesystem.File)
				if !ok {
					return fmt.Errorf("无法将条目转换为文件类型")
				}
				jobChan <- fileEntry
			}
		}
	} else {
		jobChan <- entry
	}
	return nil
}

func processEntry(entry filesystem.File, outputPath string, processed *uint64, mutex *sync.Mutex, showProgress bool, total uint64) error {
	// 读取文件内容
	content, err := entry.ReadAll()
	if err != nil {
		return fmt.Errorf("读取文件内容失败: %w", err)
	}

	// 创建输出文件
	fileOutputPath := filepath.Join(outputPath, entry.GetPath())
	if err := os.MkdirAll(filepath.Dir(fileOutputPath), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	if err := os.WriteFile(fileOutputPath, content, 0644); err != nil {
		return fmt.Errorf("写入输出文件失败: %w", err)
	}

	// 更新进度
	mutex.Lock()
	*processed++
	if showProgress {
		progress := float64(*processed) / float64(total) * 100
		fmt.Printf("\r进度: %.1f%% (%d/%d 文件)", progress, *processed, total)
	}
	mutex.Unlock()

	return nil
}
