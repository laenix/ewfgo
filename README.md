# EWFGO - 纯Go实现的EWF取证镜像解析库

EWFGO是一个纯Go实现的Expert Witness Format (EWF) 取证镜像解析库，可以用于读取和分析EWF格式的磁盘镜像文件（例如EnCase的.E01文件）。

## 功能特性

- 完全用Go语言实现，无外部依赖
- 支持验证EWF文件格式
- 解析EWF文件的各个部分（header, disk, table等）
- 读取扇区数据（单个扇区或多个连续扇区）
- 支持压缩和非压缩数据块
- 提供对原始字节数据的访问
- 支持MD5/SHA1摘要验证
- **文件系统解析**（支持FAT32，未来将支持更多文件系统）

## 安装

```bash
go get github.com/laenix/ewfgo
```

## 快速开始

### 基本用法

```go
package main

import (
    "fmt"
    ewf "github.com/laenix/ewfgo"
)

func main() {
    // 验证文件是否为EWF格式
    if !ewf.IsEWFFile("evidence.E01") {
        fmt.Println("不是有效的EWF文件")
        return
    }
    
    // 创建并解析EWF镜像
    image := ewf.NewWithFilePath("evidence.E01")
    err := image.Parse()
    if err != nil {
        fmt.Printf("解析失败: %v\n", err)
        return
    }
    
    // 显示基本信息
    fmt.Printf("扇区大小: %d字节\n", image.GetSectorSize())
    fmt.Printf("扇区总数: %d\n", image.GetSectorCount())
    
    // 读取第一个扇区
    sector0, err := image.ReadSector(0)
    if err != nil {
        fmt.Printf("读取失败: %v\n", err)
        return
    }
    
    fmt.Printf("第一个扇区的前16个字节: % x\n", sector0[:16])
}
```

### 文件系统解析

```go
package main

import (
    "fmt"
    ewf "github.com/laenix/ewfgo"
)

func main() {
    // 创建并解析EWF镜像
    image := ewf.NewWithFilePath("evidence.E01")
    err := image.Parse()
    if err != nil {
        fmt.Printf("解析失败: %v\n", err)
        return
    }
    
    // 获取文件系统
    fs, err := image.GetFileSystem()
    if err != nil {
        fmt.Printf("获取文件系统失败: %v\n", err)
        return
    }
    
    if fs == nil {
        fmt.Println("未检测到已知的文件系统")
        return
    }
    
    fmt.Printf("文件系统类型: %s\n", fs.GetType())
    
    // 获取根目录
    root, err := fs.GetRootDirectory()
    if err != nil {
        fmt.Printf("获取根目录失败: %v\n", err)
        return
    }
    
    // 列出根目录文件
    files, err := root.GetFiles()
    if err != nil {
        fmt.Printf("读取文件列表失败: %v\n", err)
        return
    }
    
    fmt.Printf("根目录包含 %d 个文件:\n", len(files))
    for _, file := range files {
        fmt.Printf("文件: %s, 大小: %d字节\n", file.GetName(), file.GetSize())
    }
    
    // 获取特定文件
    file, err := fs.GetFileByPath("/Windows/System32/notepad.exe")
    if err != nil {
        fmt.Printf("获取文件失败: %v\n", err)
        return
    }
    
    // 读取文件内容
    content, err := file.ReadAll()
    if err != nil {
        fmt.Printf("读取文件内容失败: %v\n", err)
        return
    }
    
    fmt.Printf("读取文件 %s 成功，大小: %d字节\n", file.GetPath(), len(content))
}
```

### 使用示例程序

库中包含一个功能完整的示例程序 `examples/reade01.go`，可以展示如何使用该库：

```bash
# 显示EWF文件的基本信息
go run examples/reade01.go -file=证据.E01 -action=info

# 提取指定扇区并保存到文件
go run examples/reade01.go -file=证据.E01 -action=extract -start=0 -count=1 -output=mbr.bin

# 列出EWF文件中的所有部分
go run examples/reade01.go -file=证据.E01 -action=list

# 列出根目录内容
go run examples/reade01.go -file=证据.E01 -action=fs -path=/

# 提取文件
go run examples/reade01.go -file=证据.E01 -action=fs -path=/Windows/notepad.exe -output=notepad.exe
```

## API参考

### 主要类型

- `EWFImage` - 表示EWF镜像文件
- `Section` - 表示EWF文件中的部分
- `TableSection`/`Table2Section` - 表示块表
- `TableEntry` - 表示块表中的表项
- `DiskSMART` - 包含磁盘信息

### 主要函数和方法

#### 验证和创建

- `IsEWFFile(filename string) bool` - 检查文件是否为EWF格式
- `NewWithFilePath(filepath string) *EWFImage` - 创建新的EWFImage对象

#### 解析和访问

- `(e *EWFImage) Parse() error` - 解析EWF文件
- `(e *EWFImage) GetSectorSize() uint32` - 获取扇区大小
- `(e *EWFImage) GetSectorCount() uint64` - 获取扇区总数
- `(e *EWFImage) GetChunkSize() uint32` - 获取数据块大小

#### 数据读取

- `(e *EWFImage) ReadSector(sectorNumber uint64) ([]byte, error)` - 读取单个扇区
- `(e *EWFImage) ReadSectors(startSector, count uint64) ([]byte, error)` - 读取多个连续扇区
- `(e *EWFImage) ReadBytes(offset, size uint64) ([]byte, error)` - 根据字节偏移量和大小读取数据

#### 文件系统

- `(e *EWFImage) GetFileSystem() (filesystem.FileSystem, error)` - 获取文件系统解析器

## 支持的文件系统

当前库支持以下文件系统的解析：

- FAT32 - 全面支持
- NTFS - 计划实现
- EXT2/3/4 - 计划实现

## 支持的EWF版本

当前支持EnCase 1-7格式的EWF文件（EWF-E01）。

## 贡献

欢迎提交Pull Request或Issue！

## 许可证

MIT