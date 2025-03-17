package ewf

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/laenix/ewfgo/filesystem"
)

// EWFImage 表示一个EWF镜像文件
type EWFImage struct {
	filepath    string            // EWF文件路径
	file        *os.File          // 文件句柄
	fileMutex   sync.Mutex        // 文件访问互斥锁
	Sections    []*Section        // 所有部分
	Tables      []*TableSection   // 表部分
	Tables2     []*Table2Section  // 表2部分
	DiskInfo    *DiskSMART        // 磁盘信息
	HeaderInfo  *HeaderSection    // 头部信息
	SystemInfo  *SystemInfo       // 系统信息
	VMDKPath    string            // VMDK文件路径
	chunkCache  map[uint64][]byte // 块缓存
	cacheMutex  sync.RWMutex      // 缓存访问互斥锁
	initialized bool              // 是否已初始化
}

// 常量定义
const (
	// 媒体类型
	MediaTypeRemovable = 0x00 // 可移动存储设备
	MediaTypeFixed     = 0x01 // 固定存储设备
	MediaTypeOptical   = 0x03 // 光学存储设备
	MediaTypeLogical   = 0x0e // 逻辑证据文件
	MediaTypeRAM       = 0x10 // 内存设备

	// 媒体标志
	MediaFlagImage    = 0x01 // 镜像文件
	MediaFlagPhysical = 0x02 // 物理设备
	MediaFlagFastbloc = 0x04 // Fastbloc写保护器
	MediaFlagTableau  = 0x08 // Tableau写保护器

	// 压缩级别
	CompressionNone = 0x00 // 无压缩
	CompressionGood = 0x01 // 良好压缩
	CompressionBest = 0x02 // 最佳压缩

	// 块标志
	ChunkIsCompressed     = 0x01 // 块已压缩
	ChunkCanBeCompressed  = 0x02 // 块可以被压缩
	ChunkIsPacket         = 0x04 // 块是数据包
	ChunkContainsChecksum = 0x10 // 块包含校验和

	// 缓存大小
	MaxCacheSize = 1024 // 最大缓存块数

	// 默认磁盘大小
	DefaultDiskSize = 1024 * 1024 * 1024 // 1GB

	// 默认扇区大小
	DefaultSectorSize = 512
)

// NewWithFilePath 创建一个新的EWF镜像实例
func NewWithFilePath(filepath string) *EWFImage {
	return &EWFImage{
		filepath:   filepath,
		chunkCache: make(map[uint64][]byte),
		Tables:     make([]*TableSection, 0),
		Tables2:    make([]*Table2Section, 0),
		Sections:   make([]*Section, 0),
	}
}

// Close 关闭EWF镜像
func (e *EWFImage) Close() error {
	if e.file != nil {
		return e.file.Close()
	}
	return nil
}

// Initialize 初始化EWF镜像
func (e *EWFImage) Initialize() error {
	if e.initialized {
		return nil
	}

	var err error
	e.file, err = os.Open(e.filepath)
	if err != nil {
		return fmt.Errorf("打开EWF文件失败: %w", err)
	}

	if err := e.Parse(); err != nil {
		e.file.Close()
		return fmt.Errorf("解析EWF文件失败: %w", err)
	}

	e.initialized = true
	return nil
}

// 2.1.1
// 13 bytes
type EWFFileHeader struct {
	EVFSignature  [8]byte // "EVF\0x09\0x0d\0x0a\0xff\0x00"
	FieldsStart   uint8   // 1
	SegmentNumber uint16  // 256
	FieldsEnd     uint16  // 0
}

// 3 Section
// 76 bytes
type Section struct {
	SectionTypeDefinition [16]byte // A string containing the section type definition. E.g. "header", "volume", etc.
	NextOffset            uint64   // Next section offset The offset is relative from the start of the segment file
	SectionSize           uint64   // Section size
	Padding               [40]byte // 填充
	CheckSum              uint32   // 校验和
}

// 3.3 header2
// 76 bytes
type Header2Section struct {
	ByteOrderMark [2]byte  // 0xfffe UTF-16 little-endian | 0xfeff big-endian
	Header2       [74]byte // zlib
}

// 3.4 header
// 76 bytes
type HeaderSection struct {
	ByteOrderMark [2]byte  // 0xfffe UTF-16 little-endian | 0xfeff big-endian
	Header        [74]byte // zlib
}

// c	n	a	e	t	av	ov	m	u	p	r
type HeaderSectionString struct {
	CaseNumber        string // c
	EvidenceNumber    string // n
	UniqueDescription string // a
	ExaminerName      string // e
	Notes             string // t
	Version           string // av
	Platform          string // ov
	AcquisitionDate   string // m
	SystemDate        string // u
	PasswordHash      string // p
	Char              string // r
}

// 3.5 Volume and 3.6 Disk
// 94 bytes
type EWFSpecification struct {
	Reserved     uint32
	SegmentChunk uint32
	ChunkSectors uint32
	SectorsBytes uint32
	SectorCounts uint32
	Reserved2    [20]byte
	Padding      [45]byte
	Signature    [5]byte
	CheckSum     uint32
}

// 3.5 Volume and 3.6 Disk
// 1052 bytes
type DiskSMART struct {
	MediaType                uint8     // 媒体类型
	Space                    [3]byte   // 分割 - 无意义
	ChunkCount               uint32    // 块数
	ChunkSectors             uint32    // 每个块的扇区数
	SectorBytes              uint32    // 每个扇区的字节数
	SectorsCount             uint64    // 总扇区数
	CHScylinders             uint32    // CHS柱面数
	CHSheads                 uint32    // CHS磁头数
	CHSsectors               uint32    // CHS扇区数
	MediaFlag                uint8     // 媒体标志
	Space2                   [3]byte   // 分割 - 无意义
	PALMVolumeStartSector    uint32    // PALM卷起始扇区
	Space3                   uint32    // 分割 - 无意义
	SMARTLogsStartSector     uint32    // SMART日志起始扇区
	CompressionLevel         uint8     // 压缩级别
	Space4                   [3]byte   // 分割 - 无意义
	SectorErrorGranularity   uint32    // 扇区错误粒度
	Space5                   uint32    // 分割 - 无意义
	SegmentFileSetIdentifier [16]byte  // 段文件集标识符 GUID/UUID
	Space6                   [963]byte // 分割 - 无意义
	Signature                [5]byte   // 标记
	CheckSum                 uint32    // 校验和
	Size                     uint64    // 磁盘大小（字节）
	SectorSize               uint32    // 扇区大小（字节）
}

// 3.7
type DataSection struct {
	MediaType                uint8     // 媒体类型
	Space                    [3]byte   // 分割 - 无意义
	ChunkCount               uint32    // 块数
	ChunkSectors             uint32    // 每个块的扇区数
	SectorBytes              uint32    // 每个扇区的字节数
	SectorsCount             uint64    // 总扇区数
	CHScylinders             uint32    // CHS柱面数
	CHSheads                 uint32    // CHS磁头数
	CHSsectors               uint32    // CHS扇区数
	MediaFlag                uint8     // 媒体标志
	Space2                   [3]byte   // 分割 - 无意义
	PALMVolumeStartSector    uint32    // PALM卷起始扇区
	Space3                   uint32    // 分割 - 无意义
	SMARTLogsStartSector     uint32    // SMART日志起始扇区
	CompressionLevel         uint8     // 压缩级别
	Space4                   [3]byte   // 分割 - 无意义
	SectorErrorGranularity   uint32    // 扇区错误粒度
	Space5                   uint32    // 分割 - 无意义
	SegmentFileSetIdentifier [16]byte  // 段文件集标识符 GUID/UUID
	Space6                   [963]byte // 分割 - 无意义
	Signature                [5]byte   // 标记
	CheckSum                 uint32    // 校验和
}

// 3.8 Sectors
type SectorsSection struct {
	SectorsNumber uint64   // 扇区数量
	Reserved      [4]byte  // 保留字节
	Padding       [20]byte // 填充
	CheckSum      uint32   // 校验和
	SectorsData   []byte   // 扇区数据 - 解析时动态分配
}

// 3.9 Table
type TableSection struct {
	EntryNumber uint32       // 表项数
	Padding     [16]byte     // 分割 - 无意义
	CheckSum    uint32       // 校验和
	Entries     []TableEntry // 添加表项数组
}

// 表项结构，用于记录数据块的位置和状态
type TableEntry struct {
	ChunkOffset uint64 // 数据块偏移量
	ChunkSize   uint32 // 数据块大小
	ChunkFlags  uint32 // 数据块标志
}

// 3.10 Table2
type Table2Section struct {
	EntryNumber uint32       // 表项数
	Padding     [16]byte     // 分割 - 无意义
	CheckSum    uint32       // 校验和
	Entries     []TableEntry // 添加表项数组
}

// 3.11 Next
type NextSection struct {
}

// 3.12 Ltype
type LtypeSection struct{}

// 3.13 Ltree
type LtreeSection struct{}

// 3.14 Map
type MapSection struct{}

// 3.15 Session
type SessionSection struct{}

// 3.16 Error2
type Error2Section struct{}

// 3.17 Digest
type DigestSection struct {
	MD5Digest  [16]byte // MD5摘要
	SHA1Digest [20]byte // SHA1摘要
	Padding    [40]byte // 填充
	CheckSum   uint32   // 校验和
}

// 3.18 Hash
type HashSection struct {
	MD5Hash  [16]byte // MD5哈希
	SHA1Hash [20]byte // SHA1哈希
	Padding  [40]byte // 填充
	CheckSum uint32   // 校验和
}

// 3.19 Done
type DoneSection struct{}

// SystemInfo 存储系统信息
type SystemInfo struct {
	IsWindows bool
	Version   string
	Arch      string
	Users     []UserInfo
}

// UserInfo 存储用户信息
type UserInfo struct {
	Username    string
	Password    string
	IsAdmin     bool
	IsDisabled  bool
	LastLogin   time.Time
	ProfilePath string
}

// VMDKStreamWriter 表示一个VMDK流式写入器
type VMDKStreamWriter struct {
	file          *os.File
	diskSize      uint64
	sectorSize    uint32
	totalSectors  uint64
	currentSector uint64
	headerWritten bool
}

// NewVMDKStreamWriter 创建一个新的VMDK流式写入器
func NewVMDKStreamWriter(outputPath string, diskSize uint64, sectorSize uint32) (*VMDKStreamWriter, error) {
	// 创建VMDK描述符文件
	descPath := outputPath
	flatPath := strings.TrimSuffix(outputPath, ".vmdk") + "-flat.vmdk"

	// 创建描述符文件
	descFile, err := os.Create(descPath)
	if err != nil {
		return nil, fmt.Errorf("创建VMDK描述符文件失败: %w", err)
	}

	// 写入描述符内容
	header := fmt.Sprintf(`# Disk DescriptorFile
version=1
encoding="UTF-8"
CID=ffffffff
parentCID=ffffffff
isNativeSnapshot="no"
createType="monolithicFlat"

# Extent description
RW %d FLAT "%s" 0

# The Disk Data Base
#DDB

ddb.adapterType = "ide"
ddb.geometry.cylinders = "%d"
ddb.geometry.heads = "255"
ddb.geometry.sectors = "63"
ddb.virtualHWVersion = "4"
`,
		diskSize,
		filepath.Base(flatPath),
		diskSize/(255*63*uint64(sectorSize)),
	)

	if _, err := descFile.WriteString(header); err != nil {
		descFile.Close()
		return nil, fmt.Errorf("写入VMDK描述符失败: %w", err)
	}
	descFile.Close()

	// 创建数据文件
	dataFile, err := os.Create(flatPath)
	if err != nil {
		os.Remove(descPath)
		return nil, fmt.Errorf("创建VMDK数据文件失败: %w", err)
	}

	return &VMDKStreamWriter{
		file:          dataFile,
		diskSize:      diskSize,
		sectorSize:    sectorSize,
		totalSectors:  diskSize / uint64(sectorSize),
		currentSector: 0,
		headerWritten: true,
	}, nil
}

// WriteSectors 写入扇区数据
func (w *VMDKStreamWriter) WriteSectors(data []byte) error {
	if !w.headerWritten {
		return fmt.Errorf("VMDK头部未写入")
	}

	if w.currentSector >= w.totalSectors {
		return fmt.Errorf("超出磁盘容量")
	}

	// 写入数据
	_, err := w.file.Write(data)
	if err != nil {
		return fmt.Errorf("写入扇区数据失败: %w", err)
	}

	// 更新当前扇区位置
	w.currentSector += uint64(len(data)) / uint64(w.sectorSize)
	return nil
}

// Close 关闭VMDK流式写入器
func (w *VMDKStreamWriter) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// StreamToVMDK 流式转换E01为VMDK
func (e *EWFImage) StreamToVMDK(outputPath string) error {
	// 检查是否已经解析
	if e.DiskInfo == nil {
		return fmt.Errorf("EWF镜像未解析")
	}

	// 获取磁盘大小
	diskSize := uint64(e.DiskInfo.SectorsCount) * uint64(e.DiskInfo.SectorBytes)
	if diskSize == 0 {
		// 如果计算出的磁盘大小为零，使用一个合理的默认值
		diskSize = 1024 * 1024 * 1024 // 1GB
	}

	// 获取扇区大小
	sectorSize := e.DiskInfo.SectorBytes
	if sectorSize == 0 {
		// 如果扇区大小为零，使用标准扇区大小
		sectorSize = 512
	}

	// 创建VMDK流写入器
	writer, err := NewVMDKStreamWriter(outputPath, diskSize, sectorSize)
	if err != nil {
		return fmt.Errorf("创建VMDK流写入器失败: %w", err)
	}
	defer writer.Close()

	// 获取扇区数量
	sectorCount := e.DiskInfo.SectorsCount
	if sectorCount == 0 {
		// 如果扇区数量为零，根据磁盘大小计算
		sectorCount = uint64(diskSize) / uint64(sectorSize)
	}

	// 每次读取的扇区数
	const batchSize = 1024

	// 分批读取扇区并写入VMDK
	for i := uint64(0); i < sectorCount; i += batchSize {
		// 计算本批次的扇区数
		currentBatch := batchSize
		if i+uint64(currentBatch) > sectorCount {
			currentBatch = int(sectorCount - i)
		}

		// 读取扇区
		data, err := e.ReadSectors(i, uint64(currentBatch))
		if err != nil {
			// 使用零填充
			data = make([]byte, uint64(currentBatch)*uint64(sectorSize))
		}

		// 写入VMDK
		if err := writer.WriteSectors(data); err != nil {
			return fmt.Errorf("写入VMDK失败: %w", err)
		}

		// 打印进度
		fmt.Printf("\r转换进度: %.2f%%", float64(i+uint64(currentBatch))*100/float64(sectorCount))
	}

	fmt.Println("\n转换完成")
	return nil
}

func IsEWFFile(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()

	header := &EWFFileHeader{}
	if err := binary.Read(file, binary.LittleEndian, header); err != nil {
		return false
	}

	// 使用相同的签名验证逻辑
	expectedSignature := []byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00}
	return bytes.Equal(header.EVFSignature[:], expectedSignature)
}

// Parse 解析EWF文件
func (e *EWFImage) Parse() error {
	// 获取文件大小
	fileInfo, err := e.file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}
	fileSize := fileInfo.Size()

	// 读取EWF文件头
	header := &EWFFileHeader{}
	if err := binary.Read(e.file, binary.LittleEndian, header); err != nil {
		return fmt.Errorf("读取EWF文件头失败: %w", err)
	}

	// 验证EWF签名
	expectedSignature := []byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00}
	if !bytes.Equal(header.EVFSignature[:], expectedSignature) {
		return fmt.Errorf("无效的EWF签名")
	}

	// 读取初始部分
	section, err := e.ReadSection(e.file, 13)
	if err != nil {
		return fmt.Errorf("读取初始部分失败: %w", err)
	}
	e.Sections = append(e.Sections, section)

	// 记录已处理的偏移量，防止循环
	processedOffsets := make(map[uint64]bool)
	processedOffsets[13] = true

	var lastOffset uint64 = 13
	var foundDiskInfo bool
	var foundDone bool

	// 循环读取所有部分
	for {
		// 检查是否已处理过该偏移量
		if processedOffsets[section.NextOffset] {
			break
		}

		// 验证偏移量的合理性
		if section.NextOffset <= lastOffset {
			break
		}
		if section.NextOffset >= uint64(fileSize) {
			break
		}

		processedOffsets[section.NextOffset] = true
		lastOffset = section.NextOffset

		section, err = e.ReadSection(e.file, int64(section.NextOffset))
		if err != nil {
			return fmt.Errorf("读取部分失败: %w", err)
		}

		sectionType := string(bytes.TrimRight(section.SectionTypeDefinition[:], "\x00"))
		e.Sections = append(e.Sections, section)

		// 根据部分类型解析
		switch sectionType {
		case "header", "header2":
			headerStr, err := e.ParseHeaderSection(e.file, section)
			if err == nil && headerStr != nil {
				e.HeaderInfo = &HeaderSection{
					ByteOrderMark: [2]byte{0xff, 0xfe}, // UTF-16 little-endian
					Header:        [74]byte{},          // 将在后续实现转换
				}
				// TODO: 将headerStr的信息转换为HeaderSection格式
			}
		case "disk", "volume":
			diskInfo, err := e.ParseVolume(e.file, section)
			if err == nil {
				e.DiskInfo = &diskInfo
				foundDiskInfo = true
			}
		case "table":
			table, err := e.ParseTable(e.file, section)
			if err == nil && table != nil {
				e.Tables = append(e.Tables, table)
			}
		case "table2":
			table2, err := e.ParseTable2(e.file, section)
			if err == nil && table2 != nil {
				e.Tables2 = append(e.Tables2, table2)
			}
		case "done":
			foundDone = true
			break
		}

		// 如果找到done部分或下一部分偏移为0，结束解析
		if foundDone || section.NextOffset == 0 {
			break
		}
	}

	// 验证必要的信息是否已解析
	if !foundDiskInfo {
		return fmt.Errorf("未找到磁盘信息部分")
	}
	if len(e.Tables) == 0 && len(e.Tables2) == 0 {
		return fmt.Errorf("未找到任何有效的表部分")
	}

	return nil
}

// isValidTableEntry 验证表项是否有效
func isValidTableEntry(entry TableEntry, fileSize int64) bool {
	// 基本验证
	if entry.ChunkOffset == 0 {
		return false
	}

	// 大小限制验证（放宽限制）
	if entry.ChunkSize == 0 || entry.ChunkSize > 1024*1024*1024 {
		return false
	}

	// 偏移量范围验证（放宽限制）
	if entry.ChunkOffset >= uint64(fileSize) {
		return false
	}

	// 确保块不会超出文件范围（放宽限制）
	if entry.ChunkOffset+uint64(entry.ChunkSize) > uint64(fileSize) {
		return false
	}

	// 检查块标志的合理性（放宽限制）
	// 不再检查标志位

	// 不再检查偏移量对齐

	return true
}

// ParseTable 解析表部分
func (e *EWFImage) ParseTable(file *os.File, section *Section) (*TableSection, error) {
	e.fileMutex.Lock()
	defer e.fileMutex.Unlock()

	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("获取文件信息失败: %w", err)
	}
	fileSize := fileInfo.Size()

	// 保存当前位置
	currentPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("获取当前文件位置失败: %w", err)
	}

	// 验证section大小是否合理
	if section.SectionSize < 24 { // 至少需要包含EntryNumber(4) + Padding(16) + Checksum(4)
		return nil, fmt.Errorf("表部分大小异常: %d", section.SectionSize)
	}

	// 读取表头
	table := &TableSection{}
	if err := binary.Read(file, binary.LittleEndian, &table.EntryNumber); err != nil {
		return nil, fmt.Errorf("读取表项数量失败: %w", err)
	}

	// 计算实际可以容纳的表项数
	maxEntries := (section.SectionSize - 24) / 16 // 每个表项16字节(offset:8 + size:4 + flags:4)

	// 判断是否需要处理压缩数据
	needDecompression := table.EntryNumber > uint32(maxEntries)

	if needDecompression {
		// 回到section数据开始处
		if _, err := file.Seek(currentPos, io.SeekStart); err != nil {
			return nil, fmt.Errorf("重新定位到section开始位置失败: %w", err)
		}

		// 读取整个section数据
		sectionData := make([]byte, section.SectionSize)
		if _, err := io.ReadFull(file, sectionData); err != nil {
			return nil, fmt.Errorf("读取section数据失败: %w", err)
		}

		// 尝试不同的解压缩方式
		var decompressedData []byte
		var decompressed bool

		// 尝试zlib解压缩
		if len(sectionData) > 4 && (sectionData[0] == 0x78 && (sectionData[1] == 0x01 || sectionData[1] == 0x9C || sectionData[1] == 0xDA)) {
			r, err := zlib.NewReader(bytes.NewReader(sectionData))
			if err == nil {
				defer r.Close()

				if decompressedData, err = io.ReadAll(r); err == nil {
					decompressed = true
				}
			}
		}

		// 如果zlib解压缩失败，尝试EWF专用的压缩方式
		if !decompressed {
			// 对于EWF格式，表项条目通常是以16字节为单位的固定长度结构
			// 这里可以尝试直接按实际需要的表项数构建表

			// 重新读取表头信息
			if _, err := file.Seek(currentPos, io.SeekStart); err != nil {
				return nil, fmt.Errorf("重新定位到section开始位置失败: %w", err)
			}

			if err := binary.Read(file, binary.LittleEndian, &table.EntryNumber); err != nil {
				return nil, fmt.Errorf("重新读取表项数量失败: %w", err)
			}

			if err := binary.Read(file, binary.LittleEndian, &table.Padding); err != nil {
				return nil, fmt.Errorf("读取填充数据失败: %w", err)
			}

			if err := binary.Read(file, binary.LittleEndian, &table.CheckSum); err != nil {
				return nil, fmt.Errorf("读取校验和失败: %w", err)
			}

			// 预分配切片以提高性能，但使用实际可容纳的表项数量
			actualEntryCount := maxEntries
			table.Entries = make([]TableEntry, 0, actualEntryCount)

			// 读取能容纳的所有表项
			var validEntries uint32
			for i := uint32(0); i < uint32(actualEntryCount); i++ {
				var entry TableEntry

				// 确保每个表项的数据对齐
				if _, err := file.Seek(currentPos+24+int64(i*16), io.SeekStart); err != nil {
					return nil, fmt.Errorf("定位到表项 %d 失败: %w", i, err)
				}

				// 分别读取每个字段以确保正确的字节序
				if err := binary.Read(file, binary.LittleEndian, &entry.ChunkOffset); err != nil {
					return nil, fmt.Errorf("读取表项 %d 的偏移量失败: %w", i, err)
				}

				if err := binary.Read(file, binary.LittleEndian, &entry.ChunkSize); err != nil {
					return nil, fmt.Errorf("读取表项 %d 的大小失败: %w", i, err)
				}

				if err := binary.Read(file, binary.LittleEndian, &entry.ChunkFlags); err != nil {
					return nil, fmt.Errorf("读取表项 %d 的标志失败: %w", i, err)
				}

				// 验证表项的合理性
				if isValidTableEntry(entry, fileSize) {
					validEntries++
					table.Entries = append(table.Entries, entry)
				}
			}

			return table, nil
		}

		// 使用解压缩后的数据继续处理
		reader := bytes.NewReader(decompressedData)

		// 重新读取表头
		if err := binary.Read(reader, binary.LittleEndian, &table.EntryNumber); err != nil {
			return nil, fmt.Errorf("从解压数据读取表项数量失败: %w", err)
		}

		if err := binary.Read(reader, binary.LittleEndian, &table.Padding); err != nil {
			return nil, fmt.Errorf("从解压数据读取填充数据失败: %w", err)
		}

		if err := binary.Read(reader, binary.LittleEndian, &table.CheckSum); err != nil {
			return nil, fmt.Errorf("从解压数据读取校验和失败: %w", err)
		}

		// 预分配切片以提高性能
		table.Entries = make([]TableEntry, 0, table.EntryNumber)

		// 读取所有表项
		var validEntries uint32
		for i := uint32(0); i < table.EntryNumber; i++ {
			var entry TableEntry

			// 直接从reader读取数据
			if err := binary.Read(reader, binary.LittleEndian, &entry.ChunkOffset); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的偏移量失败: %w", i, err)
			}

			if err := binary.Read(reader, binary.LittleEndian, &entry.ChunkSize); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的大小失败: %w", i, err)
			}

			if err := binary.Read(reader, binary.LittleEndian, &entry.ChunkFlags); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的标志失败: %w", i, err)
			}

			// 验证表项的合理性
			if isValidTableEntry(entry, fileSize) {
				validEntries++
				table.Entries = append(table.Entries, entry)
			}
		}
	} else {
		// 常规处理方式，未压缩数据
		if err := binary.Read(file, binary.LittleEndian, &table.Padding); err != nil {
			return nil, fmt.Errorf("读取填充数据失败: %w", err)
		}

		if err := binary.Read(file, binary.LittleEndian, &table.CheckSum); err != nil {
			return nil, fmt.Errorf("读取校验和失败: %w", err)
		}

		// 预分配切片以提高性能
		table.Entries = make([]TableEntry, 0, table.EntryNumber)

		// 读取所有表项
		var validEntries uint32
		for i := uint32(0); i < table.EntryNumber; i++ {
			var entry TableEntry

			// 确保每个表项的数据对齐
			if _, err := file.Seek(currentPos+24+int64(i*16), io.SeekStart); err != nil {
				return nil, fmt.Errorf("定位到表项 %d 失败: %w", i, err)
			}

			// 分别读取每个字段以确保正确的字节序
			if err := binary.Read(file, binary.LittleEndian, &entry.ChunkOffset); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的偏移量失败: %w", i, err)
			}

			if err := binary.Read(file, binary.LittleEndian, &entry.ChunkSize); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的大小失败: %w", i, err)
			}

			if err := binary.Read(file, binary.LittleEndian, &entry.ChunkFlags); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的标志失败: %w", i, err)
			}

			// 验证表项的合理性
			if isValidTableEntry(entry, fileSize) {
				validEntries++
				table.Entries = append(table.Entries, entry)
			}
		}
	}

	return table, nil
}

// ParseTable2 解析表2部分
func (e *EWFImage) ParseTable2(file *os.File, section *Section) (*Table2Section, error) {
	e.fileMutex.Lock()
	defer e.fileMutex.Unlock()

	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("获取文件信息失败: %w", err)
	}
	fileSize := fileInfo.Size()

	// 保存当前位置
	currentPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("获取当前文件位置失败: %w", err)
	}

	// 验证section大小是否合理
	if section.SectionSize < 24 { // 至少需要包含EntryNumber(4) + Padding(16) + Checksum(4)
		return nil, fmt.Errorf("表2部分大小异常: %d", section.SectionSize)
	}

	// 读取表头
	table2 := &Table2Section{}
	if err := binary.Read(file, binary.LittleEndian, &table2.EntryNumber); err != nil {
		return nil, fmt.Errorf("读取表2项数量失败: %w", err)
	}

	// 计算实际可以容纳的表项数
	maxEntries := (section.SectionSize - 24) / 16 // 每个表项16字节(offset:8 + size:4 + flags:4)

	// 判断是否需要处理压缩数据
	needDecompression := table2.EntryNumber > uint32(maxEntries)

	if needDecompression {
		// 回到section数据开始处
		if _, err := file.Seek(currentPos, io.SeekStart); err != nil {
			return nil, fmt.Errorf("重新定位到section开始位置失败: %w", err)
		}

		// 读取整个section数据
		sectionData := make([]byte, section.SectionSize)
		if _, err := io.ReadFull(file, sectionData); err != nil {
			return nil, fmt.Errorf("读取section数据失败: %w", err)
		}

		// 尝试不同的解压缩方式
		var decompressedData []byte
		var decompressed bool

		// 尝试zlib解压缩
		if len(sectionData) > 4 && (sectionData[0] == 0x78 && (sectionData[1] == 0x01 || sectionData[1] == 0x9C || sectionData[1] == 0xDA)) {
			r, err := zlib.NewReader(bytes.NewReader(sectionData))
			if err == nil {
				defer r.Close()

				if decompressedData, err = io.ReadAll(r); err == nil {
					decompressed = true
				}
			}
		}

		// 如果zlib解压缩失败，尝试EWF专用的压缩方式
		if !decompressed {
			// 对于EWF格式，表项条目通常是以16字节为单位的固定长度结构
			// 这里可以尝试直接按实际需要的表项数构建表

			// 重新读取表头信息
			if _, err := file.Seek(currentPos, io.SeekStart); err != nil {
				return nil, fmt.Errorf("重新定位到section开始位置失败: %w", err)
			}

			if err := binary.Read(file, binary.LittleEndian, &table2.EntryNumber); err != nil {
				return nil, fmt.Errorf("重新读取表项数量失败: %w", err)
			}

			if err := binary.Read(file, binary.LittleEndian, &table2.Padding); err != nil {
				return nil, fmt.Errorf("读取填充数据失败: %w", err)
			}

			if err := binary.Read(file, binary.LittleEndian, &table2.CheckSum); err != nil {
				return nil, fmt.Errorf("读取校验和失败: %w", err)
			}

			// 预分配切片以提高性能，但使用实际可容纳的表项数量
			actualEntryCount := maxEntries
			table2.Entries = make([]TableEntry, 0, actualEntryCount)

			// 读取能容纳的所有表项
			var validEntries uint32
			for i := uint32(0); i < uint32(actualEntryCount); i++ {
				var entry TableEntry

				// 确保每个表项的数据对齐
				if _, err := file.Seek(currentPos+24+int64(i*16), io.SeekStart); err != nil {
					return nil, fmt.Errorf("定位到表2项 %d 失败: %w", i, err)
				}

				// 分别读取每个字段以确保正确的字节序
				if err := binary.Read(file, binary.LittleEndian, &entry.ChunkOffset); err != nil {
					return nil, fmt.Errorf("读取表2项 %d 的偏移量失败: %w", i, err)
				}

				if err := binary.Read(file, binary.LittleEndian, &entry.ChunkSize); err != nil {
					return nil, fmt.Errorf("读取表2项 %d 的大小失败: %w", i, err)
				}

				if err := binary.Read(file, binary.LittleEndian, &entry.ChunkFlags); err != nil {
					return nil, fmt.Errorf("读取表2项 %d 的标志失败: %w", i, err)
				}

				// 验证表项的合理性
				if isValidTableEntry(entry, fileSize) {
					validEntries++
					table2.Entries = append(table2.Entries, entry)
				}
			}

			return table2, nil
		}

		// 使用解压缩后的数据继续处理
		reader := bytes.NewReader(decompressedData)

		// 重新读取表头
		if err := binary.Read(reader, binary.LittleEndian, &table2.EntryNumber); err != nil {
			return nil, fmt.Errorf("从解压数据读取表项数量失败: %w", err)
		}

		if err := binary.Read(reader, binary.LittleEndian, &table2.Padding); err != nil {
			return nil, fmt.Errorf("从解压数据读取填充数据失败: %w", err)
		}

		if err := binary.Read(reader, binary.LittleEndian, &table2.CheckSum); err != nil {
			return nil, fmt.Errorf("从解压数据读取校验和失败: %w", err)
		}

		// 预分配切片以提高性能
		table2.Entries = make([]TableEntry, 0, table2.EntryNumber)

		// 读取所有表项
		var validEntries uint32
		for i := uint32(0); i < table2.EntryNumber; i++ {
			var entry TableEntry

			// 直接从reader读取数据
			if err := binary.Read(reader, binary.LittleEndian, &entry.ChunkOffset); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的偏移量失败: %w", i, err)
			}

			if err := binary.Read(reader, binary.LittleEndian, &entry.ChunkSize); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的大小失败: %w", i, err)
			}

			if err := binary.Read(reader, binary.LittleEndian, &entry.ChunkFlags); err != nil {
				return nil, fmt.Errorf("读取表项 %d 的标志失败: %w", i, err)
			}

			// 验证表项的合理性
			if isValidTableEntry(entry, fileSize) {
				validEntries++
				table2.Entries = append(table2.Entries, entry)
			}
		}
	} else {
		// 常规处理方式，未压缩数据
		if err := binary.Read(file, binary.LittleEndian, &table2.Padding); err != nil {
			return nil, fmt.Errorf("读取填充数据失败: %w", err)
		}

		if err := binary.Read(file, binary.LittleEndian, &table2.CheckSum); err != nil {
			return nil, fmt.Errorf("读取校验和失败: %w", err)
		}

		// 预分配切片以提高性能
		table2.Entries = make([]TableEntry, 0, table2.EntryNumber)

		// 读取所有表项
		var validEntries uint32
		for i := uint32(0); i < table2.EntryNumber; i++ {
			var entry TableEntry

			// 确保每个表项的数据对齐
			if _, err := file.Seek(currentPos+24+int64(i*16), io.SeekStart); err != nil {
				return nil, fmt.Errorf("定位到表2项 %d 失败: %w", i, err)
			}

			// 分别读取每个字段以确保正确的字节序
			if err := binary.Read(file, binary.LittleEndian, &entry.ChunkOffset); err != nil {
				return nil, fmt.Errorf("读取表2项 %d 的偏移量失败: %w", i, err)
			}

			if err := binary.Read(file, binary.LittleEndian, &entry.ChunkSize); err != nil {
				return nil, fmt.Errorf("读取表2项 %d 的大小失败: %w", i, err)
			}

			if err := binary.Read(file, binary.LittleEndian, &entry.ChunkFlags); err != nil {
				return nil, fmt.Errorf("读取表2项 %d 的标志失败: %w", i, err)
			}

			// 验证表项的合理性
			if isValidTableEntry(entry, fileSize) {
				validEntries++
				table2.Entries = append(table2.Entries, entry)
			}
		}
	}

	return table2, nil
}

// ReadSector 读取指定扇区的数据
func (e *EWFImage) ReadSector(sectorNumber uint64) ([]byte, error) {
	if e.DiskInfo == nil {
		return nil, fmt.Errorf("未解析磁盘信息")
	}

	// 计算块号和块内偏移
	chunkNumber := sectorNumber / uint64(e.DiskInfo.ChunkSectors)
	sectorInChunk := sectorNumber % uint64(e.DiskInfo.ChunkSectors)

	// 读取数据块
	chunkData, err := e.findAndReadChunk(chunkNumber)
	if err != nil {
		return nil, fmt.Errorf("读取块 %d 失败: %w", chunkNumber, err)
	}

	// 从数据块中提取扇区数据
	sectorData, err := e.extractSectorFromChunk(chunkData, sectorInChunk)
	if err != nil {
		return nil, fmt.Errorf("从块 %d 提取扇区 %d 失败: %w",
			chunkNumber, sectorInChunk, err)
	}

	return sectorData, nil
}

// findAndReadChunk 查找并读取指定块
func (e *EWFImage) findAndReadChunk(chunkNumber uint64) ([]byte, error) {
	// 获取文件大小
	fileInfo, err := e.file.Stat()
	if err != nil {
		return nil, fmt.Errorf("获取文件信息失败: %w", err)
	}
	fileSize := fileInfo.Size()

	// 先从缓存中查找
	e.cacheMutex.RLock()
	if cachedData, ok := e.chunkCache[chunkNumber]; ok {
		e.cacheMutex.RUnlock()
		return cachedData, nil
	}
	e.cacheMutex.RUnlock()

	// 先从table中查找
	for _, table := range e.Tables {
		for j, entry := range table.Entries {
			if uint64(j) == chunkNumber {
				// 再次验证表项的有效性
				if !isValidTableEntry(entry, fileSize) {
					continue
				}

				// 验证偏移量和大小
				if entry.ChunkOffset+uint64(entry.ChunkSize) > uint64(fileSize) {
					return nil, fmt.Errorf("块 %d 超出文件范围: 偏移量=%d, 大小=%d, 文件大小=%d",
						chunkNumber, entry.ChunkOffset, entry.ChunkSize, fileSize)
				}

				// 读取块数据
				data, err := e.GetChunk(e.file, entry)
				if err != nil {
					return nil, fmt.Errorf("读取块 %d 失败: %w", chunkNumber, err)
				}

				// 添加到缓存
				e.addToCache(chunkNumber, data)
				return data, nil
			}
		}
	}

	// 再从table2中查找
	for _, table2 := range e.Tables2 {
		for j, entry := range table2.Entries {
			if uint64(j) == chunkNumber {
				// 再次验证表项的有效性
				if !isValidTableEntry(entry, fileSize) {
					continue
				}

				// 验证偏移量和大小
				if entry.ChunkOffset+uint64(entry.ChunkSize) > uint64(fileSize) {
					return nil, fmt.Errorf("块 %d 超出文件范围: 偏移量=%d, 大小=%d, 文件大小=%d",
						chunkNumber, entry.ChunkOffset, entry.ChunkSize, fileSize)
				}

				// 读取块数据
				data, err := e.GetChunk(e.file, entry)
				if err != nil {
					return nil, fmt.Errorf("读取块 %d 失败: %w", chunkNumber, err)
				}

				// 添加到缓存
				e.addToCache(chunkNumber, data)
				return data, nil
			}
		}
	}

	return nil, fmt.Errorf("找不到有效的块 %d", chunkNumber)
}

// GetChunk 从文件中读取数据块
func (e *EWFImage) GetChunk(file *os.File, entry TableEntry) ([]byte, error) {
	e.fileMutex.Lock()
	defer e.fileMutex.Unlock()

	// 定位到数据块位置
	if _, err := file.Seek(int64(entry.ChunkOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("定位到数据块位置失败: %w", err)
	}

	// 读取数据块
	chunkData := make([]byte, entry.ChunkSize)
	n, err := io.ReadFull(file, chunkData)
	if err != nil {
		return nil, fmt.Errorf("读取数据块失败(已读取 %d/%d 字节): %w",
			n, entry.ChunkSize, err)
	}

	// 如果数据块已压缩，则解压缩
	if entry.IsChunkCompressed() {
		decompressed, err := e.decompressChunk(chunkData)
		if err != nil {
			return nil, fmt.Errorf("解压缩数据块失败: %w", err)
		}
		return decompressed, nil
	}

	return chunkData, nil
}

// decompressChunk 解压缩数据块
func (e *EWFImage) decompressChunk(compressedData []byte) ([]byte, error) {
	// 创建zlib阅读器
	r, err := zlib.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("创建zlib解压缩器失败: %w", err)
	}
	defer r.Close()

	// 预分配足够大的缓冲区（假设压缩率不超过10倍）
	decompressedData := make([]byte, 0, len(compressedData)*10)
	buf := bytes.NewBuffer(decompressedData)

	// 读取解压缩的数据
	_, err = io.Copy(buf, r)
	if err != nil {
		return nil, fmt.Errorf("解压缩数据失败: %w", err)
	}

	return buf.Bytes(), nil
}

// GetChunkByIndex 通过索引获取数据块，需要提供table或table2
func (e *EWFImage) GetChunkByIndex(file *os.File, index uint32, table *TableSection) ([]byte, error) {
	if index >= table.EntryNumber {
		return nil, fmt.Errorf("索引超出范围: %d >= %d", index, table.EntryNumber)
	}

	return e.GetChunk(file, table.Entries[index])
}

// GetSectorSize 获取扇区大小
func (e *EWFImage) GetSectorSize() uint32 {
	if e.DiskInfo == nil {
		return 0
	}
	return e.DiskInfo.SectorBytes
}

// GetSectorCount 获取扇区总数
func (e *EWFImage) GetSectorCount() uint64 {
	if e.DiskInfo == nil {
		return 0
	}
	return e.DiskInfo.SectorsCount
}

// GetChunkSize 获取数据块大小（每个块包含的扇区数）
func (e *EWFImage) GetChunkSize() uint32 {
	if e.DiskInfo == nil {
		return 0
	}
	return e.DiskInfo.ChunkSectors
}

// ReadSectors 读取连续多个扇区的数据
func (e *EWFImage) ReadSectors(startSector uint64, count uint64) ([]byte, error) {
	result := make([]byte, 0, count*uint64(e.GetSectorSize()))

	for i := uint64(0); i < count; i++ {
		sectorData, err := e.ReadSector(startSector + i)
		if err != nil {
			return result, fmt.Errorf("读取扇区 %d 失败: %w", startSector+i, err)
		}
		result = append(result, sectorData...)
	}

	return result, nil
}

// ReadBytes 根据字节偏移量和大小读取数据
func (e *EWFImage) ReadBytes(offset uint64, size uint64) ([]byte, error) {
	if e.DiskInfo == nil {
		return nil, fmt.Errorf("未解析磁盘信息")
	}

	sectorSize := uint64(e.DiskInfo.SectorBytes)
	startSector := offset / sectorSize
	endSector := (offset + size - 1) / sectorSize

	sectorCount := endSector - startSector + 1
	allSectorsData, err := e.ReadSectors(startSector, sectorCount)
	if err != nil {
		return nil, err
	}

	startOffset := offset % sectorSize
	endOffset := startOffset + size

	if endOffset > uint64(len(allSectorsData)) {
		endOffset = uint64(len(allSectorsData))
	}

	return allSectorsData[startOffset:endOffset], nil
}

// ParseDigest 解析摘要部分
func (e *EWFImage) ParseDigest(file *os.File, section *Section) (*DigestSection, error) {
	digest := &DigestSection{}
	err := binary.Read(file, binary.LittleEndian, digest)
	if err != nil {
		return nil, fmt.Errorf("读取Digest部分失败: %w", err)
	}

	// 验证校验和
	if digest.CheckSum != 0 {
		// TODO: 实现校验和验证
	}

	return digest, nil
}

// ParseHash 解析哈希部分
func (e *EWFImage) ParseHash(file *os.File, section *Section) (*HashSection, error) {
	hash := &HashSection{}
	err := binary.Read(file, binary.LittleEndian, hash)
	if err != nil {
		return nil, fmt.Errorf("读取Hash部分失败: %w", err)
	}

	// 验证校验和
	if hash.CheckSum != 0 {
		// TODO: 实现校验和验证
	}

	return hash, nil
}

// VerifyChecksum 验证部分的校验和
func (e *EWFImage) VerifyChecksum(data []byte, expectedChecksum uint32) bool {
	if expectedChecksum == 0 {
		// 如果校验和为0，表示不使用校验和
		return true
	}

	calculatedChecksum := adler32.Checksum(data)
	return calculatedChecksum == expectedChecksum
}

// String 返回EWFImage的字符串表示
func (e *EWFImage) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("EWF镜像文件: %s\n", e.filepath))
	sb.WriteString(fmt.Sprintf("部分数量: %d\n", len(e.Sections)))

	if e.DiskInfo != nil {
		sb.WriteString(fmt.Sprintf("磁盘信息:\n"))
		sb.WriteString(fmt.Sprintf("  媒体类型: %d\n", e.DiskInfo.MediaType))
		sb.WriteString(fmt.Sprintf("  扇区大小: %d字节\n", e.DiskInfo.SectorBytes))
		sb.WriteString(fmt.Sprintf("  扇区总数: %d\n", e.DiskInfo.SectorsCount))
		sb.WriteString(fmt.Sprintf("  总大小: %d 字节\n", e.DiskInfo.Size))
	}

	sb.WriteString(fmt.Sprintf("表数量: %d\n", len(e.Tables)))
	sb.WriteString(fmt.Sprintf("表2数量: %d\n", len(e.Tables2)))

	return sb.String()
}

// String 返回Section的字符串表示
func (s *Section) String() string {
	sectionType := string(bytes.TrimRight(s.SectionTypeDefinition[:], "\x00"))
	return fmt.Sprintf("部分类型: %s, 大小: %d字节, 下一部分偏移: %d",
		sectionType, s.SectionSize, s.NextOffset)
}

// String 返回HeaderSectionString的字符串表示
func (h *HeaderSectionString) String() string {
	var sb strings.Builder

	sb.WriteString("Header信息:\n")
	if h.CaseNumber != "" {
		sb.WriteString(fmt.Sprintf("  案例编号: %s\n", h.CaseNumber))
	}
	if h.EvidenceNumber != "" {
		sb.WriteString(fmt.Sprintf("  证据编号: %s\n", h.EvidenceNumber))
	}
	if h.UniqueDescription != "" {
		sb.WriteString(fmt.Sprintf("  描述: %s\n", h.UniqueDescription))
	}
	if h.ExaminerName != "" {
		sb.WriteString(fmt.Sprintf("  检查员: %s\n", h.ExaminerName))
	}
	if h.Notes != "" {
		sb.WriteString(fmt.Sprintf("  备注: %s\n", h.Notes))
	}
	if h.Version != "" {
		sb.WriteString(fmt.Sprintf("  版本: %s\n", h.Version))
	}
	if h.Platform != "" {
		sb.WriteString(fmt.Sprintf("  平台: %s\n", h.Platform))
	}
	if h.AcquisitionDate != "" {
		sb.WriteString(fmt.Sprintf("  采集日期: %s\n", h.AcquisitionDate))
	}
	if h.SystemDate != "" {
		sb.WriteString(fmt.Sprintf("  系统日期: %s\n", h.SystemDate))
	}

	return sb.String()
}

// String 返回DigestSection的字符串表示
func (d *DigestSection) String() string {
	return fmt.Sprintf("MD5摘要: %x\nSHA1摘要: %x", d.MD5Digest, d.SHA1Digest)
}

// String 返回HashSection的字符串表示
func (h *HashSection) String() string {
	return fmt.Sprintf("MD5哈希: %x\nSHA1哈希: %x", h.MD5Hash, h.SHA1Hash)
}

// String 返回TableEntry的字符串表示
func (e *TableEntry) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("偏移量: %d, 大小: %d, 标志: %d",
		e.ChunkOffset, e.ChunkSize, e.ChunkFlags))

	if e.IsChunkCompressed() {
		sb.WriteString(" [已压缩]")
	}
	if e.CanChunkBeCompressed() {
		sb.WriteString(" [可压缩]")
	}
	if e.IsChunkPacket() {
		sb.WriteString(" [数据包]")
	}
	if e.ContainsChecksum() {
		sb.WriteString(" [含校验和]")
	}

	return sb.String()
}

// GetFileSystem 创建并返回一个文件系统解析器
func (e *EWFImage) GetFileSystem() (filesystem.FileSystem, error) {
	return filesystem.CreateFileSystem(e)
}

// EWFImage已经实现了filesystem.Reader接口，但为了明确，我们在这里显式地实现它
// 这样外部代码可以清楚地看到EWFImage实现了此接口
var _ filesystem.Reader = (*EWFImage)(nil)

// VirtualMount 虚拟挂载EWF镜像
func (e *EWFImage) VirtualMount() error {
	// 检查是否已经解析
	if e.DiskInfo == nil {
		return fmt.Errorf("EWF镜像未解析")
	}

	// 检查文件系统类型
	fs, err := e.GetFileSystem()
	if err != nil {
		return fmt.Errorf("获取文件系统失败: %w", err)
	}

	// 根据文件系统类型进行不同的处理
	switch fs.GetType() {
	case filesystem.FileSystemTypeFAT12, filesystem.FileSystemTypeFAT16, filesystem.FileSystemTypeFAT32,
		filesystem.FileSystemTypeNTFS, filesystem.FileSystemTypeEXT2, filesystem.FileSystemTypeEXT3,
		filesystem.FileSystemTypeEXT4:
		// 获取系统信息
		isWindows := fs.GetType() == filesystem.FileSystemTypeNTFS ||
			fs.GetType() == filesystem.FileSystemTypeFAT12 ||
			fs.GetType() == filesystem.FileSystemTypeFAT16 ||
			fs.GetType() == filesystem.FileSystemTypeFAT32

		systemInfo, err := e.getSystemInfo(fs, isWindows)
		if err != nil {
			// 忽略系统信息获取失败的错误
		} else {
			e.SystemInfo = systemInfo
		}

		return nil
	case filesystem.FileSystemTypeRaw:
		// RAW文件系统处理
		// 创建一个基本的系统信息
		e.SystemInfo = &SystemInfo{
			IsWindows: false,
			Version:   "Unknown",
			Arch:      "Unknown",
			Users:     []UserInfo{},
		}

		return nil
	default:
		return fmt.Errorf("不支持的操作系统类型")
	}
}

// getSystemInfo 获取系统信息
func (e *EWFImage) getSystemInfo(fs filesystem.FileSystem, isWindows bool) (*SystemInfo, error) {
	sysInfo := &SystemInfo{
		IsWindows: isWindows,
	}

	if isWindows {
		// 获取Windows系统信息
		sysInfo.Version = e.getWindowsVersion(fs)
		sysInfo.Arch = e.getWindowsArch(fs)
		sysInfo.Users = e.getWindowsUsers(fs)
	} else {
		// 获取Linux系统信息
		sysInfo.Version = e.getLinuxVersion(fs)
		sysInfo.Arch = e.getLinuxArch(fs)
		sysInfo.Users = e.getLinuxUsers(fs)
	}

	return sysInfo, nil
}

// getWindowsVersion 获取Windows版本信息
func (e *EWFImage) getWindowsVersion(fs filesystem.FileSystem) string {
	// 尝试读取Windows版本信息
	versionFile, err := fs.GetFileByPath("/Windows/System32/ntoskrnl.exe")
	if err != nil {
		return "Unknown"
	}

	// 读取文件头部信息
	_, err = versionFile.ReadAll()
	if err != nil {
		return "Unknown"
	}

	// 解析PE文件头获取版本信息
	// TODO: 实现PE文件头解析
	return "Windows NT"
}

// getWindowsArch 获取Windows架构信息
func (e *EWFImage) getWindowsArch(fs filesystem.FileSystem) string {
	// 检查是否存在64位系统文件
	_, err := fs.GetFileByPath("/Windows/System32/ntoskrnl.exe")
	if err == nil {
		return "x64"
	}
	return "x86"
}

// getWindowsUsers 获取Windows用户信息
func (e *EWFImage) getWindowsUsers(fs filesystem.FileSystem) []UserInfo {
	var users []UserInfo

	// 读取SAM文件
	_, err := fs.GetFileByPath("/Windows/System32/config/SAM")
	if err != nil {
		return users
	}

	// TODO: 实现SAM文件解析
	// 这里需要实现SAM文件的解析，获取用户信息
	// 包括用户名、密码哈希、账户状态等

	return users
}

// getLinuxVersion 获取Linux版本信息
func (e *EWFImage) getLinuxVersion(fs filesystem.FileSystem) string {
	// 读取/etc/os-release文件
	osRelease, err := fs.GetFileByPath("/etc/os-release")
	if err != nil {
		return "Unknown"
	}

	data, err := osRelease.ReadAll()
	if err != nil {
		return "Unknown"
	}

	// 解析os-release文件
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VERSION=") {
			return strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
		}
	}

	return "Unknown"
}

// getLinuxArch 获取Linux架构信息
func (e *EWFImage) getLinuxArch(fs filesystem.FileSystem) string {
	// 检查是否存在64位系统文件
	_, err := fs.GetFileByPath("/lib64")
	if err == nil {
		return "x64"
	}
	return "x86"
}

// getLinuxUsers 获取Linux用户信息
func (e *EWFImage) getLinuxUsers(fs filesystem.FileSystem) []UserInfo {
	var users []UserInfo

	// 读取/etc/passwd文件
	passwdFile, err := fs.GetFileByPath("/etc/passwd")
	if err != nil {
		return users
	}

	data, err := passwdFile.ReadAll()
	if err != nil {
		return users
	}

	// 解析passwd文件
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 {
			user := UserInfo{
				Username:    fields[0],
				Password:    fields[1],
				IsAdmin:     fields[2] == "0",
				ProfilePath: fields[5],
			}
			users = append(users, user)
		}
	}

	return users
}

// GetSystemInfo 获取系统信息
func (e *EWFImage) GetSystemInfo() *SystemInfo {
	return e.SystemInfo
}

// ExportToVMDK 将EWF镜像导出为VMDK格式
func (e *EWFImage) ExportToVMDK(outputPath string) error {
	// 检查是否已经虚拟挂载
	if e.SystemInfo == nil {
		return fmt.Errorf("EWF镜像未虚拟挂载")
	}

	// 创建VMDK文件
	vmdkFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建VMDK文件失败: %w", err)
	}
	defer vmdkFile.Close()

	// 写入VMDK头部
	if err := e.writeVMDKHeader(vmdkFile); err != nil {
		return err
	}

	// 写入数据
	if err := e.writeVMDKData(vmdkFile); err != nil {
		return err
	}

	return nil
}

// writeVMDKHeader 写入VMDK文件头部
func (e *EWFImage) writeVMDKHeader(file *os.File) error {
	// VMDK头部信息
	header := fmt.Sprintf(`# Disk DescriptorFile
version=1
encoding="UTF-8"
CID=ffffffff
parentCID=ffffffff
isNativeSnapshot="no"
createType="monolithicFlat"

# Extent description
RW %d FLAT "%s" 0

# The Disk Data Base
#DDB

ddb.adapterType = "ide"
ddb.geometry.cylinders = "%d"
ddb.geometry.heads = "255"
ddb.geometry.sectors = "63"
ddb.virtualHWVersion = "4"
`,
		e.DiskInfo.Size,
		filepath.Base(file.Name()),
		e.DiskInfo.Size/(255*63),
		255,
		63,
	)

	_, err := file.WriteString(header)
	return err
}

// writeVMDKData 写入VMDK数据
func (e *EWFImage) writeVMDKData(file *os.File) error {
	// 获取扇区大小
	sectorSize := uint32(e.DiskInfo.SectorSize)
	totalSectors := e.DiskInfo.Size / uint64(sectorSize)

	// 逐块读取并写入
	for sector := uint64(0); sector < totalSectors; sector += 1024 {
		// 计算本次读取的扇区数
		sectorsToRead := uint64(1024)
		if sector+sectorsToRead > totalSectors {
			sectorsToRead = totalSectors - sector
		}

		// 读取数据
		data, err := e.ReadSectors(sector, sectorsToRead)
		if err != nil {
			return fmt.Errorf("读取扇区失败: %w", err)
		}

		// 写入数据
		if _, err := file.Write(data); err != nil {
			return fmt.Errorf("写入VMDK数据失败: %w", err)
		}
	}

	return nil
}

// GenerateVMX 生成VMX配置文件
func (e *EWFImage) GenerateVMX(outputPath string) error {
	// 检查是否已经虚拟挂载
	if e.SystemInfo == nil {
		return fmt.Errorf("EWF镜像未虚拟挂载")
	}

	// 创建VMX文件
	vmxFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建VMX文件失败: %w", err)
	}
	defer vmxFile.Close()

	// 生成VMX配置
	config := e.generateVMXConfig()

	// 写入配置
	if _, err := vmxFile.WriteString(config); err != nil {
		return fmt.Errorf("写入VMX配置失败: %w", err)
	}

	return nil
}

// generateVMXConfig 生成VMX配置内容
func (e *EWFImage) generateVMXConfig() string {
	// 基础配置
	config := fmt.Sprintf(`.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "19"
memsize = "4096"
numvcpus = "2"
cpuid.coresPerSocket = "2"
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "%s"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000"
ethernet0.wakeOnPcktRcv = "FALSE"
ethernet0.addressType = "generated"
ethernet0.pciSlotNumber = "32"
ethernet0.generatedAddress = "%s"
ethernet0.generatedAddressOffset = "0"
`,
		filepath.Base(e.VMDKPath),
		generateMACAddress(),
	)

	// 根据操作系统类型添加特定配置
	if e.SystemInfo.IsWindows {
		config += e.generateWindowsVMXConfig()
	} else {
		config += e.generateLinuxVMXConfig()
	}

	return config
}

// generateWindowsVMXConfig 生成Windows特定的VMX配置
func (e *EWFImage) generateWindowsVMXConfig() string {
	return fmt.Sprintf(`guestOS = "windows9-64"
svga.present = "TRUE"
svga.vramSize = "16777216"
svga.graphicsMemoryKB = "65536"
svga.autodetect = "TRUE"
svga.maxWidth = "2560"
svga.maxHeight = "1600"
sound.present = "TRUE"
sound.fileName = "-1"
sound.autodetect = "TRUE"
sound.device = "0"
sound.notPresent = "FALSE"
`)
}

// generateLinuxVMXConfig 生成Linux特定的VMX配置
func (e *EWFImage) generateLinuxVMXConfig() string {
	return fmt.Sprintf(`guestOS = "ubuntu-64"
svga.present = "TRUE"
svga.vramSize = "16777216"
svga.graphicsMemoryKB = "65536"
svga.autodetect = "TRUE"
svga.maxWidth = "2560"
svga.maxHeight = "1600"
sound.present = "TRUE"
sound.fileName = "-1"
sound.autodetect = "TRUE"
sound.device = "0"
sound.notPresent = "FALSE"
`)
}

// generateUUID 生成UUID
func generateUUID() string {
	uuid := make([]byte, 16)
	rand.Read(uuid)
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5],
		uuid[6], uuid[7],
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15])
}

// generateContentID 生成内容ID
func generateContentID() string {
	contentID := make([]byte, 16)
	rand.Read(contentID)
	return fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		contentID[0], contentID[1], contentID[2], contentID[3],
		contentID[4], contentID[5], contentID[6], contentID[7],
		contentID[8], contentID[9], contentID[10], contentID[11],
		contentID[12], contentID[13], contentID[14], contentID[15])
}

// generateMACAddress 生成MAC地址
func generateMACAddress() string {
	mac := make([]byte, 6)
	rand.Read(mac)
	mac[0] |= 0x02 // 设置为本地管理的地址
	mac[0] &= 0xFE // 清除多播位
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// extractSectorFromChunk 从块数据中提取扇区数据
func (e *EWFImage) extractSectorFromChunk(chunkData []byte, sectorInChunk uint64) ([]byte, error) {
	sectorSize := uint64(e.DiskInfo.SectorBytes)
	sectorOffset := sectorInChunk * sectorSize

	if sectorOffset+sectorSize > uint64(len(chunkData)) {
		return nil, fmt.Errorf("数据块中没有足够的数据: 需要偏移 %d，块大小 %d",
			sectorOffset+sectorSize, len(chunkData))
	}

	return chunkData[sectorOffset : sectorOffset+sectorSize], nil
}

// addToCache 将块数据添加到缓存
func (e *EWFImage) addToCache(chunkNumber uint64, chunkData []byte) {
	// 如果缓存已满，删除一个随机条目
	if len(e.chunkCache) >= MaxCacheSize {
		for k := range e.chunkCache {
			delete(e.chunkCache, k)
			break
		}
	}
	e.chunkCache[chunkNumber] = chunkData
}

// ReadSection 读取部分
func (e *EWFImage) ReadSection(file *os.File, offset int64) (*Section, error) {
	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("获取文件信息失败: %w", err)
	}
	fileSize := fileInfo.Size()

	// 验证偏移量
	if offset < 0 || offset >= fileSize {
		return nil, fmt.Errorf("无效的部分偏移量: %d (文件大小: %d)", offset, fileSize)
	}

	// 定位到部分开始位置
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("定位到部分失败: %w", err)
	}

	// 读取部分头
	section := &Section{}
	if err := binary.Read(file, binary.LittleEndian, section); err != nil {
		return nil, fmt.Errorf("读取部分失败: %w", err)
	}

	// 验证部分大小
	if section.SectionSize == 0 || section.SectionSize > uint64(fileSize) {
		return nil, fmt.Errorf("无效的部分大小: %d", section.SectionSize)
	}

	// 验证下一部分偏移量
	if section.NextOffset > uint64(fileSize) {
		return nil, fmt.Errorf("无效的下一部分偏移量: %d (文件大小: %d)", section.NextOffset, fileSize)
	}

	// 验证部分类型
	sectionType := string(bytes.TrimRight(section.SectionTypeDefinition[:], "\x00"))
	switch sectionType {
	case "header", "header2", "disk", "volume", "table", "table2",
		"sectors", "next", "data", "error2", "digest", "hash", "done":
		// 已知的有效部分类型
	default:
		return nil, fmt.Errorf("未知的部分类型: %s", sectionType)
	}

	return section, nil
}

// ParseHeaderSection 解析头部部分
func (e *EWFImage) ParseHeaderSection(file *os.File, section *Section) (*HeaderSectionString, error) {
	// 读取压缩数据
	compressedData := make([]byte, section.SectionSize-76)
	if _, err := file.Read(compressedData); err != nil {
		return nil, fmt.Errorf("读取压缩数据失败: %w", err)
	}

	// 创建zlib解压缩器
	r, err := zlib.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("创建zlib解压缩器失败: %w", err)
	}
	defer r.Close()

	// 读取解压缩后的数据
	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		return nil, fmt.Errorf("解压缩数据失败: %w", err)
	}

	// 解析头部字符串
	headerStr := &HeaderSectionString{}
	data := out.String()
	lines := strings.Split(data, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "c":
			headerStr.CaseNumber = value
		case "n":
			headerStr.EvidenceNumber = value
		case "a":
			headerStr.UniqueDescription = value
		case "e":
			headerStr.ExaminerName = value
		case "t":
			headerStr.Notes = value
		case "av":
			headerStr.Version = value
		case "ov":
			headerStr.Platform = value
		case "m":
			headerStr.AcquisitionDate = value
		case "u":
			headerStr.SystemDate = value
		case "p":
			headerStr.PasswordHash = value
		case "r":
			headerStr.Char = value
		}
	}

	return headerStr, nil
}

// ParseVolume 解析卷部分
func (e *EWFImage) ParseVolume(file *os.File, section *Section) (DiskSMART, error) {
	// 保存当前位置
	currentPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return DiskSMART{}, fmt.Errorf("获取当前文件位置失败: %w", err)
	}

	// 读取整个section数据，以便调试
	sectionData := make([]byte, section.SectionSize)
	if _, err := file.Seek(currentPos, io.SeekStart); err != nil {
		return DiskSMART{}, fmt.Errorf("重新定位到section起始位置失败: %w", err)
	}

	if _, err := io.ReadFull(file, sectionData); err != nil {
		return DiskSMART{}, fmt.Errorf("读取section数据失败: %w", err)
	}

	// 重新定位到section起始位置
	if _, err := file.Seek(currentPos, io.SeekStart); err != nil {
		return DiskSMART{}, fmt.Errorf("重新定位到section起始位置失败: %w", err)
	}

	// 验证部分大小
	expectedSize := uint64(unsafe.Sizeof(DiskSMART{}))
	if section.SectionSize < expectedSize {
		fmt.Printf("警告: 部分大小不足，实际:%d < 期望:%d，尝试兼容处理\n", section.SectionSize, expectedSize)
	}

	disk := DiskSMART{}

	// 尝试读取尽可能多的字段
	err = binary.Read(file, binary.LittleEndian, &disk)
	if err != nil {
		// 如果完整读取失败，尝试逐个字段读取
		fmt.Printf("完整读取磁盘信息失败，尝试逐字段读取: %v\n", err)

		// 重新定位到section起始位置
		if _, err := file.Seek(currentPos, io.SeekStart); err != nil {
			return DiskSMART{}, fmt.Errorf("重新定位到section起始位置失败: %w", err)
		}

		// 尝试读取关键字段
		if err := binary.Read(file, binary.LittleEndian, &disk.MediaType); err != nil {
			return DiskSMART{}, fmt.Errorf("读取媒体类型失败: %w", err)
		}

		if err := binary.Read(file, binary.LittleEndian, &disk.Space); err != nil {
			fmt.Printf("警告: 读取Space失败: %v\n", err)
		}

		if err := binary.Read(file, binary.LittleEndian, &disk.ChunkCount); err != nil {
			return DiskSMART{}, fmt.Errorf("读取块数失败: %w", err)
		}

		if err := binary.Read(file, binary.LittleEndian, &disk.ChunkSectors); err != nil {
			return DiskSMART{}, fmt.Errorf("读取每块扇区数失败: %w", err)
		}

		if err := binary.Read(file, binary.LittleEndian, &disk.SectorBytes); err != nil {
			return DiskSMART{}, fmt.Errorf("读取扇区字节数失败: %w", err)
		}

		if err := binary.Read(file, binary.LittleEndian, &disk.SectorsCount); err != nil {
			return DiskSMART{}, fmt.Errorf("读取扇区总数失败: %w", err)
		}

		// 计算磁盘大小
		disk.Size = uint64(disk.SectorsCount) * uint64(disk.SectorBytes)

		// 其余字段默认为空
		fmt.Printf("部分读取成功，计算的磁盘大小: %d 字节\n", disk.Size)
	}

	// 验证签名
	signature := string(bytes.TrimRight(disk.Signature[:], "\x00"))
	if signature != "EWF2" && signature != "EVF2" && signature != "" {
		fmt.Printf("警告: 非标准签名: '%s'，继续处理\n", signature)
	}

	// 验证磁盘信息的合理性
	if disk.SectorBytes == 0 || disk.SectorBytes > 8192 {
		// 使用默认值
		fmt.Printf("警告: 无效的扇区大小: %d，使用默认值512\n", disk.SectorBytes)
		disk.SectorBytes = 512
	}

	if disk.ChunkSectors == 0 || disk.ChunkSectors > 65536 {
		// 使用默认值
		fmt.Printf("警告: 无效的每块扇区数: %d，使用默认值64\n", disk.ChunkSectors)
		disk.ChunkSectors = 64
	}

	if disk.SectorsCount == 0 {
		// 计算扇区数
		if disk.Size > 0 && disk.SectorBytes > 0 {
			disk.SectorsCount = uint64(disk.Size) / uint64(disk.SectorBytes)
			fmt.Printf("警告: 计算的扇区数: %d\n", disk.SectorsCount)
		} else {
			fmt.Printf("警告: 无法计算扇区数\n")
		}
	}

	if disk.Size == 0 {
		// 计算磁盘大小
		disk.Size = uint64(disk.SectorsCount) * uint64(disk.SectorBytes)
		fmt.Printf("警告: 计算的磁盘大小: %d 字节\n", disk.Size)
	}

	// 打印详细信息
	fmt.Printf("磁盘信息详情:\n")
	fmt.Printf("  媒体类型: %d\n", disk.MediaType)
	fmt.Printf("  块数: %d\n", disk.ChunkCount)
	fmt.Printf("  每块扇区数: %d\n", disk.ChunkSectors)
	fmt.Printf("  扇区大小: %d 字节\n", disk.SectorBytes)
	fmt.Printf("  扇区总数: %d\n", disk.SectorsCount)
	fmt.Printf("  磁盘大小: %d 字节 (%.2f GB)\n", disk.Size, float64(disk.Size)/(1024*1024*1024))
	fmt.Printf("  CHS几何: %d/%d/%d\n", disk.CHScylinders, disk.CHSheads, disk.CHSsectors)
	fmt.Printf("  媒体标志: %d\n", disk.MediaFlag)
	fmt.Printf("  压缩级别: %d\n", disk.CompressionLevel)

	return disk, nil
}

// min 返回两个数中的较小者
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IsChunkCompressed 检查块是否已压缩
func (e *TableEntry) IsChunkCompressed() bool {
	return e.ChunkFlags&ChunkIsCompressed != 0
}

// CanChunkBeCompressed 检查块是否可以被压缩
func (e *TableEntry) CanChunkBeCompressed() bool {
	return e.ChunkFlags&ChunkCanBeCompressed != 0
}

// IsChunkPacket 检查块是否是数据包
func (e *TableEntry) IsChunkPacket() bool {
	return e.ChunkFlags&ChunkIsPacket != 0
}

// ContainsChecksum 检查块是否包含校验和
func (e *TableEntry) ContainsChecksum() bool {
	return e.ChunkFlags&ChunkContainsChecksum != 0
}
