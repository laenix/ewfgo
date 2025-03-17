package filesystem

import (
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

// FAT32FileSystem 实现了FAT32文件系统的解析
type FAT32FileSystem struct {
	reader Reader

	// FAT32文件系统参数
	bytesPerSector    uint16
	sectorsPerCluster uint8
	reservedSectors   uint16
	numberOfFATs      uint8
	sectorsPerFAT     uint32
	rootCluster       uint32
	fatStartSector    uint64
	dataStartSector   uint64
	totalSectors      uint32
}

// NewFAT32FileSystem 创建一个新的FAT32文件系统解析器
func NewFAT32FileSystem(reader Reader) (FileSystem, error) {
	fs := &FAT32FileSystem{
		reader: reader,
	}

	// 读取FAT32引导扇区
	bootSector, err := reader.ReadSector(0)
	if err != nil {
		return nil, fmt.Errorf("读取FAT32引导扇区失败: %w", err)
	}

	// 解析FAT32引导扇区
	fs.bytesPerSector = binary.LittleEndian.Uint16(bootSector[11:13])
	fs.sectorsPerCluster = bootSector[13]
	fs.reservedSectors = binary.LittleEndian.Uint16(bootSector[14:16])
	fs.numberOfFATs = bootSector[16]
	fs.sectorsPerFAT = binary.LittleEndian.Uint32(bootSector[36:40])
	fs.rootCluster = binary.LittleEndian.Uint32(bootSector[44:48])
	fs.totalSectors = binary.LittleEndian.Uint32(bootSector[32:36])

	// 计算FAT表和数据区的起始扇区
	fs.fatStartSector = uint64(fs.reservedSectors)
	fs.dataStartSector = fs.fatStartSector + uint64(fs.numberOfFATs*uint8(fs.sectorsPerFAT))

	return fs, nil
}

// GetType 获取文件系统类型
func (fs *FAT32FileSystem) GetType() FileSystemType {
	return FileSystemTypeFAT32
}

// GetRootDirectory 返回FAT32文件系统的根目录
func (fs *FAT32FileSystem) GetRootDirectory() (Directory, error) {
	return fs.getDirectoryByCluster(fs.rootCluster, "/")
}

// GetFileByPath 根据路径获取文件
func (fs *FAT32FileSystem) GetFileByPath(path string) (File, error) {
	// 如果是根目录
	if path == "/" {
		return nil, fmt.Errorf("根目录不是文件")
	}

	// 获取父目录
	parentPath := filepath.Dir(path)
	if parentPath == "." {
		parentPath = "/"
	}

	parentDir, err := fs.GetDirectoryByPath(parentPath)
	if err != nil {
		return nil, err
	}

	// 获取文件名
	fileName := filepath.Base(path)

	// 在父目录中查找文件
	entry, err := parentDir.GetEntry(fileName)
	if err != nil {
		return nil, err
	}

	if entry.IsDirectory() {
		return nil, fmt.Errorf("路径指向的是目录: %s", path)
	}

	file, ok := entry.(File)
	if !ok {
		return nil, fmt.Errorf("无法将条目转换为文件: %s", path)
	}

	return file, nil
}

// GetDirectoryByPath 根据路径获取目录
func (fs *FAT32FileSystem) GetDirectoryByPath(path string) (Directory, error) {
	// 规范化路径
	path = normalizePath(path)

	// 如果是根目录
	if path == "/" {
		return fs.GetRootDirectory()
	}

	// 分解路径
	parts := strings.Split(path, "/")
	if parts[0] == "" {
		parts = parts[1:] // 跳过开头的空字符串
	}
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1] // 跳过结尾的空字符串
	}

	currentDir, err := fs.GetRootDirectory()
	if err != nil {
		return nil, err
	}

	// 逐级查找目录
	for _, part := range parts {
		if part == "" {
			continue
		}

		entries, err := currentDir.GetEntries()
		if err != nil {
			return nil, err
		}

		found := false
		for _, entry := range entries {
			if strings.EqualFold(entry.GetName(), part) && entry.IsDirectory() {
				currentDir = entry.(Directory)
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("目录未找到: %s in %s", part, path)
		}
	}

	return currentDir, nil
}

// 辅助函数，根据簇号获取目录
func (fs *FAT32FileSystem) getDirectoryByCluster(cluster uint32, path string) (*FAT32Directory, error) {
	return &FAT32Directory{
		fs:      fs,
		cluster: cluster,
		name:    filepath.Base(path),
		path:    path,
	}, nil
}

// 规范化路径
func normalizePath(path string) string {
	path = filepath.Clean(path)
	path = strings.Replace(path, "\\", "/", -1)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// FAT32Directory 表示FAT32文件系统中的目录
type FAT32Directory struct {
	fs      *FAT32FileSystem
	cluster uint32
	path    string
	name    string

	// 缓存的目录项
	entries []FileSystemEntry

	// 时间属性
	creationTime     time.Time
	modificationTime time.Time
	accessTime       time.Time
	attributes       uint32
}

// GetName 返回目录名
func (d *FAT32Directory) GetName() string {
	return d.name
}

// GetPath 返回目录完整路径
func (d *FAT32Directory) GetPath() string {
	return d.path
}

// GetSize 目录大小为0
func (d *FAT32Directory) GetSize() uint64 {
	return 0
}

// IsDirectory 总是返回true
func (d *FAT32Directory) IsDirectory() bool {
	return true
}

// IsDeleted 检查目录是否已删除
func (d *FAT32Directory) IsDeleted() bool {
	return false // 简单实现，实际上需要检查目录项的第一个字节
}

// GetCreationTime 返回目录创建时间
func (d *FAT32Directory) GetCreationTime() time.Time {
	return d.creationTime
}

// GetModificationTime 返回目录修改时间
func (d *FAT32Directory) GetModificationTime() time.Time {
	return d.modificationTime
}

// GetAccessTime 返回目录访问时间
func (d *FAT32Directory) GetAccessTime() time.Time {
	return d.accessTime
}

// Open 目录不能被打开为文件
func (d *FAT32Directory) Open() (io.Reader, error) {
	return nil, fmt.Errorf("不能将目录作为文件打开")
}

// ReadAll 目录不能被读取为文件内容
func (d *FAT32Directory) ReadAll() ([]byte, error) {
	return nil, fmt.Errorf("不能读取目录内容作为文件")
}

// GetAttributes 获取目录属性
func (d *FAT32Directory) GetAttributes() uint32 {
	return d.attributes
}

// GetFiles 获取所有文件
func (d *FAT32Directory) GetFiles() ([]File, error) {
	entries, err := d.GetEntries()
	if err != nil {
		return nil, err
	}

	var files []File
	for _, entry := range entries {
		if !entry.IsDirectory() {
			if file, ok := entry.(File); ok {
				files = append(files, file)
			}
		}
	}

	return files, nil
}

// GetDirectories 获取所有子目录
func (d *FAT32Directory) GetDirectories() ([]Directory, error) {
	entries, err := d.GetEntries()
	if err != nil {
		return nil, err
	}

	var dirs []Directory
	for _, entry := range entries {
		if entry.IsDirectory() {
			if dir, ok := entry.(Directory); ok {
				dirs = append(dirs, dir)
			}
		}
	}

	return dirs, nil
}

// GetEntries 获取目录内容
func (d *FAT32Directory) GetEntries() ([]FileSystemEntry, error) {
	entries, err := d.readEntries()
	if err != nil {
		return nil, err
	}

	var result []FileSystemEntry
	for _, entry := range entries {
		result = append(result, entry)
	}
	return result, nil
}

// GetEntry 获取指定名称的条目
func (d *FAT32Directory) GetEntry(name string) (FileSystemEntry, error) {
	entries, err := d.GetEntries()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.GetName() == name {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("条目未找到: %s", name)
}

// readEntries 读取目录中的所有条目
func (d *FAT32Directory) readEntries() ([]FileSystemEntry, error) {
	if d.entries != nil {
		return d.entries, nil
	}

	// 读取目录簇链
	clusters, err := d.fs.getClusterChain(d.cluster)
	if err != nil {
		return nil, err
	}

	d.entries = []FileSystemEntry{}

	// 遍历簇链中的所有簇
	for _, cluster := range clusters {
		// 计算簇的扇区范围
		startSector := d.fs.dataStartSector + uint64(cluster-2)*uint64(d.fs.sectorsPerCluster)

		// 读取整个簇的数据
		clusterData, err := d.fs.reader.ReadSectors(startSector, uint64(d.fs.sectorsPerCluster))
		if err != nil {
			return nil, err
		}

		// 解析目录项（每个目录项32字节）
		for offset := 0; offset < len(clusterData); offset += 32 {
			if offset+32 > len(clusterData) {
				break
			}

			entryData := clusterData[offset : offset+32]

			// 检查是否是有效的目录项
			firstByte := entryData[0]
			if firstByte == 0x00 { // 空目录项，表示目录结束
				break
			}
			if firstByte == 0xE5 { // 被删除的目录项
				continue
			}

			// 检查是否是长文件名项
			if entryData[11] == 0x0F { // 长文件名属性
				continue // 暂时跳过长文件名处理，简化实现
			}

			// 解析短文件名
			name := ""
			for i := 0; i < 8; i++ {
				if entryData[i] == 0x20 {
					break
				}
				name += string(entryData[i])
			}

			// 解析扩展名
			extension := ""
			for i := 8; i < 11; i++ {
				if entryData[i] == 0x20 {
					break
				}
				extension += string(entryData[i])
			}

			// 组合文件名
			fileName := name
			if extension != "" {
				fileName += "." + extension
			}

			// 解析属性
			attributes := uint32(entryData[11])
			isDirectory := (attributes & 0x10) != 0

			// 解析时间
			creationDate := binary.LittleEndian.Uint16(entryData[16:18])
			creationTime := binary.LittleEndian.Uint16(entryData[14:16])
			modificationDate := binary.LittleEndian.Uint16(entryData[24:26])
			modificationTime := binary.LittleEndian.Uint16(entryData[22:24])
			accessDate := binary.LittleEndian.Uint16(entryData[18:20])

			// 解析起始簇号（FAT32中簇号是4字节）
			clusterHigh := uint32(binary.LittleEndian.Uint16(entryData[20:22]))
			clusterLow := uint32(binary.LittleEndian.Uint16(entryData[26:28]))
			fileCluster := (clusterHigh << 16) | clusterLow

			// 解析文件大小
			fileSize := binary.LittleEndian.Uint32(entryData[28:32])

			// 创建文件路径
			filePath := d.path
			if filePath != "/" {
				filePath += "/"
			}
			filePath += fileName

			var entry FileSystemEntry
			if isDirectory {
				if fileName == "." || fileName == ".." {
					continue // 跳过特殊目录
				}

				// 创建目录项
				subDir := &FAT32Directory{
					fs:      d.fs,
					cluster: fileCluster,
					path:    filePath,
					name:    fileName,
				}

				// 设置时间
				subDir.creationTime = parseFATTime(creationDate, creationTime)
				subDir.modificationTime = parseFATTime(modificationDate, modificationTime)
				subDir.accessTime = parseFATTime(accessDate, 0)
				subDir.attributes = attributes

				entry = subDir
			} else {
				// 创建文件项
				file := &FAT32File{
					fs:         d.fs,
					cluster:    fileCluster,
					size:       uint64(fileSize),
					name:       fileName,
					path:       filePath,
					isDeleted:  false,
					attributes: attributes,
				}

				// 设置时间
				file.creationTime = parseFATTime(creationDate, creationTime)
				file.modificationTime = parseFATTime(modificationDate, modificationTime)
				file.accessTime = parseFATTime(accessDate, 0)

				entry = file
			}

			d.entries = append(d.entries, entry)
		}
	}

	return d.entries, nil
}

// FAT32File 实现了FAT32文件系统中的文件
type FAT32File struct {
	fs        *FAT32FileSystem
	cluster   uint32
	size      uint64
	name      string
	path      string
	isDeleted bool

	// 文件属性
	creationTime     time.Time
	modificationTime time.Time
	accessTime       time.Time
	attributes       uint32
}

// GetName 返回文件名
func (f *FAT32File) GetName() string {
	return f.name
}

// GetPath 返回文件完整路径
func (f *FAT32File) GetPath() string {
	return f.path
}

// GetSize 返回文件大小
func (f *FAT32File) GetSize() uint64 {
	return f.size
}

// IsDirectory 总是返回false
func (f *FAT32File) IsDirectory() bool {
	return false
}

// IsDeleted 检查文件是否已删除
func (f *FAT32File) IsDeleted() bool {
	return f.isDeleted
}

// GetCreationTime 返回文件创建时间
func (f *FAT32File) GetCreationTime() time.Time {
	return f.creationTime
}

// GetModificationTime 返回文件修改时间
func (f *FAT32File) GetModificationTime() time.Time {
	return f.modificationTime
}

// GetAccessTime 返回文件访问时间
func (f *FAT32File) GetAccessTime() time.Time {
	return f.accessTime
}

// GetAttributes 获取文件属性
func (f *FAT32File) GetAttributes() uint32 {
	return f.attributes
}

// Open 打开文件并返回一个Reader
func (f *FAT32File) Open() (io.Reader, error) {
	return &FAT32FileReader{
		fs:      f.fs,
		cluster: f.cluster,
		size:    f.size,
		pos:     0,
	}, nil
}

// ReadAll 读取整个文件内容
func (f *FAT32File) ReadAll() ([]byte, error) {
	reader, err := f.Open()
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}

// ReadAt 从指定位置读取
func (f *FAT32File) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("负的偏移量")
	}
	if off >= int64(f.size) {
		return 0, io.EOF
	}

	// 计算起始簇和偏移
	clusterSize := uint32(f.fs.bytesPerSector) * uint32(f.fs.sectorsPerCluster)
	startCluster := f.cluster
	currentOffset := uint32(0)

	// 跳过前面的簇
	for currentOffset+clusterSize <= uint32(off) {
		nextCluster, err := f.fs.getNextCluster(startCluster)
		if err != nil {
			return 0, err
		}
		if nextCluster >= 0x0FFFFFF8 {
			return 0, io.EOF
		}
		startCluster = nextCluster
		currentOffset += clusterSize
	}

	// 读取数据
	var totalRead int
	remaining := len(p)
	currentCluster := startCluster
	inClusterOffset := uint32(off) - currentOffset

	for remaining > 0 {
		// 读取当前簇
		clusterData, err := f.fs.readCluster(currentCluster)
		if err != nil {
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, err
		}

		// 计算本次读取的字节数
		toRead := len(clusterData) - int(inClusterOffset)
		if toRead > remaining {
			toRead = remaining
		}

		// 复制数据
		copy(p[totalRead:], clusterData[inClusterOffset:inClusterOffset+uint32(toRead)])
		totalRead += toRead
		remaining -= toRead
		inClusterOffset = 0

		// 获取下一个簇
		if remaining > 0 {
			nextCluster, err := f.fs.getNextCluster(currentCluster)
			if err != nil {
				return totalRead, err
			}
			if nextCluster >= 0x0FFFFFF8 {
				break
			}
			currentCluster = nextCluster
		}
	}

	return totalRead, nil
}

// FAT32FileReader 实现了FAT32文件的Reader
type FAT32FileReader struct {
	fs      *FAT32FileSystem
	cluster uint32
	size    uint64
	pos     uint64

	// 当前缓冲的簇数据
	currentCluster uint32
	clusterData    []byte
	clusterPos     int
}

// Read 实现io.Reader接口
func (r *FAT32FileReader) Read(p []byte) (n int, err error) {
	if r.pos >= r.size {
		return 0, io.EOF
	}

	// 计算还需要读取的字节数
	remaining := r.size - r.pos
	if uint64(len(p)) > remaining {
		p = p[:remaining]
	}

	bytesRead := 0

	// 循环读取数据
	for bytesRead < len(p) {
		// 如果没有缓存数据或者已读完当前簇
		if r.clusterData == nil || r.clusterPos >= len(r.clusterData) {
			// 获取下一个簇号
			if r.currentCluster == 0 {
				r.currentCluster = r.cluster
			} else {
				var err error
				r.currentCluster, err = r.fs.getNextCluster(r.currentCluster)
				if err != nil {
					return bytesRead, err
				}

				if r.currentCluster >= 0x0FFFFFF8 { // 簇链结束
					return bytesRead, io.EOF
				}
			}

			// 读取簇数据
			var err error
			startSector := r.fs.dataStartSector + uint64(r.currentCluster-2)*uint64(r.fs.sectorsPerCluster)
			r.clusterData, err = r.fs.reader.ReadSectors(startSector, uint64(r.fs.sectorsPerCluster))
			if err != nil {
				return bytesRead, err
			}

			r.clusterPos = 0
		}

		// 计算在当前簇中要读取的字节数
		bytesToCopy := len(r.clusterData) - r.clusterPos
		if bytesToCopy > len(p)-bytesRead {
			bytesToCopy = len(p) - bytesRead
		}

		// 复制数据
		copy(p[bytesRead:bytesRead+bytesToCopy], r.clusterData[r.clusterPos:r.clusterPos+bytesToCopy])

		// 更新位置
		r.clusterPos += bytesToCopy
		bytesRead += bytesToCopy
		r.pos += uint64(bytesToCopy)

		if r.pos >= r.size {
			return bytesRead, io.EOF
		}
	}

	return bytesRead, nil
}

// 辅助函数，获取下一个簇号
func (fs *FAT32FileSystem) getNextCluster(cluster uint32) (uint32, error) {
	if cluster < 2 {
		return 0, fmt.Errorf("无效的簇号: %d", cluster)
	}

	// 计算FAT表中的偏移
	fatOffset := cluster * 4 // 每个FAT32表项4字节
	fatSector := fs.fatStartSector + uint64(fatOffset)/uint64(fs.bytesPerSector)
	entryOffset := fatOffset % uint32(fs.bytesPerSector)

	// 读取FAT扇区
	sectorData, err := fs.reader.ReadSector(fatSector)
	if err != nil {
		return 0, err
	}

	// 读取簇号
	nextCluster := binary.LittleEndian.Uint32(sectorData[entryOffset : entryOffset+4])

	// 屏蔽高4位（保留位）
	nextCluster &= 0x0FFFFFFF

	return nextCluster, nil
}

// 辅助函数，获取簇链
func (fs *FAT32FileSystem) getClusterChain(startCluster uint32) ([]uint32, error) {
	if startCluster < 2 {
		return nil, fmt.Errorf("无效的起始簇号: %d", startCluster)
	}

	chain := []uint32{startCluster}
	currentCluster := startCluster

	// 遍历簇链直到结束标记
	for {
		nextCluster, err := fs.getNextCluster(currentCluster)
		if err != nil {
			return nil, err
		}

		if nextCluster >= 0x0FFFFFF8 { // 簇链结束
			break
		}

		chain = append(chain, nextCluster)
		currentCluster = nextCluster

		// 安全检查，防止无限循环
		if len(chain) > 1000000 { // 假设最大1百万个簇
			return nil, fmt.Errorf("簇链过长，可能循环引用")
		}
	}

	return chain, nil
}

// parseFATTime 解析FAT时间格式（2秒精度）
func parseFATTime(dateVal, timeVal uint16) time.Time {
	if dateVal == 0 && timeVal == 0 {
		return time.Time{} // 返回零值，表示时间未设置
	}

	year := int((dateVal>>9)&0x7F) + 1980
	month := time.Month((dateVal >> 5) & 0x0F)
	day := int(dateVal & 0x1F)

	hour := int((timeVal >> 11) & 0x1F)
	minute := int((timeVal >> 5) & 0x3F)
	second := int((timeVal & 0x1F) * 2)

	// 验证时间的有效性
	if month < 1 || month > 12 {
		month = 1
	}
	if day < 1 || day > 31 {
		day = 1
	}
	if hour > 23 {
		hour = 0
	}
	if minute > 59 {
		minute = 0
	}
	if second > 59 {
		second = 0
	}

	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// 从长文件名条目中提取文件名
func extractLongFileName(entries []byte) string {
	var name []uint16

	// 合并所有长文件名部分
	for i := 0; i < len(entries); i += 32 {
		entry := entries[i : i+32]
		if entry[11] != 0x0F { // 不是长文件名
			continue
		}

		// 从条目中提取Unicode字符
		name = append(name, binary.LittleEndian.Uint16(entry[1:3]))
		name = append(name, binary.LittleEndian.Uint16(entry[3:5]))
		name = append(name, binary.LittleEndian.Uint16(entry[5:7]))
		name = append(name, binary.LittleEndian.Uint16(entry[7:9]))
		name = append(name, binary.LittleEndian.Uint16(entry[9:11]))
		name = append(name, binary.LittleEndian.Uint16(entry[14:16]))
		name = append(name, binary.LittleEndian.Uint16(entry[16:18]))
		name = append(name, binary.LittleEndian.Uint16(entry[18:20]))
		name = append(name, binary.LittleEndian.Uint16(entry[20:22]))
		name = append(name, binary.LittleEndian.Uint16(entry[22:24]))
		name = append(name, binary.LittleEndian.Uint16(entry[24:26]))
		name = append(name, binary.LittleEndian.Uint16(entry[28:30]))
		name = append(name, binary.LittleEndian.Uint16(entry[30:32]))
	}

	// 移除结束标记和空字符
	var validName []uint16
	for _, r := range name {
		if r == 0 || r == 0xFFFF {
			break
		}
		validName = append(validName, r)
	}

	return string(utf16.Decode(validName))
}

// readCluster 读取指定簇的数据
func (fs *FAT32FileSystem) readCluster(cluster uint32) ([]byte, error) {
	if cluster < 2 {
		return nil, fmt.Errorf("无效的簇号: %d", cluster)
	}

	// 计算簇的扇区范围
	startSector := fs.dataStartSector + uint64(cluster-2)*uint64(fs.sectorsPerCluster)

	// 读取整个簇的数据
	return fs.reader.ReadSectors(startSector, uint64(fs.sectorsPerCluster))
}
