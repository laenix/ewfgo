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

// NTFSFileSystem 实现了NTFS文件系统的解析
type NTFSFileSystem struct {
	reader Reader

	// NTFS文件系统参数
	bytesPerSector    uint16
	sectorsPerCluster uint8
	mftStartCluster   uint64
	mftMirrorCluster  uint64
	bytesPerMFTEntry  uint32
	clusterSize       uint32

	// MFT缓存
	mftCache map[uint64]*MFTRecord

	// 根目录
	rootDirectory *NTFSDirectory
}

// NewNTFSFileSystem 创建一个新的NTFS文件系统解析器
func NewNTFSFileSystem(reader Reader) (FileSystem, error) {
	fs := &NTFSFileSystem{
		reader: reader,
	}

	// 读取NTFS引导扇区
	bootSector, err := reader.ReadSector(0)
	if err != nil {
		return nil, fmt.Errorf("读取NTFS引导扇区失败: %w", err)
	}

	// 解析NTFS引导扇区
	fs.bytesPerSector = uint16(bootSector[11]) | (uint16(bootSector[12]) << 8)
	fs.sectorsPerCluster = bootSector[13]
	fs.mftStartCluster = uint64(binary.LittleEndian.Uint32(bootSector[48:52]))
	fs.mftMirrorCluster = uint64(binary.LittleEndian.Uint32(bootSector[52:56]))
	fs.bytesPerMFTEntry = uint32(bootSector[64])
	if fs.bytesPerMFTEntry > 0 {
		fs.bytesPerMFTEntry = 1 << (-fs.bytesPerMFTEntry)
	} else {
		fs.bytesPerMFTEntry = 1024
	}
	fs.clusterSize = uint32(fs.bytesPerSector) * uint32(fs.sectorsPerCluster)

	return fs, nil
}

// GetType 返回文件系统类型
func (fs *NTFSFileSystem) GetType() FileSystemType {
	return FileSystemTypeNTFS
}

// GetRootDirectory 返回NTFS文件系统的根目录
func (fs *NTFSFileSystem) GetRootDirectory() (Directory, error) {
	if fs.rootDirectory != nil {
		return fs.rootDirectory, nil
	}

	// 读取MFT记录5（根目录）
	record, err := fs.getMFTRecord(5)
	if err != nil {
		return nil, fmt.Errorf("读取根目录MFT记录失败: %w", err)
	}

	// 创建根目录对象
	fs.rootDirectory = &NTFSDirectory{
		fs:               fs,
		recordNumber:     5,
		name:             "",
		path:             "/",
		isDeleted:        false,
		creationTime:     record.CreationTime,
		modificationTime: record.ModificationTime,
		accessTime:       record.AccessTime,
		attributes:       record.Attributes,
	}

	return fs.rootDirectory, nil
}

// GetFileByPath 根据路径获取文件
func (fs *NTFSFileSystem) GetFileByPath(path string) (File, error) {
	// 规范化路径
	path = normalizePath(path)

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
func (fs *NTFSFileSystem) GetDirectoryByPath(path string) (Directory, error) {
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

// NTFSFile 实现了NTFS文件系统中的文件
type NTFSFile struct {
	fs           *NTFSFileSystem
	recordNumber uint64
	name         string
	path         string
	size         uint64
	isDeleted    bool

	// 文件属性
	creationTime     time.Time
	modificationTime time.Time
	accessTime       time.Time
	attributes       uint32
}

// GetName 返回文件名
func (f *NTFSFile) GetName() string {
	return f.name
}

// GetPath 返回文件完整路径
func (f *NTFSFile) GetPath() string {
	return f.path
}

// GetSize 返回文件大小
func (f *NTFSFile) GetSize() uint64 {
	return f.size
}

// IsDirectory 总是返回false
func (f *NTFSFile) IsDirectory() bool {
	return false
}

// IsDeleted 检查文件是否已删除
func (f *NTFSFile) IsDeleted() bool {
	return f.isDeleted
}

// GetCreationTime 返回文件创建时间
func (f *NTFSFile) GetCreationTime() time.Time {
	return f.creationTime
}

// GetModificationTime 返回文件修改时间
func (f *NTFSFile) GetModificationTime() time.Time {
	return f.modificationTime
}

// GetAccessTime 返回文件访问时间
func (f *NTFSFile) GetAccessTime() time.Time {
	return f.accessTime
}

// GetAttributes 获取文件属性
func (f *NTFSFile) GetAttributes() uint32 {
	return f.attributes
}

// Open 打开文件并返回一个Reader
func (f *NTFSFile) Open() (io.Reader, error) {
	// 获取MFT记录
	record, err := f.fs.getMFTRecord(f.recordNumber)
	if err != nil {
		return nil, err
	}

	return &NTFSFileReader{
		fs:     f.fs,
		record: record,
		size:   f.size,
		pos:    0,
	}, nil
}

// ReadAll 读取整个文件内容
func (f *NTFSFile) ReadAll() ([]byte, error) {
	reader, err := f.Open()
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}

// NTFSDirectory 实现了NTFS文件系统中的目录
type NTFSDirectory struct {
	fs           *NTFSFileSystem
	recordNumber uint64
	name         string
	path         string
	isDeleted    bool

	// 目录属性
	creationTime     time.Time
	modificationTime time.Time
	accessTime       time.Time
	attributes       uint32

	// 缓存
	entries []FileSystemEntry
}

// GetName 返回目录名
func (d *NTFSDirectory) GetName() string {
	return d.name
}

// GetPath 返回目录完整路径
func (d *NTFSDirectory) GetPath() string {
	return d.path
}

// GetSize 目录大小为0
func (d *NTFSDirectory) GetSize() uint64 {
	return 0
}

// IsDirectory 总是返回true
func (d *NTFSDirectory) IsDirectory() bool {
	return true
}

// IsDeleted 检查目录是否已删除
func (d *NTFSDirectory) IsDeleted() bool {
	return d.isDeleted
}

// GetCreationTime 返回目录创建时间
func (d *NTFSDirectory) GetCreationTime() time.Time {
	return d.creationTime
}

// GetModificationTime 返回目录修改时间
func (d *NTFSDirectory) GetModificationTime() time.Time {
	return d.modificationTime
}

// GetAccessTime 返回目录访问时间
func (d *NTFSDirectory) GetAccessTime() time.Time {
	return d.accessTime
}

// GetAttributes 获取目录属性
func (d *NTFSDirectory) GetAttributes() uint32 {
	return d.attributes
}

// Open 目录不能被打开为文件
func (d *NTFSDirectory) Open() (io.Reader, error) {
	return nil, fmt.Errorf("不能将目录作为文件打开")
}

// ReadAll 目录不能被读取为文件内容
func (d *NTFSDirectory) ReadAll() ([]byte, error) {
	return nil, fmt.Errorf("不能读取目录内容作为文件")
}

// GetFiles 获取目录中的所有文件
func (d *NTFSDirectory) GetFiles() ([]File, error) {
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

// GetDirectories 获取目录中的所有子目录
func (d *NTFSDirectory) GetDirectories() ([]Directory, error) {
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

// IndexEntry 表示NTFS索引项
type IndexEntry struct {
	MFTReference     uint64
	FileName         string
	IsDirectory      bool
	Size             uint64
	CreationTime     time.Time
	ModificationTime time.Time
	AccessTime       time.Time
	Attributes       uint32
}

// parseIndexRoot 解析索引根
func parseIndexRoot(data []byte) ([]IndexEntry, error) {
	var entries []IndexEntry
	offset := uint16(0)

	// 跳过索引根头部
	offset += 0x10

	// 读取索引项
	for {
		// 检查是否到达索引项列表末尾
		if offset >= uint16(len(data)) {
			break
		}

		// 读取索引项长度
		entryLength := binary.LittleEndian.Uint16(data[offset : offset+2])
		if entryLength == 0 {
			break
		}

		// 读取MFT引用
		mftRef := binary.LittleEndian.Uint64(data[offset+8 : offset+16])

		// 读取文件名长度
		fileNameLength := data[offset+0x52]

		// 读取文件名
		fileName := make([]uint16, fileNameLength)
		for i := uint8(0); i < fileNameLength; i++ {
			fileName[i] = binary.LittleEndian.Uint16(data[offset+0x54+uint16(i)*2 : offset+0x56+uint16(i)*2])
		}

		// 读取文件属性
		fileAttributes := binary.LittleEndian.Uint32(data[offset+0x48 : offset+0x4C])
		isDirectory := (fileAttributes & 0x10) != 0

		// 读取文件大小
		fileSize := binary.LittleEndian.Uint64(data[offset+0x30 : offset+0x38])

		// 读取时间信息
		creationTime := parseNTFSTime(data[offset+0x20 : offset+0x28])
		modificationTime := parseNTFSTime(data[offset+0x28 : offset+0x30])
		accessTime := parseNTFSTime(data[offset+0x30 : offset+0x38])

		// 创建索引项
		entry := IndexEntry{
			MFTReference:     mftRef,
			FileName:         string(utf16.Decode(fileName)),
			IsDirectory:      isDirectory,
			Size:             fileSize,
			CreationTime:     creationTime,
			ModificationTime: modificationTime,
			AccessTime:       accessTime,
			Attributes:       fileAttributes,
		}

		entries = append(entries, entry)
		offset += entryLength
	}

	return entries, nil
}

// GetEntries 获取目录中的所有条目
func (d *NTFSDirectory) GetEntries() ([]FileSystemEntry, error) {
	if d.entries != nil {
		return d.entries, nil
	}

	// 获取MFT记录
	record, err := d.fs.getMFTRecord(d.recordNumber)
	if err != nil {
		return nil, err
	}

	// 读取数据运行的数据
	var indexData []byte
	for _, run := range record.DataRuns {
		// 计算扇区位置
		startSector := run.StartCluster * uint64(d.fs.sectorsPerCluster)
		sectorCount := (run.ClusterCount*uint64(d.fs.clusterSize) + uint64(d.fs.bytesPerSector) - 1) / uint64(d.fs.bytesPerSector)

		// 读取扇区数据
		sectorData, err := d.fs.reader.ReadSectors(startSector, sectorCount)
		if err != nil {
			return nil, err
		}

		indexData = append(indexData, sectorData...)
	}

	// 解析索引根
	entries, err := parseIndexRoot(indexData)
	if err != nil {
		return nil, err
	}

	// 转换为FileSystemEntry接口
	d.entries = make([]FileSystemEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDirectory {
			dir := &NTFSDirectory{
				fs:               d.fs,
				recordNumber:     entry.MFTReference & 0xFFFFFFFFFFFF,
				name:             entry.FileName,
				path:             filepath.Join(d.path, entry.FileName),
				isDeleted:        false,
				creationTime:     entry.CreationTime,
				modificationTime: entry.ModificationTime,
				accessTime:       entry.AccessTime,
				attributes:       entry.Attributes,
			}
			d.entries = append(d.entries, dir)
		} else {
			file := &NTFSFile{
				fs:               d.fs,
				recordNumber:     entry.MFTReference & 0xFFFFFFFFFFFF,
				name:             entry.FileName,
				path:             filepath.Join(d.path, entry.FileName),
				size:             entry.Size,
				isDeleted:        false,
				creationTime:     entry.CreationTime,
				modificationTime: entry.ModificationTime,
				accessTime:       entry.AccessTime,
				attributes:       entry.Attributes,
			}
			d.entries = append(d.entries, file)
		}
	}

	return d.entries, nil
}

// GetEntry 获取指定名称的条目
func (d *NTFSDirectory) GetEntry(name string) (FileSystemEntry, error) {
	entries, err := d.GetEntries()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.GetName() == name {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("未找到条目: %s", name)
}

// MFTRecord 表示NTFS的主文件表记录
type MFTRecord struct {
	RecordNumber uint64
	InUse        bool
	IsDirectory  bool
	FileName     string
	FilePath     string
	ParentRef    uint64
	Size         uint64

	// 时间信息
	CreationTime     time.Time
	ModificationTime time.Time
	AccessTime       time.Time

	// 属性
	Attributes uint32

	// 数据运行
	DataRuns []DataRun
}

// DataRun 表示NTFS数据运行
type DataRun struct {
	StartCluster uint64
	ClusterCount uint64
}

// getMFTRecord 读取指定的MFT记录
func (fs *NTFSFileSystem) getMFTRecord(recordNumber uint64) (*MFTRecord, error) {
	// 检查缓存
	if record, ok := fs.mftCache[recordNumber]; ok {
		return record, nil
	}

	// 计算记录的位置
	mftStartSector := fs.mftStartCluster * uint64(fs.sectorsPerCluster)
	recordOffset := recordNumber * uint64(fs.bytesPerMFTEntry)
	recordSector := mftStartSector + (recordOffset / uint64(fs.bytesPerSector))
	recordCount := uint64(fs.bytesPerMFTEntry) / uint64(fs.bytesPerSector)
	if fs.bytesPerMFTEntry%uint32(fs.bytesPerSector) != 0 {
		recordCount++
	}

	// 读取记录数据
	data, err := fs.reader.ReadSectors(recordSector, recordCount)
	if err != nil {
		return nil, fmt.Errorf("读取MFT记录数据失败: %w", err)
	}

	// 检查记录头部标识 "FILE"
	if data[0] != 'F' || data[1] != 'I' || data[2] != 'L' || data[3] != 'E' {
		return nil, fmt.Errorf("无效的MFT记录标识")
	}

	// 创建记录对象
	record := &MFTRecord{
		RecordNumber: recordNumber,
		InUse:        (data[0x16] & 0x01) != 0,
		IsDirectory:  (data[0x16] & 0x02) != 0,
	}

	// 解析属性列表
	attributesOffset := binary.LittleEndian.Uint16(data[0x14:0x16])
	attributesSize := binary.LittleEndian.Uint32(data[0x18:0x1C])

	// 遍历属性列表
	currentOffset := attributesOffset
	for currentOffset < attributesOffset+uint16(attributesSize) {
		attributeType := binary.LittleEndian.Uint32(data[currentOffset : currentOffset+4])
		attributeSize := binary.LittleEndian.Uint32(data[currentOffset+4 : currentOffset+8])

		switch attributeType {
		case 0x10: // $STANDARD_INFORMATION
			// 解析标准信息属性
			infoOffset := currentOffset + uint16(binary.LittleEndian.Uint16(data[currentOffset+0x14:currentOffset+0x16]))
			record.CreationTime = parseNTFSTime(data[infoOffset : infoOffset+8])
			record.ModificationTime = parseNTFSTime(data[infoOffset+8 : infoOffset+16])
			record.AccessTime = parseNTFSTime(data[infoOffset+16 : infoOffset+24])
			record.Attributes = binary.LittleEndian.Uint32(data[infoOffset+32 : infoOffset+36])

		case 0x30: // $FILE_NAME
			// 解析文件名属性
			nameOffset := currentOffset + uint16(binary.LittleEndian.Uint16(data[currentOffset+0x14:currentOffset+0x16]))
			fileNameLength := data[nameOffset+64]
			fileName := make([]uint16, fileNameLength)
			for i := uint8(0); i < fileNameLength; i++ {
				fileName[i] = binary.LittleEndian.Uint16(data[nameOffset+66+uint16(i)*2 : nameOffset+68+uint16(i)*2])
			}
			record.FileName = string(utf16.Decode(fileName))
			record.ParentRef = binary.LittleEndian.Uint64(data[nameOffset+48 : nameOffset+56])

		case 0x80: // $DATA
			// 解析数据属性
			if record.IsDirectory {
				// 目录的数据属性包含索引根
				// TODO: 实现索引根解析
			} else {
				// 文件的数据属性包含数据运行
				// TODO: 实现数据运行解析
			}
		}

		currentOffset += uint16(attributeSize)
	}

	// 添加到缓存
	fs.mftCache[recordNumber] = record

	return record, nil
}

// parseNTFSTime 解析NTFS时间格式（100纳秒精度，从1601年开始）
func parseNTFSTime(data []byte) time.Time {
	if len(data) < 8 {
		return time.Time{}
	}

	// NTFS时间是从1601年1月1日开始的100纳秒间隔数
	ntfsTime := binary.LittleEndian.Uint64(data)
	if ntfsTime == 0 {
		return time.Time{}
	}

	// 转换为Unix时间戳
	unixTime := int64(ntfsTime/10000000 - 11644473600)
	return time.Unix(unixTime, 0).UTC()
}

// parseDataRuns 解析数据运行列表
func parseDataRuns(data []byte, offset uint16) ([]DataRun, error) {
	var runs []DataRun
	currentOffset := offset

	for {
		// 读取数据运行头部
		if currentOffset >= uint16(len(data)) {
			break
		}

		header := data[currentOffset]
		if header == 0 {
			break // 数据运行列表结束
		}

		// 解析长度和偏移量字段的大小
		lengthSize := header & 0x0F
		offsetSize := (header >> 4) & 0x0F

		// 检查是否有足够的数据
		if currentOffset+1+uint16(lengthSize)+uint16(offsetSize) > uint16(len(data)) {
			return nil, fmt.Errorf("数据运行数据不完整")
		}

		// 读取长度
		var length uint64
		for i := uint8(0); i < lengthSize; i++ {
			length |= uint64(data[currentOffset+1+uint16(i)]) << (i * 8)
		}

		// 读取偏移量
		var offset uint64
		for i := uint8(0); i < offsetSize; i++ {
			offset |= uint64(data[currentOffset+1+uint16(lengthSize)+uint16(i)]) << (i * 8)
		}

		// 如果是相对偏移量，需要加上前一个数据运行的起始簇号
		if len(runs) > 0 {
			offset += runs[len(runs)-1].StartCluster + runs[len(runs)-1].ClusterCount
		}

		// 添加到数据运行列表
		runs = append(runs, DataRun{
			StartCluster: offset,
			ClusterCount: length,
		})

		// 移动到下一个数据运行
		currentOffset += 1 + uint16(lengthSize) + uint16(offsetSize)
	}

	return runs, nil
}

// NTFSFileReader 实现了NTFS文件的Reader
type NTFSFileReader struct {
	fs      *NTFSFileSystem
	record  *MFTRecord
	size    uint64
	pos     uint64
	current int    // 当前数据运行索引
	offset  uint64 // 当前数据运行中的偏移量
}

// Read 实现io.Reader接口
func (r *NTFSFileReader) Read(p []byte) (n int, err error) {
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
		// 如果当前数据运行已读完，移动到下一个
		if r.current >= len(r.record.DataRuns) {
			return bytesRead, io.EOF
		}

		run := r.record.DataRuns[r.current]
		runSize := run.ClusterCount * uint64(r.fs.clusterSize)

		// 如果当前数据运行已读完
		if r.offset >= runSize {
			r.current++
			r.offset = 0
			continue
		}

		// 计算在当前数据运行中要读取的字节数
		bytesToRead := uint64(len(p) - bytesRead)
		if r.offset+bytesToRead > runSize {
			bytesToRead = runSize - r.offset
		}

		// 计算扇区位置
		startSector := run.StartCluster * uint64(r.fs.sectorsPerCluster)
		sectorOffset := r.offset / uint64(r.fs.bytesPerSector)
		sectorCount := (bytesToRead + uint64(r.fs.bytesPerSector) - 1) / uint64(r.fs.bytesPerSector)

		// 读取扇区数据
		sectorData, err := r.fs.reader.ReadSectors(startSector+sectorOffset, sectorCount)
		if err != nil {
			return bytesRead, err
		}

		// 复制数据
		offset := r.offset % uint64(r.fs.bytesPerSector)
		copy(p[bytesRead:bytesRead+int(bytesToRead)], sectorData[offset:offset+bytesToRead])

		// 更新位置
		r.offset += bytesToRead
		bytesRead += int(bytesToRead)
		r.pos += bytesToRead
	}

	return bytesRead, nil
}

// ReadAt 目录不支持从指定位置读取
func (d *NTFSDirectory) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, fmt.Errorf("不能从目录中读取数据")
}
