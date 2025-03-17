package filesystem

import (
	"fmt"
	"time"
)

// CreateFileSystem 根据文件系统类型创建对应的文件系统解析器
func CreateFileSystem(reader Reader) (FileSystem, error) {
	// 检测文件系统类型
	fsType, err := DetectFileSystem(reader)
	if err != nil {
		return nil, fmt.Errorf("检测文件系统失败: %w", err)
	}
	if fsType == FileSystemTypeUnknown {
		return nil, fmt.Errorf("无法检测文件系统类型")
	}

	// 根据文件系统类型创建对应的解析器
	switch fsType {
	case FileSystemTypeFAT12, FileSystemTypeFAT16, FileSystemTypeFAT32:
		return NewFAT32FileSystem(reader)
	case FileSystemTypeEXT2:
		return NewEXT2(reader)
	case FileSystemTypeEXT3:
		return NewEXT3(reader)
	case FileSystemTypeEXT4:
		return NewEXT4(reader)
	case FileSystemTypeNTFS:
		return NewNTFSFileSystem(reader)
	case FileSystemTypeRaw:
		// 对于RAW类型，创建一个简单的文件系统实现
		return NewRawFileSystem(reader)
	default:
		return nil, fmt.Errorf("不支持的文件系统类型: %s", fsType)
	}
}

// NewRawFileSystem 创建一个RAW文件系统实现
func NewRawFileSystem(reader Reader) (FileSystem, error) {
	return &RawFileSystem{
		reader: reader,
	}, nil
}

// RawFileSystem 实现了FileSystem接口，用于处理非标准文件系统
type RawFileSystem struct {
	reader Reader
}

// GetType 获取文件系统类型
func (fs *RawFileSystem) GetType() FileSystemType {
	return FileSystemTypeRaw
}

// GetRootDirectory 获取根目录
func (fs *RawFileSystem) GetRootDirectory() (Directory, error) {
	return &RawDirectory{
		fs:   fs,
		name: "/",
		path: "/",
	}, nil
}

// GetFileByPath 根据路径获取文件
func (fs *RawFileSystem) GetFileByPath(path string) (File, error) {
	return nil, fmt.Errorf("RAW文件系统不支持按路径获取文件")
}

// GetDirectoryByPath 根据路径获取目录
func (fs *RawFileSystem) GetDirectoryByPath(path string) (Directory, error) {
	if path == "/" {
		return fs.GetRootDirectory()
	}
	return nil, fmt.Errorf("RAW文件系统不支持按路径获取目录")
}

// RawDirectory 实现了Directory接口，用于处理非标准文件系统的目录
type RawDirectory struct {
	fs   *RawFileSystem
	name string
	path string
}

// GetName 获取目录名称
func (d *RawDirectory) GetName() string {
	return d.name
}

// GetPath 获取目录路径
func (d *RawDirectory) GetPath() string {
	return d.path
}

// GetSize 获取目录大小
func (d *RawDirectory) GetSize() uint64 {
	return 0
}

// IsDirectory 是否为目录
func (d *RawDirectory) IsDirectory() bool {
	return true
}

// GetModificationTime 获取修改时间
func (d *RawDirectory) GetModificationTime() time.Time {
	return time.Now()
}

// GetCreationTime 获取创建时间
func (d *RawDirectory) GetCreationTime() time.Time {
	return time.Now()
}

// GetAccessTime 获取访问时间
func (d *RawDirectory) GetAccessTime() time.Time {
	return time.Now()
}

// GetAttributes 获取属性
func (d *RawDirectory) GetAttributes() uint32 {
	return 0
}

// IsDeleted 是否已删除
func (d *RawDirectory) IsDeleted() bool {
	return false
}

// GetEntries 获取目录内容
func (d *RawDirectory) GetEntries() ([]FileSystemEntry, error) {
	return []FileSystemEntry{}, nil
}

// GetEntry 获取指定名称的条目
func (d *RawDirectory) GetEntry(name string) (FileSystemEntry, error) {
	return nil, fmt.Errorf("RAW文件系统不支持获取条目")
}

// GetDirectories 获取所有子目录
func (d *RawDirectory) GetDirectories() ([]Directory, error) {
	return []Directory{}, nil
}

// GetFiles 获取所有文件
func (d *RawDirectory) GetFiles() ([]File, error) {
	return []File{}, nil
}
