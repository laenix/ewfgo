package filesystem

import (
	"io"
	"time"
)

// FileSystemEntry 表示文件系统中的一个条目（文件或目录）
type FileSystemEntry interface {
	// GetName 获取条目名称
	GetName() string
	// GetPath 获取完整路径
	GetPath() string
	// GetSize 获取大小（对于目录返回0）
	GetSize() uint64
	// IsDirectory 是否为目录
	IsDirectory() bool
	// GetModificationTime 获取修改时间
	GetModificationTime() time.Time
	// GetCreationTime 获取创建时间
	GetCreationTime() time.Time
	// GetAccessTime 获取访问时间
	GetAccessTime() time.Time
	// GetAttributes 获取属性
	GetAttributes() uint32
	// IsDeleted 是否已删除
	IsDeleted() bool
}

// File 表示文件系统中的一个文件
type File interface {
	FileSystemEntry
	// ReadAll 读取所有内容
	ReadAll() ([]byte, error)
	// ReadAt 从指定位置读取
	ReadAt(p []byte, off int64) (n int, err error)
	// Open 打开文件并返回一个Reader
	Open() (io.Reader, error)
}

// Directory 表示文件系统中的一个目录
type Directory interface {
	FileSystemEntry
	// GetEntries 获取目录内容
	GetEntries() ([]FileSystemEntry, error)
	// GetEntry 获取指定名称的条目
	GetEntry(name string) (FileSystemEntry, error)
	// GetDirectories 获取所有子目录
	GetDirectories() ([]Directory, error)
	// GetFiles 获取所有文件
	GetFiles() ([]File, error)
}

// FileSystem 表示一个文件系统
type FileSystem interface {
	// GetType 获取文件系统类型
	GetType() FileSystemType
	// GetRootDirectory 获取根目录
	GetRootDirectory() (Directory, error)
	// GetFileByPath 根据路径获取文件
	GetFileByPath(path string) (File, error)
	// GetDirectoryByPath 根据路径获取目录
	GetDirectoryByPath(path string) (Directory, error)
}

// Reader 定义读取接口
type Reader interface {
	// ReadSector 读取指定扇区
	ReadSector(sectorNumber uint64) ([]byte, error)
	// ReadSectors 读取多个连续扇区
	ReadSectors(startSector, count uint64) ([]byte, error)
	// ReadBytes 读取指定字节
	ReadBytes(offset uint64, size uint64) ([]byte, error)
	// GetSectorSize 获取扇区大小
	GetSectorSize() uint32
	// GetSectorCount 获取扇区总数
	GetSectorCount() uint64
}
