package filesystem

// FileSystemType 表示支持的文件系统类型
type FileSystemType string

const (
	// 支持的文件系统类型
	FileSystemTypeUnknown FileSystemType = "UNKNOWN"
	FileSystemTypeFAT12   FileSystemType = "FAT12"
	FileSystemTypeFAT16   FileSystemType = "FAT16"
	FileSystemTypeFAT32   FileSystemType = "FAT32"
	FileSystemTypeNTFS    FileSystemType = "NTFS"
	FileSystemTypeEXT2    FileSystemType = "EXT2"
	FileSystemTypeEXT3    FileSystemType = "EXT3"
	FileSystemTypeEXT4    FileSystemType = "EXT4"
	FileSystemTypeHFS     FileSystemType = "HFS"
	FileSystemTypeHFSPlus FileSystemType = "HFS+"
	FileSystemTypeRaw     FileSystemType = "RAW" // 添加一个RAW类型，用于处理非标准文件系统
)
