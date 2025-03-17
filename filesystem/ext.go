package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// EXT文件系统常量
const (
	EXT_SUPER_MAGIC  = 0xEF53
	EXT4_SUPER_MAGIC = 0xEF53
	EXT3_SUPER_MAGIC = 0xEF53
	EXT2_SUPER_MAGIC = 0xEF53
)

// EXT超级块结构
type EXTSuperBlock struct {
	InodesCount       uint32
	BlocksCount       uint32
	ReservedBlocks    uint32
	FreeBlocksCount   uint32
	FreeInodesCount   uint32
	FirstDataBlock    uint32
	LogBlockSize      uint32
	LogClusterSize    uint32
	BlocksPerGroup    uint32
	FragmentsPerGroup uint32
	InodesPerGroup    uint32
	Magic             uint16
	State             uint16
	Errors            uint16
	MinorRevision     uint16
	LastCheck         uint32
	CheckInterval     uint32
	CreatorOS         uint32
	RevisionLevel     uint32
	ReservedUID       uint16
	ReservedGID       uint16
	FirstInode        uint32
	InodeSize         uint16
	BlockGroupNumber  uint16
	FeatureCompat     uint32
	FeatureIncompat   uint32
	FeatureROCompat   uint32
	UUID              [16]byte
	VolumeName        [16]byte
	LastMounted       [64]byte
	AlgorithmBitmap   uint32
	PreallocBlocks    uint8
	PreallocDirBlks   uint8
	ReservedGDTBlks   uint16
	JournalUUID       [16]byte
	JournalInum       uint32
	JournalDev        uint32
	LastOrphan        uint32
	HashSeed          [4]uint32
	DefaultHashVer    uint8
	JournalBackup     uint8
	GroupDescSize     uint16
	DefaultMountOpts  uint32
	FirstMetaBG       uint32
	MkfsTime          uint32
	JournalBlocks     [17]uint32
	Reserved          [98]uint32
}

// EXT文件系统结构
type EXTFileSystem struct {
	reader     Reader
	superBlock *EXTSuperBlock
	blockSize  uint32
	fsType     FileSystemType
}

// NewEXT4 创建EXT4文件系统
func NewEXT4(reader Reader) (FileSystem, error) {
	return newEXTFileSystem(reader, FileSystemTypeEXT4)
}

// NewEXT3 创建EXT3文件系统
func NewEXT3(reader Reader) (FileSystem, error) {
	return newEXTFileSystem(reader, FileSystemTypeEXT3)
}

// NewEXT2 创建EXT2文件系统
func NewEXT2(reader Reader) (FileSystem, error) {
	return newEXTFileSystem(reader, FileSystemTypeEXT2)
}

// newEXTFileSystem 创建一个新的EXT文件系统解析器
func newEXTFileSystem(reader Reader, fsType FileSystemType) (FileSystem, error) {
	// 读取超级块
	superBlock := &EXTSuperBlock{}
	superBlockData, err := reader.ReadBytes(1024, 1024)
	if err != nil {
		return nil, fmt.Errorf("读取EXT超级块失败: %w", err)
	}

	if err := binary.Read(bytes.NewReader(superBlockData), binary.LittleEndian, superBlock); err != nil {
		return nil, fmt.Errorf("解析EXT超级块失败: %w", err)
	}

	// 验证魔数
	if superBlock.Magic != EXT_SUPER_MAGIC {
		return nil, fmt.Errorf("无效的EXT文件系统魔数")
	}

	// 计算块大小
	blockSize := uint32(1) << (10 + superBlock.LogBlockSize)

	// 创建文件系统对象
	fs := &EXTFileSystem{
		reader:     reader,
		superBlock: superBlock,
		blockSize:  blockSize,
		fsType:     fsType,
	}

	return fs, nil
}

// GetType 获取文件系统类型
func (fs *EXTFileSystem) GetType() FileSystemType {
	return fs.fsType
}

// GetRootDirectory 获取根目录
func (fs *EXTFileSystem) GetRootDirectory() (Directory, error) {
	// 读取根目录的inode
	rootInode, err := fs.readInode(2) // 根目录的inode号是2
	if err != nil {
		return nil, err
	}

	return &EXTDirectory{
		fs:    fs,
		inode: rootInode,
		path:  "/",
	}, nil
}

// GetFileByPath 根据路径获取文件
func (fs *EXTFileSystem) GetFileByPath(path string) (File, error) {
	// 解析路径
	parts := strings.Split(strings.Trim(path, "/"), "/")
	currentInode, err := fs.readInode(2) // 从根目录开始
	if err != nil {
		return nil, err
	}

	for _, part := range parts {
		if part == "" {
			continue
		}

		// 在当前目录中查找文件
		entry, err := fs.findEntry(currentInode, part)
		if err != nil {
			return nil, err
		}

		currentInode, err = fs.readInode(entry.Inode)
		if err != nil {
			return nil, err
		}
	}

	// 检查是否为文件
	if currentInode.Mode&0xF000 != 0x8000 {
		return nil, fmt.Errorf("不是文件: %s", path)
	}

	return &EXTFile{
		fs:    fs,
		inode: currentInode,
		path:  path,
		size:  uint64(currentInode.Size),
		name:  filepath.Base(path),
	}, nil
}

// GetDirectoryByPath 根据路径获取目录
func (fs *EXTFileSystem) GetDirectoryByPath(path string) (Directory, error) {
	// 解析路径
	parts := strings.Split(strings.Trim(path, "/"), "/")
	currentInode, err := fs.readInode(2) // 从根目录开始
	if err != nil {
		return nil, err
	}

	for _, part := range parts {
		if part == "" {
			continue
		}

		// 在当前目录中查找目录
		entry, err := fs.findEntry(currentInode, part)
		if err != nil {
			return nil, err
		}

		currentInode, err = fs.readInode(entry.Inode)
		if err != nil {
			return nil, err
		}

		// 检查是否为目录
		if currentInode.Mode&0xF000 != 0x4000 {
			return nil, fmt.Errorf("不是目录: %s", part)
		}
	}

	return &EXTDirectory{
		fs:    fs,
		inode: currentInode,
		path:  path,
	}, nil
}

// EXTFile 表示EXT文件系统中的文件
type EXTFile struct {
	fs    *EXTFileSystem
	inode *EXTInode
	path  string
	size  uint64
	name  string
}

// GetName 获取文件名
func (f *EXTFile) GetName() string {
	return f.name
}

// GetPath 获取完整路径
func (f *EXTFile) GetPath() string {
	return f.path
}

// GetSize 获取文件大小
func (f *EXTFile) GetSize() uint64 {
	return f.size
}

// IsDirectory 是否为目录
func (f *EXTFile) IsDirectory() bool {
	return false
}

// GetModificationTime 获取修改时间
func (f *EXTFile) GetModificationTime() time.Time {
	return time.Unix(int64(f.inode.Mtime), 0)
}

// GetCreationTime 获取创建时间
func (f *EXTFile) GetCreationTime() time.Time {
	return time.Unix(int64(f.inode.Ctime), 0)
}

// GetAccessTime 获取访问时间
func (f *EXTFile) GetAccessTime() time.Time {
	return time.Unix(int64(f.inode.Atime), 0)
}

// GetAttributes 获取属性
func (f *EXTFile) GetAttributes() uint32 {
	return uint32(f.inode.Mode)
}

// ReadAll 读取所有内容
func (f *EXTFile) ReadAll() ([]byte, error) {
	return f.fs.readInodeData(f.inode)
}

// ReadAt 从指定位置读取
func (f *EXTFile) ReadAt(p []byte, off int64) (n int, err error) {
	data, err := f.fs.readInodeData(f.inode)
	if err != nil {
		return 0, err
	}

	if off >= int64(len(data)) {
		return 0, io.EOF
	}

	n = copy(p, data[off:])
	return n, nil
}

// IsDeleted 检查文件是否已删除
func (f *EXTFile) IsDeleted() bool {
	return f.inode.Mode == 0
}

// EXTDirectory 表示EXT文件系统中的目录
type EXTDirectory struct {
	fs    *EXTFileSystem
	inode *EXTInode
	path  string
}

// GetName 获取目录名
func (d *EXTDirectory) GetName() string {
	return filepath.Base(d.path)
}

// GetPath 获取完整路径
func (d *EXTDirectory) GetPath() string {
	return d.path
}

// GetSize 获取目录大小
func (d *EXTDirectory) GetSize() uint64 {
	return 0
}

// IsDirectory 是否为目录
func (d *EXTDirectory) IsDirectory() bool {
	return true
}

// GetModificationTime 获取修改时间
func (d *EXTDirectory) GetModificationTime() time.Time {
	return time.Unix(int64(d.inode.Mtime), 0)
}

// GetCreationTime 获取创建时间
func (d *EXTDirectory) GetCreationTime() time.Time {
	return time.Unix(int64(d.inode.Ctime), 0)
}

// GetAccessTime 获取访问时间
func (d *EXTDirectory) GetAccessTime() time.Time {
	return time.Unix(int64(d.inode.Atime), 0)
}

// GetAttributes 获取属性
func (d *EXTDirectory) GetAttributes() uint32 {
	return uint32(d.inode.Mode)
}

// GetEntries 获取目录内容
func (d *EXTDirectory) GetEntries() ([]FileSystemEntry, error) {
	// 读取目录数据
	data, err := d.fs.readInodeData(d.inode)
	if err != nil {
		return nil, err
	}

	var entries []FileSystemEntry
	offset := 0

	for offset < len(data) {
		// 读取目录项
		entry := &EXTDirEntry{}
		if err := binary.Read(bytes.NewReader(data[offset:]), binary.LittleEndian, entry); err != nil {
			return nil, err
		}

		// 跳过.和..
		if entry.NameLen == 1 && data[offset+8] == '.' {
			offset += int(entry.RecLen)
			continue
		}
		if entry.NameLen == 2 && data[offset+8] == '.' && data[offset+9] == '.' {
			offset += int(entry.RecLen)
			continue
		}

		// 获取文件名
		name := string(data[offset+8 : offset+8+int(entry.NameLen)])

		// 读取inode
		inode, err := d.fs.readInode(entry.Inode)
		if err != nil {
			return nil, err
		}

		// 创建条目
		entryPath := filepath.Join(d.path, name)
		if inode.Mode&0xF000 == 0x4000 {
			entries = append(entries, &EXTDirectory{
				fs:    d.fs,
				inode: inode,
				path:  entryPath,
			})
		} else {
			entries = append(entries, &EXTFile{
				fs:    d.fs,
				inode: inode,
				path:  entryPath,
				size:  uint64(inode.Size),
				name:  name,
			})
		}

		offset += int(entry.RecLen)
	}

	return entries, nil
}

// GetEntry 获取指定名称的条目
func (d *EXTDirectory) GetEntry(name string) (FileSystemEntry, error) {
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

// GetDirectories 获取所有子目录
func (d *EXTDirectory) GetDirectories() ([]Directory, error) {
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

// IsDeleted 检查目录是否已删除
func (d *EXTDirectory) IsDeleted() bool {
	return d.inode.Mode == 0
}

// GetFiles 获取所有文件
func (d *EXTDirectory) GetFiles() ([]File, error) {
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

// Open 打开文件并返回一个Reader
func (f *EXTFile) Open() (io.Reader, error) {
	// 创建一个新的reader
	return &EXTFileReader{
		file:   f,
		offset: 0,
	}, nil
}

// EXTFileReader 实现了io.Reader接口
type EXTFileReader struct {
	file   *EXTFile
	offset int64
}

// Read 实现io.Reader接口
func (r *EXTFileReader) Read(p []byte) (n int, err error) {
	if r.offset >= int64(r.file.size) {
		return 0, io.EOF
	}

	// 计算要读取的字节数
	remaining := int64(r.file.size) - r.offset
	toRead := int64(len(p))
	if toRead > remaining {
		toRead = remaining
	}

	// 读取数据
	data, err := r.file.ReadAt(p[:toRead], r.offset)
	if err != nil {
		return data, err
	}

	r.offset += int64(data)
	return data, nil
}

// EXTInode 表示EXT文件系统的inode结构
type EXTInode struct {
	Mode       uint16
	UID        uint16
	Size       uint32
	Atime      uint32
	Ctime      uint32
	Mtime      uint32
	Blocks     uint32
	Flags      uint32
	OSD1       uint32
	Block      [15]uint32
	Generation uint32
	FileACL    uint32
	DirACL     uint32
	FAddr      uint32
	OSD2       [12]byte
}

// EXTDirEntry 表示EXT文件系统的目录项结构
type EXTDirEntry struct {
	Inode    uint32
	RecLen   uint16
	NameLen  uint8
	FileType uint8
	Name     [255]byte
}

// readInode 读取inode
func (fs *EXTFileSystem) readInode(inodeNum uint32) (*EXTInode, error) {
	// 计算inode所在的块组
	groupNum := (inodeNum - 1) / fs.superBlock.InodesPerGroup
	inodeIndex := (inodeNum - 1) % fs.superBlock.InodesPerGroup

	// 读取inode表
	inodeTableBlock := fs.superBlock.FirstDataBlock + 1 + groupNum*fs.superBlock.BlocksPerGroup
	inodeData, err := fs.reader.ReadBytes(uint64(inodeTableBlock)*uint64(fs.blockSize), uint64(fs.blockSize))
	if err != nil {
		return nil, err
	}

	// 解析inode
	inode := &EXTInode{}
	offset := int(inodeIndex) * 128 // inode大小为128字节
	if err := binary.Read(bytes.NewReader(inodeData[offset:offset+128]), binary.LittleEndian, inode); err != nil {
		return nil, err
	}

	return inode, nil
}

// readInodeData 读取inode的数据
func (fs *EXTFileSystem) readInodeData(inode *EXTInode) ([]byte, error) {
	var data []byte
	remainingSize := inode.Size

	// 读取直接块
	for i := 0; i < 12 && remainingSize > 0; i++ {
		if inode.Block[i] == 0 {
			break
		}

		blockData, err := fs.reader.ReadBytes(uint64(inode.Block[i])*uint64(fs.blockSize), uint64(fs.blockSize))
		if err != nil {
			return nil, err
		}

		bytesToRead := uint32(len(blockData))
		if bytesToRead > remainingSize {
			bytesToRead = remainingSize
		}

		data = append(data, blockData[:bytesToRead]...)
		remainingSize -= bytesToRead
	}

	// 读取间接块
	if remainingSize > 0 && inode.Block[12] != 0 {
		indirectData, err := fs.reader.ReadBytes(uint64(inode.Block[12])*uint64(fs.blockSize), uint64(fs.blockSize))
		if err != nil {
			return nil, err
		}

		indirectBlocks := make([]uint32, len(indirectData)/4)
		if err := binary.Read(bytes.NewReader(indirectData), binary.LittleEndian, indirectBlocks); err != nil {
			return nil, err
		}

		for _, block := range indirectBlocks {
			if block == 0 || remainingSize == 0 {
				break
			}

			blockData, err := fs.reader.ReadBytes(uint64(block)*uint64(fs.blockSize), uint64(fs.blockSize))
			if err != nil {
				return nil, err
			}

			bytesToRead := uint32(len(blockData))
			if bytesToRead > remainingSize {
				bytesToRead = remainingSize
			}

			data = append(data, blockData[:bytesToRead]...)
			remainingSize -= bytesToRead
		}
	}

	return data, nil
}

// findEntry 在目录中查找指定名称的条目
func (fs *EXTFileSystem) findEntry(dirInode *EXTInode, name string) (*EXTDirEntry, error) {
	data, err := fs.readInodeData(dirInode)
	if err != nil {
		return nil, err
	}

	offset := 0
	for offset < len(data) {
		entry := &EXTDirEntry{}
		if err := binary.Read(bytes.NewReader(data[offset:]), binary.LittleEndian, entry); err != nil {
			return nil, err
		}

		entryName := string(data[offset+8 : offset+8+int(entry.NameLen)])
		if entryName == name {
			return entry, nil
		}

		offset += int(entry.RecLen)
	}

	return nil, fmt.Errorf("未找到条目: %s", name)
}
