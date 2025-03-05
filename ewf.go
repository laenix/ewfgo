package ewf

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

type EWFImage struct {
	filepath string
	Sections []*Section
}

const (
	// MediaType
	RemovableStorageMediaDevice = 0x00
	FixedStorageMediaDevice     = 0x01
	OpticalDiscDevice           = 0x03
	LogicalEvidenceFile         = 0x0e
	RAM                         = 0x10
)

const (
	// MediaFlag
	ImageFile            = 0x01
	PhysicalDevice       = 0x02
	FastblocWriteBlocker = 0x04
	TableauWriteBlocker  = 0x08
)

const (
	// CompressionLevel
	NoCompression   = 0x00
	GoodCompression = 0x01
	BestCompression = 0x02
)

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

// 3.8 Sector
type SectorsSection struct {
}

// 3.9 Table
type TableSection struct {
	EntryNumber uint32   // 表项数
	Padding     [16]byte // 分割 - 无意义
	CheckSum    uint32   // 校验和
}

// 3.10 Table2
type Table2Section struct {
	EntryNumber uint32   // 表项数
	Padding     [16]byte // 分割 - 无意义
	CheckSum    uint32   // 校验和
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
type DigestSection struct{}

// 3.18 Hash
type HashSection struct{}

// 3.19 Done
type DoneSection struct{}

func IsEWFFile(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}

	header := make([]byte, 13)
	if _, err := file.Read(header); err != nil {
		return false
	}
	file.Close()
	expectedSignature := []byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00}
	return bytes.Equal(header[:8], expectedSignature)
}

func NewWithFilePath(filepath string) *EWFImage {
	return &EWFImage{
		filepath: filepath,
	}
}

func (e *EWFImage) Parse() error {
	file, err := os.Open(e.filepath)
	if err != nil {
		fmt.Println(err)
	}
	section, err := e.ReadSection(file, 13)
	e.Sections = append(e.Sections, section)

	if err != nil {
		fmt.Println(err)
	}
	// fmt.Println("section", section)
	for {
		fmt.Println("next offset: ", section.NextOffset)
		fmt.Println("next size: ", section.SectionSize)
		section, err = e.ReadSection(file, int64(section.NextOffset))
		if err != nil {
			fmt.Println(err)
		}
		if string(bytes.TrimRight(section.SectionTypeDefinition[:], "\x00")) == "done" {
			break
		}
		// 添加section
		e.Sections = append(e.Sections, section)
		switch string(bytes.TrimRight(section.SectionTypeDefinition[:], "\x00")) {
		case "header":
			e.ParseHeaderSection(file, section)
		case "header2":
			e.ParseHeaderSection(file, section)
		case "disk":
			// e.ParseEWFSpecification(file, section)
			e.ParseVolume(file, section)
		case "sectors":
			fmt.Println("sectors")
		case "table":
			e.ParseTable(file, section)
		case "table2":
			e.ParseTable(file, section)
		case "digest":
			fmt.Println("digest")
		case "hash":
			fmt.Println("hash")
		case "data":
			fmt.Println("data")
		}
	}
	return nil
}

func (e *EWFImage) ReadSection(file *os.File, offset int64) (*Section, error) {
	section := &Section{}
	file.Seek(offset, io.SeekStart)

	err := binary.Read(file, binary.LittleEndian, section)
	if err != nil {
		return nil, err
	}
	fmt.Println("section Type", string(bytes.TrimRight(section.SectionTypeDefinition[:], "\x00")))
	return section, nil
}

func (e *EWFImage) ParseHeaderSection(file *os.File, section *Section) ([]byte, error) {
	fmt.Println("ParseHeaderSection")
	compressedData := make([]byte, section.SectionSize-76) // 减去 Section 头大小
	if _, err := file.Read(compressedData); err != nil {
		return nil, err
	}

	// 解压 zlib 数据
	r, err := zlib.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var out bytes.Buffer
	io.Copy(&out, r)
	// fmt.Println("Decompressed data: ", out.String())
	lines := strings.Split(out.String(), "\n")
	// fmt.Println("lines: ", lines)
	// fmt.Println("first line: ", lines[0])
	// fmt.Println("second line: ", lines[1])
	// fmt.Println("third line: ", lines[2])

	// if lines[0] != "1" {
	// 	fmt.Println("error in parsing header section 1")
	// }
	// if lines[1] != "main" {
	// 	fmt.Println("error in parsing header section main")
	// }

	flags := strings.Split(lines[2], "\t")
	values := strings.Split(lines[3], "\t")

	header := &HeaderSectionString{}
	for k, _ := range flags {
		// c	n	a	e	t	av	ov	m	u	p	r
		switch flags[k] {
		case "c":
			header.CaseNumber = values[k]
		case "n":
			header.EvidenceNumber = values[k]
		case "a":
			header.UniqueDescription = values[k]
		case "e":
			header.ExaminerName = values[k]
		case "t":
			header.Notes = values[k]
		case "av":
			header.Version = values[k]
		case "ov":
			header.Platform = values[k]
		case "m":
			header.AcquisitionDate = values[k]
		case "u":
			header.SystemDate = values[k]
		case "p":
			header.PasswordHash = values[k]
		case "r":
			header.Char = values[k]
		}
	}
	fmt.Println("Header: ", header)
	fmt.Println("Header.CaseNumber: ", header.CaseNumber)
	fmt.Println("Header.EvidenceNumber: ", header.EvidenceNumber)
	fmt.Println("Header.UniqueDescription: ", header.UniqueDescription)
	fmt.Println("Header.ExaminerName: ", header.ExaminerName)
	fmt.Println("Header.Notes: ", header.Notes)
	fmt.Println("Header.Version: ", header.Version)
	fmt.Println("Header.Platform: ", header.Platform)
	fmt.Println("Header.AcquisitionDate: ", header.AcquisitionDate)
	fmt.Println("Header.SystemDate: ", header.SystemDate)
	fmt.Println("Header.PasswordHash: ", header.PasswordHash)
	fmt.Println("Header.Char: ", header.Char)

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	if len(buf.Bytes()) < 94 {
		return nil, fmt.Errorf("invalid header section")
	}

	return buf.Bytes(), nil
}
func (e *EWFImage) ParseVolume(file *os.File, section *Section) (DiskSMART, error) {
	fmt.Println("ParseVolumeSection")
	disk := DiskSMART{}
	err := binary.Read(file, binary.LittleEndian, &disk)
	if err != nil {
		fmt.Println("err", err)
		return disk, err
	}
	fmt.Println("DiskSMART: ", disk)
	fmt.Println("DiskSMART.MediaType: ", disk.MediaType)
	fmt.Println("DiskSMART.ChunkCount: ", disk.ChunkCount)
	fmt.Println("DiskSMART.ChunkSectors: ", disk.ChunkSectors)
	fmt.Println("DiskSMART.CompressionLevel: ", disk.CompressionLevel)
	fmt.Println("DiskSMART.CheckSum: ", disk.CheckSum)
	fmt.Println("DiskSMART.Signature: ", disk.Signature)
	fmt.Println("DiskSMART.SegmentFileSetIdentifier : ", disk.SegmentFileSetIdentifier)
	return disk, nil
}

func (e *EWFImage) ParseSectors(file *os.File, section *Section) (SectorsSection, error) {
	fmt.Println("ParseSectors")
	sectors := SectorsSection{}
	err := binary.Read(file, binary.LittleEndian, &sectors)
	if err != nil {
		fmt.Println("err", err)
		return sectors, err
	}
	fmt.Println("SectorsSection: ", sectors)
	return sectors, nil
}

// func (e *EWFImage) ParseEWFSpecification(file *os.File, section *Section) (*EWFSpecification, error) {
// 	fmt.Println("ParseEWFSpecification")

// 	ewfSpecification := &EWFSpecification{}
// 	err := binary.Read(file, binary.LittleEndian, ewfSpecification)
// 	if err != nil {
// 		fmt.Println("err", err)
// 		return nil, err
// 	}
// 	fmt.Println("EWFSpecification: ", ewfSpecification)
// 	fmt.Println("EWFSpecification.Reserved: ", ewfSpecification.Reserved)
// 	fmt.Println("EWFSpecification.SegmentChunk: ", ewfSpecification.SegmentChunk)
// 	fmt.Println("EWFSpecification.ChunkSectors: ", ewfSpecification.ChunkSectors)
// 	fmt.Println("EWFSpecification.SectorsBytes: ", ewfSpecification.SectorsBytes)
// 	fmt.Println("EWFSpecification.Reserved2: ", ewfSpecification.Reserved2)
// 	fmt.Println("EWFSpecification.Signature: ", ewfSpecification.Signature)
// 	return ewfSpecification, nil
// }

func (e *EWFImage) ParseTable(file *os.File, section *Section) (*TableSection, error) {
	fmt.Println("ParseTable")
	table := &TableSection{}
	err := binary.Read(file, binary.LittleEndian, table)
	if err != nil {
		return nil, err
	}
	fmt.Println("table:", table)
	fmt.Println("table.EntryNumber : ", table.EntryNumber)
	return table, nil
}
