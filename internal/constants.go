package internal

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

type EWFImage struct {
	filepath       string // 文件路径
	Sections       []SectionWithAddress
	Headers        []HeaderSectionString
	Volumes        []EWFSpecification
	DiskSMART      []DiskSMART
	SectorsAddress []SectionWithAddress
	TableAddress   []SectionWithAddress
	Sectors        []SectorAndTableWithAddress
}

type SectionWithAddress struct {
	Section
	Address int64
}

type SectorAndTableWithAddress struct {
	Reader     io.ReadCloser
	TableEntry []uint32
}

// 3.5.5
const (
	// MediaType
	RemovableStorageMediaDevice = 0x00
	FixedStorageMediaDevice     = 0x01
	OpticalDiscDevice           = 0x03
	LogicalEvidenceFile         = 0x0e
	RAM                         = 0x10
)

// 3.5.6
const (
	// MediaFlag
	ImageFile            = 0x01
	PhysicalDevice       = 0x02
	FastblocWriteBlocker = 0x04
	TableauWriteBlocker  = 0x08
)

// 3.5.7
const (
	// CompressionLevel
	NoCompression   = 0x00
	GoodCompression = 0x01
	BestCompression = 0x02
)

var EVFSignature = [8]byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00}
var EWFFileHeaderLength = int64(13)
var SectionLength = int64(76)
var EWFSpecificationLength = int64(94)
var DiskSMARTLength = int64(1052)
var TableSectionLength = int64(24)

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

// 3.3
type HeaderSectionString struct {
	// header2
	// line 1 for encase 4
	// 1
	// line 1 for encase 5 to 7
	// 3

	// line 2
	// main

	// line 3 for encase 4
	L3_a  string // Unique description
	L3_c  string // Case number
	L3_n  string // Evidence number
	L3_e  string // Examiner name
	L3_t  string // Notes
	L3_av string // Version
	L3_ov string // Platform
	L3_m  string // Acquisition date and time
	L3_u  string // System date and time
	L3_p  string // Password hash
	// line 3 for encase 5 to 7
	L3_md  string // The model of the media, i.e. hard disk model
	L3_sn  string // The serial number of media
	L3_l   string // The device label
	L3_pid string // Process identifier
	L3_dc  string // Unknown
	L3_ext string // Extents
	// line 4
	// line 5
	// empty
	// line 6 for encase 5 to 7
	// srce
	// line 7 for encase 5 to 7
	// Line 7 consists of 2 values, namely the values are "0 1".
	// line 8 for encase 5 to 7
	L8_p   string // p
	L8_n   string // n
	L8_id  string // Identifier
	L8_ev  string // Evidence number
	L8_tb  string // Total bytes
	L8_lo  string // Logical offset
	L8_po  string // Physical offset
	L8_ah  string // MD5 hash
	L8_sh  string // SHA1 hash
	L8_gu  string // Device GUID
	L8_pgu string // Primary device GUID
	L8_aq  string // Acquisition date and time
	// line 9 for encase 5 to 7
	// line 10 for encase 5 to 7
	// line 11 for encase 5 to 7
	// empty
	// line 12 for encase 5 to 7
	// sub
	// line 13 for encase 5 to 7
	// line 14 for encase 5 to 7
	L14_p  string // p
	L14_n  string // p
	L14_id string // Identifier
	L14_nu string // Unknown (Number)
	L14_co string // Unknown (Comment)
	L14_gu string // Unknown (GUID)

	// line 15 for encase 5 to 7
	// line 16 for encase 5 to 7
	// line 17 for encase 5 to 7
	// empty

	// header
	// line 1
	// 1
	// line 2
	// main
	// line 3
	L3_r string // Compression level
	// line 4
	// line 5
	// empty
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

// 3.7 Data
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

// type TableEntry struct {
// 	Entry []uint32
// }

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

func (e *EWFImage) IsEWFFile() bool {
	file, err := os.Open(e.filepath)
	if err != nil {
		return false
	}

	header := make([]byte, 13)
	if _, err := file.Read(header); err != nil {
		return false
	}
	file.Close()
	return bytes.Equal(header[:8], EVFSignature[:])
}

func (e *EWFImage) Open(file string) (*EWFImage, error) {
	e.filepath = file
	// 判断是否为WEF文件签名
	if !e.IsEWFFile() {
		return nil, errors.New("not ewf file")
	}
	//
	return e, nil
}

// 读取某位置的多少个字节
func (e *EWFImage) ReadAt(addr int64, length int64) []byte {
	file, err := os.Open(e.filepath)
	if err != nil {
		return nil
	}
	buffer := make([]byte, length)
	file.ReadAt(buffer, addr)
	return buffer
}

// func (e *EWFImage) ReadHeader(){

// }

func (e *EWFImage) ReadSection(address int64) (*Section, error) {
	// fmt.Println("[*]debug read section ", address)
	section := &Section{}
	buf := e.ReadAt(address, SectionLength)
	var err error
	if buf != nil {
		err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, section)
	}
	return section, err
}

func (e *EWFImage) ReadSections() error {
	// var sections []SectionWithAddress
	address := EWFFileHeaderLength

	for {
		section, err := e.ReadSection(address)
		if err != nil {
			return err
		}
		e.Sections = append(e.Sections, SectionWithAddress{
			Address: address,
			Section: *section,
		})
		address = int64(section.NextOffset)
		if string(bytes.TrimRight(section.SectionTypeDefinition[:], "\x00")) == "done" {
			break
		}
		if section.NextOffset == 0 {
			break
		}
	}
	return nil
}

func (e *EWFImage) ParseSections() error {
	for _, v := range e.Sections {
		switch string(bytes.TrimRight(v.SectionTypeDefinition[:], "\x00")) {
		case "header2":
			e.ParseHeader(v)
		case "header":
			e.ParseHeader(v)
		case "volume":
			e.ParseVolume(v)
		case "disk":
			fmt.Println("disk")
		case "data":
			fmt.Println("data")
		case "sectors":
			e.AddSectorsAddress(v)
		case "table":
			e.AddTableAddress(v)
		case "table2":
			e.ParseTable2(v)
		case "next":
			fmt.Println("next")
		case "ltype":
			fmt.Println("ltype")
		case "ltree":
			fmt.Println("ltree")
		case "map":
			fmt.Println("map")
		case "error2":
			fmt.Println("error2")
		case "digest":
			fmt.Println("digest")
		case "hash":
			fmt.Println("hash")
		case "done":
			fmt.Println("done")
		}
	}

	for k, v := range e.SectorsAddress {
		r, err := e.ParseSectors(v)
		if err != nil {
			return err
		}
		tableEntry, err := e.ParseTable(e.TableAddress[k])
		if err != nil {
			return err
		}
		e.Sectors = append(e.Sectors, SectorAndTableWithAddress{
			Reader:     r,
			TableEntry: tableEntry,
		})
	}
	return nil
}

// 3.3 3.4
func (e *EWFImage) ParseHeader(s SectionWithAddress) error {
	// 获取到section
	buf := e.ReadAt(s.Address+SectionLength, int64(s.SectionSize)-SectionLength)
	r, err := zlib.NewReader(bytes.NewReader(buf))
	if err != nil {
		return err
	}
	var header bytes.Buffer
	io.Copy(&header, r)
	defer r.Close()
	var linesdata string
	// BOM
	// UTF-16 BE
	if header.Bytes()[0] == 0xfe && header.Bytes()[1] == 0xff {
		utf16be := unicode.UTF16(unicode.BigEndian, unicode.ExpectBOM)
		decoder := utf16be.NewDecoder()
		utf8Data, _, err := transform.Bytes(decoder, header.Bytes())
		if err == nil {
			linesdata = string(utf8Data)
		}
	}
	// UTF-16 LE
	if header.Bytes()[0] == 0xff && header.Bytes()[1] == 0xfe {
		utf16le := unicode.UTF16(unicode.LittleEndian, unicode.ExpectBOM)
		decoder := utf16le.NewDecoder()
		utf8Data, _, err := transform.Bytes(decoder, header.Bytes())
		if err == nil {
			linesdata = string(utf8Data)
		}
	}
	// UTF-32
	if header.Bytes()[0] == 0x00 && header.Bytes()[1] == 0x00 && header.Bytes()[2] == 0xfe && header.Bytes()[3] == 0xff {
	}
	// UTF-32
	if header.Bytes()[0] == 0xff && header.Bytes()[1] == 0xfe && header.Bytes()[2] == 0x00 && header.Bytes()[3] == 0x00 {
	}
	// UTF-8
	if linesdata == "" {
		linesdata = header.String()
	}
	lines := strings.Split(linesdata, "\n")
	var flags []string
	var values []string
	flags = append(flags, strings.Split(lines[2], "\t")...)
	values = append(values, strings.Split(lines[3], "\t")...)

	if len(flags) == len(values) {
		headerSectionString := HeaderSectionString{}
		for k, flag := range flags {
			switch flag {
			case "a":
				headerSectionString.L3_a = values[k]
			case "c":
				headerSectionString.L3_c = values[k]
			case "n":
				headerSectionString.L3_n = values[k]
			case "e":
				headerSectionString.L3_e = values[k]
			case "t":
				headerSectionString.L3_t = values[k]
			case "av":
				headerSectionString.L3_av = values[k]
			case "ov":
				headerSectionString.L3_ov = values[k]
			case "m":
				headerSectionString.L3_m = values[k]
			case "u":
				headerSectionString.L3_u = values[k]
			case "p":
				headerSectionString.L3_p = values[k]
			case "md":
				headerSectionString.L3_md = values[k]
			case "sn":
				headerSectionString.L3_sn = values[k]
			case "l":
				headerSectionString.L3_l = values[k]
			case "pid":
				headerSectionString.L3_pid = values[k]
			case "dc":
				headerSectionString.L3_dc = values[k]
			case "ext":
				headerSectionString.L3_ext = values[k]
			}
		}
		e.Headers = append(e.Headers, headerSectionString)
	}
	return nil
}

// 3.5 Volume
func (e *EWFImage) ParseVolume(s SectionWithAddress) error {
	var buf []byte
	var err error
	// EWFSpecification 94 bytes
	if s.SectionSize > uint64(SectionLength)+uint64(DiskSMARTLength) {
		var ewfSpecification EWFSpecification
		buf = e.ReadAt(s.Address+SectionLength, EWFSpecificationLength)
		if buf != nil {
			err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &ewfSpecification)
		}
		if err != nil {
			return err
		}
		e.Volumes = append(e.Volumes, ewfSpecification)
	}
	// SMART 1052 bytes
	if s.SectionSize == uint64(SectionLength)+uint64(DiskSMARTLength) {
		var diskSMART DiskSMART
		buf = e.ReadAt(s.Address+SectionLength, DiskSMARTLength)
		if buf != nil {
			err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &diskSMART)
		}
		if err != nil {
			return err
		}
		e.DiskSMART = append(e.DiskSMART, diskSMART)
	}
	return err
}

// 3.6 Disk
func (e *EWFImage) ParseDisk(s SectionWithAddress) {

}

// 3.7 Data
func (e *EWFImage) ParseData(s SectionWithAddress) {

}

// 3.8 Sector
func (e *EWFImage) AddSectorsAddress(s SectionWithAddress) error {
	fmt.Println("[*] debug from AddSectorsAddress at", s.Address)
	e.SectorsAddress = append(e.SectorsAddress, s)
	return nil
}

func (e *EWFImage) ParseSectors(s SectionWithAddress) (io.ReadCloser, error) {
	// fmt.Println("[*]debug sectors read at", s.Address)
	// buf := e.ReadAt(s.Address+SectionLength, int64(s.SectionSize)-SectionLength)
	// r, err := zlib.NewReader(bytes.NewReader(buf))
	// // 未压缩
	// if err != nil {
	// 	r = io.NopCloser(bytes.NewReader(buf))
	// 	return r, nil
	// }
	// // var out bytes.Buffer
	// // io.CopyN(&out, r, 64)
	// // defer r.Close()
	// // fmt.Println(out.Bytes())
	return nil, nil
}

// 3.9 Table
func (e *EWFImage) AddTableAddress(s SectionWithAddress) error {
	fmt.Println("[*] debug from AddTableAddress at", s.Address)
	e.TableAddress = append(e.TableAddress, s)
	return nil
}

func (e *EWFImage) ParseTable(s SectionWithAddress) ([]uint32, error) {
	fmt.Println("[*]debug read table at", s.Address)
	tableHeaderBuf := e.ReadAt(s.Address+SectionLength, TableSectionLength)
	var tableHeader TableSection
	err := binary.Read(bytes.NewReader(tableHeaderBuf), binary.LittleEndian, &tableHeader)
	if err != nil {
		return nil, err
	}
	fmt.Printf("表项数: %d\n", tableHeader.EntryNumber)

	buf := e.ReadAt(s.Address+SectionLength+TableSectionLength, int64(s.SectionSize)-SectionLength-TableSectionLength)
	len := ((int64(s.SectionSize) - SectionLength - TableSectionLength) / 4) - 1
	tableEntry := make([]uint32, len)
	err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &tableEntry)
	if err != nil {
		return nil, err
	}
	for k, entry := range tableEntry {
		tableEntry[k] = entry & 0x7FFFFFFF
	}
	return tableEntry, nil
}

// 3.10 Table2
func (e *EWFImage) ParseTable2(s SectionWithAddress) error {
	// fmt.Println("[*]debug read table2 at", s.Address)
	// buf := e.ReadAt(s.Address+SectionLength, int64(s.SectionSize)-SectionLength)
	// fmt.Println(buf[:64])
	// fmt.Println(s.SectionSize)
	return nil
}

// 3.11 Next
func (e *EWFImage) ParsesNext(s SectionWithAddress) {

}

// 3.12 Ltype
func (e *EWFImage) ParsesLtype(s SectionWithAddress) {

}

// 3.13 Ltree
func (e *EWFImage) ParsesLtree(s SectionWithAddress) {

}

// 3.14 Map
func (e *EWFImage) ParsesMap(s SectionWithAddress) {

}

// 3.15 Session
func (e *EWFImage) ParsesSession(s SectionWithAddress) {

}

// 3.16 Error2
func (e *EWFImage) ParsesError2(s SectionWithAddress) {

}

// 3.17 Digest
func (e *EWFImage) ParsesDigest(s SectionWithAddress) {

}

// 3.18 Hash
func (e *EWFImage) ParsesHash(s SectionWithAddress) {

}

// 3.19 Done
func (e *EWFImage) ParsesDone(s SectionWithAddress) {

}
