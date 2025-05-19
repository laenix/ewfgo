package internal

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
	Address    int64    // sector address
	TableEntry []uint32 // offsets
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
