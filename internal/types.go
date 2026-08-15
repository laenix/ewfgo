package internal

import "os"

// EWFImage is the parsed state of an EWF/E01 evidence image. Open populates the
// segment handles; ReadSections + ParseSections populate the section lists; the
// read path (read.go) serves decompressed sector data from Sectors + DiskSMART.
type EWFImage struct {
	filepath       string                 // 文件路径 (segment 1)
	segments       []*SegmentFile         // segment 1 is always present; siblings follow
	Sections       []SectionWithAddress
	Headers        []HeaderSectionString
	DiskSMART      []DiskSMART
	SectorsAddress []SectionWithAddress
	TableAddress   []SectionWithAddress
	Sectors        []SectorAndTableWithAddress
	// StoredMD5/StoredSHA1 carry the acquisition hashes from the image's
	// "hash"/"digest" sections (16/20 bytes), nil when the image has none.
	StoredMD5  []byte
	StoredSHA1 []byte
	chunkCache *chunkCache // decompressed-chunk LRU (nil disables)
}

// SegmentFile is one segment file of a multi-segment EWF image (E01/E02/...).
// Segment 1 is always present; segments 2..n are the sibling files discovered
// by Open. A chunk table entry or base offset is relative to the segment file
// that holds the table section; adding `start` yields the logical image offset
// used by ReadAt.
type SegmentFile struct {
	filepath string
	file     *os.File
	size     int64 // file size in bytes
	start    int64 // cumulative offset of this segment within the logical image
}

type SectionWithAddress struct {
	Section
	Address int64
	Segment int // index into EWFImage.segments; 0 for single-file images
}

type SectorAndTableWithAddress struct {
	Address    int64    // sector address
	TableEntry []uint32 // offsets
	BaseOffset uint64   // EnCase 6+ table base offset; 0 for EnCase 1-5
	Segment    int      // segment index holding this sector/table pair
}

// Section is a 76-byte EWF section descriptor.
type Section struct {
	SectionTypeDefinition [16]byte // A string containing the section type definition. E.g. "header", "volume", etc.
	NextOffset            uint64   // Next section offset The offset is relative from the start of the segment file
	SectionSize           uint64   // Section size
	Padding               [40]byte // 填充
	CheckSum              uint32   // 校验和
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
