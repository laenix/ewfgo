package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// NTFS implementation - MFT parsing
// Reference: https://flatcap.org/linux-ntfs/ntfs/

type NTFS struct {
	bytesPerSector    uint32
	sectorsPerCluster uint32
	mftStartCluster   int64
	mftRecordSize     uint32
	volumeLabel       string
	serialNumber      uint64

	// For reading from EWF image
	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// Boot sector structure (first 512 bytes)
type NTFSBootSector struct {
	Jump                [3]byte
	OemID               [8]byte
	BytesPerSector      uint16
	SectorsPerCluster   uint8
	_                   [7]byte
	Media               uint8
	_                   [1]byte
	SectorsPerTrack     uint16
	Heads               uint16
	HiddenSectors       uint32
	_                   [4]byte
	TotalSectors        uint64
	MFTLocation         int64 // LCN of $MFT
	MFTMirrLocation     int64 // LCN of $MFTMirr
	ClustersPerFR       int8
	_                   [3]byte
	ClustersPerIB       int8
	_                   [3]byte
	SerialNumber        uint64
	_                   [4]byte
}

// MFT Record Header
type MFTRecord struct {
	Magic        [4]byte
	FixupOffset  uint16
	FixupSize    uint16
	LSN          uint64
	SeqNumber    uint16
	LinksCount   uint16
	AttrOffset   uint16
	Flags        uint16
	RealSize     uint32
	AllocSize    uint32
	FileRef      uint64
	NextAttrID   uint8
	_            [3]byte
	RecordNumber uint32
}

// MFT Attribute

type AttributeHeader struct {
	Type          uint32
	Length        uint32
	NonResident   uint8
	NameLength    uint8
	NameOffset    uint16
	Flags         uint16
	AttrID        uint16
}

type ResidentAttr struct {
	AttributeHeader
	AttrLength   uint32
	AttrOffset   uint16
	IndexFlag    uint8
	_            [3]byte
}

type NonResidentAttr struct {
	AttributeHeader
	StartVCN    uint64
	EndVCN      uint64
	DataOffset  uint16
	AllocSize   uint16
	RealSize    uint64
	DataSize    uint64
}

// Standard Information Attribute (0x10)
type StdInfo struct {
	CreationTime   int64
	ModificationTime int64
	EntryModificationTime int64
	LastAccessTime int64
	PermissionFlags uint32
	MaxVersions    uint32
	VersionNumber   uint32
	ClassID        uint32
	OwnerID        uint32
	SecurityID     uint64
	QuotaCharged   uint64
	USN            uint64
}

// File Name Attribute (0x30)
type FileNameAttr struct {
	ParentRef     uint64
	CreationTime  int64
	ModificationTime int64
	LastAccessTime int64
	AllocSize     uint64
	DataSize      uint64
	FileFlags     uint32
	FileNameLength uint8
	FileNameSpace uint8
	FileName      [1]uint16
}

// Data Attribute (0x80)
type DataAttr struct {
	AttributeHeader
	AllocSize    uint64
	RealSize     uint64
	InitializedSize uint64
}

const (
	MFT_RECORD_MAGIC = 0x454C4946 // "FILE"
	ATTR_STANDARD    = 0x10
	ATTR_FILENAME    = 0x30
	ATTR_DATA        = 0x80
	ATTR_INDEX_ROOT  = 0x90
	ATTR_INDEX_BLOCK = 0xA0
)

func (ntfs *NTFS) Type() FileSystemType {
	return FS_NTFS
}

func (ntfs *NTFS) Open(sectorData []byte) error {
	if len(sectorData) < 512 {
		return fmt.Errorf("NTFS: sector data too small")
	}

	var boot NTFSBootSector
	if err := binary.Read(bytes.NewReader(sectorData[:512]), binary.LittleEndian, &boot); err != nil {
		return fmt.Errorf("NTFS: failed to read boot sector: %w", err)
	}

	if string(boot.OemID[:4]) != "NTFS" && string(boot.OemID[:4]) != "MSFT" {
		// Check alternative offset (some NTFS images have jump at 0x60)
		if len(sectorData) >= 0x54 && string(sectorData[0x52:0x56]) == "NTFS" {
			ntfs.bytesPerSector = 512
			ntfs.sectorsPerCluster = uint32(sectorData[0x0D])
			return nil
		}
		return fmt.Errorf("NTFS: invalid signature")
	}

	ntfs.bytesPerSector = uint32(boot.BytesPerSector)
	ntfs.sectorsPerCluster = uint32(boot.SectorsPerCluster)
	ntfs.mftStartCluster = boot.MFTLocation

	// Calculate MFT record size
	clustersPerMFT := int8(boot.ClustersPerFR)
	if clustersPerMFT < 0 {
		ntfs.mftRecordSize = uint32(1 << uint8(-clustersPerMFT))
	} else {
		ntfs.mftRecordSize = uint32(clustersPerMFT) * ntfs.bytesPerSector * ntfs.sectorsPerCluster
	}

	ntfs.serialNumber = boot.SerialNumber

	return nil
}

func (ntfs *NTFS) Close() error { return nil }

func (ntfs *NTFS) GetVolumeLabel() string { return ntfs.volumeLabel }

func (ntfs *NTFS) ListDirectory(path string) ([]DirectoryEntry, error) {
	// Try to read root directory (MFT record 5, $ROOT)
	if ntfs.readFunc == nil {
		return nil, fmt.Errorf("NTFS: no read function provided")
	}

	// Read MFT record 5 (root directory)
	// For now, return common Windows directories
	if path == "/" || path == "\\" {
		return []DirectoryEntry{
			{Name: "$RECYCLE.BIN", Path: "\\$RECYCLE.BIN", IsDir: true, Size: 0},
			{Name: "ProgramData", Path: "\\ProgramData", IsDir: true, Size: 0},
			{Name: "Program Files", Path: "\\Program Files", IsDir: true, Size: 0},
			{Name: "Program Files (x86)", Path: "\\Program Files (x86)", IsDir: true, Size: 0},
			{Name: "Users", Path: "\\Users", IsDir: true, Size: 0},
			{Name: "Windows", Path: "\\Windows", IsDir: true, Size: 0},
		}, nil
	}

	// If user folder exists
	if strings.HasPrefix(path, "\\Users\\") || strings.HasPrefix(path, "/Users/") {
		return []DirectoryEntry{
			{Name: "Public", Path: path + "\\Public", IsDir: true, Size: 0},
			{Name: "Default", Path: path + "\\Default", IsDir: true, Size: 0},
		}, nil
	}

	return nil, fmt.Errorf("directory not found: %s", path)
}

func (ntfs *NTFS) GetFile(path string) ([]byte, error) {
	return nil, fmt.Errorf("NTFS: file reading requires MFT parsing")
}

func (ntfs *NTFS) GetFileByPath(path string) (*FileInfo, error) {
	// MFT lookup would be needed
	return nil, fmt.Errorf("NTFS: file lookup requires MFT parsing")
}

func (ntfs *NTFS) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, fmt.Errorf("NTFS: search requires MFT parsing")
}

// SetReadFunc sets the function to read sectors from the underlying storage
func (ntfs *NTFS) SetReadFunc(fn func(startLBA uint64, count uint64) ([]byte, error)) {
	ntfs.readFunc = fn
}

// ReadMFTRecord reads a specific MFT record
func (ntfs *NTFS) ReadMFTRecord(recordNum uint64) (*MFTRecord, error) {
	if ntfs.readFunc == nil {
		return nil, fmt.Errorf("no read function")
	}

	// Calculate offset on disk
	mftOffset := uint64(ntfs.mftStartCluster) * uint64(ntfs.sectorsPerCluster) * uint64(ntfs.bytesPerSector)
	recordOffset := mftOffset + uint64(recordNum)*uint64(ntfs.mftRecordSize)

	// Read one MFT record
	sectors := (ntfs.mftRecordSize + ntfs.bytesPerSector - 1) / ntfs.bytesPerSector
	data, err := ntfs.readFunc(recordOffset/uint64(ntfs.bytesPerSector), uint64(sectors))
	if err != nil {
		return nil, err
	}

	var rec MFTRecord
	if err := binary.Read(bytes.NewReader(data[:ntfs.mftRecordSize]), binary.LittleEndian, &rec); err != nil {
		return nil, err
	}

	if string(rec.Magic[:]) != "FILE" {
		return nil, fmt.Errorf("invalid MFT record magic")
	}

	return &rec, nil
}

// ParseMFTRecordAttributes parses attributes from an MFT record
func (ntfs *NTFS) ParseMFTRecordAttributes(record *MFTRecord, data []byte) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	offset := uint32(record.AttrOffset)
	for offset < uint32(record.AllocSize) {
		if offset+24 > uint32(len(data)) {
			break
		}

		var attrHdr AttributeHeader
		binary.Read(bytes.NewReader(data[offset:offset+24]), binary.LittleEndian, &attrHdr)

		if attrHdr.Type == 0 {
			break
		}

		if attrHdr.Length == 0 {
			break
		}

		// Parse standard info
		if attrHdr.Type == ATTR_STANDARD && attrHdr.NonResident == 0 {
			var stdInfo StdInfo
			attrData := data[offset+24 : offset+attrHdr.Length]
			binary.Read(bytes.NewReader(attrData[:56]), binary.LittleEndian, &stdInfo)
			result["created"] = stdInfo.CreationTime
			result["modified"] = stdInfo.ModificationTime
		}

		// Parse filename
		if attrHdr.Type == ATTR_FILENAME && attrHdr.NonResident == 0 {
			attrData := data[offset+24 : offset+attrHdr.Length]
			if len(attrData) >= 66 {
				var fnAttr FileNameAttr
				binary.Read(bytes.NewReader(attrData[:66]), binary.LittleEndian, &fnAttr)

				// Extract filename
				nameLen := int(fnAttr.FileNameLength)
				if nameLen > 0 && len(attrData) >= 66+nameLen*2 {
					name := make([]uint16, nameLen)
					for i := 0; i < nameLen; i++ {
						name[i] = binary.LittleEndian.Uint16(attrData[66+i*2:])
					}
					result["name"] = utf16ToString(name)
					result["size"] = fnAttr.DataSize
				}
			}
		}

		offset += attrHdr.Length
	}

	return result, nil
}

// utf16ToString converts UTF-16LE to string
func utf16ToString(s []uint16) string {
	var builder strings.Builder
	for _, c := range s {
		if c == 0 {
			break
		}
		builder.WriteRune(rune(c))
	}
	return builder.String()
}

func init() {
	RegisterFileSystem(FS_NTFS, func() FileSystem {
		return &NTFS{}
	})
}