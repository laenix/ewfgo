package hfs

// Catalog record types.
const (
	recordTypeFolder       uint16 = 0x0100
	recordTypeFile         uint16 = 0x0200
	recordTypeFolderThread uint16 = 0x0300
	recordTypeFileThread   uint16 = 0x0400
)

// FileRecordBytes is the documented length of a file record.
const FileRecordBytes = 102

// FileRecordMinBytes is the bytes this reader needs from a file record.
const FileRecordMinBytes = 98

// MaxNameBytes is the longest catalog name in a Str31.
const MaxNameBytes = 31

// catalogKey is a catalog key: the parent CNID and the stored name.
type catalogKey struct {
	parentID uint32
	name     string
}

// fileRecord is a file's catalog record with both forks.
type fileRecord struct {
	fileID               uint32
	dataStartBlock       uint16
	dataSize             uint32
	dataPhysicalSize     uint32
	resourceStartBlock   uint16
	resourceSize         uint32
	resourcePhysicalSize uint32
	created              uint32
	modified             uint32
	backup               uint32
	finderType           uint32
	finderCreator        uint32
	dataExtents          ExtentRecord
	resourceExtents      ExtentRecord
}

// catalogRecordKind names the decoded catalog record variants.
type catalogRecordKind uint8

const (
	recordFolder catalogRecordKind = iota
	recordFile
	recordThread
	recordOther
)

// catalogRecord is one decoded catalog record. Thread records are parsed and
// counted; the reader takes names from the ordinary records' keys.
type catalogRecord struct {
	kind         catalogRecordKind
	valence      uint16
	directoryID  uint32
	file         *fileRecord
	threadParent uint32
	threadName   string
	otherType    uint16
}

// parseCatalogKey decodes the key bytes a B-tree record carries.
func parseCatalogKey(key []byte) (catalogKey, error) {
	if len(key) < 6 {
		return catalogKey{}, corruptf("a catalog key is shorter than six bytes")
	}
	nameLength := int(key[5])
	if nameLength > MaxNameBytes {
		return catalogKey{}, corruptf("a catalog name declares %d bytes, more than a Str31 holds", nameLength)
	}
	end := 6 + nameLength
	if end > len(key) {
		return catalogKey{}, corruptf("a catalog key is shorter than its name length")
	}
	return catalogKey{
		parentID: be32(key, 1),
		name:     decodeMacRoman(key[6:end]),
	}, nil
}

// parseCatalogRecord decodes a record's data using the key that names it.
func parseCatalogRecord(key catalogKey, data []byte) (catalogRecord, error) {
	if len(data) < 2 {
		return catalogRecord{}, corruptf("the record for %q is shorter than its type word", key.name)
	}
	switch recordType := be16(data, 0); recordType {
	case recordTypeFolder:
		if len(data) < 10 {
			return catalogRecord{}, corruptf("the folder record for %q is %d bytes, not 10", key.name, len(data))
		}
		return catalogRecord{
			kind:        recordFolder,
			valence:     be16(data, 4),
			directoryID: be32(data, 6),
		}, nil
	case recordTypeFile:
		if len(data) < FileRecordMinBytes {
			return catalogRecord{}, corruptf("the file record for %q is %d bytes, fewer than %d",
				key.name, len(data), FileRecordMinBytes)
		}
		dataExtents, err := readExtentRecord(data, 74)
		if err != nil {
			return catalogRecord{}, err
		}
		resourceExtents, err := readExtentRecord(data, 86)
		if err != nil {
			return catalogRecord{}, err
		}
		file := &fileRecord{
			fileID:               be32(data, 20),
			dataStartBlock:       be16(data, 24),
			dataSize:             be32(data, 26),
			dataPhysicalSize:     be32(data, 30),
			resourceStartBlock:   be16(data, 34),
			resourceSize:         be32(data, 36),
			resourcePhysicalSize: be32(data, 40),
			created:              be32(data, 44),
			modified:             be32(data, 48),
			backup:               be32(data, 52),
			finderType:           be32(data, 4),
			finderCreator:        be32(data, 8),
			dataExtents:          dataExtents,
			resourceExtents:      resourceExtents,
		}
		return catalogRecord{kind: recordFile, file: file}, nil
	case recordTypeFolderThread, recordTypeFileThread:
		if len(data) < 15 {
			return catalogRecord{}, corruptf("the thread record for %q is %d bytes, not 15", key.name, len(data))
		}
		nameLength := int(data[14])
		if nameLength > MaxNameBytes {
			nameLength = MaxNameBytes
		}
		name := ""
		if 15+nameLength <= len(data) {
			name = decodeMacRoman(data[15 : 15+nameLength])
		}
		return catalogRecord{
			kind:         recordThread,
			threadParent: be32(data, 10),
			threadName:   name,
		}, nil
	default:
		return catalogRecord{kind: recordOther, otherType: recordType}, nil
	}
}
