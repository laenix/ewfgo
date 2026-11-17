package hfsplus

// HFS+ catalog keys and records.
//
// The catalog B-tree is keyed by (parent CNID, node name) and holds four
// record types: file, folder, file thread, and folder thread.  A thread record
// is keyed by the item's own CNID with an empty name and answers "where does
// this object live?", which is how a CNID is turned back into a path.
//
// Name comparison: HFSX compares UTF-16 units byte-wise; HFS+ folds case.
// Apple's full Unicode 2.1 table is not reproduced here, so only ASCII case is
// folded, exactly as the Rust reference does.  ASCII names and all CNID-based
// lookups are unaffected.

import (
	"fmt"
)

// RecordType is the leading u16 of a catalog record.
type RecordType uint16

const (
	// RecordFolder is kHFSPlusFolderRecord.
	RecordFolder RecordType = 1
	// RecordFile is kHFSPlusFileRecord.
	RecordFile RecordType = 2
	// RecordFolderThread is kHFSPlusFolderThreadRecord.
	RecordFolderThread RecordType = 3
	// RecordFileThread is kHFSPlusFileThreadRecord.
	RecordFileThread RecordType = 4
)

// Well-known catalog node IDs.
const (
	// RootFolder is the root folder's CNID.
	RootFolder uint32 = 2
	// ExtentsFileID is the extents-overflow file's CNID.
	ExtentsFileID uint32 = 3
	// CatalogFileID is the catalog file's CNID.
	CatalogFileID uint32 = 4
	// AllocationFileID is the allocation file's CNID.
	AllocationFileID uint32 = 6
	// AttributesFileID is the attributes file's CNID.
	AttributesFileID uint32 = 8
	// MetadataFolderID is the private folder holding hard-link inode files.
	MetadataFolderID uint32 = 24

	// PrivateDataName is the private folder's catalog name.  The four leading
	// NUL units keep it out of ordinary listing order.
	PrivateDataName = "\x00\x00\x00\x00HFS+ Private Data"
	// InodeFilePrefix precedes the decimal CNID of a hard-link inode file.
	InodeFilePrefix = "iNode"
	// MaxNameUnits is the longest name HFS+ stores, in UTF-16 units.
	MaxNameUnits = 255
)

// Catalog record flags.
const (
	FileFlagThreadExists   uint16 = 0x0002
	FileFlagHasAttributes  uint16 = 0x0004
	FileFlagHasSecurity    uint16 = 0x0008
	FileFlagHasFolderCount uint16 = 0x0010
	FileFlagHasLinkChain   uint16 = 0x0020
	FileFlagHasChildLink   uint16 = 0x0040
)

// Name is a sequence of UTF-16 units.  A hostile or damaged catalog may hold
// unpaired surrogates, so the units are kept verbatim.
type Name struct {
	Units []uint16
}

// NewName converts a Go string to HFS+ name units.
func NewName(value string) Name { return Name{Units: toUTF16(value)} }

func toUTF16(value string) []uint16 {
	out := make([]uint16, 0, len(value))
	for _, r := range value {
		if r <= 0xFFFF {
			out = append(out, uint16(r))
			continue
		}
		r -= 0x10000
		out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
	}
	return out
}

// String renders the name, replacing unpaired surrogates with U+FFFD.
func (n Name) String() string { return decodeUnits(n.Units) }

// Len returns the number of UTF-16 units.
func (n Name) Len() int { return len(n.Units) }

// IsEmpty reports whether the name has no units.
func (n Name) IsEmpty() bool { return len(n.Units) == 0 }

// CatalogKey is a parent CNID and a node name.
type CatalogKey struct {
	Parent uint32
	Name   Name
}

// ParseCatalogKey parses the key payload after the node's key-length field.
func ParseCatalogKey(payload []byte) (CatalogKey, error) {
	if len(payload) < 6 {
		return CatalogKey{}, invalidf("catalog key is %d bytes, too short for a parent and name", len(payload))
	}
	parent := be32(payload, 0)
	length := int(be16(payload, 4))
	if 6+length*2 > len(payload) {
		return CatalogKey{}, invalidf("catalog key declares %d name units, past its %d bytes", length, len(payload))
	}
	units := make([]uint16, length)
	for i := 0; i < length; i++ {
		units[i] = be16(payload, 6+2*i)
	}
	return CatalogKey{Parent: parent, Name: Name{Units: units}}, nil
}

// Encode encodes the key payload for a B-tree comparison.
func (k CatalogKey) Encode() ([]byte, error) {
	if k.Name.Len() > MaxNameUnits {
		return nil, invalidf("name is %d UTF-16 units, above the %d unit limit", k.Name.Len(), MaxNameUnits)
	}
	out := make([]byte, 0, 6+2*k.Name.Len())
	out = append(out, uint8(k.Parent>>24), uint8(k.Parent>>16), uint8(k.Parent>>8), uint8(k.Parent))
	out = append(out, uint8(k.Name.Len()>>8), uint8(k.Name.Len()))
	for _, unit := range k.Name.Units {
		out = append(out, uint8(unit>>8), uint8(unit))
	}
	return out, nil
}

// CompareCatalogPayloads orders two catalog key payloads, folding ASCII case
// on HFS+.
func CompareCatalogPayloads(a, b []byte, caseSensitive bool) int {
	aKey, aErr := ParseCatalogKey(a)
	bKey, bErr := ParseCatalogKey(b)
	if aErr != nil || bErr != nil {
		return bytesCompare(a, b)
	}
	if aKey.Parent != bKey.Parent {
		if aKey.Parent < bKey.Parent {
			return -1
		}
		return 1
	}
	return CompareNameUnits(aKey.Name.Units, bKey.Name.Units, caseSensitive)
}

// CompareNameUnits orders two decoded names, folding ASCII case on HFS+.
func CompareNameUnits(a, b []uint16, caseSensitive bool) int {
	shared := len(a)
	if len(b) < shared {
		shared = len(b)
	}
	for i := 0; i < shared; i++ {
		left, right := a[i], b[i]
		if !caseSensitive {
			left, right = foldUnit(left), foldUnit(right)
		}
		if left != right {
			if left < right {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func foldUnit(unit uint16) uint16 {
	if unit >= 'A' && unit <= 'Z' {
		return unit + 32
	}
	return unit
}

func bytesCompare(a, b []byte) int {
	shared := len(a)
	if len(b) < shared {
		shared = len(b)
	}
	for i := 0; i < shared; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// Permissions is the BSD ownership and mode block shared by file and folder
// records.
type Permissions struct {
	OwnerID    uint32
	GroupID    uint32
	AdminFlags uint8
	OwnerFlags uint8
	FileMode   uint16
	Special    uint32
}

func parsePermissions(bytes []byte, offset int) Permissions {
	return Permissions{
		OwnerID:    be32(bytes, offset),
		GroupID:    be32(bytes, offset+4),
		AdminFlags: bytes[offset+8],
		OwnerFlags: bytes[offset+9],
		FileMode:   be16(bytes, offset+10),
		Special:    be32(bytes, offset+12),
	}
}

// CatalogFolder is an HFSPlusCatalogFolder record.
type CatalogFolder struct {
	ID                uint32
	Flags             uint16
	Valence           uint32
	Created           Time
	ContentModified   Time
	AttributeModified Time
	Accessed          Time
	BackedUp          Time
	Permissions       Permissions
	FolderCount       uint32
}

// CatalogFile is an HFSPlusCatalogFile record.
type CatalogFile struct {
	ID                uint32
	Flags             uint16
	Created           Time
	ContentModified   Time
	AttributeModified Time
	Accessed          Time
	BackedUp          Time
	Permissions       Permissions
	DataFork          Fork
	ResourceFork      Fork
}

// IsHardLink reports whether the record points at an inode in the private
// data folder.
func (f *CatalogFile) IsHardLink() bool { return f.Flags&FileFlagHasLinkChain != 0 }

// CatalogThread is the back-pointer from a CNID to its directory entry.
type CatalogThread struct {
	Parent uint32
	Name   Name
}

// CatalogRecord is a parsed catalog record.
type CatalogRecord struct {
	Type   RecordType
	Folder *CatalogFolder
	File   *CatalogFile
	Thread *CatalogThread
}

// IsDirectory reports whether the record is a folder.
func (r *CatalogRecord) IsDirectory() bool { return r.Type == RecordFolder }

// IsThread reports whether the record is a thread record.
func (r *CatalogRecord) IsThread() bool {
	return r.Type == RecordFolderThread || r.Type == RecordFileThread
}

// ID returns the record's own CNID.  Thread records carry none.
func (r *CatalogRecord) ID() (uint32, bool) {
	switch r.Type {
	case RecordFolder:
		return r.Folder.ID, true
	case RecordFile:
		return r.File.ID, true
	default:
		return 0, false
	}
}

// Fork returns one of a file's forks, or nil for a folder/thread.
func (r *CatalogRecord) Fork(kind ForkKind) *Fork {
	if r.Type != RecordFile {
		return nil
	}
	if kind == ForkResource {
		return &r.File.ResourceFork
	}
	return &r.File.DataFork
}

// Created returns the record's creation time.
func (r *CatalogRecord) Created() (Time, bool) {
	switch r.Type {
	case RecordFolder:
		return r.Folder.Created, true
	case RecordFile:
		return r.File.Created, true
	default:
		return 0, false
	}
}

// ParseCatalogRecord parses a catalog record body.
func ParseCatalogRecord(bytes []byte) (*CatalogRecord, error) {
	if len(bytes) < 2 {
		return nil, invalidf("catalog record is shorter than its type field")
	}
	switch RecordType(be16(bytes, 0)) {
	case RecordFolder:
		folder, err := parseFolder(bytes)
		if err != nil {
			return nil, err
		}
		return &CatalogRecord{Type: RecordFolder, Folder: folder}, nil
	case RecordFile:
		file, err := parseFile(bytes)
		if err != nil {
			return nil, err
		}
		return &CatalogRecord{Type: RecordFile, File: file}, nil
	case RecordFolderThread, RecordFileThread:
		thread, err := parseThread(bytes)
		if err != nil {
			return nil, err
		}
		return &CatalogRecord{Type: RecordType(be16(bytes, 0)), Thread: thread}, nil
	default:
		return nil, invalidf("unknown catalog record type 0x%04X", be16(bytes, 0))
	}
}

func parseFolder(bytes []byte) (*CatalogFolder, error) {
	if len(bytes) < 88 {
		return nil, invalidf("folder record is %d bytes, expected at least 88", len(bytes))
	}
	return &CatalogFolder{
		Flags:             be16(bytes, 2),
		Valence:           be32(bytes, 4),
		ID:                be32(bytes, 8),
		Created:           Time(be32(bytes, 12)),
		ContentModified:   Time(be32(bytes, 16)),
		AttributeModified: Time(be32(bytes, 20)),
		Accessed:          Time(be32(bytes, 24)),
		BackedUp:          Time(be32(bytes, 28)),
		Permissions:       parsePermissions(bytes, 32),
		FolderCount:       be32(bytes, 84),
	}, nil
}

func parseFile(bytes []byte) (*CatalogFile, error) {
	if len(bytes) < 248 {
		return nil, invalidf("file record is %d bytes, expected at least 248", len(bytes))
	}
	data, err := parseFork(bytes[88:168])
	if err != nil {
		return nil, err
	}
	resource, err := parseFork(bytes[168:248])
	if err != nil {
		return nil, err
	}
	return &CatalogFile{
		Flags:             be16(bytes, 2),
		ID:                be32(bytes, 8),
		Created:           Time(be32(bytes, 12)),
		ContentModified:   Time(be32(bytes, 16)),
		AttributeModified: Time(be32(bytes, 20)),
		Accessed:          Time(be32(bytes, 24)),
		BackedUp:          Time(be32(bytes, 28)),
		Permissions:       parsePermissions(bytes, 32),
		DataFork:          data,
		ResourceFork:      resource,
	}, nil
}

func parseThread(bytes []byte) (*CatalogThread, error) {
	if len(bytes) < 10 {
		return nil, invalidf("thread record is %d bytes, expected at least 10", len(bytes))
	}
	parent := be32(bytes, 4)
	length := int(be16(bytes, 8))
	start := 10
	end := start + length*2
	if end > len(bytes) {
		return nil, invalidf("thread name length %d exceeds the %d byte record", length, len(bytes))
	}
	units := make([]uint16, length)
	for i := 0; i < length; i++ {
		units[i] = be16(bytes, start+2*i)
	}
	return &CatalogThread{Parent: parent, Name: Name{Units: units}}, nil
}

// String renders the CNID for diagnostics.
func cnidString(id uint32) string { return fmt.Sprintf("%d", id) }
