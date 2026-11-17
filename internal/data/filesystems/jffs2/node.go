package jffs2

import (
	"hash/crc32"
	"strings"
)

// JFFS2 node constants. Every node starts with a 12-byte header carrying its
// own type, total length and CRC-32; the type-specific body follows.
const (
	magic            uint16 = 0x1985
	headerBytes             = 12
	direntFixedBytes        = 40
	inodeFixedBytes         = 68
	maxNodeBytes     uint32 = 16 * 1024 * 1024
	maxNameBytes            = 255
)

// Node types this reader distinguishes.
const (
	nodeTypeDirent      uint16 = 0xe001
	nodeTypeInode       uint16 = 0xe002
	nodeTypeCleanmarker uint16 = 0x2003
	nodeTypePadding     uint16 = 0x2004
	nodeTypeSummary     uint16 = 0x2006
	nodeTypeXattr       uint16 = 0xe008
	nodeTypeXref        uint16 = 0xe009
)

// Exported aliases for callers that need the on-disk constants.
const (
	Magic            = magic
	HeaderBytes      = headerBytes
	DirentFixedBytes = direntFixedBytes
	InodeFixedBytes  = inodeFixedBytes
	MaxNodeBytes     = maxNodeBytes
	MaxNameBytes     = maxNameBytes

	NodeTypeDirent      = nodeTypeDirent
	NodeTypeInode       = nodeTypeInode
	NodeTypeCleanmarker = nodeTypeCleanmarker
	NodeTypePadding     = nodeTypePadding
	NodeTypeSummary     = nodeTypeSummary
	NodeTypeXattr       = nodeTypeXattr
	NodeTypeXref        = nodeTypeXref
)

func crc32IEEE(data []byte) uint32 { return crc32.ChecksumIEEE(data) }

func pad4(length int) int { return (length + 3) &^ 3 }

func readLE16(raw []byte, at int) uint16 {
	return uint16(raw[at]) | uint16(raw[at+1])<<8
}

func readLE32(raw []byte, at int) uint32 {
	return uint32(raw[at]) |
		uint32(raw[at+1])<<8 |
		uint32(raw[at+2])<<16 |
		uint32(raw[at+3])<<24
}

// NodeHeader is the 12-byte header every node begins with.
type NodeHeader struct {
	NodeType uint16
	// TotalLen is the node's whole length, including the header and padding.
	TotalLen uint32
}

// ParseNodeHeader parses a node header. A nil header with a nil error means
// the magic differs, so the bytes are not a node at all. An error means the
// magic matched but the header's own checks disagree.
func ParseNodeHeader(raw []byte) (*NodeHeader, error) {
	header, ok, err := parseNodeHeader(raw)
	if !ok {
		return nil, err
	}
	return &header, err
}

func parseNodeHeader(raw []byte) (NodeHeader, bool, error) {
	if len(raw) < headerBytes {
		return NodeHeader{}, false, corruptf("a node header needs %d bytes, got %d", headerBytes, len(raw))
	}
	if readLE16(raw, 0) != magic {
		return NodeHeader{}, false, nil
	}
	nodeType := readLE16(raw, 2)
	totalLen := readLE32(raw, 4)
	storedCRC := readLE32(raw, 8)
	if crc32IEEE(raw[:8]) != storedCRC {
		return NodeHeader{}, true, corruptf("the header at the node's start fails its CRC (%08x)", storedCRC)
	}
	if totalLen < headerBytes {
		return NodeHeader{}, true, corruptf("a node declares %d bytes, shorter than its own %d-byte header",
			totalLen, headerBytes)
	}
	if totalLen%4 != 0 {
		return NodeHeader{}, true, corruptf("a node declares %d bytes, not on the four-byte boundary the format keeps", totalLen)
	}
	if totalLen > maxNodeBytes {
		return NodeHeader{}, true, corruptf("a node declares %d bytes, more than the %d-byte bound this reader accepts",
			totalLen, maxNodeBytes)
	}
	return NodeHeader{NodeType: nodeType, TotalLen: totalLen}, true, nil
}

// Compression is the compressor an inode node names.
type Compression uint8

// Compressor identifiers from JFFS2's inode node.
const (
	CompressionNone      Compression = 0
	CompressionZero      Compression = 1
	CompressionRtime     Compression = 2
	CompressionRubinMips Compression = 3
	CompressionCopy      Compression = 4
	CompressionDynRubin  Compression = 5
	CompressionZlib      Compression = 6
	CompressionLzo       Compression = 7
)

// CompressionFromByte maps the on-disk byte to a compressor. Values above 7
// are kept so a report can name an unknown compressor byte.
func CompressionFromByte(value byte) Compression { return Compression(value) }

// Label returns the compressor's name.
func (c Compression) Label() string {
	switch c {
	case CompressionNone:
		return "none"
	case CompressionZero:
		return "zero"
	case CompressionRtime:
		return "rtime"
	case CompressionRubinMips:
		return "rubinmips"
	case CompressionCopy:
		return "copy"
	case CompressionDynRubin:
		return "dynrubin"
	case CompressionZlib:
		return "zlib"
	case CompressionLzo:
		return "lzo"
	default:
		return "unknown"
	}
}

// IsStored reports that the stored bytes are the logical bytes.
func (c Compression) IsStored() bool {
	return c == CompressionNone || c == CompressionCopy
}

// IsZero reports that the node's data is all zeroes.
func (c Compression) IsZero() bool { return c == CompressionZero }

// IsCompressed reports that the stored bytes must be decoded.
func (c Compression) IsCompressed() bool {
	return c == CompressionZlib || c == CompressionLzo
}

// IsSupported reports that this reader can assemble nodes using the
// compressor.
func (c Compression) IsSupported() bool {
	return c.IsStored() || c.IsZero() || c.IsCompressed()
}

// Dirent is one directory entry.
type Dirent struct {
	Pino    uint32
	Version uint32
	// Ino is the named inode; zero means the name was deleted at this
	// version.
	Ino      uint32
	MCTime   uint32
	FileType uint8
	Name     string
}

// IsDeletion reports that the entry is a tombstone rather than a name.
func (d *Dirent) IsDeletion() bool { return d.Ino == 0 }

// ParseDirent parses a whole dirent node, header included.
func ParseDirent(raw []byte) (*Dirent, error) {
	header, ok, err := parseNodeHeader(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, corruptf("a dirent without a node magic")
	}
	if header.NodeType != nodeTypeDirent {
		return nil, corruptf("node type %#06x is not a dirent", header.NodeType)
	}
	totalLen := int(header.TotalLen)
	if len(raw) < totalLen || totalLen < direntFixedBytes {
		return nil, corruptf("a %d-byte dirent is shorter than its %d-byte fixed part",
			totalLen, direntFixedBytes)
	}
	raw = raw[:totalLen]
	if crc32IEEE(raw[12:32]) != readLE32(raw, 32) {
		return nil, corruptf("a dirent's own fields fail their CRC")
	}
	nameLen := int(raw[28])
	if nameLen == 0 || nameLen > maxNameBytes {
		return nil, corruptf("a dirent names %d bytes", nameLen)
	}
	if direntFixedBytes+nameLen > totalLen || pad4(direntFixedBytes+nameLen) != totalLen {
		return nil, corruptf("a dirent of %d name bytes declares %d bytes instead of %d",
			nameLen, totalLen, pad4(direntFixedBytes+nameLen))
	}
	name := raw[direntFixedBytes : direntFixedBytes+nameLen]
	if crc32IEEE(name) != readLE32(raw, 36) {
		return nil, corruptf("a dirent's name fails its CRC")
	}
	for _, value := range name {
		if value == 0 || value == '/' {
			return nil, corruptf("a dirent's name holds a NUL or a slash, which a single name cannot")
		}
	}
	return &Dirent{
		Pino:     readLE32(raw, 12),
		Version:  readLE32(raw, 16),
		Ino:      readLE32(raw, 20),
		MCTime:   readLE32(raw, 24),
		FileType: raw[29],
		Name:     strings.ToValidUTF8(string(name), "�"),
	}, nil
}

// InodeNode is one inode node: metadata plus a slice of a file's bytes.
type InodeNode struct {
	Ino     uint32
	Version uint32
	Mode    uint32
	UID     uint16
	GID     uint16
	// Size is the file's whole logical length at this version.
	Size  uint32
	ATime uint32
	MTime uint32
	CTime uint32
	// Offset is where this node's data starts in the file.
	Offset uint32
	// CSize is the stored byte count, including any compression.
	CSize uint32
	// DSize is the logical byte count this node supplies.
	DSize       uint32
	Compression Compression
	UserCompr   uint8
	DataCRC     uint32
	// DataOffset is the stored data's absolute image offset.
	DataOffset uint64
}

// ParseInodeNode parses a whole inode node, header included. imageOffset is
// where the node starts, which makes the data's offset absolute.
func ParseInodeNode(raw []byte, imageOffset uint64) (*InodeNode, error) {
	header, ok, err := parseNodeHeader(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, corruptf("an inode without a node magic")
	}
	if header.NodeType != nodeTypeInode {
		return nil, corruptf("node type %#06x is not an inode", header.NodeType)
	}
	totalLen := int(header.TotalLen)
	if len(raw) < totalLen || totalLen < inodeFixedBytes {
		return nil, corruptf("a %d-byte inode is shorter than its %d-byte fixed part",
			totalLen, inodeFixedBytes)
	}
	raw = raw[:totalLen]
	if crc32IEEE(raw[12:64]) != readLE32(raw, 64) {
		return nil, corruptf("an inode's own fields fail their CRC")
	}
	csize := readLE32(raw, 48)
	dsize := readLE32(raw, 52)
	if uint64(inodeFixedBytes)+uint64(csize) > uint64(header.TotalLen) ||
		pad4(inodeFixedBytes+int(csize)) != totalLen {
		return nil, corruptf("an inode with %d stored bytes declares %d bytes instead of %d",
			csize, totalLen, pad4(inodeFixedBytes+int(csize)))
	}
	ino := readLE32(raw, 12)
	if ino == 0 {
		return nil, corruptf("an inode node names inode zero")
	}
	compression := CompressionFromByte(raw[56])
	if compression.IsZero() && dsize != csize && csize != 0 {
		return nil, corruptf("a zero-compressed inode stores %d bytes for %d logical bytes", csize, dsize)
	}
	return &InodeNode{
		Ino:         ino,
		Version:     readLE32(raw, 16),
		Mode:        readLE32(raw, 20),
		UID:         readLE16(raw, 24),
		GID:         readLE16(raw, 26),
		Size:        readLE32(raw, 28),
		ATime:       readLE32(raw, 32),
		MTime:       readLE32(raw, 36),
		CTime:       readLE32(raw, 40),
		Offset:      readLE32(raw, 44),
		CSize:       csize,
		DSize:       dsize,
		Compression: compression,
		UserCompr:   raw[57],
		DataCRC:     readLE32(raw, 60),
		DataOffset:  imageOffset + inodeFixedBytes,
	}, nil
}

// NodeTypeName names the node types a scan reports.
func NodeTypeName(nodeType uint16) string {
	switch nodeType {
	case nodeTypeDirent:
		return "dirent"
	case nodeTypeInode:
		return "inode"
	case nodeTypeCleanmarker:
		return "cleanmarker"
	case nodeTypePadding:
		return "padding"
	case nodeTypeSummary:
		return "summary"
	case nodeTypeXattr:
		return "xattr"
	case nodeTypeXref:
		return "xref"
	default:
		return "unknown"
	}
}
