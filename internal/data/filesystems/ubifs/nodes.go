package ubifs

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// UBIFS layout constants.
const (
	// CommonHeaderBytes is the size of every node's common header.
	CommonHeaderBytes = 24
	// MasterPage is the superblock's and each master node's size.
	MasterPage = 4096
	// KeyBytes is the stored size of a simple key.
	KeyBytes = 16
	// IndexFixed is the fixed part of an index node.
	IndexFixed = 32
	// BranchFixed is the fixed part of an index branch.
	BranchFixed = 12
	// InodeFixed is the fixed part of an inode node.
	InodeFixed = 172
	// DataFixed is the fixed part of a data node.
	DataFixed = 48
	// DentFixed is the fixed part of a dent or xent node.
	DentFixed = 56
	// BlockSize is UBIFS's logical file-block size.
	BlockSize = 4096
	// MaxIndexLevels is the deepest index nesting accepted.
	MaxIndexLevels uint16 = 8
	// MaxNodes is the walk's node cap.
	MaxNodes uint64 = 1_000_000
	// MaxEntries is the name cap.
	MaxEntries = 1_000_000
	// MaxFileBytes is the largest file this reader materializes.
	MaxFileBytes uint64 = 8 * 1024 * 1024 * 1024
	// MaxDecodedBlock is the largest decoded block accepted.
	MaxDecodedBlock = 4096
	// MaxInlineBytes is the largest inline payload accepted.
	MaxInlineBytes = 4096
)

// Node types.
const (
	NodeInode      uint8 = 0
	NodeData       uint8 = 1
	NodeDent       uint8 = 2
	NodeXent       uint8 = 3
	NodeTrun       uint8 = 4
	NodePad        uint8 = 5
	NodeSuperblock uint8 = 6
	NodeMaster     uint8 = 7
	NodeRef        uint8 = 8
	NodeIndex      uint8 = 9
	NodeCS         uint8 = 10
	NodeOrph       uint8 = 11
	NodeAuth       uint8 = 12
	NodeLPT        uint8 = 13
	NodeLPTDent    uint8 = 14
	NodeLPTIndex   uint8 = 15
)

// Composite keys.
const (
	KeyIno   uint32 = 0
	KeyData  uint32 = 1
	KeyDent  uint32 = 2
	KeyXent  uint32 = 3
	KeyAuth  uint32 = 5
	keyInode uint32 = 0
)

// nodeSuperblock is the local spelling used by the UBI geometry probe.
const nodeSuperblock = NodeSuperblock

// Common is a parsed UBIFS node common header.
type Common struct {
	CRC      uint32
	Sqnum    uint64
	Len      uint32
	NodeType uint8
}

// ParseCommon parses a node's common header.  The bool is false when the magic
// is absent, the length is impossible, or the buffer is too short.
func ParseCommon(bytes []byte) (Common, bool) {
	if len(bytes) < CommonHeaderBytes {
		return Common{}, false
	}
	if binary.LittleEndian.Uint32(bytes[0:4]) != Magic {
		return Common{}, false
	}
	length := binary.LittleEndian.Uint32(bytes[16:20])
	if length < CommonHeaderBytes || uint64(length) > uint64(len(bytes)) {
		return Common{}, false
	}
	return Common{
		CRC:      binary.LittleEndian.Uint32(bytes[4:8]),
		Sqnum:    binary.LittleEndian.Uint64(bytes[8:16]),
		Len:      length,
		NodeType: bytes[20],
	}, true
}

// CRCOK verifies the stored CRC against bytes[8:Len].
func (c Common) CRCOK(bytes []byte) bool {
	if int(c.Len) > len(bytes) || c.Len < 8 {
		return false
	}
	return foundation.CRC32Seeded(0xFFFF_FFFF, bytes[8:c.Len]) == c.CRC
}

// NodeKey is a UBIFS simple key.
type NodeKey struct {
	Inum uint32
	Kind uint32
	Pos  uint32
}

// ParseKey parses sixteen stored key bytes.  The bool is false for a short
// buffer.
func ParseKey(bytes []byte) (NodeKey, bool) {
	if len(bytes) < KeyBytes {
		return NodeKey{}, false
	}
	return NodeKey{
		Inum: binary.LittleEndian.Uint32(bytes[0:4]),
		Kind: binary.LittleEndian.Uint32(bytes[4:8]),
		Pos:  binary.LittleEndian.Uint32(bytes[8:12]),
	}, true
}

func (k NodeKey) order() [3]uint32 { return [3]uint32{k.Inum, k.Kind, k.Pos} }

func (k NodeKey) validIndexKey() bool {
	return k.Inum != 0 && k.Kind <= KeyAuth
}

// Superblock is a parsed UBIFS superblock.
type Superblock struct {
	KeyHash      uint8
	KeyFormat    uint8
	Flags        uint32
	MinIOSize    uint32
	LEBSize      uint32
	LEBCount     uint32
	MaxLEBCount  uint32
	Fanout       uint32
	FmtVersion   uint32
	DefaultCompr uint16
	UUID         [16]byte
}

// ParseSuperblock parses and proves one UBIFS superblock page.
func ParseSuperblock(bytes []byte) (*Superblock, error) {
	if len(bytes) < MasterPage {
		return nil, corruptf("UBIFS superblock is shorter than 4096 bytes")
	}
	bytes = bytes[:MasterPage]
	common, ok := ParseCommon(bytes)
	if !ok {
		return nil, corruptf("UBIFS superblock header is malformed")
	}
	if common.NodeType != NodeSuperblock || common.Len != MasterPage {
		return nil, corruptf("UBIFS superblock does not declare a 4096-byte superblock node")
	}
	if !common.CRCOK(bytes) {
		return nil, corruptf("UBIFS superblock CRC mismatch")
	}
	keyHash := bytes[24]
	if keyHash != 0 {
		return nil, unsupportedf("unsupported key hash %d", keyHash)
	}
	keyFormat := bytes[25]
	if keyFormat != 0 {
		return nil, unsupportedf("unsupported key format %d", keyFormat)
	}
	fmtVersion := binary.LittleEndian.Uint32(bytes[80:84])
	if fmtVersion < 4 || fmtVersion > 5 {
		return nil, unsupportedf("unsupported UBIFS format version %d", fmtVersion)
	}
	lebSize := binary.LittleEndian.Uint32(bytes[36:40])
	lebCount := binary.LittleEndian.Uint32(bytes[40:44])
	if lebSize == 0 || lebCount == 0 {
		return nil, corruptf("UBIFS superblock declares zero LEB size or count")
	}
	minIOSize := binary.LittleEndian.Uint32(bytes[32:36])
	if minIOSize == 0 || minIOSize > lebSize {
		return nil, corruptf("UBIFS superblock's minimum I/O size is zero or larger than a LEB")
	}
	fanout := binary.LittleEndian.Uint32(bytes[72:76])
	if fanout < 2 || fanout > 512 {
		return nil, unsupportedf("unsupported index fanout %d", fanout)
	}
	var uuid [16]byte
	copy(uuid[:], bytes[108:124])
	return &Superblock{
		KeyHash: keyHash, KeyFormat: keyFormat,
		Flags:        binary.LittleEndian.Uint32(bytes[28:32]),
		MinIOSize:    minIOSize,
		LEBSize:      lebSize,
		LEBCount:     lebCount,
		MaxLEBCount:  binary.LittleEndian.Uint32(bytes[44:48]),
		Fanout:       fanout,
		FmtVersion:   fmtVersion,
		DefaultCompr: binary.LittleEndian.Uint16(bytes[84:86]),
		UUID:         uuid,
	}, nil
}

// MasterNode is a parsed master node.
type MasterNode struct {
	Sqnum       uint64
	HighestInum uint64
	CmtNo       uint64
	RootLnum    uint32
	RootOffs    uint32
	RootLen     uint32
	IheadLnum   uint32
	IheadOffs   uint32
	NodeOffset  uint64
	CRCOK       bool
}

// MasterSelection says why a master was chosen.
type MasterSelection uint8

// Master selections.
const (
	Master1 MasterSelection = iota
	Master2
	Master1Only
	Master2Only
	EqualIdentical
)

// Label returns the selection's report name.
func (s MasterSelection) Label() string {
	switch s {
	case Master1:
		return "master1"
	case Master2:
		return "master2"
	case Master1Only:
		return "master1-only"
	case Master2Only:
		return "master2-only"
	case EqualIdentical:
		return "equal-sqnum-identical"
	default:
		return "unknown"
	}
}

// Refusal is a named condition the reader counted.
type Refusal struct {
	Feature string
	Count   uint64
}

// DeletedName is one xent deletion record.
type DeletedName struct {
	Parent      uint64
	Inum        uint64
	HasInum     bool
	Name        string
	Kind        NodeKind
	NodeOffset  uint64
	Sqnum       uint64
	Hash        uint32
	MatchedDent bool
}

// Hole is a sparse run the inode's length proves exists.
type Hole struct {
	Offset uint64
	Len    uint64
}

// BlockState is how one logical file block is stored.
type BlockState uint8

// Block states.
const (
	BlockPresent BlockState = iota
	BlockInline
	BlockHole
	BlockCorrupt
	BlockUnsupported
)

// FileBlock is one logical block and its storage.
type FileBlock struct {
	Block       uint64
	Offset      uint64
	Len         uint64
	State       BlockState
	ImageOffset uint64
	StoredLen   uint64
	Size        uint32
	Compression uint16
	Lnum        uint32
	LEBOffset   uint64
}

// backing is either a bare contiguous volume or one UBI volume.
type backing struct {
	source source.ByteSource
	ubi    *UbiImage
	volID  uint32
	bare   bool
}

// Device addresses volume bytes by LEB.
type Device struct {
	backing  backing
	lebSize  uint64
	lebCount uint32
}

func (d *Device) readAt(offset uint64, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	if d.lebSize == 0 {
		return corruptf("the volume declares a zero LEB size")
	}
	for done := 0; done < len(buf); {
		at := offset + uint64(done)
		lnum := at / d.lebSize
		within := at % d.lebSize
		if lnum >= uint64(d.lebCount) {
			return corruptf("read at %d passes the volume's %d LEBs", at, d.lebCount)
		}
		take := len(buf) - done
		if remaining := int(d.lebSize - within); take > remaining {
			take = remaining
		}
		if d.backing.bare {
			if at > d.backing.source.Len() || uint64(take) > d.backing.source.Len()-at {
				return source.NewUnexpectedEOF(at)
			}
			if err := source.ReadExactAt(d.backing.source, at, buf[done:done+take]); err != nil {
				return err
			}
		} else {
			if err := d.backing.ubi.ReadLEB(d.backing.volID, uint32(lnum), within, buf[done:done+take]); err != nil {
				return err
			}
		}
		done += take
	}
	return nil
}

func (d *Device) readNode(lnum uint32, offset, length uint64) ([]byte, uint64, error) {
	if length == 0 || length > d.lebSize || offset > d.lebSize-length {
		return nil, 0, corruptf("node at LEB %d offset %d length %d is outside the LEB", lnum, offset, length)
	}
	imageOffset, err := d.imageOffset(lnum, offset)
	if err != nil {
		return nil, 0, err
	}
	if length > uint64(^uint(0)>>1) {
		return nil, 0, limitf("node length %d exceeds int", length)
	}
	bytes := make([]byte, int(length))
	if err := d.readAt(uint64(lnum)*d.lebSize+offset, bytes); err != nil {
		return nil, 0, err
	}
	return bytes, imageOffset, nil
}

func (d *Device) imageOffset(lnum uint32, offset uint64) (uint64, error) {
	if d.backing.bare {
		if uint64(lnum) > (^uint64(0))/d.lebSize {
			return 0, corruptf("LEB %d offset overflows", lnum)
		}
		base := uint64(lnum) * d.lebSize
		if offset > ^uint64(0)-base {
			return 0, corruptf("LEB %d offset %d overflows", lnum, offset)
		}
		return base + offset, nil
	}
	value, found := d.backing.ubi.ImageOffset(d.backing.volID, lnum, offset)
	if !found {
		return 0, corruptf("volume LEB %d offset %d is not mapped", lnum, offset)
	}
	return value, nil
}

func (d *Device) imageRuns(lnum uint32, offset, length uint64) [][2]uint64 {
	if d.backing.bare {
		return [][2]uint64{{uint64(lnum)*d.lebSize + offset, length}}
	}
	runs, _ := d.backing.ubi.ImageRanges(d.backing.volID, lnum, offset, length)
	return runs
}

func readMaster(device *Device, lnum uint32) (*MasterNode, error) {
	if lnum >= device.lebCount {
		return nil, nil
	}
	bytes, imageOffset, err := device.readNode(lnum, 0, MasterPage)
	if err != nil {
		return nil, nil
	}
	common, ok := ParseCommon(bytes)
	if !ok || common.NodeType != NodeMaster || common.Len != MasterPage {
		return nil, nil
	}
	return &MasterNode{
		Sqnum:       common.Sqnum,
		HighestInum: binary.LittleEndian.Uint64(bytes[24:32]),
		CmtNo:       binary.LittleEndian.Uint64(bytes[32:40]),
		RootLnum:    binary.LittleEndian.Uint32(bytes[48:52]),
		RootOffs:    binary.LittleEndian.Uint32(bytes[52:56]),
		RootLen:     binary.LittleEndian.Uint32(bytes[56:60]),
		IheadLnum:   binary.LittleEndian.Uint32(bytes[64:68]),
		IheadOffs:   binary.LittleEndian.Uint32(bytes[68:72]),
		NodeOffset:  imageOffset,
		CRCOK:       common.CRCOK(bytes),
	}, nil
}

func selectMaster(first, second *MasterNode) (*MasterNode, MasterSelection, error) {
	if first != nil && !first.CRCOK {
		first = nil
	}
	if second != nil && !second.CRCOK {
		second = nil
	}
	switch {
	case first != nil && second != nil:
		if first.Sqnum > second.Sqnum {
			return first, Master1, nil
		}
		if second.Sqnum > first.Sqnum {
			return second, Master2, nil
		}
		if first.RootLnum == second.RootLnum && first.RootOffs == second.RootOffs &&
			first.RootLen == second.RootLen && first.HighestInum == second.HighestInum {
			return first, EqualIdentical, nil
		}
		return nil, 0, corruptf("both master nodes verify and carry equal sequence numbers but different roots; refusing to choose one")
	case first != nil:
		return first, Master1Only, nil
	case second != nil:
		return second, Master2Only, nil
	default:
		return nil, 0, corruptf("neither master node verified: UBIFS cannot be mounted without a committed root")
	}
}

func inodeTime(seconds uint64, nanos uint32) (int64, int64, bool) {
	if seconds == 0 && nanos == 0 {
		return 0, 0, false
	}
	if nanos >= 1_000_000_000 {
		return 0, 0, false
	}
	return int64(seconds), int64(nanos), true
}
