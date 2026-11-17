// Package partition reads partition tables from a ByteSource. It is a pure-Go
// port of forensic-core's data/partition layer, starting with MBR/EBR and GPT.
package partition

import (
	"errors"
	"fmt"
	"math"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ErrInvalid means the table is present but internally inconsistent.
var ErrInvalid = errors.New("partition: invalid partition table")

// ErrUnsupported means the table uses a format this reader recognises but does
// not parse.
var ErrUnsupported = errors.New("partition: unsupported partition table")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Kind identifies a partition-table flavour.
type Kind uint8

const (
	// KindMBR is a DOS/MBR table (including EBR logical partitions).
	KindMBR Kind = iota
	// KindGPT is a GUID Partition Table.
	KindGPT
	// KindAPM is an Apple Partition Map.
	KindAPM
	// KindBSD is a BSD disklabel.
	KindBSD
	// KindNone means no partition table was found.
	KindNone Kind = 0xFF
)

// Label returns the table flavour's display name.
func (k Kind) Label() string {
	switch k {
	case KindMBR:
		return "MBR"
	case KindGPT:
		return "GPT"
	case KindAPM:
		return "APM"
	case KindBSD:
		return "BSD"
	default:
		return "none"
	}
}

// Table is a detected partition table of any flavour.
type Table struct {
	Kind Kind
	MBR  *MBRTable
	GPT  *GPTTable
	APM  *ApmPartitionTable
	BSD  *BsdDisklabel
}

// Partitions returns the table's entries, or nil when there is no table.
func (t *Table) Partitions() []Partition {
	if t == nil {
		return nil
	}
	switch t.Kind {
	case KindMBR:
		if t.MBR != nil {
			return t.MBR.Partitions
		}
	case KindGPT:
		if t.GPT != nil {
			return t.GPT.Partitions
		}
	case KindAPM:
		if t.APM != nil {
			return t.APM.Partitions
		}
	case KindBSD:
		if t.BSD != nil {
			return t.BSD.Partitions
		}
	}
	return nil
}

// Partition is one table entry, normalised across table flavours.
type Partition struct {
	Index       int
	Kind        Kind
	Bootable    bool
	TypeID      uint8
	TypeGUID    string
	GUID        string
	Name        string
	StartLBA    uint64
	SectorCount uint64
	Offset      uint64
	Len         uint64
	// IsContainer is true for an MBR extended-partition container. Logical
	// partitions inside it are emitted as separate entries.
	IsContainer bool
}

// MBRTable is a parsed DOS partition table.
type MBRTable struct {
	DiskSignature uint32
	Partitions    []Partition
}

// GPTHeader is the validated GPT header a table was read from.
type GPTHeader struct {
	Revision              uint32
	HeaderSize            uint32
	HeaderCRC32           uint32
	CurrentLBA            uint64
	BackupLBA             uint64
	FirstUsableLBA        uint64
	LastUsableLBA         uint64
	DiskGUID              string
	PartitionEntryLBA     uint64
	NumPartitionEntries   uint32
	PartitionEntrySize    uint32
	PartitionEntriesCRC32 uint32
	Copy                  Copy
}

// Copy says which of a GPT disk's two headers answered.
type Copy uint8

const (
	// CopyPrimary is the header at LBA 1.
	CopyPrimary Copy = iota
	// CopyBackup is the header at the last LBA.
	CopyBackup
)

// Label returns "primary" or "backup".
func (c Copy) Label() string {
	if c == CopyBackup {
		return "backup"
	}
	return "primary"
}

// IsBackup reports whether this is the backup copy.
func (c Copy) IsBackup() bool { return c == CopyBackup }

// GPTTable is a parsed GUID Partition Table.
type GPTTable struct {
	DiskGUID   string
	Header     GPTHeader
	Partitions []Partition
}

// sectorSize returns the source's sector size after validating that it is a
// power of two of at least 512.
func sectorSize(src source.ByteSource) (uint64, error) {
	size := uint64(src.SectorSize())
	if size < 512 || size&(size-1) != 0 {
		return 0, invalid("invalid sector size %d: must be a power of two >= 512", size)
	}
	return size, nil
}

func checkedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}
