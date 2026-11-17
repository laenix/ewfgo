package hpfs

import (
	"strconv"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Fnode constants. Every file, directory and symbolic link starts with a
// 512-byte fnode; its leaf allocation form holds at most eight runs.
const (
	fnodeMagic      uint32 = 0xf7e40aae
	flagAnode       uint16 = 0x0002
	flagDirectory   uint16 = 0x0100
	btreeInternal   uint8  = 0x80
	maxFnodeExtents        = 8
)

const (
	fnMagicAt        = 0x00
	fnNameLenAt      = 0x0c
	fnNameAt         = 0x0d
	fnNameLenMax     = 15
	fnUpAt           = 0x1c
	fnACLSizeLAt     = 0x20
	fnACLSizeSAt     = 0x28
	fnACLAnodeAt     = 0x2a
	fnEASizeLAt      = 0x2c
	fnEASizeSAt      = 0x34
	fnFlagsAt        = 0x36
	fnBtreeFlagsAt   = 0x38
	fnBtreeUsedAt    = 0x3d
	fnBtreeEntriesAt = 0x40
	fnBtreeEntryLen  = 12
	fnFileSizeAt     = 0xa0
	fnNNeedEAAt      = 0xa4
)

// Extent is one run of a file, in bytes.
type Extent struct {
	// Logical is the byte offset within the file.
	Logical uint64
	// Physical is the byte offset within the volume.
	Physical uint64
	// Len is the run length, a whole number of sectors.
	Len uint64
}

// Fnode is a decoded file node.
type Fnode struct {
	// Sector is where the fnode was read from.
	Sector uint32
	// Flags is the raw flags word.
	Flags uint16
	// Name is the truncated name stored inside the fnode.
	Name []byte
	// Up is the parent directory's fnode sector.
	Up uint32
	// FileSize is the logical file length in bytes.
	FileSize uint64
	// Extents are the runs recorded directly in the fnode, in file order.
	Extents []Extent
	// EASizeDisk is the disk-resident extended-attribute length.
	EASizeDisk uint32
	// EASizeFnode is the fnode-resident extended-attribute length.
	EASizeFnode uint16
	// ACLSizeDisk is the disk-resident ACL length.
	ACLSizeDisk uint32
	// ACLSizeFnode is the fnode-resident ACL length.
	ACLSizeFnode uint16
	// ACLAnode reports that the ACL sector is an allocation node.
	ACLAnode bool
	// NNeedEA counts extended attributes that carry a "need EA" marker.
	NNeedEA uint32
	// BtreeFlags is the raw B+ tree flags byte.
	BtreeFlags uint8
	// BtreeUsed is the occupied leaf-entry count.
	BtreeUsed uint8
}

// IsDirectory reports whether the fnode describes a directory.
func (f *Fnode) IsDirectory() bool { return f.Flags&flagDirectory != 0 }

// InAnode reports whether the extended-attribute sector is an allocation node.
func (f *Fnode) InAnode() bool { return f.Flags&flagAnode != 0 }

// HasExtendedAttributes reports whether any extended attribute is recorded.
// Their contents are never decoded by this reader.
func (f *Fnode) HasExtendedAttributes() bool {
	return f.EASizeDisk > 0 || f.EASizeFnode > 0 || f.NNeedEA > 0
}

// HasACLs reports whether any ACL is recorded.
func (f *Fnode) HasACLs() bool { return f.ACLSizeDisk > 0 || f.ACLSizeFnode > 0 }

// AllocatedBytes is the number of bytes the fnode's runs allocate.
func (f *Fnode) AllocatedBytes() uint64 {
	var total uint64
	for _, extent := range f.Extents {
		total += extent.Len
	}
	return total
}

// IsEmpty reports whether the fnode records no runs.
func (f *Fnode) IsEmpty() bool { return len(f.Extents) == 0 }

func readFnode(src source.ByteSource, sb *Superblock, sector uint32) (*Fnode, error) {
	offset, err := sb.ValidateSector(sector, "an fnode")
	if err != nil {
		return nil, err
	}
	raw := make([]byte, SectorBytes)
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return nil, err
	}
	magic := le32(raw, fnMagicAt)
	if magic != fnodeMagic {
		return nil, corruptf("the fnode in sector %d has magic %#08x, not %#08x", sector, magic, fnodeMagic)
	}
	flags := le16(raw, fnFlagsAt)
	btreeFlags := raw[fnBtreeFlagsAt]
	if btreeFlags&btreeInternal != 0 {
		return nil, unsupportedf("the fnode in sector %d uses the internal B-tree form, whose anode runs are not decoded", sector)
	}
	used := raw[fnBtreeUsedAt]
	if int(used) > maxFnodeExtents {
		return nil, corruptf("the fnode in sector %d claims %d leaf entries; the fnode holds at most %d",
			sector, used, maxFnodeExtents)
	}
	extents := make([]Extent, 0, used)
	var previousEnd uint64
	for index := 0; index < int(used); index++ {
		at := fnBtreeEntriesAt + index*fnBtreeEntryLen
		fileSec := uint64(le32(raw, at))
		length := uint64(le32(raw, at+4))
		diskSec := uint64(le32(raw, at+8))
		if length == 0 {
			return nil, corruptf("extent %d of the fnode in sector %d has zero length", index, sector)
		}
		if diskSec == 0 {
			return nil, corruptf("extent %d of the fnode in sector %d names sector 0, the boot block", index, sector)
		}
		if index > 0 && fileSec < previousEnd {
			return nil, corruptf("extent %d of the fnode in sector %d starts at file sector %d, inside the previous extent ending at %d",
				index, sector, fileSec, previousEnd)
		}
		if fileSec+length > 0xffff_ffff {
			return nil, corruptf("a file extent of the fnode in sector %d overflows its 32-bit sector count", sector)
		}
		if _, err := sb.ValidateSectorRange(uint32(diskSec), uint32(length),
			"extent "+strconv.Itoa(index)+" of the fnode in sector "+strconv.Itoa(int(sector))); err != nil {
			return nil, err
		}
		extents = append(extents, Extent{
			Logical:  fileSec * SectorBytes,
			Physical: diskSec * SectorBytes,
			Len:      length * SectorBytes,
		})
		previousEnd = fileSec + length
	}
	if flags&flagDirectory != 0 && len(extents) == 0 {
		return nil, corruptf("the directory fnode in sector %d names no dnode", sector)
	}
	nameLen := int(raw[fnNameLenAt])
	if nameLen > fnNameLenMax {
		nameLen = fnNameLenMax
	}
	name := append([]byte(nil), raw[fnNameAt:fnNameAt+nameLen]...)
	return &Fnode{
		Sector:       sector,
		Flags:        flags,
		Name:         name,
		Up:           le32(raw, fnUpAt),
		FileSize:     uint64(le32(raw, fnFileSizeAt)),
		Extents:      extents,
		EASizeDisk:   le32(raw, fnEASizeLAt),
		EASizeFnode:  le16(raw, fnEASizeSAt),
		ACLSizeDisk:  le32(raw, fnACLSizeLAt),
		ACLSizeFnode: le16(raw, fnACLSizeSAt),
		ACLAnode:     raw[fnACLAnodeAt] != 0,
		NNeedEA:      le32(raw, fnNNeedEAAt),
		BtreeFlags:   btreeFlags,
		BtreeUsed:    used,
	}, nil
}
