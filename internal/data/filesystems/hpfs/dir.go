package hpfs

import (
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Directory-node constants. A directory's fnode names the sector of its root
// dnode; each dnode is four sectors and holds a B+ tree of name entries.
const (
	dnodeMagic  uint32 = 0x77e40aae
	DnodeBytes  uint64 = 2048
	MaxDnodes          = 100_000
	MaxEntries         = 1_000_000
	MaxDirDepth        = 16
)

const (
	dnFirstFreeAt = 0x04
	dnSelfAt      = 0x10
	dnEntriesAt   = 0x14

	deLengthAt      = 0x00
	deFlags1At      = 0x02
	deFlags2At      = 0x03
	deFnodeAt       = 0x04
	deWriteAt       = 0x08
	deSizeAt        = 0x0c
	deReadAt        = 0x10
	deCreationAt    = 0x14
	deEASizeAt      = 0x18
	deACLsAt        = 0x1c
	deCodePageAt    = 0x1d
	deNameLenAt     = 0x1e
	deNameAt        = 0x1f
	deHeaderBytes   = 0x1f
	deMinBytes      = 32
	deMaxBytes      = 292
	deFlagFirst     = 0x01
	deFlagDown      = 0x04
	deFlagLast      = 0x08
	deFlagHasEA     = 0x10
	deFlagDirectory = 0x10
)

// dirEntry is one name found in a directory, before its fnode is read.
type dirEntry struct {
	// Name is decoded only for printable ASCII in code page zero.
	Name        string
	RawName     []byte
	Undecodable bool
	Fnode       uint32
	Dnode       uint32
	Flags1      uint8
	Flags2      uint8
	Size        uint32
	WriteTime   uint32
	ReadTime    uint32
	CreateTime  uint32
	EASize      uint32
	ACLCount    uint8
	CodePage    uint8
}

func (e *dirEntry) IsDirectory() bool { return e.Flags2&deFlagDirectory != 0 }

func (e *dirEntry) HasExtendedAttributes() bool {
	return e.Flags1&deFlagHasEA != 0 || e.EASize > 0
}

// dirListing is every name below one directory.
type dirListing struct {
	Entries     []dirEntry
	Dnodes      int
	Undecodable int
}

func readDirectory(src source.ByteSource, sb *Superblock, fnode *Fnode) (*dirListing, error) {
	if !fnode.IsDirectory() {
		return nil, corruptf("the fnode in sector %d is not a directory", fnode.Sector)
	}
	if len(fnode.Extents) == 0 {
		return nil, corruptf("the directory fnode in sector %d names no dnode", fnode.Sector)
	}
	physical := fnode.Extents[0].Physical
	if physical%SectorBytes != 0 {
		return nil, corruptf("the directory fnode in sector %d names a non-sector-aligned root dnode", fnode.Sector)
	}
	rootSector := physical / SectorBytes
	if rootSector > 0xffff_ffff {
		return nil, corruptf("the root dnode sector does not fit in 32 bits")
	}

	type pending struct {
		sector uint32
		depth  int
	}
	queue := []pending{{uint32(rootSector), 0}}
	visited := make(map[uint32]bool)
	var listing dirListing
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if item.depth > MaxDirDepth {
			return nil, corruptf("the directory B-tree is deeper than %d levels at dnode sector %d",
				MaxDirDepth, item.sector)
		}
		if visited[item.sector] {
			return nil, corruptf("the directory B-tree reaches dnode sector %d twice (a loop)", item.sector)
		}
		visited[item.sector] = true
		if len(visited) > MaxDnodes {
			return nil, unsupportedf("the directory needs more than %d dnodes", MaxDnodes)
		}
		listing.Dnodes++

		raw, err := readDnode(src, sb, item.sector)
		if err != nil {
			return nil, err
		}
		firstFree := le32(raw, dnFirstFreeAt)
		limit := int(DnodeBytes)
		if firstFree != 0 {
			if firstFree < dnEntriesAt || firstFree > uint32(DnodeBytes) {
				return nil, corruptf("dnode %d records first_free %d, outside %d..=%d",
					item.sector, firstFree, dnEntriesAt, DnodeBytes)
			}
			limit = int(firstFree)
		}

		at := dnEntriesAt
		for at < limit {
			if at+deMinBytes > limit {
				return nil, corruptf("dnode %d ends with %d bytes, too few for a directory entry",
					item.sector, limit-at)
			}
			length := int(le16(raw, at+deLengthAt))
			if length < deMinBytes || length > deMaxBytes {
				return nil, corruptf("dnode %d: the entry at offset %d has length %d, outside %d..=%d",
					item.sector, at, length, deMinBytes, deMaxBytes)
			}
			if length%4 != 0 {
				return nil, corruptf("dnode %d: the entry at offset %d has length %d, not a multiple of four",
					item.sector, at, length)
			}
			if at+length > limit {
				return nil, corruptf("dnode %d: the entry at offset %d crosses the used region ending at %d",
					item.sector, at, limit)
			}
			flags1 := raw[at+deFlags1At]
			nameLen := int(raw[at+deNameLenAt])
			hasDown := flags1&deFlagDown != 0
			expected := (deHeaderBytes + nameLen + boolInt(hasDown)*4 + 3) &^ 3
			if nameLen == 0 || expected != length {
				return nil, corruptf("dnode %d: the entry at offset %d has name length %d but length %d",
					item.sector, at, nameLen, length)
			}
			if flags1&deFlagLast != 0 {
				break
			}
			if flags1&deFlagFirst != 0 {
				at += length
				continue
			}
			rawName := append([]byte(nil), raw[at+deNameAt:at+deNameAt+nameLen]...)
			codePage := raw[at+deCodePageAt]
			name := decodeName(rawName, codePage)
			if name == "" {
				listing.Undecodable++
			}
			fnodeSector := le32(raw, at+deFnodeAt)
			if fnodeSector == 0 {
				return nil, corruptf("dnode %d: the entry at offset %d names fnode sector 0",
					item.sector, at)
			}
			if fnodeSector >= sb.NSectors {
				return nil, corruptf("dnode %d: the entry at offset %d names fnode sector %d, outside the volume's %d sectors",
					item.sector, at, fnodeSector, sb.NSectors)
			}
			if hasDown {
				pointerAt := at + length - 4
				down := le32(raw, pointerAt)
				if down < 0x10 {
					return nil, corruptf("dnode %d: the entry at offset %d has a down pointer to sector %d",
						item.sector, at, down)
				}
				if _, err := sb.ValidateSectorRange(down, 4, "a directory down pointer"); err != nil {
					return nil, err
				}
				queue = append(queue, pending{down, item.depth + 1})
			}
			if len(listing.Entries) >= MaxEntries {
				return nil, unsupportedf("the directory holds more than %d entries", MaxEntries)
			}
			listing.Entries = append(listing.Entries, dirEntry{
				Name:        name,
				RawName:     rawName,
				Undecodable: name == "",
				Fnode:       fnodeSector,
				Dnode:       item.sector,
				Flags1:      flags1,
				Flags2:      raw[at+deFlags2At],
				Size:        le32(raw, at+deSizeAt),
				WriteTime:   le32(raw, at+deWriteAt),
				ReadTime:    le32(raw, at+deReadAt),
				CreateTime:  le32(raw, at+deCreationAt),
				EASize:      le32(raw, at+deEASizeAt),
				ACLCount:    raw[at+deACLsAt] & 0x07,
				CodePage:    codePage,
			})
			at += length
		}
	}
	return &listing, nil
}

func readDnode(src source.ByteSource, sb *Superblock, sector uint32) ([]byte, error) {
	offset, err := sb.ValidateSectorRange(sector, 4, "a dnode")
	if err != nil {
		return nil, err
	}
	raw := make([]byte, DnodeBytes)
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return nil, err
	}
	magic := le32(raw, 0)
	if magic != dnodeMagic {
		return nil, corruptf("dnode sector %d has magic %#08x, not %#08x", sector, magic, dnodeMagic)
	}
	if self := le32(raw, dnSelfAt); self != sector {
		return nil, corruptf("dnode sector %d records itself as sector %d", sector, self)
	}
	return raw, nil
}

// decodeName decodes a name only when it is printable ASCII in code page zero.
// Any other name is left raw rather than guessed at.
func decodeName(raw []byte, codePage uint8) string {
	if codePage != 0 || len(raw) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(raw))
	for _, value := range raw {
		if value < 0x20 || value > 0x7e || value == '/' || value == '\\' || value == 0 {
			return ""
		}
		builder.WriteByte(value)
	}
	return builder.String()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
