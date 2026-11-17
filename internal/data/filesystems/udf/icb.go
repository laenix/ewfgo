package udf

// Information control blocks: file entries, their timestamps, and the
// allocation descriptors that say where their data lives.
//
// A UDF file is addressed by a long allocation descriptor, not an inode
// number. The block holds a File Entry (FE) or, from UDF 2.00, an Extended
// File Entry (EFE). Its ICB flags' low three bits choose the allocation
// descriptor form: short, long, extended, or in-ICB. A descriptor whose type
// bits are 0xC is a pointer to an allocation extent descriptor block (AED)
// continuing the list.

// Bytes of an ICB tag.
const ICBTagBytes = 20

// Bytes before a plain file entry's extended attributes.
const FEExtAttrAt = 176

// Bytes before an extended file entry's extended attributes.
const EFEExtAttrAt = 216

const (
	FileTypeUndefined          = 0x00
	FileTypeUse                = 0x01
	FileTypePartitionIntegrity = 0x02
	FileTypeIndirect           = 0x03
	FileTypeDirectory          = 0x04
	FileTypeRegular            = 0x05
	FileTypeBlock              = 0x06
	FileTypeChar               = 0x07
	FileTypeExtendedAttr       = 0x08
	FileTypeFIFO               = 0x09
	FileTypeSocket             = 0x0A
	FileTypeTerminal           = 0x0B
	FileTypeSymlink            = 0x0C
	FileTypeStreamDirectory    = 0x0D
	FileTypeVAT200             = 0xF8
)

const (
	ADShort    = 0
	ADLong     = 1
	ADExtended = 2
	ADInICB    = 3
)

// IcbTag describes what kind of object an entry is and how its data is
// described.
type IcbTag struct {
	PriorEntries uint32
	Strategy     uint16
	Parameter    uint16
	MaxEntries   uint16
	FileType     uint8
	Parent       LbAddr
	Flags        uint16
}

// ParseIcbTag parses the ICB tag at the start of b.
func ParseIcbTag(b []byte) (IcbTag, bool) {
	if len(b) < ICBTagBytes {
		return IcbTag{}, false
	}
	parent, ok := lbAddr(b, 12)
	if !ok {
		return IcbTag{}, false
	}
	return IcbTag{
		PriorEntries: le32(b, 0),
		Strategy:     le16(b, 4),
		Parameter:    le16(b, 6),
		MaxEntries:   le16(b, 8),
		FileType:     b[11],
		Parent:       parent,
		Flags:        le16(b, 18),
	}, true
}

// ADKind returns the allocation descriptor form from the low flag bits.
func (t IcbTag) ADKind() uint8 { return uint8(t.Flags & 0x0007) }

// IsDirectory reports a directory entry.
func (t IcbTag) IsDirectory() bool { return t.FileType == FileTypeDirectory }

// IsSymlink reports a symbolic link entry.
func (t IcbTag) IsSymlink() bool { return t.FileType == FileTypeSymlink }

// IsRegular reports a regular file entry.
func (t IcbTag) IsRegular() bool { return t.FileType == FileTypeRegular }

// TypeLabel returns a label for the file type.
func (t IcbTag) TypeLabel() string { return TypeLabel(t.FileType) }

// IsListable reports whether the type is presented as a file or directory.
func (t IcbTag) IsListable() bool {
	return t.FileType == FileTypeDirectory || t.FileType == FileTypeRegular || t.FileType == FileTypeSymlink
}

// TypeLabel returns a label for an ECMA-167 file type.
func TypeLabel(fileType uint8) string {
	switch fileType {
	case FileTypeUndefined:
		return "undefined"
	case FileTypeUse:
		return "unallocated-space-entry"
	case FileTypePartitionIntegrity:
		return "partition-integrity"
	case FileTypeIndirect:
		return "indirect-entry"
	case FileTypeDirectory:
		return "directory"
	case FileTypeRegular:
		return "regular"
	case FileTypeBlock:
		return "block-device"
	case FileTypeChar:
		return "character-device"
	case FileTypeExtendedAttr:
		return "extended-attribute"
	case FileTypeFIFO:
		return "fifo"
	case FileTypeSocket:
		return "socket"
	case FileTypeTerminal:
		return "terminal-entry"
	case FileTypeSymlink:
		return "symlink"
	case FileTypeStreamDirectory:
		return "stream-directory"
	case FileTypeVAT200:
		return "virtual-allocation-table"
	default:
		return "unknown"
	}
}

// FileEntry is a parsed file entry (either form).
type FileEntry struct {
	Tag         Tag
	ICB         IcbTag
	UID         uint32
	GID         uint32
	Permissions uint32
	Links       uint16
	// InformationLength is the length the file claims, in bytes.
	InformationLength uint64
	// LogicalBlocks is the length the volume allocated, in bytes.
	LogicalBlocks uint64
	Accessed      UdfTime
	Modified      UdfTime
	Created       UdfTime
	Changed       UdfTime
	UniqueID      *uint64
	// ExtendedAttrICB is the ICB holding extended attributes this entry does
	// not carry. A zero-length descriptor means the entry carries all of them.
	ExtendedAttrICB     *LongAd
	LengthExtendedAttrs uint32
	LengthAllocDescs    uint32
	// ExtAttrAt is where the extended attributes (and so the data, for an
	// in-ICB entry) begin inside the entry block.
	ExtAttrAt int
	// Extended says this was an EFE rather than an FE.
	Extended bool
}

// ParseFileEntry parses either entry form. The descriptor tag decides which.
func ParseFileEntry(b []byte) (FileEntry, bool) {
	tag, ok := ParseTag(b)
	if !ok {
		return FileEntry{}, false
	}
	var extended bool
	switch tag.Ident {
	case TagFE:
	case TagEFE:
		extended = true
	default:
		return FileEntry{}, false
	}
	if len(b) < TagBytes+ICBTagBytes {
		return FileEntry{}, false
	}
	icb, ok := ParseIcbTag(b[TagBytes:])
	if !ok {
		return FileEntry{}, false
	}
	e := FileEntry{Tag: tag, ICB: icb, Extended: extended}
	if e.UID, ok = le32ok(b, 36); !ok {
		return FileEntry{}, false
	}
	if e.GID, ok = le32ok(b, 40); !ok {
		return FileEntry{}, false
	}
	if e.Permissions, ok = le32ok(b, 44); !ok {
		return FileEntry{}, false
	}
	if e.Links, ok = le16ok(b, 48); !ok {
		return FileEntry{}, false
	}
	if e.InformationLength, ok = le64ok(b, 56); !ok {
		return FileEntry{}, false
	}
	if extended {
		if e.LogicalBlocks, ok = le64ok(b, 72); !ok {
			return FileEntry{}, false
		}
		e.Accessed = timeAt(b, 80)
		e.Modified = timeAt(b, 92)
		e.Created = timeAt(b, 104)
		e.Changed = timeAt(b, 116)
		if icbAD, ok := longAD(b, 136); ok {
			e.ExtendedAttrICB = &icbAD
		}
		if unique, ok := le64ok(b, 200); ok {
			e.UniqueID = &unique
		}
		if e.LengthExtendedAttrs, ok = le32ok(b, 208); !ok {
			return FileEntry{}, false
		}
		if e.LengthAllocDescs, ok = le32ok(b, 212); !ok {
			return FileEntry{}, false
		}
		e.ExtAttrAt = EFEExtAttrAt
	} else {
		if e.LogicalBlocks, ok = le64ok(b, 64); !ok {
			return FileEntry{}, false
		}
		e.Accessed = timeAt(b, 72)
		e.Modified = timeAt(b, 84)
		e.Changed = timeAt(b, 96)
		if icbAD, ok := longAD(b, 112); ok {
			e.ExtendedAttrICB = &icbAD
		}
		if unique, ok := le64ok(b, 160); ok {
			e.UniqueID = &unique
		}
		if e.LengthExtendedAttrs, ok = le32ok(b, 168); !ok {
			return FileEntry{}, false
		}
		if e.LengthAllocDescs, ok = le32ok(b, 172); !ok {
			return FileEntry{}, false
		}
		e.ExtAttrAt = FEExtAttrAt
	}
	if len(b) < e.ExtAttrAt {
		return FileEntry{}, false
	}
	return e, true
}

// AllocDescAt returns where the allocation descriptor list begins inside the
// entry.
func (e FileEntry) AllocDescAt() (int, bool) {
	at := e.ExtAttrAt + int(e.LengthExtendedAttrs)
	if at < e.ExtAttrAt {
		return 0, false
	}
	return at, true
}

func timeAt(b []byte, at int) UdfTime {
	if at < 0 || at+12 > len(b) {
		return UdfTime{}
	}
	t, _ := parseUdfTime(b[at : at+12])
	return t
}

// InICBData returns the bytes of an in-ICB entry's data.
func (e FileEntry) InICBData(b []byte) ([]byte, bool) {
	if e.ICB.ADKind() != ADInICB {
		return nil, false
	}
	at, ok := e.AllocDescAt()
	if !ok {
		return nil, false
	}
	length := e.InformationLength
	if length > uint64(len(b)) {
		return nil, false
	}
	end := at + int(length)
	if end < at || end > len(b) {
		return nil, false
	}
	return b[at:end], true
}

// AllocDesc is one allocation descriptor decoded from any of the three forms.
type AllocDesc struct {
	// Length is the raw length field, type bits included.
	Length      uint32
	Addr        LbAddr
	Recorded    uint32
	Information uint32
	HasLengths  bool
}

// ExtentLength returns the recorded length without its type bits.
func (a AllocDesc) ExtentLength() uint32 { return a.Length & ExtLengthMask }

// Kind returns the descriptor's type bits.
func (a AllocDesc) Kind() uint32 { return a.Length & ExtTypeMask }

// IsContinuation reports a pointer to another descriptor block.
func (a AllocDesc) IsContinuation() bool { return a.Kind() == ExtNextExtentAllocDescs }

// IsHole reports one of the two not-recorded forms.
func (a AllocDesc) IsHole() bool {
	return a.Kind() == ExtNotRecordedAllocated || a.Kind() == ExtNotRecordedNotAllocated
}

// DescriptorBytes returns the bytes one allocation descriptor occupies.
func DescriptorBytes(kind uint8) (int, bool) {
	switch kind {
	case ADShort:
		return ShortADBytes, true
	case ADLong:
		return LongADBytes, true
	case ADExtended:
		return ExtendedADBytes, true
	default:
		return 0, false
	}
}

// DecodeDescriptor decodes one descriptor of the given form.
func DecodeDescriptor(kind uint8, b []byte, at int) (AllocDesc, bool) {
	switch kind {
	case ADShort:
		ad, ok := shortAD(b, at)
		if !ok {
			return AllocDesc{}, false
		}
		return AllocDesc{Length: ad.Length, Addr: LbAddr{Block: ad.Block, Partition: 0}}, true
	case ADLong:
		ad, ok := longAD(b, at)
		if !ok {
			return AllocDesc{}, false
		}
		return AllocDesc{Length: ad.Length, Addr: ad.Addr}, true
	case ADExtended:
		ad, ok := extendedAD(b, at)
		if !ok {
			return AllocDesc{}, false
		}
		return AllocDesc{
			Length:      ad.Length,
			Addr:        ad.Addr,
			Recorded:    ad.Recorded,
			Information: ad.Information,
			HasLengths:  true,
		}, true
	default:
		return AllocDesc{}, false
	}
}

// IndirectEntry is a file entry that only points at the real one.
type IndirectEntry struct {
	Tag    Tag
	ICB    IcbTag
	Target LongAd
}

// ParseIndirectEntry parses an indirect entry.
func ParseIndirectEntry(b []byte) (IndirectEntry, bool) {
	tag, ok := ParseTag(b)
	if !ok || tag.Ident != TagIE {
		return IndirectEntry{}, false
	}
	if len(b) < 36+LongADBytes {
		return IndirectEntry{}, false
	}
	icb, ok := ParseIcbTag(b[TagBytes:])
	if !ok {
		return IndirectEntry{}, false
	}
	target, ok := longAD(b, 36)
	if !ok {
		return IndirectEntry{}, false
	}
	return IndirectEntry{Tag: tag, ICB: icb, Target: target}, true
}

// AllocationExtent is an allocation extent descriptor block.
type AllocationExtent struct {
	Tag      Tag
	Previous uint32
	Length   uint32
}

// ParseAllocationExtent parses an allocation extent descriptor block.
func ParseAllocationExtent(b []byte) (AllocationExtent, bool) {
	tag, ok := ParseTag(b)
	if !ok || tag.Ident != TagAED {
		return AllocationExtent{}, false
	}
	previous, ok := le32ok(b, 16)
	if !ok {
		return AllocationExtent{}, false
	}
	length, ok := le32ok(b, 20)
	if !ok {
		return AllocationExtent{}, false
	}
	return AllocationExtent{Tag: tag, Previous: previous, Length: length}, true
}

// Symbolic link component types.
const (
	LinkRoot      = 1
	LinkMountRoot = 2
	LinkParent    = 3
	LinkCurrent   = 4
	LinkName      = 5
)

// SymbolicLink is one component of a symbolic link's target.
type SymbolicLink struct {
	Kind uint8
	Name string
	// HasName says the component carried a decodable name.
	HasName bool
}

// SymlinkComponents decodes a symbolic link's target components.
func SymlinkComponents(b []byte) []SymbolicLink {
	var out []SymbolicLink
	for at := 0; at+2 <= len(b); {
		kind := b[at]
		length := int(b[at+1])
		if at+2+length > len(b) {
			break
		}
		text := b[at+2 : at+2+length]
		component := SymbolicLink{Kind: kind}
		if kind == LinkName {
			component.Name, component.HasName = dstring(text)
		}
		out = append(out, component)
		at += 2 + length
	}
	return out
}

// ImplementationID returns the registered identifier a file entry carries.
func ImplementationID(b []byte, extended bool) (RegId, bool) {
	at := 128
	if extended {
		at = 168
	}
	if at+32 > len(b) {
		return RegId{}, false
	}
	return NewRegId(b[at : at+32])
}
