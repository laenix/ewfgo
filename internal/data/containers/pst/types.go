package pst

import (
	"fmt"
	"time"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// SignatureBytes is the length of the file signature at offset 0.
	SignatureBytes = 4
	// MagicPST is the content magic of a personal folder store (".pst").
	MagicPST = "SM"
	// MagicOST is the content magic of an offline folder store (".ost").
	MagicOST = "SO"

	ansiHeaderBytes = 512
	headerBytes     = 564
	pageBytes512    = 512
	pageBytes4K     = 4096

	blockFooterBytesANSI  = 12
	blockFooterBytes512   = 16
	blockFooterBytes4K    = 24
	blockIncrement512     = 64
	blockIncrement4K      = 512
	maxBlockAlloc512      = 8192
	maxBlockAlloc4K       = 64 * 1024
	maxBTLevels           = 8
	maxSubnodeLevels      = 4
	searchMask            = ^uint64(1)
	bitInternal           = uint64(0x2)
	arrayType             = 0x01
	nbtPageType           = 0x81
	bbtPageType           = 0x80
	subtreePageType       = 0x02
	subtreeHeaderANSI     = 4
	subtreeHeader         = 8
	subtreeLeafEntryANSI  = 12
	subtreeLeafEntry      = 24
	subtreeIndexEntryANSI = 8
	subtreeIndexEntry     = 16

	rootFolderNID = 0x22
)

// Absolute caps.  A Limits field may lower a bound but never raise it above
// the cap, so a malformed store cannot make the reader allocate without end.
const (
	maxPagesHard               = 2_000_000
	maxNodesHard               = 4_000_000
	maxBlocksHard              = 4_000_000
	maxNodeDataHard            = 64 * 1024 * 1024
	maxAttachmentHashBytesHard = 8 * 1024 * 1024
	maxPropertiesHard          = 200_000
	maxTCRowsHard              = 1_000_000
	maxTCMatrixBytes           = 64 * 1024 * 1024
	maxMultiValuesHard         = 100_000
)

// Property ids this reader interprets.
const (
	propDisplayName             uint16 = 0x3001
	propContentCount            uint16 = 0x3602
	propSubject                 uint16 = 0x0037
	propMessageClass            uint16 = 0x001A
	propClientSubmitTime        uint16 = 0x0039
	propSenderName              uint16 = 0x0C1A
	propSenderEmail             uint16 = 0x0C1E
	propSenderSMTPAddress       uint16 = 0x5D01
	propLastModificationTime    uint16 = 0x3008
	propSenderSMTP              uint16 = 0x39FE
	propDeliveryTime            uint16 = 0x0E06
	propMessageFlags            uint16 = 0x0E07
	propMessageSize             uint16 = 0x0E08
	propBody                    uint16 = 0x1000
	propTransportHeaders        uint16 = 0x007D
	propInternetMessageID       uint16 = 0x1035
	propDisplayTo               uint16 = 0x0E04
	propDisplayCc               uint16 = 0x0E03
	propDisplayBcc              uint16 = 0x0E02
	propHasAttachments          uint16 = 0x0E1D
	propHTML                    uint16 = 0x1013
	propRTFCompressed           uint16 = 0x1009
	propMessageCodepage         uint16 = 0x3FFD
	propInternetCodepage        uint16 = 0x3FDE
	propAttachSize              uint16 = 0x0E20
	propAttachDisplayName       uint16 = 0x3001
	propAttachCreationTime      uint16 = 0x3007
	propAttachModificationTime  uint16 = 0x3008
	propAttachData              uint16 = 0x3701
	propAttachExtension         uint16 = 0x3703
	propAttachFilename          uint16 = 0x3704
	propAttachMethod            uint16 = 0x3705
	propAttachLongFilename      uint16 = 0x3707
	propAttachPathname          uint16 = 0x3708
	propAttachLongPathname      uint16 = 0x370D
	propAttachMIME              uint16 = 0x370E
	propAttachContentID         uint16 = 0x3712
	propRecipientType           uint16 = 0x0C15
	propAddressType             uint16 = 0x3002
	propEmailAddress            uint16 = 0x3003
	propFolderType              uint16 = 0x660B
	propSearchFolderLastUsed    uint16 = 0x683A
	propSearchFolderTemplateID  uint16 = 0x6841
	propSearchFolderID          uint16 = 0x6842
	propSearchFolderDefinition  uint16 = 0x6845
	propSearchFolderStorageType uint16 = 0x6846
	propSearchFolderTag         uint16 = 0x6847
	propSearchFolderEFPFlags    uint16 = 0x6848
	propLTPParentNID            uint16 = 0x67F1
	propLTPRowID                uint16 = 0x67F2
)

// NID types.
const (
	nidTypeFolder         uint8 = 0x02
	nidTypeSearchFolder   uint8 = 0x03
	nidTypeMessage        uint8 = 0x04
	nidTypeAssociatedMsg  uint8 = 0x08
	nidTypeSearchCriteria uint8 = 0x07
	nidTypeSearchContents uint8 = 0x10
	nidTypeSubnode        uint8 = 0x1F
)

// Table subnode NIDs.
const (
	// AttachmentTableNID is the local subnode NID of a message's attachment
	// table.
	AttachmentTableNID uint32 = 0x0671
	// RecipientTableNID is the local subnode NID of a message's recipient
	// table.
	RecipientTableNID uint32 = 0x0692
)

// StoreKind is what the header's content magic says the store is.
type StoreKind uint8

const (
	// StorePersonal is "SM", a personal folder store, normally ".pst".
	StorePersonal StoreKind = iota
	// StoreOffline is "SO", an offline folder store, normally ".ost".
	StoreOffline
)

// Label returns "pst" or "ost".
func (k StoreKind) Label() string {
	if k == StoreOffline {
		return "ost"
	}
	return "pst"
}

// String returns the label.
func (k StoreKind) String() string { return k.Label() }

// StoreFormat is the on-disk layout the header version fixes.
type StoreFormat uint8

const (
	// FormatAnsi is versions 14/15: 32-bit NIDs/BIDs, 512-byte pages, ANSI
	// strings.
	FormatAnsi StoreFormat = iota
	// FormatUnicode512 is version 23: 64-bit NIDs/BIDs, 512-byte pages.
	FormatUnicode512
	// FormatUnicode4K is version 36: 64-bit NIDs/BIDs, 4 KiB pages.
	FormatUnicode4K
)

// Label returns "ansi", "unicode-512" or "unicode-4k".
func (f StoreFormat) Label() string {
	switch f {
	case FormatAnsi:
		return "ansi"
	case FormatUnicode512:
		return "unicode-512"
	default:
		return "unicode-4k"
	}
}

// String returns the label.
func (f StoreFormat) String() string { return f.Label() }

// PageBytes returns 512 or 4096.
func (f StoreFormat) PageBytes() int {
	if f == FormatUnicode4K {
		return pageBytes4K
	}
	return pageBytes512
}

// IsAnsi reports whether the format uses the ANSI header and tree entries.
func (f StoreFormat) IsAnsi() bool { return f == FormatAnsi }

// CryptMethod identifies the NDB block encoding.
type CryptMethod uint8

const (
	// CryptNone leaves leaf-block data plaintext.
	CryptNone CryptMethod = 0
	// CryptPermute is NDB_CRYPT_PERMUTE (compressible encryption).
	CryptPermute CryptMethod = 1
	// CryptCyclic is NDB_CRYPT_CYCLIC.
	CryptCyclic CryptMethod = 2
)

// Label returns "none", "permute" or "cyclic".
func (c CryptMethod) Label() string {
	switch c {
	case CryptNone:
		return "none"
	case CryptPermute:
		return "permute"
	case CryptCyclic:
		return "cyclic"
	default:
		return "unknown"
	}
}

// String returns the label.
func (c CryptMethod) String() string { return c.Label() }

// Bref is a block reference: the BID and the offset of the block in the file.
type Bref struct {
	BID uint64
	IB  uint64
}

// Header is the fields of a PST header this reader uses.
type Header struct {
	// Version is 14/15 (ANSI), 23 (Unicode, 512-byte pages) or 36 (Unicode,
	// 4 KiB pages).
	Version uint16
	// Format is the layout the version fixes.
	Format StoreFormat
	// ContentType is the kind the header's magic names.
	ContentType StoreKind
	// PageBytes is the page size the version fixes: 512 or 4096.
	PageBytes int
	// VersionClient is the writer's client version.
	VersionClient uint16
	// CryptMethod is the NDB block encoding.
	CryptMethod CryptMethod
	// Unique is the store's unique identifier.
	Unique uint32
	// FileEOF is the store's declared end offset.
	FileEOF uint64
	// BlockNext is the next BID the writer would assign.
	BlockNext uint64
	// NodeRoot locates the node B-tree.
	NodeRoot Bref
	// BlockRoot locates the block B-tree.
	BlockRoot Bref
}

// CryptLabel returns "none", "permute" or "cyclic".
func (h Header) CryptLabel() string { return h.CryptMethod.Label() }

// Node is one NBT descriptor entry.
type Node struct {
	NID uint64
	// Data is the BID of the node data: an external leaf block or an internal
	// XBLOCK/XXBLOCK array.
	Data uint64
	// Subnode is the BID of the node's subnode B-tree; zero when it has none.
	Subnode uint64
	// Parent is the NID of the parent folder.
	Parent uint32
	// PageOffset is the file offset of the NBT leaf page that carried the
	// descriptor.  It is provenance, not an allocation the reader owns.
	PageOffset uint64
}

// Kind returns the low five bits of the NID.
func (n Node) Kind() uint8 { return uint8(n.NID & 0x1F) }

// IsFolder reports a normal (2) or search (3) folder node.
func (n Node) IsFolder() bool {
	kind := n.Kind()
	return kind == nidTypeFolder || kind == nidTypeSearchFolder
}

// IsMessage reports an ordinary message node (NID type 4).
func (n Node) IsMessage() bool { return n.Kind() == nidTypeMessage }

// IsAssociatedMessage reports a folder associated information message
// (NID type 8): a hidden item a folder keeps for itself.
func (n Node) IsAssociatedMessage() bool { return n.Kind() == nidTypeAssociatedMsg }

// Filetime is a FILETIME: 100-nanosecond ticks since 1601-01-01 UTC.
type Filetime uint64

// Time converts the stored FILETIME to a UTC time.  A zero FILETIME is not a
// valid timestamp and returns the zero time, so absence is never turned into
// 1601.
func (f Filetime) Time() time.Time {
	if f == 0 {
		return time.Time{}
	}
	const epochDelta = 11644473600 // seconds from 1601-01-01 to 1970-01-01
	seconds := int64(f/10_000_000) - epochDelta
	nanos := int64(f%10_000_000) * 100
	return time.Unix(seconds, nanos).UTC()
}

// ValueKind is the MAPI type a Value holds.
type ValueKind uint8

const (
	ValueNull ValueKind = iota
	ValueBoolean
	ValueI2
	ValueI4
	ValueI8
	ValueFloat
	ValueDouble
	ValueCurrency
	ValueAppTime
	ValueError
	ValueTime
	ValueCLSID
	ValueString
	ValueMultiString
	ValueBinary
	ValueObject
	ValueUnsupported
)

// Label returns a report-friendly name.
func (k ValueKind) Label() string {
	switch k {
	case ValueNull:
		return "null"
	case ValueBoolean:
		return "boolean"
	case ValueI2:
		return "i2"
	case ValueI4:
		return "i4"
	case ValueI8:
		return "i8"
	case ValueFloat:
		return "float"
	case ValueDouble:
		return "double"
	case ValueCurrency:
		return "currency"
	case ValueAppTime:
		return "app-time"
	case ValueError:
		return "error"
	case ValueTime:
		return "time"
	case ValueCLSID:
		return "clsid"
	case ValueString:
		return "string"
	case ValueMultiString:
		return "multi-string"
	case ValueBinary:
		return "binary"
	case ValueObject:
		return "object"
	default:
		return "unsupported"
	}
}

// Value is a typed MAPI property value.  Only the field for Kind is
// meaningful.
type Value struct {
	Kind ValueKind

	Boolean  bool
	I2       int16
	I4       int32
	I8       int64
	Float    float32
	Double   float64
	Currency int64
	AppTime  float64
	Error    uint32
	Time     Filetime
	CLSID    [16]byte
	String   string
	// MultiString holds the decoded items of PtypMultipleString.
	MultiString []string
	// Binary holds PtypBinary bytes.
	Binary []byte
	// Object holds the stored bytes of PtypObject (often an embedded-message
	// reference).  The object itself is not parsed.
	Object []byte

	// UnsupportedKind and UnsupportedLen preserve what the store declared for
	// a type this reader does not interpret.  No value bytes are invented.
	UnsupportedKind uint16
	UnsupportedLen  int
}

// TextBasis says how a PtypString8 value was turned into text.
type TextBasis struct {
	// BytesPreserved is true when no usable code page was declared and each
	// byte was mapped to the code point of the same value.
	BytesPreserved bool
	// CodePage is the code page used when BytesPreserved is false.
	CodePage uint32
}

// Property is one property of a node's property context.
type Property struct {
	ID   uint16
	Kind uint16
	// Value is the typed value.
	Value Value
	// TextBasis is set for a PtypString8/PtypMultipleString8 value only.
	TextBasis *TextBasis
}

// Folder is a folder with the name and counts from its property context.
type Folder struct {
	NID    uint64
	Parent uint64
	// Name is nil when the store holds no PidTagDisplayName.
	Name *string
	// ContentCount is PidTagContentCount as stored.
	ContentCount *uint32
	// ChildFolders are the folder NIDs whose parent is this folder.
	ChildFolders []uint64
	// MessageCount counts ordinary messages whose parent is this folder.
	// Associated information messages are not counted.
	MessageCount int

	// Provenance.
	DataBID    uint64
	DataOffset uint64
	SubnodeBID uint64
	PageOffset uint64
}

// SearchLink is one row of a search folder's contents table.
type SearchLink struct {
	// MessageNID is PidTagLtpRowId: the Search Message object NID.
	MessageNID uint32
	// ParentNID is PidTagLtpParentNid: the folder that holds the linked
	// message.
	ParentNID *uint32
	// Problem names why this row's parent NID could not be read.
	Problem *string
}

// SearchFolder is a search folder's criteria object and contents table.
type SearchFolder struct {
	NID         uint64
	Name        *string
	FolderType  *uint32
	TemplateID  *uint32
	FolderID    []byte
	Definition  []byte
	StorageType *uint32
	Tag         *uint32
	EFPFlags    *uint32
	LastUsed    *Filetime
	Links       []SearchLink
	// CriteriaProblem names why the criteria object could not be read.
	CriteriaProblem *string
	// TableProblem names why the search contents table could not be read.
	TableProblem *string
}

// Message is a message reduced to the properties a timeline needs.
type Message struct {
	NID uint64
	// Folder is the parent folder NID.
	Folder uint64
	// Associated marks a folder associated information message.
	Associated bool

	Subject           *string
	SenderName        *string
	SenderEmail       *string
	SenderEmailSource string
	MessageClass      *string
	SubmitTime        *Filetime
	DeliveryTime      *Filetime
	Size              *uint32
	Flags             *uint32
	Body              *string
	HTML              []byte
	RTF               []byte
	TransportHeaders  *string
	MessageID         *string
	DisplayTo         []string
	DisplayCc         []string
	DisplayBcc        []string
	HasAttachments    *bool

	// Provenance.
	DataBID    uint64
	DataOffset uint64
	SubnodeBID uint64
	PageOffset uint64
}

// Attachment is one row of a message's attachment table merged with the
// properties of the attachment object the row names.
type Attachment struct {
	// Index is the zero-based row index.
	Index int
	// NID is the row id: the local subnode NID of the attachment object.
	NID       uint32
	Filename  *string
	Extension *string
	MIMEType  *string
	Method    *uint32
	Size      *uint32
	ContentID *string
	Path      *string
	Created   *Filetime
	Modified  *Filetime
	// DataBytes is the data property's length from the blocks' declared
	// sizes, even when the bytes are too large to read.
	DataBytes *uint64
	// SHA256 is the lower-case hex digest when the data was read and hashed.
	SHA256 *string
	// DataProblem explains why the data was not read or hashed.
	DataProblem *string
	// Embedded is the message embedded in a method-5 attachment.
	Embedded *EmbeddedMessage

	// Provenance of the attachment object, when its subnode entry resolved.
	ObjectBID    uint64
	ObjectOffset uint64
}

// Recipient is one row of a message's recipient table.
type Recipient struct {
	Index int
	// RowID is PidTagLtpRowId: the row's own identifier.
	RowID       uint32
	DisplayName *string
	AddressType *string
	Email       *string
	SMTP        *string
	// Kind is PidTagRecipientType: 1 To, 2 Cc, 3 Bcc, as stored.
	Kind *uint32
	// Problem names why one of this row's cells could not be read.
	Problem *string
}

// EmbeddedMessage holds the properties of a message stored inside another.
type EmbeddedMessage struct {
	NID               uint32
	Subject           *string
	SenderName        *string
	SenderEmail       *string
	SenderEmailSource string
	MessageClass      *string
	SubmitTime        *Filetime
	DeliveryTime      *Filetime
	Size              *uint32
	MessageID         *string
}

// RecoveryKind says how a deleted message was recovered.
type RecoveryKind uint8

const (
	// RecoveryFreeNode is an intact NBT descriptor in an unused leaf slot.
	RecoveryFreeNode RecoveryKind = iota
	// RecoveryOrphanNode is a live NBT node no folder chain reaches.
	RecoveryOrphanNode
	// RecoveryOrphanBlock is a live allocated block no tree references.
	RecoveryOrphanBlock
	// RecoveryFreeBlock is an intact BBT descriptor in an unused leaf slot.
	RecoveryFreeBlock
)

// Label names the recovery kind.
func (k RecoveryKind) Label() string {
	switch k {
	case RecoveryFreeNode:
		return "free-nbt-entry"
	case RecoveryOrphanNode:
		return "orphaned-node"
	case RecoveryOrphanBlock:
		return "orphaned-block"
	default:
		return "free-bbt-entry"
	}
}

// Refusal names a recovery candidate that failed structural validation.
type Refusal struct {
	Candidate string
	Offset    *uint64
	Reason    string
}

// DeletedMessage is a message recovered from free or unreachable store space.
type DeletedMessage struct {
	NID               *uint64
	Recovery          RecoveryKind
	Offset            *uint64
	Parent            *uint64
	ParentName        *string
	Associated        bool
	Subject           *string
	SenderName        *string
	SenderEmail       *string
	SenderEmailSource string
	MessageClass      *string
	SubmitTime        *Filetime
	DeliveryTime      *Filetime
	ModificationTime  *Filetime
	Size              *uint32
	BodyBytes         *uint64
	BodyStream        bool
	HTMLBytes         *uint64
	RTFStreamBytes    *uint64
	HasAttachments    *bool
	AttachmentCount   *int
	RecipientCount    *int
	DisplayTo         []string
	DisplayCc         []string
	DisplayBcc        []string
}

// Recovery is the deleted-item scan of one store.
type Recovery struct {
	Messages []DeletedMessage
	Refusals []Refusal
	Problems []string
}

// Limits bound the resources one store may consume.  A zero (or negative)
// field takes the corresponding default; a value above the hard cap is
// clamped to it.
type Limits struct {
	MaxPages               int
	MaxNodes               int
	MaxBlocks              int
	MaxNodeData            uint64
	MaxAttachmentHashBytes uint64
	MaxProperties          int
	MaxTCRows              int
	MaxTCMatrixBytes       uint64
	MaxMultiValues         int
	MaxItems               int
}

// DefaultLimits returns the documented defaults, matching the reference
// reader's caps.
func DefaultLimits() Limits {
	return Limits{
		MaxPages:               maxPagesHard,
		MaxNodes:               maxNodesHard,
		MaxBlocks:              maxBlocksHard,
		MaxNodeData:            maxNodeDataHard,
		MaxAttachmentHashBytes: maxAttachmentHashBytesHard,
		MaxProperties:          maxPropertiesHard,
		MaxTCRows:              maxTCRowsHard,
		MaxTCMatrixBytes:       maxTCMatrixBytes,
		MaxMultiValues:         maxMultiValuesHard,
		MaxItems:               maxNodesHard,
	}
}

func clampPositive(value, ceiling int) int {
	if value <= 0 {
		return ceiling
	}
	if value > ceiling {
		return ceiling
	}
	return value
}

func clampPositive64(value, ceiling uint64) uint64 {
	if value == 0 {
		return ceiling
	}
	if value > ceiling {
		return ceiling
	}
	return value
}

func (l Limits) normalized() Limits {
	return Limits{
		MaxPages:               clampPositive(l.MaxPages, maxPagesHard),
		MaxNodes:               clampPositive(l.MaxNodes, maxNodesHard),
		MaxBlocks:              clampPositive(l.MaxBlocks, maxBlocksHard),
		MaxNodeData:            clampPositive64(l.MaxNodeData, maxNodeDataHard),
		MaxAttachmentHashBytes: clampPositive64(l.MaxAttachmentHashBytes, maxAttachmentHashBytesHard),
		MaxProperties:          clampPositive(l.MaxProperties, maxPropertiesHard),
		MaxTCRows:              clampPositive(l.MaxTCRows, maxTCRowsHard),
		MaxTCMatrixBytes:       clampPositive64(l.MaxTCMatrixBytes, maxTCMatrixBytes),
		MaxMultiValues:         clampPositive(l.MaxMultiValues, maxMultiValuesHard),
		MaxItems:               clampPositive(l.MaxItems, maxNodesHard),
	}
}

// Stats describes the parsed store.
type Stats struct {
	Version                uint16
	Format                 StoreFormat
	ContentType            StoreKind
	PageBytes              int
	CryptMethod            CryptMethod
	FileEOF                uint64
	NodeCount              int
	BlockCount             int
	FreeNodeCount          int
	FreeBlockCount         int
	FolderNodes            int
	MessageNodes           int
	AssociatedMessageNodes int
	// ChecksumMismatches counts block and page CRC-32 mismatches seen so far.
	// The bytes are still returned; this is a forensic warning, not a failure.
	ChecksumMismatches uint64
}

// blockRef is one leaf entry of the block B-tree.
type blockRef struct {
	bid      uint64
	ib       uint64
	cb       uint16
	original uint16
}

// subnodeEntry is one leaf entry of a subnode B-tree.
type subnodeEntry struct {
	data   uint64
	nested uint64
}

// btPage is one validated BTPAGE.
type btPage struct {
	buf       []byte
	count     int
	maximum   int
	entrySize int
	level     uint8
}

func corruptf(format string, args ...any) *source.Error {
	return &source.Error{Kind: source.ErrCorrupt, Reason: fmt.Sprintf(format, args...)}
}

func unsupportedf(format string, args ...any) *source.Error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(format, args...)}
}

func limitf(format string, args ...any) *source.Error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: "limit exceeded: " + fmt.Sprintf(format, args...)}
}

func decryptf(format string, args ...any) *source.Error {
	return &source.Error{Kind: source.ErrDecrypt, Reason: fmt.Sprintf(format, args...)}
}

func crc32SeedZero(data []byte) uint32 {
	return foundation.CRC32Seeded(0, data)
}
