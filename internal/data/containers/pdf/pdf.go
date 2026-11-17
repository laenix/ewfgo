// Document facts, text and date decoding, and the reader entry points.

package pdf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// MaxHeaderScan is how far into the file the `%PDF-` header is looked for.
	MaxHeaderScan uint64 = 1024
	// MaxTreeDepth is the deepest page tree, name tree or form tree this
	// reader follows.
	MaxTreeDepth uint32 = 64
	// MaxActions is the most actions collected from one document.
	MaxActions = 512
)

// Limits bound the resources one document may consume. A zero or negative
// field takes its default.
type Limits struct {
	Xref                  XrefLimits
	MaxObjectBytes        int
	MaxStreamBytes        int
	MaxDecodedBytes       int
	MaxObjects            int
	MaxTreeNodes          int
	MaxNameTreeEntries    int
	MaxEmbeddedFiles      int
	MaxEmbeddedBytes      int
	MaxEmbeddedTotalBytes uint64
	MaxTextBytes          int
}

// DefaultLimits returns the documented default bounds.
func DefaultLimits() Limits {
	return Limits{
		Xref:                  DefaultXrefLimits(),
		MaxObjectBytes:        32 * 1024 * 1024,
		MaxStreamBytes:        32 * 1024 * 1024,
		MaxDecodedBytes:       DefaultMaxDecodedBytes,
		MaxObjects:            100_000,
		MaxTreeNodes:          100_000,
		MaxNameTreeEntries:    10_000,
		MaxEmbeddedFiles:      10_000,
		MaxEmbeddedBytes:      64 * 1024 * 1024,
		MaxEmbeddedTotalBytes: 256 * 1024 * 1024,
		MaxTextBytes:          1024 * 1024,
	}
}

func (l Limits) normalized() Limits {
	def := DefaultLimits()
	l.Xref = l.Xref.normalized()
	if l.MaxObjectBytes <= 0 {
		l.MaxObjectBytes = def.MaxObjectBytes
	}
	if l.MaxStreamBytes <= 0 {
		l.MaxStreamBytes = def.MaxStreamBytes
	}
	if l.MaxDecodedBytes <= 0 {
		l.MaxDecodedBytes = def.MaxDecodedBytes
	}
	if l.MaxObjects <= 0 {
		l.MaxObjects = def.MaxObjects
	}
	if l.MaxTreeNodes <= 0 {
		l.MaxTreeNodes = def.MaxTreeNodes
	}
	if l.MaxNameTreeEntries <= 0 {
		l.MaxNameTreeEntries = def.MaxNameTreeEntries
	}
	if l.MaxEmbeddedFiles <= 0 {
		l.MaxEmbeddedFiles = def.MaxEmbeddedFiles
	}
	if l.MaxEmbeddedBytes <= 0 {
		l.MaxEmbeddedBytes = def.MaxEmbeddedBytes
	}
	if l.MaxEmbeddedTotalBytes == 0 {
		l.MaxEmbeddedTotalBytes = def.MaxEmbeddedTotalBytes
	}
	if l.MaxTextBytes <= 0 {
		l.MaxTextBytes = def.MaxTextBytes
	}
	return l
}

// Date is one parsed PDF date, `D:YYYYMMDDHHmmSSOHH'mm'`.
type Date struct {
	// Raw is the text as the file wrote it.
	Raw    string
	Year   int
	Month  int
	Day    int
	Hour   int
	Minute int
	Second int
	// OffsetMinutes is the offset from UTC in minutes; nil when the file gave
	// no zone.
	OffsetMinutes *int
	// UnixSeconds is the instant in UTC seconds, when the civil fields form a
	// real date.
	UnixSeconds *int64
}

// ParsePDFDate parses a PDF date. `D:` is optional, missing fields default to
// 1 January 00:00:00, and a zone of `Z` means UTC.
func ParsePDFDate(raw string) *Date {
	text := strings.TrimSpace(raw)
	digits := strings.TrimPrefix(text, "D:")
	bytesValue := []byte(digits)
	number := func(at, length int) (uint32, bool) {
		if at < 0 || length < 0 || at+length > len(bytesValue) {
			return 0, false
		}
		field := bytesValue[at : at+length]
		for _, b := range field {
			if b < '0' || b > '9' {
				return 0, false
			}
		}
		value, err := parseU32(string(field))
		if err != nil {
			return 0, false
		}
		return value, true
	}
	year, ok := number(0, 4)
	if !ok {
		return nil
	}
	position := 4
	nextField := func(length int) (uint32, bool) {
		value, ok := number(position, length)
		if ok {
			position += length
		}
		return value, ok
	}
	month, ok := nextField(2)
	if !ok {
		month = 1
	}
	day, ok := nextField(2)
	if !ok {
		day = 1
	}
	hour, ok := nextField(2)
	if !ok {
		hour = 0
	}
	minute, ok := nextField(2)
	if !ok {
		minute = 0
	}
	second, ok := nextField(2)
	if !ok {
		second = 0
	}
	var offset *int
	if position < len(bytesValue) {
		sign := 0
		switch bytesValue[position] {
		case '+':
			sign = 1
		case '-':
			sign = -1
		case 'Z':
			sign = 0
		default:
			sign = -1
		}
		if bytesValue[position] == '+' || bytesValue[position] == '-' || bytesValue[position] == 'Z' {
			position++
			for position < len(bytesValue) && bytesValue[position] == '\'' {
				position++
			}
			zone := func(length int) uint32 {
				value, ok := number(position, length)
				if ok {
					position += length
				} else {
					value = 0
				}
				for position < len(bytesValue) && bytesValue[position] == '\'' {
					position++
				}
				if !ok {
					return 0
				}
				return value
			}
			hours := zone(2)
			minutes := zone(2)
			value := sign * (int(hours)*60 + int(minutes))
			offset = &value
		}
	}
	civil, hasCivil := unixSecondsFromCivil(int64(year), int(month), int(day), int(hour), int(minute), int(second))
	var seconds *int64
	if hasCivil {
		offsetSeconds := int64(0)
		if offset != nil {
			offsetSeconds = int64(*offset) * 60
		}
		value := civil - offsetSeconds
		seconds = &value
	}
	return &Date{
		Raw: raw, Year: int(year), Month: int(month), Day: int(day),
		Hour: int(hour), Minute: int(minute), Second: int(second),
		OffsetMinutes: offset, UnixSeconds: seconds,
	}
}

func parseU32(text string) (uint32, error) {
	var value uint32
	for _, b := range []byte(text) {
		value = value*10 + uint32(b-'0')
	}
	return value, nil
}

// DecodePDFText decodes a PDF text string: UTF-16 with a byte-order mark,
// UTF-8 with one, or PDFDocEncoding (Latin-1 with a documented set of
// substitutions).
func DecodePDFText(bytesValue []byte) string {
	if len(bytesValue) >= 2 && bytesValue[0] == 0xFE && bytesValue[1] == 0xFF {
		return utf16Text(bytesValue[2:], true)
	}
	if len(bytesValue) >= 2 && bytesValue[0] == 0xFF && bytesValue[1] == 0xFE {
		return utf16Text(bytesValue[2:], false)
	}
	if len(bytesValue) >= 3 && bytesValue[0] == 0xEF && bytesValue[1] == 0xBB && bytesValue[2] == 0xBF {
		return lossyUTF8(bytesValue[3:])
	}
	runes := make([]rune, len(bytesValue))
	for i, b := range bytesValue {
		runes[i] = pdfDocCharacter(b)
	}
	return string(runes)
}

func utf16Text(bytesValue []byte, bigEndian bool) string {
	units := make([]uint16, 0, len(bytesValue)/2)
	for i := 0; i+1 < len(bytesValue); i += 2 {
		if bigEndian {
			units = append(units, uint16(bytesValue[i])<<8|uint16(bytesValue[i+1]))
		} else {
			units = append(units, uint16(bytesValue[i+1])<<8|uint16(bytesValue[i]))
		}
	}
	return string(utf16.Decode(units))
}

func pdfDocCharacter(b byte) rune {
	switch b {
	case 0x18:
		return '˘'
	case 0x19:
		return 'ˇ'
	case 0x1A:
		return 'ˆ'
	case 0x1B:
		return '˙'
	case 0x1C:
		return '˝'
	case 0x1D:
		return '˛'
	case 0x1E:
		return '˚'
	case 0x1F:
		return '˜'
	case 0x80:
		return '•'
	case 0x81:
		return '†'
	case 0x82:
		return '‡'
	case 0x83:
		return '…'
	case 0x84:
		return '—'
	case 0x85:
		return '–'
	case 0x86:
		return 'ƒ'
	case 0x87:
		return '⁄'
	case 0x88:
		return '‹'
	case 0x89:
		return '›'
	case 0x8A:
		return '−'
	case 0x8B:
		return '‰'
	case 0x8C:
		return '„'
	case 0x8D:
		return '“'
	case 0x8E:
		return '”'
	case 0x8F:
		return '‘'
	case 0x90:
		return '’'
	case 0x91:
		return '‚'
	case 0x92:
		return '™'
	case 0x93:
		return 'ﬁ'
	case 0x94:
		return 'ﬂ'
	case 0x95:
		return 'Ł'
	case 0x96:
		return 'Œ'
	case 0x97:
		return 'Š'
	case 0x98:
		return 'Ÿ'
	case 0x99:
		return 'Ž'
	case 0x9A:
		return 'ı'
	case 0x9B:
		return 'ł'
	case 0x9C:
		return 'œ'
	case 0x9D:
		return 'š'
	case 0x9E:
		return 'ž'
	case 0xA0:
		return '€'
	}
	return rune(b)
}

// TextPair is one named text field, used for unknown information keys and XMP
// properties.
type TextPair struct {
	Name  string
	Value string
}

// Info is the document information dictionary.
type Info struct {
	Title        *string
	Author       *string
	Subject      *string
	Keywords     *string
	Creator      *string
	Producer     *string
	Trapped      *string
	CreationDate *Date
	ModifiedDate *Date
	// Other holds keys this reader does not name, decoded as text, in sorted
	// key order and bounded to 64 entries.
	Other []TextPair
}

// Encryption is the encryption dictionary as the file records it.
type Encryption struct {
	// Filter is /Filter, usually `Standard`.
	Filter          *string
	Version         *int64
	Revision        *int64
	LengthBits      *int64
	Permissions     *int64
	EncryptMetadata *bool
	// OwnerEntryBytes is the length of the /O entry in bytes (a password
	// verifier, never shown; 32 at revisions 2–4, 48 at revisions 5–6).
	OwnerEntryBytes *int
	// UserEntryBytes is the length of the /U entry.
	UserEntryBytes *int
	// CryptFilters names the crypt filters declared under /CF.
	CryptFilters []string
	// CryptMethod is the method of the first crypt filter (V2, AESV2, AESV3,
	// None).
	CryptMethod  *string
	StreamFilter *string
	StringFilter *string
}

// Action is one action found in the catalog or a name tree.
type Action struct {
	// Kind is /S, or `Destination` for a bare destination array.
	Kind string
	// Event is the event a /AA entry names (WC, DO, Open…).
	Event  *string
	Script *string
	URI    *string
	File   *string
	// Target is /D rendered as `page N`, a named destination, or `object N`.
	Target *string
}

// PagesFacts describes the page tree. Declared is the root /Count; Counted is
// the number of leaves this reader actually walked, which is the stronger
// number. Objects lists the page object numbers of the leaves.
type PagesFacts struct {
	Declared *uint32
	Counted  uint32
	Depth    uint32
	Nodes    uint32
	Objects  []uint32
}

// AcroForm describes an interactive form.
type AcroForm struct {
	XFA              bool
	Fields           int
	SignatureFields  int
	SigFlags         *int64
	NeedsAppearances *bool
}

// CatalogFacts holds catalog facts beyond the page tree.
type CatalogFacts struct {
	Pages            PagesFacts
	OpenAction       *Action
	Actions          []Action
	Lang             *string
	PageMode         *string
	PageLayout       *string
	Outlines         *int64
	AcroForm         *AcroForm
	HasNames         bool
	EmbeddedFileTree bool
	JavaScriptTree   bool
}

// EmbeddedFile is one file attached to the document.
type EmbeddedFile struct {
	// Name is the name the name tree gives the file.
	Name         string
	Filename     *string
	Description  *string
	Subtype      *string
	Size         *int64
	CreationDate *Date
	ModifiedDate *Date
	// Checksum is /Params /CheckSum as hex, when present.
	Checksum *string
	// SHA256 is the SHA-256 of the decoded content, when the content could be
	// read.
	SHA256 *string
	// Bytes is the decoded byte count hashed.
	Bytes   *int
	Filters []string
	// Note says why the content was not read, when it was not.
	Note *string

	streamNumber uint32
	hasStream    bool
}

// Metadata is XMP metadata, decoded and lightly indexed.
type Metadata struct {
	Bytes int
	// Text is the packet text, bounded by Limits.MaxTextBytes.
	Text string
	// Fields holds well-known properties found by local name, in document
	// order.
	Fields []TextPair
}

// SectionFacts is one cross-reference section in the update history.
type SectionFacts struct {
	Kind    string
	Start   uint64
	Entries int
	Hybrid  *uint64
}

// TrailerFacts holds trailer and cross-reference facts.
type TrailerFacts struct {
	Size      *int64
	Root      *Reference
	Info      *Reference
	Encrypted bool
	// IDs holds /ID strings as hex.
	IDs      []string
	Updates  int
	Repaired bool
	// Sections holds `table` or `stream`, newest section first.
	Sections []string
	// History holds the same sections with their offsets and entry counts.
	History           []SectionFacts
	Entries           int
	CompressedEntries int
}

// ObjectKind is what an xref entry describes.
type ObjectKind uint8

const (
	// ObjectFree is a free slot.
	ObjectFree ObjectKind = iota
	// ObjectInFile is an object written directly in the file.
	ObjectInFile
	// ObjectInStream is an object stored inside an object stream.
	ObjectInStream
)

// ObjectInfo describes one object the cross-reference table names.
type ObjectInfo struct {
	Number     uint32
	Kind       ObjectKind
	Offset     uint64
	Generation uint16
	Stream     uint32
	Index      uint32
}

// Stats is a point-in-time snapshot of the reader's work.
type Stats struct {
	ObjectsLoaded       int
	ObjectStreams       int
	StreamsDecoded      int
	DecodedBytes        uint64
	EmbeddedBytesHashed uint64
	XrefEntries         int
	XrefSections        int
	Repaired            bool
	Notes               int
}

// Document is a parsed PDF document.
type Document struct {
	FileSize uint64
	// HeaderVersion is the version in the `%PDF-` header.
	HeaderVersion string
	// Version is the effective version: the catalog /Version when it names one.
	Version        string
	CatalogVersion *string
	Linearized     bool
	Encrypted      *Encryption
	InfoFacts      Info
	Trailer        TrailerFacts
	Catalog        CatalogFacts
	EmbeddedFiles  []EmbeddedFile
	Metadata       *Metadata

	src    source.ByteSource
	xref   *Xref
	limits Limits
	loader *loader
	notes  []string
	mu     sync.Mutex
}

// MatchesSignature reports whether head contains a PDF header in the first
// MaxHeaderScan bytes. The header may follow leading junk, as the format
// permits.
func MatchesSignature(head []byte) bool {
	if len(head) > int(MaxHeaderScan) {
		head = head[:MaxHeaderScan]
	}
	return strings.Contains(string(head), "%PDF-")
}

// Open reads a PDF from a byte source and returns its facts.
//
// Encrypted documents are named but not decoded. OpenWithPassword offers a
// password and decrypts the strings and streams this reader supports.
func Open(src source.ByteSource, limits Limits) (*Document, error) {
	return readDocument(src, limits, nil, false)
}

// OpenWithPassword opens a PDF and, when it is encrypted, offers password as
// the user password.
//
// A verified password decrypts strings and stream bodies for the Standard
// security handler V1/V2/V4/V5 at revisions 2–6. A missing, wrong or
// unsupported password leaves the document opaque exactly as Open does, with a
// named note; only a malformed file or an unsupported structural feature fails.
func OpenWithPassword(src source.ByteSource, limits Limits, password []byte) (*Document, error) {
	return readDocument(src, limits, password, true)
}

func readDocument(src source.ByteSource, limits Limits, password []byte, provided bool) (*Document, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	limits = limits.normalized()
	length := src.Len()
	if length == 0 {
		return nil, corrupt(0, "PDF file is empty")
	}
	headLength := length
	if headLength > MaxHeaderScan {
		headLength = MaxHeaderScan
	}
	head, err := readSource(src, 0, headLength)
	if err != nil {
		return nil, err
	}
	headerVersion, ok := parseHeaderVersion(head)
	if !ok {
		return nil, corrupt(0, "no %%PDF- version header in the first %d bytes", headLength)
	}
	linearized := strings.Contains(string(head), "/Linearized")

	xref, err := ReadXrefWithRepair(src, limits.Xref)
	if err != nil {
		return nil, err
	}
	var notes []string
	notes = append(notes, xref.Notes...)
	l := newLoader(src, xref, limits)

	var encryption *Encryption
	if encryptValue, ok := xref.Trailer.Get([]byte("Encrypt")); ok {
		if dict, err := l.dictOf(encryptValue); err != nil {
			notes = append(notes, "trailer /Encrypt could not be read: "+err.Error())
		} else if dict == nil {
			notes = append(notes, "trailer /Encrypt does not name a dictionary")
		} else {
			var id0 []byte
			if ids, ok := xref.Trailer.GetArray([]byte("ID")); ok && len(ids) > 0 {
				if value, ok := ids[0].AsString(); ok {
					id0 = append([]byte(nil), value...)
				}
			}
			params := encryptParamsFromDict(dict, id0)
			l.installDecryption(params, password, provided)
			encryption = encryptionFromDict(dict)
		}
	}
	if l.encrypted {
		l.noteOnce("document is encrypted; strings and streams were not decoded")
	}

	trailer := trailerFacts(xref, encryption != nil)

	var info Info
	if infoValue, ok := xref.Trailer.Get([]byte("Info")); ok {
		if dict, err := l.dictOf(infoValue); err != nil {
			notes = append(notes, "/Info could not be read: "+err.Error())
		} else if dict == nil {
			notes = append(notes, "/Info does not point at a dictionary")
		} else if read, err := l.infoFacts(dict); err != nil {
			notes = append(notes, "information dictionary: "+err.Error())
		} else {
			info = read
		}
	}

	var catalog CatalogFacts
	var catalogVersion *string
	var catalogDict *Dict
	if root, ok := xref.Root(); ok {
		dict, err := l.dictObject(root.Number)
		if err != nil {
			notes = append(notes, "catalog object could not be read: "+err.Error())
		} else if dict != nil {
			catalogDict = dict
			if name, ok := dict.GetName([]byte("Version")); ok {
				value := lossyUTF8(name)
				catalogVersion = &value
			}
			if lang, err := l.textEntry(dict, []byte("Lang")); err == nil {
				catalog.Lang = lang
			}
			if name, ok := dict.GetName([]byte("PageMode")); ok {
				value := lossyUTF8(name)
				catalog.PageMode = &value
			}
			if name, ok := dict.GetName([]byte("PageLayout")); ok {
				value := lossyUTF8(name)
				catalog.PageLayout = &value
			}
			_, catalog.HasNames = dict.Get([]byte("Names"))
			if outline, err := l.dictEntry(dict, []byte("Outlines")); err == nil && outline != nil {
				if count, ok := outline.GetInt([]byte("Count")); ok {
					value := count
					catalog.Outlines = &value
				}
			}
			if form, err := l.dictEntry(dict, []byte("AcroForm")); err == nil && form != nil {
				if facts, err := l.acroFormFacts(form); err == nil {
					catalog.AcroForm = facts
				}
			}
			if pages, ok := dict.Get([]byte("Pages")); ok {
				if facts, err := l.pageFacts(pages); err == nil {
					catalog.Pages = facts
				}
			}
			if action, ok := dict.Get([]byte("OpenAction")); ok {
				catalog.OpenAction, _ = l.openAction(action)
			}
			if aaValue, ok := dict.Get([]byte("AA")); ok {
				if aa, err := l.dictOf(aaValue); err == nil && aa != nil {
					catalog.Actions = l.additionalActions(aa)
				}
			}
			if names, err := l.dictEntry(dict, []byte("Names")); err == nil && names != nil {
				if javascript, ok := names.Get([]byte("JavaScript")); ok {
					catalog.JavaScriptTree = true
					entries, err := l.nameTree(javascript, limits.MaxNameTreeEntries)
					if err != nil {
						notes = append(notes, "JavaScript name tree: "+err.Error())
					} else {
						for _, entry := range entries {
							if len(catalog.Actions) >= MaxActions {
								break
							}
							name := entry.Name
							if actions, err := l.actionList(entry.Value, &name); err == nil {
								catalog.Actions = append(catalog.Actions, actions...)
							}
						}
					}
				}
			}
		}
	} else {
		notes = append(notes, "trailer has no /Root catalog reference")
	}

	var embeddedFiles []EmbeddedFile
	if catalogDict != nil {
		if names, err := l.dictEntry(catalogDict, []byte("Names")); err == nil && names != nil {
			if files, ok := names.Get([]byte("EmbeddedFiles")); ok {
				catalog.EmbeddedFileTree = true
				entries, err := l.nameTree(files, limits.MaxEmbeddedFiles)
				if err != nil {
					notes = append(notes, "embedded file name tree: "+err.Error())
				} else {
					for _, entry := range entries {
						file, err := l.embeddedFile(entry.Name, entry.Value)
						if err != nil {
							notes = append(notes, "embedded file could not be read: "+err.Error())
							continue
						}
						embeddedFiles = append(embeddedFiles, file)
					}
				}
			}
		}
	}

	var metadata *Metadata
	if catalogDict != nil {
		if value, ok := catalogDict.Get([]byte("Metadata")); ok {
			bytesValue, _, isStream, err := l.decodedStreamOf(value)
			switch {
			case err != nil:
				notes = append(notes, "XMP metadata: "+err.Error())
			case !isStream:
				notes = append(notes, "/Metadata is not a stream")
			default:
				text := lossyUTF8(bytesValue)
				if len(text) > limits.MaxTextBytes {
					text = text[:charBoundary(text, limits.MaxTextBytes)]
					notes = append(notes, sprintf("XMP packet truncated to %d bytes", limits.MaxTextBytes))
				}
				metadata = &Metadata{Bytes: len(bytesValue), Text: text, Fields: xmpFields(text)}
			}
		}
	}

	l.decryptionSummary()
	if xrefEntries := len(xref.Entries); xrefEntries > limits.MaxObjects {
		notes = append(notes, sprintf("object table has %d entries; Objects() lists the first %d", xrefEntries, limits.MaxObjects))
	}

	version := headerVersion
	if catalogVersion != nil {
		version = *catalogVersion
	}
	document := &Document{
		FileSize:       length,
		HeaderVersion:  headerVersion,
		Version:        version,
		CatalogVersion: catalogVersion,
		Linearized:     linearized,
		Encrypted:      encryption,
		InfoFacts:      info,
		Trailer:        trailer,
		Catalog:        catalog,
		EmbeddedFiles:  embeddedFiles,
		Metadata:       metadata,
		src:            src,
		xref:           xref,
		limits:         limits,
		loader:         l,
		notes:          notes,
	}
	// Notes gathered while reading the graph are now owned by the document;
	// clearing the loader's list keeps Notes from repeating them.
	document.notes = append(document.notes, l.notes...)
	l.notes = nil
	return document, nil
}

func parseHeaderVersion(head []byte) (string, bool) {
	position := strings.Index(string(head), "%PDF-")
	if position < 0 {
		return "", false
	}
	rest := head[position+5:]
	end := 0
	for end < len(rest) && ((rest[end] >= '0' && rest[end] <= '9') || rest[end] == '.') {
		end++
	}
	text := string(rest[:end])
	major, minor, found := strings.Cut(text, ".")
	if !found || major == "" || len(major) > 2 || minor == "" || len(minor) > 2 {
		return "", false
	}
	return text, true
}

func charBoundary(text string, limit int) int {
	if limit >= len(text) {
		return len(text)
	}
	if limit < 0 {
		return 0
	}
	end := limit
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return end
}

func trailerFacts(xref *Xref, encrypted bool) TrailerFacts {
	var ids []string
	if values, ok := xref.Trailer.GetArray([]byte("ID")); ok {
		for _, value := range values {
			if bytesValue, ok := value.AsString(); ok {
				ids = append(ids, hex.EncodeToString(bytesValue))
			}
		}
	}
	compressed := 0
	for _, entry := range xref.Entries {
		if entry.Kind == EntryInStream {
			compressed++
		}
	}
	facts := TrailerFacts{
		Encrypted:         encrypted,
		IDs:               ids,
		Updates:           xref.Updates,
		Repaired:          xref.Repaired,
		Entries:           len(xref.Entries),
		CompressedEntries: compressed,
	}
	if size, ok := xref.Trailer.GetInt([]byte("Size")); ok {
		facts.Size = &size
	}
	if root, ok := xref.Root(); ok {
		facts.Root = &root
	}
	if info, ok := xref.InfoRef(); ok {
		facts.Info = &info
	}
	for _, section := range xref.Sections {
		facts.Sections = append(facts.Sections, section.Kind.Label())
		sectionFacts := SectionFacts{Kind: section.Kind.Label(), Start: section.Start, Entries: len(section.Entries)}
		if section.Hybrid != nil {
			offset := *section.Hybrid
			sectionFacts.Hybrid = &offset
		}
		facts.History = append(facts.History, sectionFacts)
	}
	return facts
}

func encryptionFromDict(dict *Dict) *Encryption {
	out := &Encryption{}
	if name, ok := dict.GetName([]byte("Filter")); ok {
		value := lossyUTF8(name)
		out.Filter = &value
	}
	if value, ok := dict.GetInt([]byte("V")); ok {
		out.Version = &value
	}
	if value, ok := dict.GetInt([]byte("R")); ok {
		out.Revision = &value
	}
	if value, ok := dict.GetInt([]byte("Length")); ok {
		out.LengthBits = &value
	}
	if value, ok := dict.GetInt([]byte("P")); ok {
		out.Permissions = &value
	}
	if value, ok := dict.GetBool([]byte("EncryptMetadata")); ok {
		out.EncryptMetadata = &value
	}
	if value, ok := dict.Get([]byte("O")); ok {
		if bytesValue, ok := value.AsString(); ok {
			length := len(bytesValue)
			out.OwnerEntryBytes = &length
		}
	}
	if value, ok := dict.Get([]byte("U")); ok {
		if bytesValue, ok := value.AsString(); ok {
			length := len(bytesValue)
			out.UserEntryBytes = &length
		}
	}
	if filters, ok := dict.GetDict([]byte("CF")); ok {
		for _, item := range filters.Items() {
			out.CryptFilters = append(out.CryptFilters, string(item.Key))
			if out.CryptMethod == nil {
				if filter, ok := item.Value.AsDict(); ok {
					if name, ok := filter.GetName([]byte("CFM")); ok {
						value := lossyUTF8(name)
						out.CryptMethod = &value
					}
				}
			}
		}
	}
	if name, ok := dict.GetName([]byte("StmF")); ok {
		value := lossyUTF8(name)
		out.StreamFilter = &value
	}
	if name, ok := dict.GetName([]byte("StrF")); ok {
		value := lossyUTF8(name)
		out.StringFilter = &value
	}
	return out
}

// Info returns the document information dictionary facts.
func (d *Document) Info() *Info { return &d.InfoFacts }

// Pages returns the page-tree facts.
func (d *Document) Pages() PagesFacts { return d.Catalog.Pages }

// Attachments returns a copy of the embedded file list.
func (d *Document) Attachments() []EmbeddedFile {
	return append([]EmbeddedFile(nil), d.EmbeddedFiles...)
}

// Source returns the byte source the document was read from.
func (d *Document) Source() source.ByteSource { return d.src }

// Notes returns the reader's notes: decisions, refusals and later object-load
// observations. The slice is a copy.
func (d *Document) Notes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := append([]string(nil), d.notes...)
	if d.loader != nil {
		out = append(out, d.loader.notes...)
	}
	return out
}

// Objects lists the objects the cross-reference table names, sorted by object
// number and capped at Limits.MaxObjects. It does not load object bodies.
func (d *Document) Objects() []ObjectInfo {
	numbers := make([]uint32, 0, len(d.xref.Entries))
	for number := range d.xref.Entries {
		numbers = append(numbers, number)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	if len(numbers) > d.limits.MaxObjects {
		numbers = numbers[:d.limits.MaxObjects]
	}
	out := make([]ObjectInfo, 0, len(numbers))
	for _, number := range numbers {
		entry := d.xref.Entries[number]
		info := ObjectInfo{Number: number}
		switch entry.Kind {
		case EntryFree:
			info.Kind = ObjectFree
			info.Generation = entry.Generation
		case EntryInFile:
			info.Kind = ObjectInFile
			info.Offset = entry.Offset
			info.Generation = entry.Generation
		case EntryInStream:
			info.Kind = ObjectInStream
			info.Stream = entry.Stream
			info.Index = entry.Index
		}
		out = append(out, info)
	}
	return out
}

// Object loads one indirect object by number. ok is false for a free or absent
// object. When the document is encrypted and no password was accepted, string
// values are ciphertext; StringsOpaque reports that condition, and Info and
// the notes name it. Stream bodies are never returned as content.
func (d *Document) Object(number uint32) (Value, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loader.object(number)
}

// StringsOpaque reports whether string values cannot be decoded as text: the
// document is encrypted without an accepted password, or a string crypt filter
// is unsupported.
func (d *Document) StringsOpaque() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loader.stringsOpaque()
}

// StreamsOpaque reports whether stream bodies cannot be decoded: the document
// is encrypted without an accepted password, or a stream crypt filter is
// unsupported.
func (d *Document) StreamsOpaque() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loader.streamsOpaque()
}

// Resolve follows an indirect reference. wasReference reports whether value
// was a reference; a free or absent target resolves to null.
func (d *Document) Resolve(value Value) (Value, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	resolved, _, wasReference, err := d.loader.deref(value)
	return resolved, wasReference, err
}

// Stats returns a point-in-time snapshot of the reader's work.
func (d *Document) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	stats := Stats{
		ObjectsLoaded:       d.loader.loaded,
		ObjectStreams:       len(d.loader.streams),
		XrefEntries:         len(d.xref.Entries),
		XrefSections:        len(d.xref.Sections),
		Repaired:            d.xref.Repaired,
		DecodedBytes:        d.loader.decodedBytes,
		StreamsDecoded:      d.loader.decodedStreams,
		EmbeddedBytesHashed: d.loader.hashedEmbeddedBytes,
	}
	stats.Notes = len(d.notes) + len(d.loader.notes)
	return stats
}

// sha256Hex returns the lowercase hexadecimal SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// --- XMP metadata -----------------------------------------------------------

const (
	xmpMaxNodes     = 500_000
	xmpMaxDepth     = 64
	xmpMaxTextBytes = 4 * 1024 * 1024
)

type xmpNode struct {
	name     string
	attrs    []xml.Attr
	text     strings.Builder
	children []*xmpNode
}

func xmpText(node *xmpNode) string { return strings.TrimSpace(node.text.String()) }

// parseXMP builds a small element tree. A malformed packet yields no tree,
// matching the reference reader's decision to report no fields rather than
// guess at partial XML.
func parseXMP(text string) *xmpNode {
	text = strings.TrimPrefix(text, "\uFEFF")
	decoder := xml.NewDecoder(strings.NewReader(text))
	var root *xmpNode
	var stack []*xmpNode
	nodes := 0
	textBytes := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil
		}
		switch t := token.(type) {
		case xml.StartElement:
			nodes++
			if nodes > xmpMaxNodes {
				return nil
			}
			if len(stack) > xmpMaxDepth {
				return nil
			}
			node := &xmpNode{name: t.Name.Local, attrs: append([]xml.Attr(nil), t.Attr...)}
			if len(stack) == 0 {
				if root != nil {
					return nil
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				trimmed := strings.TrimSpace(string(t))
				textBytes += len(trimmed)
				if textBytes > xmpMaxTextBytes {
					return nil
				}
				if trimmed != "" {
					stack[len(stack)-1].text.WriteString(trimmed)
				}
			}
		}
		if root != nil && len(stack) == 0 && token != nil {
			// The root element has closed; stop at the next token error or a
			// second root.
			next, err := decoder.Token()
			if err != nil {
				return root
			}
			switch next.(type) {
			case xml.StartElement:
				return nil
			default:
				return root
			}
		}
	}
}

func xmpFields(text string) []TextPair {
	root := parseXMP(text)
	if root == nil {
		return nil
	}
	names := []string{
		"title", "creator", "description", "Producer", "CreatorTool",
		"CreateDate", "ModifyDate", "MetadataDate", "DocumentID",
		"InstanceID", "Keywords", "format", "Language",
	}
	var fields []TextPair
	for _, name := range names {
		if value, ok := xmpProperty(root, name); ok {
			fields = append(fields, TextPair{Name: name, Value: value})
		}
	}
	return fields
}

// xmpProperty finds a property by local name, preferring an element and
// falling back to an attribute.
func xmpProperty(root *xmpNode, name string) (string, bool) {
	if element := findXMPElement(root, name); element != nil {
		if items := listItems(element); len(items) > 0 {
			return strings.Join(items, "; "), true
		}
		if text := xmpText(element); text != "" {
			return text, true
		}
		if value, ok := findXMPAttribute(element, name); ok {
			return value, true
		}
	}
	return findXMPAttribute(root, name)
}

func findXMPElement(element *xmpNode, name string) *xmpNode {
	if element.name == name {
		return element
	}
	for _, child := range element.children {
		if found := findXMPElement(child, name); found != nil {
			return found
		}
	}
	return nil
}

func listItems(element *xmpNode) []string {
	var out []string
	collectListItems(element, &out)
	return out
}

func collectListItems(element *xmpNode, out *[]string) {
	for _, child := range element.children {
		if child.name == "li" {
			if text := xmpText(child); text != "" {
				*out = append(*out, text)
			}
		}
		collectListItems(child, out)
	}
}

func findXMPAttribute(element *xmpNode, name string) (string, bool) {
	for _, attr := range element.attrs {
		if attr.Name.Local == name && attr.Value != "" {
			return attr.Value, true
		}
	}
	for _, child := range element.children {
		if value, ok := findXMPAttribute(child, name); ok {
			return value, true
		}
	}
	return "", false
}

// --- civil date arithmetic --------------------------------------------------

func unixSecondsFromCivil(year int64, month, day, hour, minute, second int) (int64, bool) {
	if month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) {
		return 0, false
	}
	if hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}
	days := daysFromCivil(year, month, day)
	return days*86_400 + int64(hour)*3600 + int64(minute)*60 + int64(second), true
}

func daysInMonth(year int64, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeapYear(year) {
			return 29
		}
		return 28
	}
	return 0
}

func isLeapYear(year int64) bool {
	return (year%4 == 0 && year%100 != 0) || year%400 == 0
}

// daysFromCivil converts a proleptic Gregorian date to days since 1970-01-01
// (Howard Hinnant's algorithm).
func daysFromCivil(year int64, month, day int) int64 {
	if month <= 2 {
		year--
	}
	era := year
	if year < 0 {
		era = (year - 399) / 400
	} else {
		era = year / 400
	}
	yoe := year - era*400
	m := int64(month)
	marchMonth := m - 3
	if m <= 2 {
		marchMonth = m + 9
	}
	doy := (153*marchMonth+2)/5 + int64(day) - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146_097 + doe - 719_468
}
