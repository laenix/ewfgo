// Package ooxml reads Office Open XML packages (.docx, .xlsx, .pptx, and
// their macro-enabled and template forms).
//
// An OOXML file is an OPC package: a ZIP archive whose parts are XML.  The
// document body is not read here; this reader reports the package facts an
// investigation uses to attribute a document without rendering it:
//
//   - docProps/core.xml — title, author, last modified by, revision, and the
//     W3CDTF created/modified/last-printed times;
//   - docProps/app.xml — the writing application, company, manager, template
//     path, editing time, and page/word/slide counters the application wrote;
//   - docProps/custom.xml — named custom properties with their value type;
//   - xl/workbook.xml — sheet names, their visibility state, and defined
//     names (including print areas and external references);
//   - ppt/presentation.xml — the slide count;
//   - every *_rels/*.rels part — relationships whose TargetMode is External,
//     which is where a remote template or data source is recorded;
//   - */embeddings/* members, VBA macro projects, and package signatures,
//     reported by name rather than extracted.
//
// The relationship targets and template paths are claims made by the file's
// author.  They are reported verbatim and never fetched or resolved.
//
// Limits are part of the contract: metadata parts over [Limits.MaxPartBytes]
// are named and skipped instead of expanded, strings are capped at
// [MaxTextChars], and every skipped part becomes a warning so a report cannot
// mistake absence for emptiness.  An encrypted part is named and skipped.
//
// The ZIP listing is the archive framework's reader, so member names are
// sanitized with archive.SanitizeEntryPath before this package sees them; a
// package with an unsafe member name is refused with source.ErrCorrupt.
//
// This is a Go port of forensic-core's data/containers/ooxml.rs.  Every
// functional branch of the reference reader is ported.  Three implementation
// notes: XML is parsed with encoding/xml (which resolves namespace prefixes
// before this reader sees them, so element and attribute names are matched on
// their local name, as the reference's own local-name matcher does); the
// caller's MaxPartBytes bounds [Content_Types].xml as well, where the reference
// uses its default limit while looking for a fallback main part; and
// character-reference validation is encoding/xml's (it rejects NUL and U+FFFF
// and substitutes U+FFFD for a surrogate reference, where the reference's
// minimal reader accepts or refuses different malformed documents).  The
// difference affects only malformed XML, which is reported as an unreadable
// part either way; no well-formed metadata claim is changed.
package ooxml

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/containers/archive/zip"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// DefaultMaxPartBytes is the largest metadata part this reader will
	// decompress.  These parts are small by construction; the limit only stops
	// a decompression bomb.
	DefaultMaxPartBytes uint64 = 8 * 1024 * 1024
	// MaxRelationshipParts is the most relationship parts inspected in one
	// package.
	MaxRelationshipParts = 256
	// MaxRelationships is the most external relationships reported from one
	// package.
	MaxRelationships = 4096
	// MaxCustomProperties is the most custom properties reported from one
	// package.
	MaxCustomProperties = 1024
	// MaxEmbedded is the most embedded objects reported from one package.
	MaxEmbedded = 4096
	// MaxSignatures is the most signature parts reported from one package.
	MaxSignatures = 256
	// MaxTextChars is the longest string reported from one property, in
	// characters.
	MaxTextChars = 4096

	// MaxXMLElements bounds the element count of one XML part.
	MaxXMLElements = 500_000
	// MaxXMLDepth is the deepest XML nesting this reader follows.
	MaxXMLDepth = 64
	// MaxXMLTextBytes is the largest direct text one element may accumulate.
	MaxXMLTextBytes = 4 * 1024 * 1024
)

// Limits are the resource bounds for one package.  A zero (or negative) field
// takes the corresponding default.
type Limits struct {
	// MaxPartBytes is the largest metadata part decompressed.
	MaxPartBytes uint64
	// MaxXMLElements bounds the element count of one part.
	MaxXMLElements int
	// MaxXMLDepth is the deepest XML nesting followed.
	MaxXMLDepth int
	// MaxXMLTextBytes is the largest direct text one element may accumulate.
	MaxXMLTextBytes int
}

// DefaultLimits returns the documented defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxPartBytes:    DefaultMaxPartBytes,
		MaxXMLElements:  MaxXMLElements,
		MaxXMLDepth:     MaxXMLDepth,
		MaxXMLTextBytes: MaxXMLTextBytes,
	}
}

func (l Limits) normalized() Limits {
	defaults := DefaultLimits()
	if l.MaxPartBytes == 0 {
		l.MaxPartBytes = defaults.MaxPartBytes
	}
	if l.MaxXMLElements <= 0 {
		l.MaxXMLElements = defaults.MaxXMLElements
	}
	if l.MaxXMLDepth <= 0 {
		l.MaxXMLDepth = defaults.MaxXMLDepth
	}
	if l.MaxXMLTextBytes <= 0 {
		l.MaxXMLTextBytes = defaults.MaxXMLTextBytes
	}
	return l
}

// Kind is the application family that wrote the package.
type Kind uint8

const (
	// KindOther is a package with a main part this reader does not decode
	// (Visio, for example).  Core package metadata is still reported.  It is
	// the zero value, matching the reference's default kind.
	KindOther Kind = iota
	// KindWord is a word-processing package.
	KindWord
	// KindExcel is a spreadsheet package.
	KindExcel
	// KindPresentation is a presentation package.
	KindPresentation
)

// Label returns the human-readable family name.
func (k Kind) Label() string {
	switch k {
	case KindWord:
		return "word processing"
	case KindExcel:
		return "spreadsheet"
	case KindPresentation:
		return "presentation"
	default:
		return "other"
	}
}

// String returns the label, so the kind prints readably in reports.
func (k Kind) String() string { return k.Label() }

// Time is a W3CDTF timestamp as stored, with its parsed value when the text is
// a valid RFC 3339 instant.
//
// The reference stores nanoseconds since the epoch in an i128 so that every
// four-digit year fits.  This port keeps the instant as seconds plus a
// sub-second nanosecond count, which has the same range; [Time.UnixNano]
// reports whether the combined value also fits an int64.
type Time struct {
	// Text is the stored text, verbatim.
	Text string
	// UnixSeconds is seconds since the Unix epoch, when Text parsed; nil
	// otherwise.
	UnixSeconds *int64
	// Nanos is the sub-second component, in [0, 999999999].
	Nanos int32
}

// Parsed reports whether the text was a valid RFC 3339 instant.
func (t Time) Parsed() bool { return t.UnixSeconds != nil }

// UnixNano returns the instant in nanoseconds since the epoch, when it fits an
// int64.  Four-digit years beyond 2262 do not.
func (t Time) UnixNano() (int64, bool) {
	if t.UnixSeconds == nil {
		return 0, false
	}
	seconds := *t.UnixSeconds
	nanos := int64(t.Nanos)
	// floor(MaxInt64/1e9) and its remainder.
	const maxSeconds = int64(9223372036)
	const maxRemainder = int64(854775807)
	if seconds > maxSeconds || seconds < -maxSeconds {
		return 0, false
	}
	if seconds == maxSeconds && nanos > maxRemainder {
		return 0, false
	}
	return seconds*1_000_000_000 + nanos, true
}

// CoreProperties is docProps/core.xml.
type CoreProperties struct {
	Title          *string
	Subject        *string
	Creator        *string
	Keywords       *string
	Description    *string
	LastModifiedBy *string
	Revision       *string
	Category       *string
	ContentStatus  *string
	Identifier     *string
	Language       *string
	Version        *string
	Created        *Time
	Modified       *Time
	LastPrinted    *Time
}

// AppProperties is docProps/app.xml.
type AppProperties struct {
	Application *string
	AppVersion  *string
	Company     *string
	Manager     *string
	// Template is the template path the application recorded.  It may name a
	// user path or a remote address, which is why it is kept verbatim.
	Template           *string
	TotalTimeMinutes   *uint32
	Pages              *uint32
	Words              *uint32
	Characters         *uint32
	Lines              *uint32
	Paragraphs         *uint32
	Slides             *uint32
	Notes              *uint32
	HiddenSlides       *uint32
	PresentationFormat *string
	DocSecurity        *uint32
	ScaleCrop          *bool
	LinksUpToDate      *bool
	SharedDoc          *bool
	HyperlinksChanged  *bool
}

// CustomProperty is one docProps/custom.xml property.
type CustomProperty struct {
	Name  string
	FmtID *string
	PID   *int64
	// ValueType is the value element's local name, for example "lpwstr" or
	// "filetime".
	ValueType *string
	Value     string
}

// Sheet is one xl/workbook.xml sheet.
type Sheet struct {
	Name string
	// SheetID is the stored sheetId.
	SheetID *uint32
	// RelationshipID is the r:id relationship identifier; it is not resolved
	// to a target here.
	RelationshipID *string
	// State is "visible", "hidden", "veryHidden", or the stored value.
	State *string
}

// IsHidden reports whether the sheet is hidden or very hidden.
func (s Sheet) IsHidden() bool {
	return s.State != nil && (*s.State == "hidden" || *s.State == "veryHidden")
}

// DefinedName is one xl/workbook.xml defined name.
type DefinedName struct {
	Name string
	// LocalSheetID is the zero-based sheet index the name is scoped to; nil
	// means the whole workbook.
	LocalSheetID *uint32
	Value        string
}

// ExternalRelationship is one relationship whose target is outside the
// package.
type ExternalRelationship struct {
	// Part is the .rels part that recorded the relationship.
	Part string
	ID   *string
	// Kind is the full relationship type URI.
	Kind string
	// Target is the stored target, verbatim.  It is never fetched or
	// resolved.
	Target string
}

// EmbeddedObject is one embedded object member, reported by name.
type EmbeddedObject struct {
	Path string
	Size uint64
}

// Document is a decoded OPC package.
type Document struct {
	Kind Kind
	// MainPart is the main part name, relative to the package root.
	MainPart string
	// MainContentType is the main part's content type, when
	// [Content_Types].xml names it.
	MainContentType *string
	Core            CoreProperties
	App             AppProperties
	Custom          []CustomProperty
	Sheets          []Sheet
	DefinedNames    []DefinedName
	SlideCount      *int
	// ExternalRelationships records every external relationship found in the
	// relationship parts that were read.
	ExternalRelationships []ExternalRelationship
	Embedded              []EmbeddedObject
	// MacroParts holds VBA project members, by path.
	MacroParts []string
	// Signatures holds _xmlsignatures/ members, by path.
	Signatures []string
	// Warnings names every part that was skipped, encrypted, oversized or
	// unreadable, and every list that was capped.
	Warnings []string
}

// IsMacroEnabled reports whether a VBA project member was found.
func (d *Document) IsMacroEnabled() bool { return len(d.MacroParts) != 0 }

// Detect reports whether head begins with a ZIP signature.  OOXML packages are
// ZIP archives; this sniffs the container only, and [Open] decides whether the
// archive is an OOXML package.
func Detect(head []byte) bool {
	return bytes.HasPrefix(head, []byte("PK\x03\x04")) ||
		bytes.HasPrefix(head, []byte("PK\x05\x06"))
}

type indexedEntry struct {
	lower string
	entry archive.Entry
}

// Open reads one OPC package from a read-only source.
func Open(src source.ByteSource, limits Limits) (*Document, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	limits = limits.normalized()
	reader, err := zip.Open(src, archive.DefaultLimits())
	if err != nil {
		return nil, translateArchiveError(err)
	}
	entries, err := reader.Entries()
	if err != nil {
		return nil, translateArchiveError(err)
	}
	index := make([]indexedEntry, 0, len(entries))
	for _, entry := range entries {
		index = append(index, indexedEntry{lower: asciiLower(entry.Path), entry: entry})
	}

	warnings := make([]string, 0)
	mainPart, kind, mainContentType, err := detectMainPart(reader, index, limits, &warnings)
	if err != nil {
		return nil, err
	}
	document := &Document{
		Kind:            kind,
		MainPart:        mainPart,
		MainContentType: mainContentType,
	}

	if root := partXML(reader, index, "docProps/core.xml", limits, &warnings); root != nil {
		document.Core = coreProperties(root, &warnings)
	}
	if root := partXML(reader, index, "docProps/app.xml", limits, &warnings); root != nil {
		document.App = appProperties(root, &warnings)
	}
	if root := partXML(reader, index, "docProps/custom.xml", limits, &warnings); root != nil {
		document.Custom = customProperties(root, &warnings)
	}

	switch document.Kind {
	case KindExcel:
		if root := partXML(reader, index, "xl/workbook.xml", limits, &warnings); root != nil {
			document.Sheets = sheets(root, &warnings)
			document.DefinedNames = definedNames(root, &warnings)
		}
	case KindPresentation:
		if root := partXML(reader, index, "ppt/presentation.xml", limits, &warnings); root != nil {
			count := countLocal(root, "sldId")
			document.SlideCount = &count
		}
	case KindWord, KindOther:
	}

	for _, item := range index {
		if strings.Contains(item.lower, "/embeddings/") {
			if len(document.Embedded) == MaxEmbedded {
				warnings = append(warnings, fmt.Sprintf(
					"package embeds more than %d objects; the rest are not listed", MaxEmbedded))
				// The reference stops the whole scan here, so a macro or
				// signature member ordered after the cap is not reported.
				break
			}
			document.Embedded = append(document.Embedded, EmbeddedObject{
				Path: item.entry.Path,
				Size: item.entry.Size,
			})
		}
		if strings.HasSuffix(item.lower, "vbaproject.bin") {
			document.MacroParts = append(document.MacroParts, item.entry.Path)
		}
		if strings.HasPrefix(item.lower, "_xmlsignatures/") && len(document.Signatures) < MaxSignatures {
			document.Signatures = append(document.Signatures, item.entry.Path)
		}
	}

	parts := 0
	for _, item := range index {
		if !isRelationshipPart(item.lower) {
			continue
		}
		if parts == MaxRelationshipParts {
			warnings = append(warnings, fmt.Sprintf(
				"package has more than %d relationship parts; the rest are not read", MaxRelationshipParts))
			break
		}
		parts++
		root := partXML(reader, index, item.entry.Path, limits, &warnings)
		if root == nil {
			continue
		}
		externalRelationships(item.entry.Path, root, &document.ExternalRelationships, &warnings)
	}

	document.Warnings = warnings
	return document, nil
}

// asciiLower lowercases ASCII letters only, matching the reference's
// to_ascii_lowercase on package member names.
func asciiLower(text string) string {
	bytes := []byte(text)
	for index, value := range bytes {
		if value >= 'A' && value <= 'Z' {
			bytes[index] = value + ('a' - 'A')
		}
	}
	return string(bytes)
}

func isRelationshipPart(lower string) bool {
	return strings.HasSuffix(lower, ".rels") && strings.Contains(lower, "_rels/")
}

// detectMainPart finds the package's main part from its conventional name,
// falling back to the content-type manifest for packages this reader does not
// name.
func detectMainPart(reader *zip.Reader, index []indexedEntry, limits Limits, warnings *[]string) (string, Kind, *string, error) {
	for _, conventional := range []struct {
		lower string
		kind  Kind
	}{
		{"word/document.xml", KindWord},
		{"xl/workbook.xml", KindExcel},
		{"ppt/presentation.xml", KindPresentation},
	} {
		if entry, ok := findIndexed(index, conventional.lower); ok {
			contentType := contentTypeFor(reader, index, entry.entry.Path, limits, warnings)
			return entry.entry.Path, conventional.kind, contentType, nil
		}
	}

	root := partXML(reader, index, "[Content_Types].xml", limits, warnings)
	if root == nil {
		return "", KindOther, nil, unsupported("ZIP archive has no OOXML main part")
	}

	var fallback *string
	var fallbackPart string
	for _, override := range root.childrenNamed("Override") {
		partName, hasPart := override.attribute("PartName")
		contentType, hasType := override.attribute("ContentType")
		if !hasPart || !hasType {
			continue
		}
		trimmed := strings.TrimLeft(partName, "/")
		if kind, known := kindForContentType(contentType); known {
			value := contentType
			return trimmed, kind, &value, nil
		}
		if strings.HasSuffix(contentType, ".main+xml") && fallback == nil {
			value := contentType
			fallback = &value
			fallbackPart = trimmed
		}
	}
	if fallback != nil {
		return fallbackPart, KindOther, fallback, nil
	}
	return "", KindOther, nil, unsupported("ZIP archive has no OOXML main part")
}

func kindForContentType(contentType string) (Kind, bool) {
	switch {
	case strings.Contains(contentType, "wordprocessingml"):
		return KindWord, true
	case strings.Contains(contentType, "spreadsheetml"):
		return KindExcel, true
	case strings.Contains(contentType, "presentationml"):
		return KindPresentation, true
	default:
		return KindOther, false
	}
}

// contentTypeFor returns the content type the manifest gives the main part,
// when it names it.
func contentTypeFor(reader *zip.Reader, index []indexedEntry, part string, limits Limits, warnings *[]string) *string {
	root := partXML(reader, index, "[Content_Types].xml", limits, warnings)
	if root == nil {
		return nil
	}
	wanted := "/" + strings.TrimLeft(part, "/")
	for _, override := range root.childrenNamed("Override") {
		name, ok := override.attribute("PartName")
		if !ok || !strings.EqualFold(name, wanted) {
			continue
		}
		if contentType, ok := override.attribute("ContentType"); ok {
			value := contentType
			return &value
		}
		return nil
	}
	return nil
}

// partXML reads and parses one package part as XML.
func partXML(reader *zip.Reader, index []indexedEntry, path string, limits Limits, warnings *[]string) *element {
	item, ok := findIndexed(index, strings.ToLower(path))
	if !ok {
		return nil
	}
	entry := item.entry
	if entry.Encrypted {
		*warnings = append(*warnings, fmt.Sprintf("part %s is encrypted", entry.Path))
		return nil
	}
	if entry.Size > limits.MaxPartBytes {
		*warnings = append(*warnings, fmt.Sprintf(
			"part %s is %d bytes, above the %d-byte limit",
			entry.Path, entry.Size, limits.MaxPartBytes))
		return nil
	}
	part, err := reader.OpenEntry(entry.Path, 0)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("cannot open part %s: %v", entry.Path, err))
		return nil
	}
	data, err := source.ReadVecAt(part, 0, part.Len())
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("cannot read part %s: %v", entry.Path, err))
		return nil
	}
	root, err := parseXML(data, limits)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("part %s is not readable XML: %v", entry.Path, err))
		return nil
	}
	return root
}

func findIndexed(index []indexedEntry, lower string) (indexedEntry, bool) {
	for _, item := range index {
		if item.lower == lower {
			return item, true
		}
	}
	return indexedEntry{}, false
}

func coreProperties(root *element, warnings *[]string) CoreProperties {
	return CoreProperties{
		Title:          textProperty(root, "title", warnings),
		Subject:        textProperty(root, "subject", warnings),
		Creator:        textProperty(root, "creator", warnings),
		Keywords:       textProperty(root, "keywords", warnings),
		Description:    textProperty(root, "description", warnings),
		LastModifiedBy: textProperty(root, "lastModifiedBy", warnings),
		Revision:       textProperty(root, "revision", warnings),
		Category:       textProperty(root, "category", warnings),
		ContentStatus:  textProperty(root, "contentStatus", warnings),
		Identifier:     textProperty(root, "identifier", warnings),
		Language:       textProperty(root, "language", warnings),
		Version:        textProperty(root, "version", warnings),
		Created:        timeProperty(root, "created", warnings),
		Modified:       timeProperty(root, "modified", warnings),
		LastPrinted:    timeProperty(root, "lastPrinted", warnings),
	}
}

func appProperties(root *element, warnings *[]string) AppProperties {
	return AppProperties{
		Application:        textProperty(root, "Application", warnings),
		AppVersion:         textProperty(root, "AppVersion", warnings),
		Company:            textProperty(root, "Company", warnings),
		Manager:            textProperty(root, "Manager", warnings),
		Template:           textProperty(root, "Template", warnings),
		TotalTimeMinutes:   numberProperty(root, "TotalTime"),
		Pages:              numberProperty(root, "Pages"),
		Words:              numberProperty(root, "Words"),
		Characters:         numberProperty(root, "Characters"),
		Lines:              numberProperty(root, "Lines"),
		Paragraphs:         numberProperty(root, "Paragraphs"),
		Slides:             numberProperty(root, "Slides"),
		Notes:              numberProperty(root, "Notes"),
		HiddenSlides:       numberProperty(root, "HiddenSlides"),
		PresentationFormat: textProperty(root, "PresentationFormat", warnings),
		DocSecurity:        numberProperty(root, "DocSecurity"),
		ScaleCrop:          boolProperty(root, "ScaleCrop"),
		LinksUpToDate:      boolProperty(root, "LinksUpToDate"),
		SharedDoc:          boolProperty(root, "SharedDoc"),
		HyperlinksChanged:  boolProperty(root, "HyperlinksChanged"),
	}
}

func customProperties(root *element, warnings *[]string) []CustomProperty {
	properties := make([]CustomProperty, 0)
	for _, child := range root.childrenNamed("property") {
		if len(properties) == MaxCustomProperties {
			*warnings = append(*warnings, fmt.Sprintf(
				"package has more than %d custom properties; the rest are not listed", MaxCustomProperties))
			break
		}
		name := "unnamed"
		if stored, ok := child.attribute("name"); ok {
			name = capText(stored, warnings, "custom property name")
		}
		var valueType *string
		value := ""
		if len(child.children) > 0 {
			valueElement := child.children[0]
			local := valueElement.local
			valueType = &local
			value = capText(valueElement.text, warnings, "custom property value")
		}
		var fmtID *string
		if stored, ok := child.attribute("fmtid"); ok {
			fmtID = &stored
		}
		var pid *int64
		if stored, ok := child.attribute("pid"); ok {
			if parsed, err := strconv.ParseInt(stored, 10, 64); err == nil {
				pid = &parsed
			}
		}
		properties = append(properties, CustomProperty{
			Name:      name,
			FmtID:     fmtID,
			PID:       pid,
			ValueType: valueType,
			Value:     value,
		})
	}
	return properties
}

func sheets(root *element, warnings *[]string) []Sheet {
	list := root.childLocal("sheets")
	if list == nil {
		return nil
	}
	stored := make([]Sheet, 0)
	for _, child := range list.childrenNamed("sheet") {
		sheet := Sheet{}
		if name, ok := child.attribute("name"); ok {
			sheet.Name = capText(name, warnings, "sheet name")
		}
		if value, ok := child.attribute("sheetId"); ok {
			if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
				sheetID := uint32(parsed)
				sheet.SheetID = &sheetID
			}
		}
		if value, ok := child.attributeLocal("id"); ok {
			relationshipID := value
			sheet.RelationshipID = &relationshipID
		}
		if value, ok := child.attribute("state"); ok {
			state := value
			sheet.State = &state
		}
		stored = append(stored, sheet)
	}
	return stored
}

func definedNames(root *element, warnings *[]string) []DefinedName {
	list := root.childLocal("definedNames")
	if list == nil {
		return nil
	}
	stored := make([]DefinedName, 0)
	for _, child := range list.childrenNamed("definedName") {
		name := DefinedName{}
		if value, ok := child.attribute("name"); ok {
			name.Name = capText(value, warnings, "defined name")
		}
		if value, ok := child.attribute("localSheetId"); ok {
			if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
				sheetID := uint32(parsed)
				name.LocalSheetID = &sheetID
			}
		}
		name.Value = capText(child.text, warnings, "defined name value")
		stored = append(stored, name)
	}
	return stored
}

func externalRelationships(part string, root *element, out *[]ExternalRelationship, warnings *[]string) {
	for _, child := range root.childrenNamed("Relationship") {
		mode, ok := child.attribute("TargetMode")
		if !ok || !strings.EqualFold(mode, "External") {
			continue
		}
		if len(*out) == MaxRelationships {
			*warnings = append(*warnings, fmt.Sprintf(
				"package records more than %d external relationships; the rest are not listed", MaxRelationships))
			return
		}
		target, _ := child.attribute("Target")
		relationship := ExternalRelationship{
			Part:   part,
			Kind:   "",
			Target: capText(target, warnings, "relationship target"),
		}
		if value, ok := child.attribute("Id"); ok {
			identifier := value
			relationship.ID = &identifier
		}
		if value, ok := child.attribute("Type"); ok {
			relationship.Kind = value
		}
		*out = append(*out, relationship)
	}
}

// textProperty returns the direct text of the first child with this local
// name, when it is not empty.
func textProperty(root *element, name string, warnings *[]string) *string {
	child := root.childLocal(name)
	if child == nil || child.text == "" {
		return nil
	}
	text := capText(child.text, warnings, name)
	return &text
}

func timeProperty(root *element, name string, warnings *[]string) *Time {
	text := textProperty(root, name, warnings)
	if text == nil {
		return nil
	}
	return parseTime(*text)
}

func numberProperty(root *element, name string) *uint32 {
	child := root.childLocal(name)
	if child == nil {
		return nil
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(child.text), 10, 32)
	if err != nil {
		return nil
	}
	value := uint32(parsed)
	return &value
}

func boolProperty(root *element, name string) *bool {
	child := root.childLocal(name)
	if child == nil {
		return nil
	}
	switch strings.TrimSpace(child.text) {
	case "true", "1":
		value := true
		return &value
	case "false", "0":
		value := false
		return &value
	default:
		return nil
	}
}

// capText caps a property string, recording a warning when it was shortened.
func capText(text string, warnings *[]string, what string) string {
	if utf8.RuneCountInString(text) <= MaxTextChars {
		return text
	}
	*warnings = append(*warnings, fmt.Sprintf(
		"%s is longer than %d characters and was shortened", what, MaxTextChars))
	count := 0
	for index := range text {
		if count == MaxTextChars {
			return text[:index]
		}
		count++
	}
	return text
}

func translateArchiveError(err error) error {
	if err == nil {
		return nil
	}
	for _, sentinel := range []error{
		source.ErrOutOfRange, source.ErrUnexpectedEOF, source.ErrCorrupt,
		source.ErrIO, source.ErrUnsupported, source.ErrDecrypt,
		source.ErrCancelled, source.ErrInvalidArgument,
	} {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	switch {
	case errors.Is(err, archive.ErrUnsupported),
		errors.Is(err, archive.ErrEncrypted),
		errors.Is(err, archive.ErrLimit):
		return &source.Error{Kind: source.ErrUnsupported, Reason: err.Error()}
	case errors.Is(err, archive.ErrInvalid):
		return &source.Error{Kind: source.ErrCorrupt, Reason: err.Error()}
	default:
		return err
	}
}

func unsupported(reason string) *source.Error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}
