// Package aff4 reads AFF4 (Advanced Forensic Format 4) evidence containers.
//
// AFF4 is a ZIP container carrying a small set of metadata members —
// container.description (a version line), information.turtle (RDF/Turtle) or
// information.yaml (a line-oriented YAML descriptor) — plus image, map, zero
// and segment streams.  This package parses the metadata without guessing,
// enumerates every stream and the ZIP members that back it, and exposes any
// image, map, zero or ZipSegment stream as a read-only source.ByteSource.
//
// The container is read through the repository's ZIP reader
// (internal/data/containers/archive/zip); ZIP itself is not reimplemented.
// Physical image chunks are located through the 8-byte .index entries and
// decoded with the declared stored, zero or zlib method.  Map streams join
// their aff4:target and aff4:dependentStream targets in order through 12-byte
// entries.  A stream whose declared compressor has no pure-Go decoder here
// (snappy and lz4) is still enumerated, but opening it is refused with
// source.ErrUnsupported naming the codec; bytes are never silently skipped.
// AFF4-L FileImage resources are recognised and reported, but the logical
// layer is not assembled.
//
// Auto-detection is deliberately absent: AFF4 shares the ZIP magic, so a
// caller opens it explicitly.
package aff4

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/containers/archive/zip"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// ContainerDescription is the AFF4 version member written by every
	// container.
	ContainerDescription = "container.description"
	// InformationTurtle is the RDF/Turtle metadata member.
	InformationTurtle = "information.turtle"
	// InformationYAML is the line-oriented YAML metadata member.
	InformationYAML = "information.yaml"

	// Namespace is the AFF4 schema namespace.
	Namespace = "http://aff4.org/Schema#"
	// RDFType is the RDF type predicate expanded from Turtle's "a".
	RDFType = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"

	// indexEntryBytes is the size of one AFF4 image index entry.
	indexEntryBytes uint64 = 8
	// mapEntryBytes is the size of one AFF4 map entry.
	mapEntryBytes = 12
)

var (
	zipLocalSig = [4]byte{0x50, 0x4b, 0x03, 0x04}
	zipEOCDSig  = [4]byte{0x50, 0x4b, 0x05, 0x06}
	zipSpanned  = [4]byte{0x50, 0x4b, 0x07, 0x08}
)

// ErrLimit means a configured resource budget was exceeded.
var ErrLimit = errors.New("aff4: limit exceeded")

func limitf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLimit, fmt.Sprintf(format, args...))
}

func corruptf(format string, args ...any) error {
	return source.NewCorrupt(0, fmt.Sprintf(format, args...))
}

func unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrUnsupported, fmt.Sprintf(format, args...))
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", source.ErrInvalidArgument, fmt.Sprintf(format, args...))
}

// mapArchiveError translates the archive framework's error taxonomy into the
// source package's, so AFF4 callers only need to test one set of sentinels.
func mapArchiveError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, archive.ErrLimit):
		return fmt.Errorf("%w: %v", ErrLimit, err)
	case errors.Is(err, archive.ErrUnsupported), errors.Is(err, archive.ErrEncrypted):
		return fmt.Errorf("%w: %v", source.ErrUnsupported, err)
	default:
		return fmt.Errorf("%w: %v", source.ErrCorrupt, err)
	}
}

// Limits bounds the metadata and stream parsing of one AFF4 container.
//
// Defaults are generous for real evidence but stop decompression bombs,
// pathological Turtle, and chunk geometries that would allocate without bound.
// A caller may raise a field explicitly, leaving an auditable decision in the
// case record.
type Limits struct {
	// MaxEntries is the largest number of ZIP central-directory entries.
	MaxEntries int
	// MaxEntrySize is the largest uncompressed size of one ZIP entry.
	MaxEntrySize uint64
	// MaxTotalUncompressed is the largest total uncompressed size of all file
	// entries.
	MaxTotalUncompressed uint64
	// MaxMetadataBytes is the largest descriptor member read.
	MaxMetadataBytes uint64
	// MaxLineBytes is the largest physical line in a metadata member.
	MaxLineBytes int
	// MaxTriples is the largest number of Turtle triples accepted.
	MaxTriples int
	// MaxSubjects is the largest number of distinct Turtle subjects accepted.
	MaxSubjects int
	// MaxPrefixes is the largest number of prefix declarations accepted.
	MaxPrefixes int
	// MaxURIBytes is the largest decoded IRI length.
	MaxURIBytes int
	// MaxLiteralBytes is the largest decoded short string literal.
	MaxLiteralBytes int
	// MaxHashesPerStream is the largest number of hashes retained per stream.
	MaxHashesPerStream int
	// MaxStoredPerStream is the largest number of aff4:stored, aff4:target and
	// aff4:dependentStream objects retained per stream.
	MaxStoredPerStream int
	// MaxIgnoredPredicates is the largest number of unknown-predicate names
	// retained.
	MaxIgnoredPredicates int
	// MaxWarnings is the largest number of warnings retained.
	MaxWarnings int
	// MaxSampleEntries is the largest inventory sample retained.
	MaxSampleEntries int
	// MaxChunks is the largest number of image chunks one stream may declare.
	MaxChunks uint64
	// MaxChunkBytes bounds one decoded image chunk.  It is an added safety
	// bound beyond the Rust reference, which has no per-chunk allocation cap.
	MaxChunkBytes uint64
	// MaxMapBytes is the largest map entry stream read.
	MaxMapBytes uint64
	// MaxMapEntries is the largest number of 12-byte map entries accepted.
	MaxMapEntries int
	// MaxCachedChunks is the largest number of decoded chunks cached by one
	// image source.
	MaxCachedChunks int
	// MaxMapDepth is the largest recursion depth while resolving maps.
	MaxMapDepth uint32
}

// DefaultLimits returns the defaults used by the reference reader, plus the
// per-chunk allocation cap.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:           100_000,
		MaxEntrySize:         4 * 1024 * 1024 * 1024,
		MaxTotalUncompressed: 8 * 1024 * 1024 * 1024,
		MaxMetadataBytes:     16 * 1024 * 1024,
		MaxLineBytes:         64 * 1024,
		MaxTriples:           4_096,
		MaxSubjects:          1_024,
		MaxPrefixes:          64,
		MaxURIBytes:          2_048,
		MaxLiteralBytes:      4_096,
		MaxHashesPerStream:   16,
		MaxStoredPerStream:   32,
		MaxIgnoredPredicates: 32,
		MaxWarnings:          256,
		MaxSampleEntries:     32,
		MaxChunks:            1_048_576,
		MaxChunkBytes:        64 * 1024 * 1024,
		MaxMapBytes:          64 * 1024 * 1024,
		MaxMapEntries:        1_048_576,
		MaxCachedChunks:      64,
		MaxMapDepth:          16,
	}
}

// DescriptorKind identifies the member that supplied the AFF4 version.
type DescriptorKind uint8

const (
	// DescriptorContainerDescription is container.description.
	DescriptorContainerDescription DescriptorKind = iota
	// DescriptorTurtle is information.turtle.
	DescriptorTurtle
	// DescriptorYaml is information.yaml.
	DescriptorYaml
)

// String returns the member name the kind describes.
func (k DescriptorKind) String() string {
	switch k {
	case DescriptorContainerDescription:
		return ContainerDescription
	case DescriptorTurtle:
		return InformationTurtle
	case DescriptorYaml:
		return InformationYAML
	default:
		return "unknown"
	}
}

// Descriptor is one descriptor member and the version it declares.
type Descriptor struct {
	Member  string
	Kind    DescriptorKind
	Version string // empty when the member declares no version
	Line    uint64 // one-based line the version was found on; 0 when none
	Bytes   uint64
}

// Hash is a declared hash: the algorithm and whether a value is present.  The
// value itself is never retained or verified.
type Hash struct {
	Algorithm    string
	ValuePresent bool
	ValueLen     int
}

// HashFact is one declared hash tied to the stream that declared it.  The
// reader never verifies these values, so Verified is always false.
type HashFact struct {
	Subject      string
	Algorithm    string
	ValuePresent bool
	ValueLen     int
	Verified     bool
}

// StreamRole is the role a stream member plays.
type StreamRole uint8

const (
	// RoleImage is the stream's own member.
	RoleImage StreamRole = iota
	// RoleMap is the .map companion member.
	RoleMap
	// RoleZero is the .zero companion member.
	RoleZero
	// RoleIndex is the .index companion member.
	RoleIndex
)

// String returns the role label.
func (r StreamRole) String() string {
	switch r {
	case RoleImage:
		return "image"
	case RoleMap:
		return "map"
	case RoleZero:
		return "zero"
	case RoleIndex:
		return "index"
	default:
		return "unknown"
	}
}

// MemberCheck is one stream member checked against the ZIP central directory.
type MemberCheck struct {
	Role StreamRole
	// Candidates are the member names derived from the stream URI, in check
	// order.
	Candidates []string
	// FoundMember is the normalized central-directory path that matched.
	FoundMember string
	// Size is the declared uncompressed size of the member.
	Size *uint64
	// CompressedSize is the declared stored size of the member.
	CompressedSize *uint64
	// ExpectedSize is the expected uncompressed size when chunk geometry
	// proves it (index members only).
	ExpectedSize *uint64
	// SizeMatches reports whether Size equals ExpectedSize.
	SizeMatches *bool
}

// Found reports whether a matching member was found.
func (m MemberCheck) Found() bool { return m.FoundMember != "" }

// ImageMembers is the set of member checks for one image stream.
type ImageMembers struct {
	ImageURI string
	Checks   []MemberCheck
}

// Missing returns the first candidate of each member that was not found.
func (m ImageMembers) Missing() []string {
	var out []string
	for _, check := range m.Checks {
		if !check.Found() && len(check.Candidates) > 0 {
			out = append(out, check.Candidates[0])
		}
	}
	return out
}

// StoredLink is one aff4:stored link.
type StoredLink struct {
	Subject string
	Object  string
}

// EntryInfo is one entry recorded in the bounded inventory sample.
type EntryInfo struct {
	Path           string
	Kind           archive.Kind
	Size           uint64
	CompressedSize *uint64
}

// Stream is one recognized AFF4 stream subject.
type Stream struct {
	URI string
	// Class is the recognized rdf:type local name (Image, ImageStream, Map,
	// Zero, ZipSegment, FileImage), when one was stated.
	Class string
	// Category is the aff4:category local name (imageStream, map, zero,
	// fileImage).
	Category         string
	Size             *uint64
	ChunkSize        *uint64
	ChunksPerSegment *uint64
	// Compression is the declared compression label exactly as written.
	Compression string
	Hashes      []Hash
	Stored      []string
	// Targets are the ordered aff4:target streams.
	Targets []string
	// DependentStreams are the ordered aff4:dependentStream streams, appended
	// after Targets when a map is assembled.
	DependentStreams []string
	// DataStream names the map entry stream when it is not Stored.
	DataStream string
}

// IsImage reports whether the stream is an image or image stream.
func (s Stream) IsImage() bool {
	return s.Class == "Image" || s.Class == "ImageStream" || s.Category == "imageStream"
}

// IsMap reports whether the stream is a map.
func (s Stream) IsMap() bool { return s.Class == "Map" || s.Category == "map" }

// IsZero reports whether the stream is a zero stream.
func (s Stream) IsZero() bool { return s.Class == "Zero" || s.Category == "zero" }

// IsFileImage reports whether the stream is an AFF4-L FileImage resource.
func (s Stream) IsFileImage() bool {
	return s.Class == "FileImage" || s.Category == "fileImage"
}

// IsSegment reports whether the stream is a ZipSegment resource.
func (s Stream) IsSegment() bool { return s.Class == "ZipSegment" }

// OrderedTargets returns every aff4:target followed by every
// aff4:dependentStream, in declaration order.
func (s Stream) OrderedTargets() []string {
	out := make([]string, 0, len(s.Targets)+len(s.DependentStreams))
	out = append(out, s.Targets...)
	out = append(out, s.DependentStreams...)
	return out
}

// ClassLabel returns the class, else the category, else "unknown".
func (s Stream) ClassLabel() string {
	if s.Class != "" {
		return s.Class
	}
	if s.Category != "" {
		return s.Category
	}
	return "unknown"
}

// Facts is everything one AFF4 metadata read produced.
type Facts struct {
	FileSize       uint64
	EntryCount     int
	FileCount      int
	DirectoryCount int
	Descriptors    []Descriptor
	// Version is the primary AFF4 version, from the first descriptor that
	// declares one.
	Version          string
	Streams          []Stream
	ImageStreams     int
	MapStreams       int
	ZeroStreams      int
	SegmentStreams   int
	FileImageStreams int
	Images           []ImageMembers
	Hashes           []HashFact
	StoredLinks      []StoredLink
	// Triples is the number of triples the Turtle scan accepted.
	Triples int
	// Subjects is the number of distinct subjects the Turtle scan saw.
	Subjects int
	// UnknownSubjects counts subjects that were not recognized as a stream.
	UnknownSubjects int
	// IgnoredPredicates is a bounded sample of predicate names that were
	// ignored.
	IgnoredPredicates []string
	// IgnoredPredicateCount is the total number of unknown predicate
	// occurrences.
	IgnoredPredicateCount int
	Warnings              []string
	Sample                []EntryInfo
}

// inventory is the parsed ZIP directory shared by metadata and stream access.
type inventory struct {
	entries []archive.Entry
	index   map[string]int
}

func newInventory(entries []archive.Entry) inventory {
	index := make(map[string]int, len(entries))
	for position, entry := range entries {
		if _, exists := index[entry.Path]; !exists {
			index[entry.Path] = position
		}
	}
	return inventory{entries: entries, index: index}
}

// Container is an opened AFF4 container's metadata plus the ZIP reader used to
// open its streams.  It is immutable after Open; the ByteSource streams it
// returns are independent, read-only views.
type Container struct {
	parent source.ByteSource
	reader *zip.Reader
	limits Limits
	facts  Facts
	inv    inventory
	nextID atomic.Uint64
}

// Open parses an AFF4 container's metadata.  It does not decode image data;
// use Image or OpenStream for that.
func Open(src source.ByteSource, limits Limits) (*Container, error) {
	if src == nil {
		return nil, invalidf("nil source")
	}
	return readContainer(src, limits)
}

// Parent returns the evidence source the container was opened from.
func (c *Container) Parent() source.ByteSource { return c.parent }

// Facts returns the parsed metadata.  The slices are immutable by convention;
// callers must not modify them.
func (c *Container) Facts() Facts { return c.facts }

// Version returns the primary AFF4 version.
func (c *Container) Version() string { return c.facts.Version }

// Descriptors returns a copy of the descriptor list.
func (c *Container) Descriptors() []Descriptor {
	return append([]Descriptor(nil), c.facts.Descriptors...)
}

// Streams returns a copy of every recognized stream.
func (c *Container) Streams() []Stream {
	return append([]Stream(nil), c.facts.Streams...)
}

// ImageStreams returns every image stream.
func (c *Container) ImageStreams() []Stream {
	var out []Stream
	for _, stream := range c.facts.Streams {
		if stream.IsImage() {
			out = append(out, stream)
		}
	}
	return out
}

// Image opens the container's sole image stream.  More than one image is
// ambiguous and refused by name; use OpenStream to choose one.
func (c *Container) Image() (*StreamSource, error) {
	images := c.ImageStreams()
	switch len(images) {
	case 0:
		return nil, invalidf("AFF4 container declares no image stream")
	case 1:
		return c.OpenStream(images[0].URI)
	default:
		return nil, invalidf("AFF4 container declares %d image streams; name the one to open", len(images))
	}
}

// OpenStream opens one named AFF4 stream (image, map, zero or ZipSegment) as a
// read-only ByteSource.
func (c *Container) OpenStream(uri string) (*StreamSource, error) {
	visited := make(map[string]struct{})
	return c.openStreamInner(uri, visited, 0)
}

func (c *Container) takeID() source.ID {
	return source.ID(c.nextID.Add(1))
}

func (c *Container) findStream(uri string) *Stream {
	for index := range c.facts.Streams {
		if c.facts.Streams[index].URI == uri {
			return &c.facts.Streams[index]
		}
	}
	return nil
}

func readContainer(src source.ByteSource, limits Limits) (*Container, error) {
	fileSize := src.Len()
	if fileSize < 4 {
		return nil, corruptf("not a ZIP archive: file is %d bytes, shorter than a ZIP signature", fileSize)
	}
	head, err := source.ReadVecAt(src, 0, 4)
	if err != nil {
		return nil, err
	}
	if !zipMagic(head) {
		return nil, corruptf("not a ZIP archive: first bytes are %02x %02x %02x %02x",
			head[0], head[1], head[2], head[3])
	}

	maxEntries := limits.MaxEntries
	if maxEntries < math.MaxInt {
		maxEntries++
	}
	reader, err := zip.OpenAs("aff4", src, archive.Limits{
		MaxEntries:       maxEntries,
		MaxEntrySize:     limits.MaxEntrySize,
		MaxTotalExpanded: limits.MaxTotalUncompressed,
		MaxDepth:         8,
		MaxPathLen:       4096,
	})
	if err != nil {
		return nil, mapArchiveError(err)
	}
	entries, err := reader.Entries()
	if err != nil {
		return nil, mapArchiveError(err)
	}
	if len(entries) > limits.MaxEntries {
		return nil, limitf("AFF4 archive has %d entries, limit is %d", len(entries), limits.MaxEntries)
	}
	inv := newInventory(entries)

	fileCount, directoryCount := 0, 0
	sampleCap := limits.MaxSampleEntries
	if sampleCap < 0 {
		sampleCap = 0
	}
	sample := make([]EntryInfo, 0, minInt(len(entries), sampleCap))
	for _, entry := range entries {
		switch entry.Kind {
		case archive.KindFile:
			fileCount++
		case archive.KindDirectory:
			directoryCount++
		}
		if len(sample) < limits.MaxSampleEntries {
			sample = append(sample, EntryInfo{
				Path:           entry.Path,
				Kind:           entry.Kind,
				Size:           entry.Size,
				CompressedSize: cloneU64(entry.CompressedSize),
			})
		}
	}

	var (
		descriptors []Descriptor
		versions    []versionFact
		turtle      *turtleParse
	)
	for _, spec := range []struct {
		name string
		kind DescriptorKind
	}{
		{ContainerDescription, DescriptorContainerDescription},
		{InformationTurtle, DescriptorTurtle},
		{InformationYAML, DescriptorYaml},
	} {
		entry := findDescriptorEntry(entries, spec.name)
		if entry == nil {
			continue
		}
		text, err := readMetadata(reader, entry, limits)
		if err != nil {
			return nil, err
		}
		if err := checkLines(entry.Path, text, limits.MaxLineBytes); err != nil {
			return nil, err
		}

		var version string
		var line uint64
		switch spec.kind {
		case DescriptorContainerDescription:
			version, line, err = parseContainerDescription(entry.Path, text)
			if err != nil {
				return nil, err
			}
		case DescriptorTurtle:
			parsed, parseErr := parseTurtle(entry.Path, text, limits)
			if parseErr != nil {
				return nil, parseErr
			}
			version, line = parsed.version, parsed.versionLine
			turtle = &parsed
		case DescriptorYaml:
			parsed, parseErr := parseYAML(entry.Path, text, limits)
			if parseErr != nil {
				return nil, parseErr
			}
			version, line = parsed.version, parsed.versionLine
			if len(parsed.streams) > 0 && turtle == nil {
				turtle = &parsed
			}
		}
		if version != "" {
			versions = append(versions, versionFact{version: version, member: entry.Path, line: line})
		}
		descriptors = append(descriptors, Descriptor{
			Member:  entry.Path,
			Kind:    spec.kind,
			Version: version,
			Line:    line,
			Bytes:   entry.Size,
		})
	}

	if len(descriptors) == 0 {
		return nil, corruptf("AFF4 container has no container.description, information.turtle, or information.yaml")
	}
	if len(versions) == 0 {
		return nil, corruptf("AFF4 descriptor %s declares no version", descriptors[0].Member)
	}
	primary := versions[0].version
	if !supportedVersion(primary) {
		return nil, unsupportedf("unsupported AFF4 version %s", primary)
	}

	var warnings []string
	for _, other := range versions[1:] {
		if other.version != primary {
			pushWarning(&warnings, limits.MaxWarnings,
				"descriptor %s line %d declares version %s, primary version is %s",
				other.member, other.line, other.version, primary)
		}
	}

	parsed := turtleParse{}
	if turtle != nil {
		parsed = *turtle
	}
	for _, warning := range parsed.warnings {
		pushWarning(&warnings, limits.MaxWarnings, "%s", warning)
	}

	var images []ImageMembers
	var hashes []HashFact
	for _, stream := range parsed.streams {
		if stream.IsImage() {
			images = append(images, buildImageMembers(inv, stream))
		}
		for _, hash := range stream.Hashes {
			hashes = append(hashes, HashFact{
				Subject:      stream.URI,
				Algorithm:    hash.Algorithm,
				ValuePresent: hash.ValuePresent,
				ValueLen:     hash.ValueLen,
				Verified:     false,
			})
		}
	}

	facts := Facts{
		FileSize:              fileSize,
		EntryCount:            len(entries),
		FileCount:             fileCount,
		DirectoryCount:        directoryCount,
		Descriptors:           descriptors,
		Version:               primary,
		Streams:               parsed.streams,
		ImageStreams:          parsed.imageStreams,
		MapStreams:            parsed.mapStreams,
		ZeroStreams:           parsed.zeroStreams,
		SegmentStreams:        parsed.segmentStreams,
		FileImageStreams:      parsed.fileImageStreams,
		Images:                images,
		Hashes:                hashes,
		StoredLinks:           parsed.storedLinks,
		Triples:               parsed.triples,
		Subjects:              parsed.subjects,
		UnknownSubjects:       parsed.unknownSubjects,
		IgnoredPredicates:     parsed.ignoredPredicates,
		IgnoredPredicateCount: parsed.ignoredPredicateCount,
		Warnings:              warnings,
		Sample:                sample,
	}
	container := &Container{
		parent: src,
		reader: reader,
		limits: limits,
		facts:  facts,
		inv:    inv,
	}
	container.nextID.Store(uint64(src.SourceID()))
	return container, nil
}

type versionFact struct {
	version string
	member  string
	line    uint64
}

func findDescriptorEntry(entries []archive.Entry, name string) *archive.Entry {
	for index := range entries {
		if entries[index].Kind == archive.KindFile && strings.EqualFold(entries[index].Path, name) {
			return &entries[index]
		}
	}
	return nil
}

func readMetadata(reader *zip.Reader, entry *archive.Entry, limits Limits) (string, error) {
	if entry.Size > limits.MaxMetadataBytes {
		return "", limitf("AFF4 metadata member %s is %d bytes, limit is %d",
			entry.Path, entry.Size, limits.MaxMetadataBytes)
	}
	opened, err := reader.OpenEntry(entry.Path, source.ID(2))
	if err != nil {
		return "", mapArchiveError(err)
	}
	bytes, err := source.ReadVecAt(opened, 0, entry.Size)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(bytes) {
		return "", corruptf("AFF4 metadata member %s is not valid UTF-8", entry.Path)
	}
	return string(bytes), nil
}

func zipMagic(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	var sig [4]byte
	copy(sig[:], head[:4])
	return sig == zipLocalSig || sig == zipEOCDSig || sig == zipSpanned
}

// checkLines rejects a metadata member whose physical lines exceed limit.
func checkLines(member, text string, limit int) error {
	for index, raw := range strings.Split(text, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if len(line) > limit {
			return limitf("AFF4 metadata member %s line %d is %d bytes, limit is %d",
				member, index+1, len(line), limit)
		}
	}
	return nil
}

// parseVersionNumber accepts major.minor or major.minor.patch and nothing else.
func parseVersionNumber(value string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 2 && len(parts) != 3 {
		return "", false
	}
	for _, part := range parts {
		if part == "" || !allDigits(part) {
			return "", false
		}
	}
	return strings.Join(parts, "."), true
}

// supportedVersion accepts 1.0 and 1.1 with any numeric patch.
func supportedVersion(version string) bool {
	if version == "1.0" || version == "1.1" {
		return true
	}
	for _, prefix := range []string{"1.0.", "1.1."} {
		if patch, ok := strings.CutPrefix(version, prefix); ok {
			return patch != "" && allDigits(patch)
		}
	}
	return false
}

func parseContainerDescription(member, text string) (string, uint64, error) {
	text = strings.TrimPrefix(text, "\xef\xbb\xbf")
	for index, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		rest := line
		if stripped, ok := strings.CutPrefix(line, "AFF4-"); ok {
			rest = stripped
		} else if stripped, ok := strings.CutPrefix(line, "AFF4/"); ok {
			rest = stripped
		}
		token := ""
		if fields := strings.Fields(rest); len(fields) > 0 {
			token = fields[0]
		}
		version, ok := parseVersionNumber(token)
		if !ok {
			return "", 0, corruptf("AFF4 descriptor %s line %d: expected an AFF4 version, found %q",
				member, index+1, line)
		}
		return version, uint64(index + 1), nil
	}
	return "", 0, corruptf("AFF4 descriptor %s line 1: container.description is empty", member)
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func parseU64(text string) (uint64, bool) {
	if !allDigits(text) {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// iriLocal returns the local name after the last '#' or '/', when non-empty.
func iriLocal(iri string) (string, bool) {
	local := iri
	if index := strings.LastIndexAny(iri, "#/"); index >= 0 {
		local = iri[index+1:]
	}
	if local == "" {
		return "", false
	}
	return local, true
}

// memberCandidates derives the member names a stream URI can map to for a
// metadata role.  The raw URN and the form with the aff4:// scheme removed are
// checked; companion suffixes are tried as .suffix and /suffix.
func memberCandidates(uri string, role StreamRole) []string {
	var suffixes []string
	switch role {
	case RoleImage:
		suffixes = []string{""}
	case RoleMap:
		suffixes = []string{".map", "/map"}
	case RoleZero:
		suffixes = []string{".zero", "/zero"}
	case RoleIndex:
		suffixes = []string{".index", "/index"}
	}
	bases := []string{uri}
	if rest, ok := strings.CutPrefix(uri, "aff4://"); ok {
		bases = append(bases, rest)
	}
	if rest, ok := strings.CutPrefix(uri, "aff4:"); ok && !strings.HasPrefix(rest, "/") {
		bases = append(bases, rest)
	}
	out := make([]string, 0, len(bases)*len(suffixes))
	for _, base := range bases {
		for _, suffix := range suffixes {
			candidate := base + suffix
			if !containsString(out, candidate) {
				out = append(out, candidate)
			}
		}
	}
	return out
}

// expectedIndexSize derives the uncompressed .index size from chunk geometry.
func expectedIndexSize(stream Stream) (uint64, bool) {
	if stream.Size == nil || stream.ChunkSize == nil || *stream.ChunkSize == 0 {
		return 0, false
	}
	chunks := *stream.Size / *stream.ChunkSize
	if *stream.Size%*stream.ChunkSize != 0 {
		chunks++
	}
	if chunks > math.MaxUint64/indexEntryBytes {
		return 0, false
	}
	return chunks * indexEntryBytes, true
}

func buildImageMembers(inv inventory, stream Stream) ImageMembers {
	checks := make([]MemberCheck, 0, 4)
	for _, role := range []StreamRole{RoleImage, RoleMap, RoleZero, RoleIndex} {
		candidates := memberCandidates(stream.URI, role)
		var found *archive.Entry
		for _, candidate := range candidates {
			path, err := archive.SanitizeEntryPath(candidate)
			if err != nil {
				continue
			}
			if position, ok := inv.index[path]; ok {
				found = &inv.entries[position]
				break
			}
		}
		var expected *uint64
		if role == RoleIndex {
			if size, ok := expectedIndexSize(stream); ok {
				expected = &size
			}
		}
		check := MemberCheck{
			Role:         role,
			Candidates:   candidates,
			ExpectedSize: expected,
		}
		if found != nil {
			check.FoundMember = found.Path
			size := found.Size
			check.Size = &size
			check.CompressedSize = cloneU64(found.CompressedSize)
			if expected != nil {
				matches := *expected == size
				check.SizeMatches = &matches
			}
		}
		checks = append(checks, check)
	}
	return ImageMembers{ImageURI: stream.URI, Checks: checks}
}

func pushWarning(warnings *[]string, limit int, format string, args ...any) {
	if len(*warnings) < limit {
		*warnings = append(*warnings, fmt.Sprintf(format, args...))
	}
}

func cloneU64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func containsString(list []string, want string) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func satAddU64(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func mulU64(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func divCeil(a, b uint64) uint64 {
	value := a / b
	if a%b != 0 {
		value++
	}
	return value
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
