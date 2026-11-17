// Package l01 reads EnCase logical evidence containers (`.L01`, signature
// `LVF`): an EWF v1 container whose media bytes are logical file data and
// whose catalog lives in an `ltree` section of UTF-16 `rec`/`perm`/`srce`/
// `sub`/`entry` records.
//
// The container framing is the EWF v1 13-byte file header and 76-byte section
// descriptors. Chunk tables use EnCase 6-7 4-byte entries: the high bit marks
// a zlib stream and the low 31 bits are an offset relative to the table's base
// offset. Stored chunks carry a 4-byte Adler-32 trailer.
//
// This package exposes source evidence only. It never invents a missing size,
// timestamp, or byte: an absent field stays nil/empty, and a read that cannot
// be satisfied from the recorded chunks returns an explicit error rather than
// zero-filling. Sparse regions are different: the catalog records them as
// holes, so those reads return the recorded zeroes (or the recorded repeated
// byte).
//
// EWF v2 logical evidence (`.Lx01`, `LEF2`) is a different container
// generation and is refused by name. zstd, X-Ways encrypted segments and
// vendor sections this reader does not understand are refused with
// source.ErrUnsupported; no password derivation is attempted.
package l01

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Signature is the EWF v1 logical-evidence signature (`LVF\x09\x0d\x0a\xff\x00`).
	Signature = "LVF\x09\x0d\x0a\xff\x00"
	// LEF2Signature is the EWF v2 logical-evidence signature (`.Lx01`). It is
	// named so a refusal can say which container generation was seen.
	LEF2Signature = "LEF2\r\n\x81\x00"

	// FileHeaderBytes is the size of the EWF v1 file header.
	FileHeaderBytes = 13
	// SectionDescriptorBytes is the size of an EWF v1 section descriptor.
	SectionDescriptorBytes = 76
	// LTreeHeaderBytes is the ltree header that precedes the UTF-16 catalog text.
	LTreeHeaderBytes = 48

	// SparseFlag marks an entry whose content is one stored byte repeated.
	SparseFlag uint32 = 0x0400_0000
	// FolderFlag marks a folder entry (informational; the `p` indicator decides).
	FolderFlag uint32 = 0x0200_0000
)

const (
	markerZlib                 = 0x01
	markerZstd                 = 0x21
	markerXWaysZlibEncrypted   = 0x81
	markerXWaysZstdEncrypted   = 0xa1
	maxCatalogTypeIndicators   = 256
	maxExtentCountPerEntry     = 1_000_000
	adlerChunkTrailerBytes     = 4
	ltreeAdlerFieldOffset      = 24
	ltreeTextSizeFieldOffset   = 16
	volumeChecksumFieldOffset  = 1048
	volumeMinimumBytes         = 24
	volumeMaximumReadBytes     = 1052
	sectionCompressionField    = 32
	sectionCompressionFieldEnd = 72
)

// ErrNotFound reports that no catalog entry has the requested path.
var ErrNotFound = errors.New("l01: path not found")

// ErrAmbiguousPath reports that more than one catalog entry has the path.
var ErrAmbiguousPath = errors.New("l01: ambiguous path")

// Limits bounds the structures walked while opening an L01 image.
type Limits struct {
	MaxSegments           int
	MaxSectionsPerSegment int
	MaxEntries            int
	MaxChunks             int
	MaxLTreeBytes         uint64
	MaxEntryReadBytes     uint64
	MaxChunkSize          uint64
	MaxDepth              int
}

// DefaultLimits are the same bounds the reference reader applies.
func DefaultLimits() Limits {
	return Limits{
		MaxSegments:           4096,
		MaxSectionsPerSegment: 4096,
		MaxEntries:            1_000_000,
		MaxChunks:             4_000_000,
		MaxLTreeBytes:         256 * 1024 * 1024,
		MaxEntryReadBytes:     256 * 1024 * 1024,
		MaxChunkSize:          16 * 1024 * 1024,
		MaxDepth:              256,
	}
}

// EntryKind is what the catalog's `p` indicator says an entry is.
type EntryKind uint8

const (
	// KindUnknown means the `p` indicator was absent or undefined.
	KindUnknown EntryKind = iota
	// KindFile is a regular file entry.
	KindFile
	// KindDirectory is a folder entry.
	KindDirectory
)

// String implements fmt.Stringer.
func (k EntryKind) String() string {
	switch k {
	case KindFile:
		return "file"
	case KindDirectory:
		return "directory"
	default:
		return "unknown"
	}
}

// Extent is one logical extent of a file's data, as carried by a `be` value.
type Extent struct {
	Offset uint64
	Size   uint64
	Sparse bool
}

// Entry is one catalog record. Optional values are nil when the catalog row
// did not carry them. Name is the lossy UTF-16 decoding; NameUTF16 keeps the
// raw code units when the name was not well-formed UTF-16.
type Entry struct {
	Index    int
	Parent   int // -1 for the catalog root
	Children []int
	Depth    int

	Name      string
	NameUTF16 []uint16
	Path      string
	Kind      EntryKind

	Size                  *uint64
	Flags                 *uint32
	ID                    *uint64
	MD5                   string
	SHA1                  string
	CreationTime          *int64
	ModificationTime      *int64
	AccessTime            *int64
	EntryModificationTime *int64
	DeletionTime          *int64

	DuplicateDataOffset *int64
	LogicalOffset       *int64
	PhysicalOffset      *int64
	SourceID            *int32
	SubjectID           *uint32
	PermissionGroup     *int32
	RecordType          *uint32
	ShortName           string
	Extents             []Extent
}

// Deleted reports whether the catalog row carries a `dl` deletion timestamp.
// It is a recorded value, not proof that the content is recoverable.
func (e Entry) Deleted() bool { return e.DeletionTime != nil }

// SourceRecord is one row of the `srce` category: the device/host the logical
// evidence was acquired from.
type SourceRecord struct {
	Identifier        *int32
	Name              string
	EvidenceNumber    string
	Location          string
	DeviceGUID        string
	PrimaryDeviceGUID string
	DriveType         string
	Manufacturer      string
	Model             string
	SerialNumber      string
	Domain            string
	IPAddress         string
	MACAddress        string
	Size              *uint64
	LogicalOffset     *int64
	PhysicalOffset    *int64
	AcquisitionTime   *int64
	MD5               string
	SHA1              string
}

// Subject is one row of the `sub` category.
type Subject struct {
	Identifier *uint32
	Name       string
}

// Header carries the case/acquisition metadata of the EWF `header` section.
type Header struct {
	Description         string
	CaseNumber          string
	EvidenceNumber      string
	Examiner            string
	Notes               string
	AcquisitionDate     string
	SystemDate          string
	AcquisitionSoftware string
	AcquisitionOS       string
	Model               string
	SerialNumber        string
	DeviceLabel         string
	ProcessID           string
}

// HashStatus is the result of comparing a declared catalog digest.
type HashStatus uint8

const (
	// HashNotDeclared means the catalog carries no digest of this algorithm.
	HashNotDeclared HashStatus = iota
	// HashVerified means the declared digest matches the reassembled bytes.
	HashVerified
	// HashMismatch means the declared digest does not match.
	HashMismatch
)

// HashCheck is one digest comparison.
type HashCheck struct {
	Status   HashStatus
	Declared string
	Computed string
}

// EntryHashes is the result of VerifyEntryHashes.
type EntryHashes struct {
	MD5         HashCheck
	SHA1        HashCheck
	BytesHashed uint64
}

// Info describes the container, its catalog and the integrity results.
type Info struct {
	Segments       int
	SegmentNumbers []uint16
	SectionTypes   map[string]int

	MediaType           uint8
	SectorsPerChunk     uint32
	BytesPerSector      uint32
	DeclaredSectorCount uint64
	ChunkSizeSet        bool
	ChunkSize           uint64

	LogicalSizeSet     bool
	LogicalSize        uint64
	LogicalDataSizeSet bool
	LogicalDataSize    uint64

	Entries        int
	Files          int
	Directories    int
	UnknownEntries int
	DeletedEntries int
	RootIndex      int
	RootIndexSet   bool

	Chunks           int
	StoredChunks     int
	CompressedChunks int

	// Compression is "none", "stored", "zlib" or "zlib+stored".
	Compression string
	// Encrypted is always false for an image that opened: encrypted inputs are
	// refused while walking the file header and sections.
	Encrypted bool

	LTreeMD5Present         bool
	LTreeMD5OK              bool
	LTreeHeaderAdlerPresent bool
	LTreeHeaderAdlerOK      bool

	// CaseNumber and EvidenceNumber are the header values, falling back to the
	// first non-empty `srce.ev` evidence number when the header omits it.
	CaseNumber     string
	EvidenceNumber string

	Header   Header
	Sources  []SourceRecord
	Subjects []Subject
	Warnings []string
}

// MediaSize returns the effective logical media size (catalog `rec.tb`,
// falling back to the volume geometry only when the catalog omits it).
func (i Info) MediaSize() uint64 { return i.LogicalSize }

type section struct {
	kind              string
	descriptorOffset  uint64
	dataOffset        uint64
	dataSize          uint64
	compressionMethod string
}

type segment struct {
	number   uint16
	marker   byte
	source   source.ByteSource
	sections []section
}

type volumeInfo struct {
	mediaType       uint8
	sectorsPerChunk uint32
	bytesPerSector  uint32
	sectorCount     uint64
	chunkSize       uint64
}

type chunkEncoding uint8

const (
	encodingStored chunkEncoding = iota
	encodingZlib
)

type chunkRef struct {
	segment     int
	offset      uint64
	encodedSize uint64
	logicalSize int
	encoding    chunkEncoding
}

// Image is a parsed, read-only L01 catalog and logical media reader.
type Image struct {
	id         source.ID
	imageID    source.ImageID
	sectorSize uint32
	limits     Limits

	segments     []segment
	chunkSize    uint64
	hasChunkSize bool
	mediaSize    uint64
	hasMediaSize bool
	chunks       []chunkRef
	entries      []Entry
	root         int
	paths        map[string][]int
	info         Info
}

// Open opens a single-segment L01 image with the default bounds.
func Open(src source.ByteSource) (*Image, error) {
	return OpenWithLimits(src, DefaultLimits())
}

// OpenWithLimits opens a single-segment L01 image with explicit bounds.
func OpenWithLimits(src source.ByteSource, limits Limits) (*Image, error) {
	return OpenSegmentsWithLimits([]source.ByteSource{src}, limits)
}

// OpenSegments opens a multi-segment L01 set with the default bounds.
func OpenSegments(sources []source.ByteSource) (*Image, error) {
	return OpenSegmentsWithLimits(sources, DefaultLimits())
}

// OpenSegmentsWithLimits opens a multi-segment L01 set. Segments are ordered
// by the number in their file headers; the caller's order is irrelevant.
func OpenSegmentsWithLimits(sources []source.ByteSource, limits Limits) (*Image, error) {
	if len(sources) == 0 {
		return nil, invalidArgument("an L01 image needs at least one segment source")
	}
	if len(sources) > limits.MaxSegments {
		return nil, unsupported(fmt.Sprintf(
			"segment count %d exceeds the configured bound %d", len(sources), limits.MaxSegments))
	}

	var warnings []string
	segments := make([]segment, 0, len(sources))
	for _, src := range sources {
		if src == nil {
			return nil, invalidArgument("an L01 segment source is nil")
		}
		parsed, segmentWarnings, err := walkSegment(src, limits)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, segmentWarnings...)
		segments = append(segments, parsed)
	}

	sort.SliceStable(segments, func(left, right int) bool {
		return segments[left].number < segments[right].number
	})
	for index, segment := range segments {
		expected := uint16(index + 1)
		if uint64(index+1) > 0xffff {
			return nil, unsupported("segment count does not fit the 16-bit segment number")
		}
		if segment.number != expected {
			return nil, corrupt(0, fmt.Sprintf(
				"segment set is incomplete or misnumbered: found segment %d where %d was expected",
				segment.number, expected))
		}
	}
	marker := segments[0].marker
	for _, segment := range segments {
		if segment.marker != marker {
			return nil, corrupt(0, "L01 segments disagree on the file header marker")
		}
	}
	for _, segment := range segments {
		for _, section := range segment.sections {
			if section.kind == "x_encryption" {
				return nil, unsupported(
					"X-Ways encrypted segment (x_encryption section); password key derivation is not performed")
			}
		}
	}

	img := &Image{
		id:         segments[0].source.SourceID(),
		imageID:    segments[0].source.ImageID(),
		sectorSize: segments[0].source.SectorSize(),
		limits:     limits,
		segments:   segments,
	}
	if img.sectorSize == 0 {
		img.sectorSize = 512
	}

	info := Info{Segments: len(segments), SegmentNumbers: make([]uint16, 0, len(segments))}
	for _, segment := range segments {
		info.SegmentNumbers = append(info.SegmentNumbers, segment.number)
	}
	info.SectionTypes = make(map[string]int)
	for _, segment := range segments {
		for _, section := range segment.sections {
			info.SectionTypes[section.kind]++
		}
	}

	volume, err := findVolume(segments, limits, &warnings)
	if err != nil {
		return nil, err
	}
	if volume != nil {
		info.MediaType = volume.mediaType
		info.SectorsPerChunk = volume.sectorsPerChunk
		info.BytesPerSector = volume.bytesPerSector
		info.DeclaredSectorCount = volume.sectorCount
		info.ChunkSize = volume.chunkSize
		info.ChunkSizeSet = true
		img.chunkSize = volume.chunkSize
		img.hasChunkSize = true
	}

	parsedCatalog, catalogWarnings, err := parseCatalogSection(segments, limits)
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, catalogWarnings...)

	info.LTreeMD5Present = parsedCatalog.md5Present
	info.LTreeMD5OK = parsedCatalog.md5OK
	info.LTreeHeaderAdlerPresent = parsedCatalog.adlerPresent
	info.LTreeHeaderAdlerOK = parsedCatalog.adlerOK
	info.LogicalDataSize = parsedCatalog.dataSize
	info.LogicalDataSizeSet = parsedCatalog.dataSizeSet
	info.Entries = len(parsedCatalog.entries)
	info.RootIndex = parsedCatalog.root
	info.RootIndexSet = true
	for index := range parsedCatalog.entries {
		switch parsedCatalog.entries[index].Kind {
		case KindFile:
			info.Files++
		case KindDirectory:
			info.Directories++
		default:
			info.UnknownEntries++
		}
		if parsedCatalog.entries[index].DeletionTime != nil {
			info.DeletedEntries++
		}
	}

	if parsedCatalog.dataSizeSet {
		img.mediaSize = parsedCatalog.dataSize
		img.hasMediaSize = true
	} else if volume != nil {
		if product, ok := checkedMul(volume.sectorCount, uint64(volume.bytesPerSector)); ok {
			img.mediaSize = product
			img.hasMediaSize = true
		}
	}
	info.LogicalSize = img.mediaSize
	info.LogicalSizeSet = img.hasMediaSize

	if img.hasMediaSize {
		if err := validateEntryRanges(parsedCatalog.entries, img.mediaSize); err != nil {
			return nil, err
		}
	}

	chunks, err := buildChunks(segments, img.chunkSize, img.hasChunkSize,
		img.mediaSize, img.hasMediaSize, limits, &warnings)
	if err != nil {
		return nil, err
	}
	img.chunks = chunks
	info.Chunks = len(chunks)
	for _, chunk := range chunks {
		if chunk.encoding == encodingZlib {
			info.CompressedChunks++
		} else {
			info.StoredChunks++
		}
	}
	switch {
	case len(chunks) == 0:
		info.Compression = "none"
	case info.CompressedChunks > 0 && info.StoredChunks > 0:
		info.Compression = "zlib+stored"
	case info.CompressedChunks > 0:
		info.Compression = "zlib"
	default:
		info.Compression = "stored"
	}

	info.Header = readHeaderMetadata(segments, &warnings)
	info.Sources = parsedCatalog.sources
	info.Subjects = parsedCatalog.subjects
	info.CaseNumber = info.Header.CaseNumber
	info.EvidenceNumber = info.Header.EvidenceNumber
	if info.EvidenceNumber == "" {
		for index := range info.Sources {
			if info.Sources[index].EvidenceNumber != "" {
				info.EvidenceNumber = info.Sources[index].EvidenceNumber
				break
			}
		}
	}
	info.Warnings = warnings

	img.entries = parsedCatalog.entries
	img.root = parsedCatalog.root
	img.info = info
	img.buildPaths()
	return img, nil
}

// MatchesSignature reports whether head begins an EWF v1 logical-evidence
// container.
func MatchesSignature(head []byte) bool {
	return len(head) >= len(Signature) && string(head[:len(Signature)]) == Signature
}

// SiblingSegmentFileName derives a segment name from the first segment's name.
// The `L`'s case and digit width are preserved; a non-LVF extension and a zero
// segment number yield false.
func SiblingSegmentFileName(first string, number uint32) (string, bool) {
	if number == 0 {
		return "", false
	}
	dot := strings.LastIndexByte(first, '.')
	if dot < 0 {
		return "", false
	}
	stem, extension := first[:dot], first[dot+1:]
	if len(extension) < 2 || (extension[0] != 'L' && extension[0] != 'l') {
		return "", false
	}
	digits := extension[1:]
	for index := 0; index < len(digits); index++ {
		if digits[index] < '0' || digits[index] > '9' {
			return "", false
		}
	}
	width := len(digits)
	return fmt.Sprintf("%s.%c%0*d", stem, extension[0], width, number), true
}

func walkSegment(src source.ByteSource, limits Limits) (segment, []string, error) {
	var warnings []string
	length := src.Len()
	if length < FileHeaderBytes {
		return segment{}, nil, corrupt(0, fmt.Sprintf(
			"L01 segment is truncated: %d bytes, needs at least %d", length, FileHeaderBytes))
	}
	head, err := source.ReadVecAt(src, 0, FileHeaderBytes)
	if err != nil {
		return segment{}, nil, err
	}
	if string(head[:8]) == LEF2Signature {
		return segment{}, nil, unsupported(
			"EWF v2 logical evidence (`LEF2` header, the `.Lx01`/`.Lx02` generation); " +
				"this reader decodes the EWF v1 `LVF` catalog only")
	}
	if string(head[:8]) != Signature {
		return segment{}, nil, corrupt(0, "invalid L01 signature: expected LVF\\x09\\x0d\\x0a\\xff\\x00")
	}
	marker := head[8]
	number := binary.LittleEndian.Uint16(head[9:11])
	if number == 0 {
		return segment{}, nil, corrupt(9, "L01 file header carries segment number 0")
	}
	if err := classifyMarker(marker); err != nil {
		return segment{}, nil, err
	}

	sections := make([]section, 0, 8)
	offset := uint64(FileHeaderBytes)
	for {
		if len(sections) >= limits.MaxSectionsPerSegment {
			return segment{}, nil, unsupported(fmt.Sprintf(
				"segment %d section count exceeds the configured bound %d",
				number, limits.MaxSectionsPerSegment))
		}
		descriptorEnd, ok := checkedAdd(offset, SectionDescriptorBytes)
		if !ok {
			return segment{}, nil, corrupt(offset, "L01 section descriptor offset overflows")
		}
		if descriptorEnd > length {
			return segment{}, nil, corrupt(offset, fmt.Sprintf(
				"section descriptor at %d is truncated: segment is %d bytes", offset, length))
		}
		descriptor, err := source.ReadVecAt(src, offset, SectionDescriptorBytes)
		if err != nil {
			return segment{}, nil, err
		}
		typeEnd := bytes.IndexByte(descriptor[:16], 0)
		if typeEnd < 0 {
			typeEnd = 16
		}
		kind := string(descriptor[:typeEnd])
		if kind == "" {
			return segment{}, nil, corrupt(offset, "L01 section descriptor has an empty type")
		}
		if err := sectionKindRefusal(kind, offset); err != nil {
			return segment{}, nil, err
		}
		if !knownSectionKind(kind) {
			return segment{}, nil, unsupported(fmt.Sprintf(
				"L01 section `%s` at offset %d in segment %d is not interpreted", kind, offset, number))
		}
		next := binary.LittleEndian.Uint64(descriptor[16:24])
		size := binary.LittleEndian.Uint64(descriptor[24:32])
		storedChecksum := binary.LittleEndian.Uint32(descriptor[72:76])
		if storedChecksum != 0 {
			computed := adler32Checksum(descriptor[:72])
			if storedChecksum != computed {
				return segment{}, nil, corrupt(offset+72, fmt.Sprintf(
					"section `%s` descriptor Adler-32 mismatch: stored %08x, computed %08x",
					kind, storedChecksum, computed))
			}
		}

		compressionMethod := ""
		if kind == "header" {
			if method, ok := descriptorCompressionMethod(descriptor[sectionCompressionField:sectionCompressionFieldEnd]); ok {
				lower := strings.ToLower(method)
				if lower != "zlib" && lower != "deflate" {
					return segment{}, nil, unsupported(fmt.Sprintf(
						"descriptor compression method %q (section `%s` at offset %d)", method, kind, offset))
				}
				compressionMethod = lower
			}
		}

		var dataSize uint64
		if (kind == "done" || kind == "next") && size == 0 {
			dataSize = 0
		} else {
			if size < SectionDescriptorBytes {
				return segment{}, nil, corrupt(offset, fmt.Sprintf(
					"section `%s` size %d is smaller than its %d-byte descriptor",
					kind, size, SectionDescriptorBytes))
			}
			dataSize = size - SectionDescriptorBytes
		}
		dataEnd, ok := checkedAdd(descriptorEnd, dataSize)
		if !ok {
			return segment{}, nil, corrupt(offset, fmt.Sprintf("section `%s` data range overflows", kind))
		}
		if dataEnd > length {
			return segment{}, nil, corrupt(descriptorEnd, fmt.Sprintf(
				"section `%s` data at %d is truncated: needs %d bytes, segment is %d",
				kind, descriptorEnd, dataEnd, length))
		}
		sections = append(sections, section{
			kind:              kind,
			descriptorOffset:  offset,
			dataOffset:        descriptorEnd,
			dataSize:          dataSize,
			compressionMethod: compressionMethod,
		})

		if kind == "done" || kind == "next" {
			break
		}
		if next == 0 {
			warnings = append(warnings, fmt.Sprintf(
				"segment %d: section `%s` at %d has next=0; assuming the chain ends", number, kind, offset))
			break
		}
		if next <= offset {
			return segment{}, nil, corrupt(offset, fmt.Sprintf(
				"segment %d: section `%s` next offset %d does not advance the chain", number, kind, next))
		}
		if next < dataEnd {
			return segment{}, nil, corrupt(next, fmt.Sprintf(
				"segment %d: next section at %d overlaps `%s` data ending at %d",
				number, next, kind, dataEnd))
		}
		if next > length {
			return segment{}, nil, corrupt(next, fmt.Sprintf(
				"segment %d: next section offset %d is beyond the segment length %d", number, next, length))
		}
		offset = next
	}
	return segment{number: number, marker: marker, source: src, sections: sections}, warnings, nil
}

func classifyMarker(marker byte) error {
	switch marker {
	case markerZlib:
		return nil
	case markerZstd:
		return unsupported("zstd compression (file header marker 0x21 is not decoded)")
	case markerXWaysZlibEncrypted, markerXWaysZstdEncrypted:
		return unsupported(fmt.Sprintf(
			"encrypted segment (X-Ways file header marker 0x%02x); password key derivation is not performed", marker))
	default:
		return unsupported(fmt.Sprintf(
			"file header marker 0x%02x names an unknown compression method", marker))
	}
}

var knownSectionKinds = map[string]struct{}{
	"header":       {},
	"header2":      {},
	"volume":       {},
	"disk":         {},
	"data":         {},
	"sectors":      {},
	"table":        {},
	"table2":       {},
	"ltree":        {},
	"ltypes":       {},
	"error2":       {},
	"session":      {},
	"digest":       {},
	"hash":         {},
	"done":         {},
	"next":         {},
	"x_encryption": {},
}

func knownSectionKind(kind string) bool {
	_, ok := knownSectionKinds[kind]
	return ok
}

func sectionKindRefusal(kind string, offset uint64) error {
	if kind == "x_encryption" {
		return unsupported(
			"X-Ways encrypted segment (x_encryption section); password key derivation is not performed")
	}
	if strings.HasPrefix(kind, "x_") && !knownSectionKind(kind) {
		return unsupported(fmt.Sprintf("X-Ways section `%s` at offset %d is not decoded", kind, offset))
	}
	return nil
}

func descriptorCompressionMethod(field []byte) (string, bool) {
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		end = len(field)
	}
	value := field[:end]
	if len(value) == 0 {
		return "", false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return "", false
		}
	}
	return string(value), true
}

func findVolume(segments []segment, limits Limits, warnings *[]string) (*volumeInfo, error) {
	var volumes []volumeInfo
	for _, segment := range segments {
		for _, section := range segment.sections {
			if section.kind != "volume" && section.kind != "disk" && section.kind != "data" {
				continue
			}
			if section.dataSize < volumeMinimumBytes {
				return nil, corrupt(section.dataOffset, fmt.Sprintf(
					"volume section is truncated: %d bytes, needs at least %d",
					section.dataSize, volumeMinimumBytes))
			}
			readLength := section.dataSize
			if readLength > volumeMaximumReadBytes {
				readLength = volumeMaximumReadBytes
			}
			data, err := source.ReadVecAt(segment.source, section.dataOffset, readLength)
			if err != nil {
				return nil, err
			}
			volume, err := parseVolume(data, section.dataOffset, limits)
			if err != nil {
				return nil, err
			}
			volumes = append(volumes, volume)
		}
	}
	if len(volumes) > 1 {
		*warnings = append(*warnings, fmt.Sprintf(
			"%d media sections found across the segment set; using the first", len(volumes)))
	}
	if len(volumes) == 0 {
		return nil, nil
	}
	return &volumes[0], nil
}

func parseVolume(data []byte, offset uint64, limits Limits) (volumeInfo, error) {
	if len(data) < volumeMinimumBytes {
		return volumeInfo{}, corrupt(offset, "volume section is shorter than 24 bytes")
	}
	volume := volumeInfo{
		mediaType:       data[0],
		sectorsPerChunk: binary.LittleEndian.Uint32(data[8:12]),
		bytesPerSector:  binary.LittleEndian.Uint32(data[12:16]),
		sectorCount:     binary.LittleEndian.Uint64(data[16:24]),
	}
	if volume.sectorsPerChunk == 0 || volume.bytesPerSector == 0 {
		return volumeInfo{}, corrupt(offset, fmt.Sprintf(
			"volume chunk geometry is zero (sectors_per_chunk=%d, bytes_per_sector=%d)",
			volume.sectorsPerChunk, volume.bytesPerSector))
	}
	chunkSize, ok := checkedMul(uint64(volume.sectorsPerChunk), uint64(volume.bytesPerSector))
	if !ok {
		return volumeInfo{}, corrupt(offset, "volume chunk size overflows")
	}
	volume.chunkSize = chunkSize
	if chunkSize > limits.MaxChunkSize {
		return volumeInfo{}, unsupported(fmt.Sprintf(
			"chunk size %d exceeds the configured bound %d", chunkSize, limits.MaxChunkSize))
	}
	if len(data) >= volumeMaximumReadBytes {
		stored := binary.LittleEndian.Uint32(data[volumeChecksumFieldOffset:volumeMaximumReadBytes])
		if stored != 0 {
			computed := adler32Checksum(data[:volumeChecksumFieldOffset])
			if stored != computed {
				return volumeInfo{}, corrupt(offset+volumeChecksumFieldOffset, fmt.Sprintf(
					"volume section Adler-32 mismatch: stored %08x, computed %08x", stored, computed))
			}
		}
	}
	return volume, nil
}

func parseCatalogSection(segments []segment, limits Limits) (catalog, []string, error) {
	var warnings []string
	var found catalog
	seen := 0
	for _, segment := range segments {
		for _, section := range segment.sections {
			if section.kind != "ltree" {
				continue
			}
			seen++
			if seen > 1 {
				warnings = append(warnings, fmt.Sprintf(
					"segment %d: additional ltree section at %d ignored",
					segment.number, section.descriptorOffset))
				continue
			}
			maxSectionSize, ok := checkedAdd(limits.MaxLTreeBytes, LTreeHeaderBytes)
			if !ok || section.dataSize > maxSectionSize {
				return catalog{}, nil, unsupported(fmt.Sprintf(
					"ltree section of %d bytes exceeds the configured bound %d",
					section.dataSize, limits.MaxLTreeBytes))
			}
			data, err := source.ReadVecAt(segment.source, section.dataOffset, section.dataSize)
			if err != nil {
				return catalog{}, nil, err
			}
			parsed, err := parseLTree(data, limits, &warnings)
			if err != nil {
				return catalog{}, nil, err
			}
			found = parsed
		}
	}
	if seen == 0 {
		return catalog{}, nil, corrupt(0,
			"L01 has no ltree catalog section; the file/directory tree is unavailable")
	}
	return found, warnings, nil
}

func validateEntryRanges(entries []Entry, mediaSize uint64) error {
	for index := range entries {
		entry := &entries[index]
		for extentIndex, extent := range entry.Extents {
			if extent.Sparse {
				continue
			}
			end, ok := checkedAdd(extent.Offset, extent.Size)
			if !ok {
				return corrupt(extent.Offset, fmt.Sprintf(
					"L01 entry %d extent %d offset overflows", entry.Index, extentIndex))
			}
			if end > mediaSize {
				return corrupt(extent.Offset, fmt.Sprintf(
					"L01 entry %d extent %d covers [%d, %d) but the logical media is %d bytes",
					entry.Index, extentIndex, extent.Offset, end, mediaSize))
			}
		}
		if entry.DuplicateDataOffset != nil && *entry.DuplicateDataOffset >= 0 {
			sourceOffset := uint64(*entry.DuplicateDataOffset)
			size := uint64(0)
			if entry.Size != nil {
				size = *entry.Size
			}
			end, ok := checkedAdd(sourceOffset, size)
			if !ok {
				return corrupt(sourceOffset, fmt.Sprintf(
					"L01 entry %d data offset overflows", entry.Index))
			}
			if end > mediaSize {
				return corrupt(sourceOffset, fmt.Sprintf(
					"L01 entry %d data range [%d, %d) lies past the %d-byte logical media",
					entry.Index, sourceOffset, end, mediaSize))
			}
		}
	}
	return nil
}

func buildChunks(segments []segment, chunkSize uint64, hasChunkSize bool,
	mediaSize uint64, hasMediaSize bool, limits Limits, warnings *[]string) ([]chunkRef, error) {

	hasTable := false
	for _, segment := range segments {
		for _, section := range segment.sections {
			if section.kind == "table" || section.kind == "table2" {
				hasTable = true
				break
			}
		}
		if hasTable {
			break
		}
	}
	if !hasTable {
		*warnings = append(*warnings, "L01 has no table/table2 section; no chunk data is addressable")
		return nil, nil
	}
	if !hasChunkSize {
		return nil, corrupt(0, "L01 has chunk tables but no volume section describing the chunk size")
	}

	var chunks []chunkRef
	beyondMedia := false
	for segmentIndex, segment := range segments {
		standard := make([]section, 0, 2)
		for _, section := range segment.sections {
			if section.kind == "table" {
				standard = append(standard, section)
			}
		}
		tables := standard
		if len(tables) == 0 {
			for _, section := range segment.sections {
				if section.kind == "table2" {
					tables = append(tables, section)
				}
			}
		}
		for _, table := range tables {
			if err := parseTable(segment, segmentIndex, table, chunkSize, mediaSize, hasMediaSize,
				limits, warnings, &chunks, &beyondMedia); err != nil {
				return nil, err
			}
		}
	}
	if beyondMedia {
		*warnings = append(*warnings,
			"chunk tables contain entries beyond the recorded logical media size; they were not applied")
	}
	return chunks, nil
}

func parseTable(segment segment, segmentIndex int, table section, chunkSize uint64,
	mediaSize uint64, hasMediaSize bool, limits Limits, warnings *[]string,
	chunks *[]chunkRef, beyondMedia *bool) error {

	if table.dataSize < 24 {
		return corrupt(table.dataOffset, fmt.Sprintf(
			"table section is truncated: %d data bytes, needs at least 24", table.dataSize))
	}
	header, err := source.ReadVecAt(segment.source, table.dataOffset, 24)
	if err != nil {
		return err
	}
	entryCount := uint64(binary.LittleEndian.Uint32(header[0:4]))
	baseOffset := binary.LittleEndian.Uint64(header[8:16])
	storedChecksum := binary.LittleEndian.Uint32(header[20:24])
	if storedChecksum != 0 {
		computed := adler32Checksum(header[:20])
		if storedChecksum != computed {
			return corrupt(table.dataOffset+20, fmt.Sprintf(
				"table header Adler-32 mismatch: stored %08x, computed %08x", storedChecksum, computed))
		}
	}
	if entryCount == 0 {
		return nil
	}
	if entryCount > uint64(limits.MaxChunks) {
		return unsupported(fmt.Sprintf(
			"table declares %d chunks, above the configured bound %d", entryCount, limits.MaxChunks))
	}
	total, ok := checkedAdd(uint64(len(*chunks)), entryCount)
	if !ok || total > uint64(limits.MaxChunks) {
		return unsupported(fmt.Sprintf(
			"total chunk count exceeds the configured bound %d", limits.MaxChunks))
	}

	entryBytes, ok := checkedMul(entryCount, 4)
	if !ok {
		return corrupt(table.dataOffset, "table entry bytes overflow")
	}
	entriesOffset, ok := checkedAdd(table.dataOffset, 24)
	if !ok {
		return corrupt(table.dataOffset, "table entry offset overflows")
	}
	entriesEnd, ok := checkedAdd(entriesOffset, entryBytes)
	if !ok {
		return corrupt(table.dataOffset, "table entry range overflows")
	}
	sectionEnd, ok := checkedAdd(table.dataOffset, table.dataSize)
	if !ok {
		return corrupt(table.dataOffset, "table section range overflows")
	}
	if entriesEnd > sectionEnd {
		return corrupt(entriesOffset, "table entries extend beyond the table section")
	}
	entries, err := source.ReadVecAt(segment.source, entriesOffset, entryBytes)
	if err != nil {
		return err
	}

	firstRaw := binary.LittleEndian.Uint32(entries[0:4])
	firstRelative := uint64(firstRaw & 0x7fff_ffff)
	tableResidentWithoutFooter := baseOffset == 0 && firstRelative == entriesEnd
	if !tableResidentWithoutFooter {
		if footerEnd, ok := checkedAdd(entriesEnd, 4); ok && footerEnd <= sectionEnd {
			footer, err := source.ReadVecAt(segment.source, entriesEnd, 4)
			if err != nil {
				return err
			}
			stored := binary.LittleEndian.Uint32(footer)
			if stored != 0 {
				computed := adler32Checksum(entries)
				if stored != computed {
					return corrupt(entriesEnd, fmt.Sprintf(
						"table entries Adler-32 mismatch: stored %08x, computed %08x", stored, computed))
				}
			}
		}
	}

	dataEnd, ok := sectorsDataEnd(segment, baseOffset, firstRelative)
	if !ok {
		if baseOffset != 0 {
			return corrupt(table.dataOffset, fmt.Sprintf(
				"table base offset %d is not inside a sectors section of segment %d",
				baseOffset, segment.number))
		}
		dataEnd = sectionEnd
	}

	type decodedChunk struct {
		offset     uint64
		compressed bool
	}
	decoded := make([]decodedChunk, 0, entryCount)
	for position := 0; position < int(entryCount); position++ {
		raw := binary.LittleEndian.Uint32(entries[position*4:])
		compressed := raw&0x8000_0000 != 0
		relative := uint64(raw & 0x7fff_ffff)
		offset := relative
		if baseOffset != 0 {
			computed, ok := checkedAdd(baseOffset, relative)
			if !ok {
				return corrupt(table.dataOffset, fmt.Sprintf(
					"table chunk offset overflows at base %d + %d", baseOffset, relative))
			}
			offset = computed
		}
		decoded = append(decoded, decodedChunk{offset: offset, compressed: compressed})
	}

	for localIndex, chunk := range decoded {
		next := dataEnd
		if localIndex+1 < len(decoded) {
			next = decoded[localIndex+1].offset
		}
		if next <= chunk.offset {
			return corrupt(chunk.offset, fmt.Sprintf(
				"table chunk %d offset %d is not below the next chunk offset %d",
				localIndex, chunk.offset, next))
		}
		encodedSize := next - chunk.offset
		if next > segment.source.Len() {
			return corrupt(chunk.offset, fmt.Sprintf(
				"table chunk %d range [%d, %d) is outside segment %d",
				localIndex, chunk.offset, next, segment.number))
		}
		if baseOffset == 0 && chunk.offset < entriesEnd {
			return corrupt(chunk.offset, fmt.Sprintf(
				"table-resident chunk %d at %d overlaps table metadata ending at %d",
				localIndex, chunk.offset, entriesEnd))
		}
		encoding, err := classifyChunkEncoding(chunk.compressed, encodedSize, chunkSize)
		if err != nil {
			return err
		}
		rawCap, _ := checkedAdd(chunkSize, adlerChunkTrailerBytes)
		zlibCap, err := zlibSizeCap(chunkSize)
		if err != nil {
			return err
		}
		switch {
		case encoding == encodingStored && encodedSize > rawCap:
			*warnings = append(*warnings, fmt.Sprintf(
				"stored chunk %d in segment %d has %d bytes, above the %d-byte stored bound",
				localIndex, segment.number, encodedSize, rawCap))
		case encoding == encodingZlib && encodedSize > zlibCap:
			return corrupt(chunk.offset, fmt.Sprintf(
				"compressed chunk %d has %d bytes, above the zlib bound %d",
				localIndex, encodedSize, zlibCap))
		}

		if hasMediaSize {
			start, ok := checkedMul(uint64(len(*chunks)), chunkSize)
			if !ok {
				return unsupported("L01 chunk logical offset overflows")
			}
			if start >= mediaSize {
				*beyondMedia = true
				break
			}
			logicalSize := mediaSize - start
			if logicalSize > chunkSize {
				logicalSize = chunkSize
			}
			if logicalSize > uint64(maxInt()) {
				return unsupported("L01 chunk logical size does not fit the host address space")
			}
			*chunks = append(*chunks, chunkRef{
				segment:     segmentIndex,
				offset:      chunk.offset,
				encodedSize: encodedSize,
				logicalSize: int(logicalSize),
				encoding:    encoding,
			})
		} else {
			if chunkSize > uint64(maxInt()) {
				return unsupported("L01 chunk size does not fit the host address space")
			}
			*chunks = append(*chunks, chunkRef{
				segment:     segmentIndex,
				offset:      chunk.offset,
				encodedSize: encodedSize,
				logicalSize: int(chunkSize),
				encoding:    encoding,
			})
		}
	}
	return nil
}

func classifyChunkEncoding(compressed bool, encodedSize, chunkSize uint64) (chunkEncoding, error) {
	if compressed {
		return encodingZlib, nil
	}
	rawCap, _ := checkedAdd(chunkSize, adlerChunkTrailerBytes)
	zlibCap, err := zlibSizeCap(chunkSize)
	if err != nil {
		return encodingStored, err
	}
	if encodedSize > rawCap && encodedSize <= zlibCap {
		return encodingZlib, nil
	}
	return encodingStored, nil
}

func zlibSizeCap(chunkSize uint64) (uint64, error) {
	compressBound, ok := checkedAdd(chunkSize, chunkSize>>12)
	if !ok {
		return 0, unsupported("zlib chunk size bound overflows")
	}
	add, ok := checkedAdd(compressBound, chunkSize>>14)
	if !ok {
		return 0, unsupported("zlib chunk size bound overflows")
	}
	compressBound, ok = checkedAdd(add, chunkSize>>25)
	if !ok {
		return 0, unsupported("zlib chunk size bound overflows")
	}
	compressBound, ok = checkedAdd(compressBound, 13)
	if !ok {
		return 0, unsupported("zlib chunk size bound overflows")
	}

	storedBlocks, ok := checkedAdd(chunkSize, 511)
	if !ok {
		return 0, unsupported("zlib stored-block count overflows")
	}
	storedBlocks /= 512
	storedExtra, ok := checkedMul(storedBlocks, 5)
	if !ok {
		return 0, unsupported("zlib stored-block bound overflows")
	}
	storedBound, ok := checkedAdd(chunkSize, storedExtra)
	if !ok {
		return 0, unsupported("zlib stored-block bound overflows")
	}
	storedBound, ok = checkedAdd(storedBound, 6)
	if !ok {
		return 0, unsupported("zlib stored-block bound overflows")
	}
	if compressBound > storedBound {
		return compressBound, nil
	}
	return storedBound, nil
}

func sectorsDataEnd(segment segment, baseOffset, firstRelative uint64) (uint64, bool) {
	if baseOffset != 0 {
		for _, section := range segment.sections {
			if section.kind != "sectors" {
				continue
			}
			sectionEnd, _ := checkedAdd(section.dataOffset, section.dataSize)
			if baseOffset == section.descriptorOffset ||
				(baseOffset >= section.dataOffset && baseOffset <= sectionEnd) {
				return sectionEnd, true
			}
		}
	}
	absolute := firstRelative
	if baseOffset != 0 {
		computed, ok := checkedAdd(baseOffset, firstRelative)
		if !ok {
			return 0, false
		}
		absolute = computed
	}
	for _, section := range segment.sections {
		if section.kind != "sectors" {
			continue
		}
		sectionEnd, _ := checkedAdd(section.dataOffset, section.dataSize)
		if absolute >= section.dataOffset && absolute <= sectionEnd {
			return sectionEnd, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Image accessors and reads
// ---------------------------------------------------------------------------

// SourceID is the identifier of the first segment source.
func (img *Image) SourceID() source.ID { return img.id }

// Limits returns the bounds in force for this image.
func (img *Image) Limits() Limits { return img.limits }

// Children returns the child indices of one entry, in catalog order.
func (img *Image) Children(index int) []int {
	if index < 0 || index >= len(img.entries) {
		return nil
	}
	return append([]int(nil), img.entries[index].Children...)
}

// Info returns a snapshot of the container/report metadata.
func (img *Image) Info() Info {
	info := img.info
	info.SegmentNumbers = append([]uint16(nil), info.SegmentNumbers...)
	info.Warnings = append([]string(nil), info.Warnings...)
	info.Sources = append([]SourceRecord(nil), info.Sources...)
	info.Subjects = append([]Subject(nil), info.Subjects...)
	if info.SectionTypes != nil {
		types := make(map[string]int, len(info.SectionTypes))
		for kind, count := range info.SectionTypes {
			types[kind] = count
		}
		info.SectionTypes = types
	}
	return info
}

// Entries returns the catalog in catalog order: the root first, each parent
// before its children. Path is the recorded-name path from the catalog root.
func (img *Image) Entries() ([]Entry, error) {
	entries := make([]Entry, len(img.entries))
	for index := range img.entries {
		entries[index] = cloneEntry(img.entries[index])
	}
	return entries, nil
}

// Entry returns one entry by index.
func (img *Image) Entry(index int) (Entry, bool) {
	if index < 0 || index >= len(img.entries) {
		return Entry{}, false
	}
	return cloneEntry(img.entries[index]), true
}

// Root returns the catalog root index.
func (img *Image) Root() (int, bool) {
	if len(img.entries) == 0 {
		return 0, false
	}
	return img.root, true
}

// ChunkSize returns the declared chunk size.
func (img *Image) ChunkSize() (uint64, bool) { return img.chunkSize, img.hasChunkSize }

// LogicalMediaSize returns the effective logical media size.
func (img *Image) LogicalMediaSize() (uint64, bool) { return img.mediaSize, img.hasMediaSize }

// DeletedEntries returns the entries whose catalog row carries a `dl` value.
func (img *Image) DeletedEntries() []Entry {
	deleted := make([]Entry, 0, 1)
	for index := range img.entries {
		if img.entries[index].DeletionTime != nil {
			deleted = append(deleted, cloneEntry(img.entries[index]))
		}
	}
	return deleted
}

// OpenFile opens the entry at path as a random-access source. The path is the
// recorded-name path from the catalog root; a leading slash is optional.
// Duplicate paths are refused as ambiguous rather than resolved by guessing.
func (img *Image) OpenFile(path string, id source.ID) (source.ByteSource, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty path", ErrNotFound)
	}
	indices, ok := img.paths[path]
	if !ok && !strings.HasPrefix(path, "/") {
		indices, ok = img.paths["/"+path]
	}
	if !ok || len(indices) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, path)
	}
	if len(indices) > 1 {
		return nil, fmt.Errorf("%w: %q matches %d entries", ErrAmbiguousPath, path, len(indices))
	}
	return img.OpenEntry(indices[0], id)
}

// OpenEntry opens one catalog entry index as a random-access source.
func (img *Image) OpenEntry(index int, id source.ID) (source.ByteSource, error) {
	if index < 0 || index >= len(img.entries) {
		return nil, invalidArgument(fmt.Sprintf("L01 entry index %d does not exist", index))
	}
	entry := &img.entries[index]
	if entry.Size == nil {
		return nil, invalidArgument(fmt.Sprintf(
			"L01 entry %d carries no logical size (`ls`); it has no content to read", index))
	}
	size := *entry.Size
	sparse := entry.Flags != nil && *entry.Flags&SparseFlag != 0
	if size > 0 && !sparse && len(entry.Extents) == 0 && entry.DuplicateDataOffset == nil {
		return nil, corrupt(0, fmt.Sprintf(
			"L01 entry %d carries neither extents nor a duplicate-data offset", index))
	}
	return &entrySource{reader: img, index: index, size: size, id: id}, nil
}

// ReadEntryData reads a whole entry's declared content, bounded by
// Limits.MaxEntryReadBytes.
func (img *Image) ReadEntryData(index int) ([]byte, error) {
	if index < 0 || index >= len(img.entries) {
		return nil, invalidArgument(fmt.Sprintf("L01 entry index %d does not exist", index))
	}
	entry := &img.entries[index]
	if entry.Size == nil {
		return nil, corrupt(0, fmt.Sprintf("L01 entry %d carries no logical size (`ls`)", index))
	}
	size := *entry.Size
	if size > img.limits.MaxEntryReadBytes {
		return nil, unsupported(fmt.Sprintf(
			"entry %d size %d exceeds the configured read bound %d",
			index, size, img.limits.MaxEntryReadBytes))
	}
	if size > uint64(maxInt()) {
		return nil, unsupported(fmt.Sprintf(
			"entry %d size %d does not fit the host address space", index, size))
	}
	data := make([]byte, int(size))
	read, err := img.readEntryDataAt(index, 0, data)
	if err != nil {
		return nil, err
	}
	if uint64(read) != size {
		return nil, corrupt(0, fmt.Sprintf(
			"L01 entry %d data ends after %d of %d bytes", index, read, size))
	}
	return data, nil
}

// ReadEntryDataAt reads part of one entry's content. offset is relative to the
// start of the entry.
func (img *Image) ReadEntryDataAt(index int, offset uint64, buf []byte) (int, error) {
	return img.readEntryDataAt(index, offset, buf)
}

// ReadMediaAt reads bytes of the logical media stream.
func (img *Image) ReadMediaAt(offset uint64, buf []byte) (int, error) {
	return img.readMediaInto(offset, buf)
}

// VerifyEntryHashes recomputes the declared MD5/SHA-1 from the reassembled
// entry content. A digest the catalog does not carry is NotDeclared.
func (img *Image) VerifyEntryHashes(index int) (EntryHashes, error) {
	if index < 0 || index >= len(img.entries) {
		return EntryHashes{}, invalidArgument(fmt.Sprintf("L01 entry index %d does not exist", index))
	}
	entry := &img.entries[index]
	if entry.MD5 == "" && entry.SHA1 == "" {
		return EntryHashes{MD5: HashCheck{Status: HashNotDeclared}, SHA1: HashCheck{Status: HashNotDeclared}}, nil
	}
	data, err := img.ReadEntryData(index)
	if err != nil {
		return EntryHashes{}, err
	}
	result := EntryHashes{BytesHashed: uint64(len(data))}
	if entry.MD5 != "" {
		result.MD5 = compareHash(entry.MD5, md5Hex(data))
	} else {
		result.MD5 = HashCheck{Status: HashNotDeclared}
	}
	if entry.SHA1 != "" {
		result.SHA1 = compareHash(entry.SHA1, sha1Hex(data))
	} else {
		result.SHA1 = HashCheck{Status: HashNotDeclared}
	}
	return result, nil
}

func (img *Image) readEntryDataAt(index int, offset uint64, buf []byte) (int, error) {
	if index < 0 || index >= len(img.entries) {
		return 0, invalidArgument(fmt.Sprintf("L01 entry index %d does not exist", index))
	}
	entry := &img.entries[index]
	if entry.Size == nil {
		return 0, corrupt(0, fmt.Sprintf("L01 entry %d carries no logical size (`ls`)", index))
	}
	size := *entry.Size
	if offset >= size || len(buf) == 0 {
		return 0, nil
	}
	want := int(minU64(size-offset, uint64(len(buf))))
	end, ok := checkedAdd(offset, uint64(want))
	if !ok {
		return 0, corrupt(0, fmt.Sprintf(
			"L01 entry %d read range overflows at offset %d", index, offset))
	}

	flags := uint32(0)
	if entry.Flags != nil {
		flags = *entry.Flags
	}
	if flags&SparseFlag != 0 {
		// A duplicate-data offset takes precedence: the stored byte is ignored
		// and the data really lives at that media offset.
		if entry.DuplicateDataOffset != nil && *entry.DuplicateDataOffset >= 0 {
			sourceOffset := uint64(*entry.DuplicateDataOffset)
			sourceOffset, ok = checkedAdd(sourceOffset, offset)
			if !ok {
				return 0, corrupt(0, fmt.Sprintf(
					"L01 entry %d sparse data offset overflows at %d", index, offset))
			}
			return img.readMediaInto(sourceOffset, buf[:want])
		}
		var pattern *Extent
		for extentIndex := range entry.Extents {
			extent := &entry.Extents[extentIndex]
			if !extent.Sparse && extent.Size >= 1 {
				pattern = extent
				break
			}
		}
		if pattern == nil {
			return 0, corrupt(0, fmt.Sprintf(
				"L01 entry %d is sparse but carries neither a data offset nor a stored byte extent", index))
		}
		value, err := img.readMediaByte(pattern.Offset, index)
		if err != nil {
			return 0, err
		}
		for position := 0; position < want; position++ {
			buf[position] = value
		}
		return want, nil
	}

	if len(entry.Extents) > 0 {
		var filePosition uint64
		for extentIndex := range entry.Extents {
			extent := &entry.Extents[extentIndex]
			extentEnd, ok := checkedAdd(filePosition, extent.Size)
			if !ok {
				return 0, corrupt(0, fmt.Sprintf(
					"L01 entry %d extent range overflows at %d", index, filePosition))
			}
			readStart := maxU64(filePosition, offset)
			readEnd := minU64(extentEnd, end)
			if readStart < readEnd {
				within := readStart - filePosition
				destination := buf[int(readStart-offset):int(readEnd-offset)]
				if extent.Sparse {
					clear(destination)
				} else {
					sourceOffset, ok := checkedAdd(extent.Offset, within)
					if !ok {
						return 0, corrupt(0, fmt.Sprintf(
							"L01 entry %d extent source offset overflows at %d", index, within))
					}
					if _, err := img.readMediaInto(sourceOffset, destination); err != nil {
						return 0, err
					}
				}
			}
			filePosition = extentEnd
			if filePosition >= end {
				break
			}
		}
		if filePosition < end {
			return 0, corrupt(0, fmt.Sprintf(
				"L01 entry %d extents cover %d bytes but the read needs %d",
				index, filePosition, end))
		}
		return want, nil
	}

	if entry.DuplicateDataOffset != nil {
		if *entry.DuplicateDataOffset < 0 {
			return 0, corrupt(0, fmt.Sprintf(
				"L01 entry %d carries a negative duplicate-data offset %d",
				index, *entry.DuplicateDataOffset))
		}
		sourceOffset := uint64(*entry.DuplicateDataOffset)
		sourceOffset, ok = checkedAdd(sourceOffset, offset)
		if !ok {
			return 0, corrupt(0, fmt.Sprintf(
				"L01 entry %d data offset overflows at %d", index, offset))
		}
		return img.readMediaInto(sourceOffset, buf[:want])
	}

	return 0, corrupt(0, fmt.Sprintf(
		"L01 entry %d carries neither extents nor a duplicate-data offset", index))
}

func (img *Image) readMediaByte(offset uint64, entryIndex int) (byte, error) {
	var value [1]byte
	if _, err := img.readMediaInto(offset, value[:]); err != nil {
		if errors.Is(err, source.ErrOutOfRange) {
			return 0, corrupt(0, fmt.Sprintf(
				"L01 entry %d sparse pattern offset %d is outside the logical media",
				entryIndex, offset))
		}
		return 0, err
	}
	return value[0], nil
}

func (img *Image) readMediaInto(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if !img.hasMediaSize {
		return 0, corrupt(0, "L01 logical media size is not recorded by the catalog")
	}
	if offset >= img.mediaSize {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), img.mediaSize)
	}
	want := int(minU64(img.mediaSize-offset, uint64(len(buf))))
	if !img.hasChunkSize {
		return 0, corrupt(0, "L01 has chunks but no volume section describing their size")
	}
	if img.chunkSize == 0 {
		return 0, corrupt(0, "L01 volume declares a zero chunk size")
	}

	done := 0
	mediaOffset := offset
	for done < want {
		chunkIndex := mediaOffset / img.chunkSize
		within := mediaOffset % img.chunkSize
		if chunkIndex >= uint64(len(img.chunks)) {
			return 0, corrupt(mediaOffset, fmt.Sprintf(
				"L01 chunk %d is missing from the chunk table", chunkIndex))
		}
		chunk := &img.chunks[chunkIndex]
		if within >= uint64(chunk.logicalSize) {
			return 0, corrupt(mediaOffset, fmt.Sprintf(
				"L01 chunk %d holds %d bytes but the read starts at byte %d",
				chunkIndex, chunk.logicalSize, within))
		}
		take := int(minU64(uint64(chunk.logicalSize)-within, uint64(want-done)))
		decoded, err := img.decodeChunk(chunkIndex, chunk)
		if err != nil {
			return 0, err
		}
		if len(decoded) < int(within)+take {
			return 0, corrupt(chunk.offset, fmt.Sprintf(
				"L01 chunk %d decoded to %d bytes, short of the %d requested",
				chunkIndex, len(decoded), int(within)+take))
		}
		copy(buf[done:done+take], decoded[int(within):int(within)+take])
		done += take
		mediaOffset += uint64(take)
	}
	return done, nil
}

func (img *Image) decodeChunk(index uint64, chunk *chunkRef) ([]byte, error) {
	segment := &img.segments[chunk.segment]
	end, ok := checkedAdd(chunk.offset, chunk.encodedSize)
	if !ok {
		return nil, corrupt(chunk.offset, "L01 chunk range overflows")
	}
	if end > segment.source.Len() {
		return nil, corrupt(chunk.offset, fmt.Sprintf(
			"L01 chunk %d ends at %d beyond its segment length %d",
			index, end, segment.source.Len()))
	}
	encoded, err := source.ReadVecAt(segment.source, chunk.offset, chunk.encodedSize)
	if err != nil {
		return nil, err
	}

	switch chunk.encoding {
	case encodingStored:
		if len(encoded) < chunk.logicalSize {
			return nil, corrupt(chunk.offset, fmt.Sprintf(
				"L01 stored chunk %d has %d bytes, shorter than its %d logical bytes",
				index, len(encoded), chunk.logicalSize))
		}
		if len(encoded) == chunk.logicalSize+adlerChunkTrailerBytes {
			stored := binary.LittleEndian.Uint32(encoded[chunk.logicalSize:])
			computed := adler32Checksum(encoded[:chunk.logicalSize])
			if stored != computed {
				return nil, corrupt(chunk.offset+uint64(chunk.logicalSize), fmt.Sprintf(
					"L01 stored chunk %d Adler-32 mismatch: stored %08x, computed %08x",
					index, stored, computed))
			}
		}
		return append([]byte(nil), encoded[:chunk.logicalSize]...), nil
	case encodingZlib:
		if !img.hasChunkSize {
			return nil, corrupt(0,
				"L01 has compressed chunks but no volume section describing their size")
		}
		decoded, err := zlibDecode(encoded, img.chunkSize)
		if err != nil {
			return nil, corrupt(chunk.offset, fmt.Sprintf(
				"L01 zlib chunk %d could not be decoded: %v", index, err))
		}
		if len(decoded) < chunk.logicalSize {
			return nil, corrupt(chunk.offset, fmt.Sprintf(
				"L01 zlib chunk %d decoded to %d bytes, shorter than its %d logical bytes",
				index, len(decoded), chunk.logicalSize))
		}
		return decoded[:chunk.logicalSize], nil
	default:
		return nil, corrupt(chunk.offset, "L01 chunk carries an unknown encoding")
	}
}

func zlibDecode(encoded []byte, limit uint64) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	readLimit := uint64(^uint64(0)>>1) - 1
	if limit < readLimit {
		readLimit = limit
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(readLimit)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(decoded)) > limit {
		return nil, fmt.Errorf("decompressed size exceeds %d bytes", limit)
	}
	return decoded, nil
}

// ---------------------------------------------------------------------------
// Entry source
// ---------------------------------------------------------------------------

type entrySource struct {
	reader   *Image
	index    int
	size     uint64
	id       source.ID
	counters source.Counters
}

var _ source.ByteSource = (*entrySource)(nil)

// SourceID implements source.ByteSource.
func (s *entrySource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *entrySource) Len() uint64 { return s.size }

// ImageID implements source.ByteSource. The entry's bytes ultimately live in
// the first segment's image.
func (s *entrySource) ImageID() source.ImageID { return s.reader.imageID }

// SectorSize implements source.ByteSource.
func (s *entrySource) SectorSize() uint32 { return s.reader.sectorSize }

// ReadAt implements source.ByteSource. Sparse regions return their recorded
// zeroes/repeated byte; a missing or undecodable chunk is an error, never a
// zero-filled range.
func (s *entrySource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.size)
	}
	want := int(minU64(s.size-offset, uint64(len(buf))))
	read, err := s.reader.readEntryDataAt(s.index, offset, buf[:want])
	if err != nil {
		s.counters.AddError()
		return 0, err
	}
	s.counters.AddRead(read)
	return read, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode: a damaged read
// zero-fills the requested range and is accounted as corrupt, so carving can
// continue. Strict reads still fail loudly.
func (s *entrySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.size)
	}
	want := int(minU64(s.size-offset, uint64(len(buf))))
	read, err := s.ReadAt(offset, buf[:want])
	if err != nil {
		clear(buf[:want])
		s.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return read, nil
}

// ExtentsInto implements source.ByteSource.
func (s *entrySource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.checkBounds(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	pieces, err := s.reader.entryMediaPieces(&s.reader.entries[s.index], offset, length)
	if err != nil {
		return out, err
	}
	for _, piece := range pieces {
		switch piece.kind {
		case pieceData:
			out = append(out, source.ParentRange{
				Parent: s.reader.id, ParentOffset: piece.media, Len: piece.length, Kind: source.RangeData,
			})
		case pieceZero:
			out = append(out, source.ParentRange{
				Parent: s.reader.id, ParentOffset: 0, Len: piece.length, Kind: source.RangeZero,
			})
		case piecePattern:
			out = append(out, source.ParentRange{
				Parent: s.reader.id, ParentOffset: piece.media, Len: piece.length, Kind: source.RangeDerived,
			})
		}
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *entrySource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource. Stored chunks map byte for byte; a
// zlib chunk maps to the stored compressed stream that produced it.
func (s *entrySource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.checkBounds(offset, length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	pieces, err := s.reader.entryMediaPieces(&s.reader.entries[s.index], offset, length)
	if err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, piece := range pieces {
		switch piece.kind {
		case pieceData:
			ranges, err := s.reader.mediaImageRanges(piece.media, piece.length)
			if err != nil {
				return nil, err
			}
			out = append(out, ranges...)
		case pieceZero:
			out = append(out, source.ImageRange{
				ImageID: s.reader.imageID, ImageOffset: 0, Len: piece.length, Kind: source.RangeZero,
			})
		case piecePattern:
			sourceOffset := uint64(0)
			if ranges, err := s.reader.mediaImageRanges(piece.media, 1); err == nil && len(ranges) > 0 {
				sourceOffset = ranges[0].ImageOffset
			}
			out = append(out, source.ImageRange{
				ImageID: s.reader.imageID, ImageOffset: sourceOffset, Len: piece.length, Kind: source.RangeDerived,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (s *entrySource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *entrySource) IsEmpty() bool { return s.size == 0 }

func (s *entrySource) checkBounds(offset, length uint64) error {
	if offset > s.size || length > s.size-offset {
		return source.NewOutOfRange(offset, length, s.size)
	}
	return nil
}

func (img *Image) mediaImageRanges(offset, length uint64) ([]source.ImageRange, error) {
	if length == 0 {
		return nil, nil
	}
	if !img.hasMediaSize {
		return nil, corrupt(0, "L01 logical media size is not recorded by the catalog")
	}
	mediaSize := img.mediaSize
	if offset > mediaSize || length > mediaSize-offset {
		return nil, source.NewOutOfRange(offset, length, mediaSize)
	}
	if !img.hasChunkSize {
		return nil, corrupt(0, "L01 has chunks but no volume section describing their size")
	}
	if img.chunkSize == 0 {
		return nil, corrupt(0, "L01 volume declares a zero chunk size")
	}

	var out []source.ImageRange
	media := offset
	end := offset + length
	for media < end {
		chunkIndex := media / img.chunkSize
		within := media % img.chunkSize
		if chunkIndex >= uint64(len(img.chunks)) {
			return nil, corrupt(media, fmt.Sprintf(
				"L01 chunk %d is missing from the chunk table", chunkIndex))
		}
		chunk := &img.chunks[chunkIndex]
		if within >= uint64(chunk.logicalSize) {
			return nil, corrupt(media, fmt.Sprintf(
				"L01 chunk %d holds %d bytes but the range starts at byte %d",
				chunkIndex, chunk.logicalSize, within))
		}
		take := minU64(uint64(chunk.logicalSize)-within, end-media)
		segment := &img.segments[chunk.segment]
		switch chunk.encoding {
		case encodingStored:
			imageOffset, ok := checkedAdd(chunk.offset, within)
			if !ok {
				return nil, corrupt(media, "L01 stored chunk image offset overflows")
			}
			ranges, err := segment.source.MapToImage(imageOffset, take)
			if err != nil {
				return nil, err
			}
			out = append(out, ranges...)
		case encodingZlib:
			ranges, err := segment.source.MapToImage(chunk.offset, chunk.encodedSize)
			if err != nil {
				return nil, err
			}
			out = append(out, ranges...)
		}
		media += take
	}
	return out, nil
}

type mediaPieceKind uint8

const (
	pieceData mediaPieceKind = iota
	pieceZero
	piecePattern
)

type mediaPiece struct {
	kind   mediaPieceKind
	media  uint64
	length uint64
}

func (img *Image) entryMediaPieces(entry *Entry, offset, length uint64) ([]mediaPiece, error) {
	var pieces []mediaPiece
	end := offset + length
	flags := uint32(0)
	if entry.Flags != nil {
		flags = *entry.Flags
	}

	if flags&SparseFlag != 0 {
		if entry.DuplicateDataOffset != nil && *entry.DuplicateDataOffset >= 0 {
			sourceOffset := uint64(*entry.DuplicateDataOffset)
			media, ok := checkedAdd(sourceOffset, offset)
			if !ok {
				return nil, corrupt(0, fmt.Sprintf(
					"L01 entry %d sparse data offset overflows at %d", entry.Index, offset))
			}
			pieces = append(pieces, mediaPiece{kind: pieceData, media: media, length: length})
			return pieces, nil
		}
		var pattern *Extent
		for extentIndex := range entry.Extents {
			extent := &entry.Extents[extentIndex]
			if !extent.Sparse && extent.Size >= 1 {
				pattern = extent
				break
			}
		}
		if pattern == nil {
			return nil, corrupt(0, fmt.Sprintf(
				"L01 entry %d is sparse but carries neither a data offset nor a stored byte extent",
				entry.Index))
		}
		pieces = append(pieces, mediaPiece{kind: piecePattern, media: pattern.Offset, length: length})
		return pieces, nil
	}

	if len(entry.Extents) > 0 {
		var filePosition uint64
		for extentIndex := range entry.Extents {
			extent := &entry.Extents[extentIndex]
			extentEnd, ok := checkedAdd(filePosition, extent.Size)
			if !ok {
				return nil, corrupt(0, fmt.Sprintf(
					"L01 entry %d extent range overflows at %d", entry.Index, filePosition))
			}
			readStart := maxU64(filePosition, offset)
			readEnd := minU64(extentEnd, end)
			if readStart < readEnd {
				take := readEnd - readStart
				if extent.Sparse {
					pieces = append(pieces, mediaPiece{kind: pieceZero, length: take})
				} else {
					within := readStart - filePosition
					media, ok := checkedAdd(extent.Offset, within)
					if !ok {
						return nil, corrupt(0, fmt.Sprintf(
							"L01 entry %d extent source offset overflows at %d", entry.Index, within))
					}
					pieces = append(pieces, mediaPiece{kind: pieceData, media: media, length: take})
				}
			}
			filePosition = extentEnd
			if filePosition >= end {
				break
			}
		}
		if filePosition < end {
			return nil, corrupt(0, fmt.Sprintf(
				"L01 entry %d extents cover %d bytes but the range needs %d",
				entry.Index, filePosition, end))
		}
		return pieces, nil
	}

	if entry.DuplicateDataOffset != nil {
		if *entry.DuplicateDataOffset < 0 {
			return nil, corrupt(0, fmt.Sprintf(
				"L01 entry %d carries a negative duplicate-data offset %d",
				entry.Index, *entry.DuplicateDataOffset))
		}
		sourceOffset := uint64(*entry.DuplicateDataOffset)
		media, ok := checkedAdd(sourceOffset, offset)
		if !ok {
			return nil, corrupt(0, fmt.Sprintf(
				"L01 entry %d data offset overflows at %d", entry.Index, offset))
		}
		pieces = append(pieces, mediaPiece{kind: pieceData, media: media, length: length})
		return pieces, nil
	}

	return nil, corrupt(0, fmt.Sprintf(
		"L01 entry %d carries neither extents nor a duplicate-data offset", entry.Index))
}

func (img *Image) buildPaths() {
	img.paths = make(map[string][]int, len(img.entries))
	for index := range img.entries {
		entry := &img.entries[index]
		switch {
		case entry.Parent < 0:
			if entry.Name == "" {
				entry.Path = "/"
			} else {
				entry.Path = "/" + entry.Name
			}
		default:
			parentPath := "/"
			if entry.Parent >= 0 && entry.Parent < len(img.entries) {
				parentPath = img.entries[entry.Parent].Path
			}
			if parentPath == "/" || parentPath == "" {
				entry.Path = "/" + entry.Name
			} else {
				entry.Path = parentPath + "/" + entry.Name
			}
		}
		img.paths[entry.Path] = append(img.paths[entry.Path], index)
	}
}

func cloneEntry(entry Entry) Entry {
	cloned := entry
	cloned.Children = append([]int(nil), entry.Children...)
	cloned.NameUTF16 = append([]uint16(nil), entry.NameUTF16...)
	cloned.Extents = append([]Extent(nil), entry.Extents...)
	if entry.Size != nil {
		value := *entry.Size
		cloned.Size = &value
	}
	if entry.Flags != nil {
		value := *entry.Flags
		cloned.Flags = &value
	}
	if entry.ID != nil {
		value := *entry.ID
		cloned.ID = &value
	}
	if entry.CreationTime != nil {
		value := *entry.CreationTime
		cloned.CreationTime = &value
	}
	if entry.ModificationTime != nil {
		value := *entry.ModificationTime
		cloned.ModificationTime = &value
	}
	if entry.AccessTime != nil {
		value := *entry.AccessTime
		cloned.AccessTime = &value
	}
	if entry.EntryModificationTime != nil {
		value := *entry.EntryModificationTime
		cloned.EntryModificationTime = &value
	}
	if entry.DeletionTime != nil {
		value := *entry.DeletionTime
		cloned.DeletionTime = &value
	}
	if entry.DuplicateDataOffset != nil {
		value := *entry.DuplicateDataOffset
		cloned.DuplicateDataOffset = &value
	}
	if entry.LogicalOffset != nil {
		value := *entry.LogicalOffset
		cloned.LogicalOffset = &value
	}
	if entry.PhysicalOffset != nil {
		value := *entry.PhysicalOffset
		cloned.PhysicalOffset = &value
	}
	if entry.SourceID != nil {
		value := *entry.SourceID
		cloned.SourceID = &value
	}
	if entry.SubjectID != nil {
		value := *entry.SubjectID
		cloned.SubjectID = &value
	}
	if entry.PermissionGroup != nil {
		value := *entry.PermissionGroup
		cloned.PermissionGroup = &value
	}
	if entry.RecordType != nil {
		value := *entry.RecordType
		cloned.RecordType = &value
	}
	return cloned
}

func compareHash(declared, computed string) HashCheck {
	if strings.EqualFold(declared, computed) {
		return HashCheck{Status: HashVerified, Declared: declared, Computed: computed}
	}
	return HashCheck{Status: HashMismatch, Declared: declared, Computed: computed}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func corrupt(offset uint64, reason string) error { return source.NewCorrupt(offset, reason) }

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func invalidArgument(reason string) error {
	return &source.Error{Kind: source.ErrInvalidArgument, Reason: reason}
}

func checkedAdd(left, right uint64) (uint64, bool) {
	sum := left + right
	return sum, sum >= left
}

func checkedMul(left, right uint64) (uint64, bool) {
	if left == 0 || right == 0 {
		return 0, true
	}
	product := left * right
	if product/right != left {
		return 0, false
	}
	return product, true
}

func minU64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

func maxU64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

func maxInt() int { return int(^uint(0) >> 1) }
