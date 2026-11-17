// Package wim reads the Windows Imaging Format (WIM) as a read-only evidence
// container.
//
// A WIM is not a linear disk image: it is a content-addressed blob store plus
// one metadata resource per image describing a directory tree whose files and
// named streams point at SHA-1-addressed blobs. This reader parses the fixed
// header (version 1.13), the blob lookup table, the XML metadata resource, and
// every image's directory tree, and exposes each file or named stream as a
// source.ByteSource.
//
// Compression follows the header: XPRESS Huffman ([MS-XCA] 2.2.4) and LZX are
// decoded, one independent chunk at a time. LZMS/solid images and packed
// resources are refused by name. Split WIMs are not assembled: a spanned
// header or a lookup entry for another part is an explicit
// source.ErrUnsupported naming the missing part. A SHA-1 with no blob is
// listed as unresolved rather than guessed, and opening it is refused.
//
// WIM has no single logical payload. The Container's ByteSource methods
// therefore expose the raw WIM file bytes as a transparent view; the payloads
// that matter are opened with OpenEntry and OpenStream. Every read is
// source-backed: a corrupt or truncated structure is an error, never
// fabricated bytes.
package wim

import (
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Signature is the eight-byte WIM file signature.
const Signature = "MSWIM\x00\x00\x00"

const (
	// HeaderBytes is the only header size this reader decodes.
	HeaderBytes = 208
	// Version1_13 is the WIM version Windows 8.1 through 11 writes.
	Version1_13 = 0x00010D00
	// VersionSolid is the solid/LZMS `.esd` version.
	VersionSolid = 0x00000E00
	// ResourceHeaderBytes is the size of one resource header.
	ResourceHeaderBytes = 24
	// LookupEntryBytes is the size of one blob lookup-table entry.
	LookupEntryBytes = 52
	// DirectoryEntryBytes is the fixed part of a version-1.13 directory entry.
	DirectoryEntryBytes = 102
	// StreamEntryBytes is the fixed part of a named-stream entry.
	StreamEntryBytes = 38

	// MaxLookupBytes bounds the materialized lookup table.
	MaxLookupBytes uint64 = 64 * 1024 * 1024
	// MaxXMLBytes bounds the materialized XML resource.
	MaxXMLBytes uint64 = 32 * 1024 * 1024
	// MaxMetadataBytes bounds one materialized metadata resource.
	MaxMetadataBytes uint64 = 256 * 1024 * 1024
	// MaxEntries bounds the directory entries built for one image.
	MaxEntries = 4_000_000
	// MaxDepth bounds the directory tree depth.
	MaxDepth = 256
	// MaxPathBytes bounds one built path.
	MaxPathBytes = 32_768
	// MaxSecurityEntries bounds the descriptors one metadata resource declares.
	MaxSecurityEntries = 1_000_000
	// MaxLookupEntries bounds the lookup table entries.
	MaxLookupEntries = 4_000_000
	// MaxEntrySize is the per-entry decompression budget, matching the Rust
	// archive defaults.
	MaxEntrySize uint64 = 4 * 1024 * 1024 * 1024
)

// Header flags.
const (
	FlagReadOnly        uint32 = 0x00000001
	FlagCompression     uint32 = 0x00000002
	FlagSpanned         uint32 = 0x00000004
	FlagResourceOnly    uint32 = 0x00000008
	FlagMetadataOnly    uint32 = 0x00000010
	FlagWriteInProgress uint32 = 0x00000020
	FlagRpFix           uint32 = 0x00000040
	FlagXpress          uint32 = 0x00020000
	FlagLzx             uint32 = 0x00040000
	FlagLzms            uint32 = 0x00080000
)

// Resource header flags, in the high byte of the stored-size word.
const (
	ResourceMetadata   uint8 = 0x02
	ResourceCompressed uint8 = 0x04
	ResourceSpanned    uint8 = 0x08
	ResourcePacked     uint8 = 0x10
)

// File attribute bits.
const (
	AttributeDirectory    uint32 = 0x00000010
	AttributeReparsePoint uint32 = 0x00000400
)

const (
	noSecurityID     uint32 = 0xFFFFFFFF
	filetimeEpochSec int64  = 11_644_473_600
)

// Compression names how a WIM's resources are compressed.
type Compression uint8

const (
	// None stores resources as they are.
	None Compression = iota
	// Xpress is XPRESS Huffman ([MS-XCA] 2.2.4).
	Xpress
	// Lzx is LZX with independent chunks.
	Lzx
	// Lzms is the solid/LZMS codec; it is refused by name.
	Lzms
)

// String returns the compression's name.
func (c Compression) String() string {
	switch c {
	case None:
		return "none"
	case Xpress:
		return "XPRESS Huffman"
	case Lzx:
		return "LZX"
	case Lzms:
		return "LZMS"
	default:
		return "unknown"
	}
}

// Resource is one resource header from the WIM header or lookup table.
type Resource struct {
	// CompressedSize is the low 56 bits of the stored-size word: bytes
	// occupied in the WIM.
	CompressedSize uint64
	// Offset is the byte offset from the start of the WIM file.
	Offset uint64
	// OriginalSize is the size before decompression.
	OriginalSize uint64
	// Flags is the high byte of the stored-size word.
	Flags uint8
}

// IsCompressed reports the RESOURCE_COMPRESSED flag.
func (r Resource) IsCompressed() bool { return r.Flags&ResourceCompressed != 0 }

// IsMetadata reports the RESOURCE_METADATA flag.
func (r Resource) IsMetadata() bool { return r.Flags&ResourceMetadata != 0 }

// IsSpanned reports the RESOURCE_SPANNED flag.
func (r Resource) IsSpanned() bool { return r.Flags&ResourceSpanned != 0 }

// IsPacked reports the RESOURCE_PACKED flag.
func (r Resource) IsPacked() bool { return r.Flags&ResourcePacked != 0 }

// IsAbsent reports an all-zero header, which carries no resource.
func (r Resource) IsAbsent() bool {
	return r.CompressedSize == 0 && r.Offset == 0 && r.OriginalSize == 0 && r.Flags == 0
}

// Info is the decoded WIM header.
type Info struct {
	HeaderSize  uint32
	Version     uint32
	Flags       uint32
	ChunkSize   uint32
	Compression Compression
	GUID        [16]byte
	PartNumber  uint16
	TotalParts  uint16
	ImageCount  uint32
	BootIndex   uint32
	Lookup      Resource
	XML         Resource
	// BootMetadata is the boot image's metadata resource, when present.
	BootMetadata *Resource
	// Integrity is the integrity-table resource, when present. It is not
	// decoded.
	Integrity *Resource
}

// IsReadOnly reports the read-only flag.
func (i Info) IsReadOnly() bool { return i.Flags&FlagReadOnly != 0 }

// IsSpanned reports the spanned flag or more than one part.
func (i Info) IsSpanned() bool { return i.Flags&FlagSpanned != 0 || i.TotalParts > 1 }

// IsResourceOnly reports the resource-only flag.
func (i Info) IsResourceOnly() bool { return i.Flags&FlagResourceOnly != 0 }

// IsMetadataOnly reports the metadata-only flag.
func (i Info) IsMetadataOnly() bool { return i.Flags&FlagMetadataOnly != 0 }

// IsWriteInProgress reports a capture taken mid-write.
func (i Info) IsWriteInProgress() bool { return i.Flags&FlagWriteInProgress != 0 }

// IsReparseFixed reports that the writer applied its reparse-point fixups.
func (i Info) IsReparseFixed() bool { return i.Flags&FlagRpFix != 0 }

// Windows is the Windows edition metadata from one image's <WINDOWS> element.
type Windows struct {
	Architecture     *string
	ProductName      *string
	EditionID        *string
	InstallationType *string
	ProductType      *string
	SuiteMask        *string
	Languages        *string
	SystemRoot       *string
}

// Stream is one named stream (NTFS alternate data stream) beside a file.
type Stream struct {
	Name string
	SHA1 [20]byte
	// Size comes from the lookup table; it is 0 when the hash is zero or
	// unresolved.
	Size     uint64
	Resource *Resource
	// Resolved is false when the hash names no blob in the lookup table.
	Resolved bool
}

// Entry is one directory entry from an image's metadata resource.
type Entry struct {
	// Path is below the image root, '/'-separated.
	Path       string
	Name       string
	ShortName  *string
	Attributes uint32
	// SecurityID indexes the image's security data, when one is named.
	SecurityID *uint32
	Created    uint64
	Accessed   uint64
	Written    uint64
	SHA1       [20]byte
	ReparseTag uint32
	HardLink   uint64
	Streams    []Stream
	// Size is the unnamed stream's size from the lookup table.
	Size     uint64
	Resource *Resource
	// Resolved is false when the unnamed stream's hash is absent.
	Resolved bool
}

// IsDirectory reports the directory attribute.
func (e Entry) IsDirectory() bool { return e.Attributes&AttributeDirectory != 0 }

// IsReparsePoint reports a reparse point.
func (e Entry) IsReparsePoint() bool {
	return e.Attributes&AttributeReparsePoint != 0 || e.ReparseTag != 0
}

// ModifiedUnix returns the last-write time as Unix seconds, when present.
func (e Entry) ModifiedUnix() (int64, bool) {
	if e.Written == 0 {
		return 0, false
	}
	return int64(e.Written/10_000_000) - filetimeEpochSec, true
}

// Image is one image: its XML description, metadata resource and directory
// tree.
type Image struct {
	Index       uint32
	Name        *string
	Description *string
	// Declared counters are the writer's claims, not counts this reader
	// verified.
	DeclaredDirectories     *uint64
	DeclaredFiles           *uint64
	DeclaredTotalBytes      *uint64
	DeclaredHardlinkBytes   *uint64
	Flags                   *string
	Windows                 *Windows
	Metadata                Resource
	SecurityDescriptorCount int
	Entries                 []Entry
}

// Stats are the WIM-level counters.
type Stats struct {
	LookupEntries       int
	Images              int
	Entries             int
	Files               int
	Directories         int
	NamedStreams        int
	SecurityDescriptors int
	// UnresolvedHashes counts entries whose SHA-1 has no blob.
	UnresolvedHashes int
	// PackedResources counts lookup resources using the packed layout.
	PackedResources int
}

// Detect reports whether head starts with the WIM signature.
func Detect(head []byte) bool {
	return len(head) >= len(Signature) && string(head[:len(Signature)]) == Signature
}

var nextSourceID atomic.Uint64

// Container is an opened WIM. Its ByteSource methods expose the raw WIM file;
// use OpenEntry and OpenStream for image payloads.
type Container struct {
	id       source.ID
	parent   source.ByteSource
	info     Info
	images   []Image
	stats    Stats
	byImage  map[uint32]map[string]int
	counters source.Counters
}

// Open parses a WIM and its image metadata.
func Open(src source.ByteSource) (*Container, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	if src.Len() < HeaderBytes {
		return nil, source.NewUnexpectedEOF(0)
	}
	head, err := source.ReadVecAt(src, 0, HeaderBytes)
	if err != nil {
		return nil, err
	}
	info, err := parseHeader(head, src.Len())
	if err != nil {
		return nil, err
	}

	lookupBytes, err := readResource(src, info, info.Lookup, MaxLookupBytes, "lookup table")
	if err != nil {
		return nil, err
	}
	lookup, metadataResources, err := parseLookup(lookupBytes, src.Len())
	if err != nil {
		return nil, err
	}

	xmlBytes, err := readResource(src, info, info.XML, MaxXMLBytes, "XML data")
	if err != nil {
		return nil, err
	}
	xmlImages, err := parseXML(xmlBytes)
	if err != nil {
		return nil, err
	}
	if len(xmlImages) != int(info.ImageCount) {
		return nil, corruptWIM(0x2C, fmt.Sprintf(
			"the header declares %d image(s) but the XML data describes %d",
			info.ImageCount, len(xmlImages)))
	}
	if len(metadataResources) != int(info.ImageCount) {
		return nil, corruptWIM(0x30, fmt.Sprintf(
			"the header declares %d image(s) but the lookup table holds %d metadata resource(s)",
			info.ImageCount, len(metadataResources)))
	}
	if info.ImageCount == 0 {
		return nil, corruptWIM(0x2C, "the WIM declares no images")
	}

	blobs := make(map[[20]byte]Resource)
	for _, entry := range lookup {
		if entry.empty() || entry.resource.IsMetadata() {
			continue
		}
		existing, ok := blobs[entry.sha1]
		if ok && existing != entry.resource {
			return nil, corruptWIM(entry.resource.Offset, fmt.Sprintf(
				"the lookup table names SHA-1 %x with two different resources", entry.sha1))
		}
		blobs[entry.sha1] = entry.resource
	}

	stats := Stats{}
	for _, entry := range lookup {
		if !entry.empty() {
			stats.LookupEntries++
			if entry.resource.IsPacked() {
				stats.PackedResources++
			}
		}
	}

	container := &Container{
		id:      source.ID(nextSourceID.Add(1)),
		parent:  src,
		info:    info,
		byImage: make(map[uint32]map[string]int, info.ImageCount),
	}
	for position, resource := range metadataResources {
		index := uint32(position + 1)
		xmlImage, ok := findXMLImage(xmlImages, index)
		if !ok {
			return nil, corruptWIM(0, fmt.Sprintf("the XML data has no image with index %d", index))
		}
		bytes, err := readResource(src, info, resource, MaxMetadataBytes,
			fmt.Sprintf("metadata for image %d", index))
		if err != nil {
			return nil, err
		}
		securityCount, _, entries, err := parseMetadata(bytes, blobs, &stats)
		if err != nil {
			return nil, err
		}
		stats.SecurityDescriptors += securityCount
		stats.Images++
		for _, entry := range entries {
			if entry.IsDirectory() {
				stats.Directories++
			} else {
				stats.Files++
			}
			stats.NamedStreams += len(entry.Streams)
		}
		stats.Entries += len(entries)

		indexMap := make(map[string]int, len(entries))
		for entryPosition, entry := range entries {
			indexMap[entry.Path] = entryPosition
		}
		container.byImage[index] = indexMap
		container.images = append(container.images, Image{
			Index:                   index,
			Name:                    xmlImage.name,
			Description:             xmlImage.description,
			DeclaredDirectories:     xmlImage.declaredDirectories,
			DeclaredFiles:           xmlImage.declaredFiles,
			DeclaredTotalBytes:      xmlImage.declaredTotalBytes,
			DeclaredHardlinkBytes:   xmlImage.declaredHardlinkBytes,
			Flags:                   xmlImage.flags,
			Windows:                 xmlImage.windows,
			Metadata:                resource,
			SecurityDescriptorCount: securityCount,
			Entries:                 entries,
		})
	}
	container.stats = stats
	return container, nil
}

// Info returns the decoded header.
func (c *Container) Info() Info { return c.info }

// Images returns the images in index order.
func (c *Container) Images() []Image { return c.images }

// WIMStats returns the WIM-level counters.
func (c *Container) WIMStats() Stats { return c.stats }

// Parent returns the underlying source.
func (c *Container) Parent() source.ByteSource { return c.parent }

// OpenEntry opens a file entry (path below the image root) as a ByteSource.
func (c *Container) OpenEntry(imageIndex uint32, path string) (*EntrySource, error) {
	return c.openEntry(imageIndex, path, nil)
}

// OpenStream opens one named stream of a file entry as a ByteSource.
func (c *Container) OpenStream(imageIndex uint32, path, streamName string) (*EntrySource, error) {
	return c.openEntry(imageIndex, path, &streamName)
}

func (c *Container) openEntry(imageIndex uint32, path string, streamName *string) (*EntrySource, error) {
	var image *Image
	for index := range c.images {
		if c.images[index].Index == imageIndex {
			image = &c.images[index]
			break
		}
	}
	if image == nil {
		return nil, corruptWIM(0, fmt.Sprintf("the WIM has no image with index %d", imageIndex))
	}
	entryPosition, ok := c.byImage[imageIndex][path]
	if !ok {
		return nil, corruptWIM(0, fmt.Sprintf("the WIM has no entry %q", path))
	}
	entry := &image.Entries[entryPosition]
	if entry.IsDirectory() {
		return nil, corruptWIM(0, fmt.Sprintf("%q is a directory", path))
	}
	label := entry.Path
	size := entry.Size
	resource := entry.Resource
	resolved := entry.Resolved
	if streamName != nil {
		found := false
		for index := range entry.Streams {
			stream := &entry.Streams[index]
			if stream.Name != *streamName {
				continue
			}
			found = true
			label = entry.Path + ":" + stream.Name
			size = stream.Size
			resource = stream.Resource
			resolved = stream.Resolved
			break
		}
		if !found {
			return nil, corruptWIM(0, fmt.Sprintf(
				"the entry %q has no stream %q", path, *streamName))
		}
	}
	if !resolved {
		return nil, corruptWIM(0, fmt.Sprintf(
			"%q names a SHA-1 with no blob in the lookup table", label))
	}
	if size > MaxEntrySize {
		return nil, corruptWIM(0, fmt.Sprintf(
			"the entry %q claims %d bytes, over the %d-byte per-entry limit",
			label, size, MaxEntrySize))
	}
	entrySource, err := newEntrySource(c.parent, label, size, resource,
		c.info.Compression, c.info.ChunkSize)
	if err != nil {
		return nil, err
	}
	return entrySource, nil
}

func (c *Container) SourceID() source.ID     { return c.id }
func (c *Container) ImageID() source.ImageID { return c.parent.ImageID() }
func (c *Container) Len() uint64             { return c.parent.Len() }
func (c *Container) SectorSize() uint32      { return c.parent.SectorSize() }
func (c *Container) IsEmpty() bool           { return c.parent.Len() == 0 }
func (c *Container) Stats() source.Stats     { return c.counters.Snapshot() }

// ReadAt reads the raw WIM file bytes.
func (c *Container) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		c.counters.AddRead(0)
		return 0, nil
	}
	if offset >= c.Len() {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), c.Len())
	}
	want := int(minU64(c.Len()-offset, uint64(len(buf))))
	n, err := readFull(c.parent, offset, buf[:want], false)
	if err != nil {
		return 0, err
	}
	c.counters.AddRead(n)
	return n, nil
}

// ReadAtLossy reads the raw WIM file bytes, zero-filling a damaged range.
func (c *Container) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		c.counters.AddRead(0)
		return 0, nil
	}
	if offset >= c.Len() {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), c.Len())
	}
	want := int(minU64(c.Len()-offset, uint64(len(buf))))
	n, err := readFull(c.parent, offset, buf[:want], true)
	if err != nil {
		clear(buf[:want])
		c.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	c.counters.AddRead(n)
	return n, nil
}

// ExtentsInto translates a raw WIM file range to its parent.
func (c *Container) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > c.Len() || length > c.Len()-offset {
		return out, source.NewOutOfRange(offset, length, c.Len())
	}
	if length == 0 {
		return out, nil
	}
	return append(out, source.ParentRange{
		Parent: c.parent.SourceID(), ParentOffset: offset, Len: length, Kind: source.RangeData,
	}), nil
}

// Extents translates a raw WIM file range.
func (c *Container) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return c.ExtentsInto(offset, length, nil)
}

// MapToImage translates a raw WIM file range to image offsets.
func (c *Container) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > c.Len() || length > c.Len()-offset {
		return nil, source.NewOutOfRange(offset, length, c.Len())
	}
	return c.parent.MapToImage(offset, length)
}

var _ source.ByteSource = (*Container)(nil)

// EntrySource is one file or named stream inside a WIM.
type EntrySource struct {
	id          source.ID
	parent      source.ByteSource
	label       string
	size        uint64
	resource    *Resource
	compression Compression
	chunkSize   uint32
	lzxBits     int
	layout      *chunkLayout

	mu         sync.Mutex
	cacheIndex uint64
	cacheValid bool
	cacheBytes []byte
	counters   source.Counters
}

func newEntrySource(parent source.ByteSource, label string, size uint64, resource *Resource,
	compression Compression, chunkSize uint32) (*EntrySource, error) {
	if resource != nil {
		if resource.IsPacked() {
			return nil, unsupportedWIM(fmt.Sprintf("the stream %q uses a packed/solid resource", label))
		}
		if resource.IsCompressed() && compression != Xpress && compression != Lzx {
			return nil, unsupportedWIM(fmt.Sprintf("the stream %q is compressed with %s", label, compression))
		}
		if resource.OriginalSize != size {
			return nil, corruptWIM(0, fmt.Sprintf(
				"the stream %q declares %d bytes but its resource says %d",
				label, size, resource.OriginalSize))
		}
	}
	entry := &EntrySource{
		id:          source.ID(nextSourceID.Add(1)),
		parent:      parent,
		label:       label,
		size:        size,
		resource:    resource,
		compression: compression,
		chunkSize:   chunkSize,
	}
	if resource != nil && resource.IsCompressed() && compression == Lzx {
		lzxBits, err := lzxChunkBits(chunkSize, label)
		if err != nil {
			return nil, err
		}
		entry.lzxBits = lzxBits
	}
	if resource != nil {
		layout, err := newChunkLayout(parent, resource, chunkSize)
		if err != nil {
			return nil, err
		}
		entry.layout = layout
	}
	return entry, nil
}

// Label returns the entry's path and, for a stream, its stream name.
func (s *EntrySource) Label() string { return s.label }

func (s *EntrySource) SourceID() source.ID     { return s.id }
func (s *EntrySource) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *EntrySource) Len() uint64             { return s.size }
func (s *EntrySource) SectorSize() uint32      { return s.parent.SectorSize() }
func (s *EntrySource) IsEmpty() bool           { return s.size == 0 }
func (s *EntrySource) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *EntrySource) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf, false)
}

func (s *EntrySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf, true)
}

func (s *EntrySource) readInner(offset uint64, buf []byte, lossy bool) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.size)
	}
	want := int(minU64(s.size-offset, uint64(len(buf))))
	if s.resource == nil {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.size)
	}
	resource := *s.resource
	if !resource.IsCompressed() {
		n, err := readFull(s.parent, resource.Offset+offset, buf[:want], lossy)
		if err != nil {
			if lossy {
				clear(buf[:want])
				s.counters.AddCorrupt(uint64(want))
				return want, nil
			}
			return 0, err
		}
		s.counters.AddRead(n)
		return n, nil
	}
	if s.layout == nil {
		return 0, corruptWIM(resource.Offset,
			fmt.Sprintf("the stream %q has no chunk layout", s.label))
	}
	end := offset + uint64(want)
	first := offset / uint64(s.chunkSize)
	last := (end - 1) / uint64(s.chunkSize)
	for index := first; index <= last; index++ {
		chunk, err := s.chunk(index)
		if err != nil {
			if lossy {
				clear(buf[:want])
				s.counters.AddCorrupt(uint64(want))
				return want, nil
			}
			return 0, err
		}
		chunkStart := index * uint64(s.chunkSize)
		from := offset
		if chunkStart > from {
			from = chunkStart
		}
		to := end
		if chunkStart+uint64(len(chunk)) < to {
			to = chunkStart + uint64(len(chunk))
		}
		dst := int(from - offset)
		src := int(from - chunkStart)
		length := int(to - from)
		copy(buf[dst:dst+length], chunk[src:src+length])
	}
	s.counters.AddRead(want)
	return want, nil
}

func (s *EntrySource) chunk(index uint64) ([]byte, error) {
	s.mu.Lock()
	if s.cacheValid && s.cacheIndex == index {
		data := s.cacheBytes
		s.mu.Unlock()
		s.counters.AddCacheHit()
		return data, nil
	}
	s.mu.Unlock()
	s.counters.AddCacheMiss()

	resource := *s.resource
	start, end := s.layout.rangeFor(index)
	if start > end || end > s.layout.storedSize {
		return nil, corruptWIM(resource.Offset, fmt.Sprintf(
			"chunk %d of %q names bytes %d..%d outside its resource",
			index, s.label, start, end))
	}
	storedAt := resource.Offset + start
	if storedAt < resource.Offset {
		return nil, corruptWIM(resource.Offset, fmt.Sprintf(
			"chunk %d of %q starts past u64", index, s.label))
	}
	stored, err := source.ReadVecAt(s.parent, storedAt, end-start)
	if err != nil {
		return nil, err
	}
	consumed := index * uint64(s.chunkSize)
	expected := minU64(uint64(s.chunkSize), s.size-consumed)
	if uint64(len(stored)) == expected {
		s.cache(index, stored)
		s.counters.AddRead(int(expected))
		return stored, nil
	}
	var decoded []byte
	switch s.compression {
	case Xpress:
		decoded, err = xpressDecompress(stored, int(expected))
		if err != nil {
			return nil, corruptWIM(storedAt, fmt.Sprintf(
				"chunk %d of %q does not inflate: %v", index, s.label, err))
		}
	case Lzx:
		decoder, err := newLZXDecoder(s.lzxBits, true)
		if err != nil {
			return nil, corruptWIM(storedAt, fmt.Sprintf(
				"chunk %d of %q cannot start an LZX decoder: %v", index, s.label, err))
		}
		decoded, err = decoder.decode(stored, int(expected))
		if err != nil {
			return nil, corruptWIM(storedAt, fmt.Sprintf(
				"chunk %d of %q does not decode: %v", index, s.label, err))
		}
	default:
		return nil, corruptWIM(storedAt, fmt.Sprintf(
			"chunk %d of %q uses unsupported %s compression",
			index, s.label, s.compression))
	}
	if uint64(len(decoded)) != expected {
		return nil, corruptWIM(storedAt, fmt.Sprintf(
			"chunk %d of %q inflated to %d bytes, expected %d",
			index, s.label, len(decoded), expected))
	}
	s.counters.AddDecompressed(uint64(len(decoded)))
	s.cache(index, decoded)
	return decoded, nil
}

func (s *EntrySource) cache(index uint64, data []byte) {
	s.mu.Lock()
	s.cacheIndex = index
	s.cacheBytes = data
	s.cacheValid = true
	s.mu.Unlock()
}

// ExtentsInto translates a stream range to its parent.
func (s *EntrySource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.size || length > s.size-offset {
		return out, source.NewOutOfRange(offset, length, s.size)
	}
	if length == 0 {
		return out, nil
	}
	if s.resource == nil {
		return out, corruptWIM(offset, fmt.Sprintf("the stream %q has no resource", s.label))
	}
	resource := *s.resource
	if resource.IsCompressed() {
		kind := source.RangeData
		if resource.CompressedSize == 0 {
			kind = source.RangeError
		}
		out = append(out, source.ParentRange{
			Parent: s.parent.SourceID(), ParentOffset: resource.Offset,
			Len: resource.CompressedSize, Kind: kind,
		})
	} else {
		out = append(out, source.ParentRange{
			Parent: s.parent.SourceID(), ParentOffset: resource.Offset + offset,
			Len: length, Kind: source.RangeData,
		})
	}
	return out, nil
}

// Extents translates a stream range.
func (s *EntrySource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage translates a stream range all the way to image offsets.
func (s *EntrySource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.size || length > s.size-offset {
		return nil, source.NewOutOfRange(offset, length, s.size)
	}
	if length == 0 {
		return nil, nil
	}
	if s.resource == nil {
		return nil, corruptWIM(offset, fmt.Sprintf("the stream %q has no resource", s.label))
	}
	resource := *s.resource
	if resource.IsCompressed() {
		return s.parent.MapToImage(resource.Offset, resource.CompressedSize)
	}
	return s.parent.MapToImage(resource.Offset+offset, length)
}

var _ source.ByteSource = (*EntrySource)(nil)

// ---------------------------------------------------------------------------
// Header and resource parsing.
// ---------------------------------------------------------------------------

func parseHeader(head []byte, sourceLen uint64) (Info, error) {
	if string(head[:len(Signature)]) != Signature {
		return Info{}, unsupportedWIM("the file does not start with the WIM signature `MSWIM\\0\\0\\0`")
	}
	headerSize := le32(head, 0x08)
	if headerSize != HeaderBytes {
		return Info{}, unsupportedWIM(fmt.Sprintf(
			"the header declares %d bytes; this reader decodes %d", headerSize, HeaderBytes))
	}
	version := le32(head, 0x0C)
	if version == VersionSolid {
		return Info{}, unsupportedWIM("a solid WIM/`.esd` (version 0x00000e00, LZMS resources)")
	}
	if version != Version1_13 {
		return Info{}, unsupportedWIM(fmt.Sprintf(
			"WIM version 0x%08x; this reader decodes 1.13 (0x010d00)", version))
	}
	flags := le32(head, 0x10)
	chunkSize := le32(head, 0x14)
	var guid [16]byte
	copy(guid[:], head[0x18:0x28])
	partNumber := le16(head, 0x28)
	totalParts := le16(head, 0x2A)
	if flags&FlagSpanned != 0 || totalParts > 1 {
		return Info{}, unsupportedWIM(fmt.Sprintf(
			"a split WIM (part %d of %d); the parts are not assembled", partNumber, totalParts))
	}

	algorithmBits := flags & (FlagXpress | FlagLzx | FlagLzms)
	if bits.OnesCount32(algorithmBits) > 1 {
		return Info{}, corruptWIM(0x10, fmt.Sprintf(
			"the header selects more than one compression algorithm (flags 0x%08x)", flags))
	}
	var compression Compression
	switch {
	case flags&FlagLzms != 0:
		return Info{}, unsupportedWIM("LZMS-compressed WIM resources")
	case flags&FlagLzx != 0:
		compression = Lzx
	case flags&FlagXpress != 0:
		compression = Xpress
	case flags&FlagCompression != 0:
		return Info{}, unsupportedWIM("a WIM with the compression flag but no known algorithm")
	default:
		compression = None
	}
	if compression != None && flags&FlagCompression == 0 {
		return Info{}, corruptWIM(0x10, fmt.Sprintf(
			"the header selects %s but not the compression flag", compression))
	}
	if compression != None && chunkSize == 0 {
		return Info{}, corruptWIM(0x14, "the header selects compression but declares a zero chunk size")
	}
	if chunkSize > 64*1024*1024 {
		return Info{}, corruptWIM(0x14, fmt.Sprintf(
			"the header declares a %d-byte chunk, over the 64 MiB limit", chunkSize))
	}

	lookup, err := parseResourceHeader(head, 0x30, sourceLen)
	if err != nil {
		return Info{}, err
	}
	xmlResource, err := parseResourceHeader(head, 0x48, sourceLen)
	if err != nil {
		return Info{}, err
	}
	bootMetadata, err := parseResourceHeader(head, 0x60, sourceLen)
	if err != nil {
		return Info{}, err
	}
	integrity, err := parseResourceHeader(head, 0x7C, sourceLen)
	if err != nil {
		return Info{}, err
	}
	if lookup.IsAbsent() {
		return Info{}, corruptWIM(0x30, "the header carries no lookup-table resource")
	}
	if xmlResource.IsAbsent() {
		return Info{}, corruptWIM(0x48, "the header carries no XML-data resource")
	}
	info := Info{
		HeaderSize:  headerSize,
		Version:     version,
		Flags:       flags,
		ChunkSize:   chunkSize,
		Compression: compression,
		GUID:        guid,
		PartNumber:  partNumber,
		TotalParts:  totalParts,
		ImageCount:  le32(head, 0x2C),
		BootIndex:   le32(head, 0x78),
		Lookup:      lookup,
		XML:         xmlResource,
	}
	if !bootMetadata.IsAbsent() {
		copyResource := bootMetadata
		info.BootMetadata = &copyResource
	}
	if !integrity.IsAbsent() {
		copyResource := integrity
		info.Integrity = &copyResource
	}
	return info, nil
}

func parseResourceHeader(bytes []byte, at int, sourceLen uint64) (Resource, error) {
	raw := le64(bytes, at)
	resource := Resource{
		Flags:          uint8(raw >> 56),
		CompressedSize: raw & 0x00FFFFFFFFFFFFFF,
		Offset:         le64(bytes, at+8),
		OriginalSize:   le64(bytes, at+16),
	}
	if err := validateResource(resource, sourceLen); err != nil {
		return Resource{}, err
	}
	return resource, nil
}

func validateResource(resource Resource, sourceLen uint64) error {
	if resource.IsAbsent() {
		return nil
	}
	end := resource.Offset + resource.CompressedSize
	if end < resource.Offset {
		return corruptWIM(0, "a resource's offset and stored size overflow u64")
	}
	if end > sourceLen {
		return corruptWIM(resource.Offset, fmt.Sprintf(
			"a resource at byte %d claims %d stored bytes, past the %d byte file",
			resource.Offset, resource.CompressedSize, sourceLen))
	}
	if resource.IsCompressed() && resource.CompressedSize > sourceLen {
		return corruptWIM(0, "a compressed resource is larger than the file")
	}
	if !resource.IsCompressed() && resource.CompressedSize != resource.OriginalSize {
		return corruptWIM(resource.Offset, fmt.Sprintf(
			"an uncompressed resource stores %d bytes but declares %d original bytes",
			resource.CompressedSize, resource.OriginalSize))
	}
	return nil
}

type lookupEntry struct {
	resource   Resource
	partNumber uint32
	refCount   uint32
	sha1       [20]byte
}

func (e lookupEntry) empty() bool {
	return e.sha1 == [20]byte{} && e.resource.IsAbsent() && e.refCount == 0
}

func parseLookup(bytes []byte, sourceLen uint64) ([]lookupEntry, []Resource, error) {
	if len(bytes)%LookupEntryBytes != 0 {
		return nil, nil, corruptWIM(0, fmt.Sprintf(
			"the lookup table is %d bytes, not a multiple of %d", len(bytes), LookupEntryBytes))
	}
	count := len(bytes) / LookupEntryBytes
	if count > MaxLookupEntries {
		return nil, nil, corruptWIM(0, fmt.Sprintf(
			"the lookup table holds %d entries, over the %d limit", count, MaxLookupEntries))
	}
	entries := make([]lookupEntry, 0, count)
	var metadata []Resource
	for index := 0; index < count; index++ {
		at := index * LookupEntryBytes
		raw := le64(bytes, at)
		resource := Resource{
			Flags:          uint8(raw >> 56),
			CompressedSize: raw & 0x00FFFFFFFFFFFFFF,
			Offset:         le64(bytes, at+8),
			OriginalSize:   le64(bytes, at+16),
		}
		if err := validateResource(resource, sourceLen); err != nil {
			return nil, nil, err
		}
		entry := lookupEntry{
			resource:   resource,
			partNumber: le32(bytes, at+24),
			refCount:   le32(bytes, at+28),
		}
		copy(entry.sha1[:], bytes[at+32:at+52])
		if !entry.empty() {
			if entry.partNumber != 1 {
				return nil, nil, unsupportedWIM(fmt.Sprintf(
					"a lookup entry for part %d of a split WIM", entry.partNumber))
			}
			if resource.IsMetadata() {
				metadata = append(metadata, resource)
			}
		}
		entries = append(entries, entry)
	}
	return entries, metadata, nil
}

func readResource(src source.ByteSource, info Info, resource Resource, limit uint64, label string) ([]byte, error) {
	if resource.IsAbsent() {
		return nil, corruptWIM(0, fmt.Sprintf("the %s resource is absent", label))
	}
	if resource.IsPacked() {
		return nil, unsupportedWIM(fmt.Sprintf("the %s resource uses the packed/solid layout", label))
	}
	if resource.OriginalSize > limit {
		return nil, corruptWIM(0, fmt.Sprintf(
			"the %s resource expands to %d bytes, over the %d-byte limit",
			label, resource.OriginalSize, limit))
	}
	if !resource.IsCompressed() {
		return source.ReadVecAt(src, resource.Offset, resource.OriginalSize)
	}
	stored, err := source.ReadVecAt(src, resource.Offset, resource.CompressedSize)
	if err != nil {
		return nil, err
	}
	return decompressResource(stored, resource.OriginalSize, info.ChunkSize, info.Compression, label)
}

func lzxChunkBits(chunkSize uint32, label string) (int, error) {
	if bits.OnesCount32(chunkSize) != 1 {
		return 0, corruptWIM(0, fmt.Sprintf(
			"the %s resource declares a %d-byte chunk; an LZX chunk must be a power of two",
			label, chunkSize))
	}
	bitsCount := bits.TrailingZeros32(chunkSize)
	if bitsCount < 15 || bitsCount > 21 {
		return 0, unsupportedWIM(fmt.Sprintf(
			"the %s resource uses %d-byte LZX chunks; LZX windows are 32 KiB to 2 MiB",
			label, chunkSize))
	}
	return bitsCount, nil
}

func decompressResource(stored []byte, originalSize uint64, chunkSize uint32,
	compression Compression, label string) ([]byte, error) {
	if compression != Xpress && compression != Lzx {
		return nil, unsupportedWIM(fmt.Sprintf(
			"the %s resource uses %s compression", label, compression))
	}
	if originalSize == 0 {
		return []byte{}, nil
	}
	if chunkSize == 0 {
		return nil, corruptWIM(0, "a compressed resource has a zero chunk size")
	}
	if originalSize > uint64(maxInt()) {
		return nil, corruptWIM(0, fmt.Sprintf(
			"the %s resource expands past the address space", label))
	}
	var decoder *lzxDecoder
	if compression == Lzx {
		lzxBits, err := lzxChunkBits(chunkSize, label)
		if err != nil {
			return nil, err
		}
		decoder, err = newLZXDecoder(lzxBits, true)
		if err != nil {
			return nil, corruptWIM(0, fmt.Sprintf(
				"the %s resource cannot allocate an LZX window: %v", label, err))
		}
	}
	chunks := (originalSize + uint64(chunkSize) - 1) / uint64(chunkSize)
	entrySize := uint64(4)
	if originalSize > math.MaxUint32 {
		entrySize = 8
	}
	tableEntries := chunks - 1
	tableBytes := tableEntries * entrySize
	if tableBytes/entrySize != tableEntries {
		return nil, corruptWIM(0, "a chunk table's size overflows u64")
	}
	if tableBytes > uint64(len(stored)) {
		return nil, corruptWIM(0, fmt.Sprintf(
			"the %s resource needs %d bytes of chunk offsets but stores %d",
			label, tableBytes, len(stored)))
	}
	offsets, err := parseChunkOffsets(stored, tableEntries, entrySize)
	if err != nil {
		return nil, err
	}
	if err := validateChunkOffsets(offsets, tableBytes, uint64(len(stored)), label); err != nil {
		return nil, err
	}
	out := make([]byte, 0, int(originalSize))
	for index := uint64(0); index < chunks; index++ {
		start := tableBytes
		if index != 0 {
			start = offsets[index-1]
		}
		end := uint64(len(stored))
		if index+1 != chunks {
			end = offsets[index]
		}
		if start > end {
			return nil, corruptWIM(0, fmt.Sprintf(
				"chunk %d of the %s resource has a negative length", index, label))
		}
		consumed := index * uint64(chunkSize)
		expected := minU64(uint64(chunkSize), originalSize-consumed)
		chunk := stored[start:end]
		var decoded []byte
		if uint64(len(chunk)) == expected {
			decoded = chunk
		} else if decoder != nil {
			decoded, err = decoder.decode(chunk, int(expected))
			if err != nil {
				return nil, corruptWIM(start, fmt.Sprintf(
					"chunk %d of the %s resource does not decode: %v", index, label, err))
			}
		} else {
			decoded, err = xpressDecompress(chunk, int(expected))
			if err != nil {
				return nil, corruptWIM(start, fmt.Sprintf(
					"chunk %d of the %s resource does not inflate: %v", index, label, err))
			}
		}
		if uint64(len(decoded)) != expected {
			return nil, corruptWIM(0, fmt.Sprintf(
				"chunk %d of the %s resource inflated to %d bytes, expected %d",
				index, label, len(decoded), expected))
		}
		out = append(out, decoded...)
	}
	return out, nil
}

type chunkLayout struct {
	offsets    []uint64
	tableBytes uint64
	storedSize uint64
	chunks     uint64
}

func (l *chunkLayout) rangeFor(index uint64) (uint64, uint64) {
	start := l.tableBytes
	if index != 0 {
		start = l.offsets[index-1]
	}
	end := l.storedSize
	if index+1 != l.chunks {
		end = l.offsets[index]
	}
	return start, end
}

func newChunkLayout(src source.ByteSource, resource *Resource, chunkSize uint32) (*chunkLayout, error) {
	if !resource.IsCompressed() || resource.OriginalSize == 0 {
		return nil, nil
	}
	if chunkSize == 0 {
		return nil, corruptWIM(0, "a compressed resource has a zero chunk size")
	}
	chunks := (resource.OriginalSize + uint64(chunkSize) - 1) / uint64(chunkSize)
	entrySize := uint64(4)
	if resource.OriginalSize > math.MaxUint32 {
		entrySize = 8
	}
	tableEntries := chunks - 1
	tableBytes := tableEntries * entrySize
	if tableBytes/entrySize != tableEntries {
		return nil, corruptWIM(0, "a chunk table's size overflows u64")
	}
	if tableBytes > resource.CompressedSize {
		return nil, corruptWIM(0, "a compressed resource is too short for its chunk offsets")
	}
	raw, err := source.ReadVecAt(src, resource.Offset, tableBytes)
	if err != nil {
		return nil, err
	}
	offsets, err := parseChunkOffsets(raw, tableEntries, entrySize)
	if err != nil {
		return nil, err
	}
	if err := validateChunkOffsets(offsets, tableBytes, resource.CompressedSize, "compressed"); err != nil {
		return nil, err
	}
	return &chunkLayout{
		offsets:    offsets,
		tableBytes: tableBytes,
		storedSize: resource.CompressedSize,
		chunks:     chunks,
	}, nil
}

func parseChunkOffsets(stored []byte, count uint64, entrySize uint64) ([]uint64, error) {
	if count > uint64(maxInt()) {
		return nil, corruptWIM(0, "a chunk table has too many entries")
	}
	offsets := make([]uint64, int(count))
	for index := uint64(0); index < count; index++ {
		at := index * entrySize
		if at+entrySize > uint64(len(stored)) {
			return nil, corruptWIM(0, "a chunk offset is truncated")
		}
		if entrySize == 8 {
			offsets[index] = le64(stored, int(at))
		} else {
			offsets[index] = uint64(le32(stored, int(at)))
		}
	}
	return offsets, nil
}

func validateChunkOffsets(offsets []uint64, tableBytes, storedSize uint64, label string) error {
	previous := tableBytes
	for index, offset := range offsets {
		if offset > storedSize || offset < previous {
			return corruptWIM(0, fmt.Sprintf(
				"chunk %d of the %s resource names offset %d, outside %d..=%d",
				index, label, offset, previous, storedSize))
		}
		if offset == previous {
			return corruptWIM(0, fmt.Sprintf(
				"chunk %d of the %s resource is empty", index, label))
		}
		previous = offset
	}
	if storedSize == previous {
		return corruptWIM(0, fmt.Sprintf("the last chunk of the %s resource is empty", label))
	}
	return nil
}

// ---------------------------------------------------------------------------
// XML metadata.
// ---------------------------------------------------------------------------

type xmlWindows struct {
	Architecture     *string `xml:"ARCH"`
	ProductName      *string `xml:"PRODUCTNAME"`
	EditionID        *string `xml:"EDITIONID"`
	InstallationType *string `xml:"INSTALLATIONTYPE"`
	ProductType      *string `xml:"PRODUCTTYPE"`
	SuiteMask        *string `xml:"SUITEMASK"`
	Languages        *string `xml:"LANGUAGES"`
	SystemRoot       *string `xml:"SYSTEMROOT"`
}

type xmlImage struct {
	Index                 string      `xml:"INDEX,attr"`
	Name                  *string     `xml:"NAME"`
	Description           *string     `xml:"DESCRIPTION"`
	DeclaredDirectories   *string     `xml:"DIRCOUNT"`
	DeclaredFiles         *string     `xml:"FILECOUNT"`
	DeclaredTotalBytes    *string     `xml:"TOTALBYTES"`
	DeclaredHardlinkBytes *string     `xml:"HARDLINKBYTES"`
	Flags                 *string     `xml:"FLAGS"`
	Windows               *xmlWindows `xml:"WINDOWS"`
}

type parsedXMLImage struct {
	index                 uint32
	name                  *string
	description           *string
	declaredDirectories   *uint64
	declaredFiles         *uint64
	declaredTotalBytes    *uint64
	declaredHardlinkBytes *uint64
	flags                 *string
	windows               *Windows
}

func parseXML(bytes []byte) ([]parsedXMLImage, error) {
	text, err := decodeXMLText(bytes)
	if err != nil {
		return nil, err
	}
	decoder := xml.NewDecoder(strings.NewReader(text))
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var document struct {
		XMLName xml.Name
		Images  []xmlImage `xml:"IMAGE"`
	}
	if err := decoder.Decode(&document); err != nil {
		return nil, corruptWIM(0, fmt.Sprintf("the XML data resource does not parse: %v", err))
	}
	if document.XMLName.Local != "WIM" {
		return nil, corruptWIM(0, fmt.Sprintf(
			"the XML data root element is <%s>, not <WIM>", document.XMLName.Local))
	}
	images := make([]parsedXMLImage, 0, len(document.Images))
	seen := make(map[uint32]bool)
	for _, element := range document.Images {
		if element.Index == "" {
			return nil, corruptWIM(0, "an <IMAGE> element has no INDEX attribute")
		}
		parsedIndex, err := strconv.ParseUint(element.Index, 10, 32)
		if err != nil {
			return nil, corruptWIM(0, fmt.Sprintf("<IMAGE INDEX=%q> is not a number", element.Index))
		}
		index := uint32(parsedIndex)
		if index == 0 {
			return nil, corruptWIM(0, "an <IMAGE> element has INDEX 0")
		}
		if seen[index] {
			return nil, corruptWIM(0, fmt.Sprintf("two <IMAGE> elements have INDEX %d", index))
		}
		seen[index] = true
		image := parsedXMLImage{index: index}
		if element.Name != nil {
			image.name = element.Name
		}
		if element.Description != nil {
			image.description = element.Description
		}
		if image.declaredDirectories, err = parseOptionalU64(element.DeclaredDirectories, "DIRCOUNT"); err != nil {
			return nil, err
		}
		if image.declaredFiles, err = parseOptionalU64(element.DeclaredFiles, "FILECOUNT"); err != nil {
			return nil, err
		}
		if image.declaredTotalBytes, err = parseOptionalU64(element.DeclaredTotalBytes, "TOTALBYTES"); err != nil {
			return nil, err
		}
		if image.declaredHardlinkBytes, err = parseOptionalU64(element.DeclaredHardlinkBytes, "HARDLINKBYTES"); err != nil {
			return nil, err
		}
		image.flags = element.Flags
		if element.Windows != nil {
			image.windows = &Windows{
				Architecture:     element.Windows.Architecture,
				ProductName:      element.Windows.ProductName,
				EditionID:        element.Windows.EditionID,
				InstallationType: element.Windows.InstallationType,
				ProductType:      element.Windows.ProductType,
				SuiteMask:        element.Windows.SuiteMask,
				Languages:        element.Windows.Languages,
				SystemRoot:       element.Windows.SystemRoot,
			}
		}
		images = append(images, image)
	}
	sort.Slice(images, func(i, j int) bool { return images[i].index < images[j].index })
	for position, image := range images {
		expected := uint32(position + 1)
		if image.index != expected {
			return nil, corruptWIM(0, fmt.Sprintf(
				"the XML data names image index %d where index %d is required", image.index, expected))
		}
	}
	return images, nil
}

func parseOptionalU64(text *string, name string) (*uint64, error) {
	if text == nil {
		return nil, nil
	}
	value, err := strconv.ParseUint(strings.TrimSpace(*text), 10, 64)
	if err != nil {
		return nil, corruptWIM(0, fmt.Sprintf("<%s> is not a number: %q", name, *text))
	}
	return &value, nil
}

func findXMLImage(images []parsedXMLImage, index uint32) (parsedXMLImage, bool) {
	for _, image := range images {
		if image.index == index {
			return image, true
		}
	}
	return parsedXMLImage{}, false
}

// decodeXMLText decodes the nominal UTF-16LE XML resource, with a BOM or a
// leading markup byte deciding when present. Some writers emit UTF-8.
func decodeXMLText(bytes []byte) (string, error) {
	if uint64(len(bytes)) > MaxXMLBytes {
		return "", corruptWIM(0, fmt.Sprintf(
			"the XML data is %d bytes, over the %d-byte limit", len(bytes), MaxXMLBytes))
	}
	if len(bytes) == 0 {
		return "", corruptWIM(0, "the XML data resource is empty")
	}
	if len(bytes) >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
		return decodeUTF16(bytes[2:], true)
	}
	if len(bytes) >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
		return decodeUTF16(bytes[2:], false)
	}
	if strings.HasPrefix(string(bytes), "<?xml") || strings.HasPrefix(string(bytes), "<WIM") {
		if !utf8.Valid(bytes) {
			return "", corruptWIM(0, "the XML data is neither valid UTF-8 nor UTF-16")
		}
		return string(bytes), nil
	}
	return decodeUTF16(bytes, true)
}

func decodeUTF16(bytes []byte, littleEndian bool) (string, error) {
	if len(bytes)%2 != 0 {
		return "", corruptWIM(0, "a UTF-16 XML resource has an odd byte length")
	}
	units := make([]uint16, len(bytes)/2)
	for index := range units {
		if littleEndian {
			units[index] = uint16(bytes[index*2]) | uint16(bytes[index*2+1])<<8
		} else {
			units[index] = uint16(bytes[index*2])<<8 | uint16(bytes[index*2+1])
		}
	}
	return decodeUTF16Strict(units)
}

func decodeUTF16Strict(units []uint16) (string, error) {
	var builder strings.Builder
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if index+1 >= len(units) {
				return "", corruptWIM(0, "a UTF-16 sequence ends inside a surrogate pair")
			}
			low := units[index+1]
			if low < 0xDC00 || low > 0xDFFF {
				return "", corruptWIM(0, "a UTF-16 sequence has an unpaired high surrogate")
			}
			builder.WriteRune(utf16.DecodeRune(rune(unit), rune(low)))
			index++
		case unit >= 0xDC00 && unit <= 0xDFFF:
			return "", corruptWIM(0, "a UTF-16 sequence has an unpaired low surrogate")
		default:
			builder.WriteRune(rune(unit))
		}
	}
	return builder.String(), nil
}

// ---------------------------------------------------------------------------
// Metadata resource: security data and the directory tree.
// ---------------------------------------------------------------------------

type securityData struct {
	length uint64
	count  int
}

func parseSecurity(bytes []byte) (securityData, error) {
	if len(bytes) < 8 {
		return securityData{}, corruptWIM(0, "the metadata resource is too short for its security data")
	}
	storedLength := uint64(le32(bytes, 0))
	count := le32(bytes, 4)
	totalLength := storedLength
	if storedLength == 0 {
		totalLength = 8
	}
	aligned := align8WIM(totalLength)
	if uint64(count) > MaxSecurityEntries {
		return securityData{}, corruptWIM(0, fmt.Sprintf(
			"the security data declares %d descriptors, over the %d limit", count, MaxSecurityEntries))
	}
	sizesEnd := uint64(8) + uint64(count)*8
	if sizesEnd < uint64(count)*8 {
		return securityData{}, corruptWIM(0, "the security data's descriptor count overflows its size table")
	}
	if sizesEnd > aligned {
		return securityData{}, corruptWIM(0,
			"the security data's size table does not fit in its declared length")
	}
	var descriptors uint64
	for index := uint32(0); index < count; index++ {
		at := 8 + int(index)*8
		if at+8 > len(bytes) {
			return securityData{}, corruptWIM(0, "the security descriptor size table is truncated")
		}
		size := le64(bytes, at)
		if size > math.MaxUint32 {
			return securityData{}, corruptWIM(0, fmt.Sprintf(
				"security descriptor %d declares %d bytes, over 4 GiB", index, size))
		}
		descriptors += size
		if descriptors < size {
			return securityData{}, corruptWIM(0, "the security descriptor sizes overflow")
		}
	}
	if sizesEnd+descriptors < sizesEnd {
		return securityData{}, corruptWIM(0, "the security descriptor sizes overflow")
	}
	if sizesEnd+descriptors > aligned {
		return securityData{}, corruptWIM(0,
			"the security descriptors do not fit in the declared security data length")
	}
	if aligned > uint64(len(bytes)) {
		return securityData{}, corruptWIM(0, fmt.Sprintf(
			"the security data claims %d bytes but the metadata resource is %d",
			aligned, len(bytes)))
	}
	return securityData{length: aligned, count: int(count)}, nil
}

type rawStream struct {
	sha1 [20]byte
	name string
}

type rawDentry struct {
	attributes   uint32
	securityID   uint32
	subdirOffset uint64
	created      uint64
	accessed     uint64
	written      uint64
	sha1         [20]byte
	reparseTag   uint32
	hardLink     uint64
	name         string
	shortName    *string
	streams      []rawStream
	length       uint64
}

func parseDentry(bytes []byte, offset uint64, isRoot bool) (rawDentry, error) {
	length, err := readU64WIM(bytes, offset, "a directory entry length")
	if err != nil {
		return rawDentry{}, err
	}
	if length < DirectoryEntryBytes {
		return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
			"a directory entry at byte %d declares %d bytes, under %d",
			offset, length, DirectoryEntryBytes))
	}
	if length%8 != 0 {
		return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
			"a directory entry at byte %d is %d bytes, not 8-byte aligned", offset, length))
	}
	end := offset + length
	if end < offset {
		return rawDentry{}, corruptWIM(offset, "a directory entry's length overflows")
	}
	if end > uint64(len(bytes)) {
		return rawDentry{}, corruptWIM(offset,
			fmt.Sprintf("a directory entry at byte %d runs past the metadata resource", offset))
	}
	base := int(offset)
	attributes := le32(bytes, base+8)
	securityID := le32(bytes, base+12)
	subdirOffset := le64(bytes, base+16)
	created := le64(bytes, base+40)
	accessed := le64(bytes, base+48)
	written := le64(bytes, base+56)
	var sha1Sum [20]byte
	copy(sha1Sum[:], bytes[base+64:base+84])
	reparseTag := le32(bytes, base+84)
	hardLink := le64(bytes, base+88)
	numStreams := int(le16(bytes, base+96))
	shortNameBytes := uint64(le16(bytes, base+98))
	fileNameBytes := uint64(le16(bytes, base+100))

	namesEnd := uint64(DirectoryEntryBytes) + shortNameBytes + fileNameBytes
	if namesEnd < uint64(DirectoryEntryBytes) {
		return rawDentry{}, corruptWIM(offset, "a directory entry's name lengths overflow")
	}
	if namesEnd > length {
		return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
			"a directory entry at byte %d has names that do not fit its %d bytes", offset, length))
	}
	fileAt := base + DirectoryEntryBytes
	shortAt := fileAt + int(fileNameBytes)
	name, err := decodeName(bytes, fileAt, int(fileNameBytes), offset)
	if err != nil {
		return rawDentry{}, err
	}
	var shortName *string
	if shortNameBytes != 0 {
		short, err := decodeName(bytes, shortAt, int(shortNameBytes), offset)
		if err != nil {
			return rawDentry{}, err
		}
		shortName = &short
	}
	if name == "" && !isRoot {
		return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
			"a directory entry at byte %d has an empty name", offset))
	}
	if isRoot && name != "" {
		return rawDentry{}, corruptWIM(offset,
			"the root directory entry carries a name; the tree is ambiguous")
	}
	if err := checkName(name, offset); err != nil {
		return rawDentry{}, err
	}
	if shortName != nil {
		if err := checkName(*shortName, offset); err != nil {
			return rawDentry{}, err
		}
	}

	cursor := base + int(namesEnd)
	entryEnd := int(end)
	streams := make([]rawStream, 0, numStreams)
	for index := 0; index < numStreams; index++ {
		if cursor+StreamEntryBytes > entryEnd {
			return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
				"stream %d of the entry at byte %d runs past the entry", index, offset))
		}
		streamLength := le64(bytes, cursor)
		if streamLength < StreamEntryBytes || streamLength%8 != 0 {
			return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
				"stream %d of the entry at byte %d declares %d bytes",
				index, offset, streamLength))
		}
		if streamLength > uint64(entryEnd-cursor) {
			return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
				"stream %d of the entry at byte %d runs past the entry", index, offset))
		}
		streamEnd := cursor + int(streamLength)
		nameBytes := int(le16(bytes, cursor+36))
		if StreamEntryBytes+nameBytes > int(streamLength) {
			return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
				"stream %d of the entry at byte %d has a name that does not fit", index, offset))
		}
		var streamSHA1 [20]byte
		copy(streamSHA1[:], bytes[cursor+16:cursor+36])
		streamName, err := decodeName(bytes, cursor+StreamEntryBytes, nameBytes, offset)
		if err != nil {
			return rawDentry{}, err
		}
		if streamName == "" {
			return rawDentry{}, corruptWIM(offset, fmt.Sprintf(
				"stream %d of the entry at byte %d has an empty name", index, offset))
		}
		if err := checkName(streamName, offset); err != nil {
			return rawDentry{}, err
		}
		streams = append(streams, rawStream{sha1: streamSHA1, name: streamName})
		cursor = streamEnd
	}

	return rawDentry{
		attributes:   attributes,
		securityID:   securityID,
		subdirOffset: subdirOffset,
		created:      created,
		accessed:     accessed,
		written:      written,
		sha1:         sha1Sum,
		reparseTag:   reparseTag,
		hardLink:     hardLink,
		name:         name,
		shortName:    shortName,
		streams:      streams,
		length:       length,
	}, nil
}

func decodeName(bytes []byte, at, length int, entryOffset uint64) (string, error) {
	if length%2 != 0 {
		return "", corruptWIM(entryOffset, fmt.Sprintf(
			"a name in the entry at byte %d has an odd byte length", entryOffset))
	}
	if at < 0 || at+length > len(bytes) {
		return "", corruptWIM(entryOffset, fmt.Sprintf(
			"a name in the entry at byte %d runs past the metadata resource", entryOffset))
	}
	units := make([]uint16, length/2)
	for index := range units {
		units[index] = uint16(bytes[at+index*2]) | uint16(bytes[at+index*2+1])<<8
	}
	text, err := decodeUTF16Strict(units)
	if err != nil {
		return "", corruptWIM(entryOffset, fmt.Sprintf(
			"a name in the entry at byte %d is not valid UTF-16", entryOffset))
	}
	if strings.HasSuffix(text, "\x00") {
		text = text[:len(text)-1]
	}
	return text, nil
}

func checkName(name string, offset uint64) error {
	if strings.ContainsRune(name, 0) {
		return corruptWIM(offset, fmt.Sprintf(
			"a name in the entry at byte %d contains a NUL byte", offset))
	}
	if strings.ContainsAny(name, `/\`) {
		return corruptWIM(offset, fmt.Sprintf(
			"the name %q in the entry at byte %d contains a path separator", name, offset))
	}
	if strings.ContainsRune(name, ':') {
		return corruptWIM(offset, fmt.Sprintf(
			"the name %q in the entry at byte %d contains `:`", name, offset))
	}
	return nil
}

func parseMetadata(bytes []byte, blobs map[[20]byte]Resource, stats *Stats) (int, Entry, []Entry, error) {
	security, err := parseSecurity(bytes)
	if err != nil {
		return 0, Entry{}, nil, err
	}
	rootOffset := security.length
	root, err := parseDentry(bytes, rootOffset, true)
	if err != nil {
		return 0, Entry{}, nil, err
	}
	if root.attributes&AttributeDirectory == 0 {
		return 0, Entry{}, nil, corruptWIM(rootOffset,
			"the metadata root entry is not marked as a directory")
	}
	rootEntry := buildEntry(rawDentry{
		attributes: root.attributes,
		securityID: root.securityID,
		created:    root.created,
		accessed:   root.accessed,
		written:    root.written,
		sha1:       root.sha1,
		reparseTag: root.reparseTag,
		hardLink:   root.hardLink,
		streams:    root.streams,
	}, blobs, stats)
	walker := &metadataWalker{
		bytes:   bytes,
		blobs:   blobs,
		stats:   stats,
		visited: make(map[uint64]bool),
	}
	if root.subdirOffset != 0 {
		if err := walker.walk(root.subdirOffset, "", 0); err != nil {
			return 0, Entry{}, nil, err
		}
	}
	if len(walker.entries) > MaxEntries {
		return 0, Entry{}, nil, corruptWIM(0, fmt.Sprintf(
			"the image declares more than %d entries", MaxEntries))
	}
	return security.count, rootEntry, walker.entries, nil
}

type metadataWalker struct {
	bytes   []byte
	blobs   map[[20]byte]Resource
	stats   *Stats
	visited map[uint64]bool
	entries []Entry
}

func (w *metadataWalker) walk(listOffset uint64, parent string, depth int) error {
	if depth > MaxDepth {
		return corruptWIM(0, fmt.Sprintf(
			"the directory tree is deeper than %d levels", MaxDepth))
	}
	if w.visited[listOffset] {
		return corruptWIM(listOffset, fmt.Sprintf(
			"the directory list at byte %d is reached twice", listOffset))
	}
	w.visited[listOffset] = true
	cursor := listOffset
	for {
		if cursor+8 < cursor || cursor+8 > uint64(len(w.bytes)) {
			return corruptWIM(listOffset, fmt.Sprintf(
				"a directory list at byte %d runs past the metadata resource", listOffset))
		}
		length := le64(w.bytes, int(cursor))
		if length == 0 {
			break
		}
		raw, err := parseDentry(w.bytes, cursor, false)
		if err != nil {
			return err
		}
		path := raw.name
		if parent != "" {
			path = parent + "/" + raw.name
		}
		if len(path) > MaxPathBytes {
			return corruptWIM(cursor, fmt.Sprintf(
				"the path %q is over %d bytes", path, MaxPathBytes))
		}
		if len(w.entries) >= MaxEntries {
			return corruptWIM(cursor, fmt.Sprintf(
				"the image declares more than %d entries", MaxEntries))
		}
		entry := buildEntry(raw, w.blobs, w.stats)
		entry.Path = path
		entry.Name = raw.name
		entry.ShortName = raw.shortName
		isDirectory := entry.IsDirectory()
		w.entries = append(w.entries, entry)
		if isDirectory && raw.subdirOffset != 0 {
			if err := w.walk(raw.subdirOffset, path, depth+1); err != nil {
				return err
			}
		}
		cursor += raw.length
		if cursor < raw.length {
			return corruptWIM(cursor, "a directory entry's offset overflows")
		}
	}
	return nil
}

func buildEntry(seed rawDentry, blobs map[[20]byte]Resource, stats *Stats) Entry {
	isDirectory := seed.attributes&AttributeDirectory != 0
	var resource *Resource
	var size uint64
	resolved := true
	if !isDirectory {
		resource, size, resolved = resolveHash(seed.sha1, blobs, stats)
	}
	streams := make([]Stream, 0, len(seed.streams))
	for _, raw := range seed.streams {
		streamResource, streamSize, streamResolved := resolveHash(raw.sha1, blobs, stats)
		streams = append(streams, Stream{
			Name:     raw.name,
			SHA1:     raw.sha1,
			Size:     streamSize,
			Resource: streamResource,
			Resolved: streamResolved,
		})
	}
	entry := Entry{
		Path:       seed.name,
		Name:       seed.name,
		ShortName:  seed.shortName,
		Attributes: seed.attributes,
		Created:    seed.created,
		Accessed:   seed.accessed,
		Written:    seed.written,
		SHA1:       seed.sha1,
		ReparseTag: seed.reparseTag,
		HardLink:   seed.hardLink,
		Streams:    streams,
		Size:       size,
		Resource:   resource,
		Resolved:   resolved,
	}
	if seed.securityID != noSecurityID {
		securityID := seed.securityID
		entry.SecurityID = &securityID
	}
	return entry
}

func resolveHash(sha1Sum [20]byte, blobs map[[20]byte]Resource, stats *Stats) (*Resource, uint64, bool) {
	if sha1Sum == [20]byte{} {
		return nil, 0, true
	}
	resource, ok := blobs[sha1Sum]
	if !ok {
		stats.UnresolvedHashes++
		return nil, 0, false
	}
	return &resource, resource.OriginalSize, true
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func readFull(src source.ByteSource, offset uint64, target []byte, lossy bool) (int, error) {
	var (
		n   int
		err error
	)
	if lossy {
		n, err = src.ReadAtLossy(offset, target)
	} else {
		n, err = src.ReadAt(offset, target)
	}
	if err != nil {
		return n, err
	}
	if n < len(target) {
		return n, source.NewUnexpectedEOF(offset)
	}
	return n, nil
}

func readU64WIM(bytes []byte, offset uint64, what string) (uint64, error) {
	if offset > uint64(len(bytes)) || uint64(len(bytes))-offset < 8 {
		return 0, corruptWIM(offset, fmt.Sprintf("%s at byte %d is truncated", what, offset))
	}
	return le64(bytes, int(offset)), nil
}

func le16(bytes []byte, at int) uint16 {
	return uint16(bytes[at]) | uint16(bytes[at+1])<<8
}

func le32(bytes []byte, at int) uint32 {
	return uint32(bytes[at]) | uint32(bytes[at+1])<<8 |
		uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
}

func le64(bytes []byte, at int) uint64 {
	return uint64(le32(bytes, at)) | uint64(le32(bytes, at+4))<<32
}

func align8WIM(value uint64) uint64 {
	return (value + 7) &^ 7
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxInt() int { return int(^uint(0) >> 1) }

func corruptWIM(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupportedWIM(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}
