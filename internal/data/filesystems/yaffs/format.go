package yaffs

import (
	"encoding/binary"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

// KindLabel is the filesystem name reports and facts use.
const KindLabel = "YAFFS2"

// RootObjectID is the object id of the volume root.
const RootObjectID uint32 = 1

// LostFoundObjectID is the object id of lost+found.
const LostFoundObjectID uint32 = 2

// UnlinkedObjectID and DeletedObjectID are the reserved parents of objects no
// directory names.
const (
	UnlinkedObjectID uint32 = 3
	DeletedObjectID  uint32 = 4
)

// TagBytes is the size of one packed YAFFS2 tag.
const TagBytes = 16

// Object-header field offsets and bounds.
const (
	nameOffset       = 10
	nameBytes        = 256
	headerBytes      = 298
	typeOffset       = 0
	parentOffset     = 4
	modeOffset       = 266
	uidOffset        = 270
	gidOffset        = 274
	atimeOffset      = 278
	mtimeOffset      = 282
	ctimeOffset      = 286
	sizeOffset       = 290
	equivalentOffset = 294
)

// Reader bounds.  They are large enough for real Android images and small
// enough that a hostile tag stream cannot allocate without limit.
const (
	MaxObjectID      uint32 = 0x00ff_ffff
	MaxChunkID       uint32 = 0x003f_ffff
	MaxObjects              = 1_000_000
	MaxChunkEntries         = 4_000_000
	headersKept             = 4
	detectPages      uint64 = 512
	minPlausibleTags uint64 = 4
	maxPageData             = 4096
	scanBatchBytes          = 1 << 20
)

// Layout is one page geometry: the number of data bytes in a page, the
// distance between consecutive pages, and where the sixteen-byte tag sits.
type Layout struct {
	PageData  int
	Stride    int
	TagOffset int
}

// Pages returns the number of whole pages in a source of len bytes.  The bool
// is false when the geometry does not divide the source exactly.
func (l Layout) Pages(length uint64) (uint64, bool) {
	if l.Stride <= 0 || length%uint64(l.Stride) != 0 {
		return 0, false
	}
	return length / uint64(l.Stride), true
}

// Layouts are the geometries tried, in preference order: an in-band tag first,
// then the common 64- and 128-byte spare areas at their first or third byte.
var Layouts = [...]Layout{
	{PageData: 2048, Stride: 2048 + TagBytes, TagOffset: 2048},
	{PageData: 2048, Stride: 2048 + 64, TagOffset: 2048},
	{PageData: 2048, Stride: 2048 + 64, TagOffset: 2050},
	{PageData: 2048, Stride: 2048 + 128, TagOffset: 2048},
	{PageData: 2048, Stride: 2048 + 128, TagOffset: 2050},
	{PageData: 4096, Stride: 4096 + TagBytes, TagOffset: 4096},
	{PageData: 4096, Stride: 4096 + 64, TagOffset: 4096},
	{PageData: 4096, Stride: 4096 + 64, TagOffset: 4098},
}

// NodeKind is what an object header says the object is.
type NodeKind uint8

// Object kinds.  A hard link is a file whose data belongs to Equivalent.
const (
	KindFile NodeKind = iota
	KindDirectory
	KindSymlink
	KindHardLink
	KindSpecial
)

// Compatibility aliases for callers that name the kinds without the Kind
// prefix.
const (
	NodeFile      = KindFile
	NodeDirectory = KindDirectory
	NodeSymlink   = KindSymlink
	NodeHardLink  = KindHardLink
	NodeSpecial   = KindSpecial
)

// Label returns the kind's lower-case name.
func (k NodeKind) Label() string {
	switch k {
	case KindFile:
		return "file"
	case KindDirectory:
		return "directory"
	case KindSymlink:
		return "symlink"
	case KindHardLink:
		return "hardlink"
	case KindSpecial:
		return "special"
	default:
		return "unknown"
	}
}

// IsFile reports whether the object carries file data.  A hard link is a file
// whose data lives in the object it points at.
func (k NodeKind) IsFile() bool { return k == KindFile || k == KindHardLink }

// IsDirectory reports whether the object is a directory.
func (k NodeKind) IsDirectory() bool { return k == KindDirectory }

// IsSymlink reports whether the object is a symbolic link.
func (k NodeKind) IsSymlink() bool { return k == KindSymlink }

// Header is a decoded object header.
type Header struct {
	Kind       NodeKind
	Parent     uint32
	Name       string
	Mode       uint32
	UID        uint32
	GID        uint32
	Atime      uint32
	Mtime      uint32
	Ctime      uint32
	Size       uint32
	Equivalent uint32
}

// Entry is one object as the walk found it.  Inode is the YAFFS object id and
// ParentInode the header's parent id.
type Entry struct {
	Name        string
	Path        string
	Inode       uint64
	ParentInode uint64
	Kind        NodeKind

	IsDir      bool
	IsFile     bool
	IsSymlink  bool
	IsHardLink bool
	IsSpecial  bool

	Mode uint32
	UID  uint32
	GID  uint32
	Size uint64
	// Allocated is the bytes the object's data chunks store.  It is nil for
	// every non-file and for a deleted object, whose chunks may be reused.
	Allocated *uint64

	Atime time.Time
	Mtime time.Time
	Ctime time.Time
	// HasAtime, HasMtime and HasCtime are false when the header's field was
	// zero and therefore unset.
	HasAtime bool
	HasMtime bool
	HasCtime bool

	// Deleted marks an object listed from its shadow header.
	Deleted bool
}

// IsDirectory reports whether the entry is a directory.
func (e Entry) IsDirectory() bool { return e.Kind.IsDirectory() }

// IsSymbolicLink reports whether the entry is a symbolic link.
func (e Entry) IsSymbolicLink() bool { return e.Kind.IsSymlink() }

// IsRegularFile reports whether the entry carries a file stream.
func (e Entry) IsRegularFile() bool { return e.Kind.IsFile() }

// Node is an alias used by callers that mirror the reference reader's naming.
type Node = Entry

// Info is a volume report.
type Info struct {
	Kind              string
	PageSize          int
	TagSize           int
	Stride            int
	Pages             uint64
	Tags              uint64
	Objects           uint64
	Headers           uint64
	Chunks            uint64
	Entries           uint64
	UnreadableTags    uint64
	UnreadableHeaders uint64
	UnresolvedDeleted uint64
	LostFound         bool
}

// Tag is one decoded tag.
type Tag struct {
	Serial uint32
	Object uint32
	Chunk  uint32
	Bytes  uint32
}

// ParseTag decodes one packed tag.  The bool is false when the tag is not
// plausible for a page of pageData bytes.
func ParseTag(raw []byte, pageData int) (Tag, bool) {
	if len(raw) < TagBytes {
		return Tag{}, false
	}
	tag := Tag{
		Serial: binary.LittleEndian.Uint32(raw[0:4]),
		Object: binary.LittleEndian.Uint32(raw[4:8]),
		Chunk:  binary.LittleEndian.Uint32(raw[8:12]),
		Bytes:  binary.LittleEndian.Uint32(raw[12:16]),
	}
	if tag.Object == 0 || tag.Object > MaxObjectID {
		return Tag{}, false
	}
	if tag.Chunk > MaxChunkID {
		return Tag{}, false
	}
	limit := pageData
	if limit > maxPageData {
		limit = maxPageData
	}
	if int64(tag.Bytes) > int64(limit) {
		return Tag{}, false
	}
	if tag.Serial == ^uint32(0) {
		return Tag{}, false
	}
	return tag, true
}

// ParseHeader decodes an object header out of one page's data area.  The bool
// is false when the page does not hold a plausible header.
func ParseHeader(page []byte) (Header, bool) {
	if len(page) < headerBytes {
		return Header{}, false
	}
	var kind NodeKind
	switch binary.LittleEndian.Uint32(page[typeOffset:]) {
	case 1:
		kind = KindFile
	case 2:
		kind = KindSymlink
	case 3:
		kind = KindDirectory
	case 4:
		kind = KindHardLink
	case 5:
		kind = KindSpecial
	default:
		return Header{}, false
	}
	rawName := page[nameOffset : nameOffset+nameBytes]
	end := -1
	for index, value := range rawName {
		if value == 0 {
			end = index
			break
		}
	}
	if end < 0 {
		return Header{}, false
	}
	if end == 0 && kind != KindDirectory {
		return Header{}, false
	}
	if !utf8.Valid(rawName[:end]) {
		return Header{}, false
	}
	name := string(rawName[:end])
	for _, runeValue := range name {
		if unicode.IsControl(runeValue) {
			return Header{}, false
		}
	}
	rootName := kind == KindDirectory && name == "/"
	if !rootName && (name == "" || strings.Contains(name, "/")) {
		return Header{}, false
	}
	return Header{
		Kind:       kind,
		Parent:     binary.LittleEndian.Uint32(page[parentOffset:]),
		Name:       name,
		Mode:       binary.LittleEndian.Uint32(page[modeOffset:]),
		UID:        binary.LittleEndian.Uint32(page[uidOffset:]),
		GID:        binary.LittleEndian.Uint32(page[gidOffset:]),
		Atime:      binary.LittleEndian.Uint32(page[atimeOffset:]),
		Mtime:      binary.LittleEndian.Uint32(page[mtimeOffset:]),
		Ctime:      binary.LittleEndian.Uint32(page[ctimeOffset:]),
		Size:       binary.LittleEndian.Uint32(page[sizeOffset:]),
		Equivalent: binary.LittleEndian.Uint32(page[equivalentOffset:]),
	}, true
}

type tagOccurrence struct {
	serial uint32
	page   uint64
	bytes  uint32
}

type headerOccurrence struct {
	serial uint32
	page   uint64
	header Header
}

type rawObject struct {
	headers []headerOccurrence
	chunks  map[uint32]tagOccurrence
}

// newer reports whether a is a later write than b for the same object/chunk.
func newer(aSerial uint32, aPage uint64, bSerial uint32, bPage uint64) bool {
	diff := aSerial - bSerial
	if diff == 0 {
		return aPage > bPage
	}
	return diff < 0x8000_0000
}

func (o *rawObject) pushHeader(occurrence headerOccurrence) {
	o.headers = append(o.headers, occurrence)
	// Keep the newest headers last.  Four is enough for current plus shadow
	// plus two stale writes, which is what the walk can use.
	sort.SliceStable(o.headers, func(left, right int) bool {
		return newer(o.headers[right].serial, o.headers[right].page,
			o.headers[left].serial, o.headers[left].page)
	})
	if len(o.headers) > headersKept {
		o.headers = o.headers[len(o.headers)-headersKept:]
	}
}

func (o *rawObject) pushChunk(chunk uint32, occurrence tagOccurrence) bool {
	existing, found := o.chunks[chunk]
	if found && !newer(occurrence.serial, occurrence.page, existing.serial, existing.page) {
		return false
	}
	o.chunks[chunk] = occurrence
	return !found
}

// readAt reads exactly len(buf) bytes or returns the source's error.
func readAt(src source.ByteSource, offset uint64, buf []byte) error {
	return source.ReadExactAt(src, offset, buf)
}

func nonzero(value uint32) (time.Time, bool) {
	if value == 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(value), 0).UTC(), true
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
