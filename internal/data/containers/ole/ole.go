// Package ole reads Microsoft Compound File Binary (OLE2/CFB) containers.
//
// A compound file is a small file system: a header points at a FAT, a
// directory tree of storages and streams, and (for small streams) a mini
// stream with its own FAT. Windows stores Jump Lists, legacy Office documents,
// installer packages and many application caches in it.
//
// This reader is deliberately strict about structure: a bad sector link,
// a short chain, a truncated header or a directory cycle is an explicit
// error, never a silently short stream. It never writes to the source and
// never fabricates bytes. Stream contents are materialized only when asked
// for, and each stream is bounded by Limits.MaxStreamBytes.
//
// Scope:
//
//   - header versions 3 (512-byte sectors) and 4 (4096-byte sectors);
//   - the FAT and DIFAT (including the extra DIFAT sectors of large files);
//   - the mini stream and mini FAT for streams below the cutoff;
//   - the directory tree (left/right/child sibling links), walked in order
//     with cycle and bounds protection;
//   - stream contents by path.
//
// This is a Go port of forensic-core's data/containers/cfb.rs, which the
// Rust ole.rs reader builds on. The higher-level Office classification and
// property-set decoding in ole.rs are not part of this package.
package ole

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Signature is the eight-byte compound file signature.
var Signature = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// signature is the unexported alias used internally.
var signature = Signature

const (
	// HeaderBytes is the CFB header length; sector 0 is padded to the sector
	// size in version 4.
	HeaderBytes = 512
	// DirectoryEntryBytes is the size of one directory entry.
	DirectoryEntryBytes = 128
	// MaxRegularSector is the largest regular sector number.
	MaxRegularSector uint32 = 0xFFFFFFFA
	// EndOfChain terminates a sector chain.
	EndOfChain uint32 = 0xFFFFFFFE
	// FreeSector marks an unallocated sector.
	FreeSector uint32 = 0xFFFFFFFF
	// FATSectorMark marks a sector that holds part of the FAT.
	FATSectorMark uint32 = 0xFFFFFFFD
	// DIFATSectorMark marks a sector that holds part of the DIFAT.
	DIFATSectorMark uint32 = 0xFFFFFFFC
	// NoEntry is the empty sibling/child link.
	NoEntry uint32 = 0xFFFFFFFF
	// DefaultMaxStreamBytes is the default largest stream materialized.
	DefaultMaxStreamBytes uint64 = 64 * 1024 * 1024
)

// Lower-case aliases keep the implementation readable and mirror the Rust
// names.
const (
	headerBytes         = HeaderBytes
	directoryEntryBytes = DirectoryEntryBytes
	maxRegularSector    = MaxRegularSector
	endOfChain          = EndOfChain
	freeSector          = FreeSector
	fatSectorMark       = FATSectorMark
	noEntry             = NoEntry
)

// Kind is what a directory entry describes.
type Kind uint8

const (
	// KindEmpty is a free or unallocated entry.
	KindEmpty Kind = 0
	// KindStorage is a directory that holds other entries.
	KindStorage Kind = 1
	// KindStream is a byte stream.
	KindStream Kind = 2
	// KindRoot is the root entry (a storage with no name in the tree).
	KindRoot Kind = 5
)

const (
	kindEmpty   = KindEmpty
	kindStorage = KindStorage
	kindStream  = KindStream
	kindRoot    = KindRoot
)

// Label returns "empty", "storage", "stream" or "root".
func (k Kind) Label() string {
	switch k {
	case KindStorage:
		return "storage"
	case KindStream:
		return "stream"
	case KindRoot:
		return "root"
	default:
		return "empty"
	}
}

func kindFromCode(code uint8) Kind {
	switch code {
	case 1:
		return KindStorage
	case 2:
		return KindStream
	case 5:
		return KindRoot
	default:
		return KindEmpty
	}
}

// CLSID is the class identifier stored in a directory entry. The first three
// fields are little-endian, as the GUID text form requires.
type CLSID [16]byte

// IsZero reports whether the identifier is all zeroes.
func (c CLSID) IsZero() bool { return c == CLSID{} }

// String renders the canonical GUID text.
func (c CLSID) String() string {
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(c[0:4]),
		binary.LittleEndian.Uint16(c[4:6]),
		binary.LittleEndian.Uint16(c[6:8]),
		c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15])
}

// Entry is one directory record.
//
// Created and Modified are the writer's FILETIME values: 100-nanosecond ticks
// since 1601-01-01. Zero means the writer stored no time. They are directory
// metadata of the compound file, not the underlying volume's timestamps.
type Entry struct {
	// Index is the position in the directory.
	Index uint32
	// Name is the entry name decoded from UTF-16.
	Name string
	// Kind is the entry type.
	Kind Kind
	// Type mirrors Kind under the format's field name.
	Type Kind
	// Color is the red-black tree colour bit.
	Color uint8
	// Left, Right and Child are sibling and child links. NoEntry means none.
	Left  uint32
	Right uint32
	Child uint32

	// CLSID is the class identifier, when the writer stored one.
	CLSID CLSID
	// State is the storage state bits.
	State uint32
	// Created and Modified are FILETIME ticks since 1601 (100 ns units).
	Created  uint64
	Modified uint64

	// StartSector is the first regular sector, or the first mini sector for a
	// stream below the mini cutoff.
	StartSector uint32
	// Size is the declared stream size. For the root entry it is the mini
	// stream size.
	Size uint64
}

// IsStream reports whether the entry is a stream.
func (e *Entry) IsStream() bool { return e.Kind == KindStream }

// IsStorage reports whether the entry is a storage or the root entry.
func (e *Entry) IsStorage() bool { return e.Kind == KindStorage || e.Kind == KindRoot }

// Header is the parsed CFB header.
type Header struct {
	MajorVersion    uint16
	MinorVersion    uint16
	ByteOrder       uint16
	SectorShift     uint16
	MiniSectorShift uint16
	SectorSize      uint32
	MiniSectorSize  uint32
	// Sectors is the number of regular sectors after the header.
	Sectors          uint32
	FATSectors       uint32
	DirectorySectors uint32
	MiniCutoff       uint32
	MiniFATSectors   uint32
	DIFATSectors     uint32
}

// Stats describes a parsed file.
type Stats struct {
	SectorSize       uint32
	Sectors          uint32
	FATEntries       int
	DirectoryEntries int
	Streams          int
	Storages         int
	MiniStreamBytes  int
	MiniFATEntries   int
}

// Limits bound the resources one compound file may consume.
type Limits struct {
	// MaxStreamBytes is the largest stream (and mini stream) materialized.
	// Zero means DefaultMaxStreamBytes.
	MaxStreamBytes uint64
}

func (l Limits) normalized() Limits {
	if l.MaxStreamBytes == 0 {
		l.MaxStreamBytes = DefaultMaxStreamBytes
	}
	return l
}

// Errors for path lookups. Structural failures are returned as
// *source.Error with source.ErrCorrupt or source.ErrUnsupported.
var (
	ErrNotFound    = errors.New("ole: entry not found")
	ErrInvalidPath = errors.New("ole: invalid path")
	ErrNotStorage  = errors.New("ole: entry is not a storage")
	ErrNotStream   = errors.New("ole: entry is not a stream")
)

// File is a parsed compound file over a ByteSource.
type File struct {
	src              source.ByteSource
	header           Header
	fat              []uint32
	miniFAT          []uint32
	miniStream       []byte
	entries          []Entry
	directorySectors []uint32
	limits           Limits
}

// Open parses a compound file with the default limits.
func Open(src source.ByteSource) (*File, error) {
	return OpenWithLimits(src, Limits{})
}

// OpenWithLimits parses a compound file with explicit limits.
func OpenWithLimits(src source.ByteSource, limits Limits) (*File, error) {
	limits = limits.normalized()
	length := src.Len()
	if length < headerBytes {
		return nil, corrupt(0, "file is %d bytes, shorter than the %d-byte CFB header", length, headerBytes)
	}

	fixed, err := source.ReadVecAt(src, 0, headerBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(fixed[0:8], Signature[:]) {
		return nil, corrupt(0, "not a compound file: signature mismatch")
	}
	if order := u16At(fixed, 28); order != 0xFFFE {
		return nil, corrupt(28, "unsupported byte order 0x%04X", order)
	}
	major := u16At(fixed, 26)
	minor := u16At(fixed, 24)
	shift := u16At(fixed, 30)
	var expectedShift uint16
	switch major {
	case 3:
		expectedShift = 9
	case 4:
		expectedShift = 12
	default:
		return nil, unsupported("unsupported compound file version %d", major)
	}
	if shift != expectedShift {
		return nil, corrupt(30, "sector shift %d does not match version %d", shift, major)
	}
	miniShift := u16At(fixed, 32)
	if miniShift != 6 {
		return nil, corrupt(32, "unsupported mini sector shift %d", miniShift)
	}
	sectorSize := uint32(1) << shift

	sectors := uint32(0)
	if length/uint64(sectorSize) > 0 {
		sectors = uint32(length/uint64(sectorSize) - 1)
	}
	header := Header{
		MajorVersion:     major,
		MinorVersion:     minor,
		ByteOrder:        0xFFFE,
		SectorShift:      shift,
		MiniSectorShift:  miniShift,
		SectorSize:       sectorSize,
		MiniSectorSize:   1 << miniShift,
		Sectors:          sectors,
		FATSectors:       u32At(fixed, 44),
		DirectorySectors: u32At(fixed, 40),
		MiniCutoff:       u32At(fixed, 56),
		MiniFATSectors:   u32At(fixed, 64),
		DIFATSectors:     u32At(fixed, 72),
	}
	firstDirectory := u32At(fixed, 48)
	firstMiniFAT := u32At(fixed, 60)
	firstDIFAT := u32At(fixed, 68)

	// A declared table cannot be larger than the file, which also keeps a
	// crafted header from forcing a huge allocation.
	if header.FATSectors > header.Sectors {
		return nil, corrupt(44, "the header declares %d FAT sectors but the file has %d sectors", header.FATSectors, header.Sectors)
	}
	if header.DirectorySectors > header.Sectors {
		return nil, corrupt(40, "the header declares %d directory sectors but the file has %d sectors", header.DirectorySectors, header.Sectors)
	}
	if header.MiniFATSectors > header.Sectors {
		return nil, corrupt(64, "the header declares %d mini FAT sectors but the file has %d sectors", header.MiniFATSectors, header.Sectors)
	}
	if header.DIFATSectors > header.Sectors {
		return nil, corrupt(72, "the header declares %d DIFAT sectors but the file has %d sectors", header.DIFATSectors, header.Sectors)
	}

	// The FAT sector list lives partly in the header and partly in the DIFAT
	// chain. Collect both before reading the FAT itself.
	fatSectorList := make([]uint32, 0, header.FATSectors)
	for index := 0; index < 109; index++ {
		sector := u32At(fixed, 76+index*4)
		if sector == freeSector {
			continue
		}
		if sector >= maxRegularSector {
			return nil, corrupt(76+uint64(index)*4, "DIFAT entry %d links to invalid sector 0x%08X", index, sector)
		}
		fatSectorList = append(fatSectorList, sector)
	}
	entriesPerDIFAT := int(sectorSize/4) - 1
	difat := firstDIFAT
	seenDIFAT := uint32(0)
	for difat != endOfChain && difat != freeSector {
		if seenDIFAT >= header.DIFATSectors {
			break
		}
		seenDIFAT++
		data, err := readSector(src, header, difat)
		if err != nil {
			return nil, err
		}
		for index := 0; index < entriesPerDIFAT; index++ {
			sector := u32At(data, index*4)
			if sector == freeSector {
				continue
			}
			if sector >= maxRegularSector {
				return nil, corrupt(sectorOffset(header, difat), "DIFAT sector %d links to invalid sector 0x%08X", difat, sector)
			}
			fatSectorList = append(fatSectorList, sector)
		}
		difat = u32At(data, entriesPerDIFAT*4)
	}
	if len(fatSectorList) > int(header.FATSectors) {
		fatSectorList = fatSectorList[:header.FATSectors]
	}
	if len(fatSectorList) < int(header.FATSectors) {
		return nil, corrupt(44, "the FAT has %d sectors, but the header declares %d", len(fatSectorList), header.FATSectors)
	}

	entriesPerSector := int(sectorSize / 4)
	fat := make([]uint32, 0, len(fatSectorList)*entriesPerSector)
	for _, sector := range fatSectorList {
		data, err := readSector(src, header, sector)
		if err != nil {
			return nil, err
		}
		for index := 0; index < entriesPerSector; index++ {
			fat = append(fat, u32At(data, index*4))
		}
	}

	// Version 3 leaves the directory sector count at zero, so the chain itself
	// is the only length; version 4 declares it and it caps the chain.
	declaredDirectory := 0
	if major != 3 {
		declaredDirectory = int(header.DirectorySectors)
	}
	directorySectors, err := followChain(header, fat, firstDirectory, declaredDirectory, true)
	if err != nil {
		return nil, err
	}
	directoryBytes := make([]byte, 0, len(directorySectors)*int(sectorSize))
	for _, sector := range directorySectors {
		data, err := readSector(src, header, sector)
		if err != nil {
			return nil, err
		}
		directoryBytes = append(directoryBytes, data...)
	}
	if len(directoryBytes) < directoryEntryBytes {
		return nil, corrupt(0, "the compound file has no root directory")
	}
	entries := make([]Entry, 0, len(directoryBytes)/directoryEntryBytes)
	for index := 0; index*directoryEntryBytes+directoryEntryBytes <= len(directoryBytes); index++ {
		raw := directoryBytes[index*directoryEntryBytes : (index+1)*directoryEntryBytes]
		entries = append(entries, parseEntry(uint32(index), raw, major))
	}
	if len(entries) == 0 || entries[0].Kind != KindRoot {
		return nil, corrupt(0, "the compound file has no root directory")
	}

	var miniFAT []uint32
	if header.MiniFATSectors > 0 && firstMiniFAT != endOfChain {
		sectors, err := followChain(header, fat, firstMiniFAT, int(header.MiniFATSectors), true)
		if err != nil {
			return nil, err
		}
		miniFAT = make([]uint32, 0, len(sectors)*entriesPerSector)
		for _, sector := range sectors {
			data, err := readSector(src, header, sector)
			if err != nil {
				return nil, err
			}
			for index := 0; index < entriesPerSector; index++ {
				miniFAT = append(miniFAT, u32At(data, index*4))
			}
		}
	}

	// The root entry's stream is the mini stream; every small stream is a
	// slice of it.
	root := &entries[0]
	var miniStream []byte
	if root.Size > 0 {
		if root.Size > limits.MaxStreamBytes {
			return nil, corrupt(0, "mini stream is %d bytes, above the %d-byte cap", root.Size, limits.MaxStreamBytes)
		}
		if root.Size > uint64(maxInt()) {
			return nil, corrupt(0, "mini stream is %d bytes, larger than this platform can address", root.Size)
		}
		sectors, err := followChain(header, fat, root.StartSector, 0, true)
		if err != nil {
			return nil, err
		}
		miniStream = make([]byte, 0, int(root.Size))
		for _, sector := range sectors {
			data, err := readSector(src, header, sector)
			if err != nil {
				return nil, err
			}
			miniStream = append(miniStream, data...)
			if uint64(len(miniStream)) >= root.Size {
				break
			}
		}
		if uint64(len(miniStream)) < root.Size {
			return nil, corrupt(0, "mini stream declares %d bytes but only %d are reachable", root.Size, len(miniStream))
		}
		miniStream = miniStream[:root.Size]
	}

	return &File{
		src:              src,
		header:           header,
		fat:              fat,
		miniFAT:          miniFAT,
		miniStream:       miniStream,
		entries:          entries,
		directorySectors: directorySectors,
		limits:           limits,
	}, nil
}

// Header returns the parsed header.
func (f *File) Header() Header { return f.header }

// Entries returns every directory entry, in directory order.
func (f *File) Entries() []Entry {
	return append([]Entry(nil), f.entries...)
}

// Root returns the root entry.
func (f *File) Root() *Entry {
	if len(f.entries) == 0 {
		return nil
	}
	return &f.entries[0]
}

// Stats returns counts describing the file.
func (f *File) Stats() Stats {
	stats := Stats{
		SectorSize:       f.header.SectorSize,
		Sectors:          f.header.Sectors,
		FATEntries:       len(f.fat),
		DirectoryEntries: len(f.entries),
		MiniStreamBytes:  len(f.miniStream),
		MiniFATEntries:   len(f.miniFAT),
	}
	for i := range f.entries {
		switch f.entries[i].Kind {
		case KindStream:
			stats.Streams++
		case KindStorage, KindRoot:
			stats.Storages++
		}
	}
	return stats
}

// ListStorage returns the children of the storage at path, in the sibling
// tree's in-order (name) order. An empty path, "" or "/" names the root.
func (f *File) ListStorage(path string) ([]Entry, error) {
	entry, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	if !entry.IsStorage() {
		return nil, fmt.Errorf("%w: %q", ErrNotStorage, path)
	}
	return f.children(entry)
}

// FindStream resolves path and returns the stream entry.
func (f *File) FindStream(path string) (*Entry, error) {
	entry, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	if entry.Kind != KindStream {
		return nil, fmt.Errorf("%w: %q", ErrNotStream, path)
	}
	return entry, nil
}

// OpenStream materializes the stream at path as a read-only ByteSource with
// the supplied id. The bytes are real stream contents or an explicit error.
func (f *File) OpenStream(path string, id source.ID) (source.ByteSource, error) {
	entry, err := f.FindStream(path)
	if err != nil {
		return nil, err
	}
	return f.OpenEntry(entry, id)
}

// OpenEntry materializes one stream entry.
func (f *File) OpenEntry(entry *Entry, id source.ID) (source.ByteSource, error) {
	data, err := f.streamBytes(entry)
	if err != nil {
		return nil, err
	}
	return source.NewMemorySourceWithImage(id, f.src.ImageID(), data), nil
}

func (f *File) resolve(path string) (*Entry, error) {
	parts, err := splitPath(path)
	if err != nil {
		return nil, err
	}
	current := &f.entries[0]
	for _, part := range parts {
		children, err := f.children(current)
		if err != nil {
			return nil, err
		}
		next := -1
		for i := range children {
			if strings.EqualFold(children[i].Name, part) {
				next = int(children[i].Index)
				break
			}
		}
		if next < 0 {
			return nil, fmt.Errorf("%w: %q", ErrNotFound, path)
		}
		current = &f.entries[next]
	}
	return current, nil
}

// children walks the red-black sibling tree in order. A link past the entry
// table or a cycle is an explicit error.
func (f *File) children(storage *Entry) ([]Entry, error) {
	if !storage.IsStorage() {
		return nil, fmt.Errorf("%w: %q", ErrNotStorage, storage.Name)
	}
	out := make([]Entry, 0)
	visited := make([]bool, len(f.entries))
	stack := make([]uint32, 0)
	current := storage.Child
	for current != noEntry || len(stack) > 0 {
		for current != noEntry {
			if uint64(current) >= uint64(len(f.entries)) {
				return nil, corrupt(0, "directory link %d exceeds the %d entries", current, len(f.entries))
			}
			if visited[current] {
				return nil, corrupt(0, "directory tree cycles back to entry %d", current)
			}
			visited[current] = true
			stack = append(stack, current)
			current = f.entries[current].Left
		}
		index := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entry := f.entries[index]
		if entry.Kind != KindEmpty {
			out = append(out, entry)
		}
		current = entry.Right
	}
	return out, nil
}

func (f *File) streamBytes(entry *Entry) ([]byte, error) {
	if entry.Kind != KindStream {
		return nil, fmt.Errorf("%w: %q", ErrNotStream, entry.Name)
	}
	if entry.Size > f.limits.MaxStreamBytes {
		return nil, corrupt(0, "stream %q is %d bytes, above the %d-byte cap", entry.Name, entry.Size, f.limits.MaxStreamBytes)
	}
	if entry.Size == 0 {
		return []byte{}, nil
	}
	if entry.Size > uint64(maxInt()) {
		return nil, corrupt(0, "stream %q is %d bytes, larger than this platform can address", entry.Name, entry.Size)
	}
	want := int(entry.Size)

	if entry.Size < uint64(f.header.MiniCutoff) {
		if len(f.miniStream) == 0 || len(f.miniFAT) == 0 {
			return nil, corrupt(0, "a small stream is present but the mini stream is not")
		}
		sectors, err := followChain(f.header, f.miniFAT, entry.StartSector, 0, false)
		if err != nil {
			return nil, err
		}
		miniSize := uint64(f.header.MiniSectorSize)
		data := make([]byte, 0, want)
		for _, sector := range sectors {
			start := uint64(sector) * miniSize
			end := start + miniSize
			if end > uint64(len(f.miniStream)) {
				return nil, corrupt(sectorOffset(f.header, sector), "mini sector %d is outside the %d-byte mini stream", sector, len(f.miniStream))
			}
			data = append(data, f.miniStream[int(start):int(end)]...)
			if len(data) >= want {
				break
			}
		}
		if len(data) < want {
			return nil, corrupt(0, "stream %q declares %d bytes but only %d are reachable", entry.Name, entry.Size, len(data))
		}
		return data[:want], nil
	}

	sectors, err := followChain(f.header, f.fat, entry.StartSector, 0, true)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, want)
	for _, sector := range sectors {
		chunk, err := readSector(f.src, f.header, sector)
		if err != nil {
			return nil, err
		}
		data = append(data, chunk...)
		if len(data) >= want {
			break
		}
	}
	if len(data) < want {
		return nil, corrupt(0, "stream %q declares %d bytes but only %d are reachable", entry.Name, entry.Size, len(data))
	}
	return data[:want], nil
}

func parseEntry(index uint32, raw []byte, version uint16) Entry {
	nameLength := int(u16At(raw, 64))
	name := ""
	if nameLength >= 2 && nameLength <= 64 {
		units := make([]uint16, 0, (nameLength-2)/2)
		for offset := 0; offset+2 <= nameLength-2; offset += 2 {
			unit := u16At(raw, offset)
			if unit == 0 {
				break
			}
			units = append(units, unit)
		}
		name = string(utf16.Decode(units))
	}
	size := uint64(u32At(raw, 120))
	if version != 3 {
		size = u64At(raw, 120)
	}
	var clsid CLSID
	copy(clsid[:], raw[80:96])
	kind := kindFromCode(raw[66])
	return Entry{
		Index:       index,
		Name:        name,
		Kind:        kind,
		Type:        kind,
		Color:       raw[67],
		Left:        u32At(raw, 68),
		Right:       u32At(raw, 72),
		Child:       u32At(raw, 76),
		CLSID:       clsid,
		State:       u32At(raw, 96),
		Created:     u64At(raw, 100),
		Modified:    u64At(raw, 108),
		StartSector: u32At(raw, 116),
		Size:        size,
	}
}

// followChain walks a sector chain. expected is the number of sectors the
// header declares (zero when unknown); a declared length is a cap, not a
// requirement. Revisiting a sector is a cycle error.
func followChain(header Header, table []uint32, start uint32, expected int, regular bool) ([]uint32, error) {
	capacity := expected
	if capacity == 0 {
		if regular {
			capacity = int(header.Sectors)
		} else {
			capacity = len(table)
		}
	}
	sectors := make([]uint32, 0)
	visited := make([]bool, len(table))
	current := start
	for current != endOfChain {
		if current == freeSector || current >= maxRegularSector {
			return nil, corrupt(sectorOffset(header, start), "sector %d links to invalid sector 0x%08X", start, current)
		}
		if regular && current >= header.Sectors {
			return nil, corrupt(sectorOffset(header, current), "sector %d is outside the %d sectors in the file", current, header.Sectors)
		}
		if len(sectors) >= capacity {
			return nil, corrupt(sectorOffset(header, start), "sector chain starting at %d is longer than the file allows", start)
		}
		if uint64(current) >= uint64(len(table)) {
			return nil, corrupt(sectorOffset(header, current), "the FAT has %d entries, so sector %d has no entry", len(table), current)
		}
		if visited[current] {
			return nil, corrupt(sectorOffset(header, current), "sector chain loops back to sector %d", current)
		}
		visited[current] = true
		sectors = append(sectors, current)
		current = table[current]
	}
	return sectors, nil
}

func readSector(src source.ByteSource, header Header, sector uint32) ([]byte, error) {
	if sector >= header.Sectors {
		return nil, corrupt(sectorOffset(header, sector), "sector %d is outside the %d sectors in the file", sector, header.Sectors)
	}
	start := sectorOffset(header, sector)
	data, err := source.ReadVecAt(src, start, uint64(header.SectorSize))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func sectorOffset(header Header, sector uint32) uint64 {
	return (uint64(sector) + 1) * uint64(header.SectorSize)
}

func splitPath(path string) ([]string, error) {
	normalized := strings.ReplaceAll(path, "\\", "/")
	parts := make([]string, 0)
	for _, part := range strings.Split(normalized, "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			return nil, fmt.Errorf("%w: %q", ErrInvalidPath, path)
		default:
			parts = append(parts, part)
		}
	}
	return parts, nil
}

func corrupt(offset uint64, format string, args ...any) error {
	return source.NewCorrupt(offset, fmt.Sprintf(format, args...))
}

func unsupported(format string, args ...any) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(format, args...)}
}

func u16At(buf []byte, offset int) uint16 {
	if offset < 0 || offset+2 > len(buf) {
		return 0
	}
	return binary.LittleEndian.Uint16(buf[offset:])
}

func u32At(buf []byte, offset int) uint32 {
	if offset < 0 || offset+4 > len(buf) {
		return 0
	}
	return binary.LittleEndian.Uint32(buf[offset:])
}

func u64At(buf []byte, offset int) uint64 {
	if offset < 0 || offset+8 > len(buf) {
		return 0
	}
	return binary.LittleEndian.Uint64(buf[offset:])
}

func maxInt() int { return int(^uint(0) >> 1) }
