// Package cab reads Microsoft Cabinet (`.cab`) archives.
//
// A cabinet is a CFHEADER, a CFFOLDER array, a CFFILE array, and folder data
// made of CFDATA blocks. The reader validates every offset and size against
// the declared cabinet length before using it: a range that leaves the file
// is an explicit corrupt-data error, never a silent zero.
//
// Compression:
//
//   - type 0 (none): stored bytes are the uncompressed bytes;
//   - type 1 (MSZIP): "CK" plus a raw DEFLATE stream whose preset dictionary
//     is the previous 32 KiB of folder output;
//   - type 3 (LZX): listed and validated, but this port has no LZX decoder.
//     Opening a file from an LZX folder returns source.ErrUnsupported naming
//     LZX, while the header, folder table and file table remain readable;
//   - type 2 (Quantum) and undefined types are refused at Open by name.
//
// Multi-part sets are listed in full. A file that continues into the next
// cabinet is reported with Available < Size, and reading it returns
// source.ErrUnsupported naming the next cabinet instead of pretending the
// missing bytes are present.
//
// This is a Go port of forensic-core's data/containers/cab.rs.
package cab

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Signature is the cabinet signature.
var Signature = [4]byte{'M', 'S', 'C', 'F'}

const (
	// HeaderFixed is the fixed CFHEADER length.
	HeaderFixed = 36
	// FolderFixed is the fixed CFFOLDER length.
	FolderFixed = 8
	// FileFixed is the fixed CFFILE length before the name.
	FileFixed = 16
	// DataFixed is the fixed CFDATA length before the stored bytes.
	DataFixed = 8

	// MaxEntrySize is the largest entry this reader materializes.
	MaxEntrySize uint64 = 256 * 1024 * 1024
	// MSZIPWindow is the MSZIP/LZX history window in bytes.
	MSZIPWindow = 32 * 1024
	// MaxFileName bounds the NUL scan for one file name.
	MaxFileName = 255
	// MaxMultiPartNames bounds the multipart name fields.
	MaxMultiPartNames = 4096
)

// CFHEADER flags.
const (
	FlagPrevCabinet    uint16 = 0x0001
	FlagNextCabinet    uint16 = 0x0002
	FlagReservePresent uint16 = 0x0004
	FlagEncrypted      uint16 = 0x0008

	flagKnown = FlagPrevCabinet | FlagNextCabinet | FlagReservePresent | FlagEncrypted
)

// Rust-style aliases make the format's documented names available.
const (
	FLAG_PREV_CABINET    = FlagPrevCabinet
	FLAG_NEXT_CABINET    = FlagNextCabinet
	FLAG_RESERVE_PRESENT = FlagReservePresent
	FLAG_ENCRYPTED       = FlagEncrypted
)

// CFFOLDER compression types.
const (
	MethodNone    uint16 = 0
	MethodMSZIP   uint16 = 1
	MethodQuantum uint16 = 2
	MethodLZX     uint16 = 3
)

// CFFILE attributes.
const (
	AttrNameIsUTF uint16 = 0x0080
	AttrReadOnly  uint16 = 0x0001
	AttrHidden    uint16 = 0x0002
	AttrSystem    uint16 = 0x0004
	AttrArchive   uint16 = 0x0020
	AttrExecute   uint16 = 0x0040

	ATTR_NAME_IS_UTF = AttrNameIsUTF
	ATTR_READ_ONLY   = AttrReadOnly
	ATTR_HIDDEN      = AttrHidden
	ATTR_SYSTEM      = AttrSystem
	ATTR_ARCHIVE     = AttrArchive
	ATTR_EXECUTE     = AttrExecute
)

// Errors for lookups. Structural failures use *source.Error with
// source.ErrCorrupt or source.ErrUnsupported.
var (
	ErrNotFound      = errors.New("cab: entry not found")
	ErrInvalidPath   = errors.New("cab: invalid path")
	ErrEntryTooLarge = errors.New("cab: entry exceeds the size cap")
)

// Compression identifies how a folder's CFDATA blocks are stored.
type Compression uint16

const (
	CompressionNone    Compression = Compression(MethodNone)
	CompressionMSZIP   Compression = Compression(MethodMSZIP)
	CompressionQuantum Compression = Compression(MethodQuantum)
	CompressionLZX     Compression = Compression(MethodLZX)
)

// TypeCode returns the number stored in CFFOLDER.typeCompress (the low
// nibble; LZX keeps its window bits in the raw field, not here).
func (c Compression) TypeCode() uint16 { return uint16(c) }

// Label returns the documented method name.
func (c Compression) Label() string {
	switch c {
	case CompressionNone:
		return "none"
	case CompressionMSZIP:
		return "MSZIP"
	case CompressionQuantum:
		return "Quantum"
	case CompressionLZX:
		return "LZX"
	default:
		return "unknown"
	}
}

// Header is the parsed CFHEADER. Info is an alias for callers that use the
// Rust reader's name.
type Header struct {
	CBCabinet    uint32
	COFFFiles    uint32
	VersionMajor uint8
	VersionMinor uint8
	FolderCount  uint16
	FileCount    uint16
	Flags        uint16
	SetID        uint16
	CabinetIndex uint16
	// Multipart names, present only when the corresponding flag is set.
	CabinetPrev   *string
	DiskPrev      *string
	CabinetNext   *string
	DiskNext      *string
	HeaderReserve uint16
	FolderReserve uint8
	DataReserve   uint16
}

// Info is the header, under the name the Rust reader uses.
type Info = Header

// HasPrev reports whether a previous part is named.
func (h Header) HasPrev() bool { return h.Flags&FlagPrevCabinet != 0 }

// HasNext reports whether a next part is named.
func (h Header) HasNext() bool { return h.Flags&FlagNextCabinet != 0 }

// IsMultiPart reports whether this cabinet is one part of a larger set.
func (h Header) IsMultiPart() bool { return h.HasPrev() || h.HasNext() }

// Version returns the major and minor version.
func (h Header) Version() (uint8, uint8) { return h.VersionMajor, h.VersionMinor }

// Block is one CFDATA record.
type Block struct {
	// Offset is the byte offset of the CFDATA header.
	Offset uint64
	// DataOffset is the byte offset of the stored bytes.
	DataOffset uint64
	Checksum   uint32
	// StoredSize is cbData.
	StoredSize uint16
	// UncompressedSize is cbUncomp.
	UncompressedSize uint16
}

// Folder is one CFFOLDER and the CFDATA blocks that hold its bytes.
type Folder struct {
	Index            int
	COFFCabStart     uint32
	DataBlocks       uint16
	TypeCompress     uint16
	Compression      Compression
	StoredSize       uint64
	UncompressedSize uint64
	Blocks           []Block
}

// BlockSizes returns (cbData, cbUncomp) for each block in folder order.
func (f Folder) BlockSizes() [][2]uint16 {
	out := make([][2]uint16, len(f.Blocks))
	for i, block := range f.Blocks {
		out[i] = [2]uint16{block.StoredSize, block.UncompressedSize}
	}
	return out
}

// Entry is one CFFILE record.
type Entry struct {
	// Index is the position in the CFFILE array.
	Index int
	// Name is the final path component.
	Name string
	// Path is the normalized, `/`-separated path relative to the cabinet.
	Path string
	// RawPath is the name exactly as stored, after character decoding.
	RawPath string
	// Size is cbFile.
	Size uint64
	// Available is the number of bytes present in this cabinet; it is smaller
	// than Size only when the file continues into the next part of a set.
	Available uint64
	// Folder is the index into Folders.
	Folder int
	// FolderOffset is uoffFolderStart.
	FolderOffset uint32
	// Date and Time are the raw MS-DOS words.
	Date uint16
	Time uint16
	// Modified is Date/Time interpreted as UTC, or nil for an invalid stamp.
	Modified *int64
	// Attributes is the raw attribs word.
	Attributes uint16
	// UTF8Name reports whether the name was flagged UTF-8.
	UTF8Name bool
}

// IsComplete reports whether all declared bytes are present here.
func (e *Entry) IsComplete() bool { return e.Available == e.Size }

// IsReadOnly reports the read-only attribute.
func (e *Entry) IsReadOnly() bool { return e.Attributes&AttrReadOnly != 0 }

// IsHidden reports the hidden attribute.
func (e *Entry) IsHidden() bool { return e.Attributes&AttrHidden != 0 }

// IsSystem reports the system attribute.
func (e *Entry) IsSystem() bool { return e.Attributes&AttrSystem != 0 }

// IsArchive reports the archive attribute.
func (e *Entry) IsArchive() bool { return e.Attributes&AttrArchive != 0 }

// IsExecutable reports the execute attribute.
func (e *Entry) IsExecutable() bool { return e.Attributes&AttrExecute != 0 }

// Cabinet is a read-only cabinet over a ByteSource.
type Cabinet struct {
	src                source.ByteSource
	header             Header
	folders            []Folder
	entries            []Entry
	byPath             map[string]int
	checksumMismatches atomic.Uint64
}

// Open parses and validates a cabinet.
func Open(src source.ByteSource) (*Cabinet, error) {
	header, foldersStart, err := parseHeader(src)
	if err != nil {
		return nil, err
	}
	folders, err := parseFolders(src, header, foldersStart)
	if err != nil {
		return nil, err
	}
	if err := parseDataBlocks(src, header, folders); err != nil {
		return nil, err
	}
	entries, err := parseEntries(src, header, folders)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]int, len(entries))
	for i := range entries {
		if _, exists := byPath[entries[i].Path]; !exists {
			byPath[entries[i].Path] = i
		}
	}
	return &Cabinet{
		src:     src,
		header:  header,
		folders: folders,
		entries: entries,
		byPath:  byPath,
	}, nil
}

// Info returns the parsed header.
func (c *Cabinet) Info() Info { return c.header }

// Folders returns the folder table in header order.
func (c *Cabinet) Folders() []Folder {
	out := make([]Folder, len(c.folders))
	for i := range c.folders {
		out[i] = c.folders[i]
		out[i].Blocks = append([]Block(nil), c.folders[i].Blocks...)
	}
	return out
}

// Files returns the file table in CFFILE order.
func (c *Cabinet) Files() []Entry { return append([]Entry(nil), c.entries...) }

// Entry returns the file entry at index.
func (c *Cabinet) Entry(index int) (*Entry, bool) {
	if index < 0 || index >= len(c.entries) {
		return nil, false
	}
	return &c.entries[index], true
}

// Find resolves a path, accepting both `/` and `\` separators.
func (c *Cabinet) Find(name string) (*Entry, bool) {
	normalized, err := sanitizeEntryPath(name)
	if err != nil {
		return nil, false
	}
	index, ok := c.byPath[normalized]
	if !ok {
		return nil, false
	}
	return &c.entries[index], true
}

// IsMultiPart reports whether this cabinet is one part of a set.
func (c *Cabinet) IsMultiPart() bool { return c.header.IsMultiPart() }

// ChecksumMismatches is the number of decoded blocks whose stored checksum did
// not match. A mismatch is a warning: the bytes are still returned.
func (c *Cabinet) ChecksumMismatches() uint64 { return c.checksumMismatches.Load() }

// OpenFile decodes the named entry and returns it as a read-only source.
func (c *Cabinet) OpenFile(name string, id source.ID) (source.ByteSource, error) {
	normalized, err := sanitizeEntryPath(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	index, ok := c.byPath[normalized]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return c.OpenEntry(index, id)
}

// OpenEntry decodes the entry at index.
func (c *Cabinet) OpenEntry(index int, id source.ID) (source.ByteSource, error) {
	data, err := c.readEntry(index)
	if err != nil {
		return nil, err
	}
	return source.NewMemorySourceWithImage(id, c.src.ImageID(), data), nil
}

func (c *Cabinet) readEntry(index int) ([]byte, error) {
	if index < 0 || index >= len(c.entries) {
		return nil, fmt.Errorf("%w: CAB has no file entry %d", ErrNotFound, index)
	}
	entry := &c.entries[index]
	if entry.Size > MaxEntrySize {
		return nil, fmt.Errorf("%w: CAB entry %s is %d bytes; the read cap is %d",
			ErrEntryTooLarge, entry.Path, entry.Size, MaxEntrySize)
	}
	if entry.Available < entry.Size {
		next := "<unknown>"
		if c.header.CabinetNext != nil {
			next = *c.header.CabinetNext
		}
		return nil, unsupported(
			"CAB entry %s continues into the next cabinet (%s); this part holds %d of %d bytes",
			entry.Path, next, entry.Available, entry.Size)
	}
	if entry.Size == 0 {
		return []byte{}, nil
	}
	if entry.Folder < 0 || entry.Folder >= len(c.folders) {
		return nil, corrupt(0, "CAB entry %s names folder %d but the cabinet has %d folders",
			entry.Path, entry.Folder, len(c.folders))
	}
	folder := &c.folders[entry.Folder]
	stream, err := newFolderStream(folder)
	if err != nil {
		return nil, err
	}

	start := uint64(entry.FolderOffset)
	end := start + entry.Size
	out := make([]byte, 0, int(entry.Size))
	position := uint64(0)
	for blockIndex := range folder.Blocks {
		block := &folder.Blocks[blockIndex]
		blockStart := position
		blockEnd := position + uint64(block.UncompressedSize)
		position = blockEnd
		// A plain folder needs no history, so blocks before the entry can be
		// skipped. MSZIP and LZX decode from the start of the folder to rebuild
		// the dictionary.
		if !stream.needsHistory() && blockEnd <= start {
			continue
		}
		if blockStart >= end {
			break
		}
		decoded, err := c.decodeBlock(folder, blockIndex, stream)
		if err != nil {
			return nil, err
		}
		if blockEnd > start {
			from := uint64(0)
			if start > blockStart {
				from = start - blockStart
			}
			to := end
			if blockEnd < to {
				to = blockEnd
			}
			to -= blockStart
			if from > to || to > uint64(len(decoded)) {
				return nil, corrupt(block.Offset,
					"CAB entry %s needs bytes [%d,%d) from block %d but only %d decoded",
					entry.Path, from, to, blockIndex, len(decoded))
			}
			out = append(out, decoded[from:to]...)
		}
	}
	if uint64(len(out)) != entry.Size {
		return nil, corrupt(uint64(entry.FolderOffset),
			"CAB entry %s decoded %d bytes but declares %d", entry.Path, len(out), entry.Size)
	}
	return out, nil
}

// folderStream is the decoder state one folder needs across its CFDATA blocks.
type folderStream struct {
	kind   Compression
	window []byte
}

func newFolderStream(folder *Folder) (*folderStream, error) {
	switch folder.Compression {
	case CompressionNone:
		return &folderStream{kind: CompressionNone}, nil
	case CompressionMSZIP:
		return &folderStream{kind: CompressionMSZIP, window: make([]byte, MSZIPWindow)}, nil
	case CompressionLZX:
		return nil, unsupported(
			"CAB folder %d uses LZX compression (type 3) with a %d-bit window; this reader does not decode LZX",
			folder.Index, folder.TypeCompress>>8)
	default:
		return nil, unsupported("CAB folder %d uses %s compression", folder.Index, folder.Compression.Label())
	}
}

func (s *folderStream) needsHistory() bool { return s.kind != CompressionNone }

func (c *Cabinet) decodeBlock(folder *Folder, blockIndex int, stream *folderStream) ([]byte, error) {
	block := &folder.Blocks[blockIndex]
	stored, err := source.ReadVecAt(c.src, block.DataOffset, uint64(block.StoredSize))
	if err != nil {
		return nil, err
	}
	if block.Checksum != 0 {
		computed := dataChecksum(stored, block.StoredSize, block.UncompressedSize)
		if computed != block.Checksum {
			c.checksumMismatches.Add(1)
		}
	}

	switch folder.Compression {
	case CompressionNone:
		if block.StoredSize != block.UncompressedSize {
			return nil, corrupt(block.Offset,
				"CAB folder %d block %d stores %d bytes but declares %d uncompressed",
				folder.Index, blockIndex, block.StoredSize, block.UncompressedSize)
		}
		return stored, nil
	case CompressionMSZIP:
		decoded, err := inflateMSZIP(stored, int(block.UncompressedSize), stream.window, block.Offset)
		if err != nil {
			return nil, err
		}
		stream.window = append(stream.window, decoded...)
		if len(stream.window) > MSZIPWindow {
			trimmed := append([]byte(nil), stream.window[len(stream.window)-MSZIPWindow:]...)
			stream.window = trimmed
		}
		return decoded, nil
	default:
		return nil, unsupported("CAB folder %d uses %s compression", folder.Index, folder.Compression.Label())
	}
}

// inflateMSZIP decodes one MSZIP block with window as its preset dictionary.
func inflateMSZIP(stored []byte, expected int, window []byte, offset uint64) ([]byte, error) {
	if len(stored) < 2 || stored[0] != 'C' || stored[1] != 'K' {
		return nil, corrupt(offset, "MSZIP block does not start with the CK signature")
	}
	reader := flate.NewReaderDict(bytes.NewReader(stored[2:]), window)
	data, readErr := io.ReadAll(io.LimitReader(reader, int64(expected)+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, corrupt(offset, "MSZIP block failed to inflate: %v", readErr)
	}
	if closeErr != nil {
		return nil, corrupt(offset, "MSZIP block failed to inflate: %v", closeErr)
	}
	if len(data) != expected {
		return nil, corrupt(offset, "MSZIP block inflated to %d bytes but %d were declared", len(data), expected)
	}
	return data, nil
}

func parseHeader(src source.ByteSource) (Header, uint64, error) {
	sourceLen := src.Len()
	if sourceLen < HeaderFixed {
		return Header{}, 0, corrupt(0, "CAB header needs %d bytes but the source holds %d", HeaderFixed, sourceLen)
	}
	fixed, err := source.ReadVecAt(src, 0, HeaderFixed)
	if err != nil {
		return Header{}, 0, err
	}
	if !bytes.Equal(fixed[0:4], Signature[:]) {
		return Header{}, 0, corrupt(0, "CAB signature MSCF is missing at offset 0")
	}

	header := Header{
		CBCabinet:    u32At(fixed, 8),
		COFFFiles:    u32At(fixed, 16),
		VersionMinor: fixed[24],
		VersionMajor: fixed[25],
		FolderCount:  u16At(fixed, 26),
		FileCount:    u16At(fixed, 28),
		Flags:        u16At(fixed, 30),
		SetID:        u16At(fixed, 32),
		CabinetIndex: u16At(fixed, 34),
	}
	if header.CBCabinet == 0 {
		return Header{}, 0, corrupt(8, "CAB declares zero cabinet bytes")
	}
	limit := uint64(header.CBCabinet)
	if limit > sourceLen {
		return Header{}, 0, corrupt(8, "CAB declares %d bytes but the source holds %d", header.CBCabinet, sourceLen)
	}
	if limit < HeaderFixed {
		return Header{}, 0, corrupt(8, "CAB declares %d bytes, shorter than its %d-byte header", header.CBCabinet, HeaderFixed)
	}
	if header.VersionMajor != 1 || header.VersionMinor != 3 {
		return Header{}, 0, unsupported("CAB version %d.%d; only 1.3 is defined", header.VersionMajor, header.VersionMinor)
	}
	if header.Flags&FlagEncrypted != 0 {
		return Header{}, 0, unsupported("CAB header flag 0x0008 is set; encrypted cabinets are not supported")
	}
	if reserved := header.Flags & ^uint16(flagKnown); reserved != 0 {
		return Header{}, 0, unsupported("CAB header flag bits 0x%04X are reserved", reserved)
	}

	cursor := uint64(HeaderFixed)
	if header.Flags&FlagReservePresent != 0 {
		if cursor+5 > limit {
			return Header{}, 0, corrupt(cursor, "CAB reserve counts are truncated")
		}
		record, err := source.ReadVecAt(src, cursor, 5)
		if err != nil {
			return Header{}, 0, err
		}
		cursor += 5
		header.HeaderReserve = u16At(record, 0)
		header.FolderReserve = record[2]
		header.DataReserve = u16At(record, 3)
	}
	if cursor+uint64(header.HeaderReserve) > limit {
		return Header{}, 0, corrupt(cursor, "CAB header reserve of %d bytes runs past the %d-byte cabinet", header.HeaderReserve, limit)
	}
	cursor += uint64(header.HeaderReserve)

	if header.Flags&(FlagPrevCabinet|FlagNextCabinet) != 0 {
		take := limit - cursor
		if take > MaxMultiPartNames {
			take = MaxMultiPartNames
		}
		buf, err := source.ReadVecAt(src, cursor, take)
		if err != nil {
			return Header{}, 0, err
		}
		position := 0
		if header.Flags&FlagPrevCabinet != 0 {
			cabinetPrev, next, err := takeCString(buf, position, "szCabinetPrev", cursor)
			if err != nil {
				return Header{}, 0, err
			}
			header.CabinetPrev = &cabinetPrev
			position = next
			diskPrev, next, err := takeCString(buf, position, "szDiskPrev", cursor)
			if err != nil {
				return Header{}, 0, err
			}
			header.DiskPrev = &diskPrev
			position = next
		}
		if header.Flags&FlagNextCabinet != 0 {
			cabinetNext, next, err := takeCString(buf, position, "szCabinetNext", cursor)
			if err != nil {
				return Header{}, 0, err
			}
			header.CabinetNext = &cabinetNext
			position = next
			diskNext, next, err := takeCString(buf, position, "szDiskNext", cursor)
			if err != nil {
				return Header{}, 0, err
			}
			header.DiskNext = &diskNext
			position = next
		}
		cursor += uint64(position)
	}

	return header, cursor, nil
}

func takeCString(buf []byte, position int, label string, base uint64) (string, int, error) {
	if position < 0 || position > len(buf) {
		return "", position, corrupt(base+uint64(position), "CAB %s is not NUL-terminated within the header", label)
	}
	relative := bytes.IndexByte(buf[position:], 0)
	if relative < 0 {
		return "", position, corrupt(base+uint64(position), "CAB %s is not NUL-terminated within the header", label)
	}
	value := decodeANSI(buf[position : position+relative])
	return value, position + relative + 1, nil
}

func parseFolders(src source.ByteSource, header Header, foldersStart uint64) ([]Folder, error) {
	limit := uint64(header.CBCabinet)
	stride := uint64(FolderFixed) + uint64(header.FolderReserve)
	foldersEnd := foldersStart + uint64(header.FolderCount)*stride
	if foldersEnd < foldersStart || foldersEnd > limit {
		return nil, corrupt(foldersStart, "CAB folder table for %d folders ends at %d, past the %d-byte cabinet",
			header.FolderCount, foldersEnd, limit)
	}
	coffFiles := uint64(header.COFFFiles)
	if coffFiles < foldersEnd {
		return nil, corrupt(16, "CAB coffFiles %d overlaps the folder table ending at %d", coffFiles, foldersEnd)
	}
	if coffFiles > limit {
		return nil, corrupt(16, "CAB coffFiles %d is past the %d-byte cabinet", coffFiles, limit)
	}
	if coffFiles+FileFixed > limit {
		return nil, corrupt(16, "CAB coffFiles %d leaves no room for a file entry", coffFiles)
	}

	folders := make([]Folder, 0, header.FolderCount)
	for index := 0; index < int(header.FolderCount); index++ {
		offset := foldersStart + uint64(index)*stride
		record, err := source.ReadVecAt(src, offset, FolderFixed)
		if err != nil {
			return nil, err
		}
		coffCabStart := u32At(record, 0)
		dataBlocks := u16At(record, 4)
		typeCompress := u16At(record, 6)
		compression := Compression(typeCompress & 0x000F)

		if compression == CompressionLZX {
			windowBits := typeCompress >> 8
			if typeCompress&0x00F0 != 0 {
				return nil, unsupported("CAB folder %d compression field 0x%04X sets reserved bits", index, typeCompress)
			}
			if windowBits < 15 || windowBits > 21 {
				return nil, unsupported(
					"CAB folder %d uses LZX compression (type 3) with a %d-bit window; MS-CAB allows 15..=21",
					index, windowBits)
			}
		} else if typeCompress&0xFFF0 != 0 {
			return nil, unsupported("CAB folder %d compression field 0x%04X sets reserved bits", index, typeCompress)
		}

		switch compression {
		case CompressionQuantum:
			return nil, unsupported("CAB folder %d uses Quantum compression (type 2)", index)
		case CompressionNone, CompressionMSZIP, CompressionLZX:
		default:
			return nil, unsupported("CAB folder %d uses unknown compression type %d", index, uint16(compression))
		}

		if dataBlocks > 0 {
			start := uint64(coffCabStart)
			if start < foldersEnd {
				return nil, corrupt(offset, "CAB folder %d data starts at %d, inside the folder table ending at %d",
					index, start, foldersEnd)
			}
			if start > limit {
				return nil, corrupt(offset, "CAB folder %d data starts at %d, past the %d-byte cabinet",
					index, start, limit)
			}
		}
		folders = append(folders, Folder{
			Index:        index,
			COFFCabStart: coffCabStart,
			DataBlocks:   dataBlocks,
			TypeCompress: typeCompress,
			Compression:  compression,
		})
	}
	return folders, nil
}

func parseDataBlocks(src source.ByteSource, header Header, folders []Folder) error {
	limit := uint64(header.CBCabinet)
	reserve := uint64(header.DataReserve)
	firstData := limit
	for i := range folders {
		if folders[i].DataBlocks > 0 && uint64(folders[i].COFFCabStart) < firstData {
			firstData = uint64(folders[i].COFFCabStart)
		}
	}
	if firstData < uint64(header.COFFFiles) {
		return corrupt(16, "CAB folder data starts at %d, before coffFiles %d", firstData, header.COFFFiles)
	}

	for folderIndex := range folders {
		folder := &folders[folderIndex]
		position := uint64(folder.COFFCabStart)
		for blockIndex := 0; blockIndex < int(folder.DataBlocks); blockIndex++ {
			headerEnd := position + DataFixed
			if headerEnd < position || headerEnd > limit {
				return corrupt(position, "CAB folder %d block %d CFDATA header at %d is truncated (cabinet is %d bytes)",
					folder.Index, blockIndex, position, limit)
			}
			record, err := source.ReadVecAt(src, position, DataFixed)
			if err != nil {
				return err
			}
			checksum := u32At(record, 0)
			cbData := u16At(record, 4)
			cbUncomp := u16At(record, 6)
			dataOffset := position + DataFixed
			end := dataOffset + uint64(cbData) + reserve
			if end < dataOffset || end > limit {
				return corrupt(position, "CAB folder %d block %d data [%d, +%d) runs past the %d-byte cabinet",
					folder.Index, blockIndex, dataOffset, cbData, limit)
			}
			folder.Blocks = append(folder.Blocks, Block{
				Offset:           position,
				DataOffset:       dataOffset,
				Checksum:         checksum,
				StoredSize:       cbData,
				UncompressedSize: cbUncomp,
			})
			folder.StoredSize += uint64(cbData)
			folder.UncompressedSize += uint64(cbUncomp)
			position = end
		}
	}
	return nil
}

func parseEntries(src source.ByteSource, header Header, folders []Folder) ([]Entry, error) {
	limit := uint64(header.CBCabinet)
	tableEnd := limit
	for i := range folders {
		if folders[i].DataBlocks > 0 && uint64(folders[i].COFFCabStart) < tableEnd {
			tableEnd = uint64(folders[i].COFFCabStart)
		}
	}

	entries := make([]Entry, 0, header.FileCount)
	position := uint64(header.COFFFiles)
	for index := 0; index < int(header.FileCount); index++ {
		headerEnd := position + FileFixed
		if headerEnd < position || headerEnd > tableEnd {
			return nil, corrupt(position, "CAB file entry %d header at %d is truncated", index, position)
		}
		fixed, err := source.ReadVecAt(src, position, FileFixed)
		if err != nil {
			return nil, err
		}
		cbFile := u32At(fixed, 0)
		folderOffset := u32At(fixed, 4)
		folderIndex := u16At(fixed, 8)
		date := u16At(fixed, 10)
		timeWord := u16At(fixed, 12)
		attributes := u16At(fixed, 14)

		if int(folderIndex) >= len(folders) {
			return nil, corrupt(position, "CAB file entry %d names folder %d but the cabinet has %d folders",
				index, folderIndex, len(folders))
		}
		folder := &folders[folderIndex]

		nameOffset := position + FileFixed
		nameSpace := tableEnd - nameOffset
		if nameSpace == 0 {
			return nil, corrupt(nameOffset, "CAB file entry %d has no room for a name", index)
		}
		take := nameSpace
		if take > MaxFileName+1 {
			take = MaxFileName + 1
		}
		chunk, err := source.ReadVecAt(src, nameOffset, take)
		if err != nil {
			return nil, err
		}
		nul := bytes.IndexByte(chunk, 0)
		if nul < 0 {
			return nil, corrupt(nameOffset, "CAB file entry %d name is not NUL-terminated within %d bytes", index, MaxFileName)
		}
		utf8Name := attributes&AttrNameIsUTF != 0
		rawPath, err := decodeName(chunk[:nul], utf8Name)
		if err != nil {
			return nil, corrupt(nameOffset, "CAB file entry %d: %v", index, err)
		}
		normalized, err := sanitizeEntryPath(rawPath)
		if err != nil {
			return nil, corrupt(nameOffset, "CAB file entry %d: %v", index, err)
		}

		start := uint64(folderOffset)
		end := start + uint64(cbFile)
		if start > folder.UncompressedSize {
			return nil, corrupt(position, "CAB entry %s starts at %d but folder %d holds %d bytes",
				rawPath, start, folderIndex, folder.UncompressedSize)
		}
		var available uint64
		switch {
		case end <= folder.UncompressedSize:
			available = uint64(cbFile)
		case header.HasNext():
			available = folder.UncompressedSize - start
		default:
			return nil, corrupt(position, "CAB entry %s spans [%d, +%d) but folder %d holds only %d bytes",
				rawPath, start, cbFile, folderIndex, folder.UncompressedSize)
		}

		entries = append(entries, Entry{
			Index:        index,
			Name:         leafName(normalized),
			Path:         normalized,
			RawPath:      rawPath,
			Size:         uint64(cbFile),
			Available:    available,
			Folder:       int(folderIndex),
			FolderOffset: folderOffset,
			Date:         date,
			Time:         timeWord,
			Modified:     dosDatetime(date, timeWord),
			Attributes:   attributes,
			UTF8Name:     utf8Name,
		})
		position = nameOffset + uint64(nul) + 1
	}
	return entries, nil
}

func decodeName(raw []byte, utf8Name bool) (string, error) {
	if utf8Name {
		if !utf8.Valid(raw) {
			return "", errors.New("CAB file name is flagged UTF-8 but is not valid UTF-8")
		}
		return string(raw), nil
	}
	return decodeANSI(raw), nil
}

// ANSI names have no recorded code page. Accept UTF-8 when it is valid (many
// producers write it without setting the attribute), otherwise fall back to
// code page 437, the DOS default.
func decodeANSI(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	var out strings.Builder
	out.Grow(len(raw))
	for _, value := range raw {
		out.WriteRune(cp437(value))
	}
	return out.String()
}

const cp437High = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "

var cp437Runes = []rune(cp437High)

func cp437(value byte) rune {
	if value < 0x80 {
		return rune(value)
	}
	index := int(value) - 0x80
	if index < len(cp437Runes) {
		return cp437Runes[index]
	}
	return '�'
}

func dosDatetime(date, timeWord uint16) *int64 {
	year := 1980 + int((date>>9)&0x7F)
	month := int((date >> 5) & 0x0F)
	day := int(date & 0x1F)
	hour := int((timeWord >> 11) & 0x1F)
	minute := int((timeWord >> 5) & 0x3F)
	second := int(timeWord&0x1F) * 2
	if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
		return nil
	}
	days := daysFromCivil(year, month, day)
	value := days*86400 + int64(hour)*3600 + int64(minute)*60 + int64(second)
	return &value
}

// daysFromCivil is Howard Hinnant's days_from_civil.
func daysFromCivil(year, month, day int) int64 {
	if month <= 2 {
		year--
	}
	era := year / 400
	if year < 0 {
		era = (year - 399) / 400
	}
	yearOfEra := year - era*400
	monthPrime := (month + 9) % 12
	dayOfYear := (153*monthPrime+2)/5 + day - 1
	dayOfEra := yearOfEra*365 + yearOfEra/4 - yearOfEra/100 + dayOfYear
	return int64(era)*146097 + int64(dayOfEra) - 719468
}

// dataChecksum is the CFDATA checksum: XOR of the stored bytes as
// little-endian 32-bit words, seeded with cbData | (cbUncomp << 16). The final
// one to three bytes are shifted high byte first, as libmspack consumes them.
func dataChecksum(stored []byte, cbData, cbUncomp uint16) uint32 {
	sum := uint32(cbData) | uint32(cbUncomp)<<16
	full := len(stored) / 4 * 4
	for offset := 0; offset < full; offset += 4 {
		sum ^= binary.LittleEndian.Uint32(stored[offset : offset+4])
	}
	tail := stored[full:]
	for index, value := range tail {
		sum ^= uint32(value) << (8 * uint(len(tail)-1-index))
	}
	return sum
}

// DataChecksum is the exported form of the CFDATA checksum.
func DataChecksum(stored []byte, cbData, cbUncomp uint16) uint32 {
	return dataChecksum(stored, cbData, cbUncomp)
}

// sanitizeEntryPath normalizes a cabinet path and rejects absolute paths and
// traversal outside the archive root.
func sanitizeEntryPath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("archive entry has an empty name")
	}
	if strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("archive entry name contains a NUL byte")
	}
	normalized := strings.ReplaceAll(raw, "\\", "/")
	absolute := strings.HasPrefix(normalized, "/")
	if !absolute && len(normalized) >= 2 && isASCIIAlpha(normalized[0]) && normalized[1] == ':' {
		absolute = true
	}
	if absolute {
		return "", fmt.Errorf("archive entry has an absolute path: %q", raw)
	}
	components := make([]string, 0)
	for _, component := range strings.Split(normalized, "/") {
		switch component {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("archive entry escapes the archive root: %q", raw)
		default:
			components = append(components, component)
		}
	}
	if len(components) == 0 {
		return "", fmt.Errorf("archive entry has no path components: %q", raw)
	}
	return strings.Join(components, "/"), nil
}

func isASCIIAlpha(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}

func leafName(path string) string {
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		return path[index+1:]
	}
	return path
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
