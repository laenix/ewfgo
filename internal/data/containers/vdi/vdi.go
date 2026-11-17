// Package vdi exposes Oracle VirtualBox disk images as a ByteSource. It is a
// pure-Go port of forensic-core's data/containers/vdi.rs.
package vdi

import (
	"fmt"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// TextBytes is the product banner preamble.
	TextBytes = 0x40
	// SignatureOffset is the file offset of the little-endian signature.
	SignatureOffset = 0x40
	// Signature is the VDI magic.
	Signature uint32 = 0xBEDA107F
	// CommentOffset and CommentBytes locate the free-form comment.
	CommentOffset = 0x54
	CommentBytes  = 256
	// BaseHeaderBytes is the minimum header length this reader uses.
	BaseHeaderBytes = 0x190
	// HeaderReadBytes is how much of the header is read at open.
	HeaderReadBytes = 0x200

	// ImageTypeDynamic and ImageTypeStatic are the defined disk types.
	ImageTypeDynamic uint32 = 1
	ImageTypeStatic  uint32 = 2

	// Unallocated and Zeroed block-map entries.
	Unallocated uint32 = 0xFFFFFFFF
	Zeroed      uint32 = 0xFFFFFFFE

	// SectorBytes is the only sector size VDI exposes.
	SectorBytes uint64 = 512
	// MinBlockBytes and MaxBlockBytes bound the block size.
	MinBlockBytes uint64 = 512
	MaxBlockBytes uint64 = 256 * 1024 * 1024

	tablePageEntries uint64 = 128
)

// Kind is dynamic or static.
type Kind uint8

const (
	KindDynamic Kind = iota
	KindStatic
)

// Label returns "dynamic" or "static".
func (k Kind) Label() string {
	if k == KindStatic {
		return "static"
	}
	return "dynamic"
}

// Info is the VDI's identity and geometry.
type Info struct {
	Kind           Kind
	VersionMajor   uint16
	VersionMinor   uint16
	HeaderBytes    uint32
	Flags          uint32
	Comment        string
	VirtualSize    uint64
	BlockSize      uint64
	Blocks         uint64
	Allocated      uint64
	BlockMapOffset uint64
	DataOffset     uint64
	Cylinders      uint32
	Heads          uint32
	Sectors        uint32
}

type tablePage struct {
	first   uint64
	entries []uint32
}

// Source is a read-only VDI virtual disk.
type Source struct {
	id         source.ID
	parent     source.ByteSource
	length     uint64
	blockSize  uint64
	mapOffset  uint64
	hasMap     bool
	dataOffset uint64
	blocks     uint64
	mu         sync.Mutex
	cache      *tablePage
	counters   source.Counters
	info       Info
}

// MatchesSignature reports whether head carries the VDI signature at 0x40.
func MatchesSignature(head []byte) bool {
	return len(head) >= SignatureOffset+4 && le32(head, SignatureOffset) == Signature
}

// Open parses the VDI header around parent.
func Open(id source.ID, parent source.ByteSource) (*Source, error) {
	fileLen := parent.Len()
	if fileLen < BaseHeaderBytes {
		return nil, corrupt(0, fmt.Sprintf("a VDI header is at least %d bytes, not %d", BaseHeaderBytes, fileLen))
	}
	readLen := fileLen
	if readLen > HeaderReadBytes {
		readLen = HeaderReadBytes
	}
	header, err := source.ReadVecAt(parent, 0, readLen)
	if err != nil {
		return nil, err
	}
	if !MatchesSignature(header) {
		return nil, corrupt(SignatureOffset, "no 0xbeda107f VDI signature at offset 0x40")
	}
	versionMajor := le16(header, 0x44)
	versionMinor := le16(header, 0x46)
	if versionMajor > 1 {
		return nil, unsupported(fmt.Sprintf("header version %d.%d", versionMajor, versionMinor))
	}
	headerBytes := le32(header, 0x48)
	if headerBytes < 0x180 || headerBytes > 0x10000 {
		return nil, corrupt(0x48, fmt.Sprintf("header size %d is not in 0x180..=0x10000", headerBytes))
	}
	imageType := le32(header, 0x4C)
	var kind Kind
	switch imageType {
	case ImageTypeDynamic:
		kind = KindDynamic
	case ImageTypeStatic:
		kind = KindStatic
	default:
		return nil, unsupported(fmt.Sprintf("image type %d (only 1 dynamic and 2 static are defined)", imageType))
	}
	flags := le32(header, 0x50)
	comment := readComment(header)
	mapOffset := uint64(le32(header, 0x154))
	dataOffset := uint64(le32(header, 0x158))
	cylinders := le32(header, 0x15C)
	heads := le32(header, 0x160)
	sectors := le32(header, 0x164)
	sectorSize := uint64(le32(header, 0x168))
	if sectorSize != SectorBytes {
		return nil, unsupported(fmt.Sprintf("sector size %d (only 512-byte sectors are read)", sectorSize))
	}
	virtualSize := le64(header, 0x170)
	if virtualSize == 0 {
		return nil, corrupt(0x170, "the header declares an empty disk")
	}
	blockSize := uint64(le32(header, 0x178))
	if blockSize < MinBlockBytes || blockSize > MaxBlockBytes || blockSize&(blockSize-1) != 0 {
		return nil, corrupt(0x178, fmt.Sprintf("block size %d is not a power of two in 512 B..=256 MiB", blockSize))
	}
	blocks := uint64(le32(header, 0x180))
	allocated := uint64(le32(header, 0x184))
	needed := (virtualSize + blockSize - 1) / blockSize
	if blocks < needed {
		return nil, corrupt(0x180, fmt.Sprintf("the map holds %d entries but %d blocks of %d bytes cover the %d byte disk",
			blocks, needed, blockSize, virtualSize))
	}
	if dataOffset == 0 {
		return nil, unsupported("an image that names no data offset")
	}
	if dataOffset > fileLen {
		return nil, corrupt(0x158, fmt.Sprintf("the data area starts at %d, past the %d byte file", dataOffset, fileLen))
	}

	hasMap := mapOffset != 0
	if kind == KindDynamic && !hasMap {
		return nil, corrupt(0x154, "a dynamic VDI must name its block map offset")
	}
	if hasMap {
		tableEnd := mapOffset + blocks*4
		if blocks != 0 && (tableEnd < mapOffset || blocks > (^uint64(0))/4) {
			return nil, corrupt(0x154, "block-map size overflows")
		}
		if tableEnd < mapOffset || tableEnd > fileLen {
			return nil, corrupt(0x154, fmt.Sprintf("the block map at %d (%d entries) ends beyond the %d byte file",
				mapOffset, blocks, fileLen))
		}
	}

	info := Info{
		Kind: kind, VersionMajor: versionMajor, VersionMinor: versionMinor,
		HeaderBytes: headerBytes, Flags: flags, Comment: comment,
		VirtualSize: virtualSize, BlockSize: blockSize, Blocks: blocks,
		Allocated: allocated, BlockMapOffset: mapOffset, DataOffset: dataOffset,
		Cylinders: cylinders, Heads: heads, Sectors: sectors,
	}
	return &Source{
		id: id, parent: parent, length: virtualSize, blockSize: blockSize,
		mapOffset: mapOffset, hasMap: hasMap, dataOffset: dataOffset,
		blocks: blocks, info: info,
	}, nil
}

// Info returns the disk geometry.
func (s *Source) Info() Info { return s.info }

// BlockSize returns guest bytes per block.
func (s *Source) BlockSize() uint64 { return s.blockSize }

// Parent returns the container source.
func (s *Source) Parent() source.ByteSource { return s.parent }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.length }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *Source) SectorSize() uint32      { return uint32(SectorBytes) }
func (s *Source) IsEmpty() bool           { return s.length == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) checkRange(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

func (s *Source) tableEntry(block uint64) (uint32, error) {
	s.mu.Lock()
	if page := s.cache; page != nil && block >= page.first {
		if at := block - page.first; at < uint64(len(page.entries)) {
			entry := page.entries[at]
			s.mu.Unlock()
			return entry, nil
		}
	}
	s.mu.Unlock()

	first := block - block%tablePageEntries
	count := tablePageEntries
	if remaining := s.blocks - first; remaining < count {
		count = remaining
	}
	bytes, err := source.ReadVecAt(s.parent, s.mapOffset+first*4, count*4)
	if err != nil {
		return 0, err
	}
	entries := make([]uint32, count)
	for i := range entries {
		entries[i] = le32(bytes, i*4)
	}
	s.mu.Lock()
	s.cache = &tablePage{first: first, entries: entries}
	s.mu.Unlock()
	return entries[block-first], nil
}

func (s *Source) blockOffset(block uint64) (uint64, bool, error) {
	if block >= s.blocks {
		return 0, false, source.NewOutOfRange(block*s.blockSize, s.blockSize, s.length)
	}
	var entry uint32
	if s.hasMap {
		var err error
		entry, err = s.tableEntry(block)
		if err != nil {
			return 0, false, err
		}
	} else {
		if block > 0xFFFFFFFF {
			return 0, false, corrupt(0x154, fmt.Sprintf("block %d has no map entry", block))
		}
		entry = uint32(block)
	}
	if s.info.Kind == KindDynamic && (entry == Unallocated || entry == Zeroed) {
		return 0, false, nil
	}
	base := s.dataOffset + uint64(entry)*s.blockSize
	end := base + s.blockSize
	if end < base || end > s.parent.Len() {
		return 0, false, corrupt(s.mapOffset+block*4,
			fmt.Sprintf("block %d maps to bytes %d..%d beyond the %d byte file", block, base, end, s.parent.Len()))
	}
	return base, true, nil
}

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf, false)
}

func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf, true)
}

func (s *Source) readInner(offset uint64, buf []byte, lossy bool) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	done := 0
	for done < want {
		position := offset + uint64(done)
		block := position / s.blockSize
		within := position % s.blockSize
		chunk := int(minU64(s.blockSize-within, uint64(want-done)))
		base, present, err := s.blockOffset(block)
		if err != nil {
			return 0, err
		}
		if !present {
			clear(buf[done : done+chunk])
			done += chunk
			continue
		}
		target := buf[done : done+chunk]
		var (
			n       int
			readErr error
		)
		if lossy {
			n, readErr = s.parent.ReadAtLossy(base+within, target)
		} else {
			n, readErr = s.parent.ReadAt(base+within, target)
		}
		if readErr != nil {
			return 0, readErr
		}
		if n == 0 {
			return 0, source.NewUnexpectedEOF(base + within)
		}
		done += n
		if n < chunk {
			break
		}
	}
	s.counters.AddRead(done)
	return done, nil
}

func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.checkRange(offset, length); err != nil {
		return out, err
	}
	cursor := offset
	end := offset + length
	for cursor < end {
		block := cursor / s.blockSize
		within := cursor % s.blockSize
		stop := minU64(end, (block+1)*s.blockSize)
		chunk := stop - cursor
		base, present, err := s.blockOffset(block)
		if err != nil {
			return out, err
		}
		if present {
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: base + within, Len: chunk, Kind: source.RangeData,
			})
		} else {
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: 0, Len: chunk, Kind: source.RangeZero,
			})
		}
		cursor = stop
	}
	return out, nil
}

func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	extents, err := s.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, extent := range extents {
		if extent.Kind == source.RangeData {
			mapped, err := s.parent.MapToImage(extent.ParentOffset, extent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		out = append(out, source.ImageRange{
			ImageID: s.parent.ImageID(), ImageOffset: 0, Len: extent.Len, Kind: extent.Kind,
		})
	}
	return out, nil
}

var _ source.ByteSource = (*Source)(nil)

func readComment(header []byte) string {
	end := CommentOffset + CommentBytes
	if end > len(header) {
		end = len(header)
	}
	if CommentOffset >= end {
		return ""
	}
	bytes := header[CommentOffset:end]
	stop := len(bytes)
	for i, b := range bytes {
		if b == 0 {
			stop = i
			break
		}
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(bytes[:stop]), "�"))
}

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func le16(bytes []byte, at int) uint16 {
	return uint16(bytes[at]) | uint16(bytes[at+1])<<8
}

func le32(bytes []byte, at int) uint32 {
	return uint32(bytes[at]) | uint32(bytes[at+1])<<8 | uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
}

func le64(bytes []byte, at int) uint64 {
	return uint64(le32(bytes, at)) | uint64(le32(bytes, at+4))<<32
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
