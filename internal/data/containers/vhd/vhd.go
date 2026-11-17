// Package vhd exposes Microsoft Virtual Hard Disk images (fixed, dynamic and
// differencing) as a ByteSource. It is a pure-Go port of forensic-core's
// data/containers/vhd.rs.
package vhd

import (
	"fmt"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// FooterCookie is the footer signature at the start of the 512-byte footer.
	FooterCookie = "conectix"
	// DynamicCookie is the dynamic-disk header signature.
	DynamicCookie = "cxsparse"
	// FooterBytes is the footer size.
	FooterBytes = 512
	// DynamicHeaderBytes is the dynamic header size.
	DynamicHeaderBytes = 1024
	// Version10 is the only file format version the format defines.
	Version10 uint32 = 0x00010000
	// MinBlockBytes and MaxBlockBytes bound a dynamic block.
	MinBlockBytes uint64 = 512
	MaxBlockBytes uint64 = 256 * 1024 * 1024
	// Unallocated marks a BAT entry that was never allocated.
	Unallocated uint32 = 0xFFFFFFFF
	// tablePageEntries is the number of 4-byte entries cached at once.
	tablePageEntries = 128
)

// Kind is the disk type from the footer.
type Kind uint8

const (
	KindFixed Kind = iota
	KindDynamic
	KindDifferencing
)

// Label returns "fixed", "dynamic" or "differencing".
func (k Kind) Label() string {
	switch k {
	case KindFixed:
		return "fixed"
	case KindDynamic:
		return "dynamic"
	default:
		return "differencing"
	}
}

// Info is the VHD's identity and geometry.
type Info struct {
	Kind            Kind
	Version         uint32
	VirtualSize     uint64
	OriginalSize    uint64
	BlockSize       uint64
	TableEntries    uint64
	TableOffset     uint64
	FooterOffset    uint64
	ChecksumOK      bool
	UniqueID        [16]byte
	Timestamp       uint32
	ParentUniqueID  *[16]byte
	ParentTimestamp *uint32
	Creator         string
	SavedState      bool
}

// UniqueIDText returns the canonical GUID text.
func (i Info) UniqueIDText() string { return guidText(i.UniqueID) }

type blockStateKind uint8

const (
	stateZero blockStateKind = iota
	stateParent
	stateData
)

type blockState struct {
	kind      blockStateKind
	base      uint64
	bitmap    uint64
	hasBitmap bool
}

type tablePage struct {
	first   uint64
	entries []uint32
}

// Source is a read-only VHD view.
type Source struct {
	id          source.ID
	parent      source.ByteSource
	backing     *Source
	length      uint64
	blockSize   uint64
	bitmapBytes uint64
	tableOffset uint64
	entries     uint64
	mu          sync.Mutex
	cache       *tablePage
	counters    source.Counters
	info        Info
}

// MatchesFooter reports whether footer starts with the VHD cookie.
func MatchesFooter(footer []byte) bool {
	return len(footer) >= len(FooterCookie) && string(footer[:len(FooterCookie)]) == FooterCookie
}

// MatchesHeader is the dynamic-disk head check.
func MatchesHeader(head []byte) bool { return MatchesFooter(head) }

// Open wraps parent. A differencing disk is refused; use OpenWithParent.
func Open(id source.ID, parent source.ByteSource) (*Source, error) {
	return openInner(id, parent, nil)
}

// OpenWithParent opens a differencing child over an already-opened backing.
func OpenWithParent(id source.ID, child source.ByteSource, backing *Source) (*Source, error) {
	return openInner(id, child, backing)
}

func openInner(id source.ID, parent source.ByteSource, backing *Source) (*Source, error) {
	fileLen := parent.Len()
	if fileLen < FooterBytes {
		return nil, corrupt(0, fmt.Sprintf("a VHD is at least %d bytes, not %d", FooterBytes, fileLen))
	}
	tail, err := source.ReadVecAt(parent, fileLen-FooterBytes, FooterBytes)
	if err != nil {
		return nil, err
	}
	var footer []byte
	var footerOffset uint64
	if MatchesFooter(tail) {
		footer, footerOffset = tail, fileLen-FooterBytes
	} else {
		head, err := source.ReadVecAt(parent, 0, FooterBytes)
		if err != nil {
			return nil, err
		}
		if !MatchesFooter(head) {
			return nil, corrupt(fileLen-FooterBytes,
				"no `conectix` footer at the end of the file and no footer copy at the start")
		}
		footer, footerOffset = head, 0
	}
	info, err := parseFooter(footer, footerOffset)
	if err != nil {
		return nil, err
	}
	if info.Kind == KindDifferencing && backing == nil {
		return nil, unsupported("differencing disk: it stores only the delta from a parent image; supply the parent to read the whole disk")
	}
	if info.Kind != KindDifferencing && backing != nil {
		return nil, unsupported(fmt.Sprintf("parent supplied for a %s disk that does not reference one", info.Kind.Label()))
	}

	s := &Source{
		id:        id,
		parent:    parent,
		backing:   backing,
		length:    info.VirtualSize,
		blockSize: maxU64(info.VirtualSize, 1),
		counters:  source.Counters{},
		info:      info,
	}
	switch info.Kind {
	case KindFixed:
		if fileLen < info.VirtualSize+FooterBytes {
			return nil, corrupt(fileLen,
				fmt.Sprintf("a fixed VHD of %d bytes needs at least %d bytes, not %d",
					info.VirtualSize, info.VirtualSize+FooterBytes, fileLen))
		}
	case KindDynamic, KindDifferencing:
		header, headerOffset, err := s.readDynamicHeader(footer)
		if err != nil {
			return nil, err
		}
		tableOffset := be64(header, 16)
		maxEntries := uint64(be32(header, 28))
		blockSize := uint64(be32(header, 32))
		if blockSize < MinBlockBytes || blockSize > MaxBlockBytes || blockSize&(blockSize-1) != 0 {
			return nil, corrupt(headerOffset+32,
				fmt.Sprintf("block size %d is not a power of two in 512 B..=256 MiB", blockSize))
		}
		needed := (info.VirtualSize + blockSize - 1) / blockSize
		if maxEntries < needed {
			return nil, corrupt(headerOffset+28,
				fmt.Sprintf("the BAT holds %d entries but %d blocks of %d bytes cover the %d byte disk",
					maxEntries, needed, blockSize, info.VirtualSize))
		}
		tableEnd := tableOffset + maxEntries*4
		if tableEnd < tableOffset || tableEnd > parent.Len() {
			return nil, corrupt(tableOffset,
				fmt.Sprintf("the BAT at %d (%d entries) ends beyond the %d byte file",
					tableOffset, maxEntries, parent.Len()))
		}
		s.blockSize = blockSize
		s.tableOffset = tableOffset
		s.entries = maxEntries
		s.info.BlockSize = blockSize
		s.info.TableEntries = maxEntries
		s.info.TableOffset = tableOffset
		sectors := blockSize / 512
		s.bitmapBytes = ((sectors+7)/8 + 511) / 512 * 512
		if info.Kind == KindDifferencing {
			var parentUnique [16]byte
			copy(parentUnique[:], header[40:56])
			parentTimestamp := be32(header, 56)
			s.info.ParentUniqueID = &parentUnique
			s.info.ParentTimestamp = &parentTimestamp
			if err := s.validateLinkage(parentUnique, parentTimestamp); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

func (s *Source) validateLinkage(parentUnique [16]byte, parentTimestamp uint32) error {
	backing := s.backing
	if parentUnique != backing.info.UniqueID {
		return unsupported(fmt.Sprintf("differencing parent unique id `%s` does not match the parent footer's `%s`",
			guidText(parentUnique), backing.info.UniqueIDText()))
	}
	if parentTimestamp != 0 && parentTimestamp != backing.info.Timestamp {
		return unsupported(fmt.Sprintf("differencing parent timestamp %d does not match the parent footer's %d",
			parentTimestamp, backing.info.Timestamp))
	}
	if s.info.VirtualSize != backing.Len() {
		return unsupported(fmt.Sprintf("differencing child virtual size %d does not match the parent's %d",
			s.info.VirtualSize, backing.Len()))
	}
	return nil
}

func (s *Source) readDynamicHeader(footer []byte) ([]byte, uint64, error) {
	dataOffset := be64(footer, 16)
	if dataOffset == ^uint64(0) {
		return nil, 0, corrupt(s.info.FooterOffset+16,
			"a dynamic VHD's footer must name the `cxsparse` header offset")
	}
	header, err := source.ReadVecAt(s.parent, dataOffset, DynamicHeaderBytes)
	if err != nil {
		return nil, 0, err
	}
	if string(header[:len(DynamicCookie)]) != DynamicCookie {
		return nil, 0, corrupt(dataOffset, "the dynamic header does not start with `cxsparse`")
	}
	version := be32(header, 24)
	if version != Version10 {
		return nil, 0, unsupported(fmt.Sprintf("dynamic header version %#010x", version))
	}
	return header, dataOffset, nil
}

func (s *Source) blockState(block uint64) (blockState, error) {
	if s.info.Kind == KindFixed {
		if block == 0 {
			return blockState{kind: stateData, base: 0}, nil
		}
		return blockState{kind: stateZero}, nil
	}
	if block >= s.entries {
		return blockState{}, source.NewOutOfRange(block*s.blockSize, s.blockSize, s.length)
	}
	entry, err := s.tableEntry(block)
	if err != nil {
		return blockState{}, err
	}
	if entry == Unallocated {
		if s.info.Kind == KindDifferencing {
			return blockState{kind: stateParent}, nil
		}
		return blockState{kind: stateZero}, nil
	}
	bitmap := uint64(entry) * 512
	base := bitmap + s.bitmapBytes
	end := base + s.blockSize
	if end < base || end > s.parent.Len() {
		return blockState{}, corrupt(s.tableOffset+block*4,
			fmt.Sprintf("block %d maps to bytes %d..%d beyond the %d byte file",
				block, base, end, s.parent.Len()))
	}
	return blockState{
		kind:      stateData,
		base:      base,
		bitmap:    bitmap,
		hasBitmap: s.info.Kind == KindDifferencing,
	}, nil
}

func (s *Source) tableEntry(block uint64) (uint32, error) {
	s.mu.Lock()
	if page := s.cache; page != nil && block >= page.first {
		if index := block - page.first; index < uint64(len(page.entries)) {
			entry := page.entries[index]
			s.mu.Unlock()
			return entry, nil
		}
	}
	s.mu.Unlock()

	first := block - block%tablePageEntries
	count := uint64(tablePageEntries)
	if remaining := s.entries - first; remaining < count {
		count = remaining
	}
	bytes, err := source.ReadVecAt(s.parent, s.tableOffset+first*4, count*4)
	if err != nil {
		return 0, err
	}
	entries := make([]uint32, count)
	for i := range entries {
		entries[i] = be32(bytes, int(i)*4)
	}
	entry := entries[block-first]
	s.mu.Lock()
	s.cache = &tablePage{first: first, entries: entries}
	s.mu.Unlock()
	return entry, nil
}

// Info returns the disk's identity and geometry.
func (s *Source) Info() Info { return s.info }

// BlockSize returns guest bytes per block.
func (s *Source) BlockSize() uint64 { return s.blockSize }

// Parent returns the container source the disk was unwrapped from.
func (s *Source) Parent() source.ByteSource { return s.parent }

// Backing returns the parent disk of a differencing image.
func (s *Source) Backing() *Source { return s.backing }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.length }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *Source) SectorSize() uint32      { return 512 }
func (s *Source) IsEmpty() bool           { return s.length == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf, false)
}

func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf, true)
}

func (s *Source) checkRange(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
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
	var bitmap []byte
	var bitmapBase uint64
	haveBitmap := false
	for done < want {
		position := offset + uint64(done)
		block := position / s.blockSize
		within := position % s.blockSize
		chunk := int(minU64(s.blockSize-within, uint64(want-done)))
		state, err := s.blockState(block)
		if err != nil {
			return 0, err
		}
		switch state.kind {
		case stateZero:
			clear(buf[done : done+chunk])
			done += chunk
		case stateParent:
			if err := readRun(s.backing, position, buf[done:done+chunk], lossy); err != nil {
				return 0, err
			}
			done += chunk
		case stateData:
			if !state.hasBitmap {
				if err := readRun(s.parent, state.base+within, buf[done:done+chunk], lossy); err != nil {
					return 0, err
				}
				done += chunk
				continue
			}
			if !haveBitmap || bitmapBase != state.bitmap {
				bitmap, err = source.ReadVecAt(s.parent, state.bitmap, s.bitmapBytes)
				if err != nil {
					return 0, err
				}
				bitmapBase, haveBitmap = state.bitmap, true
			}
			consumed := 0
			for consumed < chunk {
				at := position + uint64(consumed)
				sector := (at % s.blockSize) / 512
				sectorWithin := at % 512
				run := int(minU64(512-sectorWithin, uint64(chunk-consumed)))
				present := bitmap[sector/8]&(0x80>>(sector%8)) != 0
				target := buf[done+consumed : done+consumed+run]
				if present {
					if err := readRun(s.parent, state.base+(at%s.blockSize), target, lossy); err != nil {
						return 0, err
					}
				} else {
					if err := readRun(s.backing, at, target, lossy); err != nil {
						return 0, err
					}
				}
				consumed += run
			}
			done += chunk
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
		blockStart := block * s.blockSize
		within := cursor - blockStart
		stop := minU64(end, blockStart+s.blockSize)
		chunk := stop - cursor
		state, err := s.blockState(block)
		if err != nil {
			return out, err
		}
		switch state.kind {
		case stateZero:
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: 0, Len: chunk, Kind: source.RangeZero,
			})
		case stateParent:
			out = append(out, source.ParentRange{
				Parent: s.backing.SourceID(), ParentOffset: cursor, Len: chunk, Kind: source.RangeData,
			})
		case stateData:
			if !state.hasBitmap {
				out = append(out, source.ParentRange{
					Parent: s.parent.SourceID(), ParentOffset: state.base + within,
					Len: chunk, Kind: source.RangeData,
				})
			} else {
				bitmap, err := source.ReadVecAt(s.parent, state.bitmap, s.bitmapBytes)
				if err != nil {
					return out, err
				}
				at := cursor
				for at < stop {
					sector := (at - blockStart) / 512
					sectorStop := minU64(blockStart+(sector+1)*512, stop)
					present := bitmap[sector/8]&(0x80>>(sector%8)) != 0
					rangeLen := sectorStop - at
					if present {
						out = append(out, source.ParentRange{
							Parent: s.parent.SourceID(), ParentOffset: state.base + (at - blockStart),
							Len: rangeLen, Kind: source.RangeData,
						})
					} else {
						out = append(out, source.ParentRange{
							Parent: s.backing.SourceID(), ParentOffset: at,
							Len: rangeLen, Kind: source.RangeData,
						})
					}
					at = sectorStop
				}
			}
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
		if extent.Kind != source.RangeData {
			out = append(out, source.ImageRange{
				ImageID: s.parent.ImageID(), ImageOffset: 0, Len: extent.Len, Kind: extent.Kind,
			})
			continue
		}
		if s.backing != nil && extent.Parent == s.backing.SourceID() {
			mapped, err := s.backing.MapToImage(extent.ParentOffset, extent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		mapped, err := s.parent.MapToImage(extent.ParentOffset, extent.Len)
		if err != nil {
			return nil, err
		}
		out = append(out, mapped...)
	}
	return out, nil
}

var _ source.ByteSource = (*Source)(nil)

func parseFooter(bytes []byte, offset uint64) (Info, error) {
	if len(bytes) < FooterBytes {
		return Info{}, corrupt(offset, "the footer is truncated")
	}
	version := be32(bytes, 12)
	if version != Version10 {
		return Info{}, unsupported(fmt.Sprintf("footer version %#010x", version))
	}
	originalSize := be64(bytes, 40)
	virtualSize := be64(bytes, 48)
	if virtualSize == 0 {
		return Info{}, corrupt(offset+48, "the footer declares an empty disk")
	}
	diskType := be32(bytes, 60)
	var kind Kind
	switch diskType {
	case 2:
		kind = KindFixed
	case 3:
		kind = KindDynamic
	case 4:
		kind = KindDifferencing
	default:
		return Info{}, unsupported(fmt.Sprintf("disk type %d", diskType))
	}
	declared := be32(bytes, 64)
	var uniqueID [16]byte
	copy(uniqueID[:], bytes[68:84])
	info := Info{
		Kind:         kind,
		Version:      version,
		VirtualSize:  virtualSize,
		OriginalSize: originalSize,
		FooterOffset: offset,
		ChecksumOK:   declared == footerChecksum(bytes, 64),
		UniqueID:     uniqueID,
		Timestamp:    be32(bytes, 24),
		Creator:      strings.TrimRight(strings.ToValidUTF8(string(bytes[28:32]), "�"), " \t\r\n\x00"),
		SavedState:   bytes[84] != 0,
	}
	return info, nil
}

func footerChecksum(bytes []byte, checksumOffset int) uint32 {
	var sum uint32
	for index, b := range bytes {
		if index >= checksumOffset && index < checksumOffset+4 {
			continue
		}
		sum += uint32(b)
	}
	return ^sum
}

func readRun(src source.ByteSource, offset uint64, target []byte, lossy bool) error {
	if src == nil {
		return unsupported("a differencing source always has a backing")
	}
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
		return err
	}
	if n < len(target) {
		return source.NewUnexpectedEOF(offset)
	}
	return nil
}

func guidText(b [16]byte) string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func be32(bytes []byte, at int) uint32 {
	return uint32(bytes[at])<<24 | uint32(bytes[at+1])<<16 | uint32(bytes[at+2])<<8 | uint32(bytes[at+3])
}

func be64(bytes []byte, at int) uint64 {
	return uint64(be32(bytes, at))<<32 | uint64(be32(bytes, at+4))
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
