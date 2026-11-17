// Package vhdx exposes VHDX virtual disks as a ByteSource. It is a pure-Go
// port of forensic-core's data/containers/vhdx.rs.
package vhdx

import (
	"fmt"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Signature is the file identifier at offset 0.
	Signature = "vhdxfile"

	header1Offset      = 64 * 1024
	header2Offset      = 128 * 1024
	region1Offset      = 192 * 1024
	region2Offset      = 256 * 1024
	headerSize         = 4096
	regionSize         = 64 * 1024
	metadataHeaderSize = 32
	metadataEntrySize  = 32
	metadataMaxEntries = 2048
	batEntrySize       = 8
	batPageEntries     = 1024

	headerSignature   = "head"
	regionSignature   = "regi"
	metadataSignature = "metadata"

	batStateMask      = 0x7
	batFileOffsetMask = 0xFFFFFFFFFFFF0000

	blockNotPresent       = 0
	blockUndefined        = 1
	blockZero             = 2
	blockUnmapped         = 3
	blockFullyPresent     = 6
	blockPartiallyPresent = 7

	minBlockSize = 1 << 20
	maxBlockSize = 256 << 20

	batRegionGUID        = "\x66\x77\xc2\x2d\x23\xf6\x00\x42\x9d\x64\x11\x5e\x9b\xfd\x4a\x08"
	metadataRegionGUID   = "\x06\xa2\x7c\x8b\x90\x47\x9a\x4b\xb8\xfe\x57\x5f\x05\x0f\x88\x6e"
	fileParametersID     = "\x37\x67\xa1\xca\x36\xfa\x43\x4d\xb3\xb6\x33\xf0\xaa\x44\xe7\x6b"
	virtualDiskSizeID    = "\x24\x42\xa5\x2f\x1b\xcd\x76\x48\xb2\x11\x5d\xbe\xd8\x3b\xf4\xb8"
	virtualDiskIDID      = "\xab\x12\xca\xbe\xe6\xb2\x23\x45\x93\xef\xc3\x09\xe0\x00\xc7\x46"
	logicalSectorSizeID  = "\x1d\xbf\x41\x81\x6f\xa9\x09\x47\xba\x47\xf2\x33\xa8\xfa\xab\x5f"
	physicalSectorSizeID = "\xc7\x48\xa3\xcd\x5d\x44\x71\x44\x9c\xc9\xe9\x88\x52\x51\xc5\x56"
	parentLocatorID      = "\x2d\x5f\xd3\xa8\x0b\xb3\x4d\x45\xab\xf7\xd3\xd8\x48\x34\xab\x0c"
)

// Info is the virtual disk's identity and geometry.
type Info struct {
	BlockSize          uint32
	VirtualDiskSize    uint64
	LogicalSectorSize  uint32
	PhysicalSectorSize uint32
	VirtualDiskID      [16]byte
	DataWriteGUID      [16]byte
	ParentLinkage      *[16]byte
	ParentLocatorHints []string
	LogActive          bool
	HeaderSequence     uint64
}

// VirtualDiskIDString returns the usual 8-4-4-4-12 form.
func (i Info) VirtualDiskIDString() string { return formatGUID(i.VirtualDiskID) }

// ContainerInfo is the subset needed to decide whether a parent is required.
type ContainerInfo struct {
	HasParent          bool
	ParentLinkage      *[16]byte
	VirtualDiskSize    uint64
	LogicalSectorSize  uint32
	ParentLocatorHints []string
}

type blockStateKind uint8

const (
	bsZero blockStateKind = iota
	bsParent
	bsData
	bsPartial
)

type blockState struct {
	kind         blockStateKind
	fileOffset   uint64
	bitmapOffset uint64
	bitmapBytes  uint64
}

type batPage struct {
	first   uint64
	entries []uint64
}

// Source is a read-only VHDX virtual disk.
type Source struct {
	id         source.ID
	parent     source.ByteSource
	backing    *Source
	blockSize  uint64
	batOffset  uint64
	batEntries uint64
	batTotal   uint64
	chunkRatio uint64
	length     uint64
	sectorSize uint32
	info       Info
	mu         sync.Mutex
	batCache   *batPage
	counters   source.Counters
}

// MatchesSignature reports whether head starts with the VHDX file identifier.
func MatchesSignature(head []byte) bool {
	return len(head) >= len(Signature) && string(head[:len(Signature)]) == Signature
}

// ReadContainerInfo reads the metadata that says whether the disk needs a
// parent, without opening it.
func ReadContainerInfo(src source.ByteSource) (*ContainerInfo, error) {
	if err := checkSignature(src); err != nil {
		return nil, err
	}
	if _, err := readBestHeader(src); err != nil {
		return nil, err
	}
	regions, err := readRegionTable(src)
	if err != nil {
		return nil, err
	}
	metadataRegion, ok := findRegion(regions, metadataRegionGUID)
	if !ok {
		return nil, corrupt(0, "VHDX region table has no metadata region")
	}
	metadata, err := readMetadata(src, metadataRegion)
	if err != nil {
		return nil, err
	}
	return &ContainerInfo{
		HasParent:          metadata.hasParent,
		ParentLinkage:      metadata.parentLinkage,
		VirtualDiskSize:    metadata.virtualDiskSize,
		LogicalSectorSize:  metadata.logicalSectorSize,
		ParentLocatorHints: metadata.parentHints,
	}, nil
}

// Open opens a dynamic VHDX. A differencing disk is refused; use OpenWithParent.
func Open(id source.ID, parent source.ByteSource) (*Source, error) {
	return openInner(id, parent, nil)
}

// OpenWithParent opens a differencing VHDX over an already-opened backing.
func OpenWithParent(id source.ID, child source.ByteSource, backing *Source) (*Source, error) {
	return openInner(id, child, backing)
}

func openInner(id source.ID, parent source.ByteSource, backing *Source) (*Source, error) {
	if err := checkSignature(parent); err != nil {
		return nil, err
	}
	header, err := readBestHeader(parent)
	if err != nil {
		return nil, err
	}
	regions, err := readRegionTable(parent)
	if err != nil {
		return nil, err
	}
	metadataRegion, ok := findRegion(regions, metadataRegionGUID)
	if !ok {
		return nil, corrupt(0, "VHDX region table has no metadata region")
	}
	batRegion, ok := findRegion(regions, batRegionGUID)
	if !ok {
		return nil, unsupported("fixed disk without a BAT region")
	}
	metadata, err := readMetadata(parent, metadataRegion)
	if err != nil {
		return nil, err
	}
	if metadata.hasParent && backing == nil {
		return nil, unsupported("differencing disk with a parent locator: it stores only the delta from a parent image; supply the parent to read the whole disk")
	}
	if !metadata.hasParent && backing != nil {
		return nil, unsupported("parent supplied for a disk that does not reference one")
	}
	blockSize := uint64(metadata.blockSize)
	if metadata.virtualDiskSize == 0 {
		return nil, corrupt(metadataRegion.offset, "virtual disk size is zero")
	}
	if metadata.virtualDiskSize%uint64(metadata.logicalSectorSize) != 0 {
		return nil, corrupt(metadataRegion.offset, "virtual disk size is not a multiple of the logical sector size")
	}
	batEntries := (metadata.virtualDiskSize + blockSize - 1) / blockSize
	chunkRatio := (uint64(1) << 23) * uint64(metadata.logicalSectorSize) / blockSize
	if chunkRatio == 0 {
		return nil, corrupt(metadataRegion.offset, "block size is too large for the logical sector size")
	}
	chunks := (batEntries + chunkRatio - 1) / chunkRatio
	batTotal := chunks * (chunkRatio + 1)
	needed := batTotal * batEntrySize
	if batRegion.length < needed {
		return nil, corrupt(batRegion.offset,
			fmt.Sprintf("BAT region is %d bytes but %d blocks in %d chunk(s) need %d",
				batRegion.length, batEntries, chunks, needed))
	}
	info := Info{
		BlockSize:          metadata.blockSize,
		VirtualDiskSize:    metadata.virtualDiskSize,
		LogicalSectorSize:  metadata.logicalSectorSize,
		PhysicalSectorSize: metadata.physicalSectorSize,
		VirtualDiskID:      metadata.virtualDiskID,
		DataWriteGUID:      header.dataWriteGUID,
		ParentLinkage:      metadata.parentLinkage,
		ParentLocatorHints: metadata.parentHints,
		LogActive:          header.logGUID != [16]byte{},
		HeaderSequence:     header.sequence,
	}
	src := &Source{
		id:         id,
		parent:     parent,
		backing:    backing,
		blockSize:  blockSize,
		batOffset:  batRegion.offset,
		batEntries: batEntries,
		batTotal:   batTotal,
		chunkRatio: chunkRatio,
		length:     metadata.virtualDiskSize,
		sectorSize: metadata.logicalSectorSize,
		info:       info,
	}
	if backing != nil {
		if err := src.validateLinkage(); err != nil {
			return nil, err
		}
	}
	return src, nil
}

func checkSignature(src source.ByteSource) error {
	if src.Len() < uint64(len(Signature)) {
		return unsupported("file identifier")
	}
	signature, err := source.ReadVecAt(src, 0, uint64(len(Signature)))
	if err != nil {
		return err
	}
	if string(signature) != Signature {
		return unsupported("file identifier")
	}
	return nil
}

func (s *Source) validateLinkage() error {
	linkage := s.info.ParentLinkage
	if linkage == nil {
		return unsupported("differencing disk has no ParentLinkage entry")
	}
	expected := s.backing.info.DataWriteGUID
	if expected == [16]byte{} {
		expected = s.backing.info.VirtualDiskID
	}
	if *linkage != expected {
		return unsupported(fmt.Sprintf("differencing parent linkage GUID `%s` does not match the parent's `%s`",
			formatGUID(*linkage), formatGUID(expected)))
	}
	if s.length != s.backing.length {
		return unsupported(fmt.Sprintf("differencing child virtual size %d does not match the parent's %d",
			s.length, s.backing.length))
	}
	if s.sectorSize != s.backing.sectorSize {
		return unsupported(fmt.Sprintf("differencing child logical sector size %d does not match the parent's %d",
			s.sectorSize, s.backing.sectorSize))
	}
	return nil
}

// Info returns the virtual disk geometry and identity.
func (s *Source) Info() Info { return s.info }

// BlockSize returns the payload block size.
func (s *Source) BlockSize() uint64 { return s.blockSize }

// BlockCount returns the number of payload blocks.
func (s *Source) BlockCount() uint64 { return s.batEntries }

// Parent returns the container source.
func (s *Source) Parent() source.ByteSource { return s.parent }

// Backing returns the differencing parent.
func (s *Source) Backing() *Source { return s.backing }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.length }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *Source) SectorSize() uint32      { return s.sectorSize }
func (s *Source) IsEmpty() bool           { return s.length == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) checkRange(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

func (s *Source) payloadIndex(block uint64) uint64 {
	chunk := block / s.chunkRatio
	return chunk*(s.chunkRatio+1) + block%s.chunkRatio
}

func (s *Source) bitmapIndex(block uint64) uint64 {
	chunk := block / s.chunkRatio
	return chunk*(s.chunkRatio+1) + s.chunkRatio
}

func (s *Source) bitmapBytes() uint64 {
	return s.blockSize / (uint64(s.sectorSize) * 8)
}

func (s *Source) payloadOffset(block, entry, index uint64) (uint64, error) {
	fileOffset := entry & batFileOffsetMask
	end := fileOffset + s.blockSize
	if end < fileOffset || end > s.parent.Len() {
		return 0, corrupt(s.batOffset+index*batEntrySize,
			fmt.Sprintf("block %d maps to bytes %d..%d beyond the %d byte file",
				block, fileOffset, end, s.parent.Len()))
	}
	return fileOffset, nil
}

func (s *Source) blockState(block uint64) (blockState, error) {
	if block >= s.batEntries {
		return blockState{}, source.NewOutOfRange(block*s.blockSize, s.blockSize, s.length)
	}
	index := s.payloadIndex(block)
	entry, err := s.rawBATEntry(index)
	if err != nil {
		return blockState{}, err
	}
	switch entry & batStateMask {
	case blockFullyPresent:
		fileOffset, err := s.payloadOffset(block, entry, index)
		if err != nil {
			return blockState{}, err
		}
		return blockState{kind: bsData, fileOffset: fileOffset}, nil
	case blockNotPresent:
		if s.backing != nil {
			return blockState{kind: bsParent}, nil
		}
		return blockState{kind: bsZero}, nil
	case blockZero, blockUnmapped:
		return blockState{kind: bsZero}, nil
	case blockUndefined:
		return blockState{}, unsupported(fmt.Sprintf("UNDEFINED payload block %d: the format does not define its contents", block))
	case blockPartiallyPresent:
		if s.backing == nil {
			return blockState{}, unsupported(fmt.Sprintf("partially present payload block %d without a parent", block))
		}
		fileOffset, err := s.payloadOffset(block, entry, index)
		if err != nil {
			return blockState{}, err
		}
		bitmapIndex := s.bitmapIndex(block)
		bitmapEntry, err := s.rawBATEntry(bitmapIndex)
		if err != nil {
			return blockState{}, err
		}
		if bitmapEntry&batStateMask != blockFullyPresent {
			return blockState{}, corrupt(s.batOffset+bitmapIndex*batEntrySize,
				fmt.Sprintf("partially present block %d has sector bitmap state %d instead of FULLY_PRESENT",
					block, bitmapEntry&batStateMask))
		}
		bitmapBlock := bitmapEntry & batFileOffsetMask
		bitmapEnd := bitmapBlock + (1 << 20)
		if bitmapEnd < bitmapBlock || bitmapEnd > s.parent.Len() {
			return blockState{}, corrupt(s.batOffset+bitmapIndex*batEntrySize,
				fmt.Sprintf("sector bitmap block at %d ends beyond the %d byte file",
					bitmapBlock, s.parent.Len()))
		}
		bitmapBytes := s.bitmapBytes()
		return blockState{
			kind:         bsPartial,
			fileOffset:   fileOffset,
			bitmapOffset: bitmapBlock + (block%s.chunkRatio)*bitmapBytes,
			bitmapBytes:  bitmapBytes,
		}, nil
	default:
		return blockState{}, corrupt(s.batOffset+index*batEntrySize,
			fmt.Sprintf("invalid BAT state %d", entry&batStateMask))
	}
}

func (s *Source) rawBATEntry(index uint64) (uint64, error) {
	s.mu.Lock()
	if page := s.batCache; page != nil && index >= page.first {
		if offset := index - page.first; offset < uint64(len(page.entries)) {
			entry := page.entries[offset]
			s.mu.Unlock()
			return entry, nil
		}
	}
	s.mu.Unlock()

	first := index - index%batPageEntries
	count := uint64(batPageEntries)
	if remaining := s.batTotal - first; remaining < count {
		count = remaining
	}
	bytes, err := source.ReadVecAt(s.parent, s.batOffset+first*batEntrySize, count*batEntrySize)
	if err != nil {
		return 0, err
	}
	entries := make([]uint64, count)
	for i := range entries {
		entries[i] = le64(bytes, int(i)*8)
	}
	s.mu.Lock()
	s.batCache = &batPage{first: first, entries: entries}
	s.mu.Unlock()
	return entries[index-first], nil
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
	sector := uint64(s.sectorSize)
	done := 0
	var bitmap []byte
	var bitmapOffset uint64
	haveBitmap := false
	for done < want {
		position := offset + uint64(done)
		block := position / s.blockSize
		inBlock := position % s.blockSize
		chunk := int(minU64(s.blockSize-inBlock, uint64(want-done)))
		state, err := s.blockState(block)
		if err != nil {
			return 0, err
		}
		switch state.kind {
		case bsZero:
			clear(buf[done : done+chunk])
			done += chunk
		case bsParent:
			if err := readRun(s.backing, position, buf[done:done+chunk], lossy); err != nil {
				return 0, err
			}
			done += chunk
		case bsData:
			if err := readRun(s.parent, state.fileOffset+inBlock, buf[done:done+chunk], lossy); err != nil {
				return 0, err
			}
			done += chunk
		case bsPartial:
			if !haveBitmap || bitmapOffset != state.bitmapOffset {
				bitmap, err = source.ReadVecAt(s.parent, state.bitmapOffset, state.bitmapBytes)
				if err != nil {
					return 0, err
				}
				bitmapOffset, haveBitmap = state.bitmapOffset, true
			}
			consumed := 0
			for consumed < chunk {
				at := position + uint64(consumed)
				sectorIndex := (at % s.blockSize) / sector
				within := at % sector
				run := int(minU64(sector-within, uint64(chunk-consumed)))
				present := bitmap[sectorIndex/8]&(1<<(sectorIndex%8)) != 0
				target := buf[done+consumed : done+consumed+run]
				if present {
					if err := readRun(s.parent, state.fileOffset+(at%s.blockSize), target, lossy); err != nil {
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
	sector := uint64(s.sectorSize)
	cursor := offset
	end := offset + length
	for cursor < end {
		block := cursor / s.blockSize
		blockStart := block * s.blockSize
		inBlock := cursor - blockStart
		stop := minU64(end, blockStart+s.blockSize)
		chunk := stop - cursor
		state, err := s.blockState(block)
		if err != nil {
			return out, err
		}
		switch state.kind {
		case bsZero:
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: 0, Len: chunk, Kind: source.RangeZero,
			})
		case bsParent:
			out = append(out, source.ParentRange{
				Parent: s.backing.SourceID(), ParentOffset: cursor, Len: chunk, Kind: source.RangeData,
			})
		case bsData:
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: state.fileOffset + inBlock,
				Len: chunk, Kind: source.RangeData,
			})
		case bsPartial:
			bits, err := source.ReadVecAt(s.parent, state.bitmapOffset, state.bitmapBytes)
			if err != nil {
				return out, err
			}
			at := cursor
			for at < stop {
				sectorIndex := (at - blockStart) / sector
				sectorStop := minU64(blockStart+(sectorIndex+1)*sector, stop)
				present := bits[sectorIndex/8]&(1<<(sectorIndex%8)) != 0
				rangeLen := sectorStop - at
				if present {
					out = append(out, source.ParentRange{
						Parent: s.parent.SourceID(), ParentOffset: state.fileOffset + (at - blockStart),
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

type header struct {
	sequence      uint64
	dataWriteGUID [16]byte
	logGUID       [16]byte
}

func readHeader(src source.ByteSource, offset uint64) (header, error) {
	bytes, err := source.ReadVecAt(src, offset, headerSize)
	if err != nil {
		return header{}, err
	}
	if string(bytes[:4]) != headerSignature {
		return header{}, corrupt(offset, "missing VHDX header signature")
	}
	stored := le32(bytes, 4)
	checked := append([]byte(nil), bytes...)
	clear(checked[4:8])
	if foundation.CRC32C(checked) != stored {
		return header{}, corrupt(offset, "VHDX header checksum mismatch")
	}
	version := le16(bytes, 66)
	if version != 1 {
		return header{}, unsupported(fmt.Sprintf("header version %d", version))
	}
	var h header
	h.sequence = le64(bytes, 8)
	copy(h.dataWriteGUID[:], bytes[32:48])
	copy(h.logGUID[:], bytes[48:64])
	return h, nil
}

func readBestHeader(src source.ByteSource) (header, error) {
	first, firstErr := readHeader(src, header1Offset)
	second, secondErr := readHeader(src, header2Offset)
	switch {
	case firstErr == nil && secondErr == nil:
		if second.sequence > first.sequence {
			return second, nil
		}
		return first, nil
	case firstErr == nil:
		return first, nil
	case secondErr == nil:
		return second, nil
	default:
		return header{}, firstErr
	}
}

type region struct {
	guid   [16]byte
	offset uint64
	length uint64
}

func findRegion(regions []region, guid string) (region, bool) {
	for _, r := range regions {
		if string(r.guid[:]) == guid {
			return r, true
		}
	}
	return region{}, false
}

func parseRegionTable(bytes []byte, offset uint64) ([]region, error) {
	if string(bytes[:4]) != regionSignature {
		return nil, corrupt(offset, "missing VHDX region table signature")
	}
	stored := le32(bytes, 4)
	checked := append([]byte(nil), bytes...)
	clear(checked[4:8])
	if foundation.CRC32C(checked) != stored {
		return nil, corrupt(offset, "VHDX region table checksum mismatch")
	}
	count := int(le32(bytes, 8))
	capacity := (regionSize - 16) / metadataEntrySize
	if count > capacity {
		return nil, corrupt(offset, fmt.Sprintf("region table entry count %d exceeds %d", count, capacity))
	}
	regions := make([]region, count)
	for i := 0; i < count; i++ {
		start := 16 + i*metadataEntrySize
		var guid [16]byte
		copy(guid[:], bytes[start:start+16])
		regions[i] = region{
			guid:   guid,
			offset: le64(bytes, start+16),
			length: uint64(le32(bytes, start+24)),
		}
	}
	return regions, nil
}

func readRegionTable(src source.ByteSource) ([]region, error) {
	readCopy := func(offset uint64) ([]region, error) {
		bytes, err := source.ReadVecAt(src, offset, regionSize)
		if err != nil {
			return nil, err
		}
		return parseRegionTable(bytes, offset)
	}
	first, firstErr := readCopy(region1Offset)
	if firstErr == nil {
		return first, nil
	}
	second, secondErr := readCopy(region2Offset)
	if secondErr == nil {
		return second, nil
	}
	return nil, firstErr
}

type metadataItem struct {
	id     [16]byte
	offset uint32
	length uint32
}

type metadata struct {
	blockSize          uint32
	virtualDiskSize    uint64
	logicalSectorSize  uint32
	physicalSectorSize uint32
	virtualDiskID      [16]byte
	hasParent          bool
	parentLinkage      *[16]byte
	parentHints        []string
}

type parentLocator struct {
	linkage *[16]byte
	hints   []string
}

func readMetadata(src source.ByteSource, region region) (metadata, error) {
	if region.length < metadataHeaderSize {
		return metadata{}, corrupt(region.offset, "metadata region is shorter than its table header")
	}
	header, err := source.ReadVecAt(src, region.offset, metadataHeaderSize)
	if err != nil {
		return metadata{}, err
	}
	if string(header[:8]) != metadataSignature {
		return metadata{}, corrupt(region.offset, "missing VHDX metadata table signature")
	}
	count := int(le16(header, 10))
	if count > metadataMaxEntries {
		return metadata{}, corrupt(region.offset, fmt.Sprintf("metadata entry count %d exceeds %d", count, metadataMaxEntries))
	}
	tableLen := metadataHeaderSize + count*metadataEntrySize
	if uint64(tableLen) > region.length {
		return metadata{}, corrupt(region.offset, "metadata table does not fit in its region")
	}
	table, err := source.ReadVecAt(src, region.offset, uint64(tableLen))
	if err != nil {
		return metadata{}, err
	}
	items := make([]metadataItem, count)
	for i := range items {
		start := metadataHeaderSize + i*metadataEntrySize
		copy(items[i].id[:], table[start:start+16])
		items[i].offset = le32(table, start+16)
		items[i].length = le32(table, start+20)
	}

	readItem := func(id string, max int) ([]byte, bool, error) {
		for _, item := range items {
			if string(item.id[:]) != id {
				continue
			}
			length := int(item.length)
			if length > max {
				return nil, false, corrupt(region.offset, fmt.Sprintf("metadata item length %d exceeds %d", length, max))
			}
			if uint64(item.offset)+uint64(item.length) > region.length {
				return nil, false, corrupt(region.offset, "metadata item extends past its region")
			}
			value, err := source.ReadVecAt(src, region.offset+uint64(item.offset), uint64(item.length))
			if err != nil {
				return nil, false, err
			}
			return value, true, nil
		}
		return nil, false, nil
	}

	parameters, ok, err := readItem(fileParametersID, 64)
	if err != nil {
		return metadata{}, err
	}
	if !ok {
		return metadata{}, corrupt(region.offset, "VHDX has no file parameters")
	}
	if len(parameters) < 8 {
		return metadata{}, corrupt(region.offset, "VHDX file parameters are shorter than 8 bytes")
	}
	blockSize := le32(parameters, 0)
	if blockSize < minBlockSize || blockSize > maxBlockSize || blockSize&(blockSize-1) != 0 {
		return metadata{}, corrupt(region.offset, fmt.Sprintf("invalid VHDX block size %d", blockSize))
	}
	flags := le32(parameters, 4)
	hasParent := flags&0b10 != 0

	size, ok, err := readItem(virtualDiskSizeID, 8)
	if err != nil {
		return metadata{}, err
	}
	if !ok || len(size) != 8 {
		return metadata{}, corrupt(region.offset, "VHDX virtual disk size is missing or not 8 bytes")
	}
	virtualSize := le64(size, 0)

	logical, ok, err := readItem(logicalSectorSizeID, 4)
	if err != nil {
		return metadata{}, err
	}
	if !ok || len(logical) != 4 {
		return metadata{}, corrupt(region.offset, "VHDX logical sector size is missing or not 4 bytes")
	}
	logicalSector := le32(logical, 0)
	if logicalSector != 512 && logicalSector != 4096 {
		return metadata{}, unsupported(fmt.Sprintf("logical sector size %d", logicalSector))
	}

	physicalSector := logicalSector
	if value, ok, err := readItem(physicalSectorSizeID, 4); err != nil {
		return metadata{}, err
	} else if ok && len(value) == 4 {
		physicalSector = le32(value, 0)
	}

	var diskID [16]byte
	if value, ok, err := readItem(virtualDiskIDID, 16); err != nil {
		return metadata{}, err
	} else if ok && len(value) == 16 {
		copy(diskID[:], value)
	}

	hasLocator := false
	for _, item := range items {
		if string(item.id[:]) == parentLocatorID {
			hasLocator = true
			break
		}
	}
	hasParent = hasParent || hasLocator
	var linkage *[16]byte
	var hints []string
	if hasLocator {
		raw, _, err := readItem(parentLocatorID, 1<<20)
		if err != nil {
			return metadata{}, err
		}
		locator, err := parseParentLocator(raw, region.offset)
		if err != nil {
			return metadata{}, err
		}
		linkage, hints = locator.linkage, locator.hints
	}

	return metadata{
		blockSize:          blockSize,
		virtualDiskSize:    virtualSize,
		logicalSectorSize:  logicalSector,
		physicalSectorSize: physicalSector,
		virtualDiskID:      diskID,
		hasParent:          hasParent,
		parentLinkage:      linkage,
		parentHints:        hints,
	}, nil
}

func parseParentLocator(bytes []byte, regionOffset uint64) (parentLocator, error) {
	if len(bytes) < 20 {
		return parentLocator{}, corrupt(regionOffset, "parent locator is shorter than its 20-byte header")
	}
	count := int(le16(bytes, 18))
	entriesEnd := 20 + count*12
	if entriesEnd > len(bytes) {
		return parentLocator{}, corrupt(regionOffset, "parent locator entries extend past the item")
	}
	var out parentLocator
	for i := 0; i < count; i++ {
		start := 20 + i*12
		keyOffset := int(le32(bytes, start))
		valueOffset := int(le32(bytes, start+4))
		keyLength := int(le16(bytes, start+8))
		valueLength := int(le16(bytes, start+10))
		key, ok := utf16Text(bytes, keyOffset, keyLength)
		if !ok {
			return parentLocator{}, corrupt(regionOffset, "parent locator key extends past the item or is not UTF-16")
		}
		value, ok := utf16Text(bytes, valueOffset, valueLength)
		if !ok {
			return parentLocator{}, corrupt(regionOffset, "parent locator value extends past the item or is not UTF-16")
		}
		key = strings.ToLower(key)
		if key == "parent_linkage" {
			guid, ok := parseGUIDText(strings.TrimSpace(value))
			if !ok {
				return parentLocator{}, corrupt(regionOffset,
					fmt.Sprintf("parent_linkage value `%s` is not a GUID", strings.TrimSpace(value)))
			}
			out.linkage = &guid
		} else if key == "parent_filename" || strings.Contains(key, "path") || strings.Contains(key, "filename") {
			out.hints = append(out.hints, value)
		}
	}
	return out, nil
}

func utf16Text(bytes []byte, offset, length int) (string, bool) {
	if offset < 0 || length < 0 || offset+length > len(bytes) || length%2 != 0 {
		return "", false
	}
	units := make([]uint16, length/2)
	for i := range units {
		units[i] = uint16(bytes[offset+i*2]) | uint16(bytes[offset+i*2+1])<<8
	}
	return strings.TrimRight(string(utf16.Decode(units)), "\x00"), true
}

func parseGUIDText(text string) ([16]byte, bool) {
	text = strings.Trim(text, "{}")
	var hex strings.Builder
	for _, c := range text {
		if c != '-' {
			hex.WriteRune(c)
		}
	}
	raw := hex.String()
	if len(raw) != 32 {
		return [16]byte{}, false
	}
	var bytes [16]byte
	for i := 0; i < 16; i++ {
		value, ok := parseHexByte(raw[i*2 : i*2+2])
		if !ok {
			return [16]byte{}, false
		}
		bytes[i] = value
	}
	var guid [16]byte
	guid[0], guid[1], guid[2], guid[3] = bytes[3], bytes[2], bytes[1], bytes[0]
	guid[4], guid[5] = bytes[5], bytes[4]
	guid[6], guid[7] = bytes[7], bytes[6]
	copy(guid[8:], bytes[8:])
	return guid, true
}

func parseHexByte(text string) (byte, bool) {
	var value byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		var digit byte
		switch {
		case c >= '0' && c <= '9':
			digit = c - '0'
		case c >= 'a' && c <= 'f':
			digit = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			digit = c - 'A' + 10
		default:
			return 0, false
		}
		value = value<<4 | digit
	}
	return value, true
}

// formatGUID formats a GUID stored in VHDX byte order.
func formatGUID(guid [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		le32(guid[:], 0), le16(guid[:], 4), le16(guid[:], 6),
		guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15])
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
