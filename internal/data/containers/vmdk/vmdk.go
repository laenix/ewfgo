// Package vmdk exposes VMware sparse VMDK extents as a ByteSource. It is a
// pure-Go port of forensic-core's data/containers/vmdk.rs, starting with
// version-1 uncompressed extents, the redundant grain directory, the embedded
// descriptor's parent links, and differencing over an explicit parent.
package vmdk

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Signature is the sparse-extent magic at offset 0.
	Signature = "KDMV"
	// HeaderBytes is the sparse header size.
	HeaderBytes = 512
	// SectorSize is VMDK's address unit.
	SectorSize uint64 = 512
	// MaxDescriptorBytes bounds the embedded descriptor.
	MaxDescriptorBytes = 64 * 1024
	// MaxGrainSectors bounds a grain; 512 MiB.
	MaxGrainSectors = 1048576

	flagRedundantDirectory uint32 = 1 << 1
	flagCompressed         uint32 = 1 << 16
	flagMarkers            uint32 = 1 << 17

	gdAtEnd               uint64 = 0xFFFFFFFFFFFFFFFF
	gteZeroed             uint32 = 1
	directoryPageEntries  uint64 = 1024
	compressionDeflate    uint16 = 1
	footerMarkerType      uint32 = 3
	footerBytes           uint64 = 3 * SectorSize
	grainMarkerBytes      uint64 = 12
	grainMarkerCompressed uint64 = 1 << 63
)

// Info is the extent's identity and geometry.
type Info struct {
	Version                uint32
	Flags                  uint32
	CapacityBytes          uint64
	GrainSize              uint64 // sectors
	GrainsPerTable         uint32
	GrainDirectoryEntries  uint64
	RedundantDirectory     bool
	UsedRedundantDirectory bool
	DescriptorBytes        uint64
	DescriptorTruncated    bool
	UncleanShutdown        bool
	CompressAlgorithm      uint16
	StreamOptimized        bool
	FooterOffset           *uint64
	CID                    string
	ParentCID              string
	ParentFileHint         string
	Differencing           bool
}

// GrainBytes returns the grain size in bytes.
func (i Info) GrainBytes() uint64 { return i.GrainSize * SectorSize }

type grainMapKind uint8

const (
	grainUnallocated grainMapKind = iota
	grainZero
	grainData
)

type grainMap struct {
	kind       grainMapKind
	fileOffset uint64
}

type directoryPage struct {
	first   uint64
	entries []uint32
}

type tablePage struct {
	tableSector uint64
	entries     []uint32
}

// Source is a read-only VMDK sparse extent.
type Source struct {
	id             source.ID
	parent         source.ByteSource
	backing        source.ByteSource
	length         uint64
	grainBytes     uint64
	grainsPerTable uint64
	gdOffset       uint64
	gdEntries      uint64
	compressed     bool
	footerOffset   *uint64
	info           Info
	descriptor     []byte
	mu             sync.Mutex
	dirPage        *directoryPage
	tablePage      *tablePage
	grainCache     *grainCacheEntry
	counters       source.Counters
}

type grainCacheEntry struct {
	grain uint64
	data  []byte
}

// MatchesSignature reports whether head starts with KDMV.
func MatchesSignature(head []byte) bool {
	return len(head) >= 4 && string(head[:4]) == Signature
}

// Open opens a standalone sparse extent. A differencing extent is refused.
func Open(id source.ID, parent source.ByteSource) (*Source, error) {
	return openInner(id, parent, nil, false)
}

// OpenWithParent opens a differencing extent over an explicit parent.
func OpenWithParent(id source.ID, child source.ByteSource, backing *Source) (*Source, error) {
	return openInner(id, child, backing, false)
}

// OpenExtent opens one sparse extent of an assembled split disk. Per-extent
// parent linkage checks are skipped: the split descriptor owns that check, and
// backing is a window over the logical parent disk.
func OpenExtent(id source.ID, child source.ByteSource, backing source.ByteSource) (*Source, error) {
	return openInner(id, child, backing, true)
}

type vmdkHeader struct {
	version           uint32
	flags             uint32
	capacitySectors   uint64
	grainSize         uint64
	descriptorOffset  uint64
	descriptorSize    uint64
	grainsPerTable    uint32
	redundantOffset   uint64
	gdOffset          uint64
	uncleanShutdown   bool
	compressAlgorithm uint16
}

func parseHeader(bytes []byte) vmdkHeader {
	return vmdkHeader{
		version:           le32(bytes, 4),
		flags:             le32(bytes, 8),
		capacitySectors:   le64(bytes, 12),
		grainSize:         le64(bytes, 20),
		descriptorOffset:  le64(bytes, 28),
		descriptorSize:    le64(bytes, 36),
		grainsPerTable:    le32(bytes, 44),
		redundantOffset:   le64(bytes, 48),
		gdOffset:          le64(bytes, 56),
		uncleanShutdown:   bytes[72] != 0,
		compressAlgorithm: uint16(bytes[77]) | uint16(bytes[78])<<8,
	}
}

func openInner(id source.ID, parent source.ByteSource, backing source.ByteSource, splitExtent bool) (*Source, error) {
	if parent.Len() < HeaderBytes {
		return nil, unsupported("sparse-extent signature")
	}
	headerBytes, err := source.ReadVecAt(parent, 0, HeaderBytes)
	if err != nil {
		return nil, err
	}
	if string(headerBytes[:4]) != Signature {
		return nil, unsupported("sparse-extent signature")
	}
	header := parseHeader(headerBytes)
	if header.version != 1 {
		return nil, unsupported(fmt.Sprintf("sparse-extent version %d", header.version))
	}
	compressed := header.flags&flagCompressed != 0
	if compressed && header.flags&flagMarkers == 0 {
		return nil, unsupported("compressed grains without grain markers")
	}
	if !compressed && header.flags&flagMarkers != 0 {
		return nil, unsupported("grain markers without compression")
	}
	if header.compressAlgorithm > compressionDeflate {
		return nil, unsupported(fmt.Sprintf("compression algorithm %d (only zlib/deflate is defined)", header.compressAlgorithm))
	}

	var footerOffset *uint64
	if compressed {
		if parent.Len() < footerBytes {
			return nil, corrupt(0, fmt.Sprintf("streamOptimized VMDK is %d bytes, shorter than its %d byte footer", parent.Len(), footerBytes))
		}
		start := parent.Len() - footerBytes
		tail, err := source.ReadVecAt(parent, start, footerBytes)
		if err != nil {
			return nil, err
		}
		if le32(tail, 12) != footerMarkerType {
			return nil, corrupt(start, "streamOptimized footer does not begin with a FOOTER marker")
		}
		footer := tail[int(SectorSize) : int(SectorSize)+HeaderBytes]
		if string(footer[:4]) != Signature {
			return nil, corrupt(start+SectorSize, "streamOptimized footer header does not start with KDMV")
		}
		parsed := parseHeader(footer)
		if parsed.version != 1 {
			return nil, unsupported(fmt.Sprintf("sparse-extent version %d", parsed.version))
		}
		if parsed.flags&flagCompressed == 0 {
			return nil, corrupt(start+SectorSize, "streamOptimized footer does not describe compressed grains")
		}
		if parsed.compressAlgorithm > compressionDeflate {
			return nil, unsupported(fmt.Sprintf("compression algorithm %d (only zlib/deflate is defined)", parsed.compressAlgorithm))
		}
		if parsed.gdOffset == gdAtEnd {
			return nil, corrupt(start+SectorSize, "streamOptimized footer still defers the grain directory")
		}
		footerOffset = &start
		header = parsed
	} else if header.gdOffset == gdAtEnd {
		return nil, corrupt(56, "the header defers its grain directory but has no compressed grains")
	}

	if header.capacitySectors == 0 {
		return nil, corrupt(0, "virtual disk capacity is zero")
	}
	if header.grainSize == 0 || header.grainSize > MaxGrainSectors {
		return nil, corrupt(20, fmt.Sprintf("grain size %d sectors is outside 1..=%d", header.grainSize, MaxGrainSectors))
	}
	if header.grainsPerTable == 0 {
		return nil, corrupt(44, "grains per grain table is zero")
	}
	grainBytes := header.grainSize * SectorSize
	capacityBytes := header.capacitySectors * SectorSize
	grains := (header.capacitySectors + header.grainSize - 1) / header.grainSize
	gdEntries := (grains + uint64(header.grainsPerTable) - 1) / uint64(header.grainsPerTable)
	gdBytes := gdEntries * 4

	usable := func(offset uint64) bool {
		if offset == 0 {
			return false
		}
		start := offset * SectorSize
		if start/SectorSize != offset || start+gdBytes < start {
			return false
		}
		return start+gdBytes <= parent.Len()
	}
	gdOffset := header.gdOffset
	usedRedundant := false
	switch {
	case usable(header.gdOffset):
	case header.flags&flagRedundantDirectory != 0 && usable(header.redundantOffset):
		gdOffset = header.redundantOffset
		usedRedundant = true
	case header.gdOffset == 0:
		return nil, corrupt(56, "grain directory offset is zero")
	default:
		return nil, corrupt(56, fmt.Sprintf("grain directory at sector %d (%d bytes) is outside the %d byte file",
			header.gdOffset, gdBytes, parent.Len()))
	}

	descriptor, err := readDescriptor(parent, header.descriptorOffset, header.descriptorSize)
	if err != nil {
		return nil, err
	}
	links := parseDescriptorLinks(descriptor)
	differencing := links.declaresParent()
	if compressed && backing != nil {
		return nil, unsupported("a streamOptimized differencing extent: compressed grains and a parent chain are not merged")
	}
	if !splitExtent {
		if differencing && backing == nil {
			parentName := links.parentName()
			if parentName == "" {
				parentName = "an unnamed parent"
			}
			return nil, unsupported(fmt.Sprintf("a differencing sparse extent (parent %s); reading it alone would return only the delta's changes", parentName))
		}
		if !differencing && backing != nil {
			return nil, unsupported("parent supplied for a VMDK base disk that does not reference one")
		}
		if backing != nil {
			disk, ok := backing.(*Source)
			if !ok {
				return nil, unsupported("split extent backing must be opened through OpenExtent")
			}
			if err := validateParent(links, capacityBytes, disk); err != nil {
				return nil, err
			}
		}
	}

	descriptorTruncated := header.descriptorSize*SectorSize > MaxDescriptorBytes
	info := Info{
		Version:                header.version,
		Flags:                  header.flags,
		CapacityBytes:          capacityBytes,
		GrainSize:              header.grainSize,
		GrainsPerTable:         header.grainsPerTable,
		GrainDirectoryEntries:  gdEntries,
		RedundantDirectory:     header.flags&flagRedundantDirectory != 0,
		UsedRedundantDirectory: usedRedundant,
		DescriptorBytes:        uint64(len(descriptor)),
		DescriptorTruncated:    descriptorTruncated,
		UncleanShutdown:        header.uncleanShutdown,
		CompressAlgorithm:      header.compressAlgorithm,
		StreamOptimized:        footerOffset != nil,
		FooterOffset:           footerOffset,
		CID:                    links.cid,
		ParentCID:              links.parentCID,
		ParentFileHint:         links.parentFile,
		Differencing:           differencing,
	}
	return &Source{
		id:             id,
		parent:         parent,
		backing:        backing,
		length:         capacityBytes,
		grainBytes:     grainBytes,
		grainsPerTable: uint64(header.grainsPerTable),
		gdOffset:       gdOffset,
		gdEntries:      gdEntries,
		compressed:     compressed,
		footerOffset:   footerOffset,
		info:           info,
		descriptor:     descriptor,
	}, nil
}

// Info returns the extent geometry and identity.
func (s *Source) Info() Info { return s.info }

// Descriptor returns the embedded descriptor with trailing NULs removed.
func (s *Source) Descriptor() []byte { return s.descriptor }

// Parent returns the container source.
func (s *Source) Parent() source.ByteSource { return s.parent }

// Backing returns the differencing parent.
func (s *Source) Backing() source.ByteSource { return s.backing }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.length }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *Source) SectorSize() uint32      { return uint32(SectorSize) }
func (s *Source) IsEmpty() bool           { return s.length == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) checkRange(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

func (s *Source) grainMapFor(grain uint64) (grainMap, error) {
	gdIndex := grain / s.grainsPerTable
	gteIndex := grain % s.grainsPerTable
	tableSector, err := s.directoryEntry(gdIndex)
	if err != nil {
		return grainMap{}, err
	}
	if tableSector == 0 {
		return grainMap{kind: grainUnallocated}, nil
	}
	entry, err := s.tableEntry(uint64(tableSector), gteIndex)
	if err != nil {
		return grainMap{}, err
	}
	switch entry {
	case 0:
		return grainMap{kind: grainUnallocated}, nil
	case gteZeroed:
		return grainMap{kind: grainZero}, nil
	}
	offset := uint64(entry) * SectorSize
	needed := s.grainBytes
	if s.compressed {
		needed = grainMarkerBytes
	}
	end := offset + needed
	if end < offset || end > s.parent.Len() {
		return grainMap{}, corrupt(s.gdOffset*SectorSize+gdIndex*4,
			fmt.Sprintf("grain %d maps to bytes %d..%d beyond the %d byte file",
				grain, offset, end, s.parent.Len()))
	}
	return grainMap{kind: grainData, fileOffset: offset}, nil
}

func (s *Source) directoryEntry(index uint64) (uint32, error) {
	s.mu.Lock()
	if page := s.dirPage; page != nil && index >= page.first {
		if at := index - page.first; at < uint64(len(page.entries)) {
			entry := page.entries[at]
			s.mu.Unlock()
			return entry, nil
		}
	}
	s.mu.Unlock()

	first := index - index%directoryPageEntries
	count := directoryPageEntries
	if remaining := s.gdEntries - first; remaining < count {
		count = remaining
	}
	bytes, err := source.ReadVecAt(s.parent, s.gdOffset*SectorSize+first*4, count*4)
	if err != nil {
		return 0, err
	}
	entries := make([]uint32, count)
	for i := range entries {
		entries[i] = le32(bytes, i*4)
	}
	s.mu.Lock()
	s.dirPage = &directoryPage{first: first, entries: entries}
	s.mu.Unlock()
	return entries[index-first], nil
}

func (s *Source) tableEntry(tableSector, index uint64) (uint32, error) {
	s.mu.Lock()
	if page := s.tablePage; page != nil && page.tableSector == tableSector {
		if index < uint64(len(page.entries)) {
			entry := page.entries[index]
			s.mu.Unlock()
			return entry, nil
		}
	}
	s.mu.Unlock()

	start := tableSector * SectorSize
	needed := s.grainsPerTable * 4
	if start+needed < start || start+needed > s.parent.Len() {
		return 0, corrupt(start, fmt.Sprintf("grain table at sector %d (%d bytes) is outside the %d byte file",
			tableSector, needed, s.parent.Len()))
	}
	bytes, err := source.ReadVecAt(s.parent, start, needed)
	if err != nil {
		return 0, err
	}
	entries := make([]uint32, s.grainsPerTable)
	for i := range entries {
		entries[i] = le32(bytes, i*4)
	}
	s.mu.Lock()
	s.tablePage = &tablePage{tableSector: tableSector, entries: entries}
	s.mu.Unlock()
	return entries[index], nil
}

func (s *Source) visibleBytes(grain uint64) uint64 {
	start := grain * s.grainBytes
	if start >= s.length {
		return 0
	}
	return minU64(s.length-start, s.grainBytes)
}

func (s *Source) grainMarker(grain, fileOffset uint64) (payloadOffset, length uint64, err error) {
	raw, err := source.ReadVecAt(s.parent, fileOffset, grainMarkerBytes)
	if err != nil {
		return 0, 0, err
	}
	lba := le64(raw, 0)
	length = uint64(le32(raw, 8))
	if lba&grainMarkerCompressed == 0 {
		return 0, 0, unsupported(fmt.Sprintf("an uncompressed grain inside a streamOptimized extent (grain %d at byte %d)", grain, fileOffset))
	}
	lba &^= grainMarkerCompressed
	expected := grain * s.info.GrainSize
	if lba != expected {
		return 0, 0, corrupt(fileOffset, fmt.Sprintf("grain %d marker names sector %d, expected %d", grain, lba, expected))
	}
	if length == 0 {
		return 0, 0, corrupt(fileOffset, fmt.Sprintf("grain %d marker declares an empty stream", grain))
	}
	payloadOffset = fileOffset + grainMarkerBytes
	end := payloadOffset + length
	if end < payloadOffset || end > s.parent.Len() {
		return 0, 0, corrupt(fileOffset, fmt.Sprintf("grain %d stream spans bytes %d..%d, beyond the %d byte file",
			grain, payloadOffset, end, s.parent.Len()))
	}
	return payloadOffset, length, nil
}

func (s *Source) compressedGrain(grain, fileOffset uint64) ([]byte, error) {
	s.mu.Lock()
	if entry := s.grainCache; entry != nil && entry.grain == grain {
		data := entry.data
		s.mu.Unlock()
		s.counters.AddCacheHit()
		return data, nil
	}
	s.mu.Unlock()
	s.counters.AddCacheMiss()

	payloadOffset, length, err := s.grainMarker(grain, fileOffset)
	if err != nil {
		return nil, err
	}
	stream, err := source.ReadVecAt(s.parent, payloadOffset, length)
	if err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, corrupt(fileOffset, fmt.Sprintf("compressed grain %d does not inflate: %v", grain, err))
	}
	decoded, err := io.ReadAll(io.LimitReader(zr, int64(s.grainBytes)+1))
	closeErr := zr.Close()
	if err != nil {
		return nil, corrupt(fileOffset, fmt.Sprintf("compressed grain %d does not inflate: %v", grain, err))
	}
	if closeErr != nil {
		return nil, corrupt(fileOffset, fmt.Sprintf("compressed grain %d does not inflate: %v", grain, closeErr))
	}
	if uint64(len(decoded)) > s.grainBytes {
		return nil, corrupt(fileOffset, fmt.Sprintf("compressed grain %d inflates past its %d-byte grain", grain, s.grainBytes))
	}
	if uint64(len(decoded)) < s.visibleBytes(grain) {
		return nil, corrupt(fileOffset, fmt.Sprintf("compressed grain %d inflates to %d bytes but holds %d guest bytes",
			grain, len(decoded), s.visibleBytes(grain)))
	}
	for uint64(len(decoded)) < s.grainBytes {
		decoded = append(decoded, 0)
	}
	s.counters.AddDecompressed(uint64(len(decoded)))
	s.mu.Lock()
	s.grainCache = &grainCacheEntry{grain: grain, data: decoded}
	s.mu.Unlock()
	return decoded, nil
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
		grain := position / s.grainBytes
		inGrain := position % s.grainBytes
		chunk := int(minU64(s.grainBytes-inGrain, uint64(want-done)))
		mapping, err := s.grainMapFor(grain)
		if err != nil {
			return 0, err
		}
		switch mapping.kind {
		case grainData:
			if s.compressed {
				decoded, err := s.compressedGrain(grain, mapping.fileOffset)
				if err != nil {
					return 0, err
				}
				copy(buf[done:done+chunk], decoded[inGrain:inGrain+uint64(chunk)])
				done += chunk
				continue
			}
			target := buf[done : done+chunk]
			n, err := readRun(s.parent, mapping.fileOffset+inGrain, target, lossy)
			if err != nil {
				return 0, err
			}
			done += n
			if n < chunk {
				s.counters.AddRead(done)
				return done, nil
			}
		case grainUnallocated:
			if s.backing != nil {
				target := buf[done : done+chunk]
				if err := readFull(s.backing, position, target, lossy); err != nil {
					return 0, err
				}
				done += chunk
			} else {
				clear(buf[done : done+chunk])
				done += chunk
			}
		case grainZero:
			clear(buf[done : done+chunk])
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
		grain := cursor / s.grainBytes
		inGrain := cursor % s.grainBytes
		stop := minU64(end, (grain+1)*s.grainBytes)
		chunk := stop - cursor
		mapping, err := s.grainMapFor(grain)
		if err != nil {
			return out, err
		}
		switch mapping.kind {
		case grainData:
			if s.compressed {
				payloadOffset, length, err := s.grainMarker(grain, mapping.fileOffset)
				if err != nil {
					return out, err
				}
				out = append(out, source.ParentRange{
					Parent: s.parent.SourceID(), ParentOffset: payloadOffset,
					Len: length, Kind: source.RangeData,
				})
			} else {
				out = append(out, source.ParentRange{
					Parent: s.parent.SourceID(), ParentOffset: mapping.fileOffset + inGrain,
					Len: chunk, Kind: source.RangeData,
				})
			}
		case grainUnallocated:
			if s.backing != nil {
				out = append(out, source.ParentRange{
					Parent: s.backing.SourceID(), ParentOffset: cursor,
					Len: chunk, Kind: source.RangeData,
				})
			} else {
				out = append(out, source.ParentRange{
					Parent: s.parent.SourceID(), ParentOffset: 0,
					Len: chunk, Kind: source.RangeZero,
				})
			}
		case grainZero:
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: 0,
				Len: chunk, Kind: source.RangeZero,
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

type descriptorLinks struct {
	cid        string
	parentCID  string
	parentFile string
}

func parseDescriptorLinks(descriptor []byte) descriptorLinks {
	var links descriptorLinks
	text := string(descriptor)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "cid":
			links.cid = value
		case "parentcid":
			links.parentCID = value
		case "parentfilenamehint":
			links.parentFile = value
		}
	}
	return links
}

func (l descriptorLinks) declaresParent() bool {
	if l.parentFile != "" {
		return true
	}
	return l.parentCID != "" && !strings.EqualFold(l.parentCID, "ffffffff")
}

func (l descriptorLinks) parentName() string {
	if l.parentFile != "" {
		return fmt.Sprintf("%q", l.parentFile)
	}
	if l.parentCID != "" && !strings.EqualFold(l.parentCID, "ffffffff") {
		return "CID " + l.parentCID
	}
	return ""
}

func validateParent(child descriptorLinks, childCapacity uint64, backing *Source) error {
	childCID, ok := parseCID(child.parentCID)
	if !ok {
		return unsupported(fmt.Sprintf("a differencing extent whose parentCID %q is not a 32-bit content id", child.parentCID))
	}
	if backing.info.CID == "" {
		return unsupported("the supplied parent's embedded descriptor declares no CID")
	}
	parentCID, ok := parseCID(backing.info.CID)
	if !ok {
		return unsupported(fmt.Sprintf("the supplied parent's CID %q is not a 32-bit content id", backing.info.CID))
	}
	if childCID != parentCID {
		return unsupported(fmt.Sprintf("differencing parentCID %#010x does not match the parent descriptor's CID %#010x", childCID, parentCID))
	}
	if childCapacity != backing.length {
		return unsupported(fmt.Sprintf("differencing child capacity %d does not match the parent's %d", childCapacity, backing.length))
	}
	return nil
}

func parseCID(text string) (uint32, bool) {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "0x")
	if text == "" {
		return 0, false
	}
	var value uint32
	for i := 0; i < len(text); i++ {
		c := text[i]
		var digit uint32
		switch {
		case c >= '0' && c <= '9':
			digit = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			digit = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			digit = uint32(c-'A') + 10
		default:
			return 0, false
		}
		next := value<<4 | digit
		if next>>4 != value {
			return 0, false
		}
		value = next
	}
	return value, true
}

func readDescriptor(parent source.ByteSource, offsetSectors, sizeSectors uint64) ([]byte, error) {
	if offsetSectors == 0 || sizeSectors == 0 {
		return nil, nil
	}
	start := offsetSectors * SectorSize
	if start/SectorSize != offsetSectors || start >= parent.Len() {
		return nil, nil
	}
	declared := sizeSectors * SectorSize
	if declared/SectorSize != sizeSectors {
		return nil, nil
	}
	available := parent.Len() - start
	want := declared
	if want > MaxDescriptorBytes {
		want = MaxDescriptorBytes
	}
	if want > available {
		want = available
	}
	bytes, err := source.ReadVecAt(parent, start, want)
	if err != nil {
		return nil, err
	}
	for len(bytes) > 0 && bytes[len(bytes)-1] == 0 {
		bytes = bytes[:len(bytes)-1]
	}
	return bytes, nil
}

func readRun(src source.ByteSource, offset uint64, target []byte, lossy bool) (int, error) {
	if lossy {
		return src.ReadAtLossy(offset, target)
	}
	return src.ReadAt(offset, target)
}

func readFull(src source.ByteSource, offset uint64, target []byte, lossy bool) error {
	n, err := readRun(src, offset, target, lossy)
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
