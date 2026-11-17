package aff4

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

// StreamKind is the kind of stream a StreamSource presents.
type StreamKind uint8

const (
	// KindImage is a chunked image stream.
	KindImage StreamKind = iota
	// KindMap is a map stream joining targets.
	KindMap
	// KindZero is a stream of zeros.
	KindZero
	// KindSegment is a ZipSegment stream backed by one ZIP member.
	KindSegment
)

// String returns the stream kind label.
func (k StreamKind) String() string {
	switch k {
	case KindImage:
		return "image"
	case KindMap:
		return "map"
	case KindZero:
		return "zero"
	case KindSegment:
		return "segment"
	default:
		return "unknown"
	}
}

// compression is the per-chunk codec an image stream declares.
type compression uint8

const (
	compressionStored compression = iota
	compressionZero
	compressionZlib
	compressionSnappy
	compressionLz4
)

// String returns the codec label.
func (c compression) String() string {
	switch c {
	case compressionStored:
		return "stored"
	case compressionZero:
		return "zero"
	case compressionZlib:
		return "zlib"
	case compressionSnappy:
		return "snappy"
	case compressionLz4:
		return "lz4"
	default:
		return "unknown"
	}
}

// hasDecoder reports whether this build can decode the codec.  Snappy and lz4
// are recognised (so the stream is enumerated and refused by name) but have no
// pure-Go implementation in this module.
func (c compression) hasDecoder() bool {
	return c == compressionStored || c == compressionZero || c == compressionZlib
}

// parseCompression resolves a declared label.  ok is false only for a label
// this reader does not recognize at all.
func parseCompression(label string) (compression, bool) {
	local := label
	if strings.ContainsAny(label, "#/") {
		value, ok := iriLocal(label)
		if !ok {
			return 0, false
		}
		local = value
	} else {
		local = strings.TrimPrefix(label, "aff4:")
	}
	switch strings.ToLower(local) {
	case "stored", "none":
		return compressionStored, true
	case "zero":
		return compressionZero, true
	case "zlib":
		return compressionZlib, true
	case "snappy":
		return compressionSnappy, true
	case "lz4":
		return compressionLz4, true
	default:
		return 0, false
	}
}

// ChunkInfo is one resolved image chunk.
type ChunkInfo struct {
	Index uint64
	// Bevy is the bevy number, derived from geometry or read from the index.
	Bevy uint64
	// Member is the normalized central-directory path of the bevy member.
	Member string
	// MemberOffset is the offset of the chunk inside the bevy's decoded bytes.
	MemberOffset uint64
	// StoredLen is the compressed length inside the bevy.
	StoredLen uint64
	// LogicalOffset is the offset of the chunk in the image stream.
	LogicalOffset uint64
	// LogicalLen is the uncompressed chunk length (the last chunk may be short).
	LogicalLen uint64
	// ImageOffset is the evidence offset of the stored chunk: exact when
	// ImageOffsetExact is true, otherwise the start of the ZIP member payload.
	ImageOffset uint64
	// ImageOffsetExact reports whether ImageOffset is the exact payload offset.
	ImageOffsetExact bool
}

// MemberCRC is one ZIP member CRC the reader looked at.
type MemberCRC struct {
	Member   string
	Recorded *uint32
	Checked  bool
	Matches  *bool
}

// memberEntry is the subset of the ZIP entry source this package needs.
type memberEntry interface {
	source.ByteSource
	Entry() archive.Entry
	DataOffset() uint64
	CompressedSize() uint64
	Method() uint16
	CRC32Result() *bool
}

type imageReader struct {
	chunkSize    uint64
	compression  compression
	chunks       []ChunkInfo
	bevies       []string
	indexMember  string
	maxCached    int
	maxChunkSize uint64

	mu      sync.Mutex
	entries map[string]memberEntry
	cache   map[uint64][]byte
	order   []uint64
}

func (r *imageReader) chunk(index uint64) (ChunkInfo, bool) {
	if index >= uint64(len(r.chunks)) {
		return ChunkInfo{}, false
	}
	return r.chunks[index], true
}

func (r *imageReader) entrySource(member string) (memberEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[member]
	if !ok {
		return nil, corruptf("AFF4 bevy member %s was not opened with the stream", member)
	}
	return entry, nil
}

func (r *imageReader) entryFor(member string) (memberEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[member]
	return entry, ok
}

func (r *imageReader) decodeChunk(parent *StreamSource, index uint64) ([]byte, error) {
	r.mu.Lock()
	if decoded, ok := r.cache[index]; ok {
		r.mu.Unlock()
		parent.counters.AddCacheHit()
		return decoded, nil
	}
	r.mu.Unlock()
	parent.counters.AddCacheMiss()

	info, ok := r.chunk(index)
	if !ok {
		return nil, source.NewOutOfRange(index, 0, uint64(len(r.chunks)))
	}
	entry, err := r.entrySource(info.Member)
	if err != nil {
		return nil, err
	}
	stored, err := source.ReadVecAt(entry, info.MemberOffset, info.StoredLen)
	if err != nil {
		return nil, err
	}
	if info.LogicalLen > r.maxChunkSize {
		return nil, limitf("AFF4 chunk %d declares %d logical bytes, limit is %d",
			info.Index, info.LogicalLen, r.maxChunkSize)
	}
	if info.LogicalLen > uint64(maxIntValue()) {
		return nil, corruptf("AFF4 chunk %d is larger than this platform's int", info.Index)
	}
	expected := int(info.LogicalLen)

	var decoded []byte
	switch r.compression {
	case compressionStored:
		decoded = stored
	case compressionZero:
		if len(stored) != 0 {
			return nil, corruptf("AFF4 zero-compressed chunk %d carries %d stored bytes",
				info.Index, len(stored))
		}
		decoded = make([]byte, expected)
	case compressionZlib:
		decoded, err = decodeZlibChunk(stored, expected, info)
		if err != nil {
			return nil, err
		}
		parent.counters.AddDecompressed(uint64(len(decoded)))
	default:
		return nil, unsupportedf("AFF4 stream %s declares compression method %s, which has no decoder here",
			parent.uri, r.compression)
	}
	if len(decoded) != expected {
		return nil, corruptf("AFF4 chunk %d decoded to %d bytes, the geometry declares %d",
			info.Index, len(decoded), expected)
	}

	cacheLimit := r.maxCached
	if cacheLimit < 1 {
		cacheLimit = 1
	}
	r.mu.Lock()
	for len(r.cache) >= cacheLimit && len(r.order) > 0 {
		oldest := r.order[0]
		r.order = r.order[1:]
		delete(r.cache, oldest)
	}
	r.cache[index] = decoded
	r.order = append(r.order, index)
	r.mu.Unlock()
	return decoded, nil
}

func decodeZlibChunk(stored []byte, expected int, info ChunkInfo) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(stored))
	if err != nil {
		return nil, corruptf("AFF4 chunk %d did not decode as zlib: %v", info.Index, err)
	}
	defer reader.Close()
	limit := int64(expected)
	if limit < math.MaxInt64 {
		limit++
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, limit))
	if err != nil {
		return nil, corruptf("AFF4 chunk %d did not decode as zlib: %v", info.Index, err)
	}
	return decoded, nil
}

type mapEntry struct {
	target        int
	targetOffset  uint64
	logicalOffset uint64
	length        uint64
}

type mapReader struct {
	entries   []mapEntry
	targets   []*StreamSource
	dataEntry memberEntry
}

func (r *mapReader) entryAt(offset uint64) (mapEntry, bool) {
	position := sort.Search(len(r.entries), func(index int) bool {
		return r.entries[index].logicalOffset > offset
	})
	if position == 0 {
		return mapEntry{}, false
	}
	entry := r.entries[position-1]
	if offset-entry.logicalOffset < entry.length {
		return entry, true
	}
	return mapEntry{}, false
}

// StreamSource is a read-only AFF4 image, map, zero or segment stream.
//
// It reads the ZIP container through the existing reader, resolves each image
// chunk to its bevy member and decodes only the chunks a read touches.  Every
// read reports its owning member, uncompressed offset and evidence offset
// through Chunks and the ByteSource extent methods.
type StreamSource struct {
	id       source.ID
	parent   source.ByteSource
	facts    *Facts
	uri      string
	kind     StreamKind
	size     uint64
	counters source.Counters

	image   *imageReader
	mapData *mapReader
	segment memberEntry
}

// StreamURI returns the AFF4 URI this source presents.
func (s *StreamSource) StreamURI() string { return s.uri }

// Kind returns the stream kind.
func (s *StreamSource) Kind() StreamKind { return s.kind }

// Facts returns the container metadata this source was opened from.
func (s *StreamSource) Facts() Facts { return *s.facts }

// Chunks returns the resolved chunks of an image stream, in ascending order.
// A map, zero or segment stream returns an empty slice.
func (s *StreamSource) Chunks() []ChunkInfo {
	if s.image == nil {
		return nil
	}
	return append([]ChunkInfo(nil), s.image.chunks...)
}

// ChunkAt returns the image chunk that contains offset.
func (s *StreamSource) ChunkAt(offset uint64) (ChunkInfo, bool) {
	if s.image == nil || s.image.chunkSize == 0 {
		return ChunkInfo{}, false
	}
	return s.image.chunk(offset / s.image.chunkSize)
}

// DeclaredHashes returns the hashes declared for this stream.  They are
// reported, never verified.
func (s *StreamSource) DeclaredHashes() []HashFact {
	var out []HashFact
	for _, hash := range s.facts.Hashes {
		if hash.Subject == s.uri {
			out = append(out, hash)
		}
	}
	return out
}

// MemberCRCs returns the ZIP member CRCs this source and its targets use.
func (s *StreamSource) MemberCRCs() ([]MemberCRC, error) {
	members := make(map[string]struct{})
	s.collectMembers(members)
	out := make([]MemberCRC, 0, len(members))
	for _, member := range sortedKeys(members) {
		entry, ok := s.findEntry(member)
		if !ok {
			continue
		}
		recorded := cloneU32(entry.Entry().CRC32)
		result := entry.CRC32Result()
		out = append(out, MemberCRC{
			Member:   member,
			Recorded: recorded,
			Checked:  result != nil,
			Matches:  result,
		})
	}
	return out, nil
}

func (s *StreamSource) collectMembers(out map[string]struct{}) {
	switch s.kind {
	case KindImage:
		for _, member := range s.image.bevies {
			out[member] = struct{}{}
		}
		if s.image.indexMember != "" {
			out[s.image.indexMember] = struct{}{}
		}
	case KindMap:
		if s.mapData.dataEntry != nil {
			out[s.mapData.dataEntry.Entry().Path] = struct{}{}
		}
		for _, target := range s.mapData.targets {
			target.collectMembers(out)
		}
	case KindSegment:
		if s.segment != nil {
			out[s.segment.Entry().Path] = struct{}{}
		}
	}
}

func (s *StreamSource) findEntry(member string) (memberEntry, bool) {
	stack := []*StreamSource{s}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch current.kind {
		case KindImage:
			if entry, ok := current.image.entryFor(member); ok {
				return entry, true
			}
		case KindSegment:
			if current.segment != nil && current.segment.Entry().Path == member {
				return current.segment, true
			}
		case KindMap:
			if current.mapData.dataEntry != nil && current.mapData.dataEntry.Entry().Path == member {
				return current.mapData.dataEntry, true
			}
			stack = append(stack, current.mapData.targets...)
		}
	}
	return nil, false
}

func (c *Container) openMember(path string, id source.ID) (memberEntry, error) {
	opened, err := c.reader.OpenEntry(path, id)
	if err != nil {
		return nil, corruptf("AFF4 ZIP member %s could not be opened: %v", path, err)
	}
	entry, ok := opened.(memberEntry)
	if !ok {
		return nil, corruptf("AFF4 ZIP member %s is not a readable entry", path)
	}
	return entry, nil
}

// memberSize resolves candidate member names to the first present entry.
func (c *Container) memberSize(candidates []string) (string, uint64, bool) {
	for _, candidate := range candidates {
		path, err := archive.SanitizeEntryPath(candidate)
		if err != nil {
			continue
		}
		if position, ok := c.inv.index[path]; ok {
			entry := c.inv.entries[position]
			return entry.Path, entry.Size, true
		}
	}
	return "", 0, false
}

func (c *Container) openStreamInner(uri string, visited map[string]struct{}, depth uint32) (*StreamSource, error) {
	stream := c.findStream(uri)
	if stream == nil {
		return nil, invalidf("AFF4 metadata does not declare stream %s", uri)
	}
	if stream.IsFileImage() {
		return nil, unsupportedf("AFF4 stream %s has class FileImage, which is not opened here", uri)
	}
	if stream.IsMap() {
		if depth >= c.limits.MaxMapDepth {
			return nil, limitf("AFF4 map dependency chain at %s is deeper than %d", uri, c.limits.MaxMapDepth)
		}
		if _, seen := visited[uri]; seen {
			return nil, corruptf("AFF4 map dependency cycle at %s", uri)
		}
		visited[uri] = struct{}{}
		built, err := c.buildMapSource(stream, visited, depth+1)
		delete(visited, uri)
		return built, err
	}
	if stream.IsImage() {
		return c.buildImageSource(stream)
	}
	if stream.IsZero() {
		if stream.Size == nil {
			return nil, corruptf("AFF4 stream %s is missing required property aff4:size", uri)
		}
		return &StreamSource{
			id:     c.takeID(),
			parent: c.parent,
			facts:  &c.facts,
			uri:    uri,
			kind:   KindZero,
			size:   *stream.Size,
		}, nil
	}
	if stream.IsSegment() {
		member, memberSize, ok := c.memberSize(segmentMemberCandidates(stream))
		if !ok {
			return nil, corruptf("AFF4 metadata does not declare stream %s", uri)
		}
		entry, err := c.openMember(member, c.takeID())
		if err != nil {
			return nil, err
		}
		size := memberSize
		if stream.Size != nil {
			size = *stream.Size
		}
		return &StreamSource{
			id:      c.takeID(),
			parent:  c.parent,
			facts:   &c.facts,
			uri:     uri,
			kind:    KindSegment,
			size:    size,
			segment: entry,
		}, nil
	}
	return nil, unsupportedf("AFF4 stream %s has class %s, which is not opened here", uri, stream.ClassLabel())
}

func (c *Container) buildImageSource(stream *Stream) (*StreamSource, error) {
	if stream.Size == nil {
		return nil, corruptf("AFF4 stream %s is missing required property aff4:size", stream.URI)
	}
	size := *stream.Size
	if stream.ChunkSize == nil || *stream.ChunkSize == 0 {
		return nil, corruptf("AFF4 stream %s is missing required property aff4:chunkSize", stream.URI)
	}
	chunkSize := *stream.ChunkSize
	if stream.ChunksPerSegment == nil || *stream.ChunksPerSegment == 0 {
		return nil, corruptf("AFF4 stream %s is missing required property aff4:chunksPerSegment", stream.URI)
	}
	chunksPerSegment := *stream.ChunksPerSegment
	if stream.Compression == "" {
		return nil, corruptf("AFF4 stream %s is missing required property aff4:compressionMethod", stream.URI)
	}
	codec, recognized := parseCompression(stream.Compression)
	if !recognized || !codec.hasDecoder() {
		return nil, unsupportedf("AFF4 stream %s declares compression method %s, which has no decoder here",
			stream.URI, stream.Compression)
	}
	if effective := minU64(chunkSize, size); effective > c.limits.MaxChunkBytes {
		return nil, limitf("AFF4 stream %s declares %d-byte chunks, limit is %d",
			stream.URI, effective, c.limits.MaxChunkBytes)
	}

	chunkCount := divCeil(size, chunkSize)
	if chunkCount > c.limits.MaxChunks {
		return nil, limitf("AFF4 image declares %d chunks, limit is %d", chunkCount, c.limits.MaxChunks)
	}
	bevyCount := divCeil(chunkCount, chunksPerSegment)

	var indexEntries [][2]uint32
	indexMember := ""
	opened := make(map[string]memberEntry)
	if member, memberSize, ok := c.memberSize(suffixMemberCandidates(stream.URI, []string{".index", "/index"})); ok {
		indexMember = member
		entry, err := c.openMember(member, c.takeID())
		if err != nil {
			return nil, err
		}
		opened[indexMember] = entry
		needed, ok := mulU64(chunkCount, indexEntryBytes)
		if !ok {
			return nil, corruptf("AFF4 index member %s is %d bytes, the chunk geometry needs more",
				member, memberSize)
		}
		if entry.Len() < needed {
			return nil, corruptf("AFF4 index member %s is %d bytes, the chunk geometry needs %d",
				member, entry.Len(), needed)
		}
		bytes, err := source.ReadVecAt(entry, 0, needed)
		if err != nil {
			return nil, err
		}
		indexEntries = parseIndex(bytes)
	}
	if indexEntries == nil && codec != compressionStored {
		return nil, corruptf("AFF4 image %s needs its .index member to locate compressed chunks", stream.URI)
	}

	capacity := int(minU64(chunkCount, 4096))
	chunks := make([]ChunkInfo, 0, capacity)
	bevies := make([]string, 0, 4)
	bevySeen := make(map[string]struct{})
	for index := uint64(0); index < chunkCount; index++ {
		logicalOffset, ok := mulU64(index, chunkSize)
		if !ok {
			return nil, corruptf("AFF4 chunk %d logical offset overflows", index)
		}
		logicalLen := chunkSize
		if remaining := size - logicalOffset; remaining < logicalLen {
			logicalLen = remaining
		}

		var bevy, memberOffset uint64
		var storedLen *uint64
		if indexEntries != nil {
			bevy = uint64(indexEntries[index][0])
			memberOffset = uint64(indexEntries[index][1])
			if bevy >= bevyCount {
				return nil, corruptf("AFF4 chunk %d index names bevy %d, only %d bevies exist",
					index, bevy, bevyCount)
			}
		} else {
			bevy = index / chunksPerSegment
			memberOffset, ok = mulU64(index%chunksPerSegment, chunkSize)
			if !ok {
				return nil, corruptf("AFF4 chunk %d member offset overflows", index)
			}
			length := logicalLen
			storedLen = &length
		}

		candidates := bevyCandidates(stream.URI, bevy)
		member, memberSize, ok := c.memberSize(candidates)
		if !ok {
			return nil, corruptf("AFF4 chunk %d has no bevy member; tried %s",
				index, strings.Join(candidates, ", "))
		}
		entry, exists := opened[member]
		if !exists {
			openedEntry, err := c.openMember(member, c.takeID())
			if err != nil {
				return nil, err
			}
			entry = openedEntry
			opened[member] = entry
		}

		var stored uint64
		if storedLen != nil {
			if *storedLen != logicalLen {
				return nil, corruptf("AFF4 stored chunk %d is %d bytes for a %d-byte logical chunk",
					index, *storedLen, logicalLen)
			}
			stored = *storedLen
		} else {
			end := memberSize
			if index+1 < chunkCount {
				next := indexEntries[index+1]
				if uint64(next[0]) == bevy {
					end = uint64(next[1])
				}
			}
			if end < memberOffset {
				return nil, corruptf("AFF4 chunk %d index offset %d precedes the previous offset %d",
					index, end, memberOffset)
			}
			if end > memberSize || memberOffset > memberSize {
				return nil, corruptf("AFF4 chunk %d index offset %d is past %s (%d bytes)",
					index, maxU64(end, memberOffset), member, memberSize)
			}
			stored = end - memberOffset
		}
		if memberOffset > memberSize {
			return nil, corruptf("AFF4 chunk %d index offset %d is past %s (%d bytes)",
				index, memberOffset, member, memberSize)
		}

		exact := entry.Method() == 0
		imageOffset := entry.DataOffset()
		if exact {
			imageOffset += memberOffset
		}
		if _, seen := bevySeen[member]; !seen {
			bevySeen[member] = struct{}{}
			bevies = append(bevies, member)
		}
		chunks = append(chunks, ChunkInfo{
			Index:            index,
			Bevy:             bevy,
			Member:           member,
			MemberOffset:     memberOffset,
			StoredLen:        stored,
			LogicalOffset:    logicalOffset,
			LogicalLen:       logicalLen,
			ImageOffset:      imageOffset,
			ImageOffsetExact: exact,
		})
	}

	return &StreamSource{
		id:     c.takeID(),
		parent: c.parent,
		facts:  &c.facts,
		uri:    stream.URI,
		kind:   KindImage,
		size:   size,
		image: &imageReader{
			chunkSize:    chunkSize,
			compression:  codec,
			chunks:       chunks,
			bevies:       bevies,
			indexMember:  indexMember,
			maxCached:    c.limits.MaxCachedChunks,
			maxChunkSize: c.limits.MaxChunkBytes,
			entries:      opened,
			cache:        make(map[uint64][]byte),
		},
	}, nil
}

type span struct {
	start  uint64
	length uint64
}

func (c *Container) buildMapSource(stream *Stream, visited map[string]struct{}, depth uint32) (*StreamSource, error) {
	targetURIs := stream.OrderedTargets()
	if len(targetURIs) == 0 {
		return nil, corruptf("AFF4 map %s declares no target stream", stream.URI)
	}
	targets := make([]*StreamSource, 0, len(targetURIs))
	spans := make([]span, 0, len(targetURIs))
	start := uint64(0)
	for _, uri := range targetURIs {
		target, err := c.openStreamInner(uri, visited, depth)
		if err != nil {
			return nil, err
		}
		spans = append(spans, span{start: start, length: target.Len()})
		start = satAddU64(start, target.Len())
		targets = append(targets, target)
	}
	backingSize := start

	data, dataEntry, err := c.readMapData(stream, visited, depth)
	if err != nil {
		return nil, err
	}
	if len(data)%mapEntryBytes != 0 {
		return nil, corruptf("AFF4 map entry at offset %d is truncated (%d bytes left)",
			uint64(len(data)/mapEntryBytes*mapEntryBytes), len(data)%mapEntryBytes)
	}
	count := len(data) / mapEntryBytes
	if count > c.limits.MaxMapEntries {
		return nil, limitf("AFF4 map has %d entries, limit is %d", count, c.limits.MaxMapEntries)
	}

	capacity := minInt(count, 4096)
	entries := make([]mapEntry, 0, capacity)
	logicalOffset := uint64(0)
	for index := 0; index < count; index++ {
		raw := data[index*mapEntryBytes : (index+1)*mapEntryBytes]
		offset := binary.LittleEndian.Uint64(raw[0:8])
		length := uint64(binary.LittleEndian.Uint32(raw[8:12]))
		if offset > backingSize || length > backingSize-offset {
			return nil, corruptf("AFF4 map entry %d covers [%d, +%d) past the %d-byte backing",
				index, offset, length, backingSize)
		}
		target, targetOffset, ok := locateTarget(spans, offset, length)
		if !ok {
			return nil, corruptf("AFF4 map entry %d [%d, +%d) crosses a target stream boundary",
				index, offset, length)
		}
		entries = append(entries, mapEntry{
			target:        target,
			targetOffset:  targetOffset,
			logicalOffset: logicalOffset,
			length:        length,
		})
		logicalOffset = satAddU64(logicalOffset, length)
	}
	if stream.Size != nil && *stream.Size != logicalOffset {
		return nil, corruptf("AFF4 map %s declares %d bytes but its entries cover %d",
			stream.URI, *stream.Size, logicalOffset)
	}

	return &StreamSource{
		id:     c.takeID(),
		parent: c.parent,
		facts:  &c.facts,
		uri:    stream.URI,
		kind:   KindMap,
		size:   logicalOffset,
		mapData: &mapReader{
			entries:   entries,
			targets:   targets,
			dataEntry: dataEntry,
		},
	}, nil
}

func (c *Container) readMapData(stream *Stream, visited map[string]struct{}, depth uint32) ([]byte, memberEntry, error) {
	stored := ""
	if len(stream.Stored) > 0 {
		stored = stream.Stored[0]
	}
	chosen := ""
	switch {
	case stream.DataStream != "" && stored != "" && stream.DataStream != stored:
		return nil, nil, corruptf(
			"AFF4 map %s names data stream %s through aff4:stored and %s through aff4:dataStream",
			stream.URI, stored, stream.DataStream)
	case stream.DataStream != "":
		chosen = stream.DataStream
	case stored != "" && stored != stream.URI:
		chosen = stored
	default:
		chosen = stream.URI
	}

	if chosen != stream.URI && c.findStream(chosen) != nil {
		sourceStream, err := c.openStreamInner(chosen, visited, depth)
		if err != nil {
			return nil, nil, err
		}
		if sourceStream.Len() > c.limits.MaxMapBytes {
			return nil, nil, limitf("AFF4 map entry stream %s is %d bytes, limit is %d",
				chosen, sourceStream.Len(), c.limits.MaxMapBytes)
		}
		data, err := source.ReadVecAt(sourceStream, 0, sourceStream.Len())
		if err != nil {
			return nil, nil, err
		}
		return data, nil, nil
	}

	member, memberSize, ok := c.memberSize(streamMemberCandidates(chosen, []string{".map", "/map"}))
	if !ok {
		return nil, nil, corruptf("AFF4 map %s has no readable map entry stream", stream.URI)
	}
	if memberSize > c.limits.MaxMapBytes {
		return nil, nil, limitf("AFF4 map entry stream %s is %d bytes, limit is %d",
			member, memberSize, c.limits.MaxMapBytes)
	}
	entry, err := c.openMember(member, c.takeID())
	if err != nil {
		return nil, nil, err
	}
	data, err := source.ReadVecAt(entry, 0, memberSize)
	if err != nil {
		return nil, nil, err
	}
	return data, entry, nil
}

// locateTarget resolves a backing offset to a target and an offset within it.
// ok is false when the range straddles two targets.
func locateTarget(spans []span, offset, length uint64) (int, uint64, bool) {
	if length == 0 {
		for index, current := range spans {
			end := satAddU64(current.start, current.length)
			if offset >= current.start && offset <= end {
				return index, offset - current.start, true
			}
		}
		return 0, 0, false
	}
	for index, current := range spans {
		end := satAddU64(current.start, current.length)
		if offset >= current.start && offset < end {
			if length <= end-offset {
				return index, offset - current.start, true
			}
			return 0, 0, false
		}
	}
	return 0, 0, false
}

func uriBases(uri string) []string {
	bases := []string{uri}
	if rest, ok := strings.CutPrefix(uri, "aff4://"); ok {
		bases = append(bases, rest, "aff4:/"+rest)
	} else if rest, ok := strings.CutPrefix(uri, "aff4:"); ok {
		if !strings.HasPrefix(rest, "/") {
			bases = append(bases, rest)
		}
	}
	sort.Strings(bases)
	return dedupStrings(bases)
}

func bevyCandidates(uri string, bevy uint64) []string {
	bases := uriBases(uri)
	out := make([]string, 0, len(bases))
	for _, base := range bases {
		out = append(out, fmt.Sprintf("%s/%08d", base, bevy))
	}
	return out
}

func streamMemberCandidates(uri string, suffixes []string) []string {
	var out []string
	for _, base := range uriBases(uri) {
		out = append(out, base)
		for _, suffix := range suffixes {
			out = append(out, base+suffix)
		}
	}
	return dedupStrings(out)
}

// suffixMemberCandidates never includes the bare URI: an index is never the
// image member itself.
func suffixMemberCandidates(uri string, suffixes []string) []string {
	var out []string
	for _, base := range uriBases(uri) {
		for _, suffix := range suffixes {
			out = append(out, base+suffix)
		}
	}
	return dedupStrings(out)
}

func segmentMemberCandidates(stream *Stream) []string {
	var out []string
	for _, stored := range stream.Stored {
		out = append(out, uriBases(stored)...)
	}
	out = append(out, uriBases(stream.URI)...)
	return dedupStrings(out)
}

func dedupStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func parseIndex(data []byte) [][2]uint32 {
	out := make([][2]uint32, len(data)/8)
	for index := range out {
		out[index][0] = binary.LittleEndian.Uint32(data[index*8:])
		out[index][1] = binary.LittleEndian.Uint32(data[index*8+4:])
	}
	return out
}

func (s *StreamSource) checkRange(offset, length uint64) error {
	if offset > s.size || length > s.size-offset {
		return source.NewOutOfRange(offset, length, s.size)
	}
	return nil
}

// SourceID implements source.ByteSource.
func (s *StreamSource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *StreamSource) Len() uint64 { return s.size }

// ImageID implements source.ByteSource.
func (s *StreamSource) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *StreamSource) SectorSize() uint32 { return s.parent.SectorSize() }

// Stats implements source.ByteSource.
func (s *StreamSource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *StreamSource) IsEmpty() bool { return s.size == 0 }

// ReadAt implements source.ByteSource.
func (s *StreamSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.size)
	}
	want := uint64(len(buf))
	if want > s.size-offset {
		want = s.size - offset
	}
	if err := s.readInto(offset, buf[:want]); err != nil {
		return 0, err
	}
	s.counters.AddRead(int(want))
	return int(want), nil
}

// ReadAtLossy implements source.ByteSource.  Unreadable bytes are zero-filled
// and counted as corrupt so recovery can continue.
func (s *StreamSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.size)
	}
	want := uint64(len(buf))
	if want > s.size-offset {
		want = s.size - offset
	}
	if _, err := s.ReadAt(offset, buf[:want]); err != nil {
		clear(buf[:want])
		s.counters.AddCorrupt(want)
		return int(want), nil
	}
	return int(want), nil
}

func (s *StreamSource) readInto(offset uint64, buf []byte) error {
	switch s.kind {
	case KindImage:
		reader := s.image
		done := 0
		cursor := offset
		end := offset + uint64(len(buf))
		for cursor < end {
			index := cursor / reader.chunkSize
			info, ok := reader.chunk(index)
			if !ok {
				return corruptf("AFF4 image has no chunk %d", index)
			}
			if cursor < info.LogicalOffset {
				return corruptf("AFF4 image chunk %d starts after the requested offset", index)
			}
			inside := cursor - info.LogicalOffset
			if inside > info.LogicalLen {
				return corruptf("AFF4 image chunk %d is shorter than the requested range", index)
			}
			take := minU64(end-cursor, info.LogicalLen-inside)
			decoded, err := reader.decodeChunk(s, index)
			if err != nil {
				return err
			}
			start := int(inside)
			copy(buf[done:done+int(take)], decoded[start:start+int(take)])
			done += int(take)
			cursor += take
			if take == 0 {
				return corruptf("AFF4 chunk %d has zero length", index)
			}
		}
		return nil

	case KindMap:
		reader := s.mapData
		done := 0
		cursor := offset
		end := offset + uint64(len(buf))
		for cursor < end {
			entry, ok := reader.entryAt(cursor)
			if !ok {
				return corruptf("AFF4 map has no entry for the offset")
			}
			inside := cursor - entry.logicalOffset
			take := minU64(end-cursor, entry.length-inside)
			target := reader.targets[entry.target]
			at := entry.targetOffset + inside
			read, err := target.ReadAt(at, buf[done:done+int(take)])
			if err != nil {
				return err
			}
			done += read
			cursor += uint64(read)
			if read == 0 {
				return corruptf("AFF4 map target returned no bytes")
			}
		}
		return nil

	case KindZero:
		clear(buf)
		return nil

	case KindSegment:
		return source.ReadExactAt(s.segment, offset, buf)
	}
	return corruptf("unknown AFF4 stream kind")
}

// ExtentsInto implements source.ByteSource.
func (s *StreamSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.checkRange(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	switch s.kind {
	case KindImage:
		reader := s.image
		cursor := offset
		end := offset + length
		for cursor < end {
			index := cursor / reader.chunkSize
			info, ok := reader.chunk(index)
			if !ok {
				return out, corruptf("AFF4 image has no chunk %d", index)
			}
			inside := cursor - info.LogicalOffset
			take := minU64(end-cursor, info.LogicalLen-inside)
			if reader.compression == compressionZero {
				out = append(out, source.ParentRange{
					Parent:       s.parent.SourceID(),
					ParentOffset: 0,
					Len:          take,
					Kind:         source.RangeZero,
				})
			} else {
				entry, err := reader.entrySource(info.Member)
				if err != nil {
					return out, err
				}
				var err2 error
				out, err2 = entry.ExtentsInto(info.MemberOffset+inside, take, out)
				if err2 != nil {
					return out, err2
				}
			}
			cursor += take
			if take == 0 {
				return out, corruptf("AFF4 chunk %d has zero length", index)
			}
		}
		return out, nil

	case KindMap:
		reader := s.mapData
		cursor := offset
		end := offset + length
		for cursor < end {
			entry, ok := reader.entryAt(cursor)
			if !ok {
				return out, corruptf("AFF4 map has no entry for the offset")
			}
			inside := cursor - entry.logicalOffset
			take := minU64(end-cursor, entry.length-inside)
			var err error
			out, err = reader.targets[entry.target].ExtentsInto(entry.targetOffset+inside, take, out)
			if err != nil {
				return out, err
			}
			cursor += take
		}
		return out, nil

	case KindZero:
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: 0,
			Len:          length,
			Kind:         source.RangeZero,
		})
		return out, nil

	case KindSegment:
		return s.segment.ExtentsInto(offset, length, out)
	}
	return out, corruptf("unknown AFF4 stream kind")
}

// Extents implements source.ByteSource.
func (s *StreamSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *StreamSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.checkRange(offset, length); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	switch s.kind {
	case KindImage:
		reader := s.image
		var out []source.ImageRange
		cursor := offset
		end := offset + length
		for cursor < end {
			index := cursor / reader.chunkSize
			info, ok := reader.chunk(index)
			if !ok {
				return nil, corruptf("AFF4 image has no chunk %d", index)
			}
			inside := cursor - info.LogicalOffset
			take := minU64(end-cursor, info.LogicalLen-inside)
			if reader.compression == compressionZero {
				out = append(out, source.ImageRange{
					ImageID:     s.parent.ImageID(),
					ImageOffset: 0,
					Len:         take,
					Kind:        source.RangeZero,
				})
			} else {
				entry, err := reader.entrySource(info.Member)
				if err != nil {
					return nil, err
				}
				ranges, err := entry.MapToImage(info.MemberOffset+inside, take)
				if err != nil {
					return nil, err
				}
				out = append(out, ranges...)
			}
			cursor += take
			if take == 0 {
				return nil, corruptf("AFF4 chunk %d has zero length", index)
			}
		}
		return out, nil

	case KindMap:
		reader := s.mapData
		var out []source.ImageRange
		cursor := offset
		end := offset + length
		for cursor < end {
			entry, ok := reader.entryAt(cursor)
			if !ok {
				return nil, corruptf("AFF4 map has no entry for the offset")
			}
			inside := cursor - entry.logicalOffset
			take := minU64(end-cursor, entry.length-inside)
			ranges, err := reader.targets[entry.target].MapToImage(entry.targetOffset+inside, take)
			if err != nil {
				return nil, err
			}
			out = append(out, ranges...)
			cursor += take
		}
		return out, nil

	case KindZero:
		return []source.ImageRange{{
			ImageID:     s.parent.ImageID(),
			ImageOffset: 0,
			Len:         length,
			Kind:        source.RangeZero,
		}}, nil

	case KindSegment:
		return s.segment.MapToImage(offset, length)
	}
	return nil, corruptf("unknown AFF4 stream kind")
}

func maxIntValue() int { return int(^uint(0) >> 1) }

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func cloneU32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

var _ source.ByteSource = (*StreamSource)(nil)
