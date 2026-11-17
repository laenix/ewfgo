// Package androidsparse expands Android sparse images (`img2simg`/`simg2img`)
// into the logical block device they describe. It is a pure-Go port of
// forensic-core's data/containers/android_sparse.rs.
package androidsparse

import (
	"fmt"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Magic is the little-endian sparse signature.
	Magic uint32 = 0xED26FF3A
	// FileHeaderBytes and ChunkHeaderBytes are the version-1 struct sizes.
	FileHeaderBytes  = 28
	ChunkHeaderBytes = 12
	// MaxBlockSize and MaxChunks bound a corrupt header.
	MaxBlockSize uint32 = 1024 * 1024
	MaxChunks    uint32 = 1000000

	// Chunk types.
	ChunkRaw      uint16 = 0xCAC1
	ChunkFill     uint16 = 0xCAC2
	ChunkDontCare uint16 = 0xCAC3
	ChunkCRC32    uint16 = 0xCAC4
)

// Info is the header plus a summary of the chunk list.
type Info struct {
	MajorVersion     uint16
	MinorVersion     uint16
	BlockSize        uint32
	TotalBlocks      uint32
	TotalChunks      uint32
	ImageChecksum    uint32
	ChecksumVerified bool
	RawChunks        int
	FillChunks       int
	DontCareChunks   int
	CRCChunks        int
	CRCPoints        []CRC32Point
	ExpandedLen      uint64
}

// CRC32Point is one declared checkpoint.
type CRC32Point struct {
	Offset   uint64
	Expected uint32
}

type segmentKind uint8

const (
	segRaw segmentKind = iota
	segFill
	segHole
)

type segment struct {
	logical    uint64
	length     uint64
	kind       segmentKind
	fileOffset uint64
	pattern    [4]byte
}

// Source is the expanded block device.
type Source struct {
	id       source.ID
	parent   source.ByteSource
	info     Info
	segments []segment
	counters source.Counters
}

// MatchesSignature reports whether head begins with the sparse magic.
func MatchesSignature(head []byte) bool {
	return len(head) >= 4 && le32(head, 0) == Magic
}

// Open parses the header and chunk list around parent.
func Open(id source.ID, parent source.ByteSource) (*Source, error) {
	fileLen := parent.Len()
	if fileLen < FileHeaderBytes {
		return nil, corrupt(0, fmt.Sprintf("the file is %d bytes, shorter than the %d-byte sparse header", fileLen, FileHeaderBytes))
	}
	header, err := source.ReadVecAt(parent, 0, FileHeaderBytes)
	if err != nil {
		return nil, err
	}
	if le32(header, 0) != Magic {
		return nil, unsupported("not an Android sparse image (bad signature)")
	}
	major := le16(header, 4)
	minor := le16(header, 6)
	fileHdrSz := le16(header, 8)
	chunkHdrSz := le16(header, 10)
	blockSize := le32(header, 12)
	totalBlocks := le32(header, 16)
	totalChunks := le32(header, 20)
	imageChecksum := le32(header, 24)
	if major != 1 {
		return nil, unsupported(fmt.Sprintf("unsupported Android sparse major version %d; only version 1 is read", major))
	}
	if fileHdrSz != FileHeaderBytes {
		return nil, unsupported(fmt.Sprintf("unsupported Android sparse file header size %d; only %d is read", fileHdrSz, FileHeaderBytes))
	}
	if chunkHdrSz != ChunkHeaderBytes {
		return nil, unsupported(fmt.Sprintf("unsupported Android sparse chunk header size %d; only %d is read", chunkHdrSz, ChunkHeaderBytes))
	}
	if blockSize == 0 {
		return nil, corrupt(12, "the sparse header declares a zero block size")
	}
	if blockSize%4 != 0 {
		return nil, corrupt(12, fmt.Sprintf("the sparse block size %d is not a multiple of 4", blockSize))
	}
	if blockSize > MaxBlockSize {
		return nil, corrupt(12, fmt.Sprintf("the sparse block size %d exceeds the %d-byte limit", blockSize, MaxBlockSize))
	}
	if totalChunks > MaxChunks {
		return nil, corrupt(20, fmt.Sprintf("the sparse header declares %d chunks, above the %d limit", totalChunks, MaxChunks))
	}
	expandedLen := uint64(totalBlocks) * uint64(blockSize)
	if totalBlocks != 0 && expandedLen/uint64(totalBlocks) != uint64(blockSize) {
		return nil, corrupt(16, "expanded length overflows")
	}

	info := Info{
		MajorVersion: major, MinorVersion: minor, BlockSize: blockSize,
		TotalBlocks: totalBlocks, TotalChunks: totalChunks,
		ImageChecksum: imageChecksum, ExpandedLen: expandedLen,
	}
	var segments []segment
	var blocks uint64
	offset := uint64(FileHeaderBytes)
	parsed := uint32(0)
	for offset < fileLen && parsed < totalChunks {
		index := parsed
		if fileLen-offset < ChunkHeaderBytes {
			return nil, corrupt(offset, fmt.Sprintf("chunk %d is shorter than a %d-byte header", index, ChunkHeaderBytes))
		}
		chunk, err := source.ReadVecAt(parent, offset, ChunkHeaderBytes)
		if err != nil {
			return nil, err
		}
		chunkType := le16(chunk, 0)
		chunkSz := le32(chunk, 4)
		totalSz := le32(chunk, 8)
		if uint64(totalSz) < ChunkHeaderBytes {
			return nil, corrupt(offset, fmt.Sprintf("chunk %d declares %d bytes, less than its %d-byte header", index, totalSz, ChunkHeaderBytes))
		}
		if uint64(totalSz) > fileLen-offset {
			return nil, corrupt(offset, fmt.Sprintf("chunk %d [%d, +%d) reaches past the %d-byte file", index, offset, totalSz, fileLen))
		}
		payloadOffset := offset + ChunkHeaderBytes
		payloadLen := uint64(totalSz) - ChunkHeaderBytes
		logical := blocks * uint64(blockSize)
		chunkBlocks := uint64(chunkSz)

		switch chunkType {
		case ChunkRaw:
			expected := chunkBlocks * uint64(blockSize)
			if payloadLen != expected {
				return nil, corrupt(offset, fmt.Sprintf("raw chunk %d declares %d payload bytes but its %d output blocks need %d",
					index, payloadLen, chunkBlocks, expected))
			}
			info.RawChunks++
			segments = pushSegment(segments, segment{logical: logical, length: expected, kind: segRaw, fileOffset: payloadOffset})
		case ChunkFill:
			if payloadLen != 4 {
				return nil, corrupt(offset, fmt.Sprintf("fill chunk %d carries %d bytes; a fill pattern is 4 bytes", index, payloadLen))
			}
			pattern, err := source.ReadVecAt(parent, payloadOffset, 4)
			if err != nil {
				return nil, err
			}
			length := chunkBlocks * uint64(blockSize)
			var fill [4]byte
			copy(fill[:], pattern)
			info.FillChunks++
			segments = pushSegment(segments, segment{logical: logical, length: length, kind: segFill, pattern: fill})
		case ChunkDontCare:
			if payloadLen != 0 {
				return nil, corrupt(offset, fmt.Sprintf("don't-care chunk %d carries %d bytes it does not use", index, payloadLen))
			}
			length := chunkBlocks * uint64(blockSize)
			info.DontCareChunks++
			segments = pushSegment(segments, segment{logical: logical, length: length, kind: segHole})
		case ChunkCRC32:
			if payloadLen != 4 {
				return nil, corrupt(offset, fmt.Sprintf("CRC32 chunk %d carries %d bytes; a CRC32 is 4 bytes", index, payloadLen))
			}
			if chunkSz != 0 {
				return nil, corrupt(offset, fmt.Sprintf("CRC32 chunk %d declares %d output blocks; it produces none", index, chunkSz))
			}
			expected, err := source.ReadVecAt(parent, payloadOffset, 4)
			if err != nil {
				return nil, err
			}
			info.CRCChunks++
			info.CRCPoints = append(info.CRCPoints, CRC32Point{Offset: logical, Expected: le32(expected, 0)})
		default:
			return nil, corrupt(offset, fmt.Sprintf("chunk %d has unknown type 0x%04X", index, chunkType))
		}

		blocks += chunkBlocks
		if blocks > uint64(totalBlocks) {
			return nil, corrupt(offset, fmt.Sprintf("chunk %d brings the output to %d blocks, past the header's %d", index, blocks, totalBlocks))
		}
		parsed++
		offset += uint64(totalSz)
	}
	if parsed != totalChunks {
		return nil, corrupt(0, fmt.Sprintf("the header declares %d chunks but %d were read", totalChunks, parsed))
	}
	if blocks != uint64(totalBlocks) {
		return nil, corrupt(0, fmt.Sprintf("the chunks expand to %d blocks but the header declares %d", blocks, totalBlocks))
	}
	if len(segments) > 0 {
		last := segments[len(segments)-1]
		if last.logical+last.length != expandedLen {
			return nil, corrupt(0, fmt.Sprintf("the chunks expand to %d bytes but the header declares %d", last.logical+last.length, expandedLen))
		}
	}
	return &Source{id: id, parent: parent, info: info, segments: segments}, nil
}

func pushSegment(out []segment, s segment) []segment {
	if s.length == 0 {
		return out
	}
	if len(out) > 0 {
		last := &out[len(out)-1]
		if last.logical+last.length == s.logical {
			switch {
			case last.kind == segHole && s.kind == segHole:
				last.length += s.length
				return out
			case last.kind == segFill && s.kind == segFill && last.pattern == s.pattern:
				last.length += s.length
				return out
			case last.kind == segRaw && s.kind == segRaw && last.fileOffset+last.length == s.fileOffset:
				last.length += s.length
				return out
			}
		}
	}
	return append(out, s)
}

// Info returns the header and chunk summary.
func (s *Source) Info() Info { return s.info }

// Segments returns the expanded runs as (logical, length, kind).
func (s *Source) Segments() []struct {
	Logical uint64
	Length  uint64
	Kind    string
} {
	out := make([]struct {
		Logical uint64
		Length  uint64
		Kind    string
	}, len(s.segments))
	for i, seg := range s.segments {
		kind := "raw"
		if seg.kind == segFill {
			kind = "fill"
		} else if seg.kind == segHole {
			kind = "dont-care"
		}
		out[i] = struct {
			Logical uint64
			Length  uint64
			Kind    string
		}{seg.logical, seg.length, kind}
	}
	return out
}

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.info.ExpandedLen }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *Source) SectorSize() uint32      { return 512 }
func (s *Source) IsEmpty() bool           { return s.info.ExpandedLen == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) checkRange(offset, length uint64) error {
	if offset > s.info.ExpandedLen || length > s.info.ExpandedLen-offset {
		return source.NewOutOfRange(offset, length, s.info.ExpandedLen)
	}
	return nil
}

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf)
}

func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf)
}

func (s *Source) readInner(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.info.ExpandedLen {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.info.ExpandedLen)
	}
	want := int(minU64(s.info.ExpandedLen-offset, uint64(len(buf))))
	end := offset + uint64(want)
	index := sort.Search(len(s.segments), func(i int) bool {
		return s.segments[i].logical+s.segments[i].length > offset
	})
	done := 0
	for index < len(s.segments) {
		seg := &s.segments[index]
		if seg.logical >= end {
			break
		}
		start := maxU64(seg.logical, offset)
		stop := minU64(seg.logical+seg.length, end)
		at := int(start - offset)
		length := int(stop - start)
		switch seg.kind {
		case segRaw:
			physical := seg.fileOffset + (start - seg.logical)
			n, err := s.parent.ReadAt(physical, buf[at:at+length])
			if n > 0 {
				if at+n > done {
					done = at + n
				}
			}
			if err != nil {
				return 0, err
			}
			if n < length {
				s.counters.AddRead(done)
				return done, nil
			}
		case segFill:
			phase := start - seg.logical
			for i := 0; i < length; i++ {
				buf[at+i] = seg.pattern[(phase+uint64(i))&3]
			}
			if at+length > done {
				done = at + length
			}
		case segHole:
			clear(buf[at : at+length])
			if at+length > done {
				done = at + length
			}
		}
		index++
	}
	s.counters.AddRead(done)
	return done, nil
}

func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.checkRange(offset, length); err != nil {
		return out, err
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	for i := range s.segments {
		seg := &s.segments[i]
		if seg.logical+seg.length <= offset || seg.logical >= end {
			continue
		}
		start := maxU64(seg.logical, offset)
		stop := minU64(seg.logical+seg.length, end)
		switch seg.kind {
		case segRaw:
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: seg.fileOffset + (start - seg.logical),
				Len: stop - start, Kind: source.RangeData,
			})
		case segFill:
			out = append(out, source.ParentRange{
				Parent: s.id, ParentOffset: start, Len: stop - start, Kind: source.RangeDerived,
			})
		case segHole:
			out = append(out, source.ParentRange{
				Parent: s.id, ParentOffset: start, Len: stop - start, Kind: source.RangeHole,
			})
		}
	}
	return out, nil
}

func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if err := s.checkRange(offset, length); err != nil {
		return nil, err
	}
	var out []source.ImageRange
	end := offset + length
	for i := range s.segments {
		seg := &s.segments[i]
		if seg.logical+seg.length <= offset || seg.logical >= end {
			continue
		}
		start := maxU64(seg.logical, offset)
		stop := minU64(seg.logical+seg.length, end)
		switch seg.kind {
		case segRaw:
			mapped, err := s.parent.MapToImage(seg.fileOffset+(start-seg.logical), stop-start)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
		case segFill:
			out = append(out, source.ImageRange{
				ImageID: s.parent.ImageID(), ImageOffset: 0, Len: stop - start, Kind: source.RangeDerived,
			})
		case segHole:
			out = append(out, source.ImageRange{
				ImageID: s.parent.ImageID(), ImageOffset: 0, Len: stop - start, Kind: source.RangeHole,
			})
		}
	}
	return out, nil
}

var _ source.ByteSource = (*Source)(nil)

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func le16(bytes []byte, at int) uint16 { return uint16(bytes[at]) | uint16(bytes[at+1])<<8 }
func le32(bytes []byte, at int) uint32 {
	return uint32(bytes[at]) | uint32(bytes[at+1])<<8 | uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
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
