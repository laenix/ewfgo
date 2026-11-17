// Package lz4 decodes LZ4 frame streams into a logical ByteSource.
//
// logrotate writes .lz4 rotations (auth.log.4.lz4) when the policy selects
// LZ4, so the data plane treats an LZ4 frame stream like any other rotated
// member. Open decodes the whole stream once and exposes the result
// read-only; it is the source-level counterpart of the Rust engine's
// Lz4Source.
//
// The decoder implements the LZ4 frame format directly (magic 0x184D2204):
// FLG/BD descriptors, the optional content size, the header checksum, block
// independence and block checksums, stored and compressed blocks, the end
// mark and the optional content checksum. Concatenated frames are decoded in
// order; skippable frames are consumed without contributing bytes. xxHash32
// and block decompression are pure Go.
//
// Every checksum the frame carries is verified. A bad header, corrupt or
// truncated block, checksum mismatch, content-size disagreement or output
// limit violation is an explicit error, and partial output is never exposed.
// Legacy frames (magic 0x184C2102) and frames that require a dictionary are
// recognised but refused as unsupported.
package lz4

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxDecodedBytes is the default cap on decompressed output (512 MiB).
const MaxDecodedBytes uint64 = 512 * 1024 * 1024

const (
	// frameMagic is the LZ4 frame format magic (little endian on disk).
	frameMagic uint32 = 0x184D2204
	// legacyMagic is the pre-standard framed magic; it carries no descriptor.
	legacyMagic uint32 = 0x184C2102
	// skippableMin and skippableMax delimit the skippable-frame magic range.
	skippableMin uint32 = 0x184D2A50
	skippableMax uint32 = 0x184D2A5F
)

// Limits bounds one decode.
type Limits struct {
	// MaxDecodedBytes is the maximum decoded bytes. Exceeding it is an error,
	// never a truncation. Zero selects MaxDecodedBytes.
	MaxDecodedBytes uint64
}

// DefaultLimits returns the default cap.
func DefaultLimits() Limits { return Limits{MaxDecodedBytes: MaxDecodedBytes} }

// Meta records what the decode did.
type Meta struct {
	// CompressedLen is the number of bytes read from the parent.
	CompressedLen uint64
	// DecompressedLen is the decoded bytes across every frame.
	DecompressedLen uint64
}

// Source is a decoded LZ4 frame stream.
type Source struct {
	id       source.ID
	parent   source.ByteSource
	data     []byte
	meta     Meta
	counters source.Counters
}

// MatchesSignature reports whether head begins with a frame, legacy-frame or
// skippable-frame magic.
func MatchesSignature(head []byte) bool {
	return len(head) >= 4 && magicMatches(binary.LittleEndian.Uint32(head))
}

func magicMatches(magic uint32) bool {
	return magic == frameMagic || magic == legacyMagic ||
		(magic >= skippableMin && magic <= skippableMax)
}

// Open decodes parent as a sequence of LZ4 frames.
func Open(id source.ID, parent source.ByteSource, limits Limits) (*Source, error) {
	if limits.MaxDecodedBytes == 0 {
		limits.MaxDecodedBytes = MaxDecodedBytes
	}
	compressedLen := parent.Len()
	if compressedLen < 4 {
		return nil, corrupt(0, fmt.Sprintf("LZ4 stream is too short (%d bytes)", compressedLen))
	}
	var head [4]byte
	if err := source.ReadExactAt(parent, 0, head[:]); err != nil {
		return nil, mapReadError(0, err)
	}
	if !MatchesSignature(head[:]) {
		return nil, corrupt(0, "not an LZ4 frame stream")
	}

	reader := &frameReader{src: parent, end: compressedLen}
	decoded := make([]byte, 0)
	for reader.off < reader.end {
		magicAt := reader.off
		magic, err := reader.u32()
		if err != nil {
			return nil, err
		}
		switch {
		case magic == frameMagic:
			if err := decodeFrame(reader, limits.MaxDecodedBytes, &decoded); err != nil {
				return nil, err
			}
		case magic >= skippableMin && magic <= skippableMax:
			if err := skipSkippable(reader); err != nil {
				return nil, err
			}
		case magic == legacyMagic:
			return nil, unsupported("legacy LZ4 frame (magic 0x184C2102) is not supported")
		default:
			return nil, corrupt(magicAt, "trailing bytes are not an LZ4 frame")
		}
	}

	result := &Source{
		id:     id,
		parent: parent,
		data:   decoded,
		meta: Meta{
			CompressedLen:   compressedLen,
			DecompressedLen: uint64(len(decoded)),
		},
	}
	result.counters.AddDecompressed(result.meta.DecompressedLen)
	return result, nil
}

// decodeFrame decodes one standard frame, appending its output to out.
func decodeFrame(reader *frameReader, maxOutput uint64, out *[]byte) error {
	outStart := len(*out)

	flgAt := reader.off
	flg, err := reader.u8()
	if err != nil {
		return err
	}
	bd, err := reader.u8()
	if err != nil {
		return err
	}

	descriptor := []byte{flg, bd}
	version := flg >> 6
	if version != 1 {
		return unsupported(fmt.Sprintf("LZ4 frame version %d is not supported", version))
	}
	if flg&0x02 != 0 {
		return corrupt(flgAt, "LZ4 frame descriptor sets a reserved bit")
	}
	blockIndependent := flg&0x20 != 0
	blockChecksum := flg&0x10 != 0
	hasContentSize := flg&0x08 != 0
	hasContentChecksum := flg&0x04 != 0
	hasDictID := flg&0x01 != 0

	if bd&0x80 != 0 || bd&0x0F != 0 {
		return corrupt(flgAt, "LZ4 frame block descriptor sets reserved bits")
	}
	blockMaxCode := (bd >> 4) & 0x07
	if blockMaxCode < 4 {
		return corrupt(flgAt, "LZ4 frame declares an invalid block maximum size")
	}
	blockMax := uint64(1) << (8 + 2*blockMaxCode)

	var declaredContentSize uint64
	if hasContentSize {
		encoded, err := reader.take(8)
		if err != nil {
			return err
		}
		descriptor = append(descriptor, encoded...)
		declaredContentSize = binary.LittleEndian.Uint64(encoded)
	}
	var dictID uint32
	if hasDictID {
		encoded, err := reader.take(4)
		if err != nil {
			return err
		}
		descriptor = append(descriptor, encoded...)
		dictID = binary.LittleEndian.Uint32(encoded)
	}

	headerChecksum, err := reader.u8()
	if err != nil {
		return err
	}
	if byte(xxh32(descriptor, 0)>>8) != headerChecksum {
		return corrupt(flgAt, "LZ4 frame header checksum mismatch")
	}
	if hasDictID {
		return unsupported(fmt.Sprintf("LZ4 frames with a dictionary ID are not supported (id %#x)", dictID))
	}

	for {
		blockAt := reader.off
		size, err := reader.u32()
		if err != nil {
			return err
		}
		if size == 0 {
			break // end mark
		}

		uncompressed := size&0x80000000 != 0
		blockLen := uint64(size & 0x7FFFFFFF)
		if blockLen > blockMax {
			return corrupt(blockAt, fmt.Sprintf(
				"LZ4 block of %d bytes exceeds the %d-byte block maximum", blockLen, blockMax))
		}
		blockData, err := reader.take(int(blockLen))
		if err != nil {
			return err
		}
		if blockChecksum {
			want, err := reader.u32()
			if err != nil {
				return err
			}
			if got := xxh32(blockData, 0); got != want {
				return corrupt(blockAt, fmt.Sprintf(
					"LZ4 block checksum mismatch: stored %#08x, computed %#08x", want, got))
			}
		}

		var decoded []byte
		if uncompressed {
			decoded = blockData
		} else {
			var dictionary []byte
			if !blockIndependent {
				frameBytes := (*out)[outStart:]
				if len(frameBytes) > maxDictionary {
					frameBytes = frameBytes[len(frameBytes)-maxDictionary:]
				}
				dictionary = frameBytes
			}
			decoded, err = decodeBlock(blockData, dictionary, blockMax)
			if err != nil {
				return corrupt(blockAt, "LZ4 block: "+err.Error())
			}
		}

		if uint64(len(decoded)) > blockMax {
			return corrupt(blockAt, fmt.Sprintf(
				"LZ4 block produced %d bytes, exceeding the %d-byte block maximum", len(decoded), blockMax))
		}
		produced := uint64(len(*out) - outStart)
		if produced > maxOutput || uint64(len(decoded)) > maxOutput-produced {
			return unsupported(fmt.Sprintf(
				"decompressed LZ4 output exceeds the %d-byte limit", maxOutput))
		}
		*out = append(*out, decoded...)
	}

	produced := uint64(len(*out) - outStart)
	if hasContentSize && produced != declaredContentSize {
		return corrupt(reader.off, fmt.Sprintf(
			"LZ4 content size %d does not match the %d decoded bytes", declaredContentSize, produced))
	}
	if hasContentChecksum {
		checksumAt := reader.off
		want, err := reader.u32()
		if err != nil {
			return err
		}
		if got := xxh32((*out)[outStart:], 0); got != want {
			return corrupt(checksumAt, fmt.Sprintf(
				"LZ4 content checksum mismatch: stored %#08x, computed %#08x", want, got))
		}
	}
	return nil
}

// skipSkippable consumes a skippable frame's declared payload. The payload
// carries no data; a declaration that runs past the end of the source is
// corruption, not a short skip.
func skipSkippable(reader *frameReader) error {
	payloadLen, err := reader.u32()
	if err != nil {
		return err
	}
	remaining := uint64(payloadLen)
	if remaining > reader.end-reader.off {
		return corrupt(reader.off, fmt.Sprintf(
			"a skippable LZ4 frame declares %d payload bytes but the file ends first", payloadLen))
	}
	reader.off += remaining
	return nil
}

// frameReader is a bounded sequential cursor over a ByteSource.
type frameReader struct {
	src source.ByteSource
	off uint64
	end uint64
}

func (r *frameReader) read(buf []byte) error {
	if err := source.ReadExactAt(r.src, r.off, buf); err != nil {
		return mapReadError(r.off, err)
	}
	r.off += uint64(len(buf))
	return nil
}

func (r *frameReader) take(n int) ([]byte, error) {
	buf := make([]byte, n)
	if err := r.read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (r *frameReader) u8() (byte, error) {
	var buf [1]byte
	if err := r.read(buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

func (r *frameReader) u32() (uint32, error) {
	var buf [4]byte
	if err := r.read(buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

func mapReadError(offset uint64, err error) error {
	switch {
	case errors.Is(err, source.ErrUnexpectedEOF):
		return corrupt(offset, fmt.Sprintf("LZ4 stream is truncated at offset %d", offset))
	case errors.Is(err, source.ErrIO):
		return source.NewIOError(offset, err)
	default:
		return corrupt(offset, fmt.Sprintf("LZ4 stream: %v", err))
	}
}

// Meta returns the recorded decode metadata.
func (s *Source) Meta() Meta { return s.meta }

// CompressedLen returns the stored stream length.
func (s *Source) CompressedLen() uint64 { return s.meta.CompressedLen }

// Bytes returns the decoded bytes.
func (s *Source) Bytes() []byte { return s.data }

// SourceID implements source.ByteSource.
func (s *Source) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *Source) Len() uint64 { return s.meta.DecompressedLen }

// ImageID implements source.ByteSource.
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *Source) SectorSize() uint32 { return s.parent.SectorSize() }

// IsEmpty implements source.ByteSource.
func (s *Source) IsEmpty() bool { return len(s.data) == 0 }

// Stats implements source.ByteSource.
func (s *Source) Stats() source.Stats { return s.counters.Snapshot() }

// ReadAt implements source.ByteSource.
func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.Len() {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.Len())
	}
	n := copy(buf, s.data[offset:])
	s.counters.AddRead(n)
	return n, nil
}

// ReadAtLossy implements source.ByteSource.
func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

// ExtentsInto implements source.ByteSource. Provenance is coarse: any decoded
// range maps to the whole compressed stream in the parent.
func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.Len() || length > s.Len()-offset {
		return out, source.NewOutOfRange(offset, length, s.Len())
	}
	if length > 0 {
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: 0,
			Len:          s.meta.CompressedLen,
			Kind:         source.RangeData,
		})
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.Len() || length > s.Len()-offset {
		return nil, source.NewOutOfRange(offset, length, s.Len())
	}
	if length == 0 {
		return nil, nil
	}
	return s.parent.MapToImage(0, s.meta.CompressedLen)
}

var _ source.ByteSource = (*Source)(nil)

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}
