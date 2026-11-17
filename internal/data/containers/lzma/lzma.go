// Package lzma decodes the LZMA-alone (.lzma) container into a logical
// ByteSource.
//
// LZMA-alone is the original LZMA container: a 13-byte header followed by one
// raw LZMA1 range-coded stream. The header holds
//
//	byte 0      the lc/lp/pb property: (pb*5 + lp)*9 + lc
//	bytes 1..4  the dictionary size, little-endian uint32
//	bytes 5..12 the uncompressed size, little-endian uint64
//
// An uncompressed size of 0xFFFFFFFFFFFFFFFF means unknown: the stream then
// ends with an end marker (a new match whose distance code is 0xFFFFFFFF).
// With a known size the decoder produces exactly that many bytes and the
// stream carries no end marker.
//
// There is no magic number. The format can only be recognised by its file
// extension (.lzma, and XAR's application/x-lzma payloads), by the caller's
// knowledge of the data, or by validating the header's property byte and
// plausible dictionary size. MatchesSignature performs that structural check
// and is deliberately only a hint: it cannot prove that a byte range really
// is LZMA-alone, and callers that know the container should skip it. Open
// decodes without a signature check for exactly that reason.
//
// The LZMA1 symbol decoder is a from-scratch pure-Go implementation. Every
// probability update, state transition, length/distance tree and dictionary
// copy is bounds-checked; a truncated payload, invalid property byte, match
// that reaches before the start of the output or past the declared dictionary
// size, size disagreement or output-limit violation is an explicit
// ErrCorrupt/ErrUnsupported error, and partial output is never returned.
package lzma

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// MaxDecodedBytes is the default cap on decompressed output (512 MiB).
	MaxDecodedBytes uint64 = 512 * 1024 * 1024
	// MaxCompressedBytes is the default cap on stored bytes read from the
	// parent (256 MiB).
	MaxCompressedBytes uint64 = 256 * 1024 * 1024

	// headerSize is the LZMA-alone header: property byte, dictionary size,
	// uncompressed size.
	headerSize = 13
	// unknownSize marks an unknown uncompressed size; the stream then ends
	// with an end marker.
	unknownSize uint64 = 0xFFFFFFFFFFFFFFFF
)

// Limits bounds one decode.
type Limits struct {
	// MaxDecodedBytes is the maximum decoded bytes. Exceeding it is an error,
	// never a truncation. Zero selects MaxDecodedBytes.
	MaxDecodedBytes uint64
	// MaxCompressedBytes is the maximum stored bytes read from the parent.
	// Zero selects MaxCompressedBytes.
	MaxCompressedBytes uint64
}

// DefaultLimits returns the default caps.
func DefaultLimits() Limits {
	return Limits{MaxDecodedBytes: MaxDecodedBytes, MaxCompressedBytes: MaxCompressedBytes}
}

// Meta records what the decode did.
type Meta struct {
	// CompressedLen is the number of bytes read from the parent, including the
	// LZMA-alone header.
	CompressedLen uint64
	// DecompressedLen is the decoded byte count.
	DecompressedLen uint64
	// DictionarySize is the dictionary size declared by the header.
	DictionarySize uint32
	// LC, LP and PB are the literal-context, literal-position and
	// position-state parameters decoded from the property byte.
	LC, LP, PB uint8
	// DeclaredSize is the uncompressed size stored in the header. It is
	// unknownSize when SizeKnown is false.
	DeclaredSize uint64
	// SizeKnown reports whether the header declared the uncompressed size.
	SizeKnown bool
	// EndMarker reports whether decoding stopped at an end marker (always true
	// for an unknown-size stream).
	EndMarker bool
}

// Source is a decoded LZMA-alone file.
type Source struct {
	id       source.ID
	parent   source.ByteSource
	data     []byte
	meta     Meta
	counters source.Counters
}

// MatchesSignature reports whether head starts with a structurally plausible
// LZMA-alone header.
//
// LZMA-alone has no magic number, so this is only a heuristic: it checks that
// head holds the 13-byte header, that the property byte encodes defined
// lc/lp/pb values, and that the dictionary size is nonzero. Arbitrary bytes
// can satisfy those conditions. Detection of a .lzma file is by extension or
// by the caller's knowledge of the container; Open does not require this
// check.
func MatchesSignature(head []byte) bool {
	if len(head) < headerSize {
		return false
	}
	if !validProperties(head[0]) {
		return false
	}
	return binary.LittleEndian.Uint32(head[1:5]) != 0
}

// Decode decodes one complete LZMA-alone stream. The whole input, header and
// payload, must belong to the stream; trailing bytes are an error.
func Decode(data []byte, limits Limits) ([]byte, error) {
	decoded, _, err := decode(data, limits)
	return decoded, err
}

// Open reads and decodes parent as one LZMA-alone stream. The caller is
// responsible for having identified the container (typically by the .lzma
// extension or a XAR archive's content type); Open validates the header and
// the stream but cannot perform magic-number detection.
func Open(id source.ID, parent source.ByteSource, limits Limits) (*Source, error) {
	limits = normalizeLimits(limits)

	compressedLen := parent.Len()
	if compressedLen < headerSize {
		return nil, corrupt(0, "LZMA-alone file is %d bytes, shorter than its %d-byte header",
			compressedLen, headerSize)
	}
	if compressedLen > limits.MaxCompressedBytes {
		return nil, unsupported("LZMA-alone compressed size %d exceeds the %d-byte limit",
			compressedLen, limits.MaxCompressedBytes)
	}

	stored, err := source.ReadVecAt(parent, 0, compressedLen)
	if err != nil {
		return nil, mapReadError(0, err)
	}
	decoded, meta, err := decode(stored, limits)
	if err != nil {
		return nil, err
	}

	result := &Source{
		id:     id,
		parent: parent,
		data:   decoded,
		meta:   meta,
	}
	result.counters.AddDecompressed(meta.DecompressedLen)
	return result, nil
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

// ExtentsInto implements source.ByteSource. LZMA1 has no random-access
// checkpoints, so any decoded range maps to the whole compressed stream.
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

// decode parses the header and decodes the payload, returning both the output
// and the metadata. Output is only returned when the whole stream is valid.
func decode(data []byte, limits Limits) ([]byte, Meta, error) {
	limits = normalizeLimits(limits)

	if uint64(len(data)) > limits.MaxCompressedBytes {
		return nil, Meta{}, unsupported("LZMA-alone compressed size %d exceeds the %d-byte limit",
			len(data), limits.MaxCompressedBytes)
	}
	if len(data) < headerSize {
		return nil, Meta{}, corrupt(0, "LZMA-alone header is %d bytes, need %d", len(data), headerSize)
	}

	prop := data[0]
	lc, lp, pb, ok := decodeProperties(prop)
	if !ok {
		return nil, Meta{}, corrupt(0, "invalid LZMA property byte %#02x", prop)
	}
	dictSize := binary.LittleEndian.Uint32(data[1:5])
	if dictSize == 0 {
		return nil, Meta{}, corrupt(1, "LZMA dictionary size is zero")
	}
	declared := binary.LittleEndian.Uint64(data[5:headerSize])
	sizeKnown := declared != unknownSize
	if sizeKnown && declared > limits.MaxDecodedBytes {
		return nil, Meta{}, unsupported(
			"decompressed LZMA output of %d bytes exceeds the %d-byte limit",
			declared, limits.MaxDecodedBytes)
	}

	payload := data[headerSize:]
	out, endMarker, err := decodePayload(payload, prop, dictSize, declared, sizeKnown, limits.MaxDecodedBytes)
	if err != nil {
		return nil, Meta{}, err
	}

	meta := Meta{
		CompressedLen:   uint64(len(data)),
		DecompressedLen: uint64(len(out)),
		DictionarySize:  dictSize,
		LC:              uint8(lc),
		LP:              uint8(lp),
		PB:              uint8(pb),
		DeclaredSize:    declared,
		SizeKnown:       sizeKnown,
		EndMarker:       endMarker,
	}
	return out, meta, nil
}

// decodePayload decodes the range-coded LZMA1 stream. With a known size it
// stops after exactly declared bytes (and requires the range coder to be
// finished); with an unknown size it stops at the end marker.
func decodePayload(payload []byte, prop byte, dictSize uint32, declared uint64, sizeKnown bool, maxDecoded uint64) ([]byte, bool, error) {
	var dec lzmaDecoder
	if !dec.setProps(prop) {
		// decode already validated the property byte; keep the invariant
		// explicit so a future caller cannot slip through.
		return nil, false, corrupt(0, "invalid LZMA property byte %#02x", prop)
	}
	rc, err := newRangeDecoder(payload)
	if err != nil {
		return nil, false, corrupt(headerSize, "LZMA range-coded payload is truncated: %v", err)
	}
	dec.rc = rc

	capHint := uint64(len(payload))*4 + 64
	if sizeKnown && declared < capHint {
		capHint = declared
	}
	if capHint > maxDecoded {
		capHint = maxDecoded
	}
	// maxDecoded was clamped to maxInt, so this conversion is safe.
	out := make([]byte, 0, int(capHint))

	endMarker := false
	for {
		if sizeKnown && uint64(len(out)) == declared {
			break
		}

		posState := uint32(len(out)) & dec.posMask
		if rc.bit(&dec.isMatch[dec.state][posState]) == 0 {
			if err := ensureCapacity(&out, 1, maxDecoded); err != nil {
				return nil, false, err
			}
			dec.decodeLiteral(&out)
		} else {
			var length int
			var dist uint32
			if rc.bit(&dec.isRep[dec.state]) != 0 {
				length, dist = dec.decodeRepMatch(posState)
			} else {
				length, dist = dec.decodeMatch(posState)
			}

			if !sizeKnown && dist == endMarkerDistance {
				endMarker = true
				break
			}
			if sizeKnown && uint64(length) > declared-uint64(len(out)) {
				return nil, false, corrupt(headerSize+uint64(rc.pos),
					"LZMA match of %d bytes crosses the declared %d-byte uncompressed size",
					length, declared)
			}
			if err := ensureCapacity(&out, length, maxDecoded); err != nil {
				return nil, false, err
			}
			if err := copyMatch(&out, dist, length, dictSize); err != nil {
				return nil, false, corrupt(headerSize+uint64(rc.pos), "%v", err)
			}
		}

		if rc.err {
			return nil, false, corrupt(headerSize+uint64(rc.pos),
				"LZMA range-coded payload is truncated")
		}
	}

	if rc.err {
		return nil, false, corrupt(headerSize+uint64(rc.pos),
			"LZMA range-coded payload is truncated")
	}
	if err := finishPayload(rc); err != nil {
		return nil, false, corrupt(headerSize+uint64(rc.pos), "LZMA stream: %v", err)
	}
	if uint64(len(out)) != declared && sizeKnown {
		return nil, false, corrupt(headerSize+uint64(rc.pos),
			"LZMA stream declared %d bytes but produced %d", declared, len(out))
	}
	return out, endMarker, nil
}

// ensureCapacity reserves room for add more bytes, enforcing the output limit
// before growing. It never allocates past maxDecoded.
func ensureCapacity(out *[]byte, add int, maxDecoded uint64) error {
	needed := uint64(len(*out)) + uint64(add)
	if needed > maxDecoded {
		return unsupported("decompressed LZMA output exceeds the %d-byte limit", maxDecoded)
	}
	if cap(*out) >= int(needed) {
		return nil
	}
	newCap := maxInt()
	if cap(*out) <= maxInt()/2 {
		newCap = cap(*out) * 2
	}
	if newCap < 64 {
		newCap = 64
	}
	if newCap < int(needed) {
		newCap = int(needed)
	}
	if uint64(newCap) > maxDecoded {
		newCap = int(maxDecoded)
	}
	if newCap < int(needed) {
		newCap = int(needed)
	}
	next := make([]byte, len(*out), newCap)
	copy(next, *out)
	*out = next
	return nil
}

func normalizeLimits(limits Limits) Limits {
	if limits.MaxDecodedBytes == 0 {
		limits.MaxDecodedBytes = MaxDecodedBytes
	}
	if limits.MaxCompressedBytes == 0 {
		limits.MaxCompressedBytes = MaxCompressedBytes
	}
	if limits.MaxDecodedBytes > uint64(maxInt()) {
		limits.MaxDecodedBytes = uint64(maxInt())
	}
	return limits
}

func maxInt() int { return int(^uint(0) >> 1) }

func corrupt(offset uint64, format string, args ...any) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: fmt.Sprintf(format, args...)}
}

func unsupported(format string, args ...any) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(format, args...)}
}

func mapReadError(offset uint64, err error) error {
	switch {
	case errors.Is(err, source.ErrUnexpectedEOF), errors.Is(err, source.ErrOutOfRange):
		return corrupt(offset, "LZMA-alone stream is truncated at offset %d", offset)
	case errors.Is(err, source.ErrIO):
		return source.NewIOError(offset, err)
	default:
		return corrupt(offset, "LZMA-alone stream: %v", err)
	}
}
