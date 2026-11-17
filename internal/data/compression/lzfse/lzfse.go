// Package lzfse decodes Apple's LZFSE compression format.
//
// LZFSE is the entropy-coded LZ format Apple uses in APFS transparent
// compression (decmpfs types 11 and 12), in UDIF disk images (DMG runs of type
// 0x80000007) and in LZVN/LZFSE command line tools. A stream is a sequence of
// self-describing blocks, each introduced by a four byte magic:
//
//	bvx-  an uncompressed block: u32 little-endian byte count, then bytes
//	bvxn  an LZVN-compressed block: u32 raw size, u32 payload size, payload
//	bvx1  an LZFSE block with uncompressed (v1) frequency tables
//	bvx2  an LZFSE block with compressed (v2) frequency tables
//	bvx$  end of stream
//
// The compressed blocks carry two independent finite-state entropy (FSE)
// streams: literals, and L(iteral length)/M(atch length)/D(istance) triples.
// Match distances are packed with a zero-distance convention (zero means
// "reuse the previous non-zero distance"), matches may overlap their own
// output, and the decoder is bounded by the header's declared raw size so a
// corrupt stream cannot be inflated past the caller's limit.
//
// The decoder is pure Go and has no dependencies. It is a from-scratch Go
// implementation written against the block layout and FSE state machine of
// Apple's liblzfse; see the package tests for the reference-generated vectors
// used to validate it.
//
// Failure is always explicit: Decode returns either the complete decoded
// stream or an error, never partial or guessed bytes. Errors wrap one of
// [ErrCorrupt], [ErrUnsupported], [ErrUnexpectedEOF] or [ErrLimit] so callers
// can classify them with errors.Is.
package lzfse

import (
	"errors"
	"fmt"
	"io"
)

// DefaultMaxOutputBytes bounds decoded output when Limits leaves the field
// unset. It is large enough for the biggest decmpfs file this project
// materializes, yet small enough that a corrupt header cannot exhaust memory.
const DefaultMaxOutputBytes uint64 = 512 << 20 // 512 MiB

// MaxSourceBytes bounds the input [DecodeSource] will buffer before decoding.
// Decode operates on a caller-owned slice and has no separate input bound.
const MaxSourceBytes uint64 = 1 << 30 // 1 GiB

// Sentinel error kinds. A returned *Error unwraps to exactly one of these.
var (
	// ErrCorrupt reports a malformed stream: bad magic, bad table, state or
	// distance, inconsistent sizes, or bytes after the end marker.
	ErrCorrupt = errors.New("lzfse: corrupt stream")
	// ErrUnsupported reports a block or stream variant this decoder does not
	// implement. Unknown bvx-family magics are reported this way; magics
	// outside the family are corruption.
	ErrUnsupported = errors.New("lzfse: unsupported stream")
	// ErrUnexpectedEOF reports input that ends before the stream completes.
	ErrUnexpectedEOF = errors.New("lzfse: unexpected end of input")
	// ErrLimit reports decoded output or buffered input above the configured
	// bound.
	ErrLimit = errors.New("lzfse: limit exceeded")
)

// Error is a structured decode failure. Kind is one of the sentinels above,
// Offset is the stream byte at which the problem was detected (zero when the
// whole stream is at fault), and Detail describes the specific rule violated.
type Error struct {
	Kind   error
	Offset int
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%v (at byte %d)", e.Kind, e.Offset)
	}
	return fmt.Sprintf("%v (at byte %d): %s", e.Kind, e.Offset, e.Detail)
}

// Unwrap returns the sentinel kind so errors.Is works.
func (e *Error) Unwrap() error { return e.Kind }

func corruptAt(off int, format string, args ...any) error {
	return &Error{Kind: ErrCorrupt, Offset: off, Detail: fmt.Sprintf(format, args...)}
}

func eofAt(off int, format string, args ...any) error {
	return &Error{Kind: ErrUnexpectedEOF, Offset: off, Detail: fmt.Sprintf(format, args...)}
}

func unsupportedAt(off int, format string, args ...any) error {
	return &Error{Kind: ErrUnsupported, Offset: off, Detail: fmt.Sprintf(format, args...)}
}

func limitAt(off int, format string, args ...any) error {
	return &Error{Kind: ErrLimit, Offset: off, Detail: fmt.Sprintf(format, args...)}
}

// Limits bounds decoding. The zero value selects DefaultMaxOutputBytes.
type Limits struct {
	// MaxOutputBytes is the largest decoded stream accepted. A stream that
	// declares or produces more fails with ErrLimit. Zero means
	// DefaultMaxOutputBytes.
	MaxOutputBytes uint64
}

func (l Limits) maxOutput() uint64 {
	if l.MaxOutputBytes == 0 {
		return DefaultMaxOutputBytes
	}
	return l.MaxOutputBytes
}

// Block magics.
var (
	magicEOS = [4]byte{'b', 'v', 'x', '$'}
	magicRaw = [4]byte{'b', 'v', 'x', '-'}
	magicVN  = [4]byte{'b', 'v', 'x', 'n'}
	magicV1  = [4]byte{'b', 'v', 'x', '1'}
	magicV2  = [4]byte{'b', 'v', 'x', '2'}
)

func magicAt(src []byte, at int) [4]byte {
	return [4]byte{src[at], src[at+1], src[at+2], src[at+3]}
}

// MatchesSignature reports whether src starts with an LZFSE block magic. It is
// a cheap detection check; a true result does not guarantee a decodable stream.
func MatchesSignature(src []byte) bool {
	if len(src) < 4 {
		return false
	}
	m := magicAt(src, 0)
	return m == magicEOS || m == magicRaw || m == magicVN || m == magicV1 || m == magicV2
}

// Decode decompresses one complete LZFSE stream.
//
// The returned slice is nil exactly when the error is non-nil. Decode supports
// v1 and v2 compressed blocks, uncompressed blocks, LZVN blocks and the end
// marker, in any order, and rejects trailing bytes after the end marker.
func Decode(src []byte, limits Limits) ([]byte, error) {
	d := decoder{src: src, limit: limits.maxOutput()}
	if err := d.run(); err != nil {
		return nil, err
	}
	return d.out, nil
}

// DecodeSource reads all of src, bounded by MaxSourceBytes, and decodes it as
// one stream. Read errors are returned wrapped but are not classified as one of
// the decode sentinels; an oversized source fails with ErrLimit.
func DecodeSource(src io.Reader, limits Limits) ([]byte, error) {
	if src == nil {
		return nil, &Error{Kind: ErrCorrupt, Detail: "nil source"}
	}
	data, err := io.ReadAll(io.LimitReader(src, int64(MaxSourceBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("lzfse: reading source: %w", err)
	}
	if uint64(len(data)) > MaxSourceBytes {
		return nil, limitAt(0, "source exceeds the %d byte input bound", MaxSourceBytes)
	}
	return Decode(data, limits)
}

type decoder struct {
	src      []byte
	pos      int
	limit    uint64
	out      []byte
	lastDist uint32 // persists across compressed blocks, as in liblzfse
}

func (d *decoder) run() error {
	for {
		if len(d.src)-d.pos < 4 {
			return eofAt(d.pos, "stream ends without an end marker")
		}
		magic := magicAt(d.src, d.pos)
		switch magic {
		case magicEOS:
			if d.pos+4 != len(d.src) {
				return corruptAt(d.pos+4, "%d trailing bytes after the end marker", len(d.src)-(d.pos+4))
			}
			d.pos += 4
			return nil
		case magicRaw:
			if err := d.uncompressedBlock(); err != nil {
				return err
			}
		case magicVN:
			if err := d.lzvnBlock(); err != nil {
				return err
			}
		case magicV1, magicV2:
			if err := d.compressedBlock(magic == magicV1); err != nil {
				return err
			}
		default:
			// A bvx-family magic we do not know is a plausible future
			// variant; anything else is simply not LZFSE.
			if d.src[d.pos] == 'b' && d.src[d.pos+1] == 'v' && d.src[d.pos+2] == 'x' {
				return unsupportedAt(d.pos, "block magic %q", magic[:])
			}
			return corruptAt(d.pos, "bad block magic %q", magic[:])
		}
	}
}

func (d *decoder) checkOutput(off int, additional uint64) error {
	if additional > maxIntValue() {
		return limitAt(off, "block of %d bytes exceeds the platform address space", additional)
	}
	if additional > d.limit || uint64(len(d.out)) > d.limit-additional {
		return limitAt(off, "decoded output would exceed the %d byte limit", d.limit)
	}
	return nil
}

func maxIntValue() uint64 { return uint64(^uint(0) >> 1) }

func (d *decoder) uncompressedBlock() error {
	const header = 8
	if len(d.src)-d.pos < header {
		return eofAt(d.pos, "truncated uncompressed block header")
	}
	n := readU32(d.src, d.pos+4)
	if uint64(len(d.src)-(d.pos+header)) < uint64(n) {
		return eofAt(d.pos, "uncompressed block declares %d bytes with only %d available",
			n, len(d.src)-(d.pos+header))
	}
	if err := d.checkOutput(d.pos, uint64(n)); err != nil {
		return err
	}
	d.out = append(d.out, d.src[d.pos+header:d.pos+header+int(n)]...)
	d.pos += header + int(n)
	return nil
}

func (d *decoder) lzvnBlock() error {
	const header = 12
	if len(d.src)-d.pos < header {
		return eofAt(d.pos, "truncated LZVN block header")
	}
	rawLen := readU32(d.src, d.pos+4)
	payloadLen := readU32(d.src, d.pos+8)
	if payloadLen < 8 {
		return corruptAt(d.pos+8, "LZVN block payload is %d bytes, shorter than its end marker", payloadLen)
	}
	start := d.pos + header
	if uint64(len(d.src)-start) < uint64(payloadLen) {
		return eofAt(d.pos, "LZVN block declares %d payload bytes with only %d available",
			payloadLen, len(d.src)-start)
	}
	if err := d.checkOutput(d.pos, uint64(rawLen)); err != nil {
		return err
	}
	decoded, err := lzvnDecode(d.src[start:start+int(payloadLen)], rawLen)
	if err != nil {
		return &Error{Kind: ErrCorrupt, Offset: d.pos, Detail: fmt.Sprintf("LZVN block: %v", err)}
	}
	d.out = append(d.out, decoded...)
	d.pos = start + int(payloadLen)
	return nil
}

func (d *decoder) compressedBlock(v1 bool) error {
	block, err := parseCompressedHeader(d.src[d.pos:], d.pos, v1)
	if err != nil {
		return err
	}
	if err := d.checkOutput(d.pos, uint64(block.nRaw)); err != nil {
		return err
	}
	tables := buildTables(&block.weights)

	base := d.pos + block.headerSize
	// The literal bit stream has no stored pad of its own: the decoder reuses
	// the last eight bytes of the weight payload as the zero lookahead pad.
	// The reader therefore starts eight bytes before the literal payload and
	// still ends exactly at the LMD payload.
	literalData := d.src[base-8 : base+int(block.litPayload)]
	lmdData := d.src[base+int(block.litPayload) : base+int(block.litPayload)+int(block.lmdPayload)]

	literals, err := decodeLiterals(literalData, block, tables, base)
	if err != nil {
		return err
	}
	lmds, err := decodeLMDs(lmdData, block, tables, base+int(block.litPayload))
	if err != nil {
		return err
	}
	if err := d.apply(literals, lmds, block.nRaw, d.pos); err != nil {
		return err
	}
	d.pos = base + int(block.litPayload) + int(block.lmdPayload)
	return nil
}

// readU32 reads a little-endian uint32; callers have bounds-checked the slice.
func readU32(src []byte, at int) uint32 {
	return uint32(src[at]) | uint32(src[at+1])<<8 | uint32(src[at+2])<<16 | uint32(src[at+3])<<24
}

func readU64(src []byte, at int) uint64 {
	return uint64(readU32(src, at)) | uint64(readU32(src, at+4))<<32
}

func readU16(src []byte, at int) uint16 {
	return uint16(src[at]) | uint16(src[at+1])<<8
}
