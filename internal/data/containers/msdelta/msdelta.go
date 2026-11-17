// Package msdelta identifies Microsoft Delta patch containers: PA19, PA30 and
// PA31.
//
// Windows stages component files as binary deltas rather than copies.  A patch
// blob begins with one of the four-byte signatures, or with a four-byte
// little-endian CRC-32 of everything that follows and the signature at byte 4:
//
//	0   u32 little-endian CRC-32 of bytes 4..
//	4   "PA19" | "PA30" | "PA31"
//	..  delta body
//
// PA30 and PA31 bodies are a delta against a base file, LZMS- or
// BSDiff-encoded, so the target bytes are not in the patch.  This reader
// identifies the container and exposes its metadata, so a caller reports "a
// delta patch, not the file" instead of parsing the body as the file's own
// format.  It does not apply the delta: that needs the base file, and
// [Patch.Reconstruct] returns [source.ErrUnsupported] with that reason rather
// than returning bytes from nowhere.
//
// This is a Go port of forensic-core's data/containers/msdelta.rs.  Every
// branch of that reader is ported: identification at byte 4 or byte 0, and
// the optional prefix CRC-32 check.  Payload reconstruction has no counterpart
// in the reference reader and is refused explicitly.
package msdelta

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// The four-byte signatures, as strings for reports and as arrays for parsing.
const (
	SignaturePA19 = "PA19"
	SignaturePA30 = "PA30"
	SignaturePA31 = "PA31"
)

// Kind is which delta format a patch declares.
type Kind uint8

const (
	// KindPA19 is the legacy PA19 form.
	KindPA19 Kind = iota
	// KindPA30 is the PA30 form.
	KindPA30
	// KindPA31 is the PA31 form used by current Windows component staging.
	KindPA31
)

// Magic returns the four bytes that identify the kind.
func (k Kind) Magic() [4]byte {
	switch k {
	case KindPA19:
		return [4]byte{'P', 'A', '1', '9'}
	case KindPA30:
		return [4]byte{'P', 'A', '3', '0'}
	default:
		return [4]byte{'P', 'A', '3', '1'}
	}
}

// Label returns the name a report uses.
func (k Kind) Label() string {
	switch k {
	case KindPA19:
		return SignaturePA19
	case KindPA30:
		return SignaturePA30
	default:
		return SignaturePA31
	}
}

// String returns the label, so the kind prints readably in reports.
func (k Kind) String() string { return k.Label() }

// Identify reports whether head opens a Microsoft Delta patch.
//
// The signature is looked for at byte 4, after the optional CRC-32, and then
// at byte 0.  Eight bytes are enough for both checks; a shorter buffer can
// only be identified when the signature sits at byte 0.  The second result is
// false when head is not a patch this reader can name.
func Identify(head []byte) (Kind, bool) {
	if kind, ok := magicAt(head, 4); ok {
		return kind, true
	}
	return magicAt(head, 0)
}

func magicAt(head []byte, at int) (Kind, bool) {
	if at < 0 || at > len(head)-4 {
		return 0, false
	}
	switch string(head[at : at+4]) {
	case SignaturePA19:
		return KindPA19, true
	case SignaturePA30:
		return KindPA30, true
	case SignaturePA31:
		return KindPA31, true
	default:
		return 0, false
	}
}

// PrefixCRCMatches reports whether the four bytes before the signature are the
// CRC-32 of everything after them.
//
// A patch written with the checksum prefix carries it; a patch without one
// starts with the signature, and this returns false because there is nothing
// to check.  The answer is evidence about how the file was written, not a
// condition for identifying it as a delta.
func PrefixCRCMatches(bytes []byte) bool {
	if len(bytes) < 8 {
		return false
	}
	prefix := bytes[:4]
	rest := bytes[4:]
	if _, ok := magicAt(rest, 0); !ok {
		return false
	}
	return binary.LittleEndian.Uint32(prefix) == foundation.CRC32(rest)
}

// Patch is the metadata of one identified delta container.  Its payload is
// deliberately not exposed: the target bytes live in the base file.
type Patch struct {
	src             source.ByteSource
	kind            Kind
	signatureOffset int
	prefixCRC       bool

	crcOnce    sync.Once
	crcMatches bool
	crcErr     error
}

// Open identifies the patch in src.  It reads at most eight bytes; the body is
// never parsed or applied.
//
// A source that does not open with a recognised signature is refused with
// [source.ErrUnsupported], naming the signatures it looked for.
func Open(src source.ByteSource) (*Patch, error) {
	length := src.Len()
	headLen := length
	if headLen > 8 {
		headLen = 8
	}
	head, err := source.ReadVecAt(src, 0, headLen)
	if err != nil {
		return nil, err
	}
	kind, ok := Identify(head)
	if !ok {
		return nil, &source.Error{
			Kind:   source.ErrUnsupported,
			Reason: fmt.Sprintf("not a Microsoft Delta patch: no PA19, PA30 or PA31 signature in the first %d bytes", len(head)),
		}
	}
	signatureOffset := 0
	if _, ok := magicAt(head, 4); ok {
		signatureOffset = 4
	}
	return &Patch{
		src:             src,
		kind:            kind,
		signatureOffset: signatureOffset,
		prefixCRC:       signatureOffset == 4,
	}, nil
}

// Kind returns the declared delta format.
func (p *Patch) Kind() Kind { return p.kind }

// SignatureOffset is 0 when the blob opens with the signature and 4 when a
// CRC-32 prefix precedes it.
func (p *Patch) SignatureOffset() int { return p.signatureOffset }

// HasPrefixCRC reports whether the signature sits after a checksum prefix.
func (p *Patch) HasPrefixCRC() bool { return p.prefixCRC }

// Len returns the size of the patch container.
func (p *Patch) Len() uint64 { return p.src.Len() }

// Source returns the underlying byte source.
func (p *Patch) Source() source.ByteSource { return p.src }

// PrefixCRCMatches verifies the optional prefix CRC-32 by streaming the source.
//
// The result is cached, so repeated calls read the source once.  A patch
// without a checksum prefix returns (false, nil).  Read failures are returned
// unchanged; they are never turned into a match or a mismatch.
func (p *Patch) PrefixCRCMatches() (bool, error) {
	p.crcOnce.Do(func() {
		if !p.prefixCRC {
			return
		}
		p.crcMatches, p.crcErr = p.verifyPrefixCRC()
	})
	return p.crcMatches, p.crcErr
}

func (p *Patch) verifyPrefixCRC() (bool, error) {
	length := p.src.Len()
	if length < 8 {
		return false, nil
	}
	prefix := make([]byte, 4)
	if err := source.ReadExactAt(p.src, 0, prefix); err != nil {
		return false, err
	}
	crc := uint32(0xFFFFFFFF)
	buf := make([]byte, 64*1024)
	for offset := uint64(4); offset < length; {
		chunk := uint64(len(buf))
		if remaining := length - offset; chunk > remaining {
			chunk = remaining
		}
		if err := source.ReadExactAt(p.src, offset, buf[:chunk]); err != nil {
			return false, err
		}
		crc = foundation.CRC32Seeded(crc, buf[:chunk])
		offset += chunk
	}
	return ^crc == binary.LittleEndian.Uint32(prefix), nil
}

// Reconstruct is the payload entry point that this reader deliberately does
// not implement.  PA30 and PA31 bodies are a delta against a base file; PA19
// is not expanded here either.  It always returns [source.ErrUnsupported]
// naming the patch kind and the missing base file, never fabricated bytes.
func (p *Patch) Reconstruct(id source.ID) (source.ByteSource, error) {
	return nil, &source.Error{
		Kind: source.ErrUnsupported,
		Reason: fmt.Sprintf(
			"the %s delta patch does not contain the target file; reconstructing it needs the base file and a delta applier, which this reader does not implement",
			p.kind.Label()),
	}
}
