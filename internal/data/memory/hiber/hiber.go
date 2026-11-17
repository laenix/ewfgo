// Package hiber reads the page-zero header of a Windows hibernation file
// (`hiberfil.sys`).
//
// Page zero holds PO_MEMORY_IMAGE. Its first four bytes are the signature and
// the next fields are layout-dependent:
//
//	| Signature   | Meaning                                | Offset 4      |
//	| hibr        | XP/2003-or-earlier legacy path         | Version (u32) |
//	| HIBR        | Vista-or-later reset path              | ImageType     |
//	| RSTR        | restoration/resume; may mark an error  | not substantiated |
//	| wake / WAKE | invalid hibernation file               | not substantiated |
//
// Across the documented legacy and Vista+ tables, CheckSum is at 0x08 and the
// self length (LengthSelf/Size) is at 0x0c, so those two fields are decoded for
// `hibr` and `HIBR`. `hibr` additionally decodes Version at 0x04 and `HIBR`
// decodes ImageType at 0x04.
//
// The hibernation header is not a published Windows SDK structure. The
// reverse-engineered tables disagree on PageSelf width, PageSize/ImageType
// offsets and per-build header sizes, and no field identifies build or
// bitness. This reader therefore decodes only the four stable fields, lists
// the deeper fields it refuses by name, and exposes Field/Decompress returning
// ErrUnsupported rather than inventing offsets. Nothing is decompressed and no
// page map or memory content is read.
//
// This package is a pure-Go port of forensic-core's data/memory/hiber.rs.
package hiber

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Magic is the legacy XP/2003 signature on disk.
var Magic = [4]byte{'h', 'i', 'b', 'r'}

// MagicVista is the Vista-or-later signature on disk.
var MagicVista = [4]byte{'H', 'I', 'B', 'R'}

// MagicRestore is the restoration/resume-state signature.
var MagicRestore = [4]byte{'R', 'S', 'T', 'R'}

// MagicWake is the lower-case "invalid hibernation file" signature.
var MagicWake = [4]byte{'w', 'a', 'k', 'e'}

// MagicWakeUpper is the upper-case "invalid hibernation file" signature.
var MagicWakeUpper = [4]byte{'W', 'A', 'K', 'E'}

// CommonFieldsBytes is the bytes needed for the four stable fields.
const CommonFieldsBytes uint64 = 16

// Field offsets common to the documented layouts.
const (
	// SignatureOffset is the offset of the signature.
	SignatureOffset = 0x00
	// VersionOrImageTypeOffset is Version (legacy) or ImageType (Vista+).
	VersionOrImageTypeOffset = 0x04
	// ChecksumOffset is CheckSum in both substantiated layouts.
	ChecksumOffset = 0x08
	// LengthSelfOffset is LengthSelf/Size in both substantiated layouts.
	LengthSelfOffset = 0x0c
)

// Signature is what a page-zero signature means.
type Signature uint8

const (
	// SignatureLegacy is `hibr`, the XP/2003 path.
	SignatureLegacy Signature = iota
	// SignatureVista is `HIBR`, the Vista-or-later path.
	SignatureVista
	// SignatureRestore is `RSTR`, a restoration/resume state that may mark an
	// erroneous file.
	SignatureRestore
	// SignatureWakeLower is `wake`, marking an invalid hibernation file.
	SignatureWakeLower
	// SignatureWakeUpper is `WAKE`, marking an invalid hibernation file.
	SignatureWakeUpper
)

// SignatureFromBytes classifies the first four bytes, if they are known.
func SignatureFromBytes(b [4]byte) (Signature, bool) {
	switch b {
	case Magic:
		return SignatureLegacy, true
	case MagicVista:
		return SignatureVista, true
	case MagicRestore:
		return SignatureRestore, true
	case MagicWake:
		return SignatureWakeLower, true
	case MagicWakeUpper:
		return SignatureWakeUpper, true
	default:
		return 0, false
	}
}

// Label returns a factual label for the signature.
func (s Signature) Label() string {
	switch s {
	case SignatureLegacy:
		return "hibr (XP/2003 legacy)"
	case SignatureVista:
		return "HIBR (Vista or later)"
	case SignatureRestore:
		return "RSTR (restoration/resume state)"
	default:
		return "wake (invalid hibernation file)"
	}
}

// IsInvalid reports whether the file is not a usable hibernation image.
func (s Signature) IsInvalid() bool {
	return s == SignatureRestore || s == SignatureWakeLower || s == SignatureWakeUpper
}

// Error kinds. Test them with errors.Is.
var (
	// ErrSignatureTooShort means fewer than four bytes are present.
	ErrSignatureTooShort = errors.New("memory/hiber: signature too short")
	// ErrHeaderTooShort means fewer than the sixteen common field bytes are
	// present.
	ErrHeaderTooShort = errors.New("memory/hiber: header too short")
	// ErrBadSignature means the first four bytes are not a known signature.
	ErrBadSignature = errors.New("memory/hiber: bad signature")
	// ErrSource means the byte source failed while the header was read.
	ErrSource = errors.New("memory/hiber: source error")
	// ErrUnsupported is the shared data-layer unsupported-feature sentinel.
	ErrUnsupported = source.ErrUnsupported
)

// Error is a structured hibernation-header failure.
type Error struct {
	Kind      error
	Need      uint64
	Available uint64
	Found     [4]byte
	Err       error
}

func (e *Error) Error() string {
	switch {
	case errors.Is(e.Kind, ErrSignatureTooShort):
		return fmt.Sprintf("hibernation header needs 4 signature bytes, source has %d", e.Available)
	case errors.Is(e.Kind, ErrHeaderTooShort):
		return fmt.Sprintf("hibernation header needs %d bytes for its stable fields, source has %d", e.Need, e.Available)
	case errors.Is(e.Kind, ErrBadSignature):
		return fmt.Sprintf("hibernation signature is % X, expected `hibr`, `HIBR`, `RSTR`, `wake` or `WAKE`", e.Found)
	case errors.Is(e.Kind, ErrSource):
		if e.Err != nil {
			return e.Err.Error()
		}
		return "hibernation source read failed"
	default:
		if e.Err != nil {
			return e.Err.Error()
		}
		return "hibernation error"
	}
}

// Unwrap exposes both the kind and the underlying cause to errors.Is/As.
func (e *Error) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.Kind != nil {
		out = append(out, e.Kind)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}

// Report is the static page-zero metadata from a hibernation file.
//
// Pointer fields are nil when the signature's layout does not place that field
// at a substantiated offset. RefusedFields names the deeper fields this reader
// deliberately does not decode; AbsentFields names counters that the documented
// layouts do not describe at all.
type Report struct {
	// Signature is the four signature bytes as stored.
	Signature [4]byte
	// SignatureKind is what the signature means.
	SignatureKind Signature
	// Version is Version at 0x04; only the legacy `hibr` layout stores it.
	Version *uint32
	// ImageType is ImageType at 0x04; only the Vista+ `HIBR` layout stores it.
	ImageType *uint32
	// Checksum is CheckSum at 0x08 for the two substantiated layouts.
	Checksum *uint32
	// LengthSelf is LengthSelf/Size at 0x0c for those layouts.
	LengthSelf *uint32
	// SourceLen is the source file length.
	SourceLen uint64
	// RefusedFields are deeper fields refused rather than guessed.
	RefusedFields []string
	// AbsentFields are counters no substantiated layout describes.
	AbsentFields []string
	// LayoutNote is one factual sentence about why the deeper layout was not
	// decoded.
	LayoutNote string
}

// LooksLike reports whether head starts with the legacy `hibr` routing magic.
// As in the reference, `HIBR` is not accepted by this narrow probe.
func LooksLike(head []byte) bool {
	return len(head) >= len(Magic) && [4]byte{head[0], head[1], head[2], head[3]} == Magic
}

// Read reads a hibernation file's page-zero header and reports the fields that
// can be laid out with confidence.
//
// Only the first sixteen bytes are read. No page map, compressed range or
// memory content is touched.
func Read(src source.ByteSource) (*Report, error) {
	sourceLen := src.Len()
	if sourceLen < 4 {
		return nil, &Error{Kind: ErrSignatureTooShort, Available: sourceLen}
	}
	if sourceLen < CommonFieldsBytes {
		return nil, &Error{Kind: ErrHeaderTooShort, Need: CommonFieldsBytes, Available: sourceLen}
	}

	var header [CommonFieldsBytes]byte
	if err := source.ReadExactAt(src, 0, header[:]); err != nil {
		return nil, &Error{Kind: ErrSource, Err: err}
	}

	signature := [4]byte{header[0], header[1], header[2], header[3]}
	kind, ok := SignatureFromBytes(signature)
	if !ok {
		return nil, &Error{Kind: ErrBadSignature, Found: signature}
	}

	var layoutNote string
	var version, imageType, checksum, lengthSelf *uint32
	var refusedFields []string
	switch kind {
	case SignatureLegacy:
		layoutNote = "legacy `hibr` header: only the stable first sixteen bytes are decoded; " +
			"the documented 32- and 64-bit tables widen PageSelf and move PageSize/ImageType, " +
			"and the numeric Version values are unmapped, so deeper fields are refused"
		version = u32ptr(binary.LittleEndian.Uint32(header[VersionOrImageTypeOffset:]))
		checksum = u32ptr(binary.LittleEndian.Uint32(header[ChecksumOffset:]))
		lengthSelf = u32ptr(binary.LittleEndian.Uint32(header[LengthSelfOffset:]))
		refusedFields = []string{
			"PageSelf",
			"PageSize",
			"ImageType",
			"FirstTablePage",
			"TotalPhysicalMemoryCount",
			"BootLoaderLogPages",
			"ResumeContext",
		}
	case SignatureVista:
		layoutNote = "Vista+ `HIBR` header: offset 4 is ImageType, not Version, and the " +
			"per-build header size differs (224-320 bytes), so deeper fields are refused"
		imageType = u32ptr(binary.LittleEndian.Uint32(header[VersionOrImageTypeOffset:]))
		checksum = u32ptr(binary.LittleEndian.Uint32(header[ChecksumOffset:]))
		lengthSelf = u32ptr(binary.LittleEndian.Uint32(header[LengthSelfOffset:]))
		refusedFields = []string{
			"PageSelf",
			"PageSize",
			"FirstTablePage",
			"TotalPhysicalMemoryCount",
			"BootLoaderLogPages",
			"ResumeContext",
		}
	case SignatureRestore:
		layoutNote = "`RSTR` restoration/error state: no field layout is substantiated, so only " +
			"the signature is reported"
		refusedFields = allRefused()
	default: // SignatureWakeLower, SignatureWakeUpper
		layoutNote = "`wake`/`WAKE` marks an invalid hibernation file; no field layout is " +
			"substantiated, so only the signature is reported"
		refusedFields = allRefused()
	}

	return &Report{
		Signature:     signature,
		SignatureKind: kind,
		Version:       version,
		ImageType:     imageType,
		Checksum:      checksum,
		LengthSelf:    lengthSelf,
		SourceLen:     sourceLen,
		RefusedFields: refusedFields,
		AbsentFields:  []string{"MachineType", "ProcessorCount"},
		LayoutNote:    layoutNote,
	}, nil
}

func allRefused() []string {
	return []string{
		"Version",
		"ImageType",
		"CheckSum",
		"LengthSelf",
		"PageSelf",
		"PageSize",
		"FirstTablePage",
		"TotalPhysicalMemoryCount",
		"BootLoaderLogPages",
		"ResumeContext",
	}
}

func u32ptr(value uint32) *uint32 { return &value }

// Field returns a decoded header field by its Windows name, or an
// errors.Is(err, ErrUnsupported) refusal for fields this reader deliberately
// does not decode. The stable fields (Version, ImageType, CheckSum,
// LengthSelf) are returned when the signature's layout substantiates them.
func (r *Report) Field(name string) (uint64, error) {
	switch name {
	case "Version":
		if r.Version != nil {
			return uint64(*r.Version), nil
		}
	case "ImageType":
		if r.ImageType != nil {
			return uint64(*r.ImageType), nil
		}
	case "CheckSum":
		if r.Checksum != nil {
			return uint64(*r.Checksum), nil
		}
	case "LengthSelf":
		if r.LengthSelf != nil {
			return uint64(*r.LengthSelf), nil
		}
	}
	return 0, fmt.Errorf("%w: hibernation field %q is not decoded at a substantiated offset", ErrUnsupported, name)
}

// Decompress refuses XPRESS decompression explicitly: the reference reader does
// not decompress page data and this port does not guess at the page map.
func (r *Report) Decompress() error {
	return fmt.Errorf("%w: hibernation XPRESS decompression and page-map traversal are not ported; the reader reports header metadata only", ErrUnsupported)
}
