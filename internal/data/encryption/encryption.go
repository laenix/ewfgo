// Package encryption reads volume-encryption headers without a key.
//
// It reports what a locked volume says about itself: the format and version,
// the cipher and mode, the key slots and their key-derivation parameters, and
// the key-protector kinds a volume master key is wrapped by. BitLocker volume
// and metadata headers (bitlocker), LUKS1 and LUKS2 binary/JSON metadata
// (luks), and the metadata half of BitLocker key files (bitlocker.ReadBek) are
// covered.
//
// It deliberately does not derive a key, unwrap a key protector, or decrypt a
// byte. Reaching key material means running a KDF, stretching a recovery
// password, or exercising a TPM secret, and each of those is refused with
// ErrUnsupported (see Refusal). No key bytes, derived keys, salts, or digests
// are published: reports carry only their presence and length.
//
// The package imports no cryptographic implementation beyond the standard
// library's SHA-256, which is needed solely to verify the LUKS2 header
// checksum.
package encryption

import (
	"bytes"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
	"github.com/laenix/ewfgo/internal/data/encryption/errs"
	"github.com/laenix/ewfgo/internal/data/encryption/luks"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// LUKSMagic is the six-byte LUKS signature, shared by versions 1 and 2.
	LUKSMagic = "LUKS\xba\xbe"
	// BitLockerSignature is the eight-byte FVE signature at offset 3.
	BitLockerSignature = "-FVE-FS-"
	// LUKS1HeaderBytes is the fixed LUKS1 header size.
	LUKS1HeaderBytes = luks.LUKS1HeaderBytes
	// LUKS2BinaryHeaderBytes is the LUKS2 binary header before the JSON area.
	LUKS2BinaryHeaderBytes = luks.LUKS2BinaryHeaderBytes
	// MaxHeaderBytes is the largest declared header this package will load.
	MaxHeaderBytes = luks.MaxHeaderBytes
	// NXMagicOffset is where an APFS container superblock carries "NXSB".
	NXMagicOffset = 0x20
)

// Format is the encryption format of a volume header.
type Format uint8

const (
	// FormatNone means no encryption header this package reads was found.
	FormatNone Format = iota
	// FormatLUKS1 is a LUKS version 1 header.
	FormatLUKS1
	// FormatLUKS2 is a LUKS version 2 header.
	FormatLUKS2
	// FormatBitLocker is a BitLocker (FVE) volume header.
	FormatBitLocker
)

// String returns a short format label.
func (f Format) String() string {
	switch f {
	case FormatLUKS1:
		return "luks1"
	case FormatLUKS2:
		return "luks2"
	case FormatBitLocker:
		return "bitlocker"
	default:
		return "none"
	}
}

// Shared sentinel errors. They are aliases of the errs package so callers can
// use errors.Is against either package.
var (
	ErrUnsupported    = errs.ErrUnsupported
	ErrTruncated      = errs.ErrTruncated
	ErrUnknownVersion = errs.ErrUnknownVersion
	ErrHeaderTooLarge = errs.ErrHeaderTooLarge
	ErrMalformed      = errs.ErrMalformed
	ErrBadMagic       = errs.ErrBadMagic
	ErrBadBase64      = errs.ErrBadBase64
)

// Operations this metadata-only package refuses by name.
const (
	OperationUnlock                = "unlock"
	OperationDecrypt               = "decrypt"
	OperationRecoveryKeyDerivation = "recovery-key derivation"
	OperationHiddenVolume          = "hidden volume"
)

// Refusal returns an error wrapping ErrUnsupported for a named operation the
// package does not perform. Callers that would otherwise have to guess whether
// an omission is accidental can test errors.Is(err, ErrUnsupported).
func Refusal(operation string) error { return errs.Unsupported(operation) }

// Identify reports the encryption header at the start of src.
//
// BitLocker is recognized by -FVE-FS- at offset 3, LUKS by its magic at offset
// 0. An APFS container (NXSB at 0x20) is recognized only to refuse it with
// ErrUnsupported, since keybag inspection is not ported here. A source with
// none of these signatures returns FormatNone and a nil error. A malformed or
// truncated header of a recognized format is an explicit error.
func Identify(src source.ByteSource) (Format, error) {
	length := src.Len()
	if length < 6 {
		return FormatNone, nil
	}

	probeLen := min(length, 11)
	probe, err := source.ReadVecAt(src, 0, probeLen)
	if err != nil {
		return FormatNone, err
	}
	if len(probe) >= 11 && bytes.Equal(probe[3:11], []byte(BitLockerSignature)) {
		if length < bitlocker.VolumeHeaderBytes {
			return FormatNone, errs.Truncated(bitlocker.VolumeHeaderBytes, length)
		}
		info, err := bitlocker.Read(src)
		if err != nil {
			return FormatNone, err
		}
		if info == nil {
			return FormatNone, nil
		}
		return FormatBitLocker, nil
	}

	headLen := min(length, uint64(LUKS2BinaryHeaderBytes))
	head, err := source.ReadVecAt(src, 0, headLen)
	if err != nil {
		return FormatNone, err
	}
	if !bytes.HasPrefix(head, []byte(LUKSMagic)) {
		if len(head) >= NXMagicOffset+4 &&
			bytes.Equal(head[NXMagicOffset:NXMagicOffset+4], []byte("NXSB")) {
			return FormatNone, errs.Unsupported("APFS keybag inspection")
		}
		return FormatNone, nil
	}

	info, err := luks.Read(src)
	if err != nil {
		return FormatNone, err
	}
	if info == nil {
		return FormatNone, nil
	}
	switch info.Version {
	case 1:
		return FormatLUKS1, nil
	case 2:
		return FormatLUKS2, nil
	default:
		return FormatNone, errs.UnknownVersion(uint16(info.Version))
	}
}
