// Package errs holds the sentinel errors shared by the encryption metadata
// readers. Keeping them in one small package lets the top-level encryption
// package and the per-format readers return errors that the same errors.Is
// checks match.
package errs

import (
	"errors"
	"fmt"
)

var (
	// ErrUnsupported means the structure or operation is recognised but this
	// metadata-only port does not read it (unlocking, decryption, key
	// derivation, hidden volumes, APFS keybags).
	ErrUnsupported = errors.New("encryption: unsupported")
	// ErrTruncated means the source ended before a declared structure did.
	ErrTruncated = errors.New("encryption: truncated structure")
	// ErrUnknownVersion means the magic is known but the version is not.
	ErrUnknownVersion = errors.New("encryption: unknown version")
	// ErrHeaderTooLarge means a declared header exceeds the reader's limit.
	ErrHeaderTooLarge = errors.New("encryption: header too large")
	// ErrMalformed means the bytes are present but do not form the structure
	// the format declares.
	ErrMalformed = errors.New("encryption: malformed structure")
	// ErrBadMagic means a per-format reader was handed bytes for another format.
	ErrBadMagic = errors.New("encryption: bad magic")
	// ErrBadBase64 means a field the format stores as Base64 is not Base64.
	ErrBadBase64 = errors.New("encryption: invalid base64")
)

// Unsupported builds an ErrUnsupported error naming the operation or branch.
func Unsupported(operation string) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, operation)
}

// UnknownVersion builds an ErrUnknownVersion error carrying the version.
func UnknownVersion(version uint16) error {
	return fmt.Errorf("%w: %d", ErrUnknownVersion, version)
}

// Malformed builds an ErrMalformed error naming the structure.
func Malformed(what string) error {
	return fmt.Errorf("%w: %s", ErrMalformed, what)
}

// Truncated builds an ErrTruncated error carrying the byte counts.
func Truncated(need, got uint64) error {
	return fmt.Errorf("%w: need %d bytes, source holds %d", ErrTruncated, need, got)
}

// BadMagic builds an ErrBadMagic error naming the expected format.
func BadMagic(what string) error {
	return fmt.Errorf("%w: %s", ErrBadMagic, what)
}

// BadBase64 builds an ErrBadBase64 error naming the field.
func BadBase64(what string) error {
	return fmt.Errorf("%w: %s", ErrBadBase64, what)
}

// TooLarge builds an ErrHeaderTooLarge error carrying the declared size.
func TooLarge(bytes, max uint64) error {
	return fmt.Errorf("%w: declared %d bytes, limit %d", ErrHeaderTooLarge, bytes, max)
}
