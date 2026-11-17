package unlock

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Recovery-password shape. A recovery password is eight groups of six decimal
// digits; every group is divisible by eleven and its quotient is one 16-bit
// half of the recovery key.
const (
	// RecoveryGroups is the number of six-digit groups.
	RecoveryGroups = 8
	// GroupDigits is the number of digits in one group.
	GroupDigits = 6
	// MinGroup is the smallest six-digit group value.
	MinGroup = 100_000
	// MaxGroup is the largest six-digit group whose quotient fits in 16 bits.
	MaxGroup = 720_885
)

// Stretching and key sizes.
const (
	// StretchIterations is the SHA-256 round count of the recovery-password
	// stretch.
	StretchIterations uint32 = 1_048_576
	// PasswordStretchIterations is the SHA-256 round count of the user-password
	// stretch. The protector does not store it; this is the documented value.
	PasswordStretchIterations uint32 = 1_048_576
	// StretchedBytes is the size of a stretched key.
	StretchedBytes = 32
	// RecoveryKeyBytes is the size of the key a recovery password yields.
	RecoveryKeyBytes = 16
	// SaltBytes is the size of a protector's stretch-key salt.
	SaltBytes = 16
	// StartupKeyBytes is the size of a startup (external) key.
	StartupKeyBytes = 32
)

// RecoveryKey turns a 48-digit recovery password into its 16-byte key.
//
// Dashes and ASCII whitespace between digits are ignored, matching the
// separators Windows prints. The digits themselves must be eight six-digit
// groups, every group divisible by eleven; the eight quotients, each written
// little-endian, are the key.
func RecoveryKey(password string) ([RecoveryKeyBytes]byte, error) {
	var key [RecoveryKeyBytes]byte
	digits := make([]byte, 0, RecoveryGroups*GroupDigits)
	for i := 0; i < len(password); i++ {
		b := password[i]
		if isASCIIWhitespace(b) || b == '-' {
			continue
		}
		digits = append(digits, b)
	}
	if len(digits) != RecoveryGroups*GroupDigits {
		return key, fmt.Errorf("%w: not 48 digits in eight groups of six", ErrPasswordShape)
	}
	for _, b := range digits {
		if b < '0' || b > '9' {
			return key, fmt.Errorf("%w: not made of digits only", ErrPasswordShape)
		}
	}
	for group := 0; group < RecoveryGroups; group++ {
		at := group * GroupDigits
		value := 0
		for _, b := range digits[at : at+GroupDigits] {
			value = value*10 + int(b-'0')
		}
		if value < MinGroup {
			return key, fmt.Errorf("%w: a group of fewer than six significant digits", ErrPasswordShape)
		}
		if value%11 != 0 {
			return key, fmt.Errorf("%w: group %d is not divisible by 11", ErrPasswordGroup, group+1)
		}
		if value > MaxGroup {
			return key, fmt.Errorf("%w: group %d divides to more than 16 bits", ErrPasswordGroupRange, group+1)
		}
		binary.LittleEndian.PutUint16(key[group*2:group*2+2], uint16(value/11))
	}
	return key, nil
}

func isASCIIWhitespace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

// StretchInitial runs the BitLocker SHA-256 chain.
//
// The running digest starts at zero. Every round hashes
// `updated || initial || salt || count`, where count is a little-endian uint64;
// the last digest is the result. The iteration count is a parameter only so a
// caller can hold it down in a test; unlocking always passes
// [StretchIterations] or [PasswordStretchIterations].
func StretchInitial(initial [StretchedBytes]byte, salt [SaltBytes]byte, iterations uint32) [StretchedBytes]byte {
	var updated [StretchedBytes]byte
	var input [StretchedBytes + StretchedBytes + SaltBytes + 8]byte
	copy(input[StretchedBytes:2*StretchedBytes], initial[:])
	copy(input[2*StretchedBytes:2*StretchedBytes+SaltBytes], salt[:])
	for count := uint32(0); count < iterations; count++ {
		copy(input[:StretchedBytes], updated[:])
		binary.LittleEndian.PutUint64(input[2*StretchedBytes+SaltBytes:], uint64(count))
		updated = sha256.Sum256(input[:])
	}
	return updated
}

// StretchKey stretches a recovery key. The initial digest is SHA-256 of the
// recovery key, as the format defines.
func StretchKey(key [RecoveryKeyBytes]byte, salt [SaltBytes]byte, iterations uint32) [StretchedBytes]byte {
	initial := sha256.Sum256(key[:])
	return StretchInitial(initial, salt, iterations)
}

// PasswordInitial computes a user password's initial digest: SHA-256 of
// SHA-256 of the password's UTF-16LE encoding, with no byte-order mark and no
// terminator. A password that is not valid UTF-8 is refused.
func PasswordInitial(password []byte) ([StretchedBytes]byte, error) {
	var zero [StretchedBytes]byte
	if !utf8.Valid(password) {
		return zero, fmt.Errorf("%w: not valid UTF-8 text", ErrPasswordText)
	}
	const byteOrderMark = rune(0xFEFF)
	text := strings.TrimPrefix(string(password), string(byteOrderMark))
	units := utf16.Encode([]rune(text))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	first := sha256.Sum256(encoded)
	return sha256.Sum256(first[:]), nil
}

// StretchPassword stretches a user password with a protector's salt using the
// documented iteration count.
func StretchPassword(password []byte, salt [SaltBytes]byte) ([StretchedBytes]byte, error) {
	initial, err := PasswordInitial(password)
	if err != nil {
		return [StretchedBytes]byte{}, err
	}
	return StretchInitial(initial, salt, PasswordStretchIterations), nil
}
