// Package sqlcipher exposes SQLCipher-encrypted SQLite databases as a
// read-only source.ByteSource.
//
// A SQLCipher database is an ordinary SQLite database whose pages have been
// replaced one for one by AES-256-CBC ciphertext, a per-page IV and, for
// generations 2 through 4, a per-page HMAC. The file does not begin with the
// plaintext SQLite magic: bytes 0..15 of page 1 are the salt, and the SQLite
// header only exists again after page 1 is decrypted.
//
// This package is a pure-Go port of forensic-core's
// data/containers/sqlcipher.rs. It implements the SQLCipher 4, 3, 2 and 1 page
// formats. Unlock is explicit: the caller supplies the passphrase (or raw key)
// and the profile. UnlockAuto and UnlockTryingProfiles exist for callers that
// deliberately want the reference implementation's ordered trial, but the
// reader itself never guesses a key.
//
// Every page read re-verifies the page HMAC before decrypting. A page that
// fails is source.ErrCorrupt, never plaintext zeroes. SQLCipher 1 has no HMAC;
// its pages after page 1 are unauthenticated by design. Extents are
// page-granular; the reserve bytes (IV and HMAC) read as zero because they are
// not SQLite data, while the extent map still names the parent bytes they
// occupy.
//
// Profile summary:
//
//	version | KDF                   | iterations | HMAC       | page | reserve
//	4       | PBKDF2-HMAC-SHA512    | 256000     | SHA-512    | 4096 | 80
//	3       | PBKDF2-HMAC-SHA1      | 64000      | SHA-1      | 1024 | 48
//	2       | PBKDF2-HMAC-SHA1      | 4000       | SHA-1      | 1024 | 48
//	1       | PBKDF2-HMAC-SHA1      | 4000       | none       | 1024 | 16
//
// The file itself records no version. A Header therefore names the profile the
// caller asked for as a hint; page_size and reserved_bytes are filled only
// after page 1 has been authenticated and decrypted.
package sqlcipher

import (
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// SQLiteMagic is the plaintext SQLite header reconstructed over the salt.
	SQLiteMagic = "SQLite format 3\x00"
	// SaltBytes is the size of the random salt at the start of page 1.
	SaltBytes = 16
	// IVBytes is the size of the per-page initialization vector.
	IVBytes = 16
	// AESBlockBytes is the AES block size and SQLCipher's reserve rounding unit.
	AESBlockBytes = 16
	// EncryptionKeyBytes is the AES-256 key size.
	EncryptionKeyBytes = 32
	// HMACSHA512Bytes is the size of an HMAC-SHA512 tag.
	HMACSHA512Bytes = 64
	// HMACSHA1Bytes is the size of an HMAC-SHA1 tag.
	HMACSHA1Bytes = 20
	// DefaultKDFIterations is the SQLCipher 4 encryption-key iteration count.
	DefaultKDFIterations uint32 = 256_000
	// DefaultHMACKDFIterations is the "fast" HMAC-key iteration count.
	DefaultHMACKDFIterations uint32 = 2
	// HMACSaltMask is XORed with every salt byte for the HMAC-key pass.
	HMACSaltMask byte = 0x3a
	// SQLCipher4PageSize is the SQLCipher 4 default page size.
	SQLCipher4PageSize uint32 = 4096
	// SQLCipher3PageSize is the SQLCipher 2 and 3 default page size.
	SQLCipher3PageSize uint32 = 1024
	// SQLCipher3KDFIterations is the SQLCipher 3 encryption-key iteration count.
	SQLCipher3KDFIterations uint32 = 64_000
	// SQLCipherLegacyKDFIterations is the SQLCipher 1 and 2 iteration count.
	SQLCipherLegacyKDFIterations uint32 = 4_000
	// SQLCipher4ReserveBytes is the 16-byte IV plus the 64-byte SHA-512 HMAC.
	SQLCipher4ReserveBytes = IVBytes + HMACSHA512Bytes
	// SQLCipher3ReserveBytes rounds 16-byte IV plus 20-byte SHA-1 HMAC to 48.
	SQLCipher3ReserveBytes = 48
	// SQLCipher1ReserveBytes is the IV alone; SQLCipher 1 has no HMAC.
	SQLCipher1ReserveBytes = IVBytes
	// MinPageSize is the smallest SQLite page size.
	MinPageSize uint32 = 512
	// MaxPageSize is the largest SQLite page size (stored as 1 in the header).
	MaxPageSize uint32 = 65_536
	// MinUsablePageBytes is SQLite's minimum usable page size after reserve.
	MinUsablePageBytes uint32 = 480
	// CacheBytes bounds decrypted page bytes retained in memory.
	CacheBytes = 8 * 1024 * 1024
)

// Version names the SQLCipher generation whose defaults a profile uses.
type Version uint8

const (
	// Version4 is SQLCipher 4.
	Version4 Version = iota
	// Version3 is SQLCipher 3.
	Version3
	// Version2 is SQLCipher 2.
	Version2
	// Version1 is SQLCipher 1.
	Version1
)

// Label returns the human-readable generation name.
func (v Version) Label() string {
	switch v {
	case Version4:
		return "SQLCipher 4"
	case Version3:
		return "SQLCipher 3"
	case Version2:
		return "SQLCipher 2"
	case Version1:
		return "SQLCipher 1"
	default:
		return fmt.Sprintf("SQLCipher (unknown version %d)", uint8(v))
	}
}

// Defaults describes the algorithms and parameters the generation shipped as
// defaults, for refusal messages.
func (v Version) Defaults() string {
	switch v {
	case Version4:
		return "PBKDF2-HMAC-SHA512 at 256000 iterations, HMAC-SHA512, 4096-byte pages"
	case Version3:
		return "PBKDF2-HMAC-SHA1 at 64000 iterations, HMAC-SHA1, 1024-byte pages"
	case Version2:
		return "PBKDF2-HMAC-SHA1 at 4000 iterations, HMAC-SHA1, 1024-byte pages"
	case Version1:
		return "PBKDF2-HMAC-SHA1 at 4000 iterations, no HMAC, 1024-byte pages"
	default:
		return "no known defaults"
	}
}

// Params returns the generation's default profile.
func (v Version) Params() Params {
	switch v {
	case Version4:
		return ParamsV4()
	case Version3:
		return ParamsV3()
	case Version2:
		return ParamsV2()
	case Version1:
		return ParamsV1()
	default:
		return Params{Version: v}
	}
}

// ProfileOrder is the order UnlockAuto tries profiles in: newest first.
var ProfileOrder = [...]Version{Version4, Version3, Version2, Version1}

// DefaultProfiles returns the four shipped profiles in ProfileOrder.
func DefaultProfiles() []Params {
	out := make([]Params, 0, len(ProfileOrder))
	for _, version := range ProfileOrder {
		out = append(out, version.Params())
	}
	return out
}

// Cipher is a SQLCipher block-cipher name.
type Cipher string

// CipherAES256CBC is the only implemented cipher.
const CipherAES256CBC Cipher = "aes-256-cbc"

// CipherFromName maps a SQLCipher cipher name to a Cipher, preserving names
// this build does not implement.
func CipherFromName(name string) Cipher {
	if name == string(CipherAES256CBC) {
		return CipherAES256CBC
	}
	return Cipher(name)
}

// Name returns the cipher name.
func (c Cipher) Name() string { return string(c) }

// Supported reports whether this build implements the cipher.
func (c Cipher) Supported() bool { return c == CipherAES256CBC }

// KDF is a SQLCipher key-derivation function.
type KDF string

const (
	// KDFPBKDF2HMACSHA512 is the SQLCipher 4 KDF.
	KDFPBKDF2HMACSHA512 KDF = "pbkdf2_hmac_sha512"
	// KDFPBKDF2HMACSHA1 is the SQLCipher 1-3 KDF.
	KDFPBKDF2HMACSHA1 KDF = "pbkdf2_hmac_sha1"
)

// KDFFromName maps a SQLCipher KDF name onto a KDF. Both underscore and
// dashed spellings are accepted. Unknown names are preserved.
func KDFFromName(name string) KDF {
	switch strings.ToLower(name) {
	case "pbkdf2_hmac_sha512", "pbkdf2-hmac-sha512":
		return KDFPBKDF2HMACSHA512
	case "pbkdf2_hmac_sha1", "pbkdf2-hmac-sha1":
		return KDFPBKDF2HMACSHA1
	default:
		return KDF(name)
	}
}

// Name returns the display name of the KDF.
func (k KDF) Name() string {
	switch k {
	case KDFPBKDF2HMACSHA512:
		return "PBKDF2-HMAC-SHA512"
	case KDFPBKDF2HMACSHA1:
		return "PBKDF2-HMAC-SHA1"
	default:
		return string(k)
	}
}

// DigestBytes returns the digest size the KDF's HMAC produces.
func (k KDF) DigestBytes() int {
	switch k {
	case KDFPBKDF2HMACSHA512:
		return HMACSHA512Bytes
	case KDFPBKDF2HMACSHA1:
		return HMACSHA1Bytes
	default:
		return 0
	}
}

// HMAC names the page authenticator.
type HMAC string

const (
	// HMACSHA512 is the SQLCipher 4 page authenticator.
	HMACSHA512 HMAC = "hmac_sha512"
	// HMACSHA1 is the SQLCipher 2 and 3 page authenticator.
	HMACSHA1 HMAC = "hmac_sha1"
	// HMACNone is SQLCipher 1's unauthenticated format.
	HMACNone HMAC = "hmac_none"
)

// HMACFromName maps a SQLCipher HMAC name onto an HMAC. Unknown names are
// preserved.
func HMACFromName(name string) HMAC {
	switch strings.ToLower(name) {
	case "hmac_sha512", "hmac-sha512":
		return HMACSHA512
	case "hmac_sha1", "hmac-sha1":
		return HMACSHA1
	case "hmac_none", "hmac-none", "none":
		return HMACNone
	default:
		return HMAC(name)
	}
}

// Name returns the display name of the HMAC.
func (h HMAC) Name() string {
	switch h {
	case HMACSHA512:
		return "HMAC-SHA512"
	case HMACSHA1:
		return "HMAC-SHA1"
	case HMACNone:
		return "no HMAC"
	default:
		return string(h)
	}
}

// CheckName names the page-1 check this HMAC provides, for refusal messages.
func (h HMAC) CheckName() string {
	switch h {
	case HMACSHA512:
		return "HMAC-SHA512"
	case HMACSHA1:
		return "HMAC-SHA1"
	case HMACNone:
		return "SQLite magic and header (SQLCipher 1 has no HMAC)"
	default:
		return "integrity check"
	}
}

// DigestBytes returns the HMAC tag size. HMACNone and unsupported names have
// no tag.
func (h HMAC) DigestBytes() int {
	switch h {
	case HMACSHA512:
		return HMACSHA512Bytes
	case HMACSHA1:
		return HMACSHA1Bytes
	default:
		return 0
	}
}

// Compute returns the HMAC of message under key, or nil when the profile has
// no page authenticator.
func (h HMAC) Compute(key, message []byte) []byte {
	switch h {
	case HMACSHA512:
		mac := hmac.New(sha512.New, key)
		mac.Write(message)
		return mac.Sum(nil)
	case HMACSHA1:
		mac := hmac.New(sha1.New, key)
		mac.Write(message)
		return mac.Sum(nil)
	default:
		return nil
	}
}

// Params is the explicit profile a caller unlocks with.
type Params struct {
	Version             Version
	Cipher              Cipher
	KDF                 KDF
	HMAC                HMAC
	KDFIterations       uint32
	HMACKDFIterations   uint32
	PageSize            uint32
	PlaintextHeaderSize int
}

// ParamsV4 returns the SQLCipher 4 default profile.
func ParamsV4() Params {
	return Params{
		Version:           Version4,
		Cipher:            CipherAES256CBC,
		KDF:               KDFPBKDF2HMACSHA512,
		HMAC:              HMACSHA512,
		KDFIterations:     DefaultKDFIterations,
		HMACKDFIterations: DefaultHMACKDFIterations,
		PageSize:          SQLCipher4PageSize,
	}
}

// ParamsV3 returns the SQLCipher 3 default profile.
func ParamsV3() Params {
	return Params{
		Version:           Version3,
		Cipher:            CipherAES256CBC,
		KDF:               KDFPBKDF2HMACSHA1,
		HMAC:              HMACSHA1,
		KDFIterations:     SQLCipher3KDFIterations,
		HMACKDFIterations: DefaultHMACKDFIterations,
		PageSize:          SQLCipher3PageSize,
	}
}

// ParamsV2 returns the SQLCipher 2 default profile.
func ParamsV2() Params {
	return Params{
		Version:           Version2,
		Cipher:            CipherAES256CBC,
		KDF:               KDFPBKDF2HMACSHA1,
		HMAC:              HMACSHA1,
		KDFIterations:     SQLCipherLegacyKDFIterations,
		HMACKDFIterations: DefaultHMACKDFIterations,
		PageSize:          SQLCipher3PageSize,
	}
}

// ParamsV1 returns the SQLCipher 1 default profile.
func ParamsV1() Params {
	return Params{
		Version:           Version1,
		Cipher:            CipherAES256CBC,
		KDF:               KDFPBKDF2HMACSHA1,
		HMAC:              HMACNone,
		KDFIterations:     SQLCipherLegacyKDFIterations,
		HMACKDFIterations: DefaultHMACKDFIterations,
		PageSize:          SQLCipher3PageSize,
	}
}

// DefaultParams returns the SQLCipher 4 profile.
func DefaultParams() Params { return ParamsV4() }

// ReserveBytes is the number of page bytes that are not SQLite data: the IV,
// the HMAC and padding to an AES block boundary.
func (p Params) ReserveBytes() int {
	return roundUp(IVBytes+p.HMAC.DigestBytes(), AESBlockBytes)
}

// Validate checks a profile before any key work.
func (p Params) Validate() error {
	if p.PlaintextHeaderSize > 0 {
		return unsupportedError(fmt.Sprintf(
			"a %d-byte plaintext header (cipher_plaintext_header_size): the salt is then stored outside the database file and must be supplied separately",
			p.PlaintextHeaderSize,
		))
	}
	if !p.Cipher.Supported() {
		return unsupportedError(fmt.Sprintf(
			"cipher %s (AES-256-CBC with SQLCipher page encryption is the only one implemented)",
			p.Cipher.Name(),
		))
	}
	var algorithmsMatch bool
	switch p.Version {
	case Version4:
		algorithmsMatch = p.KDF == KDFPBKDF2HMACSHA512 && p.HMAC == HMACSHA512
	case Version3, Version2:
		algorithmsMatch = p.KDF == KDFPBKDF2HMACSHA1 && p.HMAC == HMACSHA1
	case Version1:
		algorithmsMatch = p.KDF == KDFPBKDF2HMACSHA1 && p.HMAC == HMACNone
	default:
		algorithmsMatch = false
	}
	if !algorithmsMatch {
		return unsupportedError(fmt.Sprintf(
			"%s with KDF %s and HMAC %s; that generation uses %s",
			p.Version.Label(), p.KDF.Name(), p.HMAC.Name(), p.Version.Defaults(),
		))
	}
	if p.KDFIterations == 0 || p.HMACKDFIterations == 0 {
		return unsupportedError("zero PBKDF2 iterations")
	}
	return validatePageSize(p.PageSize, p.ReserveBytes())
}

func validatePageSize(pageSize uint32, reserve int) error {
	if pageSize < MinPageSize || pageSize > MaxPageSize || pageSize&(pageSize-1) != 0 {
		return pageSizeError(pageSize, fmt.Sprintf(
			"SQLite page sizes are powers of two in %d..=%d", MinPageSize, MaxPageSize,
		))
	}
	if int(pageSize) <= reserve {
		return pageSizeError(pageSize, fmt.Sprintf("the %d-byte reserve leaves no ciphertext", reserve))
	}
	usable := int(pageSize) - reserve
	if usable < int(MinUsablePageBytes) {
		return pageSizeError(pageSize, fmt.Sprintf(
			"the %d-byte reserve leaves %d usable bytes, below SQLite's %d-byte minimum",
			reserve, usable, MinUsablePageBytes,
		))
	}
	if (usable-SaltBytes)%AESBlockBytes != 0 {
		return pageSizeError(pageSize, fmt.Sprintf(
			"page-1 ciphertext of %d bytes is not a whole AES block", usable-SaltBytes,
		))
	}
	return nil
}

func roundUp(value, unit int) int {
	return (value + unit - 1) / unit * unit
}

// Error sentinels. Callers test them with errors.Is.
var (
	// ErrWrongPassphrase means the page-1 check did not verify under the
	// supplied key and profile.
	ErrWrongPassphrase = errors.New("sqlcipher: wrong passphrase or profile")
	// ErrRawKey means a raw-key text is malformed.
	ErrRawKey = errors.New("sqlcipher: invalid raw key")
	// ErrSaltMismatch means a supplied raw-key salt disagrees with the file.
	ErrSaltMismatch = errors.New("sqlcipher: salt mismatch")
	// ErrNoProfile means every attempted profile was refused.
	ErrNoProfile = errors.New("sqlcipher: no profile unlocked the database")
	// ErrNotSQLCipher means the file does not look like an encrypted database
	// (for example, it begins with a plaintext SQLite header).
	ErrNotSQLCipher = errors.New("sqlcipher: not a SQLCipher database")
	// ErrUnsupported means a profile, algorithm or header option is not
	// implemented.
	ErrUnsupported = errors.New("sqlcipher: unsupported feature")
	// ErrInvalidPageSize means the page size is outside SQLite's range or
	// leaves too little usable space.
	ErrInvalidPageSize = errors.New("sqlcipher: invalid page size")
	// ErrTruncated means the file is not a whole number of pages.
	ErrTruncated = errors.New("sqlcipher: truncated database")
	// ErrCorruptPage means a page failed its HMAC or its header is impossible.
	ErrCorruptPage = errors.New("sqlcipher: corrupt page")
	// ErrWALFrame means a WAL frame body failed its HMAC or was not a whole
	// page.
	ErrWALFrame = errors.New("sqlcipher: invalid WAL frame")
)

// Error is a structured SQLCipher failure. The Kind is one of the sentinels
// above, and Unwrap also exposes the closest source.Err* sentinel so callers
// can use source's error taxonomy uniformly.
type Error struct {
	Kind         error
	Check        string
	Feature      string
	PageSize     uint32
	Page         uint32
	Offset       uint64
	Reason       string
	SuppliedSalt [SaltBytes]byte
	FileSalt     [SaltBytes]byte
	Attempts     []string
	Err          error

	sourceKind error
}

func (e *Error) Error() string {
	switch e.Kind {
	case ErrWrongPassphrase:
		return fmt.Sprintf(
			"the page-1 %s did not verify: the passphrase is wrong, or the page size or SQLCipher profile does not match this database",
			e.Check,
		)
	case ErrRawKey:
		return "invalid SQLCipher raw key: " + e.Reason
	case ErrSaltMismatch:
		return fmt.Sprintf("the supplied raw-key salt %x does not match the file header salt %x",
			e.SuppliedSalt, e.FileSalt)
	case ErrNoProfile:
		return "no SQLCipher profile unlocked the database: " + strings.Join(e.Attempts, "; ")
	case ErrNotSQLCipher:
		return "not a SQLCipher database: " + e.Reason
	case ErrUnsupported:
		return "unsupported SQLCipher feature: " + e.Feature
	case ErrInvalidPageSize:
		return fmt.Sprintf("invalid SQLCipher page size %d: %s", e.PageSize, e.Reason)
	case ErrTruncated:
		return fmt.Sprintf("truncated SQLCipher database: %d bytes is not a whole number of %d-byte pages",
			e.Offset, e.PageSize)
	case ErrCorruptPage:
		return fmt.Sprintf("corrupt SQLCipher page %d at offset %d: %s", e.Page, e.Offset, e.Reason)
	case ErrWALFrame:
		return fmt.Sprintf("SQLCipher WAL frame for page %d: %s", e.Page, e.Reason)
	default:
		if e.Err != nil {
			return "sqlcipher: " + e.Err.Error()
		}
		return "sqlcipher error"
	}
}

// Unwrap exposes the structured kind, the source taxonomy, and any underlying
// source error.
func (e *Error) Unwrap() []error {
	out := make([]error, 0, 3)
	if e.Kind != nil {
		out = append(out, e.Kind)
	}
	if e.sourceKind != nil && e.sourceKind != e.Kind {
		out = append(out, e.sourceKind)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}

func unsupportedError(feature string) *Error {
	return &Error{Kind: ErrUnsupported, Feature: feature, sourceKind: source.ErrUnsupported}
}

func wrongPassphraseError(check string) *Error {
	return &Error{Kind: ErrWrongPassphrase, Check: check, sourceKind: source.ErrDecrypt}
}

func rawKeyError(reason string) *Error {
	return &Error{Kind: ErrRawKey, Reason: reason, sourceKind: source.ErrInvalidArgument}
}

func saltMismatchError(supplied, file [SaltBytes]byte) *Error {
	return &Error{
		Kind: ErrSaltMismatch, SuppliedSalt: supplied, FileSalt: file,
		sourceKind: source.ErrInvalidArgument,
	}
}

func pageSizeError(pageSize uint32, reason string) *Error {
	return &Error{Kind: ErrInvalidPageSize, PageSize: pageSize, Reason: reason, sourceKind: source.ErrUnsupported}
}

func truncatedError(length uint64, pageSize uint32) *Error {
	return &Error{Kind: ErrTruncated, Offset: length, PageSize: pageSize, sourceKind: source.ErrUnexpectedEOF}
}

func notSQLCipherError(reason string) *Error {
	return &Error{Kind: ErrNotSQLCipher, Reason: reason, sourceKind: source.ErrCorrupt}
}

func corruptPageError(page uint32, offset uint64, reason string) *Error {
	return &Error{Kind: ErrCorruptPage, Page: page, Offset: offset, Reason: reason, sourceKind: source.ErrCorrupt}
}

func walFrameError(page uint32, reason string) *Error {
	return &Error{Kind: ErrWALFrame, Page: page, Reason: reason, sourceKind: source.ErrCorrupt}
}

// Header is what the unencrypted file itself reveals.
type Header struct {
	Salt             [SaltBytes]byte
	Version          Version
	PageSize         uint32
	HasPageSize      bool
	ReservedBytes    uint8
	HasReservedBytes bool
	FileSize         uint64
}

// Detect reads the salt candidate at the start of a file.
//
// It returns (nil, nil) when the file is shorter than a salt or begins with the
// plaintext SQLite magic. That is either a plaintext database or a SQLCipher
// database with a plaintext header, whose salt is not in the file. A non-nil
// result proves only that the file is not plaintext SQLite; Unlock proves that
// it is SQLCipher by verifying page 1.
func Detect(parent source.ByteSource) (*Header, error) {
	if parent.Len() < SaltBytes {
		return nil, nil
	}
	var salt [SaltBytes]byte
	if err := source.ReadExactAt(parent, 0, salt[:]); err != nil {
		return nil, err
	}
	if string(salt[:]) == SQLiteMagic {
		return nil, nil
	}
	return &Header{
		Salt:     salt,
		Version:  Version4,
		FileSize: parent.Len(),
	}, nil
}

// Key is the AES and HMAC key pair a passphrase (or raw key) produces.
type Key struct {
	Salt          [SaltBytes]byte
	EncryptionKey [EncryptionKeyBytes]byte
	HMACKey       [EncryptionKeyBytes]byte
}

// String redacts the key material.
func (k Key) String() string {
	return fmt.Sprintf("Key{salt:%x, encryption_key:<redacted>, hmac_key:<redacted>}", k.Salt)
}

// DeriveKey validates a profile and derives both keys from passphrase.
func DeriveKey(passphrase []byte, salt [SaltBytes]byte, params Params) (Key, error) {
	if err := params.Validate(); err != nil {
		return Key{}, err
	}
	encryptionKey, err := pbkdf2For(params.KDF, passphrase, salt[:], params.KDFIterations, EncryptionKeyBytes)
	if err != nil {
		return Key{}, err
	}
	var key Key
	key.Salt = salt
	copy(key.EncryptionKey[:], encryptionKey)
	hmacKey, err := hmacKeyFor(encryptionKey, salt, params)
	if err != nil {
		return Key{}, err
	}
	key.HMACKey = hmacKey
	return key, nil
}

// KeyFromRaw uses a 32-byte AES key unchanged, as SQLCipher's raw-key form
// does. Only the HMAC key is derived.
func KeyFromRaw(encryptionKey [EncryptionKeyBytes]byte, salt [SaltBytes]byte, params Params) (Key, error) {
	if err := params.Validate(); err != nil {
		return Key{}, err
	}
	var key Key
	key.Salt = salt
	key.EncryptionKey = encryptionKey
	hmacKey, err := hmacKeyFor(encryptionKey[:], salt, params)
	if err != nil {
		return Key{}, err
	}
	key.HMACKey = hmacKey
	return key, nil
}

func hmacKeyFor(encryptionKey []byte, salt [SaltBytes]byte, params Params) ([EncryptionKeyBytes]byte, error) {
	var hmacKey [EncryptionKeyBytes]byte
	if params.HMAC == HMACNone {
		return hmacKey, nil
	}
	masked := salt
	for index := range masked {
		masked[index] ^= HMACSaltMask
	}
	derived, err := pbkdf2For(params.KDF, encryptionKey, masked[:], params.HMACKDFIterations, EncryptionKeyBytes)
	if err != nil {
		return hmacKey, err
	}
	copy(hmacKey[:], derived)
	return hmacKey, nil
}

func pbkdf2For(kdf KDF, password, salt []byte, iterations uint32, outLen int) ([]byte, error) {
	if iterations == 0 {
		return nil, unsupportedError("zero PBKDF2 iterations")
	}
	if uint64(iterations) > uint64(maxInt()) {
		return nil, unsupportedError(fmt.Sprintf("%d PBKDF2 iterations exceed the address space", iterations))
	}
	var hashFunc func() hash.Hash
	switch kdf {
	case KDFPBKDF2HMACSHA512:
		hashFunc = sha512.New
	case KDFPBKDF2HMACSHA1:
		hashFunc = sha1.New
	default:
		return nil, unsupportedError("KDF " + kdf.Name())
	}
	derived, err := pbkdf2.Key(hashFunc, string(password), salt, int(iterations), outLen)
	if err != nil {
		return nil, unsupportedError(fmt.Sprintf("%s: %v", kdf.Name(), err))
	}
	return derived, nil
}

func maxInt() int { return int(^uint(0) >> 1) }

// ParseRawKeyText parses the text form of a SQLCipher raw key. It accepts an
// optional SQLite x'…' wrapper and then exactly 64 hexadecimal digits (the
// 32-byte key) or 96 (key followed by the 16-byte salt). Whitespace, a 0x
// prefix, colons and every other separator are rejected by name.
func ParseRawKeyText(text string) ([EncryptionKeyBytes]byte, *[SaltBytes]byte, error) {
	var zeroKey [EncryptionKeyBytes]byte
	inner := text
	if strings.HasPrefix(text, "x'") || strings.HasPrefix(text, "X'") {
		rest := text[2:]
		if !strings.HasSuffix(rest, "'") {
			return zeroKey, nil, rawKeyError(fmt.Sprintf(
				"the quoted raw key %q does not end with a single quote", text,
			))
		}
		inner = rest[:len(rest)-1]
	} else if strings.Contains(text, "'") {
		return zeroKey, nil, rawKeyError(fmt.Sprintf(
			"the raw key %q carries a stray single quote; use x'…' or bare hex", text,
		))
	}
	for index, character := range inner {
		if !isHexRune(character) {
			return zeroKey, nil, rawKeyError(fmt.Sprintf(
				"non-hex character at byte %d in %q; a raw key is 64 or 96 hex digits", index, inner,
			))
		}
	}
	switch len(inner) {
	case 64:
		key, err := decodeHexArray(inner)
		if err != nil {
			return zeroKey, nil, err
		}
		return key, nil, nil
	case 96:
		key, err := decodeHexArray(inner[:64])
		if err != nil {
			return zeroKey, nil, err
		}
		saltBytes, err := hex.DecodeString(inner[64:])
		if err != nil {
			return zeroKey, nil, rawKeyError(fmt.Sprintf("non-hex character in %q", inner[64:]))
		}
		var salt [SaltBytes]byte
		copy(salt[:], saltBytes)
		return key, &salt, nil
	default:
		return zeroKey, nil, rawKeyError(fmt.Sprintf(
			"%d hex digits in %q; a raw key is 64 (key) or 96 (key + 16-byte salt)",
			len(inner), inner,
		))
	}
}

func isHexRune(character rune) bool {
	return (character >= '0' && character <= '9') ||
		(character >= 'a' && character <= 'f') ||
		(character >= 'A' && character <= 'F')
}

func decodeHexArray(text string) ([EncryptionKeyBytes]byte, error) {
	var out [EncryptionKeyBytes]byte
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return out, rawKeyError(fmt.Sprintf("non-hex character in %q", text))
	}
	copy(out[:], decoded)
	return out, nil
}

// Source is a read-only view of a decrypted SQLCipher database.
type Source struct {
	id        source.ID
	parent    source.ByteSource
	header    Header
	key       Key
	aes       cipher.Block
	params    Params
	pageSize  uint32
	reserve   int
	pageCount uint64

	mu         sync.Mutex
	cache      map[uint32]*list.Element
	lru        *list.List
	cacheBytes int

	counters source.Counters
}

type pageCacheEntry struct {
	page uint32
	data []byte
}

// Unlock validates params, verifies page 1 and returns the decrypted source.
func Unlock(id source.ID, parent source.ByteSource, passphrase []byte, params Params) (*Source, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	fileLen, header, err := checkSource(parent, params)
	if err != nil {
		return nil, err
	}
	key, err := DeriveKey(passphrase, header.Salt, params)
	if err != nil {
		return nil, err
	}
	return openUnlocked(id, parent, params, fileLen, header, key)
}

// UnlockRaw is Unlock with a 32-byte AES key used unchanged. salt is the
// file's first 16 bytes unless supplied. A supplied salt that disagrees with
// the file is ErrSaltMismatch.
func UnlockRaw(id source.ID, parent source.ByteSource, encryptionKey [EncryptionKeyBytes]byte, salt *[SaltBytes]byte, params Params) (*Source, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	fileLen, header, err := checkSource(parent, params)
	if err != nil {
		return nil, err
	}
	effectiveSalt := header.Salt
	if salt != nil {
		if *salt != header.Salt {
			return nil, saltMismatchError(*salt, header.Salt)
		}
		effectiveSalt = *salt
	}
	key, err := KeyFromRaw(encryptionKey, effectiveSalt, params)
	if err != nil {
		return nil, err
	}
	return openUnlocked(id, parent, params, fileLen, header, key)
}

// UnlockAuto tries the four shipped profiles in ProfileOrder and returns the
// first page-1 check that verifies.
func UnlockAuto(id source.ID, parent source.ByteSource, passphrase []byte) (*Source, error) {
	return UnlockTryingProfiles(id, parent, passphrase, DefaultProfiles())
}

// UnlockTryingProfiles tries profiles in exactly the order supplied.
func UnlockTryingProfiles(id source.ID, parent source.ByteSource, passphrase []byte, profiles []Params) (*Source, error) {
	attempts := make([]string, 0, len(profiles))
	for _, params := range profiles {
		unlocked, err := Unlock(id, parent, passphrase, params)
		if err == nil {
			return unlocked, nil
		}
		if errors.Is(err, ErrNotSQLCipher) {
			return nil, err
		}
		attempts = append(attempts, fmt.Sprintf("%s: %v", params.Version.Label(), err))
	}
	return nil, &Error{Kind: ErrNoProfile, Attempts: attempts, sourceKind: source.ErrDecrypt}
}

// UnlockRawTryingProfiles is the raw-key counterpart of
// UnlockTryingProfiles. A salt mismatch is returned immediately because no
// profile can fix it.
func UnlockRawTryingProfiles(id source.ID, parent source.ByteSource, encryptionKey [EncryptionKeyBytes]byte, salt *[SaltBytes]byte, profiles []Params) (*Source, error) {
	attempts := make([]string, 0, len(profiles))
	for _, params := range profiles {
		unlocked, err := UnlockRaw(id, parent, encryptionKey, salt, params)
		if err == nil {
			return unlocked, nil
		}
		if errors.Is(err, ErrNotSQLCipher) {
			return nil, err
		}
		if errors.Is(err, ErrSaltMismatch) {
			return nil, err
		}
		attempts = append(attempts, fmt.Sprintf("%s: %v", params.Version.Label(), err))
	}
	return nil, &Error{Kind: ErrNoProfile, Attempts: attempts, sourceKind: source.ErrDecrypt}
}

func checkSource(parent source.ByteSource, params Params) (uint64, Header, error) {
	pageSize := params.PageSize
	fileLen := parent.Len()
	if fileLen < uint64(pageSize) || fileLen%uint64(pageSize) != 0 {
		return 0, Header{}, truncatedError(fileLen, pageSize)
	}
	if fileLen/uint64(pageSize) > uint64(^uint32(0)) {
		return 0, Header{}, unsupportedError(fmt.Sprintf("%d pages in one database", fileLen/uint64(pageSize)))
	}
	header, err := Detect(parent)
	if err != nil {
		return 0, Header{}, err
	}
	if header == nil {
		return 0, Header{}, notSQLCipherError(
			"the file begins with the plaintext SQLite header; a SQLCipher database with a plaintext header keeps its salt outside the file and cannot be keyed from the file alone",
		)
	}
	return fileLen, *header, nil
}

func openUnlocked(id source.ID, parent source.ByteSource, params Params, fileLen uint64, header Header, key Key) (*Source, error) {
	block, err := aes.NewCipher(key.EncryptionKey[:])
	if err != nil {
		return nil, unsupportedError(fmt.Sprintf("AES-256 key: %v", err))
	}
	header.Version = params.Version
	unlocked := &Source{
		id:        id,
		parent:    parent,
		header:    header,
		key:       key,
		aes:       block,
		params:    params,
		pageSize:  params.PageSize,
		reserve:   params.ReserveBytes(),
		pageCount: fileLen / uint64(params.PageSize),
		cache:     make(map[uint32]*list.Element),
		lru:       list.New(),
	}
	raw, err := source.ReadVecAt(parent, 0, uint64(params.PageSize))
	if err != nil {
		return nil, err
	}
	if !unlocked.hmacMatches(1, raw) {
		return nil, wrongPassphraseError(params.HMAC.CheckName())
	}
	page1 := unlocked.decryptVerified(1, raw)
	reserved, err := unlocked.validatePage1(page1)
	if err != nil {
		return nil, wrongPassphraseError(params.HMAC.CheckName())
	}
	unlocked.header.PageSize = params.PageSize
	unlocked.header.HasPageSize = true
	unlocked.header.ReservedBytes = reserved
	unlocked.header.HasReservedBytes = true
	unlocked.cacheInsert(1, page1)
	return unlocked, nil
}

// Parent returns the encrypted container source.
func (s *Source) Parent() source.ByteSource { return s.parent }

// Header returns the detected header, now carrying page size and reserve.
func (s *Source) Header() Header { return s.header }

// Params returns the profile that unlocked the database.
func (s *Source) Params() Params { return s.params }

// Key returns the derived keys. The HMAC and AES keys are present; callers
// should treat them as sensitive.
func (s *Source) Key() Key { return s.key }

// Salt returns the file salt.
func (s *Source) Salt() [SaltBytes]byte { return s.key.Salt }

// PageSize returns the decrypted SQLite page size.
func (s *Source) PageSize() uint32 { return s.pageSize }

// PageCount returns the number of encrypted pages.
func (s *Source) PageCount() uint64 { return s.pageCount }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.parent.Len() }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *Source) SectorSize() uint32      { return s.parent.SectorSize() }
func (s *Source) IsEmpty() bool           { return s.Len() == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) checkRange(offset, length uint64) error {
	lengthOfSource := s.Len()
	if offset > lengthOfSource || length > lengthOfSource-offset {
		return source.NewOutOfRange(offset, length, lengthOfSource)
	}
	return nil
}

func (s *Source) pageOffset(page uint32) uint64 {
	return uint64(page-1) * uint64(s.pageSize)
}

func (s *Source) hmacMatches(page uint32, raw []byte) bool {
	digestBytes := s.params.HMAC.DigestBytes()
	if digestBytes == 0 {
		return true
	}
	pageSize := int(s.pageSize)
	macAt := pageSize - s.reserve + IVBytes
	start := 0
	if page == 1 {
		start = SaltBytes
	}
	message := make([]byte, 0, macAt-start+4)
	message = append(message, raw[start:macAt]...)
	var pageNumber [4]byte
	binary.LittleEndian.PutUint32(pageNumber[:], page)
	message = append(message, pageNumber[:]...)
	computed := s.params.HMAC.Compute(s.key.HMACKey[:], message)
	if len(computed) != digestBytes {
		return false
	}
	return hmac.Equal(computed, raw[macAt:macAt+digestBytes])
}

func (s *Source) decryptVerified(page uint32, raw []byte) []byte {
	pageSize := int(s.pageSize)
	ivAt := pageSize - s.reserve
	var iv [IVBytes]byte
	copy(iv[:], raw[ivAt:ivAt+IVBytes])
	out := make([]byte, pageSize)
	start := 0
	if page == 1 {
		copy(out[:SaltBytes], SQLiteMagic)
		start = SaltBytes
	}
	copy(out[start:ivAt], raw[start:ivAt])
	if ivAt > start {
		mode := cipher.NewCBCDecrypter(s.aes, iv[:])
		mode.CryptBlocks(out[start:ivAt], out[start:ivAt])
	}
	return out
}

func (s *Source) validatePage1(page []byte) (uint8, error) {
	if string(page[:SaltBytes]) != SQLiteMagic {
		return 0, corruptPageError(1, 0, "the decrypted page 1 does not start with the SQLite magic")
	}
	rawPageSize := binary.BigEndian.Uint16(page[16:18])
	declared := uint32(rawPageSize)
	if rawPageSize == 1 {
		declared = MaxPageSize
	}
	if declared != s.pageSize {
		return 0, corruptPageError(1, 0, fmt.Sprintf(
			"page 1 declares a %d-byte page, the profile uses %d", declared, s.pageSize,
		))
	}
	reserved := page[20]
	if int(reserved) != s.reserve {
		return 0, corruptPageError(1, 0, fmt.Sprintf(
			"page 1 declares %d reserved bytes, this profile stores %d (IV %d + %s)",
			reserved, s.reserve, IVBytes, s.params.HMAC.Name(),
		))
	}
	return reserved, nil
}

func (s *Source) cachedPage(page uint32) ([]byte, error) {
	s.mu.Lock()
	if element, ok := s.cache[page]; ok {
		s.lru.MoveToBack(element)
		data := element.Value.(*pageCacheEntry).data
		s.mu.Unlock()
		s.counters.AddCacheHit()
		return data, nil
	}
	s.mu.Unlock()
	s.counters.AddCacheMiss()

	raw, err := source.ReadVecAt(s.parent, s.pageOffset(page), uint64(s.pageSize))
	if err != nil {
		s.counters.AddError()
		return nil, err
	}
	data, err := s.decryptPage(page, raw)
	if err != nil {
		s.counters.AddCorrupt(uint64(s.pageSize))
		return nil, err
	}
	s.cacheInsert(page, data)
	return data, nil
}

func (s *Source) cacheInsert(page uint32, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if element, ok := s.cache[page]; ok {
		s.lru.Remove(element)
		s.cacheBytes -= len(element.Value.(*pageCacheEntry).data)
		delete(s.cache, page)
	}
	for s.cacheBytes+len(data) > CacheBytes && s.lru.Len() > 0 {
		front := s.lru.Front()
		entry := front.Value.(*pageCacheEntry)
		s.lru.Remove(front)
		s.cacheBytes -= len(entry.data)
		delete(s.cache, entry.page)
	}
	s.cacheBytes += len(data)
	element := s.lru.PushBack(&pageCacheEntry{page: page, data: data})
	s.cache[page] = element
}

func (s *Source) decryptPage(page uint32, raw []byte) ([]byte, error) {
	if !s.hmacMatches(page, raw) {
		return nil, corruptPageError(page, s.pageOffset(page),
			fmt.Sprintf("the page %s did not verify", s.params.HMAC.Name()))
	}
	return s.decryptVerified(page, raw), nil
}

// DecryptWALPage decrypts one committed WAL frame body. The frame HMAC is
// verified first. A page-1 frame whose salt differs from the database's is
// refused because it cannot belong to this database's WAL.
func (s *Source) DecryptWALPage(page uint32, raw []byte) ([]byte, error) {
	pageSize := int(s.pageSize)
	if page == 0 {
		return nil, walFrameError(page, "page number 0 is not a database page")
	}
	if len(raw) != pageSize {
		return nil, walFrameError(page, fmt.Sprintf(
			"the frame body is %d bytes, the profile uses %d", len(raw), pageSize,
		))
	}
	if page == 1 && !bytesEqual(raw[:SaltBytes], s.key.Salt[:]) {
		return nil, walFrameError(page, "the page-1 frame salt differs from the database salt")
	}
	if !s.hmacMatches(page, raw) {
		return nil, walFrameError(page, fmt.Sprintf("the frame %s did not verify", s.params.HMAC.Name()))
	}
	out := s.decryptVerified(page, raw)
	if page == 1 {
		if _, err := s.validatePage1(out); err != nil {
			return nil, walFrameError(page, err.Error())
		}
	}
	return out, nil
}

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf)
}

// ReadAtLossy uses the same strict path as ReadAt. SQLCipher pages are
// authenticated; returning zeroes for a failed page would fabricate plaintext.
func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf)
}

func (s *Source) readInner(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	length := s.Len()
	if offset >= length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), length)
	}
	want := int(minU64(length-offset, uint64(len(buf))))
	pageSize := uint64(s.pageSize)
	done := 0
	for done < want {
		position := offset + uint64(done)
		pageIndex := uint32(position / pageSize)
		inPage := int(position % pageSize)
		chunk := int(minU64(uint64(want-done), pageSize-uint64(inPage)))
		page, err := s.cachedPage(pageIndex + 1)
		if err != nil {
			return 0, intoSourceError(err, position)
		}
		copy(buf[done:done+chunk], page[inPage:inPage+chunk])
		done += chunk
	}
	s.counters.AddRead(done)
	return done, nil
}

func intoSourceError(err error, offset uint64) error {
	var sourceError *source.Error
	if errors.As(err, &sourceError) {
		return sourceError
	}
	var structured *Error
	if errors.As(err, &structured) {
		switch structured.Kind {
		case ErrCorruptPage:
			return source.NewCorrupt(offset, structured.Reason)
		case ErrWrongPassphrase, ErrNoProfile:
			return &source.Error{Kind: source.ErrDecrypt, Offset: offset, Reason: structured.Reason}
		case ErrUnsupported, ErrInvalidPageSize, ErrRawKey, ErrSaltMismatch:
			return &source.Error{Kind: source.ErrUnsupported, Offset: offset, Reason: structured.Error()}
		case ErrTruncated:
			return source.NewUnexpectedEOF(offset)
		default:
			return source.NewCorrupt(offset, structured.Error())
		}
	}
	return source.NewCorrupt(offset, err.Error())
}

func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.checkRange(offset, length); err != nil {
		return out, err
	}
	pageSize := uint64(s.pageSize)
	cursor := offset
	end := offset + length
	for cursor < end {
		pageStart := cursor / pageSize * pageSize
		chunk := minU64(pageStart+pageSize-cursor, end-cursor)
		out = append(out, source.ParentRange{
			Parent:       s.parent.SourceID(),
			ParentOffset: cursor,
			Len:          chunk,
			Kind:         source.RangeData,
		})
		cursor += chunk
	}
	return out, nil
}

func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	extents, err := s.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, extent := range extents {
		mapped, err := s.parent.MapToImage(extent.ParentOffset, extent.Len)
		if err != nil {
			return nil, err
		}
		out = append(out, mapped...)
	}
	return out, nil
}

var _ source.ByteSource = (*Source)(nil)

// EncryptDatabase encrypts a plaintext SQLite database in the profile's page
// format. It is the exact inverse of Source for fixtures. The IVs are derived
// deterministically from the HMAC key so output is byte-stable; real SQLCipher
// draws each IV from a CSPRNG, which the reader treats as opaque.
//
// This helper is intentionally exported for hermetic tests; the package is a
// reader.
func EncryptDatabase(plaintext []byte, salt [SaltBytes]byte, passphrase []byte, params Params) ([]byte, error) {
	key, err := DeriveKey(passphrase, salt, params)
	if err != nil {
		return nil, err
	}
	return EncryptDatabaseWithKey(plaintext, salt, key, params)
}

// EncryptDatabaseWithKey is EncryptDatabase with an already-derived key.
func EncryptDatabaseWithKey(plaintext []byte, salt [SaltBytes]byte, key Key, params Params) ([]byte, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	pageSize := int(params.PageSize)
	if len(plaintext) < pageSize || len(plaintext)%pageSize != 0 {
		return nil, unsupportedError(fmt.Sprintf(
			"a %d-byte plaintext that is not a whole number of %d-byte pages", len(plaintext), pageSize,
		))
	}
	if len(plaintext) < SaltBytes || string(plaintext[:SaltBytes]) != SQLiteMagic {
		return nil, unsupportedError("a plaintext database without the SQLite header")
	}
	block, err := aes.NewCipher(key.EncryptionKey[:])
	if err != nil {
		return nil, unsupportedError(fmt.Sprintf("AES-256 key: %v", err))
	}
	out := make([]byte, 0, len(plaintext))
	for index := 0; index < len(plaintext)/pageSize; index++ {
		page := plaintext[index*pageSize : (index+1)*pageSize]
		out = append(out, encryptPage(page, uint32(index+1), salt, key, block, params)...)
	}
	return out, nil
}

// EncryptWALPage encrypts one WAL frame body in the profile's page format.
func EncryptWALPage(plaintextPage []byte, page uint32, salt [SaltBytes]byte, passphrase []byte, params Params) ([]byte, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if page == 0 || len(plaintextPage) != int(params.PageSize) {
		return nil, unsupportedError(fmt.Sprintf(
			"a %d byte WAL page for page %d; the profile uses %d-byte pages numbered from 1",
			len(plaintextPage), page, params.PageSize,
		))
	}
	if page == 1 && string(plaintextPage[:SaltBytes]) != SQLiteMagic {
		return nil, unsupportedError("a WAL page 1 without the SQLite header")
	}
	key, err := DeriveKey(passphrase, salt, params)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key.EncryptionKey[:])
	if err != nil {
		return nil, unsupportedError(fmt.Sprintf("AES-256 key: %v", err))
	}
	return encryptPage(plaintextPage, page, salt, key, block, params), nil
}

func encryptPage(plaintextPage []byte, page uint32, salt [SaltBytes]byte, key Key, block cipher.Block, params Params) []byte {
	pageSize := int(params.PageSize)
	reserve := params.ReserveBytes()
	ivAt := pageSize - reserve
	macAt := ivAt + IVBytes
	digestBytes := params.HMAC.DigestBytes()
	start := 0
	if page == 1 {
		start = SaltBytes
	}
	encoded := make([]byte, pageSize)
	if page == 1 {
		copy(encoded[:SaltBytes], salt[:])
	}
	copy(encoded[start:ivAt], plaintextPage[start:ivAt])
	if page == 1 {
		encoded[20] = byte(reserve)
	}
	iv := deterministicIV(key.HMACKey[:], page)
	if ivAt > start {
		mode := cipher.NewCBCEncrypter(block, iv[:])
		mode.CryptBlocks(encoded[start:ivAt], encoded[start:ivAt])
	}
	copy(encoded[ivAt:ivAt+IVBytes], iv[:])
	if digestBytes > 0 {
		message := make([]byte, 0, macAt-start+4)
		message = append(message, encoded[start:macAt]...)
		var pageNumber [4]byte
		binary.LittleEndian.PutUint32(pageNumber[:], page)
		message = append(message, pageNumber[:]...)
		mac := params.HMAC.Compute(key.HMACKey[:], message)
		copy(encoded[macAt:macAt+digestBytes], mac)
	}
	return encoded
}

func deterministicIV(hmacKey []byte, page uint32) [IVBytes]byte {
	mac := hmac.New(sha512.New, hmacKey)
	mac.Write([]byte("sqlcipher-fixture-iv"))
	var pageNumber [4]byte
	binary.LittleEndian.PutUint32(pageNumber[:], page)
	mac.Write(pageNumber[:])
	sum := mac.Sum(nil)
	var iv [IVBytes]byte
	copy(iv[:], sum[:IVBytes])
	return iv
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
