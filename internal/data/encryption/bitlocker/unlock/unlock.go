// Package unlock opens a BitLocker volume with a key protector and exposes its
// decrypted bytes as a source.ByteSource.
//
// It is an additive companion to the metadata-only bitlocker package: the
// volume header and metadata block are located by that package, and this
// package re-reads the entry area because the metadata reader deliberately does
// not retain key material.
//
// The chain implemented here is the documented BitLocker one:
//
//  1. A recovery password (eight six-digit groups, each divisible by eleven)
//     becomes a 16-byte key.
//  2. The key is stretched with the chain `updated || initial || salt || count`
//     for 1,048,576 SHA-256 rounds, the salt coming from the protector.
//  3. The protector's AES-CCM wrapped key yields the volume master key (VMK);
//     only a verified tag is accepted.
//  4. The full-volume encryption key (FVEK) entry is unwrapped under the VMK and
//     names the data cipher.
//  5. Sectors are decrypted with AES-XTS or AES-CBC, with the Elephant
//     diffuser for the 0x8000/0x8001 methods.
//
// A user password uses the same stretch over `SHA-256(SHA-256(UTF-16LE(p)))`.
// A startup key is used directly as the AES-CCM key. TPM/PIN protectors are
// not opened; a volume carrying only those returns the matching
// NoProtector error.
package unlock

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
	"github.com/laenix/ewfgo/internal/data/encryption/errs"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Data-plane constants.
const (
	// SectorBytes is the sector size BitLocker encrypts in.
	SectorBytes uint64 = 512
	// MaxBootScanBytes is how far into the volume the data-area search looks.
	MaxBootScanBytes uint64 = 16 * 1024 * 1024
	// BootSizeSlackBytes is how far a boot record's declared size may fall
	// short of the bytes that follow it and still be accepted.
	BootSizeSlackBytes uint64 = 1024 * 1024
	// VolumeFullyEncrypted is the metadata block state that may be opened.
	VolumeFullyEncrypted uint16 = 0x04
)

// Sentinel errors. Kind-specific wrong-key errors wrap ErrWrongPassphrase, so
// a caller may test either the exact kind or the umbrella.
var (
	// ErrNoMetadata means the volume's metadata block could not be read.
	ErrNoMetadata = errors.New("bitlocker unlock: no metadata")
	// ErrMalformedMetadata means the metadata bytes are present but invalid.
	ErrMalformedMetadata = errors.New("bitlocker unlock: malformed metadata")
	// ErrPasswordShape means a recovery password is not 48 digits in eight
	// groups of six.
	ErrPasswordShape = errors.New("bitlocker unlock: malformed recovery password")
	// ErrPasswordGroup means a recovery-password group is not divisible by 11.
	ErrPasswordGroup = errors.New("bitlocker unlock: recovery password group is not divisible by eleven")
	// ErrPasswordGroupRange means a group's quotient does not fit in 16 bits.
	ErrPasswordGroupRange = errors.New("bitlocker unlock: recovery password group is out of range")
	// ErrPasswordText means a user password is not valid UTF-8.
	ErrPasswordText = errors.New("bitlocker unlock: invalid user password")
	// ErrStartupKeySize means an external key is not 256 bits.
	ErrStartupKeySize = errors.New("bitlocker unlock: startup key is not 256 bits")
	// ErrUnsupportedMethod means the volume names a cipher this package does
	// not open.
	ErrUnsupportedMethod = errors.New("bitlocker unlock: unsupported encryption method")
	// ErrUnfinishedConversion means the metadata block is not in the
	// fully-encrypted state.
	ErrUnfinishedConversion = errors.New("bitlocker unlock: unfinished encryption conversion")
	// ErrNoRecoveryProtector means no VMK records a recovery-password
	// protector.
	ErrNoRecoveryProtector = errors.New("bitlocker unlock: no recovery-password protector")
	// ErrNoPasswordProtector means no VMK records a user-password protector.
	ErrNoPasswordProtector = errors.New("bitlocker unlock: no user-password protector")
	// ErrNoStartupKeyProtector means no VMK records a startup-key protector.
	ErrNoStartupKeyProtector = errors.New("bitlocker unlock: no startup-key protector")
	// ErrNoStretchKey means a protector that needs a salt records none.
	ErrNoStretchKey = errors.New("bitlocker unlock: protector records no stretch key")
	// ErrNoWrappedKey means a protector or the FVEK records no AES-CCM key.
	ErrNoWrappedKey = errors.New("bitlocker unlock: no AES-CCM wrapped key")
	// ErrWrongPassphrase is the umbrella for every key that failed its tag.
	ErrWrongPassphrase = errors.New("bitlocker unlock: wrong passphrase")
	// ErrWrongRecoveryPassword means every recovery-password protector failed
	// its tag.
	ErrWrongRecoveryPassword = fmt.Errorf("%w: recovery password", ErrWrongPassphrase)
	// ErrWrongPassword means every user-password protector failed its tag.
	ErrWrongPassword = fmt.Errorf("%w: user password", ErrWrongPassphrase)
	// ErrWrongStartupKey means every startup-key protector failed its tag.
	ErrWrongStartupKey = fmt.Errorf("%w: startup key", ErrWrongPassphrase)
	// ErrKeyContainer means a decrypted key container is not the documented
	// shape.
	ErrKeyContainer = errors.New("bitlocker unlock: malformed key container")
	// ErrKeySize means an FVEK's length does not match its method.
	ErrKeySize = errors.New("bitlocker unlock: key size does not match method")
	// ErrMethodMismatch means the metadata header and the FVEK name different
	// methods.
	ErrMethodMismatch = errors.New("bitlocker unlock: metadata and FVEK method mismatch")
	// ErrNoVolumeBootRecord means no sector in the search range decrypted to a
	// volume boot record.
	ErrNoVolumeBootRecord = errors.New("bitlocker unlock: no volume boot record")
	// ErrGeometry means the volume geometry leaves no usable data area.
	ErrGeometry = errors.New("bitlocker unlock: unusable volume geometry")
	// ErrTagMismatch means an AES-CCM tag did not verify. No plaintext is
	// returned with it.
	ErrTagMismatch = errors.New("bitlocker unlock: AES-CCM tag does not match")
)

// ProtectorKind is a key protector this package can open.
type ProtectorKind uint8

const (
	// RecoveryPassword is the 48-digit recovery password.
	RecoveryPassword ProtectorKind = iota + 1
	// Password is a user password stretched into an AES-CCM key.
	Password
	// StartupKey is a 256-bit external key used directly.
	StartupKey
)

// String returns the label a report prints.
func (k ProtectorKind) String() string {
	switch k {
	case RecoveryPassword:
		return "recovery password"
	case Password:
		return "user password"
	case StartupKey:
		return "startup key"
	default:
		return "unknown protector"
	}
}

// ProtectionType returns the protector type a VMK records for this kind.
func (k ProtectorKind) ProtectionType() uint16 {
	switch k {
	case RecoveryPassword:
		return bitlocker.ProtectRecoveryPassword
	case Password:
		return bitlocker.ProtectPassword
	case StartupKey:
		return bitlocker.ProtectStartupKey
	default:
		return 0
	}
}

func (k ProtectorKind) needsStretchKey() bool { return k != StartupKey }

func (k ProtectorKind) noProtector() error {
	switch k {
	case RecoveryPassword:
		return ErrNoRecoveryProtector
	case Password:
		return ErrNoPasswordProtector
	case StartupKey:
		return ErrNoStartupKeyProtector
	default:
		return fmt.Errorf("%w: unknown protector kind %d", ErrNoWrappedKey, k)
	}
}

func (k ProtectorKind) wrongKey(protectors int) error {
	switch k {
	case RecoveryPassword:
		return fmt.Errorf("%w: did not open any of the %d protector(s)", ErrWrongRecoveryPassword, protectors)
	case Password:
		return fmt.Errorf("%w: did not open any of the %d protector(s)", ErrWrongPassword, protectors)
	case StartupKey:
		return fmt.Errorf("%w: did not open any of the %d protector(s)", ErrWrongStartupKey, protectors)
	default:
		return fmt.Errorf("%w: unknown protector kind %d", ErrWrongPassphrase, k)
	}
}

// Unlocked is a BitLocker volume whose VMK and FVEK have been opened.
type Unlocked struct {
	method     uint16
	fvek       []byte
	vmk        []byte
	dataOffset uint64
	bootBackup *bootBackup
	length     uint64
	protectors int
	kind       ProtectorKind
}

// CipherMode returns the cipher description a report should print.
func (u *Unlocked) CipherMode() string {
	switch u.method {
	case bitlocker.MethodAES128CBCElephant:
		return "aes-128-cbc-elephant"
	case bitlocker.MethodAES256CBCElephant:
		return "aes-256-cbc-elephant"
	case bitlocker.MethodAES128CBC:
		return "aes-128-cbc"
	case bitlocker.MethodAES256CBC:
		return "aes-256-cbc"
	case bitlocker.MethodAES128XTS:
		return "aes-128-xts"
	default:
		return "aes-256-xts"
	}
}

// Method returns the raw encryption method code.
func (u *Unlocked) Method() uint16 { return u.method }

// MethodLabel returns the method as the format labels it.
func (u *Unlocked) MethodLabel() string { return bitlocker.EncryptionLabel(u.method) }

// Label returns a short label for reports.
func (u *Unlocked) Label() string {
	return fmt.Sprintf("BitLocker %s (%s)", u.MethodLabel(), u.kind)
}

// ProtectorKind returns which protector opened the volume.
func (u *Unlocked) ProtectorKind() ProtectorKind { return u.kind }

// KeyBytes returns the FVEK container's length. For the Elephant methods it
// includes the separate sector-key key, so it is not the AES key size; use
// CipherKeyBits for that.
func (u *Unlocked) KeyBytes() int { return len(u.fvek) }

// CipherKeyBits returns the AES key size the method defines.
func (u *Unlocked) CipherKeyBits() uint32 {
	switch u.method {
	case bitlocker.MethodAES128CBCElephant, bitlocker.MethodAES128CBC, bitlocker.MethodAES128XTS:
		return 128
	default:
		return 256
	}
}

// Protectors returns how many protectors of the kind that opened the volume
// were recorded.
func (u *Unlocked) Protectors() int { return u.protectors }

// DataOffset returns where the decrypted volume begins in the encrypted one.
func (u *Unlocked) DataOffset() uint64 { return u.dataOffset }

// VolumeMasterKey returns the VMK that unwrapped the FVEK, for a caller that
// needs to report the chain. The bytes are a copy; callers must not log them.
func (u *Unlocked) VolumeMasterKey() []byte { return append([]byte(nil), u.vmk...) }

// Open wraps the volume in a decrypting byte source.
func (u *Unlocked) Open(id source.ID, parent source.ByteSource) (*Source, error) {
	return newSource(id, parent, u.method, u.fvek, u.dataOffset, u.bootBackup, u.length)
}

// Unlock opens a volume with a recovery password.
//
// Every recovery-password protector is tried; the first wrapped key whose tag
// verifies wins, and a wrong password returns an error matching
// ErrWrongPassphrase (and ErrWrongRecoveryPassword) rather than a key that was
// never confirmed.
func Unlock(src source.ByteSource, info *bitlocker.Info, password []byte) (*Unlocked, error) {
	key, err := RecoveryKey(string(password))
	if err != nil {
		return nil, err
	}
	return unlockWith(src, info, RecoveryPassword, func(salt [SaltBytes]byte) ([StretchedBytes]byte, error) {
		return StretchKey(key, salt, StretchIterations), nil
	})
}

// UnlockWithPassword opens a volume with a user password.
//
// The password is encoded as UTF-16LE, double-hashed and stretched with each
// protector's own salt; the AES-CCM tag is the only thing that accepts it.
func UnlockWithPassword(src source.ByteSource, info *bitlocker.Info, password []byte) (*Unlocked, error) {
	// Validate the encoding once, even when the volume records no protector,
	// so a non-text password is refused as a password problem.
	if _, err := PasswordInitial(password); err != nil {
		return nil, err
	}
	return unlockWith(src, info, Password, func(salt [SaltBytes]byte) ([StretchedBytes]byte, error) {
		return StretchPassword(password, salt)
	})
}

// UnlockWithStartupKey opens a volume with a 256-bit startup (external) key.
//
// The key is used directly as the AES-CCM key; the format defines no stretch
// for this protector. A key of any other length is refused.
func UnlockWithStartupKey(src source.ByteSource, info *bitlocker.Info, key []byte) (*Unlocked, error) {
	if len(key) != StartupKeyBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrStartupKeySize, len(key))
	}
	var direct [StartupKeyBytes]byte
	copy(direct[:], key)
	return unlockWith(src, info, StartupKey, func([SaltBytes]byte) ([StretchedBytes]byte, error) {
		return direct, nil
	})
}

type deriveFunc func(salt [SaltBytes]byte) ([StretchedBytes]byte, error)

func unlockWith(src source.ByteSource, info *bitlocker.Info, kind ProtectorKind, derive deriveFunc) (*Unlocked, error) {
	if src == nil {
		return nil, fmt.Errorf("%w: nil source", ErrNoMetadata)
	}
	if info == nil || info.Metadata == nil {
		reason := infoReason(info)
		return nil, fmt.Errorf("%w: %s", ErrNoMetadata, reason)
	}
	metadata := info.Metadata
	// 0x04 is fully encrypted. 0x05 marks a conversion that did not finish; a
	// half-converted volume must not be read as if it were finished.
	if metadata.Block.State != VolumeFullyEncrypted {
		return nil, fmt.Errorf("%w: block state 0x%04x, not 0x0004", ErrUnfinishedConversion, metadata.Block.State)
	}
	headerMethod := metadata.Header.EncryptionMethod
	if sectorCipherKeyBytes(headerMethod) == 0 {
		return nil, unsupportedMethod(headerMethod)
	}

	entries, err := readMetadataEntries(src, info)
	if err != nil {
		return nil, err
	}

	protectors := 0
	var vmk []byte
	for _, entry := range entries {
		if entry.kind != bitlocker.EntryVolumeMasterKey || entry.protector == nil {
			continue
		}
		if entry.protector.protectionType != kind.ProtectionType() {
			continue
		}
		protectors++
		tree := collectEntries(entry)
		salt, hasSalt := findStretchSalt(tree)
		if !hasSalt && kind.needsStretchKey() {
			return nil, ErrNoStretchKey
		}
		derived, err := derive(salt)
		if err != nil {
			return nil, err
		}
		wrapped := collectWrappedKeys(tree)
		if len(wrapped) == 0 {
			return nil, ErrNoWrappedKey
		}
		for _, candidate := range wrapped {
			nonce, tag, ciphertext, ok := candidate.aesCCMParts()
			if !ok {
				continue
			}
			plaintext, err := ccmOpen(derived[:], nonce, nil, ciphertext, tag)
			if err != nil {
				// A tag that does not verify is a wrong key candidate. Other
				// CCM refusals (size) cannot be accepted either.
				continue
			}
			container, err := parseKeyContainer(plaintext)
			if err != nil {
				return nil, err
			}
			vmk = container.data
			break
		}
		if vmk != nil {
			break
		}
	}
	if protectors == 0 {
		return nil, kind.noProtector()
	}
	if vmk == nil {
		return nil, kind.wrongKey(protectors)
	}

	// The FVEK entry is wrapped under the VMK, and its own container names the
	// data cipher.
	var fvekError error
	var fvek *keyContainer
	for _, entry := range entries {
		if entry.kind != bitlocker.EntryFullVolumeEncryptionKey {
			continue
		}
		tree := collectEntries(entry)
		wrapped := collectWrappedKeys(tree)
		for _, candidate := range wrapped {
			nonce, tag, ciphertext, ok := candidate.aesCCMParts()
			if !ok {
				continue
			}
			plaintext, err := ccmOpen(vmk, nonce, nil, ciphertext, tag)
			if err != nil {
				if errors.Is(err, ErrTagMismatch) {
					fvekError = fmt.Errorf("%w: a tag the volume master key verifies", ErrKeyContainer)
				} else {
					fvekError = fmt.Errorf("%w: a decryptable key", ErrKeyContainer)
				}
				continue
			}
			container, err := parseKeyContainer(plaintext)
			if err != nil {
				return nil, err
			}
			fvek = container
			break
		}
		if fvek != nil {
			break
		}
	}
	if fvek == nil {
		if fvekError != nil {
			return nil, fvekError
		}
		return nil, fmt.Errorf("%w: the full volume encryption key", ErrNoWrappedKey)
	}
	method := fvek.method
	if sectorCipherKeyBytes(method) == 0 {
		return nil, unsupportedMethod(method)
	}
	if method != headerMethod {
		return nil, fmt.Errorf("%w: header 0x%04x, FVEK 0x%04x", ErrMethodMismatch, headerMethod, method)
	}
	cipher, err := newSectorCipher(method, fvek.data)
	if err != nil {
		return nil, err
	}

	dataOffset, bootBackup, err := findDataArea(src, cipher, info)
	if err != nil {
		return nil, err
	}
	if dataOffset > src.Len() {
		return nil, fmt.Errorf("%w: data offset %d past end %d", ErrGeometry, dataOffset, src.Len())
	}
	return &Unlocked{
		method:     method,
		fvek:       append([]byte(nil), fvek.data...),
		vmk:        append([]byte(nil), vmk...),
		dataOffset: dataOffset,
		bootBackup: bootBackup,
		length:     src.Len() - dataOffset,
		protectors: protectors,
		kind:       kind,
	}, nil
}

func infoReason(i *bitlocker.Info) string {
	if i == nil {
		return "no BitLocker volume information"
	}
	if i.MetadataError != "" {
		return i.MetadataError
	}
	return "the volume names no metadata block"
}

func unsupportedMethod(method uint16) error {
	return fmt.Errorf("%w: %s (0x%04x); only AES-XTS, AES-CBC and AES-CBC with the Elephant diffuser are opened",
		ErrUnsupportedMethod, bitlocker.EncryptionLabel(method), method)
}

// keyProtector is a VMK's protector record.
type keyProtector struct {
	id             [16]byte
	lastModified   uint64
	protectionType uint16
}

// metadataEntry is one entry, with its raw value retained so key material can
// be unwrapped. The metadata-only bitlocker package intentionally drops it.
type metadataEntry struct {
	kind       uint16
	valueType  uint16
	version    uint16
	size       uint16
	protector  *keyProtector
	keyMethod  *uint16
	keyPresent bool
	keyBytes   int
	value      []byte
	properties []metadataEntry
}

const (
	maxEntryDepth      = 4
	maxMetadataEntries = 4096
	maxKeyValueBytes   = 4096
	entryHeaderBytes   = 8
)

// readMetadataEntries re-reads the entry area located by the metadata-only
// reader and parses every entry, nested values included.
func readMetadataEntries(src source.ByteSource, info *bitlocker.Info) ([]metadataEntry, error) {
	metadata := info.Metadata
	if !metadata.Limited && metadata.Truncated > 0 {
		return nil, fmt.Errorf("%w: %w", ErrMalformedMetadata,
			errs.Truncated(uint64(metadata.Header.Size), src.Len()))
	}
	at := metadata.Offset + bitlocker.BlockHeaderBytes + bitlocker.MetadataHeaderBytes
	if at > src.Len() {
		return nil, fmt.Errorf("%w: %w", ErrMalformedMetadata, errs.Truncated(at, src.Len()))
	}
	size := uint64(metadata.Header.Size)
	if size < bitlocker.MetadataHeaderBytes {
		return nil, fmt.Errorf("%w: metadata size %d is smaller than its header", ErrMalformedMetadata, size)
	}
	entryBytes := size - bitlocker.MetadataHeaderBytes
	if entryBytes > bitlocker.MaxMetadataBytes {
		entryBytes = bitlocker.MaxMetadataBytes
	}
	available := src.Len() - at
	want := entryBytes
	if want > available {
		want = available
	}
	if want < entryBytes {
		return nil, fmt.Errorf("%w: %w", ErrMalformedMetadata,
			errs.Truncated(at+entryBytes, src.Len()))
	}
	data, err := source.ReadVecAt(src, at, want)
	if err != nil {
		return nil, err
	}
	entries, malformed := parseMetadataEntries(data, 0)
	if malformed != 0 {
		return nil, fmt.Errorf("%w: the entry area does not tile (%d problem(s))", ErrMalformedMetadata, malformed)
	}
	return entries, nil
}

func parseMetadataEntries(data []byte, depth int) ([]metadataEntry, int) {
	entries := make([]metadataEntry, 0)
	malformed := 0
	at := 0
	for at+entryHeaderBytes <= len(data) {
		size := le16(data, at)
		kind := le16(data, at+2)
		valueType := le16(data, at+4)
		version := le16(data, at+6)
		if kind == bitlocker.EntryNone && valueType == bitlocker.ValueErased && size == 0 {
			break
		}
		if size < entryHeaderBytes {
			malformed++
			break
		}
		end := at + int(size)
		if end > len(data) || len(entries) >= maxMetadataEntries {
			malformed++
			break
		}
		payload := data[at+entryHeaderBytes : end]
		entry := metadataEntry{
			kind:      kind,
			valueType: valueType,
			version:   version,
			size:      size,
		}
		switch valueType {
		case bitlocker.ValueVolumeMasterKey:
			if len(payload) >= 28 {
				protector := &keyProtector{
					lastModified:   le64(payload, 16),
					protectionType: le16(payload, 26),
				}
				copy(protector.id[:], payload[:16])
				entry.protector = protector
			}
		case bitlocker.ValueKey:
			if len(payload) >= 4 {
				method := le16(payload, 0)
				entry.keyMethod = &method
				entry.keyPresent = true
				entry.keyBytes = len(payload) - 4
			}
		case bitlocker.ValueStretchKey, bitlocker.ValueAESCCMKey:
			if len(payload) <= maxKeyValueBytes {
				entry.value = append([]byte(nil), payload...)
			} else {
				entry.keyPresent = true
				entry.keyBytes = len(payload)
			}
		}
		if depth < maxEntryDepth {
			if nested := nestedOffset(valueType); nested >= 0 && nested < len(payload) {
				properties, nestedMalformed := parseMetadataEntries(payload[nested:], depth+1)
				entry.properties = properties
				malformed += nestedMalformed
			}
		}
		entries = append(entries, entry)
		at = end
	}
	if at < len(data) && len(entries) == 0 {
		malformed++
	}
	return entries, malformed
}

func nestedOffset(valueType uint16) int {
	switch valueType {
	case bitlocker.ValueUseKey:
		return 4
	case bitlocker.ValueStretchKey:
		return 20
	case bitlocker.ValueVolumeMasterKey:
		return 28
	case bitlocker.ValueExternalKey:
		return 24
	case bitlocker.ValueUpdate:
		return 36
	default:
		return -1
	}
}

// collectEntries returns this entry and every entry nested in it.
func collectEntries(entry metadataEntry) []metadataEntry {
	out := []metadataEntry{entry}
	for _, property := range entry.properties {
		out = append(out, collectEntries(property)...)
	}
	return out
}

// collectWrappedKeys returns every AES-CCM wrapped key in the subtree.
func collectWrappedKeys(entries []metadataEntry) []metadataEntry {
	var out []metadataEntry
	for _, entry := range entries {
		if entry.valueType == bitlocker.ValueAESCCMKey {
			out = append(out, entry)
		}
	}
	return out
}

// findStretchSalt returns the first stretch-key salt in the subtree.
func findStretchSalt(entries []metadataEntry) ([SaltBytes]byte, bool) {
	var salt [SaltBytes]byte
	for _, entry := range entries {
		if entry.valueType != bitlocker.ValueStretchKey || len(entry.value) < 4+SaltBytes {
			continue
		}
		copy(salt[:], entry.value[4:4+SaltBytes])
		return salt, true
	}
	return salt, false
}

// aesCCMParts splits a wrapped key into its nonce, tag and ciphertext.
func (e metadataEntry) aesCCMParts() (nonce, tag, ciphertext []byte, ok bool) {
	if e.valueType != bitlocker.ValueAESCCMKey || len(e.value) < bitlocker.NonceBytes+16 {
		return nil, nil, nil, false
	}
	return e.value[:bitlocker.NonceBytes],
		e.value[bitlocker.NonceBytes : bitlocker.NonceBytes+16],
		e.value[bitlocker.NonceBytes+16:],
		true
}

// keyContainer is a decrypted key container: size, version, method, key data.
type keyContainer struct {
	method uint16
	data   []byte
}

func parseKeyContainer(bytes []byte) (*keyContainer, error) {
	if len(bytes) < 12 {
		return nil, fmt.Errorf("%w: size, version and method", ErrKeyContainer)
	}
	size := int(le32(bytes, 0))
	version := le16(bytes, 4)
	if version != 1 {
		return nil, fmt.Errorf("%w: version %d, not 1", ErrKeyContainer, version)
	}
	end := len(bytes)
	if size >= 12 && size <= len(bytes) {
		end = size
	}
	method := le16(bytes, 8)
	return &keyContainer{
		method: method,
		data:   append([]byte(nil), bytes[12:end]...),
	}, nil
}

func le16(b []byte, at int) uint16 {
	if at < 0 || at+2 > len(b) {
		return 0
	}
	return uint16(b[at]) | uint16(b[at+1])<<8
}

func le32(b []byte, at int) uint32 {
	if at < 0 || at+4 > len(b) {
		return 0
	}
	return uint32(b[at]) | uint32(b[at+1])<<8 | uint32(b[at+2])<<16 | uint32(b[at+3])<<24
}

func le64(b []byte, at int) uint64 {
	return uint64(le32(b, at)) | uint64(le32(b, at+4))<<32
}
