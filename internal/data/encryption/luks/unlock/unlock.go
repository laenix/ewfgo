// Package unlock opens a LUKS1 or LUKS2 volume with a passphrase and exposes
// its decrypted payload as a source.ByteSource.
//
// It is an additive companion to the metadata-only
// github.com/laenix/ewfgo/internal/data/encryption/luks package: that package
// deliberately publishes no salt, digest, key material or plaintext, so this
// package re-reads the header it needs. The chain is the format's own:
//
//  1. Derive the slot key from the passphrase with the slot's KDF:
//     PBKDF2-HMAC-SHA1/SHA256 (LUKS1), PBKDF2 with SHA-1, SHA-256, SHA-512 or
//     RIPEMD-160 (LUKS2), or Argon2i/Argon2id (LUKS2).
//  2. Read the slot's encrypted area and decrypt it with the area's own AES
//     mode, numbering sectors from the start of the volume.
//  3. Anti-forensically merge the striped plaintext into a candidate master
//     key.
//  4. Accept it only when the volume's digest confirms it: PBKDF2 over the
//     master key for LUKS1, or the LUKS2 digest that names this key slot.
//
// Step 4 is the format's own check. A wrong passphrase cannot produce a key
// that is then used: the attempt fails and the next slot is tried. No key is
// ever returned for an unverified slot.
//
// AES-XTS (plain64, plain64be, plain), AES-CBC-ESSIV-SHA256, AES-CBC-plain64
// and AES-CBC-plain are implemented locally over crypto/aes. Unknown ciphers,
// IV modes, hashes, KDFs, digests, key-slot and segment formats, detached
// headers, and out-of-range geometry are all refused explicitly by name.
package unlock

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/encryption/errs"
	"github.com/laenix/ewfgo/internal/data/encryption/luks"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Bounds applied before any derivation or allocation.
const (
	// LUKS1DigestBytes is the master-key digest length LUKS1 defines.
	LUKS1DigestBytes = 20
	// MaxKDFIterations is the largest PBKDF2 iteration count that will run.
	MaxKDFIterations uint64 = 10_000_000
	// MaxStripes is the largest anti-forensic stripe count accepted.
	MaxStripes uint64 = 1 << 20
	// MaxArgon2Passes is the largest Argon2 time cost that will run.
	MaxArgon2Passes uint32 = 1024
	// MaxArgon2MemoryKiB is the largest Argon2 memory cost that will be
	// allocated.
	MaxArgon2MemoryKiB = argon2MaxMemoryKiB
	// DMSectorBytes is dm-crypt's sector unit, and the unit key-slot areas use.
	DMSectorBytes uint64 = 512
	// MinLUKS2SectorBytes and MaxLUKS2SectorBytes bound a segment's encryption
	// sector size (powers of two only).
	MinLUKS2SectorBytes uint32 = 512
	MaxLUKS2SectorBytes uint32 = 4096
)

// Sentinel errors. Every failure wraps one of these, so callers test with
// errors.Is rather than matching message text.
var (
	// ErrNotLUKS means the source does not begin with the LUKS magic.
	ErrNotLUKS = errors.New("luks unlock: not a LUKS volume")
	// ErrUnsupportedVersion means the version is neither 1 nor 2.
	ErrUnsupportedVersion = errors.New("luks unlock: unsupported LUKS version")
	// ErrTruncated means the source ended before a declared structure did.
	ErrTruncated = errors.New("luks unlock: truncated structure")
	// ErrMalformed means the bytes are present but do not form the declared
	// structure.
	ErrMalformed = errors.New("luks unlock: malformed structure")
	// ErrHeaderTooLarge means a declared header exceeds the reader's limit.
	ErrHeaderTooLarge = errors.New("luks unlock: header too large")
	// ErrBadBase64 means a field the format stores as Base64 is not Base64.
	ErrBadBase64 = errors.New("luks unlock: invalid base64")
	// ErrDetachedHeader means the header declares a non-zero hdr_offset. The
	// reference reader does not resolve detached or relocated headers, so this
	// package refuses them instead of reading the wrong bytes.
	ErrDetachedHeader = errors.New("luks unlock: detached or relocated header is not supported")
	// ErrWrongPassphrase is the umbrella for a passphrase that opened no slot.
	ErrWrongPassphrase = errors.New("luks unlock: wrong passphrase")
	// ErrNoActiveKeyslot means no key slot holds material.
	ErrNoActiveKeyslot = errors.New("luks unlock: no key slot holds material")
	// ErrUnsupportedCipher means a cipher or IV mode is not implemented.
	ErrUnsupportedCipher = errors.New("luks unlock: unsupported cipher or mode")
	// ErrUnsupportedHash means a PBKDF2 or anti-forensic hash is not
	// implemented.
	ErrUnsupportedHash = errors.New("luks unlock: unsupported hash")
	// ErrUnsupportedKDF means a key slot names a KDF that is not implemented.
	ErrUnsupportedKDF = errors.New("luks unlock: unsupported key derivation function")
	// ErrUnsupportedFormat means a key slot or area format is not implemented.
	ErrUnsupportedFormat = errors.New("luks unlock: unsupported key-slot format")
	// ErrUnsupportedDigest means no digest that names a slot can be computed.
	ErrUnsupportedDigest = errors.New("luks unlock: unsupported digest")
	// ErrUnsupportedSegment means a segment is not a dm-crypt mapping.
	ErrUnsupportedSegment = errors.New("luks unlock: unsupported segment")
	// ErrUnsupportedSectorSize means a segment's encryption sector size is not
	// a power of two between 512 and 4096.
	ErrUnsupportedSectorSize = errors.New("luks unlock: unsupported encryption sector size")
	// ErrGeometry means the volume geometry leaves no usable payload or key
	// area.
	ErrGeometry = errors.New("luks unlock: unusable volume geometry")
	// ErrKeyBytes means a key size is not usable with the declared cipher.
	ErrKeyBytes = errors.New("luks unlock: key size is not usable with the cipher")
	// ErrIVSector means a sector number does not fit the mode's IV width.
	ErrIVSector = errors.New("luks unlock: sector number does not fit the IV")
	// ErrIterations means a PBKDF2 iteration count is outside the bound.
	ErrIterations = errors.New("luks unlock: PBKDF2 iteration count out of range")
	// ErrStripes means an anti-forensic stripe count is outside the bound.
	ErrStripes = errors.New("luks unlock: anti-forensic stripe count out of range")
	// ErrKeyslotOutside means a key slot's area lies outside the source.
	ErrKeyslotOutside = errors.New("luks unlock: key slot lies outside the source")
	// ErrSegmentLayout means the LUKS2 segments are not one contiguous payload.
	ErrSegmentLayout = errors.New("luks unlock: segment layout is not contiguous")
	// ErrSegmentOutside means a segment lies outside the source.
	ErrSegmentOutside = errors.New("luks unlock: segment lies outside the source")
	// ErrArgon2Passes means a slot's Argon2 time cost is outside the bound.
	ErrArgon2Passes = errors.New("luks unlock: argon2 pass count out of range")
	// ErrArgon2Parameters means Argon2 refused the slot's parameters.
	ErrArgon2Parameters = errors.New("luks unlock: argon2 parameters refused")
	// ErrAntiForensic means the stripe area could not be merged into a key.
	ErrAntiForensic = errors.New("luks unlock: anti-forensic merge failed")
	// ErrNoDigest means no digest can confirm a candidate master key.
	ErrNoDigest = errors.New("luks unlock: no digest confirms a candidate key")
	// ErrKDF means a key derivation failed before producing output.
	ErrKDF = errors.New("luks unlock: key derivation failed")
	// ErrCipherBlockSize means a data unit is not a whole number of AES
	// blocks where the cipher requires it.
	ErrCipherBlockSize = errors.New("luks unlock: cipher data unit is not block aligned")
	// ErrSource means the parent source could not supply the requested bytes.
	ErrSource = errors.New("luks unlock: source read failed")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrMalformed, errs.ErrMalformed, fmt.Sprintf(format, args...))
}

func truncated(need, got uint64) error {
	return fmt.Errorf("%w: %w: need %d bytes, source holds %d", ErrTruncated, errs.ErrTruncated, need, got)
}

func badBase64(what string) error {
	return fmt.Errorf("%w: %w: %s", ErrBadBase64, errs.ErrBadBase64, what)
}

func readError(err error) error {
	return fmt.Errorf("%w: %w", ErrSource, err)
}

func kdfErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrKDF, fmt.Sprintf(format, args...))
}

func argon2Errorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrArgon2Parameters, fmt.Sprintf(format, args...))
}

func afErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrAntiForensic, fmt.Sprintf(format, args...))
}

// Unlocked is a LUKS volume opened by a passphrase.
//
// The master key is private to this type; MasterKey returns a copy and Open
// wraps it in a decrypting source. A value is only produced after the volume's
// own digest confirmed the key.
type Unlocked struct {
	// Version is 1 or 2.
	Version int
	// Keyslot is the index of the slot that opened.
	Keyslot int
	// KDF is "pbkdf2", "argon2i" or "argon2id".
	KDF string
	// Cipher is the cipher name ("aes").
	Cipher string
	// Mode is the canonical IV mode ("xts-plain64", "cbc-essiv:sha256", ...).
	Mode string
	// KeyBytes is the master-key size.
	KeyBytes int
	// Stripes is the anti-forensic stripe count of the slot that opened.
	Stripes uint64
	// Iterations is the slot's PBKDF2 iteration count (0 for Argon2).
	Iterations uint64
	// AreaOffset is where the slot's encrypted area begins, in bytes.
	AreaOffset uint64
	// PayloadOffset is where the encrypted payload begins, in bytes.
	PayloadOffset uint64
	// PayloadLen is the logical payload length.
	PayloadLen uint64
	// IVTweak is the tweak of the payload's first data unit.
	IVTweak uint64

	segments  []segmentPlan
	masterKey []byte
}

// CipherMode returns the cipher and mode as one label.
func (u *Unlocked) CipherMode() string {
	if u.Cipher == "" {
		return u.Mode
	}
	return u.Cipher + "-" + u.Mode
}

// Label returns a short line for a report.
func (u *Unlocked) Label() string {
	if u.Version == 1 {
		return fmt.Sprintf("LUKS1 (key slot %d)", u.Keyslot)
	}
	return fmt.Sprintf("LUKS%d %s (key slot %d)", u.Version, u.KDF, u.Keyslot)
}

// MasterKey returns a copy of the confirmed master key.
func (u *Unlocked) MasterKey() []byte {
	if u == nil || u.masterKey == nil {
		return nil
	}
	out := make([]byte, len(u.masterKey))
	copy(out, u.masterKey)
	return out
}

// Open wraps the decrypted payload in a decrypting byte source.
//
// id is the identifier the caller's source graph gives the new node and
// parent is the encrypted volume the header was read from.
func (u *Unlocked) Open(id source.ID, parent source.ByteSource) (*Source, error) {
	if u == nil {
		return nil, fmt.Errorf("%w: nil unlocked volume", ErrGeometry)
	}
	return newSource(id, parent, u.segments, u.masterKey)
}

// Unlock detects LUKS1 or LUKS2 from the magic and opens the volume with
// passphrase. It returns an error unless a digest confirmed the recovered key.
func Unlock(src source.ByteSource, passphrase []byte) (*Unlocked, error) {
	if src == nil {
		return nil, fmt.Errorf("%w: nil source", ErrSource)
	}
	if src.Len() < 6 {
		return nil, ErrNotLUKS
	}
	head, err := source.ReadVecAt(src, 0, 8)
	if err != nil {
		return nil, readError(err)
	}
	if string(head[:6]) != luks.Magic {
		return nil, ErrNotLUKS
	}
	switch version := binary.BigEndian.Uint16(head[6:8]); version {
	case 1:
		return unlockLUKS1(src, passphrase)
	case 2:
		return unlockLUKS2(src, passphrase)
	default:
		return nil, fmt.Errorf("%w: %w: %d", ErrUnsupportedVersion, errs.ErrUnknownVersion, version)
	}
}

// UnlockLUKS1 opens a LUKS1 volume with passphrase.
func UnlockLUKS1(src source.ByteSource, passphrase []byte) (*Unlocked, error) {
	return unlockLUKS1(src, passphrase)
}

// UnlockLUKS2 opens a LUKS2 volume with passphrase.
func UnlockLUKS2(src source.ByteSource, passphrase []byte) (*Unlocked, error) {
	return unlockLUKS2(src, passphrase)
}

// segmentPlan is one validated LUKS2 crypt segment in logical order.
type segmentPlan struct {
	index          int
	logicalOffset  uint64
	physicalOffset uint64
	size           uint64
	ivTweak        uint64
	sectorSize     uint32
	spec           cipherSpec
	encryption     string
}

func unlockLUKS2(src source.ByteSource, passphrase []byte) (*Unlocked, error) {
	metadata, err := readLUKS2Metadata(src)
	if err != nil {
		return nil, err
	}
	if len(metadata.keyslots) == 0 {
		return nil, ErrNoActiveKeyslot
	}
	segments, err := planSegments(metadata.segments, src.Len())
	if err != nil {
		return nil, err
	}
	last := segments[len(segments)-1]
	payloadLen := last.logicalOffset + last.size

	var tried []int
	checked := 0
	unsupportedDigest := ""
	for _, slot := range metadata.keyslots {
		tried = append(tried, slot.index)
		if !strings.EqualFold(slot.kind, "luks2") {
			return nil, fmt.Errorf("%w: key slot %d type %q", ErrUnsupportedFormat, slot.index, slot.kind)
		}
		if !strings.EqualFold(slot.area.kind, "raw") {
			return nil, fmt.Errorf("%w: key slot %d area type %q", ErrUnsupportedFormat, slot.index, slot.area.kind)
		}
		if !strings.EqualFold(slot.afHash, "sha256") {
			return nil, fmt.Errorf("%w: key slot %d anti-forensic hash %q", ErrUnsupportedHash, slot.index, slot.afHash)
		}
		if slot.stripes == 0 || uint64(slot.stripes) > MaxStripes {
			return nil, fmt.Errorf("%w: key slot %d declares %d stripes (1..=%d allowed)",
				ErrStripes, slot.index, slot.stripes, MaxStripes)
		}
		keyBytes := slot.keySize
		for _, plan := range segments {
			if !plan.spec.acceptsKey(keyBytes) {
				return nil, fmt.Errorf("%w: a %d-byte volume key with %s", ErrKeyBytes, keyBytes, plan.spec.name)
			}
		}
		areaSpec, err := parseEncryption(slot.area.encryption)
		if err != nil {
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}
		if !areaSpec.acceptsKey(slot.area.keySize) {
			return nil, fmt.Errorf("%w: key slot %d area key of %d bytes", ErrKeyBytes, slot.index, slot.area.keySize)
		}

		slotKey, err := deriveSlotKey(slot, passphrase)
		if err != nil {
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}
		needed := uint64(keyBytes) * uint64(slot.stripes)
		needed = (needed + DMSectorBytes - 1) / DMSectorBytes * DMSectorBytes
		if slot.area.size < needed {
			zeroBytes(slotKey)
			return nil, fmt.Errorf("%w: key slot %d area holds %d bytes, needs %d",
				ErrGeometry, slot.index, slot.area.size, needed)
		}
		// The declared area is validated in full (capped to the read limit),
		// even though only the stripe bytes are read.
		areaBytes := slot.area.size
		if areaBytes > MaxAreaBytes {
			areaBytes = MaxAreaBytes
		}
		if areaBytes < needed {
			zeroBytes(slotKey)
			return nil, fmt.Errorf("%w: key slot %d area within the %d-byte limit",
				ErrGeometry, slot.index, MaxAreaBytes)
		}
		if slot.area.offset > src.Len() || areaBytes > src.Len()-slot.area.offset {
			zeroBytes(slotKey)
			return nil, fmt.Errorf("%w: key slot %d needs %d bytes at offset %d but the source holds %d bytes",
				ErrKeyslotOutside, slot.index, areaBytes, slot.area.offset, src.Len())
		}
		area, err := source.ReadVecAt(src, slot.area.offset, needed)
		if err != nil {
			zeroBytes(slotKey)
			return nil, readError(err)
		}
		areaCipher, err := newSectorCipher(areaSpec, slotKey)
		if err != nil {
			zeroBytes(slotKey)
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}
		if err := decryptArea(areaCipher, area, slot.area.offset); err != nil {
			zeroBytes(slotKey)
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}
		zeroBytes(slotKey)
		candidate, err := afMerge(area[:uint64(keyBytes)*uint64(slot.stripes)], keyBytes)
		zeroBytes(area)
		if err != nil {
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}

		verified := false
		for _, digest := range metadata.digests {
			if !containsInt(digest.keyslots, slot.index) {
				continue
			}
			verdict, detail, err := checkDigest(digest, candidate, slot.index)
			if err != nil {
				return nil, err
			}
			switch verdict {
			case digestVerified:
				verified = true
			case digestMismatch:
				checked++
			case digestUnsupported:
				if unsupportedDigest == "" {
					unsupportedDigest = detail
				}
			}
		}
		if verified {
			return &Unlocked{
				Version:       2,
				Keyslot:       slot.index,
				KDF:           kdfName(slot.kdf),
				Cipher:        "aes",
				Mode:          segments[0].spec.name,
				KeyBytes:      keyBytes,
				Stripes:       uint64(slot.stripes),
				Iterations:    uint64(slot.kdf.iterations),
				AreaOffset:    slot.area.offset,
				PayloadOffset: segments[0].physicalOffset,
				PayloadLen:    payloadLen,
				IVTweak:       segments[0].ivTweak,
				segments:      segments,
				masterKey:     candidate,
			}, nil
		}
		zeroBytes(candidate)
	}
	if checked == 0 && unsupportedDigest != "" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedDigest, unsupportedDigest)
	}
	return nil, fmt.Errorf("%w: tried key slots %v", ErrWrongPassphrase, tried)
}

// planSegments validates the LUKS2 crypt segments and turns them into one
// contiguous logical payload.
func planSegments(segments []luks2Segment, sourceLen uint64) ([]segmentPlan, error) {
	if len(segments) == 0 {
		return nil, fmt.Errorf("%w: no LUKS2 segments", ErrGeometry)
	}
	last := len(segments) - 1
	plans := make([]segmentPlan, 0, len(segments))
	var logicalOffset uint64
	var previousEnd uint64
	havePrevious := false
	for position, segment := range segments {
		if !strings.EqualFold(segment.kind, "crypt") {
			return nil, fmt.Errorf("%w: segment %d is a %q mapping", ErrUnsupportedSegment, segment.index, segment.kind)
		}
		spec, err := parseEncryption(segment.encryption)
		if err != nil {
			return nil, fmt.Errorf("segment %d: %w", segment.index, err)
		}
		if !validSectorSize(segment.sectorSize) {
			return nil, fmt.Errorf("%w: segment %d uses %d-byte sectors", ErrUnsupportedSectorSize, segment.index, segment.sectorSize)
		}
		if !segment.hasSize && position != last {
			return nil, fmt.Errorf("%w: segment %d: only the last segment may be dynamic", ErrSegmentLayout, segment.index)
		}
		if segment.offset > sourceLen {
			return nil, fmt.Errorf("%w: segment %d needs [%d, +0) but the source holds %d bytes",
				ErrSegmentOutside, segment.index, segment.offset, sourceLen)
		}
		size := segment.size
		if !segment.hasSize {
			size = sourceLen - segment.offset
		}
		if size == 0 {
			return nil, fmt.Errorf("%w: segment %d has no bytes", ErrSegmentLayout, segment.index)
		}
		if size > sourceLen-segment.offset {
			return nil, fmt.Errorf("%w: segment %d needs [%d, %d) but the source holds %d bytes",
				ErrSegmentOutside, segment.index, segment.offset, segment.offset+size, sourceLen)
		}
		if havePrevious {
			if segment.offset < previousEnd {
				return nil, fmt.Errorf("%w: segment %d overlaps the previous segment", ErrSegmentLayout, segment.index)
			}
			if segment.offset > previousEnd {
				return nil, fmt.Errorf("%w: segment %d leaves a gap after the previous segment", ErrSegmentLayout, segment.index)
			}
		}
		units := size / uint64(segment.sectorSize)
		if size%uint64(segment.sectorSize) != 0 {
			units++
		}
		if segment.ivTweak > ^uint64(0)-units {
			return nil, fmt.Errorf("%w: segment %d IV tweak runs past the sector range", ErrSegmentLayout, segment.index)
		}
		if logicalOffset > ^uint64(0)-size {
			return nil, fmt.Errorf("%w: segment %d overflows the logical payload length", ErrSegmentLayout, segment.index)
		}
		plans = append(plans, segmentPlan{
			index:          segment.index,
			logicalOffset:  logicalOffset,
			physicalOffset: segment.offset,
			size:           size,
			ivTweak:        segment.ivTweak,
			sectorSize:     segment.sectorSize,
			spec:           spec,
			encryption:     segment.encryption,
		})
		logicalOffset += size
		previousEnd = segment.offset + size
		havePrevious = true
	}
	return plans, nil
}

func validSectorSize(bytes uint32) bool {
	return bytes >= MinLUKS2SectorBytes && bytes <= MaxLUKS2SectorBytes && bytes&(bytes-1) == 0
}

func deriveSlotKey(slot luks2Keyslot, passphrase []byte) ([]byte, error) {
	switch slot.kdf.kind {
	case "pbkdf2":
		hash, ok := pbkdf2HashByName(slot.kdf.hash, false)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedHash, slot.kdf.hash)
		}
		if uint64(slot.kdf.iterations) > MaxKDFIterations {
			return nil, fmt.Errorf("%w: %d iterations, limit %d", ErrIterations, slot.kdf.iterations, MaxKDFIterations)
		}
		return pbkdf2Key(hash.new, passphrase, slot.kdf.salt, slot.kdf.iterations, slot.area.keySize)
	case "argon2i", "argon2id":
		if slot.kdf.passes > MaxArgon2Passes {
			return nil, fmt.Errorf("%w: %d passes, limit %d", ErrArgon2Passes, slot.kdf.passes, MaxArgon2Passes)
		}
		variant, _ := argon2VariantByName(slot.kdf.kind)
		key, err := argon2Hash(argon2Params{
			variant:   variant,
			passes:    slot.kdf.passes,
			memoryKiB: slot.kdf.memoryKiB,
			lanes:     slot.kdf.lanes,
			tagBytes:  slot.area.keySize,
		}, passphrase, slot.kdf.salt, nil, nil)
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKDF, slot.kdf.kind)
	}
}

func kdfName(kdf luks2KDF) string {
	return kdf.kind
}

type digestVerdict uint8

const (
	digestMismatch digestVerdict = iota
	digestVerified
	digestUnsupported
)

func checkDigest(digest luks2Digest, key []byte, slot int) (digestVerdict, string, error) {
	if !strings.EqualFold(digest.kind, "pbkdf2") {
		return digestUnsupported, digest.kind + " digest", nil
	}
	hash, ok := pbkdf2HashByName(digest.hash, false)
	if !ok {
		return digestUnsupported, digest.hash + " digest hash", nil
	}
	if uint64(digest.iterations) > MaxKDFIterations {
		return digestMismatch, "", fmt.Errorf("%w: digest for key slot %d uses %d iterations, limit %d",
			ErrIterations, slot, digest.iterations, MaxKDFIterations)
	}
	if len(digest.digest) == 0 || len(digest.digest) > hash.size {
		return digestMismatch, "", fmt.Errorf("%w: digest for key slot %d is %d bytes",
			ErrGeometry, slot, len(digest.digest))
	}
	computed, err := pbkdf2Key(hash.new, key, digest.salt, digest.iterations, len(digest.digest))
	if err != nil {
		return digestMismatch, "", err
	}
	if subtle.ConstantTimeCompare(computed, digest.digest) == 1 {
		return digestVerified, "", nil
	}
	return digestMismatch, "", nil
}

func decryptArea(cipher *sectorCipher, area []byte, offset uint64) error {
	first := offset / DMSectorBytes
	for index := 0; index < len(area); index += int(DMSectorBytes) {
		end := index + int(DMSectorBytes)
		if end > len(area) {
			end = len(area)
		}
		number := first + uint64(index/int(DMSectorBytes))
		if err := cipher.decryptSector(number, area[index:end]); err != nil {
			return err
		}
	}
	return nil
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
