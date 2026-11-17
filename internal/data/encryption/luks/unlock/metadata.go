package unlock

// LUKS2 metadata: the binary header, the JSON document, and the decoded
// records an unlock needs.
//
// The descriptive luks package intentionally keeps salts, digests and key
// areas out of its public records. Unlocking needs those bytes, so this
// package re-reads the header locally rather than changing the metadata
// reader. The document follows cryptsetup's format: Base64 salts and digests,
// and numbers that may be written either as JSON numbers or as JSON strings.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/laenix/ewfgo/internal/data/encryption/luks"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// MaxCryptoBytes bounds one Base64 salt or digest.
	MaxCryptoBytes = 256
	// MaxAreaBytes bounds the encrypted key-slot area this package reads.
	// cryptsetup's default is 256000 bytes.
	MaxAreaBytes uint64 = 64 * 1024 * 1024
)

// flexUint accepts a JSON number or a JSON string containing a decimal.
type flexUint uint64

func (f *flexUint) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		*f = 0
		return nil
	}
	if len(text) >= 2 && text[0] == '"' {
		var inner string
		if err := json.Unmarshal(data, &inner); err != nil {
			return err
		}
		text = strings.TrimSpace(inner)
		if text == "" {
			*f = 0
			return nil
		}
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return err
	}
	*f = flexUint(value)
	return nil
}

// jsonSize accepts a number, a numeric string, `"dynamic"`, or nothing.
type jsonSize struct {
	Set     bool
	Dynamic bool
	Value   uint64
}

func (s *jsonSize) UnmarshalJSON(data []byte) error {
	*s = jsonSize{}
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		return nil
	}
	if len(text) >= 2 && text[0] == '"' {
		var inner string
		if err := json.Unmarshal(data, &inner); err != nil {
			return err
		}
		text = strings.TrimSpace(inner)
		if text == "dynamic" {
			s.Dynamic = true
			return nil
		}
		if text == "" {
			return nil
		}
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return err
	}
	s.Value = value
	s.Set = true
	return nil
}

type kdfJSON struct {
	Type       string    `json:"type"`
	Hash       string    `json:"hash"`
	Iterations *flexUint `json:"iterations"`
	Time       *flexUint `json:"time"`
	Memory     *flexUint `json:"memory"`
	CPUs       *flexUint `json:"cpus"`
	Salt       *string   `json:"salt"`
}

type afJSON struct {
	Type    string    `json:"type"`
	Stripes *flexUint `json:"stripes"`
	Hash    string    `json:"hash"`
}

type areaJSON struct {
	Type       string    `json:"type"`
	Offset     *flexUint `json:"offset"`
	Size       *flexUint `json:"size"`
	Encryption string    `json:"encryption"`
	KeySize    *flexUint `json:"key_size"`
}

type keyslotJSON struct {
	Type    string    `json:"type"`
	KeySize *flexUint `json:"key_size"`
	KDF     *kdfJSON  `json:"kdf"`
	AF      *afJSON   `json:"af"`
	Area    *areaJSON `json:"area"`
}

type digestJSON struct {
	Type       string    `json:"type"`
	Keyslots   []string  `json:"keyslots"`
	Hash       string    `json:"hash"`
	Iterations *flexUint `json:"iterations"`
	Salt       *string   `json:"salt"`
	Digest     *string   `json:"digest"`
}

type segmentJSON struct {
	Type       string    `json:"type"`
	Offset     *flexUint `json:"offset"`
	Size       jsonSize  `json:"size"`
	IVTweak    *flexUint `json:"iv_tweak"`
	SectorSize *flexUint `json:"sector_size"`
	Encryption string    `json:"encryption"`
}

type metadataDocument struct {
	Keyslots *map[string]keyslotJSON `json:"keyslots"`
	Digests  map[string]digestJSON   `json:"digests"`
	Segments map[string]segmentJSON  `json:"segments"`
}

// luks2KDF is one key-derivation record.
type luks2KDF struct {
	kind       string
	hash       string
	iterations uint32
	passes     uint32
	memoryKiB  uint32
	lanes      uint32
	salt       []byte
}

type luks2Area struct {
	kind       string
	offset     uint64
	size       uint64
	keySize    int
	encryption string
}

type luks2Keyslot struct {
	index   int
	kind    string
	keySize int
	kdf     luks2KDF
	stripes uint32
	afHash  string
	area    luks2Area
}

type luks2Digest struct {
	kind       string
	keyslots   []int
	hash       string
	iterations uint32
	salt       []byte
	digest     []byte
}

type luks2Segment struct {
	index      int
	kind       string
	offset     uint64
	size       uint64
	hasSize    bool
	ivTweak    uint64
	sectorSize uint32
	encryption string
}

type luks2Metadata struct {
	headerSize   uint64
	headerOffset uint64
	keyslots     []luks2Keyslot
	digests      []luks2Digest
	segments     []luks2Segment
}

// readLUKS2Metadata reads and decodes the header and JSON document.
func readLUKS2Metadata(src source.ByteSource) (*luks2Metadata, error) {
	if src.Len() < uint64(luks.LUKS2BinaryHeaderBytes) {
		return nil, truncated(uint64(luks.LUKS2BinaryHeaderBytes), src.Len())
	}
	binaryHeader, err := source.ReadVecAt(src, 0, uint64(luks.LUKS2BinaryHeaderBytes))
	if err != nil {
		return nil, readError(err)
	}
	if !bytes.HasPrefix(binaryHeader, []byte(luks.Magic)) {
		return nil, ErrNotLUKS
	}
	version := binary.BigEndian.Uint16(binaryHeader[6:8])
	if version != 2 {
		if version == 1 {
			return nil, fmt.Errorf("%w: LUKS1 is not LUKS2 metadata", ErrUnsupportedVersion)
		}
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	headerSize := binary.BigEndian.Uint64(binaryHeader[8:16])
	if headerSize < uint64(luks.LUKS2BinaryHeaderBytes) {
		return nil, malformed("LUKS2 hdr_size %d is smaller than the binary header", headerSize)
	}
	if headerSize > luks.MaxHeaderBytes {
		return nil, fmt.Errorf("%w: declared %d bytes, limit %d", ErrHeaderTooLarge, headerSize, luks.MaxHeaderBytes)
	}
	if src.Len() < headerSize {
		return nil, truncated(headerSize, src.Len())
	}
	header, err := source.ReadVecAt(src, 0, headerSize)
	if err != nil {
		return nil, readError(err)
	}
	var headerOffset uint64
	if headerSize >= 0x108 {
		headerOffset = binary.BigEndian.Uint64(header[0x100:0x108])
	}
	if headerOffset != 0 {
		return nil, fmt.Errorf("%w: hdr_offset is %d", ErrDetachedHeader, headerOffset)
	}

	area := header[luks.LUKS2BinaryHeaderBytes:headerSize]
	end := len(area)
	for end > 0 && (area[end-1] == 0 || isJSONSpace(area[end-1])) {
		end--
	}
	if end == 0 {
		return nil, malformed("the LUKS2 metadata area is empty")
	}
	var document metadataDocument
	if err := json.Unmarshal(area[:end], &document); err != nil {
		return nil, malformed("the LUKS2 metadata area is not valid JSON: %v", err)
	}
	if document.Keyslots == nil {
		return nil, malformed("the LUKS2 metadata has no keyslots object")
	}
	keyslots, err := decodeKeyslots(*document.Keyslots)
	if err != nil {
		return nil, err
	}
	digests, err := decodeDigests(document.Digests)
	if err != nil {
		return nil, err
	}
	segments, err := decodeSegments(document.Segments)
	if err != nil {
		return nil, err
	}
	return &luks2Metadata{
		headerSize:   headerSize,
		headerOffset: headerOffset,
		keyslots:     keyslots,
		digests:      digests,
		segments:     segments,
	}, nil
}

func decodeKeyslots(members map[string]keyslotJSON) ([]luks2Keyslot, error) {
	names := make([]string, 0, len(members))
	for name := range members {
		if _, ok := parseNumericName(name); !ok {
			return nil, malformed("a LUKS2 key-slot name %q is not numeric", name)
		}
		names = append(names, name)
	}
	sortNumeric(names)
	out := make([]luks2Keyslot, 0, len(names))
	for _, name := range names {
		index, _ := parseNumericName(name)
		slot := members[name]
		if slot.KDF == nil {
			return nil, malformed("key slot %d has no kdf object", index)
		}
		if slot.AF == nil {
			return nil, malformed("key slot %d has no af object", index)
		}
		if slot.Area == nil {
			return nil, malformed("key slot %d has no area object", index)
		}
		keySize, ok := firstUint(slot.KeySize, slot.Area.KeySize)
		if !ok {
			return nil, malformed("key slot %d has no key_size", index)
		}
		kdf, err := decodeKDF(slot.KDF)
		if err != nil {
			return nil, err
		}
		if slot.AF.Stripes == nil {
			return nil, malformed("key slot %d has no af.stripes", index)
		}
		if uint64(*slot.AF.Stripes) > uint64(^uint32(0)) {
			return nil, malformed("key slot %d af.stripes is out of range", index)
		}
		if slot.Area.Offset == nil {
			return nil, malformed("key slot %d has no area.offset", index)
		}
		if slot.Area.Size == nil {
			return nil, malformed("key slot %d has no area.size", index)
		}
		if keySize > uint64(maxIntValue()) {
			return nil, malformed("key slot %d key_size is out of range", index)
		}
		areaKeySize := int(keySize)
		if slot.Area.KeySize != nil {
			if uint64(*slot.Area.KeySize) > uint64(maxIntValue()) {
				return nil, malformed("key slot %d area.key_size is out of range", index)
			}
			areaKeySize = int(*slot.Area.KeySize)
		}
		afHash := slot.AF.Hash
		if afHash == "" {
			afHash = "sha256"
		}
		out = append(out, luks2Keyslot{
			index:   index,
			kind:    slot.Type,
			keySize: int(keySize),
			kdf:     kdf,
			stripes: uint32(*slot.AF.Stripes),
			afHash:  afHash,
			area: luks2Area{
				kind:       slot.Area.Type,
				offset:     uint64(*slot.Area.Offset),
				size:       uint64(*slot.Area.Size),
				keySize:    areaKeySize,
				encryption: slot.Area.Encryption,
			},
		})
	}
	return out, nil
}

func decodeKDF(raw *kdfJSON) (luks2KDF, error) {
	kind := raw.Type
	out := luks2KDF{kind: kind}
	switch kind {
	case "pbkdf2":
		out.hash = raw.Hash
		if out.hash == "" {
			out.hash = "sha256"
		}
		if raw.Iterations == nil {
			return out, malformed("a pbkdf2 key slot has no kdf.iterations")
		}
		if uint64(*raw.Iterations) > uint64(^uint32(0)) {
			return out, malformed("kdf.iterations is out of range")
		}
		out.iterations = uint32(*raw.Iterations)
		salt, err := decodeSalt(raw.Salt, "kdf salt")
		if err != nil {
			return out, err
		}
		out.salt = salt
	case "argon2i", "argon2id":
		if raw.Time == nil {
			return out, malformed("an argon2 key slot has no kdf.time")
		}
		if raw.Memory == nil {
			return out, malformed("an argon2 key slot has no kdf.memory")
		}
		if raw.CPUs == nil {
			return out, malformed("an argon2 key slot has no kdf.cpus")
		}
		if uint64(*raw.Time) > uint64(^uint32(0)) {
			return out, malformed("kdf.time is out of range")
		}
		if uint64(*raw.Memory) > uint64(^uint32(0)) {
			return out, malformed("kdf.memory is out of range")
		}
		if uint64(*raw.CPUs) > uint64(^uint32(0)) {
			return out, malformed("kdf.cpus is out of range")
		}
		out.passes = uint32(*raw.Time)
		out.memoryKiB = uint32(*raw.Memory)
		out.lanes = uint32(*raw.CPUs)
		salt, err := decodeSalt(raw.Salt, "kdf salt")
		if err != nil {
			return out, err
		}
		out.salt = salt
	default:
		// Kept by name so the unlock can refuse it explicitly.
	}
	return out, nil
}

func decodeDigests(members map[string]digestJSON) ([]luks2Digest, error) {
	out := make([]luks2Digest, 0, len(members))
	for _, raw := range members {
		keyslots := numericKeyslots(raw.Keyslots)
		if len(keyslots) == 0 {
			// A digest that names no key slot cannot confirm a candidate
			// master key, so the unlock never consults it. Such a record may
			// legitimately be partial — the fixture corpus has a
			// description-only header whose digest carries only a type, hash
			// and iteration count — and refusing the whole document would make
			// an otherwise readable volume un-openable because of a record that
			// has no say in whether a key is accepted.
			continue
		}
		// A digest that does name a slot is the volume's own verification
		// step: both the salt and the expected digest must be present and
		// Base64 before any passphrase is tried.
		salt, err := decodeSalt(raw.Salt, "digest salt")
		if err != nil {
			return nil, err
		}
		digest, err := decodeSalt(raw.Digest, "digest")
		if err != nil {
			return nil, err
		}
		out = append(out, luks2Digest{
			kind:       raw.Type,
			keyslots:   keyslots,
			hash:       raw.Hash,
			iterations: uint32OrZero(raw.Iterations),
			salt:       salt,
			digest:     digest,
		})
	}
	return out, nil
}

func decodeSegments(members map[string]segmentJSON) ([]luks2Segment, error) {
	names := make([]string, 0, len(members))
	for name := range members {
		if _, ok := parseNumericName(name); !ok {
			return nil, malformed("a LUKS2 segment name %q is not numeric", name)
		}
		names = append(names, name)
	}
	sortNumeric(names)
	out := make([]luks2Segment, 0, len(names))
	for _, name := range names {
		index, _ := parseNumericName(name)
		raw := members[name]
		if raw.Offset == nil {
			return nil, malformed("segment %d has no offset", index)
		}
		sectorSize := uint32(512)
		if raw.SectorSize != nil {
			if uint64(*raw.SectorSize) > uint64(^uint32(0)) {
				return nil, malformed("segment %d sector_size is out of range", index)
			}
			sectorSize = uint32(*raw.SectorSize)
		}
		var ivTweak uint64
		if raw.IVTweak != nil {
			ivTweak = uint64(*raw.IVTweak)
		}
		out = append(out, luks2Segment{
			index:      index,
			kind:       raw.Type,
			offset:     uint64(*raw.Offset),
			size:       raw.Size.Value,
			hasSize:    raw.Size.Set,
			ivTweak:    ivTweak,
			sectorSize: sectorSize,
			encryption: raw.Encryption,
		})
	}
	return out, nil
}

func decodeSalt(text *string, what string) ([]byte, error) {
	if text == nil {
		return nil, malformed("the %s is missing", what)
	}
	if *text == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(*text)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(*text)
	}
	if err != nil {
		return nil, badBase64(what)
	}
	if len(decoded) > MaxCryptoBytes {
		return nil, malformed("the %s is %d bytes, over the %d-byte limit", what, len(decoded), MaxCryptoBytes)
	}
	return decoded, nil
}

func numericKeyslots(names []string) []int {
	out := make([]int, 0, len(names))
	for _, name := range names {
		if index, ok := parseNumericName(name); ok {
			out = append(out, index)
		}
	}
	return out
}

// parseNumericName accepts only an unsigned decimal that fits the platform's
// int; a leading sign is not a key-slot or segment index.
func parseNumericName(name string) (int, bool) {
	value, err := strconv.ParseUint(name, 10, 64)
	if err != nil || value > uint64(maxIntValue()) {
		return 0, false
	}
	return int(value), true
}

func firstUint(values ...*flexUint) (uint64, bool) {
	for _, value := range values {
		if value != nil {
			return uint64(*value), true
		}
	}
	return 0, false
}

func uint32OrZero(value *flexUint) uint32 {
	if value == nil {
		return 0
	}
	if uint64(*value) > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(*value)
}

func isJSONSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

func sortNumeric(names []string) {
	sort.Slice(names, func(i, j int) bool {
		left, leftOK := parseNumericName(names[i])
		right, rightOK := parseNumericName(names[j])
		if leftOK && rightOK {
			return left < right
		}
		return names[i] < names[j]
	})
}
