// Package luks reads the headers and JSON key-slot metadata of LUKS1 and LUKS2
// volumes without a key.
//
// LUKS1 is a 592-byte big-endian header: cipher, mode, hash, payload offset,
// key size, master-key digest parameters, UUID, and eight 48-byte key-slot
// descriptors. LUKS2 is a 4096-byte binary header followed by a JSON metadata
// area: key slots with their KDF parameters, digests, crypt segments, tokens
// and configuration flags.
//
// The reader reports KDF parameters (PBKDF2 hash and iteration count, Argon2
// time, memory and parallelism), salts by presence and length, and key
// material by presence and length. It never publishes a salt, a digest, an
// encrypted key area, a derived key, or decrypted payload. Unlocking,
// executing a KDF, deriving a key, and decrypting are refused with
// ErrUnsupported (see Info.Unsupported).
package luks

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/encryption/errs"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Magic is the six-byte LUKS signature, shared by versions 1 and 2.
	Magic = "LUKS\xba\xbe"
	// LUKS1HeaderBytes is the fixed LUKS1 header size.
	LUKS1HeaderBytes = 592
	// LUKS2BinaryHeaderBytes is the size of the LUKS2 binary header.
	LUKS2BinaryHeaderBytes = 4096
	// MaxHeaderBytes is the largest declared header this reader loads.
	MaxHeaderBytes uint64 = 16 * 1024 * 1024
	// LUKS1Keyslots is the number of key-slot descriptors in a LUKS1 header.
	LUKS1Keyslots = 8
	// LUKS1KeyslotBytes is the size of one LUKS1 key-slot descriptor.
	LUKS1KeyslotBytes = 48
	// LUKS1KeyslotActive is the marker in an active LUKS1 key slot.
	LUKS1KeyslotActive uint32 = 0x00ac71f3
)

// Operations this package refuses by name.
const (
	UnsupportedUnlock         = "unlock"
	UnsupportedKeyDerivation  = "key-derivation execution"
	UnsupportedDecrypt        = "decrypt"
	UnsupportedHiddenVolume   = "hidden volume"
	UnsupportedCipherDispatch = "cipher dispatch"
)

// ChecksumStatus is the outcome of checking a LUKS2 header checksum.
type ChecksumStatus uint8

const (
	// ChecksumUnknown means no checksum was checked (an unknown algorithm or
	// a header too short to carry one).
	ChecksumUnknown ChecksumStatus = iota
	// ChecksumValid means the stored digest matches the computed one.
	ChecksumValid
	// ChecksumMismatch means the stored digest does not match.
	ChecksumMismatch
)

// String returns the report label.
func (c ChecksumStatus) String() string {
	switch c {
	case ChecksumValid:
		return "valid"
	case ChecksumMismatch:
		return "mismatch"
	default:
		return "unknown"
	}
}

// Keyslot is one LUKS key slot. Salts and key areas are described, never
// carried.
type Keyslot struct {
	Index          int
	Active         bool
	Kind           string
	KDF            string
	Hash           string
	Iterations     uint64
	MemoryKiB      uint64
	Parallelism    uint64
	Stripes        uint64
	KeySize        uint64
	AreaOffset     uint64
	AreaSize       uint64
	AreaEncryption string
	SaltPresent    bool
	SaltBytes      int
}

// Digest is one LUKS2 master-key digest. The digest and salt bytes are not
// carried, only their presence and length.
type Digest struct {
	Kind          string
	Keyslots      []int
	Hash          string
	Iterations    uint64
	SaltPresent   bool
	SaltBytes     int
	DigestPresent bool
	DigestBytes   int
}

// Segment is one LUKS2 crypt segment.
type Segment struct {
	Index       int
	Kind        string
	Offset      uint64
	Size        uint64
	SizeSet     bool
	SizeDynamic bool
	IVTweak     uint64
	SectorSize  uint32
	Encryption  string
}

// Info is the identity and parameters of a LUKS volume.
type Info struct {
	Version int
	// VolumeBytes is the source length, the best available volume size.
	VolumeBytes uint64
	// SectorSize is the segment sector size for LUKS2, or the source hint for
	// LUKS1.
	SectorSize uint32
	// Cipher is the LUKS1 cipher name; for LUKS2 it is the segment's full
	// encryption string.
	Cipher string
	// Mode is the LUKS1 cipher mode; LUKS2 records the whole string in Cipher.
	Mode string
	// Hash is the LUKS1 PBKDF hash.
	Hash  string
	UUID  string
	Label string
	// Subsystem is LUKS2's subsystem string.
	Subsystem string
	// PayloadOffset is where the encrypted payload begins, in bytes.
	PayloadOffset    uint64
	PayloadOffsetSet bool
	// KeyBytes is the LUKS1 master-key size.
	KeyBytes    uint64
	KeyBytesSet bool
	// HeaderBytes is the declared header size (592 for LUKS1).
	HeaderBytes uint64
	// Sequence is LUKS2's sequence id.
	Sequence    uint64
	SequenceSet bool
	// HeaderOffset is LUKS2's hdr_offset.
	HeaderOffset    uint64
	HeaderOffsetSet bool
	// ChecksumAlgorithm and Checksum describe the LUKS2 header check.
	ChecksumAlgorithm string
	Checksum          ChecksumStatus
	// SecondaryHeader reports a second header at HeaderBytes.
	SecondaryHeader bool
	Keyslots        []Keyslot
	ActiveKeyslots  int
	Tokens          int
	Digests         []Digest
	Segments        []Segment
	Flags           []string
	// MKDigest* describe the LUKS1 master-key digest without carrying it.
	MKDigestPresent     bool
	MKDigestBytes       int
	MKDigestSaltPresent bool
	MKDigestSaltBytes   int
	MKDigestIterations  uint64
	// Unsupported lists operations this metadata-only reader does not
	// perform for the volume.
	Unsupported []string
}

// EncryptionMethod returns the cipher and mode as one label.
func (i *Info) EncryptionMethod() string {
	if i.Cipher == "" {
		return ""
	}
	if i.Mode == "" {
		return i.Cipher
	}
	return i.Cipher + "-" + i.Mode
}

// HasActiveKeyslot reports whether at least one key slot can be opened.
func (i *Info) HasActiveKeyslot() bool { return i.ActiveKeyslotCount() > 0 }

// ActiveKeyslotCount returns the number of key slots carrying material.
func (i *Info) ActiveKeyslotCount() int { return i.ActiveKeyslots }

// Describe returns one line for a report.
func (i *Info) Describe() string {
	cipher := i.EncryptionMethod()
	if cipher == "" {
		cipher = "(cipher not recorded)"
	}
	return fmt.Sprintf("LUKS%d (%s), %d active key slot(s), header %d B",
		i.Version, cipher, i.ActiveKeyslots, i.HeaderBytes)
}

// Read parses the LUKS header at the start of src.
//
// It returns nil, nil when the source does not start with the LUKS magic. A
// truncated or malformed header of a recognized version is an explicit error.
func Read(src source.ByteSource) (*Info, error) {
	length := src.Len()
	if length < 6 {
		return nil, nil
	}
	headLen := min(length, uint64(LUKS2BinaryHeaderBytes))
	head, err := source.ReadVecAt(src, 0, headLen)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(head, []byte(Magic)) {
		return nil, nil
	}
	if len(head) < 8 {
		return nil, errs.Truncated(8, length)
	}
	version := binary.BigEndian.Uint16(head[6:8])
	switch version {
	case 1:
		return readLUKS1(src, length)
	case 2:
		return readLUKS2(src, length, head)
	default:
		return nil, errs.UnknownVersion(version)
	}
}

func readLUKS1(src source.ByteSource, length uint64) (*Info, error) {
	if length < LUKS1HeaderBytes {
		return nil, errs.Truncated(LUKS1HeaderBytes, length)
	}
	head, err := source.ReadVecAt(src, 0, LUKS1HeaderBytes)
	if err != nil {
		return nil, err
	}
	info := &Info{
		Version:     1,
		VolumeBytes: length,
		SectorSize:  src.SectorSize(),
		Cipher:      luksString(head, 0x08, 32),
		Mode:        luksString(head, 0x28, 32),
		Hash:        luksString(head, 0x48, 32),
		UUID:        luksString(head, 0xa8, 40),
		HeaderBytes: LUKS1HeaderBytes,
		Unsupported: luksUnsupported(),
	}
	info.PayloadOffset = uint64(binary.BigEndian.Uint32(head[0x68:])) * 512
	info.PayloadOffsetSet = true
	info.KeyBytes = uint64(binary.BigEndian.Uint32(head[0x6c:]))
	info.KeyBytesSet = true

	mkDigest := head[0x70:0x84]
	info.MKDigestBytes = len(mkDigest)
	info.MKDigestPresent = !allZero(mkDigest)
	mkSalt := head[0x84:0xa4]
	info.MKDigestSaltBytes = len(mkSalt)
	info.MKDigestSaltPresent = !allZero(mkSalt)
	info.MKDigestIterations = uint64(binary.BigEndian.Uint32(head[0xa4:]))

	headerHash := info.Hash
	slots := make([]Keyslot, 0, LUKS1Keyslots)
	active := 0
	for index := 0; index < LUKS1Keyslots; index++ {
		base := 0xd0 + index*LUKS1KeyslotBytes
		slot := Keyslot{
			Index: index,
			Kind:  "luks1",
			KDF:   "pbkdf2",
			Hash:  headerHash,
		}
		if binary.BigEndian.Uint32(head[base:]) == LUKS1KeyslotActive {
			slot.Active = true
			active++
			slot.Iterations = uint64(binary.BigEndian.Uint32(head[base+4:]))
			slot.AreaOffset = uint64(binary.BigEndian.Uint32(head[base+40:]))
			slot.Stripes = uint64(binary.BigEndian.Uint32(head[base+44:]))
			slot.SaltPresent = true
			slot.SaltBytes = 32
		}
		slots = append(slots, slot)
	}
	info.Keyslots = slots
	info.ActiveKeyslots = active
	return info, nil
}

func readLUKS2(src source.ByteSource, length uint64, prefix []byte) (*Info, error) {
	if length < LUKS2BinaryHeaderBytes {
		return nil, errs.Truncated(LUKS2BinaryHeaderBytes, length)
	}
	headerBytes := binary.BigEndian.Uint64(prefix[8:16])
	if headerBytes < LUKS2BinaryHeaderBytes {
		return nil, errs.Malformed("LUKS2 hdr_size smaller than the binary header")
	}
	if headerBytes > MaxHeaderBytes {
		return nil, errs.TooLarge(headerBytes, MaxHeaderBytes)
	}
	if length < headerBytes {
		return nil, errs.Truncated(headerBytes, length)
	}
	header, err := source.ReadVecAt(src, 0, headerBytes)
	if err != nil {
		return nil, err
	}
	document, err := parseMetadata(header)
	if err != nil {
		return nil, err
	}

	info := &Info{
		Version:           2,
		VolumeBytes:       length,
		SectorSize:        src.SectorSize(),
		HeaderBytes:       headerBytes,
		UUID:              luksString(header, 0xa8, 40),
		Label:             luksString(header, 0x18, 48),
		Subsystem:         luksString(header, 0xd0, 48),
		ChecksumAlgorithm: luksString(header, 0x48, 32),
		Keyslots:          document.keyslots,
		ActiveKeyslots:    len(document.keyslots),
		Tokens:            document.tokens,
		Digests:           document.digests,
		Segments:          document.segments,
		Flags:             document.flags,
		Unsupported:       luksUnsupported(),
	}
	if headerBytes >= 0x18 {
		info.Sequence = binary.BigEndian.Uint64(header[0x10:0x18])
		info.SequenceSet = true
	}
	if headerBytes >= 0x108 {
		info.HeaderOffset = binary.BigEndian.Uint64(header[0x100:0x108])
		info.HeaderOffsetSet = true
	}
	if info.ChecksumAlgorithm != "" {
		info.Checksum = verifyChecksum(info.ChecksumAlgorithm, header[:headerBytes])
	}
	if length >= headerBytes*2 {
		check, err := source.ReadVecAt(src, headerBytes, 6)
		if err != nil {
			return nil, err
		}
		info.SecondaryHeader = bytes.Equal(check, []byte(Magic))
	}
	if segment, ok := primarySegment(document.segments); ok {
		info.Cipher = segment.Encryption
		info.PayloadOffset = segment.Offset
		info.PayloadOffsetSet = true
		if segment.SectorSize != 0 {
			info.SectorSize = segment.SectorSize
		}
	}
	return info, nil
}

func primarySegment(segments []Segment) (Segment, bool) {
	if len(segments) == 0 {
		return Segment{}, false
	}
	for _, segment := range segments {
		if segment.Index == 0 {
			return segment, true
		}
	}
	return segments[0], true
}

func luksUnsupported() []string {
	return []string{
		UnsupportedUnlock,
		UnsupportedKeyDerivation,
		UnsupportedDecrypt,
		UnsupportedHiddenVolume,
		UnsupportedCipherDispatch,
	}
}

func verifyChecksum(algorithm string, header []byte) ChecksumStatus {
	if !strings.EqualFold(algorithm, "sha256") || len(header) < 0x200 {
		return ChecksumUnknown
	}
	salt := header[0x68:0xa8]
	stored := header[0x1c0:0x200]
	hash := sha256.New()
	hash.Write(salt)
	hash.Write(header[:0x1c0])
	hash.Write(make([]byte, 64))
	hash.Write(header[0x200:])
	digest := hash.Sum(nil)
	for i := 0; i < 32; i++ {
		if digest[i] != stored[i] {
			return ChecksumMismatch
		}
	}
	return ChecksumValid
}

func luksString(bytes []byte, offset, width int) string {
	if offset < 0 || width <= 0 || offset+width > len(bytes) {
		return ""
	}
	field := bytes[offset : offset+width]
	end := bytesIndexByte(field, 0)
	if end < 0 {
		end = width
	}
	if end == 0 || !utf8.Valid(field[:end]) {
		return ""
	}
	return strings.TrimSpace(string(field[:end]))
}

func bytesIndexByte(bytes []byte, target byte) int {
	for i, b := range bytes {
		if b == target {
			return i
		}
	}
	return -1
}

func allZero(bytes []byte) bool {
	for _, b := range bytes {
		if b != 0 {
			return false
		}
	}
	return true
}

// LUKS2 JSON metadata.

type flexUint uint64

func (f *flexUint) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*f = 0
		return nil
	}
	if data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		text = strings.TrimSpace(text)
		if text == "" {
			*f = 0
			return nil
		}
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return err
		}
		*f = flexUint(value)
		return nil
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return err
	}
	*f = flexUint(value)
	return nil
}

type optionalSize struct {
	Value   uint64
	Set     bool
	Dynamic bool
}

func (s *optionalSize) UnmarshalJSON(data []byte) error {
	*s = optionalSize{}
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		text = strings.TrimSpace(text)
		if text == "dynamic" {
			s.Dynamic = true
			return nil
		}
		if text == "" {
			return nil
		}
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return err
		}
		s.Value = value
		s.Set = true
		return nil
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return err
	}
	s.Value = value
	s.Set = true
	return nil
}

type kdfJSON struct {
	Type       string   `json:"type"`
	Hash       string   `json:"hash"`
	Iterations flexUint `json:"iterations"`
	Time       flexUint `json:"time"`
	Memory     flexUint `json:"memory"`
	CPUs       flexUint `json:"cpus"`
	Salt       string   `json:"salt"`
}

type afJSON struct {
	Type    string   `json:"type"`
	Stripes flexUint `json:"stripes"`
	Hash    string   `json:"hash"`
}

type areaJSON struct {
	Type       string   `json:"type"`
	Offset     flexUint `json:"offset"`
	Size       flexUint `json:"size"`
	Encryption string   `json:"encryption"`
	KeySize    flexUint `json:"key_size"`
}

type keyslotJSON struct {
	Type    string   `json:"type"`
	KeySize flexUint `json:"key_size"`
	KDF     kdfJSON  `json:"kdf"`
	AF      afJSON   `json:"af"`
	Area    areaJSON `json:"area"`
}

type digestJSON struct {
	Type       string   `json:"type"`
	Keyslots   []string `json:"keyslots"`
	Hash       string   `json:"hash"`
	Iterations flexUint `json:"iterations"`
	Salt       string   `json:"salt"`
	Digest     string   `json:"digest"`
}

type segmentJSON struct {
	Type       string       `json:"type"`
	Offset     flexUint     `json:"offset"`
	Size       optionalSize `json:"size"`
	IVTweak    flexUint     `json:"iv_tweak"`
	SectorSize flexUint     `json:"sector_size"`
	Encryption string       `json:"encryption"`
}

type configJSON struct {
	Flags []string `json:"flags"`
}

type metadataDocument struct {
	Keyslots map[string]keyslotJSON     `json:"keyslots"`
	Digests  map[string]digestJSON      `json:"digests"`
	Segments map[string]segmentJSON     `json:"segments"`
	Tokens   map[string]json.RawMessage `json:"tokens"`
	Config   configJSON                 `json:"config"`
}

type decodedMetadata struct {
	keyslots []Keyslot
	digests  []Digest
	segments []Segment
	tokens   int
	flags    []string
}

func parseMetadata(header []byte) (*decodedMetadata, error) {
	if len(header) < LUKS2BinaryHeaderBytes {
		return nil, errs.Truncated(LUKS2BinaryHeaderBytes, uint64(len(header)))
	}
	area := header[LUKS2BinaryHeaderBytes:]
	end := len(area)
	for end > 0 && (area[end-1] == 0 || isJSONSpace(area[end-1])) {
		end--
	}
	if end == 0 {
		return nil, errs.Malformed("the LUKS2 metadata area is empty")
	}
	var document metadataDocument
	if err := json.Unmarshal(area[:end], &document); err != nil {
		return nil, errs.Malformed("the LUKS2 metadata area is not valid JSON: " + err.Error())
	}
	if document.Keyslots == nil {
		return nil, errs.Malformed("the LUKS2 metadata has no keyslots object")
	}
	keyslots, err := decodeKeyslots(document.Keyslots)
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
	return &decodedMetadata{
		keyslots: keyslots,
		digests:  digests,
		segments: segments,
		tokens:   len(document.Tokens),
		flags:    document.Config.Flags,
	}, nil
}

func isJSONSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

func decodeKeyslots(slots map[string]keyslotJSON) ([]Keyslot, error) {
	names, err := sortedNumericNames(slots, "keyslot")
	if err != nil {
		return nil, err
	}
	out := make([]Keyslot, 0, len(names))
	for _, name := range names {
		index, _ := strconv.Atoi(name)
		slot := slots[name]
		saltBytes, err := base64Length(slot.KDF.Salt, "kdf salt")
		if err != nil {
			return nil, err
		}
		keyslot := Keyslot{
			Index:          index,
			Active:         true,
			Kind:           slot.Type,
			KDF:            slot.KDF.Type,
			Hash:           slot.KDF.Hash,
			Iterations:     uint64(slot.KDF.Iterations),
			MemoryKiB:      uint64(slot.KDF.Memory),
			Parallelism:    uint64(slot.KDF.CPUs),
			Stripes:        uint64(slot.AF.Stripes),
			KeySize:        uint64(slot.KeySize),
			AreaOffset:     uint64(slot.Area.Offset),
			AreaSize:       uint64(slot.Area.Size),
			AreaEncryption: slot.Area.Encryption,
			SaltPresent:    slot.KDF.Salt != "",
			SaltBytes:      saltBytes,
		}
		if keyslot.Hash == "" {
			keyslot.Hash = slot.AF.Hash
		}
		if slot.KDF.Iterations == 0 && slot.KDF.Time != 0 {
			keyslot.Iterations = uint64(slot.KDF.Time)
		}
		out = append(out, keyslot)
	}
	return out, nil
}

func decodeDigests(digests map[string]digestJSON) ([]Digest, error) {
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sortNumeric(names)
	out := make([]Digest, 0, len(names))
	for _, name := range names {
		digest := digests[name]
		saltBytes, err := base64Length(digest.Salt, "digest salt")
		if err != nil {
			return nil, err
		}
		digestBytes, err := base64Length(digest.Digest, "digest")
		if err != nil {
			return nil, err
		}
		keyslots := make([]int, 0, len(digest.Keyslots))
		for _, name := range digest.Keyslots {
			if index, err := strconv.Atoi(name); err == nil {
				keyslots = append(keyslots, index)
			}
		}
		out = append(out, Digest{
			Kind:          digest.Type,
			Keyslots:      keyslots,
			Hash:          digest.Hash,
			Iterations:    uint64(digest.Iterations),
			SaltPresent:   digest.Salt != "",
			SaltBytes:     saltBytes,
			DigestPresent: digest.Digest != "",
			DigestBytes:   digestBytes,
		})
	}
	return out, nil
}

func decodeSegments(segments map[string]segmentJSON) ([]Segment, error) {
	if len(segments) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(segments))
	for name := range segments {
		if _, err := strconv.Atoi(name); err != nil {
			return nil, errs.Malformed("a LUKS2 segment name is not numeric")
		}
		names = append(names, name)
	}
	sortNumeric(names)
	out := make([]Segment, 0, len(names))
	for _, name := range names {
		index, _ := strconv.Atoi(name)
		segment := segments[name]
		sectorSize := uint32(segment.SectorSize)
		if sectorSize == 0 {
			sectorSize = 512
		}
		out = append(out, Segment{
			Index:       index,
			Kind:        segment.Type,
			Offset:      uint64(segment.Offset),
			Size:        segment.Size.Value,
			SizeSet:     segment.Size.Set,
			SizeDynamic: segment.Size.Dynamic,
			IVTweak:     uint64(segment.IVTweak),
			SectorSize:  sectorSize,
			Encryption:  segment.Encryption,
		})
	}
	return out, nil
}

func sortedNumericNames[T any](values map[string]T, what string) ([]string, error) {
	names := make([]string, 0, len(values))
	for name := range values {
		if _, err := strconv.Atoi(name); err != nil {
			return nil, errs.Malformed("a LUKS2 " + what + " name is not numeric")
		}
		names = append(names, name)
	}
	sortNumeric(names)
	return names, nil
}

func sortNumeric(names []string) {
	sort.Slice(names, func(i, j int) bool {
		left, leftErr := strconv.Atoi(names[i])
		right, rightErr := strconv.Atoi(names[j])
		if leftErr == nil && rightErr == nil {
			return left < right
		}
		return names[i] < names[j]
	})
}

func base64Length(text, what string) (int, error) {
	if text == "" {
		return 0, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(text)
	}
	if err != nil {
		return 0, errs.BadBase64(what)
	}
	return len(decoded), nil
}
