// Package bitlocker reads the BitLocker (FVE) volume header, the FVE metadata
// block it points at, and the metadata half of a saved BitLocker key file.
//
// A volume header is 512 bytes with -FVE-FS- at offset 3. Two layouts share
// that signature: Windows Vista stores one metadata cluster number, and
// Windows 7 and later store three byte offsets. The metadata block is a
// 64-byte block header, a 48-byte FVE metadata header, and a sequence of
// entries: volume master keys with their protectors, the full-volume
// encryption key, strings, and the wrapped keys a protector holds.
//
// Entry values are never published. A key entry contributes its presence and
// byte length; a stretch key or AES-CCM wrapped key contributes its presence
// and length. The protector a volume master key is wrapped by is reported by
// kind (TPM, TPM and PIN, recovery password, password, startup key). Unlocking,
// decryption, recovery-password stretching, and TPM secret use are refused
// with ErrUnsupported (see Info.Unsupported).
package bitlocker

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/encryption/errs"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// VolumeSignature is the FVE signature at offset 3 of the first sector.
	VolumeSignature = "-FVE-FS-"
	// VolumeHeaderBytes is the size of a primary or backup volume header.
	VolumeHeaderBytes = 512
	// BlockHeaderBytes is the size of the metadata block header.
	BlockHeaderBytes = 64
	// MetadataHeaderBytes is the size of the FVE metadata header.
	MetadataHeaderBytes = 48
	// EntryHeaderBytes is the size of one metadata entry header.
	EntryHeaderBytes = 8
	// MaxMetadataBytes is the largest metadata entry area this reader walks.
	MaxMetadataBytes = 1024 * 1024
	// MaxEntries is the number of entries accepted in one metadata block.
	MaxEntries = 4096
	// NonceBytes is the FILETIME and counter in front of an AES-CCM key.
	NonceBytes = 12
	// MaxKeyValueBytes is the largest entry value this reader records.
	MaxKeyValueBytes = 4096
)

// Entry types.
const (
	EntryNone                    uint16 = 0x0000
	EntryVolumeMasterKey         uint16 = 0x0002
	EntryFullVolumeEncryptionKey uint16 = 0x0003
	EntryValidation              uint16 = 0x0004
	EntryStartupKey              uint16 = 0x0006
	EntryDescription             uint16 = 0x0007
	EntryAutoUnlock              uint16 = 0x000b
	EntryMetadataArea            uint16 = 0x000f
)

// Value types.
const (
	ValueErased          uint16 = 0x0000
	ValueKey             uint16 = 0x0001
	ValueUnicodeString   uint16 = 0x0002
	ValueStretchKey      uint16 = 0x0003
	ValueUseKey          uint16 = 0x0004
	ValueAESCCMKey       uint16 = 0x0005
	ValueTPMKey          uint16 = 0x0006
	ValueValidation      uint16 = 0x0007
	ValueVolumeMasterKey uint16 = 0x0008
	ValueExternalKey     uint16 = 0x0009
	ValueUpdate          uint16 = 0x000a
	ValueError           uint16 = 0x000b
	ValueMetadataArea    uint16 = 0x000f
)

// Protector types.
const (
	ProtectClear            uint16 = 0x0000
	ProtectTPM              uint16 = 0x0100
	ProtectStartupKey       uint16 = 0x0200
	ProtectTPMPIN           uint16 = 0x0500
	ProtectRecoveryPassword uint16 = 0x0800
	ProtectPassword         uint16 = 0x2000
)

// Encryption methods.
const (
	MethodAES128CBCElephant uint16 = 0x8000
	MethodAES256CBCElephant uint16 = 0x8001
	MethodAES128CBC         uint16 = 0x8002
	MethodAES256CBC         uint16 = 0x8003
	MethodAES128XTS         uint16 = 0x8004
	MethodAES256XTS         uint16 = 0x8005
)

// Operations this package refuses by name.
const (
	UnsupportedUnlock                = "unlock"
	UnsupportedDecrypt               = "decrypt"
	UnsupportedRecoveryKeyDerivation = "recovery-key derivation"
	UnsupportedHiddenVolume          = "hidden volume"
	UnsupportedTPMSecret             = "TPM/PIN/startup-key secret use"
)

// VolumeFormat is which of the two volume-header layouts a volume uses.
type VolumeFormat uint8

const (
	// FormatWindows7 is the Windows 7 and later layout: three byte offsets
	// and a 64 KiB metadata block.
	FormatWindows7 VolumeFormat = iota + 1
	// FormatVista is the Vista layout: one cluster number and a 16 KiB
	// metadata block.
	FormatVista
)

// String returns the layout label used in reports.
func (f VolumeFormat) String() string {
	if f == FormatVista {
		return "vista"
	}
	return "windows7"
}

// VolumeHeader is the geometry and identity a volume header records.
type VolumeHeader struct {
	Format            VolumeFormat
	BytesPerSector    uint16
	SectorsPerCluster uint8
	TotalSectors      uint64
	VolumeSerial      uint64
	HasVolumeSerial   bool
	VolumeLabel       string
	FileSystem        string
	MetadataOffsets   [3]uint64
	MetadataSize      uint64
}

// ClusterBytes returns the cluster size, or zero when the geometry is unsound.
func (v VolumeHeader) ClusterBytes() uint64 {
	if v.BytesPerSector == 0 || v.SectorsPerCluster == 0 {
		return 0
	}
	return uint64(v.BytesPerSector) * uint64(v.SectorsPerCluster)
}

// FirstMetadataOffset returns the first metadata offset the header names.
func (v VolumeHeader) FirstMetadataOffset() (uint64, bool) {
	for _, offset := range v.MetadataOffsets {
		if offset != 0 {
			return offset, true
		}
	}
	return 0, false
}

// BlockHeader is the 64-byte header in front of an FVE metadata block.
type BlockHeader struct {
	Version               uint16
	State                 uint16
	StateCopy             uint16
	Offsets               [3]uint64
	MFTMirrorCluster      uint64
	HasMFTMirrorCluster   bool
	VolumeHeaderOffset    uint64
	HasVolumeHeaderOffset bool
	VolumeHeaderSectors   uint32
	EncryptedVolumeBytes  uint64
}

// MetadataHeader is the 48-byte header inside an FVE metadata block.
type MetadataHeader struct {
	Size                 uint32
	Version              uint32
	HeaderSize           uint32
	SizeCopy             uint32
	VolumeIdentifier     string
	NextNonce            uint32
	EncryptionMethod     uint16
	EncryptionMethodCopy uint16
	CreationTime         uint64
}

// KeyProtector is how a volume master key is wrapped.
type KeyProtector struct {
	// ID is the protector GUID as sixteen lower-case hex bytes.
	ID string
	// LastModified is a Windows FILETIME.
	LastModified uint64
	// ProtectionType is one of the Protect* constants.
	ProtectionType uint16
}

// Label returns the protector kind.
func (p KeyProtector) Label() string { return ProtectionLabel(p.ProtectionType) }

// MetadataEntry is one entry. Key bytes are never retained: KeyBytes and
// ValueBytes record only their length.
type MetadataEntry struct {
	Kind      uint16
	ValueType uint16
	Version   uint16
	Size      uint16
	// Protector is set for a volume master key entry.
	Protector *KeyProtector
	// KeyMethod is the method word in front of key material.
	KeyMethod *uint16
	// KeyPresent reports that a key entry carried material; KeyBytes is its
	// length after the method word.
	KeyPresent bool
	KeyBytes   int
	// ValuePresent reports a stretch key or AES-CCM wrapped key; ValueBytes
	// is its on-disk length. The bytes themselves are not kept.
	ValuePresent bool
	ValueBytes   int
	// Text is a UTF-16 description or label.
	Text string
	// Properties are entries nested inside a fixed-width value header.
	Properties []MetadataEntry
}

// KeyData records the presence and length of one key-bearing value.
type KeyData struct {
	EntryType uint16
	ValueType uint16
	Present   bool
	Bytes     int
	Wrapped   bool
}

// Metadata is one parsed FVE metadata block.
type Metadata struct {
	Offset    uint64
	Block     BlockHeader
	Header    MetadataHeader
	Entries   []MetadataEntry
	Truncated uint64
	Malformed int
	Limited   bool
	KeyData   []KeyData
}

// Info is everything a locked BitLocker volume says about itself.
type Info struct {
	Volume        VolumeHeader
	Backup        *VolumeHeader
	Metadata      *Metadata
	MetadataError string
	// VolumeBytes is TotalSectors times BytesPerSector.
	VolumeBytes uint64
	// SectorSize mirrors the header's bytes-per-sector.
	SectorSize uint32
	// MethodCode is the raw encryption method; EncryptionMethod is its label.
	MethodCode       uint16
	EncryptionMethod string
	Protectors       []KeyProtector
	ProtectorLabels  []string
	KeyData          []KeyData
	// Unsupported lists the operations this metadata-only reader does not
	// perform for the volume.
	Unsupported []string
}

// ProtectorCount returns the number of volume master key protectors.
func (i *Info) ProtectorCount() int { return len(i.Protectors) }

// HasRecoveryPassword reports whether a recovery-password protector is present.
func (i *Info) HasRecoveryPassword() bool {
	for _, protector := range i.Protectors {
		if protector.ProtectionType == ProtectRecoveryPassword {
			return true
		}
	}
	return false
}

// Describe returns one line for a report.
func (i *Info) Describe() string {
	method := i.EncryptionMethod
	if method == "" && i.MethodCode != 0 {
		method = fmt.Sprintf("method 0x%04x", i.MethodCode)
	}
	if method == "" {
		method = "(metadata not read)"
	}
	if i.Metadata == nil {
		return fmt.Sprintf("BitLocker (%s)", method)
	}
	return fmt.Sprintf("BitLocker (%s), %d key protector(s)", method, i.ProtectorCount())
}

// HasSignature reports whether head carries the FVE signature at offset 3.
func HasSignature(head []byte) bool {
	return len(head) >= 11 && bytes.Equal(head[3:11], []byte(VolumeSignature))
}

// Read parses the BitLocker volume header at the start of src and the metadata
// block it points at.
//
// It returns nil, nil when the first sector does not carry the FVE signature.
// A volume whose metadata block is damaged still returns Info, with the reason
// in MetadataError, because the volume header alone names the volume and its
// geometry. A source too short to hold the signed volume header is an explicit
// ErrTruncated.
func Read(src source.ByteSource) (*Info, error) {
	length := src.Len()
	if length < 11 {
		return nil, nil
	}
	probe, err := source.ReadVecAt(src, 0, min(length, 11))
	if err != nil {
		return nil, err
	}
	if !HasSignature(probe) {
		return nil, nil
	}
	if length < VolumeHeaderBytes {
		return nil, errs.Truncated(VolumeHeaderBytes, length)
	}
	head, err := source.ReadVecAt(src, 0, VolumeHeaderBytes)
	if err != nil {
		return nil, err
	}
	return parseWith(head, length, func(offset, count uint64) ([]byte, error) {
		return source.ReadVecAt(src, offset, count)
	})
}

type candidate struct {
	format VolumeFormat
	offset uint64
}

func parseWith(head []byte, length uint64, fetch func(uint64, uint64) ([]byte, error)) (*Info, error) {
	vista := vistaCandidates(head)
	windows7 := [3]uint64{
		le64(head, 0x99),
		le64(head, 0xa1),
		le64(head, 0xa9),
	}

	var chosen *candidate
	var first *candidate
	var chosenBlock []byte
	for _, group := range []struct {
		format  VolumeFormat
		offsets [3]uint64
	}{
		{FormatWindows7, windows7},
		{FormatVista, vista},
	} {
		for _, offset := range group.offsets {
			if offset == 0 || offset+BlockHeaderBytes > length {
				continue
			}
			if first == nil {
				first = &candidate{group.format, offset}
			}
			block, err := fetch(offset, BlockHeaderBytes)
			if err != nil {
				return nil, err
			}
			if bytes.HasPrefix(block, []byte(VolumeSignature)) {
				chosen = &candidate{group.format, offset}
				chosenBlock = block
				break
			}
		}
		if chosen != nil {
			break
		}
	}

	var metadata *Metadata
	var metadataError string
	if chosen != nil {
		format := chosen.format
		switch le16(chosenBlock, 10) {
		case 1:
			format = FormatVista
		case 2:
			format = FormatWindows7
		}
		parsed, err := readMetadata(fetch, chosen.offset, length, chosenBlock, format)
		if err != nil {
			metadataError = err.Error()
		} else {
			metadata = parsed
		}
	} else if first != nil {
		metadataError = fmt.Sprintf(
			"the metadata block at byte %d does not start with the FVE signature", first.offset)
	} else {
		metadataError = "the volume header names no usable metadata block"
	}

	format := FormatWindows7
	switch {
	case metadata != nil:
		if metadata.Block.Version == 1 {
			format = FormatVista
		} else {
			format = FormatWindows7
		}
	case chosen != nil:
		format = chosen.format
	case first != nil:
		format = first.format
	}
	volume := parseVolumeHeader(head, format)

	var backup *VolumeHeader
	if length >= VolumeHeaderBytes*2 {
		tail, err := fetch(length-VolumeHeaderBytes, VolumeHeaderBytes)
		if err != nil {
			return nil, err
		}
		if HasSignature(tail) {
			parsed := parseVolumeHeader(tail, format)
			backup = &parsed
		}
	}

	info := &Info{
		Volume:        volume,
		Backup:        backup,
		Metadata:      metadata,
		MetadataError: metadataError,
		SectorSize:    uint32(volume.BytesPerSector),
		Unsupported: []string{
			UnsupportedUnlock,
			UnsupportedDecrypt,
			UnsupportedRecoveryKeyDerivation,
			UnsupportedHiddenVolume,
			UnsupportedTPMSecret,
		},
	}
	if volume.BytesPerSector != 0 {
		if volume.TotalSectors > ^uint64(0)/uint64(volume.BytesPerSector) {
			info.VolumeBytes = ^uint64(0)
		} else {
			info.VolumeBytes = volume.TotalSectors * uint64(volume.BytesPerSector)
		}
	}
	if metadata != nil {
		info.MethodCode = metadata.Header.EncryptionMethod
		if info.MethodCode != 0 {
			info.EncryptionMethod = EncryptionLabel(info.MethodCode)
		}
		for _, entry := range metadata.Entries {
			if entry.Kind == EntryVolumeMasterKey && entry.Protector != nil {
				info.Protectors = append(info.Protectors, *entry.Protector)
				info.ProtectorLabels = append(info.ProtectorLabels, entry.Protector.Label())
			}
		}
		info.KeyData = collectKeyData(metadata.Entries)
	}
	return info, nil
}

func vistaCandidates(head []byte) [3]uint64 {
	cluster := le64(head, 0x38)
	bytesPerSector := uint64(le16(head, 0x0b))
	sectorsPerCluster := uint64(headAt(head, 0x0d))
	return [3]uint64{satMul(satMul(cluster, bytesPerSector), sectorsPerCluster), 0, 0}
}

func satMul(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}

func parseVolumeHeader(head []byte, format VolumeFormat) VolumeHeader {
	volume := VolumeHeader{
		Format:            format,
		BytesPerSector:    le16(head, 0x0b),
		SectorsPerCluster: headAt(head, 0x0d),
	}
	if total := le64(head, 0x28); total != 0 {
		volume.TotalSectors = total
	} else if total := le32(head, 0x20); total != 0 {
		volume.TotalSectors = uint64(total)
	} else if total := le16(head, 0x13); total != 0 {
		volume.TotalSectors = uint64(total)
	}
	switch format {
	case FormatWindows7:
		if serial := le32(head, 0x43); serial != 0 {
			volume.VolumeSerial = uint64(serial)
			volume.HasVolumeSerial = true
		}
		volume.VolumeLabel = ascii(head, 0x47, 11)
		volume.FileSystem = ascii(head, 0x52, 8)
		volume.MetadataOffsets = [3]uint64{
			le64(head, 0x99),
			le64(head, 0xa1),
			le64(head, 0xa9),
		}
		volume.MetadataSize = 65_536
	case FormatVista:
		if serial := le64(head, 0x48); serial != 0 {
			volume.VolumeSerial = serial
			volume.HasVolumeSerial = true
		}
		volume.MetadataOffsets = vistaCandidates(head)
		volume.MetadataSize = 16_384
	}
	return volume
}

func readMetadata(fetch func(uint64, uint64) ([]byte, error), offset, length uint64,
	block []byte, format VolumeFormat) (*Metadata, error) {
	blockHeader := BlockHeader{
		Version:   le16(block, 10),
		State:     le16(block, 12),
		StateCopy: le16(block, 14),
		Offsets: [3]uint64{
			le64(block, 32),
			le64(block, 40),
			le64(block, 48),
		},
	}
	if format == FormatVista {
		blockHeader.MFTMirrorCluster = le64(block, 56)
		blockHeader.HasMFTMirrorCluster = true
	} else {
		blockHeader.VolumeHeaderOffset = le64(block, 56)
		blockHeader.HasVolumeHeaderOffset = true
		blockHeader.VolumeHeaderSectors = le32(block, 28)
		blockHeader.EncryptedVolumeBytes = le64(block, 16)
	}

	headerAt := offset + BlockHeaderBytes
	if headerAt+MetadataHeaderBytes > length {
		return nil, errs.Truncated(headerAt+MetadataHeaderBytes, length)
	}
	headerBytes, err := fetch(headerAt, MetadataHeaderBytes)
	if err != nil {
		return nil, err
	}
	size := le32(headerBytes, 0)
	header := MetadataHeader{
		Size:                 size,
		Version:              le32(headerBytes, 4),
		HeaderSize:           le32(headerBytes, 8),
		SizeCopy:             le32(headerBytes, 12),
		VolumeIdentifier:     hex(headerBytes[16:32]),
		NextNonce:            le32(headerBytes, 32),
		EncryptionMethod:     le16(headerBytes, 36),
		EncryptionMethodCopy: le16(headerBytes, 38),
		CreationTime:         le64(headerBytes, 40),
	}
	if uint64(size) < MetadataHeaderBytes {
		return nil, errs.Malformed("a metadata size that covers its own header")
	}

	entryBytes := uint64(size) - MetadataHeaderBytes
	limited := false
	if entryBytes > MaxMetadataBytes {
		entryBytes = MaxMetadataBytes
		limited = true
	}
	available := uint64(0)
	if length > headerAt+MetadataHeaderBytes {
		available = length - (headerAt + MetadataHeaderBytes)
	}
	wanted := min(entryBytes, available)
	truncated := entryBytes - wanted
	entriesAt := headerAt + MetadataHeaderBytes
	bytes, err := fetch(entriesAt, wanted)
	if err != nil {
		return nil, err
	}
	entries, malformed := parseEntries(bytes, 0)
	return &Metadata{
		Offset:    offset,
		Block:     blockHeader,
		Header:    header,
		Entries:   entries,
		Truncated: truncated,
		Malformed: malformed,
		Limited:   limited,
		KeyData:   collectKeyData(entries),
	}, nil
}

func parseEntries(bytes []byte, depth int) ([]MetadataEntry, int) {
	var entries []MetadataEntry
	malformed := 0
	at := 0
	for at+EntryHeaderBytes <= len(bytes) {
		size := le16(bytes, at)
		kind := le16(bytes, at+2)
		valueType := le16(bytes, at+4)
		version := le16(bytes, at+6)
		if kind == EntryNone && valueType == ValueErased && size == 0 {
			break
		}
		if size < EntryHeaderBytes {
			malformed++
			break
		}
		end := at + int(size)
		if end > len(bytes) || len(entries) >= MaxEntries {
			malformed++
			break
		}
		payload := bytes[at+EntryHeaderBytes : end]
		entry := MetadataEntry{
			Kind:      kind,
			ValueType: valueType,
			Version:   version,
			Size:      size,
		}
		switch valueType {
		case ValueVolumeMasterKey:
			if len(payload) >= 28 {
				entry.Protector = &KeyProtector{
					ID:             hex(payload[0:16]),
					LastModified:   le64(payload, 16),
					ProtectionType: le16(payload, 26),
				}
			}
		case ValueKey:
			if len(payload) >= 4 {
				method := le16(payload, 0)
				entry.KeyMethod = &method
				entry.KeyPresent = true
				entry.KeyBytes = len(payload) - 4
			}
		case ValueStretchKey, ValueAESCCMKey:
			if len(payload) <= MaxKeyValueBytes {
				entry.ValuePresent = true
				entry.ValueBytes = len(payload)
			} else {
				entry.KeyPresent = true
				entry.KeyBytes = len(payload)
			}
		case ValueUnicodeString:
			entry.Text = decodeUTF16(payload)
		}
		if depth < 4 {
			if nested := nestedOffset(valueType); nested >= 0 && nested < len(payload) {
				properties, _ := parseEntries(payload[nested:], depth+1)
				entry.Properties = properties
			}
		}
		entries = append(entries, entry)
		at = end
	}
	if at < len(bytes) && len(entries) == 0 {
		malformed++
	}
	return entries, malformed
}

func nestedOffset(valueType uint16) int {
	switch valueType {
	case ValueUseKey:
		return 4
	case ValueStretchKey:
		return 20
	case ValueVolumeMasterKey:
		return 28
	case ValueExternalKey:
		return 24
	case ValueUpdate:
		return 36
	default:
		return -1
	}
}

func collectKeyData(entries []MetadataEntry) []KeyData {
	var out []KeyData
	var walk func([]MetadataEntry)
	walk = func(list []MetadataEntry) {
		for _, entry := range list {
			switch entry.ValueType {
			case ValueKey:
				if entry.KeyPresent {
					out = append(out, KeyData{
						EntryType: entry.Kind,
						ValueType: entry.ValueType,
						Present:   true,
						Bytes:     entry.KeyBytes,
					})
				}
			case ValueStretchKey, ValueAESCCMKey:
				switch {
				case entry.ValuePresent:
					out = append(out, KeyData{
						EntryType: entry.Kind,
						ValueType: entry.ValueType,
						Present:   true,
						Bytes:     entry.ValueBytes,
						Wrapped:   true,
					})
				case entry.KeyPresent:
					out = append(out, KeyData{
						EntryType: entry.Kind,
						ValueType: entry.ValueType,
						Present:   true,
						Bytes:     entry.KeyBytes,
						Wrapped:   true,
					})
				}
			}
			walk(entry.Properties)
		}
	}
	walk(entries)
	return out
}

// EntryTypeLabel returns a short label for an entry type.
func EntryTypeLabel(kind uint16) string {
	switch kind {
	case EntryNone:
		return "none"
	case EntryVolumeMasterKey:
		return "volume master key"
	case EntryFullVolumeEncryptionKey:
		return "full volume encryption key"
	case EntryValidation:
		return "validation"
	case EntryStartupKey:
		return "startup key"
	case EntryDescription:
		return "description"
	case EntryAutoUnlock:
		return "auto unlock"
	case EntryMetadataArea:
		return "metadata area"
	default:
		return "unknown"
	}
}

// ValueTypeLabel returns a short label for a value type.
func ValueTypeLabel(valueType uint16) string {
	switch valueType {
	case ValueErased:
		return "erased"
	case ValueKey:
		return "key"
	case ValueUnicodeString:
		return "string"
	case ValueStretchKey:
		return "stretch key"
	case ValueUseKey:
		return "use key"
	case ValueAESCCMKey:
		return "AES-CCM key"
	case ValueTPMKey:
		return "TPM key"
	case ValueValidation:
		return "validation"
	case ValueVolumeMasterKey:
		return "volume master key"
	case ValueExternalKey:
		return "external key"
	case ValueUpdate:
		return "update"
	case ValueError:
		return "error"
	case ValueMetadataArea:
		return "metadata area"
	default:
		return "unknown"
	}
}

// ProtectionLabel returns a short label for a protector type.
func ProtectionLabel(protection uint16) string {
	switch protection {
	case ProtectClear:
		return "clear key"
	case ProtectTPM:
		return "TPM"
	case ProtectStartupKey:
		return "startup key"
	case ProtectTPMPIN:
		return "TPM and PIN"
	case ProtectRecoveryPassword:
		return "recovery password"
	case ProtectPassword:
		return "password"
	default:
		return "unknown protector"
	}
}

// EncryptionLabel returns a short label for an encryption method.
func EncryptionLabel(method uint16) string {
	switch method {
	case MethodAES128CBCElephant:
		return "AES-128-CBC with Elephant"
	case MethodAES256CBCElephant:
		return "AES-256-CBC with Elephant"
	case MethodAES128CBC:
		return "AES-128-CBC"
	case MethodAES256CBC:
		return "AES-256-CBC"
	case MethodAES128XTS:
		return "AES-128-XTS"
	case MethodAES256XTS:
		return "AES-256-XTS"
	default:
		return "unknown method"
	}
}

func headAt(bytes []byte, at int) byte {
	if at < 0 || at >= len(bytes) {
		return 0
	}
	return bytes[at]
}

func le16(bytes []byte, at int) uint16 {
	if at < 0 || at+2 > len(bytes) {
		return 0
	}
	return uint16(bytes[at]) | uint16(bytes[at+1])<<8
}

func le32(bytes []byte, at int) uint32 {
	if at < 0 || at+4 > len(bytes) {
		return 0
	}
	return uint32(bytes[at]) | uint32(bytes[at+1])<<8 |
		uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
}

func le64(bytes []byte, at int) uint64 {
	return uint64(le32(bytes, at)) | uint64(le32(bytes, at+4))<<32
}

func ascii(bytes []byte, at, width int) string {
	if at < 0 || at+width > len(bytes) {
		return ""
	}
	text := strings.Trim(string(bytes[at:at+width]), "\x00 ")
	return text
}

func decodeUTF16(bytes []byte) string {
	units := make([]uint16, 0, len(bytes)/2)
	for at := 0; at+2 <= len(bytes); at += 2 {
		unit := le16(bytes, at)
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	if len(units) == 0 {
		return ""
	}
	return strings.Trim(string(utf16.Decode(units)), " ")
}

func hex(bytes []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(bytes)*2)
	for i, b := range bytes {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}
