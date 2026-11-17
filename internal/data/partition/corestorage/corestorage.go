// Package corestorage decodes Apple CoreStorage physical-volume metadata, the
// container FileVault 2 volumes use from Mac OS X 10.7 through macOS 10.13.
//
// It reads the 512-byte physical-volume header, the first 8192-byte metadata
// block (the "disk label") and the volume-group descriptor inside it. It never
// unwraps the keybag, never derives a key and never produces a plaintext view:
// key material is reported only as present (its size and encryption method),
// and the encrypted logical volumes stay opaque.
//
// It is a pure-Go port of forensic-core's data/partition/corestorage.rs.
//
// # On-disk layout
//
//	byte 0             physical volume header (512 bytes)
//	  0x00  u32        checksum (weak CRC-32C over bytes 8..512)
//	  0x04  u32        checksum seed, 0xFFFFFFFF
//	  0x08  u16        format version, 1
//	  0x0A  u16        block type, 0x0010 (physical volume header)
//	  0x0C  u32        serial number
//	  0x30  u32        bytes per sector
//	  0x40  u64        physical volume size in bytes
//	  0x58  "CS"       CoreStorage signature
//	  0x5A  u32        checksum algorithm, 1 (CRC-32C)
//	  0x5E  u16        number of metadata blocks (normally 4)
//	  0x60  u32        block size
//	  0x64  u32        metadata size
//	  0x68  4 x u64    metadata block numbers (multiply by block size)
//	  0xA8  u32        key data size (16)
//	  0xAC  u32        encryption method, 2 = AES-XTS
//	  0xB0  16 bytes   key data (reported as present, never printed)
//	  0x130 16 bytes   physical volume UUID (big-endian)
//	  0x140 16 bytes   volume group UUID (big-endian)
//
//	metadata block metadata_block_numbers[0] * block_size (8192 bytes)
//	  0x00  u32        checksum (weak CRC-32C over bytes 8..8192)
//	  0x08  u16        version
//	  0x0A  u16        block type, 0x0011 (metadata section)
//	  0x30  u32        block size, 8192
//	  0x40  u32        metadata size (must equal the header's)
//	  0xDC  u32        volume-group descriptor offset (from block start)
//
//	volume-group descriptor
//	  0x00  u64        conversion/encryption state
//	  0x08  u64        encrypted metadata block count
//	  0x20  u64        primary encrypted metadata block (low 48 bits block
//	                   number, high 16 bits physical volume index)
//	  0x28  u64        secondary encrypted metadata block (not parsed)
//	  0x30  ...        volume group XML plist (not parsed)
//
// # Named gaps
//
// The backup header at the end of the volume, the secondary encrypted metadata
// block, the volume-group XML plist, the logical-volume list, the encryption
// context blocks, the logical-to-physical mapping and every transaction
// fragment are not decoded. FileVault 2 unlock, keybag parsing, key derivation
// and AES-XTS decryption are not implemented.
package corestorage

import (
	"errors"
	"fmt"
	"math"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Signature is the two-byte CoreStorage magic at SignatureOffset.
	Signature = "CS"
	// SignatureOffset is the offset of the signature in the header.
	SignatureOffset = 88
	// HeaderBytes is the size of the physical volume header at offset 0.
	HeaderBytes = 512
	// HeaderBlockType is the block type of the physical volume header.
	HeaderBlockType uint16 = 0x0010
	// MetadataBlockType is the block type of the metadata section.
	MetadataBlockType uint16 = 0x0011
	// MetadataBlockBytes is the size of the first metadata block.
	MetadataBlockBytes = 8192
	// MetadataSizeOffset is the metadata section's own size field, past the
	// 64-byte block header.
	MetadataSizeOffset = 64
	// VolumeGroupDescriptorOffset is the descriptor offset field inside the
	// metadata block.
	VolumeGroupDescriptorOffset = 220
	// VolumeGroupDescriptorBytes is the minimum descriptor size, from the
	// state word through the start of the plist.
	VolumeGroupDescriptorBytes = 48
	// MinVolumeGroupDescriptorOffset is the first byte after the fixed
	// metadata-section fields.
	MinVolumeGroupDescriptorOffset uint32 = 248
	// ChecksumSeed is the stored initial value at header offset 4.
	ChecksumSeed uint32 = 0xFFFF_FFFF
	// ChecksumAlgorithmCRC32C names the weak (un-inverted) reflected CRC-32C.
	ChecksumAlgorithmCRC32C uint32 = 1
	// EncryptionMethodAESXTS is encryption method 2.
	EncryptionMethodAESXTS uint32 = 2
	// WipedMarker is the first-eight-bytes marker of a wiped header block.
	WipedMarker = "LVFwiped"
	// MaxBlockSize caps the header's block size.
	MaxBlockSize uint32 = 1024 * 1024
	// MaxMetadataSize caps the header's metadata size.
	MaxMetadataSize uint32 = 16 * 1024 * 1024
	// MaxEncryptedMetadataBlocks caps a forged descriptor count.
	MaxEncryptedMetadataBlocks uint64 = 1 << 24
)

// ErrUnrouted means the fixed signature is absent: the image is not a
// CoreStorage physical volume.
var ErrUnrouted = errors.New("corestorage: not an Apple CoreStorage physical volume")

// HeaderError means a CoreStorage header was found but a required field or
// invariant is wrong.
type HeaderError struct {
	Reason string
}

func (e *HeaderError) Error() string {
	return "corestorage: invalid header: " + e.Reason
}

// UnknownVersionError means the on-disk format version is not implemented.
type UnknownVersionError struct {
	Version uint16
}

func (e *UnknownVersionError) Error() string {
	return fmt.Sprintf("corestorage: unsupported format version %d", e.Version)
}

// OutOfBoundsError means a metadata reference points outside the source or
// overflows.
type OutOfBoundsError struct {
	Reason string
}

func (e *OutOfBoundsError) Error() string {
	return "corestorage: metadata outside the source: " + e.Reason
}

// CapError means a declared size or count exceeds this reader's cap.
type CapError struct {
	Reason string
}

func (e *CapError) Error() string {
	return "corestorage: structure over the reader cap: " + e.Reason
}

// TruncatedError means the source ends before a structure the header declares.
type TruncatedError struct {
	Offset uint64
	Need   uint64
	Have   uint64
}

func (e *TruncatedError) Error() string {
	return fmt.Sprintf("corestorage: structure at %d needs %d bytes, source has %d", e.Offset, e.Need, e.Have)
}

// ConversionState is the volume-group descriptor's state word class.
//
// The 0/1/2 meanings come from libfvde's documentation alone; the raw word is
// still reported in VolumeGroupDescriptor.StateRaw so an unknown or
// single-source label never hides the bytes.
type ConversionState uint8

const (
	// ConversionUnencrypted is state 0.
	ConversionUnencrypted ConversionState = iota
	// ConversionEncrypted is state 1.
	ConversionEncrypted
	// ConversionDecrypting is state 2.
	ConversionDecrypting
	// ConversionUnknown is any other state word.
	ConversionUnknown
)

// ConversionStateFromRaw maps a raw descriptor state word to its class.
func ConversionStateFromRaw(value uint64) ConversionState {
	switch value {
	case 0:
		return ConversionUnencrypted
	case 1:
		return ConversionEncrypted
	case 2:
		return ConversionDecrypting
	default:
		return ConversionUnknown
	}
}

// Label returns the documented label, or "unknown".
func (c ConversionState) Label() string {
	switch c {
	case ConversionUnencrypted:
		return "unencrypted"
	case ConversionEncrypted:
		return "encrypted"
	case ConversionDecrypting:
		return "decrypting"
	default:
		return "unknown"
	}
}

// EncryptedMetadataBlock references an encrypted metadata block: a block
// number plus the physical volume that holds it.
type EncryptedMetadataBlock struct {
	// BlockNumber is the low 48 bits of the descriptor field, relative to the
	// physical volume.
	BlockNumber uint64
	// VolumeIndex is the high 16 bits: the physical volume index (0 first).
	VolumeIndex uint16
}

// VolumeGroupDescriptor is the descriptor inside metadata block type 0x0011.
type VolumeGroupDescriptor struct {
	// StateRaw is the raw eight-byte state word at descriptor offset 0.
	StateRaw uint64
	// State is the class of StateRaw.
	State ConversionState
	// EncryptedMetadataBlockCount is the count at descriptor offset 8.
	EncryptedMetadataBlockCount uint64
	// PrimaryEncryptedMetadata is the primary block at descriptor offset 32,
	// or nil when the field is zero.
	PrimaryEncryptedMetadata *EncryptedMetadataBlock
	// EncryptedMetadataPresent reports whether the volume declares encrypted
	// metadata blocks.
	EncryptedMetadataPresent bool
}

// MetadataSection is the first metadata block (the "disk label").
type MetadataSection struct {
	// Offset is the absolute byte offset of the block in the source.
	Offset uint64
	// BlockNumber is the metadata block number from the header.
	BlockNumber uint64
	// Checksum is the stored checksum.
	Checksum uint32
	// ChecksumComputed is the CRC-32C over bytes 8..8192.
	ChecksumComputed uint32
	// ChecksumOK reports a matching stored CRC-32C, or a wiped block (whose
	// checksum is not checked).
	ChecksumOK bool
	// Wiped reports that the block begins with WipedMarker.
	Wiped bool
	// Version is the block version at offset 8.
	Version uint16
	// BlockType is the block type at offset 10.
	BlockType uint16
	// BlockSize is the block size field at offset 48.
	BlockSize uint32
	// MetadataSize is the metadata size at offset 64.
	MetadataSize uint32
	// MetadataSizeMatches reports that MetadataSize equals the header's.
	MetadataSizeMatches bool
	// VolumeGroupDescriptorOffset is the descriptor offset, from block start.
	VolumeGroupDescriptorOffset uint32
	// VolumeGroup is the parsed descriptor, or nil for a wiped block.
	VolumeGroup *VolumeGroupDescriptor
}

// HasVolumeGroup reports whether this block describes a volume group. A nil
// section has no volume group.
func (m *MetadataSection) HasVolumeGroup() bool {
	return m != nil && m.VolumeGroup != nil
}

// Volume is a parsed CoreStorage physical-volume header and its metadata.
type Volume struct {
	Checksum           uint32
	ChecksumComputed   uint32
	ChecksumOK         bool
	InitialValue       uint32
	Version            uint16
	BlockType          uint16
	SerialNumber       uint32
	BytesPerSector     uint32
	PhysicalVolumeSize uint64
	BlockSize          uint32
	MetadataSize       uint32
	// MetadataBlockNumbers holds the four block numbers; multiply each by
	// BlockSize.
	MetadataBlockNumbers [4]uint64
	KeyDataSize          uint32
	EncryptionMethod     uint32
	// KeyDataPresent reports that at least one byte of the 16-byte key data is
	// non-zero. The bytes themselves are never exposed or printed.
	KeyDataPresent bool
	// PhysicalVolumeUUID is the big-endian formatting of bytes 304..320, or
	// empty when all sixteen are zero.
	PhysicalVolumeUUID string
	// VolumeGroupUUID is the big-endian formatting of bytes 320..336, or empty
	// when all sixteen are zero.
	VolumeGroupUUID string
	// Metadata is the first metadata section, or nil when
	// MetadataBlockNumbers[0] is zero.
	Metadata *MetadataSection
}

// EncryptionMethodLabel returns the documented method name, or "unknown".
func (v *Volume) EncryptionMethodLabel() string {
	if v.EncryptionMethod == EncryptionMethodAESXTS {
		return "AES-XTS"
	}
	return "unknown"
}

// Roles returns the CoreStorage roles this metadata proves are present. A
// physical volume header always proves "physical-volume"; a metadata section
// proves "volume-group". Logical volumes are not decoded, so
// "logical-volume" is never claimed.
func (v *Volume) Roles() []string {
	roles := []string{"physical-volume"}
	if v.Metadata != nil {
		roles = append(roles, "volume-group")
	}
	return roles
}

// EncryptedMetadataPresent reports whether the metadata declares encrypted
// metadata blocks.
func (v *Volume) EncryptedMetadataPresent() bool {
	return v.Metadata.HasVolumeGroup() && v.Metadata.VolumeGroup.EncryptedMetadataPresent
}

// LooksLikeVolumeHeader reports whether head holds a CoreStorage physical
// volume header trusted enough to route automatically.
//
// The two-byte signature is not enough on its own: the check also requires
// version 1, block type 0x0010, checksum algorithm 1, a plausible block size
// and a matching CRC-32C over bytes 8..512.
func LooksLikeVolumeHeader(head []byte) bool {
	if len(head) < HeaderBytes {
		return false
	}
	if !hasSignature(head) {
		return false
	}
	version := le16(head, 8)
	blockType := le16(head, 10)
	initialValue := le32(head, 4)
	algorithm := le32(head, 90)
	blockSize := le32(head, 96)
	if version != 1 ||
		blockType != HeaderBlockType ||
		initialValue != ChecksumSeed ||
		algorithm != ChecksumAlgorithmCRC32C ||
		blockSize < 512 ||
		!isPowerOfTwo(blockSize) ||
		blockSize > MaxBlockSize {
		return false
	}
	return foundation.CRC32CSeeded(initialValue, head[8:HeaderBytes]) == le32(head, 0)
}

// Read parses a CoreStorage physical volume's header and first metadata block.
//
// ErrUnrouted means the fixed signature is absent: the image is not a
// CoreStorage physical volume. Once the signature is present, a header that
// violates the documented invariants is a named refusal, not "not
// CoreStorage".
func Read(src source.ByteSource) (*Volume, error) {
	length := src.Len()
	if length < uint64(SignatureOffset+len(Signature)) {
		return nil, ErrUnrouted
	}
	// A signature-bearing but short image is truncated, not unrelated. Read
	// only what is there first, so ErrUnrouted stays distinguishable.
	headLen := length
	if headLen > HeaderBytes {
		headLen = HeaderBytes
	}
	head := make([]byte, int(headLen))
	if err := source.ReadExactAt(src, 0, head); err != nil {
		return nil, err
	}
	if !hasSignature(head) {
		return nil, ErrUnrouted
	}
	if length < HeaderBytes {
		return nil, &TruncatedError{Offset: 0, Need: HeaderBytes, Have: length}
	}
	header := make([]byte, HeaderBytes)
	if err := source.ReadExactAt(src, 0, header); err != nil {
		return nil, err
	}
	volume, err := parseHeader(header)
	if err != nil {
		return nil, err
	}
	if volume.MetadataBlockNumbers[0] == 0 {
		return volume, nil
	}
	metadata, err := readMetadata(src, volume.MetadataBlockNumbers[0], volume.BlockSize, volume.MetadataSize, length)
	if err != nil {
		return nil, err
	}
	volume.Metadata = metadata
	return volume, nil
}

func parseHeader(header []byte) (*Volume, error) {
	if !hasSignature(header) {
		return nil, ErrUnrouted
	}
	version := le16(header, 8)
	if version != 1 {
		return nil, &UnknownVersionError{Version: version}
	}
	blockType := le16(header, 10)
	if blockType != HeaderBlockType {
		return nil, &HeaderError{Reason: fmt.Sprintf("block type 0x%04X, expected 0x0010", blockType)}
	}
	initialValue := le32(header, 4)
	if initialValue != ChecksumSeed {
		return nil, &HeaderError{Reason: fmt.Sprintf("checksum seed 0x%08X, expected 0xFFFFFFFF", initialValue)}
	}
	algorithm := le32(header, 90)
	if algorithm != ChecksumAlgorithmCRC32C {
		return nil, &HeaderError{Reason: fmt.Sprintf("checksum algorithm %d, expected 1 (CRC-32C)", algorithm)}
	}
	checksum := le32(header, 0)
	checksumComputed := foundation.CRC32CSeeded(initialValue, header[8:])

	bytesPerSector := le32(header, 48)
	if bytesPerSector == 0 {
		return nil, &HeaderError{Reason: "bytes per sector is zero"}
	}
	blockSize := le32(header, 96)
	if blockSize == 0 {
		return nil, &HeaderError{Reason: "block size is zero"}
	}
	if !isPowerOfTwo(blockSize) {
		return nil, &HeaderError{Reason: fmt.Sprintf("block size %d is not a power of two", blockSize)}
	}
	if blockSize < 512 {
		return nil, &HeaderError{Reason: fmt.Sprintf("block size %d is below one sector", blockSize)}
	}
	if blockSize > MaxBlockSize {
		return nil, &CapError{Reason: fmt.Sprintf("block size %d exceeds %d", blockSize, MaxBlockSize)}
	}
	metadataSize := le32(header, 100)
	if metadataSize == 0 {
		return nil, &HeaderError{Reason: "metadata size is zero"}
	}
	if metadataSize > MaxMetadataSize {
		return nil, &CapError{Reason: fmt.Sprintf("metadata size %d exceeds %d", metadataSize, MaxMetadataSize)}
	}
	var metadataBlockNumbers [4]uint64
	for index := range metadataBlockNumbers {
		metadataBlockNumbers[index] = le64(header, 104+index*8)
	}
	keyDataSize := le32(header, 168)
	encryptionMethod := le32(header, 172)
	keyDataPresent := false
	for _, b := range header[176:192] {
		if b != 0 {
			keyDataPresent = true
			break
		}
	}

	return &Volume{
		Checksum:             checksum,
		ChecksumComputed:     checksumComputed,
		ChecksumOK:           checksum == checksumComputed,
		InitialValue:         initialValue,
		Version:              version,
		BlockType:            blockType,
		SerialNumber:         le32(header, 12),
		BytesPerSector:       bytesPerSector,
		PhysicalVolumeSize:   le64(header, 64),
		BlockSize:            blockSize,
		MetadataSize:         metadataSize,
		MetadataBlockNumbers: metadataBlockNumbers,
		KeyDataSize:          keyDataSize,
		EncryptionMethod:     encryptionMethod,
		KeyDataPresent:       keyDataPresent,
		PhysicalVolumeUUID:   uuidAt(header, 304),
		VolumeGroupUUID:      uuidAt(header, 320),
	}, nil
}

func readMetadata(src source.ByteSource, blockNumber uint64, blockSize uint32, headerMetadataSize uint32, sourceLen uint64) (*MetadataSection, error) {
	if blockNumber > math.MaxUint64/uint64(blockSize) {
		return nil, &OutOfBoundsError{Reason: fmt.Sprintf("metadata block %d times block size %d overflows", blockNumber, blockSize)}
	}
	offset := blockNumber * uint64(blockSize)
	if offset > math.MaxUint64-uint64(MetadataBlockBytes) {
		return nil, &OutOfBoundsError{Reason: "metadata block end overflows"}
	}
	end := offset + uint64(MetadataBlockBytes)
	if end > sourceLen {
		return nil, &OutOfBoundsError{Reason: fmt.Sprintf("metadata block %d at bytes %d..%d, source is %d bytes", blockNumber, offset, end, sourceLen)}
	}
	block := make([]byte, MetadataBlockBytes)
	if err := source.ReadExactAt(src, offset, block); err != nil {
		return nil, err
	}
	return parseMetadataBlock(block, offset, blockNumber, headerMetadataSize)
}

func parseMetadataBlock(block []byte, offset uint64, blockNumber uint64, headerMetadataSize uint32) (*MetadataSection, error) {
	wiped := string(block[0:8]) == WipedMarker
	version := le16(block, 8)
	blockType := le16(block, 10)
	checksum := le32(block, 0)
	checksumComputed := foundation.CRC32CSeeded(ChecksumSeed, block[8:])
	checksumOK := wiped || checksum == checksumComputed
	blockSize := le32(block, 48)
	if blockSize != MetadataBlockBytes {
		return nil, &HeaderError{Reason: fmt.Sprintf("metadata block declares block size %d, expected %d", blockSize, MetadataBlockBytes)}
	}
	if !wiped && blockType != MetadataBlockType {
		return nil, &HeaderError{Reason: fmt.Sprintf("metadata block type 0x%04X, expected 0x0011", blockType)}
	}
	metadataSize := le32(block, MetadataSizeOffset)
	metadataSizeMatches := metadataSize == headerMetadataSize
	if !wiped && !metadataSizeMatches {
		return nil, &HeaderError{Reason: fmt.Sprintf("metadata block size %d differs from the header's %d", metadataSize, headerMetadataSize)}
	}
	volumeGroupDescriptorOffset := le32(block, VolumeGroupDescriptorOffset)

	section := &MetadataSection{
		Offset:                      offset,
		BlockNumber:                 blockNumber,
		Checksum:                    checksum,
		ChecksumComputed:            checksumComputed,
		ChecksumOK:                  checksumOK,
		Wiped:                       wiped,
		Version:                     version,
		BlockType:                   blockType,
		BlockSize:                   blockSize,
		MetadataSize:                metadataSize,
		MetadataSizeMatches:         metadataSizeMatches,
		VolumeGroupDescriptorOffset: volumeGroupDescriptorOffset,
	}
	if wiped {
		return section, nil
	}
	if volumeGroupDescriptorOffset < MinVolumeGroupDescriptorOffset {
		return nil, &HeaderError{Reason: fmt.Sprintf(
			"volume-group descriptor offset %d is before the fixed metadata fields (%d)",
			volumeGroupDescriptorOffset, MinVolumeGroupDescriptorOffset)}
	}
	descriptorStart := int(volumeGroupDescriptorOffset)
	descriptorEnd := descriptorStart + VolumeGroupDescriptorBytes
	if descriptorEnd > len(block) {
		return nil, &OutOfBoundsError{Reason: fmt.Sprintf(
			"volume-group descriptor at %d..%d is outside the %d-byte block",
			descriptorStart, descriptorEnd, MetadataBlockBytes)}
	}
	descriptor := block[descriptorStart:descriptorEnd]
	stateRaw := le64(descriptor, 0)
	encryptedMetadataBlockCount := le64(descriptor, 8)
	if encryptedMetadataBlockCount > MaxEncryptedMetadataBlocks {
		return nil, &CapError{Reason: fmt.Sprintf(
			"encrypted metadata block count %d exceeds %d",
			encryptedMetadataBlockCount, MaxEncryptedMetadataBlocks)}
	}
	var primaryEncryptedMetadata *EncryptedMetadataBlock
	if primary := le64(descriptor, 32); primary != 0 {
		primaryEncryptedMetadata = &EncryptedMetadataBlock{
			BlockNumber: primary & 0x0000_FFFF_FFFF_FFFF,
			VolumeIndex: uint16(primary >> 48),
		}
	}
	section.VolumeGroup = &VolumeGroupDescriptor{
		StateRaw:                    stateRaw,
		State:                       ConversionStateFromRaw(stateRaw),
		EncryptedMetadataBlockCount: encryptedMetadataBlockCount,
		PrimaryEncryptedMetadata:    primaryEncryptedMetadata,
		EncryptedMetadataPresent:    encryptedMetadataBlockCount > 0,
	}
	return section, nil
}

func hasSignature(bytes []byte) bool {
	return len(bytes) >= SignatureOffset+len(Signature) &&
		string(bytes[SignatureOffset:SignatureOffset+len(Signature)]) == Signature
}

func isPowerOfTwo(value uint32) bool {
	return value != 0 && value&(value-1) == 0
}

func le16(bytes []byte, offset int) uint16 {
	return uint16(bytes[offset]) | uint16(bytes[offset+1])<<8
}

func le32(bytes []byte, offset int) uint32 {
	return uint32(bytes[offset]) |
		uint32(bytes[offset+1])<<8 |
		uint32(bytes[offset+2])<<16 |
		uint32(bytes[offset+3])<<24
}

func le64(bytes []byte, offset int) uint64 {
	var value uint64
	for i := 0; i < 8; i++ {
		value |= uint64(bytes[offset+i]) << (8 * i)
	}
	return value
}

// uuidAt formats a 16-byte big-endian UUID, or returns "" when every byte is
// zero.
func uuidAt(bytes []byte, offset int) string {
	if offset+16 > len(bytes) {
		return ""
	}
	raw := bytes[offset : offset+16]
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	)
}
