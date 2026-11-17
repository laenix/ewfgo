package reiserfs

import (
	"bytes"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Byte offsets the kernel searches for the 204-byte superblock, in order.
const (
	// SuperblockOffset35 is block 2 of a 4 KiB filesystem.
	SuperblockOffset35 uint64 = 8_192
	// SuperblockOffset36 is the copy 3.6 also accepts.
	SuperblockOffset36 uint64 = 65_536
	// SuperblockLen is the bytes this reader decodes.
	SuperblockLen = 204
)

// Block-size limits.
const (
	MinBlockSize uint32 = 1_024
	MaxBlockSize uint32 = 65_536
)

// Magics. The magic field is ten bytes on disk; the strings are NUL padded.
var (
	Magic35        = []byte("ReIsErFs")
	Magic36        = []byte("ReIsEr2Fs")
	Magic36Journal = []byte("ReIsEr3Fs")
)

// Mount and fsck states.
const (
	FSCleanlyUnmounted    uint16 = 1
	FSNotCleanlyUnmounted uint16 = 2

	FSConsistent uint16 = 0
	FSError      uint16 = 1
	FSFatal      uint16 = 2
)

// Hash codes.
const (
	HashUnsetCode uint32 = 0
	HashTeaCode   uint32 = 1
	HashYuraCode  uint32 = 2
	HashR5Code    uint32 = 3
)

// ReiserFSAttrsCleared is the only documented s_flags bit.
const ReiserFSAttrsCleared uint32 = 0x0000_0001

// MaxHeight is the tallest tree the format allows.
const MaxHeight uint16 = 5

// FsVersion is which generation of the format a magic names.
type FsVersion int

const (
	// V35 is ReIsErFs, the 3.5 format.
	V35 FsVersion = iota
	// V36 is ReIsEr2Fs, the 3.6 format.
	V36
	// V36Journal is ReIsEr3Fs, 3.6 with a relocated journal.
	V36Journal
)

// ID returns a stable identifier for the format generation.
func (v FsVersion) ID() string {
	if v == V35 {
		return "reiserfs3.5"
	}
	return "reiserfs3.6"
}

// Label returns a display name.
func (v FsVersion) Label() string {
	switch v {
	case V35:
		return "ReiserFS 3.5"
	case V36:
		return "ReiserFS 3.6"
	default:
		return "ReiserFS 3.6 (relocated journal)"
	}
}

// KeysAreV2 reports whether keys use the 3.6 encoding.
func (v FsVersion) KeysAreV2() bool { return v == V36 || v == V36Journal }

// HasCheckCounters reports whether the 3.6 check counters exist.
func (v FsVersion) HasCheckCounters() bool { return v != V35 }

// HashFunction is the name-hash code the superblock records.
type HashFunction uint32

const (
	// HashUnset records no function; the kernel detects it from the names.
	HashUnset HashFunction = HashFunction(HashUnsetCode)
	// HashTea is the TEA hash.
	HashTea HashFunction = HashFunction(HashTeaCode)
	// HashYura is Rupasov's hash (also called "yura").
	HashYura HashFunction = HashFunction(HashYuraCode)
	// HashR5 is the 3.6 default.
	HashR5 HashFunction = HashFunction(HashR5Code)
)

// Name returns the lower-case name of the hash.
func (h HashFunction) Name() string {
	switch h {
	case HashTea:
		return "tea"
	case HashYura:
		return "rupasov"
	case HashR5:
		return "r5"
	default:
		return "unset"
	}
}

func hashFromCode(code uint32) (HashFunction, error) {
	switch code {
	case HashUnsetCode:
		return HashUnset, nil
	case HashTeaCode:
		return HashTea, nil
	case HashYuraCode:
		return HashYura, nil
	case HashR5Code:
		return HashR5, nil
	default:
		return 0, unsupportedf("hash function %d; known codes are 0 (unset), 1 (tea), 2 (rupasov), 3 (r5)", code)
	}
}

// Superblock is a decoded ReiserFS superblock.
type Superblock struct {
	Offset  uint64
	Version FsVersion

	BlockCount uint32
	FreeBlocks uint32
	RootBlock  uint32

	JournalBlock        uint32
	JournalDev          uint32
	JournalSize         uint32
	JournalTransMax     uint32
	JournalBlockCount   uint32
	JournalMaxBatch     uint32
	JournalMaxCommitAge uint32
	JournalMaxTransAge  uint32

	BlockSize          uint32
	OIDMaxSize         uint16
	OIDCurSize         uint16
	UmountState        uint16
	FSState            uint16
	Hash               HashFunction
	TreeHeight         uint16
	BmapCount          uint32
	DiskVersion        uint16
	ReservedForJournal uint16
	InodeGeneration    uint32
	Flags              uint32
	UUID               [16]byte
	Label              string

	MountCount    *uint16
	MaxMountCount *uint16
	LastCheck     *uint32
	CheckInterval *uint32
}

// ParseSuperblock decodes one 204-byte superblock already known to carry
// version's magic.
func ParseSuperblock(raw []byte, offset uint64, version FsVersion) (*Superblock, error) {
	if len(raw) < SuperblockLen {
		return nil, corruptf("the superblock at %d is %d bytes; %d are needed", offset, len(raw), SuperblockLen)
	}
	blockSize := uint32(le16(raw, 0x2C))
	hash, err := hashFromCode(le32(raw, 0x40))
	if err != nil {
		return nil, err
	}
	sb := &Superblock{
		Offset:              offset,
		Version:             version,
		BlockCount:          le32(raw, 0x00),
		FreeBlocks:          le32(raw, 0x04),
		RootBlock:           le32(raw, 0x08),
		JournalBlock:        le32(raw, 0x0C),
		JournalDev:          le32(raw, 0x10),
		JournalSize:         le32(raw, 0x14),
		JournalTransMax:     le32(raw, 0x18),
		JournalBlockCount:   le32(raw, 0x1C),
		JournalMaxBatch:     le32(raw, 0x20),
		JournalMaxCommitAge: le32(raw, 0x24),
		JournalMaxTransAge:  le32(raw, 0x28),
		BlockSize:           blockSize,
		OIDMaxSize:          le16(raw, 0x2E),
		OIDCurSize:          le16(raw, 0x30),
		UmountState:         le16(raw, 0x32),
		FSState:             le16(raw, 0x3E),
		Hash:                hash,
		TreeHeight:          le16(raw, 0x44),
		BmapCount:           uint32(le16(raw, 0x46)),
		DiskVersion:         le16(raw, 0x48),
		ReservedForJournal:  le16(raw, 0x4A),
		InodeGeneration:     le32(raw, 0x4C),
		Flags:               le32(raw, 0x50),
	}
	copy(sb.UUID[:], raw[0x54:0x64])
	sb.Label = fixedText(raw[0x64:0x74])
	if version.HasCheckCounters() {
		mountCount := le16(raw, 0x74)
		maxMountCount := le16(raw, 0x76)
		lastCheck := le32(raw, 0x78)
		checkInterval := le32(raw, 0x7C)
		sb.MountCount = &mountCount
		sb.MaxMountCount = &maxMountCount
		sb.LastCheck = &lastCheck
		sb.CheckInterval = &checkInterval
	}
	return sb, nil
}

// DetectSuperblock finds and validates a superblock. (nil, nil) means no magic
// was present at either offset; a syntactically present but broken superblock
// is an error.
func DetectSuperblock(src source.ByteSource) (*Superblock, error) {
	if src == nil {
		return nil, corruptf("a nil byte source")
	}
	for _, offset := range []uint64{SuperblockOffset35, SuperblockOffset36} {
		if src.Len() < offset+SuperblockLen {
			continue
		}
		raw, err := source.ReadVecAt(src, offset, SuperblockLen)
		if err != nil {
			return nil, err
		}
		version, ok := magicOf(raw)
		if !ok {
			continue
		}
		sb, err := ParseSuperblock(raw, offset, version)
		if err != nil {
			return nil, err
		}
		if err := sb.validate(src.Len()); err != nil {
			return nil, err
		}
		return sb, nil
	}
	return nil, nil
}

// ReadSuperblock is DetectSuperblock that refuses an absent superblock.
func ReadSuperblock(src source.ByteSource) (*Superblock, error) {
	sb, err := DetectSuperblock(src)
	if err != nil {
		return nil, err
	}
	if sb == nil {
		return nil, corruptf("no ReiserFS superblock (ReIsErFs, ReIsEr2Fs, or ReIsEr3Fs) at byte 8192 or 65536")
	}
	return sb, nil
}

func (s *Superblock) validate(volumeLen uint64) error {
	if s.BlockSize == 0 || s.BlockSize&(s.BlockSize-1) != 0 ||
		s.BlockSize < MinBlockSize || s.BlockSize > MaxBlockSize {
		return corruptf("block size %d is not a power of two between %d and %d",
			s.BlockSize, MinBlockSize, MaxBlockSize)
	}
	if s.BlockCount < 3 {
		return corruptf("block count %d cannot hold a superblock, bitmap, and root", s.BlockCount)
	}
	declared := uint64(s.BlockCount) * uint64(s.BlockSize)
	if declared > volumeLen {
		return corruptf("the superblock declares %d bytes (%d blocks of %d) but the volume holds %d",
			declared, s.BlockCount, s.BlockSize, volumeLen)
	}
	if s.RootBlock == 0 || s.RootBlock >= s.BlockCount {
		return corruptf("root block %d is outside the volume's %d blocks", s.RootBlock, s.BlockCount)
	}
	if s.BmapCount == 0 || s.BmapCount >= s.BlockCount {
		return corruptf("bitmap block %d is outside the volume's %d blocks", s.BmapCount, s.BlockCount)
	}
	if s.TreeHeight == 0 || s.TreeHeight > MaxHeight {
		return corruptf("tree height %d is outside 1..=%d", s.TreeHeight, MaxHeight)
	}
	if s.JournalDev == 0 && s.JournalBlock != 0 && s.JournalBlock >= s.BlockCount {
		return corruptf("journal block %d is outside the volume's %d blocks", s.JournalBlock, s.BlockCount)
	}
	return nil
}

// Kind returns the stable format identifier.
func (s *Superblock) Kind() string { return s.Version.ID() }

// BlockSizeBytes returns bytes in one block.
func (s *Superblock) BlockSizeBytes() uint32 { return s.BlockSize }

// VolumeLen returns the bytes the filesystem spans.
func (s *Superblock) VolumeLen() uint64 {
	return uint64(s.BlockCount) * uint64(s.BlockSize)
}

// BlockOffset returns a block's byte offset, refusing a block outside the
// volume.
func (s *Superblock) BlockOffset(block uint32) (uint64, error) {
	if block >= s.BlockCount {
		return 0, corruptf("block %d is outside the volume's %d blocks", block, s.BlockCount)
	}
	return uint64(block) * uint64(s.BlockSize), nil
}

// UUIDText returns the UUID in dashed lowercase form.
func (s *Superblock) UUIDText() string { return uuidText(s.UUID) }

// IsClean reports whether both state fields agree the volume was left clean.
func (s *Superblock) IsClean() bool {
	return s.UmountState == FSCleanlyUnmounted && s.FSState == FSConsistent
}

// WasNotCleanlyUnmounted reports the unmount-state field.
func (s *Superblock) WasNotCleanlyUnmounted() bool {
	return s.UmountState == FSNotCleanlyUnmounted
}

// FSStateName returns fs_state in words.
func (s *Superblock) FSStateName() string {
	switch s.FSState {
	case FSConsistent:
		return "consistent"
	case FSError:
		return "error"
	case FSFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// UmountStateName returns umount_state in words.
func (s *Superblock) UmountStateName() string {
	switch s.UmountState {
	case FSCleanlyUnmounted:
		return "cleanly unmounted"
	case FSNotCleanlyUnmounted:
		return "not cleanly unmounted"
	default:
		return "unknown"
	}
}

// AttributesCleared reports the only documented s_flags bit.
func (s *Superblock) AttributesCleared() bool { return s.Flags&ReiserFSAttrsCleared != 0 }

func magicOf(raw []byte) (FsVersion, bool) {
	if len(raw) < 0x34+10 {
		return 0, false
	}
	field := raw[0x34 : 0x34+10]
	switch {
	case bytes.HasPrefix(field, Magic36Journal):
		return V36Journal, true
	case bytes.HasPrefix(field, Magic36):
		return V36, true
	case bytes.HasPrefix(field, Magic35):
		return V35, true
	default:
		return 0, false
	}
}

func fixedText(raw []byte) string {
	if end := bytes.IndexByte(raw, 0); end >= 0 {
		raw = raw[:end]
	}
	return string(raw)
}

func uuidText(uuid [16]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for index, value := range uuid {
		switch index {
		case 4, 6, 8, 10:
			out = append(out, '-')
		}
		out = append(out, hex[value>>4], hex[value&0x0F])
	}
	return string(out)
}

func le16(raw []byte, at int) uint16 {
	return uint16(raw[at]) | uint16(raw[at+1])<<8
}

func le32(raw []byte, at int) uint32 {
	return uint32(raw[at]) |
		uint32(raw[at+1])<<8 |
		uint32(raw[at+2])<<16 |
		uint32(raw[at+3])<<24
}

func le64(raw []byte, at int) uint64 {
	return uint64(le32(raw, at)) | uint64(le32(raw, at+4))<<32
}
