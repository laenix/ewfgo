package jfs

import (
	"bytes"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

const superLen = 0xB8

// Superblock is a parsed JFS aggregate superblock. The primary copy lives at
// byte 0x8000; the secondary copy at 0xF000 is reported, never used to mount.
type Superblock struct {
	// Offset is the byte offset the structure was read from.
	Offset uint64
	// Version is s_version. Linux writes 2.
	Version uint32
	// SizeRaw is s_size: aggregate size in hardware/LVM blocks.
	SizeRaw uint64
	// BlockSize is s_bsize, always 4096 here.
	BlockSize uint32
	// L2Bsize is the base-two logarithm of BlockSize.
	L2Bsize uint16
	// L2Bfactor is log2(BlockSize / Pbsize).
	L2Bfactor uint16
	// Pbsize is the physical (hardware) block size.
	Pbsize uint32
	// L2Pbsize is the base-two logarithm of Pbsize.
	L2Pbsize uint16
	// AGSize is the allocation group size in filesystem blocks.
	AGSize uint32
	// Flags is s_flag.
	Flags uint32
	// State is s_state.
	State uint32
	// Compress is s_compress.
	Compress uint32
	// Ait2 and Aim2 describe the secondary aggregate inode table and map.
	Ait2 Pxd
	Aim2 Pxd

	LogDev     uint32
	LogSerial  uint32
	LogPxd     Pxd
	FsckPxd    Pxd
	Time       Timestamp
	FsckLogLen uint32
	FsckLog    int8

	// Fpack is the OS/2-compatible volume pack name.
	Fpack   [11]byte
	UUID    [16]byte
	Label   [16]byte
	LogUUID [16]byte
}

// ParseSuperblock validates and decodes the 184-byte structure. A matching
// magic with a broken geometry is an error, so a caller can tell "not JFS"
// from "broken JFS".
func ParseSuperblock(raw []byte, offset uint64) (*Superblock, error) {
	if len(raw) < superLen {
		return nil, corruptf("a JFS superblock needs %d bytes, not %d", superLen, len(raw))
	}
	raw = raw[:superLen]
	if !bytes.Equal(raw[0:4], Magic[:]) {
		return nil, corruptf("the superblock does not begin with the JFS1 magic")
	}
	version := le32(raw, 0x04)
	if version > AggregateVersion {
		return nil, corruptf("superblock version %d is newer than the format's version %d", version, AggregateVersion)
	}
	blockSize := le32(raw, 0x10)
	if blockSize != BlockSize {
		return nil, corruptf("JFS block size %d is not 4096; Linux JFS supports only 4 KiB blocks", blockSize)
	}
	if l2 := le16(raw, 0x14); l2 != 12 {
		return nil, corruptf("s_l2bsize is %d, but a 4096-byte block has base-two logarithm 12", l2)
	}
	if le16(raw, 0x1E) != 0 {
		return nil, corruptf("the superblock's alignment pad field is not zero")
	}
	state := le32(raw, 0x28)
	if state > FMStateMask {
		return nil, corruptf("mount state %#x is outside the defined range 0..=%#x", state, FMStateMask)
	}
	l2bfactor := le16(raw, 0x16)
	if l2bfactor > 16 {
		return nil, corruptf("s_l2bfactor %d is implausibly large", l2bfactor)
	}
	ait2, err := ParsePxd(raw, 0x30)
	if err != nil {
		return nil, err
	}
	aim2, err := ParsePxd(raw, 0x38)
	if err != nil {
		return nil, err
	}
	logPxd, err := ParsePxd(raw, 0x48)
	if err != nil {
		return nil, err
	}
	fsckPxd, err := ParsePxd(raw, 0x50)
	if err != nil {
		return nil, err
	}
	timestamp, err := ParseTimestamp(raw, 0x58)
	if err != nil {
		return nil, err
	}
	sb := &Superblock{
		Offset:     offset,
		Version:    version,
		SizeRaw:    le64(raw, 0x08),
		BlockSize:  blockSize,
		L2Bsize:    le16(raw, 0x14),
		L2Bfactor:  l2bfactor,
		Pbsize:     le32(raw, 0x18),
		L2Pbsize:   le16(raw, 0x1C),
		AGSize:     le32(raw, 0x20),
		Flags:      le32(raw, 0x24),
		State:      state,
		Compress:   le32(raw, 0x2C),
		Ait2:       ait2,
		Aim2:       aim2,
		LogDev:     le32(raw, 0x40),
		LogSerial:  le32(raw, 0x44),
		LogPxd:     logPxd,
		FsckPxd:    fsckPxd,
		Time:       timestamp,
		FsckLogLen: le32(raw, 0x60),
		FsckLog:    int8(raw[0x64]),
	}
	copy(sb.Fpack[:], raw[0x65:0x70])
	copy(sb.UUID[:], raw[0x88:0x98])
	copy(sb.Label[:], raw[0x98:0xA8])
	copy(sb.LogUUID[:], raw[0xA8:0xB8])
	return sb, nil
}

// DetectSuperblock reads the primary superblock when the source carries one.
// A source too short to hold the magic, or whose magic is something else,
// yields (nil, nil). Once the magic matches, a damaged structure is an error.
func DetectSuperblock(src source.ByteSource) (*Superblock, error) {
	if src == nil {
		return nil, corruptf("a nil byte source")
	}
	if src.Len() < SuperblockOffset+4 {
		return nil, nil
	}
	var magic [4]byte
	if err := source.ReadExactAt(src, SuperblockOffset, magic[:]); err != nil {
		return nil, nil
	}
	if !bytes.Equal(magic[:], Magic[:]) {
		return nil, nil
	}
	if src.Len() < SuperblockOffset+superLen {
		return nil, source.NewUnexpectedEOF(SuperblockOffset)
	}
	raw, err := source.ReadVecAt(src, SuperblockOffset, superLen)
	if err != nil {
		return nil, err
	}
	return ParseSuperblock(raw, SuperblockOffset)
}

// ReadSuperblock is DetectSuperblock that refuses an absent superblock.
func ReadSuperblock(src source.ByteSource) (*Superblock, error) {
	sb, err := DetectSuperblock(src)
	if err != nil {
		return nil, err
	}
	if sb == nil {
		return nil, corruptf("no JFS1 superblock at byte %#x", SuperblockOffset)
	}
	return sb, nil
}

// SizeBlocks returns the aggregate size in filesystem blocks.
func (s *Superblock) SizeBlocks() uint64 {
	return s.SizeRaw >> s.L2Bfactor
}

// LabelText returns the volume label with the NUL padding removed.
func (s *Superblock) LabelText() string { return fixedText(s.Label[:]) }

// FpackText returns the OS/2-compatible pack name.
func (s *Superblock) FpackText() string { return fixedText(s.Fpack[:]) }

// UUIDText returns the UUID in dashed lowercase form.
func (s *Superblock) UUIDText() string { return uuidText(s.UUID) }

// LogUUIDText returns the log device UUID in dashed lowercase form.
func (s *Superblock) LogUUIDText() string { return uuidText(s.LogUUID) }

// IsClean reports whether the aggregate was cleanly unmounted.
func (s *Superblock) IsClean() bool { return s.State == FMClean }

// StateName returns the mount state in words.
func (s *Superblock) StateName() string {
	switch s.State {
	case FMClean:
		return "clean"
	case FMMount:
		return "mounted"
	case FMDirty:
		return "dirty"
	case FMLogRedo:
		return "log redo"
	case FMExtendFS:
		return "extending"
	default:
		return "unknown"
	}
}

// HasDirectoryIndex reports whether directory leaf entries carry the
// persistent index word (which shortens the inline name area).
func (s *Superblock) HasDirectoryIndex() bool { return s.Flags&JFSDirIndex != 0 }

// IsOS2 reports whether names follow OS/2's case-insensitive rule.
func (s *Superblock) IsOS2() bool { return s.Flags&JFSOS2 != 0 }

// HasInlineLog reports whether the aggregate carries an inline log.
func (s *Superblock) HasInlineLog() bool { return s.Flags&JFSInlineLog != 0 }

// SecondaryAITBad reports whether the secondary aggregate inode table is
// known to be invalid.
func (s *Superblock) SecondaryAITBad() bool { return s.Flags&JFSBadSAIT != 0 }

// FlagNames returns the set flag names, in the order the format declares them.
func (s *Superblock) FlagNames() []string {
	names := []struct {
		bit  uint32
		name string
	}{
		{JFSUnicode, "unicode"},
		{JFSInlineLog, "inline-log"},
		{JFSBadSAIT, "secondary-ait-bad"},
		{JFSSparse, "sparse"},
		{JFSSwapBytes, "swapped"},
		{JFSDirIndex, "directory-index"},
		{JFSLinux, "linux"},
		{JFSOS2, "os2"},
		{JFSAIX, "aix"},
	}
	out := make([]string, 0, len(names))
	for _, entry := range names {
		if s.Flags&entry.bit != 0 {
			out = append(out, entry.name)
		}
	}
	return out
}

func fixedText(raw []byte) string {
	if end := bytes.IndexByte(raw, 0); end >= 0 {
		raw = raw[:end]
	}
	return string(raw)
}

func uuidText(uuid [16]byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15])
}
