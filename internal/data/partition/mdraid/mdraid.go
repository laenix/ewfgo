// Package mdraid decodes Linux software-RAID member metadata: the 0.90 and
// 1.x superblock families. It is a pure-Go port of forensic-core's
// partition/mdraid layer, starting with superblock parsing, the single-member
// data-area source, and RAID0 assembly.
package mdraid

import (
	"errors"
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// MDMagic is the superblock magic shared by both families.
	MDMagic uint32 = 0xA92B4EFC
	// SuperblockBytes is the size of one superblock block.
	SuperblockBytes = 4096
	// SectorBytes is md's address unit for data areas.
	SectorBytes uint64 = 512
	// ReservedBytes090 is the tail a 0.90 member reserves for metadata.
	ReservedBytes090 uint64 = 64 * 1024
)

const (
	sb1ChecksumFixedBytes = 256
	sb1CsumOffset         = 0xD8
	sb1RolesOffset        = 0x100
	sb1MaxDevOffset       = 0xDC
	sb1MaxDevLimit        = (SuperblockBytes - sb1ChecksumFixedBytes) / 2
	sb0CsumOffset         = 0x98
	sb0MinorOffset        = 0x08
	sb0DisksOffset        = 0x200
	sb0DescriptorBytes    = 128
	sb0Disks              = 27
	sb0DescriptorRole     = 12
	sb0DescriptorState    = 16
	mdDiskFaulty          = 1 << 0
	mdDiskActive          = 1 << 1
	mdDiskSync            = 1 << 2
	sb0ActiveRoleMinor    = 91
	sb0ReservedSectors    = 128
	mdDiskRoleMax         = 0xFF00
	mdDiskRoleSpare       = 0xFFFF
	mdDiskRoleFaulty      = 0xFFFE
	seconds40Bits         = (uint64(1) << 40) - 1
)

// Errors. Callers test them with errors.Is.
var (
	ErrUnsupported = errors.New("mdraid: unsupported")
	ErrCorrupt     = errors.New("mdraid: corrupt superblock")
)

// Version identifies the superblock family and, for 1.x, the location.
type Version struct {
	// Family is 0 for 0.90 and 1 for 1.x.
	Family uint8
	// Minor is 0, 1 or 2 for 1.x; ignored for 0.90.
	Minor uint8
}

// Label returns "0.90", "1.0", "1.1", "1.2" or "1.x".
func (v Version) Label() string {
	if v.Family == 0 {
		return "0.90"
	}
	switch v.Minor {
	case 0:
		return "1.0"
	case 1:
		return "1.1"
	case 2:
		return "1.2"
	default:
		return "1.x"
	}
}

// Checksum is the result of checking sb_csum.
type Checksum uint8

const (
	// ChecksumVerified means the computed sum equals the stored sum.
	ChecksumVerified Checksum = iota
	// ChecksumMismatch means the stored sum differs; the superblock is still
	// reported because a torn write is common on a pulled member.
	ChecksumMismatch
)

// Label returns "verified" or "mismatch".
func (c Checksum) Label() string {
	if c == ChecksumVerified {
		return "verified"
	}
	return "mismatch"
}

// Superblock is one member's decoded metadata.
type Superblock struct {
	Version                Version
	Magic                  uint32
	MajorVersion           uint32
	FeatureMap             uint32
	Pad0                   uint32
	SetUUID                [16]byte
	SetName                string
	Ctime                  uint64
	Level                  int32
	Layout                 uint32
	Size                   uint64
	ChunkSizeBytes         uint64
	RaidDisks              uint32
	BitmapOffsetSectors    int32
	NewLevel               int32
	ReshapePositionSectors *uint64
	DeltaDisks             int32
	NewLayout              uint32
	NewChunk               uint32
	NewOffsetSectors       int32
	DataOffsetSectors      uint64
	DataSizeSectors        uint64
	SuperOffsetSectors     uint64
	RecoveryOffsetSectors  uint64
	DevNumber              uint32
	CntCorrectedRead       uint32
	DeviceUUID             [16]byte
	DevFlags               uint8
	BBLogShift             uint8
	Utime                  uint64
	Events                 uint64
	ResyncOffset           uint64
	SBCsum                 uint32
	MaxDev                 uint32
	Roles                  []uint16
	Checksum               Checksum
	SuperblockOffset       uint64
	State                  *uint32
}

// DataOffsetBytes returns the byte offset of the member's data area.
func (s *Superblock) DataOffsetBytes() uint64 { return s.DataOffsetSectors * SectorBytes }

// DataSizeBytes returns the data area length in bytes; zero means "the rest of
// the device".
func (s *Superblock) DataSizeBytes() uint64 { return s.DataSizeSectors * SectorBytes }

// ComponentSizeBytes returns the per-member size the superblock records.
func (s *Superblock) ComponentSizeBytes() uint64 {
	if s.Version.Family == 0 {
		return s.Size * 1024
	}
	return s.Size * SectorBytes
}

// LevelName returns the RAID level name.
func (s *Superblock) LevelName() string {
	if name, ok := levelName(s.Level); ok {
		return name
	}
	return "unknown"
}

// Role returns this member's role from the per-device role table.
func (s *Superblock) Role() (uint16, bool) {
	if int(s.DevNumber) >= len(s.Roles) {
		return 0, false
	}
	return s.Roles[s.DevNumber], true
}

// ArrayUUID returns mdadm's colon-separated text form of the set identifier.
func (s *Superblock) ArrayUUID() string { return uuidText(s.SetUUID) }

// MemberUUID returns the per-device identifier in the same text form.
func (s *Superblock) MemberUUID() string { return uuidText(s.DeviceUUID) }

// CtimeSeconds returns the creation time as Unix seconds.
func (s *Superblock) CtimeSeconds() uint64 {
	if s.Version.Family == 0 {
		return s.Ctime
	}
	return s.Ctime & seconds40Bits
}

// UpdatedSeconds returns the last update time as Unix seconds.
func (s *Superblock) UpdatedSeconds() uint64 {
	if s.Version.Family == 0 {
		return s.Utime
	}
	return s.Utime & seconds40Bits
}

// Clean reports the 0.90 clean bit. A 1.x superblock has no array-state word,
// so this returns nil rather than a guess.
func (s *Superblock) Clean() *bool {
	if s.Version.Family != 0 || s.State == nil {
		return nil
	}
	clean := *s.State&1 != 0
	return &clean
}

// HasFeature reports whether a 1.x feature bit is set. Always false for 0.90.
func (s *Superblock) HasFeature(feature uint32) bool { return s.FeatureMap&feature != 0 }

// Parse reads a member's superblock. A nil result with a nil error means no
// superblock was found at any defined location.
func Parse(src source.ByteSource) (*Superblock, error) {
	length := src.Len()
	if length < SuperblockBytes {
		return nil, nil
	}

	if sb, err := read1x(src, 0, 1); err != nil {
		return nil, err
	} else if sb != nil {
		return sb, nil
	}
	if length >= 2*SuperblockBytes {
		if sb, err := read1x(src, SuperblockBytes, 2); err != nil {
			return nil, err
		} else if sb != nil {
			return sb, nil
		}
	}
	if offset, ok := sb10Offset(length); ok && offset != 0 {
		if sb, err := read1x(src, offset, 0); err != nil {
			return nil, err
		} else if sb != nil {
			return sb, nil
		}
	}
	return read090(src)
}

// MatchesHead reports whether a short intake buffer starts like a 1.1 or 1.2
// member. It cannot see 1.0 or 0.90 superblocks.
func MatchesHead(head []byte) bool {
	magic := []byte{0xFC, 0x4E, 0x2B, 0xA9} // MDMagic little-endian
	return len(head) >= 4 && string(head[0:4]) == string(magic) ||
		len(head) >= 4100 && string(head[4096:4100]) == string(magic)
}

func read1x(src source.ByteSource, offset uint64, minor uint8) (*Superblock, error) {
	if offset+SuperblockBytes > src.Len() {
		return nil, nil
	}
	block, err := source.ReadVecAt(src, offset, SuperblockBytes)
	if err != nil {
		return nil, err
	}
	if le32(block, 0) != MDMagic {
		return nil, nil
	}
	major := le32(block, 4)
	if major == 0 {
		return nil, nil
	}
	if major != 1 {
		return nil, fmt.Errorf("%w: mdraid major version %d at offset %d", ErrUnsupported, major, offset)
	}

	maxDev := le32(block, sb1MaxDevOffset)
	if maxDev > sb1MaxDevLimit {
		return nil, fmt.Errorf("%w: mdraid 1.x max_dev %d extends the checksum past the superblock",
			ErrCorrupt, maxDev)
	}
	stored := le32(block, sb1CsumOffset)
	covered := append([]byte(nil), block...)
	clear(covered[sb1CsumOffset : sb1CsumOffset+4])
	computed := foldChecksum(covered, sb1ChecksumFixedBytes+int(maxDev)*2, false)
	checksum := ChecksumVerified
	if computed != stored {
		checksum = ChecksumMismatch
	}

	roles := make([]uint16, maxDev)
	for i := range roles {
		roles[i] = le16(block, sb1RolesOffset+i*2)
	}

	level := int32(le32(block, 0x48))
	if err := checkLevel(level, offset); err != nil {
		return nil, err
	}
	dataOffset := le64(block, 0x80)
	dataSize := le64(block, 0x88)
	if err := validateDataArea(offset, src.Len(), dataOffset, dataSize); err != nil {
		return nil, err
	}

	var setUUID, deviceUUID [16]byte
	copy(setUUID[:], block[0x10:0x20])
	copy(deviceUUID[:], block[0xA8:0xB8])
	reshape := le64(block, 0x68)

	return &Superblock{
		Version:                Version{Family: 1, Minor: minor},
		Magic:                  MDMagic,
		MajorVersion:           major,
		FeatureMap:             le32(block, 0x08),
		Pad0:                   le32(block, 0x0C),
		SetUUID:                setUUID,
		SetName:                cString(block, 0x20, 32),
		Ctime:                  le64(block, 0x40),
		Level:                  level,
		Layout:                 le32(block, 0x4C),
		Size:                   le64(block, 0x50),
		ChunkSizeBytes:         uint64(le32(block, 0x58)) * SectorBytes,
		RaidDisks:              le32(block, 0x5C),
		BitmapOffsetSectors:    int32(le32(block, 0x60)),
		NewLevel:               int32(le32(block, 0x64)),
		ReshapePositionSectors: &reshape,
		DeltaDisks:             int32(le32(block, 0x70)),
		NewLayout:              le32(block, 0x74),
		NewChunk:               le32(block, 0x78),
		NewOffsetSectors:       int32(le32(block, 0x7C)),
		DataOffsetSectors:      dataOffset,
		DataSizeSectors:        dataSize,
		SuperOffsetSectors:     le64(block, 0x90),
		RecoveryOffsetSectors:  le64(block, 0x98),
		DevNumber:              le32(block, 0xA0),
		CntCorrectedRead:       le32(block, 0xA4),
		DeviceUUID:             deviceUUID,
		DevFlags:               block[0xB8],
		BBLogShift:             block[0xB9],
		Utime:                  le64(block, 0xC0),
		Events:                 le64(block, 0xC8),
		ResyncOffset:           le64(block, 0xD0),
		SBCsum:                 stored,
		MaxDev:                 maxDev,
		Roles:                  roles,
		Checksum:               checksum,
		SuperblockOffset:       offset,
	}, nil
}

func read090(src source.ByteSource) (*Superblock, error) {
	length := src.Len()
	first := sb0Offset(length)
	tail := length - SuperblockBytes
	if sb, err := read090At(src, first); err != nil {
		return nil, err
	} else if sb != nil {
		return sb, nil
	}
	if tail != first {
		if sb, err := read090At(src, tail); err != nil {
			return nil, err
		} else if sb != nil {
			return sb, nil
		}
	}
	return nil, nil
}

func read090At(src source.ByteSource, offset uint64) (*Superblock, error) {
	if offset+SuperblockBytes > src.Len() {
		return nil, nil
	}
	block, err := source.ReadVecAt(src, offset, SuperblockBytes)
	if err != nil {
		return nil, err
	}

	little := le32(block, 0)
	big := be32(block, 0)
	var bigEndian bool
	switch {
	case little == MDMagic:
		bigEndian = false
	case big == MDMagic:
		bigEndian = true
	default:
		return nil, nil
	}

	major := readU32(block, 4, bigEndian)
	if major == 1 {
		return nil, nil
	}
	if major != 0 {
		return nil, fmt.Errorf("%w: mdraid major version %d at offset %d", ErrUnsupported, major, offset)
	}

	length := src.Len()
	if length < ReservedBytes090 {
		return nil, fmt.Errorf("%w: a 0.90 mdraid member of %d bytes is smaller than the %d bytes the family reserves",
			ErrCorrupt, length, ReservedBytes090)
	}

	level := int32(readU32(block, 0x1C, bigEndian))
	if err := checkLevel(level, offset); err != nil {
		return nil, err
	}
	raidDisks := readU32(block, 0x28, bigEndian)
	chunkSize := uint64(readU32(block, 0x104, bigEndian))
	roles := read090Roles(block, raidDisks, bigEndian)

	stored := readU32(block, sb0CsumOffset, bigEndian)
	covered := append([]byte(nil), block...)
	clear(covered[sb0CsumOffset : sb0CsumOffset+4])
	computed := foldChecksum(covered, SuperblockBytes, bigEndian)
	checksum := ChecksumVerified
	if computed != stored {
		checksum = ChecksumMismatch
	}

	var setUUID [16]byte
	for index, at := range []int{0x14, 0x34, 0x38, 0x3C} {
		word := readU32(block, at, bigEndian)
		setUUID[index*4] = byte(word >> 24)
		setUUID[index*4+1] = byte(word >> 16)
		setUUID[index*4+2] = byte(word >> 8)
		setUUID[index*4+3] = byte(word)
	}

	dataSizeSectors := offset / SectorBytes
	state := readU32(block, 0x84, bigEndian)
	reshape := readU64(block, 0xB0, bigEndian)

	return &Superblock{
		Version:                Version{Family: 0},
		Magic:                  MDMagic,
		MajorVersion:           major,
		SetUUID:                setUUID,
		Ctime:                  uint64(readU32(block, 0x18, bigEndian)),
		Level:                  level,
		Layout:                 readU32(block, 0x100, bigEndian),
		Size:                   uint64(readU32(block, 0x20, bigEndian)),
		ChunkSizeBytes:         chunkSize,
		RaidDisks:              raidDisks,
		NewLevel:               int32(readU32(block, 0xB8, bigEndian)),
		ReshapePositionSectors: &reshape,
		DeltaDisks:             int32(readU32(block, 0xBC, bigEndian)),
		NewLayout:              readU32(block, 0xC0, bigEndian),
		NewChunk:               readU32(block, 0xC4, bigEndian),
		DataOffsetSectors:      0,
		DataSizeSectors:        dataSizeSectors,
		SuperOffsetSectors:     offset / SectorBytes,
		RecoveryOffsetSectors:  uint64(readU32(block, 0xAC, bigEndian)),
		DevNumber:              readU32(block, 0xF80, bigEndian),
		Utime:                  uint64(readU32(block, 0x80, bigEndian)),
		Events:                 readU64(block, 0x9C, bigEndian),
		SBCsum:                 stored,
		Roles:                  roles,
		Checksum:               checksum,
		SuperblockOffset:       offset,
		State:                  &state,
	}, nil
}

func read090Roles(block []byte, raidDisks uint32, bigEndian bool) []uint16 {
	minor := readU32(block, sb0MinorOffset, bigEndian)
	roles := make([]uint16, sb0Disks)
	for slot := 0; slot < sb0Disks; slot++ {
		at := sb0DisksOffset + slot*sb0DescriptorBytes
		role := readU32(block, at+sb0DescriptorRole, bigEndian)
		state := readU32(block, at+sb0DescriptorState, bigEndian)
		regular := role < mdDiskRoleMax
		hasRole := (state&mdDiskSync != 0 && role < raidDisks) ||
			(state&mdDiskActive != 0 && minor >= sb0ActiveRoleMinor)
		switch {
		case state&mdDiskFaulty != 0:
			roles[slot] = mdDiskRoleFaulty
		case hasRole && regular:
			roles[slot] = uint16(role)
		default:
			roles[slot] = mdDiskRoleSpare
		}
	}
	return roles
}

func validateDataArea(superblockOffset, deviceLen, dataOffsetSectors, dataSizeSectors uint64) error {
	start, ok := checkedMul(dataOffsetSectors, SectorBytes)
	if !ok {
		return fmt.Errorf("%w: mdraid data offset %d sectors overflows a byte offset",
			ErrCorrupt, dataOffsetSectors)
	}
	if start > deviceLen {
		return fmt.Errorf("%w: mdraid data area starts at byte %d, past the %d-byte member",
			ErrCorrupt, start, deviceLen)
	}
	if dataSizeSectors == 0 {
		return nil
	}
	size, ok := checkedMul(dataSizeSectors, SectorBytes)
	if !ok {
		return fmt.Errorf("%w: mdraid data size %d sectors overflows a byte length",
			ErrCorrupt, dataSizeSectors)
	}
	available := deviceLen - start
	if size > available {
		return fmt.Errorf("%w: mdraid data area at byte %d with %d bytes does not fit in the %d-byte member",
			ErrCorrupt, start, size, deviceLen)
	}
	return nil
}

func checkLevel(level int32, offset uint64) error {
	if _, ok := levelName(level); ok {
		return nil
	}
	return fmt.Errorf("%w: mdraid RAID level %d at offset %d is not a defined level",
		ErrUnsupported, level, offset)
}

func levelName(level int32) (string, bool) {
	switch level {
	case -5:
		return "faulty", true
	case -4:
		return "multipath", true
	case -1:
		return "linear", true
	case 0:
		return "raid0", true
	case 1:
		return "raid1", true
	case 4:
		return "raid4", true
	case 5:
		return "raid5", true
	case 6:
		return "raid6", true
	case 10:
		return "raid10", true
	default:
		return "", false
	}
}

// sb10Offset returns the kernel's 1.0 superblock offset:
// (sectors - 8*2) & ~(4*2 - 1).
func sb10Offset(length uint64) (uint64, bool) {
	sectors := length / SectorBytes
	start := uint64(0)
	if sectors >= 16 {
		start = sectors - 16
	}
	start &= ^uint64(7)
	offset := start * SectorBytes
	if offset+SuperblockBytes <= length {
		return offset, true
	}
	return 0, false
}

// sb0Offset returns the start of a 0.90 member's reserved tail:
// (sectors & ~127) - 128.
func sb0Offset(length uint64) uint64 {
	sectors := length / SectorBytes
	start := sectors & ^uint64(sb0ReservedSectors-1)
	if start >= sb0ReservedSectors {
		start -= sb0ReservedSectors
	} else {
		start = 0
	}
	return start * SectorBytes
}

// wordSum sums 32-bit words over bytes[:span], accumulating in 64 bits. A
// two-byte tail is added as a 16-bit word.
func wordSum(bytes []byte, span int, bigEndian bool) uint64 {
	if span > len(bytes) {
		span = len(bytes)
	}
	whole := span - span%4
	var sum uint64
	for i := 0; i < whole; i += 4 {
		sum += uint64(readU32(bytes, i, bigEndian))
	}
	if span%4 == 2 {
		sum += uint64(readU16(bytes, whole, bigEndian))
	}
	return sum
}

// foldChecksum folds the 64-bit word sum once, as both md checksum families do.
func foldChecksum(bytes []byte, span int, bigEndian bool) uint32 {
	sum := wordSum(bytes, span, bigEndian)
	return uint32((sum & 0xFFFFFFFF) + (sum >> 32))
}

func cString(bytes []byte, at, length int) string {
	raw := bytes[at : at+length]
	end := len(raw)
	for i, b := range raw {
		if b == 0 {
			end = i
			break
		}
	}
	return strings.ToValidUTF8(string(raw[:end]), "�")
}

func uuidText(bytes [16]byte) string {
	var out strings.Builder
	for i := 0; i < 16; i += 4 {
		if i > 0 {
			out.WriteByte(':')
		}
		fmt.Fprintf(&out, "%02x%02x%02x%02x", bytes[i], bytes[i+1], bytes[i+2], bytes[i+3])
	}
	return out.String()
}

func readU16(bytes []byte, at int, bigEndian bool) uint16 {
	if bigEndian {
		return uint16(bytes[at])<<8 | uint16(bytes[at+1])
	}
	return uint16(bytes[at]) | uint16(bytes[at+1])<<8
}

func readU32(bytes []byte, at int, bigEndian bool) uint32 {
	if bigEndian {
		return uint32(bytes[at])<<24 | uint32(bytes[at+1])<<16 | uint32(bytes[at+2])<<8 | uint32(bytes[at+3])
	}
	return uint32(bytes[at]) | uint32(bytes[at+1])<<8 | uint32(bytes[at+2])<<16 | uint32(bytes[at+3])<<24
}

func readU64(bytes []byte, at int, bigEndian bool) uint64 {
	if bigEndian {
		return uint64(readU32(bytes, at, true))<<32 | uint64(readU32(bytes, at+4, true))
	}
	return uint64(readU32(bytes, at, false)) | uint64(readU32(bytes, at+4, false))<<32
}

func le16(bytes []byte, at int) uint16 { return readU16(bytes, at, false) }
func le32(bytes []byte, at int) uint32 { return readU32(bytes, at, false) }
func le64(bytes []byte, at int) uint64 { return readU64(bytes, at, false) }
func be32(bytes []byte, at int) uint32 { return readU32(bytes, at, true) }

func checkedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}
