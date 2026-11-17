package hammer2

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Magic is HAMMER2_VOLUME_ID_HBO as a little-endian word.
const Magic uint64 = 0x4841_4d32_0517_2011

// MagicReversed is the same word in reversed byte order (HAMMER2_VOLUME_ID_ABO).
const MagicReversed uint64 = 0x1120_1705_324d_4148

// VolhdrBytes is HAMMER2_VOLUME_BYTES: one volume header record.
const VolhdrBytes uint64 = 65_536

// ZoneBytes is HAMMER2_ZONE_BYTES64: the distance between header copies.
const ZoneBytes uint64 = 2 * 1024 * 1024 * 1024

// NumVolhdr is HAMMER2_NUM_VOLHDRS.
const NumVolhdr = 4

// VolumeAlign is HAMMER2_VOLUME_ALIGN.
const VolumeAlign uint64 = 8 * 1024 * 1024

// MaxVolumes is HAMMER2_MAX_VOLUMES.
const MaxVolumes = 64

// Volume format versions.
const (
	VersionMin          uint32 = 1
	VersionMultiVolumes uint32 = 2
	VersionWIP          uint32 = 3
	MaxVersion          uint32 = VersionMultiVolumes
)

// FSTypeUUID is HAMMER2_UUID_STRING.
const FSTypeUUID = "5cbb9ad1-862d-11dc-a94d-01301bb8a9f5"

// FSTypeLE is the fstype UUID in DragonFly's on-disk struct field order.
var FSTypeLE = [16]byte{
	0xd1, 0x9a, 0xbb, 0x5c, 0x2d, 0x86, 0xdc, 0x11,
	0xa9, 0x4d, 0x01, 0x30, 0x1b, 0xb8, 0xa9, 0xf5,
}

// FSTypeRFC is the same UUID in RFC 4122 byte order, accepted as an
// alternative encoding.
var FSTypeRFC = [16]byte{
	0x5c, 0xbb, 0x9a, 0xd1, 0x86, 0x2d, 0x11, 0xdc,
	0xa9, 0x4d, 0x01, 0x30, 0x1b, 0xb8, 0xa9, 0xf5,
}

// Offsets inside the volume header.
const (
	MagicAt           = 0x0000
	BootBegAt         = 0x0008
	BootEndAt         = 0x0010
	AuxBegAt          = 0x0018
	AuxEndAt          = 0x0020
	VoluSizeAt        = 0x0028
	VersionAt         = 0x0030
	FlagsAt           = 0x0034
	CopyIDAt          = 0x0038
	FreemapVersionAt  = 0x0039
	PeerTypeAt        = 0x003a
	VolumeIDAt        = 0x003b
	NVolumesAt        = 0x003c
	FSIDAt            = 0x0040
	FSTypeAt          = 0x0050
	AllocatorSizeAt   = 0x0060
	AllocatorFreeAt   = 0x0068
	AllocatorBegAt    = 0x0070
	MirrorTidAt       = 0x0078
	FreemapTidAt      = 0x0090
	BulkfreeTidAt     = 0x0098
	TotalSizeAt       = 0x00c0
	SrootBlocksetAt   = 0x0200
	FreemapBlocksetAt = 0x0800
	VoluLoffAt        = 0x0e00
)

// Stored CRC offsets.
const (
	ICRCSect1At  = 0x01f8
	ICRCSect0At  = 0x01fc
	ICRCVolhdrAt = 0xfffc
)

// Superblock is a parsed, checksum-verified HAMMER2 volume header.
type Superblock struct {
	Zone           uint32
	VolumeOffset   uint64
	BootBeg        uint64
	BootEnd        uint64
	AuxBeg         uint64
	AuxEnd         uint64
	VoluSize       uint64
	Version        uint32
	Flags          uint32
	CopyID         uint8
	FreemapVersion uint8
	PeerType       uint8
	VolumeID       uint8
	NVolumes       uint8
	FSID           [16]byte
	FSType         [16]byte
	AllocatorSize  uint64
	AllocatorFree  uint64
	AllocatorBeg   uint64
	MirrorTid      uint64
	FreemapTid     uint64
	BulkfreeTid    uint64
	TotalSize      uint64
	VoluLoff       [MaxVolumes]uint64
	// SrootBlockset is the super-root. Its first non-empty key-0 reference
	// is the root inode of the whole filesystem.
	SrootBlockset *Blockset
	// FreemapBlockset is parsed for structure; never decoded.
	FreemapBlockset *Blockset
	// SourceBytes is how many bytes the source holds, used to bound reads.
	SourceBytes uint64
}

// FSTypeCanonical reports whether the stored fstype is HAMMER2's, in either
// accepted encoding.
func (s *Superblock) FSTypeCanonical() bool {
	return s.FSType == FSTypeLE || s.FSType == FSTypeRFC
}

// FSTypeHex returns the fstype as lowercase hexadecimal.
func (s *Superblock) FSTypeHex() string { return hex.EncodeToString(s.FSType[:]) }

// FSIDHex returns the fsid as lowercase hexadecimal.
func (s *Superblock) FSIDHex() string { return hex.EncodeToString(s.FSID[:]) }

// magicAt reads the magic of the copy in one zone, or reports that the zone
// lies beyond the end of the source.
func magicAt(src source.ByteSource, offset uint64) (uint64, bool, error) {
	end := offset + 8
	if end < offset || end > src.Len() {
		return 0, false, nil
	}
	var raw [8]byte
	if err := source.ReadExactAt(src, offset, raw[:]); err != nil {
		return 0, false, err
	}
	return le64(raw[:], 0), true, nil
}

func verifyCRCs(raw []byte, zone uint32) error {
	crc0 := foundation.CRC32C(raw[0:508])
	if stored := le32(raw, ICRCSect0At); stored != crc0 {
		return corruptf("volume header #%d fails its sector-0 CRC: stored 0x%08x, computed 0x%08x",
			zone, stored, crc0)
	}
	crc1 := foundation.CRC32C(raw[512 : 512+512])
	if stored := le32(raw, ICRCSect1At); stored != crc1 {
		return corruptf("volume header #%d fails its sector-1 CRC: stored 0x%08x, computed 0x%08x",
			zone, stored, crc1)
	}
	crcvh := foundation.CRC32C(raw[0:65532])
	if stored := le32(raw, ICRCVolhdrAt); stored != crcvh {
		return corruptf("volume header #%d fails its volume-header CRC: stored 0x%08x, computed 0x%08x",
			zone, stored, crcvh)
	}
	return nil
}

func verifyVolumes(superblock *Superblock, zone uint32) error {
	switch superblock.Version {
	case 0:
		return corruptf("volume header #%d records version 0; the minimum is %d", zone, VersionMin)
	case VersionMin:
		if superblock.NVolumes != 0 {
			return corruptf("volume header #%d records version 1 but a volume count of %d; version 1 requires 0",
				zone, superblock.NVolumes)
		}
		if superblock.TotalSize != 0 {
			return corruptf("volume header #%d records version 1 but a total size of %d; version 1 requires 0",
				zone, superblock.TotalSize)
		}
		for index, offset := range superblock.VoluLoff {
			if offset != 0 {
				return corruptf("volume header #%d records version 1 but a non-zero logical offset for volume %d",
					zone, index)
			}
		}
	case VersionMultiVolumes:
		if superblock.NVolumes != 1 {
			return unsupportedf("multi-volume HAMMER2 set with %d volumes; this reader decodes a single volume",
				superblock.NVolumes)
		}
		if superblock.TotalSize != superblock.VoluSize {
			return corruptf("volume header #%d records total size 0x%x but volume size 0x%x; a single volume requires them to match",
				zone, superblock.TotalSize, superblock.VoluSize)
		}
		if superblock.VoluLoff[0] != 0 {
			return corruptf("volume header #%d records logical offset 0x%x for volume 0; the root volume must start at 0",
				zone, superblock.VoluLoff[0])
		}
		for index := 1; index < MaxVolumes; index++ {
			if superblock.VoluLoff[index] != ^uint64(0) {
				return corruptf("volume header #%d records a logical offset for unused volume %d; it must be u64::MAX",
					zone, index)
			}
		}
	default:
		return unsupportedf("volume format version %d; this reader decodes versions 1 and 2 (version %d is work in progress)",
			superblock.Version, VersionWIP)
	}
	if superblock.VoluSize == 0 {
		return corruptf("volume header #%d records a volume size of zero", zone)
	}
	if superblock.VoluSize&(VolumeAlign-1) != 0 {
		return corruptf("volume header #%d records volume size 0x%x, which is not %d byte aligned",
			zone, superblock.VoluSize, VolumeAlign)
	}
	return nil
}

// readAt parses the copy at offset, which is zone index zone.
func readAt(src source.ByteSource, zone uint32, offset uint64) (*Superblock, error) {
	end := offset + VolhdrBytes
	if end < offset {
		return nil, corruptf("volume header #%d at byte %d overflows the address space", zone, offset)
	}
	if end > src.Len() {
		return nil, source.NewUnexpectedEOF(offset)
	}
	raw := make([]byte, int(VolhdrBytes))
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return nil, err
	}

	magic := le64(raw, MagicAt)
	if magic == MagicReversed {
		return nil, unsupportedf("volume header #%d carries the reverse-endian (ABO) magic; this reader decodes little-endian (HBO) volumes only", zone)
	}
	if magic != Magic {
		return nil, corruptf("volume header #%d at byte %d has magic 0x%016x, not HAMMER2's 0x%016x",
			zone, offset, magic, Magic)
	}
	if err := verifyCRCs(raw, zone); err != nil {
		return nil, err
	}
	version := le32(raw, VersionAt)
	if version > MaxVersion {
		return nil, unsupportedf("volume format version %d; this reader decodes versions 1 and 2 (version %d is work in progress)",
			version, VersionWIP)
	}
	volumeID := raw[VolumeIDAt]
	if volumeID != 0 {
		return nil, unsupportedf("volume header #%d describes volume %d of a multi-volume set; this reader decodes volume 0 only",
			zone, volumeID)
	}

	superblock := &Superblock{
		Zone:           zone,
		VolumeOffset:   offset,
		BootBeg:        le64(raw, BootBegAt),
		BootEnd:        le64(raw, BootEndAt),
		AuxBeg:         le64(raw, AuxBegAt),
		AuxEnd:         le64(raw, AuxEndAt),
		VoluSize:       le64(raw, VoluSizeAt),
		Version:        version,
		Flags:          le32(raw, FlagsAt),
		CopyID:         raw[CopyIDAt],
		FreemapVersion: raw[FreemapVersionAt],
		PeerType:       raw[PeerTypeAt],
		VolumeID:       volumeID,
		NVolumes:       raw[NVolumesAt],
		AllocatorSize:  le64(raw, AllocatorSizeAt),
		AllocatorFree:  le64(raw, AllocatorFreeAt),
		AllocatorBeg:   le64(raw, AllocatorBegAt),
		MirrorTid:      le64(raw, MirrorTidAt),
		FreemapTid:     le64(raw, FreemapTidAt),
		BulkfreeTid:    le64(raw, BulkfreeTidAt),
		TotalSize:      le64(raw, TotalSizeAt),
		SourceBytes:    src.Len(),
	}
	copy(superblock.FSID[:], raw[FSIDAt:FSIDAt+16])
	copy(superblock.FSType[:], raw[FSTypeAt:FSTypeAt+16])
	for index := 0; index < MaxVolumes; index++ {
		superblock.VoluLoff[index] = le64(raw, VoluLoffAt+index*8)
	}
	sroot, err := ParseBlockset(raw[SrootBlocksetAt:SrootBlocksetAt+BlocksetBytes], "the super-root blockset")
	if err != nil {
		return nil, err
	}
	superblock.SrootBlockset = sroot
	freemap, err := ParseBlockset(raw[FreemapBlocksetAt:FreemapBlocksetAt+BlocksetBytes], "the freemap blockset")
	if err != nil {
		return nil, err
	}
	superblock.FreemapBlockset = freemap

	if !superblock.FSTypeCanonical() {
		return nil, corruptf("volume header #%d records fstype %s, not HAMMER2's %s",
			zone, superblock.FSTypeHex(), FSTypeUUID)
	}
	if err := verifyVolumes(superblock, zone); err != nil {
		return nil, err
	}
	return superblock, nil
}

// detect reports whether the source carries a HAMMER2 volume-header magic in
// any of the four zone copies.
func detect(src source.ByteSource) (bool, error) {
	for zone := 0; zone < NumVolhdr; zone++ {
		magic, present, err := magicAt(src, uint64(zone)*ZoneBytes)
		if err != nil {
			return false, err
		}
		if present && (magic == Magic || magic == MagicReversed) {
			return true, nil
		}
	}
	return false, nil
}

// ReadSuperblock reads every volume-header copy and returns the valid one
// with the highest mirror_tid, the way hammer2_read_volume_header does (the
// first copy wins a tie).
func ReadSuperblock(src source.ByteSource) (*Superblock, error) {
	var selected *Superblock
	var failures []string
	var refusal string
	hasRefusal := false
	reverseEndian := false
	var firstEOF error

	for zone := 0; zone < NumVolhdr; zone++ {
		offset := uint64(zone) * ZoneBytes
		magic, present, err := magicAt(src, offset)
		if err != nil {
			return nil, err
		}
		if !present {
			failures = append(failures, fmt.Sprintf("#%d: absent (source is %d bytes)", zone, src.Len()))
			continue
		}
		if magic == MagicReversed {
			reverseEndian = true
		} else if magic != Magic {
			failures = append(failures, fmt.Sprintf("#%d: magic 0x%016x", zone, magic))
			continue
		}
		candidate, err := readAt(src, uint32(zone), offset)
		if err == nil {
			if selected == nil || selected.MirrorTid < candidate.MirrorTid {
				selected = candidate
			}
			continue
		}
		if isUnsupported(err) {
			if !hasRefusal {
				refusal = err.Error()
				hasRefusal = true
			}
			continue
		}
		if errors.Is(err, source.ErrUnexpectedEOF) && firstEOF == nil {
			firstEOF = err
		}
		failures = append(failures, fmt.Sprintf("#%d: %v", zone, err))
	}

	if selected != nil {
		return selected, nil
	}
	if reverseEndian {
		return nil, unsupportedf("reverse-endian (ABO) HAMMER2 volume header; this reader decodes little-endian (HBO) volumes only")
	}
	if hasRefusal {
		return nil, fmt.Errorf("%w: %s", source.ErrUnsupported, refusal)
	}
	if firstEOF != nil {
		return nil, firstEOF
	}
	return nil, corruptf("no valid HAMMER2 volume header among the %d zone copies: %s",
		NumVolhdr, strings.Join(failures, "; "))
}
