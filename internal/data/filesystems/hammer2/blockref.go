package hammer2

import (
	"crypto/sha256"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// BlockrefBytes is the size of one block reference.
const BlockrefBytes = 128

// SetCount is the number of references in one blockset.
const SetCount = 4

// BlocksetBytes is the size of one blockset.
const BlocksetBytes = BlockrefBytes * SetCount

// OffMask removes the radix bits from data_off.
const OffMask uint64 = 0xFFFF_FFFF_FFFF_FFC0

// OffMaskRadix masks the radix stored in data_off's low bits.
const OffMaskRadix uint64 = 0x0000_0000_0000_003F

// XXHHammer2Seed is XXH_HAMMER2_SEED.
const XXHHammer2Seed uint64 = 0x4d61_7474_446c_6c6e

// DirhashVisible marks a visible directory entry in a key.
const DirhashVisible uint64 = 0x8000_0000_0000_0000

// Block reference types.
const (
	BrefTypeEmpty       uint8 = 0
	BrefTypeInode       uint8 = 1
	BrefTypeIndirect    uint8 = 2
	BrefTypeData        uint8 = 3
	BrefTypeDirent      uint8 = 4
	BrefTypeFreemapNode uint8 = 5
	BrefTypeFreemapLeaf uint8 = 6
	BrefTypeInvalid     uint8 = 7
	BrefTypeFreemap     uint8 = 254
	BrefTypeVolume      uint8 = 255
)

// BrefFlagPFSRoot is HAMMER2_BREF_FLAG_PFSROOT.
const BrefFlagPFSRoot uint8 = 0x01

// Check algorithms.
const (
	CheckNone     uint8 = 0
	CheckDisabled uint8 = 1
	CheckISCSI32  uint8 = 2
	CheckXXHash64 uint8 = 3
	CheckSHA192   uint8 = 4
	CheckFreemap  uint8 = 5
)

// Compression algorithms.
const (
	CompNone     uint8 = 0
	CompAutoZero uint8 = 1
	CompLZ4      uint8 = 2
	CompZlib     uint8 = 3
)

// TypeLabel is the type name DragonFly's hammer2_bref_type_str reports.
func TypeLabel(btype uint8) string {
	switch btype {
	case BrefTypeEmpty:
		return "empty"
	case BrefTypeInode:
		return "inode"
	case BrefTypeIndirect:
		return "indirect"
	case BrefTypeData:
		return "data"
	case BrefTypeDirent:
		return "dirent"
	case BrefTypeFreemapNode:
		return "freemap node"
	case BrefTypeFreemapLeaf:
		return "freemap leaf"
	case BrefTypeInvalid:
		return "invalid"
	case BrefTypeFreemap:
		return "freemap"
	case BrefTypeVolume:
		return "volume"
	default:
		return "unknown"
	}
}

// CompressionLabel names a compression algorithm.
func CompressionLabel(comp uint8) string {
	switch comp {
	case CompNone:
		return "none"
	case CompAutoZero:
		return "autozero"
	case CompLZ4:
		return "LZ4"
	case CompZlib:
		return "zlib"
	default:
		return "unknown"
	}
}

// Blockref is one parsed 128-byte block reference.
type Blockref struct {
	BType     uint8
	Methods   uint8
	CopyID    uint8
	KeyBits   uint8
	VRadix    uint8
	Flags     uint8
	LeafCount uint16
	Key       uint64
	MirrorTid uint64
	ModifyTid uint64
	DataOff   uint64
	UpdateTid uint64
	Embed     [16]byte
	Check     [64]byte
}

// ParseBlockref parses one 128-byte reference.
func ParseBlockref(raw []byte, what string) (*Blockref, error) {
	if len(raw) < BlockrefBytes {
		return nil, corruptf("%s is %d bytes, shorter than the %d-byte block reference",
			what, len(raw), BlockrefBytes)
	}
	ref := &Blockref{
		BType:     raw[0x00],
		Methods:   raw[0x01],
		CopyID:    raw[0x02],
		KeyBits:   raw[0x03],
		VRadix:    raw[0x04],
		Flags:     raw[0x05],
		LeafCount: le16(raw, 0x06),
		Key:       le64(raw, 0x08),
		MirrorTid: le64(raw, 0x10),
		ModifyTid: le64(raw, 0x18),
		DataOff:   le64(raw, 0x20),
		UpdateTid: le64(raw, 0x28),
	}
	copy(ref.Embed[:], raw[0x30:0x40])
	copy(ref.Check[:], raw[0x40:0x80])
	return ref, nil
}

// CheckAlgo is the check algorithm encoded in methods.
func (r *Blockref) CheckAlgo() uint8 { return (r.Methods >> 4) & 0x0f }

// CompAlgo is the compression algorithm encoded in methods.
func (r *Blockref) CompAlgo() uint8 { return r.Methods & 0x0f }

// Visible reports whether bit 63 of the key marks a visible directory entry.
func (r *Blockref) Visible() bool { return r.Key&DirhashVisible != 0 }

// PFSRoot reports whether the reference carries the PFS-root flag.
func (r *Blockref) PFSRoot() bool { return r.Flags&BrefFlagPFSRoot != 0 }

// Radix is the physical radix stored in data_off's low bits.
func (r *Blockref) Radix() uint8 { return uint8(r.DataOff & OffMaskRadix) }

// PhysicalOffset is the physical byte offset with the radix bits removed.
func (r *Blockref) PhysicalOffset() uint64 { return r.DataOff & OffMask }

// PhysicalBytes reports the bytes the reference covers, or false for radix
// zero (embedded).
func (r *Blockref) PhysicalBytes() (uint64, bool) {
	radix := r.Radix()
	if radix == 0 || radix > 30 {
		return 0, false
	}
	return uint64(1) << radix, true
}

// ExternalBytes returns the bytes the reference covers; radix zero is an
// error for items that must have external data.
func (r *Blockref) ExternalBytes(what string) (uint64, error) {
	radix := r.Radix()
	if radix == 0 {
		return 0, corruptf("%s has no external data (data_off radix is zero)", what)
	}
	if radix > 30 {
		return 0, corruptf("%s names an impossible physical radix %d", what, radix)
	}
	return uint64(1) << radix, nil
}

// ValidateMethods refuses compression and an unknown check algorithm by name.
func (r *Blockref) ValidateMethods(what string) error {
	return ValidateMethods(r.Methods, what)
}

// VerifyCheck verifies the stored check code over exactly the bytes the
// reference covers. The caller must pass 1 << radix bytes.
func (r *Blockref) VerifyCheck(bytes []byte, what string) error {
	expected, err := r.ExternalBytes(what)
	if err != nil {
		return err
	}
	if uint64(len(bytes)) != expected {
		return corruptf("%s: %d bytes were read but the block reference covers %d",
			what, len(bytes), expected)
	}
	return verifyCheckCode(r.CheckAlgo(), r.Check[:], bytes, what)
}

// ReadBytes reads and verifies the item this reference names.
func (r *Blockref) ReadBytes(src source.ByteSource, what string) ([]byte, error) {
	if err := r.ValidateMethods(what); err != nil {
		return nil, err
	}
	radix := r.Radix()
	if radix == 0 {
		return nil, corruptf("%s has no external data (data_off radix is zero)", what)
	}
	if radix > 16 {
		return nil, corruptf("%s names physical radix %d, larger than HAMMER2's 64 KiB item limit",
			what, radix)
	}
	length := uint64(1) << radix
	offset := r.PhysicalOffset()
	if offset == 0 {
		return nil, corruptf("%s names physical offset 0, which holds the volume header", what)
	}
	end := offset + length
	if end < offset {
		return nil, corruptf("%s: physical offset 0x%x overflows", what, offset)
	}
	if end > src.Len() {
		return nil, corruptf("%s names bytes 0x%x..0x%x, past the %d bytes the source holds",
			what, offset, end, src.Len())
	}
	buffer := make([]byte, int(length))
	if err := source.ReadExactAt(src, offset, buffer); err != nil {
		return nil, err
	}
	if err := r.VerifyCheck(buffer, what); err != nil {
		return nil, err
	}
	return buffer, nil
}

// ValidateMethods refuses compression and an unknown check algorithm by name.
func ValidateMethods(methods uint8, what string) error {
	if comp := methods & 0x0f; comp != CompNone {
		return unsupportedf("%s is stored with %s compression (methods 0x%02x); this reader decodes uncompressed blocks only",
			what, CompressionLabel(comp), methods)
	}
	switch check := (methods >> 4) & 0x0f; check {
	case CheckNone, CheckDisabled, CheckISCSI32, CheckXXHash64, CheckSHA192:
		return nil
	case CheckFreemap:
		return unsupportedf("%s uses the freemap check algorithm; this reader does not decode freemap blocks", what)
	default:
		return unsupportedf("%s uses unknown check algorithm %d (methods 0x%02x)", what, check, methods)
	}
}

// verifyCheckCode verifies a stored 64-byte check code over an item's bytes.
func verifyCheckCode(checkAlgo uint8, check, bytes []byte, what string) error {
	switch checkAlgo {
	case CheckNone, CheckDisabled:
		return nil
	case CheckISCSI32:
		if len(check) < 4 {
			return corruptf("%s has a truncated iSCSI CRC-32C check", what)
		}
		stored := le32(check, 0)
		computed := foundation.CRC32C(bytes)
		if stored != computed {
			return corruptf("%s fails its iSCSI CRC-32C check: stored 0x%08x, computed 0x%08x",
				what, stored, computed)
		}
		return nil
	case CheckXXHash64:
		if len(check) < 8 {
			return corruptf("%s has a truncated XXH64 check", what)
		}
		stored := le64(check, 0)
		computed := xxh64(bytes, XXHHammer2Seed)
		if stored != computed {
			return corruptf("%s fails its XXH64 check: stored 0x%016x, computed 0x%016x",
				what, stored, computed)
		}
		return nil
	case CheckSHA192:
		if len(check) < 24 {
			return corruptf("%s has a truncated SHA-192 check", what)
		}
		digest := sha256.Sum256(bytes)
		for index := 0; index < 8; index++ {
			digest[16+index] ^= digest[24+index]
		}
		for index := 0; index < 24; index++ {
			if check[index] != digest[index] {
				return corruptf("%s fails its SHA-192 check", what)
			}
		}
		return nil
	case CheckFreemap:
		return unsupportedf("%s uses the freemap check algorithm; this reader does not decode freemap blocks", what)
	default:
		return unsupportedf("%s uses unknown check algorithm %d", what, checkAlgo)
	}
}

// Blockset is four fully associative block references.
type Blockset struct {
	refs [SetCount]Blockref
}

// ParseBlockset parses a 512-byte blockset.
func ParseBlockset(raw []byte, what string) (*Blockset, error) {
	if len(raw) < BlocksetBytes {
		return nil, corruptf("%s is %d bytes, shorter than the %d-byte blockset",
			what, len(raw), BlocksetBytes)
	}
	set := &Blockset{}
	for index := 0; index < SetCount; index++ {
		ref, err := ParseBlockref(raw[index*BlockrefBytes:(index+1)*BlockrefBytes], what)
		if err != nil {
			return nil, err
		}
		set.refs[index] = *ref
	}
	// An all-zero slot is the empty sentinel. A slot whose type is EMPTY
	// must not name data or a key.
	for index := range set.refs {
		if set.refs[index].BType == BrefTypeEmpty {
			set.refs[index].Methods = 0
			set.refs[index].Key = 0
			set.refs[index].DataOff = 0
		}
	}
	return set, nil
}

// Refs returns the four slots in on-disk order.
func (s *Blockset) Refs() []Blockref { return s.refs[:] }
