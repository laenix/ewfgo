package cramfs

import (
	"encoding/binary"
	"hash/crc32"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The CramFS superblock and where in a source it starts.
//
//	 0  magic        u32   0x28cd3d45
//	 4  size         u32   image bytes
//	 8  flags        u32   feature bits
//	12  future       u32   reserved
//	16  signature   16    "Compressed ROMFS"
//	32  crc          u32   fsid checksum
//	36  edition      u32
//	40  blocks       u32   declared block count
//	44  files        u32   declared file count
//	48  name        16    a user-chosen volume name
//	64  root inode  12    a directory whose data starts the tree
//
// The image may also start at byte 512 behind a boot header. Every offset
// recorded inside the filesystem is an absolute source offset, so a shifted
// image needs no other adjustment.

const (
	magic            uint32 = 0x28cd_3d45
	magicWrongEndian uint32 = 0x453d_cd28
	superBytes              = 76
	shiftedBase      uint64 = 512
	crcOffset               = 32
	crcChunkBytes           = 1024 * 1024
)

// Superblock feature bits.
const (
	flagFSIDVersion2      uint32 = 0x0000_0001
	flagSortedDirs        uint32 = 0x0000_0002
	flagHoles             uint32 = 0x0000_0100
	flagWrongSignature    uint32 = 0x0000_0200
	flagShiftedRootOffset uint32 = 0x0000_0400
	flagExtBlockPointers  uint32 = 0x0000_0800
)

// supportedFlags is the kernel's mask: the reserved low bits plus the named
// features. Any other bit can change what an offset means, so it is refused.
const supportedFlags uint32 = 0x0000_00FF | flagHoles | flagWrongSignature |
	flagShiftedRootOffset | flagExtBlockPointers

const signature = "Compressed ROMFS"

type superblock struct {
	base        uint64
	size        uint32
	flags       uint32
	future      uint32
	signatureOK bool
	crc         uint32
	edition     uint32
	blocks      uint32
	files       uint32
	name        string
	root        inode
}

func (sb superblock) hasFlag(flag uint32) bool { return sb.flags&flag != 0 }

func (sb superblock) hasFSIDv2() bool { return sb.hasFlag(flagFSIDVersion2) }

// limit is the last byte any read may touch: the declared image end when
// version 2 records a usable one, else the source's own end.
func (sb superblock) limit(sourceLen uint64) uint64 {
	if sb.hasFSIDv2() && uint64(sb.size) >= sb.base+superBytes {
		if uint64(sb.size) < sourceLen {
			return uint64(sb.size)
		}
	}
	return sourceLen
}

// isEmpty reports a root inode with no listing, which a writer uses for an
// empty filesystem.
func (sb superblock) isEmpty() bool { return sb.root.dataOffset() == 0 }

func flagNames(flags uint32) []string {
	var names []string
	for _, pair := range []struct {
		flag uint32
		name string
	}{
		{flagFSIDVersion2, "fsid_version_2"},
		{flagSortedDirs, "sorted_dirs"},
		{flagHoles, "holes"},
		{flagWrongSignature, "wrong_signature"},
		{flagShiftedRootOffset, "shifted_root_offset"},
		{flagExtBlockPointers, "ext_block_pointers"},
	} {
		if flags&pair.flag != 0 {
			names = append(names, pair.name)
		}
	}
	return names
}

// detectBase reports where a superblock starts: byte zero or byte 512, the
// two places the kernel accepts. A big-endian image is refused by name.
func detectBase(src source.ByteSource) (uint64, bool, error) {
	for _, base := range []uint64{0, shiftedBase} {
		if src.Len() < base+4 {
			continue
		}
		var bytes [4]byte
		if err := source.ReadExactAt(src, base, bytes[:]); err != nil {
			return 0, false, err
		}
		word := binary.LittleEndian.Uint32(bytes[:])
		if word == magic {
			return base, true, nil
		}
		if word == magicWrongEndian {
			return 0, false, unsupportedf(
				"a big-endian image at byte %d; this reader decodes little-endian only", base)
		}
	}
	return 0, false, nil
}

func cString(bytes []byte) string {
	end := len(bytes)
	for i, b := range bytes {
		if b == 0 {
			end = i
			break
		}
	}
	return strings.ToValidUTF8(string(bytes[:end]), "�")
}

// readSuperblock reads the superblock and validates everything that names a
// layout.
func readSuperblock(src source.ByteSource) (superblock, error) {
	base, found, err := detectBase(src)
	if err != nil {
		return superblock{}, err
	}
	if !found {
		return superblock{}, corruptf("no CramFS magic at byte 0 or 512")
	}
	var bytes [superBytes]byte
	if err := source.ReadExactAt(src, base, bytes[:]); err != nil {
		return superblock{}, err
	}

	flags := binary.LittleEndian.Uint32(bytes[8:])
	if unknown := flags &^ supportedFlags; unknown != 0 {
		return superblock{}, unsupportedf(
			"feature flags %#010x at byte %d set unknown bits %#010x",
			flags, base, unknown)
	}

	signatureOK := string(bytes[16:32]) == signature
	root, err := parseInode(bytes[64:76])
	if err != nil {
		return superblock{}, err
	}
	if root.kind != inodeDirectory {
		return superblock{}, corruptf("the root inode is a %s, not a directory", root.kind.label())
	}

	rootOffset := root.dataOffset()
	if rootOffset != 0 && flags&flagShiftedRootOffset == 0 &&
		rootOffset != base+superBytes && rootOffset != shiftedBase+superBytes {
		return superblock{}, corruptf(
			"the root listing is at %d, not after the superblock at %d",
			rootOffset, base+superBytes)
	}
	if rootOffset == 0 && root.size != 0 {
		return superblock{}, corruptf(
			"the root has no listing offset but declares %d bytes", root.size)
	}

	size := binary.LittleEndian.Uint32(bytes[4:])
	if flags&flagFSIDVersion2 != 0 {
		if uint64(size) < base+superBytes || uint64(size) > src.Len() {
			return superblock{}, corruptf(
				"the image declares %d bytes but the source holds %d", size, src.Len())
		}
	}

	return superblock{
		base:        base,
		size:        size,
		flags:       flags,
		future:      binary.LittleEndian.Uint32(bytes[12:]),
		signatureOK: signatureOK,
		crc:         binary.LittleEndian.Uint32(bytes[32:]),
		edition:     binary.LittleEndian.Uint32(bytes[36:]),
		blocks:      binary.LittleEndian.Uint32(bytes[40:]),
		files:       binary.LittleEndian.Uint32(bytes[44:]),
		name:        cString(bytes[48:64]),
		root:        root,
	}, nil
}

// CRCState is how far a comparison of the fsid checksum got.
type CRCState uint8

const (
	// CRCVerified means the stored checksum equals a fresh CRC-32.
	CRCVerified CRCState = iota
	// CRCMismatch means the stored checksum differs from a fresh one.
	CRCMismatch
	// CRCNotRecorded means the superblock stores zero. A writer that records a
	// checksum cannot normally produce zero, so the field is reported as not
	// recorded rather than as a mismatch.
	CRCNotRecorded
	// CRCNotVersion2 means FSID version 1: the field is not a checksum.
	CRCNotVersion2
	// CRCShifted means the image starts at byte 512, where the checksummed
	// byte range is not established.
	CRCShifted
)

func (s CRCState) String() string {
	switch s {
	case CRCVerified:
		return "verified"
	case CRCMismatch:
		return "mismatch"
	case CRCNotRecorded:
		return "not recorded"
	case CRCNotVersion2:
		return "not a checksum (fsid version 1)"
	default:
		return "unverified (shifted image)"
	}
}

// CRCVerification is the result of Volume.VerifyCRC.
type CRCVerification struct {
	State       CRCState
	Stored      uint32
	Computed    uint32
	HasComputed bool
}

// verifyCRC compares the recorded fsid checksum with a fresh CRC-32 over the
// image. A CramFS writer computes the checksum over the declared bytes with
// the four checksum bytes themselves zeroed.
func (sb superblock) verifyCRC(src source.ByteSource) (CRCVerification, error) {
	stored := sb.crc
	state := CRCVerified
	switch {
	case !sb.hasFSIDv2():
		state = CRCNotVersion2
	case sb.base != 0:
		state = CRCShifted
	case stored == 0:
		state = CRCNotRecorded
	}
	if state == CRCNotVersion2 || state == CRCShifted {
		return CRCVerification{State: state, Stored: stored}, nil
	}

	computed, err := sb.computeCRC(src)
	if err != nil {
		return CRCVerification{}, err
	}
	if state != CRCNotRecorded {
		if computed == stored {
			state = CRCVerified
		} else {
			state = CRCMismatch
		}
	}
	return CRCVerification{
		State:       state,
		Stored:      stored,
		Computed:    computed,
		HasComputed: true,
	}, nil
}

// computeCRC is CRC-32 over [base, base+size), with the checksum field zeroed.
func (sb superblock) computeCRC(src source.ByteSource) (uint32, error) {
	total := uint64(sb.size)
	if total < sb.base+superBytes {
		return 0, corruptf("the image declares %d bytes, shorter than its superblock", total)
	}
	fieldStart := sb.base + crcOffset
	fieldEnd := fieldStart + 4
	var crc uint32
	buffer := make([]byte, 0, crcChunkBytes)
	for at := uint64(0); at < total; {
		want := total - at
		if want > crcChunkBytes {
			want = crcChunkBytes
		}
		if cap(buffer) < int(want) {
			buffer = make([]byte, want)
		} else {
			buffer = buffer[:want]
		}
		if err := source.ReadExactAt(src, at, buffer); err != nil {
			return 0, err
		}
		zeroFrom := fieldStart
		if at > zeroFrom {
			zeroFrom = at
		}
		zeroTo := fieldEnd
		if at+want < zeroTo {
			zeroTo = at + want
		}
		if zeroFrom < zeroTo {
			for i := zeroFrom - at; i < zeroTo-at; i++ {
				buffer[i] = 0
			}
		}
		crc = crc32.Update(crc, crc32.IEEETable, buffer)
		at += want
	}
	return crc, nil
}
