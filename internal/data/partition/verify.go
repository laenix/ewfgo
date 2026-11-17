package partition

import (
	"bytes"
	"fmt"
	"math"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// This file is the Go port of forensic-core's data/partition/verify.rs: after
// the scan finds a magic at a sector boundary, the candidate is re-examined
// against the format's own structure.  A signature proves the magic is where
// the format keeps it; it does not prove the bytes behind it are a volume.
//
// Checksums that can be computed from the candidate's head with the primitives
// in internal/data/foundation are verified exactly.  A format whose header
// parser is not ported yet is reported as Unverified with the reason that says
// so; it is never silently rejected and no field is invented.

// VerifyCandidate re-examines the candidate whose first byte is at offset.
//
// head holds the bytes already read for the signature check (up to 68 KiB, or
// what the image holds); available is the number of bytes from offset to the
// end of the source.  The signature and label are passed through so the verdict
// can name the format instead of saying "some volume".
func VerifyCandidate(
	src source.ByteSource,
	offset uint64,
	id string,
	label string,
	head []byte,
	available uint64,
) Verification {
	_ = src // reserved for checks that read past the head, as the Rust window does
	_ = offset
	switch id {
	case "btrfs-volume":
		return verifyBtrfs(head, available)
	case "ext-volume":
		return verifyExt(head, available)
	case "xfs-volume":
		return verifyXFS(head, available)
	case "jffs2-volume":
		return verifyJFFS2(head, available)
	case "lvm-volume":
		return verifyLVM(head)
	case "corestorage-volume":
		return verifyCoreStorage(head)
	default:
		return verifyUnported(id, label)
	}
}

// verifyBtrfs checks the primary superblock at 64 KiB: its checksum and its
// own recorded address.
func verifyBtrfs(head []byte, available uint64) Verification {
	const at = 64 * 1024
	const length = 4096
	if len(head) < at+length {
		return rejected(fmt.Sprintf("the image ends before the Btrfs superblock at byte %d", at))
	}
	sb := head[at : at+length]
	if !bytes.Equal(sb[64:72], []byte("_BHRfS_M")) {
		return rejected("the superblock magic is missing")
	}
	bytenr, ok := u64leAt(sb, 48)
	if !ok || bytenr != at {
		return rejected(fmt.Sprintf("the superblock at %d says it lives at %d", at, bytenr))
	}

	csumType, _ := u16leAt(sb, 196)
	switch {
	case csumType == 0:
		stored, _ := u32leAt(sb, 0)
		computed := foundation.CRC32C(sb[32:])
		if stored != computed {
			return rejected(fmt.Sprintf(
				"the superblock's crc32c checksum is 0x%08x, computed 0x%08x", stored, computed))
		}
	case csumType <= 3:
		// xxhash64, SHA-256 and BLAKE2b are declared by the format but this
		// reader has no primitive for them.  The structure can still be
		// checked; the checksum stays explicitly unverified.
		verdict, _ := btrfsGeometry(head, sb, available, false, csumType)
		return verdict
	default:
		return rejected(fmt.Sprintf("unknown checksum type %d", csumType))
	}

	if verdict, ok := btrfsGeometry(head, sb, available, true, csumType); !ok {
		return verdict
	}
	return verified(fmt.Sprintf(
		"the crc32c checksum and the superblock's own address (bytenr %d) match", bytenr))
}

// btrfsGeometry validates the superblock fields the Rust parser checks.  The
// bool result is false when the returned verdict is final.
func btrfsGeometry(head, sb []byte, available uint64, checksumVerified bool, csumType uint16) (Verification, bool) {
	_ = head
	sectorSize, okSector := u32leAt(sb, 144)
	nodeSize, okNode := u32leAt(sb, 148)
	if !okSector || sectorSize < 512 || sectorSize > 65536 || !scanPow2U32(sectorSize) {
		return rejected(fmt.Sprintf("the sector size %d is not a power of two in range", sectorSize)), false
	}
	if !okNode || nodeSize < 4096 || nodeSize > 65536 || !scanPow2U32(nodeSize) {
		return rejected(fmt.Sprintf("the node size %d is not a power of two in 4096..=65536", nodeSize)), false
	}
	if sectorSize > nodeSize {
		return rejected("the sector size exceeds the node size"), false
	}
	stripeSize, okStripe := u32leAt(sb, 156)
	if !okStripe || stripeSize == 0 {
		return rejected("the stripe size is zero"), false
	}
	totalBytes, okTotal := u64leAt(sb, 112)
	if !okTotal || totalBytes == 0 {
		return rejected("the volume declares zero bytes"), false
	}
	root, okRoot := u64leAt(sb, 80)
	if !okRoot || root == 0 || root >= totalBytes {
		return rejected(fmt.Sprintf("the tree of trees root %d is outside the volume", root)), false
	}
	chunkRoot, okChunk := u64leAt(sb, 88)
	if !okChunk || chunkRoot == 0 || chunkRoot >= totalBytes {
		return rejected(fmt.Sprintf("the chunk tree root %d is outside the volume", chunkRoot)), false
	}
	sysSize, okSys := u32leAt(sb, 160)
	if !okSys || sysSize > 2048 {
		return rejected(fmt.Sprintf("the system chunk array claims %d bytes of 2048", sysSize)), false
	}
	if totalBytes > available {
		return rejected(fmt.Sprintf(
			"the superblock declares %d bytes but only %d are present from this offset", totalBytes, available)), false
	}
	if !checksumVerified {
		return unverified(fmt.Sprintf(
			"the Btrfs geometry fits, but the superblock uses %s (type %d), which this reader cannot verify",
			btrfsChecksumName(csumType), csumType)), false
	}
	return Verification{}, true
}

func btrfsChecksumName(csumType uint16) string {
	switch csumType {
	case 0:
		return "crc32c"
	case 1:
		return "xxhash64"
	case 2:
		return "sha256"
	case 3:
		return "blake2b"
	default:
		return "unknown"
	}
}

// verifyExt checks the ext2/3/4 superblock and its metadata_csum CRC-32C.
func verifyExt(head []byte, available uint64) Verification {
	const at = 1024
	const length = 1024
	if len(head) < at+length {
		return rejected("the superblock could not be read: the head ends before byte 2048")
	}
	sb := head[at : at+length]
	magic, ok := u16leAt(sb, 0x38)
	if !ok || magic != 0xEF53 {
		return rejected(fmt.Sprintf("superblock magic is 0x%04x, expected 0xef53", magic))
	}
	logBlock, _ := u32leAt(sb, 0x18)
	if logBlock > 6 {
		return rejected("block size exponent is out of range")
	}
	blockSize := uint64(1024) << logBlock

	revLevel, _ := u32leAt(sb, 0x4c)
	inodeSize, _ := u16leAt(sb, 0x58)
	if inodeSize == 0 {
		if revLevel != 0 {
			return rejected("dynamic-revision superblock has no inode size")
		}
		inodeSize = 128
	}
	if inodeSize < 128 || uint64(inodeSize) > blockSize || inodeSize%4 != 0 {
		return rejected(fmt.Sprintf("implausible inode size %d", inodeSize))
	}

	featureIncompat, _ := u32leAt(sb, 0x60)
	is64Bit := featureIncompat&0x0080 != 0
	declaredDesc, _ := u16leAt(sb, 0xFE)
	descSize := uint32(32)
	if declaredDesc >= 32 {
		descSize = uint32(declaredDesc)
	} else if is64Bit {
		descSize = 64
	}
	if is64Bit && descSize < 64 {
		return rejected(fmt.Sprintf("64-bit volume declares a %d-byte group descriptor", descSize))
	}
	if uint64(descSize) > blockSize {
		return rejected(fmt.Sprintf("group descriptor size %d exceeds the block size", descSize))
	}

	blocksPerGroup, _ := u32leAt(sb, 0x20)
	inodesPerGroup, _ := u32leAt(sb, 0x28)
	if blocksPerGroup == 0 || inodesPerGroup == 0 {
		return rejected("volume declares zero-sized block groups")
	}
	if uint64(blocksPerGroup) > 8*blockSize {
		return rejected(fmt.Sprintf("blocks per group %d exceeds the bitmap capacity", blocksPerGroup))
	}

	blocksLo, _ := u32leAt(sb, 0x04)
	blocksCount := uint64(blocksLo)
	if is64Bit {
		blocksHi, _ := u32leAt(sb, 0x150)
		blocksCount |= uint64(blocksHi) << 32
	}
	firstDataBlock, _ := u32leAt(sb, 0x14)
	if blocksCount <= uint64(firstDataBlock) {
		return rejected("volume declares no data blocks")
	}

	roCompat, _ := u32leAt(sb, 0x64)
	checksumVerified := false
	if roCompat&0x0400 != 0 {
		checksumType := sb[0x175]
		if checksumType != 1 {
			return unverified(fmt.Sprintf(
				"refused by name: metadata checksum type %d; only crc32c is defined", checksumType))
		}
		stored, _ := u32leAt(sb, 0x3FC)
		computed := foundation.CRC32CSeeded(0xFFFFFFFF, sb[:0x3FC])
		if stored != computed {
			return rejected(fmt.Sprintf(
				"the superblock fails its crc32c checksum (0x%08x stored, 0x%08x computed)", stored, computed))
		}
		checksumVerified = true
	}

	declared, okMul := scanMul(blocksCount, blockSize)
	if !okMul {
		declared = math.MaxUint64
	}
	if declared == 0 || declared > available {
		return rejected(fmt.Sprintf(
			"the superblock declares %d bytes but only %d are present from this offset", declared, available))
	}
	if checksumVerified {
		return verified("the metadata_csum CRC-32C over the superblock matches")
	}
	return unverified("the superblock geometry fits, but metadata_csum is off so nothing seals it")
}

// verifyXFS checks the big-endian superblock and, for version 5, its CRC-32C.
func verifyXFS(head []byte, available uint64) Verification {
	const length = 512
	if len(head) < length {
		return rejected("the superblock is truncated")
	}
	sb := head[:length]
	if !bytes.Equal(sb[0:4], []byte("XFSB")) {
		return rejected("the superblock magic is not XFSB")
	}
	versionNumber, _ := u16beAt(sb, 0x64)
	version := versionNumber & 0x000F
	if version != 4 && version != 5 {
		return unverified(fmt.Sprintf(
			"refused by name: superblock version %d (this reader knows versions 4 and 5)", version))
	}

	blockSize, _ := u32beAt(sb, 0x04)
	if !xfsPowerOfTwo(uint64(blockSize), 512, 65536) {
		return rejected(fmt.Sprintf("block size %d is not a power of two in 512..=65536", blockSize))
	}
	blockLog := sb[0x78]
	if uint64(1)<<blockLog != uint64(blockSize) {
		return rejected(fmt.Sprintf("block size %d disagrees with sb_blocklog %d", blockSize, blockLog))
	}
	sectorSize, _ := u16beAt(sb, 0x66)
	if !xfsPowerOfTwo(uint64(sectorSize), 512, 32768) {
		return rejected(fmt.Sprintf("sector size %d is not a power of two in 512..=32768", sectorSize))
	}
	sectorLog := sb[0x79]
	if uint64(1)<<sectorLog != uint64(sectorSize) {
		return rejected(fmt.Sprintf("sector size %d disagrees with sb_sectlog %d", sectorSize, sectorLog))
	}
	if blockSize < uint32(sectorSize) {
		return rejected(fmt.Sprintf("block size %d is smaller than sector size %d", blockSize, sectorSize))
	}
	inodeSize, _ := u16beAt(sb, 0x68)
	if !xfsPowerOfTwo(uint64(inodeSize), 256, 2048) {
		return rejected(fmt.Sprintf("inode size %d is not a power of two in 256..=2048", inodeSize))
	}
	inodeLog := sb[0x7A]
	if uint64(1)<<inodeLog != uint64(inodeSize) {
		return rejected(fmt.Sprintf("inode size %d disagrees with sb_inodelog %d", inodeSize, inodeLog))
	}
	inodesPerBlock, _ := u16beAt(sb, 0x6A)
	if uint32(inodesPerBlock)*uint32(inodeSize) != blockSize {
		return rejected(fmt.Sprintf(
			"%d inodes of %d bytes do not fill a %d-byte block", inodesPerBlock, inodeSize, blockSize))
	}
	inodesPerBlockLog := sb[0x7B]
	if uint32(1)<<inodesPerBlockLog != uint32(inodesPerBlock) {
		return rejected(fmt.Sprintf(
			"%d inodes per block disagrees with sb_inopblog %d", inodesPerBlock, inodesPerBlockLog))
	}
	agCount, _ := u32beAt(sb, 0x58)
	if agCount == 0 || agCount > 1_000_000 {
		return rejected(fmt.Sprintf("%d allocation groups is outside 1..=1000000", agCount))
	}
	agBlocks, _ := u32beAt(sb, 0x54)
	if agBlocks == 0 || agBlocks > math.MaxInt32 {
		return rejected(fmt.Sprintf("%d blocks per allocation group is outside 1..=%d", agBlocks, math.MaxInt32))
	}
	agBlockLog := sb[0x7C]
	if agBlockLog > 31 {
		return rejected(fmt.Sprintf("sb_agblklog %d exceeds 31", agBlockLog))
	}
	if uint64(1)<<agBlockLog < uint64(agBlocks) {
		return rejected(fmt.Sprintf("sb_agblklog %d cannot address %d blocks", agBlockLog, agBlocks))
	}
	inodeShift := uint32(agBlockLog) + uint32(inodesPerBlockLog)
	if inodeShift+1 > 63 {
		return rejected(fmt.Sprintf("inode numbers would need %d bits to address", inodeShift+1))
	}

	dataBlocks, _ := u64beAt(sb, 0x08)
	covered, okCovered := scanMul(uint64(agCount), uint64(agBlocks))
	if !okCovered {
		return rejected("the allocation group count overflows the volume size")
	}
	if dataBlocks == 0 || dataBlocks > covered {
		return rejected(fmt.Sprintf(
			"sb_dblocks %d exceeds %d groups of %d blocks", dataBlocks, agCount, agBlocks))
	}
	minimumBase, okMin := scanMul(uint64(agCount-1), uint64(agBlocks))
	minimum, okMinAdd := scanAdd(minimumBase, 1)
	if !okMin || !okMinAdd {
		return rejected("the allocation group count overflows the volume size")
	}
	if dataBlocks < minimum {
		return rejected(fmt.Sprintf(
			"sb_dblocks %d cannot fill %d allocation groups", dataBlocks, agCount))
	}
	if sb[0x7E] != 0 {
		return rejected("the volume was never finished by mkfs (sb_inprogress is set)")
	}

	featuresIncompat, _ := u32beAt(sb, 0xD8)
	if version == 5 {
		if featuresIncompat&0x0010 != 0 {
			return unverified("refused by name: the filesystem is marked as needing repair (sb_features_incompat)")
		}
		if featuresIncompat&0x0020 != 0 {
			return unverified("refused by name: 64-bit extent counters (nrext64) move di_nextents out of the core the reader parses")
		}
		const supported = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0040
		unknown := featuresIncompat &^ (supported | 0x0010 | 0x0020)
		if unknown != 0 {
			return unverified(fmt.Sprintf("refused by name: sb_features_incompat 0x%08X", unknown))
		}
	}

	rootInode, _ := u64beAt(sb, 0x38)
	if rootInode == 0 {
		return rejected("the superblock names no root inode")
	}
	// check_source: the declared size must fit the candidate and the root
	// inode address must name a real slot.
	declared, okDeclared := scanMul(dataBlocks, uint64(blockSize))
	if !okDeclared {
		declared = math.MaxUint64
	}
	if declared > available {
		return rejected(fmt.Sprintf(
			"the volume declares %d bytes but the source holds %d", declared, available))
	}
	if inodeShift < 64 {
		agno := rootInode >> inodeShift
		if agno >= uint64(agCount) {
			return rejected(fmt.Sprintf(
				"inode %d names allocation group %d, but the volume has %d", rootInode, agno, agCount))
		}
		agino := rootInode & ((uint64(1) << inodeShift) - 1)
		agbno := agino >> inodesPerBlockLog
		agBlocksIn := uint64(agBlocks)
		if agno+1 == uint64(agCount) {
			usedBase, _ := scanMul(uint64(agCount-1), uint64(agBlocks))
			agBlocksIn = dataBlocks - usedBase
		}
		if agbno >= agBlocksIn {
			return rejected(fmt.Sprintf(
				"inode %d sits in block %d, past allocation group %d", rootInode, agbno, agno))
		}
	}

	if version == 5 {
		sectorLen := int(sectorSize)
		if sectorLen < length {
			sectorLen = length
		}
		if len(head) < sectorLen {
			return rejected("the superblock sector is truncated")
		}
		const crcAt = 0x0E0
		stored, _ := u32leAt(head, crcAt)
		sealed := append([]byte(nil), head[:sectorLen]...)
		clear(sealed[crcAt : crcAt+4])
		computed := foundation.CRC32C(sealed)
		if stored != computed {
			return rejected(fmt.Sprintf(
				"the superblock fails its crc32c checksum (0x%08x stored, 0x%08x computed)", stored, computed))
		}
		return verified("the version-5 superblock CRC-32C matches and its geometry fits the candidate")
	}
	return unverified("the version-4 superblock geometry fits, but version 4 carries no CRC")
}

func xfsPowerOfTwo(value, low, high uint64) bool {
	return value >= low && value <= high && scanPow2U64(value)
}

// verifyJFFS2 checks the first eraseblock node's header CRC-32 and length.
func verifyJFFS2(head []byte, available uint64) Verification {
	const headerBytes = 12
	if len(head) < headerBytes {
		return rejected("the JFFS2 node header could not be read: the head is shorter than 12 bytes")
	}
	magic, _ := u16leAt(head, 0)
	if magic != 0x1985 {
		return rejected("the bytes at this offset are not a JFFS2 node")
	}
	totlen, _ := u32leAt(head, 4)
	stored, _ := u32leAt(head, 8)
	computed := foundation.CRC32(head[0:8])
	if stored != computed {
		return rejected(fmt.Sprintf(
			"the header at the node's start fails its CRC (0x%08x stored, 0x%08x computed)", stored, computed))
	}
	if totlen < headerBytes {
		return rejected(fmt.Sprintf("a node declares %d bytes, shorter than its own header", totlen))
	}
	if totlen%4 != 0 {
		return rejected(fmt.Sprintf("a node declares %d bytes, not on the four-byte boundary", totlen))
	}
	if totlen > 16*1024*1024 {
		return rejected(fmt.Sprintf("a node declares %d bytes, more than the reader accepts", totlen))
	}
	if uint64(totlen) > available {
		return rejected(fmt.Sprintf(
			"the first node declares %d bytes but only %d are present from this offset", totlen, available))
	}
	return verified("the first JFFS2 node's header CRC-32 matches and its declared length fits the candidate")
}

// verifyLVM checks the LABELONE sector's CRC-32.
//
// verify.rs has no branch for LVM; the label reader in the Rust tree does
// verify this checksum, so the port checks it here rather than reporting an
// unverified candidate whose label is demonstrably damaged.
func verifyLVM(head []byte) Verification {
	const at = 512
	const labelBytes = 512
	if len(head) < at+labelBytes {
		return unverified("the LVM2 label sector is truncated; only the signature was confirmed")
	}
	label := head[at : at+labelBytes]
	if !bytes.Equal(label[0:8], []byte("LABELONE")) {
		return rejected("byte 512 does not hold a LABELONE sector")
	}
	if !bytes.Equal(label[24:32], []byte("LVM2 001")) {
		return rejected("the LABELONE sector's label type is not `LVM2 001`")
	}
	headerOffset, _ := u32leAt(label, 20)
	if headerOffset < 32 || uint64(headerOffset)+32 > labelBytes {
		return rejected("the pv_header offset is outside the label sector")
	}
	pvUUID := label[headerOffset : headerOffset+32]
	for _, b := range pvUUID {
		if b < 0x21 || b > 0x7E {
			return rejected("the pv_uuid is not 32 printable bytes")
		}
	}
	stored, _ := u32leAt(label, 16)
	crcInput := append([]byte(nil), label...)
	clear(crcInput[16:20])
	computed := foundation.CRC32(crcInput)
	if stored != computed {
		return rejected(fmt.Sprintf(
			"the LVM2 label CRC-32 is 0x%08x, computed 0x%08x", stored, computed))
	}
	return verified("the LVM2 label CRC-32 matches")
}

// verifyCoreStorage checks the physical-volume header's CRC-32C.
//
// VolumeSignature already applies this CRC through
// corestorage.LooksLikeVolumeHeader; re-checking it here keeps the verdict
// derived from the bytes rather than from the fact that a signature matched.
func verifyCoreStorage(head []byte) Verification {
	const headerBytes = 512
	if len(head) < headerBytes {
		return unverified("the CoreStorage physical-volume header is truncated; only the signature was confirmed")
	}
	stored, _ := u32leAt(head, 0)
	seed, _ := u32leAt(head, 4)
	computed := foundation.CRC32CSeeded(seed, head[8:headerBytes])
	if stored != computed {
		return rejected(fmt.Sprintf(
			"the CoreStorage header CRC-32C is 0x%08x, computed 0x%08x", stored, computed))
	}
	return verified("the CoreStorage physical-volume header CRC-32C (bytes 8..512) matches")
}

// verifyUnported reports a format whose Rust verifier exists but whose Go
// header parser is not ported yet.  It never pretends the structure was
// checked and never rejects a header it did not parse.
var unportedFormats = map[string]bool{
	"ntfs-volume":        true,
	"fat-volume":         true,
	"exfat-volume":       true,
	"apfs-volume":        true,
	"hfs-volume":         true,
	"hfs-classic-volume": true,
	"iso-volume":         true,
	"udf-volume":         true,
	"f2fs-volume":        true,
	"squashfs-volume":    true,
	"cramfs-volume":      true,
	"erofs-volume":       true,
	"reiserfs-volume":    true,
	"jfs-volume":         true,
	"minix-volume":       true,
	"befs-volume":        true,
	"ocfs2-volume":       true,
	"gfs2-volume":        true,
	"qnx6-volume":        true,
	"hpfs-volume":        true,
	"sysv-volume":        true,
	"ufs-volume":         true,
}

func verifyUnported(id, label string) Verification {
	if unportedFormats[id] {
		return unverified(fmt.Sprintf(
			"the %s header parser is not ported yet; only the signature was confirmed", label))
	}
	return unverified(fmt.Sprintf(
		"no internal consistency check is implemented for %s; only the signature was confirmed", label))
}
