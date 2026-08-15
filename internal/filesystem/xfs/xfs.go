package xfs

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"strings"

	"github.com/laenix/ewfgo/internal/filesystem"
)

func init() {
	filesystem.RegisterFileSystem(filesystem.FS_XFS, func() filesystem.FileSystem { return &XFS{} })
	filesystem.RegisterHandler(filesystem.FS_XFS, func(r filesystem.Reader, startLBA, partitionSize uint64) (filesystem.FileSystem, error) {
		return NewXFSHandler(r, startLBA)
	})
}

// XFS filesystem implementation.
//
// References: the Linux kernel xfs_format.h / xfs_dir2_format.h on-disk
// structures. Every fixed field offset below was verified against the committed
// xfs-*.E01 fixtures (real mkfs.xfs images) using xfs_db on the same image, so
// the offsets reflect the on-disk truth for this fixture family rather than a
// guessed layout.

// XFS on-disk magic numbers.
const (
	xfsSuperblockMagic = "XFSB"
	xfsInodeMagic      = 0x494e // "IN"
	xfsAGIMagic        = "XAGI"
	xfsInobtMagic      = "IAB3"
	xfsDirDataMagic    = "XDB3"
	// xfsDirDataMagic2 is the dir3 data-block magic used by some v5 (CRC)
	// filesystems for directory data blocks that carry the full dir3 CRC
	// header but a non-"B" magic byte. Confirmed on real CentOS 7 images
	// (server.E01, 服务器检材一.E01): the block decodes identically to XDB3 —
	// 48-byte header (magic/crc/blkno/lsn/uuid/owner) + bestfree area, first
	// entry at 0x40 — and xfs_db reports a valid CRC. Only the magic byte
	// differs.
	xfsDirDataMagic2 = "XDD3"
	xfsDirLeaf1Magic = "XDL1"
	xfsDirLeafNMagic = "XDLN"
	xfsDirNodeMagic  = "XDND"
	xfsBmbtMagic     = "BMA3"
)

const (
	xfsInodesPerChunk = 64  // inodes per inobt chunk
	xfsInodeCoreSize  = 176 // 0xb0: v3 dinode core, data fork starts here
	xfsAGIHeaderSize  = 512 // AGI header size (XFS_AGI_SIZE)

	// v5 (CRCs) short-form btree block header length and the fixed inobt
	// element sizes. Node keys and pointers live in separate maxrecs-sized
	// sections (kernel xfs_btree_ptr_offset), so locating a node's pointers
	// needs maxrecs, not the current record count.
	xfsBtreeShortHeaderLen = 56 // XFS_BTREE_SBLOCK_CRC_LEN
	xfsInobtKeyLen         = 4  // xfs_inobt_key_t: be32 startino
	xfsInobtPtrLen         = 4  // xfs_inobt_ptr_t: be32 agbno

	// Bmap btree element sizes. The long-form (on-disk) bmbt block header is
	// 24 bytes without CRCs (magic, level, numrecs, leftsib, rightsib) and 72
	// bytes on a v5 (CRC) filesystem: the 24-byte short part plus blkno(8),
	// lsn(8), uuid(16), owner(8), crc(4) and pad(4). The extra 8 bytes versus
	// the inobt short header come from the long-form left/right sibling pair
	// being 64-bit each, and from a 64-bit owner field (verified against
	// xfs_db on both a fresh kernel-6.8 image and a CentOS-era image).
	xfsBtreeLongHeaderLen    = 24 // XFS_BTREE_LBLOCK_LEN
	xfsBtreeLongHeaderCRCLen = 72 // XFS_BTREE_LBLOCK_CRC_LEN
	xfsBmdrBlockLen          = 4  // xfs_bmdr_block_t: bb_level u16 + bb_numrecs u16
	xfsBmdrKeyLen            = 8  // xfs_bmdr_key_t: be64 br_startoff
	// xfs_bmdr_ptr_t is a full 64-bit xfs_fsblock_t (agno<<agblklog | agbno) on
	// every filesystem we support — confirmed on-disk (fresh mkfs.xfs and a
	// CentOS-era image) where a 4-byte read at the computed pointer offset
	// misreads the high half of the pointer.
	xfsBmdrPtrLen = 8  // xfs_bmdr_ptr_t: be64 xfs_fsblock_t
	xfsBmbtKeyLen = 8  // xfs_bmbt_key_t: be64 br_startoff
	xfsBmbtPtrLen = 8  // xfs_bmbt_ptr_t: be64 xfs_fsblock_t
	xfsBmbtRecLen = 16 // xfs_bmbt_rec_t: 128-bit extent record

	// Bounds for symlink target reads and path traversal.
	xfsMaxSymlinkBytes = 1 << 20 // a symlink target is at most one big block
	xfsMaxSymlinkHops  = 40      // guard against symlink cycles in resolvePath

	// XFS_DIFLAG2_BIGTIME in di_flags2.
	xfsInodeFlagBigtime = 0x8
	// XFS_SB_FEAT_INCOMPAT_FTYPE / XFS_SB_FEAT_INCOMPAT_SPINODES in
	// sb_features_incompat.
	xfsIncompatFtype    = 0x01
	xfsIncompatSpinodes = 0x02
)

// XFS superblock field offsets (all big-endian), within the first 512 bytes of
// the 4096-byte superblock block.
const (
	xfsSBMagicOffset      = 0x00
	xfsSBBlocksizeOffset  = 0x04
	xfsSBUUIDOffset       = 0x20
	xfsSBRootinoOffset    = 0x38
	xfsSBAgblocksOffset   = 0x54
	xfsSBAgcountOffset    = 0x58
	xfsSBVersionnumOffset = 0x64
	xfsSBInodesizeOffset  = 0x68
	xfsSBInopblockOffset  = 0x6a
	xfsSBFnameOffset      = 0x6c
	xfsSBInopblogOffset   = 0x7b
	xfsSBAgblklogOffset   = 0x7c
	xfsSBSectlogOffset    = 0x79
	xfsSBFeatIncompatOff  = 0xd8 // 0xd0 is features_compat, not features_incompat
	xfsSBFeatures2Offset  = 0xc8 // sb_features2 (valid only with MOREBITS set)
)

// v3 dinode field offsets within the inode (512 bytes for the fixture).
const (
	xfsInodeModeOffset     = 0x02
	xfsInodeVersionOffset  = 0x04
	xfsInodeFormatOffset   = 0x05
	xfsInodeNlinkOffset    = 0x10
	xfsInodeAtimeOffset    = 0x1c
	xfsInodeMtimeOffset    = 0x24
	xfsInodeCtimeOffset    = 0x2c
	xfsInodeSizeOffset     = 0x38
	xfsInodeNextentsOffset = 0x4c
	xfsInodeForkoffOffset  = 0x52
	xfsInodeAformatOffset  = 0x53
	xfsInodeFlags2Offset   = 0x78
	xfsInodeDataForkOffset = xfsInodeCoreSize
)

// xfs_dinode di_format values.
const (
	xfsDinodeFormatDevice  = 0
	xfsDinodeFormatLocal   = 1
	xfsDinodeFormatExtents = 2
	xfsDinodeFormatBtree   = 3
	xfsDinodeFormatUUID    = 4
)

// xfs_dir2_data_fname / ftype values used by shortform and data-block entries.
const (
	xfsDir3FTUnknown = 0
	xfsDir3FTDir     = 2
)

// XFS is a reader-backed XFS filesystem handler. All on-disk reads go through
// xfs.readFunc relative to startLBA (the partition start sector), every slice
// is bounds-checked, and every parse failure surfaces as an explicit error —
// never a panic and never fabricated data.
type XFS struct {
	startLBA  uint64
	blocksize uint32
	agblocks  uint32
	agcount   uint32
	inodesize uint16
	inopblock uint16
	agblklog  uint
	inopblog  uint8
	inodelog  uint8
	sectlog   uint8
	ftype     bool
	spinodes  bool
	// crc reports a v5 filesystem (the low nibble of sb_versionnum is 5), which
	// governs the bmbt long-block header length.
	crc  bool
	uuid [16]byte
	// volumeName is the real sb_fname field, so GetVolumeLabel returns real
	// on-disk data rather than a guess.
	volumeName string
	rootIno    uint64

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// NewXFSHandler creates a new XFS filesystem handler over reader, with the
// filesystem's byte offset 0 at partition-relative sector startLBA.
func NewXFSHandler(reader filesystem.Reader, startLBA uint64) (*XFS, error) {
	xfs := &XFS{
		startLBA: startLBA,
		readFunc: reader.ReadSectors,
	}

	// The superblock block is 4096 bytes, but every field we need sits in the
	// first sector.
	sectorData, err := reader.ReadSectors(startLBA, 1)
	if err != nil {
		return nil, fmt.Errorf("XFS: failed to read superblock: %w", err)
	}

	if err := xfs.Open(sectorData); err != nil {
		return nil, err
	}
	return xfs, nil
}

func (xfs *XFS) Type() filesystem.FileSystemType { return filesystem.FS_XFS }

// Open validates the XFS superblock and caches the fields the parser needs. It
// must never fabricate values: any superblock field that fails validation is an
// error.
func (xfs *XFS) Open(sectorData []byte) error {
	if len(sectorData) < 512 {
		return fmt.Errorf("XFS: superblock too small (%d bytes)", len(sectorData))
	}
	if string(sectorData[0:4]) != xfsSuperblockMagic {
		return fmt.Errorf("XFS: invalid superblock magic %q", sectorData[0:4])
	}

	blocksize := binary.BigEndian.Uint32(sectorData[xfsSBBlocksizeOffset:])
	if blocksize < 512 || blocksize > 65536 || (blocksize&(blocksize-1)) != 0 {
		return fmt.Errorf("XFS: invalid blocksize %d", blocksize)
	}
	agcount := binary.BigEndian.Uint32(sectorData[xfsSBAgcountOffset:])
	agblocks := binary.BigEndian.Uint32(sectorData[xfsSBAgblocksOffset:])
	if agcount == 0 || agcount > 1000 {
		return fmt.Errorf("XFS: invalid agcount %d", agcount)
	}
	if agblocks < 2 || agblocks > (1<<30) {
		return fmt.Errorf("XFS: invalid agblocks %d", agblocks)
	}

	inodesize := binary.BigEndian.Uint16(sectorData[xfsSBInodesizeOffset:])
	inopblock := binary.BigEndian.Uint16(sectorData[xfsSBInopblockOffset:])
	if inodesize < 256 || inodesize > 2048 || (inodesize&(inodesize-1)) != 0 {
		return fmt.Errorf("XFS: invalid inodesize %d", inodesize)
	}
	if inopblock == 0 || uint32(inopblock) > blocksize/uint32(inodesize) {
		return fmt.Errorf("XFS: invalid inopblock %d", inopblock)
	}

	featIncompat := binary.BigEndian.Uint32(sectorData[xfsSBFeatIncompatOff:])
	rootIno := binary.BigEndian.Uint64(sectorData[xfsSBRootinoOffset:])
	if rootIno == 0 {
		return fmt.Errorf("XFS: superblock root inode is zero")
	}

	// A v5 (CRC) filesystem is reported by the low nibble of sb_versionnum
	// (XFS_SB_VERSION_NUMBITS) being 5. The MOREBITS+features2 CRCBIT test is
	// wrong for some real images (server.E01 has versionnum 0xb4b5 and
	// features2 without the CRCBIT bit yet is v5), so the version nibble is the
	// authoritative check. It selects the 72-byte long-form bmbt block header;
	// v4 uses the 24-byte header.
	versionnum := binary.BigEndian.Uint16(sectorData[xfsSBVersionnumOffset:])
	xfs.crc = versionnum&0xf == 5

	xfs.blocksize = blocksize
	xfs.agblocks = agblocks
	xfs.agcount = agcount
	xfs.inodesize = inodesize
	xfs.inopblock = inopblock
	// sb_agblklog is authoritative: it is the log2 of the AG size in blocks,
	// used to split an inode number into (agno, agino). The kernel derives
	// m_agblklog from sb_agblklog. Computing bits.Len32(agblocks)-1 only
	// matches when agblocks is an exact power of two — a real image whose
	// agblocks is 19200 carries sb_agblklog=15, not 14 — so the superblock
	// field must win. Fall back to the computed value only when the field is
	// absent (0; impossible on a real fs, which needs at least 2 blocks).
	agblklog := uint(sectorData[xfsSBAgblklogOffset])
	if agblklog == 0 || agblklog > 31 {
		agblklog = uint(bits.Len32(agblocks) - 1)
	}
	xfs.agblklog = agblklog
	xfs.inopblog = sectorData[xfsSBInopblogOffset]
	xfs.sectlog = sectorData[xfsSBSectlogOffset]
	if xfs.sectlog < 9 || xfs.sectlog > 15 {
		return fmt.Errorf("XFS: invalid sectlog %d", xfs.sectlog)
	}
	xfs.ftype = featIncompat&xfsIncompatFtype != 0
	xfs.spinodes = featIncompat&xfsIncompatSpinodes != 0
	xfs.rootIno = rootIno
	copy(xfs.uuid[:], sectorData[xfsSBUUIDOffset:xfsSBUUIDOffset+16])
	xfs.volumeName = strings.TrimRight(string(sectorData[xfsSBFnameOffset:xfsSBFnameOffset+12]), "\x00 \t")

	return nil
}

func (xfs *XFS) Close() error { return nil }

// DebugInode reads a raw inode (temporary diagnostic — remove before commit).
func (xfs *XFS) DebugInode(ino uint64) ([]byte, error) { return xfs.readInode(ino) }

// DebugBlock reads a raw filesystem block (temporary diagnostic — remove before commit).
func (xfs *XFS) DebugBlock(fsb uint64) ([]byte, error) { return xfs.readBlock(fsb) }

// DebugExtents exposes readBtreeExtents (temporary diagnostic — remove before commit).
func (xfs *XFS) DebugExtents(ino []byte, inoNum uint64) ([]xfsExtent, error) {
	return xfs.readBtreeExtents(ino, inoNum)
}

// GetVolumeLabel returns the real sb_fname volume label (empty string when the
// field is unset).
func (xfs *XFS) GetVolumeLabel() string { return xfs.volumeName }

// readBytes reads length bytes at filesystem-relative byte offset off.
func (xfs *XFS) readBytes(off uint64, length uint64) ([]byte, error) {
	if xfs.readFunc == nil {
		return nil, fmt.Errorf("XFS: handler has no reader")
	}
	if length == 0 {
		return []byte{}, nil
	}
	if off > 1<<44 {
		return nil, fmt.Errorf("XFS: read offset 0x%x out of range", off)
	}
	if length > 1<<30 {
		return nil, fmt.Errorf("XFS: read length %d out of range", length)
	}
	const sectorSize = 512
	byteOff := xfs.startLBA*sectorSize + off
	lba := byteOff / sectorSize
	start := byteOff % sectorSize
	count := (start + length + sectorSize - 1) / sectorSize
	data, err := xfs.readFunc(lba, count)
	if err != nil {
		return nil, err
	}
	if start+length > uint64(len(data)) {
		return nil, fmt.Errorf("XFS: short read at byte 0x%x: got %d bytes, want %d", off, len(data), start+length)
	}
	return data[start : start+length], nil
}

// readBlock reads a full filesystem block (blocksize bytes) at fsb.
func (xfs *XFS) readBlock(fsb uint64) ([]byte, error) {
	if fsb > 1<<40 {
		return nil, fmt.Errorf("XFS: block number %d out of range", fsb)
	}
	return xfs.readBytes(fsb*uint64(xfs.blocksize), uint64(xfs.blocksize))
}

// fsbToFsb converts an on-disk bmbt startblock (xfs_fsblock_t) to the real
// filesystem block number. The startblock encodes its AG in the high bits as
// agno<<sb_agblklog | agbno, so the physical block is agno*agblocks + agbno.
// The two formulas agree only when agblocks == 2^agblklog; a "small AG"
// filesystem (e.g. a 300MB image whose AGs were clamped to 19200 blocks while
// sb_agblklog stayed 15) mislocates every AG>0 extent if the raw startblock is
// used as a linear fsb. The conversion is the identity on ordinary images, so
// it is safe for every filesystem.
func (xfs *XFS) fsbToFsb(startBlock uint64) uint64 {
	agno := startBlock >> xfs.agblklog
	agbno := startBlock & ((uint64(1) << xfs.agblklog) - 1)
	return agno*uint64(xfs.agblocks) + agbno
}

// readAGI reads the allocation-group-inode header for AG agno and returns it.
// AG headers are packed at the start of each AG at 512-byte sector addresses
// (superblock@0, AGF@1, AGI@2, AGFL@3 for a 512-byte sector size; proportionally
// scaled by (1 << (sectlog-9)) for larger sector sizes), so the AGI sits
// (2 << (sectlog-9)) * 512 bytes into the AG, not at a block boundary.
func (xfs *XFS) readAGI(agno uint32) ([]byte, error) {
	sectbbLog := uint(xfs.sectlog) - 9
	agiOff := (uint64(2) << sectbbLog) * 512
	off := uint64(agno)*uint64(xfs.agblocks)*uint64(xfs.blocksize) + agiOff
	agi, err := xfs.readBytes(off, xfsAGIHeaderSize)
	if err != nil {
		return nil, fmt.Errorf("XFS: failed to read AGI for AG %d: %w", agno, err)
	}
	if string(agi[0:4]) != xfsAGIMagic {
		return nil, fmt.Errorf("XFS: invalid AGI magic %q at AG %d", agi[0:4], agno)
	}
	return agi, nil
}

// inobtRecord is one inode b-tree leaf record. freeCount is parsed but not
// trusted for allocation decisions; the free bitmap is the source of truth.
type inobtRecord struct {
	startIno uint32
	free     uint64
	spmask   uint64
}

// parseInobtLeaf parses an already-read inobt leaf block and returns the record
// whose range [startIno, startIno+64) contains agino.
func (xfs *XFS) parseInobtLeaf(block []byte, fsb uint64, agino uint32) (inobtRecord, error) {
	var rec inobtRecord
	if len(block) < 0x50 {
		return rec, fmt.Errorf("XFS: inobt leaf block %d too small", fsb)
	}
	// The v5 inobt header is 56 bytes (XFS_BTREE_SBLOCK_CRC_LEN), so records
	// start at offset 0x38 — verified against the committed fixtures with
	// xfs_db. The freecount field is ignored: allocation comes from the free
	// bitmap.
	recStride := 16
	if xfs.spinodes {
		recStride = 32
	}
	recOff := xfsBtreeShortHeaderLen
	numrecs := binary.BigEndian.Uint16(block[6:8])
	for i := uint16(0); i < numrecs; i++ {
		if recOff+recStride > len(block) {
			return rec, fmt.Errorf("XFS: inobt leaf %d record %d out of bounds", fsb, i)
		}
		startIno := binary.BigEndian.Uint32(block[recOff:])
		free := binary.BigEndian.Uint64(block[recOff+8:])
		var spmask uint64
		if xfs.spinodes && recOff+24 <= len(block) {
			spmask = binary.BigEndian.Uint64(block[recOff+16:])
		}
		if agino >= startIno && agino < startIno+xfsInodesPerChunk {
			return inobtRecord{startIno: startIno, free: free, spmask: spmask}, nil
		}
		recOff += recStride
	}
	return rec, fmt.Errorf("XFS: no inobt record for inode %d", agino)
}

// readInode reads the on-disk inode bytes for inode number ino. The inode
// number is split into (agno, agino), the inobt is walked from the AGI root to
// locate the owning chunk, and the inode's position within the chunk is
// resolved to an absolute byte offset (startLBA added) before reading.
func (xfs *XFS) readInode(ino uint64) ([]byte, error) {
	shift := xfs.agblklog + uint(xfs.inopblog)
	if ino == 0 || ino>>shift >= uint64(xfs.agcount) {
		return nil, fmt.Errorf("XFS: inode %d out of range", ino)
	}
	agno := uint32(ino >> shift)
	agino := uint32(ino & ((1 << shift) - 1))

	agi, err := xfs.readAGI(agno)
	if err != nil {
		return nil, err
	}
	agiRoot := binary.BigEndian.Uint32(agi[0x14:0x18])
	if agiRoot == 0 {
		return nil, fmt.Errorf("XFS: AG %d inobt root is zero", agno)
	}

	// Walk the inobt from the AGI root. Each block's own level field is the
	// source of truth (the AGI level is not reliable on every image): interior
	// nodes (level > 0) carry {keys, ptrs}, the leaf (level 0) the records.
	var rec inobtRecord
	child := agiRoot
	found := false
	for depth := 0; depth < 32; depth++ {
		fsb := uint64(agno)*uint64(xfs.agblocks) + uint64(child)
		block, err := xfs.readBlock(fsb)
		if err != nil {
			return nil, err
		}
		if len(block) < 0x38 || string(block[0:4]) != xfsInobtMagic {
			return nil, fmt.Errorf("XFS: invalid inobt block %d", fsb)
		}
		level := binary.BigEndian.Uint16(block[4:6])
		numrecs := binary.BigEndian.Uint16(block[6:8])
		if numrecs == 0 {
			return nil, fmt.Errorf("XFS: empty inobt block %d", fsb)
		}
		if level == 0 {
			rec, err = xfs.parseInobtLeaf(block, fsb, agino)
			if err != nil {
				return nil, err
			}
			found = true
			break
		}
		keysOff := xfsBtreeShortHeaderLen
		if keysOff+int(numrecs)*xfsInobtKeyLen > len(block) {
			return nil, fmt.Errorf("XFS: inobt node %d keys out of bounds", fsb)
		}
		// Kernel xfs_btree_ptr_offset: a node's pointers sit after the full
		// maxrecs-wide key section (keysOff + maxrecs*key_len), where maxrecs is
		// the block's node capacity — (blocksize - header) / (key_len + ptr_len)
		// — NOT immediately after the numrecs keys. Reading at the numrecs
		// offset lands in the unused key section (zeros) on any real node that
		// holds fewer than maxrecs keys, producing a null child.
		maxrecs := (int(xfs.blocksize) - xfsBtreeShortHeaderLen) / (xfsInobtKeyLen + xfsInobtPtrLen)
		ptrsOff := keysOff + maxrecs*xfsInobtKeyLen
		if ptrsOff+int(numrecs)*xfsInobtPtrLen > len(block) {
			return nil, fmt.Errorf("XFS: inobt node %d ptrs out of bounds", fsb)
		}
		// Find the last key <= agino; the matching child is the corresponding
		// ptr, with the final ptr covering everything past the last key.
		child = binary.BigEndian.Uint32(block[ptrsOff+int(numrecs-1)*xfsInobtPtrLen:])
		for i := 0; i < int(numrecs); i++ {
			key := binary.BigEndian.Uint32(block[keysOff+i*xfsInobtKeyLen:])
			if agino >= key {
				child = binary.BigEndian.Uint32(block[ptrsOff+i*xfsInobtPtrLen:])
				continue
			}
			break
		}
		if child == 0 {
			return nil, fmt.Errorf("XFS: inobt node %d has null child", fsb)
		}
	}
	if !found {
		return nil, fmt.Errorf("XFS: inobt walk for inode %d did not reach a leaf", ino)
	}
	relIno := agino - rec.startIno
	if relIno >= xfsInodesPerChunk {
		return nil, fmt.Errorf("XFS: inode %d not in record [%d, %d)", ino, rec.startIno, rec.startIno+xfsInodesPerChunk)
	}
	if rec.free&(1<<relIno) != 0 {
		return nil, fmt.Errorf("XFS: inode %d is marked free", ino)
	}

	chunkStart := rec.startIno / uint32(xfs.inopblock)
	subBlock := relIno / uint32(xfs.inopblock)
	if subBlock >= 8 {
		return nil, fmt.Errorf("XFS: inode %d sub-block %d out of range", ino, subBlock)
	}
	// Sparse chunks pack only the present sub-blocks; a hole means the inode is
	// not stored.
	if xfs.spinodes && (rec.spmask&(1<<subBlock)) != 0 {
		return nil, fmt.Errorf("XFS: inode %d sits in a sparse hole", ino)
	}
	present := uint64(0)
	if xfs.spinodes {
		mask := uint64(1)<<subBlock - 1
		present = uint64(bits.OnesCount64(rec.spmask & mask))
	}
	agbno := uint64(chunkStart) + present + uint64(subBlock)
	if agbno >= uint64(xfs.agblocks) {
		return nil, fmt.Errorf("XFS: inode %d maps to agbno %d beyond agblocks %d", ino, agbno, xfs.agblocks)
	}
	inodeInBlock := relIno % uint32(xfs.inopblock)

	byteOff := (uint64(agno)*uint64(xfs.agblocks)+agbno)*uint64(xfs.blocksize) +
		uint64(inodeInBlock)*uint64(xfs.inodesize)
	inoData, err := xfs.readBytes(byteOff, uint64(xfs.inodesize))
	if err != nil {
		return nil, err
	}
	if len(inoData) < 4 || binary.BigEndian.Uint16(inoData[0:2]) != xfsInodeMagic {
		return nil, fmt.Errorf("XFS: inode %d has invalid magic", ino)
	}
	return inoData, nil
}

// inodeTime returns the unix seconds for a timestamp at inodeOffset, decoding
// bigtime when the bigtime flag is set (XFS_DIFLAG2_BIGTIME).
func inodeTime(ino []byte, offset int, flags2 uint64) int64 {
	raw := binary.BigEndian.Uint64(ino[offset : offset+8])
	if flags2&xfsInodeFlagBigtime != 0 {
		const scale = 1000000000
		const epochOffset = int64(1) << 31
		sec := int64(raw / scale)
		return sec - epochOffset
	}
	// Non-bigtime: 4-byte seconds then 4-byte nanoseconds.
	return int64(binary.BigEndian.Uint32(ino[offset : offset+4]))
}

// xfsExtent is one data-fork extent.
type xfsExtent struct {
	startoff   uint64 // logical file block
	startBlock uint64 // filesystem block
	blockCount uint64 // blocks in extent
}

// parseExtents decodes the on-disk xfs_bmbt_rec array (16 bytes each) in the
// data fork for format-2 inodes.
func parseExtents(fork []byte, nextents uint32) ([]xfsExtent, error) {
	if uint64(nextents) > uint64(len(fork))/16 {
		return nil, fmt.Errorf("XFS: nextents %d exceeds fork capacity %d", nextents, len(fork)/16)
	}
	exts := make([]xfsExtent, 0, nextents)
	for i := uint32(0); i < nextents; i++ {
		rec := fork[i*16 : i*16+16]
		l0 := binary.BigEndian.Uint64(rec[0:8])
		l1 := binary.BigEndian.Uint64(rec[8:16])
		// startoff is bits 9..62 of l0 (54 bits); startblock splits across the
		// low 9 bits of l0 and the top 43 bits of l1; blockcount is the low 21
		// bits of l1 (kernel xfs_bmbt_rec layout).
		startoff := (l0 & (1<<63 - 1)) >> 9
		startBlock := ((l0 & 0x1ff) << 43) | (l1 >> 21)
		blockCount := l1 & 0x1fffff
		if blockCount == 0 {
			return nil, fmt.Errorf("XFS: extent %d has zero block count", i)
		}
		exts = append(exts, xfsExtent{startoff: startoff, startBlock: startBlock, blockCount: blockCount})
	}
	return exts, nil
}

// dataForkLimit returns the byte offset at which the data fork ends. When
// forkoff is nonzero the kernel places the attribute fork at
// XFS_DFORK_APTR = XFS_DFORK_DPTR + (forkoff<<3), i.e. core_end + forkoff*8,
// so the data fork spans [core_end, core_end+forkoff*8). When forkoff is zero
// the data fork extends to the end of the inode (XFS_LITINO). A forged forkoff
// whose data fork would overrun the inode is malformed and surfaces as an
// error rather than allowing ino[176:limit] to panic on a crafted inode.
func (xfs *XFS) dataForkLimit(ino []byte) (int, error) {
	forkoff := ino[xfsInodeForkoffOffset]
	if forkoff == 0 {
		return len(ino), nil
	}
	limit := xfsInodeDataForkOffset + int(forkoff)*8
	if limit > len(ino) {
		return 0, fmt.Errorf("XFS: data fork end %d exceeds inode size %d", limit, len(ino))
	}
	return limit, nil
}

// readFileData reads the data fork of a regular inode: local (inline) data or
// extents. size limits the returned slice.
func (xfs *XFS) readFileData(ino []byte, inoNum uint64, size uint64) ([]byte, error) {
	// A forged di_size must not drive a huge allocation or an unbounded read.
	if size > 1<<40 {
		return nil, fmt.Errorf("XFS: declared size %d out of range", size)
	}
	format := ino[xfsInodeFormatOffset]
	limit, err := xfs.dataForkLimit(ino)
	if err != nil {
		return nil, err
	}
	fork := ino[xfsInodeDataForkOffset:limit]

	switch format {
	case xfsDinodeFormatLocal:
		if uint64(len(fork)) < size {
			return nil, fmt.Errorf("XFS: local data %d bytes shorter than size %d", len(fork), size)
		}
		return fork[:size], nil
	case xfsDinodeFormatExtents:
		nextents := binary.BigEndian.Uint32(ino[xfsInodeNextentsOffset : xfsInodeNextentsOffset+4])
		exts, err := parseExtents(fork, nextents)
		if err != nil {
			return nil, err
		}
		return xfs.readExtents(exts, size)
	case xfsDinodeFormatBtree:
		exts, err := xfs.readBtreeExtents(ino, inoNum)
		if err != nil {
			return nil, err
		}
		return xfs.readExtents(exts, size)
	default:
		return nil, fmt.Errorf("XFS: unsupported data fork format %d", format)
	}
}

// readExtents assembles size bytes from an extent list, reading each extent's
// blocks from disk and honoring each extent's logical startoff. XFS stores
// sparse files by simply omitting the unallocated ranges from the extent list,
// so a gap between consecutive extents (or past the last one) is a hole whose
// real content is zeros — the same bytes a live mount returns. All reads are
// bounds-checked and size-limited.
func (xfs *XFS) readExtents(exts []xfsExtent, size uint64) ([]byte, error) {
	blockSize := uint64(xfs.blocksize)
	if blockSize == 0 {
		return nil, fmt.Errorf("XFS: invalid block size 0")
	}
	// Cap the eager preallocation so a crafted extent list cannot force a huge
	// allocation; append grows the buffer for genuinely large files.
	initialCap := size
	if initialCap > 1<<20 {
		initialCap = 1 << 20
	}
	out := make([]byte, 0, initialCap)
	// pos is the logical byte position assembled so far.
	var pos uint64
	for _, ext := range exts {
		if pos >= size {
			break
		}
		// Fill any hole before this extent with zeros (see above).
		extOff := ext.startoff * blockSize
		if extOff > pos {
			hole := extOff - pos
			if hole > size-pos {
				hole = size - pos
			}
			out = append(out, make([]byte, hole)...)
			pos += hole
		}
		if pos >= size {
			break
		}
		if ext.startBlock > 1<<40 {
			return nil, fmt.Errorf("XFS: extent start block %d out of range", ext.startBlock)
		}
		bytesAvailable := ext.blockCount * blockSize
		toRead := bytesAvailable
		if toRead > size-pos {
			toRead = size - pos
		}
		chunk, err := xfs.readBytes(xfs.fsbToFsb(ext.startBlock)*blockSize, toRead)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		pos += uint64(len(chunk))
	}
	// A trailing range past the last extent is also a hole.
	if pos < size {
		out = append(out, make([]byte, size-pos)...)
	}
	return out, nil
}

// bmbtHeaderLen returns the long-form bmbt block header length for this
// filesystem: 72 bytes on v5 (CRC) filesystems, 24 on v4.
func (xfs *XFS) bmbtHeaderLen() int {
	if xfs.crc {
		return xfsBtreeLongHeaderCRCLen
	}
	return xfsBtreeLongHeaderLen
}

// parseBmbtRecords decodes numrecs 16-byte xfs_bmbt_rec records from buf
// (the record area of a bmbt leaf). The record layout matches parseExtents.
func parseBmbtRecords(buf []byte, numrecs uint16) ([]xfsExtent, error) {
	if int(numrecs)*xfsBmbtRecLen > len(buf) {
		return nil, fmt.Errorf("XFS: bmbt records %d exceed capacity %d", numrecs, len(buf)/xfsBmbtRecLen)
	}
	exts := make([]xfsExtent, 0, numrecs)
	for i := uint16(0); i < numrecs; i++ {
		rec := buf[int(i)*xfsBmbtRecLen : int(i)*xfsBmbtRecLen+xfsBmbtRecLen]
		l0 := binary.BigEndian.Uint64(rec[0:8])
		l1 := binary.BigEndian.Uint64(rec[8:16])
		startoff := (l0 & (1<<63 - 1)) >> 9
		startBlock := ((l0 & 0x1ff) << 43) | (l1 >> 21)
		blockCount := l1 & 0x1fffff
		if blockCount == 0 {
			return nil, fmt.Errorf("XFS: bmbt record %d has zero block count", i)
		}
		exts = append(exts, xfsExtent{startoff: startoff, startBlock: startBlock, blockCount: blockCount})
	}
	return exts, nil
}

// walkBmbt gathers every extent record from the bmbt tree rooted at the
// on-disk block block. Interior nodes (level > 0) carry 64-bit fsb pointers
// after the full maxrecs-wide key section; leaves (level 0) carry records
// right after the header. Depth is bounded so a crafted tree cannot loop.
func (xfs *XFS) walkBmbt(block []byte, hdr int, out *[]xfsExtent, depth int) error {
	if depth > 32 {
		return fmt.Errorf("XFS: bmbt depth exceeded at block magic %q", blockPrefix(block))
	}
	if len(block) < hdr || string(block[0:4]) != xfsBmbtMagic {
		return fmt.Errorf("XFS: invalid bmbt block magic %q", blockPrefix(block))
	}
	level := binary.BigEndian.Uint16(block[4:6])
	numrecs := binary.BigEndian.Uint16(block[6:8])
	if numrecs == 0 {
		return fmt.Errorf("XFS: empty bmbt block")
	}
	if level == 0 {
		exts, err := parseBmbtRecords(block[hdr:], numrecs)
		if err != nil {
			return err
		}
		*out = append(*out, exts...)
		return nil
	}
	// Node pointers sit after the full maxrecs-wide key section (kernel
	// xfs_btree_lblock_ptr_offset), exactly like the inobt short-block nodes.
	maxrecs := (len(block) - hdr) / (xfsBmbtKeyLen + xfsBmbtPtrLen)
	ptrsOff := hdr + maxrecs*xfsBmbtKeyLen
	if ptrsOff+int(numrecs)*xfsBmbtPtrLen > len(block) {
		return fmt.Errorf("XFS: bmbt node pointers out of bounds")
	}
	for i := uint16(0); i < numrecs; i++ {
		fsb := binary.BigEndian.Uint64(block[ptrsOff+int(i)*xfsBmbtPtrLen:])
		if fsb > 1<<40 {
			return fmt.Errorf("XFS: bmbt child block %d out of range", fsb)
		}
		// Node pointers are packed xfs_fsblock_t (agno<<agblklog | agbno);
		// expand to the linear filesystem block before reading.
		child, err := xfs.readBlock(xfs.fsbToFsb(fsb))
		if err != nil {
			return err
		}
		if err := xfs.walkBmbt(child, hdr, out, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// blockPrefix returns the first bytes of a block for error messages without
// panicking on a short slice.
func blockPrefix(b []byte) string {
	if len(b) < 4 {
		return string(b)
	}
	return string(b[0:4])
}

// readBtreeExtents reads the extent list of a format-3 (btree) data fork.
//
// The inode-resident root is a compact bmdr block: {level u16, numrecs u16},
// then maxrecs keys (br_startoff u64 each), then maxrecs pointers, where
// maxrecs = (DSIZE-4)/(key+ptr). DSIZE is forkoff<<3 when forkoff is set, else
// XFS_LITINO (336 for 512-byte v3 inodes). Every pointer — root and node alike
// — is a packed xfs_fsblock_t (agno<<agblklog | agbno), expanded to the linear
// filesystem block via fsbToFsb before reading. Confirmed on-disk against a
// fresh kernel-6.8 image and a CentOS-era image (server.E01).
func (xfs *XFS) readBtreeExtents(ino []byte, inoNum uint64) ([]xfsExtent, error) {
	limit, err := xfs.dataForkLimit(ino)
	if err != nil {
		return nil, err
	}
	fork := ino[xfsInodeDataForkOffset:limit]
	if len(fork) < xfsBmdrBlockLen {
		return nil, fmt.Errorf("XFS: btree data fork too small (%d bytes)", len(fork))
	}
	level := binary.BigEndian.Uint16(fork[0:2])
	numrecs := binary.BigEndian.Uint16(fork[2:4])
	if level == 0 {
		return nil, fmt.Errorf("XFS: btree data fork root has level 0")
	}
	if numrecs == 0 {
		return nil, fmt.Errorf("XFS: btree data fork root is empty")
	}
	maxrecs := (len(fork) - xfsBmdrBlockLen) / (xfsBmdrKeyLen + xfsBmdrPtrLen)
	if maxrecs < 1 {
		return nil, fmt.Errorf("XFS: btree data fork too small for a root")
	}
	ptrsOff := xfsBmdrBlockLen + maxrecs*xfsBmdrKeyLen
	if ptrsOff+int(numrecs)*xfsBmdrPtrLen > len(fork) {
		return nil, fmt.Errorf("XFS: btree data fork root pointers out of bounds")
	}
	hdr := xfs.bmbtHeaderLen()
	var exts []xfsExtent
	for i := uint16(0); i < numrecs; i++ {
		// Root pointers are packed xfs_fsblock_t (agno<<agblklog | agbno);
		// expand to the linear filesystem block before reading.
		fsb := xfs.fsbToFsb(binary.BigEndian.Uint64(fork[ptrsOff+int(i)*xfsBmdrPtrLen:]))
		if fsb > 1<<40 {
			return nil, fmt.Errorf("XFS: btree root child block %d out of range", fsb)
		}
		block, err := xfs.readBlock(fsb)
		if err != nil {
			return nil, err
		}
		if err := xfs.walkBmbt(block, hdr, &exts, 0); err != nil {
			return nil, err
		}
	}
	return exts, nil
}

// isDirectoryInode reports whether the inode describes a directory.
func isDirectoryInode(ino []byte) bool {
	mode := binary.BigEndian.Uint16(ino[xfsInodeModeOffset : xfsInodeModeOffset+2])
	return mode&0xf000 == 0x4000
}

// isSymlinkInode reports whether the inode is a symbolic link.
func isSymlinkInode(ino []byte) bool {
	mode := binary.BigEndian.Uint16(ino[xfsInodeModeOffset : xfsInodeModeOffset+2])
	return mode&0xf000 == 0xa000
}

// symlinkTarget returns the target string of a symlink inode. Short links are
// stored inline in the data fork (format 1); long links live in a block read
// through the extent list, exactly like file content. The result is validated
// as a path string, so a crafted inode cannot smuggle garbage into a listing.
func (xfs *XFS) symlinkTarget(ino []byte, inoNum uint64) (string, error) {
	size := binary.BigEndian.Uint64(ino[xfsInodeSizeOffset : xfsInodeSizeOffset+8])
	if size > xfsMaxSymlinkBytes {
		return "", fmt.Errorf("XFS: symlink target size %d exceeds the supported maximum", size)
	}
	data, err := xfs.readFileData(ino, inoNum, size)
	if err != nil {
		return "", err
	}
	if i := strings.IndexByte(string(data), 0); i >= 0 {
		data = data[:i]
	}
	if !validDirName(string(data)) {
		return "", fmt.Errorf("XFS: symlink target %q is not a valid path", data)
	}
	return string(data), nil
}

// parentInode returns the parent directory inode of a directory. Shortform
// (local) dirs store the parent in the sf header — "." and ".." are implicit
// there — while block and node dirs carry ".." as a real on-disk entry.
func (xfs *XFS) parentInode(inoData []byte, inoNum uint64) (uint64, error) {
	if inoData[xfsInodeFormatOffset] == xfsDinodeFormatLocal {
		size := binary.BigEndian.Uint64(inoData[xfsInodeSizeOffset : xfsInodeSizeOffset+8])
		limit, err := xfs.dataForkLimit(inoData)
		if err != nil {
			return 0, err
		}
		if size > uint64(limit-xfsInodeDataForkOffset) {
			return 0, fmt.Errorf("XFS: shortform dir %d size exceeds fork data", inoNum)
		}
		data := inoData[xfsInodeDataForkOffset : uint64(xfsInodeDataForkOffset)+size]
		if len(data) < 6 {
			return 0, fmt.Errorf("XFS: shortform dir %d too small for parent", inoNum)
		}
		if data[1] > 0 { // i8count: the parent field is 8 bytes when any ino is 8 bytes
			if len(data) < 10 {
				return 0, fmt.Errorf("XFS: shortform dir %d too small for parent", inoNum)
			}
			return binary.BigEndian.Uint64(data[2:10]), nil
		}
		return uint64(binary.BigEndian.Uint32(data[2:6])), nil
	}
	entries, err := xfs.readDirectory(inoData, inoNum, "")
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if e.Name == ".." {
			return e.Inode, nil
		}
	}
	return 0, fmt.Errorf("XFS: directory %d has no '..' entry", inoNum)
}

// lookupDirEntry finds the entry named name in a directory listing, returning
// an explicit "not found" error when absent.
func lookupDirEntry(entries []filesystem.DirectoryEntry, name string) (uint64, error) {
	for _, e := range entries {
		if e.Name == name {
			return e.Inode, nil
		}
	}
	return 0, fmt.Errorf("XFS: %q not found in directory", name)
}

// readDirectory parses the directory data fork of an inode, dispatching on the
// fork format: local (shortform), extents (block/leaf via the extent list) or
// btree (node). It returns only names actually stored on disk.
func (xfs *XFS) readDirectory(ino []byte, inoNum uint64, dirPath string) ([]filesystem.DirectoryEntry, error) {
	if !isDirectoryInode(ino) {
		return nil, fmt.Errorf("XFS: inode is not a directory")
	}
	format := ino[xfsInodeFormatOffset]
	switch format {
	case xfsDinodeFormatLocal:
		return xfs.parseShortformDir(ino, dirPath)
	case xfsDinodeFormatExtents:
		return xfs.parseDirExtents(ino, dirPath)
	case xfsDinodeFormatBtree:
		return xfs.parseDirNode(ino, inoNum, dirPath)
	default:
		return nil, fmt.Errorf("XFS: unsupported directory format %d", format)
	}
}

// filterDotEntries removes the "." and ".." self/parent entries from a raw
// directory listing. Block/node-format XFS directories store them as real
// on-disk entries, but the public API convention (matching FAT32 and ext4)
// excludes them: a downstream walker that recurses into "." would loop or
// fabricate nested paths. Internal consumers that need the raw ".." (parent
// resolution) read via readDirectory, which stays unfiltered.
func filterDotEntries(entries []filesystem.DirectoryEntry) []filesystem.DirectoryEntry {
	out := entries[:0]
	for _, e := range entries {
		if e.Name != "." && e.Name != ".." {
			out = append(out, e)
		}
	}
	return out
}

// childInodeSize returns the on-disk size of inode ino, or 0 when the inode
// cannot be read (freed or sparse). XFS directory entries store no size — the
// dirent holds only {inode, name, type} — so a listing reads each child inode
// to report a real size rather than fabricating one.
func (xfs *XFS) childInodeSize(ino uint64) uint64 {
	d, err := xfs.readInode(ino)
	if err != nil {
		return 0
	}
	return binary.BigEndian.Uint64(d[xfsInodeSizeOffset : xfsInodeSizeOffset+8])
}

// parseShortformDir parses a shortform (local) directory: the sf header holds
// count/i8count/parent, followed by packed entries. Empty shortform dirs carry
// no "." or ".." on disk (they are implicit), so an empty root yields an empty
// non-nil listing.
func (xfs *XFS) parseShortformDir(ino []byte, dirPath string) ([]filesystem.DirectoryEntry, error) {
	size := binary.BigEndian.Uint64(ino[xfsInodeSizeOffset : xfsInodeSizeOffset+8])
	limit, err := xfs.dataForkLimit(ino)
	if err != nil {
		return nil, err
	}
	if limit < xfsInodeDataForkOffset {
		return nil, fmt.Errorf("XFS: shortform dir fork end %d precedes data fork start", limit)
	}
	if size > uint64(limit-xfsInodeDataForkOffset) {
		return nil, fmt.Errorf("XFS: shortform dir size %d exceeds fork data length %d", size, limit-xfsInodeDataForkOffset)
	}
	data := ino[xfsInodeDataForkOffset : uint64(xfsInodeDataForkOffset)+size]
	if len(data) < 2 {
		return nil, fmt.Errorf("XFS: shortform dir data too short (%d bytes)", len(data))
	}
	count := data[0]
	i8count := data[1]

	// xfs_dir2_sf_hdr: count + i8count, then parent (4 bytes when i8count==0,
	// 8 bytes when i8count>0). Header size is driven by i8count ONLY — it does
	// not depend on the ftype feature bit, nor on crc/version.
	hdr := 2
	if i8count > 0 {
		hdr += 8
	} else {
		hdr += 4
	}
	if hdr > len(data) {
		return nil, fmt.Errorf("XFS: shortform dir header %d exceeds data %d", hdr, len(data))
	}

	inoSize := 4
	if i8count > 0 {
		inoSize = 8
	}

	entries := make([]filesystem.DirectoryEntry, 0, count)
	off := hdr
	for i := byte(0); i < count; i++ {
		if off+3 > len(data) {
			return nil, fmt.Errorf("XFS: shortform entry %d header out of bounds", i)
		}
		namelen := int(data[off])
		if namelen == 0 {
			return nil, fmt.Errorf("XFS: shortform entry %d has zero name length", i)
		}
		nameOff := off + 3
		ftypeOff := nameOff + namelen
		inoOff := ftypeOff
		if xfs.ftype {
			inoOff++
		}
		if nameOff+namelen > len(data) || inoOff+inoSize > len(data) {
			return nil, fmt.Errorf("XFS: shortform entry %d out of bounds", i)
		}
		name := string(data[nameOff : nameOff+namelen])
		if !validDirName(name) {
			return nil, fmt.Errorf("XFS: shortform entry %d has invalid name", i)
		}
		var childIno uint64
		if inoSize == 8 {
			childIno = binary.BigEndian.Uint64(data[inoOff : inoOff+8])
		} else {
			childIno = uint64(binary.BigEndian.Uint32(data[inoOff : inoOff+4]))
		}
		isDir := false
		childSize := uint64(0)
		if xfs.ftype && ftypeOff < inoOff {
			isDir = data[ftypeOff] == xfsDir3FTDir
		} else {
			if childData, err := xfs.readInode(childIno); err == nil {
				isDir = isDirectoryInode(childData)
				childSize = binary.BigEndian.Uint64(childData[xfsInodeSizeOffset : xfsInodeSizeOffset+8])
			}
		}
		// XFS dirents carry no size; only the child inode does. Report a real
		// size for non-directory entries so listings are not all-zeros.
		if !isDir && childSize == 0 {
			childSize = xfs.childInodeSize(childIno)
		}
		entries = append(entries, filesystem.DirectoryEntry{
			Name:  name,
			Path:  filesystem.JoinPath(dirPath, name),
			IsDir: isDir,
			Size:  childSize,
			Inode: childIno,
		})
		off = inoOff + inoSize
	}
	return entries, nil
}

// dirDataBoundary returns the largest logical filesystem block number that can
// hold directory data. The dir2/dir3 data region occupies logical byte offsets
// below XFS_DIR2_DATA_OFFSET (1<<32); leaf, free, and node index blocks start
// at or above it. In fsb units the boundary is 2^(32-blocklog). Blocks at or
// beyond the boundary hold no directory entries — only the allocation index —
// so they must be skipped, not parsed as data.
func (xfs *XFS) dirDataBoundary() uint64 {
	return uint64(1) << (32 - bits.TrailingZeros32(xfs.blocksize))
}

// parseDirExtents reads a format-2 (block/leaf) directory: the extent list
// locates the directory data blocks, each of which is parsed for entries.
// Index blocks (leaf/free, and node blocks for node-format dirs) live at
// logical offsets at or beyond the data boundary and are skipped.
func (xfs *XFS) parseDirExtents(ino []byte, dirPath string) ([]filesystem.DirectoryEntry, error) {
	limit, err := xfs.dataForkLimit(ino)
	if err != nil {
		return nil, err
	}
	fork := ino[xfsInodeDataForkOffset:limit]
	nextents := binary.BigEndian.Uint32(ino[xfsInodeNextentsOffset : xfsInodeNextentsOffset+4])
	exts, err := parseExtents(fork, nextents)
	if err != nil {
		return nil, err
	}
	boundary := xfs.dirDataBoundary()
	var entries []filesystem.DirectoryEntry
	for _, ext := range exts {
		for b := uint64(0); b < ext.blockCount; b++ {
			// A leaf-format directory maps data blocks at logical offsets below
			// the data region and its leaf block(s) at or above it; skipping
			// index blocks by logical offset is correct even when an index
			// block's magic is zeroed on disk (entries never live there).
			if ext.startoff+b >= boundary {
				continue
			}
			block, err := xfs.readBlock(xfs.fsbToFsb(ext.startBlock + b))
			if err != nil {
				return nil, err
			}
			got, err := xfs.parseDirDataBlock(block, dirPath)
			if err != nil {
				return nil, err
			}
			entries = append(entries, got...)
		}
	}
	if entries == nil {
		return []filesystem.DirectoryEntry{}, nil
	}
	return entries, nil
}

// parseDirDataBlock parses one dir3 data block ("XDB3"). The on-disk entry
// layout is inode-first — the reverse of the shortform layout:
//
//	inode(8) namelen(1) name(n) ftype(1) ...pad... tag(2)
//
// where each entry occupies an 8-byte-aligned slot of align8(12+n) bytes (11+n
// without the ftype feature) and the big-endian tag — the entry's byte offset
// in the block — sits at the slot's last 2 bytes. Free/unused regions begin
// with the 0xffff freetag and carry their length at off+2 (big-endian); used
// entries continue after them, so the walk skips free space rather than
// stopping. The walk is bounds-checked and stops cleanly at the first entry
// that fails structural validation (zero namelen, an inode number outside the
// filesystem's inode space, a mismatched slot tag, or the block's leaf/tail
// area).
func (xfs *XFS) parseDirDataBlock(block []byte, dirPath string) ([]filesystem.DirectoryEntry, error) {
	if len(block) < 0x40 {
		return nil, fmt.Errorf("XFS: dir data block too small")
	}
	magic := string(block[0:4])
	if magic != xfsDirDataMagic && magic != xfsDirDataMagic2 {
		return nil, fmt.Errorf("XFS: invalid dir data block magic %q", magic)
	}
	var entries []filesystem.DirectoryEntry
	// The dir3 data block header is 64 bytes (magic, crc, blkno, lsn, uuid,
	// owner, ...); the first entry follows it.
	off := 0x40
	// The block tail differs by magic: a dir3 CRC block ("XDB3") carries an
	// 8-byte xfs_dir3_data_tail (bestcount + padding); the dir2-style "XDD3"
	// block has no tail, so its entries may legitimately extend to the very
	// end of the block. Confirmed on server.E01/服务器检材一.E01: grub2/i386-pc's
	// first data block is exactly full — its last entry ends at the block
	// boundary, and a reserve would drop it. We never parse the real
	// dir2/dir3 leaf tail (XFS_DIR2_LEAF_BESTS); the walk terminates
	// independently via the per-entry tag check, so the reserve only needs to
	// keep the walk out of the tail.
	tail := 8
	if magic == xfsDirDataMagic2 {
		tail = 0
	}
	limit := len(block) - tail
	if limit < off {
		limit = off
	}
	// An inode number must resolve to an allocation group inside the
	// filesystem (agno = ino >> (agblklog + inopblog)). Numbers that don't are
	// leftover bytes — a free region or the leaf area — masquerading as an
	// entry.
	inoShift := xfs.agblklog + uint(xfs.inopblog)
	for off+10 <= limit {
		// A free/unused region begins with the 0xffff freetag. Its header
		// stores the region length at off+2 (big-endian); skip the whole
		// region, since used entries continue after it.
		if block[off] == 0xff && block[off+1] == 0xff {
			length := int(binary.BigEndian.Uint16(block[off+2 : off+4]))
			if length < 8 || off+length > limit {
				break
			}
			off += length
			continue
		}
		inumber := binary.BigEndian.Uint64(block[off : off+8])
		namelen := int(block[off+8])
		if namelen == 0 {
			break
		}
		if inumber == 0 || xfs.agcount == 0 || inumber>>inoShift >= uint64(xfs.agcount) {
			break
		}
		nameOff := off + 9
		if nameOff+namelen > limit {
			break
		}
		name := string(block[nameOff : nameOff+namelen])
		if !validDirName(name) {
			return nil, fmt.Errorf("XFS: dir data block has invalid name")
		}
		ftypeOff := nameOff + namelen
		isDir := false
		if xfs.ftype && ftypeOff < limit {
			isDir = block[ftypeOff] == xfsDir3FTDir
		}
		childSize := uint64(0)
		if !isDir {
			childSize = xfs.childInodeSize(inumber)
		}
		// Slot size: 11 fixed bytes without ftype (inode, namelen, name,
		// tag), 12 with ftype, rounded up to an 8-byte alignment.
		slot := (namelen + 11 + 7) &^ 7
		if xfs.ftype {
			slot = (namelen + 12 + 7) &^ 7
		}
		if slot < 16 {
			return nil, fmt.Errorf("XFS: dir data block entry %q has undersized slot %d", name, slot)
		}
		if off+slot > limit {
			break
		}
		// Every used entry ends with a big-endian tag equal to its own byte
		// offset in the block. A mismatch means this is not a used entry
		// (the block's leaf/tail area), so stop.
		if binary.BigEndian.Uint16(block[off+slot-2:off+slot]) != uint16(off) {
			break
		}
		entries = append(entries, filesystem.DirectoryEntry{
			Name:  name,
			Path:  filesystem.JoinPath(dirPath, name),
			IsDir: isDir,
			Size:  childSize,
			Inode: inumber,
		})
		off += slot
	}
	if entries == nil {
		return []filesystem.DirectoryEntry{}, nil
	}
	return entries, nil
}

// parseDirNode parses a format-3 (node) directory by walking the btree of
// "XDND" node blocks down to data blocks, which are parsed for entries.
func (xfs *XFS) parseDirNode(ino []byte, inoNum uint64, dirPath string) ([]filesystem.DirectoryEntry, error) {
	// A node-format directory's data fork holds a compact bmdr root, not an
	// extent list, so the extent list must come from the bmbt tree it points at.
	exts, err := xfs.readBtreeExtents(ino, inoNum)
	if err != nil {
		return nil, err
	}
	visited := make(map[uint64]struct{})
	boundary := xfs.dirDataBoundary()
	var entries []filesystem.DirectoryEntry
	for _, ext := range exts {
		for b := uint64(0); b < ext.blockCount; b++ {
			fsb := xfs.fsbToFsb(ext.startBlock + b)
			if _, seen := visited[fsb]; seen {
				continue
			}
			visited[fsb] = struct{}{}
			// Interior node and leaf blocks live at logical offsets at or
			// beyond the data boundary (XFS_DIR2_NODE_OFFSET / LEAF_OFFSET,
			// both > XFS_DIR2_DATA_OFFSET = 1<<32 bytes) and hold no entries.
			// A data-region block must be a real data block; anything else is
			// corruption and is reported rather than skipped.
			if ext.startoff+b >= boundary {
				continue
			}
			block, err := xfs.readBlock(fsb)
			if err != nil {
				return nil, err
			}
			if len(block) < 4 {
				return nil, fmt.Errorf("XFS: dir node block %d too small", fsb)
			}
			got, err := xfs.parseDirDataBlock(block, dirPath)
			if err != nil {
				return nil, err
			}
			entries = append(entries, got...)
		}
	}
	if entries == nil {
		return []filesystem.DirectoryEntry{}, nil
	}
	return entries, nil
}

// validDirName rejects names that cannot be a real on-disk directory entry
// (embedded NUL, control bytes, or non-printable characters).
func validDirName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == 0 || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// splitXfsPath splits a path into components, dropping empty parts.
func splitXfsPath(path string) []string {
	parts := strings.Split(path, "/")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolvePath walks path from the root inode and returns the final inode's
// bytes. Symlinks are followed at every component; when followFinal is set they
// are followed at the final component too, so listing or searching through a
// symlink reaches its target. An empty path resolves to the root.
func (xfs *XFS) resolvePath(path string, followFinal bool) ([]byte, uint64, error) {
	return xfs.resolvePathFrom(xfs.rootIno, splitXfsPath(path), followFinal, make(map[uint64]struct{}))
}

// resolvePathNoFollow resolves path without following a symlink at the final
// component, so GetFile and GetFileByPath return the symlink itself rather than
// its target (GetFile then returns the target string, matching the ext4
// convention).
func (xfs *XFS) resolvePathNoFollow(path string) ([]byte, uint64, error) {
	return xfs.resolvePath(path, false)
}

// resolvePathFrom resolves comps starting from inoNum, following symlinks as
// described by resolvePath. seen holds every symlink inode dereferenced so far
// across the whole walk, bounding total symlink hops and breaking loops. A
// relative symlink target is resolved within the directory that contained the
// symlink, exactly like the kernel's path walk.
func (xfs *XFS) resolvePathFrom(inoNum uint64, comps []string, followFinal bool, seen map[uint64]struct{}) ([]byte, uint64, error) {
	inoData, err := xfs.readInode(inoNum)
	if err != nil {
		return nil, 0, err
	}
	for i, comp := range comps {
		var child uint64
		switch {
		case comp == ".":
			child = inoNum
		case comp == "..":
			child, err = xfs.parentInode(inoData, inoNum)
			if err != nil {
				return nil, 0, err
			}
		default:
			var entries []filesystem.DirectoryEntry
			entries, err = xfs.readDirectory(inoData, inoNum, "")
			if err != nil {
				return nil, 0, err
			}
			child, err = lookupDirEntry(entries, comp)
			if err != nil {
				return nil, 0, err
			}
		}
		parentNum := inoNum
		inoNum = child
		inoData, err = xfs.readInode(child)
		if err != nil {
			return nil, 0, err
		}
		last := i == len(comps)-1
		if isSymlinkInode(inoData) && (followFinal || !last) {
			if len(seen) >= xfsMaxSymlinkHops {
				return nil, 0, fmt.Errorf("XFS: too many symlinks resolving %q", comp)
			}
			if _, loop := seen[inoNum]; loop {
				return nil, 0, fmt.Errorf("XFS: symlink loop at %q", comp)
			}
			seen[inoNum] = struct{}{}
			target, err := xfs.symlinkTarget(inoData, inoNum)
			if err != nil {
				return nil, 0, err
			}
			targetComps := append(splitXfsPath(target), comps[i+1:]...)
			if strings.HasPrefix(target, "/") {
				return xfs.resolvePathFrom(xfs.rootIno, targetComps, followFinal, seen)
			}
			return xfs.resolvePathFrom(parentNum, targetComps, followFinal, seen)
		}
	}
	return inoData, inoNum, nil
}

// ListDirectory lists a directory path. "" and "/" both denote the root. Only
// names actually stored on disk are returned.
func (xfs *XFS) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	if xfs.readFunc == nil {
		return nil, fmt.Errorf("XFS: directory parsing requires a reader")
	}
	inoData, inoNum, err := xfs.resolvePath(path, true)
	if err != nil {
		return nil, err
	}
	dirPath := ""
	if path != "" && path != "/" {
		dirPath = "/" + strings.Trim(path, "/")
	}
	entries, err := xfs.readDirectory(inoData, inoNum, dirPath)
	if err != nil {
		return nil, fmt.Errorf("XFS: cannot list inode %d: %w", inoNum, err)
	}
	return filterDotEntries(entries), nil
}

// GetFile reads a file's contents by path. Missing files return an explicit
// error.
func (xfs *XFS) GetFile(path string) ([]byte, error) {
	if xfs.readFunc == nil {
		return nil, fmt.Errorf("XFS: file reading requires a reader")
	}
	inoData, inoNum, err := xfs.resolvePathNoFollow(path)
	if err != nil {
		return nil, err
	}
	if isDirectoryInode(inoData) {
		return nil, fmt.Errorf("XFS: %q is a directory", path)
	}
	if isSymlinkInode(inoData) {
		target, err := xfs.symlinkTarget(inoData, inoNum)
		if err != nil {
			return nil, err
		}
		return []byte(target), nil
	}
	size := binary.BigEndian.Uint64(inoData[xfsInodeSizeOffset : xfsInodeSizeOffset+8])
	return xfs.readFileData(inoData, inoNum, size)
}

// GetFileByPath returns metadata for a path, or an explicit error when the
// path does not exist.
func (xfs *XFS) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	if xfs.readFunc == nil {
		return nil, fmt.Errorf("XFS: file lookup requires a reader")
	}
	inoData, _, err := xfs.resolvePathNoFollow(path)
	if err != nil {
		return nil, err
	}
	mode := binary.BigEndian.Uint16(inoData[xfsInodeModeOffset : xfsInodeModeOffset+2])
	flags2 := binary.BigEndian.Uint64(inoData[xfsInodeFlags2Offset : xfsInodeFlags2Offset+8])
	fi := &filesystem.FileInfo{
		Name:    path[strings.LastIndex(path, "/")+1:],
		Path:    "/" + strings.Trim(path, "/"),
		Size:    binary.BigEndian.Uint64(inoData[xfsInodeSizeOffset : xfsInodeSizeOffset+8]),
		Mode:    filesystem.FileMode(mode & 0xf000),
		IsDir:   mode&0xf000 == 0x4000,
		ModTime: inodeTime(inoData, xfsInodeMtimeOffset, flags2),
	}
	return fi, nil
}

const (
	xfsMaxSearchDepth = 32
	xfsMaxSearchCount = 10000
)

// SearchFiles walks the directory tree under rootPath and returns every
// FileInfo for which predicate returns true.
func (xfs *XFS) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	if xfs.readFunc == nil {
		return nil, fmt.Errorf("XFS: search requires a reader")
	}
	_, startNum, err := xfs.resolvePath(rootPath, true)
	if err != nil {
		return nil, err
	}

	results := make([]filesystem.FileInfo, 0)
	visited := make(map[uint64]struct{})
	base := ""
	if rootPath != "" && rootPath != "/" {
		base = "/" + strings.Trim(rootPath, "/")
	}

	var walk func(inoNum uint64, dirPath string, depth int) error
	walk = func(inoNum uint64, dirPath string, depth int) error {
		if depth > xfsMaxSearchDepth {
			return nil
		}
		if _, seen := visited[inoNum]; seen {
			return nil
		}
		visited[inoNum] = struct{}{}
		inoData, err := xfs.readInode(inoNum)
		if err != nil {
			return nil
		}
		entries, err := xfs.readDirectory(inoData, inoNum, dirPath)
		if err != nil {
			return nil
		}
		seenNames := make(map[string]struct{})
		for _, e := range entries {
			if e.Name == "." || e.Name == ".." {
				continue
			}
			if _, dup := seenNames[e.Name]; dup {
				continue
			}
			seenNames[e.Name] = struct{}{}
			if len(results) >= xfsMaxSearchCount {
				return fmt.Errorf("XFS: search exceeded %d results", xfsMaxSearchCount)
			}
			fi := filesystem.FileInfo{
				Name:  e.Name,
				Path:  filesystem.JoinPath(dirPath, e.Name),
				Mode:  filesystem.ModeRegular,
				IsDir: e.IsDir,
			}
			if e.IsDir {
				fi.Mode = filesystem.ModeDir
			}
			if predicate(fi) {
				results = append(results, fi)
			}
			if e.IsDir && depth < xfsMaxSearchDepth {
				if err := walk(e.Inode, fi.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(startNum, base, 0); err != nil {
		return nil, err
	}
	return results, nil
}
