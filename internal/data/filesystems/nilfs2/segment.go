package nilfs2

import (
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// The last partial segment begins with a segment summary; when it ends a
// checkpoint its last block holds a super root carrying the four metadata
// inodes (DAT, cpfile, sufile, ifile). Only the newest checkpoint is read;
// older checkpoints are not replayed.

const (
	// SummaryMagic is NILFS_SEGMENT_SUMMARY_MAGIC.
	SummaryMagic uint32 = 0x5345_4753
	// SummaryHeaderSize is the fixed segment-summary header.
	SummaryHeaderSize = 64

	// Segment summary flag bits.
	FlagLogBegin  uint16 = 0x0001
	FlagLogEnd    uint16 = 0x0002
	FlagSuperRoot uint16 = 0x0004
	FlagSyncDAT   uint16 = 0x0008
	FlagGC        uint16 = 0x0010

	knownSummaryFlags = FlagLogBegin | FlagLogEnd | FlagSuperRoot | FlagSyncDAT | FlagGC

	// SuperRootBytes is the fixed super-root size: header plus four inodes.
	SuperRootBytes = 0x210
	// SuperRootInodeOffset is the offset of the first inode in a super root.
	SuperRootInodeOffset = 0x10
	// SuperRootInodes is the number of metadata inodes a super root holds.
	SuperRootInodes = 4
)

// Summary is a parsed segment summary.
type Summary struct {
	Block          uint64
	Magic          uint32
	Bytes          uint16
	Flags          uint16
	Seq            uint64
	Create         *int64
	NBlocks        uint32
	NFinfo         uint32
	SumBytes       uint32
	CNO            uint64
	ChecksumBytes  int
	SuperRootBlock uint64
}

// HasSuperRoot reports whether the segment ends a checkpoint.
func (s *Summary) HasSuperRoot() bool { return s.Flags&FlagSuperRoot != 0 }

// SuperRoot is the four metadata inodes of the newest checkpoint.
type SuperRoot struct {
	Block      uint64
	Bytes      uint16
	Flags      uint16
	NongcCtime *int64
	Dat        *Inode
	Cpfile     *Inode
	Sufile     *Inode
	Ifile      *Inode
}

func readSegmentBlock(src source.ByteSource, superblock *Superblock, block uint64) ([]byte, error) {
	if _, err := superblock.ValidateBlock(block, "a segment block"); err != nil {
		return nil, err
	}
	offset, ok := superblock.BlockOffset(block)
	if !ok {
		return nil, corruptf("segment block %d overflows the address space", block)
	}
	bytes := make([]byte, int(superblock.BlockSize))
	if err := source.ReadExactAt(src, offset, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// ReadSummary reads and validates the segment summary named by the superblock.
func ReadSummary(src source.ByteSource, superblock *Superblock) (*Summary, error) {
	block := superblock.LastPseg
	if block == 0 {
		return nil, unsupportedf("the superblock names no partial segment (s_last_pseg is 0); there is no checkpoint to locate the super root from")
	}
	bytes, err := readSegmentBlock(src, superblock, block)
	if err != nil {
		return nil, err
	}
	blockSize := len(bytes)
	if blockSize < SummaryHeaderSize {
		return nil, corruptf("the segment summary block %d is %d bytes, shorter than the %d-byte header",
			block, blockSize, SummaryHeaderSize)
	}
	magic := le32(bytes, 0x00)
	if magic != SummaryMagic {
		return nil, corruptf("the segment summary at block %d has magic 0x%08x, not the NILFS2 summary magic 0x%08x",
			block, magic, SummaryMagic)
	}
	declared := int(le16(bytes, 0x04))
	if declared < SummaryHeaderSize || declared > blockSize {
		return nil, corruptf("the segment summary at block %d declares %d bytes, outside %d..=%d",
			block, declared, SummaryHeaderSize, blockSize)
	}
	flags := le16(bytes, 0x06)
	if unknown := flags &^ knownSummaryFlags; unknown != 0 {
		return nil, unsupportedf("the segment summary at block %d sets unknown flag bits 0x%04x", block, unknown)
	}
	nblocks := le32(bytes, 0x18)
	if nblocks == 0 {
		return nil, corruptf("the segment summary at block %d declares an empty partial segment", block)
	}
	end := block + uint64(nblocks)
	if end < block {
		return nil, corruptf("the partial segment's end overflows")
	}
	if _, err := superblock.ValidateBlock(end-1, "the partial segment's last block"); err != nil {
		return nil, err
	}
	segmentStart := (block / superblock.BlocksPerSegment) * superblock.BlocksPerSegment
	if block-segmentStart+uint64(nblocks) > superblock.BlocksPerSegment {
		return nil, corruptf("the partial segment at block %d runs %d blocks past the %d-block segment boundary",
			block, nblocks, superblock.BlocksPerSegment)
	}

	sumBytes := le32(bytes, 0x20)
	sumBytesInt := uint64(sumBytes)
	if sumBytesInt < uint64(declared) || sumBytesInt > uint64(blockSize) {
		return nil, corruptf("the segment summary at block %d declares %d total summary bytes, outside %d..=%d",
			block, sumBytes, declared, blockSize)
	}
	if flags&FlagSuperRoot == 0 {
		return nil, unsupportedf("the newest partial segment at block %d does not end a checkpoint (flags 0x%04x have no super root); this reader does not replay older checkpoints",
			block, flags)
	}
	if flags&FlagLogEnd == 0 {
		return nil, corruptf("the segment summary at block %d carries a super root without the log-end flag (flags 0x%04x)",
			block, flags)
	}

	storedSum := le32(bytes, 0x38)
	checksumBytes := -1
	for _, candidate := range []int{declared, int(sumBytes)} {
		hashed := append([]byte(nil), bytes[:candidate]...)
		clear(hashed[0x38:0x3c])
		if foundation.CRC32Seeded(superblock.CRCSeed, hashed) == storedSum {
			checksumBytes = candidate
			break
		}
	}
	if checksumBytes < 0 {
		hashed := append([]byte(nil), bytes[:declared]...)
		clear(hashed[0x38:0x3c])
		computed := foundation.CRC32Seeded(superblock.CRCSeed, hashed)
		return nil, corruptf("the segment summary at block %d checksum is 0x%08x; the %d-byte header computes 0x%08x",
			block, storedSum, declared, computed)
	}

	create, err := timestamp(le64(bytes, 0x10))
	if err != nil {
		return nil, err
	}
	return &Summary{
		Block:          block,
		Magic:          magic,
		Bytes:          le16(bytes, 0x04),
		Flags:          flags,
		Seq:            le64(bytes, 0x08),
		Create:         create,
		NBlocks:        nblocks,
		NFinfo:         le32(bytes, 0x1c),
		SumBytes:       sumBytes,
		CNO:            le64(bytes, 0x28),
		ChecksumBytes:  checksumBytes,
		SuperRootBlock: end - 1,
	}, nil
}

// ReadSuperRoot reads and validates the super-root block.
func ReadSuperRoot(src source.ByteSource, superblock *Superblock, block uint64) (*SuperRoot, error) {
	bytes, err := readSegmentBlock(src, superblock, block)
	if err != nil {
		return nil, err
	}
	declared := int(le16(bytes, 0x04))
	if declared < SuperRootBytes || declared > len(bytes) {
		return nil, corruptf("the super root at block %d declares %d bytes, outside %d..=%d",
			block, declared, SuperRootBytes, len(bytes))
	}
	storedSum := le32(bytes, 0x00)
	hashed := append([]byte(nil), bytes[:declared]...)
	clear(hashed[0x00:0x04])
	computed := foundation.CRC32Seeded(superblock.CRCSeed, hashed)
	if computed != storedSum {
		return nil, corruptf("the super root at block %d checksum is 0x%08x but the %d covered bytes compute 0x%08x",
			block, storedSum, declared, computed)
	}
	flags := le16(bytes, 0x06)
	if flags != 0 {
		return nil, unsupportedf("the super root at block %d sets flags 0x%04x; this reader knows no super-root flags",
			block, flags)
	}

	inodes := make([]*Inode, 0, SuperRootInodes)
	for index := 0; index < SuperRootInodes; index++ {
		start := SuperRootInodeOffset + index*InodeSize
		end := start + InodeSize
		if end > len(bytes) {
			return nil, corruptf("super-root inode %d at block %d is past the %d-byte block", index, block, len(bytes))
		}
		inode, err := ParseMetadataInode(bytes[start:end],
			"super-root inode "+u64Text(uint64(index))+" at block "+u64Text(block))
		if err != nil {
			return nil, err
		}
		inodes = append(inodes, inode)
	}
	nongc, err := timestamp(le64(bytes, 0x08))
	if err != nil {
		return nil, err
	}
	return &SuperRoot{
		Block:      block,
		Bytes:      le16(bytes, 0x04),
		Flags:      flags,
		NongcCtime: nongc,
		Dat:        inodes[0],
		Cpfile:     inodes[1],
		Sufile:     inodes[2],
		Ifile:      inodes[3],
	}, nil
}
