package gfs2

import (
	"math"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxDataBlocks is the most data blocks one file or directory map may hold.
const MaxDataBlocks uint64 = 16_777_216

// BlockMap is one dinode's resolved pointer tree, in logical order.
type BlockMap struct {
	// Blocks are data blocks indexed from logical block zero.
	Blocks []uint64
	// MetadataBlocks counts indirect IN blocks read while resolving the map.
	MetadataBlocks uint64
	// Pointers counts pointer slots examined while resolving the map.
	Pointers uint64
}

// resolveMap resolves needed logical blocks of a dinode's data. A stuffed
// dinode has no block map and must not be passed here.
func resolveMap(superblock *Superblock, src source.ByteSource, inode *Dinode, needed uint64) (*BlockMap, error) {
	if inode.Height == 0 {
		return nil, corruptf("dinode block %d is stuffed and has no block map", inode.Block)
	}
	if needed > MaxDataBlocks {
		return nil, unsupportedf("dinode block %d needs %d data blocks, more than the %d-block cap",
			inode.Block, needed, MaxDataBlocks)
	}
	m := &BlockMap{}
	if needed == 0 {
		return m, nil
	}

	dinode, err := blockBytes(superblock, src, inode.Block, "a dinode")
	if err != nil {
		return nil, err
	}
	top := readPointers(dinode, DinodeSize, superblock.DinodePointers())
	what := "dinode block " + u64(inode.Block)
	if err := collectMap(superblock, src, top, inode.Height, needed, 0, what, m); err != nil {
		return nil, err
	}
	if uint64(len(m.Blocks)) != needed {
		return nil, corruptf("%s: the pointer tree yielded %d data blocks, expected %d",
			what, len(m.Blocks), needed)
	}
	return m, nil
}

// readPointers decodes at most count big-endian pointers at raw[offset:].
// A count past the bytes present stops at the array's end.
func readPointers(raw []byte, offset int, count uint64) []uint64 {
	if offset < 0 || offset > len(raw) {
		return nil
	}
	available := uint64((len(raw) - offset) / 8)
	if count > available {
		count = available
	}
	out := make([]uint64, int(count))
	for index := range out {
		out[index] = be64(raw, offset+index*8)
	}
	return out
}

func collectMap(superblock *Superblock, src source.ByteSource, entries []uint64, level uint16,
	needed, logicalStart uint64, what string, m *BlockMap) error {
	if needed == 0 {
		return nil
	}
	if level == 0 {
		return corruptf("%s: the pointer tree ended before logical block %d", what, logicalStart)
	}
	if level == 1 {
		take := needed
		if take > uint64(len(entries)) {
			take = uint64(len(entries))
		}
		for index := uint64(0); index < take; index++ {
			m.Pointers++
			logical := logicalStart + index
			pointer := entries[index]
			if pointer == 0 {
				return corruptf("%s: logical data block %d is a hole (zero pointer); holes are refused, not zero-filled",
					what, logical)
			}
			if err := superblock.ValidateBlock(pointer,
				what+": logical data block "+u64(logical)); err != nil {
				return err
			}
			m.Blocks = append(m.Blocks, pointer)
		}
		if take < needed {
			return corruptf("%s: the pointer array holds %d of the %d data blocks the file reaches",
				what, take, needed)
		}
		return nil
	}

	per := saturatingPow(superblock.IndirectPointers(), uint64(level-1))
	remaining := needed
	index := uint64(0)
	for _, pointer := range entries {
		if remaining == 0 {
			break
		}
		m.Pointers++
		logical := logicalStart + index
		if pointer == 0 {
			return corruptf("%s: the subtree for logical data block %d is a hole (zero pointer); holes are refused, not zero-filled",
				what, logical)
		}
		if err := superblock.ValidateBlock(pointer,
			what+": an indirect block for logical data block "+u64(logical)); err != nil {
			return err
		}
		block, err := blockBytes(superblock, src, pointer, what+": indirect block")
		if err != nil {
			return err
		}
		if err := validateMeta(block, MetaIN, FormatIN,
			what+": indirect block "+u64(pointer)); err != nil {
			return err
		}
		m.MetadataBlocks++
		child := readPointers(block, MetaHeaderSize, superblock.IndirectPointers())
		take := remaining
		if take > per {
			take = per
		}
		if err := collectMap(superblock, src, child, level-1, take, logical, what, m); err != nil {
			return err
		}
		remaining -= take
		if index > math.MaxUint64-per {
			index = math.MaxUint64
		} else {
			index += per
		}
	}
	if remaining > 0 {
		return corruptf("%s: the pointer tree ends before logical data block %d",
			what, logicalStart+index)
	}
	return nil
}

func saturatingPow(base, exponent uint64) uint64 {
	if base == 0 {
		return 0
	}
	result := uint64(1)
	for index := uint64(0); index < exponent; index++ {
		if result > math.MaxUint64/base {
			return math.MaxUint64
		}
		result *= base
	}
	return result
}
