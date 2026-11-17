package qnx6

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Unused is the format's unused-pointer value. Zero is a valid block, so this
// is the only hole marker.
const Unused uint32 = ^uint32(0)

// MaxDataBlocks is the most data blocks one file or directory stream may map.
const MaxDataBlocks uint64 = 16_777_216

// BlockMap is a resolved block map in logical order.
type BlockMap struct {
	// Blocks are data blocks, indexed from logical block zero.
	Blocks []uint64
	// MetadataBlocks counts pointer blocks read while resolving the map.
	MetadataBlocks uint64
	// Pointers counts pointer slots examined while resolving the map.
	Pointers uint64
}

// Mapper is a caching pointer-tree walker. One walker can map an inode's
// stream, a directory's stream and the Longfile stream; a pointer block is
// read at most once per walker.
type Mapper struct {
	superblock *Superblock
	source     source.ByteSource
	cache      map[uint64][]uint32

	// MetadataBlocks counts pointer blocks read.
	MetadataBlocks uint64
	// Pointers counts pointer slots examined.
	Pointers uint64
}

// NewMapper returns a walker over src.
func NewMapper(superblock *Superblock, src source.ByteSource) *Mapper {
	return &Mapper{
		superblock: superblock,
		source:     src,
		cache:      make(map[uint64][]uint32),
	}
}

func (m *Mapper) readPointerBlock(block uint64, what string) ([]uint32, error) {
	if words, ok := m.cache[block]; ok {
		return words, nil
	}
	offset, ok := m.superblock.BlockOffset(block)
	if !ok {
		return nil, corruptf("%s: pointer block %d overflows the byte address space", what, block)
	}
	size := int(m.superblock.BlockSize)
	bytes := make([]byte, size)
	if err := source.ReadExactAt(m.source, offset, bytes); err != nil {
		return nil, err
	}
	order := m.superblock.Order
	words := make([]uint32, size/4)
	for index := range words {
		words[index] = order.u32(bytes, index*4)
	}
	m.MetadataBlocks++
	m.cache[block] = words
	return words, nil
}

// Map maps one logical block of a stream described by ptrs and levels. The
// returned number is filesystem-relative.
func (m *Mapper) Map(ptrs [16]uint32, levels uint8, no uint64, what string) (uint64, error) {
	if levels > MaxPtrLevels {
		return 0, unsupportedf("%s: pointer depth %d, more than the %d-level cap",
			what, levels, MaxPtrLevels)
	}
	ptrbits := m.superblock.PtrBits()
	mask := (uint64(1) << ptrbits) - 1
	bitdelta := ptrbits * uint32(levels)
	top := shiftRight(no, bitdelta)
	if top >= 16 {
		return 0, corruptf("%s: logical block %d needs top-level pointer %d, past the 16 pointers a depth-%d stream has",
			what, no, top, levels)
	}
	m.Pointers++
	ptr := ptrs[top]
	for depth := uint8(0); depth < levels; depth++ {
		if ptr == Unused {
			return 0, corruptf("%s: logical block %d is a hole (unused 0xffffffff pointer); holes are refused, not zero-filled",
				what, no)
		}
		block := uint64(ptr)
		if err := m.superblock.ValidateBlock(block, fmt.Sprintf("%s pointer for logical block %d", what, no)); err != nil {
			return 0, err
		}
		bitdelta -= ptrbits
		index := shiftRight(no, bitdelta) & mask
		words, err := m.readPointerBlock(block, what)
		if err != nil {
			return 0, err
		}
		if index >= uint64(len(words)) {
			return 0, corruptf("%s: pointer index %d is outside pointer block %d", what, index, block)
		}
		ptr = words[index]
		m.Pointers++
	}
	if ptr == Unused {
		return 0, corruptf("%s: logical block %d is a hole (unused 0xffffffff pointer); holes are refused, not zero-filled",
			what, no)
	}
	data := uint64(ptr)
	if err := m.superblock.ValidateBlock(data, fmt.Sprintf("%s data block for logical block %d", what, no)); err != nil {
		return 0, err
	}
	return data, nil
}

// shiftRight is value >> shift, with a shift of 64 or more yielding zero
// instead of panicking. QNX6 depths can make the nominal shift exceed 32.
func shiftRight(value uint64, shift uint32) uint64 {
	if shift >= 64 {
		return 0
	}
	return value >> shift
}

// Resolve resolves needed logical blocks of a stream.
func Resolve(superblock *Superblock, src source.ByteSource, ptrs [16]uint32, levels uint8,
	needed uint64, what string) (*BlockMap, error) {
	if needed > MaxDataBlocks {
		return nil, unsupportedf("%s needs %d data blocks, more than the %d-block cap",
			what, needed, MaxDataBlocks)
	}
	mapper := NewMapper(superblock, src)
	blocks := make([]uint64, 0, int(needed))
	for no := uint64(0); no < needed; no++ {
		block, err := mapper.Map(ptrs, levels, no, what)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	return &BlockMap{
		Blocks:         blocks,
		MetadataBlocks: mapper.MetadataBlocks,
		Pointers:       mapper.Pointers,
	}, nil
}
