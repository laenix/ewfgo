package ufs

import "github.com/laenix/ewfgo/internal/data/source"

// Block-map bounds. A corrupt tree that points at itself stops at these.
const (
	// MaxIndirectBlocks is the indirect blocks one map may read.
	MaxIndirectBlocks uint64 = 4_000_000
	// MaxBlocks is the block pointers one map may hold.
	MaxBlocks = 8_000_000
)

// BlockEntry is one logical block and the fragment that holds it.
type BlockEntry struct {
	LogicalBlock uint64
	Fragment     uint64
}

// BlockMap is everything a block-map walk named: the data blocks a file maps
// and the indirect blocks walked to reach them.
//
// Indirect fragments are kept apart because they are metadata: deleted-content
// recovery must check that they are still free too, since a reused indirect
// block holds another file's pointers.
type BlockMap struct {
	// Blocks holds data blocks in logical order.
	Blocks []BlockEntry
	// Indirect holds single, double and triple indirect fragments in walk
	// order.
	Indirect []uint64
}

// ReadBlockMap resolves every block a file's inode names, in logical order.
func ReadBlockMap(src source.ByteSource, sb *Superblock, inode *Inode) ([]BlockEntry, error) {
	all, err := ReadBlockMapAll(src, sb, inode)
	if err != nil {
		return nil, err
	}
	return all.Blocks, nil
}

// ReadBlockMapAll resolves a file's data blocks together with the indirect
// blocks that hold their pointers.
func ReadBlockMapAll(src source.ByteSource, sb *Superblock, inode *Inode) (*BlockMap, error) {
	blockSize := sb.BlockSize()
	blocks := inode.Size / blockSize
	if inode.Size%blockSize != 0 {
		blocks++
	}
	mapData := &BlockMap{}
	if blocks == 0 {
		return mapData, nil
	}
	budget := &walkBudget{}
	for index := 0; index < len(inode.DB); index++ {
		if uint64(index) >= blocks {
			break
		}
		if inode.DB[index] != 0 {
			if err := pushBlock(mapData, uint64(index), inode.DB[index]); err != nil {
				return nil, err
			}
		}
	}
	nindir := sb.PointersPerBlock()
	base := uint64(UFSNDirect)
	covers := nindir
	for level := 0; level < UFSNIndirect; level++ {
		if base >= blocks {
			break
		}
		pointer := inode.IB[level]
		if pointer != 0 {
			if err := walkIndirect(src, sb, pointer, level+1, base, blocks, mapData, budget); err != nil {
				return nil, err
			}
		}
		base = satAdd(base, covers)
		covers = satMul(covers, nindir)
	}
	return mapData, nil
}

type walkBudget struct {
	indirectBlocks uint64
}

func pushBlock(out *BlockMap, logicalBlock uint64, fragment int64) error {
	if len(out.Blocks) >= MaxBlocks {
		return corruptf("the file names more than %d blocks", MaxBlocks)
	}
	if fragment < 0 {
		return corruptf("logical block %d points at the negative fragment %d", logicalBlock, fragment)
	}
	out.Blocks = append(out.Blocks, BlockEntry{LogicalBlock: logicalBlock, Fragment: uint64(fragment)})
	return nil
}

func walkIndirect(src source.ByteSource, sb *Superblock, fragment int64, depth int, base, blocks uint64, out *BlockMap, budget *walkBudget) error {
	if depth == 0 || depth > UFSNIndirect {
		return corruptf("indirect depth %d is past three", depth)
	}
	if fragment < 0 {
		return corruptf("an indirect pointer at depth %d is negative: %d", depth, fragment)
	}
	budget.indirectBlocks++
	if budget.indirectBlocks > MaxIndirectBlocks {
		return corruptf("the file names more than %d indirect blocks", MaxIndirectBlocks)
	}
	offset, err := sb.FragmentOffset(uint64(fragment))
	if err != nil {
		return err
	}
	out.Indirect = append(out.Indirect, uint64(fragment))
	blockSize := int(sb.BlockSize())
	raw := make([]byte, blockSize)
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return err
	}
	pointerSize := sb.Version.PointerSize()
	nindir := int(sb.PointersPerBlock())
	stride := uint64(1)
	if depth > 1 {
		stride = satPow(sb.PointersPerBlock(), uint32(depth-1))
	}
	for index := 0; index < nindir; index++ {
		logical := satAdd(base, satMul(uint64(index), stride))
		if logical >= blocks {
			break
		}
		entry := readPointer(sb.Endian, sb.Version, raw, index*pointerSize)
		if entry == 0 {
			continue
		}
		if depth == 1 {
			if err := pushBlock(out, logical, entry); err != nil {
				return err
			}
			continue
		}
		if err := walkIndirect(src, sb, entry, depth-1, logical, blocks, out, budget); err != nil {
			return err
		}
	}
	return nil
}

func readPointer(endian Endian, version Version, raw []byte, at int) int64 {
	if version == UFS1 {
		return int64(endian.I32(raw, at))
	}
	return endian.I64(raw, at)
}

func satAdd(left, right uint64) uint64 {
	if left > ^uint64(0)-right {
		return ^uint64(0)
	}
	return left + right
}

func satMul(left, right uint64) uint64 {
	if left == 0 || right == 0 {
		return 0
	}
	if left > ^uint64(0)/right {
		return ^uint64(0)
	}
	return left * right
}

func satPow(base uint64, exponent uint32) uint64 {
	result := uint64(1)
	for index := uint32(0); index < exponent; index++ {
		result = satMul(result, base)
	}
	return result
}
