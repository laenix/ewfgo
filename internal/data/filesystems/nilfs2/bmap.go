package nilfs2

// The direct block map: seven pointers after a flags word. For user inodes the
// pointers are virtual block numbers translated through the DAT file; for
// metadata inodes they are physical. A pointer past the seventh slot needs the
// B-tree map, which this reader does not decode; a zero pointer is a hole.
// Both are refused by name.

// MaxDataBlocks bounds one file's or directory's data map.
const MaxDataBlocks uint64 = 16_777_216

// BlockMap is a resolved block map in logical order.
type BlockMap struct {
	Blocks []uint64
	// Pointers is the number of pointer slots examined.
	Pointers uint64
}

// ResolveDirect resolves needed logical blocks of an inode's data. translate
// converts a stored pointer to a physical block number: identity for metadata
// inodes, a DAT lookup for user inodes.
func ResolveDirect(superblock *Superblock, inode *Inode, needed uint64, what string,
	translate func(uint64) (uint64, error)) (*BlockMap, error) {
	if inode.IsLargeBmap() {
		return nil, unsupportedf("%s uses the NILFS2 B-tree block map; this reader decodes direct block maps only", what)
	}
	if needed > MaxDataBlocks {
		return nil, unsupportedf("%s needs %d data blocks, more than the %d-block cap", what, needed, MaxDataBlocks)
	}
	mapData := &BlockMap{}
	for logical := uint64(0); logical < needed; logical++ {
		if logical >= DirectPointers {
			return nil, unsupportedf("%s: logical data block %d is past the %d direct pointers; the B-tree block map is not decoded",
				what, logical, DirectPointers)
		}
		pointer := inode.Bmap[logical]
		mapData.Pointers++
		if pointer == 0 {
			return nil, corruptf("%s: logical data block %d is a hole (zero pointer); holes are refused, not zero-filled",
				what, logical)
		}
		physical, err := translate(pointer)
		if err != nil {
			return nil, err
		}
		if _, err := superblock.ValidateBlock(physical,
			what+" logical data block"); err != nil {
			return nil, err
		}
		mapData.Blocks = append(mapData.Blocks, physical)
	}
	return mapData, nil
}
