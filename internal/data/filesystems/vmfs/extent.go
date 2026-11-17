package vmfs

// A file descriptor's 256 block addresses describe one of:
//
//   - a direct map (zla = 1, FB): each entry is a 1 MiB file-block id;
//   - a single-indirect map (zla = 3, PB): each entry names a 64 KiB pointer
//     block in the pointer-block bitmap (".pbc.sf"), and that block holds 1024
//     32-bit file-block ids.
//
// Block ids carry their type in the low three bits; the physical 1 MiB block is
// id >> 3. A pointer block id packs its bitmap entry in bits 6..27 and its item
// in bits 28..31; the bitmap header in ".pbc.sf" turns that pair into a byte
// offset.
//
// A double-indirect map (zla = 6, PB2) and sub-block data (SB) are refused by
// name, as is the VMFS5 extended zero-level address space (values at or above
// 4301). A zero block id or an out-of-range block is refused, never
// zero-filled: a hole this reader cannot prove is empty is an error, not a run
// of zeros.
const (
	// pointerBlockItems is the number of file-block addresses in one pointer
	// block.
	pointerBlockItems uint64 = 1024
	// descriptorItems is the number of block addresses in one descriptor.
	descriptorItems uint64 = 256
	// maxFileBlocks is the number of file blocks one descriptor's map may name.
	maxFileBlocks uint64 = descriptorItems * pointerBlockItems
	// zlaExtensionBase is the first zero-level address value used by the VMFS5
	// extension encoding.
	zlaExtensionBase uint32 = 4301
)

// extent is one logical-to-physical block run, in bytes.
type extent struct {
	logical  uint64
	physical uint64
	len      uint64
}

// extentMap is a resolved block map.
type extentMap struct {
	extents []extent
	// pointerBlocks is the number of pointer blocks read to build the map.
	pointerBlocks uint64
	// pointerRecords is the number of file-block addresses examined.
	pointerRecords uint64
}

// resolveExtents resolves a file descriptor's block map.
func resolveExtents(sb *superblock, in *inode, pbc *pbc) (*extentMap, error) {
	if in.blockCount == 0 {
		return &extentMap{}, nil
	}
	if in.blockCount > maxFileBlocks {
		return nil, unsupportedf("file descriptor 0x%08x names %d file blocks, more than the %d a descriptor's map can address",
			in.blockID, in.blockCount, maxFileBlocks)
	}
	if in.zla >= zlaExtensionBase {
		return nil, unsupportedf("file descriptor 0x%08x at byte 0x%x uses VMFS5 extended zero-level address type %d (base %d); extended addressing is not decoded",
			in.blockID, in.at, in.zla, zlaExtensionBase)
	}
	switch in.zla {
	case blkTypeFB:
		return resolveDirect(sb, in)
	case blkTypePB:
		return resolveIndirect(sb, in, pbc)
	case blkTypeSB:
		return nil, unsupportedf("file descriptor 0x%08x at byte 0x%x stores its data in sub-blocks (zero-level address type 2); sub-block addressing is not decoded",
			in.blockID, in.at)
	case blkTypePB2:
		return nil, unsupportedf("file descriptor 0x%08x at byte 0x%x uses a double-indirect map (zero-level address type 6); double-indirect addressing is not decoded",
			in.blockID, in.at)
	default:
		return nil, unsupportedf("file descriptor 0x%08x at byte 0x%x has zero-level address type %d, which this reader does not decode",
			in.blockID, in.at, in.zla)
	}
}

func validateFileBlock(sb *superblock, id uint64, what string) (uint64, error) {
	if id > uint64(^uint32(0)) {
		return 0, corruptf("%s has block id 0x%x, which does not fit the 32-bit VMFS5/VMFS6 encoding", what, id)
	}
	kind := blockType(uint32(id))
	if kind != blkTypeFB {
		switch kind {
		case blkTypeSB:
			return 0, unsupportedf("%s names a sub-block (type 2); sub-block addressing is not decoded", what)
		case blkTypePB2:
			return 0, unsupportedf("%s names a double-indirect pointer block (type 6); double-indirect addressing is not decoded", what)
		default:
			return 0, corruptf("%s names block id 0x%08x of type %d, not a file block (type 1)", what, uint32(id), kind)
		}
	}
	return sb.validateBlock(blockNumber(uint32(id)), what)
}

func resolveDirect(sb *superblock, in *inode) (*extentMap, error) {
	if in.blockCount > descriptorItems {
		return nil, corruptf("file descriptor 0x%08x is direct but names %d blocks, more than the %d descriptor entries",
			in.blockID, in.blockCount, descriptorItems)
	}
	extents := make([]extent, 0, int(in.blockCount))
	for index := uint64(0); index < in.blockCount; index++ {
		id := in.blocks[index]
		if id == 0 {
			return nil, corruptf("file descriptor 0x%08x at byte 0x%x: direct block address %d is zero; a hole is refused rather than zero-filled",
				in.blockID, in.at, index)
		}
		what := "file descriptor 0x" + hex32(in.blockID) + "'s direct block address " + utoa(index)
		physicalBlock, err := validateFileBlock(sb, id, what)
		if err != nil {
			return nil, err
		}
		logical, ok := mulChecked(index, in.blockSize)
		if !ok {
			return nil, corruptf("a logical extent overflows")
		}
		physical, ok := mulChecked(physicalBlock, in.blockSize)
		if !ok {
			return nil, corruptf("a physical extent overflows")
		}
		extents = append(extents, extent{logical: logical, physical: physical, len: in.blockSize})
	}
	return &extentMap{extents: extents}, nil
}

func resolveIndirect(sb *superblock, in *inode, pbc *pbc) (*extentMap, error) {
	needed := (in.blockCount + pointerBlockItems - 1) / pointerBlockItems
	if needed > descriptorItems {
		return nil, corruptf("file descriptor 0x%08x needs %d pointer blocks, more than the %d descriptor entries",
			in.blockID, needed, descriptorItems)
	}
	if pbc == nil {
		return nil, unsupportedf("file descriptor 0x%08x at byte 0x%x uses a single-indirect map, but the pointer-block cache (\".pbc.sf\") could not be opened, so its pointer blocks cannot be located",
			in.blockID, in.at)
	}
	extents := make([]extent, 0, int(in.blockCount))
	remaining := in.blockCount
	var pointerBlocks, pointerRecords uint64
	for index := uint64(0); index < needed; index++ {
		pbID64 := in.blocks[index]
		if pbID64 == 0 {
			return nil, corruptf("file descriptor 0x%08x: pointer-block address %d is zero; a hole is refused rather than zero-filled",
				in.blockID, index)
		}
		if pbID64 > uint64(^uint32(0)) {
			return nil, corruptf("file descriptor 0x%08x: pointer block id 0x%x does not fit 32 bits", in.blockID, pbID64)
		}
		pbID := uint32(pbID64)
		switch blockType(pbID) {
		case blkTypePB:
		case blkTypePB2:
			return nil, unsupportedf("file descriptor 0x%08x at byte 0x%x: pointer-block address %d names a double-indirect pointer block (type 6); double-indirect addressing is not decoded",
				in.blockID, in.at, index)
		case blkTypeSB:
			return nil, unsupportedf("file descriptor 0x%08x at byte 0x%x: pointer-block address %d names a sub-block (type 2); sub-block addressing is not decoded",
				in.blockID, in.at, index)
		default:
			return nil, corruptf("file descriptor 0x%08x: pointer-block address %d has block id 0x%08x of type %d, not a pointer block (type 3)",
				in.blockID, index, pbID, blockType(pbID))
		}
		bytes, err := pbc.readPointerBlock(pbID, in.blockID)
		if err != nil {
			return nil, err
		}
		pointerBlocks++
		take := remaining
		if take > pointerBlockItems {
			take = pointerBlockItems
		}
		for within := uint64(0); within < take; within++ {
			at := within * 4
			child := uint64(le32(bytes, int(at)))
			if child == 0 {
				return nil, corruptf("file descriptor 0x%08x: pointer block 0x%08x entry %d is zero; a hole is refused rather than zero-filled",
					in.blockID, pbID, within)
			}
			what := "file descriptor 0x" + hex32(in.blockID) + "'s pointer block 0x" + hex32(pbID) + " entry " + utoa(within)
			physicalBlock, err := validateFileBlock(sb, child, what)
			if err != nil {
				return nil, err
			}
			ordinal, ok := mulChecked(index, pointerBlockItems)
			if !ok {
				return nil, corruptf("a file-block ordinal overflows")
			}
			ordinal, ok = addChecked(ordinal, within)
			if !ok {
				return nil, corruptf("a file-block ordinal overflows")
			}
			logical, ok := mulChecked(ordinal, in.blockSize)
			if !ok {
				return nil, corruptf("a logical extent overflows")
			}
			physical, ok := mulChecked(physicalBlock, in.blockSize)
			if !ok {
				return nil, corruptf("a physical extent overflows")
			}
			extents = append(extents, extent{logical: logical, physical: physical, len: in.blockSize})
			pointerRecords++
		}
		remaining -= take
	}
	if remaining != 0 {
		return nil, corruptf("file descriptor 0x%08x's map covers %d of its %d blocks",
			in.blockID, in.blockCount-remaining, in.blockCount)
	}
	return &extentMap{extents: extents, pointerBlocks: pointerBlocks, pointerRecords: pointerRecords}, nil
}
