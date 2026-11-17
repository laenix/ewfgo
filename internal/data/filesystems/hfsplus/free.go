package hfsplus

// Free allocation blocks, read from the allocation file (CNID 6).
//
// The file's data fork holds one bit per allocation block, most significant
// bit first: bit 0 of byte 0 is the high bit and stands for block 0.  A set
// bit means the block is in use.  The volume header's freeBlocks count is
// reported separately and is not merged with the bitmap: on a volume that was
// not cleanly unmounted the two can disagree, and only the bitmap says which
// blocks no file owns.
//
// A missing, short, or insufficiently covered allocation file is refused
// rather than treated as "everything free".

// FreeSpace is the allocation file's bitmap.
type FreeSpace struct {
	blocks    uint64
	blockSize uint64
	bitmap    []byte
}

// IsBlockFree reports whether one allocation block is free.
func (f *FreeSpace) IsBlockFree(block uint32) bool {
	if uint64(block) >= f.blocks {
		return false
	}
	return f.bitmap[block/8]&(0x80>>(block%8)) == 0
}

// IsFree reports whether every block covering [offset, offset+length) is free.
// Out-of-range ranges are not free.
func (f *FreeSpace) IsFree(offset, length uint64) bool {
	if f.blockSize == 0 {
		return false
	}
	if length == 0 {
		return true
	}
	end := offset + length
	if end < offset {
		return false
	}
	first := offset / f.blockSize
	last := (end + f.blockSize - 1) / f.blockSize
	for block := first; block < last; block++ {
		if block >= f.blocks {
			return false
		}
		if f.bitmap[block/8]&(0x80>>(block%8)) != 0 {
			return false
		}
	}
	return true
}

// Blocks returns the number of blocks the bitmap describes.
func (f *FreeSpace) Blocks() uint64 { return f.blocks }

// FreeSpace reads and validates the allocation file's bitmap.
func (v *Volume) FreeSpace() (*FreeSpace, error) {
	header := v.header
	blockSize := uint64(header.BlockSize)
	if blockSize == 0 {
		return nil, invalidf("the volume header declares a zero block size")
	}
	blocks := uint64(header.TotalBlocks)
	if blocks == 0 {
		return nil, invalidf("the volume header declares no allocation blocks")
	}
	volumeLen := v.src.Len()
	var covered uint64
	if blocks > ^uint64(0)/blockSize {
		covered = volumeLen
	} else {
		covered = blocks * blockSize
		if covered > volumeLen {
			covered = volumeLen
		}
	}
	bits := blocks
	if covered/blockSize < bits {
		bits = covered / blockSize
	}
	if bits == 0 {
		return nil, invalidf("the volume declares %d blocks of %d bytes but only %d bytes are readable",
			blocks, blockSize, volumeLen)
	}
	needed := (bits + 7) / 8
	fork := header.AllocationFile
	if fork.LogicalSize < needed {
		return nil, invalidf("the allocation file declares %d bytes for %d blocks; %d are needed",
			fork.LogicalSize, bits, needed)
	}
	extents, err := resolveFork(v.src, v.extents, header.BlockSize, ForkData, AllocationFileID, fork)
	if err != nil {
		return nil, err
	}
	held := extents.CoveredBytes(header.BlockSize)
	if held < needed {
		return nil, invalidf("the allocation file's extents cover %d bytes; %d are needed for %d blocks",
			held, needed, bits)
	}
	bitmap := make([]byte, int(needed))
	if err := extents.ReadExact(v.src, header.BlockSize, 0, bitmap); err != nil {
		return nil, err
	}
	return &FreeSpace{blocks: bits, blockSize: blockSize, bitmap: bitmap}, nil
}
