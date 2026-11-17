package udf

// Free blocks, read from the partition's unallocated space bitmap.
//
// A UDF partition descriptor carries a partition header descriptor naming an
// unallocated space bitmap by short allocation descriptor. The bitmap is a
// space bitmap descriptor (tag 0x0108) followed by one bit per logical block.
//
// Two details decide the answer:
//
//   - A set bit means free. ECMA-167 marks unallocated blocks with ones;
//     allocation clears the bit.
//   - The first 192 bits are the descriptor. Bit n of the bitmap area describes
//     logical block n-192, so the bit stream spills across block boundaries.
//
// Within a byte, bit 0 is the least significant bit.
//
// A volume that records no bitmap is not damaged, but it also records no free
// space; that is refused by name rather than reported as full or empty.

// Space bitmap descriptor bytes before the bits.
const bitmapHeader = 24

// Those bytes as bits: the offset of logical block 0 in the bit stream.
const bitmapHeaderBits = bitmapHeader * 8

// FreeRun is one run of unallocated blocks, partition-relative.
type FreeRun struct {
	Start  uint64
	Blocks uint64
}

// FreeSpace is a partition's unallocated space bitmap.
type FreeSpace struct {
	BlockSize uint32
	// PartitionStart is the partition's first volume block.
	PartitionStart uint32
	// PartitionBlocks is the partition's length in blocks.
	PartitionBlocks uint64
	// FreeBlocks is the number of blocks the bitmap marks unallocated.
	FreeBlocks uint64
	// Runs are the unallocated runs, partition-relative.
	Runs []FreeRun
}

// IsBlockFree reports whether a partition-relative block is unallocated.
func (f *FreeSpace) IsBlockFree(block uint64) bool {
	if block >= f.PartitionBlocks {
		return false
	}
	for _, run := range f.Runs {
		if block >= run.Start && block < run.Start+run.Blocks {
			return true
		}
	}
	return false
}

// FreeSpace reads and validates the partition's unallocated space bitmap.
func (v *Volume) FreeSpace() (*FreeSpace, error) {
	v.freeOnce.Do(func() {
		v.free, v.freeErr = v.loadFreeSpace()
	})
	return v.free, v.freeErr
}

func (v *Volume) loadFreeSpace() (*FreeSpace, error) {
	blockSize := uint64(v.blockSize)
	if blockSize == 0 {
		return nil, corruptf("the volume declares a zero block size")
	}
	if len(v.partitions) != 1 {
		return nil, unsupportedf(
			"the volume maps %d partitions, and free space would need one map per partition",
			len(v.partitions))
	}
	slot := v.partitions[0]
	if slot.UnallocatedBitmap == nil {
		return nil, unsupportedf(
			"the partition descriptor names no unallocated space bitmap, so the volume records no free space")
	}
	bitmap := *slot.UnallocatedBitmap
	partitionStart := uint64(slot.Start)
	partitionLen := uint64(slot.Length)
	covered := (partitionStart + partitionLen) * blockSize
	if covered > v.src.Len() {
		return nil, corruptf(
			"the partition ends at byte %d, past the %d readable bytes", covered, v.src.Len())
	}

	extentBytes := uint64(bitmap.ExtentLength())
	extentBlocks := (extentBytes + blockSize - 1) / blockSize
	if extentBlocks == 0 {
		return nil, corruptf("the unallocated space bitmap is zero bytes long")
	}
	bitmapBlock := uint64(bitmap.Block)
	if bitmapBlock+extentBlocks > partitionLen {
		return nil, corruptf(
			"the unallocated space bitmap's %d blocks start at block %d of a %d-block partition",
			extentBlocks, bitmapBlock, partitionLen)
	}
	firstBlock := partitionStart + bitmapBlock
	first, err := v.readVolumeBytes(firstBlock*blockSize, blockSize, "unallocated space bitmap")
	if err != nil {
		return nil, err
	}
	tag, err := descriptorTag(first, "unallocated space bitmap", uint32(bitmapBlock))
	if err != nil {
		return nil, err
	}
	if tag.Ident != TagSBD {
		return nil, corruptf(
			"the partition's unallocated space bitmap block holds a %s", tag.Label())
	}
	declaredBits := uint64(le32(first, 16))
	declaredBytes := uint64(le32(first, 20))
	if declaredBits < partitionLen {
		return nil, corruptf(
			"the unallocated space bitmap declares %d bits, fewer than the partition's %d blocks",
			declaredBits, partitionLen)
	}
	if declaredBytes > extentBlocks*blockSize-bitmapHeader {
		return nil, corruptf(
			"the unallocated space bitmap declares %d bytes, more than its %d-block extent holds after the descriptor",
			declaredBytes, extentBlocks)
	}
	available := extentBlocks*blockSize*8 - bitmapHeaderBits
	if available < partitionLen {
		return nil, corruptf(
			"the unallocated space bitmap's extent covers %d blocks, fewer than the partition's %d",
			available, partitionLen)
	}

	groups := make(map[uint64][]byte)
	groups[0] = first
	bit := func(index uint64) (bool, error) {
		position := bitmapHeaderBits + index
		bitsPerBlock := blockSize * 8
		group := position / bitsPerBlock
		if group >= extentBlocks {
			return false, corruptf(
				"partition block %d lies past the %d-block bitmap extent", index, extentBlocks)
		}
		data, ok := groups[group]
		if !ok {
			data, err = v.readVolumeBytes((firstBlock+group)*blockSize, blockSize, "unallocated space bitmap")
			if err != nil {
				return false, err
			}
			groups[group] = data
		}
		offset := position % bitsPerBlock
		return data[offset/8]&(1<<(offset%8)) != 0, nil
	}

	free := &FreeSpace{
		BlockSize:       v.blockSize,
		PartitionStart:  slot.Start,
		PartitionBlocks: partitionLen,
	}
	var runStart uint64
	var runBlocks uint64
	for block := uint64(0); block < partitionLen; block++ {
		isFree, err := bit(block)
		if err != nil {
			return nil, err
		}
		if isFree {
			if runBlocks == 0 {
				runStart = block
			}
			runBlocks++
			free.FreeBlocks++
			continue
		}
		if runBlocks > 0 {
			free.Runs = append(free.Runs, FreeRun{Start: runStart, Blocks: runBlocks})
			runBlocks = 0
		}
	}
	if runBlocks > 0 {
		free.Runs = append(free.Runs, FreeRun{Start: runStart, Blocks: runBlocks})
	}
	return free, nil
}
