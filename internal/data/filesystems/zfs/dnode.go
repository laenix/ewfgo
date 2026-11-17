package zfs

import "fmt"

// Dnodes and object data.
//
// A dnode describes one object: its type, block size, indirect tree shape,
// checksum and the block pointers that hold its data. The dnodes of an object
// set live in one object's data, addressed by object number times 512. Object
// 0's dnode is stored directly at the start of the object set block, which is
// the bootstrap that makes the rest reachable.

const (
	dnodeSize     = 512
	dnodeCoreSize = 64

	dmuOtNone              = 0
	dmuOtObjectDirectory   = 1
	dmuOtDnode             = 10
	dmuOtObjset            = 11
	dmuOtDslDir            = 12
	dmuOtDslDataset        = 16
	dmuOtZnode             = 17
	dmuOtPlainFile         = 19
	dmuOtDirectoryContents = 20
	dmuOtMasterNode        = 21
	dmuOtSA                = 44
	// dmuOtZapMetadata is DMU_OT_NEWTYPE|DMU_OT_METADATA|DMU_OT_BSWAP_ZAP:
	// an object that held a data-less struct was turned into a ZAP by
	// dmu_object_zapify(), keeping its original bonus type. A DSL dataset is
	// identified by that bonus type, not by this data type.
	dmuOtZapMetadata = 0xc4

	// dnodeFlagSpillBlkptr marks a bonus whose remainder lives in the block
	// the record's last pointer names.
	dnodeFlagSpillBlkptr = 0x04

	// dnMaxLevels is OpenZFS's DN_MAX_LEVELS.
	dnMaxLevels = 12
	// maxDataBlockSectors is 16 MiB / 512.
	maxDataBlockSectors = 32_768
)

// Dnode is one decoded dnode record.
type Dnode struct {
	object       uint64
	kind         uint8
	indblkshift  uint8
	nlevels      uint8
	nblkptr      uint8
	bonustype    uint8
	checksum     uint8
	compress     uint8
	flags        uint8
	datablkszsec uint16
	bonuslen     uint16
	extraSlots   uint8
	maxBlkID     uint64
	used         uint64
	bonus        []byte
	spill        *BlockPointer
	slots        []byte
}

// parseDnode parses the first 512 bytes of a dnode record. bytes must hold the
// whole record, including extra slots.
func parseDnode(bytes []byte, object uint64) (*Dnode, error) {
	if len(bytes) < dnodeSize {
		return nil, corruptf("object %d's dnode is %d bytes, not %d", object, len(bytes), dnodeSize)
	}
	extraSlots := bytes[12]
	wanted := (int(extraSlots) + 1) * dnodeSize
	if len(bytes) < wanted {
		return nil, corruptf("object %d's dnode claims %d extra slot(s) but only %d bytes were read",
			object, extraSlots, len(bytes))
	}
	slots := bytes[:wanted]
	kind := slots[0]
	nblkptr := slots[3]
	// A free slot (type 0) holds no pointers and no size; a live object has
	// between one and three.
	if kind != dmuOtNone && (nblkptr < 1 || nblkptr > 3) {
		return nil, corruptf("object %d's dnode has %d block pointer(s)", object, nblkptr)
	}
	flags := slots[7]
	bonusStart := dnodeCoreSize + int(nblkptr)*blockPointerSize
	bonuslen := uint16(slots[10]) | uint16(slots[11])<<8
	var spill *BlockPointer
	if flags&dnodeFlagSpillBlkptr != 0 {
		start := wanted - blockPointerSize
		pointer, err := parseBlockPointer(slots[start:wanted])
		if err != nil {
			return nil, err
		}
		spill = &pointer
	}
	bonusLimit := wanted
	if spill != nil {
		bonusLimit -= blockPointerSize
	}
	if bonusStart+int(bonuslen) > bonusLimit {
		beside := ""
		if spill != nil {
			beside = " beside its spill pointer"
		}
		return nil, corruptf("object %d's %d-byte bonus does not fit in its dnode%s", object, bonuslen, beside)
	}
	datablkszsec := uint16(slots[8]) | uint16(slots[9])<<8
	if kind != dmuOtNone && (datablkszsec == 0 || datablkszsec > maxDataBlockSectors) {
		return nil, corruptf("object %d has a %d-sector data block", object, datablkszsec)
	}
	nlevels := slots[2]
	if kind != dmuOtNone && (nlevels < 1 || nlevels > dnMaxLevels) {
		return nil, corruptf("object %d has an indirect tree %d level(s) deep; ZFS stops at %d",
			object, nlevels, dnMaxLevels)
	}
	bonus := append([]byte(nil), slots[bonusStart:bonusStart+int(bonuslen)]...)
	return &Dnode{
		object:       object,
		kind:         kind,
		indblkshift:  slots[1],
		nlevels:      nlevels,
		nblkptr:      nblkptr,
		bonustype:    slots[4],
		checksum:     slots[5],
		compress:     slots[6],
		flags:        flags,
		datablkszsec: datablkszsec,
		bonuslen:     bonuslen,
		extraSlots:   extraSlots,
		maxBlkID:     leUint64(slots[16:24]),
		used:         leUint64(slots[24:32]),
		bonus:        bonus,
		spill:        spill,
		slots:        append([]byte(nil), slots...),
	}, nil
}

// isFree reports a slot that holds no object.
func (d *Dnode) isFree() bool { return d.kind == dmuOtNone }

// dataBlockSize is the logical size of one data block.
func (d *Dnode) dataBlockSize() uint64 {
	if d.isFree() {
		return 0
	}
	return uint64(d.datablkszsec) << minBlockShift
}

// slotCount is the number of dnodes this record occupies.
func (d *Dnode) slotCount() int { return int(d.extraSlots) + 1 }

// spillPointer returns the block pointer to the rest of a spilled bonus.
func (d *Dnode) spillPointer() *BlockPointer { return d.spill }

func (d *Dnode) blockPointer(index int) (BlockPointer, error) {
	if index < 0 || index >= int(d.nblkptr) {
		return BlockPointer{}, corruptf("object %d has no block pointer %d", d.object, index)
	}
	start := dnodeCoreSize + index*blockPointerSize
	return parseBlockPointer(d.slots[start : start+blockPointerSize])
}

// readObject reads length bytes at a logical offset inside an object.
func readObject(reader *BlockReader, node *Dnode, offset uint64, length int) ([]byte, error) {
	if length < 0 || length > maxBlockSize {
		return nil, corruptf("an object read of %d bytes; the cap is %d", length, maxBlockSize)
	}
	blockSize := node.dataBlockSize()
	if blockSize == 0 || length == 0 {
		return make([]byte, length), nil
	}
	end := offset + uint64(length)
	if end < offset {
		return nil, corruptf("an object read offset overflows")
	}
	out := make([]byte, 0, length)
	position := offset
	for position < end {
		within := position % blockSize
		take := blockSize - within
		if remaining := end - position; remaining < take {
			take = remaining
		}
		pointer, err := locateBlock(reader, node, position)
		if err != nil {
			return nil, err
		}
		if pointer.isHole() {
			out = append(out, make([]byte, take)...)
		} else {
			data, err := reader.read(pointer)
			if err != nil {
				return nil, err
			}
			start := int(within)
			if start >= len(data) {
				out = append(out, make([]byte, take)...)
			} else {
				available := take
				if uint64(len(data)-start) < available {
					available = uint64(len(data) - start)
				}
				out = append(out, data[start:start+int(available)]...)
				out = append(out, make([]byte, take-available)...)
			}
		}
		position += take
	}
	return out, nil
}

// ObjectBlock is one level-0 pointer and the logical range it covers.
type ObjectBlock struct {
	logical uint64
	len     uint64
	pointer BlockPointer
}

// maxProvenanceBlocks bounds a whole-file provenance walk.
const maxProvenanceBlocks uint64 = 1 << 20

// dataBlocksInto appends the level-0 pointers covering offset..offset+len. An
// indirect pointer that is a hole stands for every block below it.
func dataBlocksInto(reader *BlockReader, node *Dnode, offset, length uint64, out *[]ObjectBlock) error {
	if length == 0 {
		return nil
	}
	blockSize := node.dataBlockSize()
	if blockSize == 0 {
		return nil
	}
	end := offset + length
	if end < offset {
		return corruptf("an object read offset overflows")
	}
	firstID := offset / blockSize
	lastID := (end - 1) / blockSize
	count := lastID - firstID + 1
	if count > maxProvenanceBlocks {
		return corruptf("the range needs %d data blocks, more than the %d a provenance walk enumerates",
			count, maxProvenanceBlocks)
	}
	if node.nlevels <= 1 {
		for blockID := firstID; blockID <= lastID; blockID++ {
			if blockID >= uint64(node.nblkptr) {
				return corruptf("object %d reads block %d at offset %d, but its dnode holds only %d direct pointer(s)",
					node.object, blockID, offset, node.nblkptr)
			}
			pointer, err := node.blockPointer(int(blockID))
			if err != nil {
				return err
			}
			*out = append(*out, ObjectBlock{logical: blockID * blockSize, len: blockSize, pointer: pointer})
		}
		return nil
	}
	shift := uint32(node.indblkshift)
	if shift < 7 || shift > 20 {
		return corruptf("object %d has indirect block shift %d", node.object, shift)
	}
	epbs := shift - 7
	level := uint32(node.nlevels) - 1
	topLo := shrBlockID(firstID, level*epbs)
	topHi := shrBlockID(lastID, level*epbs)
	if topHi >= uint64(node.nblkptr) {
		return corruptf("object %d reads block %d at offset %d, but its dnode holds only %d top-level pointer(s)",
			node.object, firstID, offset, node.nblkptr)
	}
	span := uint64(1) << minU32(level*epbs, 63)
	for top := topLo; top <= topHi; top++ {
		base := satMul(top, span)
		localFirst := satSub(firstID, base)
		localLast := satSub(lastID, base)
		if localLast > span-1 {
			localLast = span - 1
		}
		pointer, err := node.blockPointer(int(top))
		if err != nil {
			return err
		}
		if err := walkLevel(reader, node.object, blockSize, epbs, level, pointer, base, localFirst, localLast, out); err != nil {
			return err
		}
	}
	return nil
}

func walkLevel(reader *BlockReader, object uint64, blockSize uint64, epbs, level uint32,
	pointer BlockPointer, base, firstLocal, lastLocal uint64, out *[]ObjectBlock) error {
	if level == 0 {
		*out = append(*out, ObjectBlock{logical: satMul(satAdd(base, firstLocal), blockSize), len: blockSize, pointer: pointer})
		return nil
	}
	if pointer.isHole() {
		for local := firstLocal; local <= lastLocal; local++ {
			*out = append(*out, ObjectBlock{logical: satMul(satAdd(base, local), blockSize), len: blockSize, pointer: pointer})
		}
		return nil
	}
	if uint32(pointer.level()) != level {
		return corruptf("object %d's indirect tree holds a level-%d pointer where level %d belongs",
			object, pointer.level(), level)
	}
	block, err := reader.read(pointer)
	if err != nil {
		return err
	}
	entries := len(block) / blockPointerSize
	if entries != 1<<epbs {
		return corruptf("object %d's level-%d indirect block holds %d pointer(s); its shift %d implies %d",
			object, level, entries, epbs, 1<<epbs)
	}
	childShift := (level - 1) * epbs
	lo := shrBlockID(firstLocal, childShift)
	hi := shrBlockID(lastLocal, childShift)
	childSpan := uint64(1) << minU32(childShift, 63)
	for index := lo; index <= hi; index++ {
		offset := satMul(index, childSpan)
		childBase := satAdd(base, offset)
		childFirst := satSub(firstLocal, offset)
		childLast := satSub(lastLocal, offset)
		if childLast > childSpan-1 {
			childLast = childSpan - 1
		}
		start := int(index) * blockPointerSize
		child, err := parseBlockPointer(block[start:])
		if err != nil {
			return err
		}
		if err := walkLevel(reader, object, blockSize, epbs, level-1, child, childBase, childFirst, childLast, out); err != nil {
			return err
		}
	}
	return nil
}

// locateBlock walks the indirect tree to the level-0 pointer covering offset.
func locateBlock(reader *BlockReader, node *Dnode, offset uint64) (BlockPointer, error) {
	if node.nlevels <= 1 {
		blockSize := node.dataBlockSize()
		if blockSize == 0 {
			return BlockPointer{}, corruptf("object %d has no data block size to index block pointers", node.object)
		}
		index := offset / blockSize
		if index >= uint64(node.nblkptr) {
			return BlockPointer{}, corruptf("object %d reads block %d at offset %d, but its dnode holds only %d direct pointer(s)",
				node.object, index, offset, node.nblkptr)
		}
		return node.blockPointer(int(index))
	}
	shift := uint32(node.indblkshift)
	if shift < 7 || shift > 20 {
		return BlockPointer{}, corruptf("object %d has indirect block shift %d", node.object, shift)
	}
	// Indirect blocks hold 1 << (indblkshift - 7) pointers. Indexing is by
	// data block number, not byte offset: the block number is divided by epbs
	// bits per level, and the low epbs bits select within a block.
	epbs := shift - 7
	blockSize := node.dataBlockSize()
	if blockSize == 0 {
		return BlockPointer{}, corruptf("object %d has no data block size to index block pointers", node.object)
	}
	blockID := offset / blockSize
	level := uint32(node.nlevels) - 1
	top := shrBlockID(blockID, level*epbs)
	if top >= uint64(node.nblkptr) {
		return BlockPointer{}, corruptf("object %d reads block %d at offset %d, but its dnode holds only %d top-level pointer(s)",
			node.object, blockID, offset, node.nblkptr)
	}
	pointer, err := node.blockPointer(int(top))
	if err != nil {
		return BlockPointer{}, err
	}
	for level > 0 {
		if uint32(pointer.level()) != level {
			return BlockPointer{}, corruptf("object %d's indirect tree holds a level-%d pointer where level %d belongs",
				node.object, pointer.level(), level)
		}
		block, err := reader.read(pointer)
		if err != nil {
			return BlockPointer{}, err
		}
		entries := len(block) / blockPointerSize
		if entries == 0 || entries&(entries-1) != 0 {
			return BlockPointer{}, corruptf("object %d has an indirect block of %d pointer(s)", node.object, entries)
		}
		index := int(shrBlockID(blockID, (level-1)*epbs)) & (entries - 1)
		pointer, err = parseBlockPointer(block[index*blockPointerSize:])
		if err != nil {
			return BlockPointer{}, err
		}
		level--
	}
	if pointer.level() != 0 {
		return BlockPointer{}, corruptf("object %d's indirect tree ends at a level-%d pointer instead of data",
			node.object, pointer.level())
	}
	return pointer, nil
}

// shrBlockID shifts a block id, treating an over-wide shift as a zero index
// rather than panicking.
func shrBlockID(value uint64, bits uint32) uint64 {
	if bits >= 64 {
		return 0
	}
	return value >> bits
}

func satAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

func satSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

func satMul(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// objectTypeName is the object's name for reports; unknown types keep their
// number.
func objectTypeName(kind uint8) string {
	switch kind {
	case 0:
		return "none"
	case 1:
		return "object_directory"
	case 2:
		return "object_array"
	case 10:
		return "dnode"
	case 11:
		return "objset"
	case 12:
		return "dsl_dir"
	case 16:
		return "dsl_dataset"
	case 17:
		return "znode"
	case 19:
		return "plain_file_contents"
	case 20:
		return "directory_contents"
	case 21:
		return "master_node"
	case 27:
		return "zap_other"
	case 44:
		return "sa"
	case dmuOtZapMetadata:
		return "zap_metadata"
	default:
		return fmt.Sprintf("type %d", kind)
	}
}
