package ocfs2

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// An OCFS2 file's data map is a tree of ocfs2_extent_rec records. The root list
// lives in the dinode's id2.i_list; when l_tree_depth is zero its records are
// leaves, otherwise each record names an EXBLK01 block one level lower. Extents
// must start at cluster 0, be contiguous, and cover exactly i_clusters.

// ExtentBlockSignature is the signature of an extent block.
var ExtentBlockSignature = []byte("EXBLK01")

const (
	// MaxPathDepth; a tree at this depth or deeper is refused.
	MaxPathDepth uint16 = 5
	// MaxExtentBlocks bounds one map.
	MaxExtentBlocks uint64 = 1_000_000
	// MaxExtents bounds one map's leaf extents.
	MaxExtents uint64 = 1_000_000
	// ExtentUnwritten is the leaf "content is not written" flag.
	ExtentUnwritten uint8 = 0x01

	// ExtentBlockListOffset is where an extent block's list begins.
	ExtentBlockListOffset = 0x30
	// ExtentBlockRecordsOffset is where an extent block's records begin.
	ExtentBlockRecordsOffset = 0x40
)

// ExtentRecord is one parsed extent record.
type ExtentRecord struct {
	Cpos     uint32
	Clusters uint32
	Physical uint64
	Flags    uint8
	Interior bool
}

// ExtentList is one parsed extent list.
type ExtentList struct {
	Depth    uint16
	Count    uint16
	NextFree uint16
	Records  []ExtentRecord
}

// ClusterExtent is one logical-to-physical cluster run.
type ClusterExtent struct {
	LogicalCluster uint64
	PhysicalBlock  uint64
	Clusters       uint64
}

// ExtentMap is a resolved extent map.
type ExtentMap struct {
	Extents      []ClusterExtent
	ExtentBlocks uint64
	Records      uint64
}

// ParseExtentList parses one extent list at at inside bytes. blockSize bounds
// the list's record capacity; the list's own l_count is checked against it.
func ParseExtentList(bytes []byte, at int, blockSize int, what string) (*ExtentList, error) {
	if at < 0 || at+16 > len(bytes) || at+16 < at {
		return nil, corruptf("%s starts at offset %d, past the %d bytes available", what, at, len(bytes))
	}
	depth := le16(bytes, at)
	count := le16(bytes, at+2)
	nextFree := le16(bytes, at+4)
	recordsStart := at + 16
	if recordsStart > blockSize {
		return nil, corruptf("%s places its records at offset %d, past the %d-byte block", what, recordsStart, blockSize)
	}
	capacity := (blockSize - recordsStart) / 16
	if capacity > int(^uint16(0)) {
		capacity = int(^uint16(0))
	}
	if int(count) > capacity {
		return nil, corruptf("%s declares %d record slots, more than the %d that fit", what, count, capacity)
	}
	if nextFree > count {
		return nil, corruptf("%s has %d records in use but only %d slots", what, nextFree, count)
	}
	if recordsStart+int(nextFree)*16 > len(bytes) {
		return nil, corruptf("%s records run past the %d bytes available", what, len(bytes))
	}

	records := make([]ExtentRecord, 0, int(nextFree))
	for index := 0; index < int(nextFree); index++ {
		recordAt := recordsStart + index*16
		cpos := le32(bytes, recordAt)
		second := le32(bytes, recordAt+4)
		physical := le64(bytes, recordAt+8)
		var clusters uint32
		var flags uint8
		interior := depth != 0
		if !interior {
			clusters = second & 0xffff
			flags = uint8(second >> 24)
		} else {
			clusters = second
		}
		if clusters == 0 {
			return nil, corruptf("%s record %d at logical cluster %d covers no clusters", what, index, cpos)
		}
		records = append(records, ExtentRecord{
			Cpos: cpos, Clusters: clusters, Physical: physical, Flags: flags, Interior: interior,
		})
	}
	return &ExtentList{Depth: depth, Count: count, NextFree: nextFree, Records: records}, nil
}

// ResolveExtents resolves an inode's extent list into contiguous logical
// cluster runs.
func ResolveExtents(superblock *Superblock, src source.ByteSource, inodeBlock uint64,
	list *ExtentList, totalClusters uint32) (*ExtentMap, error) {
	mapData := &ExtentMap{}
	if totalClusters == 0 {
		if list.NextFree != 0 {
			return nil, corruptf("inode block %d allocates no clusters but its extent list has %d records",
				inodeBlock, list.NextFree)
		}
		return mapData, nil
	}
	if list.NextFree == 0 {
		return nil, corruptf("inode block %d allocates %d clusters but its extent list is empty",
			inodeBlock, totalClusters)
	}
	if list.Depth >= MaxPathDepth {
		return nil, unsupportedf("inode block %d has extent tree depth %d, deeper than the %d levels this reader walks",
			inodeBlock, list.Depth, MaxPathDepth)
	}
	walk := &extentWalk{superblock: superblock, source: src, inodeBlock: inodeBlock, mapData: mapData}
	end, err := walk.list(list, list.Depth, 0, uint64(totalClusters), "the inode's extent list")
	if err != nil {
		return nil, err
	}
	if end != uint64(totalClusters) {
		return nil, corruptf("inode block %d's extent tree ends at logical cluster %d, not %d",
			inodeBlock, end, totalClusters)
	}
	return mapData, nil
}

type extentWalk struct {
	superblock *Superblock
	source     source.ByteSource
	inodeBlock uint64
	mapData    *ExtentMap
}

// list walks one list and returns the logical cluster just past it.
func (w *extentWalk) list(list *ExtentList, depth uint16, expectedStart, expectedClusters uint64, what string) (uint64, error) {
	if list.Depth != depth {
		return 0, corruptf("inode block %d: %s has tree depth %d, expected %d",
			w.inodeBlock, what, list.Depth, depth)
	}
	w.mapData.Records += uint64(len(list.Records))
	if w.mapData.Records < uint64(len(list.Records)) {
		return 0, corruptf("the extent record count overflows")
	}

	cursor := expectedStart
	for _, record := range list.Records {
		if uint64(record.Cpos) != cursor {
			return 0, corruptf("inode block %d: %s is not contiguous at logical cluster %d; the next record starts at %d",
				w.inodeBlock, what, cursor, record.Cpos)
		}
		if depth == 0 {
			if record.Flags&ExtentUnwritten != 0 {
				return 0, unsupportedf("inode block %d: an unwritten extent at logical cluster %d; its content is undefined and this reader will not zero-fill it",
					w.inodeBlock, record.Cpos)
			}
			if record.Flags&^ExtentUnwritten != 0 {
				return 0, unsupportedf("inode block %d: extent flags 0x%02x at logical cluster %d",
					w.inodeBlock, record.Flags, record.Cpos)
			}
			clusters := uint64(record.Clusters)
			physical, err := w.superblock.ValidateBlock(record.Physical, "an extent")
			if err != nil {
				return 0, err
			}
			clusterBlocks := w.superblock.ClusterBlocks()
			if clusterBlocks == 0 {
				return 0, corruptf("the volume declares a zero-block cluster")
			}
			if physical%clusterBlocks != 0 {
				return 0, corruptf("inode block %d: the extent at logical cluster %d starts at block %d, which is not aligned to the %d-block cluster",
					w.inodeBlock, record.Cpos, physical, clusterBlocks)
			}
			blocks := clusters * clusterBlocks
			if clusterBlocks != 0 && blocks/clusterBlocks != clusters {
				return 0, corruptf("an extent's block count overflows")
			}
			end := physical + blocks
			if end < physical {
				return 0, corruptf("an extent ends past the block address space")
			}
			if end > w.superblock.TotalBlocks {
				return 0, corruptf("inode block %d: the extent at logical cluster %d ends at block %d, out of range for the volume's %d blocks",
					w.inodeBlock, record.Cpos, end, w.superblock.TotalBlocks)
			}
			if uint64(len(w.mapData.Extents)) >= MaxExtents {
				return 0, unsupportedf("inode block %d needs more than %d extents", w.inodeBlock, MaxExtents)
			}
			w.mapData.Extents = append(w.mapData.Extents, ClusterExtent{
				LogicalCluster: cursor, PhysicalBlock: physical, Clusters: clusters,
			})
			cursor += clusters
			if cursor < clusters {
				return 0, corruptf("a file's logical size overflows")
			}
		} else {
			clusters := uint64(record.Clusters)
			physical, err := w.superblock.ValidateBlock(record.Physical, "an extent block")
			if err != nil {
				return 0, err
			}
			if w.mapData.ExtentBlocks >= MaxExtentBlocks {
				return 0, unsupportedf("inode block %d needs more than %d extent blocks", w.inodeBlock, MaxExtentBlocks)
			}
			child, err := w.readExtentBlock(physical)
			if err != nil {
				return 0, err
			}
			childEnd, err := w.list(child, depth-1, cursor, clusters, "an extent block's list")
			if err != nil {
				return 0, err
			}
			if childEnd != cursor+clusters {
				return 0, corruptf("inode block %d: the extent block at block %d covers up to logical cluster %d, expected %d",
					w.inodeBlock, physical, childEnd, cursor+clusters)
			}
			w.mapData.ExtentBlocks++
			cursor = childEnd
		}
	}

	expectedEnd := expectedStart + expectedClusters
	if expectedEnd < expectedStart {
		return 0, corruptf("an extent list's logical end overflows")
	}
	if cursor != expectedEnd {
		return 0, corruptf("inode block %d: %s ends at logical cluster %d, expected %d",
			w.inodeBlock, what, cursor, expectedEnd)
	}
	return cursor, nil
}

func (w *extentWalk) readExtentBlock(block uint64) (*ExtentList, error) {
	at, ok := w.superblock.BlockOffset(block)
	if !ok {
		return nil, corruptf("extent block %d overflows the byte address space", block)
	}
	blockSize := int(w.superblock.BlockSize)
	bytes := make([]byte, blockSize)
	if err := source.ReadExactAt(w.source, at, bytes); err != nil {
		return nil, err
	}
	if !hasSignature(bytes, ExtentBlockSignature) {
		return nil, corruptf("inode block %d: block %d is named as an extent block but carries no EXBLK01 signature",
			w.inodeBlock, block)
	}
	named := le64(bytes, 0x18)
	if named != block {
		return nil, corruptf("inode block %d: extent block read from block %d names itself as block %d",
			w.inodeBlock, block, named)
	}
	generation := le32(bytes, 0x14)
	if generation != w.superblock.FsGeneration {
		return nil, corruptf("inode block %d: extent block %d has filesystem generation 0x%08x, expected 0x%08x",
			w.inodeBlock, block, generation, w.superblock.FsGeneration)
	}
	return ParseExtentList(bytes, ExtentBlockListOffset, blockSize, "an extent block's list")
}
