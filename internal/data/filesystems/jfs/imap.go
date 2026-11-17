package jfs

import (
	"math/bits"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The JFS inode allocation map. An inode number selects an allocation group
// (4096 inodes), an extent within it (32 inodes), a page inside the extent
// (8 inodes), and a slot on the page. The map file itself is a normal JFS file
// read through its inode's extent tree.
const (
	// DinomapSize is the bytes of an inode-map control page.
	DinomapSize = 4096
	// IagSize is the bytes of one allocation group page.
	IagSize = 4096
)

type inodeMap struct {
	inode   *Dinode
	control *dinomap
}

type dinomap struct {
	FreeIAG         uint32
	NextIAG         uint32
	NumInos         uint32
	NumFree         uint32
	BlocksPerIExt   uint32
	L2BlocksPerIExt uint32
	DiskBlock       uint32
	MaxAG           uint32
	AGCtl           [MaxAllocationGroups][4]uint32
}

func parseDinomap(raw []byte) (*dinomap, error) {
	if len(raw) < DinomapSize {
		return nil, corruptf("an inode map control page needs %d bytes, not %d", DinomapSize, len(raw))
	}
	blocksPerIExt := le32(raw, 16)
	l2 := le32(raw, 20)
	if blocksPerIExt == 0 || blocksPerIExt&(blocksPerIExt-1) != 0 ||
		l2 != uint32(bits.TrailingZeros32(blocksPerIExt)) {
		return nil, corruptf("the inode map says %d blocks per inode extent with logarithm %d", blocksPerIExt, l2)
	}
	if blocksPerIExt != PagesPerInodeExtent {
		return nil, corruptf("an inode extent covers %d blocks, but 32 inodes of %d bytes need %d",
			blocksPerIExt, InodeSize, PagesPerInodeExtent)
	}
	control := &dinomap{
		FreeIAG:         le32(raw, 0),
		NextIAG:         le32(raw, 4),
		NumInos:         le32(raw, 8),
		NumFree:         le32(raw, 12),
		BlocksPerIExt:   blocksPerIExt,
		L2BlocksPerIExt: l2,
		DiskBlock:       le32(raw, 24),
		MaxAG:           le32(raw, 28),
	}
	for index := 0; index < MaxAllocationGroups; index++ {
		at := 2048 + index*16
		for field := 0; field < 4; field++ {
			control.AGCtl[index][field] = le32(raw, at+field*4)
		}
	}
	return control, nil
}

type iag struct {
	AGStart  uint64
	IAGNum   uint32
	FreeInos uint32
	FreeExts uint32
	InoExt   [ExtentsPerGroup]Pxd
}

func parseIag(raw []byte, expected uint32) (*iag, error) {
	if len(raw) < IagSize {
		return nil, corruptf("an inode allocation group page needs %d bytes, not %d", IagSize, len(raw))
	}
	iagnum := le32(raw, 8)
	if iagnum != expected {
		return nil, corruptf("allocation group page %d names itself %d", expected, iagnum)
	}
	group := &iag{
		AGStart:  le64(raw, 0),
		IAGNum:   iagnum,
		FreeInos: le32(raw, 64),
		FreeExts: le32(raw, 68),
	}
	for index := 0; index < ExtentsPerGroup; index++ {
		extent, err := ParsePxd(raw, 3072+index*8)
		if err != nil {
			return nil, err
		}
		group.InoExt[index] = extent
	}
	return group, nil
}

// LocatedInode is an inode plus the absolute byte offset of its slot.
type LocatedInode struct {
	Inode  *Dinode
	Offset uint64
}

func openInodeMap(src source.ByteSource, volumeBlocks uint64, inode *Dinode) (*inodeMap, error) {
	raw, err := readLogicalBlock(src, volumeBlocks, inode.ExtentTreeRoot(), 0)
	if err != nil {
		return nil, err
	}
	control, err := parseDinomap(raw)
	if err != nil {
		return nil, err
	}
	return &inodeMap{inode: inode, control: control}, nil
}

func (m *inodeMap) allocationGroup(src source.ByteSource, volumeBlocks uint64, iagno uint32) (*iag, error) {
	raw, err := readLogicalBlock(src, volumeBlocks, m.inode.ExtentTreeRoot(), uint64(iagno)+1)
	if err != nil {
		return nil, err
	}
	return parseIag(raw, iagno)
}

func (m *inodeMap) resolveInode(src source.ByteSource, volumeBlocks uint64, number uint32) (*LocatedInode, error) {
	iagno := number / InodesPerGroup
	within := number % InodesPerGroup
	extentIndex := within / InodesPerExtent
	group, err := m.allocationGroup(src, volumeBlocks, iagno)
	if err != nil {
		return nil, err
	}
	if group.AGStart >= volumeBlocks {
		return nil, corruptf("allocation group %d starts at block %d, past the aggregate's %d",
			iagno, group.AGStart, volumeBlocks)
	}
	extent := group.InoExt[extentIndex]
	if extent.Len != m.control.BlocksPerIExt || extent.Address == 0 {
		return nil, corruptf(
			"inode %d: extent %d of allocation group %d is %d blocks at %d, not %d blocks at a real address",
			number, extentIndex, iagno, extent.Len, extent.Address, m.control.BlocksPerIExt)
	}
	end, err := extent.End()
	if err != nil {
		return nil, err
	}
	if end > volumeBlocks {
		return nil, corruptf("inode %d: the inode extent at block %d runs past the aggregate's %d",
			number, extent.Address, volumeBlocks)
	}
	pageInExtent := uint64((within % InodesPerExtent) / InodesPerPage)
	block := extent.Address + pageInExtent
	slot := uint64(number % InodesPerPage)
	base := block * BlockSize
	if block != 0 && base/block != BlockSize {
		return nil, corruptf("inode %d has an overflowing on-disk offset", number)
	}
	offset := base + slot*InodeSize
	if offset < base {
		return nil, corruptf("inode %d has an overflowing on-disk offset", number)
	}
	raw, err := source.ReadVecAt(src, offset, InodeSize)
	if err != nil {
		return nil, err
	}
	inode, err := ParseDinode(raw)
	if err != nil {
		return nil, err
	}
	if inode.Number() != number {
		return nil, corruptf("inode slot %d holds inode %d instead", number, inode.Number())
	}
	if inode.Nlink() == 0 {
		return nil, corruptf("inode %d has a zero link count: its slot was freed", number)
	}
	return &LocatedInode{Inode: inode, Offset: offset}, nil
}

// readAggregateInode reads one inode from the fixed 32-slot aggregate table.
func readAggregateInode(src source.ByteSource, number uint32) (*Dinode, error) {
	if number >= AggregateInodeCount {
		return nil, corruptf("aggregate inode %d is outside the fixed table's %d slots", number, AggregateInodeCount)
	}
	offset := AITableOffset + uint64(number)*InodeSize
	raw, err := source.ReadVecAt(src, offset, InodeSize)
	if err != nil {
		return nil, err
	}
	inode, err := ParseDinode(raw)
	if err != nil {
		return nil, err
	}
	if inode.Nlink() == 0 {
		return nil, corruptf("aggregate inode %d has a zero link count", number)
	}
	return inode, nil
}

func openFilesetMap(src source.ByteSource, volumeBlocks uint64) (*inodeMap, error) {
	inode, err := readAggregateInode(src, FilesystemInode)
	if err != nil {
		return nil, err
	}
	return openInodeMap(src, volumeBlocks, inode)
}
