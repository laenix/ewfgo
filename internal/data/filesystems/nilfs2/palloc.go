package nilfs2

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// NILFS2's inode file and DAT are persistent-allocator ("palloc") files: a
// flat array of fixed-size entries addressed in groups. One group is a
// descriptor block, a bitmap block, then entry blocks. This reader decodes
// group 0 only; a larger inode or virtual block number is refused by name.

const (
	// DatEntrySize is the DAT entry size.
	DatEntrySize = 32
	// IfileEntrySize is the inode-file entry size.
	IfileEntrySize = 128
)

// EntriesPerGroup returns blockSize*8, one entry per bitmap bit.
func EntriesPerGroup(blockSize uint32) uint64 { return uint64(blockSize) * 8 }

// EntriesPerBlock returns how many entries of entrySize fit in one block.
func EntriesPerBlock(blockSize uint32, entrySize int) uint64 {
	if entrySize <= 0 {
		return 0
	}
	return uint64(blockSize) / uint64(entrySize)
}

// BlocksPerGroup returns the bitmap block plus the entry blocks.
func BlocksPerGroup(blockSize uint32, entrySize int) uint64 {
	perBlock := EntriesPerBlock(blockSize, entrySize)
	if perBlock == 0 {
		return 0
	}
	return 1 + EntriesPerGroup(blockSize)/perBlock
}

// EntryLocation returns the file block and byte offset of entry number inside
// palloc group zero.
func EntryLocation(blockSize uint32, entrySize int, number uint64) (uint64, int, error) {
	if entrySize <= 0 || uint64(blockSize)%uint64(entrySize) != 0 {
		return 0, 0, corruptf("a %d-byte entry does not divide the %d-byte block", entrySize, blockSize)
	}
	groupEntries := EntriesPerGroup(blockSize)
	if number >= groupEntries {
		return 0, 0, unsupportedf("entry %d is outside the first palloc group (%d entries); this reader decodes group 0 only",
			number, groupEntries)
	}
	perBlock := EntriesPerBlock(blockSize, entrySize)
	fileBlock := 2 + number/perBlock
	offset := (number % perBlock) * uint64(entrySize)
	if offset > uint64(maxInt()) {
		return 0, 0, corruptf("a palloc entry offset does not fit in memory")
	}
	return fileBlock, int(offset), nil
}

func maxInt() int { return int(^uint(0) >> 1) }

// readMetadataBlock reads one logical block of a metadata file whose bmap
// pointers are physical block numbers.
func readMetadataBlock(superblock *Superblock, src source.ByteSource, file *Inode, fileBlock uint64, what string) ([]byte, error) {
	if file.IsLargeBmap() {
		return nil, unsupportedf("%s: the metadata file uses a B-tree block map; this reader decodes direct block maps only", what)
	}
	if fileBlock >= DirectPointers {
		return nil, unsupportedf("%s: file block %d is past the %d direct pointers", what, fileBlock, DirectPointers)
	}
	physical := file.Bmap[fileBlock]
	if physical == 0 {
		return nil, corruptf("%s: file block %d is a hole (zero pointer); the palloc layout cannot be read", what, fileBlock)
	}
	if _, err := superblock.ValidateBlock(physical, what+" file block"); err != nil {
		return nil, err
	}
	offset, ok := superblock.BlockOffset(physical)
	if !ok {
		return nil, corruptf("%s: file block %d overflows the address space", what, fileBlock)
	}
	bytes := make([]byte, int(superblock.BlockSize))
	if err := source.ReadExactAt(src, offset, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// DatEntry is one translated virtual block.
type DatEntry struct {
	Blocknr  uint64
	StartCNO uint64
	EndCNO   uint64
}

// Dat is a virtual-block-number translator backed by the DAT file.
type Dat struct {
	Inode       *Inode
	BlocksRead  uint64
	EntriesRead uint64
}

// NewDat validates the super root's DAT inode.
func NewDat(inode *Inode) (*Dat, error) {
	if inode.Kind != KindFile && inode.Kind != KindUnknown {
		return nil, corruptf("the super root's DAT inode is a %s, not a regular file", inode.Kind.Label())
	}
	if inode.IsLargeBmap() {
		return nil, unsupportedf("the DAT inode uses a B-tree block map; this reader decodes direct block maps only")
	}
	return &Dat{Inode: inode}, nil
}

// Entry reads the DAT entry for a virtual block number.
func (d *Dat) Entry(superblock *Superblock, src source.ByteSource, virtualBlock uint64) (DatEntry, error) {
	fileBlock, offset, err := EntryLocation(superblock.BlockSize, DatEntrySize, virtualBlock)
	if err != nil {
		return DatEntry{}, err
	}
	bytes, err := readMetadataBlock(superblock, src, d.Inode, fileBlock, "the DAT file")
	if err != nil {
		return DatEntry{}, err
	}
	d.BlocksRead++
	d.EntriesRead++
	if offset+DatEntrySize > len(bytes) {
		return DatEntry{}, corruptf("the DAT entry %d at offset %d is past the %d-byte block", virtualBlock, offset, len(bytes))
	}
	return DatEntry{
		Blocknr:  le64(bytes, offset+0x00),
		StartCNO: le64(bytes, offset+0x08),
		EndCNO:   le64(bytes, offset+0x10),
	}, nil
}

// Translate maps a virtual block number to a physical block number.
func (d *Dat) Translate(superblock *Superblock, src source.ByteSource, virtualBlock uint64) (uint64, error) {
	entry, err := d.Entry(superblock, src, virtualBlock)
	if err != nil {
		return 0, err
	}
	if entry.Blocknr == 0 {
		return 0, corruptf("DAT entry %d names block 0 (unallocated); the logical block is a hole and is not zero-filled", virtualBlock)
	}
	return entry.Blocknr, nil
}

// Ifile is the inode file.
type Ifile struct {
	Inode      *Inode
	BlocksRead uint64
	InodesRead uint64
}

// NewIfile validates the super root's ifile inode.
func NewIfile(inode *Inode) (*Ifile, error) {
	if inode.Kind != KindFile && inode.Kind != KindUnknown {
		return nil, corruptf("the super root's ifile inode is a %s, not a regular file", inode.Kind.Label())
	}
	if inode.IsLargeBmap() {
		return nil, unsupportedf("the ifile inode uses a B-tree block map; this reader decodes direct block maps only")
	}
	return &Ifile{Inode: inode}, nil
}

// ReadInode reads the inode with the given number.
func (f *Ifile) ReadInode(superblock *Superblock, src source.ByteSource, number uint64) (*Inode, error) {
	fileBlock, offset, err := EntryLocation(superblock.BlockSize, IfileEntrySize, number)
	if err != nil {
		return nil, err
	}
	bytes, err := readMetadataBlock(superblock, src, f.Inode, fileBlock, "the inode file")
	if err != nil {
		return nil, err
	}
	f.BlocksRead++
	f.InodesRead++
	if offset+IfileEntrySize > len(bytes) {
		return nil, corruptf("inode %d at offset %d is past the %d-byte block", number, offset, len(bytes))
	}
	inode, err := ParseUserInode(bytes[offset:offset+IfileEntrySize],
		"inode "+u64Text(number), superblock.VolumeBytes)
	if err != nil {
		return nil, err
	}
	inode.number = number
	return inode, nil
}

func u64Text(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	index := len(buf)
	for value > 0 {
		index--
		buf[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[index:])
}
