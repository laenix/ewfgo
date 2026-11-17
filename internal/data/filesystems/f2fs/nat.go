package f2fs

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// Node address table constants.
const (
	NATEntrySize        = 9
	NullAddr     uint32 = 0
	NewAddr      uint32 = ^uint32(0)
	CompressAddr uint32 = ^uint32(0) - 1
)

// NATEntry is one node address table entry.
type NATEntry struct {
	Version uint8
	Ino     uint32
	Block   uint32
}

// NATTable is the node address table in one of its two bitmap orders.
type NATTable struct {
	layout          BitmapLayout
	base            uint32
	bitmap          []byte
	blocks          uint32
	entriesPerBlock uint32
	blockSize       uint32
	mainStart       uint32
	mainEnd         uint32
	journal         []NATJournalEntry
}

// NewNATTable binds the table to a geometry and a bitmap order.
func NewNATTable(sb *Superblock, cp *Checkpoint, layout BitmapLayout) *NATTable {
	blocks := sb.SegmentCountNAT * sb.BlocksPerSegment
	mainEnd := sb.MainBlkaddr + sb.SegmentCountMain*sb.BlocksPerSegment
	bitmap := make([]byte, len(cp.NATBitmap(layout)))
	copy(bitmap, cp.NATBitmap(layout))
	return &NATTable{
		layout:          layout,
		base:            sb.NATBlkaddr,
		bitmap:          bitmap,
		blocks:          blocks,
		entriesPerBlock: sb.BlockSize / NATEntrySize,
		blockSize:       sb.BlockSize,
		mainStart:       sb.MainBlkaddr,
		mainEnd:         mainEnd,
	}
}

// WithJournal attaches the checkpoint's node-address journal to the table.
func (t *NATTable) WithJournal(journal []NATJournalEntry) *NATTable {
	t.journal = journal
	return t
}

// Journal returns the journal entries this table consults before its bytes.
func (t *NATTable) Journal() []NATJournalEntry { return t.journal }

// Layout returns the bitmap order this table was built with.
func (t *NATTable) Layout() BitmapLayout { return t.layout }

// EntriesPerBlock returns the node ids one table block holds.
func (t *NATTable) EntriesPerBlock() uint32 { return t.entriesPerBlock }

// InMain reports whether block lies inside the main area.
func (t *NATTable) InMain(block uint32) bool {
	return block >= t.mainStart && block < t.mainEnd
}

// BlockFor returns the physical block that holds nid's entry.
func (t *NATTable) BlockFor(nid uint32) (uint32, error) {
	perBlock := t.entriesPerBlock
	if perBlock == 0 {
		return 0, invalidf("the block size cannot hold a node-address entry")
	}
	offset := uint64(nid) / uint64(perBlock)
	half := uint64(t.blocks) / 2
	if offset >= half {
		return 0, invalidf("node id %d needs table block %d, past the %d-block half", nid, offset, half)
	}
	block := uint64(t.base) + offset
	if bitSet(t.bitmap, int(offset)) {
		block = uint64(t.base) + half + offset
	}
	if block > uint64(^uint32(0)) {
		return 0, invalidf("node id %d lands past the end of the address space", nid)
	}
	return uint32(block), nil
}

// Entry reads the entry for nid, preferring a journal entry.
func (t *NATTable) Entry(src source.ByteSource, nid uint32) (NATEntry, error) {
	for _, entry := range t.journal {
		if entry.NID == nid {
			return NATEntry{Version: entry.Version, Ino: entry.Ino, Block: entry.Block}, nil
		}
	}
	return t.tableEntry(src, nid)
}

func (t *NATTable) tableEntry(src source.ByteSource, nid uint32) (NATEntry, error) {
	block, err := t.BlockFor(nid)
	if err != nil {
		return NATEntry{}, err
	}
	bytes, err := source.ReadVecAt(src, uint64(block)*uint64(t.blockSize), uint64(t.blockSize))
	if err != nil {
		return NATEntry{}, err
	}
	index := int(uint64(nid)%uint64(t.entriesPerBlock)) * NATEntrySize
	version, err := u8At(bytes, index)
	if err != nil {
		return NATEntry{}, err
	}
	ino, err := u32At(bytes, index+1)
	if err != nil {
		return NATEntry{}, err
	}
	node, err := u32At(bytes, index+5)
	if err != nil {
		return NATEntry{}, err
	}
	return NATEntry{Version: version, Ino: ino, Block: node}, nil
}

// NodeBlock returns the block holding nid's node, refusing the sentinels by
// name.
func (t *NATTable) NodeBlock(src source.ByteSource, nid uint32) (uint32, error) {
	entry, err := t.Entry(src, nid)
	if err != nil {
		return 0, err
	}
	switch entry.Block {
	case NullAddr:
		return 0, invalidf("node id %d points at no block", nid)
	case NewAddr:
		return 0, unsupportedf("node id %d, whose block is still in a current segment", nid)
	case CompressAddr:
		return 0, unsupportedf("the compressed node %d", nid)
	}
	if !t.InMain(entry.Block) {
		return 0, invalidf("node id %d points at block %d, outside the main area %d..%d",
			nid, entry.Block, t.mainStart, t.mainEnd)
	}
	return entry.Block, nil
}

// DetectNAT chooses the bitmap order the volume itself confirms.
func DetectNAT(src source.ByteSource, sb *Superblock, cp *Checkpoint) (*NATTable, error) {
	return DetectNATWithJournal(src, sb, cp, nil)
}

// DetectNATWithJournal chooses the bitmap order, then attaches the journal.
func DetectNATWithJournal(src source.ByteSource, sb *Superblock, cp *Checkpoint, journal []NATJournalEntry) (*NATTable, error) {
	var failures []string
	for _, layout := range AllBitmapLayouts {
		table := NewNATTable(sb, cp, layout)
		entry, err := table.tableEntry(src, sb.NodeIno)
		if err == nil && entry.Ino == sb.NodeIno && table.InMain(entry.Block) {
			return table.WithJournal(journal), nil
		}
		if err != nil {
			failures = append(failures, layout.Describe()+": "+err.Error())
		} else {
			failures = append(failures, layout.Describe()+": node id "+
				itoa(int(sb.NodeIno))+" names inode "+itoa(int(entry.Ino))+
				" at block "+itoa(int(entry.Block)))
		}
	}
	return nil, invalidf("the node-address table reads nowhere sensible under either bitmap order (%s)",
		joinStrings(failures, "; "))
}
