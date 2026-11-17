package f2fs

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// Summary pack layout constants.
const (
	SummaryEntrySize     = 7
	EntriesInSummary     = 512
	SummaryAreaSize      = EntriesInSummary * SummaryEntrySize
	SummaryFooterSize    = 5
	JournalSize          = 4096 - SummaryFooterSize - SummaryAreaSize
	NATJournalEntrySize  = 4 + NATEntrySize
	SITJournalEntrySize  = 4 + SITEntrySize
	MaxNATJournalEntries = (JournalSize - 2) / NATJournalEntrySize
	MaxSITJournalEntries = (JournalSize - 2) / SITJournalEntrySize
	DataLogs             = 3
	NodeLogs             = 3
	SumTypeData          = 0
	AllocLFS             = 0
	AllocSSR             = 1
)

// NATJournalEntry is a node-address table override from the checkpoint's hot
// data summary.
type NATJournalEntry struct {
	NID     uint32
	Version uint8
	Ino     uint32
	Block   uint32
}

// SITJournalEntry is a segment-information override from the checkpoint's cold
// data summary.
type SITJournalEntry struct {
	Segno    uint32
	VBlocks  uint16
	ValidMap [64]byte
	Mtime    uint64
}

// DataSummaryEntry is one parent relationship recorded in a data summary block.
type DataSummaryEntry struct {
	Log       uint8
	Index     uint16
	NID       uint32
	Version   uint8
	OfsInNode uint16
}

// RecoveryReport records what the checkpoint pack described and what was left
// unapplied.
type RecoveryReport struct {
	Fastboot            bool
	CompactSummaries    bool
	DataSummaryBlocks   uint32
	NodeSummaryBlocks   uint32
	OrphanBlocks        uint32
	NATJournalEntries   int
	SITJournalEntries   int
	DataSummaryEntries  uint64
	DataSummaryParented uint64
	Limits              []string
}

// Facts renders the counters as key/value facts.
func (r RecoveryReport) Facts() [][2]string {
	state := "dirty checkpoint"
	if r.Fastboot {
		state = "fastboot checkpoint"
	}
	facts := [][2]string{
		{"recovery_state", state},
		{"recovery_compact_summaries", boolString(r.CompactSummaries)},
		{"recovery_nat_journal_entries", itoa(r.NATJournalEntries)},
		{"recovery_sit_journal_entries", itoa(r.SITJournalEntries)},
		{"recovery_data_summary_blocks", itoa(int(r.DataSummaryBlocks))},
		{"recovery_data_summary_entries", uintString(r.DataSummaryEntries)},
		{"recovery_data_summary_parented", uintString(r.DataSummaryParented)},
		{"recovery_node_summary_blocks", itoa(int(r.NodeSummaryBlocks))},
		{"recovery_orphan_blocks", itoa(int(r.OrphanBlocks))},
	}
	if len(r.Limits) > 0 {
		facts = append(facts, [2]string{"recovery_limits", joinStrings(r.Limits, "; ")})
	}
	return facts
}

// Recovery is a checkpoint pack read into the overrides and counters it holds.
type Recovery struct {
	report        RecoveryReport
	natJournal    []NATJournalEntry
	sitJournal    []SITJournalEntry
	dataSummaries [DataLogs][]DataSummaryEntry
}

// Report returns the replay's counters.
func (r *Recovery) Report() RecoveryReport { return r.report }

// NATJournal returns the node-address overrides.
func (r *Recovery) NATJournal() []NATJournalEntry { return r.natJournal }

// SITJournal returns the segment-information overrides.
func (r *Recovery) SITJournal() []SITJournalEntry { return r.sitJournal }

// DataSummaries returns the summary entries of one data log.
func (r *Recovery) DataSummaries(log int) []DataSummaryEntry {
	if log < 0 || log >= DataLogs {
		return nil
	}
	return r.dataSummaries[log]
}

// SITOverride returns the last journal entry for segment, which is what the
// kernel's sequential replay would leave in place.
func (r *Recovery) SITOverride(segment uint32) *SITJournalEntry {
	for index := len(r.sitJournal) - 1; index >= 0; index-- {
		if r.sitJournal[index].Segno == segment {
			return &r.sitJournal[index]
		}
	}
	return nil
}

// replayedSIT returns the journal entry that overrides segment, if one was
// replayed.
func (v *Volume) replayedSIT(segment uint32) *SITJournalEntry {
	if v.recovery == nil {
		return nil
	}
	return v.recovery.SITOverride(segment)
}

type packGeometry struct {
	startSum     uint32
	dataBlocks   uint32
	nodeBlocks   uint32
	orphanBlocks uint32
	compact      bool
}

// recover reads the checkpoint pack that follows checkpoint.
func recover(src source.ByteSource, sb *Superblock, cp *Checkpoint) (*Recovery, error) {
	if sb.CPPayload != 0 {
		return nil, unsupportedf("%d checkpoint payload block(s); the summary pack follows the payload, which this reader does not lay out", sb.CPPayload)
	}
	if sb.BlockSize != 4096 {
		return nil, unsupportedf("a %d-byte block size; the F2FS summary pack is written for 4096-byte blocks", sb.BlockSize)
	}
	if sb.BlocksPerSegment > EntriesInSummary {
		return nil, invalidf("a segment of %d blocks cannot be described by a %d-entry summary",
			sb.BlocksPerSegment, EntriesInSummary)
	}
	pack, err := packGeometryOf(src, sb, cp)
	if err != nil {
		return nil, err
	}
	var natJournal []NATJournalEntry
	var sitJournal []SITJournalEntry
	var dataSummaries [DataLogs][]DataSummaryEntry
	if pack.compact {
		natJournal, sitJournal, dataSummaries, err = readCompact(src, sb, cp, pack)
	} else {
		natJournal, sitJournal, dataSummaries, err = readNormal(src, sb, cp, pack)
	}
	if err != nil {
		return nil, err
	}
	limits := []string{
		"blocks written after this checkpoint: the kernel's fsync-data scan of node summary blocks is not replayed, so the view is the checkpoint's state",
		"data summary entries are read and counted but not applied; data blocks are resolved through each node's block map",
	}
	if pack.nodeBlocks != 0 {
		limits = append(limits, itoa(int(pack.nodeBlocks))+" node summary block(s) are counted but not read; nodes are resolved through the node-address table and its journal")
	}
	if pack.orphanBlocks != 0 {
		limits = append(limits, itoa(int(pack.orphanBlocks))+" checkpoint orphan block(s) were not read; orphan-inode deletion is not replayed")
	}
	if cp.Flags&CPOrphanPresentFlag != 0 && pack.orphanBlocks == 0 {
		limits = append(limits, "the checkpoint marks orphan entries present but its pack reserves no orphan block")
	}
	if cp.Flags&CPFsckFlag != 0 {
		limits = append(limits, "the checkpoint asks for fsck; its findings are not available")
	}
	if cp.Flags&CPErrorFlag != 0 {
		limits = append(limits, "the checkpoint records a write error; the view is what was written")
	}
	var dataEntries uint64
	var parented uint64
	for _, entries := range dataSummaries {
		dataEntries += uint64(len(entries))
		for _, entry := range entries {
			if entry.NID != 0 {
				parented++
			}
		}
	}
	return &Recovery{
		report: RecoveryReport{
			Fastboot:            cp.Flags&CPFastbootFlag != 0,
			CompactSummaries:    pack.compact,
			DataSummaryBlocks:   pack.dataBlocks,
			NodeSummaryBlocks:   pack.nodeBlocks,
			OrphanBlocks:        pack.orphanBlocks,
			NATJournalEntries:   len(natJournal),
			SITJournalEntries:   len(sitJournal),
			DataSummaryEntries:  dataEntries,
			DataSummaryParented: parented,
			Limits:              limits,
		},
		natJournal:    natJournal,
		sitJournal:    sitJournal,
		dataSummaries: dataSummaries,
	}, nil
}

func packGeometryOf(src source.ByteSource, sb *Superblock, cp *Checkpoint) (packGeometry, error) {
	total := cp.PackBlockCount
	if total <= 2 {
		return packGeometry{}, invalidf("the checkpoint pack claims %d blocks, but a pack with summaries holds more than two", total)
	}
	end := uint64(cp.Block) + uint64(total) - 1
	ckptEnd := uint64(sb.CPBlkaddr) + uint64(sb.SegmentCountCkpt)*uint64(sb.BlocksPerSegment)
	if end >= ckptEnd {
		return packGeometry{}, invalidf("the %d-block checkpoint pack ends at block %d, past the checkpoint area's last block %d",
			total, end, ckptEnd-1)
	}
	if end > uint64(^uint32(0)) {
		return packGeometry{}, invalidf("the checkpoint pack's last block does not fit an address")
	}
	endBlock := uint32(end)
	closing, err := readSummaryBlock(src, sb, endBlock, "the checkpoint pack's last block")
	if err != nil {
		return packGeometry{}, err
	}
	closingCheckpoint, err := ParseCheckpoint(closing, endBlock, cp.Copy, sb)
	if err != nil {
		return packGeometry{}, err
	}
	if closingCheckpoint.Version != cp.Version {
		return packGeometry{}, invalidf("the checkpoint pack opens with version %d but closes with %d; the pack is torn",
			cp.Version, closingCheckpoint.Version)
	}
	if cp.PackStartSum == 0 {
		return packGeometry{}, invalidf("the checkpoint's first summary block is block zero")
	}
	orphanBlocks := cp.PackStartSum - 1
	var nodeBlocks uint32
	if cp.HasNodeSummaries() {
		nodeBlocks = NodeLogs
	}
	if total < 2+orphanBlocks+nodeBlocks {
		return packGeometry{}, invalidf("a %d-block pack cannot hold its checkpoint, %d orphan and %d node summary blocks",
			total, orphanBlocks, nodeBlocks)
	}
	dataBlocks := total - 2 - orphanBlocks - nodeBlocks
	if dataBlocks == 0 || dataBlocks > DataLogs {
		return packGeometry{}, invalidf("the checkpoint pack holds %d data summary block(s), not one to %d", dataBlocks, DataLogs)
	}
	startSum := cp.Block + cp.PackStartSum
	if uint64(startSum)+uint64(dataBlocks+nodeBlocks) != end {
		return packGeometry{}, invalidf("the pack's %d data and %d node summary blocks do not fill the space between block %d and its last block %d",
			dataBlocks, nodeBlocks, startSum, end)
	}
	compact := cp.Flags&CPCompactSumFlag != 0
	if compact != (dataBlocks < DataLogs) {
		set := "clears"
		if compact {
			set = "sets"
		}
		return packGeometry{}, invalidf("the checkpoint %s the compacted summary flag but holds %d data summary blocks", set, dataBlocks)
	}
	return packGeometry{
		startSum:     startSum,
		dataBlocks:   dataBlocks,
		nodeBlocks:   nodeBlocks,
		orphanBlocks: orphanBlocks,
		compact:      compact,
	}, nil
}

func readNormal(src source.ByteSource, sb *Superblock, cp *Checkpoint, pack packGeometry) ([]NATJournalEntry, []SITJournalEntry, [DataLogs][]DataSummaryEntry, error) {
	var dataSummaries [DataLogs][]DataSummaryEntry
	var natJournal []NATJournalEntry
	var sitJournal []SITJournalEntry
	for logIndex := 0; logIndex < DataLogs; logIndex++ {
		blockAddress := pack.startSum + uint32(logIndex)
		block, err := readSummaryBlock(src, sb, blockAddress, "a data summary block")
		if err != nil {
			return nil, nil, dataSummaries, err
		}
		if block[len(block)-SummaryFooterSize] != SumTypeData {
			return nil, nil, dataSummaries, invalidf("the block at %d closes with summary type %d, not a data summary",
				blockAddress, block[len(block)-SummaryFooterSize])
		}
		count, err := dataEntryCount(sb, cp, logIndex)
		if err != nil {
			return nil, nil, dataSummaries, err
		}
		entries := make([]DataSummaryEntry, 0, count)
		for index := 0; index < count; index++ {
			entry, err := parseSummaryEntry(block, index*SummaryEntrySize, logIndex, index)
			if err != nil {
				return nil, nil, dataSummaries, err
			}
			entries = append(entries, entry)
		}
		dataSummaries[logIndex] = entries
		journal := block[SummaryAreaSize : SummaryAreaSize+JournalSize]
		if logIndex == 0 {
			natJournal, err = parseNATJournal(journal, sb)
			if err != nil {
				return nil, nil, dataSummaries, err
			}
		} else if logIndex == 2 {
			sitJournal, err = parseSITJournal(journal, sb)
			if err != nil {
				return nil, nil, dataSummaries, err
			}
		}
	}
	return natJournal, sitJournal, dataSummaries, nil
}

func readCompact(src source.ByteSource, sb *Superblock, cp *Checkpoint, pack packGeometry) ([]NATJournalEntry, []SITJournalEntry, [DataLogs][]DataSummaryEntry, error) {
	var dataSummaries [DataLogs][]DataSummaryEntry
	pages := make([][]byte, 0, pack.dataBlocks)
	for index := uint32(0); index < pack.dataBlocks; index++ {
		page, err := readSummaryBlock(src, sb, pack.startSum+index, "a compacted summary block")
		if err != nil {
			return nil, nil, dataSummaries, err
		}
		pages = append(pages, page)
	}
	first := pages[0]
	natJournal, err := parseNATJournal(first[:JournalSize], sb)
	if err != nil {
		return nil, nil, dataSummaries, err
	}
	sitJournal, err := parseSITJournal(first[JournalSize:JournalSize*2], sb)
	if err != nil {
		return nil, nil, dataSummaries, err
	}
	page := 0
	offset := JournalSize * 2
	for logIndex := 0; logIndex < DataLogs; logIndex++ {
		count, err := dataEntryCount(sb, cp, logIndex)
		if err != nil {
			return nil, nil, dataSummaries, err
		}
		entries := make([]DataSummaryEntry, 0, count)
		for index := 0; index < count; index++ {
			if page >= len(pages) {
				return nil, nil, dataSummaries, invalidf("the compacted summaries need more than the pack's %d block(s)", pack.dataBlocks)
			}
			block := pages[page]
			if offset+SummaryEntrySize > len(block)-SummaryFooterSize {
				return nil, nil, dataSummaries, invalidf("a summary entry at offset %d runs into the block footer", offset)
			}
			entry, err := parseSummaryEntry(block, offset, logIndex, index)
			if err != nil {
				return nil, nil, dataSummaries, err
			}
			entries = append(entries, entry)
			offset += SummaryEntrySize
			if offset+SummaryEntrySize > len(block)-SummaryFooterSize {
				page++
				offset = 0
			}
		}
		dataSummaries[logIndex] = entries
	}
	return natJournal, sitJournal, dataSummaries, nil
}

func dataEntryCount(sb *Superblock, cp *Checkpoint, logIndex int) (int, error) {
	blkoff := uint32(cp.CurDataBlkoff[logIndex])
	if blkoff > sb.BlocksPerSegment {
		return 0, invalidf("data log %d claims an append offset of %d, past its %d-block segment",
			logIndex, blkoff, sb.BlocksPerSegment)
	}
	if cp.AllocType[logIndex] == AllocSSR {
		return int(sb.BlocksPerSegment), nil
	}
	return int(blkoff), nil
}

func parseSummaryEntry(block []byte, offset, logIndex, index int) (DataSummaryEntry, error) {
	if offset+SummaryEntrySize > SummaryAreaSize && offset+SummaryEntrySize > len(block)-SummaryFooterSize {
		return DataSummaryEntry{}, invalidf("summary entry %d of log %d is past the summary block", index, logIndex)
	}
	nid, err := u32At(block, offset)
	if err != nil {
		return DataSummaryEntry{}, err
	}
	version, err := u8At(block, offset+4)
	if err != nil {
		return DataSummaryEntry{}, err
	}
	ofs, err := u16At(block, offset+5)
	if err != nil {
		return DataSummaryEntry{}, err
	}
	return DataSummaryEntry{
		Log:       uint8(logIndex),
		Index:     uint16(index),
		NID:       nid,
		Version:   version,
		OfsInNode: ofs,
	}, nil
}

func parseNATJournal(journal []byte, sb *Superblock) ([]NATJournalEntry, error) {
	count, err := u16At(journal, 0)
	if err != nil {
		return nil, err
	}
	if int(count) > MaxNATJournalEntries {
		return nil, invalidf("the node-address journal holds %d entries, more than %d", count, MaxNATJournalEntries)
	}
	halfBlocks := sb.NATBlocks() / 2
	maxNID := halfBlocks * (uint64(sb.BlockSize) / NATEntrySize)
	entries := make([]NATJournalEntry, 0, count)
	for index := 0; index < int(count); index++ {
		at := 2 + index*NATJournalEntrySize
		nid, err := u32At(journal, at)
		if err != nil {
			return nil, err
		}
		version, err := u8At(journal, at+4)
		if err != nil {
			return nil, err
		}
		ino, err := u32At(journal, at+5)
		if err != nil {
			return nil, err
		}
		block, err := u32At(journal, at+9)
		if err != nil {
			return nil, err
		}
		if uint64(nid) >= maxNID {
			return nil, invalidf("the node-address journal names node id %d, but the table ends at %d", nid, maxNID)
		}
		if block != NullAddr && block != CompressAddr {
			if block == NewAddr {
				return nil, invalidf("the node-address journal names node id %d at NEW_ADDR, a node whose block was not written", nid)
			}
			if !inMainBlock(sb, block) {
				end := uint64(sb.MainBlkaddr) + uint64(sb.SegmentCountMain)*uint64(sb.BlocksPerSegment)
				return nil, invalidf("the node-address journal puts node id %d at block %d, outside the main area %d..%d",
					nid, block, sb.MainBlkaddr, end)
			}
		}
		entries = append(entries, NATJournalEntry{NID: nid, Version: version, Ino: ino, Block: block})
	}
	return entries, nil
}

func parseSITJournal(journal []byte, sb *Superblock) ([]SITJournalEntry, error) {
	count, err := u16At(journal, 0)
	if err != nil {
		return nil, err
	}
	if int(count) > MaxSITJournalEntries {
		return nil, invalidf("the segment-information journal holds %d entries, more than %d", count, MaxSITJournalEntries)
	}
	entries := make([]SITJournalEntry, 0, count)
	for index := 0; index < int(count); index++ {
		at := 2 + index*SITJournalEntrySize
		segno, err := u32At(journal, at)
		if err != nil {
			return nil, err
		}
		if segno >= sb.SegmentCountMain {
			return nil, invalidf("the segment-information journal names segment %d, but the main area holds %d segments",
				segno, sb.SegmentCountMain)
		}
		rawVBlocks, err := u16At(journal, at+4)
		if err != nil {
			return nil, err
		}
		vblocks := rawVBlocks & sitVBlocksMask
		if at+6+sitValidMapSize > len(journal) {
			return nil, invalidf("a segment-information journal entry is short")
		}
		var validMap [64]byte
		copy(validMap[:], journal[at+6:at+6+sitValidMapSize])
		mtime, err := u64At(journal, at+6+sitValidMapSize)
		if err != nil {
			return nil, err
		}
		limit := int(sb.BlocksPerSegment)
		var set int
		for block := 0; block < len(validMap)*8; block++ {
			if bitSet(validMap[:], block) {
				if block >= limit {
					return nil, invalidf("segment %d's journal valid map marks block %d, past the segment's %d blocks",
						segno, block, limit)
				}
				set++
			}
		}
		if set != int(vblocks) {
			return nil, invalidf("segment %d journals %d valid blocks but its valid map marks %d", segno, vblocks, set)
		}
		entries = append(entries, SITJournalEntry{Segno: segno, VBlocks: vblocks, ValidMap: validMap, Mtime: mtime})
	}
	return entries, nil
}

func inMainBlock(sb *Superblock, block uint32) bool {
	end := uint64(sb.MainBlkaddr) + uint64(sb.SegmentCountMain)*uint64(sb.BlocksPerSegment)
	return uint64(block) >= uint64(sb.MainBlkaddr) && uint64(block) < end
}

func readSummaryBlock(src source.ByteSource, sb *Superblock, block uint32, what string) ([]byte, error) {
	if uint64(block) >= sb.BlockCount {
		return nil, invalidf("%s at block %d is past the volume's %d blocks", what, block, sb.BlockCount)
	}
	return source.ReadVecAt(src, sb.ByteOffset(block), uint64(sb.BlockSize))
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func uintString(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	at := len(buf)
	for value > 0 {
		at--
		buf[at] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[at:])
}
