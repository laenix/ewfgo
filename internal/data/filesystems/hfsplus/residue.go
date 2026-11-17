package hfsplus

// Catalog records a deletion left in a leaf node's unused space.
//
// HFS+ compacts a B-tree node when a record is removed: later records move
// down and the free-space offset rises, but the bytes the removed record
// occupied are not erased.  The record survives in the free space until
// something overwrites it.  This module reports that residue as evidence, not
// as a live entry.
//
// A record is accepted only when its key names a non-empty, well-formed UTF-16
// name, its parent CNID is not zero, its body has a known type and a non-zero
// catalog ID, and its reserved field is zero.  Recovery of a stale file's
// content is gated on the allocation file: every block the fork names must
// still be free, otherwise the bytes may belong to another file.

import (
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// MaxOutsideNodes caps how many catalog nodes outside the leaf chain a
	// scan may read.
	MaxOutsideNodes uint32 = 1 << 16
	// MaxOverflowLookups caps the overflow-tree lookups one stale fork makes.
	MaxOverflowLookups uint64 = 1024
	// MaxResidueExtents caps the extent list one recovery attempt may hold.
	MaxResidueExtents = int(MaxOverflowLookups)*InlineExtents + InlineExtents
)

// ResidueKind is the catalog record type the leftover bytes claim.
type ResidueKind int

const (
	// ResidueFolder is a stale folder record.
	ResidueFolder ResidueKind = iota
	// ResidueFile is a stale file record.
	ResidueFile
	// ResidueFolderThread is a stale folder thread record.
	ResidueFolderThread
	// ResidueFileThread is a stale file thread record.
	ResidueFileThread
)

func residueKindFromRaw(raw uint16) (ResidueKind, bool) {
	switch raw {
	case 1:
		return ResidueFolder, true
	case 2:
		return ResidueFile, true
	case 3:
		return ResidueFolderThread, true
	case 4:
		return ResidueFileThread, true
	default:
		return 0, false
	}
}

func (k ResidueKind) String() string {
	switch k {
	case ResidueFolder:
		return "folder"
	case ResidueFile:
		return "file"
	case ResidueFolderThread:
		return "folder thread"
	case ResidueFileThread:
		return "file thread"
	default:
		return "unknown"
	}
}

func (k ResidueKind) isThread() bool {
	return k == ResidueFolderThread || k == ResidueFileThread
}

// CatalogResidue is one catalog record still legible in a leaf's unused space.
type CatalogResidue struct {
	Node     uint32
	Offset   uint16
	Parent   uint32
	Name     string
	Kind     ResidueKind
	ID       *uint32
	Size     *uint64
	Fork     *Fork
	Live     bool
	Detached bool
}

// IsDeleted reports whether the live catalog no longer holds this (parent,
// name).
func (r *CatalogResidue) IsDeleted() bool { return !r.Live }

// ResidueVerdict is what a stale file's data fork still yields.
type ResidueVerdict string

const (
	ResidueNothing            ResidueVerdict = "nothing"
	ResidueExtentsDisagree    ResidueVerdict = "extents-disagree"
	ResidueOverflowBeyondFork ResidueVerdict = "overflow-beyond-fork"
	ResidueOverflowMissing    ResidueVerdict = "overflow-missing"
	ResidueOverflowShort      ResidueVerdict = "overflow-short"
	ResidueOverflowUnreadable ResidueVerdict = "overflow-unreadable"
	ResidueOverflowLoop       ResidueVerdict = "overflow-loop"
	ResidueHole               ResidueVerdict = "hole"
	ResidueSizeBeyondExtents  ResidueVerdict = "size-beyond-extents"
	ResidueOutsideVolume      ResidueVerdict = "outside-volume"
	ResidueOverlap            ResidueVerdict = "overlap"
	ResidueInUse              ResidueVerdict = "in-use"
	ResidueContent            ResidueVerdict = "content"
)

// ResidueRecovery is the outcome of weighing one stale file.
type ResidueRecovery struct {
	Kind ResidueVerdict

	// Content fields.
	Bytes     []byte
	Size      uint64
	Truncated bool

	// ExtentsDisagree fields.
	Inline         uint64
	DeclaredBlocks uint64

	// Overflow fields.
	Covered    uint32
	Declared   uint32
	Block      uint32
	ShortBytes int
	Reason     string

	// SizeBeyondExtents fields.
	SizeBytes uint64
	Capacity  uint64

	// InUse fields.
	InUse  uint64
	Blocks uint64
}

// Content returns the recovered bytes, when the verdict served any.
func (r ResidueRecovery) Content() []byte {
	if r.Kind == ResidueContent {
		return r.Bytes
	}
	return nil
}

// OverflowStats records what resolving a stale fork's overflow extents cost.
type OverflowStats struct {
	Lookups     uint64
	ExtentsUsed uint64
	Rejected    uint64
	Files       uint64
}

// NodeCountMismatch records a disagreement between the header's freeNodes and
// the node map's free-node population.
type NodeCountMismatch struct {
	Header uint32
	Bitmap uint32
}

// ResidueReport is what one pass over the catalog's leaves found.
type ResidueReport struct {
	Residues          []CatalogResidue
	Leaves            uint32
	DetachedLeaves    uint32
	NodesOutsideChain uint32
	NodesSkipped      uint32
	BytesScanned      uint64
	Truncated         bool
	NodesTruncated    bool
	BitmapUsed        bool
	BitmapRefusal     string
	BitmapFreeNodes   uint32
	BitmapInUseNodes  uint32
	NodesInUseSkipped uint32
	FreeNodesMismatch *NodeCountMismatch
}

type residueLiveKey struct {
	parent uint32
	name   string
}

// ScanResidue searches the unused space of every catalog leaf for stale
// records, then marks a residue live when the current catalog still holds its
// (parent, name).
func (v *Volume) ScanResidue(limit int) (*ResidueReport, error) {
	if limit < 0 {
		limit = 0
	}
	report := &ResidueReport{}
	var nodeMap *NodeMap
	mapRead, err := v.catalog.NodeMap(v.src)
	if err != nil {
		report.BitmapRefusal = err.Error()
	} else {
		nodeMap = mapRead
		report.BitmapUsed = true
		report.BitmapInUseNodes = mapRead.UsedNodes()
		report.BitmapFreeNodes = mapRead.FreeNodes()
		if report.BitmapFreeNodes != v.catalog.header.FreeNodes {
			report.FreeNodesMismatch = &NodeCountMismatch{
				Header: v.catalog.header.FreeNodes,
				Bitmap: report.BitmapFreeNodes,
			}
		}
	}

	var chain []uint32
	stopped := false
	if err := v.catalog.forEachLeaf(v.src, func(number uint32, node *Node) (bool, error) {
		chain = append(chain, number)
		report.Leaves++
		scanResidueNode(number, node, false, limit, report)
		if len(report.Residues) >= limit {
			report.Truncated = true
			stopped = true
		}
		return !stopped, nil
	}); err != nil {
		return nil, err
	}
	if !stopped {
		sort.Slice(chain, func(i, j int) bool { return chain[i] < chain[j] })
		scanResidueOutside(v.catalog, v.src, chain, nodeMap, limit, report)
	}

	if len(report.Residues) > 0 {
		live, err := v.liveResidueNames()
		if err != nil {
			return nil, err
		}
		for i := range report.Residues {
			item := &report.Residues[i]
			item.Live = live[residueLiveKey{parent: item.Parent, name: item.Name}]
		}
	}
	return report, nil
}

// liveResidueNames collects the (parent, name) pairs the live catalog holds.
func (v *Volume) liveResidueNames() (map[residueLiveKey]bool, error) {
	limit := int(v.catalog.header.LeafRecords)
	if limit < 1 {
		limit = 1
	}
	if limit > 200_000 {
		limit = 200_000
	}
	names := make(map[residueLiveKey]bool, limit)
	seen := 0
	compare := func(a, b []byte) int {
		return CompareCatalogPayloads(a, b, v.CaseSensitive())
	}
	err := v.catalog.ScanAll(v.src, compare, func(keyBytes, data []byte) (bool, error) {
		if seen >= limit {
			return false, nil
		}
		key, err := ParseCatalogKey(keyBytes)
		if err != nil {
			return false, err
		}
		record, err := ParseCatalogRecord(data)
		if err != nil {
			return false, err
		}
		seen++
		if record.Type == RecordFolder || record.Type == RecordFile {
			names[residueLiveKey{parent: key.Parent, name: key.Name.String()}] = true
		}
		return true, nil
	})
	return names, err
}

func scanResidueOutside(tree *BTree, src source.ByteSource, chain []uint32, nodeMap *NodeMap, limit int, report *ResidueReport) {
	total := tree.header.TotalNodes
	if total <= 1 {
		return
	}
	inChain := func(number uint32) bool {
		index := sort.Search(len(chain), func(i int) bool { return chain[i] >= number })
		return index < len(chain) && chain[index] == number
	}
	for number := uint32(1); number < total; number++ {
		if report.NodesOutsideChain >= MaxOutsideNodes {
			report.NodesTruncated = true
			break
		}
		if inChain(number) {
			continue
		}
		if nodeMap != nil && nodeMap.IsUsed(number) {
			report.NodesInUseSkipped++
			continue
		}
		report.NodesOutsideChain++
		node, err := tree.node(src, number)
		if err != nil {
			report.NodesSkipped++
			continue
		}
		if node.Kind() != NodeLeaf {
			if nodeMap != nil {
				report.NodesSkipped++
			}
			continue
		}
		scanResidueNode(number, node, true, limit, report)
		if len(report.Residues) >= limit {
			report.Truncated = true
			break
		}
	}
}

func scanResidueNode(number uint32, node *Node, detached bool, limit int, report *ResidueReport) {
	start, end := node.freeSpace()
	if end <= start {
		return
	}
	report.BytesScanned += uint64(end - start)
	if detached {
		report.DetachedLeaves++
	}
	slack := node.Bytes()[start:end]
	pos := 0
	for pos+2 <= len(slack) && len(report.Residues) < limit {
		item, consumed, ok := parseResidueAt(number, slack, pos)
		if !ok {
			// A real record is word-aligned; a miss steps one unit.
			pos += 2
			continue
		}
		item.Offset = uint16(start + pos)
		item.Detached = detached
		report.Residues = append(report.Residues, item)
		if consumed < 2 {
			consumed = 2
		}
		pos += consumed
	}
}

func parseResidueAt(number uint32, slack []byte, pos int) (CatalogResidue, int, bool) {
	keyLen := int(be16(slack, pos))
	if keyLen < 6 || keyLen%2 != 0 || keyLen > 6+2*MaxNameUnits {
		return CatalogResidue{}, 0, false
	}
	keyEnd := pos + 2 + keyLen
	if keyEnd+2 > len(slack) {
		return CatalogResidue{}, 0, false
	}
	parent := be32(slack, pos+2)
	if parent == 0 {
		return CatalogResidue{}, 0, false
	}
	nameLen := (keyLen - 6) / 2
	body := slack[keyEnd:]
	kind, ok := residueKindFromRaw(be16(body, 0))
	if !ok {
		return CatalogResidue{}, 0, false
	}

	if kind.isThread() {
		// A thread key names its object by CNID and carries an empty name;
		// the body says where the object lives and what it is called.
		if nameLen != 0 {
			return CatalogResidue{}, 0, false
		}
		if len(body) < 10 {
			return CatalogResidue{}, 0, false
		}
		if be16(body, 2) != 0 {
			return CatalogResidue{}, 0, false
		}
		owner := be32(body, 4)
		units := int(be16(body, 8))
		if owner == 0 || units == 0 || units > MaxNameUnits {
			return CatalogResidue{}, 0, false
		}
		nameEnd := 10 + units*2
		if nameEnd > len(body) {
			return CatalogResidue{}, 0, false
		}
		name, ok := decodeResidueName(body[10:nameEnd])
		if !ok {
			return CatalogResidue{}, 0, false
		}
		object := parent
		return CatalogResidue{
			Node:   number,
			Parent: owner,
			Name:   name,
			Kind:   kind,
			ID:     &object,
		}, 2 + keyLen + nameEnd, true
	}

	if nameLen == 0 || pos+8 > keyEnd {
		return CatalogResidue{}, 0, false
	}
	name, ok := decodeResidueName(slack[pos+8 : keyEnd])
	if !ok {
		return CatalogResidue{}, 0, false
	}
	if len(body) < 12 {
		return CatalogResidue{}, 0, false
	}
	object := be32(body, 8)
	if object < 2 {
		return CatalogResidue{}, 0, false
	}
	switch kind {
	case ResidueFolder:
		if len(body) < 88 {
			return CatalogResidue{}, 0, false
		}
		return CatalogResidue{
			Node: number, Parent: parent, Name: name, Kind: kind, ID: &object,
		}, 2 + keyLen + 88, true
	case ResidueFile:
		if len(body) < 248 {
			return CatalogResidue{}, 0, false
		}
		if be32(body, 4) != 0 {
			return CatalogResidue{}, 0, false
		}
		fork, err := parseFork(body[88:168])
		if err != nil {
			return CatalogResidue{}, 0, false
		}
		size := fork.LogicalSize
		return CatalogResidue{
			Node: number, Parent: parent, Name: name, Kind: kind,
			ID: &object, Size: &size, Fork: &fork,
		}, 2 + keyLen + 248, true
	default:
		return CatalogResidue{}, 0, false
	}
}

func decodeResidueName(bytes []byte) (string, bool) {
	units := make([]uint16, len(bytes)/2)
	for i := range units {
		units[i] = be16(bytes, 2*i)
	}
	if !validUTF16(units) {
		return "", false
	}
	name := decodeUnits(units)
	if name == "" {
		return "", false
	}
	for _, r := range name {
		if r == 0 {
			return "", false
		}
	}
	return name, true
}

func validUTF16(units []uint16) bool {
	for i := 0; i < len(units); i++ {
		unit := units[i]
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return false
			}
			i++
		case unit >= 0xDC00 && unit <= 0xDFFF:
			return false
		}
	}
	return true
}

// RecoverResidue weighs what a stale file record still names, if the
// allocation map says every block is free.
func (v *Volume) RecoverResidue(residue *CatalogResidue, free *FreeSpace, limit uint64) (ResidueRecovery, error) {
	verdict, _, err := v.RecoverResidueWithStats(residue, free, limit)
	return verdict, err
}

// RecoverResidueWithStats is RecoverResidue plus what the overflow lookup cost.
func (v *Volume) RecoverResidueWithStats(residue *CatalogResidue, free *FreeSpace, limit uint64) (ResidueRecovery, OverflowStats, error) {
	stats := OverflowStats{}
	verdict, err := v.recoverResidue(residue, free, limit, &stats)
	return verdict, stats, err
}

func (v *Volume) recoverResidue(residue *CatalogResidue, free *FreeSpace, limit uint64, stats *OverflowStats) (ResidueRecovery, error) {
	if residue == nil || residue.Kind != ResidueFile || residue.Fork == nil {
		return ResidueRecovery{Kind: ResidueNothing}, nil
	}
	fork := *residue.Fork
	if fork.LogicalSize == 0 || fork.TotalBlocks == 0 {
		return ResidueRecovery{Kind: ResidueNothing}, nil
	}
	blockSize := uint64(v.header.BlockSize)
	if blockSize == 0 {
		return ResidueRecovery{}, invalidf("the volume header declares a zero block size")
	}
	declared := uint64(fork.TotalBlocks)
	inline := fork.InlineExtents()
	var inlineBlocks uint64
	for _, extent := range inline {
		inlineBlocks += uint64(extent.BlockCount)
	}
	if inlineBlocks > declared {
		return ResidueRecovery{Kind: ResidueExtentsDisagree, Inline: inlineBlocks, DeclaredBlocks: declared}, nil
	}
	extents := inline
	if inlineBlocks < declared {
		stats.Files = 1
		if residue.ID == nil {
			stats.Rejected++
			return ResidueRecovery{
				Kind:   ResidueOverflowUnreadable,
				Block:  uint32(inlineBlocks),
				Reason: "the stale file record names no CNID",
			}, nil
		}
		resolved, refusal := v.walkOverflow(*residue.ID, fork, inline, stats)
		if refusal != nil {
			return *refusal, nil
		}
		extents = resolved
	}

	var covered uint64
	for _, extent := range extents {
		covered += uint64(extent.BlockCount)
	}
	if covered > declared {
		return ResidueRecovery{Kind: ResidueOverflowBeyondFork, Covered: uint32(covered), Declared: fork.TotalBlocks}, nil
	}
	if covered < declared {
		return ResidueRecovery{Kind: ResidueOverflowMissing, Block: uint32(covered), Declared: fork.TotalBlocks}, nil
	}
	capacity := covered * blockSize
	if fork.LogicalSize > capacity {
		return ResidueRecovery{Kind: ResidueSizeBeyondExtents, SizeBytes: fork.LogicalSize, Capacity: capacity}, nil
	}
	if refusal := validateResidueExtents(extents, uint64(v.header.TotalBlocks)); refusal != nil {
		return *refusal, nil
	}
	if free == nil {
		return ResidueRecovery{}, invalidf("residue recovery needs an allocation map")
	}
	if inUse := residueAllocatedBlocks(extents, free, blockSize); inUse > 0 {
		return ResidueRecovery{Kind: ResidueInUse, InUse: inUse, Blocks: declared}, nil
	}

	take := fork.LogicalSize
	if take > limit {
		take = limit
	}
	bytes := make([]byte, 0, int(take))
	remaining := take
	for _, extent := range extents {
		if remaining == 0 {
			break
		}
		available := uint64(extent.BlockCount) * blockSize
		chunk := remaining
		if chunk > available {
			chunk = available
		}
		start := len(bytes)
		bytes = append(bytes, make([]byte, int(chunk))...)
		if err := source.ReadExactAt(v.src, uint64(extent.StartBlock)*blockSize, bytes[start:]); err != nil {
			return ResidueRecovery{}, err
		}
		remaining -= chunk
	}
	return ResidueRecovery{
		Kind:      ResidueContent,
		Bytes:     bytes,
		Size:      fork.LogicalSize,
		Truncated: take < fork.LogicalSize,
	}, nil
}

func (v *Volume) walkOverflow(fileID uint32, fork Fork, inline []Extent, stats *OverflowStats) ([]Extent, *ResidueRecovery) {
	declared := uint64(fork.TotalBlocks)
	extents := append([]Extent(nil), inline...)
	var covered uint64
	for _, extent := range extents {
		covered += uint64(extent.BlockCount)
	}
	for covered < declared {
		if stats.Lookups >= MaxOverflowLookups || len(extents) > MaxResidueExtents {
			stats.Rejected++
			return nil, &ResidueRecovery{Kind: ResidueOverflowLoop, Block: uint32(covered)}
		}
		stats.Lookups++
		block := uint32(covered)
		key := extentsKey(ForkData, fileID, block)
		_, data, found, err := v.extents.Lookup(v.src, key, bytesCompare)
		if err != nil {
			stats.Rejected++
			return nil, &ResidueRecovery{Kind: ResidueOverflowUnreadable, Block: block, Reason: err.Error()}
		}
		if !found {
			stats.Rejected++
			return nil, &ResidueRecovery{Kind: ResidueOverflowMissing, Block: block, Declared: fork.TotalBlocks}
		}
		if len(data) < InlineExtents*8 {
			stats.Rejected++
			return nil, &ResidueRecovery{Kind: ResidueOverflowShort, Block: block, ShortBytes: len(data)}
		}
		more, err := ParseExtentsRecord(data)
		if err != nil {
			stats.Rejected++
			return nil, &ResidueRecovery{Kind: ResidueOverflowUnreadable, Block: block, Reason: err.Error()}
		}
		var blocks uint64
		for _, extent := range more {
			blocks += uint64(extent.BlockCount)
		}
		if blocks == 0 {
			stats.Rejected++
			return nil, &ResidueRecovery{Kind: ResidueOverflowLoop, Block: block}
		}
		next := covered + blocks
		if next > declared {
			stats.Rejected++
			return nil, &ResidueRecovery{Kind: ResidueOverflowBeyondFork, Covered: uint32(next), Declared: fork.TotalBlocks}
		}
		stats.ExtentsUsed += uint64(len(more))
		extents = append(extents, more...)
		covered = next
	}
	return extents, nil
}

func validateResidueExtents(extents []Extent, volumeBlocks uint64) *ResidueRecovery {
	for _, extent := range extents {
		if extent.StartBlock == 0 {
			return &ResidueRecovery{Kind: ResidueHole, Block: 0}
		}
		start := uint64(extent.StartBlock)
		count := uint64(extent.BlockCount)
		if start+count < start || start+count > volumeBlocks {
			return &ResidueRecovery{Kind: ResidueOutsideVolume, Block: extent.StartBlock}
		}
	}
	spans := make([]Extent, 0, len(extents))
	for _, extent := range extents {
		if extent.BlockCount > 0 {
			spans = append(spans, extent)
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].StartBlock < spans[j].StartBlock })
	for i := 1; i < len(spans); i++ {
		if spans[i].StartBlock < spans[i-1].EndBlock() {
			return &ResidueRecovery{Kind: ResidueOverlap, Block: spans[i].StartBlock}
		}
	}
	return nil
}

func residueAllocatedBlocks(extents []Extent, free *FreeSpace, blockSize uint64) uint64 {
	var inUse uint64
	for _, extent := range extents {
		start := uint64(extent.StartBlock) * blockSize
		length := uint64(extent.BlockCount) * blockSize
		if !free.IsFree(start, length) {
			inUse += uint64(extent.BlockCount)
		}
	}
	return inUse
}
