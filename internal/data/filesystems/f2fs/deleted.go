package f2fs

import (
	"sort"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Deleted-scan bounds.
const (
	DefaultScanLimit   uint64 = 256 << 20
	MaxCandidates      uint64 = 65536
	MaxRecords                = 65536
	MaxLiveDirectories        = 65536
	MaxParentDepth            = 255
	MaxContentBlocks   uint64 = 1 << 20
	// MaxTimestamp is 9999-12-31T23:59:59Z.
	MaxTimestamp uint64 = 253402300799
)

// ScanCap is the bound that stopped a scan.
type ScanCap string

const (
	ScanCapScanLimit      ScanCap = "scan_limit"
	ScanCapCandidateLimit ScanCap = "candidate_limit"
	ScanCapRecordLimit    ScanCap = "record_limit"
)

// DeletedOptions is what a scan may spend.
type DeletedOptions struct {
	ScanLimit     uint64
	MaxCandidates uint64
	MaxRecords    int
}

// DefaultDeletedOptions returns the Rust default bounds.
func DefaultDeletedOptions() DeletedOptions {
	return DeletedOptions{
		ScanLimit:     DefaultScanLimit,
		MaxCandidates: MaxCandidates,
		MaxRecords:    MaxRecords,
	}
}

// DeletedStats records what the scan did.
type DeletedStats struct {
	ScannedBlocks       uint64
	ScannedBytes        uint64
	FreeRuns            uint64
	Candidates          uint64
	NodeCandidates      uint64
	DirectoryCandidates uint64
	DuplicateCandidates uint64
	RejectedFooter      uint64
	RejectedIdentity    uint64
	RejectedType        uint64
	RejectedBounds      uint64
	RejectedInode       uint64
	RejectedDirectory   uint64
	RejectedUnreadable  uint64
	CappedAt            ScanCap
}

// CapReached reports whether a bound stopped the scan.
func (s DeletedStats) CapReached() bool { return s.CappedAt != "" }

// EntryState says whether an entry still names a file, is gone, or cannot be
// placed.
type EntryState string

const (
	// EntryDeleted means the live tree no longer holds this (parent, name) for
	// this inode.
	EntryDeleted EntryState = "deleted"
	// EntryStillLive means the live tree still holds the same name for the same
	// inode.
	EntryStillLive EntryState = "still_live"
	// EntryUnresolved means the name was recovered but its parent chain cannot
	// be proven.
	EntryUnresolved EntryState = "unresolved"
)

// ContentState says whether a recovered inode's bytes can be served.
type ContentState struct {
	metadataOnly bool
	reason       string
}

// RecoverableContent returns a content state whose bytes can be served.
func RecoverableContent() ContentState { return ContentState{} }

// MetadataOnlyContent returns a content state whose bytes are not offered, for
// the named reason.
func MetadataOnlyContent(reason string) ContentState {
	return ContentState{metadataOnly: true, reason: reason}
}

// IsRecoverable reports whether the bytes can be served.
func (c ContentState) IsRecoverable() bool { return !c.metadataOnly }

// Reason returns why the bytes are not offered, or the empty string.
func (c ContentState) Reason() string { return c.reason }

// RecoveredInode is one inode lifted from a free node block.
type RecoveredInode struct {
	Ino      uint32
	NID      uint32
	Inode    *Inode
	Physical uint64
	Block    uint32
	Content  ContentState
	Path     string
	HasPath  bool
}

// RecoveredEntry is one (parent, name) -> child entry lifted from a stale
// directory block.
type RecoveredEntry struct {
	Parent     uint32
	Name       string
	Child      uint32
	FileType   uint8
	Physical   uint64
	Block      uint32
	State      EntryState
	Path       string
	HasPath    bool
	Components []string
	Reason     string
	Content    ContentState
	// Deleted is true unless the live tree still holds the same name.
	Deleted bool
}

// DeletedScan is everything one bounded free-block scan proved.
type DeletedScan struct {
	Stats   DeletedStats
	Inodes  []RecoveredInode
	Entries []RecoveredEntry
	nodes   map[uint32]staleNode
}

// DeletedEntries returns the entries that are not still live.
func (s *DeletedScan) DeletedEntries() []RecoveredEntry {
	out := make([]RecoveredEntry, 0, len(s.Entries))
	for _, entry := range s.Entries {
		if entry.State != EntryStillLive {
			out = append(out, entry)
		}
	}
	return out
}

// Inode returns the recovered inode numbered ino, if one was found.
func (s *DeletedScan) Inode(ino uint32) *RecoveredInode {
	for index := range s.Inodes {
		if s.Inodes[index].Ino == ino {
			return &s.Inodes[index]
		}
	}
	return nil
}

type staleNode struct {
	block uint32
	ino   uint32
	flag  uint32
}

type rawInode struct {
	inode    *Inode
	physical uint64
	block    uint32
	cpVer    uint64
}

type rawEntry struct {
	parent   uint32
	name     string
	child    uint32
	fileType uint8
	physical uint64
	block    uint32
}

type recoveredName struct {
	parent uint32
	name   string
}

type liveParent struct {
	parent uint32
	name   string
}

type rawKey struct {
	parent uint32
	name   string
	child  uint32
}

type liveTree struct {
	directories map[uint32][]DirEntry
	parents     map[uint32]liveParent
}

func (l *liveTree) entry(parent uint32, name string) *DirEntry {
	listing := l.directories[parent]
	for index := range listing {
		if !IsDot(listing[index].Name) && string(listing[index].Name) == name {
			return &listing[index]
		}
	}
	return nil
}

type mainArea struct {
	start uint64
	end   uint64
}

func (m mainArea) contains(block uint32) bool {
	return uint64(block) >= m.start && uint64(block) < m.end
}

// DeletedScan searches free blocks for stale node and directory blocks and
// decodes the deleted records they still hold.
func (v *Volume) DeletedScan(options *DeletedOptions) (*DeletedScan, error) {
	opts := DefaultDeletedOptions()
	if options != nil {
		opts = *options
	}
	free, err := v.FreeSpace()
	if err != nil {
		return nil, err
	}
	blockSize := uint64(v.BlockSize())
	sb := v.superblock
	main := mainArea{
		start: uint64(sb.MainBlkaddr),
		end:   uint64(sb.MainBlkaddr) + uint64(sb.SegmentCountMain)*uint64(sb.BlocksPerSegment),
	}
	blockCount := sb.BlockCount
	live := v.liveTree()

	var stats DeletedStats
	inodes := make(map[uint32]rawInode)
	entries := make(map[rawKey]rawEntry)
	nodes := make(map[uint32]staleNode)
	var accepted uint64

scanRuns:
	for _, run := range free.Runs() {
		stats.FreeRuns++
		at := ((run.Offset + blockSize - 1) / blockSize) * blockSize
		for at+blockSize <= run.End() {
			if stats.ScannedBytes >= opts.ScanLimit {
				stats.CappedAt = ScanCapScanLimit
				break scanRuns
			}
			if accepted >= opts.MaxCandidates {
				stats.CappedAt = ScanCapCandidateLimit
				break scanRuns
			}
			stats.ScannedBlocks++
			stats.ScannedBytes += blockSize
			blockNumber64 := at / blockSize
			if blockNumber64 > uint64(^uint32(0)) {
				at += blockSize
				continue
			}
			blockNumber := uint32(blockNumber64)
			raw, err := source.ReadVecAt(v.source, at, blockSize)
			if err != nil {
				stats.RejectedUnreadable++
				at += blockSize
				continue
			}
			if looksLikeDirectory(raw, v.BlockSize()) {
				parent, listed, err := validateStaleDirectory(raw, v.BlockSize())
				if err != nil {
					stats.RejectedDirectory++
				} else {
					accepted++
					stats.DirectoryCandidates++
					for _, entry := range listed {
						if IsDot(entry.Name) {
							continue
						}
						identity := rawKey{parent: parent, name: string(entry.Name), child: entry.Ino}
						if _, exists := entries[identity]; !exists &&
							len(inodes)+len(entries) >= opts.MaxRecords {
							stats.CappedAt = ScanCapRecordLimit
							break scanRuns
						}
						if existing, exists := entries[identity]; exists {
							stats.DuplicateCandidates++
							if at < existing.physical {
								entries[identity] = rawEntry{
									parent: parent, name: string(entry.Name), child: entry.Ino,
									fileType: entry.FileType, physical: at, block: blockNumber,
								}
							}
						} else {
							entries[identity] = rawEntry{
								parent: parent, name: string(entry.Name), child: entry.Ino,
								fileType: entry.FileType, physical: at, block: blockNumber,
							}
						}
					}
				}
				at += blockSize
				continue
			}
			footer, ok := parseNodeFooterSafe(raw, v.BlockSize())
			if !ok {
				stats.RejectedFooter++
				at += blockSize
				continue
			}
			if footer.NID == 0 || footer.Ino == 0 {
				if footer.NID == 0 && footer.Ino == 0 {
					stats.RejectedFooter++
				} else {
					stats.RejectedIdentity++
				}
				at += blockSize
				continue
			}
			if !nextBlockIsKnown(footer.NextBlkaddr, blockCount) {
				stats.RejectedFooter++
				at += blockSize
				continue
			}
			switch {
			case footer.Flag == 0:
				inode, ok := gateInode(raw, v.BlockSize(), footer, main, v, &stats)
				if !ok {
					at += blockSize
					continue
				}
				if _, exists := inodes[inode.Ino]; !exists &&
					len(inodes)+len(entries) >= opts.MaxRecords {
					stats.CappedAt = ScanCapRecordLimit
					break scanRuns
				}
				accepted++
				stats.Candidates++
				existing, exists := inodes[inode.Ino]
				if !exists {
					inodes[inode.Ino] = rawInode{inode: inode, physical: at, block: blockNumber, cpVer: footer.CPVer}
				} else {
					stats.DuplicateCandidates++
					if isNewer(footer.CPVer, at, existing.cpVer, existing.physical) {
						inodes[inode.Ino] = rawInode{inode: inode, physical: at, block: blockNumber, cpVer: footer.CPVer}
					}
				}
			case footer.Flag >= 1 && footer.Flag <= 3:
				if !gateNodeEntries(raw, v.BlockSize(), footer.Flag, main, v) {
					stats.RejectedBounds++
					at += blockSize
					continue
				}
				accepted++
				stats.NodeCandidates++
				stale := staleNode{block: blockNumber, ino: footer.Ino, flag: footer.Flag}
				if existing, exists := nodes[footer.NID]; exists {
					stats.DuplicateCandidates++
					if stale.flag != 3 && existing.flag == 3 {
						nodes[footer.NID] = stale
					}
				} else {
					nodes[footer.NID] = stale
				}
			default:
				stats.RejectedFooter++
			}
			at += blockSize
		}
	}

	recoveredInodes := make([]RecoveredInode, 0, len(inodes))
	for _, raw := range inodes {
		content := v.contentState(free, nodes, raw.inode, raw.physical, main)
		recoveredInodes = append(recoveredInodes, RecoveredInode{
			Ino:      raw.inode.Ino,
			NID:      raw.inode.NID,
			Inode:    raw.inode,
			Physical: raw.physical,
			Block:    raw.block,
			Content:  content,
		})
	}

	recoveredNames := recoveredNamesByChild(entries)
	recoveredEntries := make([]RecoveredEntry, 0, len(entries))
	for _, raw := range entries {
		liveEntry := live.entry(raw.parent, raw.name)
		var state EntryState
		var liveReason string
		if liveEntry != nil {
			if liveEntry.Ino == raw.child {
				state = EntryStillLive
			} else {
				state = EntryDeleted
				liveReason = "the live name now refers to inode " + itoa(int(liveEntry.Ino))
			}
		} else {
			state = EntryDeleted
		}
		var path string
		var hasPath bool
		var components []string
		var pathReason string
		if state != EntryStillLive {
			path, hasPath, components, pathReason = resolvePath(
				raw.parent, raw.name, recoveredNames, live.parents, v.RootIno())
		}
		var inode *RecoveredInode
		for index := range recoveredInodes {
			if recoveredInodes[index].Ino == raw.child {
				inode = &recoveredInodes[index]
				break
			}
		}
		var content ContentState
		var contentReason string
		if inode != nil {
			content = inode.Content
			contentReason = inode.Content.Reason()
		} else {
			content = MetadataOnlyContent("no recovered inode " + itoa(int(raw.child)) + " in free space")
		}
		if state == EntryDeleted && !hasPath {
			state = EntryUnresolved
		}
		reason := ""
		switch state {
		case EntryUnresolved:
			if pathReason != "" {
				reason = pathReason
			} else {
				reason = liveReason
			}
		case EntryStillLive:
			reason = ""
		case EntryDeleted:
			if liveReason != "" {
				reason = liveReason
			} else {
				reason = contentReason
			}
		}
		recoveredEntries = append(recoveredEntries, RecoveredEntry{
			Parent: raw.parent, Name: raw.name, Child: raw.child, FileType: raw.fileType,
			Physical: raw.physical, Block: raw.block, State: state,
			Path: path, HasPath: hasPath, Components: components, Reason: reason,
			Content: content, Deleted: state != EntryStillLive,
		})
	}

	sort.Slice(recoveredEntries, func(i, j int) bool {
		a, b := recoveredEntries[i], recoveredEntries[j]
		if a.Parent != b.Parent {
			return a.Parent < b.Parent
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Child < b.Child
	})
	paths := make(map[uint32]string)
	for _, entry := range recoveredEntries {
		if entry.HasPath {
			if _, exists := paths[entry.Child]; !exists {
				paths[entry.Child] = entry.Path
			}
		}
	}
	for index := range recoveredInodes {
		if path, ok := paths[recoveredInodes[index].Ino]; ok {
			recoveredInodes[index].Path = path
			recoveredInodes[index].HasPath = true
		}
	}
	sort.Slice(recoveredInodes, func(i, j int) bool {
		return recoveredInodes[i].Ino < recoveredInodes[j].Ino
	})

	return &DeletedScan{
		Stats:   stats,
		Inodes:  recoveredInodes,
		Entries: recoveredEntries,
		nodes:   nodes,
	}, nil
}

// DeletedFileSource returns a byte source over a recovered inode's content.
func (v *Volume) DeletedFileSource(scan *DeletedScan, ino uint32) (source.ByteSource, error) {
	recovered := scan.Inode(ino)
	if recovered == nil {
		return nil, invalidf("no recovered inode %d in free space; scan first", ino)
	}
	if !recovered.Content.IsRecoverable() {
		return nil, unsupportedf("deleted inode %d cannot be exported: %s", ino, recovered.Content.Reason())
	}
	if !recovered.Inode.IsRegular() {
		return nil, unsupportedf("recovered inode %d is a %s, not a regular file", ino, fileTypeName(recovered.Inode.Mode))
	}
	free, err := v.FreeSpace()
	if err != nil {
		return nil, err
	}
	sb := v.superblock
	main := mainArea{
		start: uint64(sb.MainBlkaddr),
		end:   uint64(sb.MainBlkaddr) + uint64(sb.SegmentCountMain)*uint64(sb.BlocksPerSegment),
	}
	blockMap := newDeletedMap(v.source, v.BlockSize(), free, scan.nodes, recovered.Inode, recovered.Physical, main)
	if err := blockMap.checkContent(); err != nil {
		return nil, unsupportedf("deleted inode %d cannot be exported: %v", ino, err)
	}
	id := source.ID(v.fileID.Add(1))
	return &DeletedFileSource{id: id, blockMap: blockMap, ino: ino}, nil
}

func (v *Volume) liveTree() *liveTree {
	root := v.RootIno()
	directories := make(map[uint32][]DirEntry)
	parents := make(map[uint32]liveParent)
	queue := []uint32{root}
	visited := map[uint32]bool{root: true}
	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		if len(directories) >= MaxLiveDirectories {
			break
		}
		listing, err := v.ReadDir(directory)
		if err != nil {
			continue
		}
		for _, entry := range listing {
			if IsDot(entry.Name) {
				continue
			}
			if _, exists := parents[entry.Ino]; !exists {
				parents[entry.Ino] = liveParent{parent: directory, name: string(entry.Name)}
			}
			inode, err := v.Inode(entry.Ino)
			if err == nil && inode.IsDir() && !visited[entry.Ino] {
				visited[entry.Ino] = true
				queue = append(queue, entry.Ino)
			}
		}
		directories[directory] = listing
	}
	return &liveTree{directories: directories, parents: parents}
}

func (v *Volume) contentState(free *FreeSpace, nodes map[uint32]staleNode, inode *Inode, physical uint64, main mainArea) ContentState {
	if !inode.IsRegular() {
		return MetadataOnlyContent("the inode is a " + fileTypeName(inode.Mode) + ", not a regular file")
	}
	if inode.IsCompressed() {
		return MetadataOnlyContent("the inode records compressed blocks (log cluster size " +
			itoa(int(inode.LogClusterSize)) + "), which this recovery pass does not decode")
	}
	if inode.InlineFlags&InlineData != 0 {
		if inode.Inline == nil {
			return MetadataOnlyContent("the inode is marked as holding inline data but its bytes were not decoded")
		}
		if err := inode.CheckReadable(); err != nil {
			return MetadataOnlyContent(err.Error())
		}
		return RecoverableContent()
	}
	blockSize := uint64(inode.BlockSize)
	needed := (inode.Size + blockSize - 1) / blockSize
	if needed > MaxContentBlocks {
		return MetadataOnlyContent("the " + uintString(inode.Size) + "-byte file needs " +
			uintString(needed) + " blocks, above the " + uintString(MaxContentBlocks) + "-block content check")
	}
	blockMap := newDeletedMap(v.source, inode.BlockSize, free, nodes, inode, physical, main)
	for index := uint64(0); index < needed; index++ {
		if _, _, err := blockMap.dataBlock(index); err != nil {
			return MetadataOnlyContent(err.Error())
		}
	}
	return RecoverableContent()
}

func parseNodeFooterSafe(raw []byte, blockSize uint32) (NodeFooter, bool) {
	if int(blockSize) <= NodeFooterSize {
		return NodeFooter{}, false
	}
	footer, err := ParseNodeFooter(raw, int(blockSize))
	return footer, err == nil
}

func nextBlockIsKnown(next uint32, blockCount uint64) bool {
	return next == NullAddr || next == NewAddr || uint64(next) < blockCount
}

func gateInode(raw []byte, blockSize uint32, footer NodeFooter, main mainArea, v *Volume, stats *DeletedStats) (*Inode, bool) {
	if footer.NID != footer.Ino {
		stats.RejectedIdentity++
		return nil, false
	}
	inode, err := ParseInode(raw, blockSize, footer.NID)
	if err != nil {
		stats.RejectedInode++
		return nil, false
	}
	if fileTypeBits(inode.Mode) == 0 {
		stats.RejectedType++
		return nil, false
	}
	if !timesArePlausible(inode) {
		stats.RejectedBounds++
		return nil, false
	}
	if inode.Size > maximumFileBytes(inode) {
		stats.RejectedBounds++
		return nil, false
	}
	inlineContent := inode.Inline != nil &&
		(inode.InlineFlags&InlineData != 0 || inode.IsSymlink())
	if !inlineContent {
		for _, address := range inode.Addresses {
			if !addressIsKnown(address, main) {
				stats.RejectedBounds++
				return nil, false
			}
		}
	}
	for _, nid := range inode.NIDs {
		if nid != NullAddr {
			if _, err := v.nat.BlockFor(nid); err != nil {
				stats.RejectedBounds++
				return nil, false
			}
		}
	}
	return inode, true
}

func gateNodeEntries(raw []byte, blockSize uint32, flag uint32, main mainArea, v *Volume) bool {
	if flag == 3 {
		return true
	}
	count := NodeEntries(blockSize)
	for index := uint64(0); index < count; index++ {
		address, err := u32At(raw, int(index)*4)
		if err != nil {
			return false
		}
		switch flag {
		case 1:
			if !addressIsKnown(address, main) {
				return false
			}
		case 2:
			if address != NullAddr {
				if _, err := v.nat.BlockFor(address); err != nil {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func addressIsKnown(address uint32, main mainArea) bool {
	switch address {
	case NullAddr, NewAddr, CompressAddr:
		return true
	default:
		return main.contains(address)
	}
}

func maximumFileBytes(inode *Inode) uint64 {
	direct := uint64(inode.DirectCapacity())
	first := NodeEntries(inode.BlockSize)
	second := first * first
	third := first * second
	return (direct + 2*first + 2*second + third) * uint64(inode.BlockSize)
}

func timesArePlausible(inode *Inode) bool {
	ok := func(t F2fsTime) bool {
		return t.Seconds <= MaxTimestamp && t.Nanos < 1_000_000_000
	}
	if !ok(inode.Atime) || !ok(inode.Ctime) || !ok(inode.Mtime) {
		return false
	}
	return inode.Crtime == nil || ok(*inode.Crtime)
}

func fileTypeBits(mode uint16) uint16 {
	switch mode & SIFMT {
	case SIFDIR, SIFREG, SIFLNK, 0x1000, 0x2000, 0x6000, 0xC000:
		return mode & SIFMT
	default:
		return 0
	}
}

func fileTypeName(mode uint16) string {
	switch mode & SIFMT {
	case SIFDIR:
		return "directory"
	case SIFREG:
		return "regular file"
	case SIFLNK:
		return "symbolic link"
	case 0x1000:
		return "fifo"
	case 0x2000:
		return "character device"
	case 0x6000:
		return "block device"
	case 0xC000:
		return "socket"
	default:
		return "unknown type"
	}
}

func isNewer(cpVer, physical, oldCpVer, oldPhysical uint64) bool {
	return cpVer > oldCpVer || (cpVer == oldCpVer && physical < oldPhysical)
}

func looksLikeDirectory(raw []byte, blockSize uint32) bool {
	if int(blockSize) != DirBlockSize || len(raw) < DirBlockSize {
		return false
	}
	dotOK := func(slot int, name string) bool {
		if raw[slot/8]&(1<<uint(slot%8)) == 0 {
			return false
		}
		at := DirEntryOffset + slot*DirEntrySize
		length := int(uint16(raw[at+8]) | uint16(raw[at+9])<<8)
		if length != len(name) {
			return false
		}
		nameAt := DirFilenameOffset + slot*DirSlotSize
		ino := uint32(raw[at+4]) | uint32(raw[at+5])<<8 | uint32(raw[at+6])<<16 | uint32(raw[at+7])<<24
		return string(raw[nameAt:nameAt+length]) == name && raw[at+10] == DTDir && ino != 0
	}
	return dotOK(0, ".") && dotOK(1, "..")
}

func validateStaleDirectory(raw []byte, blockSize uint32) (uint32, []DirEntry, error) {
	entries, err := ParseDirBlock(raw, blockSize)
	if err != nil {
		return 0, nil, err
	}
	if len(entries) < 3 {
		return 0, nil, invalidf("the stale directory block holds only %d entries", len(entries))
	}
	if string(entries[0].Name) != "." || string(entries[1].Name) != ".." ||
		entries[0].FileType != DTDir || entries[1].FileType != DTDir ||
		entries[0].Ino == 0 || entries[1].Ino == 0 {
		return 0, nil, invalidf("the stale directory block does not begin with `.` and `..`")
	}
	for _, entry := range entries {
		if entry.Ino == 0 {
			return 0, nil, invalidf("the stale directory slot %d names inode zero", entry.Slot)
		}
		if strings.IndexByte(string(entry.Name), 0) >= 0 || strings.IndexByte(string(entry.Name), '/') >= 0 {
			return 0, nil, invalidf("the stale directory slot %d holds a name that cannot be a path component", entry.Slot)
		}
		if !knownFileType(entry.FileType) {
			return 0, nil, invalidf("the stale directory slot %d names unknown type %d", entry.Slot, entry.FileType)
		}
	}
	return entries[0].Ino, entries, nil
}

func knownFileType(fileType uint8) bool {
	switch fileType {
	case DTUnknown, DTFifo, DTChr, DTDir, DTBlk, DTReg, DTLnk, DTSock:
		return true
	default:
		return false
	}
}

func recoveredNamesByChild(entries map[rawKey]rawEntry) map[uint32][]recoveredName {
	out := make(map[uint32][]recoveredName)
	for _, entry := range entries {
		pair := recoveredName{parent: entry.parent, name: entry.name}
		names := out[entry.child]
		found := false
		for _, existing := range names {
			if existing == pair {
				found = true
				break
			}
		}
		if !found {
			names = append(names, pair)
			out[entry.child] = names
		}
	}
	for child, names := range out {
		sort.Slice(names, func(i, j int) bool {
			if names[i].parent != names[j].parent {
				return names[i].parent < names[j].parent
			}
			return names[i].name < names[j].name
		})
		out[child] = names
	}
	return out
}

func resolvePath(parent uint32, name string, recovered map[uint32][]recoveredName, liveParents map[uint32]liveParent, root uint32) (string, bool, []string, string) {
	components := []string{name}
	current := parent
	seen := make(map[uint32]bool)
	for step := 0; step < MaxParentDepth; step++ {
		if current == root {
			reverseStrings(components)
			return "/" + strings.Join(components, "/"), true, components, ""
		}
		if seen[current] {
			reverseStrings(components)
			return "", false, components, "the parent chain loops at inode " + itoa(int(current))
		}
		seen[current] = true
		recoveredNames, hasRecovered := recovered[current]
		liveName, hasLive := liveParents[current]
		var nextParent uint32
		var nextName string
		switch {
		case hasRecovered && len(recoveredNames) == 1:
			nextParent = recoveredNames[0].parent
			nextName = recoveredNames[0].name
		case hasLive:
			nextParent = liveName.parent
			nextName = liveName.name
		case hasRecovered && len(recoveredNames) > 1:
			reverseStrings(components)
			return "", false, components, "inode " + itoa(int(current)) + " has " +
				itoa(len(recoveredNames)) + " recovered names, so the parent is ambiguous"
		default:
			reverseStrings(components)
			return "", false, components, "parent inode " + itoa(int(current)) +
				" is not in the live tree or any recovered record"
		}
		components = append(components, nextName)
		current = nextParent
	}
	reverseStrings(components)
	return "", false, components, "the parent chain is deeper than " + itoa(MaxParentDepth) + " steps"
}

func reverseStrings(values []string) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func keyOf(parent uint32, name string, child uint32) string {
	return itoa(int(parent)) + "\x00" + name + "\x00" + itoa(int(child))
}

func atoiOrZero(text string) uint32 {
	var value uint64
	for index := 0; index < len(text); index++ {
		ch := text[index]
		if ch < '0' || ch > '9' {
			return 0
		}
		value = value*10 + uint64(ch-'0')
		if value > uint64(^uint32(0)) {
			return 0
		}
	}
	return uint32(value)
}

func numericLess(a, b string) bool { return atoiOrZero(a) < atoiOrZero(b) }

// deletedMap is a recovered inode's block map, resolved through the free node
// index rather than the live node-address table.
type deletedMap struct {
	source         source.ByteSource
	blockSize      uint32
	entriesPerNode uint64
	addresses      []uint32
	nids           [NIDsPerInode]uint32
	inline         []byte
	inlineAt       uint64
	length         uint64
	free           *FreeSpace
	nodes          map[uint32]staleNode
	ino            uint32
	main           mainArea
	cacheNID       uint32
	cacheValid     bool
	cacheData      []uint32
}

func newDeletedMap(src source.ByteSource, blockSize uint32, free *FreeSpace, nodes map[uint32]staleNode, inode *Inode, physical uint64, main mainArea) *deletedMap {
	var inlineAt uint64
	if inode.Inline != nil {
		inlineAt = physical + uint64(inode.AddressesOffset)
	}
	return &deletedMap{
		source:         src,
		blockSize:      blockSize,
		entriesPerNode: NodeEntries(blockSize),
		addresses:      append([]uint32(nil), inode.Addresses...),
		nids:           inode.NIDs,
		inline:         append([]byte(nil), inode.Inline...),
		inlineAt:       inlineAt,
		length:         inode.Size,
		free:           free,
		nodes:          nodes,
		ino:            inode.Ino,
		main:           main,
	}
}

func (m *deletedMap) isInline() bool { return m.inline != nil }

func (m *deletedMap) checkContent() error {
	if m.isInline() {
		return nil
	}
	blockSize := uint64(m.blockSize)
	needed := (m.length + blockSize - 1) / blockSize
	if needed > MaxContentBlocks {
		return unsupportedf("the %d-byte file needs %d blocks, above the %d-block content check",
			m.length, needed, MaxContentBlocks)
	}
	for index := uint64(0); index < needed; index++ {
		if _, _, err := m.dataBlock(index); err != nil {
			return err
		}
	}
	return nil
}

func (m *deletedMap) nodeEntries(nid uint32) ([]uint32, error) {
	if m.cacheValid && m.cacheNID == nid {
		return m.cacheData, nil
	}
	node, ok := m.nodes[nid]
	if !ok {
		return nil, unsupportedf("the indirect node %d is not among the free node blocks this scan proved", nid)
	}
	if node.ino != m.ino {
		return nil, invalidf("the indirect node %d belongs to inode %d, not %d", nid, node.ino, m.ino)
	}
	at := uint64(node.block) * uint64(m.blockSize)
	if !m.free.IsFree(at, uint64(m.blockSize)) {
		return nil, unsupportedf("the indirect node %d at block %d is still allocated", nid, node.block)
	}
	bytes, err := source.ReadVecAt(m.source, at, uint64(m.blockSize))
	if err != nil {
		return nil, err
	}
	footer, err := ParseNodeFooter(bytes, int(m.blockSize))
	if err != nil {
		return nil, err
	}
	if footer.NID != nid || footer.Ino != m.ino {
		return nil, invalidf("the node block read for id %d carries id %d and inode %d", nid, footer.NID, footer.Ino)
	}
	entries := make([]uint32, m.entriesPerNode)
	for index := range entries {
		entries[index], err = u32At(bytes, index*4)
		if err != nil {
			return nil, err
		}
	}
	m.cacheNID = nid
	m.cacheValid = true
	m.cacheData = entries
	return entries, nil
}

func (m *deletedMap) rawAddress(index uint64) (uint32, error) {
	direct := uint64(len(m.addresses))
	first := m.entriesPerNode
	if index < direct {
		return m.addresses[index], nil
	}
	rest := index - direct
	if rest < 2*first {
		node := m.nids[rest/first]
		if node == NullAddr {
			return NullAddr, nil
		}
		entries, err := m.nodeEntries(node)
		if err != nil {
			return 0, err
		}
		return entries[rest%first], nil
	}
	rest -= 2 * first
	second := first * first
	if rest < 2*second {
		upper := m.nids[2+rest/second]
		if upper == NullAddr {
			return NullAddr, nil
		}
		indirect, err := m.nodeEntries(upper)
		if err != nil {
			return 0, err
		}
		lower := indirect[(rest%second)/first]
		if lower == NullAddr {
			return NullAddr, nil
		}
		entries, err := m.nodeEntries(lower)
		if err != nil {
			return 0, err
		}
		return entries[rest%first], nil
	}
	rest -= 2 * second
	third := first * second
	if rest < third {
		if m.nids[4] == NullAddr {
			return NullAddr, nil
		}
		double, err := m.nodeEntries(m.nids[4])
		if err != nil {
			return 0, err
		}
		upper := double[rest/second]
		if upper == NullAddr {
			return NullAddr, nil
		}
		indirect, err := m.nodeEntries(upper)
		if err != nil {
			return 0, err
		}
		lower := indirect[(rest%second)/first]
		if lower == NullAddr {
			return NullAddr, nil
		}
		entries, err := m.nodeEntries(lower)
		if err != nil {
			return 0, err
		}
		return entries[rest%first], nil
	}
	maximum := direct + 2*first + 2*second + third
	return 0, invalidf("block %d is past the %d this block size can address", index, maximum)
}

func (m *deletedMap) resolve(address uint32) (uint32, bool, error) {
	switch address {
	case NullAddr:
		return 0, false, nil
	case NewAddr:
		return 0, false, unsupportedf("a data block still in a current segment, which the checkpoint has not committed")
	case CompressAddr:
		return 0, false, unsupportedf("a compressed cluster marker, whose plaintext this recovery pass does not decode")
	}
	if !m.main.contains(address) {
		return 0, false, invalidf("a data block at %d, outside the main area", address)
	}
	at := uint64(address) * uint64(m.blockSize)
	if !m.free.IsFree(at, uint64(m.blockSize)) {
		return 0, false, unsupportedf("the data block at block %d is still allocated", address)
	}
	return address, true, nil
}

func (m *deletedMap) dataBlock(index uint64) (uint32, bool, error) {
	address, err := m.rawAddress(index)
	if err != nil {
		return 0, false, err
	}
	return m.resolve(address)
}

func (m *deletedMap) readAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= m.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), m.length)
	}
	want := len(buf)
	if remaining := m.length - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	out := buf[:want]
	clear(out)
	if m.inline != nil {
		start := int(offset)
		stop := start + want
		if stop > len(m.inline) {
			stop = len(m.inline)
		}
		if start < stop {
			copy(out[:stop-start], m.inline[start:stop])
		}
		return want, nil
	}
	blockSize := uint64(m.blockSize)
	done := 0
	for done < want {
		position := offset + uint64(done)
		index := position / blockSize
		within := int(position % blockSize)
		take := want - done
		if remaining := int(m.blockSize) - within; take > remaining {
			take = remaining
		}
		block, present, err := m.dataBlock(index)
		if err != nil {
			return done, err
		}
		if present {
			if err := source.ReadExactAt(m.source, uint64(block)*blockSize+uint64(within), out[done:done+take]); err != nil {
				return done, err
			}
		}
		done += take
	}
	return want, nil
}

// DeletedFileSource is a recovered F2FS inode's content, read from free blocks.
type DeletedFileSource struct {
	id       source.ID
	blockMap *deletedMap
	ino      uint32
	counters source.Counters
}

// MapLen returns the recovered file's length.
func (f *DeletedFileSource) MapLen() uint64 { return f.blockMap.length }

// Ino returns the recovered inode number.
func (f *DeletedFileSource) Ino() uint32 { return f.ino }

// IsInline reports whether the recovered bytes live inside the inode block.
func (f *DeletedFileSource) IsInline() bool { return f.blockMap.isInline() }

// SourceID implements source.ByteSource.
func (f *DeletedFileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *DeletedFileSource) Len() uint64 { return f.blockMap.length }

// ImageID implements source.ByteSource.
func (f *DeletedFileSource) ImageID() source.ImageID { return f.blockMap.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *DeletedFileSource) SectorSize() uint32 { return f.blockMap.blockSize }

// ReadAt implements source.ByteSource with strict semantics.
func (f *DeletedFileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.blockMap.readAt(offset, buf)
	if err != nil {
		return got, mapSourceError(err)
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *DeletedFileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.blockMap.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.blockMap.length)
	}
	want := len(buf)
	if remaining := f.blockMap.length - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	got, err := f.ReadAt(offset, buf[:want])
	if err != nil {
		clear(buf[:want])
		f.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return got, nil
}

// ExtentsInto implements source.ByteSource.
func (f *DeletedFileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.blockMap.length || length > f.blockMap.length-offset {
		return out, source.NewOutOfRange(offset, length, f.blockMap.length)
	}
	if length == 0 {
		return out, nil
	}
	if f.blockMap.inline != nil {
		return append(out, source.ParentRange{
			Parent:       f.blockMap.source.SourceID(),
			ParentOffset: f.blockMap.inlineAt + offset,
			Len:          length,
			Kind:         source.RangeData,
		}), nil
	}
	blockSize := uint64(f.blockMap.blockSize)
	end := offset + length
	cursor := offset
	for cursor < end {
		index := cursor / blockSize
		within := cursor % blockSize
		take := end - cursor
		if remaining := blockSize - within; take > remaining {
			take = remaining
		}
		block, present, err := f.blockMap.dataBlock(index)
		if err != nil {
			return out, mapSourceError(err)
		}
		if present {
			at := uint64(block)*blockSize + within
			merged := false
			if len(out) > 0 {
				last := &out[len(out)-1]
				if last.Kind == source.RangeData && last.ParentOffset+last.Len == at {
					last.Len += take
					merged = true
				}
			}
			if !merged {
				out = append(out, source.ParentRange{
					Parent: f.blockMap.source.SourceID(), ParentOffset: at, Len: take, Kind: source.RangeData,
				})
			}
		} else {
			merged := false
			if len(out) > 0 {
				last := &out[len(out)-1]
				if last.Kind == source.RangeHole {
					last.Len += take
					merged = true
				}
			}
			if !merged {
				out = append(out, source.ParentRange{
					Parent: f.blockMap.source.SourceID(), ParentOffset: 0, Len: take, Kind: source.RangeHole,
				})
			}
		}
		cursor += take
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (f *DeletedFileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *DeletedFileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Kind == source.RangeData {
			imageRanges, err := f.blockMap.source.MapToImage(r.ParentOffset, r.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, imageRanges...)
		} else {
			out = append(out, source.ImageRange{
				ImageID: f.blockMap.source.ImageID(), ImageOffset: 0, Len: r.Len, Kind: r.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *DeletedFileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *DeletedFileSource) IsEmpty() bool { return f.blockMap.length == 0 }

var _ source.ByteSource = (*DeletedFileSource)(nil)
