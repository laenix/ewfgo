package ufs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Deleted-scan bounds.
const (
	// DefaultScanLimit is the inode-table bytes one scan reads by default.
	DefaultScanLimit uint64 = 256 << 20
	// MaxCandidates is the candidates one scan keeps by default.
	MaxCandidates uint64 = 65_536
	// MaxRecords is the name records one scan keeps by default.
	MaxRecords = 65_536
	// MaxFreeListHops is the di_freelink links one scan follows.
	MaxFreeListHops = 4_096
	// MinTimestamp is 0001-01-01T00:00:00Z.
	MinTimestamp int64 = -62_135_596_800
	// MaxTimestamp is 9999-12-31T23:59:59Z.
	MaxTimestamp int64 = 253_402_300_799
)

// ScanCap names the bound that stopped a scan.
type ScanCap string

const (
	ScanCapScanLimit      ScanCap = "scan_limit"
	ScanCapCandidateLimit ScanCap = "candidate_limit"
	ScanCapRecordLimit    ScanCap = "record_limit"
)

// DeletedOptions is what a scan may spend.
type DeletedOptions struct {
	// ScanLimit is inode-table bytes to read, allocated and free slots
	// together.
	ScanLimit     uint64
	MaxCandidates uint64
	MaxRecords    int
}

// DefaultDeletedOptions returns the Rust defaults.
func DefaultDeletedOptions() DeletedOptions {
	return DeletedOptions{
		ScanLimit:     DefaultScanLimit,
		MaxCandidates: MaxCandidates,
		MaxRecords:    MaxRecords,
	}
}

// DeletedStats records what a scan did.
type DeletedStats struct {
	GroupsScanned         uint64
	ScannedInodes         uint64
	ScannedBytes          uint64
	FreeSlots             uint64
	Candidates            uint64
	RejectedCleared       uint64
	RejectedType          uint64
	RejectedHash          uint64
	RejectedBounds        uint64
	RejectedUnreadable    uint64
	NonZeroLinks          uint64
	FreeListMembers       uint64
	NamesFreedRecords     uint64
	NamesStaleRecords     uint64
	NamesMismatched       uint64
	DuplicateNames        uint64
	Entries               uint64
	DirectoriesScanned    uint64
	DirectoriesUnreadable uint64
	DirectoryCapReached   bool
	CappedAt              ScanCap
}

// CapReached reports whether a bound stopped the scan.
func (s DeletedStats) CapReached() bool { return s.CappedAt != "" }

// EntryState says whether a recovered name still names the live file.
type EntryState string

const (
	// EntryDeleted means the live tree does not hold this name for this inode.
	EntryDeleted EntryState = "deleted"
	// EntryStillLive means the live tree holds this name for the same inode.
	EntryStillLive EntryState = "still_live"
	// EntryUnresolved means the name is evidence but no path can be proved.
	EntryUnresolved EntryState = "unresolved"
)

// ContentState says whether a candidate's bytes can be exported.
type ContentState struct {
	metadataOnly bool
	reason       string
}

// RecoverableContent returns a state whose bytes can be served.
func RecoverableContent() ContentState { return ContentState{} }

// MetadataOnlyContent returns a state whose bytes are withheld for the reason.
func MetadataOnlyContent(reason string) ContentState {
	return ContentState{metadataOnly: true, reason: reason}
}

// IsRecoverable reports whether the bytes can be served.
func (c ContentState) IsRecoverable() bool { return !c.metadataOnly }

// Reason returns why the bytes are not offered, or "".
func (c ContentState) Reason() string { return c.reason }

// NameSource says where a recovered name was read from.
type NameSource string

const (
	// NameSourceFreedRecord is slack behind a live record.
	NameSourceFreedRecord NameSource = "freed_record"
	// NameSourceStaleRecord is a live record whose inode slot is free.
	NameSourceStaleRecord NameSource = "stale_record"
)

// RecoveredInode is a free inode that passed the structural gate. The bytes
// are residue; the bitmap proves only that the slot is not allocated now.
type RecoveredInode struct {
	Inode        *Inode
	Physical     uint64
	Group        uint64
	Slot         uint32
	FreeListLink *uint32
	NonZeroLinks bool
	Content      ContentState
	Path         string
	HasPath      bool
}

// RecoveredEntry is one recovered name attached to a candidate inode.
type RecoveredEntry struct {
	Parent uint32
	Name   string
	Child  uint32
	Kind   uint8
	Source NameSource
	// RecordOffset is the byte offset of the record inside the parent
	// directory's data.
	RecordOffset uint64
	State        EntryState
	Path         string
	HasPath      bool
	Components   []string
	// Reason explains why the state is not a plain deleted name.
	Reason  string
	Content ContentState
}

// DeletedScan is the result of one scan.
type DeletedScan struct {
	Stats         DeletedStats
	Inodes        []RecoveredInode
	Entries       []RecoveredEntry
	RefusedGroups []string
}

// DeletedEntries returns the entries no live name claims.
func (s *DeletedScan) DeletedEntries() []RecoveredEntry {
	out := make([]RecoveredEntry, 0, len(s.Entries))
	for _, entry := range s.Entries {
		if entry.State == EntryDeleted {
			out = append(out, entry)
		}
	}
	return out
}

// Inode returns the recovered candidate numbered number, if one was found.
func (s *DeletedScan) Inode(number uint32) *RecoveredInode {
	for index := range s.Inodes {
		if s.Inodes[index].Inode.Number == number {
			return &s.Inodes[index]
		}
	}
	return nil
}

type credibility int

const (
	credibilityOK credibility = iota
	credibilityCleared
	credibilityUnknownType
	credibilityHash
	credibilityBounds
)

type rawName struct {
	parent uint32
	name   string
	child  uint32
	kind   uint8
	source NameSource
	offset uint64
}

type nameKey struct {
	parent uint32
	name   string
}

type entryKey struct {
	parent uint32
	name   string
	child  uint32
}

// DeletedScan scans freed inodes and reclaimed directory space.
//
// Every readable group's inode bitmap is consulted; a group whose bitmap
// cannot be read is refused by name and its slots are not guessed at.
// Allocated slots are read only to find directories that may still hold
// names. A candidate is a free slot whose residue is structurally credible.
func (v *Volume) DeletedScan(options *DeletedOptions) (*DeletedScan, error) {
	if options == nil {
		defaults := DefaultDeletedOptions()
		options = &defaults
	}
	sb := v.superblock
	inodeBytes := uint64(sb.InodeSize())
	stats := DeletedStats{}
	scan := &DeletedScan{}
	bitmaps := make([]*InodeBitmap, 0, sb.NCG)
	for group := uint64(0); group < uint64(sb.NCG); group++ {
		bitmap, err := ReadInodeBitmap(v.source, sb, group)
		if err != nil {
			scan.RefusedGroups = append(scan.RefusedGroups, fmt.Sprintf("cylinder group %d: %v", group, err))
			continue
		}
		stats.GroupsScanned++
		bitmaps = append(bitmaps, bitmap)
	}

	// A content check needs the fragment bitmap; without it the records stand
	// but no byte can be promised.
	free, freeErr := v.FreeSpace()
	var freeError string
	if freeErr != nil {
		freeError = freeErr.Error()
	}

	candidates := map[uint32]*RecoveredInode{}
	directorySet := map[uint32]bool{}

scanGroups:
	for _, bitmap := range bitmaps {
		for slot := uint32(0); slot < bitmap.Count; slot++ {
			if stats.ScannedBytes+inodeBytes > options.ScanLimit {
				stats.CappedAt = ScanCapScanLimit
				break scanGroups
			}
			number64 := uint64(bitmap.FirstInode) + uint64(slot)
			if number64 > uint64(^uint32(0)) || number64 == 0 {
				continue
			}
			number := uint32(number64)
			raw, err := v.ReadInodeBytes(number)
			if err != nil {
				stats.RejectedUnreadable++
				continue
			}
			stats.ScannedInodes++
			stats.ScannedBytes += inodeBytes
			inode, err := ParseInode(number, raw, sb.Version, sb.Endian)
			if err != nil {
				stats.RejectedUnreadable++
				continue
			}
			if bitmap.IsUsed(slot) {
				if inode.IsDirectory() && !inode.IsCleared() {
					if len(directorySet) < MaxDeletedDirectories {
						directorySet[number] = true
					} else {
						stats.DirectoryCapReached = true
					}
				}
				continue
			}
			stats.FreeSlots++
			switch credibleInode(sb, inode, raw) {
			case credibilityOK:
			case credibilityCleared:
				stats.RejectedCleared++
				continue
			case credibilityUnknownType:
				stats.RejectedType++
				continue
			case credibilityHash:
				stats.RejectedHash++
				continue
			default:
				stats.RejectedBounds++
				continue
			}
			if uint64(len(candidates)) >= options.MaxCandidates {
				stats.CappedAt = ScanCapCandidateLimit
				break scanGroups
			}
			stats.Candidates++
			if inode.Links != 0 {
				stats.NonZeroLinks++
			}
			physical, _ := sb.InodeOffset(number)
			var freeListLink *uint32
			if inode.FreeLink != nil && *inode.FreeLink != 0 {
				value := *inode.FreeLink
				freeListLink = &value
			}
			candidates[number] = &RecoveredInode{
				Inode:        inode,
				Physical:     physical,
				Group:        bitmap.Group,
				Slot:         slot,
				FreeListLink: freeListLink,
				NonZeroLinks: inode.Links != 0,
				Content:      contentState(sb, free, freeError, v.source, inode),
			}
		}
	}

	stats.FreeListMembers = v.followFreeList(bitmaps, candidates)

	// Live paths, breadth-first from the root, through allocated children
	// only. A record naming a free slot is not an ancestor.
	livePaths := v.livePaths(bitmaps)
	liveNames := map[nameKey]uint32{}

	directories := make([]uint32, 0, len(directorySet))
	for number := range directorySet {
		directories = append(directories, number)
	}
	sort.Slice(directories, func(left, right int) bool { return directories[left] < directories[right] })

	var rawNames []rawName
scanDirectories:
	for _, directory := range directories {
		if len(rawNames) >= options.MaxRecords {
			stats.CappedAt = ScanCapRecordLimit
			break
		}
		entries, slack, _, err := v.readDirBlocks(directory)
		if err != nil {
			stats.DirectoriesUnreadable++
			continue
		}
		stats.DirectoriesScanned++
		_, reachable := livePaths[directory]
		for _, entry := range entries {
			if entry.Name == "." || entry.Name == ".." {
				continue
			}
			used, known := allocationOf(bitmaps, entry.Inode)
			switch {
			case known && used && reachable:
				liveNames[nameKey{directory, entry.Name}] = entry.Inode
			case known && !used && candidates[entry.Inode] != nil:
				if len(rawNames) >= options.MaxRecords {
					stats.CappedAt = ScanCapRecordLimit
					break scanDirectories
				}
				stats.NamesStaleRecords++
				rawNames = append(rawNames, rawName{
					parent: directory,
					name:   entry.Name,
					child:  entry.Inode,
					kind:   entry.Kind,
					source: NameSourceStaleRecord,
					offset: entry.Offset,
				})
			}
		}
		for _, record := range slack {
			used, known := allocationOf(bitmaps, record.Inode)
			if known && !used && candidates[record.Inode] != nil {
				if len(rawNames) >= options.MaxRecords {
					stats.CappedAt = ScanCapRecordLimit
					break scanDirectories
				}
				stats.NamesFreedRecords++
				rawNames = append(rawNames, rawName{
					parent: directory,
					name:   record.Name,
					child:  record.Inode,
					kind:   record.Kind,
					source: NameSourceFreedRecord,
					offset: record.Offset,
				})
			}
		}
	}

	// A name claimed for two different candidates is ambiguous: neither path
	// is proved.
	claims := map[nameKey]map[uint32]bool{}
	for _, raw := range rawNames {
		key := nameKey{raw.parent, raw.name}
		if claims[key] == nil {
			claims[key] = map[uint32]bool{}
		}
		claims[key][raw.child] = true
	}

	seen := map[entryKey]bool{}
	var entries []RecoveredEntry
	for _, raw := range rawNames {
		key := entryKey{raw.parent, raw.name, raw.child}
		if seen[key] {
			stats.DuplicateNames++
			continue
		}
		seen[key] = true
		if len(entries) >= options.MaxRecords {
			stats.CappedAt = ScanCapRecordLimit
			break
		}
		candidate := candidates[raw.child]
		if candidate == nil {
			continue
		}
		var reasons []string
		if !kindAgrees(raw.kind, candidate.Inode.FileType()) && kindKnown(raw.kind) {
			stats.NamesMismatched++
			reasons = append(reasons, fmt.Sprintf("the record's type (%s) does not match the inode's (%s)",
				KindName(raw.kind), candidate.Inode.FileType().Name()))
		}
		claim := claims[nameKey{raw.parent, raw.name}]
		ambiguous := len(claim) > 1
		liveChild, hasLive := liveNames[nameKey{raw.parent, raw.name}]
		state := EntryDeleted
		if hasLive {
			if liveChild == raw.child {
				state = EntryStillLive
				reasons = append(reasons, "the live tree holds this name for the same inode")
			} else {
				reasons = append(reasons, fmt.Sprintf("the live name now names inode %d", liveChild))
			}
		}
		var path string
		var hasPath bool
		var components []string
		if ambiguous {
			state = EntryUnresolved
			children := make([]string, 0, len(claim))
			for child := range claim {
				children = append(children, fmt.Sprint(child))
			}
			sort.Strings(children)
			reasons = append(reasons, fmt.Sprintf("the name is claimed for more than one inode (%s)", strings.Join(children, ", ")))
			components = []string{raw.name}
		} else if base, ok := livePaths[raw.parent]; ok {
			path = joinPath(base, raw.name)
			hasPath = true
			components = []string{raw.name}
		} else {
			state = EntryUnresolved
			reasons = append(reasons, fmt.Sprintf("parent inode %d is not reachable from the root through live directories", raw.parent))
			components = []string{raw.name}
		}
		entries = append(entries, RecoveredEntry{
			Parent:       raw.parent,
			Name:         raw.name,
			Child:        raw.child,
			Kind:         raw.kind,
			Source:       raw.source,
			RecordOffset: raw.offset,
			State:        state,
			Path:         path,
			HasPath:      hasPath,
			Components:   components,
			Reason:       strings.Join(reasons, "; "),
			Content:      candidate.Content,
		})
	}
	stats.Entries = uint64(len(entries))
	for index := range entries {
		if !entries[index].HasPath {
			continue
		}
		if candidate := candidates[entries[index].Child]; candidate != nil && !candidate.HasPath {
			candidate.Path = entries[index].Path
			candidate.HasPath = true
		}
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].Parent != entries[right].Parent {
			return entries[left].Parent < entries[right].Parent
		}
		if entries[left].Name != entries[right].Name {
			return entries[left].Name < entries[right].Name
		}
		return entries[left].Child < entries[right].Child
	})

	recovered := make([]RecoveredInode, 0, len(candidates))
	for _, candidate := range candidates {
		recovered = append(recovered, *candidate)
	}
	sort.Slice(recovered, func(left, right int) bool {
		return recovered[left].Inode.Number < recovered[right].Inode.Number
	})
	scan.Stats = stats
	scan.Inodes = recovered
	scan.Entries = entries
	return scan, nil
}

// DeletedFileSource returns a source over a recovered candidate's content.
// The free state is re-checked now: a block reused since the scan makes the
// export refuse rather than serve another file's bytes.
func (v *Volume) DeletedFileSource(scan *DeletedScan, number uint32) (source.ByteSource, error) {
	recovered := scan.Inode(number)
	if recovered == nil {
		return nil, corruptf("inode %d is not one of the scan's recovered candidates", number)
	}
	if !recovered.Inode.IsRegular() {
		return nil, unsupportedf("inode %d is a %s, not a regular file", number, recovered.Inode.FileType().Name())
	}
	sb := v.superblock
	bitmap, err := ReadInodeBitmap(v.source, sb, recovered.Group)
	if err != nil {
		return nil, err
	}
	if number < bitmap.FirstInode || number-bitmap.FirstInode >= bitmap.Count {
		return nil, corruptf("inode %d is outside cylinder group %d's bitmap", number, recovered.Group)
	}
	slot := number - bitmap.FirstInode
	if bitmap.IsUsed(slot) {
		return nil, unsupportedf("inode %d is allocated now, so it is not deleted residue", number)
	}
	raw, err := v.ReadInodeBytes(number)
	if err != nil {
		return nil, err
	}
	inode, err := ParseInode(number, raw, sb.Version, sb.Endian)
	if err != nil {
		return nil, err
	}
	if credibleInode(sb, inode, raw) != credibilityOK {
		return nil, unsupportedf("inode %d no longer passes the structural check for a freed inode", number)
	}
	if !inode.IsRegular() {
		return nil, unsupportedf("inode %d no longer names a regular file", number)
	}
	free, err := v.FreeSpace()
	if err != nil {
		return nil, err
	}
	content := contentState(sb, free, "", v.source, inode)
	if !content.IsRecoverable() {
		return nil, unsupportedf("inode %d's content cannot be exported: %s", number, content.Reason())
	}
	mapData, err := BuildExtentMap(v.source, sb, inode)
	if err != nil {
		return nil, err
	}
	id := source.ID(v.fileID.Add(1))
	return newFileSource(id, v.source, mapData, number), nil
}

// livePaths walks live directory entries breadth-first from the root, proving
// a path for every directory whose child slot is allocated.
func (v *Volume) livePaths(bitmaps []*InodeBitmap) map[uint32]string {
	paths := map[uint32]string{RootInode: "/"}
	queue := []uint32{RootInode}
	seen := map[uint32]bool{RootInode: true}
	visited := 0
	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		visited++
		if visited > MaxPathDirectories {
			break
		}
		entries, err := v.ReadDir(directory)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Name == "." || entry.Name == ".." {
				continue
			}
			used, known := allocationOf(bitmaps, entry.Inode)
			if !known || !used {
				continue
			}
			if seen[entry.Inode] {
				continue
			}
			seen[entry.Inode] = true
			inode, err := v.Inode(entry.Inode)
			if err != nil {
				continue
			}
			if !inode.IsDirectory() {
				continue
			}
			path := joinPath(paths[directory], entry.Name)
			paths[entry.Inode] = path
			queue = append(queue, entry.Inode)
		}
	}
	return paths
}

// followFreeList follows di_freelink chains only to count their members. The
// chain never chooses or hides candidates; every slot was scanned above.
func (v *Volume) followFreeList(bitmaps []*InodeBitmap, candidates map[uint32]*RecoveredInode) uint64 {
	visited := map[uint32]bool{}
	members := uint64(0)
	hops := 0
	for _, candidate := range candidates {
		next := uint32(0)
		hasNext := candidate.FreeListLink != nil
		if hasNext {
			next = *candidate.FreeListLink
		}
		for hasNext {
			if hops >= MaxFreeListHops || visited[next] {
				break
			}
			visited[next] = true
			hops++
			used, known := allocationOf(bitmaps, next)
			if !known || used {
				break
			}
			raw, err := v.ReadInodeBytes(next)
			if err != nil || len(raw) < 244 {
				break
			}
			members++
			link := v.superblock.Endian.U32(raw, 240)
			if link == 0 || link == next {
				hasNext = false
			} else {
				next = link
			}
		}
	}
	return members
}

func allocationOf(bitmaps []*InodeBitmap, number uint32) (used, known bool) {
	for _, bitmap := range bitmaps {
		end := uint64(bitmap.FirstInode) + uint64(bitmap.Count)
		if uint64(number) >= uint64(bitmap.FirstInode) && uint64(number) < end {
			return bitmap.IsUsed(number - bitmap.FirstInode), true
		}
	}
	return false, false
}

// credibleInode is the structural gate a free slot must pass.
func credibleInode(sb *Superblock, inode *Inode, raw []byte) credibility {
	if inode.IsCleared() {
		return credibilityCleared
	}
	if inode.FileType() == InodeUnknown {
		return credibilityUnknownType
	}
	if !inodeHashMatches(sb, inode, raw) {
		return credibilityHash
	}
	if !boundsHold(sb, inode) {
		return credibilityBounds
	}
	return credibilityOK
}

// inodeHashMatches checks UFS2's di_ckhash when the volume maintains it. A
// stored zero is an absent hash: the checksum cannot have written it, so a
// plausible inode with a zero hash is not accepted.
func inodeHashMatches(sb *Superblock, inode *Inode, raw []byte) bool {
	if !sb.Checks(CK_INODE) {
		return true
	}
	if inode.CheckHash == nil {
		return false
	}
	stored := *inode.CheckHash
	if stored == 0 || len(raw) < 248 {
		return false
	}
	bytes := append([]byte(nil), raw...)
	clear(bytes[244:248])
	return foundation.CRC32C(bytes) == stored
}

// boundsHold checks the inode's size, block count, timestamps and pointers
// against the ranges the format and the volume define.
func boundsHold(sb *Superblock, inode *Inode) bool {
	timeOK := func(value UfsTime) bool {
		return value.Seconds >= MinTimestamp && value.Seconds <= MaxTimestamp
	}
	if !timeOK(inode.AccessTime) || !timeOK(inode.ModificationTime) || !timeOK(inode.ChangeTime) {
		return false
	}
	if inode.CreationTime != nil && !timeOK(*inode.CreationTime) {
		return false
	}
	limit := maxFileBytes(sb)
	if inode.IsDirectory() {
		limit = MaxDirSize
	}
	if inode.Size > limit {
		return false
	}
	volumeLen := sb.VolumeLen()
	blockLimit := volumeLen / 512
	if volumeLen%512 != 0 {
		blockLimit++
	}
	if inode.Blocks > blockLimit {
		return false
	}
	// A fast symlink's pointer bytes are its target, not pointers.
	if inode.IsFastSymlink(sb.MaxSymlinkLen) {
		return true
	}
	total := sb.SizeFrags
	for _, pointer := range inode.DB {
		if pointer != 0 && (pointer < 0 || uint64(pointer) >= total) {
			return false
		}
	}
	for _, pointer := range inode.IB {
		if pointer != 0 && (pointer < 0 || uint64(pointer) >= total) {
			return false
		}
	}
	return true
}

// maxFileBytes is the largest byte size direct, single, double and triple
// pointers cover.
func maxFileBytes(sb *Superblock) uint64 {
	pointers := sb.PointersPerBlock()
	blocks := satAdd(12, pointers)
	blocks = satAdd(blocks, satMul(pointers, pointers))
	blocks = satAdd(blocks, satMul(satMul(pointers, pointers), pointers))
	return satMul(blocks, sb.BlockSize())
}

// contentState decides whether a candidate's bytes may be exported.
func contentState(sb *Superblock, free *FreeSpace, freeError string, src source.ByteSource, inode *Inode) ContentState {
	if !inode.IsRegular() {
		return MetadataOnlyContent(fmt.Sprintf("the inode is a %s, not a regular file", inode.FileType().Name()))
	}
	if free == nil {
		if freeError == "" {
			freeError = "the reason was not recorded"
		}
		return MetadataOnlyContent("the free-space map could not be read: " + freeError)
	}
	blockMap, err := ReadBlockMapAll(src, sb, inode)
	if err != nil {
		return MetadataOnlyContent("the block map could not be walked: " + err.Error())
	}
	mapData, err := extentMapFromEntries(sb, inode, blockMap.Blocks)
	if err != nil {
		return MetadataOnlyContent("the block map cannot be represented: " + err.Error())
	}
	frag := sb.FragSize()
	for _, run := range mapData.Runs() {
		end := satAdd(run.Physical, run.Len)
		first := run.Physical - run.Physical%frag
		last := end
		if remainder := end % frag; remainder != 0 {
			var ok bool
			last, ok = addCheck(end, frag-remainder)
			if !ok {
				return MetadataOnlyContent("the data run's fragment-aligned end overflows")
			}
		}
		if !free.IsFree(first, last-first) {
			return MetadataOnlyContent(fmt.Sprintf(
				"the data run at logical bytes %d..%d maps to volume bytes %d..%d, which the fragment bitmap does not mark free",
				run.Logical, satAdd(run.Logical, run.Len), first, last))
		}
	}
	for _, fragment := range blockMap.Indirect {
		offset, err := sb.FragmentOffset(fragment)
		if err != nil {
			return MetadataOnlyContent(fmt.Sprintf("the indirect block at fragment %d is outside the volume", fragment))
		}
		if !free.IsFree(offset, frag) {
			return MetadataOnlyContent(fmt.Sprintf("the indirect block at fragment %d is not free", fragment))
		}
	}
	return RecoverableContent()
}

// kindKnown reports whether a d_type value names a type at all.
func kindKnown(kind uint8) bool {
	_, known := KindIsDirectory(kind)
	return known
}

// kindAgrees reports whether a d_type value names the candidate's type.
func kindAgrees(kind uint8, fileType InodeType) bool {
	expected, ok := inodeTypeForKind(kind)
	return ok && expected == fileType
}

func inodeTypeForKind(kind uint8) (InodeType, bool) {
	switch kind {
	case DTFifo:
		return InodeFifo, true
	case DTChr:
		return InodeCharacter, true
	case DTDir:
		return InodeDirectory, true
	case DTBlk:
		return InodeBlock, true
	case DTReg:
		return InodeRegular, true
	case DTLnk:
		return InodeSymlink, true
	case DTSock:
		return InodeSocket, true
	default:
		return InodeUnknown, false
	}
}
