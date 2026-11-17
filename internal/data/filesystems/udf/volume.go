package udf

// Mounting a UDF volume and walking its directory tree.

import (
	"fmt"
	pathpkg "path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	kindLabel = "UDF"

	// Volume descriptors scanned from the main sequence before giving up.
	maxDescriptorBlocks = 64
	// Blocks followed through allocation-extent chains for one file.
	maxAllocBlocks = 64
	// Allocation descriptors read for one file.
	maxRuns = 1 << 20
	// Bytes read for one directory.
	maxDirectoryBytes = 64 << 20
	// Bytes read from a symbolic link's data.
	maxSymlinkBytes = 4096
	// Indirect entries followed for one file entry.
	maxIndirectDepth = 2
	// Entries the walk may produce.
	maxNodes = 5_000_000
	// Volume recognition sectors examined.
	maxVRSSectors = 16
)

var (
	virtualMapIdent  = "*UDF Virtual Partition"
	metadataMapIdent = "*UDF Metadata Partition"
)

// PartitionSlot is one entry of the logical volume's partition map table,
// resolved against the partition descriptor it names.
type PartitionSlot struct {
	Number            uint16
	Start             uint32
	Length            uint32
	VolumeSequence    uint16
	UnallocatedBitmap *ShortAd
}

// PartitionInfo is the volume-level view of one partition.
type PartitionInfo struct {
	Number      uint16
	Start       uint32
	Length      uint32
	AccessType  uint32
	AccessLabel string
	Contents    string
	HasBitmap   bool
}

// PartitionMapInfo is the volume-level view of one partition map.
type PartitionMapInfo struct {
	Kind            uint8
	VolumeSequence  uint16
	PartitionNumber uint16
	Identifier      string
	Suffix          string
}

// Info is the volume-level description returned by Volume.Info.
type Info struct {
	Type string
	// UDFRevision is the minimum read revision from the integrity descriptor,
	// as major.minor BCD, or "unknown".
	UDFRevision      string
	UDFWriteRevision string
	// VRS is the revision the volume recognition sequence declared: NSR02 or
	// NSR03.
	VRS string
	// RootICB is the root directory's information control block address, as the
	// file set descriptor names it.
	RootICB LbAddr

	VolumeID    string
	VolumeSetID string
	FileSetID   string
	Domain      string
	Application string

	BlockSize         uint32
	VolumeBlocks      uint64
	LogicalVolumeSize uint64
	AnchorByte        uint64
	DescriptorBlocks  uint64

	VolumeClosed        *bool
	RecordedFiles       *uint32
	RecordedDirectories *uint32

	PartitionMaps []PartitionMapInfo
	Partitions    []PartitionInfo

	Unreadable   uint64
	OtherEntries uint64
}

// Entry describes one name the walk found.
type Entry struct {
	Name string
	Path string

	IsDir     bool
	IsSymlink bool
	IsFile    bool

	// Size is the logical length in bytes; zero for a directory.
	Size uint64
	// Permissions is the raw ECMA-167 permission word.
	Permissions uint32
	// Mode is Permissions mapped onto POSIX owner/group/other bits plus a
	// type bit. UDF does not store a POSIX mode, so the raw word is also kept.
	Mode uint32

	UID   uint32
	GID   uint32
	Links uint16

	FileType       uint8
	TypeLabel      string
	AllocationType string
	ICBStrategy    uint16
	ICB            LbAddr

	SymlinkTarget string

	Created     time.Time
	Modified    time.Time
	Changed     time.Time
	Accessed    time.Time
	HasCreated  bool
	HasModified bool
	HasChanged  bool
	HasAccessed bool

	// Extents are the physical runs and holes, in order.
	Extents []Run
	// UniqueID is present only when the entry records one.
	UniqueID *uint64
	// HasXattr says the entry records an extended-attribute space or names an
	// external attribute ICB.
	HasXattr bool
}

type node struct {
	name    string
	path    string
	parent  int
	isDir   bool
	isLink  bool
	size    uint64
	runs    []Run
	runsErr error

	fileType       uint8
	allocationType string
	icbStrategy    uint16
	permissions    uint32
	uid, gid       uint32
	links          uint16

	created, modified, changed, accessed UdfTime

	symlinkTarget string
	icb           LbAddr
	uniqueID      *uint64
	hasXattr      bool
	children      []int
}

type entryRecord struct {
	entry     FileEntry
	allocs    []byte
	inlineLen uint64
	offset    uint64
	addr      LbAddr
}

// Volume is a mounted UDF image.
type Volume struct {
	src source.ByteSource

	anchorAt  uint64
	anchor    Anchor
	blockSize uint32

	primary   PrimaryVolume
	logical   LogicalVolume
	integrity *Integrity
	fileSet   FileSet
	vrs       string

	partitions       []PartitionSlot
	partitionDescs   []Partition
	descriptorBlocks uint64

	nodes        []node
	paths        map[string]int
	unreadable   uint64
	otherEntries uint64

	entryCache map[LbAddr]*entryRecord

	freeOnce sync.Once
	free     *FreeSpace
	freeErr  error
}

var nextFileSourceID atomic.Uint64

// Open recognises, reads and walks a UDF volume at offset zero of src.
func Open(src source.ByteSource) (*Volume, error) {
	vol, err := readSetup(src)
	if err != nil {
		return nil, err
	}
	if err := vol.walk(); err != nil {
		return nil, err
	}
	return vol, nil
}

// Info returns volume-level facts.
func (v *Volume) Info() Info {
	info := Info{
		Type:             kindLabel,
		UDFRevision:      "unknown",
		VRS:              v.vrs,
		RootICB:          v.fileSet.Root.Addr,
		VolumeID:         v.primary.VolumeID,
		VolumeSetID:      v.primary.VolumeSetID,
		FileSetID:        v.fileSet.SetID,
		Domain:           v.logical.Domain,
		Application:      v.primary.Application,
		BlockSize:        v.blockSize,
		AnchorByte:       v.anchorAt,
		DescriptorBlocks: v.descriptorBlocks,
		Unreadable:       v.unreadable,
		OtherEntries:     v.otherEntries,
	}
	if len(v.partitions) > 0 {
		info.VolumeBlocks = uint64(v.partitions[0].Length)
		info.LogicalVolumeSize = uint64(v.partitions[0].Length) * uint64(v.blockSize)
	}
	if v.integrity != nil {
		info.VolumeClosed = v.integrity.Closed
		info.RecordedFiles = v.integrity.NumFiles
		info.RecordedDirectories = v.integrity.NumDirectories
		if revision, ok := v.integrity.ReadRevision(); ok {
			info.UDFRevision = revision
		}
		if revision, ok := v.integrity.WriteRevision(); ok {
			info.UDFWriteRevision = revision
		}
	}
	for _, m := range v.logical.Maps {
		pm := PartitionMapInfo{
			Kind:            m.Kind,
			VolumeSequence:  m.VolumeSequence,
			PartitionNumber: m.PartitionNumber,
		}
		if m.Kind == 2 {
			pm.Identifier = m.IdentText()
			pm.Suffix = fmt.Sprintf("%x", m.Suffix)
		}
		info.PartitionMaps = append(info.PartitionMaps, pm)
	}
	for _, p := range v.partitionDescs {
		info.Partitions = append(info.Partitions, PartitionInfo{
			Number:      p.Number,
			Start:       p.Start,
			Length:      p.Length,
			AccessType:  p.AccessType,
			AccessLabel: p.AccessLabel(),
			Contents:    p.Contents,
			HasBitmap:   p.UnallocatedBitmap != nil,
		})
	}
	return info
}

// ListDir returns the entries of the directory at path, in stored order.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	if !v.nodes[index].isDir {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	entries := make([]Entry, 0, len(v.nodes[index].children))
	for _, child := range v.nodes[index].children {
		entries = append(entries, v.entryOf(child))
	}
	return entries, nil
}

// Stat returns the entry at path.
func (v *Volume) Stat(path string) (*Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.entryOf(index)
	return &entry, nil
}

// OpenFile opens a regular file's data. A directory or symbolic link has no
// stream; the latter's target is recorded in the entry instead.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := v.nodes[index]
	if n.isDir || n.isLink {
		return nil, fmt.Errorf("%w: %s", ErrNotAFile, path)
	}
	if n.runsErr != nil {
		return nil, n.runsErr
	}
	id := source.ID(nextFileSourceID.Add(1) + 3_000_000)
	return newFileSource(id, v.src, append([]Run(nil), n.runs...), n.size), nil
}

// Xattrs reads the extended attributes of the entry at path.
func (v *Volume) Xattrs(path string) ([]ExtendedAttribute, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := v.nodes[index]
	block, err := v.readPartitionBlock(n.icb)
	if err != nil {
		return nil, err
	}
	entry, ok := ParseFileEntry(block)
	if !ok {
		return nil, corruptf(
			"the file entry at partition %d block %d is truncated", n.icb.Partition, n.icb.Block)
	}
	space, err := extendedAttributeSpace(entry, block)
	if err != nil {
		return nil, err
	}
	if len(space) > 0 {
		return ParseExtendedAttributes(space)
	}
	external := entry.ExtendedAttrICB
	if external == nil || external.ExtentLength() == 0 {
		return nil, nil
	}
	externalBlock, err := v.readPartitionBlock(external.Addr)
	if err != nil {
		return nil, err
	}
	externalEntry, ok := ParseFileEntry(externalBlock)
	if !ok {
		return nil, corruptf(
			"the extended-attribute ICB at partition %d block %d is truncated",
			external.Addr.Partition, external.Addr.Block)
	}
	space, err = extendedAttributeSpace(externalEntry, externalBlock)
	if err != nil {
		return nil, err
	}
	if len(space) == 0 {
		return nil, nil
	}
	return ParseExtendedAttributes(space)
}

func extendedAttributeSpace(entry FileEntry, block []byte) ([]byte, error) {
	length := int(entry.LengthExtendedAttrs)
	if length == 0 {
		return nil, nil
	}
	end := entry.ExtAttrAt + length
	if end < entry.ExtAttrAt || end > len(block) {
		return nil, corruptf(
			"the %d-byte extended-attribute space at offset %d does not fit in the %d-byte entry block",
			length, entry.ExtAttrAt, len(block))
	}
	return block[entry.ExtAttrAt:end], nil
}

func (v *Volume) lookup(path string) (int, error) {
	index, ok := v.paths[normalizePath(path)]
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrPathNotFound, path)
	}
	return index, nil
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return pathpkg.Clean(path)
}

func (v *Volume) entryOf(index int) Entry {
	n := v.nodes[index]
	entry := Entry{
		Name:           n.name,
		Path:           n.path,
		IsDir:          n.isDir,
		IsSymlink:      n.isLink,
		IsFile:         !n.isDir && !n.isLink,
		Size:           n.size,
		Permissions:    n.permissions,
		Mode:           posixMode(n),
		UID:            n.uid,
		GID:            n.gid,
		Links:          n.links,
		FileType:       n.fileType,
		TypeLabel:      TypeLabel(n.fileType),
		AllocationType: n.allocationType,
		ICBStrategy:    n.icbStrategy,
		ICB:            n.icb,
		SymlinkTarget:  n.symlinkTarget,
		Extents:        append([]Run(nil), n.runs...),
		UniqueID:       n.uniqueID,
		HasXattr:       n.hasXattr,
	}
	entry.Created, entry.HasCreated = n.created.Time(), n.created.Valid
	entry.Modified, entry.HasModified = n.modified.Time(), n.modified.Valid
	entry.Changed, entry.HasChanged = n.changed.Time(), n.changed.Valid
	entry.Accessed, entry.HasAccessed = n.accessed.Time(), n.accessed.Valid
	return entry
}

func posixMode(n node) uint32 {
	// ECMA-167 orders the permission bits other, group, owner from bit 0, so
	// each three-bit field lands on POSIX's read/write/execute ordering.
	other := n.permissions & 0x7
	group := (n.permissions >> 3) & 0x7
	owner := (n.permissions >> 6) & 0x7
	mode := owner<<6 | group<<3 | other
	switch {
	case n.isDir:
		mode |= 0o040000
	case n.isLink:
		mode |= 0o120000
	default:
		mode |= 0o100000
	}
	return mode
}

// -- descriptor setup -------------------------------------------------------

// recognizeVRS checks the ECMA-167 volume recognition sequence: BEA01 followed
// by NSR02 or NSR03.
func recognizeVRS(src source.ByteSource) (string, error) {
	foundBEA := false
	revision := ""
	for i := 0; i < maxVRSSectors; i++ {
		offset := (16 + uint64(i)) * SectorBytes
		if offset+SectorBytes > src.Len() {
			break
		}
		b, err := source.ReadVecAt(src, offset, SectorBytes)
		if err != nil {
			break
		}
		if b[0] != 0 {
			continue
		}
		ident := string(b[1:6])
		switch ident {
		case "BEA01":
			foundBEA = true
		case "NSR02", "NSR03":
			if foundBEA {
				revision = ident
			}
		case "TEA01":
			if foundBEA && revision != "" {
				return revision, nil
			}
		}
	}
	if !foundBEA {
		return "", corruptf("the volume recognition sequence does not open with BEA01")
	}
	if revision == "" {
		return "", corruptf("the volume recognition sequence declares no NSR02 or NSR03 revision")
	}
	return revision, nil
}

type anchorCandidate struct {
	offset uint64
	hint   uint32
}

func anchorCandidates(length uint64) []anchorCandidate {
	var out []anchorCandidate
	push := func(at uint64, size uint32) {
		if at+SectorBytes > length {
			return
		}
		for _, known := range out {
			if known.offset == at {
				return
			}
		}
		out = append(out, anchorCandidate{offset: at, hint: size})
	}
	push(AnchorSector*SectorBytes, 2048)
	for _, size := range []uint32{512, 1024, 4096} {
		push(AnchorSector*uint64(size), size)
	}
	blocks := length / SectorBytes
	if blocks > AnchorSector {
		push((blocks-AnchorSector)*SectorBytes, 2048)
	}
	if blocks > 0 {
		push((blocks-1)*SectorBytes, 2048)
	}
	return out
}

func findAnchor(src source.ByteSource) (uint64, Anchor, uint32, error) {
	var badAt *uint64
	for _, candidate := range anchorCandidates(src.Len()) {
		b, err := readSoft(src, candidate.offset, SectorBytes)
		if err != nil {
			continue
		}
		tag, ok := ParseTag(b)
		if !ok || tag.Ident != TagAVDP {
			continue
		}
		anchor, ok := parseAnchor(b)
		if !ok {
			continue
		}
		if tag.Verified() {
			return candidate.offset, anchor, candidate.hint, nil
		}
		if badAt == nil {
			at := candidate.offset
			badAt = &at
		}
	}
	if badAt != nil {
		return 0, Anchor{}, 0, corruptf(
			"the anchor volume descriptor pointer at byte %d fails its tag checksum or body CRC", *badAt)
	}
	return 0, Anchor{}, 0, corruptf(
		"no anchor volume descriptor pointer at sector 256 or near the end of the volume")
}

func convergeBlockSize(src source.ByteSource, extent ExtentAd, hint uint32) (uint32, error) {
	order := []uint32{hint}
	for _, size := range []uint32{2048, 512, 1024, 4096} {
		if size != hint {
			order = append(order, size)
		}
	}
	var fallback uint32
	for _, size := range order {
		offset := uint64(extent.Location) * uint64(size)
		b, err := readSoft(src, offset, uint64(size))
		if err != nil {
			continue
		}
		tag, ok := ParseTag(b)
		if !ok || tag.Ident != TagPVD {
			continue
		}
		if tag.Location == extent.Location {
			if !tag.Verified() {
				return 0, corruptf(
					"the primary volume descriptor at block %d fails its tag checksum or body CRC",
					extent.Location)
			}
			return size, nil
		}
		if tag.Verified() {
			fallback = size
		}
	}
	if fallback != 0 {
		return fallback, nil
	}
	return 0, corruptf(
		"the descriptor sequence at block %d holds no primary volume descriptor under any supported block size",
		extent.Location)
}

func readSetup(src source.ByteSource) (*Volume, error) {
	vrs, err := recognizeVRS(src)
	if err != nil {
		return nil, err
	}
	anchorAt, anchor, hint, err := findAnchor(src)
	if err != nil {
		return nil, err
	}
	blockSize, err := convergeBlockSize(src, anchor.Main, hint)
	if err != nil {
		return nil, err
	}
	vol := &Volume{
		src:        src,
		anchorAt:   anchorAt,
		anchor:     anchor,
		blockSize:  blockSize,
		vrs:        vrs,
		paths:      make(map[string]int),
		entryCache: make(map[LbAddr]*entryRecord),
	}

	var primary *PrimaryVolume
	var logical *LogicalVolume
	var descriptorBlocks uint64
	wanted := uint64(anchor.Main.Length) / uint64(blockSize)
	if wanted > maxDescriptorBlocks {
		wanted = maxDescriptorBlocks
	}
	if wanted == 0 {
		return nil, corruptf("the anchor names an empty volume descriptor sequence")
	}
loop:
	for index := uint64(0); index < wanted; index++ {
		block := uint64(anchor.Main.Location) + index
		b, err := readVolumeBlock(src, blockSize, block)
		if err != nil {
			break
		}
		descriptorBlocks++
		tag, ok := ParseTag(b)
		if !ok {
			break
		}
		if !tag.Verified() || uint64(tag.Location) != block {
			return nil, corruptf(
				"the volume descriptor at block %d fails its tag checksum, body CRC, or recorded location", block)
		}
		switch tag.Ident {
		case TagPVD:
			if primary == nil {
				p, ok := parsePrimary(b)
				if !ok {
					return nil, corruptf("the primary volume descriptor is truncated")
				}
				primary = &p
			}
		case TagPD:
			p, ok := parsePartition(b)
			if !ok {
				return nil, corruptf("the partition descriptor at block %d is truncated", block)
			}
			vol.partitionDescs = append(vol.partitionDescs, p)
		case TagLVD:
			if logical == nil {
				l, ok := parseLogical(b)
				if !ok {
					return nil, corruptf("the logical volume descriptor is truncated")
				}
				logical = &l
			}
		case TagTD:
			break loop
		}
	}
	vol.descriptorBlocks = descriptorBlocks
	if primary == nil {
		return nil, corruptf("the volume descriptor sequence holds no primary volume descriptor")
	}
	if logical == nil {
		return nil, corruptf("the volume descriptor sequence holds no logical volume descriptor")
	}
	vol.primary = *primary
	vol.logical = *logical

	size := logical.BlockSize
	if size < 512 || size > 4096 || size&(size-1) != 0 {
		return nil, corruptf("logical block size %d is not a power of two between 512 and 4096", size)
	}
	if size != blockSize {
		return nil, corruptf(
			"the logical volume declares %d-byte blocks but its descriptors were read in %d-byte blocks",
			size, blockSize)
	}
	if uint32(len(logical.Maps)) != logical.MapCount {
		return nil, corruptf(
			"the logical volume declares %d partition maps but holds %d", logical.MapCount, len(logical.Maps))
	}
	if !logical.IsUdfDomain() {
		return nil, unsupportedf(
			"the logical volume's domain is %q, not *OSTA UDF Compliant", logical.Domain)
	}

	for _, partitionMap := range logical.Maps {
		volumeSequence, partitionNumber, err := resolvePartitionMap(partitionMap)
		if err != nil {
			return nil, err
		}
		var descriptor *Partition
		for i := range vol.partitionDescs {
			if vol.partitionDescs[i].Number == partitionNumber {
				descriptor = &vol.partitionDescs[i]
				break
			}
		}
		if descriptor == nil {
			return nil, corruptf(
				"a partition map names partition %d, which no partition descriptor declares", partitionNumber)
		}
		if descriptor.Length == 0 {
			return nil, corruptf("partition %d is declared with zero length", partitionNumber)
		}
		vol.partitions = append(vol.partitions, PartitionSlot{
			Number:            descriptor.Number,
			Start:             descriptor.Start,
			Length:            descriptor.Length,
			VolumeSequence:    volumeSequence,
			UnallocatedBitmap: descriptor.UnallocatedBitmap,
		})
	}
	if len(vol.partitions) == 0 {
		return nil, corruptf("the logical volume maps no partitions")
	}

	if logical.Integrity.Length > 0 {
		if b, err := readVolumeBlock(src, size, uint64(logical.Integrity.Location)); err == nil {
			if integrity, ok := parseIntegrity(b); ok {
				vol.integrity = &integrity
			}
		}
	}

	root, ok := logical.RootDescriptor()
	if !ok || root.ExtentLength() == 0 {
		return nil, corruptf("the logical volume holds no file set descriptor address")
	}
	fsd, err := vol.readPartitionBlock(root.Addr)
	if err != nil {
		return nil, err
	}
	fsdTag, err := descriptorTag(fsd, "file set descriptor", root.Addr.Block)
	if err != nil {
		return nil, err
	}
	if fsdTag.Ident != TagFSD {
		return nil, corruptf("the file set descriptor's block holds a %s instead", fsdTag.Label())
	}
	fileSet, ok := parseFileSet(fsd)
	if !ok {
		return nil, corruptf("the file set descriptor is truncated")
	}
	vol.fileSet = fileSet
	return vol, nil
}

func resolvePartitionMap(m PartitionMap) (volumeSequence, partitionNumber uint16, err error) {
	switch m.Kind {
	case 1:
		if m.Length < 6 {
			return 0, 0, corruptf("a type 1 partition map is shorter than its fields")
		}
		return m.VolumeSequence, m.PartitionNumber, nil
	case 2:
		if m.Length < 40 {
			return 0, 0, corruptf("a type 2 partition map is shorter than its fields")
		}
		ident := m.IdentText()
		switch ident {
		case virtualMapIdent:
			return 0, 0, unsupportedf(
				"partition map type 2 (%q): the virtual allocation table is not ported", ident)
		case metadataMapIdent:
			return 0, 0, unsupportedf(
				"partition map type 2 (%q): the UDF 2.50 metadata partition is not ported", ident)
		default:
			return 0, 0, unsupportedf(
				"partition map type 2 (%q), which this reader does not model", ident)
		}
	default:
		return 0, 0, unsupportedf(
			"partition map type %d of %d bytes (only type 1 is modelled)", m.Kind, m.Length)
	}
}

// -- reading blocks and entries --------------------------------------------

func (v *Volume) partitionOffset(addr LbAddr) (uint64, error) {
	if int(addr.Partition) >= len(v.partitions) {
		return 0, corruptf(
			"partition reference %d is not in the volume's map table", addr.Partition)
	}
	slot := v.partitions[addr.Partition]
	if uint64(addr.Block) >= uint64(slot.Length) {
		return 0, corruptf(
			"block %d lies past the end of partition %d (%d blocks)",
			addr.Block, slot.Number, slot.Length)
	}
	return (uint64(slot.Start) + uint64(addr.Block)) * uint64(v.blockSize), nil
}

func (v *Volume) readPartitionBlock(addr LbAddr) ([]byte, error) {
	offset, err := v.partitionOffset(addr)
	if err != nil {
		return nil, err
	}
	return v.readVolumeBytes(offset, uint64(v.blockSize),
		fmt.Sprintf("the block at partition %d block %d", addr.Partition, addr.Block))
}

func (v *Volume) readVolumeBytes(offset, length uint64, what string) ([]byte, error) {
	end := offset + length
	if end < offset || end > v.src.Len() {
		return nil, corruptf(
			"%s at byte %d runs past the end of the image (%d bytes)", what, offset, v.src.Len())
	}
	b, err := source.ReadVecAt(v.src, offset, length)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func readVolumeBlock(src source.ByteSource, blockSize uint32, block uint64) ([]byte, error) {
	offset := block * uint64(blockSize)
	return source.ReadVecAt(src, offset, uint64(blockSize))
}

func readSoft(src source.ByteSource, offset, length uint64) ([]byte, error) {
	if offset+length < offset || offset+length > src.Len() {
		return nil, source.NewOutOfRange(offset, length, src.Len())
	}
	return source.ReadVecAt(src, offset, length)
}

// entry resolves an address to a file entry, following indirect entries.
func (v *Volume) entry(addr LbAddr) (*entryRecord, error) {
	if hit, ok := v.entryCache[addr]; ok {
		return hit, nil
	}
	current := addr
	depth := 0
	for {
		b, err := v.readPartitionBlock(current)
		if err != nil {
			return nil, err
		}
		tag, err := descriptorTag(b, "file entry", current.Block)
		if err != nil {
			return nil, err
		}
		switch tag.Ident {
		case TagFE, TagEFE:
			entry, ok := ParseFileEntry(b)
			if !ok {
				return nil, corruptf(
					"the file entry at partition %d block %d is truncated",
					current.Partition, current.Block)
			}
			offset, err := v.partitionOffset(current)
			if err != nil {
				return nil, err
			}
			record := &entryRecord{entry: entry, offset: offset, addr: current}
			at, ok := entry.AllocDescAt()
			if !ok || at > len(b) {
				return nil, corruptf(
					"the file entry at partition %d block %d records its allocation descriptors past the block",
					current.Partition, current.Block)
			}
			available := len(b) - at
			if entry.ICB.ADKind() == ADInICB {
				record.inlineLen = uint64(available)
			} else {
				want := int(entry.LengthAllocDescs)
				if want > available {
					want = available
				}
				record.allocs = append([]byte(nil), b[at:at+want]...)
			}
			v.entryCache[addr] = record
			v.entryCache[current] = record
			return record, nil
		case TagIE:
			if depth >= maxIndirectDepth {
				return nil, unsupportedf(
					"an indirect entry chain deeper than %d", maxIndirectDepth)
			}
			depth++
			indirect, ok := ParseIndirectEntry(b)
			if !ok {
				return nil, corruptf(
					"the indirect entry at partition %d block %d is truncated",
					current.Partition, current.Block)
			}
			if indirect.Target.ExtentLength() == 0 {
				return nil, corruptf(
					"the indirect entry at block %d points at a zero-length target", current.Block)
			}
			current = indirect.Target.Addr
		default:
			return nil, corruptf(
				"partition %d block %d holds a %s where a file entry belongs",
				current.Partition, current.Block, tag.Label())
		}
	}
}

// runsOf turns a file entry's allocation descriptors into runs.
func (v *Volume) runsOf(record *entryRecord) ([]Run, error) {
	entry := &record.entry
	information := entry.InformationLength
	if information == 0 {
		return nil, nil
	}
	kind := entry.ICB.ADKind()
	if kind == ADInICB {
		at, ok := entry.AllocDescAt()
		if !ok {
			return nil, corruptf("an in-ICB entry has no descriptor offset")
		}
		data := minU64(information, record.inlineLen)
		var runs []Run
		if data > 0 {
			runs = append(runs, Run{Offset: record.offset + uint64(at), Len: data})
		}
		if information > data {
			runs = append(runs, Run{Hole: true, Len: information - data})
		}
		return runs, nil
	}
	descBytes, ok := DescriptorBytes(kind)
	if !ok {
		return nil, corruptf(
			"allocation descriptor form %d is not one ECMA-167 defines", kind)
	}
	var runs []Run
	area := record.allocs
	continued := 0
	for {
		var next []byte
		for at := 0; at+descBytes <= len(area); at += descBytes {
			ad, ok := DecodeDescriptor(kind, area, at)
			if !ok {
				break
			}
			if kind == ADShort {
				ad.Addr.Partition = record.addr.Partition
			}
			if ad.IsContinuation() {
				continued++
				if continued > maxAllocBlocks {
					return nil, corruptf(
						"an allocation descriptor chain longer than %d blocks", maxAllocBlocks)
				}
				aedBytes, err := v.readPartitionBlock(ad.Addr)
				if err != nil {
					return nil, err
				}
				aedTag, err := descriptorTag(aedBytes, "allocation extent descriptor", ad.Addr.Block)
				if err != nil {
					return nil, err
				}
				if aedTag.Ident != TagAED {
					return nil, corruptf(
						"the allocation extent descriptor at partition %d block %d holds a %s",
						ad.Addr.Partition, ad.Addr.Block, aedTag.Label())
				}
				aed, ok := ParseAllocationExtent(aedBytes)
				if !ok {
					return nil, corruptf(
						"the allocation extent descriptor at partition %d block %d is truncated",
						ad.Addr.Partition, ad.Addr.Block)
				}
				const aedHeader = 24
				if aedHeader > len(aedBytes) {
					break
				}
				length := int(aed.Length)
				if length > len(aedBytes)-aedHeader {
					length = len(aedBytes) - aedHeader
				}
				next = append([]byte(nil), aedBytes[aedHeader:aedHeader+length]...)
				break
			}
			length := uint64(ad.ExtentLength())
			var data, hole uint64
			switch ad.Kind() {
			case ExtRecordedAllocated:
				if ad.HasLengths {
					data = minU64(minU64(uint64(ad.Recorded), uint64(ad.Information)), length)
					hole = uint64(ad.Information) - data
				} else {
					data = length
				}
			case ExtNotRecordedAllocated, ExtNotRecordedNotAllocated:
				hole = length
			default:
				data = length
			}
			if data > 0 {
				offset, err := v.partitionOffset(ad.Addr)
				if err != nil {
					return nil, err
				}
				end := offset + data
				if end < offset || end > v.src.Len() {
					return nil, corruptf(
						"an extent of %d bytes at byte %d runs past the end of the image", data, offset)
				}
				runs = append(runs, Run{Offset: offset, Len: data})
				if len(runs) > maxRuns {
					return nil, corruptf(
						"a file with more than %d allocation descriptors", maxRuns)
				}
			}
			if hole > 0 {
				runs = append(runs, Run{Hole: true, Len: hole})
				if len(runs) > maxRuns {
					return nil, corruptf(
						"a file with more than %d allocation descriptors", maxRuns)
				}
			}
		}
		if next == nil {
			break
		}
		area = next
	}
	var covered uint64
	for _, run := range runs {
		covered += run.Len
	}
	if covered < information {
		runs = append(runs, Run{Hole: true, Len: information - covered})
	}
	return runs, nil
}

func (v *Volume) directoryBytes(record *entryRecord) ([]byte, error) {
	length := record.entry.InformationLength
	if length > maxDirectoryBytes {
		return nil, corruptf(
			"a directory of %d bytes is larger than this reader will hold", length)
	}
	runs, err := v.runsOf(record)
	if err != nil {
		return nil, err
	}
	return readRuns(v.src, runs, length)
}

func readRuns(src source.ByteSource, runs []Run, want uint64) ([]byte, error) {
	if want > uint64(int(^uint(0)>>1)) {
		return nil, corruptf("a stream of %d bytes cannot be held in memory", want)
	}
	out := make([]byte, int(want))
	at := 0
	for _, run := range runs {
		if at >= len(out) {
			break
		}
		n := int(minU64(run.Len, uint64(len(out)-at)))
		if n == 0 {
			continue
		}
		if !run.Hole {
			if err := source.ReadExactAt(src, run.Offset, out[at:at+n]); err != nil {
				return nil, err
			}
		}
		at += n
	}
	return out, nil
}

func (v *Volume) symlinkTarget(runs []Run, length uint64) string {
	bytes, err := readRuns(v.src, runs, minU64(length, maxSymlinkBytes))
	if err != nil {
		return ""
	}
	var out string
	for _, component := range SymlinkComponents(bytes) {
		switch component.Kind {
		case LinkRoot, LinkMountRoot:
			out = "/"
		case LinkParent:
			if out != "" && !strings.HasSuffix(out, "/") {
				out += "/"
			}
			out += ".."
		case LinkCurrent:
			if out != "" && !strings.HasSuffix(out, "/") {
				out += "/"
			}
			out += "."
		case LinkName:
			if !component.HasName {
				return ""
			}
			if out != "" && !strings.HasSuffix(out, "/") {
				out += "/"
			}
			out += component.Name
		default:
			return ""
		}
	}
	return out
}

// -- walking ----------------------------------------------------------------

func (v *Volume) walk() error {
	rootAddr := v.fileSet.Root.Addr
	root, err := v.entry(rootAddr)
	if err != nil {
		return err
	}
	if !root.entry.ICB.IsDirectory() {
		return corruptf(
			"the file set's root entry is a %s, not a directory", root.entry.ICB.TypeLabel())
	}
	v.nodes = append(v.nodes, v.nodeFrom(root, -1, "/", "/"))
	v.paths["/"] = 0

	type queueItem struct {
		index int
		addr  LbAddr
	}
	queue := []queueItem{{index: 0, addr: root.addr}}
	visited := map[LbAddr]bool{root.addr: true}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		record, err := v.entry(item.addr)
		if err != nil {
			v.unreadable++
			continue
		}
		directoryBytes, err := v.directoryBytes(record)
		if err != nil {
			v.unreadable++
			continue
		}
		identifiers := ParseDirectoryEntries(directoryBytes)
		parentPath := v.nodes[item.index].path
		for _, identifier := range identifiers {
			if identifier.IsParent() {
				continue
			}
			if identifier.IsDeleted() {
				// Deleted-name recovery is not ported; the live tree only.
				continue
			}
			name, ok := identifier.Name()
			if !ok {
				continue
			}
			child, err := v.entry(identifier.ICB.Addr)
			if err != nil {
				v.unreadable++
				continue
			}
			if !child.entry.ICB.IsListable() {
				v.otherEntries++
				continue
			}
			if len(v.nodes) >= maxNodes {
				return unsupportedf("a volume with more than %d entries", maxNodes)
			}
			path := "/" + name
			if parentPath != "/" {
				path = parentPath + "/" + name
			}
			index := len(v.nodes)
			childNode := v.nodeFrom(child, item.index, name, path)
			v.nodes = append(v.nodes, childNode)
			v.paths[path] = index
			v.nodes[item.index].children = append(v.nodes[item.index].children, index)
			if childNode.isDir && !visited[child.addr] {
				visited[child.addr] = true
				queue = append(queue, queueItem{index: index, addr: child.addr})
			}
		}
	}
	return nil
}

func (v *Volume) nodeFrom(record *entryRecord, parent int, name, path string) node {
	entry := &record.entry
	n := node{
		name:           name,
		path:           path,
		parent:         parent,
		isDir:          entry.ICB.IsDirectory(),
		isLink:         entry.ICB.IsSymlink(),
		fileType:       entry.ICB.FileType,
		allocationType: allocationTypeLabel(entry.ICB.ADKind()),
		icbStrategy:    entry.ICB.Strategy,
		permissions:    entry.Permissions,
		uid:            entry.UID,
		gid:            entry.GID,
		links:          entry.Links,
		created:        entry.Created,
		modified:       entry.Modified,
		changed:        entry.Changed,
		accessed:       entry.Accessed,
		icb:            record.addr,
		uniqueID:       entry.UniqueID,
		hasXattr: entry.LengthExtendedAttrs > 0 ||
			(entry.ExtendedAttrICB != nil && entry.ExtendedAttrICB.ExtentLength() > 0),
	}
	if n.isDir {
		n.size = 0
	} else {
		n.size = entry.InformationLength
	}
	runs, err := v.runsOf(record)
	n.runs = runs
	n.runsErr = err
	if n.isLink {
		n.symlinkTarget = v.symlinkTarget(runs, entry.InformationLength)
	}
	return n
}

func allocationTypeLabel(kind uint8) string {
	switch kind {
	case ADShort:
		return "short"
	case ADLong:
		return "long"
	case ADExtended:
		return "extended"
	case ADInICB:
		return "in-icb"
	default:
		return "unknown"
	}
}
