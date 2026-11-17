package clfs

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// LogBlockHeader is the fixed CLFS_LOG_BLOCK_HEADER at the start of every log
// block.
type LogBlockHeader struct {
	// BlockOffset is the file offset the header was read from.
	BlockOffset  uint64
	MajorVersion uint8
	MinorVersion uint8
	// USN ties the sectors of one atomic write together.
	USN uint8
	// ClientID is the client (stream) number; 0 names a container block.
	ClientID         uint8
	TotalSectorCount uint16
	ValidSectorCount uint16
	// Checksum is the CRC-32 as stored at 0x0C.
	Checksum   uint32
	Flags      uint32
	CurrentLSN uint64
	NextLSN    uint64
	// RecordOffsets are record offsets relative to the start of the log block.
	RecordOffsets [16]uint32
	// SignaturesOffset is the offset of the sector-signature backup array.
	SignaturesOffset uint32
	// DeclaredBytes is TotalSectorCount * SectorSize.
	DeclaredBytes uint64
	// ChecksumOK is non-nil when the checksum was recorded and checked:
	// false means the recomputed CRC-32 did not match. It is nil when the
	// checksum is zero (not recorded) or the block was not read in full.
	ChecksumOK *bool
}

// Signature returns the two signature bytes the format defines: 15 00.
func (h LogBlockHeader) Signature() [2]byte {
	return [2]byte{h.MajorVersion, h.MinorVersion}
}

// FirstRecordOffset returns the first record offset declared by the header,
// when it is usable.
//
// The 16 slots are ordered, but a writer does not have to fill slot 0:
// Windows leaves it as the 0xFFFFFFFF "no record" sentinel and puts the
// block's first record in the next slot. Scanning past both the sentinel and
// a zero is what a live base log requires; taking slot 0 literally sends the
// control-record reader to offset 4294967295.
func (h LogBlockHeader) FirstRecordOffset() (uint64, bool) {
	for _, raw := range h.RecordOffsets {
		if raw == 0 || raw == ^uint32(0) {
			continue
		}
		offset := uint64(raw)
		if offset < LogBlockHeaderBytes {
			return 0, false
		}
		return offset, true
	}
	return 0, false
}

func parseLogBlockHeader(bytes []byte, blockOffset uint64) (LogBlockHeader, error) {
	if len(bytes) < LogBlockHeaderBytes {
		return LogBlockHeader{}, corrupt(blockOffset, fmt.Sprintf(
			"a CLFS log block header is %d bytes, not %d", LogBlockHeaderBytes, len(bytes)))
	}
	major := bytes[0]
	minor := bytes[1]
	if major != MajorVersion || minor != MinorVersion {
		return LogBlockHeader{}, corrupt(blockOffset, fmt.Sprintf(
			"the CLFS log block signature is %02X %02X, not %02X %02X",
			major, minor, MajorVersion, MinorVersion))
	}
	totalSectors, err := u16At(bytes, 0x04, blockOffset)
	if err != nil {
		return LogBlockHeader{}, err
	}
	validSectors, err := u16At(bytes, 0x06, blockOffset)
	if err != nil {
		return LogBlockHeader{}, err
	}
	declared := uint64(totalSectors) * SectorSize
	if declared < LogBlockHeaderBytes {
		return LogBlockHeader{}, corrupt(blockOffset+0x04, fmt.Sprintf(
			"the log block declares %d sector(s), too few for a %d-byte header",
			totalSectors, LogBlockHeaderBytes))
	}
	var recordOffsets [16]uint32
	for index := range recordOffsets {
		value, err := u32At(bytes, 0x24+index*4, blockOffset)
		if err != nil {
			return LogBlockHeader{}, err
		}
		recordOffsets[index] = value
	}
	checksum, err := u32At(bytes, 0x0C, blockOffset)
	if err != nil {
		return LogBlockHeader{}, err
	}
	flags, err := u32At(bytes, 0x10, blockOffset)
	if err != nil {
		return LogBlockHeader{}, err
	}
	currentLSN, err := u64At(bytes, 0x14, blockOffset)
	if err != nil {
		return LogBlockHeader{}, err
	}
	nextLSN, err := u64At(bytes, 0x1C, blockOffset)
	if err != nil {
		return LogBlockHeader{}, err
	}
	signaturesOffset, err := u32At(bytes, 0x68, blockOffset)
	if err != nil {
		return LogBlockHeader{}, err
	}
	return LogBlockHeader{
		BlockOffset:      blockOffset,
		MajorVersion:     major,
		MinorVersion:     minor,
		USN:              bytes[0x02],
		ClientID:         bytes[0x03],
		TotalSectorCount: totalSectors,
		ValidSectorCount: validSectors,
		Checksum:         checksum,
		Flags:            flags,
		CurrentLSN:       currentLSN,
		NextLSN:          nextLSN,
		RecordOffsets:    recordOffsets,
		SignaturesOffset: signaturesOffset,
		DeclaredBytes:    declared,
	}, nil
}

// MetadataBlock is one entry of the control record's metadata-block array.
type MetadataBlock struct {
	// Index is the index inside rgBlocks.
	Index int
	// PBImage is the in-memory image pointer as stored (normally zero on disk).
	PBImage uint64
	// CBImage is the size of the block image in bytes.
	CBImage uint32
	// CBOffset is the file offset of the block.
	CBOffset uint32
	// BlockType is 0 Control, 1 ControlShadow, 2 General, 3 GeneralShadow,
	// 4 Scratch, 5 ScratchShadow.
	BlockType uint32
	// Truncated is true when the declared image reaches past the end of the
	// source.
	Truncated bool
}

// TypeName returns the label the block type names.
func (b MetadataBlock) TypeName() string { return blockTypeName(b.BlockType) }

// IsShadow reports whether this is a shadow copy of another block.
func (b MetadataBlock) IsShadow() bool {
	return b.BlockType == 1 || b.BlockType == 3 || b.BlockType == 5
}

func blockTypeName(blockType uint32) string {
	switch blockType {
	case 0:
		return "control"
	case 1:
		return "control-shadow"
	case 2:
		return "general"
	case 3:
		return "general-shadow"
	case 4:
		return "scratch"
	case 5:
		return "scratch-shadow"
	default:
		return "unknown"
	}
}

// ControlRecord is the control record: layout, extend/truncate state, and the
// block table.
type ControlRecord struct {
	// RecordOffset is the absolute file offset of the record.
	RecordOffset       uint64
	DumpCount          uint64
	Version            uint8
	ExtendState        uint32
	ExtendBlock        uint16
	FlushBlock         uint16
	NewBlockSectors    uint32
	ExtendStartSectors uint32
	ExtendSectors      uint32
	// BlocksDeclared is the number of metadata blocks the record declares,
	// before bounding.
	BlocksDeclared uint16
	Reserved       uint32
	// ChecksumOK reports whether the enclosing log block's CRC matched.
	ChecksumOK *bool
}

// BaseRecord holds the fixed fields of the base record
// (CLFS_BASE_RECORD_HEADER).
type BaseRecord struct {
	// RecordOffset is the absolute file offset of the base record (past the
	// log block header).
	RecordOffset uint64
	DumpCount    uint64
	// LogID is the CLFS_LOG_ID, the log's 16-byte identifier.
	LogID [16]byte
	// ClientSymbolTable is rgClientSymTbl: offsets relative to RecordOffset.
	ClientSymbolTable [SymbolTableEntries]uint64
	// ContainerSymbolTable is rgContainerSymTbl: offsets relative to RecordOffset.
	ContainerSymbolTable [SymbolTableEntries]uint64
	// SecuritySymbolTable is rgSecuritySymTbl: offsets relative to RecordOffset.
	SecuritySymbolTable [SymbolTableEntries]uint64
	// SymbolZoneBytes is cbSymbolZone: next free symbol offset.
	SymbolZoneBytes uint32
	// SectorSize is cbSector, the sector size the record declares.
	SectorSize uint32
	// LogState is eLogState.
	LogState uint32
	// USN is cUsn.
	USN uint8
	// DeclaredClients is cClients, the number of clients the record declares.
	DeclaredClients uint8
	// ChecksumOK reports whether the enclosing log block's CRC matched.
	ChecksumOK *bool
}

// LogIDText renders the log id in the stored byte order, grouped as a GUID.
func (r BaseRecord) LogIDText() string { return guidText(r.LogID) }

// SectorSizeIsCanonical reports whether the declared sector size is the only
// value the format defines.
func (r BaseRecord) SectorSizeIsCanonical() bool {
	return r.SectorSize == 0 || uint64(r.SectorSize) == SectorSize
}

// Symbol is a CLFSHASHSYM: the header shared by client, container, and
// security symbols. Offset and every link is relative to the base record.
type Symbol struct {
	Offset   uint64
	NodeType uint32
	// NodeSize is the node id's second dword, a structure-size validation
	// value.
	NodeSize uint32
	// NameHash is the hash of the uppercased symbol name.
	NameHash uint32
	// DataSize is the size of the symbol data that begins at ContextOffset.
	DataSize uint32
	// Below and Above are hash-collision links.
	Below uint64
	Above uint64
	// NameOffset is the offset of the UTF-16 name, relative to the base record.
	NameOffset int32
	// ContextOffset is the offset of the context data, relative to the base
	// record.
	ContextOffset int32
	// ContextOffsetLost reports that the log sector signature overwrote part
	// of ContextOffset. The stored value is reported as stored, but it is not
	// a usable offset: the two bytes the signature replaced are gone. A
	// symbol with this flag has its context skipped rather than sliced at an
	// invented offset.
	ContextOffsetLost bool
	Deleted           bool
	// Name is the decoded name when the bytes formed valid UTF-16; HasName
	// reports whether it was decoded.
	Name    string
	HasName bool
}

// ClientContext is the fixed part of CLFS_CLIENT_CONTEXT.
type ClientContext struct {
	NodeType uint32
	NodeSize uint32
	ClientID uint32
	// Attributes is fAttributes, the file attributes of the client's stream.
	Attributes     uint16
	FlushThreshold uint32
	ShadowSectors  uint32
	UndoCommitment uint64
	// CreateTime, AccessTime and WriteTime are stored LARGE_INTEGERs; the
	// writer uses NT time (100 ns since 1601).
	CreateTime     uint64
	AccessTime     uint64
	WriteTime      uint64
	OwnerPageLSN   uint64
	ArchiveTailLSN uint64
	BaseLSN        uint64
	LastLSN        uint64
	// RestartLSN is the client's restart LSN. The restart record itself is
	// not read.
	RestartLSN      uint64
	PhysicalBaseLSN uint64
	UnusedLSN1      uint64
	UnusedLSN2      uint64
	// State is eLogState bit flags.
	State uint32
	// SecurityContext is the on-disk value of the security-context field
	// (normally zero).
	SecurityContext uint64
}

// ContainerContext is the fixed part of CLFS_CONTAINER_CONTEXT.
type ContainerContext struct {
	NodeType uint32
	NodeSize uint32
	// ContainerBytes is cbContainer: the container's size in bytes.
	ContainerBytes uint64
	ContainerID    uint32
	QueueID        uint32
	// StoredContainerPointer is the on-disk value of the kernel container
	// pointer (normally zero).
	StoredContainerPointer uint64
	USN                    uint64
	State                  uint32
	PreviousOffset         uint32
	NextOffset             uint32
	// Extents is always empty: the documented context carries no extent
	// list, and the container is one contiguous file whose blocks are located
	// by physical LSNs. MaxExtents bounds it if a future definition supplies
	// extents.
	Extents []Extent
}

// Extent is one extent of a container file. Reserved for a format definition
// that stores extents; the documented CLFS_CONTAINER_CONTEXT does not.
type Extent struct {
	Offset uint64
	Len    uint64
}

// Client is a client symbol and its decoded context.
type Client struct {
	Symbol  Symbol
	Context ClientContext
}

// Name returns the symbol name, for example the registry hive path a stream
// serves.
func (c Client) Name() (string, bool) { return c.Symbol.Name, c.Symbol.HasName }

// LogContainer is a container symbol and its decoded context.
type LogContainer struct {
	Symbol  Symbol
	Context ContainerContext
}

// Name returns the symbol name, normally the container's `*.regtrans-ms` path.
func (c LogContainer) Name() (string, bool) { return c.Symbol.Name, c.Symbol.HasName }

// Stats holds counters and non-fatal findings for one base log file.
type Stats struct {
	FileLen uint64
	// MetadataBlocks is the number of metadata entries decoded.
	MetadataBlocks int
	// Clients is the number of clients with a decoded context.
	Clients int
	// Containers is the number of containers with a decoded context.
	Containers int
	// DeletedSymbols is the number of symbols whose fDeleted flag was set.
	DeletedSymbols int
	// ClientSymbols is the number of client symbols walked, including ones
	// whose context was skipped.
	ClientSymbols int
	// ContainerSymbols is the number of container symbols walked, including
	// ones whose context was skipped.
	ContainerSymbols int
	// MetadataBlocksCapped reports that the control record named more blocks
	// than MaxMetadataBlocks.
	MetadataBlocksCapped bool
	// ClientsCapped reports that the client symbol table held more symbols
	// than MaxClients.
	ClientsCapped bool
	// ContainersCapped reports that the container symbol table held more
	// symbols than MaxContainers.
	ContainersCapped bool
	// ChecksumFailures is the number of blocks whose recomputed CRC-32 did
	// not match.
	ChecksumFailures int
	// Warnings holds non-fatal findings. Every limit hit names what was
	// skipped.
	Warnings []string
}

// BaseLog is a parsed CLFS base log file.
type BaseLog struct {
	source        source.ByteSource
	controlHeader LogBlockHeader
	control       ControlRecord
	baseHeader    LogBlockHeader
	baseRecord    BaseRecord
	blocks        []MetadataBlock
	clients       []Client
	containers    []LogContainer
	stats         Stats
}

// OpenBaseLog reads the base log file's metadata.
//
// The source is read only through bounded ByteSource reads. A bad log-block
// signature, a control record whose magic or block array does not fit, a
// missing general metadata block, or a base record shorter than 0x1338 bytes
// is refused by name. A decode problem inside one symbol is a warning; a
// symbol context that is declared but truncated is refused, because reporting
// it would require inventing bytes.
func OpenBaseLog(src source.ByteSource) (*BaseLog, error) {
	if src == nil {
		return nil, corrupt(0, "a nil source cannot be read")
	}
	fileLen := src.Len()
	if fileLen < LogBlockHeaderBytes {
		return nil, corrupt(0, fmt.Sprintf(
			"a CLFS base log file needs at least %d bytes, not %d", LogBlockHeaderBytes, fileLen))
	}
	var warnings []string
	head, err := source.ReadVecAt(src, 0, LogBlockHeaderBytes)
	if err != nil {
		return nil, err
	}
	controlHeader, err := parseLogBlockHeader(head, 0)
	if err != nil {
		return nil, err
	}

	controlLen := controlHeader.DeclaredBytes
	if controlLen > fileLen {
		return nil, corrupt(0, fmt.Sprintf(
			"the control log block declares %d bytes but the file is only %d bytes",
			controlLen, fileLen))
	}
	controlBytes, err := source.ReadVecAt(src, 0, controlLen)
	if err != nil {
		return nil, err
	}
	applyChecksum(controlBytes, &controlHeader, "control log block", &warnings)

	recordOffset, ok := controlHeader.FirstRecordOffset()
	if !ok {
		return nil, corrupt(0, "the control log block names no record offset")
	}
	control, blocks, err := parseControlRecord(controlBytes, recordOffset, fileLen, &warnings)
	if err != nil {
		return nil, err
	}
	control.ChecksumOK = controlHeader.ChecksumOK

	metadataBlocksCapped := len(blocks) < int(control.BlocksDeclared)

	chosen := -1
	for index := range blocks {
		if blocks[index].BlockType == 2 && !blocks[index].Truncated {
			chosen = index
			break
		}
	}
	if chosen < 0 {
		for index := range blocks {
			if blocks[index].BlockType == 3 && !blocks[index].Truncated {
				chosen = index
				break
			}
		}
	}
	if chosen < 0 {
		return nil, &source.Error{
			Kind:   source.ErrUnsupported,
			Reason: "CLFS: the control record names no usable general/base metadata block",
		}
	}
	block := blocks[chosen]
	if block.BlockType == 3 {
		warnings = append(warnings,
			"only the shadow copy of the general metadata block is usable; its contents were read")
	}
	if block.CBImage == 0 {
		return nil, corrupt(uint64(block.CBOffset),
			"the control record declares a zero-size general metadata block")
	}
	baseOffset := uint64(block.CBOffset)
	baseImageLen := uint64(block.CBImage)
	// Defensive: the block selection above skips a truncated block, so this
	// check mirrors the reference without being reachable through that path.
	if baseOffset > fileLen || baseImageLen > fileLen-baseOffset {
		return nil, corrupt(baseOffset, fmt.Sprintf(
			"the general metadata block at %d (+%d bytes) extends past the %d byte file",
			baseOffset, baseImageLen, fileLen))
	}

	readLen := baseImageLen
	if readLen > MaxBaseRecordBytes {
		readLen = MaxBaseRecordBytes
	}
	if readLen < baseImageLen {
		warnings = append(warnings, fmt.Sprintf(
			"the general metadata block is %d bytes; only the first %d were read (%d-byte limit)",
			baseImageLen, readLen, MaxBaseRecordBytes))
	}
	baseBytes, err := source.ReadVecAt(src, baseOffset, readLen)
	if err != nil {
		return nil, err
	}
	if len(baseBytes) < LogBlockHeaderBytes {
		return nil, corrupt(baseOffset, "the general block header is truncated")
	}
	baseHeader, err := parseLogBlockHeader(baseBytes[:LogBlockHeaderBytes], baseOffset)
	if err != nil {
		return nil, err
	}
	if readLen == baseImageLen {
		applyChecksum(baseBytes, &baseHeader, "general metadata block", &warnings)
	} else {
		warnings = append(warnings,
			"the general metadata block checksum was not checked because only a prefix was read")
	}

	baseRecordRelative, ok := baseHeader.FirstRecordOffset()
	if !ok {
		return nil, corrupt(baseOffset, "the general metadata block names no record offset")
	}
	if baseRecordRelative < LogBlockHeaderBytes ||
		baseRecordRelative > readLen ||
		uint64(BaseRecordBytes) > readLen-baseRecordRelative {
		return nil, corrupt(addSaturating(baseOffset, baseRecordRelative), fmt.Sprintf(
			"the base record at block offset %d does not fit in the %d byte general block",
			baseRecordRelative, readLen))
	}
	baseRecordFileOffset := baseOffset + baseRecordRelative
	recordImage := baseBytes[baseRecordRelative:]
	baseRecord, err := parseBaseRecord(recordImage, baseRecordFileOffset)
	if err != nil {
		return nil, err
	}
	baseRecord.ChecksumOK = baseHeader.ChecksumOK

	deletedSymbols := 0
	clientWalk := walkSymbols(recordImage, baseRecord.ClientSymbolTable,
		baseRecordFileOffset, baseRecord.SectorSize, MaxClients, "client", &warnings)
	deletedSymbols += clientWalk.deleted
	containerWalk := walkSymbols(recordImage, baseRecord.ContainerSymbolTable,
		baseRecordFileOffset, baseRecord.SectorSize, MaxContainers, "container", &warnings)
	deletedSymbols += containerWalk.deleted
	warnTableCrossing("client", baseRecordFileOffset, ClientSymbolTableOffset,
		baseRecord.ClientSymbolTable, baseRecord.SectorSize, recordImage, &warnings)
	warnTableCrossing("container", baseRecordFileOffset, ContainerSymbolTableOffset,
		baseRecord.ContainerSymbolTable, baseRecord.SectorSize, recordImage, &warnings)

	clientSymbols := len(clientWalk.symbols)
	containerSymbols := len(containerWalk.symbols)
	clients, err := parseClients(recordImage, baseRecordFileOffset,
		baseRecord.SectorSize, &clientWalk.symbols, &warnings)
	if err != nil {
		return nil, err
	}
	containers, err := parseContainers(recordImage, baseRecordFileOffset,
		baseRecord.SectorSize, &containerWalk.symbols, &warnings)
	if err != nil {
		return nil, err
	}

	checksumFailures := 0
	if controlHeader.ChecksumOK != nil && !*controlHeader.ChecksumOK {
		checksumFailures++
	}
	if baseHeader.ChecksumOK != nil && !*baseHeader.ChecksumOK {
		checksumFailures++
	}
	if !baseRecord.SectorSizeIsCanonical() {
		warnings = append(warnings, fmt.Sprintf(
			"the base record declares a sector size of %d, not %d; the field is reported as stored",
			baseRecord.SectorSize, SectorSize))
	}
	if int(baseRecord.DeclaredClients) != len(clients) && baseRecord.DeclaredClients != 0 {
		warnings = append(warnings, fmt.Sprintf(
			"the base record declares %d client(s) but %d context(s) decoded",
			baseRecord.DeclaredClients, len(clients)))
	}
	stats := Stats{
		FileLen:              fileLen,
		MetadataBlocks:       len(blocks),
		Clients:              len(clients),
		Containers:           len(containers),
		DeletedSymbols:       deletedSymbols,
		ClientSymbols:        clientSymbols,
		ContainerSymbols:     containerSymbols,
		MetadataBlocksCapped: metadataBlocksCapped,
		ClientsCapped:        clientWalk.capped,
		ContainersCapped:     containerWalk.capped,
		ChecksumFailures:     checksumFailures,
		Warnings:             warnings,
	}
	return &BaseLog{
		source:        src,
		controlHeader: controlHeader,
		control:       control,
		baseHeader:    baseHeader,
		baseRecord:    baseRecord,
		blocks:        blocks,
		clients:       clients,
		containers:    containers,
		stats:         stats,
	}, nil
}

// ControlHeader returns the log block header at file offset 0.
func (l *BaseLog) ControlHeader() *LogBlockHeader { return &l.controlHeader }

// Control returns the control record.
func (l *BaseLog) Control() *ControlRecord { return &l.control }

// BaseHeader returns the general block's log block header.
func (l *BaseLog) BaseHeader() *LogBlockHeader { return &l.baseHeader }

// BaseRecord returns the base record.
func (l *BaseLog) BaseRecord() *BaseRecord { return &l.baseRecord }

// MetadataBlocks returns every metadata block the control record named,
// decoded or truncated.
func (l *BaseLog) MetadataBlocks() []MetadataBlock { return l.blocks }

// Clients returns clients whose contexts decoded.
func (l *BaseLog) Clients() []Client { return l.clients }

// Containers returns containers whose contexts decoded.
func (l *BaseLog) Containers() []LogContainer { return l.containers }

// Stats returns counters and warnings.
func (l *BaseLog) Stats() Stats { return l.stats }

// Warnings returns non-fatal findings in read order.
func (l *BaseLog) Warnings() []string { return l.stats.Warnings }

// Source returns the underlying file.
func (l *BaseLog) Source() source.ByteSource { return l.source }

func parseControlRecord(block []byte, recordOffset, fileLen uint64, warnings *[]string) (ControlRecord, []MetadataBlock, error) {
	blockLen := uint64(len(block))
	at := recordOffset
	if at < LogBlockHeaderBytes || at > blockLen || blockLen-at < 0x50 {
		return ControlRecord{}, nil, corrupt(recordOffset, fmt.Sprintf(
			"the control record at %d is truncated: the fixed part needs %d bytes but the control block is %d bytes",
			recordOffset, 0x50, len(block)))
	}
	magic, err := u64At(block, int(at)+0x08, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	if magic != ControlRecordMagic {
		return ControlRecord{}, nil, corrupt(recordOffset+0x08, fmt.Sprintf(
			"the control record magic is %016X, not %016X", magic, ControlRecordMagic))
	}
	declared, err := u16At(block, int(at)+0x48, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	if declared == 0 {
		return ControlRecord{}, nil, corrupt(recordOffset+0x48,
			"the control record declares no metadata blocks")
	}
	capped := int(declared)
	if capped > MaxMetadataBlocks {
		capped = MaxMetadataBlocks
	}
	if capped < int(declared) {
		*warnings = append(*warnings, fmt.Sprintf(
			"the control record declares %d metadata blocks; only the first %d were decoded",
			declared, MaxMetadataBlocks))
	}
	needed := uint64(0x50 + capped*0x18)
	if needed > blockLen-at {
		return ControlRecord{}, nil, corrupt(recordOffset, fmt.Sprintf(
			"the control record at %d is truncated: %d metadata block(s) need %d bytes but the control block is %d bytes",
			recordOffset, declared, needed, len(block)))
	}

	dumpCount, err := u64At(block, int(at), 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	extendState, err := u32At(block, int(at)+0x14, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	extendBlock, err := u16At(block, int(at)+0x18, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	flushBlock, err := u16At(block, int(at)+0x1A, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	newBlockSectors, err := u32At(block, int(at)+0x1C, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	extendStartSectors, err := u32At(block, int(at)+0x20, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	extendSectors, err := u32At(block, int(at)+0x24, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	reserved, err := u32At(block, int(at)+0x4C, 0)
	if err != nil {
		return ControlRecord{}, nil, err
	}
	control := ControlRecord{
		RecordOffset:       recordOffset,
		DumpCount:          dumpCount,
		Version:            block[int(at)+0x10],
		ExtendState:        extendState,
		ExtendBlock:        extendBlock,
		FlushBlock:         flushBlock,
		NewBlockSectors:    newBlockSectors,
		ExtendStartSectors: extendStartSectors,
		ExtendSectors:      extendSectors,
		BlocksDeclared:     declared,
		Reserved:           reserved,
	}

	blocks := make([]MetadataBlock, 0, capped)
	for index := 0; index < capped; index++ {
		entry := int(at) + 0x50 + index*0x18
		image, err := u64At(block, entry, 0)
		if err != nil {
			return ControlRecord{}, nil, err
		}
		cbImage, err := u32At(block, entry+0x08, 0)
		if err != nil {
			return ControlRecord{}, nil, err
		}
		cbOffset, err := u32At(block, entry+0x0C, 0)
		if err != nil {
			return ControlRecord{}, nil, err
		}
		blockType, err := u32At(block, entry+0x10, 0)
		if err != nil {
			return ControlRecord{}, nil, err
		}
		end := uint64(cbOffset) + uint64(cbImage)
		truncated := end > fileLen
		if cbImage == 0 {
			*warnings = append(*warnings, fmt.Sprintf(
				"metadata block %d (%s) has a zero size", index, blockTypeName(blockType)))
		}
		if truncated {
			*warnings = append(*warnings, fmt.Sprintf(
				"metadata block %d (%s) at %d (+%d bytes) extends past the %d byte file",
				index, blockTypeName(blockType), cbOffset, cbImage, fileLen))
		}
		blocks = append(blocks, MetadataBlock{
			Index:     index,
			PBImage:   image,
			CBImage:   cbImage,
			CBOffset:  cbOffset,
			BlockType: blockType,
			Truncated: truncated,
		})
	}
	return control, blocks, nil
}

func parseBaseRecord(record []byte, fileOffset uint64) (BaseRecord, error) {
	if len(record) < BaseRecordBytes {
		return BaseRecord{}, corrupt(fileOffset, fmt.Sprintf(
			"the base record is truncated: it needs %d bytes but only %d are available",
			BaseRecordBytes, len(record)))
	}
	var logID [16]byte
	copy(logID[:], record[0x08:0x18])
	dumpCount, err := u64At(record, 0x00, fileOffset)
	if err != nil {
		return BaseRecord{}, err
	}
	clientTable, err := symbolTable(record, ClientSymbolTableOffset, fileOffset)
	if err != nil {
		return BaseRecord{}, err
	}
	containerTable, err := symbolTable(record, ContainerSymbolTableOffset, fileOffset)
	if err != nil {
		return BaseRecord{}, err
	}
	securityTable, err := symbolTable(record, SecuritySymbolTableOffset, fileOffset)
	if err != nil {
		return BaseRecord{}, err
	}
	symbolZoneBytes, err := u32At(record, 0x1328, fileOffset)
	if err != nil {
		return BaseRecord{}, err
	}
	sectorSize, err := u32At(record, 0x132C, fileOffset)
	if err != nil {
		return BaseRecord{}, err
	}
	logState, err := u32At(record, 0x1332, fileOffset)
	if err != nil {
		return BaseRecord{}, err
	}
	return BaseRecord{
		RecordOffset:         fileOffset,
		DumpCount:            dumpCount,
		LogID:                logID,
		ClientSymbolTable:    clientTable,
		ContainerSymbolTable: containerTable,
		SecuritySymbolTable:  securityTable,
		SymbolZoneBytes:      symbolZoneBytes,
		SectorSize:           sectorSize,
		LogState:             logState,
		USN:                  record[0x1336],
		DeclaredClients:      record[0x1337],
	}, nil
}

func symbolTable(record []byte, at int, fileOffset uint64) ([SymbolTableEntries]uint64, error) {
	var table [SymbolTableEntries]uint64
	for index := range table {
		value, err := u64At(record, at+index*8, fileOffset)
		if err != nil {
			return table, err
		}
		table[index] = value
	}
	return table, nil
}

type symbolWalk struct {
	symbols []Symbol
	capped  bool
	deleted int
}

type originKind uint8

const (
	originTable originKind = iota
	originBelow
	originAbove
)

// symbolOrigin records which pointer led the walk to a symbol offset. It is
// kept so a bad pointer can be attributed to the bucket that stored it or to
// the collision link that carried it, instead of naming the symbol table for a
// value a node held.
type symbolOrigin struct {
	kind originKind
	node uint64
}

func (o symbolOrigin) describe(kind string) string {
	switch o.kind {
	case originBelow:
		return fmt.Sprintf("the %s symbol node at offset %d has its below link", kind, o.node)
	case originAbove:
		return fmt.Sprintf("the %s symbol node at offset %d has its above link", kind, o.node)
	default:
		return fmt.Sprintf("the %s symbol table", kind)
	}
}

// symbolField names the symbol-node field a header byte belongs to.
func symbolField(relative uint64) string {
	switch {
	case relative <= 0x03:
		return "node type"
	case relative <= 0x07:
		return "node size"
	case relative <= 0x0B:
		return "name hash"
	case relative <= 0x0F:
		return "declared data size"
	case relative <= 0x17:
		return "below link"
	case relative <= 0x1F:
		return "above link"
	case relative <= 0x23:
		return "name offset"
	case relative <= 0x27:
		return "context offset"
	case relative == 0x28:
		return "deleted flag"
	default:
		return "padding"
	}
}

// fieldCrossed reports whether any of stamps (absolute file offsets)
// overlaps one node field.
func fieldCrossed(stamps []uint64, nodeAbs, fieldOffset, fieldLen uint64) bool {
	for _, stamp := range stamps {
		relative := uint64(0)
		if stamp > nodeAbs {
			relative = stamp - nodeAbs
		}
		if relative < fieldOffset+fieldLen && relative+sectorSignatureBytes > fieldOffset {
			return true
		}
	}
	return false
}

// walkSymbols walks one symbol table's hash buckets and collision links.
//
// The 11 buckets are roots of collision trees/chains. Below and Above are
// followed as links, with a visited set so a cycle cannot loop and a hard node
// budget so a hostile block cannot make the walk unbounded. Symbols outside
// the record image are named and skipped; reaching limit stops the walk and
// records the cap.
//
// A symbol node's header starts at a fixed offset but not at a fixed sector
// phase, so the two-byte sector signature can land inside one of its fields.
// A link whose bytes the signature overwrote is reported as stored and not
// followed: the writer's intended value is gone from the file, and following
// the stored bytes would walk into whatever the signature value happens to
// name.
func walkSymbols(image []byte, table [SymbolTableEntries]uint64, fileOffset uint64,
	sectorSize uint32, limit int, kind string, warnings *[]string) symbolWalk {
	nodeBudget := limit*2 + 16
	type entry struct {
		offset uint64
		origin symbolOrigin
	}
	stack := make([]entry, 0, len(table))
	for _, offset := range table {
		if offset != 0 {
			stack = append(stack, entry{offset: offset, origin: symbolOrigin{kind: originTable}})
		}
	}
	visited := make(map[uint64]struct{})
	var symbols []Symbol
	deleted := 0
	capped := false
	imageLen := uint64(len(image))

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		offset := current.offset
		if offset == 0 {
			continue
		}
		if _, seen := visited[offset]; seen {
			continue
		}
		visited[offset] = struct{}{}
		sourceText := current.origin.describe(kind)
		if len(visited) > nodeBudget {
			*warnings = append(*warnings, fmt.Sprintf(
				"the %s symbol walk visited more than %d nodes; the rest were skipped",
				kind, nodeBudget))
			capped = true
			break
		}
		if len(symbols) >= limit {
			*warnings = append(*warnings, fmt.Sprintf(
				"the %s symbol table holds more than %d symbols; the rest were skipped",
				kind, limit))
			capped = true
			break
		}
		if offset > uint64(maxInt()) {
			*warnings = append(*warnings, fmt.Sprintf(
				"%s pointing at offset %d, which does not fit an in-memory offset",
				sourceText, offset))
			continue
		}
		at := int(offset)
		if uint64(at) > imageLen || uint64(SymbolHeaderBytes) > imageLen-uint64(at) {
			*warnings = append(*warnings, fmt.Sprintf(
				"%s pointing at offset %d, outside the %d-byte base record",
				sourceText, offset, len(image)))
			continue
		}
		nodeAbs := addSaturating(fileOffset, offset)
		var crossings []uint64
		for _, stamp := range signatureStamps(nodeAbs,
			addSaturating(nodeAbs, uint64(SymbolHeaderBytes)), sectorSize) {
			relativeToImage := stamp - fileOffset
			if relativeToImage+2 > imageLen {
				continue
			}
			word := uint16(image[relativeToImage]) | uint16(image[relativeToImage+1])<<8
			if word != 0 {
				crossings = append(crossings, stamp)
			}
		}
		for _, stamp := range crossings {
			relativeToImage := stamp - fileOffset
			word := uint16(image[relativeToImage]) | uint16(image[relativeToImage+1])<<8
			relative := stamp - nodeAbs
			first := symbolField(relative)
			second := symbolField(relative + 1)
			place := fmt.Sprintf("inside the node's %s field", first)
			if first != second {
				place = fmt.Sprintf("across the node's %s and %s fields", first, second)
			}
			*warnings = append(*warnings, fmt.Sprintf(
				"the %s symbol node at offset %d has its header crossed by the log sector signature at file offset %d; the two bytes stored at %d are %04X, %s, where a stamped sector carries its signature instead of record data",
				kind, offset, stamp+sectorSignatureBytes, stamp, word, place))
		}
		belowCrossed := fieldCrossed(crossings, nodeAbs, 0x10, 8)
		aboveCrossed := fieldCrossed(crossings, nodeAbs, 0x18, 8)
		nameOffsetCrossed := fieldCrossed(crossings, nodeAbs, 0x20, 4)
		contextOffsetCrossed := fieldCrossed(crossings, nodeAbs, 0x24, 4)

		nodeType, err := u32At(image, at, fileOffset)
		if err != nil {
			nodeType = 0
		}
		if nodeType != NodeTypeSymbol {
			*warnings = append(*warnings, fmt.Sprintf(
				"%s pointing at offset %d, whose node type is %08X rather than %08X",
				sourceText, offset, nodeType, NodeTypeSymbol))
			continue
		}
		below, err := u64At(image, at+0x10, fileOffset)
		if err != nil {
			below = 0
		}
		above, err := u64At(image, at+0x18, fileOffset)
		if err != nil {
			above = 0
		}
		nameOffset, err := i32At(image, at+0x20, fileOffset)
		if err != nil {
			nameOffset = 0
		}
		contextOffset, err := i32At(image, at+0x24, fileOffset)
		if err != nil {
			contextOffset = 0
		}
		// The name and the context are independent: a crossed context offset
		// must not hide a name whose own offset is intact. When the context
		// offset was lost it is not used even to bound the name slot, and the
		// context itself is skipped later with the stored value reported.
		var name string
		var nameBytes int
		hasName := false
		if nameOffsetCrossed {
			*warnings = append(*warnings, fmt.Sprintf(
				"the %s symbol node at offset %d has its name offset overwritten by the log sector signature; the stored bytes are reported as stored (name 0x%08X, context 0x%08X) and the name is not decoded",
				kind, offset, uint32(nameOffset), uint32(contextOffset)))
		} else {
			bound := contextOffset
			if contextOffsetCrossed {
				bound = -1
			}
			name, nameBytes, hasName = decodeSymbolName(image, nameOffset, bound)
			if !hasName && nameOffset > 0 {
				*warnings = append(*warnings, fmt.Sprintf(
					"the %s symbol at offset %d has a name at %d that did not decode as UTF-16",
					kind, offset, nameOffset))
			}
		}
		if hasName {
			start := addSaturating(fileOffset, uint64(nameOffset))
			end := addSaturating(start, uint64(nameBytes))
			for _, stamp := range signatureStamps(start, end, sectorSize) {
				relativeToImage := stamp - fileOffset
				if relativeToImage+2 > imageLen {
					continue
				}
				word := uint16(image[relativeToImage]) | uint16(image[relativeToImage+1])<<8
				if word == 0 {
					continue
				}
				*warnings = append(*warnings, fmt.Sprintf(
					"the %s symbol's name at offset %d crosses the log sector boundary at file offset %d; the two bytes stored at %d are %04X, where a stamped sector carries its signature instead of record data",
					kind, nameOffset, stamp+sectorSignatureBytes, stamp, word))
			}
		}
		nodeSize, err := u32At(image, at+0x04, fileOffset)
		if err != nil {
			nodeSize = 0
		}
		nameHash, err := u32At(image, at+0x08, fileOffset)
		if err != nil {
			nameHash = 0
		}
		dataSize, err := u32At(image, at+0x0C, fileOffset)
		if err != nil {
			dataSize = 0
		}
		symbol := Symbol{
			Offset:            offset,
			NodeType:          nodeType,
			NodeSize:          nodeSize,
			NameHash:          nameHash,
			DataSize:          dataSize,
			Below:             below,
			Above:             above,
			NameOffset:        nameOffset,
			ContextOffset:     contextOffset,
			ContextOffsetLost: contextOffsetCrossed,
			Deleted:           image[at+0x28] != 0,
			Name:              name,
			HasName:           hasName,
		}
		if symbol.Deleted {
			deleted++
		}
		if below != 0 {
			if belowCrossed {
				*warnings = append(*warnings, fmt.Sprintf(
					"the %s symbol node at offset %d has a below link whose bytes the log sector signature overwrote; the stored value 0x%016X is reported as stored and is not followed",
					kind, offset, below))
			} else {
				stack = append(stack, entry{offset: below, origin: symbolOrigin{kind: originBelow, node: offset}})
			}
		}
		if above != 0 {
			if aboveCrossed {
				*warnings = append(*warnings, fmt.Sprintf(
					"the %s symbol node at offset %d has an above link whose bytes the log sector signature overwrote; the stored value 0x%016X is reported as stored and is not followed",
					kind, offset, above))
			} else {
				stack = append(stack, entry{offset: above, origin: symbolOrigin{kind: originAbove, node: offset}})
			}
		}
		symbols = append(symbols, symbol)
	}
	return symbolWalk{symbols: symbols, capped: capped, deleted: deleted}
}

func parseClients(image []byte, fileOffset uint64, sectorSize uint32,
	symbols *[]Symbol, warnings *[]string) ([]Client, error) {
	clients := make([]Client, 0, len(*symbols))
	for _, symbol := range *symbols {
		if symbol.ContextOffsetLost {
			*warnings = append(*warnings, fmt.Sprintf(
				"the client symbol at offset %d has a context offset the log sector signature overwrote; its context was skipped and the stored offset (%d) is not used",
				symbol.Offset, symbol.ContextOffset))
			continue
		}
		slice, ok, err := contextSlice(image, fileOffset, symbol, ClientContextBytes, "client", warnings)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		contextOffset := addSaturating(fileOffset, uint64(symbol.ContextOffset))
		nodeType, err := u32At(slice, 0, contextOffset)
		if err != nil {
			return nil, err
		}
		if nodeType != NodeTypeClientContext {
			*warnings = append(*warnings, fmt.Sprintf(
				"the client symbol at offset %d has context type %08X, not %08X; its context was skipped",
				symbol.Offset, nodeType, NodeTypeClientContext))
			continue
		}
		context, err := parseClientContext(slice, contextOffset, sectorSize, warnings)
		if err != nil {
			return nil, err
		}
		clients = append(clients, Client{Symbol: symbol, Context: context})
	}
	*symbols = (*symbols)[:0]
	return clients, nil
}

func parseContainers(image []byte, fileOffset uint64, sectorSize uint32,
	symbols *[]Symbol, warnings *[]string) ([]LogContainer, error) {
	containers := make([]LogContainer, 0, len(*symbols))
	for _, symbol := range *symbols {
		if symbol.ContextOffsetLost {
			*warnings = append(*warnings, fmt.Sprintf(
				"the container symbol at offset %d has a context offset the log sector signature overwrote; its context was skipped and the stored offset (%d) is not used",
				symbol.Offset, symbol.ContextOffset))
			continue
		}
		slice, ok, err := contextSlice(image, fileOffset, symbol, ContainerContextBytes, "container", warnings)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		contextOffset := addSaturating(fileOffset, uint64(symbol.ContextOffset))
		nodeType, err := u32At(slice, 0, contextOffset)
		if err != nil {
			return nil, err
		}
		if nodeType != NodeTypeContainerContext {
			*warnings = append(*warnings, fmt.Sprintf(
				"the container symbol at offset %d has context type %08X, not %08X; its context was skipped",
				symbol.Offset, nodeType, NodeTypeContainerContext))
			continue
		}
		context, err := parseContainerContext(slice, contextOffset, sectorSize, warnings)
		if err != nil {
			return nil, err
		}
		containers = append(containers, LogContainer{Symbol: symbol, Context: context})
	}
	*symbols = (*symbols)[:0]
	return containers, nil
}

// contextSlice slices one symbol's declared context, refusing a truncated
// declaration.
//
// A symbol with no declared data is a warning and is skipped. A declaration
// that runs past the record image is refused by name: parsing it would mean
// manufacturing the missing bytes. A context shorter than the fixed structure
// is refused for the same reason.
func contextSlice(image []byte, fileOffset uint64, symbol Symbol, minimum int,
	kind string, warnings *[]string) ([]byte, bool, error) {
	if symbol.ContextOffset < 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"the %s symbol at offset %d declares a negative context offset %d; it was skipped",
			kind, symbol.Offset, symbol.ContextOffset))
		return nil, false, nil
	}
	start := uint64(symbol.ContextOffset)
	size := uint64(symbol.DataSize)
	if size == 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"the %s symbol at offset %d declares no context data; it was skipped",
			kind, symbol.Offset))
		return nil, false, nil
	}
	imageLen := uint64(len(image))
	end := addSaturating(start, size)
	if (end > imageLen || size < uint64(minimum)) && symbol.Deleted {
		// A deleted symbol's length field is not trustworthy: the $TxfLog
		// base log keeps a deleted container symbol declaring 0xAF100060
		// bytes while its fixed context is intact. Reading the fixed
		// structure is not manufacturing bytes — those bytes exist and the
		// caller checks the node type — and the stale declaration is named
		// instead of discarding every other container in the log.
		fixedEnd := addSaturating(start, uint64(minimum))
		if start <= imageLen && fixedEnd <= imageLen {
			*warnings = append(*warnings, fmt.Sprintf(
				"the deleted %s symbol at offset %d declares %d bytes for its context, which the %d byte base record cannot hold; the %d-byte fixed structure was read and the declaration is not used as its length",
				kind, symbol.Offset, size, len(image), minimum))
			return image[start:fixedEnd], true, nil
		}
	}
	if end > imageLen {
		return nil, false, corrupt(addSaturating(fileOffset, start), fmt.Sprintf(
			"the %s context at offset %d declares %d bytes but the base record image is only %d bytes",
			kind, start, size, len(image)))
	}
	if size < uint64(minimum) {
		return nil, false, corrupt(addSaturating(fileOffset, start), fmt.Sprintf(
			"the %s context at offset %d is %d bytes, shorter than the %d-byte fixed structure",
			kind, start, size, minimum))
	}
	return image[start:end], true, nil
}

// warnTableCrossing names every sector-signature stamp inside a symbol-table
// entry.
//
// A bucket holds one eight-byte pointer in the base record. When those eight
// bytes cross a sector boundary the stamp overwrites two of them, so a value
// built from the stored bytes is not what the log wrote — an empty bucket can
// read as a huge pointer. The walk still follows the stored value; this only
// says which entry the signature touched.
func warnTableCrossing(kind string, fileOffset uint64, tableOffset int,
	table [SymbolTableEntries]uint64, sectorSize uint32, record []byte, warnings *[]string) {
	tableAbs := addSaturating(fileOffset, uint64(tableOffset))
	recordLen := uint64(len(record))
	for index, value := range table {
		if value == 0 {
			continue
		}
		entryAbs := addSaturating(tableAbs, uint64(index)*8)
		for _, stamp := range signatureStamps(entryAbs, addSaturating(entryAbs, 8), sectorSize) {
			relativeToRecord := stamp - fileOffset
			if relativeToRecord+2 > recordLen {
				continue
			}
			word := uint16(record[relativeToRecord]) | uint16(record[relativeToRecord+1])<<8
			if word == 0 {
				continue
			}
			*warnings = append(*warnings, fmt.Sprintf(
				"the %s symbol table's bucket %d at file offset %d crosses the log sector boundary at file offset %d; the two bytes stored at %d are %04X, where a stamped sector carries its signature, so the stored pointer 0x%016X holds signature bytes rather than record data",
				kind, index, entryAbs, stamp+sectorSignatureBytes, stamp, word, value))
		}
	}
}

// warnContextCrossing names every sector-signature stamp inside one fixed
// context.
//
// The signature overwrites whatever record bytes sit at the end of a sector,
// so a field crossing that point carries the signature value instead of its
// own. The context is still parsed exactly as stored; this warning says where
// the record no longer holds its own bytes.
func warnContextCrossing(kind string, fileOffset uint64, bytes int, sectorSize uint32,
	context []byte, warnings *[]string) {
	contextLen := uint64(len(context))
	for _, stamp := range signatureStamps(fileOffset, addSaturating(fileOffset, uint64(bytes)), sectorSize) {
		relative := stamp - fileOffset
		if relative+2 > contextLen {
			continue
		}
		word := uint16(context[relative]) | uint16(context[relative+1])<<8
		if word == 0 {
			continue
		}
		*warnings = append(*warnings, fmt.Sprintf(
			"the %s context at offset %d crosses the log sector boundary at file offset %d; the two bytes stored at %d are %04X, where a stamped sector carries its signature, so a field holding them may not hold record data",
			kind, fileOffset, stamp+sectorSignatureBytes, stamp, word))
	}
}

func parseClientContext(bytes []byte, fileOffset uint64, sectorSize uint32,
	warnings *[]string) (ClientContext, error) {
	warnContextCrossing("client", fileOffset, ClientContextBytes, sectorSize, bytes, warnings)
	nodeType, err := u32At(bytes, 0x00, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	nodeSize, err := u32At(bytes, 0x04, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	clientID, err := u32At(bytes, 0x08, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	attributes, err := u16At(bytes, 0x0C, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	flushThreshold, err := u32At(bytes, 0x10, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	shadowSectors, err := u32At(bytes, 0x14, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	undoCommitment, err := u64At(bytes, 0x18, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	createTime, err := u64At(bytes, 0x20, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	accessTime, err := u64At(bytes, 0x28, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	writeTime, err := u64At(bytes, 0x30, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	ownerPageLSN, err := u64At(bytes, 0x38, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	archiveTailLSN, err := u64At(bytes, 0x40, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	baseLSN, err := u64At(bytes, 0x48, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	lastLSN, err := u64At(bytes, 0x50, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	restartLSN, err := u64At(bytes, 0x58, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	physicalBaseLSN, err := u64At(bytes, 0x60, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	unusedLSN1, err := u64At(bytes, 0x68, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	unusedLSN2, err := u64At(bytes, 0x70, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	state, err := u32At(bytes, 0x78, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	securityContext, err := u64At(bytes, 0x80, fileOffset)
	if err != nil {
		return ClientContext{}, err
	}
	return ClientContext{
		NodeType:        nodeType,
		NodeSize:        nodeSize,
		ClientID:        clientID,
		Attributes:      attributes,
		FlushThreshold:  flushThreshold,
		ShadowSectors:   shadowSectors,
		UndoCommitment:  undoCommitment,
		CreateTime:      createTime,
		AccessTime:      accessTime,
		WriteTime:       writeTime,
		OwnerPageLSN:    ownerPageLSN,
		ArchiveTailLSN:  archiveTailLSN,
		BaseLSN:         baseLSN,
		LastLSN:         lastLSN,
		RestartLSN:      restartLSN,
		PhysicalBaseLSN: physicalBaseLSN,
		UnusedLSN1:      unusedLSN1,
		UnusedLSN2:      unusedLSN2,
		State:           state,
		SecurityContext: securityContext,
	}, nil
}

func parseContainerContext(bytes []byte, fileOffset uint64, sectorSize uint32,
	warnings *[]string) (ContainerContext, error) {
	warnContextCrossing("container", fileOffset, ContainerContextBytes, sectorSize, bytes, warnings)
	nodeType, err := u32At(bytes, 0x00, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	nodeSize, err := u32At(bytes, 0x04, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	containerBytes, err := u64At(bytes, 0x08, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	containerID, err := u32At(bytes, 0x10, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	queueID, err := u32At(bytes, 0x14, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	storedPointer, err := u64At(bytes, 0x18, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	usn, err := u64At(bytes, 0x20, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	state, err := u32At(bytes, 0x28, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	previousOffset, err := u32At(bytes, 0x2C, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	nextOffset, err := u32At(bytes, 0x30, fileOffset)
	if err != nil {
		return ContainerContext{}, err
	}
	return ContainerContext{
		NodeType:               nodeType,
		NodeSize:               nodeSize,
		ContainerBytes:         containerBytes,
		ContainerID:            containerID,
		QueueID:                queueID,
		StoredContainerPointer: storedPointer,
		USN:                    usn,
		State:                  state,
		PreviousOffset:         previousOffset,
		NextOffset:             nextOffset,
		Extents:                nil,
	}, nil
}

// decodeSymbolName decodes a symbol's UTF-16LE name exactly as stored.
//
// The name begins at nameOffset. When the context offset lies after it, the
// bytes in between are the exact name region; otherwise the decoder scans for
// a NUL terminator. Either way the read is capped at MaxNameBytes and the
// result is trimmed of trailing NULs.
//
// Every log sector ends with a two-byte signature and the writer does not
// reserve room for it: a name that spans a sector boundary has those two
// bytes replaced by the signature. The returned text is therefore the stored
// bytes, signature value included, and the second result is the byte length
// the name occupied so the caller can name the stamp with signatureStamps.
// The original character is not recoverable — the file no longer holds it.
func decodeSymbolName(image []byte, nameOffset, contextOffset int32) (string, int, bool) {
	if nameOffset < 0 {
		return "", 0, false
	}
	start := int(nameOffset)
	if start >= len(image) {
		return "", 0, false
	}
	end := start + MaxNameBytes
	if end > len(image) {
		end = len(image)
	}
	if contextOffset > nameOffset {
		context := int(contextOffset)
		if context > start && context <= len(image) && context < end {
			end = context
		}
	}
	units := make([]uint16, 0, (end-start)/2)
	at := start
	for at+2 <= end {
		unit := uint16(image[at]) | uint16(image[at+1])<<8
		if unit == 0 {
			break
		}
		units = append(units, unit)
		at += 2
	}
	if len(units) == 0 {
		return "", 0, false
	}
	text, ok := decodeUTF16(units)
	if !ok {
		return "", 0, false
	}
	if text == "" {
		return "", 0, false
	}
	return text, at - start, true
}

// decodeUTF16 matches Rust's String::from_utf16: any unpaired surrogate is an
// error, not a replacement character.
func decodeUTF16(units []uint16) (string, bool) {
	runes := make([]rune, 0, len(units))
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if index+1 >= len(units) {
				return "", false
			}
			next := units[index+1]
			if next < 0xDC00 || next > 0xDFFF {
				return "", false
			}
			runes = append(runes, 0x10000+((rune(unit)-0xD800)<<10)+(rune(next)-0xDC00))
			index++
		case unit >= 0xDC00 && unit <= 0xDFFF:
			return "", false
		default:
			runes = append(runes, rune(unit))
		}
	}
	return string(runes), true
}

func maxInt() int { return int(^uint(0) >> 1) }
