// Package clfs reads Microsoft Common Log File System (CLFS) metadata.
//
// CLFS is the log engine Windows uses for the transactional registry (TxR)
// and other crash-safe writers. Two kinds of file matter to a forensic
// reader:
//
//   - the base log file (`SYSTEM.blf` or `{GUID}.blf`), which lists the log's
//     clients (the streams the log serves) and its containers (the
//     `*.regtrans-ms` files that hold log records);
//   - the containers (`{GUID}.TxR.N.regtrans-ms`), each a contiguous file of
//     CLFS log blocks.
//
// This package is deliberately metadata-only. It reads the base log file's
// log block header, its control record (which locates the metadata blocks),
// its base record (log id, client/container symbol tables, state), and the
// client and container contexts reachable from those symbol tables. It does
// not walk log records, replay a log, decode container record payloads, or
// read registry cells; OpenStream and OpenRecord therefore return
// source.ErrUnsupported. A container read stops after the first log block
// header: the container's physical LSN names the container id, the byte
// offset of the block inside the container, and the record sequence within
// the block, but no extent table is decoded.
//
// The layout follows the public reverse-engineering references that agree
// with each other: the libfsclfs project documentation (Joachim Metz), Alex
// Ionescu's clfs-docs, and Fox-IT's dissect.clfs.
//
// Checksums: a metadata block header stores a CRC-32 at 0x0C. ClfsEncodeBlock
// zeroes that field and computes a CRC-32 over the whole block with
// polynomial 0x04C11DB7. This reader computes the reflected IEEE-802.3
// CRC-32 (0xEDB88320, initial and final 0xFFFFFFFF) over the declared block
// with the checksum field zeroed and reports the comparison. A mismatch is a
// warning, not a refusal: a torn tail is common in acquired images and the
// metadata is still the only description of the log. A checksum that was
// never recorded (all zero) is reported as nil, never as a pass. No other
// checksum is claimed.
//
// Every read is bounded and every skip is named in Stats.Warnings. Corrupt,
// truncated or unsupported structures are explicit errors
// (source.ErrCorrupt, source.ErrUnexpectedEOF, source.ErrUnsupported); no
// damaged block is zero-filled.
//
// This is a pure-Go port of forensic-core's data/containers/clfs.rs.
package clfs

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"

	"github.com/laenix/ewfgo/internal/data/source"
)

// One CLFS sector. All log-block sizes are multiples of this.
const SectorSize uint64 = 512

// Bytes at the end of every log sector that hold the sector signature.
const sectorSignatureBytes uint64 = 2

const (
	// LogBlockHeaderBytes is the fixed size of a log block header.
	LogBlockHeaderBytes = 0x70
	// ControlRecordMagic is the magic at control record +0x08
	// (C1F5C1F5 00005F1C).
	ControlRecordMagic uint64 = 0xC1F5C1F500005F1C
	// BaseRecordBytes is the size of the fixed CLFS_BASE_RECORD_HEADER.
	BaseRecordBytes = 0x1338
	// MajorVersion is the major version every CLFS log block carries.
	MajorVersion uint8 = 0x15
	// MinorVersion is the minor version every CLFS log block carries.
	MinorVersion uint8 = 0x00
)

// CLFS node types.
const (
	// NodeTypeSymbol is CLFS_NODE_TYPE_SYMBOL, a CLFSHASHSYM header.
	NodeTypeSymbol uint32 = 0xC1FDF006
	// NodeTypeClientContext is CLFS_NODE_TYPE_CLIENT_CONTEXT.
	NodeTypeClientContext uint32 = 0xC1FDF007
	// NodeTypeContainerContext is CLFS_NODE_TYPE_CONTAINER_CONTEXT.
	NodeTypeContainerContext uint32 = 0xC1FDF008
	// NodeTypeSharedSecurityContext is CLFS_NODE_TYPE_SHARED_SECURITY_CONTEXT.
	NodeTypeSharedSecurityContext uint32 = 0xC1FDF00D
)

const (
	// SymbolTableEntries is the bucket count in each base-record symbol table.
	SymbolTableEntries = 11
	// ClientSymbolTableOffset is the base-record offset of the client table.
	ClientSymbolTableOffset = 0x18
	// ContainerSymbolTableOffset is the base-record offset of the container table.
	ContainerSymbolTableOffset = 0x70
	// SecuritySymbolTableOffset is the base-record offset of the security table.
	SecuritySymbolTableOffset = 0xC8
	// SymbolHeaderBytes is the size of a CLFSHASHSYM header.
	SymbolHeaderBytes = 0x30
	// ClientContextBytes is the fixed part of a client context.
	ClientContextBytes = 0x88
	// ContainerContextBytes is the fixed part of a container context.
	ContainerContextBytes = 0x38
	// MaxNameBytes is the longest UTF-16 symbol name this reader decodes.
	MaxNameBytes = 0x1000
	// MaxMetadataBlocks bounds metadata entries decoded from a control record.
	MaxMetadataBlocks = 64
	// MaxClients bounds client symbols decoded from a base record.
	MaxClients = 64
	// MaxContainers bounds container symbols decoded from a base record.
	MaxContainers = 1024
	// MaxExtents bounds a context extent list if a future definition supplies
	// one. The documented CLFS_CONTAINER_CONTEXT has no extent list, so parsed
	// contexts always expose an empty slice; this bound is part of the
	// reader's contract rather than a value seen on disk.
	MaxExtents = 1024
)

// MaxBaseRecordBytes bounds a general metadata block image. A larger block is
// only read up to this many bytes.
const MaxBaseRecordBytes uint64 = 16 * 1024 * 1024

// MaxFirstBlockScan is how many bytes of a container are searched when offset
// zero is log data. A circular container can begin in the middle of a block,
// which is far shorter than this window.
const MaxFirstBlockScan uint64 = 1024 * 1024

// Kind identifies which CLFS file Open parsed.
type Kind uint8

const (
	// KindBaseLog is a base log file (`.blf`).
	KindBaseLog Kind = iota
	// KindContainer is a container file (`*.regtrans-ms`).
	KindContainer
)

// Label returns "base-log" or "container".
func (k Kind) Label() string {
	if k == KindContainer {
		return "container"
	}
	return "base-log"
}

// Container is the parsed form of a CLFS file: either a base log or a
// container file. It is read-only and backed by the source it was opened
// from. This reader exposes metadata only.
type Container struct {
	source source.ByteSource
	kind   Kind
	base   *BaseLog
	header *ContainerHeader
}

// Open parses a CLFS file. A head carrying the control-record magic at 0x78
// is read as a base log; a head carrying the 15 00 log-block signature
// without that magic is read as a container. Anything else is handed to the
// base-log reader so the failure names the offset-zero signature.
func Open(src source.ByteSource) (*Container, error) {
	if src == nil {
		return nil, corrupt(0, "a nil source cannot be read")
	}
	headLen := src.Len()
	if headLen > LogBlockHeaderBytes+0x10 {
		headLen = LogBlockHeaderBytes + 0x10
	}
	var head []byte
	if headLen > 0 {
		var err error
		head, err = source.ReadVecAt(src, 0, headLen)
		if err != nil {
			return nil, err
		}
	}
	switch {
	case Detect(head):
		base, err := OpenBaseLog(src)
		if err != nil {
			return nil, err
		}
		return &Container{source: src, kind: KindBaseLog, base: base}, nil
	case hasLogBlockSignature(head):
		header, err := OpenContainer(src)
		if err != nil {
			return nil, err
		}
		return &Container{source: src, kind: KindContainer, header: header}, nil
	default:
		base, err := OpenBaseLog(src)
		if err != nil {
			return nil, err
		}
		return &Container{source: src, kind: KindBaseLog, base: base}, nil
	}
}

// Detect reports whether head looks like the start of a CLFS base log file:
// the 15 00 log-block signature and the control-record magic at 0x78.
func Detect(head []byte) bool {
	return len(head) >= LogBlockHeaderBytes+0x10 &&
		head[0] == MajorVersion &&
		head[1] == MinorVersion &&
		binary.LittleEndian.Uint64(head[0x78:0x80]) == ControlRecordMagic
}

// DetectContainer reports whether head looks like a CLFS container log block:
// the 15 00 signature, stream number 0, and no base-log control-record magic
// at 0x78.
//
// The magic check is what separates a container from a base log file: both
// start with the same log block header, and the base log's control record is
// the stronger content discriminator. Container detection is a heuristic;
// callers should prefer the `.blf` check first when a file's extension is not
// enough.
func DetectContainer(head []byte) bool {
	return len(head) >= LogBlockHeaderBytes &&
		head[0] == MajorVersion &&
		head[1] == MinorVersion &&
		head[3] == 0 &&
		!Detect(head)
}

// Kind returns which CLFS file was parsed.
func (c *Container) Kind() Kind { return c.kind }

// Source returns the underlying file.
func (c *Container) Source() source.ByteSource { return c.source }

// BaseLog returns the parsed base log, or nil when this is a container file.
func (c *Container) BaseLog() *BaseLog { return c.base }

// Header returns the parsed container header, or nil when this is a base log.
func (c *Container) Header() *ContainerHeader { return c.header }

// OpenStream refuses payload reconstruction. The reference reader is
// metadata-only and does not walk log records, so no stream bytes can be
// exposed without inventing them.
func (c *Container) OpenStream(name string) (source.ByteSource, error) {
	return nil, unsupportedPayload()
}

// OpenRecord refuses payload reconstruction. The reference reader is
// metadata-only and does not decode container record payloads.
func (c *Container) OpenRecord(lsn uint64) (source.ByteSource, error) {
	return nil, unsupportedPayload()
}

func unsupportedPayload() error {
	return &source.Error{
		Kind: source.ErrUnsupported,
		Reason: "CLFS: log record payload reconstruction is not implemented; " +
			"the reader exposes metadata only",
	}
}

func hasLogBlockSignature(head []byte) bool {
	return len(head) >= 2 && head[0] == MajorVersion && head[1] == MinorVersion
}

// LSN is a physical LSN split into its three documented fields.
type LSN struct {
	Raw uint64
	// ContainerID is the high 32 bits.
	ContainerID uint32
	// BlockOffset is the block's byte offset inside the container: low 32
	// bits, bits 31..=9 (23 bits), scaled by SectorSize.
	BlockOffset uint64
	// RecordSequence is the low 9 bits: the record sequence within the block.
	RecordSequence uint16
}

// DecodePhysicalLSN decodes a physical LSN the way the CLFS definitions
// describe it.
func DecodePhysicalLSN(raw uint64) LSN {
	index := uint32(raw)
	return LSN{
		Raw:            raw,
		ContainerID:    uint32(raw >> 32),
		BlockOffset:    uint64((index>>9)&0x007FFFFF) * SectorSize,
		RecordSequence: uint16(index & 0x1FF),
	}
}

// effectiveSectorSize returns the sector size a record's physical offsets are
// measured in. A record that states no sector size still uses the format's
// 512-byte sectors. A declared size that is not a power of two in 512..=4096
// is not used to place signatures.
func effectiveSectorSize(sectorSize uint32) (uint64, bool) {
	if sectorSize == 0 {
		return SectorSize, true
	}
	if sectorSize&(sectorSize-1) != 0 {
		return 0, false
	}
	size := uint64(sectorSize)
	if size < 512 || size > 4096 {
		return 0, false
	}
	return size, true
}

// signatureStamps returns the absolute offsets of every sector-signature stamp
// inside [start, end). A stamp is the two bytes immediately before a sector
// boundary. The writer does not reserve these bytes: a record field crossing a
// boundary has the signature written over it, so the stamp offset names bytes
// that no longer hold record data.
func signatureStamps(start, end uint64, sectorSize uint32) []uint64 {
	sector, ok := effectiveSectorSize(sectorSize)
	if !ok || end <= start {
		return nil
	}
	quotient := start / sector
	if quotient > math.MaxUint64/sector-1 {
		return nil
	}
	boundary := (quotient + 1) * sector
	var stamps []uint64
	for boundary >= sectorSignatureBytes {
		stamp := boundary - sectorSignatureBytes
		if stamp >= end {
			break
		}
		// Only a window wholly inside the range is reported: the bytes that
		// follow must be readable from the same slice.
		if stamp >= start && stamp+sectorSignatureBytes <= end {
			stamps = append(stamps, stamp)
		}
		if boundary > math.MaxUint64-sector {
			break
		}
		boundary += sector
	}
	return stamps
}

// applyChecksum recomputes the header's CRC-32 over the block with the
// checksum zeroed and records the comparison on the header. A zero stored
// checksum means "not recorded" and leaves ChecksumOK nil.
func applyChecksum(block []byte, header *LogBlockHeader, label string, warnings *[]string) {
	if header.Checksum == 0 || len(block) < LogBlockHeaderBytes {
		return
	}
	buffer := make([]byte, len(block))
	copy(buffer, block)
	for index := 0x0C; index < 0x10; index++ {
		buffer[index] = 0
	}
	computed := crc32.ChecksumIEEE(buffer)
	ok := computed == header.Checksum
	header.ChecksumOK = &ok
	if !ok {
		*warnings = append(*warnings, fmt.Sprintf(
			"the %s CRC-32 is 0x%08X as computed, but 0x%08X is stored",
			label, computed, header.Checksum,
		))
	}
}

// guidText renders the stored log id in the byte order it was stored, grouped
// as a GUID for display.
func guidText(bytes [16]byte) string {
	return fmt.Sprintf(
		"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		bytes[0], bytes[1], bytes[2], bytes[3],
		bytes[4], bytes[5], bytes[6], bytes[7],
		bytes[8], bytes[9], bytes[10], bytes[11],
		bytes[12], bytes[13], bytes[14], bytes[15],
	)
}

func corrupt(offset uint64, reason string) error {
	return source.NewCorrupt(offset, reason)
}

func addSaturating(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func fieldPastEnd(base uint64, at int) error {
	offset := base
	if at >= 0 {
		offset = addSaturating(base, uint64(at))
	}
	return corrupt(offset, "field is past the end of the structure")
}

func u16At(bytes []byte, at int, base uint64) (uint16, error) {
	if at < 0 || at > len(bytes)-2 {
		return 0, fieldPastEnd(base, at)
	}
	return binary.LittleEndian.Uint16(bytes[at:]), nil
}

func u32At(bytes []byte, at int, base uint64) (uint32, error) {
	if at < 0 || at > len(bytes)-4 {
		return 0, fieldPastEnd(base, at)
	}
	return binary.LittleEndian.Uint32(bytes[at:]), nil
}

func i32At(bytes []byte, at int, base uint64) (int32, error) {
	value, err := u32At(bytes, at, base)
	return int32(value), err
}

func u64At(bytes []byte, at int, base uint64) (uint64, error) {
	if at < 0 || at > len(bytes)-8 {
		return 0, fieldPastEnd(base, at)
	}
	return binary.LittleEndian.Uint64(bytes[at:]), nil
}
