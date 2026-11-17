package clfs

import (
	"fmt"
	"math"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ContainerHeader is a container file's first log block, decoded as far as its
// header.
//
// Containers are contiguous files of log blocks. The first block's physical
// LSN names the container id, the block's byte offset inside the container,
// and the record sequence within the block. This reader verifies the log-block
// signature and reports the stored CRC; it does not walk the container's owner
// pages, sector maps, or records, and the format documents no extent list in
// this header.
type ContainerHeader struct {
	Header LogBlockHeader
	// ContainerID is the high dword of the physical LSN, when claimed.
	ContainerID *uint32
	// BlockOffset is the byte offset of this block inside the container (low
	// 23 bits, scaled by SectorSize), as the physical LSN encodes it, when
	// claimed.
	BlockOffset *uint64
	// RecordSequence is the record sequence within the block (low 9 bits),
	// when claimed.
	RecordSequence *uint16
	// FileLen is the whole file's length, which bounds the container's one
	// extent.
	FileLen uint64
	// Warnings includes a non-zero stream number or a torn checksum.
	Warnings []string
}

// OpenContainer reads the first log block header of a container.
//
// The 15 00 signature and a non-zero sector count are required. A block that
// declares more bytes than the file holds is reported with a warning and
// parsed only as far as the file allows, because a truncated container is
// common in acquired images. A checksum of zero is "not recorded", never a
// pass.
//
// A container is a circular log. Registry transaction-log containers
// (`{GUID}.TxR.N.regtrans-ms`) are written by the registry in one update
// sequence at a time and can begin in the middle of a block that started in an
// earlier 512 KiB region; offset zero then holds log data, not a header. When
// the first sectors carry no block header, the reader looks for the first
// complete header at a sector boundary in the file's first megabyte and
// reports its offset with a warning. The prefix is named rather than assumed
// away, and a file with no valid header anywhere in that window is still
// refused with the offset-zero error.
func OpenContainer(src source.ByteSource) (*ContainerHeader, error) {
	if src == nil {
		return nil, corrupt(0, "a nil source cannot be read")
	}
	fileLen := src.Len()
	if fileLen < LogBlockHeaderBytes {
		return nil, corrupt(0, fmt.Sprintf(
			"a CLFS container needs at least %d bytes, not %d", LogBlockHeaderBytes, fileLen))
	}
	var warnings []string
	var firstOffset uint64
	head, err := source.ReadVecAt(src, 0, LogBlockHeaderBytes)
	if err != nil {
		return nil, err
	}
	header, parseErr := parseLogBlockHeader(head, 0)
	if parseErr != nil {
		offset, candidate, found, scanErr := findFirstBlock(src, fileLen)
		if scanErr != nil {
			return nil, scanErr
		}
		if !found {
			return nil, parseErr
		}
		warnings = append(warnings, fmt.Sprintf(
			"the file does not begin with a log block (%v); the first complete log block header is at offset %d",
			parseErr, offset))
		firstOffset = offset
		header, parseErr = parseLogBlockHeader(candidate, offset)
		if parseErr != nil {
			return nil, parseErr
		}
	}
	// Defensive: parseLogBlockHeader already rejects a sector count too small
	// for the fixed header, so a zero count cannot reach this branch. The
	// check mirrors the reference implementation.
	if header.TotalSectorCount == 0 {
		return nil, corrupt(firstOffset+0x04, "the container log block declares zero sectors")
	}
	if header.ClientID != 0 {
		warnings = append(warnings, fmt.Sprintf(
			"the log block's stream number is %d, not 0 (a container block); it is reported as stored",
			header.ClientID))
	}
	available := fileLen - firstOffset
	readLen := header.DeclaredBytes
	if readLen > available {
		readLen = available
	}
	if header.DeclaredBytes > available {
		warnings = append(warnings, fmt.Sprintf(
			"the container log block declares %d bytes but only %d remain from offset %d; the block is truncated",
			header.DeclaredBytes, available, firstOffset))
	}
	if readLen == header.DeclaredBytes && readLen >= LogBlockHeaderBytes {
		block, err := source.ReadVecAt(src, firstOffset, readLen)
		if err != nil {
			return nil, err
		}
		applyChecksum(block, &header, "container log block", &warnings)
	}
	var containerID *uint32
	var blockOffset *uint64
	var recordSequence *uint16
	if header.CurrentLSN == math.MaxUint64 {
		warnings = append(warnings,
			"the container log block's current LSN is invalid (FFFFFFFFFFFFFFFF); no container id or offset is decoded")
	} else {
		decoded := DecodePhysicalLSN(header.CurrentLSN)
		// A block found past offset zero must also claim that file offset;
		// the registry writes its `N.regtrans-ms` containers so that the
		// first header sits inside the file, and the LSN in those blocks
		// decodes to offset zero. Reporting its container id would name a
		// container the base log does not list, so the fields are left
		// unclaimed and the mismatch is named instead.
		if firstOffset != 0 && decoded.BlockOffset != firstOffset {
			warnings = append(warnings, fmt.Sprintf(
				"the block's current LSN decodes to container %d at offset %d, but its header is at file offset %d; no container id or block offset is claimed",
				decoded.ContainerID, decoded.BlockOffset, firstOffset))
		} else {
			id := decoded.ContainerID
			offset := decoded.BlockOffset
			sequence := decoded.RecordSequence
			containerID = &id
			blockOffset = &offset
			recordSequence = &sequence
		}
	}
	return &ContainerHeader{
		Header:         header,
		ContainerID:    containerID,
		BlockOffset:    blockOffset,
		RecordSequence: recordSequence,
		FileLen:        fileLen,
		Warnings:       warnings,
	}, nil
}

// findFirstBlock looks for the first complete log block header at a sector
// boundary in the head of a container.
//
// This is only consulted when offset zero carries no header: a circular log
// can begin inside a block begun in an earlier region. Candidates must satisfy
// the header's own bounds (a sector count that fits the file and a
// signature-backup offset inside the block), which keeps a stray 15 00 in log
// data from being reported as a block.
func findFirstBlock(src source.ByteSource, fileLen uint64) (uint64, []byte, bool, error) {
	window := fileLen
	if window > MaxFirstBlockScan {
		window = MaxFirstBlockScan
	}
	if window < LogBlockHeaderBytes+SectorSize {
		return 0, nil, false, nil
	}
	prefix, err := source.ReadVecAt(src, 0, window)
	if err != nil {
		return 0, nil, false, err
	}
	for offset := SectorSize; addSaturating(offset, LogBlockHeaderBytes) <= window; offset += SectorSize {
		start := int(offset)
		candidate := prefix[start : start+LogBlockHeaderBytes]
		if candidate[0] != MajorVersion || candidate[1] != MinorVersion || candidate[3] != 0 {
			continue
		}
		header, err := parseLogBlockHeader(candidate, offset)
		if err != nil {
			continue
		}
		signatures := uint64(header.SignaturesOffset)
		if header.TotalSectorCount > 0 &&
			header.ValidSectorCount <= header.TotalSectorCount &&
			header.DeclaredBytes <= fileLen-offset &&
			signatures >= LogBlockHeaderBytes &&
			signatures < header.DeclaredBytes {
			return offset, candidate, true, nil
		}
	}
	return 0, nil, false, nil
}
