// EVTX carving: whole event logs and the chunks left when the header is gone.
//
// An event log is a 4 KiB file header followed by 64 KiB chunks, and every
// chunk carries two CRCs of its own: one over its header fields and one over the
// event records it holds. That is enough structure to carve without the file
// header — a chunk found at an arbitrary offset proves itself, and its extent is
// the fixed 64 KiB the format gives every chunk.
//
// The file header adds its own CRC and the chunk count. A whole log is carved
// when the header verifies and the chunks it points at verify too; the extent is
// the last chunk that verifies, so a live log's preallocated but empty tail is
// not claimed as part of the object. A log whose header says nothing about its
// chunk count (a live image can catch it mid-write) is walked chunk by chunk
// until the sequence ends.

package carving

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	evtxFileHeaderLen  uint64 = 0x1000
	evtxChunkHeaderLen uint64 = 0x200
	evtxChunkLen       uint64 = 0x10000
)

// A file header that claims more chunks than this is not taken: the walk is
// bounded by the carve limit anyway, and this stops a nonsense count early.
const evtxMaxChunks uint64 = 1 << 12

var (
	evtxFileMagic  = []byte("ElfFile\x00")
	evtxChunkMagic = []byte("ElfChnk\x00")
)

// evtxChunkState is what one chunk header and its records prove.
type evtxChunkState int

const (
	evtxChunkInvalid evtxChunkState = iota
	evtxChunkIncomplete
	evtxChunkValid
)

func evtxFileBounds(src source.ByteSource, start, limit uint64) (*bounds, error) {
	if satSub(limit, start) < evtxFileHeaderLen+evtxChunkHeaderLen {
		return nil, nil
	}
	header, err := readVec(src, start, 0x80)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header[0:8], evtxFileMagic) {
		return nil, nil
	}
	if le32(header, 0x20) != 0x80 || le16(header, 0x28) != 0x1000 {
		return nil, nil
	}
	if le32(header, 0x7C) != foundation.CRC32(header[0:0x78]) {
		return nil, nil
	}
	declared := uint64(le16(header, 0x2A))
	if declared > evtxMaxChunks {
		return nil, nil
	}

	chunksAt := start + evtxFileHeaderLen
	var verified uint64
	var emptyAt *uint64
	for {
		if declared > 0 && verified >= declared {
			break
		}
		if verified >= evtxMaxChunks {
			return nil, nil
		}
		at := chunksAt + verified*evtxChunkLen
		if satAdd(at, evtxChunkHeaderLen) > limit {
			if verified == 0 {
				return nil, nil
			}
			return truncatedAt(limit, uint32(verified), "the next chunk runs past the bound"), nil
		}
		head, err := readVec(src, at, evtxChunkHeaderLen)
		if err != nil {
			return nil, err
		}
		if allZero(head) {
			// Allocated but never written. The log ends here, whatever the
			// header's count says.
			index := verified
			emptyAt = &index
			break
		}
		if !bytes.Equal(head[0:8], evtxChunkMagic) {
			// With a count the slot must hold a chunk; without one, anything
			// else is where the sequence ends.
			if declared > 0 {
				return nil, nil
			}
			break
		}
		state, recordsEnd, err := evtxChunkStateOf(src, at, head, limit)
		if err != nil {
			return nil, err
		}
		switch state {
		case evtxChunkValid:
			if satAdd(at, evtxChunkLen) > limit {
				return truncatedAt(limit, uint32(verified+1), "the chunk's 64 KiB extent runs past the bound"), nil
			}
			_ = recordsEnd
			verified++
		case evtxChunkIncomplete:
			if verified == 0 {
				return nil, nil
			}
			return truncatedAt(limit, uint32(verified), "a chunk's records run past the bound"), nil
		case evtxChunkInvalid:
			return nil, nil
		}
	}
	if verified == 0 {
		return nil, nil
	}

	end := chunksAt + verified*evtxChunkLen
	detail := fmt.Sprintf("%d chunk(s) with both checksums verified", verified)
	if declared > 0 && declared != verified {
		detail += fmt.Sprintf("; the header declares %d", declared)
	}
	if emptyAt != nil {
		detail += fmt.Sprintf("; chunk %d is empty, which ends the log", *emptyAt)
	}
	return &bounds{End: end, Terminated: true, Detail: detail}, nil
}

func evtxChunkBounds(src source.ByteSource, start, limit uint64) (*bounds, error) {
	if satSub(limit, start) < evtxChunkHeaderLen {
		return nil, nil
	}
	head, err := readVec(src, start, evtxChunkHeaderLen)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(head[0:8], evtxChunkMagic) {
		return nil, nil
	}
	state, recordsEnd, err := evtxChunkStateOf(src, start, head, limit)
	if err != nil {
		return nil, err
	}
	switch state {
	case evtxChunkInvalid:
		return nil, nil
	case evtxChunkIncomplete:
		return truncatedAt(limit, 0, "the chunk's records run past the bound"), nil
	default:
		if satAdd(start, evtxChunkLen) > limit {
			return truncatedAt(limit, 0, fmt.Sprintf(
				"the chunk's records end at %#x, but its 64 KiB extent runs past the bound",
				recordsEnd,
			)), nil
		}
		return &bounds{
			End:        start + evtxChunkLen,
			Terminated: true,
			Detail:     fmt.Sprintf("one 64 KiB chunk; its records end at %#x", recordsEnd),
		}, nil
	}
}

func evtxChunkStateOf(src source.ByteSource, at uint64, head []byte, limit uint64) (evtxChunkState, uint64, error) {
	recordsEnd := uint64(le32(head, 0x30))
	if recordsEnd < evtxChunkHeaderLen || recordsEnd > evtxChunkLen {
		return evtxChunkInvalid, 0, nil
	}
	if le32(head, 0x7C) != evtxChunkHeaderChecksum(head) {
		return evtxChunkInvalid, 0, nil
	}
	if satAdd(at, recordsEnd) > limit {
		return evtxChunkIncomplete, 0, nil
	}
	records, err := crcRange(src, at+evtxChunkHeaderLen, recordsEnd-evtxChunkHeaderLen)
	if err != nil {
		return evtxChunkInvalid, 0, err
	}
	if records != le32(head, 0x34) {
		return evtxChunkInvalid, 0, nil
	}
	return evtxChunkValid, recordsEnd, nil
}

// evtxChunkHeaderChecksum covers the first 0x78 bytes and the offset table that
// follows the checksum field, skipping the checksum itself.
func evtxChunkHeaderChecksum(head []byte) uint32 {
	state := foundation.CRC32Seeded(0xFFFFFFFF, head[0:0x78])
	state = foundation.CRC32Seeded(state, head[0x80:0x200])
	return ^state
}

func le16(bytes []byte, at int) uint16 {
	return binary.LittleEndian.Uint16(bytes[at : at+2])
}

func le32(bytes []byte, at int) uint32 {
	return binary.LittleEndian.Uint32(bytes[at : at+4])
}

func allZero(bytes []byte) bool {
	for _, b := range bytes {
		if b != 0 {
			return false
		}
	}
	return true
}
