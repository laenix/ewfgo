package leveldb

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxWalBytes is the largest WAL this reader decodes in memory.
const MaxWalBytes uint64 = 256 * 1024 * 1024

// Log is what a write-ahead log says about itself.
type Log struct {
	// Records is the number of log records read, including ones that did
	// not decode.
	Records uint64
	// Batches is the number of write batches that decoded.
	Batches uint64
	// Entries is the number of entries across the decoded batches.
	Entries uint64
	// Deletions is the number of entries whose type is a deletion.
	Deletions uint64
	// ChecksumFailures is the number of records skipped because their CRC
	// did not match.
	ChecksumFailures uint64
	// DecodeFailures is the number of records skipped because their batch
	// did not decode.
	DecodeFailures uint64
	// FirstSequence is the smallest sequence number seen.
	FirstSequence *uint64
	// LastSequence is the largest sequence number seen.
	LastSequence *uint64
	// FirstKey is the first entry's key, rendered.
	FirstKey *string
	// LastKey is the last entry's key, rendered.
	LastKey *string
	// KeyBytes is the sum of key bytes across entries.
	KeyBytes uint64
	// ValueBytes is the sum of value bytes across non-deletion entries.
	ValueBytes uint64
	// StoppedAtLimit is true when a log limit stopped the scan.
	StoppedAtLimit bool
	// Warnings are issues that did not stop the parse.
	Warnings []string
}

// BatchHeader is a write batch's own header.
type BatchHeader struct {
	// Sequence is the sequence number of the batch's first entry.
	Sequence uint64
	// Count is the entry count the header declares.
	Count uint32
}

// BatchEntry is one entry for EncodeBatch.
type BatchEntry struct {
	Key     []byte
	Value   []byte
	Deleted bool
}

// OpenLog reads and decodes a whole write-ahead log with the default limits.
func OpenLog(src source.ByteSource) (*Log, error) {
	return OpenLogWithLimits(src, DefaultLogLimits())
}

// OpenLogWithLimits reads and decodes a whole write-ahead log.
func OpenLogWithLimits(src source.ByteSource, limits LogLimits) (*Log, error) {
	limits = limits.normalized()
	max := MaxWalBytes
	if uint64(limits.MaxBytes) < max {
		max = uint64(limits.MaxBytes)
	}
	bytes, err := readWholeSource(src, max)
	if err != nil {
		return nil, err
	}
	return parseWalBytes(bytes, limits)
}

type decodedBatchEntry struct {
	sequence uint64
	key      []byte
	value    []byte
	deleted  bool
}

func parseWalBytes(bytes []byte, limits LogLimits) (*Log, error) {
	scan, err := ScanLog(bytes, limits)
	if err != nil {
		return nil, err
	}
	log := &Log{
		StoppedAtLimit: scan.StoppedAtLimit,
		Warnings:       append([]string(nil), scan.Warnings...),
	}
	for _, record := range scan.Records {
		log.Records++
		if !record.CRCOK {
			log.ChecksumFailures++
			log.Warnings = append(log.Warnings, fmt.Sprintf(
				"write batch at byte %d failed its checksum and was skipped", record.Offset))
			continue
		}
		// Decode the whole batch before counting anything, so a truncated
		// batch contributes no partial entries to the summary.
		var entries []decodedBatchEntry
		_, err := DecodeBatch(record.Payload, func(sequence uint64, key, value []byte, deleted bool) bool {
			entries = append(entries, decodedBatchEntry{
				sequence: sequence,
				key:      append([]byte(nil), key...),
				value:    append([]byte(nil), value...),
				deleted:  deleted,
			})
			return true
		})
		if err != nil {
			log.DecodeFailures++
			log.Warnings = append(log.Warnings, fmt.Sprintf(
				"write batch at byte %d: %v", record.Offset, err))
			continue
		}
		log.Batches++
		for _, entry := range entries {
			log.Entries++
			if entry.deleted {
				log.Deletions++
			} else {
				log.ValueBytes += uint64(len(entry.value))
			}
			log.KeyBytes += uint64(len(entry.key))
			log.FirstSequence = ptr(minValue(log.FirstSequence, entry.sequence))
			log.LastSequence = ptr(maxValue(log.LastSequence, entry.sequence))
			rendered := RenderKey(entry.key)
			if log.FirstKey == nil {
				log.FirstKey = ptr(rendered)
			}
			log.LastKey = ptr(rendered)
		}
	}
	return log, nil
}

// DecodeBatch visits every entry of one batch with its sequence number. A
// deletion is passed with deleted=true and a nil value. Returning false stops
// the walk; the header is still returned.
func DecodeBatch(payload []byte, visit func(sequence uint64, key, value []byte, deleted bool) bool) (BatchHeader, error) {
	if len(payload) < 12 {
		return BatchHeader{}, corrupt(0, fmt.Sprintf(
			"a write batch of %d bytes is shorter than its 12-byte header", len(payload)))
	}
	header := BatchHeader{
		Sequence: le64(payload, 0),
		Count:    le32(payload, 8),
	}
	at := 12
	var seen uint32
	for seen < header.Count {
		if at >= len(payload) {
			return header, corrupt(0, fmt.Sprintf(
				"the batch declares %d entries but holds %d", header.Count, seen))
		}
		tag := payload[at]
		at++
		keyLen, used, ok := readVarint(payload[at:])
		if !ok {
			return header, corrupt(0, fmt.Sprintf("entry %d's key length does not decode", seen))
		}
		at += used
		if keyLen > uint64(len(payload)-at) {
			return header, corrupt(0, fmt.Sprintf("entry %d's key runs past the batch", seen))
		}
		keyEnd := at + int(keyLen)
		key := payload[at:keyEnd]
		at = keyEnd
		var value []byte
		var deleted bool
		switch tag {
		case 0:
			deleted = true
		case 1:
			valueLen, used, ok := readVarint(payload[at:])
			if !ok {
				return header, corrupt(0, fmt.Sprintf("entry %d's value length does not decode", seen))
			}
			at += used
			if valueLen > uint64(len(payload)-at) {
				return header, corrupt(0, fmt.Sprintf("entry %d's value runs past the batch", seen))
			}
			valueEnd := at + int(valueLen)
			value = payload[at:valueEnd]
			at = valueEnd
		default:
			return header, corrupt(0, fmt.Sprintf(
				"entry %d has value type %d, which is neither a deletion nor a value", seen, tag))
		}
		sequence := header.Sequence + uint64(seen)
		seen++
		if !visit(sequence, key, value, deleted) {
			break
		}
	}
	return header, nil
}

// EncodeBatch encodes one batch, as a fixture builder would.
func EncodeBatch(sequence uint64, entries []BatchEntry) []byte {
	out := make([]byte, 0, 12+len(entries)*8)
	var header [12]byte
	for index := 0; index < 8; index++ {
		header[index] = byte(sequence >> (8 * index))
	}
	count := uint32(len(entries))
	header[8] = byte(count)
	header[9] = byte(count >> 8)
	header[10] = byte(count >> 16)
	header[11] = byte(count >> 24)
	out = append(out, header[:]...)
	for _, entry := range entries {
		if entry.Deleted {
			out = append(out, 0)
		} else {
			out = append(out, 1)
		}
		out = appendVarint(out, uint64(len(entry.Key)))
		out = append(out, entry.Key...)
		if !entry.Deleted {
			out = appendVarint(out, uint64(len(entry.Value)))
			out = append(out, entry.Value...)
		}
	}
	return out
}
