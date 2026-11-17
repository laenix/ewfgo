package leveldb

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// LogBlockBytes is the bytes per log block.
	LogBlockBytes = 32 * 1024
	// LogHeaderBytes is the bytes of a record header.
	LogHeaderBytes = 7
)

const (
	logTypeZero   byte = 0
	logTypeFull   byte = 1
	logTypeFirst  byte = 2
	logTypeMiddle byte = 3
	logTypeLast   byte = 4
)

const maskDelta uint32 = 0xa282ead8

// LogLimits bounds how much of a log a scan may keep.
type LogLimits struct {
	// MaxRecords bounds stitched records held.
	MaxRecords int
	// MaxBytes bounds payload bytes held.
	MaxBytes int
	// MaxPayload bounds one record's payload.
	MaxPayload int
}

// DefaultLogLimits returns the reference reader's log bounds.
func DefaultLogLimits() LogLimits {
	return LogLimits{
		MaxRecords: 1_000_000,
		MaxBytes:   64 * 1024 * 1024,
		MaxPayload: 16 * 1024 * 1024,
	}
}

func (l LogLimits) normalized() LogLimits {
	defaults := DefaultLogLimits()
	if l.MaxRecords <= 0 {
		l.MaxRecords = defaults.MaxRecords
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = defaults.MaxBytes
	}
	if l.MaxPayload <= 0 {
		l.MaxPayload = defaults.MaxPayload
	}
	return l
}

// MaskCRC masks a CRC the way LevelDB stores it.
func MaskCRC(crc uint32) uint32 { return maskCRC(crc) }

// UnmaskCRC unmasks a stored CRC.
func UnmaskCRC(masked uint32) uint32 {
	return rotateLeft15(masked - maskDelta)
}

func rotateLeft15(value uint32) uint32 {
	return value<<15 | value>>(32-15)
}

// LogRecord is one stitched record.
type LogRecord struct {
	// Payload is the record's bytes.
	Payload []byte
	// Offset is the byte offset of the fragment that started the record.
	Offset uint64
	// CRCOK is false when the stored CRC did not match the payload.
	CRCOK bool
}

// LogScan is the result of reading a whole log.
type LogScan struct {
	// Records are the stitched records, including ones whose CRC failed.
	Records []LogRecord
	// ChecksumFailures counts records whose CRC did not match.
	ChecksumFailures uint64
	// Incomplete counts records whose fragments end without a last.
	Incomplete uint64
	// Truncated counts bytes of a record that ran past the declared bounds.
	Truncated uint64
	// StoppedAtLimit is true when a limit stopped the scan before the end of
	// the file.
	StoppedAtLimit bool
	// Warnings are issues that did not stop the scan.
	Warnings []string
}

// ScanLog reads every record in a log file held in memory.
func ScanLog(bytes []byte, limits LogLimits) (*LogScan, error) {
	limits = limits.normalized()
	scan := &LogScan{}
	at := 0
	var partial []byte
	var partialStart uint64
	keptBytes := 0
	for at+LogHeaderBytes <= len(bytes) {
		blockLeft := LogBlockBytes - (at % LogBlockBytes)
		if blockLeft < LogHeaderBytes {
			// The block's tail is padding; the next block starts a record.
			at += blockLeft
			continue
		}
		storedCRC := le32(bytes, at)
		length := int(uint16(bytes[at+4]) | uint16(bytes[at+5])<<8)
		kind := bytes[at+6]
		if kind == logTypeZero && length == 0 {
			// Preallocated tail: nothing follows in this block.
			at += blockLeft
			continue
		}
		if kind < logTypeFull || kind > logTypeLast {
			scan.Truncated++
			scan.Warnings = append(scan.Warnings, fmt.Sprintf("log record at byte %d has type %d", at, kind))
			at += blockLeft
			continue
		}
		end := at + LogHeaderBytes + length
		if end > len(bytes) || LogHeaderBytes+length > blockLeft {
			scan.Truncated++
			scan.Warnings = append(scan.Warnings, fmt.Sprintf(
				"log record at byte %d declares %d bytes, past its block or the file", at, length))
			break
		}
		payload := bytes[at+LogHeaderBytes : end]
		crc := foundation.CRC32CSeeded(0xFFFFFFFF, []byte{kind})
		crc = foundation.CRC32CSeeded(crc, payload)
		crcOK := maskCRC(^crc) == storedCRC
		switch kind {
		case logTypeFull:
			if partial != nil {
				scan.Incomplete++
				scan.Warnings = append(scan.Warnings, fmt.Sprintf(
					"a first fragment before byte %d never ended", at))
				partial = nil
			}
			if err := pushRecord(scan, append([]byte(nil), payload...), uint64(at), crcOK, &keptBytes, limits); err != nil {
				return nil, err
			}
		case logTypeFirst:
			if partial != nil {
				scan.Incomplete++
				scan.Warnings = append(scan.Warnings, fmt.Sprintf(
					"a first fragment before byte %d never ended", at))
			}
			partial = append([]byte(nil), payload...)
			partialStart = uint64(at)
		case logTypeMiddle:
			if partial == nil {
				scan.Incomplete++
				scan.Warnings = append(scan.Warnings, fmt.Sprintf(
					"a middle fragment at byte %d has no first fragment", at))
			} else {
				partial = append(partial, payload...)
			}
		case logTypeLast:
			if partial == nil {
				scan.Incomplete++
				scan.Warnings = append(scan.Warnings, fmt.Sprintf(
					"a last fragment at byte %d has no first fragment", at))
			} else {
				partial = append(partial, payload...)
				if err := pushRecord(scan, partial, partialStart, crcOK, &keptBytes, limits); err != nil {
					return nil, err
				}
				partial = nil
			}
		}
		at = end
		if scan.StoppedAtLimit {
			break
		}
	}
	if partial != nil {
		scan.Incomplete++
		scan.Warnings = append(scan.Warnings, fmt.Sprintf(
			"the record at byte %d holds %d bytes but never ends", partialStart, len(partial)))
	}
	if !scan.StoppedAtLimit && at < len(bytes) && len(bytes)-at >= LogHeaderBytes {
		scan.Warnings = append(scan.Warnings, fmt.Sprintf("%d trailing byte(s) were not read", len(bytes)-at))
	}
	return scan, nil
}

func pushRecord(scan *LogScan, payload []byte, offset uint64, crcOK bool, keptBytes *int, limits LogLimits) error {
	if len(payload) > limits.MaxPayload {
		return limitError("a log record is %d bytes, above the %d-byte bound", len(payload), limits.MaxPayload)
	}
	if !crcOK {
		scan.ChecksumFailures++
	}
	if len(scan.Records) >= limits.MaxRecords || *keptBytes >= limits.MaxBytes {
		scan.StoppedAtLimit = true
		return nil
	}
	*keptBytes += len(payload)
	scan.Records = append(scan.Records, LogRecord{Payload: payload, Offset: offset, CRCOK: crcOK})
	return nil
}

// EncodeFullRecord builds the bytes of one full record, as the writer would.
// It is used by fixtures and tests; this reader never writes a log.
func EncodeFullRecord(payload []byte) []byte {
	crc := foundation.CRC32CSeeded(0xFFFFFFFF, []byte{logTypeFull})
	crc = foundation.CRC32CSeeded(crc, payload)
	out := make([]byte, 0, LogHeaderBytes+len(payload))
	out = append(out, 0, 0, 0, 0)
	out = append(out, byte(len(payload)), byte(len(payload)>>8), logTypeFull)
	out = append(out, payload...)
	putLE32(out, maskCRC(^crc))
	return out
}

func putLE32(out []byte, value uint32) {
	out[0] = byte(value)
	out[1] = byte(value >> 8)
	out[2] = byte(value >> 16)
	out[3] = byte(value >> 24)
}

// readWholeSource reads an entire source after checking it against a bound.
func readWholeSource(src source.ByteSource, max uint64) ([]byte, error) {
	length := src.Len()
	if length > max {
		return nil, limitError("a %d-byte file is above the %d-byte in-memory bound", length, max)
	}
	return source.ReadVecAt(src, 0, length)
}
