// Package certstore reads Microsoft serialized certificate stores
// ("certificates.sst", "RootCAs.sst").
//
// Several Windows components, among them the Connected Devices Platform and
// Sentinel, keep their certificate lists in a small flat file.  Some of those
// files carry an ".sst" extension, which is also LevelDB's table extension,
// but the bytes are not a LevelDB table: there is no table magic and no block
// structure.  The file is an eight-byte header followed by a stream of
// length-prefixed records:
//
//	header   u32 little-endian, observed 0
//	         "CERT"
//	record   u32 type
//	         u32 version, observed 1
//	         u32 payload length
//	         payload[length]
//
// A record with type 0, version 0 and length 0 is a terminator.  The samples
// seen here end with one; the file may carry bytes after it, and those bytes
// are counted rather than interpreted.  The record types known to this reader
// are:
//
//	0x0b   friendly name, UTF-16LE, NUL-terminated
//	0x02   two u32 offsets from the payload start, each naming a
//	       UTF-16LE NUL-terminated string (a certificate name and a
//	       key-storage provider name)
//	0x20   one DER value, the stored certificate
//	0x03   a stored 20-byte SHA-1 thumbprint of the next certificate record
//	0x62   a stored 32-byte SHA-256 thumbprint of the next certificate record
//
// A stored thumbprint is compared with the digest this reader computes over
// the next 0x20 payload.  The comparison result is nil when no thumbprint of
// that kind was seen since the previous certificate record.
//
// Any other record type, and a known type whose payload cannot be decoded, is
// kept in the opaque list with its numeric type, offset and length.  That list
// is bounded, as are the certificate and name lists: a file that runs past a
// bound stops the walk early and sets [Store.Capped] rather than growing
// without limit.
//
// # What the file proves
//
// The file is producer-written.  A certificate's presence proves the store
// recorded those bytes; it does not prove the certificate was trusted, that it
// was used for a connection, or that any private key still exists.  A stored
// thumbprint that matches the computed digest is corroboration that the
// producer wrote a digest for these same bytes, not an independent signature
// over them; the file carries no MAC or signature of its own.  Records of a
// type this reader does not know are counted with their numeric type and never
// labelled as one of the known kinds.
//
// # What this reader does not do
//
// It does not parse the DER into X.509 fields (subject, issuer, validity), does
// not dereference the two offsets of a 0x02 record beyond their own payload,
// and does not guess at a record type the samples did not show.  Certificate
// payloads are exposed as raw bytes and as a source-backed blob through
// [Store.CertificateSource]; no field extraction is invented.  A record length
// that runs past the end of the file is refused with the record's offset, the
// bytes that are present and the bytes the record declares.
//
// This is a Go port of forensic-core's data/containers/certificate_store.rs.
// Every functional branch of the reference reader is ported.
package certstore

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Largest input this reader accepts by default.
const MaxBytes uint64 = 256 * 1024 * 1024

// Most certificate records this reader collects by default.
const MaxCertificates = 4096

// Most name strings this reader collects by default.
const MaxNames = 4096

// Most records this reader walks by default.
const MaxRecords = 200_000

// Most opaque records this reader keeps by default.
const MaxOpaque = 4096

// MaxNameUnits is the longest name kept, in UTF-16 code units, by default.
// Longer runs are cut and a warning names where, so a corrupt length cannot
// force a huge allocation.
const MaxNameUnits = 2048

// Bytes of the fixed header: the zero word and "CERT".
const HeaderBytes = 8

// Bytes of a record header: type, version and length.
const RecordHeaderBytes = 12

// Record type of a friendly name.
const TypeName uint32 = 0x0b

// Record type of a pair of offsets naming strings.
const TypeNamePair uint32 = 0x02

// Record type of one DER certificate.
const TypeCertificate uint32 = 0x20

// Record type of a stored SHA-1 thumbprint.
const TypeSHA1 uint32 = 0x03

// Record type of a stored SHA-256 thumbprint.
const TypeSHA256 uint32 = 0x62

// Signature is the eight-byte file header.
var Signature = [HeaderBytes]byte{0, 0, 0, 0, 'C', 'E', 'R', 'T'}

// Limits bound the resources one store may consume.  A zero (or negative)
// field takes the corresponding default, so a caller can raise one bound
// explicitly and leave an auditable decision in the case record.
type Limits struct {
	MaxBytes        uint64
	MaxCertificates int
	MaxNames        int
	MaxRecords      int
	MaxOpaque       int
	MaxNameUnits    int
}

// DefaultLimits returns the documented defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:        MaxBytes,
		MaxCertificates: MaxCertificates,
		MaxNames:        MaxNames,
		MaxRecords:      MaxRecords,
		MaxOpaque:       MaxOpaque,
		MaxNameUnits:    MaxNameUnits,
	}
}

func (l Limits) normalized() Limits {
	defaults := DefaultLimits()
	if l.MaxBytes == 0 {
		l.MaxBytes = defaults.MaxBytes
	}
	if l.MaxCertificates <= 0 {
		l.MaxCertificates = defaults.MaxCertificates
	}
	if l.MaxNames <= 0 {
		l.MaxNames = defaults.MaxNames
	}
	if l.MaxRecords <= 0 {
		l.MaxRecords = defaults.MaxRecords
	}
	if l.MaxOpaque <= 0 {
		l.MaxOpaque = defaults.MaxOpaque
	}
	if l.MaxNameUnits <= 0 {
		l.MaxNameUnits = defaults.MaxNameUnits
	}
	return l
}

// Certificate is one certificate record whose payload verified as a single DER
// value.
type Certificate struct {
	// Offset is the absolute offset of the DER's first byte in the file.
	Offset uint64
	// Len is the length of the DER payload.
	Len uint64
	// SHA1 is the lower-case hex SHA-1 of the DER payload.
	SHA1 string
	// SHA256 is the lower-case hex SHA-256 of the DER payload.
	SHA256 string
	// StoredSHA1Matches reports whether the most recent stored 0x03 record
	// matched, when one was seen since the previous certificate record.
	StoredSHA1Matches *bool
	// StoredSHA256Matches reports whether the most recent stored 0x62 record
	// matched, when one was seen since the previous certificate record.
	StoredSHA256Matches *bool
}

// OpaqueRecord is a record this reader kept without interpreting it.
type OpaqueRecord struct {
	// Type is the stored numeric type.
	Type uint32
	// Offset is the absolute offset of the record header in the file.
	Offset uint64
	// Len is the stored payload length.
	Len uint64
}

// Store is everything one serialized certificate store yields.
type Store struct {
	// Records is the number of records walked, not counting the terminator.
	Records int
	// Certificates holds certificate records whose payload verified as one DER
	// value.
	Certificates []Certificate
	// Names holds friendly names and the name pair's strings, in stored order.
	Names []string
	// Opaque holds records of unknown type and known-type records that did not
	// decode.
	Opaque []OpaqueRecord
	// Terminated reports whether a type 0, version 0, length 0 terminator was
	// reached.
	Terminated bool
	// TrailingBytes is the byte count after the terminator; zero when there was
	// none.
	TrailingBytes uint64
	// Capped reports whether a list bound, the record bound or the input bound
	// stopped the walk before the file's end.
	Capped bool
	// Warnings holds facts about records that did not decode as their type
	// promises.
	Warnings []string

	src source.ByteSource
}

// CertificateSource exposes the DER payload of certificate index as a
// read-only blob over the store source.  It is available only for a store
// opened with [Open]; a store produced by [Read] has no source and returns
// source.ErrUnsupported.
func (s *Store) CertificateSource(index int, id source.ID) (source.ByteSource, error) {
	if index < 0 || index >= len(s.Certificates) {
		return nil, &source.Error{
			Kind:   source.ErrInvalidArgument,
			Reason: fmt.Sprintf("certificate index %d is outside the %d stored certificates", index, len(s.Certificates)),
		}
	}
	if s.src == nil {
		return nil, &source.Error{
			Kind:   source.ErrUnsupported,
			Reason: "the store was decoded from memory, so no source-backed blob is available",
		}
	}
	certificate := s.Certificates[index]
	return source.NewSubSource(id, s.src, certificate.Offset, certificate.Len)
}

// Detect reports whether head begins with the serialized-certificate-store
// signature: four zero bytes followed by ASCII "CERT".
func Detect(head []byte) bool {
	if len(head) < HeaderBytes {
		return false
	}
	for index := 0; index < 4; index++ {
		if head[index] != 0 {
			return false
		}
	}
	return head[4] == 'C' && head[5] == 'E' && head[6] == 'R' && head[7] == 'T'
}

// Read decodes one serialized certificate store already in memory.  The
// decision is a pure function of the bytes.  The walk stops at a terminator, at
// the end of the file, or at a bound, and never allocates from a declared
// length alone.
func Read(data []byte, limits Limits) (*Store, error) {
	limits = limits.normalized()
	if uint64(len(data)) > limits.MaxBytes {
		return nil, unsupported(fmt.Sprintf(
			"the file is %d bytes, above the %d-byte bound for a serialized certificate store",
			len(data), limits.MaxBytes))
	}
	if len(data) < HeaderBytes {
		return nil, unexpectedEOF(0, fmt.Sprintf(
			"the file is %d bytes; a Microsoft serialized certificate store starts with an eight-byte header of four zero bytes and ASCII CERT",
			len(data)))
	}
	magic := data[:HeaderBytes]
	if leU32At(magic, 0) != 0 || string(magic[4:]) != "CERT" {
		return nil, unsupported(fmt.Sprintf(
			"the file starts with % x; a Microsoft serialized certificate store starts with four zero bytes and ASCII CERT",
			magic))
	}

	store := &Store{}
	var pendingSHA1 *[20]byte
	var pendingSHA256 *[32]byte
	at := uint64(HeaderBytes)
	length := uint64(len(data))
	for at < length {
		if store.Records >= limits.MaxRecords {
			store.Capped = true
			break
		}
		remaining := length - at
		recordType, version, payloadLength, ok := recordHeader(data, at)
		if !ok {
			return nil, unexpectedEOF(at, fmt.Sprintf(
				"the record at byte %d declares a %d-byte payload but only %d bytes are present",
				at, RecordHeaderBytes, remaining))
		}
		if recordType == 0 && version == 0 && payloadLength == 0 {
			store.Terminated = true
			store.TrailingBytes = length - (at + RecordHeaderBytes)
			break
		}
		payloadStart := at + RecordHeaderBytes
		payloadLength64 := uint64(payloadLength)
		if payloadLength64 > length-payloadStart {
			return nil, unexpectedEOF(at, fmt.Sprintf(
				"the record at byte %d declares a %d-byte payload but only %d bytes are present",
				at, payloadLength64, length-payloadStart))
		}
		payloadEnd := payloadStart + payloadLength64
		payload := data[payloadStart:payloadEnd]
		store.Records++

		switch recordType {
		case TypeName:
			text, ok, cut := utf16Name(payload, limits.MaxNameUnits)
			if cut {
				store.Warnings = append(store.Warnings, fmt.Sprintf(
					"the name at byte %d is longer than %d UTF-16 code units and is cut there",
					payloadStart, limits.MaxNameUnits))
			}
			switch {
			case ok && text != "":
				if !store.keepName(text, limits.MaxNames) {
					return store, nil
				}
			case ok:
				// An empty decoded name is not recorded and is not opaque,
				// matching the reference.
			default:
				if !store.keepOpaque(OpaqueRecord{Type: recordType, Offset: at, Len: payloadLength64}, limits.MaxOpaque) {
					return store, nil
				}
			}

		case TypeNamePair:
			offsetA, okA := leU32(payload, 0)
			offsetB, okB := leU32(payload, 4)
			if !okA || !okB {
				store.Warnings = append(store.Warnings, fmt.Sprintf(
					"the record at byte %d is type 0x02 but its %d payload bytes are shorter than the two 32-bit offsets",
					at, payloadLength64))
				if !store.keepOpaque(OpaqueRecord{Type: recordType, Offset: at, Len: payloadLength64}, limits.MaxOpaque) {
					return store, nil
				}
				at = payloadEnd
				continue
			}
			stopped := false
			for _, offset := range []uint64{uint64(offsetA), uint64(offsetB)} {
				if offset >= uint64(len(payload)) {
					continue
				}
				text, ok, cut := utf16Name(payload[offset:], limits.MaxNameUnits)
				if cut {
					store.Warnings = append(store.Warnings, fmt.Sprintf(
						"the name at byte %d is longer than %d UTF-16 code units and is cut there",
						payloadStart+offset, limits.MaxNameUnits))
				}
				if ok && text != "" {
					if !store.keepName(text, limits.MaxNames) {
						stopped = true
						break
					}
				}
			}
			if stopped {
				return store, nil
			}

		case TypeCertificate:
			if derLengthMatches(payload) {
				if len(store.Certificates) >= limits.MaxCertificates {
					store.Capped = true
					return store, nil
				}
				digestSHA1 := sha1.Sum(payload)
				digestSHA256 := sha256.Sum256(payload)
				certificate := Certificate{
					Offset: payloadStart,
					Len:    payloadLength64,
					SHA1:   hex.EncodeToString(digestSHA1[:]),
					SHA256: hex.EncodeToString(digestSHA256[:]),
				}
				if pendingSHA1 != nil {
					matches := *pendingSHA1 == digestSHA1
					certificate.StoredSHA1Matches = &matches
				}
				if pendingSHA256 != nil {
					matches := *pendingSHA256 == digestSHA256
					certificate.StoredSHA256Matches = &matches
				}
				store.Certificates = append(store.Certificates, certificate)
			} else {
				store.Warnings = append(store.Warnings, fmt.Sprintf(
					"the record at byte %d is type 0x20 but its %d payload bytes are not one DER value",
					at, payloadLength64))
				if !store.keepOpaque(OpaqueRecord{Type: recordType, Offset: at, Len: payloadLength64}, limits.MaxOpaque) {
					return store, nil
				}
			}
			pendingSHA1 = nil
			pendingSHA256 = nil

		case TypeSHA1:
			if len(payload) == 20 {
				digest := [20]byte{}
				copy(digest[:], payload)
				pendingSHA1 = &digest
			} else {
				store.Warnings = append(store.Warnings, fmt.Sprintf(
					"the record at byte %d is type 0x03 but stores %d bytes; a SHA-1 thumbprint is 20",
					at, payloadLength64))
			}

		case TypeSHA256:
			if len(payload) == 32 {
				digest := [32]byte{}
				copy(digest[:], payload)
				pendingSHA256 = &digest
			} else {
				store.Warnings = append(store.Warnings, fmt.Sprintf(
					"the record at byte %d is type 0x62 but stores %d bytes; a SHA-256 thumbprint is 32",
					at, payloadLength64))
			}

		default:
			if !store.keepOpaque(OpaqueRecord{Type: recordType, Offset: at, Len: payloadLength64}, limits.MaxOpaque) {
				return store, nil
			}
		}
		at = payloadEnd
	}
	return store, nil
}

// Open reads a serialized certificate store from a source and keeps the source
// so [Store.CertificateSource] can expose certificate payloads.
func Open(src source.ByteSource, limits Limits) (*Store, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	limits = limits.normalized()
	length := src.Len()
	if length > limits.MaxBytes {
		return nil, unsupported(fmt.Sprintf(
			"the file is %d bytes, above the %d-byte bound for a serialized certificate store",
			length, limits.MaxBytes))
	}
	data, err := source.ReadVecAt(src, 0, length)
	if err != nil {
		return nil, err
	}
	store, err := Read(data, limits)
	if err != nil {
		return nil, err
	}
	store.src = src
	return store, nil
}

func (s *Store) keepName(name string, limit int) bool {
	if len(s.Names) >= limit {
		s.Capped = true
		return false
	}
	s.Names = append(s.Names, name)
	return true
}

func (s *Store) keepOpaque(record OpaqueRecord, limit int) bool {
	if len(s.Opaque) >= limit {
		s.Capped = true
		return false
	}
	s.Opaque = append(s.Opaque, record)
	return true
}

func unsupported(reason string) *source.Error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func unexpectedEOF(offset uint64, reason string) *source.Error {
	return &source.Error{Kind: source.ErrUnexpectedEOF, Offset: offset, Reason: reason}
}

// recordHeader reads one 12-byte record header at offset.
func recordHeader(data []byte, offset uint64) (recordType, version, length uint32, ok bool) {
	if offset > uint64(len(data)) || RecordHeaderBytes > uint64(len(data))-offset {
		return 0, 0, 0, false
	}
	raw := data[offset : offset+RecordHeaderBytes]
	return leU32At(raw, 0), leU32At(raw, 4), leU32At(raw, 8), true
}

// leU32At reads a little-endian u32 at offset, or zero when it does not fit.
// Callers that need to distinguish absence check the slice length first, as
// the name-pair branch does.
func leU32At(data []byte, offset int) uint32 {
	return uint32(data[offset]) | uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
}

func leU32(data []byte, offset int) (uint32, bool) {
	if offset < 0 || offset+4 > len(data) {
		return 0, false
	}
	return leU32At(data, offset), true
}

// utf16Name decodes the UTF-16LE run before the first NUL unit.  cut reports
// that the run reached maxUnits without a terminator and was cut; ok is false
// when the units are not valid text or the run was empty.
func utf16Name(payload []byte, maxUnits int) (text string, ok bool, cut bool) {
	values := make([]uint16, 0, min(len(payload)/2, 64))
	for index := 0; index+1 < len(payload); index += 2 {
		unit := uint16(payload[index]) | uint16(payload[index+1])<<8
		if unit == 0 {
			break
		}
		if len(values) >= maxUnits {
			cut = true
			break
		}
		values = append(values, unit)
	}
	if len(values) == 0 {
		return "", false, cut
	}
	decoded, valid := decodeUTF16Strict(values)
	if !valid {
		return "", false, cut
	}
	return decoded, true, cut
}

func decodeUTF16Strict(units []uint16) (string, bool) {
	var out strings.Builder
	out.Grow(len(units))
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if index+1 >= len(units) {
				return "", false
			}
			low := units[index+1]
			if low < 0xDC00 || low > 0xDFFF {
				return "", false
			}
			value := 0x10000 + (rune(unit)-0xD800)<<10 + (rune(low) - 0xDC00)
			out.WriteRune(value)
			index++
		case unit >= 0xDC00 && unit <= 0xDFFF:
			return "", false
		default:
			out.WriteRune(rune(unit))
		}
	}
	return out.String(), true
}

// derLengthMatches reports whether payload is exactly one DER value: a 0x30
// SEQUENCE whose declared length covers the payload and nothing more.
func derLengthMatches(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}
	if payload[0] != 0x30 {
		return false
	}
	second := payload[1]
	if second < 0x80 {
		return uint64(second)+2 == uint64(len(payload))
	}
	count := int(second & 0x7f)
	if count < 1 || count > 4 {
		return false
	}
	if 2+count > len(payload) {
		return false
	}
	var declared uint64
	for _, value := range payload[2 : 2+count] {
		if declared > (^uint64(0)-uint64(value))/256 {
			return false
		}
		declared = declared*256 + uint64(value)
	}
	total := declared + 2 + uint64(count)
	return total == uint64(len(payload))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
