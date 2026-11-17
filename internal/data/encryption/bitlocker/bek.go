// This file ports the metadata half of BitLocker key files (*.bek).
//
// Windows writes a recovery password as a small XML document rooted at
// BitLockerRecoveryKey, and a startup key as a packed binary document with a
// 48-byte header and one startup-key entry. Both forms carry an identifier,
// a creation time and a description that are ordinary metadata; the password
// or external key is secret.
//
// ReadBek reports the key's presence, length and (for a recovery password)
// the format's own eight-group shape check. It never copies the password or
// the external key into the report, and it neither derives a recovery key nor
// stretches anything: those operations are refused with ErrUnsupported.
package bitlocker

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/encryption/errs"
)

const (
	// BekRoot is the XML root element that identifies a recovery-key document.
	BekRoot = "BitLockerRecoveryKey"
	// MaxBekBytes is the largest key file this reader loads.
	MaxBekBytes = 1024 * 1024
	// MaxBekTextChars is the longest text kept from one XML element.
	MaxBekTextChars = 2048
	// BinaryBekHeaderBytes is the binary startup-key file header size.
	BinaryBekHeaderBytes = 48
	// StartupKeyHeaderBytes is the startup-key header inside the first entry.
	StartupKeyHeaderBytes = 24
	// BinaryBekEntryHeaderBytes is the size of a binary entry header.
	BinaryBekEntryHeaderBytes = 8

	// RecoveryPasswordDigits is the required digit count.
	RecoveryPasswordDigits = 48
	// RecoveryPasswordGroups is the number of six-digit groups.
	RecoveryPasswordGroups = 8
	// RecoveryGroupDigits is the number of digits in one group.
	RecoveryGroupDigits = 6
	// RecoveryGroupMin and RecoveryGroupMax bound one six-digit group.
	RecoveryGroupMin = 100_000
	RecoveryGroupMax = 720_885
)

// Binary entry types that are specific to the startup-key document.
const (
	BekEntryProperty   uint16 = 0x0000
	BekEntryVolumeGUID uint16 = 0x0019
	BekValueKey        uint16 = 0x0001
	BekValueString     uint16 = 0x0002
	BekValueGUID       uint16 = 0x0017
)

// BekFormat is the document form of a key file.
type BekFormat uint8

const (
	// BekXML is the BitLockerRecoveryKey XML document.
	BekXML BekFormat = iota + 1
	// BekBinaryStartupKey is the packed binary startup-key document.
	BekBinaryStartupKey
)

// String returns the format label used in reports.
func (f BekFormat) String() string {
	switch f {
	case BekXML:
		return "xml"
	case BekBinaryStartupKey:
		return "binary-startup-key"
	default:
		return "unknown"
	}
}

// BekKeyType is the kind of material a key file holds.
type BekKeyType uint8

const (
	// BekRecoveryPassword is eight groups of six digits.
	BekRecoveryPassword BekKeyType = iota + 1
	// BekExternalKey is raw key bytes for a startup-key protector.
	BekExternalKey
	// BekOther is a type this reader reports by name without decoding.
	BekOther
)

// String returns the key-type label used in reports.
func (k BekKeyType) String() string {
	switch k {
	case BekRecoveryPassword:
		return "RecoveryPassword"
	case BekExternalKey:
		return "ExternalKey"
	default:
		return "other"
	}
}

// BekInfo is the metadata of one parsed key file. It intentionally has no
// field that can carry the password or external key bytes.
type BekInfo struct {
	Format      BekFormat
	Version     string
	KeyType     BekKeyType
	KeyTypeName string
	// RecoveryKeyID is the XML RecoveryKeyID, or the binary header GUID as
	// sixteen lower-case hex bytes in stored order.
	RecoveryKeyID string
	// VolumeID is the XML VolumeID or the binary volume-GUID entry in stored
	// byte order.
	VolumeID     string
	Description  string
	CreationTime string
	// CreationFiletime is the binary header's Windows FILETIME.
	CreationFiletime    uint64
	HasCreationFiletime bool
	// PasswordPresent reports a RecoveryPassword element; PasswordDigits is
	// its digit count and PasswordValid the eight-group check.
	PasswordPresent bool
	PasswordDigits  int
	PasswordValid   bool
	PasswordProblem string
	// ExternalKeyPresent reports external key material; ExternalKeyBytes is
	// its decoded length. The key itself is not retained.
	ExternalKeyPresent bool
	ExternalKeyBytes   int
}

// IsBek reports whether bytes look like a BitLocker key file in either form.
// It is a cheap content probe, not a full parse.
func IsBek(data []byte) bool {
	head := data
	if len(head) > 16*1024 {
		head = head[:16*1024]
	}
	name := []byte(BekRoot)
	if bytes.Contains(head, name) ||
		bytes.Contains(head, utf16Encoding(name, true)) ||
		bytes.Contains(head, utf16Encoding(name, false)) {
		return true
	}
	return isBinaryStartupKey(data)
}

// ReadBek parses one key file, XML or binary.
//
// A structural failure is an explicit error. A recovery password whose shape
// the format rejects is reported in PasswordProblem rather than returned as an
// error, so the key id and volume id remain usable.
func ReadBek(data []byte) (*BekInfo, error) {
	if len(data) == 0 {
		return nil, errs.Malformed("empty .bek document")
	}
	if uint64(len(data)) > MaxBekBytes {
		return nil, errs.TooLarge(uint64(len(data)), MaxBekBytes)
	}
	if looksLikeBinaryBek(data) {
		return parseBinaryBek(data)
	}
	text, err := decodeBekText(data)
	if err != nil {
		return nil, err
	}
	var document bekDocument
	if err := xml.Unmarshal(text, &document); err != nil {
		return nil, errs.Malformed("the .bek document is not valid XML: " + err.Error())
	}
	if document.XMLName.Local != BekRoot {
		return nil, errs.Malformed("the .bek root element is not " + BekRoot)
	}
	keyTypeText := strings.TrimSpace(document.KeyType)
	if keyTypeText == "" {
		return nil, errs.Malformed("the .bek document has no KeyType")
	}

	info := &BekInfo{
		Format:        BekXML,
		Version:       truncateBekText(strings.TrimSpace(document.Version)),
		RecoveryKeyID: truncateBekText(strings.TrimSpace(document.RecoveryKeyID)),
		VolumeID:      truncateBekText(strings.TrimSpace(document.VolumeID)),
		Description:   truncateBekText(strings.TrimSpace(document.Description)),
		CreationTime:  truncateBekText(strings.TrimSpace(document.CreationTime)),
	}
	switch strings.ToLower(keyTypeText) {
	case "recoverypassword":
		info.KeyType = BekRecoveryPassword
		info.KeyTypeName = "RecoveryPassword"
		if document.RecoveryPassword == nil {
			return nil, errs.Malformed("the .bek document has no RecoveryPassword element")
		}
		info.PasswordPresent = true
		info.PasswordDigits, info.PasswordValid, info.PasswordProblem =
			recoveryPasswordShape(*document.RecoveryPassword)
	case "externalkey":
		info.KeyType = BekExternalKey
		info.KeyTypeName = "ExternalKey"
		if document.ExternalKey == nil {
			return nil, errs.Malformed("the .bek document has no ExternalKey element")
		}
		length, err := decodedBase64Length(*document.ExternalKey, "external key")
		if err != nil {
			return nil, err
		}
		if length == 0 {
			return nil, errs.Malformed("the .bek external key decodes to no bytes")
		}
		info.ExternalKeyPresent = true
		info.ExternalKeyBytes = length
	default:
		info.KeyType = BekOther
		info.KeyTypeName = truncateBekText(keyTypeText)
	}
	return info, nil
}

type bekDocument struct {
	XMLName          xml.Name
	Version          string  `xml:"Version"`
	KeyType          string  `xml:"KeyType"`
	RecoveryKeyID    string  `xml:"RecoveryKeyID"`
	VolumeID         string  `xml:"VolumeID"`
	Description      string  `xml:"Description"`
	CreationTime     string  `xml:"CreationTime"`
	RecoveryPassword *string `xml:"RecoveryPassword"`
	ExternalKey      *string `xml:"ExternalKey"`
}

func decodeBekText(data []byte) ([]byte, error) {
	if len(data) >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		data = data[3:]
	} else if len(data) >= 2 {
		switch {
		case data[0] == 0xff && data[1] == 0xfe:
			return decodeUTF16Text(data[2:], true)
		case data[0] == 0xfe && data[1] == 0xff:
			return decodeUTF16Text(data[2:], false)
		case data[0] == '<' && data[1] == 0:
			return decodeUTF16Text(data, true)
		case data[0] == 0 && data[1] == '<':
			return decodeUTF16Text(data, false)
		}
	}
	if !utf8.Valid(data) {
		return nil, errs.Malformed("the .bek document is not valid UTF-8")
	}
	return data, nil
}

func decodeUTF16Text(data []byte, littleEndian bool) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, errs.Malformed("the .bek document has an odd UTF-16 length")
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		if littleEndian {
			units[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
		} else {
			units[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
		}
	}
	return []byte(string(utf16.Decode(units))), nil
}

func utf16Encoding(text []byte, littleEndian bool) []byte {
	out := make([]byte, 0, len(text)*2)
	for _, b := range text {
		if littleEndian {
			out = append(out, b, 0)
		} else {
			out = append(out, 0, b)
		}
	}
	return out
}

func looksLikeBinaryBek(data []byte) bool {
	if len(data) < BinaryBekHeaderBytes {
		return false
	}
	return le32(data, 8) == BinaryBekHeaderBytes && le32(data, 12) == le32(data, 8)
}

func isBinaryStartupKey(data []byte) bool {
	if len(data) < BinaryBekHeaderBytes+BinaryBekEntryHeaderBytes {
		return false
	}
	if uint64(le32(data, 0)) != uint64(len(data)) || le32(data, 4) != 1 {
		return false
	}
	if le32(data, 8) != BinaryBekHeaderBytes || le32(data, 12) != le32(data, 8) {
		return false
	}
	entryAt := BinaryBekHeaderBytes
	size := le16(data, entryAt)
	return size >= BinaryBekEntryHeaderBytes &&
		le16(data, entryAt+2) == EntryStartupKey &&
		le16(data, entryAt+4) == ValueExternalKey &&
		entryAt+int(size) <= len(data)
}

func parseBinaryBek(data []byte) (*BekInfo, error) {
	length := len(data)
	if length < BinaryBekHeaderBytes {
		return nil, errs.Truncated(BinaryBekHeaderBytes, uint64(length))
	}
	declared := uint64(le32(data, 0))
	if declared > uint64(length) {
		return nil, errs.Truncated(declared, uint64(length))
	}
	if declared != uint64(length) {
		return nil, errs.Malformed("the .bek declared size does not match the file length")
	}
	if le32(data, 4) != 1 {
		return nil, errs.Malformed("the .bek binary version is not 1")
	}
	if le32(data, 8) != BinaryBekHeaderBytes {
		return nil, errs.Malformed("the .bek binary header size is not 48")
	}
	if le32(data, 12) != le32(data, 8) {
		return nil, errs.Malformed("the two .bek binary header sizes disagree")
	}

	entryAt := BinaryBekHeaderBytes
	need := entryAt + BinaryBekEntryHeaderBytes
	if length < need {
		return nil, errs.Truncated(uint64(need), uint64(length))
	}
	entrySize := int(le16(data, entryAt))
	if entrySize < BinaryBekEntryHeaderBytes {
		return nil, errs.Malformed("the first .bek entry is smaller than its header")
	}
	entryEnd := entryAt + entrySize
	if entryEnd > length {
		return nil, errs.Truncated(uint64(entryEnd), uint64(length))
	}
	if le16(data, entryAt+2) != EntryStartupKey || le16(data, entryAt+4) != ValueExternalKey {
		return nil, errs.Malformed("the first .bek entry is not a startup-key/external-key pair")
	}

	at := entryAt + BinaryBekEntryHeaderBytes + StartupKeyHeaderBytes
	if at > entryEnd {
		return nil, errs.Truncated(uint64(at), uint64(entryEnd))
	}
	keyPresent := false
	keyBytes := 0
	volumeID := ""
	for at+BinaryBekEntryHeaderBytes <= entryEnd {
		size := int(le16(data, at))
		if size == 0 {
			break
		}
		if size < BinaryBekEntryHeaderBytes {
			return nil, errs.Malformed("a nested .bek entry is smaller than its header")
		}
		end := at + size
		if end > entryEnd {
			return nil, errs.Truncated(uint64(end), uint64(entryEnd))
		}
		kind := le16(data, at+2)
		value := le16(data, at+4)
		switch kind {
		case BekEntryProperty, BekEntryVolumeGUID:
			switch value {
			case BekValueKey:
				if size < BinaryBekEntryHeaderBytes+4 {
					return nil, errs.Malformed("a .bek key entry is smaller than its method field")
				}
				if !keyPresent {
					keyPresent = true
					keyBytes = size - BinaryBekEntryHeaderBytes - 4
				}
			case BekValueGUID:
				if size < BinaryBekEntryHeaderBytes+16 {
					return nil, errs.Malformed("a .bek GUID entry is smaller than its GUID")
				}
				if kind == BekEntryVolumeGUID && volumeID == "" {
					volumeID = hex(data[at+BinaryBekEntryHeaderBytes : at+BinaryBekEntryHeaderBytes+16])
				}
			case BekValueString:
				// A string carries no key material.
			}
		default:
			return nil, errs.Malformed(fmt.Sprintf("unexpected .bek entry type 0x%04x", kind))
		}
		at = end
	}
	if !keyPresent || keyBytes == 0 {
		return nil, errs.Malformed("the .bek document has no external key")
	}

	info := &BekInfo{
		Format:             BekBinaryStartupKey,
		Version:            strconv.FormatUint(uint64(le32(data, 4)), 10),
		KeyType:            BekExternalKey,
		KeyTypeName:        "ExternalKey",
		VolumeID:           volumeID,
		ExternalKeyPresent: true,
		ExternalKeyBytes:   keyBytes,
	}
	if guid := data[16:32]; !allZero(guid) {
		info.RecoveryKeyID = hex(guid)
	}
	if filetime := le64(data, 40); filetime != 0 {
		info.CreationFiletime = filetime
		info.HasCreationFiletime = true
	}
	return info, nil
}

func recoveryPasswordShape(text string) (digits int, valid bool, problem string) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' {
			return -1
		}
		return r
	}, text)
	digits = len(compact)
	if digits != RecoveryPasswordGroups*RecoveryGroupDigits {
		return digits, false, "not 48 digits in eight groups of six"
	}
	for _, b := range []byte(compact) {
		if b < '0' || b > '9' {
			return digits, false, "not made of digits only"
		}
	}
	for group := 0; group < RecoveryPasswordGroups; group++ {
		value, err := strconv.Atoi(compact[group*RecoveryGroupDigits : (group+1)*RecoveryGroupDigits])
		if err != nil {
			return digits, false, "not made of digits only"
		}
		if value < RecoveryGroupMin {
			return digits, false, "a group of fewer than six digits"
		}
		if value%11 != 0 {
			return digits, false, fmt.Sprintf("group %d is not divisible by eleven", group)
		}
		if value > RecoveryGroupMax {
			return digits, false, fmt.Sprintf("group %d is out of range", group)
		}
	}
	return digits, true, ""
}

func decodedBase64Length(text, what string) (int, error) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, text)
	if compact == "" {
		return 0, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(compact)
	}
	if err != nil {
		return 0, errs.BadBase64(what)
	}
	return len(decoded), nil
}

func truncateBekText(text string) string {
	runes := []rune(text)
	if len(runes) <= MaxBekTextChars {
		return text
	}
	return string(runes[:MaxBekTextChars])
}

func allZero(bytes []byte) bool {
	for _, b := range bytes {
		if b != 0 {
			return false
		}
	}
	return true
}
