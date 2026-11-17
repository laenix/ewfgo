package bitlocker

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/encryption/errs"
)

func buildBinaryBek(keyBytes []byte) []byte {
	nested := make([]byte, 8+4+len(keyBytes))
	putLE16(nested, 0, uint16(len(nested)))
	putLE16(nested, 2, 0x0000) // property
	putLE16(nested, 4, 0x0001) // key
	putLE16(nested, 6, 1)
	copy(nested[12:], keyBytes)

	guidEntry := make([]byte, 8+16)
	putLE16(guidEntry, 0, uint16(len(guidEntry)))
	putLE16(guidEntry, 2, 0x0019) // volume GUID
	putLE16(guidEntry, 4, 0x0017) // GUID value
	putLE16(guidEntry, 6, 1)
	copy(guidEntry[8:], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9})

	entryPayload := make([]byte, 24)
	first := make([]byte, 8+len(entryPayload)+len(nested)+len(guidEntry))
	putLE16(first, 0, uint16(len(first)))
	putLE16(first, 2, EntryStartupKey)
	putLE16(first, 4, ValueExternalKey)
	putLE16(first, 6, 1)
	copy(first[8:], entryPayload)
	copy(first[8+24:], nested)
	copy(first[8+24+len(nested):], guidEntry)

	file := make([]byte, 48+len(first))
	putLE32(file, 0, uint32(len(file)))
	putLE32(file, 4, 1)
	putLE32(file, 8, 48)
	putLE32(file, 12, 48)
	copy(file[16:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	putLE32(file, 32, uint32(MethodAES256XTS))
	putLE64(file, 40, 0x01d9a12345678900)
	copy(file[48:], first)
	return file
}

func TestReadBinaryStartupKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	info, err := ReadBek(buildBinaryBek(key))
	if err != nil {
		t.Fatalf("ReadBek error = %v", err)
	}
	if info.Format != BekBinaryStartupKey {
		t.Fatalf("format = %v", info.Format)
	}
	if info.Version != "1" {
		t.Fatalf("version = %q", info.Version)
	}
	if info.KeyType != BekExternalKey {
		t.Fatalf("key type = %v", info.KeyType)
	}
	if !info.ExternalKeyPresent || info.ExternalKeyBytes != 32 {
		t.Fatalf("external key = present %v, %d bytes", info.ExternalKeyPresent, info.ExternalKeyBytes)
	}
	if info.RecoveryKeyID != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("recovery key id = %q", info.RecoveryKeyID)
	}
	if info.VolumeID != "aabbccddeeff00010203040506070809" {
		t.Fatalf("volume id = %q", info.VolumeID)
	}
	if !info.HasCreationFiletime || info.CreationFiletime != 0x01d9a12345678900 {
		t.Fatalf("creation filetime = %#x", info.CreationFiletime)
	}
}

func TestReadBinaryBekTruncated(t *testing.T) {
	file := buildBinaryBek(make([]byte, 32))
	_, err := ReadBek(file[:50])
	if !errors.Is(err, errs.ErrTruncated) {
		t.Fatalf("ReadBek error = %v, want ErrTruncated", err)
	}
}

func TestReadBinaryBekWrongVersion(t *testing.T) {
	file := buildBinaryBek(make([]byte, 32))
	putLE32(file, 4, 2)
	_, err := ReadBek(file)
	if !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("ReadBek error = %v, want ErrMalformed", err)
	}
}

const xmlRecovery = `<?xml version="1.0" encoding="UTF-8"?>
<BitLockerRecoveryKey xmlns="http://schemas.microsoft.com/win/2008/01/BitLockerRecoveryKey">
  <Version>1</Version>
  <KeyType>RecoveryPassword</KeyType>
  <RecoveryKeyID>11111111-2222-3333-4444-555555555555</RecoveryKeyID>
  <VolumeID>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</VolumeID>
  <RecoveryPassword>110000-110000-110000-110000-110000-110000-110000-110000</RecoveryPassword>
  <CreationTime>2026-11-17T00:00:00Z</CreationTime>
  <Description>recovery key for test volume</Description>
</BitLockerRecoveryKey>`

func TestReadXMLRecoveryPassword(t *testing.T) {
	info, err := ReadBek([]byte(xmlRecovery))
	if err != nil {
		t.Fatalf("ReadBek error = %v", err)
	}
	if info.Format != BekXML || info.KeyType != BekRecoveryPassword {
		t.Fatalf("format/type = %v/%v", info.Format, info.KeyType)
	}
	if !info.PasswordPresent || info.PasswordDigits != 48 || !info.PasswordValid {
		t.Fatalf("password = present %v digits %d valid %v (%s)",
			info.PasswordPresent, info.PasswordDigits, info.PasswordValid, info.PasswordProblem)
	}
	if info.ExternalKeyPresent {
		t.Fatal("external key present on a recovery-password document")
	}
	if info.Description != "recovery key for test volume" {
		t.Fatalf("description = %q", info.Description)
	}
	if info.RecoveryKeyID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("recovery key id = %q", info.RecoveryKeyID)
	}
}

func TestReadXMLBadRecoveryPasswordShape(t *testing.T) {
	// 123456 is not divisible by eleven, so the format's own group check must
	// reject it while the document still parses.
	document := strings.Replace(xmlRecovery,
		"110000-110000-110000-110000-110000-110000-110000-110000",
		"123456-110000-110000-110000-110000-110000-110000-110000", 1)
	info, err := ReadBek([]byte(document))
	if err != nil {
		t.Fatalf("ReadBek error = %v", err)
	}
	if info.PasswordValid {
		t.Fatal("password valid = true for a group not divisible by eleven")
	}
	if info.PasswordProblem == "" {
		t.Fatal("PasswordProblem is empty")
	}
	if !info.PasswordPresent || info.PasswordDigits != 48 {
		t.Fatalf("password presence = %v digits %d", info.PasswordPresent, info.PasswordDigits)
	}
}

func TestReadXMLUnsupportedRoot(t *testing.T) {
	_, err := ReadBek([]byte(`<NotBitLocker><KeyType>RecoveryPassword</KeyType></NotBitLocker>`))
	if !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("ReadBek error = %v, want ErrMalformed", err)
	}
}

func utf16LE(text string) []byte {
	units := make([]uint16, 0, len(text))
	for _, r := range text {
		units = append(units, uint16(r))
	}
	out := []byte{0xff, 0xfe}
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func TestReadXMLUTF16(t *testing.T) {
	document := `<BitLockerRecoveryKey><Version>1</Version><KeyType>ExternalKey</KeyType><ExternalKey>` +
		base64.StdEncoding.EncodeToString(make([]byte, 32)) +
		`</ExternalKey></BitLockerRecoveryKey>`
	info, err := ReadBek(utf16LE(document))
	if err != nil {
		t.Fatalf("ReadBek error = %v", err)
	}
	if info.KeyType != BekExternalKey || !info.ExternalKeyPresent || info.ExternalKeyBytes != 32 {
		t.Fatalf("external key = type %v present %v %d bytes",
			info.KeyType, info.ExternalKeyPresent, info.ExternalKeyBytes)
	}
}
