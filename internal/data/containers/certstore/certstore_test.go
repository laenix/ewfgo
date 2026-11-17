package certstore

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// DER is a valid-length DER SEQUENCE; it is not a real X.509 certificate, and
// that is enough for the reader's length check.
var der = []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}

func header() []byte {
	bytes := make([]byte, 4)
	bytes = append(bytes, 'C', 'E', 'R', 'T')
	return bytes
}

func record(recordType, version uint32, payload []byte) []byte {
	bytes := make([]byte, 0, 12+len(payload))
	bytes = append(bytes, byte(recordType), byte(recordType>>8), byte(recordType>>16), byte(recordType>>24))
	bytes = append(bytes, byte(version), byte(version>>8), byte(version>>16), byte(version>>24))
	length := uint32(len(payload))
	bytes = append(bytes, byte(length), byte(length>>8), byte(length>>16), byte(length>>24))
	return append(bytes, payload...)
}

func terminator() []byte { return record(0, 0, nil) }

func utf16Bytes(text string) []byte {
	bytes := make([]byte, 0, len(text)*2+2)
	for _, value := range text {
		if value < 0x10000 {
			bytes = append(bytes, byte(value), byte(value>>8))
			continue
		}
		value -= 0x10000
		high := uint16(0xD800 + (value >> 10))
		low := uint16(0xDC00 + (value & 0x3FF))
		bytes = append(bytes, byte(high), byte(high>>8), byte(low), byte(low>>8))
	}
	return append(bytes, 0, 0)
}

func sha1Bytes(data []byte) []byte {
	sum := sha1.Sum(data)
	return sum[:]
}

func sha256Bytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha1Hex(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func mustRead(t *testing.T, data []byte, limits Limits) *Store {
	t.Helper()
	store, err := Read(data, limits)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return store
}

func TestDetectRecognisesTheSignature(t *testing.T) {
	if !Detect(header()) {
		t.Fatal("signature not detected")
	}
	if Detect([]byte("CERT")) {
		t.Fatal("short input detected")
	}
	bad := header()
	bad[4] = 'X'
	if Detect(bad) {
		t.Fatal("wrong magic detected")
	}
	if Detect(make([]byte, 8)) {
		t.Fatal("zero bytes detected")
	}
}

func TestNameAndCertificateWithMatchingThumbprintsDecode(t *testing.T) {
	name := utf16Bytes("TrustCor RootCert CA-1")
	if len(name) != 46 {
		t.Fatalf("name length = %d, want 46", len(name))
	}
	var data []byte
	data = append(data, header()...)
	data = append(data, record(TypeName, 1, name)...)
	data = append(data, record(TypeSHA1, 1, sha1Bytes(der))...)
	data = append(data, record(TypeSHA256, 1, sha256Bytes(der))...)
	data = append(data, record(TypeCertificate, 1, der)...)
	data = append(data, terminator()...)

	store := mustRead(t, data, Limits{})
	if store.Records != 4 {
		t.Fatalf("records = %d", store.Records)
	}
	if !store.Terminated || store.TrailingBytes != 0 {
		t.Fatalf("terminated/trailing = %v/%d", store.Terminated, store.TrailingBytes)
	}
	if len(store.Names) != 1 || store.Names[0] != "TrustCor RootCert CA-1" {
		t.Fatalf("names = %v", store.Names)
	}
	if len(store.Certificates) != 1 {
		t.Fatalf("certificates = %d", len(store.Certificates))
	}
	certificate := store.Certificates[0]
	offset := bytes.Index(data, der)
	if certificate.Offset != uint64(offset) {
		t.Fatalf("offset = %d, want %d", certificate.Offset, offset)
	}
	if certificate.Len != uint64(len(der)) {
		t.Fatalf("len = %d", certificate.Len)
	}
	if certificate.SHA1 != sha1Hex(der) || certificate.SHA256 != sha256Hex(der) {
		t.Fatalf("hashes = %s / %s", certificate.SHA1, certificate.SHA256)
	}
	if certificate.StoredSHA1Matches == nil || !*certificate.StoredSHA1Matches {
		t.Fatalf("stored sha1 match = %v", certificate.StoredSHA1Matches)
	}
	if certificate.StoredSHA256Matches == nil || !*certificate.StoredSHA256Matches {
		t.Fatalf("stored sha256 match = %v", certificate.StoredSHA256Matches)
	}
}

func TestMismatchingStoredThumbprintIsReportedAsFalse(t *testing.T) {
	stored := sha1Bytes(der)
	stored[0] ^= 0xff
	var data []byte
	data = append(data, header()...)
	data = append(data, record(TypeSHA1, 1, stored)...)
	data = append(data, record(TypeCertificate, 1, der)...)

	store := mustRead(t, data, Limits{})
	certificate := store.Certificates[0]
	if certificate.StoredSHA1Matches == nil || *certificate.StoredSHA1Matches {
		t.Fatalf("sha1 match = %v", certificate.StoredSHA1Matches)
	}
	if certificate.StoredSHA256Matches != nil {
		t.Fatalf("sha256 match = %v", certificate.StoredSHA256Matches)
	}
}

func TestPayloadThatIsNotOneDERValueIsNotACertificate(t *testing.T) {
	payload := append(append([]byte{}, der...), 0x00)
	var data []byte
	data = append(data, header()...)
	data = append(data, record(TypeCertificate, 1, payload)...)

	store := mustRead(t, data, Limits{})
	if len(store.Certificates) != 0 {
		t.Fatalf("certificates = %d", len(store.Certificates))
	}
	if len(store.Opaque) != 1 {
		t.Fatalf("opaque = %+v", store.Opaque)
	}
	if store.Opaque[0].Type != TypeCertificate || store.Opaque[0].Offset != 8 {
		t.Fatalf("opaque record = %+v", store.Opaque[0])
	}
	if len(store.Warnings) == 0 || !strings.Contains(store.Warnings[0], "byte 8") {
		t.Fatalf("warnings = %v", store.Warnings)
	}
}

func TestRecordLengthPastTheEndIsRefusedWithItsOffset(t *testing.T) {
	data := header()
	data = append(data, 0x20, 0, 0, 0, 1, 0, 0, 0, 100, 0, 0, 0)
	data = append(data, make([]byte, 10)...)

	_, err := Read(data, Limits{})
	if !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("error = %v", err)
	}
	var detail *source.Error
	if !errors.As(err, &detail) {
		t.Fatalf("error type = %T", err)
	}
	if detail.Offset != 8 {
		t.Fatalf("offset = %d", detail.Offset)
	}
	if !strings.Contains(detail.Reason, "byte 8") || !strings.Contains(detail.Reason, "100") {
		t.Fatalf("reason = %q", detail.Reason)
	}
}

func TestWrongMagicIsRefusedByNumber(t *testing.T) {
	data := header()
	data[4] = 'X'
	_, err := Read(data, Limits{})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "CERT") {
		t.Fatalf("message = %v", err)
	}
}

func TestTwoOffsetsOfANamePairNameBothStrings(t *testing.T) {
	left := utf16Bytes("Leaf Certificate")
	right := utf16Bytes("Microsoft Software Key Storage Provider")
	var payload []byte
	payload = append(payload, 8, 0, 0, 0)
	offsetB := uint32(8 + len(left))
	payload = append(payload, byte(offsetB), byte(offsetB>>8), byte(offsetB>>16), byte(offsetB>>24))
	payload = append(payload, left...)
	payload = append(payload, right...)

	data := header()
	data = append(data, record(TypeNamePair, 1, payload)...)

	store := mustRead(t, data, Limits{})
	if len(store.Names) != 2 || store.Names[0] != "Leaf Certificate" || store.Names[1] != "Microsoft Software Key Storage Provider" {
		t.Fatalf("names = %v", store.Names)
	}
}

func TestNamePairOffsetsOutsideThePayloadAreIgnored(t *testing.T) {
	payload := make([]byte, 8)
	payload[0] = 100
	payload[4] = 200
	data := header()
	data = append(data, record(TypeNamePair, 1, payload)...)

	store := mustRead(t, data, Limits{})
	if len(store.Names) != 0 || len(store.Opaque) != 0 || len(store.Warnings) != 0 {
		t.Fatalf("store = %+v", store)
	}
	if store.Records != 1 {
		t.Fatalf("records = %d", store.Records)
	}
}

func TestShortNamePairWarnsAndIsOpaque(t *testing.T) {
	data := header()
	data = append(data, record(TypeNamePair, 1, []byte{1, 2, 3})...)
	store := mustRead(t, data, Limits{})
	if len(store.Opaque) != 1 || store.Opaque[0].Type != TypeNamePair {
		t.Fatalf("opaque = %+v", store.Opaque)
	}
	if len(store.Warnings) != 1 || !strings.Contains(store.Warnings[0], "shorter than the two 32-bit offsets") {
		t.Fatalf("warnings = %v", store.Warnings)
	}
}

func TestTerminatorLeavesBytesAfterItCounted(t *testing.T) {
	data := header()
	data = append(data, terminator()...)
	data = append(data, 0x7f)

	store := mustRead(t, data, Limits{})
	if !store.Terminated {
		t.Fatal("not terminated")
	}
	if store.TrailingBytes != 1 {
		t.Fatalf("trailing = %d", store.TrailingBytes)
	}
	if store.Records != 0 || len(store.Certificates) != 0 {
		t.Fatalf("store = %+v", store)
	}
}

func TestUndecodableNameIsKeptAsOpaque(t *testing.T) {
	// A lone high surrogate is not valid UTF-16.
	payload := []byte{0x00, 0xd8, 0x41, 0x00, 0x00, 0x00}
	data := header()
	data = append(data, record(TypeName, 1, payload)...)

	store := mustRead(t, data, Limits{})
	if len(store.Names) != 0 {
		t.Fatalf("names = %v", store.Names)
	}
	if len(store.Opaque) != 1 || store.Opaque[0].Type != TypeName {
		t.Fatalf("opaque = %+v", store.Opaque)
	}
}

func TestStoredDigestOfWrongLengthWarnsAndIsNotCompared(t *testing.T) {
	data := header()
	data = append(data, record(TypeSHA1, 1, make([]byte, 19))...)
	data = append(data, record(TypeCertificate, 1, der)...)

	store := mustRead(t, data, Limits{})
	if store.Certificates[0].StoredSHA1Matches != nil {
		t.Fatalf("match = %v", store.Certificates[0].StoredSHA1Matches)
	}
	if len(store.Warnings) != 1 || !strings.Contains(store.Warnings[0], "SHA-1 thumbprint is 20") {
		t.Fatalf("warnings = %v", store.Warnings)
	}
}

func TestStoredSHA256OfWrongLengthWarns(t *testing.T) {
	data := header()
	data = append(data, record(TypeSHA256, 1, make([]byte, 31))...)
	data = append(data, record(TypeCertificate, 1, der)...)
	store := mustRead(t, data, Limits{})
	if store.Certificates[0].StoredSHA256Matches != nil {
		t.Fatalf("match = %v", store.Certificates[0].StoredSHA256Matches)
	}
	if len(store.Warnings) != 1 || !strings.Contains(store.Warnings[0], "SHA-256 thumbprint is 32") {
		t.Fatalf("warnings = %v", store.Warnings)
	}
}

func TestBadDigestRecordDoesNotClearAnEarlierPendingDigest(t *testing.T) {
	data := header()
	data = append(data, record(TypeSHA1, 1, sha1Bytes(der))...)
	data = append(data, record(TypeSHA1, 1, make([]byte, 19))...)
	data = append(data, record(TypeCertificate, 1, der)...)
	store := mustRead(t, data, Limits{})
	if store.Certificates[0].StoredSHA1Matches == nil || !*store.Certificates[0].StoredSHA1Matches {
		t.Fatalf("match = %v", store.Certificates[0].StoredSHA1Matches)
	}
}

func TestUnknownTypeIsCountedWithItsNumericType(t *testing.T) {
	data := header()
	data = append(data, record(0x41, 1, []byte("anything"))...)
	store := mustRead(t, data, Limits{})
	if len(store.Opaque) != 1 || store.Opaque[0].Type != 0x41 || store.Opaque[0].Len != 8 {
		t.Fatalf("opaque = %+v", store.Opaque)
	}
	if store.Records != 1 {
		t.Fatalf("records = %d", store.Records)
	}
}

func TestLongFormDERLengthIsChecked(t *testing.T) {
	longDER := []byte{0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}
	data := header()
	data = append(data, record(TypeCertificate, 1, longDER)...)
	store := mustRead(t, data, Limits{})
	if len(store.Certificates) != 1 || store.Certificates[0].Len != uint64(len(longDER)) {
		t.Fatalf("certificates = %+v", store.Certificates)
	}
}

func TestDERLengthMismatchesAreOpaque(t *testing.T) {
	cases := [][]byte{
		{},
		{0x31, 0x00},
		{0x30},
		{0x30, 0x82, 0x00},                   // long-form length bytes truncated
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, // declares a value no file can hold
		{0x30, 0x80, 0x00, 0x00},             // indefinite length
	}
	for index, payload := range cases {
		data := header()
		data = append(data, record(TypeCertificate, 1, payload)...)
		store := mustRead(t, data, Limits{})
		if len(store.Certificates) != 0 || len(store.Opaque) != 1 {
			t.Fatalf("case %d: certificates=%d opaque=%+v", index, len(store.Certificates), store.Opaque)
		}
	}
}

func TestFileShorterThanTheHeaderIsRefused(t *testing.T) {
	_, err := Read([]byte("CERT"), Limits{})
	if !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("error = %v", err)
	}
	var detail *source.Error
	if !errors.As(err, &detail) || !strings.Contains(detail.Reason, "eight-byte header") {
		t.Fatalf("reason = %v", err)
	}
}

func TestHeaderAloneIsAnEmptyStore(t *testing.T) {
	store := mustRead(t, header(), Limits{})
	if store.Records != 0 || store.Terminated || store.TrailingBytes != 0 || store.Capped {
		t.Fatalf("store = %+v", store)
	}
}

func TestPartialRecordHeaderIsRefused(t *testing.T) {
	data := header()
	data = append(data, 1, 2, 3, 4, 5)
	_, err := Read(data, Limits{})
	if !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("error = %v", err)
	}
	var detail *source.Error
	if !errors.As(err, &detail) || detail.Offset != 8 {
		t.Fatalf("detail = %+v", detail)
	}
	if !strings.Contains(detail.Reason, "5") || !strings.Contains(detail.Reason, "12") {
		t.Fatalf("reason = %q", detail.Reason)
	}
}

func TestTypeZeroWithNonzeroVersionIsOpaque(t *testing.T) {
	data := header()
	data = append(data, record(0, 1, nil)...)
	store := mustRead(t, data, Limits{})
	if store.Terminated {
		t.Fatal("wrongly treated as a terminator")
	}
	if len(store.Opaque) != 1 || store.Opaque[0].Type != 0 {
		t.Fatalf("opaque = %+v", store.Opaque)
	}
}

func TestLimitsCapTheListsAndSetCapped(t *testing.T) {
	var data []byte
	data = append(data, header()...)
	data = append(data, record(TypeCertificate, 1, der)...)
	data = append(data, record(TypeCertificate, 1, der)...)
	store := mustRead(t, data, Limits{MaxCertificates: 1})
	if len(store.Certificates) != 1 || !store.Capped {
		t.Fatalf("certificates=%d capped=%v", len(store.Certificates), store.Capped)
	}

	var names []byte
	names = append(names, header()...)
	names = append(names, record(TypeName, 1, utf16Bytes("a"))...)
	names = append(names, record(TypeName, 1, utf16Bytes("b"))...)
	store = mustRead(t, names, Limits{MaxNames: 1})
	if len(store.Names) != 1 || !store.Capped {
		t.Fatalf("names=%v capped=%v", store.Names, store.Capped)
	}

	var opaque []byte
	opaque = append(opaque, header()...)
	opaque = append(opaque, record(0x41, 1, []byte("a"))...)
	opaque = append(opaque, record(0x41, 1, []byte("b"))...)
	store = mustRead(t, opaque, Limits{MaxOpaque: 1})
	if len(store.Opaque) != 1 || !store.Capped {
		t.Fatalf("opaque=%v capped=%v", store.Opaque, store.Capped)
	}
}

func TestRecordLimitStopsTheWalk(t *testing.T) {
	var data []byte
	data = append(data, header()...)
	data = append(data, record(TypeName, 1, utf16Bytes("a"))...)
	data = append(data, record(TypeName, 1, utf16Bytes("b"))...)
	store := mustRead(t, data, Limits{MaxRecords: 1})
	if store.Records != 1 || !store.Capped {
		t.Fatalf("records=%d capped=%v", store.Records, store.Capped)
	}
}

func TestLongNamesAreCutAndWarned(t *testing.T) {
	data := header()
	data = append(data, record(TypeName, 1, utf16Bytes("abcdef"))...)
	store := mustRead(t, data, Limits{MaxNameUnits: 3})
	if len(store.Names) != 1 || store.Names[0] != "abc" {
		t.Fatalf("names = %v", store.Names)
	}
	if len(store.Warnings) != 1 || !strings.Contains(store.Warnings[0], "longer than 3 UTF-16 code units") {
		t.Fatalf("warnings = %v", store.Warnings)
	}
}

func TestMaxBytesIsEnforced(t *testing.T) {
	data := append(header(), record(0x41, 1, []byte("x"))...)
	_, err := Read(data, Limits{MaxBytes: 8})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenReadsASourceAndExposesCertificateBlobs(t *testing.T) {
	var data []byte
	data = append(data, header()...)
	data = append(data, record(TypeCertificate, 1, der)...)

	memory := source.NewMemorySource(7, data)
	store, err := Open(memory, Limits{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(store.Certificates) != 1 {
		t.Fatalf("certificates = %d", len(store.Certificates))
	}
	blob, err := store.CertificateSource(0, 42)
	if err != nil {
		t.Fatalf("CertificateSource: %v", err)
	}
	if blob.SourceID() != 42 || blob.Len() != uint64(len(der)) {
		t.Fatalf("blob id/len = %d/%d", blob.SourceID(), blob.Len())
	}
	read, err := source.ReadVecAt(blob, 0, blob.Len())
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if !bytes.Equal(read, der) {
		t.Fatalf("blob = %x, want %x", read, der)
	}
	extents, err := blob.Extents(0, blob.Len())
	if err != nil || len(extents) != 1 {
		t.Fatalf("extents = %+v, %v", extents, err)
	}
	if extents[0].ParentOffset != store.Certificates[0].Offset {
		t.Fatalf("extent offset = %d, want %d", extents[0].ParentOffset, store.Certificates[0].Offset)
	}

	if _, err := store.CertificateSource(1, 43); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("out-of-range error = %v", err)
	}
}

func TestDecodedStoreHasNoBlobSource(t *testing.T) {
	store := mustRead(t, append(header(), record(TypeCertificate, 1, der)...), Limits{})
	if _, err := store.CertificateSource(0, 1); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenRefusesNilSource(t *testing.T) {
	_, err := Open(nil, Limits{})
	if !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("error = %v", err)
	}
}

func TestReadRefusesHugeDeclaredLengthWithoutAllocating(t *testing.T) {
	data := header()
	data = append(data, 0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff)
	_, err := Read(data, Limits{})
	if !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("error = %v", err)
	}
	var detail *source.Error
	if !errors.As(err, &detail) || !strings.Contains(detail.Reason, "4294967295") {
		t.Fatalf("reason = %v", err)
	}
}
