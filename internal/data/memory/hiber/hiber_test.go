package hiber

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func putU32(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }

func pageZero(signature [4]byte) []byte {
	bytes := make([]byte, 0x1000)
	copy(bytes[0:4], signature[:])
	putU32(bytes, 4, 7)
	putU32(bytes, 8, 0x1234_5678)
	putU32(bytes, 12, 168)
	return bytes
}

func memory(bytes []byte) *source.MemorySource { return source.NewMemorySource(1, bytes) }

func TestSignatureClassification(t *testing.T) {
	cases := []struct {
		in    [4]byte
		kind  Signature
		label string
	}{
		{Magic, SignatureLegacy, "hibr (XP/2003 legacy)"},
		{MagicVista, SignatureVista, "HIBR (Vista or later)"},
		{MagicRestore, SignatureRestore, "RSTR (restoration/resume state)"},
		{MagicWake, SignatureWakeLower, "wake (invalid hibernation file)"},
		{MagicWakeUpper, SignatureWakeUpper, "wake (invalid hibernation file)"},
	}
	for _, tc := range cases {
		kind, ok := SignatureFromBytes(tc.in)
		if !ok || kind != tc.kind {
			t.Fatalf("SignatureFromBytes(%q) = %v/%v", tc.in, kind, ok)
		}
		if kind.Label() != tc.label {
			t.Fatalf("Label(%q) = %q", tc.in, kind.Label())
		}
	}
	if _, ok := SignatureFromBytes([4]byte{'a', 'b', 'c', 'd'}); ok {
		t.Fatal("SignatureFromBytes accepted an unknown signature")
	}
	if !SignatureRestore.IsInvalid() || !SignatureWakeLower.IsInvalid() || !SignatureWakeUpper.IsInvalid() {
		t.Fatal("invalid signatures not marked invalid")
	}
	if SignatureLegacy.IsInvalid() || SignatureVista.IsInvalid() {
		t.Fatal("valid signatures marked invalid")
	}
}

func TestReadsLegacyCommonFields(t *testing.T) {
	report, err := Read(memory(pageZero(Magic)))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.Signature != Magic || report.SignatureKind != SignatureLegacy {
		t.Fatalf("signature = %+v", report)
	}
	if report.Version == nil || *report.Version != 7 {
		t.Fatalf("version = %v", report.Version)
	}
	if report.ImageType != nil {
		t.Fatalf("image type = %v, want nil", report.ImageType)
	}
	if report.Checksum == nil || *report.Checksum != 0x1234_5678 {
		t.Fatalf("checksum = %v", report.Checksum)
	}
	if report.LengthSelf == nil || *report.LengthSelf != 168 {
		t.Fatalf("length self = %v", report.LengthSelf)
	}
	if report.SourceLen != 0x1000 {
		t.Fatalf("source len = %d", report.SourceLen)
	}
	if !contains(report.RefusedFields, "PageSize") || !contains(report.AbsentFields, "ProcessorCount") {
		t.Fatalf("fields = refused %v absent %v", report.RefusedFields, report.AbsentFields)
	}
	if report.LayoutNote == "" {
		t.Fatal("layout note is empty")
	}
}

func TestReadsVistaImageTypeInsteadOfVersion(t *testing.T) {
	report, err := Read(memory(pageZero(MagicVista)))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.SignatureKind != SignatureVista {
		t.Fatalf("signature kind = %v", report.SignatureKind)
	}
	if report.Version != nil {
		t.Fatalf("version = %v, want nil", report.Version)
	}
	if report.ImageType == nil || *report.ImageType != 7 {
		t.Fatalf("image type = %v", report.ImageType)
	}
	if report.Checksum == nil || *report.Checksum != 0x1234_5678 {
		t.Fatalf("checksum = %v", report.Checksum)
	}
	if !contains(report.RefusedFields, "PageSelf") {
		t.Fatalf("refused fields = %v", report.RefusedFields)
	}
}

func TestRestoreAndWakeSignaturesReportOnlyTheSignature(t *testing.T) {
	for _, signature := range [][4]byte{MagicRestore, MagicWake, MagicWakeUpper} {
		report, err := Read(memory(pageZero(signature)))
		if err != nil {
			t.Fatalf("Read(%q) error = %v", signature, err)
		}
		if !report.SignatureKind.IsInvalid() {
			t.Fatalf("%q not invalid", signature)
		}
		if report.Version != nil || report.ImageType != nil || report.Checksum != nil || report.LengthSelf != nil {
			t.Fatalf("%q decoded fields: %+v", signature, report)
		}
		if !contains(report.RefusedFields, "CheckSum") {
			t.Fatalf("%q refused fields = %v", signature, report.RefusedFields)
		}
	}
}

func TestUnknownSignatureNamed(t *testing.T) {
	_, err := Read(memory(pageZero([4]byte{'a', 'b', 'c', 'd'})))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("error = %v, want ErrBadSignature", err)
	}
	var hiberErr *Error
	if !errors.As(err, &hiberErr) || hiberErr.Found != [4]byte{'a', 'b', 'c', 'd'} {
		t.Fatalf("error detail = %+v", hiberErr)
	}
}

func TestShortHeaderNamedBeforeAnyFieldIsRead(t *testing.T) {
	_, err := Read(memory([]byte("hibr")))
	if !errors.Is(err, ErrHeaderTooShort) {
		t.Fatalf("error = %v, want ErrHeaderTooShort", err)
	}
	var hiberErr *Error
	if !errors.As(err, &hiberErr) || hiberErr.Need != CommonFieldsBytes || hiberErr.Available != 4 {
		t.Fatalf("error detail = %+v", hiberErr)
	}

	_, err = Read(memory([]byte("hi")))
	if !errors.Is(err, ErrSignatureTooShort) {
		t.Fatalf("error = %v, want ErrSignatureTooShort", err)
	}
	if !errors.As(err, &hiberErr) || hiberErr.Available != 2 {
		t.Fatalf("error detail = %+v", hiberErr)
	}
}

func TestLooksLikeAcceptsLowerCaseRoutingMagicOnly(t *testing.T) {
	if !LooksLike([]byte("hibr....")) {
		t.Fatal("LooksLike rejected hibr")
	}
	if LooksLike([]byte("HIBR....")) {
		t.Fatal("LooksLike accepted HIBR")
	}
	if LooksLike([]byte("hib")) {
		t.Fatal("LooksLike accepted a short prefix")
	}
}

func TestDeeperFieldsAndDecompressionAreExplicitlyUnsupported(t *testing.T) {
	report, err := Read(memory(pageZero(MagicVista)))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	for _, name := range report.RefusedFields {
		if _, err := report.Field(name); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Field(%q) error = %v, want ErrUnsupported", name, err)
		}
	}
	if _, err := report.Field("MachineType"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Field(MachineType) error = %v, want ErrUnsupported", err)
	}
	if err := report.Decompress(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Decompress error = %v, want ErrUnsupported", err)
	}
	// The source sentinel must match too, so callers can use one taxonomy.
	if !errors.Is(report.Decompress(), source.ErrUnsupported) {
		t.Fatal("Decompress error does not match source.ErrUnsupported")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
