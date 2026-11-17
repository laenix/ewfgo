package encryption

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestIdentifyBitLocker(t *testing.T) {
	head := make([]byte, 512)
	copy(head[3:], BitLockerSignature)
	binary.LittleEndian.PutUint16(head[0x0b:], 512)
	head[0x0d] = 8
	format, err := Identify(source.NewMemorySource(1, head))
	if err != nil {
		t.Fatalf("Identify error = %v", err)
	}
	if format != FormatBitLocker {
		t.Fatalf("format = %v, want BitLocker", format)
	}
}

func TestIdentifyLUKS1(t *testing.T) {
	head := make([]byte, 592)
	copy(head, LUKSMagic)
	binary.BigEndian.PutUint16(head[6:], 1)
	format, err := Identify(source.NewMemorySource(1, head))
	if err != nil {
		t.Fatalf("Identify error = %v", err)
	}
	if format != FormatLUKS1 {
		t.Fatalf("format = %v, want LUKS1", format)
	}
}

func TestIdentifyLUKS2(t *testing.T) {
	head := make([]byte, 8192)
	copy(head, LUKSMagic)
	binary.BigEndian.PutUint16(head[6:], 2)
	binary.BigEndian.PutUint64(head[8:], 8192)
	copy(head[4096:], `{"keyslots":{}}`)
	format, err := Identify(source.NewMemorySource(1, head))
	if err != nil {
		t.Fatalf("Identify error = %v", err)
	}
	if format != FormatLUKS2 {
		t.Fatalf("format = %v, want LUKS2", format)
	}
}

func TestIdentifyUnrecognized(t *testing.T) {
	format, err := Identify(source.NewMemorySource(1, make([]byte, 4096)))
	if err != nil {
		t.Fatalf("Identify error = %v", err)
	}
	if format != FormatNone {
		t.Fatalf("format = %v, want none", format)
	}
}

func TestIdentifyUnknownLUKSVersion(t *testing.T) {
	head := make([]byte, 592)
	copy(head, LUKSMagic)
	binary.BigEndian.PutUint16(head[6:], 3)
	_, err := Identify(source.NewMemorySource(1, head))
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("Identify error = %v, want ErrUnknownVersion", err)
	}
}

func TestIdentifyTruncatedLUKS1(t *testing.T) {
	head := make([]byte, 100)
	copy(head, LUKSMagic)
	binary.BigEndian.PutUint16(head[6:], 1)
	_, err := Identify(source.NewMemorySource(1, head))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("Identify error = %v, want ErrTruncated", err)
	}
}

func TestIdentifyTruncatedBitLocker(t *testing.T) {
	head := make([]byte, 100)
	copy(head[3:], BitLockerSignature)
	_, err := Identify(source.NewMemorySource(1, head))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("Identify error = %v, want ErrTruncated", err)
	}
}

func TestIdentifyAPFSIsExplicitlyUnsupported(t *testing.T) {
	head := make([]byte, 64)
	copy(head[NXMagicOffset:], "NXSB")
	_, err := Identify(source.NewMemorySource(1, head))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Identify error = %v, want ErrUnsupported", err)
	}
}

func TestRefusalUsesUnsupportedSentinel(t *testing.T) {
	for _, operation := range []string{
		OperationUnlock,
		OperationDecrypt,
		OperationRecoveryKeyDerivation,
		OperationHiddenVolume,
	} {
		if err := Refusal(operation); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Refusal(%q) = %v, want ErrUnsupported", operation, err)
		}
	}
}
