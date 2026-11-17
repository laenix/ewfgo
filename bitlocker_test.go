package forensic_test

import (
	"context"
	"errors"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func TestOpenBitLockerSourceRejectsNil(t *testing.T) {
	_, err := forensic.OpenBitLockerSource(context.Background(), nil, forensic.BitLockerCredentials{RecoveryPassword: "000000-000000"})
	if !errors.Is(err, forensic.ErrInvalidArgument) {
		t.Fatalf("nil source = %v, want ErrInvalidArgument", err)
	}
}

func TestOpenBitLockerSourceRejectsPlainVolume(t *testing.T) {
	plain := source.NewMemorySource(1, make([]byte, 1<<20))
	_, err := forensic.OpenBitLockerSource(context.Background(), plain, forensic.BitLockerCredentials{})
	if !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("plain volume = %v, want ErrUnsupported", err)
	}
}
