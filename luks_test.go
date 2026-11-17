package forensic_test

import (
	"context"
	"errors"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func TestOpenLUKSSourceRejectsNil(t *testing.T) {
	_, err := forensic.OpenLUKSSource(context.Background(), nil, "passphrase")
	if !errors.Is(err, forensic.ErrInvalidArgument) {
		t.Fatalf("nil source = %v, want ErrInvalidArgument", err)
	}
}

func TestOpenLUKSSourceRejectsPlainVolume(t *testing.T) {
	plain := source.NewMemorySource(1, make([]byte, 1<<20))
	_, err := forensic.OpenLUKSSource(context.Background(), plain, "passphrase")
	if !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("plain volume = %v, want ErrUnsupported", err)
	}
}
