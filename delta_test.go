package forensic_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func TestOpenDeltaPatch(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name   string
		data   []byte
		kind   string
		offset int
		prefix bool
	}{
		{"pa30.delta", append([]byte("PA30"), make([]byte, 100)...), "PA30", 0, false},
		{"pa19.delta", append([]byte{1, 2, 3, 4}, append([]byte("PA19"), make([]byte, 50)...)...), "PA19", 4, true},
	}
	for _, tc := range cases {
		path := filepath.Join(dir, tc.name)
		if err := os.WriteFile(path, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		patch, err := forensic.OpenDelta(context.Background(), path, forensic.Options{})
		if err != nil {
			t.Fatalf("%s: OpenDelta: %v", tc.name, err)
		}
		info := patch.Info()
		if info.Kind != tc.kind || info.SignatureOffset != tc.offset || info.HasPrefixCRC != tc.prefix {
			t.Fatalf("%s: info = %+v", tc.name, info)
		}
		if info.Length != uint64(len(tc.data)) {
			t.Fatalf("%s: length = %d", tc.name, info.Length)
		}
		if err := patch.Close(); err != nil {
			t.Fatalf("%s: Close: %v", tc.name, err)
		}
	}
}

func TestOpenDeltaSource(t *testing.T) {
	patch, err := forensic.OpenDeltaSource(context.Background(), source.NewMemorySource(1, append([]byte("PA30"), make([]byte, 16)...)), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenDeltaSource: %v", err)
	}
	if patch.Info().Kind != "PA30" {
		t.Fatalf("kind = %q", patch.Info().Kind)
	}
}

func TestOpenDeltaRejectsPlainFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(path, []byte("not a delta patch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := forensic.OpenDelta(context.Background(), path, forensic.Options{}); !errors.Is(err, forensic.ErrUnsupported) {
		t.Fatalf("OpenDelta(plain) = %v, want ErrUnsupported", err)
	}
}

func TestOpenRejectsDeltaPatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.patch")
	if err := os.WriteFile(path, append([]byte("PA31"), make([]byte, 16)...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := forensic.Open(context.Background(), path, forensic.Options{})
	if !errors.Is(err, forensic.ErrInvalidArgument) {
		t.Fatalf("Open(delta) = %v, want ErrInvalidArgument", err)
	}
	if !strings.Contains(err.Error(), "OpenDelta") {
		t.Fatalf("Open(delta) = %v, want guidance to OpenDelta", err)
	}
}
