package forensic_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	forensic "github.com/laenix/ewfgo"
)

func TestOpenRealmRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "default.realm")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := forensic.OpenRealm(context.Background(), path, forensic.Options{}); err == nil {
		t.Fatal("OpenRealm accepted an empty file")
	}
}
