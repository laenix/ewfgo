package forensic_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/containers/leveldb"
)

func writeLevelDBStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	comparator := "leveldb.BytewiseComparator"
	logNumber := uint64(3)
	nextFile := uint64(4)
	lastSequence := uint64(41)
	payload := leveldb.EncodeEdit(leveldb.EncodedEdit{
		Comparator:   &comparator,
		LogNumber:    &logNumber,
		NextFile:     &nextFile,
		LastSequence: &lastSequence,
	})
	manifest := leveldb.EncodeFullRecord(payload)
	if err := os.WriteFile(filepath.Join(dir, "CURRENT"), []byte("MANIFEST-000002\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST-000002"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOpenLevelDB(t *testing.T) {
	dir := writeLevelDBStore(t)
	store, err := forensic.OpenLevelDB(dir, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenLevelDB: %v", err)
	}
	defer store.Close()

	info := store.Info()
	if info.CurrentManifest != "MANIFEST-000002" {
		t.Fatalf("CurrentManifest = %q", info.CurrentManifest)
	}
	if !info.ManifestComplete || info.ManifestEdits != 1 {
		t.Fatalf("manifest = %+v", info)
	}
	if info.ManifestFiles != 1 || info.Tables != 0 || info.Logs != 0 {
		t.Fatalf("counts = %+v", info)
	}
	tables, err := store.Tables(context.Background())
	if err != nil {
		t.Fatalf("Tables: %v", err)
	}
	if len(tables) != 0 {
		t.Fatalf("tables = %+v", tables)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestOpenLevelDBRejectsMissingCurrent(t *testing.T) {
	if _, err := forensic.OpenLevelDB(t.TempDir(), forensic.Options{}); err == nil {
		t.Fatal("OpenLevelDB accepted a directory without CURRENT")
	}
}

func TestOpenLevelDBRejectsEscapingManifestName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CURRENT"), []byte("../MANIFEST-000001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := forensic.OpenLevelDB(dir, forensic.Options{}); err == nil {
		t.Fatal("OpenLevelDB accepted a CURRENT that escapes the store")
	}
}

func TestLevelDBWarningsAndClose(t *testing.T) {
	dir := writeLevelDBStore(t)
	// A file named like a table but without a table footer must be warned
	// about, never parsed.
	if err := os.WriteFile(filepath.Join(dir, "000005.ldb"), []byte("not a table"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := forensic.OpenLevelDB(dir, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenLevelDB: %v", err)
	}
	defer store.Close()
	warnings, err := store.Warnings(context.Background())
	if err != nil {
		t.Fatalf("Warnings: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected a warning for the bogus table file")
	}
	if store.Info().Tables != 0 {
		t.Fatalf("bogus table was accepted: %+v", store.Info())
	}
	if _, err := store.Tables(context.Background()); err != nil {
		t.Fatalf("Tables: %v", err)
	}
}
